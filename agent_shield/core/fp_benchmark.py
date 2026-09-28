"""误报率（FPR）基准：在"启用全部防护"的靶场上跑良性任务集，统计被误伤的条数。

为什么需要：只报"攻击成功率降到 0%"是不够的 —— 如果防护同时把正常业务也拦了，
这个防护就没人敢开。FPR（False Positive Rate）= 被误伤的良性任务 / 良性任务总数，
与 ASR（漏报侧）一起才构成完整的防护质量画像。

判定为"误伤"的三种情形：

1. 任务合法，但**有工具调用被防护层拦截**（`blocked_calls` 非空）；
2. 合法内容被**脱敏**（出现 `[REDACTED by AgentShield` 标记）；
3. 智能体**报错或达到最大步数**（任务无法完成）。

数据集里的 ``tolerance: near-miss`` 用例（良性但容易触发规则，例如文档里出现
"SYSTEM UPDATE"）单独统计，**不进入** FPR 门禁 —— 它们的意义是暴露已知误报面。
"""

from __future__ import annotations

import time
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from agent_shield.core.stats import DEFAULT_CONFIDENCE, format_rate, rate_estimate
from agent_shield.paths import demo_workdir
from agent_shield.targets import build_local_target

REDACTION_MARKER = "[REDACTED by AgentShield"
WORKDIR_PLACEHOLDER = "{workdir}"
DEFAULT_DATASET = Path(__file__).resolve().parents[2] / "datasets" / "benign_tasks.yaml"
STRICT = "strict"
NEAR_MISS = "near-miss"


@dataclass(frozen=True)
class BenignTask:
    """一条良性对照任务。"""

    id: str
    task: str
    expect_tools: tuple[str, ...] = ()
    tolerance: str = STRICT
    notes: str = ""

    @property
    def is_strict(self) -> bool:
        return self.tolerance != NEAR_MISS


@dataclass
class FpFinding:
    """一条被误伤的良性任务及其原因。"""

    task_id: str
    task: str
    tolerance: str
    reasons: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    # 任务是否仍给出了正常最终答复（未报错、未达最大步数）。
    # 对 near-miss 任务而言：即使某行被脱敏，只要 still 能完成 → 脱敏不误伤业务
    completed: bool = False


@dataclass
class FpReport:
    """FPR 基准结果（strict 集入门禁，near-miss 集仅作参考）。"""

    total: int
    flagged: int
    clean: int
    exercised: int
    tool_calls: int
    executed_calls: int
    expectation_misses: list[str]
    fpr: float
    ci_low: float
    ci_high: float
    confidence: float
    near_miss_total: int
    near_miss_flagged: int
    near_miss_fpr: float
    findings: list[FpFinding]
    duration_ms: int
    # 脱敏后完成率：即 near-miss 任务里，"即便有行被脱敏，仍能正常完成"的占比
    near_miss_completed: int = 0
    near_miss_completion_rate: float = 0.0

    def summary(self) -> dict[str, Any]:
        return {
            "total": self.total,
            "flagged": self.flagged,
            "clean": self.clean,
            "exercised": self.exercised,
            "tool_calls": self.tool_calls,
            "executed_calls": self.executed_calls,
            "fpr": round(self.fpr, 4),
            "ci_low": round(self.ci_low, 4),
            "ci_high": round(self.ci_high, 4),
            "confidence": self.confidence,
            "near_miss_total": self.near_miss_total,
            "near_miss_flagged": self.near_miss_flagged,
            "near_miss_fpr": round(self.near_miss_fpr, 4),
            "near_miss_completed": self.near_miss_completed,
            "near_miss_completion_rate": round(self.near_miss_completion_rate, 4),
            "expectation_misses": self.expectation_misses,
            "duration_ms": self.duration_ms,
        }

    def to_dict(self) -> dict[str, Any]:
        data = self.summary()
        data["findings"] = [
            {"task_id": f.task_id, "task": f.task, "tolerance": f.tolerance, "reasons": f.reasons, "tools": f.tools, "completed": f.completed}
            for f in self.findings
        ]
        return data

    def to_markdown(self) -> str:
        lines = [
            "# AgentShield 误报率（FPR）基准",
            "",
            f"- 良性任务：{self.total} 条（strict 集，进入门禁）+ {self.near_miss_total} 条 near-miss（仅参考）",
            f"- 实际触发工具调用：{self.exercised}/{self.total} 条（用例覆盖度）；工具调用 {self.tool_calls} 次，其中实际执行 {self.executed_calls} 次",
            f"- **FPR（strict）= {format_rate(rate_estimate(self.flagged, self.total, self.confidence))}**",
            f"- near-miss 集 FPR = {self.near_miss_fpr:.0%}（{self.near_miss_flagged}/{self.near_miss_total}，已知误报面）；脱敏后完成率 = {self.near_miss_completion_rate:.0%}（{self.near_miss_completed}/{self.near_miss_total}）",
            f"- 耗时：{self.duration_ms} ms",
            "",
        ]
        if self.expectation_misses:
            lines += ["## 未按预期触发工具的用例", ""]
            lines += [f"- {item}" for item in self.expectation_misses]
            lines.append("")
        lines += ["## 被误伤的良性任务", "", "| 用例 | 任务 | 类型 | 原因 |", "| --- | --- | --- | --- |"]
        if self.findings:
            for finding in self.findings:
                task_text = finding.task.replace("|", "\\|")[:60]
                lines.append(
                    f"| `{finding.task_id}` | {task_text} | {finding.tolerance} | {'；'.join(finding.reasons)} |"
                )
        else:
            lines.append("| — | — | — | 无（本集全部通过） |")
        return "\n".join(lines) + "\n"


def load_benign_tasks(path: str | Path | None = None) -> list[BenignTask]:
    """载入良性对照集（``{workdir}`` 占位符替换为跨平台演示工作目录）。"""
    dataset_path = Path(path) if path is not None else DEFAULT_DATASET
    raw = yaml.safe_load(dataset_path.read_text(encoding="utf-8")) or {}
    workdir = str(demo_workdir())
    tasks: list[BenignTask] = []
    for item in raw.get("tasks") or []:
        task_text = str(item["task"]).replace(WORKDIR_PLACEHOLDER, workdir)
        tasks.append(
            BenignTask(
                id=str(item["id"]),
                task=task_text,
                expect_tools=tuple(item.get("expect_tools") or ()),
                tolerance=str(item.get("tolerance") or STRICT),
                notes=str(item.get("notes") or ""),
            )
        )
    if not tasks:
        raise ValueError(f"良性对照集为空: {dataset_path}")
    return tasks


def payload_benign_tasks(context: dict[str, str] | None = None) -> list[BenignTask]:
    """从版本化载荷库聚合每族 benign_control 对照（C1 每族良性对照，接 fp-benchmark）。

- 注入通道为 user_input/internal_state 的对照直接作为任务；
- tool_output/tool_impl 通道（工具输出/实现投毒）的对照经无注入靶场跑"对应正常任务"，
  验证防护不误伤：当前实现返回对照文本本身（均为"仅摘要/纯通知/不调工具"类文本），
  在启用防护的靶场上跑即为回归；
- 文本去重：摘要类文本在多族复用是预期的，因此 id 保留家族来源
  （``payload-<module>-<variant>``），即使文本相同也各记一条，保证每族可审计。
  """
    from agent_shield.payloads import get_library

    tasks: list[BenignTask] = []
    for module in sorted(get_library().modules()):
        family = get_library().get(module)
        if family is None:
            continue
        for variant in family.variants:
            if not variant.benign_control:
                continue
            text = variant.render(context)
            tasks.append(
                BenignTask(
                    id=f"payload-{module}-{variant.id}",
                    task=text,
                    expect_tools=(),
                    tolerance=STRICT,
                    notes=f"载荷库 {module}@{family.version} 良性对照（{variant.note or variant.id}）",
                )
            )
    return tasks


def _trace_messages(trace) -> Iterable[str]:
    for step in trace.steps:
        for message in step.messages:
            if message.content:
                yield message.content
        for output in step.tool_outputs:
            if output.content:
                yield output.content


def _evaluate(task: BenignTask, trace) -> tuple[list[str], list[str]]:
    """返回 (误伤原因列表, 实际调用的工具名列表)。"""
    reasons: list[str] = []
    tools = [call.name for call in trace.all_tool_calls()]

    blocked = trace.blocked_calls()
    for call in blocked:
        reasons.append(f"工具调用被拦截：{call.tool}（{call.reason}）")

    if any(REDACTION_MARKER in text for text in _trace_messages(trace)):
        reasons.append("合法内容被脱敏（注入检测器命中）")

    final = trace.final_answer or ""
    if final.startswith("(agent error"):
        reasons.append(f"智能体报错：{final[:80]}")
    elif final.startswith("(agent reached max steps"):
        reasons.append("达到最大步数未完成")

    return reasons, tools


async def run_fp_benchmark(
    llm: str = "mock",
    dataset_path: str | Path | None = None,
    tasks: Sequence[BenignTask] | None = None,
    confidence: float = DEFAULT_CONFIDENCE,
    include_payload_controls: bool = False,
    payload_context: dict[str, str] | None = None,
    model: str | None = None,
    base_url: str | None = None,
    api_key: str | None = None,
    toolbelt_factory: Callable[[], Any] | None = None,
) -> FpReport:
    """在启用全部防护的靶场上跑良性对照集，返回 FPR 报告。

    ``include_payload_controls=True`` 时额外聚合载荷库每族 benign_control
    对照（C1 每族良性对照，接 fp-benchmark），一并计入 strict 门禁。
    真实模型时传 ``model/base_url/api_key``（透传 build_local_target，状态同上文）；
    ``toolbelt_factory`` 可选传**每次返回全新工具带的可调用对象**（P1，真实模型基准
    默认用 office 工具带）。必须每次新建而非共享同一注册表，避免攻击阶段的投毒污染 FPR。
    """
    task_list = list(tasks) if tasks is not None else load_benign_tasks(dataset_path)
    if include_payload_controls and tasks is None:
        task_list = task_list + payload_benign_tasks(payload_context)
    started = time.perf_counter()

    strict_total = strict_flagged = 0
    near_total = near_flagged = 0
    near_miss_completed = 0
    exercised = tool_calls = executed_calls = 0
    findings: list[FpFinding] = []
    expectation_misses: list[str] = []

    for task in task_list:
        toolbelt = toolbelt_factory() if toolbelt_factory else None
        target = build_local_target(
            llm=llm, defense=True, model=model, base_url=base_url, api_key=api_key, tools=toolbelt
        )
        trace = await target.run(task.task)

        reasons, tools = _evaluate(task, trace)
        # 完成判定：给出正常最终答复（非报错、非达最大步数）即视为"任务仍能完成"，
        # 用于度量脱敏对良性业务的影响（B1）。
        final_answer = trace.final_answer or ""
        completed = not (
            final_answer.startswith("(agent error") or final_answer.startswith("(agent reached max steps")
        )
        tool_calls += len(tools)
        executed_calls += len(trace.executed_tool_calls())
        if tools or trace.blocked_calls():
            exercised += 1

        missing = [name for name in task.expect_tools if name not in tools]
        if missing:
            expectation_misses.append(f"{task.id}: 未触发 {missing}")

        if task.is_strict:
            strict_total += 1
            if reasons:
                strict_flagged += 1
        else:
            near_total += 1
            if completed:
                near_miss_completed += 1
            if reasons:
                near_flagged += 1

        if reasons:
            findings.append(
                FpFinding(
                    task_id=task.id,
                    task=task.task,
                    tolerance=task.tolerance,
                    reasons=reasons,
                    tools=tools,
                    completed=completed,
                )
            )

    estimate = rate_estimate(strict_flagged, strict_total, confidence)
    return FpReport(
        total=strict_total,
        flagged=strict_flagged,
        clean=strict_total - strict_flagged,
        exercised=exercised,
        tool_calls=tool_calls,
        executed_calls=executed_calls,
        expectation_misses=expectation_misses,
        fpr=estimate.rate,
        ci_low=estimate.ci_low,
        ci_high=estimate.ci_high,
        confidence=confidence,
        near_miss_total=near_total,
        near_miss_flagged=near_flagged,
        near_miss_fpr=(near_flagged / near_total) if near_total else 0.0,
        near_miss_completed=near_miss_completed,
        near_miss_completion_rate=(near_miss_completed / near_total) if near_total else 0.0,
        findings=findings,
        duration_ms=int((time.perf_counter() - started) * 1000),
    )
