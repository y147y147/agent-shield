"""C3 自适应绕过：按防护反馈逐轮换编码重试（defense-aware）。

流程（离线确定性，Mock 靶场可复现）：

1. 用 plain 基线打一轮（``attempt``），收集每条载荷的 verdict + 防护反馈
   （``blocked_calls[].reason`` 与脱敏标记）；
2. 若全部 SUCCESS 则提前结束；否则按反馈分类选择下一轮编码：
   - 注入检测器命中（reason 含 sanitize/INSTRUCTION/注入）→ 换编码混淆
     （``fullwidth-colon`` → ``zero-width`` → ``base64``）；
   - 策略/语义拦截（reason 含 policy/semantic/rule）→ 换同义模板
     （同家族下一 variant 的 plain 形态）；
   - 其他失败 → 按 ``ENCODING_LADDER`` 逐级升级；
3. 每条载荷最多 ``rounds`` 轮、全局最多 ``budget`` 次执行，同一 seed 下
   候选顺序与结果可复现；budget 耗尽即停并如实报告。

注意：自适应只做"编码/模板"维度的重试，不做语义改写（不引入 LLM），
Mock 上编码载荷仍可执行；对真实模型的绕过效果需实测。返回的
``AdaptiveReport`` 可直接拼进 AttackResult 的 evidence/params 做归因。

重要：``run_adaptive`` 的 ``attempt`` 回调只做"试探 + 判定"，不产出最终
case；调用方需用 ``report.attempts`` 的 payload 再执行一次并经模块 judge
产出正式 ``AttackCase``（保证 trace 与 verdict 一致，便于 benchmark 聚合）。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

ENCODING_LADDER: tuple[str, ...] = ("plain", "fullwidth-colon", "zero-width", "base64", "html-entity", "unicode-homoglyph")


def _feedback_kind(reasons: list[str], payload: str) -> str:
    """按防护反馈分类：detector（注入检测）/ policy（策略拦截）/ other。"""
    blob = " ".join(reasons + [payload]).lower()
    detector_keys = ("sanitiz", "redacted", "injection", "instruction", "detector", "judge")
    if any(k in blob for k in detector_keys):
        return "detector"
    policy_keys = ("policy", "semantic", "fail-closed", "denied by rule", "budget", "integrity", "sandbox")
    if any(k in blob for k in policy_keys):
        return "policy"
    return "other"


def next_encoding(current: str, kind: str) -> str:
    """按反馈种类选择下一级编码：detector 走混淆链，policy 回 plain 换模板，other 爬梯子。"""
    if kind == "policy":
        return "plain"
    try:
        idx = ENCODING_LADDER.index(current)
    except ValueError:
        return "plain"
    return ENCODING_LADDER[min(idx + 1, len(ENCODING_LADDER) - 1)]


@dataclass
class AdaptiveAttempt:
    payload: str
    encoding: str
    variant_id: str = ""
    round_no: int = 0
    verdict: str = ""
    reasons: list[str] = field(default_factory=list)


@dataclass
class AdaptiveReport:
    module: str
    seed: int
    rounds_used: int = 0
    executions: int = 0
    successes: int = 0
    blocked: int = 0
    failed: int = 0
    attempts: list[AdaptiveAttempt] = field(default_factory=list)
    encoding_wins: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "module": self.module,
            "seed": self.seed,
            "rounds_used": self.rounds_used,
            "executions": self.executions,
            "successes": self.successes,
            "blocked": self.blocked,
            "failed": self.failed,
            "encoding_wins": dict(self.encoding_wins),
            "attempts": [
                {
                    "payload": a.payload[:300],
                    "encoding": a.encoding,
                    "variant_id": a.variant_id,
                    "round": a.round_no,
                    "verdict": a.verdict,
                    "reasons": a.reasons,
                }
                for a in self.attempts
            ],
        }


async def run_adaptive(
    module_name: str,
    texts_with_meta: list[tuple[str, str, str]],
    *,
    seed: int,
    rounds: int,
    budget: int,
    attempt,
    context: dict[str, str] | None = None,
) -> AdaptiveReport:
    """执行自适应循环，``attempt(payload)`` 返回 ``(verdict, reasons)``。

    ``texts_with_meta`` 为 ``(variant_id, encoding, text)`` 的基线候选；
    同一 (module, seed, rounds, budget) 输入下候选顺序与重试路径可复现。
    ``context`` 用于 policy 分支换模板时重渲染 ``{placeholders}``（如 marker）。
    """
    from agent_shield.payloads.mutator import apply_encoding

    report = AdaptiveReport(module=module_name, seed=seed)
    queue: list[AdaptiveAttempt] = [
        AdaptiveAttempt(payload=text, encoding=enc, variant_id=vid, round_no=0)
        for vid, enc, text in texts_with_meta
    ]
    # seed 决定重试时的模板轮换起点（可复现），基线顺序保持 YAML 声明顺序
    template_cursor = seed % max(1, len(texts_with_meta))

    executions = 0
    for round_no in range(max(1, rounds)):
        if not queue or executions >= budget:
            break
        report.rounds_used = round_no + 1
        next_queue: list[AdaptiveAttempt] = []
        for item in queue:
            if executions >= budget:
                next_queue.append(item)
                continue
            verdict, reasons = await attempt(item.payload)
            executions += 1
            report.executions = executions
            item.verdict = verdict
            item.reasons = list(reasons)
            item.round_no = round_no + 1
            report.attempts.append(item)
            if verdict == "success":
                report.successes += 1
                report.encoding_wins[item.encoding] = report.encoding_wins.get(item.encoding, 0) + 1
                continue
            if verdict == "blocked":
                report.blocked += 1
            else:
                report.failed += 1
            if round_no + 1 >= rounds or executions >= budget:
                continue
            kind = _feedback_kind(list(reasons), item.payload)
            if kind == "policy":
                # 策略拦截：换同家族下一模板的 plain 形态（同义改写近似）
                template_cursor = (template_cursor + 1) % len(texts_with_meta)
                vid2, _, text2 = texts_with_meta[template_cursor]
                # 用调用方 context 重渲染模板占位符（如 {marker}），保证换模板后仍可执行
                from agent_shield.payloads import get_library

                family = get_library().get(module_name)
                plain_text = text2
                if family is not None:
                    for v in family.variants:
                        if v.id == vid2:
                            plain_text = v.render(context)
                            break
                next_queue.append(
                    AdaptiveAttempt(payload=plain_text, encoding="plain", variant_id=vid2, round_no=round_no + 1)
                )
            else:
                nxt = next_encoding(item.encoding, kind)
                # 在当前载荷的 plain 基底上套用下一级编码（避免编码叠加失真）
                base_text = _strip_to_plain(item, texts_with_meta)
                next_queue.append(
                    AdaptiveAttempt(
                        payload=apply_encoding(base_text, nxt, seed=seed + executions),
                        encoding=nxt,
                        variant_id=item.variant_id,
                        round_no=round_no + 1,
                    )
                )
        queue = next_queue
    return report


def _strip_to_plain(item: AdaptiveAttempt, texts_with_meta: list[tuple[str, str, str]]) -> str:
    for vid, enc, text in texts_with_meta:
        if vid == item.variant_id and enc == "plain":
            return text
    for vid, _enc, text in texts_with_meta:
        if vid == item.variant_id:
            return text
    return item.payload
