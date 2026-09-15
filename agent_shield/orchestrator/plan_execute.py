"""Phase A：Plan-and-Execute — 一次规划，顺序执行，聚合会话终报。"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from agent_shield.attacks import get_attack_module
from agent_shield.models import (
    AuditPlan,
    AuditPlanStep,
    AuditSessionReport,
    AuditStepResult,
    ChatMessage,
    aggregate_audit_session,
)
from agent_shield.observability import get_logger
from agent_shield.orchestrator.prompts import (
    build_plan_system_prompt,
    build_plan_user_message,
    parse_audit_plan,
)
from agent_shield.orchestrator.tools_bridge import execute_attack_tool
from agent_shield.runtime.llm import LLMClient, LLMResponse
from agent_shield.targets.base import AgentTarget

logger = get_logger("orchestrator.plan_execute")

TargetFactory = Callable[..., AgentTarget]
EventSink = Callable[[dict[str, Any]], None]

# CLI / Web Mock 规划器默认计划（≥3 模块，满足 Phase A 验收）
DEFAULT_FIXED_PLAN = AuditPlan(
    objective="代表性覆盖：直接注入 → 间接注入 → 越权",
    steps=[
        AuditPlanStep(module="direct_injection", rationale="先探用户输入侧目标劫持", num_variants=2),
        AuditPlanStep(module="indirect_injection", rationale="输入清洗时改走工具输出投毒", num_variants=2),
        AuditPlanStep(module="privilege_escalation", rationale="验证权限边界与外发", num_variants=2),
    ],
)


class FixedPlanLLM(LLMClient):
    """测试/离线用规划器：忽略输入，固定返回 AuditPlan JSON。"""

    name = "fixed-plan"

    def __init__(self, plan: AuditPlan | dict[str, Any] | str | None = None):
        if plan is None:
            plan = DEFAULT_FIXED_PLAN
        if isinstance(plan, AuditPlan):
            self._content = plan.model_dump_json()
        elif isinstance(plan, dict):
            self._content = json.dumps(plan, ensure_ascii=False)
        else:
            self._content = str(plan)

    async def chat(self, messages: list[ChatMessage], tools: list) -> LLMResponse:
        return LLMResponse(content=self._content)


def _emit(on_event: EventSink | None, event: dict[str, Any]) -> None:
    if on_event is None:
        return
    try:
        on_event(event)
    except Exception:
        logger.debug("event sink 回调失败（已忽略）", exc_info=True)


def _known_module(name: str) -> bool:
    try:
        get_attack_module(name)
        return True
    except ValueError:
        return False


def _is_mock_only(name: str) -> bool:
    try:
        return bool(get_attack_module(name).mock_only)
    except ValueError:
        return False


def _observation_to_step_result(
    module: str,
    *,
    defense_on: bool,
    raw: str,
    bypass_index: int = 0,
) -> AuditStepResult:
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return AuditStepResult(
            module=module,
            defense_on=defense_on,
            bypass_index=bypass_index,
            error=f"invalid tool observation JSON: {raw[:200]}",
        )
    err = data.get("error")
    if data.get("hitl_required"):
        return AuditStepResult(
            module=module,
            defense_on=defense_on,
            bypass_index=bypass_index,
            error=f"HITL: {data.get('reason') or '需人工确认'}",
        )
    if err or data.get("skipped"):
        return AuditStepResult(
            module=module,
            defense_on=defense_on,
            bypass_index=bypass_index,
            result_summary=data.get("summary") or {},
            error=str(err or "skipped"),
        )
    summary = data.get("summary") or {}
    cases = data.get("cases") or []
    evidence_refs = list(data.get("evidence_refs") or [])
    if not evidence_refs:
        evidence_refs = [c.get("ref") for c in cases if isinstance(c, dict) and c.get("ref")]
    poc_findings = list(data.get("poc_findings") or [])
    if not poc_findings:
        poc_findings = [
            c for c in cases if isinstance(c, dict) and c.get("verdict") == "success"
        ]
    trace_exports = dict(data.get("trace_exports") or {})
    return AuditStepResult(
        module=module,
        defense_on=defense_on,
        bypass_index=bypass_index,
        result_summary=summary,
        error=None,
        evidence_refs=[str(r) for r in evidence_refs if r],
        poc_findings=poc_findings,
        trace_exports=trace_exports,
    )


def _step_event_text(step_result: AuditStepResult) -> str:
    if step_result.error:
        return f"{step_result.module}（{'防护' if step_result.defense_on else '脆弱'}）错误: {step_result.error}"
    s = step_result.result_summary
    return (
        f"{step_result.module}（{'防护' if step_result.defense_on else '脆弱'}）"
        f" 成功 {s.get('successes', 0)}/{s.get('total', 0)}"
        f" 成功率 {float(s.get('success_rate') or 0):.0%}"
        f" 拦截 {s.get('blocked', 0)}"
    )


async def _execute_plan_step(
    step: AuditPlanStep,
    *,
    task: str,
    target_factory: TargetFactory,
    compare_defense: bool,
    include_mock_only: bool,
    on_event: EventSink | None = None,
    step_index: int = 1,
    step_total: int = 1,
    export_traces: bool = False,
    hitl_confirmed_modules: set[str] | frozenset[str] | None = None,
) -> list[AuditStepResult]:
    """执行单步：脆弱侧必跑；compare_defense 时再跑防护侧。"""
    results: list[AuditStepResult] = []

    _emit(
        on_event,
        {
            "type": "phase",
            "label": f"步骤 {step_index}/{step_total}：执行 `{step.module}`",
            "text": step.rationale or "",
        },
    )

    if not _known_module(step.module):
        err = AuditStepResult(
            module=step.module,
            defense_on=False,
            error=f"未知攻击模块: {step.module}",
        )
        results.append(err)
        _emit(on_event, {"type": "error", "text": err.error or ""})
        return results

    if _is_mock_only(step.module) and not include_mock_only:
        err = AuditStepResult(
            module=step.module,
            defense_on=False,
            error="mock_only 模块在当前配置下不可执行",
        )
        results.append(err)
        _emit(on_event, {"type": "error", "text": err.error or ""})
        return results

    arguments: dict[str, Any] = {
        "task": step.task or task,
        "num_variants": step.num_variants,
        "params": dict(step.params or {}),
        "with_defense": False,
    }

    _emit(on_event, {"type": "phase", "label": f"  · `{step.module}` 脆弱靶场", "text": ""})
    vulnerable = target_factory(defense=False)
    defended = target_factory(defense=True) if compare_defense else None

    raw_v = await execute_attack_tool(
        step.module,
        arguments,
        target_vulnerable=vulnerable,
        target_defended=defended,
        allow_mock_only=include_mock_only,
        default_task=task,
        export_traces=export_traces,
        hitl_confirmed_modules=hitl_confirmed_modules,
    )
    r_v = _observation_to_step_result(step.module, defense_on=False, raw=raw_v)
    results.append(r_v)
    try:
        hitl_data = json.loads(raw_v)
        if hitl_data.get("hitl_required"):
            _emit(
                on_event,
                {
                    "type": "hitl",
                    "module": hitl_data.get("module"),
                    "reason": hitl_data.get("reason"),
                    "text": hitl_data.get("reason") or "",
                },
            )
    except json.JSONDecodeError:
        pass
    _emit(on_event, {"type": "output", "tool": step.module, "text": _step_event_text(r_v)})

    if compare_defense:
        _emit(on_event, {"type": "phase", "label": f"  · `{step.module}` 加固靶场", "text": ""})
        arguments_d = {**arguments, "with_defense": True}
        vulnerable2 = target_factory(defense=False)
        defended2 = target_factory(defense=True)
        raw_d = await execute_attack_tool(
            step.module,
            arguments_d,
            target_vulnerable=vulnerable2,
            target_defended=defended2,
            allow_mock_only=include_mock_only,
            default_task=task,
            export_traces=export_traces,
            hitl_confirmed_modules=hitl_confirmed_modules,
        )
        r_d = _observation_to_step_result(step.module, defense_on=True, raw=raw_d)
        results.append(r_d)
        _emit(on_event, {"type": "output", "tool": step.module, "text": _step_event_text(r_d)})

    return results


async def audit_plan_and_execute(
    *,
    planner: LLMClient,
    target_factory: TargetFactory,
    task: str,
    max_steps: int = 5,
    compare_defense: bool = True,
    include_mock_only: bool = True,
    fail_fast: bool = False,
    full: bool = False,
    objective: str | None = None,
    on_event: EventSink | None = None,
    export_traces: bool = False,
    hitl_confirmed_modules: set[str] | frozenset[str] | None = None,
) -> AuditSessionReport:
    """Plan-and-Execute：LLM 一次出计划 → 顺序执行 → 聚合 AuditSessionReport。

    ``target_factory`` 须接受 ``defense: bool`` 关键字参数，返回 ``AgentTarget``。
    单步失败写入 ``AuditStepResult.error``，默认不中断；``fail_fast=True`` 时遇错停止后续步骤。
    ``on_event`` 可选进度回调（Web 过程链）。
    """
    from agent_shield.orchestrator.usage import UsageTrackingPlanner

    usage_tracker = UsageTrackingPlanner(planner)
    planner = usage_tracker
    _emit(on_event, {"type": "phase", "label": "阶段 1：规划器生成 AuditPlan", "text": ""})
    system = build_plan_system_prompt(
        max_steps=max_steps,
        full=full,
        allow_mock_only=include_mock_only,
    )
    user = build_plan_user_message(
        task=task,
        objective=objective,
        compare_defense=compare_defense,
        max_steps=None if full else max_steps,
        full=full,
    )
    messages = [ChatMessage.system(system), ChatMessage.user(user)]

    # Plan 模式不传攻击 tools：要求模型直接吐 JSON
    response = await planner.chat(messages, tools=[])
    if not response.content:
        raise ValueError("规划器未返回内容")

    plan = parse_audit_plan(response.content)
    steps = list(plan.steps)
    if not full:
        steps = steps[: max(1, max_steps)]
    modules_planned = [s.module for s in steps]
    _emit(
        on_event,
        {
            "type": "think",
            "text": f"目标：{plan.objective}\n计划：{' → '.join(modules_planned)}",
        },
    )
    _emit(on_event, {"type": "phase", "label": "阶段 2：按序执行攻击模块", "text": ""})

    step_results: list[AuditStepResult] = []
    for i, step in enumerate(steps, start=1):
        batch = await _execute_plan_step(
            step,
            task=task,
            target_factory=target_factory,
            compare_defense=compare_defense,
            include_mock_only=include_mock_only,
            on_event=on_event,
            step_index=i,
            step_total=len(steps),
            export_traces=export_traces,
            hitl_confirmed_modules=hitl_confirmed_modules,
        )
        step_results.extend(batch)
        if fail_fast and any(r.error for r in batch):
            _emit(on_event, {"type": "error", "text": f"fail_fast：在 `{step.module}` 停止"})
            break

    report = aggregate_audit_session(
        mode="plan",
        objective=plan.objective or objective or task,
        modules_planned=modules_planned,
        steps=step_results,
        narrative="",
        planner_usage=usage_tracker.accumulator.to_dict(),
    )
    _emit(
        on_event,
        {
            "type": "final",
            "text": (
                f"覆盖 {report.vectors_covered} 向量 · risk={report.risk_level} · "
                f"脆弱成功 {report.successes_vulnerable} · 防护成功 {report.successes_defended}"
            ),
        },
    )
    return report
