"""Phase D2：从 AttackResult / AgentTrace 提取 PoC 证据。"""

from __future__ import annotations

from typing import Any

from agent_shield.models import AgentTrace, AttackCase, AttackResult, AttackVerdict


def case_ref(module: str, index: int, case: AttackCase) -> str:
    label = (case.name or f"case-{index}").strip() or f"case-{index}"
    return f"{module}:{label}"


def trace_tool_chain(trace: AgentTrace | None) -> list[dict[str, Any]]:
    """从 AgentTrace 提取工具调用链（供 PoC 报告）。"""
    if trace is None:
        return []
    chain: list[dict[str, Any]] = []
    for step in trace.steps:
        for tc in step.tool_calls:
            chain.append({"tool": tc.name, "arguments": tc.arguments})
        for bc in step.blocked_calls:
            chain.append(
                {
                    "tool": bc.tool,
                    "arguments": bc.arguments,
                    "blocked": True,
                    "reason": bc.reason,
                }
            )
    return chain


def case_to_poc_dict(
    module: str,
    index: int,
    case: AttackCase,
    *,
    export_traces: bool = False,
) -> dict[str, Any]:
    """将 AttackCase 转为可序列化的 PoC 条目。"""
    ref = case_ref(module, index, case)
    payload = case.payload or ""
    if len(payload) > 800:
        payload = payload[:800] + "…"
    item: dict[str, Any] = {
        "ref": ref,
        "module": module,
        "name": case.name or f"case-{index}",
        "verdict": case.verdict.value,
        "severity": case.severity.value,
        "payload": payload,
        "evidence": list(case.evidence),
        "tool_chain": trace_tool_chain(case.trace),
    }
    if export_traces and case.trace is not None:
        item["trace"] = case.trace.model_dump(mode="json")
    return item


def result_to_poc_payload(
    result: AttackResult,
    *,
    export_traces: bool = False,
) -> tuple[list[dict[str, Any]], list[str], list[dict[str, Any]], dict[str, Any]]:
    """返回 (cases, evidence_refs, poc_findings, trace_exports)。"""
    cases: list[dict[str, Any]] = []
    evidence_refs: list[str] = []
    poc_findings: list[dict[str, Any]] = []
    trace_exports: dict[str, Any] = {}

    for i, case in enumerate(result.cases):
        item = case_to_poc_dict(result.module, i, case, export_traces=export_traces)
        cases.append(item)
        evidence_refs.append(item["ref"])
        if case.verdict == AttackVerdict.SUCCESS:
            poc_findings.append(item)
        if export_traces and "trace" in item:
            trace_exports[item["ref"]] = item.pop("trace")

    return cases, evidence_refs, poc_findings, trace_exports


def collect_session_trace_exports(steps: list[Any]) -> dict[str, Any]:
    """合并各 AuditStepResult.trace_exports。"""
    merged: dict[str, Any] = {}
    for step in steps:
        exports = getattr(step, "trace_exports", None) or {}
        merged.update(exports)
    return merged
