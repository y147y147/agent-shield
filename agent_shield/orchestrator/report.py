"""自主审计会话报告：JSON / Markdown（覆盖表 + 攻防对比 + PoC 证据）。"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agent_shield.models import AuditSessionReport, AuditStepResult
from agent_shield.orchestrator.poc import collect_session_trace_exports


def session_report_to_json(report: AuditSessionReport) -> dict[str, Any]:
    """序列化为 JSON 友好 dict。"""
    return {
        "summary": report.summary(),
        "narrative": report.narrative,
        "steps": [s.model_dump() for s in report.steps],
        "comparison": _comparison_rows(report.steps),
        "high_risk_findings": collect_high_risk_findings(report.steps),
        "chains": list(report.chains),
        "chain_edges": list(report.chain_edges),
        "planner_usage": dict(report.planner_usage),
    }


def collect_high_risk_findings(steps: list[AuditStepResult]) -> list[dict[str, Any]]:
    """聚合各步成功 PoC（脆弱侧优先，去重 ref）。"""
    seen: set[str] = set()
    findings: list[dict[str, Any]] = []
    for step in steps:
        if step.defense_on or step.error:
            continue
        for item in step.poc_findings:
            ref = str(item.get("ref") or "")
            if ref and ref in seen:
                continue
            if ref:
                seen.add(ref)
            entry = dict(item)
            entry["defense_on"] = step.defense_on
            entry["bypass_index"] = step.bypass_index
            findings.append(entry)
    return findings


def export_session_traces(report: AuditSessionReport, path: str | Path) -> int:
    """将报告中收集的 AgentTrace 导出为 JSON 文件，返回条目数。"""
    traces = collect_session_trace_exports(report.steps)
    out = Path(path)
    out.write_text(json.dumps(traces, ensure_ascii=False, indent=2), encoding="utf-8")
    return len(traces)


def session_report_to_markdown(report: AuditSessionReport) -> str:
    """Markdown 终报：摘要 + 覆盖表 + 攻防对比列（风格对齐 result_to_markdown）。"""
    lines = [        f"# Audit Session Report (`{report.mode}`)",
        "",
        f"- **objective**: {report.objective}",
        f"- **risk_level**: `{report.risk_level}`",
        f"- **vectors_covered**: {report.vectors_covered}",
        f"- **bypass_attempts**: {report.bypass_attempts}",
        "",
        "## Summary",
        "",
        "| 指标 | 值 |",
        "| --- | --- |",
        f"| 计划模块 | {', '.join(f'`{m}`' for m in report.modules_planned) or '—'} |",
        f"| 已执行模块 | {', '.join(f'`{m}`' for m in report.modules_executed) or '—'} |",
        f"| 脆弱侧成功用例合计 | {report.successes_vulnerable} |",
        f"| 防护侧成功用例合计 | {report.successes_defended} |",
        f"| 防护侧拦截用例合计 | {report.blocked_defended} |",
        "",
        "## 攻防对比",
        "",
        "| 模块 | 加固前成功率 | 加固后成功率 | 加固前成功 | 加固后成功 | 加固后拦截 |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for row in _comparison_rows(report.steps):
        lines.append(
            f"| `{row['module']}` "
            f"| {_fmt_rate(row['vulnerable_success_rate'])} "
            f"| {_fmt_rate(row['defended_success_rate'])} "
            f"| {row['vulnerable_successes']} "
            f"| {row['defended_successes']} "
            f"| {row['defended_blocked']} |"
        )

    findings = collect_high_risk_findings(report.steps)
    if findings:
        lines.extend(["", "## 高危发现（PoC）", ""])
        for i, f in enumerate(findings, start=1):
            lines.append(f"### {i}. `{f.get('ref', f.get('module', '?'))}`")
            lines.append("")
            if f.get("payload"):
                lines.append("**载荷 / Payload**")
                lines.append("")
                lines.append("```text")
                lines.append(str(f["payload"]))
                lines.append("```")
                lines.append("")
            if f.get("evidence"):
                lines.append("**证据**")
                for ev in f["evidence"]:
                    lines.append(f"- {ev}")
                lines.append("")
            chain = f.get("tool_chain") or []
            if chain:
                lines.append("**工具链**")
                lines.append("")
                lines.append("| 工具 | 参数 | 拦截 |")
                lines.append("| --- | --- | --- |")
                for link in chain:
                    args = json.dumps(link.get("arguments") or {}, ensure_ascii=False)
                    if len(args) > 120:
                        args = args[:120] + "…"
                    blocked = "是" if link.get("blocked") else "—"
                    lines.append(f"| `{link.get('tool', '?')}` | `{args}` | {blocked} |")
                lines.append("")

    if report.chains or report.chain_edges:
        lines.extend(["", "## 攻击链（显式依赖）", ""])
        for ch in report.chains:
            lines.append(
                f"- **{ch.get('name') or ch.get('chain_id') or 'chain'}**: "
                + " → ".join(f"`{s.get('module')}`" for s in (ch.get("steps") or []))
            )
        if report.chain_edges:
            lines.extend(["", "| 从 | 到 | 映射 params |", "| --- | --- | --- |"])
            for e in report.chain_edges:
                mapped = json.dumps(e.get("mapped_params") or {}, ensure_ascii=False)
                if len(mapped) > 100:
                    mapped = mapped[:100] + "…"
                lines.append(
                    f"| `{e.get('from_module')}({e.get('from_step')})` "
                    f"| `{e.get('to_module')}({e.get('to_step')})` "
                    f"| `{mapped}` |"
                )
        lines.append("")

    lines.extend(["", "## Steps", "", "| # | 模块 | 防护 | bypass | 成功/总数 | 错误 |", "| --- | --- | --- | --- | --- | --- |"])
    for i, step in enumerate(report.steps, start=1):
        total = step.result_summary.get("total", "—")
        successes = step.result_summary.get("successes", "—")
        err = step.error or "—"
        lines.append(
            f"| {i} | `{step.module}` | {'on' if step.defense_on else 'off'} "
            f"| {step.bypass_index} | {successes}/{total} | {err} |"
        )

    if report.narrative:
        lines.extend(["", "## Narrative", "", report.narrative])

    return "\n".join(lines) + "\n"


def _fmt_rate(rate: float | None) -> str:
    if rate is None:
        return "—"
    return f"{rate:.0%}"


def _pick_summary(steps: list[AuditStepResult], *, defense_on: bool) -> dict[str, Any] | None:
    """同一模块多步时取 bypass_index 最大的一条有效摘要。"""
    matched = [s for s in steps if s.defense_on == defense_on and not s.error]
    if not matched:
        return None
    best = max(matched, key=lambda s: s.bypass_index)
    return best.result_summary


def _comparison_rows(steps: list[AuditStepResult]) -> list[dict[str, Any]]:
    modules: list[str] = []
    seen: set[str] = set()
    for s in steps:
        if s.module not in seen:
            seen.add(s.module)
            modules.append(s.module)

    rows: list[dict[str, Any]] = []
    for module in modules:
        mod_steps = [s for s in steps if s.module == module]
        vuln = _pick_summary(mod_steps, defense_on=False)
        defn = _pick_summary(mod_steps, defense_on=True)
        rows.append(
            {
                "module": module,
                "vulnerable_success_rate": None if vuln is None else float(vuln.get("success_rate") or 0.0),
                "defended_success_rate": None if defn is None else float(defn.get("success_rate") or 0.0),
                "vulnerable_successes": 0 if vuln is None else int(vuln.get("successes") or 0),
                "defended_successes": 0 if defn is None else int(defn.get("successes") or 0),
                "defended_blocked": 0 if defn is None else int(defn.get("blocked") or 0),
            }
        )
    return rows
