"""报告渲染：JSON / Markdown / 控制台对比。"""

from __future__ import annotations

from agent_shield.models import AttackResult


# --------------------------------------------------------------------------- #
# JSON
# --------------------------------------------------------------------------- #
def result_to_json(result: AttackResult) -> dict:
    """序列化为 JSON 友好的 dict（不含超长载荷，可加 --full 展开）。"""
    return {
        "summary": result.summary(),
        "cases": [
            {
                "name": c.name,
                "verdict": c.verdict.value,
                "severity": c.severity.value,
                "evidence": c.evidence,
                "trace_duration_ms": c.trace.duration_ms if c.trace else None,
                "tool_calls": [
                    {"name": tc.name, "arguments": tc.arguments} for tc in (c.trace.all_tool_calls() if c.trace else [])
                ],
            }
            for c in result.cases
        ],
    }


# --------------------------------------------------------------------------- #
# Markdown
# --------------------------------------------------------------------------- #
def result_to_markdown(result: AttackResult) -> str:
    lines = [
        f"# Attack Report: `{result.module}`",
        "",
        f"- **description**: {result.description}",
        f"- **MITRE ATLAS**: {result.atlas_id or '—'}",
        f"- **OWASP ASI**: {result.owasp_asi or '—'}",
        f"- **duration**: {result.duration_ms} ms",
        "",
        "## Summary",
        "",
        "| 指标 | 值 |",
        "| --- | --- |",
        f"| 用例数 | {result.total} |",
        f"| 成功（漏洞确认） | {result.successes} |",
        f"| 被拦截 | {result.blocked} |",
        f"| 未生效 | {result.failed} |",
        f"| 成功率 | {result.success_rate:.1%} |",
        "",
        "## Cases",
        "",
        "| # | 判定 | 严重度 | 证据 |",
        "| --- | --- | --- | --- |",
    ]
    for i, c in enumerate(result.cases, start=1):
        evidence = "; ".join(c.evidence) or "—"
        lines.append(f"| {i} | {c.verdict.value} | {c.severity.value} | {evidence} |")
    return "\n".join(lines) + "\n"
