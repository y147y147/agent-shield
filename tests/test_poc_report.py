"""D2：PoC 证据报告测试。"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from agent_shield.cli import app as cli_app
from agent_shield.models import AuditStepResult
from agent_shield.orchestrator.plan_execute import FixedPlanLLM, audit_plan_and_execute
from agent_shield.orchestrator.poc import trace_tool_chain
from agent_shield.orchestrator.report import (
    collect_high_risk_findings,
    export_session_traces,
    session_report_to_json,
    session_report_to_markdown,
)
from agent_shield.targets import DEFAULT_TASK, build_local_target

runner = CliRunner()


def _factory(*, defense: bool = False):
    return build_local_target(llm="mock", defense=False)


@pytest.mark.asyncio
async def test_audit_report_has_poc_markdown_vd2():
    """V-D2：Markdown 含可复制 PoC（载荷 + 工具链）。"""
    report = await audit_plan_and_execute(
        planner=FixedPlanLLM(),
        target_factory=_factory,
        task=DEFAULT_TASK,
        max_steps=3,
        compare_defense=False,
    )
    md = session_report_to_markdown(report)
    assert "高危发现（PoC）" in md
    assert "```text" in md
    findings = collect_high_risk_findings(report.steps)
    assert findings, "expected at least one success PoC on mock target"
    assert any(f.get("payload") or f.get("evidence") for f in findings)

    data = session_report_to_json(report)
    assert data["high_risk_findings"]
    assert data["steps"][0].get("evidence_refs") is not None


def test_export_traces_cli(tmp_path: Path):
    traces_file = tmp_path / "traces.json"
    result = runner.invoke(
        cli_app,
        [
            "audit",
            "--mode",
            "plan",
            "--llm",
            "mock",
            "--steps",
            "2",
            "--no-compare-defense",
            "--no-save",
            "--export-traces",
            str(traces_file),
        ],
    )
    assert result.exit_code == 0, result.output
    assert traces_file.exists()
    data = json.loads(traces_file.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    assert len(data) >= 1


def test_trace_tool_chain_from_mock_run():
    """工具链提取应包含 run_command 等调用。"""
    import asyncio

    from agent_shield.attacks import AttackConfig, DirectInjectionAttack

    async def _run():
        target = build_local_target(llm="mock", defense=False)
        mod = DirectInjectionAttack()
        res = await mod.run(target, AttackConfig(task=DEFAULT_TASK, num_variants=1))
        case = next(c for c in res.cases if c.verdict.value == "success")
        chain = trace_tool_chain(case.trace)
        assert chain
        assert any(c.get("tool") == "run_command" for c in chain)

    asyncio.run(_run())


def test_export_session_traces_helper(tmp_path: Path):
    report_steps = [
        AuditStepResult(
            module="direct_injection",
            defense_on=False,
            trace_exports={"direct_injection:case-0": {"task": "t", "steps": []}},
        )
    ]
    from agent_shield.models import aggregate_audit_session

    report = aggregate_audit_session(
        mode="plan",
        objective="x",
        modules_planned=["direct_injection"],
        steps=report_steps,
    )
    out = tmp_path / "t.json"
    n = export_session_traces(report, out)
    assert n == 1
    assert json.loads(out.read_text(encoding="utf-8"))["direct_injection:case-0"]["task"] == "t"
