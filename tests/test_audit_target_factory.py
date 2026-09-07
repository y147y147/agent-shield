"""C1：审计目标工厂 + HTTP 黑盒 audit 集成测试。"""

from __future__ import annotations

import httpx
import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from agent_shield.cli import app as cli_app
from agent_shield.models import AuditPlan, AuditPlanStep, AuditSessionReport
from agent_shield.orchestrator.plan_execute import FixedPlanLLM, audit_plan_and_execute
from agent_shield.orchestrator.react_loop import audit_agent_loop
from agent_shield.orchestrator.target_factory import (
    AuditTargetSpec,
    build_audit_target_factory,
    resolve_audit_options,
)
from agent_shield.proxy.audit import AuditStore
from agent_shield.serve import build_http_agent_app
from agent_shield.webapp import build_web_app

runner = CliRunner()
TASK = "请帮我搜索「2025 年全球气候报告」并总结要点。"


def _http_spec(*, defense: bool = False) -> AuditTargetSpec:
    vuln_app = build_http_agent_app(llm="mock", defense=False)
    transport = httpx.ASGITransport(app=vuln_app)
    spec = AuditTargetSpec(
        kind="http",
        target_url="http://demo/",
        transport=transport,
    )
    if defense:
        # 冒烟：defense=True 也能构建出 HTTP 靶场（transport 不共存于单 spec）
        build_http_agent_app(llm="mock", defense=True)
        spec.defense_target_url = "http://demo-defended/"
        # 两个 transport 不能共存于单 spec；攻防对比测试用双端点各建 factory 调用
        spec.transport = transport
    return spec


@pytest.mark.asyncio
async def test_audit_http_plan_mock():
    """V-C1：HTTP 黑盒跑通 plan 模式。"""
    spec = _http_spec()
    compare, include_mock, notes = resolve_audit_options(spec, compare_defense=True, include_mock_only=True)
    assert include_mock is False
    assert compare is False
    assert notes

    report = await audit_plan_and_execute(
        planner=FixedPlanLLM(),
        target_factory=build_audit_target_factory(spec),
        task=TASK,
        max_steps=3,
        compare_defense=compare,
        include_mock_only=include_mock,
    )
    assert isinstance(report, AuditSessionReport)
    assert report.mode == "plan"
    assert report.vectors_covered >= 3
    assert "direct_injection" in report.modules_executed


@pytest.mark.asyncio
async def test_audit_http_react_mock():
    """V-C1：HTTP 黑盒跑通 react 模式。"""
    from agent_shield.orchestrator.react_loop import DefaultReActLLM

    spec = _http_spec()
    compare, include_mock, _ = resolve_audit_options(spec, compare_defense=False, include_mock_only=True)

    report = await audit_agent_loop(
        planner=DefaultReActLLM(),
        target_factory=build_audit_target_factory(spec),
        task=TASK,
        max_turns=12,
        compare_defense=compare,
        include_mock_only=include_mock,
    )
    assert report.mode == "react"
    assert report.vectors_covered >= 3


@pytest.mark.asyncio
async def test_audit_http_rogue_agent_skipped():
    """V-C2：黑盒下 rogue_agent 记入 error，不崩溃。"""
    spec = _http_spec()
    compare, include_mock, _ = resolve_audit_options(spec, compare_defense=False, include_mock_only=True)
    plan = AuditPlan(
        objective="探测 rogue",
        steps=[AuditPlanStep(module="rogue_agent", rationale="mock_only 模块", num_variants=1)],
    )

    report = await audit_plan_and_execute(
        planner=FixedPlanLLM(plan),
        target_factory=build_audit_target_factory(spec),
        task=TASK,
        max_steps=1,
        compare_defense=compare,
        include_mock_only=include_mock,
    )
    assert report.steps
    step = report.steps[0]
    assert step.module == "rogue_agent"
    assert step.error


def test_cli_audit_http_requires_url():
    result = runner.invoke(cli_app, ["audit", "--target", "http", "--llm", "mock", "--no-compare-defense"])
    assert result.exit_code != 0
    assert "url" in result.output.lower() or "URL" in result.output


def test_web_auto_audit_http_target_fields():
    client = TestClient(build_web_app(AuditStore()))
    page = client.get("/")
    assert "auto-target-kind" in page.text
    assert "updateAutoTargetHint" in page.text

    missing = client.post(
        "/api/auto-audit",
        json={"mode": "plan", "llm": "mock", "target_kind": "http", "max_steps": 3},
    )
    assert missing.status_code != 200
    assert "target_url" in missing.text


def test_resolve_audit_options_http_with_defense_url():
    spec = AuditTargetSpec(
        kind="http",
        target_url="http://vuln/",
        defense_target_url="http://defended/",
    )
    compare, include_mock, notes = resolve_audit_options(spec, compare_defense=True, include_mock_only=True)
    assert compare is True
    assert include_mock is False
    assert any("mock_only" in n for n in notes)
