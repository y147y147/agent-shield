"""A3：Plan-and-Execute 主循环。"""

from __future__ import annotations

import pytest

from agent_shield.models import AuditPlan, AuditPlanStep, AuditSessionReport
from agent_shield.orchestrator.plan_execute import FixedPlanLLM, audit_plan_and_execute
from agent_shield.targets import DEFAULT_TASK, build_local_target


def _factory(*, defense: bool = False):
    return build_local_target(llm="mock", defense=defense)


@pytest.mark.asyncio
async def test_plan_and_execute_mock_planner_e2e():
    plan = AuditPlan(
        objective="覆盖注入与越权",
        steps=[
            AuditPlanStep(module="direct_injection", rationale="先探输入侧", num_variants=2),
            AuditPlanStep(module="indirect_injection", rationale="工具输出注入", num_variants=2),
            AuditPlanStep(module="privilege_escalation", rationale="权限边界", num_variants=2),
        ],
    )
    report = await audit_plan_and_execute(
        planner=FixedPlanLLM(plan),
        target_factory=_factory,
        task=DEFAULT_TASK,
        max_steps=5,
        compare_defense=True,
        include_mock_only=True,
    )
    assert isinstance(report, AuditSessionReport)
    assert report.mode == "plan"
    assert len(report.modules_planned) >= 3
    assert set(report.modules_executed) >= {
        "direct_injection",
        "indirect_injection",
        "privilege_escalation",
    }
    # 每模块脆弱 + 防护各一步
    assert len(report.steps) == 6
    assert all(s.error is None for s in report.steps)
    assert any(not s.defense_on and s.result_summary.get("successes", 0) >= 1 for s in report.steps)
    assert report.risk_level in {"critical", "high", "medium", "low", "info"}
    assert "success_rate" in (report.steps[0].result_summary or {})


@pytest.mark.asyncio
async def test_unknown_module_recorded_without_abort():
    plan = {
        "objective": "含非法模块",
        "steps": [
            {"module": "direct_injection", "rationale": "ok", "num_variants": 1},
            {"module": "not_a_real_module", "rationale": "坏"},
            {"module": "indirect_injection", "rationale": "继续", "num_variants": 1},
        ],
    }
    report = await audit_plan_and_execute(
        planner=FixedPlanLLM(plan),
        target_factory=_factory,
        task=DEFAULT_TASK,
        compare_defense=False,
        fail_fast=False,
    )
    assert "not_a_real_module" in report.modules_planned
    bad = [s for s in report.steps if s.module == "not_a_real_module"]
    assert len(bad) == 1 and bad[0].error and "未知" in bad[0].error
    assert "indirect_injection" in report.modules_executed


@pytest.mark.asyncio
async def test_fail_fast_stops_after_error():
    plan = AuditPlan(
        objective="fail fast",
        steps=[
            AuditPlanStep(module="not_a_real_module", rationale="坏"),
            AuditPlanStep(module="direct_injection", rationale="不应执行", num_variants=1),
        ],
    )
    report = await audit_plan_and_execute(
        planner=FixedPlanLLM(plan),
        target_factory=_factory,
        task=DEFAULT_TASK,
        compare_defense=False,
        fail_fast=True,
    )
    assert len(report.steps) == 1
    assert report.steps[0].module == "not_a_real_module"
    assert report.steps[0].error
    assert "direct_injection" not in [s.module for s in report.steps]


@pytest.mark.asyncio
async def test_max_steps_truncates_plan():
    plan = AuditPlan(
        objective="截断",
        steps=[
            AuditPlanStep(module="direct_injection", num_variants=1),
            AuditPlanStep(module="indirect_injection", num_variants=1),
            AuditPlanStep(module="privilege_escalation", num_variants=1),
            AuditPlanStep(module="data_exfiltration", num_variants=1),
        ],
    )
    report = await audit_plan_and_execute(
        planner=FixedPlanLLM(plan),
        target_factory=_factory,
        task=DEFAULT_TASK,
        max_steps=2,
        compare_defense=False,
    )
    assert report.modules_planned == ["direct_injection", "indirect_injection"]
    assert len(report.steps) == 2
