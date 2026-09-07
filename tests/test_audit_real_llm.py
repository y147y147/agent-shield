"""C2：ReAct 场景验收 + 真实 LLM 集成测试（可选）。"""

from __future__ import annotations

import os

import pytest

from agent_shield.models import AuditSessionReport
from agent_shield.orchestrator.react_loop import ScriptedReActLLM, audit_agent_loop
from agent_shield.runtime.llm import OpenAICompatLLM
from agent_shield.targets import DEFAULT_TASK, build_local_target
from tests.fixtures.react_scenarios import SCENARIOS, get_scenario


def _factory(*, defense: bool = False):
    return build_local_target(llm="mock", defense=defense)


def _audit_llm_config() -> dict[str, str] | None:
    """读取 AUDIT_LLM_* 或 OPENAI_* 环境变量；未配置 model 时返回 None。"""
    model = os.environ.get("AUDIT_LLM_MODEL") or os.environ.get("OPENAI_MODEL")
    if not model:
        return None
    api_key = os.environ.get("AUDIT_LLM_API_KEY") or os.environ.get("OPENAI_API_KEY") or ""
    base_url = os.environ.get("AUDIT_LLM_BASE_URL") or os.environ.get("OPENAI_BASE_URL") or ""
    return {"model": model, "api_key": api_key, "base_url": base_url}


@pytest.mark.parametrize("scenario_name", list(SCENARIOS.keys()))
@pytest.mark.asyncio
async def test_react_scenario_offline(scenario_name: str):
    """V-C3：脚本化场景离线验收（失败→改参 / 换模块 / 防重复）。"""
    scenario = get_scenario(scenario_name)
    events: list[dict] = []

    report = await audit_agent_loop(
        planner=ScriptedReActLLM(scenario.script),
        target_factory=_factory,
        task=DEFAULT_TASK,
        max_turns=16,
        compare_defense=False,
        on_event=events.append,
    )

    assert isinstance(report, AuditSessionReport)
    assert report.mode == "react"
    executed = report.modules_executed

    for mod in scenario.expect_modules:
        assert mod in executed, f"场景 {scenario_name} 应执行模块 {mod}"

    if scenario.expect_bypass_index_gt_zero:
        bypasses = [s.bypass_index for s in report.steps if not s.defense_on]
        assert any(b > 0 for b in bypasses), f"场景 {scenario_name} 应有 bypass_index > 0"

    if scenario_name == "duplicate_then_retry":
        assert any(
            "禁止无 Observation 重复" in (e.get("text") or "")
            for e in events
            if e.get("type") == "error"
        )


@pytest.mark.integration
@pytest.mark.asyncio
async def test_real_llm_react_audit_finish():
    """V-C4：真实 LLM react 审计（需 AUDIT_LLM_MODEL + API Key）。"""
    cfg = _audit_llm_config()
    if not cfg:
        pytest.skip("未设置 AUDIT_LLM_MODEL 或 OPENAI_MODEL")

    planner = OpenAICompatLLM(
        model=cfg["model"],
        api_key=cfg["api_key"] or None,
        base_url=cfg["base_url"] or None,
        timeout=60,
    )

    report = await audit_agent_loop(
        planner=planner,
        target_factory=_factory,
        task=DEFAULT_TASK,
        max_turns=8,
        compare_defense=False,
        include_mock_only=False,
    )

    parsed = AuditSessionReport.model_validate(report.model_dump())
    assert parsed.mode == "react"
    assert parsed.vectors_covered >= 1
    assert parsed.risk_level in {"critical", "high", "medium", "low", "info"}


@pytest.mark.integration
@pytest.mark.asyncio
async def test_real_llm_plan_audit():
    """真实 LLM plan 模式冒烟（可选）。"""
    cfg = _audit_llm_config()
    if not cfg:
        pytest.skip("未设置 AUDIT_LLM_MODEL 或 OPENAI_MODEL")

    from agent_shield.orchestrator.plan_execute import audit_plan_and_execute

    planner = OpenAICompatLLM(
        model=cfg["model"],
        api_key=cfg["api_key"] or None,
        base_url=cfg["base_url"] or None,
        timeout=60,
    )

    report = await audit_plan_and_execute(
        planner=planner,
        target_factory=_factory,
        task=DEFAULT_TASK,
        max_steps=3,
        compare_defense=False,
        include_mock_only=False,
    )

    assert report.mode == "plan"
    assert len(report.modules_planned) >= 1
