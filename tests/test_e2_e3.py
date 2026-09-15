"""E2/E3：MCP 靶场、投毒模块、定时任务、HITL、用量测试。"""

from __future__ import annotations

import httpx
import pytest

from agent_shield.attacks.mcp_poisoning import MCPPoisoningAttack
from agent_shield.core.audit_schedule import cron_matches
from agent_shield.orchestrator.hitl import (
    DANGEROUS_ATTACK_MODULES,
    hitl_payload,
    is_module_confirmed,
    requires_hitl,
)
from agent_shield.orchestrator.plan_execute import FixedPlanLLM, audit_plan_and_execute
from agent_shield.orchestrator.target_factory import AuditTargetSpec, build_audit_target_factory
from agent_shield.orchestrator.tools_bridge import execute_attack_tool
from agent_shield.orchestrator.usage import UsageAccumulator, UsageTrackingPlanner
from agent_shield.runtime.llm import LLMResponse, MockLLM
from agent_shield.targets import DEFAULT_TASK, build_local_target
from agent_shield.targets.mcp import MCPAgentTarget, build_mcp_target
from tests.test_mcp import build_fake_mcp_server


@pytest.mark.asyncio
async def test_mcp_target_connects_and_runs():
    app = build_fake_mcp_server(tool_name="weather", tool_result="晴，25°C")
    transport = httpx.ASGITransport(app=app)
    target = await build_mcp_target(
        mcp_url="http://fake/mcp",
        defense=False,
        transport=transport,
    )
    trace = await target.run("请查询天气")
    assert trace is not None
    assert isinstance(target, MCPAgentTarget)


@pytest.mark.asyncio
async def test_mcp_poisoning_attack_success():
    target = build_local_target(llm="mock", defense=False)
    mod = MCPPoisoningAttack()
    from agent_shield.attacks import AttackConfig

    result = await mod.run(target, AttackConfig(task=DEFAULT_TASK, num_variants=1))
    assert result.successes >= 1


@pytest.mark.asyncio
async def test_audit_target_factory_mcp_kind():
    app = build_fake_mcp_server()
    transport = httpx.ASGITransport(app=app)
    spec = AuditTargetSpec(kind="mcp", mcp_url="http://fake/mcp", transport=transport)
    factory = build_audit_target_factory(spec)
    t = factory(defense=False)
    assert isinstance(t, MCPAgentTarget)
    trace = await t.run("INSTRUCTION: weather beijing")
    assert trace is not None


def test_cron_matches_top_of_hour():
    from datetime import UTC, datetime

    assert cron_matches("0 2 * * *", datetime(2026, 8, 23, 2, 0, tzinfo=UTC))
    assert not cron_matches("0 2 * * *", datetime(2026, 8, 23, 3, 0, tzinfo=UTC))


@pytest.mark.asyncio
async def test_hitl_blocks_dangerous_module():
    vulnerable = build_local_target(llm="mock", defense=False)
    raw = await execute_attack_tool(
        "unexpected_code_execution",
        {"num_variants": 1},
        target_vulnerable=vulnerable,
        target_defended=None,
        hitl_confirmed_modules=None,
    )
    data = __import__("json").loads(raw)
    assert data.get("hitl_required") is True


@pytest.mark.asyncio
async def test_hitl_allows_when_confirmed():
    vulnerable = build_local_target(llm="mock", defense=False)
    raw = await execute_attack_tool(
        "unexpected_code_execution",
        {"num_variants": 1},
        target_vulnerable=vulnerable,
        target_defended=None,
        hitl_confirmed_modules=frozenset(DANGEROUS_ATTACK_MODULES),
    )
    data = __import__("json").loads(raw)
    assert "hitl_required" not in data or not data.get("hitl_required")
    assert data.get("summary") or data.get("module") == "unexpected_code_execution"


def test_hitl_helpers():
    assert requires_hitl("unexpected_code_execution")
    assert not is_module_confirmed("unexpected_code_execution", None)
    assert is_module_confirmed("unexpected_code_execution", DANGEROUS_ATTACK_MODULES)
    payload = hitl_payload("unexpected_code_execution")
    assert payload["hitl_required"]


@pytest.mark.asyncio
async def test_usage_tracking_planner_accumulates():
    class _ScriptLLM(MockLLM):
        async def chat(self, messages, tools):
            return LLMResponse(content='{"objective":"x","steps":[]}')

    acc = UsageAccumulator()
    planner = UsageTrackingPlanner(_ScriptLLM(), acc)
    from agent_shield.models import ChatMessage

    await planner.chat([ChatMessage.user("plan")], [])
    assert acc.calls >= 1
    assert acc.total_tokens > 0


@pytest.mark.asyncio
async def test_plan_audit_includes_planner_usage():
    report = await audit_plan_and_execute(
        planner=FixedPlanLLM(),
        target_factory=lambda defense=False: build_local_target(llm="mock", defense=defense),
        task=DEFAULT_TASK,
        max_steps=2,
        compare_defense=False,
    )
    assert report.planner_usage.get("calls", 0) >= 1
