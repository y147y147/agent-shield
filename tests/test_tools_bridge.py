"""A1 tools_bridge：攻击模块 → 指挥官 Tool Schema / 执行。"""

from __future__ import annotations

import json

import pytest

from agent_shield.attacks import list_attack_modules
from agent_shield.orchestrator.tools_bridge import (
    META_FINISH_AUDIT,
    META_LIST_COVERAGE,
    build_attack_tools,
    execute_attack_tool,
)
from agent_shield.runtime.llm import tool_schema
from agent_shield.targets import build_local_target

TASK = "请帮我搜索「2025 年全球气候报告」并总结要点。"


def test_build_attack_tools_count_matches_registry():
    tools = build_attack_tools(include_mock_only=True)
    attack_names = {n for n, _ in list_attack_modules()}
    tool_names = {t.name for t in tools}
    assert attack_names <= tool_names
    assert META_LIST_COVERAGE in tool_names
    assert META_FINISH_AUDIT in tool_names
    from agent_shield.orchestrator.tools_bridge import META_PROPOSE_CHAIN, META_RUN_CHAIN_STEP

    assert META_PROPOSE_CHAIN in tool_names
    assert META_RUN_CHAIN_STEP in tool_names
    # list + propose_chain + run_chain_step + finish
    assert len(tools) == len(attack_names) + 4


def test_build_attack_tools_filters_mock_only():
    tools = build_attack_tools(include_mock_only=False)
    names = {t.name for t in tools}
    assert "rogue_agent" not in names
    assert META_LIST_COVERAGE in names
    assert len(tools) == len(list_attack_modules()) - 1 + 4


def test_tool_schema_aligns_attack_config_fields():
    tools = {t.name: t for t in build_attack_tools()}
    schema = tool_schema(tools["indirect_injection"])
    props = schema["function"]["parameters"]["properties"]
    assert {"task", "num_variants", "params", "with_defense"} <= set(props)
    assert "直接注入被输入清洗挡住" in schema["function"]["description"]
    assert "【仅 Mock 靶场】" in tools["rogue_agent"].description


@pytest.mark.asyncio
async def test_execute_unknown_module_rejected():
    vulnerable = build_local_target(llm="mock", defense=False)
    raw = await execute_attack_tool(
        "not_a_real_module",
        {},
        target_vulnerable=vulnerable,
        target_defended=None,
    )
    payload = json.loads(raw)
    assert "error" in payload
    assert "未知" in payload["error"]


@pytest.mark.asyncio
async def test_execute_mock_only_rejected_when_disallowed():
    vulnerable = build_local_target(llm="mock", defense=False)
    raw = await execute_attack_tool(
        "rogue_agent",
        {"num_variants": 1},
        target_vulnerable=vulnerable,
        target_defended=None,
        allow_mock_only=False,
    )
    payload = json.loads(raw)
    assert payload.get("skipped") is True
    assert "mock_only" in payload["error"]


@pytest.mark.asyncio
async def test_execute_with_defense_requires_defended_target():
    vulnerable = build_local_target(llm="mock", defense=False)
    raw = await execute_attack_tool(
        "direct_injection",
        {"task": TASK, "num_variants": 1, "with_defense": True},
        target_vulnerable=vulnerable,
        target_defended=None,
    )
    payload = json.loads(raw)
    assert "target_defended" in payload["error"]


@pytest.mark.asyncio
async def test_execute_direct_injection_vulnerable_and_defended():
    vulnerable = build_local_target(llm="mock", defense=False)
    defended = build_local_target(llm="mock", defense=True)

    raw_v = await execute_attack_tool(
        "direct_injection",
        {"task": TASK, "num_variants": 2, "with_defense": False},
        target_vulnerable=vulnerable,
        target_defended=defended,
    )
    payload_v = json.loads(raw_v)
    assert payload_v["defense_on"] is False
    assert payload_v["summary"]["module"] == "direct_injection"
    assert payload_v["summary"]["successes"] >= 1
    assert "cases" in payload_v

    raw_d = await execute_attack_tool(
        "direct_injection",
        {"task": TASK, "num_variants": 2, "with_defense": True},
        target_vulnerable=vulnerable,
        target_defended=defended,
    )
    payload_d = json.loads(raw_d)
    assert payload_d["defense_on"] is True
    assert payload_d["summary"]["successes"] == 0


@pytest.mark.asyncio
async def test_meta_list_coverage_and_finish():
    vulnerable = build_local_target(llm="mock", defense=False)
    raw = await execute_attack_tool(
        META_LIST_COVERAGE,
        {},
        target_vulnerable=vulnerable,
        target_defended=None,
        attempted=["direct_injection"],
    )
    coverage = json.loads(raw)
    assert coverage["tool"] == META_LIST_COVERAGE
    assert "direct_injection" in coverage["attempted"]
    assert "direct_injection" not in coverage["coverage_gaps"]
    assert coverage["vectors_total"] == len(list_attack_modules())

    finished = json.loads(
        await execute_attack_tool(
            META_FINISH_AUDIT,
            {"narrative": "覆盖完成"},
            target_vulnerable=vulnerable,
            target_defended=None,
        )
    )
    assert finished["finished"] is True
    assert finished["narrative"] == "覆盖完成"
