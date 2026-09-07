"""Phase B：ReAct 主循环单测。"""

from __future__ import annotations

import pytest

from agent_shield.models import AuditSessionReport
from agent_shield.orchestrator.react_loop import (
    DefaultReActLLM,
    ScriptedReActLLM,
    audit_agent_loop,
)
from agent_shield.orchestrator.tools_bridge import META_FINISH_AUDIT
from agent_shield.runtime.llm import LLMResponse, ToolCall
from agent_shield.targets import DEFAULT_TASK, build_local_target


def _factory(*, defense: bool = False):
    return build_local_target(llm="mock", defense=defense)


@pytest.mark.asyncio
async def test_default_react_e2e():
    report = await audit_agent_loop(
        planner=DefaultReActLLM(),
        target_factory=_factory,
        task=DEFAULT_TASK,
        max_turns=12,
        compare_defense=True,
    )
    assert isinstance(report, AuditSessionReport)
    assert report.mode == "react"
    assert report.vectors_covered >= 3
    assert report.risk_level in {"critical", "high", "medium", "low", "info"}
    assert "离线" in report.narrative or report.narrative == ""


@pytest.mark.asyncio
async def test_scripted_changes_params_on_retry():
    """首次 num_variants=1，第二次 num_variants=5 → 参数应变化。"""
    script = [
        LLMResponse(
            content="Thought: 首次尝试",
            tool_calls=[ToolCall(id="a1", name="direct_injection", arguments={"num_variants": 1})],
        ),
        LLMResponse(
            content="Thought: 提高变体",
            tool_calls=[ToolCall(id="a2", name="direct_injection", arguments={"num_variants": 5})],
        ),
        LLMResponse(
            tool_calls=[ToolCall(id="fin", name=META_FINISH_AUDIT, arguments={"narrative": "done"})],
        ),
    ]
    report = await audit_agent_loop(
        planner=ScriptedReActLLM(script),
        target_factory=_factory,
        task=DEFAULT_TASK,
        max_turns=8,
        compare_defense=False,
    )
    variants = [s.bypass_index for s in report.steps if s.module == "direct_injection" and not s.defense_on]
    assert 0 in variants and 1 in variants
    assert report.narrative == "done"


@pytest.mark.asyncio
async def test_bypass_limit_blocks_sixth_attempt():
    """同一模块第 6 次调用应被 bypass 上限拒绝（默认 5）。"""
    calls = [
        LLMResponse(
            tool_calls=[ToolCall(id=f"c{i}", name="direct_injection", arguments={"num_variants": i + 1})]
        )
        for i in range(6)
    ]
    calls.append(
        LLMResponse(
            tool_calls=[ToolCall(id="fin", name=META_FINISH_AUDIT, arguments={})],
        )
    )
    events: list[dict] = []

    def sink(e: dict) -> None:
        events.append(e)

    report = await audit_agent_loop(
        planner=ScriptedReActLLM(calls),
        target_factory=_factory,
        task=DEFAULT_TASK,
        max_turns=20,
        max_bypass_per_module=5,
        compare_defense=False,
        on_event=sink,
    )
    vuln_steps = [s for s in report.steps if s.module == "direct_injection" and not s.defense_on]
    assert len(vuln_steps) == 5
    assert any("bypass 上限" in (e.get("text") or "") for e in events if e.get("type") == "error")


@pytest.mark.asyncio
async def test_session_report_validates():
    report = await audit_agent_loop(
        planner=DefaultReActLLM(),
        target_factory=_factory,
        task=DEFAULT_TASK,
        compare_defense=False,
    )
    parsed = AuditSessionReport.model_validate(report.model_dump())
    assert parsed.mode == "react"
