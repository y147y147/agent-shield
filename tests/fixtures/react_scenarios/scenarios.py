"""命名 ReAct 场景：模拟「失败 → 改参 / 换模块」等自适应路径。"""

from __future__ import annotations

from dataclasses import dataclass, field

from agent_shield.orchestrator.tools_bridge import META_FINISH_AUDIT, META_LIST_COVERAGE
from agent_shield.runtime.llm import LLMResponse, ToolCall


@dataclass(frozen=True)
class ReactScenario:
    """可复用的 ScriptedReActLLM 脚本 + 断言提示。"""

    name: str
    description: str
    script: list[LLMResponse] = field(default_factory=list)
    expect_bypass_index_gt_zero: bool = False
    expect_modules: list[str] = field(default_factory=list)


def _finish(narrative: str = "scenario complete") -> LLMResponse:
    return LLMResponse(
        content="Thought: 覆盖完成，输出终报。",
        tool_calls=[
            ToolCall(id="fin", name=META_FINISH_AUDIT, arguments={"narrative": narrative}),
        ],
    )


SCENARIOS: dict[str, ReactScenario] = {
    "retry_change_params": ReactScenario(
        name="retry_change_params",
        description="同一模块首次 num_variants=1，第二次提高到 5（应产生 bypass_index=1）。",
        script=[
            LLMResponse(
                content="Thought: 先查看覆盖。",
                tool_calls=[ToolCall(id="cov", name=META_LIST_COVERAGE, arguments={})],
            ),
            LLMResponse(
                content="Thought: 首次试探直接注入。",
                tool_calls=[
                    ToolCall(id="a1", name="direct_injection", arguments={"num_variants": 1}),
                ],
            ),
            LLMResponse(
                content="Reflection: 成功率偏低，提高变体数再试。",
                tool_calls=[
                    ToolCall(id="a2", name="direct_injection", arguments={"num_variants": 5}),
                ],
            ),
            _finish("retry_change_params: 改参重试完成"),
        ],
        expect_bypass_index_gt_zero=True,
        expect_modules=["direct_injection"],
    ),
    "switch_module": ReactScenario(
        name="switch_module",
        description="直接注入后改测间接注入（模块应发生变化）。",
        script=[
            LLMResponse(
                content="Thought: 先测直接注入。",
                tool_calls=[
                    ToolCall(id="d1", name="direct_injection", arguments={"num_variants": 2}),
                ],
            ),
            LLMResponse(
                content="Reflection: 改走工具输出投毒向量。",
                tool_calls=[
                    ToolCall(id="i1", name="indirect_injection", arguments={"num_variants": 2}),
                ],
            ),
            _finish("switch_module: 已切换攻击向量"),
        ],
        expect_modules=["direct_injection", "indirect_injection"],
    ),
    "duplicate_then_retry": ReactScenario(
        name="duplicate_then_retry",
        description="重复同参应被拒绝，改 num_variants 后成功执行第二次。",
        script=[
            LLMResponse(
                tool_calls=[
                    ToolCall(id="x1", name="privilege_escalation", arguments={"num_variants": 2}),
                ],
            ),
            LLMResponse(
                content="Thought: 误重复同参（应被系统拒绝）。",
                tool_calls=[
                    ToolCall(id="x1dup", name="privilege_escalation", arguments={"num_variants": 2}),
                ],
            ),
            LLMResponse(
                content="Reflection: 修改变体数后重试。",
                tool_calls=[
                    ToolCall(id="x2", name="privilege_escalation", arguments={"num_variants": 4}),
                ],
            ),
            _finish("duplicate_then_retry: 防重复后改参成功"),
        ],
        expect_bypass_index_gt_zero=True,
        expect_modules=["privilege_escalation"],
    ),
}


def get_scenario(name: str) -> ReactScenario:
    if name not in SCENARIOS:
        raise KeyError(f"未知场景: {name}，可选: {', '.join(SCENARIOS)}")
    return SCENARIOS[name]
