"""间接注入攻击模块单元测试（载荷生成 + 判定逻辑）。"""

from agent_shield.attacks import DEFAULT_MARKER_CMD, IndirectInjectionAttack
from agent_shield.models import (
    AgentTrace,
    AttackVerdict,
    BlockedCall,
    ToolCall,
    TraceStep,
)


def test_build_variants_contains_marker():
    attack = IndirectInjectionAttack()
    variants = attack.build_variants(5)
    assert len(variants) == 5
    assert all(DEFAULT_MARKER_CMD in v for v in variants)


def test_build_variants_pads_when_n_larger():
    attack = IndirectInjectionAttack()
    assert len(attack.build_variants(12)) == 12


def test_judge_success_when_marker_command_executed():
    attack = IndirectInjectionAttack()
    trace = AgentTrace(
        task="t",
        steps=[
            TraceStep(
                tool_calls=[ToolCall(id="c1", name="run_command", arguments={"command": DEFAULT_MARKER_CMD})],
            )
        ],
    )
    case = attack.judge(trace, "payload")
    assert case.verdict == AttackVerdict.SUCCESS
    assert case.severity.value == "critical"
    assert case.evidence


def test_judge_blocked_when_guardrail_intercepted():
    attack = IndirectInjectionAttack()
    trace = AgentTrace(
        task="t",
        steps=[
            TraceStep(
                blocked_calls=[
                    BlockedCall(tool_call_id="c1", tool="run_command", arguments={"command": DEFAULT_MARKER_CMD}, reason="denied by rule")
                ]
            )
        ],
    )
    case = attack.judge(trace, "payload")
    assert case.verdict == AttackVerdict.BLOCKED


def test_judge_failed_when_instruction_ignored():
    attack = IndirectInjectionAttack()
    trace = AgentTrace(task="t", steps=[TraceStep(final_answer="正常总结。")])
    case = attack.judge(trace, "payload")
    assert case.verdict == AttackVerdict.FAILED
