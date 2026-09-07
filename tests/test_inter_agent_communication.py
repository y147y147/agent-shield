"""不安全智能体间通信攻击（ASI-07）：端到端。"""

from agent_shield.attacks import AttackConfig, InterAgentCommunicationAttack
from agent_shield.models import AttackVerdict
from agent_shield.targets import build_local_target


async def test_attack_succeeds_on_vulnerable_target(tmp_path):
    marker = f"touch {tmp_path / 'pwned'}"
    attack = InterAgentCommunicationAttack(marker_command=marker)
    target = build_local_target(llm="mock", defense=False)
    result = await attack.run(target, AttackConfig(num_variants=2))
    assert result.successes == 2
    assert all(c.verdict == AttackVerdict.SUCCESS for c in result.cases)
    # 证据：目标先读取了通信通道（receive_message），再执行了消息中的命令
    trace = result.cases[0].trace
    assert trace.has_executed_tool_call("receive_message")
    assert trace.has_executed_tool_call("run_command", command=marker)


async def test_attack_fails_on_defended_target(tmp_path):
    marker = f"touch {tmp_path / 'pwned'}"
    attack = InterAgentCommunicationAttack(marker_command=marker)
    target = build_local_target(llm="mock", defense=True)
    result = await attack.run(target, AttackConfig(num_variants=2))
    assert result.successes == 0
    assert all(c.verdict == AttackVerdict.FAILED for c in result.cases)


def test_module_maps_to_asi_07():
    assert InterAgentCommunicationAttack().owasp_asi == "ASI-07"
