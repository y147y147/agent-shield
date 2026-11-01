"""失控智能体攻击（ASI-10）：Mock 端到端 + 真实载体（非 Mock 目标）测法。"""

from agent_shield.attacks import AttackConfig, RogueAgentAttack
from agent_shield.attacks.rogue_agent import REAL_CARRIER_TASKS
from agent_shield.models import AgentTrace, AttackVerdict
from agent_shield.runtime.agent import AgentRuntime
from agent_shield.runtime.llm import LLMClient, LLMResponse, ToolCall
from agent_shield.runtime.tools import build_default_tools
from agent_shield.targets import build_local_target
from agent_shield.targets.base import AgentTarget
from agent_shield.targets.local import LocalAgentTarget


class _StubTarget(AgentTarget):
    """无 runtime 的目标（模拟 HTTP 黑盒），真实载体分支应优雅降级为 FAILED。"""

    name = "stub"
    description = "stub target without runtime/llm"

    async def run(self, task: str) -> AgentTrace:
        return AgentTrace(task=task)


class _ScriptedLLM(LLMClient):
    """脚本化假 LLM：每条任务的首轮（末条为用户消息）返回预设工具调用，
    执行完成后收尾（模拟"无条件服从"的失控模型）。"""

    name = "scripted"

    def __init__(self, calls: list[ToolCall]) -> None:
        self._calls = calls

    async def chat(self, messages: list, tools: list) -> LLMResponse:
        if messages and messages[-1].role == "user":
            return LLMResponse(tool_calls=self._calls)
        return LLMResponse(content="（脚本）完成。")


def _build_scripted_target(calls: list[ToolCall], *, defense: bool = False) -> LocalAgentTarget:
    from agent_shield.defenses import (
        AutonomyGuard,
        CallBudgetGuard,
        InjectionDetector,
        InterAgentChannelGuard,
        MemoryIntegrityGuard,
        PolicyEngine,
        ToolIntegrityGuard,
    )

    registry = build_default_tools()
    guardrails = []
    if defense:
        guardrails.extend(
            [
                InjectionDetector(sanitize=True),
                PolicyEngine(),
                CallBudgetGuard(max_calls=24),
                ToolIntegrityGuard(registry),
                AutonomyGuard(max_autonomy_credit=8),
                MemoryIntegrityGuard(),
                InterAgentChannelGuard(),
            ]
        )
    runtime = AgentRuntime(llm=_ScriptedLLM(calls), tools=registry, guardrails=guardrails, max_steps=12)
    return LocalAgentTarget(runtime, name="scripted-vulnerable")


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


async def test_real_carrier_success_when_model_complies():
    """真实载体：脚本化模型对权威越权请求直接执行 → SUCCESS（ASI-10 实战化打穿）。"""
    attack = RogueAgentAttack()
    target = _build_scripted_target(
        [ToolCall(id="call_1", name="read_file", arguments={"path": "/etc/passwd"})]
    )
    result = await attack.run(target, AttackConfig(num_variants=3))
    assert result.total == 3  # 真实载体：num_variants 个权威任务语境
    assert result.successes == 3
    case = result.cases[0]
    assert case.verdict == AttackVerdict.SUCCESS
    assert "真实载体（权威任务语境，无注入标记）" in " ".join(case.evidence)
    assert case.payload == REAL_CARRIER_TASKS[0]  # payload 是权威任务语境
    assert case.trace.has_executed_tool_call("read_file", path="/etc/passwd")


async def test_real_carrier_failed_when_model_refuses():
    """真实载体：脚本化模型拒止（只给文本）→ FAILED，evidence 措辞为"模型拒止/未越权"。"""
    attack = RogueAgentAttack()
    target = _build_scripted_target([])
    result = await attack.run(target, AttackConfig(num_variants=2))
    assert result.total == 2
    assert result.failed == 2
    assert "模型拒止/未越权" in " ".join(result.cases[0].evidence)


async def test_real_carrier_blocked_when_defended():
    """真实载体 + 全量防线：越权读取被策略引擎拦截 → BLOCKED。"""
    attack = RogueAgentAttack()
    target = _build_scripted_target(
        [ToolCall(id="call_1", name="read_file", arguments={"path": "/etc/passwd"})],
        defense=True,
    )
    result = await attack.run(target, AttackConfig(num_variants=1))
    assert result.successes == 0
    assert result.cases[0].verdict == AttackVerdict.BLOCKED


async def test_graceful_fallback_without_runtime():
    attack = RogueAgentAttack()
    result = await attack.run(_StubTarget(), AttackConfig(num_variants=1))
    assert result.total == 1
    assert result.successes == 0
    assert result.cases[0].verdict == AttackVerdict.FAILED
    assert "模型拒止/未越权" in " ".join(result.cases[0].evidence)


def test_module_maps_to_asi_10():
    assert RogueAgentAttack().owasp_asi == "ASI-10"
