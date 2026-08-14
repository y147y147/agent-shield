"""核心模型单元测试。"""

from agent_shield.models import AgentTrace, BlockedCall, ChatMessage, ToolCall, TraceStep


def _trace_with_run_command() -> AgentTrace:
    step = TraceStep(
        tool_calls=[ToolCall(id="c1", name="run_command", arguments={"command": "touch /tmp/agent-shield-pwned"})],
        tool_outputs=[ChatMessage.tool("exit=0", "c1", "run_command")],
    )
    return AgentTrace(task="t", steps=[step])


def test_has_tool_call_matches_fragment():
    trace = _trace_with_run_command()
    assert trace.has_tool_call("run_command", command="agent-shield-pwned")
    assert not trace.has_tool_call("run_command", command="rm -rf")
    assert not trace.has_tool_call("web_search")


def test_has_tool_call_arg_substring():
    step = TraceStep(tool_calls=[ToolCall(id="c2", name="read_file", arguments={"path": "/etc/passwd"})])
    trace = AgentTrace(task="t", steps=[step])
    assert trace.has_tool_call("read_file", path="/etc/")


def test_blocked_calls_flat():
    step = TraceStep(blocked_calls=[BlockedCall(tool_call_id="c1", tool="run_command", arguments={"command": "rm -rf /"}, reason="denied")])
    trace = AgentTrace(task="t", steps=[step])
    assert len(trace.blocked_calls()) == 1


def test_chat_message_factories():
    m = ChatMessage.tool("out", "c1", "web_search")
    assert m.role == "tool" and m.tool_call_id == "c1" and m.name == "web_search"
    assert ChatMessage.system("x").role == "system"


def test_attack_result_summary():
    from agent_shield.models import AttackCase, AttackResult, AttackVerdict

    result = AttackResult(
        module="m",
        cases=[
            AttackCase(module="m", verdict=AttackVerdict.SUCCESS, severity="critical"),
            AttackCase(module="m", verdict=AttackVerdict.BLOCKED),
            AttackCase(module="m", verdict=AttackVerdict.FAILED),
        ],
    )
    s = result.summary()
    assert s["successes"] == 1 and s["blocked"] == 1 and s["failed"] == 1
    assert result.success_rate == 1 / 3
