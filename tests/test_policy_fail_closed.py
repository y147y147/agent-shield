"""策略引擎 fail-closed 语义测试：默认拒绝、通配兜底、显式放行。

背景（v1.0-M0）：旧实现把"未覆盖的工具"默认放行（fail-open），与文档里
"失败关闭"的宣传不一致 —— 新增一个工具就会自动失去防护。本文件锁定新的三层语义：

1. **未覆盖的工具** → 默认拒绝（可用 ``default_action`` 或 ``"*"`` 显式放行）；
2. **单条规则未写 action** → 默认拒绝（必须 ``action: allow`` 才放行）；
3. **语义解析失败 / 无法判定** → 拒绝。
"""

import pytest

from agent_shield.defenses import DEFAULT_POLICY, PolicyEngine
from agent_shield.models import ToolCall
from agent_shield.paths import demo_workdir


def _call(name: str, **arguments) -> ToolCall:
    return ToolCall(id="c1", name=name, arguments=arguments)


# --------------------------------------------------------------------------- #
# 1) 未覆盖工具：默认拒绝
# --------------------------------------------------------------------------- #
async def test_uncovered_tool_denied_by_default():
    engine = PolicyEngine()
    decision = await engine.check_tool_call(_call("brand_new_tool", a="b"))
    assert not decision.allowed
    assert "fail-closed" in decision.reason
    assert "brand_new_tool" in decision.reason


async def test_default_policy_declares_fail_closed_default():
    assert DEFAULT_POLICY["default_action"] == "deny"


async def test_default_action_key_is_not_treated_as_tool_name():
    engine = PolicyEngine()
    assert "default_action" not in engine.policy


async def test_default_action_allow_lets_uncovered_tool_through():
    """显式声明 allow 时，未覆盖工具放行（给"观测模式/影子模式"留出口）。"""
    engine = PolicyEngine(default_action="allow")
    assert engine.default_action == "allow"
    assert (await engine.check_tool_call(_call("brand_new_tool", a="b"))).allowed


async def test_default_action_can_come_from_policy_dict():
    engine = PolicyEngine(policy={"default_action": "allow", "send_email": {"action": "deny"}})
    assert (await engine.check_tool_call(_call("whatever_tool"))).allowed
    assert not (await engine.check_tool_call(_call("send_email", to="x@y.z", body="b"))).allowed


def test_invalid_default_action_rejected():
    with pytest.raises(ValueError):
        PolicyEngine(default_action="maybe")


# --------------------------------------------------------------------------- #
# 2) 通配兜底规则与优先级
# --------------------------------------------------------------------------- #
async def test_wildcard_rule_acts_as_uncovered_fallback():
    engine = PolicyEngine(policy={"*": {"action": "allow"}})
    assert (await engine.check_tool_call(_call("anything_at_all"))).allowed


async def test_exact_rule_takes_precedence_over_wildcard():
    engine = PolicyEngine(policy={"*": {"action": "allow"}, "send_email": {"action": "deny"}})
    assert (await engine.check_tool_call(_call("anything_at_all"))).allowed
    assert not (await engine.check_tool_call(_call("send_email", to="a@b.c", body="x"))).allowed


# --------------------------------------------------------------------------- #
# 3) 单条规则缺省 action 亦为拒绝；显式 allow 才放行
# --------------------------------------------------------------------------- #
async def test_rule_without_action_is_fail_closed():
    engine = PolicyEngine(policy={"custom_tool": {"deny": [r"evil"]}})
    assert not (await engine.check_tool_call(_call("custom_tool", q="hello"))).allowed
    assert not (await engine.check_tool_call(_call("custom_tool", q="evil"))).allowed


async def test_rule_with_allow_pattern_passes_matching_arguments():
    engine = PolicyEngine(policy={"custom_tool": {"allow": [r"^safe"]}})
    assert (await engine.check_tool_call(_call("custom_tool", q="safe query"))).allowed
    assert not (await engine.check_tool_call(_call("custom_tool", q="other query"))).allowed


# --------------------------------------------------------------------------- #
# 4) 可用性回归：合法只读工具必须仍然可用（安全 ≠ 不可用）
# --------------------------------------------------------------------------- #
async def test_default_policy_keeps_benign_tools_usable():
    engine = PolicyEngine()
    assert (await engine.check_tool_call(_call("web_search", query="2025 全球气候报告"))).allowed
    assert (await engine.check_tool_call(_call("receive_message"))).allowed

    root = demo_workdir()
    assert (await engine.check_tool_call(_call("read_file", path=str(root / "note.txt")))).allowed

    assert (await engine.check_tool_call(_call("run_command", command="ls -la"))).allowed


async def test_default_policy_still_denies_dangerous_and_uncovered():
    engine = PolicyEngine()
    assert not (await engine.check_tool_call(_call("read_file", path="/etc/passwd"))).allowed
    assert not (await engine.check_tool_call(_call("send_email", to="attacker@evil.com", body="x"))).allowed
    assert not (await engine.check_tool_call(_call("run_command", command="rm -rf /"))).allowed
    assert not (await engine.check_tool_call(_call("unknown_tool"))).allowed


# --------------------------------------------------------------------------- #
# 5) YAML 载入（default_action + 通配规则）
# --------------------------------------------------------------------------- #
async def test_from_yaml_supports_default_action_and_wildcard(tmp_path):
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(
        'default_action: deny\n'
        '"*":\n  action: allow\n'
        "send_email:\n  action: deny\n",
        encoding="utf-8",
    )
    engine = PolicyEngine.from_yaml(str(policy_file))
    assert engine.default_action == "deny"
    assert (await engine.check_tool_call(_call("some_tool"))).allowed
    assert not (await engine.check_tool_call(_call("send_email", to="a@b.c"))).allowed
