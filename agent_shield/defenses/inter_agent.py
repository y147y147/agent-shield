"""智能体间通道策略（InterAgentChannelGuard）。

目标：对智能体间通信通道（receive_message）做来源校验 + 指令净化（ASI-07 防护）。

不可信同伴消息中的指令性文本被净化；可信同伴消息仍走一次纵深扫描。
"""

from __future__ import annotations

import re

from agent_shield.defenses._instruction import contains_instruction, redact_instruction_lines
from agent_shield.defenses.base import GuardRail, ToolCallDecision
from agent_shield.models import ToolCall

_SENDER_RE = re.compile(r"\[来自\s*(.+?)\s*的消息\]")


def parse_sender(output: str, default: str = "unknown") -> str:
    """从输出解析来源，形如 "[来自 agent-a 的消息]..."；缺省用 default。"""
    m = _SENDER_RE.search(output)
    return m.group(1).strip() if m else default


class InterAgentChannelGuard(GuardRail):
    """校验智能体间通道来源并净化不可信消息中的指令。"""

    name = "inter_agent_channel"

    def __init__(
        self,
        channel_tools: set[str] | None = None,
        allowlisted_peers: set[str] | None = None,
        audit_store=None,
    ):
        self.channel_tools = set(channel_tools) if channel_tools else {"receive_message", "send_message"}
        self.allowlisted_peers = set(allowlisted_peers or ())
        self.audit_store = audit_store

    def record_channel_event(self, kind: str, detail: str) -> None:
        if self.audit_store is None:
            return
        self.audit_store.record_event(direction="channel", model="", action=kind, detail=detail)

    async def sanitize_tool_output(self, call: ToolCall, output: str) -> str:
        if call.name not in self.channel_tools:
            return output
        sender = parse_sender(output, default=getattr(call, "name", "unknown"))
        trusted = sender in self.allowlisted_peers
        self.record_channel_event("recv", f"来自 {sender} 的消息（trusted={trusted}）")

        # 无论来源是否可信都做一次扫描（纵深）；不可信 + 命中才用专用脱敏标记
        if contains_instruction(output):
            if trusted:
                # 可信同伴：仍净化，但保留通用脱敏标记
                return redact_instruction_lines(output)
            # 不可信同伴：整段"不可信指令"替换为专用标记
            self.record_channel_event("redacted", f"不可信同伴 {sender} 消息中夹带指令")
            return _redact_untrusted(output)
        return output

    async def check_tool_call(self, call: ToolCall) -> ToolCallDecision:
        # send_message 类工具可按 allowlist 限制目标接收者（发送方向简配）。
        if call.name == "send_message" and self.allowlisted_peers:
            receiver = str(call.arguments.get("to") or call.arguments.get("recipient") or "").strip()
            if receiver and receiver not in self.allowlisted_peers:
                return ToolCallDecision(
                    allowed=False, reason=f"目标接收者不在可信同伴名单：{receiver}"
                )
        return ToolCallDecision(allowed=True, reason="allowed")


def _redact_untrusted(output: str) -> str:
    """把不可信同伴消息中的整段"不可信指令"替换为专用标记，其余文本保留。"""
    parts = []
    for line in output.splitlines():
        if contains_instruction(line):
            parts.append("[REDACTED by AgentShield: 不可信同伴消息]")
        else:
            parts.append(line)
    return "\n".join(parts)