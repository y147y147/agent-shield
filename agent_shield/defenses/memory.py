"""记忆库完整性 + 写入审计（MemoryIntegrityGuard）。

目标：任何"写入持久记忆/记忆库"的操作内容若夹带注入指令则拒绝落库（持久注入
ASI-06 的防护），并审计每次记忆读写。

内容检测用离线规则（defenses._instruction），不依赖 LLM。
"""

from __future__ import annotations

from agent_shield.defenses._instruction import contains_instruction, redact_instruction_lines
from agent_shield.defenses.base import GuardRail, ToolCallDecision
from agent_shield.models import ToolCall


def _extract_content(arguments: dict, key: str) -> str:
    """从调用参数中提取记忆内容：优先取顶层 key，否则递归找第一个同名子键。"""
    value = arguments.get(key)
    if isinstance(value, str):
        return value
    # 下潜搜索（如 {"params": {"content": "..."}}）
    for v in arguments.values():
        if isinstance(v, dict):
            found = _extract_content(v, key)
            if found:
                return found
    if isinstance(value, (int, float, bool)):
        return str(value)
    return ""


class MemoryIntegrityGuard(GuardRail):
    """拦截夹带注入指令的记忆写入，并对记忆读回内容做脱敏 + 审计每次读写。"""

    name = "memory_integrity"

    def __init__(
        self,
        memory_tools: set[str] | None = None,
        content_param: str = "content",
        audit_store=None,
    ):
        self.memory_tools = set(memory_tools) if memory_tools else {"remember", "save_memory", "append_memory"}
        self.content_param = content_param
        self.audit_store = audit_store

    def _is_memory_tool(self, name: str) -> bool:
        return name in self.memory_tools

    def record_memory_event(self, kind: str, detail: str) -> None:
        """kind in {read, write, blocked}。写入审计（可选）。"""
        if self.audit_store is None:
            return
        self.audit_store.record_event(
            direction="memory",
            model="",
            action=kind,
            detail=detail,
        )

    async def check_tool_call(self, call: ToolCall) -> ToolCallDecision:
        if not self._is_memory_tool(call.name):
            return ToolCallDecision(allowed=True, reason="allowed")
        content = _extract_content(call.arguments, self.content_param)
        if contains_instruction(content):
            self.record_memory_event("blocked", f"{call.name} 疑似持久注入，拒绝写入记忆")
            return ToolCallDecision(
                allowed=False,
                reason="疑似持久注入，拒绝写入记忆（MemoryIntegrityGuard）",
            )
        self.record_memory_event("write", f"{call.name} 记忆写入")
        return ToolCallDecision(allowed=True, reason="allowed")

    async def sanitize_tool_output(self, call: ToolCall, output: str) -> str:
        # 记忆类工具的读回内容同样扫描，命中即脱敏
        if not self._is_memory_tool(call.name):
            return output
        self.record_memory_event("read", f"{call.name} 记忆读取")
        return redact_instruction_lines(output)