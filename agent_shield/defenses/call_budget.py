"""调用预算：单次运行限制工具调用次数（资源滥用 / DoS 防御，ASI-08）。"""

from __future__ import annotations

from agent_shield.defenses.base import GuardRail, ToolCallDecision
from agent_shield.models import ToolCall


class CallBudgetGuard(GuardRail):
    """执行预算：超过 max_calls 的工具调用一律拒绝。"""

    name = "call_budget"

    def __init__(self, max_calls: int = 8):
        self.max_calls = max_calls
        self._count = 0

    def reset(self) -> None:
        """每次 run 开始时重置计数。"""
        self._count = 0

    async def check_tool_call(self, call: ToolCall) -> ToolCallDecision:
        self._count += 1
        if self._count > self.max_calls:
            return ToolCallDecision(allowed=False, reason=f"call budget exceeded ({self.max_calls})")
        return ToolCallDecision(allowed=True, reason=f"within budget ({self._count}/{self.max_calls})")
