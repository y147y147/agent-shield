"""防护层抽象：GuardRail（策略检查 + 输出清洗）。"""

from __future__ import annotations

from abc import ABC

from pydantic import BaseModel

from agent_shield.models import ToolCall


class ToolCallDecision(BaseModel):
    """一次工具调用的处置决定。"""

    allowed: bool
    reason: str = ""


class GuardRail(ABC):
    """智能体运行时防护模块基类。

    - check_tool_call: 工具调用前检查（如策略引擎，deny 即拦截）；
    - sanitize_tool_output: 工具输出喂给 LLM 前清洗（如注入检测器）。
    """

    name: str = "base"

    def check_tool_call(self, call: ToolCall) -> ToolCallDecision:
        return ToolCallDecision(allowed=True, reason="no policy")

    def sanitize_tool_output(self, call: ToolCall, output: str) -> str:
        return output
