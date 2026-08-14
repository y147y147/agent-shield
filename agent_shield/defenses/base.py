"""防护层抽象：GuardRail（策略检查 + 输出/输入清洗）。

所有钩子均为 async：LLM-as-Judge 等慢路径需要异步调用模型。
"""

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
    - sanitize_tool_output: 工具输出喂给 LLM 前清洗（如注入检测器）；
    - sanitize_user_input: 用户输入喂给 LLM 前清洗（直接注入防御）。
    """

    name: str = "base"

    async def check_tool_call(self, call: ToolCall) -> ToolCallDecision:
        return ToolCallDecision(allowed=True, reason="no policy")

    async def sanitize_tool_output(self, call: ToolCall, output: str) -> str:
        return output

    async def sanitize_user_input(self, text: str) -> str:
        return text
