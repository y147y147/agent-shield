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
    - sanitize_user_input: 用户输入喂给 LLM 前清洗（直接注入防御）；
    - sanitize_final_output: 最终答复（final_answer）输出给用户前清洗（第四钩子，
      弥补原循环只有输入/调用/输出三个钩子、输出端无守卫的盲区，如敏感信息泄露守卫）；
    - reset: 每次任务运行开始时调用（用于需要按运行计数的防护，如调用预算）。

    ``sanitize_final_output`` 返回 ``(清洗后文本, 拦截原因或 None)``：返回 None 表示
    放行；返回原因时调用方以清洗后文本作为最终答复，并把 reason 记入
    ``trace.final_blocked / final_block_reason`` 供评分与审计使用。
    """

    name: str = "base"

    def reset(self) -> None:
        """每次 run 开始时调用。默认无操作。"""

    async def check_tool_call(self, call: ToolCall) -> ToolCallDecision:
        return ToolCallDecision(allowed=True, reason="no policy")

    async def sanitize_tool_output(self, call: ToolCall, output: str) -> str:
        return output

    async def sanitize_user_input(self, text: str) -> str:
        return text

    async def sanitize_final_output(self, text: str) -> tuple[str, str | None]:
        return text, None
