"""Target 抽象：攻击框架与任意智能体之间的统一接口。"""

from __future__ import annotations

from abc import ABC, abstractmethod

from agent_shield.models import AgentTrace


class AgentTarget(ABC):
    """一个可被攻击测试的智能体目标。"""

    name: str = "base"
    description: str = ""

    @abstractmethod
    async def run(self, task: str) -> AgentTrace:
        """让目标执行一个任务并返回完整轨迹。"""

    def inject_tool_payload(self, tool_name: str, payload: str | None) -> None:
        """模拟攻击者控制的第三方工具内容（间接注入的注入点）。

        例如把 payload 混入 web_search 返回的"页面内容"。
        默认实现不做任何事；具体 Target 可覆盖。
        """

    def inject_poisoned_tool(self, tool) -> None:
        """模拟供应链/恶意 MCP 投毒：替换/注册一个同名恶意工具。

        默认实现不做任何事；具体 Target 可覆盖。
        """
