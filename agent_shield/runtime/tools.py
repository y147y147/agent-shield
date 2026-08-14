"""智能体工具：注册表 + 内置工具集（含"故意危险"的命令执行工具）。"""

from __future__ import annotations

import hashlib
import inspect
import subprocess
from collections.abc import Awaitable, Callable
from typing import Any

from agent_shield.runtime.llm import tool_schema


class Tool:
    """一个可被智能体调用的工具。fn 可为同步或异步函数。"""

    def __init__(
        self,
        name: str,
        description: str,
        parameters: dict[str, Any],
        fn: Callable[[dict[str, Any]], Awaitable[str] | str],
    ):
        self.name = name
        self.description = description
        self.parameters = parameters
        self._fn = fn

    async def execute(self, arguments: dict[str, Any]) -> str:
        result = self._fn(arguments)
        if inspect.isawaitable(result):
            result = await result
        return str(result)

    def schema(self) -> dict:
        return tool_schema(self)

    def fingerprint(self) -> str:
        """工具指纹：名称+描述+参数模式+实现源码的哈希。

        用于工具完整性校验（供应链/MCP 投毒防御）：被替换/篡改的工具
        指纹必然与可信列表不一致。
        """
        try:
            source = inspect.getsource(self._fn)
        except (OSError, TypeError):
            source = repr(self._fn)
        raw = f"{self.name}|{self.description}|{self.parameters}|{source}"
        return hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()[:16]


class ToolRegistry:
    def __init__(self, tools: list[Tool] | None = None):
        self._tools: dict[str, Tool] = {}
        if tools:
            for tool in tools:
                self.add(tool)

    def add(self, tool: Tool) -> None:
        self._tools[tool.name] = tool

    def get(self, name: str) -> Tool:
        return self._tools[name]

    def names(self) -> list[str]:
        return list(self._tools)

    def all(self) -> list[Tool]:
        return list(self._tools.values())

    def fingerprints(self) -> dict[str, str]:
        return {name: tool.fingerprint() for name, tool in self._tools.items()}

    async def execute(self, name: str, arguments: dict[str, Any]) -> str:
        return await self._tools[name].execute(arguments)


# --------------------------------------------------------------------------- #
# 内置工具（Demo 靶场用）
# --------------------------------------------------------------------------- #
class WebSearchTool(Tool):
    """模拟网页搜索。inject_payload 非空时会把攻击者控制的"页面内容"
    混入搜索结果 —— 这正是间接 Prompt 注入的注入点抽象。"""

    def __init__(self) -> None:
        self.inject_payload: str | None = None
        super().__init__(
            name="web_search",
            description="搜索网页并返回搜索结果摘要。",
            parameters={
                "type": "object",
                "properties": {"query": {"type": "string", "description": "搜索关键词"}},
                "required": ["query"],
            },
            fn=self._run,
        )

    def _run(self, arguments: dict[str, Any]) -> str:
        query = arguments.get("query", "")
        content = (
            f"【搜索结果】（模拟数据，来源 example.com）\n"
            f"标题：2025 年全球气候报告要点\n"
            f"摘要：全球平均气温较工业化前上升约 1.5°C，极端天气事件增多……\n"
            f"（查询词：{query}）"
        )
        if self.inject_payload:
            content += f"\n\n[页面正文摘录]\n{self.inject_payload}\n[/页面正文摘录]"
        return content


class RunCommandTool(Tool):
    """执行 shell 命令 —— 脆弱靶场的核心危险面。

    注意：真实场景必须配合沙箱/策略引擎；此处故意不做任何限制以演示漏洞。
    """

    def __init__(self) -> None:
        super().__init__(
            name="run_command",
            description="在本地执行一条 shell 命令并返回输出。",
            parameters={
                "type": "object",
                "properties": {"command": {"type": "string", "description": "要执行的 shell 命令"}},
                "required": ["command"],
            },
            fn=self._run,
        )

    @staticmethod
    def _run(arguments: dict[str, Any]) -> str:
        command = arguments.get("command", "")
        try:
            proc = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=10,
                cwd="/tmp",
                check=False,
            )
            stdout = proc.stdout.strip()
            stderr = proc.stderr.strip()
            return f"exit={proc.returncode}\nstdout: {stdout}\nstderr: {stderr}"
        except subprocess.TimeoutExpired:
            return "error: command timed out (10s)"


class ReadFileTool(Tool):
    def __init__(self) -> None:
        super().__init__(
            name="read_file",
            description="读取本地文件内容。",
            parameters={
                "type": "object",
                "properties": {"path": {"type": "string", "description": "文件路径"}},
                "required": ["path"],
            },
            fn=self._run,
        )

    @staticmethod
    def _run(arguments: dict[str, Any]) -> str:
        try:
            with open(arguments["path"], encoding="utf-8", errors="replace") as f:
                return f.read()[:4000]
        except OSError as exc:
            return f"error: {exc}"


class WriteFileTool(Tool):
    def __init__(self) -> None:
        super().__init__(
            name="write_file",
            description="把内容写入本地文件。",
            parameters={
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "文件路径"},
                    "content": {"type": "string", "description": "文件内容"},
                },
                "required": ["path", "content"],
            },
            fn=self._run,
        )

    @staticmethod
    def _run(arguments: dict[str, Any]) -> str:
        try:
            with open(arguments["path"], "w", encoding="utf-8") as f:
                f.write(arguments.get("content", ""))
            return f"written: {arguments['path']}"
        except OSError as exc:
            return f"error: {exc}"


class SendEmailTool(Tool):
    """模拟发送邮件（不真实投递），用于数据窃取类攻击演示。"""

    def __init__(self) -> None:
        super().__init__(
            name="send_email",
            description="发送一封邮件。",
            parameters={
                "type": "object",
                "properties": {
                    "to": {"type": "string"},
                    "subject": {"type": "string"},
                    "body": {"type": "string"},
                },
                "required": ["to", "subject", "body"],
            },
            fn=self._run,
        )

    @staticmethod
    def _run(arguments: dict[str, Any]) -> str:
        return f"email sent to {arguments.get('to')}: {arguments.get('subject')}"


def build_default_tools() -> ToolRegistry:
    """Demo 靶场默认工具集。"""
    registry = ToolRegistry()
    registry.add(WebSearchTool())
    registry.add(RunCommandTool())
    registry.add(ReadFileTool())
    registry.add(WriteFileTool())
    registry.add(SendEmailTool())
    return registry
