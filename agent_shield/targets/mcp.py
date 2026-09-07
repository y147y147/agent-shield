"""MCP 靶场 Target：将远程 MCP server 工具接入本地 AgentRuntime。"""

from __future__ import annotations

from typing import Any

import httpx

from agent_shield.connectors.mcp import connect_mcp
from agent_shield.models import AgentTrace
from agent_shield.runtime.tools import Tool, ToolRegistry, build_default_tools
from agent_shield.targets.base import AgentTarget
from agent_shield.targets.local import build_local_target


class MCPAgentTarget(AgentTarget):
    """懒连接 MCP server，合并默认工具与 MCP 工具后复用 LocalAgentTarget。"""

    def __init__(
        self,
        *,
        mcp_url: str,
        llm: str = "mock",
        defense: bool = False,
        model: str | None = None,
        api_key: str | None = None,
        base_url: str | None = None,
        audit_store: Any = None,
        sandbox: bool = False,
        event_sink: Any = None,
        judge_llm: Any = None,
        timeout: float = 30.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.mcp_url = mcp_url
        self._llm = llm
        self._defense = defense
        self._model = model
        self._api_key = api_key
        self._api_base_url = base_url
        self._audit_store = audit_store
        self._sandbox = sandbox
        self._event_sink = event_sink
        self._judge_llm = judge_llm
        self._timeout = timeout
        self._transport = transport
        self._inner: AgentTarget | None = None
        self._mcp_client: Any = None
        mode = "defended" if defense else "vulnerable"
        self.name = f"mcp-agent[{mode}]"
        self.description = f"MCP 靶场（{mode}）— {mcp_url}"

    async def _ensure_connected(self) -> AgentTarget:
        if self._inner is not None:
            return self._inner
        client, mcp_registry = await connect_mcp(
            self.mcp_url,
            timeout=self._timeout,
            transport=self._transport,
        )
        self._mcp_client = client
        merged = build_default_tools()
        for tool in mcp_registry.all():
            merged.add(tool)
        self._inner = build_local_target(
            llm=self._llm,
            defense=self._defense,
            model=self._model,
            api_key=self._api_key,
            base_url=self._api_base_url,
            tools=merged,
            judge_llm=self._judge_llm,
            audit_store=self._audit_store,
            sandbox=self._sandbox,
            event_sink=self._event_sink,
        )
        return self._inner

    async def run(self, task: str) -> AgentTrace:
        inner = await self._ensure_connected()
        return await inner.run(task)

    def inject_tool_payload(self, tool_name: str, payload: str | None) -> None:
        if self._inner is not None:
            self._inner.inject_tool_payload(tool_name, payload)

    def inject_poisoned_tool(self, tool: Tool) -> None:
        if self._inner is not None:
            self._inner.inject_poisoned_tool(tool)


async def build_mcp_target(
    *,
    mcp_url: str,
    defense: bool = False,
    llm: str = "mock",
    model: str | None = None,
    api_key: str | None = None,
    base_url: str | None = None,
    audit_store: Any = None,
    sandbox: bool = False,
    event_sink: Any = None,
    judge_llm: Any = None,
    timeout: float = 30.0,
    transport: httpx.AsyncBaseTransport | None = None,
) -> MCPAgentTarget:
    """构建并预连接 MCP 靶场（测试/CLI 一次性初始化）。"""
    target = MCPAgentTarget(
        mcp_url=mcp_url,
        llm=llm,
        defense=defense,
        model=model,
        api_key=api_key,
        base_url=base_url,
        audit_store=audit_store,
        sandbox=sandbox,
        event_sink=event_sink,
        judge_llm=judge_llm,
        timeout=timeout,
        transport=transport,
    )
    await target._ensure_connected()
    return target


def merge_mcp_registry(base: ToolRegistry, mcp_registry: ToolRegistry) -> ToolRegistry:
    """合并默认工具与 MCP 工具（MCP 同名工具覆盖默认）。"""
    merged = ToolRegistry(base.all())
    for tool in mcp_registry.all():
        merged.add(tool)
    return merged
