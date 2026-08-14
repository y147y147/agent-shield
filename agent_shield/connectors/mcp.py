"""MCP（Model Context Protocol）连接器：最小 JSON-RPC 客户端。

- MCPClient: initialize / tools/list / tools/call（HTTP transport）；
- mcp_tools_to_registry: 把远程 MCP server 暴露的工具接入 ToolRegistry，
  从而让智能体直接调用 MCP 工具 —— 其输出同样经过注入检测/策略防护。

MCP 安全背景：恶意 MCP server 可用工具名/描述劫持智能体上下文、在工具输出中
注入指令（参考 docs/attack-taxonomy.md 的 AML.T0104 工具投毒）。
"""

from __future__ import annotations

import httpx

from agent_shield.runtime.tools import Tool, ToolRegistry

MCP_PROTOCOL_VERSION = "2024-11-05"


class MCPError(Exception):
    """MCP JSON-RPC 调用错误。"""


class MCPClient:
    """MCP HTTP 传输的最小客户端（仅需 initialize / tools/list / tools/call）。"""

    def __init__(
        self,
        base_url: str,
        headers: dict[str, str] | None = None,
        timeout: float = 30.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.headers = {"Content-Type": "application/json", **(headers or {})}
        self.timeout = timeout
        self.transport = transport  # 测试时注入 ASGITransport
        self._request_id = 0
        self.server_info: dict | None = None

    async def _call(self, method: str, params: dict | None = None) -> dict:
        self._request_id += 1
        payload = {"jsonrpc": "2.0", "id": self._request_id, "method": method, "params": params or {}}
        async with httpx.AsyncClient(timeout=self.timeout, transport=self.transport) as client:
            resp = await client.post(self.base_url, json=payload, headers=self.headers)
            resp.raise_for_status()
        data = resp.json()
        if data.get("error"):
            raise MCPError(f"MCP error: {data['error']}")
        return data.get("result") or {}

    async def initialize(self) -> dict:
        """建立 MCP 会话（协议握手）。"""
        self.server_info = await self._call(
            "initialize",
            {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "agent-shield", "version": "0.1.0"},
            },
        )
        return self.server_info

    async def list_tools(self) -> list[dict]:
        result = await self._call("tools/list")
        return result.get("tools", [])

    async def call_tool(self, name: str, arguments: dict | None = None) -> str:
        result = await self._call("tools/call", {"name": name, "arguments": arguments or {}})
        texts = [c.get("text", "") for c in result.get("content", []) if c.get("type") == "text"]
        joined = "\n".join(texts)
        prefix = f"[mcp:{name}]"
        return f"{prefix} {joined}" if not result.get("isError") else f"{prefix} error: {joined}"


def mcp_tools_to_registry(client: MCPClient, mcp_tools: list[dict]) -> ToolRegistry:
    """把 MCP server 暴露的工具转换为本地 ToolRegistry（供 AgentRuntime 调用）。"""
    registry = ToolRegistry()
    for mcp_tool in mcp_tools:
        name = mcp_tool["name"]

        async def _fn(arguments: dict, _name: str = name) -> str:
            return await client.call_tool(_name, arguments)

        registry.add(
            Tool(
                name=name,
                description=mcp_tool.get("description", ""),
                parameters=mcp_tool.get("inputSchema") or {"type": "object", "properties": {}},
                fn=_fn,
            )
        )
    return registry


async def connect_mcp(base_url: str, **kwargs) -> tuple[MCPClient, ToolRegistry]:
    """连接 MCP server 并构建工具注册表（一步到位）。"""
    client = MCPClient(base_url, **kwargs)
    await client.initialize()
    return client, mcp_tools_to_registry(client, await client.list_tools())
