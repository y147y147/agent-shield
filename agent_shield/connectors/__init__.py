"""外部系统连接器：MCP（Model Context Protocol）等。"""

from agent_shield.connectors.mcp import (
    MCP_PROTOCOL_VERSION,
    MCPClient,
    MCPError,
    connect_mcp,
    mcp_tools_to_registry,
)

__all__ = ["MCP_PROTOCOL_VERSION", "MCPClient", "MCPError", "connect_mcp", "mcp_tools_to_registry"]
