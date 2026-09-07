"""Target 适配层：本地进程内靶场 + HTTP 黑盒 + MCP 靶场。"""

from agent_shield.targets.base import AgentTarget
from agent_shield.targets.http import HttpAgentTarget
from agent_shield.targets.local import DEFAULT_TASK, LocalAgentTarget, build_local_target
from agent_shield.targets.mcp import MCPAgentTarget, build_mcp_target

__all__ = [
    "DEFAULT_TASK",
    "AgentTarget",
    "HttpAgentTarget",
    "LocalAgentTarget",
    "MCPAgentTarget",
    "build_local_target",
    "build_mcp_target",
]
