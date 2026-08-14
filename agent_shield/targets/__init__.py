"""Target 适配层：本地进程内靶场 + HTTP 黑盒目标。"""

from agent_shield.targets.base import AgentTarget
from agent_shield.targets.http import HttpAgentTarget
from agent_shield.targets.local import DEFAULT_TASK, LocalAgentTarget, build_local_target

__all__ = ["DEFAULT_TASK", "AgentTarget", "HttpAgentTarget", "LocalAgentTarget", "build_local_target"]
