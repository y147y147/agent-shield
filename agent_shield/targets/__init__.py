"""Target 适配层。"""

from agent_shield.targets.base import AgentTarget
from agent_shield.targets.local import DEFAULT_TASK, LocalAgentTarget, build_local_target

__all__ = ["DEFAULT_TASK", "AgentTarget", "LocalAgentTarget", "build_local_target"]
