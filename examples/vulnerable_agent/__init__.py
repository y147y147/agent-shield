"""故意有漏洞的 Demo 智能体靶场。

直接复用 agent_shield.targets.local 的构建器：

    from examples.vulnerable_agent import build_local_target

    target = build_local_target(llm="mock")          # 脆弱版（默认）
    target = build_local_target(llm="mock", defense=True)  # 加固版
"""

from agent_shield.targets import DEFAULT_TASK, LocalAgentTarget, build_local_target

__all__ = ["DEFAULT_TASK", "LocalAgentTarget", "build_local_target"]
