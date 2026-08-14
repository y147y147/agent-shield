"""工具完整性校验：只允许调用指纹与可信列表一致的工具。

防御对象：工具投毒（AML.T0104 / ASI-02）—— 攻击者通过供应链或恶意 MCP
server 替换/注册同名工具，工具在正常任务中被调用时执行隐藏恶意动作。
本防护在调用前校验工具指纹（名称+描述+参数模式+实现源码哈希），
不匹配即拒绝 —— 相当于给智能体的工具加了"软件签名校验"。
"""

from __future__ import annotations

from agent_shield.defenses.base import GuardRail, ToolCallDecision
from agent_shield.models import ToolCall
from agent_shield.runtime.tools import ToolRegistry


class ToolIntegrityGuard(GuardRail):
    """工具完整性校验。"""

    name = "tool_integrity"

    def __init__(self, registry: ToolRegistry, trusted: dict[str, str] | None = None):
        self.registry = registry
        # 默认以当前注册表快照为可信基线（构建防护时即固化）
        self.trusted = trusted if trusted is not None else registry.fingerprints()

    async def check_tool_call(self, call: ToolCall) -> ToolCallDecision:
        try:
            tool = self.registry.get(call.name)
        except KeyError:
            return ToolCallDecision(allowed=False, reason=f"tool not in registry: {call.name}")
        current = tool.fingerprint()
        if self.trusted.get(call.name) != current:
            return ToolCallDecision(
                allowed=False,
                reason=f"tool integrity mismatch: {call.name} 被替换/篡改（指纹不一致）",
            )
        return ToolCallDecision(allowed=True, reason="tool integrity ok")
