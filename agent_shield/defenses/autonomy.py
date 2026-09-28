"""编排自主性上限（AutonomyGuard）。

目标：Agent 循环里限制单次任务（一次 run）内可累积的"敏感动作额度"，跨过阈值即
拦截并提示"需人工审批"，封堵权限累积 / 级联（ASI-08 级联、ASI-10 失控蔓延）。

每次 run 开始时 reset() 清零额度（按运行计数）。
"""

from __future__ import annotations

from agent_shield.defenses.base import GuardRail, ToolCallDecision
from agent_shield.models import ToolCall


class AutonomyGuard(GuardRail):
    """敏感动作额度预算：超限即拦截（需人工审批）。

    参数：
        sensitive_tools: 计入额度的敏感工具名集合。
        weight_map: 某工具额度权重（缺省 1）。
        max_autonomy_credit: 额度上限（float）。
        exclusive_actions: 可选：这些动作任意两个组合即硬拦截（如 write→run 代码执行链）。
    """

    name = "autonomy"

    def __init__(
        self,
        sensitive_tools: set[str] | None = None,
        weight_map: dict[str, int] | None = None,
        max_autonomy_credit: float = 6.0,
        exclusive_actions: list[str] | None = None,
    ):
        self.sensitive_tools = set(sensitive_tools) if sensitive_tools else {"run_command", "write_file", "send_email"}
        self.weight_map = dict(weight_map or {})
        self.max_autonomy_credit = float(max_autonomy_credit)
        self.exclusive_actions = list(exclusive_actions or [])
        self._credit = 0.0
        self._used_actions: set[str] = set()

    @property
    def credit_used(self) -> float:
        return self._credit

    def reset(self) -> None:
        self._credit = 0.0
        self._used_actions.clear()

    async def check_tool_call(self, call: ToolCall) -> ToolCallDecision:
        if call.name not in self.sensitive_tools:
            return ToolCallDecision(allowed=True, reason="allowed")
        weight = float(self.weight_map.get(call.name, 1))
        self._credit += weight
        self._used_actions.add(call.name)

        # 可选硬拦截：任意两个敏感动作组合即判"代码执行链"，不等累计超限
        if (
            len(self.exclusive_actions) >= 2
            and set(self.exclusive_actions) <= self._used_actions
        ):
            return ToolCallDecision(
                allowed=False,
                reason=f"exclusive sensitive action combo detected（{', '.join(sorted(self.exclusive_actions))}），需人工审批",
            )

        if self._credit > self.max_autonomy_credit:
            return ToolCallDecision(
                allowed=False,
                reason=(
                    f"autonomy limit reached（本轮敏感动作 {self._credit:.0f}/"
                    f"{self.max_autonomy_credit:.0f}），需人工审批"
                ),
            )
        return ToolCallDecision(allowed=True, reason="allowed")