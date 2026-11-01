"""WS-C 自适应防御（依模型回答动态升级）：见 docs/plan-v2.md Phase 2。

把防线从"二进制开/关的静态门"升级为"按越界信号事件**只升不降**的策略档位状态机"：

    normal → strict → locked

- **normal**：不额外拦截（与无自适应时行为一致，FPR 不受影响）；
- **strict**：拦截高危工具（run_command）—— 触发一次"越界信号事件"后升到此档；
- **locked**：在 strict 基础上再拦外发（send_email）等，全面收紧。

触发源（快路径直觉 + 慢路径扩展点）：
- 监督器在工具输出 / 用户输入中检测到注入信号（复用 InjectionDetector 规则）→ 升一档；
- 也可由外部显式 ``escalate(reason)`` 触发（给 LLM-as-Judge 慢路径预留的扩展点）。

红线：**动态防御只允许"更严"，绝不赠与权限**（与 plan 防蔓延红线一致）。level **只升不降**，
``reset()`` 不降档 —— 连跑多任务时一旦越界就保持高警戒，跨任务存续。
"""

from __future__ import annotations

import logging

from agent_shield.defenses.base import GuardRail, ToolCallDecision
from agent_shield.defenses.injection_detector import InjectionDetector
from agent_shield.models import ToolCall
from agent_shield.observability import get_logger, log_event

logger = get_logger("defenses.adaptive")

# 档位序：只升序，normal → strict → locked
_LEVEL_RANK = {"normal": 0, "strict": 1, "locked": 2}

# strict 起拦截的高危工具
_STRICT_BLOCKED = frozenset({"run_command"})
# locked 额外拦截的外发等敏感工具
_LOCKED_BLOCKED = frozenset({"run_command", "send_email"})


class AdaptivePolicySupervisor(GuardRail):
    """响应监督器：按越界信号现场升档，档位只升不降，越严越收。”

    挂进靶场运行循环后：
    - ``sanitize_tool_output / sanitize_user_input`` 观察文本，检测到注入信号即升档；
    - ``check_tool_call`` 依当前档位拦截高危工具；
    - ``reset`` 不降档（跨任务存续的越界记忆）。
    """

    name = "adaptive_policy_supervisor"

    def __init__(self, detector: InjectionDetector | None = None, start_level: str = "normal"):
        if start_level not in _LEVEL_RANK:
            raise ValueError(f"起始档位必须 ∈ {list(_LEVEL_RANK)}，收到: {start_level!r}")
        self._detector = detector or InjectionDetector(sanitize=False)
        self.level = start_level
        # 升档事件日志：(档位, 原因)
        self.events: list[tuple[str, str]] = []
        self.blocked_count = 0
        # 已触发的越界信号事件（同一文本去重，避免单轮内重复计数）
        self._seen: set[str] = set()

    @property
    def rank(self) -> int:
        return _LEVEL_RANK[self.level]

    # ------------------------------------------------------------------ #
    def escalate(self, reason: str) -> str:
        """升一档（只升不降，locked 后不再变）。返回当前档位。"""
        if self.level == "locked":
            return self.level
        nxt = "strict" if self.level == "normal" else "locked"
        self.level = nxt
        self.events.append((nxt, reason))
        log_event(logger, "adaptive_escalated", level=logging.INFO, state=nxt, reason=reason)
        return self.level

    def reset(self) -> None:
        # 只升不降：每次 run 调用时不降档（越界记忆跨任务存续）
        pass

    # ------------------------------------------------------------------ #
    # 观察钩子：检测越界信号
    # ------------------------------------------------------------------ #
    def _observe(self, text: str) -> None:
        if self.rank >= _LEVEL_RANK["locked"] or not text:
            return  # 已封顶或空内容，不再升档
        key = text  # 不同来源的注入话术视为"不同越界信号事件"
        if self._detector.detect(text):
            if key in self._seen:
                return  # 同一段文本反复出现不再叠加升档（避免单轮内重复计数）
            self._seen.add(key)
            self.escalate("检测到越界注入信号（新事件）")

    async def sanitize_tool_output(self, call: ToolCall, output: str) -> str:
        self._observe(output)
        return output  # 监督器不篡改内容，清洗交给注入检测器等守卫

    async def sanitize_user_input(self, text: str) -> str:
        self._observe(text)
        return text

    # ------------------------------------------------------------------ #
    # 决策钩子：依档位拦截高危工具
    # ------------------------------------------------------------------ #
    async def check_tool_call(self, call: ToolCall) -> ToolCallDecision:
        blocked = _LOCKED_BLOCKED if self.rank >= _LEVEL_RANK["locked"] else _STRICT_BLOCKED
        if call.name in blocked:
            self.blocked_count += 1
            return ToolCallDecision(
                allowed=False,
                reason=f"adaptive[{self.level}] 拦截高危工具 {call.name}（越界后自适应收严）",
            )
        return ToolCallDecision(allowed=True, reason=f"adaptive[{self.level}] allow")