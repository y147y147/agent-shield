"""M2 意图识别分类器（intent_classifier）：请求进主模型**之前**的轻量级前置过滤。

与规则快路径 InjectionDetector 互补：InjectionDetector 清"指令"（INSTRUCTION: 等
显式注入标记），意图分类器判"意图"（请求是否隐含恶意越狱/越权目的，即使措辞
完全中性）。命中即拦截/标记，``trace.intent_flag`` 记录来源（§5 schema 已预留）。

实现：确定性规则分类（关键词 + 目标动作白名单，零成本、CI 可测）；``targeted``
模式可再叠一层可选的 LLM 语义分类（judge_llm，真实模型，M2 决策门用）。

判定口径（与 AttackVerdict 对齐）：
- 命中恶意意图 → 拦截（blocked，reason 记 intent_classifier 类别）；
- 未命中 → 放行（模型正常处理，能力分不受影响）。
"""

from __future__ import annotations

import re

from agent_shield.defenses.base import GuardRail, ToolCallDecision
from agent_shield.models import ToolCall

# 恶意越狱意图信号（关键词族）：命中任一即判"有恶意意图"
INTENT_BLOCKED_PREFIX = "[意图分类器拦截]"
INTENT_SIGNALS: tuple[str, ...] = (
    "越狱",
    "绕过",
    "注入",
    "提权",
    "越权",
    "外发",
    "渗透",
    "删库",
    "删除",
    "取密码",
    "密码",
    "私钥",
    "攻击者",
    "evil",
    "exfil",
    "attacker",
    "INSTRUCTION",
    "jsjailbreak",
    "sysprompt",
    "泄露",
    "dump",
    "凭据",
    "窃取",
)

# 边界工具调用（命中即视为"越界动作意图"，即使措辞中性——工具冒充族的盲区）
BOUNDARY_TOOLS: tuple[str, ...] = ("send_email", "run_command", "read_file", "write_file")

_ACTION_WORDS = re.compile(r"(?:调用|执行|发送|读取|运行|使用|通过)")


def _classify(text: str, signals: tuple[str, ...], boundary_tools: tuple[str, ...]) -> tuple[bool, str]:
    """规则分类核心：返回 (是否命中恶意意图, 命中类别)。

    category：keyword（显式恶意词命中）/ boundary（中性措辞但要求边界工具动作）。
    """
    pattern = re.compile("|".join(re.escape(s) for s in signals), re.IGNORECASE)
    if pattern.search(text):
        return True, "keyword"
    # 边界动作意图：提到调用边界工具完成指定动作（覆盖工具升级/运维审计口吻盲区）
    lowered = text.lower()
    for tool in boundary_tools:
        if tool in lowered and _ACTION_WORDS.search(lowered):
            return True, "boundary"
    return False, ""


def classify_intent(text: str) -> tuple[bool, str]:
    """默认信号集下的规则分类（纯函数 API，供 CLI/测试直接调用）。"""
    return _classify(text, INTENT_SIGNALS, BOUNDARY_TOOLS)


class IntentClassifier(GuardRail):
    """意图识别分类器 GuardRail：请求进主模型前拦截恶意越狱意图。

    挂载位置：作为 sanitize_user_input 钩子的前置守卫（在 InjectionDetector 之前），
    命中即返回拦截标记；运行时把命中记入 ``trace.intent_flag``。
    """

    name = "intent_classifier"
    # 运行时状态：最近一次命中的类别（keyword/boundary），测试可断言
    last_hit_category: str = ""

    def __init__(self, signals: tuple[str, ...] = INTENT_SIGNALS,
                 boundary_tools: tuple[str, ...] = BOUNDARY_TOOLS, *, flag_field: str = "intent_flag"):
        self._signals = signals
        self._boundary_tools = boundary_tools
        self._flag_field = flag_field

    def is_malicious(self, text: str) -> tuple[bool, str]:
        return _classify(text, self._signals, self._boundary_tools)

    async def sanitize_user_input(self, text: str) -> str:
        """请求进主模型前：命中恶意意图 → 拦截占位（运行时识别该前缀即整体拦截）。"""
        hit, category = self.is_malicious(text)
        if hit:
            self.last_hit_category = category
            return f"{INTENT_BLOCKED_PREFIX}：{category}（请求已拦截）"
        return text

    async def check_tool_call(self, call: ToolCall) -> ToolCallDecision:
        # 工具调用侧不拦截（分类器只做入口过滤）；边界工具放行由 PolicyEngine 判定
        return ToolCallDecision(allowed=True, reason="intent classifier: entry filter only")
