"""离线指令特征扫描：MemoryIntegrityGuard / InterAgentChannelGuard 共享。

纯规则（不依赖 LLM），用于检测文本中的疑似注入指令。检测到即判定为注入，
供记忆写入拦截 / 智能体间通道净化使用。
"""

from __future__ import annotations

import re

# 指令性文本特征（保持离线可控；与 injection_detector.SIGNALS 有交集但独立维护）
_INSTRUCTION_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(p, re.IGNORECASE)
    for p in (
        r"INSTRUCTION\s*:",
        r"ignore\s+(?:all\s+)?previous\s+(?:instructions|prompts)",  # 忽略先前指令
        r"disregard\s+(?:all\s+)?previous",  # 忽略先前指令（变体）
        r"system\s+(?:update|message|instruction|prompt)",  # 伪系统消息
        r"系统提示\s*(词|消息)?\s*[:：]?\s*覆盖",  # 系统提示词覆盖
        r"你\s*是\s*(?:一个)?\s*(?:系统|AI|助手|智能体)",  # 角色劫持
        r"you\s+are\s+now\b",  # 角色劫持（英文）
        r"覆盖\s*(?:你|本)?\s*(?:的)?\s*(?:系统提示词|指令|设定)",  # 覆盖系统提示词
    )
)


def find_instruction_lines(text: str) -> list[int]:
    """返回命中注入特征的**行号**（1-based）。用于逐行脱敏。"""
    flagged: list[int] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        if any(rx.search(line) for rx in _INSTRUCTION_PATTERNS):
            flagged.append(line_no)
    return flagged


def contains_instruction(text: str) -> bool:
    """是否夹带注入指令（整体一次扫描）。"""
    return any(rx.search(text) for rx in _INSTRUCTION_PATTERNS)


def redact_instruction_lines(text: str, marker: str = "[REDACTED by AgentShield: 指令内容已脱敏]") -> str:
    """把命中注入特征的整行替换为脱敏标记，其余文本保留。"""
    flagged = set(find_instruction_lines(text))
    if not flagged:
        return text
    return "\n".join(marker if (i + 1) in flagged else line for i, line in enumerate(text.splitlines()))