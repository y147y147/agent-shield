"""注入检测器：识别并清洗工具输出中的疑似外部指令（间接 Prompt 注入防御）。

两级方案中的"快路径"（规则/启发式）；"慢路径"（LLM-as-Judge）留作扩展点。
核心思想：工具输出属于"不可信域"，其中的指令性文本应被标记或清除。
"""

from __future__ import annotations

import re

from pydantic import BaseModel

from agent_shield.defenses.base import GuardRail
from agent_shield.models import Severity, ToolCall

# (正则, 信号描述, 严重度)
SIGNALS: list[tuple[str, str, Severity]] = [
    (r"INSTRUCTION\s*:", "指令块标记", Severity.HIGH),
    (r"ignore\s+(all\s+)?previous\s+instructions", "忽略先前指令", Severity.HIGH),
    (r"disregard\s+(all\s+)?previous", "忽略先前指令（变体）", Severity.HIGH),
    (r"system\s+(update|message|instruction|prompt)", "伪系统消息", Severity.HIGH),
    (r"you\s+are\s+now\b", "角色劫持", Severity.HIGH),
    (r"execute\s+(the\s+)?following\s+command", "命令执行指令", Severity.HIGH),
    (r"rm\s+-rf\b", "破坏性命令", Severity.CRITICAL),
    (r"base64.{0,60}(decode|解码)", "编码混淆指令", Severity.MEDIUM),
    (r"【系统提示】", "伪系统消息（中文）", Severity.HIGH),
]


class Detection(BaseModel):
    signal: str
    severity: Severity
    line_no: int
    snippet: str


class InjectionDetector(GuardRail):
    """基于规则的注入检测器。

    - detect(text): 返回命中的信号列表；
    - sanitize_tool_output: 将命中信号的行替换为脱敏标记（默认开启）。
    """

    name = "injection_detector"

    def __init__(self, sanitize: bool = True):
        self.sanitize = sanitize
        self._compiled = [(re.compile(pattern, re.IGNORECASE), desc, sev) for pattern, desc, sev in SIGNALS]

    def detect(self, text: str) -> list[Detection]:
        findings: list[Detection] = []
        for line_no, line in enumerate(text.splitlines(), start=1):
            for rx, desc, sev in self._compiled:
                if rx.search(line):
                    findings.append(
                        Detection(signal=desc, severity=sev, line_no=line_no, snippet=line.strip()[:120])
                    )
                    break  # 一行只需记录一个信号
        return findings

    def sanitize_text(self, text: str) -> str:
        """纯函数：把命中信号的行替换为脱敏标记（运行时与 MITM 代理共用）。"""
        if not self.sanitize:
            return text
        findings = self.detect(text)
        if not findings:
            return text
        flagged = {f.line_no for f in findings}
        lines = text.splitlines()
        return "\n".join(
            "[REDACTED by AgentShield: 检测到疑似注入指令]" if i + 1 in flagged else line
            for i, line in enumerate(lines)
        )

    async def sanitize_tool_output(self, call: ToolCall, output: str) -> str:
        return self.sanitize_text(output)

    async def sanitize_user_input(self, text: str) -> str:
        """直接注入防御：用户输入中的指令性文本同样被清洗。"""
        return self.sanitize_text(text)
