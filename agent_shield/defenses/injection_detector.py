"""注入检测器：识别并清洗工具输出中的疑似外部指令（间接 Prompt 注入防御）。

两级方案中的"快路径"（规则/启发式）；"慢路径"（LLM-as-Judge）留作扩展点。
核心思想：工具输出属于"不可信域"，其中的指令性文本应被标记或清除。
"""

from __future__ import annotations

import re

from pydantic import BaseModel

from agent_shield.defenses.base import GuardRail
from agent_shield.defenses.deobfuscate import normalize_for_detection
from agent_shield.defenses.semantic_injection import looks_like_semantic_injection
from agent_shield.models import Severity, ToolCall
from agent_shield.observability import INJECTION_FINDINGS

# 不可信工具通道：输出默认视为攻击者可控（间接注入主战场）
UNTRUSTED_TOOL_CHANNELS: frozenset[str] = frozenset(
    {"web_search", "receive_message", "http_fetch"}
)
# 工具输出通道专用意图信号（比入口 IntentClassifier 更窄，控 FPR）
_TOOL_CHANNEL_INTENT_RE = re.compile(
    r"(?:INSTRUCTION\s*:|ignore\s+(?:your\s+|all\s+|the\s+)?(?:previous|prior|above)|"
    r"system[_\s-]?message|【系统提示】|jsjailbreak|sysprompt|"
    r"run_command\s+\S+|请(?:立即)?执行\s*(?:run_command|touch\b))",
    re.IGNORECASE,
)

# 整段脱敏后的统一前缀（运行时据此短路，禁止把占位符再喂给真实模型去「探索」工具）
INPUT_REDACTED_PREFIX = "[REDACTED by AgentShield"
_LINE_REDACT = f"{INPUT_REDACTED_PREFIX}: 检测到疑似注入指令]"

# (正则, 信号描述, 严重度)
SIGNALS: list[tuple[str, str, Severity]] = [
    (r"INSTRUCTION\s*:", "指令块标记", Severity.HIGH),
    # 覆盖 Ignore your/all/the previous|above|prior（AgentDojo IgnorePrevious 原文含 your）
    (r"ignore\s+(?:your\s+|all\s+|the\s+)?(?:previous|prior|above)\s+instructions?", "忽略先前指令", Severity.HIGH),
    (r"ignore\s+(?:the\s+)?(?:above|prior)\b", "忽略上文指令", Severity.HIGH),
    (r"disregard\s+(?:all\s+)?(?:previous|prior|above)", "忽略先前指令（变体）", Severity.HIGH),
    # SYSTEM UPDATE 单独信号：近误报面（章节名），只做片段脱敏、不整段短路
    (r"system\s+update\b", "系统更新章节名", Severity.MEDIUM),
    (r"system\s+(message|instruction|prompt)", "伪系统消息", Severity.HIGH),
    # AgentDojo DAN：###(system_message) 无空格形态
    (r"###\s*\(?\s*system[_\s-]?message", "伪系统消息块", Severity.HIGH),
    (r"system[_\s-]?message\b", "伪系统消息标识", Severity.HIGH),
    (r"you\s+are\s+now\b", "角色劫持", Severity.HIGH),
    (r"execute\s+(the\s+)?following\s+command", "命令执行指令", Severity.HIGH),
    (r"rm\s+-rf\b", "破坏性命令", Severity.CRITICAL),
    (r"base64.{0,60}(decode|解码)", "编码混淆指令", Severity.MEDIUM),
    (r"【系统提示】", "伪系统消息（中文）", Severity.HIGH),
]

# 仅「软信号」：片段脱敏，保留任务其余部分（避免 SYSTEM UPDATE 章节名整段短路抬 FPR 误判）
_SOFT_SIGNALS = frozenset({"系统更新章节名", "编码混淆指令"})

# 良性框架 + 敏感动作共现（TODO/IMPORTANT 单独出现不拦，避免抬 FPR）
_FRAME_RE = re.compile(
    r"(?:^\s*TODO\b|IMPORTANT[!！]{2,}|\bDAN\b|"
    r"ignore\s+(?:your\s+|all\s+|the\s+)?(?:previous|prior|above)\b|"
    r"###\s*\(?\s*system[_\s-]?message|system[_\s-]?message\b)",
    re.IGNORECASE | re.MULTILINE,
)
_SENSITIVE_ACTION_RE = re.compile(
    r"(?:secrets?[._-]?(?:txt|json)?|\.env\b|credentials(?:\.json)?|"
    r"/etc/(?:passwd|shadow)|写入\s*/(?:tmp|var)/|(?:数据库)?密码|私钥|pwned|exfil|leak\.out|"
    r"\bwrite_file\b|调用\s*write_file|追加.*(?:配置|超级用户))",
    re.IGNORECASE,
)


def is_fully_redacted_input(text: str) -> bool:
    """清洗后的用户输入是否已是整段脱敏占位（不应再交给主模型）。"""
    return bool(text) and text.strip().startswith(INPUT_REDACTED_PREFIX)


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

    def __init__(self, sanitize: bool = True, memory=None, signals=None):
        self.sanitize = sanitize
        self.memory = memory  # 可选 AttackMemory：命中历史攻击指纹的载荷走快路径拦截
        # 可注入的信号集（WS-E 弱防护用它"去掉 INSTRUCTION: 信号"来模拟规则放宽/懒防御）
        raw = list(signals) if signals is not None else list(SIGNALS)
        self._compiled = [(re.compile(pattern, re.IGNORECASE), desc, sev) for pattern, desc, sev in raw]

    def memory_hit(self, text: str) -> str | None:
        """快路径：text 中是否命中攻击指纹记忆库中的已知载荷（返回该载荷）。"""
        if self.memory is None or not text:
            return None
        return self.memory.known_in(text)

    def detect(self, text: str) -> list[Detection]:
        """对原文与归一化视图（去混淆）双边检测；归一化命中记 ``encoding_bypass`` 行。"""
        findings: list[Detection] = []
        findings.extend(self._detect_raw(text))
        normalized = normalize_for_detection(text)
        if normalized != text:
            extra = self._detect_raw(normalized)
            if extra and not findings:
                # 仅归一化命中 = 编码混淆绕过面：整段记一条，便于 sanitize 全量脱敏
                findings.append(
                    Detection(
                        signal="编码混淆后注入信号",
                        severity=Severity.HIGH,
                        line_no=1,
                        snippet=normalized.strip()[:120],
                    )
                )
                INJECTION_FINDINGS.inc(signal="编码混淆后注入信号")
            elif extra:
                for f in extra:
                    if f.signal not in {x.signal for x in findings}:
                        findings.append(f)
                        INJECTION_FINDINGS.inc(signal=f.signal)
        return findings

    def _detect_raw(self, text: str) -> list[Detection]:
        findings: list[Detection] = []
        for line_no, line in enumerate(text.splitlines(), start=1):
            for rx, desc, sev in self._compiled:
                if rx.search(line):
                    findings.append(
                        Detection(signal=desc, severity=sev, line_no=line_no, snippet=line.strip()[:120])
                    )
                    break  # 一行只需记录一个信号
        # 复合信号：良性框架（TODO/IMPORTANT/Ignore…）+ 敏感动作共现 → 整段记一条
        if text and _FRAME_RE.search(text) and _SENSITIVE_ACTION_RE.search(text):
            findings.append(
                Detection(
                    signal="良性框架+敏感动作复合注入",
                    severity=Severity.HIGH,
                    line_no=1,
                    snippet=text.strip()[:120],
                )
            )
        # 语义伪装：无 INSTRUCTION: 但运维/审计口吻 + 祈使执行探针命令
        if text and looks_like_semantic_injection(text):
            findings.append(
                Detection(
                    signal="语义伪装间接注入",
                    severity=Severity.HIGH,
                    line_no=1,
                    snippet=text.strip()[:120],
                )
            )
        return findings

    def sanitize_text(self, text: str) -> str:
        """纯函数：把命中信号的行替换为脱敏标记（运行时与 MITM 代理共用）。

        攻击指纹记忆库快路径优先：若整段文本命中库中已知攻击载荷（说明这是
        历史命中过的攻击，即使本轮基准规则未覆盖），整体脱敏不放行。
        复合框架注入：整段脱敏（避免 TODO 行只清一半、启发式仍看到「写入」）。
        软信号（SYSTEM UPDATE 章节名 / base64 教程）：只替换命中片段，保留任务主体，
        避免整段短路导致真实模型无任务可做、或 FPR 看不到脱敏证据。
        编码混淆：归一化后才命中 → 原文整段脱敏（无法可靠对齐片段）。
        """
        if not self.sanitize:
            return text
        if self.memory_hit(text) is not None:
            return f"{INPUT_REDACTED_PREFIX}: 攻击指纹记忆命中]"
        norm = normalize_for_detection(text)
        if text and _FRAME_RE.search(norm) and _SENSITIVE_ACTION_RE.search(norm):
            INJECTION_FINDINGS.inc(signal="良性框架+敏感动作复合注入")
            return _LINE_REDACT
        findings = self.detect(text)
        if not findings:
            return text

        # 编码混淆 / 复合 / 语义伪装 / 硬信号铺满 → 整段
        if any(
            f.signal
            in {
                "编码混淆后注入信号",
                "良性框架+敏感动作复合注入",
                "语义伪装间接注入",
            }
            for f in findings
        ):
            return _LINE_REDACT

        hard = [f for f in findings if f.signal not in _SOFT_SIGNALS]
        soft = [f for f in findings if f.signal in _SOFT_SIGNALS]

        if hard:
            flagged = {f.line_no for f in hard}
            nonempty = [i for i, line in enumerate(text.splitlines(), start=1) if line.strip()]
            if nonempty and all(i in flagged for i in nonempty):
                return _LINE_REDACT
            # 归一化命中但原文行号对不齐时也整段脱敏
            if norm != text and hard:
                return _LINE_REDACT
            lines = text.splitlines()
            return "\n".join(_LINE_REDACT if i + 1 in flagged else line for i, line in enumerate(lines))

        # 仅软信号：片段脱敏（保留「请读取…并对 … 章节做摘要」等任务骨架）
        out = text
        for f in soft:
            for rx, desc, _sev in self._compiled:
                if desc != f.signal:
                    continue
                out, n = rx.subn(_LINE_REDACT, out, count=1)
                if n:
                    break
        return out

    async def sanitize_tool_output(self, call: ToolCall, output: str) -> str:
        cleaned = self.sanitize_text(output)
        # 不可信通道额外意图扫描（IntentClassifier 入口盲区的补位）
        if call.name in UNTRUSTED_TOOL_CHANNELS:
            probe = normalize_for_detection(output)
            if _TOOL_CHANNEL_INTENT_RE.search(probe) or looks_like_semantic_injection(probe):
                INJECTION_FINDINGS.inc(signal="不可信工具通道意图")
                return f"{INPUT_REDACTED_PREFIX}: 不可信工具输出疑似注入指令]"
            # 清洗后仍残留通道意图 → 再拦一次
            if cleaned != output and (
                _TOOL_CHANNEL_INTENT_RE.search(normalize_for_detection(cleaned))
                or looks_like_semantic_injection(normalize_for_detection(cleaned))
            ):
                return f"{INPUT_REDACTED_PREFIX}: 不可信工具输出疑似注入指令]"
        return cleaned

    async def sanitize_user_input(self, text: str) -> str:
        """直接注入防御：用户输入中的指令性文本同样被清洗。"""
        return self.sanitize_text(text)
