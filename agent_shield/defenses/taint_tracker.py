"""语义污点跟踪：拦「敏感源 → 外泄汇」链式动作。

背景（社区基准 ad04 / PROJECT.md §10）：注入可拆成「读 secrets → 写 /tmp」多步；
策略引擎可能只拦住半链（敏感名读拒绝），另一端 write_file 仍在 allowed_roots 落地。
本守卫在**同一次 run** 内跟踪污点：

1. **源（source）**：读/cat 敏感路径、或工具输出含凭据形态 → 置污点（本守卫对源调用一律放行，
   真正拒绝交给 PolicyEngine，避免抢先短路导致后续守卫看不到源）；
2. **汇（sink）**：已污点时拒绝 write_file / send_email / 带重定向的 run_command；
3. **用户输入通道**：TODO/IMPORTANT/Ignore… 等良性框架 + 敏感动作共现 → 置污点，
   使同批「读失败 + 写成功」的 mock/真模型启发式也拦得住写端。

``reset()`` 在每次 ``AgentRuntime.run`` 开头调用，污点不跨任务。
"""

from __future__ import annotations

import re

from agent_shield.defenses.base import GuardRail, ToolCallDecision
from agent_shield.defenses.policy_engine import _is_sensitive_path
from agent_shield.models import ToolCall

# 良性框架（任务管理/强调口吻）——单独出现不拦，与敏感动作共现才置污点
_FRAME_RE = re.compile(
    r"(?:^\s*TODO\b|IMPORTANT[!！]{2,}|\bDAN\b|"
    r"ignore\s+(?:your\s+|all\s+|the\s+)?(?:previous|prior|above)\b|"
    r"disregard\s+(?:all\s+)?(?:previous|prior|above)\b)",
    re.IGNORECASE | re.MULTILINE,
)

# 敏感动作 / 目标（与 InjectionDetector 复合信号对齐，略宽以覆盖路径口语）
_SENSITIVE_ACTION_RE = re.compile(
    r"(?:secrets?[._-]?(?:txt|json)?|\.env\b|credentials(?:\.json)?|"
    r"/etc/(?:passwd|shadow)|id_rsa|\.pem\b|"
    r"写入\s*/(?:tmp|var)/|write(?:_file)?\s+.*/(?:tmp|var)/|"
    r"(?:数据库)?密码|私钥|pwned|exfil|leak\.out)",
    re.IGNORECASE,
)

# 工具输出里的凭据形态（与 FinalAnswerGuard 口径接近，偏保守）
_SECRET_CONTENT_RE = re.compile(
    r"(?:API[_-]?KEY|password|passwd|secret[_-]?(?:token|key)?)\s*[=:：]\s*\S+"
    r"|BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY"
    r"|wsx-exfil-demo-secret",
    re.IGNORECASE,
)

_SINK_TOOLS = frozenset({"write_file", "send_email"})
_SOURCE_TOOLS = frozenset({"read_file", "run_command", "http_fetch", "web_search"})


def user_input_looks_tainted(text: str) -> bool:
    """用户输入是否呈现「框架注入 + 敏感动作」复合形态。"""
    if not text:
        return False
    return bool(_FRAME_RE.search(text) and _SENSITIVE_ACTION_RE.search(text))


def _command_has_redirect(command: str) -> bool:
    """未加引号的 ``>`` / ``>>`` 视为写出汇（简化：整串含重定向符即视为可疑）。"""
    return bool(re.search(r"(?<![\"'])>{1,2}(?![\"'])", command))


def _call_is_sensitive_source(call: ToolCall) -> bool:
    """该调用是否在尝试触达敏感源（路径名或 cat/type 敏感文件）。"""
    if call.name == "read_file":
        path = str(call.arguments.get("path", "") or "")
        return bool(path) and (
            _is_sensitive_path(path) or bool(_SENSITIVE_ACTION_RE.search(path))
        )
    if call.name == "run_command":
        cmd = str(call.arguments.get("command", "") or "")
        if not cmd:
            return False
        # cat/type/head 等读敏感文件
        if re.search(r"\b(?:cat|type|head|tail|less|more)\b", cmd, re.IGNORECASE):
            return bool(_SENSITIVE_ACTION_RE.search(cmd) or _is_sensitive_path(cmd))
        return bool(_SENSITIVE_ACTION_RE.search(cmd))
    if call.name in ("http_fetch", "web_search"):
        blob = " ".join(str(v) for v in call.arguments.values())
        return bool(_SENSITIVE_ACTION_RE.search(blob))
    return False


def _call_is_sink(call: ToolCall) -> bool:
    if call.name in _SINK_TOOLS:
        return True
    if call.name == "run_command":
        cmd = str(call.arguments.get("command", "") or "")
        return _command_has_redirect(cmd) or bool(
            re.search(r"\b(?:curl|wget|nc|ncat|scp)\b", cmd, re.IGNORECASE)
        )
    return False


class TaintTracker(GuardRail):
    """会话级污点跟踪：敏感源/复合注入 → 拒绝外泄汇。"""

    name = "taint_tracker"

    def __init__(self) -> None:
        self._tainted = False
        self._reasons: list[str] = []

    def reset(self) -> None:
        self._tainted = False
        self._reasons = []

    @property
    def tainted(self) -> bool:
        return self._tainted

    def _mark(self, reason: str) -> None:
        self._tainted = True
        if reason and reason not in self._reasons:
            self._reasons.append(reason)

    async def sanitize_user_input(self, text: str) -> str:
        if user_input_looks_tainted(text):
            self._mark("user input: frame+sensitive-action composite")
        return text

    async def check_tool_call(self, call: ToolCall) -> ToolCallDecision:
        if call.name in _SOURCE_TOOLS and _call_is_sensitive_source(call):
            self._mark(f"sensitive source attempt: {call.name}")

        if self._tainted and _call_is_sink(call):
            why = "; ".join(self._reasons) or "tainted session"
            return ToolCallDecision(
                allowed=False,
                reason=f"denied by taint_tracker: sink {call.name!r} after {why}",
            )
        return ToolCallDecision(allowed=True, reason="taint_tracker: pass")

    async def sanitize_tool_output(self, call: ToolCall, output: str) -> str:
        if call.name in _SOURCE_TOOLS and _call_is_sensitive_source(call):
            self._mark(f"sensitive source executed: {call.name}")
        if output and _SECRET_CONTENT_RE.search(output):
            self._mark(f"sensitive content in {call.name} output")
        return output

    async def sanitize_final_output(self, text: str) -> tuple[str, str | None]:
        if self._tainted and text and _SECRET_CONTENT_RE.search(text):
            return (
                "（最终答复已被 AgentShield 拦截：污点跟踪检测到敏感内容外泄）",
                f"taint_tracker blocked final answer ({'; '.join(self._reasons)})",
            )
        return text, None
