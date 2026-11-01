"""工具调用策略引擎：类 WAF 的白名单/黑名单 + **默认拒绝（fail-closed）**。

规则格式（YAML 或 Python dict）::

    default_action: deny      # 顶层兜底：未覆盖的工具默认拒绝（可显式改成 allow）
    run_command:
      action: deny            # deny 表示默认拒绝，仅在命中 allow 时才放行
      allow:
        - "^(ls|cat|pwd|whoami|echo)\\b.*"
      deny:
        - "rm\\s+-rf"
        - "curl\\b"
      semantic:               # 可选：语义校验（推荐，能防 allow 前缀绕过）
        kind: shell           # shell：整条命令解析 + 元字符拦截 + 命令白名单 + 路径校验
        allow_commands: [ls, cat, pwd, whoami, echo, head, tail, grep, wc]
        file_commands: [ls, cat, head, tail, grep, wc]   # 需要校验文件参数的工具
        allowed_roots: ["/tmp"]                          # 文件参数允许的根目录
    read_file:
      action: deny
      semantic:
        kind: path            # path：路径 realpath 归一化后必须位于 allowed_roots 内
        allowed_roots: ["/tmp"]
    web_search:
      action: allow           # allow 表示默认放行，仅在命中 deny 时拦截
    "*":                      # 通配兜底规则：优先于 default_action，优先级低于精确工具名
      action: allow

Fail-closed（默认拒绝）的三层语义：
1. **未覆盖的工具** → 按顶层 ``default_action`` 处置（默认 deny）：新增工具不会"默认裸奔"；
2. **单条规则未显式声明 action** → 默认 deny：必须写 ``action: allow`` 才放行；
3. **语义校验解析失败 / 无法判定** → deny。
要放行某个工具，请显式写 ``action: allow``（内置策略里 web_search / receive_message 即如此）。

语义校验解决的"前缀白名单绕过"类问题：
- `cat /etc/passwd`（允许清单只匹配命令开头）→ 命令白名单+路径校验拦截；
- `echo evil > /etc/cron.d/x`（echo 前缀 + 重定向写任意文件）→ shell 元字符拦截；
- `cat /etc/passwd | mail x`（管道外发）→ shell 元字符拦截；
- `/tmp/../etc/passwd`（路径穿越绕过前缀）→ realpath 归一化后根目录校验拦截。
"""

from __future__ import annotations

import copy
import logging
import os
import re
import shlex
from typing import Any

from agent_shield.defenses.base import GuardRail, ToolCallDecision
from agent_shield.defenses.sandbox import DANGEROUS_COMMAND_PATTERNS
from agent_shield.models import ToolCall
from agent_shield.observability import POLICY_DECISIONS, get_logger, log_event
from agent_shield.paths import allowed_demo_roots

logger = get_logger("defenses.policy_engine")

# 危险的 shell 元字符：命令分隔/后台、重定向、命令替换、变量展开、子 shell、
# 花括号展开（fork bomb 如 :(){ :|:& };:）、多行、反斜杠转义。
# 注意：单 `|`（管道）不在其中 —— 它由 _split_pipe_segments 按段拆分后逐段做白名单校验；
# 只有 `||` 逻辑运算符会被显式拒绝。
_SHELL_METACHARS = set(";|&<>`$\n{}")

# 安全管道最多允许的段数，防超长管道链攻击
_MAX_PIPE_SEGMENTS = 8


def _split_pipe_segments(command: str) -> list[str] | None:
    """按**未加引号**的单 `|` 把命令切成段。

    - 引号（' "）内的 `|` 是普通字符，不断段；
    - 出现未加引号的 `||`（逻辑运算符）或段数超过上限 → 返回 ``None``（应拒绝）。
    """
    segments: list[str] = []
    buf: list[str] = []
    quote: str | None = None
    i = 0
    n = len(command)
    while i < n:
        ch = command[i]
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = None
        elif ch in ('"', "'"):
            quote = ch
            buf.append(ch)
        elif ch == "|":
            if i + 1 < n and command[i + 1] == "|":
                return None
            segments.append("".join(buf).strip())
            buf = []
        else:
            buf.append(ch)
        i += 1
    segments.append("".join(buf).strip())
    if len(segments) > _MAX_PIPE_SEGMENTS:
        return None
    return segments

# 顶层兜底动作的保留键（不会被当作工具名）与通配规则键
DEFAULT_ACTION_KEY = "default_action"
WILDCARD_RULE = "*"
DEFAULT_ACTION = "deny"  # fail-closed：未覆盖的工具默认拒绝

# 默认策略：命令执行失败关闭（fail-closed），未覆盖工具同样默认拒绝
_DEMO_ROOTS = allowed_demo_roots()


def _platform_shell_commands() -> tuple[list[str], list[str]]:
    """按宿主平台返回 (allow_commands 增量, file_commands 增量)。

    Windows 主机追加**只读内省**命令：dir≈ls、type≈cat、find/findstr≈grep、where≈which。
    这些命令不会写入/执行，也不增加可执行攻击面。**刻意不放行** cmd/powershell 等解释器，
    也不放行 rd/del/copy/move/mkdir 等有副作用的命令 —— 那才是真正的攻击缺口。
    """
    if os.name != "nt":
        return [], []
    return ["dir", "type", "find", "findstr", "where"], ["dir", "type", "find", "findstr"]


_EXTRA_CMDS, _EXTRA_FILE_CMDS = _platform_shell_commands()
DEFAULT_POLICY: dict[str, Any] = {
    DEFAULT_ACTION_KEY: DEFAULT_ACTION,
    "run_command": {
        "action": "deny",
        # 危险命令黑名单与沙箱共用（DANGEROUS_COMMAND_PATTERNS），防止规则漂移
        "deny": list(DANGEROUS_COMMAND_PATTERNS),
        "semantic": {
            "kind": "shell",
            "allow_commands": ["ls", "cat", "pwd", "whoami", "echo", "head", "tail", "grep", "wc"]
            + _EXTRA_CMDS,
            # 会操作文件参数的工具：参数路径必须位于 allowed_roots 内（realpath 归一化）
            "file_commands": ["ls", "cat", "head", "tail", "grep", "wc"] + _EXTRA_FILE_CMDS,
            "allowed_roots": list(_DEMO_ROOTS),
        },
    },
    "write_file": {
        "action": "deny",
        "deny": [],
        "semantic": {"kind": "path", "allowed_roots": list(_DEMO_ROOTS)},
    },
    "read_file": {
        "action": "deny",
        "deny": [],
        "semantic": {"kind": "path", "allowed_roots": list(_DEMO_ROOTS)},
    },
    # Office 工具带的只读工具：目录列举（路径仍限定 allowed_roots，fail-closed）与
    # 内网文档抓取（仅返回固定摘要，不写不执行）。二者**不打开写入/执行攻击面**，
    # 显式覆盖以免被 fail-closed 默认拒绝而误伤良性任务（真实模型基准 FPR 主因）。
    "list_dir": {
        "action": "deny",
        "deny": [],
        "semantic": {"kind": "path", "allowed_roots": list(_DEMO_ROOTS)},
    },
    "http_fetch": {"action": "allow", "deny": []},
    "web_search": {"action": "allow", "deny": []},
    # 智能体间消息读取：允许调用，但其输出属不可信内容，交由注入检测器清洗
    "receive_message": {"action": "allow", "deny": []},
    "send_email": {"action": "deny", "allow": [], "deny": []},
}


class PolicyEngine(GuardRail):
    """按规则决策工具调用。规则可来自默认策略或外部 YAML。

    - 带 ``semantic`` 的规则走语义校验（整条命令解析 / 路径归一化）；
    - 不带 ``semantic`` 的规则（自定义 YAML）回退到正则 allow/deny（向后兼容）；
    - **未覆盖的工具按 ``default_action`` 处置（默认 deny）**；``"*"`` 可作为通配兜底规则；
    - 单条规则未写 ``action`` 时同样默认 deny（fail-closed）。

    参数：
        policy: 规则字典；缺省用 ``DEFAULT_POLICY``。
        default_action: 显式指定兜底动作（覆盖 policy 里的 ``default_action``）。
    """

    name = "policy_engine"

    def __init__(
        self,
        policy: dict[str, Any] | None = None,
        default_action: str | None = None,
    ):
        raw = copy.deepcopy(policy) if policy is not None else copy.deepcopy(DEFAULT_POLICY)
        declared = raw.pop(DEFAULT_ACTION_KEY, None)
        action = str(default_action or declared or DEFAULT_ACTION).lower()
        if action not in ("allow", "deny"):
            raise ValueError(f"default_action 只能是 'allow' 或 'deny'，收到: {action!r}")
        self.default_action = action
        self.policy: dict[str, dict[str, Any]] = raw

    @classmethod
    def from_yaml(cls, path: str) -> PolicyEngine:
        import yaml

        with open(path, encoding="utf-8") as f:
            return cls(yaml.safe_load(f))

    async def check_tool_call(self, call: ToolCall) -> ToolCallDecision:
        decision = self._decide(call)
        POLICY_DECISIONS.inc(tool=call.name, decision="allowed" if decision.allowed else "blocked")
        if not decision.allowed:
            log_event(logger, "policy_denied", level=logging.DEBUG, tool=call.name, reason=decision.reason)
        return decision

    def _decide(self, call: ToolCall) -> ToolCallDecision:
        spec = self.policy.get(call.name)
        if spec is not None:
            return self._check_rule(call, spec, tool_label=call.name)

        wildcard = self.policy.get(WILDCARD_RULE)
        if wildcard is not None:
            return self._check_rule(call, wildcard, tool_label=WILDCARD_RULE)

        # 未覆盖的工具：fail-closed（默认拒绝），只有显式 default_action: allow 才放行
        if self.default_action == "allow":
            return ToolCallDecision(
                allowed=True, reason=f"tool {call.name!r} not covered by policy (default_action=allow)"
            )
        return ToolCallDecision(
            allowed=False,
            reason=f"denied by fail-closed default: tool {call.name!r} is not covered by policy",
        )

    def _check_rule(self, call: ToolCall, spec: dict[str, Any], *, tool_label: str) -> ToolCallDecision:
        """按单条规则决策（正则 deny → 语义校验 → 正则 allow → action 兜底）。"""
        deny_patterns = spec.get("deny", [])
        argstr = " ".join(str(v) for v in call.arguments.values())
        for pat in deny_patterns:
            if re.search(pat, argstr):
                return ToolCallDecision(allowed=False, reason=f"denied by rule: {pat}")

        if spec.get("semantic"):
            return self._check_semantic(call, spec)

        # 旧版正则 allow/deny（自定义 YAML 策略向后兼容）
        allow_patterns = spec.get("allow", [])
        for pat in allow_patterns:
            if re.search(pat, argstr):
                return ToolCallDecision(allowed=True, reason=f"allowed by rule: {pat}")
        # 未显式声明 action 时同样 fail-closed（必须写 action: allow 才放行）
        action = str(spec.get("action", "deny")).lower()
        if action == "allow":
            return ToolCallDecision(allowed=True, reason=f"allowed by policy for tool {tool_label!r}")
        return ToolCallDecision(
            allowed=False,
            reason=f"denied by fail-closed default for tool {tool_label!r} (no allow rule matched)",
        )

    # ------------------------------------------------------------------ #
    # 语义校验
    # ------------------------------------------------------------------ #
    def _check_semantic(self, call: ToolCall, spec: dict[str, Any]) -> ToolCallDecision:
        semantic = spec.get("semantic") or {}
        kind = semantic.get("kind")
        if kind == "shell":
            return self._check_shell(call, semantic)
        if kind == "path":
            return self._check_path(call, semantic)
        return ToolCallDecision(allowed=False, reason="unknown semantic kind, fail-closed")

    def _check_shell(self, call: ToolCall, semantic: dict[str, Any]) -> ToolCallDecision:
        command = str(call.arguments.get("command", ""))
        if not command.strip():
            return ToolCallDecision(allowed=False, reason="denied by semantic policy: empty command")

        # 0) 按"未加引号的单 `|`"切分段；出现未加引号的 `||` 或超长管道链视为可疑拒绝。
        #    单 `|` 本身不是攻击向量 —— 真正的风险是管道通向非白名单命令（`| mail`、`| curl`、
        #    `| bash`），而下面的每段白名单+路径校验会把这些挡下。逻辑运算符 `||` 直接拒绝。
        segments = _split_pipe_segments(command)
        if segments is None:
            return ToolCallDecision(allowed=False, reason="denied by semantic policy: shell logical operator '||'")

        # 1) 每段元字符拦截：除"单 `|` 已按段拆分"外的分隔/后台/重定向/替换/子 shell/换行/转义等一律拒绝
        banned = _SHELL_METACHARS - {"|"}
        for seg in segments:
            for ch in seg:
                if ch in banned:
                    return ToolCallDecision(
                        allowed=False,
                        reason=f"denied by semantic policy: shell metacharacter {ch!r}",
                    )

        # 2/3/4) 每段独立：整条命令解析（Windows 反斜杠防误判）→ 命令白名单 → 文件路径根校验。
        #    Windows 注意：shlex(posix=True) 会把反斜杠当转义符，导致 `C:\dir\file` 被解析成
        #    `C:dirfile` 而误判为"越界路径"。因此解析前先把路径分隔符统一为 "/"，
        #    避免合法命令被误拦（该误报由良性对照集 tests/test_fp_benchmark.py 发现）。
        allow_commands = semantic.get("allow_commands") or []
        file_commands = semantic.get("file_commands") or []
        roots = semantic.get("allowed_roots") or []
        first_base = None
        for seg in segments:
            seg = seg.strip()
            if not seg:
                return ToolCallDecision(allowed=False, reason="denied by semantic policy: empty pipe segment")
            parse_input = seg.replace("\\", "/") if os.name == "nt" else seg
            try:
                tokens = shlex.split(parse_input, posix=True)
            except ValueError as exc:
                return ToolCallDecision(allowed=False, reason=f"denied by semantic policy: unparsable command ({exc})")
            if not tokens:
                return ToolCallDecision(allowed=False, reason="denied by semantic policy: empty command")

            base = tokens[0]
            if base not in allow_commands:
                return ToolCallDecision(
                    allowed=False,
                    reason=f"denied by semantic policy: command {base!r} not in allow-list",
                )
            if base in file_commands:
                for token in tokens[1:]:
                    if not _looks_like_path(token):
                        continue  # 选项（-l、/s）、模式（grep foo）等非路径参数
                    # 敏感文件最小权限：命中敏感名模式（凭据/密钥类）即拒绝，根目录内也不放行
                    if _is_sensitive_path(token):
                        return ToolCallDecision(
                            allowed=False,
                            reason=f"denied by semantic policy: path {token!r} is a sensitive file",
                        )
                    if not self._path_allowed(token, roots):
                        return ToolCallDecision(
                            allowed=False,
                            reason=f"denied by semantic policy: path {token!r} outside allowed roots {roots}",
                        )
            first_base = first_base or base

        return ToolCallDecision(allowed=True, reason=f"allowed by semantic policy: {first_base}")

    def _check_path(self, call: ToolCall, semantic: dict[str, Any]) -> ToolCallDecision:
        path = str(call.arguments.get("path", ""))
        if not path:
            return ToolCallDecision(allowed=False, reason="denied by semantic policy: missing path")
        # 敏感文件最小权限：命中敏感名模式（凭据/密钥类）即拒绝，根目录内也不放行
        if _is_sensitive_path(path):
            return ToolCallDecision(
                allowed=False,
                reason=f"denied by semantic policy: path {path!r} is a sensitive file",
            )
        roots = semantic.get("allowed_roots") or []
        if not self._path_allowed(path, roots):
            return ToolCallDecision(
                allowed=False,
                reason=f"denied by semantic policy: path {path!r} outside allowed roots {roots}",
            )
        return ToolCallDecision(allowed=True, reason=f"allowed by semantic policy: {path}")

    # ------------------------------------------------------------------ #
    @staticmethod
    def _path_allowed(path: str, roots: list[str]) -> bool:
        """realpath 归一化后必须等于某个根目录或其子路径（防 ../ 穿越与符号链接逃逸）。"""
        try:
            real = os.path.realpath(path)
        except (OSError, ValueError):
            return False
        if not real:
            return False
        for root in roots:
            root_real = os.path.realpath(root)
            if real == root_real or real.startswith(root_real.rstrip("/") + os.sep):
                return True
        return False


# Windows 上 `/s` `/b` `/ad` `/a-d` 这类是命令行选项（dir /s、dir /ad、dir /a-d），不是路径；
# 充当标志则跳过路径校验（与 `-x` 同理）。但占比不能过宽：过长或可能拼成 Unix 绝对路径
# 的写法会被误放行（如 `/etc`、`/bin`），所以这里收紧为「≤2 位短字母数字」或「带连字符如 /a-d」，
# 带冒号的（/C:...）或含多余斜杠的（/c/Users/...）一律仍按路径检查，防误放行。
_WIN_FLAG_RE = re.compile(r"^/(?:[A-Za-z0-9]{1,2}|[A-Za-z0-9]+-[A-Za-z0-9]+)$") if os.name == "nt" else None


# 安全的敏感文件名模式：凭据 / 密钥 / 私钥 / 令牌类文件（大小写不敏感）。
# 无论路径是否在 allowed_roots 内，命中即拒绝读/写/cat —— 工作目录不应承载
# 敏感数据（workspace_exfiltration 盲区闭环：允许集内放行的前提是内容不敏感）。
# 模式刻意保守，避免误伤良性任务（如 "demo.txt"、"report.md" 均不命中）。
SENSITIVE_NAME_PATTERNS: tuple[str, ...] = (
    r"\.env$",
    r"credentials[._-]?(?:json|txt|yaml|yml)?$",
    r"secrets?[._-]?(?:txt|json|yaml|yml)?$",
    r"\.git[-_]credentials$",
    r"id_rsa$",
    r"id_ed25519$",
    r"id_dsa$",
    r"id_ecdsa$",
    r"\.pem$",
    r"\.key$",
    r"\.pgp$",
    r"\.gnupg$",
    r"(?:api|auth|access)[._-]?key[s]?$",
    r"token[s]?[._-]?(?:txt|json|yaml)?$",
    r"\.aws[/\\]?credentials$",
    r"\.ssh[/\\]?config$",
)
_SENSITIVE_NAME_RE = re.compile("|".join(SENSITIVE_NAME_PATTERNS), re.IGNORECASE)


def _is_sensitive_path(path: str) -> bool:
    """文件名（或整条路径）命中敏感模式即视为敏感，禁止访问。

    同时检查 basename 与归一化后的全路径：覆盖 ``.env``、``credentials.json``
    等裸文件名，也覆盖 ``.aws/credentials``、``.ssh/config`` 等子目录形态。
    """
    norm = path.replace("\\", "/") if os.name == "nt" else path
    basename = norm.rsplit("/", 1)[-1]
    return bool(_SENSITIVE_NAME_RE.search(basename) or _SENSITIVE_NAME_RE.search(norm))


def _looks_like_path(token: str) -> bool:
    """判断 token 是否为文件路径参数（绝对路径 / 相对路径 / 含目录分隔符）。"""
    if not token:
        return False
    if token.startswith("-"):  # 选项
        return False
    if _WIN_FLAG_RE is not None and _WIN_FLAG_RE.match(token):
        return False  # Windows 单段 `/flag` 选项，非路径
    return token.startswith(("/", ".")) or "/" in token
