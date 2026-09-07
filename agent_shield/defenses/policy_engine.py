"""工具调用策略引擎：类 WAF 的白名单/黑名单 + 失败关闭（fail-closed）默认。

规则格式（YAML 或 Python dict）::

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

语义校验解决了"前缀白名单绕过"类问题：
- `cat /etc/passwd`（允许清单只匹配命令开头）→ 命令白名单+路径校验拦截；
- `echo evil > /etc/cron.d/x`（echo 前缀 + 重定向写任意文件）→ shell 元字符拦截；
- `cat /etc/passwd | mail x`（管道外发）→ shell 元字符拦截；
- `/tmp/../etc/passwd`（路径穿越绕过前缀）→ realpath 归一化后根目录校验拦截。
"""

from __future__ import annotations

import copy
import os
import re
import shlex
from typing import Any

from agent_shield.defenses.base import GuardRail, ToolCallDecision
from agent_shield.defenses.sandbox import DANGEROUS_COMMAND_PATTERNS
from agent_shield.models import ToolCall
from agent_shield.paths import allowed_demo_roots

# 危险的 shell 元字符：命令分隔/后台、管道、重定向、命令替换、变量展开、子 shell、
# 花括号展开（fork bomb 如 :(){ :|:& };:）、多行、反斜杠转义
_SHELL_METACHARS = set(";|&<>`$\n{}")

# 默认策略：命令执行失败关闭（fail-closed），未覆盖工具默认放行
_DEMO_ROOTS = allowed_demo_roots()
DEFAULT_POLICY: dict[str, dict[str, Any]] = {
    "run_command": {
        "action": "deny",
        # 危险命令黑名单与沙箱共用（DANGEROUS_COMMAND_PATTERNS），防止规则漂移
        "deny": list(DANGEROUS_COMMAND_PATTERNS),
        "semantic": {
            "kind": "shell",
            "allow_commands": ["ls", "cat", "pwd", "whoami", "echo", "head", "tail", "grep", "wc"],
            # 会操作文件参数的工具：参数路径必须位于 allowed_roots 内（realpath 归一化）
            "file_commands": ["ls", "cat", "head", "tail", "grep", "wc"],
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
    "web_search": {"action": "allow", "deny": []},
    "send_email": {"action": "deny", "allow": [], "deny": []},
}


class PolicyEngine(GuardRail):
    """按规则决策工具调用。规则可来自默认策略或外部 YAML。

    - 带 ``semantic`` 的规则走语义校验（整条命令解析 / 路径归一化）；
    - 不带 ``semantic`` 的规则（自定义 YAML）回退到正则 allow/deny（向后兼容）。
    """

    name = "policy_engine"

    def __init__(self, policy: dict[str, dict[str, Any]] | None = None):
        self.policy = policy if policy is not None else copy.deepcopy(DEFAULT_POLICY)

    @classmethod
    def from_yaml(cls, path: str) -> PolicyEngine:
        import yaml

        with open(path, encoding="utf-8") as f:
            return cls(yaml.safe_load(f))

    async def check_tool_call(self, call: ToolCall) -> ToolCallDecision:
        spec = self.policy.get(call.name)
        if spec is None:
            # 未覆盖的工具：默认放行（策略显式覆盖危险工具）
            return ToolCallDecision(allowed=True, reason="tool not covered by policy")

        deny_patterns = spec.get("deny", [])
        argstr = " ".join(str(v) for v in call.arguments.values())
        for pat in deny_patterns:
            if re.search(pat, argstr):
                return ToolCallDecision(allowed=False, reason=f"denied by rule: {pat}")

        if spec.get("semantic"):
            return self._check_semantic(call, spec)

        # 旧版正则 allow/deny（自定义 YAML 策略向后兼容）
        allow_patterns = spec.get("allow", [])
        action = spec.get("action", "allow")
        for pat in allow_patterns:
            if re.search(pat, argstr):
                return ToolCallDecision(allowed=True, reason=f"allowed by rule: {pat}")
        if action == "deny":
            return ToolCallDecision(allowed=False, reason="denied by fail-closed default")
        return ToolCallDecision(allowed=True, reason="allowed by policy")

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

        # 1) shell 元字符拦截：分隔/管道/重定向/替换/子 shell/换行/转义等一律拒绝
        for ch in command:
            if ch in _SHELL_METACHARS:
                return ToolCallDecision(
                    allowed=False,
                    reason=f"denied by semantic policy: shell metacharacter {ch!r}",
                )

        # 2) 整条命令解析：必须是简单 "cmd arg1 arg2 ..."（引号内参数允许）
        try:
            tokens = shlex.split(command, posix=True)
        except ValueError as exc:
            return ToolCallDecision(allowed=False, reason=f"denied by semantic policy: unparsable command ({exc})")
        if not tokens:
            return ToolCallDecision(allowed=False, reason="denied by semantic policy: empty command")

        # 3) 命令白名单：首 token 必须是允许的命令
        base = tokens[0]
        allow_commands = semantic.get("allow_commands") or []
        if base not in allow_commands:
            return ToolCallDecision(
                allowed=False,
                reason=f"denied by semantic policy: command {base!r} not in allow-list",
            )

        # 4) 文件参数语义校验：操作文件的命令，其路径参数必须位于允许根目录内
        if base in (semantic.get("file_commands") or []):
            roots = semantic.get("allowed_roots") or []
            for token in tokens[1:]:
                if not _looks_like_path(token):
                    continue  # 选项（-l）、模式（grep foo）等非路径参数
                if not self._path_allowed(token, roots):
                    return ToolCallDecision(
                        allowed=False,
                        reason=f"denied by semantic policy: path {token!r} outside allowed roots {roots}",
                    )

        return ToolCallDecision(allowed=True, reason=f"allowed by semantic policy: {base}")

    def _check_path(self, call: ToolCall, semantic: dict[str, Any]) -> ToolCallDecision:
        path = str(call.arguments.get("path", ""))
        if not path:
            return ToolCallDecision(allowed=False, reason="denied by semantic policy: missing path")
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


def _looks_like_path(token: str) -> bool:
    """判断 token 是否为文件路径参数（绝对路径 / 相对路径 / 含目录分隔符）。"""
    if not token:
        return False
    if token.startswith("-"):  # 选项
        return False
    return token.startswith(("/", ".")) or "/" in token
