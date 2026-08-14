"""工具调用策略引擎：类 WAF 的白名单/黑名单 + 失败关闭（fail-closed）默认。

规则格式（YAML 或 Python dict）::

    run_command:
      action: deny            # deny 表示默认拒绝，仅在命中 allow 时才放行
      allow:
        - "^(ls|cat|pwd|whoami|echo)\\b.*"
      deny:
        - "rm\\s+-rf"
        - "curl\\b"
    web_search:
      action: allow           # allow 表示默认放行，仅在命中 deny 时拦截
"""

from __future__ import annotations

import copy
import re
from typing import Any

from agent_shield.defenses.base import GuardRail, ToolCallDecision
from agent_shield.models import ToolCall

# 默认策略：命令执行失败关闭（fail-closed），未覆盖工具默认放行
DEFAULT_POLICY: dict[str, dict[str, Any]] = {
    "run_command": {
        "action": "deny",
        "allow": [r"^(ls|cat|pwd|whoami|echo)\b.*"],
        "deny": [
            r"rm\s+-rf\b",
            r"mkfs\b",
            r"dd\s+if=",
            r":\(\)\s*\{",
            r"\bcurl\b",
            r"\bwget\b",
            r"\bnc\b",
            r"\bncat\b",
        ],
    },
    "write_file": {
        "action": "deny",
        "allow": [r"^/tmp/"],
        "deny": [],
    },
    "read_file": {
        "action": "deny",
        "allow": [r"^/tmp/"],
        "deny": [],
    },
    "web_search": {"action": "allow", "deny": []},
    "send_email": {"action": "deny", "allow": [], "deny": []},
}


class PolicyEngine(GuardRail):
    """按规则决策工具调用。规则可来自默认策略或外部 YAML。"""

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

        argstr = " ".join(str(v) for v in call.arguments.values())
        deny_patterns = spec.get("deny", [])
        allow_patterns = spec.get("allow", [])
        action = spec.get("action", "allow")

        for pat in deny_patterns:
            if re.search(pat, argstr):
                return ToolCallDecision(allowed=False, reason=f"denied by rule: {pat}")

        if action == "deny":
            # 失败关闭：必须命中 allow 规则才放行
            for pat in allow_patterns:
                if re.search(pat, argstr):
                    return ToolCallDecision(allowed=True, reason=f"allowed by rule: {pat}")
            return ToolCallDecision(allowed=False, reason="denied by fail-closed default")

        return ToolCallDecision(allowed=True, reason="allowed by policy")
