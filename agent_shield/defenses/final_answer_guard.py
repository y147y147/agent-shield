"""最终答复（final_answer）敏感信息泄露守卫（第四钩子）。

背景（workspace_exfiltration 盲区闭环，见 docs/phase4-report.md 4.2/4.3）：原
Agent 循环只有 ``sanitize_user_input`` / ``check_tool_call`` / ``sanitize_tool_output``
三个钩子，模型把读到的敏感内容复述进**最终答复**时没有任何守卫 —— 泄露通道在
输出端。本守卫挂到新增的 ``sanitize_final_output`` 钩子上：最终答复出现疑似
敏感信息（凭据 / 密钥 / 私钥 / 基准演示标记）时整体替换为拦截通告。

判定口径：命中任一敏感模式即整体替换（部分脱敏仍可能残留可拼接的碎片），
并在 trace 上记 ``final_blocked=True`` + 原因，供攻击判定（BLOCKED）与审计。
"""

from __future__ import annotations

import re

from agent_shield.defenses.base import GuardRail

# 基准演示的敏感标记（workspace_exfiltration 预置文件的客观判定锚点）
DEMO_SECRET_MARKER = "wsx-exfil-demo-secret"

# 保守的敏感信息模式：仅匹配"键=值/键: 值"形态的凭据密钥与私钥块，
# 不会命中普通文本叙述（如"请检查密码策略"）。整体以 re.IGNORECASE 编译。
_SENSITIVE_PATTERNS: tuple[str, ...] = (
    re.escape(DEMO_SECRET_MARKER),
    r"API[_-]?KEY[=:：]\s*\S+",
    r"(?:password|passwd)[=:：]\s*\S+",
    r"(?:secret[_-]?(?:token|key)?|totp[-_]seed)[=:：\-]\s*\S+",
    r"BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY",
)
_SENSITIVE_RE = re.compile("|".join(_SENSITIVE_PATTERNS), re.IGNORECASE)

# 拦截通告（作为最终答复返回给用户，敏感信息不再出现在输出端）
REDACTED_FINAL = "（最终答复已被 AgentShield 拦截：检测到疑似敏感信息泄露）"


class FinalAnswerGuard(GuardRail):
    """最终答复敏感信息守卫：命中即整体替换 + 记拦截原因。"""

    name = "final_answer_guard"

    async def sanitize_final_output(self, text: str) -> tuple[str, str | None]:
        if not text:
            return text, None
        match = _SENSITIVE_RE.search(text)
        if match is None:
            return text, None
        return REDACTED_FINAL, f"final answer matched sensitive pattern {match.group(0)!r}"
