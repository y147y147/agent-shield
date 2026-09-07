"""E3：高风险攻击模块 Human-in-the-loop 门控。"""

from __future__ import annotations

from typing import Any

DANGEROUS_ATTACK_MODULES: frozenset[str] = frozenset(
    {
        "unexpected_code_execution",
        "rogue_agent",
    }
)

HITL_REASONS: dict[str, str] = {
    "unexpected_code_execution": "可能写入并执行任意脚本（ASI-05）",
    "rogue_agent": "模拟内部失控智能体，仅 Mock 靶场（ASI-10）",
}


def requires_hitl(module: str) -> bool:
    return module in DANGEROUS_ATTACK_MODULES


def hitl_payload(module: str) -> dict[str, Any]:
    return {
        "hitl_required": True,
        "module": module,
        "reason": HITL_REASONS.get(module, "高风险攻击模块，需人工确认"),
        "dangerous_modules": sorted(DANGEROUS_ATTACK_MODULES),
    }


def is_module_confirmed(module: str, confirmed: set[str] | frozenset[str] | None) -> bool:
    if not requires_hitl(module):
        return True
    if confirmed is None:
        return False
    return module in confirmed
