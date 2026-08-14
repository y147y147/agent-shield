"""攻击模块：直接注入 / 间接注入 / 越权 + 注册表。"""

from agent_shield.attacks.base import AttackConfig, AttackModule
from agent_shield.attacks.direct_injection import DirectInjectionAttack
from agent_shield.attacks.indirect_injection import DEFAULT_MARKER_CMD, IndirectInjectionAttack
from agent_shield.attacks.privilege_escalation import (
    ATTACKER_EMAIL,
    SENSITIVE_READ,
    PrivilegeEscalationAttack,
)
from agent_shield.attacks.registry import get_attack_module, list_attack_modules, register

__all__ = [
    "ATTACKER_EMAIL",
    "DEFAULT_MARKER_CMD",
    "SENSITIVE_READ",
    "AttackConfig",
    "AttackModule",
    "DirectInjectionAttack",
    "IndirectInjectionAttack",
    "PrivilegeEscalationAttack",
    "get_attack_module",
    "list_attack_modules",
    "register",
]
