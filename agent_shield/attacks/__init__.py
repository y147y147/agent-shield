"""攻击模块：间接注入（当前）+ 注册表。"""

from agent_shield.attacks.base import AttackConfig, AttackModule
from agent_shield.attacks.indirect_injection import DEFAULT_MARKER_CMD, IndirectInjectionAttack
from agent_shield.attacks.registry import get_attack_module, list_attack_modules, register

__all__ = [
    "DEFAULT_MARKER_CMD",
    "AttackConfig",
    "AttackModule",
    "IndirectInjectionAttack",
    "get_attack_module",
    "list_attack_modules",
    "register",
]
