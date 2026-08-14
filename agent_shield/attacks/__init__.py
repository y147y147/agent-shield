"""攻击模块：7 个攻击向量 + 注册表。"""

from agent_shield.attacks.base import AttackConfig, AttackModule
from agent_shield.attacks.data_exfiltration import ATTACKER_EMAIL, DataExfiltrationAttack
from agent_shield.attacks.direct_injection import DirectInjectionAttack
from agent_shield.attacks.indirect_injection import DEFAULT_MARKER_CMD, IndirectInjectionAttack
from agent_shield.attacks.memory_poisoning import MemoryPoisoningAttack
from agent_shield.attacks.privilege_escalation import SENSITIVE_READ as PE_SENSITIVE_READ
from agent_shield.attacks.privilege_escalation import PrivilegeEscalationAttack
from agent_shield.attacks.registry import get_attack_module, list_attack_modules, register
from agent_shield.attacks.resource_abuse import LOOP_THRESHOLD, ResourceAbuseAttack
from agent_shield.attacks.tool_poisoning import VICTIM_TOOL, ToolPoisoningAttack

__all__ = [
    "ATTACKER_EMAIL",
    "DEFAULT_MARKER_CMD",
    "LOOP_THRESHOLD",
    "PE_SENSITIVE_READ",
    "VICTIM_TOOL",
    "AttackConfig",
    "AttackModule",
    "DataExfiltrationAttack",
    "DirectInjectionAttack",
    "IndirectInjectionAttack",
    "MemoryPoisoningAttack",
    "PrivilegeEscalationAttack",
    "ResourceAbuseAttack",
    "ToolPoisoningAttack",
    "get_attack_module",
    "list_attack_modules",
    "register",
]
