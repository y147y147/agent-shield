"""攻击模块：12 个攻击向量（覆盖 OWASP ASI-01 ~ ASI-10 全部 10 类风险，ASI-04 含工具投毒与 MCP 投毒两个变体）+ 注册表。"""

from agent_shield.attacks.base import AttackConfig, AttackModule
from agent_shield.attacks.data_exfiltration import ATTACKER_EMAIL, DataExfiltrationAttack
from agent_shield.attacks.direct_injection import DirectInjectionAttack
from agent_shield.attacks.human_trust_exploitation import HumanTrustExploitationAttack
from agent_shield.attacks.indirect_injection import DEFAULT_MARKER_CMD, IndirectInjectionAttack
from agent_shield.attacks.inter_agent_communication import InterAgentCommunicationAttack
from agent_shield.attacks.memory_poisoning import MemoryPoisoningAttack
from agent_shield.attacks.mcp_poisoning import MCPPoisoningAttack, DEFAULT_MCP_TOOL
from agent_shield.attacks.privilege_escalation import SENSITIVE_READ as PE_SENSITIVE_READ
from agent_shield.attacks.privilege_escalation import PrivilegeEscalationAttack
from agent_shield.attacks.registry import get_attack_module, list_attack_modules, register
from agent_shield.attacks.resource_abuse import LOOP_THRESHOLD, ResourceAbuseAttack
from agent_shield.attacks.rogue_agent import RogueAgentAttack
from agent_shield.attacks.tool_poisoning import VICTIM_TOOL, ToolPoisoningAttack
from agent_shield.attacks.unexpected_code_execution import UnexpectedCodeExecutionAttack

__all__ = [
    "ATTACKER_EMAIL",
    "DEFAULT_MARKER_CMD",
    "DEFAULT_MCP_TOOL",
    "LOOP_THRESHOLD",
    "PE_SENSITIVE_READ",
    "VICTIM_TOOL",
    "AttackConfig",
    "AttackModule",
    "DataExfiltrationAttack",
    "DirectInjectionAttack",
    "HumanTrustExploitationAttack",
    "IndirectInjectionAttack",
    "InterAgentCommunicationAttack",
    "MemoryPoisoningAttack",
    "MCPPoisoningAttack",
    "PrivilegeEscalationAttack",
    "ResourceAbuseAttack",
    "RogueAgentAttack",
    "ToolPoisoningAttack",
    "UnexpectedCodeExecutionAttack",
    "get_attack_module",
    "list_attack_modules",
    "register",
]
