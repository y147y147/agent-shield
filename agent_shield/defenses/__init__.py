"""防御层：注入检测（含去混淆）+ 工具输出通道意图、策略引擎、污点、沙箱等。"""

from agent_shield.defenses.adaptive_defense import AdaptivePolicySupervisor
from agent_shield.defenses.autonomy import AutonomyGuard
from agent_shield.defenses.base import GuardRail, ToolCallDecision
from agent_shield.defenses.call_budget import CallBudgetGuard
from agent_shield.defenses.deobfuscate import normalize_for_detection
from agent_shield.defenses.docker_sandbox import (
    DEFAULT_SANDBOX_IMAGE,
    DockerSandboxExecutor,
    build_sandbox_executor,
    docker_available,
    resolve_sandbox_backend,
)
from agent_shield.defenses.final_answer_guard import FinalAnswerGuard
from agent_shield.defenses.injection_detector import (
    INPUT_REDACTED_PREFIX,
    UNTRUSTED_TOOL_CHANNELS,
    Detection,
    InjectionDetector,
    is_fully_redacted_input,
)
from agent_shield.defenses.intent_classifier import (
    BOUNDARY_TOOLS,
    INTENT_BLOCKED_PREFIX,
    INTENT_SIGNALS,
    TOOL_CHANNEL_SIGNALS,
    IntentClassifier,
    classify_intent,
)
from agent_shield.defenses.inter_agent import InterAgentChannelGuard
from agent_shield.defenses.judge import JUDGE_SYSTEM_PROMPT, LLMJudgeDetector
from agent_shield.defenses.memory import MemoryIntegrityGuard
from agent_shield.defenses.path_normalize import PathNormalizeGuard, normalize_git_bash_path
from agent_shield.defenses.policy_engine import DEFAULT_POLICY, PolicyEngine
from agent_shield.defenses.sandbox import (
    DANGEROUS_COMMAND_PATTERNS,
    SandboxExecutor,
    SandboxLimits,
    SandboxResult,
)
from agent_shield.defenses.semantic_injection import (
    SEMANTIC_DISGUISE_TEMPLATES,
    extract_semantic_run_commands,
    looks_like_semantic_injection,
    render_semantic_disguise,
)
from agent_shield.defenses.taint_tracker import TaintTracker, user_input_looks_tainted
from agent_shield.defenses.tool_integrity import ToolIntegrityGuard

__all__ = [
    "BOUNDARY_TOOLS",
    "DANGEROUS_COMMAND_PATTERNS",
    "DEFAULT_POLICY",
    "DEFAULT_SANDBOX_IMAGE",
    "INPUT_REDACTED_PREFIX",
    "INTENT_BLOCKED_PREFIX",
    "INTENT_SIGNALS",
    "JUDGE_SYSTEM_PROMPT",
    "SEMANTIC_DISGUISE_TEMPLATES",
    "TOOL_CHANNEL_SIGNALS",
    "UNTRUSTED_TOOL_CHANNELS",
    "AdaptivePolicySupervisor",
    "AutonomyGuard",
    "CallBudgetGuard",
    "Detection",
    "DockerSandboxExecutor",
    "FinalAnswerGuard",
    "GuardRail",
    "InjectionDetector",
    "IntentClassifier",
    "InterAgentChannelGuard",
    "LLMJudgeDetector",
    "PathNormalizeGuard",
    "TaintTracker",
    "build_sandbox_executor",
    "classify_intent",
    "docker_available",
    "extract_semantic_run_commands",
    "is_fully_redacted_input",
    "looks_like_semantic_injection",
    "normalize_for_detection",
    "normalize_git_bash_path",
    "render_semantic_disguise",
    "resolve_sandbox_backend",
    "user_input_looks_tainted",
    "MemoryIntegrityGuard",
    "PolicyEngine",
    "SandboxExecutor",
    "SandboxLimits",
    "SandboxResult",
    "ToolCallDecision",
    "ToolIntegrityGuard",
]
