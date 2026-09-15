"""自主安全审计编排层：把攻击模块暴露给指挥官 LLM，并驱动 Plan / ReAct 循环。"""

from agent_shield.orchestrator.memory import SessionMemory
from agent_shield.orchestrator.plan_execute import (
    DEFAULT_FIXED_PLAN,
    FixedPlanLLM,
    audit_plan_and_execute,
)
from agent_shield.orchestrator.prompts import (
    REACT_SYSTEM_PROMPT,
    build_plan_system_prompt,
    build_plan_user_message,
    build_react_system_prompt,
    build_react_user_message,
    parse_audit_plan,
)
from agent_shield.orchestrator.react_loop import (
    DefaultReActLLM,
    ScriptedReActLLM,
    audit_agent_loop,
)
from agent_shield.orchestrator.report import (
    collect_high_risk_findings,
    export_session_traces,
    session_report_to_json,
    session_report_to_markdown,
)
from agent_shield.orchestrator.session_store import AuditSessionStore, target_spec_to_dict
from agent_shield.orchestrator.target_factory import (
    AuditTargetSpec,
    build_audit_target_factory,
    resolve_audit_options,
)
from agent_shield.orchestrator.tools_bridge import (
    META_ANALYZE_PROXY_EVENTS,
    META_FINISH_AUDIT,
    META_LIST_COVERAGE,
    META_PROPOSE_CHAIN,
    META_RUN_CHAIN_STEP,
    build_attack_tools,
    execute_attack_tool,
)

__all__ = [
    "DEFAULT_FIXED_PLAN",
    "META_ANALYZE_PROXY_EVENTS",
    "META_FINISH_AUDIT",
    "META_LIST_COVERAGE",
    "META_PROPOSE_CHAIN",
    "META_RUN_CHAIN_STEP",
    "REACT_SYSTEM_PROMPT",
    "AuditSessionStore",
    "AuditTargetSpec",
    "DefaultReActLLM",
    "FixedPlanLLM",
    "ScriptedReActLLM",
    "SessionMemory",
    "audit_agent_loop",
    "audit_plan_and_execute",
    "build_attack_tools",
    "build_audit_target_factory",
    "build_plan_system_prompt",
    "build_plan_user_message",
    "build_react_system_prompt",
    "build_react_user_message",
    "collect_high_risk_findings",
    "execute_attack_tool",
    "export_session_traces",
    "parse_audit_plan",
    "resolve_audit_options",
    "session_report_to_json",
    "session_report_to_markdown",
    "target_spec_to_dict",
]
