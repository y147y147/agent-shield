"""A4：自主审计会话模型与报告渲染。"""

from __future__ import annotations

from agent_shield.models import (
    AuditPlan,
    AuditPlanStep,
    AuditSessionReport,
    AuditStepResult,
    aggregate_audit_session,
    compute_risk_level,
)
from agent_shield.orchestrator.report import session_report_to_json, session_report_to_markdown


def test_audit_plan_roundtrip():
    plan = AuditPlan(
        objective="覆盖 ASI-01/03",
        steps=[
            AuditPlanStep(module="direct_injection", rationale="先探输入侧"),
            AuditPlanStep(module="indirect_injection", num_variants=5, params={"encoding": "b64"}),
        ],
    )
    parsed = AuditPlan.model_validate(plan.model_dump())
    assert parsed.steps[1].params["encoding"] == "b64"
    assert len(parsed.steps) == 2


def test_compute_risk_critical_vulnerable():
    steps = [
        AuditStepResult(
            module="direct_injection",
            defense_on=False,
            result_summary={"successes": 3, "success_rate": 1.0, "criticals": 3, "blocked": 0},
        )
    ]
    assert compute_risk_level(steps) == "critical"


def test_compute_risk_medium_when_defense_holds():
    steps = [
        AuditStepResult(
            module="direct_injection",
            defense_on=False,
            result_summary={"successes": 2, "success_rate": 1.0, "criticals": 2, "blocked": 0},
        ),
        AuditStepResult(
            module="direct_injection",
            defense_on=True,
            result_summary={"successes": 0, "success_rate": 0.0, "criticals": 0, "blocked": 1},
        ),
    ]
    # 脆弱侧已达 critical 阈值（rate>=0.5 + criticals）
    assert compute_risk_level(steps) == "critical"

    steps_no_crit = [
        AuditStepResult(
            module="human_trust_exploitation",
            defense_on=False,
            result_summary={"successes": 1, "success_rate": 0.3, "criticals": 0, "blocked": 0},
        ),
        AuditStepResult(
            module="human_trust_exploitation",
            defense_on=True,
            result_summary={"successes": 0, "success_rate": 0.0, "criticals": 0, "blocked": 0},
        ),
    ]
    assert compute_risk_level(steps_no_crit) == "medium"


def test_compute_risk_high_when_defense_bypassed_once():
    steps = [
        AuditStepResult(
            module="indirect_injection",
            defense_on=True,
            result_summary={"successes": 1, "success_rate": 0.3, "criticals": 1, "blocked": 0},
        )
    ]
    assert compute_risk_level(steps) == "high"


def test_aggregate_audit_session_numbers():
    steps = [
        AuditStepResult(
            module="direct_injection",
            defense_on=False,
            bypass_index=0,
            result_summary={"successes": 2, "blocked": 0, "success_rate": 1.0, "criticals": 2},
        ),
        AuditStepResult(
            module="direct_injection",
            defense_on=True,
            bypass_index=0,
            result_summary={"successes": 0, "blocked": 2, "success_rate": 0.0, "criticals": 0},
        ),
        AuditStepResult(
            module="privilege_escalation",
            defense_on=False,
            bypass_index=1,
            result_summary={"successes": 1, "blocked": 0, "success_rate": 0.5, "criticals": 1},
            error=None,
        ),
        AuditStepResult(module="rogue_agent", defense_on=False, error="mock_only skipped"),
    ]
    report = aggregate_audit_session(
        mode="plan",
        objective="demo",
        modules_planned=["direct_injection", "privilege_escalation", "rogue_agent"],
        steps=steps,
        narrative="护栏有效",
    )
    assert isinstance(report, AuditSessionReport)
    assert report.vectors_covered == 3
    assert report.successes_vulnerable == 3
    assert report.successes_defended == 0
    assert report.blocked_defended == 2
    assert report.bypass_attempts == 1
    assert report.risk_level == "critical"
    assert report.narrative == "护栏有效"


def test_session_report_markdown_has_comparison():
    report = aggregate_audit_session(
        mode="plan",
        objective="对比",
        modules_planned=["direct_injection"],
        steps=[
            AuditStepResult(
                module="direct_injection",
                defense_on=False,
                result_summary={"successes": 3, "total": 3, "success_rate": 1.0, "blocked": 0, "criticals": 3},
            ),
            AuditStepResult(
                module="direct_injection",
                defense_on=True,
                result_summary={"successes": 0, "total": 3, "success_rate": 0.0, "blocked": 0, "criticals": 0},
            ),
        ],
    )
    md = session_report_to_markdown(report)
    assert "攻防对比" in md
    assert "`direct_injection`" in md
    assert "100%" in md
    assert "0%" in md
    data = session_report_to_json(report)
    assert data["summary"]["risk_level"] == "critical"
    assert data["comparison"][0]["module"] == "direct_injection"
