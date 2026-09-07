"""C3：审计会话持久化单测。"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from agent_shield.cli import app as cli_app
from agent_shield.models import AuditSessionReport
from agent_shield.orchestrator.plan_execute import FixedPlanLLM, audit_plan_and_execute
from agent_shield.orchestrator.session_store import AuditSessionStore
from agent_shield.orchestrator.target_factory import AuditTargetSpec
from agent_shield.proxy.audit import AuditStore
from agent_shield.targets import DEFAULT_TASK, build_local_target
from agent_shield.webapp import build_web_app

runner = CliRunner()


def _factory(*, defense: bool = False):
    return build_local_target(llm="mock", defense=defense)


@pytest.fixture
def session_db(tmp_path):
    return tmp_path / "sessions.db"


@pytest.fixture
def session_store(session_db):
    store = AuditSessionStore(session_db)
    yield store
    store.close()


@pytest.mark.asyncio
async def test_session_store_save_and_load(session_store):
    report = await audit_plan_and_execute(
        planner=FixedPlanLLM(),
        target_factory=_factory,
        task=DEFAULT_TASK,
        max_steps=3,
        compare_defense=False,
    )
    spec = AuditTargetSpec(kind="local", llm="mock")
    sid = session_store.save_session(report, target_spec=spec, task=DEFAULT_TASK)

    assert sid
    assert session_store.count() == 1

    loaded = session_store.load_report(sid)
    parsed = AuditSessionReport.model_validate(loaded.model_dump())
    assert parsed.mode == report.mode
    assert parsed.vectors_covered == report.vectors_covered


def test_session_store_list_and_get(session_store):
    report = AuditSessionReport(
        mode="plan",
        objective="test",
        modules_planned=["direct_injection"],
        modules_executed=["direct_injection"],
        vectors_covered=1,
        risk_level="medium",
    )
    sid = session_store.save_session(
        report,
        target_spec={"kind": "local", "llm": "mock"},
        task="t",
    )
    rows = session_store.list_sessions()
    assert len(rows) == 1
    assert rows[0]["id"] == sid

    detail = session_store.get_session(sid)
    assert detail is not None
    assert "markdown" in detail
    assert "# Audit Session Report" in detail["markdown"]


def test_cli_audit_save_session(session_db):
    result = runner.invoke(
        cli_app,
        [
            "audit",
            "--mode",
            "plan",
            "--llm",
            "mock",
            "--steps",
            "3",
            "--no-compare-defense",
            "--session-db",
            str(session_db),
        ],
    )
    assert result.exit_code == 0, result.output
    assert "会话已保存" in result.output

    store = AuditSessionStore(session_db)
    try:
        assert store.count() == 1
        report = store.load_report(store.list_sessions()[0]["id"])
        AuditSessionReport.model_validate(report.model_dump())
    finally:
        store.close()


def test_web_audit_sessions_api(session_db):
    client = TestClient(build_web_app(AuditStore(session_db), AuditSessionStore(session_db)))

    data = client.post(
        "/api/auto-audit",
        json={"mode": "plan", "llm": "mock", "max_steps": 3, "compare_defense": False},
    ).json()
    assert data.get("session_id")
    assert data["summary"]["vectors_covered"] >= 3

    listed = client.get("/api/auto-audit/sessions").json()
    assert listed["total"] >= 1
    assert len(listed["sessions"]) >= 1

    sid = listed["sessions"][0]["id"]
    detail = client.get(f"/api/auto-audit/sessions/{sid}").json()
    assert detail["markdown"]
    assert detail["report"]["summary"]["mode"] == "plan"

    store = AuditSessionStore(session_db)
    try:
        parsed = store.load_report(sid)
        AuditSessionReport.model_validate(parsed.model_dump())
    finally:
        store.close()


def test_web_two_audits_two_sessions(session_db):
    """V-C5：连续两次 audit，历史列表可见 2 条。"""
    client = TestClient(build_web_app(AuditStore(session_db), AuditSessionStore(session_db)))
    body = {"mode": "plan", "llm": "mock", "max_steps": 3, "compare_defense": False}
    client.post("/api/auto-audit", json=body)
    client.post("/api/auto-audit", json=body)
    listed = client.get("/api/auto-audit/sessions").json()
    assert listed["total"] == 2
    assert len(listed["sessions"]) == 2


def test_web_session_page_has_history_ui(session_db):
    client = TestClient(build_web_app(AuditStore(session_db), AuditSessionStore(session_db)))
    page = client.get("/")
    assert "auto-sessions-table" in page.text
    assert "loadAuditSessions" in page.text
    assert "/api/auto-audit/sessions" in page.text
