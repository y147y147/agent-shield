"""A5：CLI audit 与 Web 自主审计 API。"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from agent_shield.cli import app
from agent_shield.proxy.audit import AuditStore
from agent_shield.webapp import build_web_app

runner = CliRunner()


def test_cli_audit_plan_mock():
    result = runner.invoke(app, ["audit", "--mode", "plan", "--llm", "mock", "--steps", "3", "--no-compare-defense"])
    assert result.exit_code == 0, result.output
    assert "自主安全审计" in result.output or "Plan-and-Execute" in result.output
    assert "direct_injection" in result.output
    assert "risk=" in result.output


def test_cli_audit_react_mock():
    result = runner.invoke(app, ["audit", "--mode", "react", "--llm", "mock", "--no-compare-defense"])
    assert result.exit_code == 0, result.output
    assert "react" in result.output.lower() or "ReAct" in result.output
    assert "direct_injection" in result.output


def test_web_auto_audit_tab_and_api():
    client = TestClient(build_web_app(AuditStore()))
    page = client.get("/")
    assert page.status_code == 200
    assert "自主审计" in page.text
    assert 'id="tab-auto"' in page.text
    assert "runAutoAudit" in page.text
    assert "auto-mock-hint" in page.text
    assert "/api/auto-audit/stream" in page.text

    data = client.post(
        "/api/auto-audit",
        json={"mode": "plan", "llm": "mock", "max_steps": 3, "compare_defense": True},
    ).json()
    assert data["summary"]["vectors_covered"] >= 3
    assert data["summary"]["risk_level"] in {"critical", "high", "medium", "low", "info"}
    assert len(data["steps"]) >= 3
    assert data["comparison"]


def test_web_auto_audit_stream_plan_emits_events():
    client = TestClient(build_web_app(AuditStore()))
    created = client.post(
        "/api/auto-audit/stream",
        json={"mode": "plan", "llm": "mock", "max_steps": 3, "compare_defense": False},
    ).json()
    job_id = created["job_id"]
    import time

    st = None
    for _ in range(80):
        st = client.get(f"/api/auto-audit/events/{job_id}").json()
        if st["status"] in {"done", "error"}:
            break
        time.sleep(0.05)
    assert st is not None
    assert st["status"] == "done", st.get("error")
    assert any(e.get("type") == "phase" for e in st["events"])
    assert st["result"]["summary"]["vectors_covered"] >= 3


@pytest.mark.asyncio
async def test_data_exfiltration_default_path_is_writable():
    """默认 secret 路径应落在可写演示目录，不再硬编码 /tmp（Windows 会炸）。"""
    from agent_shield.attacks import AttackConfig, DataExfiltrationAttack
    from agent_shield.paths import demo_workdir
    from agent_shield.targets import build_local_target

    attack = DataExfiltrationAttack()
    result = await attack.run(build_local_target(llm="mock", defense=False), AttackConfig(num_variants=1))
    assert result.total == 1
    task = result.cases[0].trace.task if result.cases and result.cases[0].trace else ""
    assert str(demo_workdir()) in task
    assert result.successes >= 1


def test_web_auto_audit_stream_react_mode():
    client = TestClient(build_web_app(AuditStore()))
    created = client.post(
        "/api/auto-audit/stream",
        json={"mode": "react", "llm": "mock", "max_turns": 12, "compare_defense": False},
    ).json()
    import time

    st = None
    for _ in range(80):
        st = client.get(f"/api/auto-audit/events/{created['job_id']}").json()
        if st["status"] in {"done", "error"}:
            break
        time.sleep(0.05)
    assert st["status"] == "done", st.get("error")
    assert st["result"]["summary"]["mode"] == "react"
    assert any(e.get("type") == "phase" for e in st["events"])
