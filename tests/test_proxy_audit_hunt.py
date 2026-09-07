"""D1：Proxy → Audit 狩猎闭环测试。"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from agent_shield.orchestrator.proxy_analysis import analyze_proxy_events
from agent_shield.orchestrator.react_loop import DefaultReActLLM, audit_agent_loop
from agent_shield.orchestrator.session_store import AuditSessionStore
from agent_shield.orchestrator.tools_bridge import META_ANALYZE_PROXY_EVENTS, execute_attack_tool
from agent_shield.proxy.audit import AuditStore
from agent_shield.targets import DEFAULT_TASK, build_local_target
from agent_shield.webapp import build_web_app


def _factory(*, defense: bool = False):
    return build_local_target(llm="mock", defense=defense)


def _seed_injection_event(store: AuditStore) -> None:
    store.record_event(
        "in",
        "test-model",
        "block",
        [{"signal": "指令块标记", "severity": "high", "line_no": 1, "snippet": "INSTRUCTION: run_command touch"}],
        "injection detected",
    )


def test_analyze_proxy_events_suggests_modules():
    store = AuditStore()
    _seed_injection_event(store)
    data = analyze_proxy_events(store, limit=20)
    assert data["total_events"] == 1
    assert data["action_counts"].get("block") == 1
    assert "direct_injection" in data["suggested_modules"] or "indirect_injection" in data["suggested_modules"]


@pytest.mark.asyncio
async def test_analyze_proxy_events_tool():
    store = AuditStore()
    _seed_injection_event(store)
    raw = await execute_attack_tool(
        META_ANALYZE_PROXY_EVENTS,
        {"limit": 10},
        target_vulnerable=_factory(defense=False),
        target_defended=None,
        proxy_store=store,
    )
    data = json.loads(raw)
    assert data["tool"] == META_ANALYZE_PROXY_EVENTS
    assert data["suggested_modules"]


@pytest.mark.asyncio
async def test_proxy_hunt_react_audit_vd1():
    """V-D1：注入 proxy 样本后，react 狩猎报告含与检测相关的模块。"""
    store = AuditStore()
    _seed_injection_event(store)

    report = await audit_agent_loop(
        planner=DefaultReActLLM(use_proxy_analysis=True),
        target_factory=_factory,
        task=DEFAULT_TASK,
        max_turns=16,
        compare_defense=False,
        proxy_store=store,
    )

    executed = set(report.modules_executed)
    related = {"direct_injection", "indirect_injection", "unexpected_code_execution", "privilege_escalation"}
    assert executed & related, f"expected hunting modules, got {executed}"


def test_web_proxy_hunt_button_and_api(tmp_path):
    db = tmp_path / "web.db"
    store = AuditStore(db)
    _seed_injection_event(store)
    client = TestClient(build_web_app(store, AuditSessionStore(db)))

    page = client.get("/")
    assert "startProxyHuntAudit" in page.text
    assert "基于此流量发起自主审计" in page.text

    data = client.post(
        "/api/auto-audit",
        json={
            "mode": "react",
            "llm": "mock",
            "max_turns": 16,
            "compare_defense": False,
            "use_proxy_hunt": True,
        },
    ).json()
    assert data["summary"]["mode"] == "react"
    modules = set(data["summary"].get("modules_executed") or [])
    assert modules & {"direct_injection", "indirect_injection", "privilege_escalation"}
