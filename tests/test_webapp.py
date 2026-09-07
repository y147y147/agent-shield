"""Web 攻防工作台测试：页面渲染 + 攻防 API + 模型对比 + 策略 + 沙箱 + 审计。"""

from fastapi.testclient import TestClient

from agent_shield.proxy.audit import AuditStore
from agent_shield.webapp import build_web_app


def _client() -> TestClient:
    return TestClient(build_web_app(AuditStore()))


def test_index_page_renders():
    client = _client()
    page = client.get("/")
    assert page.status_code == 200
    assert "攻防工作台" in page.text
    assert "模型对比" in page.text
    # 回归：过程链容器与状态行必须存在且分离（spinner 不能覆盖过程链）
    assert 'id="chain"' in page.text
    assert 'id="run-status"' in page.text
    assert 'id="chain-done"' in page.text


def test_modules_api_lists_all_12():
    client = _client()
    data = client.get("/api/modules").json()
    assert len(data) == 12
    assert {m["owasp_asi"] for m in data} == {f"ASI-{i:02d}" for i in range(1, 11)}


def test_attack_api_succeeds_on_vulnerable():
    client = _client()
    data = client.post("/api/attack", json={"module": "indirect_injection", "llm": "mock", "variants": 2}).json()
    assert data["summary"]["successes"] == 2
    assert data["summary"]["success_rate"] == 1.0
    assert data["timeline"], "应返回 Agent 轨迹时间线"


def test_attack_api_compare_before_after():
    client = _client()
    data = client.post(
        "/api/attack", json={"module": "indirect_injection", "llm": "mock", "variants": 2, "compare": True}
    ).json()
    assert data["compare"] is True
    assert data["before"]["summary"]["successes"] == 2
    assert data["after"]["summary"]["successes"] == 0


def test_attack_api_defense_blocks():
    client = _client()
    data = client.post(
        "/api/attack", json={"module": "rogue_agent", "llm": "mock", "variants": 2, "defense": True}
    ).json()
    assert data["summary"]["successes"] == 0
    assert data["summary"]["blocked"] == 2


def test_policy_check_api_denies_bypass():
    client = _client()
    data = client.post(
        "/api/policy/check",
        json={"tool": "run_command", "arguments": {"command": "cat /etc/passwd"}},
    ).json()
    assert data["allowed"] is False
    assert "outside allowed roots" in data["reason"]


def test_policy_check_api_allows_safe():
    client = _client()
    data = client.post(
        "/api/policy/check",
        json={"tool": "run_command", "arguments": {"command": "ls -la /tmp"}},
    ).json()
    assert data["allowed"] is True


def test_sandbox_api_runs_command():
    client = _client()
    data = client.post("/api/sandbox/run", json={"command": "echo hello", "sandbox": True}).json()
    assert data["returncode"] == 0
    assert "hello" in data["stdout"]


def test_sandbox_api_denies_dangerous_command():
    """沙箱测试页：危险命令必须被拦截（策略层或沙箱黑名单），且不执行。"""
    client = _client()
    data = client.post("/api/sandbox/run", json={"command": "rm -rf /", "sandbox": True}).json()
    assert data["denied"] is True
    assert data["stage"] in ("policy", "sandbox")
    assert "denied" in data["stderr"]


def test_sandbox_api_policy_denies_even_without_sandbox():
    """沙箱测试页：即使关闭沙箱开关，危险命令仍被语义策略拦截。"""
    client = _client()
    data = client.post("/api/sandbox/run", json={"command": "cat /etc/passwd", "sandbox": False}).json()
    assert data["denied"] is True
    assert data["stage"] == "policy"


def test_ping_api_mock():
    client = _client()
    data = client.post("/api/ping", json={"llm": "mock"}).json()
    assert data["ok"] is True


def test_ping_api_requires_model_for_openai():
    client = _client()
    res = client.post("/api/ping", json={"llm": "openai-compat", "model": ""})
    assert res.status_code == 400
    assert "模型名" in res.json()["detail"]


def test_benchmark_api_mock_model():
    client = _client()
    data = client.post(
        "/api/benchmark",
        json={"module": "indirect_injection", "models": [{"label": "Mock", "model": "mock"}], "variants": 2},
    ).json()
    assert data["rows"][0]["vulnerable_success_rate"] == 1.0
    assert data["rows"][0]["defended_success_rate"] == 0.0


def test_benchmark_skips_mock_only_module_on_real_model():
    """ASI-10 失控智能体需控制内部状态：对黑盒真实 API 标记不可测，且不发起真实调用。"""
    client = _client()
    data = client.post(
        "/api/benchmark",
        json={
            "module": "rogue_agent",
            "models": [
                {"label": "Mock", "model": "mock"},
                {"label": "真实模型", "model": "some-model", "base_url": "http://127.0.0.1:1/v1"},
            ],
        },
    ).json()
    assert data["rows"][0]["vulnerable_success_rate"] == 1.0  # Mock 可测
    assert data["rows"][1]["skipped"] is True  # 真实 API 不可测（未发起网络请求）
    assert "Mock" in data["rows"][1]["note"]


def test_audit_api_records_attack_events():
    store = AuditStore()
    client = TestClient(build_web_app(store))
    client.post("/api/attack", json={"module": "indirect_injection", "llm": "mock", "variants": 1})
    data = client.get("/api/audit").json()
    assert data["summary"]["total"] >= 1
    assert any(e["action"] == "executed" for e in data["events"])


# --------------------------------------------------------------------------- #
# 实时过程链（stream + 轮询 events）
# --------------------------------------------------------------------------- #
def _poll_job(client, job_id, max_tries=100):
    import time

    for _ in range(max_tries):
        data = client.get(f"/api/attack/events/{job_id}").json()
        if data["status"] != "running":
            return data
        time.sleep(0.05)
    raise AssertionError("job 未在预期时间内完成")


def test_attack_stream_shows_process_chain():
    client = _client()
    res = client.post(
        "/api/attack/stream",
        json={"module": "indirect_injection", "llm": "mock", "variants": 1},
    )
    assert res.status_code == 200
    job_id = res.json()["job_id"]

    # 首个轮询：mock 可能已秒完成，但过程链事件必须可见（不是最后才出结果）
    first = client.get(f"/api/attack/events/{job_id}").json()
    assert first["status"] in ("running", "done")
    assert first["events"], "任务应已有过程链事件"

    done = _poll_job(client, job_id)
    assert done["status"] == "done"
    types = {e["type"] for e in done["events"]}
    # 过程链必须包含：用户输入 / 模型决策 / 工具调用 / 工具输出 / 最终答复
    assert {"user", "think", "call", "output", "final"} <= types
    assert done["result"]["summary"]["successes"] == 1


def test_attack_stream_compare_two_phases():
    client = _client()
    res = client.post(
        "/api/attack/stream",
        json={"module": "indirect_injection", "llm": "mock", "variants": 1, "compare": True},
    )
    job_id = res.json()["job_id"]
    done = _poll_job(client, job_id)
    assert done["status"] == "done"
    phases = [e["label"] for e in done["events"] if e["type"] == "phase"]
    assert len(phases) == 2
    assert done["result"]["before"]["summary"]["successes"] == 1
    assert done["result"]["after"]["summary"]["successes"] == 0


def test_attack_stream_error_surfaces():
    client = _client()
    res = client.post("/api/attack/stream", json={"module": "unknown_module_x", "llm": "mock"})
    # 模块不存在：job 快速进入 error 状态
    job_id = res.json()["job_id"]
    done = _poll_job(client, job_id)
    assert done["status"] == "error"
    assert done["error"]
