"""M4 Web 控制台测试：任务下发 → 结果视图 → 报告导出 全流程（mock 确定性）。

决策门（计划书 §8 M4）：一条命令起 Web，单人完成"下发→看结果→导出 md/svg"全流程。
"""

import time

from fastapi.testclient import TestClient

from agent_shield.proxy.audit import AuditStore
from agent_shield.web_console import build_console_app
from agent_shield.webapp import build_web_app


def _client(tmp_path) -> TestClient:
    return TestClient(build_console_app(store_path=tmp_path / "console.db"))


def _poll_job(client, job_id, max_tries=300):
    for _ in range(max_tries):
        data = client.get(f"/api/jobs/{job_id}").json()
        if data["status"] != "running":
            return data
        time.sleep(0.05)
    raise AssertionError("job 未在预期时间内完成")


def _dispatch(client, kind, params):
    res = client.post("/api/dispatch", json={"kind": kind, "params": params})
    assert res.status_code == 200, res.text
    job = _poll_job(client, res.json()["job_id"])
    assert job["status"] == "done", job.get("error")
    return job["result"]


# --------------------------------------------------------------------------- #
# 页面与元数据
# --------------------------------------------------------------------------- #
def test_index_page_renders(tmp_path):
    with _client(tmp_path) as client:
        page = client.get("/")
        assert page.status_code == 200
        assert "AgentShield 控制台" in page.text
        assert "任务下发" in page.text and "结果视图" in page.text and "报告导出" in page.text


def test_modules_api_lists_all_modules(tmp_path):
    with _client(tmp_path) as client:
        data = client.get("/api/modules").json()
        assert len(data) == 14


def test_blind_spots_api_lists_cases(tmp_path):
    with _client(tmp_path) as client:
        data = client.get("/api/blind-spots").json()
        ids = {d["id"] for d in data}
        assert "injection_relaxed_signals" in ids and "final_output_no_guard" in ids


def test_dispatch_unknown_kind_400(tmp_path):
    with _client(tmp_path) as client:
        res = client.post("/api/dispatch", json={"kind": "nope", "params": {}})
        assert res.status_code == 400


# --------------------------------------------------------------------------- #
# 任务下发 → 结果视图 → 导出（campaign 全流程）
# --------------------------------------------------------------------------- #
def test_campaign_dispatch_view_export_full_flow(tmp_path):
    with _client(tmp_path) as client:
        result = _dispatch(client, "campaign", {
            "targets": "mock", "modules": "direct_injection", "variants": 2, "defense": False,
        })
        assert result["kind"] == "campaign"
        cid = result["campaign_id"]
        assert result["runs"] == 1
        assert result["summary"]["per_target"]["mock"]["asr"] == 1.0

        # 结果视图：campaigns 列表 → 明细（runs）
        campaigns = client.get("/api/campaigns").json()
        assert any(c["id"] == cid for c in campaigns)
        detail = client.get(f"/api/campaigns/{cid}").json()
        assert len(detail["runs"]) == 1
        run_id = detail["runs"][0]["id"]

        # run 明细：traces / verdicts / costs
        run = client.get(f"/api/campaigns/{cid}/runs/{run_id}").json()
        assert run["traces"] and run["verdicts"] and run["costs"]
        assert run["verdicts"][0]["verdict"] == "success"

        # 报告导出：md + svg
        md = client.get(f"/api/campaigns/{cid}/report.md")
        assert md.status_code == 200 and "AgentShield" in md.text
        assert md.headers["content-disposition"].startswith("attachment")
        svg = client.get(f"/api/campaigns/{cid}/chart.svg")
        assert svg.status_code == 200 and "<svg" in svg.text
        assert svg.headers["content-disposition"].startswith("attachment")


def test_campaign_unknown_404(tmp_path):
    with _client(tmp_path) as client:
        assert client.get("/api/campaigns/nope").status_code == 404
        assert client.get("/api/campaigns/nope/report.md").status_code == 404
        assert client.get("/api/campaigns/nope/chart.svg").status_code == 404


# --------------------------------------------------------------------------- #
# 任务下发：repair / self-improve
# --------------------------------------------------------------------------- #
def test_repair_dispatch_verified(tmp_path):
    with _client(tmp_path) as client:
        result = _dispatch(client, "repair", {
            "blind_spot": "injection_relaxed_signals", "variants": 2,
        })
        assert result["kind"] == "repair"
        assert result["verified"] is True
        assert result["asr"] == {"bare": 1.0, "flawed": 1.0, "fixed": 0.0}

        # findings 状态机：direct_injection 应为 verified
        findings = client.get("/api/findings").json()
        row = next(f for f in findings if f["module"] == "direct_injection")
        assert row["status"] == "verified"
        assert row["asr_bare"] == 1.0 and row["asr_defended"] == 0.0


def test_repair_dispatch_unknown_blind_spot_errors(tmp_path):
    with _client(tmp_path) as client:
        res = client.post("/api/dispatch", json={"kind": "repair", "params": {"blind_spot": "nope"}})
        job = _poll_job(client, res.json()["job_id"])
        assert job["status"] == "error"
        assert "未知盲区案例" in job["error"]


def test_self_improve_dispatch(tmp_path):
    with _client(tmp_path) as client:
        result = _dispatch(client, "self-improve", {
            "module": "human_trust_exploitation", "budget": 6, "rounds": 2, "variants": 2,
        })
        assert result["kind"] == "self-improve"
        assert result["campaign_id"]
        assert result["baseline_asr"] == 1.0
        campaigns = client.get("/api/campaigns").json()
        assert any(c["id"] == result["campaign_id"] for c in campaigns)


def test_openai_dispatch_requires_model(tmp_path):
    """openai-compat 未给 model 必须报错（与 CLI 校验一致，不发起真实调用）。"""
    with _client(tmp_path) as client:
        res = client.post("/api/dispatch", json={"kind": "campaign", "params": {"llm": "openai-compat"}})
        job = _poll_job(client, res.json()["job_id"])
        assert job["status"] == "error"
        assert "model" in job["error"]


# --------------------------------------------------------------------------- #
# 挂载集成：web 命令的 build_web_app + /console（一条命令起 Web）
# --------------------------------------------------------------------------- #
def test_mounted_console_inside_workbench(tmp_path):
    app = build_web_app(AuditStore(tmp_path / "audit.db"))
    app.mount("/console", build_console_app(store_path=tmp_path / "console.db"))
    with TestClient(app) as client:
        assert client.get("/").status_code == 200  # 原攻防工作台不受影响
        page = client.get("/console/")
        assert page.status_code == 200 and "AgentShield 控制台" in page.text
        assert client.get("/console/api/modules").json().__len__() == 14
