"""M5 成本门禁测试（计划书 §7/§8 M5 决策门）：超预算任务被刹停且落库。

决策门验收（mock 确定性）：
1. 单价表可换算可配置：deepseek-chat/reasoner、qwen-plus 内置，set_pricing 可覆盖；
2. CostBudget 任务/日预算超限抛 CostBudgetExceeded（刹停语义，costs 落库告警）；
3. mock campaign + 极小预算 → 任务被刹停（后续格跳过），CLI/控制台落库 aborted + 告警可查；
4. 预算充足时战役正常完成（不误伤）。
"""

from __future__ import annotations

import sqlite3

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from agent_shield.budget import (
    CostBudget,
    CostBudgetExceeded,
    cny_to_usd,
    estimate_cost_usd,
    reset_pricing,
    set_pricing,
    today_start_ts,
)
from agent_shield.campaign import CampaignConfig, run_campaign
from agent_shield.cli import app as cli_app
from agent_shield.core.benchmark import ModelSpec
from agent_shield.orchestrator.usage import LLMUsage
from agent_shield.repair import RepairConfig, run_repair
from agent_shield.self_improve.loop import (
    MockPayloadRewriter,
    SelfImproveConfig,
    run_self_improve,
)
from agent_shield.store import Store
from agent_shield.targets import build_local_target
from agent_shield.web_console import build_console_app

runner = CliRunner()


@pytest.fixture(autouse=True)
def _restore_pricing():
    yield
    reset_pricing()


@pytest.fixture
def store(tmp_path):
    s = Store(tmp_path / "attack-agent.db")
    yield s
    s.close()


def _tiny_budget() -> CostBudget:
    """极小任务预算（USD）：mock 单 case 估算费用 ~1e-5，必然在首格超限。"""
    return CostBudget(task_budget_usd=1e-7)


# --------------------------------------------------------------------------- #
# 决策门 1：单价表换算 + 可配置
# --------------------------------------------------------------------------- #
def test_pricing_known_and_default_models():
    """内置单价表：deepseek-chat/reasoner 同档，qwen-plus/未知走默认档。"""
    assert estimate_cost_usd("deepseek-chat", 1000, 500) == pytest.approx(0.00028)
    assert estimate_cost_usd("deepseek-reasoner", 1000, 500) == pytest.approx(0.00028)
    assert estimate_cost_usd("qwen-plus", 1000, 500) == pytest.approx(0.002)
    assert estimate_cost_usd("unknown-model", 1000, 500) == pytest.approx(0.002)
    # gpt-4 子串规则与旧 usage.py 三档一致
    assert estimate_cost_usd("gpt-4o", 1000, 500) == pytest.approx(0.06)


def test_pricing_matches_usage_forwarder():
    """usage.estimate_cost_usd 转发到 budget 单价表（单一价格源，数值一致）。"""
    from agent_shield.orchestrator.usage import estimate_cost_usd as usage_cost

    u = LLMUsage(prompt_tokens=1000, completion_tokens=500, total_tokens=1500)
    assert usage_cost("deepseek-chat", u) == estimate_cost_usd("deepseek-chat", 1000, 500)
    assert usage_cost("unknown", u) == estimate_cost_usd("unknown", 1000, 500)


def test_set_pricing_override_and_reset():
    """set_pricing 运行时覆盖单价（§7② 可配置），reset_pricing 还原。"""
    set_pricing("my-model", 0.01, 0.02)
    assert estimate_cost_usd("my-model", 1000, 500) == pytest.approx(0.02)
    reset_pricing()
    assert estimate_cost_usd("my-model", 1000, 500) == pytest.approx(0.002)  # 回默认档


def test_cny_to_usd_constant():
    """预算换算：元 → USD（固定汇率常量）。"""
    assert cny_to_usd(0) == 0.0
    assert cny_to_usd(1.0) == pytest.approx(0.14)


# --------------------------------------------------------------------------- #
# 决策门 2：CostBudget 门禁（任务/日预算超限抛异常）
# --------------------------------------------------------------------------- #
def test_cost_budget_task_exceeded():
    b = CostBudget(task_budget_usd=0.001)
    b.spend(0.0006)
    with pytest.raises(CostBudgetExceeded) as ei:
        b.spend(0.0006)
    assert ei.value.kind == "task"
    assert ei.value.spent == pytest.approx(0.0012)
    assert b.exceeded and b.exceeded_kind == "task"


def test_cost_budget_daily_exceeded_with_initial_spent():
    """daily 预算含库中今日已用（initial_daily_spent），超限抛 daily。"""
    b = CostBudget(daily_budget_usd=0.001, initial_daily_spent=0.0009)
    with pytest.raises(CostBudgetExceeded) as ei:
        b.spend(0.0002)
    assert ei.value.kind == "daily"
    assert b.daily_spent == pytest.approx(0.0011)


def test_cost_budget_within_limit_passes():
    b = CostBudget(task_budget_usd=0.01)
    b.spend(0.0005)
    assert not b.exceeded
    assert b.task_spent == pytest.approx(0.0005)


def test_cost_budget_disabled_when_no_limits():
    b = CostBudget()
    assert not b.enabled
    b.spend(0.5)  # 无预算不抛
    assert b.task_spent == pytest.approx(0.5)


# --------------------------------------------------------------------------- #
# 决策门 3：campaign 极小预算 → 刹停（后续格跳过）
# --------------------------------------------------------------------------- #
async def _campaign_cfg(*, budget: CostBudget | None = None, variants: int = 2, rounds: int = 2):
    return CampaignConfig(
        targets=[ModelSpec(label="mock", llm="mock")],
        modules=["indirect_injection"],
        num_variants=variants,
        rounds=rounds,
        concurrency=1,
        seed=7,
        defense=True,
        cost_budget=budget,
    )


async def test_run_campaign_aborted_on_tiny_budget():
    """极小预算 → run_campaign 抛 CostBudgetExceeded，budget 标记 exceeded（刹停）。"""
    b = _tiny_budget()
    cfg = await _campaign_cfg(budget=b)
    with pytest.raises(CostBudgetExceeded):
        await run_campaign(cfg)
    assert b.exceeded


async def test_run_campaign_within_budget_completes():
    """充足预算 → 战役正常完成，不误伤。"""
    b = CostBudget(task_budget_usd=10.0)
    cfg = await _campaign_cfg(budget=b)
    report = await run_campaign(cfg)
    assert len(report.cells) == 2  # 2 轮 × 1 模块 × 1 目标
    assert not b.exceeded


# --------------------------------------------------------------------------- #
# 决策门 4：超限落库（aborted + costs 告警）
# --------------------------------------------------------------------------- #
def test_record_campaign_aborted_status(store):
    """aborted 战役落库：status=aborted，summary 携带 budget_alert。"""
    cfg = CampaignConfig(targets=[ModelSpec(llm="mock")], modules=["indirect_injection"])
    cid = store.record_campaign(
        None, cfg, status="aborted",
        summary_override={"aborted": True, "budget_alert": {"kind": "task"}},
    )
    camp = store.get_campaign(cid)
    assert camp["status"] == "aborted"
    assert camp["summary"]["aborted"] is True


def test_record_cost_alert_and_total_cost_since(store):
    """costs 告警行可查（model=budget-alert:*），且计入 total_cost_since（每日预算口径）。"""
    cfg = CampaignConfig(targets=[ModelSpec(llm="mock")], modules=["indirect_injection"])
    cid = store.record_campaign(None, cfg, status="aborted", summary_override={"aborted": True})
    run_id = store.record_cost_alert(cid, "task", limit_usd=0.001, spent_usd=0.0015)
    run = store.get_run(run_id)
    assert run["verdict"] == "aborted" and run["module"] == "__cost_budget__"
    assert run["costs"] and run["costs"][0]["model"] == "budget-alert:task"
    assert run["costs"][0]["unit_price"] == pytest.approx(0.001)   # 限额
    assert run["costs"][0]["total_cost"] == pytest.approx(0.0015)  # 已花
    # 每日预算口径：告警的已花计入今日累计
    assert store.total_cost_since(today_start_ts()) == pytest.approx(0.0015)


async def test_store_persist_full_aborted_chain(store):
    """全链路：超限 campaign 落库 aborted，已收集格费用照实入库，告警可查。"""
    cells: list[tuple] = []
    b = _tiny_budget()
    cfg = CampaignConfig(
        targets=[ModelSpec(label="mock", llm="mock")],
        modules=["indirect_injection"],
        num_variants=1, rounds=2, concurrency=1, seed=7, defense=True,
        cost_budget=b,
        on_cell_result=lambda spec, module_name, round_idx, result: cells.append(
            (spec, module_name, round_idx, result)
        ),
    )
    with pytest.raises(CostBudgetExceeded) as ei:
        await run_campaign(cfg)
    # 首格已收集（回调先于 spend 检查触发）
    assert len(cells) >= 1
    cid = store.record_campaign(
        None, cfg, status="aborted",
        summary_override={"aborted": True, "budget_alert": ei.value.as_dict()},
    )
    for spec, _m, _r, result in cells:
        store.record_attack_result(result, campaign_id=cid, target=spec.label, defense=True)
    store.record_cost_alert(cid, ei.value.kind, ei.value.limit, ei.value.spent)
    camp = store.get_campaign(cid)
    assert camp["status"] == "aborted"
    assert len(camp["runs"]) == len(cells) + 1  # 已收集格 + 1 条告警 run


# --------------------------------------------------------------------------- #
# 决策门 5：self-improve / repair / CLI / Web 控制台 刹停
# --------------------------------------------------------------------------- #
async def test_self_improve_aborted_on_tiny_budget():
    """自改进循环：极小预算 → 首轮执行即超限抛异常（刹停）。"""
    cfg = SelfImproveConfig(
        module="human_trust_exploitation",
        target=build_local_target(llm="mock", defense=False),
        rewriter=MockPayloadRewriter(),
        num_variants=2, rounds=2, seed=7,
        cost_budget=_tiny_budget(),
    )
    with pytest.raises(CostBudgetExceeded):
        await run_self_improve(cfg)


async def test_repair_aborted_on_tiny_budget():
    """修复闭环：极小预算 → 裸机对照阶段即超限抛异常（刹停）。"""
    cfg = RepairConfig(
        blind_spot="injection_relaxed_signals",
        llm="mock", num_variants=2, seed=7,
        cost_budget=_tiny_budget(),
    )
    with pytest.raises(CostBudgetExceeded):
        await run_repair(cfg)


def test_cli_run_campaign_budget_aborts_and_persists(tmp_path):
    """CLI：--cost-budget 极小 → 非零退出 + aborted 战役 + costs 告警落库。"""
    db = tmp_path / "m5.db"
    result = runner.invoke(
        cli_app,
        [
            "run-campaign", "--targets", "mock", "-m", "indirect_injection",
            "-n", "1", "--rounds", "1", "--cost-budget", "0.0000001",
            "--store", str(db),
        ],
    )
    assert result.exit_code == 1
    assert "成本门禁超限" in result.output
    assert "aborted" in result.output
    conn = sqlite3.connect(db)
    try:
        status = conn.execute("SELECT status FROM campaigns ORDER BY ts DESC LIMIT 1").fetchone()[0]
        assert status == "aborted"
        alert = conn.execute(
            "SELECT model FROM costs WHERE model LIKE 'budget-alert:%' ORDER BY id DESC LIMIT 1"
        ).fetchone()
        assert alert is not None and alert[0].startswith("budget-alert:")
    finally:
        conn.close()


def test_cli_run_campaign_budget_ok_completes(tmp_path):
    """CLI：--cost-budget 充足 → 正常完成 + completed 战役落库。"""
    db = tmp_path / "m5-ok.db"
    result = runner.invoke(
        cli_app,
        [
            "run-campaign", "--targets", "mock", "-m", "indirect_injection",
            "-n", "1", "--rounds", "1", "--cost-budget", "10", "--store", str(db),
        ],
    )
    assert result.exit_code == 0, result.output
    conn = sqlite3.connect(db)
    try:
        status = conn.execute("SELECT status FROM campaigns ORDER BY ts DESC LIMIT 1").fetchone()[0]
        assert status == "completed"
    finally:
        conn.close()


def test_web_console_dispatch_aborted(tmp_path):
    """Web 控制台：下发带极小预算的 campaign → 结果带 aborted 标记，库中可查告警。"""
    db = tmp_path / "console-m5.db"
    with TestClient(build_console_app(store_path=db)) as client:
        res = client.post("/api/dispatch", json={
            "kind": "campaign",
            "params": {
                "targets": "mock", "modules": "indirect_injection",
                "variants": 1, "rounds": 1, "defense": True,
                "cost_budget": 0.0000001,
            },
        })
        assert res.status_code == 200
        job_id = res.json()["job_id"]
        for _ in range(300):
            data = client.get(f"/api/jobs/{job_id}").json()
            if data["status"] != "running":
                break
            import time
            time.sleep(0.05)
        assert data["status"] == "done", data.get("error")
        assert data["result"]["aborted"] is True
        assert data["result"]["budget_alert"]["kind"] in ("task", "daily")
        conn = sqlite3.connect(db)
        try:
            alert = conn.execute(
                "SELECT model FROM costs WHERE model LIKE 'budget-alert:%' LIMIT 1"
            ).fetchone()
            assert alert is not None
        finally:
            conn.close()
