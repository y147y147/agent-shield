"""M1 数据层测试（计划书 §5/§8 M1 决策门）：campaign 全链路落库可查 + findings 状态机。

决策门验收：
1. 一次 mock campaign 全链路落库可查（campaigns → attack_runs → traces/verdicts/costs → findings）；
2. findings 能标 open / patched / verified 三态（含非法迁移拒绝）；
3. 隔离字段（user_id/tenant_id/job_id）默认 0，schema 幂等可重复初始化。
"""

from __future__ import annotations

import sqlite3

import pytest

from agent_shield.campaign import CampaignConfig, run_campaign
from agent_shield.core.benchmark import ModelSpec
from agent_shield.store import FindingStatus, Store


@pytest.fixture
def store(tmp_path):
    s = Store(tmp_path / "attack-agent.db")
    yield s
    s.close()


async def _mock_campaign_cells(*, defense: bool = True, seed: int = 7):
    """跑一个小型 mock campaign（单模块、单变体，CI 快），返回 (report, cells)。"""
    cells: list[tuple] = []
    cfg = CampaignConfig(
        targets=[ModelSpec(label="mock", llm="mock")],
        modules=["indirect_injection"],
        num_variants=1,
        rounds=1,
        concurrency=1,
        seed=seed,
        defense=defense,
        on_cell_result=lambda spec, module_name, round_idx, result: cells.append(
            (spec, module_name, round_idx, result)
        ),
    )
    report = await run_campaign(cfg)
    return report, cells


# --------------------------------------------------------------------------- #
# 决策门 1：mock campaign 全链路落库可查
# --------------------------------------------------------------------------- #
async def test_campaign_full_chain_persists_and_queryable(store):
    """M1 决策门①：一次 mock campaign 全链路（campaign→run→trace→verdict→cost→finding）落库可查。"""
    report, cells = await _mock_campaign_cells()
    assert cells, "回调应收集到至少一个 (spec, module, round, result)"

    cid = store.record_campaign(report, report.cfg)
    for spec, module_name, _round, result in cells:
        store.record_attack_result(result, campaign_id=cid, target=spec.label, defense=True)
        store.upsert_finding(result, campaign_id=cid, target=spec.label, defense=True)

    # campaigns
    camp = store.get_campaign(cid)
    assert camp is not None and camp["id"] == cid
    assert camp["config"]["modules"] == ["indirect_injection"]
    assert len(camp["runs"]) == len(cells)
    run = camp["runs"][0]
    assert run["module"] == "indirect_injection" and run["defense"] is True
    assert 0 <= run["asr"] <= 1

    # traces + verdicts + costs（每 run 至少一条）
    conn = sqlite3.connect(store.path)
    try:
        n_traces = conn.execute("SELECT COUNT(*) FROM traces WHERE run_id = ?", (run["id"],)).fetchone()[0]
        n_verdicts = conn.execute("SELECT COUNT(*) FROM verdicts WHERE run_id = ?", (run["id"],)).fetchone()[0]
        n_costs = conn.execute("SELECT COUNT(*) FROM costs WHERE run_id = ?", (run["id"],)).fetchone()[0]
        assert n_traces >= 1 and n_verdicts >= 1 and n_costs == 1
        row = conn.execute(
            "SELECT module, final_blocked, intent_flag FROM traces WHERE run_id = ? LIMIT 1",
            (run["id"],),
        ).fetchone()
        assert row[0] == "indirect_injection"
        assert row[1] in (0, 1) and row[2] in (0, 1)
    finally:
        conn.close()

    # findings：加固侧写入 asr_defended
    finding = store.get_finding("indirect_injection")
    assert finding is not None
    assert finding.status == FindingStatus.OPEN
    assert finding.asr_defended is not None  # 本 campaign 是加固档
    assert finding.asr_bare is None  # 裸机档另跑（决策门②见下）

    # 可累积：第二次 campaign 可查
    report2, cells2 = await _mock_campaign_cells(defense=False, seed=99)
    cid2 = store.record_campaign(report2, report2.cfg)
    for spec, module_name, _round, result in cells2:
        store.record_attack_result(result, campaign_id=cid2, target=spec.label, defense=False)
        store.upsert_finding(result, campaign_id=cid2, target=spec.label, defense=False)
    assert len(store.list_campaigns()) == 2
    merged = store.get_finding("indirect_injection")
    assert merged.asr_bare is not None and merged.asr_defended is not None  # 双侧合并


async def test_store_schema_has_all_six_tables(store):
    conn = sqlite3.connect(store.path)
    try:
        tables = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        )}
        assert {"campaigns", "attack_runs", "traces", "verdicts", "costs", "findings"} <= tables
        assert conn.execute("PRAGMA user_version").fetchone()[0] >= 1
    finally:
        conn.close()


# --------------------------------------------------------------------------- #
# 决策门 2：findings 状态机 open → patched → verified
# --------------------------------------------------------------------------- #
async def test_finding_state_machine_full_cycle(store):
    _, cells = await _mock_campaign_cells()
    store.record_attack_result(cells[0][3], campaign_id="c1", target="mock", defense=True)
    store.upsert_finding(cells[0][3], campaign_id="c1", target="mock", defense=True)

    # open → patched → verified
    f = store.set_finding_status("indirect_injection", FindingStatus.PATCHED, notes="新增第四钩子 sanitize_final_output")
    assert f.status == FindingStatus.PATCHED and "第四钩子" in f.repair_notes
    f = store.set_finding_status("indirect_injection", FindingStatus.VERIFIED, notes="三连测回归通过")
    assert f.status == FindingStatus.VERIFIED

    # verified → open（回归漂移重开）
    f = store.set_finding_status("indirect_injection", FindingStatus.OPEN, notes="新变体打穿，重开")
    assert f.status == FindingStatus.OPEN


def test_finding_state_machine_rejects_illegal_transition(store):
    store.record_matrix_row({
        "module": "direct_injection",
        "vulnerable_success_rate": 1.0,
        "defended_success_rate": 0.0,
    }, campaign_id="c0")
    assert store.get_finding("direct_injection").status == FindingStatus.OPEN
    # 不存在的 module 抛 KeyError
    with pytest.raises(KeyError):
        store.set_finding_status("nope_module", FindingStatus.PATCHED)
    # verified → patched 是回退（非法，必须先 open）
    store.set_finding_status("direct_injection", FindingStatus.VERIFIED)
    with pytest.raises(ValueError):
        store.set_finding_status("direct_injection", FindingStatus.PATCHED)
    # 合法回退：verified → open → patched
    assert store.set_finding_status("direct_injection", FindingStatus.OPEN).status == FindingStatus.OPEN
    assert store.set_finding_status("direct_injection", FindingStatus.PATCHED).status == FindingStatus.PATCHED


# --------------------------------------------------------------------------- #
# 决策门 3：隔离字段默认 + schema 幂等
# --------------------------------------------------------------------------- #
def test_isolations_default_zero_and_migration_idempotent(tmp_path):
    p = tmp_path / "again.db"
    s1 = Store(p)
    s1.close()
    # 幂等：同一路径重复初始化不报错
    s2 = Store(p)
    s2.close()

    s3 = Store(p)
    conn = sqlite3.connect(p)
    try:
        row = conn.execute(
            "SELECT user_id, tenant_id, job_id FROM campaigns LIMIT 1"
        ).fetchone()
        assert row is None  # 无 campaign 时列存在即可
        cols = {r[1] for r in conn.execute("PRAGMA table_info(campaigns)")}
        assert {"user_id", "tenant_id", "job_id"} <= cols
    finally:
        conn.close()
    s3.close()


# --------------------------------------------------------------------------- #
# 落库旁路回调不影响战役（异常被吞）
# --------------------------------------------------------------------------- #
async def test_on_cell_result_exception_does_not_break_campaign():
    def boom(*_a, **_k):
        raise RuntimeError("callback boom")

    cfg = CampaignConfig(
        targets=[ModelSpec(label="mock", llm="mock")],
        modules=["indirect_injection"],
        num_variants=1,
        rounds=1,
        concurrency=1,
        seed=1,
        defense=True,
        on_cell_result=boom,
    )
    report = await run_campaign(cfg)  # 不应抛错
    assert len(report.cells) == 1
