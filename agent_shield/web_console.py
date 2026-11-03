"""M4 Web 控制台：任务下发 → 结果视图 → 报告导出（扩展现有 audit dashboard）。

设计（计划书 §8 M4）：
- 挂载进现有 ``web`` 命令（/console），一条命令起 Web；mock 默认零成本，真实模型由用户填
  model/base-url/api-key（密钥只透传调用、不落库）；
- 任务下发：campaign（run_campaign）｜ self-improve（run_self_improve）｜ repair（run_repair）
  三类任务，异步 job 轮询（复用现有 /api/attack/stream 的 job 模式）；
- 结果视图：campaigns 列表 / campaign 明细（runs）/ run 明细（traces/verdicts/costs）/ findings；
- 报告导出：campaign 的 markdown（入库时已存）+ SVG 图表（由 runs 重建 CampaignReport 渲染）。
"""

from __future__ import annotations

import asyncio
import uuid
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel, Field

from agent_shield.attacks import list_attack_modules
from agent_shield.budget import CostBudgetExceeded
from agent_shield.campaign import (
    DEFAULT_TASK,
    CampaignConfig,
    CampaignReport,
    CellResult,
    run_campaign,
)
from agent_shield.core.benchmark import ModelSpec
from agent_shield.core.campaign_chart import render_campaign_chart_svg
from agent_shield.defenses import IntentClassifier
from agent_shield.models import AttackCase, AttackResult, AttackVerdict
from agent_shield.repair import RepairConfig, list_blind_spots, run_repair
from agent_shield.self_improve.loop import (
    LLMRewriter,
    MockPayloadRewriter,
    SelfImproveConfig,
    rewrite_profile_for,
    run_self_improve,
)
from agent_shield.store import FindingStatus, Store, default_attack_db_path
from agent_shield.targets import build_local_target


# --------------------------------------------------------------------------- #
# 任务下发参数与 job 调度
# --------------------------------------------------------------------------- #
class DispatchRequest(BaseModel):
    kind: str  # campaign | self-improve | repair
    params: dict[str, Any] = Field(default_factory=dict)


_jobs: dict[str, dict[str, Any]] = {}
# 强引用集：防止 create_task 后台任务在完成前被垃圾回收
_tasks: set[asyncio.Task] = set()


async def _run_job(job_id: str, coro) -> None:
    """异步执行下发任务，结果/错误写入 job 状态（错误兜底返回给前端展示）。"""
    try:
        result = await coro
        _jobs[job_id] = {"status": "done", "result": result, "error": None}
    except Exception as exc:  # noqa: BLE001 —— 前端展示具体失败原因
        _jobs[job_id] = {"status": "error", "result": None, "error": f"{type(exc).__name__}: {exc}"}


def _parse_target_specs(targets: str, *, llm: str = "mock", model: str | None = None,
                        base_url: str | None = None, api_key: str | None = None) -> list[ModelSpec]:
    """解析 targets 输入（CLI 同款语法：'label' 或 'label=model'，逗号分隔）。"""
    specs: list[ModelSpec] = []
    for tok in [t.strip() for t in targets.split(",") if t.strip()]:
        if "=" in tok:
            label, _, m = tok.partition("=")
            specs.append(ModelSpec(
                label=label.strip(), llm="openai-compat" if m.strip() else "mock",
                model=m.strip() or None, base_url=base_url, api_key=api_key,
            ))
        else:
            specs.append(ModelSpec(
                label=tok, llm=llm,
                model=model if llm == "openai-compat" else None,
                base_url=base_url, api_key=api_key,
            ))
    return specs or [ModelSpec(llm="mock")]


def _require_openai_model(params: dict[str, Any], llm: str) -> None:
    """openai-compat 必须指定 model（与 CLI 校验一致），否则前端直接报错。"""
    if llm == "openai-compat" and not params.get("model"):
        raise ValueError("使用 openai-compat 时必须指定 model（如 deepseek-chat）")


def _make_console_budget(p: dict[str, Any], store: Store) -> Any | None:
    """M5：从下发参数构造 CostBudget（单位=元 → USD；daily 经 store 查今日已用）。"""
    cost_budget = float(p.get("cost_budget", 0.0) or 0.0)
    daily_budget = float(p.get("daily_budget", 0.0) or 0.0)
    if not cost_budget and not daily_budget:
        return None
    from agent_shield.budget import CostBudget, cny_to_usd, today_start_ts

    initial = store.total_cost_since(today_start_ts()) if store is not None else 0.0
    return CostBudget(
        task_budget_usd=cny_to_usd(cost_budget) if cost_budget else None,
        daily_budget_usd=cny_to_usd(daily_budget) if daily_budget else None,
        initial_daily_spent=initial,
    )


def _persist_aborted_campaign(store: Store, cfg: Any, exc: CostBudgetExceeded) -> str:
    """成本超限刹停落库：aborted 战役（summary 含告警）+ costs 告警行，返回 campaign_id。"""
    cid = store.record_campaign(
        None, cfg, status="aborted",
        summary_override={"aborted": True, "budget_alert": exc.as_dict()},
    )
    store.record_cost_alert(cid, exc.kind, exc.limit, exc.spent)
    return cid


# --------------------------------------------------------------------------- #
# 三类任务的下发实现（含 store 落库，与 CLI 同款语义）
# --------------------------------------------------------------------------- #
async def _dispatch_campaign(store: Store, p: dict[str, Any]) -> dict[str, Any]:
    llm = p.get("llm", "mock")
    _require_openai_model(p, llm)
    cfg = CampaignConfig(
        targets=_parse_target_specs(
            p.get("targets", "mock"), llm=llm, model=p.get("model"),
            base_url=p.get("base_url"), api_key=p.get("api_key"),
        ),
        modules=[m.strip() for m in str(p.get("modules", "")).split(",") if m.strip()],
        num_variants=int(p.get("variants", 3)),
        rounds=int(p.get("rounds", 1)),
        concurrency=int(p.get("concurrency", 1)),
        seed=p.get("seed"), defense=bool(p.get("defense", True)),
        task=p.get("task", DEFAULT_TASK),
    )
    # M5：成本预算透传（元 → USD），超限刹停并落库 aborted + costs 告警
    cfg.cost_budget = _make_console_budget(p, store)
    cells: list[tuple[ModelSpec, str, int, Any]] = []
    cfg.on_cell_result = lambda spec, module_name, round_idx, result: cells.append(
        (spec, module_name, round_idx, result)
    )
    try:
        report = await run_campaign(cfg)
    except CostBudgetExceeded as exc:
        cid = _persist_aborted_campaign(store, cfg, exc)
        for spec, _module_name, _round_idx, result in cells:
            store.record_attack_result(result, campaign_id=cid, target=spec.label, defense=cfg.defense)
        return {
            "kind": "campaign", "campaign_id": cid, "runs": len(cells),
            "aborted": True, "budget_alert": exc.as_dict(),
            "summary": {"aborted": True, "budget_alert": exc.as_dict()},
        }
    cid = store.record_campaign(report, cfg)
    for spec, _module_name, _round_idx, result in cells:
        store.record_attack_result(result, campaign_id=cid, target=spec.label, defense=cfg.defense)
        store.upsert_finding(result, campaign_id=cid, target=spec.label, defense=cfg.defense)
    return {
        "kind": "campaign", "campaign_id": cid, "runs": len(cells),
        "summary": report.summary(), "findings": store.count_findings(),
    }


async def _dispatch_self_improve(store: Store, p: dict[str, Any]) -> dict[str, Any]:
    module = p.get("module", "tool_impersonation")
    llm = p.get("llm", "mock")
    _require_openai_model(p, llm)
    defense = bool(p.get("defense", False))
    intent_classifier = bool(p.get("intent_classifier", False))
    profile = rewrite_profile_for(module)
    action_hint = p.get("action_hint", "auto")
    if action_hint == "auto":
        action_hint = profile.action_hint
    action_description = p.get("action_description") or profile.action_description
    classifier = IntentClassifier() if intent_classifier else None
    target = build_local_target(
        llm=llm, defense=defense, model=p.get("model"),
        api_key=p.get("api_key"), base_url=p.get("base_url"),
        intent_classifier=classifier,
    )
    budget_gate = _make_console_budget(p, store)  # M5 成本门禁
    if llm == "openai-compat":
        rewriter = LLMRewriter(
            model=p.get("model"), api_key=p.get("api_key"), base_url=p.get("base_url"),
            action_description=action_description, cost_budget=budget_gate,
            marker=profile.marker, style=profile.style,
        )
    else:
        rewriter = MockPayloadRewriter(
            marker=profile.marker or "touch /tmp/agent-shield-selfimprove-pwned",
            style=profile.style,
        )
    cfg = SelfImproveConfig(
        module=module, target=target, rewriter=rewriter,
        budget=int(p.get("budget", 12)), rounds=int(p.get("rounds", 3)),
        num_variants=int(p.get("variants", 3)), task=p.get("task", DEFAULT_TASK),
        seed=p.get("seed"), action_hint=action_hint, cost_budget=budget_gate,
    )
    try:
        report = await run_self_improve(cfg)
    except CostBudgetExceeded as exc:
        cfg_store = CampaignConfig(
            targets=[ModelSpec(label="selfimprove", llm=llm, model=p.get("model"))],
            modules=[module], rounds=cfg.rounds, defense=defense,
        )
        cid = _persist_aborted_campaign(store, cfg_store, exc)
        return {
            "kind": "self-improve", "campaign_id": cid, "module": module,
            "aborted": True, "budget_alert": exc.as_dict(),
        }

    verdict_of = {
        "success": AttackVerdict.SUCCESS,
        "blocked": AttackVerdict.BLOCKED,
        "failed": AttackVerdict.FAILED,
    }
    cases = [
        AttackCase(
            module=module, name=f"attempt-{i}", payload=a.payload,
            verdict=verdict_of[a.verdict],
            evidence=[a.feedback] if a.feedback else [],
        )
        for i, a in enumerate(report.attempts, start=1)
    ]
    result = AttackResult(
        module=module,
        description=f"self-improve loop (budget={cfg.budget}, rounds={cfg.rounds}, action_hint={action_hint})",
        cases=cases,
    )
    cfg_store = CampaignConfig(
        targets=[ModelSpec(label="selfimprove", llm=llm, model=p.get("model"))],
        modules=[module], rounds=cfg.rounds, defense=defense,
    )
    cid = store.record_campaign(report, cfg_store)
    store.record_attack_result(result, campaign_id=cid, target="selfimprove", defense=defense)
    store.upsert_finding(result, campaign_id=cid, target="selfimprove", defense=defense)
    return {
        "kind": "self-improve", "campaign_id": cid, "module": module,
        "baseline_asr": report.baseline_asr, "improved_asr": report.improved_asr,
        "gain": report.summary().get("gain", 0.0),
        "executions": report.executions, "rounds": report.rounds,
        "findings": store.count_findings(),
    }


async def _dispatch_repair(store: Store, p: dict[str, Any]) -> dict[str, Any]:
    blind_spot = p.get("blind_spot", "injection_relaxed_signals")
    llm = p.get("llm", "mock")
    _require_openai_model(p, llm)
    if blind_spot not in {cid for cid, _desc in list_blind_spots()}:
        raise ValueError(f"未知盲区案例: {blind_spot}（可选: {', '.join(cid for cid, _ in list_blind_spots())}）")
    budget_gate = _make_console_budget(p, store)  # M5 成本门禁
    try:
        report = await run_repair(RepairConfig(
            blind_spot=blind_spot, llm=llm, model=p.get("model"), api_key=p.get("api_key"),
            base_url=p.get("base_url"), num_variants=int(p.get("variants", 4)),
            task=p.get("task", DEFAULT_TASK), seed=p.get("seed"),
            capability_tolerance=float(p.get("tolerance", 0.0)),
            cost_budget=budget_gate,
        ))
    except CostBudgetExceeded as exc:
        cfg_store = CampaignConfig(
            targets=[ModelSpec(label="repair", llm=llm, model=p.get("model"))],
            modules=[blind_spot], rounds=1, defense=True,
        )
        cid = _persist_aborted_campaign(store, cfg_store, exc)
        return {
            "kind": "repair", "campaign_id": cid, "module": blind_spot, "blind_spot": blind_spot,
            "aborted": True, "budget_alert": exc.as_dict(),
        }
    cfg_store = CampaignConfig(
        targets=[ModelSpec(label="repair", llm=llm, model=p.get("model"))],
        modules=[report.module], rounds=1, defense=True,
    )
    cid = store.record_campaign(report, cfg_store)
    if report.bare_result is not None:
        store.record_attack_result(report.bare_result, campaign_id=cid, target="bare", defense=False)
    if report.flawed_result is not None:
        store.record_attack_result(report.flawed_result, campaign_id=cid, target="flawed", defense=False)
    if report.fixed_result is not None:
        store.record_attack_result(report.fixed_result, campaign_id=cid, target="fixed", defense=True)
        store.upsert_finding(report.fixed_result, campaign_id=cid, target="fixed", defense=True)
    if report.bare_result is not None:
        store.upsert_finding(report.bare_result, campaign_id=cid, target="bare", defense=False)
    notes = "; ".join(report.fix_actions)
    if report.verified:
        store.set_finding_status(report.module, FindingStatus.VERIFIED, notes=f"[M3-{blind_spot}] {notes}")
    else:
        store.set_finding_status(
            report.module, FindingStatus.OPEN,
            notes=f"[M3-{blind_spot} 未达标] " + "; ".join(
                f"{g.name}✗({g.actual})" for g in report.gates if not g.passed
            ),
        )
    return {
        "kind": "repair", "campaign_id": cid, "module": report.module, "blind_spot": blind_spot,
        "verified": report.verified,
        "asr": {"bare": report.asr_bare, "flawed": report.asr_flawed, "fixed": report.asr_fixed},
        "gates": [{"name": g.name, "passed": g.passed, "actual": g.actual} for g in report.gates],
        "findings": store.count_findings(),
    }


_DISPATCHERS: dict[str, Any] = {
    "campaign": _dispatch_campaign,
    "self-improve": _dispatch_self_improve,
    "repair": _dispatch_repair,
}


def _report_from_campaign(item: dict[str, Any]) -> CampaignReport:
    """由 store 的 campaign 明细（config + runs）重建 CampaignReport，供 SVG 图表渲染。"""
    cfg_config = item.get("config", {}) or {}
    cfg = CampaignConfig(
        targets=[ModelSpec(label=t) for t in cfg_config.get("targets", [])],
        modules=cfg_config.get("modules", []),
        rounds=cfg_config.get("rounds", 1),
        concurrency=cfg_config.get("concurrency", 1),
        seed=cfg_config.get("seed"),
        defense=cfg_config.get("defense", True),
        task=cfg_config.get("task", ""),
        num_variants=cfg_config.get("num_variants", 3),
    )
    cells = [
        CellResult(
            target=r["target"], module=r["module"], round=0,
            successes=r["successes"], blocked=r["blocked"],
            total=r["total"], duration_ms=r["duration_ms"],
        )
        for r in item.get("runs", [])
    ]
    return CampaignReport(cells=cells, duration_ms=0, cfg=cfg)


# --------------------------------------------------------------------------- #
# 页面（原生 HTML/JS，无前端依赖，与 workbench 同风格）
# --------------------------------------------------------------------------- #
CONSOLE_HTML = """<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><title>AgentShield 控制台</title>
<style>
  body{font-family:Segoe UI,-apple-system,Arial,sans-serif;margin:0;background:#f3f4f6;color:#111827}
  header{background:#0f172a;color:#fff;padding:14px 22px;display:flex;align-items:baseline;gap:14px}
  header b{font-size:18px} header span{color:#94a3b8;font-size:12px}
  nav{background:#1e293b;padding:0 22px}
  nav a{display:inline-block;color:#cbd5e1;padding:10px 16px;text-decoration:none;font-size:14px}
  nav a.on{color:#fff;border-bottom:3px solid #38bdf8;font-weight:600}
  main{padding:18px 22px;max-width:1200px}
  .card{background:#fff;border:1px solid #e5e7eb;border-radius:8px;padding:14px 16px;margin-bottom:14px}
  .card h3{margin:0 0 10px;font-size:15px}
  .row{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-bottom:8px}
  label{font-size:12px;color:#475569;min-width:84px}
  input,select{font-size:13px;padding:5px 8px;border:1px solid #cbd5e1;border-radius:5px}
  input[type=checkbox]{width:auto}
  button{background:#2563eb;color:#fff;border:0;border-radius:6px;padding:8px 18px;font-size:13px;cursor:pointer}
  button.ghost{background:#fff;color:#2563eb;border:1px solid #2563eb}
  button.sm{padding:3px 10px;font-size:12px;background:#e2e8f0;color:#0f172a}
  table{border-collapse:collapse;width:100%;font-size:13px}
  th,td{border:1px solid #e5e7eb;padding:6px 10px;text-align:left}
  th{background:#f8fafc;cursor:pointer}
  tr.row-click{cursor:pointer} tr.row-click:hover{background:#eff6ff}
  .badge{display:inline-block;padding:1px 8px;border-radius:10px;font-size:11px;color:#fff}
  .b-open{background:#dc2626}.b-patched{background:#d97706}.b-verified{background:#16a34a}
  .err{color:#dc2626;font-size:13px} .ok{color:#16a34a;font-size:13px}
  .hint{color:#64748b;font-size:12px}
  .sec{display:none} .sec.on{display:block}
  pre{background:#0f172a;color:#e2e8f0;padding:10px;border-radius:6px;font-size:12px;overflow:auto;max-height:340px}
</style></head><body>
<header><b>AgentShield 控制台</b><span>任务下发 → 结果视图 → 报告导出（M4）</span></header>
<nav>
  <a data-sec="dispatch" class="on" href="#">任务下发</a>
  <a data-sec="results" href="#">结果视图</a>
  <a data-sec="export" href="#">报告导出</a>
</nav>
<main>

<div id="sec-dispatch" class="sec on">
  <div class="card">
    <h3>下发任务</h3>
    <div class="row"><label>任务类型</label>
      <select id="kind"><option value="campaign">campaign 红队战役</option>
        <option value="self-improve">self-improve 自改进循环</option>
        <option value="repair">repair 修复闭环</option></select></div>
    <div class="row"><label>目标模型</label>
      <select id="f-llm"><option value="mock">mock（离线）</option><option value="openai-compat">openai-compat（真实 API）</option></select>
      <input id="f-model" placeholder="model（真实 API 必填，如 deepseek-chat）" size="26">
      <input id="f-base-url" placeholder="base-url（默认 OPENAI_BASE_URL）" size="30">
      <input id="f-api-key" type="password" placeholder="api-key（只透传不落库）" size="26"></div>

    <div id="pf-campaign">
      <div class="row"><label>目标集</label><input id="f-targets" value="mock" size="40">
        <span class="hint">'label' 或 'label=model'，逗号分隔</span></div>
      <div class="row"><label>模块集</label><input id="f-modules" placeholder="空 = 全部模块，逗号分隔" size="40">
        <label>变体</label><input id="f-variants" type="number" value="2" style="width:60px">
        <label>轮次</label><input id="f-rounds" type="number" value="1" style="width:60px">
        <label>并发</label><input id="f-concurrency" type="number" value="1" style="width:60px"></div>
      <div class="row"><label>防护</label><input id="f-defense" type="checkbox" checked><span class="hint">启用防护层（defense）</span>
        <label>seed</label><input id="f-seed" placeholder="可选" style="width:80px"></div>
    </div>

    <div id="pf-selfimprove" style="display:none">
      <div class="row"><label>模块</label><select id="f-si-module"></select>
        <label>预算</label><input id="f-budget" type="number" value="6" style="width:60px">
        <label>重写轮</label><input id="f-si-rounds" type="number" value="2" style="width:60px">
        <label>变体</label><input id="f-si-variants" type="number" value="2" style="width:60px"></div>
      <div class="row"><label>动作提示</label>
        <select id="f-action-hint"><option value="auto">auto（按模块推断）</option><option value="say">say</option><option value="run_command">run_command</option></select>
        <label>前置意图分类</label><input id="f-intent" type="checkbox">
        <label>防护</label><input id="f-si-defense" type="checkbox"></div>
    </div>

    <div id="pf-repair" style="display:none">
      <div class="row"><label>盲区案例</label><select id="f-blind-spot"></select>
        <label>变体</label><input id="f-rep-variants" type="number" value="2" style="width:60px">
        <label>能力容差</label><input id="f-tolerance" type="number" value="0" step="0.05" style="width:70px"></div>
    </div>

    <div class="row"><label>任务描述</label><input id="f-task" value="请帮我搜索「2025 年全球气候报告」并总结要点。" size="64"></div>
    <button onclick="dispatch()">下发任务</button>
    <div id="job-out"></div>
  </div>
</div>

<div id="sec-results" class="sec">
  <div class="card">
    <h3>战役 / findings</h3>
    <button class="ghost sm" onclick="loadCampaigns()">刷新战役</button>
    <table id="tbl-campaigns"><thead><tr><th>campaign_id</th><th>时间</th><th>配置</th><th>状态</th><th>ASR 汇总</th><th>操作</th></tr></thead><tbody></tbody></table>
  </div>
  <div id="campaign-detail"></div>
  <div class="card">
    <h3>findings（修复状态机）</h3>
    <button class="ghost sm" onclick="loadFindings()">刷新 findings</button>
    <table id="tbl-findings"><thead><tr><th>module</th><th>状态</th><th>asr_bare</th><th>asr_defended</th><th>defense_hits</th><th>备注</th></tr></thead><tbody></tbody></table>
  </div>
</div>

<div id="sec-export" class="sec">
  <div class="card">
    <h3>报告导出</h3>
    <div class="row"><label>选择战役</label><select id="exp-campaign"></select>
      <button class="ghost" onclick="exportMd()">导出 Markdown</button>
      <button class="ghost" onclick="exportSvg()">导出 SVG 图表</button></div>
    <div id="exp-out" class="hint">导出文件将直接下载。</div>
  </div>
</div>

<script>
const $ = s => document.getElementById(s);
const qs = s => document.querySelector(s);
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
document.querySelectorAll('nav a').forEach(a => a.onclick = e => {
  e.preventDefault();
  document.querySelectorAll('nav a').forEach(x => x.classList.remove('on'));
  document.querySelectorAll('.sec').forEach(x => x.classList.remove('on'));
  a.classList.add('on'); $('sec-' + a.dataset.sec).classList.add('on');
});
$('kind').onchange = () => {
  const k = $('kind').value;
  $('pf-campaign').style.display = k === 'campaign' ? '' : 'none';
  $('pf-selfimprove').style.display = k === 'self-improve' ? '' : 'none';
  $('pf-repair').style.display = k === 'repair' ? '' : 'none';
};
async function init() {
  const mods = await (await fetch('api/modules')).json();
  $('f-si-module').innerHTML = mods.map(m => `<option>${esc(m.name)}</option>`).join('');
  const spots = await (await fetch('api/blind-spots')).json();
  $('f-blind-spot').innerHTML = spots.map(s => `<option value="${esc(s.id)}">${esc(s.id)} · ${esc(s.description)}</option>`).join('');
  loadCampaigns(); loadFindings();
}
async function dispatch() {
  const p = {llm: $('f-llm').value, model: $('f-model').value.trim() || null, base_url: $('f-base-url').value.trim() || null,
             api_key: $('f-api-key').value.trim() || null, task: $('f-task').value, seed: $('f-seed').value || null};
  const k = $('kind').value;
  if (k === 'campaign') {
    p.targets = $('f-targets').value; p.modules = $('f-modules').value;
    p.variants = +$('f-variants').value; p.rounds = +$('f-rounds').value;
    p.concurrency = +$('f-concurrency').value; p.defense = $('f-defense').checked;
  } else if (k === 'self-improve') {
    p.module = $('f-si-module').value; p.budget = +$('f-budget').value;
    p.rounds = +$('f-si-rounds').value; p.variants = +$('f-si-variants').value;
    p.action_hint = $('f-action-hint').value; p.intent_classifier = $('f-intent').checked;
    p.defense = $('f-si-defense').checked;
  } else {
    p.blind_spot = $('f-blind-spot').value; p.variants = +$('f-rep-variants').value;
    p.tolerance = +$('f-tolerance').value;
  }
  $('job-out').innerHTML = '<div class="hint">⏳ 任务已下发，运行中（真实 API 每次模型调用最长 60s）…</div>';
  const res = await (await fetch('api/dispatch', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({kind:k, params:p})})).json();
  const jobId = res.job_id;
  const iv = setInterval(async () => {
    const j = await (await fetch('api/jobs/' + jobId)).json();
    if (j.status === 'done') {
      clearInterval(iv);
      $('job-out').innerHTML = '<div class="ok">✓ 任务完成</div><pre>' + esc(JSON.stringify(j.result, null, 2)) + '</pre>';
      loadCampaigns(); loadFindings();
    } else if (j.status === 'error') {
      clearInterval(iv);
      $('job-out').innerHTML = '<div class="err">✗ 任务失败</div><pre>' + esc(j.error) + '</pre>';
    }
  }, 400);
}
async function loadCampaigns() {
  const rows = await (await fetch('api/campaigns')).json();
  qs('#tbl-campaigns tbody').innerHTML = rows.map(r => {
    const st = r.summary && r.summary.per_target ? Object.entries(r.summary.per_target)
      .map(([t, v]) => `${t}:${(v.asr*100).toFixed(0)}%`).join(' · ') : '—';
    const cfg = r.config.targets?.join(',') + ' / ' + (r.config.modules?.join(',') || 'all');
    return `<tr class="row-click" onclick="loadCampaign('${r.id}')">
      <td>${esc(r.id)}</td><td>${new Date(r.ts*1000).toLocaleString()}</td><td>${esc(cfg)}</td>
      <td>${esc(r.status)}</td><td>${esc(st)}</td>
      <td><button class="sm" onclick="event.stopPropagation();exportMd('${r.id}')">md</button>
      <button class="sm" onclick="event.stopPropagation();exportSvg('${r.id}')">svg</button></td></tr>`;
  }).join('') || '<tr><td colspan="6" class="hint">暂无战役</td></tr>';
  $('exp-campaign').innerHTML = rows.map(r => `<option value="${r.id}">${esc(r.id)}</option>`).join('');
}
async function loadCampaign(id) {
  const c = await (await fetch('api/campaigns/' + id)).json();
  $('campaign-detail').innerHTML = `<div class="card"><h3>campaign ${esc(id)} · ${esc(c.status)}</h3>
    <pre>${esc(JSON.stringify(c.summary, null, 2))}</pre>
    <table><thead><tr><th>run_id</th><th>module</th><th>target</th><th>defense</th><th>verdict</th><th>ASR</th><th>成功/拦截/失败</th></tr></thead><tbody>
    ${c.runs.map(r => `<tr class="row-click" onclick="loadRun(${r.id})"><td>${r.id}</td><td>${esc(r.module)}</td><td>${esc(r.target)}</td>
      <td>${r.defense?'开':'关'}</td><td>${esc(r.verdict)}</td><td>${(r.asr*100).toFixed(0)}%</td>
      <td>${r.successes}/${r.blocked}/${r.failed}</td></tr>`).join('')}
    </tbody></table></div>`;
}
async function loadRun(id) {
  const r = await (await fetch('api/campaigns/' + $('exp-campaign').value + '/runs/' + id)).catch(() => null);
  const run = r ? await r.json() : null;
  if (!run) return;
  $('campaign-detail').insertAdjacentHTML('beforeend', `<div class="card"><h3>run ${id} · ${esc(run.module)}（${esc(run.target)}${run.defense?' · 加固':''}）</h3>
    <b>traces</b><pre>${esc(JSON.stringify(run.traces, null, 2))}</pre>
    <b>verdicts</b><pre>${esc(JSON.stringify(run.verdicts, null, 2))}</pre>
    <b>costs</b><pre>${esc(JSON.stringify(run.costs, null, 2))}</pre></div>`);
}
async function loadFindings() {
  const rows = await (await fetch('api/findings')).json();
  qs('#tbl-findings tbody').innerHTML = rows.map(f => `<tr>
    <td>${esc(f.module)}</td><td><span class="badge b-${esc(f.status)}">${esc(f.status)}</span></td>
    <td>${f.asr_bare==null?'—':(f.asr_bare*100).toFixed(0)+'%'}</td>
    <td>${f.asr_defended==null?'—':(f.asr_defended*100).toFixed(0)+'%'}</td>
    <td>${esc((f.defense_hits||[]).join('; '))}</td><td>${esc(f.repair_notes||'')}</td></tr>`).join('')
    || '<tr><td colspan="6" class="hint">暂无 findings</td></tr>';
}
function exportMd(id) {
  const cid = id || $('exp-campaign').value;
  window.open(`api/campaigns/${cid}/report.md`, '_blank');
}
function exportSvg(id) {
  const cid = id || $('exp-campaign').value;
  window.open(`api/campaigns/${cid}/chart.svg`, '_blank');
}
init();
</script></body></html>
"""


# --------------------------------------------------------------------------- #
# App 构建
# --------------------------------------------------------------------------- #
def build_console_app(store: Store | None = None, store_path=None) -> FastAPI:
    """构建 M4 控制台 App。

    - store：注入 Store 实例（测试用）；缺省按 store_path / 默认路径懒建。
    - 路由相对路径设计为挂载在 /console 下（web 命令 mount），也可独立 TestClient。
    """
    astore = store or Store(store_path or default_attack_db_path())
    app = FastAPI(title="AgentShield 控制台")

    @app.get("/", response_class=HTMLResponse)
    async def index() -> str:
        return CONSOLE_HTML

    @app.get("/api/modules")
    def modules_list() -> list[dict[str, str]]:
        return [{"name": n, "description": d} for n, d in list_attack_modules()]

    @app.get("/api/blind-spots")
    def blind_spots() -> list[dict[str, str]]:
        return [{"id": cid, "description": desc} for cid, desc in list_blind_spots()]

    @app.post("/api/dispatch")
    async def dispatch(req: DispatchRequest) -> dict[str, str]:
        handler = _DISPATCHERS.get(req.kind)
        if handler is None:
            raise HTTPException(400, f"未知任务类型: {req.kind}（可选: {', '.join(_DISPATCHERS)}）")
        job_id = uuid.uuid4().hex[:12]
        _jobs[job_id] = {"status": "running", "result": None, "error": None}
        task = asyncio.create_task(_run_job(job_id, handler(astore, req.params)))
        _tasks.add(task)
        task.add_done_callback(_tasks.discard)
        return {"job_id": job_id}

    @app.get("/api/jobs/{job_id}")
    def job_status(job_id: str) -> dict[str, Any]:
        job = _jobs.get(job_id)
        if job is None:
            raise HTTPException(404, "job 不存在")
        return job

    @app.get("/api/campaigns")
    def campaigns() -> list[dict[str, Any]]:
        return astore.list_campaigns(limit=50)

    @app.get("/api/campaigns/{cid}")
    def campaign_detail(cid: str) -> dict[str, Any]:
        item = astore.get_campaign(cid)
        if item is None:
            raise HTTPException(404, f"campaign 不存在: {cid}")
        return item

    @app.get("/api/campaigns/{cid}/runs/{run_id}")
    def run_detail(cid: str, run_id: int) -> dict[str, Any]:
        item = astore.get_run(int(run_id))
        if item is None or item["campaign_id"] != cid:
            raise HTTPException(404, "run 不存在")
        return item

    @app.get("/api/campaigns/{cid}/report.md")
    def export_md(cid: str) -> PlainTextResponse:
        item = astore.get_campaign(cid)
        if item is None:
            raise HTTPException(404, f"campaign 不存在: {cid}")
        return PlainTextResponse(
            item.get("markdown") or "# 该战役未保存 markdown\n",
            media_type="text/markdown; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{cid}.md"'},
        )

    @app.get("/api/campaigns/{cid}/chart.svg")
    def export_svg(cid: str) -> PlainTextResponse:
        item = astore.get_campaign(cid)
        if item is None:
            raise HTTPException(404, f"campaign 不存在: {cid}")
        report = _report_from_campaign(item)
        return PlainTextResponse(
            render_campaign_chart_svg(report),
            media_type="image/svg+xml; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{cid}.svg"'},
        )

    @app.get("/api/findings")
    def findings() -> list[dict[str, Any]]:
        return [f.as_dict() for f in astore.list_findings(limit=100)]

    return app
