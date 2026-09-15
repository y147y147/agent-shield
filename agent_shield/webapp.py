"""Web 攻防工作台：可视化攻击 / 防护对比 / 多模型测试 / 策略 / 沙箱 / 审计。

单页应用（无前端依赖，FastAPI + 原生 HTML/JS），功能：
- 攻防工作台：选模型（Mock 离线 / OpenAI 兼容真实 API，可切换）、选攻击模块、
  开防护/沙箱，一键攻击或"加固前后对比"，并可视化 Agent 轨迹；
- 模型对比：同一攻击在多个真实模型上跑"加固前/后"成功率矩阵（挖真实模型漏洞）；
- 策略测试：对任意工具调用实时评估语义策略引擎决策；
- 沙箱测试：命令在沙箱内/外执行对比；
- 审计：每次攻击的工具调用事件实时入库展示。

启动：`agent-shield web --port 8086`，浏览器打开 http://127.0.0.1:8086
"""

from __future__ import annotations

import asyncio
import copy
import uuid
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel, Field

from agent_shield.attacks import AttackConfig, list_attack_modules
from agent_shield.attacks.registry import get_attack_module as _get
from agent_shield.defenses import PolicyEngine, SandboxExecutor
from agent_shield.models import AgentTrace, AttackResult
from agent_shield.observability import render_metrics
from agent_shield.targets import DEFAULT_TASK, build_local_target

WORKBENCH_HTML = """<!doctype html>
<html lang="zh">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AgentShield 攻防工作台</title>
<style>
  :root { --bg:#0f1117; --panel:#1a1d29; --border:#2a2e3d; --fg:#d1d5db; --muted:#9ca3af;
          --accent:#7dd3fc; --red:#f87171; --green:#4ade80; --yellow:#facc15; --blue:#60a5fa; }
  * { box-sizing:border-box; }
  body { font-family:-apple-system,"PingFang SC","Microsoft YaHei",monospace; background:var(--bg);
         color:var(--fg); margin:0; padding:20px; }
  h1 { color:#e5e7eb; font-size:20px; margin:0 0 4px; }
  .sub { color:var(--muted); font-size:12px; margin-bottom:16px; }
  .tabs { display:flex; gap:6px; margin-bottom:16px; flex-wrap:wrap; }
  .tab { padding:8px 16px; border-radius:8px 8px 0 0; background:var(--panel); border:1px solid var(--border);
         border-bottom:none; cursor:pointer; color:var(--muted); font-size:13px; }
  .tab.active { color:var(--accent); border-top:2px solid var(--accent); background:#141824; }
  .panel { display:none; background:var(--panel); border:1px solid var(--border); border-radius:0 8px 8px 8px;
           padding:18px; }
  .panel.active { display:block; }
  .grid { display:grid; grid-template-columns:340px 1fr; gap:16px; }
  @media (max-width:960px){ .grid { grid-template-columns:1fr; } }
  .field { margin-bottom:10px; }
  label { display:block; font-size:12px; color:var(--muted); margin-bottom:4px; }
  input, select, textarea { width:100%; background:#10131c; border:1px solid var(--border); color:var(--fg);
         border-radius:6px; padding:7px 9px; font-size:13px; font-family:inherit; }
  textarea { min-height:56px; resize:vertical; }
  button { background:#1e3a5f; color:#bfdbfe; border:1px solid #2b4a6f; border-radius:6px; padding:8px 14px;
           font-size:13px; cursor:pointer; }
  button:hover { background:#24466f; }
  button.primary { background:#14532d; color:#bbf7d0; border-color:#166534; }
  button.primary:hover { background:#166534; }
  .row { display:flex; gap:12px; align-items:flex-end; flex-wrap:wrap; }
  .row .field { flex:1; min-width:120px; }
  .toggle { display:flex; gap:16px; align-items:center; margin:10px 0; }
  .toggle label { margin:0; display:flex; align-items:center; gap:6px; cursor:pointer; }
  input[type=checkbox] { width:auto; accent-color:var(--accent); }
  .badge { display:inline-block; padding:2px 8px; border-radius:10px; font-size:11px; margin-left:6px; }
  .b-success { background:#14532d; color:#bbf7d0; } .b-blocked { background:#7f1d1d; color:#fecaca; }
  .b-failed { background:#1f2937; color:#9ca3af; }
  .sev-critical{color:var(--red)} .sev-high{color:#fb923c} .sev-medium{color:var(--yellow)}
  .sev-low{color:var(--blue)} .sev-info{color:var(--muted)}
  .cards { display:flex; gap:12px; margin:14px 0; flex-wrap:wrap; }
  .card { background:#141824; border:1px solid var(--border); border-radius:8px; padding:10px 16px; min-width:100px; }
  .card b { display:block; font-size:22px; } .card span { font-size:11px; color:var(--muted); }
  table { width:100%; border-collapse:collapse; font-size:12.5px; margin-top:8px; }
  th, td { padding:7px 10px; text-align:left; border-bottom:1px solid var(--border); vertical-align:top; }
  th { color:var(--muted); font-weight:600; }
  pre { background:#10131c; border:1px solid var(--border); border-radius:6px; padding:10px; font-size:12px;
        white-space:pre-wrap; word-break:break-all; margin:4px 0; }
  .timeline { display:flex; flex-direction:column; gap:8px; margin-top:10px; max-height:520px; overflow-y:auto; }
  .msg { border-radius:8px; padding:8px 12px; font-size:12.5px; border:1px solid var(--border); }
  .msg.user { background:#1e3a5f33; border-left:3px solid var(--blue); }
  .msg.call { background:#3b1d5f33; border-left:3px solid #c084fc; }
  .msg.out { background:#14532d33; border-left:3px solid var(--green); }
  .msg.blocked { background:#7f1d1d33; border-left:3px solid var(--red); }
  .msg.final { background:#1f2937; border-left:3px solid var(--accent); }
  .msg.think { background:#78350f22; border-left:3px solid var(--yellow); }
  .msg.llm { background:#0c4a6e22; border-left:3px solid #38bdf8; }
  .msg .t { font-size:11px; color:var(--muted); margin-bottom:3px; }
  .hint { font-size:12px; color:var(--muted); margin-top:6px; }
  .err { color:var(--red); font-size:13px; margin-top:10px; white-space:pre-wrap; }
  .bar { height:14px; border-radius:4px; background:#1f2937; overflow:hidden; min-width:80px; }
  .bar > div { height:100%; }
  .modelrow { display:grid; grid-template-columns:1fr 1fr 1fr; gap:8px; margin-bottom:8px; }
  @media (max-width:960px){ .modelrow { grid-template-columns:1fr; } }
  .muted { color:var(--muted); }
</style>
</head>
<body>
<h1>🛡 AgentShield 攻防工作台</h1>
<div class="sub">攻击测试（红队）→ 挂防护（蓝队）→ 验证是否仍可绕过 · 覆盖 OWASP ASI-01 ~ ASI-10</div>

<div class="tabs">
  <div class="tab active" data-tab="workbench">⚔ 攻防工作台</div>
  <div class="tab" data-tab="models">🔀 模型对比</div>
  <div class="tab" data-tab="policy">🧱 策略测试</div>
  <div class="tab" data-tab="sandbox">📦 沙箱测试</div>
  <div class="tab" data-tab="auto">🤖 自主审计</div>
  <div class="tab" data-tab="audit">📋 审计</div>
</div>

<!-- ================= 攻防工作台 ================= -->
<div class="panel active" id="tab-workbench">
  <div class="grid">
    <div>
      <div class="field"><label>目标模型（可切换 API）</label>
        <select id="model-preset"></select>
      </div>
      <div class="row">
        <div class="field"><label>模型名</label><input id="m-model" placeholder="deepseek-chat / qwen-max / qwen2.5:7b"></div>
        <div class="field"><label>Base URL</label><input id="m-base" placeholder="https://api.deepseek.com/v1"></div>
      </div>
      <div class="field"><label>API Key</label><input id="m-key" placeholder="sk-...（本地 Ollama 可留空）"></div>
      <div class="hint" id="model-hint">mock = 离线靶场，无需任何配置。</div>
      <button onclick="pingModel()" style="margin-bottom:10px">🔌 测试连接（先验证 API 配置，再跑攻击）</button>
      <div id="ping-result" class="hint"></div>
      <div class="field"><label>攻击模块（ASI 映射）</label><select id="module"></select></div>
      <div class="hint" id="module-hint"></div>
      <div class="row">
        <div class="field"><label>变体数</label><input id="variants" type="number" value="3" min="1"></div>
        <div class="field"><label>任务（留空用模块默认）</label><input id="task" placeholder="请帮我搜索…并总结"></div>
      </div>
      <div class="toggle">
        <label><input type="checkbox" id="defense"> 启用防护（注入检测 + 语义策略 + 预算 + 完整性）</label>
        <label><input type="checkbox" id="sandbox"> 沙箱执行</label>
        <label><input type="checkbox" id="judge"> LLM-as-Judge</label>
      </div>
      <div class="row">
        <button class="primary" onclick="runAttack(false)">▶ 单独攻击</button>
        <button onclick="runAttack(true)">⚖ 加固前后对比</button>
      </div>
      <div class="hint">mock = 离线确定性靶场；填 model/base-url/api-key 即切换为真实 API 大模型测试。</div>
      <div id="workbench-err" class="err"></div>
    </div>
    <div>
      <div id="wb-result"></div>
    </div>
  </div>
</div>

<!-- ================= 模型对比 ================= -->
<div class="panel" id="tab-models">
  <div class="field"><label>攻击模块</label><select id="bm-module"></select></div>
  <div class="field"><label>对比模型列表（每行一个；模型名填 mock 表示离线）</label></div>
  <div id="bm-models"></div>
  <div class="row"><button class="primary" onclick="runBenchmark()">🔀 跑多模型对比</button></div>
  <div id="bm-err" class="err"></div>
  <div id="bm-result"></div>
</div>

<!-- ================= 策略测试 ================= -->
<div class="panel" id="tab-policy">
  <div class="field"><label>工具名</label>
    <select id="pol-tool"><option>run_command</option><option>read_file</option><option>write_file</option><option>send_email</option></select>
  </div>
  <div class="field"><label>参数（run_command 填 command；read_file/write_file 填 path）</label>
    <input id="pol-arg" placeholder='例如: cat /etc/passwd 或 /tmp/../etc/passwd'>
  </div>
  <button class="primary" onclick="checkPolicy()">🧱 评估策略</button>
  <div id="pol-result"></div>
</div>

<!-- ================= 沙箱测试 ================= -->
<div class="panel" id="tab-sandbox">
  <div class="field"><label>命令</label><input id="sb-cmd" placeholder="例如: echo hello（试 rm -rf / 看拦截）"></div>
  <div class="toggle">
    <label><input type="checkbox" id="sb-on" checked> 沙箱（危险命令拦截 + CPU 1s / 文件 1MB / 内存 256MB / 超时 10s）</label>
  </div>
  <button class="primary" onclick="runSandbox()">📦 执行</button>
  <div id="sb-result"></div>
</div>

<!-- ================= 自主审计（Plan-and-Execute） ================= -->
<div class="panel" id="tab-auto">
  <div class="grid">
    <div>
      <div class="hint" style="margin-bottom:12px">plan = 一次生成计划再执行；react = 每步根据 Observation 自主改策略（流式过程链）。</div>
      <div id="auto-mock-hint" class="hint" style="margin-bottom:12px;color:var(--yellow)">离线 Mock 下 plan/react 结果相近；选 OpenAI 兼容 + API Key 后 react 才会自适应。</div>
      <div class="field"><label>审计模式</label>
        <select id="auto-mode"><option value="plan">plan（Plan-and-Execute）</option><option value="react">react（ReAct 自主决策）</option></select>
      </div>
      <div class="field"><label>目标类型</label>
        <select id="auto-target-kind" onchange="updateAutoTargetHint()">
          <option value="local">local（本地靶场）</option>
          <option value="http">http（黑盒 HTTP Agent）</option>
          <option value="mcp">mcp（MCP server 靶场）</option>
        </select>
      </div>
      <div class="field" id="auto-http-url-wrap" style="display:none"><label>HTTP 地址</label>
        <input id="auto-target-url" placeholder="http://127.0.0.1:8000">
      </div>
      <div class="field" id="auto-mcp-url-wrap" style="display:none"><label>MCP 地址</label>
        <input id="auto-mcp-url" placeholder="http://127.0.0.1:8080/mcp">
      </div>
      <div class="field" id="auto-http-defense-url-wrap" style="display:none"><label>加固端点（可选）</label>
        <input id="auto-defense-url" placeholder="留空则不做攻防对比">
      </div>
      <div id="auto-target-hint" class="hint" style="margin-bottom:8px"></div>
      <div class="field"><label>靶场模型（local）</label>
        <select id="auto-llm" onchange="updateAutoLlmHint()"><option value="mock">Mock 离线指挥官</option><option value="openai-compat">OpenAI 兼容（真实 LLM）</option></select>
      </div>
      <div class="row">
        <div class="field"><label>模型名</label><input id="auto-model" placeholder="deepseek-chat"></div>
        <div class="field"><label>Base URL</label><input id="auto-base" placeholder="https://api.deepseek.com/v1"></div>
      </div>
      <div class="field"><label>API Key</label><input id="auto-key" placeholder="sk-...（mock 可留空）"></div>
      <div class="row">
        <div class="field"><label>步数上限（plan）</label><input id="auto-steps" type="number" value="5" min="1" max="11"></div>
        <div class="field"><label>最大轮次（react）</label><input id="auto-max-turns" type="number" value="12" min="1" max="30"></div>
        <div class="field"><label>任务</label><input id="auto-task" placeholder="留空用默认搜索任务"></div>
      </div>
      <div class="toggle">
        <label><input type="checkbox" id="auto-compare" checked> 加固前后对比</label>
        <label><input type="checkbox" id="auto-full"> full 覆盖</label>
        <label><input type="checkbox" id="auto-hitl"> 确认执行高风险模块（unexpected_code_execution 等）</label>
      </div>
      <button class="primary" onclick="runAutoAudit()">▶ 开始自主审计</button>
      <div id="auto-err" class="err"></div>
    </div>
    <div>
      <div id="auto-status" class="hint"></div>
      <h3 style="font-size:14px;color:var(--accent);display:none" id="auto-chain-title">过程链（实时）</h3>
      <div class="timeline" id="auto-chain"></div>
      <div id="auto-result"></div>
      <h3 style="font-size:14px;color:var(--accent);margin-top:20px">历史会话</h3>
      <button type="button" class="primary" style="margin-bottom:8px" onclick="loadAuditSessions()">🔄 刷新历史</button>
      <table id="auto-sessions-table"><thead><tr><th>时间</th><th>模式</th><th>risk</th><th>覆盖</th><th>操作</th></tr></thead><tbody></tbody></table>
      <h3 style="font-size:13px;color:var(--accent);display:none;margin-top:12px" id="auto-session-md-title">会话报告（Markdown）</h3>
      <pre id="auto-session-md" style="display:none;max-height:360px;overflow:auto;background:var(--bg2);padding:12px;border-radius:8px;font-size:12px"></pre>
    </div>
  </div>
</div>

<!-- ================= 审计 ================= -->
<div class="panel" id="tab-audit">
  <div class="hint" style="margin-bottom:12px">运行时工具调用与 MITM Proxy 事件（共用当前 Web 工作台 SQLite 库）。</div>
  <button type="button" class="primary" style="margin-bottom:12px" onclick="startProxyHuntAudit()">🎯 基于此流量发起自主审计</button>
  <div class="cards" id="audit-stats"></div>
  <table id="audit-table"><thead><tr><th>时间</th><th>动作</th><th>详情</th></tr></thead><tbody></tbody></table>
</div>

<script>
const $ = id => document.getElementById(id);
let MODULES = [];
let runTimer = null;

function esc(s){ return String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }

async function api(path, body, timeoutMs = 150000){
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(path, {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body), signal: ctrl.signal});
    let data = {}; try { data = await res.json(); } catch (_) {}
    if (!res.ok) throw new Error(data.detail || data.error || res.statusText);
    return data;
  } catch (e) {
    if (e.name === 'AbortError') throw new Error('请求超时（>150s）—— 请检查 Base URL / API Key / 模型名是否正确，可先点"测试连接"');
    throw e;
  } finally { clearTimeout(timer); }
}

let runStartedAt = 0;
function startRunning(el){
  runStartedAt = Date.now();
  el.innerHTML = '⏳ 运行中… <b id="run-elapsed">0</b>s（真实 API 每次模型调用最长 60s；过程链会实时刷新，超时会自动提示）';
  runTimer = setInterval(() => { const s = $('run-elapsed'); if (s) s.textContent = Math.floor((Date.now() - runStartedAt) / 1000); }, 1000);
}
function stopRunning(doneText){
  if (runTimer) { clearInterval(runTimer); runTimer = null; }
  const st = $('run-status') || $('auto-status');
  if (st && doneText !== undefined) st.textContent = doneText || '✅ 完成';
  else if (st && !st.textContent.includes('✅') && !st.textContent.includes('❌')) st.textContent = '✅ 完成';
}

document.querySelectorAll('.tab').forEach(t => t.onclick = () => {
  document.querySelectorAll('.tab').forEach(x => x.classList.toggle('active', x === t));
  document.querySelectorAll('.panel').forEach(p => p.classList.toggle('active', p.id === 'tab-' + t.dataset.tab));
  if (t.dataset.tab) location.hash = t.dataset.tab;
});

function activateTab(name){
  const t = document.querySelector('.tab[data-tab="' + name + '"]');
  if (t) t.click();
}

function modelConfig(){
  const m = $('model-preset').value;
  const llm = m === 'mock' ? 'mock' : 'openai-compat';
  return { llm, model: $('m-model').value.trim() || null, base_url: $('m-base').value.trim() || null,
           api_key: $('m-key').value.trim() || null };
}

function updateModuleHint(){
  const mod = MODULES.find(x => x.name === $('module').value);
  const hint = $('module-hint');
  if (!mod) return;
  if (mod.mock_only && modelConfig().llm !== 'mock') {
    hint.textContent = '⚠ ' + mod.name + ' 需控制智能体内部状态（ASI-10 内部失控），仅本地 Mock 靶场可测；黑盒真实 API 将显示"不可测"。';
    hint.style.color = 'var(--yellow)';
  } else { hint.textContent = ''; }
}

async function init(){
  MODULES = await (await fetch('/api/modules')).json();
  const modSel = $('module'), bmMod = $('bm-module');
  MODULES.forEach(mod => {
    const opt = document.createElement('option');
    opt.value = mod.name; opt.textContent = `${mod.name}（${mod.owasp_asi || '—'}）`;
    modSel.appendChild(opt); bmMod.appendChild(opt.cloneNode(true));
  });
  modSel.onchange = updateModuleHint;
  const presets = await (await fetch('/api/model-presets')).json();
  const sel = $('model-preset');
  const HINTS = {
    mock: 'mock = 离线确定性靶场，无需任何配置。',
    openai: '云端 API：Base URL 填服务商的 /v1 兼容地址（DeepSeek: https://api.deepseek.com/v1 · OpenAI: https://api.openai.com/v1 · 阿里云 DashScope: https://dashscope.aliyuncs.com/compatible-mode/v1），模型名需与该服务商一致（如 deepseek-chat / qwen-max / qwen-plus），并填 API Key。',
    ollama: '本地 Ollama：Base URL 填 http://localhost:11434/v1，模型名如 qwen2.5:7b / deepseek-r1:7b，API Key 可留空。',
  };
  presets.forEach(p => { const o = document.createElement('option'); o.value = p.key; o.textContent = p.label; sel.appendChild(o); });
  sel.onchange = () => {
    const p = presets.find(x => x.key === sel.value);
    if (p) { $('m-model').value = p.model || ''; $('m-base').value = p.base_url || ''; $('m-key').value = p.api_key || ''; }
    $('model-hint').textContent = HINTS[sel.value] || '';
    updateModuleHint();
  };
  // 模型对比：3 行初始
  const wrap = $('bm-models');
  const addRow = (label, model, base, key) => {
    const d = document.createElement('div'); d.className = 'modelrow';
    d.innerHTML = `<input placeholder="标签（如 DeepSeek）" value="${esc(label)}">
                   <input placeholder="模型名（mock=离线）" value="${esc(model)}">
                   <input placeholder="Base URL" value="${esc(base)}">
                   <input placeholder="API Key" value="${esc(key)}">`;
    wrap.appendChild(d);
  };
  addRow('Mock 离线', 'mock', '', '');
  addRow('DeepSeek', 'deepseek-chat', 'https://api.deepseek.com/v1', '');
  addRow('Ollama 本地', 'qwen2.5:7b', 'http://localhost:11434/v1', '');
  updateAutoTargetHint();
  updateAutoLlmHint();
  loadAuditSessions();
}

function caseTable(cases){
  return `<table><thead><tr><th>#</th><th>判定</th><th>严重度</th><th>证据</th></tr></thead><tbody>` +
    cases.map((c, i) => `<tr>
      <td>${i + 1}</td>
      <td><span class="badge b-${c.verdict}">${c.verdict}</span></td>
      <td class="sev-${c.severity}">${c.severity}</td>
      <td>${esc((c.evidence || []).join('；')) || '—'}</td></tr>`).join('') + `</tbody></table>`;
}

function summaryCards(s){
  return `<div class="cards">
    <div class="card"><b>${s.successes}/${s.total}</b><span>攻击成功</span></div>
    <div class="card"><b>${(s.success_rate * 100).toFixed(0)}%</b><span>成功率</span></div>
    <div class="card"><b>${s.blocked}</b><span>被拦截</span></div>
    <div class="card"><b>${s.failed}</b><span>未生效</span></div>
    <div class="card"><b>${s.duration_ms}ms</b><span>耗时</span></div></div>`;
}

function timelineView(trace){
  if (!trace || !trace.items) return '';
  const t = {
    user: ['用户输入', 'msg user'], assistant_call: ['工具调用', 'msg call'],
    tool_output: ['工具输出', 'msg out'], blocked: ['被拦截', 'msg blocked'], final: ['最终答复', 'msg final']
  };
  return `<div class="timeline">` + trace.items.map(it => {
    const [label, cls] = t[it.type] || [it.type, 'msg'];
    let body = esc(it.text || '');
    if (it.type === 'assistant_call') body = `🔧 <b>${esc(it.tool)}</b> <pre>${esc(JSON.stringify(it.args))}</pre>`;
    if (it.type === 'tool_output') body = `<b>${esc(it.tool)}</b> → <pre>${esc(it.text)}</pre>`;
    if (it.type === 'blocked') body = `<b>${esc(it.tool)}</b> 被拦截：${esc(it.reason)}`;
    return `<div class="${cls}"><div class="t">${label}</div>${body}</div>`;
  }).join('') + `</div>`;
}

async function runAttack(compare){
  $('workbench-err').textContent = '';
  const body = { module: $('module').value, variants: +$('variants').value, task: $('task').value,
                 defense: $('defense').checked, sandbox: $('sandbox').checked,
                 judge: $('judge').checked, compare, ...modelConfig() };
  const out = $('wb-result');
  // 状态行与过程链容器分离：spinner 不会覆盖过程链
  out.innerHTML = '<div id="run-status" class="hint"></div>' +
                  '<h3 style="font-size:14px;color:var(--accent)">过程链（实时）</h3><div class="timeline" id="chain"></div>' +
                  '<div id="chain-done"></div>';
  startRunning($('run-status'));
  try {
    const { job_id } = await api('/api/attack/stream', body, 20000);
    let seen = 0;
    let st = null;
    while (true) {
      st = await (await fetch('/api/attack/events/' + job_id)).json();
      for (; seen < (st.events || []).length; seen++) appendChainEvent(st.events[seen]);
      if (st.status === 'done') { stopRunning('✅ 完成（' + Math.floor((Date.now() - runStartedAt) / 1000) + 's）'); break; }
      if (st.status === 'error') { stopRunning('❌ 出错'); throw new Error(st.error || '任务失败'); }
      await new Promise(r => setTimeout(r, 250));
    }
    const data = st.result;
    let html = '';
    // 模型 API 调用失败：本次结果无效，必须先修连接（否则 0 成功会被误读为"没漏洞"）
    if (data.warnings && data.warnings.length) {
      html += `<div class="hint" style="color:var(--red);border:1px solid #7f1d1d;background:#7f1d1d22;padding:8px 12px;border-radius:6px;margin-bottom:10px">
        ⚠️ <b>模型 API 调用失败 ${data.warnings.length} 次</b>，本次结果无效！<br>${esc(data.warnings[0])}<br>
        请先点「🔌 测试连接」确认 Base URL / API Key / 模型名，再重新攻击。</div>`;
    }
    html += '<h3 style="font-size:14px;color:var(--accent);margin-top:16px">判定结果</h3>';
    if (data.compare) {
      html += `<div class="cards">
        <div class="card"><b>${data.before.summary.successes}/${data.before.summary.total}</b><span>加固前成功</span></div>
        <div class="card"><b>${(data.before.summary.success_rate*100).toFixed(0)}%</b><span>加固前成功率</span></div>
        <div class="card"><b>${data.after.summary.successes}/${data.after.summary.total}</b><span>加固后成功</span></div>
        <div class="card"><b>${(data.after.summary.success_rate*100).toFixed(0)}%</b><span>加固后成功率</span></div></div>`;
      html += `<div class="hint">加固前 100% → 加固后 0% = 防护生效；若加固后仍有成功，说明存在绕过。</div>`;
      html += `<h3 style="font-size:13px;color:var(--accent)">加固前（脆弱）</h3>` + caseTable(data.before.cases);
      html += `<h3 style="font-size:13px;color:var(--accent)">加固后（防护）</h3>` + caseTable(data.after.cases);
    } else {
      html += summaryCards(data.summary);
      html += `<div class="hint">模块：<b>${esc(data.module)}</b> · OWASP ${data.owasp_asi || '—'} · ATLAS ${data.atlas_id || '—'}</div>`;
      html += caseTable(data.cases);
      // 真实模型 0 成功：提示"失败 ≠ 无漏洞"，引导看轨迹/加样本/交叉验证
      if (modelConfig().llm !== 'mock' && data.summary.successes === 0) {
        html += `<div class="hint" style="color:var(--yellow);border:1px solid #78350f;background:#451a0333;padding:8px 12px;border-radius:6px;margin-top:10px">
          ⚠️ <b>0 成功 ≠ 模型没有漏洞</b>。请看上面过程链的"最终答复"：模型是明确拒绝了，
          还是把敏感内容写进了答复？建议增大变体数（10+）重跑，或换 indirect_injection 交叉验证。</div>`;
      }
    }
    $('chain-done').innerHTML = html;
  } catch (e) { $('chain-done').innerHTML = ''; $('workbench-err').textContent = '❌ ' + e.message; }
  finally { stopRunning(); }
}

function appendChainEvent(ev){
  const chain = $('chain');
  if (!chain) return;
  const div = document.createElement('div');
  const T = {
    phase:   ['阶段', 'msg final'],
    user:    ['👤 用户输入', 'msg user'],
    think:   ['💭 模型决策/思考', 'msg think'],
    llm:     ['🤖 模型回复', 'msg llm'],
    call:    ['🔧 工具调用', 'msg call'],
    output:  ['📥 工具输出', 'msg out'],
    blocked: ['⛔ 被拦截', 'msg blocked'],
    final:   ['🏁 最终答复', 'msg final'],
    error:   ['❌ 错误', 'msg blocked'],
  };
  const [label, cls] = T[ev.type] || [ev.type, 'msg'];
  let body = esc(ev.text || '');
  if (ev.type === 'call') body = `<b>${esc(ev.tool)}</b> <pre>${esc(JSON.stringify(ev.args))}</pre>`;
  if (ev.type === 'output') body = `<b>${esc(ev.tool)}</b> → <pre>${esc(ev.text)}</pre>`;
  if (ev.type === 'blocked') body = `<b>${esc(ev.tool)}</b> 被拦截：${esc(ev.reason)}`;
  div.className = cls;
  div.innerHTML = `<div class="t">${label}</div>${body}`;
  chain.appendChild(div);
  chain.scrollTop = chain.scrollHeight;
}

async function pingModel(){
  const r = $('ping-result');
  r.textContent = '⏳ 连接测试中…';
  r.style.color = 'var(--muted)';
  try {
    const d = await api('/api/ping', modelConfig(), 30000);
    r.textContent = '✅ ' + d.message;
    r.style.color = 'var(--green)';
  } catch (e) {
    r.textContent = '❌ ' + e.message;
    r.style.color = 'var(--red)';
  }
}

async function runBenchmark(){
  const rows = [...document.querySelectorAll('#bm-models .modelrow')].map(r => {
    const v = [...r.querySelectorAll('input')].map(i => i.value.trim());
    return { label: v[0] || v[1], model: v[1], base_url: v[2], api_key: v[3] };
  }).filter(r => r.model);
  $('bm-err').textContent = '';
  $('bm-result').innerHTML = '<div class="hint">⏳ 逐模型运行中（真实 API 会较慢）…</div>';
  try {
    const data = await api('/api/benchmark', { module: $('bm-module').value, models: rows, variants: 3 });
    $('bm-result').innerHTML = `<table><thead><tr><th>模型</th><th>加固前成功率</th><th>加固后成功率</th><th>加固前成功</th><th>结论</th></tr></thead><tbody>` +
      data.rows.map(r => {
        if (r.skipped) {
          return `<tr><td><b>${esc(r.label)}</b><div class="muted">${esc(r.model)}</div></td>
            <td colspan="3" class="muted">⚠ ${esc(r.note || '不可测')}</td>
            <td><span class="badge b-blocked">不可测</span></td></tr>`;
        }
        if (r.error) {
          return `<tr><td><b>${esc(r.label)}</b><div class="muted">${esc(r.model)}</div></td>
            <td colspan="3" class="danger">❌ ${esc(r.error)}</td>
            <td><span class="badge b-blocked">连接失败</span></td></tr>`;
        }
        const pct = x => (x * 100).toFixed(0) + '%';
        const bar = (x, color) => `<div class="bar"><div style="width:${Math.max(x*100, 2)}%;background:${color}"></div></div>`;
        const verdict = r.defended_success_rate === 0
          ? `<span class="badge b-failed">防护可拦截</span>`
          : `<span class="badge b-success">存在绕过！</span>`;
        return `<tr><td><b>${esc(r.label)}</b><div class="muted">${esc(r.model)}</div></td>
          <td>${pct(r.vulnerable_success_rate)} ${bar(r.vulnerable_success_rate, '#f87171')}</td>
          <td>${pct(r.defended_success_rate)} ${bar(r.defended_success_rate, '#4ade80')}</td>
          <td>${r.vulnerable_successes}/${r.total}</td><td>${verdict}</td></tr>`;
      }).join('') + `</tbody></table>`;
  } catch (e) { $('bm-err').textContent = '❌ ' + e.message; }
}

async function checkPolicy(){
  const arg = $('pol-arg').value.trim();
  const tool = $('pol-tool').value;
  try {
    const d = await api('/api/policy/check', { tool, arguments: { [tool === 'run_command' ? 'command' : 'path']: arg } });
    const ok = d.allowed;
    $('pol-result').innerHTML = `<div class="card" style="margin-top:10px">
      <b style="color:${ok ? 'var(--green)' : 'var(--red)'}">${ok ? '✅ 放行' : '⛔ 拦截'}</b>
      <span>${esc(d.reason)}</span></div>`;
  } catch (e) { $('pol-result').innerHTML = `<div class="err">❌ ${esc(e.message)}</div>`; }
}

async function runSandbox(){
  try {
    const d = await api('/api/sandbox/run', { command: $('sb-cmd').value, sandbox: $('sb-on').checked });
    if (d.denied) {
      $('sb-result').innerHTML = `<div class="card" style="margin-top:10px">
        <b style="color:var(--red)">⛔ 已拦截（${d.stage === 'policy' ? '语义策略引擎' : '沙箱危险命令黑名单'}）</b>
        <span>${esc(d.stderr)}</span></div>`;
      return;
    }
    $('sb-result').innerHTML = `<div class="cards">
      <div class="card"><b>${d.returncode}</b><span>exit code</span></div>
      <div class="card"><b>${d.timed_out ? '超时' : '正常'}</b><span>状态</span></div></div>
      <h3 style="font-size:13px;color:var(--accent)">stdout</h3><pre>${esc(d.stdout)}</pre>
      <h3 style="font-size:13px;color:var(--accent)">stderr</h3><pre>${esc(d.stderr)}</pre>`;
  } catch (e) { $('sb-result').innerHTML = `<div class="err">❌ ${esc(e.message)}</div>`; }
}

function updateAutoLlmHint(){
  const hint = $('auto-mock-hint');
  if (!hint) return;
  const isMock = $('auto-llm').value === 'mock';
  hint.style.display = isMock ? 'block' : 'none';
}

function updateAutoTargetHint(){
  const kind = $('auto-target-kind').value;
  const httpOn = kind === 'http';
  const mcpOn = kind === 'mcp';
  $('auto-http-url-wrap').style.display = httpOn ? 'block' : 'none';
  $('auto-http-defense-url-wrap').style.display = httpOn ? 'block' : 'none';
  $('auto-mcp-url-wrap').style.display = mcpOn ? 'block' : 'none';
  const hint = $('auto-target-hint');
  if (httpOn) {
    hint.textContent = '⚠ HTTP 黑盒无法注入工具内容；mock_only 模块（如 rogue_agent）将自动排除。未填加固端点时关闭攻防对比。';
    hint.style.color = 'var(--yellow)';
  } else if (mcpOn) {
    hint.textContent = 'MCP 靶场：远程 MCP 工具与本地默认工具合并；适合 mcp_poisoning / tool_poisoning 审计。';
    hint.style.color = 'var(--accent)';
  } else {
    hint.textContent = '';
  }
}

function startProxyHuntAudit(){
  activateTab('auto');
  $('auto-mode').value = 'react';
  $('auto-llm').value = 'mock';
  updateAutoLlmHint();
  window._useProxyHunt = true;
  runAutoAudit();
}

async function runAutoAudit(){
  $('auto-err').textContent = '';
  $('auto-result').innerHTML = '';
  const chain = $('auto-chain');
  chain.innerHTML = '';
  $('auto-chain-title').style.display = 'block';
  const status = $('auto-status');
  startRunning(status);
  const body = {
    mode: $('auto-mode').value,
    target_kind: $('auto-target-kind').value,
    target_url: $('auto-target-url').value.trim() || null,
    defense_target_url: $('auto-defense-url').value.trim() || null,
    mcp_url: $('auto-mcp-url').value.trim() || null,
    use_proxy_hunt: !!window._useProxyHunt,
    hitl_confirm_dangerous: $('auto-hitl').checked,
    llm: $('auto-llm').value,
    model: $('auto-model').value.trim() || null,
    base_url: $('auto-base').value.trim() || null,
    api_key: $('auto-key').value.trim() || null,
    max_steps: parseInt($('auto-steps').value, 10) || 5,
    max_turns: parseInt($('auto-max-turns').value, 10) || 12,
    task: $('auto-task').value.trim() || '',
    compare_defense: $('auto-compare').checked,
    full: $('auto-full').checked,
  };
  try {
    const { job_id } = await api('/api/auto-audit/stream', body, 20000);
    let seen = 0;
    let st = null;
    while (true) {
      st = await (await fetch('/api/auto-audit/events/' + job_id)).json();
      for (; seen < (st.events || []).length; seen++) appendChainEventTo(st.events[seen], chain);
      if (st.status === 'done') {
        stopRunning('✅ 完成（' + Math.floor((Date.now() - runStartedAt) / 1000) + 's）');
        break;
      }
      if (st.status === 'error') {
        stopRunning('❌ 出错');
        throw new Error(st.error || '任务失败');
      }
      await new Promise(r => setTimeout(r, 250));
    }
    renderAutoAuditResult(st.result || {});
    loadAuditSessions();
  } catch (e) {
    $('auto-err').textContent = '❌ ' + e.message;
  } finally {
    window._useProxyHunt = false;
    if (runTimer) { clearInterval(runTimer); runTimer = null; }
  }
}

function appendChainEventTo(ev, chain){
  if (!chain) return;
  const div = document.createElement('div');
  const T = {
    phase:   ['阶段', 'msg final'],
    user:    ['👤 用户输入', 'msg user'],
    think:   ['💭 模型决策/思考', 'msg think'],
    llm:     ['🤖 模型回复', 'msg llm'],
    call:    ['🔧 工具调用', 'msg call'],
    output:  ['📥 步骤结果', 'msg out'],
    blocked: ['⛔ 被拦截', 'msg blocked'],
    final:   ['🏁 最终答复', 'msg final'],
    error:   ['❌ 错误', 'msg blocked'],
    chain:   ['🔗 攻击链依赖', 'msg call'],
    hitl:    ['⚠️ 需人工确认', 'msg blocked'],
  };
  const [label, cls] = T[ev.type] || [ev.type, 'msg'];
  let body = esc(ev.text || ev.label || '');
  if (ev.type === 'phase') body = `<b>${esc(ev.label || '')}</b>${ev.text ? '<pre>'+esc(ev.text)+'</pre>' : ''}`;
  if (ev.type === 'output') body = `<b>${esc(ev.tool || '')}</b> → <pre>${esc(ev.text || '')}</pre>`;
  if (ev.type === 'think') body = `<pre>${esc(ev.text || '')}</pre>`;
  if (ev.type === 'chain') {
    const edges = ev.edges || (ev.from_module ? [{
      from_module: ev.from_module, to_module: ev.to_module,
      from_step: ev.from_step, to_step: ev.to_step,
      mapped_params: ev.mapped_params
    }] : []);
    const edgeHtml = edges.map(e =>
      `<div style="margin:4px 0"><code>${esc(e.from_module||'?')}</code>` +
      `<span style="color:var(--accent);margin:0 6px">→</span>` +
      `<code>${esc(e.to_module||'?')}</code>` +
      (e.mapped_params ? ` <span class="hint">${esc(JSON.stringify(e.mapped_params))}</span>` : '') +
      `</div>`
    ).join('');
    body = `<b>${esc(ev.label || '攻击链')}</b>${edgeHtml || (ev.text ? '<pre>'+esc(ev.text)+'</pre>' : '')}`;
  }
  if (ev.type === 'hitl') {
    body = `<b>模块 <code>${esc(ev.module||'?')}</code></b><p>${esc(ev.reason||ev.text||'')}</p>` +
      '<p class="hint">请在表单勾选「确认执行高风险模块」后重新运行。</p>';
  }
  div.className = cls;
  div.innerHTML = `<div class="t">${label}</div>${body}`;
  chain.appendChild(div);
  chain.scrollTop = chain.scrollHeight;
}

function renderAutoAuditResult(data){
  const s = data.summary || {};
  const rows = (data.comparison || []).map(r =>
    `<tr><td><code>${esc(r.module)}</code></td>
     <td>${r.vulnerable_success_rate == null ? '—' : (r.vulnerable_success_rate*100).toFixed(0)+'%'}</td>
     <td>${r.defended_success_rate == null ? '—' : (r.defended_success_rate*100).toFixed(0)+'%'}</td>
     <td>${r.vulnerable_successes}</td><td>${r.defended_successes}</td><td>${r.defended_blocked}</td></tr>`
  ).join('');
  const stepRows = (data.steps || []).map((st, i) =>
    `<tr><td>${i+1}</td><td><code>${esc(st.module)}</code></td>
     <td>${st.defense_on ? 'on' : 'off'}</td>
     <td>${(st.result_summary&&st.result_summary.successes)!=null ? st.result_summary.successes+'/'+(st.result_summary.total||'?') : '—'}</td>
     <td class="err">${esc(st.error||'—')}</td></tr>`
  ).join('');
  const poc = (data.high_risk_findings || []).map((f, i) => {
    const chain = (f.tool_chain || []).map(c =>
      `<tr><td><code>${esc(c.tool||'?')}</code></td><td><code>${esc(JSON.stringify(c.arguments||{}))}</code></td>
       <td>${c.blocked ? '是' : '—'}</td></tr>`).join('');
    return `<div style="margin-bottom:14px;padding:10px;background:#141824;border-radius:8px;border:1px solid var(--border)">
      <b>${i+1}. <code>${esc(f.ref||f.module)}</code></b>
      ${f.payload ? '<pre style="margin:8px 0">'+esc(f.payload)+'</pre>' : ''}
      ${(f.evidence||[]).length ? '<div class="hint">'+esc((f.evidence||[]).join('；'))+'</div>' : ''}
      ${chain ? '<table><thead><tr><th>工具</th><th>参数</th><th>拦截</th></tr></thead><tbody>'+chain+'</tbody></table>' : ''}
    </div>`;
  }).join('');
  const chainEdges = (data.chain_edges || []).map(e =>
    `<tr><td><code>${esc(e.from_module)}(${esc(e.from_step)})</code></td>
     <td style="color:var(--accent)">→</td>
     <td><code>${esc(e.to_module)}(${esc(e.to_step)})</code></td>
     <td><code>${esc(JSON.stringify(e.mapped_params||{}))}</code></td></tr>`
  ).join('');
  const chainList = (data.chains || []).map(ch =>
    `<li><b>${esc(ch.name||ch.chain_id||'chain')}</b>: ` +
    (ch.steps||[]).map(s => `<code>${esc(s.module)}</code>`).join(' → ') + '</li>'
  ).join('');
  const pu = data.planner_usage || {};
  $('auto-result').innerHTML = `
    <h3 style="font-size:14px;color:var(--accent);margin-top:16px">判定结果</h3>
    <div class="cards">
      <div class="card"><b>${esc(s.risk_level||'?')}</b><span>risk_level</span></div>
      <div class="card"><b>${s.vectors_covered||0}</b><span>覆盖向量</span></div>
      <div class="card"><b>${s.successes_vulnerable||0}</b><span>脆弱侧成功</span></div>
      <div class="card"><b>${s.successes_defended||0}</b><span>防护侧成功</span></div>
      <div class="card"><b>${s.blocked_defended||0}</b><span>防护拦截</span></div>
      ${pu.calls ? `<div class="card"><b>${pu.total_tokens||0}</b><span>指挥官 tokens</span></div>
      <div class="card"><b>$${(pu.estimated_cost_usd||0).toFixed(4)}</b><span>估算费用</span></div>` : ''}
    </div>
    <div class="hint">${esc(s.objective||'')}</div>
    ${poc ? '<h3 style="font-size:13px;color:var(--accent);margin-top:14px">高危发现（PoC）</h3>'+poc : ''}
    ${(chainList || chainEdges) ? '<h3 style="font-size:13px;color:var(--accent);margin-top:14px">攻击链依赖</h3>' +
      (chainList ? '<ul style="font-size:12px;margin:6px 0 10px 18px">'+chainList+'</ul>' : '') +
      (chainEdges ? '<table><thead><tr><th>从</th><th></th><th>到</th><th>映射 params</th></tr></thead><tbody>'+chainEdges+'</tbody></table>' : '')
      : ''}
    <h3 style="font-size:13px;color:var(--accent)">攻防对比</h3>
    <table><thead><tr><th>模块</th><th>加固前成功率</th><th>加固后成功率</th><th>前成功</th><th>后成功</th><th>后拦截</th></tr></thead>
    <tbody>${rows || '<tr><td colspan="6">无数据</td></tr>'}</tbody></table>
    <h3 style="font-size:13px;color:var(--accent)">步骤</h3>
    <table><thead><tr><th>#</th><th>模块</th><th>防护</th><th>成功/总数</th><th>错误</th></tr></thead>
    <tbody>${stepRows}</tbody></table>`;
}

async function loadAuditSessions(){
  const tbody = $('auto-sessions-table')?.querySelector('tbody');
  if (!tbody) return;
  try {
    const data = await (await fetch('/api/auto-audit/sessions')).json();
    const rows = (data.sessions || []).map(s =>
      `<tr><td>${new Date((s.ts||0)*1000).toLocaleString()}</td>
       <td><code>${esc(s.mode)}</code></td>
       <td>${esc(s.risk_level)}</td>
       <td>${s.vectors_covered ?? 0}</td>
       <td><a href="#" onclick="viewAuditSession('${esc(s.id)}');return false">查看</a></td></tr>`
    ).join('');
    tbody.innerHTML = rows || '<tr><td colspan="5">暂无历史会话</td></tr>';
  } catch (_) {
    tbody.innerHTML = '<tr><td colspan="5">加载失败</td></tr>';
  }
}

async function viewAuditSession(id){
  try {
    const data = await (await fetch('/api/auto-audit/sessions/' + encodeURIComponent(id))).json();
    $('auto-session-md-title').style.display = 'block';
    const pre = $('auto-session-md');
    pre.style.display = 'block';
    pre.textContent = data.markdown || '';
    if (data.report) renderAutoAuditResult(data.report);
  } catch (e) {
    $('auto-err').textContent = '❌ ' + e.message;
  }
}

async function loadAudit(){
  try {
    const data = await (await fetch('/api/audit')).json();
    $('audit-stats').innerHTML = Object.entries(data.summary).map(([k, v]) =>
      `<div class="card"><b>${v}</b><span>${esc(k)}</span></div>`).join('') || '<div class="card"><b>0</b><span>事件</span></div>';
    $('audit-table tbody').innerHTML = data.events.map(e =>
      `<tr><td>${new Date(e.ts * 1000).toLocaleTimeString()}</td>
       <td><span class="badge b-${e.action}">${esc(e.action)}</span></td>
       <td>${esc(e.detail || '')}</td></tr>`).join('') || '<tr><td colspan="3">暂无事件（先在攻防工作台跑一次攻击）</td></tr>';
  } catch (_) {}
}

init();
if (location.hash) {
  const name = location.hash.replace(/^#/, '');
  if (name) setTimeout(() => activateTab(name), 0);
}
setInterval(loadAudit, 3000);
</script>
</body>
</html>
"""


# --------------------------------------------------------------------------- #
# 请求模型
# --------------------------------------------------------------------------- #
class AttackRequest(BaseModel):
    module: str = "indirect_injection"
    llm: str = "mock"
    model: str | None = None
    base_url: str | None = None
    api_key: str | None = None
    defense: bool = False
    sandbox: bool = False
    judge: bool = False
    variants: int = Field(default=3, ge=1, le=20)
    task: str = ""
    compare: bool = False
    timeout: int = Field(default=120, ge=5, le=600)  # 秒：真实 API 慢/网络不通时兜底


class BenchmarkRequest(BaseModel):
    module: str = "indirect_injection"
    models: list[dict[str, Any]] = Field(default_factory=list)
    variants: int = Field(default=3, ge=1, le=20)


class PingRequest(BaseModel):
    llm: str = "mock"
    model: str | None = None
    base_url: str | None = None
    api_key: str | None = None


class PolicyRequest(BaseModel):
    tool: str = "run_command"
    arguments: dict[str, Any] = Field(default_factory=dict)


class SandboxRequest(BaseModel):
    command: str
    sandbox: bool = True


class AutoAuditRequest(BaseModel):
    mode: str = "plan"
    target_kind: str = "local"
    target_url: str | None = None
    defense_target_url: str | None = None
    timeout: float = Field(default=60.0, gt=0)
    llm: str = "mock"
    model: str | None = None
    base_url: str | None = None
    api_key: str | None = None
    max_steps: int = Field(default=5, ge=1, le=11)
    max_turns: int = Field(default=12, ge=1, le=30)
    task: str = ""
    compare_defense: bool = True
    full: bool = False
    include_mock_only: bool = True
    fail_fast: bool = False
    use_proxy_hunt: bool = False
    hitl_confirm_dangerous: bool = False
    mcp_url: str | None = None


# --------------------------------------------------------------------------- #
# 工具函数
# --------------------------------------------------------------------------- #
def _trace_items(trace: AgentTrace | None) -> list[dict]:
    if trace is None:
        return []
    items: list[dict] = [{"type": "user", "text": trace.task}]
    for step in trace.steps:
        for tc in step.tool_calls:
            items.append({"type": "assistant_call", "tool": tc.name, "args": tc.arguments})
        for bc in step.blocked_calls:
            items.append({"type": "blocked", "tool": bc.tool, "reason": bc.reason})
        for out in step.tool_outputs:
            items.append({"type": "tool_output", "tool": out.name, "text": out.content})
        if step.final_answer:
            items.append({"type": "final", "text": step.final_answer})
    return items


def _result_payload(result: AttackResult) -> dict:
    return {
        "module": result.module,
        "owasp_asi": result.owasp_asi,
        "atlas_id": result.atlas_id,
        "summary": result.summary(),
        "warnings": _collect_warnings(result),
        "cases": [
            {
                "name": c.name,
                "verdict": c.verdict.value,
                "severity": c.severity.value,
                "evidence": c.evidence,
            }
            for c in result.cases
        ],
        "timeline": _trace_items(result.cases[0].trace) if result.cases else [],
    }


def _collect_warnings(result: AttackResult) -> list[str]:
    """扫描用例轨迹中的 agent error（真实 API 调用失败会被运行时吞进 trace，
    若不提示会被误判为"模型没有漏洞"）。"""
    seen: list[str] = []
    for case in result.cases:
        if case.trace and case.trace.final_answer and "agent error" in case.trace.final_answer:
            msg = case.trace.final_answer.replace("(agent error: ", "").rstrip(")")
            if msg and msg not in seen:
                seen.append(msg)
    return seen


async def _preflight_llm(req: AttackRequest) -> None:
    """真实 API 在跑攻击前先做一次最小连接测试，避免整轮跑完才发现连不上。"""
    if req.llm != "openai-compat" or not req.model:
        return
    from agent_shield.models import ChatMessage
    from agent_shield.runtime.llm import OpenAICompatLLM

    llm = OpenAICompatLLM(model=req.model, api_key=req.api_key or None, base_url=req.base_url or None, timeout=15)
    await asyncio.wait_for(llm.chat([ChatMessage.user("回复 OK")], []), timeout=18)


def _build_target(req: AttackRequest, store=None, event_sink=None):
    judge_llm = None
    if req.judge and req.llm == "openai-compat" and req.model:
        from agent_shield.runtime.llm import OpenAICompatLLM

        judge_llm = OpenAICompatLLM(model=req.model, api_key=req.api_key, base_url=req.base_url)
    return build_local_target(
        llm=req.llm,
        defense=req.defense,
        sandbox=req.sandbox,
        model=req.model,
        base_url=req.base_url,
        api_key=req.api_key,
        judge_llm=judge_llm,
        audit_store=store,
        event_sink=event_sink,
    )


# --------------------------------------------------------------------------- #
# 应用
# --------------------------------------------------------------------------- #
# 过程链任务表：POST /api/attack/stream 创建任务，GET /api/attack/events/{id} 轮询进度
_JOBS: dict[str, dict] = {}
_MAX_JOBS = 50


def _cleanup_jobs() -> None:
    """清理已完成任务，防止内存无限增长。"""
    done = [jid for jid, j in _JOBS.items() if j["status"] != "running"]
    for jid in done[: _MAX_JOBS // 2]:
        _JOBS.pop(jid, None)


async def _run_attack_job(job: dict, req: AttackRequest, store) -> None:
    """后台执行攻击，把过程链事件实时写入 job["events"]（前端轮询展示）。"""
    task = req.task or DEFAULT_TASK
    try:
        module = _get(req.module)

        def sink(event: dict) -> None:
            job["events"].append(event)

        # 预检：真实 API 连不上时直接报错，不再白白跑完整轮攻击
        try:
            await _preflight_llm(req)
        except TimeoutError as exc:
            raise ValueError("模型连接超时（>18s）：请检查 Base URL / API Key / 网络") from exc

        if req.compare:
            job["events"].append({"type": "phase", "label": "阶段 1：加固前（脆弱靶场）"})
            req.defense = False
            before = await asyncio.wait_for(
                module.run(_build_target(req, store, sink), AttackConfig(task=task, num_variants=req.variants)),
                timeout=req.timeout,
            )
            job["events"].append({"type": "phase", "label": "阶段 2：加固后（挂防护层）"})
            req.defense = True
            after = await asyncio.wait_for(
                module.run(_build_target(req, store, sink), AttackConfig(task=task, num_variants=req.variants)),
                timeout=req.timeout,
            )
            job["result"] = {"compare": True, "before": _result_payload(before), "after": _result_payload(after)}
        else:
            result = await asyncio.wait_for(
                module.run(_build_target(req, store, sink), AttackConfig(task=task, num_variants=req.variants)),
                timeout=req.timeout,
            )
            job["result"] = _result_payload(result)
        job["status"] = "done"
    except TimeoutError:
        job["status"] = "error"
        job["error"] = (
            f"运行超时（>{req.timeout}s）：真实 API 可能网络不通、Key/Base URL 错误或模型名不对。"
            "请先点「测试连接」确认配置。"
        )
    except Exception as exc:  # noqa: BLE001 —— 任务级兜底，错误透出到前端
        job["status"] = "error"
        job["error"] = f"{type(exc).__name__}: {exc}"


async def _resolve_audit_planner(req: AutoAuditRequest, store=None):
    from agent_shield.orchestrator.plan_execute import FixedPlanLLM
    from agent_shield.orchestrator.react_loop import DefaultReActLLM
    from agent_shield.runtime.llm import OpenAICompatLLM

    if req.mode not in {"plan", "react"}:
        raise ValueError(f"未知 mode: {req.mode}")
    if req.llm == "mock":
        if req.mode == "plan":
            return FixedPlanLLM()
        use_proxy = bool(
            req.use_proxy_hunt and store is not None and store.count() > 0
        )
        return DefaultReActLLM(use_proxy_analysis=use_proxy)
    if req.llm == "openai-compat":
        if not req.model:
            raise ValueError("openai-compat 需填写 model")
        return OpenAICompatLLM(model=req.model, api_key=req.api_key, base_url=req.base_url)
    raise ValueError(f"未知 llm: {req.llm}")


def _audit_target_spec_from_request(req: AutoAuditRequest, store) -> "AuditTargetSpec":  # noqa: F821
    from agent_shield.orchestrator.target_factory import AuditTargetSpec

    if req.target_kind not in {"local", "http", "mcp"}:
        raise ValueError(f"未知 target_kind: {req.target_kind}")
    if req.target_kind == "http" and not req.target_url:
        raise ValueError("http 目标需填写 target_url")
    if req.target_kind == "mcp" and not req.mcp_url:
        raise ValueError("mcp 目标需填写 mcp_url")
    return AuditTargetSpec(
        kind=req.target_kind,  # type: ignore[arg-type]
        llm=req.llm,
        model=req.model,
        api_key=req.api_key,
        api_base_url=req.base_url,
        target_url=req.target_url,
        defense_target_url=req.defense_target_url,
        timeout=req.timeout,
        mcp_url=req.mcp_url,
        audit_store=store,
    )


def _save_audit_session(session_store, report, req: AutoAuditRequest, store) -> str | None:
    if session_store is None:
        return None
    from agent_shield.targets import DEFAULT_TASK

    spec = _audit_target_spec_from_request(req, store)
    return session_store.save_session(report, target_spec=spec, task=req.task or DEFAULT_TASK)


async def _run_auto_audit_core(req: AutoAuditRequest, store, on_event=None):
    from agent_shield.orchestrator.plan_execute import audit_plan_and_execute
    from agent_shield.orchestrator.react_loop import audit_agent_loop
    from agent_shield.orchestrator.target_factory import build_audit_target_factory, resolve_audit_options

    target_spec = _audit_target_spec_from_request(req, store)
    planner = await _resolve_audit_planner(req, store)

    compare_defense, include_mock_only, option_notes = resolve_audit_options(
        target_spec,
        compare_defense=req.compare_defense,
        include_mock_only=req.include_mock_only,
    )
    if on_event:
        for note in option_notes:
            on_event({"type": "phase", "label": "目标配置", "text": note})
        if req.use_proxy_hunt and store is not None and store.count() > 0:
            on_event(
                {
                    "type": "phase",
                    "label": "Proxy 狩猎",
                    "text": f"已加载 {store.count()} 条 audit_events，将优先 analyze_proxy_events",
                }
            )

    target_factory = build_audit_target_factory(target_spec)
    proxy_store = store if (store is not None and req.mode == "react") else None
    from agent_shield.orchestrator.hitl import DANGEROUS_ATTACK_MODULES

    hitl_confirmed = frozenset(DANGEROUS_ATTACK_MODULES) if req.hitl_confirm_dangerous else None

    if req.mode == "plan":
        return await audit_plan_and_execute(
            planner=planner,
            target_factory=target_factory,
            task=req.task or DEFAULT_TASK,
            max_steps=req.max_steps,
            compare_defense=compare_defense,
            include_mock_only=include_mock_only,
            fail_fast=req.fail_fast,
            full=req.full,
            on_event=on_event,
            export_traces=False,
            hitl_confirmed_modules=hitl_confirmed,
        )
    return await audit_agent_loop(
        planner=planner,
        target_factory=target_factory,
        task=req.task or DEFAULT_TASK,
        max_turns=req.max_turns,
        compare_defense=compare_defense,
        include_mock_only=include_mock_only,
        on_event=on_event,
        proxy_store=proxy_store,
        export_traces=False,
        hitl_confirmed_modules=hitl_confirmed,
    )


async def _run_auto_audit_job(job: dict, req: AutoAuditRequest, store, session_store=None) -> None:
    """后台执行自主审计，把规划/逐步结果写入 job['events']。"""
    from agent_shield.orchestrator.report import session_report_to_json

    try:
        def sink(event: dict) -> None:
            job["events"].append(event)

        report = await _run_auto_audit_core(req, store, on_event=sink)
        payload = session_report_to_json(report)
        sid = _save_audit_session(session_store, report, req, store)
        if sid:
            payload["session_id"] = sid
        job["result"] = payload
        job["status"] = "done"
    except Exception as exc:  # noqa: BLE001
        job["status"] = "error"
        job["error"] = f"{type(exc).__name__}: {exc}"
        job["events"].append({"type": "error", "text": job["error"]})


def build_web_app(store=None, session_store=None) -> FastAPI:
    """构建攻防工作台应用（/ 页面 + /api/* JSON 接口）。

    store：可选 AuditStore，攻击过程中的工具调用事件会写入并可在"审计"页查看。
    session_store：可选 AuditSessionStore，自主审计终报持久化。
    """
    if session_store is None and store is not None:
        from agent_shield.orchestrator.session_store import AuditSessionStore

        session_store = AuditSessionStore(store.path)
    elif session_store is None:
        from agent_shield.orchestrator.session_store import AuditSessionStore

        session_store = AuditSessionStore()
    app = FastAPI(title="AgentShield 攻防工作台")

    @app.get("/", response_class=HTMLResponse)
    async def index() -> str:
        return WORKBENCH_HTML

    @app.get("/metrics")
    async def metrics() -> PlainTextResponse:
        """Prometheus 文本格式指标（与代理的 /metrics 同一注册表）。"""
        return PlainTextResponse(render_metrics(), media_type="text/plain; version=0.0.4; charset=utf-8")

    @app.get("/api/modules")
    async def modules() -> list[dict]:
        return [
            {
                "name": name,
                "description": desc,
                "owasp_asi": _get(name).owasp_asi,
                "atlas_id": _get(name).atlas_id,
                "mock_only": _get(name).mock_only,
            }
            for name, desc in list_attack_modules()
        ]

    @app.get("/api/model-presets")
    async def model_presets() -> list[dict]:
        return [
            {"key": "mock", "label": "Mock 离线靶场（零成本）", "model": "", "base_url": "", "api_key": ""},
            {"key": "openai", "label": "OpenAI / DeepSeek / Qwen 等兼容 API", "model": "deepseek-chat", "base_url": "https://api.deepseek.com/v1", "api_key": ""},
            {"key": "ollama", "label": "Ollama 本地模型", "model": "qwen2.5:7b", "base_url": "http://localhost:11434/v1", "api_key": ""},
        ]

    @app.post("/api/attack")
    async def attack(req: AttackRequest) -> dict:
        module = _get(req.module)
        task = req.task or DEFAULT_TASK
        try:
            await _preflight_llm(req)

            async def _run(defense: bool) -> AttackResult:
                phase_req = copy.copy(req)
                phase_req.defense = defense
                return await module.run(
                    _build_target(phase_req, store), AttackConfig(task=task, num_variants=req.variants)
                )

            if req.compare:
                # 加固前后使用各自独立靶场，可并行（耗时减半）
                before, after = await asyncio.gather(
                    asyncio.wait_for(_run(False), timeout=req.timeout),
                    asyncio.wait_for(_run(True), timeout=req.timeout),
                )
                return {"compare": True, "before": _result_payload(before), "after": _result_payload(after)}
            result = await asyncio.wait_for(_run(req.defense), timeout=req.timeout)
            return _result_payload(result)
        except TimeoutError as exc:
            raise HTTPException(
                status_code=408,
                detail=f"运行超时（>{req.timeout}s）：真实 API 可能网络不通、Key/Base URL 错误或模型名不对。"
                f"请检查：mock 无需配置；云端 API 需填服务商 base-url + api-key + 正确模型名；本地 Ollama 填 http://localhost:11434/v1",
            ) from exc
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"{type(exc).__name__}: {exc}") from exc

    @app.post("/api/attack/stream")
    async def attack_stream(req: AttackRequest) -> dict:
        """创建攻击任务：立即返回 job_id，前端轮询 /api/attack/events/{id} 看实时过程链。"""
        _cleanup_jobs()
        job_id = uuid.uuid4().hex[:12]
        job: dict = {"id": job_id, "status": "running", "events": [], "error": "", "result": None}
        _JOBS[job_id] = job
        asyncio.create_task(_run_attack_job(job, req, store))
        return {"job_id": job_id}

    @app.get("/api/attack/events/{job_id}")
    async def attack_events(job_id: str) -> dict:
        job = _JOBS.get(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="job not found（可能已过期清理）")
        return {
            "status": job["status"],
            "events": job["events"],
            "error": job["error"],
            "result": job["result"],
        }

    @app.post("/api/benchmark")
    async def benchmark(req: BenchmarkRequest) -> dict:
        module = _get(req.module)
        rows: list[dict] = []

        async def _run_model(m: dict) -> dict:
            label = m.get("label") or m.get("model") or "?"
            is_mock = (m.get("model") or "").strip().lower() == "mock"
            # 需要控制智能体内部状态的模块（如 ASI-10 失控智能体）对黑盒真实 API 不可测
            if module.mock_only and not is_mock:
                return {
                    "label": label,
                    "model": m.get("model"),
                    "skipped": True,
                    "note": "该攻击需要控制智能体内部状态（仅本地 Mock 靶场可测），黑盒真实 API 无法模拟",
                }

            async def _run(defense: bool) -> AttackResult:
                return await module.run(
                    build_local_target(
                        llm="mock" if is_mock else "openai-compat",
                        defense=defense,
                        model=None if is_mock else m.get("model"),
                        base_url=m.get("base_url"),
                        api_key=m.get("api_key"),
                    ),
                    AttackConfig(num_variants=req.variants),
                )

            try:
                # 每个模型的加固前/后并行（多个模型也整体并行，总耗时 ≈ 最慢的一个模型）
                before, after = await asyncio.gather(
                    asyncio.wait_for(_run(False), timeout=60),
                    asyncio.wait_for(_run(True), timeout=60),
                )
            except Exception as exc:  # noqa: BLE001 —— 单个模型失败不阻塞其他模型
                return {"label": label, "model": m.get("model"), "error": f"{type(exc).__name__}: {exc}"}
            return {
                "label": label,
                "model": m.get("model"),
                "vulnerable_success_rate": before.success_rate,
                "defended_success_rate": after.success_rate,
                "vulnerable_successes": before.successes,
                "defended_successes": after.successes,
                "total": before.total,
            }

        results = await asyncio.gather(*(_run_model(m) for m in req.models))
        rows.extend(results)
        return {"module": req.module, "rows": rows}

    @app.post("/api/ping")
    async def ping(req: PingRequest) -> dict:
        """先用一条最小消息验证模型 API 配置，避免攻击流程白等。"""
        if req.llm == "mock":
            return {"ok": True, "message": "Mock 离线靶场可用，无需配置。"}
        if not req.model:
            raise HTTPException(status_code=400, detail="请填写模型名（如 deepseek-chat / qwen-max）")
        from agent_shield.models import ChatMessage
        from agent_shield.runtime.llm import OpenAICompatLLM

        llm = OpenAICompatLLM(model=req.model, api_key=req.api_key or None, base_url=req.base_url or None, timeout=20)
        try:
            resp = await asyncio.wait_for(llm.chat([ChatMessage.user("请只回复两个字：OK")], []), timeout=25)
            return {"ok": True, "message": f"连接成功，模型回复：{(resp.content or '').strip()[:60]}"}
        except TimeoutError as exc:
            raise HTTPException(status_code=408, detail="连接超时（>25s）：请检查 Base URL / 网络 / API Key") from exc
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"连接失败：{type(exc).__name__}: {exc}") from exc

    @app.post("/api/policy/check")
    async def policy_check(req: PolicyRequest) -> dict:
        from agent_shield.models import ToolCall

        engine = PolicyEngine()
        decision = await engine.check_tool_call(ToolCall(id="web", name=req.tool, arguments=req.arguments))
        return {"allowed": decision.allowed, "reason": decision.reason}

    @app.post("/api/sandbox/run")
    async def sandbox_run(req: SandboxRequest) -> dict:
        from agent_shield.models import ToolCall

        # 第一道防线：语义策略引擎（命令/路径白名单 + 元字符拦截）
        engine = PolicyEngine()
        policy = await engine.check_tool_call(ToolCall(id="web", name="run_command", arguments={"command": req.command}))
        if not policy.allowed:
            return {
                "returncode": -3,
                "stdout": "",
                "stderr": f"denied by policy: {policy.reason}",
                "timed_out": False,
                "denied": True,
                "stage": "policy",
            }
        # 第二道防线：沙箱危险命令黑名单 + 资源限制
        result = SandboxExecutor().run(req.command, sandbox=req.sandbox)
        return {
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "timed_out": result.timed_out,
            "denied": result.denied,
            "stage": "sandbox" if result.denied else "executed",
        }

    @app.post("/api/auto-audit")
    async def auto_audit(req: AutoAuditRequest) -> dict:
        """自主审计（plan / react，同步，便于单测）。"""
        from agent_shield.orchestrator.report import session_report_to_json

        try:
            report = await _run_auto_audit_core(req, store)
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"{type(exc).__name__}: {exc}") from exc
        payload = session_report_to_json(report)
        sid = _save_audit_session(session_store, report, req, store)
        if sid:
            payload["session_id"] = sid
        return payload

    @app.post("/api/auto-audit/stream")
    async def auto_audit_stream(req: AutoAuditRequest) -> dict:
        """创建自主审计任务：立即返回 job_id，前端轮询过程链。"""
        _cleanup_jobs()
        job_id = uuid.uuid4().hex[:12]
        job: dict = {"id": job_id, "status": "running", "events": [], "error": "", "result": None}
        _JOBS[job_id] = job
        asyncio.create_task(_run_auto_audit_job(job, req, store, session_store))
        return {"job_id": job_id}

    @app.get("/api/auto-audit/events/{job_id}")
    async def auto_audit_events(job_id: str) -> dict:
        job = _JOBS.get(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="job not found（可能已过期清理）")
        return {
            "status": job["status"],
            "events": job["events"],
            "error": job["error"],
            "result": job["result"],
        }

    @app.get("/api/auto-audit/sessions")
    async def auto_audit_sessions(limit: int = 50) -> dict:
        rows = session_store.list_sessions(limit=limit)
        return {"sessions": rows, "total": session_store.count()}

    @app.get("/api/auto-audit/sessions/{session_id}")
    async def auto_audit_session_detail(session_id: str) -> dict:
        item = session_store.get_session(session_id)
        if item is None:
            raise HTTPException(status_code=404, detail="session not found")
        from agent_shield.orchestrator.report import session_report_to_json

        report = session_store.load_report(session_id)
        return {
            "id": item["id"],
            "ts": item["ts"],
            "mode": item["mode"],
            "target_spec": item["target_spec"],
            "task": item["task"],
            "risk_level": item["risk_level"],
            "vectors_covered": item["vectors_covered"],
            "markdown": item["markdown"],
            "report": session_report_to_json(report),
        }

    @app.get("/api/audit")
    async def audit() -> dict:
        if store is None:
            return {"events": [], "summary": {}}
        rows = store.latest(100)
        summary: dict[str, int] = {}
        for row in rows:
            summary[row["action"]] = summary.get(row["action"], 0) + 1
        summary["total"] = len(rows)
        return {"events": rows, "summary": summary}

    return app
