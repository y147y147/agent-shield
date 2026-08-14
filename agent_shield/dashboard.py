"""Web Dashboard：审计事件可视化（无前端依赖，FastAPI + 原生 HTML/JS）。"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.responses import HTMLResponse

from agent_shield.proxy.audit import AuditStore

DASHBOARD_HTML = """<!doctype html>
<html lang="zh">
<head>
<meta charset="utf-8">
<title>AgentShield Audit Dashboard</title>
<style>
  body { font-family: -apple-system, "PingFang SC", monospace; background:#0f1117; color:#d1d5db; margin:0; padding:24px; }
  h1 { color:#e5e7eb; font-size:20px; }
  .stats { display:flex; gap:16px; margin:16px 0 24px; flex-wrap:wrap; }
  .card { background:#1a1d29; border:1px solid #2a2e3d; border-radius:8px; padding:12px 20px; min-width:110px; }
  .card b { display:block; font-size:26px; color:#7dd3fc; }
  .card span { font-size:12px; color:#9ca3af; }
  table { width:100%; border-collapse:collapse; background:#1a1d29; border-radius:8px; overflow:hidden; font-size:13px; }
  th, td { padding:8px 12px; text-align:left; border-bottom:1px solid #2a2e3d; }
  th { color:#9ca3af; font-weight:600; }
  .badge { padding:2px 8px; border-radius:10px; font-size:11px; }
  .b-block { background:#7f1d1d; color:#fecaca; }
  .b-mock, .b-forward { background:#1e3a5f; color:#bfdbfe; }
  .b-executed { background:#14532d; color:#bbf7d0; }
  .danger { color:#f87171; }
</style>
</head>
<body>
<h1>🛡 AgentShield 审计看板 <span id="mode" style="font-size:13px;color:#9ca3af"></span></h1>
<div class="stats" id="stats"></div>
<table id="events">
  <thead><tr><th>时间</th><th>方向</th><th>模型</th><th>动作</th><th>检测到注入</th><th>详情</th></tr></thead>
  <tbody></tbody>
</table>
<script>
async function load() {
  const res = await fetch('/api/events?n=200');
  const data = await res.json();
  const evts = data.events || [];
  const counts = data.summary || {};
  document.getElementById('mode').textContent = '(自动刷新 5s)';
  document.getElementById('stats').innerHTML = Object.entries(counts)
    .map(([k, v]) => `<div class="card"><b>${v}</b><span>${k}</span></div>`).join('') ||
    '<div class="card"><b>0</b><span>events</span></div>';
  const rows = evts.map(e => {
    const dets = e.detections ? JSON.parse(e.detections || '[]') : [];
    const badge = dets.length ? `<span class="badge b-block">${dets.length} 条注入信号</span>` : '';
    const t = new Date(e.ts * 1000).toLocaleString();
    return `<tr>
      <td>${t}</td><td>${e.direction}</td><td>${e.model || '-'}</td>
      <td><span class="badge b-${e.action}">${e.action}</span></td>
      <td>${badge || '-'}</td><td class="danger">${(dets[0]?.snippet || e.detail || '').slice(0, 120)}</td>
    </tr>`;
  }).join('');
  document.querySelector('#events tbody').innerHTML = rows || '<tr><td colspan="6">暂无事件</td></tr>';
}
load();
setInterval(load, 5000);
</script>
</body>
</html>
"""


def build_dashboard_app(store: AuditStore) -> FastAPI:
    """构建审计看板应用（/ 页面 + /api/events JSON）。"""
    app = FastAPI(title="AgentShield Dashboard")

    @app.get("/", response_class=HTMLResponse)
    async def index() -> str:
        return DASHBOARD_HTML

    @app.get("/api/events")
    async def events(n: int = 200) -> dict:
        rows = store.latest(n)
        summary = {}
        for row in rows:
            summary[row["action"]] = summary.get(row["action"], 0) + 1
        summary["total"] = len(rows)
        return {"events": rows, "summary": summary}

    return app
