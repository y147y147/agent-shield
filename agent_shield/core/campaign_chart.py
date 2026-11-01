"""Phase 3 图表：把 campaign 战报渲染为纯 SVG 横向柱状图（关注点：逐 (目标×模块) 的 ASR）。

与 ```model_benchmark.render_chart_svg``` 同一风格，但面向红队战役战报：
- 横轴为 (target, module) 聚合的 aggr_rate（ASR）；
- 绿色 = 0%（该格轻击全部被防/未打穿），红色或琥珀 = >0%（有打穿面，后续要收敛）。
输出纯 SVG 字符串，CLI 直接落盘，离线可回归（无第三方图表库）。
"""

from __future__ import annotations

_WIDTH = 880
_LEFT = 210
_ROW_H = 24
_GREEN = "#16a34a"
_RED = "#dc2626"
_AMBER = "#d97706"
_NEUTRAL = "#6b7280"
_BAR_H = 10


def render_campaign_chart_svg(report) -> str:
    """把 CampaignReport 渲染成 SVG（逐 target×module 的 aggr_rate 横向柱），返回 SVG 字符串。"""
    rows = list(report.per_target_rows())
    top = 52
    height = top + _ROW_H * (len(rows) + 2)
    svg = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {_WIDTH} {height}" '
        f'font-family="Segoe UI, -apple-system, Arial, sans-serif" width="100%">',
        f'<rect width="{_WIDTH}" height="{height}" fill="#ffffff"/>',
        f'<text x="{_LEFT}" y="22" font-size="15" font-weight="700" fill="#111827">'
        "AgentShield 红队战役战报 · 逐格攻击成功率 ASR</text>",
        f'<text x="{_LEFT}" y="42" font-size="12" fill="{_NEUTRAL}">'
        f'rounds={report.cfg.rounds} · variants={report.cfg.num_variants} · '
        f'concurrency={report.cfg.concurrency} · seed={report.cfg.seed} · '
        f'defense={report.cfg.defense} · {len(report.cells)} cells</text>',
    ]
    y = top + 6
    for row in rows:
        label = f'{row["target"][:18]}:{row["module"].replace("_", " ")[:18]}'
        rate = float(row["aggr_rate"])
        w = int(rate * 620)
        color = _GREEN if rate == 0 else (_RED if rate >= 0.5 else _AMBER)
        svg.append(f'<text x="{_LEFT - 10}" y="{y + 3}" font-size="10" text-anchor="end" fill="#374151">{label}</text>')
        svg.append(f'<rect x="{_LEFT}" y="{y - _BAR_H + 2}" width="{max(w, 2)}" height="{_BAR_H}" rx="2" fill="{color}"/>')
        svg.append(f'<text x="{_LEFT + w + 6}" y="{y + 3}" font-size="10" fill="{color}">{rate:.0%}</text>')
        y += _ROW_H
    svg.append(
        f'<text x="{_LEFT}" y="{y + 12}" font-size="10" fill="{_NEUTRAL}">'
        f'■ 0% · 该格全部被防/未打穿　● >0% · 存在打穿面（加固后需收敛）</text>'
    )
    svg.append("</svg>")
    return "\n".join(svg)