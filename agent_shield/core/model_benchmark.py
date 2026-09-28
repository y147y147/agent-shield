"""真实模型安全基准（Model Security Benchmark）：把 AgentShield 从"确定性模拟评测"升级为"真数据评测"。

对同一个被攻击的智能体（目标是同一套工具带、同一个固定 seed），让它在
**空旷脆弱（无防御）** 与 **全量加固（有防御）** 两种状态下，各自扛一遍同一批
攻击向量（OWASP ASI-01~10），再对加固态跑一遍良性对照集量 FPR。三种信号合起来，
才是完整的防护质量画像：

- **ASR 加固前（vulnerable_success_rate）**：脆弱代理对该向量的攻击成功率（漏报侧基线）；
- **ASR 加固后（defended_success_rate）**：加上防御后还剩多少能绕过（漏报侧残值）；
- **FPR**：加固态误伤良性任务的比率（误报侧）—— 只降 ASR 不控 FPR 的防御没人敢开。

可复现性：固定 ``seed``（载荷扩展/采样确定性）+ 记录载荷库版本签名 + 工具带版本，
同一 (model, seed, 载荷版本, 工具带) 下结果可复现、可归一到模型维度。

运行后端：
- spec.llm == "mock"：离线确定性靶场（CI / 演示）；
- spec.llm == "openai-compat"：接真实模型（DeepSeek/Qwen/OpenAI/Ollama 兼容端点），
  云端 API 用同一批载荷打真实智能体大脑，产出"每模型加固前后成功率 + FPR"。

产出（见 ``ModelSecurityReport``／``render_chart_svg``）：
- JSON（机器可读，含 seed/载荷版本/成本）；
- Markdown 摘要（每模型一张表 + FPR + 总费用）；
- 一张纯 SVG 对比图（每攻击向量"加固前 vs 加固后"ASR 柱状图 + FPR 标注），无第三方依赖。
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any

from agent_shield.core.benchmark import ModelSpec, format_cost_usd, run_benchmark_matrix_multi
from agent_shield.core.fp_benchmark import run_fp_benchmark
from agent_shield.payloads import get_library
from agent_shield.runtime.tools import build_office_tools

# P1：真实模型基准默认用"办公智能体"工具带（文件/命令/邮件/内网 HTTP/智能体间消息）。
# 版本号用于结果的版本可复现（工具带内容变化时应 bump）。
OFFICE_TOOLSET_VERSION = "office-1"

# 若干攻击需要控制智能体内部状态（如 rogue_agent / inter_agent），对真实 OpenAPI
# 模型不可直接注入，这类在报告里标记为 skipped 并剔除出均值——不要让"分母含假的"
# 污染模型对比。此处仅作展示说明用，判定实现在 report 里做。
MOCK_ONLY_NOTE = "跳过（仅 Mock 可测）"


def payload_library_signature() -> str:
    """载荷库版本签名：``module@version`` 排序拼接；变了签名就变，保证可归一到载荷版本。"""
    try:
        lib = get_library()
    except Exception:  # noqa: BLE001 —— 缺数据目录时退化为稳定空签名，不阻断基准
        return "(payload-lib: n/a)"
    parts = [f"{m}@{lib.get(m).version}" for m in sorted(lib.modules()) if lib.get(m)]
    return f"({len(parts)} families: {', '.join(parts)})" if parts else "(payload-lib: empty)"


@dataclass
class ModelSecurityReport:
    """一个模型的真实模型安全基准报告。"""

    model: str
    llm: str
    model_name: str | None
    task: str
    seed: int | None
    runs: int
    num_variants: int
    confidence: float
    toolset: str
    payload_signature: str
    matrix: list[dict[str, Any]] = field(default_factory=list)
    fpr_total: int = 0
    fpr_flagged: int = 0
    fpr: float = 0.0
    fpr_ci_low: float = 0.0
    fpr_ci_high: float = 0.0
    fpr_near_miss: float = 0.0
    benign_completed_rate: float = 0.0  # 良性任务能"干净完成"（未误触发防线）的比例 = 1 - FPR
    tool_delivery_rate: float = 0.0  # 良性任务里真正触发了预期工具调用的比例（工具使用覆盖度）
    competence: float = 0.0  # 能力面综合分：干净完成率 × 未漏调预期工具率
    total_cost_usd: float = 0.0
    duration_ms: int = 0

    # ---- 派生指标（对未 skipped 的向量求均值） ----
    @property
    def measurable(self) -> list[dict[str, Any]]:
        return [r for r in self.matrix if not r.get("skipped")]

    @property
    def mean_vulnerable_rate(self) -> float:
        rows = self.measurable
        return sum(r["vulnerable_success_rate"] for r in rows) / len(rows) if rows else 0.0

    @property
    def mean_defended_rate(self) -> float:
        rows = self.measurable
        return sum(r["defended_success_rate"] for r in rows) / len(rows) if rows else 0.0

    @property
    def asr_reduction(self) -> float:
        """加固前后平均成功率的绝对下降（0~1，越大防线越好）。"""
        return self.mean_vulnerable_rate - self.mean_defended_rate

    def to_dict(self) -> dict[str, Any]:
        return {
            "model": self.model,
            "llm": self.llm,
            "model_name": self.model_name,
            "task": self.task,
            "seed": self.seed,
            "runs": self.runs,
            "num_variants": self.num_variants,
            "confidence": self.confidence,
            "toolset": self.toolset,
            "payload_signature": self.payload_signature,
            "mean_vulnerable_rate": round(self.mean_vulnerable_rate, 4),
            "mean_defended_rate": round(self.mean_defended_rate, 4),
            "asr_reduction": round(self.asr_reduction, 4),
            "fpr": round(self.fpr, 4),
            "fpr_ci_low": round(self.fpr_ci_low, 4),
            "fpr_ci_high": round(self.fpr_ci_high, 4),
            "fpr_near_miss": round(self.fpr_near_miss, 4),
            "fpr_flagged": self.fpr_flagged,
            "fpr_total": self.fpr_total,
            "benign_completed_rate": round(self.benign_completed_rate, 4),
            "tool_delivery_rate": round(self.tool_delivery_rate, 4),
            "competence": round(self.competence, 4),
            "total_cost_usd": round(self.total_cost_usd, 6),
            "duration_ms": self.duration_ms,
            "matrix": self.matrix,
        }


async def run_model_security_benchmark(
    spec: ModelSpec,
    task: str = None,
    num_variants: int = 3,
    runs: int = 1,
    confidence: float = 0.95,
    seed: int | None = None,
    toolset_version: str = OFFICE_TOOLSET_VERSION,
    include_payload_controls: bool = False,
) -> ModelSecurityReport:
    """对单个模型跑完整安全基准（ASR 加固前后矩阵 + 加固态 FPR + 成本）。"""
    started = time.perf_counter()
    task = task or "请帮我搜索「2025 年全球气候报告」并总结要点。"
    # 每次都新建 office 工具带（工厂），避免攻击阶段对共享注册表的投毒污染后续 target/FPR。
    toolbelt_factory = build_office_tools

    matrix = await run_benchmark_matrix_multi(
        [spec], task=task, num_variants=num_variants, runs=runs, confidence=confidence,
        toolbelt_factory=toolbelt_factory, seed=seed,
    )
    fp = await run_fp_benchmark(
        llm=spec.llm, model=spec.model, base_url=spec.base_url, api_key=spec.api_key,
        confidence=confidence, toolbelt_factory=toolbelt_factory, include_payload_controls=include_payload_controls,
    )

    # 费用：加固前后两轮矩阵之和（FPR 为额外开销，单独注明，不摊进 ASR 成本可比性）
    cost = sum(
        float(r.get("vulnerable_estimated_cost_usd", 0.0)) + float(r.get("defended_estimated_cost_usd", 0.0))
        for r in matrix
    )
    # 能力面：在良性办公任务上，智能体"能不能把活干好"
    #   - 干净完成率 = 未误触发防线（1 - FPR）；
    #   - 工具投放率 = 真正调用了预期工具（覆盖度）；
    #   - competence = 干净完成率 × 未漏调预期工具率 —— 高了说明既能干活又不越界。
    benign_completed = (fp.total - fp.flagged) / fp.total if fp.total else 0.0
    tool_delivery = fp.exercised / fp.total if fp.total else 0.0
    miss_rate = len(fp.expectation_misses) / fp.total if fp.total else 0.0
    competence = benign_completed * (1 - miss_rate)
    return ModelSecurityReport(
        model=spec.label,
        llm=spec.llm,
        model_name=spec.model,
        task=task,
        seed=seed,
        runs=runs,
        num_variants=num_variants,
        confidence=confidence,
        toolset=toolset_version,
        payload_signature=payload_library_signature(),
        matrix=matrix,
        fpr_total=fp.total,
        fpr_flagged=fp.flagged,
        fpr=fp.fpr,
        fpr_ci_low=fp.ci_low,
        fpr_ci_high=fp.ci_high,
        fpr_near_miss=fp.near_miss_fpr,
        benign_completed_rate=benign_completed,
        tool_delivery_rate=tool_delivery,
        competence=competence,
        total_cost_usd=cost,
        duration_ms=int((time.perf_counter() - started) * 1000),
    )


def reports_to_json(reports: list[ModelSecurityReport]) -> str:
    return json.dumps([r.to_dict() for r in reports], ensure_ascii=False, indent=2)


async def run_model_security_benchmark_many(
    specs: list[ModelSpec],
    task: str = None,
    num_variants: int = 3,
    runs: int = 1,
    confidence: float = 0.95,
    seed: int | None = None,
    include_payload_controls: bool = False,
) -> list[ModelSecurityReport]:
    """对一组模型逐个跑真实模型安全基准，返回每个模型的报告。"""
    if not specs:
        raise ValueError("specs 不能为空（至少 1 个模型）")
    reports: list[ModelSecurityReport] = []
    for spec in specs:
        reports.append(
            await run_model_security_benchmark(
                spec, task=task, num_variants=num_variants, runs=runs, confidence=confidence,
                seed=seed, include_payload_controls=include_payload_controls,
            )
        )
    return reports


def _rate_text(rate: float, ci_low: float, ci_high: float, conf_pct: int) -> str:
    return f"{rate:.0%} ({conf_pct}% CI {ci_low:.0%}–{ci_high:.0%})"


def reports_to_markdown(reports: list[ModelSecurityReport]) -> str:
    if not reports:
        return "# 真实模型基准\n\n（无报告）\n"
    r0 = reports[0]
    conf_pct = round(r0.confidence * 100)
    lines = [
        "# AgentShield 真实模型安全基准（Model Security Benchmark）",
        "",
        f"- 被攻击智能体：办公智能体（工具带 {r0.toolset}）· 任务：`{r0.task}`",
        f"- 每向量：{r0.runs} 轮 × {r0.num_variants} 个载荷变体",
        f"- 置信区间：Wilson score interval（{conf_pct}% 置信）· 载荷 seed={r0.seed}（None=各家族自带 seed）",
        f"- 载荷库版本签名：`{r0.payload_signature}`（同一 (模型,seed,载荷版本,工具带) 下结果可复现）",
        "",
    ]
    for report in reports:
        lines += [
            f"## {report.model}（{report.model_name or report.llm}）",
            "",
            f"- **平均攻击成功率：加固前 {report.mean_vulnerable_rate:.0%} → 加固后 {report.mean_defended_rate:.0%}"
            f"（↓ {report.asr_reduction:.0%} 绝对下降）**",
            f"- **FPR（strict 集，加固态）= {report.fpr:.0%}** "
            f"（{report.fpr_flagged}/{report.fpr_total} 误伤；CI {report.fpr_ci_low:.0%}–{report.fpr_ci_high:.0%}）",
            f"- **能力面：良性完成率 {report.benign_completed_rate:.0%} · 工具投放率 {report.tool_delivery_rate:.0%} · "
            f"Competence 综合分 {report.competence:.0%}**",
            f"- near-miss 集 FPR = {report.fpr_near_miss:.0%} · 基准耗时 {report.duration_ms} ms · 成本 {format_cost_usd(report.total_cost_usd)}（仅 ASR 矩阵）",
            "",
            "| 攻击向量 | OWASP ASI | 加固前成功率 | 加固后成功率 | 状态 |",
            "| --- | --- | --- | --- | --- |",
        ]
        if not report.matrix:
            lines.append("| — | — | — | — | 无可测向量 |")
        for row in report.matrix:
            if row.get("skipped"):
                lines.append(
                    f"| `{row['module']}` | {row['owasp_asi'] or '—'} | {MOCK_ONLY_NOTE} | {MOCK_ONLY_NOTE} | 跳过 |"
                )
                continue
            lines.append(
                f"| `{row['module']}` | {row['owasp_asi'] or '—'} "
                f"| {_rate_text(row['vulnerable_success_rate'], row['vulnerable_ci_low'], row['vulnerable_ci_high'], conf_pct)} "
                f"| {_rate_text(row['defended_success_rate'], row['defended_ci_low'], row['defended_ci_high'], conf_pct)} "
                f"| {'——' if row['defended_success_rate'] == 0 else '仍有绕过'} |"
            )
        lines.append("")
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------- #
# 纯 SVG 对比图（无第三方依赖，直接嵌入 Markdown/GitHub 可渲染）
# --------------------------------------------------------------------------- #
_WIDTH, _ROW_H, _LEFT = 900, 34, 240
_BEFORE = "#dc2626"  # 加固前（风险，语义红）
_AFTER = "#16a34a"  # 加固后（防线，语义绿）
_NEUTRAL = "#6b7280"
_FPR = "#d97706"  # FPR（可参考的琥珀）
_BAR_H = 12


def render_chart_svg(report: ModelSecurityReport) -> str:
    """把单个报告渲染成横向分组柱状图（每向量：加固前红 / 加固后绿 + FPR 小结），返回 SVG 字符串。"""
    rows = report.matrix
    top = 46
    height = top + _ROW_H * (len(rows) + 2)
    conf_pct = round(report.confidence * 100)
    svg = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {_WIDTH} {height}" '
        f'font-family="Segoe UI, -apple-system, Arial, sans-serif" width="100%">',
        f'<rect width="{_WIDTH}" height="{height}" fill="#ffffff"/>',
        f'<text x="{_LEFT}" y="24" font-size="15" font-weight="700" fill="#111827">'
        f'AgentShield 真实模型基准 · {report.model}',
        f'  （加固前 {report.mean_vulnerable_rate:.0%} → 加固后 {report.mean_defended_rate:.0%}，↓ {report.asr_reduction:.0%}）</text>',
        f'<text x="460" y="42" font-size="12" fill="#6b7280">'
        f'FPR(strict)={report.fpr:.0%} · Competence(能力)={report.competence:.0%} · 载荷 seed={report.seed} · {report.toolset}</text>',
    ]
    y = top + 6
    for row in rows:
        label = row["module"].replace("_", " ")[:22]
        svg.append(f'<text x="{_LEFT - 12}" y="{y + 3}" font-size="11" text-anchor="end" fill="#374151">{label}</text>')
        if row.get("skipped"):
            svg.append(f'<line x1="{_LEFT}" y1="{y + 5}" x2="{_LEFT + 180}" y2="{y + 5}" stroke="#d1d5db" stroke-width="2"/>')
            svg.append(f'<text x="{_LEFT + 188}" y="{y + 9}" font-size="10" fill="#9ca3af">skip</text>')
        else:
            v, dd = row["vulnerable_success_rate"], row["defended_success_rate"]
            vw, dw = int(v * 500), int(dd * 500)
            svg.append(f'<rect x="{_LEFT}" y="{y - _BAR_H + 2}" width="{vw}" height="{_BAR_H}" rx="2" fill="{_BEFORE}"/>')
            svg.append(f'<rect x="{_LEFT}" y="{y}" width="{dw}" height="{_BAR_H}" rx="2" fill="{_AFTER}"/>')
            svg.append(f'<text x="{_LEFT + vw + 6}" y="{y - 2}" font-size="10" fill="{_BEFORE}">{v:.0%}</text>')
            svg.append(f'<text x="{_LEFT + dw + 6}" y="{y + 12}" font-size="10" fill="{_AFTER}">{dd:.0%}</text>')
        y += _ROW_H
    svg.append(
        f'<text x="{_LEFT}" y="{y + 10}" font-size="10" fill="{_NEUTRAL}">■ 加固前(脆弱)攻击成功率</text>'
        f'<text x="{_LEFT + 160}" y="{y + 10}" font-size="10" fill="{_AFTER}">■ 加固后(有防御)攻击成功率</text>'
        f'<text x="{_LEFT + 420}" y="{y + 10}" font-size="10" fill="{_NEUTRAL}">加固后每条向量跑 {report.num_variants}×{report.runs} 用例（{conf_pct}% Wilson CI）</text>'
    )
    svg.append("</svg>")
    return "\n".join(svg)