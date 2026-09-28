"""真实模型安全基准（model_benchmark）测试：离线 Mock 跑通、可复现、报告与图、CLI 端到端。

这些用例刻意不联网（llm=mock），保证 CI 绿灯；真实模型只用于最终对比，不在此断言。
"""

from __future__ import annotations

import json

from typer.testing import CliRunner

from agent_shield.cli import app
from agent_shield.core.benchmark import ModelSpec
from agent_shield.core.model_benchmark import (
    ModelSecurityReport,
    payload_library_signature,
    render_chart_svg,
    reports_to_json,
    reports_to_markdown,
    run_model_security_benchmark,
    run_model_security_benchmark_many,
)

runner = CliRunner()


async def test_mock_benchmark_reproducible_with_same_seed():
    """同一 (model, seed, 载荷版本, 工具带) 下两次结果的确定性字段完全一致（可复现门禁，耗时排除）。"""
    spec = ModelSpec(label="mock", llm="mock")
    a = await run_model_security_benchmark(spec, num_variants=1, runs=1, seed=42)
    b = await run_model_security_benchmark(spec, num_variants=1, runs=1, seed=42)

    def _stable(report: ModelSecurityReport) -> dict:
        data = report.to_dict()
        for row in data["matrix"]:
            row.pop("model_elapsed_ms", None)
            row.pop("duration_ms", None)
            row.pop("vulnerable_duration_ms", None)
            row.pop("defended_duration_ms", None)
        data.pop("duration_ms", None)
        data["matrix"].sort(key=lambda r: r["module"])
        return data

    assert _stable(a) == _stable(b)
    assert a.seed == 42
    assert a.payload_signature  # 记录载荷库版本签名


async def test_mock_benchmark_structure_and_derived_metrics():
    report = await run_model_security_benchmark(ModelSpec(label="mock", llm="mock"), num_variants=1, runs=1)
    assert report.matrix, "矩阵不应为空（全量攻击向量）"
    rows = report.measurable
    assert rows, "应至少有一个可测向量（mock 下 rogue_agent 也可测）"
    # 派生指标落在 [0,1] 且加固后应不高于加固前（mock 防护必然生效）
    assert 0.0 <= report.mean_vulnerable_rate <= 1.0
    assert 0.0 <= report.mean_defended_rate <= 1.0
    assert report.mean_defended_rate <= report.mean_vulnerable_rate + 1e-9
    assert report.asr_reduction >= 0.0
    # FPR 来自良性对照集（含 payload control）：应无量且已被统计
    assert report.fpr_total > 0


async def test_mock_benchmark_json_and_markdown():
    report = await run_model_security_benchmark(ModelSpec(label="mock", llm="mock"), num_variants=1, runs=1, seed=7)
    data = json.loads(reports_to_json([report]))
    assert data and data[0]["model"] == "mock"
    assert {"seed", "asr_reduction", "fpr", "total_cost_usd", "matrix"} <= set(data[0])
    md = reports_to_markdown([report])
    assert "真实模型安全基准" in md
    assert "加固前" in md and "加固后" in md and "FPR" in md
    assert report.model in md


def test_render_chart_svg_outputs_valid_markup():
    report = ModelSecurityReport(
        model="mock",
        llm="mock",
        model_name=None,
        task="t",
        seed=1,
        runs=1,
        num_variants=3,
        confidence=0.95,
        toolset="office-1",
        payload_signature="s",
        matrix=[
            {
                "module": "direct_injection",
                "owasp_asi": "ASI-01",
                "vulnerable_success_rate": 1.0,
                "vulnerable_ci_low": 0.0,
                "vulnerable_ci_high": 1.0,
                "defended_success_rate": 0.0,
                "defended_ci_low": 0.0,
                "defended_ci_high": 0.0,
                "skipped": False,
            }
        ],
        fpr=0.0,
        fpr_total=10,
        fpr_flagged=0,
        fpr_ci_low=0.0,
        fpr_ci_high=0.0,
        fpr_near_miss=0.0,
    )
    svg = render_chart_svg(report)
    assert svg.startswith("<svg")
    assert svg.rstrip().endswith("</svg>")
    assert "direct injection" in svg  # 下划线渲染为空格
    assert "direct_injection" in report.matrix[0]["module"]
    assert "加固后" in svg
    assert "FPR" in svg


async def test_many_two_labels():
    reports = await run_model_security_benchmark_many(
        [ModelSpec(label="m1", llm="mock"), ModelSpec(label="m2", llm="mock")],
        num_variants=1,
        runs=1,
    )
    assert [r.model for r in reports] == ["m1", "m2"]
    assert all(r.matrix for r in reports)


def test_payload_library_signature_nonempty():
    sig = payload_library_signature()
    assert "families" in sig or "(payload-lib" in sig


def test_cli_model_benchmark_mock_end_to_end(tmp_path):
    json_path = tmp_path / "model-bench.json"
    md_path = tmp_path / "model-bench.md"
    chart_dir = tmp_path / "charts"
    result = runner.invoke(
        app,
        [
            "model-benchmark",
            "--runs", "1",
            "-n", "1",
            "--seed", "42",
            "--json", str(json_path),
            "--markdown", str(md_path),
            "--chart-dir", str(chart_dir),
        ],
    )
    assert result.exit_code == 0, result.output
    assert "真实模型安全基准" in result.output
    assert json_path.exists() and md_path.exists()
    data = json.loads(json_path.read_text(encoding="utf-8"))
    assert data and "asr_reduction" in data[0]
    assert list(chart_dir.glob("chart-*.svg")), "应产出对比图"