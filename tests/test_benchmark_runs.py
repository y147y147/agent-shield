"""多轮基准评测测试：轮次聚合、置信区间字段、Markdown/CLI 输出。"""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from agent_shield.cli import app
from agent_shield.core.benchmark import (
    format_matrix_rate,
    matrix_to_markdown,
    run_benchmark,
    run_benchmark_matrix,
)

runner = CliRunner()


# --------------------------------------------------------------------------- #
# 轮次聚合
# --------------------------------------------------------------------------- #
async def test_run_benchmark_aggregates_multiple_runs():
    rows = await run_benchmark(llm="mock", defense=False, num_variants=2, runs=3)
    assert rows, "应至少有一个攻击模块"
    for row in rows:
        assert row["runs"] == 3
        assert row["total"] == 6, "2 个变体 × 3 轮 = 6 个用例"
        assert row["successes"] == 6
        assert row["success_rate"] == 1.0
        assert row["ci_high"] == 1.0
        assert 0.0 < row["ci_low"] < 1.0, "小样本下 100% 的下界应显著低于 1"
        assert row["confidence"] == 0.95


async def test_run_benchmark_defended_reports_zero_with_ci():
    rows = await run_benchmark(llm="mock", defense=True, num_variants=2, runs=3)
    for row in rows:
        assert row["success_rate"] == 0.0
        assert row["ci_low"] == 0.0
        assert 0.0 < row["ci_high"] < 1.0, "0/6 的置信上界应大于 0（不宜断言「绝不可能」）"


async def test_run_benchmark_single_run_keeps_legacy_shape():
    """默认 runs=1 时保持旧字段语义，避免破坏既有调用方。"""
    rows = await run_benchmark(llm="mock", defense=False, num_variants=2)
    assert all(row["runs"] == 1 and row["total"] == 2 for row in rows)
    assert all(row["success_rate"] == 1.0 for row in rows)


async def test_run_benchmark_rejects_invalid_runs():
    with pytest.raises(ValueError):
        await run_benchmark(llm="mock", runs=0)


# --------------------------------------------------------------------------- #
# 矩阵与渲染
# --------------------------------------------------------------------------- #
async def test_matrix_contains_confidence_columns():
    matrix = await run_benchmark_matrix(llm="mock", num_variants=2, runs=2)
    assert len(matrix) >= 7
    for row in matrix:
        assert row["vulnerable_success_rate"] == 1.0
        assert row["defended_success_rate"] == 0.0
        for key in (
            "vulnerable_ci_low",
            "vulnerable_ci_high",
            "defended_ci_low",
            "defended_ci_high",
            "vulnerable_cases",
            "defended_cases",
            "runs",
            "confidence",
        ):
            assert key in row, f"矩阵行缺少字段 {key}"
        assert row["vulnerable_cases"] == row["defended_cases"] == 4


async def test_matrix_markdown_documents_sample_size_and_ci():
    matrix = await run_benchmark_matrix(llm="mock", num_variants=2, runs=2)
    md = matrix_to_markdown(matrix)
    assert "AgentShield 基准评测" in md
    assert "2 轮 × 2 个载荷变体" in md
    assert "Wilson" in md
    assert "95% CI" in md


def test_format_matrix_rate_renders_ci():
    row = {
        "vulnerable_success_rate": 1.0,
        "vulnerable_ci_low": 0.4385,
        "vulnerable_ci_high": 1.0,
        "confidence": 0.95,
    }
    text = format_matrix_rate(row, "vulnerable")
    assert text == "100% (95% CI 44%–100%)"


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def test_cli_benchmark_runs_and_exports(tmp_path):
    json_path = tmp_path / "bench.json"
    md_path = tmp_path / "bench.md"
    result = runner.invoke(
        app,
        ["benchmark", "--runs", "2", "-n", "2", "--json", str(json_path), "--markdown", str(md_path)],
    )
    assert result.exit_code == 0, result.output
    assert "95% CI" in result.output

    matrix = json.loads(json_path.read_text(encoding="utf-8"))
    assert matrix and all(row["runs"] == 2 for row in matrix)
    assert "Wilson" in md_path.read_text(encoding="utf-8")
