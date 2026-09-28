"""多模型 benchmark：规格解析、单模型矩阵、聚合矩阵、成本列。"""

from __future__ import annotations

import json

from typer.testing import CliRunner

from agent_shield.cli import app
from agent_shield.core.benchmark import (
    ModelSpec,
    format_cost_usd,
    matrix_to_markdown,
    parse_model_specs,
    run_benchmark,
    run_benchmark_matrix_multi,
    run_model_matrix,
)

runner = CliRunner()


# --------------------------------------------------------------------------- #
# 规格解析
# --------------------------------------------------------------------------- #
def test_parse_model_specs_defaults_to_mock():
    specs = parse_model_specs()
    assert specs == [ModelSpec(label="mock", llm="mock")]


def test_parse_model_specs_single_model_flag():
    specs = parse_model_specs(llm="openai-compat", model="deepseek-chat", base_url="https://x/v1")
    assert len(specs) == 1
    assert specs[0].label == "deepseek-chat"
    assert specs[0].llm == "openai-compat"
    assert specs[0].model == "deepseek-chat"
    assert specs[0].base_url == "https://x/v1"


def test_parse_model_specs_multi_mixed_mock_and_real():
    specs = parse_model_specs(models="mock,deepseek=deepseek-chat")
    assert len(specs) == 2
    assert specs[0].llm == "mock"
    assert specs[1] == ModelSpec(
        label="deepseek", llm="openai-compat", model="deepseek-chat", base_url=None, api_key=None
    )


def test_parse_model_specs_dedupes_labels():
    specs = parse_model_specs(models="a=mock,a=mock,b=mock")
    assert [s.label for s in specs] == ["a", "b"]


def test_parse_model_specs_rejects_empty():
    import pytest

    with pytest.raises(ValueError):
        parse_model_specs(models=" , , ")


# --------------------------------------------------------------------------- #
# 用量与成本列（Mock 离线，全量模块但每模块 1 变体以控制耗时）
# --------------------------------------------------------------------------- #
async def test_run_benchmark_rows_carry_usage_fields():
    rows = await run_benchmark(llm="mock", defense=False, num_variants=1, runs=1)
    assert rows
    for row in rows:
        for key in ("prompt_tokens", "completion_tokens", "total_tokens", "estimated_cost_usd", "llm_calls"):
            assert key in row, f"行缺少用量字段 {key}"
        assert row["total_tokens"] >= row["prompt_tokens"]
        assert row["llm_calls"] >= 1  # 每轮至少一次 LLM 调用


def test_format_cost_usd_zero_and_nonzero():
    assert format_cost_usd(0.0) == "$0"
    assert format_cost_usd(0.00009).startswith("$")
    assert format_cost_usd(1.5) == "$1.5"


async def test_run_model_matrix_marks_mock_only_skipped_for_real_llm():
    # openai-compat 无真实服务时 run 会产生 agent error，但 mock_only 置 skipped 与否只看规格
    rows = await run_model_matrix(
        ModelSpec(label="unreachable", llm="openai-compat", model="no-such-model", base_url="http://127.0.0.1:9/v1"),
        num_variants=1,
        runs=1,
    )
    assert rows
    rogue_rows = [r for r in rows if r["module"] == "rogue_agent"]
    assert len(rogue_rows) == 1
    assert rogue_rows[0]["skipped"] is True
    assert rogue_rows[0]["model"] == "unreachable"
    normal = [r for r in rows if r["module"] != "rogue_agent"]
    assert all(r["skipped"] is False for r in normal)


async def test_run_benchmark_matrix_multi_mock_two_labels():
    flat = await run_benchmark_matrix_multi(
        [ModelSpec(label="m1", llm="mock"), ModelSpec(label="m2", llm="mock")],
        num_variants=1,
        runs=1,
    )
    assert flat
    labels = {r["model"] for r in flat}
    assert labels == {"m1", "m2"}
    for row in flat:
        assert row["llm"] == "mock"
        assert "vulnerable_total_tokens" in row
        assert "defended_estimated_cost_usd" in row


async def test_multi_markdown_has_cost_columns_and_skip_row():
    flat = await run_benchmark_matrix_multi([ModelSpec(label="mock", llm="mock")], num_variants=1, runs=1)
    md = matrix_to_markdown(flat)
    assert "多模型" in md
    assert "Tokens 前/后" in md
    assert "费用 USD" in md


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def test_cli_benchmark_single_model_cost_columns(tmp_path):
    json_path = tmp_path / "bench.json"
    md_path = tmp_path / "bench.md"
    result = runner.invoke(
        app, ["benchmark", "--runs", "1", "-n", "1", "--json", str(json_path), "--markdown", str(md_path)]
    )
    assert result.exit_code == 0, result.output
    assert "Tokens" in result.output
    assert "USD" in result.output
    matrix = json.loads(json_path.read_text(encoding="utf-8"))
    assert matrix and all("vulnerable_total_tokens" in r for r in matrix)
    md = md_path.read_text(encoding="utf-8")
    assert "Tokens 前/后" in md


def test_cli_benchmark_multi_models_mock_labels(tmp_path):
    json_path = tmp_path / "bench2.json"
    result = runner.invoke(
        app, ["benchmark", "--models", "m1=mock,m2=mock", "-n", "1", "--json", str(json_path)]
    )
    assert result.exit_code == 0, result.output
    assert "m1" in result.output and "m2" in result.output
    matrix = json.loads(json_path.read_text(encoding="utf-8"))
    labels = {r["model"] for r in matrix}
    assert labels == {"m1", "m2"}
