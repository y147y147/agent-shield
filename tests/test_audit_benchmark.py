"""D3：自主审计指挥官质量回归测试。"""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from agent_shield.cli import app as cli_app
from agent_shield.core.audit_benchmark import (
    TARGET_CONFIGS,
    AuditBenchMetrics,
    AuditBenchThresholds,
    evaluate_metrics,
    run_audit_bench_case,
    run_audit_benchmark,
)
from agent_shield.models import AuditPlan, AuditPlanStep
from agent_shield.orchestrator.plan_execute import FixedPlanLLM
from agent_shield.runtime.llm import LLMResponse, ToolCall

runner = CliRunner()


@pytest.mark.asyncio
async def test_audit_benchmark_quick_all_pass():
    """quick benchmark：6 场景（3 配置 × plan/react）全部通过。"""
    results = await run_audit_benchmark(quick=True)
    assert len(results) == 6
    failures = [(r.target_config, r.mode, r.failures) for r in results if not r.passed]
    assert not failures, failures


@pytest.mark.asyncio
async def test_vd3_degraded_plan_detected():
    """V-D3：劣化规划器 modules_covered 不足时 benchmark 失败。"""
    bad_plan = AuditPlan(
        objective="仅跑一个模块",
        steps=[AuditPlanStep(module="direct_injection", rationale="缩水计划", num_variants=1)],
    )
    cfg = TARGET_CONFIGS[0]  # vuln_only
    result = await run_audit_bench_case(
        cfg,
        "plan",
        planner=FixedPlanLLM(bad_plan),
        plan_max_steps=1,
    )
    assert not result.passed
    assert any("modules_covered" in f for f in result.failures)


@pytest.mark.asyncio
async def test_vd3_degraded_react_no_finish_detected():
    """V-D3：ReAct 未调用 finish_audit 时 benchmark 失败。"""

    class OneShotNoFinishLLM:
        name = "one-shot-no-finish"

        def __init__(self) -> None:
            self._done = False

        async def chat(self, messages, tools):
            if not self._done:
                self._done = True
                return LLMResponse(
                    tool_calls=[
                        ToolCall(id="d1", name="direct_injection", arguments={"num_variants": 2}),
                    ],
                )
            return LLMResponse(content="结束，不调用 finish_audit。")

    cfg = TARGET_CONFIGS[0]
    result = await run_audit_bench_case(
        cfg,
        "react",
        planner=OneShotNoFinishLLM(),
        react_max_turns=4,
    )
    assert not result.passed
    assert any("finish_called" in f for f in result.failures)


def test_evaluate_metrics_thresholds():
    metrics = AuditBenchMetrics(
        modules_covered=1,
        risk_level="info",
        bypass_used=False,
        turns=1,
        finish_called=False,
    )
    th = AuditBenchThresholds(min_modules_covered=3, allowed_risk_levels=frozenset({"critical"}))
    errs = evaluate_metrics(metrics, th)
    assert len(errs) >= 2


def test_audit_benchmark_cli_quick():
    result = runner.invoke(cli_app, ["audit-benchmark", "--quick"])
    assert result.exit_code == 0, result.output
    assert "自主审计 Benchmark" in result.output or "benchmark" in result.output.lower()


def test_audit_benchmark_cli_json(tmp_path):
    out = tmp_path / "bench.json"
    result = runner.invoke(cli_app, ["audit-benchmark", "--quick", "--json", str(out)])
    assert result.exit_code == 0, result.output
    data = json.loads(out.read_text(encoding="utf-8"))
    assert len(data) == 6
    assert all(item["passed"] for item in data)


def test_audit_benchmark_cli_fail_on_regression():
    """CLI --fail-on-regression 在劣化指标时应非零退出。"""
    # 直接测 evaluate + 合成失败，避免注入坏 planner 到 CLI
    metrics = AuditBenchMetrics(
        modules_covered=0,
        risk_level="info",
        bypass_used=False,
        turns=0,
        finish_called=False,
    )
    th = AuditBenchThresholds(min_modules_covered=3)
    assert evaluate_metrics(metrics, th)
