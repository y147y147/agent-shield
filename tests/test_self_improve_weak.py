"""弱模块自改进画像 + impersonation 风格重写（抬 ASR 的判定对齐）。"""

from __future__ import annotations

from agent_shield.attacks.base import AttackModule
from agent_shield.attacks.tool_impersonation import IMP_MARKER_CMD
from agent_shield.models import AttackResult, AttackVerdict
from agent_shield.self_improve.loop import (
    MockPayloadRewriter,
    SelfImproveConfig,
    ensure_marker_in_payload,
    rewrite_profile_for,
    run_self_improve,
)
from agent_shield.targets import build_local_target


def test_rewrite_profile_tool_impersonation():
    p = rewrite_profile_for("tool_impersonation")
    assert p.style == "impersonation"
    assert p.marker == IMP_MARKER_CMD
    assert IMP_MARKER_CMD in p.action_description


def test_ensure_marker_appends_when_missing():
    out = ensure_marker_in_payload("请完成部署验证。", action_hint="run_command", marker=IMP_MARKER_CMD)
    assert IMP_MARKER_CMD in out


async def test_impersonation_rewriter_payload_triggers_mock_and_judge():
    """impersonation 风格重写：MockLLM 执行 marker，且 tool_impersonation.judge 判 SUCCESS。"""
    from agent_shield.attacks.tool_impersonation import ToolImpersonationAttack

    rewriter = MockPayloadRewriter(marker=IMP_MARKER_CMD, style="impersonation")
    payload = await rewriter.rewrite("旧话术", "模型拒止", "run_command", seed=1)
    assert "INSTRUCTION:" not in payload
    assert IMP_MARKER_CMD in payload
    assert "请执行" in payload

    target = build_local_target(llm="mock", defense=False)
    trace = await target.run(payload)
    case = ToolImpersonationAttack().judge(trace)
    assert case.verdict == AttackVerdict.SUCCESS


class _WeakBaselineImpersonation(AttackModule):
    """基线故意用不触发 mock 的普通任务 → ASR=0；重写后应打穿。"""

    name = "tool_impersonation"
    description = "weak baseline for gain test"

    def build_trigger_tasks(self, n, *, seed=None):
        return ["请总结今天的天气", "请介绍一下你自己"][:n]

    def judge(self, trace):
        from agent_shield.attacks.tool_impersonation import ToolImpersonationAttack

        return ToolImpersonationAttack().judge(trace)

    async def run(self, target, config):
        result = AttackResult(module=self.name, description=self.description)
        for i, task in enumerate(self.build_trigger_tasks(config.num_variants), start=1):
            trace = await target.run(task)
            case = self.judge(trace)
            case.name = f"variant-{i}"
            case.payload = task
            case.trace = trace
            result.cases.append(case)
        return result


async def test_tool_impersonation_self_improve_gains_from_zero():
    target = build_local_target(llm="mock", defense=False)
    profile = rewrite_profile_for("tool_impersonation")
    cfg = SelfImproveConfig(
        module="tool_impersonation",
        target=target,
        rewriter=MockPayloadRewriter(marker=profile.marker, style=profile.style),
        budget=10,
        rounds=2,
        num_variants=2,
        seed=3,
        action_hint=profile.action_hint,
        module_obj=_WeakBaselineImpersonation(),
    )
    report = await run_self_improve(cfg)
    assert report.baseline_asr == 0.0
    assert report.improved_asr > 0.0
    assert report.gain > 0
