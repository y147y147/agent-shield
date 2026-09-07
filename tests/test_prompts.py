"""A2：审计规划器 Plan 提示词。"""

from __future__ import annotations

import pytest

from agent_shield.attacks import list_attack_modules
from agent_shield.models import AuditPlan
from agent_shield.orchestrator.prompts import (
    REACT_SYSTEM_PROMPT,
    build_plan_system_prompt,
    build_plan_user_message,
    build_react_system_prompt,
    build_react_user_message,
    extract_json_object,
    parse_audit_plan,
)


def test_plan_system_prompt_contains_role_and_schema():
    prompt = build_plan_system_prompt(max_steps=5, allow_mock_only=True)
    assert "渗透测试指挥官" in prompt
    assert "AuditPlan" in prompt
    assert "只输出一个 JSON" in prompt
    assert "direct_injection" in prompt
    assert "indirect_injection" in prompt
    assert "`rogue_agent`" in prompt
    assert "硬上限 5" in prompt or "最多" in prompt


def test_plan_system_prompt_full_and_filter_mock():
    full = build_plan_system_prompt(full=True, allow_mock_only=False)
    assert "full 覆盖" in full
    assert "rogue_agent" not in full or "[mock_only]" not in full
    # allow_mock_only=False 时应排除 rogue_agent 模块行
    assert "- `rogue_agent`" not in full
    assert "禁止选用标注 [mock_only]" in full


def test_plan_system_prompt_lists_all_when_mock_allowed():
    prompt = build_plan_system_prompt(allow_mock_only=True)
    for name, _ in list_attack_modules():
        assert f"`{name}`" in prompt


def test_plan_user_message():
    msg = build_plan_user_message(task="搜索气候报告", compare_defense=True, max_steps=4)
    assert "搜索气候报告" in msg
    assert "无防护/有防护" in msg
    assert "AuditPlan JSON" in msg


def test_parse_audit_plan_plain_and_fenced():
    plain = '{"objective":"覆盖注入","steps":[{"module":"direct_injection","rationale":"先探"}]}'
    plan = parse_audit_plan(plain)
    assert isinstance(plan, AuditPlan)
    assert plan.steps[0].module == "direct_injection"

    fenced = """好的，计划如下：
```json
{
  "objective": "ASI-01",
  "steps": [
    {"module": "indirect_injection", "rationale": "绕过输入清洗", "num_variants": 4}
  ]
}
```
"""
    plan2 = parse_audit_plan(fenced)
    assert plan2.steps[0].num_variants == 4


def test_extract_json_rejects_empty():
    with pytest.raises(ValueError, match="空内容"):
        extract_json_object("   ")


def test_react_prompt_contains_rules():
    prompt = build_react_system_prompt(max_turns=10, max_bypass_per_module=5)
    assert "ReAct" in prompt
    assert "finish_audit" in prompt
    assert "最多尝试 5 次" in prompt
    assert "direct_injection" in prompt


def test_react_user_message():
    msg = build_react_user_message(task="测试任务", compare_defense=True)
    assert "测试任务" in msg
    assert "finish_audit" in msg


def test_react_prompt_skeleton_present():
    assert "ReAct" in REACT_SYSTEM_PROMPT
    assert "finish_audit" in REACT_SYSTEM_PROMPT
