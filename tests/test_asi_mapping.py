"""ASI 映射测试：12 个攻击模块必须覆盖 OWASP Agentic Top 10（2026）全部 10 类风险。

官方清单（2025-12-09 发布）：
ASI-01 Agent Goal Hijack / ASI-02 Tool Misuse / ASI-03 Identity & Privilege Abuse /
ASI-04 Agentic Supply Chain / ASI-05 Unexpected Code Execution / ASI-06 Memory & Context
Poisoning / ASI-07 Insecure Inter-Agent Communication / ASI-08 Cascading Failures /
ASI-09 Human-Agent Trust Exploitation / ASI-10 Rogue Agents
"""

from agent_shield.attacks import list_attack_modules
from agent_shield.attacks.registry import get_attack_module

# 每个模块应映射到的官方 ASI（防止回归到旧版/错误映射）
EXPECTED_MAPPING = {
    "indirect_injection": "ASI-01",
    "direct_injection": "ASI-01",
    "data_exfiltration": "ASI-02",
    "privilege_escalation": "ASI-03",
    "tool_poisoning": "ASI-04",
    "mcp_poisoning": "ASI-04",
    "unexpected_code_execution": "ASI-05",
    "memory_poisoning": "ASI-06",
    "inter_agent_communication": "ASI-07",
    "resource_abuse": "ASI-08",
    "human_trust_exploitation": "ASI-09",
    "rogue_agent": "ASI-10",
}


def test_all_modules_have_correct_asi_mapping():
    registered = {name for name, _ in list_attack_modules()}
    assert registered == set(EXPECTED_MAPPING)
    for name, expected in EXPECTED_MAPPING.items():
        assert get_attack_module(name).owasp_asi == expected, f"{name} 应映射 {expected}"


def test_asi_coverage_all_ten_categories():
    """去重后必须覆盖 ASI-01 ~ ASI-10 全部 10 类。"""
    covered = {get_attack_module(name).owasp_asi for name, _ in list_attack_modules()}
    assert covered == {f"ASI-{i:02d}" for i in range(1, 11)}


def test_each_module_has_name_and_description():
    for name, desc in list_attack_modules():
        assert name and desc
        assert get_attack_module(name).name == name
