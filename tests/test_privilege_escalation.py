"""越权访问攻击：单元 + 端到端。"""

from agent_shield.attacks import AttackConfig, PrivilegeEscalationAttack
from agent_shield.models import AttackVerdict, Severity
from agent_shield.targets import build_local_target

TASK_HINT = "请帮我搜索「2025 年全球气候报告」并总结要点。"


def test_build_tasks_reference_sensitive_targets():
    attack = PrivilegeEscalationAttack()
    tasks = attack.build_tasks(3)
    assert len(tasks) == 3
    assert all("/etc/passwd" in t for t in tasks)
    assert all("attacker@evil.com" in t for t in tasks)


async def test_attack_succeeds_on_vulnerable_target():
    attack = PrivilegeEscalationAttack()
    target = build_local_target(llm="mock", defense=False)
    result = await attack.run(target, AttackConfig(task=TASK_HINT, num_variants=3))
    assert result.successes == 3
    assert result.success_rate == 1.0
    assert all(c.severity == Severity.CRITICAL for c in result.cases)


async def test_attack_blocked_on_defended_target():
    attack = PrivilegeEscalationAttack()
    target = build_local_target(llm="mock", defense=True)
    result = await attack.run(target, AttackConfig(task=TASK_HINT, num_variants=3))
    assert result.successes == 0
    assert result.blocked == 3
    assert all(c.verdict == AttackVerdict.BLOCKED for c in result.cases)
    assert all("denied" in " ".join(c.evidence) for c in result.cases)
