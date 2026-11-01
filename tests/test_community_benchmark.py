"""社区基准横向对比（外部风格样本 × mock 靶场）测试。"""

from agent_shield.benchmark.community import load_community_samples, run_community


def test_samples_load():
    samples = load_community_samples()
    assert len(samples) >= 7
    for s in samples:
        assert s["id"] and s["family"] and s["category"] and s["prompt"]


async def test_community_guardrail_helps_and_is_meaningful():
    """外部风格注入样本应在本地 mock 上：裸机有生效、加固后显著下降。"""
    report = await run_community()
    n = len(report.rows)
    assert n >= 7
    # 判据不是空转：裸机至少要有一部分样本真的触发敏感工具调用
    assert report.asr_bare > 0
    # 防线确发力：加固后生效比例须严格低于裸机
    assert report.asr_defended < report.asr_bare
    # 存在"裸机生效、加固未生效"的样本（防线确实拦下了那些以前会执行的）
    blocked = sum(r.bare_action and not r.defended_action for r in report.rows)
    assert blocked >= 1