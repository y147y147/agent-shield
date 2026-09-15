"""统计模块测试：Wilson 置信区间的数学正确性与边界行为。"""

import pytest

from agent_shield.core.stats import (
    DEFAULT_CONFIDENCE,
    RateEstimate,
    format_rate,
    rate_estimate,
    wilson_interval,
)


def test_default_confidence_is_95_percent():
    assert DEFAULT_CONFIDENCE == 0.95


def test_wilson_matches_known_values():
    """经典取值：n=100, p=0.5 → 95% CI ≈ (0.4038, 0.5962)。"""
    low, high = wilson_interval(50, 100)
    assert low == pytest.approx(0.4038, abs=5e-4)
    assert high == pytest.approx(0.5962, abs=5e-4)


def test_wilson_extreme_proportions_stay_in_range():
    """极端比例（0 / 全成功）下区间不越界，这是 Wilson 相对正态近似的优势。"""
    low, high = wilson_interval(0, 3)
    assert low == 0.0
    assert high == pytest.approx(0.5615, abs=5e-4)

    low2, high2 = wilson_interval(3, 3)
    assert low2 == pytest.approx(0.4385, abs=5e-4)
    assert high2 == 1.0

    # 任何输入都不越界
    for successes, total in [(0, 1), (1, 1), (0, 10), (10, 10), (1, 3)]:
        low_i, high_i = wilson_interval(successes, total)
        assert 0.0 <= low_i <= high_i <= 1.0


def test_wilson_zero_samples_returns_zero_interval():
    assert wilson_interval(0, 0) == (0.0, 0.0)


def test_wilson_interval_narrows_with_more_samples():
    """样本越多，区间越窄：3 次 vs 300 次（同为 100% 成功率）。"""
    narrow = wilson_interval(300, 300)
    wide = wilson_interval(3, 3)
    assert (narrow[1] - narrow[0]) < (wide[1] - wide[0])


def test_higher_confidence_gives_wider_interval():
    low90, high90 = wilson_interval(5, 10, confidence=0.90)
    low99, high99 = wilson_interval(5, 10, confidence=0.99)
    assert (low99, high99) != (low90, high90)
    assert low99 < low90 and high99 > high90


def test_wilson_rejects_invalid_input():
    with pytest.raises(ValueError):
        wilson_interval(3, 2)
    with pytest.raises(ValueError):
        wilson_interval(-1, 2)
    with pytest.raises(ValueError):
        wilson_interval(1, 2, confidence=1.5)


def test_rate_estimate_fields_and_width():
    est = rate_estimate(3, 3)
    assert isinstance(est, RateEstimate)
    assert est.successes == 3 and est.total == 3
    assert est.rate == 1.0
    assert est.ci_low < est.rate <= est.ci_high
    assert est.width == pytest.approx(est.ci_high - est.ci_low)
    assert rate_estimate(0, 0).rate == 0.0


def test_format_rate_is_human_readable():
    text = format_rate(rate_estimate(3, 3))
    assert text.startswith("100%")
    assert "95% CI" in text
    assert "44%" in text and "100%" in text
