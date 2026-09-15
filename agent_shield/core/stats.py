"""统计工具：比例指标的置信区间（Wilson score interval）。

为什么需要它：攻击成功率是"n 次试验里的比例"，单次运行给出的 100% 或 0% 没有误差概念。
Wilson 区间在小样本（n 小）与极端比例（0 / 1）下都比正态近似更稳，因此用于把
"成功率"升级为"成功率 + 置信区间"。

用法::

    est = rate_estimate(successes=3, total=3)
    est.rate      # 1.0
    est.ci_low    # ≈ 0.4385（95% 置信下界）
    format_rate(est)   # '100% (95% CI 44%–100%)'
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from statistics import NormalDist

DEFAULT_CONFIDENCE = 0.95


@dataclass(frozen=True)
class RateEstimate:
    """比例估计：点估计 + 双侧置信区间。"""

    successes: int
    total: int
    rate: float
    ci_low: float
    ci_high: float
    confidence: float = DEFAULT_CONFIDENCE

    @property
    def width(self) -> float:
        """置信区间宽度（越小说明样本越充分）。"""
        return self.ci_high - self.ci_low


def _z_for(confidence: float) -> float:
    """置信水平 → 标准正态分位数（双侧）。"""
    if not 0.0 < confidence < 1.0:
        raise ValueError(f"confidence 必须在 (0, 1) 内，收到: {confidence!r}")
    return NormalDist().inv_cdf(1.0 - (1.0 - confidence) / 2.0)


def wilson_interval(
    successes: int,
    total: int,
    confidence: float = DEFAULT_CONFIDENCE,
) -> tuple[float, float]:
    """Wilson score 置信区间；``total == 0`` 时返回 ``(0.0, 0.0)``。"""
    if total < 0 or successes < 0:
        raise ValueError("successes/total 不能为负数")
    if successes > total:
        raise ValueError(f"successes({successes}) 不能大于 total({total})")
    if total == 0:
        return 0.0, 0.0

    z = _z_for(confidence)
    n = float(total)
    p = successes / n
    z2 = z * z
    denominator = 1.0 + z2 / n
    center = (p + z2 / (2 * n)) / denominator
    margin = (z / denominator) * math.sqrt(p * (1 - p) / n + z2 / (4 * n * n))
    return max(0.0, center - margin), min(1.0, center + margin)


def rate_estimate(
    successes: int,
    total: int,
    confidence: float = DEFAULT_CONFIDENCE,
) -> RateEstimate:
    """构造比例估计（点估计 + 置信区间）。"""
    low, high = wilson_interval(successes, total, confidence)
    rate = successes / total if total else 0.0
    return RateEstimate(
        successes=successes,
        total=total,
        rate=rate,
        ci_low=low,
        ci_high=high,
        confidence=confidence,
    )


def format_rate(estimate: RateEstimate, *, digits: int = 0) -> str:
    """人类可读：``100% (95% CI 44%–100%)``。"""
    ci = round(estimate.confidence * 100)
    return (
        f"{estimate.rate:.{digits}%} "
        f"({ci}% CI {estimate.ci_low:.{digits}%}–{estimate.ci_high:.{digits}%})"
    )
