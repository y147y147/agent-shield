"""E3：定时自主审计（cron 守护 / 单次触发）。"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any


def _parse_field(field: str, value: int, min_v: int, max_v: int) -> bool:
    if field == "*":
        return True
    for part in field.split(","):
        if "/" in part:
            base, step = part.split("/", 1)
            if base != "*":
                raise ValueError(f"步进字段仅支持 */n 形式: {field}")
            step_i = int(step)
            return value % step_i == 0
        if "-" in part:
            lo, hi = part.split("-", 1)
            if int(lo) <= value <= int(hi):
                return True
        elif int(part) == value:
            return True
    return False


def cron_matches(expr: str, when: datetime) -> bool:
    """5 段 cron：minute hour day month weekday（weekday 0=周一 … 6=周日，与 datetime.weekday 一致）。"""
    parts = expr.strip().split()
    if len(parts) != 5:
        raise ValueError(f"cron 须为 5 段: minute hour day month weekday，收到: {expr}")
    minute, hour, day, month, weekday = parts
    # datetime.weekday(): Monday=0
    return (
        _parse_field(minute, when.minute, 0, 59)
        and _parse_field(hour, when.hour, 0, 23)
        and _parse_field(day, when.day, 1, 31)
        and _parse_field(month, when.month, 1, 12)
        and _parse_field(weekday, when.weekday(), 0, 6)
    )


async def run_cron_loop(
    cron_expr: str,
    job: Callable[[], Any],
    *,
    poll_seconds: int = 60,
    on_tick: Callable[[datetime], None] | None = None,
) -> None:
    """每分钟检查 cron，匹配时执行 job（async 或 sync）。"""
    last_run_minute: str | None = None
    while True:
        now = datetime.now(UTC)
        if on_tick:
            on_tick(now)
        key = now.strftime("%Y-%m-%d %H:%M")
        if cron_matches(cron_expr, now) and key != last_run_minute:
            last_run_minute = key
            result = job()
            if asyncio.iscoroutine(result):
                await result
        await asyncio.sleep(poll_seconds)


def run_cron_once(cron_expr: str, when: datetime | None = None) -> bool:
    """检查当前时刻是否匹配 cron（不执行 job）。"""
    return cron_matches(cron_expr, when or datetime.now(UTC))
