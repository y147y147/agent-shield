"""Phase D1：MITM Proxy 流量分析 → 审计指挥官狩猎建议。"""

from __future__ import annotations

import json
from collections import Counter
from typing import Any

from agent_shield.proxy.audit import AuditStore

# 检测信号 / 动作 → 建议攻击模块（红队狩猎启发式）
_SIGNAL_MODULE_MAP: list[tuple[tuple[str, ...], str]] = [
    (("指令块标记", "忽略先前指令", "伪系统消息", "角色劫持"), "direct_injection"),
    (("命令执行指令", "破坏性命令", "编码混淆指令"), "unexpected_code_execution"),
    (("指令块标记", "忽略先前指令"), "indirect_injection"),
]

_ACTION_MODULE_MAP: dict[str, list[str]] = {
    "block": ["indirect_injection", "direct_injection"],
    "sanitize": ["indirect_injection"],
    "mock": ["indirect_injection"],
}


def _parse_detections(raw: Any) -> list[dict[str, Any]]:
    if isinstance(raw, list):
        return [d for d in raw if isinstance(d, dict)]
    if isinstance(raw, str):
        try:
            data = json.loads(raw)
            return data if isinstance(data, list) else []
        except json.JSONDecodeError:
            return []
    return []


def _suggest_modules(events: list[dict[str, Any]]) -> list[str]:
    suggested: list[str] = []
    seen: set[str] = set()

    def add(mod: str) -> None:
        if mod not in seen:
            seen.add(mod)
            suggested.append(mod)

    for event in events:
        action = str(event.get("action") or "")
        for mod in _ACTION_MODULE_MAP.get(action, []):
            add(mod)

        for det in _parse_detections(event.get("detections")):
            signal = str(det.get("signal") or "")
            snippet = str(det.get("snippet") or "").lower()
            for keywords, mod in _SIGNAL_MODULE_MAP:
                if any(k in signal for k in keywords):
                    add(mod)
            if "instruction:" in snippet or "injection" in snippet:
                add("indirect_injection")
            if "run_command" in snippet or "write_file" in snippet:
                add("privilege_escalation")

    if not suggested and events:
        add("direct_injection")
        add("indirect_injection")
    return suggested


def analyze_proxy_events(
    store: AuditStore,
    *,
    limit: int = 100,
    since_ts: float | None = None,
) -> dict[str, Any]:
    """分析 Proxy / 运行时审计事件，输出狩猎建议（供 analyze_proxy_events 元工具）。"""
    events = store.list_events(limit=limit, since_ts=since_ts)
    action_counts = dict(Counter(str(e.get("action") or "?") for e in events))

    signal_counts: Counter[str] = Counter()
    suspicious: list[dict[str, Any]] = []
    for event in events:
        dets = _parse_detections(event.get("detections"))
        if not dets and event.get("action") in {"block", "sanitize"}:
            suspicious.append(
                {
                    "ts": event.get("ts"),
                    "action": event.get("action"),
                    "model": event.get("model"),
                    "detail": event.get("detail"),
                    "reason": "防护动作触发但 detections 为空",
                }
            )
        for det in dets:
            sig = str(det.get("signal") or "unknown")
            signal_counts[sig] += 1
            if len(suspicious) < 8:
                suspicious.append(
                    {
                        "ts": event.get("ts"),
                        "action": event.get("action"),
                        "model": event.get("model"),
                        "signal": sig,
                        "severity": det.get("severity"),
                        "snippet": det.get("snippet"),
                    }
                )

    suggested = _suggest_modules(events)
    models = dict(Counter(str(e.get("model") or "?") for e in events))

    return {
        "tool": "analyze_proxy_events",
        "total_events": len(events),
        "action_counts": action_counts,
        "model_counts": models,
        "detection_summary": [
            {"signal": sig, "count": cnt} for sig, cnt in signal_counts.most_common(12)
        ],
        "suspicious_patterns": suspicious,
        "suggested_modules": suggested,
        "hunting_hint": (
            "优先验证 suggested_modules 中的向量；注入类信号优先 indirect_injection / direct_injection。"
            if suggested
            else "暂无显著可疑流量；可先 list_coverage 再选代表性模块。"
        ),
    }
