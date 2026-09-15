"""零依赖指标注册表：输出 Prometheus 文本格式（``GET /metrics`` 直接抓取）。

支持的指标类型：Counter（只增）、Gauge（可设/增减）、Histogram（分桶 + sum + count）。
标签（label）在创建指标时声明，写入时必须完全匹配，避免拼错标签导致指标静默丢失。
"""

from __future__ import annotations

from typing import Iterable, Sequence

DEFAULT_BUCKETS: tuple[float, ...] = (
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
)


def _escape_label_value(value: object) -> str:
    text = str(value)
    return text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _format_labels(labels: dict[str, object]) -> str:
    if not labels:
        return ""
    body = ",".join(f'{key}="{_escape_label_value(value)}"' for key, value in sorted(labels.items()))
    return f"{{{body}}}"


def _format_bucket_labels(labels: dict[str, object], le: str) -> str:
    """直方图分桶标签：常规标签按字典序，``le`` 固定放最后（Prometheus 惯例）。"""
    body = ",".join(f'{key}="{_escape_label_value(value)}"' for key, value in sorted(labels.items()))
    prefix = f"{body}," if body else ""
    return f'{{{prefix}le="{le}"}}'


def _format_value(value: float) -> str:
    return f"{value:g}"


class _Metric:
    """指标基类：管理标签校验与序列（series）。"""

    kind = "untyped"

    def __init__(self, name: str, help_text: str, label_names: Sequence[str] = ()):
        self.name = name
        self.help_text = help_text
        self.label_names = tuple(label_names)

    def reset_values(self) -> None:
        """清空该指标的样本（保留注册信息，模块级引用仍然有效）。"""
        raise NotImplementedError

    def _validate(self, labels: dict[str, object]) -> dict[str, object]:
        if set(labels) != set(self.label_names):
            raise ValueError(
                f"指标 {self.name} 的标签不匹配：需要 {sorted(self.label_names)}，收到 {sorted(labels)}"
            )
        return labels

    def _key(self, labels: dict[str, object]) -> tuple[tuple[str, str], ...]:
        return tuple(sorted((key, str(value)) for key, value in self._validate(labels).items()))


class Counter(_Metric):
    """只增计数器（Prometheus 约定：名字以 ``_total`` 结尾）。"""

    kind = "counter"

    def __init__(self, name: str, help_text: str, label_names: Sequence[str] = ()):
        super().__init__(name, help_text, label_names)
        self._values: dict[tuple, float] = {}

    def inc(self, value: float = 1.0, **labels: object) -> None:
        key = self._key(labels)
        self._values[key] = self._values.get(key, 0.0) + float(value)

    def value(self, **labels: object) -> float:
        return self._values.get(self._key(labels), 0.0)

    def reset_values(self) -> None:
        self._values.clear()

    def render(self) -> list[str]:
        lines: list[str] = []
        for key, value in sorted(self._values.items()):
            lines.append(f"{self.name}{_format_labels(dict(key))} {_format_value(value)}")
        return lines


class Gauge(_Metric):
    """可增可减/可设值的仪表盘指标。"""

    kind = "gauge"

    def __init__(self, name: str, help_text: str, label_names: Sequence[str] = ()):
        super().__init__(name, help_text, label_names)
        self._values: dict[tuple, float] = {}

    def set(self, value: float, **labels: object) -> None:
        self._values[self._key(labels)] = float(value)

    def inc(self, value: float = 1.0, **labels: object) -> None:
        key = self._key(labels)
        self._values[key] = self._values.get(key, 0.0) + float(value)

    def dec(self, value: float = 1.0, **labels: object) -> None:
        self.inc(-value, **labels)

    def value(self, **labels: object) -> float:
        return self._values.get(self._key(labels), 0.0)

    def reset_values(self) -> None:
        self._values.clear()

    def render(self) -> list[str]:
        return [
            f"{self.name}{_format_labels(dict(key))} {_format_value(value)}"
            for key, value in sorted(self._values.items())
        ]


class Histogram(_Metric):
    """直方图：分桶计数 + ``_sum`` + ``_count``（用于延迟/开销等分布指标）。"""

    kind = "histogram"

    def __init__(
        self,
        name: str,
        help_text: str,
        label_names: Sequence[str] = (),
        buckets: Iterable[float] = DEFAULT_BUCKETS,
    ):
        super().__init__(name, help_text, label_names)
        self.buckets = tuple(sorted(float(b) for b in buckets))
        self._counts: dict[tuple, list[float]] = {}
        self._sums: dict[tuple, float] = {}

    def observe(self, value: float, **labels: object) -> None:
        key = self._key(labels)
        counts = self._counts.setdefault(key, [0.0] * (len(self.buckets) + 1))
        for index, bound in enumerate(self.buckets):
            if value <= bound:
                counts[index] += 1
                break
        else:
            counts[-1] += 1
        self._sums[key] = self._sums.get(key, 0.0) + float(value)

    def count(self, **labels: object) -> float:
        return sum(self._counts.get(self._key(labels), []))

    def sum(self, **labels: object) -> float:
        return self._sums.get(self._key(labels), 0.0)

    def reset_values(self) -> None:
        self._counts.clear()
        self._sums.clear()

    def render(self) -> list[str]:
        lines: list[str] = []
        for key in sorted(self._counts):
            base_labels = dict(key)
            counts = self._counts[key]
            cumulative = 0.0
            for index, bound in enumerate(self.buckets):
                cumulative += counts[index]
                lines.append(
                    f"{self.name}_bucket{_format_bucket_labels(base_labels, _format_value(bound))} "
                    f"{_format_value(cumulative)}"
                )
            cumulative += counts[-1]
            lines.append(
                f"{self.name}_bucket{_format_bucket_labels(base_labels, '+Inf')} {_format_value(cumulative)}"
            )
            lines.append(f"{self.name}_sum{_format_labels(base_labels)} {_format_value(self._sums.get(key, 0.0))}")
            lines.append(f"{self.name}_count{_format_labels(base_labels)} {_format_value(cumulative)}")
        return lines


class MetricsRegistry:
    """指标注册表：同名指标复用同一实例，``render()`` 输出 Prometheus 文本格式。"""

    def __init__(self) -> None:
        self._metrics: dict[str, _Metric] = {}

    def _get_or_create(self, metric: _Metric) -> _Metric:
        existing = self._metrics.get(metric.name)
        if existing is not None:
            if existing.kind != metric.kind or existing.label_names != metric.label_names:
                raise ValueError(f"指标 {metric.name} 已存在且类型/标签不一致")
            return existing
        self._metrics[metric.name] = metric
        return metric

    def counter(self, name: str, help_text: str, label_names: Sequence[str] = ()) -> Counter:
        return self._get_or_create(Counter(name, help_text, label_names))  # type: ignore[return-value]

    def gauge(self, name: str, help_text: str, label_names: Sequence[str] = ()) -> Gauge:
        return self._get_or_create(Gauge(name, help_text, label_names))  # type: ignore[return-value]

    def histogram(
        self,
        name: str,
        help_text: str,
        label_names: Sequence[str] = (),
        buckets: Iterable[float] = DEFAULT_BUCKETS,
    ) -> Histogram:
        return self._get_or_create(Histogram(name, help_text, label_names, buckets))  # type: ignore[return-value]

    def reset(self) -> None:
        """清空所有样本值，但保留指标注册（模块级引用如 ``TOOL_CALLS`` 仍然有效）。"""
        for metric in self._metrics.values():
            metric.reset_values()

    def render(self) -> str:
        """Prometheus exposition 文本（每个指标带 HELP/TYPE）。"""
        lines: list[str] = []
        for name in sorted(self._metrics):
            metric = self._metrics[name]
            lines.append(f"# HELP {name} {metric.help_text}")
            lines.append(f"# TYPE {name} {metric.kind}")
            lines.extend(metric.render())
        return "\n".join(lines) + "\n"


METRICS = MetricsRegistry()

# 全局指标（在各模块中被引用；名字与语义固定，便于 Grafana 面板复用）
TOOL_CALLS = METRICS.counter(
    "agentshield_tool_calls_total", "工具调用次数（按工具与处置结果）", ("tool", "decision")
)
GUARDRAIL_LATENCY = METRICS.histogram(
    "agentshield_guardrail_latency_seconds", "防护层决策耗时（秒，按工具）", ("tool",),
    buckets=(0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0),
)
POLICY_DECISIONS = METRICS.counter(
    "agentshield_policy_decisions_total", "策略引擎决策次数（按工具与结论）", ("tool", "decision")
)
INJECTION_FINDINGS = METRICS.counter(
    "agentshield_injection_findings_total", "注入检测命中次数（按信号）", ("signal",)
)
SANDBOX_RUNS = METRICS.counter(
    "agentshield_sandbox_runs_total", "沙箱命令执行结果（ok/denied/timeout/error）", ("outcome",)
)


def render_metrics() -> str:
    """渲染全局注册表（供 /metrics 端点使用）。"""
    return METRICS.render()


def reset_metrics() -> None:
    """清空指标（测试用）。"""
    METRICS.reset()
