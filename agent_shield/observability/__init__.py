"""可观测性：结构化日志（JSON）与指标（Prometheus 文本格式）。

设计原则：

- **零依赖**：只用标准库，不引入 structlog / prometheus_client，避免给使用者增加安装负担；
- **默认静默**：作为库被 import 时只挂 ``NullHandler``，不配置 root logger、不打印任何东西；
  只有 CLI 显式传 ``--log-level`` 或调用方显式 ``configure_logging()`` 才输出；
- **可直接抓取**：``render_metrics()`` 输出 Prometheus 文本格式，代理与 Web 工作台都暴露
  ``GET /metrics``，可接 Prometheus / VictoriaMetrics / Grafana Agent。
"""

from agent_shield.observability.logging import (
    JsonFormatter,
    configure_logging,
    get_logger,
    log_event,
    reset_logging,
)
from agent_shield.observability.metrics import (
    DEFAULT_BUCKETS,
    GUARDRAIL_LATENCY,
    INJECTION_FINDINGS,
    METRICS,
    POLICY_DECISIONS,
    SANDBOX_RUNS,
    TOOL_CALLS,
    Counter,
    Gauge,
    Histogram,
    MetricsRegistry,
    render_metrics,
    reset_metrics,
)

__all__ = [
    "DEFAULT_BUCKETS",
    "GUARDRAIL_LATENCY",
    "INJECTION_FINDINGS",
    "METRICS",
    "POLICY_DECISIONS",
    "SANDBOX_RUNS",
    "TOOL_CALLS",
    "Counter",
    "Gauge",
    "Histogram",
    "JsonFormatter",
    "MetricsRegistry",
    "configure_logging",
    "get_logger",
    "log_event",
    "render_metrics",
    "reset_logging",
    "reset_metrics",
]
