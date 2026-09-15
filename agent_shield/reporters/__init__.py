"""报告器插件：把攻击/审计结果渲染成 CI 与安全平台可消费的格式。

当前提供：

- ``sarif``：SARIF 2.1.0（GitHub Code Scanning、DefectDojo 等通用交换格式）。
"""

from agent_shield.reporters.sarif import (
    DEFAULT_TARGET_ARTIFACT,
    SARIF_SCHEMA,
    SARIF_VERSION,
    dumps,
    level_for,
    result_to_sarif,
    results_to_sarif,
    write_sarif,
)

__all__ = [
    "DEFAULT_TARGET_ARTIFACT",
    "SARIF_SCHEMA",
    "SARIF_VERSION",
    "dumps",
    "level_for",
    "result_to_sarif",
    "results_to_sarif",
    "write_sarif",
]
