"""结构化日志：JSON 行格式（stdout/stderr 友好，可直接进 ELK / Loki）。

用法::

    from agent_shield.observability import configure_logging, get_logger, log_event

    configure_logging(level="INFO", json_output=True)   # CLI: --log-level INFO --log-format json
    log = get_logger()
    log_event(log, "tool_call_blocked", tool="run_command", reason="denied by rule: rm\\s+-rf")

输出（单行 JSON）::

    {"ts": "2026-..., "level": "INFO", "logger": "agent_shield", "message": "tool_call_blocked",
     "event": "tool_call_blocked", "tool": "run_command", "reason": "denied by rule: rm\\s+-rf"}
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import UTC, datetime
from typing import Any, TextIO

LOGGER_NAME = "agent_shield"
_HANDLER_MARKER = "_agentshield_handler"

# LogRecord 的内置属性：这些不进 JSON 的"额外字段"，避免噪音
_STANDARD_ATTRS = frozenset(
    {
        "args", "asctime", "created", "exc_info", "exc_text", "filename", "funcName", "levelname",
        "levelno", "lineno", "message", "module", "msecs", "msg", "name", "pathname", "process",
        "processName", "relativeCreated", "stack_info", "taskName", "thread", "threadName",
    }
)


class JsonFormatter(logging.Formatter):
    """把日志记录渲染成单行 JSON（保留中文；异常栈进 ``exception`` 字段）。"""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, tz=UTC).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for key, value in record.__dict__.items():
            if key in _STANDARD_ATTRS or key.startswith("_"):
                continue
            payload[key] = value
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False, default=str)


def get_logger(name: str | None = None) -> logging.Logger:
    """取 ``agent_shield`` 命名空间下的 logger（``name`` 为子模块名时自动加前缀）。"""
    if not name or name == LOGGER_NAME:
        return logging.getLogger(LOGGER_NAME)
    if name.startswith(f"{LOGGER_NAME}."):
        return logging.getLogger(name)
    return logging.getLogger(f"{LOGGER_NAME}.{name}")


def configure_logging(
    level: str | int = "INFO",
    json_output: bool = True,
    stream: TextIO | None = None,
) -> logging.Logger:
    """配置 ``agent_shield`` logger（幂等：重复调用不会叠加 handler）。

    参数：
        level: 日志级别（字符串或 logging 常量）。
        json_output: True → 单行 JSON；False → 人类可读文本。
        stream: 输出流，默认 stderr（避免污染 CLI 的结构化输出）。
    """
    logger = logging.getLogger(LOGGER_NAME)
    for handler in list(logger.handlers):
        if getattr(handler, _HANDLER_MARKER, False):
            logger.removeHandler(handler)
            handler.close()

    handler = logging.StreamHandler(stream or sys.stderr)
    setattr(handler, _HANDLER_MARKER, True)
    handler.setFormatter(
        JsonFormatter()
        if json_output
        else logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    )
    logger.addHandler(handler)
    logger.setLevel(level.upper() if isinstance(level, str) else level)
    logger.propagate = False
    return logger


def reset_logging() -> None:
    """移除本模块添加的 handler（测试与嵌入式使用场景）。"""
    logger = logging.getLogger(LOGGER_NAME)
    for handler in list(logger.handlers):
        if getattr(handler, _HANDLER_MARKER, False):
            logger.removeHandler(handler)
            handler.close()


def log_event(logger: logging.Logger, event: str, level: int = logging.INFO, **fields: Any) -> None:
    """记录一条结构化事件：``event`` 同时作为 message 与 ``event`` 字段。"""
    logger.log(level, event, extra={"event": event, **fields})


# 库默认静默：不配置 root，不输出任何内容
logging.getLogger(LOGGER_NAME).addHandler(logging.NullHandler())
