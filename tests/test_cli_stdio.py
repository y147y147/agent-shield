"""CLI 标准流编码测试（Windows cp1252 回归）。

背景：GitHub 的 Windows runner 上 Python stdout 默认是 cp1252，Rich 渲染中文会抛
``UnicodeEncodeError``，命令以退出码 1 结束（CI 的 `audit-benchmark` 步骤即因此失败）。
`agent_shield.cli._configure_stdio()` 会在命令执行前把标准流切到 UTF-8。
"""

from __future__ import annotations

import io
import os
import subprocess
import sys
from pathlib import Path

from typer.testing import CliRunner

from agent_shield.cli import _configure_stdio, app

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_configure_stdio_switches_cp1252_stream_to_utf8(monkeypatch):
    buffer = io.TextIOWrapper(io.BytesIO(), encoding="cp1252")
    monkeypatch.setattr(sys, "stdout", buffer)

    _configure_stdio()

    assert buffer.encoding.lower().replace("-", "") == "utf8"


def test_configure_stdio_does_not_crash_on_plain_stream(monkeypatch):
    """没有 reconfigure 的流（如 StringIO）应被安全跳过。"""
    monkeypatch.setattr(sys, "stdout", io.StringIO())
    _configure_stdio()  # 不抛异常即通过


def test_cli_chinese_output_survives_cp1252_console():
    """真实回归：以 cp1252 作为 stdout 编码跑 CLI，不应因编码问题失败。

    复现的正是 CI 上的失败形态：
    ``UnicodeEncodeError: 'charmap' codec can't encode characters ...``
    """
    env = dict(os.environ, PYTHONIOENCODING="cp1252", PYTHONPATH=str(REPO_ROOT))
    proc = subprocess.run(
        [
            sys.executable,
            "-c",
            "from agent_shield.cli import app; app()",
            "audit-benchmark",
            "--quick",
            "--no-fail-on-regression",
        ],
        capture_output=True,
        env=env,
        cwd=str(REPO_ROOT),
        timeout=600,
    )
    output = (proc.stdout + proc.stderr).decode("utf-8", errors="replace")
    assert proc.returncode == 0, output[-2000:]
    assert "UnicodeEncodeError" not in output


def test_cli_modules_command_uses_runner_stream():
    runner = CliRunner()
    result = runner.invoke(app, ["modules"])
    assert result.exit_code == 0, result.output
