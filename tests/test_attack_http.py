"""attack-http 一键挂载：本地 --serve 起靶场并对 HttpAgentTarget 打一发。"""

from __future__ import annotations

from typer.testing import CliRunner

from agent_shield.cli import app

runner = CliRunner()


def test_attack_http_serve_tool_impersonation():
    result = runner.invoke(
        app,
        [
            "attack-http",
            "--serve",
            "--port",
            "18765",
            "-m",
            "tool_impersonation",
            "-n",
            "1",
            "--no-fail-on-finding",
            "--seed",
            "1",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "http-agent" in result.output or "黑盒" in result.output or "Demo Agent" in result.output


def test_attack_http_requires_url_or_serve():
    result = runner.invoke(app, ["attack-http", "-m", "direct_injection", "--no-fail-on-finding"])
    assert result.exit_code != 0
