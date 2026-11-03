"""容器级沙箱后端：Docker（可插拔，缺省回退轻量 SandboxExecutor）。

设计目标（对照 docs/sandbox-escape-matrix.md A1）：
- 无网络（``--network=none``）
- 只读根文件系统 + ``tmpfs`` 挂载工作目录
- 非 root（``nobody``）
- CPU / 内存 / PIDs 限制
- 与 ``SandboxExecutor`` 同一 ``run`` / ``deny_match`` 接口

环境变量：
- ``AGENT_SHIELD_SANDBOX=docker|local|auto``（默认 auto：有 Docker 用容器，否则本地）
- ``AGENT_SHIELD_SANDBOX_IMAGE``（默认 ``alpine:3.20``）
"""

from __future__ import annotations

import os
import shutil
import subprocess
from typing import Literal

from agent_shield.defenses.sandbox import (
    DANGEROUS_COMMAND_PATTERNS,
    SandboxExecutor,
    SandboxLimits,
    SandboxResult,
)
from agent_shield.observability import SANDBOX_RUNS

SandboxBackend = Literal["auto", "local", "docker"]

DEFAULT_SANDBOX_IMAGE = "alpine:3.20"

_DOCKER_AVAILABLE_CACHE: bool | None = None


def docker_available(timeout: float = 8.0, *, force_refresh: bool = False) -> bool:
    """本机是否可用 ``docker`` CLI 且 daemon 可达（结果进程内缓存）。"""
    global _DOCKER_AVAILABLE_CACHE
    if _DOCKER_AVAILABLE_CACHE is not None and not force_refresh:
        return _DOCKER_AVAILABLE_CACHE
    if shutil.which("docker") is None:
        _DOCKER_AVAILABLE_CACHE = False
        return False
    try:
        proc = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        _DOCKER_AVAILABLE_CACHE = proc.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        _DOCKER_AVAILABLE_CACHE = False
    return _DOCKER_AVAILABLE_CACHE


def resolve_sandbox_backend(explicit: str | None = None) -> SandboxBackend:
    raw = (explicit or os.environ.get("AGENT_SHIELD_SANDBOX") or "auto").strip().lower()
    if raw in ("auto", "local", "docker"):
        return raw  # type: ignore[return-value]
    return "auto"


def build_sandbox_executor(
    backend: str | None = None,
    *,
    limits: SandboxLimits | None = None,
    cwd: str | None = None,
    image: str | None = None,
) -> SandboxExecutor:
    """按后端构造执行器；``auto`` 在 Docker 不可用时静默回退 local。"""
    choice = resolve_sandbox_backend(backend)
    if choice == "docker" or (choice == "auto" and docker_available()):
        return DockerSandboxExecutor(limits=limits, cwd=cwd, image=image)
    return SandboxExecutor(limits=limits, cwd=cwd)


class DockerSandboxExecutor(SandboxExecutor):
    """在短生命周期容器内执行命令；黑名单仍先判定（省一次容器启动）。"""

    name = "docker_sandbox"

    def __init__(
        self,
        limits: SandboxLimits | None = None,
        cwd: str | None = None,
        deny_patterns: list[str] | None = None,
        image: str | None = None,
        docker_bin: str = "docker",
    ):
        super().__init__(limits=limits, cwd=cwd, deny_patterns=deny_patterns)
        self.image = image or os.environ.get("AGENT_SHIELD_SANDBOX_IMAGE") or DEFAULT_SANDBOX_IMAGE
        self.docker_bin = docker_bin

    def run(self, command: str, sandbox: bool = True) -> SandboxResult:
        if not sandbox:
            # 对照脆弱模式：仍走父类本机执行
            return super().run(command, sandbox=False)

        pattern = self.deny_match(command)
        if pattern is not None:
            SANDBOX_RUNS.inc(outcome="denied")
            return SandboxResult(
                returncode=-2,
                stdout="",
                stderr=f"denied by sandbox policy: {pattern}",
                denied=True,
            )

        work = self.cwd or "/tmp"
        # 内存：Docker 要人类可读；沿用 limits.max_memory_bytes
        mem_mb = max(64, int(self.limits.max_memory_bytes / (1 << 20)))
        cpus = "0.5"
        docker_cmd = [
            self.docker_bin,
            "run",
            "--rm",
            "--network=none",
            "--read-only",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=64m",
            "--workdir",
            "/tmp",
            "--user",
            "65534:65534",
            "--memory",
            f"{mem_mb}m",
            "--cpus",
            cpus,
            "--pids-limit",
            "64",
            "--security-opt",
            "no-new-privileges",
            # 可选：把宿主 cwd 挂成可写数据卷（仅 /work，根仍只读）
            "-v",
            f"{work}:/work:rw",
            "-e",
            "HOME=/tmp",
            self.image,
            "sh",
            "-c",
            command,
        ]
        try:
            proc = subprocess.run(
                docker_cmd,
                capture_output=True,
                text=True,
                timeout=self.limits.timeout_seconds + 5.0,
                check=False,
            )
            SANDBOX_RUNS.inc(outcome="ok" if proc.returncode == 0 else "error")
            return SandboxResult(
                returncode=proc.returncode,
                stdout=(proc.stdout or "").strip(),
                stderr=(proc.stderr or "").strip(),
            )
        except subprocess.TimeoutExpired:
            SANDBOX_RUNS.inc(outcome="timeout")
            return SandboxResult(
                returncode=-1,
                stdout="",
                stderr=f"docker sandbox timed out after {self.limits.timeout_seconds}s",
                timed_out=True,
            )
        except FileNotFoundError:
            SANDBOX_RUNS.inc(outcome="error")
            return SandboxResult(
                returncode=-3,
                stdout="",
                stderr="docker binary not found; fallback unavailable in strict docker mode",
                denied=True,
            )


# 再导出黑名单，便于文档/测试引用
__all__ = [
    "DANGEROUS_COMMAND_PATTERNS",
    "DEFAULT_SANDBOX_IMAGE",
    "DockerSandboxExecutor",
    "build_sandbox_executor",
    "docker_available",
    "resolve_sandbox_backend",
]
