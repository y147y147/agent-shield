"""沙箱执行：在受限环境中运行 shell 命令。

对应风险：ASI-05（意外代码执行）/ ASI-08（级联故障）—— 即使攻击者成功诱导
智能体执行命令，命令也在受限环境中运行：

1. **危险命令拦截**：命中黑名单（rm -rf /、mkfs、curl/wget/nc 外联、fork bomb、
   关机重启、sudo 提权、写磁盘等）直接拒绝，不执行；
2. **资源限制**：CPU 时间、文件大小、内存均被限制，并强制超时终止；
3. **固定工作目录**：cwd="/tmp"，避免命令在仓库/系统目录产生副作用。

当前实现为"轻量沙箱"（黑名单 + subprocess + resource 限制 + 超时）。黑名单能挡住
常见破坏命令，但**不是强隔离**（如 python3 -c 内嵌代码仍可绕过模式匹配）——
生产环境请升级为 Docker / nsjail / gVisor 等强隔离（见 docker-compose.yml），
SandboxExecutor 保持同一接口。
"""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
from dataclasses import dataclass

try:
    import resource  # Unix only；Windows 无此模块
except ImportError:  # pragma: no cover
    resource = None  # type: ignore[assignment]

# 危险命令黑名单（轻量沙箱的近似拦截；与 PolicyEngine 共用，防止策略/沙箱规则漂移）
DANGEROUS_COMMAND_PATTERNS: list[str] = [
    r"rm\s+-[rf]+\b",  # rm -rf / 等破坏性删除
    r"rm\s+-r\s+-f\b",
    r"mkfs\b",  # 格式化磁盘
    r"fdisk\b",
    r"dd\s+if=",  # 写磁盘/覆写设备
    r"\bformat\s+[a-z]:",
    r":\(\)\s*\{",  # fork bomb
    r"\bcurl\b",  # 外联（数据外发 / 下载执行）
    r"\bwget\b",
    r"\bnc\b",
    r"\bncat\b",
    r"\b(?:shutdown|reboot|halt|poweroff)\b",  # 关机/重启
    r"\bsudo\b",  # 提权
    r"\bsu\s+-",
    r"--no-preserve-root",
    r">\s*/dev/(?:sd|hd|disk)",  # 直接写块设备
    r"chmod\s+-R\s+777\s*/",
    r"kill\s+-9\s+\d+",
]

_COMPILED_DANGEROUS = [(re.compile(p), p) for p in DANGEROUS_COMMAND_PATTERNS]


@dataclass
class SandboxLimits:
    """子进程资源上限（近似"无网络 + 只读宿主"的轻量隔离）。"""

    cpu_seconds: int = 1  # RLIMIT_CPU：最多 1 秒 CPU 时间
    max_file_bytes: int = 1 << 20  # RLIMIT_FSIZE：最多写 1MB 文件
    max_memory_bytes: int = 256 << 20  # RLIMIT_AS：最多 256MB 内存
    timeout_seconds: float = 10.0  # 墙钟超时（超时即 SIGKILL）


@dataclass
class SandboxResult:
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False
    denied: bool = False  # 命中危险命令黑名单被拒绝（未执行）

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out and not self.denied


class SandboxExecutor:
    """受限命令执行器：危险命令拦截 + resource 限制 + 超时 + 固定工作目录。"""

    def __init__(
        self,
        limits: SandboxLimits | None = None,
        cwd: str | None = None,
        deny_patterns: list[str] | None = None,
    ):
        self.limits = limits or SandboxLimits()
        # Unix 默认 /tmp；Windows 等用系统临时目录（避免 WinError 267）
        self.cwd = cwd if cwd is not None else (tempfile.gettempdir() if os.name == "nt" else "/tmp")
        self._deny = [(re.compile(p), p) for p in (deny_patterns if deny_patterns is not None else DANGEROUS_COMMAND_PATTERNS)]

    def run(self, command: str, sandbox: bool = True) -> SandboxResult:
        """执行命令。sandbox=False 时仅保留超时，用于对照（脆弱靶场）。

        sandbox=True（沙箱开启）时：先过危险命令黑名单（命中即拒绝，不执行），
        再套资源限制 + 超时。注意：Web 工作台的沙箱测试页还会先过语义策略引擎，
        因此即使关闭沙箱开关，危险命令也会被策略层拦截。
        """
        if sandbox:
            for rx, pattern in self._deny:
                if rx.search(command):
                    return SandboxResult(
                        returncode=-2,
                        stdout="",
                        stderr=f"denied by sandbox policy: {pattern}",
                        denied=True,
                    )
        # preexec_fn / resource 仅 Unix 可用；Windows 仍保留黑名单 + 超时
        preexec_fn = self._limit_resources if sandbox and resource is not None else None
        run_kwargs: dict = {
            "shell": True,
            "capture_output": True,
            "text": True,
            "timeout": self.limits.timeout_seconds,
            "cwd": self.cwd,
            "check": False,
        }
        if preexec_fn is not None:
            run_kwargs["preexec_fn"] = preexec_fn
        try:
            proc = subprocess.run(command, **run_kwargs)
            return SandboxResult(
                returncode=proc.returncode,
                stdout=proc.stdout.strip(),
                stderr=proc.stderr.strip(),
            )
        except subprocess.TimeoutExpired:
            return SandboxResult(
                returncode=-1,
                stdout="",
                stderr=f"timed out after {self.limits.timeout_seconds}s",
                timed_out=True,
            )

    def _limit_resources(self) -> None:
        """在子进程 exec 前设置资源上限（对子进程及其后代生效）。

        每个限制独立 try/except：某些平台（如 macOS 的 RLIMIT_AS）不支持特定
        限制，跳过即可 —— 沙箱为"尽力而为"，CPU/文件/超时限制仍生效。
        """
        if resource is None:  # pragma: no cover
            return
        for rlimit, value, label in (
            (resource.RLIMIT_CPU, self.limits.cpu_seconds, "RLIMIT_CPU"),
            (resource.RLIMIT_FSIZE, self.limits.max_file_bytes, "RLIMIT_FSIZE"),
            (resource.RLIMIT_AS, self.limits.max_memory_bytes, "RLIMIT_AS"),
        ):
            try:
                resource.setrlimit(rlimit, (value, value))
            except (ValueError, OSError):
                # 平台不支持该限制 → 跳过（不影响其他限制生效）
                pass
