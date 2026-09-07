"""跨平台演示用临时目录（Windows 无 /tmp）。"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path


def demo_workdir() -> Path:
    """靶场/攻击模块写入演示文件的根目录。

    Unix 用 ``/tmp``（与策略默认 allowed_roots 一致）；
    Windows 用系统临时目录，并确保目录存在。
    """
    if os.name == "nt":
        root = Path(tempfile.gettempdir()) / "agent-shield"
    else:
        root = Path("/tmp")
    root.mkdir(parents=True, exist_ok=True)
    return root


def demo_file(name: str) -> Path:
    """在演示工作目录下生成文件路径（不创建文件内容）。"""
    return demo_workdir() / name


def allowed_demo_roots() -> list[str]:
    """策略引擎允许的文件根目录（含 Unix /tmp 与本机演示目录）。"""
    roots = ["/tmp", str(demo_workdir())]
    # 去重（保留顺序）
    seen: set[str] = set()
    out: list[str] = []
    for r in roots:
        key = os.path.normcase(os.path.abspath(r))
        if key not in seen:
            seen.add(key)
            out.append(r)
    return out


def user_data_dir() -> Path:
    """用户数据目录（会话库等），跨平台：~/.agent-shield。"""
    root = Path.home() / ".agent-shield"
    root.mkdir(parents=True, exist_ok=True)
    return root


def default_session_db_path() -> Path:
    """自主审计会话 SQLite 默认路径。"""
    return user_data_dir() / "audit_sessions.db"
