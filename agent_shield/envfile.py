"""本地 ``.env`` 加载（不依赖 python-dotenv）。

安全约定：密钥只放在本机环境变量或被 gitignore 的 ``.env`` 里，**不要粘贴到聊天**。
本模块仅把尚未设置的键写入 ``os.environ``，不覆盖已有环境变量。
"""

from __future__ import annotations

import os
from pathlib import Path


def load_dotenv(path: str | Path | None = None) -> Path | None:
    """若存在 ``.env`` 则解析 ``KEY=VALUE`` 行；返回实际加载的路径，否则 ``None``。"""
    candidate = Path(path) if path is not None else Path.cwd() / ".env"
    if not candidate.is_file():
        return None
    for raw in candidate.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip("'").strip('"')
        if not key:
            continue
        # 不覆盖已在 shell 里 export 的值
        if key not in os.environ or os.environ.get(key, "") == "":
            os.environ[key] = value
    return candidate
