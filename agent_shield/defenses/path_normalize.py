"""路径形态归一化：降低真实模型把工作目录写成 git-bash 风格后的误拦（FPR）。

真实模型常把 ``C:\\Users\\...`` 臆造为 ``/c/Users/...`` 或 ``/mnt/c/Users/...``，
策略引擎按字面 realpath 校验会判越界 → 抬高 FPR。本守卫在 PolicyEngine **之前**
改写参数中的 path / command 路径片段；改写后仍走原策略，不放宽权限。
"""

from __future__ import annotations

import os
import re

from agent_shield.defenses.base import GuardRail, ToolCallDecision
from agent_shield.models import ToolCall

# /c/Users/foo 或 /mnt/c/Users/foo → 仅在 Windows 宿主上改写
_GIT_BASH_PATH_RE = re.compile(
    r"(?P<prefix>^|[\s\"'=])(?P<path>/(?:mnt/)?(?P<drive>[A-Za-z])/(?P<rest>[^\s\"']*))"
)


def normalize_git_bash_path(path: str) -> str:
    """单段路径：git-bash / msys 盘符形式 → 宿主盘符路径；其它原样返回。"""
    if os.name != "nt" or not path:
        return path
    normalized = path.replace("\\", "/")
    m = re.match(r"^/(?:mnt/)?([A-Za-z])/(.*)$", normalized)
    if not m:
        return path
    drive = m.group(1).upper()
    rest = m.group(2).replace("/", "\\")
    return f"{drive}:\\{rest}" if rest else f"{drive}:\\"


def normalize_paths_in_text(text: str) -> str:
    """命令字符串内嵌的 git-bash 路径一并改写。"""
    if os.name != "nt" or not text:
        return text
    if not re.search(r"/(?:mnt/)?[A-Za-z]/", text):
        return text

    def _sub(m: re.Match[str]) -> str:
        return m.group("prefix") + normalize_git_bash_path(m.group("path"))

    return _GIT_BASH_PATH_RE.sub(_sub, text)


class PathNormalizeGuard(GuardRail):
    """就地改写工具参数中的路径形态；始终放行，决策交给后续策略引擎。"""

    name = "path_normalize"

    async def check_tool_call(self, call: ToolCall) -> ToolCallDecision:
        args = call.arguments
        if "path" in args and isinstance(args["path"], str):
            args["path"] = normalize_git_bash_path(args["path"])
        if "command" in args and isinstance(args["command"], str):
            args["command"] = normalize_paths_in_text(args["command"])
        # write_file 等也可能带 path
        for key in ("file", "filename", "dest", "destination"):
            if key in args and isinstance(args[key], str):
                args[key] = normalize_git_bash_path(args[key])
        return ToolCallDecision(allowed=True, reason="path_normalize: rewritten")
