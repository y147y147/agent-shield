"""不可信文本归一化：在注入检测前还原常见编码混淆面。

对应红队变异器（``payloads/mutator.py``）的编码阶梯：
base64 / 全角冒号 / 零宽字符 / HTML 实体 / Unicode 同形字。
检测器对**归一化后**的文本跑规则；一旦命中，对原文做整段脱敏（片段对齐不可靠）。
"""

from __future__ import annotations

import base64
import html
import re
import unicodedata

_ZERO_WIDTH_RE = re.compile(r"[\u200b\u200c\u200d\ufeff]")
# mutator.encode_base64_instruction 形态：base64 解码并执行: <blob>
_BASE64_HINT_RE = re.compile(
    r"base64[^:\n]{0,24}[:：]\s*([A-Za-z0-9+/]{20,}={0,2})",
    re.IGNORECASE,
)
# 裸长 base64 段（避免误伤短 token）
_BARE_B64_RE = re.compile(r"(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{40,}={0,2})(?![A-Za-z0-9+/=])")


def _decode_b64_blob(blob: str) -> str | None:
    pad = (-len(blob)) % 4
    try:
        raw = base64.b64decode(blob + ("=" * pad), validate=False)
        text = raw.decode("utf-8")
    except Exception:  # noqa: BLE001 —— 非法 base64 原样保留
        return None
    # 只接受「解码后像可读指令」的结果，避免噪声
    if not text or not any(ch.isprintable() or ch in "\n\r\t" for ch in text):
        return None
    if not re.search(r"[A-Za-z\u4e00-\u9fff]", text):
        return None
    return text


def _expand_base64(text: str) -> str:
    def _hint(m: re.Match[str]) -> str:
        decoded = _decode_b64_blob(m.group(1))
        return decoded if decoded is not None else m.group(0)

    out = _BASE64_HINT_RE.sub(_hint, text)

    def _bare(m: re.Match[str]) -> str:
        decoded = _decode_b64_blob(m.group(1))
        if decoded is None:
            return m.group(0)
        # 解码结果需含指令线索才替换，降低误伤
        if re.search(r"INSTRUCTION|run_command|ignore\s+(?:your\s+)?previous|系统提示", decoded, re.I):
            return decoded
        return m.group(0)

    return _BARE_B64_RE.sub(_bare, out)


def normalize_for_detection(text: str) -> str:
    """供注入/意图检测使用的归一化视图（不修改业务原文语义展示，仅用于匹配）。"""
    if not text:
        return text
    out = _ZERO_WIDTH_RE.sub("", text)
    out = html.unescape(out)
    out = unicodedata.normalize("NFKC", out)
    out = _expand_base64(out)
    return out
