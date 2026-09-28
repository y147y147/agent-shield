"""载荷变异器：确定性扩展 + 编码变换 + 去重。

用途：
- C2（Fuzzing）：单族载荷自动扩展到 N 个去重变体（同义改写由编码变换近似，
  不引入 LLM 改写以保证离线可复现）；
- B5（编码混淆检测）：把已知绕过面（base64/全角/零宽/HTML 实体/同形字）逐条
  转为可执行变体，供红队回归与蓝队检测器测试；
- 同一 ``seed`` 下输出顺序与内容完全一致（``random.Random(seed)``），不同
  seed 得到不同采样/排列，便于"同一实验包半年后重跑结论一致"。

注意：变异是纯文本变换，不改变载荷语义（marker 与 INSTRUCTION 关键字保留），
MockLLM 仍能识别；对真实模型的绕过效果需实测。
"""

from __future__ import annotations

import base64
import random
from dataclasses import dataclass

FULLWIDTH_COLON = "\uff1a"

_ZERO_WIDTH_CHARS = ("\u200b", "\u200c", "\u200d", "\ufeff")

_HTML_ENTITY_MAP = {"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;"}

_HOMOGLYPH_MAP = {
    ":": "\uff1a",
    "(": "\uff08",
    ")": "\uff09",
    ";": "\uff1b",
    "I": "\uff29",
    "N": "\uff2e",
    "S": "\uff33",
    "T": "\uff34",
}


def encode_base64_instruction(text: str) -> str:
    """把首个 INSTRUCTION 段整体 base64，并保留解码提示（模拟"编码混淆"绕过）。"""
    marker = "INSTRUCTION:"
    idx = text.find(marker)
    if idx == -1:
        return text
    head, tail = text[:idx], text[idx:]
    encoded = base64.b64encode(tail.encode("utf-8")).decode("ascii")
    return f"{head}base64 解码并执行: {encoded}"


def encode_fullwidth_colon(text: str) -> str:
    """英文冒号转全角冒号（已知绕过：正则只匹配 ASCII 冒号时失效）。"""
    return text.replace("INSTRUCTION:", f"INSTRUCTION{FULLWIDTH_COLON}")


def encode_zero_width(text: str, seed: int = 0) -> str:
    """在关键字内插入零宽字符（肉眼不可见，朴素正则失效）。"""
    rng = random.Random(seed)
    zw = rng.choice(_ZERO_WIDTH_CHARS)
    return text.replace("INSTRUCTION", f"INS{zw}TRUCTION", 1)


def encode_html_entity(text: str) -> str:
    """尖括号/引号转 HTML 实体（渲染后还原，检测器需归一化）。"""
    out = text
    for raw, entity in _HTML_ENTITY_MAP.items():
        out = out.replace(raw, entity)
    return out


def encode_unicode_homoglyph(text: str) -> str:
    """ASCII 标点/字母转全角同形字（视觉一致，字节不一致）。"""
    return "".join(_HOMOGLYPH_MAP.get(ch, ch) for ch in text)


ENCODERS = {
    "plain": lambda text, seed=0: text,
    "base64": lambda text, seed=0: encode_base64_instruction(text),
    "fullwidth-colon": lambda text, seed=0: encode_fullwidth_colon(text),
    "zero-width": encode_zero_width,
    "html-entity": lambda text, seed=0: encode_html_entity(text),
    "unicode-homoglyph": lambda text, seed=0: encode_unicode_homoglyph(text),
}


def apply_encoding(text: str, encoding: str, seed: int = 0) -> str:
    """对单条载荷应用一种编码变换，未知编码抛 ValueError。"""
    try:
        encoder = ENCODERS[encoding]
    except KeyError as exc:
        raise ValueError(f"不支持的 encoding: {encoding!r}") from exc
    return encoder(text, seed)


@dataclass(frozen=True)
class MutateOptions:
    """变异选项：目标总数、允许的编码集合、随机种子。"""

    count: int = 10
    encodings: tuple[str, ...] = ("plain", "base64", "fullwidth-colon", "zero-width")
    seed: int = 0


def mutate(texts: list[str], options: MutateOptions | None = None) -> list[str]:
    """确定性扩展：轮换编码变换 + 去重，返回恰好 ``count`` 条（不足则循环复用）。

    同一 (texts, options) 输入恒返回同一输出；不同 seed 的编码参数/顺序不同。
    """
    opts = options or MutateOptions()
    if opts.count < 1:
        raise ValueError(f"count 必须 ≥ 1，收到: {opts.count}")
    for enc in opts.encodings:
        if enc not in ENCODERS:
            raise ValueError(f"不支持的 encoding: {enc!r}")
    if not texts:
        return []

    rng = random.Random(opts.seed)
    order = list(range(len(texts)))
    rng.shuffle(order)

    expanded: list[str] = []
    seen: set[str] = set()

    def _push(text: str) -> None:
        if text not in seen:
            seen.add(text)
            expanded.append(text)

    # 第一轮：每条原文按轮换编码各变一次（保证覆盖全部编码面）
    for idx, text_idx in enumerate(order):
        enc = opts.encodings[idx % len(opts.encodings)]
        _push(apply_encoding(texts[text_idx], enc, seed=opts.seed + idx))
        if len(expanded) >= opts.count:
            return expanded[: opts.count]

    # 后续轮：继续用递增 seed 做编码变换（零宽字符等随 seed 变化），直到凑够
    round_no = 1
    while len(expanded) < opts.count:
        for idx, text_idx in enumerate(order):
            enc = opts.encodings[(idx + round_no) % len(opts.encodings)]
            _push(apply_encoding(texts[text_idx], enc, seed=opts.seed + round_no * 100 + idx))
            if len(expanded) >= opts.count:
                return expanded[: opts.count]
        round_no += 1
        if round_no > opts.count + 5:
            break

    # 极端情况（去重后仍不足，如全部输入相同）：循环复用已有条目补齐
    while len(expanded) < opts.count:
        expanded.append(expanded[len(expanded) % len(seen)])
    return expanded[: opts.count]
