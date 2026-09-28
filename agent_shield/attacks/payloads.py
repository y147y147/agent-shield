"""YAML 载荷家族 → 可执行载荷文本：模板渲染 + 编码面过滤/变异。

所有读 YAML 的攻击模块共用此 helper，保证语义一致：

1. 优先读 ``agent_shield/payloads/data/<module>.yaml``（``seed`` 可复现）；
2. 缺文件/解析失败时回退到各模块内置 ``fallback``（渐进迁移期不断现有行为）；
3. ``encodings`` 参数可限制编码面（白盒回归用）；``mutate=True`` 时用变异器
   确定性扩展到 ``n`` 条（含编码变换 + 去重）。
"""

from __future__ import annotations

from agent_shield.attacks.base import effective_payload_options
from agent_shield.payloads import PayloadFamily, PayloadVariant, get_library
from agent_shield.payloads.mutator import MutateOptions, apply_encoding, mutate


def resolve_baseline_with_meta(
    module: str,
    n: int,
    context: dict[str, str] | None = None,
    *,
    config=None,
    fallback: list[str] | None = None,
) -> tuple[list[tuple[str, str, str]], PayloadFamily | None]:
    """C3 自适应基线：返回 ``(variant_id, encoding, text)`` 列表（默认 plain，不展开编码）。

    与 ``resolve_payloads`` 的区别：保留每条文本的来源 variant 与编码，供
    自适应循环做"按反馈换编码/换模板"归因；``benign_control`` 对照不参与。
    """
    seed, encodings, _ = effective_payload_options(config) if config is not None else (None, None, False)
    family: PayloadFamily | None = None
    try:
        family = get_library().get(module)
    except Exception:  # noqa: BLE001 —— 载荷库异常不阻断攻击，回退内置
        family = None
    if family is None:
        base = list(fallback or [])
        texts = (base * (n // len(base) + 1))[:n] if base else []
        return [(f"fallback-{i + 1}", "plain", t) for i, t in enumerate(texts)], None
    _ = seed
    items: list[tuple[str, str, str]] = []
    for variant in family.variants:
        if variant.benign_control:
            continue
        allowed = variant.encodings if encodings is None else [e for e in variant.encodings if e in encodings]
        if not allowed or "plain" not in allowed:
            continue
        items.append((variant.id, "plain", variant.render(context)))
    if not items:
        base = list(fallback or [])
        texts = (base * (n // len(base) + 1))[:n] if base else []
        return [(f"fallback-{i + 1}", "plain", t) for i, t in enumerate(texts)], family
    return (items * (n // len(items) + 1))[:n], family


def resolve_payloads(
    module: str,
    n: int,
    context: dict[str, str] | None = None,
    *,
    config=None,
    fallback: list[str] | None = None,
) -> tuple[list[str], PayloadFamily | None, list[PayloadVariant]]:
    """解析一个模块的 n 条载荷，返回 (texts, family, used_variants)。

    - family 为 None 表示走了 fallback（无 YAML 或加载失败）；
    - used_variants 为实际参与的 YAML variant（编码过滤后；mutate 模式下为
      扩展前基底，便于报告标注来源）。
    """
    seed, encodings, do_mutate = effective_payload_options(config) if config is not None else (None, None, False)
    family: PayloadFamily | None = None
    try:
        family = get_library().get(module)
    except Exception:  # noqa: BLE001 —— 载荷库异常不阻断攻击，回退内置
        family = None

    if family is None:
        base = list(fallback or [])
        return (base * (n // len(base) + 1))[:n] if base else [], None, []

    base_seed = seed if seed is not None else family.seed
    rendered: list[tuple[PayloadVariant, str]] = []
    for variant in family.variants:
        allowed = variant.encodings if encodings is None else [e for e in variant.encodings if e in encodings]
        if not allowed:
            continue
        text = variant.render(context)
        # 默认只取 plain（保持与旧硬编码行为一致：可执行原文）；
        # 显式传 encodings（含非 plain）时才展开编码变换。
        if encodings is None:
            rendered.append((variant, text))
        elif len(allowed) == 1 and allowed[0] == "plain":
            rendered.append((variant, text))
        else:
            for i, enc in enumerate(allowed):
                rendered.append((variant, apply_encoding(text, enc, seed=base_seed + len(rendered) + i)))

    if do_mutate:
        flat = [text for _, text in rendered] or [v.render(context) for v in family.variants]
        mutated = mutate(
            flat,
            MutateOptions(
                count=n,
                encodings=tuple(encodings) if encodings else ("plain", "base64", "fullwidth-colon", "zero-width"),
                seed=base_seed,
            ),
        )
        return mutated, family, [v for v, _ in rendered]

    texts = [text for _, text in rendered]
    if not texts:
        base = list(fallback or [])
        return (base * (n // len(base) + 1))[:n] if base else [], family, []
    return (texts * (n // len(texts) + 1))[:n], family, [v for v, _ in rendered]
