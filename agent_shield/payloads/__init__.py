"""版本化载荷库：YAML schema、加载器、模板渲染。

设计：
- 每个攻击族一个 YAML（``agent_shield/payloads/data/<module>.yaml``），含 id/version/mapping/channel/seed
  与 variants 列表；每个 variant 有 id/text/template/severity/encodings/benign_control/note。
- ``text`` 为静态载荷；``template`` 为含 ``{placeholders}`` 的模板，由调用方传入
  context 渲染（如 ``{marker}``）。两者必须且只能出现其一。
- 加载器做 schema 校验（缺字段、重复 id、encodings 非法即报错），保证数据集
  可独立发布、可 diff、可回滚。
- 同一 ``seed`` 下扩展/采样结果可复现（见 ``agent_shield/payloads/mutator.py``）。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

PAYLOAD_DIR = Path(__file__).resolve().parent / "data"

SUPPORTED_ENCODINGS = ("plain", "base64", "fullwidth-colon", "zero-width", "html-entity", "unicode-homoglyph")

REQUIRED_FILE_KEYS = ("id", "version", "mapping", "channel", "variants")
REQUIRED_VARIANT_KEYS = ("id", "severity")


@dataclass(frozen=True)
class PayloadVariant:
    """单个载荷变体：静态文本或模板二选一。"""

    id: str
    text: str | None = None
    template: str | None = None
    severity: str = "info"
    encodings: tuple[str, ...] = ("plain",)
    benign_control: bool = False
    note: str = ""

    def render(self, context: dict[str, str] | None = None) -> str:
        """渲染为最终载荷文本：静态 text 直接返回，template 按 context 格式化。"""
        if self.template is not None:
            ctx = context or {}
            try:
                return self.template.format(**ctx)
            except KeyError as exc:
                raise ValueError(f"载荷模板 {self.id!r} 缺少占位符: {exc}") from exc
        return self.text or ""


@dataclass(frozen=True)
class PayloadFamily:
    """一个攻击族的版本化载荷集。"""

    id: str
    version: str
    mapping: dict
    channel: str
    seed: int = 0
    variants: tuple[PayloadVariant, ...] = ()
    path: str = ""

    def texts(self, context: dict[str, str] | None = None) -> list[str]:
        return [v.render(context) for v in self.variants]


@dataclass
class PayloadLibrary:
    """已加载的载荷库：按模块名索引，缺省回退到内置硬编码（渐进迁移期）。"""

    families: dict[str, PayloadFamily] = field(default_factory=dict)

    def get(self, module: str) -> PayloadFamily | None:
        return self.families.get(module)

    def modules(self) -> list[str]:
        return sorted(self.families)


def load_family(path: str | Path) -> PayloadFamily:
    """加载并校验单个 YAML 文件，失败抛 ValueError（附文件路径与原因）。"""
    path = Path(path)
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError(f"载荷文件不存在: {path}") from exc
    except yaml.YAMLError as exc:
        raise ValueError(f"载荷文件 YAML 解析失败 {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"载荷文件顶层须为 mapping，收到 {type(data).__name__}: {path}")
    for key in REQUIRED_FILE_KEYS:
        if key not in data:
            raise ValueError(f"载荷文件缺少必填键 {key!r}: {path}")
    raw_variants = data["variants"]
    if not isinstance(raw_variants, list) or not raw_variants:
        raise ValueError(f"载荷文件 variants 须为非空列表: {path}")

    seen: set[str] = set()
    variants: list[PayloadVariant] = []
    for i, raw in enumerate(raw_variants):
        if not isinstance(raw, dict):
            raise ValueError(f"variants[{i}] 须为 mapping: {path}")
        for key in REQUIRED_VARIANT_KEYS:
            if key not in raw:
                raise ValueError(f"variants[{i}] 缺少必填键 {key!r}: {path}")
        vid = str(raw["id"])
        if vid in seen:
            raise ValueError(f"variants[{i}] 重复 id {vid!r}: {path}")
        seen.add(vid)
        text = raw.get("text")
        template = raw.get("template")
        if (text is None) == (template is None):
            raise ValueError(f"variants[{i}] {vid!r} 的 text/template 必须且只能出现其一: {path}")
        encodings = tuple(raw.get("encodings") or ["plain"])
        for enc in encodings:
            if enc not in SUPPORTED_ENCODINGS:
                raise ValueError(f"variants[{i}] {vid!r} 不支持的 encoding {enc!r}: {path}")
        variants.append(
            PayloadVariant(
                id=vid,
                text=str(text) if text is not None else None,
                template=str(template) if template is not None else None,
                severity=str(raw.get("severity") or "info"),
                encodings=encodings,
                benign_control=bool(raw.get("benign_control", False)),
                note=str(raw.get("note") or ""),
            )
        )
    mapping = data["mapping"]
    if not isinstance(mapping, dict):
        raise ValueError(f"载荷文件 mapping 须为 mapping: {path}")
    return PayloadFamily(
        id=str(data["id"]),
        version=str(data["version"]),
        mapping=dict(mapping),
        channel=str(data["channel"]),
        seed=int(data.get("seed") or 0),
        variants=tuple(variants),
        path=str(path),
    )


def load_library(payload_dir: str | Path = PAYLOAD_DIR) -> PayloadLibrary:
    """加载目录下全部 ``*.yaml``，逐文件校验，文件名须为 ``<module>.yaml``。"""
    payload_dir = Path(payload_dir)
    lib = PayloadLibrary()
    if not payload_dir.is_dir():
        return lib
    for path in sorted(payload_dir.glob("*.yaml")):
        family = load_family(path)
        lib.families[path.stem] = family
    return lib


_DEFAULT_LIBRARY: PayloadLibrary | None = None


def get_library() -> PayloadLibrary:
    """进程内默认载荷库（懒加载，缺目录时返回空库，调用方可回退内置）。"""
    global _DEFAULT_LIBRARY
    if _DEFAULT_LIBRARY is None:
        _DEFAULT_LIBRARY = load_library()
    return _DEFAULT_LIBRARY


def reset_library_cache() -> None:
    """测试用：清空默认库缓存，下次 get_library 重新从磁盘加载。"""
    global _DEFAULT_LIBRARY
    _DEFAULT_LIBRARY = None
