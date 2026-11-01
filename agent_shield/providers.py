"""Provider 配置加载：运行时切换 API 提供方，密钥只读环境变量、不落盘。

背景（WS-D Provider 可配置，见 docs/plan-v2.md）：真实模型要接 DeepSeek/Qwen/OpenAI
等多个兼容端点，用 CLI flag + env 逐个覆盖太繁琐。这里支持从 ``agent_shield.toml``
声明多个 provider（名称 / base_url / model / api_key_env），并提供
``provider_to_spec()`` 编排为底层复用的 :class:`ModelSpec` —— 多套 provider 一键切换，
密钥经 ``api_key_env`` 指向环境变量，绝不写进配置文件。

示例 ``agent_shield.toml``::

    [provider.mock]
    llm = "mock"

    [provider.deepseek]
    llm = "openai-compat"
    model = "deepseek-chat"
    base_url = "https://api.deepseek.com/v1"
    api_key_env = "OPENAI_API_KEY"
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from agent_shield.core.benchmark import ModelSpec

DEFAULT_PROVIDER_CONFIG = Path(__file__).resolve().parents[1] / "agent_shield.toml"


@dataclass(frozen=True)
class ProviderSpec:
    """一个可切换的 API 提供方配置。"""

    name: str
    llm: str = "mock"  # mock | openai-compat
    model: str | None = None  # openai-compat 时的模型名
    base_url: str | None = None
    api_key_env: str | None = None  # 读取密钥的环境变量名（不存明文）

    def resolve_api_key(self) -> str | None:
        if not self.api_key_env:
            return None
        key = os.getenv(self.api_key_env)
        if not key:
            raise ValueError(f"provider[{self.name}].api_key_env={self.api_key_env!r} 对应的环境变量未设置")
        return key

    def to_spec(self, api_key: str | None = None, base_url: str | None = None) -> ModelSpec:
        """编排为底层 benchmark 复用的 :class:`ModelSpec`。

        命令行显式给的 api_key/base_url 优先，其次读 provider.api_key_env；
        密钥永远不落盘，只从环境或内存传入。
        """
        final_key = api_key if api_key is not None else self.resolve_api_key()
        final_base = base_url if base_url is not None else self.base_url
        return ModelSpec(
            label=self.name,
            llm=self.llm,
            model=self.model,
            base_url=final_base,
            api_key=final_key,
        )


@dataclass
class ProviderSet:
    """一个配置文件解析出的全部 provider（按名字索引 + 保序列表）。"""

    providers: dict[str, ProviderSpec] = field(default_factory=dict)

    def names(self) -> list[str]:
        return list(self.providers)

    def get(self, name: str) -> ProviderSpec:
        provider = self.providers.get(name)
        if provider is None:
            raise KeyError(f"未知 provider: {name!r}（可用: {', '.join(self.names()) or '无'}）")
        return provider

    def canonical_path(self) -> str:
        return str(DEFAULT_PROVIDER_CONFIG)


def load_providers(path: str | Path | None = None) -> ProviderSet:
    """从一个 TOML 文件加载 provider 配置。

    ``provider.<name>`` 段映射到 :class:`ProviderSpec`；整文件缺失或未配置 provider
    时不报错（返回空集，调用方回退到 CLI flag/env 旧路径）。
    """
    config_path = Path(path) if path is not None else DEFAULT_PROVIDER_CONFIG
    if not config_path.exists():
        return ProviderSet()
    raw = tomllib.loads(config_path.read_text(encoding="utf-8"))
    providers: dict[str, ProviderSpec] = {}
    for name, block in (raw.get("provider") or {}).items():
        api_key_env = str(block.get("api_key_env") or "").strip() or None
        providers[name] = ProviderSpec(
            name=name,
            llm=str(block.get("llm") or "openai-compat"),
            model=(str(block["model"]) if block.get("model") else None),
            base_url=(str(block["base_url"]) if block.get("base_url") else None),
            api_key_env=api_key_env,
        )
    if not providers:
        # 兼容旧式 sample 的兼容性检查：什么都不配就空跑
        return ProviderSet()
    return ProviderSet(providers=providers)


def resolve_spec(
    provider: str | None,
    providers: ProviderSet | None = None,
    llm: str = "mock",
    model: str | None = None,
    base_url: str | None = None,
    api_key: str | None = None,
) -> ModelSpec:
    """优先按 ``provider`` 名从配置解析 :class:`ModelSpec`；否则回退到 CLI arg/env 单规格。

    与 ``parse_model_specs`` 同源语义（见 agent_shield/core/benchmark.py）。
    """
    if provider:
        provider_set = providers or load_providers()
        spec = provider_set.get(provider)
        return spec.to_spec(api_key=api_key, base_url=base_url)

    from agent_shield.core.benchmark import parse_model_specs
    specs = parse_model_specs(llm=llm, model=model, base_url=base_url, api_key=api_key)
    return specs[0]


def provider_config_to_dict(provider_set: ProviderSet) -> dict[str, Any]:
    """给报告/日志用：只导出非敏感字段（不含 api_key，只有 env 名）。"""
    return {name: asdict(p) for name, p in provider_set.providers.items()}