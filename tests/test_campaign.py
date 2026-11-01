"""Phase 0 测试：campaign（WS-A 批量/并发/可复现）与 provider 配置（WS-D）。"""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_shield.campaign import CampaignConfig, run_campaign
from agent_shield.core.benchmark import ModelSpec
from agent_shield.providers import ProviderSpec, load_providers, resolve_spec


def _mock_spec(label: str) -> ModelSpec:
    return ModelSpec(label=label, llm="mock")


# --------------------------------------------------------------------------- #
# WS-A campaign
# --------------------------------------------------------------------------- #
def _cell_key(c) -> tuple:
    return c.target, c.module, c.round, c.successes, c.blocked, c.total


async def test_campaign_three_targets_offline():
    """离线 mock 下 3 目标 × 单模块能跑通并产出逐目标结果。"""
    cfg = CampaignConfig(
        targets=[_mock_spec("a"), _mock_spec("b"), _mock_spec("c")],
        modules=["indirect_injection"],
        num_variants=1,
        rounds=1,
        concurrency=2,
        seed=7,
        defense=True,
    )
    report = await run_campaign(cfg)
    assert report.cfg.targets == cfg.targets
    rows = report.per_target_rows()
    # 每目标一行
    assert {r["target"] for r in rows} == {"a", "b", "c"}
    for r in rows:
        assert r["successes"] <= r["total"]
        assert 0.0 <= r["aggr_rate"] <= 1.0


async def test_campaign_deterministic_same_seed():
    """固定 seed 两次跑一致（可复现）。"""
    cfg = CampaignConfig(
        targets=[_mock_spec("a")],
        modules=["indirect_injection"],  # 少格保 CI 快
        num_variants=1,
        rounds=1,
        concurrency=1,
        seed=42,
        defense=True,
    )
    r1 = await run_campaign(cfg)
    r2 = await run_campaign(cfg)
    assert [_cell_key(c) for c in r1.cells] == [_cell_key(c) for c in r2.cells]


async def test_campaign_concurrency_matches_serial():
    """并发结果与串行一致（每格独立 → 调度顺序不影响输出）。"""
    def make(concurrency: int) -> CampaignConfig:
        return CampaignConfig(
            targets=[_mock_spec("a")],
            modules=["indirect_injection"],
            num_variants=1,
            rounds=2,
            concurrency=concurrency,
            seed=1234,
            defense=True,
        )

    serial = await run_campaign(make(1))
    para = await run_campaign(make(8))
    assert {c.target for c in serial.cells} == {c.target for c in para.cells}
    assert len(serial.cells) == len(para.cells)
    assert [_cell_key(c) for c in serial.cells] == [_cell_key(c) for c in para.cells]


# --------------------------------------------------------------------------- #
# WS-D provider 配置
# --------------------------------------------------------------------------- #
def test_load_providers_sample(tmp_path, monkeypatch):
    """从样例 toml 加载多 provider，密钥走 env 不落盘。"""
    monkeypatch.setenv("OPENAI_API_KEY", "sk-deepseek")
    monkeypatch.setenv("QWEN_API_KEY", "sk-qwen")
    p = tmp_path / "agent_shield.toml"
    p.write_text(
        """
[provider.mock]
llm = "mock"

[provider.deepseek]
llm = "openai-compat"
model = "deepseek-chat"
base_url = "https://api.deepseek.com/v1"
api_key_env = "OPENAI_API_KEY"
""",
        encoding="utf-8",
    )
    ps = load_providers(p)
    assert set(ps.names()) == {"mock", "deepseek"}
    spec = ps.get("deepseek").to_spec()
    assert spec.llm == "openai-compat"
    assert spec.model == "deepseek-chat"
    assert spec.base_url == "https://api.deepseek.com/v1"
    assert spec.api_key == "sk-deepseek"  # 从 env 读出，非文件明文


def test_provider_key_not_in_config(tmp_path):
    """配置文件里只有 env 名，绝不写 api_key 明文。"""
    p = tmp_path / "agent_shield.toml"
    p.write_text(
        '[provider.deepseek]\nllm="openai-compat"\nmodel="deepseek-chat"\n'
        'base_url="https://api.deepseek.com/v1"\napi_key_env="OPENAI_API_KEY"\n',
        encoding="utf-8",
    )
    raw = p.read_text(encoding="utf-8")
    assert "sk-" not in raw  # 无明文密钥
    assert "api_key_env" in raw


def test_resolve_spec_unknown_provider_raises(tmp_path):
    p = tmp_path / "agent_shield.toml"
    p.write_text('[provider.mock]\nllm="mock"\n', encoding="utf-8")
    with pytest.raises(KeyError):
        resolve_spec("nope", providers=load_providers(p))


def test_provider_spec_resolve_api_key_env_missing(tmp_path, monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    p = Path(tmp_path) / "agent_shield.toml"
    p.write_text(
        '[provider.deepseek]\nllm="openai-compat"\nmodel="deepseek-chat"\napi_key_env="OPENAI_API_KEY"\n',
        encoding="utf-8",
    )
    with pytest.raises(ValueError):
        load_providers(p).get("deepseek").to_spec()


def test_resolve_spec_provider_overrides_cli():
    """provider 优先于 CLI flag：显式 api_key 覆盖 provider env，base_url 兜底 provider。"""
    spec = ProviderSpec(
        name="deepseek", llm="openai-compat", model="deepseek-chat",
        base_url="https://api.deepseek.com/v1", api_key_env=None,
    ).to_spec(api_key="sk-cli")
    assert spec.api_key == "sk-cli"
    assert spec.base_url == "https://api.deepseek.com/v1"