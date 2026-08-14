"""攻击模块注册表：新增攻击向量 = 实现 AttackModule 并 @register。"""

from __future__ import annotations

from agent_shield.attacks.base import AttackModule

_REGISTRY: dict[str, type[AttackModule]] = {}


def register(cls: type[AttackModule]) -> type[AttackModule]:
    """类装饰器：把攻击模块注册到全局表。"""
    if cls.name in _REGISTRY:
        raise ValueError(f"duplicate attack module name: {cls.name}")
    _REGISTRY[cls.name] = cls
    return cls


def get_attack_module(name: str) -> AttackModule:
    try:
        return _REGISTRY[name]()
    except KeyError:
        available = ", ".join(sorted(_REGISTRY))
        raise ValueError(f"未知攻击模块: {name}（可用: {available}）") from None


def list_attack_modules() -> list[tuple[str, str]]:
    return [(cls.name, cls.description) for cls in _REGISTRY.values()]
