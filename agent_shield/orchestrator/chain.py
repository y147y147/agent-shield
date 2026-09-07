"""E1：显式多步攻击链 — 前置模块输出映射为后置 params。"""

from __future__ import annotations

import uuid
from typing import Any

from agent_shield.attacks import get_attack_module, list_attack_modules
from agent_shield.models import AuditChainProposal, AuditChainStep

# depends_on 已设但未给 map_from_prev 时的默认映射（目标键 ← 前置 outputs 字段）
DEFAULT_MAP_FROM_PREV: dict[str, str] = {
    "prior_payload": "payload",
    "prior_evidence": "evidence",
    "prior_module": "module",
    "marker_command": "marker_command",
}


def extract_outputs_from_attack_payload(payload: dict[str, Any], *, module: str) -> dict[str, Any]:
    """从攻击 Observation JSON 提取可链式传递的输出。"""
    summary = payload.get("summary") or {}
    cases = payload.get("cases") or []
    success = next(
        (c for c in cases if str(c.get("verdict", "")).lower() in {"success", "attackverdict.success"}),
        None,
    )
    pick = success or (cases[0] if cases else {})
    evidence = pick.get("evidence") or []
    if isinstance(evidence, list):
        evidence_text = "；".join(str(e) for e in evidence[:5])
    else:
        evidence_text = str(evidence)

    payload_text = str(pick.get("payload") or "")
    marker = ""
    # 从 payload / evidence 启发式提取 touch/echo 标记命令
    for src in (payload_text, evidence_text):
        if "touch " in src:
            idx = src.find("touch ")
            marker = src[idx:].split("\n", 1)[0].strip()[:120]
            break
        if "run_command " in src:
            idx = src.find("run_command ")
            marker = src[idx + len("run_command ") :].split("\n", 1)[0].strip()[:120]
            break

    return {
        "module": module,
        "payload": payload_text[:500],
        "evidence": evidence_text[:500],
        "marker_command": marker,
        "successes": int(summary.get("successes") or 0),
        "blocked": int(summary.get("blocked") or 0),
        "success_rate": float(summary.get("success_rate") or 0.0),
        "ref": str(pick.get("ref") or ""),
    }


def _lookup_output(outputs: dict[str, Any], field: str) -> Any:
    if field in outputs:
        return outputs[field]
    # 支持 summary.successes 风格
    if "." in field:
        cur: Any = outputs
        for part in field.split("."):
            if not isinstance(cur, dict) or part not in cur:
                return None
            cur = cur[part]
        return cur
    return None


def merge_params_from_prev(
    step: AuditChainStep,
    prev_outputs: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """将前置 outputs 按 map_from_prev（或默认表）合并进本步 params。"""
    mapping = dict(step.map_from_prev) if step.map_from_prev else dict(DEFAULT_MAP_FROM_PREV)
    merged = dict(step.params or {})
    applied: dict[str, Any] = {}
    for dest_key, src_field in mapping.items():
        value = _lookup_output(prev_outputs, src_field)
        if value is None or value == "":
            continue
        merged[dest_key] = value
        applied[dest_key] = value
    return merged, applied


def validate_chain_steps(
    steps: list[AuditChainStep],
    *,
    allow_mock_only: bool = True,
) -> list[str]:
    """校验链定义，返回错误列表（空 = 合法）。"""
    errors: list[str] = []
    if not steps:
        errors.append("steps 不能为空")
        return errors

    ids = [s.step_id for s in steps]
    if len(ids) != len(set(ids)):
        errors.append("step_id 必须唯一")

    known = {n for n, _ in list_attack_modules()}
    id_set = set(ids)
    for s in steps:
        if s.module not in known:
            errors.append(f"未知模块: {s.module} (step={s.step_id})")
            continue
        try:
            mod = get_attack_module(s.module)
            if mod.mock_only and not allow_mock_only:
                errors.append(f"mock_only 模块不可用: {s.module} (step={s.step_id})")
        except ValueError as exc:
            errors.append(str(exc))
        if s.depends_on:
            if s.depends_on not in id_set:
                errors.append(f"depends_on 指向不存在的 step_id: {s.depends_on} (step={s.step_id})")
            elif s.depends_on == s.step_id:
                errors.append(f"不可自依赖: {s.step_id}")
            else:
                # 前置必须出现在本步之前（禁止前向引用环的简单线性约束）
                if ids.index(s.depends_on) >= ids.index(s.step_id):
                    errors.append(f"depends_on 必须指向更早的步骤: {s.step_id} → {s.depends_on}")
    return errors


def parse_chain_proposal(arguments: dict[str, Any], *, allow_mock_only: bool = True) -> tuple[AuditChainProposal | None, list[str]]:
    """从 tool arguments 解析并校验攻击链。"""
    raw_steps = arguments.get("steps") or []
    if not isinstance(raw_steps, list):
        return None, ["steps 必须是数组"]

    steps: list[AuditChainStep] = []
    try:
        for i, item in enumerate(raw_steps):
            if not isinstance(item, dict):
                return None, [f"steps[{i}] 必须是对象"]
            data = dict(item)
            if not data.get("step_id"):
                data["step_id"] = f"s{i + 1}"
            steps.append(AuditChainStep.model_validate(data))
    except Exception as exc:  # noqa: BLE001
        return None, [f"steps 解析失败: {exc}"]

    errors = validate_chain_steps(steps, allow_mock_only=allow_mock_only)
    if errors:
        return None, errors

    chain_id = str(arguments.get("chain_id") or f"chain-{uuid.uuid4().hex[:8]}")
    proposal = AuditChainProposal(
        chain_id=chain_id,
        name=str(arguments.get("name") or ""),
        objective=str(arguments.get("objective") or ""),
        steps=steps,
    )
    return proposal, []


class ChainRuntime:
    """会话内活跃攻击链状态：提议 → 逐步执行 → 输出传递。"""

    def __init__(self) -> None:
        self.proposal: AuditChainProposal | None = None
        self.completed: set[str] = set()
        self.outputs: dict[str, dict[str, Any]] = {}  # step_id → outputs
        self.edges: list[dict[str, Any]] = []
        self.history: list[dict[str, Any]] = []  # 历次 propose 快照

    def propose(self, proposal: AuditChainProposal) -> dict[str, Any]:
        self.proposal = proposal
        self.completed.clear()
        self.outputs.clear()
        self.edges.clear()
        snap = proposal.model_dump()
        self.history.append(snap)
        edges_preview = []
        for s in proposal.steps:
            if s.depends_on:
                edges_preview.append(
                    {
                        "from_step": s.depends_on,
                        "to_step": s.step_id,
                        "from_module": next(
                            (x.module for x in proposal.steps if x.step_id == s.depends_on), "?"
                        ),
                        "to_module": s.module,
                    }
                )
        return {
            "tool": "propose_chain",
            "accepted": True,
            "chain_id": proposal.chain_id,
            "name": proposal.name,
            "objective": proposal.objective,
            "steps": [s.model_dump() for s in proposal.steps],
            "edges": edges_preview,
            "next_step_id": proposal.steps[0].step_id if proposal.steps else None,
            "hint": "请按顺序调用 run_chain_step 执行；后置步会自动合并前置 outputs → params",
        }

    def next_pending_step(self) -> AuditChainStep | None:
        if not self.proposal:
            return None
        for s in self.proposal.steps:
            if s.step_id not in self.completed:
                return s
        return None

    def get_step(self, step_id: str) -> AuditChainStep | None:
        if not self.proposal:
            return None
        for s in self.proposal.steps:
            if s.step_id == step_id:
                return s
        return None

    def resolve_arguments(
        self,
        step: AuditChainStep,
        *,
        default_task: str | None = None,
        with_defense: bool = False,
    ) -> tuple[dict[str, Any], dict[str, Any] | None]:
        """解析本步攻击参数；若有依赖则合并前置输出。返回 (arguments, edge_info|None)。"""
        params = dict(step.params or {})
        edge: dict[str, Any] | None = None
        if step.depends_on:
            prev = self.outputs.get(step.depends_on)
            if prev is None:
                raise ValueError(f"前置步骤尚未执行: {step.depends_on}")
            params, applied = merge_params_from_prev(step, prev)
            prev_mod = prev.get("module") or "?"
            edge = {
                "from_step": step.depends_on,
                "to_step": step.step_id,
                "from_module": prev_mod,
                "to_module": step.module,
                "mapped_params": applied,
            }
        args: dict[str, Any] = {
            "num_variants": step.num_variants,
            "params": params,
            "with_defense": with_defense,
        }
        if step.task or default_task:
            args["task"] = step.task or default_task
        return args, edge

    def mark_completed(self, step_id: str, outputs: dict[str, Any], edge: dict[str, Any] | None) -> None:
        self.completed.add(step_id)
        self.outputs[step_id] = outputs
        if edge:
            self.edges.append(edge)

    def status(self) -> dict[str, Any]:
        pending = self.next_pending_step()
        return {
            "chain_id": self.proposal.chain_id if self.proposal else None,
            "completed": sorted(self.completed),
            "pending_step_id": pending.step_id if pending else None,
            "done": bool(self.proposal) and pending is None,
            "edges": list(self.edges),
        }

    def to_report_fields(self) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        return list(self.history), list(self.edges)
