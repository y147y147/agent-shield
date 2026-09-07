"""Phase B：ReAct 自主决策主循环。"""

from __future__ import annotations

import json
import uuid
from collections.abc import Callable
from typing import Any

from agent_shield.attacks import get_attack_module
from agent_shield.models import AuditSessionReport, AuditStepResult, ChatMessage, ToolCall, aggregate_audit_session
from agent_shield.orchestrator.memory import SessionMemory
from agent_shield.orchestrator.plan_execute import _observation_to_step_result
from agent_shield.orchestrator.prompts import build_react_system_prompt, build_react_user_message
from agent_shield.orchestrator.tools_bridge import (
    META_ANALYZE_PROXY_EVENTS,
    META_FINISH_AUDIT,
    META_LIST_COVERAGE,
    META_PROPOSE_CHAIN,
    META_RUN_CHAIN_STEP,
    META_TOOLS,
    build_attack_tools,
    execute_attack_tool,
)
from agent_shield.runtime.llm import LLMClient, LLMResponse
from agent_shield.targets.base import AgentTarget

TargetFactory = Callable[..., AgentTarget]
EventSink = Callable[[dict[str, Any]], None]


def _emit(on_event: EventSink | None, event: dict[str, Any]) -> None:
    if on_event is None:
        return
    try:
        on_event(event)
    except Exception:  # noqa: BLE001
        pass


def _is_attack_tool(name: str) -> bool:
    if name in META_TOOLS:
        return False
    try:
        get_attack_module(name)
        return True
    except ValueError:
        return False


class ScriptedReActLLM(LLMClient):
    """测试用：按脚本顺序返回 tool_calls（用于 bypass / 改参单测）。"""

    name = "scripted-react"

    def __init__(self, script: list[LLMResponse]) -> None:
        self._script = list(script)
        self._index = 0

    async def chat(self, messages: list[ChatMessage], tools: list) -> LLMResponse:
        if self._index >= len(self._script):
            return LLMResponse(
                tool_calls=[
                    ToolCall(id=f"fin_{uuid.uuid4().hex[:6]}", name=META_FINISH_AUDIT, arguments={})
                ]
            )
        resp = self._script[self._index]
        self._index += 1
        return resp


class DefaultReActLLM(LLMClient):
    """离线 CI 用 ReAct 指挥官：固定脚本（coverage → 3 模块 → finish）。"""

    name = "default-react"

    def __init__(self, *, use_proxy_analysis: bool = False) -> None:
        self._index = 0
        self._script: list[LLMResponse] = []
        if use_proxy_analysis:
            self._script.append(
                LLMResponse(
                    content="Thought: 先分析旁路 Proxy 流量。",
                    tool_calls=[
                        ToolCall(id="p0", name=META_ANALYZE_PROXY_EVENTS, arguments={"limit": 50})
                    ],
                )
            )
        self._script.extend(
            [
            LLMResponse(
                content="Thought: 先查看覆盖缺口。",
                tool_calls=[ToolCall(id="t0", name=META_LIST_COVERAGE, arguments={})],
            ),
            LLMResponse(
                content="Thought: 先测直接注入。",
                tool_calls=[
                    ToolCall(
                        id="t1",
                        name="direct_injection",
                        arguments={"num_variants": 2},
                    )
                ],
            ),
            LLMResponse(
                content="Thought: 再测间接注入。",
                tool_calls=[
                    ToolCall(
                        id="t2",
                        name="indirect_injection",
                        arguments={"num_variants": 2},
                    )
                ],
            ),
            LLMResponse(
                content="Thought: 验证越权边界。",
                tool_calls=[
                    ToolCall(
                        id="t3",
                        name="privilege_escalation",
                        arguments={"num_variants": 2},
                    )
                ],
            ),
            LLMResponse(
                content="Thought: 覆盖完成，输出终报。",
                tool_calls=[
                    ToolCall(
                        id="t4",
                        name=META_FINISH_AUDIT,
                        arguments={"narrative": "离线 DefaultReActLLM：完成注入与越权覆盖。"},
                    )
                ],
            ),
            ]
        )

    async def chat(self, messages: list[ChatMessage], tools: list) -> LLMResponse:
        if self._index >= len(self._script):
            return LLMResponse(
                tool_calls=[
                    ToolCall(id="fin", name=META_FINISH_AUDIT, arguments={"narrative": "已达脚本末尾"})
                ]
            )
        resp = self._script[self._index]
        self._index += 1
        return resp


async def _run_attack_tool_call(
    name: str,
    arguments: dict[str, Any],
    *,
    task: str,
    target_factory: TargetFactory,
    compare_defense: bool,
    include_mock_only: bool,
    bypass_index: int,
    attempted: list[str],
    export_traces: bool = False,
    hitl_confirmed_modules: set[str] | frozenset[str] | None = None,
) -> list[AuditStepResult]:
    arguments = dict(arguments or {})
    if "task" not in arguments or not arguments.get("task"):
        arguments["task"] = task

    vulnerable = target_factory(defense=False)
    defended = target_factory(defense=True) if compare_defense else None
    results: list[AuditStepResult] = []

    raw_v = await execute_attack_tool(
        name,
        {**arguments, "with_defense": False},
        target_vulnerable=vulnerable,
        target_defended=defended,
        allow_mock_only=include_mock_only,
        attempted=attempted,
        default_task=task,
        export_traces=export_traces,
        hitl_confirmed_modules=hitl_confirmed_modules,
    )
    step_v = _observation_to_step_result(name, defense_on=False, raw=raw_v, bypass_index=bypass_index)
    try:
        hitl_data = json.loads(raw_v)
        if hitl_data.get("hitl_required"):
            return [step_v]
    except json.JSONDecodeError:
        pass
    results.append(step_v)

    if compare_defense:
        vulnerable2 = target_factory(defense=False)
        defended2 = target_factory(defense=True)
        raw_d = await execute_attack_tool(
            name,
            {**arguments, "with_defense": True},
            target_vulnerable=vulnerable2,
            target_defended=defended2,
            allow_mock_only=include_mock_only,
            attempted=attempted,
            default_task=task,
            export_traces=export_traces,
            hitl_confirmed_modules=hitl_confirmed_modules,
        )
        step_d = _observation_to_step_result(name, defense_on=True, raw=raw_d, bypass_index=bypass_index)
        results.append(step_d)

    return results


async def audit_agent_loop(
    *,
    planner: LLMClient,
    target_factory: TargetFactory,
    task: str,
    max_turns: int = 12,
    max_bypass_per_module: int = 5,
    compare_defense: bool = True,
    include_mock_only: bool = True,
    objective: str | None = None,
    on_event: EventSink | None = None,
    proxy_store: Any | None = None,
    export_traces: bool = False,
    hitl_confirmed_modules: set[str] | frozenset[str] | None = None,
) -> AuditSessionReport:
    """ReAct：每轮 Thought→Action→Observation，本地聚合终报（B2/B4）。"""
    from agent_shield.orchestrator.usage import UsageTrackingPlanner

    usage_tracker = UsageTrackingPlanner(planner)
    planner = usage_tracker
    obj = objective or task
    has_proxy = proxy_store is not None and getattr(proxy_store, "count", lambda: 0)() > 0
    memory = SessionMemory(
        messages=[
            ChatMessage.system(
                build_react_system_prompt(
                    max_turns=max_turns,
                    max_bypass_per_module=max_bypass_per_module,
                    allow_mock_only=include_mock_only,
                    compare_defense=compare_defense,
                    has_proxy_events=has_proxy,
                )
            ),
            ChatMessage.user(
                build_react_user_message(
                    task=task,
                    objective=objective,
                    compare_defense=compare_defense,
                    has_proxy_events=has_proxy,
                )
            ),
        ],
        objective=obj,
    )
    tools = build_attack_tools(
        include_mock_only=include_mock_only,
        include_proxy_analysis=proxy_store is not None,
    )
    narrative = ""
    finished = False

    _emit(on_event, {"type": "phase", "label": "ReAct 自主决策循环", "text": ""})

    for turn in range(max_turns):
        if finished:
            break

        _emit(on_event, {"type": "think", "text": f"轮次 {turn + 1}/{max_turns}"})
        response = await planner.chat(memory.messages_for_planner(), tools)

        if response.content and not response.tool_calls:
            memory.append_assistant(response.content)
            _emit(on_event, {"type": "llm", "text": response.content})
            continue

        if not response.tool_calls:
            break

        memory.append_assistant(response.content, tool_calls=response.tool_calls)
        if response.content:
            _emit(on_event, {"type": "think", "text": response.content})

        for tc in response.tool_calls:
            if finished:
                break

            if tc.name == META_FINISH_AUDIT:
                raw = await execute_attack_tool(
                    META_FINISH_AUDIT,
                    tc.arguments,
                    target_vulnerable=target_factory(defense=False),
                    target_defended=None,
                )
                try:
                    data = json.loads(raw)
                    narrative = str(data.get("narrative") or "")
                except json.JSONDecodeError:
                    narrative = tc.arguments.get("narrative") or ""
                memory.append_tool_result(tc, raw)
                _emit(on_event, {"type": "final", "text": narrative or "finish_audit"})
                finished = True
                continue

            if tc.name == META_LIST_COVERAGE:
                raw = await execute_attack_tool(
                    META_LIST_COVERAGE,
                    tc.arguments,
                    target_vulnerable=target_factory(defense=False),
                    target_defended=None,
                    allow_mock_only=include_mock_only,
                    attempted=memory.attempted_modules(),
                    proxy_store=proxy_store,
                )
                memory.append_tool_result(tc, raw)
                _emit(on_event, {"type": "output", "tool": META_LIST_COVERAGE, "text": raw[:500]})
                continue

            if tc.name == META_ANALYZE_PROXY_EVENTS:
                raw = await execute_attack_tool(
                    META_ANALYZE_PROXY_EVENTS,
                    tc.arguments,
                    target_vulnerable=target_factory(defense=False),
                    target_defended=None,
                    proxy_store=proxy_store,
                )
                memory.append_tool_result(tc, raw)
                _emit(on_event, {"type": "output", "tool": META_ANALYZE_PROXY_EVENTS, "text": raw[:800]})
                continue

            if tc.name == META_PROPOSE_CHAIN:
                raw = await execute_attack_tool(
                    META_PROPOSE_CHAIN,
                    tc.arguments,
                    target_vulnerable=target_factory(defense=False),
                    target_defended=None,
                    allow_mock_only=include_mock_only,
                    chain_runtime=memory.chain_runtime,
                )
                memory.append_tool_result(tc, raw)
                try:
                    data = json.loads(raw)
                except json.JSONDecodeError:
                    data = {}
                edges = data.get("edges") or []
                _emit(
                    on_event,
                    {
                        "type": "chain",
                        "label": f"propose_chain `{data.get('chain_id') or '?'}`",
                        "text": json.dumps(
                            {"name": data.get("name"), "steps": data.get("steps"), "edges": edges},
                            ensure_ascii=False,
                        )[:1200],
                        "edges": edges,
                    },
                )
                _emit(on_event, {"type": "output", "tool": META_PROPOSE_CHAIN, "text": raw[:800]})
                continue

            if tc.name == META_RUN_CHAIN_STEP:
                vulnerable = target_factory(defense=False)
                defended = target_factory(defense=True) if compare_defense else None
                raw = await execute_attack_tool(
                    META_RUN_CHAIN_STEP,
                    tc.arguments,
                    target_vulnerable=vulnerable,
                    target_defended=defended,
                    allow_mock_only=include_mock_only,
                    default_task=task,
                    export_traces=export_traces,
                    chain_runtime=memory.chain_runtime,
                    hitl_confirmed_modules=hitl_confirmed_modules,
                )
                memory.append_tool_result(tc, raw)
                try:
                    data = json.loads(raw)
                except json.JSONDecodeError:
                    data = {"error": raw}

                edge = data.get("edge")
                if edge:
                    _emit(
                        on_event,
                        {
                            "type": "chain",
                            "label": f"{edge.get('from_module')} → {edge.get('to_module')}",
                            "from_step": edge.get("from_step"),
                            "to_step": edge.get("to_step"),
                            "from_module": edge.get("from_module"),
                            "to_module": edge.get("to_module"),
                            "mapped_params": edge.get("mapped_params") or {},
                            "text": json.dumps(edge.get("mapped_params") or {}, ensure_ascii=False),
                        },
                    )

                attack = data.get("attack") or {}
                module = str(data.get("module") or "chain_step")
                if isinstance(attack, dict) and (attack.get("summary") or attack.get("error") or attack.get("skipped")):
                    step = _observation_to_step_result(
                        module,
                        defense_on=bool(attack.get("defense_on")),
                        raw=json.dumps(attack, ensure_ascii=False),
                        bypass_index=0,
                    )
                    memory.record_step(
                        module=module,
                        arguments={"params": data.get("resolved_params") or {}, "chain_step": data.get("step_id")},
                        step=step,
                    )
                    text = (
                        f"chain {data.get('step_id')}: {module} "
                        f"成功 {step.result_summary.get('successes', 0)}/"
                        f"{step.result_summary.get('total', 0)}"
                    )
                    if step.error:
                        text = f"chain {data.get('step_id')}: 错误 {step.error}"
                    _emit(on_event, {"type": "output", "tool": META_RUN_CHAIN_STEP, "text": text})
                else:
                    _emit(
                        on_event,
                        {
                            "type": "error" if data.get("error") else "output",
                            "tool": META_RUN_CHAIN_STEP,
                            "text": raw[:800],
                        },
                    )
                continue

            if not _is_attack_tool(tc.name):
                err = json.dumps({"error": f"未知工具: {tc.name}"}, ensure_ascii=False)
                memory.append_tool_result(tc, err)
                _emit(on_event, {"type": "error", "text": err})
                continue

            attempt_count = memory.module_attempt_count(tc.name)
            if attempt_count >= max_bypass_per_module:
                err = json.dumps(
                    {
                        "module": tc.name,
                        "error": f"已达 bypass 上限 {max_bypass_per_module}，请换模块或 finish_audit",
                    },
                    ensure_ascii=False,
                )
                memory.append_tool_result(tc, err)
                _emit(on_event, {"type": "error", "text": err})
                continue

            if memory.has_duplicate_config(tc.name, tc.arguments):
                err = json.dumps(
                    {
                        "module": tc.name,
                        "error": "禁止无 Observation 重复相同参数；请修改 num_variants/params 或换模块",
                    },
                    ensure_ascii=False,
                )
                memory.append_tool_result(tc, err)
                _emit(on_event, {"type": "error", "text": err})
                continue

            bypass_index = attempt_count
            _emit(
                on_event,
                {
                    "type": "phase",
                    "label": f"Action: `{tc.name}` bypass={bypass_index}",
                    "text": json.dumps(tc.arguments, ensure_ascii=False),
                },
            )

            steps = await _run_attack_tool_call(
                tc.name,
                tc.arguments,
                task=task,
                target_factory=target_factory,
                compare_defense=compare_defense,
                include_mock_only=include_mock_only,
                bypass_index=bypass_index,
                attempted=memory.attempted_modules(),
                export_traces=export_traces,
                hitl_confirmed_modules=hitl_confirmed_modules,
            )

            observations: list[str] = []
            for step in steps:
                memory.record_step(module=tc.name, arguments=tc.arguments, step=step)
                text = (
                    f"{'防护' if step.defense_on else '脆弱'} "
                    f"成功 {step.result_summary.get('successes', 0)}/"
                    f"{step.result_summary.get('total', 0)}"
                )
                if step.error:
                    text = f"错误: {step.error}"
                    if step.error.startswith("HITL:"):
                        _emit(
                            on_event,
                            {
                                "type": "hitl",
                                "module": tc.name,
                                "reason": step.error.replace("HITL:", "").strip(),
                                "text": step.error,
                            },
                        )
                observations.append(text)
                _emit(on_event, {"type": "output", "tool": tc.name, "text": text})

            obs_json = json.dumps(
                {"module": tc.name, "observations": observations, "steps": [s.model_dump() for s in steps]},
                ensure_ascii=False,
            )
            memory.append_tool_result(tc, obs_json)

    modules_executed = memory.attempted_modules()
    chains, chain_edges = memory.chain_runtime.to_report_fields()
    return aggregate_audit_session(
        mode="react",
        objective=obj,
        modules_planned=modules_executed,
        steps=memory.step_results,
        narrative=narrative,
        chains=chains,
        chain_edges=chain_edges,
        planner_usage=usage_tracker.accumulator.to_dict(),
    )
