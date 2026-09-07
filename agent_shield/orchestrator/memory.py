"""ReAct 会话记忆：messages + AttemptLog 旁路结构（B3）。"""

from __future__ import annotations

import json
from typing import Any

from agent_shield.models import AttemptLog, AuditStepResult, ChatMessage, ToolCall


class SessionMemory:
    """审计指挥官会话状态：完整对话 + 结构化尝试记录。"""

    def __init__(self, *, messages: list[ChatMessage], objective: str) -> None:
        self.messages = messages
        self.objective = objective
        self.attempts: list[AttemptLog] = []
        self.step_results: list[AuditStepResult] = []
        from agent_shield.orchestrator.chain import ChainRuntime

        self.chain_runtime = ChainRuntime()

    def module_attempt_count(self, module: str) -> int:
        return sum(1 for a in self.attempts if a.module == module)

    def attempted_modules(self) -> list[str]:
        seen: set[str] = set()
        out: list[str] = []
        for a in self.attempts:
            if a.module not in seen:
                seen.add(a.module)
                out.append(a.module)
        return out

    def config_key(self, module: str, arguments: dict[str, Any]) -> tuple[Any, ...]:
        params = arguments.get("params") or {}
        if not isinstance(params, dict):
            params = {}
        return (
            module,
            arguments.get("task") or "",
            int(arguments.get("num_variants") or 3),
            json.dumps(params, sort_keys=True, ensure_ascii=False),
            bool(arguments.get("with_defense", False)),
        )

    def has_duplicate_config(self, module: str, arguments: dict[str, Any]) -> bool:
        key = self.config_key(module, arguments)
        for a in self.attempts:
            if a.module != module:
                continue
            existing = (
                a.module,
                a.task,
                a.num_variants,
                json.dumps(a.params, sort_keys=True, ensure_ascii=False),
                a.defense_on,
            )
            if existing == key:
                return True
        return False

    def record_step(
        self,
        *,
        module: str,
        arguments: dict[str, Any],
        step: AuditStepResult,
    ) -> None:
        summary = step.result_summary or {}
        params = arguments.get("params") or {}
        if not isinstance(params, dict):
            params = {}
        self.attempts.append(
            AttemptLog(
                module=module,
                task=str(arguments.get("task") or ""),
                num_variants=int(arguments.get("num_variants") or 3),
                params=dict(params),
                defense_on=step.defense_on,
                bypass_index=step.bypass_index,
                successes=int(summary.get("successes") or 0),
                blocked=int(summary.get("blocked") or 0),
                failed=int(summary.get("failed") or 0),
                success_rate=float(summary.get("success_rate") or 0.0),
                error=step.error,
            )
        )
        self.step_results.append(step)

    def append_assistant(self, content: str | None, tool_calls: list[ToolCall] | None = None) -> None:
        self.messages.append(ChatMessage.assistant(content, tool_calls=tool_calls))

    def append_tool_result(self, tool_call: ToolCall, content: str) -> None:
        self.messages.append(
            ChatMessage.tool(content, tool_call_id=tool_call.id, name=tool_call.name)
        )

    def attempts_summary_text(self, *, limit: int = 12) -> str:
        if not self.attempts:
            return "（尚无尝试记录）"
        lines: list[str] = []
        for a in self.attempts[-limit:]:
            if a.error:
                lines.append(
                    f"- {a.module} bypass={a.bypass_index} defense={'on' if a.defense_on else 'off'} "
                    f"ERROR: {a.error}"
                )
            else:
                lines.append(
                    f"- {a.module} bypass={a.bypass_index} defense={'on' if a.defense_on else 'off'} "
                    f"variants={a.num_variants} params={json.dumps(a.params, ensure_ascii=False)} "
                    f"成功={a.successes}/{a.successes + a.blocked + a.failed} "
                    f"rate={a.success_rate:.0%}"
                )
        return "\n".join(lines)

    def messages_for_planner(self) -> list[ChatMessage]:
        """回传 LLM 前注入已尝试摘要（截断 trace，保留 summary）。"""
        if not self.attempts:
            return list(self.messages)
        summary = self.attempts_summary_text()
        return [
            *self.messages,
            ChatMessage.user(f"[系统] 已尝试摘要（请勿无 Observation 重复相同参数）：\n{summary}"),
        ]
