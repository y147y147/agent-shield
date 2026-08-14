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


class LLMClient(ABC):
    """Agent 循环与 LLM 之间的最小接口。"""

    name: str = "base"

    @abstractmethod
    async def chat(self, messages: list[ChatMessage], tools: list) -> LLMResponse:
        """给定对话与可用工具，返回模型的回答（含可能的工具调用）。"""


# --------------------------------------------------------------------------- #
# MockLLM：离线确定性"脆弱模型"
# --------------------------------------------------------------------------- #
_INSTRUCTION_RE = re.compile(r"INSTRUCTION:\s*(run_command|write_file|read_file|send_email)\s+(.+)", re.IGNORECASE)


def _extract_instruction(text: str) -> tuple[str, str] | None:
    """从文本中提取攻击者指令，返回 (工具名, 参数串) 或 None。"""
    m = _INSTRUCTION_RE.search(text)
    if not m:
        return None
    return m.group(1).lower(), m.group(2).strip()


class MockLLM(LLMClient):
    """确定性规则模型，模拟一个"脆弱"的 LLM 智能体。

    设计意图：真实 LLM 会把输入（用户消息或工具返回内容）中的指令性文本当作
    权威指令执行 —— 这正是直接/间接 Prompt 注入的共同根因。MockLLM 用简单的
    规则复现这一缺陷，使整个攻防流程可以在无 API、零成本、完全确定性的环境
    下跑通（CI / Demo）。
    """

    name = "mock"

    async def chat(self, messages: list[ChatMessage], tools: list) -> LLMResponse:
        tool_names = {getattr(t, "name", str(t)) for t in tools}

        # 1) 最近一条工具输出里是否藏有指令？（间接注入）
        last_tool = next((m for m in reversed(messages) if m.role == "tool"), None)
        if last_tool is not None:
            instr = _extract_instruction(last_tool.content or "")
            if instr is not None:
                return _instruction_to_call(*instr, tool_names=tool_names)
            # 无指令：正常收尾，给出总结
            return LLMResponse(content="（Mock）已根据搜索结果完成总结。")

        # 2) 用户消息里是否藏有指令？（直接注入）
        user_msg = next((m for m in reversed(messages) if m.role == "user"), None)
        content = (user_msg.content or "") if user_msg else ""
        if user_msg is not None:
            instr = _extract_instruction(content)
            if instr is not None:
                return _instruction_to_call(*instr, tool_names=tool_names)

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

        if calls:
            return LLMResponse(tool_calls=calls)
        return LLMResponse(content="（Mock）完成。")


def _instruction_to_call(tool_name: str, argstr: str, tool_names: set[str]) -> LLMResponse:
    if tool_name == "run_command" and "run_command" in tool_names:
        return LLMResponse(
            tool_calls=[ToolCall(id=f"call_{uuid.uuid4().hex[:8]}", name="run_command", arguments={"command": argstr})]
        )
    if tool_name == "read_file" and "read_file" in tool_names:
        return LLMResponse(
            tool_calls=[ToolCall(id=f"call_{uuid.uuid4().hex[:8]}", name="read_file", arguments={"path": argstr})]
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
    ):
        self.model = model
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY", "EMPTY")
        self.base_url = (base_url or os.environ.get("OPENAI_BASE_URL") or "https://api.openai.com/v1").rstrip("/")
        self.temperature = temperature
        self.timeout = timeout

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

        tool_calls: list[ToolCall] = []
        for tc in choice.get("tool_calls") or []:
            try:
                arguments = json.loads(tc["function"].get("arguments") or "{}")
            except json.JSONDecodeError:
                arguments = {"raw": tc["function"].get("arguments")}
            tool_calls.append(ToolCall(id=tc.get("id", f"call_{uuid.uuid4().hex[:8]}"), name=tc["function"]["name"], arguments=arguments))

        return LLMResponse(content=choice.get("content"), tool_calls=tool_calls)


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
