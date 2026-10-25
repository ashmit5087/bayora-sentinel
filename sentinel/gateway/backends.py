"""Model backends behind the gateway.

The mock backend validates pipeline mechanics only. It says nothing about real
model behaviour, and every result produced with it must be labelled as such.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Protocol

import httpx


@dataclass
class CompletionResult:
    text: str
    # llama.cpp's own timing report. It is a direct cache oracle, so the
    # gateway keeps it server-side and NEVER returns it to tenants.
    server_timings: dict | None = None


class ModelBackend(Protocol):
    async def complete(self, prompt: str, max_tokens: int, *, slot: int | None, cache_prompt: bool) -> CompletionResult: ...


class MockBackend:
    """Deterministic, stateless stand-in for a model."""

    async def complete(self, prompt: str, max_tokens: int, *, slot: int | None, cache_prompt: bool) -> CompletionResult:
        digest = hashlib.sha256(prompt.encode("utf-8")).hexdigest()[:8]
        return CompletionResult(text=f"[mock:{digest}] acknowledged")


class LlamaBackend:
    """llama.cpp server (/completion). `slot` pins the request to one KV-cache slot."""

    def __init__(self, base_url: str, timeout_s: float = 120.0):
        self._client = httpx.AsyncClient(base_url=base_url.rstrip("/"), timeout=timeout_s)

    async def complete(self, prompt: str, max_tokens: int, *, slot: int | None, cache_prompt: bool) -> CompletionResult:
        payload: dict = {
            "prompt": prompt,
            "n_predict": max_tokens,
            "temperature": 0,
            "cache_prompt": cache_prompt,
            "stream": False,
        }
        if slot is not None:
            payload["id_slot"] = slot
        resp = await self._client.post("/completion", json=payload)
        resp.raise_for_status()
        body = resp.json()
        return CompletionResult(text=body.get("content", ""), server_timings=body.get("timings"))
