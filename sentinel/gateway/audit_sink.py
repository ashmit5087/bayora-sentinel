"""Where the gateway sends audit events."""
from __future__ import annotations

from typing import Protocol

import httpx

from sentinel.audit.chain import AuditChain


class AuditUnavailable(Exception):
    """The audit trail could not record an event."""


class AuditSink(Protocol):
    async def append(self, actor: str, action: str, details: dict) -> dict: ...


class HttpAuditSink:
    """Production path: POST to the audit service with the write-only token."""

    def __init__(self, base_url: str, write_token: str, timeout_s: float = 3.0):
        self._client = httpx.AsyncClient(
            base_url=base_url.rstrip("/"),
            headers={"Authorization": f"Bearer {write_token}"},
            timeout=timeout_s,
        )

    async def append(self, actor: str, action: str, details: dict) -> dict:
        try:
            resp = await self._client.post("/append", json={"actor": actor, "action": action, "details": details})
            resp.raise_for_status()
            return resp.json()
        except Exception as exc:  # network error, timeout, non-2xx
            raise AuditUnavailable(type(exc).__name__) from exc


class LocalAuditSink:
    """Dev/test path: write straight to a chain file in-process."""

    def __init__(self, chain: AuditChain):
        self.chain = chain

    async def append(self, actor: str, action: str, details: dict) -> dict:
        try:
            return self.chain.append(actor, action, details)
        except Exception as exc:
            raise AuditUnavailable(type(exc).__name__) from exc
