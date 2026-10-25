"""The gateway: the only approved path to the model.

Every request is authenticated, scoped, rate-limited and audited before the
model is touched. Authorization is enforced here, in the backend, not in the UI.

Run:  uvicorn --factory sentinel.gateway.app:create_app_from_env --port 8000
"""
from __future__ import annotations

import hashlib
import hmac
import os
import time
import uuid
from collections import deque
from typing import Callable

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, ValidationError

from sentinel.audit.chain import AuditChain
from sentinel.common.secrets import get_secret

from .audit_sink import AuditSink, AuditUnavailable, HttpAuditSink, LocalAuditSink
from .backends import LlamaBackend, MockBackend, ModelBackend
from .settings import SCOPES, Settings


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class CompleteIn(BaseModel):
    prompt: str = Field(min_length=1)
    max_tokens: int = Field(default=64, ge=1)
    session_id: str | None = Field(default=None, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")


class RateLimiter:
    """Sliding one-minute window per key."""

    def __init__(self, limit_per_min: int, clock: Callable[[], float] = time.monotonic):
        self.limit = limit_per_min
        self.clock = clock
        self._hits: dict[str, deque[float]] = {}

    def allow(self, key: str) -> bool:
        now = self.clock()
        hits = self._hits.setdefault(key, deque())
        while hits and now - hits[0] >= 60.0:
            hits.popleft()
        if len(hits) >= self.limit:
            return False
        hits.append(now)
        return True


def authenticate(settings: Settings, authorization: str | None, x_tenant: str | None) -> tuple[str | None, str]:
    """Return (tenant, reason). tenant is None when authentication fails."""
    if not authorization or not authorization.lower().startswith("bearer "):
        return None, "missing_bearer"
    token = authorization[7:].strip().encode()

    if settings.auth_mode == "shared_static":
        # INSECURE BY DESIGN (used only by the insecure compose file): one shared
        # key, and the caller simply claims which tenant it is.
        if settings.shared_api_key and hmac.compare_digest(token, settings.shared_api_key.encode()):
            return (x_tenant or "unknown"), "ok"
        return None, "bad_token"

    matched = None
    for tenant, secret in settings.tenant_tokens.items():
        if hmac.compare_digest(token, secret.encode()):  # check all, do not short-circuit
            matched = tenant
    return (matched, "ok") if matched else (None, "bad_token")


def route(settings: Settings, tenant: str) -> tuple[int | None, bool]:
    """Return (kv-cache slot, cache_prompt) for this tenant under the configured cache mode."""
    if settings.cache_mode == "isolated":
        if tenant not in settings.slot_map:
            raise LookupError(tenant)
        return settings.slot_map[tenant], True
    if settings.cache_mode == "off":
        return None, False
    return None, True  # shared


def create_app(
    settings: Settings,
    backend: ModelBackend,
    audit: AuditSink,
    clock: Callable[[], float] = time.monotonic,
) -> FastAPI:
    app = FastAPI(title="Sentinel Gateway", docs_url=None, redoc_url=None, openapi_url=None)
    limiter = RateLimiter(settings.rate_limit_per_min, clock)
    closed = settings.audit_fail_mode == "closed"

    async def record(actor: str, action: str, details: dict) -> bool:
        try:
            await audit.append(actor, action, details)
            return True
        except AuditUnavailable:
            return False

    async def authn(request: Request) -> tuple[str | None, JSONResponse | None]:
        tenant, reason = authenticate(settings, request.headers.get("authorization"), request.headers.get("x-tenant"))
        if tenant is None:
            await record("anonymous", "auth.denied", {"reason": reason, "path": request.url.path})
            return None, JSONResponse({"detail": "unauthorized"}, status_code=401)
        return tenant, None

    @app.get("/health")
    async def health() -> dict:
        return {"status": "ok"}

    @app.get("/v1/whoami")
    async def whoami(request: Request):
        tenant, err = await authn(request)
        if err:
            return err
        scopes = SCOPES.get(tenant, frozenset())
        if "whoami" not in scopes:
            await record(tenant, "authz.denied", {"needed": "whoami", "path": request.url.path})
            return JSONResponse({"detail": "forbidden"}, status_code=403)
        return {"tenant": tenant, "scopes": sorted(scopes)}

    @app.post("/v1/complete")
    async def complete(request: Request):
        tenant, err = await authn(request)
        if err:
            return err
        if "complete" not in SCOPES.get(tenant, frozenset()):
            await record(tenant, "authz.denied", {"needed": "complete", "path": request.url.path})
            return JSONResponse({"detail": "forbidden"}, status_code=403)

        try:
            raw = await request.json()
        except Exception:
            return JSONResponse({"detail": "invalid json"}, status_code=400)
        try:
            req = CompleteIn.model_validate(raw)
        except ValidationError:
            return JSONResponse({"detail": "invalid request"}, status_code=422)  # do not echo input back

        if len(req.prompt) > settings.max_prompt_chars:
            await record(tenant, "request.rejected", {"reason": "prompt_too_large", "prompt_len": len(req.prompt)})
            return JSONResponse({"detail": "prompt too large"}, status_code=413)

        if not limiter.allow(tenant):
            await record(tenant, "ratelimit.denied", {})
            return JSONResponse({"detail": "rate limit exceeded"}, status_code=429)

        try:
            slot, cache_prompt = route(settings, tenant)
        except LookupError:
            await record(tenant, "authz.denied", {"needed": "cache_slot", "path": request.url.path})
            return JSONResponse({"detail": "no cache slot assigned"}, status_code=403)

        request_id = uuid.uuid4().hex
        max_tokens = min(req.max_tokens, settings.max_tokens_cap)

        # Raw prompts are never written to the audit trail: only a hash and a length.
        logged = await record(tenant, "gateway.request", {
            "request_id": request_id,
            "prompt_sha256": sha256_hex(req.prompt),
            "prompt_len": len(req.prompt),
            "session_id": req.session_id,
            "cache_mode": settings.cache_mode,
            "slot": slot,
            "max_tokens": max_tokens,
        })
        if not logged and closed:
            return JSONResponse({"detail": "audit unavailable"}, status_code=503)  # fail closed: no model call

        t0 = time.perf_counter()
        try:
            result = await backend.complete(req.prompt, max_tokens, slot=slot, cache_prompt=cache_prompt)
        except Exception as exc:
            await record(tenant, "gateway.error", {"request_id": request_id, "error": type(exc).__name__})
            return JSONResponse({"detail": "model backend error"}, status_code=502)
        latency_ms = round((time.perf_counter() - t0) * 1000.0, 2)

        logged = await record(tenant, "gateway.response", {
            "request_id": request_id,
            "latency_ms": latency_ms,
            "response_sha256": sha256_hex(result.text),
            "response_len": len(result.text),
        })
        if not logged and closed:
            return JSONResponse({"detail": "audit unavailable"}, status_code=503)  # unaudited output is withheld

        # Note: result.server_timings is deliberately NOT returned. It reports how
        # many prompt tokens were served from cache, which is a direct oracle.
        return {
            "request_id": request_id,
            "tenant": tenant,
            "text": result.text,
            "latency_ms": latency_ms,
            "cache_mode": settings.cache_mode,
        }

    return app


def create_app_from_env() -> FastAPI:
    settings = Settings.from_env()
    backend: ModelBackend = LlamaBackend(settings.llama_url) if settings.backend == "llama" else MockBackend()

    audit_url = os.environ.get("AUDIT_URL")
    write_token = get_secret("AUDIT_WRITE_TOKEN")
    if audit_url and write_token:
        sink: AuditSink = HttpAuditSink(audit_url, write_token)
    elif os.environ.get("AUDIT_CHAIN_PATH"):
        sink = LocalAuditSink(AuditChain(os.environ["AUDIT_CHAIN_PATH"]))  # single-process dev mode
    else:
        raise ValueError("configure AUDIT_URL + AUDIT_WRITE_TOKEN (or AUDIT_CHAIN_PATH for local dev)")
    return create_app(settings, backend, sink)
