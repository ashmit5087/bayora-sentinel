"""Audit service: append-only HTTP front for the hash chain.

Two separate bearer tokens:
  * write token : held by the gateway, can only POST /append
  * read token  : held by the control plane / signer / dashboard, can read and verify

Run:  uvicorn --factory sentinel.audit.service:create_app_from_env --port 8100
"""
from __future__ import annotations

import hmac
import os
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from sentinel.common.secrets import get_secret

from .chain import AuditChain, parse_file, verify_records
from .checkpoint import load_checkpoints, load_public_key, verify_with_checkpoints


class AppendIn(BaseModel):
    actor: str = Field(min_length=1, max_length=64)
    action: str = Field(min_length=1, max_length=64)
    details: dict = Field(default_factory=dict)


def _bearer_ok(expected: str, authorization: str | None) -> bool:
    if not authorization or not authorization.lower().startswith("bearer "):
        return False
    return hmac.compare_digest(authorization[7:].strip().encode(), expected.encode())


def create_app(
    chain: AuditChain,
    write_token: str,
    read_token: str,
    checkpoint_path: str | Path | None = None,
    public_key_pem: bytes | None = None,
) -> FastAPI:
    if not write_token or not read_token:
        raise ValueError("both AUDIT_WRITE_TOKEN and AUDIT_READ_TOKEN are required (fail closed)")
    if write_token == read_token:
        raise ValueError("write and read tokens must differ")

    app = FastAPI(title="Sentinel Audit", docs_url=None, redoc_url=None, openapi_url=None)
    public_key = load_public_key(public_key_pem) if public_key_pem else None

    def need_write(authorization: str | None) -> None:
        if not _bearer_ok(write_token, authorization):
            raise HTTPException(status_code=401, detail="unauthorized")

    def need_read(authorization: str | None) -> None:
        if not _bearer_ok(read_token, authorization):
            raise HTTPException(status_code=401, detail="unauthorized")

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok"}

    @app.post("/append")
    def append(body: AppendIn, authorization: str | None = Header(default=None)) -> dict:
        need_write(authorization)
        try:
            return chain.append(body.actor, body.action, body.details)
        except TypeError:
            raise HTTPException(status_code=422, detail="details must be JSON-serializable")

    @app.get("/head")
    def head(authorization: str | None = Header(default=None)) -> dict:
        need_read(authorization)
        return chain.head

    @app.get("/records")
    def records(start: int = 0, limit: int = 100, authorization: str | None = Header(default=None)) -> dict:
        need_read(authorization)
        limit = max(1, min(limit, 500))
        return {"start": start, "records": chain.records(start, limit)}

    @app.get("/verify")
    def verify(authorization: str | None = Header(default=None)) -> dict:
        need_read(authorization)
        recs, failure = parse_file(chain.path)
        if failure:
            return {**failure.to_dict(), "checkpoints_checked": 0}
        checkpoints: list[dict] = []
        if checkpoint_path and public_key:
            try:
                checkpoints = load_checkpoints(checkpoint_path)
            except ValueError:
                return {"ok": False, "count": len(recs), "head_hash": "", "broken_at": None,
                        "reason": "checkpoint file unparseable", "checkpoints_checked": 0}
        if checkpoints and public_key:
            result = verify_with_checkpoints(recs, checkpoints, public_key)
        else:
            result = verify_records(recs)
        return {**result.to_dict(), "checkpoints_checked": len(checkpoints)}

    return app


def create_app_from_env() -> FastAPI:
    chain = AuditChain(os.environ.get("AUDIT_CHAIN_PATH", "/data/chain.jsonl"))
    public_key_path = os.environ.get("AUDIT_PUBLIC_KEY_PATH")
    public_pem = Path(public_key_path).read_bytes() if public_key_path and Path(public_key_path).exists() else None
    return create_app(
        chain,
        write_token=get_secret("AUDIT_WRITE_TOKEN") or "",
        read_token=get_secret("AUDIT_READ_TOKEN") or "",
        checkpoint_path=os.environ.get("AUDIT_CHECKPOINT_PATH"),
        public_key_pem=public_pem,
    )
