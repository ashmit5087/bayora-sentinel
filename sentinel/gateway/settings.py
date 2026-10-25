"""Gateway configuration.

Defaults are the SECURE choices. The insecure compose file overrides them on
purpose so the gauntlet can show the difference:

  AUTH_MODE         per_tenant (default) | shared_static  (INSECURE: one key, client-claimed identity)
  CACHE_MODE        isolated   (default) | shared | off
  AUDIT_FAIL_MODE   closed     (default) | open          (INSECURE: serve requests even if audit is down)
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field

from sentinel.common.secrets import get_secret

TENANTS = ("red", "blue", "auditor")

# What each tenant may do. Enforced server-side in the gateway, never in the UI.
SCOPES: dict[str, frozenset[str]] = {
    "red": frozenset({"whoami", "complete"}),
    "blue": frozenset({"whoami", "complete"}),
    "auditor": frozenset({"whoami"}),
}

AUTH_MODES = ("per_tenant", "shared_static")
CACHE_MODES = ("isolated", "shared", "off")
AUDIT_FAIL_MODES = ("closed", "open")
BACKENDS = ("mock", "llama")


@dataclass(frozen=True)
class Settings:
    auth_mode: str = "per_tenant"
    cache_mode: str = "isolated"
    audit_fail_mode: str = "closed"
    backend: str = "mock"
    tenant_tokens: dict[str, str] = field(default_factory=dict)
    shared_api_key: str | None = None
    slot_map: dict[str, int] = field(default_factory=lambda: {"red": 0, "blue": 1})
    rate_limit_per_min: int = 60
    max_prompt_chars: int = 20000
    max_tokens_cap: int = 256
    llama_url: str = "http://model:8080"

    def __post_init__(self) -> None:
        for name, value, allowed in (
            ("auth_mode", self.auth_mode, AUTH_MODES),
            ("cache_mode", self.cache_mode, CACHE_MODES),
            ("audit_fail_mode", self.audit_fail_mode, AUDIT_FAIL_MODES),
            ("backend", self.backend, BACKENDS),
        ):
            if value not in allowed:
                raise ValueError(f"{name}={value!r} is not one of {allowed}")

    @classmethod
    def from_env(cls) -> "Settings":
        tokens = {}
        for tenant in TENANTS:
            value = get_secret(f"GATEWAY_TOKEN_{tenant.upper()}")
            if value:
                tokens[tenant] = value

        settings = cls(
            auth_mode=os.environ.get("AUTH_MODE", "per_tenant"),
            cache_mode=os.environ.get("CACHE_MODE", "isolated"),
            audit_fail_mode=os.environ.get("AUDIT_FAIL_MODE", "closed"),
            backend=os.environ.get("MODEL_BACKEND", "mock"),
            tenant_tokens=tokens,
            shared_api_key=get_secret("GATEWAY_SHARED_API_KEY"),
            slot_map=_parse_slot_map(os.environ.get("GATEWAY_SLOT_MAP", "red:0,blue:1")),
            rate_limit_per_min=int(os.environ.get("RATE_LIMIT_PER_MIN", "60")),
            llama_url=os.environ.get("LLAMA_URL", "http://model:8080"),
        )
        settings.validate_secrets()
        return settings

    def validate_secrets(self) -> None:
        """Refuse to start with missing, short or duplicated secrets (fail closed)."""
        if self.auth_mode == "per_tenant":
            if not self.tenant_tokens:
                raise ValueError("per_tenant auth needs GATEWAY_TOKEN_RED / _BLUE / _AUDITOR")
            tokens = list(self.tenant_tokens.values())
            if any(len(t) < 16 for t in tokens):
                raise ValueError("gateway tokens must be at least 16 characters")
            if len(set(tokens)) != len(tokens):
                raise ValueError("each tenant must have a distinct token")
        elif not self.shared_api_key:
            raise ValueError("shared_static auth needs GATEWAY_SHARED_API_KEY")


def _parse_slot_map(raw: str) -> dict[str, int]:
    out = {}
    for pair in filter(None, (p.strip() for p in raw.split(","))):
        tenant, _, slot = pair.partition(":")
        out[tenant.strip()] = int(slot)
    return out
