#!/usr/bin/env python3
"""Create .env, secrets/ and the checkpoint-signing keypair. Safe to rerun: it never overwrites.

.env        used by compose.dev.yaml and compose.insecure.yaml (secrets as env vars)
secrets/    used by compose.hardened.yaml (Docker secrets, mounted at /run/secrets)
Both hold the SAME token values, so the two configurations are comparable.
"""
import secrets
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from sentinel.audit.checkpoint import generate_keypair  # noqa: E402

ENV = ROOT / ".env"
SECRETS = ROOT / "secrets"
TOKENS = ["AUDIT_WRITE_TOKEN", "AUDIT_READ_TOKEN", "GATEWAY_TOKEN_RED", "GATEWAY_TOKEN_BLUE",
          "GATEWAY_TOKEN_AUDITOR", "GATEWAY_SHARED_API_KEY"]


def write_secret(path: Path, data: str | bytes) -> bool:
    if path.exists():
        return False
    path.write_bytes(data if isinstance(data, bytes) else data.encode("utf-8"))
    path.chmod(0o644)  # on purpose: the container runs as UID 10001 and must read the bind-mounted file
    return True


SECRETS.mkdir(exist_ok=True)
created = []

if ENV.exists():
    print(".env already exists: keeping your existing tokens.")
    values = dict(line.split("=", 1) for line in ENV.read_text(encoding="utf-8").splitlines() if "=" in line and not line.startswith("#"))
    missing = [k for k in TOKENS if k not in values]
    if missing:
        sys.exit(f".env is missing {missing}. Delete .env and secrets/*.* and rerun for a fresh set.")
else:
    values = {k: secrets.token_urlsafe(32) for k in TOKENS}
    ENV.write_text("\n".join(f"{k}={v}" for k, v in values.items()) + "\nMODEL_BACKEND=mock\nCACHE_MODE=isolated\n", encoding="utf-8")
    created.append(".env")

for key in TOKENS:
    if key != "GATEWAY_SHARED_API_KEY" and write_secret(SECRETS / key.lower(), values[key]):  # shared key: insecure stack only
        created.append(f"secrets/{key.lower()}")

if not (SECRETS / "signer_key").exists():
    private_pem, public_pem = generate_keypair()
    write_secret(SECRETS / "signer_key", private_pem)
    write_secret(SECRETS / "signer_pub", public_pem)
    created += ["secrets/signer_key", "secrets/signer_pub"]

print("Created:", ", ".join(created) if created else "nothing (everything already exists)")
print("Never commit .env or secrets/.")
