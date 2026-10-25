"""Signed checkpoints: independent anchors for the audit chain.

A separate signer holds an Ed25519 private key and periodically signs
(idx, hash, ts) of the chain head. The audit service and the workers never see
that key. A verifier with only the PUBLIC key can then detect:

  * a wholesale rewrite of history (rewritten hashes no longer match the signed ones)
  * truncation (chain shorter than a signed checkpoint)
  * forged checkpoints (bad signature)

Limits, stated plainly:
  * events appended after the newest checkpoint are not anchored yet
  * someone who steals the signing key can sign a rewritten history
"""
from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .chain import VerifyResult, canonical_json, verify_records


def generate_keypair() -> tuple[bytes, bytes]:
    """Return (private_pem, public_pem)."""
    key = Ed25519PrivateKey.generate()
    private_pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    public_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_pem, public_pem


def load_private_key(pem: bytes) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(pem, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("not an Ed25519 private key")
    return key


def load_public_key(pem: bytes) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(pem)
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("not an Ed25519 public key")
    return key


def _message(idx: int, hash_hex: str, ts: str) -> bytes:
    return canonical_json({"idx": idx, "hash": hash_hex, "ts": ts})


def make_checkpoint(private_key: Ed25519PrivateKey, idx: int, hash_hex: str, ts: str | None = None) -> dict:
    ts = ts or datetime.now(timezone.utc).isoformat(timespec="milliseconds")
    sig = private_key.sign(_message(idx, hash_hex, ts))
    return {"idx": idx, "hash": hash_hex, "ts": ts, "sig": base64.b64encode(sig).decode("ascii")}


def verify_checkpoint_signature(public_key: Ed25519PublicKey, cp: dict) -> bool:
    try:
        public_key.verify(base64.b64decode(cp["sig"], validate=True), _message(cp["idx"], cp["hash"], cp["ts"]))
        return True
    except (InvalidSignature, KeyError, TypeError, ValueError):
        return False


def append_checkpoint(path: str | Path, cp: dict) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(cp) + "\n")


def load_checkpoints(path: str | Path) -> list[dict]:
    p = Path(path)
    if not p.exists():
        return []
    out = []
    for line in p.read_text(encoding="utf-8").splitlines():
        if line.strip():
            out.append(json.loads(line))  # JSONDecodeError (a ValueError) bubbles up to the caller
    return out


def verify_with_checkpoints(records: list[dict], checkpoints: list[dict], public_key: Ed25519PublicKey) -> VerifyResult:
    base = verify_records(records)
    if not base.ok:
        return base

    def fail(at: int | None, reason: str) -> VerifyResult:
        return VerifyResult(False, base.count, base.head_hash, broken_at=at, reason=reason)

    anchored: int | None = None
    for cp in sorted(checkpoints, key=lambda c: c.get("idx", -1) if isinstance(c.get("idx"), int) else -1):
        if not verify_checkpoint_signature(public_key, cp):
            return fail(cp.get("idx"), "checkpoint signature invalid (forged or corrupted checkpoint)")
        idx = cp["idx"]
        if idx >= len(records):
            return fail(len(records), "chain is shorter than a signed checkpoint (truncation or deletion)")
        if records[idx]["hash"] != cp["hash"]:
            return fail(idx, "chain diverges from signed checkpoint (history was rewritten)")
        anchored = idx

    base.anchored_through = anchored
    base.unanchored_events = len(records) - 1 - anchored if anchored is not None else len(records)
    return base
