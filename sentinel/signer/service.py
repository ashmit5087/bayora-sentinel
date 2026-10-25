"""Checkpoint signer: the only component that holds the signing key.

It reads the audit chain head (read-only HTTP), signs (idx, hash, ts) with Ed25519, and
appends the result to a checkpoint file on a volume that ONLY the signer can write. The
audit service mounts that volume read-only and the workers never see it.

    python -m sentinel.signer.service --once              # sign the current head and exit
    python -m sentinel.signer.service --interval 5        # keep signing every 5 seconds

What this buys, and what it does not:
  * detects a rewritten, truncated or forged history up to the newest checkpoint
  * events after the newest checkpoint are not anchored yet
  * someone who steals the signing key can sign a rewritten history
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from sentinel.audit.checkpoint import append_checkpoint, load_checkpoints, load_private_key, make_checkpoint
from sentinel.common.secrets import get_secret

_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def fetch_head(base: str, read_token: str, timeout: float = 5.0) -> dict:
    req = urllib.request.Request(base.rstrip("/") + "/head", headers={"Authorization": f"Bearer {read_token}"})
    with _OPENER.open(req, timeout=timeout) as resp:
        return json.loads(resp.read())


def last_signed_idx(checkpoint_path: str | Path) -> int:
    try:
        checkpoints = load_checkpoints(checkpoint_path)
    except ValueError:
        raise SystemExit("checkpoint file is unparseable; refusing to append to it")
    return max((c["idx"] for c in checkpoints), default=-1)


def sign_head_once(base: str, read_token: str, private_key, checkpoint_path: str | Path) -> dict | None:
    """Sign the current head if it is newer than the newest checkpoint. Returns the checkpoint or None."""
    head = fetch_head(base, read_token)
    if head["idx"] < 0 or head["idx"] <= last_signed_idx(checkpoint_path):
        return None
    checkpoint = make_checkpoint(private_key, head["idx"], head["hash"])
    append_checkpoint(checkpoint_path, checkpoint)
    return checkpoint


def describe_failure(exc: Exception, checkpoint_path: str | Path) -> str:
    """Network failures and file failures need different fixes, so never report one as the other."""
    if isinstance(exc, (urllib.error.URLError, ConnectionError, TimeoutError)):
        return f"audit service not reachable: {type(exc).__name__}"
    if isinstance(exc, PermissionError):
        return (f"cannot write the checkpoint file {checkpoint_path}: permission denied. "
                "The checkpoint volume must be writable by the signer's user (UID 10001).")
    return f"checkpoint file error on {checkpoint_path}: {type(exc).__name__}: {exc}"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--once", action="store_true")
    ap.add_argument("--interval", type=float, default=5.0)
    args = ap.parse_args()

    base = os.environ.get("AUDIT_URL", "http://audit:8100")
    key_path = os.environ.get("SIGNER_KEY_PATH", "/run/secrets/signer_key")
    checkpoint_path = os.environ.get("CHECKPOINT_PATH", "/checkpoints/checkpoints.jsonl")
    read_token = get_secret("AUDIT_READ_TOKEN")
    if not read_token:
        print("AUDIT_READ_TOKEN is not available to the signer", file=sys.stderr)
        return 2
    private_key = load_private_key(Path(key_path).read_bytes())

    while True:
        try:
            cp = sign_head_once(base, read_token, private_key, checkpoint_path)
            if cp:
                print(f"signed checkpoint idx={cp['idx']} hash={cp['hash'][:12]}...", flush=True)
            elif args.once:
                print("nothing new to sign", flush=True)
        except OSError as exc:  # URLError, ConnectionError and PermissionError are all OSError subclasses
            print(describe_failure(exc, checkpoint_path), file=sys.stderr, flush=True)
            if args.once:
                return 1
        if args.once:
            return 0
        time.sleep(args.interval)


if __name__ == "__main__":
    raise SystemExit(main())
