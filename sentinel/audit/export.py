"""Export the audit chain, its signed checkpoints and the public key as one JSON document.

Runs INSIDE the audit container. The dashboard and the tamper demo work on this export,
a disposable copy: nothing they do can touch the live chain.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from .chain import parse_file, verify_records
from .checkpoint import load_checkpoints, load_public_key, verify_with_checkpoints


def build_export(chain_path: str, checkpoint_path: str | None, public_key_path: str | None) -> dict:
    records, failure = parse_file(chain_path)
    checkpoints: list[dict] = []
    public_pem = ""
    if checkpoint_path and Path(checkpoint_path).exists():
        checkpoints = load_checkpoints(checkpoint_path)
    if public_key_path and Path(public_key_path).exists():
        public_pem = Path(public_key_path).read_text(encoding="utf-8")

    if failure:
        verify = {**failure.to_dict(), "checkpoints_checked": 0}
    elif checkpoints and public_pem:
        verify = {**verify_with_checkpoints(records, checkpoints, load_public_key(public_pem.encode())).to_dict(),
                  "checkpoints_checked": len(checkpoints)}
    else:
        verify = {**verify_records(records).to_dict(), "checkpoints_checked": 0}
    return {"schema_version": 1, "records": records, "checkpoints": checkpoints, "public_key_pem": public_pem, "verify": verify}


def main() -> int:
    export = build_export(
        os.environ.get("AUDIT_CHAIN_PATH", "/audit/chain.jsonl"),
        os.environ.get("AUDIT_CHECKPOINT_PATH"),
        os.environ.get("AUDIT_PUBLIC_KEY_PATH"),
    )
    json.dump(export, sys.stdout)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
