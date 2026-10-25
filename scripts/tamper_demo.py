#!/usr/bin/env python3
"""Tamper-evidence demo on a DISPOSABLE COPY of the audit chain. Never touches the live chain.

    python scripts/tamper_demo.py                       # uses results/audit_export.hardened.json
    python scripts/tamper_demo.py path/to/export.json

Four scenarios, each with its verdict and its honest limit:
  1. edit one record                      -> the chain alone detects it, at the edited index
  2. rewrite history consistently         -> the chain alone is FOOLED; the signed checkpoint is not
  3. truncate the tail                    -> the chain alone is FOOLED; the signed checkpoint is not
  4. add or rewrite events after the newest checkpoint -> NOT detected (the stated limit)
"""
from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from sentinel.audit.chain import compute_hash, verify_records  # noqa: E402
from sentinel.audit.checkpoint import load_public_key, verify_with_checkpoints  # noqa: E402

G, R, Y, X = "\033[32m", "\033[31m", "\033[33m", "\033[0m"


def rewrite_from(records: list[dict], start: int, details: dict) -> list[dict]:
    """What a privileged attacker does: change a record, then recompute every hash after it."""
    out = copy.deepcopy(records)
    out[start]["details"] = details
    for i in range(start, len(out)):
        out[i]["prev_hash"] = out[i - 1]["hash"] if i else out[0]["prev_hash"]
        out[i]["hash"] = compute_hash(out[i])
    return out


def line(label: str, result, expect_ok: bool | None = None) -> None:
    colour = G if result.ok else R
    where = "" if result.ok else f" at record {result.broken_at}"
    reason = "" if result.ok else f" ({result.reason})"
    print(f"    {label:<34} {colour}{'VALID' if result.ok else 'REJECTED'}{X}{where}{reason}")


def main() -> int:
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "results" / "audit_export.hardened.json"
    if not path.exists():
        sys.exit(f"{path} not found. Run scripts/run_gauntlet.py hardened first.")
    export = json.loads(path.read_text(encoding="utf-8"))
    records, checkpoints = export["records"], export["checkpoints"]
    if len(records) < 4 or not checkpoints or not export["public_key_pem"]:
        sys.exit("The export needs at least 4 records, one signed checkpoint and the public key (hardened stack).")
    public = load_public_key(export["public_key_pem"].encode())
    newest = max(c["idx"] for c in checkpoints)
    target = max(1, newest // 2)

    print(f"\nChain: {len(records)} records, {len(checkpoints)} signed checkpoint(s), newest anchors record {newest}.")
    print("All work below is on an in-memory copy.\n")

    line("0. untouched", verify_with_checkpoints(records, checkpoints, public))

    print(f"\n1. Edit record {target} (change who did it)")
    edited = copy.deepcopy(records)
    edited[target]["actor"] = "blue"
    line("hash chain alone", verify_records(edited))

    print(f"\n2. Rewrite history from record {target} and recompute every hash")
    rewritten = rewrite_from(records, target, {"note": "history rewritten by an attacker"})
    line("hash chain alone", verify_records(rewritten))
    line("with signed checkpoints", verify_with_checkpoints(rewritten, checkpoints, public))

    keep = max(1, newest - 1)
    print(f"\n3. Truncate the chain to {keep} records (delete the tail)")
    line("hash chain alone", verify_records(records[:keep]))
    line("with signed checkpoints", verify_with_checkpoints(records[:keep], checkpoints, public))

    if newest < len(records) - 1:
        late = newest + 1
        print(f"\n4. Rewrite only records after the newest checkpoint (from {late})")
        late_rewrite = rewrite_from(records, late, {"note": "late rewrite"})
        result = verify_with_checkpoints(late_rewrite, checkpoints, public)
        line("with signed checkpoints", result)
        print(f"    {Y}Known limit: records after the newest checkpoint are not anchored yet.{X}")
    else:
        print("\n4. Append two forged records AFTER the newest checkpoint (valid hashes, written by someone who can append)")
        forged = copy.deepcopy(records)
        for note in ("forged event A", "forged event B"):
            rec = {"idx": len(forged), "ts": records[-1]["ts"], "actor": "red", "action": "probe.forged_event",
                   "details": {"note": note}, "prev_hash": forged[-1]["hash"]}
            rec["hash"] = compute_hash(rec)
            forged.append(rec)
        result = verify_with_checkpoints(forged, checkpoints, public)
        line("with signed checkpoints", result)
        print(f"    {Y}Known limit: the checkpoint only covers records up to {newest}; {result.unanchored_events} forged records sit after it and verify.{X}")
        print(f"    {Y}Access control (probe P13) is what stops forged appends; the chain cannot.{X}")

    print("\nNot covered: someone who steals the signing key can sign a rewritten history.")
    print("Not covered: an attacker who APPENDS a forged event through a stolen write token (see probe P13).\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
