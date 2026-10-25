"""Append-only, hash-linked audit log (JSON Lines on disk).

Each record commits to the previous record's hash, so editing, deleting or
reordering a record breaks verification from that point on.

What this does NOT do: stop someone who can write the file from rewriting the
WHOLE chain consistently. That is what signed checkpoints (checkpoint.py) add.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

GENESIS_HASH = "0" * 64
HASHED_FIELDS = ("idx", "ts", "actor", "action", "details", "prev_hash")


class ChainCorruptError(Exception):
    """The on-disk chain cannot be parsed; the service must not append to it."""


def canonical_json(obj: Any) -> bytes:
    """Deterministic encoding: sorted keys, no whitespace, UTF-8."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def compute_hash(record: dict) -> str:
    payload = {k: record[k] for k in HASHED_FIELDS}
    return hashlib.sha256(canonical_json(payload)).hexdigest()


@dataclass
class VerifyResult:
    ok: bool
    count: int
    head_hash: str
    broken_at: int | None = None
    reason: str | None = None
    # Filled in only when signed checkpoints were checked:
    anchored_through: int | None = None    # highest record idx covered by a verified checkpoint
    unanchored_events: int | None = None   # records after that point (not covered by any checkpoint)

    def to_dict(self) -> dict:
        return asdict(self)


def verify_records(records: list[dict]) -> VerifyResult:
    """Check the internal consistency of a list of records."""
    expected_prev = GENESIS_HASH
    for position, rec in enumerate(records):
        missing = [k for k in (*HASHED_FIELDS, "hash") if k not in rec]
        if missing:
            return VerifyResult(False, len(records), expected_prev, position, f"record missing fields: {missing}")
        if rec["idx"] != position:
            return VerifyResult(False, len(records), expected_prev, position,
                                "index mismatch (a record was removed, inserted or reordered)")
        if rec["prev_hash"] != expected_prev:
            return VerifyResult(False, len(records), expected_prev, position, "prev_hash does not match the previous record")
        if compute_hash(rec) != rec["hash"]:
            return VerifyResult(False, len(records), expected_prev, position, "hash mismatch (record content was modified)")
        expected_prev = rec["hash"]
    return VerifyResult(True, len(records), expected_prev)


def parse_file(path: str | Path) -> tuple[list[dict], VerifyResult | None]:
    """Read a chain file tolerantly. Returns (records, failure) where failure is set on a parse error."""
    records: list[dict] = []
    p = Path(path)
    if not p.exists():
        return records, None
    with p.open("r", encoding="utf-8") as fh:
        for line_no, line in enumerate(fh):
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                return records, VerifyResult(False, len(records), GENESIS_HASH, line_no, "unparseable line (file was modified)")
    return records, None


def verify_file(path: str | Path) -> VerifyResult:
    records, failure = parse_file(path)
    return failure if failure else verify_records(records)


class AuditChain:
    """Thread-safe appender. Opens an existing chain and continues it."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.touch(exist_ok=True)
        self._lock = threading.Lock()
        records, failure = parse_file(self.path)
        if failure:
            raise ChainCorruptError(f"{self.path}: {failure.reason} at line {failure.broken_at}")
        self._next_idx = len(records)
        self._head = records[-1]["hash"] if records else GENESIS_HASH

    @property
    def head(self) -> dict:
        with self._lock:
            return {"idx": self._next_idx - 1, "hash": self._head, "count": self._next_idx}

    def append(self, actor: str, action: str, details: dict | None = None) -> dict:
        with self._lock:
            record = {
                "idx": self._next_idx,
                "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
                "actor": actor,
                "action": action,
                "details": details or {},
                "prev_hash": self._head,
            }
            record["hash"] = compute_hash(record)  # raises TypeError on non-JSON details, before anything is written
            line = json.dumps(record, ensure_ascii=False) + "\n"
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(line)
                fh.flush()
                os.fsync(fh.fileno())
            self._next_idx += 1
            self._head = record["hash"]
            return record

    def records(self, start: int = 0, limit: int = 100) -> list[dict]:
        recs, _ = parse_file(self.path)
        return recs[start:start + limit]
