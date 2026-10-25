"""Turn raw probe output plus audit hashes into a contract-valid GauntletRun."""
from __future__ import annotations

import uuid

from sentinel.contracts import GauntletRun


def build_run(config: str, probes: list[dict], hashes: dict[str, str] | None = None,
              source: str = "live", notes: list[str] | None = None) -> dict:
    hashes = hashes or {}
    enriched = [{**p, "audit_hash": hashes.get(p["id"])} for p in probes]
    started = min((p["started_at"] for p in enriched), default="")
    run = GauntletRun(
        run_id=f"{source}-{config}-{uuid.uuid4().hex[:8]}",
        source=source, config=config, started_at=started, probes=enriched, notes=notes or [],
    )
    return run.model_dump()


def summarize(run: dict) -> dict[str, int]:
    counts = {"pass": 0, "fail": 0, "untested": 0, "out_of_scope": 0}
    for p in run["probes"]:
        counts[p["status"]] += 1
    return counts
