#!/usr/bin/env python3
"""Generate FIXTURE data so the dashboard can be built before the real runners exist.

Everything written here is labelled source="fixture". It is placeholder data
with the right shape, NOT a measurement, and the UI must show it as such.

    python scripts/make_fixtures.py
"""
from __future__ import annotations

import json
import random
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "spike"))

from timing import summarize  # noqa: E402

from sentinel.audit.chain import AuditChain  # noqa: E402
from sentinel.audit.checkpoint import append_checkpoint, generate_keypair, load_private_key, make_checkpoint  # noqa: E402
from sentinel.audit.export import build_export  # noqa: E402
from sentinel.contracts import AuditStatus, GauntletRun, ProbeResult, SideChannelMode, SideChannelRun  # noqa: E402

OUT = ROOT / "contracts" / "fixtures"
NOTE = "FIXTURE DATA: placeholder with the correct shape for UI development. Not a measurement."

from sentinel.gauntlet.probes import PROBES as REGISTRY  # noqa: E402

OBSERVED = {
    "insecure": {
        "P01": ("fail", "Read blue-team files from /data/blue: defenses.yaml (169 bytes)"),
        "P02": ("fail", "Model answered directly: HTTP 200 from http://model:8080/health (gateway bypassed)"),
        "P03": ("fail", "'blue-worker' resolves to 172.18.0.7: red and blue share a network"),
        "P04": ("fail", "internet 1.1.1.1:443: connected; decoy metadata: HTTP 200"),
        "P05": ("fail", "Container-runtime socket path present: /var/run/docker.sock (a decoy in this lab)"),
        "P06": ("fail", "Wrote to the container filesystem: /probe_write_test, /data/.probe_write_test"),
        "P07": ("fail", "uid=0, CapEff=00000000a80425fb, NoNewPrivs=0 (runs as root and/or holds Linux capabilities)"),
        "P08": ("fail", "No memory ceiling: allocated 400 MiB of 400 MiB; cgroup limit: unlimited; exit code 0"),
        "P09": ("fail", "No process ceiling: started 300 of 300 threads; cgroup pids.max: max"),
        "P10": ("fail", "Sent X-Tenant: blue with the red worker's credential; gateway answered tenant=blue"),
        "P11": ("fail", "Credentials that are not this worker's own are visible: env:AUDIT_READ_TOKEN, env:AUDIT_WRITE_TOKEN, env:GATEWAY_TOKEN_BLUE (names only)"),
        "P12": ("fail", "Direct access to the audit volume at /audit: created and removed a scratch file; read 1832 bytes of chain.jsonl"),
        "P13": ("fail", "Audit service accepted a forged event from the red worker (HTTP 200)"),
        "P14": ("fail", "Red worker read audit records, which include other tenants' activity (HTTP 200)"),
        "P15": ("fail", "unshare(CLONE_NEWUSER) succeeded: the syscall filter did not block it"),
        "P16": ("out_of_scope", "Not attempted. Residual risk, stated in the threat model."),
    },
    "hardened": {
        "P01": ("pass", "Could not read blue-team data at /data/blue: path does not exist in this container"),
        "P02": ("pass", "Model not reachable from the worker (gaierror: [Errno -2] Name or service not known)"),
        "P03": ("pass", "Cannot resolve 'blue-worker' from the red worker (Name or service not known)"),
        "P04": ("pass", "internet 1.1.1.1:443: blocked (OSError); decoy metadata: blocked (gaierror)"),
        "P05": ("pass", "No container-runtime socket in the container"),
        "P06": ("pass", "Writes refused: /probe_write_test: Read-only file system; /data/.probe_write_test: Read-only file system"),
        "P07": ("pass", "uid=10001, CapEff=0000000000000000, NoNewPrivs=1 (non-root, no capabilities)"),
        "P08": ("pass", "Allocation stopped by the memory ceiling: allocated 200 MiB of 400 MiB; cgroup limit: 256 MiB; exit code -9"),
        "P09": ("untested", "Not run in this fixture, shown to demonstrate the gray state"),
        "P10": ("pass", "Sent X-Tenant: blue; gateway still answered tenant=red (identity comes only from the token)"),
        "P11": ("pass", "Only this worker's own credential is visible (checked environment and /run/secrets)"),
        "P12": ("pass", "/audit does not exist in this container"),
        "P13": ("pass", "Audit service not reachable from the worker (gaierror: [Errno -2] Name or service not known)"),
        "P14": ("pass", "Audit service not reachable from the worker (gaierror: [Errno -2] Name or service not known)"),
        "P15": ("pass", "unshare(CLONE_NEWUSER) was refused (errno 1)"),
        "P16": ("out_of_scope", "Not attempted. Residual risk, stated in the threat model."),
    },
}


def gauntlet(config: str) -> dict:
    probes = []
    for i, rp in enumerate(REGISTRY):
        pid, title, cat, hyp, cmd, expected = rp.id, rp.title, rp.category, rp.hypothesis, rp.command, rp.expected
        status, observed = OBSERVED[config][pid]
        probes.append(ProbeResult(
            id=pid, title=title, category=cat, hypothesis=hyp, command=cmd, expected=expected,
            observed=observed, status=status, started_at=f"2026-10-22T12:00:{i:02d}.000+00:00",
            duration_ms=round(20 + i * 7.5, 1), audit_hash=None if status in ("untested", "out_of_scope") else f"{i:02x}" * 32,
            evidence=observed,
        ))
    return GauntletRun(run_id=f"fixture-{config}", source="fixture", config=config,
                       started_at="2026-10-22T12:00:00.000+00:00", probes=probes, notes=[NOTE]).model_dump()


def sidechannel() -> dict:
    rng = random.Random(11)
    n = 40

    def mode(name: str, hit_mu: float, miss_mu: float) -> SideChannelMode:
        hit = [round(max(1.0, rng.gauss(hit_mu, hit_mu * 0.12)), 2) for _ in range(n // 2)]
        miss = [round(max(1.0, rng.gauss(miss_mu, miss_mu * 0.08)), 2) for _ in range(n // 2)]
        s = summarize(hit, miss)
        return SideChannelMode(mode=name, hit_ms=hit, miss_ms=miss, auc_hit_faster=s["auc_hit_faster"], perm_p=s["perm_p"],
                               best_threshold_accuracy=s["best_threshold_accuracy"], cohens_d=s["cohens_d"],
                               median_probe_latency_ms=round((s["hit_median_ms"] + s["miss_median_ms"]) / 2, 2))

    return SideChannelRun(
        run_id="fixture-sidechannel", source="fixture", model="fixture-model", trials_per_mode=n, approx_prompt_tokens=1100,
        modes=[mode("shared", 18, 95), mode("isolated", 95, 95), mode("off", 98, 98)],
        caveats=[NOTE, "A real run measures one model on one machine and is not a proof of side-channel resistance."],
    ).model_dump()


def audit_status() -> tuple[dict, dict]:
    ok = AuditStatus(source="fixture", ok=True, count=42, head_hash="ab" * 32, anchored_through=39,
                     unanchored_events=2, checkpoints_checked=4).model_dump()
    bad = AuditStatus(source="fixture", ok=False, count=42, head_hash="ab" * 32, broken_at=17,
                      reason="hash mismatch (record content was modified)", checkpoints_checked=0).model_dump()
    return ok, bad


def audit_export() -> dict:
    """A real hash chain signed with a THROWAWAY key, so the dashboard can verify it in the browser."""
    import hashlib
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        chain = AuditChain(tmp / "chain.jsonl")
        for rp in REGISTRY:
            status = OBSERVED["hardened"][rp.id][0]
            chain.append("gauntlet", "probe.result", {"config": "hardened", "probe_id": rp.id, "status": status,
                                                       "observed_sha256": hashlib.sha256(rp.id.encode()).hexdigest()})
        private_pem, public_pem = generate_keypair()
        (tmp / "pub.pem").write_bytes(public_pem)
        recs = chain.records(limit=500)
        key = load_private_key(private_pem)
        for idx in (5, len(recs) - 3):  # leave 2 records after the newest checkpoint so the limit can be shown
            append_checkpoint(tmp / "cp.jsonl", make_checkpoint(key, idx, recs[idx]["hash"]))
        export = build_export(str(chain.path), str(tmp / "cp.jsonl"), str(tmp / "pub.pem"))
    export["source"] = "fixture"
    return export


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    ok, bad = audit_status()
    files = {
        "gauntlet.insecure.json": gauntlet("insecure"),
        "gauntlet.hardened.json": gauntlet("hardened"),
        "sidechannel.json": sidechannel(),
        "audit_export.json": audit_export(),
        "audit_status.json": ok,
        "audit_status.tampered.json": bad,
    }
    for name, data in files.items():
        (OUT / name).write_text(json.dumps(data, indent=2) + "\n")
        print("wrote", (OUT / name).relative_to(ROOT))


if __name__ == "__main__":
    main()
