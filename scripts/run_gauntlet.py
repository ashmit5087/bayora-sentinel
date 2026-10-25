#!/usr/bin/env python3
"""Run the Breakout Gauntlet against the insecure and/or hardened stack.

    python scripts/run_gauntlet.py both          # insecure, then hardened (default)
    python scripts/run_gauntlet.py hardened --down

For each configuration it: starts the stack, runs the probes INSIDE the red-worker
container, records every result in that stack's audit chain, verifies the chain, and
writes results/gauntlet.<config>.json and results/audit_status.<config>.json.

Needs: Docker Desktop running, and `python scripts/gen_env.py` already run.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from sentinel.contracts import AuditStatus  # noqa: E402
from sentinel.gauntlet.report import build_run, summarize  # noqa: E402

RESULTS = ROOT / "results"
ICON = {"pass": "PASS ", "fail": "FAIL ", "untested": "n/t  ", "out_of_scope": "n/a  "}


def compose(config: str, *args: str, stdin: str | None = None) -> subprocess.CompletedProcess:
    cmd = ["docker", "compose", "-p", f"sentinel-{config}", "-f", f"compose.{config}.yaml", *args]
    return subprocess.run(cmd, cwd=ROOT, input=stdin, capture_output=True, text=True, encoding="utf-8")


def must(proc: subprocess.CompletedProcess, what: str) -> str:
    if proc.returncode != 0:
        print(f"\nFAILED: {what}\n--- stderr ---\n{proc.stderr.strip()[-2000:]}\n--- stdout ---\n{proc.stdout.strip()[-1000:]}", file=sys.stderr)
        sys.exit(1)
    return proc.stdout


def preflight() -> None:
    if not (ROOT / ".env").exists() or not (ROOT / "secrets" / "gateway_token_red").exists():
        sys.exit("Missing .env or secrets/. Run:  python scripts/gen_env.py")
    decoy = ROOT / "decoy" / "docker.sock"
    decoy.parent.mkdir(exist_ok=True)
    decoy.touch(exist_ok=True)  # must exist as a FILE or Docker would create a directory in its place
    probe = subprocess.run(["docker", "info"], capture_output=True, text=True)
    if probe.returncode != 0:
        sys.exit("Docker is not reachable. Start Docker Desktop and retry.")


def run_config(config: str, build: bool, down: bool) -> dict:
    print(f"\n=== {config.upper()} ===")
    print("starting stack (first build can take a few minutes)...")
    must(compose(config, "up", "-d", *(["--build"] if build else [])), f"docker compose up ({config})")

    print("running probes inside the red-worker container...")
    out = must(compose(config, "exec", "-T", "red-worker", "python", "-m", "sentinel.gauntlet.run", "--wait", "90"),
               "probe run")
    probes = json.loads(out)["probes"]

    print("recording results in the audit chain...")
    ingest_out = must(compose(config, "exec", "-T", "audit", "python", "-m", "sentinel.audit.ingest",
                              stdin=json.dumps({"config": config, "probes": probes})), "audit ingest")
    ingested = json.loads(ingest_out)

    notes = ["Live run inside Docker. A 'pass' means that one probe passed on this setup, nothing more.",
             "P05 uses a decoy file, not a real runtime socket. P16 (kernel escape) is out of scope."]
    run = build_run(config, probes, ingested["hashes"], source="live", notes=notes)
    RESULTS.mkdir(exist_ok=True)
    (RESULTS / f"gauntlet.{config}.json").write_text(json.dumps(run, indent=2) + "\n", encoding="utf-8")  # saved first: later steps cannot lose it

    if config == "hardened":
        print("signing a checkpoint of the audit chain...")
        must(compose(config, "exec", "-T", "signer", "python", "-m", "sentinel.signer.service", "--once"), "signer")

    print("exporting the audit chain (disposable copy for the dashboard and tamper demo)...")
    export = json.loads(must(compose(config, "exec", "-T", "audit", "python", "-m", "sentinel.audit.export"), "audit export"))

    export["source"] = "live"
    v = export["verify"]
    audit = AuditStatus(source="live", ok=v["ok"], count=v["count"], head_hash=v["head_hash"], broken_at=v.get("broken_at"),
                        reason=v.get("reason"), anchored_through=v.get("anchored_through"),
                        unanchored_events=v.get("unanchored_events"), checkpoints_checked=v.get("checkpoints_checked", 0))
    (RESULTS / f"audit_status.{config}.json").write_text(json.dumps(audit.model_dump(), indent=2) + "\n", encoding="utf-8")
    (RESULTS / f"audit_export.{config}.json").write_text(json.dumps(export) + "\n", encoding="utf-8")

    for p in run["probes"]:
        print(f"  {ICON[p['status']]} {p['id']}  {p['title']}\n          {p['observed'][:140]}")
    c = summarize(run)
    print(f"\n  {config}: {c['pass']} pass, {c['fail']} fail, {c['untested']} untested, {c['out_of_scope']} out of scope")
    anchored = f", anchored through record {audit.anchored_through} by {audit.checkpoints_checked} signed checkpoint(s)" if audit.checkpoints_checked else ", no signed checkpoints (insecure stack)"
    print(f"  audit chain: ok={audit.ok}, {audit.count} records{anchored}")
    if down:
        compose(config, "down", "-v")
        print("  stack removed")
    return run


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("config", nargs="?", default="both", choices=["insecure", "hardened", "both"])
    ap.add_argument("--no-build", action="store_true", help="skip rebuilding the image")
    ap.add_argument("--down", action="store_true", help="remove the stack (and its audit chain) afterwards")
    args = ap.parse_args()

    preflight()
    configs = ["insecure", "hardened"] if args.config == "both" else [args.config]
    for config in configs:
        run_config(config, build=not args.no_build, down=args.down)
    print(f"\nResults saved in {RESULTS}")


if __name__ == "__main__":
    main()
