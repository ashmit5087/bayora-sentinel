#!/usr/bin/env python3
"""Push the recorded results to the hosted (Replit) page so it updates by itself.

    set INGEST_TOKEN=<the secret you set in Replit>        (PowerShell: $env:INGEST_TOKEN="...")
    python scripts/publish_results.py https://<your-app>.replit.app

Sends only results (probe outcomes, timing numbers, the audit chain and PUBLIC key). Never .env or secrets/.
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from sentinel.control.payload import normalise  # noqa: E402
from sentinel.control.server import FILES  # noqa: E402

KEYS = {"gauntlet.insecure.json": "gauntlet_insecure", "gauntlet.hardened.json": "gauntlet_hardened",
        "sidechannel.json": "sidechannel", "audit_export.json": "audit_export"}


def main() -> int:
    if len(sys.argv) != 2 or not sys.argv[1].startswith("http"):
        sys.exit(__doc__)
    token = os.environ.get("INGEST_TOKEN")
    if not token:
        sys.exit("Set INGEST_TOKEN first (the same value as the Replit secret).")
    body = {}
    for name, key in KEYS.items():
        path = ROOT / "results" / FILES[name][0]
        if path.exists():  # recorded runs only: placeholders are never published
            body[key] = normalise(key, json.loads(path.read_text(encoding="utf-8")))
    if not body:
        sys.exit("No recorded results in results/ yet. Run the lab from the control room first.")
    req = urllib.request.Request(sys.argv[1].rstrip("/") + "/api/ingest", data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            print(f"published {', '.join(body)} (HTTP {r.status})")
    except urllib.error.HTTPError as e:
        sys.exit(f"rejected: HTTP {e.code} {e.read()[:300].decode(errors='replace')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
