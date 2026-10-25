#!/usr/bin/env python3
"""Copy the newest results into the dashboard's data folder.

    python scripts/sync_dashboard_data.py

For each file it prefers a real recording in results/ and falls back to the placeholder fixture
in contracts/fixtures/. The dashboard labels fixture data as placeholder, so nothing is passed off as a result.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RESULTS, FIXTURES = ROOT / "results", ROOT / "contracts" / "fixtures"
DEST = ROOT / "dashboard" / "public" / "data"

# destination name -> (results file, fixture file)
FILES = {
    "gauntlet.insecure.json": ("gauntlet.insecure.json", "gauntlet.insecure.json"),
    "gauntlet.hardened.json": ("gauntlet.hardened.json", "gauntlet.hardened.json"),
    "sidechannel.json": ("sidechannel.json", "sidechannel.json"),
    "audit_export.json": ("audit_export.hardened.json", "audit_export.json"),
}


def main() -> None:
    DEST.mkdir(parents=True, exist_ok=True)
    origin = {}
    for name, (result_name, fixture_name) in FILES.items():
        live, fixture = RESULTS / result_name, FIXTURES / fixture_name
        if live.exists():
            shutil.copyfile(live, DEST / name)
            origin[name] = "recorded run"
        elif fixture.exists():
            shutil.copyfile(fixture, DEST / name)
            origin[name] = "PLACEHOLDER (no recording yet)"
        else:
            origin[name] = "missing"
    (DEST / "manifest.json").write_text(json.dumps(origin, indent=2) + "\n", encoding="utf-8")
    width = max(map(len, origin))
    for name, what in origin.items():
        print(f"  {name:<{width}}  {what}")
    print(f"\nCopied to {DEST}")


if __name__ == "__main__":
    main()
