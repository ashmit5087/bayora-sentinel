"""Entry point executed INSIDE the red-worker container.

    python -m sentinel.gauntlet.run --wait 90

Prints one JSON document on stdout (progress goes to stderr).
"""
from __future__ import annotations

import argparse
import json
import sys
import time

from .probes import cfg, http_request, run_all


def wait_for_gateway(seconds: int) -> bool:
    url = cfg("GAUNTLET_GATEWAY_URL", "http://gateway:8000") + "/health"
    deadline = time.time() + seconds
    while time.time() < deadline:
        kind, status, _ = http_request(url, timeout=2.0)
        if kind == "response" and status == 200:
            return True
        time.sleep(2)
    return False


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--wait", type=int, default=0, help="seconds to wait for the gateway before probing")
    ap.add_argument("--only", default="", help="comma-separated probe ids, e.g. P01,P02")
    args = ap.parse_args()

    if args.wait and not wait_for_gateway(args.wait):
        print(f"warning: gateway not healthy after {args.wait}s; gateway-dependent probes will be 'untested'", file=sys.stderr)

    only = {x.strip() for x in args.only.split(",") if x.strip()} or None
    probes = run_all(only)
    json.dump({"probes": probes}, sys.stdout)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
