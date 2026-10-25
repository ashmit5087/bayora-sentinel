"""Record gauntlet results in the audit chain.

Runs INSIDE the audit container (the operator's `docker compose exec`), talks to
the audit service on localhost with the write token, then asks it to verify the
chain. Reads {"config": ..., "probes": [...]} on stdin, prints JSON on stdout.

Going through the HTTP service (not the file) keeps a single writer, so the chain
cannot be corrupted by two processes appending at once.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.request

from sentinel.common.secrets import get_secret

_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _call(base: str, path: str, token: str, body: dict | None = None, timeout: float = 5.0) -> dict:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(
        base.rstrip("/") + path, data=data, method="POST" if body is not None else "GET",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    with _OPENER.open(req, timeout=timeout) as resp:
        return json.loads(resp.read())


def wait_healthy(base: str, seconds: int = 30) -> None:
    deadline = time.time() + seconds
    while time.time() < deadline:
        try:
            with _OPENER.open(base.rstrip("/") + "/health", timeout=2) as resp:
                if resp.status == 200:
                    return
        except (urllib.error.URLError, OSError):
            time.sleep(1)
    raise RuntimeError(f"audit service at {base} not healthy after {seconds}s")


def ingest(config: str, probes: list[dict], base: str, write_token: str, read_token: str) -> dict:
    hashes: dict[str, str] = {}
    for p in probes:
        rec = _call(base, "/append", write_token, {
            "actor": "gauntlet",
            "action": "probe.result",
            "details": {
                "config": config,
                "probe_id": p["id"],
                "status": p["status"],
                "observed_sha256": hashlib.sha256(p["observed"].encode("utf-8")).hexdigest(),
            },
        })
        hashes[p["id"]] = rec["hash"]
    return {"hashes": hashes, "head": _call(base, "/head", read_token), "verify": _call(base, "/verify", read_token)}


def main() -> int:
    payload = json.load(sys.stdin)
    base = os.environ.get("AUDIT_INGEST_URL", "http://127.0.0.1:8100")
    write_token, read_token = get_secret("AUDIT_WRITE_TOKEN"), get_secret("AUDIT_READ_TOKEN")
    if not write_token or not read_token:
        print("audit tokens are not available in this container", file=sys.stderr)
        return 2
    wait_healthy(base)
    json.dump(ingest(payload["config"], payload["probes"], base, write_token, read_token), sys.stdout)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
