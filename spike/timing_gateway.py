#!/usr/bin/env python3
"""Cache-timing experiment THROUGH the Sentinel gateway (the real attack path).

spike/timing.py talks to llama.cpp directly. This script runs the same experiment, but both tenants
use the gateway with their own bearer token, so the gateway (not the script) decides the cache slot:

    A = red tenant  (victim: sends a prompt that starts with a secret canary)
    B = blue tenant (attacker: only sees how long its own requests take)

The gateway's CACHE_MODE (shared | isolated | off) is set when the gateway starts, so run this once per
mode and restart the gateway in between:

    python timing_gateway.py --mode shared   --trials 40
    python timing_gateway.py --mode isolated --trials 40
    python timing_gateway.py --mode off      --trials 40

Each run MERGES into out/timing.gateway.json. The script refuses to run if the gateway reports a
different cache mode than --mode, so a mislabelled result cannot be saved.

Tokens come from the environment: GATEWAY_TOKEN_RED and GATEWAY_TOKEN_BLUE (same values as in .env).
Place this file in spike/ (it imports timing.py from the same folder). Standard library only.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import random
import statistics
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("timing", HERE / "timing.py")
T = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(T)  # reuse prompts + statistics so results are comparable with the direct run


def gw_complete(base: str, token: str, prompt: str, session_id: str) -> tuple[float, dict]:
    """One request through the gateway. Returns (client-side wall ms, response body)."""
    data = json.dumps({"prompt": prompt, "max_tokens": 1, "session_id": session_id}).encode()
    req = urllib.request.Request(
        base.rstrip("/") + "/v1/complete", data=data,
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"})
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=300) as resp:
            body = json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:200]
        hint = {401: "token wrong", 403: "scope or slot problem", 429: "rate limit: set RATE_LIMIT_PER_MIN=100000",
                502: "gateway cannot reach llama.cpp (is it running with --parallel 2?)",
                503: "audit unavailable (fail-closed)"}.get(exc.code, "")
        sys.exit(f"HTTP {exc.code} from gateway: {detail}  [{hint}]")
    except Exception as exc:  # noqa: BLE001
        sys.exit(f"Gateway not answering ({type(exc).__name__}: {exc}). Is it running on {base}?")
    return (time.perf_counter() - t0) * 1000.0, body


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--gateway", default="http://127.0.0.1:8000")
    ap.add_argument("--mode", choices=["shared", "isolated", "off"], required=True)
    ap.add_argument("--trials", type=int, default=40, help="trials per mode (even number)")
    ap.add_argument("--filler-words", type=int, default=1100)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--out", default="out/timing.gateway.json")
    args = ap.parse_args()
    if args.trials % 2:
        sys.exit("--trials must be even")

    tok_a, tok_b = os.environ.get("GATEWAY_TOKEN_RED"), os.environ.get("GATEWAY_TOKEN_BLUE")
    if not tok_a or not tok_b:
        sys.exit("Set GATEWAY_TOKEN_RED and GATEWAY_TOKEN_BLUE in this shell (values are in .env).")

    T.wait_for_server(args.gateway)  # gateway has /health
    rng = random.Random(args.seed)
    filler = T.make_filler(args.filler_words)

    # Safety check: the gateway reports its own cache mode in every response.
    _, probe = gw_complete(args.gateway, tok_b, T.scrub_prompt(rng), "warmup")
    if probe.get("cache_mode") != args.mode:
        sys.exit(f"Gateway is running CACHE_MODE={probe.get('cache_mode')!r} but you asked for --mode {args.mode}. "
                 "Restart the gateway with the right CACHE_MODE.")
    print(f"Gateway OK, cache_mode={probe['cache_mode']}, attacker identity={probe.get('tenant')}")

    for _ in range(2):  # untimed warm-up
        gw_complete(args.gateway, tok_b, T.scrub_prompt(rng), "warmup")

    schedule = ["hit", "miss"] * (args.trials // 2)
    rng.shuffle(schedule)
    rows = []
    for i, kind in enumerate(schedule, 1):
        canary = T.rand_canary(rng)
        gw_complete(args.gateway, tok_b, T.scrub_prompt(rng), f"b-scrub-{i}")                    # B clears its view
        gw_complete(args.gateway, tok_a, T.build_prompt(canary, filler), f"a-prime-{i}")          # A primes the canary
        guess = canary if kind == "hit" else T.rand_canary(rng)
        wall_ms, body = gw_complete(args.gateway, tok_b, T.build_prompt(guess, filler), f"b-probe-{i}")  # B probes
        rows.append({"kind": kind, "wall_ms": wall_ms})
        if i % 10 == 0:
            print(f"  {i}/{len(schedule)} trials done")

    hit = [r["wall_ms"] for r in rows if r["kind"] == "hit"]
    miss = [r["wall_ms"] for r in rows if r["kind"] == "miss"]
    res = {
        "mode": args.mode, "path": "gateway",
        "hit_ms": [round(x, 3) for x in hit], "miss_ms": [round(x, 3) for x in miss],
        "stats": T.summarize(hit, miss),
        "server_view": {  # the gateway deliberately withholds llama.cpp timings, so there is no ground truth here
            "hit_median_tokens_evaluated": None, "miss_median_tokens_evaluated": None,
            "hit_median_tokens_reused": None, "miss_median_tokens_reused": None},
        "median_probe_latency_ms": round(statistics.median(hit + miss), 2),
    }

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    prev = json.loads(out.read_text()) if out.exists() else {"modes": {}}
    meta = {"generated_at": datetime.now(timezone.utc).isoformat(), "url": args.gateway, "path": "via Sentinel gateway",
            "trials_per_mode": args.trials, "filler_words": args.filler_words, "approx_prompt_tokens": None,
            "seed": args.seed, "note": "Measured through the gateway on one local setup. Not a proof of side-channel resistance."}
    prev["meta"] = meta
    prev["modes"][args.mode] = res
    out.write_text(json.dumps(prev, indent=2))

    s = res["stats"]
    print(T.ascii_hist(res["hit_ms"], res["miss_ms"]))
    print(f"\nhit  median {s['hit_median_ms']} ms   miss median {s['miss_median_ms']} ms")
    print(f"AUC(hit faster) = {s['auc_hit_faster']}   best-threshold acc = {s['best_threshold_accuracy']}   "
          f"d = {s['cohens_d']}   p = {s['perm_p']}")
    print(f"-> {T.verdict(s['auc_hit_faster'], s['perm_p'])}\nSaved {out}")


if __name__ == "__main__":
    main()
