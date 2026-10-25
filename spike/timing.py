#!/usr/bin/env python3
"""
Phase 0 spike: does a shared llama.cpp prompt cache leak through timing?

Everything here is synthetic and runs against your own local model.

Scenario
  Tenant A sends a prompt that starts with a secret canary.
  Tenant B can only observe response times. B guesses the canary.
  If the guess matches A's cached prefix, the server skips most of the prompt
  evaluation and answers faster. We measure that gap in three configurations:

    shared    one shared prompt cache (no slot pinning)          -> expected to leak
    isolated  each tenant pinned to its own slot (id_slot)       -> mitigation 1
    off       prompt caching disabled (cache_prompt=false)       -> mitigation 2

Per trial: B scrubs its cache -> A primes the canary -> B probes with either
the correct canary ("hit") or a random one ("miss"). Hit/miss order is shuffled.

Reading the result
  AUC = probability that a random "hit" probe is faster than a random "miss"
  probe. ~1.0 means timing reveals the cache state; ~0.5 means no separation
  was observed in this run. That is a measurement on one setup, not a proof.

Standard library only.
"""
from __future__ import annotations

import argparse
import http.client
import json
import random
import statistics
import string
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

WORDS = (
    "river stone amber window garden copper lantern meadow harbor velvet "
    "orchard timber cobalt saddle marble thistle ember pocket ribbon canyon "
    "walnut silver meadow anchor bridge falcon puzzle candle forest quartz "
    "jungle mirror pebble violet summit tunnel willow zephyr basket carpet "
    "dragon engine fabric glacier hammer island jacket kettle ladder magnet "
    "needle oyster pillow rabbit sparrow tablet umbrella voyage wagon yonder"
).split()


# ----------------------------------------------------------------- prompts
def make_filler(n_words: int, seed: int = 1234) -> str:
    rng = random.Random(seed)
    return " ".join(rng.choice(WORDS) for _ in range(n_words))


def rand_canary(rng: random.Random) -> str:
    return "CANARY-" + "".join(rng.choices(string.ascii_uppercase + string.digits, k=12))


def build_prompt(canary: str, filler: str) -> str:
    # The secret sits at the START so a wrong guess diverges from A's cached
    # prefix almost immediately, while a right guess shares the whole prompt.
    return f"Confidential session note. Secret: {canary}\n\n{filler}\n\nSummarize the note in one word."


def scrub_prompt(rng: random.Random, n_words: int = 200) -> str:
    return "Unrelated scrub text: " + " ".join(rng.choice(WORDS) + str(rng.randint(0, 9999)) for _ in range(n_words))


# -------------------------------------------------------------------- http
def post(url: str, payload: dict, timeout: float = 180.0) -> tuple[float, dict]:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:300]
        sys.exit(f"HTTP {exc.code} from {url}: {detail}\n"
                 "Hint: id_slot=1 needs the server started with --parallel 2.")
    except (urllib.error.URLError, ConnectionError, http.client.HTTPException, TimeoutError) as exc:
        sys.exit(f"\nThe server stopped answering ({type(exc).__name__}). It has probably crashed.\n"
                 "Finished modes were already saved. Check the container:\n"
                 "  docker compose -f compose.cpu.yaml ps -a\n"
                 "  docker compose -f compose.cpu.yaml logs --tail 40 model\n"
                 "Restart it, then rerun only the missing mode, e.g.  python timing.py --mode isolated")
    return (time.perf_counter() - t0) * 1000.0, body


def complete(base: str, prompt: str, slot: int | None, cache: bool) -> tuple[float, dict]:
    payload = {
        "prompt": prompt,
        "n_predict": 1,
        "temperature": 0,
        "cache_prompt": cache,
        "stream": False,
    }
    if slot is not None:
        payload["id_slot"] = slot
    return post(base.rstrip("/") + "/completion", payload)


def wait_for_server(base: str, timeout_s: int = 180) -> None:
    deadline = time.time() + timeout_s
    url = base.rstrip("/") + "/health"
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=3) as resp:
                if resp.status == 200:
                    return
        except Exception:
            pass
        time.sleep(2)
    sys.exit(f"Server at {base} did not become healthy within {timeout_s}s.")


# ------------------------------------------------------------------- stats
def percentile(xs: list[float], p: float) -> float:
    s = sorted(xs)
    k = (len(s) - 1) * p
    lo, hi = int(k), min(int(k) + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (k - lo)


def auc_hit_faster(hit: list[float], miss: list[float]) -> float:
    score = 0.0
    for h in hit:
        for m in miss:
            score += 1.0 if h < m else 0.5 if h == m else 0.0
    return score / (len(hit) * len(miss))


def best_threshold_accuracy(hit: list[float], miss: list[float]) -> float:
    """Best single-threshold classifier in EITHER direction: a perfectly reversed signal is still a perfect leak."""
    total = len(hit) + len(miss)
    best = 0.0
    for t in sorted(hit + miss):
        faster = sum(1 for h in hit if h <= t) + sum(1 for m in miss if m > t)
        slower = sum(1 for h in hit if h > t) + sum(1 for m in miss if m <= t)
        best = max(best, faster / total, slower / total)
    return best


def cohens_d(a: list[float], b: list[float]) -> float:
    if len(a) < 2 or len(b) < 2:
        return 0.0
    pooled = ((len(a) - 1) * statistics.variance(a) + (len(b) - 1) * statistics.variance(b)) / (len(a) + len(b) - 2)
    return (statistics.mean(b) - statistics.mean(a)) / (pooled ** 0.5) if pooled > 0 else 0.0


def permutation_p(hit: list[float], miss: list[float], iters: int = 4000, seed: int = 0) -> float:
    """Two-sided permutation test on the AUC: how often does shuffling the labels
    separate the groups at least as well as the real labels did?"""
    rng = random.Random(seed)
    observed = abs(auc_hit_faster(hit, miss) - 0.5)
    pooled = hit + miss
    n_hit = len(hit)
    extreme = 0
    for _ in range(iters):
        rng.shuffle(pooled)
        if abs(auc_hit_faster(pooled[:n_hit], pooled[n_hit:]) - 0.5) >= observed:
            extreme += 1
    return round((extreme + 1) / (iters + 1), 4)


def verdict(auc: float, p: float) -> str:
    if auc >= 0.90 and p < 0.01:
        return "SEPARABLE: timing revealed the cache state in this run"
    if auc <= 0.10 and p < 0.01:
        return ("SEPARABLE IN REVERSE: correct guesses were SLOWER than wrong ones. The two cases are still perfectly "
                "distinguishable, so this is NOT evidence that the channel is closed. Unexplained: check server_view.")
    if p < 0.05:
        return f"PARTIAL: statistically detectable separation (p={p})"
    return f"no significant separation detected (p={p}); that is not proof of absence"


def summarize(hit: list[float], miss: list[float]) -> dict:
    return {
        "hit_median_ms": round(statistics.median(hit), 2),
        "miss_median_ms": round(statistics.median(miss), 2),
        "hit_p10_p90_ms": [round(percentile(hit, 0.10), 2), round(percentile(hit, 0.90), 2)],
        "miss_p10_p90_ms": [round(percentile(miss, 0.10), 2), round(percentile(miss, 0.90), 2)],
        "auc_hit_faster": round(auc_hit_faster(hit, miss), 4),
        "best_threshold_accuracy": round(best_threshold_accuracy(hit, miss), 4),
        "cohens_d": round(cohens_d(hit, miss), 2),
        "perm_p": permutation_p(hit, miss),
        "n_hit": len(hit),
        "n_miss": len(miss),
    }


def ascii_hist(hit: list[float], miss: list[float], bins: int = 22) -> str:
    both = sorted(hit + miss)
    lo, hi = both[0], percentile(both, 0.98)
    if hi <= lo:
        hi = lo + 1.0
    width = (hi - lo) / bins
    counts = {"hit": [0] * bins, "miss": [0] * bins}
    for name, xs in (("hit", hit), ("miss", miss)):
        for x in xs:
            counts[name][min(int((min(x, hi) - lo) / width), bins - 1)] += 1
    peak = max(max(counts["hit"]), max(counts["miss"]), 1)
    scale = 28 / peak
    lines = [f"{'ms':>8} | {'hit (#)':<30} | miss (+)"]
    for i in range(bins):
        edge = lo + i * width
        lines.append(f"{edge:8.1f} | {'#' * round(counts['hit'][i] * scale):<30} | {'+' * round(counts['miss'][i] * scale)}")
    return "\n".join(lines)


# -------------------------------------------------------------- experiment
def run_mode(base: str, mode: str, trials: int, filler: str, rng: random.Random) -> dict:
    isolated = mode == "isolated"
    cache = mode != "off"
    slot_a = 0 if isolated else None
    slot_b = 1 if isolated else None

    for _ in range(3):  # untimed warm-up
        complete(base, scrub_prompt(rng), slot_b, cache)

    schedule = ["hit", "miss"] * (trials // 2)
    rng.shuffle(schedule)

    rows = []
    for kind in schedule:
        canary = rand_canary(rng)
        complete(base, scrub_prompt(rng), slot_b, cache)                    # B clears its own view
        complete(base, build_prompt(canary, filler), slot_a, cache)         # A primes the canary
        guess = canary if kind == "hit" else rand_canary(rng)
        wall_ms, body = complete(base, build_prompt(guess, filler), slot_b, cache)  # B probes
        timings = body.get("timings", {}) or {}
        rows.append({
            "kind": kind,
            "wall_ms": wall_ms,
            "server_prompt_n": timings.get("prompt_n"),
            "server_cache_n": timings.get("cache_n"),
            "server_prompt_ms": timings.get("prompt_ms"),
        })

    hit = [r["wall_ms"] for r in rows if r["kind"] == "hit"]
    miss = [r["wall_ms"] for r in rows if r["kind"] == "miss"]

    def med(kind: str, key: str):
        vals = [r[key] for r in rows if r["kind"] == kind and r[key] is not None]
        return round(statistics.median(vals), 2) if vals else None

    return {
        "mode": mode,
        "hit_ms": [round(x, 3) for x in hit],
        "miss_ms": [round(x, 3) for x in miss],
        "stats": summarize(hit, miss),
        # Ground truth from the server (an attacker would NOT see this):
        "server_view": {
            "hit_median_tokens_evaluated": med("hit", "server_prompt_n"),
            "miss_median_tokens_evaluated": med("miss", "server_prompt_n"),
            "hit_median_tokens_reused": med("hit", "server_cache_n"),
            "miss_median_tokens_reused": med("miss", "server_cache_n"),
        },
        "median_probe_latency_ms": round(statistics.median(hit + miss), 2),
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", default="http://127.0.0.1:8080")
    ap.add_argument("--trials", type=int, default=40, help="trials per mode (even number)")
    ap.add_argument("--filler-words", type=int, default=1100, help="prompt length knob; raise CTX if you raise this")
    ap.add_argument("--mode", choices=["shared", "isolated", "off", "all"], default="all")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--out", default="out/timing.json")
    args = ap.parse_args()
    if args.trials % 2:
        sys.exit("--trials must be even")

    wait_for_server(args.url)
    rng = random.Random(args.seed)
    filler = make_filler(args.filler_words)

    probe_ms, probe_body = complete(args.url, build_prompt(rand_canary(rng), filler), None, False)
    n_tok = (probe_body.get("timings") or {}).get("prompt_n")
    print(f"Server reachable. Prompt is about {n_tok if n_tok is not None else '?'} tokens "
          f"(first request {probe_ms:.0f} ms).\n")

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    meta = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "url": args.url,
        "trials_per_mode": args.trials,
        "filler_words": args.filler_words,
        "approx_prompt_tokens": n_tok,
        "seed": args.seed,
        "note": "Measured on one local setup. Not a proof of side-channel resistance.",
    }
    # Merge with earlier runs so a crash, or a rerun of one mode, never loses finished modes.
    results: dict = {}
    if out.exists():
        try:
            results = json.loads(out.read_text()).get("modes", {})
        except (ValueError, OSError):
            results = {}

    modes = ["shared", "isolated", "off"] if args.mode == "all" else [args.mode]
    for mode in modes:
        print(f"=== mode: {mode} ({args.trials} trials) ===")
        res = run_mode(args.url, mode, args.trials, filler, rng)
        results[mode] = res
        out.write_text(json.dumps({"meta": meta, "modes": results}, indent=2))  # save after every mode
        s = res["stats"]
        print(ascii_hist(res["hit_ms"], res["miss_ms"]))
        print(f"\nhit  median {s['hit_median_ms']} ms   p10-p90 {s['hit_p10_p90_ms']}")
        print(f"miss median {s['miss_median_ms']} ms   p10-p90 {s['miss_p10_p90_ms']}")
        print(f"AUC(hit faster) = {s['auc_hit_faster']}   best-threshold accuracy = {s['best_threshold_accuracy']}   d = {s['cohens_d']}   p = {s['perm_p']}")
        sv = res["server_view"]
        print(f"server view: tokens evaluated hit/miss = {sv['hit_median_tokens_evaluated']}/{sv['miss_median_tokens_evaluated']}, "
              f"reused hit/miss = {sv['hit_median_tokens_reused']}/{sv['miss_median_tokens_reused']}")
        print(f"-> {verdict(s['auc_hit_faster'], s['perm_p'])}\n")

    if "shared" in results and "isolated" in results:
        sh, iso = results["shared"]["stats"], results["isolated"]["stats"]
        sh_ok = sh["auc_hit_faster"] >= 0.90 and sh.get("perm_p", 1.0) < 0.01
        iso_ok = iso.get("perm_p", 0.0) >= 0.05
        reused = results["isolated"]["server_view"]["hit_median_tokens_reused"]
        print("GO / NO-GO for pillar 2:", "GO" if sh_ok and iso_ok else "NOT YET")
        print(f"  shared: AUC {sh['auc_hit_faster']}, p {sh.get('perm_p')}  (want AUC >= 0.90 and p < 0.01)")
        print(f"  isolated: AUC {iso['auc_hit_faster']}, p {iso.get('perm_p')}  (want p >= 0.05); "
              f"server-side tokens reused on a matching probe = {reused} (want 0)")
        if "off" in results:
            print(f"  median probe latency: shared {results['shared']['median_probe_latency_ms']} ms, "
                  f"isolated {results['isolated']['median_probe_latency_ms']} ms, "
                  f"off {results['off']['median_probe_latency_ms']} ms  (mitigation cost)")

    print(f"\nSaved {out}")


if __name__ == "__main__":
    main()
