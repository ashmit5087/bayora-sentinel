#!/usr/bin/env python3
"""Convert spike/out/timing.json (from timing.py) into the dashboard's SideChannelRun contract.

    python scripts/convert_timing.py [--model "Qwen2.5-1.5B Q4_K_M (CPU)"]

Writes results/sidechannel.json with source "live".
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from sentinel.contracts import SideChannelMode, SideChannelRun  # noqa: E402


def _timing():
    import importlib.util
    spec = importlib.util.spec_from_file_location("timing", ROOT / "spike" / "timing.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def convert(timing: dict, model: str) -> dict:
    meta, modes = timing["meta"], []
    for name in ("shared", "isolated", "off"):
        m = timing["modes"].get(name)
        if not m:
            continue
        s = dict(m["stats"])
        # Older recordings scored only the "hit is faster" direction; rescore in both so a reversed signal is not hidden.
        s["best_threshold_accuracy"] = max(s["best_threshold_accuracy"], _timing().best_threshold_accuracy(m["hit_ms"], m["miss_ms"]))
        modes.append(SideChannelMode(
            mode=name, hit_ms=m["hit_ms"], miss_ms=m["miss_ms"], auc_hit_faster=s["auc_hit_faster"],
            best_threshold_accuracy=s["best_threshold_accuracy"], cohens_d=s["cohens_d"], perm_p=s.get("perm_p"),
            median_probe_latency_ms=m["median_probe_latency_ms"],
        ))
    if not modes:
        sys.exit("timing.json has no modes")
    run = SideChannelRun(
        run_id=f"live-sidechannel-{meta['generated_at'][:19].replace(':', '')}", source="live", model=model,
        trials_per_mode=meta["trials_per_mode"], approx_prompt_tokens=meta.get("approx_prompt_tokens"), modes=modes,
        caveats=[
            "Measured on one local machine with one model: a measurement, not a proof of side-channel resistance.",
            "'Isolated' means each tenant is pinned to its own llama.cpp KV-cache slot by the gateway. "
            "Other channels (shared CPU caches, memory bandwidth, power) were not tested.",
            meta.get("note", ""),
        ],
    )
    return run.model_dump()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="src", default=str(ROOT / "spike" / "out" / "timing.json"))
    ap.add_argument("--out", default=str(ROOT / "results" / "sidechannel.json"))
    ap.add_argument("--model", default="Qwen2.5-1.5B-Instruct Q4_K_M on llama.cpp (CPU)")
    args = ap.parse_args()
    src = Path(args.src)
    if not src.exists():
        sys.exit(f"{src} not found. Run spike/timing.py first.")
    run = convert(json.loads(src.read_text()), args.model)
    out = Path(args.out)
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(run, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {out}: modes = {[m['mode'] for m in run['modes']]}")


if __name__ == "__main__":
    main()
