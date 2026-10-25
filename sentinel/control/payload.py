"""Shape the recorded results into exactly what the web UI's API schema expects.

The UI (and the hosted /api/ingest) validates integers and rejects missing fields, while our recordings use null for
"not applicable". This keeps both the local /api/data and scripts/publish_results.py in one agreed shape.
"""
from __future__ import annotations

from typing import Any

PROBE_KEYS = ("id", "title", "category", "hypothesis", "command", "expected", "observed", "status", "duration_ms", "audit_hash")


def _gauntlet(g: dict) -> dict:
    probes = []
    for p in g.get("probes", []):
        q = {k: p.get(k) for k in PROBE_KEYS}
        q["duration_ms"] = float(q["duration_ms"] or 0)
        for k in ("title", "category", "hypothesis", "command", "expected", "observed"):
            q[k] = q[k] or ""
        probes.append(q)
    return {"run_id": g["run_id"], "source": g["source"], "config": g["config"], "started_at": g["started_at"],
            "notes": g.get("notes", []), "probes": probes}


def _sidechannel(s: dict) -> dict:
    modes = [{"mode": m["mode"], "hit_ms": m["hit_ms"], "miss_ms": m["miss_ms"], "auc_hit_faster": m["auc_hit_faster"],
              "perm_p": m.get("perm_p"), "cohens_d": m["cohens_d"], "best_threshold_accuracy": m["best_threshold_accuracy"]}
             for m in s.get("modes", [])]
    return {"model": s["model"], "trials_per_mode": s["trials_per_mode"],
            "approx_prompt_tokens": int(s.get("approx_prompt_tokens") or 0), "caveats": s.get("caveats", []), "modes": modes}


def _audit(a: dict) -> dict:
    v = a.get("verify", {})
    count = int(v.get("count", len(a.get("records", []))))
    anchored = v.get("anchored_through")
    unanchored = v.get("unanchored_events")
    return {"records": a["records"], "checkpoints": a.get("checkpoints", []), "public_key_pem": a.get("public_key_pem") or "",
            "verify": {"ok": bool(v.get("ok", False)), "count": count,
                       "anchored_through": -1 if anchored is None else int(anchored),
                       "unanchored_events": count if unanchored is None else int(unanchored)}}


_FIX: dict[str, Any] = {"gauntlet_insecure": _gauntlet, "gauntlet_hardened": _gauntlet, "sidechannel": _sidechannel, "audit_export": _audit}


def normalise(key: str, value: dict | None) -> dict | None:
    return None if value is None else _FIX[key](value)
