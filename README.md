# Bayora Sentinel

*Don't trust the sandbox. Test the boundary.*

Prototype for Hack in Hills '26, PS 04 (securing adversarial AI safety testing infrastructure).
Instead of claiming a shared red/blue-team sandbox is secure, Sentinel attacks it live, in two
configurations, and shows which controls held, which failed, and what remains untested.

**Prototype status: see [STATUS.md](STATUS.md). Nothing here is certified or proven secure.**

## Three pillars

1. **Breakout Gauntlet** *(built, awaiting first Docker run)*: 16 probes run from inside the red-team container against `compose.insecure.yaml` and `compose.hardened.yaml`.
2. **Prefix-cache timing channel** *(spike ready)*: measure whether a shared llama.cpp cache leaks across tenants, and whether per-tenant slots close it (shared leak confirmed; the slot mitigation is currently unproven, see docs/THREAT_MODEL.md).
3. **Tamper-evident audit** *(built; signer container awaiting first Docker run)*: SHA-256 hash chain plus Ed25519-signed checkpoints held by a separate signer. Demo: `python scripts/tamper_demo.py`.

## Quick start (developer machine)

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements-dev.txt
python -m pytest -q
```

Run the services without Docker (two terminals, after `python scripts/gen_env.py` and exporting the `.env` values),
or with Docker:

```powershell
python scripts/gen_env.py
docker compose -f compose.dev.yaml up --build
```

## Run the Breakout Gauntlet (needs Docker Desktop)

```powershell
python scripts/gen_env.py                 # random tokens: .env and secrets/
python scripts/run_gauntlet.py both       # starts both stacks, runs the probes, saves results/
```

Output: `results/gauntlet.insecure.json`, `results/gauntlet.hardened.json` and the matching
`audit_status.*.json`. Stop the stacks with
`docker compose -p sentinel-insecure -f compose.insecure.yaml down -v` (and the same for `hardened`).
The insecure stack is deliberately weak: never run it anywhere but your own machine.

## Layout

| Path | What |
|---|---|
| `spike/` | Phase 0: llama.cpp compose and `timing.py`. Start here. |
| `sentinel/audit/` | hash chain, signed checkpoints, audit HTTP service |
| `sentinel/gateway/` | tenant tokens, scopes, rate limit, cache-slot routing, audited model access |
| `sentinel/gauntlet/` | the 16 probes, the in-container entry point, result reporting |
| `compose.insecure.yaml`, `compose.hardened.yaml` | the "before" and "after" stacks the probes attack |
| `scripts/run_gauntlet.py` | host driver: start stacks, probe, record in audit, sign, export, save results |
| `sentinel/signer/` | holds the signing key; signs audit-chain checkpoints |
| `scripts/tamper_demo.py` | edit / rewrite / truncate a disposable copy of the chain and show what is and is not detected |
| `scripts/convert_timing.py` | turn `spike/out/timing.json` into the dashboard's side-channel file |
| `sentinel/contracts.py` | frozen JSON shapes the dashboard reads |
| `contracts/fixtures/` | placeholder data (`source: "fixture"`) so the UI can start now |
| `tests/` | pytest suite |

## Honesty rules

- A `pass` means one specific check passed on one specific setup. There is no "secure" badge.
- Mock-model output validates pipeline mechanics only.
- A hash chain is tamper-evident, not immutable. Signed checkpoints narrow the gap; events after the newest checkpoint and a stolen signing key remain residual risks (both are covered by tests that document them).
- Docker is not a boundary against kernel-level escapes. That is listed as out of scope in the threat model.

## Control room (no manual scripts)
The finished site (cinematic hero, control room, results) is prebuilt in `ui/`, so there is nothing to build. Just run:

    python scripts/control_server.py      # http://127.0.0.1:8765

The page has buttons that run the attacks and the timing experiment, show each pipeline step live, and refresh the results
when a run finishes. The server runs only a fixed list of actions, listens on 127.0.0.1 only, and rejects foreign hosts and
origins. It needs Docker Desktop running and `python scripts/gen_env.py` done once.

To also update a hosted copy: `python scripts/publish_results.py https://<app>.replit.app` (needs INGEST_TOKEN in your environment).
The older, simpler dashboard is still in `dashboard/` and is used only if `ui/` is missing.
