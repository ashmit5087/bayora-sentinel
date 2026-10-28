# Bayora Sentinel

*Don't trust the sandbox. Test the boundary.*

Prototype for Hack in Hills '26, PS 04 (securing adversarial AI safety testing infrastructure).
Instead of claiming a shared red/blue-team sandbox is secure, Sentinel attacks it live, in two
configurations, and shows which controls held, which failed, and what remains untested.

**Prototype status: see [STATUS.md](STATUS.md). Nothing here is certified or proven secure.**

## Three pillars

1. **Breakout Gauntlet**: 16 probes run from inside the red-team container against `compose.insecure.yaml` and `compose.hardened.yaml`.
2. **Prefix-cache timing channel**: measures whether a shared llama.cpp cache leaks across tenants, both directly and through the Sentinel gateway. The recorded shared-cache run demonstrates a leak; isolated-cache results remain setup-specific evidence, not proof of universal resistance.
3. **Tamper-evident audit**: SHA-256 hash chain plus Ed25519-signed checkpoints held by a separate signer. Demo: `python scripts/tamper_demo.py`.

The repository does **not** currently claim to contain a separate prompt-level
baseline-versus-defense evaluation suite. The implemented evaluation surfaces
are the breakout gauntlet and the cache-timing experiment.

## Quick start (developer machine)

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements-dev.txt
python -m pytest -q
```

The current verified Python suite contains 96 passing tests. A warning from the
installed HTTP test-client stack may be reported, but does not fail the suite.

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

## Run the cache-timing experiment

The direct experiment talks to llama.cpp:

```powershell
cd spike
docker compose -f compose.cpu.yaml up -d
python timing.py --mode all --trials 40 --out out/timing.direct.json
```

The gateway experiment must be run one cache mode at a time, with the gateway
restarted between modes:

```powershell
cd spike
python timing_gateway.py --mode shared --trials 40 --out out/timing.gateway.json
python timing_gateway.py --mode isolated --trials 40 --out out/timing.gateway.json
```

Keep raw timing recordings separate when comparing direct-model and gateway
runs. Convert a recording into the dashboard contract without modifying the
raw input:

```powershell
cd ..
python scripts/convert_timing.py `
  --in spike/out/timing.gateway.json `
  --model "Qwen2.5-1.5B-Instruct Q4_K_M on llama.cpp (CPU), via Sentinel gateway"
```

The converter writes `results/sidechannel.json`. It accepts both the direct
timing shape and gateway timing recordings, and preserves the cautious
interpretation in the generated caveats.

## Layout

| Path | What |
|---|---|
| `spike/` | llama.cpp compose, direct timing experiment, and gateway timing experiment |
| `sentinel/audit/` | hash chain, signed checkpoints, audit HTTP service |
| `sentinel/gateway/` | tenant tokens, scopes, rate limit, cache-slot routing, audited model access |
| `sentinel/gauntlet/` | the 16 probes, the in-container entry point, result reporting |
| `compose.insecure.yaml`, `compose.hardened.yaml` | the "before" and "after" stacks the probes attack |
| `scripts/run_gauntlet.py` | host driver: start stacks, probe, record in audit, sign, export, save results |
| `sentinel/signer/` | holds the signing key; signs audit-chain checkpoints |
| `scripts/tamper_demo.py` | edit / rewrite / truncate a disposable copy of the chain and show what is and is not detected |
| `scripts/convert_timing.py` | validate and turn a raw timing recording into the dashboard's side-channel file |
| `sentinel/contracts.py` | frozen JSON shapes the dashboard reads |
| `contracts/fixtures/` | placeholder data (`source: "fixture"`) so the UI can start now |
| `tests/` | pytest suite |

## Honesty rules

- A `pass` means one specific check passed on one specific setup. There is no "secure" badge.
- Mock-model output validates pipeline mechanics only.
- A hash chain is tamper-evident, not immutable. Signed checkpoints narrow the gap; events after the newest checkpoint and a stolen signing key remain residual risks (both are covered by tests that document them).
- Docker is not a boundary against kernel-level escapes. That is listed as out of scope in the threat model.

## Control room (no manual scripts)
The finished site (hero, control room, results, evidence counters, and responsive layout) is prebuilt in `ui/`, so there is nothing to build. Just run:

    python scripts/control_server.py      # http://127.0.0.1:8765

The page has buttons that run the attacks and the timing experiment, show each pipeline step live, and refresh the results
when a run finishes. The server runs only a fixed list of actions, listens on 127.0.0.1 only, and rejects foreign hosts and
origins. It needs Docker Desktop running and `python scripts/gen_env.py` done once.

To also update a hosted copy: `python scripts/publish_results.py https://<app>.replit.app` (needs INGEST_TOKEN in your environment).
The older, simpler dashboard is still in `dashboard/` and is used only if `ui/` is missing.

The showcase UI uses recorded or fixture data according to the available
result files. It must not be read as a live measurement unless the displayed
artifact was generated by a completed local run.
