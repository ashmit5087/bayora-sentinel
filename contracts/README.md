# Data contracts (frozen)

The dashboard consumes exactly these shapes. Source of truth: `sentinel/contracts.py`.
Export JSON Schemas for TypeScript types with `python -m sentinel.contracts`.

| File in `fixtures/` | Model | Used by |
|---|---|---|
| `gauntlet.insecure.json`, `gauntlet.hardened.json` | `GauntletRun` | probe x config matrix, topology animation |
| `sidechannel.json` | `SideChannelRun` | overlapping histograms, mitigation cost |
| `audit_status.json`, `audit_status.tampered.json` | `AuditStatus` | audit stream and verification badge |

## Status semantics

| status | meaning |
|---|---|
| `pass` | the control held; the attempted breach **failed** |
| `fail` | the control was absent or broken; the attempted breach **succeeded** |
| `untested` | not run in this session (gray, always shown) |
| `out_of_scope` | deliberately not attempted; the reason is in `observed` |

## Rules for the UI

- Every file carries `source`: `live`, `replay` or `fixture`. Show it as a badge on every panel.
  Fixtures are placeholder data with the right shape and must never be presented as results.
- A `pass` means only that this probe passed on this setup. There is no overall "secure" badge.
- Regenerate fixtures with `python scripts/make_fixtures.py`.
