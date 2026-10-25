# STATUS

Updated: Sat 24 Oct 2026, 01:30. Plan: submit Fri night (24 Oct is emergency buffer only).

## Verified (evidence exists)

| Item | Evidence |
|---|---|
| Audit hash chain: tamper, delete, reorder, garbage-line detection | 12 pytest cases |
| Signed checkpoints: forged, truncated and full-rewrite histories rejected; limits kept as tests | 7 pytest cases |
| Gateway: auth, scopes, per-tenant slots, rate limit, fail-closed audit, no timing leak, no raw prompts in audit | 25 pytest cases |
| Audit service: separate write and read tokens | 7 pytest cases |
| Gauntlet probes classify correctly against real local servers and temp dirs (identity probe against BOTH gateway modes; audit probes against a real audit service) | 14 pytest cases |
| Audit ingest: one record per probe, chain verifies, observations stored as hashes | 2 pytest cases |
| Host runner orchestration (parse, audit-link, contract-validate, write files), driven with local stand-ins for `docker compose` | manual end-to-end run: 16/16 probes linked to a verified chain |
| Timing statistics (AUC, permutation p-value) | 4 pytest cases + simulator |
| Signer signs the head once, skips duplicates; audit service verifies against its checkpoints; export carries chain + checkpoints + public key | 5 pytest cases |
| Tamper demo script tells the truth, including the stated limit (rewrite after the newest checkpoint is not detected) | pytest + manual read of its output |
| Compose files are syntactically valid | `docker compose config` on all three |

Total: 88 automated tests passing.

## Measured on the real machine (CPU llama.cpp, Qwen2.5-1.5B, ~780-token prompt)

| Mode | Result |
|---|---|
| shared cache | correct guess ~66 ms vs wrong guess ~3,733 ms; AUC 1.0; server reused 779 of 780 tokens |
| per-tenant slots (n = 10 vs 10) | AUC 0.70, **server reused 0 tokens**; sample too small to call statistically; the 40-trial run with p-value is pending |

## Measured in Docker on the real machine (first run, Fri morning)

| Stack | Result |
|---|---|
| insecure | 0 pass, 15 fail, 1 out of scope. Audit chain valid with 17 records: it accepted the forged event from P13 as a legitimate record. |
| hardened | 14 pass, 1 fail, 1 out of scope. The 1 fail was a **probe false positive** (P11 flagged `GPG_KEY`, a public key ID shipped in the python base image). Fixed with a documented allowlist and a regression test. |

## Written but NOT yet verified

| Item | Risk |
|---|---|
| Signer container in the hardened stack (key as Docker secret, checkpoint volume writable only by the signer) | Syntax-checked only; first Docker run pending. Likely issue: secret file permissions for UID 10001. |
| Hardened stack after the P11 fix: expected 15 pass / 0 fail | Unknown until rerun. |
| Full 3-mode timing run with p-values | Pending (user started it Thu night). |

## Not started

Demo video, final timing numbers in the dashboard (run convert_timing + sync), submission form.

## Next steps

1. Reset both stacks, rerun `python scripts/run_gauntlet.py both`, then `python scripts/tamper_demo.py` and `python scripts/convert_timing.py`.
2. Dashboard against `contracts/fixtures/` then `results/`.
3. Threat model written from the actual results.

## Update
Verified in Docker: insecure 0/15 held, hardened 15/15 held, signer anchored chain, tamper demo scenarios 1-3. Dashboard built (build + 6 vitest pass). Threat model in docs/THREAT_MODEL.md.

## Timing result (Sat 24 Oct, 18:00)
Shared: AUC 1.0, p 0.0002 (leak confirmed). Isolated: AUC 0.0, p 0.0002, i.e. perfectly separable in REVERSE (correct guesses ~13 s, wrong ~0.1-0.7 s). Isolation is NOT shown to work. Needs server_view token counts and a rerun. Dashboard wording, threat model and verdict logic now say this.
