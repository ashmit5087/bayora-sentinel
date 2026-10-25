# Threat model: Bayora Sentinel (PS 04)

We do not claim this sandbox is secure. We attack it from inside and report what held, with the limits.

## What we protect
1. Tenant separation: red-team and blue-team workloads must not read each other's data, credentials or identity.
2. The model gateway: the only approved path to the model; it decides identity from the token, never from a header.
3. Prompt confidentiality against timing: one tenant must not learn another's prompt prefix from latency.
4. The audit log: tamper-evident, and writable only by the gateway/ingest path.

## Attacker
A malicious or compromised red-team worker container: arbitrary code inside its own container, a valid red-tenant token, network access to whatever its zone allows. Not assumed: host access, Docker daemon access, kernel exploits.

## Controls (hardened build)
Per-zone internal networks; non-root UID 10001; all capabilities dropped; read-only root filesystem; no-new-privileges; default seccomp; memory (256 MiB, swap equal), PID (64) and CPU limits; Docker secrets per service; per-tenant bearer tokens with scopes; per-tenant llama.cpp cache slots; fail-closed audit; hash-chained audit with Ed25519 checkpoints signed by a separate container.

## Results (recorded run, Docker on the author's laptop)
| | Insecure | Hardened |
|---|---|---|
| Breaches that worked | 15 of 15 | 0 of 15 |
| Out of scope | P16 kernel escape | P16 kernel escape |

Cache timing (llama.cpp, Qwen2.5-1.5B, CPU, ~1,400-token prompt, 10 correct + 10 wrong guesses per mode):
- **Shared cache: leak confirmed.** Correct guess median ~117 ms vs wrong guess ~13.2 s, AUC 1.0, permutation p = 0.0002.
- **Per-tenant cache slots: NOT shown to close the channel.** An earlier 10+10 run reused 0 tokens (AUC 0.70, not significant). The final 10+10 run separated the cases perfectly but in reverse (correct guesses ~13 s, wrong guesses ~0.1 to 0.7 s, AUC 0.0, p = 0.0002). A reversed signal is still distinguishable, so we do not claim isolation works. The cause is unexplained (possible harness or server cache behaviour); it needs the server-side token counts and a rerun.

Audit: the hash chain alone detects an edited record but not a consistent rewrite or tail truncation; signed checkpoints detect both.

## Residual risk (stated, not hidden)
- Shared kernel: a kernel escape (P16) is not tested. Mitigation path: gVisor or a microVM.
- Records after the newest signed checkpoint are not anchored; rewrites there are not detected until the next checkpoint.
- A stolen signing key can sign a rewritten history. Production: HSM or remote signer.
- Forged appends via a stolen write token are stopped by access control (P13), not by the chain.
- P05 uses a decoy file, not a real runtime socket.
- Timing: one small model on one machine, 20 trials per mode. The shared-cache leak is clear; the per-tenant-slot mitigation is unproven (see above).
- Prompt-level attacks (jailbreaks, output exfiltration) are out of scope.
- "Held" means one probe failed to breach this configuration, nothing more.
