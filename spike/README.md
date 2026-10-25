# Phase 0 spike (target: 1 hour, then decide GO / NO-GO)

Question: can we **measure** a prefix-cache timing channel on your laptop, and does
per-tenant slot isolation make it disappear?

Status of these files: the script logic was run against a local simulator only.
It has **not** been run against a real llama.cpp server yet. Your run is the first real test.

## 1. Check Docker can see the GPU

```powershell
docker run --rm --gpus all ubuntu nvidia-smi
```

You should see the RTX 4050. If this fails, use `compose.cpu.yaml` below instead
(slower, but the timing gap is still measurable).

## 2. Get a small model (about 1 GB)

```powershell
cd spike
mkdir models
curl.exe -L -o models/qwen2.5-1.5b-instruct-q4_k_m.gguf https://huggingface.co/Qwen/Qwen2.5-1.5B-Instruct-GGUF/resolve/main/qwen2.5-1.5b-instruct-q4_k_m.gguf
```

If that URL 404s, search Hugging Face for "Qwen2.5-1.5B-Instruct-GGUF" and download the q4_k_m file.
Any small GGUF works as long as the filename matches the `-m` argument in the compose file.

## 3. Start the server

```powershell
docker compose up -d
docker compose logs -f model
```

Wait for the log line saying the server is listening. CPU fallback: `docker compose -f compose.cpu.yaml up -d`.

## 4. Run the timing experiment

```powershell
python timing.py --trials 40
```

It runs three modes (shared cache, per-tenant slots, cache off) and writes `out/timing.json`.

## 5. Read the result

| Observation | Meaning | Action |
|---|---|---|
| shared AUC >= 0.90 **and** isolated AUC <= 0.65 | channel measured, mitigation works | **GO**, keep pillar 2 |
| shared AUC below 0.75 | channel too weak to see | rerun with `$env:CTX=16384; docker compose up -d --force-recreate`, then `python timing.py --filler-words 3000` |
| shared looks fine, isolated also separable | slot pinning is not isolating the cache on this build | try `--mode off` as the mitigation, check `server view` token counts |
| still nothing after the retry | no channel on this setup | **NO-GO**: drop pillar 2, spend the time on the dashboard |

The `server view` line shows how many prompt tokens the server actually evaluated.
If hits evaluate far fewer tokens than misses, the cache is working even when wall-clock noise hides it.
An attacker does not get that view; it is printed so you can debug.

## Honest limits

- One model, one machine, one run: a measurement, not a proof of resistance.
- Newer llama.cpp builds change KV-cache and slot behaviour. If something looks off, note your image digest.
- Slot pinning (`id_slot`) is what the gateway will use in `isolated` mode. Verify it here before relying on it.
