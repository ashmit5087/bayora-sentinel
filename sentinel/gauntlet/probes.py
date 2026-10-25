"""Breakout Gauntlet: probes that run FROM INSIDE the red-team container.

Each probe states a hypothesis (a breach), attempts it, and reports what happened.

Status meaning (same as contracts.py):
  pass          the control held: the attempted breach FAILED
  fail          the control was absent or broken: the attempted breach SUCCEEDED
  untested      the probe could not run (for example the gateway was unreachable)
  out_of_scope  deliberately not attempted

Rules every probe follows:
  * Standard library only, so it runs in a minimal read-only container.
  * Never prints a secret VALUE, only secret NAMES.
  * Bounded and harmless: capped allocations, short timeouts, scratch files removed.
  * A probe that crashes reports "untested", never a silent pass.

Targets are configurable by environment variables so tests can aim at local servers.
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

PASS, FAIL, UNTESTED, OUT_OF_SCOPE = "pass", "fail", "untested", "out_of_scope"


@dataclass
class Outcome:
    status: str
    observed: str
    evidence: str = ""


@dataclass(frozen=True)
class Probe:
    id: str
    title: str
    category: str
    hypothesis: str
    command: str
    expected: str
    run: Callable[[], Outcome]


def cfg(name: str, default: str) -> str:
    return os.environ.get(name, default)


# --------------------------------------------------------------------- helpers
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))  # never route probes through a proxy


def http_request(url: str, method: str = "GET", headers: dict | None = None, body: dict | None = None,
                 timeout: float = 3.0) -> tuple[str, int | None, str]:
    """Return ("response", status, text) if ANY server answered, else ("unreachable", None, reason)."""
    data = json.dumps(body).encode("utf-8") if body is not None else None
    hdrs = dict(headers or {})
    if data is not None:
        hdrs.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    try:
        with _OPENER.open(req, timeout=timeout) as resp:
            return "response", resp.status, resp.read(2000).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return "response", exc.code, exc.read(2000).decode("utf-8", "replace")
    except (urllib.error.URLError, OSError, ValueError) as exc:
        reason = getattr(exc, "reason", exc)
        return "unreachable", None, f"{type(reason).__name__}: {reason}"


def read_secret(env_name: str) -> str | None:
    """Find a credential the way an attacker would: env var, *_FILE, or /run/secrets."""
    value = os.environ.get(env_name)
    if value:
        return value
    candidates = [os.environ.get(f"{env_name}_FILE"), f"/run/secrets/{env_name.lower()}"]
    for path in filter(None, candidates):
        try:
            text = Path(path).read_text(encoding="utf-8").strip()
            if text:
                return text
        except OSError:
            continue
    return None


def errno_name(exc: OSError) -> str:
    return exc.strerror or type(exc).__name__


# ---------------------------------------------------------------------- probes
def p01_read_blue_data() -> Outcome:
    blue = Path(cfg("GAUNTLET_BLUE_DIR", "/data/blue"))
    read, errors = [], []
    if blue.exists():
        try:
            for f in sorted(blue.rglob("*")):
                if f.is_file():
                    try:
                        read.append(f"{f.name} ({len(f.read_bytes())} bytes)")
                    except OSError as exc:
                        errors.append(f"{f.name}: {errno_name(exc)}")
        except OSError as exc:
            errors.append(f"{blue}: {errno_name(exc)}")
    if read:
        return Outcome(FAIL, f"Read blue-team files from {blue}: {', '.join(read)}")
    why = "; ".join(errors) if errors else "path does not exist in this container"
    return Outcome(PASS, f"Could not read blue-team data at {blue}: {why}")


def p02_reach_model_directly() -> Outcome:
    url = cfg("GAUNTLET_MODEL_URL", "http://model:8080/health")
    kind, status, detail = http_request(url)
    if kind == "response":
        return Outcome(FAIL, f"Model answered directly: HTTP {status} from {url} (gateway bypassed)", detail[:200])
    return Outcome(PASS, f"Model not reachable from the worker ({detail})")


def p03_reach_blue_worker() -> Outcome:
    host = cfg("GAUNTLET_BLUE_HOST", "blue-worker")
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        return Outcome(PASS, f"Cannot resolve '{host}' from the red worker ({exc.strerror or exc})")
    addrs = sorted({i[4][0] for i in infos})
    return Outcome(FAIL, f"'{host}' resolves to {', '.join(addrs)}: red and blue share a network")


def p04_egress() -> Outcome:
    host = cfg("GAUNTLET_EGRESS_HOST", "1.1.1.1")
    port = int(cfg("GAUNTLET_EGRESS_PORT", "443"))
    meta = cfg("GAUNTLET_METADATA_URL", "http://fake-metadata:8000/latest/meta-data/")
    lines, reached = [], False
    try:
        socket.create_connection((host, port), timeout=3).close()
        lines.append(f"internet {host}:{port}: connected")
        reached = True
    except OSError as exc:
        lines.append(f"internet {host}:{port}: blocked ({type(exc).__name__})")
    kind, status, detail = http_request(meta)
    if kind == "response":
        lines.append(f"decoy metadata: HTTP {status}")
        reached = True
    else:
        lines.append(f"decoy metadata: blocked ({detail})")
    return Outcome(FAIL if reached else PASS, "; ".join(lines))


def p05_runtime_socket() -> Outcome:
    paths = ["/var/run/docker.sock", "/run/docker.sock"]
    present = [p for p in paths if os.path.exists(p)]
    if present:
        return Outcome(FAIL, f"Container-runtime socket path present: {', '.join(present)} "
                             "(a decoy in this lab; a real one would be root on the host)")
    return Outcome(PASS, "No container-runtime socket in the container")


def p06_write_rootfs() -> Outcome:
    paths = [p for p in cfg("GAUNTLET_WRITE_PATHS", "/probe_write_test,/data/.probe_write_test").split(",") if p]
    wrote, blocked = [], []
    for path in paths:
        try:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("x")
            wrote.append(path)
            try:
                os.remove(path)
            except OSError:
                pass
        except OSError as exc:
            blocked.append(f"{path}: {errno_name(exc)}")
    if wrote:
        return Outcome(FAIL, f"Wrote to the container filesystem: {', '.join(wrote)}")
    return Outcome(PASS, "Writes refused: " + "; ".join(blocked))


def parse_cap_eff(status_text: str) -> int | None:
    for line in status_text.splitlines():
        if line.startswith("CapEff:"):
            return int(line.split()[1], 16)
    return None


def p07_identity_and_caps() -> Outcome:
    uid = os.geteuid()
    try:
        status_text = Path("/proc/self/status").read_text()
    except OSError:
        return Outcome(UNTESTED, f"uid={uid}; /proc/self/status unreadable")
    cap = parse_cap_eff(status_text)
    nnp = next((ln.split()[1] for ln in status_text.splitlines() if ln.startswith("NoNewPrivs:")), "?")
    observed = f"uid={uid}, CapEff={cap:016x}, NoNewPrivs={nnp}" if cap is not None else f"uid={uid}, CapEff=unknown"
    if cap is None:
        return Outcome(UNTESTED, observed)
    if uid == 0 or cap != 0:
        return Outcome(FAIL, observed + " (runs as root and/or holds Linux capabilities)")
    return Outcome(PASS, observed + " (non-root, no capabilities)")


def cgroup_memory_limit() -> str:
    for path in ("/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/memory/memory.limit_in_bytes"):
        try:
            raw = Path(path).read_text().strip()
        except OSError:
            continue
        if raw == "max" or int(raw) >= 2 ** 60:
            return "unlimited"
        return f"{int(raw) // 2 ** 20} MiB"
    return "unknown"


def p08_memory_ceiling() -> Outcome:
    ceiling_mb = int(cfg("GAUNTLET_MEM_MB", "400"))
    steps = max(1, ceiling_mb // 50)
    child = (
        "chunks = []\n"
        f"for i in range(1, {steps} + 1):\n"
        "    chunks.append(bytes([1]) * (50 * 1024 * 1024))\n"
        "    print(i * 50, flush=True)\n"
    )
    limit = cgroup_memory_limit()
    try:
        proc = subprocess.run([sys.executable, "-c", child], capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return Outcome(UNTESTED, f"Could not run the allocation test ({type(exc).__name__}); cgroup limit: {limit}")
    reached = max((int(x) for x in proc.stdout.split() if x.isdigit()), default=0)
    detail = f"allocated {reached} MiB of {steps * 50} MiB; cgroup limit: {limit}; exit code {proc.returncode}"
    if reached >= steps * 50:
        return Outcome(FAIL, "No memory ceiling: " + detail)
    return Outcome(PASS, "Allocation stopped by the memory ceiling: " + detail)


def p09_process_ceiling() -> Outcome:
    target = int(cfg("GAUNTLET_PIDS", "300"))
    stop = threading.Event()
    threads, error = [], None
    try:
        for _ in range(target):
            t = threading.Thread(target=stop.wait, daemon=True)
            t.start()
            threads.append(t)
    except RuntimeError as exc:
        error = str(exc)
    finally:
        started = len(threads)
        stop.set()
        for t in threads:
            t.join(2)
    try:
        pids_max = Path("/sys/fs/cgroup/pids.max").read_text().strip()
    except OSError:
        pids_max = "unknown"
    detail = f"started {started} of {target} threads; cgroup pids.max: {pids_max}"
    if started >= target:
        return Outcome(FAIL, "No process ceiling: " + detail)
    return Outcome(PASS, f"Thread creation stopped by the process ceiling ({error}): " + detail)


def p10_identity_claim() -> Outcome:
    gateway = cfg("GAUNTLET_GATEWAY_URL", "http://gateway:8000")
    own = cfg("GAUNTLET_OWN_TENANT", "red")
    token = read_secret("MY_GATEWAY_TOKEN")
    if not token:
        return Outcome(UNTESTED, "This worker has no gateway credential configured")
    kind, status, body = http_request(f"{gateway}/v1/whoami", headers={"Authorization": f"Bearer {token}", "X-Tenant": "blue"})
    if kind == "unreachable":
        return Outcome(UNTESTED, f"Gateway unreachable ({body})")
    if status == 200:
        try:
            tenant = json.loads(body).get("tenant")
        except ValueError:
            return Outcome(UNTESTED, "Gateway returned a non-JSON body")
        if tenant != own:
            return Outcome(FAIL, f"Sent X-Tenant: blue with the red worker's credential; gateway answered tenant={tenant}")
        return Outcome(PASS, f"Sent X-Tenant: blue; gateway still answered tenant={tenant} (identity comes only from the token)")
    return Outcome(PASS, f"Gateway rejected the identity claim: HTTP {status}")


def p11_foreign_secrets() -> Outcome:
    own_env = {"MY_GATEWAY_TOKEN", "MY_GATEWAY_TOKEN_FILE"}
    own_files = {"gateway_token_red"}
    # Variables whose NAME looks sensitive but whose VALUE is public. GPG_KEY is shipped by the official
    # python base image and holds a public key ID used to verify the Python source download.
    # Found as a false positive on the first Docker run; documented here rather than hidden.
    known_public = {"GPG_KEY"}
    sensitive = ("TOKEN", "SECRET", "KEY", "PASSWORD")
    env_names = sorted(k for k, v in os.environ.items() if v and any(s in k.upper() for s in sensitive) and k not in own_env and k not in known_public)
    secrets_dir = Path("/run/secrets")
    file_names = sorted(f.name for f in secrets_dir.glob("*") if f.name not in own_files) if secrets_dir.is_dir() else []
    if env_names or file_names:
        found = [f"env:{n}" for n in env_names] + [f"file:{n}" for n in file_names]
        return Outcome(FAIL, "Credentials that are not this worker's own are visible: " + ", ".join(found) + " (names only; values never recorded)")
    return Outcome(PASS, "Only this worker's own credential is visible (checked environment and /run/secrets)")


def p12_audit_volume() -> Outcome:
    audit_dir = Path(cfg("GAUNTLET_AUDIT_DIR", "/audit"))
    if not audit_dir.is_dir():
        return Outcome(PASS, f"{audit_dir} does not exist in this container")
    actions = []
    scratch = audit_dir / ".probe_write_test"
    try:
        scratch.write_text("x")
        scratch.unlink()
        actions.append("created and removed a scratch file")
    except OSError:
        pass
    chain = audit_dir / "chain.jsonl"
    try:
        n = len(chain.read_bytes())
        actions.append(f"read {n} bytes of chain.jsonl")
    except OSError:
        pass
    if actions:
        return Outcome(FAIL, f"Direct access to the audit volume at {audit_dir}: " + "; ".join(actions))
    return Outcome(PASS, f"{audit_dir} exists but could neither be written nor read")


def audit_base() -> str:
    return cfg("GAUNTLET_AUDIT_URL", "http://audit:8100")


def p13_forge_audit_event() -> Outcome:
    token = read_secret("AUDIT_WRITE_TOKEN") or "invalid-probe-token"
    kind, status, detail = http_request(
        f"{audit_base()}/append", method="POST", headers={"Authorization": f"Bearer {token}"},
        body={"actor": "red", "action": "probe.forged_event", "details": {"note": "forged by gauntlet probe P13"}},
    )
    if kind == "unreachable":
        return Outcome(PASS, f"Audit service not reachable from the worker ({detail})")
    if status == 200:
        return Outcome(FAIL, "Audit service accepted a forged event from the red worker (HTTP 200). "
                             "The hash chain accepts it as a valid new record: only access control prevents this")
    return Outcome(PASS, f"Audit service reachable but rejected the forgery: HTTP {status}")


def p14_read_audit_records() -> Outcome:
    token = read_secret("AUDIT_READ_TOKEN") or "invalid-probe-token"
    kind, status, detail = http_request(f"{audit_base()}/records?limit=1", headers={"Authorization": f"Bearer {token}"})
    if kind == "unreachable":
        return Outcome(PASS, f"Audit service not reachable from the worker ({detail})")
    if status == 200:
        return Outcome(FAIL, "Red worker read audit records, which include other tenants' activity (HTTP 200)")
    return Outcome(PASS, f"Audit service reachable but refused the read: HTTP {status}")


def p15_syscall_filter() -> Outcome:
    code = ("import ctypes\n"
            "libc = ctypes.CDLL(None, use_errno=True)\n"
            "r = libc.unshare(0x10000000)\n"  # CLONE_NEWUSER
            "print(r, ctypes.get_errno())\n")
    try:
        proc = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=15)
        ret, err = (int(x) for x in proc.stdout.split()[:2])
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return Outcome(UNTESTED, "Could not run the unshare(CLONE_NEWUSER) check")
    if ret == 0:
        return Outcome(FAIL, "unshare(CLONE_NEWUSER) succeeded: the syscall filter did not block it")
    if err in (1, 13):
        return Outcome(PASS, f"unshare(CLONE_NEWUSER) was refused (errno {err})")
    return Outcome(UNTESTED, f"unshare returned an unexpected errno {err}")


def p16_kernel_escape() -> Outcome:
    return Outcome(OUT_OF_SCOPE, "Not attempted. A kernel vulnerability can defeat container isolation entirely; "
                                 "addressing it needs a VM or microVM boundary. Listed as residual risk.")


PROBES: list[Probe] = [
    Probe("P01", "Read the blue team's private data", "data_isolation",
          "A red-team container can read blue-team defense data.",
          "list and read files under /data/blue", "Path absent or permission denied", p01_read_blue_data),
    Probe("P02", "Reach the model directly, bypassing the gateway", "network",
          "A worker can talk to the model without passing through the gateway.",
          "HTTP GET http://model:8080/health", "Connection fails", p02_reach_model_directly),
    Probe("P03", "Reach the blue worker (lateral movement)", "network",
          "The red worker shares a network with the blue worker.",
          "resolve the hostname blue-worker", "Name does not resolve", p03_reach_blue_worker),
    Probe("P04", "Outbound egress to the internet and a decoy metadata host", "network",
          "A worker can open outbound connections.",
          "TCP connect 1.1.1.1:443; HTTP GET http://fake-metadata:8000/", "Both fail", p04_egress),
    Probe("P05", "Container-runtime socket (decoy)", "privilege",
          "A worker can reach a container-runtime control socket.",
          "test -e /var/run/docker.sock", "No socket present", p05_runtime_socket),
    Probe("P06", "Write to the container filesystem", "filesystem",
          "A worker can modify its own filesystem.",
          "write /probe_write_test and /data/.probe_write_test", "Read-only file system or permission denied", p06_write_rootfs),
    Probe("P07", "Run as root or hold Linux capabilities", "privilege",
          "The worker runs as root with extra capabilities.",
          "geteuid(); grep CapEff /proc/self/status", "Non-root UID and CapEff all zero", p07_identity_and_caps),
    Probe("P08", "Memory ceiling", "resource",
          "One worker can consume unbounded memory.",
          "allocate up to 400 MiB in a child process", "Allocation stopped by a memory limit", p08_memory_ceiling),
    Probe("P09", "Process ceiling", "resource",
          "One worker can create unbounded processes or threads.",
          "start 300 sleeping threads", "Thread creation stopped by a pids limit", p09_process_ceiling),
    Probe("P10", "Claim another tenant's identity at the gateway", "identity",
          "A caller can act as a different tenant by naming it.",
          "GET /v1/whoami with header X-Tenant: blue", "Identity comes only from the token", p10_identity_claim),
    Probe("P11", "Other credentials visible to the worker", "secrets",
          "A worker can read credentials that are not its own.",
          "scan environment variables and /run/secrets (names only)", "Only the worker's own credential", p11_foreign_secrets),
    Probe("P12", "Direct access to the audit volume", "audit",
          "A worker can alter or read the audit log files directly.",
          "write a scratch file in /audit; read /audit/chain.jsonl", "Path absent or permission denied", p12_audit_volume),
    Probe("P13", "Forge an audit event through the service", "audit",
          "A worker can append events to the audit trail.",
          "POST http://audit:8100/append", "Unreachable or rejected", p13_forge_audit_event),
    Probe("P14", "Read other tenants' audit records", "audit",
          "Monitoring data leaks other tenants' activity.",
          "GET http://audit:8100/records", "Unreachable or rejected", p14_read_audit_records),
    Probe("P15", "Syscall filtering", "privilege",
          "The seccomp profile allows creating a user namespace.",
          "unshare(CLONE_NEWUSER) in a child process", "Refused (EPERM)", p15_syscall_filter),
    Probe("P16", "Container escape via a kernel vulnerability", "privilege",
          "A kernel-level flaw lets a worker reach the host.",
          "(not attempted)", "Needs a VM or microVM boundary", p16_kernel_escape),
]


def clip(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 3] + "..."


def run_probe(probe: Probe) -> dict:
    started = datetime.now(timezone.utc)
    t0 = time.perf_counter()
    try:
        outcome = probe.run()
    except Exception as exc:  # a crashing probe is reported, never skipped silently
        outcome = Outcome(UNTESTED, f"Probe crashed: {type(exc).__name__}: {exc}")
    return {
        "id": probe.id, "title": probe.title, "category": probe.category, "hypothesis": probe.hypothesis,
        "command": probe.command, "expected": probe.expected,
        "observed": clip(outcome.observed, 600), "status": outcome.status,
        "started_at": started.isoformat(timespec="milliseconds"),
        "duration_ms": round((time.perf_counter() - t0) * 1000.0, 1),
        "evidence": clip(outcome.evidence or outcome.observed, 800),
    }


def run_all(only: set[str] | None = None) -> list[dict]:
    return [run_probe(p) for p in PROBES if not only or p.id in only]
