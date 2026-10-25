"""Local control server: lets the dashboard start the lab's experiments with buttons.

Runs ON THE LAPTOP (it needs Docker). It can only run a fixed list of actions, never an arbitrary command,
listens on 127.0.0.1 only, rejects foreign Host/Origin headers, and runs one job at a time.

    python scripts/control_server.py        # then open http://127.0.0.1:8765
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from sentinel.control.payload import normalise

ROOT = Path(__file__).resolve().parent.parent.parent
PY = sys.executable
PORT = 8765
ALLOWED_HOSTS = {f"127.0.0.1:{PORT}", f"localhost:{PORT}"}
ALLOWED_ORIGINS = [f"http://127.0.0.1:{PORT}", f"http://localhost:{PORT}", "http://127.0.0.1:5173", "http://localhost:5173"]


@dataclass
class Cmd:
    argv: list[str]
    cwd: Path = ROOT
    # (node id, label, marker). A node starts when its marker text appears in the output; the first node starts with the command.
    nodes: list[tuple[str, str, str | None]] = field(default_factory=list)


def gauntlet(cfg: str) -> list[Cmd]:
    nodes = [(f"{cfg}-up", f"Build and start the {cfg} lab", None),
             (f"{cfg}-probes", "Run the 16 attacks from inside the red worker", "running probes"),
             (f"{cfg}-audit", "Write every result into the audit chain", "recording results"),
             ]
    if cfg == "hardened":
        nodes.append((f"{cfg}-sign", "Sign a checkpoint (separate signer container)", "signing a checkpoint"))
    nodes.append((f"{cfg}-export", "Export the chain so the browser can verify it", "exporting the audit chain"))
    return [Cmd([PY, "-u", "scripts/run_gauntlet.py", cfg], nodes=nodes)]


def timing(trials: int) -> list[Cmd]:
    spike = ROOT / "spike"
    return [
        Cmd(["docker", "compose", "-f", "compose.cpu.yaml", "up", "-d"], spike, [("model", "Start the model server", None)]),
        Cmd([PY, "-u", "timing.py", "--mode", "shared", "--trials", str(trials)], spike,
            [("t-wait", "Wait for the model to be ready", None), ("t-shared", f"Shared cache: {trials} guesses", "=== mode: shared")]),
        Cmd([PY, "-u", "timing.py", "--mode", "isolated", "--trials", str(trials)], spike,
            [("t-wait2", "Reconnect to the model", None), ("t-isolated", f"Per-tenant cache slots: {trials} guesses", "=== mode: isolated")]),
        Cmd([PY, "-u", "scripts/convert_timing.py"], ROOT, [("t-convert", "Compute the statistics", None)]),
    ]


ACTIONS: dict[str, Callable[[int], list[Cmd]]] = {
    "gauntlet_insecure": lambda t: gauntlet("insecure"),
    "gauntlet_hardened": lambda t: gauntlet("hardened"),
    "timing": timing,
    "everything": lambda t: gauntlet("insecure") + gauntlet("hardened") + timing(t),
}
TITLES = {"gauntlet_insecure": "Attack the insecure build", "gauntlet_hardened": "Attack the hardened build",
          "timing": "Measure the cache timing channel", "everything": "Run everything"}


class Job:
    def __init__(self, action: str, plan: list[Cmd]):
        self.action, self.plan = action, plan
        self.id = str(int(time.time() * 1000))
        self.state = "running"          # running | done | failed | cancelled
        self.nodes = [{"id": n[0], "label": n[1], "state": "pending"} for c in plan for n in c.nodes]
        self.log: list[str] = []
        self.started = time.time()
        self.finished: float | None = None
        self.proc: subprocess.Popen | None = None
        self.cancel = False
        self.lock = threading.Lock()

    def _set(self, node_id: str, state: str) -> None:
        for n in self.nodes:
            if n["id"] == node_id:
                n["state"] = state

    def _line(self, text: str) -> None:
        with self.lock:
            self.log.append(text)
            del self.log[:-400]

    def run(self) -> None:
        try:
            for cmd in self.plan:
                if self.cancel:
                    break
                if not self._run_cmd(cmd):
                    return self._end("cancelled" if self.cancel else "failed")
            self._end("cancelled" if self.cancel else "done")
        except Exception as exc:  # noqa: BLE001  a crashed job must still end in a visible state
            self._line(f"control server error: {type(exc).__name__}: {exc}")
            self._end("failed")

    def _end(self, state: str) -> None:
        self.state, self.finished = state, time.time()

    def _run_cmd(self, cmd: Cmd) -> bool:
        ids = [n[0] for n in cmd.nodes]
        current = 0
        if ids:
            self._set(ids[0], "running")
        self._line(f"$ {' '.join(os.path.basename(a) if a == PY else a for a in cmd.argv)}")
        env = {**os.environ, "PYTHONUNBUFFERED": "1", "PYTHONIOENCODING": "utf-8"}
        try:
            self.proc = subprocess.Popen(cmd.argv, cwd=cmd.cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                         text=True, encoding="utf-8", errors="replace")
        except FileNotFoundError:
            self._line(f"cannot start '{cmd.argv[0]}': is it installed and on PATH?")
            if ids:
                self._set(ids[current], "failed")
            return False
        if self.cancel:  # Stop was pressed before the process existed
            self.proc.terminate()
        for raw in self.proc.stdout:  # type: ignore[union-attr]
            line = raw.rstrip()
            self._line(line)
            for k in range(current + 1, len(cmd.nodes)):
                marker = cmd.nodes[k][2]
                if marker and marker in line:
                    for j in range(current, k):
                        self._set(ids[j], "done")
                    current = k
                    self._set(ids[k], "running")
        code = self.proc.wait()
        if code == 0:
            for i in ids:
                self._set(i, "done")
            return True
        if ids:
            self._set(ids[current], "cancelled" if self.cancel else "failed")
        self._line(f"exit code {code}")
        return False

    def view(self) -> dict:
        with self.lock:
            log = list(self.log[-80:])
        return {"id": self.id, "action": self.action, "title": TITLES.get(self.action, self.action), "state": self.state,
                "nodes": self.nodes, "log": log, "elapsed_s": round((self.finished or time.time()) - self.started, 1)}


FILES = {  # name the dashboard asks for -> (recorded result, placeholder fixture)
    "gauntlet.insecure.json": ("gauntlet.insecure.json", "gauntlet.insecure.json"),
    "gauntlet.hardened.json": ("gauntlet.hardened.json", "gauntlet.hardened.json"),
    "sidechannel.json": ("sidechannel.json", "sidechannel.json"),
    "audit_export.json": ("audit_export.hardened.json", "audit_export.json"),
}


def create_app(root: Path = ROOT, actions: dict | None = None) -> FastAPI:
    acts = actions if actions is not None else ACTIONS
    app = FastAPI(title="Sentinel control server")
    app.add_middleware(CORSMiddleware, allow_origins=ALLOWED_ORIGINS, allow_methods=["GET", "POST"], allow_headers=["Content-Type", "X-Sentinel-Control"])
    state: dict = {"job": None}
    guard = threading.Lock()

    @app.middleware("http")
    async def host_and_origin_guard(request: Request, call_next):
        host = request.headers.get("host", "")
        if host not in ALLOWED_HOSTS and not host.startswith("testserver"):
            return JSONResponse({"detail": "bad host"}, status_code=403)  # blocks DNS-rebinding
        if request.method == "POST":
            origin = request.headers.get("origin")
            if (origin and origin not in ALLOWED_ORIGINS) or request.headers.get("x-sentinel-control") != "1":
                return JSONResponse({"detail": "forbidden"}, status_code=403)
        return await call_next(request)

    def docker_ok() -> bool:
        if not shutil.which("docker"):
            return False
        try:
            return subprocess.run(["docker", "info"], capture_output=True, timeout=8).returncode == 0
        except (subprocess.TimeoutExpired, OSError):
            return False

    @app.get("/api/status")
    def status():
        results = root / "results"
        job: Job | None = state["job"]
        return {"control": True, "docker": docker_ok(), "env_ready": (root / ".env").exists() and (root / "secrets").exists(),
                "has_results": {k: (results / v[0]).exists() for k, v in FILES.items()},
                "actions": [{"id": a, "title": TITLES.get(a, a)} for a in acts],
                "job": job.view() if job else None}

    @app.post("/api/run")
    def run(body: dict):
        action, trials = body.get("action"), body.get("trials", 20)
        if action not in acts:
            raise HTTPException(400, "unknown action")
        if trials not in (20, 40):
            raise HTTPException(400, "trials must be 20 or 40")
        with guard:
            cur: Job | None = state["job"]
            if cur and cur.state == "running":
                raise HTTPException(409, "a job is already running")
            job = Job(action, acts[action](trials))
            state["job"] = job
        threading.Thread(target=job.run, daemon=True).start()
        return job.view()

    @app.post("/api/cancel")
    def cancel():
        job: Job | None = state["job"]
        if job and job.state == "running":
            job.cancel = True
            if job.proc and job.proc.poll() is None:
                job.proc.terminate()
        return {"ok": True}

    @app.get("/data/{name}")
    def data(name: str):
        if name == "manifest.json":
            return JSONResponse({k: ("recorded run" if (root / "results" / v[0]).exists() else "PLACEHOLDER") for k, v in FILES.items()})
        if name not in FILES:
            raise HTTPException(404)
        for path in (root / "results" / FILES[name][0], root / "contracts" / "fixtures" / FILES[name][1]):
            if path.exists():
                return Response(path.read_bytes(), media_type="application/json", headers={"Cache-Control": "no-store"})
        raise HTTPException(404)

    @app.get("/api/data")
    def all_data():
        """Everything the dashboard shows in one object (same shape the hosted page's /api/data returns)."""
        keys = {"gauntlet.insecure.json": "gauntlet_insecure", "gauntlet.hardened.json": "gauntlet_hardened",
                "sidechannel.json": "sidechannel", "audit_export.json": "audit_export"}
        out: dict = {"sources": {}}
        for name, key in keys.items():
            live, fixture = root / "results" / FILES[name][0], root / "contracts" / "fixtures" / FILES[name][1]
            path = live if live.exists() else fixture if fixture.exists() else None
            out[key] = normalise(key, json.loads(path.read_text(encoding="utf-8"))) if path else None
            out["sources"][key] = "recorded" if path == live else "placeholder" if path else "missing"
        stamps = [(root / "results" / v[0]).stat().st_mtime for v in FILES.values() if (root / "results" / v[0]).exists()]
        out["received_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(max(stamps))) if stamps else None
        return JSONResponse(out, headers={"Cache-Control": "no-store"})

    # The Replit-designed UI (ui/) wins; the original dashboard build is the fallback.
    dist = next((d for d in (root / "ui", root / "dashboard" / "dist") if (d / "index.html").exists()), None)
    if dist:
        app.mount("/", StaticFiles(directory=dist, html=True), name="ui")
    return app


def main() -> None:
    import uvicorn
    if not (ROOT / "ui" / "index.html").exists() and not (ROOT / "dashboard" / "dist" / "index.html").exists():
        print("Note: no UI found. Expected ui/index.html (the prebuilt site), or run: cd dashboard && npm run build")
    print(f"Control room: http://127.0.0.1:{PORT}   (Ctrl+C to stop)")
    uvicorn.run(create_app(), host="127.0.0.1", port=PORT, log_level="warning")
