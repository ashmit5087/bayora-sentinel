import { useCallback, useEffect, useRef, useState } from "react";

interface Node { id: string; label: string; state: "pending" | "running" | "done" | "failed" | "cancelled" }
interface JobView { id: string; action: string; title: string; state: "running" | "done" | "failed" | "cancelled"; nodes: Node[]; log: string[]; elapsed_s: number }
interface Status { control: boolean; docker: boolean; env_ready: boolean; job: JobView | null }

const GLYPH: Record<Node["state"], string> = { pending: "○", running: "◐", done: "✓", failed: "✕", cancelled: "–" };
const ACTIONS: { id: string; title: string; note: string }[] = [
  { id: "gauntlet_insecure", title: "Attack the insecure build", note: "16 attacks, about 1 minute" },
  { id: "gauntlet_hardened", title: "Attack the hardened build", note: "Also signs the audit log" },
  { id: "timing", title: "Measure the cache timing leak", note: "Needs the model file; 10 to 25 min" },
  { id: "everything", title: "Run everything", note: "All of the above, in order" },
];
const post = (url: string, body?: unknown) =>
  fetch(url, { method: "POST", headers: { "Content-Type": "application/json", "X-Sentinel-Control": "1" }, body: JSON.stringify(body ?? {}) });

export function Control({ onFinished }: { onFinished: () => void }) {
  const [st, setSt] = useState<Status | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [trials, setTrials] = useState(20);
  const prev = useRef<string | null>(null);
  const logRef = useRef<HTMLPreElement>(null);

  const poll = useCallback(async () => {
    try {
      const r = await fetch("/api/status", { cache: "no-store" });
      if (!r.ok || !(r.headers.get("content-type") ?? "").includes("json")) throw new Error("no control server");
      setSt((await r.json()) as Status);
    } catch {
      setSt(null);
    }
  }, []);

  useEffect(() => { poll(); const t = setInterval(poll, st?.job?.state === "running" ? 1000 : 4000); return () => clearInterval(t); }, [poll, st?.job?.state]);
  useEffect(() => {
    const s = st?.job ? `${st.job.id}:${st.job.state}` : null;
    if (prev.current?.endsWith(":running") && s && !s.endsWith(":running")) onFinished();
    prev.current = s;
  }, [st, onFinished]);
  useEffect(() => { logRef.current?.scrollTo({ top: logRef.current.scrollHeight }); }, [st?.job?.log.length]);

  async function start(action: string) {
    setErr(null);
    const r = await post("/api/run", { action, trials });
    if (!r.ok) setErr(((await r.json().catch(() => ({}))) as { detail?: string }).detail ?? "Could not start");
    poll();
  }

  if (!st) {
    return (
      <div className="ctl ctl-off">
        <p><strong>Control server not running.</strong> The buttons need it because Docker lives on your computer. Showing the last recorded results below.</p>
        <p>Start it with <code>python scripts/control_server.py</code>, then open <code>http://127.0.0.1:8765</code>.</p>
      </div>
    );
  }
  const job = st.job, busy = job?.state === "running";
  const blocked = !st.docker ? "Docker is not running. Start Docker Desktop." : !st.env_ready ? "Run python scripts/gen_env.py once." : null;

  return (
    <div className="ctl">
      <div className="ctl-actions">
        {ACTIONS.map((a) => (
          <button key={a.id} type="button" className="ctl-btn" disabled={busy || !!blocked} onClick={() => start(a.id)}>
            <strong>{a.title}</strong><span>{a.note}</span>
          </button>
        ))}
      </div>
      <div className="ctl-opts">
        <label>Timing guesses per mode{" "}
          <select value={trials} disabled={busy} onChange={(e) => setTrials(Number(e.target.value))}>
            <option value={20}>20 (quicker)</option><option value={40}>40 (stronger statistics)</option>
          </select>
        </label>
        {blocked && <span className="ctl-warn" role="alert">{blocked}</span>}
        {err && <span className="ctl-warn" role="alert">{err}</span>}
      </div>

      {job && (
        <div className="ctl-job">
          <div className="ctl-jobhead">
            <strong>{job.title}</strong>
            <span className={`ctl-state ctl-${job.state}`}>{job.state === "running" ? "Running" : job.state === "done" ? "Finished" : job.state === "failed" ? "Failed" : "Cancelled"} · {Math.round(job.elapsed_s)} s</span>
            {busy && <button type="button" className="ctl-cancel" onClick={() => post("/api/cancel").then(poll)}>Stop</button>}
          </div>
          <ol className="steps">
            {job.nodes.map((n) => (
              <li key={n.id} className={`step step-${n.state}`}><span aria-hidden="true" className="step-glyph">{GLYPH[n.state]}</span>{n.label}</li>
            ))}
          </ol>
          <pre className="ctl-log" ref={logRef} aria-label="Live output">{job.log.join("\n")}</pre>
        </div>
      )}
    </div>
  );
}
