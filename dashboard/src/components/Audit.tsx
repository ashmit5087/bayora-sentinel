import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { AuditExport, AuditRecord } from "../lib/types";
import { appendForged, editRecord, rewriteFrom, truncate, verifyAgainstCheckpoints, verifyChain } from "../lib/audit";
import type { ChainVerdict, CheckpointVerdict } from "../lib/audit";

function Verdict({ title, ok, text, detail }: { title: string; ok: boolean | null; text: string; detail?: string }) {
  return (
    <div className={`verdict ${ok === null ? "verdict-wait" : ok ? "verdict-ok" : "verdict-bad"}`} role="status">
      <span className="verdict-title">{title}</span>
      <strong><span aria-hidden="true">{ok === null ? "…" : ok ? "✓ " : "✕ "}</span>{text}</strong>
      {detail && <span className="verdict-detail">{detail}</span>}
    </div>
  );
}

export function Audit({ audit, focus }: { audit: AuditExport | null; focus: number | null }) {
  const [records, setRecords] = useState<AuditRecord[]>(audit?.records ?? []);
  const [label, setLabel] = useState("Untouched copy of the recorded chain");
  const [chain, setChain] = useState<ChainVerdict | null>(null);
  const [cp, setCp] = useState<CheckpointVerdict | null>(null);
  const rowRefs = useRef<Record<number, HTMLLIElement | null>>({});

  useEffect(() => { if (audit) setRecords(audit.records); }, [audit]);
  useEffect(() => {
    if (!audit) return;
    let live = true;
    setChain(null); setCp(null);
    (async () => {
      const a = await verifyChain(records);
      const b = await verifyAgainstCheckpoints(records, audit.checkpoints, audit.public_key_pem);
      if (live) { setChain(a); setCp(b); }
    })();
    return () => { live = false; };
  }, [records, audit]);
  useEffect(() => { if (focus !== null) rowRefs.current[focus]?.scrollIntoView({ block: "center", behavior: "smooth" }); }, [focus]);

  const cpAt = useMemo(() => new Set((audit?.checkpoints ?? []).map((c) => c.idx)), [audit]);
  const act = useCallback((l: string, f: () => AuditRecord[] | Promise<AuditRecord[]>) => async () => { setRecords(await f()); setLabel(l); }, []);

  if (!audit || !audit.records.length) return <p className="empty">No audit chain yet. Run <code>python scripts/run_gauntlet.py hardened</code>.</p>;
  const n = audit.records.length;
  const k = Math.max(1, Math.floor((audit.checkpoints.at(-1)?.idx ?? n) / 2));
  const tampered = records !== audit.records;

  return (
    <div className="audit">
      <div className="audit-tools">
        <p className="audit-label">Working on: <strong>{label}</strong>. This is an in-browser copy; the real chain is never touched.</p>
        <div className="btnrow">
          <button type="button" onClick={act(`Record ${k} edited`, () => editRecord(audit.records, k))}>Edit record {k}</button>
          <button type="button" onClick={act(`History rewritten from record ${k}, every hash recomputed`, () => rewriteFrom(audit.records, k))}>Rewrite history from {k}</button>
          <button type="button" onClick={act("Last 2 records deleted", () => truncate(audit.records, 2))}>Delete last 2</button>
          <button type="button" onClick={act("2 forged records appended with valid hashes", () => appendForged(audit.records, 2))}>Append 2 forged</button>
          <button type="button" className="btn-quiet" disabled={!tampered} onClick={act("Untouched copy of the recorded chain", () => audit.records)}>Reset</button>
        </div>
      </div>

      <div className="verdicts">
        <Verdict title="Hash chain alone" ok={chain ? chain.ok : null}
          text={chain ? (chain.ok ? "Valid" : `Rejected at record ${chain.brokenAt}`) : "Checking"} detail={chain?.reason ?? undefined} />
        <Verdict title="Hash chain + signed checkpoints" ok={cp ? cp.ok : null}
          text={cp ? (cp.ok ? (cp.anchoredThrough === null ? "Valid, nothing anchored" : `Valid, anchored through record ${cp.anchoredThrough}`) : "Rejected") : "Checking"}
          detail={cp ? (cp.ok ? (cp.unanchored > 0 ? `${cp.unanchored} newer record(s) are not anchored yet, so they cannot be vouched for.` : undefined) : cp.reason ?? undefined) : undefined} />
      </div>

      <ol className="chain" aria-label="Audit records">
        {records.map((r, i) => (
          <li key={i} ref={(el) => { rowRefs.current[i] = el; }}
              className={`chain-row${chain?.suspect[i] ? " is-suspect" : ""}${focus === i ? " is-focus" : ""}${i === (cp?.anchoredThrough ?? -1) ? " is-anchor" : ""}`}>
            <span className="chain-idx">{r.idx}</span>
            <span className="chain-what"><b>{r.actor}</b> {r.action}{typeof r.details?.probe_id === "string" ? ` ${r.details.probe_id} → ${String(r.details.status)}` : ""}</span>
            <code className="chain-hash">{r.hash.slice(0, 10)}</code>
            {cpAt.has(r.idx) ? <span className="flag">signed checkpoint</span> : <span />}
          </li>
        ))}
      </ol>
    </div>
  );
}
