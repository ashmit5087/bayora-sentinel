import type { Config, GauntletRun, ProbeResult } from "../lib/types";
import { StatusChip } from "./Chip";
import { Topology } from "./Topology";

const INSIDE = ["P05", "P06", "P07", "P08", "P09", "P11", "P15", "P16"];

export function Evidence({ runs, config, setConfig, selected, onSelect, auditHashes, onJumpToRecord }: {
  runs: Partial<Record<Config, GauntletRun>>;
  config: Config;
  setConfig: (c: Config) => void;
  selected: string;
  onSelect: (id: string) => void;
  auditHashes: Map<string, number>;
  onJumpToRecord: (idx: number) => void;
}) {
  const run = runs[config];
  const probe: ProbeResult | undefined = run?.probes.find((p) => p.id === selected);
  const other: Config = config === "insecure" ? "hardened" : "insecure";
  const otherProbe = runs[other]?.probes.find((p) => p.id === selected);
  const recordIdx = probe?.audit_hash ? auditHashes.get(probe.audit_hash) : undefined;

  return (
    <aside className="evidence" aria-label="Evidence for the selected attack">
      <div className="seg" role="group" aria-label="Which build to show">
        {(["insecure", "hardened"] as Config[]).map((c) => (
          <button key={c} type="button" className={config === c ? "is-on" : ""} aria-pressed={config === c} onClick={() => setConfig(c)}>
            {c === "insecure" ? "Insecure build" : "Hardened build"}
          </button>
        ))}
      </div>

      <Topology config={config} run={run} selected={selected} />

      <div className="inside">
        <span className="inside-label">Inside the red worker, and the host beneath it</span>
        <div className="inside-chips">
          {INSIDE.map((id) => {
            const p = run?.probes.find((q) => q.id === id);
            return (
              <button key={id} type="button" className={`mini mini-${p?.status ?? "none"}${selected === id ? " is-selected" : ""}`} onClick={() => onSelect(id)} title={p?.title} aria-pressed={selected === id}>
                {id}
              </button>
            );
          })}
        </div>
      </div>

      {probe ? (
        <div className="detail">
          <div className="detail-top">
            <h3>{probe.title}</h3>
            <StatusChip status={probe.status} />
          </div>
          <p className="detail-hyp">{probe.hypothesis}</p>
          <dl>
            <dt>What we ran</dt>
            <dd><code>{probe.command}</code></dd>
            <dt>What a working defense looks like</dt>
            <dd>{probe.expected}</dd>
            <dt>What happened</dt>
            <dd><code className="block">{probe.observed}</code></dd>
          </dl>
          <div className="detail-meta">
            <span>{probe.duration_ms.toFixed(0)} ms</span>
            {otherProbe && <span>{other === "insecure" ? "Insecure build" : "Hardened build"}: <StatusChip status={otherProbe.status} small /></span>}
            {probe.audit_hash && (recordIdx !== undefined ? (
              <button type="button" className="hashlink" onClick={() => onJumpToRecord(recordIdx)}>Audit record {recordIdx}: {probe.audit_hash.slice(0, 10)}</button>
            ) : (
              <span className="hashnote" title="This result is recorded in that build's own audit chain, which is not the one shown below.">Audit hash {probe.audit_hash.slice(0, 10)}</span>
            ))}
          </div>
        </div>
      ) : (
        <p className="empty">No result for {selected} in this build yet. Run <code>python scripts/run_gauntlet.py both</code>.</p>
      )}
    </aside>
  );
}
