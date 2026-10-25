import type { Config, GauntletRun, ProbeResult, Status } from "../lib/types";
import { StatusChip } from "./Chip";

function counts(run: GauntletRun | undefined) {
  const c = { worked: 0, failed: 0, notRun: 0, scope: 0 };
  run?.probes.forEach((p) => {
    if (p.status === "fail") c.worked++;
    else if (p.status === "pass") c.failed++;
    else if (p.status === "untested") c.notRun++;
    else c.scope++;
  });
  return c;
}

function Column({ title, run }: { title: string; run: GauntletRun | undefined }) {
  const c = counts(run);
  const tried = c.worked + c.failed;
  return (
    <div className="ledger-colhead">
      <div className="ledger-colname">{title}</div>
      {run ? (
        <>
          <div className="ledger-count"><strong>{c.worked}</strong> of {tried} breaches worked</div>
          {(c.notRun > 0 || c.scope > 0) && (
            <div className="ledger-sub">{[c.notRun ? `${c.notRun} not run` : "", c.scope ? `${c.scope} out of scope` : ""].filter(Boolean).join(", ")}</div>
          )}
        </>
      ) : (
        <div className="ledger-sub">No results yet</div>
      )}
    </div>
  );
}

export function Ledger({ runs, selected, onSelect }: {
  runs: Partial<Record<Config, GauntletRun>>;
  selected: string;
  onSelect: (id: string, config?: Config) => void;
}) {
  const ids = Array.from(new Set([...(runs.insecure?.probes ?? []), ...(runs.hardened?.probes ?? [])].map((p) => p.id))).sort();
  const find = (cfg: Config, id: string): ProbeResult | undefined => runs[cfg]?.probes.find((p) => p.id === id);
  const title = (id: string) => (find("hardened", id) ?? find("insecure", id))?.title ?? id;

  return (
    <div className="ledger" role="table" aria-label="The same attacks against both builds">
      <div className="ledger-head" role="row">
        <div className="ledger-attack" role="columnheader">
          <span className="ledger-colname">Attack</span>
          <span className="ledger-sub">Each row is one attempted breach, run from inside the red-team container.</span>
        </div>
        <Column title="Insecure build" run={runs.insecure} />
        <Column title="Hardened build" run={runs.hardened} />
      </div>
      {ids.map((id) => {
        const a: Status | undefined = find("insecure", id)?.status;
        const b: Status | undefined = find("hardened", id)?.status;
        return (
          <div key={id} role="row" className={`ledger-row${selected === id ? " is-selected" : ""}`}>
            <button type="button" className="ledger-attack ledger-pick" onClick={() => onSelect(id)} aria-pressed={selected === id}>
              <span className="ledger-code">{id}</span>
              <span>{title(id)}</span>
            </button>
            <div className="ledger-cell" role="cell"><StatusChip status={a} /></div>
            <div className="ledger-cell" role="cell"><StatusChip status={b} /></div>
          </div>
        );
      })}
      <p className="ledger-foot">“Held” means that one probe failed to breach the build on this setup. It is not a claim that the build is secure.</p>
    </div>
  );
}
