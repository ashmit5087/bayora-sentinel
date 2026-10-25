import { useCallback, useEffect, useMemo, useState } from "react";
import { loadAll } from "./lib/data";
import type { Dataset } from "./lib/data";
import type { Config } from "./lib/types";
import { Ledger } from "./components/Ledger";
import { Evidence } from "./components/Evidence";
import { Timing } from "./components/Timing";
import { Audit } from "./components/Audit";
import { Limits } from "./components/Limits";
import { Control } from "./components/Control";

export default function App() {
  const [data, setData] = useState<Dataset | null>(null);
  const [selected, setSelected] = useState("P02");
  const [config, setConfig] = useState<Config>("insecure");
  const [focus, setFocus] = useState<number | null>(null);

  useEffect(() => { loadAll().then(setData); }, []);
  const reload = useCallback(() => { loadAll().then(setData); }, []);

  const auditHashes = useMemo(() => new Map((data?.audit?.records ?? []).map((r) => [r.hash, r.idx])), [data]);
  if (!data) return <main className="page"><p className="empty">Loading results…</p></main>;

  const sources = [data.gauntlet.insecure?.source, data.gauntlet.hardened?.source, data.side?.source, data.audit?.source];
  const placeholder = sources.some((s) => s === "fixture");
  const started = data.gauntlet.hardened?.started_at ?? data.gauntlet.insecure?.started_at;

  return (
    <main className="page">
      <header className="top">
        <div>
          <p className="eyebrow">Bayora Sentinel · Hack in Hills ’26 · PS 04</p>
          <h1>We don’t claim the sandbox is secure. We attack it and show what held.</h1>
          <p className="lede">Sixteen attacks run from inside a red-team container against two builds of the same AI testing lab. Every result is written to a tamper-evident audit log you can verify in this page.</p>
        </div>
        <p className="stamp">{placeholder ? "Placeholder data" : "Recorded run"}{started ? ` · ${new Date(started).toLocaleString()}` : ""}</p>
      </header>

      {(placeholder || data.missing.length > 0) && (
        <p className="banner" role="alert">
          {placeholder ? "Some of this data is placeholder, not a measurement. Use the Control room above to run the experiments. " : ""}
          {data.missing.length ? `Missing: ${data.missing.join(", ")}.` : ""}
        </p>
      )}

      <section aria-labelledby="h-control">
        <h2 id="h-control">Control room</h2>
        <Control onFinished={reload} />
      </section>

      <section aria-labelledby="h-matrix">
        <h2 id="h-matrix">1 · Breakout Gauntlet</h2>
        <div className="hero">
          <Ledger runs={data.gauntlet} selected={selected} onSelect={setSelected} />
          <Evidence runs={data.gauntlet} config={config} setConfig={setConfig} selected={selected} onSelect={setSelected}
            auditHashes={auditHashes} onJumpToRecord={(i) => { setFocus(i); document.getElementById("h-audit")?.scrollIntoView({ behavior: "smooth" }); }} />
        </div>
      </section>

      <section aria-labelledby="h-timing">
        <h2 id="h-timing">2 · Can one tenant see another’s prompts through timing?</h2>
        <Timing side={data.side} />
      </section>

      <section aria-labelledby="h-audit">
        <h2 id="h-audit">3 · Can the audit log be rewritten without anyone noticing?</h2>
        <Audit audit={data.audit} focus={focus} />
      </section>

      <section aria-labelledby="h-limits">
        <h2 id="h-limits">What these results do not cover</h2>
        <Limits />
      </section>
    </main>
  );
}
