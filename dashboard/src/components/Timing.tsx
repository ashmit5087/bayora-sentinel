import { useMemo } from "react";
import type { SideChannelMode, SideChannelRun } from "../lib/types";
import { fmtMs, fmtP, histogram, median } from "../lib/stats";

const W = 300, H = 120, PAD = 18, BINS = 16;

function Panel({ m }: { m: SideChannelMode }) {
  const { hit, miss, lo, hi } = useMemo(() => {
    const all = [...m.hit_ms, ...m.miss_ms];
    const lo = Math.min(...all), hi = Math.max(...all);
    const span = hi - lo || 1;
    return { lo: lo - span * 0.02, hi: hi + span * 0.02, hit: [] as number[], miss: [] as number[] };
  }, [m]);
  const hb = histogram(m.hit_ms, lo, hi, BINS), mb = histogram(m.miss_ms, lo, hi, BINS);
  const max = Math.max(1, ...hb.map((b) => b.count), ...mb.map((b) => b.count));
  const bw = (W - 2 * PAD) / BINS;
  const bar = (b: { count: number }, i: number, cls: string) => (
    <rect key={`${cls}${i}`} className={cls} x={PAD + i * bw + 1} width={Math.max(1, bw - 2)} y={H - PAD - (b.count / max) * (H - 2 * PAD)} height={(b.count / max) * (H - 2 * PAD)} />
  );
  void hit; void miss;
  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="hist" role="img" aria-label={`Latency distributions for ${m.mode} mode: correct guesses median ${fmtMs(median(m.hit_ms))}, wrong guesses median ${fmtMs(median(m.miss_ms))}`}>
      <line x1={PAD} x2={W - PAD} y1={H - PAD} y2={H - PAD} className="hist-axis" />
      {hb.map((b, i) => bar(b, i, "hist-hit"))}
      {mb.map((b, i) => bar(b, i, "hist-miss"))}
      <text x={PAD} y={H - 4} className="hist-tick">{fmtMs(lo)}</text>
      <text x={W - PAD} y={H - 4} textAnchor="end" className="hist-tick">{fmtMs(hi)}</text>
    </svg>
  );
}

const NAME: Record<string, string> = { shared: "Shared cache (insecure default)", isolated: "Per-tenant cache slots (hardened)", off: "Cache off" };

function sentence(m: SideChannelMode): string {
  const sig = m.perm_p !== null ? m.perm_p < 0.01 : m.auc_hit_faster > 0.9;
  const hit = fmtMs(median(m.hit_ms)), miss = fmtMs(median(m.miss_ms));
  if (m.auc_hit_faster >= 0.9 && sig)
    return `An attacker can tell whether another tenant's prompt prefix is cached: correct guesses answer in ${hit}, wrong ones in ${miss}.`;
  if (m.perm_p !== null && m.perm_p >= 0.05) return `No reliable timing difference between correct (${hit}) and wrong (${miss}) guesses in this run.`;
  return `Weak or unclear signal (correct ${hit}, wrong ${miss}). Not enough to call either way.`;
}

export function Timing({ side }: { side: SideChannelRun | null }) {
  if (!side) return <p className="empty">No timing results yet. Run <code>python scripts/convert_timing.py</code>.</p>;
  return (
    <div>
      <div className="legend">
        <span><i className="sw sw-hit" /> Attacker guessed the prefix correctly</span>
        <span><i className="sw sw-miss" /> Attacker guessed wrong</span>
      </div>
      <div className="timing-grid">
        {side.modes.map((m) => (
          <article key={m.mode} className="timing-card">
            <h3>{NAME[m.mode] ?? m.mode}</h3>
            <p className="timing-say">{sentence(m)}</p>
            <Panel m={m} />
            <dl className="stats">
              <div><dt>Separability (AUC)</dt><dd>{m.auc_hit_faster.toFixed(2)}</dd></div>
              <div><dt>Permutation test</dt><dd>{fmtP(m.perm_p)}</dd></div>
              <div><dt>Effect size (d)</dt><dd>{m.cohens_d.toFixed(1)}</dd></div>
              <div><dt>Trials</dt><dd>{m.hit_ms.length} + {m.miss_ms.length}</dd></div>
            </dl>
          </article>
        ))}
      </div>
      <p className="note">AUC 0.5 means the attacker learns nothing from timing; 1.0 means timing reveals the answer every time. Model: {side.model}, prompts of about {side.approx_prompt_tokens ?? "?"} tokens.</p>
      <p className="note"><strong>Trade-off:</strong> per-tenant slots remove the shared cache, so tenants no longer reuse each other's prefixes. Isolation costs speed.</p>
      <ul className="caveats">{side.caveats.map((c) => <li key={c}>{c}</li>)}</ul>
    </div>
  );
}
