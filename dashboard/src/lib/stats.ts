export interface Bin {
  from: number;
  to: number;
  count: number;
}

export function histogram(values: number[], lo: number, hi: number, bins: number): Bin[] {
  const width = (hi - lo) / bins || 1;
  const out: Bin[] = Array.from({ length: bins }, (_, i) => ({ from: lo + i * width, to: lo + (i + 1) * width, count: 0 }));
  for (const v of values) out[Math.min(bins - 1, Math.max(0, Math.floor((v - lo) / width)))].count++;
  return out;
}

export function median(values: number[]): number {
  if (!values.length) return NaN;
  const s = [...values].sort((a, b) => a - b);
  const mid = Math.floor(s.length / 2);
  return s.length % 2 ? s[mid] : (s[mid - 1] + s[mid]) / 2;
}

export function fmtMs(ms: number): string {
  if (!Number.isFinite(ms)) return "n/a";
  return ms >= 1000 ? `${(ms / 1000).toFixed(2)} s` : `${Math.round(ms)} ms`;
}

export function fmtP(p: number | null): string {
  if (p === null || p === undefined) return "n/a";
  return p < 0.001 ? "p < 0.001" : `p = ${p.toFixed(3)}`;
}
