import type { Status } from "../lib/types";

// Status is never colour alone: each state has its own glyph and word.
const LABEL: Record<Status, string> = { fail: "Breached", pass: "Held", untested: "Not run", out_of_scope: "Out of scope" };
const GLYPH: Record<Status, string> = { fail: "✕", pass: "✓", untested: "–", out_of_scope: "○" };

export function StatusChip({ status, small = false }: { status: Status | undefined; small?: boolean }) {
  if (!status) return <span className={`chip chip-none${small ? " chip-sm" : ""}`}>No data</span>;
  return (
    <span className={`chip chip-${status}${small ? " chip-sm" : ""}`}>
      <span aria-hidden="true" className="chip-glyph">{GLYPH[status]}</span>
      {LABEL[status]}
    </span>
  );
}

export const statusWord = (s: Status): string => LABEL[s];
