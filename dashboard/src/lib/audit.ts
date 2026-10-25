// Re-implements the audit verification from sentinel/audit/{chain,checkpoint}.py in the browser,
// so a viewer can watch the checks run instead of trusting a badge.
import type { AuditRecord, Checkpoint } from "./types";

export const GENESIS = "0".repeat(64);
const enc = new TextEncoder();

/** Same bytes as Python's json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False). */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + value.map(canonicalJson).join(",") + "]";
  const obj = value as Record<string, unknown>;
  return "{" + Object.keys(obj).sort().map((k) => JSON.stringify(k) + ":" + canonicalJson(obj[k])).join(",") + "}";
}

function toHex(buf: ArrayBuffer): string {
  return Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, "0")).join("");
}

export async function sha256Hex(text: string): Promise<string> {
  return toHex(await crypto.subtle.digest("SHA-256", enc.encode(text)));
}

export async function hashRecord(r: Pick<AuditRecord, "idx" | "ts" | "actor" | "action" | "details" | "prev_hash">): Promise<string> {
  return sha256Hex(canonicalJson({ idx: r.idx, ts: r.ts, actor: r.actor, action: r.action, details: r.details, prev_hash: r.prev_hash }));
}

export interface ChainVerdict {
  ok: boolean;
  /** Index of the first record that fails, if any. */
  brokenAt: number | null;
  reason: string | null;
  /** True for every record from the first failure onward (the chain cannot vouch for them). */
  suspect: boolean[];
}

export async function verifyChain(records: AuditRecord[]): Promise<ChainVerdict> {
  let expectedPrev = GENESIS;
  for (let i = 0; i < records.length; i++) {
    const r = records[i];
    let reason: string | null = null;
    if (r.idx !== i) reason = "index mismatch (a record was removed, inserted or reordered)";
    else if (r.prev_hash !== expectedPrev) reason = "prev_hash does not match the previous record";
    else if ((await hashRecord(r)) !== r.hash) reason = "hash mismatch (record content was modified)";
    if (reason) return { ok: false, brokenAt: i, reason, suspect: records.map((_, j) => j >= i) };
    expectedPrev = r.hash;
  }
  return { ok: true, brokenAt: null, reason: null, suspect: records.map(() => false) };
}

export interface CheckpointVerdict {
  ok: boolean;
  brokenAt: number | null;
  reason: string | null;
  anchoredThrough: number | null;
  unanchored: number;
  /** Set when this browser cannot verify Ed25519 signatures at all. */
  unsupported?: boolean;
}

function b64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

export async function importPublicKey(pem: string): Promise<CryptoKey> {
  const body = pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
  return crypto.subtle.importKey("spki", b64ToBytes(body), { name: "Ed25519" }, false, ["verify"]);
}

export async function verifySignature(key: CryptoKey, cp: Checkpoint): Promise<boolean> {
  try {
    const message = enc.encode(canonicalJson({ idx: cp.idx, hash: cp.hash, ts: cp.ts }));
    return await crypto.subtle.verify({ name: "Ed25519" }, key, b64ToBytes(cp.sig), message);
  } catch {
    return false;
  }
}

/** Mirrors verify_with_checkpoints(): the chain must already be internally valid, then every checkpoint must hold. */
export async function verifyAgainstCheckpoints(records: AuditRecord[], checkpoints: Checkpoint[], publicKeyPem: string): Promise<CheckpointVerdict> {
  const base = await verifyChain(records);
  if (!base.ok) return { ok: false, brokenAt: base.brokenAt, reason: base.reason, anchoredThrough: null, unanchored: records.length };
  if (checkpoints.length === 0) return { ok: true, brokenAt: null, reason: null, anchoredThrough: null, unanchored: records.length };

  let key: CryptoKey;
  try {
    key = await importPublicKey(publicKeyPem);
  } catch {
    return { ok: false, brokenAt: null, reason: "this browser cannot verify Ed25519 signatures", anchoredThrough: null, unanchored: records.length, unsupported: true };
  }

  let anchored: number | null = null;
  for (const cp of [...checkpoints].sort((a, b) => a.idx - b.idx)) {
    if (!(await verifySignature(key, cp))) {
      return { ok: false, brokenAt: cp.idx, reason: "checkpoint signature invalid (forged or corrupted checkpoint)", anchoredThrough: anchored, unanchored: records.length };
    }
    if (cp.idx >= records.length) {
      return { ok: false, brokenAt: records.length, reason: "chain is shorter than a signed checkpoint (truncation or deletion)", anchoredThrough: anchored, unanchored: records.length };
    }
    if (records[cp.idx].hash !== cp.hash) {
      return { ok: false, brokenAt: cp.idx, reason: "chain diverges from signed checkpoint (history was rewritten)", anchoredThrough: anchored, unanchored: records.length };
    }
    anchored = cp.idx;
  }
  return { ok: true, brokenAt: null, reason: null, anchoredThrough: anchored, unanchored: anchored === null ? records.length : records.length - 1 - anchored };
}

// ---- tamper operations (always on a copy; nothing here can reach the real chain) ----

export function editRecord(records: AuditRecord[], idx: number): AuditRecord[] {
  return records.map((r, i) => (i === idx ? { ...r, actor: r.actor === "blue" ? "red" : "blue" } : r));
}

/** What a privileged attacker does: edit one record, then recompute every hash after it so the chain stays consistent. */
export async function rewriteFrom(records: AuditRecord[], idx: number): Promise<AuditRecord[]> {
  const out = records.map((r) => ({ ...r, details: { ...r.details } }));
  out[idx].details = { ...out[idx].details, note: "history rewritten by an attacker" };
  for (let i = idx; i < out.length; i++) {
    out[i].prev_hash = i === 0 ? out[0].prev_hash : out[i - 1].hash;
    out[i].hash = await hashRecord(out[i]);
  }
  return out;
}

export function truncate(records: AuditRecord[], remove: number): AuditRecord[] {
  return records.slice(0, Math.max(0, records.length - remove));
}

/** Append validly hashed forged records: allowed by the chain, stopped only by access control. */
export async function appendForged(records: AuditRecord[], count: number): Promise<AuditRecord[]> {
  const out = records.map((r) => ({ ...r }));
  for (let n = 0; n < count; n++) {
    const prev = out[out.length - 1];
    const rec = { idx: out.length, ts: prev.ts, actor: "red", action: "probe.forged_event", details: { note: `forged event ${n + 1}` }, prev_hash: prev.hash };
    out.push({ ...rec, hash: await hashRecord(rec) });
  }
  return out;
}
