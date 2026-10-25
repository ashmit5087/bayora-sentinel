// Cross-language check: the chain below was produced and signed by the PYTHON implementation
// (scripts/make_fixtures.py). The TypeScript verifier must agree with it byte for byte.
import { describe, expect, it } from "vitest";
import fixture from "../../public/data/audit_export.json";
import { appendForged, editRecord, rewriteFrom, truncate, verifyAgainstCheckpoints, verifyChain } from "./audit";
import type { AuditExport } from "./types";

const data = fixture as unknown as AuditExport;
const { records, checkpoints, public_key_pem: pem } = data;

describe("verification agrees with the Python implementation", () => {
  it("accepts the untouched chain and its Ed25519 checkpoints", async () => {
    expect((await verifyChain(records)).ok).toBe(true);
    const v = await verifyAgainstCheckpoints(records, checkpoints, pem);
    expect(v.ok).toBe(true);
    expect(v.anchoredThrough).toBe(checkpoints[checkpoints.length - 1].idx);
    expect(v.unanchored).toBe(data.verify.unanchored_events);
  });

  it("detects an edited record at the right index", async () => {
    const v = await verifyChain(editRecord(records, 7));
    expect(v.ok).toBe(false);
    expect(v.brokenAt).toBe(7);
    expect(v.suspect.slice(0, 7).every((s) => !s)).toBe(true);
    expect(v.suspect.slice(7).every((s) => s)).toBe(true);
  });

  it("a consistent rewrite fools the chain alone but not the signed checkpoint", async () => {
    const rewritten = await rewriteFrom(records, 3);
    expect((await verifyChain(rewritten)).ok).toBe(true);
    const v = await verifyAgainstCheckpoints(rewritten, checkpoints, pem);
    expect(v.ok).toBe(false);
    expect(v.reason).toContain("rewritten");
  });

  it("detects truncation below a checkpoint", async () => {
    const v = await verifyAgainstCheckpoints(truncate(records, 8), checkpoints, pem);
    expect(v.ok).toBe(false);
    expect(v.reason).toContain("shorter");
  });

  it("does not detect forged records appended after the newest checkpoint (the stated limit)", async () => {
    const forged = await appendForged(records, 2);
    const v = await verifyAgainstCheckpoints(forged, checkpoints, pem);
    expect(v.ok).toBe(true);
    expect(v.unanchored).toBe((data.verify.unanchored_events ?? 0) + 2);
  });

  it("rejects a forged checkpoint signature", async () => {
    const bad = checkpoints.map((c, i) => (i === 0 ? { ...c, sig: c.sig.replace(/.$/, c.sig.endsWith("A") ? "B" : "A") } : c));
    const v = await verifyAgainstCheckpoints(records, bad, pem);
    expect(v.ok).toBe(false);
    expect(v.reason).toContain("signature");
  });
});
