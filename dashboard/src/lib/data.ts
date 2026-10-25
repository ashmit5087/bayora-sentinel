import type { AuditExport, Config, GauntletRun, SideChannelRun } from "./types";

export interface Dataset {
  gauntlet: Partial<Record<Config, GauntletRun>>;
  side: SideChannelRun | null;
  audit: AuditExport | null;
  missing: string[];
}

async function load<T>(name: string): Promise<T | null> {
  try {
    const res = await fetch(`${import.meta.env.BASE_URL}data/${name}`, { cache: "no-store" });
    if (!res.ok) return null;
    return (await res.json()) as T;
  } catch {
    return null;
  }
}

export async function loadAll(): Promise<Dataset> {
  const [insecure, hardened, side, audit] = await Promise.all([
    load<GauntletRun>("gauntlet.insecure.json"),
    load<GauntletRun>("gauntlet.hardened.json"),
    load<SideChannelRun>("sidechannel.json"),
    load<AuditExport>("audit_export.json"),
  ]);
  const missing: string[] = [];
  if (!insecure || !hardened) missing.push("the gauntlet results");
  if (!side) missing.push("the cache-timing results");
  if (!audit) missing.push("the audit chain");
  return { gauntlet: { ...(insecure ? { insecure } : {}), ...(hardened ? { hardened } : {}) }, side, audit, missing };
}
