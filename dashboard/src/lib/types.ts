// Mirrors sentinel/contracts.py. The Python models are the source of truth.
export type Status = "pass" | "fail" | "untested" | "out_of_scope";
export type Config = "insecure" | "hardened";
export type Source = "live" | "replay" | "fixture";

export interface ProbeResult {
  id: string;
  title: string;
  category: string;
  hypothesis: string;
  command: string;
  expected: string;
  observed: string;
  status: Status;
  started_at: string;
  duration_ms: number;
  audit_hash: string | null;
  evidence: string;
}

export interface GauntletRun {
  run_id: string;
  source: Source;
  config: Config;
  started_at: string;
  probes: ProbeResult[];
  notes: string[];
}

export interface SideChannelMode {
  mode: "shared" | "isolated" | "off";
  hit_ms: number[];
  miss_ms: number[];
  auc_hit_faster: number;
  best_threshold_accuracy: number;
  cohens_d: number;
  perm_p: number | null;
  median_probe_latency_ms: number;
}

export interface SideChannelRun {
  run_id: string;
  source: Source;
  model: string;
  trials_per_mode: number;
  approx_prompt_tokens: number | null;
  modes: SideChannelMode[];
  caveats: string[];
}

export interface AuditRecord {
  idx: number;
  ts: string;
  actor: string;
  action: string;
  details: Record<string, unknown>;
  prev_hash: string;
  hash: string;
}

export interface Checkpoint {
  idx: number;
  hash: string;
  ts: string;
  sig: string;
}

export interface AuditExport {
  source?: Source;
  records: AuditRecord[];
  checkpoints: Checkpoint[];
  public_key_pem: string;
  verify: { ok: boolean; count: number; broken_at?: number | null; reason?: string | null; anchored_through?: number | null; unanchored_events?: number | null };
}
