"""Frozen data contracts between the backend and the dashboard.

The dashboard reads these shapes and nothing else, so the UI can be built
against fixtures while the real runners are still being written.

Status semantics (the same everywhere):
  pass          the control held: the attempted breach FAILED
  fail          the control was absent or broken: the attempted breach SUCCEEDED
  untested      not run in this session (shown in gray, never hidden)
  out_of_scope  deliberately not attempted; the reason is stated in `observed`
"""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

Status = Literal["pass", "fail", "untested", "out_of_scope"]
Config = Literal["insecure", "hardened"]
Source = Literal["live", "replay", "fixture"]
Category = Literal[
    "data_isolation", "network", "privilege", "filesystem", "resource", "identity", "audit", "secrets", "side_channel"
]


class ProbeResult(BaseModel):
    id: str = Field(pattern=r"^P\d{2}$")
    title: str
    category: Category
    hypothesis: str
    command: str
    expected: str
    observed: str
    status: Status
    started_at: str
    duration_ms: float = Field(ge=0)
    audit_hash: str | None = None      # links the probe to the audit chain
    evidence: str = ""                  # raw output, truncated by the runner


class GauntletRun(BaseModel):
    schema_version: Literal[1] = 1
    run_id: str
    source: Source
    config: Config
    started_at: str
    probes: list[ProbeResult]
    notes: list[str] = Field(default_factory=list)


class SideChannelMode(BaseModel):
    mode: Literal["shared", "isolated", "off"]
    hit_ms: list[float]
    miss_ms: list[float]
    auc_hit_faster: float = Field(ge=0, le=1)
    best_threshold_accuracy: float = Field(ge=0, le=1)
    cohens_d: float
    perm_p: float | None = Field(default=None, ge=0, le=1)   # permutation-test p-value on the AUC
    median_probe_latency_ms: float


class SideChannelRun(BaseModel):
    schema_version: Literal[1] = 1
    run_id: str
    source: Source
    model: str
    trials_per_mode: int = Field(gt=0)
    approx_prompt_tokens: int | None = None
    modes: list[SideChannelMode]
    caveats: list[str] = Field(default_factory=list)


class AuditStatus(BaseModel):
    schema_version: Literal[1] = 1
    source: Source
    ok: bool
    count: int = Field(ge=0)
    head_hash: str
    broken_at: int | None = None
    reason: str | None = None
    anchored_through: int | None = None
    unanchored_events: int | None = None
    checkpoints_checked: int = 0


if __name__ == "__main__":  # python -m sentinel.contracts  -> JSON Schemas for the frontend types
    import json

    print(json.dumps({m.__name__: m.model_json_schema() for m in (GauntletRun, SideChannelRun, AuditStatus)}, indent=2))
