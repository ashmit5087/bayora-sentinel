"""Tests for the gauntlet probes themselves.

These check that each probe classifies a situation correctly, using real local servers and temp
directories. They do NOT prove the compose files isolate anything: that is what running the
gauntlet inside Docker is for.
"""
import json

import pytest
from conftest import serve

from sentinel.audit.chain import AuditChain
from sentinel.audit.service import create_app as create_audit_app
from sentinel.contracts import ProbeResult
from sentinel.gateway.app import create_app as create_gateway_app
from sentinel.gateway.audit_sink import LocalAuditSink
from sentinel.gateway.backends import MockBackend
from sentinel.gateway.settings import Settings
from sentinel.gauntlet import probes as P
from sentinel.gauntlet.report import build_run, summarize

TOKENS = {"red": "red-token-0123456789", "blue": "blue-token-0123456789", "auditor": "auditor-token-0123456789"}


def test_registry_is_complete_and_unique():
    ids = [p.id for p in P.PROBES]
    assert ids == [f"P{i:02d}" for i in range(1, 17)]
    assert all(p.hypothesis and p.command and p.expected for p in P.PROBES)


def test_p01_fails_when_blue_data_is_readable_and_never_leaks_contents(tmp_path, monkeypatch):
    (tmp_path / "defenses.yaml").write_text("marker: BLUE-SECRET-MARKER")
    monkeypatch.setenv("GAUNTLET_BLUE_DIR", str(tmp_path))
    out = P.p01_read_blue_data()
    assert out.status == "fail" and "defenses.yaml" in out.observed
    assert "BLUE-SECRET-MARKER" not in out.observed + out.evidence


def test_p01_passes_when_path_is_absent(tmp_path, monkeypatch):
    monkeypatch.setenv("GAUNTLET_BLUE_DIR", str(tmp_path / "nope"))
    assert P.p01_read_blue_data().status == "pass"


def test_p06_detects_writable_and_unwritable(tmp_path, monkeypatch):
    monkeypatch.setenv("GAUNTLET_WRITE_PATHS", str(tmp_path / "w.txt"))
    assert P.p06_write_rootfs().status == "fail"
    assert not (tmp_path / "w.txt").exists(), "scratch file must be cleaned up"
    monkeypatch.setenv("GAUNTLET_WRITE_PATHS", "/proc/definitely/not/writable")
    assert P.p06_write_rootfs().status == "pass"


def test_p12_audit_volume(tmp_path, monkeypatch):
    monkeypatch.setenv("GAUNTLET_AUDIT_DIR", str(tmp_path / "absent"))
    assert P.p12_audit_volume().status == "pass"
    (tmp_path / "chain.jsonl").write_text('{"x":1}\n')
    monkeypatch.setenv("GAUNTLET_AUDIT_DIR", str(tmp_path))
    out = P.p12_audit_volume()
    assert out.status == "fail" and not (tmp_path / ".probe_write_test").exists()


def test_parse_cap_eff():
    assert P.parse_cap_eff("Name: x\nCapEff:\t000001fffeffffff\n") == 0x1FFFEFFFFFF
    assert P.parse_cap_eff("CapEff:\t0000000000000000\n") == 0
    assert P.parse_cap_eff("nothing here") is None


def test_unreachable_targets_pass(monkeypatch):
    monkeypatch.setenv("GAUNTLET_MODEL_URL", "http://127.0.0.1:1/health")
    assert P.p02_reach_model_directly().status == "pass"
    monkeypatch.setenv("GAUNTLET_BLUE_HOST", "no-such-host.invalid")
    assert P.p03_reach_blue_worker().status == "pass"


def test_reachable_model_fails(monkeypatch):
    from sentinel.stubs.http_stub import make_handler
    from http.server import ThreadingHTTPServer
    import threading

    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler("model"))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    monkeypatch.setenv("GAUNTLET_MODEL_URL", f"http://127.0.0.1:{server.server_port}/health")
    try:
        out = P.p02_reach_model_directly()
    finally:
        server.shutdown()
    assert out.status == "fail" and "bypassed" in out.observed


def gateway_app(tmp_path, **overrides):
    chain = AuditChain(tmp_path / "gw-chain.jsonl")
    return create_gateway_app(Settings(**overrides), MockBackend(), LocalAuditSink(chain))


def test_p10_catches_a_spoofable_gateway_and_passes_a_correct_one(tmp_path, monkeypatch):
    monkeypatch.setenv("MY_GATEWAY_TOKEN", "shared-key-0123456789")
    insecure = gateway_app(tmp_path, auth_mode="shared_static", shared_api_key="shared-key-0123456789")
    with serve(insecure) as url:
        monkeypatch.setenv("GAUNTLET_GATEWAY_URL", url)
        out = P.p10_identity_claim()
    assert out.status == "fail" and "tenant=blue" in out.observed

    monkeypatch.setenv("MY_GATEWAY_TOKEN", TOKENS["red"])
    hardened = gateway_app(tmp_path, tenant_tokens=TOKENS)
    with serve(hardened) as url:
        monkeypatch.setenv("GAUNTLET_GATEWAY_URL", url)
        out = P.p10_identity_claim()
    assert out.status == "pass" and "tenant=red" in out.observed


def test_p10_is_untested_without_a_credential_or_gateway(monkeypatch):
    monkeypatch.delenv("MY_GATEWAY_TOKEN", raising=False)
    monkeypatch.delenv("MY_GATEWAY_TOKEN_FILE", raising=False)
    assert P.p10_identity_claim().status == "untested"
    monkeypatch.setenv("MY_GATEWAY_TOKEN", "x" * 20)
    monkeypatch.setenv("GAUNTLET_GATEWAY_URL", "http://127.0.0.1:1")
    assert P.p10_identity_claim().status == "untested"


def test_p13_p14_audit_probes(tmp_path, monkeypatch):
    chain = AuditChain(tmp_path / "audit-chain.jsonl")
    app = create_audit_app(chain, "write-token-0123456789", "read-token-0123456789")
    with serve(app) as url:
        monkeypatch.setenv("GAUNTLET_AUDIT_URL", url)
        # Attacker holds the real tokens (the insecure configuration): both breaches succeed.
        monkeypatch.setenv("AUDIT_WRITE_TOKEN", "write-token-0123456789")
        monkeypatch.setenv("AUDIT_READ_TOKEN", "read-token-0123456789")
        assert P.p13_forge_audit_event().status == "fail"
        assert P.p14_read_audit_records().status == "fail"
        assert any(r["action"] == "probe.forged_event" for r in chain.records())
        # Attacker has no valid tokens but can reach the service: it must reject.
        monkeypatch.delenv("AUDIT_WRITE_TOKEN")
        monkeypatch.delenv("AUDIT_READ_TOKEN")
        assert P.p13_forge_audit_event().status == "pass"
        assert P.p14_read_audit_records().status == "pass"
    # Service unreachable (the hardened network case).
    monkeypatch.setenv("GAUNTLET_AUDIT_URL", "http://127.0.0.1:1")
    assert P.p13_forge_audit_event().status == "pass"
    assert P.p14_read_audit_records().status == "pass"


def test_p11_reports_names_never_values(monkeypatch):
    monkeypatch.setenv("AUDIT_WRITE_TOKEN", "super-secret-value-123")
    out = P.p11_foreign_secrets()
    assert out.status == "fail" and "env:AUDIT_WRITE_TOKEN" in out.observed
    assert "super-secret-value-123" not in out.observed + out.evidence


def test_p11_ignores_known_public_base_image_variables(monkeypatch):
    for name in [k for k in __import__("os").environ if any(s in k.upper() for s in ("TOKEN", "SECRET", "KEY", "PASSWORD"))]:
        monkeypatch.delenv(name)
    monkeypatch.setenv("GPG_KEY", "A035C8C19219BA821ECEA86B64E628F8D684696D")  # public key id from the python image
    assert P.p11_foreign_secrets().status == "pass"
    monkeypatch.setenv("AUDIT_READ_TOKEN", "x" * 20)
    assert P.p11_foreign_secrets().status == "fail"


def test_p16_is_out_of_scope():
    assert P.p16_kernel_escape().status == "out_of_scope"


def test_a_crashing_probe_is_reported_as_untested():
    def boom():
        raise RuntimeError("kaboom")

    rec = P.run_probe(P.Probe("P99", "t", "network", "h", "c", "e", boom))
    assert rec["status"] == "untested" and "kaboom" in rec["observed"]


def test_full_run_produces_contract_valid_results(monkeypatch):
    # Point the network probes at closed local ports and shrink the resource probes so this is quick.
    monkeypatch.setenv("GAUNTLET_MODEL_URL", "http://127.0.0.1:1/")
    monkeypatch.setenv("GAUNTLET_BLUE_HOST", "no-such-host.invalid")
    monkeypatch.setenv("GAUNTLET_EGRESS_HOST", "127.0.0.1")
    monkeypatch.setenv("GAUNTLET_EGRESS_PORT", "1")
    monkeypatch.setenv("GAUNTLET_METADATA_URL", "http://127.0.0.1:1/")
    monkeypatch.setenv("GAUNTLET_GATEWAY_URL", "http://127.0.0.1:1")
    monkeypatch.setenv("GAUNTLET_AUDIT_URL", "http://127.0.0.1:1")
    monkeypatch.setenv("GAUNTLET_MEM_MB", "100")
    monkeypatch.setenv("GAUNTLET_PIDS", "40")
    records = P.run_all()
    assert len(records) == 16
    for rec in records:
        ProbeResult.model_validate({**rec, "audit_hash": None})
    run = build_run("insecure", records, {"P01": "ab" * 32})
    assert run["source"] == "live" and summarize(run)["out_of_scope"] == 1
    assert json.dumps(run)  # serializable
