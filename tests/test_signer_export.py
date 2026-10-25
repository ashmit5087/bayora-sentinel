import json
import subprocess
import sys
from pathlib import Path

from conftest import serve

from sentinel.audit.chain import AuditChain
from sentinel.audit.checkpoint import generate_keypair, load_checkpoints, load_private_key
from sentinel.audit.export import build_export
from sentinel.audit.ingest import ingest
from sentinel.audit.service import create_app
from sentinel.signer.service import last_signed_idx, sign_head_once

ROOT = Path(__file__).resolve().parent.parent
WRITE, READ = "write-token-0123456789", "read-token-0123456789"


def probes(n=6):
    return [{"id": f"P{i:02d}", "status": "pass", "observed": f"observation {i}"} for i in range(1, n + 1)]


def setup(tmp_path):
    chain = AuditChain(tmp_path / "chain.jsonl")
    private_pem, public_pem = generate_keypair()
    (tmp_path / "pub.pem").write_bytes(public_pem)
    app = create_app(chain, WRITE, READ, tmp_path / "checkpoints.jsonl", public_pem)
    return chain, load_private_key(private_pem), app


def test_signer_signs_the_head_once_and_skips_when_nothing_is_new(tmp_path):
    chain, key, app = setup(tmp_path)
    cp_path = tmp_path / "checkpoints.jsonl"
    with serve(app) as url:
        assert sign_head_once(url, READ, key, cp_path) is None  # empty chain: nothing to sign
        ingest("hardened", probes(), url, WRITE, READ)
        cp = sign_head_once(url, READ, key, cp_path)
        assert cp and cp["idx"] == 5 and cp["hash"] == chain.records()[5]["hash"]
        assert sign_head_once(url, READ, key, cp_path) is None  # same head: no duplicate
        ingest("hardened", probes(2), url, WRITE, READ)
        assert sign_head_once(url, READ, key, cp_path)["idx"] == 7
    assert [c["idx"] for c in load_checkpoints(cp_path)] == [5, 7]
    assert last_signed_idx(cp_path) == 7


def test_audit_service_verifies_against_signer_checkpoints(tmp_path):
    chain, key, app = setup(tmp_path)
    cp_path = tmp_path / "checkpoints.jsonl"
    with serve(app) as url:
        ingest("hardened", probes(), url, WRITE, READ)
        sign_head_once(url, READ, key, cp_path)
        ingest("hardened", probes(2), url, WRITE, READ)  # two unanchored events
        result = ingest("hardened", [], url, WRITE, READ)["verify"]
    assert result["ok"] and result["anchored_through"] == 5 and result["unanchored_events"] == 2


def test_export_contains_chain_checkpoints_key_and_verdict(tmp_path):
    chain, key, app = setup(tmp_path)
    cp_path = tmp_path / "checkpoints.jsonl"
    with serve(app) as url:
        ingest("hardened", probes(), url, WRITE, READ)
        sign_head_once(url, READ, key, cp_path)
    export = build_export(str(chain.path), str(cp_path), str(tmp_path / "pub.pem"))
    assert len(export["records"]) == 6 and len(export["checkpoints"]) == 1
    assert export["public_key_pem"].startswith("-----BEGIN PUBLIC KEY-----")
    assert export["verify"]["ok"] and export["verify"]["checkpoints_checked"] == 1
    json.dumps(export)  # serializable


def test_export_without_checkpoints_still_reports_chain_validity(tmp_path):
    chain = AuditChain(tmp_path / "chain.jsonl")
    chain.append("red", "x", {})
    export = build_export(str(chain.path), None, None)
    assert export["verify"]["ok"] and export["verify"]["checkpoints_checked"] == 0 and export["checkpoints"] == []


def test_tamper_demo_script_runs_on_an_export_and_tells_the_truth(tmp_path):
    chain, key, app = setup(tmp_path)
    cp_path = tmp_path / "checkpoints.jsonl"
    with serve(app) as url:
        ingest("hardened", probes(10), url, WRITE, READ)
        sign_head_once(url, READ, key, cp_path)   # anchors through record 9
        ingest("hardened", probes(3), url, WRITE, READ)  # 3 unanchored records
    export_path = tmp_path / "export.json"
    export_path.write_text(json.dumps(build_export(str(chain.path), str(cp_path), str(tmp_path / "pub.pem"))))
    proc = subprocess.run([sys.executable, str(ROOT / "scripts" / "tamper_demo.py"), str(export_path)],
                          capture_output=True, text=True, timeout=60)
    out = proc.stdout
    assert proc.returncode == 0, proc.stderr
    plain = out.replace("\033[32m", "").replace("\033[31m", "").replace("\033[33m", "").replace("\033[0m", "")
    assert "0. untouched" in plain and "VALID" in plain
    # scenario 2: the chain alone is fooled, the signed checkpoint is not
    s2 = plain.split("2. Rewrite history")[1].split("3. Truncate")[0]
    assert "hash chain alone" in s2 and "VALID" in s2.split("with signed checkpoints")[0]
    assert "REJECTED" in s2.split("with signed checkpoints")[1]
    # scenario 4: the stated limit is demonstrated, not hidden
    assert "Known limit" in plain
    s4 = plain.split("4. Rewrite only records")[1].split("Known limit")[0]
    assert "VALID" in s4 and "REJECTED" not in s4


def test_convert_timing_produces_a_contract_valid_run():
    sys.path.insert(0, str(ROOT / "scripts"))
    import convert_timing

    mode = lambda hit, miss, auc, p: {  # noqa: E731
        "hit_ms": hit, "miss_ms": miss, "median_probe_latency_ms": 100.0,
        "stats": {"auc_hit_faster": auc, "best_threshold_accuracy": 0.9, "cohens_d": 5.0, "perm_p": p},
    }
    timing = {"meta": {"generated_at": "2026-10-23T05:00:00+00:00", "trials_per_mode": 4, "approx_prompt_tokens": 779},
              "modes": {"shared": mode([60.0, 65.0], [3700.0, 3800.0], 1.0, 0.0002), "isolated": mode([3700.0, 3800.0], [3750.0, 3790.0], 0.5, 0.9)}}
    run = convert_timing.convert(timing, "test-model")
    assert run["source"] == "live" and [m["mode"] for m in run["modes"]] == ["shared", "isolated"]
    assert run["modes"][0]["perm_p"] == 0.0002 and any("not a proof" in c for c in run["caveats"])


def test_signer_error_messages_tell_network_and_file_problems_apart():
    import urllib.error
    from sentinel.signer.service import describe_failure

    network = describe_failure(urllib.error.URLError("refused"), "/checkpoints/c.jsonl")
    assert "not reachable" in network
    assert "not reachable" in describe_failure(ConnectionResetError(), "/c")
    perm = describe_failure(PermissionError(13, "Permission denied"), "/checkpoints/c.jsonl")
    assert "not reachable" not in perm and "permission denied" in perm and "10001" in perm
    other = describe_failure(OSError(28, "No space left on device"), "/checkpoints/c.jsonl")
    assert "not reachable" not in other and "No space left" in other


def test_signer_surfaces_a_checkpoint_write_failure(tmp_path, monkeypatch):
    import pytest
    from sentinel.signer import service

    chain, key, app = setup(tmp_path)

    def deny(*a, **k):
        raise PermissionError(13, "Permission denied")

    with serve(app) as url:
        ingest("hardened", probes(2), url, WRITE, READ)
        monkeypatch.setattr(service, "append_checkpoint", deny)
        with pytest.raises(PermissionError):
            service.sign_head_once(url, READ, key, tmp_path / "checkpoints.jsonl")
