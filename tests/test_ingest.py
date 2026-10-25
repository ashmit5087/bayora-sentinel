import hashlib

from conftest import serve

from sentinel.audit.chain import AuditChain, verify_file
from sentinel.audit.ingest import ingest
from sentinel.audit.service import create_app

WRITE, READ = "write-token-0123456789", "read-token-0123456789"


def sample_probes():
    return [
        {"id": "P01", "status": "fail", "observed": "Read blue-team files"},
        {"id": "P02", "status": "pass", "observed": "Model not reachable"},
        {"id": "P16", "status": "out_of_scope", "observed": "Not attempted"},
    ]


def test_ingest_appends_one_record_per_probe_and_chain_verifies(tmp_path):
    chain = AuditChain(tmp_path / "chain.jsonl")
    with serve(create_app(chain, WRITE, READ)) as url:
        result = ingest("insecure", sample_probes(), url, WRITE, READ)
    assert set(result["hashes"]) == {"P01", "P02", "P16"}
    assert result["verify"]["ok"] and result["verify"]["count"] == 3
    recs = chain.records()
    assert [r["details"]["probe_id"] for r in recs] == ["P01", "P02", "P16"]
    assert recs[0]["hash"] == result["hashes"]["P01"]
    assert verify_file(chain.path).ok


def test_ingest_stores_a_hash_of_the_observation_not_free_text(tmp_path):
    chain = AuditChain(tmp_path / "chain.jsonl")
    with serve(create_app(chain, WRITE, READ)) as url:
        ingest("hardened", sample_probes(), url, WRITE, READ)
    details = chain.records()[0]["details"]
    assert details["observed_sha256"] == hashlib.sha256(b"Read blue-team files").hexdigest()
    assert "observed" not in details and details["config"] == "hardened"
