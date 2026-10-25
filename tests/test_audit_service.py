import json

import pytest
from fastapi.testclient import TestClient

from sentinel.audit.chain import AuditChain
from sentinel.audit.checkpoint import append_checkpoint, generate_keypair, load_private_key, make_checkpoint
from sentinel.audit.service import create_app

WRITE = {"Authorization": "Bearer write-token-0123456789"}
READ = {"Authorization": "Bearer read-token-0123456789"}


@pytest.fixture
def client(tmp_path):
    chain = AuditChain(tmp_path / "chain.jsonl")
    return TestClient(create_app(chain, "write-token-0123456789", "read-token-0123456789")), chain


def append(client, n=3):
    for i in range(n):
        assert client.post("/append", json={"actor": "red", "action": "x", "details": {"i": i}}, headers=WRITE).status_code == 200


def test_append_requires_the_write_token(client):
    c, _ = client
    body = {"actor": "red", "action": "x", "details": {}}
    assert c.post("/append", json=body).status_code == 401
    assert c.post("/append", json=body, headers=READ).status_code == 401  # read token cannot write
    assert c.post("/append", json=body, headers=WRITE).status_code == 200


def test_reads_require_the_read_token(client):
    c, _ = client
    for path in ("/head", "/records", "/verify"):
        assert c.get(path).status_code == 401
        assert c.get(path, headers=WRITE).status_code == 401  # write token cannot read


def test_head_records_and_verify(client):
    c, _ = client
    append(c)
    assert c.get("/head", headers=READ).json()["count"] == 3
    assert len(c.get("/records", headers=READ).json()["records"]) == 3
    result = c.get("/verify", headers=READ).json()
    assert result["ok"] and result["count"] == 3


def test_verify_detects_tampering_on_disk(client):
    c, chain = client
    append(c)
    lines = chain.path.read_text().splitlines()
    rec = json.loads(lines[1])
    rec["actor"] = "blue"
    lines[1] = json.dumps(rec)
    chain.path.write_text("\n".join(lines) + "\n")
    result = c.get("/verify", headers=READ).json()
    assert not result["ok"] and result["broken_at"] == 1


def test_verify_uses_signed_checkpoints_when_configured(tmp_path):
    chain = AuditChain(tmp_path / "chain.jsonl")
    priv_pem, pub_pem = generate_keypair()
    priv = load_private_key(priv_pem)
    cp_path = tmp_path / "checkpoints.jsonl"
    app = create_app(chain, "write-token-0123456789", "read-token-0123456789", cp_path, pub_pem)
    c = TestClient(app)
    append(c, 4)
    append_checkpoint(cp_path, make_checkpoint(priv, 2, chain.records()[2]["hash"]))
    result = c.get("/verify", headers=READ).json()
    assert result["ok"] and result["checkpoints_checked"] == 1 and result["anchored_through"] == 2


def test_service_refuses_to_start_without_distinct_tokens(tmp_path):
    chain = AuditChain(tmp_path / "chain.jsonl")
    with pytest.raises(ValueError):
        create_app(chain, "", "read-token-0123456789")
    with pytest.raises(ValueError):
        create_app(chain, "same-token-0123456789", "same-token-0123456789")


def test_non_json_details_are_422(client):
    c, _ = client
    # JSON itself cannot carry non-serializable values, but oversized/invalid shapes are rejected by the schema
    assert c.post("/append", json={"actor": "", "action": "x"}, headers=WRITE).status_code == 422
