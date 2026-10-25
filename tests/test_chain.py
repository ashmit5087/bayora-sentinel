import json

import pytest

from sentinel.audit.chain import (
    GENESIS_HASH,
    AuditChain,
    ChainCorruptError,
    compute_hash,
    verify_file,
    verify_records,
)


def make_chain(tmp_path, n=5):
    chain = AuditChain(tmp_path / "chain.jsonl")
    for i in range(n):
        chain.append("red", "gateway.request", {"i": i})
    return chain


def read_lines(path):
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def write_lines(path, records):
    path.write_text("".join(json.dumps(r) + "\n" for r in records))


def test_empty_chain_verifies(tmp_path):
    chain = AuditChain(tmp_path / "c.jsonl")
    result = verify_file(chain.path)
    assert result.ok and result.count == 0 and result.head_hash == GENESIS_HASH


def test_records_are_linked_and_verify(tmp_path):
    chain = make_chain(tmp_path)
    recs = read_lines(chain.path)
    assert recs[0]["prev_hash"] == GENESIS_HASH
    for prev, cur in zip(recs, recs[1:]):
        assert cur["prev_hash"] == prev["hash"]
    result = verify_file(chain.path)
    assert result.ok and result.count == 5 and result.head_hash == recs[-1]["hash"]


def test_modified_record_is_detected_at_the_right_index(tmp_path):
    chain = make_chain(tmp_path)
    recs = read_lines(chain.path)
    recs[2]["details"]["i"] = 999
    write_lines(chain.path, recs)
    result = verify_file(chain.path)
    assert not result.ok and result.broken_at == 2 and "modified" in result.reason


def test_deleted_record_is_detected(tmp_path):
    chain = make_chain(tmp_path)
    recs = read_lines(chain.path)
    del recs[2]
    write_lines(chain.path, recs)
    result = verify_file(chain.path)
    assert not result.ok and result.broken_at == 2


def test_reordered_records_are_detected(tmp_path):
    chain = make_chain(tmp_path)
    recs = read_lines(chain.path)
    recs[1], recs[3] = recs[3], recs[1]
    write_lines(chain.path, recs)
    assert not verify_file(chain.path).ok


def test_garbage_line_is_detected(tmp_path):
    chain = make_chain(tmp_path)
    with chain.path.open("a") as fh:
        fh.write("not json\n")
    result = verify_file(chain.path)
    assert not result.ok and result.broken_at == 5


def test_tail_truncation_is_NOT_detected_by_the_chain_alone(tmp_path):
    """Known limitation. Signed checkpoints (test_checkpoint.py) close this gap."""
    chain = make_chain(tmp_path)
    recs = read_lines(chain.path)
    write_lines(chain.path, recs[:3])
    assert verify_file(chain.path).ok


def test_chain_continues_after_restart(tmp_path):
    chain = make_chain(tmp_path, n=3)
    reopened = AuditChain(chain.path)
    rec = reopened.append("blue", "gateway.request", {"after": "restart"})
    assert rec["idx"] == 3
    assert verify_file(chain.path).ok


def test_refuses_to_open_a_corrupt_file(tmp_path):
    path = tmp_path / "c.jsonl"
    path.write_text("{broken\n")
    with pytest.raises(ChainCorruptError):
        AuditChain(path)


def test_non_json_details_are_rejected_and_nothing_is_written(tmp_path):
    chain = make_chain(tmp_path, n=1)
    before = chain.path.read_text()
    with pytest.raises(TypeError):
        chain.append("red", "x", {"bad": object()})
    assert chain.path.read_text() == before
    assert chain.append("red", "x", {})["idx"] == 1  # chain still usable


def test_hash_covers_every_field(tmp_path):
    rec = make_chain(tmp_path, n=1).records()[0]
    for field in ("idx", "ts", "actor", "action", "details", "prev_hash"):
        mutated = dict(rec)
        mutated[field] = "changed" if field != "details" else {"x": 1}
        if field == "idx":
            mutated[field] = 42
        assert compute_hash(mutated) != rec["hash"], field


def test_verify_records_reports_missing_fields():
    result = verify_records([{"idx": 0}])
    assert not result.ok and result.broken_at == 0
