import json

from sentinel.audit.chain import AuditChain, compute_hash, parse_file, verify_records
from sentinel.audit.checkpoint import (
    append_checkpoint,
    generate_keypair,
    load_checkpoints,
    load_private_key,
    load_public_key,
    make_checkpoint,
    verify_checkpoint_signature,
    verify_with_checkpoints,
)


def keys():
    priv_pem, pub_pem = generate_keypair()
    return load_private_key(priv_pem), load_public_key(pub_pem)


def build(tmp_path, n=10):
    chain = AuditChain(tmp_path / "chain.jsonl")
    for i in range(n):
        chain.append("red", "gateway.request", {"i": i})
    records, _ = parse_file(chain.path)
    return records


def checkpoint_at(priv, records, idx):
    return make_checkpoint(priv, idx, records[idx]["hash"])


def rewrite_from(records, start, new_details):
    """What a privileged attacker does: change a record, then recompute every hash after it."""
    out = [dict(r) for r in records]
    out[start]["details"] = new_details
    for i in range(start, len(out)):
        out[i]["prev_hash"] = out[i - 1]["hash"] if i else out[0]["prev_hash"]
        out[i]["hash"] = compute_hash(out[i])
    return out


def test_signature_roundtrip_and_tamper():
    priv, pub = keys()
    cp = make_checkpoint(priv, 4, "ab" * 32)
    assert verify_checkpoint_signature(pub, cp)
    assert not verify_checkpoint_signature(pub, {**cp, "hash": "cd" * 32})
    assert not verify_checkpoint_signature(pub, {**cp, "idx": 5})
    assert not verify_checkpoint_signature(pub, {"idx": 1})  # malformed
    _, other_pub = keys()
    assert not verify_checkpoint_signature(other_pub, cp)


def test_clean_chain_with_checkpoints_verifies(tmp_path):
    priv, pub = keys()
    records = build(tmp_path)
    result = verify_with_checkpoints(records, [checkpoint_at(priv, records, 4), checkpoint_at(priv, records, 7)], pub)
    assert result.ok and result.anchored_through == 7 and result.unanchored_events == 2


def test_full_chain_rewrite_passes_plain_verification_but_fails_against_checkpoint(tmp_path):
    """The demo: rewriting the whole chain consistently fools the hash chain, not the signed anchor."""
    priv, pub = keys()
    records = build(tmp_path)
    cps = [checkpoint_at(priv, records, 5)]

    rewritten = rewrite_from(records, 3, {"i": "forged"})
    assert verify_records(rewritten).ok                        # chain alone is fooled
    result = verify_with_checkpoints(rewritten, cps, pub)      # signed checkpoint is not
    assert not result.ok and result.broken_at == 5 and "rewritten" in result.reason


def test_rewrite_after_the_last_checkpoint_is_not_detected(tmp_path):
    """Known limitation, kept as a test so the README can state it with evidence."""
    priv, pub = keys()
    records = build(tmp_path)
    cps = [checkpoint_at(priv, records, 5)]
    rewritten = rewrite_from(records, 8, {"i": "forged"})
    result = verify_with_checkpoints(rewritten, cps, pub)
    assert result.ok and result.unanchored_events == 4


def test_truncation_is_detected(tmp_path):
    priv, pub = keys()
    records = build(tmp_path)
    cps = [checkpoint_at(priv, records, 7)]
    result = verify_with_checkpoints(records[:5], cps, pub)
    assert not result.ok and "shorter" in result.reason


def test_forged_checkpoint_is_rejected(tmp_path):
    priv, pub = keys()
    attacker_priv, _ = keys()
    records = build(tmp_path)
    forged = checkpoint_at(attacker_priv, records, 5)
    result = verify_with_checkpoints(records, [forged], pub)
    assert not result.ok and "signature" in result.reason


def test_checkpoint_file_roundtrip(tmp_path):
    priv, _ = keys()
    path = tmp_path / "cp" / "checkpoints.jsonl"
    cp = make_checkpoint(priv, 1, "ef" * 32)
    append_checkpoint(path, cp)
    assert load_checkpoints(path) == [cp]
    assert load_checkpoints(tmp_path / "missing.jsonl") == []
    path.write_text("{oops\n")
    try:
        load_checkpoints(path)
        raise AssertionError("expected a parse error")
    except json.JSONDecodeError:
        pass
