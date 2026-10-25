import pytest
from fastapi.testclient import TestClient

from sentinel.audit.chain import AuditChain, parse_file, verify_file
from sentinel.gateway.app import RateLimiter, create_app
from sentinel.gateway.audit_sink import AuditUnavailable, LocalAuditSink
from sentinel.gateway.backends import CompletionResult
from sentinel.gateway.settings import Settings

TOKENS = {"red": "red-token-0123456789", "blue": "blue-token-0123456789", "auditor": "auditor-token-0123456789"}


class RecordingBackend:
    def __init__(self):
        self.calls = []

    async def complete(self, prompt, max_tokens, *, slot, cache_prompt):
        self.calls.append({"prompt": prompt, "max_tokens": max_tokens, "slot": slot, "cache_prompt": cache_prompt})
        return CompletionResult(text="ok-response", server_timings={"cache_n": 1234, "prompt_ms": 1.0})


class FailingSink:
    async def append(self, actor, action, details):
        raise AuditUnavailable("down")


def bearer(tenant):
    return {"Authorization": f"Bearer {TOKENS[tenant]}"}


@pytest.fixture
def env(tmp_path):
    chain = AuditChain(tmp_path / "chain.jsonl")
    backend = RecordingBackend()

    def build(**overrides):
        settings = Settings(tenant_tokens=TOKENS, **overrides)
        return TestClient(create_app(settings, backend, LocalAuditSink(chain)))

    return build, backend, chain


def actions(chain):
    return [r["action"] for r in chain.records(limit=500)]


def test_health_is_open_and_reveals_nothing(env):
    build, _, _ = env
    resp = build().get("/health")
    assert resp.status_code == 200 and resp.json() == {"status": "ok"}


def test_no_token_is_401_and_audited(env):
    build, backend, chain = env
    resp = build().post("/v1/complete", json={"prompt": "hi"})
    assert resp.status_code == 401
    assert "auth.denied" in actions(chain) and backend.calls == []


def test_wrong_token_is_401(env):
    build, backend, _ = env
    resp = build().post("/v1/complete", json={"prompt": "hi"}, headers={"Authorization": "Bearer nope"})
    assert resp.status_code == 401 and backend.calls == []


def test_non_ascii_token_does_not_crash(env):
    build, _, _ = env
    # Sent as raw bytes: the client library will not encode a non-ASCII str header.
    resp = build().get("/v1/whoami", headers={"Authorization": "Bearer tøken".encode("latin-1")})
    assert resp.status_code == 401


def test_authentication_happens_before_validation(env):
    build, _, _ = env
    assert build().post("/v1/complete", json={"wrong": "shape"}).status_code == 401


def test_valid_request_flows_through_and_is_audited(env):
    build, backend, chain = env
    resp = build().post("/v1/complete", json={"prompt": "hello there", "session_id": "s1"}, headers=bearer("red"))
    assert resp.status_code == 200
    body = resp.json()
    assert body["tenant"] == "red" and body["text"] == "ok-response"
    assert len(backend.calls) == 1
    assert actions(chain) == ["gateway.request", "gateway.response"]
    assert verify_file(chain.path).ok


def test_server_timings_are_never_returned_to_tenants(env):
    build, _, _ = env
    resp = build().post("/v1/complete", json={"prompt": "hello"}, headers=bearer("red"))
    assert "timings" not in resp.text and "cache_n" not in resp.text and "1234" not in resp.text


def test_raw_prompt_is_never_written_to_the_audit_trail(env):
    build, _, chain = env
    secret_prompt = "CANARY-SUPERSECRET-123456 please keep this out of logs"
    build().post("/v1/complete", json={"prompt": secret_prompt}, headers=bearer("red"))
    on_disk = chain.path.read_text()
    assert "SUPERSECRET" not in on_disk and "prompt_sha256" in on_disk


def test_auditor_can_identify_itself_but_cannot_use_the_model(env):
    build, backend, chain = env
    client = build()
    assert client.get("/v1/whoami", headers=bearer("auditor")).json()["tenant"] == "auditor"
    resp = client.post("/v1/complete", json={"prompt": "hi"}, headers=bearer("auditor"))
    assert resp.status_code == 403 and backend.calls == []
    assert "authz.denied" in actions(chain)


def test_isolated_mode_pins_each_tenant_to_its_own_slot(env):
    build, backend, _ = env
    client = build(cache_mode="isolated")
    client.post("/v1/complete", json={"prompt": "a"}, headers=bearer("red"))
    client.post("/v1/complete", json={"prompt": "b"}, headers=bearer("blue"))
    assert [(c["slot"], c["cache_prompt"]) for c in backend.calls] == [(0, True), (1, True)]


def test_shared_mode_does_not_pin_slots(env):
    build, backend, _ = env
    build(cache_mode="shared").post("/v1/complete", json={"prompt": "a"}, headers=bearer("red"))
    assert backend.calls[0]["slot"] is None and backend.calls[0]["cache_prompt"] is True


def test_off_mode_disables_prompt_caching(env):
    build, backend, _ = env
    build(cache_mode="off").post("/v1/complete", json={"prompt": "a"}, headers=bearer("red"))
    assert backend.calls[0]["slot"] is None and backend.calls[0]["cache_prompt"] is False


def test_isolated_mode_without_a_slot_assignment_is_denied(env):
    build, backend, _ = env
    client = build(cache_mode="isolated", slot_map={"blue": 1})
    assert client.post("/v1/complete", json={"prompt": "a"}, headers=bearer("red")).status_code == 403
    assert backend.calls == []


def test_per_tenant_mode_ignores_a_forged_tenant_header(env):
    build, _, _ = env
    headers = {**bearer("red"), "X-Tenant": "auditor"}
    assert build(auth_mode="per_tenant").get("/v1/whoami", headers=headers).json()["tenant"] == "red"


def test_shared_static_mode_lets_the_caller_claim_any_identity(env):
    """The INSECURE configuration, kept as a test so the gauntlet probe has a verified counterpart."""
    build, _, _ = env
    client = build(auth_mode="shared_static", shared_api_key="one-shared-key-0123456789")
    headers = {"Authorization": "Bearer one-shared-key-0123456789", "X-Tenant": "blue"}
    assert client.get("/v1/whoami", headers=headers).json()["tenant"] == "blue"


def test_audit_fail_closed_blocks_the_request_before_the_model_is_called(env):
    build, backend, _ = env
    app = create_app(Settings(tenant_tokens=TOKENS, audit_fail_mode="closed"), backend, FailingSink())
    resp = TestClient(app).post("/v1/complete", json={"prompt": "hi"}, headers=bearer("red"))
    assert resp.status_code == 503 and backend.calls == []


def test_audit_fail_open_still_serves(env):
    build, backend, _ = env
    app = create_app(Settings(tenant_tokens=TOKENS, audit_fail_mode="open"), backend, FailingSink())
    resp = TestClient(app).post("/v1/complete", json={"prompt": "hi"}, headers=bearer("red"))
    assert resp.status_code == 200 and len(backend.calls) == 1


def test_rate_limit_returns_429_and_is_audited(env):
    build, backend, chain = env
    client = build(rate_limit_per_min=2)
    codes = [client.post("/v1/complete", json={"prompt": "x"}, headers=bearer("red")).status_code for _ in range(3)]
    assert codes == [200, 200, 429]
    assert "ratelimit.denied" in actions(chain)


def test_rate_limit_is_per_tenant(env):
    build, _, _ = env
    client = build(rate_limit_per_min=1)
    assert client.post("/v1/complete", json={"prompt": "x"}, headers=bearer("red")).status_code == 200
    assert client.post("/v1/complete", json={"prompt": "x"}, headers=bearer("blue")).status_code == 200


def test_rate_limiter_window_expires():
    now = [0.0]
    limiter = RateLimiter(1, clock=lambda: now[0])
    assert limiter.allow("t") and not limiter.allow("t")
    now[0] = 61.0
    assert limiter.allow("t")


def test_oversized_prompt_is_413(env):
    build, backend, _ = env
    resp = build(max_prompt_chars=10).post("/v1/complete", json={"prompt": "x" * 11}, headers=bearer("red"))
    assert resp.status_code == 413 and backend.calls == []


def test_invalid_body_is_422_and_does_not_echo_input(env):
    build, _, _ = env
    resp = build().post("/v1/complete", json={"prompt": "", "max_tokens": 0}, headers=bearer("red"))
    assert resp.status_code == 422 and "prompt" not in resp.text.lower().replace("invalid request", "")


def test_max_tokens_is_capped(env):
    build, backend, _ = env
    build(max_tokens_cap=32).post("/v1/complete", json={"prompt": "x", "max_tokens": 5000}, headers=bearer("red"))
    assert backend.calls[0]["max_tokens"] == 32


def test_backend_failure_is_502_and_audited(env):
    build, _, chain = env

    class Boom:
        async def complete(self, *a, **k):
            raise RuntimeError("model down")

    app = create_app(Settings(tenant_tokens=TOKENS), Boom(), LocalAuditSink(chain))
    resp = TestClient(app).post("/v1/complete", json={"prompt": "x"}, headers=bearer("red"))
    assert resp.status_code == 502 and "gateway.error" in actions(chain)


def test_settings_reject_weak_or_duplicate_tokens():
    with pytest.raises(ValueError):
        Settings(tenant_tokens={"red": "short"}).validate_secrets()
    with pytest.raises(ValueError):
        Settings(tenant_tokens={"red": "x" * 20, "blue": "x" * 20}).validate_secrets()
    with pytest.raises(ValueError):
        Settings(auth_mode="shared_static").validate_secrets()
    with pytest.raises(ValueError):
        Settings(cache_mode="bogus")
