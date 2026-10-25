import sys
import time

from fastapi.testclient import TestClient

from sentinel.control.server import ROOT, Cmd, create_app

H = {"X-Sentinel-Control": "1"}


def fake_actions():
    ok = Cmd([sys.executable, "-u", "-c", "print('hello'); print('phase two'); print('bye')"], ROOT,
             [("a", "First", None), ("b", "Second", "phase two")])
    bad = Cmd([sys.executable, "-c", "import sys; print('boom'); sys.exit(3)"], ROOT, [("x", "Explodes", None)])
    slow = Cmd([sys.executable, "-c", "import time; time.sleep(30)"], ROOT, [("s", "Slow", None)])
    return {"ok": lambda t: [ok], "bad": lambda t: [bad], "slow": lambda t: [slow]}


def wait_done(client, timeout=20):
    end = time.time() + timeout
    while time.time() < end:
        job = client.get("/api/status").json()["job"]
        if job and job["state"] != "running":
            return job
        time.sleep(0.1)
    raise AssertionError("job did not finish")


def test_runs_a_job_and_tracks_steps_from_output_markers():
    c = TestClient(create_app(actions=fake_actions()))
    assert c.post("/api/run", json={"action": "ok"}, headers=H).status_code == 200
    job = wait_done(c)
    assert job["state"] == "done" and [n["state"] for n in job["nodes"]] == ["done", "done"]
    assert "phase two" in job["log"]


def test_failed_step_is_marked_failed_and_reported():
    c = TestClient(create_app(actions=fake_actions()))
    c.post("/api/run", json={"action": "bad"}, headers=H)
    job = wait_done(c)
    assert job["state"] == "failed" and job["nodes"][0]["state"] == "failed" and "exit code 3" in job["log"]


def test_only_known_actions_and_one_job_at_a_time_and_cancel():
    c = TestClient(create_app(actions=fake_actions()))
    assert c.post("/api/run", json={"action": "rm -rf /"}, headers=H).status_code == 400
    assert c.post("/api/run", json={"action": "ok", "trials": 5}, headers=H).status_code == 400
    assert c.post("/api/run", json={"action": "slow"}, headers=H).status_code == 200
    assert c.post("/api/run", json={"action": "ok"}, headers=H).status_code == 409
    c.post("/api/cancel", headers=H)
    assert wait_done(c)["state"] == "cancelled"


def test_rejects_cross_site_posts_and_foreign_hosts():
    c = TestClient(create_app(actions=fake_actions()))
    assert c.post("/api/run", json={"action": "ok"}).status_code == 403  # no custom header
    assert c.post("/api/run", json={"action": "ok"}, headers={**H, "Origin": "https://evil.example"}).status_code == 403
    assert c.get("/api/status", headers={"Host": "evil.example"}).status_code == 403


def test_data_endpoint_serves_only_known_files_and_falls_back_to_fixtures(tmp_path):
    (tmp_path / "contracts" / "fixtures").mkdir(parents=True)
    (tmp_path / "contracts" / "fixtures" / "sidechannel.json").write_text('{"source":"fixture"}')
    (tmp_path / "results").mkdir()
    (tmp_path / "results" / "sidechannel.json").write_text('{"source":"live"}')
    (tmp_path / "contracts" / "fixtures" / "gauntlet.insecure.json").write_text('{"source":"fixture"}')
    c = TestClient(create_app(root=tmp_path, actions={}))
    assert c.get("/data/sidechannel.json").json()["source"] == "live"
    assert c.get("/data/gauntlet.insecure.json").json()["source"] == "fixture"
    assert c.get("/data/../.env").status_code in (404, 422)
    assert c.get("/data/secrets.json").status_code == 404


def test_api_data_combines_results_and_labels_placeholders(tmp_path):
    (tmp_path / "contracts" / "fixtures").mkdir(parents=True)
    (tmp_path / "contracts" / "fixtures" / "gauntlet.insecure.json").write_text(
        '{"run_id":"r","source":"fixture","config":"insecure","started_at":"t","notes":[],"probes":[]}')
    (tmp_path / "results").mkdir()
    (tmp_path / "results" / "sidechannel.json").write_text('{"source":"live","model":"m","trials_per_mode":2,"caveats":[],"modes":[]}')
    body = TestClient(create_app(root=tmp_path, actions={})).get("/api/data").json()
    assert body["sidechannel"]["model"] == "m" and body["sources"]["sidechannel"] == "recorded"
    assert body["sources"]["gauntlet_insecure"] == "placeholder" and body["sources"]["audit_export"] == "missing"
    assert body["audit_export"] is None and body["received_at"]


def test_api_data_matches_the_ui_schema_for_nulls(tmp_path):
    import json
    from sentinel.control.payload import normalise
    audit = {"records": [], "checkpoints": [], "public_key_pem": None, "verify": {"ok": True, "count": 3, "anchored_through": None, "unanchored_events": None}}
    out = normalise("audit_export", audit)
    assert out["verify"] == {"ok": True, "count": 3, "anchored_through": -1, "unanchored_events": 3} and out["public_key_pem"] == ""
    side = normalise("sidechannel", {"model": "m", "trials_per_mode": 20, "approx_prompt_tokens": None, "caveats": [],
                                      "modes": [{"mode": "shared", "hit_ms": [1], "miss_ms": [2], "auc_hit_faster": 1, "perm_p": None, "cohens_d": 2,
                                                 "best_threshold_accuracy": 1, "median_probe_latency_ms": 9}]})
    assert side["approx_prompt_tokens"] == 0 and "median_probe_latency_ms" not in side["modes"][0]
    g = normalise("gauntlet_hardened", {"run_id": "r", "source": "live", "config": "hardened", "started_at": "t", "notes": [],
                                        "probes": [{"id": "P01", "status": "pass", "evidence": "x", "duration_ms": None, "audit_hash": None}]})
    assert "evidence" not in g["probes"][0] and g["probes"][0]["duration_ms"] == 0.0
    json.dumps(g)
