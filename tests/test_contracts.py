import json
from pathlib import Path

import pytest

from sentinel.contracts import AuditStatus, GauntletRun, SideChannelRun

FIXTURES = Path(__file__).resolve().parent.parent / "contracts" / "fixtures"

CASES = [
    ("gauntlet.insecure.json", GauntletRun),
    ("gauntlet.hardened.json", GauntletRun),
    ("sidechannel.json", SideChannelRun),
    ("audit_status.json", AuditStatus),
    ("audit_status.tampered.json", AuditStatus),
]


@pytest.mark.parametrize("name,model", CASES)
def test_fixture_matches_contract_and_is_labelled(name, model):
    data = json.loads((FIXTURES / name).read_text())
    parsed = model.model_validate(data)
    assert parsed.source == "fixture", "fixtures must never pose as measurements"


def test_fixtures_exercise_all_four_states():
    seen = set()
    for name in ("gauntlet.insecure.json", "gauntlet.hardened.json"):
        run = GauntletRun.model_validate(json.loads((FIXTURES / name).read_text()))
        seen |= {p.status for p in run.probes}
    assert seen == {"pass", "fail", "untested", "out_of_scope"}


def test_both_configs_cover_the_same_probes():
    ids = []
    for name in ("gauntlet.insecure.json", "gauntlet.hardened.json"):
        run = GauntletRun.model_validate(json.loads((FIXTURES / name).read_text()))
        ids.append([p.id for p in run.probes])
    assert ids[0] == ids[1]
