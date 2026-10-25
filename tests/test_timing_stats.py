import importlib.util
import random
from pathlib import Path

SPEC = importlib.util.spec_from_file_location("timing", Path(__file__).resolve().parent.parent / "spike" / "timing.py")
timing = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(timing)


def test_clearly_separated_groups_are_significant():
    hit = [60 + i for i in range(20)]
    miss = [3700 + i for i in range(20)]
    assert timing.auc_hit_faster(hit, miss) == 1.0
    assert timing.permutation_p(hit, miss) < 0.01
    assert timing.verdict(1.0, 0.0002).startswith("SEPARABLE")


def test_same_distribution_is_not_significant():
    rng = random.Random(3)
    hit = [rng.gauss(3800, 150) for _ in range(20)]
    miss = [rng.gauss(3800, 150) for _ in range(20)]
    assert timing.permutation_p(hit, miss) > 0.05


def test_small_sample_moderate_auc_is_not_called_significant():
    # The shape of the real isolated run: 10 vs 10, AUC about 0.7. Too weak to claim a channel.
    hit = [3543, 3543, 3622, 3701, 3701, 3781, 3939, 4018, 4097, 4255]
    miss = [3701, 3701, 3781, 3860, 3860, 4018, 4334, 4888, 4967, 5205]
    assert 0.6 < timing.auc_hit_faster(hit, miss) < 0.85
    assert timing.permutation_p(hit, miss) > 0.05


def test_permutation_p_is_deterministic():
    hit, miss = [1.0, 2.0, 3.0], [2.5, 3.5, 4.5]
    assert timing.permutation_p(hit, miss) == timing.permutation_p(hit, miss)


def test_a_perfectly_reversed_signal_is_reported_as_separable_not_as_safe():
    hit = [13000 + i for i in range(10)]      # correct guesses slow
    miss = [200 + i for i in range(10)]       # wrong guesses fast
    assert timing.auc_hit_faster(hit, miss) == 0.0
    assert timing.best_threshold_accuracy(hit, miss) == 1.0
    v = timing.verdict(0.0, timing.permutation_p(hit, miss))
    assert v.startswith("SEPARABLE IN REVERSE") and "NOT evidence" in v
