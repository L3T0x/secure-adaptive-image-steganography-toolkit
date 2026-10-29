from __future__ import annotations

import pytest

from eval_harness import EvaluationHarness


def test_resistance_score_formula_is_bounded_and_reproducible() -> None:
    result = EvaluationHarness().calculate_resistance_score(
        ssim=0.9,
        successful_extractions=3,
        total_attempted_transforms=6,
        roc_auc=0.75,
    )

    assert result["quality_score"] == pytest.approx(90.0)
    assert result["robustness_score"] == pytest.approx(50.0)
    assert result["evasion_score"] == pytest.approx(50.0)
    assert result["final_score"] == pytest.approx((90.0 + 50.0 + 50.0) / 3.0)
    assert 0.0 <= result["final_score"] <= 100.0
