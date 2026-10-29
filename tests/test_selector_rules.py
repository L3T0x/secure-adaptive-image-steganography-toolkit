from __future__ import annotations

from selector import ExplainableSelector


def test_selector_uses_png_matching_for_noise_expected() -> None:
    config, trace = ExplainableSelector().select_configuration(
        carrier_metadata={
            "format": "PNG",
            "width": 64,
            "height": 64,
            "channels": 3,
        },
        payload_size_bits=512,
        expected_transformations=["noise"],
    )

    assert config["engine_name"] == "PNGEngine"
    assert config["mode"] == "lsb_matching"
    assert any("noise" in line for line in trace)


def test_selector_uses_jpeg_robust_ecc_for_recompression_expected() -> None:
    config, trace = ExplainableSelector().select_configuration(
        carrier_metadata={
            "format": "JPEG",
            "non_zero_ac_count": 50_000,
            "robust_non_zero_ac_count": 40_000,
        },
        payload_size_bits=512,
        expected_transformations=["jpeg_recompression"],
    )

    assert config["engine_name"] == "JPEGEngine"
    assert config["robust_mode"] is True
    assert config["use_ecc"] is True
    assert config["payload_rate_bpnzac"] == 0.05
    assert any("Reed-Solomon" in line for line in trace)
