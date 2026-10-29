from __future__ import annotations

import numpy as np
from PIL import Image

from stego_engines import PNGEmbedMode, PNGEngine


def test_png_lsb_matching_roundtrip_on_unmodified_carrier(tmp_path) -> None:
    cover = tmp_path / "cover.png"
    stego = tmp_path / "stego.png"
    rng = np.random.default_rng(20260630)
    image = rng.integers(0, 256, size=(64, 64, 3), dtype=np.uint8)
    Image.fromarray(image, "RGB").save(cover, format="PNG")

    payload = b"png roundtrip payload"
    seed = "pytest-fixed-seed"
    engine = PNGEngine()
    engine.embed(
        cover,
        payload,
        seed,
        output_path=stego,
        mode=PNGEmbedMode.LSB_MATCHING,
    )

    recovered = engine.extract(stego, len(payload) * 8, seed)

    assert recovered == payload
