"""Generate baseline-vs-primary comparison evidence for the FYP system.

The script compares:

- PNG baseline: LSB replacement
- PNG primary: LSB matching
- JPEG baseline: standard non-zero AC DCT embedding
- JPEG primary: robust DCT selection with Reed-Solomon ECC

Outputs are written to ``evidence/baseline_primary_comparison`` as JSON,
Markdown, cover images, stego images, and transformed check images.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
import json
from typing import Any, Callable

import numpy as np
from PIL import Image

from eval_harness import EvaluationHarness
from stego_engines import DEFAULT_RS_ECC_SYMBOLS, JPEGEngine, PNGEmbedMode, PNGEngine

_OUTPUT_DIR = Path("evidence/baseline_primary_comparison")
_SEED = "baseline-primary-comparison-seed"
_PNG_PAYLOAD = b"PNG baseline primary comparison payload"
_JPEG_PAYLOAD = b"JPEG baseline primary comparison payload"


@dataclass(frozen=True, slots=True)
class VariantResult:
    """One comparison result row."""

    sample_id: int
    seed: str
    family: str
    variant: str
    method: str
    cover_path: str
    stego_path: str
    roundtrip_ok: bool
    transform_check: str
    transform_roundtrip_ok: bool
    transform_failure_reason: str | None
    ssim: float
    psnr: float
    mse: float
    payload_bytes: int
    settings: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "sample_id": self.sample_id,
            "seed": self.seed,
            "family": self.family,
            "variant": self.variant,
            "method": self.method,
            "cover_path": self.cover_path,
            "stego_path": self.stego_path,
            "roundtrip_ok": self.roundtrip_ok,
            "transform_check": self.transform_check,
            "transform_roundtrip_ok": self.transform_roundtrip_ok,
            "transform_failure_reason": self.transform_failure_reason,
            "ssim": self.ssim,
            "psnr": self.psnr,
            "mse": self.mse,
            "payload_bytes": self.payload_bytes,
            "settings": self.settings,
        }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate PNG/JPEG baseline-vs-primary comparison evidence."
    )
    parser.add_argument("--output-dir", type=Path, default=_OUTPUT_DIR)
    parser.add_argument(
        "--samples",
        type=int,
        default=1,
        help="Number of deterministic synthetic cover samples to evaluate.",
    )
    parser.add_argument(
        "--jpeg-qf",
        type=int,
        default=90,
        help="JPEG recompression quality factor for the transform check.",
    )
    args = parser.parse_args()
    summary = run_comparison(
        output_dir=args.output_dir,
        sample_count=args.samples,
        jpeg_transform_quality=args.jpeg_qf,
    )
    print(json.dumps(summary, indent=2))


def run_comparison(
    output_dir: Path = _OUTPUT_DIR,
    *,
    sample_count: int = 1,
    jpeg_transform_quality: int = 90,
) -> dict[str, Any]:
    if sample_count <= 0:
        raise ValueError("sample_count must be a positive integer.")
    if not 1 <= jpeg_transform_quality <= 100:
        raise ValueError("jpeg_transform_quality must be within [1, 100].")

    output = output_dir.expanduser().resolve()
    output.mkdir(parents=True, exist_ok=True)

    covers_dir = output / "covers"
    stego_dir = output / "stego"
    transformed_dir = output / "transformed"
    for directory in (covers_dir, stego_dir, transformed_dir):
        directory.mkdir(parents=True, exist_ok=True)

    evaluator = EvaluationHarness()
    results: list[VariantResult] = []
    for sample_id in range(1, sample_count + 1):
        rng = np.random.default_rng(20260630 + sample_id)
        base_image = _make_textured_image(rng)
        sample_seed = f"{_SEED}-{sample_id:03d}"
        sample_prefix = f"sample_{sample_id:03d}"
        png_cover = covers_dir / f"{sample_prefix}_cover.png"
        jpeg_cover = covers_dir / f"{sample_prefix}_cover.jpg"
        Image.fromarray(base_image, "RGB").save(png_cover, format="PNG")
        Image.fromarray(base_image, "RGB").save(jpeg_cover, format="JPEG", quality=95)
        png_payload = _PNG_PAYLOAD + f" sample={sample_id:03d}".encode("ascii")
        jpeg_payload = _JPEG_PAYLOAD + f" sample={sample_id:03d}".encode("ascii")

        results.extend(
            [
                _run_png_variant(
                    evaluator=evaluator,
                    sample_id=sample_id,
                    seed=sample_seed,
                    payload=png_payload,
                    cover_path=png_cover,
                    stego_path=stego_dir / f"{sample_prefix}_png_lsb_replacement.png",
                    transformed_path=transformed_dir
                    / f"{sample_prefix}_png_lsb_replacement_noise.png",
                    mode=PNGEmbedMode.LSB_REPLACEMENT,
                    variant="baseline",
                    noise_seed=2026 + sample_id,
                ),
                _run_png_variant(
                    evaluator=evaluator,
                    sample_id=sample_id,
                    seed=sample_seed,
                    payload=png_payload,
                    cover_path=png_cover,
                    stego_path=stego_dir / f"{sample_prefix}_png_lsb_matching.png",
                    transformed_path=transformed_dir
                    / f"{sample_prefix}_png_lsb_matching_noise.png",
                    mode=PNGEmbedMode.LSB_MATCHING,
                    variant="primary",
                    noise_seed=2026 + sample_id,
                ),
                _run_jpeg_variant(
                    evaluator=evaluator,
                    sample_id=sample_id,
                    seed=sample_seed,
                    payload=jpeg_payload,
                    cover_path=jpeg_cover,
                    stego_path=stego_dir / f"{sample_prefix}_jpeg_standard_dct.jpg",
                    transformed_path=transformed_dir
                    / f"{sample_prefix}_jpeg_standard_dct_q{jpeg_transform_quality}.jpg",
                    variant="baseline",
                    payload_rate_bpnzac=0.1,
                    use_ecc=False,
                    robust_mode=False,
                    jpeg_transform_quality=jpeg_transform_quality,
                ),
                _run_jpeg_variant(
                    evaluator=evaluator,
                    sample_id=sample_id,
                    seed=sample_seed,
                    payload=jpeg_payload,
                    cover_path=jpeg_cover,
                    stego_path=stego_dir / f"{sample_prefix}_jpeg_robust_dct_ecc.jpg",
                    transformed_path=transformed_dir
                    / f"{sample_prefix}_jpeg_robust_dct_ecc_q{jpeg_transform_quality}.jpg",
                    variant="primary",
                    payload_rate_bpnzac=0.05,
                    use_ecc=True,
                    robust_mode=True,
                    jpeg_transform_quality=jpeg_transform_quality,
                ),
            ]
        )

    summary = {
        "comparison_name": "Baseline vs primary embedding comparison",
        "seed_prefix": _SEED,
        "sample_count": sample_count,
        "jpeg_transform_quality": jpeg_transform_quality,
        "notes": [
            "PNG transform check applies deterministic Gaussian noise.",
            f"JPEG transform check applies JPEG recompression at quality factor {jpeg_transform_quality}.",
            "Transform failures are reported as evidence, not hidden.",
            "A failed transform extraction is not counted as robustness success.",
            "These comparison outputs are preliminary evidence unless produced on the final documented evaluation sample.",
        ],
        "aggregate": _summarize_results(results),
        "results": [result.to_dict() for result in results],
    }

    json_path = output / "baseline_primary_comparison.json"
    markdown_path = output / "baseline_primary_comparison.md"
    summary["json_report"] = str(json_path)
    summary["markdown_report"] = str(markdown_path)
    json_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    markdown_path.write_text(_render_markdown(summary), encoding="utf-8")
    return summary


def _run_png_variant(
    *,
    evaluator: EvaluationHarness,
    sample_id: int,
    seed: str,
    payload: bytes,
    cover_path: Path,
    stego_path: Path,
    transformed_path: Path,
    mode: PNGEmbedMode,
    variant: str,
    noise_seed: int,
) -> VariantResult:
    engine = PNGEngine()
    engine.embed(
        cover_path,
        payload,
        seed,
        output_path=stego_path,
        mode=mode,
    )
    recovered = engine.extract(stego_path, len(payload) * 8, seed)
    roundtrip_ok = recovered == payload

    stego_image = _load_image(stego_path)
    noisy = evaluator.transform_image(stego_image, "noise", noise_seed=noise_seed)
    Image.fromarray(noisy).save(transformed_path, format="PNG")
    transformed_recovered = engine.extract(
        transformed_path,
        len(payload) * 8,
        seed,
    )
    transform_roundtrip_ok = transformed_recovered == payload

    quality = evaluator.calculate_quality(_load_image(cover_path), stego_image)
    return VariantResult(
        sample_id=sample_id,
        seed=seed,
        family="PNG",
        variant=variant,
        method=mode.value,
        cover_path=str(cover_path),
        stego_path=str(stego_path),
        roundtrip_ok=roundtrip_ok,
        transform_check=f"gaussian_noise_seed_{noise_seed}",
        transform_roundtrip_ok=transform_roundtrip_ok,
        transform_failure_reason=None if transform_roundtrip_ok else "payload bits changed after noise",
        ssim=float(quality["ssim"]),
        psnr=float(quality["psnr"]),
        mse=float(quality["mse"]),
        payload_bytes=len(payload),
        settings={"mode": mode.value},
    )


def _run_jpeg_variant(
    *,
    evaluator: EvaluationHarness,
    sample_id: int,
    seed: str,
    payload: bytes,
    cover_path: Path,
    stego_path: Path,
    transformed_path: Path,
    variant: str,
    payload_rate_bpnzac: float,
    use_ecc: bool,
    robust_mode: bool,
    jpeg_transform_quality: int,
) -> VariantResult:
    engine = JPEGEngine()
    metadata: dict[str, Any] = {}
    engine.embed(
        cover_path,
        payload,
        seed,
        output_path=stego_path,
        payload_rate_bpnzac=payload_rate_bpnzac,
        use_ecc=use_ecc,
        ecc_symbols=DEFAULT_RS_ECC_SYMBOLS,
        robust_mode=robust_mode,
        metadata_out=metadata,
    )
    extract_kwargs = {
        "payload_rate_bpnzac": payload_rate_bpnzac,
        "use_ecc": use_ecc,
        "ecc_symbols": DEFAULT_RS_ECC_SYMBOLS,
        "robust_mode": robust_mode,
        "selection_metadata": metadata,
    }
    recovered = engine.extract(
        stego_path,
        len(payload) * 8,
        seed,
        **extract_kwargs,
    )
    roundtrip_ok = recovered == payload

    Image.open(stego_path).save(
        transformed_path,
        format="JPEG",
        quality=jpeg_transform_quality,
    )
    transform_ok, transform_failure = _attempt_extract(
        lambda: engine.extract(
            transformed_path,
            len(payload) * 8,
            seed,
            **extract_kwargs,
        )
        == payload
    )

    quality = evaluator.calculate_quality(_load_image(cover_path), _load_image(stego_path))
    method = "robust_dct_with_reed_solomon_ecc" if use_ecc else "standard_dct"
    return VariantResult(
        sample_id=sample_id,
        seed=seed,
        family="JPEG",
        variant=variant,
        method=method,
        cover_path=str(cover_path),
        stego_path=str(stego_path),
        roundtrip_ok=roundtrip_ok,
        transform_check=f"jpeg_recompression_q{jpeg_transform_quality}",
        transform_roundtrip_ok=transform_ok,
        transform_failure_reason=transform_failure,
        ssim=float(quality["ssim"]),
        psnr=float(quality["psnr"]),
        mse=float(quality["mse"]),
        payload_bytes=len(payload),
        settings={
            "payload_rate_bpnzac": payload_rate_bpnzac,
            "use_ecc": use_ecc,
            "ecc_symbols": DEFAULT_RS_ECC_SYMBOLS,
            "robust_mode": robust_mode,
        },
    )


def _attempt_extract(operation: Callable[[], bool]) -> tuple[bool, str | None]:
    try:
        ok = bool(operation())
    except Exception as exc:  # pragma: no cover - evidence reporting
        return False, f"{type(exc).__name__}: {exc}"
    return ok, None if ok else "extracted payload did not match"


def _make_textured_image(rng: np.random.Generator) -> np.ndarray:
    height, width = 256, 256
    y = np.linspace(0, 255, height, dtype=np.float32)[:, None]
    x = np.linspace(0, 255, width, dtype=np.float32)[None, :]
    noise = rng.normal(0, 18, size=(height, width)).astype(np.float32)
    red = np.clip(0.65 * x + 0.35 * y + noise, 0, 255)
    green = np.clip(0.25 * x + 0.75 * y + noise, 0, 255)
    blue = np.clip(255 - 0.55 * x + 0.45 * y + noise, 0, 255)
    return np.stack([red, green, blue], axis=-1).astype(np.uint8)


def _load_image(path: Path) -> np.ndarray:
    with Image.open(path) as image:
        return np.asarray(image.convert("RGB"), dtype=np.uint8)


def _summarize_results(results: list[VariantResult]) -> list[dict[str, Any]]:
    groups: dict[tuple[str, str, str], list[VariantResult]] = {}
    for result in results:
        groups.setdefault((result.family, result.variant, result.method), []).append(result)

    aggregate: list[dict[str, Any]] = []
    for (family, variant, method), rows in sorted(groups.items()):
        count = len(rows)
        aggregate.append(
            {
                "family": family,
                "variant": variant,
                "method": method,
                "samples": count,
                "roundtrip_successes": sum(row.roundtrip_ok for row in rows),
                "transform_successes": sum(row.transform_roundtrip_ok for row in rows),
                "transform_success_rate": sum(row.transform_roundtrip_ok for row in rows)
                / count,
                "mean_ssim": sum(row.ssim for row in rows) / count,
                "mean_psnr": sum(row.psnr for row in rows) / count,
                "mean_mse": sum(row.mse for row in rows) / count,
            }
        )
    return aggregate


def _render_markdown(summary: dict[str, Any]) -> str:
    lines = [
        "# Baseline vs Primary Comparison",
        "",
        f"- Seed prefix: `{summary['seed_prefix']}`",
        f"- Samples: `{summary['sample_count']}`",
        f"- JPEG transform check: `q{summary['jpeg_transform_quality']}`",
        "",
        "## Aggregate",
        "",
        "| Family | Variant | Method | Samples | Roundtrip | Transform Roundtrip | Mean SSIM | Mean PSNR |",
        "| --- | --- | --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for row in summary["aggregate"]:
        lines.append(
            "| {family} | {variant} | {method} | {samples} | {roundtrip}/{samples} | "
            "{transform}/{samples} | {ssim:.6f} | {psnr:.2f} |".format(
                family=row["family"],
                variant=row["variant"],
                method=row["method"],
                samples=int(row["samples"]),
                roundtrip=int(row["roundtrip_successes"]),
                transform=int(row["transform_successes"]),
                ssim=float(row["mean_ssim"]),
                psnr=float(row["mean_psnr"]),
            )
        )

    lines.extend(
        [
            "",
            "## Detailed Results",
            "",
            "| Sample | Family | Variant | Method | Roundtrip | Transform | Transform Roundtrip | SSIM | PSNR |",
            "| ---: | --- | --- | --- | ---: | --- | ---: | ---: | ---: |",
        ]
    )
    for result in summary["results"]:
        lines.append(
            "| {sample} | {family} | {variant} | {method} | {roundtrip} | {transform} | "
            "{transform_ok} | {ssim:.6f} | {psnr:.2f} |".format(
                sample=result["sample_id"],
                family=result["family"],
                variant=result["variant"],
                method=result["method"],
                roundtrip=result["roundtrip_ok"],
                transform=result["transform_check"],
                transform_ok=result["transform_roundtrip_ok"],
                ssim=float(result["ssim"]),
                psnr=float(result["psnr"]),
            )
        )

    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "- PNG results should be described as successful extraction on unmodified carriers.",
            "- PNG post-processing failures should be described as payload corruption after destructive transformation.",
            "- JPEG robust mode with ECC is the primary configuration for lossy recompression scenarios.",
            "- These results are comparison evidence, not a claim of universal robustness.",
            "",
        ]
    )
    return "\n".join(lines)


if __name__ == "__main__":
    main()
