"""Run reproducible BOSSbase-sourced PNG/JPEG toolkit evaluations.

BOSSbase 1.01 stores grayscale PGM images. This project targets PNG and JPEG,
so the benchmark converts selected BOSSbase images into PNG/JPEG carrier files,
then runs the normal secure embed, extract, steganalysis, and resistance-score
pipeline against those carriers.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
from io import BytesIO
import json
from pathlib import Path
import secrets
import zipfile
from typing import Any, Iterable, Mapping

import numpy as np
from PIL import Image

from crypto_layer import AuthenticationError
from main import StegoToolkit

_DEFAULT_ARCHIVE = Path("datasets/BOSSbase_1.01.zip")
_DEFAULT_OUTPUT_DIR = Path("datasets/bossbase_runs/latest")
_DEFAULT_MANIFEST = Path("datasets/BOSSbase_1.01_manifest.json")
_JPEG_QUALITY = 95


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run BOSSbase-sourced PNG/JPEG benchmark evaluations."
    )
    parser.add_argument("--archive", type=Path, default=_DEFAULT_ARCHIVE)
    parser.add_argument("--output-dir", type=Path, default=_DEFAULT_OUTPUT_DIR)
    parser.add_argument("--limit", type=int, default=2)
    parser.add_argument("--start", type=int, default=0)
    parser.add_argument(
        "--formats",
        default="PNG,JPEG",
        help="Comma-separated output carrier formats: PNG, JPEG, or PNG,JPEG.",
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        default=_DEFAULT_MANIFEST,
        help="Optional dataset manifest JSON produced during acquisition.",
    )
    args = parser.parse_args()

    formats = _parse_formats(args.formats)
    summary = run_bossbase_benchmark(
        archive_path=args.archive,
        output_dir=args.output_dir,
        limit=args.limit,
        start=args.start,
        formats=formats,
        manifest_path=args.manifest,
    )
    print(json.dumps(summary, indent=2))


def run_bossbase_benchmark(
    *,
    archive_path: Path,
    output_dir: Path,
    limit: int,
    start: int = 0,
    formats: tuple[str, ...] = ("PNG", "JPEG"),
    manifest_path: Path | None = _DEFAULT_MANIFEST,
) -> dict[str, Any]:
    """Create carriers from BOSSbase images and evaluate toolkit performance."""

    if limit <= 0:
        raise ValueError("limit must be a positive integer.")
    if start < 0:
        raise ValueError("start must be >= 0.")

    archive = archive_path.expanduser().resolve()
    if not archive.exists():
        raise FileNotFoundError(f"BOSSbase archive not found: {archive}")

    output = output_dir.expanduser().resolve()
    output.mkdir(parents=True, exist_ok=True)
    (output / "covers" / "png").mkdir(parents=True, exist_ok=True)
    (output / "covers" / "jpeg").mkdir(parents=True, exist_ok=True)
    (output / "stego").mkdir(parents=True, exist_ok=True)
    (output / "reports").mkdir(parents=True, exist_ok=True)

    dataset_manifest = _load_manifest(manifest_path)
    password = secrets.token_urlsafe(32)
    toolkit = StegoToolkit()
    records: list[dict[str, Any]] = []

    with zipfile.ZipFile(archive) as zf:
        image_entries = _bossbase_image_entries(zf)
        selected_entries = image_entries[start : start + limit]
        if len(selected_entries) < limit:
            raise ValueError(
                f"Requested {limit} images from start={start}, but only "
                f"{len(selected_entries)} entries were available."
            )

        for entry_name in selected_entries:
            source_id = Path(entry_name).stem
            source_image = _read_bossbase_image(zf, entry_name)
            for carrier_format in formats:
                record = _evaluate_one_carrier(
                    toolkit=toolkit,
                    source_image=source_image,
                    source_entry=entry_name,
                    source_id=source_id,
                    carrier_format=carrier_format,
                    password=password,
                    output_dir=output,
                )
                records.append(record)

    summary = {
        "benchmark_name": "BOSSbase-sourced PNG/JPEG secure steganography benchmark",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "archive_path": str(archive),
        "archive_sha256": _sha256_file(archive),
        "dataset_manifest": dataset_manifest,
        "bossbase_source_format": "PGM grayscale",
        "toolkit_carrier_formats": list(formats),
        "requested_image_limit": int(limit),
        "start_index": int(start),
        "evaluated_pairs": len(records),
        "password_sha256": hashlib.sha256(password.encode("utf-8")).hexdigest(),
        "records": records,
    }
    summary["aggregate"] = _aggregate_records(records)

    summary_path = output / "bossbase_benchmark_summary.json"
    markdown_path = output / "bossbase_benchmark_summary.md"
    summary["summary_json"] = str(summary_path)
    summary["summary_markdown"] = str(markdown_path)

    summary_path.write_text(json.dumps(_json_ready(summary), indent=2), encoding="utf-8")
    markdown_path.write_text(_render_markdown_summary(summary), encoding="utf-8")
    return _json_ready(summary)


def _evaluate_one_carrier(
    *,
    toolkit: StegoToolkit,
    source_image: Image.Image,
    source_entry: str,
    source_id: str,
    carrier_format: str,
    password: str,
    output_dir: Path,
) -> dict[str, Any]:
    carrier_format = carrier_format.upper()
    expected_transforms = (
        ["noise"] if carrier_format == "PNG" else ["jpeg_recompression"]
    )
    payload = (
        f"BOSSbase 1.01 source={source_id}; carrier={carrier_format}; "
        "secure adaptive steganography benchmark"
    ).encode("utf-8")

    cover_path = _write_cover_image(
        source_image=source_image,
        source_id=source_id,
        carrier_format=carrier_format,
        output_dir=output_dir,
    )
    stego_suffix = ".png" if carrier_format == "PNG" else ".jpg"
    stego_path = output_dir / "stego" / f"{source_id}_{carrier_format.lower()}_stego{stego_suffix}"

    embed_result = toolkit.protect_and_embed(
        cover_path=cover_path,
        payload_bytes=payload,
        password=password,
        expected_transforms=expected_transforms,
        output_path=stego_path,
    )
    recovered = toolkit.extract_and_verify(stego_path, password)
    roundtrip_ok = recovered == payload
    wrong_password_failed_closed = _wrong_password_fails_closed(toolkit, stego_path)
    report = toolkit.run_evaluation(cover_path, stego_path)

    report_path = output_dir / "reports" / f"{source_id}_{carrier_format.lower()}_report.json"
    report_path.write_text(json.dumps(_json_ready(report), indent=2), encoding="utf-8")

    return {
        "source_entry": source_entry,
        "source_id": source_id,
        "source_format": "PGM grayscale",
        "carrier_format": carrier_format,
        "cover_path": str(cover_path),
        "stego_path": str(stego_path),
        "manifest_path": embed_result["manifest_path"],
        "evaluation_report_json": str(report_path),
        "payload_bytes": len(payload),
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
        "roundtrip_ok": bool(roundtrip_ok),
        "wrong_password_failed_closed": bool(wrong_password_failed_closed),
        "detector_name": report["detectability"].get("detector_name"),
        "roc_auc": float(report["detectability"]["roc_auc"]),
        "confusion_matrix": report["detectability"]["confusion_matrix"],
        "ssim": float(report["quality_metrics"]["ssim"]),
        "psnr": float(report["quality_metrics"]["psnr"]),
        "successful_extractions": int(report["robustness"]["successful_extractions"]),
        "total_attempted_transforms": int(report["robustness"]["total_attempted_transforms"]),
        "resistance_score": float(report["resistance_score"]["final_score"]),
        "selected_engine": report["selected_config"].get("engine_name"),
    }


def _write_cover_image(
    *,
    source_image: Image.Image,
    source_id: str,
    carrier_format: str,
    output_dir: Path,
) -> Path:
    rgb = source_image.convert("RGB")
    if carrier_format == "PNG":
        path = output_dir / "covers" / "png" / f"{source_id}.png"
        rgb.save(path, format="PNG")
        return path
    if carrier_format == "JPEG":
        path = output_dir / "covers" / "jpeg" / f"{source_id}.jpg"
        rgb.save(path, format="JPEG", quality=_JPEG_QUALITY)
        return path
    raise ValueError(f"Unsupported carrier format: {carrier_format!r}")


def _wrong_password_fails_closed(toolkit: StegoToolkit, stego_path: Path) -> bool:
    try:
        toolkit.extract_and_verify(stego_path, "wrong-password-for-benchmark")
    except AuthenticationError:
        return True
    return False


def _bossbase_image_entries(zf: zipfile.ZipFile) -> list[str]:
    names = [
        name for name in zf.namelist()
        if name.lower().endswith(".pgm") and not name.endswith("/")
    ]

    def sort_key(name: str) -> tuple[int, str]:
        stem = Path(name).stem
        return (int(stem) if stem.isdigit() else 10**9, name)

    return sorted(names, key=sort_key)


def _read_bossbase_image(zf: zipfile.ZipFile, entry_name: str) -> Image.Image:
    with zf.open(entry_name) as handle:
        raw = handle.read()
    image = Image.open(BytesIO(raw))
    image.load()
    return image


def _parse_formats(raw: str) -> tuple[str, ...]:
    formats = tuple(part.strip().upper() for part in raw.split(",") if part.strip())
    if not formats:
        raise ValueError("At least one carrier format must be provided.")
    invalid = [fmt for fmt in formats if fmt not in {"PNG", "JPEG"}]
    if invalid:
        raise ValueError(f"Unsupported formats: {', '.join(invalid)}")
    return formats


def _load_manifest(path: Path | None) -> dict[str, Any] | None:
    if path is None:
        return None
    expanded = path.expanduser()
    if not expanded.exists():
        return None
    raw = json.loads(expanded.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"Dataset manifest is not a JSON object: {expanded}")
    return raw


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _json_ready(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _json_ready(item) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [_json_ready(item) for item in value]
    if isinstance(value, np.integer):
        return int(value)
    if isinstance(value, np.floating):
        return float(value)
    if isinstance(value, np.ndarray):
        return value.tolist()
    if isinstance(value, Path):
        return str(value)
    return value


def _aggregate_records(records: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Summarize benchmark records by carrier format for submission evidence."""

    groups: dict[str, list[Mapping[str, Any]]] = {}
    for record in records:
        carrier = str(record.get("carrier_format", "unknown"))
        groups.setdefault(carrier, []).append(record)

    aggregate: list[dict[str, Any]] = []
    for carrier, rows in sorted(groups.items()):
        count = len(rows)
        attempted = sum(int(row.get("total_attempted_transforms", 0)) for row in rows)
        transform_successes = sum(int(row.get("successful_extractions", 0)) for row in rows)
        aggregate.append(
            {
                "carrier_format": carrier,
                "pairs": count,
                "roundtrip_successes": sum(bool(row.get("roundtrip_ok")) for row in rows),
                "wrong_password_fail_closed_successes": sum(
                    bool(row.get("wrong_password_failed_closed")) for row in rows
                ),
                "transform_successes": transform_successes,
                "total_attempted_transforms": attempted,
                "transform_success_rate": transform_successes / attempted if attempted else 0.0,
                "mean_roc_auc": sum(float(row.get("roc_auc", 0.0)) for row in rows) / count,
                "mean_ssim": sum(float(row.get("ssim", 0.0)) for row in rows) / count,
                "mean_resistance_score": sum(
                    float(row.get("resistance_score", 0.0)) for row in rows
                )
                / count,
            }
        )
    return aggregate


def _render_markdown_summary(summary: Mapping[str, Any]) -> str:
    records = summary.get("records", [])
    aggregate = summary.get("aggregate", [])
    lines = [
        "# BOSSbase-Sourced Benchmark Summary",
        "",
        f"- Created UTC: `{summary.get('created_utc')}`",
        f"- Archive: `{summary.get('archive_path')}`",
        f"- Archive SHA-256: `{summary.get('archive_sha256')}`",
        f"- Source format: `{summary.get('bossbase_source_format')}`",
        f"- Toolkit carrier formats: `{', '.join(summary.get('toolkit_carrier_formats', []))}`",
        f"- Evaluated cover/stego pairs: `{summary.get('evaluated_pairs')}`",
        "",
        "## Method Note",
        "",
        "BOSSbase 1.01 images are stored as grayscale PGM files. For this PNG/JPEG "
        "toolkit, each selected source image is converted into the evaluated carrier "
        "format before embedding. This benchmark therefore supports the wording "
        "\"BOSSbase-sourced PNG/JPEG carriers\" rather than claiming the original "
        "PGM files were embedded directly.",
        "",
        "## Interpretation Note",
        "",
        "These detector AUC, transformation-survival, and resistance-score outputs "
        "are preliminary implementation evidence for the documented sample. A failed "
        "authenticated extraction after transformation is recorded as secure "
        "fail-closed behavior, not as a robustness success. Robustness success is "
        "counted only when the original authenticated payload is recovered.",
        "",
        "## Aggregate",
        "",
        "| Carrier | Pairs | Roundtrip | Wrong Password Fail-Closed | Transform Success | "
        "Mean ROC AUC | Mean SSIM | Mean Resistance |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    if isinstance(aggregate, Iterable):
        for row in aggregate:
            if not isinstance(row, Mapping):
                continue
            transform_success = (
                f"{int(row.get('transform_successes', 0))}/"
                f"{int(row.get('total_attempted_transforms', 0))}"
            )
            lines.append(
                "| {carrier} | {pairs} | {roundtrip}/{pairs} | {fail_closed}/{pairs} | "
                "{transform_success} | {auc:.6f} | {ssim:.6f} | {score:.2f} |".format(
                    carrier=row.get("carrier_format", "unknown"),
                    pairs=int(row.get("pairs", 0)),
                    roundtrip=int(row.get("roundtrip_successes", 0)),
                    fail_closed=int(row.get("wrong_password_fail_closed_successes", 0)),
                    transform_success=transform_success,
                    auc=float(row.get("mean_roc_auc", 0.0)),
                    ssim=float(row.get("mean_ssim", 0.0)),
                    score=float(row.get("mean_resistance_score", 0.0)),
                )
            )

    lines.extend(
        [
            "",
            "## Per-Pair Results",
            "",
        "",
        "| Source | Carrier | Roundtrip | Detector | ROC AUC | SSIM | PSNR | Resistance |",
        "| --- | --- | ---: | --- | ---: | ---: | ---: | ---: |",
        ]
    )
    if isinstance(records, Iterable):
        for record in records:
            if not isinstance(record, Mapping):
                continue
            lines.append(
                "| {source} | {carrier} | {roundtrip} | {detector} | {auc:.6f} | "
                "{ssim:.6f} | {psnr:.2f} | {score:.2f} |".format(
                    source=record.get("source_id", "unknown"),
                    carrier=record.get("carrier_format", "unknown"),
                    roundtrip=str(record.get("roundtrip_ok", False)),
                    detector=record.get("detector_name", "unknown"),
                    auc=float(record.get("roc_auc", 0.0)),
                    ssim=float(record.get("ssim", 0.0)),
                    psnr=float(record.get("psnr", 0.0)),
                    score=float(record.get("resistance_score", 0.0)),
                )
            )
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    main()
