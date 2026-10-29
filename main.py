"""Integrated Python API and CLI for the steganography toolkit.

This module provides:

1. ``StegoToolkit``: a high-level Python facade for embedding, extraction, and
   evaluation.
2. A secure command-line interface that never accepts passwords as plaintext
   arguments and instead prompts via ``getpass`` at runtime.

Implementation note:
    The lower-level steganography engines deliberately do not embed extraction
    metadata such as payload length or seed. To make end-to-end usage
    deterministic and production-friendly, this module persists a JSON sidecar
    manifest next to each stego image. The manifest contains only non-secret
    metadata:

    - selected engine configuration
    - deterministic seed used for path selection
    - serialized encrypted-envelope bit length
    - SHA-256 digest of the encrypted envelope
    - selector justification trace

    Passwords and plaintext payloads are never written to disk.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from functools import partial
import getpass
import hashlib
import json
import logging
from pathlib import Path
import secrets
import sys
import tempfile
from typing import Any, Final, Mapping, Optional, Sequence

import numpy as np
from PIL import Image
from rich.console import Console
from rich.logging import RichHandler
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
import typer

from crypto_layer import AuthenticationError, IntegrityError, decrypt_payload, encrypt_payload
from eval_harness import EvaluationHarness
from selector import ExplainableSelector, render_policy_log
from steganalysis import RichResidualEnsembleDetector, SteganalysisDatasetError
from stego_engines import CapacityError, EngineFactory, JPEGEngine, MissingDependencyError, PNGEngine, StegoEngine

logger = logging.getLogger(__name__)
console = Console()
app = typer.Typer(
    help="Secure Adaptive Image Steganography Toolkit with mandatory cryptography and reproducible evaluation.",
    no_args_is_help=True,
)

_PNG_FORMAT: Final[str] = "PNG"
_JPEG_FORMAT: Final[str] = "JPEG"
_SUPPORTED_FORMATS: Final[set[str]] = {_PNG_FORMAT, _JPEG_FORMAT}
_MANIFEST_VERSION: Final[int] = 1
_DEFAULT_JPEG_SAVE_QUALITY: Final[int] = 95
_DEFAULT_AUDIT_LOG: Final[Path] = Path("logs/stegtoolkit-audit.log")
_SUCCESS_LEVEL: Final[int] = 25
_SECURE_FAIL_CLOSED_STATUS: Final[str] = "Secure Fail-Closed (Tamper Detected)"
_SURVIVED_TRANSFORM_STATUS: Final[str] = "Survived Transform (Envelope Intact)"

logging.addLevelName(_SUCCESS_LEVEL, "SUCCESS")


@dataclass(frozen=True, slots=True)
class TransformSpec:
    """Named transformation plus parameter set for evaluation workflows."""

    name: str
    params: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class StegoManifest:
    """Non-secret sidecar metadata required for deterministic extraction."""

    version: int
    created_utc: str
    carrier_format: str
    engine_name: str
    seed: str
    embedded_payload_bits: int
    encrypted_envelope_sha256: str
    selected_config: dict[str, Any]
    justification_trace: list[str]
    expected_transforms: list[str]
    carrier_metadata: dict[str, Any]
    engine_metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize the manifest into a JSON-compatible dictionary."""

        return {
            "version": self.version,
            "created_utc": self.created_utc,
            "carrier_format": self.carrier_format,
            "engine_name": self.engine_name,
            "seed": self.seed,
            "embedded_payload_bits": self.embedded_payload_bits,
            "encrypted_envelope_sha256": self.encrypted_envelope_sha256,
            "selected_config": self.selected_config,
            "justification_trace": self.justification_trace,
            "expected_transforms": self.expected_transforms,
            "carrier_metadata": self.carrier_metadata,
            "engine_metadata": self.engine_metadata,
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "StegoManifest":
        """Parse a validated manifest mapping."""

        version = _require_int(raw, key="version", minimum=1)
        created_utc = _require_non_empty_str(raw, key="created_utc")
        carrier_format = _normalize_format(_require_non_empty_str(raw, key="carrier_format"))
        engine_name = _require_non_empty_str(raw, key="engine_name")
        seed = _require_non_empty_str(raw, key="seed")
        embedded_payload_bits = _require_int(raw, key="embedded_payload_bits", minimum=0)
        encrypted_envelope_sha256 = _require_non_empty_str(raw, key="encrypted_envelope_sha256")
        selected_config = _require_dict(raw, key="selected_config")
        justification_trace = _require_str_list(raw, key="justification_trace")
        expected_transforms = _require_str_list(raw, key="expected_transforms")
        carrier_metadata = _require_dict(raw, key="carrier_metadata")
        engine_metadata = (
            _require_dict(raw, key="engine_metadata")
            if "engine_metadata" in raw
            else {}
        )

        return cls(
            version=version,
            created_utc=created_utc,
            carrier_format=carrier_format,
            engine_name=engine_name,
            seed=seed,
            embedded_payload_bits=embedded_payload_bits,
            encrypted_envelope_sha256=encrypted_envelope_sha256,
            selected_config=dict(selected_config),
            justification_trace=list(justification_trace),
            expected_transforms=list(expected_transforms),
            carrier_metadata=dict(carrier_metadata),
            engine_metadata=dict(engine_metadata),
        )


@dataclass(slots=True)
class StegoToolkit:
    """High-level facade for secure embedding, extraction, and evaluation."""

    selector: ExplainableSelector = field(default_factory=ExplainableSelector)
    evaluator: EvaluationHarness = field(default_factory=EvaluationHarness)
    steganalysis_detector: RichResidualEnsembleDetector = field(
        default_factory=RichResidualEnsembleDetector
    )
    default_transform_specs: tuple[TransformSpec, ...] = (
        TransformSpec(name="jpeg_recompression", params={"jpeg_quality": 75}),
        TransformSpec(name="jpeg_recompression", params={"jpeg_quality": 85}),
        TransformSpec(name="jpeg_recompression", params={"jpeg_quality": 90}),
        TransformSpec(name="resize"),
        TransformSpec(name="crop"),
        TransformSpec(name="noise", params={"noise_seed": 1337}),
    )

    def protect_and_embed(
        self,
        cover_path: str | Path,
        payload_bytes: bytes,
        password: str,
        expected_transforms: Sequence[str] | None = None,
        output_path: str | Path | None = None,
    ) -> dict[str, Any]:
        """Encrypt a payload, choose an engine, embed, and persist a manifest."""

        cover = Path(cover_path).expanduser().resolve()
        if not cover.exists():
            raise FileNotFoundError(f"Cover image not found: {cover}")
        _ensure_non_empty_password(password)

        carrier_metadata = self._extract_carrier_metadata(cover)
        normalized_output = _normalize_output_path(
            output_path=output_path,
            carrier_format=carrier_metadata["format"],
        )
        normalized_expected_transforms = _normalize_transform_list(expected_transforms)

        encrypted_envelope = encrypt_payload(payload_bytes, password)
        embedded_payload_bits = len(encrypted_envelope) * 8

        selected_config, justification_trace = self.selector.select_configuration(
            carrier_metadata=carrier_metadata,
            payload_size_bits=embedded_payload_bits,
            expected_transformations=normalized_expected_transforms,
        )

        for line in justification_trace:
            logger.info("%s", line)

        engine = self._instantiate_engine(selected_config["carrier_format"])
        seed = secrets.token_hex(16)
        engine_metadata: dict[str, Any] = {}
        stego_path = engine.embed(
            cover,
            encrypted_envelope,
            seed,
            output_path=normalized_output,
            metadata_out=engine_metadata,
            **dict(selected_config.get("embed_kwargs", {})),
        )

        manifest = StegoManifest(
            version=_MANIFEST_VERSION,
            created_utc=datetime.now(timezone.utc).isoformat(),
            carrier_format=selected_config["carrier_format"],
            engine_name=selected_config["engine_name"],
            seed=seed,
            embedded_payload_bits=embedded_payload_bits,
            encrypted_envelope_sha256=_sha256_hex(encrypted_envelope),
            selected_config=_json_safe_config(selected_config),
            justification_trace=list(justification_trace),
            expected_transforms=list(normalized_expected_transforms),
            carrier_metadata=dict(carrier_metadata),
            engine_metadata=_json_safe_config(engine_metadata),
        )
        manifest_path = self._manifest_path_for_stego(stego_path)
        manifest_path.write_text(
            json.dumps(manifest.to_dict(), indent=2),
            encoding="utf-8",
        )

        return {
            "cover_path": str(cover),
            "stego_path": str(Path(stego_path).resolve()),
            "manifest_path": str(manifest_path.resolve()),
            "carrier_metadata": carrier_metadata,
            "selected_config": manifest.selected_config,
            "justification_trace": list(justification_trace),
            "embedded_payload_bits": embedded_payload_bits,
        }

    def analyze_carrier(self, image_path: str | Path) -> dict[str, Any]:
        """Return metadata and steganographic capacity for a candidate carrier."""

        path = Path(image_path).expanduser().resolve()
        if not path.exists():
            raise FileNotFoundError(f"Carrier image not found: {path}")
        metadata = self._extract_carrier_metadata(path)
        capacity_bits = int(metadata.get("capacity_bits", 0))
        analysis = {
            "path": str(path),
            "format": metadata["format"],
            "width": metadata.get("width"),
            "height": metadata.get("height"),
            "channels": metadata.get("channels"),
            "capacity_bits": capacity_bits,
            "capacity_bytes": capacity_bits // 8,
            "metadata": metadata,
        }
        if metadata["format"] == _JPEG_FORMAT:
            robust_count = int(metadata.get("robust_non_zero_ac_count", 0))
            analysis["robust_capacity_bits"] = int(0.05 * robust_count)
            analysis["robust_capacity_bytes"] = int(analysis["robust_capacity_bits"]) // 8
        return analysis

    def extract_and_verify(
        self,
        stego_path: str | Path,
        password: str,
    ) -> bytes:
        """Extract an encrypted envelope from a stego image and authenticate it."""

        stego = Path(stego_path).expanduser().resolve()
        if not stego.exists():
            raise FileNotFoundError(f"Stego image not found: {stego}")
        _ensure_non_empty_password(password)

        manifest = self._load_manifest(stego)
        carrier_format = self._detect_format(stego)
        if carrier_format != manifest.carrier_format:
            raise ValueError(
                f"Manifest carrier format {manifest.carrier_format!r} does not match image format {carrier_format!r}."
            )

        raw_envelope = self._extract_raw_envelope(
            stego_path=stego,
            manifest=manifest,
        )
        return decrypt_payload(raw_envelope, password)

    def run_evaluation(
        self,
        cover_path: str | Path,
        stego_path: str | Path,
    ) -> dict[str, Any]:
        """Run quality, robustness, detectability, and unified scoring."""

        cover = Path(cover_path).expanduser().resolve()
        stego = Path(stego_path).expanduser().resolve()
        if not cover.exists():
            raise FileNotFoundError(f"Cover image not found: {cover}")
        if not stego.exists():
            raise FileNotFoundError(f"Stego image not found: {stego}")

        manifest = self._load_manifest(stego)
        cover_format = self._detect_format(cover)
        stego_format = self._detect_format(stego)
        if cover_format != stego_format:
            raise ValueError(
                f"Cover/stego format mismatch: {cover_format!r} != {stego_format!r}."
            )

        cover_image = self._load_image_array(cover)
        stego_image = self._load_image_array(stego)
        quality_metrics = self.evaluator.calculate_quality(cover_image, stego_image)

        robustness = self._evaluate_robustness(
            stego_path=stego,
            carrier_format=stego_format,
            manifest=manifest,
        )
        detectability = self._evaluate_detectability(
            cover_image=cover_image,
            stego_image=stego_image,
        )
        resistance_score = self.evaluator.calculate_resistance_score(
            ssim=float(quality_metrics["ssim"]),
            successful_extractions=robustness["successful_extractions"],
            total_attempted_transforms=robustness["total_attempted_transforms"],
            roc_auc=float(detectability["roc_auc"]),
        )

        return {
            "cover_path": str(cover),
            "stego_path": str(stego),
            "carrier_format": stego_format,
            "quality_metrics": quality_metrics,
            "robustness": robustness,
            "detectability": detectability,
            "resistance_score": resistance_score,
            "selected_config": manifest.selected_config,
            "justification_trace": list(manifest.justification_trace),
            "carrier_metadata": dict(manifest.carrier_metadata),
        }

    def _extract_carrier_metadata(self, image_path: Path) -> dict[str, Any]:
        """Extract selector-relevant metadata from a carrier image."""

        carrier_format = self._detect_format(image_path)
        metadata: dict[str, Any] = {
            "format": carrier_format,
        }

        if carrier_format == _PNG_FORMAT:
            report = PNGEngine().capacity_report(image_path)
            metadata.update(
                {
                    "width": report.width,
                    "height": report.height,
                    "channels": report.embeddable_channels,
                    "capacity_bits": report.capacity_bits,
                }
            )
            return metadata

        standard_report = JPEGEngine().capacity_report(
            image_path,
            payload_rate_bpnzac=1.0,
            robust_mode=False,
        )
        robust_report = JPEGEngine().capacity_report(
            image_path,
            payload_rate_bpnzac=1.0,
            robust_mode=True,
        )
        with Image.open(image_path) as image:
            metadata.update(
                {
                    "width": int(image.width),
                    "height": int(image.height),
                    "channels": len(image.getbands()),
                    "non_zero_ac_count": standard_report.total_nonzero_ac_coefficients,
                    "robust_non_zero_ac_count": robust_report.total_nonzero_ac_coefficients,
                    "capacity_bits": standard_report.capacity_bits,
                }
            )
        return metadata

    def _extract_raw_envelope(
        self,
        *,
        stego_path: Path,
        manifest: StegoManifest,
    ) -> bytes:
        """Extract the raw encrypted envelope using manifest metadata."""

        engine = self._instantiate_engine(manifest.carrier_format)
        extract_kwargs = dict(manifest.selected_config.get("embed_kwargs", {}))
        if manifest.engine_metadata:
            extract_kwargs["selection_metadata"] = dict(manifest.engine_metadata)
        raw_envelope = engine.extract(
            stego_path,
            manifest.embedded_payload_bits,
            manifest.seed,
            **extract_kwargs,
        )
        return raw_envelope

    def _evaluate_robustness(
        self,
        *,
        stego_path: Path,
        carrier_format: str,
        manifest: StegoManifest,
    ) -> dict[str, Any]:
        """Apply default transforms and record encrypted-envelope recovery success."""

        transform_results: list[dict[str, Any]] = []
        successful_extractions = 0

        with tempfile.TemporaryDirectory(prefix="saistk_eval_") as tmp_dir:
            temp_dir = Path(tmp_dir)
            for index, spec in enumerate(self.default_transform_specs, start=1):
                transform_label = _format_transform_label(spec)
                transformed_path = temp_dir / self._transformed_filename(
                    source_suffix=stego_path.suffix,
                    index=index,
                )
                try:
                    self._materialize_transformed_image(
                        source_path=stego_path,
                        carrier_format=carrier_format,
                        spec=spec,
                        destination=transformed_path,
                    )
                    extracted = self._extract_raw_envelope(
                        stego_path=transformed_path,
                        manifest=manifest,
                    )
                    digest = _sha256_hex(extracted)
                    matched = digest == manifest.encrypted_envelope_sha256
                    if matched:
                        successful_extractions += 1
                    security_status = (
                        _SURVIVED_TRANSFORM_STATUS
                        if matched
                        else _SECURE_FAIL_CLOSED_STATUS
                    )
                    transform_results.append(
                        {
                            "transform": spec.name,
                            "parameters": dict(spec.params),
                            "success": matched,
                            "security_status": security_status,
                            "extracted_sha256": digest,
                            "failure_reason": (
                                None
                                if matched
                                else (
                                    "Extracted encrypted envelope no longer matched the "
                                    "original authenticated ciphertext."
                                )
                            ),
                        }
                    )
                except (CapacityError, IntegrityError, ValueError, RuntimeError, FileNotFoundError) as exc:
                    transform_results.append(
                        {
                            "transform": spec.name,
                            "parameters": dict(spec.params),
                            "success": False,
                            "security_status": _SECURE_FAIL_CLOSED_STATUS,
                            "error": str(exc),
                        }
                    )
                logger.debug(
                    "Robustness transform %s -> %s",
                    transform_label,
                    "PASS" if transform_results[-1]["success"] else "FAIL",
                )

        return {
            "successful_extractions": successful_extractions,
            "total_attempted_transforms": len(self.default_transform_specs),
            "survival_rate": successful_extractions / len(self.default_transform_specs),
            "transform_results": transform_results,
        }

    def _evaluate_detectability(
        self,
        *,
        cover_image: np.ndarray,
        stego_image: np.ndarray,
    ) -> dict[str, Any]:
        """Train the feature-based ensemble baseline and compute detectability metrics."""

        transform_specs = [
            {"name": spec.name, "params": dict(spec.params)}
            for spec in self.default_transform_specs
        ]
        try:
            detector_output = self.steganalysis_detector.evaluate(
                cover_image=cover_image,
                stego_image=stego_image,
                transform_specs=transform_specs,
                transform_image=self.evaluator.transform_image,
            )
            report = self.evaluator.calculate_detectability(
                detector_output["y_true"],
                detector_output["y_scores"],
            )
            metadata = detector_output.get("metadata", {})
            if isinstance(metadata, Mapping):
                report.update(dict(metadata))
            return report
        except SteganalysisDatasetError as exc:
            logger.warning(
                "Feature-based ensemble detector could not be trained; "
                "falling back to deterministic proxy: %s",
                exc,
            )
            return self._evaluate_proxy_detectability(
                cover_image=cover_image,
                stego_image=stego_image,
            )

    def _evaluate_proxy_detectability(
        self,
        *,
        cover_image: np.ndarray,
        stego_image: np.ndarray,
    ) -> dict[str, Any]:
        """Build a deterministic proxy detector dataset for constrained inputs."""

        negative_samples = [cover_image]
        positive_samples = [stego_image]
        for spec in self.default_transform_specs:
            negative_samples.append(
                self.evaluator.transform_image(
                    cover_image,
                    spec.name,
                    **dict(spec.params),
                )
            )
            positive_samples.append(
                self.evaluator.transform_image(
                    stego_image,
                    spec.name,
                    **dict(spec.params),
                )
            )

        y_true = np.array(
            [0] * len(negative_samples) + [1] * len(positive_samples),
            dtype=np.int64,
        )
        all_samples = [*negative_samples, *positive_samples]
        y_scores = np.array(
            self.evaluator.score_samples_concurrently(
                all_samples,
                partial(_proxy_detector_score, cover_image),
            ),
            dtype=np.float64,
        )

        report = self.evaluator.calculate_detectability(y_true, y_scores)
        report["detector_name"] = "mean_absolute_difference_proxy"
        report["fallback_reason"] = "feature_based_ensemble_dataset_too_small"
        report["sample_count"] = int(y_true.size)
        return report

    def _materialize_transformed_image(
        self,
        *,
        source_path: Path,
        carrier_format: str,
        spec: TransformSpec,
        destination: Path,
    ) -> None:
        """Persist a transformed carrier image for robustness extraction tests."""

        if carrier_format == _JPEG_FORMAT and spec.name == "jpeg_recompression":
            image = self._load_image_array(source_path)
            self._save_image_array(
                image=image,
                destination=destination,
                carrier_format=carrier_format,
                jpeg_quality=int(spec.params["jpeg_quality"]),
            )
            return

        source_image = self._load_image_array(source_path)
        transformed = self.evaluator.transform_image(
            source_image,
            spec.name,
            **dict(spec.params),
        )
        jpeg_quality = (
            int(spec.params["jpeg_quality"])
            if carrier_format == _JPEG_FORMAT and spec.name == "jpeg_recompression"
            else _DEFAULT_JPEG_SAVE_QUALITY
        )
        self._save_image_array(
            image=transformed,
            destination=destination,
            carrier_format=carrier_format,
            jpeg_quality=jpeg_quality,
        )

    @staticmethod
    def _save_image_array(
        *,
        image: np.ndarray,
        destination: Path,
        carrier_format: str,
        jpeg_quality: int = _DEFAULT_JPEG_SAVE_QUALITY,
    ) -> None:
        """Save an image array to disk using the requested carrier format."""

        destination.parent.mkdir(parents=True, exist_ok=True)
        pil_image = Image.fromarray(image)
        if carrier_format == _PNG_FORMAT:
            pil_image.save(destination, format="PNG")
            return
        pil_image.save(destination, format="JPEG", quality=jpeg_quality)

    @staticmethod
    def _load_image_array(image_path: Path) -> np.ndarray:
        """Load an image into a NumPy array while preserving channel structure."""

        with Image.open(image_path) as image:
            return np.array(image)

    @staticmethod
    def _detect_format(image_path: Path) -> str:
        """Detect and normalize the image format."""

        with Image.open(image_path) as image:
            if image.format is None:
                raise ValueError(f"Unable to determine image format for: {image_path}")
            return _normalize_format(image.format)

    @staticmethod
    def _instantiate_engine(carrier_format: str) -> StegoEngine:
        """Create the steganography engine that matches the carrier format."""

        return EngineFactory.create(_normalize_format(carrier_format))

    @staticmethod
    def _manifest_path_for_stego(stego_path: str | Path) -> Path:
        """Return the sidecar manifest path for a stego image."""

        path = Path(stego_path).expanduser().resolve()
        return path.with_suffix(path.suffix + ".manifest.json")

    def _load_manifest(self, stego_path: Path) -> StegoManifest:
        """Load and parse a stego sidecar manifest."""

        manifest_path = self._manifest_path_for_stego(stego_path)
        if not manifest_path.exists():
            raise FileNotFoundError(
                f"Manifest not found for stego image: {manifest_path}"
            )
        raw = json.loads(manifest_path.read_text(encoding="utf-8"))
        return StegoManifest.from_dict(raw)

    @staticmethod
    def _transformed_filename(*, source_suffix: str, index: int) -> str:
        """Create a deterministic temporary filename for transformed images."""

        suffix = source_suffix if source_suffix else ".bin"
        return f"transform_{index:02d}{suffix}"


def _normalize_output_path(
    *,
    output_path: str | Path | None,
    carrier_format: str,
) -> Path | None:
    """Validate or normalize the requested stego output path."""

    if output_path is None:
        return None

    path = Path(output_path).expanduser()
    normalized_format = _normalize_format(carrier_format)
    expected_suffixes = {".png"} if normalized_format == _PNG_FORMAT else {".jpg", ".jpeg"}
    if path.suffix.lower() not in expected_suffixes:
        raise ValueError(
            f"Output path suffix must match carrier format {normalized_format}: "
            f"expected one of {sorted(expected_suffixes)}, received '{path.suffix}'."
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def _normalize_format(raw_format: str) -> str:
    """Normalize an image format label into PNG or JPEG."""

    normalized = raw_format.strip().upper()
    if normalized == "JPG":
        return _JPEG_FORMAT
    if normalized not in _SUPPORTED_FORMATS:
        raise ValueError(f"Unsupported image format: {raw_format}")
    return normalized


def _normalize_transform_list(
    transforms: Sequence[str] | None,
) -> list[str]:
    """Normalize a transform list into a de-duplicated ordered list."""

    if transforms is None:
        return []
    seen: set[str] = set()
    normalized: list[str] = []
    for value in transforms:
        stripped = value.strip().lower()
        if stripped and stripped not in seen:
            seen.add(stripped)
            normalized.append(stripped)
    return normalized


def _json_safe_config(config: Mapping[str, Any]) -> dict[str, Any]:
    """Convert runtime-only values into JSON-serializable equivalents."""

    safe: dict[str, Any] = {}
    for key, value in config.items():
        if isinstance(value, type):
            safe[key] = value.__name__
        elif isinstance(value, dict):
            safe[key] = dict(value)
        elif isinstance(value, list):
            safe[key] = list(value)
        else:
            safe[key] = value
    return safe


def _sha256_hex(data: bytes) -> str:
    """Return the SHA-256 digest of a byte string as hex."""

    return hashlib.sha256(data).hexdigest()


def _proxy_detector_score(reference_cover: np.ndarray, candidate_image: np.ndarray) -> float:
    """Simple deterministic proxy detector score based on absolute difference."""

    if reference_cover.shape != candidate_image.shape:
        raise ValueError("Proxy detector requires shape-matched images.")
    diff = np.abs(
        reference_cover.astype(np.float32, copy=False)
        - candidate_image.astype(np.float32, copy=False)
    )
    return float(np.mean(diff) / 255.0)


def _format_transform_label(spec: TransformSpec) -> str:
    """Render a compact human-readable transform label."""

    if not spec.params:
        return spec.name
    items = ", ".join(f"{key}={value}" for key, value in spec.params.items())
    return f"{spec.name}({items})"


def _require_non_empty_str(mapping: Mapping[str, Any], *, key: str) -> str:
    """Require a non-empty string value from a mapping."""

    value = mapping.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Manifest field '{key}' must be a non-empty string.")
    return value


def _require_int(
    mapping: Mapping[str, Any],
    *,
    key: str,
    minimum: int,
) -> int:
    """Require an integer value from a mapping."""

    value = mapping.get(key)
    if not isinstance(value, int):
        raise ValueError(f"Manifest field '{key}' must be an integer.")
    if value < minimum:
        raise ValueError(f"Manifest field '{key}' must be >= {minimum}.")
    return value


def _require_dict(mapping: Mapping[str, Any], *, key: str) -> dict[str, Any]:
    """Require a dict value from a mapping."""

    value = mapping.get(key)
    if not isinstance(value, dict):
        raise ValueError(f"Manifest field '{key}' must be a JSON object.")
    return dict(value)


def _require_str_list(mapping: Mapping[str, Any], *, key: str) -> list[str]:
    """Require a list of strings from a mapping."""

    value = mapping.get(key)
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"Manifest field '{key}' must be a list of strings.")
    return list(value)


def _ensure_non_empty_password(password: str) -> None:
    """Reject empty passwords before cryptographic processing begins."""

    if not password:
        raise ValueError("Password must not be empty.")


def _parse_expected_transforms(value: str) -> list[str]:
    """Parse a comma-separated expected-transform list."""

    if not value.strip():
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def _read_payload_bytes(
    *,
    payload_file: Path | None,
    payload_string: str | None,
) -> bytes:
    """Resolve CLI payload input into bytes."""

    if payload_file is not None and payload_string is not None:
        raise typer.BadParameter("Use either --payload-file or --payload-string, not both.")
    if payload_file is not None:
        return payload_file.expanduser().read_bytes()
    if payload_string is not None:
        return payload_string.encode("utf-8")
    raise typer.BadParameter("Provide either --payload-file or --payload-string.")


def _read_password(*, password_stdin: bool) -> str:
    """Read a password interactively or from stdin for automation."""

    if password_stdin:
        password = sys.stdin.readline().rstrip("\r\n")
    else:
        password = getpass.getpass("Password: ")
    _ensure_non_empty_password(password)
    return password


def configure_logging(
    *,
    log_file: Path = _DEFAULT_AUDIT_LOG,
    verbose: bool = False,
) -> None:
    """Configure colored console logging and an audit log file."""

    log_path = log_file.expanduser()
    log_path.parent.mkdir(parents=True, exist_ok=True)
    level = logging.DEBUG if verbose else logging.INFO

    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setFormatter(
        logging.Formatter(
            "%(asctime)sZ %(levelname)s %(name)s :: %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S",
        )
    )

    rich_handler = RichHandler(
        console=console,
        rich_tracebacks=True,
        show_path=False,
        markup=True,
    )
    logging.basicConfig(
        level=level,
        format="%(message)s",
        handlers=[rich_handler, file_handler],
        force=True,
    )
    logger.info("Audit log initialized at %s", log_path.resolve())


def _log_success(message: str, *args: object) -> None:
    """Write a success-level audit log entry."""

    logger.log(_SUCCESS_LEVEL, message, *args)


def _render_trace_table(trace: Sequence[str]) -> Table:
    """Render selector justification as a Rich table."""

    table = Table(title="Selector Justification Trace", show_lines=True)
    table.add_column("#", justify="right", style="cyan", no_wrap=True)
    table.add_column("Rule Decision", style="white")
    for index, line in enumerate(trace, start=1):
        table.add_row(str(index), line)
    return table


def _render_quality_table(report: Mapping[str, Any]) -> Table:
    """Render visual quality metrics."""

    quality = _require_dict(report, key="quality_metrics")
    table = Table(title="Visual Imperceptibility")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", justify="right", style="green")
    table.add_row("SSIM", f"{float(quality['ssim']):.6f}")
    table.add_row("PSNR", f"{float(quality['psnr']):.2f} dB")
    table.add_row("MSE", f"{float(quality['mse']):.6f}")
    return table


def _render_steganalysis_table(report: Mapping[str, Any]) -> Table:
    """Render ROC/AUC and resistance-score metrics."""

    detectability = _require_dict(report, key="detectability")
    resistance = _require_dict(report, key="resistance_score")
    final_score = float(resistance["final_score"])
    status = classify_resistance_score(final_score)
    table = Table(title="Steganalysis Results")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", justify="right", style="green")
    table.add_row("Detector", str(detectability.get("detector_name", "unknown")))
    if "classifier" in detectability:
        table.add_row("Classifier", str(detectability["classifier"]))
    if "feature_count" in detectability:
        table.add_row("Feature Count", f"{int(detectability['feature_count']):,}")
    if "train_sample_count" in detectability and "test_sample_count" in detectability:
        table.add_row(
            "Train/Test Samples",
            f"{int(detectability['train_sample_count'])}/{int(detectability['test_sample_count'])}",
        )
    table.add_row("ROC AUC", f"{float(detectability['roc_auc']):.6f}")
    table.add_row("TPR @ 1.0% FPR", f"{float(detectability['tpr_at_1_fpr']):.6f}")
    table.add_row("TPR @ 0.1% FPR", f"{float(detectability['tpr_at_0_1_fpr']):.6f}")
    table.add_row("Resistance Score", f"{final_score:.2f} / 100")
    table.add_row("Security Status", f"[{status['rich_color']}]{status['label']}[/{status['rich_color']}]")
    return table


def classify_resistance_score(score: float) -> dict[str, str]:
    """Classify a resistance score for perceptible security feedback."""

    if score >= 75.0:
        return {
            "label": "High Resistance",
            "rich_color": "green",
            "gui_color": "#2e7d32",
            "description": "Stego output shows strong measured resistance.",
        }
    if score >= 50.0:
        return {
            "label": "Moderate",
            "rich_color": "yellow",
            "gui_color": "#b7791f",
            "description": "Stego output is usable but has visible evaluation risks.",
        }
    return {
        "label": "High Risk",
        "rich_color": "red",
        "gui_color": "#b91c1c",
        "description": "Evaluation indicates high detectability or poor robustness.",
    }


def _render_robustness_table(report: Mapping[str, Any]) -> Table:
    """Render transformation-survival results."""

    robustness = _require_dict(report, key="robustness")
    transform_results = robustness.get("transform_results", [])
    table = Table(title="Transformation Robustness", show_lines=True)
    table.add_column("Transform", style="cyan")
    table.add_column("Outcome", style="white")
    table.add_column("Status", style="green")
    table.add_column("Details", style="dim")
    if not isinstance(transform_results, list):
        return table
    for result in transform_results:
        if not isinstance(result, dict):
            continue
        spec = TransformSpec(
            name=str(result.get("transform", "unknown")),
            params=dict(result.get("parameters", {}))
            if isinstance(result.get("parameters", {}), dict)
            else {},
        )
        outcome = "PASS" if bool(result.get("success", False)) else "FAIL-CLOSED"
        detail = result.get("failure_reason") or result.get("error") or ""
        table.add_row(
            _format_transform_label(spec),
            outcome,
            str(result.get("security_status", "")),
            str(detail),
        )
    return table


def _render_carrier_analysis_table(analysis: Mapping[str, Any]) -> Table:
    """Render carrier metadata and capacity before embedding."""

    table = Table(title="Carrier Analysis Dashboard")
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="green")
    table.add_row("Path", str(analysis["path"]))
    table.add_row("Format", str(analysis["format"]))
    table.add_row("Dimensions", f"{analysis.get('width')} x {analysis.get('height')}")
    table.add_row("Channels", str(analysis.get("channels")))
    table.add_row("Steganographic Capacity", f"{int(analysis['capacity_bits']):,} bits ({int(analysis['capacity_bytes']):,} bytes)")
    if "robust_capacity_bits" in analysis:
        table.add_row(
            "Robust JPEG Capacity",
            f"{int(analysis['robust_capacity_bits']):,} bits ({int(analysis['robust_capacity_bytes']):,} bytes)",
        )
    return table


def _render_pipeline_table(completed: Sequence[str], active: str | None = None) -> Table:
    """Render the FYP W1-W8 execution pipeline as a Rich table."""

    stages = (
        ("W1", "Dataset / carrier load"),
        ("W2", "Payload security"),
        ("W3", "Payload sizing / logging"),
        ("W4", "PNG/JPEG embed"),
        ("W5", "Transform / recompress"),
        ("W6", "Extract + decrypt / verify"),
        ("W7", "Steganalysis"),
        ("W8", "Metrics + reporting"),
    )
    completed_set = set(completed)
    table = Table(title="FYP Research Pipeline Trace")
    table.add_column("Stage", style="cyan", no_wrap=True)
    table.add_column("Pipeline Step")
    table.add_column("Status", justify="center")
    for stage_id, label in stages:
        if stage_id == active:
            status = "[blue]RUNNING[/blue]"
        elif stage_id in completed_set:
            status = "[green]DONE[/green]"
        else:
            status = "[dim]PENDING[/dim]"
        table.add_row(stage_id, label, status)
    return table


def _render_crypto_assurance_panel() -> Panel:
    """Render the mandatory payload-protection chain."""

    return Panel.fit(
        "[cyan]Password[/cyan] -> [green]Argon2id memory-hard KDF[/green] -> "
        "[green]AES-GCM authenticated encryption[/green] -> [cyan]Stego embedding[/cyan]\n"
        "[dim]Plaintext payloads are never embedded directly; authentication failure is fail-closed.[/dim]",
        title="Crypto Assurance",
        border_style="green",
    )


def _render_embedding_audit_table(result: Mapping[str, Any]) -> Table:
    """Render reproducibility metadata for an embedding run."""

    selected_config = _require_dict(result, key="selected_config")
    table = Table(title="Embedding Audit Artifact")
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="green")
    table.add_row("Cover", str(result.get("cover_path", "")))
    table.add_row("Stego", str(result.get("stego_path", "")))
    table.add_row("Manifest", str(result.get("manifest_path", "")))
    table.add_row("Engine", str(selected_config.get("engine_name", "unknown")))
    table.add_row("Carrier Format", str(selected_config.get("carrier_format", "unknown")))
    table.add_row("Embedded Payload", f"{int(result.get('embedded_payload_bits', 0)):,} bits")
    table.add_row("Crypto Policy", "Argon2id + AES-GCM mandatory")
    return table


def _render_evaluation_reproducibility_table(report: Mapping[str, Any]) -> Table:
    """Render evaluation metadata linked to the FYP reporting protocol."""

    detectability = _require_dict(report, key="detectability")
    resistance = _require_dict(report, key="resistance_score")
    quality = _require_dict(report, key="quality_metrics")
    table = Table(title="Evaluation Reproducibility Snapshot")
    table.add_column("Protocol Item", style="cyan")
    table.add_column("Recorded Value", style="green")
    table.add_row("Carrier Format", str(report.get("carrier_format", "unknown")))
    table.add_row("PSNR", f"{float(quality['psnr']):.2f} dB")
    table.add_row("SSIM", f"{float(quality['ssim']):.6f}")
    table.add_row("Detector", str(detectability.get("detector_name", "unknown")))
    table.add_row("ROC AUC", f"{float(detectability['roc_auc']):.6f}")
    table.add_row("Resistance Score", f"{float(resistance['final_score']):.2f} / 100")
    table.add_row("Safe Failure Policy", "AEAD authentication required before release")
    return table


def _write_json_report(report: Mapping[str, Any] | Sequence[Mapping[str, Any]], path: Path) -> None:
    """Persist a JSON evaluation artifact."""

    destination = path.expanduser()
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(report, indent=2), encoding="utf-8")
    _log_success("JSON report written to %s", destination.resolve())


def _handle_cli_error(exc: Exception) -> None:
    """Render and log a controlled CLI error."""

    if isinstance(exc, AuthenticationError):
        logger.error("Authentication failed: %s", exc)
        console.print(f"[bold red]Authentication failed:[/bold red] {exc}")
    elif isinstance(exc, CapacityError):
        logger.error("Carrier capacity exceeded: %s", exc)
        console.print(f"[bold red]Carrier capacity exceeded:[/bold red] {exc}")
    else:
        logger.error("Operation failed: %s", exc)
        console.print(f"[bold red]Error:[/bold red] {exc}")


def _progress() -> Progress:
    """Create the standard Rich progress renderer."""

    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
    )


def _load_batch_pairs(path: Path) -> list[tuple[Path, Path]]:
    """Load batch evaluation cover/stego pairs from JSON."""

    raw = json.loads(path.expanduser().read_text(encoding="utf-8-sig"))
    if not isinstance(raw, list):
        raise ValueError("Batch pairs JSON must contain a list of objects.")

    pairs: list[tuple[Path, Path]] = []
    for index, item in enumerate(raw, start=1):
        if not isinstance(item, dict):
            raise ValueError(f"Batch pair #{index} must be a JSON object.")
        cover = item.get("cover")
        stego = item.get("stego")
        if not isinstance(cover, str) or not isinstance(stego, str):
            raise ValueError(f"Batch pair #{index} must include string 'cover' and 'stego' fields.")
        pairs.append((Path(cover).expanduser(), Path(stego).expanduser()))
    return pairs


@app.command("analyze-carrier")
def analyze_carrier(
    carrier: Path = typer.Option(
        ...,
        "--carrier",
        exists=True,
        dir_okay=False,
        readable=True,
        help="PNG or JPEG carrier image to inspect before embedding.",
    ),
    log_file: Path = typer.Option(
        _DEFAULT_AUDIT_LOG,
        "--log-file",
        help="Audit log path.",
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable debug logging."),
) -> None:
    """Preview carrier metadata and steganographic capacity."""

    configure_logging(log_file=log_file, verbose=verbose)
    try:
        analysis = StegoToolkit().analyze_carrier(carrier)
        console.print(_render_carrier_analysis_table(analysis))
        logger.info(
            "Carrier analysis completed for %s with capacity=%s bits.",
            analysis["path"],
            analysis["capacity_bits"],
        )
    except (FileNotFoundError, MissingDependencyError, ValueError, RuntimeError) as exc:
        _handle_cli_error(exc)
        raise typer.Exit(1) from exc


@app.command()
def embed(
    cover: Path = typer.Option(
        ...,
        "--cover",
        exists=True,
        dir_okay=False,
        readable=True,
        help="PNG or JPEG carrier image.",
    ),
    payload_file: Optional[Path] = typer.Option(
        None,
        "--payload-file",
        exists=True,
        dir_okay=False,
        readable=True,
        help="File containing payload bytes.",
    ),
    payload_string: Optional[str] = typer.Option(
        None,
        "--payload-string",
        help="UTF-8 string payload for quick tests.",
    ),
    output: Path = typer.Option(
        ...,
        "--output",
        help="Destination stego image path.",
    ),
    expected_transforms: str = typer.Option(
        "",
        "--expected-transforms",
        help="Comma-separated expected transforms, e.g. jpeg_recompression,noise.",
    ),
    log_file: Path = typer.Option(
        _DEFAULT_AUDIT_LOG,
        "--log-file",
        help="Audit log path.",
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable debug logging."),
    password_stdin: bool = typer.Option(
        False,
        "--password-stdin",
        help="Read the password from stdin for automation without exposing it as an argument.",
    ),
) -> None:
    """Encrypt a payload, select an engine, embed it, and write a manifest."""

    configure_logging(log_file=log_file, verbose=verbose)
    try:
        payload_bytes = _read_payload_bytes(
            payload_file=payload_file,
            payload_string=payload_string,
        )
        password = _read_password(password_stdin=password_stdin)
        toolkit = StegoToolkit()
        with _progress() as progress:
            task = progress.add_task("Encrypting and embedding payload", total=1)
            result = toolkit.protect_and_embed(
                cover_path=cover,
                payload_bytes=payload_bytes,
                password=password,
                expected_transforms=_parse_expected_transforms(expected_transforms),
                output_path=output,
            )
            progress.advance(task)

        _log_success("Stego image written to %s", result["stego_path"])
        console.print(_render_pipeline_table(["W1", "W2", "W3", "W4", "W6"], active="W7"))
        console.print(_render_crypto_assurance_panel())
        console.print(
            render_policy_log(
                selected_config=result["selected_config"],
                justification_trace=result["justification_trace"],
            )
        )
        console.print(_render_embedding_audit_table(result))
        console.print(
            Panel.fit(
                f"[green]Stego image:[/green] {result['stego_path']}\n"
                f"[green]Manifest:[/green] {result['manifest_path']}",
                title="Embed Complete",
                border_style="green",
            )
        )
    except (AuthenticationError, CapacityError, FileNotFoundError, MissingDependencyError, ValueError, RuntimeError) as exc:
        _handle_cli_error(exc)
        raise typer.Exit(1) from exc


@app.command()
def extract(
    stego: Path = typer.Option(
        ...,
        "--stego",
        exists=True,
        dir_okay=False,
        readable=True,
        help="Stego image with a neighboring manifest file.",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        help="Optional destination for recovered payload bytes.",
    ),
    log_file: Path = typer.Option(
        _DEFAULT_AUDIT_LOG,
        "--log-file",
        help="Audit log path.",
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable debug logging."),
    password_stdin: bool = typer.Option(
        False,
        "--password-stdin",
        help="Read the password from stdin for automation without exposing it as an argument.",
    ),
) -> None:
    """Extract and authenticate a payload."""

    configure_logging(log_file=log_file, verbose=verbose)
    try:
        password = _read_password(password_stdin=password_stdin)
        payload = StegoToolkit().extract_and_verify(stego, password)
        if output is not None:
            destination = output.expanduser()
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(payload)
            _log_success("Extracted payload written to %s", destination.resolve())
            console.print(f"[green]Extracted payload written to:[/green] {destination.resolve()}")
            return
        sys.stdout.buffer.write(payload)
        sys.stdout.buffer.flush()
    except (AuthenticationError, IntegrityError, CapacityError, FileNotFoundError, MissingDependencyError, ValueError, RuntimeError) as exc:
        _handle_cli_error(exc)
        raise typer.Exit(1) from exc


@app.command("audit-manifest")
def audit_manifest(
    stego: Path = typer.Option(
        ...,
        "--stego",
        exists=True,
        dir_okay=False,
        readable=True,
        help="Stego image with a neighboring manifest file.",
    ),
    log_file: Path = typer.Option(
        _DEFAULT_AUDIT_LOG,
        "--log-file",
        help="Audit log path.",
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable debug logging."),
) -> None:
    """Inspect non-secret manifest metadata and selector reasoning."""

    configure_logging(log_file=log_file, verbose=verbose)
    try:
        toolkit = StegoToolkit()
        manifest = toolkit._load_manifest(stego.expanduser().resolve())
        table = Table(title="Manifest Audit Record", show_lines=True)
        table.add_column("Field", style="cyan")
        table.add_column("Value", style="green")
        table.add_row("Version", str(manifest.version))
        table.add_row("Created UTC", manifest.created_utc)
        table.add_row("Carrier Format", manifest.carrier_format)
        table.add_row("Engine", manifest.engine_name)
        table.add_row("Seed", manifest.seed)
        table.add_row("Embedded Payload", f"{manifest.embedded_payload_bits:,} bits")
        table.add_row("Ciphertext SHA-256", manifest.encrypted_envelope_sha256)
        table.add_row("Expected Transforms", ", ".join(manifest.expected_transforms) or "none")
        table.add_row("Manifest Path", str(toolkit._manifest_path_for_stego(stego).resolve()))
        console.print(_render_pipeline_table(["W1", "W2", "W3", "W4", "W6"]))
        console.print(_render_crypto_assurance_panel())
        console.print(table)
        console.print(
            render_policy_log(
                selected_config=manifest.selected_config,
                justification_trace=manifest.justification_trace,
            )
        )
    except (FileNotFoundError, MissingDependencyError, ValueError, RuntimeError) as exc:
        _handle_cli_error(exc)
        raise typer.Exit(1) from exc


@app.command()
def evaluate(
    cover: Path = typer.Option(
        ...,
        "--cover",
        exists=True,
        dir_okay=False,
        readable=True,
        help="Original cover image.",
    ),
    stego: Path = typer.Option(
        ...,
        "--stego",
        exists=True,
        dir_okay=False,
        readable=True,
        help="Stego image.",
    ),
    json_output: Optional[Path] = typer.Option(
        None,
        "--json-output",
        help="Optional JSON report destination.",
    ),
    markdown_output: Optional[Path] = typer.Option(
        Path("report.md"),
        "--markdown-output",
        help="Markdown academic report destination.",
    ),
    log_file: Path = typer.Option(
        _DEFAULT_AUDIT_LOG,
        "--log-file",
        help="Audit log path.",
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable debug logging."),
) -> None:
    """Run quality, robustness, steganalysis, and resistance-score reporting."""

    configure_logging(log_file=log_file, verbose=verbose)
    try:
        with _progress() as progress:
            task = progress.add_task("Running evaluation protocol", total=1)
            report = StegoToolkit().run_evaluation(cover, stego)
            progress.advance(task)

        console.print(_render_quality_table(report))
        console.print(_render_robustness_table(report))
        console.print(_render_steganalysis_table(report))
        console.print(_render_evaluation_reproducibility_table(report))
        console.print(_render_pipeline_table(["W1", "W2", "W3", "W4", "W5", "W6", "W7", "W8"]))
        if json_output is not None:
            _write_json_report(report, json_output)
            console.print(f"[green]JSON report written to:[/green] {json_output.expanduser().resolve()}")
        if markdown_output is not None:
            report_path = StegoToolkit().evaluator.write_markdown_report(report, markdown_output)
            _log_success("Markdown report written to %s", report_path.resolve())
            console.print(f"[green]Markdown report written to:[/green] {report_path.resolve()}")
    except (AuthenticationError, IntegrityError, CapacityError, FileNotFoundError, MissingDependencyError, ValueError, RuntimeError) as exc:
        _handle_cli_error(exc)
        raise typer.Exit(1) from exc


@app.command("batch-evaluate")
def batch_evaluate(
    pairs_json: Path = typer.Option(
        ...,
        "--pairs-json",
        exists=True,
        dir_okay=False,
        readable=True,
        help="JSON list of {'cover': '...', 'stego': '...'} pairs.",
    ),
    json_output: Optional[Path] = typer.Option(
        None,
        "--json-output",
        help="Optional JSON report destination.",
    ),
    max_workers: int = typer.Option(
        4,
        "--max-workers",
        min=1,
        help="Concurrent workers for batch evaluation.",
    ),
    log_file: Path = typer.Option(
        _DEFAULT_AUDIT_LOG,
        "--log-file",
        help="Audit log path.",
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable debug logging."),
) -> None:
    """Evaluate many cover/stego pairs with a Rich progress bar."""

    configure_logging(log_file=log_file, verbose=verbose)
    try:
        pairs = _load_batch_pairs(pairs_json)
        reports: list[dict[str, Any]] = []
        with _progress() as progress:
            task = progress.add_task("Evaluating batch", total=len(pairs))
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {
                    executor.submit(StegoToolkit().run_evaluation, cover, stego): (cover, stego)
                    for cover, stego in pairs
                }
                for future in as_completed(futures):
                    cover_path, stego_path = futures[future]
                    report = future.result()
                    reports.append(report)
                    progress.advance(task)
                    logger.info("Evaluated pair cover=%s stego=%s", cover_path, stego_path)

        summary = Table(title="Batch Evaluation Summary")
        summary.add_column("#", justify="right", style="cyan")
        summary.add_column("Carrier")
        summary.add_column("ROC AUC", justify="right")
        summary.add_column("Resistance", justify="right")
        for index, report in enumerate(reports, start=1):
            detectability = _require_dict(report, key="detectability")
            resistance = _require_dict(report, key="resistance_score")
            summary.add_row(
                str(index),
                str(report["carrier_format"]),
                f"{float(detectability['roc_auc']):.6f}",
                f"{float(resistance['final_score']):.2f}",
            )
        console.print(summary)
        if json_output is not None:
            _write_json_report(reports, json_output)
            console.print(f"[green]Batch JSON report written to:[/green] {json_output.expanduser().resolve()}")
    except (AuthenticationError, IntegrityError, CapacityError, FileNotFoundError, MissingDependencyError, ValueError, RuntimeError) as exc:
        _handle_cli_error(exc)
        raise typer.Exit(1) from exc


def _format_evaluation_summary(report: Mapping[str, Any]) -> str:
    """Render a human-readable markdown-style evaluation summary."""

    quality = _require_dict(report, key="quality_metrics")
    robustness = _require_dict(report, key="robustness")
    detectability = _require_dict(report, key="detectability")
    resistance = _require_dict(report, key="resistance_score")

    transform_results = robustness.get("transform_results", [])
    if not isinstance(transform_results, list):
        raise ValueError("Evaluation report field 'transform_results' must be a list.")

    survived = int(robustness["successful_extractions"])
    attempted = int(robustness["total_attempted_transforms"])
    survival_rate = float(robustness.get("survival_rate", survived / attempted if attempted else 0.0))

    jpeg_results = [
        result for result in transform_results
        if isinstance(result, dict) and result.get("transform") == "jpeg_recompression"
    ]
    severe_results = [
        result for result in transform_results
        if isinstance(result, dict) and result.get("transform") in {"resize", "crop", "noise"}
    ]

    lines = [
        "# Secure Adaptive Image Steganography Evaluation Report",
        "",
        f"- Cover Image: {report['cover_path']}",
        f"- Stego Image: {report['stego_path']}",
        f"- Carrier Format: {report['carrier_format']}",
        "",
        "## Visual Imperceptibility",
        f"- SSIM: {float(quality['ssim']):.6f}",
        f"- PSNR: {float(quality['psnr']):.2f} dB",
        "",
        "## Robustness",
        f"- Survival Rate: Survived {survived}/{attempted} transforms ({survival_rate * 100.0:.1f}%).",
        "- Primary Operational Goal: Survival under JPEG recompression is the intended robustness target for this toolkit.",
        "- Secure Degradation Policy: Resize, crop, and severe-noise scenarios are expected to trigger secure fail-closed behavior rather than unauthenticated recovery.",
    ]

    if jpeg_results:
        lines.extend(
            [
                "",
                "### JPEG Recompression Results",
            ]
        )
        for result in jpeg_results:
            lines.append(f"- {_format_transform_result_line(result)}")

    if severe_results:
        lines.extend(
            [
                "",
                "### Geometric / Severe Degradation Results",
            ]
        )
        for result in severe_results:
            lines.append(f"- {_format_transform_result_line(result)}")

    lines.extend(
        [
            "",
            "## Detectability",
            f"- ROC AUC: {float(detectability['roc_auc']):.6f}",
            f"- Operational Detection Rate (TPR @ 1.0% FPR): {float(detectability['tpr_at_1_fpr']):.6f}",
            f"- Operational Detection Rate (TPR @ 0.1% FPR): {float(detectability['tpr_at_0_1_fpr']):.6f}",
            "",
            "## Unified Resistance Score",
            f"- Final Score: {float(resistance['final_score']):.2f} / 100",
        ]
    )
    return "\n".join(lines)


def _format_transform_result_line(result: Mapping[str, Any]) -> str:
    """Render a compact one-line robustness result."""

    spec = TransformSpec(
        name=str(result.get("transform", "unknown")),
        params=dict(result.get("parameters", {})) if isinstance(result.get("parameters", {}), dict) else {},
    )
    outcome = "PASS" if bool(result.get("success", False)) else "FAIL-CLOSED"
    security_status = str(result.get("security_status", _SECURE_FAIL_CLOSED_STATUS))
    reason = result.get("failure_reason") or result.get("error")
    suffix = f" | {reason}" if isinstance(reason, str) and reason.strip() else ""
    return f"{_format_transform_label(spec)} -> {outcome} | {security_status}{suffix}"


def main(argv: Sequence[str] | None = None) -> int:
    """Typer CLI entry point used by console scripts and direct execution."""

    app(args=list(argv) if argv is not None else None)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
