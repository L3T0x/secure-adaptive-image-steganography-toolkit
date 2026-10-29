"""Evaluation and steganalysis harness for the steganography toolkit.

This module provides:

1. Controlled image post-processing transformations.
2. Visual quality metrics for cover/stego comparison.
3. Detectability metrics for external steganalysis detectors.
4. A bounded unified resistance score that aggregates quality, robustness,
   and evasion behavior.

The harness is designed for offline, reproducible experimentation and audit
workflows. It operates on in-memory image arrays and detector outputs so it can
be integrated into both CLI and Python API flows.
"""

from __future__ import annotations

from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass
import json
import math
from numbers import Integral, Real
from pathlib import Path
from typing import Any, Callable, Final, Mapping, Sequence, TypeAlias

import cv2
import numpy as np
from numpy.typing import NDArray
from skimage.metrics import (
    mean_squared_error,
    peak_signal_noise_ratio,
    structural_similarity,
)
from sklearn.metrics import confusion_matrix, roc_auc_score, roc_curve

ImageArray: TypeAlias = NDArray[np.generic]

_DEFAULT_JPEG_QUALITY: Final[int] = 85
_DEFAULT_NOISE_MEAN: Final[float] = 0.0
_DEFAULT_NOISE_VARIANCE: Final[float] = 0.01
_DEFAULT_RESIZE_SCALE: Final[float] = 0.5
_DEFAULT_CROP_FRACTION: Final[float] = 0.8
_RANDOM_BASELINE_AUC: Final[float] = 0.5


@dataclass(frozen=True, slots=True)
class EvaluationHarness:
    """Evaluation toolkit for transforms, quality, detectability, and scoring."""

    default_noise_mean: float = _DEFAULT_NOISE_MEAN
    default_noise_variance: float = _DEFAULT_NOISE_VARIANCE

    def transform_image(
        self,
        image: ImageArray,
        transformation: str,
        **kwargs: Any,
    ) -> NDArray[np.uint8]:
        """Apply a controlled post-processing transformation to an image array.

        Supported transformations:

        - ``"jpeg_recompression"``: JPEG round-trip at a configurable quality.
        - ``"resize"``: Downscale to 50%, then upscale back using bicubic.
        - ``"crop"``: Keep the center 80% and pad back to original size.
        - ``"noise"``: Add Gaussian noise in normalized [0, 1] space.

        Args:
            image: Input image array. Expected to be grayscale or channel-last.
            transformation: Transformation name.
            **kwargs: Optional transformation-specific parameters.

        Keyword Args:
            jpeg_quality: JPEG quality factor for recompression.
            resize_scale: Downscale factor for resize.
            crop_fraction: Fraction of the image retained in the center crop.
            noise_mean: Gaussian noise mean in normalized [0, 1] space.
            noise_variance: Gaussian noise variance in normalized [0, 1] space.
            noise_seed: Optional deterministic seed for noise generation.

        Returns:
            Transformed image as ``uint8`` with the same shape as the input
            when the transformation semantics allow it.
        """

        normalized = transformation.strip().lower()
        source = _ensure_uint8_image(image)

        if normalized == "jpeg_recompression":
            jpeg_quality = _validate_jpeg_quality(
                kwargs.get("jpeg_quality", kwargs.get("qf", _DEFAULT_JPEG_QUALITY))
            )
            return self._jpeg_recompress(source, jpeg_quality=jpeg_quality)

        if normalized == "resize":
            resize_scale = _validate_fraction(
                kwargs.get("resize_scale", _DEFAULT_RESIZE_SCALE),
                field_name="resize_scale",
            )
            return self._resize_roundtrip(source, resize_scale=resize_scale)

        if normalized == "crop":
            crop_fraction = _validate_fraction(
                kwargs.get("crop_fraction", _DEFAULT_CROP_FRACTION),
                field_name="crop_fraction",
            )
            return self._center_crop_and_pad(source, crop_fraction=crop_fraction)

        if normalized == "noise":
            noise_mean = float(kwargs.get("noise_mean", self.default_noise_mean))
            noise_variance = _validate_non_negative_real(
                kwargs.get("noise_variance", self.default_noise_variance),
                field_name="noise_variance",
            )
            noise_seed = kwargs.get("noise_seed")
            return self._add_gaussian_noise(
                source,
                noise_mean=noise_mean,
                noise_variance=noise_variance,
                noise_seed=noise_seed,
            )

        raise ValueError(
            "Unsupported transformation. Expected one of: "
            "'jpeg_recompression', 'resize', 'crop', or 'noise'."
        )

    def calculate_quality(
        self,
        cover_image: ImageArray,
        stego_image: ImageArray,
    ) -> dict[str, float]:
        """Calculate MSE, PSNR, and SSIM for an original/stego image pair."""

        cover, stego = _validate_image_pair(cover_image, stego_image)
        cover_float = cover.astype(np.float64, copy=False)
        stego_float = stego.astype(np.float64, copy=False)
        data_range = _infer_data_range(cover, stego)
        channel_axis = _infer_channel_axis(cover)
        ssim_kwargs: dict[str, Any] = {
            "data_range": data_range,
            "channel_axis": channel_axis,
        }
        win_size = _infer_ssim_win_size(cover.shape)
        if win_size is not None:
            ssim_kwargs["win_size"] = win_size

        mse_value = float(mean_squared_error(cover_float, stego_float))
        psnr_value = float(
            peak_signal_noise_ratio(cover_float, stego_float, data_range=data_range)
        )
        ssim_value = float(
            structural_similarity(cover_float, stego_float, **ssim_kwargs)
        )
        return {
            "mse": mse_value,
            "psnr": psnr_value,
            "ssim": ssim_value,
        }

    def calculate_detectability(
        self,
        y_true: ImageArray | list[int] | tuple[int, ...],
        y_scores: ImageArray | list[float] | tuple[float, ...],
    ) -> dict[str, Any]:
        """Calculate confusion matrix, ROC curve data, AUC, and fixed-FPR TPR."""

        truth = np.asarray(y_true, dtype=np.int64)
        scores = np.asarray(y_scores, dtype=np.float64)
        if truth.ndim != 1 or scores.ndim != 1:
            raise ValueError("y_true and y_scores must be one-dimensional.")
        if truth.shape[0] != scores.shape[0]:
            raise ValueError("y_true and y_scores must have the same length.")
        if truth.shape[0] == 0:
            raise ValueError("y_true and y_scores must not be empty.")
        if not np.isin(truth, np.array([0, 1], dtype=np.int64)).all():
            raise ValueError("y_true must contain only binary labels 0 and 1.")
        if not np.isfinite(scores).all():
            raise ValueError("y_scores must contain only finite numeric values.")
        if np.unique(truth).size != 2:
            raise ValueError("y_true must contain both cover (0) and stego (1) labels.")

        predicted = (scores >= 0.5).astype(np.int64, copy=False)
        matrix = confusion_matrix(truth, predicted, labels=[0, 1])
        roc_auc = float(roc_auc_score(truth, scores))
        fpr, tpr, thresholds = roc_curve(truth, scores)

        return {
            "confusion_matrix": matrix.tolist(),
            "roc_curve": {
                "fpr": fpr.astype(float, copy=False).tolist(),
                "tpr": tpr.astype(float, copy=False).tolist(),
                "thresholds": thresholds.astype(float, copy=False).tolist(),
            },
            "roc_auc": roc_auc,
            "tpr_at_1_fpr": _tpr_at_or_below_fpr(fpr=fpr, tpr=tpr, target_fpr=0.01),
            "tpr_at_0_1_fpr": _tpr_at_or_below_fpr(
                fpr=fpr,
                tpr=tpr,
                target_fpr=0.001,
            ),
        }

    def score_samples_concurrently(
        self,
        samples: Sequence[ImageArray],
        scorer: Callable[[ImageArray], float],
        *,
        max_workers: int | None = None,
    ) -> list[float]:
        """Score image samples concurrently while preserving input order."""

        if not samples:
            return []

        scores: list[float] = [0.0] * len(samples)
        with ProcessPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(scorer, sample): index
                for index, sample in enumerate(samples)
            }
            for future in as_completed(futures):
                index = futures[future]
                score = float(future.result())
                if not math.isfinite(score):
                    raise ValueError("Detector scorer returned a non-finite value.")
                scores[index] = score
        return scores

    def write_markdown_report(
        self,
        report: Mapping[str, Any],
        output_path: str | Path = "report.md",
    ) -> Path:
        """Write a professional Markdown evaluation report.

        The structure mirrors social-media steganography evaluation practice:
        carrier metadata, perceptual quality, transform survival, detector
        behavior, and a compact academic interpretation.
        """

        destination = Path(output_path).expanduser()
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(_render_markdown_report(report), encoding="utf-8")
        return destination

    def calculate_resistance_score(
        self,
        *,
        ssim: float,
        successful_extractions: int,
        total_attempted_transforms: int,
        roc_auc: float,
    ) -> dict[str, float | int]:
        """Aggregate quality, robustness, and evasion into a bounded 0-100 score.

        The component formulas are defined by the project brief:

        - ``Quality_Score = SSIM * 100``
        - ``Robustness_Score = (Successful Extractions / Total Attempted Transforms) * 100``
        - ``Evasion_Score = (1.0 - max(0.5, AUC)) * 200``

        The final score is returned as the arithmetic mean of the three 0-100
        component scores so the overall result remains bounded to 0-100.
        """

        ssim_value = _validate_bounded_real(ssim, field_name="ssim", lower=0.0, upper=1.0)
        auc_value = _validate_bounded_real(
            roc_auc,
            field_name="roc_auc",
            lower=0.0,
            upper=1.0,
        )
        success_count = _validate_non_negative_integral(
            successful_extractions,
            field_name="successful_extractions",
        )
        attempted_count = _validate_positive_integral(
            total_attempted_transforms,
            field_name="total_attempted_transforms",
        )
        if success_count > attempted_count:
            raise ValueError(
                "successful_extractions must be <= total_attempted_transforms."
            )

        quality_score = _clamp(ssim_value * 100.0, 0.0, 100.0)
        robustness_score = _clamp(
            (success_count / attempted_count) * 100.0,
            0.0,
            100.0,
        )
        evasion_score = _clamp(
            (1.0 - max(_RANDOM_BASELINE_AUC, auc_value)) * 200.0,
            0.0,
            100.0,
        )
        final_score = _clamp(
            (quality_score + robustness_score + evasion_score) / 3.0,
            0.0,
            100.0,
        )

        return {
            "quality_score": quality_score,
            "robustness_score": robustness_score,
            "evasion_score": evasion_score,
            "final_score": final_score,
            "raw_ssim": ssim_value,
            "raw_roc_auc": auc_value,
            "successful_extractions": success_count,
            "total_attempted_transforms": attempted_count,
            "extraction_success_rate": success_count / attempted_count,
        }

    @staticmethod
    def _jpeg_recompress(
        image: NDArray[np.uint8],
        *,
        jpeg_quality: int,
    ) -> NDArray[np.uint8]:
        """Apply an in-memory JPEG encode/decode round-trip."""

        base, alpha = _split_alpha(image)
        encoded_input = _rgb_like_to_cv2(base)
        ok, buffer = cv2.imencode(
            ".jpg",
            encoded_input,
            [int(cv2.IMWRITE_JPEG_QUALITY), jpeg_quality],
        )
        if not ok:
            raise RuntimeError("OpenCV JPEG encoding failed.")

        decoded = cv2.imdecode(buffer, cv2.IMREAD_UNCHANGED)
        if decoded is None:
            raise RuntimeError("OpenCV JPEG decoding failed.")

        restored = _cv2_to_rgb_like(decoded, source_channels=base.shape[2] if base.ndim == 3 else 1)
        return _recombine_alpha(restored, alpha)

    @staticmethod
    def _resize_roundtrip(
        image: NDArray[np.uint8],
        *,
        resize_scale: float,
    ) -> NDArray[np.uint8]:
        """Downscale and then upscale an image using bicubic interpolation."""

        height, width = image.shape[:2]
        down_width = max(1, int(round(width * resize_scale)))
        down_height = max(1, int(round(height * resize_scale)))
        downscaled = cv2.resize(
            image,
            (down_width, down_height),
            interpolation=cv2.INTER_CUBIC,
        )
        upscaled = cv2.resize(
            downscaled,
            (width, height),
            interpolation=cv2.INTER_CUBIC,
        )
        return upscaled.astype(np.uint8, copy=False)

    @staticmethod
    def _center_crop_and_pad(
        image: NDArray[np.uint8],
        *,
        crop_fraction: float,
    ) -> NDArray[np.uint8]:
        """Crop the center region and pad back to the original size with black."""

        height, width = image.shape[:2]
        crop_height = max(1, int(round(height * crop_fraction)))
        crop_width = max(1, int(round(width * crop_fraction)))
        top = (height - crop_height) // 2
        left = (width - crop_width) // 2
        cropped = image[top : top + crop_height, left : left + crop_width]

        padded = np.zeros_like(image)
        pad_top = (height - crop_height) // 2
        pad_left = (width - crop_width) // 2
        padded[pad_top : pad_top + crop_height, pad_left : pad_left + crop_width] = cropped
        return padded

    @staticmethod
    def _add_gaussian_noise(
        image: NDArray[np.uint8],
        *,
        noise_mean: float,
        noise_variance: float,
        noise_seed: Any,
    ) -> NDArray[np.uint8]:
        """Add Gaussian noise in normalized [0, 1] space and return uint8 output."""

        sigma = math.sqrt(noise_variance)
        rng = np.random.default_rng(noise_seed)
        normalized = image.astype(np.float32) / 255.0
        noise = rng.normal(
            loc=noise_mean,
            scale=sigma,
            size=image.shape,
        ).astype(np.float32, copy=False)
        noisy = np.clip(normalized + noise, 0.0, 1.0)
        return np.rint(noisy * 255.0).astype(np.uint8)


def _ensure_uint8_image(image: ImageArray) -> NDArray[np.uint8]:
    """Normalize an image array into channel-last uint8 form."""

    array = np.asarray(image)
    if array.ndim not in (2, 3):
        raise ValueError("Image arrays must be 2D grayscale or 3D channel-last.")
    if array.ndim == 3 and array.shape[2] not in (1, 3, 4):
        raise ValueError("Supported channel counts are 1, 3, or 4.")
    if not np.issubdtype(array.dtype, np.number):
        raise TypeError("Image arrays must use a numeric dtype.")

    if np.issubdtype(array.dtype, np.integer):
        info = np.iinfo(array.dtype)
        if info.max == 255 and info.min == 0 and array.dtype == np.uint8:
            return array.copy()
        scaled = array.astype(np.float32)
        scaled = np.clip((scaled - info.min) / max(1.0, info.max - info.min), 0.0, 1.0)
        return np.rint(scaled * 255.0).astype(np.uint8)

    float_array = array.astype(np.float32, copy=False)
    finite = np.isfinite(float_array)
    if not finite.all():
        raise ValueError("Image arrays must not contain NaN or infinite values.")

    max_value = float(np.max(float_array))
    min_value = float(np.min(float_array))
    if 0.0 <= min_value and max_value <= 1.0:
        scaled = float_array
    else:
        dynamic_range = max_value - min_value
        if dynamic_range == 0.0:
            scaled = np.zeros_like(float_array)
        else:
            scaled = (float_array - min_value) / dynamic_range
    return np.rint(np.clip(scaled, 0.0, 1.0) * 255.0).astype(np.uint8)


def _validate_image_pair(
    cover_image: ImageArray,
    stego_image: ImageArray,
) -> tuple[ImageArray, ImageArray]:
    """Validate that two images are shape-compatible for metric comparison."""

    cover = np.asarray(cover_image)
    stego = np.asarray(stego_image)
    if cover.shape != stego.shape:
        raise ValueError(
            f"Image shapes must match for quality metrics: {cover.shape!r} != {stego.shape!r}."
        )
    if cover.ndim not in (2, 3):
        raise ValueError("Images must be 2D or 3D channel-last arrays.")
    if not np.issubdtype(cover.dtype, np.number) or not np.issubdtype(stego.dtype, np.number):
        raise TypeError("Images must have numeric dtypes.")
    return cover, stego


def _infer_data_range(cover_image: ImageArray, stego_image: ImageArray) -> float:
    """Infer an appropriate data range for PSNR and SSIM calculations."""

    if np.issubdtype(cover_image.dtype, np.integer):
        info = np.iinfo(cover_image.dtype)
        return float(info.max - info.min)

    combined_min = min(float(np.min(cover_image)), float(np.min(stego_image)))
    combined_max = max(float(np.max(cover_image)), float(np.max(stego_image)))
    data_range = combined_max - combined_min
    return float(data_range if data_range > 0.0 else 1.0)


def _infer_channel_axis(image: ImageArray) -> int | None:
    """Infer the skimage channel axis for channel-last RGB-like arrays."""

    if image.ndim == 3 and image.shape[2] > 1:
        return -1
    return None


def _infer_ssim_win_size(shape: tuple[int, ...]) -> int | None:
    """Infer a valid SSIM window size for small images."""

    smallest_side = min(shape[0], shape[1])
    if smallest_side >= 7:
        return None
    win_size = smallest_side if smallest_side % 2 == 1 else smallest_side - 1
    if win_size < 3:
        raise ValueError("Images are too small to compute SSIM reliably.")
    return win_size


def _split_alpha(
    image: NDArray[np.uint8],
) -> tuple[NDArray[np.uint8], NDArray[np.uint8] | None]:
    """Split RGB(A) input into base image plus optional alpha plane."""

    if image.ndim == 3 and image.shape[2] == 4:
        return image[:, :, :3], image[:, :, 3:]
    return image, None


def _recombine_alpha(
    base: NDArray[np.uint8],
    alpha: NDArray[np.uint8] | None,
) -> NDArray[np.uint8]:
    """Recombine a base image with an optional alpha plane."""

    if alpha is None:
        return base
    return np.concatenate([base, alpha], axis=2)


def _rgb_like_to_cv2(image: NDArray[np.uint8]) -> NDArray[np.uint8]:
    """Convert channel-last RGB-like data into OpenCV's expected ordering."""

    if image.ndim == 2:
        return image
    if image.shape[2] == 1:
        return image[:, :, 0]
    if image.shape[2] == 3:
        return cv2.cvtColor(image, cv2.COLOR_RGB2BGR)
    raise ValueError("Unsupported base image channel count for OpenCV conversion.")


def _cv2_to_rgb_like(
    image: NDArray[np.uint8],
    *,
    source_channels: int,
) -> NDArray[np.uint8]:
    """Convert OpenCV decode output back into channel-last RGB-like ordering."""

    if source_channels == 1:
        if image.ndim == 3:
            return cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
        return image
    if source_channels == 3:
        if image.ndim == 2:
            return np.stack([image, image, image], axis=-1)
        return cv2.cvtColor(image, cv2.COLOR_BGR2RGB)
    raise ValueError("Unsupported source channel count for RGB-like conversion.")


def _validate_jpeg_quality(value: Any) -> int:
    """Validate JPEG quality factor."""

    if not isinstance(value, Integral):
        raise TypeError("jpeg_quality must be an integer.")
    quality = int(value)
    if not 1 <= quality <= 100:
        raise ValueError("jpeg_quality must be within [1, 100].")
    return quality


def _validate_fraction(value: Any, *, field_name: str) -> float:
    """Validate a fraction within the open interval (0, 1]."""

    return _validate_bounded_real(value, field_name=field_name, lower=0.0, upper=1.0, lower_open=True)


def _validate_non_negative_real(value: Any, *, field_name: str) -> float:
    """Validate a non-negative real value."""

    if not isinstance(value, Real):
        raise TypeError(f"{field_name} must be a real number.")
    normalized = float(value)
    if normalized < 0.0:
        raise ValueError(f"{field_name} must be >= 0.")
    return normalized


def _validate_bounded_real(
    value: Any,
    *,
    field_name: str,
    lower: float,
    upper: float,
    lower_open: bool = False,
) -> float:
    """Validate a bounded real value."""

    if not isinstance(value, Real):
        raise TypeError(f"{field_name} must be a real number.")
    normalized = float(value)
    if not np.isfinite(normalized):
        raise ValueError(f"{field_name} must be finite.")
    lower_valid = normalized > lower if lower_open else normalized >= lower
    if not lower_valid or normalized > upper:
        interval = f"({lower}, {upper}]" if lower_open else f"[{lower}, {upper}]"
        raise ValueError(f"{field_name} must be within {interval}.")
    return normalized


def _validate_non_negative_integral(value: Any, *, field_name: str) -> int:
    """Validate a non-negative integer value."""

    if not isinstance(value, Integral):
        raise TypeError(f"{field_name} must be an integer.")
    normalized = int(value)
    if normalized < 0:
        raise ValueError(f"{field_name} must be >= 0.")
    return normalized


def _validate_positive_integral(value: Any, *, field_name: str) -> int:
    """Validate a strictly positive integer value."""

    normalized = _validate_non_negative_integral(value, field_name=field_name)
    if normalized <= 0:
        raise ValueError(f"{field_name} must be > 0.")
    return normalized


def _tpr_at_or_below_fpr(
    *,
    fpr: NDArray[np.float64],
    tpr: NDArray[np.float64],
    target_fpr: float,
) -> float:
    """Return the maximum TPR where FPR is less than or equal to a target."""

    valid = fpr <= target_fpr
    if not np.any(valid):
        return 0.0
    return float(np.max(tpr[valid]))


def _clamp(value: float, lower: float, upper: float) -> float:
    """Clamp a float value to a closed interval."""

    return float(min(max(value, lower), upper))


def _render_markdown_report(report: Mapping[str, Any]) -> str:
    """Render an academic Markdown report from an evaluation result mapping."""

    quality = _require_mapping(report, "quality_metrics")
    robustness = _require_mapping(report, "robustness")
    detectability = _require_mapping(report, "detectability")
    resistance = _require_mapping(report, "resistance_score")
    carrier_metadata = report.get("carrier_metadata", {})
    selected_config = report.get("selected_config", {})

    transform_results = robustness.get("transform_results", [])
    transform_lines: list[str] = []
    if isinstance(transform_results, list):
        for result in transform_results:
            if not isinstance(result, Mapping):
                continue
            params = result.get("parameters", {})
            param_text = (
                ", ".join(f"{key}={value}" for key, value in params.items())
                if isinstance(params, Mapping) and params
                else "default"
            )
            status = "PASS" if bool(result.get("success", False)) else "FAIL-CLOSED"
            detail = result.get("failure_reason") or result.get("error") or ""
            transform_lines.append(
                f"| {result.get('transform', 'unknown')} | {param_text} | {status} | {detail} |"
            )

    if not transform_lines:
        transform_lines.append("| n/a | n/a | n/a | No transform results recorded. |")

    status_label = _resistance_label(float(resistance["final_score"]))
    confusion = detectability.get("confusion_matrix", [])
    confusion_text = json.dumps(confusion)
    detector_lines = [
        f"| Detector | {detectability.get('detector_name', 'unknown')} |",
    ]
    for key, label in (
        ("feature_family", "Feature family"),
        ("classifier", "Classifier"),
        ("training_protocol", "Training protocol"),
        ("feature_count", "Feature count"),
        ("train_sample_count", "Train samples"),
        ("test_sample_count", "Test samples"),
    ):
        if key in detectability:
            detector_lines.append(f"| {label} | {detectability[key]} |")

    return "\n".join(
        [
            "# Secure Adaptive Image Steganography Evaluation Report",
            "",
            "## Executive Summary",
            "",
            f"- Carrier format: `{report.get('carrier_format', 'unknown')}`",
            f"- Resistance status: **{status_label}**",
            f"- Final resistance score: **{float(resistance['final_score']):.2f} / 100**",
            f"- ROC AUC: **{float(detectability['roc_auc']):.6f}**",
            f"- Transform survival: **{int(robustness['successful_extractions'])}/"
            f"{int(robustness['total_attempted_transforms'])}**",
            "",
            "## Carrier And Embedding Configuration",
            "",
            "| Field | Value |",
            "| --- | --- |",
            *[
                f"| {key} | {value} |"
                for key, value in sorted(_mapping_items(carrier_metadata))
            ],
            *[
                f"| selected.{key} | {value} |"
                for key, value in sorted(_mapping_items(selected_config))
                if key not in {"engine_class", "embed_kwargs"}
            ],
            "",
            "## Perceptual Quality",
            "",
            "| Metric | Value | Interpretation |",
            "| --- | ---: | --- |",
            f"| SSIM | {float(quality['ssim']):.6f} | Structural similarity; closer to 1 is better. |",
            f"| PSNR | {float(quality['psnr']):.2f} dB | Higher values indicate lower visible distortion. |",
            f"| MSE | {float(quality['mse']):.6f} | Lower values indicate lower pixel error. |",
            "",
            "## Transformation Robustness",
            "",
            "| Transform | Parameters | Outcome | Notes |",
            "| --- | --- | --- | --- |",
            *transform_lines,
            "",
            "## Steganalysis Reporting",
            "",
            "| Metric | Value |",
            "| --- | ---: |",
            *detector_lines,
            f"| ROC AUC | {float(detectability['roc_auc']):.6f} |",
            f"| TPR @ 1.0% FPR | {float(detectability['tpr_at_1_fpr']):.6f} |",
            f"| TPR @ 0.1% FPR | {float(detectability['tpr_at_0_1_fpr']):.6f} |",
            f"| Confusion Matrix | `{confusion_text}` |",
            "",
            "## Resistance Score Decomposition",
            "",
            "| Component | Score |",
            "| --- | ---: |",
            f"| Quality | {float(resistance['quality_score']):.2f} |",
            f"| Robustness | {float(resistance['robustness_score']):.2f} |",
            f"| Evasion | {float(resistance['evasion_score']):.2f} |",
            f"| Final | {float(resistance['final_score']):.2f} |",
            "",
            "## Method Note",
            "",
            "This report follows a social-media-style steganography evaluation pattern: "
            "measure perceptual distortion, apply realistic post-processing transforms, "
            "verify authenticated extraction, and report threshold-independent detector "
            "behavior with ROC/AUC. Failures after destructive transforms are classified "
            "as secure fail-closed when the authenticated envelope is not recovered.",
            "",
        ]
    )


def _require_mapping(report: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    """Require a nested mapping from an evaluation report."""

    value = report.get(key)
    if not isinstance(value, Mapping):
        raise ValueError(f"Evaluation report field '{key}' must be a mapping.")
    return value


def _mapping_items(value: Any) -> list[tuple[str, Any]]:
    """Return simple mapping items for Markdown tables."""

    if not isinstance(value, Mapping):
        return []
    return [(str(key), item) for key, item in value.items() if _is_markdown_scalar(item)]


def _is_markdown_scalar(value: Any) -> bool:
    """Return whether a value is compact enough for an inline Markdown cell."""

    return isinstance(value, (str, int, float, bool)) or value is None


def _resistance_label(score: float) -> str:
    """Classify resistance using perceptible security-status thresholds."""

    if score >= 75.0:
        return "High Resistance"
    if score >= 50.0:
        return "Moderate Resistance"
    return "High Risk"


if __name__ == "__main__":
    harness = EvaluationHarness()
    rng = np.random.default_rng(20260504)

    y_true = np.array([0] * 50 + [1] * 50, dtype=np.int64)
    cover_scores = np.clip(rng.normal(loc=0.45, scale=0.12, size=50), 0.0, 1.0)
    stego_scores = np.clip(rng.normal(loc=0.55, scale=0.12, size=50), 0.0, 1.0)
    y_scores = np.concatenate([cover_scores, stego_scores]).astype(np.float64)

    detectability = harness.calculate_detectability(y_true=y_true, y_scores=y_scores)
    resistance = harness.calculate_resistance_score(
        ssim=0.98,
        successful_extractions=3,
        total_attempted_transforms=4,
        roc_auc=float(detectability["roc_auc"]),
    )

    print("Detectability Report:")
    print(json.dumps(detectability, indent=2))
    print()
    print("Resistance Score:")
    print(json.dumps(resistance, indent=2))
