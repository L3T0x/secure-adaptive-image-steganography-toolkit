"""Feature-based steganalysis baseline with an ensemble classifier.

The detector implemented here is intentionally local and reproducible. It uses
high-pass residual histograms, residual co-occurrences, and block-DCT magnitude
histograms as a rich statistical feature family, then trains an Extra Trees
ensemble with a deterministic stratified patch split.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping, Sequence

import cv2
import numpy as np
from numpy.typing import NDArray
from sklearn.ensemble import ExtraTreesClassifier

ImageArray = NDArray[np.generic]

_RESIDUAL_CLIP: int = 4
_DCT_MAGNITUDE_CLIP: int = 16
_MIN_PATCH_SIDE: int = 16


class SteganalysisDatasetError(ValueError):
    """Raised when there is not enough image data to train the detector."""


@dataclass(frozen=True, slots=True)
class RichResidualEnsembleDetector:
    """SRM-style residual feature extractor plus deterministic ensemble detector."""

    patch_size: int = 64
    max_patches_per_image: int = 64
    test_fraction: float = 0.4
    random_state: int = 2026
    n_estimators: int = 200

    def evaluate(
        self,
        *,
        cover_image: ImageArray,
        stego_image: ImageArray,
        transform_specs: Sequence[Mapping[str, Any]],
        transform_image: Callable[..., NDArray[np.uint8]],
    ) -> dict[str, Any]:
        """Train/test the feature ensemble and return labels, scores, and metadata."""

        cover_samples = [np.asarray(cover_image)]
        stego_samples = [np.asarray(stego_image)]
        for spec in transform_specs:
            name = str(spec.get("name", "")).strip()
            params = spec.get("params", {})
            if not name:
                continue
            if not isinstance(params, Mapping):
                params = {}
            cover_samples.append(transform_image(cover_image, name, **dict(params)))
            stego_samples.append(transform_image(stego_image, name, **dict(params)))

        features, labels, patch_count = self._build_feature_matrix(
            cover_samples=cover_samples,
            stego_samples=stego_samples,
        )
        train_idx, test_idx = _stratified_split(
            labels,
            test_fraction=self.test_fraction,
            random_state=self.random_state,
        )

        classifier = ExtraTreesClassifier(
            n_estimators=self.n_estimators,
            max_features="sqrt",
            class_weight="balanced",
            bootstrap=False,
            n_jobs=-1,
            random_state=self.random_state,
        )
        classifier.fit(features[train_idx], labels[train_idx])
        y_scores = classifier.predict_proba(features[test_idx])[:, 1]

        return {
            "y_true": labels[test_idx].astype(np.int64, copy=False),
            "y_scores": y_scores.astype(np.float64, copy=False),
            "metadata": {
                "detector_name": "rich_residual_ensemble",
                "feature_family": (
                    "high-pass residual histograms, residual co-occurrences, "
                    "and block-DCT magnitude histograms"
                ),
                "classifier": (
                    f"ExtraTreesClassifier(n_estimators={self.n_estimators}, "
                    f"random_state={self.random_state})"
                ),
                "training_protocol": (
                    "deterministic stratified patch split from cover/stego images "
                    "and their controlled transformed variants"
                ),
                "sample_count": int(labels.size),
                "train_sample_count": int(train_idx.size),
                "test_sample_count": int(test_idx.size),
                "feature_count": int(features.shape[1]),
                "patch_size": int(self.patch_size),
                "patch_count": int(patch_count),
                "image_variant_count_per_class": int(len(cover_samples)),
            },
        }

    def _build_feature_matrix(
        self,
        *,
        cover_samples: Sequence[ImageArray],
        stego_samples: Sequence[ImageArray],
    ) -> tuple[NDArray[np.float64], NDArray[np.int64], int]:
        feature_rows: list[NDArray[np.float64]] = []
        labels: list[int] = []
        patch_count = 0

        for label, samples in ((0, cover_samples), (1, stego_samples)):
            for sample in samples:
                patches = _extract_patches(
                    sample,
                    patch_size=self.patch_size,
                    max_patches=self.max_patches_per_image,
                )
                for patch in patches:
                    feature_rows.append(extract_rich_residual_features(patch))
                    labels.append(label)
                patch_count += len(patches)

        if not feature_rows:
            raise SteganalysisDatasetError("No image patches were available for steganalysis.")

        features = np.vstack(feature_rows).astype(np.float64, copy=False)
        label_array = np.asarray(labels, dtype=np.int64)
        if np.unique(label_array).size != 2:
            raise SteganalysisDatasetError("Detector dataset must contain cover and stego samples.")
        if min(np.bincount(label_array, minlength=2)) < 2:
            raise SteganalysisDatasetError(
                "At least two cover and two stego patches are required."
            )
        if not np.isfinite(features).all():
            raise SteganalysisDatasetError("Extracted steganalysis features are not finite.")

        return features, label_array, patch_count


def extract_rich_residual_features(image: ImageArray) -> NDArray[np.float64]:
    """Extract normalized residual, co-occurrence, and DCT histogram features."""

    gray = _to_grayscale_float(image)
    features: list[NDArray[np.float64]] = []

    for kernel in _residual_kernels():
        residual = cv2.filter2D(gray, cv2.CV_32F, kernel)
        quantized = _quantize_residual(residual)
        features.append(_normalized_histogram(quantized.ravel(), 2 * _RESIDUAL_CLIP + 1))
        features.append(_cooccurrence_histogram(quantized, axis=1))
        features.append(_cooccurrence_histogram(quantized, axis=0))
        features.append(_residual_statistics(residual))

    features.append(_dct_magnitude_histogram(gray))
    vector = np.concatenate(features).astype(np.float64, copy=False)
    return np.nan_to_num(vector, nan=0.0, posinf=0.0, neginf=0.0)


def _to_grayscale_float(image: ImageArray) -> NDArray[np.float32]:
    array = np.asarray(image)
    if array.ndim == 2:
        gray = array.astype(np.float32, copy=False)
    elif array.ndim == 3 and array.shape[2] >= 3:
        rgb = array[..., :3].astype(np.float32, copy=False)
        gray = (
            0.299 * rgb[..., 0]
            + 0.587 * rgb[..., 1]
            + 0.114 * rgb[..., 2]
        )
    else:
        raise SteganalysisDatasetError("Images must be grayscale or channel-last RGB arrays.")
    if min(gray.shape[:2]) < _MIN_PATCH_SIDE:
        raise SteganalysisDatasetError("Image patches are too small for residual features.")
    return gray.astype(np.float32, copy=False)


def _residual_kernels() -> tuple[NDArray[np.float32], ...]:
    return (
        np.array([[1, -1]], dtype=np.float32),
        np.array([[1], [-1]], dtype=np.float32),
        np.array([[1, 0], [0, -1]], dtype=np.float32),
        np.array([[0, 1, 0], [1, -4, 1], [0, 1, 0]], dtype=np.float32),
        np.array([[-1, 2, -1]], dtype=np.float32),
        np.array([[-1], [2], [-1]], dtype=np.float32),
    )


def _quantize_residual(residual: NDArray[np.float32]) -> NDArray[np.int16]:
    clipped = np.clip(np.rint(residual), -_RESIDUAL_CLIP, _RESIDUAL_CLIP)
    return (clipped.astype(np.int16, copy=False) + _RESIDUAL_CLIP)


def _normalized_histogram(values: NDArray[np.integer], bins: int) -> NDArray[np.float64]:
    counts = np.bincount(values.astype(np.int64, copy=False), minlength=bins)
    counts = counts[:bins].astype(np.float64, copy=False)
    total = float(counts.sum())
    if total == 0.0:
        return np.zeros(bins, dtype=np.float64)
    return counts / total


def _cooccurrence_histogram(
    quantized: NDArray[np.int16],
    *,
    axis: int,
) -> NDArray[np.float64]:
    bins = 2 * _RESIDUAL_CLIP + 1
    if axis == 1:
        if quantized.shape[1] < 2:
            return np.zeros(bins * bins, dtype=np.float64)
        left = quantized[:, :-1].astype(np.int64, copy=False)
        right = quantized[:, 1:].astype(np.int64, copy=False)
    elif axis == 0:
        if quantized.shape[0] < 2:
            return np.zeros(bins * bins, dtype=np.float64)
        left = quantized[:-1, :].astype(np.int64, copy=False)
        right = quantized[1:, :].astype(np.int64, copy=False)
    else:
        raise ValueError("axis must be 0 or 1.")

    pair_ids = (left * bins + right).ravel()
    return _normalized_histogram(pair_ids, bins * bins)


def _residual_statistics(residual: NDArray[np.float32]) -> NDArray[np.float64]:
    residual64 = residual.astype(np.float64, copy=False)
    centered = residual64 - float(np.mean(residual64))
    std = float(np.std(residual64))
    if std > 0.0:
        fourth = float(np.mean((centered / std) ** 4))
    else:
        fourth = 0.0
    return np.asarray(
        [
            float(np.mean(np.abs(residual64))),
            std,
            float(np.percentile(np.abs(residual64), 75)),
            fourth,
        ],
        dtype=np.float64,
    )


def _dct_magnitude_histogram(gray: NDArray[np.float32]) -> NDArray[np.float64]:
    usable_h = (gray.shape[0] // 8) * 8
    usable_w = (gray.shape[1] // 8) * 8
    bins = _DCT_MAGNITUDE_CLIP + 1
    if usable_h < 8 or usable_w < 8:
        return np.zeros(bins, dtype=np.float64)

    crop = gray[:usable_h, :usable_w].astype(np.float32, copy=False) - 128.0
    blocks = (
        crop.reshape(usable_h // 8, 8, usable_w // 8, 8)
        .swapaxes(1, 2)
        .reshape(-1, 8, 8)
    )
    magnitudes: list[NDArray[np.float32]] = []
    for block in blocks:
        coeffs = cv2.dct(block)
        magnitudes.append(np.abs(coeffs.ravel()[1:]))
    if not magnitudes:
        return np.zeros(bins, dtype=np.float64)
    values = np.clip(np.rint(np.concatenate(magnitudes)), 0, _DCT_MAGNITUDE_CLIP)
    return _normalized_histogram(values.astype(np.int64, copy=False), bins)


def _extract_patches(
    image: ImageArray,
    *,
    patch_size: int,
    max_patches: int,
) -> list[NDArray[np.generic]]:
    array = np.asarray(image)
    if array.ndim < 2:
        raise SteganalysisDatasetError("Image arrays must have at least two dimensions.")
    height, width = int(array.shape[0]), int(array.shape[1])
    if height < _MIN_PATCH_SIDE or width < _MIN_PATCH_SIDE:
        raise SteganalysisDatasetError("Image is too small for steganalysis patches.")

    side = min(int(patch_size), height, width)
    if side < _MIN_PATCH_SIDE:
        side = min(height, width)
    step = max(side // 2, _MIN_PATCH_SIDE)
    y_positions = _grid_positions(length=height, window=side, step=step)
    x_positions = _grid_positions(length=width, window=side, step=step)

    patches: list[NDArray[np.generic]] = [array[:side, :side]]
    for y in y_positions:
        for x in x_positions:
            patch = array[y : y + side, x : x + side]
            if patch.shape[0] == side and patch.shape[1] == side:
                patches.append(patch)

    if len(patches) > max_patches:
        keep_indices = np.linspace(0, len(patches) - 1, max_patches, dtype=np.int64)
        patches = [patches[int(index)] for index in keep_indices]
    return patches


def _grid_positions(*, length: int, window: int, step: int) -> list[int]:
    if length <= window:
        return [0]
    positions = list(range(0, length - window + 1, step))
    last = length - window
    if positions[-1] != last:
        positions.append(last)
    return positions


def _stratified_split(
    labels: NDArray[np.int64],
    *,
    test_fraction: float,
    random_state: int,
) -> tuple[NDArray[np.int64], NDArray[np.int64]]:
    rng = np.random.default_rng(random_state)
    train_indices: list[int] = []
    test_indices: list[int] = []

    for label in (0, 1):
        indices = np.flatnonzero(labels == label)
        if indices.size < 2:
            raise SteganalysisDatasetError("Each class needs at least two samples.")
        shuffled = np.array(indices, copy=True)
        rng.shuffle(shuffled)
        test_count = max(1, int(round(shuffled.size * test_fraction)))
        if shuffled.size - test_count < 1:
            test_count = shuffled.size - 1
        test_indices.extend(int(index) for index in shuffled[:test_count])
        train_indices.extend(int(index) for index in shuffled[test_count:])

    train = np.asarray(sorted(train_indices), dtype=np.int64)
    test = np.asarray(sorted(test_indices), dtype=np.int64)
    if train.size == 0 or test.size == 0:
        raise SteganalysisDatasetError("Detector split produced an empty train or test set.")
    return train, test
