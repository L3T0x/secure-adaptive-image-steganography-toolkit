"""Steganography engines for PNG and JPEG carriers.

This module provides two concrete steganography engines:

1. ``PNGEngine`` for spatial-domain embedding using RGB LSB substitution.
2. ``JPEGEngine`` for transform-domain embedding using quantized, non-zero
   AC DCT coefficients.

The engines are deterministic with respect to the caller-provided seed. The
seed drives pseudo-random target selection so payload bits are scattered across
the carrier rather than embedded sequentially.

The module is intentionally agnostic to payload semantics. Callers should feed
it ciphertext bytes produced by ``crypto_layer.py`` rather than plaintext.
Neither engine stores payload length metadata inside the image; callers must
track the payload length externally and supply it during extraction.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
import hashlib
import logging
import math
from numbers import Integral
from os import PathLike
from pathlib import Path
import secrets
import tempfile
from typing import Any, Final, Sequence, Union

import numpy as np
from numpy.typing import NDArray
from PIL import Image

try:
    import jpeglib
except ImportError:  # pragma: no cover - exercised only when dependency is absent.
    jpeglib = None

try:
    from reedsolo import RSCodec, ReedSolomonError
except ImportError:  # pragma: no cover - exercised only when dependency is absent.
    RSCodec = None
    ReedSolomonError = None

__all__ = [
    "CapacityError",
    "CarrierCapacityExceeded",
    "DEFAULT_RS_ECC_SYMBOLS",
    "EngineFactory",
    "JPEGCapacityReport",
    "JPEGEngine",
    "MissingDependencyError",
    "PNGCapacityReport",
    "PNGEmbedMode",
    "PNGEngine",
    "StegoEngine",
    "StegoEngineError",
    "estimate_ecc_encoded_length_bits",
    "estimate_ecc_encoded_length_bytes",
]

logger = logging.getLogger(__name__)

StrPath = Union[str, PathLike[str]]
SeedInput = Union[int, str, bytes, bytearray, memoryview]

_PNG_EXT: Final[str] = ".png"
_JPEG_EXTENSIONS: Final[tuple[str, ...]] = (".jpg", ".jpeg")
_JPEG_DEFAULT_EXT: Final[str] = ".jpg"
_ROBUST_LOW_FREQUENCY_MAX_ZIGZAG: Final[int] = 10
_RS_CODEWORD_SIZE_BYTES: Final[int] = 255
DEFAULT_RS_ECC_SYMBOLS: Final[int] = 64


class StegoEngineError(Exception):
    """Base exception for steganography engine failures."""


class CapacityError(StegoEngineError, ValueError):
    """Raised when a payload exceeds the available embedding capacity."""


class CarrierCapacityExceeded(CapacityError):
    """Raised when a carrier cannot hold the requested payload."""


class MissingDependencyError(RuntimeError):
    """Raised when a required optional dependency is unavailable."""


class PNGEmbedMode(str, Enum):
    """Supported spatial-domain PNG embedding strategies."""

    LSB_REPLACEMENT = "lsb_replacement"
    LSB_MATCHING = "lsb_matching"


@dataclass(frozen=True, slots=True)
class PNGCapacityReport:
    """Capacity summary for the PNG spatial engine."""

    width: int
    height: int
    embeddable_channels: int
    capacity_bits: int


@dataclass(frozen=True, slots=True)
class JPEGCapacityReport:
    """Capacity summary for the JPEG DCT engine.

    The capacity rule is fixed by the project requirements:

    ``C = floor(r * N)``

    where ``r`` is the payload rate in bpnzAC and ``N`` is the total number of
    quantized, non-zero AC coefficients.
    """

    payload_rate_bpnzac: float
    total_nonzero_ac_coefficients: int
    capacity_bits: int


@dataclass(frozen=True, slots=True)
class _JPEGComponentPool:
    """Internal mapping of eligible DCT coefficient locations for one component."""

    name: str
    array: NDArray[np.int16]
    candidate_flat_indices: NDArray[np.int64]
    robust_candidate_flat_indices: NDArray[np.int64]

    @property
    def candidate_count(self) -> int:
        """Return the number of embeddable coefficients in this component."""

        return int(self.candidate_flat_indices.size)

    @property
    def robust_candidate_count(self) -> int:
        """Return the number of robust-preference candidates in this component."""

        return int(self.robust_candidate_flat_indices.size)


@dataclass(frozen=True, slots=True)
class _JPEGSelectionResult:
    """Internal result describing explicit JPEG embedding positions."""

    components: list[str]
    component_ids: list[int]
    flat_indices: list[int]
    encoded_payload_bits: int


class StegoEngine(ABC):
    """Abstract base class for deterministic steganography engines."""

    @abstractmethod
    def embed(
        self,
        cover_image_path: StrPath,
        payload_bytes: bytes,
        seed: SeedInput,
        **kwargs: Any,
    ) -> str:
        """Embed payload bytes into a cover image and return the stego path."""

    @abstractmethod
    def extract(
        self,
        stego_image_path: StrPath,
        payload_length_bits: int,
        seed: SeedInput,
        **kwargs: Any,
    ) -> bytes:
        """Extract payload bytes from a stego image."""


class EngineFactory:
    """Registry-backed factory for format-specific steganography engines.

    New carrier formats can be added by registering an engine class against one
    or more normalized format labels, for example ``EngineFactory.register("WEBP",
    WebPEngine)``.
    """

    _registry: dict[str, type[StegoEngine]] = {}

    @classmethod
    def register(cls, carrier_format: str, engine_cls: type[StegoEngine]) -> None:
        """Register an engine class for a carrier format label."""

        if not isinstance(carrier_format, str) or not carrier_format.strip():
            raise ValueError("carrier_format must be a non-empty string.")
        if not issubclass(engine_cls, StegoEngine):
            raise TypeError("engine_cls must derive from StegoEngine.")
        cls._registry[carrier_format.strip().upper()] = engine_cls

    @classmethod
    def create(cls, carrier_format: str) -> StegoEngine:
        """Instantiate the engine registered for ``carrier_format``."""

        key = carrier_format.strip().upper()
        if key == "JPG":
            key = "JPEG"
        engine_cls = cls._registry.get(key)
        if engine_cls is None:
            supported = ", ".join(sorted(cls._registry)) or "<none>"
            raise ValueError(
                f"Unsupported carrier format '{carrier_format}'. Registered formats: {supported}."
            )
        return engine_cls()

    @classmethod
    def supported_formats(cls) -> tuple[str, ...]:
        """Return the currently registered carrier format labels."""

        return tuple(sorted(cls._registry))


class PNGEngine(StegoEngine):
    """Spatial-domain PNG LSB engine.

    The engine operates over RGB channels. If a source PNG carries an alpha
    channel, the alpha plane is preserved but never used for embedding.
    """

    def capacity_report(self, cover_image_path: StrPath) -> PNGCapacityReport:
        """Return the raw spatial embedding capacity for a PNG carrier."""

        image, rgb, _ = self._load_png_channels(cover_image_path)
        try:
            height, width, channels = rgb.shape
            if channels != 3:
                raise ValueError("PNGEngine expects exactly three RGB channels.")
            capacity_bits = int(rgb.size)
            return PNGCapacityReport(
                width=width,
                height=height,
                embeddable_channels=channels,
                capacity_bits=capacity_bits,
            )
        finally:
            image.close()

    def embed(
        self,
        cover_image_path: StrPath,
        payload_bytes: bytes,
        seed: SeedInput,
        **kwargs: Any,
    ) -> str:
        """Embed payload bytes into a PNG using seeded scattered LSB operations.

        Keyword Args:
            mode: Either ``PNGEmbedMode.LSB_REPLACEMENT`` or
                ``PNGEmbedMode.LSB_MATCHING``. Defaults to LSB matching.
            output_path: Optional explicit destination path.
        """

        mode = _parse_png_mode(kwargs.get("mode", PNGEmbedMode.LSB_MATCHING))
        output_path = kwargs.get("output_path")

        payload = _ensure_bytes(payload_bytes, field_name="payload_bytes")
        bits = _bytes_to_bits(payload)
        payload_bits = int(bits.size)

        image, rgb, alpha = self._load_png_channels(cover_image_path)
        try:
            flat_rgb = rgb.reshape(-1)
            capacity_bits = int(flat_rgb.size)
            if payload_bits > capacity_bits:
                raise CarrierCapacityExceeded(
                    f"Payload requires {payload_bits} bits but PNG capacity is {capacity_bits} bits."
                )

            if payload_bits > 0:
                rng = _make_rng(seed)
                selected_positions = _select_unique_positions(
                    rng=rng,
                    population_size=capacity_bits,
                    sample_size=payload_bits,
                )
                if mode is PNGEmbedMode.LSB_REPLACEMENT:
                    flat_rgb[selected_positions] = (
                        flat_rgb[selected_positions] & np.uint8(0xFE)
                    ) | bits
                else:
                    self._apply_lsb_matching(
                        flat_rgb=flat_rgb,
                        selected_positions=selected_positions,
                        bits=bits,
                        rng=rng,
                    )

            stego = self._recombine_png(rgb=rgb, alpha=alpha)
            destination = _resolve_output_path(
                input_path=cover_image_path,
                output_path=output_path,
                suffix="_stego",
                default_extension=_PNG_EXT,
            )
            Image.fromarray(stego).save(destination, format="PNG")
            return str(destination)
        finally:
            image.close()

    def extract(
        self,
        stego_image_path: StrPath,
        payload_length_bits: int,
        seed: SeedInput,
        **kwargs: Any,
    ) -> bytes:
        """Extract payload bytes from a PNG stego image.

        ``kwargs`` are accepted for interface symmetry but currently unused.
        """

        del kwargs
        requested_bits = _validate_requested_bits(payload_length_bits)
        if requested_bits == 0:
            return b""

        image, rgb, _ = self._load_png_channels(stego_image_path)
        try:
            flat_rgb = rgb.reshape(-1)
            capacity_bits = int(flat_rgb.size)
            if requested_bits > capacity_bits:
                raise CarrierCapacityExceeded(
                    f"Requested {requested_bits} bits but PNG capacity is only {capacity_bits} bits."
                )

            rng = _make_rng(seed)
            selected_positions = _select_unique_positions(
                rng=rng,
                population_size=capacity_bits,
                sample_size=requested_bits,
            )
            bits = flat_rgb[selected_positions] & np.uint8(1)
            return _bits_to_bytes(bits, requested_bits)
        finally:
            image.close()

    @staticmethod
    def _load_png_channels(
        image_path: StrPath,
    ) -> tuple[Image.Image, NDArray[np.uint8], NDArray[np.uint8] | None]:
        """Load an image and split it into RGB payload channels plus optional alpha."""

        path = _coerce_path(image_path)
        image = Image.open(path)
        source = np.array(image)

        if source.ndim == 2:
            rgb = np.stack([source, source, source], axis=-1).astype(np.uint8, copy=False)
            alpha = None
        elif source.ndim == 3 and source.shape[2] == 4:
            rgb = source[:, :, :3].astype(np.uint8, copy=True)
            alpha = source[:, :, 3:].astype(np.uint8, copy=True)
        elif source.ndim == 3 and source.shape[2] >= 3:
            rgb = source[:, :, :3].astype(np.uint8, copy=True)
            alpha = None
        else:
            image.close()
            raise ValueError(f"Unsupported image shape for PNG engine: {source.shape!r}")

        return image, rgb, alpha

    @staticmethod
    def _apply_lsb_matching(
        *,
        flat_rgb: NDArray[np.uint8],
        selected_positions: NDArray[np.int64],
        bits: NDArray[np.uint8],
        rng: np.random.Generator,
    ) -> None:
        """Apply LSB matching to the selected uint8 samples in-place."""

        current = flat_rgb[selected_positions]
        mismatch_mask = (current & np.uint8(1)) != bits
        if not np.any(mismatch_mask):
            return

        mismatch_positions = selected_positions[mismatch_mask]
        mismatch_values = current[mismatch_mask].astype(np.int16, copy=True)
        updated_values = mismatch_values.copy()

        at_zero = mismatch_values == 0
        at_max = mismatch_values == 255
        middle = ~(at_zero | at_max)

        updated_values[at_zero] = 1
        updated_values[at_max] = 254

        middle_count = int(np.count_nonzero(middle))
        if middle_count > 0:
            direction_bits = rng.integers(0, 2, size=middle_count, dtype=np.int8)
            deltas = np.where(direction_bits == 0, -1, 1).astype(np.int16, copy=False)
            updated_values[middle] = mismatch_values[middle] + deltas

        flat_rgb[mismatch_positions] = updated_values.astype(np.uint8, copy=False)

    @staticmethod
    def _recombine_png(
        *,
        rgb: NDArray[np.uint8],
        alpha: NDArray[np.uint8] | None,
    ) -> NDArray[np.uint8]:
        """Recombine RGB payload planes with optional alpha."""

        if alpha is None:
            return rgb
        return np.concatenate([rgb, alpha], axis=2)


class JPEGEngine(StegoEngine):
    """Transform-domain JPEG engine using quantized, non-zero AC coefficients.

    Embedding is restricted to non-zero AC coefficients only. DC coefficients
    are never modified and coefficients are updated in a way that never creates
    new zeros, which keeps the eligible pool stable for deterministic
    extraction.
    """

    def capacity_report(
        self,
        cover_image_path: StrPath,
        *,
        payload_rate_bpnzac: float = 1.0,
        robust_mode: bool = False,
    ) -> JPEGCapacityReport:
        """Compute JPEG capacity using ``C = floor(r * N)`` exactly."""

        rate = _validate_payload_rate(payload_rate_bpnzac)
        jpeg = self._read_dct_jpeg(cover_image_path)
        try:
            component_pools = self._build_component_pools(jpeg)
            total_nonzero = (
                int(sum(pool.robust_candidate_count for pool in component_pools))
                if robust_mode
                else int(sum(pool.candidate_count for pool in component_pools))
            )
        finally:
            _close_jpeg(jpeg)

        capacity_bits = int(math.floor(rate * total_nonzero))
        report = JPEGCapacityReport(
            payload_rate_bpnzac=rate,
            total_nonzero_ac_coefficients=total_nonzero,
            capacity_bits=capacity_bits,
        )
        logger.info(
            "JPEG capacity computed with C = floor(r * N): r=%.6f, N=%d, C=%d bits",
            report.payload_rate_bpnzac,
            report.total_nonzero_ac_coefficients,
            report.capacity_bits,
        )
        return report

    def embed(
        self,
        cover_image_path: StrPath,
        payload_bytes: bytes,
        seed: SeedInput,
        **kwargs: Any,
    ) -> str:
        """Embed payload bytes into JPEG DCT coefficients.

        Keyword Args:
            output_path: Optional explicit destination path.
            payload_rate_bpnzac: Rate used for the strict capacity rule.
            use_ecc: Whether to wrap the payload with Reed-Solomon ECC.
            ecc_symbols: Reed-Solomon parity bytes per codeword chunk.
            robust_mode: Prefer larger-magnitude / lower-frequency coefficients.
            metadata_out: Optional dict populated with runtime extraction metadata.
        """

        payload = _ensure_bytes(payload_bytes, field_name="payload_bytes")
        output_path = kwargs.get("output_path")
        payload_rate_bpnzac = kwargs.get("payload_rate_bpnzac", 1.0)
        use_ecc = bool(kwargs.get("use_ecc", False))
        ecc_symbols = _validate_ecc_symbols(kwargs.get("ecc_symbols", DEFAULT_RS_ECC_SYMBOLS))
        robust_mode = bool(kwargs.get("robust_mode", False))
        metadata_out = kwargs.get("metadata_out")
        if metadata_out is not None and not isinstance(metadata_out, dict):
            raise TypeError("metadata_out must be a dict if provided.")

        embedded_payload = (
            _rs_encode_payload(payload, ecc_symbols=ecc_symbols) if use_ecc else payload
        )
        bits = _bytes_to_bits(embedded_payload)
        embedded_payload_bits = int(bits.size)

        report = self.capacity_report(
            cover_image_path,
            payload_rate_bpnzac=payload_rate_bpnzac,
            robust_mode=robust_mode,
        )
        if embedded_payload_bits > report.capacity_bits:
            raise CarrierCapacityExceeded(
                "Payload requires "
                f"{embedded_payload_bits} bits after ECC/selection overhead but JPEG capacity is {report.capacity_bits} bits "
                f"for r={report.payload_rate_bpnzac:.6f} and "
                f"N={report.total_nonzero_ac_coefficients}."
            )

        destination = _resolve_output_path(
            input_path=cover_image_path,
            output_path=output_path,
            suffix="_stego",
            default_extension=_JPEG_DEFAULT_EXT,
            allowed_extensions=_JPEG_EXTENSIONS,
        )

        jpeg = self._read_dct_jpeg(cover_image_path)
        try:
            component_pools = self._build_component_pools(jpeg)
            selection = self._select_explicit_positions(
                component_pools=component_pools,
                sample_size=embedded_payload_bits,
                robust_mode=robust_mode,
                seed=seed,
            )
            self._embed_bits_at_explicit_positions(
                component_pools=component_pools,
                selection=selection,
                bits=bits,
                seed=seed,
                robust_mode=robust_mode,
            )

            jpeg.write_dct(str(destination))
        finally:
            _close_jpeg(jpeg)

        if metadata_out is not None:
            metadata_out.clear()
            metadata_out.update(
                {
                    "components": list(selection.components),
                    "component_ids": list(selection.component_ids),
                    "flat_indices": list(selection.flat_indices),
                    "encoded_payload_bits": selection.encoded_payload_bits,
                    "use_ecc": use_ecc,
                    "ecc_symbols": ecc_symbols,
                    "robust_mode": robust_mode,
                }
            )

        return str(destination)

    def extract(
        self,
        stego_image_path: StrPath,
        payload_length_bits: int,
        seed: SeedInput,
        **kwargs: Any,
    ) -> bytes:
        """Extract payload bytes from JPEG DCT coefficients.

        Keyword Args:
            payload_rate_bpnzac: Optional rate used only for capacity validation.
            use_ecc: Whether Reed-Solomon decoding should be attempted.
            ecc_symbols: Reed-Solomon parity bytes per codeword chunk.
            robust_mode: Whether robust selection metadata is expected.
            selection_metadata: Optional explicit position map produced at embed time.
        """

        requested_bits = _validate_requested_bits(payload_length_bits)
        payload_rate_bpnzac = kwargs.get("payload_rate_bpnzac")
        use_ecc = bool(kwargs.get("use_ecc", False))
        ecc_symbols = _validate_ecc_symbols(kwargs.get("ecc_symbols", DEFAULT_RS_ECC_SYMBOLS))
        robust_mode = bool(kwargs.get("robust_mode", False))
        selection_metadata = kwargs.get("selection_metadata")
        if selection_metadata is not None and not isinstance(selection_metadata, dict):
            raise TypeError("selection_metadata must be a dict if provided.")

        if requested_bits == 0:
            return b""

        requested_payload_bytes = _bits_to_bytes_length(requested_bits)
        if isinstance(selection_metadata, dict) and "encoded_payload_bits" in selection_metadata:
            encoded_payload_bits = _validate_requested_bits(selection_metadata["encoded_payload_bits"])
        elif use_ecc:
            encoded_payload_bits = estimate_ecc_encoded_length_bits(
                requested_bits,
                ecc_symbols=ecc_symbols,
            )
        else:
            encoded_payload_bits = requested_bits

        jpeg = self._read_dct_jpeg(stego_image_path)
        try:
            component_pools = self._build_component_pools(jpeg)
            total_nonzero = (
                int(sum(pool.robust_candidate_count for pool in component_pools))
                if robust_mode
                else int(sum(pool.candidate_count for pool in component_pools))
            )

            if payload_rate_bpnzac is not None:
                rate = _validate_payload_rate(float(payload_rate_bpnzac))
                capacity_bits = int(math.floor(rate * total_nonzero))
                if encoded_payload_bits > capacity_bits:
                    raise CarrierCapacityExceeded(
                        "Requested "
                        f"{encoded_payload_bits} embedded bits but the configured JPEG capacity is only {capacity_bits} bits "
                        f"for r={rate:.6f} and N={total_nonzero}."
                    )

            if selection_metadata is not None:
                bits = self._extract_bits_from_metadata(
                    component_pools=component_pools,
                    selection_metadata=selection_metadata,
                    payload_length_bits=encoded_payload_bits,
                    robust_mode=robust_mode,
                )
            else:
                if encoded_payload_bits > total_nonzero:
                    raise CarrierCapacityExceeded(
                        f"Requested {encoded_payload_bits} bits but only {total_nonzero} embeddable coefficients exist."
                    )
                rng = _make_rng(seed)
                selected_pool_positions = _select_unique_positions(
                    rng=rng,
                    population_size=total_nonzero,
                    sample_size=encoded_payload_bits,
                )
                bits = self._extract_bits_from_pools(
                    component_pools=component_pools,
                    selected_pool_positions=selected_pool_positions,
                    payload_length_bits=encoded_payload_bits,
                    robust_mode=robust_mode,
                )
        finally:
            _close_jpeg(jpeg)

        extracted_payload = _bits_to_bytes(bits, encoded_payload_bits)
        if not use_ecc:
            return extracted_payload

        try:
            return _rs_decode_payload(
                extracted_payload,
                original_length_bytes=requested_payload_bytes,
                ecc_symbols=ecc_symbols,
            )
        except ValueError as exc:
            raise ValueError(
                "Reed-Solomon correction failed; payload integrity could not be recovered."
            ) from exc

    @staticmethod
    def _read_dct_jpeg(image_path: StrPath) -> Any:
        """Read a JPEG as quantized DCT coefficients."""

        if jpeglib is None:
            raise MissingDependencyError(
                "JPEGEngine requires the optional 'jpeglib' dependency."
            )

        path = _coerce_path(image_path)
        if path.suffix.lower() not in _JPEG_EXTENSIONS:
            raise ValueError(
                f"JPEGEngine expects a JPEG file with one of {_JPEG_EXTENSIONS}, got '{path.suffix}'."
            )
        return jpeglib.read_dct(str(path))

    @staticmethod
    def _build_component_pools(jpeg: Any) -> list[_JPEGComponentPool]:
        """Enumerate embeddable coefficients and the robust-preference subset."""

        pools: list[_JPEGComponentPool] = []
        zigzag_ranks = _jpeg_zigzag_rank_map()
        for component_name in ("Y", "Cb", "Cr", "K"):
            component = getattr(jpeg, component_name, None)
            if component is None:
                continue

            array = np.asarray(component, dtype=np.int16)
            if array.ndim != 4 or array.shape[-2:] != (8, 8):
                raise ValueError(
                    f"Unexpected DCT array shape for component {component_name}: {array.shape!r}"
                )

            mask = np.ones(array.shape, dtype=bool)
            mask[..., 0, 0] = False
            mask &= array != 0
            robust_mask = mask & (
                (np.abs(array) > 1)
                | (zigzag_ranks <= _ROBUST_LOW_FREQUENCY_MAX_ZIGZAG)
            )
            candidate_flat_indices = np.flatnonzero(mask.reshape(-1)).astype(
                np.int64,
                copy=False,
            )
            robust_candidate_flat_indices = np.flatnonzero(
                robust_mask.reshape(-1)
            ).astype(
                np.int64,
                copy=False,
            )
            pools.append(
                _JPEGComponentPool(
                    name=component_name,
                    array=array,
                    candidate_flat_indices=candidate_flat_indices,
                    robust_candidate_flat_indices=robust_candidate_flat_indices,
                )
            )

        if not pools:
            raise CarrierCapacityExceeded("JPEG carrier exposes no embeddable non-zero AC coefficients.")
        return pools

    @staticmethod
    def _select_explicit_positions(
        *,
        component_pools: Sequence[_JPEGComponentPool],
        sample_size: int,
        robust_mode: bool,
        seed: SeedInput,
    ) -> _JPEGSelectionResult:
        """Select explicit component/flat-index positions for deterministic reuse."""

        component_names = [pool.name for pool in component_pools]
        if sample_size == 0:
            return _JPEGSelectionResult(
                components=component_names,
                component_ids=[],
                flat_indices=[],
                encoded_payload_bits=0,
            )

        rng = _make_rng(seed)
        all_component_ids, all_flat_indices = JPEGEngine._flatten_position_arrays(
            component_pools=component_pools,
            robust_only=False,
        )
        total_candidates = int(all_flat_indices.size)
        if sample_size > total_candidates:
            raise CarrierCapacityExceeded(
                f"Payload requires {sample_size} bits but only {total_candidates} embeddable coefficients exist."
            )

        if robust_mode:
            robust_component_ids, robust_flat_indices = JPEGEngine._flatten_position_arrays(
                component_pools=component_pools,
                robust_only=True,
            )
            robust_total = int(robust_flat_indices.size)
            if robust_total == 0:
                raise CarrierCapacityExceeded("Robust JPEG mode found no preferred coefficients to embed into.")

            if sample_size <= robust_total:
                robust_choice = _select_unique_positions(
                    rng=rng,
                    population_size=robust_total,
                    sample_size=sample_size,
                )
                selected_component_ids = robust_component_ids[robust_choice]
                selected_flat_indices = robust_flat_indices[robust_choice]
            else:
                robust_keys = _position_keys(robust_component_ids, robust_flat_indices)
                all_keys = _position_keys(all_component_ids, all_flat_indices)
                remaining_mask = ~np.isin(all_keys, robust_keys, assume_unique=False)
                remaining_component_ids = all_component_ids[remaining_mask]
                remaining_flat_indices = all_flat_indices[remaining_mask]
                remaining_needed = sample_size - robust_total
                extra_choice = _select_unique_positions(
                    rng=rng,
                    population_size=int(remaining_flat_indices.size),
                    sample_size=remaining_needed,
                )
                selected_component_ids = np.concatenate(
                    [
                        robust_component_ids,
                        remaining_component_ids[extra_choice],
                    ]
                )
                selected_flat_indices = np.concatenate(
                    [
                        robust_flat_indices,
                        remaining_flat_indices[extra_choice],
                    ]
                )
        else:
            choice = _select_unique_positions(
                rng=rng,
                population_size=total_candidates,
                sample_size=sample_size,
            )
            selected_component_ids = all_component_ids[choice]
            selected_flat_indices = all_flat_indices[choice]

        return _JPEGSelectionResult(
            components=component_names,
            component_ids=selected_component_ids.astype(np.int64, copy=False).tolist(),
            flat_indices=selected_flat_indices.astype(np.int64, copy=False).tolist(),
            encoded_payload_bits=sample_size,
        )

    @staticmethod
    def _flatten_position_arrays(
        *,
        component_pools: Sequence[_JPEGComponentPool],
        robust_only: bool,
    ) -> tuple[NDArray[np.int64], NDArray[np.int64]]:
        """Flatten per-component position arrays into component-id and flat-index vectors."""

        component_id_parts: list[NDArray[np.int64]] = []
        flat_index_parts: list[NDArray[np.int64]] = []
        for component_index, pool in enumerate(component_pools):
            flat_indices = (
                pool.robust_candidate_flat_indices if robust_only else pool.candidate_flat_indices
            )
            if flat_indices.size == 0:
                continue
            component_id_parts.append(
                np.full(flat_indices.size, component_index, dtype=np.int64)
            )
            flat_index_parts.append(flat_indices.astype(np.int64, copy=False))

        if not flat_index_parts:
            return (
                np.empty(0, dtype=np.int64),
                np.empty(0, dtype=np.int64),
            )
        return (
            np.concatenate(component_id_parts),
            np.concatenate(flat_index_parts),
        )

    @staticmethod
    def _embed_bits_at_explicit_positions(
        *,
        component_pools: Sequence[_JPEGComponentPool],
        selection: _JPEGSelectionResult,
        bits: NDArray[np.uint8],
        seed: SeedInput,
        robust_mode: bool,
    ) -> None:
        """Embed bits at explicitly stored component/flat-index locations."""

        if len(selection.flat_indices) != int(bits.size):
            raise ValueError("Selection metadata size does not match the embedded bit count.")
        if bits.size == 0:
            return

        component_ids = np.asarray(selection.component_ids, dtype=np.int64)
        flat_indices = np.asarray(selection.flat_indices, dtype=np.int64)
        rng = _make_rng(seed)

        for component_index, pool in enumerate(component_pools):
            bit_positions = np.flatnonzero(component_ids == component_index)
            if bit_positions.size == 0:
                continue

            coefficient_flat_positions = flat_indices[bit_positions]
            flat_component = pool.array.reshape(-1)
            current_values = flat_component[coefficient_flat_positions].astype(
                np.int32,
                copy=True,
            )
            target_bits = bits[bit_positions]
            if robust_mode:
                updated_values = JPEGEngine._apply_signed_sign_modulation(
                    current_values=current_values,
                    target_bits=target_bits,
                )
            else:
                updated_values = JPEGEngine._apply_signed_lsb_modification(
                    current_values=current_values,
                    target_bits=target_bits,
                    rng=rng,
                )
            flat_component[coefficient_flat_positions] = updated_values.astype(
                np.int16,
                copy=False,
            )

    @staticmethod
    def _extract_bits_from_metadata(
        *,
        component_pools: Sequence[_JPEGComponentPool],
        selection_metadata: dict[str, Any],
        payload_length_bits: int,
        robust_mode: bool,
    ) -> NDArray[np.uint8]:
        """Extract bits using the explicit position map recorded during embedding."""

        components = selection_metadata.get("components")
        component_ids = selection_metadata.get("component_ids")
        flat_indices = selection_metadata.get("flat_indices")
        if not (
            isinstance(components, list)
            and isinstance(component_ids, list)
            and isinstance(flat_indices, list)
        ):
            raise ValueError("selection_metadata must include 'components', 'component_ids', and 'flat_indices'.")
        if len(component_ids) != payload_length_bits or len(flat_indices) != payload_length_bits:
            raise ValueError("selection_metadata does not match the requested payload length.")

        component_map = {pool.name: pool for pool in component_pools}
        component_names = [str(name) for name in components]
        bits = np.zeros(payload_length_bits, dtype=np.uint8)

        for bit_index, (component_id, flat_index) in enumerate(zip(component_ids, flat_indices)):
            if not isinstance(component_id, int) or not isinstance(flat_index, int):
                raise ValueError("selection_metadata indices must be integers.")
            if component_id < 0 or component_id >= len(component_names):
                raise ValueError("selection_metadata contains an out-of-range component id.")
            component_name = component_names[component_id]
            pool = component_map.get(component_name)
            if pool is None:
                raise ValueError(f"selection_metadata references unknown component '{component_name}'.")
            flat_component = pool.array.reshape(-1)
            if flat_index < 0 or flat_index >= flat_component.size:
                raise ValueError("selection_metadata contains an out-of-range flat index.")
            coefficient = int(flat_component[flat_index])
            if robust_mode:
                bits[bit_index] = np.uint8(1 if coefficient > 0 else 0)
            else:
                bits[bit_index] = np.uint8(abs(coefficient) & 1)

        return bits

    @staticmethod
    def _extract_bits_from_pools(
        *,
        component_pools: Sequence[_JPEGComponentPool],
        selected_pool_positions: NDArray[np.int64],
        payload_length_bits: int,
        robust_mode: bool,
    ) -> NDArray[np.uint8]:
        """Extract bits from the selected DCT coefficient pools."""

        counts = np.array(
            [
                pool.robust_candidate_count if robust_mode else pool.candidate_count
                for pool in component_pools
            ],
            dtype=np.int64,
        )
        cumulative_counts = np.cumsum(counts)
        component_ids = np.searchsorted(
            cumulative_counts,
            selected_pool_positions,
            side="right",
        )
        bits = np.zeros(payload_length_bits, dtype=np.uint8)

        for component_index, pool in enumerate(component_pools):
            bit_positions = np.flatnonzero(component_ids == component_index)
            if bit_positions.size == 0:
                continue

            prefix = 0 if component_index == 0 else int(cumulative_counts[component_index - 1])
            local_candidate_offsets = selected_pool_positions[bit_positions] - prefix
            candidate_indices = (
                pool.robust_candidate_flat_indices if robust_mode else pool.candidate_flat_indices
            )
            coefficient_flat_positions = candidate_indices[local_candidate_offsets]
            flat_component = pool.array.reshape(-1)
            coefficients = flat_component[coefficient_flat_positions].astype(np.int32, copy=False)
            if robust_mode:
                bits[bit_positions] = (coefficients > 0).astype(np.uint8, copy=False)
            else:
                bits[bit_positions] = (np.abs(coefficients) & 1).astype(np.uint8, copy=False)

        return bits

    @staticmethod
    def _apply_signed_lsb_modification(
        *,
        current_values: NDArray[np.int32],
        target_bits: NDArray[np.uint8],
        rng: np.random.Generator,
    ) -> NDArray[np.int32]:
        """Modify signed, non-zero coefficients so ``abs(value) & 1`` matches the bit.

        The update rule never produces zero:

        1. If a coefficient already matches the target bit, it is left unchanged.
        2. If ``abs(value) == 1`` and a parity flip is required, the magnitude is
           increased to ``2`` while preserving the sign.
        3. Otherwise the magnitude is shifted by one, with deterministic
           pseudo-random choice between moving toward or away from zero.
        """

        updated = current_values.copy()
        mismatch = ((np.abs(updated) & 1).astype(np.uint8, copy=False)) != target_bits
        if not np.any(mismatch):
            return updated

        mismatch_values = updated[mismatch]
        abs_values = np.abs(mismatch_values)
        updated_mismatch = mismatch_values.copy()

        unit_mask = abs_values == 1
        updated_mismatch[unit_mask] = np.where(
            mismatch_values[unit_mask] > 0,
            2,
            -2,
        )

        remaining_mask = ~unit_mask
        remaining_count = int(np.count_nonzero(remaining_mask))
        if remaining_count > 0:
            directions = rng.integers(0, 2, size=remaining_count, dtype=np.int8)
            remaining_values = mismatch_values[remaining_mask]
            signs = np.sign(remaining_values).astype(np.int32, copy=False)
            deltas = np.where(directions == 0, -signs, signs)
            updated_mismatch[remaining_mask] = remaining_values + deltas

        updated[mismatch] = updated_mismatch
        if np.any(updated == 0):
            raise RuntimeError("JPEG embedding unexpectedly produced zero coefficients.")
        return updated

    @staticmethod
    def _apply_signed_sign_modulation(
        *,
        current_values: NDArray[np.int32],
        target_bits: NDArray[np.uint8],
    ) -> NDArray[np.int32]:
        """Encode bits into coefficient sign for the robust JPEG path."""

        updated = current_values.copy()
        if np.any(updated == 0):
            raise RuntimeError("Robust JPEG mode received a zero coefficient.")

        positive_targets = target_bits.astype(bool, copy=False)
        updated[positive_targets] = np.abs(updated[positive_targets])
        updated[~positive_targets] = -np.abs(updated[~positive_targets])
        if np.any(updated == 0):
            raise RuntimeError("Robust JPEG sign modulation unexpectedly produced zero coefficients.")
        return updated


EngineFactory.register("PNG", PNGEngine)
EngineFactory.register("JPEG", JPEGEngine)
EngineFactory.register("JPG", JPEGEngine)


def _bytes_to_bits(payload_bytes: bytes) -> NDArray[np.uint8]:
    """Expand bytes into a big-endian bit array."""

    if len(payload_bytes) == 0:
        return np.empty(0, dtype=np.uint8)
    return np.unpackbits(np.frombuffer(payload_bytes, dtype=np.uint8), bitorder="big")


def _bits_to_bytes(bits: NDArray[np.uint8], bit_count: int) -> bytes:
    """Pack a bit array into bytes, padding the final byte if needed."""

    if bit_count == 0:
        return b""
    packed = np.packbits(bits[:bit_count], bitorder="big")
    return packed.tobytes()


def _bits_to_bytes_length(bit_count: int) -> int:
    """Return the minimum number of whole bytes needed to represent a bit count."""

    return int((bit_count + 7) // 8)


def estimate_ecc_encoded_length_bytes(
    payload_length_bytes: int,
    *,
    ecc_symbols: int = DEFAULT_RS_ECC_SYMBOLS,
) -> int:
    """Estimate Reed-Solomon encoded length for chunked payload protection."""

    raw_length = _validate_non_negative_int(payload_length_bytes, field_name="payload_length_bytes")
    symbols = _validate_ecc_symbols(ecc_symbols)
    if raw_length == 0:
        return 0
    data_bytes_per_chunk = _RS_CODEWORD_SIZE_BYTES - symbols
    chunk_count = int(math.ceil(raw_length / data_bytes_per_chunk))
    return raw_length + chunk_count * symbols


def estimate_ecc_encoded_length_bits(
    payload_length_bits: int,
    *,
    ecc_symbols: int = DEFAULT_RS_ECC_SYMBOLS,
) -> int:
    """Estimate Reed-Solomon encoded length in bits for a payload bit count."""

    raw_bits = _validate_non_negative_int(payload_length_bits, field_name="payload_length_bits")
    raw_bytes = _bits_to_bytes_length(raw_bits)
    return estimate_ecc_encoded_length_bytes(
        raw_bytes,
        ecc_symbols=ecc_symbols,
    ) * 8


def _validate_ecc_symbols(value: Any) -> int:
    """Validate the Reed-Solomon parity size per codeword chunk."""

    if not isinstance(value, Integral):
        raise TypeError("ecc_symbols must be an integer.")
    symbols = int(value)
    if not 2 <= symbols < _RS_CODEWORD_SIZE_BYTES:
        raise ValueError(
            f"ecc_symbols must be within [2, {_RS_CODEWORD_SIZE_BYTES - 1}]."
        )
    return symbols


def _rs_encode_payload(payload: bytes, *, ecc_symbols: int) -> bytes:
    """Chunk and encode a payload using Reed-Solomon ECC."""

    if RSCodec is None:
        raise MissingDependencyError(
            "JPEG ECC mode requires the optional 'reedsolo' dependency."
        )
    if len(payload) == 0:
        return b""

    codec = RSCodec(ecc_symbols)
    data_bytes_per_chunk = _RS_CODEWORD_SIZE_BYTES - ecc_symbols
    encoded_chunks: list[bytes] = []
    for start in range(0, len(payload), data_bytes_per_chunk):
        chunk = payload[start : start + data_bytes_per_chunk]
        encoded_chunks.append(bytes(codec.encode(chunk)))
    return b"".join(encoded_chunks)


def _rs_decode_payload(
    payload: bytes,
    *,
    original_length_bytes: int,
    ecc_symbols: int,
) -> bytes:
    """Chunk and decode a Reed-Solomon protected payload."""

    if RSCodec is None or ReedSolomonError is None:
        raise MissingDependencyError(
            "JPEG ECC mode requires the optional 'reedsolo' dependency."
        )
    original_length = _validate_non_negative_int(
        original_length_bytes,
        field_name="original_length_bytes",
    )
    if original_length == 0:
        return b""

    codec = RSCodec(ecc_symbols)
    data_bytes_per_chunk = _RS_CODEWORD_SIZE_BYTES - ecc_symbols
    decoded_chunks: list[bytes] = []
    payload_offset = 0
    remaining_plain = original_length

    while remaining_plain > 0:
        plain_chunk_length = min(data_bytes_per_chunk, remaining_plain)
        encoded_chunk_length = plain_chunk_length + ecc_symbols
        encoded_chunk = payload[payload_offset : payload_offset + encoded_chunk_length]
        if len(encoded_chunk) != encoded_chunk_length:
            raise ValueError("Encoded ECC payload is truncated.")
        try:
            decoded_chunk, _, _ = codec.decode(encoded_chunk)
        except ReedSolomonError as exc:
            raise ValueError("Reed-Solomon decode failed.") from exc
        decoded_bytes = bytes(decoded_chunk)
        if len(decoded_bytes) != plain_chunk_length:
            raise ValueError("Decoded ECC chunk length is inconsistent.")
        decoded_chunks.append(decoded_bytes)
        payload_offset += encoded_chunk_length
        remaining_plain -= plain_chunk_length

    if payload_offset != len(payload):
        raise ValueError("Encoded ECC payload has trailing bytes.")
    return b"".join(decoded_chunks)


def _jpeg_zigzag_rank_map() -> NDArray[np.int16]:
    """Return a broadcast-friendly 8x8 zigzag rank map for JPEG blocks."""

    ranks = np.array(
        [
            [0, 1, 5, 6, 14, 15, 27, 28],
            [2, 4, 7, 13, 16, 26, 29, 42],
            [3, 8, 12, 17, 25, 30, 41, 43],
            [9, 11, 18, 24, 31, 40, 44, 53],
            [10, 19, 23, 32, 39, 45, 52, 54],
            [20, 22, 33, 38, 46, 51, 55, 60],
            [21, 34, 37, 47, 50, 56, 59, 61],
            [35, 36, 48, 49, 57, 58, 62, 63],
        ],
        dtype=np.int16,
    )
    return ranks.reshape(1, 1, 8, 8)


def _position_keys(
    component_ids: NDArray[np.int64],
    flat_indices: NDArray[np.int64],
) -> NDArray[np.int64]:
    """Create stable 64-bit keys for component/index position pairs."""

    return (component_ids.astype(np.int64) << np.int64(32)) | flat_indices.astype(np.int64)


def _ensure_bytes(value: bytes, *, field_name: str) -> bytes:
    """Validate that a payload is immutable bytes."""

    if not isinstance(value, bytes):
        raise TypeError(f"{field_name} must be bytes.")
    return value


def _validate_requested_bits(payload_length_bits: int) -> int:
    """Normalize and validate a requested extraction length."""

    if not isinstance(payload_length_bits, Integral):
        raise TypeError("payload_length_bits must be an integer.")
    requested_bits = int(payload_length_bits)
    if requested_bits < 0:
        raise ValueError("payload_length_bits must be >= 0.")
    return requested_bits


def _validate_non_negative_int(value: int, *, field_name: str) -> int:
    """Validate a non-negative integer helper value."""

    if not isinstance(value, Integral):
        raise TypeError(f"{field_name} must be an integer.")
    normalized = int(value)
    if normalized < 0:
        raise ValueError(f"{field_name} must be >= 0.")
    return normalized


def _validate_payload_rate(payload_rate_bpnzac: float) -> float:
    """Validate the JPEG payload rate for a 1-bit-per-coefficient baseline."""

    try:
        rate = float(payload_rate_bpnzac)
    except (TypeError, ValueError) as exc:
        raise TypeError("payload_rate_bpnzac must be numeric.") from exc
    if not (0.0 < rate <= 1.0):
        raise ValueError(
            "payload_rate_bpnzac must be within (0.0, 1.0] for this baseline engine."
        )
    return rate


def _parse_png_mode(value: PNGEmbedMode | str) -> PNGEmbedMode:
    """Parse a caller-supplied PNG mode value."""

    if isinstance(value, PNGEmbedMode):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        for mode in PNGEmbedMode:
            if mode.value == normalized or mode.name.lower() == normalized:
                return mode
    raise ValueError(
        "mode must be one of: "
        + ", ".join(mode.value for mode in PNGEmbedMode)
        + "."
    )


def _coerce_path(path: StrPath) -> Path:
    """Coerce a path-like input into a resolved ``Path``."""

    resolved = Path(path).expanduser()
    if not resolved.exists():
        raise FileNotFoundError(f"Image path does not exist: {resolved}")
    return resolved


def _resolve_output_path(
    *,
    input_path: StrPath,
    output_path: StrPath | None,
    suffix: str,
    default_extension: str,
    allowed_extensions: Sequence[str] | None = None,
) -> Path:
    """Resolve an output path, deriving a sensible default if necessary."""

    if output_path is not None:
        destination = Path(output_path).expanduser()
    else:
        source = Path(input_path).expanduser()
        extension = source.suffix if source.suffix else default_extension
        if allowed_extensions is not None and extension.lower() not in allowed_extensions:
            extension = default_extension
        destination = source.with_name(f"{source.stem}{suffix}{extension}")

    if destination.suffix == "":
        destination = destination.with_suffix(default_extension)
    parent = destination.parent
    parent.mkdir(parents=True, exist_ok=True)
    return destination


def _make_rng(seed: SeedInput) -> np.random.Generator:
    """Create a deterministic RNG from flexible seed input."""

    seed_bytes: bytes
    if isinstance(seed, Integral):
        seed_bytes = f"int:{int(seed)}".encode("utf-8")
    elif isinstance(seed, str):
        seed_bytes = f"str:{seed}".encode("utf-8")
    elif isinstance(seed, bytes):
        seed_bytes = b"bytes:" + seed
    elif isinstance(seed, bytearray):
        seed_bytes = b"bytearray:" + bytes(seed)
    elif isinstance(seed, memoryview):
        seed_bytes = b"memoryview:" + seed.tobytes()
    else:
        raise TypeError("seed must be an int, str, or bytes-like object.")

    digest = hashlib.blake2b(seed_bytes, digest_size=16).digest()
    seed_int = int.from_bytes(digest, byteorder="big", signed=False)
    return np.random.default_rng(np.random.SeedSequence(seed_int))


def _select_unique_positions(
    *,
    rng: np.random.Generator,
    population_size: int,
    sample_size: int,
) -> NDArray[np.int64]:
    """Select deterministic unique indices without replacement."""

    if sample_size == 0:
        return np.empty(0, dtype=np.int64)
    return np.asarray(
        rng.choice(population_size, size=sample_size, replace=False),
        dtype=np.int64,
    )


def _close_jpeg(jpeg: Any) -> None:
    """Best-effort release for JPEG DCT objects."""

    for method_name in ("close", "free"):
        method = getattr(jpeg, method_name, None)
        if callable(method):
            try:
                method()
            except Exception:
                logger.debug("Ignoring JPEG close/free error from %s.", method_name, exc_info=True)


def _self_test() -> None:
    """Run an end-to-end sanity check for both stego engines."""

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    png_engine = PNGEngine()
    jpeg_engine = JPEGEngine()
    seed = "module-2-self-test-seed"

    with tempfile.TemporaryDirectory(prefix="saistk_stego_") as tmp_dir:
        tmp_path = Path(tmp_dir)

        png_cover = tmp_path / "cover.png"
        jpeg_cover = tmp_path / "cover.jpg"

        rng = np.random.default_rng(20260504)
        rgb = rng.integers(0, 256, size=(128, 128, 3), dtype=np.uint8)
        Image.fromarray(rgb, "RGB").save(png_cover, format="PNG")
        Image.fromarray(rgb, "RGB").save(jpeg_cover, format="JPEG", quality=95)

        png_capacity = png_engine.capacity_report(png_cover)
        jpeg_capacity = jpeg_engine.capacity_report(jpeg_cover, payload_rate_bpnzac=1.0)

        max_bytes = min(
            png_capacity.capacity_bits // 8,
            jpeg_capacity.capacity_bits // 8,
            512,
        )
        if max_bytes <= 0:
            raise RuntimeError("Self-test images did not expose any embedding capacity.")

        payload_bytes = secrets.token_bytes(max_bytes)

        png_stego = png_engine.embed(
            png_cover,
            payload_bytes,
            seed,
            mode=PNGEmbedMode.LSB_MATCHING,
        )
        png_extracted = png_engine.extract(
            png_stego,
            len(payload_bytes) * 8,
            seed,
        )
        if png_extracted != payload_bytes:
            raise AssertionError("PNG engine round-trip verification failed.")

        png_replacement_stego = png_engine.embed(
            png_cover,
            payload_bytes,
            seed,
            mode=PNGEmbedMode.LSB_REPLACEMENT,
            output_path=tmp_path / "cover_replacement_stego.png",
        )
        png_replacement_extracted = png_engine.extract(
            png_replacement_stego,
            len(payload_bytes) * 8,
            seed,
        )
        if png_replacement_extracted != payload_bytes:
            raise AssertionError("PNG replacement-mode round-trip verification failed.")

        jpeg_stego = jpeg_engine.embed(
            jpeg_cover,
            payload_bytes,
            seed,
            payload_rate_bpnzac=1.0,
        )
        jpeg_extracted = jpeg_engine.extract(
            jpeg_stego,
            len(payload_bytes) * 8,
            seed,
            payload_rate_bpnzac=1.0,
        )
        if jpeg_extracted != payload_bytes:
            raise AssertionError("JPEG engine round-trip verification failed.")

        print(f"PNG capacity bits: {png_capacity.capacity_bits}")
        print(
            "JPEG capacity bits: "
            f"{jpeg_capacity.capacity_bits} (r={jpeg_capacity.payload_rate_bpnzac}, "
            f"N={jpeg_capacity.total_nonzero_ac_coefficients})"
        )
        print(f"Round-trip payload bytes: {len(payload_bytes)}")
        print("Self-test completed successfully.")


if __name__ == "__main__":
    _self_test()
