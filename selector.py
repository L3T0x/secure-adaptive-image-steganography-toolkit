"""Explainable rule-based selector for steganography engine configuration.

This module implements a deterministic, auditable policy layer that chooses a
steganography engine configuration based on carrier metadata, payload size, and
anticipated downstream transformations.

The selector intentionally avoids black-box behavior. Every decision appends a
human-readable entry to a sequential justification trace so an operator,
researcher, or auditor can understand exactly why a given configuration was
selected.
"""

from __future__ import annotations

from dataclasses import dataclass
import math
from numbers import Integral
from pprint import pprint
from typing import Any, Final, Mapping, Sequence

from rich.console import Console
from rich.table import Table

from stego_engines import (
    CapacityError,
    CarrierCapacityExceeded,
    DEFAULT_RS_ECC_SYMBOLS,
    JPEGEngine,
    PNGEmbedMode,
    PNGEngine,
    StegoEngine,
    estimate_ecc_encoded_length_bits,
)

CarrierMetadata = Mapping[str, Any]
SelectedConfig = dict[str, Any]
JustificationTrace = list[str]

_PNG_FORMAT: Final[str] = "PNG"
_JPEG_FORMAT: Final[str] = "JPEG"
_console = Console()


@dataclass(frozen=True, slots=True)
class ExplainableSelector:
    """Rule-based configuration selector with transparent audit tracing."""

    jpeg_robust_rate_bpnzac: float = 0.05
    jpeg_standard_rate_bpnzac: float = 0.1
    jpeg_ecc_symbols: int = DEFAULT_RS_ECC_SYMBOLS
    default_png_mode: PNGEmbedMode = PNGEmbedMode.LSB_MATCHING

    def select_configuration(
        self,
        carrier_metadata: CarrierMetadata,
        payload_size_bits: int,
        expected_transformations: Sequence[str],
    ) -> tuple[SelectedConfig, JustificationTrace]:
        """Select an engine configuration and produce a rule audit trail.

        Args:
            carrier_metadata: Metadata describing the candidate carrier. At
                minimum, this must contain ``format`` and the capacity-related
                fields required by that format:

                - PNG: ``width``, ``height``, ``channels``
                - JPEG: ``non_zero_ac_count``, ``robust_non_zero_ac_count``
            payload_size_bits: Size of the ciphertext payload in bits.
            expected_transformations: Anticipated downstream transformations,
                such as ``"noise"``, ``"resizing"``, or
                ``"jpeg_recompression"``.

        Returns:
            A two-tuple of ``(selected_config, justification_trace)``.

        Raises:
            CapacityError: If the payload cannot fit within the selected
                configuration.
            ValueError: If the carrier format or metadata are invalid.
            TypeError: If argument types are invalid.
        """

        payload_bits = _validate_payload_size_bits(payload_size_bits)
        normalized_transformations = _normalize_transformations(expected_transformations)
        trace: JustificationTrace = []

        carrier_format = _extract_format(carrier_metadata)
        if carrier_format == _PNG_FORMAT:
            selected_config = self._select_png_configuration(
                carrier_metadata=carrier_metadata,
                payload_size_bits=payload_bits,
                normalized_transformations=normalized_transformations,
                trace=trace,
            )
        elif carrier_format == _JPEG_FORMAT:
            selected_config = self._select_jpeg_configuration(
                carrier_metadata=carrier_metadata,
                payload_size_bits=payload_bits,
                normalized_transformations=normalized_transformations,
                trace=trace,
            )
        else:
            raise ValueError(
                "Unsupported carrier format. Expected 'PNG' or 'JPEG', "
                f"received '{carrier_format}'."
            )

        return selected_config, trace

    def _select_png_configuration(
        self,
        *,
        carrier_metadata: CarrierMetadata,
        payload_size_bits: int,
        normalized_transformations: set[str],
        trace: JustificationTrace,
    ) -> SelectedConfig:
        """Apply PNG-specific selection rules."""

        trace.append(
            "[RULE EVAL] Carrier format is PNG -> Engine set to PNGEngine."
        )

        mode = self.default_png_mode
        if "resizing" in normalized_transformations or "noise" in normalized_transformations:
            triggers: list[str] = []
            if "resizing" in normalized_transformations:
                triggers.append("'resizing'")
            if "noise" in normalized_transformations:
                triggers.append("'noise'")
            trace.append(
                "[RULE EVAL] "
                + " and ".join(triggers)
                + " found in expected_transformations -> "
                f"Mode set to {mode.value} to reduce simple statistical exposure versus replacement."
            )
        else:
            trace.append(
                "[RULE EVAL] No PNG-specific hostile transformations declared -> "
                f"defaulting to {mode.value} as the primary safer baseline."
            )

        width = _require_positive_int(carrier_metadata, key="width")
        height = _require_positive_int(carrier_metadata, key="height")
        channels = _require_positive_int(carrier_metadata, key="channels")
        capacity_bits = width * height * channels

        self._enforce_capacity(
            payload_size_bits=payload_size_bits,
            capacity_bits=capacity_bits,
            success_message=(
                "[CAPACITY CHECK] Payload size "
                f"{payload_size_bits} bits fits within PNG spatial capacity of {capacity_bits} bits "
                f"(width={width}, height={height}, channels={channels}) -> PASS."
            ),
            failure_message=(
                "[CAPACITY CHECK] Payload size "
                f"{payload_size_bits} bits exceeds PNG spatial capacity of {capacity_bits} bits "
                f"(width={width}, height={height}, channels={channels}) -> FAIL."
            ),
            trace=trace,
        )

        return {
            "engine_name": PNGEngine.__name__,
            "engine_class": PNGEngine,
            "carrier_format": _PNG_FORMAT,
            "embed_kwargs": {
                "mode": mode.value,
            },
            "mode": mode.value,
            "capacity_bits": capacity_bits,
            "payload_size_bits": payload_size_bits,
        }

    def _select_jpeg_configuration(
        self,
        *,
        carrier_metadata: CarrierMetadata,
        payload_size_bits: int,
        normalized_transformations: set[str],
        trace: JustificationTrace,
    ) -> SelectedConfig:
        """Apply JPEG-specific selection rules."""

        trace.append(
            "[RULE EVAL] Carrier format is JPEG -> Engine set to JPEGEngine."
        )

        use_ecc = False
        robust_mode = False
        if (
            "jpeg_recompression" in normalized_transformations
            or "noise" in normalized_transformations
        ):
            use_ecc = True
            robust_mode = True
            trace.append(
                "[RULE EVAL] Expected lossy transformations -> Enabling Reed-Solomon Error Correction and Robust DCT Selection."
            )

        if "jpeg_recompression" in normalized_transformations:
            rate = self.jpeg_robust_rate_bpnzac
            trace.append(
                "[RULE EVAL] 'jpeg_recompression' found in expected_transformations -> "
                f"Rate 'r' throttled to {rate:.2f} bpnzAC for survival."
            )
            capacity_label = "robust capacity limit"
        else:
            rate = self.jpeg_standard_rate_bpnzac
            trace.append(
                "[RULE EVAL] No JPEG recompression expected -> "
                f"Rate 'r' set to {rate:.2f} bpnzAC for standard capacity."
            )
            capacity_label = "standard capacity limit"

        non_zero_ac_count = _require_non_negative_int(carrier_metadata, key="non_zero_ac_count")
        robust_non_zero_ac_count = _require_non_negative_int(
            carrier_metadata,
            key="robust_non_zero_ac_count",
        )
        selected_non_zero_ac_count = (
            robust_non_zero_ac_count if robust_mode else non_zero_ac_count
        )
        capacity_bits = int(math.floor(rate * selected_non_zero_ac_count))
        required_embedding_bits = (
            estimate_ecc_encoded_length_bits(
                payload_size_bits,
                ecc_symbols=self.jpeg_ecc_symbols,
            )
            if use_ecc
            else payload_size_bits
        )

        trace.append(
            "[RULE EVAL] JPEG capacity rule applied exactly as "
            f"C = floor(r * N) with r={rate:.2f} and N={selected_non_zero_ac_count} -> C={capacity_bits} bits."
        )
        if use_ecc:
            trace.append(
                "[RULE EVAL] Reed-Solomon overhead applied before embedding -> "
                f"effective payload grows from {payload_size_bits} bits to {required_embedding_bits} bits."
            )

        self._enforce_capacity(
            payload_size_bits=required_embedding_bits,
            capacity_bits=capacity_bits,
            success_message=(
                "[CAPACITY CHECK] Payload size "
                f"{required_embedding_bits} bits fits within {capacity_label} of {capacity_bits} bits -> PASS."
            ),
            failure_message=(
                "[CAPACITY CHECK] Payload size "
                f"{required_embedding_bits} bits exceeds {capacity_label} of {capacity_bits} bits -> FAIL."
            ),
            trace=trace,
        )

        return {
            "engine_name": JPEGEngine.__name__,
            "engine_class": JPEGEngine,
            "carrier_format": _JPEG_FORMAT,
            "embed_kwargs": {
                "payload_rate_bpnzac": rate,
                "use_ecc": use_ecc,
                "ecc_symbols": self.jpeg_ecc_symbols,
                "robust_mode": robust_mode,
            },
            "payload_rate_bpnzac": rate,
            "use_ecc": use_ecc,
            "ecc_symbols": self.jpeg_ecc_symbols,
            "robust_mode": robust_mode,
            "non_zero_ac_count": non_zero_ac_count,
            "robust_non_zero_ac_count": robust_non_zero_ac_count,
            "capacity_bits": capacity_bits,
            "payload_size_bits": payload_size_bits,
            "required_embedding_bits": required_embedding_bits,
        }

    @staticmethod
    def _enforce_capacity(
        *,
        payload_size_bits: int,
        capacity_bits: int,
        success_message: str,
        failure_message: str,
        trace: JustificationTrace,
    ) -> None:
        """Append an auditable capacity result or raise ``CapacityError``."""

        if payload_size_bits > capacity_bits:
            raise CarrierCapacityExceeded(failure_message)
        trace.append(success_message)


def _extract_format(carrier_metadata: CarrierMetadata) -> str:
    """Normalize and validate the carrier format field."""

    raw_format = carrier_metadata.get("format")
    if not isinstance(raw_format, str) or not raw_format.strip():
        raise ValueError("carrier_metadata['format'] must be a non-empty string.")

    normalized = raw_format.strip().upper()
    if normalized in {"JPG", "JPEG"}:
        return _JPEG_FORMAT
    if normalized == _PNG_FORMAT:
        return _PNG_FORMAT
    return normalized


def _normalize_transformations(expected_transformations: Sequence[str]) -> set[str]:
    """Normalize transformation labels into a lowercase set."""

    normalized: set[str] = set()
    for transformation in expected_transformations:
        if not isinstance(transformation, str):
            raise TypeError("expected_transformations must contain only strings.")
        stripped = transformation.strip().lower()
        if stripped:
            normalized.add(stripped)
    return normalized


def _validate_payload_size_bits(payload_size_bits: int) -> int:
    """Validate payload size input."""

    if not isinstance(payload_size_bits, Integral):
        raise TypeError("payload_size_bits must be an integer.")
    value = int(payload_size_bits)
    if value < 0:
        raise ValueError("payload_size_bits must be >= 0.")
    return value


def _require_positive_int(carrier_metadata: CarrierMetadata, *, key: str) -> int:
    """Require a strictly positive integer metadata field."""

    value = carrier_metadata.get(key)
    if not isinstance(value, Integral):
        raise TypeError(f"carrier_metadata['{key}'] must be an integer.")
    normalized = int(value)
    if normalized <= 0:
        raise ValueError(f"carrier_metadata['{key}'] must be > 0.")
    return normalized


def _require_non_negative_int(carrier_metadata: CarrierMetadata, *, key: str) -> int:
    """Require a non-negative integer metadata field."""

    value = carrier_metadata.get(key)
    if not isinstance(value, Integral):
        raise TypeError(f"carrier_metadata['{key}'] must be an integer.")
    normalized = int(value)
    if normalized < 0:
        raise ValueError(f"carrier_metadata['{key}'] must be >= 0.")
    return normalized


def _render_config_for_display(selected_config: SelectedConfig) -> SelectedConfig:
    """Convert non-serializable runtime objects into display-friendly values."""

    display_config = dict(selected_config)
    engine_class = display_config.get("engine_class")
    if isinstance(engine_class, type) and issubclass(engine_class, StegoEngine):
        display_config["engine_class"] = engine_class.__name__
    return display_config


def render_policy_log(
    *,
    selected_config: Mapping[str, Any],
    justification_trace: Sequence[str],
) -> Table:
    """Render selector reasoning as an explainable Rich policy log.

    The table is designed for predictable CLI feedback: the selected engine,
    capacity policy, and every fired rule are visible in one place.
    """

    table = Table(title="Selector Policy Log", show_lines=True)
    table.add_column("#", justify="right", style="cyan", no_wrap=True)
    table.add_column("Predictable Decision Point", style="bold white")
    table.add_column("Feedback", style="green")

    engine = str(selected_config.get("engine_name", "unknown"))
    carrier_format = str(selected_config.get("carrier_format", "unknown"))
    mode = selected_config.get("mode") or (
        "robust DCT" if selected_config.get("robust_mode") else "standard DCT"
    )
    table.add_row(
        "0",
        "Selected engine",
        f"{engine} for {carrier_format} carrier using {mode}.",
    )
    for index, entry in enumerate(justification_trace, start=1):
        table.add_row(str(index), _policy_category(entry), entry)
    return table


def print_policy_log(
    *,
    selected_config: Mapping[str, Any],
    justification_trace: Sequence[str],
    console: Console | None = None,
) -> None:
    """Print selector reasoning using Rich."""

    target = console or _console
    target.print(
        render_policy_log(
            selected_config=selected_config,
            justification_trace=justification_trace,
        )
    )


def _policy_category(entry: str) -> str:
    """Classify a policy log entry for quick scanning."""

    if "Carrier format" in entry:
        return "Carrier policy"
    if "expected_transformations" in entry or "Expected lossy" in entry:
        return "Threat expectation"
    if "capacity" in entry.lower() or "Payload size" in entry:
        return "Capacity feedback"
    if "Reed-Solomon" in entry:
        return "Reliability policy"
    return "Selector rule"


def _print_scenario(
    *,
    name: str,
    selector: ExplainableSelector,
    carrier_metadata: CarrierMetadata,
    payload_size_bits: int,
    expected_transformations: Sequence[str],
) -> None:
    """Execute and pretty-print one selector scenario."""

    print(f"=== {name} ===")
    selected_config, trace = selector.select_configuration(
        carrier_metadata=carrier_metadata,
        payload_size_bits=payload_size_bits,
        expected_transformations=expected_transformations,
    )
    print("Selected Configuration:")
    pprint(_render_config_for_display(selected_config), sort_dicts=False)
    print_policy_log(selected_config=selected_config, justification_trace=trace)
    print()


if __name__ == "__main__":
    selector = ExplainableSelector()

    png_metadata: CarrierMetadata = {
        "format": "PNG",
        "width": 1024,
        "height": 768,
        "channels": 3,
    }
    jpeg_metadata: CarrierMetadata = {
        "format": "JPEG",
        "non_zero_ac_count": 196_000,
        "robust_non_zero_ac_count": 120_000,
    }

    _print_scenario(
        name="Scenario 1: PNG carrier expecting noise",
        selector=selector,
        carrier_metadata=png_metadata,
        payload_size_bits=8_192,
        expected_transformations=["noise"],
    )

    _print_scenario(
        name="Scenario 2: JPEG carrier expecting recompression",
        selector=selector,
        carrier_metadata=jpeg_metadata,
        payload_size_bits=4_096,
        expected_transformations=["jpeg_recompression", "metadata_stripping"],
    )
