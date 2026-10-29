"""Cryptographic payload protection for the steganography toolkit.

This module implements a fail-closed cryptographic pipeline for payloads that
will later be embedded into images by the steganography engines. Payloads are
never embedded as plaintext: callers must first encrypt them with this module,
which derives an AES key using Argon2id and then performs authenticated
encryption using AES-GCM.

Design goals:

1. Secure defaults suitable for offline local execution.
2. Self-describing serialized envelopes so future defaults can evolve safely.
3. Strict tamper-fail behavior: modified ciphertext, wrong passphrases, or
   mismatched associated data must produce an explicit integrity error and no
   partial plaintext.
4. No plaintext logging or debug output.

The serialized envelope format is binary and authenticated. Its header is used
as internal AEAD associated data so parameter tampering is detected during
decryption.
"""

from __future__ import annotations

import base64
import binascii
from datetime import datetime, timezone
from dataclasses import dataclass, field
import hashlib
import json
import logging
import os
from pathlib import Path
import secrets
import struct
import threading
from typing import Final, Union

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

BytesLike = Union[bytes, bytearray, memoryview]
SecretInput = Union[str, bytes, bytearray, memoryview]

logger = logging.getLogger(__name__)

__all__ = [
    "AES_GCM_NONCE_BYTES",
    "AES_GCM_TAG_BYTES",
    "AES_256_KEY_BYTES",
    "Argon2Parameters",
    "CipherEnvelope",
    "CryptoLayer",
    "CryptoLayerError",
    "EnvelopeFormatError",
    "AuthenticationError",
    "IntegrityError",
    "NonceExhaustedError",
    "UnsupportedEnvelopeError",
    "decrypt_payload",
    "encrypt_payload",
]

_MAGIC: Final[bytes] = b"SAISTK01"
_FORMAT_VERSION: Final[int] = 1
_KDF_ID_ARGON2ID: Final[int] = 1
_CIPHER_ID_AES_GCM: Final[int] = 1

AES_256_KEY_BYTES: Final[int] = 32
AES_GCM_NONCE_BYTES: Final[int] = 12
AES_GCM_TAG_BYTES: Final[int] = 16
ARGON2_DEFAULT_MEMORY_COST_KIB: Final[int] = 262_144
ARGON2_DEFAULT_ITERATIONS: Final[int] = 3
ARGON2_DEFAULT_LANES: Final[int] = 4
ARGON2_DEFAULT_SALT_BYTES: Final[int] = 16

_HEADER_STRUCT: Final[struct.Struct] = struct.Struct(">8sBBBBBBIIII")
_MAX_COMPONENT_BYTES: Final[int] = 255
_MAX_CIPHERTEXT_BYTES: Final[int] = 2**32 - 1
_NONCE_COUNTER_PREFIX_BYTES: Final[int] = 4
_NONCE_COUNTER_VALUE_BYTES: Final[int] = 8
_MAX_AES_GCM_NONCE_COUNTER: Final[int] = 2**64 - 1
_NONCE_COUNTER_STORE_VERSION: Final[int] = 1
_DEFAULT_NONCE_COUNTER_STORE: Final[Path] = Path("logs/aes_gcm_nonce_counters.json")
_NONCE_COUNTER_LOCK: Final[threading.Lock] = threading.Lock()


class CryptoLayerError(Exception):
    """Base exception for all crypto-layer failures."""


class EnvelopeFormatError(CryptoLayerError):
    """Raised when a serialized envelope is malformed or truncated."""


class UnsupportedEnvelopeError(CryptoLayerError):
    """Raised when an envelope uses an unsupported format or algorithm."""


class IntegrityError(CryptoLayerError):
    """Raised when authenticated decryption fails.

    This error is intentionally ambiguous about the exact cause because AES-GCM
    tag failures may indicate ciphertext tampering, metadata tampering,
    mismatched associated data, or an incorrect passphrase.
    """


class AuthenticationError(IntegrityError):
    """Raised when AEAD authentication fails for a payload envelope."""


class NonceExhaustedError(CryptoLayerError):
    """Raised when the AES-GCM monotonic nonce counter reaches its maximum."""


@dataclass(frozen=True, slots=True)
class Argon2Parameters:
    """Parameter set for Argon2id key derivation.

    Defaults are intentionally conservative for a desktop/offline workflow:
    256 MiB memory, 3 iterations, and 4 lanes. This normally lands in the
    requested moderate-to-high range on modern systems while still remaining
    practical for local use.
    """

    memory_cost_kib: int = ARGON2_DEFAULT_MEMORY_COST_KIB
    iterations: int = ARGON2_DEFAULT_ITERATIONS
    lanes: int = ARGON2_DEFAULT_LANES
    salt_bytes: int = ARGON2_DEFAULT_SALT_BYTES
    key_bytes: int = AES_256_KEY_BYTES

    def validate(self) -> None:
        """Validate the parameter set before use.

        Raises:
            ValueError: If any parameter is insecure, malformed, or unsupported.
        """

        if self.memory_cost_kib < 8 * self.lanes:
            raise ValueError(
                "Argon2 memory_cost_kib must be at least 8 * lanes per RFC 9106."
            )
        if self.iterations < 1:
            raise ValueError("Argon2 iterations must be >= 1.")
        if self.lanes < 1:
            raise ValueError("Argon2 lanes must be >= 1.")
        if not 16 <= self.salt_bytes <= _MAX_COMPONENT_BYTES:
            raise ValueError("salt_bytes must be between 16 and 255.")
        if self.key_bytes not in (16, 24, 32):
            raise ValueError("AES-GCM key_bytes must be one of 16, 24, or 32.")


@dataclass(frozen=True, slots=True)
class CipherEnvelope:
    """Self-describing encrypted payload container.

    The envelope stores the KDF parameters, salt, nonce, and AES-GCM ciphertext.
    Its header is authenticated as internal associated data, so parameter
    tampering is detected at decrypt time.
    """

    argon2: Argon2Parameters
    salt: bytes
    nonce: bytes
    ciphertext: bytes
    version: int = _FORMAT_VERSION
    kdf_id: int = _KDF_ID_ARGON2ID
    cipher_id: int = _CIPHER_ID_AES_GCM

    def __post_init__(self) -> None:
        self.argon2.validate()
        if len(self.salt) != self.argon2.salt_bytes:
            raise ValueError("Salt length does not match the serialized KDF parameters.")
        if not 8 <= len(self.nonce) <= _MAX_COMPONENT_BYTES:
            raise ValueError("AES-GCM nonce length must be between 8 and 255 bytes.")
        if len(self.ciphertext) < AES_GCM_TAG_BYTES:
            raise ValueError("Ciphertext is too short to contain a valid GCM tag.")
        if len(self.ciphertext) > _MAX_CIPHERTEXT_BYTES:
            raise ValueError("Ciphertext exceeds the maximum supported envelope size.")

    def header_bytes(self) -> bytes:
        """Serialize the authenticated envelope header."""

        return _pack_header(
            version=self.version,
            kdf_id=self.kdf_id,
            cipher_id=self.cipher_id,
            argon2=self.argon2,
            nonce_len=len(self.nonce),
            ciphertext_len=len(self.ciphertext),
        )

    def to_bytes(self) -> bytes:
        """Serialize the envelope into a compact binary representation."""

        return self.header_bytes() + self.salt + self.nonce + self.ciphertext

    def to_base64(self) -> str:
        """Serialize the envelope as a URL-safe base64 string."""

        return base64.urlsafe_b64encode(self.to_bytes()).decode("ascii")

    @classmethod
    def from_bytes(cls, blob: BytesLike) -> "CipherEnvelope":
        """Parse a serialized envelope.

        Args:
            blob: Raw serialized envelope bytes.

        Returns:
            Parsed :class:`CipherEnvelope`.

        Raises:
            EnvelopeFormatError: If the blob is malformed or truncated.
            UnsupportedEnvelopeError: If the format or algorithms are unsupported.
        """

        raw = _coerce_bytes(blob, field_name="blob", allow_empty=False)
        if len(raw) < _HEADER_STRUCT.size:
            raise EnvelopeFormatError("Envelope is too short to contain a valid header.")

        (
            magic,
            version,
            kdf_id,
            cipher_id,
            salt_len,
            nonce_len,
            key_len,
            memory_cost_kib,
            iterations,
            lanes,
            ciphertext_len,
        ) = _HEADER_STRUCT.unpack_from(raw, 0)

        if magic != _MAGIC:
            raise UnsupportedEnvelopeError("Envelope magic is not recognized.")
        if version != _FORMAT_VERSION:
            raise UnsupportedEnvelopeError(
                f"Unsupported envelope version: {version}."
            )
        if kdf_id != _KDF_ID_ARGON2ID:
            raise UnsupportedEnvelopeError(f"Unsupported KDF identifier: {kdf_id}.")
        if cipher_id != _CIPHER_ID_AES_GCM:
            raise UnsupportedEnvelopeError(
                f"Unsupported cipher identifier: {cipher_id}."
            )
        if salt_len < 16 or nonce_len < 8:
            raise EnvelopeFormatError("Envelope declares insecure salt or nonce lengths.")
        if key_len not in (16, 24, 32):
            raise EnvelopeFormatError("Envelope declares an invalid AES key length.")
        if ciphertext_len < AES_GCM_TAG_BYTES:
            raise EnvelopeFormatError(
                "Envelope declares a ciphertext shorter than the GCM tag length."
            )

        header_len = _HEADER_STRUCT.size
        expected_len = header_len + salt_len + nonce_len + ciphertext_len
        if expected_len != len(raw):
            raise EnvelopeFormatError(
                "Envelope length does not match its declared component sizes."
            )

        salt_start = header_len
        salt_end = salt_start + salt_len
        nonce_end = salt_end + nonce_len

        salt = raw[salt_start:salt_end]
        nonce = raw[salt_end:nonce_end]
        ciphertext = raw[nonce_end:]

        params = Argon2Parameters(
            memory_cost_kib=memory_cost_kib,
            iterations=iterations,
            lanes=lanes,
            salt_bytes=salt_len,
            key_bytes=key_len,
        )

        return cls(
            argon2=params,
            salt=salt,
            nonce=nonce,
            ciphertext=ciphertext,
            version=version,
            kdf_id=kdf_id,
            cipher_id=cipher_id,
        )

    @classmethod
    def from_base64(cls, value: str) -> "CipherEnvelope":
        """Parse a URL-safe base64 encoded serialized envelope."""

        if not value:
            raise EnvelopeFormatError("Base64 envelope value must not be empty.")
        try:
            raw = base64.urlsafe_b64decode(value.encode("ascii"))
        except (UnicodeEncodeError, ValueError, binascii.Error) as exc:
            raise EnvelopeFormatError("Envelope is not valid URL-safe base64.") from exc
        return cls.from_bytes(raw)


@dataclass(frozen=True, slots=True)
class CryptoLayer:
    """High-level API for payload encryption and decryption.

    The class encapsulates secure defaults so later steganography modules can
    treat encryption as a mandatory preprocessing step.
    """

    argon2: Argon2Parameters = field(default_factory=Argon2Parameters)
    nonce_bytes: int = AES_GCM_NONCE_BYTES
    use_monotonic_nonce_counter: bool = True
    nonce_counter_store: Path | None = None

    def __post_init__(self) -> None:
        self.argon2.validate()
        if not 8 <= self.nonce_bytes <= _MAX_COMPONENT_BYTES:
            raise ValueError("nonce_bytes must be between 8 and 255.")
        if self.use_monotonic_nonce_counter and self.nonce_bytes != AES_GCM_NONCE_BYTES:
            raise ValueError(
                "Monotonic AES-GCM nonce generation requires the default 96-bit nonce size."
            )

    def encrypt_envelope(
        self,
        plaintext: BytesLike,
        passphrase: SecretInput,
        *,
        associated_data: BytesLike | None = None,
        salt: bytes | None = None,
        nonce: bytes | None = None,
    ) -> CipherEnvelope:
        """Encrypt a payload into a structured envelope.

        Args:
            plaintext: Bytes to protect before steganographic embedding.
            passphrase: User secret used for Argon2id key derivation.
            associated_data: Optional external AEAD associated data. This value
                is authenticated but not stored inside the envelope, so callers
                must supply the same bytes during decryption.
            salt: Optional explicit Argon2id salt. If omitted, a cryptographic
                random salt is generated.
            nonce: Optional explicit AES-GCM nonce. If omitted, the default
                policy creates a nonce from a per-key monotonic counter.

        Returns:
            A structured :class:`CipherEnvelope`.
        """

        plain = _coerce_bytes(plaintext, field_name="plaintext", allow_empty=True)
        password = _normalize_passphrase(passphrase)
        auth_context = _coerce_optional_bytes(associated_data)

        if salt is None:
            logger.info(
                "Live Log: generating Argon2id salt (%d bytes, value not logged).",
                self.argon2.salt_bytes,
            )
            actual_salt = secrets.token_bytes(self.argon2.salt_bytes)
        else:
            logger.info("Live Log: using caller-provided Argon2id salt (value not logged).")
            actual_salt = salt

        if nonce is None:
            if self.use_monotonic_nonce_counter:
                logger.info(
                    "Live Log: deriving AES-GCM nonce from monotonic counter "
                    "(%d bytes, value not logged).",
                    self.nonce_bytes,
                )
                actual_nonce = _next_counter_nonce(
                    salt=actual_salt,
                    argon2=self.argon2,
                    nonce_bytes=self.nonce_bytes,
                    store_path=self.nonce_counter_store or _DEFAULT_NONCE_COUNTER_STORE,
                )
            else:
                logger.info(
                    "Live Log: generating AES-GCM nonce (%d bytes, value not logged).",
                    self.nonce_bytes,
                )
                actual_nonce = secrets.token_bytes(self.nonce_bytes)
        else:
            logger.info("Live Log: using caller-provided AES-GCM nonce (value not logged).")
            actual_nonce = nonce

        if len(actual_salt) != self.argon2.salt_bytes:
            raise ValueError("Provided salt length does not match argon2.salt_bytes.")
        if len(actual_nonce) != self.nonce_bytes:
            raise ValueError("Provided nonce length does not match nonce_bytes.")

        logger.info(
            "Live Log: deriving AES key with Argon2id (memory=%d KiB, iterations=%d, lanes=%d).",
            self.argon2.memory_cost_kib,
            self.argon2.iterations,
            self.argon2.lanes,
        )
        key = _derive_key(password=password, salt=actual_salt, params=self.argon2)
        ciphertext_len = len(plain) + AES_GCM_TAG_BYTES
        internal_aad = _pack_header(
            version=_FORMAT_VERSION,
            kdf_id=_KDF_ID_ARGON2ID,
            cipher_id=_CIPHER_ID_AES_GCM,
            argon2=self.argon2,
            nonce_len=len(actual_nonce),
            ciphertext_len=ciphertext_len,
        )
        aesgcm = AESGCM(key)
        logger.info(
            "Live Log: encrypting payload with AES-%d-GCM and authenticated envelope header.",
            self.argon2.key_bytes * 8,
        )
        ciphertext = aesgcm.encrypt(actual_nonce, plain, internal_aad + auth_context)

        return CipherEnvelope(
            argon2=self.argon2,
            salt=actual_salt,
            nonce=actual_nonce,
            ciphertext=ciphertext,
        )

    def encrypt(
        self,
        plaintext: BytesLike,
        passphrase: SecretInput,
        *,
        associated_data: BytesLike | None = None,
        salt: bytes | None = None,
        nonce: bytes | None = None,
    ) -> bytes:
        """Encrypt a payload and return its serialized envelope bytes."""

        return self.encrypt_envelope(
            plaintext=plaintext,
            passphrase=passphrase,
            associated_data=associated_data,
            salt=salt,
            nonce=nonce,
        ).to_bytes()

    def decrypt(
        self,
        envelope: BytesLike | CipherEnvelope,
        passphrase: SecretInput,
        *,
        associated_data: BytesLike | None = None,
    ) -> bytes:
        """Decrypt a serialized envelope or parsed envelope object.

        Args:
            envelope: Serialized bytes or a parsed :class:`CipherEnvelope`.
            passphrase: Passphrase used for decryption.
            associated_data: Optional external associated data that must exactly
                match the value supplied at encryption time.

        Returns:
            The recovered plaintext bytes.

        Raises:
            IntegrityError: If authentication fails for any reason.
            EnvelopeFormatError: If the envelope is malformed.
            UnsupportedEnvelopeError: If the envelope format is unsupported.
        """

        parsed = envelope if isinstance(envelope, CipherEnvelope) else CipherEnvelope.from_bytes(envelope)
        password = _normalize_passphrase(passphrase)
        auth_context = _coerce_optional_bytes(associated_data)

        key = _derive_key(password=password, salt=parsed.salt, params=parsed.argon2)
        aesgcm = AESGCM(key)
        logger.info("Live Log: authenticating and decrypting AES-GCM envelope.")
        try:
            return aesgcm.decrypt(
                parsed.nonce,
                parsed.ciphertext,
                parsed.header_bytes() + auth_context,
            )
        except InvalidTag as exc:
            raise AuthenticationError(
                "AES-GCM authentication failed; payload integrity cannot be verified."
            ) from exc


def encrypt_payload(
    plaintext: BytesLike,
    passphrase: SecretInput,
    *,
    associated_data: BytesLike | None = None,
    argon2: Argon2Parameters | None = None,
    nonce_bytes: int = AES_GCM_NONCE_BYTES,
    use_monotonic_nonce_counter: bool = True,
    nonce_counter_store: str | Path | None = None,
) -> bytes:
    """Convenience wrapper for one-shot payload encryption."""

    layer = CryptoLayer(
        argon2=argon2 or Argon2Parameters(),
        nonce_bytes=nonce_bytes,
        use_monotonic_nonce_counter=use_monotonic_nonce_counter,
        nonce_counter_store=Path(nonce_counter_store) if nonce_counter_store else None,
    )
    return layer.encrypt(
        plaintext=plaintext,
        passphrase=passphrase,
        associated_data=associated_data,
    )


def decrypt_payload(
    envelope: BytesLike | CipherEnvelope,
    passphrase: SecretInput,
    *,
    associated_data: BytesLike | None = None,
) -> bytes:
    """Convenience wrapper for one-shot payload decryption.

    The serialized envelope carries its own Argon2id parameters, so decryption
    can safely use a fresh ``CryptoLayer`` with default construction.
    """

    layer = CryptoLayer()
    return layer.decrypt(
        envelope=envelope,
        passphrase=passphrase,
        associated_data=associated_data,
    )


def _derive_key(
    *,
    password: bytes,
    salt: bytes,
    params: Argon2Parameters,
) -> bytes:
    """Derive an AES key from a passphrase using Argon2id."""

    params.validate()
    kdf = Argon2id(
        salt=salt,
        length=params.key_bytes,
        iterations=params.iterations,
        lanes=params.lanes,
        memory_cost=params.memory_cost_kib,
        ad=None,
        secret=None,
    )
    return kdf.derive(password)


def _pack_header(
    *,
    version: int,
    kdf_id: int,
    cipher_id: int,
    argon2: Argon2Parameters,
    nonce_len: int,
    ciphertext_len: int,
) -> bytes:
    """Serialize an authenticated envelope header."""

    return _HEADER_STRUCT.pack(
        _MAGIC,
        version,
        kdf_id,
        cipher_id,
        argon2.salt_bytes,
        nonce_len,
        argon2.key_bytes,
        argon2.memory_cost_kib,
        argon2.iterations,
        argon2.lanes,
        ciphertext_len,
    )


def _next_counter_nonce(
    *,
    salt: bytes,
    argon2: Argon2Parameters,
    nonce_bytes: int,
    store_path: Path,
) -> bytes:
    """Return a 96-bit AES-GCM nonce using a random prefix and monotonic counter."""

    if nonce_bytes != _NONCE_COUNTER_PREFIX_BYTES + _NONCE_COUNTER_VALUE_BYTES:
        raise ValueError("Counter-based AES-GCM nonce generation requires 96-bit nonces.")

    context_id = _nonce_counter_context_id(salt=salt, argon2=argon2)
    with _NONCE_COUNTER_LOCK:
        store = _load_nonce_counter_store(store_path)
        contexts = store.setdefault("contexts", {})
        if not isinstance(contexts, dict):
            raise EnvelopeFormatError("Nonce counter store contains an invalid context map.")

        raw_entry = contexts.get(context_id)
        if raw_entry is None:
            prefix = secrets.token_bytes(_NONCE_COUNTER_PREFIX_BYTES)
            current_counter = 0
        else:
            if not isinstance(raw_entry, dict):
                raise EnvelopeFormatError("Nonce counter context entry is invalid.")
            prefix = _decode_counter_prefix(raw_entry.get("prefix"))
            current_counter = _coerce_counter_value(raw_entry.get("counter"))

        if current_counter >= _MAX_AES_GCM_NONCE_COUNTER:
            raise NonceExhaustedError(
                "AES-GCM nonce counter exhausted for this key context; encryption denied."
            )

        next_counter = current_counter + 1
        contexts[context_id] = {
            "prefix": base64.urlsafe_b64encode(prefix).decode("ascii"),
            "counter": next_counter,
            "updated_utc": datetime.now(timezone.utc).isoformat(),
        }
        _write_nonce_counter_store(store_path, store)

    return prefix + next_counter.to_bytes(_NONCE_COUNTER_VALUE_BYTES, "big")


def _nonce_counter_context_id(*, salt: bytes, argon2: Argon2Parameters) -> str:
    """Build a non-secret identifier for the Argon2id/AES-GCM key context."""

    payload = b"|".join(
        [
            _MAGIC,
            str(_FORMAT_VERSION).encode("ascii"),
            str(_KDF_ID_ARGON2ID).encode("ascii"),
            str(_CIPHER_ID_AES_GCM).encode("ascii"),
            str(argon2.memory_cost_kib).encode("ascii"),
            str(argon2.iterations).encode("ascii"),
            str(argon2.lanes).encode("ascii"),
            str(argon2.key_bytes).encode("ascii"),
            salt,
        ]
    )
    return hashlib.sha256(payload).hexdigest()


def _load_nonce_counter_store(path: Path) -> dict[str, object]:
    """Load the local AES-GCM nonce counter store."""

    if not path.exists():
        return {"version": _NONCE_COUNTER_STORE_VERSION, "contexts": {}}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise EnvelopeFormatError("Nonce counter store is not valid JSON.") from exc
    if not isinstance(raw, dict):
        raise EnvelopeFormatError("Nonce counter store root must be a JSON object.")
    version = raw.get("version")
    if version != _NONCE_COUNTER_STORE_VERSION:
        raise UnsupportedEnvelopeError(
            f"Unsupported nonce counter store version: {version!r}."
        )
    if "contexts" not in raw:
        raw["contexts"] = {}
    return raw


def _write_nonce_counter_store(path: Path, store: dict[str, object]) -> None:
    """Persist the AES-GCM nonce counter store atomically."""

    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_name(f"{path.name}.tmp")
    temp_path.write_text(json.dumps(store, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(temp_path, path)


def _decode_counter_prefix(value: object) -> bytes:
    """Decode and validate a nonce-counter prefix from JSON."""

    if not isinstance(value, str) or not value:
        raise EnvelopeFormatError("Nonce counter prefix is missing or invalid.")
    try:
        prefix = base64.urlsafe_b64decode(value.encode("ascii"))
    except (UnicodeEncodeError, ValueError, binascii.Error) as exc:
        raise EnvelopeFormatError("Nonce counter prefix is not valid base64.") from exc
    if len(prefix) != _NONCE_COUNTER_PREFIX_BYTES:
        raise EnvelopeFormatError("Nonce counter prefix has an invalid length.")
    return prefix


def _coerce_counter_value(value: object) -> int:
    """Validate a stored AES-GCM nonce counter value."""

    if not isinstance(value, int):
        raise EnvelopeFormatError("Nonce counter value must be an integer.")
    if not 0 <= value <= _MAX_AES_GCM_NONCE_COUNTER:
        raise EnvelopeFormatError("Nonce counter value is outside the supported range.")
    return value


def _normalize_passphrase(value: SecretInput) -> bytes:
    """Normalize and validate a passphrase input."""

    if isinstance(value, str):
        encoded = value.encode("utf-8")
    else:
        encoded = _coerce_bytes(value, field_name="passphrase", allow_empty=False)
    if len(encoded) == 0:
        raise ValueError("Passphrase must not be empty.")
    return encoded


def _coerce_optional_bytes(value: BytesLike | None) -> bytes:
    """Normalize optional bytes-like input."""

    if value is None:
        return b""
    return _coerce_bytes(value, field_name="associated_data", allow_empty=True)


def _coerce_bytes(
    value: BytesLike,
    *,
    field_name: str,
    allow_empty: bool,
) -> bytes:
    """Normalize bytes-like inputs into immutable bytes."""

    if isinstance(value, bytes):
        result = value
    elif isinstance(value, bytearray):
        result = bytes(value)
    elif isinstance(value, memoryview):
        result = value.tobytes()
    else:
        raise TypeError(f"{field_name} must be bytes-like.")

    if not allow_empty and len(result) == 0:
        raise ValueError(f"{field_name} must not be empty.")
    return result
