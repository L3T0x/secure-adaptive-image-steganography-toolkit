from __future__ import annotations

import pytest

from crypto_layer import Argon2Parameters, AuthenticationError, CryptoLayer


def test_aes_gcm_fails_closed_when_ciphertext_is_tampered() -> None:
    params = Argon2Parameters(
        memory_cost_kib=8192,
        iterations=1,
        lanes=1,
        salt_bytes=16,
    )
    layer = CryptoLayer(argon2=params)
    envelope = bytearray(layer.encrypt(b"confidential payload", "correct-password"))

    envelope[-1] ^= 0x01

    with pytest.raises(AuthenticationError):
        layer.decrypt(bytes(envelope), "correct-password")


def test_aes_gcm_fails_closed_with_wrong_password() -> None:
    params = Argon2Parameters(
        memory_cost_kib=8192,
        iterations=1,
        lanes=1,
        salt_bytes=16,
    )
    layer = CryptoLayer(argon2=params)
    envelope = layer.encrypt(b"confidential payload", "correct-password")

    with pytest.raises(AuthenticationError):
        layer.decrypt(envelope, "wrong-password")
