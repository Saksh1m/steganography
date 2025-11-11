"""Utility helpers for RSA encryption/decryption and hashing."""
from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from typing import Optional

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto import Random


DEFAULT_RSA_BITS = 2048


class RSAKeyError(Exception):
    """Raised when RSA key operations fail."""


@dataclass
class RSAKeyPair:
    """Container describing an RSA key pair."""

    private_key: RSA.RsaKey
    public_key: RSA.RsaKey


def generate_rsa_keypair(bits: int = DEFAULT_RSA_BITS) -> RSAKeyPair:
    """Generate an RSA key pair with the provided key size."""

    if bits < 1024:
        raise ValueError("RSA key size must be at least 1024 bits")
    private_key = RSA.generate(bits, Random.get_random_bytes)
    return RSAKeyPair(private_key=private_key, public_key=private_key.publickey())


def save_private_key(key: RSA.RsaKey, path: str, passphrase: Optional[str] = None) -> None:
    """Persist a private key to disk in PEM format."""

    pem = key.export_key(format="PEM", passphrase=passphrase)
    with open(path, "wb") as handle:
        handle.write(pem)


def save_public_key(key: RSA.RsaKey, path: str) -> None:
    """Persist a public key to disk in PEM format."""

    pem = key.export_key(format="PEM")
    with open(path, "wb") as handle:
        handle.write(pem)


def load_public_key(path: str) -> RSA.RsaKey:
    """Load an RSA public key from a PEM file."""

    try:
        with open(path, "rb") as handle:
            data = handle.read()
        return RSA.import_key(data)
    except (ValueError, OSError) as exc:
        raise RSAKeyError("Unable to load the public key") from exc


def load_private_key(path: str, passphrase: Optional[str] = None) -> RSA.RsaKey:
    """Load an RSA private key from a PEM file."""

    try:
        with open(path, "rb") as handle:
            data = handle.read()
        return RSA.import_key(data, passphrase=passphrase)
    except (ValueError, OSError) as exc:
        raise RSAKeyError("Unable to load the private key") from exc


def max_message_length(key: RSA.RsaKey) -> int:
    """Return the maximum plaintext size supported by the key when using OAEP."""

    cipher = PKCS1_OAEP.new(key)
    hash_size = cipher._hashObj.digest_size  # type: ignore[attr-defined]
    return key.size_in_bytes() - 2 * hash_size - 2


def encrypt_message(message: str, public_key: RSA.RsaKey) -> bytes:
    """Encrypt a UTF-8 message using RSA OAEP."""

    cipher = PKCS1_OAEP.new(public_key)
    data = message.encode("utf-8")
    limit = max_message_length(public_key)
    if len(data) > limit:
        raise ValueError(
            "Message too long for the supplied RSA key. "
            f"Maximum size is {limit} bytes, got {len(data)} bytes."
        )
    return cipher.encrypt(data)


def decrypt_message(ciphertext: bytes, private_key: RSA.RsaKey) -> str:
    """Decrypt RSA OAEP ciphertext and return a UTF-8 string."""

    cipher = PKCS1_OAEP.new(private_key)
    data = cipher.decrypt(ciphertext)
    return data.decode("utf-8")


def compute_md5(message: str) -> bytes:
    """Compute the MD5 digest of a string (stored as bytes)."""

    return hashlib.md5(message.encode("utf-8")).digest()


def derive_password_hash(password: str, salt: bytes) -> bytes:
    """Derive a SHA-256 hash using the provided password and salt."""

    return hashlib.sha256(salt + password.encode("utf-8")).digest()


def remove_file_secure(path: str) -> None:
    """Attempt secure deletion by overwriting before removing."""

    if not os.path.exists(path):
        return

    try:
        size = os.path.getsize(path)
        with open(path, "r+b", buffering=0) as handle:
            handle.seek(0)
            handle.write(os.urandom(size))
        os.remove(path)
    except OSError:
        # Fallback: best effort removal
        try:
            os.remove(path)
        except OSError:
            pass


__all__ = [
    "RSAKeyError",
    "RSAKeyPair",
    "generate_rsa_keypair",
    "save_private_key",
    "save_public_key",
    "load_public_key",
    "load_private_key",
    "max_message_length",
    "encrypt_message",
    "decrypt_message",
    "compute_md5",
    "derive_password_hash",
    "remove_file_secure",
]