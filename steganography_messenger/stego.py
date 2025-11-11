"""Least significant bit steganography helpers."""
from __future__ import annotations

import os
import struct
from typing import Callable, Optional

import numpy as np
from PIL import Image


MAGIC = b"SGM1"
HEADER_SIZE = 8  # magic (4) + payload length (4)
SALT_SIZE = 16
PASSWORD_HASH_SIZE = 32

ProgressCallback = Optional[Callable[[float], None]]


def _bytes_to_bits(data: bytes) -> np.ndarray:
    bits = np.unpackbits(np.frombuffer(data, dtype=np.uint8), bitorder="big")
    return bits.astype(np.uint8)


def _bits_to_bytes(bits: np.ndarray, expected_bytes: Optional[int] = None) -> bytes:
    if bits.size == 0:
        return b""
    pad = (-bits.size) % 8
    if pad:
        bits = np.pad(bits, (0, pad), constant_values=0)
    packed = np.packbits(bits, bitorder="big").tobytes()
    if expected_bytes is None:
        return packed
    return packed[:expected_bytes]


def _invoke_progress(callback: ProgressCallback, value: float) -> None:
    if callback is not None:
        callback(max(0.0, min(100.0, value)))


def embed_payload(image_path: str, payload: bytes, output_path: str, progress: ProgressCallback = None) -> None:
    """Embed the payload bytes into the least significant bits of the image."""

    if not payload:
        raise ValueError("Payload is empty; nothing to embed")

    with Image.open(image_path) as img:
        img = img.convert("RGB")
        arr = np.array(img)

    total_capacity_bits = arr.size
    payload_bits = _bytes_to_bits(payload)
    if payload_bits.size > total_capacity_bits:
        raise ValueError(
            "Payload is too large for the selected image. "
            f"Capacity: {total_capacity_bits // 8} bytes, payload: {payload_bits.size // 8} bytes"
        )

    flat = arr.reshape(-1)
    _invoke_progress(progress, 40.0)

    flat[: payload_bits.size] = (flat[: payload_bits.size] & 0xFE) | payload_bits
    _invoke_progress(progress, 80.0)

    embedded = flat.reshape(arr.shape)
    stego_image = Image.fromarray(embedded, mode="RGB")
    stego_image.save(output_path)
    _invoke_progress(progress, 100.0)


def extract_payload(image_path: str, progress: ProgressCallback = None) -> bytes:
    """Extract the payload from an image and return the raw bytes."""

    with Image.open(image_path) as img:
        img = img.convert("RGB")
        arr = np.array(img)

    bits = (arr.reshape(-1) & 0x01).astype(np.uint8)
    if bits.size < HEADER_SIZE * 8:
        raise ValueError("Image does not contain an embedded payload")

    header_bits = bits[: HEADER_SIZE * 8]
    header = _bits_to_bytes(header_bits, expected_bytes=HEADER_SIZE)
    if header[:4] != MAGIC:
        raise ValueError("Image does not contain Steganography Messenger data")

    payload_length = struct.unpack(">I", header[4:8])[0]
    total_bytes = HEADER_SIZE + payload_length
    total_bits = total_bytes * 8
    if total_bits > bits.size:
        raise ValueError("Image appears to contain truncated payload data")

    _invoke_progress(progress, 60.0)
    payload_bits = bits[:total_bits]
    payload = _bits_to_bytes(payload_bits, expected_bytes=total_bytes)
    _invoke_progress(progress, 100.0)
    return payload


def build_payload(
    encrypted_message: bytes,
    md5_digest: bytes,
    password: str,
    salt: Optional[bytes] = None,
) -> bytes:
    """Construct a payload ready for embedding."""

    if len(md5_digest) != 16:
        raise ValueError("MD5 digest must be 16 bytes long")
    if not encrypted_message:
        raise ValueError("Encrypted message must not be empty")

    salt = salt or os.urandom(SALT_SIZE)
    from .crypto_utils import derive_password_hash

    password_hash = derive_password_hash(password, salt)
    body = b"".join(
        [
            salt,
            password_hash,
            struct.pack(">I", len(encrypted_message)),
            struct.pack(">I", len(md5_digest)),
            encrypted_message,
            md5_digest,
        ]
    )
    header = MAGIC + struct.pack(">I", len(body))
    return header + body


def parse_payload(payload: bytes, password: str) -> tuple[bytes, bytes]:
    """Parse and validate a payload returning (encrypted, md5)."""

    if len(payload) < HEADER_SIZE:
        raise ValueError("Payload too small")
    if payload[:4] != MAGIC:
        raise ValueError("Invalid payload header")

    body_len = struct.unpack(">I", payload[4:8])[0]
    expected_total = HEADER_SIZE + body_len
    if len(payload) < expected_total:
        raise ValueError("Payload data truncated")

    body = payload[8:expected_total]
    salt = body[:SALT_SIZE]
    password_hash = body[SALT_SIZE : SALT_SIZE + PASSWORD_HASH_SIZE]

    from .crypto_utils import derive_password_hash

    if derive_password_hash(password, salt) != password_hash:
        raise PermissionError("Incorrect password provided")

    offset = SALT_SIZE + PASSWORD_HASH_SIZE
    encrypted_length = struct.unpack(">I", body[offset : offset + 4])[0]
    offset += 4
    md5_length = struct.unpack(">I", body[offset : offset + 4])[0]
    offset += 4

    encrypted_message = body[offset : offset + encrypted_length]
    offset += encrypted_length
    md5_digest = body[offset : offset + md5_length]

    if len(encrypted_message) != encrypted_length or len(md5_digest) != md5_length:
        raise ValueError("Payload structure is invalid")
    if md5_length != 16:
        raise ValueError("MD5 digest length mismatch")

    return encrypted_message, md5_digest


__all__ = [
    "build_payload",
    "embed_payload",
    "extract_payload",
    "parse_payload",
]