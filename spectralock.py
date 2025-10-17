#!/usr/bin/env python3
"""
SpectraLock — password-protected steganography with optional Zenity dialogs.

Features:
    - Embed encrypted text inside PNG images by tweaking pixel least-significant bits.
    - Store encrypted text in JPEG images via custom metadata blocks to remain intact.
    - Recover the hidden text only when the correct password is provided.
"""

from __future__ import annotations

import os
import struct
import subprocess
import sys
from dataclasses import dataclass
from typing import Iterable, Optional, Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from PIL import Image


APP_NAME = "SpectraLock"
MAGIC = b"SLK1"
SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32
JPEG_APP_MARKER = 0xEF
JPEG_IDENTIFIER = b"SLKJ"
JPEG_META_STRUCT = struct.Struct(">HHI")
JPEG_CHUNK_SIZE = 60000


def _has_zenity() -> bool:
    """Return True if zenity is available on PATH."""
    from shutil import which

    return which("zenity") is not None


ZENITY_AVAILABLE = _has_zenity()


def _run_zenity(args: Iterable[str], input_text: Optional[str] = None) -> Optional[str]:
    """Run zenity with args and optional stdin, returning stdout stripped or None on cancel."""
    if not ZENITY_AVAILABLE:
        return None

    proc = subprocess.run(
        ["zenity", *args],
        input=input_text,
        text=True,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if proc.returncode != 0:
        return None
    return proc.stdout.rstrip("\n")


def _show_info(message: str, title: str = APP_NAME) -> None:
    """Display an informational message using zenity or stdout."""
    if ZENITY_AVAILABLE:
        _run_zenity(["--info", "--title", title, "--text", message])
    else:
        print(f"[{APP_NAME}] {message}")


def _show_error(message: str, title: str = f"{APP_NAME} error") -> None:
    """Display an error message using zenity or stderr."""
    if ZENITY_AVAILABLE:
        _run_zenity(["--error", "--title", title, "--text", message])
    else:
        print(f"[{APP_NAME} ERROR] {message}", file=sys.stderr)


def _ask_action() -> Optional[str]:
    """Ask the user to choose between encrypting or decrypting."""
    if ZENITY_AVAILABLE:
        choice = _run_zenity(
            [
                "--list",
                "--title",
                APP_NAME,
                "--text",
                "What should SpectraLock do?",
                "--column",
                "Action",
                "Encrypt and hide text",
                "Recover hidden text",
            ]
        )
        return choice

    prompt = (
        f"{APP_NAME} — select operation:\n"
        "1) Encrypt and hide text\n"
        "2) Recover hidden text\n"
        "Choice [1/2]: "
    )
    answer = input(prompt).strip()
    if answer == "1":
        return "Encrypt and hide text"
    if answer == "2":
        return "Recover hidden text"
    return None


def _ask_file(title: str, save: bool = False) -> Optional[str]:
    """Ask the user for a file path. save=True opens save dialog."""
    if ZENITY_AVAILABLE:
        args = ["--file-selection", "--title", title]
        if save:
            args.extend(["--save", "--confirm-overwrite"])
        path = _run_zenity(args)
        if not path:
            return None
        return path

    prompt = f"{title}\nFull path: "
    path = input(prompt).strip()
    return path or None


def _ask_message() -> Optional[str]:
    """Prompt for the plaintext message to embed."""
    if ZENITY_AVAILABLE:
        text = _run_zenity(
            [
                "--entry",
                "--title",
                "Text to hide",
                "--text",
                "Enter the text or URL to hide:",
            ]
        )
        return text

    try:
        return input("Enter the text or URL to hide: ")
    except EOFError:
        return None


def _ask_password(confirm: bool = False) -> Optional[str]:
    """Prompt for a password, optionally asking for confirmation."""
    if ZENITY_AVAILABLE:
        passwd = _run_zenity(["--password", "--title", "Encryption password"])
        if passwd is None:
            return None
        if confirm:
            confirm_pass = _run_zenity(
                ["--password", "--title", "Confirm encryption password"]
            )
            if confirm_pass is None or confirm_pass != passwd:
                _show_error("Passwords do not match.")
                return None
        return passwd

    try:
        import getpass

        pwd = getpass.getpass("Password: ")
        if confirm:
            pwd2 = getpass.getpass("Confirm password: ")
            if pwd != pwd2:
                _show_error("Passwords do not match.")
                return None
        return pwd
    except EOFError:
        return None


def _show_text_output(message: str, title: str = "Recovered text") -> None:
    """Display recovered plaintext."""
    if ZENITY_AVAILABLE:
        _run_zenity(
            [
                "--text-info",
                "--title",
                title,
                "--width",
                "400",
                "--height",
                "250",
            ],
            input_text=message,
        )
    else:
        print(message)


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive an AES key from password and salt using scrypt."""
    kdf = Scrypt(
        salt=salt,
        length=KEY_SIZE,
        n=2**14,
        r=8,
        p=1,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_message(password: str, plaintext: str) -> bytes:
    """Encrypt plaintext using password-derived key and return payload to embed."""
    salt = os.urandom(SALT_SIZE)
    key = derive_key(password, salt)
    nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    packet = MAGIC + salt + nonce + ciphertext
    length_prefix = struct.pack(">I", len(packet))
    return length_prefix + packet


def decrypt_message(password: str, payload: bytes) -> str:
    """Decrypt payload extracted from image."""
    if len(payload) < len(MAGIC) + SALT_SIZE + NONCE_SIZE:
        raise ValueError("Hidden data too short.")
    if not payload.startswith(MAGIC):
        raise ValueError("No recognizable hidden message in this image.")
    salt_start = len(MAGIC)
    nonce_start = salt_start + SALT_SIZE
    ciphertext = payload[nonce_start + NONCE_SIZE :]
    salt = payload[salt_start:nonce_start]
    nonce = payload[nonce_start:nonce_start + NONCE_SIZE]
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    try:
        plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, None)
    except InvalidTag as exc:
        raise ValueError("Incorrect password or corrupted data.") from exc
    return plaintext_bytes.decode("utf-8")


def _bytes_to_bits(data: bytes) -> list[int]:
    """Convert bytes to a list of bits (big-endian within each byte)."""
    bits: list[int] = []
    for byte in data:
        for shift in range(7, -1, -1):
            bits.append((byte >> shift) & 1)
    return bits


def _bits_to_bytes(bits: Iterable[int]) -> bytes:
    """Convert an iterable of bits to bytes (consumes bits length multiple of 8)."""
    bit_list = list(bits)
    if len(bit_list) % 8 != 0:
        raise ValueError("Invalid number of bits.")
    output = bytearray()
    for idx in range(0, len(bit_list), 8):
        byte = 0
        for bit in bit_list[idx : idx + 8]:
            byte = (byte << 1) | (bit & 1)
        output.append(byte)
    return bytes(output)


def _split_jpeg_prefix_suffix(data: bytes) -> Tuple[bytes, bytes]:
    """Remove existing SpectraLock APP segments and return prefix and suffix slices."""
    if not data.startswith(b"\xFF\xD8"):
        raise ValueError("Invalid JPEG file.")
    markers_no_length = {0x01} | set(range(0xD0, 0xD8))
    prefix = bytearray()
    prefix.extend(data[:2])  # SOI
    idx = 2
    length = len(data)

    while idx + 1 < length:
        if data[idx] != 0xFF:
            prefix.append(data[idx])
            idx += 1
            continue
        marker = data[idx + 1]
        start = idx
        if marker == 0xDA:  # Start of Scan
            suffix = data[start:]
            return bytes(prefix), suffix
        if marker == 0xD9:  # End of Image
            suffix = data[start:]
            prefix.extend(suffix)
            return bytes(prefix), b""
        idx += 2
        if marker in markers_no_length:
            prefix.extend(data[start:idx])
            continue
        if idx + 2 > length:
            raise ValueError("Truncated JPEG segment.")
        seg_length = (data[idx] << 8) + data[idx + 1]
        end = idx + seg_length
        if end > length:
            raise ValueError("Truncated JPEG segment data.")
        segment = data[start:end]
        segment_data = data[idx + 2 : end]
        if marker == JPEG_APP_MARKER and segment_data.startswith(JPEG_IDENTIFIER):
            idx = end
            continue
        prefix.extend(segment)
        idx = end

    # If we exit the loop without encountering SOS, treat entire data as prefix.
    return bytes(prefix), b""


def _build_jpeg_segments(payload: bytes) -> bytes:
    """Return byte string of APP segments carrying the payload."""
    if not payload:
        total_chunks = 1
    else:
        total_chunks = (len(payload) + JPEG_CHUNK_SIZE - 1) // JPEG_CHUNK_SIZE
    segments = []
    total_length = len(payload)
    for chunk_index in range(total_chunks):
        start = chunk_index * JPEG_CHUNK_SIZE
        end = start + JPEG_CHUNK_SIZE
        chunk = payload[start:end]
        header = JPEG_IDENTIFIER + JPEG_META_STRUCT.pack(
            total_chunks, chunk_index, total_length
        )
        segment_data = header + chunk
        segment_length = len(segment_data) + 2  # includes length field
        if segment_length > 0xFFFF:
            raise ValueError("Payload chunk too large for JPEG metadata.")
        segment = b"\xFF" + bytes([JPEG_APP_MARKER]) + struct.pack(
            ">H", segment_length
        ) + segment_data
        segments.append(segment)
    return b"".join(segments)


def _inject_payload_into_jpeg(path: str, payload: bytes) -> None:
    """Embed payload inside JPEG APP markers."""
    with open(path, "rb") as file:
        data = file.read()
    prefix, suffix = _split_jpeg_prefix_suffix(data)
    segments = _build_jpeg_segments(payload)
    with open(path, "wb") as file:
        file.write(prefix + segments + suffix)


def _extract_payload_from_jpeg(path: str) -> Optional[bytes]:
    """Extract payload stored in JPEG APP markers."""
    with open(path, "rb") as file:
        data = file.read()
    if not data.startswith(b"\xFF\xD8"):
        return None
    markers_no_length = {0x01} | set(range(0xD0, 0xD8))
    idx = 2
    length = len(data)
    chunks: dict[int, bytes] = {}
    total_chunks: Optional[int] = None
    total_length: Optional[int] = None

    while idx + 1 < length:
        if data[idx] != 0xFF:
            idx += 1
            continue
        marker = data[idx + 1]
        if marker == 0xDA or marker == 0xD9:
            break
        start = idx
        idx += 2
        if marker in markers_no_length:
            continue
        if idx + 2 > length:
            break
        seg_length = (data[idx] << 8) + data[idx + 1]
        end = idx + seg_length
        if end > length:
            break
        segment_data = data[idx + 2 : end]
        if marker == JPEG_APP_MARKER and segment_data.startswith(JPEG_IDENTIFIER):
            header_offset = len(JPEG_IDENTIFIER)
            if len(segment_data) < header_offset + JPEG_META_STRUCT.size:
                idx = end
                continue
            total_chunks_candidate, chunk_index, total_length_candidate = (
                JPEG_META_STRUCT.unpack_from(segment_data, header_offset)
            )
            chunk = segment_data[
                header_offset + JPEG_META_STRUCT.size :
            ]
            if total_chunks is None:
                total_chunks = total_chunks_candidate
                total_length = total_length_candidate
            if (
                total_chunks != total_chunks_candidate
                or total_length != total_length_candidate
            ):
                idx = end
                continue
            chunks[chunk_index] = chunk
        idx = end

    if not chunks or total_chunks is None or total_length is None:
        return None

    assembled = bytearray()
    for chunk_index in range(total_chunks):
        if chunk_index not in chunks:
            return None
        assembled.extend(chunks[chunk_index])
    return bytes(assembled[:total_length])


def _load_image_pixels(path: str) -> tuple[list[int], tuple[int, int]]:
    """Return flattened RGB pixel values and original dimensions."""
    with Image.open(path) as img:
        rgb_image = img.convert("RGB")
        width, height = rgb_image.size
        flat_pixels = [value for pixel in rgb_image.getdata() for value in pixel]
    return flat_pixels, (width, height)


def embed_payload_into_image(
    image_path: str, output_path: str, payload: bytes
) -> tuple[str, Optional[str]]:
    """Embed payload bytes into the image using least-significant bits.

    Returns the actual output path and optional warning string (e.g., JPEG fallback).
    """
    flat_pixels, size = _load_image_pixels(image_path)
    total_capacity_bits = len(flat_pixels)
    payload_bits = _bytes_to_bits(payload)
    required_bits = len(payload_bits)

    if required_bits > total_capacity_bits:
        raise ValueError(
            "Image too small. "
            f"Requires {required_bits} bits but only {total_capacity_bits} are available."
        )

    modified_pixels = flat_pixels[:]
    for idx, bit in enumerate(payload_bits):
        modified_pixels[idx] = (modified_pixels[idx] & 0xFE) | bit

    width, height = size
    pixel_list = list(modified_pixels)
    if len(pixel_list) != width * height * 3:
        raise ValueError("Pixel dimensions mismatch.")
    tuples = [
        tuple(pixel_list[i : i + 3]) for i in range(0, len(pixel_list), 3)
    ]
    image = Image.new("RGB", size)
    image.putdata(tuples)

    _, ext = os.path.splitext(output_path)
    if not ext:
        raise ValueError("Output filename must include an extension.")
    ext_lower = ext.lower()
    warning: Optional[str] = None

    if ext_lower in {".jpg", ".jpeg"}:
        image.save(output_path, format="JPEG", quality=100, subsampling=0, optimize=False)
        _inject_payload_into_jpeg(output_path, payload)
        warning = (
            "Payload stored inside JPEG metadata. Editing or recompressing the image "
            "may remove it."
        )
    elif ext_lower == ".png":
        image.save(output_path, format="PNG")
    else:
        raise ValueError("Unsupported output format. Use .png, .jpg, or .jpeg.")

    return output_path, warning


def extract_payload_from_image(image_path: str) -> bytes:
    """Extract embedded payload bytes from image."""
    ext = os.path.splitext(image_path)[1].lower()
    if ext in {".jpg", ".jpeg"}:
        jpeg_payload = _extract_payload_from_jpeg(image_path)
        if jpeg_payload is None:
            raise ValueError("No SpectraLock payload found in this JPEG.")
        return jpeg_payload

    flat_pixels, _ = _load_image_pixels(image_path)
    if len(flat_pixels) < 32:
        raise ValueError("Image too small or missing hidden data.")

    bits = [value & 1 for value in flat_pixels]
    length_bits = bits[:32]
    payload_length = 0
    for bit in length_bits:
        payload_length = (payload_length << 1) | bit

    total_bits_needed = payload_length * 8
    if payload_length <= 0:
        raise ValueError("No hidden message found.")

    if 32 + total_bits_needed > len(bits):
        raise ValueError("Incomplete data or corrupted image.")

    payload_bits = bits[32 : 32 + total_bits_needed]
    payload = _bits_to_bytes(payload_bits)
    length_prefix = struct.pack(">I", payload_length)
    return length_prefix + payload


@dataclass
class EncryptInputs:
    source_image: str
    output_image: str
    message: str
    password: str


def _gather_encrypt_inputs() -> Optional[EncryptInputs]:
    """Collect inputs for encryption workflow."""
    source = _ask_file("Select the source image")
    if not source:
        return None
    if not os.path.isfile(source):
        _show_error("Source image not found.")
        return None
    message = _ask_message()
    if message is None or message == "":
        _show_error("Text to hide cannot be empty.")
        return None

    password = _ask_password(confirm=True)
    if not password:
        return None

    output = _ask_file("Save image with hidden data", save=True)
    if not output:
        return None
    source_ext = os.path.splitext(source)[1]
    output_root, output_ext = os.path.splitext(output)
    if not output_ext:
        if source_ext:
            output = output_root + source_ext
        else:
            output = output_root + ".png"
        output_ext = os.path.splitext(output)[1]
    if output_ext.lower() not in {".png", ".jpg", ".jpeg"}:
        _show_error("Unsupported output format. Use .png, .jpg, or .jpeg.")
        return None

    return EncryptInputs(source, output, message, password)


def _encrypt_flow() -> None:
    """Handle the encrypt workflow end-to-end."""
    inputs = _gather_encrypt_inputs()
    if not inputs:
        return
    try:
        payload = encrypt_message(inputs.password, inputs.message)
        saved_path, warning = embed_payload_into_image(
            inputs.source_image, inputs.output_image, payload
        )
        message = f"Operation completed.\nFile saved to:\n{saved_path}"
        if warning:
            message += f"\n\nWarning: {warning}"
        _show_info(message)
    except Exception as exc:  # pylint: disable=broad-except
        _show_error(f"Unable to embed the message: {exc}")


def _decrypt_flow() -> None:
    """Handle the decrypt workflow end-to-end."""
    image_path = _ask_file("Select the image to analyze")
    if not image_path:
        return
    if not os.path.isfile(image_path):
        _show_error("Image not found.")
        return
    password = _ask_password()
    if not password:
        return

    try:
        payload = extract_payload_from_image(image_path)
        data_length = struct.unpack(">I", payload[:4])[0]
        if len(payload) < 4 + data_length:
            raise ValueError("Incomplete data or corrupted image.")
        packet = payload[4 : 4 + data_length]
        message = decrypt_message(password, packet)
        _show_text_output(message)
    except Exception as exc:  # pylint: disable=broad-except
        _show_error(f"Unable to recover the message: {exc}")


def main() -> None:
    if not ZENITY_AVAILABLE:
        print(
            f"{APP_NAME}: Zenity not detected. Falling back to terminal prompts.",
            file=sys.stderr,
        )
    choice = _ask_action()
    if choice == "Encrypt and hide text":
        _encrypt_flow()
    elif choice == "Recover hidden text":
        _decrypt_flow()
    else:
        if ZENITY_AVAILABLE:
            # Choice is None when dialog is closed.
            return
        _show_error("Invalid selection.")


if __name__ == "__main__":
    main()
