"""Envelope encryption, key-slot management, and chunked AES-256-GCM streaming.

Container wire format (v1):
    MAGIC       (10 bytes): b"SSHACRYPT\\x01"
    HEADER_LEN  (4 bytes) : uint32 big-endian length of canonical JSON header
    HEADER_JSON (N bytes) : UTF-8 canonical JSON (version, cipher, kdf, file_id,
                            nonce_prefix, chunk_size, slots[])
    HEADER_MAC  (32 bytes): HMAC-SHA256(header_mac_key, MAGIC || HEADER_LEN || HEADER_JSON)
    PAYLOAD     (stream)  : Sequence of framed AES-256-GCM chunks:
                              uint32 big-endian ct_len || ciphertext || 16-byte GCM tag
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Sequence

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .agent import (
    AgentKey,
    KeySelectionError,
    SSHAgentClient,
    compute_fingerprint,
    extract_key_type,
    parse_openssh_pubkey_file,
)

MAGIC = b"SSHACRYPT\x01"
FORMAT_VERSION = 1
CIPHER_NAME = "AES-256-GCM"
KDF_NAME = "HKDF-SHA256"

DEFAULT_CHUNK_SIZE = 65536  # 64 KiB
MIN_CHUNK_SIZE = 1024
MAX_CHUNK_SIZE = 16 * 1024 * 1024  # 16 MiB
MAX_HEADER_LEN = 4 * 1024 * 1024  # 4 MiB

DEK_LEN = 32
FILE_ID_LEN = 16
CHALLENGE_LEN = 32
WRAP_NONCE_LEN = 12
NONCE_PREFIX_LEN = 8
HEADER_MAC_LEN = 32
GCM_TAG_LEN = 16
MAX_CHUNKS = (1 << 32) - 1

# Domain separation labels
CHALLENGE_DOMAIN = b"ssh-agent-crypt-v1:kek-challenge\x00"
KEK_INFO_PREFIX = b"ssh-agent-crypt-v1:kek:"
SLOT_AAD_PREFIX = b"ssh-agent-crypt-v1:slot:"
PAYLOAD_KEY_INFO = b"ssh-agent-crypt-v1:payload-key"
HEADER_MAC_KEY_INFO = b"ssh-agent-crypt-v1:header-mac-key"
CHUNK_AAD_PREFIX = b"ssh-agent-crypt-v1:chunk:"


class CryptoFormatError(Exception):
    """Raised when an encrypted container is malformed or unsupported."""


class DecryptionError(Exception):
    """Raised when decryption or integrity verification fails."""


class KeyManagementError(Exception):
    """Raised when a key management operation cannot be safely completed."""


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(text: str, field_name: str, expected_len: int | None = None) -> bytes:
    if not isinstance(text, str):
        raise CryptoFormatError(f"Header field '{field_name}' must be a string")
    try:
        raw = base64.b64decode(text, validate=True)
    except ValueError as exc:
        raise CryptoFormatError(f"Header field '{field_name}' has invalid base64") from exc
    if expected_len is not None and len(raw) != expected_len:
        raise CryptoFormatError(
            f"Header field '{field_name}' expected {expected_len} bytes, got {len(raw)}"
        )
    return raw


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    """Derive a key using HKDF-SHA256."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    ).derive(ikm)


def derive_payload_key(dek: bytes, file_id: bytes) -> bytes:
    return hkdf_sha256(ikm=dek, salt=file_id, info=PAYLOAD_KEY_INFO, length=32)


def derive_header_mac_key(dek: bytes, file_id: bytes) -> bytes:
    return hkdf_sha256(ikm=dek, salt=file_id, info=HEADER_MAC_KEY_INFO, length=32)


def build_sign_input(file_id: bytes, challenge: bytes, key_blob: bytes) -> bytes:
    """Construct the domain-separated challenge signed by ssh-agent."""
    key_hash = hashlib.sha256(key_blob).digest()
    return CHALLENGE_DOMAIN + file_id + challenge + key_hash


def derive_kek(signature_blob: bytes, challenge: bytes, key_blob: bytes) -> bytes:
    """Derive a 256-bit Key Encryption Key from a deterministic ssh-agent signature."""
    key_hash = hashlib.sha256(key_blob).digest()
    return hkdf_sha256(
        ikm=signature_blob,
        salt=challenge,
        info=KEK_INFO_PREFIX + key_hash,
        length=32,
    )


def build_slot_aad(file_id: bytes, key_blob: bytes, challenge: bytes) -> bytes:
    key_hash = hashlib.sha256(key_blob).digest()
    return SLOT_AAD_PREFIX + file_id + key_hash + challenge


def build_chunk_nonce(nonce_prefix: bytes, chunk_index: int) -> bytes:
    return nonce_prefix + struct.pack(">I", chunk_index)


def build_chunk_aad(file_id: bytes, chunk_index: int, is_final: bool) -> bytes:
    return CHUNK_AAD_PREFIX + file_id + struct.pack(">IB", chunk_index, 1 if is_final else 0)


def compute_header_mac(dek: bytes, file_id: bytes, raw_header_bytes: bytes) -> bytes:
    mac_key = derive_header_mac_key(dek, file_id)
    mac_input = MAGIC + struct.pack(">I", len(raw_header_bytes)) + raw_header_bytes
    return hmac.new(mac_key, mac_input, hashlib.sha256).digest()


def verify_header_mac(
    dek: bytes, file_id: bytes, raw_header_bytes: bytes, expected_mac: bytes
) -> None:
    actual_mac = compute_header_mac(dek, file_id, raw_header_bytes)
    if not hmac.compare_digest(actual_mac, expected_mac):
        raise DecryptionError(
            "Header MAC verification failed: file header was tampered with or corrupted."
        )


@dataclass
class KeySlot:
    """Authorized SSH key slot containing a KEK-wrapped copy of the file DEK."""

    slot_id: str
    fingerprint: str
    key_type: str
    comment: str
    public_key_b64: str
    sign_flags: int
    challenge_b64: str
    wrap_nonce_b64: str
    wrapped_dek_b64: str

    @property
    def key_blob(self) -> bytes:
        return _b64d(self.public_key_b64, "slots[].public_key_b64")

    @property
    def challenge(self) -> bytes:
        return _b64d(self.challenge_b64, "slots[].challenge_b64", CHALLENGE_LEN)

    @property
    def wrap_nonce(self) -> bytes:
        return _b64d(self.wrap_nonce_b64, "slots[].wrap_nonce_b64", WRAP_NONCE_LEN)

    @property
    def wrapped_dek(self) -> bytes:
        return _b64d(
            self.wrapped_dek_b64, "slots[].wrapped_dek_b64", DEK_LEN + GCM_TAG_LEN
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "slot_id": self.slot_id,
            "fingerprint": self.fingerprint,
            "key_type": self.key_type,
            "comment": self.comment,
            "public_key_b64": self.public_key_b64,
            "sign_flags": self.sign_flags,
            "challenge_b64": self.challenge_b64,
            "wrap_nonce_b64": self.wrap_nonce_b64,
            "wrapped_dek_b64": self.wrapped_dek_b64,
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> KeySlot:
        if not isinstance(data, dict):
            raise CryptoFormatError("Each key slot must be a JSON object")
        required = (
            "slot_id",
            "fingerprint",
            "key_type",
            "comment",
            "public_key_b64",
            "sign_flags",
            "challenge_b64",
            "wrap_nonce_b64",
            "wrapped_dek_b64",
        )
        for field_name in required:
            if field_name not in data:
                raise CryptoFormatError(f"Key slot missing required field '{field_name}'")

        if not isinstance(data["sign_flags"], int) or isinstance(data["sign_flags"], bool):
            raise CryptoFormatError("Key slot 'sign_flags' must be an integer")
        if data["sign_flags"] < 0 or data["sign_flags"] > 0xFFFFFFFF:
            raise CryptoFormatError("Key slot 'sign_flags' out of range")

        slot = cls(
            slot_id=str(data["slot_id"]),
            fingerprint=str(data["fingerprint"]),
            key_type=str(data["key_type"]),
            comment=str(data["comment"]),
            public_key_b64=str(data["public_key_b64"]),
            sign_flags=int(data["sign_flags"]),
            challenge_b64=str(data["challenge_b64"]),
            wrap_nonce_b64=str(data["wrap_nonce_b64"]),
            wrapped_dek_b64=str(data["wrapped_dek_b64"]),
        )
        # Validate binary fields and self-consistency of public key blob
        blob = slot.key_blob
        actual_fp = compute_fingerprint(blob)
        if actual_fp != slot.fingerprint:
            raise CryptoFormatError(
                f"Slot {slot.slot_id} fingerprint mismatch ({slot.fingerprint} != {actual_fp})"
            )
        actual_type = extract_key_type(blob)
        if actual_type != slot.key_type:
            raise CryptoFormatError(
                f"Slot {slot.slot_id} key_type mismatch ({slot.key_type} != {actual_type})"
            )
        _ = slot.challenge
        _ = slot.wrap_nonce
        _ = slot.wrapped_dek
        return slot


@dataclass
class EncryptedHeader:
    """Authenticated container metadata header."""

    version: int
    cipher: str
    kdf: str
    file_id_b64: str
    nonce_prefix_b64: str
    chunk_size: int
    slots: list[KeySlot]

    @property
    def file_id(self) -> bytes:
        return _b64d(self.file_id_b64, "file_id_b64", FILE_ID_LEN)

    @property
    def nonce_prefix(self) -> bytes:
        return _b64d(self.nonce_prefix_b64, "nonce_prefix_b64", NONCE_PREFIX_LEN)

    def to_canonical_json(self) -> bytes:
        obj = {
            "version": self.version,
            "cipher": self.cipher,
            "kdf": self.kdf,
            "file_id_b64": self.file_id_b64,
            "nonce_prefix_b64": self.nonce_prefix_b64,
            "chunk_size": self.chunk_size,
            "slots": [slot.to_dict() for slot in self.slots],
        }
        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")

    @classmethod
    def from_json(cls, raw: bytes) -> EncryptedHeader:
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CryptoFormatError(f"Invalid header JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise CryptoFormatError("Header JSON must be an object")

        version = data.get("version")
        if version != FORMAT_VERSION:
            raise CryptoFormatError(f"Unsupported container format version: {version!r}")
        cipher = data.get("cipher")
        if cipher != CIPHER_NAME:
            raise CryptoFormatError(f"Unsupported cipher: {cipher!r}")
        kdf = data.get("kdf")
        if kdf != KDF_NAME:
            raise CryptoFormatError(f"Unsupported KDF: {kdf!r}")

        chunk_size = data.get("chunk_size")
        if (
            not isinstance(chunk_size, int)
            or isinstance(chunk_size, bool)
            or chunk_size < MIN_CHUNK_SIZE
            or chunk_size > MAX_CHUNK_SIZE
        ):
            raise CryptoFormatError(f"Invalid chunk_size: {chunk_size!r}")

        raw_slots = data.get("slots")
        if not isinstance(raw_slots, list) or not raw_slots:
            raise CryptoFormatError("Header must contain at least one key slot")

        slots = [KeySlot.from_dict(item) for item in raw_slots]
        header = cls(
            version=version,
            cipher=cipher,
            kdf=kdf,
            file_id_b64=str(data.get("file_id_b64", "")),
            nonce_prefix_b64=str(data.get("nonce_prefix_b64", "")),
            chunk_size=chunk_size,
            slots=slots,
        )
        _ = header.file_id
        _ = header.nonce_prefix
        return header


def _read_exact(stream: BinaryIO, length: int) -> bytes:
    chunks: list[bytes] = []
    remaining = length
    while remaining > 0:
        data = stream.read(remaining)
        if not data:
            raise CryptoFormatError(
                f"Unexpected EOF: expected {length} bytes, got {length - remaining}"
            )
        chunks.append(data)
        remaining -= len(data)
    return b"".join(chunks)


def _read_up_to(stream: BinaryIO, length: int) -> bytes:
    """Read up to `length` bytes, continuing across short reads until full or EOF."""
    chunks: list[bytes] = []
    remaining = length
    while remaining > 0:
        data = stream.read(remaining)
        if not data:
            break
        chunks.append(data)
        remaining -= len(data)
    return b"".join(chunks)


def read_container_header(
    stream: BinaryIO,
) -> tuple[EncryptedHeader, bytes, bytes]:
    """Read and parse the container header and its MAC without reading payload chunks."""
    magic = _read_up_to(stream, len(MAGIC))
    if magic != MAGIC:
        raise CryptoFormatError(
            "Input is not a valid ssh-agent-crypt v1 file (bad magic header)."
        )
    len_bytes = _read_exact(stream, 4)
    (header_len,) = struct.unpack(">I", len_bytes)
    if header_len == 0 or header_len > MAX_HEADER_LEN:
        raise CryptoFormatError(f"Invalid header length: {header_len}")
    raw_header = _read_exact(stream, header_len)
    header_mac = _read_exact(stream, HEADER_MAC_LEN)
    header = EncryptedHeader.from_json(raw_header)
    return header, raw_header, header_mac


def write_container_header(
    stream: BinaryIO, header: EncryptedHeader, dek: bytes
) -> bytes:
    """Serialize header, compute Header MAC, and write MAGIC + len + JSON + MAC."""
    raw_header = header.to_canonical_json()
    header_mac = compute_header_mac(dek, header.file_id, raw_header)
    stream.write(MAGIC)
    stream.write(struct.pack(">I", len(raw_header)))
    stream.write(raw_header)
    stream.write(header_mac)
    return raw_header


def create_key_slot(
    agent: SSHAgentClient,
    key: AgentKey,
    dek: bytes,
    file_id: bytes,
) -> KeySlot:
    """Wrap `dek` into a new KeySlot using a deterministic ssh-agent signature."""
    challenge = os.urandom(CHALLENGE_LEN)
    wrap_nonce = os.urandom(WRAP_NONCE_LEN)
    slot_id = os.urandom(8).hex()
    sign_flags = key.default_sign_flags

    sign_input = build_sign_input(file_id, challenge, key.key_blob)
    signature = agent.sign_deterministic(key.key_blob, sign_input, flags=sign_flags)
    kek = derive_kek(signature, challenge, key.key_blob)
    aad = build_slot_aad(file_id, key.key_blob, challenge)
    wrapped_dek = AESGCM(kek).encrypt(wrap_nonce, dek, aad)

    return KeySlot(
        slot_id=slot_id,
        fingerprint=key.fingerprint,
        key_type=key.key_type,
        comment=key.comment,
        public_key_b64=key.public_key_b64,
        sign_flags=sign_flags,
        challenge_b64=_b64e(challenge),
        wrap_nonce_b64=_b64e(wrap_nonce),
        wrapped_dek_b64=_b64e(wrapped_dek),
    )


def unlock_dek(
    agent: SSHAgentClient,
    header: EncryptedHeader,
    raw_header: bytes,
    header_mac: bytes,
    preferred_key: AgentKey | None = None,
) -> tuple[bytes, KeySlot]:
    """Recover the file DEK using an authorized key currently loaded in ssh-agent."""
    if preferred_key is not None:
        agent_by_fp = {preferred_key.fingerprint: preferred_key}
    else:
        agent_by_fp = {k.fingerprint: k for k in agent.list_keys()}

    matching_slots = [s for s in header.slots if s.fingerprint in agent_by_fp]
    if not matching_slots:
        authorized = ", ".join(
            f"{s.fingerprint} ({s.comment})" if s.comment else s.fingerprint
            for s in header.slots
        )
        raise DecryptionError(
            "None of the file's authorized SSH keys are loaded in the SSH agent.\n"
            f"Authorized keys: {authorized}"
        )

    file_id = header.file_id
    last_error: Exception | None = None
    for slot in matching_slots:
        try:
            key_blob = slot.key_blob
            challenge = slot.challenge
            sign_input = build_sign_input(file_id, challenge, key_blob)
            signature = agent.sign(key_blob, sign_input, flags=slot.sign_flags)
            kek = derive_kek(signature, challenge, key_blob)
            aad = build_slot_aad(file_id, key_blob, challenge)
            dek = AESGCM(kek).decrypt(slot.wrap_nonce, slot.wrapped_dek, aad)
        except InvalidTag as exc:
            last_error = exc
            continue
        except Exception as exc:  # noqa: BLE001
            last_error = exc
            continue

        if len(dek) != DEK_LEN:
            raise DecryptionError("Unwrapped DEK has invalid length")
        verify_header_mac(dek, file_id, raw_header, header_mac)
        return dek, slot

    raise DecryptionError(
        "Failed to unwrap DEK with any matching SSH agent key "
        f"(last error: {last_error}). The file may be corrupted or the key signature changed."
    )


def encrypt_stream(
    agent: SSHAgentClient,
    keys: Sequence[AgentKey],
    src: BinaryIO,
    dst: BinaryIO,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> tuple[EncryptedHeader, int]:
    """Encrypt `src` to `dst` for all specified SSH agent keys."""
    if not keys:
        raise KeyManagementError("At least one SSH agent key is required for encryption.")
    if chunk_size < MIN_CHUNK_SIZE or chunk_size > MAX_CHUNK_SIZE:
        raise ValueError(
            f"chunk_size must be between {MIN_CHUNK_SIZE} and {MAX_CHUNK_SIZE} bytes"
        )

    dek = os.urandom(DEK_LEN)
    file_id = os.urandom(FILE_ID_LEN)
    nonce_prefix = os.urandom(NONCE_PREFIX_LEN)

    slots: list[KeySlot] = []
    seen_fps: set[str] = set()
    for key in keys:
        if key.fingerprint in seen_fps:
            continue
        slots.append(create_key_slot(agent, key, dek, file_id))
        seen_fps.add(key.fingerprint)

    header = EncryptedHeader(
        version=FORMAT_VERSION,
        cipher=CIPHER_NAME,
        kdf=KDF_NAME,
        file_id_b64=_b64e(file_id),
        nonce_prefix_b64=_b64e(nonce_prefix),
        chunk_size=chunk_size,
        slots=slots,
    )
    write_container_header(dst, header, dek)

    payload_key = derive_payload_key(dek, file_id)
    aesgcm = AESGCM(payload_key)

    total_plaintext = 0
    chunk_index = 0
    current = _read_up_to(src, chunk_size)
    while True:
        next_chunk = _read_up_to(src, chunk_size)
        is_final = len(next_chunk) == 0
        if chunk_index > MAX_CHUNKS:
            raise CryptoFormatError("Input exceeds maximum supported chunk count")

        nonce = build_chunk_nonce(nonce_prefix, chunk_index)
        aad = build_chunk_aad(file_id, chunk_index, is_final)
        ct = aesgcm.encrypt(nonce, current, aad)
        dst.write(struct.pack(">I", len(ct)))
        dst.write(ct)
        total_plaintext += len(current)

        if is_final:
            break
        current = next_chunk
        chunk_index += 1

    return header, total_plaintext


def _decrypt_payload_chunks(
    header: EncryptedHeader,
    dek: bytes,
    src: BinaryIO,
    dst: BinaryIO | None,
) -> int:
    """Decrypt (or verify when dst is None) all framed AES-256-GCM payload chunks."""
    file_id = header.file_id
    nonce_prefix = header.nonce_prefix
    payload_key = derive_payload_key(dek, file_id)
    aesgcm = AESGCM(payload_key)

    first_len_bytes = _read_up_to(src, 4)
    if len(first_len_bytes) != 4:
        raise DecryptionError("Truncated ciphertext: missing initial payload chunk.")

    total_plaintext = 0
    chunk_index = 0
    cur_len_bytes = first_len_bytes

    while True:
        if chunk_index > MAX_CHUNKS:
            raise DecryptionError("Ciphertext exceeds maximum supported chunk count.")
        (ct_len,) = struct.unpack(">I", cur_len_bytes)
        if ct_len < GCM_TAG_LEN or ct_len > header.chunk_size + GCM_TAG_LEN:
            raise DecryptionError(f"Invalid ciphertext chunk length: {ct_len}")

        ct = _read_up_to(src, ct_len)
        if len(ct) != ct_len:
            raise DecryptionError(
                f"Truncated ciphertext chunk {chunk_index}: expected {ct_len} bytes, got {len(ct)}"
            )

        next_len_bytes = _read_up_to(src, 4)
        if len(next_len_bytes) == 0:
            is_final = True
        elif len(next_len_bytes) == 4:
            is_final = False
        else:
            raise DecryptionError("Corrupted ciphertext: trailing truncated chunk header.")

        nonce = build_chunk_nonce(nonce_prefix, chunk_index)
        aad = build_chunk_aad(file_id, chunk_index, is_final)
        try:
            plaintext = aesgcm.decrypt(nonce, ct, aad)
        except InvalidTag as exc:
            raise DecryptionError(
                f"Authentication failed at chunk {chunk_index}: ciphertext was modified or truncated."
            ) from exc

        if dst is not None:
            dst.write(plaintext)
        total_plaintext += len(plaintext)

        if is_final:
            break
        cur_len_bytes = next_len_bytes
        chunk_index += 1

    return total_plaintext


def decrypt_stream(
    agent: SSHAgentClient,
    src: BinaryIO,
    dst: BinaryIO | None,
    preferred_key: AgentKey | None = None,
) -> tuple[EncryptedHeader, KeySlot, int]:
    """Decrypt (or verify when dst is None) a container stream using ssh-agent."""
    header, raw_header, header_mac = read_container_header(src)
    dek, used_slot = unlock_dek(agent, header, raw_header, header_mac, preferred_key)
    total_plaintext = _decrypt_payload_chunks(header, dek, src, dst)
    return header, used_slot, total_plaintext


def _copy_raw_stream(src: BinaryIO, dst: BinaryIO, buf_size: int = 65536) -> None:
    while True:
        chunk = src.read(buf_size)
        if not chunk:
            break
        dst.write(chunk)


def _reencrypt_payload_chunks(
    old_header: EncryptedHeader,
    old_dek: bytes,
    new_header: EncryptedHeader,
    new_dek: bytes,
    src: BinaryIO,
    dst: BinaryIO,
) -> int:
    """Stream-decrypt payload chunks under old_dek and re-encrypt under new_dek."""
    old_file_id = old_header.file_id
    old_nonce_prefix = old_header.nonce_prefix
    old_aesgcm = AESGCM(derive_payload_key(old_dek, old_file_id))

    new_file_id = new_header.file_id
    new_nonce_prefix = new_header.nonce_prefix
    new_aesgcm = AESGCM(derive_payload_key(new_dek, new_file_id))

    first_len_bytes = _read_up_to(src, 4)
    if len(first_len_bytes) != 4:
        raise DecryptionError("Truncated ciphertext: missing initial payload chunk.")

    total_plaintext = 0
    chunk_index = 0
    cur_len_bytes = first_len_bytes

    while True:
        (ct_len,) = struct.unpack(">I", cur_len_bytes)
        if ct_len < GCM_TAG_LEN or ct_len > old_header.chunk_size + GCM_TAG_LEN:
            raise DecryptionError(f"Invalid ciphertext chunk length: {ct_len}")

        ct = _read_up_to(src, ct_len)
        if len(ct) != ct_len:
            raise DecryptionError(f"Truncated ciphertext chunk {chunk_index}")

        next_len_bytes = _read_up_to(src, 4)
        if len(next_len_bytes) == 0:
            is_final = True
        elif len(next_len_bytes) == 4:
            is_final = False
        else:
            raise DecryptionError("Corrupted ciphertext: trailing truncated chunk header.")

        old_nonce = build_chunk_nonce(old_nonce_prefix, chunk_index)
        old_aad = build_chunk_aad(old_file_id, chunk_index, is_final)
        try:
            plaintext = old_aesgcm.decrypt(old_nonce, ct, old_aad)
        except InvalidTag as exc:
            raise DecryptionError(
                f"Authentication failed at chunk {chunk_index} during rekey."
            ) from exc

        new_nonce = build_chunk_nonce(new_nonce_prefix, chunk_index)
        new_aad = build_chunk_aad(new_file_id, chunk_index, is_final)
        new_ct = new_aesgcm.encrypt(new_nonce, plaintext, new_aad)
        dst.write(struct.pack(">I", len(new_ct)))
        dst.write(new_ct)
        total_plaintext += len(plaintext)

        if is_final:
            break
        cur_len_bytes = next_len_bytes
        chunk_index += 1

    return total_plaintext


def match_slot_selector(slots: Sequence[KeySlot], selector: str) -> KeySlot:
    """Resolve a selector against an encrypted file's KeySlots."""
    sel = selector.strip()
    if not sel:
        raise KeySelectionError("Empty key selector")

    # 1. Public key file path (.pub)
    path = Path(sel).expanduser()
    if path.is_file():
        blob = parse_openssh_pubkey_file(path)
        target_fp = compute_fingerprint(blob)
        matches = [s for s in slots if s.fingerprint == target_fp]
        if len(matches) == 1:
            return matches[0]
        if len(matches) > 1:
            raise KeySelectionError(f"Multiple slots match public key '{sel}' ({target_fp})")
        raise KeySelectionError(
            f"Public key from '{sel}' ({target_fp}) is not authorized on this file."
        )

    # 2. Exact slot_id
    exact_id = [s for s in slots if s.slot_id == sel]
    if len(exact_id) == 1:
        return exact_id[0]

    # 3. Exact fingerprint
    exact_fp = [s for s in slots if s.fingerprint == sel]
    if len(exact_fp) == 1:
        return exact_fp[0]

    # 4. Unique slot_id prefix
    prefix_id = [s for s in slots if s.slot_id.startswith(sel)]
    if len(prefix_id) == 1:
        return prefix_id[0]
    if len(prefix_id) > 1:
        raise KeySelectionError(f"Ambiguous slot_id prefix '{sel}'")

    # 5. Unique fingerprint prefix (with or without SHA256:)
    norm_sel = sel if sel.startswith("SHA256:") else f"SHA256:{sel}"
    prefix_fp = [s for s in slots if s.fingerprint.startswith(norm_sel)]
    if len(prefix_fp) == 1:
        return prefix_fp[0]
    if len(prefix_fp) > 1:
        listing = ", ".join(f"{s.fingerprint} ({s.comment})" for s in prefix_fp)
        raise KeySelectionError(f"Ambiguous fingerprint prefix '{sel}': {listing}")

    # 6. Exact comment
    exact_comment = [s for s in slots if s.comment == sel]
    if len(exact_comment) == 1:
        return exact_comment[0]
    if len(exact_comment) > 1:
        listing = ", ".join(f"{s.slot_id}:{s.fingerprint}" for s in exact_comment)
        raise KeySelectionError(f"Ambiguous comment '{sel}': {listing}")

    # 7. Case-insensitive comment substring
    low = sel.lower()
    sub_comment = [s for s in slots if low in s.comment.lower()]
    if len(sub_comment) == 1:
        return sub_comment[0]
    if len(sub_comment) > 1:
        listing = ", ".join(f"{s.slot_id}:{s.fingerprint} ({s.comment})" for s in sub_comment)
        raise KeySelectionError(f"Ambiguous selector '{sel}': {listing}")

    raise KeySelectionError(f"No key slot in file matched selector '{sel}'")


def add_keys_to_stream(
    agent: SSHAgentClient,
    src: BinaryIO,
    dst: BinaryIO,
    new_keys: Sequence[AgentKey],
    unlock_key: AgentKey | None = None,
) -> tuple[EncryptedHeader, list[KeySlot], list[str]]:
    """Add one or more SSH agent keys to an existing encrypted container.

    Does not re-encrypt the payload and preserves all existing (even offline) slots.
    """
    if not new_keys:
        raise KeyManagementError("No keys provided to add.")

    header, raw_header, header_mac = read_container_header(src)
    dek, _used_slot = unlock_dek(agent, header, raw_header, header_mac, unlock_key)

    existing_fps = {s.fingerprint for s in header.slots}
    added: list[KeySlot] = []
    skipped_fps: list[str] = []

    for key in new_keys:
        if key.fingerprint in existing_fps:
            skipped_fps.append(key.fingerprint)
            continue
        slot = create_key_slot(agent, key, dek, header.file_id)
        header.slots.append(slot)
        existing_fps.add(key.fingerprint)
        added.append(slot)

    write_container_header(dst, header, dek)
    _copy_raw_stream(src, dst)
    return header, added, skipped_fps


def remove_keys_from_stream(
    agent: SSHAgentClient,
    src: BinaryIO,
    dst: BinaryIO,
    selectors: Sequence[str],
    unlock_key: AgentKey | None = None,
    rekey: bool = False,
    force_lockout: bool = False,
) -> tuple[EncryptedHeader, list[KeySlot]]:
    """Remove one or more key slots from an encrypted container.

    Refuses to remove the last remaining key. When `rekey=True`, rotates the DEK
    and re-encrypts the payload for all remaining keys (which must all be loaded
    in the SSH agent).
    """
    if not selectors:
        raise KeyManagementError("No key selectors provided to remove.")

    header, raw_header, header_mac = read_container_header(src)
    dek, _used_slot = unlock_dek(agent, header, raw_header, header_mac, unlock_key)

    to_remove_ids: set[str] = set()
    removed_slots: list[KeySlot] = []
    for sel in selectors:
        slot = match_slot_selector(header.slots, sel)
        if slot.slot_id not in to_remove_ids:
            to_remove_ids.add(slot.slot_id)
            removed_slots.append(slot)

    remaining_slots = [s for s in header.slots if s.slot_id not in to_remove_ids]
    if not remaining_slots:
        raise KeyManagementError(
            "Refusing to remove the last remaining key slot; doing so would make the "
            "file permanently undecryptable."
        )

    agent_by_fp = {k.fingerprint: k for k in agent.list_keys()}
    remaining_in_agent = [s for s in remaining_slots if s.fingerprint in agent_by_fp]

    if rekey:
        missing = [s for s in remaining_slots if s.fingerprint not in agent_by_fp]
        if missing:
            listing = ", ".join(f"{s.fingerprint} ({s.comment})" for s in missing)
            raise KeyManagementError(
                "Cannot --rekey because some remaining authorized keys are not loaded in "
                f"the SSH agent: {listing}"
            )
        new_dek = os.urandom(DEK_LEN)
        new_file_id = os.urandom(FILE_ID_LEN)
        new_nonce_prefix = os.urandom(NONCE_PREFIX_LEN)
        new_slots = [
            create_key_slot(agent, agent_by_fp[s.fingerprint], new_dek, new_file_id)
            for s in remaining_slots
        ]
        new_header = EncryptedHeader(
            version=FORMAT_VERSION,
            cipher=CIPHER_NAME,
            kdf=KDF_NAME,
            file_id_b64=_b64e(new_file_id),
            nonce_prefix_b64=_b64e(new_nonce_prefix),
            chunk_size=header.chunk_size,
            slots=new_slots,
        )
        write_container_header(dst, new_header, new_dek)
        _reencrypt_payload_chunks(header, dek, new_header, new_dek, src, dst)
        return new_header, removed_slots

    if not remaining_in_agent and not force_lockout:
        raise KeyManagementError(
            "Removing these key(s) would leave zero keys currently loaded in your SSH agent. "
            "Pass --force if you are sure another authorized key is backed up elsewhere."
        )

    header.slots = remaining_slots
    write_container_header(dst, header, dek)
    _copy_raw_stream(src, dst)
    return header, removed_slots


def rekey_stream(
    agent: SSHAgentClient,
    src: BinaryIO,
    dst: BinaryIO,
    unlock_key: AgentKey | None = None,
    drop_missing: bool = False,
) -> tuple[EncryptedHeader, list[KeySlot], list[KeySlot]]:
    """Rotate the DEK and file_id and re-encrypt the payload for active keys."""
    header, raw_header, header_mac = read_container_header(src)
    old_dek, _used_slot = unlock_dek(agent, header, raw_header, header_mac, unlock_key)

    agent_by_fp = {k.fingerprint: k for k in agent.list_keys()}
    present_slots = [s for s in header.slots if s.fingerprint in agent_by_fp]
    missing_slots = [s for s in header.slots if s.fingerprint not in agent_by_fp]

    if missing_slots and not drop_missing:
        listing = ", ".join(f"{s.fingerprint} ({s.comment})" for s in missing_slots)
        raise KeyManagementError(
            "Cannot rekey while authorized keys are missing from the SSH agent: "
            f"{listing}. Load those keys or pass --drop-missing."
        )
    if not present_slots:
        raise KeyManagementError("No authorized keys are loaded in the SSH agent to rekey for.")

    new_dek = os.urandom(DEK_LEN)
    new_file_id = os.urandom(FILE_ID_LEN)
    new_nonce_prefix = os.urandom(NONCE_PREFIX_LEN)
    new_slots = [
        create_key_slot(agent, agent_by_fp[s.fingerprint], new_dek, new_file_id)
        for s in present_slots
    ]
    new_header = EncryptedHeader(
        version=FORMAT_VERSION,
        cipher=CIPHER_NAME,
        kdf=KDF_NAME,
        file_id_b64=_b64e(new_file_id),
        nonce_prefix_b64=_b64e(new_nonce_prefix),
        chunk_size=header.chunk_size,
        slots=new_slots,
    )
    write_container_header(dst, new_header, new_dek)
    _reencrypt_payload_chunks(header, old_dek, new_header, new_dek, src, dst)
    return new_header, new_slots, missing_slots
