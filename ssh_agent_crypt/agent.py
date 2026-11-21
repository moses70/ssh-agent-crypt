"""Pure-Python SSH agent protocol client using SSH_AGENT_SOCK / SSH_AUTH_SOCK.

Communicates directly with the Unix domain socket of a running ssh-agent
(draft-miller-ssh-agent) without spawning subprocesses or exposing sensitive
material on the command line or on disk.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import socket
import stat
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence

# SSH Agent Protocol message numbers
SSH_AGENT_FAILURE = 5
SSH_AGENT_SUCCESS = 6
SSH_AGENTC_REQUEST_IDENTITIES = 11
SSH_AGENT_IDENTITIES_ANSWER = 12
SSH_AGENTC_SIGN_REQUEST = 13
SSH_AGENT_SIGN_RESPONSE = 14

# SSH Agent signature flags (RFC 8332 / OpenSSH)
SSH_AGENT_RSA_SHA2_256 = 0x02
SSH_AGENT_RSA_SHA2_512 = 0x04

# Maximum allowed agent response size (4 MiB safety limit)
MAX_AGENT_MESSAGE_SIZE = 4 * 1024 * 1024

# Deterministic key types supported for KEK derivation and their default flags
SUPPORTED_KEY_TYPES: dict[str, int] = {
    "ssh-ed25519": 0,
    "ssh-rsa": SSH_AGENT_RSA_SHA2_512,
}


class AgentError(Exception):
    """Base error for SSH agent communication failures."""


class NonDeterministicKeyError(AgentError):
    """Raised when an SSH key produces non-deterministic signatures."""


class KeySelectionError(AgentError):
    """Raised when a key selector cannot be resolved unambiguously."""


def pack_ssh_string(data: bytes) -> bytes:
    """Encode bytes as an RFC 4251 SSH string (uint32 length + payload)."""
    return struct.pack(">I", len(data)) + data


def unpack_ssh_string(buf: bytes, offset: int = 0) -> tuple[bytes, int]:
    """Decode an RFC 4251 SSH string starting at offset."""
    if offset + 4 > len(buf):
        raise AgentError("Truncated SSH string length in agent message")
    (length,) = struct.unpack_from(">I", buf, offset)
    offset += 4
    end = offset + length
    if end > len(buf):
        raise AgentError("Truncated SSH string payload in agent message")
    return buf[offset:end], end


def extract_key_type(key_blob: bytes) -> str:
    """Extract the OpenSSH key algorithm name from a public key blob."""
    raw_type, _ = unpack_ssh_string(key_blob, 0)
    try:
        return raw_type.decode("ascii")
    except UnicodeDecodeError as exc:
        raise AgentError("Invalid non-ASCII key type in public key blob") from exc


def compute_fingerprint(key_blob: bytes) -> str:
    """Compute the OpenSSH SHA256 fingerprint (matches `ssh-add -l`)."""
    digest = hashlib.sha256(key_blob).digest()
    encoded = base64.b64encode(digest).rstrip(b"=").decode("ascii")
    return f"SHA256:{encoded}"


def parse_openssh_pubkey_file(path: Path) -> bytes:
    """Parse an OpenSSH `.pub` file and return its raw key blob."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise KeySelectionError(f"Could not read public key file '{path}': {exc}") from exc

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        try:
            blob = base64.b64decode(parts[1], validate=True)
            key_type = extract_key_type(blob)
            if key_type != parts[0]:
                raise KeySelectionError(
                    f"Public key file '{path}' has mismatched type '{parts[0]}' vs blob '{key_type}'"
                )
            return blob
        except (ValueError, AgentError) as exc:
            raise KeySelectionError(f"Invalid OpenSSH public key in '{path}': {exc}") from exc

    raise KeySelectionError(f"No OpenSSH public key found in '{path}'")


@dataclass(frozen=True)
class AgentKey:
    """Represents a single public identity held by an SSH agent."""

    key_blob: bytes
    comment: str
    key_type: str
    fingerprint: str

    @property
    def is_supported(self) -> bool:
        return self.key_type in SUPPORTED_KEY_TYPES

    @property
    def default_sign_flags(self) -> int:
        return SUPPORTED_KEY_TYPES.get(self.key_type, 0)

    @property
    def public_key_b64(self) -> str:
        return base64.b64encode(self.key_blob).decode("ascii")


def resolve_agent_socket(cli_socket: str | None = None) -> tuple[str, str]:
    """Resolve the SSH agent Unix socket path.

    Priority:
      1. Explicit CLI `--socket` argument
      2. `SSH_AGENT_SOCK` environment variable
      3. `SSH_AUTH_SOCK` environment variable

    Returns `(socket_path, source_description)`.
    """
    candidates: list[tuple[str, str]] = []
    if cli_socket:
        candidates.append((cli_socket, "--socket"))
    else:
        for env_name in ("SSH_AGENT_SOCK", "SSH_AUTH_SOCK"):
            val = os.environ.get(env_name, "").strip()
            if val:
                candidates.append((val, env_name))
                break

    if not candidates:
        raise AgentError(
            "No SSH agent socket configured. Set SSH_AGENT_SOCK (or SSH_AUTH_SOCK) "
            "or pass --socket PATH."
        )

    sock_path, source = candidates[0]
    try:
        st = os.stat(sock_path)
    except FileNotFoundError as exc:
        raise AgentError(
            f"SSH agent socket from {source} does not exist: {sock_path}"
        ) from exc
    except OSError as exc:
        raise AgentError(
            f"Cannot access SSH agent socket from {source} ({sock_path}): {exc}"
        ) from exc

    if not stat.S_ISSOCK(st.st_mode):
        raise AgentError(
            f"Path from {source} is not a Unix domain socket: {sock_path}"
        )

    return sock_path, source


class SSHAgentClient:
    """Minimal, dependency-free client for the OpenSSH agent Unix socket."""

    def __init__(self, socket_path: str, timeout: float = 30.0) -> None:
        self.socket_path = socket_path
        self.timeout = timeout
        self._sock: socket.socket | None = None

    def connect(self) -> None:
        if self._sock is not None:
            return
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect(self.socket_path)
        except OSError as exc:
            sock.close()
            raise AgentError(
                f"Failed to connect to SSH agent socket '{self.socket_path}': {exc}"
            ) from exc
        self._sock = sock

    def close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            finally:
                self._sock = None

    def __enter__(self) -> SSHAgentClient:
        self.connect()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def _recv_exact(self, length: int) -> bytes:
        assert self._sock is not None
        chunks: list[bytes] = []
        remaining = length
        while remaining > 0:
            chunk = self._sock.recv(remaining)
            if not chunk:
                raise AgentError("SSH agent closed the connection unexpectedly")
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def _request(self, payload: bytes) -> tuple[int, bytes]:
        if self._sock is None:
            self.connect()
        assert self._sock is not None
        frame = struct.pack(">I", len(payload)) + payload
        try:
            self._sock.sendall(frame)
            header = self._recv_exact(4)
            (resp_len,) = struct.unpack(">I", header)
            if resp_len < 1 or resp_len > MAX_AGENT_MESSAGE_SIZE:
                raise AgentError(f"Invalid SSH agent response length: {resp_len}")
            resp = self._recv_exact(resp_len)
        except OSError as exc:
            raise AgentError(f"SSH agent communication error: {exc}") from exc
        return resp[0], resp[1:]

    def list_keys(self) -> list[AgentKey]:
        """Return all public identities currently loaded in the SSH agent."""
        msg_type, body = self._request(bytes([SSH_AGENTC_REQUEST_IDENTITIES]))
        if msg_type != SSH_AGENT_IDENTITIES_ANSWER:
            raise AgentError(
                f"Unexpected response to REQUEST_IDENTITIES (code {msg_type})"
            )
        if len(body) < 4:
            raise AgentError("Truncated SSH_AGENT_IDENTITIES_ANSWER")
        (count,) = struct.unpack_from(">I", body, 0)
        offset = 4
        keys: list[AgentKey] = []
        for _ in range(count):
            key_blob, offset = unpack_ssh_string(body, offset)
            comment_bytes, offset = unpack_ssh_string(body, offset)
            comment = comment_bytes.decode("utf-8", errors="replace")
            key_type = extract_key_type(key_blob)
            fingerprint = compute_fingerprint(key_blob)
            keys.append(
                AgentKey(
                    key_blob=key_blob,
                    comment=comment,
                    key_type=key_type,
                    fingerprint=fingerprint,
                )
            )
        return keys

    def sign(self, key_blob: bytes, data: bytes, flags: int = 0) -> bytes:
        """Ask the SSH agent to sign `data` with the key identified by `key_blob`."""
        payload = (
            bytes([SSH_AGENTC_SIGN_REQUEST])
            + pack_ssh_string(key_blob)
            + pack_ssh_string(data)
            + struct.pack(">I", flags)
        )
        msg_type, body = self._request(payload)
        if msg_type == SSH_AGENT_FAILURE:
            raise AgentError(
                "SSH agent refused signing request (key unavailable, locked, or unsupported flags)"
            )
        if msg_type != SSH_AGENT_SIGN_RESPONSE:
            raise AgentError(f"Unexpected response to SIGN_REQUEST (code {msg_type})")
        signature_blob, _ = unpack_ssh_string(body, 0)
        return signature_blob

    def sign_deterministic(self, key_blob: bytes, data: bytes, flags: int = 0) -> bytes:
        """Sign `data` twice and verify both signatures are byte-for-byte identical.

        Only deterministic signature schemes (such as Ed25519 and RSA PKCS#1 v1.5)
        can reliably derive a reproducible KEK across encrypt and decrypt runs.
        """
        sig1 = self.sign(key_blob, data, flags=flags)
        sig2 = self.sign(key_blob, data, flags=flags)
        if not hmac.compare_digest(sig1, sig2):
            key_type = extract_key_type(key_blob)
            fp = compute_fingerprint(key_blob)
            raise NonDeterministicKeyError(
                f"Key {fp} ({key_type}) produced non-deterministic signatures and cannot be "
                "used to wrap keys via ssh-agent. Use an Ed25519 (ssh-ed25519) or RSA (ssh-rsa) key."
            )
        return sig1


def match_key_selector(
    candidates: Sequence[AgentKey],
    selector: str,
) -> AgentKey:
    """Resolve a single selector (pubkey file, fingerprint/prefix, or comment) to one AgentKey."""
    sel = selector.strip()
    if not sel:
        raise KeySelectionError("Empty key selector")

    # 1. Public key file path (.pub)
    path = Path(sel).expanduser()
    if path.is_file():
        blob = parse_openssh_pubkey_file(path)
        target_fp = compute_fingerprint(blob)
        for key in candidates:
            if key.fingerprint == target_fp:
                return key
        raise KeySelectionError(
            f"Public key from '{sel}' ({target_fp}) is not currently loaded in the SSH agent."
        )

    # 2. Exact fingerprint match
    exact_fp = [k for k in candidates if k.fingerprint == sel]
    if len(exact_fp) == 1:
        return exact_fp[0]

    # 3. Fingerprint prefix match (with or without leading "SHA256:")
    norm_sel = sel if sel.startswith("SHA256:") else f"SHA256:{sel}"
    prefix_fp = [k for k in candidates if k.fingerprint.startswith(norm_sel)]
    if len(prefix_fp) == 1:
        return prefix_fp[0]
    if len(prefix_fp) > 1:
        listing = ", ".join(f"{k.fingerprint} ({k.comment})" for k in prefix_fp)
        raise KeySelectionError(f"Ambiguous fingerprint prefix '{sel}': matches {listing}")

    # 4. Exact comment match
    exact_comment = [k for k in candidates if k.comment == sel]
    if len(exact_comment) == 1:
        return exact_comment[0]
    if len(exact_comment) > 1:
        listing = ", ".join(f"{k.fingerprint} ({k.comment})" for k in exact_comment)
        raise KeySelectionError(f"Ambiguous comment '{sel}': matches {listing}")

    # 5. Case-insensitive comment substring match
    low = sel.lower()
    sub_comment = [k for k in candidates if low in k.comment.lower()]
    if len(sub_comment) == 1:
        return sub_comment[0]
    if len(sub_comment) > 1:
        listing = ", ".join(f"{k.fingerprint} ({k.comment})" for k in sub_comment)
        raise KeySelectionError(
            f"Ambiguous selector '{sel}': matches multiple keys ({listing})"
        )

    raise KeySelectionError(f"No loaded SSH agent key matched selector '{sel}'")


def select_agent_keys(
    agent_keys: Sequence[AgentKey],
    selectors: Iterable[str],
    require_supported: bool = True,
) -> list[AgentKey]:
    """Resolve multiple selectors to a deduplicated list of AgentKey objects."""
    selected: list[AgentKey] = []
    seen_fps: set[str] = set()
    for selector in selectors:
        key = match_key_selector(agent_keys, selector)
        if require_supported and not key.is_supported:
            raise NonDeterministicKeyError(
                f"Key {key.fingerprint} ({key.key_type}, '{key.comment}') is not a supported "
                f"deterministic key type. Supported types: {', '.join(sorted(SUPPORTED_KEY_TYPES))}"
            )
        if key.fingerprint not in seen_fps:
            selected.append(key)
            seen_fps.add(key.fingerprint)
    return selected
