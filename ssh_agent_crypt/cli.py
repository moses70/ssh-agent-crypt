"""Command-line interface for ssh-agent-crypt.

Security design:
  - Never accepts plaintext, passphrases, or private keys as CLI arguments.
  - Communicates directly with SSH_AGENT_SOCK (fallback: SSH_AUTH_SOCK).
  - Writes files atomically via temporary files in the target directory.
  - Decrypted output files are created strictly with mode 0600.
  - Informational messages are written to stderr; stdout stays clean for piping.
"""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import BinaryIO, Iterator, Sequence

from . import __version__
from .agent import (
    AgentError,
    AgentKey,
    KeySelectionError,
    SSHAgentClient,
    match_key_selector,
    resolve_agent_socket,
    select_agent_keys,
)
from .crypto import (
    DEFAULT_CHUNK_SIZE,
    CryptoFormatError,
    DecryptionError,
    KeyManagementError,
    add_keys_to_stream,
    decrypt_stream,
    encrypt_stream,
    read_container_header,
    rekey_stream,
    remove_keys_from_stream,
    unlock_dek,
)
from .completion import (
    generate_bash_completion,
    generate_zsh_completion,
    query_agent_key_candidates,
    query_file_key_candidates,
)
from .installer import InstallError, install_tool


def _info(msg: str, quiet: bool = False) -> None:
    if not quiet:
        print(msg, file=sys.stderr)


@contextmanager
def _atomic_file_writer(
    target_path: Path,
    *,
    mode: int = 0o600,
    allow_overwrite: bool = False,
) -> Iterator[BinaryIO]:
    """Open a temp file in target_path's directory and atomically replace on success."""
    target = target_path.expanduser()
    if target.exists() and not allow_overwrite:
        raise FileExistsError(
            f"Output file already exists: {target} (use --force to overwrite)"
        )
    parent = target.parent if str(target.parent) else Path(".")
    if not parent.exists():
        raise FileNotFoundError(f"Output directory does not exist: {parent}")

    fd, tmp_name = tempfile.mkstemp(prefix=".ssh-agent-crypt-", dir=str(parent))
    tmp_path = Path(tmp_name)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as handle:
            yield handle
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, target)
    except BaseException:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def _open_agent(cli_socket: str | None) -> tuple[SSHAgentClient, str, str]:
    sock_path, source = resolve_agent_socket(cli_socket)
    return SSHAgentClient(sock_path), sock_path, source


def _resolve_optional_unlock_key(
    agent: SSHAgentClient, selector: str | None
) -> AgentKey | None:
    if not selector:
        return None
    keys = agent.list_keys()
    return match_key_selector(keys, selector)


def _cmd_agent_keys(args: argparse.Namespace) -> int:
    client, sock_path, source = _open_agent(args.socket)
    with client:
        keys = client.list_keys()

    if args.json:
        payload = {
            "socket": sock_path,
            "socket_source": source,
            "keys": [
                {
                    "fingerprint": k.fingerprint,
                    "key_type": k.key_type,
                    "supported": k.is_supported,
                    "comment": k.comment,
                }
                for k in keys
            ],
        }
        print(json.dumps(payload, indent=2))
        return 0

    _info(f"SSH agent socket ({source}): {sock_path}", quiet=args.quiet)
    if not keys:
        print("No keys loaded in SSH agent.")
        return 0

    for idx, key in enumerate(keys, start=1):
        status = "supported" if key.is_supported else "unsupported (non-deterministic)"
        comment = key.comment or "<no comment>"
        print(f"{idx}. {key.fingerprint}  {key.key_type:<14}  [{status}]  {comment}")
    return 0


def _cmd_encrypt(args: argparse.Namespace) -> int:
    if args.output == "-" and not args.stdout_explicit and sys.stdout.isatty():
        raise ValueError(
            "Refusing to write binary ciphertext to a terminal. "
            "Specify -o FILE or -o - (or redirect stdout)."
        )

    client, _sock_path, _source = _open_agent(args.socket)
    with client:
        agent_keys = client.list_keys()
        if not agent_keys:
            raise AgentError("No keys are loaded in the SSH agent.")

        supported_keys = [k for k in agent_keys if k.is_supported]
        if args.all_keys and args.key:
            raise KeySelectionError("Cannot combine --all-keys with --key.")

        if args.all_keys:
            if not supported_keys:
                raise KeySelectionError(
                    "No supported deterministic keys (ssh-ed25519, ssh-rsa) found in SSH agent."
                )
            selected = supported_keys
        elif args.key:
            selected = select_agent_keys(agent_keys, args.key, require_supported=True)
        else:
            if len(supported_keys) == 1:
                selected = supported_keys
                _info(
                    f"Using sole supported agent key: {selected[0].fingerprint} "
                    f"({selected[0].comment or selected[0].key_type})",
                    quiet=args.quiet,
                )
            elif len(supported_keys) == 0:
                raise KeySelectionError(
                    "No supported deterministic keys (ssh-ed25519, ssh-rsa) found in SSH agent."
                )
            else:
                listing = "\n".join(
                    f"  - {k.fingerprint} ({k.key_type}) {k.comment}"
                    for k in supported_keys
                )
                raise KeySelectionError(
                    "Multiple supported keys are loaded in the SSH agent. "
                    "Specify --key SELECTOR (repeatable) or --all-keys:\n" + listing
                )

        def _run_encrypt(src: BinaryIO, dst: BinaryIO) -> tuple[int, int]:
            header, total_bytes = encrypt_stream(
                client,
                selected,
                src,
                dst,
                chunk_size=args.chunk_size,
            )
            return len(header.slots), total_bytes

        if args.input == "-":
            src_stream: BinaryIO = sys.stdin.buffer
            close_src = False
        else:
            src_stream = open(Path(args.input).expanduser(), "rb")
            close_src = True

        try:
            if args.output == "-":
                slot_count, total_bytes = _run_encrypt(src_stream, sys.stdout.buffer)
                sys.stdout.buffer.flush()
            else:
                with _atomic_file_writer(
                    Path(args.output), mode=0o644, allow_overwrite=args.force
                ) as dst_stream:
                    slot_count, total_bytes = _run_encrypt(src_stream, dst_stream)
        finally:
            if close_src:
                src_stream.close()

    _info(
        f"Encrypted {total_bytes} byte(s) for {slot_count} key(s).",
        quiet=args.quiet,
    )
    return 0


def _cmd_decrypt(args: argparse.Namespace) -> int:
    client, _sock_path, _source = _open_agent(args.socket)
    with client:
        preferred = _resolve_optional_unlock_key(client, args.key)

        if args.input == "-":
            src_stream: BinaryIO = sys.stdin.buffer
            close_src = False
        else:
            src_stream = open(Path(args.input).expanduser(), "rb")
            close_src = True

        try:
            if args.output == "-":
                _header, used_slot, total_bytes = decrypt_stream(
                    client, src_stream, sys.stdout.buffer, preferred_key=preferred
                )
                sys.stdout.buffer.flush()
            else:
                # Decrypted plaintext is always written with strict 0600 permissions
                with _atomic_file_writer(
                    Path(args.output), mode=0o600, allow_overwrite=args.force
                ) as dst_stream:
                    _header, used_slot, total_bytes = decrypt_stream(
                        client, src_stream, dst_stream, preferred_key=preferred
                    )
        finally:
            if close_src:
                src_stream.close()

    _info(
        f"Decrypted {total_bytes} byte(s) using key {used_slot.fingerprint} "
        f"({used_slot.comment or used_slot.key_type}).",
        quiet=args.quiet,
    )
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    client, _sock_path, _source = _open_agent(args.socket)
    with client:
        preferred = _resolve_optional_unlock_key(client, args.key)
        if args.file == "-":
            header, used_slot, total_bytes = decrypt_stream(
                client, sys.stdin.buffer, None, preferred_key=preferred
            )
        else:
            with open(Path(args.file).expanduser(), "rb") as src_stream:
                header, used_slot, total_bytes = decrypt_stream(
                    client, src_stream, None, preferred_key=preferred
                )

    _info(
        f"OK: Verified header MAC and {total_bytes} plaintext byte(s) "
        f"({len(header.slots)} authorized key(s); unlocked with {used_slot.fingerprint}).",
        quiet=args.quiet,
    )
    return 0


def _cmd_info(args: argparse.Namespace) -> int:
    if args.file == "-":
        header, raw_header, header_mac = read_container_header(sys.stdin.buffer)
    else:
        with open(Path(args.file).expanduser(), "rb") as src_stream:
            header, raw_header, header_mac = read_container_header(src_stream)

    agent_fps: set[str] | None = None
    mac_verified: bool | None = None
    try:
        client, _sock_path, _source = _open_agent(args.socket)
        with client:
            agent_fps = {k.fingerprint for k in client.list_keys()}
            if args.verify:
                unlock_dek(client, header, raw_header, header_mac)
                mac_verified = True
    except AgentError:
        if args.verify:
            raise
        agent_fps = None

    if args.json:
        out = {
            "version": header.version,
            "cipher": header.cipher,
            "kdf": header.kdf,
            "file_id_b64": header.file_id_b64,
            "chunk_size": header.chunk_size,
            "header_mac_verified": mac_verified,
            "slots": [
                {
                    "slot_id": s.slot_id,
                    "fingerprint": s.fingerprint,
                    "key_type": s.key_type,
                    "comment": s.comment,
                    "in_agent": (
                        (s.fingerprint in agent_fps) if agent_fps is not None else None
                    ),
                }
                for s in header.slots
            ],
        }
        print(json.dumps(out, indent=2))
        return 0

    print(f"Format version : {header.version}")
    print(f"Cipher / KDF   : {header.cipher} / {header.kdf}")
    print(f"Chunk size     : {header.chunk_size} bytes")
    print(f"File ID        : {header.file_id_b64}")
    if mac_verified is True:
        print("Header MAC     : VERIFIED")
    print(f"Authorized keys ({len(header.slots)}):")
    for idx, slot in enumerate(header.slots, start=1):
        if agent_fps is None:
            presence = "agent-unavailable"
        elif slot.fingerprint in agent_fps:
            presence = "in-agent"
        else:
            presence = "not-in-agent"
        comment = slot.comment or "<no comment>"
        print(
            f"  {idx}. [{slot.slot_id}] {slot.fingerprint}  "
            f"{slot.key_type:<12}  ({presence})  {comment}"
        )
    return 0


def _preserve_mode(path: Path, default: int = 0o644) -> int:
    try:
        return stat.S_IMODE(os.stat(path).st_mode)
    except OSError:
        return default


def _cmd_add_key(args: argparse.Namespace) -> int:
    src_path = Path(args.file).expanduser()
    dst_path = Path(args.output).expanduser() if args.output else src_path
    in_place = dst_path.resolve() == src_path.resolve() if dst_path.exists() else False
    allow_overwrite = in_place or args.force
    file_mode = _preserve_mode(src_path, default=0o644)

    client, _sock_path, _source = _open_agent(args.socket)
    with client:
        agent_keys = client.list_keys()
        if not agent_keys:
            raise AgentError("No keys are loaded in the SSH agent.")

        if args.all_keys and args.key:
            raise KeySelectionError("Cannot combine --all-keys with --key.")
        if args.all_keys:
            new_keys = [k for k in agent_keys if k.is_supported]
            if not new_keys:
                raise KeySelectionError("No supported deterministic keys found in SSH agent.")
        elif args.key:
            new_keys = select_agent_keys(agent_keys, args.key, require_supported=True)
        else:
            raise KeySelectionError("Specify --key SELECTOR (repeatable) or --all-keys.")

        unlock_key = _resolve_optional_unlock_key(client, args.unlock_key)

        with open(src_path, "rb") as src_stream:
            with _atomic_file_writer(
                dst_path, mode=file_mode, allow_overwrite=allow_overwrite
            ) as dst_stream:
                header, added, skipped = add_keys_to_stream(
                    client, src_stream, dst_stream, new_keys, unlock_key=unlock_key
                )

    for slot in added:
        _info(
            f"Added key [{slot.slot_id}] {slot.fingerprint} ({slot.comment or slot.key_type})",
            quiet=args.quiet,
        )
    for fp in skipped:
        _info(f"Skipped already authorized key: {fp}", quiet=args.quiet)
    _info(f"Total authorized keys: {len(header.slots)}", quiet=args.quiet)
    return 0


def _cmd_remove_key(args: argparse.Namespace) -> int:
    src_path = Path(args.file).expanduser()
    dst_path = Path(args.output).expanduser() if args.output else src_path
    in_place = dst_path.resolve() == src_path.resolve() if dst_path.exists() else False
    allow_overwrite = in_place or args.force
    file_mode = _preserve_mode(src_path, default=0o644)

    client, _sock_path, _source = _open_agent(args.socket)
    with client:
        unlock_key = _resolve_optional_unlock_key(client, args.unlock_key)
        with open(src_path, "rb") as src_stream:
            with _atomic_file_writer(
                dst_path, mode=file_mode, allow_overwrite=allow_overwrite
            ) as dst_stream:
                header, removed = remove_keys_from_stream(
                    client,
                    src_stream,
                    dst_stream,
                    args.key,
                    unlock_key=unlock_key,
                    rekey=args.rekey,
                    force_lockout=args.force,
                )

    for slot in removed:
        _info(
            f"Removed key [{slot.slot_id}] {slot.fingerprint} ({slot.comment or slot.key_type})",
            quiet=args.quiet,
        )
    if args.rekey:
        _info("Rotated DEK and re-encrypted payload for remaining keys.", quiet=args.quiet)
    _info(f"Remaining authorized keys: {len(header.slots)}", quiet=args.quiet)
    return 0


def _cmd_rekey(args: argparse.Namespace) -> int:
    src_path = Path(args.file).expanduser()
    dst_path = Path(args.output).expanduser() if args.output else src_path
    in_place = dst_path.resolve() == src_path.resolve() if dst_path.exists() else False
    allow_overwrite = in_place or args.force
    file_mode = _preserve_mode(src_path, default=0o644)

    client, _sock_path, _source = _open_agent(args.socket)
    with client:
        unlock_key = _resolve_optional_unlock_key(client, args.unlock_key)
        with open(src_path, "rb") as src_stream:
            with _atomic_file_writer(
                dst_path, mode=file_mode, allow_overwrite=allow_overwrite
            ) as dst_stream:
                header, new_slots, dropped = rekey_stream(
                    client,
                    src_stream,
                    dst_stream,
                    unlock_key=unlock_key,
                    drop_missing=args.drop_missing,
                )

    _info(
        f"Rekeyed file with new DEK (file_id={header.file_id_b64}) for {len(new_slots)} key(s).",
        quiet=args.quiet,
    )
    for slot in dropped:
        _info(
            f"Dropped missing key [{slot.slot_id}] {slot.fingerprint} ({slot.comment})",
            quiet=args.quiet,
        )
    return 0


def _cmd_install(args: argparse.Namespace) -> int:
    want_bashrc = not (args.no_alias and args.no_completion)
    result = install_tool(
        bin_dir=Path(args.bin_dir),
        command_name=args.name,
        bashrc_path=Path(args.bashrc) if want_bashrc else None,
        alias_name=None if args.no_alias else args.alias,
        enable_completion=not args.no_completion,
        use_sudo=not args.no_sudo,
        force=args.force,
        dry_run=args.dry_run,
    )

    prefix = "[dry-run] " if result.dry_run else ""
    if result.dry_run:
        _info(f"{prefix}Binary     : {result.bin_action}", quiet=args.quiet)
    else:
        sudo_note = " (via sudo)" if result.used_sudo else ""
        _info(
            f"Installed {result.target_bin} -> {result.source_script}{sudo_note}",
            quiet=args.quiet,
        )

    if result.bashrc_path is not None:
        features: list[str] = []
        if result.alias_name:
            features.append(f"alias '{result.alias_name}'")
        if result.completion_enabled:
            features.append("bash completion")
        feature_desc = " + ".join(features)
        _info(
            f"{prefix}Shell rc   : {feature_desc} in {result.bashrc_path} ({result.bashrc_action})",
            quiet=args.quiet,
        )
        if not result.dry_run and result.bashrc_action in ("added", "updated"):
            _info(
                f"Run 'source {result.bashrc_path}' or open a new shell to activate changes.",
                quiet=args.quiet,
            )
    else:
        _info(f"{prefix}Shell rc   : skipped (--no-alias --no-completion)", quiet=args.quiet)

    return 0


def _cmd_completion(args: argparse.Namespace) -> int:
    if args.query_agent_keys:
        for item in query_agent_key_candidates(args.socket):
            print(item)
        return 0
    if args.query_file_keys is not None:
        for item in query_file_key_candidates(args.query_file_keys):
            print(item)
        return 0

    alias = None if args.no_alias else args.alias
    if args.shell == "bash":
        sys.stdout.write(generate_bash_completion(command_name=args.command_name, alias_name=alias))
        return 0
    if args.shell == "zsh":
        sys.stdout.write(generate_zsh_completion(command_name=args.command_name, alias_name=alias))
        return 0
    raise ValueError(f"Unsupported shell: {args.shell}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ssh-agent-crypt",
        description=(
            "Encrypt and decrypt files using keys held by an SSH agent "
            "(via SSH_AGENT_SOCK or SSH_AUTH_SOCK) without exposing secrets on the CLI."
        ),
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    parser.add_argument(
        "--socket",
        metavar="PATH",
        help="Path to SSH agent Unix socket (overrides SSH_AGENT_SOCK and SSH_AUTH_SOCK).",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Suppress informational messages on stderr.",
    )

    # Shared options also accepted after any subcommand without clobbering root values
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--socket",
        default=argparse.SUPPRESS,
        metavar="PATH",
        help="Path to SSH agent Unix socket (overrides SSH_AGENT_SOCK and SSH_AUTH_SOCK).",
    )
    common.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Suppress informational messages on stderr.",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    # agent-keys
    p_ak = sub.add_parser(
        "agent-keys",
        aliases=["list-agent-keys"],
        parents=[common],
        help="List SSH keys currently loaded in the SSH agent.",
    )
    p_ak.add_argument("--json", action="store_true", help="Output as JSON.")
    p_ak.set_defaults(func=_cmd_agent_keys)

    # encrypt
    p_enc = sub.add_parser(
        "encrypt",
        parents=[common],
        help="Encrypt a file (or stdin) for one or more SSH keys.",
    )
    p_enc.add_argument(
        "-i", "--input", default="-", metavar="PATH", help="Input file path, or '-' for stdin."
    )
    p_enc.add_argument(
        "-o", "--output", default=None, metavar="PATH", help="Output file path, or '-' for stdout."
    )
    p_enc.add_argument(
        "-k",
        "--key",
        action="append",
        metavar="SELECTOR",
        help="SSH key selector (fingerprint, prefix, comment, or .pub file). Repeatable.",
    )
    p_enc.add_argument(
        "-a",
        "--all-keys",
        action="store_true",
        help="Encrypt for all supported deterministic keys loaded in the SSH agent.",
    )
    p_enc.add_argument(
        "--chunk-size",
        type=int,
        default=DEFAULT_CHUNK_SIZE,
        metavar="BYTES",
        help=f"Encryption chunk size in bytes (default: {DEFAULT_CHUNK_SIZE}).",
    )
    p_enc.add_argument(
        "-f", "--force", action="store_true", help="Overwrite output file if it already exists."
    )
    p_enc.set_defaults(func=_cmd_encrypt)

    # decrypt
    p_dec = sub.add_parser(
        "decrypt",
        parents=[common],
        help="Decrypt a file (or stdin) using a loaded SSH key.",
    )
    p_dec.add_argument(
        "-i", "--input", default="-", metavar="PATH", help="Encrypted input file, or '-' for stdin."
    )
    p_dec.add_argument(
        "-o", "--output", default="-", metavar="PATH", help="Plaintext output file, or '-' for stdout."
    )
    p_dec.add_argument(
        "-k",
        "--key",
        metavar="SELECTOR",
        help="Optional: force decryption with a specific loaded SSH agent key.",
    )
    p_dec.add_argument(
        "-f", "--force", action="store_true", help="Overwrite output file if it already exists."
    )
    p_dec.set_defaults(func=_cmd_decrypt)

    # info
    p_info = sub.add_parser(
        "info",
        aliases=["list-keys"],
        parents=[common],
        help="Show container metadata and authorized SSH key slots.",
    )
    p_info.add_argument("file", help="Encrypted file path, or '-' for stdin.")
    p_info.add_argument(
        "--verify",
        action="store_true",
        help="Also verify the Header MAC using a loaded SSH agent key.",
    )
    p_info.add_argument("--json", action="store_true", help="Output as JSON.")
    p_info.set_defaults(func=_cmd_info)

    # verify
    p_ver = sub.add_parser(
        "verify",
        parents=[common],
        help="Verify header MAC and all encrypted payload chunks without writing plaintext.",
    )
    p_ver.add_argument("file", help="Encrypted file path, or '-' for stdin.")
    p_ver.add_argument(
        "-k",
        "--key",
        metavar="SELECTOR",
        help="Optional: force verification with a specific loaded SSH agent key.",
    )
    p_ver.set_defaults(func=_cmd_verify)

    # add-key
    p_add = sub.add_parser(
        "add-key",
        parents=[common],
        help="Add one or more SSH keys from the agent to an existing encrypted file.",
    )
    p_add.add_argument("file", help="Encrypted file to update.")
    p_add.add_argument(
        "-k",
        "--key",
        action="append",
        metavar="SELECTOR",
        help="New SSH key selector to add (repeatable).",
    )
    p_add.add_argument(
        "-a",
        "--all-keys",
        action="store_true",
        help="Add all supported deterministic keys currently loaded in the SSH agent.",
    )
    p_add.add_argument(
        "--unlock-key",
        metavar="SELECTOR",
        help="Optional: specific existing authorized key to unlock the file.",
    )
    p_add.add_argument(
        "-o", "--output", metavar="PATH", help="Write updated container to a new file instead of in-place."
    )
    p_add.add_argument(
        "-f", "--force", action="store_true", help="Overwrite --output if it exists."
    )
    p_add.set_defaults(func=_cmd_add_key)

    # remove-key
    p_rem = sub.add_parser(
        "remove-key",
        parents=[common],
        help="Remove one or more authorized SSH keys from an encrypted file.",
    )
    p_rem.add_argument("file", help="Encrypted file to update.")
    p_rem.add_argument(
        "-k",
        "--key",
        action="append",
        required=True,
        metavar="SELECTOR",
        help="Authorized key selector to remove (slot_id, fingerprint, comment, or .pub). Repeatable.",
    )
    p_rem.add_argument(
        "--unlock-key",
        metavar="SELECTOR",
        help="Optional: specific authorized key to unlock the file.",
    )
    p_rem.add_argument(
        "--rekey",
        action="store_true",
        help="Rotate DEK and re-encrypt payload so removed slots cannot decrypt the new file.",
    )
    p_rem.add_argument(
        "-o", "--output", metavar="PATH", help="Write updated container to a new file instead of in-place."
    )
    p_rem.add_argument(
        "-f",
        "--force",
        action="store_true",
        help="Allow overwriting --output or leaving zero remaining keys currently in the agent.",
    )
    p_rem.set_defaults(func=_cmd_remove_key)

    # rekey
    p_rk = sub.add_parser(
        "rekey",
        parents=[common],
        help="Rotate the DEK and re-encrypt the payload for authorized keys.",
    )
    p_rk.add_argument("file", help="Encrypted file to rekey.")
    p_rk.add_argument(
        "--unlock-key",
        metavar="SELECTOR",
        help="Optional: specific authorized key to unlock the file.",
    )
    p_rk.add_argument(
        "--drop-missing",
        action="store_true",
        help="Drop authorized keys that are not currently loaded in the SSH agent.",
    )
    p_rk.add_argument(
        "-o", "--output", metavar="PATH", help="Write rekeyed container to a new file instead of in-place."
    )
    p_rk.add_argument(
        "-f", "--force", action="store_true", help="Overwrite --output if it exists."
    )
    p_rk.set_defaults(func=_cmd_rekey)

    # install
    p_inst = sub.add_parser(
        "install",
        parents=[common],
        help="Install ssh-agent-crypt into /usr/local/bin (via sudo) and configure alias 'ssc' + bash completion in ~/.bashrc.",
    )
    p_inst.add_argument(
        "--bin-dir",
        default="/usr/local/bin",
        metavar="PATH",
        help="Target directory for the installed symlink (default: /usr/local/bin).",
    )
    p_inst.add_argument(
        "--name",
        default="ssh-agent-crypt",
        metavar="NAME",
        help="Installed executable name in --bin-dir (default: ssh-agent-crypt).",
    )
    p_inst.add_argument(
        "--bashrc",
        default="~/.bashrc",
        metavar="PATH",
        help="Shell rc file to receive the alias and completion (default: ~/.bashrc).",
    )
    p_inst.add_argument(
        "--alias",
        default="ssc",
        metavar="NAME",
        help="Shell alias name to add to --bashrc (default: ssc).",
    )
    p_inst.add_argument(
        "--no-alias",
        action="store_true",
        help="Skip adding the shell alias to ~/.bashrc.",
    )
    p_inst.add_argument(
        "--no-completion",
        action="store_true",
        help="Skip adding bash tab-completion to ~/.bashrc.",
    )
    p_inst.add_argument(
        "--no-sudo",
        action="store_true",
        help="Install without sudo (for writable directories such as ~/.local/bin).",
    )
    p_inst.add_argument(
        "--dry-run",
        action="store_true",
        help="Show planned install actions without modifying any files.",
    )
    p_inst.add_argument(
        "-f",
        "--force",
        action="store_true",
        help="Add managed block even if an unmanaged alias with the same name exists.",
    )
    p_inst.set_defaults(func=_cmd_install)

    # completion
    p_comp = sub.add_parser(
        "completion",
        parents=[common],
        help="Generate shell tab-completion script (bash or zsh).",
    )
    p_comp.add_argument(
        "shell",
        nargs="?",
        default="bash",
        choices=("bash", "zsh"),
        help="Target shell (default: bash).",
    )
    p_comp.add_argument(
        "--command",
        dest="command_name",
        default="ssh-agent-crypt",
        metavar="NAME",
        help="Primary command name to register completion for (default: ssh-agent-crypt).",
    )
    p_comp.add_argument(
        "--alias",
        default="ssc",
        metavar="NAME",
        help="Additional alias name to register completion for (default: ssc).",
    )
    p_comp.add_argument(
        "--no-alias",
        action="store_true",
        help="Do not register completion for an alias.",
    )
    p_comp.add_argument(
        "--query-agent-keys",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    p_comp.add_argument(
        "--query-file-keys",
        metavar="PATH",
        help=argparse.SUPPRESS,
    )
    p_comp.set_defaults(func=_cmd_completion)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "encrypt":
        args.stdout_explicit = args.output == "-"
        if args.output is None:
            args.output = "-"
    try:
        return args.func(args)
    except (
        AgentError,
        KeySelectionError,
        CryptoFormatError,
        DecryptionError,
        KeyManagementError,
        InstallError,
        FileExistsError,
        FileNotFoundError,
        PermissionError,
        ValueError,
    ) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Aborted.", file=sys.stderr)
        return 130
