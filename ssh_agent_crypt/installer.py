"""Installation helper for ssh-agent-crypt (/usr/local/bin + ~/.bashrc alias)."""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

ALIAS_BEGIN = "# >>> ssh-agent-crypt alias >>>"
ALIAS_END = "# <<< ssh-agent-crypt alias <<<"
SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]+$")


class InstallError(Exception):
    """Raised when installation cannot be completed safely."""


@dataclass(frozen=True)
class InstallResult:
    source_script: Path
    target_bin: Path
    used_sudo: bool
    bin_action: str
    bashrc_path: Path | None
    alias_name: str | None
    alias_action: str
    dry_run: bool


def default_source_script() -> Path:
    """Locate the repository's executable ssh-agent-crypt entrypoint."""
    return Path(__file__).resolve().parent.parent / "ssh-agent-crypt"


def _validate_name(value: str, label: str) -> str:
    if not value or not SAFE_NAME_RE.match(value):
        raise InstallError(
            f"Invalid {label} '{value}'. Allowed characters: letters, digits, '_', '.', '-'."
        )
    return value


def _install_symlink_no_sudo(source: Path, target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.is_dir() and not target.is_symlink():
        raise InstallError(f"Target path is a directory, not a file/symlink: {target}")
    # Atomic symlink replacement in target.parent
    tmp_name = f".{target.name}.tmp.{os.getpid()}"
    tmp_link = target.parent / tmp_name
    try:
        tmp_link.unlink(missing_ok=True)
        os.symlink(str(source), str(tmp_link))
        os.replace(str(tmp_link), str(target))
    except BaseException:
        try:
            tmp_link.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def _install_symlink_with_sudo(source: Path, target: Path) -> None:
    if shutil.which("sudo") is None:
        raise InstallError(
            "sudo is not available on PATH. Run as root or pass --no-sudo with a writable --bin-dir."
        )
    try:
        if not target.parent.exists():
            subprocess.run(
                ["sudo", "install", "-d", "-m", "755", str(target.parent)],
                check=True,
            )
        subprocess.run(
            ["sudo", "ln", "-sfn", str(source), str(target)],
            check=True,
        )
    except subprocess.CalledProcessError as exc:
        raise InstallError(
            f"sudo installation failed with exit code {exc.returncode}."
        ) from exc


def _update_bashrc_alias(
    bashrc_path: Path,
    alias_name: str,
    command_name: str,
    *,
    force: bool = False,
    dry_run: bool = False,
) -> str:
    """Idempotently add or update `alias <alias_name>='<command_name>'` in bashrc."""
    alias_line = f"alias {alias_name}='{command_name}'"
    managed_block = f"{ALIAS_BEGIN}\n{alias_line}\n{ALIAS_END}\n"

    if bashrc_path.exists():
        original = bashrc_path.read_text(encoding="utf-8")
        mode = stat.S_IMODE(os.stat(bashrc_path).st_mode)
    else:
        original = ""
        mode = 0o644

    block_re = re.compile(
        rf"{re.escape(ALIAS_BEGIN)}\n.*?\n{re.escape(ALIAS_END)}\n?",
        re.DOTALL,
    )
    existing_block = block_re.search(original)
    if existing_block:
        if existing_block.group(0).rstrip("\n") == managed_block.rstrip("\n"):
            return "unchanged"
        updated = block_re.sub(managed_block, original, count=1)
        action = "updated"
    else:
        # Check for unmanaged alias with the same name
        unmanaged_re = re.compile(
            rf"^\s*alias\s+{re.escape(alias_name)}=(?P<rhs>.+?)\s*$",
            re.MULTILINE,
        )
        match = unmanaged_re.search(original)
        if match:
            rhs = match.group("rhs").strip()
            if rhs in (f"'{command_name}'", f'"{command_name}"', command_name):
                return "unchanged"
            if not force:
                raise InstallError(
                    f"Alias '{alias_name}' already exists in {bashrc_path} as: "
                    f"{match.group(0).strip()}\n"
                    "Use --force to add the managed alias anyway or choose another name with --alias."
                )

        if original and not original.endswith("\n"):
            updated = original + "\n\n" + managed_block
        elif original:
            updated = original + "\n" + managed_block
        else:
            updated = managed_block
        action = "added"

    if dry_run:
        return f"would-{action}"

    bashrc_path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        prefix=".bashrc-ssh-agent-crypt-", dir=str(bashrc_path.parent)
    )
    tmp_path = Path(tmp_name)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(updated)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, bashrc_path)
    except BaseException:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise

    return action


def install_tool(
    *,
    bin_dir: Path = Path("/usr/local/bin"),
    command_name: str = "ssh-agent-crypt",
    bashrc_path: Path | None = Path("~/.bashrc"),
    alias_name: str | None = "ssc",
    use_sudo: bool | None = None,
    force: bool = False,
    dry_run: bool = False,
    source_script: Path | None = None,
) -> InstallResult:
    """Install ssh-agent-crypt into `bin_dir` (via sudo if needed) and configure bashrc alias."""
    command_name = _validate_name(command_name, "command name")
    if alias_name is not None:
        alias_name = _validate_name(alias_name, "alias name")

    source = (source_script or default_source_script()).resolve()
    if not source.is_file():
        raise InstallError(f"Source script not found: {source}")
    if not os.access(source, os.X_OK):
        raise InstallError(f"Source script is not executable: {source}")

    resolved_bin_dir = bin_dir.expanduser()
    target_bin = resolved_bin_dir / command_name

    # Decide whether sudo is needed
    if use_sudo is None:
        effective_sudo = os.geteuid() != 0
    else:
        effective_sudo = use_sudo and (os.geteuid() != 0)

    if dry_run:
        bin_action = (
            f"would-link (sudo ln -sfn {source} {target_bin})"
            if effective_sudo
            else f"would-link ({target_bin} -> {source})"
        )
    else:
        if effective_sudo:
            _install_symlink_with_sudo(source, target_bin)
        else:
            _install_symlink_no_sudo(source, target_bin)
        bin_action = "linked"

    resolved_bashrc: Path | None = None
    if bashrc_path is not None and alias_name is not None:
        resolved_bashrc = bashrc_path.expanduser()
        alias_action = _update_bashrc_alias(
            resolved_bashrc,
            alias_name,
            command_name,
            force=force,
            dry_run=dry_run,
        )
    else:
        alias_action = "skipped"

    return InstallResult(
        source_script=source,
        target_bin=target_bin,
        used_sudo=effective_sudo,
        bin_action=bin_action,
        bashrc_path=resolved_bashrc,
        alias_name=alias_name if resolved_bashrc is not None else None,
        alias_action=alias_action,
        dry_run=dry_run,
    )
