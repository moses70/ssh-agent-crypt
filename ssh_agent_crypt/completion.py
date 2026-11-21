"""Shell completion generator (Bash and Zsh) for ssh-agent-crypt."""

from __future__ import annotations

import re
from pathlib import Path

from .agent import AgentError, SSHAgentClient, resolve_agent_socket
from .crypto import CryptoFormatError, read_container_header

SAFE_TOKEN_RE = re.compile(r"^[A-Za-z0-9_@.+:/-]+$")
SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]+$")


def _validate_shell_name(name: str, label: str) -> str:
    if not name or not SAFE_NAME_RE.match(name):
        raise ValueError(f"Invalid {label}: {name!r}")
    return name


def _format_candidate(text: str) -> str | None:
    cleaned = text.strip()
    if not cleaned or not SAFE_TOKEN_RE.match(cleaned):
        return None
    return cleaned


def query_agent_key_candidates(cli_socket: str | None = None) -> list[str]:
    """Return safe, non-secret completion candidates from the active SSH agent."""
    try:
        sock_path, _source = resolve_agent_socket(cli_socket)
        with SSHAgentClient(sock_path, timeout=2.0) as client:
            keys = client.list_keys()
    except AgentError:
        return []

    candidates: list[str] = []
    seen: set[str] = set()
    for key in keys:
        if not key.is_supported:
            continue
        # Prefer comment (if single safe token) and bare fingerprint hash (no ':' for Bash COMP_WORDBREAKS)
        comment_cand = _format_candidate(key.comment)
        if comment_cand and ":" not in comment_cand and comment_cand not in seen:
            candidates.append(comment_cand)
            seen.add(comment_cand)
        bare_fp = key.fingerprint.removeprefix("SHA256:")
        if bare_fp and bare_fp not in seen:
            candidates.append(bare_fp)
            seen.add(bare_fp)
    return candidates


def query_file_key_candidates(file_path: str) -> list[str]:
    """Return safe, non-secret key slot completion candidates from an encrypted file header."""
    path = Path(file_path).expanduser()
    if not path.is_file():
        return []
    try:
        with open(path, "rb") as handle:
            header, _raw, _mac = read_container_header(handle)
    except (OSError, CryptoFormatError):
        return []

    candidates: list[str] = []
    seen: set[str] = set()
    for slot in header.slots:
        comment_cand = _format_candidate(slot.comment)
        if comment_cand and ":" not in comment_cand and comment_cand not in seen:
            candidates.append(comment_cand)
            seen.add(comment_cand)
        if slot.slot_id and slot.slot_id not in seen:
            candidates.append(slot.slot_id)
            seen.add(slot.slot_id)
        bare_fp = slot.fingerprint.removeprefix("SHA256:")
        if bare_fp and bare_fp not in seen:
            candidates.append(bare_fp)
            seen.add(bare_fp)
    return candidates


def generate_bash_completion(
    command_name: str = "ssh-agent-crypt",
    alias_name: str | None = "ssc",
) -> str:
    """Generate a self-contained Bash completion script."""
    cmd = _validate_shell_name(command_name, "command name")
    registrations = [f"complete -o default -F _ssh_agent_crypt_completions {cmd}"]
    if alias_name:
        alias = _validate_shell_name(alias_name, "alias name")
        if alias != cmd:
            registrations.append(
                f"complete -o default -F _ssh_agent_crypt_completions {alias}"
            )

    reg_lines = "\n".join(registrations)
    return f"""# Bash completion for {cmd}
_ssh_agent_crypt_completions() {{
    local cur prev
    cur="${{COMP_WORDS[COMP_CWORD]}}"
    prev=""
    if (( COMP_CWORD > 0 )); then
        prev="${{COMP_WORDS[COMP_CWORD-1]}}"
    fi

    local global_opts="--version --socket -q --quiet -h --help"
    local subcommands="agent-keys list-agent-keys encrypt decrypt info list-keys verify add-key remove-key rekey install completion"

    local subcmd=""
    local target_file=""
    local i=1
    while (( i < COMP_CWORD )); do
        local w="${{COMP_WORDS[i]}}"
        case "${{w}}" in
            --socket)
                (( i += 2 ))
                continue
                ;;
            -*)
                (( i += 1 ))
                continue
                ;;
            *)
                subcmd="${{w}}"
                (( i += 1 ))
                break
                ;;
        esac
    done

    if [[ "${{prev}}" == "--socket" ]]; then
        COMPREPLY=( $(compgen -f -- "${{cur}}") )
        return 0
    fi

    if [[ -z "${{subcmd}}" ]]; then
        if [[ "${{cur}}" == -* ]]; then
            COMPREPLY=( $(compgen -W "${{global_opts}}" -- "${{cur}}") )
        else
            COMPREPLY=( $(compgen -W "${{subcommands}}" -- "${{cur}}") )
        fi
        return 0
    fi

    while (( i < COMP_CWORD )); do
        local w="${{COMP_WORDS[i]}}"
        case "${{w}}" in
            -i|--input|-o|--output|-k|--key|--unlock-key|--chunk-size|--bin-dir|--name|--bashrc|--alias|--command|--socket)
                (( i += 2 ))
                continue
                ;;
            -*)
                (( i += 1 ))
                continue
                ;;
            *)
                if [[ -z "${{target_file}}" ]]; then
                    target_file="${{w}}"
                fi
                (( i += 1 ))
                ;;
        esac
    done

    case "${{prev}}" in
        -i|--input|-o|--output|--bashrc)
            COMPREPLY=( $(compgen -f -- "${{cur}}") )
            return 0
            ;;
        --bin-dir)
            COMPREPLY=( $(compgen -d -- "${{cur}}") )
            return 0
            ;;
        --chunk-size)
            COMPREPLY=( $(compgen -W "4096 16384 65536 262144 1048576" -- "${{cur}}") )
            return 0
            ;;
        -k|--key|--unlock-key)
            local key_candidates=""
            if [[ "${{subcmd}}" == "remove-key" && "${{prev}}" != "--unlock-key" && -n "${{target_file}}" && -f "${{target_file}}" ]]; then
                key_candidates="$({cmd} completion --query-file-keys "${{target_file}}" 2>/dev/null || true)"
            else
                key_candidates="$({cmd} completion --query-agent-keys 2>/dev/null || true)"
            fi
            local IFS=$'\\n'
            COMPREPLY=( $(compgen -W "${{key_candidates}}" -- "${{cur}}") )
            if [[ ${{#COMPREPLY[@]}} -eq 0 || "${{cur}}" == */* || "${{cur}}" == .* || "${{cur}}" == ~* ]]; then
                COMPREPLY+=( $(compgen -f -X '!*.pub' -- "${{cur}}") )
            fi
            return 0
            ;;
    esac

    local opts=""
    local shared_opts="-q --quiet --socket -h --help"
    case "${{subcmd}}" in
        agent-keys|list-agent-keys)
            opts="--json ${{shared_opts}}"
            ;;
        encrypt)
            opts="-i --input -o --output -k --key -a --all-keys --chunk-size -f --force ${{shared_opts}}"
            ;;
        decrypt)
            opts="-i --input -o --output -k --key -f --force ${{shared_opts}}"
            ;;
        info|list-keys)
            opts="--verify --json ${{shared_opts}}"
            ;;
        verify)
            opts="-k --key ${{shared_opts}}"
            ;;
        add-key)
            opts="-k --key -a --all-keys --unlock-key -o --output -f --force ${{shared_opts}}"
            ;;
        remove-key)
            opts="-k --key --unlock-key --rekey -o --output -f --force ${{shared_opts}}"
            ;;
        rekey)
            opts="--unlock-key --drop-missing -o --output -f --force ${{shared_opts}}"
            ;;
        install)
            opts="--bin-dir --name --bashrc --alias --no-alias --no-completion --no-sudo --dry-run -f --force ${{shared_opts}}"
            ;;
        completion)
            if [[ "${{cur}}" == -* ]]; then
                opts="--alias --no-alias --command ${{shared_opts}}"
            else
                COMPREPLY=( $(compgen -W "bash zsh" -- "${{cur}}") )
                return 0
            fi
            ;;
    esac

    if [[ "${{cur}}" == -* ]]; then
        COMPREPLY=( $(compgen -W "${{opts}}" -- "${{cur}}") )
    else
        case "${{subcmd}}" in
            info|list-keys|verify|add-key|remove-key|rekey)
                COMPREPLY=( $(compgen -f -- "${{cur}}") )
                ;;
        esac
    fi
    return 0
}}
{reg_lines}
"""


def generate_zsh_completion(
    command_name: str = "ssh-agent-crypt",
    alias_name: str | None = "ssc",
) -> str:
    """Generate a Zsh completion snippet leveraging bashcompinit."""
    bash_script = generate_bash_completion(command_name=command_name, alias_name=alias_name)
    return (
        "# Zsh completion via bashcompinit\n"
        "autoload -Uz compinit && compinit\n"
        "autoload -Uz bashcompinit && bashcompinit\n\n"
        + bash_script
    )
