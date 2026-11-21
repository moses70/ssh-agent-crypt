# ssh-agent-crypt

File encryption and decryption backed by a running SSH agent (`SSH_AGENT_SOCK` / `SSH_AUTH_SOCK`) with support for **multiple SSH keys** that can be **added and removed at any time** — without ever exposing secrets on the command line.

## Features

- **Direct `SSH_AGENT_SOCK` / `SSH_AUTH_SOCK` socket client**: Speaks the OpenSSH agent protocol directly over the Unix domain socket in pure Python (`socket.AF_UNIX`), with no external subprocesses and no temporary key files.
  - Resolution priority: `--socket PATH` → `SSH_AGENT_SOCK` → `SSH_AUTH_SOCK`
- **Multi-key envelope encryption**:
  - Every file is encrypted with a random 256-bit **Data Encryption Key (DEK)** using chunked **AES-256-GCM**.
  - Each authorized SSH key receives its own **Key Slot** in an authenticated container header.
  - **Add keys at any time (`add-key`)**: Add new keys from the SSH agent without re-encrypting the payload — existing offline keys remain intact.
  - **Remove keys at any time (`remove-key`)**: Remove individual key slots with built-in safeguards against removing the last remaining key or accidentally locking yourself out. Pass `--rekey` to rotate the DEK and re-encrypt the entire payload.
  - **Rotate DEK (`rekey`)**: Rotate DEK, `file_id`, and chunk nonces for all authorized keys.
- **No secrets on the command line**:
  - Never accepts plaintext, passphrases, DEKs, or private keys as CLI arguments.
  - Supports streaming via `stdin` / `stdout` (`-i - -o -`).
  - Decrypted output files are written atomically via temporary files in the target directory with strict **`0600`** permissions.
- **Integrity & tamper detection**:
  - **Header MAC** (`HMAC-SHA256` with a separate HKDF-derived subkey) authenticates all header metadata and key slots.
  - **Chunked AES-256-GCM** with unique per-chunk nonces (`nonce_prefix || chunk_index`) and an `is_final` flag in AAD detects bit flips, chunk reordering, truncation, and appended trailing bytes.
  - **Determinism verification**: Because `ssh-agent` only signs (it has no decrypt RPC), each slot's Key Encryption Key (KEK) is derived via `HKDF-SHA256` from a deterministic signature over a per-slot random challenge. When creating a slot, the agent signs the challenge twice and both signatures are compared byte-for-byte; non-deterministic key types (such as `ecdsa-sha2-*` or FIDO2 `sk-*`) are safely rejected. Supported key types are **`ssh-ed25519`** and **`ssh-rsa`** (`rsa-sha2-512`).

## Requirements

- Linux / WSL2 with Python 3.10+
- Python `cryptography` package
- Running `ssh-agent` with `SSH_AGENT_SOCK` (or `SSH_AUTH_SOCK`) set

## Installation (`/usr/local/bin` + `ssc` alias + Tab Completion)

```bash
# Preview planned changes first (no files modified)
./ssh-agent-crypt install --dry-run

# Symlink into /usr/local/bin (via sudo) and add alias 'ssc' + Bash tab-completion to ~/.bashrc
./ssh-agent-crypt install
source ~/.bashrc

# Verify both the installed binary and the alias
ssh-agent-crypt --version
ssc --version
```

Tab completion works for both `ssh-agent-crypt` and the `ssc` alias, completing subcommands, flags, file paths, live SSH agent keys (for `--key` / `--unlock-key`), and authorized file key slots (for `remove-key <file> --key`).

Additional `install` options:
- `--bin-dir PATH` (default: `/usr/local/bin`)
- `--name NAME` (default: `ssh-agent-crypt`)
- `--bashrc PATH` (default: `~/.bashrc`)
- `--alias NAME` (default: `ssc`) or `--no-alias`
- `--no-completion` (skip adding Bash completion to `~/.bashrc`)
- `--no-sudo` (e.g., when installing into `~/.local/bin`)
- `--dry-run` (show planned actions without modifying anything)

Manual completion setup (Bash or Zsh):
```bash
# Bash
eval "$(ssh-agent-crypt completion bash --alias ssc)"

# Zsh
eval "$(ssh-agent-crypt completion zsh --alias ssc)"
```

## Usage

### 1. List keys loaded in the SSH agent

```bash
export SSH_AGENT_SOCK="${SSH_AUTH_SOCK}"
ssc agent-keys
```

### 2. Encrypt a file (or `stdin`)

```bash
# Encrypt for a specific key (fingerprint, prefix, comment, or .pub file)
ssc encrypt -i secret.txt -o secret.txt.senc --key alice@host

# Encrypt for multiple keys or all supported keys in the agent
ssc encrypt -i secret.txt -o secret.txt.senc --key alice --key bob
ssc encrypt -i secret.txt -o secret.txt.senc --all-keys

# Pipe plaintext directly via stdin (never touches disk unencrypted)
cat secret.txt | ssc encrypt --all-keys -o secret.txt.senc
```

### 3. Decrypt, inspect, or verify a file

```bash
# Decrypt to a file (created atomically with mode 0600)
ssc decrypt -i secret.txt.senc -o secret.txt

# Decrypt directly to stdout
ssc decrypt -i secret.txt.senc -o -

# Verify header MAC and all encrypted chunks without outputting plaintext
ssc verify secret.txt.senc

# List authorized keys stored in the encrypted file header (works even offline)
ssc info secret.txt.senc
ssc list-keys secret.txt.senc

# Same, plus cryptographic Header MAC verification via ssh-agent
ssc info --verify secret.txt.senc
ssc info --json secret.txt.senc
```

### 4. Add, remove, and rotate keys at any time

```bash
# Add another key from the SSH agent (offline authorized keys remain intact)
ssc add-key secret.txt.senc --key ~/.ssh/id_backup.pub

# Remove a key (by slot_id, fingerprint/prefix, comment, or .pub file)
ssc remove-key secret.txt.senc --key bob@host

# Remove a key AND rotate the DEK (re-encrypts payload for all remaining keys)
ssc remove-key secret.txt.senc --key bob@host --rekey

# Rotate DEK independently
ssc rekey secret.txt.senc
```

---

## Using with Ansible and SOPS / age

By default, using **SOPS** with **age** in Ansible (`community.sops`) requires keeping an unencrypted `age` private key file on disk (e.g., `~/.config/sops/age/keys.txt`). With `ssh-agent-crypt`, you can keep the `age` private key encrypted at rest (even versioned inside your repository or workstation) and unlock it transparently on demand through your running `ssh-agent` — **without ever writing the plaintext `age` private key to disk or passing it on the command line**.

### Step 1: Generate an `age` key and encrypt it directly via `stdin`

The `age` secret key flows directly from `age-keygen` into `ssh-agent-crypt` over a pipe, so the plaintext private key never touches disk:

```bash
mkdir -p secrets

# Generate age keypair: write public key info to secrets/sops-age.pub.txt
# and encrypt the secret key directly via stdin
age-keygen 2> secrets/sops-age.pub.txt \
  | ssh-agent-crypt encrypt -i - -o secrets/sops-age.key.senc --key alice@workstation

# Inspect the age public key (age1...) to place in .sops.yaml
cat secrets/sops-age.pub.txt
```

### Step 2: Configure `.sops.yaml`

Add the generated `age1...` recipient public key to `.sops.yaml` in your Ansible repository:

```yaml
# .sops.yaml
creation_rules:
  - path_regex: \.sops\.ya?ml$
    age: >-
      age1xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

### Step 3: Option A — Native zero-disk integration via `SOPS_AGE_KEY_CMD` (Recommended)

**Requirements:** SOPS `3.10.0+` and Ansible `community.sops` `2.3.0+`.

Configure `ansible.cfg` so `community.sops` automatically asks `ssh-agent-crypt` for the `age` key in memory whenever Ansible reads a `*.sops.yml` file:

```ini
# ansible.cfg
[defaults]
vars_plugins_enabled = host_group_vars,community.sops.sops

[community.sops]
age_key_cmd = ssh-agent-crypt decrypt -q -i ./secrets/sops-age.key.senc -o -
```

> **Note:** Always use the installed binary name `ssh-agent-crypt` (not the interactive bash alias `ssc`) inside `ansible.cfg` and `SOPS_AGE_KEY_CMD`, because non-interactive subshells spawned by Ansible/SOPS do not expand bash aliases.

You can now run Ansible and the `sops` CLI seamlessly:

```bash
# Run Ansible — community.sops decrypts group_vars/host_vars automatically
ansible-playbook site.yml

# Edit or view SOPS files directly from your shell
export SOPS_AGE_KEY_CMD="ssh-agent-crypt decrypt -q -i ./secrets/sops-age.key.senc -o -"
sops group_vars/all/secrets.sops.yml
```

You can also use the `community.sops.sops` lookup plugin in playbooks or tasks without any extra parameters once `ansible.cfg` is configured:

```yaml
- name: Configure service with SOPS-encrypted secret
  ansible.builtin.template:
    src: app.conf.j2
    dest: /etc/app/app.conf
    mode: "0600"
  vars:
    db_password: "{{ lookup('community.sops.sops', 'secrets/db.sops.yml') | from_yaml | json_query('db_password') }}"
  no_log: true
```

### Step 3: Option B — Single-unlock RAM wrapper (`tmpfs`) for SOPS < 3.10.0 or large inventories

If you use an older SOPS release (`< 3.10.0`), have a very large inventory with dozens of SOPS files, or use an SSH agent that prompts for confirmation on every signature, decrypt the `age` key **once** into RAM-only `/dev/shm` with `0600` permissions and clean it up automatically on exit:

```bash
#!/usr/bin/env bash
# scripts/ansible-sops-run.sh
set -euo pipefail

AGE_KEY_ENC="${AGE_KEY_ENC:-./secrets/sops-age.key.senc}"
TMP_KEY="$(mktemp -p /dev/shm sops-age-XXXXXX)"
chmod 600 "${TMP_KEY}"

cleanup() {
    rm -f "${TMP_KEY}"
}
trap cleanup EXIT

ssh-agent-crypt decrypt -q -f -i "${AGE_KEY_ENC}" -o "${TMP_KEY}"
export SOPS_AGE_KEY_FILE="${TMP_KEY}"

exec_status=0
"$@" || exec_status=$?
exit "${exec_status}"
```

Usage:

```bash
./scripts/ansible-sops-run.sh ansible-playbook site.yml
./scripts/ansible-sops-run.sh sops group_vars/all/secrets.sops.yml
```

### Step 4: Managing team access cleanly

- **Onboard a new teammate** (without re-encrypting every SOPS file in the repo):
  ```bash
  # Load teammate's key or have them add their key while an existing key unlocks the file
  ssc add-key secrets/sops-age.key.senc --key bob@laptop
  ssc info --verify secrets/sops-age.key.senc
  ```
- **Remove a key** from the encrypted `age` key container:
  ```bash
  ssc remove-key secrets/sops-age.key.senc --key bob@laptop --rekey
  ```
  > **Security note:** Removing a key with `--rekey` prevents future decryption of the updated `sops-age.key.senc` container, but anyone who previously held access could have copied the underlying `age` private key or plaintext secrets. For full offboarding revocation, also generate a new `age` keypair, run `sops updatekeys` on your SOPS files, and rotate the underlying application secrets.

---

## Project Structure

```text
.
├── ssh-agent-crypt               # Executable CLI entrypoint
├── ssh_agent_crypt/
│   ├── __init__.py
│   ├── agent.py                  # Pure-Python SSH agent protocol client (SSH_AGENT_SOCK / SSH_AUTH_SOCK)
│   ├── crypto.py                 # Envelope encryption, key slots, Header MAC, chunked AES-256-GCM
│   ├── cli.py                    # CLI subcommands, atomic file writes, 0600 plaintext permissions
│   ├── completion.py             # Bash/Zsh tab-completion generator & dynamic key candidates
│   └── installer.py              # Installer for /usr/local/bin (via sudo), alias & completion in ~/.bashrc
├── scripts/
│   ├── run-tests.sh              # Runs the full automated test suite
│   └── demo-workflow.sh          # Isolated end-to-end demo using a temporary ssh-agent
└── tests/
    └── test_ssh_agent_crypt.py   # Unit & live ssh-agent integration tests
```

## Running Tests & Demo

All tests launch a private, isolated `ssh-agent` in a temporary directory and never modify your active SSH agent or `~/.ssh`:

```bash
./scripts/run-tests.sh
./scripts/demo-workflow.sh
```

## Container Format (v1)

```text
MAGIC        (10 bytes) : "SSHACRYPT\x01"
HEADER_LEN   ( 4 bytes) : uint32 big-endian
HEADER_JSON  ( N bytes) : Canonical UTF-8 JSON (version, cipher, kdf, file_id, nonce_prefix, chunk_size, slots[])
HEADER_MAC   (32 bytes) : HMAC-SHA256(header_mac_key, MAGIC || HEADER_LEN || HEADER_JSON)
PAYLOAD      (stream)   : Sequence of uint32(ct_len) || AES-256-GCM(payload_key, nonce, plaintext, aad)
```
