#!/usr/bin/env bash
# End-to-end demonstration of ssh-agent-crypt using an isolated ssh-agent
# exposed exclusively via SSH_AGENT_SOCK (without touching the user's real agent
# or exposing any secrets on the command line).
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
TOOL="${REPO_ROOT}/ssh-agent-crypt"

TMPDIR_DEMO="$(mktemp -d -t ssh-agent-crypt-demo-XXXXXX)"
AGENT_PID=""

cleanup() {
    if [[ -n "${AGENT_PID}" ]]; then
        kill "${AGENT_PID}" 2>/dev/null || true
        wait "${AGENT_PID}" 2>/dev/null || true
    fi
    rm -rf "${TMPDIR_DEMO}"
}
trap cleanup EXIT

SOCK="${TMPDIR_DEMO}/agent.sock"
ssh-agent -D -a "${SOCK}" >/dev/null 2>&1 &
AGENT_PID=$!

for _ in $(seq 1 50); do
    [[ -S "${SOCK}" ]] && break
    sleep 0.05
done

# Export SSH_AGENT_SOCK and unset SSH_AUTH_SOCK for the tool
unset SSH_AUTH_SOCK
export SSH_AGENT_SOCK="${SOCK}"

echo "=== 1. Generate two ephemeral test keys (Ed25519 + RSA) ==="
ssh-keygen -q -t ed25519 -N "" -C "alice@demo" -f "${TMPDIR_DEMO}/id_alice"
ssh-keygen -q -t rsa -b 2048 -N "" -C "bob@demo" -f "${TMPDIR_DEMO}/id_bob"

SSH_AUTH_SOCK="${SOCK}" ssh-add -q "${TMPDIR_DEMO}/id_alice"
"${TOOL}" agent-keys

echo
echo "=== 2. Encrypt sample file via stdin/file (no secret on CLI) ==="
cat > "${TMPDIR_DEMO}/sample.txt" <<'EOF'
Geheime Testdaten fuer ssh-agent-crypt.
Zeile 2: Verschluesselt mit AES-256-GCM und SSH-Agent-Schluessel-Slots.
EOF
chmod 600 "${TMPDIR_DEMO}/sample.txt"

"${TOOL}" encrypt -i "${TMPDIR_DEMO}/sample.txt" -o "${TMPDIR_DEMO}/sample.txt.senc" --key "alice@demo"
"${TOOL}" info --verify "${TMPDIR_DEMO}/sample.txt.senc"

echo
echo "=== 3. Add Bob's RSA key to the encrypted file ==="
SSH_AUTH_SOCK="${SOCK}" ssh-add -q "${TMPDIR_DEMO}/id_bob"
"${TOOL}" add-key "${TMPDIR_DEMO}/sample.txt.senc" --key "bob@demo"
"${TOOL}" info "${TMPDIR_DEMO}/sample.txt.senc"

echo
echo "=== 4. Remove Alice from ssh-agent and decrypt with Bob alone ==="
SSH_AUTH_SOCK="${SOCK}" ssh-add -q -d "${TMPDIR_DEMO}/id_alice.pub"
"${TOOL}" decrypt -i "${TMPDIR_DEMO}/sample.txt.senc" -o "${TMPDIR_DEMO}/decrypted_by_bob.txt"
cmp -s "${TMPDIR_DEMO}/sample.txt" "${TMPDIR_DEMO}/decrypted_by_bob.txt"
echo "Decrypted by Bob matches original (file mode: $(stat -c '%a' "${TMPDIR_DEMO}/decrypted_by_bob.txt"))!"

echo
echo "=== 5. Remove Alice from encrypted file with --rekey (DEK rotation) ==="
"${TOOL}" remove-key "${TMPDIR_DEMO}/sample.txt.senc" --key "alice@demo" --rekey
"${TOOL}" info --verify "${TMPDIR_DEMO}/sample.txt.senc"

echo
echo "=== 6. Confirm Alice can no longer decrypt after removal ==="
SSH_AUTH_SOCK="${SOCK}" ssh-add -q -D
SSH_AUTH_SOCK="${SOCK}" ssh-add -q "${TMPDIR_DEMO}/id_alice"
if "${TOOL}" verify "${TMPDIR_DEMO}/sample.txt.senc" 2>/dev/null; then
    echo "ERROR: Alice unexpectedly succeeded!" >&2
    exit 1
else
    echo "Confirmed: Alice is revoked and cannot decrypt."
fi

echo
echo "=== Demo completed successfully! ==="
