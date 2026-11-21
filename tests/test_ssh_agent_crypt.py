"""Comprehensive unit and live ssh-agent integration tests for ssh-agent-crypt."""

from __future__ import annotations

import json
import os
import shutil
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CLI_BIN = REPO_ROOT / "ssh-agent-crypt"
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from ssh_agent_crypt.agent import (  # noqa: E402
    NonDeterministicKeyError,
    SSHAgentClient,
    compute_fingerprint,
    parse_openssh_pubkey_file,
)
from ssh_agent_crypt.crypto import MAGIC  # noqa: E402


class IsolatedSSHAgent:
    """Starts an isolated ssh-agent bound to a private temporary Unix socket."""

    def __init__(self, workdir: Path) -> None:
        self.socket_path = workdir / "agent.sock"
        self.proc: subprocess.Popen[bytes] | None = None

    def __enter__(self) -> IsolatedSSHAgent:
        self.proc = subprocess.Popen(
            ["ssh-agent", "-D", "-a", str(self.socket_path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            if self.socket_path.exists():
                return self
            if self.proc.poll() is not None:
                raise RuntimeError(f"ssh-agent exited early with code {self.proc.returncode}")
            time.sleep(0.05)
        raise RuntimeError("Timed out waiting for isolated ssh-agent socket")

    def __exit__(self, exc_type, exc, tb) -> None:
        if self.proc is not None and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=3.0)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=3.0)
        self.socket_path.unlink(missing_ok=True)

    def _agent_env(self) -> dict[str, str]:
        env = os.environ.copy()
        env["SSH_AUTH_SOCK"] = str(self.socket_path)
        env.pop("SSH_AGENT_SOCK", None)
        return env

    def add_key(self, private_key_path: Path) -> None:
        subprocess.run(
            ["ssh-add", str(private_key_path)],
            env=self._agent_env(),
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )

    def remove_key(self, pub_key_path: Path) -> None:
        subprocess.run(
            ["ssh-add", "-d", str(pub_key_path)],
            env=self._agent_env(),
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )

    def clear_keys(self) -> None:
        subprocess.run(
            ["ssh-add", "-D"],
            env=self._agent_env(),
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )


def generate_test_key(
    directory: Path, name: str, key_type: str = "ed25519", bits: int | None = None
) -> tuple[Path, Path, str]:
    """Generate an ephemeral test SSH keypair (test-only, no passphrase)."""
    priv = directory / f"id_{name}"
    pub = directory / f"id_{name}.pub"
    cmd = ["ssh-keygen", "-q", "-t", key_type, "-N", "", "-C", f"{name}@test", "-f", str(priv)]
    if bits is not None:
        cmd.extend(["-b", str(bits)])
    subprocess.run(cmd, check=True)
    fp = compute_fingerprint(parse_openssh_pubkey_file(pub))
    return priv, pub, fp


class TestSSHAgentCrypt(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = Path(tempfile.mkdtemp(prefix="ssh-agent-crypt-test-"))
        self.keys_dir = self.tmpdir / "keys"
        self.keys_dir.mkdir(mode=0o700)
        self.agent = IsolatedSSHAgent(self.tmpdir)
        self.agent.__enter__()

        self.alice_priv, self.alice_pub, self.alice_fp = generate_test_key(
            self.keys_dir, "alice-ed25519", "ed25519"
        )
        self.bob_priv, self.bob_pub, self.bob_fp = generate_test_key(
            self.keys_dir, "bob-ed25519", "ed25519"
        )
        self.carol_priv, self.carol_pub, self.carol_fp = generate_test_key(
            self.keys_dir, "carol-rsa", "rsa", bits=2048
        )
        self.ecdsa_priv, self.ecdsa_pub, self.ecdsa_fp = generate_test_key(
            self.keys_dir, "dave-ecdsa", "ecdsa", bits=256
        )

    def tearDown(self) -> None:
        self.agent.__exit__(None, None, None)
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def run_cli(
        self,
        args: list[str],
        *,
        stdin_bytes: bytes | None = None,
        use_agent_sock_env: bool = True,
        use_auth_sock_env: bool = False,
        extra_env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        env = os.environ.copy()
        env.pop("SSH_AGENT_SOCK", None)
        env.pop("SSH_AUTH_SOCK", None)
        if use_agent_sock_env:
            env["SSH_AGENT_SOCK"] = str(self.agent.socket_path)
        if use_auth_sock_env:
            env["SSH_AUTH_SOCK"] = str(self.agent.socket_path)
        if extra_env:
            env.update(extra_env)

        return subprocess.run(
            [str(CLI_BIN), *args],
            input=stdin_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )

    def test_socket_env_resolution(self) -> None:
        self.agent.add_key(self.alice_priv)

        # 1. Only SSH_AGENT_SOCK set
        res = self.run_cli(
            ["agent-keys", "--json"], use_agent_sock_env=True, use_auth_sock_env=False
        )
        self.assertEqual(res.returncode, 0, res.stderr.decode())
        data = json.loads(res.stdout)
        self.assertEqual(data["socket_source"], "SSH_AGENT_SOCK")
        self.assertEqual(len(data["keys"]), 1)
        self.assertEqual(data["keys"][0]["fingerprint"], self.alice_fp)

        # 2. Only SSH_AUTH_SOCK set (fallback)
        res = self.run_cli(
            ["agent-keys", "--json"], use_agent_sock_env=False, use_auth_sock_env=True
        )
        self.assertEqual(res.returncode, 0, res.stderr.decode())
        data = json.loads(res.stdout)
        self.assertEqual(data["socket_source"], "SSH_AUTH_SOCK")

        # 3. SSH_AGENT_SOCK takes precedence over SSH_AUTH_SOCK
        res = self.run_cli(
            ["agent-keys", "--json"],
            use_agent_sock_env=True,
            use_auth_sock_env=False,
            extra_env={"SSH_AUTH_SOCK": "/nonexistent/ignored.sock"},
        )
        self.assertEqual(res.returncode, 0, res.stderr.decode())
        data = json.loads(res.stdout)
        self.assertEqual(data["socket_source"], "SSH_AGENT_SOCK")

        # 4. Explicit --socket overrides env vars
        res = self.run_cli(
            ["--socket", str(self.agent.socket_path), "agent-keys", "--json"],
            use_agent_sock_env=False,
            use_auth_sock_env=False,
        )
        self.assertEqual(res.returncode, 0, res.stderr.decode())
        data = json.loads(res.stdout)
        self.assertEqual(data["socket_source"], "--socket")

        # 5. Missing socket fails cleanly
        res = self.run_cli(
            ["agent-keys"], use_agent_sock_env=False, use_auth_sock_env=False
        )
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("SSH_AGENT_SOCK", res.stderr.decode())

    def test_encrypt_decrypt_ed25519_and_permissions(self) -> None:
        self.agent.add_key(self.alice_priv)
        plain_in = self.tmpdir / "secret.txt"
        enc_file = self.tmpdir / "secret.txt.senc"
        plain_out = self.tmpdir / "secret.decrypted.txt"
        secret_content = b"Top secret payload: \x00\x01\xff UTF-8: \xc3\xa4\xc3\xb6\xc3\xbc\n"
        plain_in.write_bytes(secret_content)

        # Single key in agent -> auto-selected without needing --key
        res = self.run_cli(["encrypt", "-i", str(plain_in), "-o", str(enc_file)])
        self.assertEqual(res.returncode, 0, res.stderr.decode())
        self.assertTrue(enc_file.read_bytes().startswith(MAGIC))
        self.assertNotIn(b"Top secret payload", enc_file.read_bytes())

        # Decrypt to file
        res = self.run_cli(["decrypt", "-i", str(enc_file), "-o", str(plain_out)])
        self.assertEqual(res.returncode, 0, res.stderr.decode())
        self.assertEqual(plain_out.read_bytes(), secret_content)

        # Decrypted file MUST have 0600 permissions
        mode = stat.S_IMODE(os.stat(plain_out).st_mode)
        self.assertEqual(mode, 0o600)

        # Refuses overwrite without --force
        res = self.run_cli(["decrypt", "-i", str(enc_file), "-o", str(plain_out)])
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("--force", res.stderr.decode())

        # Verify command succeeds without writing plaintext
        res = self.run_cli(["verify", str(enc_file)])
        self.assertEqual(res.returncode, 0, res.stderr.decode())

    def test_encrypt_decrypt_rsa_key(self) -> None:
        self.agent.add_key(self.carol_priv)
        secret = b"RSA-SHA2-512 deterministic wrapping test payload"
        enc_res = self.run_cli(
            ["encrypt", "-i", "-", "-o", "-", "--key", "carol-rsa"],
            stdin_bytes=secret,
        )
        self.assertEqual(enc_res.returncode, 0, enc_res.stderr.decode())
        self.assertTrue(enc_res.stdout.startswith(MAGIC))

        dec_res = self.run_cli(
            ["decrypt", "-i", "-", "-o", "-"],
            stdin_bytes=enc_res.stdout,
        )
        self.assertEqual(dec_res.returncode, 0, dec_res.stderr.decode())
        self.assertEqual(dec_res.stdout, secret)

    def test_non_deterministic_ecdsa_rejected(self) -> None:
        self.agent.add_key(self.ecdsa_priv)

        # CLI marks ECDSA unsupported and rejects encryption
        ak_res = self.run_cli(["agent-keys", "--json"])
        self.assertEqual(ak_res.returncode, 0)
        keys = json.loads(ak_res.stdout)["keys"]
        self.assertEqual(len(keys), 1)
        self.assertFalse(keys[0]["supported"])

        enc_res = self.run_cli(
            ["encrypt", "-i", "-", "-o", "-", "--key", "dave-ecdsa"],
            stdin_bytes=b"hello",
        )
        self.assertNotEqual(enc_res.returncode, 0)
        self.assertIn("deterministic", enc_res.stderr.decode().lower())

        # Direct double-sign determinism guard in SSHAgentClient also catches ECDSA
        with SSHAgentClient(str(self.agent.socket_path)) as client:
            agent_keys = client.list_keys()
            with self.assertRaises(NonDeterministicKeyError):
                client.sign_deterministic(agent_keys[0].key_blob, b"test-challenge", flags=0)

    def test_multi_key_lifecycle_add_and_remove_anytime(self) -> None:
        """Encrypt with Alice, add Bob, switch to Bob, add Carol (RSA) while Alice offline,
        remove Bob, verify Bob loses access while offline Alice & Carol retain access."""
        self.agent.add_key(self.alice_priv)
        enc_file = self.tmpdir / "multi.senc"
        secret = b"Multi-key secret document with dynamic key rotation.\n"

        # 1. Encrypt initially for Alice only
        res = self.run_cli(
            ["encrypt", "-i", "-", "-o", str(enc_file), "--key", str(self.alice_pub)],
            stdin_bytes=secret,
        )
        self.assertEqual(res.returncode, 0, res.stderr.decode())

        # 2. Load Bob into agent and add Bob to the encrypted file
        self.agent.add_key(self.bob_priv)
        res = self.run_cli(["add-key", str(enc_file), "--key", "bob-ed25519"])
        self.assertEqual(res.returncode, 0, res.stderr.decode())

        # Adding Bob a second time is idempotent (skipped cleanly)
        res = self.run_cli(["add-key", str(enc_file), "--key", self.bob_fp])
        self.assertEqual(res.returncode, 0, res.stderr.decode())
        self.assertIn("Skipped already authorized key", res.stderr.decode())

        # 3. Unload Alice from agent; Bob alone can decrypt!
        self.agent.remove_key(self.alice_pub)
        dec_bob = self.run_cli(["decrypt", "-i", str(enc_file), "-o", "-"])
        self.assertEqual(dec_bob.returncode, 0, dec_bob.stderr.decode())
        self.assertEqual(dec_bob.stdout, secret)

        # 4. Load Carol (RSA) and add Carol while Alice is OFFLINE
        self.agent.add_key(self.carol_priv)
        res = self.run_cli(["add-key", str(enc_file), "--key", "carol-rsa"])
        self.assertEqual(res.returncode, 0, res.stderr.decode())

        # Inspect info --json --verify
        info_res = self.run_cli(["info", "--verify", "--json", str(enc_file)])
        self.assertEqual(info_res.returncode, 0, info_res.stderr.decode())
        info = json.loads(info_res.stdout)
        self.assertTrue(info["header_mac_verified"])
        self.assertEqual(len(info["slots"]), 3)
        by_fp = {s["fingerprint"]: s for s in info["slots"]}
        self.assertFalse(by_fp[self.alice_fp]["in_agent"])
        self.assertTrue(by_fp[self.bob_fp]["in_agent"])
        self.assertTrue(by_fp[self.carol_fp]["in_agent"])

        # 5. Remove Bob from the file (Alice offline, Carol active)
        res = self.run_cli(["remove-key", str(enc_file), "--key", "bob-ed25519"])
        self.assertEqual(res.returncode, 0, res.stderr.decode())

        # 6. Keep ONLY Bob in agent -> decryption MUST fail!
        self.agent.remove_key(self.carol_pub)
        dec_bob_after = self.run_cli(["decrypt", "-i", str(enc_file), "-o", "-"])
        self.assertNotEqual(dec_bob_after.returncode, 0)
        self.assertIn("None of the file's authorized SSH keys", dec_bob_after.stderr.decode())

        # 7. Reload offline Alice -> decryption MUST succeed (offline slot preserved!)
        self.agent.clear_keys()
        self.agent.add_key(self.alice_priv)
        dec_alice = self.run_cli(["decrypt", "-i", str(enc_file), "-o", "-"])
        self.assertEqual(dec_alice.returncode, 0, dec_alice.stderr.decode())
        self.assertEqual(dec_alice.stdout, secret)

        # 8. Reload Carol -> decryption also succeeds
        self.agent.clear_keys()
        self.agent.add_key(self.carol_priv)
        dec_carol = self.run_cli(["decrypt", "-i", str(enc_file), "-o", "-"])
        self.assertEqual(dec_carol.returncode, 0, dec_carol.stderr.decode())
        self.assertEqual(dec_carol.stdout, secret)

    def test_remove_key_guards_and_rekey(self) -> None:
        self.agent.add_key(self.alice_priv)
        self.agent.add_key(self.bob_priv)
        enc_file = self.tmpdir / "rekey.senc"
        secret = b"Secret data before and after DEK rotation."

        res = self.run_cli(
            ["encrypt", "-i", "-", "-o", str(enc_file), "--all-keys"],
            stdin_bytes=secret,
        )
        self.assertEqual(res.returncode, 0, res.stderr.decode())

        # Refuses removing all keys at once
        res = self.run_cli(
            ["remove-key", str(enc_file), "--key", "alice", "--key", "bob"]
        )
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("last remaining key", res.stderr.decode())

        # Save original file_id and raw bytes
        info_before = json.loads(self.run_cli(["info", "--json", str(enc_file)]).stdout)
        old_bytes = enc_file.read_bytes()

        # Remove Bob WITH --rekey (rotates DEK + file_id + re-encrypts payload)
        res = self.run_cli(["remove-key", str(enc_file), "--key", "bob", "--rekey"])
        self.assertEqual(res.returncode, 0, res.stderr.decode())

        info_after = json.loads(self.run_cli(["info", "--json", str(enc_file)]).stdout)
        self.assertNotEqual(info_before["file_id_b64"], info_after["file_id_b64"])
        self.assertEqual(len(info_after["slots"]), 1)
        self.assertEqual(info_after["slots"][0]["fingerprint"], self.alice_fp)
        self.assertNotEqual(old_bytes, enc_file.read_bytes())

        # Alice decrypts rekeyed file
        dec = self.run_cli(["decrypt", "-i", str(enc_file), "-o", "-"])
        self.assertEqual(dec.returncode, 0, dec.stderr.decode())
        self.assertEqual(dec.stdout, secret)

        # Cannot remove Alice (the sole remaining key)
        res = self.run_cli(["remove-key", str(enc_file), "--key", "alice", "--force"])
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("last remaining key", res.stderr.decode())

    def test_lockout_guard_when_remaining_key_offline(self) -> None:
        self.agent.add_key(self.alice_priv)
        self.agent.add_key(self.bob_priv)
        enc_file = self.tmpdir / "lockout.senc"
        self.run_cli(
            ["encrypt", "-i", "-", "-o", str(enc_file), "--all-keys"],
            stdin_bytes=b"lockout test",
        )
        # Unload Bob so only Alice is in agent
        self.agent.remove_key(self.bob_pub)

        # Trying to remove Alice without --force fails because Bob is not in agent
        res = self.run_cli(["remove-key", str(enc_file), "--key", "alice"])
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("--force", res.stderr.decode())

        # With --force, removing Alice succeeds and Bob can decrypt later
        res = self.run_cli(["remove-key", str(enc_file), "--key", "alice", "--force"])
        self.assertEqual(res.returncode, 0, res.stderr.decode())

        self.agent.clear_keys()
        self.agent.add_key(self.bob_priv)
        dec = self.run_cli(["decrypt", "-i", str(enc_file), "-o", "-"])
        self.assertEqual(dec.returncode, 0, dec.stderr.decode())
        self.assertEqual(dec.stdout, b"lockout test")

    def test_rekey_command_and_drop_missing(self) -> None:
        self.agent.add_key(self.alice_priv)
        self.agent.add_key(self.bob_priv)
        enc_file = self.tmpdir / "standalone_rekey.senc"
        secret = b"Standalone rekey test payload"
        self.run_cli(
            ["encrypt", "-i", "-", "-o", str(enc_file), "--all-keys"],
            stdin_bytes=secret,
        )
        old_id = json.loads(self.run_cli(["info", "--json", str(enc_file)]).stdout)["file_id_b64"]

        # Unload Bob -> rekey refuses unless --drop-missing is passed
        self.agent.remove_key(self.bob_pub)
        res = self.run_cli(["rekey", str(enc_file)])
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("--drop-missing", res.stderr.decode())

        # Rekey with --drop-missing succeeds for Alice
        res = self.run_cli(["rekey", "--drop-missing", str(enc_file)])
        self.assertEqual(res.returncode, 0, res.stderr.decode())
        info = json.loads(self.run_cli(["info", "--json", str(enc_file)]).stdout)
        self.assertNotEqual(info["file_id_b64"], old_id)
        self.assertEqual(len(info["slots"]), 1)

        dec = self.run_cli(["decrypt", "-i", str(enc_file), "-o", "-"])
        self.assertEqual(dec.returncode, 0)
        self.assertEqual(dec.stdout, secret)

    def test_empty_exact_chunk_and_large_multichunk_files(self) -> None:
        self.agent.add_key(self.alice_priv)
        for label, payload in [
            ("empty", b""),
            ("exact_chunk", os.urandom(4096)),
            ("multi_chunk", os.urandom(4096 * 25 + 137)),
        ]:
            with self.subTest(case=label):
                enc = self.run_cli(
                    ["encrypt", "-i", "-", "-o", "-", "--chunk-size", "4096"],
                    stdin_bytes=payload,
                )
                self.assertEqual(enc.returncode, 0, enc.stderr.decode())
                dec = self.run_cli(
                    ["decrypt", "-i", "-", "-o", "-"],
                    stdin_bytes=enc.stdout,
                )
                self.assertEqual(dec.returncode, 0, dec.stderr.decode())
                self.assertEqual(dec.stdout, payload)

    def test_tampering_truncation_and_trailing_garbage_detected(self) -> None:
        self.agent.add_key(self.alice_priv)
        enc_file = self.tmpdir / "tamper.senc"
        payload = os.urandom(4096 * 3 + 500)  # 4 chunks
        res = self.run_cli(
            ["encrypt", "-i", "-", "-o", str(enc_file), "--chunk-size", "4096"],
            stdin_bytes=payload,
        )
        self.assertEqual(res.returncode, 0, res.stderr.decode())
        valid = enc_file.read_bytes()
        (header_len,) = struct.unpack_from(">I", valid, len(MAGIC))
        header_start = len(MAGIC) + 4
        mac_start = header_start + header_len
        payload_start = mac_start + 32

        # 1. Tamper 1 byte in Header JSON (e.g. comment char) -> Header MAC fails
        tampered_header = bytearray(valid)
        idx = valid.find(b"alice-ed25519@test")
        self.assertGreater(idx, 0)
        tampered_header[idx] ^= 0x01
        r = self.run_cli(["verify", "-"], stdin_bytes=bytes(tampered_header))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("Header MAC", r.stderr.decode())

        # 2. Tamper 1 byte in Header MAC -> fails
        tampered_mac = bytearray(valid)
        tampered_mac[mac_start] ^= 0xFF
        r = self.run_cli(["verify", "-"], stdin_bytes=bytes(tampered_mac))
        self.assertNotEqual(r.returncode, 0)

        # 3. Tamper 1 byte in payload -> fails AND does not leave output file behind
        tampered_payload = bytearray(valid)
        tampered_payload[payload_start + 10] ^= 0x80
        bad_file = self.tmpdir / "bad_payload.senc"
        bad_file.write_bytes(bytes(tampered_payload))
        out_file = self.tmpdir / "should_not_exist.txt"
        r = self.run_cli(["decrypt", "-i", str(bad_file), "-o", str(out_file)])
        self.assertNotEqual(r.returncode, 0)
        self.assertFalse(out_file.exists())

        # 4. Truncation attack: drop the final chunk while keeping chunk 0 intact
        (chunk0_len,) = struct.unpack_from(">I", valid, payload_start)
        truncated = valid[: payload_start + 4 + chunk0_len]
        r = self.run_cli(["verify", "-"], stdin_bytes=truncated)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("Authentication failed", r.stderr.decode())

        # 5. Trailing garbage appended after valid final chunk
        r = self.run_cli(["verify", "-"], stdin_bytes=valid + b"\x00\x00")
        self.assertNotEqual(r.returncode, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
