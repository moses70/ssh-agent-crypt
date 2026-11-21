# ssh-agent-crypt

Dateiverschlüsselung und -entschlüsselung über einen laufenden SSH-Agent (`SSH_AGENT_SOCK` bzw. `SSH_AUTH_SOCK`) mit Unterstützung für **mehrere SSH-Keys**, die **jederzeit hinzugefügt und entfernt** werden können – ohne Secrets auf der Kommandozeile.

## Features

- **Direkte Kommunikation mit `SSH_AGENT_SOCK` / `SSH_AUTH_SOCK`**: Spricht das OpenSSH-Agent-Protokoll direkt über den Unix-Domain-Socket in reinem Python (`socket.AF_UNIX`), ohne Subprozesse und ohne temporäre Schlüsseldateien.
  - Priorität: `--socket PATH` → `SSH_AGENT_SOCK` → `SSH_AUTH_SOCK`
- **Multi-Key-Envelope-Verschlüsselung**:
  - Jede Datei wird mit einem zufälligen 256-Bit **Data Encryption Key (DEK)** und chunked **AES-256-GCM** verschlüsselt.
  - Jeder autorisierte SSH-Key erhält einen eigenen **Key Slot** im authentifizierten Header.
  - **Keys jederzeit hinzufügen (`add-key`)**: Fügt neue Keys aus dem SSH-Agent hinzu, ohne die Nutzdaten neu zu verschlüsseln – andere (derzeit nicht im Agent geladene) Keys bleiben unberührt.
  - **Keys jederzeit entfernen (`remove-key`)**: Entfernt gezielt einzelne Key Slots; schützt vor dem Löschen des letzten Keys und vor versehentlichem Aussperren. Mit `--rekey` wird zusätzlich ein neuer DEK erzeugt und die gesamte Datei neu verschlüsselt.
  - **DEK-Rotation (`rekey`)**: Rotiert DEK, `file_id` und Nonces für alle autorisierten Keys.
- **Keine Secrets auf der Kommandozeile**:
  - Keine Passphrasen, Klartexte oder Private Keys als CLI-Parameter.
  - Unterstützt Streaming über `stdin` / `stdout` (`-i - -o -`).
  - Entschlüsselte Ausgabedateien werden atomar über temporäre Dateien im Zielverzeichnis mit strikten Dateirechten **`0600`** geschrieben.
- **Integrität & Manipulationsschutz**:
  - **Header MAC** (`HMAC-SHA256` mit separatem, per HKDF abgeleitetem Schlüssel) schützt alle Header-Metadaten und Key Slots.
  - **Chunked AES-256-GCM** mit strikt eindeutigen Nonces (`nonce_prefix || chunk_index`) und `is_final`-Flag im AAD erkennt Bitflips, Umordnung, Abschneiden (Truncation) und angehängte Daten.
  - **Determinismus-Prüfung**: Da `ssh-agent` nur signieren (nicht direkt entschlüsseln) kann, wird der Key Encryption Key (KEK) per `HKDF-SHA256` aus einer deterministischen Signatur über eine zufällige Challenge abgeleitet. Beim Hinzufügen eines Keys wird zweimal signiert und bytegenau verglichen – nicht-deterministische Schlüsseltypen (z. B. `ecdsa-sha2-*` oder FIDO2 `sk-*`) werden sofort sicher abgewiesen. Unterstützt werden **`ssh-ed25519`** und **`ssh-rsa`** (`rsa-sha2-512`).

## Voraussetzungen

- Linux / WSL2 mit Python 3.10+
- Python-Paket `cryptography`
- Laufender `ssh-agent` mit gesetzter Variable `SSH_AGENT_SOCK` (oder `SSH_AUTH_SOCK`)

## Installation (`/usr/local/bin` + Alias `ssc`)

```bash
# Optional vorab prüfen (Dry-Run ohne Änderungen)
./ssh-agent-crypt install --dry-run

# In /usr/local/bin per sudo verlinken und Alias 'ssc' in ~/.bashrc eintragen
./ssh-agent-crypt install
source ~/.bashrc

# Danach überall als `ssh-agent-crypt` oder kurz als `ssc` nutzbar
ssc --version
```

Weitere Optionen für `install`:
- `--bin-dir PATH` (Standard: `/usr/local/bin`)
- `--bashrc PATH` (Standard: `~/.bashrc`)
- `--alias NAME` (Standard: `ssc`) oder `--no-alias`
- `--no-sudo` (z. B. für `~/.local/bin`)
- `--dry-run` (zeigt geplante Aktionen ohne Änderungen)

## Verwendung

### 1. Geladene Keys im SSH-Agent anzeigen

```bash
export SSH_AGENT_SOCK="${SSH_AUTH_SOCK}"
./ssh-agent-crypt agent-keys
```

### 2. Datei (oder `stdin`) verschlüsseln

```bash
# Mit einem bestimmten Key (Fingerprint, Präfix, Kommentar oder .pub-Datei)
./ssh-agent-crypt encrypt -i geheim.txt -o geheim.txt.senc --key alice@host

# Direkt für mehrere Keys oder alle unterstützten Keys im Agent
./ssh-agent-crypt encrypt -i geheim.txt -o geheim.txt.senc --key alice --key bob
./ssh-agent-crypt encrypt -i geheim.txt -o geheim.txt.senc --all-keys

# Ohne Klartext auf Platte (über Pipe)
cat geheim.txt | ./ssh-agent-crypt encrypt --all-keys -o geheim.txt.senc
```

### 3. Datei entschlüsseln oder prüfen

```bash
# In Datei entschlüsseln (erzeugt Datei mit Modus 0600)
./ssh-agent-crypt decrypt -i geheim.txt.senc -o geheim.txt

# Auf stdout entschlüsseln
./ssh-agent-crypt decrypt -i geheim.txt.senc -o -

# Integrität (Header MAC + alle GCM-Chunks) prüfen ohne Klartext auszugeben
./ssh-agent-crypt verify geheim.txt.senc

# Autorisierte Key Slots anzeigen
./ssh-agent-crypt info --verify geheim.txt.senc
```

### 4. Keys dynamisch hinzufügen, entfernen und rotieren

```bash
# Weiteren Key aus dem SSH-Agent hinzufügen (bestehende Offline-Keys bleiben erhalten)
./ssh-agent-crypt add-key geheim.txt.senc --key ~/.ssh/id_backup.pub

# Key entfernen (per Slot-ID, Fingerprint, Kommentar oder .pub-Datei)
./ssh-agent-crypt remove-key geheim.txt.senc --key bob@host

# Key entfernen UND DEK rotieren (Payload wird komplett neu verschlüsselt)
./ssh-agent-crypt remove-key geheim.txt.senc --key bob@host --rekey

# DEK unabhängig rotieren
./ssh-agent-crypt rekey geheim.txt.senc
```

## Projektstruktur

```text
.
├── ssh-agent-crypt               # Ausführbares CLI-Skript
├── ssh_agent_crypt/
│   ├── __init__.py
│   ├── agent.py                  # SSH-Agent-Protokoll-Client (SSH_AGENT_SOCK / SSH_AUTH_SOCK)
│   ├── crypto.py                 # Envelope-Encryption, Key Slots, Header MAC, Chunked AES-256-GCM
│   ├── cli.py                    # CLI-Subkommandos, atomares Schreiben, 0600-Rechte
│   └── installer.py              # Installation in /usr/local/bin (per sudo) & Alias in ~/.bashrc
├── scripts/
│   ├── run-tests.sh              # Startet die vollständige Test-Suite
│   └── demo-workflow.sh          # Isolierte End-to-End-Demo mit eigenem ssh-agent
└── tests/
    └── test_ssh_agent_crypt.py   # Unit- & Live-ssh-agent-Integrationstests
```

## Tests & Demo ausführen

Die Tests starten automatisch einen isolierten `ssh-agent` in einem temporären Verzeichnis und verändern weder den aktiven SSH-Agent noch `~/.ssh`:

```bash
./scripts/run-tests.sh
./scripts/demo-workflow.sh
```

## Container-Format (v1)

```text
MAGIC        (10 Bytes) : "SSHACRYPT\x01"
HEADER_LEN   ( 4 Bytes) : uint32 big-endian
HEADER_JSON  ( N Bytes) : Kanonisches UTF-8 JSON (version, cipher, kdf, file_id, nonce_prefix, chunk_size, slots[])
HEADER_MAC   (32 Bytes) : HMAC-SHA256(header_mac_key, MAGIC || HEADER_LEN || HEADER_JSON)
PAYLOAD      (Stream)   : Folge aus uint32(ct_len) || AES-256-GCM(payload_key, nonce, plaintext, aad)
```
