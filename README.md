# wa-mini

**Minimal WhatsApp Primary Device Service**

A lightweight C service that acts as a WhatsApp primary device, allowing companion
devices (like mautrix-whatsapp) to link to it without a physical phone running.

## Features

- **Primary Device Mode** - Import credentials from Android to run as primary device
- **Companion Linking** - Generate link codes for WhatsApp Web/Desktop/bridges
- **Multi-Account Support** - Manage multiple phone numbers
- **Daemon with IPC** - Unix socket control for live account management
- **Minimal Footprint** - ~9000 lines of C, no heavy dependencies

**Note:** Direct registration is not supported due to WhatsApp's Android Keystore
Attestation requirement. You must register on a real Android device first, then
extract the credentials.

## Quick Start

### Build

```sh
# Install dependencies (Debian/Ubuntu)
sudo apt install build-essential libsodium-dev libssl-dev

# Fedora/RHEL
sudo dnf install gcc make libsodium-devel openssl-devel

# Alpine Linux
sudo apk add build-base libsodium-dev openssl-dev

# OpenBSD
doas pkg_add libsodium

# FreeBSD
sudo pkg install libsodium openssl

# macOS
brew install libsodium openssl

# Compile
make

# Debug build (with symbols, no optimization)
make debug

# Install to /usr/local/bin (includes man page)
sudo make install

# View man page
man wa-mini
```

### Usage

```sh
# Import credentials (see "Credential Extraction" section below)
./tools/extract_credentials.py --adb --phone +15551234567

# Generate link code for companion device
wa-mini link +15551234567

# Run as daemon
wa-mini daemon
```

## Credential Extraction

Direct registration is not supported because WhatsApp requires Android Keystore
Attestation since 2025. Instead, you must:

1. Register on a rooted Android device (physical or emulator)
2. Extract the credentials from the device
3. Import them into wa-mini

### Prerequisites

- **Rooted Android device or emulator** (Android-x86 VM works)
- ADB access to the device
- Python 3 with `cryptography` module
- WhatsApp installed and registered on the device

**Important:** Root access is mandatory. WhatsApp stores its credentials in
`/data/data/com.whatsapp/` which is only accessible with root privileges.
Without root, extraction is impossible - there is no workaround. If you don't
have a rooted device, you can use an Android-x86 emulator (e.g., in a VM) which
typically has root access by default.

### Step 1: Register on Android

Install WhatsApp on your rooted Android device and complete the normal
registration process (SMS verification).

### Step 2: Extract Credentials

Use the provided extraction tool:

```sh
# Pull credentials from connected Android device
./tools/extract_credentials.py --adb --phone +15551234567

# Or extract from already-pulled database files
./tools/extract_credentials.py --axolotl /path/to/axolotl.db \
                               --keystore /path/to/keystore.xml \
                               --phone +15551234567
```

The tool extracts from:
- `/data/data/com.whatsapp/databases/axolotl.db` - Signal protocol keys
- `/data/data/com.whatsapp/shared_prefs/keystore.xml` - Noise protocol keys

### Step 3: Manual Extraction (if tool fails)

If the extraction tool doesn't work, extract manually:

```sh
# Connect to device
adb connect <device_ip>:5555

# Pull databases (requires root)
adb shell "su -c 'cp /data/data/com.whatsapp/databases/axolotl.db /sdcard/'"
adb shell "su -c 'cp /data/data/com.whatsapp/shared_prefs/keystore.xml /sdcard/'"
adb pull /sdcard/axolotl.db
adb pull /sdcard/keystore.xml

# Dump database to see structure
./tools/extract_credentials.py --dump axolotl.db
```

### Credential Storage Format

WhatsApp stores credentials in SQLite (`axolotl.db`):

| Table | Contents |
|-------|----------|
| `identities` | Identity key pair (private + public), registration ID |
| `signed_prekeys` | Signed prekey (protobuf record with private key, signature) |
| `prekeys` | One-time prekeys pool |

The `keystore.xml` file contains:
- `client_static_keypair_pwd_enc` - Password-encrypted Noise keypair (format 2)
- `client_static_keypair_enc` - Android Keystore encrypted Noise keypair (format 0)
- `server_static_public` - WhatsApp server's Noise public key (plaintext)

**Noise Key Encryption:** WhatsApp stores the Noise keypair in two formats:
- **Format 0** (`client_static_keypair_enc`): Encrypted with Android Keystore -
  cannot be decrypted without the device's hardware-backed keys.
- **Format 2** (`client_static_keypair_pwd_enc`): Password-based encryption using
  PBKDF2-SHA1 and AES-OFB. The extraction tool can decrypt this format using a
  reverse-engineered identifier from WhatsApp's code.

The extraction tool automatically attempts to decrypt the password-encrypted
keypair. Using the original Noise keys is important for successful authentication
with WhatsApp servers.

### wa-mini Account File Format

Credentials are stored in `~/.wa-mini/accounts/<phone>.acc` (312 bytes):

| Offset | Size | Field |
|--------|------|-------|
| 0-3 | 4 | Magic "WAMN" |
| 4 | 1 | Format version (1) |
| 5 | 1 | Active flag |
| 8-27 | 20 | Phone number |
| 28-59 | 32 | Identity private key |
| 60-91 | 32 | Identity public key |
| 92-123 | 32 | Signed prekey private |
| 124-187 | 64 | Signed prekey signature |
| 188-191 | 4 | Signed prekey ID |
| 192-195 | 4 | Registration ID |
| 196-227 | 32 | Noise static private |
| 228-259 | 32 | Noise static public |
| 260-291 | 32 | Server static public |
| 292-299 | 8 | Timestamp |
| 308-311 | 4 | CRC32 checksum |

### Why Registration Doesn't Work

WhatsApp's `/v2/code` endpoint requires Android Keystore Attestation - an X.509
certificate chain proving the request comes from a genuine Android device with
the legitimate WhatsApp app. This attestation cannot be faked from non-Android
clients because:

- Certificate chain is verified against Google's root certificates
- Attestation proves keys were generated in hardware/TEE
- Challenge-response binds attestation to the specific request

See the research notes in `docs/attestation.md` for full technical details.

## CLI Commands

```
wa-mini <command> [options]

Commands:
  link [phone]         Display link code for companion pairing
  list                 List all imported accounts
  status [phone]       Show connection status
  daemon [--stop]      Run all accounts as background service
  logout <phone>       Unregister from server and remove account
  version              Show WhatsApp version

Options:
  -d, --data <path>    Data directory (default: ~/.wa-mini)
  -a, --account <phone> Select account
  -s, --stop           Stop the running daemon
  -v, --verbose        Verbose logging
  -h, --help           Show help
```

## Architecture

```
wa-mini
├── CLI Interface
│   ├── link               Companion pairing
│   └── daemon             Background service with IPC
│
├── Daemon (multi-process)
│   ├── Parent Process     Control socket, child management
│   │   ├── Handles IPC commands
│   │   └── Spawns/reaps child processes
│   │
│   └── Child Processes    One per account
│       ├── WhatsApp connection
│       └── Message handling
│
├── Control Socket (IPC)
│   ├── ~/.wa-mini/control.sock
│   ├── Line-based protocol (COMMAND [ARGS]\n)
│   └── JSON responses (OK/ERR {...}\n)
│
├── Protocol Stack
│   ├── TCP Socket         g.whatsapp.net:443
│   ├── Noise Protocol     XX handshake, AES-GCM
│   ├── Binary XMPP        Dictionary compression
│   └── Signal Protocol    E2E encryption keys
│
└── Storage
    └── ~/.wa-mini/
        ├── config              (key=value text file)
        ├── accounts/
        │   ├── +15551234567.acc       (binary account data)
        │   ├── +15551234567.prekeys   (binary prekey pool)
        │   └── +15551234567.companions (binary companion list)
        ├── control.sock   (daemon running)
        └── daemon.pid     (daemon running)
```

## Dependencies

- **libsodium** - Cryptography (Curve25519, SHA-256, HMAC)
- **OpenSSL** - AES-256-GCM (software implementation for ARM/non-AES-NI systems)

## Setup Guide

### 1. Build and Install

```sh
make
sudo make install install-service
```

### 2. Create Service User

```sh
# Linux
sudo useradd -r -s /sbin/nologin -d /var/lib/wa-mini _wamini
sudo mkdir -p /var/lib/wa-mini
sudo chown _wamini:_wamini /var/lib/wa-mini

# OpenBSD
doas useradd -s /sbin/nologin -d /var/lib/wa-mini _wamini
doas mkdir -p /var/lib/wa-mini
doas chown _wamini:_wamini /var/lib/wa-mini
```

### 3. Import Account

```sh
# Extract credentials from rooted Android (see "Credential Extraction" above)
./tools/extract_credentials.py --adb --phone +15551234567

# The tool creates ~/.wa-mini/accounts/+15551234567.acc
```

### 4. Copy Credentials to Service Directory

```sh
# Linux
sudo cp -r ~/.wa-mini/* /var/lib/wa-mini/
sudo chown -R _wamini:_wamini /var/lib/wa-mini

# OpenBSD
doas cp -r ~/.wa-mini/* /var/lib/wa-mini/
doas chown -R _wamini:_wamini /var/lib/wa-mini
```

### 5. Start Service

```sh
# Linux
sudo systemctl daemon-reload
sudo systemctl enable wa-mini
sudo systemctl start wa-mini

# OpenBSD
doas rcctl enable wa_mini
doas rcctl start wa_mini
```

### 6. Link Companion Device

```sh
# Generate link code for mautrix-whatsapp or other bridges
wa-mini link +15551234567
```

### Adding More Accounts

Extract credentials from your Android device and notify the daemon:

```sh
# Extract credentials (creates ~/.wa-mini/accounts/+15559876543.acc)
./tools/extract_credentials.py --adb --phone +15559876543

# Tell daemon to load the new account
echo "RELOAD" | nc -U ~/.wa-mini/control.sock
```

If running as a system service with a different data directory:

```sh
# Extract locally, then copy to service
./tools/extract_credentials.py --adb --phone +15559876543
sudo cp ~/.wa-mini/accounts/+15559876543.acc /var/lib/wa-mini/accounts/
sudo chown _wamini:_wamini /var/lib/wa-mini/accounts/+15559876543.acc
echo "RELOAD" | nc -U /var/lib/wa-mini/control.sock
```

## Daemon IPC

The daemon provides a Unix socket interface for live management without restarts.

### Control Socket

- **Path**: `~/.wa-mini/control.sock` (or `<data_dir>/control.sock`)
- **Permissions**: `0600` (owner only)
- **Protocol**: Line-based text commands, JSON responses

### Commands

| Command | Args | Description |
|---------|------|-------------|
| `PING` | - | Health check |
| `LIST` | - | List running accounts with status |
| `STATUS` | phone | Get account connection status |
| `LOGOUT` | phone | Stop process and delete account |
| `RELOAD` | - | Rescan accounts directory for new accounts |
| `STOP` | - | Graceful daemon shutdown |

### Response Format

```
OK {"key":"value"}\n
ERR {"code":"ERROR_CODE","message":"..."}\n
```

### CLI Integration

When the daemon is running, CLI commands automatically use IPC:

```sh
# Check if daemon is running and get live status
wa-mini list
wa-mini status +15551234567

# Stop the daemon gracefully
wa-mini daemon --stop
```

### Manual IPC (for scripting)

```sh
# Send command to daemon
echo "PING" | nc -U ~/.wa-mini/control.sock

# List running accounts
echo "LIST" | nc -U ~/.wa-mini/control.sock

# Stop specific account
echo "LOGOUT +15551234567" | nc -U ~/.wa-mini/control.sock
```

## Protocol Details

### Noise Handshake

- Pattern: `Noise_XX_25519_AESGCM_SHA256`
- Flow: `-> e, <- e, ee, s, es, -> s, se`

### Binary XMPP

WhatsApp uses dictionary-compressed binary XMPP:
- 300+ primary tokens (single byte)
- 600+ secondary tokens (two bytes)
- Packed nibble encoding for numbers

### Frame Format

```
[3-byte length] [encrypted payload] [16-byte GCM tag]
```

## Security

- All crypto via libsodium
- Keys stored with 0600 permissions
- Control socket with 0600 permissions (owner only)
- Daemon runs as dedicated user
- Systemd security hardening enabled
- Continuous fuzz testing via CI

## Fuzzing

The project includes fuzz testing targets for security-critical parsers.

### Build Fuzz Targets

Requires clang with libFuzzer support:

```sh
# Install dependencies (Debian/Ubuntu)
sudo apt install clang llvm

# Build all fuzz targets
make fuzz

# Create seed corpus
make fuzz-seed
```

### Run Fuzzers

```sh
# Run XMPP decoder fuzzer
./fuzz_xmpp fuzz/corpus/xmpp -dict=fuzz/dictionaries/xmpp.dict

# Run protobuf decoder fuzzer
./fuzz_proto fuzz/corpus/proto -dict=fuzz/dictionaries/proto.dict

# Run Noise protocol fuzzer
./fuzz_noise fuzz/corpus/noise -dict=fuzz/dictionaries/noise.dict
```

### Fuzz Targets

| Target | Description |
|--------|-------------|
| `fuzz_xmpp` | Binary XMPP decoder (untrusted server data) |
| `fuzz_proto` | Protobuf handshake message decoder |
| `fuzz_noise` | Noise protocol message reading |

### CI Fuzzing

Fuzz tests run automatically via GitHub Actions:
- On every push to main
- On pull requests
- Daily scheduled runs (10 minutes each target)

Crashes are uploaded as artifacts for investigation.

## Migration from SQLite

If you're upgrading from a version that used SQLite storage (`credentials.db`),
you'll need to re-import your accounts. The new flat file format stores each
account as a separate binary file in `~/.wa-mini/accounts/`.

```sh
# Backup old data
cp -r ~/.wa-mini ~/.wa-mini.bak

# Remove old database
rm ~/.wa-mini/credentials.db*

# Re-import accounts from Android
./tools/extract_credentials.py --adb --phone +15551234567
```

## License

BSD 2-Clause License

Copyright (c) 2025, Renaud Allard <renaud@allard.it>

## References

- [Noise Protocol](https://noiseprotocol.org/noise.html)
- [libsodium](https://doc.libsodium.org/)
- [Signal Protocol](https://signal.org/docs/)
