# wa-mini

**Minimal WhatsApp Primary Device Service** (Work in Progress)

A lightweight C service that acts as a WhatsApp primary device, allowing companion
devices (like mautrix-whatsapp) to link to it without a physical phone running.

> **⚠️ Current Status: Not Working**
>
> Authentication with WhatsApp servers fails after the Noise handshake completes.
> The server closes the connection after receiving ClientFinish, likely due to
> missing or incorrect fields in the ClientPayload. This is under investigation.
>
> Additionally, key injection before registration does not work reliably -
> WhatsApp validates and regenerates keys during registration.

## Features (Planned)

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

## Credential Setup

Direct registration from wa-mini is not supported because WhatsApp requires
Android Keystore Attestation. You must register on a real Android device first,
then extract the credentials.

### Extract Credentials from Existing Registration

```sh
./tools/extract_credentials.py --adb --phone +15551234567
```

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

### Key Injection (Experimental - Does Not Work Reliably)

An experimental tool `inject_credentials.py` exists to pre-inject keys before
WhatsApp registration. The theory was that WhatsApp would use the injected
Noise keypair while handling attestation itself.

**This approach does not work reliably** because:
- WhatsApp validates and often regenerates keys during registration
- Even when the Noise keypair is preserved, Signal protocol keys are regenerated
- Registration often fails in a loop after SMS verification with injected keys
- The signed prekey signature generation is complex (XEdDSA) and hard to replicate

The tool remains in `tools/inject_credentials.py` for research purposes only.

### Manual Credential Extraction

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
the legitimate WhatsApp app.

#### Keystore Encryption vs Attestation

There's an important distinction between two uses of Android Keystore:

**1. Keystore Encryption (for local storage)**

WhatsApp stores the Noise keypair encrypted with Android Keystore:
- `client_static_keypair_enc` (format 0): AES-128-GCM with Keystore-managed key
- `client_static_keypair_pwd_enc` (format 2): PBKDF2 + AES-OFB backup

On x86 emulators without hardware TEE, this encryption is software-emulated.
The AES key can be extracted from `/data/misc/keystore/user_0/<uid>_USRPKEY_*`
at offset 0x2e (16 bytes). This is what `extract_credentials.py` does.

**2. Keystore Attestation (for registration)**

When registering, WhatsApp requests an attestation certificate chain:
```
Device → Keymaster HAL → Google Play Services → Google servers
                                    ↓
                          Signed certificate chain
                          Root: Google Hardware Attestation Root CA
```

Even on x86 emulators with software-backed keys, attestation requires:
- Google Play Services installed and running
- Communication with Google's attestation servers
- Google signing the certificate with their private keys

#### Why Open-Source Google Services (microG) Won't Help

Projects like microG can replace most Play Services functionality but **cannot**
generate valid attestation certificates because:

- Attestation certificates must chain to Google's root CA
- Only Google has the private keys to sign these certificates
- No amount of local software emulation can forge this signature

#### What About x86 Emulators?

Registration works on x86 Android emulators because:
1. They have real Google Play Services installed
2. Play Services contacts Google's servers for attestation
3. Google issues "software-backed" attestation (lower security tier)
4. WhatsApp accepts this level of attestation

The emulator is not "emulating" attestation - it's getting real certificates
from Google, just with a software (not hardware) security level.

#### Investigation Findings (x86 Android VM)

Testing on an Android-x86 VM with WhatsApp 2.26.4.71 confirmed:

| Component | Status |
|-----------|--------|
| Google Play Services | Running (v26.04.34) |
| SafetyNet service | Available and functional |
| Keystore encryption | Software-emulated, extractable |
| Keystore attestation | Works via Google's servers |
| WhatsApp registration | Successful (when not injecting keys) |

The VM has full Google services running (`com.google.android.gms`,
`com.google.process.gservices`, etc.) which handle attestation requests.

#### Key Injection Experiments (Failed)

We attempted to inject pre-generated keys into WhatsApp before registration,
hoping WhatsApp would use our keys while handling attestation itself:

**Approach 1: Inject Noise + Signal keys**
- Created `keystore.xml` with encrypted Noise keypair (format 2)
- Created `axolotl.db` with identity key, signed prekey, and prekeys
- Result: WhatsApp used our Noise keypair but regenerated Signal keys
- Registration failed in a loop ("finishing setup" → back to name entry)

**Approach 2: Inject Noise keypair only**
- Only injected `keystore.xml` with Noise keypair
- Let WhatsApp generate its own Signal keys
- Result: WhatsApp regenerated the Noise keypair entirely, ignoring our injection

**Approach 3: Inject with server_static_public**
- Added `server_static_public` to make WhatsApp think registration completed
- Result: Same failure - registration loop

**Conclusion:** WhatsApp validates and regenerates keys during registration.
The exact validation mechanism is unknown, but key injection before registration
does not work reliably. The only working method is extracting credentials from
an already-completed registration.

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
