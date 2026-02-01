# wa-mini

**Minimal WhatsApp Primary Device Service**

A lightweight C service that registers as a WhatsApp primary device, eliminating the need for a physical phone. Generate QR/link codes for companion devices (like mautrix-whatsapp) to link to it.

## Features

- **Primary Device Registration** - Register with WhatsApp using SMS verification
- **Companion Linking** - Generate link codes for WhatsApp Web/Desktop/bridges
- **Multi-Account Support** - Manage multiple phone numbers
- **Daemon with IPC** - Unix socket control for live account management
- **Minimal Footprint** - ~9000 lines of C, no heavy dependencies

## Quick Start

### Build

```sh
# Install dependencies (Debian/Ubuntu)
sudo apt install build-essential libsodium-dev

# Fedora/RHEL
sudo dnf install gcc make libsodium-devel

# Alpine Linux
sudo apk add build-base libsodium-dev

# OpenBSD
doas pkg_add libsodium

# FreeBSD
sudo pkg install libsodium

# macOS
brew install libsodium

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
# Register a new account
wa-mini register +15551234567
wa-mini verify -a +15551234567 123456

# Generate link code for companion device
wa-mini link +15551234567

# Run as daemon
wa-mini daemon
```

## Registration

WhatsApp uses anti-bot protection for new device registration. The registration
API requires an HMAC-SHA1 token computed from:

- **WA_SIGNATURE**: WhatsApp APK signing certificate (fixed, known)
- **WA_MD5_CLASSES**: Base64(MD5(classes.dex)) - changes per version
- **WA_KEY**: 80-byte HMAC key - extracted from native library

Token = Base64(HMAC-SHA1(KEY, SIGNATURE + MD5_CLASSES + phone))

**Current Status**: Fully configured for WhatsApp version 2.26.4.71.
All registration constants (SIGNATURE, MD5_CLASSES, KEY) are in place.

### Updating to a New Version

When WhatsApp releases a new version, both MD5_CLASSES and KEY must be updated:

```sh
# 1. Download the new APK
# 2. Extract and calculate MD5_CLASSES
unzip -p WhatsApp.apk classes.dex | md5sum | cut -d' ' -f1 | xxd -r -p | base64

# 3. Extract KEY from the native library (see below)
# 4. Update src/register.c with:
#    - WA_VERSION
#    - WA_MD5_CLASSES
#    - WA_KEY
# 5. Rebuild
make clean && make
```

### Extracting the HMAC Key for New Versions

The KEY is stored in `libwhatsappmerged.so` inside a SuperPack compressed
archive (`libs.so`). To extract it:

**Option 1: Static Analysis (Ghidra)**
1. Extract APK: `unzip WhatsApp.apk -d apk_extracted/`
2. Extract SuperPack archive from `lib/x86_64/libs.so`
   - Find offsets: `nm libs.so | grep superpack`
   - Extract: `dd if=libs.so of=archive.bin bs=1 skip=<offset> count=<size>`
3. Decompress XZ streams in the archive
4. Search for 80-byte high-entropy sequence near "hmac sha-1" string
5. The key has maximum entropy (all 80 bytes unique)

**Option 2: Frida (requires rooted device/emulator)**
1. Install the specific WhatsApp version on a rooted Android device
2. Use Frida to hook `mbedtls_md_hmac_starts` with key length 80
3. Capture the KEY value during registration

### Alternative: Import Existing Account

If you have an existing WhatsApp account on another device, you may be able to
import the credentials by extracting them from that device.

## CLI Commands

```
wa-mini <command> [options]

Commands:
  register <phone>     Register new phone number (+1234567890)
  verify <code>        Enter SMS verification code
  link [phone]         Display link code for companion pairing
  list                 List all registered accounts
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
│   ├── register/verify    SMS registration (via daemon if running)
│   ├── link               Companion pairing
│   └── daemon             Background service with IPC
│
├── Daemon (multi-process)
│   ├── Parent Process     Control socket, child management
│   │   ├── Handles IPC commands
│   │   ├── Spawns/reaps child processes
│   │   └── Registration/verification
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

- **libsodium** - Cryptography (Curve25519, AES-GCM, SHA-256)

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

### 3. Register Account

```sh
# Request SMS verification code
wa-mini register +15551234567

# Enter the code you receive
wa-mini verify -a +15551234567 123456
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

When the daemon is running, new accounts are started automatically after verification:

```sh
# Register and verify - daemon handles everything
wa-mini register +15559876543
wa-mini verify -a +15559876543 654321
# Account is automatically saved and started by daemon
```

If running as a system service with a different data directory:

```sh
# Register locally, then copy to service
wa-mini register +15559876543
wa-mini verify -a +15559876543 654321
sudo cp -r ~/.wa-mini/* /var/lib/wa-mini/
sudo chown -R _wamini:_wamini /var/lib/wa-mini
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
| `REGISTER` | phone [method] | Request SMS verification code |
| `VERIFY` | phone code | Verify code, save account, start process |
| `LOGOUT` | phone | Stop process and delete account |
| `RELOAD` | - | Rescan database for new accounts |
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
you'll need to re-register your accounts. The new flat file format stores each
account as a separate binary file in `~/.wa-mini/accounts/`.

```sh
# Backup old data
cp -r ~/.wa-mini ~/.wa-mini.bak

# Remove old database
rm ~/.wa-mini/credentials.db*

# Re-register accounts
wa-mini register +15551234567
wa-mini verify -a +15551234567 <code>
```

## License

BSD 2-Clause License

Copyright (c) 2025, Renaud Allard <renaud@allard.it>

## References

- [Noise Protocol](https://noiseprotocol.org/noise.html)
- [libsodium](https://doc.libsodium.org/)
- [Signal Protocol](https://signal.org/docs/)
