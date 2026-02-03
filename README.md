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

**WARNING: As of 2025, WhatsApp registration requires Android Keystore
Attestation. See "Current Limitations" below.**

### Current Limitations (2025)

Research conducted via Frida dynamic instrumentation on WhatsApp 2.26.x revealed
that WhatsApp has fundamentally changed its registration security model.

#### Android Keystore Attestation Required

WhatsApp's `/v2/code` registration endpoint now requires an `Authorization`
header containing an X.509 certificate chain that proves:

1. **Device Authenticity** - Request originates from a genuine Android device
2. **APK Integrity** - WhatsApp APK has the correct signature (`04f8678c`)
3. **Hardware-Backed Key** - A cryptographic challenge was signed by a key
   generated in the Android Keystore (hardware or TEE-backed)

The certificate chain structure:
```
Root:         Android Keystore Software Attestation Root (Google, Inc.)
Intermediate: Android Keystore Software Attestation Intermediate
Leaf:         Android Keystore Key (contains attestation extension)
```

The attestation extension (OID 1.3.6.1.4.1.11129.2.1.17) includes:
- Package name: `com.whatsapp`
- APK signature digest
- Challenge-response proof
- Device security level (software/TEE/strongbox)

#### What This Means

The traditional HMAC-SHA1 token (computed from `KEY + SIGNATURE + MD5_CLASSES +
phone`) is **no longer sufficient** for registration. Even with the correct
token, requests are rejected without valid Android Keystore attestation.

**This attestation cannot be faked from a non-Android client** because:
- The certificate chain is verified against Google's root certificates
- The attestation proves keys were generated on-device
- The challenge-response binds the attestation to the specific request

#### Viable Alternatives

1. **Register on Real Android, Export Credentials**
   - Install WhatsApp on an Android device/emulator
   - Complete registration normally
   - Export the account credentials for use with wa-mini
   - Use wa-mini only for the messaging protocol (post-registration)

2. **Use Companion Device Pairing**
   - Register on a real phone
   - Use wa-mini as a linked companion device
   - Requires keeping the primary phone active

3. **Already-Registered Accounts**
   - If you have existing WhatsApp credentials from before 2025
   - These may continue working for the messaging protocol
   - Re-registration would require Android attestation

### Historical: HMAC Token (Pre-2025)

For reference, WhatsApp previously used anti-bot protection via HMAC tokens:

- **WA_SIGNATURE**: WhatsApp APK signing certificate (fixed, known)
- **WA_MD5_CLASSES**: Base64(MD5(classes.dex)) - changes per version
- **WA_KEY**: 80-byte HMAC key - extracted from native library

```
Token = Base64(HMAC-SHA1(KEY, SIGNATURE + MD5_CLASSES + phone))
```

The code in `src/register.c` still implements this token generation, but it
alone is no longer accepted by WhatsApp's servers.

### Research Methodology

The attestation requirement was discovered through:

1. **Frida SSL Interception** - Hooking `SSL_write` in `libssl.so` to capture
   HTTP request bodies before encryption
2. **Traffic Analysis** - Examining `/v2/code` POST requests
3. **Certificate Decoding** - Parsing the Authorization header to identify
   Android Keystore attestation certificates

Captured request structure:
```
POST /v2/code HTTP/1.1
Authorization: MIICiz... [Base64 X.509 certificate chain]
Content-Type: application/x-www-form-urlencoded
Content-Length: 5550

[body with phone, method, token, and other parameters]
```

### Troubleshooting Registration

| Error | Cause | Solution |
|-------|-------|----------|
| `bad_token` | Missing/invalid attestation | Cannot be fixed without Android device |
| `bad_param` | Malformed request | Check URL encoding of parameters |
| `old_version` | WhatsApp version outdated | Update WA_VERSION in register.c |
| `blocked` | Too many attempts | Wait and try again later |

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
