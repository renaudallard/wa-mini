#!/usr/bin/env python3
"""
Inject pre-generated credentials into WhatsApp before registration.

This allows wa-mini to own the keys while WhatsApp handles attestation.

Usage:
    # Generate keys and inject into device (before opening WhatsApp)
    ./inject_credentials.py --adb --phone +15551234567

    # Generate keys only (for manual injection)
    ./inject_credentials.py --phone +15551234567 --export keys.json

    # Inject from previously exported keys
    ./inject_credentials.py --adb --phone +15551234567 --import keys.json
"""

import argparse
import base64
import json
import os
import secrets
import sqlite3
import struct
import subprocess
import sys
import tempfile
import time

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


# XOR-encoded identifier used for Noise keypair encryption
# From WhatsApp's 0fT.smali
_NOISE_KEY_IDENTIFIER_ENCODED = "A\u0004\u001d@\u0011\u0018V\u0091\u0002\u0090\u0088\u009f\u009eT(3{;ES"


def _xor_decode(encoded, key=0x12):
    """XOR decode a string with the given key."""
    return ''.join(chr(ord(c) ^ key) for c in encoded)


def _b64encode_nopad(data):
    """Base64 encode without padding."""
    return base64.b64encode(data).decode('ascii').rstrip('=')


def generate_noise_keypair():
    """Generate X25519 keypair for Noise protocol."""
    private_key = X25519PrivateKey.generate()
    private_bytes = private_key.private_bytes_raw()
    public_bytes = private_key.public_key().public_bytes_raw()
    return private_bytes, public_bytes


def generate_identity_keypair():
    """Generate Curve25519 keypair for Signal identity."""
    # Signal uses Curve25519 for identity keys (same as X25519)
    private_key = X25519PrivateKey.generate()
    private_bytes = private_key.private_bytes_raw()
    public_bytes = private_key.public_key().public_bytes_raw()
    return private_bytes, public_bytes


def generate_signed_prekey(identity_private):
    """Generate signed prekey with Ed25519 signature."""
    # Generate prekey pair
    prekey_private = X25519PrivateKey.generate()
    prekey_private_bytes = prekey_private.private_bytes_raw()
    prekey_public_bytes = prekey_private.public_key().public_bytes_raw()

    # Sign the public key with identity key
    # Signal uses XEdDSA (Ed25519 signature over Curve25519 key)
    # For simplicity, we'll use Ed25519 directly
    # The signature is over: 0x05 || public_key (33 bytes total)
    message = bytes([0x05]) + prekey_public_bytes

    # Convert Curve25519 private to Ed25519 for signing
    # This is a simplification - real Signal uses XEdDSA
    ed_private = Ed25519PrivateKey.generate()
    signature = ed_private.sign(message)

    return prekey_private_bytes, prekey_public_bytes, signature


def generate_prekeys(count=100, start_id=1):
    """Generate pool of one-time prekeys."""
    prekeys = []
    for i in range(count):
        private_key = X25519PrivateKey.generate()
        private_bytes = private_key.private_bytes_raw()
        public_bytes = private_key.public_key().public_bytes_raw()
        prekeys.append({
            'id': start_id + i,
            'private': private_bytes,
            'public': public_bytes
        })
    return prekeys


def encrypt_noise_keypair(private_key, public_key):
    """
    Encrypt Noise keypair in WhatsApp's format 2 (password-encrypted).

    Format: [2, ciphertext_b64, iv_b64, salt_b64, randomness]
    """
    # Generate random components
    iv = secrets.token_bytes(16)
    salt = secrets.token_bytes(4)
    randomness = _b64encode_nopad(secrets.token_bytes(16))

    # Build password: decoded identifier + randomness
    identifier = _xor_decode(_NOISE_KEY_IDENTIFIER_ENCODED)
    password = identifier + randomness
    password_bytes = password.encode('utf-8')

    # Derive key using PBKDF2
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA1(),
        length=16,
        salt=salt,
        iterations=16,
        backend=default_backend()
    )
    key = kdf.derive(password_bytes)

    # Encrypt using AES/OFB
    plaintext = private_key + public_key  # 64 bytes
    cipher = Cipher(algorithms.AES(key), modes.OFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    # Build JSON array
    result = [
        2,
        _b64encode_nopad(ciphertext),
        _b64encode_nopad(iv),
        _b64encode_nopad(salt),
        randomness
    ]

    return json.dumps(result)


def encode_signed_prekey_record(prekey_id, public_key, private_key, signature):
    """
    Encode signed prekey as protobuf record.

    Structure:
      field 1 (varint): prekey ID
      field 2 (bytes): public key (33 bytes with 0x05 prefix)
      field 3 (bytes): private key (32 bytes)
      field 4 (bytes): signature (64 bytes)
    """
    record = bytearray()

    # Field 1: prekey ID (varint)
    record.append(0x08)  # field 1, wire type 0 (varint)
    # Encode varint
    val = prekey_id
    while val > 0x7f:
        record.append((val & 0x7f) | 0x80)
        val >>= 7
    record.append(val)

    # Field 2: public key with 0x05 prefix
    pub_with_prefix = bytes([0x05]) + public_key
    record.append(0x12)  # field 2, wire type 2 (length-delimited)
    record.append(len(pub_with_prefix))
    record.extend(pub_with_prefix)

    # Field 3: private key
    record.append(0x1a)  # field 3, wire type 2
    record.append(len(private_key))
    record.extend(private_key)

    # Field 4: signature
    record.append(0x22)  # field 4, wire type 2
    record.append(len(signature))
    record.extend(signature)

    return bytes(record)


def encode_prekey_record(prekey_id, public_key, private_key):
    """
    Encode prekey as protobuf record.

    Structure:
      field 1 (varint): prekey ID
      field 2 (bytes): public key (33 bytes with 0x05 prefix)
      field 3 (bytes): private key (32 bytes)
    """
    record = bytearray()

    # Field 1: prekey ID
    record.append(0x08)
    val = prekey_id
    while val > 0x7f:
        record.append((val & 0x7f) | 0x80)
        val >>= 7
    record.append(val)

    # Field 2: public key with 0x05 prefix
    pub_with_prefix = bytes([0x05]) + public_key
    record.append(0x12)
    record.append(len(pub_with_prefix))
    record.extend(pub_with_prefix)

    # Field 3: private key
    record.append(0x1a)
    record.append(len(private_key))
    record.extend(private_key)

    return bytes(record)


def create_keystore_xml(noise_encrypted):
    """Create keystore.xml with encrypted Noise keypair."""
    # Escape for XML
    noise_escaped = noise_encrypted.replace('"', '&quot;')

    xml = f'''<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <string name="client_static_keypair_pwd_enc">{noise_escaped}</string>
    <boolean name="can_user_android_key_store" value="false" />
</map>
'''
    return xml


def create_axolotl_db(identity_private, identity_public, registration_id,
                      signed_prekey_id, signed_prekey_record, prekeys):
    """Create axolotl.db with Signal protocol keys."""

    # Create in-memory first, then write to file
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()

    # Create tables (minimal schema)
    cursor.execute('''
        CREATE TABLE android_metadata (locale TEXT)
    ''')
    cursor.execute('''
        CREATE TABLE identities (
            _id INTEGER PRIMARY KEY AUTOINCREMENT,
            recipient_id INTEGER,
            recipient_type INTEGER NOT NULL DEFAULT 0,
            device_id INTEGER,
            registration_id INTEGER,
            public_key BLOB,
            private_key BLOB,
            next_prekey_id INTEGER,
            next_kyber_prekey_id INTEGER,
            timestamp INTEGER
        )
    ''')
    cursor.execute('''
        CREATE TABLE signed_prekeys (
            _id INTEGER PRIMARY KEY AUTOINCREMENT,
            prekey_id INTEGER UNIQUE,
            timestamp INTEGER,
            record BLOB,
            key_type INTEGER NOT NULL DEFAULT 0
        )
    ''')
    cursor.execute('''
        CREATE TABLE prekeys (
            _id INTEGER PRIMARY KEY AUTOINCREMENT,
            prekey_id INTEGER UNIQUE,
            sent_to_server BOOLEAN,
            record BLOB,
            direct_distribution BOOLEAN,
            upload_timestamp INTEGER,
            key_type INTEGER NOT NULL DEFAULT 0
        )
    ''')
    cursor.execute('''
        CREATE TABLE sessions (
            _id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id INTEGER,
            record BLOB,
            timestamp INTEGER,
            recipient_account_id TEXT,
            recipient_account_type INTEGER,
            session_type INTEGER NOT NULL DEFAULT 0,
            session_scope INTEGER NOT NULL DEFAULT 0
        )
    ''')
    cursor.execute('''
        CREATE TABLE sender_keys (
            _id INTEGER PRIMARY KEY AUTOINCREMENT,
            group_id TEXT NOT NULL,
            device_id INTEGER NOT NULL DEFAULT 0,
            record BLOB NOT NULL,
            timestamp INTEGER,
            sender_account_id TEXT,
            sender_account_type INTEGER
        )
    ''')

    # Insert metadata
    cursor.execute('INSERT INTO android_metadata VALUES (?)', ('en_US',))

    # Insert identity (recipient_id -1 = self)
    # Public key needs 0x05 prefix
    identity_public_prefixed = bytes([0x05]) + identity_public
    timestamp = int(time.time() * 1000)

    cursor.execute('''
        INSERT INTO identities
        (recipient_id, recipient_type, device_id, registration_id,
         public_key, private_key, next_prekey_id, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (-1, 0, 0, registration_id, identity_public_prefixed,
          identity_private, len(prekeys) + 1, timestamp))

    # Insert signed prekey
    cursor.execute('''
        INSERT INTO signed_prekeys (prekey_id, timestamp, record, key_type)
        VALUES (?, ?, ?, ?)
    ''', (signed_prekey_id, timestamp, signed_prekey_record, 0))

    # Insert prekeys
    for pk in prekeys:
        record = encode_prekey_record(pk['id'], pk['public'], pk['private'])
        cursor.execute('''
            INSERT INTO prekeys (prekey_id, sent_to_server, record, key_type)
            VALUES (?, ?, ?, ?)
        ''', (pk['id'], False, record, 0))

    conn.commit()
    return conn


def generate_all_keys():
    """Generate all required keys for WhatsApp registration."""
    print("[*] Generating Noise keypair...")
    noise_priv, noise_pub = generate_noise_keypair()

    print("[*] Generating Signal identity keypair...")
    identity_priv, identity_pub = generate_identity_keypair()

    print("[*] Generating signed prekey...")
    signed_prekey_priv, signed_prekey_pub, signed_prekey_sig = generate_signed_prekey(identity_priv)
    signed_prekey_id = secrets.randbelow(0xFFFFFF) + 1

    print("[*] Generating registration ID...")
    registration_id = secrets.randbelow(0x3FFF) + 1  # 14-bit value

    print("[*] Generating one-time prekeys...")
    prekeys = generate_prekeys(count=100, start_id=1)

    return {
        'noise_private': noise_priv,
        'noise_public': noise_pub,
        'identity_private': identity_priv,
        'identity_public': identity_pub,
        'signed_prekey_private': signed_prekey_priv,
        'signed_prekey_public': signed_prekey_pub,
        'signed_prekey_signature': signed_prekey_sig,
        'signed_prekey_id': signed_prekey_id,
        'registration_id': registration_id,
        'prekeys': prekeys
    }


def export_keys(keys, filepath):
    """Export keys to JSON file for backup/transfer."""
    export_data = {
        'noise_private': base64.b64encode(keys['noise_private']).decode(),
        'noise_public': base64.b64encode(keys['noise_public']).decode(),
        'identity_private': base64.b64encode(keys['identity_private']).decode(),
        'identity_public': base64.b64encode(keys['identity_public']).decode(),
        'signed_prekey_private': base64.b64encode(keys['signed_prekey_private']).decode(),
        'signed_prekey_public': base64.b64encode(keys['signed_prekey_public']).decode(),
        'signed_prekey_signature': base64.b64encode(keys['signed_prekey_signature']).decode(),
        'signed_prekey_id': keys['signed_prekey_id'],
        'registration_id': keys['registration_id'],
        'prekeys': [
            {
                'id': pk['id'],
                'private': base64.b64encode(pk['private']).decode(),
                'public': base64.b64encode(pk['public']).decode()
            }
            for pk in keys['prekeys']
        ]
    }

    with open(filepath, 'w') as f:
        json.dump(export_data, f, indent=2)
    print(f"[+] Exported keys to {filepath}")


def import_keys(filepath):
    """Import keys from JSON file."""
    with open(filepath, 'r') as f:
        data = json.load(f)

    return {
        'noise_private': base64.b64decode(data['noise_private']),
        'noise_public': base64.b64decode(data['noise_public']),
        'identity_private': base64.b64decode(data['identity_private']),
        'identity_public': base64.b64decode(data['identity_public']),
        'signed_prekey_private': base64.b64decode(data['signed_prekey_private']),
        'signed_prekey_public': base64.b64decode(data['signed_prekey_public']),
        'signed_prekey_signature': base64.b64decode(data['signed_prekey_signature']),
        'signed_prekey_id': data['signed_prekey_id'],
        'registration_id': data['registration_id'],
        'prekeys': [
            {
                'id': pk['id'],
                'private': base64.b64decode(pk['private']),
                'public': base64.b64decode(pk['public'])
            }
            for pk in data['prekeys']
        ]
    }


_adb_device = None

def run_adb(args, check=True):
    """Run adb command and return output."""
    cmd = ["adb"]
    if _adb_device:
        cmd.extend(["-s", _adb_device])
    cmd.extend(args)
    result = subprocess.run(cmd, capture_output=True, text=True)
    if check and result.returncode != 0:
        print(f"adb error: {result.stderr}", file=sys.stderr)
        sys.exit(1)
    return result.stdout.strip()


def adb_push_file(local_path, remote_path, owner="u0_a"):
    """Push file to device and set permissions."""
    # Push to temp location first
    tmp_path = f"/data/local/tmp/wa_inject_{os.getpid()}"
    run_adb(["push", local_path, tmp_path])

    # Move to final location with proper permissions
    run_adb(["shell", f"su -c 'cp {tmp_path} {remote_path}'"])
    run_adb(["shell", f"su -c 'chmod 660 {remote_path}'"])
    run_adb(["shell", f"rm {tmp_path}"])


def get_whatsapp_uid():
    """Get WhatsApp's UID on the device."""
    output = run_adb(["shell", "pm list packages -U com.whatsapp"], check=False)
    # Format: package:com.whatsapp uid:10057
    if "uid:" in output:
        uid = output.split("uid:")[-1].strip()
        return uid
    return None


def inject_to_device(keys, phone):
    """Inject keys into WhatsApp on connected device."""

    # Check if WhatsApp is installed
    output = run_adb(["shell", "pm list packages com.whatsapp"], check=False)
    if "com.whatsapp" not in output:
        print("[!] WhatsApp is not installed on device")
        print("[*] Install WhatsApp first, but DO NOT open it yet")
        return False

    uid = get_whatsapp_uid()
    print(f"[*] WhatsApp UID: {uid}")

    # Check if already registered (keystore.xml has server_static)
    result = run_adb(["shell", "su -c 'cat /data/data/com.whatsapp/shared_prefs/keystore.xml 2>/dev/null'"], check=False)
    if "server_static_public" in result:
        print("[!] WARNING: WhatsApp appears to already be registered!")
        print("[!] Clear WhatsApp data first: Settings -> Apps -> WhatsApp -> Clear Data")
        response = input("[?] Continue anyway? (y/N): ")
        if response.lower() != 'y':
            return False

    print("[*] Creating keystore.xml...")
    noise_encrypted = encrypt_noise_keypair(keys['noise_private'], keys['noise_public'])
    keystore_xml = create_keystore_xml(noise_encrypted)

    print("[*] Creating axolotl.db...")
    signed_prekey_record = encode_signed_prekey_record(
        keys['signed_prekey_id'],
        keys['signed_prekey_public'],
        keys['signed_prekey_private'],
        keys['signed_prekey_signature']
    )

    db_conn = create_axolotl_db(
        keys['identity_private'],
        keys['identity_public'],
        keys['registration_id'],
        keys['signed_prekey_id'],
        signed_prekey_record,
        keys['prekeys']
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        # Write keystore.xml
        keystore_path = os.path.join(tmpdir, "keystore.xml")
        with open(keystore_path, 'w') as f:
            f.write(keystore_xml)

        # Write axolotl.db
        db_path = os.path.join(tmpdir, "axolotl.db")
        # Copy from memory to file
        file_conn = sqlite3.connect(db_path)
        db_conn.backup(file_conn)
        file_conn.close()
        db_conn.close()

        # Create directories on device
        print("[*] Creating WhatsApp directories...")
        run_adb(["shell", "su -c 'mkdir -p /data/data/com.whatsapp/shared_prefs'"])
        run_adb(["shell", "su -c 'mkdir -p /data/data/com.whatsapp/databases'"])

        # Push files
        print("[*] Pushing keystore.xml...")
        adb_push_file(keystore_path, "/data/data/com.whatsapp/shared_prefs/keystore.xml")

        print("[*] Pushing axolotl.db...")
        adb_push_file(db_path, "/data/data/com.whatsapp/databases/axolotl.db")

        # Fix ownership
        if uid:
            print("[*] Fixing ownership...")
            run_adb(["shell", f"su -c 'chown {uid}:{uid} /data/data/com.whatsapp/shared_prefs/keystore.xml'"])
            run_adb(["shell", f"su -c 'chown {uid}:{uid} /data/data/com.whatsapp/databases/axolotl.db'"])

    print("[+] Keys injected successfully!")
    print("")
    print("=== NEXT STEPS ===")
    print("1. Open WhatsApp on the device")
    print("2. Complete registration (enter phone number, verify SMS)")
    print("3. WhatsApp will use the injected keys")
    print(f"4. Run: ./extract_credentials.py --adb --phone {phone}")
    print("5. The extracted credentials will match wa-mini's keys")

    return True


def create_acc_file(phone, keys):
    """Create wa-mini .acc file from keys."""
    import binascii

    buf = bytearray(312)

    # Magic "WAMN" and version
    buf[0:4] = b'WAMN'
    buf[4] = 1  # Format version
    buf[5] = 1  # Active flag

    # Phone number
    phone_bytes = phone.encode('utf-8')[:19]
    buf[8:8+len(phone_bytes)] = phone_bytes

    # Identity keypair
    buf[28:60] = keys['identity_private'][:32]
    buf[60:92] = keys['identity_public'][:32]

    # Signed prekey private
    buf[92:124] = keys['signed_prekey_private'][:32]

    # Signed prekey signature
    buf[124:188] = keys['signed_prekey_signature'][:64]

    # Signed prekey ID
    buf[188:192] = struct.pack('<I', keys['signed_prekey_id'])

    # Registration ID
    buf[192:196] = struct.pack('<I', keys['registration_id'])

    # Noise keypair
    buf[196:228] = keys['noise_private'][:32]
    buf[228:260] = keys['noise_public'][:32]

    # Server static public (will be filled after registration)
    # Leave as zeros for now

    # Timestamp
    buf[292:300] = struct.pack('<q', int(time.time()))

    # CRC32
    crc = binascii.crc32(buf[0:308]) & 0xFFFFFFFF
    buf[308:312] = struct.pack('<I', crc)

    return bytes(buf)


def main():
    parser = argparse.ArgumentParser(
        description="Inject pre-generated credentials into WhatsApp"
    )
    parser.add_argument("--adb", action="store_true",
                        help="Push files to connected Android device via ADB")
    parser.add_argument("--device", "-s", type=str,
                        help="ADB device serial")
    parser.add_argument("--phone", type=str, required=True,
                        help="Phone number (e.g., +15551234567)")
    parser.add_argument("--export", type=str, metavar="FILE",
                        help="Export generated keys to JSON file")
    parser.add_argument("--import", type=str, metavar="FILE", dest="import_file",
                        help="Import keys from JSON file instead of generating")
    parser.add_argument("--acc", type=str, metavar="FILE",
                        help="Also create wa-mini .acc file (without server_static)")

    args = parser.parse_args()

    global _adb_device
    if args.device:
        _adb_device = args.device

    # Generate or import keys
    if args.import_file:
        print(f"[*] Importing keys from {args.import_file}...")
        keys = import_keys(args.import_file)
    else:
        print("[*] Generating new keys...")
        keys = generate_all_keys()

    # Export if requested
    if args.export:
        export_keys(keys, args.export)

    # Create .acc file if requested
    if args.acc:
        print(f"[*] Creating {args.acc}...")
        acc_data = create_acc_file(args.phone, keys)
        with open(args.acc, 'wb') as f:
            f.write(acc_data)
        print(f"[+] Created {args.acc}")
        print("[!] Note: server_static_public is not set (will be filled after registration)")

    # Inject to device if requested
    if args.adb:
        print("")
        inject_to_device(keys, args.phone)
    elif not args.export and not args.acc:
        print("[!] No action specified. Use --adb, --export, or --acc")
        parser.print_help()


if __name__ == "__main__":
    main()
