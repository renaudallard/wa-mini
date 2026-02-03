#!/usr/bin/env python3
"""
Extract WhatsApp credentials from rooted Android device and convert to wa-mini .acc format.

Usage:
    # Pull and convert in one step
    ./extract_credentials.py --adb --phone +15551234567

    # With multiple devices, specify which one
    ./extract_credentials.py --adb -s emulator-5554 --phone +15551234567

    # Or from already-extracted files
    ./extract_credentials.py --axolotl axolotl.db --keystore keystore.xml --phone +15551234567

    # Just dump the database schema/contents
    ./extract_credentials.py --dump axolotl.db
"""

import argparse
import base64
import binascii
import os
import re
import sqlite3
import struct
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey


def generate_noise_keypair():
    """Generate a fresh X25519 keypair for Noise protocol."""
    private_key = X25519PrivateKey.generate()
    private_bytes = private_key.private_bytes_raw()
    public_bytes = private_key.public_key().public_bytes_raw()
    return private_bytes, public_bytes


def parse_protobuf_signed_prekey(data):
    """
    Parse Signal signed prekey protobuf record.

    Structure:
      field 1 (varint): prekey ID
      field 2 (bytes): public key (33 bytes with 0x05 prefix)
      field 3 (bytes): private key (32 bytes)
      field 4 (bytes): signature (64 bytes)
    """
    result = {}
    pos = 0

    while pos < len(data):
        if pos >= len(data):
            break

        # Read field tag (varint)
        tag_byte = data[pos]
        field_num = tag_byte >> 3
        wire_type = tag_byte & 0x07
        pos += 1

        if wire_type == 0:  # Varint
            value = 0
            shift = 0
            while pos < len(data):
                b = data[pos]
                pos += 1
                value |= (b & 0x7f) << shift
                if (b & 0x80) == 0:
                    break
                shift += 7
            if field_num == 1:
                result["id"] = value

        elif wire_type == 2:  # Length-delimited
            length = 0
            shift = 0
            while pos < len(data):
                b = data[pos]
                pos += 1
                length |= (b & 0x7f) << shift
                if (b & 0x80) == 0:
                    break
                shift += 7

            if pos + length > len(data):
                break

            field_data = data[pos:pos + length]
            pos += length

            if field_num == 2:  # Public key (33 bytes with 0x05 prefix)
                result["public"] = field_data
            elif field_num == 3:  # Private key (32 bytes)
                result["private"] = field_data
            elif field_num == 4:  # Signature (64 bytes)
                result["signature"] = field_data

        else:
            # Unknown wire type, skip
            break

    return result


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


def adb_pull_file(remote_path, local_path):
    """Pull file from device using adb with root."""
    # Use su to copy to accessible location first
    tmp_path = f"/data/local/tmp/wa_extract_{os.getpid()}"
    run_adb(["shell", f"su -c 'cp {remote_path} {tmp_path} && chmod 644 {tmp_path}'"])
    run_adb(["pull", tmp_path, local_path])
    run_adb(["shell", f"rm {tmp_path}"])


def dump_database(db_path):
    """Dump database schema and contents for analysis."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Get all tables
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [row[0] for row in cursor.fetchall()]

    print(f"Database: {db_path}")
    print(f"Tables: {', '.join(tables)}\n")

    for table in tables:
        print(f"=== Table: {table} ===")

        # Get schema
        cursor.execute(f"PRAGMA table_info({table})")
        columns = cursor.fetchall()
        col_names = [col[1] for col in columns]
        col_types = [col[2] for col in columns]
        print(f"Columns: {', '.join(f'{n} ({t})' for n, t in zip(col_names, col_types))}")

        # Get row count
        cursor.execute(f"SELECT COUNT(*) FROM {table}")
        count = cursor.fetchone()[0]
        print(f"Rows: {count}")

        # Show first few rows
        if count > 0:
            cursor.execute(f"SELECT * FROM {table} LIMIT 5")
            rows = cursor.fetchall()
            for i, row in enumerate(rows):
                print(f"  Row {i}:")
                for name, val in zip(col_names, row):
                    if isinstance(val, bytes):
                        if len(val) <= 64:
                            print(f"    {name}: {val.hex()} ({len(val)} bytes)")
                        else:
                            print(f"    {name}: {val[:32].hex()}... ({len(val)} bytes)")
                    elif isinstance(val, str) and len(val) > 100:
                        print(f"    {name}: {val[:100]}... ({len(val)} chars)")
                    else:
                        print(f"    {name}: {val}")
        print()

    conn.close()


def parse_axolotl_db(db_path):
    """Parse axolotl.db to extract Signal protocol keys."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    result = {
        "identity_key_private": None,
        "identity_key_public": None,
        "signed_prekey_private": None,
        "signed_prekey_public": None,
        "signed_prekey_signature": None,
        "signed_prekey_id": None,
        "registration_id": None,
    }

    # Get table list to understand schema
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [row[0] for row in cursor.fetchall()]
    print(f"[*] axolotl.db tables: {', '.join(tables)}")

    # Try different table names used by WhatsApp versions
    # Identity keys
    identity_tables = ["identities", "identity_key", "identitykeys"]
    for table in identity_tables:
        if table in tables:
            cursor.execute(f"PRAGMA table_info({table})")
            cols = {col[1]: col[0] for col in cursor.fetchall()}
            print(f"[*] Found identity table '{table}' with columns: {list(cols.keys())}")

            cursor.execute(f"SELECT * FROM {table} LIMIT 1")
            row = cursor.fetchone()
            if row:
                # Try to find private and public key columns
                for priv_col in ["private_key", "privatekey", "key_private", "private"]:
                    if priv_col in cols:
                        result["identity_key_private"] = row[cols[priv_col]]
                        break
                for pub_col in ["public_key", "publickey", "key_public", "public", "key"]:
                    if pub_col in cols:
                        result["identity_key_public"] = row[cols[pub_col]]
                        break
                # Registration ID is often in the identities table
                for reg_col in ["registration_id", "regid", "reg_id"]:
                    if reg_col in cols:
                        result["registration_id"] = row[cols[reg_col]]
                        break
            break

    # Signed prekeys
    prekey_tables = ["signed_prekeys", "signedprekeys", "signed_prekey"]
    for table in prekey_tables:
        if table in tables:
            cursor.execute(f"PRAGMA table_info({table})")
            cols = {col[1]: col[0] for col in cursor.fetchall()}
            print(f"[*] Found signed prekey table '{table}' with columns: {list(cols.keys())}")

            # Get the most recent signed prekey
            cursor.execute(f"SELECT * FROM {table} ORDER BY rowid DESC LIMIT 1")
            row = cursor.fetchone()
            if row:
                # First try direct columns
                for priv_col in ["private_key", "privatekey", "key_private", "private"]:
                    if priv_col in cols:
                        result["signed_prekey_private"] = row[cols[priv_col]]
                        break
                for pub_col in ["public_key", "publickey", "key_public", "public", "key"]:
                    if pub_col in cols:
                        result["signed_prekey_public"] = row[cols[pub_col]]
                        break
                for sig_col in ["signature", "sig"]:
                    if sig_col in cols:
                        result["signed_prekey_signature"] = row[cols[sig_col]]
                        break
                for id_col in ["prekey_id", "id", "_id", "key_id"]:
                    if id_col in cols:
                        result["signed_prekey_id"] = row[cols[id_col]]
                        break

                # If not found, try parsing protobuf record
                if not result["signed_prekey_private"] and "record" in cols:
                    record = row[cols["record"]]
                    if isinstance(record, bytes):
                        print("[*] Parsing signed prekey protobuf record...")
                        parsed = parse_protobuf_signed_prekey(record)
                        if parsed.get("private"):
                            result["signed_prekey_private"] = parsed["private"]
                            print(f"[+] Found signed prekey private ({len(parsed['private'])} bytes)")
                        if parsed.get("public"):
                            result["signed_prekey_public"] = parsed["public"]
                        if parsed.get("signature"):
                            result["signed_prekey_signature"] = parsed["signature"]
                            print(f"[+] Found signed prekey signature ({len(parsed['signature'])} bytes)")
                        if parsed.get("id") and not result["signed_prekey_id"]:
                            result["signed_prekey_id"] = parsed["id"]
            break

    # Registration ID - might be in a separate table or with identity
    reg_tables = ["registration", "account", "local_identity"]
    for table in reg_tables:
        if table in tables:
            cursor.execute(f"PRAGMA table_info({table})")
            cols = {col[1]: col[0] for col in cursor.fetchall()}

            cursor.execute(f"SELECT * FROM {table} LIMIT 1")
            row = cursor.fetchone()
            if row:
                for reg_col in ["registration_id", "regid", "reg_id"]:
                    if reg_col in cols:
                        result["registration_id"] = row[cols[reg_col]]
                        break
            break

    conn.close()
    return result


def parse_keystore_xml(xml_path):
    """Parse keystore.xml to extract Noise protocol keys."""
    result = {
        "noise_private": None,
        "noise_public": None,
        "server_public": None,
        "phone": None,
    }

    with open(xml_path, 'r') as f:
        content = f.read()

    # Try XML parsing first
    try:
        root = ET.fromstring(content)
        for item in root.findall(".//string"):
            name = item.get("name", "")
            value = item.text or ""

            if "client_static_keypair" in name and "pwd_enc" not in name:
                # Base64 encoded keypair (64 bytes: 32 private + 32 public)
                try:
                    keypair = base64.b64decode(value)
                    if len(keypair) == 64:
                        result["noise_private"] = keypair[:32]
                        result["noise_public"] = keypair[32:]
                        print("[+] Found Noise keypair (plaintext)")
                except Exception:
                    pass

            elif "server_static" in name:
                try:
                    # Add base64 padding if needed
                    padded = value + '=' * (-len(value) % 4)
                    result["server_public"] = base64.b64decode(padded)
                    print("[+] Found server static public key")
                except Exception:
                    pass

            elif name in ["phone", "phonenumber", "cc_phone"]:
                result["phone"] = value
                print(f"[+] Found phone: {value}")

    except ET.ParseError:
        # Fallback to regex
        pass

    # Also try regex for encoded values
    patterns = [
        (r'client_static_keypair[^>]*>([A-Za-z0-9+/=]+)<', "noise_keypair"),
        (r'server_static[^>]*>([A-Za-z0-9+/=]+)<', "server_public"),
    ]

    for pattern, key in patterns:
        match = re.search(pattern, content)
        if match and result.get(key) is None:
            try:
                # Add base64 padding if needed
                b64_value = match.group(1)
                padded = b64_value + '=' * (-len(b64_value) % 4)
                data = base64.b64decode(padded)
                if key == "noise_keypair" and len(data) == 64:
                    result["noise_private"] = data[:32]
                    result["noise_public"] = data[32:]
                elif key == "server_public":
                    result["server_public"] = data
            except Exception:
                pass

    return result


def strip_key_prefix(key_bytes):
    """Strip 0x05 DJB type prefix from Curve25519 public key if present."""
    if isinstance(key_bytes, bytes) and len(key_bytes) == 33 and key_bytes[0] == 0x05:
        return key_bytes[1:]
    return key_bytes


def create_acc_file(phone, identity_priv, identity_pub, signed_prekey_priv,
                    signed_prekey_sig, signed_prekey_id, registration_id,
                    noise_priv, noise_pub, server_pub):
    """Create wa-mini .acc file from extracted credentials."""

    buf = bytearray(312)

    # Magic "WAMN" and version
    buf[0:4] = b'WAMN'
    buf[4] = 1  # Format version
    buf[5] = 1  # Active flag

    # Phone number (null-padded, max 19 chars + null)
    phone_bytes = phone.encode('utf-8')[:19]
    buf[8:8+len(phone_bytes)] = phone_bytes

    # Strip 0x05 type prefix from public keys if present
    identity_pub = strip_key_prefix(identity_pub)

    # Identity keypair (32 + 32 bytes)
    if isinstance(identity_priv, bytes) and len(identity_priv) >= 32:
        buf[28:60] = identity_priv[:32]
    if isinstance(identity_pub, bytes) and len(identity_pub) >= 32:
        buf[60:92] = identity_pub[:32]

    # Signed prekey private (32 bytes)
    if isinstance(signed_prekey_priv, bytes) and len(signed_prekey_priv) >= 32:
        buf[92:124] = signed_prekey_priv[:32]

    # Signed prekey signature (64 bytes)
    if isinstance(signed_prekey_sig, bytes) and len(signed_prekey_sig) >= 64:
        buf[124:188] = signed_prekey_sig[:64]

    # Signed prekey ID (4 bytes, little-endian)
    if signed_prekey_id is not None:
        buf[188:192] = struct.pack('<I', int(signed_prekey_id) & 0xFFFFFFFF)

    # Registration ID (4 bytes, little-endian)
    if registration_id is not None:
        buf[192:196] = struct.pack('<I', int(registration_id) & 0xFFFFFFFF)

    # Noise static keypair (32 + 32 bytes)
    if isinstance(noise_priv, bytes) and len(noise_priv) >= 32:
        buf[196:228] = noise_priv[:32]
    if isinstance(noise_pub, bytes) and len(noise_pub) >= 32:
        buf[228:260] = noise_pub[:32]

    # Server static public key (32 bytes)
    if isinstance(server_pub, bytes) and len(server_pub) >= 32:
        buf[260:292] = server_pub[:32]

    # Timestamp (8 bytes, little-endian)
    buf[292:300] = struct.pack('<q', int(time.time()))

    # Reserved (8 bytes)
    # Already zero

    # CRC32 checksum over bytes 0-307
    crc = binascii.crc32(buf[0:308]) & 0xFFFFFFFF
    buf[308:312] = struct.pack('<I', crc)

    return bytes(buf)


def print_key_summary(label, data):
    """Print key data summary."""
    if data is None:
        print(f"  {label}: NOT FOUND")
    elif isinstance(data, bytes):
        print(f"  {label}: {data[:16].hex()}... ({len(data)} bytes)")
    else:
        print(f"  {label}: {data}")


def main():
    parser = argparse.ArgumentParser(
        description="Extract WhatsApp credentials and convert to wa-mini format"
    )
    parser.add_argument("--adb", action="store_true",
                        help="Pull files from connected Android device via ADB")
    parser.add_argument("--device", "-s", type=str,
                        help="ADB device serial (use 'adb devices' to list)")
    parser.add_argument("--axolotl", type=str,
                        help="Path to axolotl.db file")
    parser.add_argument("--keystore", type=str,
                        help="Path to keystore.xml file")
    parser.add_argument("--phone", type=str,
                        help="Phone number (e.g., +15551234567)")
    parser.add_argument("-o", "--output", type=str,
                        help="Output .acc file path")
    parser.add_argument("--dump", type=str,
                        help="Dump database schema and contents (for analysis)")

    args = parser.parse_args()

    # Dump mode
    if args.dump:
        dump_database(args.dump)
        return

    # Set ADB device if specified
    global _adb_device
    if args.device:
        _adb_device = args.device

    # Need either --adb or manual file paths
    if not args.adb and not (args.axolotl or args.keystore):
        parser.print_help()
        print("\nError: Specify --adb or provide file paths", file=sys.stderr)
        sys.exit(1)

    axolotl_path = args.axolotl
    keystore_path = args.keystore

    # Pull files via ADB if requested
    if args.adb:
        print("[*] Pulling files from device via ADB...")

        with tempfile.TemporaryDirectory() as tmpdir:
            if not axolotl_path:
                axolotl_path = os.path.join(tmpdir, "axolotl.db")
                print("[*] Pulling axolotl.db...")
                adb_pull_file("/data/data/com.whatsapp/databases/axolotl.db", axolotl_path)

            if not keystore_path:
                keystore_path = os.path.join(tmpdir, "keystore.xml")
                print("[*] Pulling keystore.xml...")
                adb_pull_file("/data/data/com.whatsapp/shared_prefs/keystore.xml", keystore_path)

            # Process with temp files
            process_files(axolotl_path, keystore_path, args.phone, args.output)
    else:
        process_files(axolotl_path, keystore_path, args.phone, args.output)


def process_files(axolotl_path, keystore_path, phone, output_path):
    """Process extracted files and create .acc file."""

    axolotl_data = {}
    keystore_data = {}

    if axolotl_path and os.path.exists(axolotl_path):
        print(f"\n[*] Parsing {axolotl_path}...")
        axolotl_data = parse_axolotl_db(axolotl_path)

    if keystore_path and os.path.exists(keystore_path):
        print(f"\n[*] Parsing {keystore_path}...")
        keystore_data = parse_keystore_xml(keystore_path)

    # Use phone from keystore if not provided
    if not phone and keystore_data.get("phone"):
        phone = keystore_data["phone"]

    # Always generate fresh Noise keypair
    # WhatsApp servers accept new Noise keys for existing accounts, and the
    # encrypted Noise keys in newer WhatsApp versions can't be decrypted anyway
    print("\n[*] Generating fresh Noise keypair...")
    noise_priv, noise_pub = generate_noise_keypair()
    print(f"[+] Generated Noise keypair: {noise_pub[:8].hex()}...")

    # Summary
    print("\n=== Extracted Credentials ===")
    print_key_summary("Identity Private", axolotl_data.get("identity_key_private"))
    print_key_summary("Identity Public", axolotl_data.get("identity_key_public"))
    print_key_summary("Signed Prekey Private", axolotl_data.get("signed_prekey_private"))
    print_key_summary("Signed Prekey Public", axolotl_data.get("signed_prekey_public"))
    print_key_summary("Signed Prekey Signature", axolotl_data.get("signed_prekey_signature"))
    print_key_summary("Signed Prekey ID", axolotl_data.get("signed_prekey_id"))
    print_key_summary("Registration ID", axolotl_data.get("registration_id"))
    print_key_summary("Noise Private", noise_priv)
    print_key_summary("Noise Public", noise_pub)
    print_key_summary("Server Public", keystore_data.get("server_public"))
    print_key_summary("Phone", phone)

    # Check for missing required fields (Noise keys no longer needed from keystore)
    missing = []
    if not axolotl_data.get("identity_key_private"):
        missing.append("identity_key_private")
    if not axolotl_data.get("identity_key_public"):
        missing.append("identity_key_public")
    if not axolotl_data.get("signed_prekey_private"):
        missing.append("signed_prekey_private")
    if not phone:
        missing.append("phone")

    if missing:
        print(f"\n[!] Missing required fields: {', '.join(missing)}")
        print("[!] Cannot create .acc file without these fields")
        print("\n[*] Try --dump to analyze database structure")
        return

    if not output_path:
        # Default to wa-mini accounts directory
        wa_mini_dir = os.path.expanduser("~/.wa-mini/accounts")
        os.makedirs(wa_mini_dir, exist_ok=True)
        output_path = os.path.join(wa_mini_dir, f"{phone}.acc")

    # Create .acc file
    print(f"\n[*] Creating {output_path}...")

    # Ensure parent directory exists
    parent_dir = os.path.dirname(output_path)
    if parent_dir:
        os.makedirs(parent_dir, exist_ok=True)

    acc_data = create_acc_file(
        phone=phone,
        identity_priv=axolotl_data.get("identity_key_private"),
        identity_pub=axolotl_data.get("identity_key_public"),
        signed_prekey_priv=axolotl_data.get("signed_prekey_private"),
        signed_prekey_sig=axolotl_data.get("signed_prekey_signature", b'\x00' * 64),
        signed_prekey_id=axolotl_data.get("signed_prekey_id", 1),
        registration_id=axolotl_data.get("registration_id", 1),
        noise_priv=noise_priv,
        noise_pub=noise_pub,
        server_pub=keystore_data.get("server_public", b'\x00' * 32),
    )

    with open(output_path, 'wb') as f:
        f.write(acc_data)

    print(f"[+] Created {output_path} ({len(acc_data)} bytes)")


if __name__ == "__main__":
    main()
