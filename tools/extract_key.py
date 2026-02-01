#!/usr/bin/env python3
"""
WhatsApp HMAC Key Extraction Tool

Extracts the 80-byte HMAC key from WhatsApp APK for registration token generation.
Also calculates MD5_CLASSES from classes.dex.

Usage:
    ./extract_key.py /path/to/WhatsApp.apk

Output:
    WA_VERSION: 2.26.4.71
    WA_MD5_CLASSES: PNuIlAsWtqBNw7eLEYwWUA==
    WA_KEY: dCLnrTWF4vk36Bx1325H8RpxHSnFiW+3Yg6qGL4b/FY+...
"""

import argparse
import base64
import hashlib
import lzma
import os
import re
import struct
import sys
import zipfile
from collections import Counter


def parse_elf_symbols(data: bytes) -> dict:
    """Parse ELF file and extract symbol table entries."""
    if data[:4] != b'\x7fELF':
        raise ValueError("Not a valid ELF file")

    # ELF header
    ei_class = data[4]  # 1 = 32-bit, 2 = 64-bit
    ei_data = data[5]   # 1 = little endian, 2 = big endian

    if ei_data != 1:
        raise ValueError("Only little-endian ELF supported")

    is_64bit = (ei_class == 2)

    if is_64bit:
        # 64-bit ELF header
        e_shoff = struct.unpack_from('<Q', data, 40)[0]
        e_shentsize = struct.unpack_from('<H', data, 58)[0]
        e_shnum = struct.unpack_from('<H', data, 60)[0]
        e_shstrndx = struct.unpack_from('<H', data, 62)[0]
    else:
        # 32-bit ELF header
        e_shoff = struct.unpack_from('<I', data, 32)[0]
        e_shentsize = struct.unpack_from('<H', data, 46)[0]
        e_shnum = struct.unpack_from('<H', data, 48)[0]
        e_shstrndx = struct.unpack_from('<H', data, 50)[0]

    if e_shoff == 0 or e_shnum == 0:
        return {}

    # Read section headers
    sections = []
    for i in range(e_shnum):
        sh_offset = e_shoff + i * e_shentsize
        if is_64bit:
            sh_name = struct.unpack_from('<I', data, sh_offset)[0]
            sh_type = struct.unpack_from('<I', data, sh_offset + 4)[0]
            sh_addr = struct.unpack_from('<Q', data, sh_offset + 16)[0]
            sh_file_offset = struct.unpack_from('<Q', data, sh_offset + 24)[0]
            sh_size = struct.unpack_from('<Q', data, sh_offset + 32)[0]
            sh_link = struct.unpack_from('<I', data, sh_offset + 40)[0]
            sh_entsize = struct.unpack_from('<Q', data, sh_offset + 56)[0]
        else:
            sh_name = struct.unpack_from('<I', data, sh_offset)[0]
            sh_type = struct.unpack_from('<I', data, sh_offset + 4)[0]
            sh_addr = struct.unpack_from('<I', data, sh_offset + 12)[0]
            sh_file_offset = struct.unpack_from('<I', data, sh_offset + 16)[0]
            sh_size = struct.unpack_from('<I', data, sh_offset + 20)[0]
            sh_link = struct.unpack_from('<I', data, sh_offset + 24)[0]
            sh_entsize = struct.unpack_from('<I', data, sh_offset + 36)[0]

        sections.append({
            'name_offset': sh_name,
            'type': sh_type,
            'addr': sh_addr,
            'offset': sh_file_offset,
            'size': sh_size,
            'link': sh_link,
            'entsize': sh_entsize
        })

    # Get section name string table
    if e_shstrndx >= len(sections):
        return {}

    shstrtab = sections[e_shstrndx]
    shstrtab_data = data[shstrtab['offset']:shstrtab['offset'] + shstrtab['size']]

    # Name sections
    for sec in sections:
        name_end = shstrtab_data.find(b'\x00', sec['name_offset'])
        if name_end == -1:
            name_end = len(shstrtab_data)
        sec['name'] = shstrtab_data[sec['name_offset']:name_end].decode('utf-8', errors='replace')

    # Find symbol tables (SHT_SYMTAB=2, SHT_DYNSYM=11)
    symbols = {}
    for sec in sections:
        if sec['type'] not in (2, 11):
            continue

        # Get string table for this symbol table
        if sec['link'] >= len(sections):
            continue
        strtab = sections[sec['link']]
        strtab_data = data[strtab['offset']:strtab['offset'] + strtab['size']]

        # Parse symbols
        sym_data = data[sec['offset']:sec['offset'] + sec['size']]
        entsize = sec['entsize']
        if entsize == 0:
            entsize = 24 if is_64bit else 16

        num_symbols = len(sym_data) // entsize
        for i in range(num_symbols):
            sym_offset = i * entsize
            if is_64bit:
                st_name = struct.unpack_from('<I', sym_data, sym_offset)[0]
                st_value = struct.unpack_from('<Q', sym_data, sym_offset + 8)[0]
                st_size = struct.unpack_from('<Q', sym_data, sym_offset + 16)[0]
            else:
                st_name = struct.unpack_from('<I', sym_data, sym_offset)[0]
                st_value = struct.unpack_from('<I', sym_data, sym_offset + 4)[0]
                st_size = struct.unpack_from('<I', sym_data, sym_offset + 8)[0]

            if st_name == 0:
                continue

            name_end = strtab_data.find(b'\x00', st_name)
            if name_end == -1:
                name_end = len(strtab_data)
            name = strtab_data[st_name:name_end].decode('utf-8', errors='replace')

            if name:
                symbols[name] = {'value': st_value, 'size': st_size}

    return symbols


def find_superpack_archive(elf_data: bytes, symbols: dict) -> tuple:
    """Find SuperPack archive boundaries in libs.so."""
    start_sym = symbols.get('_superpack_archive_start')
    end_sym = symbols.get('_superpack_archive_end')

    if not start_sym or not end_sym:
        # Try to find by magic number
        magic = b'\xb4\x41\x4d\x5e'  # SuperPack magic
        pos = elf_data.find(magic)
        if pos == -1:
            raise ValueError("Could not find SuperPack archive")
        # Estimate end by searching for next section or end of file
        return pos, len(elf_data) - pos

    # Convert virtual addresses to file offsets
    # For libs.so, the data section is typically loaded at its file offset
    start_addr = start_sym['value']
    end_addr = end_sym['value']

    # Find the actual file offset by searching for SuperPack magic near expected location
    magic = b'\xb4\x41\x4d\x5e'

    # Search around the expected location
    search_start = max(0, start_addr - 0x10000)
    search_end = min(len(elf_data), start_addr + 0x10000)

    pos = elf_data.find(magic, search_start, search_end)
    if pos == -1:
        # Try searching the whole file
        pos = elf_data.find(magic)
        if pos == -1:
            raise ValueError("Could not find SuperPack magic")

    size = end_addr - start_addr
    return pos, size


def parse_superpack_header(data: bytes) -> list:
    """Parse SuperPack header and return list of XZ stream offsets."""
    if data[:4] != b'\xb4\x41\x4d\x5e':
        raise ValueError("Invalid SuperPack magic")

    # Header structure (observed from WhatsApp 2.26.4.71):
    # 0x00: magic (4 bytes)
    # 0x04: version/flags (4 bytes)
    # 0x08: num_libs (4 bytes)
    # 0x0c: library table offset (4 bytes)
    # ... more header fields ...
    # Then XZ streams start after header

    # Find XZ stream magic (0xfd377a585a00)
    xz_magic = b'\xfd7zXZ\x00'
    streams = []
    pos = 0

    while True:
        pos = data.find(xz_magic, pos)
        if pos == -1:
            break
        streams.append(pos)
        pos += 1

    return streams


def decompress_xz_stream(data: bytes, offset: int) -> bytes:
    """Decompress a single XZ stream starting at offset."""
    # Find the end of this XZ stream
    # XZ streams end with a specific footer pattern
    xz_magic = b'\xfd7zXZ\x00'

    # Find next stream or end of data
    next_stream = data.find(xz_magic, offset + 6)
    if next_stream == -1:
        stream_data = data[offset:]
    else:
        stream_data = data[offset:next_stream]

    try:
        decompressor = lzma.LZMADecompressor()
        result = decompressor.decompress(stream_data)
        return result
    except lzma.LZMAError:
        # Try with different chunk sizes
        for end_offset in range(len(stream_data), 0, -1000):
            try:
                decompressor = lzma.LZMADecompressor()
                result = decompressor.decompress(stream_data[:end_offset])
                return result
            except lzma.LZMAError:
                continue
        return b''


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of data."""
    if not data:
        return 0.0

    counter = Counter(data)
    length = len(data)
    entropy = 0.0

    for count in counter.values():
        if count > 0:
            p = count / length
            entropy -= p * (p and (p > 0) and (import_log2(p)) or 0)

    return entropy


def import_log2(x):
    """Import math.log2 or provide fallback."""
    import math
    return math.log2(x) if x > 0 else 0


def find_hmac_key(data: bytes) -> list:
    """Search for 80-byte high-entropy sequences near HMAC-related strings."""
    import math

    # Search for "hmac sha-1" or similar strings
    search_patterns = [
        b'hmac sha-1',
        b'HMAC-SHA1',
        b'hmac sha1',
        b'hmac_sha1',
    ]

    # Find all pattern matches
    pattern_matches = []
    for pattern in search_patterns:
        pos = 0
        while True:
            pos = data.find(pattern, pos)
            if pos == -1:
                break
            pattern_matches.append((pos, pattern))
            pos += 1

    if not pattern_matches:
        return []

    # For each pattern match, find the best high-entropy sequence nearby
    # Prefer sequences AFTER the pattern (key typically follows its description)
    candidates = []
    seen_offsets = set()

    for context_offset, pattern in pattern_matches:
        # Search in a window: prefer after the string, but also check before
        # Key is usually within ~256 bytes after the reference string
        search_ranges = [
            (context_offset, min(len(data), context_offset + 0x200)),  # After (primary)
            (max(0, context_offset - 0x200), context_offset),          # Before (fallback)
        ]

        for window_start, window_end in search_ranges:
            # Scan with 8-byte alignment for efficiency
            for offset in range(window_start, window_end - 80, 8):
                # Skip if we've seen a nearby offset
                aligned = (offset // 80) * 80
                if aligned in seen_offsets:
                    continue

                chunk = data[offset:offset + 80]

                # Check for high entropy (unique bytes)
                unique_bytes = len(set(chunk))
                if unique_bytes < 78:  # Require at least 78 unique bytes
                    continue

                # Calculate actual entropy
                counter = Counter(chunk)
                entropy = -sum((c/80) * math.log2(c/80) for c in counter.values())

                if entropy < 6.2:  # High entropy threshold
                    continue

                # Calculate distance to context
                distance = offset - context_offset
                is_after = distance > 0

                seen_offsets.add(aligned)
                candidates.append({
                    'offset': offset,
                    'data': chunk,
                    'unique_bytes': unique_bytes,
                    'entropy': entropy,
                    'context_offset': context_offset,
                    'context': pattern.decode('utf-8', errors='replace'),
                    'distance': distance,
                    'is_after': is_after,
                })

    # For each candidate region, do a fine-grained search to find exact key start
    # The key blob starts where the high-entropy sequence begins
    refined = []
    for c in candidates:
        region_start = max(0, c['offset'] - 16)
        region_end = min(len(data), c['offset'] + 96)

        best_offset = c['offset']
        best_unique = c['unique_bytes']

        # Scan byte by byte to find the earliest offset with max unique bytes
        for fine_offset in range(region_start, region_end - 80):
            chunk = data[fine_offset:fine_offset + 80]
            unique = len(set(chunk))
            if unique == 80:
                # Found perfect entropy - use earliest such offset
                best_offset = fine_offset
                best_unique = unique
                break
            elif unique > best_unique:
                best_offset = fine_offset
                best_unique = unique

        # Update candidate with refined offset
        chunk = data[best_offset:best_offset + 80]
        counter = Counter(chunk)
        entropy = -sum((cnt/80) * math.log2(cnt/80) for cnt in counter.values())

        refined.append({
            'offset': best_offset,
            'data': chunk,
            'unique_bytes': len(set(chunk)),
            'entropy': entropy,
            'context_offset': c['context_offset'],
            'context': c['context'],
            'distance': best_offset - c['context_offset'],
            'is_after': best_offset > c['context_offset'],
        })

    # Deduplicate by offset
    seen = set()
    deduped = []
    for c in refined:
        if c['offset'] not in seen:
            seen.add(c['offset'])
            deduped.append(c)

    # Sort by: unique bytes, then entropy, then prefer keys after the string
    deduped.sort(key=lambda x: (
        x['unique_bytes'],
        x['entropy'],
        x['is_after'],  # True > False
        -abs(x['distance'])  # Closer is better
    ), reverse=True)

    return deduped


def extract_version_from_apk(apk_path: str) -> str:
    """Extract WhatsApp version from APK filename."""
    # Try to get version from filename
    basename = os.path.basename(apk_path)
    match = re.search(r'(\d+\.\d+\.\d+\.\d+)', basename)
    if match:
        return match.group(1)

    return "unknown"


def calculate_md5_classes(apk_path: str) -> str:
    """Calculate Base64(MD5(classes.dex)) from APK."""
    with zipfile.ZipFile(apk_path, 'r') as zf:
        if 'classes.dex' not in zf.namelist():
            raise ValueError("classes.dex not found in APK")

        with zf.open('classes.dex') as f:
            md5_hash = hashlib.md5(f.read()).digest()
            return base64.b64encode(md5_hash).decode('ascii')


def main():
    parser = argparse.ArgumentParser(
        description='Extract HMAC key from WhatsApp APK',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    %(prog)s WhatsApp.apk
    %(prog)s ~/Downloads/WhatsApp_2.26.4.71.apk

Output can be directly used in src/register.c
        """
    )
    parser.add_argument('apk', help='Path to WhatsApp APK file')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Verbose output')
    parser.add_argument('--arch', choices=['x86_64', 'arm64-v8a', 'armeabi-v7a'],
                        default='x86_64', help='Architecture to extract (default: x86_64)')
    parser.add_argument('--all', action='store_true',
                        help='Show all candidate keys for manual verification')
    parser.add_argument('--offset', type=lambda x: int(x, 0),
                        help='Extract key at specific offset (hex or decimal)')

    args = parser.parse_args()

    if not os.path.exists(args.apk):
        print(f"Error: APK file not found: {args.apk}", file=sys.stderr)
        sys.exit(1)

    print(f"Processing: {args.apk}")
    print()

    # Calculate MD5_CLASSES
    try:
        md5_classes = calculate_md5_classes(args.apk)
        print(f"WA_MD5_CLASSES: {md5_classes}")
    except Exception as e:
        print(f"Warning: Could not calculate MD5_CLASSES: {e}", file=sys.stderr)
        md5_classes = None

    # Extract libs.so from APK
    libs_path = f'lib/{args.arch}/libs.so'

    with zipfile.ZipFile(args.apk, 'r') as zf:
        if libs_path not in zf.namelist():
            # Try other architectures
            for arch in ['x86_64', 'arm64-v8a', 'armeabi-v7a', 'x86']:
                alt_path = f'lib/{arch}/libs.so'
                if alt_path in zf.namelist():
                    libs_path = alt_path
                    print(f"Using architecture: {arch}")
                    break
            else:
                print("Error: libs.so not found in APK", file=sys.stderr)
                print("Available files in lib/:", file=sys.stderr)
                for name in zf.namelist():
                    if name.startswith('lib/'):
                        print(f"  {name}", file=sys.stderr)
                sys.exit(1)

        if args.verbose:
            print(f"Extracting: {libs_path}")

        libs_data = zf.read(libs_path)

    print(f"libs.so size: {len(libs_data):,} bytes")

    # Parse ELF symbols
    if args.verbose:
        print("Parsing ELF symbols...")

    symbols = parse_elf_symbols(libs_data)

    if args.verbose:
        superpack_syms = {k: v for k, v in symbols.items() if 'superpack' in k.lower()}
        if superpack_syms:
            print("SuperPack symbols found:")
            for name, info in superpack_syms.items():
                print(f"  {name}: 0x{info['value']:x}")

    # Find SuperPack archive
    if args.verbose:
        print("Locating SuperPack archive...")

    try:
        archive_offset, archive_size = find_superpack_archive(libs_data, symbols)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"SuperPack archive: offset=0x{archive_offset:x}, size={archive_size:,} bytes")

    archive_data = libs_data[archive_offset:archive_offset + archive_size]

    # Find XZ streams
    if args.verbose:
        print("Finding XZ streams...")

    stream_offsets = parse_superpack_header(archive_data)
    print(f"Found {len(stream_offsets)} XZ streams")

    # Decompress streams and search for key
    print("Decompressing and searching for HMAC key...")

    all_candidates = []

    for i, offset in enumerate(stream_offsets):
        if args.verbose:
            print(f"  Processing stream {i}...", end='', flush=True)

        try:
            decompressed = decompress_xz_stream(archive_data, offset)
            if args.verbose:
                print(f" {len(decompressed):,} bytes", end='')

            candidates = find_hmac_key(decompressed)
            if candidates:
                for c in candidates:
                    c['stream'] = i
                all_candidates.extend(candidates)
                if args.verbose:
                    print(f" - {len(candidates)} candidate(s) found!")
            elif args.verbose:
                print()

        except Exception as e:
            if args.verbose:
                print(f" error: {e}")

    # Handle --offset option: extract key at specific offset
    if args.offset is not None:
        print(f"Extracting key at specified offset 0x{args.offset:x}...")
        # Find which stream contains this offset
        for i, offset in enumerate(stream_offsets):
            try:
                decompressed = decompress_xz_stream(archive_data, offset)
                if args.offset < len(decompressed):
                    chunk = decompressed[args.offset:args.offset + 80]
                    if len(chunk) == 80:
                        key_base64 = base64.b64encode(chunk).decode('ascii')
                        print()
                        print("=" * 60)
                        print("EXTRACTION RESULTS")
                        print("=" * 60)
                        print()
                        if md5_classes:
                            print(f'#define WA_MD5_CLASSES "{md5_classes}"')
                        print(f'#define WA_KEY "{key_base64}"')
                        print()
                        print(f"Key extracted from stream {i} at offset 0x{args.offset:x}")
                        print(f"Unique bytes: {len(set(chunk))}/80")
                        if args.verbose:
                            print(f"Key (hex): {chunk.hex()}")
                        sys.exit(0)
            except Exception:
                continue
        print("Error: Could not find data at specified offset", file=sys.stderr)
        sys.exit(1)

    if not all_candidates:
        print()
        print("Error: No HMAC key candidates found", file=sys.stderr)
        print("The key extraction method may need updating for this WhatsApp version.",
              file=sys.stderr)
        sys.exit(1)

    # Sort and get best candidate
    all_candidates.sort(key=lambda x: (x['unique_bytes'], x['entropy']), reverse=True)
    best = all_candidates[0]

    key_base64 = base64.b64encode(best['data']).decode('ascii')
    key_hex = best['data'].hex()

    print()
    print("=" * 60)
    print("EXTRACTION RESULTS")
    print("=" * 60)
    print()

    if md5_classes:
        print(f'#define WA_MD5_CLASSES "{md5_classes}"')

    print(f'#define WA_KEY "{key_base64}"')

    print()
    print(f"Key found in stream {best['stream']} at offset 0x{best['offset']:x}")
    print(f"Context: near '{best['context']}' string")
    print(f"Unique bytes: {best['unique_bytes']}/80, Entropy: {best['entropy']:.2f}")

    if args.verbose:
        print()
        print(f"Key (hex): {key_hex}")

    # Show all candidates if requested
    if args.all and len(all_candidates) > 1:
        print()
        print("=" * 60)
        print("ALL CANDIDATES")
        print("=" * 60)
        for i, c in enumerate(all_candidates, 1):
            key_b64 = base64.b64encode(c['data']).decode('ascii')
            print(f"\n#{i}: stream {c['stream']}, offset 0x{c['offset']:x}")
            print(f"    Unique: {c['unique_bytes']}/80, Entropy: {c['entropy']:.2f}")
            print(f"    Distance from '{c['context']}': {c['distance']:+d} bytes")
            print(f"    Key: {key_b64}")
    elif len(all_candidates) > 1:
        print()
        print(f"Note: {len(all_candidates)} total candidates found. Use --all to see all.")
        if args.verbose:
            print("Other candidates:")
            for i, c in enumerate(all_candidates[1:5], 2):
                print(f"  #{i}: stream {c['stream']}, offset 0x{c['offset']:x}, "
                      f"unique={c['unique_bytes']}, entropy={c['entropy']:.2f}")


if __name__ == '__main__':
    main()
