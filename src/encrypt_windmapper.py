"""
AES-256-GCM encrypt the raw WindMapper.exe bytes exported by HxD
(WindMapper.c) into src/windmapper_data.inc + src/windmapper_embedded.h
for embedding in AiDAStandalone / AiDA.dll.

Usage:
    python src/encrypt_windmapper.py

Each invocation generates a fresh random 256-bit key and 96-bit nonce; the
key, nonce, GCM tag, and ciphertext length are written into
windmapper_embedded.h, and the ciphertext byte array is written into
windmapper_data.inc (kept as a separate include so the giant byte
initializer does not bloat the wrapping header). driver_loader.cpp reads
the key from the generated header at runtime, so keys are NEVER duplicated
between this script and the C++ loader.
"""
import os
import re
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
INPUT_PATH = os.path.join(PROJECT_ROOT, "WindMapper.c")
INC_PATH = os.path.join(SCRIPT_DIR, "windmapper_data.inc")
HEADER_PATH = os.path.join(SCRIPT_DIR, "windmapper_embedded.h")

KEY_BYTES = 32
NONCE_BYTES = 12
TAG_BYTES = 16
BYTES_PER_LINE = 12


def _format_byte_array(name: str, data: bytes) -> list:
    out = [f"static const unsigned char {name}[{len(data)}] = {{\n"]
    total = len(data)
    for i in range(0, total, BYTES_PER_LINE):
        chunk = data[i:i + BYTES_PER_LINE]
        hex_strs = [f"0x{b:02X}" for b in chunk]
        line = "\t" + ", ".join(hex_strs)
        if i + BYTES_PER_LINE < total:
            line += ","
        out.append(line + "\n")
    out.append("};\n")
    return out


def _format_inc_lines(data: bytes) -> list:
    out = []
    total = len(data)
    for i in range(0, total, BYTES_PER_LINE):
        chunk = data[i:i + BYTES_PER_LINE]
        hex_vals = ", ".join(f"0x{b:02X}" for b in chunk)
        if i + BYTES_PER_LINE < total:
            hex_vals += ","
        out.append("\t" + hex_vals)
    return out


def main():
    if not os.path.isfile(INPUT_PATH):
        print(f"[!] Input file not found: {INPUT_PATH}")
        sys.exit(1)

    with open(INPUT_PATH, "r") as f:
        content = f.read()

    hex_pattern = re.compile(r"0x([0-9A-Fa-f]{2})")
    matches = hex_pattern.findall(content)
    raw_bytes = bytes(int(m, 16) for m in matches)
    total = len(raw_bytes)

    print(f"[*] Parsed {total} bytes from {INPUT_PATH}")
    if total < 2:
        print("[!] Input too small to be a PE.")
        sys.exit(1)
    print(f"[*] First 2 bytes: 0x{raw_bytes[0]:02X} 0x{raw_bytes[1]:02X}")

    if raw_bytes[0] != 0x4D or raw_bytes[1] != 0x5A:
        print("[!] Data does NOT start with MZ -- not a valid PE.")
        sys.exit(1)

    key = os.urandom(KEY_BYTES)
    nonce = os.urandom(NONCE_BYTES)

    aes = AESGCM(key)
    sealed = aes.encrypt(nonce, raw_bytes, None)
    ciphertext = sealed[:-TAG_BYTES]
    tag = sealed[-TAG_BYTES:]

    if len(ciphertext) != total:
        print(f"[!] Ciphertext length mismatch: {len(ciphertext)} vs {total}")
        sys.exit(1)

    decrypted = AESGCM(key).decrypt(nonce, ciphertext + tag, None)
    if decrypted != raw_bytes:
        print("[!] Round-trip verification failed -- aborting.")
        sys.exit(1)
    print("[+] AES-256-GCM round-trip verified")

    inc_lines = _format_inc_lines(ciphertext)
    with open(INC_PATH, "w", newline="\n") as f:
        f.write("\n".join(inc_lines) + "\n")

    header_lines = ["#pragma once\n", "\n"]
    header_lines.extend(_format_byte_array("g_windmapper_key", key))
    header_lines.append("\n")
    header_lines.extend(_format_byte_array("g_windmapper_nonce", nonce))
    header_lines.append("\n")
    header_lines.extend(_format_byte_array("g_windmapper_tag", tag))
    header_lines.append("\n")
    header_lines.append(f"static const unsigned long g_windmapper_ciphertext_len = {len(ciphertext)}u;\n")
    header_lines.append("\n")
    header_lines.append("static const unsigned char g_windmapper_ciphertext[] = {\n")
    header_lines.append("#include \"windmapper_data.inc\"\n")
    header_lines.append("};\n")

    with open(HEADER_PATH, "w", newline="\n") as f:
        f.writelines(header_lines)

    print(f"[+] Wrote {len(ciphertext)} ciphertext bytes to {INC_PATH}")
    print(f"[+] Wrote AES-256-GCM key/nonce/tag header to {HEADER_PATH}")
    print(f"[+] Plaintext: {total} bytes  Key: {KEY_BYTES} bytes  "
          f"Nonce: {NONCE_BYTES} bytes  Tag: {TAG_BYTES} bytes")


if __name__ == "__main__":
    main()
