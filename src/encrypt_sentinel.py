"""
AES-256-GCM encrypt the raw Sentinel.sys bytes exported by HxD (Sentinel.c)
into src/sentinel_encrypted.h for embedding in AiDAStandalone / AiDA.dll.

Usage:
    python src/encrypt_sentinel.py

Each invocation generates a fresh random 256-bit key and 96-bit nonce; the
key, nonce, GCM tag, and ciphertext are all emitted into the generated
header. driver_loader.cpp reads the key from this header at runtime, so
keys are NEVER duplicated between this script and the C++ loader.
"""
import os
import re
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
INPUT_PATH = os.path.join(PROJECT_ROOT, "Sentinel.c")
OUTPUT_PATH = os.path.join(SCRIPT_DIR, "sentinel_encrypted.h")

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

    lines = ["#pragma once\n", "\n"]
    lines.extend(_format_byte_array("g_sentinel_key", key))
    lines.append("\n")
    lines.extend(_format_byte_array("g_sentinel_nonce", nonce))
    lines.append("\n")
    lines.extend(_format_byte_array("g_sentinel_tag", tag))
    lines.append("\n")
    lines.extend(_format_byte_array("g_sentinel_ciphertext", ciphertext))
    lines.append("\n")
    lines.append("static const unsigned long g_sentinel_ciphertext_len = "
                 "sizeof(g_sentinel_ciphertext);\n")

    with open(OUTPUT_PATH, "w", newline="\n") as f:
        f.writelines(lines)

    print(f"[+] Wrote AES-256-GCM header to {OUTPUT_PATH}")
    print(f"[+] Plaintext: {total} bytes  Ciphertext: {len(ciphertext)} bytes  "
          f"Key: {KEY_BYTES} bytes  Nonce: {NONCE_BYTES} bytes  Tag: {TAG_BYTES} bytes")


if __name__ == "__main__":
    main()
