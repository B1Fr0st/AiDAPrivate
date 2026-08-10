"""
Embed the raw WhosWho.sys bytes into src/whoswho_embedded.h as a plain
C++ byte array for embedding in AiDAStandalone / AiDA.dll.

Usage:
    python src/encrypt_whoswho.py
    python src/encrypt_whoswho.py --from-binary path/to/WhosWho.sys

Without --from-binary the script reads the legacy WhosWho.c hex dump at the
project root. With --from-binary the binary is read directly and the legacy
WhosWho.c hex dump is regenerated in HxD-compatible format (so diffs and
manual inspection still work). This lets CMake skip the manual HxD export
step.

No encryption is applied: the generated header carries the exact driver
bytes under namespace aida_driver_embed as kWhosWhoSys / kWhosWhoSysSize.
driver_loader.cpp stages those bytes to disk and hands them to the mapper
or the native NtLoadDriver fallback.
"""
import argparse
import datetime
import os
import re
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
INPUT_PATH = os.path.join(PROJECT_ROOT, "WhosWho.c")
OUTPUT_PATH = os.path.join(SCRIPT_DIR, "whoswho_embedded.h")
HEX_VAR_NAME = "rawData"

BYTES_PER_LINE = 12


def _format_embedded_header(raw_bytes: bytes) -> list:
    total = len(raw_bytes)
    lines = ["#pragma once\n", "\n"]
    lines.append("namespace aida_driver_embed {\n\n")
    lines.append(f"inline const unsigned char kWhosWhoSys[] = {{\n")
    for i in range(0, total, BYTES_PER_LINE):
        chunk = raw_bytes[i:i + BYTES_PER_LINE]
        hex_strs = [f"0x{b:02X}" for b in chunk]
        line = "\t" + ", ".join(hex_strs)
        if i + BYTES_PER_LINE < total:
            line += ","
        lines.append(line + "\n")
    lines.append("};\n\n")
    lines.append("inline const unsigned int kWhosWhoSysSize = "
                 "static_cast<unsigned int>(sizeof(kWhosWhoSys));\n\n")
    lines.append("}\n")
    return lines


def _regenerate_hex_dump(binary_path: str, hex_path: str, raw_bytes: bytes) -> None:
    total = len(raw_bytes)
    end_offset = max(total - 1, 0)
    fmt = "%#m/%#d/%Y %#I:%M:%S %p" if os.name == "nt" else "%-m/%-d/%Y %-I:%M:%S %p"
    timestamp = datetime.datetime.now().strftime(fmt)
    lines = []
    lines.append(f"/* {binary_path} ({timestamp})\n")
    lines.append(
        f"   StartOffset(h): 00000000, EndOffset(h): {end_offset:08X}, "
        f"Length(h): {total:08X} */\n"
    )
    lines.append("\n")
    lines.append(f"unsigned char {HEX_VAR_NAME}[{total}] = {{\n")
    for i in range(0, total, BYTES_PER_LINE):
        chunk = raw_bytes[i:i + BYTES_PER_LINE]
        hex_strs = [f"0x{b:02X}" for b in chunk]
        line = "\t" + ", ".join(hex_strs)
        if i + BYTES_PER_LINE < total:
            line += ","
        lines.append(line + "\n")
    lines.append("};\n")
    with open(hex_path, "w", newline="\n") as f:
        f.writelines(lines)


def _read_hex_dump(hex_path: str) -> bytes:
    with open(hex_path, "r") as f:
        content = f.read()
    hex_pattern = re.compile(r"0x([0-9A-Fa-f]{2})")
    matches = hex_pattern.findall(content)
    return bytes(int(m, 16) for m in matches)


def main():
    parser = argparse.ArgumentParser(description="Embed WhosWho.sys as plain bytes.")
    parser.add_argument(
        "--from-binary",
        dest="from_binary",
        default=None,
        help="Path to the built WhosWho.sys; bypasses the WhosWho.c hex dump and "
             "regenerates it from the binary before embedding.",
    )
    args = parser.parse_args()

    if args.from_binary and os.path.isfile(args.from_binary):
        binary_path = os.path.abspath(args.from_binary)
        with open(binary_path, "rb") as f:
            raw_bytes = f.read()
        print(f"[*] Read {len(raw_bytes)} bytes from {binary_path}")
        _regenerate_hex_dump(binary_path, INPUT_PATH, raw_bytes)
        print(f"[+] Regenerated hex dump at {INPUT_PATH}")
    elif args.from_binary:
        print(f"[!] --from-binary path not found: {args.from_binary}")
        print(f"[*] Falling back to existing hex dump: {INPUT_PATH}")
        if not os.path.isfile(INPUT_PATH):
            print(f"[!] Hex dump not found either: {INPUT_PATH}")
            sys.exit(1)
        raw_bytes = _read_hex_dump(INPUT_PATH)
    else:
        if not os.path.isfile(INPUT_PATH):
            print(f"[!] Input file not found: {INPUT_PATH}")
            sys.exit(1)
        raw_bytes = _read_hex_dump(INPUT_PATH)

    total = len(raw_bytes)

    print(f"[*] Parsed {total} bytes for embedding")
    if total < 2:
        print("[!] Input too small to be a PE.")
        sys.exit(1)
    print(f"[*] First 2 bytes: 0x{raw_bytes[0]:02X} 0x{raw_bytes[1]:02X}")

    if raw_bytes[0] != 0x4D or raw_bytes[1] != 0x5A:
        print("[!] Data does NOT start with MZ -- not a valid PE.")
        sys.exit(1)

    lines = _format_embedded_header(raw_bytes)

    with open(OUTPUT_PATH, "w", newline="\n") as f:
        f.writelines(lines)

    print(f"[+] Wrote plain embedded driver header to {OUTPUT_PATH}")
    print(f"[+] Embedded {total} bytes as aida_driver_embed::kWhosWhoSys")


if __name__ == "__main__":
    main()
