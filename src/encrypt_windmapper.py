"""
XOR-encrypt the raw WindMapper.exe bytes in windmapper_data.inc so that
driver_loader.cpp can correctly XOR-decrypt them at runtime.

This must be run once whenever windmapper_data.inc is regenerated from a
new WindMapper.exe build.

Usage:
    python src/encrypt_windmapper.py
"""
import re, os, sys

MAPPER_KEY = bytes([
    0x91, 0x3C, 0xAE, 0x57, 0xF8, 0x22, 0xD4, 0x6B,
    0x15, 0xC9, 0x83, 0x4F, 0xBA, 0x60, 0x7E, 0xE3
])

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
INC_PATH = os.path.join(SCRIPT_DIR, "windmapper_data.inc")

def main():
    if not os.path.isfile(INC_PATH):
        print(f"[!] Input file not found: {INC_PATH}")
        sys.exit(1)

    with open(INC_PATH, "r") as f:
        content = f.read()

    hex_pattern = re.compile(r"0x([0-9A-Fa-f]{2})")
    matches = hex_pattern.findall(content)
    raw_bytes = bytes([int(m, 16) for m in matches])
    total = len(raw_bytes)

    print(f"[*] Parsed {total} bytes from {INC_PATH}")
    print(f"[*] First 2 bytes: 0x{raw_bytes[0]:02X} 0x{raw_bytes[1]:02X}")

    if raw_bytes[0] != 0x4D or raw_bytes[1] != 0x5A:
        print("[!] Data does NOT start with MZ — not a valid PE.")
        sys.exit(1)

    encrypted = bytes([b ^ MAPPER_KEY[i % len(MAPPER_KEY)] for i, b in enumerate(raw_bytes)])

    # Verify round-trip
    decrypted = bytes([b ^ MAPPER_KEY[i % len(MAPPER_KEY)] for i, b in enumerate(encrypted)])
    assert decrypted == raw_bytes, "Round-trip check failed!"

    # Write back as hex array
    lines = []
    for i in range(0, total, 12):
        chunk = encrypted[i:i+12]
        hex_vals = ", ".join(f"0x{b:02X}" for b in chunk)
        if i + 12 < total:
            hex_vals += ","
        lines.append("\t" + hex_vals)

    with open(INC_PATH, "w", newline="\n") as f:
        f.write("\n".join(lines) + "\n")

    print(f"[+] Wrote {total} XOR-encrypted bytes back to {INC_PATH}")
    print(f"[+] First 2 encrypted bytes: 0x{encrypted[0]:02X} 0x{encrypted[1]:02X}")

if __name__ == "__main__":
    main()
