"""
XOR-encrypt the raw driver bytes in P2CDriverBytes.h so that
EmbeddedDriver.cpp's InitializeDriverData() can correctly XOR-decrypt them
back to the original PE. This must be run once whenever a new plaintext
driver is dumped into P2CDriverBytes.h.
"""
import re, os, sys

XOR_KEY = bytes([
    0x7A, 0xC3, 0x91, 0xE5, 0x3D, 0xF8, 0x46, 0xAB,
    0x1F, 0x82, 0xD7, 0x54, 0x69, 0xBE, 0x03, 0xC6
])

HEADER_PATH = os.path.join(os.path.dirname(__file__), "src", "P2CDriverBytes.h")

def main():
    with open(HEADER_PATH, "r") as f:
        content = f.read()

    # Extract all hex byte values
    hex_pattern = re.compile(r"0x([0-9A-Fa-f]{2})")
    matches = hex_pattern.findall(content)
    raw_bytes = bytes([int(m, 16) for m in matches])
    total = len(raw_bytes)

    print(f"[*] Parsed {total} bytes from {HEADER_PATH}")
    print(f"[*] First 2 bytes: 0x{raw_bytes[0]:02X} 0x{raw_bytes[1]:02X}")

    # Check if already encrypted (not starting with MZ)
    if raw_bytes[0] != 0x4D or raw_bytes[1] != 0x5A:
        print("[!] Data does NOT start with MZ -- may already be encrypted.")
        print("[!] Aborting to prevent double-encryption.")
        sys.exit(1)

    # XOR-encrypt
    encrypted = bytes([b ^ XOR_KEY[i % len(XOR_KEY)] for i, b in enumerate(raw_bytes)])

    # Verify round-trip
    dec0 = encrypted[0] ^ XOR_KEY[0]
    dec1 = encrypted[1] ^ XOR_KEY[1]
    assert dec0 == 0x4D and dec1 == 0x5A, "Round-trip verification failed!"
    print(f"[+] Encryption verified (decrypts back to MZ)")

    # Build the new header
    lines = []
    lines.append("#pragma once\n")
    lines.append("\n")
    lines.append("/* XOR-encrypted driver bytes (key in EmbeddedDriver.cpp) */\n")
    lines.append("\n")
    lines.append(f"unsigned char rawData[{total}] = {{\n")

    BYTES_PER_LINE = 12
    for i in range(0, total, BYTES_PER_LINE):
        chunk = encrypted[i:i + BYTES_PER_LINE]
        hex_strs = [f"0x{b:02X}" for b in chunk]
        line = "\t" + ", ".join(hex_strs)
        if i + BYTES_PER_LINE < total:
            line += ","
        lines.append(line + "\n")

    lines.append("};\n")
    lines.append("\n")
    lines.append("\n")
    lines.append(f"static const unsigned long rawDataSize = sizeof(rawData);\n")

    with open(HEADER_PATH, "w") as f:
        f.writelines(lines)

    print(f"[+] Wrote encrypted header to {HEADER_PATH}")
    print(f"[+] {total} bytes encrypted with 16-byte XOR key")

if __name__ == "__main__":
    main()
