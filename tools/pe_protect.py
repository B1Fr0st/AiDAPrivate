#!/usr/bin/env python3
"""
pe_protect.py — AiDA per-buyer DLL watermark stamper.

Locates the sentinel string %%AIDA_WM_00000000000000000000%% in the compiled
DLL binary and overwrites it with a buyer-specific watermark ID.  This allows
every distributed build to be uniquely traced back to its buyer if it leaks.

Usage:
    1. Edit BUYER_ID below before each build
    2. Build AiDA normally — the post-build step stamps it automatically

The watermark ID must be 1-20 alphanumeric characters.
"""

import sys
import re
import hashlib
import os

# ═══════════════════════════════════════════════════════════════════════════════
# CHANGE THIS BEFORE EACH BUILD — set to the buyer's watermark ID
# ═══════════════════════════════════════════════════════════════════════════════
BUYER_ID = "AiDAOwner"   # e.g. "JOHN01", "CLIENT042", "BETA7"  (leave "" for no stamp)
# ═══════════════════════════════════════════════════════════════════════════════

SENTINEL = b"%%AIDA_WM_00000000000000000000%%"
SENTINEL_LEN = len(SENTINEL)      # 32 bytes total
PREFIX = b"%%AIDA_WM_"
SUFFIX = b"%%"
PAYLOAD_LEN = 20                   # chars between prefix and suffix


def stamp_watermark(dll_path, watermark_id):
    """Patch the sentinel in the DLL with the buyer watermark."""
    if not re.match(r'^[A-Za-z0-9]{1,20}$', watermark_id):
        print(f"ERROR: Watermark ID must be 1-20 alphanumeric chars, got: {watermark_id!r}",
              file=sys.stderr)
        return False

    with open(dll_path, 'rb') as f:
        data = f.read()

    idx = data.find(SENTINEL)
    if idx == -1:
        print("ERROR: Sentinel not found in binary. Was the DLL compiled with "
              "AIDA_WATERMARK_SENTINEL?", file=sys.stderr)
        return False

    # Check for multiple occurrences (compiler might duplicate the string)
    # We stamp ALL of them so the const and any copies are consistent
    positions = []
    search_start = 0
    while True:
        pos = data.find(SENTINEL, search_start)
        if pos == -1:
            break
        positions.append(pos)
        search_start = pos + SENTINEL_LEN

    padded = watermark_id.ljust(PAYLOAD_LEN, '0').encode('ascii')
    replacement = PREFIX + padded + SUFFIX

    assert len(replacement) == SENTINEL_LEN, "Replacement length mismatch"

    for pos in positions:
        data = data[:pos] + replacement + data[pos + SENTINEL_LEN:]

    with open(dll_path, 'wb') as f:
        f.write(data)

    sha256 = hashlib.sha256(data).hexdigest()
    print(f"OK: Stamped {len(positions)} location(s) with watermark '{watermark_id}'")
    print(f"    SHA-256: {sha256}")
    print(f"    File:    {dll_path}")
    return True


def main():
    if len(sys.argv) < 2:
        print("Usage: pe_protect.py <dll_path>", file=sys.stderr)
        sys.exit(1)

    dll_path = sys.argv[1]

    # CLI --watermark flag overrides hardcoded BUYER_ID
    watermark_id = None
    for i, arg in enumerate(sys.argv[2:], start=2):
        if arg == '--watermark' and i + 1 < len(sys.argv):
            watermark_id = sys.argv[i + 1]
            break

    if watermark_id is None:
        watermark_id = BUYER_ID.strip()

    if not watermark_id:
        print("pe_protect: No watermark set (BUYER_ID is empty), skipping stamp.")
        sys.exit(0)

    if not stamp_watermark(dll_path, watermark_id):
        sys.exit(1)


if __name__ == '__main__':
    main()