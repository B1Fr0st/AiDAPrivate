"""
AES-256-GCM encrypt the protected AiDA.dll bytes into
src/aida_plugin_encrypted.h for embedding in AiDAStandalone.

The standalone never writes AiDA.dll to disk; ida_injector.cpp decrypts
this header in memory, prepares the image, allocates remote memory in a
freshly-spawned ida64.exe, copies the prepared image, and runs a tiny
position-independent bootstrap that calls DllMain + PLUGIN.init().

Header inputs the C++ side needs:
    - AES-256 key (32 B), GCM nonce (12 B), GCM tag (16 B), ciphertext
    - SHA-256 of the protected DLL (provenance + idempotency check)
    - Required-export RVAs (PLUGIN, aida_manual_map_marker,
      aida_proof_buffer): the script validates that these exports
      exist at build time so the build fails fast if AiDA.dll forgets
      to export them, instead of crashing the user at runtime.

Usage:
    python src/encrypt_aida_plugin.py --input <protected_AiDA.dll>
                                      --output <aida_plugin_encrypted.h>

Idempotency:
    If the output header already encodes the same input SHA-256 we leave
    the file untouched, so AiDAStandalone does not re-link on every
    AiDA.dll rebuild when the protected bytes haven't changed.
"""

import argparse
import hashlib
import os
import re
import struct
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


KEY_BYTES = 32
NONCE_BYTES = 12
TAG_BYTES = 16
BYTES_PER_LINE = 16

REQUIRED_EXPORTS = (
    "PLUGIN",
    "aida_manual_map_marker",
    "aida_proof_buffer",
    "aida_proof_buffer_len",
)


def _read_pe_exports(pe_bytes):
    if len(pe_bytes) < 0x40:
        raise SystemExit("[!] Input file is too small to be a PE.")
    if pe_bytes[0:2] != b"MZ":
        raise SystemExit("[!] Input does not begin with MZ.")
    e_lfanew = struct.unpack_from("<I", pe_bytes, 0x3C)[0]
    if e_lfanew + 0x18 + 0xF0 > len(pe_bytes):
        raise SystemExit("[!] e_lfanew points past end of file.")
    if pe_bytes[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        raise SystemExit("[!] Missing PE signature.")
    file_header_off = e_lfanew + 4
    machine = struct.unpack_from("<H", pe_bytes, file_header_off + 0)[0]
    if machine != 0x8664:
        raise SystemExit(f"[!] Expected x86_64 (0x8664), got 0x{machine:04X}.")
    num_sections = struct.unpack_from("<H", pe_bytes, file_header_off + 2)[0]
    size_optional = struct.unpack_from("<H", pe_bytes, file_header_off + 16)[0]
    optional_off = file_header_off + 20
    magic = struct.unpack_from("<H", pe_bytes, optional_off)[0]
    if magic != 0x20B:
        raise SystemExit(f"[!] Optional header magic 0x{magic:04X} is not PE32+.")
    image_base = struct.unpack_from("<Q", pe_bytes, optional_off + 24)[0]
    size_of_image = struct.unpack_from("<I", pe_bytes, optional_off + 56)[0]
    address_of_entry_point = struct.unpack_from("<I", pe_bytes, optional_off + 16)[0]
    number_of_rva_and_sizes = struct.unpack_from("<I", pe_bytes, optional_off + 108)[0]
    if number_of_rva_and_sizes < 1:
        raise SystemExit("[!] DataDirectory is empty; no export table.")
    data_dir_off = optional_off + 112
    export_rva = struct.unpack_from("<I", pe_bytes, data_dir_off + 0)[0]
    export_size = struct.unpack_from("<I", pe_bytes, data_dir_off + 4)[0]
    if export_rva == 0 or export_size == 0:
        raise SystemExit("[!] Export directory is empty.")

    section_off = optional_off + size_optional
    sections = []
    for i in range(num_sections):
        base = section_off + i * 40
        name = pe_bytes[base:base + 8].rstrip(b"\0").decode("ascii", errors="replace")
        v_size = struct.unpack_from("<I", pe_bytes, base + 8)[0]
        v_addr = struct.unpack_from("<I", pe_bytes, base + 12)[0]
        r_size = struct.unpack_from("<I", pe_bytes, base + 16)[0]
        r_off = struct.unpack_from("<I", pe_bytes, base + 20)[0]
        sections.append((name, v_addr, v_size, r_off, r_size))

    def rva_to_off(rva):
        for _, v_addr, v_size, r_off, r_size in sections:
            v_end = v_addr + max(v_size, r_size)
            if v_addr <= rva < v_end:
                return r_off + (rva - v_addr)
        raise SystemExit(f"[!] RVA 0x{rva:08X} does not fall inside any section.")

    export_off = rva_to_off(export_rva)
    num_funcs = struct.unpack_from("<I", pe_bytes, export_off + 20)[0]
    num_names = struct.unpack_from("<I", pe_bytes, export_off + 24)[0]
    funcs_rva = struct.unpack_from("<I", pe_bytes, export_off + 28)[0]
    names_rva = struct.unpack_from("<I", pe_bytes, export_off + 32)[0]
    ordinals_rva = struct.unpack_from("<I", pe_bytes, export_off + 36)[0]

    funcs_off = rva_to_off(funcs_rva)
    names_off = rva_to_off(names_rva)
    ordinals_off = rva_to_off(ordinals_rva)

    exports = {}
    for i in range(num_names):
        name_rva = struct.unpack_from("<I", pe_bytes, names_off + i * 4)[0]
        name_off = rva_to_off(name_rva)
        end = pe_bytes.find(b"\0", name_off)
        name = pe_bytes[name_off:end].decode("ascii", errors="replace")
        ordinal = struct.unpack_from("<H", pe_bytes, ordinals_off + i * 2)[0]
        if ordinal >= num_funcs:
            continue
        rva = struct.unpack_from("<I", pe_bytes, funcs_off + ordinal * 4)[0]
        exports[name] = rva

    return {
        "image_base": image_base,
        "size_of_image": size_of_image,
        "entry_rva": address_of_entry_point,
        "exports": exports,
    }


def _format_byte_array(name, data):
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
    return "".join(out)


def _existing_sha256(header_path):
    if not os.path.isfile(header_path):
        return None
    try:
        with open(header_path, "r", encoding="utf-8") as f:
            head = f.read(4096)
    except OSError:
        return None
    m = re.search(r"//\s*input_sha256\s*=\s*([0-9a-f]{64})", head)
    return m.group(1) if m else None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True,
                        help="Path to the protected AiDA.dll")
    parser.add_argument("--output", required=True,
                        help="Output header path")
    args = parser.parse_args()

    with open(args.input, "rb") as f:
        raw = f.read()

    sha = hashlib.sha256(raw).hexdigest()
    if _existing_sha256(args.output) == sha:
        print(f"[=] aida_plugin_encrypted.h already current "
              f"(sha256={sha[:16]}...), skipping.")
        return 0

    info = _read_pe_exports(raw)
    missing = [e for e in REQUIRED_EXPORTS if e not in info["exports"]]
    if missing:
        raise SystemExit(
            f"[!] Required exports missing from AiDA.dll: {missing}. "
            f"Add them to src/AiDA.def and define them in src/aida.cpp.")

    key = os.urandom(KEY_BYTES)
    nonce = os.urandom(NONCE_BYTES)
    aes = AESGCM(key)
    sealed = aes.encrypt(nonce, raw, None)
    ciphertext = sealed[:-TAG_BYTES]
    tag = sealed[-TAG_BYTES:]
    if AESGCM(key).decrypt(nonce, ciphertext + tag, None) != raw:
        raise SystemExit("[!] AES-GCM round-trip verification failed.")

    plugin_rva = info["exports"]["PLUGIN"]
    marker_rva = info["exports"]["aida_manual_map_marker"]
    proof_rva = info["exports"]["aida_proof_buffer"]
    proof_len_rva = info["exports"]["aida_proof_buffer_len"]
    entry_rva = info["entry_rva"]
    image_base = info["image_base"]
    size_of_image = info["size_of_image"]

    sha_bytes = bytes.fromhex(sha)

    lines = [
        "#pragma once\n",
        f"// input_sha256 = {sha}\n",
        f"// generated from {os.path.basename(args.input)} ({len(raw)} bytes)\n",
        "\n",
        "#include <cstdint>\n",
        "\n",
        f"static constexpr unsigned long g_aida_plugin_plaintext_size = {len(raw)}u;\n",
        f"static constexpr unsigned long g_aida_plugin_image_size = {size_of_image}u;\n",
        f"static constexpr std::uint64_t g_aida_plugin_preferred_base = "
        f"0x{image_base:016X}ull;\n",
        f"static constexpr unsigned long g_aida_plugin_dllmain_rva = 0x{entry_rva:08X}u;\n",
        f"static constexpr unsigned long g_aida_plugin_struct_rva = 0x{plugin_rva:08X}u;\n",
        f"static constexpr unsigned long g_aida_plugin_marker_rva = 0x{marker_rva:08X}u;\n",
        f"static constexpr unsigned long g_aida_plugin_proof_rva = 0x{proof_rva:08X}u;\n",
        f"static constexpr unsigned long g_aida_plugin_proof_len_rva = "
        f"0x{proof_len_rva:08X}u;\n",
        "\n",
        _format_byte_array("g_aida_plugin_key", key),
        "\n",
        _format_byte_array("g_aida_plugin_nonce", nonce),
        "\n",
        _format_byte_array("g_aida_plugin_tag", tag),
        "\n",
        _format_byte_array("g_aida_plugin_ciphertext", ciphertext),
        "\n",
        "static constexpr unsigned long g_aida_plugin_ciphertext_len = "
        "sizeof(g_aida_plugin_ciphertext);\n",
        "\n",
        _format_byte_array("g_aida_plugin_input_sha256", sha_bytes),
    ]

    output_dir = os.path.dirname(os.path.abspath(args.output))
    os.makedirs(output_dir, exist_ok=True)
    with open(args.output, "w", newline="\n", encoding="utf-8") as f:
        f.writelines(lines)

    print(f"[+] Wrote {args.output} ({len(raw)} -> {len(ciphertext)} bytes ciphertext, "
          f"sha256={sha[:16]}...)")
    print(f"    PLUGIN rva=0x{plugin_rva:08X}  marker rva=0x{marker_rva:08X}  "
          f"proof rva=0x{proof_rva:08X}  proof_len rva=0x{proof_len_rva:08X}")
    print(f"    DllMain rva=0x{entry_rva:08X}  image_size=0x{size_of_image:08X}  "
          f"preferred_base=0x{image_base:016X}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
