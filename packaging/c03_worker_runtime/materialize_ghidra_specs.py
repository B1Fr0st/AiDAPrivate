import argparse
import ctypes
import hashlib
import json
import os
import secrets
import sys
from pathlib import Path, PurePosixPath


EXPECTED_SPECS = (
    ("x86-64.sla", "sla"), ("x86.sla", "sla"), ("ARM7_le.sla", "sla"),
    ("ARM7_be.sla", "sla"), ("AARCH64.sla", "sla"), ("AARCH64BE.sla", "sla"),
    ("mips32le.sla", "sla"), ("mips32be.sla", "sla"), ("mips64le.sla", "sla"),
    ("mips64be.sla", "sla"), ("ppc_32_le.sla", "sla"), ("ppc_32_be.sla", "sla"),
    ("ppc_64_le.sla", "sla"), ("ppc_64_be.sla", "sla"),
    ("riscv.ilp32d.sla", "sla"), ("riscv.lp64d.sla", "sla"),
    ("x86-64.pspec", "pspec"), ("x86-64-win.cspec", "cspec"),
    ("x86-64-gcc.cspec", "cspec"), ("x86.pspec", "pspec"),
    ("x86win.cspec", "cspec"), ("x86gcc.cspec", "cspec"),
    ("x86-16-real.pspec", "pspec"), ("x86-16.cspec", "cspec"),
    ("x86.ldefs", "ldefs"), ("ARMt.pspec", "pspec"), ("ARM.cspec", "cspec"),
    ("ARM_win.cspec", "cspec"), ("ARM.ldefs", "ldefs"),
    ("AARCH64.pspec", "pspec"), ("AARCH64.cspec", "cspec"),
    ("AARCH64_win.cspec", "cspec"), ("AARCH64.ldefs", "ldefs"),
    ("mips32.pspec", "pspec"), ("mips64.pspec", "pspec"),
    ("mips32le.cspec", "cspec"), ("mips32be.cspec", "cspec"),
    ("mips64le.cspec", "cspec"), ("mips64be.cspec", "cspec"),
    ("mips.ldefs", "ldefs"), ("ppc_32.pspec", "pspec"),
    ("ppc_64.pspec", "pspec"), ("ppc_32.cspec", "cspec"),
    ("ppc_64_le.cspec", "cspec"), ("ppc_64_be.cspec", "cspec"),
    ("ppc.ldefs", "ldefs"), ("RV32.pspec", "pspec"), ("RV64.pspec", "pspec"),
    ("riscv32-fp.cspec", "cspec"), ("riscv64-fp.cspec", "cspec"),
    ("riscv.ldefs", "ldefs"),
)
MIRRORS = ("ghidra_specs", "deps/ghidra_specs")
MANIFEST_RELATIVE_PATH = "deps/AiDA_GhidraSpecs.manifest.json"
DIGEST_RELATIVE_PATH = "deps/AiDA_GhidraSpecs.manifest.sha256"
FILE_ATTRIBUTE_DIRECTORY = 0x10
FILE_ATTRIBUTE_REPARSE_POINT = 0x400
INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF
GENERIC_READ = 0x80000000
FILE_SHARE_READ = 0x1
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x80
FILE_FLAG_SEQUENTIAL_SCAN = 0x08000000
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


def fail(message):
    raise RuntimeError(message)


def canonical_json(value):
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def is_safe_relative(value):
    if not isinstance(value, str) or "\\" in value or ":" in value or "\x00" in value:
        return False
    parsed = PurePosixPath(value)
    return not parsed.is_absolute() and bool(parsed.parts) and all(part not in ("", ".", "..") for part in parsed.parts)


def safe_join(root, relative, label):
    if not is_safe_relative(relative):
        fail(label + " contains an unsafe relative path")
    candidate = root.joinpath(*PurePosixPath(relative).parts)
    resolved_parent = candidate.parent.resolve(strict=False)
    try:
        resolved_parent.relative_to(root)
    except ValueError:
        fail(label + " escapes its approved root")
    return resolved_parent / candidate.name


def reject_reparse(path, label):
    if os.name != "nt":
        fail("Ghidra specification materialization is Windows-only")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetFileAttributesW.argtypes = [ctypes.c_wchar_p]
    kernel32.GetFileAttributesW.restype = ctypes.c_uint32
    current = path
    while current != current.parent:
        attributes = kernel32.GetFileAttributesW(str(current))
        if attributes != INVALID_FILE_ATTRIBUTES and attributes & FILE_ATTRIBUTE_REPARSE_POINT:
            fail(label + " crosses a reparse point")
        current = current.parent


def read_locked(path, label, maximum_bytes=536870912):
    reject_reparse(path, label)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetFileAttributesW.argtypes = [ctypes.c_wchar_p]
    kernel32.GetFileAttributesW.restype = ctypes.c_uint32
    kernel32.CreateFileW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32,
                                     ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32,
                                     ctypes.c_void_p]
    kernel32.CreateFileW.restype = ctypes.c_void_p
    kernel32.GetFileSizeEx.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_longlong)]
    kernel32.GetFileSizeEx.restype = ctypes.c_int
    kernel32.ReadFile.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32,
                                  ctypes.POINTER(ctypes.c_uint32), ctypes.c_void_p]
    kernel32.ReadFile.restype = ctypes.c_int
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = ctypes.c_int
    attributes = kernel32.GetFileAttributesW(str(path))
    if attributes == INVALID_FILE_ATTRIBUTES or attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT):
        fail(label + " must be a regular non-reparse file")
    handle = kernel32.CreateFileW(str(path), GENERIC_READ, FILE_SHARE_READ, None, OPEN_EXISTING,
                                  FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, None)
    if handle in (None, INVALID_HANDLE_VALUE):
        fail(label + " could not be locked")
    try:
        size = ctypes.c_longlong()
        if not kernel32.GetFileSizeEx(handle, ctypes.byref(size)) or size.value <= 0 or size.value > maximum_bytes:
            fail(label + " size violates policy")
        data = bytearray()
        digest = hashlib.sha256()
        remaining = size.value
        buffer = ctypes.create_string_buffer(min(1024 * 1024, remaining))
        while remaining:
            requested = min(remaining, len(buffer))
            received = ctypes.c_uint32()
            if not kernel32.ReadFile(handle, buffer, requested, ctypes.byref(received), None) or not received.value:
                fail(label + " changed or became unreadable")
            block = buffer.raw[:received.value]
            data.extend(block)
            digest.update(block)
            remaining -= received.value
        return bytes(data), size.value, digest.hexdigest()
    finally:
        kernel32.CloseHandle(handle)


def atomic_write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    reject_reparse(path.parent, "Ghidra specification output directory")
    if path.exists() or path.is_symlink():
        reject_reparse(path, "Ghidra specification output")
        if not path.is_file():
            fail("Ghidra specification output is not a regular file")
    temporary = path.with_name(path.name + "." + str(os.getpid()) + "." + secrets.token_hex(8) + ".tmp")
    descriptor = None
    try:
        descriptor = os.open(str(temporary), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                fail("Ghidra specification output write made no progress")
            view = view[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        os.replace(temporary, path)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary.exists():
            temporary.unlink()


def read_contract(path):
    data, _, digest = read_locked(path, "Ghidra specification source contract", 16 * 1024 * 1024)
    try:
        contract = json.loads(data.decode("utf-8", errors="strict"))
    except (UnicodeError, json.JSONDecodeError) as error:
        fail("Ghidra specification source contract is malformed: " + str(error))
    if set(contract) != {"schema", "schema_version", "producer", "specifications", "package", "materialization"}:
        fail("Ghidra specification source contract property set is invalid")
    if contract["schema"] != "aida.c03.ghidra-spec-source" or contract["schema_version"] != 1:
        fail("Ghidra specification source contract is downgraded")
    if contract["producer"] != {
        "id": "ghidra_sleigh_compiler",
        "usage": "build_only",
        "network_fetch_forbidden": True,
        "approved_input_root_required": True,
        "approved_generator_root_required": True,
    }:
        fail("Ghidra specification producer policy is invalid")
    expected_records = [{"name": name, "kind": kind} for name, kind in EXPECTED_SPECS]
    if contract["specifications"] != expected_records:
        fail("Ghidra specification source inventory is incomplete, reordered, or duplicated")
    if contract["package"] != {
        "mirrors": list(MIRRORS),
        "manifest_relative_path": MANIFEST_RELATIVE_PATH,
        "digest_relative_path": DIGEST_RELATIVE_PATH,
        "exact_inventory": True,
        "mixed_generation_forbidden": True,
        "unexpected_files_forbidden": True,
    }:
        fail("Ghidra specification package policy is invalid")
    if contract["materialization"] != {
        "hash_algorithm": "sha256",
        "copy_mode": "atomic",
        "reparse_points_forbidden": True,
        "verify_after_copy": True,
        "network_fetch_forbidden": True,
    }:
        fail("Ghidra specification materialization policy is invalid")
    return contract, digest


def under_root(path, root, label):
    resolved = path.resolve(strict=True)
    try:
        resolved.relative_to(root)
    except ValueError:
        fail(label + " is outside its approved root")
    reject_reparse(resolved, label)
    return resolved


def enumerate_files(root, label):
    files = []
    for candidate in root.rglob("*"):
        reject_reparse(candidate, label)
        if candidate.is_dir():
            continue
        if not candidate.is_file():
            fail(label + " contains a non-file entry")
        files.append(candidate.relative_to(root).as_posix())
    return sorted(files, key=lambda value: value.encode("utf-8"))


def validate_spec_data(name, kind, data):
    if kind == "sla":
        if len(data) < 16 or data.lstrip().startswith(b"<"):
            fail("compiled Ghidra SLA is malformed: " + name)
        return
    try:
        text = data.decode("utf-8-sig", errors="strict").lstrip()
    except UnicodeError as error:
        fail("Ghidra XML specification is not valid UTF-8: " + name + ": " + str(error))
    if not text.startswith("<"):
        fail("Ghidra XML specification is malformed: " + name)


def materialize(arguments):
    if os.name != "nt":
        fail("Ghidra specification materialization is Windows-only")
    repository_root = Path(arguments.repository_root).resolve(strict=True)
    package_root = Path(arguments.package_root).resolve(strict=True)
    input_root = Path(arguments.approved_input_root).resolve(strict=True)
    generator_root = Path(arguments.approved_generator_root).resolve(strict=True)
    for root, label in ((repository_root, "repository root"), (package_root, "package root"),
                        (input_root, "approved Ghidra input root"),
                        (generator_root, "approved Ghidra generator root")):
        if not root.is_dir():
            fail(label + " is not an existing directory")
        reject_reparse(root, label)
    contract_path = under_root(Path(arguments.contract), repository_root, "Ghidra specification source contract")
    _, contract_sha256 = read_contract(contract_path)
    generator = under_root(Path(arguments.generator), generator_root, "Ghidra specification generator")
    _, _, generator_sha256 = read_locked(generator, "Ghidra specification generator", 512 * 1024 * 1024)
    if len(arguments.input) != len(EXPECTED_SPECS):
        fail("Ghidra specification command input count is invalid")
    supplied = {}
    for raw in arguments.input:
        path = under_root(Path(raw), input_root, "Ghidra specification input")
        if path.parent != input_root:
            fail("Ghidra specification input must be a direct child of the approved root")
        folded = path.name.casefold()
        if folded in supplied:
            fail("Ghidra specification input is duplicated")
        supplied[folded] = path
    expected_names = [name for name, _ in EXPECTED_SPECS]
    if sorted(supplied) != sorted(name.casefold() for name in expected_names):
        fail("Ghidra specification command inputs are incomplete or unexpected")
    actual_input_files = enumerate_files(input_root, "approved Ghidra input root")
    if actual_input_files != sorted(expected_names, key=lambda value: value.encode("utf-8")):
        fail("approved Ghidra input root contains an incomplete or unexpected inventory")
    source_records = []
    source_data = {}
    for name, kind in EXPECTED_SPECS:
        data, size, digest = read_locked(supplied[name.casefold()], "Ghidra specification input")
        validate_spec_data(name, kind, data)
        source_data[name] = data
        source_records.append({"name": name, "kind": kind, "size_bytes": size, "sha256": digest})
    expected_mirror_files = sorted(expected_names, key=lambda value: value.encode("utf-8"))
    for mirror_relative in MIRRORS:
        mirror = safe_join(package_root, mirror_relative, "Ghidra specification mirror")
        if mirror.exists():
            extras = sorted(set(enumerate_files(mirror, "Ghidra specification mirror")) - set(expected_names))
            if extras:
                fail("Ghidra specification mirror contains an unexpected file: " + extras[0])
        for record in source_records:
            destination = safe_join(mirror, record["name"], "Ghidra specification destination")
            if not arguments.verify_only:
                atomic_write(destination, source_data[record["name"]])
            data, size, digest = read_locked(destination, "Ghidra specification destination")
            if size != record["size_bytes"] or not secrets.compare_digest(digest, record["sha256"]) or not secrets.compare_digest(data, source_data[record["name"]]):
                fail("Ghidra specification mirror contains a mixed generation")
        if enumerate_files(mirror, "Ghidra specification mirror") != expected_mirror_files:
            fail("Ghidra specification mirror exact inventory is invalid")
    canonical_rows = "".join(f"{record['name']}\t{record['kind']}\t{record['size_bytes']}\t{record['sha256']}\n"
                             for record in source_records)
    inventory_sha256 = hashlib.sha256(canonical_rows.encode("utf-8")).hexdigest()
    generation_material = ("aida.c03.ghidra-spec-generation.v1\n" + contract_sha256 + "\n" +
                           generator_sha256 + "\n" + inventory_sha256 + "\n").encode("ascii")
    generation_id = hashlib.sha256(generation_material).hexdigest()
    manifest = {
        "schema": "aida.c03.ghidra-spec-manifest",
        "schema_version": 1,
        "source_contract_sha256": contract_sha256,
        "producer": {
            "id": "ghidra_sleigh_compiler",
            "executable_sha256": generator_sha256,
            "approved_input_root": True,
            "approved_generator_root": True,
        },
        "specifications": {
            "file_count": len(source_records),
            "mirrors": list(MIRRORS),
            "exact_inventory": True,
            "generation_id": generation_id,
            "canonical_inventory_sha256": inventory_sha256,
            "files": source_records,
        },
    }
    manifest_bytes = canonical_json(manifest)
    manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
    digest_bytes = (manifest_sha256 + "\n").encode("ascii")
    manifest_path = safe_join(package_root, MANIFEST_RELATIVE_PATH, "Ghidra specification manifest")
    digest_path = safe_join(package_root, DIGEST_RELATIVE_PATH, "Ghidra specification manifest digest")
    if not arguments.verify_only:
        atomic_write(manifest_path, manifest_bytes)
        atomic_write(digest_path, digest_bytes)
    actual_manifest, _, actual_manifest_sha256 = read_locked(manifest_path, "Ghidra specification manifest", 16 * 1024 * 1024)
    actual_digest, _, _ = read_locked(digest_path, "Ghidra specification manifest digest", 256)
    if not secrets.compare_digest(actual_manifest, manifest_bytes) or not secrets.compare_digest(actual_manifest_sha256, manifest_sha256) or not secrets.compare_digest(actual_digest, digest_bytes):
        fail("Ghidra specification manifest verification failed")
    return {
        "file_count": len(source_records),
        "generation_id": generation_id,
        "manifest": MANIFEST_RELATIVE_PATH,
        "manifest_sha256": manifest_sha256,
        "verified": True,
    }


def main():
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--repository-root", required=True)
    parser.add_argument("--package-root", required=True)
    parser.add_argument("--contract", required=True)
    parser.add_argument("--approved-input-root", required=True)
    parser.add_argument("--approved-generator-root", required=True)
    parser.add_argument("--generator", required=True)
    parser.add_argument("--input", action="append", required=True)
    parser.add_argument("--verify-only", action="store_true")
    arguments = parser.parse_args()
    print(json.dumps(materialize(arguments), sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
