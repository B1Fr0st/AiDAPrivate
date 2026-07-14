import argparse
import ctypes
import hashlib
import json
import os
import secrets
import struct
import sys
from pathlib import Path, PurePosixPath


EXPECTED_CONTRACT = {
    "schema": "aida.c03.native-worker-manifest-source",
    "schema_version": 2,
    "artifact": {
        "format": "aida.native-worker-manifest",
        "magic": "NWMF",
        "byte_order": "little-endian",
        "schema_version": 2,
        "relative_path": "deps/AiDA_NativeDecompilerWorker.manifest.bin",
        "digest_relative_path": "deps/AiDA_NativeDecompilerWorker.manifest.sha256",
        "digest_format": "lowercase-hex-newline",
    },
    "worker": {
        "relative_path": "deps/AiDA_NativeDecompilerWorker.exe",
        "provider": {
            "id": 1,
            "name": "aida-native-decompiler",
            "version": "2",
            "worker_build_id": "aida-native-decompiler-worker-v3",
            "worker_build_hash_material": "aida-native-decompiler-worker-build-v3|bounded-printc-evidence",
        },
        "protocol": {
            "version": 3,
            "hash_material": "aida.isolated-decompiler.worker.frame.v3|bootstrap.v1|hmac-sha256|strict-sequence|readonly-provider-input|attested-provider-artifacts|bounded-native-printc-evidence|control-frame-8m|result-frame-80m|provider-artifacts-48m|printc-8m",
        },
        "capabilities": ["decompile"],
        "startup_arguments": [],
    },
    "materialization": {
        "worker_binary_hash": "",
        "provider_binary_hash": "",
        "manifest_digest": "",
        "worker_lock": "deny-write-and-delete-while-hashing",
        "atomic_write": True,
        "verify_after_write": True,
    },
}

INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
GENERIC_READ = 0x80000000
FILE_SHARE_READ = 0x00000001
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x00000080
FILE_ATTRIBUTE_DIRECTORY = 0x00000010
FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
FILE_FLAG_SEQUENTIAL_SCAN = 0x08000000
INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF
MAX_WORKER_BYTES = 2 * 1024 * 1024 * 1024
MANIFEST_MAGIC = 0x464D574E
MANIFEST_CAPABILITY_DECOMPILE = 1
MAX_STRING_BYTES = 4096
MAX_ARGUMENTS = 32


def fail(message):
    raise RuntimeError(message)


def load_contract(path):
    if path.is_symlink() or not path.is_file():
        fail("manifest source contract must be a regular non-symlink file")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        fail("manifest source contract could not be decoded: " + str(error))
    if value != EXPECTED_CONTRACT:
        fail("manifest source contract does not match the canonical native worker contract")
    return value


def relative_path(root, value):
    parsed = PurePosixPath(value)
    if parsed.is_absolute() or not parsed.parts or any(part in ("", ".", "..") for part in parsed.parts):
        fail("manifest contract contains an unsafe relative path")
    candidate = root.joinpath(*parsed.parts)
    resolved_parent = candidate.parent.resolve(strict=True)
    if os.path.commonpath((str(root), str(resolved_parent))) != str(root):
        fail("manifest artifact path escapes the package root")
    return resolved_parent / candidate.name


def with_locked_worker(path, operation):
    if os.name != "nt":
        fail("native worker manifests can only be materialized on Windows")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetFileAttributesW.argtypes = [ctypes.c_wchar_p]
    kernel32.GetFileAttributesW.restype = ctypes.c_uint32
    kernel32.CreateFileW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p,
                                     ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p]
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
        fail("staged native worker must be a regular non-reparse file")
    handle = kernel32.CreateFileW(str(path), GENERIC_READ, FILE_SHARE_READ, None, OPEN_EXISTING,
                                  FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, None)
    if handle == INVALID_HANDLE_VALUE or handle is None:
        fail("staged native worker could not be locked for hashing")
    try:
        size = ctypes.c_longlong()
        if not kernel32.GetFileSizeEx(handle, ctypes.byref(size)) or size.value <= 0 or size.value > MAX_WORKER_BYTES:
            fail("staged native worker size violates the manifest contract")
        digest = hashlib.sha256()
        remaining = size.value
        buffer = ctypes.create_string_buffer(1024 * 1024)
        while remaining:
            requested = min(remaining, len(buffer))
            received = ctypes.c_uint32()
            if not kernel32.ReadFile(handle, buffer, requested, ctypes.byref(received), None) or received.value == 0:
                fail("staged native worker changed or became unreadable while hashing")
            digest.update(buffer.raw[:received.value])
            remaining -= received.value
        return operation(digest.digest())
    finally:
        kernel32.CloseHandle(handle)


def encoded_string(value):
    if not isinstance(value, str) or "\x00" in value:
        fail("manifest string is invalid")
    encoded = value.encode("utf-8", errors="strict")
    if not encoded or len(encoded) > MAX_STRING_BYTES:
        fail("manifest string violates its size contract")
    return struct.pack("<I", len(encoded)) + encoded


def build_manifest(contract, worker_hash):
    worker = contract["worker"]
    provider = worker["provider"]
    protocol = worker["protocol"]
    arguments = worker["startup_arguments"]
    if len(worker_hash) != 32 or len(arguments) > MAX_ARGUMENTS:
        fail("manifest binary inputs are invalid")
    protocol_hash = hashlib.sha256(protocol["hash_material"].encode("utf-8")).digest()
    build_hash = hashlib.sha256(provider["worker_build_hash_material"].encode("utf-8")).digest()
    fields = [
        struct.pack("<II", MANIFEST_MAGIC, contract["artifact"]["schema_version"]),
        encoded_string(worker["relative_path"]),
        worker_hash,
        struct.pack("<B", provider["id"]),
        encoded_string(provider["name"]),
        encoded_string(provider["version"]),
        worker_hash,
        encoded_string(provider["worker_build_id"]),
        build_hash,
        struct.pack("<I", protocol["version"]),
        protocol_hash,
        struct.pack("<II", MANIFEST_CAPABILITY_DECOMPILE, len(arguments)),
    ]
    fields.extend(encoded_string(argument) for argument in arguments)
    return b"".join(fields)


def atomic_write(path, data):
    if path.exists() and path.is_symlink():
        fail("manifest output cannot replace a symbolic link")
    temporary = path.with_name(path.name + "." + str(os.getpid()) + "." + secrets.token_hex(8) + ".tmp")
    try:
        descriptor = os.open(str(temporary), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
        try:
            view = memoryview(data)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    fail("manifest output write made no progress")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def verify_outputs(manifest_path, digest_path, expected_manifest, expected_digest_text):
    if manifest_path.is_symlink() or digest_path.is_symlink():
        fail("manifest outputs must not be symbolic links")
    try:
        actual_manifest = manifest_path.read_bytes()
        actual_digest_text = digest_path.read_text(encoding="ascii")
    except (OSError, UnicodeError) as error:
        fail("manifest outputs could not be verified: " + str(error))
    if not secrets.compare_digest(actual_manifest, expected_manifest):
        fail("emitted native worker manifest does not match the locked worker")
    if not secrets.compare_digest(actual_digest_text, expected_digest_text):
        fail("emitted native worker manifest digest does not match the manifest")


def main():
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--contract", required=True)
    parser.add_argument("--package-root", required=True)
    parser.add_argument("--worker", required=True)
    parser.add_argument("--verify-only", action="store_true")
    arguments = parser.parse_args()
    contract_input = Path(arguments.contract)
    if contract_input.is_symlink():
        fail("manifest source contract must not be a symbolic link")
    contract_path = contract_input.resolve(strict=True)
    package_root_input = Path(arguments.package_root)
    if package_root_input.is_symlink():
        fail("package root must not be a symbolic link")
    package_root = package_root_input.resolve(strict=True)
    if not package_root.is_dir():
        fail("package root must be an existing directory")
    contract = load_contract(contract_path)
    expected_worker_path = relative_path(package_root, contract["worker"]["relative_path"])
    if expected_worker_path.is_symlink():
        fail("staged native worker must not be a symbolic link")
    expected_worker_resolved = expected_worker_path.resolve(strict=True)
    if os.path.commonpath((str(package_root), str(expected_worker_resolved))) != str(package_root):
        fail("staged native worker escapes the package root")
    worker_path = Path(arguments.worker).resolve(strict=True)
    if worker_path != expected_worker_resolved:
        fail("worker path does not match the package manifest contract")
    manifest_path = relative_path(package_root, contract["artifact"]["relative_path"])
    digest_path = relative_path(package_root, contract["artifact"]["digest_relative_path"])
    if manifest_path == digest_path or worker_path in (manifest_path, digest_path):
        fail("manifest output paths overlap protected inputs")

    def materialize(worker_hash):
        manifest = build_manifest(contract, worker_hash)
        manifest_digest = hashlib.sha256(manifest).hexdigest()
        digest_text = manifest_digest + "\n"
        if not arguments.verify_only:
            atomic_write(manifest_path, manifest)
            atomic_write(digest_path, digest_text.encode("ascii"))
        verify_outputs(manifest_path, digest_path, manifest, digest_text)
        return worker_hash, manifest_digest

    worker_hash, manifest_digest = with_locked_worker(worker_path, materialize)
    print(json.dumps({
        "manifest": contract["artifact"]["relative_path"],
        "manifest_sha256": manifest_digest,
        "worker": contract["worker"]["relative_path"],
        "worker_sha256": worker_hash.hex(),
        "verified": True,
    }, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
