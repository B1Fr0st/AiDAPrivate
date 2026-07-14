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
    "schema": "aida.c03.managed-worker-manifest-source",
    "schema_version": 3,
    "artifact": {
        "format": "aida.native-worker-manifest",
        "magic": "NWMF",
        "byte_order": "little-endian",
        "schema_version": 3,
        "relative_path": "deps/AiDA_ManagedDecompilerWorker.manifest.bin",
        "digest_relative_path": "deps/AiDA_ManagedDecompilerWorker.manifest.sha256",
        "digest_format": "lowercase-hex-newline",
    },
    "worker": {
        "relative_path": "deps/AiDA_ManagedDecompilerWorker.exe",
        "provider": {
            "id": 2,
            "name": "ICSharpCode.Decompiler",
            "version": "10.1.0.8386",
            "binary_relative_path": "deps/ICSharpCode.Decompiler.dll",
            "binary_sha256": "bebc24d573164da41b6f43f521d96362516d0f4b5b2715a9e7d877f4b2730345",
            "worker_build_id": "aida-managed-decompiler-worker-v3",
            "worker_build_hash_material": "aida-managed-decompiler-worker-build-v3|snapshot-bound-contract=4fe173593d2e044466706c58b3573ec528930a1762a3177ac53e7b84c166cfa6|tfm=net10.0|runtime=Microsoft.NETCore.App/10.0.9",
        },
        "protocol": {
            "version": 3,
            "hash_material": "aida.isolated-decompiler.worker.frame.v3|bootstrap.v1|hmac-sha256|strict-sequence|readonly-provider-input|attested-provider-artifacts|bounded-native-printc-evidence|control-frame-8m|result-frame-80m|provider-artifacts-48m|printc-8m",
            "contract_hash_material": "aida.c03.managed-cli.contract.v3|readonly-inherited-mapping.v1|source-kind|logical-identity|module-sha256|module-size|entity|generation|type-revision|profile|runtime-manifest|provider|cache|request-binding|exact-response",
        },
        "capabilities": ["decompile"],
        "startup_arguments": [],
        "runtime": {
            "target_framework": "net10.0",
            "framework": "Microsoft.NETCore.App",
            "framework_version": "10.0.9",
            "runtime_identifier": "win-x64",
            "manifest_relative_path": "deps/AiDA_ManagedRuntime.manifest.json",
            "manifest_digest_relative_path": "deps/AiDA_ManagedRuntime.manifest.sha256",
            "dotnet_root_relative_path": "deps/dotnet",
            "machine_runtime_fallback": False,
        },
    },
    "materialization": {
        "worker_binary_hash": "",
        "provider_binary_hash": "bebc24d573164da41b6f43f521d96362516d0f4b5b2715a9e7d877f4b2730345",
        "runtime_manifest_hash": "",
        "manifest_digest": "",
        "input_lock": "deny-write-and-delete-while-hashing",
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
MAX_INPUT_BYTES = 2 * 1024 * 1024 * 1024
MANIFEST_MAGIC = 0x464D574E
MANIFEST_CAPABILITY_DECOMPILE = 1
MAX_STRING_BYTES = 4096


def fail(message):
    raise RuntimeError(message)


def load_contract(path):
    if path.is_symlink() or not path.is_file():
        fail("managed manifest source contract must be a regular non-symlink file")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        fail("managed manifest source contract could not be decoded: " + str(error))
    if value != EXPECTED_CONTRACT:
        fail("managed manifest source contract does not match the canonical contract")
    return value


def relative_path(root, value):
    parsed = PurePosixPath(value)
    if parsed.is_absolute() or not parsed.parts or any(part in ("", ".", "..") for part in parsed.parts):
        fail("managed manifest contains an unsafe relative path")
    candidate = root.joinpath(*parsed.parts)
    resolved_parent = candidate.parent.resolve(strict=True)
    if os.path.commonpath((str(root), str(resolved_parent))) != str(root):
        fail("managed manifest artifact escapes the package root")
    return resolved_parent / candidate.name


class LockedInput:
    def __init__(self, path):
        if os.name != "nt":
            fail("managed worker manifests can only be materialized on Windows")
        self.kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self.kernel32.GetFileAttributesW.argtypes = [ctypes.c_wchar_p]
        self.kernel32.GetFileAttributesW.restype = ctypes.c_uint32
        self.kernel32.CreateFileW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p,
                                              ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p]
        self.kernel32.CreateFileW.restype = ctypes.c_void_p
        self.kernel32.GetFileSizeEx.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_longlong)]
        self.kernel32.GetFileSizeEx.restype = ctypes.c_int
        self.kernel32.ReadFile.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32,
                                           ctypes.POINTER(ctypes.c_uint32), ctypes.c_void_p]
        self.kernel32.ReadFile.restype = ctypes.c_int
        self.kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
        self.kernel32.CloseHandle.restype = ctypes.c_int
        attributes = self.kernel32.GetFileAttributesW(str(path))
        if attributes == INVALID_FILE_ATTRIBUTES or attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT):
            fail("managed manifest input must be a regular non-reparse file")
        self.handle = self.kernel32.CreateFileW(str(path), GENERIC_READ, FILE_SHARE_READ, None, OPEN_EXISTING,
                                                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, None)
        if self.handle == INVALID_HANDLE_VALUE or self.handle is None:
            fail("managed manifest input could not be locked")

    def hash(self):
        size = ctypes.c_longlong()
        if not self.kernel32.GetFileSizeEx(self.handle, ctypes.byref(size)) or size.value <= 0 or size.value > MAX_INPUT_BYTES:
            fail("managed manifest input size is invalid")
        digest = hashlib.sha256()
        remaining = size.value
        buffer = ctypes.create_string_buffer(1024 * 1024)
        while remaining:
            requested = min(remaining, len(buffer))
            received = ctypes.c_uint32()
            if not self.kernel32.ReadFile(self.handle, buffer, requested, ctypes.byref(received), None) or received.value == 0:
                fail("managed manifest input changed while hashing")
            digest.update(buffer.raw[:received.value])
            remaining -= received.value
        return digest.digest()

    def close(self):
        if self.handle not in (None, INVALID_HANDLE_VALUE):
            self.kernel32.CloseHandle(self.handle)
            self.handle = None


def encoded_string(value):
    if not isinstance(value, str) or "\x00" in value:
        fail("managed manifest string is invalid")
    encoded = value.encode("utf-8", errors="strict")
    if not encoded or len(encoded) > MAX_STRING_BYTES:
        fail("managed manifest string violates its size contract")
    return struct.pack("<I", len(encoded)) + encoded


def validate_runtime_manifest(manifest_bytes, digest_bytes):
    if len(manifest_bytes) == 0 or len(manifest_bytes) > 512 * 1024:
        fail("managed runtime manifest size is invalid")
    expected_digest = hashlib.sha256(manifest_bytes).hexdigest()
    try:
        digest_text = digest_bytes.decode("ascii")
    except UnicodeDecodeError:
        fail("managed runtime manifest digest is not ASCII")
    if digest_text != expected_digest + "\n":
        fail("managed runtime manifest digest does not match its exact bytes")
    try:
        value = json.loads(manifest_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail("managed runtime manifest could not be decoded: " + str(error))
    if set(value) != {"schema", "schema_version", "source_contract_sha256", "target_framework", "runtime", "application", "launch", "inventory"} or \
            value["schema"] != "aida.c03.managed-runtime-manifest" or value["schema_version"] != 1 or \
            value["target_framework"] != "net10.0" or \
            not isinstance(value["source_contract_sha256"], str) or \
            len(value["source_contract_sha256"]) != 64 or \
            any(character not in "0123456789abcdef" for character in value["source_contract_sha256"]) or \
            set(value["source_contract_sha256"]) == {"0"}:
        fail("managed runtime manifest header is invalid")
    runtime = value["runtime"]
    application = value["application"]
    launch = value["launch"]
    inventory = value["inventory"]
    if set(runtime) != {"framework", "version", "runtime_identifier", "relative_root", "exact_inventory", "file_count", "total_size_bytes", "canonical_inventory_sha256", "files"} or \
            runtime["framework"] != "Microsoft.NETCore.App" or runtime["version"] != "10.0.9" or \
            runtime["runtime_identifier"] != "win-x64" or runtime["relative_root"] != "deps/dotnet" or \
            runtime["exact_inventory"] is not True or runtime["file_count"] != 193 or \
            runtime["canonical_inventory_sha256"] != "8582bda52b66ad61651a2c9bc2c705cf10b038e374f87662045397c7966b02c9" or \
            not isinstance(runtime["files"], list) or len(runtime["files"]) != 193:
        fail("managed runtime manifest runtime identity is invalid")
    if set(application) != {"exact_inventory", "files"} or application["exact_inventory"] is not True or \
            not isinstance(application["files"], list) or len(application["files"]) != 7:
        fail("managed runtime manifest application identity is invalid")
    if set(launch) != {"executable_relative_path", "hostfxr_relative_path", "dotnet_root_relative_path", "multilevel_lookup", "roll_forward", "roll_forward_to_prerelease", "machine_runtime_fallback"} or \
            launch["executable_relative_path"] != "deps/AiDA_ManagedDecompilerWorker.exe" or \
            launch["hostfxr_relative_path"] != "deps/dotnet/host/fxr/10.0.9/hostfxr.dll" or \
            launch["dotnet_root_relative_path"] != "deps/dotnet" or launch["multilevel_lookup"] is not False or \
            launch["roll_forward"] != "Disable" or launch["roll_forward_to_prerelease"] is not False or \
            launch["machine_runtime_fallback"] is not False:
        fail("managed runtime manifest launch identity is invalid")
    if set(inventory) != {"file_count", "total_size_bytes", "canonical_inventory_sha256"} or inventory["file_count"] != 200:
        fail("managed runtime manifest combined inventory is invalid")
    paths = set()
    runtime_rows = []
    application_rows = []
    roles = {}
    direct_dependencies = set()
    for entry in runtime["files"]:
        if set(entry) != {"relative_path", "size_bytes", "sha256"}:
            fail("managed runtime file record is malformed")
        relative = entry["relative_path"]
        size = entry["size_bytes"]
        sha256 = entry["sha256"]
        if not isinstance(relative, str) or not relative.startswith("deps/dotnet/") or \
                not isinstance(size, int) or isinstance(size, bool) or size <= 0 or \
                not isinstance(sha256, str) or len(sha256) != 64 or any(character not in "0123456789abcdef" for character in sha256) or \
                relative.lower() in paths:
            fail("managed runtime file record is invalid")
        paths.add(relative.lower())
        runtime_rows.append((relative, size, sha256))
    expected_roles = {
        "apphost": "deps/AiDA_ManagedDecompilerWorker.exe",
        "assembly": "deps/AiDA_ManagedDecompilerWorker.dll",
        "deps": "deps/AiDA_ManagedDecompilerWorker.deps.json",
        "runtimeconfig": "deps/AiDA_ManagedDecompilerWorker.runtimeconfig.json",
        "provider": "deps/ICSharpCode.Decompiler.dll",
    }
    for entry in application["files"]:
        if set(entry) != {"role", "relative_path", "size_bytes", "sha256"}:
            fail("managed application file record is malformed")
        role = entry["role"]
        relative = entry["relative_path"]
        size = entry["size_bytes"]
        sha256 = entry["sha256"]
        if not isinstance(role, str) or not isinstance(relative, str) or \
                not isinstance(size, int) or isinstance(size, bool) or size <= 0 or \
                not isinstance(sha256, str) or len(sha256) != 64 or any(character not in "0123456789abcdef" for character in sha256) or \
                relative.lower() in paths:
            fail("managed application file record is invalid")
        paths.add(relative.lower())
        roles[role] = roles.get(role, 0) + 1
        if role == "direct_dependency":
            direct_dependencies.add(relative)
        elif role not in expected_roles or expected_roles[role] != relative:
            fail("managed application role identity is invalid")
        application_rows.append((relative, size, sha256))
    if roles != {"apphost": 1, "assembly": 1, "deps": 1, "runtimeconfig": 1, "provider": 1, "direct_dependency": 2} or \
            direct_dependencies != {"deps/System.Collections.Immutable.dll", "deps/System.Reflection.Metadata.dll"}:
        fail("managed application role inventory is invalid")
    def canonical_hash(rows):
        material = "\n".join("|".join((relative, str(size), sha256)) for relative, size, sha256 in sorted(rows))
        return hashlib.sha256(material.encode("utf-8")).hexdigest()
    runtime_size = sum(row[1] for row in runtime_rows)
    application_size = sum(row[1] for row in application_rows)
    if runtime["total_size_bytes"] != runtime_size or inventory["total_size_bytes"] != runtime_size + application_size or \
            canonical_hash(runtime_rows) != runtime["canonical_inventory_sha256"] or \
            canonical_hash(runtime_rows + application_rows) != inventory["canonical_inventory_sha256"]:
        fail("managed runtime canonical inventory is invalid")
    return bytes.fromhex(expected_digest)


def build_manifest(contract, worker_hash, provider_hash, runtime_manifest_hash):
    worker = contract["worker"]
    provider = worker["provider"]
    protocol = worker["protocol"]
    contract_hash = hashlib.sha256(protocol["contract_hash_material"].encode("utf-8")).hexdigest()
    if provider["worker_build_hash_material"] != "aida-managed-decompiler-worker-build-v3|snapshot-bound-contract=" + contract_hash + "|tfm=net10.0|runtime=Microsoft.NETCore.App/10.0.9":
        fail("managed worker build identity is not bound to the managed protocol contract")
    protocol_hash = hashlib.sha256(protocol["hash_material"].encode("utf-8")).digest()
    build_hash = hashlib.sha256(provider["worker_build_hash_material"].encode("utf-8")).digest()
    fields = [
        struct.pack("<II", MANIFEST_MAGIC, contract["artifact"]["schema_version"]),
        encoded_string(worker["relative_path"]),
        worker_hash,
        struct.pack("<B", provider["id"]),
        encoded_string(provider["name"]),
        encoded_string(provider["version"]),
        provider_hash,
        encoded_string(provider["worker_build_id"]),
        build_hash,
        struct.pack("<I", protocol["version"]),
        protocol_hash,
        struct.pack("<II", MANIFEST_CAPABILITY_DECOMPILE, 0),
        runtime_manifest_hash,
    ]
    return b"".join(fields)


def atomic_write(path, data):
    if path.exists() and path.is_symlink():
        fail("managed manifest output cannot replace a symbolic link")
    temporary = path.with_name(path.name + "." + str(os.getpid()) + "." + secrets.token_hex(8) + ".tmp")
    try:
        descriptor = os.open(str(temporary), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
        try:
            view = memoryview(data)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    fail("managed manifest write made no progress")
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
        fail("managed manifest outputs must not be symbolic links")
    try:
        actual_manifest = manifest_path.read_bytes()
        actual_digest_text = digest_path.read_text(encoding="ascii")
    except (OSError, UnicodeError) as error:
        fail("managed manifest outputs could not be verified: " + str(error))
    if not secrets.compare_digest(actual_manifest, expected_manifest) or not secrets.compare_digest(actual_digest_text, expected_digest_text):
        fail("managed manifest outputs do not match the locked inputs")


def main():
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--contract", required=True)
    parser.add_argument("--package-root", required=True)
    parser.add_argument("--worker", required=True)
    parser.add_argument("--provider", required=True)
    parser.add_argument("--runtime-manifest", required=True)
    parser.add_argument("--runtime-manifest-digest", required=True)
    parser.add_argument("--verify-only", action="store_true")
    arguments = parser.parse_args()
    contract_input = Path(arguments.contract)
    if contract_input.is_symlink():
        fail("managed manifest source contract must not be a symbolic link")
    contract_path = contract_input.resolve(strict=True)
    package_root_input = Path(arguments.package_root)
    if package_root_input.is_symlink():
        fail("managed package root must not be a symbolic link")
    package_root = package_root_input.resolve(strict=True)
    if not package_root.is_dir():
        fail("managed package root must be an existing directory")
    contract = load_contract(contract_path)
    expected_worker_input = relative_path(package_root, contract["worker"]["relative_path"])
    expected_provider_input = relative_path(package_root, contract["worker"]["provider"]["binary_relative_path"])
    expected_runtime_manifest_input = relative_path(package_root, contract["worker"]["runtime"]["manifest_relative_path"])
    expected_runtime_digest_input = relative_path(package_root, contract["worker"]["runtime"]["manifest_digest_relative_path"])
    worker_input = Path(arguments.worker)
    provider_input = Path(arguments.provider)
    runtime_manifest_input = Path(arguments.runtime_manifest)
    runtime_digest_input = Path(arguments.runtime_manifest_digest)
    if expected_worker_input.is_symlink() or expected_provider_input.is_symlink() or \
            expected_runtime_manifest_input.is_symlink() or expected_runtime_digest_input.is_symlink() or \
            worker_input.is_symlink() or provider_input.is_symlink() or \
            runtime_manifest_input.is_symlink() or runtime_digest_input.is_symlink():
        fail("managed worker package inputs must not be symbolic links")
    expected_worker = expected_worker_input.resolve(strict=True)
    expected_provider = expected_provider_input.resolve(strict=True)
    worker_path = worker_input.resolve(strict=True)
    provider_path = provider_input.resolve(strict=True)
    expected_runtime_manifest = expected_runtime_manifest_input.resolve(strict=True)
    expected_runtime_digest = expected_runtime_digest_input.resolve(strict=True)
    runtime_manifest_path = runtime_manifest_input.resolve(strict=True)
    runtime_digest_path = runtime_digest_input.resolve(strict=True)
    if os.path.commonpath((str(package_root), str(expected_worker))) != str(package_root) or \
            os.path.commonpath((str(package_root), str(expected_provider))) != str(package_root) or \
            os.path.commonpath((str(package_root), str(expected_runtime_manifest))) != str(package_root) or \
            os.path.commonpath((str(package_root), str(expected_runtime_digest))) != str(package_root):
        fail("managed worker package input escapes the package root")
    if worker_path != expected_worker or provider_path != expected_provider or \
            runtime_manifest_path != expected_runtime_manifest or runtime_digest_path != expected_runtime_digest:
        fail("managed worker package path does not match the package contract")
    manifest_path = relative_path(package_root, contract["artifact"]["relative_path"])
    digest_path = relative_path(package_root, contract["artifact"]["digest_relative_path"])
    if len({worker_path, provider_path, runtime_manifest_path, runtime_digest_path, manifest_path, digest_path}) != 6:
        fail("managed manifest paths overlap protected inputs")

    worker_lock = LockedInput(expected_worker_input)
    provider_lock = None
    runtime_manifest_lock = None
    runtime_digest_lock = None
    try:
        provider_lock = LockedInput(expected_provider_input)
        runtime_manifest_lock = LockedInput(expected_runtime_manifest_input)
        runtime_digest_lock = LockedInput(expected_runtime_digest_input)
        worker_hash = worker_lock.hash()
        provider_hash = provider_lock.hash()
        if not secrets.compare_digest(provider_hash.hex(), contract["worker"]["provider"]["binary_sha256"]):
            fail("managed provider hash does not match the pinned build input")
        if runtime_manifest_path.stat().st_size > 512 * 1024 or runtime_digest_path.stat().st_size != 65:
            fail("managed runtime manifest package size is invalid")
        runtime_manifest_bytes = runtime_manifest_path.read_bytes()
        runtime_digest_bytes = runtime_digest_path.read_bytes()
        runtime_manifest_hash = validate_runtime_manifest(runtime_manifest_bytes, runtime_digest_bytes)
        if not secrets.compare_digest(runtime_manifest_lock.hash(), runtime_manifest_hash) or \
                not secrets.compare_digest(runtime_digest_lock.hash(), hashlib.sha256(runtime_digest_bytes).digest()):
            fail("managed runtime manifest changed while binding the worker")
        manifest = build_manifest(contract, worker_hash, provider_hash, runtime_manifest_hash)
        manifest_digest = hashlib.sha256(manifest).hexdigest()
        digest_text = manifest_digest + "\n"
        if not arguments.verify_only:
            atomic_write(manifest_path, manifest)
            atomic_write(digest_path, digest_text.encode("ascii"))
        verify_outputs(manifest_path, digest_path, manifest, digest_text)
    finally:
        if runtime_digest_lock is not None:
            runtime_digest_lock.close()
        if runtime_manifest_lock is not None:
            runtime_manifest_lock.close()
        if provider_lock is not None:
            provider_lock.close()
        worker_lock.close()
    print(json.dumps({
        "manifest": contract["artifact"]["relative_path"],
        "manifest_sha256": manifest_digest,
        "provider": contract["worker"]["provider"]["binary_relative_path"],
        "provider_sha256": provider_hash.hex(),
        "runtime_manifest_sha256": runtime_manifest_hash.hex(),
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
