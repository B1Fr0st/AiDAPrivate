import argparse
import ctypes
import hashlib
import json
import os
import secrets
import sys
from pathlib import Path, PurePosixPath


EXPECTED_INDIVIDUAL_FILES = (
    "dotnet.exe",
    "LICENSE.txt",
    "ThirdPartyNotices.txt",
    "host/fxr/10.0.9/hostfxr.dll",
)
EXPECTED_APPLICATION_FILES = (
    ("apphost", "deps/AiDA_ManagedDecompilerWorker.exe"),
    ("assembly", "deps/AiDA_ManagedDecompilerWorker.dll"),
    ("deps", "deps/AiDA_ManagedDecompilerWorker.deps.json"),
    ("runtimeconfig", "deps/AiDA_ManagedDecompilerWorker.runtimeconfig.json"),
    ("provider", "deps/ICSharpCode.Decompiler.dll"),
    ("direct_dependency", "deps/System.Collections.Immutable.dll"),
    ("direct_dependency", "deps/System.Reflection.Metadata.dll"),
)
EXPECTED_RUNTIME_DIRECTORY = "shared/Microsoft.NETCore.App/10.0.9"
EXPECTED_RUNTIME_FILE_COUNT = 193
EXPECTED_RUNTIME_DIRECTORY_FILE_COUNT = 189
EXPECTED_RUNTIME_BYTES = 80344570
EXPECTED_RUNTIME_INVENTORY_SHA256 = "20687edbe0abc5020387ed0f6bdaef85d4ed91529bc356a99510150032af2fe5"
EXPECTED_PACKAGED_RUNTIME_INVENTORY_SHA256 = "8582bda52b66ad61651a2c9bc2c705cf10b038e374f87662045397c7966b02c9"
EXPECTED_SOURCE_ROOT = ".deps/dotnet-sdk-10.0.301-win-x64"
RUNTIME_RELATIVE_ROOT = "deps/dotnet"
MANIFEST_RELATIVE_PATH = "deps/AiDA_ManagedRuntime.manifest.json"
DIGEST_RELATIVE_PATH = "deps/AiDA_ManagedRuntime.manifest.sha256"
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


def canonical_windows_path_order(value):
    encoded = value.encode("utf-8", errors="strict")
    return value.casefold().encode("utf-8", errors="strict"), encoded


def safe_join(root, relative, label, must_exist=False):
    if not is_safe_relative(relative):
        fail(label + " contains an unsafe relative path")
    candidate = root.joinpath(*PurePosixPath(relative).parts)
    parent = candidate.parent.resolve(strict=must_exist)
    try:
        parent.relative_to(root)
    except ValueError:
        fail(label + " escapes its approved root")
    return parent / candidate.name


def reject_reparse(path, label, include_leaf=True):
    if os.name != "nt":
        fail("managed runtime materialization is Windows-only")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetFileAttributesW.argtypes = [ctypes.c_wchar_p]
    kernel32.GetFileAttributesW.restype = ctypes.c_uint32
    current = path if include_leaf else path.parent
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
    reject_reparse(path, "managed runtime output", include_leaf=False)
    path.parent.mkdir(parents=True, exist_ok=True)
    reject_reparse(path.parent, "managed runtime output directory")
    if path.exists() or path.is_symlink():
        reject_reparse(path, "managed runtime output")
        if not path.is_file():
            fail("managed runtime output is not a regular file")
    temporary = path.with_name(path.name + "." + str(os.getpid()) + "." + secrets.token_hex(8) + ".tmp")
    descriptor = None
    try:
        descriptor = os.open(str(temporary), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                fail("managed runtime output write made no progress")
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


def read_json(path, label):
    data, _, digest = read_locked(path, label, 16 * 1024 * 1024)
    try:
        value = json.loads(data.decode("utf-8", errors="strict"))
    except (UnicodeError, json.JSONDecodeError) as error:
        fail(label + " is malformed: " + str(error))
    return value, digest


def validate_contract(contract):
    if set(contract) != {"schema", "schema_version", "source", "selection", "application", "package", "launch", "materialization"}:
        fail("managed runtime source contract property set is invalid")
    source = contract["source"]
    if source != {
        "repository_relative_root": EXPECTED_SOURCE_ROOT,
        "sdk_version": "10.0.301",
        "sdk_usage": "build_only",
        "runtime_framework": "Microsoft.NETCore.App",
        "runtime_version": "10.0.9",
        "runtime_identifier": "win-x64",
    }:
        fail("managed runtime source identity is invalid")
    selection = contract["selection"]
    if selection != {
        "individual_files": list(EXPECTED_INDIVIDUAL_FILES),
        "directory": EXPECTED_RUNTIME_DIRECTORY,
        "directory_file_count": EXPECTED_RUNTIME_DIRECTORY_FILE_COUNT,
        "file_count": EXPECTED_RUNTIME_FILE_COUNT,
        "total_size_bytes": EXPECTED_RUNTIME_BYTES,
        "canonical_inventory_sha256": EXPECTED_RUNTIME_INVENTORY_SHA256,
        "canonical_inventory_format": "relative-path-tab-size-tab-sha256-newline",
    }:
        fail("managed runtime source selection is invalid")
    expected_application = {
        "target_framework": "net10.0",
        "files": [{"role": role, "relative_path": path} for role, path in EXPECTED_APPLICATION_FILES],
        "exact_inventory": True,
    }
    if contract["application"] != expected_application:
        fail("managed application inventory contract is invalid")
    if contract["package"] != {
        "runtime_relative_root": RUNTIME_RELATIVE_ROOT,
        "manifest_relative_path": MANIFEST_RELATIVE_PATH,
        "digest_relative_path": DIGEST_RELATIVE_PATH,
        "exact_inventory": True,
        "sdk_files_forbidden": True,
        "nuget_packages_forbidden": True,
        "source_files_forbidden": True,
    }:
        fail("managed runtime package policy is invalid")
    if contract["launch"] != {
        "executable_relative_path": "deps/AiDA_ManagedDecompilerWorker.exe",
        "hostfxr_relative_path": "deps/dotnet/host/fxr/10.0.9/hostfxr.dll",
        "dotnet_root_relative_path": RUNTIME_RELATIVE_ROOT,
        "multilevel_lookup": False,
        "roll_forward": "Disable",
        "roll_forward_to_prerelease": False,
        "machine_runtime_fallback": False,
    }:
        fail("managed runtime launch policy is invalid")
    if contract["materialization"] != {
        "hash_algorithm": "sha256",
        "copy_mode": "atomic",
        "reparse_points_forbidden": True,
        "verify_after_copy": True,
        "network_fetch_forbidden": True,
    }:
        fail("managed runtime materialization policy is invalid")


def inventory_sources(source_root):
    selected = []
    for relative in EXPECTED_INDIVIDUAL_FILES:
        selected.append((relative, safe_join(source_root, relative, "managed runtime source", True)))
    directory = safe_join(source_root, EXPECTED_RUNTIME_DIRECTORY, "managed runtime directory", True)
    reject_reparse(directory, "managed runtime directory")
    directory_files = []
    for candidate in directory.rglob("*"):
        reject_reparse(candidate, "managed runtime source")
        if candidate.is_dir():
            continue
        if not candidate.is_file():
            fail("managed runtime source contains a non-file entry")
        relative = candidate.relative_to(source_root).as_posix()
        directory_files.append((relative, candidate))
    directory_files.sort(key=lambda item: canonical_windows_path_order(item[0]))
    if len(directory_files) != EXPECTED_RUNTIME_DIRECTORY_FILE_COUNT:
        fail("managed runtime directory file count does not match the locked source")
    selected.extend(directory_files)
    paths = [relative.casefold() for relative, _ in selected]
    if len(selected) != EXPECTED_RUNTIME_FILE_COUNT or len(set(paths)) != len(paths):
        fail("managed runtime selection is incomplete or duplicated")
    return selected


def canonical_source_inventory(entries):
    rows = [f"{entry['relative_path']}\t{entry['size_bytes']}\t{entry['sha256']}\n" for entry in entries]
    return hashlib.sha256("".join(rows).encode("utf-8")).hexdigest()


def canonical_packaged_inventory(entries):
    ordered = sorted(entries, key=lambda entry: canonical_windows_path_order(entry["relative_path"]))
    material = "\n".join(f"{entry['relative_path']}|{entry['size_bytes']}|{entry['sha256']}"
                         for entry in ordered)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def canonical_complete_inventory(runtime_entries, application_entries):
    return canonical_packaged_inventory(runtime_entries + application_entries)


def validate_runtimeconfig(package_root):
    path = safe_join(package_root, "deps/AiDA_ManagedDecompilerWorker.runtimeconfig.json", "runtimeconfig", True)
    value, _ = read_json(path, "managed worker runtimeconfig")
    options = value.get("runtimeOptions") if isinstance(value, dict) else None
    framework = options.get("framework") if isinstance(options, dict) else None
    if not isinstance(framework, dict) or framework.get("name") != "Microsoft.NETCore.App" or framework.get("version") != "10.0.9":
        fail("managed worker runtimeconfig does not pin Microsoft.NETCore.App 10.0.9")
    if options.get("tfm") != "net10.0" or options.get("rollForward") != "Disable":
        fail("managed worker runtimeconfig does not pin net10.0 with roll-forward disabled")


def enumerate_destination(runtime_root):
    if not runtime_root.exists():
        return []
    reject_reparse(runtime_root, "managed runtime destination")
    entries = []
    for candidate in runtime_root.rglob("*"):
        reject_reparse(candidate, "managed runtime destination")
        if candidate.is_dir():
            continue
        if not candidate.is_file():
            fail("managed runtime destination contains a non-file entry")
        entries.append(candidate.relative_to(runtime_root).as_posix())
    return sorted(entries, key=canonical_windows_path_order)


def materialize(arguments):
    if os.name != "nt":
        fail("managed runtime materialization is Windows-only")
    repository_root = Path(arguments.repository_root).resolve(strict=True)
    package_root = Path(arguments.package_root).resolve(strict=True)
    if not repository_root.is_dir() or not package_root.is_dir():
        fail("repository and package roots must be existing directories")
    reject_reparse(repository_root, "repository root")
    reject_reparse(package_root, "package root")
    contract_path = Path(arguments.contract).resolve(strict=True)
    try:
        contract_path.relative_to(repository_root)
    except ValueError:
        fail("managed runtime source contract is outside the repository root")
    contract, contract_sha256 = read_json(contract_path, "managed runtime source contract")
    validate_contract(contract)
    source_root = safe_join(repository_root, EXPECTED_SOURCE_ROOT, "managed runtime source root", True)
    reject_reparse(source_root, "managed runtime source root")
    runtime_root = safe_join(package_root, RUNTIME_RELATIVE_ROOT, "managed runtime package root")
    source_entries = inventory_sources(source_root)
    expected_paths = [relative for relative, _ in source_entries]
    sorted_expected_paths = sorted(expected_paths, key=canonical_windows_path_order)
    if arguments.verify_only and enumerate_destination(runtime_root) != sorted_expected_paths:
        fail("managed runtime destination exact inventory is invalid")
    if not arguments.verify_only:
        existing = enumerate_destination(runtime_root)
        unexpected = sorted(set(existing) - set(expected_paths))
        if unexpected:
            fail("managed runtime destination contains an unlisted file: " + unexpected[0])
    runtime_entries = []
    for relative, source in source_entries:
        data, size, digest = read_locked(source, "managed runtime source")
        destination = safe_join(runtime_root, relative, "managed runtime destination")
        if not arguments.verify_only:
            atomic_write(destination, data)
        staged_data, staged_size, staged_digest = read_locked(destination, "managed runtime destination")
        if staged_size != size or not secrets.compare_digest(staged_digest, digest) or not secrets.compare_digest(staged_data, data):
            fail("managed runtime destination does not match its locked source")
        runtime_entries.append({"relative_path": RUNTIME_RELATIVE_ROOT + "/" + relative,
                                "size_bytes": size, "sha256": digest})
    if enumerate_destination(runtime_root) != sorted_expected_paths:
        fail("managed runtime destination exact inventory is invalid after materialization")
    runtime_total = sum(entry["size_bytes"] for entry in runtime_entries)
    source_inventory_entries = [
        {"relative_path": relative, "size_bytes": entry["size_bytes"], "sha256": entry["sha256"]}
        for (relative, _), entry in zip(source_entries, runtime_entries)
    ]
    source_inventory = canonical_source_inventory(source_inventory_entries)
    runtime_inventory = canonical_packaged_inventory(runtime_entries)
    if runtime_total != EXPECTED_RUNTIME_BYTES or not secrets.compare_digest(source_inventory, EXPECTED_RUNTIME_INVENTORY_SHA256) or not secrets.compare_digest(runtime_inventory, EXPECTED_PACKAGED_RUNTIME_INVENTORY_SHA256):
        fail("managed runtime source inventory identity does not match the locked contract")
    validate_runtimeconfig(package_root)
    application_entries = []
    for role, relative in EXPECTED_APPLICATION_FILES:
        path = safe_join(package_root, relative, "managed application artifact", True)
        _, size, digest = read_locked(path, "managed application artifact", 2 * 1024 * 1024 * 1024)
        application_entries.append({"role": role, "relative_path": relative, "size_bytes": size, "sha256": digest})
    total_size = runtime_total + sum(entry["size_bytes"] for entry in application_entries)
    manifest = {
        "schema": "aida.c03.managed-runtime-manifest",
        "schema_version": 1,
        "source_contract_sha256": contract_sha256,
        "target_framework": "net10.0",
        "runtime": {
            "framework": "Microsoft.NETCore.App",
            "version": "10.0.9",
            "runtime_identifier": "win-x64",
            "relative_root": RUNTIME_RELATIVE_ROOT,
            "exact_inventory": True,
            "file_count": len(runtime_entries),
            "total_size_bytes": runtime_total,
            "canonical_inventory_sha256": runtime_inventory,
            "files": runtime_entries,
        },
        "application": {"exact_inventory": True, "files": application_entries},
        "launch": contract["launch"],
        "inventory": {
            "file_count": len(runtime_entries) + len(application_entries),
            "total_size_bytes": total_size,
            "canonical_inventory_sha256": canonical_complete_inventory(runtime_entries, application_entries),
        },
    }
    manifest_bytes = canonical_json(manifest)
    manifest_digest = hashlib.sha256(manifest_bytes).hexdigest()
    digest_bytes = (manifest_digest + "\n").encode("ascii")
    manifest_path = safe_join(package_root, MANIFEST_RELATIVE_PATH, "managed runtime manifest")
    digest_path = safe_join(package_root, DIGEST_RELATIVE_PATH, "managed runtime manifest digest")
    if not arguments.verify_only:
        atomic_write(manifest_path, manifest_bytes)
        atomic_write(digest_path, digest_bytes)
    actual_manifest, _, actual_manifest_digest = read_locked(manifest_path, "managed runtime manifest", 16 * 1024 * 1024)
    actual_digest, _, _ = read_locked(digest_path, "managed runtime manifest digest", 256)
    if not secrets.compare_digest(actual_manifest, manifest_bytes) or not secrets.compare_digest(actual_manifest_digest, manifest_digest) or not secrets.compare_digest(actual_digest, digest_bytes):
        fail("managed runtime manifest verification failed")
    return {
        "application_file_count": len(application_entries),
        "manifest": MANIFEST_RELATIVE_PATH,
        "manifest_sha256": manifest_digest,
        "runtime_file_count": len(runtime_entries),
        "runtime_inventory_sha256": runtime_inventory,
        "verified": True,
    }


def main():
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--repository-root", required=True)
    parser.add_argument("--package-root", required=True)
    parser.add_argument("--contract", required=True)
    parser.add_argument("--verify-only", action="store_true")
    arguments = parser.parse_args()
    print(json.dumps(materialize(arguments), sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
