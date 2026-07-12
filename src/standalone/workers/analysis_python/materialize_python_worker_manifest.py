import argparse
import ctypes
import hashlib
import os
import secrets
import struct
import sys
from pathlib import Path


MAGIC = 0x4D575041
SCHEMA_VERSION = 1
RELATIVE_WORKER = "deps/AiDA_AnalysisPythonWorker.exe"
PROTOCOL = "aida.analysis-python.worker.frame.v1|bootstrap.v1|hmac-sha256|strict-sequence|approved-workspace-api"
CAPABILITY_EXECUTE_FILE = 1
MAX_WORKER_BYTES = 2 * 1024 * 1024 * 1024
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
GENERIC_READ = 0x80000000
FILE_SHARE_READ = 0x00000001
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x00000080
FILE_ATTRIBUTE_DIRECTORY = 0x00000010
FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
FILE_FLAG_SEQUENTIAL_SCAN = 0x08000000
INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF


def fail(message):
    raise RuntimeError(message)


def under_root(root, candidate):
    try:
        candidate.relative_to(root)
    except ValueError:
        fail("path escapes package root")


def read_worker_hash(path):
    if os.name != "nt":
        fail("worker manifest materialization requires Windows")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetFileAttributesW.argtypes = [ctypes.c_wchar_p]
    kernel32.GetFileAttributesW.restype = ctypes.c_uint32
    kernel32.CreateFileW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p]
    kernel32.CreateFileW.restype = ctypes.c_void_p
    kernel32.GetFileSizeEx.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_longlong)]
    kernel32.GetFileSizeEx.restype = ctypes.c_int
    kernel32.ReadFile.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32), ctypes.c_void_p]
    kernel32.ReadFile.restype = ctypes.c_int
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = ctypes.c_int
    attributes = kernel32.GetFileAttributesW(str(path))
    if attributes == INVALID_FILE_ATTRIBUTES or attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT):
        fail("worker must be a regular non-reparse file")
    handle = kernel32.CreateFileW(str(path), GENERIC_READ, FILE_SHARE_READ, None, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, None)
    if handle in (None, INVALID_HANDLE_VALUE):
        fail("worker cannot be locked for hashing")
    try:
        size = ctypes.c_longlong()
        if not kernel32.GetFileSizeEx(handle, ctypes.byref(size)) or size.value <= 0 or size.value > MAX_WORKER_BYTES:
            fail("worker size violates manifest policy")
        digest = hashlib.sha256()
        buffer = ctypes.create_string_buffer(1024 * 1024)
        remaining = size.value
        while remaining:
            requested = min(remaining, len(buffer))
            received = ctypes.c_uint32()
            if not kernel32.ReadFile(handle, buffer, requested, ctypes.byref(received), None) or received.value == 0:
                fail("worker changed while hashing")
            digest.update(buffer.raw[:received.value])
            remaining -= received.value
        return digest.digest()
    finally:
        kernel32.CloseHandle(handle)


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
                    fail("manifest write made no progress")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def materialize(root, worker, manifest, digest_path):
    if "camoufox" in str(worker).lower():
        fail("analysis Python worker cannot use a browser runtime")
    expected_worker = (root / "deps" / "AiDA_AnalysisPythonWorker.exe").resolve(strict=True)
    if worker != expected_worker:
        fail("worker path does not match the fixed package location")
    for value in (manifest, digest_path):
        under_root(root, value.parent.resolve(strict=True))
        if value.name in ("", ".", ".."):
            fail("manifest output path is invalid")
    worker_hash = read_worker_hash(worker)
    path_bytes = RELATIVE_WORKER.encode("utf-8")
    payload = struct.pack("<III", MAGIC, SCHEMA_VERSION, len(path_bytes)) + path_bytes + worker_hash + hashlib.sha256(PROTOCOL.encode("utf-8")).digest() + struct.pack("<I", CAPABILITY_EXECUTE_FILE)
    manifest_hash = hashlib.sha256(payload).hexdigest()
    atomic_write(manifest, payload)
    atomic_write(digest_path, (manifest_hash + "\n").encode("ascii"))
    if manifest.read_bytes() != payload or digest_path.read_text(encoding="ascii") != manifest_hash + "\n":
        fail("manifest verification failed")
    print('{"manifest":"%s","manifest_sha256":"%s","worker":"%s","worker_sha256":"%s","verified":true}' % (manifest.relative_to(root).as_posix(), manifest_hash, RELATIVE_WORKER, worker_hash.hex()))


def main():
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--package-root", required=True)
    parser.add_argument("--worker", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--digest", required=True)
    args = parser.parse_args()
    root = Path(args.package_root).resolve(strict=True)
    if not root.is_dir() or root.is_symlink():
        fail("package root must be a regular directory")
    worker = Path(args.worker).resolve(strict=True)
    manifest = Path(args.manifest).resolve(strict=False)
    digest_path = Path(args.digest).resolve(strict=False)
    materialize(root, worker, manifest, digest_path)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
