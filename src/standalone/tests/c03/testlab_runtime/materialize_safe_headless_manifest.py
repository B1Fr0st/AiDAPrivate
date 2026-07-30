import argparse
import hashlib
import json
import os
import pathlib
import re
import stat
import tempfile


MANIFEST_SCHEMA = "aida.c03.safe-headless.manifest.v2"
INVENTORY_SCHEMA = "aida.c03.safe-headless.inventory.v1"
TARGET_SCHEMA = "aida.c03.safe-headless.target-records.v2"
RESOURCE_POLICY_CASES_SCHEMA = "aida.c03.safe-headless.target-resource-policy-cases.v1"
RESULT_SCHEMA = "aida.c03.safe-headless.result.v1"
MANIFEST_VERSION = 2
TARGET_VERSION = 2
INVENTORY_VERSION = 1
QUALITY_ENTRY_ID = "decompiler.quality_scorer"
QUALITY_SOURCE_TARGET = "aida_c03_a06_decompiler_quality_scorer_harness"
DEFAULT_ACTIVE_PROCESSES = 1
QUALITY_ACTIVE_PROCESSES = 4
DEFAULT_WALL_MS = 120000
QUALITY_WALL_MS = 1800000
RESOURCE_POLICY_CASES_VERSION = 1
EXPECTED_RESOURCE_POLICY_CASES = {
    "ordinary-default": ("fixture.materializer", "aida_c03_a06_fixture_materializer_harness", 1, 120000, True),
    "quality-approved": (QUALITY_ENTRY_ID, QUALITY_SOURCE_TARGET, 4, 1800000, True),
    "zero-process": ("fixture.materializer", "aida_c03_a06_fixture_materializer_harness", 0, 120000, False),
    "over-process": (QUALITY_ENTRY_ID, QUALITY_SOURCE_TARGET, 5, 1800000, False),
    "unauthorized-multi-process": ("fixture.materializer", "aida_c03_a06_fixture_materializer_harness", 4, 120000, False),
    "unauthorized-wall-override": ("fixture.materializer", "aida_c03_a06_fixture_materializer_harness", 1, 1800000, False),
    "quality-noncanonical-process": (QUALITY_ENTRY_ID, QUALITY_SOURCE_TARGET, 3, 1800000, False),
    "quality-noncanonical-wall": (QUALITY_ENTRY_ID, QUALITY_SOURCE_TARGET, 4, 120000, False),
    "under-wall-bound": ("fixture.materializer", "aida_c03_a06_fixture_materializer_harness", 1, 99, False),
    "over-wall-bound": (QUALITY_ENTRY_ID, QUALITY_SOURCE_TARGET, 4, 1800001, False),
}
ALLOWED_CATEGORIES = {
    "contract", "fixture", "provider", "layout", "store", "scheduler",
    "reader", "container", "decode", "recovery", "query", "persistence", "decompiler",
    "worker", "mcp", "workbench", "performance", "surface", "security",
}
REQUIRED_REQUIREMENTS = (
    {"SURF-01", "SEC-01", "DEP-02", "VER-02"}
    | {f"PERF-{index:02d}" for index in range(1, 11)}
    | {f"FMT-{index:02d}" for index in range(1, 4)}
    | {f"ARCH-{index:02d}" for index in range(1, 3)}
    | {f"REC-{index:02d}" for index in range(1, 3)}
    | {f"DEC-{index:02d}" for index in range(1, 11)}
    | {f"MCP-{index:02d}" for index in range(1, 11)}
    | {f"WB-{index:02d}" for index in range(1, 6)}
    | {f"OVL-{index:02d}" for index in range(1, 4)}
    | {f"LIVE-{index:02d}" for index in range(1, 4)}
    | {f"HAR-{index:02d}" for index in range(1, 4)}
)
UNSAFE_FLAGS = {
    "requires_driver",
    "requires_network",
    "launches_application",
    "launches_bootstrap",
    "performs_packaging",
    "performs_deployment",
    "performs_live_operation",
    "performs_debugger_operation",
    "executes_target_artifact",
    "mutates_source_or_repository",
}


def fail(message):
    raise RuntimeError(message)


def load_json(path):
    if not path.is_file() or reparse_path(path) or path.stat().st_size == 0 or path.stat().st_size > 8 * 1024 * 1024:
        fail(f"JSON input is missing, unsafe, or oversized: {path}")
    require_non_reparse_chain(path.absolute())
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def exact_keys(value, keys, label):
    if not isinstance(value, dict) or set(value) != set(keys):
        fail(f"{label} fields are invalid")


def unsigned_between(value, minimum, maximum):
    return isinstance(value, int) and not isinstance(value, bool) and minimum <= value <= maximum


def ascii_identity(value, maximum):
    return isinstance(value, str) and 0 < len(value) <= maximum and re.fullmatch(r"[A-Za-z0-9_.-]+", value) is not None


def requirement_identity(value):
    return isinstance(value, str) and 4 <= len(value) <= 48 and re.fullmatch(r"[A-Z]+-[0-9]+", value) is not None


def target_resource_policy_accepts(entry_id, source_target, active_processes, wall_ms):
    approved_quality = entry_id == QUALITY_ENTRY_ID and source_target == QUALITY_SOURCE_TARGET
    return active_processes == (QUALITY_ACTIVE_PROCESSES if approved_quality else DEFAULT_ACTIVE_PROCESSES) and wall_ms == (QUALITY_WALL_MS if approved_quality else DEFAULT_WALL_MS)


def validate_resource_policy_cases(path):
    document = load_json(path)
    exact_keys(document, {"schema", "version", "cases"}, "resource policy cases")
    if document["schema"] != RESOURCE_POLICY_CASES_SCHEMA or document["version"] != RESOURCE_POLICY_CASES_VERSION:
        fail("resource policy case schema or version is invalid")
    cases = document["cases"]
    if not isinstance(cases, list) or len(cases) != len(EXPECTED_RESOURCE_POLICY_CASES):
        fail("resource policy case cardinality is invalid")
    observed = set()
    for case in cases:
        exact_keys(case, {"id", "entry_id", "source_target", "max_active_processes", "max_wall_ms", "accepted"}, "resource policy case")
        identity = case["id"]
        if not ascii_identity(identity, 96) or identity in observed or identity not in EXPECTED_RESOURCE_POLICY_CASES:
            fail("resource policy case identity is invalid or duplicated")
        observed.add(identity)
        actual = (case["entry_id"], case["source_target"], case["max_active_processes"], case["max_wall_ms"], case["accepted"])
        if actual != EXPECTED_RESOURCE_POLICY_CASES[identity]:
            fail(f"resource policy case payload is noncanonical: {identity}")
        if not ascii_identity(case["entry_id"], 96) or not ascii_identity(case["source_target"], 160):
            fail(f"resource policy case target identity is invalid: {identity}")
        if not unsigned_between(case["max_active_processes"], 0, 0xffffffff) or not unsigned_between(case["max_wall_ms"], 0, 0xffffffff) or not isinstance(case["accepted"], bool):
            fail(f"resource policy case value is invalid: {identity}")
        accepted = target_resource_policy_accepts(case["entry_id"], case["source_target"], case["max_active_processes"], case["max_wall_ms"])
        if accepted is not case["accepted"]:
            fail(f"resource policy case disposition is invalid: {identity}")
    if observed != set(EXPECTED_RESOURCE_POLICY_CASES):
        fail("resource policy case inventory is incomplete")


def sha256_identity(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def digest_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        before = os.fstat(handle.fileno())
        while True:
            block = handle.read(1024 * 1024)
            if not block:
                break
            digest.update(block)
        after = os.fstat(handle.fileno())
    identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    if identity != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
        fail(f"file identity changed while hashing: {path}")
    path_identity = path.stat()
    if identity != (path_identity.st_dev, path_identity.st_ino, path_identity.st_size, path_identity.st_mtime_ns):
        fail(f"file path identity changed while hashing: {path}")
    return digest.hexdigest(), before.st_size


def safe_relative(value, executable=False):
    if not isinstance(value, str) or not value or "\0" in value or "\\" in value:
        return False
    if value == ".":
        return not executable
    path = pathlib.PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        return False
    for part in path.parts:
        if part[-1] in {".", " "} or any(ord(character) < 32 or character in ':"<>|?*' for character in part):
            return False
        stem = part.split(".", 1)[0].lower()
        if stem in {"con", "prn", "aux", "nul"} or (len(stem) == 4 and stem[:3] in {"com", "lpt"} and stem[3] in "123456789"):
            return False
    return not executable or path.suffix.lower() == ".exe"


def reparse_path(path):
    try:
        attributes = os.lstat(path).st_file_attributes
    except AttributeError:
        return path.is_symlink()
    return bool(attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT)


def require_non_reparse_chain(path):
    for component in (path, *path.parents):
        if component.exists() and reparse_path(component):
            fail(f"path contains a reparse component: {path}")


def rooted_path(root, relative, expected_directory):
    if not safe_relative(relative, relative.lower().endswith(".exe")):
        fail(f"unsafe relative path: {relative}")
    candidate = root.joinpath(*pathlib.PurePosixPath(relative).parts)
    current = root
    for part in pathlib.PurePosixPath(relative).parts:
        current = current / part
        if current.exists() and reparse_path(current):
            fail(f"reparse or symlink component is forbidden: {relative}")
    if not candidate.exists() or reparse_path(candidate):
        fail(f"target path is missing or unsafe: {relative}")
    if expected_directory and not candidate.is_dir():
        fail(f"target working directory is not a directory: {relative}")
    if not expected_directory and not candidate.is_file():
        fail(f"target executable is not a regular file: {relative}")
    resolved = candidate.resolve(strict=True)
    try:
        resolved.relative_to(root)
    except ValueError:
        fail(f"target path escapes the approved root: {relative}")
    return candidate


def canonical_bytes(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def atomic_write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def main():
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--inventory", required=True, type=pathlib.Path)
    parser.add_argument("--target-records", required=True, type=pathlib.Path)
    parser.add_argument("--policy-cases", required=True, type=pathlib.Path)
    parser.add_argument("--approved-root", required=True, type=pathlib.Path)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    parser.add_argument("--digest", required=False, type=pathlib.Path, default=None)
    parser.add_argument("--build-identity", required=True)
    parser.add_argument("--contract-identity", required=True)
    args = parser.parse_args()
    if not sha256_identity(args.build_identity) or not sha256_identity(args.contract_identity):
        fail("build and contract identities must be SHA-256 values")
    validate_resource_policy_cases(args.policy_cases)
    requested_root = args.approved_root.absolute()
    if not requested_root.is_dir() or reparse_path(requested_root):
        fail("approved root is not a regular non-reparse directory")
    require_non_reparse_chain(requested_root)
    root = requested_root.resolve(strict=True)
    output = args.output.absolute()
    if output.name != "manifest.json" or output.parent.resolve(strict=True) != root:
        fail("manifest output must use the canonical name directly under the approved root")
    if args.digest is not None:
        digest_output = args.digest.absolute()
        if digest_output.name != "manifest.sha256" or digest_output.parent.resolve(strict=True) != root:
            fail("manifest digest output must use the canonical name directly under the approved root")
    inventory = load_json(args.inventory)
    records = load_json(args.target_records)
    exact_keys(inventory, {"schema", "version", "defaults", "entries"}, "inventory")
    exact_keys(records, {"schema", "version", "targets"}, "target records")
    if inventory["schema"] != INVENTORY_SCHEMA or inventory["version"] != INVENTORY_VERSION:
        fail("inventory schema or version is invalid")
    if records["schema"] != TARGET_SCHEMA or records["version"] != TARGET_VERSION:
        fail("target-record schema or version is invalid")
    exact_keys(inventory["defaults"], {"max_wall_ms", "max_private_bytes", "max_stdout_bytes", "max_stderr_bytes", "max_result_bytes", "safety"}, "inventory defaults")
    defaults = inventory["defaults"]
    if not unsigned_between(defaults["max_wall_ms"], 100, 30 * 60 * 1000):
        fail("inventory wall limit is invalid")
    if defaults["max_wall_ms"] != DEFAULT_WALL_MS:
        fail("inventory default wall limit is not canonical")
    if not unsigned_between(defaults["max_private_bytes"], 16 * 1024 * 1024, 8 * 1024 * 1024 * 1024):
        fail("inventory private-byte limit is invalid")
    if not unsigned_between(defaults["max_stdout_bytes"], 1, 4 * 1024 * 1024) or not unsigned_between(defaults["max_stderr_bytes"], 1, 4 * 1024 * 1024) or not unsigned_between(defaults["max_result_bytes"], 1, 1024 * 1024):
        fail("inventory capture limit is invalid")
    safety = defaults["safety"]
    exact_keys(safety, {"safe_headless"} | UNSAFE_FLAGS, "safety")
    if safety["safe_headless"] is not True or any(safety[name] is not False for name in UNSAFE_FLAGS):
        fail("inventory violates the safe-headless policy")
    if not isinstance(inventory["entries"], list) or not 1 <= len(inventory["entries"]) <= 512:
        fail("inventory entry cardinality is invalid")
    if not isinstance(records["targets"], list) or len(records["targets"]) != len(inventory["entries"]):
        fail("target-record cardinality is invalid")
    by_target = {}
    for record in records["targets"]:
        exact_keys(record, {"source_target", "executable_relative_path", "working_directory_relative_path", "arguments", "source_files", "runtime_files", "max_active_processes", "max_wall_ms"}, "target record")
        target = record["source_target"]
        if not ascii_identity(target, 160) or not isinstance(record["executable_relative_path"], str) or not isinstance(record["working_directory_relative_path"], str) or target in by_target:
            fail(f"duplicate target record: {target}")
        if not unsigned_between(record["max_active_processes"], DEFAULT_ACTIVE_PROCESSES, QUALITY_ACTIVE_PROCESSES) or not unsigned_between(record["max_wall_ms"], 100, QUALITY_WALL_MS):
            fail(f"target resource bounds are invalid: {target}")
        by_target[target] = record
    entries = []
    ids = set()
    executables = set()
    inventory_targets = set()
    covered_categories = set()
    covered_requirements = set()
    for contract in inventory["entries"]:
        exact_keys(contract, {"id", "category", "requirement_ids", "source_target"}, "inventory entry")
        target = contract["source_target"]
        requirements = contract["requirement_ids"]
        if not ascii_identity(contract["id"], 96) or contract["category"] not in ALLOWED_CATEGORIES:
            fail("inventory entry identity or category is invalid")
        if not isinstance(requirements, list) or not 1 <= len(requirements) <= 128 or not all(requirement_identity(value) for value in requirements) or len(set(requirements)) != len(requirements):
            fail(f"inventory requirements are invalid: {contract['id']}")
        if contract["id"] in ids or target in inventory_targets:
            fail("inventory contains a duplicate id or target")
        ids.add(contract["id"])
        inventory_targets.add(target)
        covered_categories.add(contract["category"])
        covered_requirements.update(requirements)
        if target not in by_target:
            fail(f"target remains unregistered: {target}")
        record = by_target[target]
        if not target_resource_policy_accepts(contract["id"], target,
                record["max_active_processes"], record["max_wall_ms"]):
            fail(f"target resource contract is unauthorized: {target}")
        executable_relative = record["executable_relative_path"]
        if executable_relative in executables:
            fail(f"duplicate executable ownership: {executable_relative}")
        executables.add(executable_relative)
        executable = rooted_path(root, executable_relative, False)
        rooted_path(root, record["working_directory_relative_path"], True)
        source_files = record["source_files"]
        if not isinstance(source_files, list) or not 1 <= len(source_files) <= 1024 or not all(isinstance(value, str) and value != "." and safe_relative(value) for value in source_files) or len(set(source_files)) != len(source_files):
            fail(f"target source ownership is invalid: {target}")
        arguments = record["arguments"]
        if not isinstance(arguments, list) or sum(len(value) for value in arguments if isinstance(value, str)) > 16384 or not all(isinstance(value, str) and value and len(value) <= 16384 and "\0" not in value and "\r" not in value and "\n" not in value and not value.startswith("--aida-c03-") for value in arguments):
            fail(f"target arguments are invalid: {target}")
        runtime_paths = record["runtime_files"]
        if not isinstance(runtime_paths, list) or len(runtime_paths) > 512 or not all(isinstance(value, str) and value != "." and safe_relative(value) for value in runtime_paths) or len(set(runtime_paths)) != len(runtime_paths):
            fail(f"target runtime-file inventory is invalid: {target}")
        runtime_files = []
        runtime_size = 0
        for relative in runtime_paths:
            if relative == executable_relative:
                fail(f"target executable is duplicated as a runtime file: {target}")
            runtime_path = rooted_path(root, relative, False)
            runtime_hash, size = digest_file(runtime_path)
            if not 1 <= size <= 512 * 1024 * 1024 or runtime_size > 2 * 1024 * 1024 * 1024 - size:
                fail(f"target runtime-file size budget is invalid: {target}")
            runtime_size += size
            runtime_files.append({"relative_path": relative, "size": size, "sha256": runtime_hash})
        executable_hash, executable_size = digest_file(executable)
        if not 1 <= executable_size <= 512 * 1024 * 1024:
            fail(f"target executable size is invalid: {target}")
        entries.append({
            "id": contract["id"],
            "category": contract["category"],
            "requirement_ids": requirements,
            "source_target": target,
            "source_files": source_files,
            "runtime_files": runtime_files,
            "executable_relative_path": executable_relative,
            "working_directory_relative_path": record["working_directory_relative_path"],
            "arguments": arguments,
            "executable_size": executable_size,
            "executable_sha256": executable_hash,
            "build_identity": args.build_identity,
            "max_active_processes": record["max_active_processes"],
            "max_wall_ms": record["max_wall_ms"],
            "max_private_bytes": defaults["max_private_bytes"],
            "max_stdout_bytes": defaults["max_stdout_bytes"],
            "max_stderr_bytes": defaults["max_stderr_bytes"],
            "max_result_bytes": defaults["max_result_bytes"],
            "expected_result_schema": RESULT_SCHEMA,
            "safety": safety,
        })
    extras = set(by_target) - inventory_targets
    if extras:
        fail("target records contain unowned targets: " + ",".join(sorted(extras)))
    if covered_categories != ALLOWED_CATEGORIES:
        fail("inventory does not cover the complete safe-headless category set")
    if covered_requirements != REQUIRED_REQUIREMENTS:
        fail("inventory does not cover the exact C03 requirement ledger")
    manifest = {
        "schema": MANIFEST_SCHEMA,
        "version": MANIFEST_VERSION,
        "build_identity": args.build_identity,
        "contract_identity": args.contract_identity,
        "entries": entries,
    }
    data = canonical_bytes(manifest)
    atomic_write(output, data)
    if args.digest is not None:
        atomic_write(digest_output, hashlib.sha256(data).hexdigest().encode("ascii") + b"\n")


if __name__ == "__main__":
    main()
