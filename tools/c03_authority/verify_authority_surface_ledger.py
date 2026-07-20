from __future__ import annotations

import argparse
import ast
import ctypes
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any, Iterable


class LedgerError(RuntimeError):
    pass


MAX_ARCHIVE_MEMBERS = 4096
MAX_ARCHIVE_COMPRESSED_BYTES = 128 * 1024 * 1024
MAX_ARCHIVE_UNCOMPRESSED_BYTES = 512 * 1024 * 1024
MAX_ARCHIVE_MEMBER_BYTES = 32 * 1024 * 1024
MAX_COMPRESSION_RATIO = 200
MAX_REACHABILITY_SOURCE_FILES = 4096
MAX_REACHABILITY_SOURCE_BYTES = 512 * 1024 * 1024
MAX_REACHABILITY_FILE_BYTES = 32 * 1024 * 1024


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest().upper()


def sha256_lines(values: Iterable[str]) -> str:
    return hashlib.sha256("\n".join(values).encode("utf-8")).hexdigest().upper()


def read_utf8_source(path: Path) -> str:
    return path.read_bytes().decode("utf-8-sig")


def cpp_matching_index(text: str, start: int, opening: str, closing: str) -> int:
    if start < 0 or start >= len(text) or text[start] != opening:
        raise LedgerError("invalid C++ balanced-range start")
    depth = 0
    for index in range(start, len(text)):
        if text[index] == opening:
            depth += 1
        elif text[index] == closing:
            depth -= 1
            if depth == 0:
                return index
    raise LedgerError(f"unterminated C++ balanced range at offset {start}")


def cpp_digit_separator(source: str, index: int) -> bool:
    if index <= 0 or index + 1 >= len(source) or source[index] != "'":
        return False
    start = index - 1
    while start >= 0 and re.fullmatch(r"[A-Za-z0-9_'.]", source[start]) is not None:
        start -= 1
    prefix = source[start + 1:index]
    previous = source[index - 1]
    following = source[index + 1]
    if re.fullmatch(r"0[xX][0-9A-Fa-f.pP']*", prefix) is not None:
        return (re.fullmatch(r"[0-9A-Fa-f]", previous) is not None and
                re.fullmatch(r"[0-9A-Fa-f]", following) is not None)
    if re.fullmatch(r"0[bB][01']*", prefix) is not None:
        return previous in "01" and following in "01"
    return (re.fullmatch(r"[0-9][0-9.eE']*", prefix) is not None and
            previous in "0123456789" and following in "0123456789")


def cpp_mask_error_context(source: str, index: int, label: str) -> str:
    bounded = max(0, min(index, len(source)))
    byte_offset = len(source[:bounded].encode("utf-8"))
    return (f"source={label!r} line={source_line(source, bounded)} "
            f"character_offset={bounded} byte_offset={byte_offset}")


def cpp_code_mask(source: str, label: str = "<memory>") -> str:
    masked = list(source)
    index = 0
    length = len(source)
    while index < length:
        current = source[index]
        following = source[index + 1] if index + 1 < length else "\0"
        if current == "/" and following == "/":
            while index < length and source[index] not in "\r\n":
                masked[index] = " "
                index += 1
            continue
        if current == "/" and following == "*":
            comment_start = index
            masked[index] = " "
            masked[index + 1] = " "
            index += 2
            closed = False
            while index < length:
                if index + 1 < length and source[index:index + 2] == "*/":
                    masked[index] = " "
                    masked[index + 1] = " "
                    index += 2
                    closed = True
                    break
                if source[index] not in "\r\n":
                    masked[index] = " "
                index += 1
            if not closed:
                raise LedgerError(
                    "unterminated C++ block comment " +
                    cpp_mask_error_context(source, comment_start, label))
            continue
        if current == "R" and following == '"':
            raw_start = index
            delimiter_start = index + 2
            opening = source.find("(", delimiter_start)
            if delimiter_start <= opening <= delimiter_start + 16:
                delimiter = source[delimiter_start:opening]
                if not re.search(r"[\s\\()]", delimiter):
                    terminator = ")" + delimiter + '"'
                    closing = source.find(terminator, opening + 1)
                    if closing < 0:
                        raise LedgerError(
                            "unterminated C++ raw string " +
                            cpp_mask_error_context(source, raw_start, label))
                    end = closing + len(terminator)
                    while index < end:
                        if source[index] not in "\r\n":
                            masked[index] = " "
                        index += 1
                    continue
        if current == "'" and cpp_digit_separator(source, index):
            masked[index] = " "
            index += 1
            continue
        if current in ('"', "'"):
            literal_start = index
            quote = current
            masked[index] = " "
            index += 1
            closed = False
            while index < length:
                literal = source[index]
                if literal == "\\":
                    masked[index] = " "
                    index += 1
                    if index < length:
                        if source[index] not in "\r\n":
                            masked[index] = " "
                        index += 1
                    continue
                if literal not in "\r\n":
                    masked[index] = " "
                index += 1
                if literal == quote:
                    closed = True
                    break
            if not closed:
                raise LedgerError(
                    "unterminated C++ quoted literal " +
                    cpp_mask_error_context(source, literal_start, label))
            continue
        index += 1
    return "".join(masked)


def source_line(source: str, offset: int) -> int:
    return source.count("\n", 0, offset) + 1


def cpp_namespace_ranges(source: str, mask: str) -> list[dict[str, Any]]:
    ranges: list[dict[str, Any]] = []
    pattern = re.compile(r"\bnamespace\s*(?P<name>[A-Za-z_]\w*(?:::[A-Za-z_]\w*)*)?\s*\{")
    for match in pattern.finditer(mask):
        opening = mask.find("{", match.start())
        closing = cpp_matching_index(mask, opening, "{", "}")
        name = match.group("name") or f"<anonymous@{source_line(source, match.start())}>"
        ranges.append({"name": name, "open": opening, "close": closing})
    return ranges


def cpp_namespace_at(ranges: list[dict[str, Any]], offset: int) -> str:
    return "::".join(
        value["name"] for value in sorted(ranges, key=lambda item: item["open"])
        if value_contains(value, offset)
    )


def value_contains(value: dict[str, Any], offset: int) -> bool:
    return int(value["open"]) < offset < int(value["close"])


def cpp_split_top_level(text: str) -> list[str]:
    if not text.strip():
        return []
    output: list[str] = []
    start = 0
    round_depth = 0
    curly_depth = 0
    square_depth = 0
    quote = ""
    escape = False
    for index, character in enumerate(text):
        if quote:
            if escape:
                escape = False
            elif character == "\\":
                escape = True
            elif character == quote:
                quote = ""
            continue
        if character == "'" and cpp_digit_separator(text, index):
            continue
        if character in ('"', "'"):
            quote = character
        elif character == "(":
            round_depth += 1
        elif character == ")":
            round_depth -= 1
        elif character == "{":
            curly_depth += 1
        elif character == "}":
            curly_depth -= 1
        elif character == "[":
            square_depth += 1
        elif character == "]":
            square_depth -= 1
        elif character == "," and round_depth == 0 and curly_depth == 0 and square_depth == 0:
            output.append(text[start:index].strip())
            start = index + 1
    output.append(text[start:].strip())
    return output


def cpp_parameter_has_top_level_default(parameter: str, label: str) -> bool:
    mask = cpp_code_mask(parameter, label)
    round_depth = 0
    curly_depth = 0
    square_depth = 0
    for index, character in enumerate(mask):
        if character == "(":
            round_depth += 1
        elif character == ")":
            round_depth -= 1
            if round_depth < 0:
                raise LedgerError(f"{label} has unbalanced parentheses")
        elif character == "{":
            curly_depth += 1
        elif character == "}":
            curly_depth -= 1
            if curly_depth < 0:
                raise LedgerError(f"{label} has unbalanced braces")
        elif character == "[":
            square_depth += 1
        elif character == "]":
            square_depth -= 1
            if square_depth < 0:
                raise LedgerError(f"{label} has unbalanced brackets")
        elif character == "=" and round_depth == 0 and curly_depth == 0 and square_depth == 0:
            previous = mask[index - 1] if index > 0 else "\0"
            following = mask[index + 1] if index + 1 < len(mask) else "\0"
            if previous not in "=!<>+-*/%&|^" and following != "=":
                return True
    if round_depth != 0 or curly_depth != 0 or square_depth != 0:
        raise LedgerError(f"{label} has unbalanced delimiters")
    return False


def cpp_registrar_definitions(relative: str, source: str, mask: str) -> list[dict[str, Any]]:
    definitions: list[dict[str, Any]] = []
    namespaces = cpp_namespace_ranges(source, mask)
    pattern = re.compile(
        r"(?<![A-Za-z0-9_])(?P<name>(?:[A-Za-z_]\w*::)*register_[A-Za-z0-9_]+)\s*\(")
    for match in pattern.finditer(mask):
        opening = mask.find("(", match.start())
        closing = cpp_matching_index(mask, opening, "(", ")")
        parameters = source[opening + 1:closing]
        cursor = closing + 1
        while cursor < len(mask) and mask[cursor].isspace():
            cursor += 1
        if mask.startswith("noexcept", cursor):
            cursor += len("noexcept")
            while cursor < len(mask) and mask[cursor].isspace():
                cursor += 1
        if cursor >= len(mask) or mask[cursor] != "{":
            continue
        body_end = cpp_matching_index(mask, cursor, "{", "}")
        declared = match.group("name")
        namespace = cpp_namespace_at(namespaces, match.start())
        symbol = declared if not namespace or declared.startswith(namespace + "::") else namespace + "::" + declared
        line = source_line(source, match.start())
        parameter_parts = cpp_split_top_level(parameters)
        required_parameter_count = 0
        default_seen = False
        for parameter_index, parameter in enumerate(parameter_parts):
            if not parameter.strip():
                raise LedgerError(f"registrar definition has an empty parameter: {relative}:{line}")
            has_default = cpp_parameter_has_top_level_default(
                parameter, f"registrar parameter {relative}:{line} index={parameter_index}")
            if has_default:
                default_seen = True
            elif default_seen:
                raise LedgerError(
                    f"registrar definition has a non-trailing required parameter: {relative}:{line}")
            else:
                required_parameter_count += 1
        definitions.append({
            "id": f"{relative}:{line}:{symbol}",
            "symbol": symbol,
            "bare_name": declared.rsplit("::", 1)[-1],
            "namespace": namespace,
            "parameters": re.sub(r"\s+", " ", parameters).strip(),
            "minimum_parameter_count": required_parameter_count,
            "parameter_count": len(parameter_parts),
            "file": relative,
            "line": line,
            "name_offset": match.start(),
            "body_start": cursor,
            "body_end": body_end,
        })
    return definitions


def cpp_registrar_accepts_argument_count(definition: dict[str, Any], argument_count: int) -> bool:
    minimum = definition.get("minimum_parameter_count")
    maximum = definition.get("parameter_count")
    if (not isinstance(minimum, int) or isinstance(minimum, bool) or
            not isinstance(maximum, int) or isinstance(maximum, bool)):
        raise LedgerError(f"registrar definition lacks arity metadata: {definition.get('id', '')}")
    if minimum < 0 or maximum < minimum:
        raise LedgerError(f"registrar definition has invalid arity metadata: {definition.get('id', '')}")
    return minimum <= argument_count <= maximum


def cpp_anonymous_namespace_segment(segment: str) -> bool:
    return re.fullmatch(r"<anonymous@[0-9]+>", segment) is not None


def cpp_namespace_contains_anonymous(namespace: str) -> bool:
    return re.search(r"(?:^|::)<anonymous@[0-9]+>(?:::|$)", namespace) is not None


def cpp_definition_injected_at_scope(definition: dict[str, Any], caller_file: str,
                                     scope: str) -> bool:
    if definition.get("file") != caller_file:
        return False
    namespace = str(definition.get("namespace", ""))
    if not namespace:
        return False
    segments = namespace.split("::")
    while segments and cpp_anonymous_namespace_segment(segments[-1]):
        segments.pop()
        if "::".join(segments) == scope:
            return True
    return False


def resolve_cpp_registrar_target(caller: dict[str, Any], callee: str,
                                  definitions: list[dict[str, Any]],
                                  argument_count: int) -> dict[str, Any]:
    qualified = "::" in callee
    if qualified:
        candidate_names: list[str] = []
        namespace = str(caller["namespace"])
        while namespace:
            candidate_names.append(namespace + "::" + callee)
            namespace = namespace.rsplit("::", 1)[0] if "::" in namespace else ""
        candidate_names.append(callee)
        for candidate_name in candidate_names:
            matches = [definition for definition in definitions
                       if definition["symbol"] == candidate_name and
                       cpp_registrar_accepts_argument_count(definition, argument_count)]
            if len(matches) > 1:
                raise LedgerError(
                    f"ambiguous registrar definition for {callee!r} from {caller['id']}")
            if len(matches) == 1:
                return matches[0]
    else:
        scopes: list[str] = []
        namespace = str(caller["namespace"])
        while namespace:
            scopes.append(namespace)
            namespace = namespace.rsplit("::", 1)[0] if "::" in namespace else ""
        scopes.append("")
        for scope in scopes:
            candidate_name = callee if not scope else scope + "::" + callee
            matches = [definition for definition in definitions
                       if cpp_registrar_accepts_argument_count(definition, argument_count) and
                       (definition["symbol"] == candidate_name or
                        cpp_definition_injected_at_scope(
                            definition, str(caller["file"]), scope)) and
                       definition["bare_name"] == callee]
            if len(matches) > 1:
                scope_label = scope or "<global>"
                raise LedgerError(
                    f"ambiguous registrar definition for {callee!r} at scope "
                    f"{scope_label!r} from {caller['id']}")
            if len(matches) == 1:
                return matches[0]
    bare = callee.rsplit("::", 1)[-1]
    if qualified:
        fallback = [definition for definition in definitions
                    if (definition["symbol"] == callee or
                        str(definition["symbol"]).endswith("::" + callee)) and
                    cpp_registrar_accepts_argument_count(definition, argument_count)]
    else:
        fallback = [definition for definition in definitions
                    if definition["bare_name"] == bare and
                    cpp_registrar_accepts_argument_count(definition, argument_count) and
                    not cpp_namespace_contains_anonymous(str(definition["namespace"]))]
    if len(fallback) != 1:
        raise LedgerError(
            f"unresolved or ambiguous registrar edge {callee!r} from "
            f"{caller['id']} candidates={len(fallback)}")
    return fallback[0]



def require_unique(values: list[str], label: str) -> set[str]:
    if len(values) != len(set(values)):
        duplicates = sorted({value for value in values if values.count(value) > 1})
        raise LedgerError(f"{label} has duplicate names: {','.join(duplicates)}")
    return set(values)


def decorator_name(decorator: ast.expr) -> str | None:
    expression = decorator.func if isinstance(decorator, ast.Call) else decorator
    if isinstance(expression, ast.Name):
        return expression.id
    if isinstance(expression, ast.Attribute):
        return expression.attr
    return None


def archive_tool_names(archive_path: Path) -> tuple[str, list[str]]:
    try:
        with zipfile.ZipFile(archive_path, "r") as archive:
            infos = archive.infolist()
            if not infos or len(infos) > MAX_ARCHIVE_MEMBERS:
                raise LedgerError("pinned archive member count exceeds the inspection policy")
            names: set[str] = set()
            folded_names: set[str] = set()
            compressed_total = 0
            uncompressed_total = 0
            for info in infos:
                name = info.filename
                path = PurePosixPath(name)
                if not name or "\x00" in name or path.is_absolute() or ".." in path.parts or "\\" in name or ":" in name:
                    raise LedgerError(f"pinned archive contains unsafe member path {name!r}")
                if name in names or name.casefold() in folded_names:
                    raise LedgerError(f"pinned archive contains duplicate member {name!r}")
                names.add(name)
                folded_names.add(name.casefold())
                unix_mode = (info.external_attr >> 16) & 0xFFFF
                if unix_mode & 0o170000 == 0o120000:
                    raise LedgerError(f"pinned archive contains symbolic link member {name!r}")
                if info.flag_bits & 0x1:
                    raise LedgerError(f"pinned archive contains encrypted member {name!r}")
                if info.file_size < 0 or info.compress_size < 0 or info.file_size > MAX_ARCHIVE_MEMBER_BYTES:
                    raise LedgerError(f"pinned archive member exceeds the inspection size policy: {name!r}")
                if info.file_size and info.compress_size == 0:
                    raise LedgerError(f"pinned archive member has invalid compression metadata: {name!r}")
                if info.compress_size and info.file_size > info.compress_size * MAX_COMPRESSION_RATIO:
                    raise LedgerError(f"pinned archive member exceeds the compression-ratio policy: {name!r}")
                compressed_total += info.compress_size
                uncompressed_total += info.file_size
                if compressed_total > MAX_ARCHIVE_COMPRESSED_BYTES or uncompressed_total > MAX_ARCHIVE_UNCOMPRESSED_BYTES:
                    raise LedgerError("pinned archive exceeds the aggregate inspection size policy")
            pyproject_name = "ida-pro-mcp/pyproject.toml"
            if pyproject_name not in names:
                raise LedgerError(f"archive is missing {pyproject_name}")
            pyproject = archive.read(pyproject_name).decode("utf-8")
            version_match = re.search(r'^version\s*=\s*"([^"]+)"\s*$', pyproject, re.MULTILINE)
            if version_match is None:
                raise LedgerError("archive pyproject has no project version")
            tool_names: list[str] = []
            for entry_name in sorted(names):
                if not entry_name.startswith("ida-pro-mcp/src/ida_pro_mcp/ida_mcp/api_"):
                    continue
                if not entry_name.endswith(".py") or entry_name.endswith("api_resources.py"):
                    continue
                source = archive.read(entry_name).decode("utf-8")
                try:
                    module = ast.parse(source, filename=entry_name)
                except SyntaxError as error:
                    raise LedgerError(f"archive syntax error in {entry_name}:{error.lineno}") from error
                for node in module.body:
                    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        continue
                    if any(decorator_name(decorator) == "tool" for decorator in node.decorator_list):
                        tool_names.append(node.name)
    except (zipfile.BadZipFile, OSError, UnicodeError, KeyError) as error:
        raise LedgerError(f"invalid pinned archive: {archive_path}") from error
    return version_match.group(1), sorted(tool_names)


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise LedgerError(f"cannot load JSON {path}: {error}") from error
    if not isinstance(value, dict):
        raise LedgerError(f"JSON root must be an object: {path}")
    return value


def resolve_record_path(root: Path, value: str) -> Path:
    path = Path(value)
    return path.resolve() if path.is_absolute() else (root / path).resolve()


def resolve_repository_file(root: Path, value: Any, label: str) -> Path:
    if not isinstance(value, str) or not value:
        raise LedgerError(f"{label} path is invalid")
    relative = Path(value)
    if relative.is_absolute() or any(part in ("", ".", "..") for part in relative.parts):
        raise LedgerError(f"{label} path must be a canonical repository-relative file")
    try:
        path = (root / relative).resolve(strict=True)
        path.relative_to(root)
    except (OSError, RuntimeError, ValueError) as error:
        raise LedgerError(f"{label} escapes or is unavailable in the repository: {value}") from error
    if not path.is_file():
        raise LedgerError(f"{label} is not a regular repository file: {value}")
    return path


def validate_absolute_executable(path: Path, label: str, expected_name: str | None = None) -> Path:
    if not path.is_absolute():
        raise LedgerError(f"{label} path must be absolute")
    normalized = Path(os.path.normpath(str(path)))
    if normalized != path or any(part in (".", "..") for part in path.parts):
        raise LedgerError(f"{label} path is ambiguous or non-canonical")
    if expected_name is not None and path.name.casefold() != expected_name.casefold():
        raise LedgerError(f"{label} path must name {expected_name}")
    current = Path(path.anchor)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    try:
        for part in path.parts[1:]:
            current /= part
            metadata = os.lstat(current)
            if getattr(metadata, "st_file_attributes", 0) & reparse_flag:
                raise LedgerError(f"{label} path contains a reparse point: {current}")
        resolved = path.resolve(strict=True)
        metadata = os.stat(resolved, follow_symlinks=False)
    except (OSError, RuntimeError) as error:
        raise LedgerError(f"{label} executable is unavailable: {path}: {error}") from error
    if resolved != path or not stat.S_ISREG(metadata.st_mode):
        raise LedgerError(f"{label} executable path is non-canonical or not a regular file: {path}")
    return resolved


def executable_identity(path: Path) -> tuple[int, int, int, int, str]:
    metadata = os.stat(path, follow_symlinks=False)
    return (metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns,
            sha256_file(path))


def canonical_windows_powershell() -> Path:
    if os.name != "nt":
        raise LedgerError("authority surface verification requires Windows")
    buffer = ctypes.create_unicode_buffer(32768)
    length = ctypes.windll.kernel32.GetSystemDirectoryW(buffer, len(buffer))
    if length == 0 or length >= len(buffer):
        raise LedgerError("GetSystemDirectoryW could not derive the canonical system directory")
    return Path(buffer.value) / "WindowsPowerShell" / "v1.0" / "powershell.exe"


def verify_hash_record(root: Path, record: dict[str, Any], label: str) -> Path:
    path_value = record.get("path")
    expected_hash = record.get("sha256")
    if not isinstance(path_value, str) or not path_value or not isinstance(expected_hash, str):
        raise LedgerError(f"{label} hash record is incomplete")
    path = resolve_record_path(root, path_value)
    if not path.is_file():
        raise LedgerError(f"{label} is unavailable: {path}")
    observed_hash = sha256_file(path)
    if observed_hash != expected_hash:
        raise LedgerError(f"{label} SHA-256 mismatch: expected {expected_hash}, observed {observed_hash}")
    return path


def run_checked(command: list[str], label: str, timeout_seconds: int = 180) -> str:
    try:
        completed = subprocess.run(command, check=False, capture_output=True, text=True,
                                   encoding="utf-8", errors="replace", timeout=timeout_seconds)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise LedgerError(f"{label} could not complete: {error}") from error
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()
        raise LedgerError(f"{label} failed with exit {completed.returncode}: {detail}")
    return completed.stdout.strip()


def verify_generated_contract_reproduction(ledger: dict[str, Any], root: Path, archive_path: Path,
                                           python_path: Path) -> dict[str, Any]:
    contract_generation = ledger["contract_generation"]
    generator_path = verify_hash_record(root, contract_generation["generator"], "MCP contract generator")
    artifacts = contract_generation.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts or not all(isinstance(value, str) and value for value in artifacts):
        raise LedgerError("MCP generated artifact inventory is invalid")
    if len(artifacts) != len(set(artifacts)):
        raise LedgerError("MCP generated artifact inventory contains duplicates")
    observed: dict[str, str] = {}
    generator_before = executable_identity(generator_path)
    with tempfile.TemporaryDirectory(prefix="aida-c03-contract-reproduction-") as directory:
        temporary_root = Path(directory).resolve()
        python_before = executable_identity(python_path)
        run_checked([
            str(python_path), str(generator_path), "--archive", str(archive_path),
            "--repo-root", str(temporary_root),
        ], "deterministic MCP contract reproduction")
        if executable_identity(python_path) != python_before:
            raise LedgerError("Python interpreter identity changed during MCP contract reproduction")
        if executable_identity(generator_path) != generator_before:
            raise LedgerError("MCP contract generator identity changed during reproduction")
        for relative in artifacts:
            if Path(relative).is_absolute() or ".." in Path(relative).parts:
                raise LedgerError(f"generated artifact path escapes the repository: {relative}")
            reproduced_path = temporary_root / relative
            checked_in_path = root / relative
            if not reproduced_path.is_file() or not checked_in_path.is_file():
                raise LedgerError(f"generated artifact is unavailable for byte comparison: {relative}")
            reproduced = reproduced_path.read_bytes()
            checked_in = checked_in_path.read_bytes()
            if reproduced != checked_in:
                raise LedgerError(f"generated MCP contract artifact is stale: {relative}")
            observed[relative] = hashlib.sha256(reproduced).hexdigest().upper()
    descriptor_hashes = contract_generation.get("descriptor_artifact_sha256")
    if not isinstance(descriptor_hashes, dict) or set(descriptor_hashes) != set(artifacts[:3]):
        raise LedgerError("generated MCP descriptor hash inventory is invalid")
    for relative, expected in descriptor_hashes.items():
        if not isinstance(expected, str) or observed.get(relative) != expected:
            raise LedgerError(f"generated MCP descriptor hash mismatch: {relative}")
    return {
        "generator_sha256": generator_before[4],
        "python": {"path": str(python_path), "sha256": python_before[4]},
        "artifacts": observed,
    }


def require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise LedgerError(f"{label} must be an object")
    return value


def require_array(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise LedgerError(f"{label} must be an array")
    return value


def reject_external_refs(value: Any, label: str) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if key == "$ref" and (not isinstance(child, str) or not child.startswith("#/")):
                raise LedgerError(f"{label} contains a remote, file, or non-local schema reference")
            reject_external_refs(child, label)
    elif isinstance(value, list):
        for child in value:
            reject_external_refs(child, label)


def cpp_registrar_declaration(mask: str, start: int, closing: int) -> bool:
    after = closing + 1
    while after < len(mask) and mask[after].isspace():
        after += 1
    if after >= len(mask) or mask[after] != ";":
        return False
    boundary = start - 1
    while boundary >= 0 and mask[boundary] not in ";{}\r\n":
        boundary -= 1
    prefix = mask[boundary + 1:start].strip()
    if not prefix:
        return False
    if re.match(r"^(?:return|co_return|co_await|throw)\b", prefix):
        return False
    type_token = r"(?:[A-Za-z_]\w*::)*[A-Za-z_]\w*(?:\s*<[^;{}()]*>)?(?:\s*[*&]+)?"
    return re.fullmatch(
        rf"(?:(?:extern|static|inline|constexpr|consteval|constinit|friend|virtual|explicit|typename|const|volatile)\s+)*(?:{type_token})(?:\s+{type_token})*",
        prefix) is not None


def cpp_registrar_terminal_identity(relative: str, mask: str, offset: int,
                                    label: str) -> dict[str, Any]:
    if offset < 0 or offset >= len(mask):
        raise LedgerError(f"{label} has an invalid source offset: {relative}:{offset}")
    match = re.match(
        r"(?:\.\s*|->\s*)?(?P<callee>(?:[A-Za-z_]\w*::)*(?:register|replace)_[A-Za-z0-9_]+)\s*\(",
        mask[offset:])
    if match is None:
        raise LedgerError(f"{label} is not anchored to a registrar call: {relative}:{offset}")
    callee_offset = offset + match.start("callee")
    opening = mask.find("(", callee_offset)
    if opening < 0:
        raise LedgerError(f"{label} has no registrar argument list: {relative}:{offset}")
    cpp_matching_index(mask, opening, "(", ")")
    return {
        "key": f"{relative}:{callee_offset}",
        "callee": match.group("callee"),
        "character_offset": callee_offset,
    }


def cpp_physical_registration_terminals(definition: dict[str, Any],
                                        mask: str) -> list[dict[str, Any]]:
    body_start = int(definition["body_start"]) + 1
    body_end = int(definition["body_end"])
    if body_end <= body_start:
        return []
    terminals: list[dict[str, Any]] = []
    pattern = re.compile(r"(?:\.|->)\s*(?P<callee>(?:register|replace)_tool)\s*\(")
    for match in pattern.finditer(mask[body_start:body_end]):
        offset = body_start + match.start("callee")
        opening = mask.find("(", offset)
        if opening < 0:
            raise LedgerError(
                f"physical registration terminal has no argument list: {definition['id']}")
        cpp_matching_index(mask, opening, "(", ")")
        terminals.append({
            "key": f"{definition['file']}:{offset}",
            "callee": match.group("callee"),
            "character_offset": offset,
            "line": source_line(mask, offset),
        })
    return terminals


def cpp_registrar_calls(definition: dict[str, Any], source: str, mask: str,
                        definitions: list[dict[str, Any]], terminal_offsets: set[str],
                        explicit_edges: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    body_start = int(definition["body_start"]) + 1
    body_end = int(definition["body_end"])
    body_mask = mask[body_start:body_end]
    calls: list[dict[str, Any]] = []
    pattern = re.compile(
        r"(?P<callee>(?:[A-Za-z_]\w*::)*(?:register|replace)_[A-Za-z0-9_]+)\s*\(")
    for match in pattern.finditer(body_mask):
        absolute = body_start + match.start()
        callee = match.group("callee")
        terminal_key = f"{definition['file']}:{absolute}"
        if terminal_key in terminal_offsets:
            continue
        opening = mask.find("(", absolute)
        closing = cpp_matching_index(mask, opening, "(", ")")
        if cpp_registrar_declaration(mask, absolute, closing):
            raise LedgerError(
                f"registrar declaration is forbidden in reachable code: {callee} from {definition['id']}")
        if terminal_key in explicit_edges:
            edge = explicit_edges[terminal_key]
            if edge.get("caller_id") != definition["id"]:
                raise LedgerError(f"explicit registrar edge has the wrong enclosing owner at {terminal_key}")
            calls.append({
                "caller_id": edge["caller_id"],
                "callee_id": edge["callee_id"],
                "callee_symbol": edge["callee_symbol"],
                "file": definition["file"],
                "line": source_line(source, absolute),
                "character_offset": absolute,
                "expression": edge["expression"],
            })
            continue
        immediate_previous = mask[absolute - 1] if absolute > 0 else "\0"
        previous_index = absolute - 1
        while previous_index >= 0 and mask[previous_index].isspace():
            previous_index -= 1
        previous = mask[previous_index] if previous_index >= 0 else "\0"
        if previous in ".>:":
            raise LedgerError(
                f"indirect registrar edge {callee} is not source-resolvable from {definition['id']}")
        if immediate_previous.isalnum() or immediate_previous == "_":
            continue
        arguments = source[opening + 1:closing]
        target = resolve_cpp_registrar_target(
            definition, callee, definitions, len(cpp_split_top_level(arguments)))
        expression = re.sub(r"\s+", " ", source[absolute:closing + 1]).strip()
        calls.append({
            "caller_id": definition["id"],
            "callee_id": target["id"],
            "callee_symbol": target["symbol"],
            "file": definition["file"],
            "line": source_line(source, absolute),
            "character_offset": absolute,
            "expression": expression,
        })
    return calls


def unique_cpp_code_call(root: Path, relative: str, pattern: str, label: str) -> dict[str, Any]:
    path = resolve_repository_file(root, relative, label)
    source = read_utf8_source(path)
    mask = cpp_code_mask(source, relative)
    matches = list(re.finditer(pattern, mask))
    if len(matches) != 1:
        raise LedgerError(f"{label} must have exactly one code occurrence, observed {len(matches)}")
    match = matches[0]
    opening = mask.find("(", match.start())
    closing = cpp_matching_index(mask, opening, "(", ")")
    return {
        "file": relative,
        "line": source_line(source, match.start()),
        "character_offset": match.start(),
        "expression": re.sub(r"\s+", " ", source[match.start():closing + 1]).strip(),
    }


def owned_cpp_code_call(root: Path, relative: str, pattern: str, label: str,
                        definitions: list[dict[str, Any]]) -> dict[str, Any]:
    call = unique_cpp_code_call(root, relative, pattern, label)
    owners = [definition for definition in definitions
              if definition["file"] == relative and
              int(definition["body_start"]) < int(call["character_offset"]) <
              int(definition["body_end"])]
    if len(owners) != 1:
        raise LedgerError(f"{label} has {len(owners)} enclosing function definitions")
    call["caller_id"] = owners[0]["id"]
    call["caller_symbol"] = owners[0]["symbol"]
    path = resolve_repository_file(root, relative, label)
    mask = cpp_code_mask(read_utf8_source(path), relative)
    opening = mask.find("(", int(call["character_offset"]))
    closing = cpp_matching_index(mask, opening, "(", ")")
    token = re.search(r"\b(?:register|replace)_[A-Za-z0-9_]+\s*\(",
                      mask[int(call["character_offset"]):closing + 1])
    if token is None:
        raise LedgerError(f"{label} does not contain a registrar-like call")
    call["registrar_character_offset"] = int(call["character_offset"]) + token.start()
    return call


def select_unique_cpp_definition(definitions: list[dict[str, Any]], relative: str,
                                 bare_name: str, parameter_pattern: str,
                                 label: str) -> dict[str, Any]:
    pattern = re.compile(parameter_pattern)
    matches = [definition for definition in definitions
               if definition["file"] == relative and
               definition["bare_name"] == bare_name and
               pattern.search(str(definition["parameters"])) is not None]
    if len(matches) != 1:
        raise LedgerError(f"{label} definition count is {len(matches)}, expected one")
    return matches[0]


def load_cpp_reachability_sources(root: Path) -> tuple[list[dict[str, Any]], dict[str, str], dict[str, str]]:
    standalone_root = root / "src/standalone/src"
    core_root = standalone_root / "core"
    header_extensions = {".h", ".hh", ".hpp", ".hxx", ".inl", ".ipp"}
    candidates = list(core_root.rglob("*.cpp"))
    candidates.extend(path for path in standalone_root.rglob("*")
                      if path.is_file() and path.suffix.casefold() in header_extensions)
    paths: list[Path] = []
    path_identities: set[str] = set()
    for path in sorted(candidates, key=lambda value: str(value).casefold()):
        try:
            resolved = path.resolve(strict=True)
            resolved.relative_to(root)
        except (OSError, RuntimeError, ValueError) as error:
            raise LedgerError(f"C++ reachability source escapes the repository: {path}") from error
        identity = str(resolved).casefold()
        if identity not in path_identities:
            path_identities.add(identity)
            paths.append(resolved)
    if not paths or len(paths) > MAX_REACHABILITY_SOURCE_FILES:
        raise LedgerError("C++ reachability source count exceeds policy")
    definitions: list[dict[str, Any]] = []
    sources: dict[str, str] = {}
    masks: dict[str, str] = {}
    total_bytes = 0
    for path in paths:
        size = path.stat().st_size
        if size > MAX_REACHABILITY_FILE_BYTES:
            raise LedgerError(f"C++ reachability source exceeds per-file policy: {path}")
        total_bytes += size
        if total_bytes > MAX_REACHABILITY_SOURCE_BYTES:
            raise LedgerError("C++ reachability sources exceed aggregate policy")
        try:
            source = read_utf8_source(path)
        except (OSError, UnicodeError) as error:
            raise LedgerError(f"C++ reachability source is not valid UTF-8: {path}") from error
        if "register_" not in source:
            continue
        relative = path.relative_to(root).as_posix()
        mask = cpp_code_mask(source, relative)
        sources[relative] = source
        masks[relative] = mask
        definitions.extend(cpp_registrar_definitions(relative, source, mask))
    ids = [str(value["id"]) for value in definitions]
    require_unique(ids, "C++ registrar definition identities")
    return definitions, sources, masks


def derive_cpp_reachability_graph(
        root: Path, registrations: list[Any]) -> tuple[
            dict[str, Any], list[dict[str, Any]], list[dict[str, Any]],
            dict[str, list[str]], list[dict[str, Any]], dict[str, str],
            dict[str, str], dict[str, Any], dict[str, Any], set[str]]:
    definitions, sources, masks = load_cpp_reachability_sources(root)
    roots = [value for value in definitions
             if value["symbol"] == "mcp_standalone::register_standalone_tools"]
    if len(roots) != 1:
        raise LedgerError(f"production MCP root registrar definition count is {len(roots)}, expected one")
    root_definition = roots[0]
    entry = unique_cpp_code_call(
        root, "src/standalone/src/core/ai/standalone_chat.cpp",
        r"\bmcp_standalone::register_standalone_tools\s*\(\s*s_mcp_server\s*\)",
        "standalone production MCP initialization call")
    entry["root_registrar_id"] = root_definition["id"]
    entry["root_registrar_symbol"] = root_definition["symbol"]
    reachable = {str(root_definition["id"]): root_definition}
    parents: dict[str, str] = {}
    chains = {str(root_definition["id"]): [str(root_definition["id"])]}
    queue = [root_definition]
    edges: list[dict[str, Any]] = []
    edge_sites: dict[str, str] = {}
    registration_terminal_offsets: set[str] = set()
    registration_terminal_evidence: dict[str, str] = {}
    registration_producer_sites: dict[str, dict[str, Any]] = {}
    for value in registrations:
        registration = require_object(value, "current MCP reachability registration")
        name = registration.get("name")
        if not isinstance(name, str) or not name:
            raise LedgerError("MCP registration terminal has an empty public name")
        source_record = require_object(
            registration.get("source"), f"current MCP registration {name} source")
        relative = source_record.get("file")
        offset = source_record.get("character_offset")
        if not isinstance(relative, str) or not isinstance(offset, int) or isinstance(offset, bool):
            raise LedgerError("current MCP reachability registration lacks an exact source offset")
        if offset < 0:
            if "helper_terminal_binding" in source_record:
                raise LedgerError(
                    f"generated MCP projection has a helper terminal binding: {name}")
            continue
        if relative not in sources or relative not in masks:
            raise LedgerError(f"MCP registration terminal source is unavailable: {relative}:{offset}")
        identity = cpp_registrar_terminal_identity(
            relative, masks[relative], offset, f"MCP registration {name!r}")
        key = str(identity["key"])
        identity_callee = str(identity["callee"])
        identity_offset = int(identity["character_offset"])
        line = source_record.get("line")
        if not isinstance(line, int) or isinstance(line, bool) or \
                line != source_line(sources[relative], identity_offset):
            raise LedgerError(
                f"MCP registration terminal line metadata is invalid: {relative}:{offset}")
        evidence_name = source_record.get("evidence")
        if not isinstance(evidence_name, str) or not evidence_name:
            raise LedgerError(f"MCP registration terminal evidence is invalid: {relative}:{offset}")
        evidence = (f"{name}\t{relative}\t{line}\t{offset}\t{evidence_name}\t"
                    f"{identity_callee}\t{identity_offset}")
        identity_prefix = masks[relative][offset:identity_offset]
        member_terminal = re.match(r"^(?:\.|->)", identity_prefix) is not None
        producer_target: dict[str, Any] | None = None
        if not member_terminal and evidence_name != "compat_initializer":
            owners = [definition for definition in definitions
                      if definition["file"] == relative and
                      int(definition["body_start"]) < identity_offset <
                      int(definition["body_end"])]
            if len(owners) != 1:
                raise LedgerError(
                    f"MCP registration producer has {len(owners)} enclosing registrars: {key}")
            opening = masks[relative].find("(", identity_offset)
            closing = cpp_matching_index(masks[relative], opening, "(", ")")
            arguments = sources[relative][opening + 1:closing]
            producer_target = resolve_cpp_registrar_target(
                owners[0], identity_callee, definitions,
                len(cpp_split_top_level(arguments)))
        if producer_target is not None:
            if key in registration_producer_sites:
                raise LedgerError(f"duplicate MCP registration producer identity: {key}")
            registration_producer_sites[key] = {
                "registration": registration,
                "target_id": producer_target["id"],
                "target_symbol": producer_target["symbol"],
                "evidence": evidence,
            }
            continue
        if "helper_terminal_binding" in source_record:
            raise LedgerError(f"direct MCP registration has a helper terminal binding: {key}")
        if key in registration_terminal_evidence:
            if registration_terminal_evidence[key] != evidence:
                raise LedgerError(f"conflicting MCP registration terminal identity: {key}")
            raise LedgerError(f"duplicate MCP registration terminal identity: {key}")
        registration_terminal_evidence[key] = evidence
        if key in registration_terminal_offsets:
            raise LedgerError(f"duplicate MCP registration terminal offset: {key}")
        registration_terminal_offsets.add(key)
    route_entry = owned_cpp_code_call(
        root, "src/standalone/src/core/mcp/mcp_standalone_tools.cpp",
        r"\bregister_c03_compatibility_tools\s*\(\s*srv\s*\)",
        "C03 compatibility root registrar edge", definitions)
    if route_entry["caller_id"] != root_definition["id"]:
        raise LedgerError("C03 compatibility root registrar edge is outside the production root")
    direct_terminal_offsets = set(registration_terminal_offsets)
    helper_terminal_owners: dict[str, str] = {}
    physical_terminal_definition_owners: dict[str, str] = {}
    physical_terminals_by_definition: dict[str, list[dict[str, Any]]] = {}
    for definition in definitions:
        definition_id = str(definition["id"])
        relative = str(definition["file"])
        if relative not in masks:
            raise LedgerError(f"registrar terminal source cache is unavailable: {definition_id}")
        definition_terminals = cpp_physical_registration_terminals(
            definition, masks[relative])
        physical_terminals_by_definition[definition_id] = definition_terminals
        for terminal in definition_terminals:
            key = str(terminal["key"])
            if key in physical_terminal_definition_owners:
                if physical_terminal_definition_owners[key] != definition_id:
                    raise LedgerError(
                        f"physical registration terminal has multiple definition owners: {key}")
                raise LedgerError(f"duplicate physical registration terminal identity: {key}")
            physical_terminal_definition_owners[key] = definition_id
            direct_terminal_offsets.add(key)
    bound_registration_producer_sites: set[str] = set()
    registration_producer_edges: dict[str, dict[str, Any]] = {}
    direct_terminal_offsets.add(
        f"{route_entry['file']}:{route_entry['registrar_character_offset']}")
    by_id = {str(value["id"]): value for value in definitions}
    while queue:
        caller = queue.pop(0)
        relative = str(caller["file"])
        if relative not in sources or relative not in masks:
            raise LedgerError(f"registrar source cache is unavailable: {relative}")
        calls = cpp_registrar_calls(
            caller, sources[relative], masks[relative], definitions,
            direct_terminal_offsets, {})
        for edge in calls:
            if edge["caller_id"] != caller["id"] or edge["file"] != relative:
                raise LedgerError(
                    f"registrar call-site ownership metadata is invalid: {caller['id']}")
            edge_offset = edge.get("character_offset")
            edge_line = edge.get("line")
            if (not isinstance(edge_offset, int) or isinstance(edge_offset, bool) or
                    not isinstance(edge_line, int) or isinstance(edge_line, bool) or
                    edge_offset <= int(caller["body_start"]) or
                    edge_offset >= int(caller["body_end"]) or
                    edge_line != source_line(sources[relative], edge_offset) or
                    not isinstance(edge.get("expression"), str) or not edge["expression"].strip()):
                raise LedgerError(
                    f"registrar call-site location metadata is invalid: {caller['id']}")
            site_key = f"{relative}:{edge_offset}"
            site_evidence = (f"{edge['caller_id']}\t{edge['callee_id']}\t"
                             f"{edge['callee_symbol']}\t{relative}\t{edge_line}\t"
                             f"{edge_offset}\t{edge['expression']}")
            if site_key in edge_sites:
                if edge_sites[site_key] != site_evidence:
                    raise LedgerError(f"conflicting registrar call-site evidence: {site_key}")
                raise LedgerError(f"duplicate registrar call-site evidence: {site_key}")
            edge_sites[site_key] = site_evidence
            target_id = str(edge["callee_id"])
            if target_id == root_definition["id"] or target_id == caller["id"]:
                raise LedgerError(f"registrar has a cycle or multiple production parents: {target_id}")
            if target_id not in by_id:
                raise LedgerError(f"resolved registrar target identity is invalid: {target_id}")
            target = by_id[target_id]
            if edge["callee_symbol"] != target["symbol"]:
                raise LedgerError(
                    f"resolved registrar target metadata conflicts with its definition: {target_id}")
            if site_key in registration_producer_sites:
                producer = registration_producer_sites[site_key]
                if (producer["target_id"] != target_id or
                        producer["target_symbol"] != target["symbol"]):
                    raise LedgerError(
                        f"MCP registration producer target conflicts with its graph edge: {site_key}")
                if site_key in registration_producer_edges:
                    raise LedgerError(
                        f"MCP registration producer graph edge is duplicated: {site_key}")
                registration_producer_edges[site_key] = edge
            if target_id in parents:
                if parents[target_id] != caller["id"]:
                    raise LedgerError(
                        f"registrar has a cycle or multiple production parents: {target_id}")
                if target_id not in reachable or target_id not in chains:
                    raise LedgerError(
                        f"repeated registrar target has inconsistent graph state: {target_id}")
                edges.append(edge)
                continue
            if (target_id in reachable or target_id in chains or
                    str(caller["id"]) not in chains):
                raise LedgerError(f"registrar target has inconsistent graph state: {target_id}")
            parents[target_id] = str(caller["id"])
            chains[target_id] = chains[str(caller["id"])] + [target_id]
            reachable[target_id] = target
            edges.append(edge)
            queue.append(target)
    if set(registration_producer_edges) != set(registration_producer_sites):
        missing = sorted(set(registration_producer_sites) - set(registration_producer_edges))
        raise LedgerError(
            f"MCP registration producers lack exact graph edges: {', '.join(missing)}")
    outgoing_edges: dict[str, list[dict[str, Any]]] = {}
    for edge in edges:
        outgoing_edges.setdefault(str(edge["caller_id"]), []).append(edge)
    for site_key in sorted(registration_producer_sites):
        producer = registration_producer_sites[site_key]
        producer_edge = registration_producer_edges[site_key]
        helper_id = str(producer["target_id"])
        if producer_edge["callee_id"] != helper_id:
            raise LedgerError(
                f"MCP registration producer edge target is inconsistent: {site_key}")
        if helper_id not in by_id or helper_id not in reachable:
            raise LedgerError(
                f"MCP registration producer helper is not uniquely reachable: {site_key}")
        helper = by_id[helper_id]
        terminal_chain: list[str] = []
        bridge_calls: list[dict[str, Any]] = []
        visited_chain: set[str] = set()
        current_id = helper_id
        terminal_owner: dict[str, Any] | None = None
        physical_terminals: list[dict[str, Any]] = []
        while True:
            if current_id in visited_chain:
                raise LedgerError(
                    f"MCP registration helper chain contains a cycle: "
                    f"{site_key} target={current_id}")
            visited_chain.add(current_id)
            terminal_chain.append(current_id)
            if (current_id not in by_id or current_id not in reachable or
                    current_id not in physical_terminals_by_definition):
                raise LedgerError(
                    f"MCP registration helper chain target is invalid: "
                    f"{site_key} target={current_id}")
            current = by_id[current_id]
            physical_terminals = physical_terminals_by_definition[current_id]
            outgoing = sorted(outgoing_edges.get(current_id, []), key=lambda edge: (
                str(edge["file"]), int(edge["character_offset"]), str(edge["callee_id"])))
            if physical_terminals:
                if outgoing:
                    raise LedgerError(
                        f"MCP registration helper has both physical and delegated terminals: "
                        f"{current_id}")
                terminal_owner = current
                break
            if len(outgoing) != 1:
                raise LedgerError(
                    f"MCP registration helper chain has {len(outgoing)} delegated terminals: "
                    f"{current_id}")
            bridge_edge = outgoing[0]
            if (bridge_edge["caller_id"] != current_id or
                    not isinstance(bridge_edge.get("expression"), str) or
                    not bridge_edge["expression"].strip()):
                raise LedgerError(
                    f"MCP registration helper bridge call identity is invalid: {current_id}")
            next_id = str(bridge_edge["callee_id"])
            if not next_id or next_id == current_id:
                raise LedgerError(
                    f"MCP registration helper bridge target is invalid: {current_id}")
            bridge_calls.append({
                "caller_id": current_id,
                "callee_id": next_id,
                "callee_symbol": bridge_edge["callee_symbol"],
                "file": bridge_edge["file"],
                "line": bridge_edge["line"],
                "character_offset": bridge_edge["character_offset"],
                "expression": bridge_edge["expression"],
            })
            current_id = next_id
        if terminal_owner is None or not physical_terminals:
            raise LedgerError(
                f"MCP registration helper chain has no physical terminal: {site_key}")
        chain_hash = sha256_lines(terminal_chain)
        terminal_owner_evidence = f"{helper_id}\t{chain_hash}"
        terminal_bindings: list[dict[str, Any]] = []
        for terminal in sorted(
                physical_terminals, key=lambda value: int(value["character_offset"])):
            physical_key = str(terminal["key"])
            if physical_key in registration_terminal_offsets:
                raise LedgerError(
                    f"helper physical terminal conflicts with a direct registration: {physical_key}")
            if physical_terminal_definition_owners.get(physical_key) != terminal_owner["id"]:
                raise LedgerError(
                    f"helper physical terminal definition owner is invalid: {physical_key}")
            if (physical_key in helper_terminal_owners and
                    helper_terminal_owners[physical_key] != terminal_owner_evidence):
                raise LedgerError(
                    f"helper physical terminal has multiple registrar provenance owners: {physical_key}")
            helper_terminal_owners[physical_key] = terminal_owner_evidence
            terminal_bindings.append({
                "key": physical_key,
                "file": terminal_owner["file"],
                "line": terminal["line"],
                "character_offset": terminal["character_offset"],
                "callee": terminal["callee"],
                "owner_id": terminal_owner["id"],
                "owner_symbol": terminal_owner["symbol"],
            })
        expected_binding = {
            "producer_key": site_key,
            "helper_id": helper_id,
            "helper_symbol": helper["symbol"],
            "chain": terminal_chain,
            "chain_sha256": chain_hash,
            "bridge_calls": bridge_calls,
            "terminal_owner_id": terminal_owner["id"],
            "terminal_owner_symbol": terminal_owner["symbol"],
            "terminals": terminal_bindings,
        }
        registration = require_object(
            producer["registration"], "MCP registration producer")
        source_record = require_object(
            registration.get("source"), "MCP registration producer source")
        observed_binding = require_object(
            source_record.get("helper_terminal_binding"),
            f"MCP registration producer {site_key} helper terminal binding")
        if observed_binding != expected_binding:
            raise LedgerError(
                f"MCP registration producer has an invalid helper terminal binding: {site_key}")
        if site_key in bound_registration_producer_sites:
            raise LedgerError(f"MCP registration producer was bound more than once: {site_key}")
        bound_registration_producer_sites.add(site_key)
    if bound_registration_producer_sites != set(registration_producer_sites):
        missing = sorted(set(registration_producer_sites) - bound_registration_producer_sites)
        raise LedgerError(
            f"MCP registration producers lack helper terminal bindings: {', '.join(missing)}")
    registrar_rows = []
    for value in sorted(reachable.values(), key=lambda item: str(item["id"])):
        identifier = str(value["id"])
        registrar_rows.append({
            "id": identifier,
            "symbol": value["symbol"],
            "file": value["file"],
            "line": value["line"],
            "body_start": value["body_start"],
            "body_end": value["body_end"],
            "parent_id": None if identifier == root_definition["id"] else parents[identifier],
            "chain": chains[identifier],
        })
    edge_rows = sorted(edges, key=lambda item: (
        str(item["caller_id"]), str(item["callee_id"]), str(item["file"]),
        int(item["line"]), int(item["character_offset"]), str(item["expression"])))
    return (entry, registrar_rows, edge_rows, chains, definitions, sources, masks,
            root_definition, route_entry, registration_terminal_offsets)


def derive_generated_compatibility_route(
        root: Path, definitions: list[dict[str, Any]], sources: dict[str, str],
        masks: dict[str, str], root_definition: dict[str, Any],
        direct_edges: list[dict[str, Any]], route_entry: dict[str, Any],
        registration_terminal_offsets: set[str],
        generated_rows: dict[str, dict[str, Any]]) -> tuple[
            dict[str, Any], dict[str, dict[str, Any]]]:
    standalone_tools = "src/standalone/src/core/mcp/mcp_standalone_tools.cpp"
    server_path = "src/standalone/src/core/mcp/mcp_standalone.cpp"
    registration_path = "src/standalone/src/core/mcp/compat/c03_compatibility_registration.cpp"
    integration_path = "src/standalone/src/core/mcp/compat/mcp_server_integration.cpp"
    server_bridge = select_unique_cpp_definition(
        definitions, server_path, "register_c03_compatibility_tools",
        r"server_t\s*&", "C03 server bridge")
    config_bridge = select_unique_cpp_definition(
        definitions, registration_path, "register_c03_compatibility_tools",
        r"tool_registry_t\s*&.*c03_compatibility_runtime_config_t",
        "C03 runtime-config bridge")
    wave_registrar = select_unique_cpp_definition(
        definitions, registration_path, "register_wave_c_compatibility_tools",
        r"tool_registry_t\s*&.*c03_compatibility_runtime_config_t",
        "C03 Wave C registrar")
    generated_registrar = select_unique_cpp_definition(
        definitions, integration_path, "register_generated_tools", r"^$",
        "C03 generated registrar")
    extension_registrar = select_unique_cpp_definition(
        definitions, integration_path, "register_extension_tools", r"^$",
        "C03 extension registrar")
    entry_registrar = select_unique_cpp_definition(
        definitions, integration_path, "register_entry",
        r"shared_ptr<mcp_server_integration_t>.*std::string\s*&",
        "C03 per-name registrar")
    specifications = [
        (route_entry, root_definition, server_bridge),
        (owned_cpp_code_call(
            root, server_path,
            r"\bregister_c03_compatibility_tools\s*\(\s*server\.registry\s*\(\s*\)\s*,\s*make_application_c03_compatibility_runtime_config\s*\(\s*\)\s*\)",
            "C03 compatibility server bridge edge", definitions),
         server_bridge, config_bridge),
        (owned_cpp_code_call(
            root, registration_path,
            r"\bregister_wave_c_compatibility_tools\s*\(\s*registry\s*,\s*std::move\s*\(\s*config\s*\)\s*\)",
            "C03 compatibility wave registrar edge", definitions),
         config_bridge, wave_registrar),
        (owned_cpp_code_call(
            root, registration_path,
            r"\bintegration\s*->\s*register_generated_tools\s*\(\s*\)",
            "C03 generated compatibility registrar edge", definitions),
         wave_registrar, generated_registrar),
        (owned_cpp_code_call(
            root, registration_path,
            r"\bintegration\s*->\s*register_extension_tools\s*\(\s*\)",
            "C03 extension registrar edge", definitions),
         wave_registrar, extension_registrar),
        (owned_cpp_code_call(
            root, integration_path,
            r"\bimpl_\s*->\s*register_entry\s*\(\s*owner\s*,\s*name\s*\)",
            "C03 generated per-name registrar edge", definitions),
         generated_registrar, entry_registrar),
        (owned_cpp_code_call(
            root, integration_path,
            r"\bimpl_\s*->\s*register_entry\s*\(\s*owner\s*,\s*std::string\s*\(\s*name\s*\)\s*\)",
            "C03 extension per-name registrar edge", definitions),
         extension_registrar, entry_registrar),
    ]
    route_edges: list[dict[str, Any]] = []
    for call, caller, callee in specifications:
        if call["caller_id"] != caller["id"]:
            raise LedgerError(f"C03 route call has the wrong enclosing owner: {call['expression']}")
        route_edges.append({
            "caller_id": caller["id"],
            "caller_symbol": caller["symbol"],
            "callee_id": callee["id"],
            "callee_symbol": callee["symbol"],
            "file": call["file"],
            "line": call["line"],
            "character_offset": call["registrar_character_offset"],
            "expression": call["expression"],
        })
    operation_calls = [
        owned_cpp_code_call(
            root, integration_path,
            r"\bstate\.registry\s*->\s*replace_tool\s*\(\s*std::move\s*\(\s*tool\s*\)\s*\)",
            "C03 replacement terminal registration", definitions),
        owned_cpp_code_call(
            root, integration_path,
            r"\bstate\.registry\s*->\s*register_tool\s*\(\s*std::move\s*\(\s*tool\s*\)\s*\)",
            "C03 insertion terminal registration", definitions),
    ]
    terminal_operations: list[dict[str, Any]] = []
    for operation in operation_calls:
        if operation["caller_id"] != entry_registrar["id"]:
            raise LedgerError("C03 terminal registration is outside the per-name registrar")
        terminal_operations.append({
            "file": operation["file"],
            "line": operation["line"],
            "character_offset": operation["registrar_character_offset"],
            "expression": operation["expression"],
            "caller_id": operation["caller_id"],
            "caller_symbol": operation["caller_symbol"],
        })
    explicit_edges: dict[str, dict[str, Any]] = {}
    for edge in route_edges:
        key = f"{edge['file']}:{edge['character_offset']}"
        if key in explicit_edges:
            raise LedgerError(f"C03 explicit registrar route offset is duplicated: {key}")
        explicit_edges[key] = edge
    route_terminal_offsets = set(registration_terminal_offsets)
    route_terminal_offsets.update(
        f"{operation['file']}:{operation['character_offset']}"
        for operation in terminal_operations)
    route_definitions = [
        root_definition, server_bridge, config_bridge, wave_registrar,
        generated_registrar, extension_registrar, entry_registrar,
    ]
    for definition in route_definitions:
        relative = str(definition["file"])
        observed = cpp_registrar_calls(
            definition, sources[relative], masks[relative], definitions,
            route_terminal_offsets, explicit_edges)
        expected = [edge for edge in route_edges
                    if edge["caller_id"] == definition["id"]]
        if definition["id"] == root_definition["id"]:
            expected.extend(edge for edge in direct_edges
                            if edge["caller_id"] == definition["id"])
        observed_lines = sorted(
            f"{edge['caller_id']}\t{edge['callee_id']}\t{edge['file']}\t{edge['character_offset']}"
            for edge in observed)
        expected_lines = sorted(
            f"{edge['caller_id']}\t{edge['callee_id']}\t{edge['file']}\t{edge['character_offset']}"
            for edge in expected)
        if observed_lines != expected_lines:
            raise LedgerError(
                f"C03 registrar body has an unclassified or missing edge: {definition['id']}")
    route_nodes = [{
        "id": definition["id"],
        "symbol": definition["symbol"],
        "file": definition["file"],
        "line": definition["line"],
        "body_start": definition["body_start"],
        "body_end": definition["body_end"],
        "parameters": definition["parameters"],
    } for definition in route_definitions]
    generated_base_chain = [
        str(root_definition["id"]), str(server_bridge["id"]),
        str(config_bridge["id"]), str(wave_registrar["id"]),
    ]
    compatibility_chain = generated_base_chain + [
        str(generated_registrar["id"]), str(entry_registrar["id"])]
    extension_chain = generated_base_chain + [
        str(extension_registrar["id"]), str(entry_registrar["id"])]
    bindings: list[dict[str, Any]] = []
    binding_by_name: dict[str, dict[str, Any]] = {}
    for name, row in generated_rows.items():
        if name in binding_by_name:
            raise LedgerError(f"C03 generated reachability binding is duplicated: {name}")
        extension = "#wave_c_extension_binding" in str(row.get("descriptor_source", ""))
        chain = extension_chain if extension else compatibility_chain
        binding = {
            "name": name,
            "branch": "extension" if extension else "generated_compatibility",
            "registrar_id": entry_registrar["id"],
            "registrar_symbol": entry_registrar["symbol"],
            "chain": chain,
            "chain_sha256": sha256_lines(chain),
        }
        binding_by_name[name] = binding
        bindings.append(binding)
    bindings.sort(key=lambda value: str(value["name"]))
    if (len(bindings) != 92 or
            sum(value["branch"] == "generated_compatibility" for value in bindings) != 88 or
            sum(value["branch"] == "extension" for value in bindings) != 4):
        raise LedgerError("C03 generated per-name reachability partition is invalid")
    route_lines = [
        f"R\t{node['id']}\t{node['symbol']}\t{node['file']}\t{node['line']}"
        for node in route_nodes]
    route_lines.extend(
        f"E\t{edge['caller_id']}\t{edge['callee_id']}\t{edge['file']}\t{edge['line']}\t{edge['character_offset']}\t{edge['expression']}"
        for edge in route_edges)
    route_lines.extend(
        f"T\t{operation['caller_id']}\t{operation['file']}\t{operation['line']}\t{operation['character_offset']}\t{operation['expression']}"
        for operation in terminal_operations)
    binding_lines = [
        f"{binding['name']}\t{binding['branch']}\t{binding['registrar_id']}\t{binding['chain_sha256']}"
        for binding in bindings]
    generated_route = {
        "node_count": len(route_nodes),
        "edge_count": len(route_edges),
        "terminal_operation_count": len(terminal_operations),
        "binding_count": len(bindings),
        "generated_compatibility_count": 88,
        "extension_count": 4,
        "shared_terminal_definition_id": entry_registrar["id"],
        "shared_terminal_parent_ids": sorted([
            str(generated_registrar["id"]), str(extension_registrar["id"])]),
        "nodes": route_nodes,
        "edges": route_edges,
        "terminal_operations": terminal_operations,
        "bindings": bindings,
        "route_sha256": sha256_lines(sorted(set(route_lines))),
        "binding_sha256": sha256_lines(sorted(set(binding_lines))),
    }
    return generated_route, binding_by_name


def verify_mcp_production_reachability(root: Path, mcp: dict[str, Any],
                                       authority: dict[str, Any],
                                       generated_rows: dict[str, dict[str, Any]]) -> dict[str, Any]:
    policy = require_object(mcp.get("production_reachability"),
                            "current MCP production reachability")
    if policy.get("schema_version") != 1:
        raise LedgerError("current MCP production reachability schema is invalid")
    registrations = require_array(mcp.get("registrations"),
                                  "current MCP reachability registrations")
    (entry, registrar_rows, edge_rows, chains, definitions, sources, masks,
     root_definition, route_entry, registration_terminal_offsets) = \
        derive_cpp_reachability_graph(root, registrations)
    expected_registration_count = authority.get("legacy_resolved_count")
    if (not isinstance(expected_registration_count, int) or
            isinstance(expected_registration_count, bool) or
            expected_registration_count <= 0 or
            len(registrations) != expected_registration_count):
        raise LedgerError("current MCP reachability registration cardinality is invalid")
    if root_definition["file"] != authority.get("production_entry_source"):
        raise LedgerError("current MCP root registrar source differs from its authority contract")
    if require_object(policy.get("production_entry"),
                      "current MCP production entry") != entry:
        raise LedgerError("current MCP production entry identity is invalid")
    observed_registrars = require_array(policy.get("registrars"),
                                        "current MCP reachable registrars")
    observed_edges = require_array(policy.get("edges"), "current MCP registrar edges")
    if observed_registrars != registrar_rows or observed_edges != edge_rows:
        raise LedgerError("current MCP registrar graph differs from independently derived source reachability")
    registrar_ids = [str(value.get("id", "")) for value in observed_registrars
                     if isinstance(value, dict)]
    if len(registrar_ids) != len(observed_registrars):
        raise LedgerError("current MCP reachable registrar row is malformed")
    reachable_ids = require_unique(registrar_ids, "current MCP reachable registrar identities")
    graph_lines = [
        f"R\t{value['id']}\t{value['symbol']}\t{value['file']}\t{value['line']}\t{value['parent_id'] or ''}"
        for value in registrar_rows
    ]
    graph_lines.extend(
        f"E\t{value['caller_id']}\t{value['callee_id']}\t{value['file']}\t{value['line']}\t{value['character_offset']}\t{value['expression']}"
        for value in edge_rows)
    graph_hash = sha256_lines(sorted(set(graph_lines)))
    if policy.get("reachable_registrar_count") != len(registrar_rows) or policy.get("registrar_edge_count") != len(edge_rows) or policy.get("registrar_graph_sha256") != graph_hash:
        raise LedgerError("current MCP registrar graph cardinality or identity is invalid")
    generated_route_expected, generated_bindings = derive_generated_compatibility_route(
        root, definitions, sources, masks, root_definition, edge_rows, route_entry,
        registration_terminal_offsets, generated_rows)
    generated_route = require_object(policy.get("generated_route"),
                                     "current generated MCP production route")
    if generated_route != generated_route_expected:
        raise LedgerError("current generated MCP production route differs from independently derived source evidence")
    for name, row in generated_rows.items():
        observed_binding = require_object(
            row.get("production_reachability"),
            f"current generated MCP registration {name} reachability")
        if observed_binding != generated_bindings[name]:
            raise LedgerError(
                f"current generated MCP registration {name} has invalid production reachability")
    definition_by_id = {str(value["id"]): value for value in definitions}
    direct_count = 0
    projection_count = 0
    row_lines: list[str] = []
    for value in registrations:
        registration = require_object(value, "current MCP reachability registration")
        name = registration.get("name")
        if not isinstance(name, str) or not name:
            raise LedgerError("current MCP reachability registration has an invalid name")
        source_record = require_object(registration.get("source"),
                                       f"current MCP registration {name} source")
        relative = source_record.get("file")
        offset = source_record.get("character_offset")
        if not isinstance(relative, str) or not isinstance(offset, int) or isinstance(offset, bool):
            raise LedgerError(f"current MCP registration {name} lacks an exact source offset")
        reachability = require_object(registration.get("production_reachability"),
                                      f"current MCP registration {name} reachability")
        if offset >= 0:
            if relative not in sources or relative not in masks:
                raise LedgerError(f"current MCP registration {name} source is outside the registrar graph")
            source = sources[relative]
            mask = masks[relative]
            if offset >= len(mask) or source_line(source, offset) != source_record.get("line"):
                raise LedgerError(f"current MCP registration {name} source offset or line is invalid")
            identity = cpp_registrar_terminal_identity(
                relative, mask, offset, f"current MCP registration {name!r}")
            identity_offset = int(identity["character_offset"])
            if source_line(source, identity_offset) != source_record.get("line"):
                raise LedgerError(f"current MCP registration {name} terminal line is invalid")
            opening = mask.find("(", identity_offset)
            closing = cpp_matching_index(mask, opening, "(", ")")
            evidence = source_record.get("evidence")
            if evidence != "assigned_tool_definition" and f'"{name}"' not in source[offset:closing + 1]:
                raise LedgerError(f"current MCP registration {name} call does not contain its concrete name")
            enclosing = [definition for definition in definitions
                         if definition["file"] == relative and
                         int(definition["body_start"]) < offset < int(definition["body_end"])]
            if len(enclosing) != 1:
                raise LedgerError(
                    f"current MCP registration {name} has {len(enclosing)} enclosing registrars")
            registrar = enclosing[0]
            registrar_id = str(registrar["id"])
            if registrar_id not in reachable_ids or registrar_id not in chains:
                raise LedgerError(f"current MCP registration {name} is in an unreachable registrar")
            expected_chain = chains[registrar_id]
            expected = {
                "mode": "direct_registration",
                "registrar_id": registrar_id,
                "registrar_symbol": registrar["symbol"],
                "chain": expected_chain,
                "chain_sha256": sha256_lines(expected_chain),
            }
            if reachability != expected or registrar_id not in definition_by_id:
                raise LedgerError(f"current MCP registration {name} has invalid registrar binding")
            direct_count += 1
        else:
            if offset != -1 or name not in generated_bindings:
                raise LedgerError(f"current MCP registration {name} has an invalid generated projection")
            generated_binding = generated_bindings[name]
            expected = {
                "mode": "generated_compatibility_projection",
                "generated_branch": generated_binding["branch"],
                "registrar_id": generated_binding["registrar_id"],
                "registrar_symbol": generated_binding["registrar_symbol"],
                "chain": generated_binding["chain"],
                "chain_sha256": generated_binding["chain_sha256"],
            }
            if reachability != expected:
                raise LedgerError(f"current MCP registration {name} has invalid generated route binding")
            projection_count += 1
        row_lines.append(
            f"{name}\t{reachability['mode']}\t{reachability['registrar_id']}\t{reachability['chain_sha256']}")
    row_hash = sha256_lines(sorted(set(row_lines)))
    if (policy.get("concrete_registration_count") != expected_registration_count or
            policy.get("direct_registration_count") != direct_count or
            policy.get("generated_projection_count") != projection_count or
            direct_count + projection_count != expected_registration_count or
            policy.get("row_binding_sha256") != row_hash):
        raise LedgerError("current MCP production reachability row cardinality or identity is invalid")
    expected_source_files = {str(value["file"]) for value in registrar_rows} | {
        "src/standalone/src/core/ai/standalone_chat.cpp",
        "src/standalone/src/core/mcp/mcp_standalone.cpp",
        "src/standalone/src/core/mcp/compat/c03_compatibility_registration.cpp",
        "src/standalone/src/core/mcp/compat/mcp_server_integration.cpp",
    }
    source_files = require_array(policy.get("source_files"),
                                 "current MCP reachability source files")
    if require_unique(source_files, "current MCP reachability source files") != expected_source_files:
        raise LedgerError("current MCP reachability source inventory is invalid")
    return {
        "production_entry": entry,
        "concrete_registration_count": len(registrations),
        "direct_registration_count": direct_count,
        "generated_projection_count": projection_count,
        "reachable_registrar_count": len(registrar_rows),
        "registrar_edge_count": len(edge_rows),
        "row_binding_sha256": row_hash,
        "registrar_graph_sha256": graph_hash,
        "generated_route_node_count": generated_route_expected["node_count"],
        "generated_route_edge_count": generated_route_expected["edge_count"],
        "generated_terminal_operation_count": generated_route_expected["terminal_operation_count"],
        "generated_binding_count": generated_route_expected["binding_count"],
        "generated_compatibility_count": generated_route_expected["generated_compatibility_count"],
        "generated_extension_count": generated_route_expected["extension_count"],
        "generated_route_sha256": generated_route_expected["route_sha256"],
        "generated_binding_sha256": generated_route_expected["binding_sha256"],
    }


def verify_c03_descriptor_contracts(ledger: dict[str, Any], root: Path) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]], list[str]]:
    generation = ledger["contract_generation"]
    descriptor_hashes = require_object(generation.get("descriptor_artifact_sha256"),
                                       "descriptor artifact hash inventory")
    documents: dict[str, dict[str, Any]] = {}
    for relative, expected_hash in descriptor_hashes.items():
        path = resolve_repository_file(root, relative, "generated MCP descriptor")
        if not isinstance(expected_hash, str) or sha256_file(path) != expected_hash:
            raise LedgerError(f"generated MCP descriptor identity mismatch: {relative}")
        documents[Path(relative).name] = load_json(path)
    contracts_document = documents.get("contracts.json")
    effects_document = documents.get("effect_ledger.json")
    archive_manifest = documents.get("archive_manifest.json")
    if not contracts_document or not effects_document or not archive_manifest:
        raise LedgerError("generated MCP descriptor set is incomplete")
    if contracts_document.get("schema_version") != 1 or effects_document.get("schema_version") != 1 or archive_manifest.get("schema_version") != 1:
        raise LedgerError("generated MCP descriptor schema version is invalid")
    compatibility = ledger["mcp_compatibility"]
    required_names = compatibility["required_compatibility_names"]
    extension_names = compatibility["preserved_aida_extensions"]
    union_names = required_names + extension_names
    contract_names = require_array(contracts_document.get("compatibility_names"),
                                   "generated MCP compatibility names")
    if require_unique(contract_names, "generated MCP compatibility names") != set(required_names) or len(contract_names) != 88:
        raise LedgerError("generated MCP contract compatibility inventory is invalid")
    if contracts_document.get("excluded_tools") != ["py_eval"]:
        raise LedgerError("generated MCP contract exclusion policy is invalid")
    archive_compatibility = require_array(archive_manifest.get("compatibility_names"),
                                          "generated MCP archive compatibility names")
    archive_extensions = require_array(archive_manifest.get("aida_extensions"),
                                       "generated MCP archive extensions")
    archive_union = require_array(archive_manifest.get("union_names"),
                                  "generated MCP archive union")
    if require_unique(archive_compatibility, "generated MCP archive compatibility names") != set(required_names) or len(archive_compatibility) != 88 or archive_extensions != extension_names or require_unique(archive_union, "generated MCP archive union") != set(union_names) or len(archive_union) != 92:
        raise LedgerError("generated MCP archive manifest inventory is invalid")
    if archive_manifest.get("archive_tool_count") != 88 or archive_manifest.get("compatibility_tool_count") != 88 or archive_manifest.get("aida_extension_count") != 4 or archive_manifest.get("union_tool_count") != 92:
        raise LedgerError("generated MCP archive manifest cardinality is invalid")
    contracts: dict[str, dict[str, Any]] = {}
    for value in require_array(contracts_document.get("contracts"), "generated MCP contracts"):
        contract = require_object(value, "generated MCP contract")
        name = contract.get("name")
        if not isinstance(name, str) or not name or name in contracts:
            raise LedgerError("generated MCP contracts contain an invalid or duplicate name")
        for field in ("description", "adapter_symbol", "effect", "lock"):
            if not isinstance(contract.get(field), str) or not contract[field]:
                raise LedgerError(f"generated MCP contract {name} has invalid {field}")
        if not contract["adapter_symbol"].startswith("aida::standalone::mcp::compat::adapters::"):
            raise LedgerError(f"generated MCP contract {name} has an invalid adapter binding")
        for field in ("input_schema", "output_schema", "annotations", "routing"):
            require_object(contract.get(field), f"generated MCP contract {name} {field}")
            reject_external_refs(contract[field], f"generated MCP contract {name} {field}")
        routing = contract["routing"]
        routing_fields = [require_object(field, f"generated MCP contract {name} routing field").get("name")
                          for field in require_array(routing.get("fields"), f"generated MCP contract {name} routing fields")]
        if not all(isinstance(field, str) and field for field in routing_fields):
            raise LedgerError(f"generated MCP contract {name} has a malformed routing field")
        require_unique(routing_fields, f"generated MCP contract {name} routing fields")
        if routing.get("target_dependent") is True and set(routing_fields) != {"pid", "bin_name"}:
            raise LedgerError(f"target-dependent generated MCP contract {name} lacks exact additive selectors")
        if routing.get("target_dependent") is not True and routing_fields:
            raise LedgerError(f"target-independent generated MCP contract {name} exposes routing selectors")
        contracts[name] = contract
    if set(contracts) != set(required_names) or len(contracts) != 88:
        raise LedgerError("generated MCP contract ledger must contain exactly 88 required names")
    effects: dict[str, dict[str, Any]] = {}
    for value in require_array(effects_document.get("contracts"), "generated MCP effects"):
        effect = require_object(value, "generated MCP effect")
        name = effect.get("name")
        if not isinstance(name, str) or not name or name in effects:
            raise LedgerError("generated MCP effects contain an invalid or duplicate name")
        effects[name] = effect
    if set(effects) != set(contracts):
        raise LedgerError("generated MCP effect ledger does not match the contract ledger")
    for name, contract in contracts.items():
        effect = effects[name]
        for field in ("adapter_symbol", "effect", "lock", "read_only", "unsafe"):
            if contract.get(field) != effect.get(field):
                raise LedgerError(f"generated MCP effect mismatch for {name} field {field}")
        routing_fields = [field["name"] for field in contract["routing"]["fields"]]
        if effect.get("target_dependent") != contract["routing"].get("target_dependent") or effect.get("routing_fields") != routing_fields:
            raise LedgerError(f"generated MCP routing effect mismatch for {name}")
    return contracts, effects, union_names


def verify_current_surface_reproduction(ledger: dict[str, Any], root: Path,
                                        powershell_path: Path) -> dict[str, Any]:
    policy = ledger["current_surface_reproduction"]
    generator_path = verify_hash_record(root, policy["generator"], "standalone surface generator")
    baseline_path = verify_hash_record(root, policy["baseline"], "historical standalone surface baseline")
    checked_in_path = resolve_repository_file(
        root, policy.get("checked_in_path"), "checked-in standalone surface inventory")
    generator_before = executable_identity(generator_path)
    with tempfile.TemporaryDirectory(prefix="aida-c03-surface-reproduction-") as directory:
        output_path = Path(directory) / "standalone_surface_current.json"
        powershell_before = executable_identity(powershell_path)
        run_checked([
            str(powershell_path), "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
            "-File", str(generator_path), "-RepositoryRoot", str(root), "-OutputPath", str(output_path),
            "-BaselinePath", str(baseline_path),
        ], "standalone surface reproduction", 300)
        if executable_identity(powershell_path) != powershell_before:
            raise LedgerError("PowerShell interpreter identity changed during surface reproduction")
        if executable_identity(generator_path) != generator_before:
            raise LedgerError("standalone surface generator identity changed during reproduction")
        if not output_path.is_file():
            raise LedgerError("standalone surface reproduction produced no inventory")
        reproduced = output_path.read_bytes()
        checked_in = checked_in_path.read_bytes()
        if reproduced != checked_in:
            raise LedgerError("checked-in standalone surface inventory is stale relative to current source")
        current = load_json(output_path)
    contract_rows, effects, union_order = verify_c03_descriptor_contracts(ledger, root)
    contract = ledger["current_surface_contract"]
    mcp_contract = contract["mcp"]
    mcp = require_object(current.get("mcp"), "current standalone MCP surface")
    registrations = require_array(mcp.get("registrations"), "current standalone MCP registrations")
    names = [require_object(record, "current standalone MCP registration").get("name")
             for record in registrations]
    if not all(isinstance(name, str) and name for name in names):
        raise LedgerError("current standalone surface has malformed MCP registrations")
    current_names = require_unique(names, "current standalone MCP surface")
    if len(current_names) != mcp_contract["legacy_resolved_count"] or mcp.get("registration_count") != len(current_names) or mcp.get("unique_name_count") != len(current_names):
        raise LedgerError("current standalone legacy MCP registration cardinality is invalid")
    if mcp.get("duplicate_names") != []:
        raise LedgerError("current standalone legacy MCP registration surface contains duplicates")
    unresolved = require_array(mcp.get("dynamic_registration_templates"),
                               "unresolved MCP registration templates")
    if unresolved or mcp.get("unresolved_registration_count") != mcp_contract["unresolved_registration_count"]:
        raise LedgerError("current standalone surface contains unresolved public MCP registrations")
    helper_rows = require_array(mcp.get("resolved_registration_helpers"),
                                "resolved MCP registration helpers")
    helpers: dict[str, dict[str, Any]] = {}
    for value in helper_rows:
        row = require_object(value, "resolved MCP registration helper")
        name = row.get("helper")
        if not isinstance(name, str) or not name or name in helpers:
            raise LedgerError("resolved MCP registration helper inventory is invalid or duplicated")
        concrete_names = require_array(row.get("concrete_registration_names"),
                                       f"resolved MCP registration helper {name} concrete names")
        concrete_set = require_unique(concrete_names,
                                      f"resolved MCP registration helper {name} concrete names")
        if row.get("expression") != "alias" or row.get("concrete_registration_count") != len(concrete_set):
            raise LedgerError(f"resolved MCP registration helper evidence is invalid: {name}")
        missing_concrete = concrete_set.difference(current_names)
        if missing_concrete:
            raise LedgerError(f"resolved MCP registration helper {name} names are absent from the public surface")
        helpers[name] = row
    expected_helpers = mcp_contract["resolved_helpers"]
    if set(helpers) != set(expected_helpers) or any(
        helpers[name].get("concrete_registration_count") != count
        for name, count in expected_helpers.items()
    ) or mcp.get("resolved_helper_template_count") != mcp_contract["resolved_helper_template_count"] or mcp.get("resolved_helper_registration_count") != mcp_contract["resolved_helper_registration_count"] or sum(expected_helpers.values()) != mcp_contract["resolved_helper_registration_count"]:
        raise LedgerError("resolved MCP registration helper cardinality is invalid")
    compatibility = ledger["mcp_compatibility"]
    required_union = set(compatibility["required_compatibility_names"]) | set(compatibility["preserved_aida_extensions"])
    generated_names = require_array(mcp.get("generated_union_names"), "generated MCP union names")
    generated_set = require_unique(generated_names, "generated MCP union names")
    if generated_names != sorted(union_order) or generated_set != required_union or mcp.get("generated_registration_count") != mcp_contract["generated_registration_count"] or len(generated_set) != 92:
        raise LedgerError("current standalone generated MCP union is invalid")
    overlap = current_names & generated_set
    generated_only = generated_set - current_names
    effective = current_names | generated_set
    expected_sets = (
        ("generated_overlap_names", overlap, "generated_overlap_count", "generated_overlap_count"),
        ("generated_only_names", generated_only, "generated_only_count", "generated_only_count"),
        ("effective_registration_names", effective, "effective_registration_count", "effective_registration_count"),
    )
    for names_field, expected_set, count_field, contract_count_field in expected_sets:
        observed_names = require_array(mcp.get(names_field), f"current standalone {names_field}")
        observed_set = require_unique(observed_names, f"current standalone {names_field}")
        if observed_set != expected_set or mcp.get(count_field) != len(expected_set) or len(expected_set) != mcp_contract[contract_count_field]:
            raise LedgerError(f"current standalone {names_field} inventory is invalid")
    if "py_eval" in effective:
        raise LedgerError("current standalone surface exposes excluded py_eval")
    source_contracts = require_object(current.get("source_contracts"), "current standalone source contracts")
    compatibility_surface = require_object(source_contracts.get("ida_compatibility"),
                                           "current generated MCP compatibility surface")
    compatibility_rows = require_array(compatibility_surface.get("registrations"),
                                       "current generated MCP compatibility registrations")
    rows_by_name: dict[str, dict[str, Any]] = {}
    for value in compatibility_rows:
        row = require_object(value, "current generated MCP compatibility registration")
        name = row.get("name")
        if not isinstance(name, str) or not name or name in rows_by_name:
            raise LedgerError("current generated MCP compatibility registrations contain an invalid or duplicate name")
        rows_by_name[name] = row
    if set(rows_by_name) != required_union or compatibility_surface.get("registration_count") != 92 or compatibility_surface.get("archive_backed_count") != mcp_contract["archive_backed_count"] or compatibility_surface.get("proxy_local_count") != mcp_contract["proxy_local_count"] or compatibility_surface.get("extension_count") != mcp_contract["extension_count"]:
        raise LedgerError("current generated MCP compatibility row cardinality is invalid")
    surface_union = require_array(compatibility_surface.get("union_names"),
                                  "current generated MCP compatibility union")
    if require_unique(surface_union, "current generated MCP compatibility union") != required_union or len(surface_union) != 92:
        raise LedgerError("current generated MCP compatibility union does not match the authority ledger")
    reachability_report = verify_mcp_production_reachability(
        root, mcp, mcp_contract, rows_by_name)
    domains = require_object(mcp_contract.get("domains"), "MCP compatibility domain contract")
    domain_for_name: dict[str, str] = {}
    expected_domain_records: dict[str, dict[str, Any]] = {}
    for domain_name, value in domains.items():
        domain = require_object(value, f"MCP compatibility domain {domain_name}")
        handler_path = resolve_repository_file(
            root, domain.get("handler"), f"MCP compatibility domain {domain_name} handler")
        fixture_path = resolve_repository_file(
            root, domain.get("fixture"), f"MCP compatibility domain {domain_name} fixture")
        for marker_field in ("handler_marker", "fixture_marker"):
            if not isinstance(domain.get(marker_field), str) or not domain[marker_field]:
                raise LedgerError(f"MCP compatibility domain {domain_name} has an invalid {marker_field}")
        handler_source = handler_path.read_text(encoding="utf-8")
        fixture_source = fixture_path.read_text(encoding="utf-8")
        if domain["handler_marker"] not in handler_source or domain["fixture_marker"] not in fixture_source:
            raise LedgerError(f"MCP compatibility domain marker is unavailable: {domain_name}")
        names_in_domain = require_array(domain.get("names"), f"MCP compatibility domain {domain_name} names")
        for name in names_in_domain:
            if not isinstance(name, str) or not name or name in domain_for_name:
                raise LedgerError("MCP compatibility domain partition contains an invalid or duplicate name")
            if f'"{name}"' not in handler_source or f'"{name}"' not in fixture_source:
                raise LedgerError(f"MCP compatibility tool lacks a production handler or functional fixture: {name}")
            domain_for_name[name] = domain_name
        expected_domain_records[domain_name] = domain
    if set(domain_for_name) != required_union:
        raise LedgerError("MCP compatibility domain partition does not cover the 92-name union")
    manifest_domains = require_array(compatibility_surface.get("domains"), "current generated MCP domains")
    manifest_domain_names: set[str] = set()
    for value in manifest_domains:
        row = require_object(value, "current generated MCP domain")
        domain_name = row.get("domain")
        if not isinstance(domain_name, str) or domain_name in manifest_domain_names or domain_name not in expected_domain_records:
            raise LedgerError("current generated MCP domains contain an invalid or duplicate domain")
        manifest_domain_names.add(domain_name)
        expected = expected_domain_records[domain_name]
        manifest_names = require_array(row.get("names"),
                                       f"current generated MCP domain {domain_name} names")
        if require_unique(manifest_names, f"current generated MCP domain {domain_name} names") != set(expected["names"]) or row.get("production_handler") != expected["handler"] or row.get("handler_marker") != expected["handler_marker"] or row.get("functional_fixture") != expected["fixture"] or row.get("fixture_marker") != expected["fixture_marker"]:
            raise LedgerError(f"current generated MCP domain record is invalid: {domain_name}")
    if manifest_domain_names != set(domains):
        raise LedgerError("current generated MCP domain inventory is incomplete")
    extension_policy = {
        "analyze_funcs": ("workspace_overlay_mutation", "workspace_overlay_transaction", True, True, False),
        "find_insns": ("workspace_read", "workspace_shared", True, True, True),
        "calculator": ("registry_read", "registry_read", False, False, True),
        "calculate": ("registry_read", "registry_read", False, False, True),
    }
    descriptor_path = "src/standalone/src/resources/mcp/ida_pro_mcp_2_0_0/contracts.json"
    for name, row in rows_by_name.items():
        domain = expected_domain_records[domain_for_name[name]]
        if row.get("domain") != domain_for_name[name] or row.get("production_handler") != domain["handler"] or row.get("functional_fixture") != domain["fixture"]:
            raise LedgerError(f"current generated MCP row has invalid production evidence: {name}")
        if name in contract_rows:
            generated = contract_rows[name]
            effect = effects[name]
            routing_fields = {field["name"] for field in generated["routing"]["fields"]}
            expected_values = {
                "descriptor_source": descriptor_path,
                "adapter_symbol": generated["adapter_symbol"],
                "effect": generated["effect"],
                "lock": generated["lock"],
                "target_dependent": generated["routing"]["target_dependent"],
                "accepts_pid": "pid" in routing_fields,
                "accepts_bin_name": "bin_name" in routing_fields,
                "read_only": generated["read_only"],
                "unsafe": generated["unsafe"],
            }
            if any(row.get(field) != expected for field, expected in expected_values.items()):
                raise LedgerError(f"current generated MCP row disagrees with its descriptor: {name}")
            if effect["effect"] != row["effect"]:
                raise LedgerError(f"current generated MCP row disagrees with its effect ledger: {name}")
        else:
            effect, lock, target_dependent, accepts_selectors, read_only = extension_policy[name]
            expected_values = {
                "adapter_symbol": f"aida::standalone::mcp::compat::adapters::{name}",
                "effect": effect,
                "lock": lock,
                "target_dependent": target_dependent,
                "accepts_pid": accepts_selectors,
                "accepts_bin_name": accepts_selectors,
                "read_only": read_only,
                "unsafe": False,
            }
            if any(row.get(field) != expected for field, expected in expected_values.items()):
                raise LedgerError(f"current AiDA extension row has invalid effect or routing policy: {name}")
    artifacts = require_object(compatibility_surface.get("descriptor_artifacts"),
                               "current generated MCP descriptor artifacts")
    descriptor_hashes = ledger["contract_generation"]["descriptor_artifact_sha256"]
    artifact_keys = {"contracts": "contracts.json", "effects": "effect_ledger.json", "archive_manifest": "archive_manifest.json"}
    for key, leaf in artifact_keys.items():
        record = require_object(artifacts.get(key), f"current generated MCP descriptor artifact {key}")
        expected_path = next(path for path in descriptor_hashes if Path(path).name == leaf)
        if record.get("path") != expected_path or record.get("sha256", "").upper() != descriptor_hashes[expected_path]:
            raise LedgerError(f"current generated MCP descriptor artifact identity is invalid: {key}")
    source_parts = []
    for field in ("production_entry_source", "registration_source", "server_integration_source"):
        path = resolve_repository_file(root, mcp_contract.get(field),
                                       f"MCP compatibility {field}")
        source_parts.append(path.read_text(encoding="utf-8"))
    production_source = "\n".join(source_parts)
    for marker in mcp_contract["production_entry_markers"]:
        if marker not in production_source:
            raise LedgerError(f"MCP compatibility production marker is unavailable: {marker}")
    if "register_ida_compatibility_tools(srv)" in production_source or "install_ida_compat_schema_validation();" in production_source:
        raise LedgerError("removed legacy MCP compatibility registration path remains reachable")
    resources = require_array(mcp.get("resources"), "current standalone MCP resources")
    if any(isinstance(record, dict) and str(record.get("uri", "")).startswith("ida://") for record in resources):
        raise LedgerError("current standalone surface exposes forbidden ida:// resources")
    public = require_object(current.get("public_surfaces"), "current standalone public surfaces")
    commands = require_object(public.get("commands"), "current built-in command surface")
    command_names = require_array(commands.get("builtin_names"), "current built-in command names")
    command_set = require_unique(command_names, "current built-in command names")
    baseline_commands = set(ledger["preservation_baseline"]["commands"]["builtin_names"])
    if command_set != baseline_commands or commands.get("builtin_count") != contract["commands"]["builtin_count"] or commands.get("dynamic_producers") != contract["commands"]["dynamic_producers"]:
        raise LedgerError("current built-in command surface is invalid")
    test_lab = require_object(public.get("test_lab"), "current Test Lab surface")
    features = require_array(test_lab.get("features"), "current Test Lab features")
    feature_ids = [f"{require_object(value, 'current Test Lab feature').get('category')}:{value.get('name')}"
                   for value in features]
    feature_set = require_unique(feature_ids, "current Test Lab features")
    baseline_features = set(ledger["preservation_baseline"]["test_lab"]["feature_ids"])
    if not baseline_features.issubset(feature_set) or not set(contract["test_lab"]["required_additive_features"]).issubset(feature_set) or len(feature_set) < contract["test_lab"]["minimum_feature_count"] or test_lab.get("feature_count") != len(feature_set):
        raise LedgerError("current Test Lab surface is missing baseline or C03 features")
    workbench = require_object(public.get("workbench"), "current workbench surface")
    if workbench.get("analysis_document_kinds") != contract["workbench"]["analysis_document_kinds"] or workbench.get("analysis_document_count") != len(contract["workbench"]["analysis_document_kinds"]) or workbench.get("default_analysis_document") != contract["workbench"]["default_analysis_document"] or workbench.get("per_workspace_persistence") != contract["workbench"]["per_workspace_persistence"]:
        raise LedgerError("current workbench public surface is invalid")
    overlay = require_object(public.get("overlay"), "current overlay surface")
    operations = require_array(overlay.get("operations"), "current overlay operations")
    operation_names = [require_object(value, "current overlay operation").get("name") for value in operations]
    operation_ordinals = [value.get("ordinal") for value in operations]
    overlay_contract = contract["overlay"]
    if operation_names != overlay_contract["operations"] or operation_ordinals != list(range(18)) or overlay.get("operation_count") != 18:
        raise LedgerError("current overlay operation ordinal surface is invalid")
    for field in ("legacy_ordinal_min", "legacy_ordinal_max", "appended_ordinal_min", "appended_ordinal_max"):
        if overlay.get(field) != overlay_contract[field]:
            raise LedgerError(f"current overlay boundary is invalid: {field}")
    dead_paths = require_object(public.get("dead_paths"), "current dead-path reconciliation")
    absent_paths = require_array(dead_paths.get("absent_paths"), "current absent C03 paths")
    replacement_paths = require_array(dead_paths.get("replacement_paths"),
                                      "current replacement C03 paths")
    if require_unique(absent_paths, "current absent C03 paths") != set(contract["dead_paths"]["absent"]) or require_unique(replacement_paths, "current replacement C03 paths") != set(contract["dead_paths"]["replacements"]):
        raise LedgerError("current dead-path reconciliation inventory is invalid")
    for relative in contract["dead_paths"]["absent"]:
        if not isinstance(relative, str) or not relative or Path(relative).is_absolute() or ".." in Path(relative).parts:
            raise LedgerError(f"removed C03 path contract is invalid: {relative}")
        if (root / relative).exists():
            raise LedgerError(f"removed C03 path exists: {relative}")
    for relative in contract["dead_paths"]["replacements"]:
        resolve_repository_file(root, relative, "required C03 replacement path")
    retirement_rows = require_array(dead_paths.get("retirements"), "current C03 retirement responsibilities")
    retirement_by_responsibility: dict[str, dict[str, Any]] = {}
    for value in retirement_rows:
        row = require_object(value, "current C03 retirement responsibility")
        responsibility = row.get("responsibility")
        if not isinstance(responsibility, str) or not responsibility or responsibility in retirement_by_responsibility:
            raise LedgerError("current C03 retirement responsibilities are invalid or duplicated")
        retirement_by_responsibility[responsibility] = row
    expected_responsibilities = contract["dead_paths"]["responsibilities"]
    if set(retirement_by_responsibility) != set(expected_responsibilities):
        raise LedgerError("current C03 retirement responsibility inventory is incomplete")
    cmake_record = require_object(dead_paths.get("cmake_graph"), "current C03 retirement CMake graph")
    cmake_path = resolve_repository_file(root, cmake_record.get("path"),
                                         "current C03 retirement CMake graph")
    cmake_source = cmake_path.read_text(encoding="utf-8")
    observed_cmake_markers: set[str] = set()
    for responsibility, expected in expected_responsibilities.items():
        row = retirement_by_responsibility[responsibility]
        if set(row.get("retired_paths", [])) != set(expected["retired"]) or set(row.get("replacement_paths", [])) != set(expected["replacements"]):
            raise LedgerError(f"current C03 retirement mapping is invalid: {responsibility}")
        markers = require_array(row.get("cmake_markers"),
                                f"current C03 retirement {responsibility} CMake markers")
        if not markers or not all(isinstance(marker, str) and marker for marker in markers):
            raise LedgerError(f"current C03 retirement has malformed CMake markers: {responsibility}")
        marker_set = require_unique(markers,
                                    f"current C03 retirement {responsibility} CMake markers")
        if observed_cmake_markers.intersection(marker_set):
            raise LedgerError(f"current C03 retirement reuses a CMake marker: {responsibility}")
        if any(marker not in cmake_source for marker in markers):
            raise LedgerError(f"current C03 retirement lacks executable CMake graph evidence: {responsibility}")
        observed_cmake_markers.update(marker_set)
    if cmake_record.get("marker_count") != len(observed_cmake_markers) or cmake_record.get("marker_sha256") != sha256_lines(sorted(observed_cmake_markers)):
        raise LedgerError("current C03 retirement CMake graph marker identity is invalid")
    replacement_rows = require_array(dead_paths.get("replacement_evidence"),
                                     "current C03 replacement evidence")
    replacement_by_path: dict[str, dict[str, Any]] = {}
    for value in replacement_rows:
        row = require_object(value, "current C03 replacement evidence row")
        relative = row.get("path")
        if not isinstance(relative, str) or not relative or relative in replacement_by_path:
            raise LedgerError("current C03 replacement evidence is invalid or duplicated")
        path = resolve_repository_file(root, relative, "current C03 replacement evidence")
        if sha256_file(path) != str(row.get("sha256", "")).upper():
            raise LedgerError(f"current C03 replacement source identity is invalid: {relative}")
        expected_owners = sorted(
            responsibility for responsibility, expected in expected_responsibilities.items()
            if relative in expected["replacements"]
        )
        if row.get("responsibilities") != expected_owners:
            raise LedgerError(f"current C03 replacement responsibility is invalid: {relative}")
        replacement_by_path[relative] = row
    if set(replacement_by_path) != set(contract["dead_paths"]["replacements"]):
        raise LedgerError("current C03 replacement source identity inventory is incomplete")
    evidence_hashes = require_array(current.get("evidence_source_hashes"),
                                    "current surface evidence hashes")
    evidence_paths: set[str] = set()
    for value in evidence_hashes:
        record = require_object(value, "current surface evidence hash")
        relative = record.get("file")
        expected = record.get("sha256")
        if not isinstance(relative, str) or not relative or relative in evidence_paths or not isinstance(expected, str):
            raise LedgerError("current surface evidence hash inventory is malformed or duplicated")
        evidence_paths.add(relative)
        path = resolve_repository_file(root, relative, "current surface evidence source")
        if sha256_file(path) != expected.upper():
            raise LedgerError(f"current surface evidence source identity mismatch: {relative}")
    return {
        "generator_sha256": generator_before[4],
        "powershell": {"path": str(powershell_path), "sha256": powershell_before[4]},
        "baseline_sha256": sha256_file(baseline_path),
        "current_surface_sha256": hashlib.sha256(checked_in).hexdigest().upper(),
        "legacy_registration_count": len(current_names),
        "generated_registration_count": len(generated_set),
        "generated_overlap_count": len(overlap),
        "generated_only_count": len(generated_only),
        "effective_registration_count": len(effective),
        "resolved_helper_template_count": len(helpers),
        "resolved_helper_registration_count": sum(
            row["concrete_registration_count"] for row in helpers.values()),
        "unresolved_registration_count": len(unresolved),
        "required_union_count": len(required_union),
        "builtin_command_count": len(command_set),
        "test_lab_feature_count": len(feature_set),
        "workbench_analysis_document_count": len(workbench["analysis_document_kinds"]),
        "overlay_operation_count": len(operations),
        "evidence_source_count": len(evidence_paths),
        "production_reachability": reachability_report,
    }


def verify_archive_contract(ledger: dict[str, Any], archive_path: Path) -> dict[str, Any]:
    authority = ledger["authority"]
    archive = authority["pinned_ida_pro_mcp_archive"]
    expected_hash = archive["sha256"]
    archive_before = executable_identity(archive_path)
    actual_hash = archive_before[4]
    if actual_hash != expected_hash:
        raise LedgerError(f"pinned archive SHA-256 mismatch: expected {expected_hash}, observed {actual_hash}")
    observed_version, observed_tools = archive_tool_names(archive_path)
    if executable_identity(archive_path) != archive_before:
        raise LedgerError("pinned archive identity changed during inspection")
    if observed_version != archive["version"]:
        raise LedgerError(f"pinned archive version mismatch: expected {archive['version']}, observed {observed_version}")
    archive_license = archive.get("license")
    if archive_license is None:
        raise LedgerError("pinned archive ledger is missing the license field")
    if archive_license != "MIT":
        raise LedgerError(f"pinned archive license must be MIT, observed {archive_license}")
    compatibility = ledger["mcp_compatibility"]
    upstream = compatibility["upstream_tool_names"]
    upstream_set = require_unique(upstream, "upstream tool ledger")
    if len(upstream) != compatibility["upstream_tool_count"] or len(upstream) != 88:
        raise LedgerError(f"upstream tool count must be 88, observed {len(upstream)}")
    if observed_tools != sorted(upstream):
        raise LedgerError("pinned archive tool inventory does not match the checked-in ledger")
    exclusions = compatibility["explicit_excluded_tools"]
    if exclusions != ["py_eval"]:
        raise LedgerError("py_eval must be the only excluded upstream tool")
    if "py_eval" not in upstream_set:
        raise LedgerError("upstream tool ledger does not contain py_eval")
    local_tools = compatibility["proxy_local_compatibility_tools"]
    if local_tools != ["list_instances"]:
        raise LedgerError("list_instances must be the only proxy-local compatibility tool")
    required = compatibility["required_compatibility_names"]
    required_set = require_unique(required, "required compatibility ledger")
    expected_required = (upstream_set - {"py_eval"}) | {"list_instances"}
    if required_set != expected_required or len(required) != compatibility["required_compatibility_count"] or len(required) != 88:
        raise LedgerError("required compatibility ledger must contain exactly 88 names including list_instances")
    extensions = compatibility["preserved_aida_extensions"]
    extension_set = require_unique(extensions, "AiDA extension ledger")
    if extensions != ["analyze_funcs", "find_insns", "calculator", "calculate"]:
        raise LedgerError("AiDA extension ledger must preserve analyze_funcs, find_insns, calculator, calculate")
    if required_set & extension_set:
        raise LedgerError("AiDA extension ledger overlaps compatibility names")
    union = required_set | extension_set
    if len(union) != compatibility["compatibility_extension_union_count"] or len(union) != 92:
        raise LedgerError("compatibility-plus-extension union must contain exactly 92 names")
    return {
        "archive_path": str(archive_path),
        "archive_sha256": actual_hash,
        "archive_version": observed_version,
        "archive_license": archive_license,
        "upstream_tool_count": len(upstream_set),
        "excluded_tools": exclusions,
        "required_compatibility_count": len(required_set),
        "preserved_aida_extensions": extensions,
        "compatibility_extension_union_count": len(union),
        "compatibility_extension_union_names": sorted(union),
    }


def verify_preservation_baseline(ledger: dict[str, Any], root: Path) -> dict[str, Any]:
    baseline = ledger["preservation_baseline"]
    manifest = baseline["source_manifest"]
    manifest_path = root / manifest["path"]
    if sha256_file(manifest_path) != manifest["sha256"]:
        raise LedgerError("C02 source surface manifest SHA-256 does not match the preservation baseline")
    source = load_json(manifest_path)
    if source.get("schema_version") != manifest["schema_version"]:
        raise LedgerError("C02 source surface manifest schema version does not match the preservation baseline")
    mcp = source.get("mcp", {})
    registration_names = sorted(record["name"] for record in mcp.get("registrations", []))
    require_unique(registration_names, "C02 MCP registration inventory")
    expected_mcp = baseline["aida_mcp"]
    if len(registration_names) != expected_mcp["registration_count"] or len(registration_names) != expected_mcp["unique_name_count"]:
        raise LedgerError("C02 MCP registration count does not match the preservation baseline")
    if sha256_lines(registration_names) != expected_mcp["sorted_name_list_sha256"]:
        raise LedgerError("C02 MCP registration names do not match the preservation baseline")
    resource_lines = sorted(
        f"{record['uri']}\t{record['name']}\t{record['mime_type']}" for record in mcp.get("resources", [])
    )
    if resource_lines != sorted(
        f"{record['uri']}\t{record['name']}\t{record['mime_type']}" for record in expected_mcp["resources"]
    ):
        raise LedgerError("C02 MCP resources do not match the preservation baseline")
    if sha256_lines(resource_lines) != expected_mcp["resource_list_sha256"]:
        raise LedgerError("C02 MCP resource fingerprint does not match the preservation baseline")
    ui = source.get("ui", {})
    expected_ui = baseline["ui"]
    center_views = sorted(ui.get("center_views", []))
    if center_views != expected_ui["center_views"] or sha256_lines(center_views) != expected_ui["center_view_list_sha256"]:
        raise LedgerError("C02 center-view inventory does not match the preservation baseline")
    action_labels = sorted(record["label"] for record in ui.get("actions", []))
    if action_labels != expected_ui["action_labels"] or sha256_lines(action_labels) != expected_ui["action_label_list_sha256"]:
        raise LedgerError("C02 UI action inventory does not match the preservation baseline")
    shortcut_lines = [f"{record['key']}\t{record['expression']}" for record in ui.get("shortcuts", [])]
    if len(shortcut_lines) != expected_ui["shortcut_expression_count"] or sha256_lines(shortcut_lines) != expected_ui["shortcut_expression_list_sha256"]:
        raise LedgerError("C02 shortcut inventory does not match the preservation baseline")
    commands = baseline["commands"]
    command_names = commands["builtin_names"]
    require_unique(command_names, "builtin command ledger")
    if sha256_lines(command_names) != commands["builtin_name_list_sha256"]:
        raise LedgerError("builtin command inventory does not match the preservation baseline")
    test_lab = baseline["test_lab"]
    feature_ids = test_lab["feature_ids"]
    require_unique(feature_ids, "Test Lab feature ledger")
    if len(feature_ids) != test_lab["registered_feature_count"] or sha256_lines(feature_ids) != test_lab["feature_id_list_sha256"]:
        raise LedgerError("Test Lab inventory does not match the preservation baseline")
    return {
        "aida_mcp_registration_count": len(registration_names),
        "aida_mcp_resource_count": len(resource_lines),
        "center_view_count": len(center_views),
        "ui_action_count": len(action_labels),
        "shortcut_expression_count": len(shortcut_lines),
        "builtin_command_count": len(command_names),
        "test_lab_feature_count": len(feature_ids),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository-root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--ledger", type=Path, default=Path(__file__).with_name("authority_surface_ledger.json"))
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--powershell", type=Path, required=True)
    args = parser.parse_args()
    root = args.repository_root.resolve()
    ledger_path = args.ledger.resolve()
    ledger = load_json(ledger_path)
    if ledger.get("schema") != "aida.c03.authority-surface-ledger.v2":
        raise LedgerError("unsupported authority surface ledger schema")
    authority = ledger["authority"]
    verifier_path = verify_hash_record(
        root, ledger["current_surface_reproduction"]["verifier"],
        "authority surface verifier")
    if not os.path.samefile(verifier_path, Path(__file__).resolve()):
        raise LedgerError("authority surface verifier hash record does not identify the running verifier")
    verifier_before = executable_identity(verifier_path)
    receipt_path = verify_hash_record(root, authority["c02_completion_receipt"], "C02 completion receipt")
    prompt_path = verify_hash_record(root, authority["c03_activation_prompt"], "C03 activation prompt")
    draft_path = verify_hash_record(root, authority["c03_draft"], "C03 draft")
    ledger_archive = Path(ledger["authority"]["pinned_ida_pro_mcp_archive"]["path"]).resolve()
    archive = (args.archive or ledger_archive).resolve()
    if archive != ledger_archive:
        raise LedgerError(f"archive argument does not identify the pinned authority path: {archive}")
    if not archive.is_file():
        raise LedgerError(f"pinned authority archive is unavailable: {archive}")
    python_path = validate_absolute_executable(Path(sys.executable), "Python interpreter")
    powershell_path = validate_absolute_executable(args.powershell, "PowerShell interpreter",
                                                   "powershell.exe")
    canonical_powershell = validate_absolute_executable(
        canonical_windows_powershell(), "Canonical PowerShell interpreter", "powershell.exe")
    if powershell_path != canonical_powershell:
        raise LedgerError(
            f"PowerShell interpreter is not the canonical Windows system executable: {powershell_path}")
    archive_report = verify_archive_contract(ledger, archive)
    contract_report = verify_generated_contract_reproduction(ledger, root, archive, python_path)
    preservation_report = verify_preservation_baseline(ledger, root)
    surface_report = verify_current_surface_reproduction(ledger, root, powershell_path)
    if executable_identity(verifier_path) != verifier_before:
        raise LedgerError("authority surface verifier identity changed during verification")
    report = {
        "ledger_path": ledger_path.as_posix(),
        "ledger_sha256": sha256_file(ledger_path),
        "verifier": {"path": verifier_path.as_posix(), "sha256": verifier_before[4]},
        "authority": {
            "c02_receipt": {"path": receipt_path.as_posix(), "sha256": sha256_file(receipt_path)},
            "c03_activation_prompt": {"path": prompt_path.as_posix(), "sha256": sha256_file(prompt_path)},
            "c03_draft": {"path": draft_path.as_posix(), "sha256": sha256_file(draft_path)},
        },
        "archive": archive_report,
        "interpreters": {
            "python": {"path": str(python_path), "sha256": sha256_file(python_path)},
            "powershell": {"path": str(powershell_path), "sha256": sha256_file(powershell_path)},
        },
        "contract_reproduction": contract_report,
        "preservation_baseline": preservation_report,
        "current_surface_reproduction": surface_report,
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except LedgerError as error:
        print(f"authority surface ledger verification failed: {error}", file=sys.stderr)
        raise SystemExit(1)
