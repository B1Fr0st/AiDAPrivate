from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import re
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any


ARCHIVE_SHA256 = "3F7E7D9F534E3534C191D21251BBF0788DB14376C659488EA61681D48BC8D0F7"
ARCHIVE_VERSION = "2.0.0"
ARCHIVE_ROOT = "ida-pro-mcp/"
SOURCE_ROOT = "ida-pro-mcp/src/ida_pro_mcp/"
EXCLUDED_TOOLS = ("py_eval",)
EXTENSION_NAMES = ("analyze_funcs", "find_insns", "calculator", "calculate")
ROUTING_DESCRIPTIONS = {
    "pid": "PID of the IDA instance to route this call to. If omitted, the default instance is used.",
    "bin_name": "Binary filename (or substring) of the IDA instance to route this call to. If omitted, the default instance is used.",
}
TARGET_INDEPENDENT_TOOL_NAMES = ("int_convert", "list_instances")
OVERLAY_MUTATION_TOOL_NAMES = (
    "add_bookmark", "set_comments", "append_comments", "patch_asm", "rename", "define_func",
    "define_code", "undefine", "force_recompile", "set_op_type", "make_data", "patch", "put_int",
    "diff_before_after", "declare_stack", "delete_stack", "declare_type", "enum_upsert", "set_type",
    "type_apply_batch",
)
MAX_ARCHIVE_MEMBERS = 4096
MAX_ARCHIVE_COMPRESSED_BYTES = 128 * 1024 * 1024
MAX_ARCHIVE_UNCOMPRESSED_BYTES = 512 * 1024 * 1024
MAX_ARCHIVE_MEMBER_BYTES = 32 * 1024 * 1024
MAX_SOURCE_MEMBER_BYTES = 4 * 1024 * 1024
MAX_SOURCE_TOTAL_BYTES = 64 * 1024 * 1024
MAX_COMPRESSION_RATIO = 200
MAX_ARCHIVE_PATH_BYTES = 1024


class ContractGenerationError(RuntimeError):
    pass


@dataclass(frozen=True)
class Location:
    path: str
    line: int
    column: int

    def format(self) -> str:
        return f"{self.path}:{self.line}:{self.column}"


@dataclass
class Module:
    name: str
    path: str
    tree: ast.Module
    imports: dict[str, str]
    definitions: dict[str, ast.AST]


def fail(message: str, node: ast.AST | None = None, module: Module | None = None) -> None:
    if node is not None and module is not None:
        line = getattr(node, "lineno", 1)
        column = getattr(node, "col_offset", 0) + 1
        raise ContractGenerationError(f"{module.path}:{line}:{column}: {message}")
    raise ContractGenerationError(message)


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n"


def canonical_json_value(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest().upper()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest().upper()


def validate_archive_members(archive: zipfile.ZipFile) -> None:
    names: set[str] = set()
    folded_names: set[str] = set()
    compressed_total = 0
    uncompressed_total = 0
    infos = archive.infolist()
    if not infos or len(infos) > MAX_ARCHIVE_MEMBERS:
        raise ContractGenerationError("archive member count exceeds the bounded inspection policy")
    for info in infos:
        name = info.filename
        path = PurePosixPath(name)
        if not name or "\x00" in name or len(name.encode("utf-8")) > MAX_ARCHIVE_PATH_BYTES:
            raise ContractGenerationError("archive contains an invalid or overlong member path")
        if name in names or name.casefold() in folded_names:
            raise ContractGenerationError(f"archive contains duplicate member {name!r}")
        names.add(name)
        folded_names.add(name.casefold())
        if path.is_absolute() or ".." in path.parts or "\\" in name or ":" in name:
            raise ContractGenerationError(f"archive contains unsafe member path {name!r}")
        unix_mode = (info.external_attr >> 16) & 0xFFFF
        if unix_mode & 0o170000 == 0o120000:
            raise ContractGenerationError(f"archive contains symbolic link member {name!r}")
        if info.flag_bits & 0x1:
            raise ContractGenerationError(f"archive contains encrypted member {name!r}")
        if info.file_size < 0 or info.compress_size < 0 or info.file_size > MAX_ARCHIVE_MEMBER_BYTES:
            raise ContractGenerationError(f"archive member exceeds the bounded size policy: {name!r}")
        if info.file_size and info.compress_size == 0:
            raise ContractGenerationError(f"archive member has an invalid zero compressed size: {name!r}")
        if info.compress_size and info.file_size > info.compress_size * MAX_COMPRESSION_RATIO:
            raise ContractGenerationError(f"archive member exceeds the compression-ratio policy: {name!r}")
        compressed_total += info.compress_size
        uncompressed_total += info.file_size
        if compressed_total > MAX_ARCHIVE_COMPRESSED_BYTES or uncompressed_total > MAX_ARCHIVE_UNCOMPRESSED_BYTES:
            raise ContractGenerationError("archive exceeds the bounded aggregate size policy")
    if not any(name.startswith(ARCHIVE_ROOT) for name in names):
        raise ContractGenerationError(f"archive root {ARCHIVE_ROOT!r} is absent")


def read_archive_sources(archive_path: Path) -> tuple[dict[str, str], dict[str, Any]]:
    actual_hash = sha256_file(archive_path)
    if actual_hash != ARCHIVE_SHA256:
        raise ContractGenerationError(
            f"pinned archive hash mismatch: expected {ARCHIVE_SHA256}, got {actual_hash}"
        )
    try:
        with zipfile.ZipFile(archive_path, "r") as archive:
            validate_archive_members(archive)
            pyproject_name = f"{ARCHIVE_ROOT}pyproject.toml"
            license_name = f"{ARCHIVE_ROOT}LICENSE"
            try:
                pyproject_text = archive.read(pyproject_name).decode("utf-8")
                license_text = archive.read(license_name).decode("utf-8")
            except KeyError as exc:
                raise ContractGenerationError(f"archive is missing required member {exc.args[0]!r}") from exc
            version_match = re.search(r'^version\s*=\s*"([^"]+)"\s*$', pyproject_text, re.MULTILINE)
            if version_match is None or version_match.group(1) != ARCHIVE_VERSION:
                raise ContractGenerationError("archive project version does not match pinned version 2.0.0")
            if "MIT License" not in license_text:
                raise ContractGenerationError("archive license is not the expected MIT license")
            sources: dict[str, str] = {}
            source_total = 0
            for info in archive.infolist():
                if not info.filename.startswith(SOURCE_ROOT) or not info.filename.endswith(".py"):
                    continue
                if info.file_size > MAX_SOURCE_MEMBER_BYTES:
                    raise ContractGenerationError(f"{info.filename}: source member exceeds the bounded size policy")
                source_total += info.file_size
                if source_total > MAX_SOURCE_TOTAL_BYTES:
                    raise ContractGenerationError("archive source set exceeds the bounded aggregate size policy")
                try:
                    sources[info.filename] = archive.read(info).decode("utf-8")
                except UnicodeDecodeError as exc:
                    raise ContractGenerationError(f"{info.filename}: archive source is not UTF-8") from exc
    except zipfile.BadZipFile as exc:
        raise ContractGenerationError(f"invalid pinned archive: {exc}") from exc
    if not sources:
        raise ContractGenerationError("archive contains no Python sources under the expected package root")
    metadata = {
        "archive_sha256": actual_hash,
        "archive_version": ARCHIVE_VERSION,
        "license": "MIT",
        "source_root": SOURCE_ROOT,
    }
    return sources, metadata


def validate_schema_references(value: Any, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}"
            if key == "$ref":
                if not isinstance(child, str) or not child.startswith("#/"):
                    raise ContractGenerationError(f"{child_path}: remote, file, and network schema references are forbidden")
            if key in {"$schema", "$id"} and isinstance(child, str):
                lowered = child.strip().casefold()
                if re.match(r"^[a-z][a-z0-9+.-]*:", lowered) or lowered.startswith(("//", "\\\\")):
                    raise ContractGenerationError(f"{child_path}: external schema identifiers are forbidden")
            validate_schema_references(child, child_path)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            validate_schema_references(child, f"{path}[{index}]")


def module_name_for_path(path: str) -> str:
    if not path.startswith(SOURCE_ROOT) or not path.endswith(".py"):
        raise ContractGenerationError(f"cannot derive module name from {path!r}")
    suffix = path[len(SOURCE_ROOT):-3]
    parts = suffix.split("/")
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return "ida_pro_mcp" + ("." + ".".join(parts) if parts else "")


def import_base(module_name: str, level: int, imported_module: str | None) -> str:
    if level == 0:
        return imported_module or ""
    package_parts = module_name.split(".")[:-1]
    if level > len(package_parts) + 1:
        raise ContractGenerationError(f"relative import escapes package in {module_name}")
    base_parts = package_parts[: len(package_parts) - level + 1]
    if imported_module:
        base_parts.extend(imported_module.split("."))
    return ".".join(base_parts)


def build_modules(sources: dict[str, str]) -> dict[str, Module]:
    modules: dict[str, Module] = {}
    for path, source in sorted(sources.items()):
        name = module_name_for_path(path)
        if not name.startswith("ida_pro_mcp.ida_mcp"):
            continue
        if name.startswith("ida_pro_mcp.ida_mcp.zeromcp") or ".tests" in name:
            continue
        try:
            tree = ast.parse(source, filename=path, mode="exec", type_comments=True)
        except SyntaxError as exc:
            line = exc.lineno or 1
            column = exc.offset or 1
            raise ContractGenerationError(f"{path}:{line}:{column}: archive source syntax error: {exc.msg}") from exc
        modules[name] = Module(name=name, path=path, tree=tree, imports={}, definitions={})
    for module in modules.values():
        for node in module.tree.body:
            if isinstance(node, ast.Import):
                for alias in node.names:
                    local_name = alias.asname or alias.name.split(".")[0]
                    module.imports[local_name] = alias.name
            elif isinstance(node, ast.ImportFrom):
                try:
                    base = import_base(module.name, node.level, node.module)
                except ContractGenerationError as exc:
                    fail(str(exc), node, module)
                for alias in node.names:
                    local_name = alias.asname or alias.name
                    module.imports[local_name] = f"{base}.{alias.name}" if base else alias.name
            elif isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                module.definitions[node.name] = node
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        module.definitions[target.id] = node
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                module.definitions[node.target.id] = node
    return modules


def active_api_modules(modules: dict[str, Module]) -> list[Module]:
    package = modules.get("ida_pro_mcp.ida_mcp")
    if package is None:
        raise ContractGenerationError("archive package initializer ida_pro_mcp.ida_mcp is absent")
    names: list[str] = []
    for node in package.tree.body:
        if not isinstance(node, ast.ImportFrom) or node.level != 1 or node.module is not None:
            continue
        for alias in node.names:
            if alias.name.startswith("api_"):
                names.append(alias.name)
    if not names:
        raise ContractGenerationError("archive initializer does not statically import API modules")
    result: list[Module] = []
    for name in names:
        module_name = f"ida_pro_mcp.ida_mcp.{name}"
        module = modules.get(module_name)
        if module is None:
            raise ContractGenerationError(f"archive initializer imports absent module {module_name}")
        result.append(module)
    return result


def dotted_name(node: ast.AST, module: Module) -> str | None:
    if isinstance(node, ast.Name):
        return module.imports.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        parent = dotted_name(node.value, module)
        return f"{parent}.{node.attr}" if parent else None
    return None


def annotation_text(node: ast.AST, module: Module) -> str:
    try:
        return ast.unparse(node)
    except Exception as exc:
        fail(f"cannot canonicalize annotation: {exc}", node, module)
    raise AssertionError("unreachable")


def literal_value(node: ast.AST, module: Module, seen: set[str] | None = None) -> Any:
    if isinstance(node, ast.Name):
        definitions = module.definitions
        definition = definitions.get(node.id)
        key = f"{module.name}.{node.id}"
        seen = set() if seen is None else seen
        if key in seen:
            fail(f"cyclic static constant {node.id!r}", node, module)
        if isinstance(definition, ast.Assign) and len(definition.targets) == 1:
            return literal_value(definition.value, module, seen | {key})
        if isinstance(definition, ast.AnnAssign) and definition.value is not None:
            return literal_value(definition.value, module, seen | {key})
    try:
        value = ast.literal_eval(node)
    except (ValueError, TypeError) as exc:
        fail("schema metadata and default values must be literal JSON values", node, module)
        raise AssertionError("unreachable") from exc
    try:
        json.dumps(value, ensure_ascii=True, allow_nan=False)
    except (TypeError, ValueError) as exc:
        fail("schema metadata and default values must be JSON values", node, module)
        raise AssertionError("unreachable") from exc
    return value


def annotation_arguments(node: ast.Subscript) -> list[ast.AST]:
    if isinstance(node.slice, ast.Tuple):
        return list(node.slice.elts)
    return [node.slice]


def flatten_union(node: ast.AST) -> list[ast.AST]:
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        return flatten_union(node.left) + flatten_union(node.right)
    return [node]


class SchemaResolver:
    def __init__(self, modules: dict[str, Module]):
        self.modules = modules
        self.in_progress: set[str] = set()
        self.generic_bindings: dict[str, tuple[ast.AST, Module]] = {}

    def resolve_definition(self, qualified: str, use_node: ast.AST, use_module: Module) -> tuple[Module, ast.AST]:
        module_name, separator, symbol = qualified.rpartition(".")
        if not separator:
            module_name = use_module.name
            symbol = qualified
        module = self.modules.get(module_name)
        if module is None:
            fail(f"unknown annotation module {module_name!r}", use_node, use_module)
        definition = module.definitions.get(symbol)
        if definition is None:
            fail(f"unknown annotation symbol {qualified!r}", use_node, use_module)
        return module, definition

    def is_wrapper(self, node: ast.AST, module: Module, names: set[str]) -> bool:
        name = dotted_name(node, module)
        return name in names

    def unwrap_requirement(self, node: ast.AST, module: Module) -> tuple[ast.AST, bool | None]:
        if not isinstance(node, ast.Subscript):
            return node, None
        name = dotted_name(node.value, module)
        values = annotation_arguments(node)
        if name in {"typing.NotRequired", "NotRequired"}:
            if len(values) != 1:
                fail("NotRequired requires one type argument", node, module)
            return values[0], False
        if name in {"typing.Required", "Required"}:
            if len(values) != 1:
                fail("Required requires one type argument", node, module)
            return values[0], True
        return node, None

    def schema(self, node: ast.AST, module: Module) -> dict[str, Any]:
        if isinstance(node, ast.Constant) and node.value is None:
            return {"type": "null"}
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
            return {"anyOf": [self.schema(item, module) for item in flatten_union(node)]}
        if isinstance(node, ast.Name):
            return self.schema_name(dotted_name(node, module) or node.id, node, module)
        if isinstance(node, ast.Attribute):
            name = dotted_name(node, module)
            if name is None:
                fail("unsupported attribute annotation", node, module)
            return self.schema_name(name, node, module)
        if isinstance(node, ast.Subscript):
            return self.schema_subscript(node, module)
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id == "type" and len(node.args) == 1:
                argument = node.args[0]
                if isinstance(argument, ast.Constant) and argument.value is None:
                    return {"type": "null"}
            fail("unsupported callable annotation", node, module)
        fail(f"unsupported schema annotation {annotation_text(node, module)!r}", node, module)
        raise AssertionError("unreachable")

    def schema_name(self, name: str, node: ast.AST, module: Module) -> dict[str, Any]:
        binding = self.generic_bindings.get(f"{module.name}.{name}")
        if binding is not None:
            return self.schema(binding[0], binding[1])
        primitive_types = {
            "int": "integer",
            "float": "number",
            "str": "string",
            "bool": "boolean",
            "list": "array",
            "dict": "object",
            "None": "null",
            "NoneType": "null",
            "builtins.int": "integer",
            "builtins.float": "number",
            "builtins.str": "string",
            "builtins.bool": "boolean",
            "builtins.list": "array",
            "builtins.dict": "object",
            "typing.Any": None,
            "Any": None,
        }
        if name in primitive_types:
            schema_type = primitive_types[name]
            return {} if schema_type is None else {"type": schema_type}
        definition_module, definition = self.resolve_definition(name, node, module)
        key = f"{definition_module.name}.{getattr(definition, 'name', name)}"
        if key in self.in_progress:
            fail(f"recursive schema definition {key!r} is unsupported", node, module)
        self.in_progress.add(key)
        try:
            if isinstance(definition, ast.ClassDef):
                return self.schema_typed_dict(definition, definition_module)
            if isinstance(definition, ast.Assign):
                if len(definition.targets) != 1:
                    fail("type alias assignment must have one target", definition, definition_module)
                if isinstance(definition.value, ast.Call) and dotted_name(definition.value.func, definition_module) in {"typing.TypedDict", "TypedDict"}:
                    return self.schema_typed_dict_call(definition.value, definition_module)
                return self.schema(definition.value, definition_module)
            if isinstance(definition, ast.AnnAssign) and definition.value is not None:
                return self.schema(definition.value, definition_module)
            fail(f"annotation symbol {name!r} is not a supported TypedDict or alias", definition, definition_module)
        finally:
            self.in_progress.remove(key)
        raise AssertionError("unreachable")

    def schema_typed_dict_call(self, call: ast.Call, module: Module) -> dict[str, Any]:
        if len(call.args) != 2:
            fail("functional TypedDict requires a literal name and field mapping", call, module)
        declared_name = literal_value(call.args[0], module)
        if not isinstance(declared_name, str) or not isinstance(call.args[1], ast.Dict):
            fail("functional TypedDict requires a literal string name and dictionary fields", call, module)
        total = True
        for keyword in call.keywords:
            if keyword.arg != "total":
                fail("unsupported functional TypedDict keyword", keyword.value, module)
            value = literal_value(keyword.value, module)
            if not isinstance(value, bool):
                fail("functional TypedDict total keyword must be boolean", keyword.value, module)
            total = value
        fields = call.args[1]
        properties: dict[str, Any] = {}
        required: list[str] = []
        for key, value in zip(fields.keys, fields.values):
            if key is None:
                fail("functional TypedDict dictionary unpacking is unsupported", fields, module)
            field_name = literal_value(key, module)
            if not isinstance(field_name, str):
                fail("functional TypedDict field names must be strings", key, module)
            field_annotation, requirement = self.unwrap_requirement(value, module)
            properties[field_name] = self.schema(field_annotation, module)
            if total if requirement is None else requirement:
                required.append(field_name)
        return {
            "type": "object",
            "properties": properties,
            "required": required,
            "additionalProperties": False,
        }

    def schema_subscript(self, node: ast.Subscript, module: Module) -> dict[str, Any]:
        name = dotted_name(node.value, module)
        if name is None:
            fail("unsupported generic annotation base", node, module)
        arguments = annotation_arguments(node)
        if name in {"typing.Annotated", "Annotated"}:
            if len(arguments) < 2:
                fail("Annotated requires a type and metadata", node, module)
            metadata = literal_value(arguments[-1], module)
            return {**self.schema(arguments[0], module), "description": str(metadata)}
        if name in {"list", "typing.List", "List"}:
            if len(arguments) != 1:
                fail("list requires one type argument", node, module)
            return {"type": "array", "items": self.schema(arguments[0], module)}
        if name in {"dict", "typing.Dict", "Dict"}:
            if len(arguments) != 2:
                fail("dict requires two type arguments", node, module)
            return {"type": "object", "additionalProperties": self.schema(arguments[1], module)}
        if name in {"typing.Optional", "Optional"}:
            if len(arguments) != 1:
                fail("Optional requires one type argument", node, module)
            return {"anyOf": [self.schema(arguments[0], module), {"type": "null"}]}
        if name in {"typing.Union", "Union"}:
            if len(arguments) < 2:
                fail("Union requires at least two type arguments", node, module)
            return {"anyOf": [self.schema(argument, module) for argument in arguments]}
        if name in {"typing.NotRequired", "NotRequired", "typing.Required", "Required"}:
            if len(arguments) != 1:
                fail(f"{name.rsplit('.', 1)[-1]} requires one type argument", node, module)
            return self.schema(arguments[0], module)
        definition_module, definition = self.resolve_definition(name, node, module)
        if isinstance(definition, ast.ClassDef):
            generic_parameters = self.generic_parameters(definition, definition_module)
            if generic_parameters:
                if len(arguments) != len(generic_parameters):
                    fail("generic TypedDict argument count does not match its declaration", node, module)
                old_bindings = self.generic_bindings
                self.generic_bindings = {
                    **old_bindings,
                    **{
                        f"{definition_module.name}.{parameter}": (argument, module)
                        for parameter, argument in zip(generic_parameters, arguments)
                    },
                }
                try:
                    return self.schema_typed_dict(definition, definition_module)
                finally:
                    self.generic_bindings = old_bindings
        fail(f"unsupported schema generic {name!r}", node, module)
        raise AssertionError("unreachable")

    def generic_parameters(self, definition: ast.ClassDef, module: Module) -> list[str]:
        parameters: list[str] = []
        for base in definition.bases:
            if not isinstance(base, ast.Subscript) or dotted_name(base.value, module) not in {"typing.Generic", "Generic"}:
                continue
            for parameter in annotation_arguments(base):
                if not isinstance(parameter, ast.Name):
                    fail("Generic declarations must use named type variables", parameter, module)
                parameters.append(parameter.id)
        return parameters

    def schema_typed_dict(self, definition: ast.ClassDef, module: Module) -> dict[str, Any]:
        typed_dict_bases = [base for base in definition.bases if dotted_name(base, module) in {"typing.TypedDict", "TypedDict"}]
        generic_bases = [
            base for base in definition.bases
            if isinstance(base, ast.Subscript) and dotted_name(base.value, module) in {"typing.Generic", "Generic"}
        ]
        inherited_bases = [base for base in definition.bases if base not in typed_dict_bases and base not in generic_bases]
        if len(typed_dict_bases) > 1 or len(inherited_bases) > 1:
            fail("multiple TypedDict bases are unsupported", definition, module)
        if not typed_dict_bases and not inherited_bases:
            fail(f"class {definition.name!r} is not a TypedDict", definition, module)
        for base in definition.bases:
            if base in typed_dict_bases or base in inherited_bases:
                continue
            if not isinstance(base, ast.Subscript) or dotted_name(base.value, module) not in {"typing.Generic", "Generic"}:
                fail("unsupported TypedDict base class", base, module)
        total = True
        for keyword in definition.keywords:
            if keyword.arg != "total":
                fail("unsupported TypedDict keyword", keyword.value, module)
            value = literal_value(keyword.value, module)
            if not isinstance(value, bool):
                fail("TypedDict total keyword must be boolean", keyword.value, module)
            total = value
        properties: dict[str, Any] = {}
        required: list[str] = []
        if inherited_bases:
            inherited = self.schema(inherited_bases[0], module)
            if inherited.get("type") != "object" or not isinstance(inherited.get("properties"), dict):
                fail("TypedDict base must resolve to an object schema", inherited_bases[0], module)
            properties.update(inherited["properties"])
            inherited_required = inherited.get("required", [])
            if not isinstance(inherited_required, list) or not all(isinstance(name, str) for name in inherited_required):
                fail("TypedDict base required list is invalid", inherited_bases[0], module)
            required.extend(inherited_required)
        for item in definition.body:
            if isinstance(item, ast.Pass) or (
                isinstance(item, ast.Expr) and isinstance(item.value, ast.Constant) and isinstance(item.value.value, str)
            ):
                continue
            if not isinstance(item, ast.AnnAssign) or not isinstance(item.target, ast.Name) or item.value is not None:
                fail("TypedDict bodies may only contain annotated fields", item, module)
            field_annotation, requirement = self.unwrap_requirement(item.annotation, module)
            properties[item.target.id] = self.schema(field_annotation, module)
            required_field = total if requirement is None else requirement
            if required_field:
                required.append(item.target.id)
        return {
            "type": "object",
            "properties": properties,
            "required": required,
            "additionalProperties": False,
        }


def schema_is_object_like(schema: dict[str, Any]) -> bool:
    if schema.get("type") == "object":
        return True
    variants = schema.get("anyOf")
    return isinstance(variants, list) and all(isinstance(item, dict) and schema_is_object_like(item) for item in variants)


def decorator_record(node: ast.AST, module: Module) -> tuple[str, list[Any], dict[str, Any]]:
    if isinstance(node, ast.Name):
        return dotted_name(node, module) or node.id, [], {}
    if isinstance(node, ast.Call):
        name = dotted_name(node.func, module)
        if name is None:
            fail("unsupported decorator target", node, module)
        return name, [literal_value(argument, module) for argument in node.args], {
            keyword.arg: literal_value(keyword.value, module)
            for keyword in node.keywords
            if keyword.arg is not None
        }
    fail("unsupported decorator form", node, module)
    raise AssertionError("unreachable")


def function_decorators(node: ast.FunctionDef | ast.AsyncFunctionDef, module: Module) -> tuple[list[dict[str, Any]], bool, str | None, bool]:
    records: list[dict[str, Any]] = []
    tool = False
    unsafe = False
    extension: str | None = None
    for decorator in node.decorator_list:
        name, args, keywords = decorator_record(decorator, module)
        terminal = name.rsplit(".", 1)[-1]
        if terminal == "tool":
            if args or keywords:
                fail("tool decorator does not accept arguments", decorator, module)
            tool = True
        elif terminal == "unsafe":
            if args or keywords:
                fail("unsafe decorator does not accept arguments", decorator, module)
            unsafe = True
        elif terminal == "ext":
            if keywords or len(args) != 1 or not isinstance(args[0], str):
                fail("ext decorator requires exactly one string argument", decorator, module)
            if extension is not None:
                fail("tool has multiple extension decorators", decorator, module)
            extension = args[0]
        elif terminal == "idasync":
            if args or keywords:
                fail("idasync decorator does not accept arguments", decorator, module)
        elif terminal == "tool_timeout":
            if keywords or len(args) != 1 or not isinstance(args[0], (int, float)):
                fail("tool_timeout decorator requires exactly one numeric argument", decorator, module)
        elif terminal == "keep_batch":
            if args or keywords:
                fail("keep_batch decorator does not accept arguments", decorator, module)
        else:
            fail(f"unsupported tool decorator {name!r}", decorator, module)
        records.append({"name": terminal, "args": args, "keywords": keywords})
    return records, tool, extension, unsafe


def function_schema(node: ast.FunctionDef | ast.AsyncFunctionDef, module: Module, resolver: SchemaResolver) -> tuple[dict[str, Any], dict[str, Any]]:
    args = node.args
    if args.posonlyargs or args.vararg is not None or args.kwarg is not None or args.kwonlyargs:
        fail("tool signatures may only use annotated positional-or-keyword parameters", node, module)
    defaults: dict[str, ast.AST] = {}
    if args.defaults:
        for argument, default in zip(args.args[-len(args.defaults):], args.defaults):
            defaults[argument.arg] = default
    properties: dict[str, Any] = {}
    required: list[str] = []
    parameter_annotations: list[dict[str, Any]] = []
    for argument in args.args:
        if argument.annotation is None:
            fail(f"tool parameter {argument.arg!r} lacks an annotation", argument, module)
        schema = resolver.schema(argument.annotation, module)
        parameter = {
            "name": argument.arg,
            "annotation": annotation_text(argument.annotation, module),
            "required": argument.arg not in defaults,
        }
        if argument.arg in defaults:
            value = literal_value(defaults[argument.arg], module)
            schema["default"] = value
            parameter["default"] = value
        else:
            required.append(argument.arg)
        properties[argument.arg] = schema
        parameter_annotations.append(parameter)
    input_schema = {"type": "object", "properties": properties, "required": required}
    output_schema: dict[str, Any] | None = None
    return_annotation = None
    if node.returns is not None:
        return_annotation = annotation_text(node.returns, module)
        candidate = resolver.schema(node.returns, module)
        if candidate != {"type": "null"}:
            if not schema_is_object_like(candidate):
                candidate = {"type": "object", "properties": {"result": candidate}, "required": ["result"]}
            elif candidate.get("type") != "object":
                candidate = {"type": "object", **candidate}
            output_schema = candidate
    annotations = {"parameters": parameter_annotations, "return": return_annotation}
    return {"input_schema": input_schema, "output_schema": output_schema}, annotations


def direct_registrations(module: Module) -> dict[str, ast.AST]:
    registrations: dict[str, ast.AST] = {}
    for node in module.tree.body:
        if not isinstance(node, ast.Expr) or not isinstance(node.value, ast.Call):
            continue
        call = node.value
        name = dotted_name(call.func, module)
        if name not in {"ida_pro_mcp.ida_mcp.rpc.MCP_SERVER.tool", "MCP_SERVER.tool", "ida_pro_mcp.ida_mcp.rpc.MCP_SERVER.tools.method", "MCP_SERVER.tools.method"}:
            continue
        if len(call.args) != 1 or call.keywords or not isinstance(call.args[0], ast.Name):
            fail("direct tool registration must use one simple function name", call, module)
        registrations[call.args[0].id] = call
    return registrations


def is_target_dependent(name: str) -> bool:
    return name not in TARGET_INDEPENDENT_TOOL_NAMES


def effect_for_tool(name: str) -> tuple[str, str, bool]:
    if name == "list_instances":
        return "registry_read", "registry_read", True
    if name == "idb_save":
        return "workspace_checkpoint", "workspace_checkpoint", False
    if name == "py_exec_file":
        return "isolated_python", "python_worker", False
    if name.startswith("dbg_"):
        if name == "dbg_write":
            return "debugger_write", "debugger_lane", False
        if name in {
            "dbg_start", "dbg_exit", "dbg_continue", "dbg_run_to", "dbg_step_into", "dbg_step_over",
            "dbg_add_bp", "dbg_delete_bp", "dbg_toggle_bp", "dbg_set_bp_condition",
        }:
            return "debugger_control", "debugger_lane", False
        return "debugger_read", "debugger_lane", True
    if name in OVERLAY_MUTATION_TOOL_NAMES:
        return "workspace_overlay_mutation", "workspace_overlay_transaction", False
    return "workspace_read", "workspace_shared", True


def routing_for_tool(name: str) -> dict[str, Any]:
    target_dependent = is_target_dependent(name)
    return {
        "target_dependent": target_dependent,
        "fields": [
            {"name": "pid", "schema": {"type": "integer", "description": ROUTING_DESCRIPTIONS["pid"]}},
            {"name": "bin_name", "schema": {"type": "string", "description": ROUTING_DESCRIPTIONS["bin_name"]}},
        ] if target_dependent else [],
    }


def add_routing_fields(input_schema: dict[str, Any], routing: dict[str, Any]) -> dict[str, Any]:
    result = json.loads(canonical_json_value(input_schema))
    if not routing["target_dependent"]:
        return result
    properties = result.get("properties")
    if not isinstance(properties, dict):
        raise ContractGenerationError("generated input schema lacks object properties")
    for field in routing["fields"]:
        name = field["name"]
        if name in properties:
            raise ContractGenerationError(f"upstream schema already owns routing field {name!r}")
        properties[name] = field["schema"]
    return result


def override_idb_save_contract(contract: dict[str, Any]) -> None:
    input_schema = contract["input_schema"]
    input_properties = input_schema.get("properties")
    if not isinstance(input_properties, dict):
        raise ContractGenerationError("idb_save input schema must expose object properties")
    input_path = input_properties.get("path")
    if not isinstance(input_path, dict) or input_path.get("type") != "string" or input_path.get("default") != "":
        raise ContractGenerationError("idb_save input compatibility shape changed")
    input_path["description"] = "Optional compatibility argument. It must be empty; AiDA flushes the active workspace checkpoint."

    output_schema = contract["output_schema"]
    if not isinstance(output_schema, dict):
        raise ContractGenerationError("idb_save output schema must remain object-shaped")
    output_properties = output_schema.get("properties")
    if not isinstance(output_properties, dict):
        raise ContractGenerationError("idb_save output schema must expose object properties")
    ok_schema = output_properties.get("ok")
    path_schema = output_properties.get("path")
    error_schema = output_properties.get("error")
    if not isinstance(ok_schema, dict) or ok_schema.get("type") != "boolean":
        raise ContractGenerationError("idb_save output compatibility shape changed for ok")
    if not isinstance(path_schema, dict) or not isinstance(path_schema.get("anyOf"), list):
        raise ContractGenerationError("idb_save output compatibility shape changed for path")
    if not isinstance(error_schema, dict) or error_schema.get("type") != "string":
        raise ContractGenerationError("idb_save output compatibility shape changed for error")
    ok_schema["description"] = "Whether AiDA durably checkpointed and flushed the active workspace."
    path_schema["description"] = "AiDA workspace checkpoint reference, not a filesystem destination."
    error_schema["description"] = "Checkpoint failure detail when the workspace was not flushed."

    annotations = contract["annotations"]
    parameters = annotations.get("parameters")
    if not isinstance(parameters, list) or len(parameters) != 1 or not isinstance(parameters[0], dict):
        raise ContractGenerationError("idb_save annotation compatibility shape changed")
    parameter = parameters[0]
    if parameter.get("name") != "path" or parameter.get("required") is not False or parameter.get("default") != "":
        raise ContractGenerationError("idb_save annotation compatibility parameter changed")
    parameter["annotation"] = "Annotated[str, 'Optional compatibility argument; it must be empty because AiDA flushes the active workspace checkpoint.']"
    annotations["return"] = "WorkspaceCheckpointResult"
    contract["description"] = "Flush and durably checkpoint the active AiDA workspace. This compatibility operation never creates an IDA database or writes a caller-selected file."


def override_py_exec_file_contract(contract: dict[str, Any]) -> None:
    input_schema = contract["input_schema"]
    input_properties = input_schema.get("properties")
    if not isinstance(input_properties, dict):
        raise ContractGenerationError("py_exec_file input schema must expose object properties")
    file_path_schema = input_properties.get("file_path")
    if not isinstance(file_path_schema, dict) or file_path_schema.get("type") != "string":
        raise ContractGenerationError("py_exec_file input compatibility shape changed for file_path")
    file_path_schema["description"] = "Workspace-relative path to the Python script"
    file_path_schema["maxLength"] = 4096
    file_path_schema["minLength"] = 1
    input_properties["approve_unsafe"] = {
        "description": "Explicit approval for isolated script execution",
        "type": "boolean",
    }
    bin_name_schema = input_properties.get("bin_name")
    if isinstance(bin_name_schema, dict):
        bin_name_schema["description"] = "AiDA workspace binary name used to route this call"
    pid_schema = input_properties.get("pid")
    if isinstance(pid_schema, dict):
        pid_schema["description"] = "AiDA workspace process ID used to route this call when applicable"
    input_schema["additionalProperties"] = False
    required = input_schema.get("required")
    if not isinstance(required, list) or "file_path" not in required:
        raise ContractGenerationError("py_exec_file input schema must require file_path")
    if "approve_unsafe" not in required:
        required.append("approve_unsafe")

    output_schema = contract["output_schema"]
    if not isinstance(output_schema, dict):
        raise ContractGenerationError("py_exec_file output schema must remain object-shaped")
    output_properties = output_schema.get("properties")
    if not isinstance(output_properties, dict):
        raise ContractGenerationError("py_exec_file output schema must expose object properties")
    output_properties["worker_generation"] = {"type": "integer"}
    output_properties["worker_process_id"] = {"type": "integer"}
    output_properties["diagnostics"] = {"type": "array"}
    output_required = output_schema.get("required")
    if not isinstance(output_required, list):
        raise ContractGenerationError("py_exec_file output schema must expose required list")
    for field in ("worker_generation", "worker_process_id", "diagnostics"):
        if field not in output_required:
            output_required.append(field)

    annotations = contract["annotations"]
    decorators = annotations.get("decorators")
    if not isinstance(decorators, list):
        raise ContractGenerationError("py_exec_file annotation decorators must be a list")
    decorators[:] = [d for d in decorators if not (isinstance(d, dict) and d.get("name") == "idasync")]
    parameters = annotations.get("parameters")
    if not isinstance(parameters, list) or len(parameters) != 1 or not isinstance(parameters[0], dict):
        raise ContractGenerationError("py_exec_file annotation compatibility shape changed")
    parameter = parameters[0]
    if parameter.get("name") != "file_path" or parameter.get("required") is not True:
        raise ContractGenerationError("py_exec_file annotation compatibility parameter changed")
    parameter["annotation"] = "Annotated[str, 'Workspace-relative path to a Python script']"
    parameters.append({
        "annotation": "Annotated[bool, 'Explicit approval for isolated script execution']",
        "name": "approve_unsafe",
        "required": True,
    })
    annotations["extension"] = "aida_standalone_isolated_worker"
    annotations["return"] = "IsolatedPythonWorkerResult"
    contract["adapter_symbol"] = "aida::standalone::mcp::compat::python_worker_host_t::execute"
    contract["description"] = (
        "Execute a workspace-relative Python script in AiDA Standalone's isolated analysis worker "
        "and return bounded stdout/stderr. Explicit unsafe approval is required. The worker has no "
        "network, child-process, or live-target write capability and can query only approved "
        "static-workspace APIs."
    )


def override_read_struct_contract(contract: dict[str, Any]) -> None:
    input_schema = contract["input_schema"]
    input_properties = input_schema.get("properties")
    input_required = input_schema.get("required")
    if not isinstance(input_properties, dict) or not isinstance(input_required, list):
        raise ContractGenerationError("read_struct input schema must remain object-shaped")
    queries_schema = input_properties.get("queries")
    if not isinstance(queries_schema, dict) or input_required != ["queries"]:
        raise ContractGenerationError("read_struct archive input compatibility shape changed")

    input_properties.update({
        "address": {
            "description": "Struct base address or arithmetic expression",
            "type": "string",
            "minLength": 1,
            "maxLength": 4096,
        },
        "struct_name": {
            "description": "Declared workspace struct name",
            "type": "string",
            "minLength": 1,
        },
        "fields": {
            "description": "Live struct fields with explicit names, offsets, and value types",
            "type": "array",
            "minItems": 1,
            "maxItems": 256,
            "items": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "minLength": 1, "maxLength": 256},
                    "offset": {
                        "oneOf": [
                            {"type": "string", "minLength": 1, "maxLength": 4096},
                            {"type": "integer", "minimum": 0},
                        ],
                    },
                    "type": {"type": "string", "minLength": 1, "maxLength": 64},
                    "size": {
                        "oneOf": [
                            {"type": "string", "minLength": 1, "maxLength": 4096},
                            {"type": "integer", "minimum": 1, "maximum": 1048576},
                        ],
                    },
                },
                "required": ["name", "offset", "type"],
                "additionalProperties": False,
            },
        },
        "size": {
            "description": "Optional total live read size; it must cover every field",
            "oneOf": [
                {"type": "string", "minLength": 1, "maxLength": 4096},
                {"type": "integer", "minimum": 1, "maximum": 1048576},
            ],
        },
        "target": {"type": "string", "enum": ["auto", "guest", "host"]},
        "timeout_ms": {"type": "integer", "minimum": 1, "maximum": 300000},
    })
    input_schema["required"] = []
    input_schema["oneOf"] = [
        {
            "required": ["queries"],
            "not": {"anyOf": [
                {"required": ["address"]},
                {"required": ["struct_name"]},
                {"required": ["fields"]},
            ]},
        },
        {
            "required": ["address", "struct_name"],
            "not": {"anyOf": [
                {"required": ["queries"]},
                {"required": ["fields"]},
            ]},
        },
        {
            "required": ["address", "fields"],
            "not": {"anyOf": [
                {"required": ["queries"]},
                {"required": ["struct_name"]},
            ]},
        },
    ]
    input_schema["additionalProperties"] = False

    legacy_output_schema = contract["output_schema"]
    if not isinstance(legacy_output_schema, dict) or "result" not in legacy_output_schema.get("properties", {}):
        raise ContractGenerationError("read_struct archive output compatibility shape changed")
    live_output_schema = {
        "type": "object",
        "properties": {
            "address": {"type": "string"},
            "size": {"type": "integer"},
            "requested_size": {"type": "integer"},
            "complete": {"type": "boolean"},
            "hex": {"type": "string"},
            "ascii": {"type": "string"},
            "fields": {"type": "array"},
            "struct": {"type": "object"},
        },
        "required": ["address", "size", "requested_size", "complete", "hex", "ascii", "fields", "struct"],
    }
    contract["output_schema"] = {"oneOf": [legacy_output_schema, live_output_schema]}

    annotations = contract["annotations"]
    annotations["parameters"] = [
        {"annotation": "list[StructRead] | StructRead", "name": "queries", "required": False},
        {"annotation": "str", "name": "address", "required": False},
        {"annotation": "str", "name": "struct_name", "required": False},
        {"annotation": "list[LiveStructField]", "name": "fields", "required": False},
        {"annotation": "int | str", "name": "size", "required": False},
    ]
    annotations["return"] = "list[ReadStructResult] | LiveStructReadResult"
    contract["description"] = (
        "Read declared workspace structs through the compatible queries form, or read a live struct "
        "with an arithmetic address and explicit typed fields."
    )


def adapter_symbol(name: str) -> str:
    return f"aida::standalone::mcp::compat::adapters::{name}"


def location_data(module: Module, node: ast.AST, symbol: str, registration: str) -> dict[str, Any]:
    return {
        "path": module.path,
        "line": getattr(node, "lineno", 1),
        "column": getattr(node, "col_offset", 0) + 1,
        "module": module.name,
        "symbol": symbol,
        "registration": registration,
    }


def collect_archive_tools(modules: dict[str, Module]) -> list[dict[str, Any]]:
    resolver = SchemaResolver(modules)
    contracts: list[dict[str, Any]] = []
    names: set[str] = set()
    for module in active_api_modules(modules):
        direct = direct_registrations(module)
        defined: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
        for item in module.tree.body:
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                defined[item.name] = item
        for symbol, function in defined.items():
            has_tool_decorator = any(
                (dotted_name(decorator if not isinstance(decorator, ast.Call) else decorator.func, module) or "").rsplit(".", 1)[-1] == "tool"
                for decorator in function.decorator_list
            )
            direct_node = direct.get(symbol)
            if not has_tool_decorator and direct_node is None:
                continue
            decorators, decorated_tool, extension, unsafe = function_decorators(function, module)
            if decorated_tool and direct_node is not None:
                fail("tool uses both decorator and direct registration", function, module)
            if symbol in names:
                fail(f"duplicate tool registration {symbol!r}", function, module)
            names.add(symbol)
            schemas, annotations = function_schema(function, module, resolver)
            description = (ast.get_docstring(function, clean=False) or f"Call {symbol}").strip()
            routing = routing_for_tool(symbol)
            effect, lock, read_only = effect_for_tool(symbol)
            annotations["decorators"] = decorators
            annotations["extension"] = extension
            annotations["unsafe"] = unsafe
            contract = {
                "name": symbol,
                "archive_backed": True,
                "source": location_data(module, function, symbol, "decorator" if decorated_tool else "direct"),
                "description": description,
                "input_schema": add_routing_fields(schemas["input_schema"], routing),
                "output_schema": schemas["output_schema"],
                "annotations": annotations,
                "routing": routing,
                "effect": effect,
                "lock": lock,
                "read_only": read_only,
                "unsafe": unsafe,
                "adapter_symbol": adapter_symbol(symbol),
            }
            if symbol == "idb_save":
                override_idb_save_contract(contract)
            if symbol == "py_exec_file":
                override_py_exec_file_contract(contract)
            if symbol == "read_struct":
                override_read_struct_contract(contract)
            contracts.append(contract)
        unknown_direct = sorted(set(direct).difference(defined))
        if unknown_direct:
            fail(f"direct registration references unknown functions {unknown_direct!r}", direct[unknown_direct[0]], module)
    return sorted(contracts, key=lambda item: item["name"])


def local_list_instances_contract() -> dict[str, Any]:
    effect, lock, read_only = effect_for_tool("list_instances")
    return {
        "name": "list_instances",
        "archive_backed": False,
        "source": {
            "path": "proxy-local",
            "line": 0,
            "column": 0,
            "module": "aida.standalone.mcp.compat",
            "symbol": "list_instances",
            "registration": "proxy-local",
        },
        "description": "List available AiDA analysis instances for explicit MCP routing.",
        "input_schema": {"type": "object", "properties": {}, "required": []},
        "output_schema": {
            "type": "object",
            "properties": {
                "instances": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "pid": {"type": "integer"},
                            "bin_name": {"type": "string"},
                        },
                        "required": ["pid", "bin_name"],
                        "additionalProperties": False,
                    },
                },
            },
            "required": ["instances"],
        },
        "annotations": {"parameters": [], "return": "list[instance]", "decorators": [], "extension": None, "unsafe": False},
        "routing": routing_for_tool("list_instances"),
        "effect": effect,
        "lock": lock,
        "read_only": read_only,
        "unsafe": False,
        "adapter_symbol": adapter_symbol("list_instances"),
    }


def assert_inventory(archive_contracts: list[dict[str, Any]], contracts: list[dict[str, Any]]) -> None:
    archive_names = {item["name"] for item in archive_contracts}
    expected_compatibility = archive_names.difference(EXCLUDED_TOOLS).union({"list_instances"})
    compatibility_names = {item["name"] for item in contracts}
    union_names = compatibility_names.union(EXTENSION_NAMES)
    if len(archive_names) != 88:
        raise ContractGenerationError(f"expected 88 archive tools, found {len(archive_names)}")
    if archive_names.intersection(EXCLUDED_TOOLS) != set(EXCLUDED_TOOLS):
        raise ContractGenerationError("the sole excluded tool py_eval is absent from the archive inventory")
    if compatibility_names != expected_compatibility:
        missing = sorted(expected_compatibility.difference(compatibility_names))
        unexpected = sorted(compatibility_names.difference(expected_compatibility))
        raise ContractGenerationError(f"compatibility inventory mismatch: missing={missing}, unexpected={unexpected}")
    if len(compatibility_names) != 88:
        raise ContractGenerationError(f"expected 88 compatibility names, found {len(compatibility_names)}")
    if len(EXTENSION_NAMES) != 4 or compatibility_names.intersection(EXTENSION_NAMES):
        raise ContractGenerationError("AiDA extension ledger is not four distinct additive names")
    if len(union_names) != 92:
        raise ContractGenerationError(f"expected 92 union names, found {len(union_names)}")


def build_artifacts(archive_path: Path) -> dict[str, bytes]:
    sources, archive_metadata = read_archive_sources(archive_path)
    modules = build_modules(sources)
    archive_contracts = collect_archive_tools(modules)
    contracts = sorted(
        [item for item in archive_contracts if item["name"] not in EXCLUDED_TOOLS] + [local_list_instances_contract()],
        key=lambda item: item["name"],
    )
    assert_inventory(archive_contracts, contracts)
    archive_names = [item["name"] for item in archive_contracts]
    compatibility_names = [item["name"] for item in contracts]
    union_names = sorted(set(compatibility_names).union(EXTENSION_NAMES))
    effect_ledger = {
        "schema_version": 1,
        "contracts": [
            {
                "name": item["name"],
                "archive_backed": item["archive_backed"],
                "adapter_symbol": item["adapter_symbol"],
                "effect": item["effect"],
                "lock": item["lock"],
                "read_only": item["read_only"],
                "unsafe": item["unsafe"],
                "target_dependent": item["routing"]["target_dependent"],
                "routing_fields": [field["name"] for field in item["routing"]["fields"]],
            }
            for item in contracts
        ],
    }
    contract_ledger = {
        "schema_version": 1,
        "archive": archive_metadata,
        "excluded_tools": list(EXCLUDED_TOOLS),
        "compatibility_names": compatibility_names,
        "contracts": contracts,
        "routing_policy": {
            "target_dependent_fields": ["pid", "bin_name"],
            "ambiguous_target": "error",
            "ui_activation": "forbidden",
        },
    }
    validate_schema_references(contract_ledger)
    validate_schema_references(effect_ledger)
    contract_bytes = canonical_json(contract_ledger).encode("ascii")
    effect_bytes = canonical_json(effect_ledger).encode("ascii")
    manifest = {
        "schema_version": 1,
        "archive": archive_metadata,
        "archive_tool_count": len(archive_names),
        "archive_tool_names": archive_names,
        "excluded_tools": list(EXCLUDED_TOOLS),
        "compatibility_tool_count": len(compatibility_names),
        "compatibility_names": compatibility_names,
        "aida_extension_count": len(EXTENSION_NAMES),
        "aida_extensions": list(EXTENSION_NAMES),
        "union_tool_count": len(union_names),
        "union_names": union_names,
        "contract_ledger_sha256": sha256_bytes(contract_bytes),
        "effect_ledger_sha256": sha256_bytes(effect_bytes),
    }
    validate_schema_references(manifest)
    manifest_bytes = canonical_json(manifest).encode("ascii")
    header = render_header(manifest, sha256_bytes(manifest_bytes))
    source = render_source(contracts)
    return {
        "src/standalone/src/resources/mcp/ida_pro_mcp_2_0_0/contracts.json": contract_bytes,
        "src/standalone/src/resources/mcp/ida_pro_mcp_2_0_0/effect_ledger.json": effect_bytes,
        "src/standalone/src/resources/mcp/ida_pro_mcp_2_0_0/archive_manifest.json": manifest_bytes,
        "src/standalone/src/core/mcp/compat/ida_contracts_generated.hpp": header.encode("ascii"),
        "src/standalone/src/core/mcp/compat/ida_contracts_generated.cpp": source.encode("ascii"),
    }


def cpp_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)


def render_header(manifest: dict[str, Any], manifest_hash: str) -> str:
    extensions = ", ".join(cpp_string(name) for name in EXTENSION_NAMES)
    return "\n".join([
        "#pragma once",
        "",
        "#include <cstddef>",
        "#include <cstdint>",
        "#include <string_view>",
        "",
        "namespace aida::standalone::mcp::compat {",
        "",
        "enum class contract_effect_t : std::uint8_t {",
        "    workspace_read,",
        "    workspace_checkpoint,",
        "    workspace_overlay_mutation,",
        "    debugger_read,",
        "    debugger_control,",
        "    debugger_write,",
        "    isolated_python,",
        "    registry_read,",
        "};",
        "",
        "enum class contract_lock_t : std::uint8_t {",
        "    workspace_shared,",
        "    workspace_checkpoint,",
        "    workspace_overlay_transaction,",
        "    debugger_lane,",
        "    python_worker,",
        "    registry_read,",
        "};",
        "",
        "struct contract_descriptor_t {",
        "    std::string_view name;",
        "    std::string_view description;",
        "    std::string_view input_schema_json;",
        "    std::string_view output_schema_json;",
        "    std::string_view annotations_json;",
        "    std::string_view adapter_symbol;",
        "    std::string_view source_path;",
        "    std::uint32_t source_line;",
        "    contract_effect_t effect;",
        "    contract_lock_t lock;",
        "    bool archive_backed;",
        "    bool target_dependent;",
        "    bool accepts_pid;",
        "    bool accepts_bin_name;",
        "    bool read_only;",
        "    bool unsafe;",
        "};",
        "",
        f"inline constexpr std::string_view k_pinned_archive_sha256 = {cpp_string(manifest['archive']['archive_sha256'])};",
        f"inline constexpr std::string_view k_generated_contract_ledger_sha256 = {cpp_string(manifest['contract_ledger_sha256'])};",
        f"inline constexpr std::string_view k_generated_effect_ledger_sha256 = {cpp_string(manifest['effect_ledger_sha256'])};",
        f"inline constexpr std::string_view k_generated_archive_manifest_sha256 = {cpp_string(manifest_hash)};",
        f"inline constexpr std::size_t k_archive_tool_count = {manifest['archive_tool_count']};",
        f"inline constexpr std::size_t k_compatibility_tool_count = {manifest['compatibility_tool_count']};",
        f"inline constexpr std::size_t k_aida_extension_count = {manifest['aida_extension_count']};",
        f"inline constexpr std::size_t k_union_tool_count = {manifest['union_tool_count']};",
        f"inline constexpr std::string_view k_aida_extension_names[] = {{{extensions}}};",
        "",
        "const contract_descriptor_t* contracts() noexcept;",
        "std::size_t contract_count() noexcept;",
        "const contract_descriptor_t* find_contract(std::string_view name) noexcept;",
        "",
        "}",
        "",
    ])


def render_source(contracts: list[dict[str, Any]]) -> str:
    lines = [
        "#include \"ida_contracts_generated.hpp\"",
        "",
        "namespace aida::standalone::mcp::compat {",
        "",
        "namespace {",
        "",
        "constexpr contract_descriptor_t k_contracts[] = {",
    ]
    for item in contracts:
        routing_fields = {field["name"] for field in item["routing"]["fields"]}
        output = "" if item["output_schema"] is None else canonical_json_value(item["output_schema"])
        lines.extend([
            "    {",
            f"        {cpp_string(item['name'])},",
            f"        {cpp_string(item['description'])},",
            f"        {cpp_string(canonical_json_value(item['input_schema']))},",
            f"        {cpp_string(output)},",
            f"        {cpp_string(canonical_json_value(item['annotations']))},",
            f"        {cpp_string(item['adapter_symbol'])},",
            f"        {cpp_string(item['source']['path'])},",
            f"        {item['source']['line']}u,",
            f"        contract_effect_t::{item['effect']},",
            f"        contract_lock_t::{item['lock']},",
            f"        {'true' if item['archive_backed'] else 'false'},",
            f"        {'true' if item['routing']['target_dependent'] else 'false'},",
            f"        {'true' if 'pid' in routing_fields else 'false'},",
            f"        {'true' if 'bin_name' in routing_fields else 'false'},",
            f"        {'true' if item['read_only'] else 'false'},",
            f"        {'true' if item['unsafe'] else 'false'},",
            "    },",
        ])
    lines.extend([
        "};",
        "",
        "}",
        "",
        "const contract_descriptor_t* contracts() noexcept {",
        "    return k_contracts;",
        "}",
        "",
        "std::size_t contract_count() noexcept {",
        "    return sizeof(k_contracts) / sizeof(k_contracts[0]);",
        "}",
        "",
        "const contract_descriptor_t* find_contract(std::string_view name) noexcept {",
        "    for (const auto& contract : k_contracts) {",
        "        if (contract.name == name) {",
        "            return &contract;",
        "        }",
        "    }",
        "    return nullptr;",
        "}",
        "",
        "}",
        "",
    ])
    return "\n".join(lines)


def write_artifacts(root: Path, artifacts: dict[str, bytes], check: bool) -> None:
    stale: list[str] = []
    for relative, expected in artifacts.items():
        path = root / relative
        if not path.is_file() or path.read_bytes() != expected:
            stale.append(relative)
    if check:
        if stale:
            raise ContractGenerationError("generated contract artifacts are stale: " + ", ".join(stale))
        return
    for relative, content in artifacts.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as stream:
            stream.write(content)
            temporary = Path(stream.name)
        temporary.replace(path)


def parse_arguments() -> argparse.Namespace:
    default_root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", type=Path, default=Path(os.environ.get("AIDA_IDA_MCP_ARCHIVE", r"C:\\Users\\ruar1337\\ida-pro-mcp.zip")))
    parser.add_argument("--repo-root", type=Path, default=default_root)
    parser.add_argument("--check", action="store_true")
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    archive = arguments.archive.resolve()
    root = arguments.repo_root.resolve()
    if not archive.is_file():
        raise ContractGenerationError(f"pinned archive does not exist: {archive}")
    if not root.is_dir():
        raise ContractGenerationError(f"repository root does not exist: {root}")
    artifacts = build_artifacts(archive)
    write_artifacts(root, artifacts, arguments.check)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ContractGenerationError as exc:
        raise SystemExit(f"contract generation failed: {exc}")
