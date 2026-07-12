from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
import sys
import zipfile
from pathlib import Path
from typing import Any, Iterable


class LedgerError(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest().upper()


def sha256_lines(values: Iterable[str]) -> str:
    return hashlib.sha256("\n".join(values).encode("utf-8")).hexdigest().upper()


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
            names = set(archive.namelist())
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
    except zipfile.BadZipFile as error:
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


def verify_archive_contract(ledger: dict[str, Any], archive_path: Path) -> dict[str, Any]:
    authority = ledger["authority"]
    archive = authority["pinned_ida_pro_mcp_archive"]
    expected_hash = archive["sha256"]
    actual_hash = sha256_file(archive_path)
    if actual_hash != expected_hash:
        raise LedgerError(f"pinned archive SHA-256 mismatch: expected {expected_hash}, observed {actual_hash}")
    observed_version, observed_tools = archive_tool_names(archive_path)
    if observed_version != archive["version"]:
        raise LedgerError(f"pinned archive version mismatch: expected {archive['version']}, observed {observed_version}")
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
        "archive_sha256": actual_hash,
        "archive_version": observed_version,
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
    if require_unique(registration_names, "C02 MCP registration inventory") != set(registration_names):
        raise LedgerError("unreachable MCP uniqueness failure")
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
    args = parser.parse_args()
    root = args.repository_root.resolve()
    ledger_path = args.ledger.resolve()
    ledger = load_json(ledger_path)
    if ledger.get("schema") != "aida.c03.authority-surface-ledger.v1":
        raise LedgerError("unsupported authority surface ledger schema")
    receipt = ledger["authority"]["c02_completion_receipt"]
    if sha256_file(root / receipt["path"]) != receipt["sha256"]:
        raise LedgerError("C02 completion receipt SHA-256 does not match the authority ledger")
    archive = args.archive or Path(ledger["authority"]["pinned_ida_pro_mcp_archive"]["path"])
    report = {
        "ledger_path": ledger_path.as_posix(),
        "ledger_sha256": sha256_file(ledger_path),
        "archive": verify_archive_contract(ledger, archive),
        "preservation_baseline": verify_preservation_baseline(ledger, root),
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except LedgerError as error:
        print(f"authority surface ledger verification failed: {error}", file=sys.stderr)
        raise SystemExit(1)
