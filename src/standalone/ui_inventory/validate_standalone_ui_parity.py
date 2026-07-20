from __future__ import annotations

import json
import pathlib
import re
import sys
from collections import Counter


ROOT = pathlib.Path(__file__).resolve().parents[3]
MANIFEST = pathlib.Path(__file__).with_name("standalone_ui_parity.json")
ALLOWED_STATUS = {"reachable", "partial", "alias", "unreachable", "backend_only"}
ALLOWED_DISPOSITION = {
    "preserve", "migrate", "activate", "parity_replace", "capability_gate",
    "retire_after_parity"
}
ALLOWED_MIGRATION = {"inventoried", "target_defined", "gated", "runtime_pending", "implemented"}
REQUIRED_GATES = {"G1", "G2", "G3", "G4", "G5"}
REQUIRED_KINDS = {
    "shell", "view", "document", "dialog", "menu_action", "toolbar",
    "context_menu", "navigation", "status", "shortcut", "visibility",
    "persistence", "selection", "state", "widget", "long_task", "provider", "alias"
}
REQUIRED_WORKSPACES = {
    "global", "analysis", "debugging", "memory", "types", "network",
    "automation_ai", "programming"
}
MINIMUM_KIND_COUNTS = {
    "view": 65,
    "document": 6,
    "dialog": 20,
    "menu_action": 35,
    "context_menu": 10,
    "long_task": 7,
    "state": 7,
    "shortcut": 12,
}
EXPECTED_DIALOG_COUNT = 74
REQUIRED_IDS = {
    "document.code", "document.disassembly", "document.hex", "document.pseudocode",
    "document.graph", "document.diff", "view.project_explorer", "view.workspace_search",
    "view.inspector", "view.navigator", "view.ai_chat", "view.background_tasks",
    "view.debug.cpu", "view.debug.breakpoints", "view.memory.value_scan",
    "view.types.structures", "view.network.connections", "view.network.headless",
    "candidate.analysis.functions_panel", "candidate.analysis.xref_db",
    "candidate.analysis.code_patcher", "provider.programming.terminal",
    "provider.programming.language_services", "task.contract.taskflow_runtime",
    "persistence.retention.task_center", "context.code_text", "context.dock_tab"
}
NETWORK_IDS = {
    "connections", "capture", "intercept", "proxy", "dns", "filters", "bandwidth",
    "repeater", "keylog", "pcap", "fuzzer", "offensive", "websocket", "scripting",
    "decoder", "site_map", "scope", "cookies", "scanner", "recon", "intruder",
    "collaborator", "sequencer", "comparer", "jwt_lab", "match_replace", "session",
    "api", "ws_editor", "h2_editor", "logger", "csp", "upstream", "browser", "reports",
    "headless"
}
DEBUG_IDS = {
    "cpu", "breakpoints", "memory_map", "call_stack", "threads", "watches", "handles",
    "trace", "strings", "bookmarks", "modules", "patches", "seh", "cfg"
}
FORBIDDEN_PATH_PARTS = ("testlab", "plugin_plans", "/plugin/", "/server/", "/driver/")
ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]+$")
REGISTRY_SOURCE = ROOT / "src" / "standalone" / "src" / "core" / "ui" / "application_view_registry.cpp"
DYNAMIC_VIEW_SOURCES = {
    "view.background_tasks": (
        ROOT / "src" / "standalone" / "src" / "core" / "ui" / "task_center.cpp",
        "tasks.render = render_tasks_view",
    ),
    "view.diagnostics": (
        ROOT / "src" / "standalone" / "src" / "core" / "ui" / "task_center.cpp",
        "diagnostics.render = render_diagnostics_view",
    ),
}


def fail(errors: list[str], message: str) -> None:
    errors.append(message)


def validate_registry_coverage(target_ids: set[str], errors: list[str]) -> None:
    try:
        source = REGISTRY_SOURCE.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        fail(errors, f"canonical view registry unreadable: {exc}")
        return
    catalog_start = source.find("constexpr catalog_entry_t k_catalog[]")
    catalog_end = source.find("#undef AIDA_VIEW", catalog_start)
    if catalog_start < 0 or catalog_end < 0:
        fail(errors, "canonical view registry catalog boundary is missing")
        return
    catalog = source[catalog_start:catalog_end]
    entries: dict[str, tuple[str, str, str]] = {}
    for line in catalog.splitlines():
        macro_match = re.search(
            r'\b(AIDA_VIEW|AIDA_DEBUG_VIEW|AIDA_NETWORK_VIEW)\(\s*"([a-z0-9._-]+)"',
            line,
        )
        if not macro_match:
            continue
        macro, view_id = macro_match.groups()
        if view_id in entries:
            fail(errors, f"duplicate canonical registry view {view_id}")
            continue
        category = ""
        subview = ""
        if macro == "AIDA_VIEW":
            route_match = re.search(
                r'AIDA_VIEW\(\s*"[^"]+"\s*,\s*"[^"]*"\s*,\s*([a-z_]+)\s*,\s*'
                r'[a-z_]+\s*,\s*[a-z_]+\s*,\s*([a-z_]+)\s*,',
                line,
            )
            if not route_match:
                fail(errors, f"canonical registry entry is not statically parseable: {view_id}")
                continue
            category, subview = route_match.groups()
        entries[view_id] = (macro, category, subview)
    if not entries:
        fail(errors, "canonical view registry catalog contains no parsed views")
        return

    generic_routes = {
        ("analysis", "analysis"): "analysis_hub_view::render_subview",
        ("memory", "scan"): "scan_hub_view::render_subview",
        ("types", "types"): "types_hub_view::render_subview",
        ("debugger", "debugger"): "debugger_view::render_pane",
        ("network", "network"): "network_view::render_pane",
    }
    for view_id, (macro, category, subview) in sorted(entries.items()):
        if view_id not in target_ids:
            fail(errors, f"canonical registry view lacks inventory target coverage: {view_id}")
        if macro == "AIDA_DEBUG_VIEW":
            category, subview = "debugger", "debugger"
        elif macro == "AIDA_NETWORK_VIEW":
            category, subview = "network", "network"
        generic_symbol = generic_routes.get((category, subview))
        if generic_symbol:
            if generic_symbol not in source:
                fail(errors, f"canonical registry route missing for {view_id}: {generic_symbol}")
            continue
        dispatch = f'std::strcmp(entry.id, "{view_id}")'
        if dispatch not in source:
            fail(errors, f"canonical registry view has no render dispatch: {view_id}")

    for view_id, (owner, render_binding) in DYNAMIC_VIEW_SOURCES.items():
        if view_id not in target_ids:
            fail(errors, f"dynamic registry view lacks inventory target coverage: {view_id}")
        try:
            owner_source = owner.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            fail(errors, f"dynamic registry owner unreadable for {view_id}: {exc}")
            continue
        if f'stable_view_id_t("{view_id}")' not in owner_source or render_binding not in owner_source:
            fail(errors, f"dynamic registry view has no exact render binding: {view_id}")


def main() -> int:
    errors: list[str] = []
    try:
        data = json.loads(MANIFEST.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"FAIL manifest unreadable: {exc}")
        return 1

    if data.get("schema_version") != 1:
        fail(errors, "schema_version must be 1")
    authority = data.get("authority")
    if not isinstance(authority, dict) or authority.get("scope") != "standalone_human_ui":
        fail(errors, "authority.scope must be standalone_human_ui")
    gates = data.get("gates")
    if not isinstance(gates, dict) or set(gates) != REQUIRED_GATES:
        fail(errors, "gates must contain exactly G1-G5")
    else:
        for gate_id, gate in gates.items():
            if not isinstance(gate, dict) or not gate.get("decision") or not gate.get("evidence"):
                fail(errors, f"{gate_id} lacks decision/evidence")
            if gate_id == "G2" and len(gate.get("candidates", [])) != 3:
                fail(errors, "G2 must resolve exactly three legacy candidates")
            if gate_id == "G3":
                capabilities = gate.get("capabilities", [])
                if not capabilities or any(c.get("status") == "available" and not c.get("provider_symbol") for c in capabilities):
                    fail(errors, "G3 available capabilities require provider_symbol evidence")
                if any(c.get("status") == "absent" and c.get("register_ui") for c in capabilities):
                    fail(errors, "G3 absent capabilities cannot register UI")
            if gate_id == "G4":
                contracts = gate.get("cancel_contracts", [])
                if not contracts or any(not c.get("owner_symbol") or not c.get("handle_type") for c in contracts):
                    fail(errors, "G4 cancellation contracts require exact owner symbols and handles")
                if gate.get("global_cancel_enabled") is not False:
                    fail(errors, "G4 global Cancel must remain disabled until owner opt-in")
            if gate_id == "G5":
                if gate.get("new_sensitive_persistence") is not False:
                    fail(errors, "G5 forbids new sensitive persistence")
                if gate.get("task_history_storage") != "bounded_memory_only":
                    fail(errors, "G5 task history must be bounded_memory_only")

    inventory = data.get("inventory")
    if not isinstance(inventory, list):
        fail(errors, "inventory must be an array")
        inventory = []
    if len(inventory) < 120:
        fail(errors, f"inventory cardinality {len(inventory)} is below 120")

    stable_ids: set[str] = set()
    target_ids: set[str] = set()
    counts: Counter[str] = Counter()
    workspaces: set[str] = set()
    for index, item in enumerate(inventory):
        prefix = f"inventory[{index}]"
        if not isinstance(item, dict):
            fail(errors, f"{prefix} is not an object")
            continue
        required = {
            "stable_id", "target_id", "kind", "label", "workspace", "category",
            "source_path", "source_symbol", "current_status", "disposition",
            "migration_status", "parity_requirements"
        }
        missing = sorted(required - set(item))
        if missing:
            fail(errors, f"{prefix} missing {','.join(missing)}")
            continue
        stable_id = item["stable_id"]
        target_id = item["target_id"]
        if not isinstance(stable_id, str) or not ID_RE.fullmatch(stable_id):
            fail(errors, f"{prefix} invalid stable_id")
        elif stable_id in stable_ids:
            fail(errors, f"duplicate stable_id {stable_id}")
        else:
            stable_ids.add(stable_id)
        if not isinstance(target_id, str) or not ID_RE.fullmatch(target_id):
            fail(errors, f"{prefix} invalid target_id")
        elif target_id in target_ids:
            fail(errors, f"duplicate target_id {target_id}")
        else:
            target_ids.add(target_id)
        kind = item["kind"]
        counts[kind] += 1
        workspaces.add(item["workspace"])
        if item["current_status"] not in ALLOWED_STATUS:
            fail(errors, f"{prefix} incomplete current_status")
        if item["disposition"] not in ALLOWED_DISPOSITION:
            fail(errors, f"{prefix} incomplete disposition")
        if item["migration_status"] not in ALLOWED_MIGRATION:
            fail(errors, f"{prefix} incomplete migration_status")
        requirements = item["parity_requirements"]
        if not isinstance(requirements, list) or not requirements or any(not isinstance(v, str) or len(v) < 4 for v in requirements):
            fail(errors, f"{prefix} lacks parity requirements")
        path = item["source_path"].replace("\\", "/")
        lower_path = f"/{path.lower().strip('/')}/"
        if not path.startswith("src/standalone/src/"):
            fail(errors, f"{prefix} source path is outside standalone runtime")
        if any(part in lower_path for part in FORBIDDEN_PATH_PARTS):
            fail(errors, f"{prefix} source path is forbidden: {path}")
        if not (ROOT / pathlib.PurePosixPath(path)).is_file():
            fail(errors, f"{prefix} source path does not exist: {path}")
        if not isinstance(item["source_symbol"], str) or len(item["source_symbol"].strip()) < 2:
            fail(errors, f"{prefix} source_symbol missing")

    missing_kinds = REQUIRED_KINDS - set(counts)
    if missing_kinds:
        fail(errors, f"missing categories: {','.join(sorted(missing_kinds))}")
    missing_workspaces = REQUIRED_WORKSPACES - workspaces
    if missing_workspaces:
        fail(errors, f"missing workspaces: {','.join(sorted(missing_workspaces))}")
    for kind, minimum in MINIMUM_KIND_COUNTS.items():
        if counts[kind] < minimum:
            fail(errors, f"kind {kind} has {counts[kind]}, expected at least {minimum}")
    if counts["dialog"] != EXPECTED_DIALOG_COUNT:
        fail(errors, f"kind dialog has {counts['dialog']}, expected exactly {EXPECTED_DIALOG_COUNT}")
    missing_ids = REQUIRED_IDS - stable_ids
    if missing_ids:
        fail(errors, f"missing required IDs: {','.join(sorted(missing_ids))}")
    missing_network = {f"view.network.{name}" for name in NETWORK_IDS} - stable_ids
    if missing_network:
        fail(errors, f"missing network views: {','.join(sorted(missing_network))}")
    missing_debug = {f"view.debug.{name}" for name in DEBUG_IDS} - stable_ids
    if missing_debug:
        fail(errors, f"missing debugger views: {','.join(sorted(missing_debug))}")

    validate_registry_coverage(target_ids, errors)

    standalone_source = ROOT / "src" / "standalone" / "src"
    shared_modal_owner = standalone_source / "core" / "ui" / "design_system.cpp"
    for suffix in ("*.cpp", "*.hpp"):
        for source in standalone_source.rglob(suffix):
            if source == shared_modal_owner:
                continue
            try:
                text = source.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                text = source.read_text(encoding="utf-8", errors="replace")
            if "BeginPopupModal(" in text:
                fail(errors, f"raw BeginPopupModal outside shared owner: {source.relative_to(ROOT)}")

    if errors:
        for error in errors:
            print(f"FAIL {error}")
        print(f"FAILED errors={len(errors)} rows={len(inventory)}")
        return 1
    category_summary = ",".join(f"{key}:{counts[key]}" for key in sorted(counts))
    print(f"PASS rows={len(inventory)} stable_ids={len(stable_ids)} target_ids={len(target_ids)}")
    print(f"CATEGORIES {category_summary}")
    print(f"WORKSPACES {','.join(sorted(workspaces))}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
