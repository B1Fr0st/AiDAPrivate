from __future__ import annotations

import os
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
STANDALONE_SRC = ROOT / "src" / "standalone" / "src"
CORE_DIR = STANDALONE_SRC / "core"
MCP_DIR = CORE_DIR / "mcp"

SOURCE_SUFFIXES = {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx", ".inl"}
SKIP_DIRS = {
    ".git", ".claude", ".serena", ".vs", ".vscode", ".deps",
    "build", "build-ninja", "out", "dist", "node_modules", "__pycache__",
}

REQUIRED_PRODUCER_KINDS = [
    "background_command",
    "camoufox_longop",
    "driver_debugger",
    "scanner",
    "decompiler",
    "pdb_parser",
    "broad_enumeration",
    "burp_network",
    "api_monitor",
    "feature_worker",
]

REQUIRED_LOG_EVENTS = [
    "MCP-DOWNSTREAM-ADMIT",
    "MCP-DOWNSTREAM-REJECT",
    "MCP-DOWNSTREAM-RELEASE",
    "MCP-DOWNSTREAM-SNAPSHOT",
    "BACKGROUND-COMMAND-ADMIT",
    "BACKGROUND-COMMAND-REJECT",
    "BACKGROUND-COMMAND-RELEASE",
    "CAMOUFOX-LONGOP-ADMIT",
    "CAMOUFOX-LONGOP-REJECT",
    "CAMOUFOX-LONGOP-RELEASE",
    "DRIVER-DEBUGGER-QUOTA-ADMIT",
    "DRIVER-DEBUGGER-QUOTA-REJECT",
    "DRIVER-DEBUGGER-QUOTA-RELEASE",
    "FEATURE-WORKER-GROUP-ADMIT",
    "FEATURE-WORKER-GROUP-REJECT",
    "FEATURE-WORKER-GROUP-RELEASE",
    "FEATURE-WORKER-GROUP-SNAPSHOT",
    "BURP-NETWORK-WORKER-ADMIT",
    "BURP-NETWORK-WORKER-REJECT",
    "BURP-NETWORK-WORKER-RELEASE",
]

MIGRATION_TARGET_DIRS = [
    CORE_DIR / "scanner",
    CORE_DIR / "disasm",
    CORE_DIR / "analysis",
    CORE_DIR / "network" / "burp",
]

PDB_FILES = [
    CORE_DIR / "analysis" / "pdb_parser.hpp",
    CORE_DIR / "analysis" / "pdb_downloader.cpp",
    CORE_DIR / "analysis" / "pdb_downloader.hpp",
]

COLLABORATOR_FILES = [
    CORE_DIR / "network" / "burp" / "collaborator.cpp",
    CORE_DIR / "network" / "burp" / "collaborator.hpp",
]

BROWSER_TOOL_DIRS = [
    CORE_DIR / "network" / "burp",
]

checks = []
all_passed = True


def check_result(name: str, passed: bool, detail: str = "") -> None:
    global all_passed
    status = "PASS" if passed else "FAIL"
    if not passed:
        all_passed = False
    line = f"  [{status}] {name}"
    if detail:
        line += f" -- {detail}"
    checks.append(line)


def read_file(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return ""


def iter_source_files(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        parts = Path(dirpath).parts
        if any(p in SKIP_DIRS for p in parts):
            dirnames.clear()
            continue
        for fname in filenames:
            ext = Path(fname).suffix.lower()
            if ext in SOURCE_SUFFIXES:
                yield Path(dirpath) / fname


def scan_all_sources():
    texts = {}
    for path in iter_source_files(STANDALONE_SRC):
        rel = path.relative_to(ROOT).as_posix()
        texts[rel] = read_file(path)
    return texts


def check_1_governor_header():
    header_path = MCP_DIR / "downstream_producer_governor.hpp"
    text = read_file(header_path)
    if not text:
        check_result("1: downstream_producer_governor.hpp exists", False, "file not found")
        return
    check_result("1: downstream_producer_governor.hpp exists", True)
    missing = []
    for kind in REQUIRED_PRODUCER_KINDS:
        if kind not in text:
            missing.append(kind)
    if missing:
        check_result("1: all required producer kinds defined", False,
                     f"missing: {', '.join(missing)}")
    else:
        check_result("1: all required producer kinds defined", True,
                     f"all {len(REQUIRED_PRODUCER_KINDS)} kinds present")
    required_symbols = [
        "governor_t",
        "snapshot_json",
        "quota_json",
        "request_shutdown",
        "try_admit",
        "scoped_admission_t",
        "feature_worker_group_t",
        "rejection_json",
    ]
    missing_syms = [s for s in required_symbols if s not in text]
    if missing_syms:
        check_result("1: governor public API symbols present", False,
                     f"missing: {', '.join(missing_syms)}")
    else:
        check_result("1: governor public API symbols present", True)


def check_2_command_sessions_admission():
    path = CORE_DIR / "tools" / "command_sessions.hpp"
    text = read_file(path)
    if not text:
        check_result("2: command_sessions.hpp exists", False, "file not found")
        return
    has_include = "downstream_producer_governor.hpp" in text
    check_result("2: command_sessions includes governor header", has_include)
    has_try_admit = "governor_t::instance().try_admit" in text or "try_admit" in text
    check_result("2: command_sessions calls try_admit", has_try_admit)
    has_background = "producer_kind_t::background_command" in text
    check_result("2: command_sessions uses background_command kind", has_background)
    has_admission_fn = "acquire_background_command_admission" in text
    check_result("2: admission helper function defined", has_admission_fn)
    has_token_field = "downstream_token" in text
    check_result("2: session carries downstream admission token", has_token_field)
    tools_dir = CORE_DIR / "tools"
    mcp_tools_text = ""
    for f in tools_dir.glob("*"):
        if f.is_file() and f.suffix.lower() in SOURCE_SUFFIXES:
            mcp_tools_text += read_file(f)
    mcp_standalone_text = read_file(MCP_DIR / "mcp_standalone.cpp")
    combined_tools = mcp_tools_text + mcp_standalone_text
    has_admission_call = "acquire_background_command_admission" in combined_tools and \
        combined_tools.count("acquire_background_command_admission") > 1
    check_result("2: admission acquired before process launch", has_admission_call,
                 "function defined" if has_admission_fn else "function not defined")
    has_admit_log = "BACKGROUND-COMMAND-ADMIT" in text
    check_result("2: BACKGROUND-COMMAND-ADMIT log present", has_admit_log)
    has_reject_log = "BACKGROUND-COMMAND-REJECT" in text
    check_result("2: BACKGROUND-COMMAND-REJECT log present", has_reject_log)
    has_release_log = "BACKGROUND-COMMAND-RELEASE" in text
    check_result("2: BACKGROUND-COMMAND-RELEASE log present", has_release_log)


def check_3_camoufox_longop():
    found_admit = False
    found_kind = False
    found_try = False
    bridge_files = list((CORE_DIR / "network" / "burp").glob("camoufox_bridge*"))
    bridge_files += list((CORE_DIR / "network" / "burp").glob("camoufox_*"))
    all_texts = ""
    for path in bridge_files:
        all_texts += read_file(path)
    if not bridge_files:
        check_result("3: camoufox bridge files exist", False, "no camoufox_bridge* files found")
    else:
        check_result("3: camoufox bridge files exist", True,
                     f"{len(bridge_files)} files")
    found_kind = "camoufox_longop" in all_texts
    check_result("3: camoufox_longop producer kind referenced", found_kind)
    found_try = "try_admit" in all_texts or "scoped_admission_t::acquire" in all_texts
    check_result("3: camoufox bridge acquires admission", found_try)
    found_admit_log = "CAMOUFOX-LONGOP-ADMIT" in all_texts
    check_result("3: CAMOUFOX-LONGOP-ADMIT log present", found_admit_log)
    found_reject_log = "CAMOUFOX-LONGOP-REJECT" in all_texts
    check_result("3: CAMOUFOX-LONGOP-REJECT log present", found_reject_log)
    found_release_log = "CAMOUFOX-LONGOP-RELEASE" in all_texts
    check_result("3: CAMOUFOX-LONGOP-RELEASE log present", found_release_log)


def check_4_driver_debugger_quota():
    driver_files = list((CORE_DIR / "tools").glob("driver_tools*"))
    all_texts = ""
    for path in driver_files:
        all_texts += read_file(path)
    if not driver_files:
        check_result("4: driver tools files exist", False, "no driver_tools* files found")
    else:
        check_result("4: driver tools files exist", True, f"{len(driver_files)} files")
    found_kind = "driver_debugger" in all_texts
    check_result("4: driver_debugger producer kind referenced", found_kind)
    found_try = "try_admit" in all_texts or "scoped_admission_t::acquire" in all_texts
    check_result("4: driver tools acquire admission", found_try)
    found_admit_log = "DRIVER-DEBUGGER-QUOTA-ADMIT" in all_texts
    check_result("4: DRIVER-DEBUGGER-QUOTA-ADMIT log present", found_admit_log)
    found_reject_log = "DRIVER-DEBUGGER-QUOTA-REJECT" in all_texts
    check_result("4: DRIVER-DEBUGGER-QUOTA-REJECT log present", found_reject_log)
    found_release_log = "DRIVER-DEBUGGER-QUOTA-RELEASE" in all_texts
    check_result("4: DRIVER-DEBUGGER-QUOTA-RELEASE log present", found_release_log)


def check_5_scanner_admission():
    scanner_files = list((CORE_DIR / "scanner").glob("*"))
    all_texts = ""
    for path in scanner_files:
        if path.is_file() and path.suffix.lower() in SOURCE_SUFFIXES:
            all_texts += read_file(path)
    if not all_texts:
        check_result("5: scanner source files exist", False, "no scanner source files found")
    else:
        check_result("5: scanner source files exist", True)
    has_feature_worker = "feature_worker_group" in all_texts or "feature_worker_group_t" in all_texts
    has_try_admit = "try_admit" in all_texts or "scoped_admission_t::acquire" in all_texts
    has_scanner_kind = "producer_kind_t::scanner" in all_texts or '"scanner"' in all_texts
    passed = has_feature_worker or (has_try_admit and has_scanner_kind)
    detail = []
    if has_feature_worker:
        detail.append("feature_worker_group")
    if has_try_admit:
        detail.append("try_admit")
    if has_scanner_kind:
        detail.append("scanner kind")
    check_result("5: scanner uses bounded worker group or downstream admission",
                 passed, ", ".join(detail) if detail else "none found")
    has_admit_log = "FEATURE-WORKER-GROUP-ADMIT" in all_texts
    check_result("5: FEATURE-WORKER-GROUP-ADMIT log present", has_admit_log)
    has_reject_log = "FEATURE-WORKER-GROUP-REJECT" in all_texts
    check_result("5: FEATURE-WORKER-GROUP-REJECT log present", has_reject_log)
    has_release_log = "FEATURE-WORKER-GROUP-RELEASE" in all_texts
    check_result("5: FEATURE-WORKER-GROUP-RELEASE log present", has_release_log)


def check_6_no_raw_thread_groups():
    thread_vector_re = re.compile(r"std::vector\s*<\s*std::thread\s*>\s+(\w+)")
    thread_emplace_re = re.compile(r"(\w+)\s*\.\s*(?:emplace_back|push_back)\s*\(")
    raw_thread_re = re.compile(r"\bstd::thread\s+(?!hardware_concurrency)")
    violations = []
    for target_dir in MIGRATION_TARGET_DIRS:
        if not target_dir.exists():
            continue
        for path in iter_source_files(target_dir):
            text = read_file(path)
            rel = path.relative_to(ROOT).as_posix()
            for match in raw_thread_re.finditer(text):
                line = text.count("\n", 0, match.start()) + 1
                snippet = text[match.start():match.start() + 80].split("\n")[0].strip()
                violations.append(f"{rel}:{line}: {snippet}")
            for match in thread_vector_re.finditer(text):
                var_name = match.group(1)
                emplace_pattern = re.compile(
                    r"\b" + re.escape(var_name) + r"\s*\.\s*(?:emplace_back|push_back)\s*\(")
                for ematch in emplace_pattern.finditer(text):
                    line = text.count("\n", 0, ematch.start()) + 1
                    snippet = text[ematch.start():ematch.start() + 80].split("\n")[0].strip()
                    violations.append(f"{rel}:{line}: {snippet}")
    if violations:
        detail = f"{len(violations)} raw std::thread occurrences"
        if len(violations) <= 5:
            detail += ": " + "; ".join(violations)
        check_result("6: no raw std::thread groups in migration targets", False, detail)
    else:
        check_result("6: no raw std::thread groups in migration targets", True)


def check_7_no_raw_detach():
    detach_re = re.compile(r"\.\s*detach\s*\(")
    violations = []
    for path in PDB_FILES + COLLABORATOR_FILES:
        if not path.exists():
            continue
        text = read_file(path)
        rel = path.relative_to(ROOT).as_posix()
        for match in detach_re.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            snippet = text[match.start():match.start() + 80].split("\n")[0].strip()
            violations.append(f"{rel}:{line}: {snippet}")
    if violations:
        detail = f"{len(violations)} detach() calls: " + "; ".join(violations)
        check_result("7: no raw detach() in PDB parser or collaborator", False, detail)
    else:
        check_result("7: no raw detach() in PDB parser or collaborator", True)


def check_8_health_endpoint_snapshot():
    path = MCP_DIR / "mcp_standalone.cpp"
    text = read_file(path)
    if not text:
        check_result("8: mcp_standalone.cpp exists", False, "file not found")
        return
    has_include = '#include "downstream_producer_governor.hpp"' in text
    check_result("8: mcp_standalone includes governor header", has_include)
    has_snapshot = 'out["downstream_producers"]' in text
    check_result("8: health endpoint includes downstream_producers field", has_snapshot)
    has_snapshot_json = "snapshot_json()" in text
    check_result("8: health endpoint calls snapshot_json()", has_snapshot_json)
    has_quota_json = "quota_json()" in text
    check_result("8: health endpoint calls quota_json()", has_quota_json)
    has_phase7 = "phase7_downstream_producer_governance" in text
    check_result("8: phase field updated to phase7", has_phase7)
    overload_keys = [
        'out["overload_flags"]["downstream_background_commands"]',
        'out["overload_flags"]["downstream_camoufox_longops"]',
        'out["overload_flags"]["downstream_driver_debugger"]',
        'out["overload_flags"]["downstream_scanner"]',
        'out["overload_flags"]["downstream_decompiler"]',
        'out["overload_flags"]["downstream_pdb"]',
        'out["overload_flags"]["downstream_broad_enum"]',
        'out["overload_flags"]["downstream_burp_network"]',
        'out["overload_flags"]["downstream_api_monitor"]',
    ]
    missing_overload = [k for k in overload_keys if k not in text]
    if missing_overload:
        check_result("8: all downstream overload flags present", False,
                     f"missing: {', '.join(missing_overload)}")
    else:
        check_result("8: all downstream overload flags present", True,
                     f"{len(overload_keys)} flags")
    has_rejection = 'out["rejection_counters"]["downstream_total"]' in text
    check_result("8: downstream rejection counters present", has_rejection)
    has_oldest = 'downstream_oldest_active' in text
    check_result("8: downstream oldest age in oldest_age_ms", has_oldest)
    has_contributors = 'downstream_pressure_contributors' in text
    check_result("8: downstream pressure contributors present", has_contributors)
    has_log = "MCP-DOWNSTREAM-SNAPSHOT" in text
    check_result("8: MCP-DOWNSTREAM-SNAPSHOT log event present", has_log)


def check_9_request_shutdown():
    path = MCP_DIR / "mcp_standalone.cpp"
    text = read_file(path)
    has_shutdown = "mcp_standalone::downstream::governor_t::instance().request_shutdown()" in text
    count = text.count("mcp_standalone::downstream::governor_t::instance().request_shutdown()")
    if has_shutdown and count >= 2:
        check_result("9: request_shutdown() called in shutdown paths", True,
                     f"{count} call sites")
    elif has_shutdown:
        check_result("9: request_shutdown() called in shutdown paths", True,
                     f"{count} call site(s)")
    else:
        check_result("9: request_shutdown() called in shutdown paths", False,
                     "no request_shutdown() calls found")


def check_10_no_non_camoufox_browser_fallback():
    browser_exe_re = re.compile(
        r'(?:chrome\.exe|msedge\.exe|firefox\.exe|chromium\.exe|iexplore\.exe)',
        re.IGNORECASE,
    )
    playwright_browser_re = re.compile(
        r'playwright\s*\.\s*(?:chromium|firefox|webkit)\b',
        re.IGNORECASE,
    )
    fallback_logic_re = re.compile(
        r'(?:system_default_browser|default_browser_fallback|browser_fallback|'
        r'fallback_browser|use_chrome_fallback|use_edge_fallback|use_firefox_fallback|'
        r'chrome_fallback|edge_fallback|firefox_fallback|'
        r'open_with_chrome|open_with_edge|open_with_firefox|open_with_default|'
        r'launch_chrome|launch_edge|launch_firefox|'
        r'start_chrome|start_edge|start_firefox)',
        re.IGNORECASE,
    )
    shellexec_browser_re = re.compile(
        r'(?:ShellExecute\w*|CreateProcess\w*)\s*\([^)]*(?:chrome|msedge|firefox|chromium|iexplore)',
        re.IGNORECASE | re.DOTALL,
    )
    violations = []
    for target_dir in BROWSER_TOOL_DIRS:
        if not target_dir.exists():
            continue
        for path in iter_source_files(target_dir):
            text = read_file(path)
            rel = path.relative_to(ROOT).as_posix()
            lines = text.splitlines()
            for idx, line in enumerate(lines, 1):
                stripped = line.strip()
                if stripped.startswith('"') and stripped.endswith('",') and len(stripped) > 200:
                    continue
                if stripped.startswith('"') and stripped.endswith('"') and len(stripped) > 200:
                    continue
                for pattern, label in [
                    (browser_exe_re, "non-Camoufox browser executable"),
                    (playwright_browser_re, "playwright non-Camoufox browser API"),
                    (fallback_logic_re, "browser fallback logic"),
                    (shellexec_browser_re, "ShellExecute/CreateProcess with non-Camoufox browser"),
                ]:
                    for match in pattern.finditer(line):
                        snippet = match.group(0)[:120]
                        violations.append(f"{rel}:{idx}: {label}: {snippet}")
    if violations:
        detail = f"{len(violations)} non-Camoufox browser fallback(s): " + "; ".join(violations[:5])
        check_result("10: no non-Camoufox browser fallback introduced", False, detail)
    else:
        check_result("10: no non-Camoufox browser fallback introduced", True)


def check_11_log_events():
    all_source = scan_all_sources()
    combined = "\n".join(all_source.values())
    missing = []
    for event in REQUIRED_LOG_EVENTS:
        if event not in combined:
            missing.append(event)
    if missing:
        check_result("11: all required log event names present", False,
                     f"missing {len(missing)}: {', '.join(missing)}")
    else:
        check_result("11: all required log event names present", True,
                     f"all {len(REQUIRED_LOG_EVENTS)} events found")


def strip_comments_and_strings(text: str) -> str:
    result = []
    i = 0
    n = len(text)
    in_string = False
    in_char = False
    in_line_comment = False
    in_block_comment = False
    while i < n:
        c = text[i]
        nc = text[i + 1] if i + 1 < n else ''
        if in_line_comment:
            if c == '\n':
                in_line_comment = False
                result.append(c)
            i += 1
            continue
        if in_block_comment:
            if c == '*' and nc == '/':
                in_block_comment = False
                i += 2
                continue
            i += 1
            continue
        if in_string:
            if c == '\\':
                i += 2
                continue
            if c == '"':
                in_string = False
            i += 1
            continue
        if in_char:
            if c == '\\':
                i += 2
                continue
            if c == "'":
                in_char = False
            i += 1
            continue
        if c == '/' and nc == '/':
            in_line_comment = True
            i += 2
            continue
        if c == '/' and nc == '*':
            in_block_comment = True
            i += 2
            continue
        if c == '"':
            in_string = True
            i += 1
            continue
        if c == "'":
            in_char = True
            i += 1
            continue
        result.append(c)
        i += 1
    return ''.join(result)


def check_12_decompiler_admission():
    disasm_dir = CORE_DIR / "disasm"
    decompiler_path = disasm_dir / "decompiler_engine.hpp"
    text = read_file(decompiler_path)
    if not text:
        check_result("12: decompiler_engine.hpp exists", False, "file not found")
        return
    check_result("12: decompiler_engine.hpp exists", True)
    has_include = "downstream_producer_governor.hpp" in text
    check_result("12: decompiler includes governor header", has_include)
    has_kind = "producer_kind_t::decompiler" in text
    check_result("12: decompiler uses producer_kind_t::decompiler", has_kind)
    has_admission = "scoped_admission_t::acquire" in text or "try_admit" in text
    check_result("12: decompiler acquires scoped admission", has_admission)
    all_disasm_text = ""
    for path in iter_source_files(disasm_dir):
        all_disasm_text += read_file(path)
    has_admit_log = "FEATURE-WORKER-GROUP-ADMIT" in all_disasm_text
    check_result("12: FEATURE-WORKER-GROUP-ADMIT in disasm directory", has_admit_log)
    has_reject_log = "FEATURE-WORKER-GROUP-REJECT" in all_disasm_text
    check_result("12: FEATURE-WORKER-GROUP-REJECT in disasm directory", has_reject_log)


def check_13_pdb_parser_admission():
    analysis_dir = CORE_DIR / "analysis"
    pdb_parser_path = analysis_dir / "pdb_parser.hpp"
    text = read_file(pdb_parser_path)
    if not text:
        check_result("13: pdb_parser.hpp exists", False, "file not found")
        return
    check_result("13: pdb_parser.hpp exists", True)
    has_include = "downstream_producer_governor.hpp" in text
    check_result("13: pdb_parser includes governor header", has_include)
    has_kind = "producer_kind_t::pdb_parser" in text
    check_result("13: pdb_parser uses producer_kind_t::pdb_parser", has_kind)
    pdb_dl_path = analysis_dir / "pdb_downloader.cpp"
    dl_text = read_file(pdb_dl_path)
    if not dl_text:
        check_result("13: pdb_downloader.cpp exists", False, "file not found")
    else:
        check_result("13: pdb_downloader.cpp exists", True)
        dl_has_include = "downstream_producer_governor.hpp" in dl_text
        check_result("13: pdb_downloader includes governor header", dl_has_include)
        dl_has_admission = (
            "scoped_admission_t::acquire" in dl_text
            or "try_admit" in dl_text
            or "acquire_background_command_admission" in dl_text
        )
        check_result("13: pdb_downloader acquires admission", dl_has_admission)
    all_analysis_text = ""
    for path in iter_source_files(analysis_dir):
        all_analysis_text += read_file(path)
    has_admit_log = "FEATURE-WORKER-GROUP-ADMIT" in all_analysis_text
    check_result("13: FEATURE-WORKER-GROUP-ADMIT in analysis directory", has_admit_log)
    has_reject_log = "FEATURE-WORKER-GROUP-REJECT" in all_analysis_text
    check_result("13: FEATURE-WORKER-GROUP-REJECT in analysis directory", has_reject_log)


def check_14_broad_enumeration_admission():
    analysis_dir = CORE_DIR / "analysis"
    analysis_tools_path = analysis_dir / "analysis_tools_standalone.cpp"
    text = read_file(analysis_tools_path)
    if not text:
        check_result("14: analysis_tools_standalone.cpp exists", False, "file not found")
        return
    check_result("14: analysis_tools_standalone.cpp exists", True)
    has_kind = "producer_kind_t::broad_enumeration" in text
    check_result("14: broad_enumeration producer kind referenced", has_kind)
    has_admission = "scoped_admission_t::acquire" in text or "try_admit" in text
    check_result("14: broad enumeration acquires admission", has_admission)


def check_15_debugger_thread_intel_admission():
    debugger_dir = CORE_DIR / "debugger"
    debugger_tools_path = debugger_dir / "debugger_tools_standalone.cpp"
    text = read_file(debugger_tools_path)
    if not text:
        check_result("15: debugger_tools_standalone.cpp exists", False, "file not found")
    else:
        check_result("15: debugger_tools_standalone.cpp exists", True)
        has_include = "downstream_producer_governor.hpp" in text
        check_result("15: debugger tools include governor header", has_include)
        has_quota = (
            "driver_debugger_quota_guard_t" in text
            or "acquire_driver_debugger_quota" in text
        )
        check_result("15: debugger tools use driver debugger quota guard", has_quota)
    thread_intel_path = debugger_dir / "thread_intel_tools_standalone.cpp"
    ti_text = read_file(thread_intel_path)
    if not ti_text:
        check_result("15: thread_intel_tools_standalone.cpp exists", False, "file not found")
    else:
        check_result("15: thread_intel_tools_standalone.cpp exists", True)
        ti_has_include = "downstream_producer_governor.hpp" in ti_text
        check_result("15: thread intel tools include governor header", ti_has_include)
        ti_has_quota = (
            "driver_debugger_quota_guard_t" in ti_text
            or "acquire_driver_debugger_quota" in ti_text
        )
        check_result("15: thread intel tools use driver debugger quota guard", ti_has_quota)
    all_debugger_text = ""
    for path in iter_source_files(debugger_dir):
        all_debugger_text += read_file(path)
    has_admit_log = "DRIVER-DEBUGGER-QUOTA-ADMIT" in all_debugger_text
    check_result("15: DRIVER-DEBUGGER-QUOTA-ADMIT in debugger directory", has_admit_log)
    has_reject_log = "DRIVER-DEBUGGER-QUOTA-REJECT" in all_debugger_text
    check_result("15: DRIVER-DEBUGGER-QUOTA-REJECT in debugger directory", has_reject_log)
    has_release_log = "DRIVER-DEBUGGER-QUOTA-RELEASE" in all_debugger_text
    check_result("15: DRIVER-DEBUGGER-QUOTA-RELEASE in debugger directory", has_release_log)


def check_16_no_raw_thread_in_proxies():
    proxy_files = [
        CORE_DIR / "network" / "quic_proxy.cpp",
        CORE_DIR / "network" / "mitm_proxy.cpp",
    ]
    raw_thread_re = re.compile(r"\bstd::thread\s+(?!hardware_concurrency)")
    violations = []
    for path in proxy_files:
        if not path.exists():
            continue
        text = read_file(path)
        rel = path.relative_to(ROOT).as_posix()
        stripped = strip_comments_and_strings(text)
        for match in raw_thread_re.finditer(stripped):
            line = stripped.count("\n", 0, match.start()) + 1
            snippet = stripped[match.start():match.start() + 80].split("\n")[0].strip()
            violations.append(f"{rel}:{line}: {snippet}")
    has_alternative = False
    for path in proxy_files:
        if not path.exists():
            continue
        text = read_file(path)
        if "win_thread" in text or "joinable_thread_t" in text:
            has_alternative = True
            break
    if violations:
        detail = f"{len(violations)} raw std::thread occurrences: " + "; ".join(violations)
        check_result("16: no raw std::thread in quic_proxy.cpp and mitm_proxy.cpp",
                     False, detail)
    else:
        alt_detail = "uses win_thread/joinable_thread_t" if has_alternative else "no thread creation found"
        check_result("16: no raw std::thread in quic_proxy.cpp and mitm_proxy.cpp",
                     True, alt_detail)


def check_17_rejection_by_reason():
    path = MCP_DIR / "mcp_standalone.cpp"
    text = read_file(path)
    if not text:
        check_result("17: mcp_standalone.cpp exists", False, "file not found")
        return
    has_by_reason = "downstream_by_reason" in text or "rejection_by_reason" in text
    check_result("17: health endpoint includes rejection by reason", has_by_reason)


def check_18_burp_network_worker_admission():
    burp_dir = CORE_DIR / "network" / "burp"
    target_files = [
        "active_scanner.cpp",
        "content_discovery.cpp",
        "crawler.cpp",
        "scan_orchestrator.cpp",
        "collaborator.cpp",
        "intruder_engine.cpp",
    ]
    missing = []
    found = []
    for fname in target_files:
        path = burp_dir / fname
        text = read_file(path)
        if not text:
            missing.append(f"{fname} (not found)")
            continue
        if "BURP-NETWORK-WORKER-ADMIT" in text:
            found.append(fname)
        else:
            missing.append(fname)
    if missing:
        check_result("18: BURP-NETWORK-WORKER-ADMIT in all burp worker files",
                     False, f"missing in: {', '.join(missing)}")
    else:
        check_result("18: BURP-NETWORK-WORKER-ADMIT in all burp worker files",
                     True, f"{len(found)} files")


def main() -> int:
    print("=" * 72)
    print("Phase 7: Downstream Producer Governance - Static Verification")
    print("=" * 72)
    print()
    check_1_governor_header()
    check_2_command_sessions_admission()
    check_3_camoufox_longop()
    check_4_driver_debugger_quota()
    check_5_scanner_admission()
    check_6_no_raw_thread_groups()
    check_7_no_raw_detach()
    check_8_health_endpoint_snapshot()
    check_9_request_shutdown()
    check_10_no_non_camoufox_browser_fallback()
    check_11_log_events()
    check_12_decompiler_admission()
    check_13_pdb_parser_admission()
    check_14_broad_enumeration_admission()
    check_15_debugger_thread_intel_admission()
    check_16_no_raw_thread_in_proxies()
    check_17_rejection_by_reason()
    check_18_burp_network_worker_admission()
    for line in checks:
        print(line)
    print()
    if all_passed:
        print("RESULT: ALL CHECKS PASSED")
        return 0
    else:
        failed = sum(1 for l in checks if "[FAIL]" in l)
        passed = sum(1 for l in checks if "[PASS]" in l)
        print(f"RESULT: {failed} CHECK(S) FAILED, {passed} PASSED")
        return 1


if __name__ == "__main__":
    sys.exit(main())
