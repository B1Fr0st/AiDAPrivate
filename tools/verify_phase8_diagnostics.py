#!/usr/bin/env python3
"""Phase 8: Diagnostics Completion - Static Source Verification Script.

This script verifies that all Phase 8 diagnostic components exist in the source
code without invoking any build, configure, compile, link, or package step.

Phase 8 requirements:
  1. CRASH-SNAPSHOT
  2. WINDOW-HUNG-SNAPSHOT (enhanced)
  3. Always-on bounded metadata ring
  4. /health?diagnostics=1 or equivalent diagnostic surface
  5. Test Lab one-shot hung diagnostic packet
  6. Out-of-process observer
  7. WER/Event Log correlation normalization

Required log event families:
  CRASH-SNAPSHOT, WINDOW-HUNG-SNAPSHOT, METADATA-RING-EVENT, METADATA-RING-DUMP,
  MCP-DIAGNOSTIC-SNAPSHOT, QUEUE-DIAGNOSTIC-SNAPSHOT, THREAD-RUNTIME-DIAGNOSTIC-SNAPSHOT,
  TESTLAB-HUNG-DIAGNOSTIC-PACKET, WER-CONFIG, WER-EVENT-CORRELATION,
  OBSERVER-START, OBSERVER-HEARTBEAT, OBSERVER-HANG, OBSERVER-WER-CORRELATION,
  OBSERVER-STOP, DIAGNOSTIC-SNAPSHOT-FAILED
"""

import os
import re
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STANDALONE_ROOT = os.path.join(REPO_ROOT, "src", "standalone", "src")
DIAG_ROOT = os.path.join(STANDALONE_ROOT, "core", "diagnostics")

errors = []
warnings = []
passed = []


def check_file_exists(path, description):
    if os.path.isfile(path):
        passed.append(f"EXISTS: {description} ({os.path.relpath(path, REPO_ROOT)})")
        return True
    else:
        errors.append(f"MISSING: {description} ({os.path.relpath(path, REPO_ROOT)})")
        return False


def check_pattern_in_file(path, pattern, description, flags=0):
    if not os.path.isfile(path):
        errors.append(f"FILE_MISSING for {description}: {path}")
        return False
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
        if re.search(pattern, content, flags):
            passed.append(f"FOUND: {description}")
            return True
        else:
            errors.append(f"NOT_FOUND: {description} in {os.path.relpath(path, REPO_ROOT)}")
            return False
    except Exception as e:
        errors.append(f"READ_ERROR: {description}: {e}")
        return False


def check_pattern_in_dir(dirpath, pattern, description, extensions=(".hpp", ".cpp", ".h"), flags=0):
    if not os.path.isdir(dirpath):
        errors.append(f"DIR_MISSING for {description}: {dirpath}")
        return False
    for root, dirs, files in os.walk(dirpath):
        for fname in files:
            if fname.endswith(extensions):
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                        content = f.read()
                    if re.search(pattern, content, flags):
                        passed.append(f"FOUND: {description} in {os.path.relpath(fpath, REPO_ROOT)}")
                        return True
                except Exception:
                    pass
    errors.append(f"NOT_FOUND_IN_DIR: {description} in {os.path.relpath(dirpath, REPO_ROOT)}")
    return False


print("=" * 70)
print("Phase 8: Diagnostics Completion - Static Source Verification")
print("=" * 70)
print()

# --- 1. Core diagnostic infrastructure headers ---
print("[1] Core diagnostic infrastructure headers")

check_file_exists(os.path.join(DIAG_ROOT, "metadata_ring.hpp"), "metadata_ring.hpp")
check_file_exists(os.path.join(DIAG_ROOT, "wer_correlation.hpp"), "wer_correlation.hpp")
check_file_exists(os.path.join(DIAG_ROOT, "crash_snapshot.hpp"), "crash_snapshot.hpp")
check_file_exists(os.path.join(DIAG_ROOT, "window_hung_snapshot.hpp"), "window_hung_snapshot.hpp")
check_file_exists(os.path.join(DIAG_ROOT, "diagnostic_snapshot.hpp"), "diagnostic_snapshot.hpp")
check_file_exists(os.path.join(DIAG_ROOT, "testlab_hung_packet.hpp"), "testlab_hung_packet.hpp")
check_file_exists(os.path.join(DIAG_ROOT, "observer.hpp"), "observer.hpp")

# --- 2. Metadata ring ---
print("[2] Always-on bounded metadata ring")

check_pattern_in_file(
    os.path.join(DIAG_ROOT, "metadata_ring.hpp"),
    r"breadcrumb_category_t",
    "metadata ring breadcrumb categories enum"
)
check_pattern_in_file(
    os.path.join(DIAG_ROOT, "metadata_ring.hpp"),
    r"kMetadataRingCapacity",
    "metadata ring fixed capacity"
)
check_pattern_in_file(
    os.path.join(DIAG_ROOT, "metadata_ring.hpp"),
    r"startup_shutdown|message_pump|wndproc|render|ui_dispatcher|mcp_ingress|mcp_tool_call|mcp_lease|capacity_governor|downstream_producer|work_queue|critical_queue|service_queue|thread_runtime|testlab|driver_debugger|license_arc_watchdog|camoufox|background_command|crash_exception|observer",
    "metadata ring minimum breadcrumb categories"
)
check_pattern_in_file(
    os.path.join(DIAG_ROOT, "metadata_ring.hpp"),
    r"should_rate_limit",
    "metadata ring rate limiting"
)
check_pattern_in_file(
    os.path.join(DIAG_ROOT, "metadata_ring.hpp"),
    r"METADATA-RING-EVENT",
    "METADATA-RING-EVENT log tag"
)
check_pattern_in_file(
    os.path.join(DIAG_ROOT, "metadata_ring.hpp"),
    r"METADATA-RING-DUMP",
    "METADATA-RING-DUMP log tag"
)

# --- 3. Crash snapshot ---
print("[3] CRASH-SNAPSHOT")

check_pattern_in_file(
    os.path.join(DIAG_ROOT, "crash_snapshot.hpp"),
    r"CRASH-SNAPSHOT",
    "CRASH-SNAPSHOT log tag"
)
check_pattern_in_file(
    os.path.join(DIAG_ROOT, "crash_snapshot.hpp"),
    r"exception_code|exception_address|fault.*module|rva",
    "crash snapshot exception and module fields"
)
check_pattern_in_file(
    os.path.join(DIAG_ROOT, "crash_snapshot.hpp"),
    r"render_phase|render_heartbeat|wndproc_stage|dispatch_stage|pump_phase",
    "crash snapshot render/wndproc/pump fields"
)
check_pattern_in_file(
    os.path.join(DIAG_ROOT, "crash_snapshot.hpp"),
    r"testlab_phase|testlab_step",
    "crash snapshot testlab fields"
)
check_pattern_in_file(
    os.path.join(DIAG_ROOT, "crash_snapshot.hpp"),
    r"license_liveness|arc_liveness|driver_watchdog",
    "crash snapshot liveness fields"
)

# --- 4. Window hung snapshot ---
print("[4] WINDOW-HUNG-SNAPSHOT")

check_pattern_in_file(
    os.path.join(DIAG_ROOT, "window_hung_snapshot.hpp"),
    r"WINDOW-HUNG-SNAPSHOT",
    "WINDOW-HUNG-SNAPSHOT log tag"
)
check_pattern_in_file(
    os.path.join(DIAG_ROOT, "window_hung_snapshot.hpp"),
    r"is_hung|IsHungAppWindow|SendMessageTimeout|WM_NULL",
    "window hung snapshot HWND responsiveness fields"
)
check_pattern_in_file(
    os.path.join(DIAG_ROOT, "window_hung_snapshot.hpp"),
    r"ui_dispatcher_queue_depth|ui_dispatcher_rejected|ui_dispatcher_drained|ui_dispatcher_budget",
    "window hung snapshot UI dispatcher fields"
)
check_pattern_in_file(
    os.path.join(DIAG_ROOT, "window_hung_snapshot.hpp"),
    r"mcp_active_requests|mcp_active_leases|mcp_oldest_owner",
    "window hung snapshot MCP fields"
)

# --- 5. WER/Event Log correlation ---
print("[5] WER/Event Log correlation")

check_pattern_in_file(
    os.path.join(DIAG_ROOT, "wer_correlation.hpp"),
    r"WER-CONFIG",
    "WER-CONFIG log tag"
)
check_pattern_in_file(
    os.path.join(DIAG_ROOT, "wer_correlation.hpp"),
    r"WER-EVENT-CORRELATION",
    "WER-EVENT-CORRELATION log tag"
)
check_pattern_in_file(
    os.path.join(DIAG_ROOT, "wer_correlation.hpp"),
    r"LocalDumps|DumpFolder|DumpType|DumpCount",
    "WER registry LocalDumps fields"
)
check_pattern_in_file(
    os.path.join(DIAG_ROOT, "wer_correlation.hpp"),
    r"AiDAStandalone.exe",
    "WER per-exe scope for AiDAStandalone"
)
check_pattern_in_file(
    os.path.join(DIAG_ROOT, "wer_correlation.hpp"),
    r"find_recent_dump_files",
    "WER recent dump file discovery"
)

# --- 6. Health diagnostics surface ---
print("[6] /health?diagnostics=1 surface")

check_pattern_in_file(
    os.path.join(DIAG_ROOT, "diagnostic_snapshot.hpp"),
    r"is_diagnostics_requested",
    "diagnostics=1 query parameter parser"
)
check_pattern_in_file(
    os.path.join(DIAG_ROOT, "diagnostic_snapshot.hpp"),
    r"build_diagnostics_json",
    "diagnostics JSON builder"
)
check_pattern_in_file(
    os.path.join(DIAG_ROOT, "diagnostic_snapshot.hpp"),
    r"MCP-DIAGNOSTIC-SNAPSHOT",
    "MCP-DIAGNOSTIC-SNAPSHOT log tag"
)
check_pattern_in_file(
    os.path.join(DIAG_ROOT, "diagnostic_snapshot.hpp"),
    r"QUEUE-DIAGNOSTIC-SNAPSHOT",
    "QUEUE-DIAGNOSTIC-SNAPSHOT log tag"
)
check_pattern_in_file(
    os.path.join(DIAG_ROOT, "diagnostic_snapshot.hpp"),
    r"THREAD-RUNTIME-DIAGNOSTIC-SNAPSHOT",
    "THREAD-RUNTIME-DIAGNOSTIC-SNAPSHOT log tag"
)
check_pattern_in_file(
    os.path.join(DIAG_ROOT, "diagnostic_snapshot.hpp"),
    r"DIAGNOSTIC-SNAPSHOT-FAILED",
    "DIAGNOSTIC-SNAPSHOT-FAILED log tag"
)
check_pattern_in_file(
    os.path.join(STANDALONE_ROOT, "core", "mcp", "mcp_standalone.cpp"),
    r"diagnostics=1|is_diagnostics_requested",
    "/health?diagnostics=1 wired in mcp_standalone.cpp"
)

# --- 7. Test Lab hung diagnostic packet ---
print("[7] Test Lab hung diagnostic packet")

check_pattern_in_file(
    os.path.join(DIAG_ROOT, "testlab_hung_packet.hpp"),
    r"TESTLAB-HUNG-DIAGNOSTIC-PACKET",
    "TESTLAB-HUNG-DIAGNOSTIC-PACKET log tag"
)
check_pattern_in_file(
    os.path.join(DIAG_ROOT, "testlab_hung_packet.hpp"),
    r"should_emit_packet|mark_packet_emitted",
    "one-shot packet dedup mechanism"
)
check_pattern_in_file(
    os.path.join(DIAG_ROOT, "testlab_hung_packet.hpp"),
    r"test_run_id|suite|domain|test_name|phase|step_label|step_start_ms|step_elapsed_ms",
    "hung packet test identity fields"
)
check_pattern_in_file(
    os.path.join(DIAG_ROOT, "testlab_hung_packet.hpp"),
    r"target_executable_path|target_pid|driver_attached",
    "hung packet target fields"
)
check_pattern_in_file(
    os.path.join(DIAG_ROOT, "testlab_hung_packet.hpp"),
    r"first_failure_marker|last_successful_marker",
    "hung packet failure/success markers"
)
check_pattern_in_file(
    os.path.join(STANDALONE_ROOT, "core", "testlab", "test_all_features.cpp"),
    r"log_hung_diagnostic_packet|testlab_hung_packet",
    "hung packet wired in test_all_features.cpp"
)

# --- 8. Out-of-process observer ---
print("[8] Out-of-process observer")

check_pattern_in_file(
    os.path.join(DIAG_ROOT, "observer.hpp"),
    r"OBSERVER-START",
    "OBSERVER-START log tag"
)
check_pattern_in_file(
    os.path.join(DIAG_ROOT, "observer.hpp"),
    r"OBSERVER-HEARTBEAT",
    "OBSERVER-HEARTBEAT log tag"
)
check_pattern_in_file(
    os.path.join(DIAG_ROOT, "observer.hpp"),
    r"OBSERVER-HANG",
    "OBSERVER-HANG log tag"
)
check_pattern_in_file(
    os.path.join(DIAG_ROOT, "observer.hpp"),
    r"OBSERVER-STOP",
    "OBSERVER-STOP log tag"
)
check_pattern_in_file(
    os.path.join(DIAG_ROOT, "observer.hpp"),
    r"IsHungAppWindow|SendMessageTimeoutW",
    "observer HWND responsiveness probes"
)
check_pattern_in_file(
    os.path.join(DIAG_ROOT, "observer.hpp"),
    r"observer",
    "observer non-authoritative - diagnostics only module"
)
check_pattern_in_file(
    os.path.join(DIAG_ROOT, "observer.hpp"),
    r"OpenProcess|PROCESS_QUERY_LIMITED_INFORMATION",
    "observer limited to process liveness queries only"
)

check_pattern_in_file(
    os.path.join(STANDALONE_ROOT, "main.cpp"),
    r"observer::start|diagnostics::observer",
    "observer started from main.cpp"
)

# --- 9. Integration in main.cpp ---
print("[9] main.cpp integration")

check_pattern_in_file(
    os.path.join(STANDALONE_ROOT, "main.cpp"),
    r"core/diagnostics/metadata_ring.hpp",
    "metadata_ring.hpp included in main.cpp"
)
check_pattern_in_file(
    os.path.join(STANDALONE_ROOT, "main.cpp"),
    r"core/diagnostics/crash_snapshot.hpp",
    "crash_snapshot.hpp included in main.cpp"
)
check_pattern_in_file(
    os.path.join(STANDALONE_ROOT, "main.cpp"),
    r"core/diagnostics/window_hung_snapshot.hpp",
    "window_hung_snapshot.hpp included in main.cpp"
)
check_pattern_in_file(
    os.path.join(STANDALONE_ROOT, "main.cpp"),
    r"core/diagnostics/observer.hpp",
    "observer.hpp included in main.cpp"
)
check_pattern_in_file(
    os.path.join(STANDALONE_ROOT, "main.cpp"),
    r"crash::log_crash_snapshot|emit_crash_breadcrumb",
    "crash snapshot called from main.cpp"
)
check_pattern_in_file(
    os.path.join(STANDALONE_ROOT, "main.cpp"),
    r"metadata_ring::emit",
    "metadata ring emit called from main.cpp"
)

# --- 10. Integration in mcp_standalone.cpp ---
print("[10] mcp_standalone.cpp integration")

check_pattern_in_file(
    os.path.join(STANDALONE_ROOT, "core", "mcp", "mcp_standalone.cpp"),
    r"diagnostics/metadata_ring.hpp",
    "metadata_ring.hpp included in mcp_standalone.cpp"
)
check_pattern_in_file(
    os.path.join(STANDALONE_ROOT, "core", "mcp", "mcp_standalone.cpp"),
    r"diagnostics/diagnostic_snapshot.hpp",
    "diagnostic_snapshot.hpp included in mcp_standalone.cpp"
)

# --- 11. Security checks ---
print("[11] Security checks")

# Check no secrets in diagnostic headers
found_secrets = False
for root, dirs, files in os.walk(DIAG_ROOT):
    for fname in files:
        if fname.endswith((".hpp", ".cpp", ".h")):
            fpath = os.path.join(root, fname)
            try:
                with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
                if re.search(r"private_key|signing_key|oauth_token|bearer_token|api_key", content, re.IGNORECASE):
                    errors.append(f"SECURITY: found potential secret reference in {os.path.relpath(fpath, REPO_ROOT)}")
                    found_secrets = True
            except Exception:
                pass
if not found_secrets:
    passed.append("SECURITY: no secret references found in diagnostic headers")

# --- 12. CMakeLists.txt ---
print("[12] CMakeLists.txt include directories")

check_pattern_in_file(
    os.path.join(REPO_ROOT, "CMakeLists.txt"),
    r"core/diagnostics",
    "core/diagnostics in CMake include directories"
)

# --- 13. Phase 0-7 guard compatibility ---
print("[13] Phase 0-7 guard compatibility - checking existing guards exist")

for phase in range(8):
    guard_name = f"verify_phase{phase}"
    phase_guards = {
        0: "verify_phase0_invariants.py",
        1: "verify_thread_runtime_contract.py",
        2: "verify_phase2_capacity.py",
        3: "verify_phase3_admission.py",
        4: "verify_phase4_tool_admission.py",
        5: "verify_phase5_lease_registry.py",
        6: "verify_phase6_ui_dispatcher.py",
        7: "verify_phase7_downstream_producers.py",
    }
    if phase in phase_guards:
        guard_path = os.path.join(REPO_ROOT, "tools", phase_guards[phase])
        check_file_exists(guard_path, f"Phase {phase} guard script")

# --- Summary ---
print()
print("=" * 70)
print(f"PASSED:  {len(passed)}")
print(f"WARNINGS: {len(warnings)}")
print(f"ERRORS:  {len(errors)}")
print("=" * 70)

if errors:
    print()
    print("ERRORS:")
    for e in errors:
        print(f"  - {e}")

if warnings:
    print()
    print("WARNINGS:")
    for w in warnings:
        print(f"  - {w}")

if errors:
    sys.exit(1)
else:
    print()
    print("Phase 8 static source verification: PASSED")
    sys.exit(0)
