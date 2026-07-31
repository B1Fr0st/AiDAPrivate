#!/usr/bin/env python3

import json
import os
import re
import subprocess
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BENCHMARK_ROOT = os.path.join(
    REPO_ROOT, "src", "standalone", "src", "core", "analysis", "benchmark")
RUNNER_CPP = os.path.join(BENCHMARK_ROOT, "benchmark_runner.cpp")
RUNNER_HPP = os.path.join(BENCHMARK_ROOT, "benchmark_runner.hpp")
SCORECARD_HPP = os.path.join(BENCHMARK_ROOT, "benchmark_scorecard.hpp")
TOOLS_CPP = os.path.join(
    REPO_ROOT, "src", "standalone", "src", "core", "analysis",
    "analysis_tools_standalone.cpp")
TESTLAB_CPP = os.path.join(
    REPO_ROOT, "src", "standalone", "src", "core", "testlab",
    "test_all_analysis.cpp")
HARNESS_CPP = os.path.join(
    REPO_ROOT, "src", "standalone", "tests", "analysis_workspace",
    "analysis_benchmark_harness.cpp")
CMAKE_MANIFEST = os.path.join(
    REPO_ROOT, "cmake", "aida_c03_safe_headless_manifest.cmake")
BASELINE_JSON = os.path.join(
    REPO_ROOT, "src", "standalone", "tests", "analysis_workspace",
    "baselines", "synthetic_32mb_baseline.json")

errors = []
passed = []
warnings = []


def rel(path):
    return os.path.relpath(path, REPO_ROOT)


def read(path):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


def check_file(path, label):
    if os.path.isfile(path):
        passed.append(f"EXISTS: {label} ({rel(path)})")
        return True
    errors.append(f"MISSING: {label} ({rel(path)})")
    return False


def require(path, pattern, label, flags=0):
    if not check_file(path, label):
        return False
    text = read(path)
    if re.search(pattern, text, flags):
        passed.append(f"FOUND: {label}")
        return True
    errors.append(f"NOT_FOUND: {label} in {rel(path)}")
    return False


def forbid(path, pattern, label, flags=0):
    if not check_file(path, label):
        return False
    text = read(path)
    matches = re.findall(pattern, text, flags)
    if matches:
        errors.append(
            f"FORBIDDEN_FOUND: {label} in {rel(path)} ({len(matches)} matches)")
        return False
    passed.append(f"ABSENT: {label}")
    return True


def require_all(path, checks, prefix, flags=0):
    ok = True
    for label, pattern in checks:
        if not require(path, pattern, f"{prefix}: {label}", flags):
            ok = False
    return ok


def verdict_actual(report, key):
    container = None
    if isinstance(report, dict):
        if isinstance(report.get("sla"), dict):
            container = report["sla"]
        elif isinstance(report.get("program_sla"), dict):
            container = report["program_sla"]
    if not container or not isinstance(container.get("verdicts"), list):
        return None
    for verdict in container["verdicts"]:
        if isinstance(verdict, dict) and verdict.get("key") == key:
            return verdict.get("actual")
    return None


def python_compare(baseline, candidate):
    thresholds = None
    for source in (candidate, baseline):
        for slot in ("sla", "program_sla"):
            block = source.get(slot) if isinstance(source, dict) else None
            if isinstance(block, dict) and isinstance(block.get("thresholds"), dict):
                thresholds = block["thresholds"]
                break
        if thresholds:
            break
    verdicts = []
    any_fail = False
    if thresholds:
        for key, target in thresholds.items():
            if key in ("threshold_schema", "threshold_schema_version"):
                continue
            base_actual = verdict_actual(baseline, key)
            cand_actual = verdict_actual(candidate, key)
            if base_actual is None or cand_actual is None:
                verdicts.append((key, "NOT_COMPARABLE"))
                continue
            if isinstance(target, bool):
                worse = base_actual is True and cand_actual is False
                any_fail = any_fail or worse
                verdicts.append((key, "FAIL" if worse else "PASS"))
                continue
            if not isinstance(base_actual, (int, float)) or not isinstance(
                    cand_actual, (int, float)):
                verdicts.append((key, "NOT_COMPARABLE"))
                continue
            if base_actual == 0:
                verdicts.append((key, "NOT_COMPARABLE"))
                continue
            delta_pct = (cand_actual - base_actual) / base_actual * 100.0
            lower_is_better = "_max" in key
            worse = delta_pct > 5.0 if lower_is_better else delta_pct < -5.0
            any_fail = any_fail or worse
            verdicts.append((key, "FAIL" if worse else "PASS"))
    informational_keys = (
        "file_bytes_per_s", "decode_bytes_per_s", "instructions_per_s",
        "functions_per_s", "index_bytes_per_s", "persist_bytes_per_s",
        "decompile_all_funcs_per_s")
    for key in informational_keys:
        before = baseline.get("throughput", {}).get(key) if isinstance(
            baseline.get("throughput"), dict) else None
        after = candidate.get("throughput", {}).get(key) if isinstance(
            candidate.get("throughput"), dict) else None
        if not isinstance(before, (int, float)) or not isinstance(
                after, (int, float)) or before == 0:
            continue
        delta_pct = (after - before) / before * 100.0
        if delta_pct < -10.0:
            warnings.append(
                f"LIVE_WARN: {key} regressed {delta_pct:.2f}% "
                f"({before} -> {after})")
    return any_fail, verdicts


def find_harness_exe():
    root = os.environ.get("AIDA_C03_DEVELOPER_ROOT")
    if not root:
        return None
    for config in ("Release", "RelWithDebInfo", "Debug", "MinSizeRel"):
        candidate = os.path.join(
            root, "direct", config, "aida_c03_analysis_benchmark_harness.exe")
        if os.path.isfile(candidate):
            return candidate
    return None


def run_live(baseline_path, candidate_path):
    print()
    print("=" * 76)
    print("Live compare mode")
    print("=" * 76)
    if not os.path.isfile(baseline_path):
        errors.append(f"LIVE_MISSING: baseline report {baseline_path}")
        return
    if not os.path.isfile(candidate_path):
        errors.append(f"LIVE_MISSING: candidate report {candidate_path}")
        return
    harness = find_harness_exe()
    if harness:
        print(f"harness: {harness}")
        completed = subprocess.run(
            [harness, "compare", baseline_path, candidate_path],
            capture_output=True, text=True)
        if completed.stdout:
            print(completed.stdout)
        if completed.returncode != 0:
            errors.append(
                f"LIVE_FAIL: harness compare exited {completed.returncode}")
        else:
            passed.append("LIVE_PASS: harness compare verdict PASS")
        return
    print("harness binary not found; using the in-Python 5%/5%/10% compare")
    try:
        with open(baseline_path, "r", encoding="utf-8") as f:
            baseline = json.load(f)
        with open(candidate_path, "r", encoding="utf-8") as f:
            candidate = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        errors.append(f"LIVE_INVALID: {exc}")
        return
    any_fail, verdicts = python_compare(baseline, candidate)
    for key, state in verdicts:
        print(f"  {key}: {state}")
    if any_fail:
        errors.append("LIVE_FAIL: python compare verdict FAIL")
    else:
        passed.append("LIVE_PASS: python compare verdict PASS")


def main():
    print("=" * 76)
    print("Benchmark Gates Static Source Verification")
    print("=" * 76)

    require(SCORECARD_HPP, r"scorecard_schema_v2_version\s*=\s*2",
            "scorecard schema v2 version constant")
    require(SCORECARD_HPP, r"aida\.hyperperf\.program-scorecard",
            "scorecard schema marker")
    require(SCORECARD_HPP, r"aida\.hyperperf\.compare-verdict",
            "compare verdict schema marker")
    require(SCORECARD_HPP, r"aida\.hyperperf\.synthetic-structural-baseline",
            "structural baseline schema marker")
    require(SCORECARD_HPP, r"harvest_workspace_baseline_metrics",
            "workspace metrics harvest helper")
    require(SCORECARD_HPP, r"baseline_phase_count",
            "13-phase harvest loop bound")
    require(SCORECARD_HPP, r"scorecard_phase_entries",
            "full phase entry builder")
    require(SCORECARD_HPP, r"compare_scorecards",
            "shared scorecard compare")
    require(SCORECARD_HPP, r"compare_structural_baseline",
            "shared structural compare")
    require(SCORECARD_HPP, r"evaluate_phase_budgets",
            "phase budget gate evaluation")
    require(SCORECARD_HPP, r"structural_compare_update_allowed",
            "structural baseline update guard")

    require(RUNNER_HPP, r"decompile_batch_lanes", "request decompile_batch_lanes")
    require(RUNNER_HPP, r"memory_sample_interval_ms",
            "request memory_sample_interval_ms")
    require(RUNNER_HPP, r"baseline_report_path", "request baseline_report_path")
    require(RUNNER_HPP, r"record_baseline_name", "request record_baseline_name")

    require(RUNNER_CPP, r"scorecard_schema_v2_version",
            "runner emits scorecard schema v2")
    require(RUNNER_CPP, r"harvest_workspace_baseline_metrics",
            "runner harvests workspace baseline metrics")
    require(RUNNER_CPP, r"scorecard_phase_entries\(\*harvested\)",
            "runner builds 13-phase block from harvest")
    require(RUNNER_CPP, r"parallelism_efficiency",
            "runner computes parallelism_efficiency")
    require(RUNNER_CPP, r"decompile_batch_orchestrator_t::create",
            "runner parallel decompile orchestrator path")
    require(RUNNER_CPP, r"run_parallel_decompile_stage",
            "runner parallel decompile stage")
    require(RUNNER_CPP, r"benchmark_runtime_sampler_t",
            "runner runtime sampler")
    require(RUNNER_CPP, r"sample_interval_ms", "runner sampler interval reporting")
    require(RUNNER_CPP, r"baseline_report_path", "runner baseline compare input")
    require(RUNNER_CPP, r"record_baseline_name", "runner baseline recording")
    require(RUNNER_CPP, r"compare_scorecards", "runner compare verdict emission")
    require(RUNNER_CPP, r"evaluate_phase_budgets", "runner phase budget gates")
    require(RUNNER_CPP, r"auto_analysis_wall", "claim track: auto-analysis wall")
    require(RUNNER_CPP, r"batch_decompile_throughput",
            "claim track: batch decompile throughput")

    forbid(RUNNER_CPP, r"\{\s*\"worker_pool\"\s*,\s*nullptr\s*\}",
            "no hollow worker_pool block")
    forbid(RUNNER_CPP, r"verdict_entry\(\s*\"metadata_ready_ms_max\"",
            "no hardcoded metadata_ready NOT_MEASURED entry")
    forbid(RUNNER_CPP, r"verdict_entry\(\s*\"workspace_mapped_bytes_max\"",
            "no hardcoded workspace_mapped NOT_MEASURED entry")
    forbid(RUNNER_CPP, r"verdict_entry\(\s*\"global_mapped_bytes_max\"",
            "no hardcoded global_mapped NOT_MEASURED entry")
    forbid(RUNNER_CPP, r"\"decode_window_granularity_ms\"",
            "no 25ms window as the decode data source")
    forbid(RUNNER_CPP, r"service->decompile",
            "no sequential decompile sampler loop")

    require(TOOLS_CPP, r"action == \"compare\"", "MCP compare action")
    require(TOOLS_CPP, r"compare_scorecards", "MCP compare wiring")
    require(TOOLS_CPP, r"batch_lanes", "MCP batch_lanes passthrough")
    require(TOOLS_CPP, r"sample_ms", "MCP sample_ms passthrough")
    require(TOOLS_CPP, r"record_baseline", "MCP record_baseline passthrough")
    require(TOOLS_CPP, r"run_determinism_stage",
            "MCP run_determinism_stage passthrough")
    require(TOOLS_CPP, r"determinism_runs", "MCP determinism_runs passthrough")

    require(TESTLAB_CPP, r"scorecard_schema_version\"\]\.get<int>\(\) != 2",
            "test lab asserts scorecard schema v2")
    require(TESTLAB_CPP, r"parallelism_efficiency",
            "test lab asserts parallelism_efficiency")
    require(TESTLAB_CPP, r"peak_rss_bytes", "test lab asserts peak RSS")
    require(TESTLAB_CPP, r"v2_complete", "test lab v2 completeness gate")
    require(TESTLAB_CPP, r"benchmark phase name=%s wall_ms",
            "test lab per-phase evidence lines")

    require(HARNESS_CPP, r"run_real_mode", "harness real mode")
    require(HARNESS_CPP, r"mode == \"real\"", "harness real mode dispatch")
    require(HARNESS_CPP, r"run_synthetic_compare_mode",
            "harness synthetic_compare mode")
    require(HARNESS_CPP, r"mode == \"synthetic_compare\"",
            "harness synthetic_compare dispatch")
    require(HARNESS_CPP, r"workspace_last_baseline_metrics",
            "harness WS1 instrumented-pass shortcut source marker")
    require(HARNESS_CPP, r"direct_instrumented_analyzer",
            "harness instrumented-pass fallback source marker")
    require(HARNESS_CPP, r"benchmark::harvest_workspace_baseline_metrics",
            "harness WS1 harvest")
    require(HARNESS_CPP, r"scorecard_schema_v2_version",
            "harness scorecard schema v2 alignment")

    require(CMAKE_MANIFEST, r"aida_c03_benchmark_synthetic_compare_harness",
            "ctest synthetic_compare target")
    require(CMAKE_MANIFEST, r"baselines/synthetic_32mb_baseline\.json",
            "ctest synthetic_compare baseline argument")

    if check_file(BASELINE_JSON, "committed structural baseline"):
        try:
            with open(BASELINE_JSON, "r", encoding="utf-8") as f:
                baseline = json.load(f)
            if baseline.get("schema") != "aida.hyperperf.synthetic-structural-baseline":
                errors.append("BASELINE_SCHEMA: baseline schema marker mismatch")
            else:
                passed.append("BASELINE_SCHEMA: schema marker present")
            if baseline.get("schema_version") != 1:
                errors.append("BASELINE_SCHEMA: baseline schema_version must be 1")
            contract = baseline.get("contract")
            if not isinstance(contract, dict):
                errors.append("BASELINE_CONTRACT: missing contract block")
            else:
                phases = contract.get("phases")
                if not isinstance(phases, list) or len(phases) != 13:
                    errors.append(
                        "BASELINE_CONTRACT: contract.phases must list all 13 baseline phases")
                else:
                    passed.append("BASELINE_CONTRACT: 13 phase names")
                blocks = contract.get("required_scorecard_blocks")
                if not isinstance(blocks, list) or not blocks:
                    errors.append(
                        "BASELINE_CONTRACT: required_scorecard_blocks must be a non-empty list")
                else:
                    passed.append("BASELINE_CONTRACT: required scorecard blocks")
                band = contract.get("write_amplification_band")
                if not (isinstance(band, list) and len(band) == 2 and
                        all(isinstance(v, (int, float)) for v in band)):
                    errors.append(
                        "BASELINE_CONTRACT: write_amplification_band must be [min, max] numbers")
                else:
                    passed.append("BASELINE_CONTRACT: write amplification band")
            capture = baseline.get("capture")
            if not isinstance(capture, dict) or capture.get("status") not in (
                    "pending", "captured"):
                errors.append(
                    "BASELINE_CAPTURE: capture.status must be pending or captured")
            else:
                passed.append(f"BASELINE_CAPTURE: status={capture.get('status')}")
        except json.JSONDecodeError as exc:
            errors.append(f"BASELINE_JSON: invalid JSON: {exc}")
    forbid(BASELINE_JSON,
            r"\"[^\"]*(?:wall_ns|wall_ms|_ns|_ms\b|elapsed|duration|latency|per_s|throughput)[^\"]*\"\s*:",
            "no wall-clock or throughput keys in the committed baseline")

    argv = sys.argv[1:]
    if argv and argv[0] == "--live":
        if len(argv) != 3:
            errors.append("USAGE: verify_benchmark_gates.py --live <baseline.json> <candidate.json>")
        else:
            run_live(argv[1], argv[2])
    elif argv:
        errors.append(f"USAGE: unknown arguments: {' '.join(argv)}")

    print()
    print("=" * 76)
    print(f"PASSED:   {len(passed)}")
    print(f"WARNINGS: {len(warnings)}")
    print(f"ERRORS:   {len(errors)}")
    print("=" * 76)
    if errors:
        print()
        print("ERRORS:")
        for item in errors:
            print(f"  - {item}")
    if warnings:
        print()
        print("WARNINGS:")
        for item in warnings:
            print(f"  - {item}")
    if errors:
        sys.exit(1)
    print()
    print("Benchmark gates static source verification: PASSED")
    sys.exit(0)


if __name__ == "__main__":
    main()
