#pragma once

#include "../workspace/analysis_metrics.hpp"
#include "../workspace/analysis_workspace.hpp"

#include <algorithm>
#include <cstdint>
#include <memory>
#include <string>
#include <type_traits>
#include <utility>

#include <nlohmann/json.hpp>

namespace aida::analysis::benchmark {

inline constexpr const char* scorecard_schema_v2 = "aida.hyperperf.program-scorecard";
inline constexpr std::uint32_t scorecard_schema_v2_version = 2;
inline constexpr const char* compare_verdict_schema_v1 = "aida.hyperperf.compare-verdict";
inline constexpr std::uint32_t compare_verdict_schema_v1_version = 1;
inline constexpr const char* structural_baseline_schema_v1 = "aida.hyperperf.synthetic-structural-baseline";
inline constexpr std::uint32_t structural_baseline_schema_v1_version = 1;
inline constexpr const char* phase_budget_gate_schema_v1 = "aida.hyperperf.phase-budget-gates";
inline constexpr const char* metrics_unavailable_reason =
    "workspace_baseline_metrics_publication_unavailable";

template <typename T, typename = void>
struct has_last_baseline_metrics_t : std::false_type {};

template <typename T>
struct has_last_baseline_metrics_t<T,
    std::void_t<decltype(std::declval<const T&>().last_baseline_metrics())>>
    : std::true_type {};

template <typename WorkspaceT>
std::shared_ptr<const analysis_metrics_snapshot_t> harvest_workspace_baseline_metrics(
    const std::shared_ptr<WorkspaceT>& workspace)
{
    if constexpr (has_last_baseline_metrics_t<WorkspaceT>::value) {
        if (workspace)
            return workspace->last_baseline_metrics();
    }
    return nullptr;
}

inline std::uint64_t metrics_counter_from_json(const nlohmann::json& metrics, const char* name)
{
    if (!metrics.is_object())
        return 0;
    const auto counters = metrics.find("counters");
    if (counters == metrics.end() || !counters->is_object())
        return 0;
    const auto entry = counters->find(name);
    if (entry == counters->end() || !entry->is_number())
        return 0;
    return entry->get<std::uint64_t>();
}

inline const nlohmann::json* metrics_phase_from_json(const nlohmann::json& metrics,
                                                     const char* name)
{
    if (!metrics.is_object())
        return nullptr;
    const auto phases = metrics.find("phases");
    if (phases == metrics.end() || !phases->is_array())
        return nullptr;
    for (const auto& phase : *phases) {
        if (phase.is_object() && phase.value("name", std::string()) == name)
            return &phase;
    }
    return nullptr;
}

inline std::uint64_t metrics_phase_wall_ns_from_json(const nlohmann::json& metrics,
                                                     const char* name)
{
    const auto* phase = metrics_phase_from_json(metrics, name);
    if (!phase)
        return 0;
    return phase->value("wall_ns", 0ULL);
}

inline nlohmann::json metrics_phase_names_from_json(const nlohmann::json& metrics)
{
    nlohmann::json names = nlohmann::json::array();
    if (!metrics.is_object())
        return names;
    const auto phases = metrics.find("phases");
    if (phases == metrics.end() || !phases->is_array())
        return names;
    for (const auto& phase : *phases) {
        if (phase.is_object())
            names.push_back(phase.value("name", std::string()));
    }
    return names;
}

inline nlohmann::json nullable_rate(std::uint64_t units, std::uint64_t wall_ns)
{
    if (wall_ns == 0)
        return nullptr;
    return static_cast<double>(units) * 1000000000.0 / static_cast<double>(wall_ns);
}

inline nlohmann::json scorecard_phase_entries(const analysis_metrics_snapshot_t& snapshot)
{
    nlohmann::json phases = nlohmann::json::array();
    for (std::size_t index = 0; index < baseline_phase_count; ++index) {
        const auto phase = static_cast<baseline_phase_t>(index);
        const auto& metric = snapshot.phases[index];
        phases.push_back(nlohmann::json{
            {"name", analysis_metrics_t::phase_name(phase)},
            {"invocations", metric.invocations},
            {"wall_ns", metric.wall_ns},
            {"cpu_ns", metric.cpu_ns},
            {"bytes_in", metric.bytes_in},
            {"bytes_out", metric.bytes_out},
            {"work_items", metric.work_items},
            {"cancellation_checks", metric.cancellation_checks},
            {"failures", metric.failures},
            {"queue_depth_peak", metric.queue_depth_peak},
            {"active_workers_peak", metric.active_workers_peak},
            {"throughput_bytes_per_s", nullable_rate(metric.bytes_out, metric.wall_ns)}});
    }
    return phases;
}

inline std::uint64_t scorecard_phase_wall_ns(const nlohmann::json& phases, const char* name)
{
    if (!phases.is_array())
        return 0;
    for (const auto& phase : phases) {
        if (phase.is_object() && phase.value("name", std::string()) == name)
            return phase.value("wall_ns", 0ULL);
    }
    return 0;
}

inline bool scorecard_phase_present(const nlohmann::json& phases, const char* name)
{
    if (!phases.is_array())
        return false;
    for (const auto& phase : phases) {
        if (phase.is_object() && phase.value("name", std::string()) == name)
            return true;
    }
    return false;
}

inline nlohmann::json sla_verdict_actual(const nlohmann::json& report, const std::string& key)
{
    const nlohmann::json* container = nullptr;
    if (report.contains("sla") && report["sla"].is_object())
        container = &report["sla"];
    else if (report.contains("program_sla") && report["program_sla"].is_object())
        container = &report["program_sla"];
    if (!container || !container->contains("verdicts") || !(*container)["verdicts"].is_array())
        return nullptr;
    for (const auto& verdict : (*container)["verdicts"]) {
        if (verdict.is_object() && verdict.value("key", std::string()) == key &&
            verdict.contains("actual"))
            return verdict["actual"];
    }
    return nullptr;
}

inline nlohmann::json compare_scorecards(const nlohmann::json& baseline,
                                         const nlohmann::json& candidate)
{
    using nlohmann::json;
    const json* thresholds = nullptr;
    if (candidate.contains("sla") && candidate["sla"].is_object() &&
        candidate["sla"].contains("thresholds") && candidate["sla"]["thresholds"].is_object())
        thresholds = &candidate["sla"]["thresholds"];
    else if (candidate.contains("program_sla") && candidate["program_sla"].is_object() &&
        candidate["program_sla"].contains("thresholds") &&
        candidate["program_sla"]["thresholds"].is_object())
        thresholds = &candidate["program_sla"]["thresholds"];
    else if (baseline.contains("sla") && baseline["sla"].is_object() &&
        baseline["sla"].contains("thresholds") && baseline["sla"]["thresholds"].is_object())
        thresholds = &baseline["sla"]["thresholds"];
    else if (baseline.contains("program_sla") && baseline["program_sla"].is_object() &&
        baseline["program_sla"].contains("thresholds") &&
        baseline["program_sla"]["thresholds"].is_object())
        thresholds = &baseline["program_sla"]["thresholds"];

    json verdicts = json::array();
    json warnings = json::array();
    bool any_fail = false;
    if (thresholds) {
        for (const auto& item : thresholds->items()) {
            const auto& key = item.key();
            if (key == "threshold_schema" || key == "threshold_schema_version")
                continue;
            const json candidate_actual = sla_verdict_actual(candidate, key);
            const json baseline_actual = sla_verdict_actual(baseline, key);
            if (baseline_actual.is_null() || candidate_actual.is_null()) {
                verdicts.push_back(json{{"key", key}, {"target", item.value()},
                    {"baseline", baseline_actual}, {"candidate", candidate_actual},
                    {"delta_pct", nullptr}, {"verdict", "NOT_COMPARABLE"}});
                continue;
            }
            if (item.value().is_boolean()) {
                const bool worse = baseline_actual.is_boolean() && baseline_actual.get<bool>() &&
                    candidate_actual.is_boolean() && !candidate_actual.get<bool>();
                if (worse)
                    any_fail = true;
                verdicts.push_back(json{{"key", key}, {"target", item.value()},
                    {"baseline", baseline_actual}, {"candidate", candidate_actual},
                    {"delta_pct", nullptr}, {"verdict", worse ? "FAIL" : "PASS"}});
                continue;
            }
            if (!baseline_actual.is_number() || !candidate_actual.is_number()) {
                verdicts.push_back(json{{"key", key}, {"target", item.value()},
                    {"baseline", baseline_actual}, {"candidate", candidate_actual},
                    {"delta_pct", nullptr}, {"verdict", "NOT_COMPARABLE"}});
                continue;
            }
            const double baseline_value = baseline_actual.get<double>();
            const double candidate_value = candidate_actual.get<double>();
            if (baseline_value == 0.0) {
                verdicts.push_back(json{{"key", key}, {"target", item.value()},
                    {"baseline", baseline_actual}, {"candidate", candidate_actual},
                    {"delta_pct", nullptr}, {"verdict", "NOT_COMPARABLE"}});
                continue;
            }
            const double delta_pct =
                (candidate_value - baseline_value) / baseline_value * 100.0;
            const bool lower_is_better = key.find("_max") != std::string::npos;
            const bool worse = lower_is_better ? delta_pct > 5.0 : delta_pct < -5.0;
            if (worse)
                any_fail = true;
            verdicts.push_back(json{{"key", key}, {"target", item.value()},
                {"baseline", baseline_actual}, {"candidate", candidate_actual},
                {"delta_pct", delta_pct}, {"verdict", worse ? "FAIL" : "PASS"}});
        }
    }

    static const char* const informational_keys[] = {
        "file_bytes_per_s", "decode_bytes_per_s", "instructions_per_s",
        "functions_per_s", "index_bytes_per_s", "persist_bytes_per_s",
        "decompile_all_funcs_per_s", "decompile_all_funcs_wall_per_s"};
    json informational = json::array();
    for (const char* key : informational_keys) {
        const json baseline_value = baseline.contains("throughput")
            ? baseline["throughput"].value(key, json(nullptr)) : json(nullptr);
        const json candidate_value = candidate.contains("throughput")
            ? candidate["throughput"].value(key, json(nullptr)) : json(nullptr);
        if (!baseline_value.is_number() || !candidate_value.is_number()) {
            informational.push_back(json{{"key", key}, {"baseline", baseline_value},
                {"candidate", candidate_value}, {"delta_pct", nullptr},
                {"verdict", "NOT_COMPARABLE"}});
            continue;
        }
        const double before = baseline_value.get<double>();
        const double after = candidate_value.get<double>();
        if (before == 0.0) {
            informational.push_back(json{{"key", key}, {"baseline", baseline_value},
                {"candidate", candidate_value}, {"delta_pct", nullptr},
                {"verdict", "NOT_COMPARABLE"}});
            continue;
        }
        const double delta_pct = (after - before) / before * 100.0;
        const bool warn = delta_pct < -10.0;
        if (warn)
            warnings.push_back(std::string(key) + " regressed " +
                std::to_string(delta_pct) + "%");
        informational.push_back(json{{"key", key}, {"baseline", baseline_value},
            {"candidate", candidate_value}, {"delta_pct", delta_pct},
            {"verdict", warn ? "WARN" : "PASS"}});
    }

    return json{
        {"schema", compare_verdict_schema_v1},
        {"schema_version", compare_verdict_schema_v1_version},
        {"structural", false},
        {"thresholds_available", thresholds != nullptr},
        {"verdicts", std::move(verdicts)},
        {"informational", std::move(informational)},
        {"warnings", std::move(warnings)},
        {"overall", any_fail ? "FAIL" : "PASS"}};
}

inline const nlohmann::json& phase_budget_thresholds()
{
    static const nlohmann::json thresholds = {
        {"threshold_schema", "aida.hyperperf.phase-budget-thresholds"},
        {"threshold_schema_version", 1},
        {"decode_ms_max_300mb", 40000.0},
        {"merge_ms_max", 5000.0},
        {"funcrec_ms_max", 20000.0},
        {"functions_ms_max", 10000.0},
        {"metadata_ms_max", 5000.0},
        {"search_ms_max", 5000.0},
        {"index_instructions_ms_max", 10000.0},
        {"commit_lag_ms_max", 30000.0},
        {"analysis_wall_ms_target", 120000.0}};
    return thresholds;
}

inline nlohmann::json evaluate_phase_budgets(const nlohmann::json& phases,
                                             double total_wall_ms,
                                             double wall_scale)
{
    using nlohmann::json;
    const auto& thresholds = phase_budget_thresholds();
    struct gate_binding_t {
        const char* key;
        const char* phase;
        const char* note;
        bool informational;
    };
    static const gate_binding_t bindings[] = {
        {"decode_ms_max_300mb", "decode", nullptr, false},
        {"merge_ms_max", "decode_merge", nullptr, false},
        {"funcrec_ms_max", "blocks",
            "function_recovery is accounted inside the blocks phase in scorecard schema v2", false},
        {"functions_ms_max", "functions", nullptr, false},
        {"metadata_ms_max", "metadata_symbols_types", nullptr, false},
        {"search_ms_max", "search_index", nullptr, false},
        {"index_instructions_ms_max", "search_index",
            "instruction-class index staging lands with the pipeline workstreams; evaluated on the combined search_index wall", false},
        {"commit_lag_ms_max", "persistence",
            "commit remains on the readiness path; evaluated on the persistence phase wall", false},
        {"analysis_wall_ms_target", nullptr,
            "informational target for the full analysis wall", true}};
    json verdicts = json::array();
    bool any_fail = false;
    bool all_pass_or_warn = true;
    const double scale = wall_scale > 0.0 ? wall_scale : 1.0;
    for (const auto& binding : bindings) {
        const double target = thresholds[binding.key].get<double>() * scale;
        json actual = nullptr;
        if (binding.phase == nullptr) {
            actual = total_wall_ms;
        } else if (scorecard_phase_present(phases, binding.phase)) {
            actual = static_cast<double>(
                scorecard_phase_wall_ns(phases, binding.phase)) / 1000000.0;
        }
        json entry{{"key", binding.key}, {"target_ms", target}, {"actual_ms", actual}};
        if (binding.phase != nullptr)
            entry["phase"] = binding.phase;
        if (binding.note != nullptr)
            entry["note"] = binding.note;
        if (binding.informational)
            entry["informational"] = true;
        if (actual.is_null()) {
            entry["verdict"] = "NOT_MEASURED";
            all_pass_or_warn = false;
        } else if (actual.get<double>() <= target) {
            entry["verdict"] = "PASS";
        } else if (binding.informational) {
            entry["verdict"] = "WARN";
        } else {
            entry["verdict"] = "FAIL";
            any_fail = true;
            all_pass_or_warn = false;
        }
        verdicts.push_back(std::move(entry));
    }
    return json{{"schema", phase_budget_gate_schema_v1},
        {"schema_version", 1},
        {"informational_only", true},
        {"targets_scaled_by", scale},
        {"thresholds", thresholds},
        {"verdicts", std::move(verdicts)},
        {"overall", any_fail ? "FAIL" : (all_pass_or_warn ? "PASS" : "NOT_MEASURED")}};
}

inline nlohmann::json compare_structural_baseline(const nlohmann::json& baseline,
                                                  const nlohmann::json& candidate)
{
    using nlohmann::json;
    json verdicts = json::array();
    bool any_fail = false;
    const auto entry = [&](const char* key, const json& baseline_value,
                           const json& candidate_value, const char* verdict) {
        if (std::string(verdict) == "FAIL")
            any_fail = true;
        verdicts.push_back(json{{"key", key}, {"baseline", baseline_value},
            {"candidate", candidate_value}, {"verdict", verdict}});
    };
    entry("schema", baseline.value("schema", std::string()),
        structural_baseline_schema_v1,
        baseline.value("schema", std::string()) == structural_baseline_schema_v1 &&
            baseline.value("schema_version", 0U) == structural_baseline_schema_v1_version &&
            candidate.value("schema", std::string()) == structural_baseline_schema_v1
            ? "PASS" : "FAIL");
    entry("fixture.code_mb", baseline.value("code_mb", 0U),
        candidate.value("code_mb", 0U),
        baseline.value("code_mb", 0U) == candidate.value("code_mb", 0U) ? "PASS" : "FAIL");
    entry("fixture.seed_hex", baseline.value("seed_hex", std::string()),
        candidate.value("seed_hex", std::string()),
        baseline.value("seed_hex", std::string()) == candidate.value("seed_hex", std::string())
            ? "PASS" : "FAIL");

    const json baseline_contract = baseline.contains("contract") &&
            baseline["contract"].is_object()
        ? baseline["contract"] : json::object();
    const json candidate_capture = candidate.contains("capture") &&
            candidate["capture"].is_object()
        ? candidate["capture"] : json::object();
    const json phases_present = candidate_capture.contains("phases_present") &&
            candidate_capture["phases_present"].is_array()
        ? candidate_capture["phases_present"] : json::array();
    json missing_phases = json::array();
    if (baseline_contract.contains("phases") && baseline_contract["phases"].is_array()) {
        for (const auto& required : baseline_contract["phases"]) {
            const auto name = required.get<std::string>();
            bool found = false;
            for (const auto& present : phases_present) {
                if (present.is_string() && present.get<std::string>() == name) {
                    found = true;
                    break;
                }
            }
            if (!found)
                missing_phases.push_back(name);
        }
    }
    const auto required_phase_count = baseline_contract.value("phases", json::array()).size();
    entry("contract.phase_coverage", required_phase_count,
        required_phase_count - missing_phases.size(),
        missing_phases.empty() ? "PASS" : "FAIL");
    if (!missing_phases.empty())
        verdicts.back()["missing"] = std::move(missing_phases);

    const json blocks = candidate_capture.contains("scorecard_blocks") &&
            candidate_capture["scorecard_blocks"].is_object()
        ? candidate_capture["scorecard_blocks"] : json::object();
    json missing_blocks = json::array();
    if (baseline_contract.contains("required_scorecard_blocks") &&
        baseline_contract["required_scorecard_blocks"].is_array()) {
        for (const auto& required : baseline_contract["required_scorecard_blocks"]) {
            const auto name = required.get<std::string>();
            if (!blocks.contains(name) || !blocks[name].is_boolean() ||
                !blocks[name].get<bool>())
                missing_blocks.push_back(name);
        }
    }
    const auto required_block_count =
        baseline_contract.value("required_scorecard_blocks", json::array()).size();
    entry("contract.scorecard_blocks", required_block_count,
        required_block_count - missing_blocks.size(),
        missing_blocks.empty() ? "PASS" : "FAIL");
    if (!missing_blocks.empty())
        verdicts.back()["missing"] = std::move(missing_blocks);

    const std::uint32_t version_min = baseline_contract.value("scorecard_schema_version_min", 0U);
    const std::uint32_t candidate_version =
        candidate_capture.value("scorecard_schema_version", 0U);
    entry("contract.scorecard_schema_version", version_min, candidate_version,
        candidate_version >= version_min && version_min != 0 ? "PASS" : "FAIL");

    const json write_amplification = candidate_capture.contains("write_amplification")
        ? candidate_capture["write_amplification"] : json(nullptr);
    if (baseline_contract.contains("write_amplification_band") &&
        baseline_contract["write_amplification_band"].is_array() &&
        baseline_contract["write_amplification_band"].size() == 2 &&
        write_amplification.is_number()) {
        const double low = baseline_contract["write_amplification_band"][0].get<double>();
        const double high = baseline_contract["write_amplification_band"][1].get<double>();
        const double value = write_amplification.get<double>();
        entry("contract.write_amplification", json::array({low, high}), value,
            value >= low && value <= high ? "PASS" : "FAIL");
    } else {
        entry("contract.write_amplification",
            baseline_contract.value("write_amplification_band", json(nullptr)),
            write_amplification, "NOT_COMPARABLE");
    }

    const json baseline_capture = baseline.contains("capture") &&
            baseline["capture"].is_object()
        ? baseline["capture"] : json::object();
    const bool baseline_captured =
        baseline_capture.value("status", std::string()) == "captured";
    if (!baseline_captured) {
        entry("capture.snapshot_sha256", baseline_capture.value("snapshot_sha256", json(nullptr)),
            candidate_capture.value("snapshot_sha256", json(nullptr)), "PENDING_BOOTSTRAP");
        entry("capture.counts", baseline_capture.value("counts", json(nullptr)),
            candidate_capture.value("counts", json(nullptr)), "PENDING_BOOTSTRAP");
    } else {
        entry("capture.snapshot_sha256",
            baseline_capture.value("snapshot_sha256", std::string()),
            candidate_capture.value("snapshot_sha256", std::string()),
            baseline_capture.value("snapshot_sha256", std::string()) ==
                    candidate_capture.value("snapshot_sha256", std::string())
                ? "PASS" : "FAIL");
        const json baseline_counts = baseline_capture.contains("counts") &&
                baseline_capture["counts"].is_object()
            ? baseline_capture["counts"] : json::object();
        const json candidate_counts = candidate_capture.contains("counts") &&
                candidate_capture["counts"].is_object()
            ? candidate_capture["counts"] : json::object();
        for (const auto& item : baseline_counts.items()) {
            const json candidate_value = candidate_counts.contains(item.key())
                ? candidate_counts[item.key()] : json(nullptr);
            entry((std::string("capture.counts.") + item.key()).c_str(), item.value(),
                candidate_value,
                candidate_value.is_number() && item.value().is_number() &&
                        candidate_value.get<std::uint64_t>() == item.value().get<std::uint64_t>()
                    ? "PASS" : "FAIL");
        }
    }

    return json{{"schema", compare_verdict_schema_v1},
        {"schema_version", compare_verdict_schema_v1_version},
        {"structural", true},
        {"baseline_capture_status",
            baseline_captured ? "captured" : baseline_capture.value("status", std::string("pending"))},
        {"verdicts", std::move(verdicts)},
        {"overall", any_fail ? "FAIL" : "PASS"}};
}

inline bool structural_compare_update_allowed(const nlohmann::json& verdict_report)
{
    if (!verdict_report.is_object() || !verdict_report.contains("verdicts") ||
        !verdict_report["verdicts"].is_array())
        return false;
    for (const auto& verdict : verdict_report["verdicts"]) {
        if (!verdict.is_object())
            continue;
        const auto key = verdict.value("key", std::string());
        const auto state = verdict.value("verdict", std::string());
        if (state != "FAIL")
            continue;
        if (key.rfind("capture.", 0) == 0)
            continue;
        return false;
    }
    return true;
}

}
