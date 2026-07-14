#include "surface_reconciliation.hpp"

#include <algorithm>
#include <initializer_list>
#include <limits>
#include <tuple>
#include <utility>

namespace aida::analysis::c03 {

namespace {

constexpr std::size_t k_default_maximum_entries = 100000;
constexpr std::size_t k_default_maximum_findings = 10000;
constexpr std::uint64_t k_default_maximum_severity = 1000;
constexpr std::size_t k_default_maximum_identifier_bytes = 512;
constexpr std::size_t k_default_maximum_text_bytes = 4096;

struct stable_code_entry_t {
    surface_error_code_t code;
    std::string_view name;
};

constexpr stable_code_entry_t k_stable_codes[] = {
    {surface_error_code_t::none,                                      "none"},
    {surface_error_code_t::dead_replaced_path_detected,               "dead_replaced_path_detected"},
    {surface_error_code_t::duplicate_store_detected,                  "duplicate_store_detected"},
    {surface_error_code_t::stale_registration_detected,               "stale_registration_detected"},
    {surface_error_code_t::old_schema_v8_writer_detected,             "old_schema_v8_writer_detected"},
    {surface_error_code_t::legacy_invalid_ast_flow_detected,          "legacy_invalid_ast_flow_detected"},
    {surface_error_code_t::unsupported_alias_detected,                "unsupported_alias_detected"},
    {surface_error_code_t::security_regression_detected,              "security_regression_detected"},
    {surface_error_code_t::unexplained_removal_detected,              "unexplained_removal_detected"},
    {surface_error_code_t::baseline_mismatch,                         "baseline_mismatch"},
    {surface_error_code_t::internal_error,                            "internal_error"},
    {surface_error_code_t::invalid_limit_contract,                    "invalid_limit_contract"},
    {surface_error_code_t::baseline_entry_cap_exceeded,               "baseline_entry_cap_exceeded"},
    {surface_error_code_t::actual_entry_cap_exceeded,                 "actual_entry_cap_exceeded"},
    {surface_error_code_t::finding_cap_exceeded,                      "finding_cap_exceeded"},
    {surface_error_code_t::duplicate_baseline_identifier_detected,    "duplicate_baseline_identifier_detected"},
    {surface_error_code_t::duplicate_actual_identifier_detected,      "duplicate_actual_identifier_detected"},
    {surface_error_code_t::invalid_surface_entry,                     "invalid_surface_entry"},
    {surface_error_code_t::invalid_surface_marker,                    "invalid_surface_marker"},
    {surface_error_code_t::auxiliary_marker_cap_exceeded,             "auxiliary_marker_cap_exceeded"},
};

struct entry_kind_name_t {
    surface_entry_kind_t kind;
    std::string_view name;
};

constexpr entry_kind_name_t k_kind_names[] = {
    {surface_entry_kind_t::source_file,            "source_file"},
    {surface_entry_kind_t::contract_registration,  "contract_registration"},
    {surface_entry_kind_t::handler_registration,   "handler_registration"},
    {surface_entry_kind_t::tool_registration,      "tool_registration"},
    {surface_entry_kind_t::schema_writer,          "schema_writer"},
    {surface_entry_kind_t::ast_path,               "ast_path"},
    {surface_entry_kind_t::alias_mapping,          "alias_mapping"},
    {surface_entry_kind_t::security_guard,         "security_guard"},
    {surface_entry_kind_t::store_definition,       "store_definition"},
    {surface_entry_kind_t::test_harness,           "test_harness"},
};

bool saturating_add(
    std::uint64_t& value, std::uint64_t increment,
    std::uint64_t maximum) noexcept {
    if (value > maximum) {
        value = maximum;
        return true;
    }
    if (increment >= maximum - value) {
        value = maximum;
        return true;
    }
    value += increment;
    return false;
}

bool saturating_atomic_add(
    std::atomic_uint64_t& value, std::uint64_t increment,
    std::uint64_t maximum) noexcept {
    auto current = value.load(std::memory_order_acquire);
    for (;;) {
        const bool saturated =
            current >= maximum ||
            increment >= maximum - std::min(current, maximum);
        const auto desired = saturated ? maximum : current + increment;
        if (value.compare_exchange_weak(
                current, desired, std::memory_order_acq_rel,
                std::memory_order_acquire)) {
            return saturated;
        }
    }
}

void append_bounded(
    std::string& destination, std::string_view value,
    std::size_t maximum_bytes) {
    if (destination.size() >= maximum_bytes || value.empty())
        return;
    const auto available = maximum_bytes - destination.size();
    destination.append(value.data(), std::min(available, value.size()));
}

std::string bounded_concat(
    std::size_t maximum_bytes,
    std::initializer_list<std::string_view> components) {
    std::string value;
    value.reserve(std::min<std::size_t>(maximum_bytes, 256));
    for (const auto component : components)
        append_bounded(value, component, maximum_bytes);
    return value;
}

std::string bounded_evidence(std::string_view value, std::size_t maximum_bytes) {
    std::string evidence;
    evidence.reserve(std::min(value.size(), maximum_bytes));
    for (std::size_t index = 0;
         index < value.size() && evidence.size() < maximum_bytes; ++index) {
        const auto byte = static_cast<unsigned char>(value[index]);
        if (byte == 0 || byte < 0x20 || byte == 0x7f)
            evidence.push_back('?');
        else
            evidence.push_back(static_cast<char>(byte));
    }
    return evidence;
}

bool valid_kind(surface_entry_kind_t kind) noexcept {
    return static_cast<std::uint8_t>(kind) <=
           static_cast<std::uint8_t>(surface_entry_kind_t::test_harness);
}

bool unknown_schema_identity(std::string_view value) noexcept {
    constexpr std::string_view sentinels[] = {
        "unknown", "unspecified", "none", "n/a", "?"
    };
    for (const auto sentinel : sentinels) {
        if (value.size() != sentinel.size())
            continue;
        bool equal = true;
        for (std::size_t index = 0; index < value.size(); ++index) {
            auto byte = static_cast<unsigned char>(value[index]);
            if (byte >= 'A' && byte <= 'Z')
                byte = static_cast<unsigned char>(byte - 'A' + 'a');
            if (byte != static_cast<unsigned char>(sentinel[index])) {
                equal = false;
                break;
            }
        }
        if (equal)
            return true;
    }
    return false;
}

std::vector<const surface_entry_t*> sorted_entries(
    const std::vector<surface_entry_t>& entries) {
    std::vector<const surface_entry_t*> ordered;
    ordered.reserve(entries.size());
    for (const auto& entry : entries)
        ordered.push_back(&entry);
    std::sort(ordered.begin(), ordered.end(), [](const auto* left, const auto* right) {
        return std::tie(
                   left->identifier, left->kind, left->canonical_path,
                   left->schema_version, left->is_active, left->is_replaced,
                   left->replaced_by, left->security_note) <
               std::tie(
                   right->identifier, right->kind, right->canonical_path,
                   right->schema_version, right->is_active, right->is_replaced,
                   right->replaced_by, right->security_note);
    });
    return ordered;
}

template <typename Map>
std::vector<const typename Map::value_type*> sorted_map_entries(const Map& values) {
    std::vector<const typename Map::value_type*> ordered;
    ordered.reserve(values.size());
    for (const auto& value : values)
        ordered.push_back(&value);
    std::sort(ordered.begin(), ordered.end(), [](const auto* left, const auto* right) {
        return std::tie(left->first, left->second) <
               std::tie(right->first, right->second);
    });
    return ordered;
}

template <typename Set>
std::vector<const typename Set::value_type*> sorted_set_entries(const Set& values) {
    std::vector<const typename Set::value_type*> ordered;
    ordered.reserve(values.size());
    for (const auto& value : values)
        ordered.push_back(&value);
    std::sort(ordered.begin(), ordered.end(), [](const auto* left, const auto* right) {
        return *left < *right;
    });
    return ordered;
}

bool has_finding(
    const surface_reconciliation_result_t& result,
    surface_error_code_t code, std::string_view identifier) {
    return std::any_of(
        result.findings.begin(), result.findings.end(),
        [code, identifier](const auto& finding) {
            return finding.code == code && finding.identifier == identifier;
        });
}

bool mandatory_finding(const surface_finding_t& finding) noexcept {
    return finding.code == surface_error_code_t::finding_cap_exceeded ||
           (finding.code == surface_error_code_t::internal_error &&
            finding.identifier == "metrics_saturated");
}

std::uint8_t retention_class(const surface_finding_t& finding) noexcept {
    if (mandatory_finding(finding))
        return 3;
    if (finding.code == surface_error_code_t::security_regression_detected)
        return 2;
    return 1;
}

bool deterministic_evidence_before(
    const surface_finding_t& left, const surface_finding_t& right) noexcept {
    return std::tie(
               left.code, left.identifier, left.canonical_path, left.detail,
               left.kind, left.severity) <
           std::tie(
               right.code, right.identifier, right.canonical_path, right.detail,
               right.kind, right.severity);
}

bool stronger_retention(
    const surface_finding_t& left, const surface_finding_t& right) noexcept {
    const auto left_class = retention_class(left);
    const auto right_class = retention_class(right);
    if (left_class != right_class)
        return left_class > right_class;
    if (left.severity != right.severity)
        return left.severity > right.severity;
    const bool left_has_path = !left.canonical_path.empty();
    const bool right_has_path = !right.canonical_path.empty();
    if (left_has_path != right_has_path)
        return left_has_path;
    if (left.detail.size() != right.detail.size())
        return left.detail.size() > right.detail.size();
    return deterministic_evidence_before(left, right);
}

}

struct surface_reconciliation_t::marker_target_proof_t final {
    struct source_evidence_t final {
        surface_entry_kind_t kind = surface_entry_kind_t::source_file;
        std::string canonical_path;
        std::string schema_version;
    };

    std::unordered_map<std::string, source_evidence_t> valid_dead_replacements;
    std::unordered_map<std::string, source_evidence_t> valid_alias_replacements;
    std::unordered_map<std::string, source_evidence_t> valid_stale_registrations;
    std::unordered_map<std::string, source_evidence_t> valid_schema_migrations;
    std::unordered_map<std::string, source_evidence_t> valid_inactive_actual;
    std::unordered_map<std::string, source_evidence_t> unique_active_actual;
};

std::string_view surface_reconciliation_t::stable_code_for(
    surface_error_code_t code) noexcept {
    for (const auto& entry : k_stable_codes) {
        if (entry.code == code)
            return entry.name;
    }
    return "unknown";
}

std::string_view surface_reconciliation_t::entry_kind_name(
    surface_entry_kind_t kind) noexcept {
    for (const auto& entry : k_kind_names) {
        if (entry.kind == kind)
            return entry.name;
    }
    return "unknown";
}

surface_finding_t surface_reconciliation_t::make_finding(
    surface_error_code_t code, std::string_view identifier,
    std::string detail, std::string canonical_path,
    surface_entry_kind_t kind, std::uint64_t severity) const {
    surface_finding_t finding;
    finding.code = code;
    finding.stable_code = stable_code_for(code);
    finding.identifier = bounded_evidence(identifier, limits_.maximum_identifier_bytes);
    finding.detail = bounded_evidence(detail, limits_.maximum_text_bytes);
    finding.canonical_path = bounded_evidence(
        canonical_path, limits_.maximum_text_bytes);
    finding.kind = valid_kind(kind) ? kind : surface_entry_kind_t::source_file;
    finding.severity = std::min(severity, k_default_maximum_severity);
    return finding;
}

surface_reconciliation_t::surface_reconciliation_t(
    surface_reconciliation_limits_t limits)
    : limits_(limits) {
    if (limits_.maximum_entries == 0 ||
        limits_.maximum_entries > k_default_maximum_entries) {
        limits_.maximum_entries = k_default_maximum_entries;
        limit_contract_valid_ = false;
    }
    if (limits_.maximum_findings < 2 ||
        limits_.maximum_findings > k_default_maximum_findings) {
        limits_.maximum_findings = k_default_maximum_findings;
        limit_contract_valid_ = false;
    }
    if (limits_.maximum_severity == 0 ||
        limits_.maximum_severity > k_default_maximum_severity) {
        limits_.maximum_severity = k_default_maximum_severity;
        limit_contract_valid_ = false;
    }
    if (limits_.maximum_identifier_bytes == 0 ||
        limits_.maximum_identifier_bytes > k_default_maximum_identifier_bytes) {
        limits_.maximum_identifier_bytes = k_default_maximum_identifier_bytes;
        limit_contract_valid_ = false;
    }
    if (limits_.maximum_text_bytes == 0 ||
        limits_.maximum_text_bytes > k_default_maximum_text_bytes) {
        limits_.maximum_text_bytes = k_default_maximum_text_bytes;
        limit_contract_valid_ = false;
    }
    if (limits_.maximum_identifier_bytes > limits_.maximum_text_bytes) {
        limits_.maximum_identifier_bytes = k_default_maximum_identifier_bytes;
        limits_.maximum_text_bytes = k_default_maximum_text_bytes;
        limit_contract_valid_ = false;
    }
    if (limits_.maximum_metric_value == 0) {
        limits_.maximum_metric_value =
            std::numeric_limits<std::uint64_t>::max();
        limit_contract_valid_ = false;
    }
}

bool surface_reconciliation_t::valid_identifier(std::string_view value) const noexcept {
    if (value.empty() || value.size() > limits_.maximum_identifier_bytes)
        return false;
    for (const char character : value) {
        const auto byte = static_cast<unsigned char>(character);
        if (byte < 0x21 || byte > 0x7e)
            return false;
    }
    return true;
}

bool surface_reconciliation_t::valid_text(
    std::string_view value, bool allow_empty) const noexcept {
    if ((!allow_empty && value.empty()) || value.size() > limits_.maximum_text_bytes)
        return false;
    for (const char character : value) {
        const auto byte = static_cast<unsigned char>(character);
        if (byte == 0 || byte < 0x20 || byte == 0x7f)
            return false;
    }
    return true;
}

bool surface_reconciliation_t::valid_path(std::string_view value) const noexcept {
    if (!valid_text(value, false) || value.front() == '/' ||
        value.back() == '/' || value.find('\\') != std::string_view::npos ||
        value.find(':') != std::string_view::npos) {
        return false;
    }
    std::size_t start = 0;
    while (start < value.size()) {
        const auto end = value.find('/', start);
        const auto length = (end == std::string_view::npos ? value.size() : end) - start;
        const auto segment = value.substr(start, length);
        if (segment.empty() || segment == "." || segment == "..")
            return false;
        if (end == std::string_view::npos)
            break;
        start = end + 1;
    }
    return true;
}

bool surface_reconciliation_t::valid_entry(
    const surface_entry_t& entry, std::string_view& reason) const noexcept {
    if (!valid_identifier(entry.identifier)) {
        reason = "invalid_identifier";
        return false;
    }
    if (!valid_path(entry.canonical_path)) {
        reason = "invalid_canonical_path";
        return false;
    }
    if (!valid_kind(entry.kind)) {
        reason = "invalid_entry_kind";
        return false;
    }
    if (entry.is_replaced) {
        if (entry.is_active) {
            reason = "active_replaced_entry";
            return false;
        }
        if (!valid_identifier(entry.replaced_by)) {
            reason = "invalid_replacement_identifier";
            return false;
        }
        if (entry.replaced_by == entry.identifier) {
            reason = "self_replacement";
            return false;
        }
    } else if (!entry.replaced_by.empty()) {
        reason = "replacement_without_replaced_state";
        return false;
    }
    if (entry.kind == surface_entry_kind_t::schema_writer) {
        if (!valid_identifier(entry.schema_version) ||
            unknown_schema_identity(entry.schema_version)) {
            reason = entry.schema_version.empty()
                ? (entry.is_active
                       ? "active_schema_writer_without_valid_version"
                       : "inactive_schema_writer_without_valid_version")
                : (unknown_schema_identity(entry.schema_version)
                       ? "unknown_schema_version"
                       : "invalid_schema_version");
            return false;
        }
    } else if (!entry.schema_version.empty()) {
        reason = "schema_version_on_non_writer";
        return false;
    }
    if (entry.kind == surface_entry_kind_t::security_guard) {
        if (!entry.security_note.empty() &&
            !valid_text(entry.security_note, false)) {
            reason = "invalid_security_note";
            return false;
        }
        if (!entry.is_active && entry.security_note.empty()) {
            reason = "inactive_security_guard_without_note";
            return false;
        }
    } else if (!entry.security_note.empty()) {
        reason = "security_note_on_non_guard";
        return false;
    }
    reason = {};
    return true;
}

void surface_reconciliation_t::record_invalid_entry(
    bool baseline, const surface_entry_t& entry, std::string_view reason) {
    auto& rejected = baseline ? rejected_baseline_entries_ : rejected_actual_entries_;
    const bool rejected_saturated =
        saturating_add(rejected, 1, limits_.maximum_metric_value);
    const bool malformed_saturated =
        saturating_add(malformed_entries_, 1, limits_.maximum_metric_value);
    if (rejected_saturated || malformed_saturated)
        metrics_saturated_.store(true, std::memory_order_release);
    auto identifier = bounded_evidence(
        entry.identifier, limits_.maximum_identifier_bytes);
    if (identifier.empty())
        identifier = "<invalid>";
    if (first_invalid_entry_reason_.empty() ||
        std::tie(identifier, baseline, reason) <
            std::tie(first_invalid_entry_identifier_,
                     first_invalid_entry_is_baseline_,
                     first_invalid_entry_reason_)) {
        first_invalid_entry_identifier_ = std::move(identifier);
        first_invalid_entry_reason_ = reason;
        first_invalid_entry_is_baseline_ = baseline;
    }
}

void surface_reconciliation_t::record_invalid_marker(
    std::string_view collection, std::string_view identifier,
    std::string_view reason) {
    const bool rejected_saturated = saturating_add(
        rejected_auxiliary_markers_, 1, limits_.maximum_metric_value);
    const bool malformed_saturated = saturating_add(
        malformed_markers_, 1, limits_.maximum_metric_value);
    if (rejected_saturated || malformed_saturated) {
        metrics_saturated_.store(true, std::memory_order_release);
    }
    auto canonical_identifier = bounded_evidence(
        identifier, limits_.maximum_identifier_bytes);
    if (canonical_identifier.empty())
        canonical_identifier = "<invalid>";
    if (first_invalid_marker_reason_.empty() ||
        std::tie(canonical_identifier, collection, reason) <
            std::tie(first_invalid_marker_identifier_,
                     first_invalid_marker_collection_,
                     first_invalid_marker_reason_)) {
        first_invalid_marker_identifier_ = std::move(canonical_identifier);
        first_invalid_marker_collection_ = collection;
        first_invalid_marker_reason_ = reason;
    }
}

bool surface_reconciliation_t::reserve_auxiliary_marker(
    std::string_view collection, std::string_view identifier,
    bool security_priority) {
    if (auxiliary_marker_count_ < limits_.maximum_entries) {
        ++auxiliary_marker_count_;
        return true;
    }

    struct marker_rank_t final {
        std::string_view collection;
        std::string_view identifier;
        bool security = false;
    };
    const auto stronger = [](const marker_rank_t& left,
                             const marker_rank_t& right) noexcept {
        if (left.security != right.security)
            return left.security;
        return std::tie(left.collection, left.identifier) <
               std::tie(right.collection, right.identifier);
    };
    marker_rank_t weakest;
    bool has_weakest = false;
    const auto consider = [&weakest, &has_weakest, &stronger](
        std::string_view candidate_collection,
        const std::string& candidate_identifier,
        bool candidate_security) {
        const marker_rank_t candidate{
            candidate_collection, candidate_identifier, candidate_security};
        if (!has_weakest || stronger(weakest, candidate)) {
            weakest = candidate;
            has_weakest = true;
        }
    };
    for (const auto& marker : dead_replaced_paths_)
        consider("dead_replaced_paths", marker.first, false);
    for (const auto& marker : duplicate_stores_)
        consider("duplicate_stores", marker.first, false);
    for (const auto& marker : stale_registrations_)
        consider("stale_registrations", marker, false);
    for (const auto& marker : old_schema_v8_writers_)
        consider("old_schema_v8_writers", marker.first, false);
    for (const auto& marker : legacy_ast_flows_)
        consider("legacy_ast_flows", marker, false);
    for (const auto& marker : unsupported_aliases_)
        consider("unsupported_aliases", marker.first, false);
    for (const auto& marker : security_regressions_)
        consider("security_regressions", marker.first, true);

    auxiliary_cap_exceeded_ = true;
    auxiliary_capacity_incomplete_ = true;
    if (saturating_add(
            rejected_auxiliary_markers_, 1,
            limits_.maximum_metric_value)) {
        metrics_saturated_.store(true, std::memory_order_release);
    }
    const marker_rank_t incoming{
        collection, identifier, security_priority};
    if (!has_weakest || !stronger(incoming, weakest)) {
        if (first_auxiliary_overflow_collection_.empty() ||
            collection < first_auxiliary_overflow_collection_) {
            first_auxiliary_overflow_collection_ = collection;
        }
        return false;
    }

    if (first_auxiliary_overflow_collection_.empty() ||
        weakest.collection < first_auxiliary_overflow_collection_) {
        first_auxiliary_overflow_collection_ = weakest.collection;
    }
    const auto evicted_identifier = std::string(weakest.identifier);
    if (weakest.collection == "dead_replaced_paths")
        dead_replaced_paths_.erase(evicted_identifier);
    else if (weakest.collection == "duplicate_stores")
        duplicate_stores_.erase(evicted_identifier);
    else if (weakest.collection == "stale_registrations")
        stale_registrations_.erase(evicted_identifier);
    else if (weakest.collection == "old_schema_v8_writers")
        old_schema_v8_writers_.erase(evicted_identifier);
    else if (weakest.collection == "legacy_ast_flows")
        legacy_ast_flows_.erase(evicted_identifier);
    else if (weakest.collection == "unsupported_aliases")
        unsupported_aliases_.erase(evicted_identifier);
    else
        security_regressions_.erase(evicted_identifier);
    return true;
}

void surface_reconciliation_t::register_baseline_entry(
    const surface_entry_t& entry) {
    if (saturating_add(
            attempted_baseline_entries_, 1, limits_.maximum_metric_value)) {
        metrics_saturated_.store(true, std::memory_order_release);
    }
    std::string_view reason;
    if (!valid_entry(entry, reason)) {
        record_invalid_entry(true, entry, reason);
        return;
    }
    if (baseline_.size() >= limits_.maximum_entries) {
        baseline_cap_exceeded_ = true;
        if (saturating_add(
                rejected_baseline_entries_, 1,
                limits_.maximum_metric_value)) {
            metrics_saturated_.store(true, std::memory_order_release);
        }
        return;
    }
    baseline_.push_back(entry);
}

void surface_reconciliation_t::register_actual_entry(
    const surface_entry_t& entry) {
    if (saturating_add(
            attempted_actual_entries_, 1, limits_.maximum_metric_value)) {
        metrics_saturated_.store(true, std::memory_order_release);
    }
    std::string_view reason;
    if (!valid_entry(entry, reason)) {
        record_invalid_entry(false, entry, reason);
        return;
    }
    if (actual_.size() >= limits_.maximum_entries) {
        actual_cap_exceeded_ = true;
        if (saturating_add(
                rejected_actual_entries_, 1,
                limits_.maximum_metric_value)) {
            metrics_saturated_.store(true, std::memory_order_release);
        }
        return;
    }
    actual_.push_back(entry);
}

void surface_reconciliation_t::mark_dead_replaced_path(
    std::string_view identifier, std::string_view replaced_by) {
    if (saturating_add(
            attempted_auxiliary_markers_, 1,
            limits_.maximum_metric_value)) {
        metrics_saturated_.store(true, std::memory_order_release);
    }
    if (!valid_identifier(identifier) || !valid_identifier(replaced_by)) {
        record_invalid_marker(
            "dead_replaced_paths", identifier, "invalid_replacement_marker");
        return;
    }
    if (identifier == replaced_by) {
        record_invalid_marker(
            "dead_replaced_paths", identifier, "self_replacement");
        return;
    }
    const auto found = dead_replaced_paths_.find(std::string(identifier));
    if (found != dead_replaced_paths_.end()) {
        if (found->second.first != replaced_by) {
            if (!found->second.second) {
                record_invalid_marker(
                    "dead_replaced_paths", identifier,
                    "conflicting_duplicate_marker");
                found->second.second = true;
            }
            if (replaced_by < found->second.first)
                found->second.first = std::string(replaced_by);
        }
        return;
    }
    if (!reserve_auxiliary_marker(
            "dead_replaced_paths", identifier, false))
        return;
    dead_replaced_paths_.emplace(
        std::string(identifier),
        std::make_pair(std::string(replaced_by), false));
}

void surface_reconciliation_t::mark_duplicate_store(
    std::string_view identifier, std::string_view other_path) {
    if (saturating_add(
            attempted_auxiliary_markers_, 1,
            limits_.maximum_metric_value)) {
        metrics_saturated_.store(true, std::memory_order_release);
    }
    if (!valid_identifier(identifier) || !valid_path(other_path)) {
        record_invalid_marker(
            "duplicate_stores", identifier, "invalid_duplicate_store_marker");
        return;
    }
    const auto found = duplicate_stores_.find(std::string(identifier));
    if (found != duplicate_stores_.end()) {
        if (found->second.first != other_path) {
            if (!found->second.second) {
                record_invalid_marker(
                    "duplicate_stores", identifier,
                    "conflicting_duplicate_marker");
                found->second.second = true;
            }
            if (other_path < found->second.first)
                found->second.first = std::string(other_path);
        }
        return;
    }
    if (!reserve_auxiliary_marker(
            "duplicate_stores", identifier, false))
        return;
    duplicate_stores_.emplace(
        std::string(identifier), std::make_pair(std::string(other_path), false));
}

void surface_reconciliation_t::mark_stale_registration(
    std::string_view identifier) {
    if (saturating_add(
            attempted_auxiliary_markers_, 1,
            limits_.maximum_metric_value)) {
        metrics_saturated_.store(true, std::memory_order_release);
    }
    if (!valid_identifier(identifier)) {
        record_invalid_marker(
            "stale_registrations", identifier, "invalid_identifier");
        return;
    }
    if (stale_registrations_.find(std::string(identifier)) !=
        stale_registrations_.end()) {
        return;
    }
    if (!reserve_auxiliary_marker(
            "stale_registrations", identifier, false))
        return;
    stale_registrations_.emplace(std::string(identifier));
}

void surface_reconciliation_t::mark_old_schema_v8_writer(
    std::string_view identifier, std::string_view canonical_path) {
    if (saturating_add(
            attempted_auxiliary_markers_, 1,
            limits_.maximum_metric_value)) {
        metrics_saturated_.store(true, std::memory_order_release);
    }
    if (!valid_identifier(identifier) || !valid_path(canonical_path)) {
        record_invalid_marker(
            "old_schema_v8_writers", identifier, "invalid_schema_marker");
        return;
    }
    const auto found = old_schema_v8_writers_.find(std::string(identifier));
    if (found != old_schema_v8_writers_.end()) {
        if (found->second.first != canonical_path) {
            if (!found->second.second) {
                record_invalid_marker(
                    "old_schema_v8_writers", identifier,
                    "conflicting_duplicate_marker");
                found->second.second = true;
            }
            if (canonical_path < found->second.first)
                found->second.first = std::string(canonical_path);
        }
        return;
    }
    if (!reserve_auxiliary_marker(
            "old_schema_v8_writers", identifier, false))
        return;
    old_schema_v8_writers_.emplace(
        std::string(identifier),
        std::make_pair(std::string(canonical_path), false));
}

void surface_reconciliation_t::mark_legacy_invalid_ast_flow(
    std::string_view identifier) {
    if (saturating_add(
            attempted_auxiliary_markers_, 1,
            limits_.maximum_metric_value)) {
        metrics_saturated_.store(true, std::memory_order_release);
    }
    if (!valid_identifier(identifier)) {
        record_invalid_marker("legacy_ast_flows", identifier, "invalid_identifier");
        return;
    }
    if (legacy_ast_flows_.find(std::string(identifier)) != legacy_ast_flows_.end())
        return;
    if (!reserve_auxiliary_marker(
            "legacy_ast_flows", identifier, false))
        return;
    legacy_ast_flows_.emplace(std::string(identifier));
}

void surface_reconciliation_t::mark_unsupported_alias(
    std::string_view alias, std::string_view canonical_name) {
    if (saturating_add(
            attempted_auxiliary_markers_, 1,
            limits_.maximum_metric_value)) {
        metrics_saturated_.store(true, std::memory_order_release);
    }
    if (!valid_identifier(alias) || !valid_identifier(canonical_name)) {
        record_invalid_marker(
            "unsupported_aliases", alias, "invalid_alias_marker");
        return;
    }
    if (alias == canonical_name) {
        record_invalid_marker(
            "unsupported_aliases", alias, "self_replacement");
        return;
    }
    const auto found = unsupported_aliases_.find(std::string(alias));
    if (found != unsupported_aliases_.end()) {
        if (found->second.first != canonical_name) {
            if (!found->second.second) {
                record_invalid_marker(
                    "unsupported_aliases", alias,
                    "conflicting_duplicate_marker");
                found->second.second = true;
            }
            if (canonical_name < found->second.first)
                found->second.first = std::string(canonical_name);
        }
        return;
    }
    if (!reserve_auxiliary_marker(
            "unsupported_aliases", alias, false))
        return;
    unsupported_aliases_.emplace(
        std::string(alias),
        std::make_pair(std::string(canonical_name), false));
}

void surface_reconciliation_t::mark_security_regression(
    std::string_view identifier, std::string_view detail) {
    if (saturating_add(
            attempted_auxiliary_markers_, 1,
            limits_.maximum_metric_value)) {
        metrics_saturated_.store(true, std::memory_order_release);
    }
    if (!valid_identifier(identifier) || !valid_text(detail, false)) {
        record_invalid_marker(
            "security_regressions", identifier, "invalid_security_marker");
        return;
    }
    const auto found = security_regressions_.find(std::string(identifier));
    if (found != security_regressions_.end()) {
        if (found->second.first != detail) {
            if (!found->second.second) {
                record_invalid_marker(
                    "security_regressions", identifier,
                    "conflicting_duplicate_marker");
                found->second.second = true;
            }
            const bool stronger_detail =
                detail.size() > found->second.first.size() ||
                (detail.size() == found->second.first.size() &&
                 detail < found->second.first);
            if (stronger_detail)
                found->second.first = std::string(detail);
        }
        return;
    }
    if (!reserve_auxiliary_marker(
            "security_regressions", identifier, true))
        return;
    security_regressions_.emplace(
        std::string(identifier), std::make_pair(std::string(detail), false));
}

void surface_reconciliation_t::append_finding(
    surface_reconciliation_result_t& result,
    surface_finding_t finding) const {
    if (saturating_add(
            result.findings_produced, 1, limits_.maximum_metric_value)) {
        result.metrics_saturated = true;
        metrics_saturated_.store(true, std::memory_order_release);
    }
    if (finding.code == surface_error_code_t::security_regression_detected) {
        const auto existing = std::find_if(
            result.findings.begin(), result.findings.end(),
            [&finding](const auto& candidate) {
                return candidate.code == finding.code &&
                       candidate.identifier == finding.identifier;
            });
        if (existing != result.findings.end()) {
            if (stronger_retention(finding, *existing))
                *existing = std::move(finding);
            return;
        }
    }
    if (result.findings.size() < limits_.maximum_findings) {
        result.findings.push_back(std::move(finding));
        return;
    }
    result.finding_cap_exceeded = true;
    const auto weakest = std::min_element(
        result.findings.begin(), result.findings.end(),
        [](const auto& left, const auto& right) {
            return stronger_retention(right, left);
        });
    if (weakest != result.findings.end() &&
        stronger_retention(finding, *weakest)) {
        *weakest = std::move(finding);
    }
    if (saturating_add(
            result.findings_discarded, 1, limits_.maximum_metric_value)) {
        result.metrics_saturated = true;
        metrics_saturated_.store(true, std::memory_order_release);
    }
}

void surface_reconciliation_t::append_input_contract_findings(
    surface_reconciliation_result_t& result) const {
    if (!limit_contract_valid_) {
        append_finding(result, make_finding(
            surface_error_code_t::invalid_limit_contract,
            "surface_reconciliation_limits",
            "one or more caller limits were zero, below the diagnostic retention minimum, cross-inconsistent, or above the enforced maximum",
            "", surface_entry_kind_t::contract_registration, 1000));
    }
    if (baseline_cap_exceeded_) {
        append_finding(result, make_finding(
            surface_error_code_t::baseline_entry_cap_exceeded,
            "baseline_entries",
            bounded_concat(limits_.maximum_text_bytes, {
                "baseline entry capacity exceeded; attempted=",
                std::to_string(attempted_baseline_entries_), ", rejected=",
                std::to_string(rejected_baseline_entries_)}),
            "", surface_entry_kind_t::source_file, 900));
    }
    if (actual_cap_exceeded_) {
        append_finding(result, make_finding(
            surface_error_code_t::actual_entry_cap_exceeded,
            "actual_entries",
            bounded_concat(limits_.maximum_text_bytes, {
                "actual entry capacity exceeded; attempted=",
                std::to_string(attempted_actual_entries_), ", rejected=",
                std::to_string(rejected_actual_entries_)}),
            "", surface_entry_kind_t::source_file, 900));
    }
    if (malformed_entries_ != 0) {
        append_finding(result, make_finding(
            surface_error_code_t::invalid_surface_entry,
            first_invalid_entry_identifier_,
            bounded_concat(limits_.maximum_text_bytes, {
                first_invalid_entry_is_baseline_ ? "baseline" : "actual",
                " surface entry rejected; reason=", first_invalid_entry_reason_,
                ", malformed=", std::to_string(malformed_entries_)}),
            "", surface_entry_kind_t::source_file, 950));
    }
    if (malformed_markers_ != 0) {
        append_finding(result, make_finding(
            surface_error_code_t::invalid_surface_marker,
            first_invalid_marker_identifier_,
            bounded_concat(limits_.maximum_text_bytes, {
                "surface marker rejected; collection=",
                first_invalid_marker_collection_, ", reason=",
                first_invalid_marker_reason_, ", malformed=",
                std::to_string(malformed_markers_)}),
            "", surface_entry_kind_t::contract_registration, 950));
    }
    if (auxiliary_cap_exceeded_) {
        append_finding(result, make_finding(
            surface_error_code_t::auxiliary_marker_cap_exceeded,
            first_auxiliary_overflow_collection_,
            bounded_concat(limits_.maximum_text_bytes, {
                "shared auxiliary marker capacity exceeded; attempted=",
                std::to_string(attempted_auxiliary_markers_), ", rejected=",
                std::to_string(rejected_auxiliary_markers_)}),
            "", surface_entry_kind_t::contract_registration, 900));
    }
}

void surface_reconciliation_t::append_metrics_saturation_finding(
    surface_reconciliation_result_t& result) const {
    if (has_finding(result, surface_error_code_t::internal_error, "metrics_saturated"))
        return;
    append_finding(result, make_finding(
        surface_error_code_t::internal_error, "metrics_saturated",
        bounded_concat(limits_.maximum_text_bytes, {
            "one or more reconciliation metrics reached the configured ceiling of ",
            std::to_string(limits_.maximum_metric_value)}),
        "", surface_entry_kind_t::contract_registration, 1000));
}

void surface_reconciliation_t::finalize_finding_cap(
    surface_reconciliation_result_t& result) const {
    if (!result.finding_cap_exceeded)
        return;
    const auto install = [this, &result](
        surface_finding_t marker) {
        auto found = std::find_if(
            result.findings.begin(), result.findings.end(),
            [&marker](const auto& finding) {
                return finding.code == marker.code &&
                       finding.identifier == marker.identifier;
            });
        if (found != result.findings.end())
            return;
        if (saturating_add(
                result.findings_produced, 1,
                limits_.maximum_metric_value)) {
            result.metrics_saturated = true;
            metrics_saturated_.store(true, std::memory_order_release);
        }
        if (result.findings.size() < limits_.maximum_findings) {
            result.findings.push_back(std::move(marker));
            return;
        }
        const auto replace = std::min_element(
            result.findings.begin(), result.findings.end(),
            [](const auto& left, const auto& right) {
                return stronger_retention(right, left);
            });
        if (replace == result.findings.end() || mandatory_finding(*replace))
            return;
        if (saturating_add(
                result.findings_discarded, 1,
                limits_.maximum_metric_value)) {
            result.metrics_saturated = true;
            metrics_saturated_.store(true, std::memory_order_release);
        }
        *replace = std::move(marker);
    };

    install(make_finding(
        surface_error_code_t::finding_cap_exceeded, "surface_findings", "",
        "", surface_entry_kind_t::contract_registration, 1000));
    if (result.metrics_saturated ||
        metrics_saturated_.load(std::memory_order_acquire)) {
        result.metrics_saturated = true;
        install(make_finding(
            surface_error_code_t::internal_error, "metrics_saturated",
            bounded_concat(limits_.maximum_text_bytes, {
                "one or more reconciliation metrics reached the configured ceiling of ",
                std::to_string(limits_.maximum_metric_value)}),
            "", surface_entry_kind_t::contract_registration, 1000));
    }
    auto cap_marker = std::find_if(
        result.findings.begin(), result.findings.end(), [](const auto& finding) {
            return finding.code == surface_error_code_t::finding_cap_exceeded;
        });
    if (cap_marker == result.findings.end())
        return;
    cap_marker->detail = bounded_concat(limits_.maximum_text_bytes, {
        "finding capacity exceeded; produced=",
        std::to_string(result.findings_produced), ", retained=",
        std::to_string(result.findings.size()), ", discarded=",
        std::to_string(result.findings_discarded)});
}

surface_reconciliation_t::marker_target_proof_t
surface_reconciliation_t::validate_marker_targets(
    surface_reconciliation_result_t& result) const {
    marker_target_proof_t proof;
    proof.valid_dead_replacements.reserve(dead_replaced_paths_.size());
    proof.valid_alias_replacements.reserve(unsupported_aliases_.size());
    proof.valid_stale_registrations.reserve(stale_registrations_.size());
    proof.valid_schema_migrations.reserve(old_schema_v8_writers_.size());
    proof.valid_inactive_actual.reserve(actual_.size());

    const auto index_entries = [](const std::vector<surface_entry_t>& entries) {
        std::unordered_map<std::string, std::vector<const surface_entry_t*>> index;
        index.reserve(entries.size());
        for (const auto& entry : entries)
            index[entry.identifier].push_back(&entry);
        return index;
    };
    const auto baseline_index = index_entries(baseline_);
    const auto actual_index = index_entries(actual_);
    proof.unique_active_actual.reserve(actual_index.size());
    for (const auto& [identifier, entries] : actual_index) {
        if (entries.size() != 1 || !entries.front()->is_active)
            continue;
        proof.unique_active_actual.emplace(
            identifier,
            marker_target_proof_t::source_evidence_t{
                entries.front()->kind, entries.front()->canonical_path,
                entries.front()->schema_version});
    }
    const auto cyclic_predecessors = [](const auto& markers) {
        std::unordered_map<std::string, std::uint8_t> state;
        std::unordered_set<std::string> invalid;
        state.reserve(markers.size());
        invalid.reserve(markers.size());
        for (const auto* root : sorted_map_entries(markers)) {
            if (root->second.second)
                continue;
            const auto root_state = state.find(root->first);
            if (root_state != state.end() && root_state->second == 2)
                continue;
            std::vector<const std::string*> path;
            path.reserve(16);
            std::string current = root->first;
            bool inherits_cycle = false;
            for (;;) {
                const auto edge = markers.find(current);
                if (edge == markers.end() || edge->second.second)
                    break;
                const auto known = state.find(edge->first);
                const auto value = known == state.end() ? 0 : known->second;
                if (value == 0) {
                    state.emplace(edge->first, 1);
                    path.push_back(&edge->first);
                    current = edge->second.first;
                    continue;
                }
                inherits_cycle =
                    value == 1 || invalid.find(edge->first) != invalid.end();
                break;
            }
            if (inherits_cycle) {
                for (const auto* identifier : path)
                    invalid.insert(*identifier);
            }
            for (const auto* identifier : path)
                state[*identifier] = 2;
        }
        return invalid;
    };

    const auto dead_cycles = cyclic_predecessors(dead_replaced_paths_);
    const auto alias_cycles = cyclic_predecessors(unsupported_aliases_);
    const auto reject = [this, &result](
        std::string_view collection, std::string_view identifier,
        std::string_view target, std::string_view reason,
        std::uint64_t marker_count) {
        const bool rejected_saturated = saturating_add(
            result.rejected_auxiliary_markers, marker_count,
            limits_.maximum_metric_value);
        const bool malformed_saturated = saturating_add(
            result.malformed_markers, marker_count,
            limits_.maximum_metric_value);
        if (rejected_saturated || malformed_saturated) {
            result.metrics_saturated = true;
            metrics_saturated_.store(true, std::memory_order_release);
        }
        const auto detail = target.empty()
            ? bounded_concat(limits_.maximum_text_bytes, {
                  "surface marker rejected; collection=", collection,
                  ", reason=", reason})
            : bounded_concat(limits_.maximum_text_bytes, {
                  "replacement marker rejected; collection=", collection,
                  ", target=", target, ", reason=", reason});
        append_finding(result, make_finding(
            surface_error_code_t::invalid_surface_marker, identifier,
            detail, "", surface_entry_kind_t::contract_registration, 950));
    };

    std::unordered_map<std::string, std::uint8_t> proof_collection_counts;
    proof_collection_counts.reserve(
        dead_replaced_paths_.size() + unsupported_aliases_.size() +
        stale_registrations_.size() + old_schema_v8_writers_.size());
    for (const auto& marker : dead_replaced_paths_) {
        if (!marker.second.second)
            ++proof_collection_counts[marker.first];
    }
    for (const auto& marker : unsupported_aliases_) {
        if (!marker.second.second)
            ++proof_collection_counts[marker.first];
    }
    for (const auto& identifier : stale_registrations_)
        ++proof_collection_counts[identifier];
    for (const auto& marker : old_schema_v8_writers_) {
        if (!marker.second.second)
            ++proof_collection_counts[marker.first];
    }
    std::vector<std::string> conflicting_proof_identifiers;
    conflicting_proof_identifiers.reserve(proof_collection_counts.size());
    for (const auto& [identifier, count] : proof_collection_counts) {
        if (count > 1)
            conflicting_proof_identifiers.push_back(identifier);
    }
    std::sort(
        conflicting_proof_identifiers.begin(),
        conflicting_proof_identifiers.end());
    std::unordered_set<std::string> conflicting_proofs;
    conflicting_proofs.reserve(conflicting_proof_identifiers.size());
    for (const auto& identifier : conflicting_proof_identifiers) {
        conflicting_proofs.insert(identifier);
        const auto marker_count = static_cast<std::uint64_t>(
            proof_collection_counts.at(identifier));
        reject(
            "inactive_entry_proofs", identifier, "",
            "conflicting_proof_markers", marker_count);
    }

    const auto validate_replacement = [
        &baseline_index, &actual_index, &conflicting_proofs, &reject](
        const auto& markers, const auto& cycles, std::string_view collection,
        bool alias, auto& valid) {
        for (const auto* marker : sorted_map_entries(markers)) {
            const auto& identifier = marker->first;
            if (marker->second.second)
                continue;
            const auto& target = marker->second.first;
            if (conflicting_proofs.find(identifier) != conflicting_proofs.end())
                continue;
            std::string_view reason;
            if (identifier == target) {
                reason = "self_replacement";
            } else if (cycles.find(identifier) != cycles.end()) {
                reason = "cyclic_replacement_graph";
            }

            const auto baseline_source = baseline_index.find(identifier);
            const auto actual_source = actual_index.find(identifier);
            const auto baseline_source_count =
                baseline_source == baseline_index.end()
                    ? 0
                    : baseline_source->second.size();
            const auto actual_source_count =
                actual_source == actual_index.end()
                    ? 0
                    : actual_source->second.size();
            if (reason.empty() &&
                (baseline_source_count > 1 || actual_source_count > 1)) {
                reason = "ambiguous_source_identity";
            } else if (reason.empty() && actual_source_count == 0) {
                reason = "missing_actual_source_identity";
            }

            surface_entry_kind_t source_kind = surface_entry_kind_t::source_file;
            const surface_entry_t* source_entry = nullptr;
            if (reason.empty()) {
                source_entry = actual_source->second.front();
                source_kind = source_entry->kind;
                if (baseline_source_count == 1 && actual_source_count == 1 &&
                    baseline_source->second.front()->kind !=
                        actual_source->second.front()->kind) {
                    reason = "conflicting_source_kind";
                } else if (baseline_source_count == 1 &&
                           baseline_source->second.front()->canonical_path !=
                               source_entry->canonical_path) {
                    reason = "conflicting_source_identity";
                } else if (baseline_source_count == 1 &&
                           baseline_source->second.front()->schema_version !=
                               source_entry->schema_version) {
                    reason = "conflicting_source_schema";
                } else if (alias &&
                           source_kind != surface_entry_kind_t::alias_mapping) {
                    reason = "alias_marker_on_incompatible_source_kind";
                } else if (!alias &&
                           source_kind == surface_entry_kind_t::alias_mapping) {
                    reason = "dead_path_marker_on_alias_source";
                } else if (source_kind == surface_entry_kind_t::security_guard) {
                    reason = "security_guard_replacement_forbidden";
                }
                if (reason.empty() && source_entry->is_active) {
                    reason = "source_is_active";
                } else if (reason.empty() && !source_entry->is_replaced) {
                    reason = "inactive_source_without_replacement_state";
                } else if (reason.empty() && source_entry->replaced_by != target) {
                    reason = "source_replacement_target_mismatch";
                }
            }

            const auto target_entries = actual_index.find(target);
            const auto target_count =
                target_entries == actual_index.end()
                    ? 0
                    : target_entries->second.size();
            if (reason.empty() && target_count == 0) {
                reason = "missing_actual_target";
            } else if (reason.empty() && target_count > 1) {
                reason = "ambiguous_actual_target";
            } else if (reason.empty() &&
                       !target_entries->second.front()->is_active) {
                reason = "inactive_actual_target";
            } else if (reason.empty()) {
                const auto target_kind = target_entries->second.front()->kind;
                const bool compatible = alias
                    ? target_kind == surface_entry_kind_t::handler_registration ||
                          target_kind == surface_entry_kind_t::tool_registration
                    : target_kind == source_kind;
                if (!compatible)
                    reason = "incompatible_actual_target_kind";
                else if (!alias &&
                         source_kind == surface_entry_kind_t::schema_writer &&
                         target_entries->second.front()->schema_version !=
                             source_entry->schema_version)
                    reason = "replacement_target_schema_mismatch";
            }

            if (!reason.empty()) {
                reject(collection, identifier, target, reason, 1);
                continue;
            }
            valid.emplace(
                identifier,
                marker_target_proof_t::source_evidence_t{
                    source_kind, source_entry->canonical_path,
                    source_entry->schema_version});
        }
    };

    validate_replacement(
        dead_replaced_paths_, dead_cycles, "dead_replaced_paths", false,
        proof.valid_dead_replacements);
    validate_replacement(
        unsupported_aliases_, alias_cycles, "unsupported_aliases", true,
        proof.valid_alias_replacements);
    for (const auto* identifier : sorted_set_entries(stale_registrations_)) {
        if (conflicting_proofs.find(*identifier) != conflicting_proofs.end())
            continue;
        std::string_view reason;
        const auto baseline_source = baseline_index.find(*identifier);
        const auto actual_source = actual_index.find(*identifier);
        const auto baseline_source_count =
            baseline_source == baseline_index.end()
                ? 0
                : baseline_source->second.size();
        const auto actual_source_count =
            actual_source == actual_index.end()
                ? 0
                : actual_source->second.size();
        if (baseline_source_count > 1 || actual_source_count > 1) {
            reason = "ambiguous_source_identity";
        } else if (actual_source_count == 0) {
            reason = "missing_actual_source_identity";
        }
        surface_entry_kind_t source_kind = surface_entry_kind_t::source_file;
        const surface_entry_t* source_entry = nullptr;
        if (reason.empty()) {
            source_entry = actual_source->second.front();
            source_kind = source_entry->kind;
            if (baseline_source_count == 1 && actual_source_count == 1 &&
                baseline_source->second.front()->kind !=
                    actual_source->second.front()->kind) {
                reason = "conflicting_source_kind";
            } else if (baseline_source_count == 1 &&
                       baseline_source->second.front()->canonical_path !=
                           source_entry->canonical_path) {
                reason = "conflicting_source_identity";
            } else if (source_kind == surface_entry_kind_t::security_guard) {
                reason = "security_guard_stale_forbidden";
            } else if (source_kind != surface_entry_kind_t::handler_registration &&
                       source_kind != surface_entry_kind_t::tool_registration) {
                reason = "stale_marker_on_incompatible_source_kind";
            }
            if (reason.empty() && source_entry->is_active)
                reason = "stale_source_is_active";
            else if (reason.empty() && source_entry->is_replaced)
                reason = "stale_source_has_replacement";
        }
        if (!reason.empty()) {
            reject("stale_registrations", *identifier, "", reason, 1);
            continue;
        }
        proof.valid_stale_registrations.emplace(
            *identifier,
            marker_target_proof_t::source_evidence_t{
                source_kind, source_entry->canonical_path,
                source_entry->schema_version});
    }

    for (const auto* marker : sorted_map_entries(old_schema_v8_writers_)) {
        if (marker->second.second ||
            conflicting_proofs.find(marker->first) != conflicting_proofs.end())
            continue;
        std::string_view reason;
        const auto baseline_source = baseline_index.find(marker->first);
        const auto actual_source = actual_index.find(marker->first);
        const auto baseline_source_count = baseline_source == baseline_index.end()
            ? 0
            : baseline_source->second.size();
        const auto actual_source_count = actual_source == actual_index.end()
            ? 0
            : actual_source->second.size();
        if (baseline_source_count == 0)
            reason = "missing_baseline_schema_writer";
        else if (actual_source_count == 0)
            reason = "missing_actual_schema_writer";
        else if (baseline_source_count > 1 || actual_source_count > 1)
            reason = "ambiguous_schema_writer_identity";
        const surface_entry_t* baseline_entry = nullptr;
        const surface_entry_t* actual_entry = nullptr;
        if (reason.empty()) {
            baseline_entry = baseline_source->second.front();
            actual_entry = actual_source->second.front();
            if (baseline_entry->kind != surface_entry_kind_t::schema_writer ||
                actual_entry->kind != surface_entry_kind_t::schema_writer)
                reason = "schema_marker_on_incompatible_source_kind";
            else if (baseline_entry->canonical_path != marker->second.first ||
                     actual_entry->canonical_path != marker->second.first)
                reason = "schema_marker_path_mismatch";
            else if (baseline_entry->schema_version != "v8")
                reason = "wrong_old_schema_version";
            else if (actual_entry->schema_version != "v9")
                reason = "wrong_current_schema_version";
            else if (!baseline_entry->is_active || !actual_entry->is_active ||
                     baseline_entry->is_replaced || actual_entry->is_replaced ||
                     !baseline_entry->replaced_by.empty() ||
                     !actual_entry->replaced_by.empty())
                reason = "schema_writer_not_active_canonical_state";
        }
        if (!reason.empty()) {
            reject(
                "old_schema_v8_writers", marker->first, "", reason, 1);
            continue;
        }
        proof.valid_schema_migrations.emplace(
            marker->first,
            marker_target_proof_t::source_evidence_t{
                surface_entry_kind_t::schema_writer,
                actual_entry->canonical_path, actual_entry->schema_version});
    }
    for (const auto& [identifier, entries] : actual_index) {
        if (entries.size() != 1 || entries.front()->is_active ||
            entries.front()->kind == surface_entry_kind_t::security_guard) {
            continue;
        }
        const marker_target_proof_t::source_evidence_t* evidence = nullptr;
        std::size_t proof_count = 0;
        const auto select = [&evidence, &proof_count](const auto& values,
                                                     const std::string& key) {
            const auto found = values.find(key);
            if (found == values.end())
                return;
            evidence = &found->second;
            ++proof_count;
        };
        select(proof.valid_dead_replacements, identifier);
        select(proof.valid_alias_replacements, identifier);
        select(proof.valid_stale_registrations, identifier);
        if (proof_count == 1) {
            proof.valid_inactive_actual.emplace(identifier, *evidence);
        }
    }
    if (auxiliary_capacity_incomplete_) {
        proof.valid_dead_replacements.clear();
        proof.valid_alias_replacements.clear();
        proof.valid_stale_registrations.clear();
        proof.valid_schema_migrations.clear();
        proof.valid_inactive_actual.clear();
    }
    return proof;
}

void surface_reconciliation_t::check_duplicate_identifiers(
    surface_reconciliation_result_t& result) const {
    const auto check = [this, &result](
        const std::vector<surface_entry_t>& entries, bool baseline) {
        const auto ordered = sorted_entries(entries);
        for (std::size_t begin = 0; begin < ordered.size();) {
            std::size_t end = begin + 1;
            while (end < ordered.size() &&
                   ordered[end]->identifier == ordered[begin]->identifier) {
                ++end;
            }
            const auto count = end - begin;
            if (count > 1) {
                const bool all_stores = std::all_of(
                    ordered.begin() + static_cast<std::ptrdiff_t>(begin),
                    ordered.begin() + static_cast<std::ptrdiff_t>(end),
                    [](const auto* entry) {
                        return entry->kind == surface_entry_kind_t::store_definition;
                    });
                if (baseline || !all_stores) {
                    append_finding(result, make_finding(
                        baseline
                            ? surface_error_code_t::duplicate_baseline_identifier_detected
                            : surface_error_code_t::duplicate_actual_identifier_detected,
                        ordered[begin]->identifier,
                        bounded_concat(limits_.maximum_text_bytes, {
                            baseline ? "baseline" : "actual",
                            " surface contains duplicate identifier entries; count=",
                            std::to_string(count)}),
                        ordered[begin]->canonical_path,
                        ordered[begin]->kind, 650));
                }
            }
            begin = end;
        }
    };
    check(baseline_, true);
    check(actual_, false);
}

void surface_reconciliation_t::check_baseline_mismatches(
    surface_reconciliation_result_t& result,
    const marker_target_proof_t& target_proof) const {
    const auto baseline = sorted_entries(baseline_);
    const auto actual = sorted_entries(actual_);
    std::size_t baseline_index = 0;
    std::size_t actual_index = 0;
    while (baseline_index < baseline.size() && actual_index < actual.size()) {
        if (baseline[baseline_index]->identifier < actual[actual_index]->identifier) {
            ++baseline_index;
            continue;
        }
        if (actual[actual_index]->identifier < baseline[baseline_index]->identifier) {
            ++actual_index;
            continue;
        }
        const auto identifier = baseline[baseline_index]->identifier;
        auto baseline_end = baseline_index + 1;
        while (baseline_end < baseline.size() &&
               baseline[baseline_end]->identifier == identifier) {
            ++baseline_end;
        }
        auto actual_end = actual_index + 1;
        while (actual_end < actual.size() &&
               actual[actual_end]->identifier == identifier) {
            ++actual_end;
        }
        if (baseline_end - baseline_index == 1 &&
            actual_end - actual_index == 1) {
            const auto& expected = *baseline[baseline_index];
            const auto& observed = *actual[actual_index];
            const bool canonical_path_changed =
                expected.canonical_path != observed.canonical_path;
            const bool kind_changed = expected.kind != observed.kind;
            const bool active_changed = expected.is_active != observed.is_active;
            const bool replaced_changed = expected.is_replaced != observed.is_replaced;
            const bool replacement_changed = expected.replaced_by != observed.replaced_by;
            const bool schema_changed = expected.schema_version != observed.schema_version;
            const bool security_note_changed =
                expected.security_note != observed.security_note;
            if (canonical_path_changed || kind_changed || active_changed ||
                replaced_changed || replacement_changed || schema_changed ||
                security_note_changed) {
                const auto dead = dead_replaced_paths_.find(identifier);
                const bool explained_replacement =
                    dead != dead_replaced_paths_.end() && expected.is_active &&
                    target_proof.valid_dead_replacements.find(identifier) !=
                        target_proof.valid_dead_replacements.end() &&
                    !expected.is_replaced && !observed.is_active &&
                    observed.is_replaced &&
                    observed.replaced_by == dead->second.first &&
                    expected.kind == observed.kind &&
                    expected.canonical_path == observed.canonical_path &&
                    expected.schema_version == observed.schema_version &&
                    expected.security_note == observed.security_note;
                const bool registration_kind =
                    expected.kind == surface_entry_kind_t::handler_registration ||
                    expected.kind == surface_entry_kind_t::tool_registration;
                const bool explained_stale_registration =
                    target_proof.valid_stale_registrations.find(identifier) !=
                        target_proof.valid_stale_registrations.end() &&
                    registration_kind && expected.kind == observed.kind &&
                    expected.is_active && !observed.is_active &&
                    expected.is_replaced == observed.is_replaced &&
                    expected.replaced_by == observed.replaced_by &&
                    expected.canonical_path == observed.canonical_path &&
                    expected.schema_version == observed.schema_version &&
                    expected.security_note == observed.security_note;
                const auto alias = unsupported_aliases_.find(identifier);
                const bool explained_alias_retirement =
                    alias != unsupported_aliases_.end() &&
                    target_proof.valid_alias_replacements.find(identifier) !=
                        target_proof.valid_alias_replacements.end() &&
                    expected.kind == surface_entry_kind_t::alias_mapping &&
                    observed.kind == surface_entry_kind_t::alias_mapping &&
                    expected.is_active && !expected.is_replaced &&
                    !observed.is_active && observed.is_replaced &&
                    observed.replaced_by == alias->second.first &&
                    expected.canonical_path == observed.canonical_path &&
                    expected.schema_version == observed.schema_version &&
                    expected.security_note == observed.security_note;
                const bool explained_schema_migration =
                    target_proof.valid_schema_migrations.find(identifier) !=
                        target_proof.valid_schema_migrations.end() &&
                    expected.kind == surface_entry_kind_t::schema_writer &&
                    observed.kind == surface_entry_kind_t::schema_writer &&
                    expected.schema_version == "v8" &&
                    observed.schema_version == "v9" &&
                    expected.canonical_path == observed.canonical_path &&
                    expected.is_active && observed.is_active &&
                    expected.is_replaced == observed.is_replaced &&
                    expected.replaced_by == observed.replaced_by &&
                    expected.security_note == observed.security_note;
                const bool security_relevant =
                    expected.kind == surface_entry_kind_t::security_guard ||
                    observed.kind == surface_entry_kind_t::security_guard ||
                    security_note_changed;
                if (!security_relevant &&
                    (explained_replacement || explained_stale_registration ||
                     explained_alias_retirement || explained_schema_migration)) {
                    baseline_index = baseline_end;
                    actual_index = actual_end;
                    continue;
                }
                std::string changed_fields;
                const auto add_field = [this, &changed_fields](std::string_view field) {
                    if (!changed_fields.empty())
                        append_bounded(changed_fields, ",", limits_.maximum_text_bytes);
                    append_bounded(changed_fields, field, limits_.maximum_text_bytes);
                };
                if (kind_changed)
                    add_field("kind");
                if (canonical_path_changed)
                    add_field("canonical_path");
                if (active_changed)
                    add_field("is_active");
                if (replaced_changed)
                    add_field("is_replaced");
                if (replacement_changed)
                    add_field("replaced_by");
                if (schema_changed)
                    add_field("schema_version");
                if (security_note_changed)
                    add_field("security_note");
                append_finding(result, make_finding(
                    security_relevant
                        ? surface_error_code_t::security_regression_detected
                        : surface_error_code_t::baseline_mismatch,
                    identifier,
                    bounded_concat(limits_.maximum_text_bytes, {
                        security_relevant
                            ? "security-relevant baseline drift in fields: "
                            : "baseline and actual surface differ in fields: ",
                        changed_fields}),
                    expected.canonical_path,
                    security_relevant
                        ? surface_entry_kind_t::security_guard
                        : expected.kind,
                    security_relevant ? 950 : 750));
            }
        }
        baseline_index = baseline_end;
        actual_index = actual_end;
    }
}

void surface_reconciliation_t::check_inactive_actual_entries(
    surface_reconciliation_result_t& result,
    const marker_target_proof_t& target_proof) const {
    const auto actual = sorted_entries(actual_);
    for (std::size_t begin = 0; begin < actual.size();) {
        std::size_t end = begin + 1;
        while (end < actual.size() &&
               actual[end]->identifier == actual[begin]->identifier) {
            ++end;
        }
        const auto& entry = *actual[begin];
        const auto evidence =
            target_proof.valid_inactive_actual.find(entry.identifier);
        const bool exact_proof =
            evidence != target_proof.valid_inactive_actual.end() &&
            evidence->second.kind == entry.kind &&
            evidence->second.canonical_path == entry.canonical_path &&
            evidence->second.schema_version == entry.schema_version;
        if (end - begin == 1 && !entry.is_active &&
            entry.kind != surface_entry_kind_t::security_guard &&
            !exact_proof) {
            if (saturating_add(
                    result.unexplained_removals, 1,
                    limits_.maximum_metric_value)) {
                result.metrics_saturated = true;
                metrics_saturated_.store(true, std::memory_order_release);
            }
            std::string detail;
            if (entry.is_replaced) {
                detail = bounded_concat(limits_.maximum_text_bytes, {
                    "inactive actual entry replacement has no exact lawful proof; target=",
                    entry.replaced_by});
            } else if (
                entry.kind == surface_entry_kind_t::handler_registration ||
                entry.kind == surface_entry_kind_t::tool_registration) {
                detail = "inactive actual registration has no exact stale proof";
            } else {
                detail = "inactive actual entry has no exact lawful retirement proof";
            }
            append_finding(result, make_finding(
                surface_error_code_t::unexplained_removal_detected,
                entry.identifier, std::move(detail), entry.canonical_path,
                entry.kind, 800));
        }
        begin = end;
    }
}

void surface_reconciliation_t::check_dead_replaced_paths(
    surface_reconciliation_result_t& result,
    const marker_target_proof_t& target_proof) const {
    for (const auto* marker : sorted_map_entries(dead_replaced_paths_)) {
        if (marker->second.second)
            continue;
        const auto evidence =
            target_proof.unique_active_actual.find(marker->first);
        if (evidence == target_proof.unique_active_actual.end()) {
            continue;
        }
        append_finding(result, make_finding(
            surface_error_code_t::dead_replaced_path_detected,
            marker->first,
            bounded_concat(limits_.maximum_text_bytes, {
                "path marked as replaced by ", marker->second.first,
                " but still active in actual surface"}),
            evidence->second.canonical_path, evidence->second.kind, 500));
    }
}

void surface_reconciliation_t::check_duplicate_stores(
    surface_reconciliation_result_t& result) const {
    const auto actual = sorted_entries(actual_);
    std::unordered_set<std::string> duplicate_actual_ids;
    for (std::size_t begin = 0; begin < actual.size();) {
        std::size_t end = begin + 1;
        while (end < actual.size() &&
               actual[end]->identifier == actual[begin]->identifier) {
            ++end;
        }
        if (end - begin > 1) {
            duplicate_actual_ids.insert(actual[begin]->identifier);
            const bool all_stores = std::all_of(
                actual.begin() + static_cast<std::ptrdiff_t>(begin),
                actual.begin() + static_cast<std::ptrdiff_t>(end),
                [](const auto* entry) {
                    return entry->kind == surface_entry_kind_t::store_definition;
                });
            if (all_stores) {
                std::string detail = "store defined in multiple paths: ";
                for (auto index = begin; index < end; ++index) {
                    if (index != begin)
                        append_bounded(detail, ", ", limits_.maximum_text_bytes);
                    append_bounded(
                        detail, actual[index]->canonical_path,
                        limits_.maximum_text_bytes);
                }
                append_finding(result, make_finding(
                    surface_error_code_t::duplicate_store_detected,
                    actual[begin]->identifier, std::move(detail),
                    actual[begin]->canonical_path,
                    surface_entry_kind_t::store_definition, 600));
            }
        }
        begin = end;
    }
    for (const auto* marker : sorted_map_entries(duplicate_stores_)) {
        if (marker->second.second)
            continue;
        if (duplicate_actual_ids.find(marker->first) != duplicate_actual_ids.end())
            continue;
        append_finding(result, make_finding(
            surface_error_code_t::duplicate_store_detected,
            marker->first,
            bounded_concat(limits_.maximum_text_bytes, {
                "duplicate store also at ", marker->second.first}),
            marker->second.first, surface_entry_kind_t::store_definition, 550));
    }
}

void surface_reconciliation_t::check_stale_registrations(
    surface_reconciliation_result_t& result,
    const marker_target_proof_t& target_proof) const {
    std::unordered_set<std::string> actual_ids;
    actual_ids.reserve(actual_.size());
    for (const auto& entry : actual_)
        actual_ids.insert(entry.identifier);
    for (const auto* identifier : sorted_set_entries(stale_registrations_)) {
        const auto evidence =
            target_proof.unique_active_actual.find(*identifier);
        if (evidence == target_proof.unique_active_actual.end() ||
            (evidence->second.kind != surface_entry_kind_t::handler_registration &&
             evidence->second.kind != surface_entry_kind_t::tool_registration)) {
            continue;
        }
        append_finding(result, make_finding(
            surface_error_code_t::stale_registration_detected,
            *identifier,
            "registration is stale but still active in actual surface",
            evidence->second.canonical_path, evidence->second.kind, 400));
    }
    const auto baseline = sorted_entries(baseline_);
    for (std::size_t begin = 0; begin < baseline.size();) {
        std::size_t end = begin + 1;
        while (end < baseline.size() &&
               baseline[end]->identifier == baseline[begin]->identifier) {
            ++end;
        }
        const auto& entry = *baseline[begin];
        const bool registration =
            entry.kind == surface_entry_kind_t::handler_registration ||
            entry.kind == surface_entry_kind_t::tool_registration;
        if (end - begin == 1 && registration && entry.is_active &&
            actual_ids.find(entry.identifier) == actual_ids.end()) {
            append_finding(result, make_finding(
                surface_error_code_t::stale_registration_detected,
                entry.identifier,
                "baseline registration not found in actual surface",
                entry.canonical_path, entry.kind, 350));
        }
        begin = end;
    }
}

void surface_reconciliation_t::check_old_schema_v8_writers(
    surface_reconciliation_result_t& result) const {
    const auto actual = sorted_entries(actual_);
    std::unordered_set<std::string> emitted;
    for (const auto* entry : actual) {
        if (entry->kind != surface_entry_kind_t::schema_writer ||
            entry->schema_version != "v8" || !entry->is_active ||
            !emitted.insert(entry->identifier).second) {
            continue;
        }
        append_finding(result, make_finding(
            surface_error_code_t::old_schema_v8_writer_detected,
            entry->identifier,
            "active schema writer uses deprecated v8 schema; migration to v9 is required",
            entry->canonical_path, surface_entry_kind_t::schema_writer, 700));
    }
}

void surface_reconciliation_t::check_legacy_invalid_ast_flows(
    surface_reconciliation_result_t& result,
    const marker_target_proof_t& target_proof) const {
    for (const auto* identifier : sorted_set_entries(legacy_ast_flows_)) {
        const auto entry = target_proof.unique_active_actual.find(*identifier);
        if (entry == target_proof.unique_active_actual.end() ||
            entry->second.kind != surface_entry_kind_t::ast_path) {
            continue;
        }
        append_finding(result, make_finding(
            surface_error_code_t::legacy_invalid_ast_flow_detected,
            *identifier,
            "legacy invalid AST flow is still active in actual surface",
            entry->second.canonical_path, entry->second.kind, 650));
    }
}

void surface_reconciliation_t::check_unsupported_aliases(
    surface_reconciliation_result_t& result,
    const marker_target_proof_t& target_proof) const {
    for (const auto* marker : sorted_map_entries(unsupported_aliases_)) {
        if (marker->second.second)
            continue;
        const auto entry = target_proof.unique_active_actual.find(marker->first);
        if (entry == target_proof.unique_active_actual.end() ||
            entry->second.kind != surface_entry_kind_t::alias_mapping) {
            continue;
        }
        append_finding(result, make_finding(
            surface_error_code_t::unsupported_alias_detected,
            marker->first,
            bounded_concat(limits_.maximum_text_bytes, {
                "unsupported alias remains active; canonical name is ",
                marker->second.first}),
            entry->second.canonical_path, entry->second.kind, 300));
    }
}

void surface_reconciliation_t::check_security_regressions(
    surface_reconciliation_result_t& result) const {
    const auto actual = sorted_entries(actual_);
    for (const auto* entry : actual) {
        if (entry->kind != surface_entry_kind_t::security_guard || entry->is_active) {
            continue;
        }
        append_finding(result, make_finding(
            surface_error_code_t::security_regression_detected,
            entry->identifier,
            bounded_concat(limits_.maximum_text_bytes, {
                "security guard is inactive in actual surface: ",
                entry->security_note}),
            entry->canonical_path, surface_entry_kind_t::security_guard, 900));
    }
    for (const auto* marker : sorted_map_entries(security_regressions_)) {
        append_finding(result, make_finding(
            surface_error_code_t::security_regression_detected,
            marker->first,
            bounded_concat(limits_.maximum_text_bytes, {
                "security regression: ", marker->second.first}),
            "", surface_entry_kind_t::security_guard, 900));
    }
    const auto baseline = sorted_entries(baseline_);
    std::unordered_map<std::string, std::pair<std::size_t, std::size_t>>
        actual_guard_counts;
    for (const auto& entry : actual_) {
        if (entry.kind != surface_entry_kind_t::security_guard)
            continue;
        auto& counts = actual_guard_counts[entry.identifier];
        ++counts.first;
        if (entry.is_active)
            ++counts.second;
    }
    for (const auto* entry : baseline) {
        if (entry->kind != surface_entry_kind_t::security_guard || !entry->is_active) {
            continue;
        }
        const auto actual_guard = actual_guard_counts.find(entry->identifier);
        if (actual_guard != actual_guard_counts.end() &&
            actual_guard->second.first == 1 && actual_guard->second.second == 1)
            continue;
        append_finding(result, make_finding(
            surface_error_code_t::security_regression_detected,
            entry->identifier,
            "baseline security guard is missing or inactive in actual surface",
            entry->canonical_path, surface_entry_kind_t::security_guard, 1000));
    }
}

void surface_reconciliation_t::check_unexplained_removals(
    surface_reconciliation_result_t& result) const {
    std::unordered_set<std::string> actual_ids;
    actual_ids.reserve(actual_.size());
    for (const auto& entry : actual_)
        actual_ids.insert(entry.identifier);
    const auto baseline = sorted_entries(baseline_);
    for (std::size_t begin = 0; begin < baseline.size();) {
        std::size_t end = begin + 1;
        while (end < baseline.size() &&
               baseline[end]->identifier == baseline[begin]->identifier) {
            ++end;
        }
        const auto& entry = *baseline[begin];
        if (end - begin == 1 && entry.is_active &&
            entry.kind != surface_entry_kind_t::security_guard &&
            actual_ids.find(entry.identifier) == actual_ids.end()) {
            if (saturating_add(
                    result.unexplained_removals, 1,
                    limits_.maximum_metric_value)) {
                result.metrics_saturated = true;
                metrics_saturated_.store(true, std::memory_order_release);
            }
            append_finding(result, make_finding(
                surface_error_code_t::unexplained_removal_detected,
                entry.identifier,
                "baseline entry is absent from actual surface with no exact inactive actual tombstone",
                entry.canonical_path, entry.kind, 800));
        }
        begin = end;
    }
}

surface_reconciliation_result_t surface_reconciliation_t::reconcile() const {
    surface_reconciliation_result_t result;
    const auto capture_size_metric = [this, &result](std::size_t value) {
        const auto converted = static_cast<std::uint64_t>(value);
        if (converted < limits_.maximum_metric_value)
            return converted;
        result.metrics_saturated = true;
        metrics_saturated_.store(true, std::memory_order_release);
        return limits_.maximum_metric_value;
    };
    result.baseline_entry_count = capture_size_metric(baseline_.size());
    result.actual_entry_count = capture_size_metric(actual_.size());
    result.attempted_baseline_entries = attempted_baseline_entries_;
    result.attempted_actual_entries = attempted_actual_entries_;
    result.rejected_baseline_entries = rejected_baseline_entries_;
    result.rejected_actual_entries = rejected_actual_entries_;
    result.attempted_auxiliary_markers = attempted_auxiliary_markers_;
    result.rejected_auxiliary_markers = rejected_auxiliary_markers_;
    result.malformed_entries = malformed_entries_;
    result.malformed_markers = malformed_markers_;
    result.limits_invalid = !limit_contract_valid_;
    result.baseline_cap_exceeded = baseline_cap_exceeded_;
    result.actual_cap_exceeded = actual_cap_exceeded_;
    result.auxiliary_cap_exceeded = auxiliary_cap_exceeded_;
    result.metrics_saturated =
        result.metrics_saturated ||
        metrics_saturated_.load(std::memory_order_acquire);
    result.total_entries_checked = result.attempted_baseline_entries;
    if (saturating_add(
            result.total_entries_checked, result.attempted_actual_entries,
            limits_.maximum_metric_value)) {
        result.metrics_saturated = true;
        metrics_saturated_.store(true, std::memory_order_release);
    }

    append_input_contract_findings(result);
    const auto marker_target_proof = validate_marker_targets(result);
    check_duplicate_identifiers(result);
    check_baseline_mismatches(result, marker_target_proof);
    check_inactive_actual_entries(result, marker_target_proof);
    check_dead_replaced_paths(result, marker_target_proof);
    check_duplicate_stores(result);
    check_stale_registrations(result, marker_target_proof);
    check_old_schema_v8_writers(result);
    check_legacy_invalid_ast_flows(result, marker_target_proof);
    check_unsupported_aliases(result, marker_target_proof);
    check_security_regressions(result);
    check_unexplained_removals(result);

    if (saturating_atomic_add(
            reconciliations_, 1, limits_.maximum_metric_value)) {
        result.metrics_saturated = true;
        metrics_saturated_.store(true, std::memory_order_release);
    }
    if (result.metrics_saturated ||
        metrics_saturated_.load(std::memory_order_acquire)) {
        result.metrics_saturated = true;
        append_metrics_saturation_finding(result);
    }
    finalize_finding_cap(result);

    const auto counted_findings = result.findings.size();
    if (saturating_atomic_add(
            total_findings_, static_cast<std::uint64_t>(counted_findings),
            limits_.maximum_metric_value)) {
        result.metrics_saturated = true;
        metrics_saturated_.store(true, std::memory_order_release);
        append_metrics_saturation_finding(result);
        finalize_finding_cap(result);
        if (result.findings.size() > counted_findings) {
            saturating_atomic_add(
                total_findings_, static_cast<std::uint64_t>(
                    result.findings.size() - counted_findings),
                limits_.maximum_metric_value);
        }
    }

    result.metrics_saturated =
        result.metrics_saturated ||
        metrics_saturated_.load(std::memory_order_acquire);
    for (auto& finding : result.findings)
        finding.severity = std::min(finding.severity, limits_.maximum_severity);
    result.clean = result.findings.empty() && result.unexplained_removals == 0 &&
                   !result.limits_invalid && !result.baseline_cap_exceeded &&
                   !result.actual_cap_exceeded && !result.auxiliary_cap_exceeded &&
                   !result.finding_cap_exceeded && result.malformed_entries == 0 &&
                   result.malformed_markers == 0 && !result.metrics_saturated;
    std::sort(result.findings.begin(), result.findings.end(), [](const auto& left,
                                                                 const auto& right) {
        return std::tie(
                   left.code, left.identifier, left.canonical_path, left.detail,
                   left.kind, left.severity) <
               std::tie(
                   right.code, right.identifier, right.canonical_path, right.detail,
                   right.kind, right.severity);
    });
    return result;
}

std::size_t surface_reconciliation_t::baseline_entry_count() const noexcept {
    return baseline_.size();
}

std::size_t surface_reconciliation_t::actual_entry_count() const noexcept {
    return actual_.size();
}

std::uint64_t surface_reconciliation_t::reconciliations_performed() const noexcept {
    return reconciliations_.load(std::memory_order_acquire);
}

std::uint64_t surface_reconciliation_t::total_findings() const noexcept {
    return total_findings_.load(std::memory_order_acquire);
}

}
