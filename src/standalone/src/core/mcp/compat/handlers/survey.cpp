#include "survey.hpp"

#include "../ida_contracts_generated.hpp"
#include "../../../analysis/workspace/compact_ir.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <cmath>
#include <exception>
#include <initializer_list>
#include <iterator>
#include <limits>
#include <numeric>
#include <optional>
#include <stdexcept>
#include <string>
#include <system_error>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace aida::standalone::mcp::compat::handlers {

namespace {

using protocol::json;
using protocol::mcp_result_t;
using protocol::result_error_code_t;

constexpr std::array<std::string_view, k_survey_tool_count> k_survey_names{{
    "survey_binary",
}};

using validation_failure_t = std::optional<json>;

json parse_generated_json(std::string_view value, std::string_view field,
                          std::string_view tool_name) {
    try {
        return json::parse(value.begin(), value.end());
    } catch (const std::exception&) {
        throw std::runtime_error(
            "generated survey contract JSON is invalid for " + std::string(tool_name) +
            " field " + std::string(field));
    }
}

protocol::tool_effect_t protocol_effect(contract_effect_t effect) {
    switch (effect) {
    case contract_effect_t::workspace_read:
        return protocol::tool_effect_t::workspace_read;
    case contract_effect_t::workspace_checkpoint:
        return protocol::tool_effect_t::workspace_checkpoint;
    case contract_effect_t::workspace_overlay_mutation:
        return protocol::tool_effect_t::workspace_overlay_mutation;
    case contract_effect_t::debugger_read:
        return protocol::tool_effect_t::debugger_read;
    case contract_effect_t::debugger_control:
        return protocol::tool_effect_t::debugger_control;
    case contract_effect_t::debugger_write:
        return protocol::tool_effect_t::debugger_write;
    case contract_effect_t::isolated_python:
        return protocol::tool_effect_t::isolated_python;
    case contract_effect_t::registry_read:
        return protocol::tool_effect_t::registry_read;
    }
    throw std::runtime_error("generated survey contract has an unknown effect");
}

protocol::effect_lock_t protocol_lock(contract_lock_t lock) {
    switch (lock) {
    case contract_lock_t::workspace_shared:
        return protocol::effect_lock_t::workspace_shared;
    case contract_lock_t::workspace_checkpoint:
        return protocol::effect_lock_t::workspace_checkpoint;
    case contract_lock_t::workspace_overlay_transaction:
        return protocol::effect_lock_t::workspace_overlay_transaction;
    case contract_lock_t::debugger_lane:
        return protocol::effect_lock_t::debugger_lane;
    case contract_lock_t::python_worker:
        return protocol::effect_lock_t::python_worker;
    case contract_lock_t::registry_read:
        return protocol::effect_lock_t::registry_read;
    }
    throw std::runtime_error("generated survey contract has an unknown lock");
}

void validate_generated_descriptor(const contract_descriptor_t& descriptor) {
    constexpr std::string_view expected_adapter =
        "aida::standalone::mcp::compat::adapters::survey_binary";
    if (descriptor.name != "survey_binary" ||
        descriptor.adapter_symbol != expected_adapter ||
        !descriptor.archive_backed || !descriptor.target_dependent ||
        !descriptor.accepts_pid || !descriptor.accepts_bin_name ||
        !descriptor.read_only || descriptor.unsafe ||
        descriptor.effect != contract_effect_t::workspace_read ||
        descriptor.lock != contract_lock_t::workspace_shared) {
        throw std::runtime_error("generated survey_binary descriptor policy mismatch");
    }
}

protocol::tool_contract_t make_tool_contract(const contract_descriptor_t& descriptor) {
    protocol::tool_contract_t contract;
    contract.name.assign(descriptor.name.data(), descriptor.name.size());
    contract.description.assign(descriptor.description.data(), descriptor.description.size());
    contract.input_schema = parse_generated_json(
        descriptor.input_schema_json, "input_schema", descriptor.name);
    contract.output_schema = parse_generated_json(
        descriptor.output_schema_json, "output_schema", descriptor.name);
    contract.annotations = parse_generated_json(
        descriptor.annotations_json, "annotations", descriptor.name);
    contract.target_policy.requirement = protocol::target_requirement_t::optional;
    contract.target_policy.accepts_pid = descriptor.accepts_pid;
    contract.target_policy.accepts_bin_name = descriptor.accepts_bin_name;
    contract.effect_policy.effect = protocol_effect(descriptor.effect);
    contract.effect_policy.lock = protocol_lock(descriptor.lock);
    contract.effect_policy.read_only = descriptor.read_only;
    contract.effect_policy.unsafe = descriptor.unsafe;
    return contract;
}

bool valid_limits(const survey_handler_limits_t& limits) noexcept {
    return limits.max_request_bytes != 0 &&
        limits.max_request_bytes <= 1024U * 1024U &&
        limits.max_response_bytes != 0 &&
        limits.max_response_bytes <= 16U * 1024U * 1024U &&
        limits.max_selector_bytes != 0 && limits.max_selector_bytes <= 1024U &&
        limits.max_workspace_id_bytes != 0 && limits.max_workspace_id_bytes <= 4096U &&
        limits.max_target_source_path_bytes != 0 &&
        limits.max_target_source_path_bytes <= 128U * 1024U &&
        limits.max_digest_bytes != 0 && limits.max_digest_bytes <= 512U &&
        limits.max_detail_level_bytes != 0 && limits.max_detail_level_bytes <= 32U &&
        limits.max_static_items != 0 && limits.max_static_items <= 256U &&
        limits.max_collection_items != 0 && limits.max_collection_items <= 64U &&
        limits.max_live_items != 0 && limits.max_live_items <= 32U &&
        limits.max_text_bytes != 0 && limits.max_text_bytes <= 4096U &&
        limits.max_diagnostics != 0 && limits.max_diagnostics <= 128U &&
        limits.max_analysis_index_items != 0 &&
        limits.max_analysis_index_items <= 1024U * 1024U &&
        limits.max_analysis_scan_items != 0 &&
        limits.max_analysis_scan_items <= 4U * 1024U * 1024U &&
        limits.max_live_snapshot_bytes != 0 &&
        limits.max_live_snapshot_bytes <= 1024ULL * 1024ULL * 1024ULL &&
        limits.max_execution_time.count() > 0 &&
        limits.max_execution_time.count() <= 120000;
}

json invalid_value(std::string path, std::string reason, const json& actual) {
    return json{
        {"policy", "bounded_survey_handler"},
        {"field", std::move(path)},
        {"reason", std::move(reason)},
        {"actual", actual},
    };
}

json exceeded_value(std::string path, std::uint64_t maximum, std::uint64_t actual) {
    return json{
        {"policy", "bounded_survey_handler"},
        {"field", std::move(path)},
        {"reason", "maximum_exceeded"},
        {"maximum", maximum},
        {"actual", actual},
    };
}

std::optional<std::uint64_t> unsigned_integer(const json& value) noexcept {
    try {
        if (value.is_number_unsigned()) {
            return value.get<std::uint64_t>();
        }
        if (value.is_number_integer()) {
            const auto signed_value = value.get<std::int64_t>();
            if (signed_value >= 0) {
                return static_cast<std::uint64_t>(signed_value);
            }
        }
    } catch (const std::exception&) {
    }
    return std::nullopt;
}

validation_failure_t bounded_text(const json& value, std::string path,
                                  std::size_t maximum, bool allow_empty) {
    if (!value.is_string()) {
        return invalid_value(std::move(path), "string_required", value);
    }
    const auto& text = value.get_ref<const std::string&>();
    if (!allow_empty && text.empty()) {
        return invalid_value(std::move(path), "nonempty_string_required", value);
    }
    if (text.find('\0') != std::string::npos) {
        return invalid_value(std::move(path), "nul_forbidden", value);
    }
    if (text.size() > maximum) {
        return exceeded_value(
            std::move(path), static_cast<std::uint64_t>(maximum),
            static_cast<std::uint64_t>(text.size()));
    }
    return std::nullopt;
}

validation_failure_t validate_arguments(const json& arguments,
                                        const survey_handler_limits_t& limits) {
    const bool has_pid = arguments.contains("pid");
    const bool has_bin_name = arguments.contains("bin_name");
    if (has_pid && has_bin_name) {
        return invalid_value("target", "single_selector_required", json{
            {"pid", arguments.at("pid")},
            {"bin_name", arguments.at("bin_name")},
        });
    }
    if (has_pid) {
        const auto value = unsigned_integer(arguments.at("pid"));
        if (!value || *value == 0 ||
            *value > (std::numeric_limits<std::uint32_t>::max)()) {
            return invalid_value("pid", "valid_process_id_required", arguments.at("pid"));
        }
    }
    if (has_bin_name) {
        if (auto failure = bounded_text(
                arguments.at("bin_name"), "bin_name", limits.max_selector_bytes, false)) {
            return failure;
        }
    }
    if (const auto detail = arguments.find("detail_level"); detail != arguments.end()) {
        if (auto failure = bounded_text(
                *detail, "detail_level", limits.max_detail_level_bytes, false)) {
            return failure;
        }
        const auto& value = detail->get_ref<const std::string&>();
        if (value != "standard" && value != "minimal") {
            return invalid_value("detail_level", "unsupported_value", *detail);
        }
    }
    return std::nullopt;
}

target_selector_t target_selector(const json& arguments) {
    target_selector_t selector;
    if (const auto pid = arguments.find("pid"); pid != arguments.end()) {
        selector.pid = static_cast<std::uint32_t>(*unsigned_integer(*pid));
    }
    if (const auto bin_name = arguments.find("bin_name"); bin_name != arguments.end()) {
        selector.bin_name = bin_name->get<std::string>();
    }
    return selector;
}

std::chrono::milliseconds execution_timeout(
    const protocol::tool_contract_t& contract,
    std::chrono::milliseconds maximum) noexcept {
    const auto decorators = contract.annotations.find("decorators");
    if (decorators == contract.annotations.end() || !decorators->is_array()) {
        return maximum;
    }
    for (const auto& decorator : *decorators) {
        if (!decorator.is_object()) {
            continue;
        }
        const auto name = decorator.find("name");
        if (name == decorator.end() || !name->is_string() ||
            name->get_ref<const std::string&>() != "tool_timeout") {
            continue;
        }
        const auto args = decorator.find("args");
        if (args == decorator.end() || !args->is_array() || args->empty() ||
            !(*args)[0].is_number()) {
            continue;
        }
        try {
            const double seconds = (*args)[0].get<double>();
            if (!std::isfinite(seconds) || seconds <= 0.0 || seconds > 86400.0) {
                continue;
            }
            const auto generated = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::duration<double>(seconds));
            if (generated.count() > 0) {
                return (std::min)(generated, maximum);
            }
        } catch (const std::exception&) {
        }
    }
    return maximum;
}

result_error_code_t adapter_error_code(adapter_error_code_t code) noexcept {
    switch (code) {
    case adapter_error_code_t::invalid_request:
        return result_error_code_t::invalid_input;
    case adapter_error_code_t::target_resolution_failed:
        return result_error_code_t::target_policy_rejected;
    case adapter_error_code_t::operation_not_permitted:
    case adapter_error_code_t::effect_policy_failed:
        return result_error_code_t::effect_policy_rejected;
    case adapter_error_code_t::none:
    case adapter_error_code_t::contract_not_found:
    case adapter_error_code_t::effect_lock_busy:
    case adapter_error_code_t::backend_unavailable:
    case adapter_error_code_t::backend_rejected:
    case adapter_error_code_t::live_snapshot_denied:
    case adapter_error_code_t::live_snapshot_bounds:
    case adapter_error_code_t::live_snapshot_invalid:
        return result_error_code_t::handler_failed;
    }
    return result_error_code_t::handler_failed;
}

mcp_result_t lease_failure(const adapter_error_t& error) {
    return mcp_result_t::failure(
        adapter_error_code(error.code),
        "Survey generation lease acquisition failed.",
        json{
            {"phase", "survey_generation_lease"},
            {"adapter_code", std::string(error.stable_code)},
            {"expected", error.expected},
            {"actual", error.actual},
        });
}

class survey_diagnostics_t final {
public:
    explicit survey_diagnostics_t(std::size_t maximum) : maximum_(maximum) {}

    void add(std::string code, std::string section, std::string detail,
             std::optional<std::uint64_t> maximum = {},
             std::optional<std::uint64_t> actual = {}) {
        for (const auto& entry : entries_) {
            if (entry.at("code") == code && entry.at("section") == section) {
                return;
            }
        }
        if (entries_.size() >= maximum_) {
            ++dropped_;
            return;
        }
        json entry{
            {"code", std::move(code)},
            {"section", std::move(section)},
            {"detail", std::move(detail)},
        };
        if (maximum) {
            entry["maximum"] = *maximum;
        }
        if (actual) {
            entry["actual"] = *actual;
        }
        entries_.push_back(std::move(entry));
    }

    bool partial() const noexcept {
        return !entries_.empty() || dropped_ != 0;
    }

    json json_value() const {
        json result = entries_;
        if (dropped_ != 0) {
            result.push_back(json{
                {"code", "diagnostics_capped"},
                {"section", "diagnostics"},
                {"detail", "additional partial-state diagnostics were suppressed"},
                {"actual", dropped_},
            });
        }
        return result;
    }

    std::string note(std::uint64_t generation) const {
        if (!partial()) {
            return "Summary generated from immutable workspace generation " +
                std::to_string(generation) + ".";
        }
        std::string result = "Partial immutable-generation summary for generation " +
            std::to_string(generation) + ": ";
        bool first = true;
        for (const auto& entry : entries_) {
            if (!first) {
                result.append(", ");
            }
            first = false;
            result.append(entry.at("code").get_ref<const std::string&>());
            result.push_back('(');
            result.append(entry.at("section").get_ref<const std::string&>());
            result.push_back(')');
        }
        if (dropped_ != 0) {
            if (!first) {
                result.append(", ");
            }
            result.append("diagnostics_capped");
        }
        result.push_back('.');
        return result;
    }

private:
    std::size_t maximum_ = 0;
    std::vector<json> entries_;
    std::uint64_t dropped_ = 0;
};

class summary_interrupt_t final {
public:
    summary_interrupt_t(const protocol::cancellation_token_t& cancellation,
                        std::chrono::steady_clock::time_point deadline)
        : cancellation_(cancellation), deadline_(deadline) {}

    bool checkpoint() noexcept {
        ++counter_;
        return (counter_ & 0xFFU) != 0U || !stopped();
    }

    bool stopped() const noexcept {
        return cancellation_.cancelled() || std::chrono::steady_clock::now() >= deadline_;
    }

    bool cancelled() const noexcept {
        return cancellation_.cancelled();
    }

private:
    const protocol::cancellation_token_t& cancellation_;
    std::chrono::steady_clock::time_point deadline_;
    std::size_t counter_ = 0;
};

mcp_result_t interrupt_failure(const summary_interrupt_t& interrupt,
                               std::string_view phase) {
    if (interrupt.cancelled()) {
        return mcp_result_t::failure(
            result_error_code_t::cancelled,
            "Survey summary construction was cancelled.",
            json{{"phase", std::string(phase)}});
    }
    return mcp_result_t::failure(
        result_error_code_t::handler_failed,
        "Survey summary construction exceeded its deadline.",
        json{{"phase", std::string(phase)}, {"reason", "deadline_exceeded"}});
}

bool checked_add(std::uint64_t lhs, std::uint64_t rhs,
                 std::uint64_t& result) noexcept {
    if (rhs > (std::numeric_limits<std::uint64_t>::max)() - lhs) {
        return false;
    }
    result = lhs + rhs;
    return true;
}

std::string hex_value(std::uint64_t value) {
    std::array<char, 16> digits{};
    const auto converted = std::to_chars(
        digits.data(), digits.data() + digits.size(), value, 16);
    if (converted.ec != std::errc()) {
        return "0x0";
    }
    std::string result("0x");
    result.append(digits.data(), converted.ptr);
    return result;
}

bool ascii_equal(unsigned char lhs, unsigned char rhs) noexcept {
    const auto lower = [](unsigned char value) {
        return value >= static_cast<unsigned char>('A') &&
                value <= static_cast<unsigned char>('Z')
            ? static_cast<unsigned char>(value + ('a' - 'A'))
            : value;
    };
    return lower(lhs) == lower(rhs);
}

bool contains_any_ascii_case_insensitive(
    std::string_view value,
    std::initializer_list<std::string_view> needles,
    std::size_t maximum) noexcept {
    value = value.substr(0, (std::min)(value.size(), maximum));
    for (const auto needle : needles) {
        if (needle.empty() || needle.size() > value.size()) {
            continue;
        }
        for (std::size_t offset = 0; offset + needle.size() <= value.size(); ++offset) {
            bool match = true;
            for (std::size_t index = 0; index < needle.size(); ++index) {
                if (!ascii_equal(
                        static_cast<unsigned char>(value[offset + index]),
                        static_cast<unsigned char>(needle[index]))) {
                    match = false;
                    break;
                }
            }
            if (match) {
                return true;
            }
        }
    }
    return false;
}

bool starts_with_ascii_case_insensitive(
    std::string_view value, std::string_view prefix) noexcept {
    if (value.size() < prefix.size()) {
        return false;
    }
    for (std::size_t index = 0; index < prefix.size(); ++index) {
        if (!ascii_equal(
                static_cast<unsigned char>(value[index]),
                static_cast<unsigned char>(prefix[index]))) {
            return false;
        }
    }
    return true;
}

std::string bounded_string(const std::string& value, std::size_t maximum,
                           survey_diagnostics_t& diagnostics,
                           std::string_view section) {
    if (value.size() <= maximum) {
        return value;
    }
    std::size_t end = maximum;
    while (end > 0 && end < value.size() &&
           (static_cast<unsigned char>(value[end]) & 0xC0U) == 0x80U) {
        --end;
    }
    diagnostics.add(
        "text_truncated", std::string(section),
        "text exceeded the survey field byte cap",
        static_cast<std::uint64_t>(maximum),
        static_cast<std::uint64_t>(value.size()));
    return value.substr(0, end);
}

std::string architecture_name(aida::analysis::architecture_id_t architecture) {
    using aida::analysis::architecture_id_t;
    switch (architecture) {
    case architecture_id_t::x86:
        return "x86";
    case architecture_id_t::x86_64:
        return "x86_64";
    case architecture_id_t::arm:
        return "arm";
    case architecture_id_t::aarch64:
        return "aarch64";
    case architecture_id_t::mips:
        return "mips";
    case architecture_id_t::ppc:
        return "ppc";
    case architecture_id_t::ppc64:
        return "ppc64";
    case architecture_id_t::riscv:
        return "riscv";
    case architecture_id_t::jvm_bytecode:
        return "jvm";
    case architecture_id_t::arm64ec:
        return "arm64ec";
    case architecture_id_t::mips64:
        return "mips64";
    case architecture_id_t::riscv32:
        return "riscv32";
    case architecture_id_t::riscv64:
        return "riscv64";
    case architecture_id_t::dalvik_bytecode:
        return "dalvik";
    case architecture_id_t::unknown:
        return "unknown";
    }
    return "unknown";
}

std::string permissions_name(std::uint32_t permissions) {
    using namespace aida::analysis;
    std::string result;
    result.push_back((permissions & image_permission_read) != 0 ? 'r' : '-');
    result.push_back((permissions & image_permission_write) != 0 ? 'w' : '-');
    result.push_back((permissions & image_permission_execute) != 0 ? 'x' : '-');
    if ((permissions & image_permission_discardable) != 0) {
        result.push_back('d');
    }
    return result;
}

struct effective_caps_t final {
    std::size_t static_items = 0;
    std::size_t collection_items = 0;
};

effective_caps_t effective_caps(const survey_handler_limits_t& limits,
                                bool minimal, bool live) noexcept {
    effective_caps_t result;
    result.static_items = minimal
        ? (std::min)(limits.max_static_items, std::size_t{16})
        : limits.max_static_items;
    result.collection_items = minimal
        ? (std::min)(limits.max_collection_items, std::size_t{5})
        : limits.max_collection_items;
    if (live) {
        result.static_items = (std::min)(result.static_items, limits.max_live_items);
        result.collection_items = (std::min)(result.collection_items, limits.max_live_items);
    }
    return result;
}

template <typename value_t, typename compare_t>
void retain_bounded(std::vector<const value_t*>& retained,
                    const value_t& value,
                    std::size_t maximum,
                    compare_t compare) {
    const auto position = std::lower_bound(
        retained.begin(), retained.end(), &value,
        [&compare](const value_t* lhs, const value_t* rhs) {
            return compare(*lhs, *rhs);
        });
    if (retained.size() < maximum) {
        retained.insert(position, &value);
    } else if (position != retained.end()) {
        retained.insert(position, &value);
        retained.pop_back();
    }
}

validation_failure_t validate_lease(const survey_generation_lease_t& lease,
                                    const survey_handler_limits_t& limits) {
    if (!lease.owner) {
        return invalid_value("lease.owner", "local_lease_required", nullptr);
    }
    const auto validate_identity_text = [](const std::string& value,
                                           std::string path,
                                           std::size_t maximum,
                                           bool allow_empty) -> validation_failure_t {
        if (!allow_empty && value.empty()) {
            return invalid_value(std::move(path), "nonempty_string_required", value);
        }
        if (value.find('\0') != std::string::npos) {
            return invalid_value(std::move(path), "nul_forbidden", value);
        }
        if (value.size() > maximum) {
            return exceeded_value(
                std::move(path), static_cast<std::uint64_t>(maximum),
                static_cast<std::uint64_t>(value.size()));
        }
        return std::nullopt;
    };
    if (auto failure = validate_identity_text(
            lease.identity.workspace_id, "lease.workspace_id",
            limits.max_workspace_id_bytes, false)) {
        return failure;
    }
    if (auto failure = validate_identity_text(
            lease.identity.bin_name, "lease.bin_name",
            limits.max_selector_bytes, false)) {
        return failure;
    }
    if (auto failure = validate_identity_text(
            lease.identity.normalized_source_path, "lease.normalized_source_path",
            limits.max_target_source_path_bytes, false)) {
        return failure;
    }
    if (auto failure = validate_identity_text(
            lease.identity.sha256, "lease.sha256", limits.max_digest_bytes, true)) {
        return failure;
    }
    if (lease.identity.md5) {
        if (auto failure = validate_identity_text(
                *lease.identity.md5, "lease.md5", limits.max_digest_bytes, true)) {
            return failure;
        }
    }
    if (lease.identity.generation == 0) {
        return invalid_value("lease.generation", "immutable_generation_required", 0);
    }
    if (lease.identity.pid && *lease.identity.pid == 0) {
        return invalid_value("lease.pid", "valid_process_id_required", 0);
    }
    if (lease.analysis) {
        if (!lease.image) {
            return invalid_value(
                "lease.image", "analysis_image_lease_required", nullptr);
        }
        if (lease.analysis->generation != lease.identity.generation) {
            return invalid_value(
                "lease.analysis.generation", "immutable_generation_mismatch",
                json{{"expected", lease.identity.generation},
                     {"actual", lease.analysis->generation}});
        }
        if (lease.analysis->analysis_revision != lease.identity.analysis_revision) {
            return invalid_value(
                "lease.analysis.analysis_revision", "immutable_revision_mismatch",
                json{{"expected", lease.identity.analysis_revision},
                     {"actual", lease.analysis->analysis_revision}});
        }
        if (lease.analysis->overlay_revision != lease.identity.overlay_revision) {
            return invalid_value(
                "lease.analysis.overlay_revision", "immutable_overlay_mismatch",
                json{{"expected", lease.identity.overlay_revision},
                     {"actual", lease.analysis->overlay_revision}});
        }
    }
    return std::nullopt;
}

const aida::analysis::workspace_image_t* leased_image(
    const survey_generation_lease_t& lease) noexcept {
    return lease.image.get();
}

json lease_metadata(const survey_generation_lease_t& lease,
                    const survey_handler_limits_t& limits,
                    const effective_caps_t& caps,
                    std::string_view detail_level,
                    const survey_diagnostics_t& diagnostics) {
    return json{
        {"workspace_id", lease.identity.workspace_id},
        {"pid", lease.identity.pid ? json(*lease.identity.pid) : json(nullptr)},
        {"bin_name", lease.identity.bin_name},
        {"generation", lease.identity.generation},
        {"analysis_revision", lease.identity.analysis_revision},
        {"overlay_revision", lease.identity.overlay_revision},
        {"target_kind", lease.identity.live ? "live_snapshot" : "static_file"},
        {"generation_lease", "local_immutable"},
        {"detail_level", std::string(detail_level)},
        {"partial", diagnostics.partial()},
        {"diagnostics", diagnostics.json_value()},
        {"caps", json{
            {"static_items", caps.static_items},
            {"collection_items", caps.collection_items},
            {"live_items", limits.max_live_items},
            {"text_bytes", limits.max_text_bytes},
            {"target_source_path_bytes", limits.max_target_source_path_bytes},
            {"analysis_index_items", limits.max_analysis_index_items},
            {"analysis_scan_items", limits.max_analysis_scan_items},
            {"live_snapshot_bytes", limits.max_live_snapshot_bytes},
            {"response_bytes", limits.max_response_bytes},
        }},
    };
}

void append_metadata(json& output,
                     const survey_generation_lease_t& lease,
                     const aida::analysis::workspace_image_t& image,
                     const survey_handler_limits_t& limits,
                     survey_diagnostics_t& diagnostics) {
    std::string sha256 = lease.identity.sha256;
    if (sha256.empty() && !image.provider_content_hash.empty()) {
        sha256 = image.provider_content_hash.to_hex();
    }
    if (sha256.empty()) {
        diagnostics.add(
            "sha256_unavailable", "metadata",
            "the leased generation has no content SHA-256");
    }
    if (!lease.identity.md5) {
        diagnostics.add(
            "md5_unavailable", "metadata",
            "MD5 was not present in the immutable metadata generation");
    }
    output["metadata"] = json{
        {"path", bounded_string(
            lease.identity.normalized_source_path, limits.max_text_bytes,
            diagnostics, "metadata.path")},
        {"module", bounded_string(
            lease.identity.bin_name, limits.max_text_bytes,
            diagnostics, "metadata.module")},
        {"arch", architecture_name(image.architecture)},
        {"base_address", hex_value(image.image_base)},
        {"image_size", hex_value(image.image_size)},
        {"md5", bounded_string(
            lease.identity.md5 ? *lease.identity.md5 : std::string(),
            limits.max_text_bytes, diagnostics, "metadata.md5")},
        {"sha256", bounded_string(
            sha256, limits.max_text_bytes, diagnostics, "metadata.sha256")},
    };
}

bool append_segments(json& output,
                     const aida::analysis::workspace_image_t& image,
                     const effective_caps_t& caps,
                     const survey_handler_limits_t& limits,
                     survey_diagnostics_t& diagnostics,
                     summary_interrupt_t& interrupt) {
    using aida::analysis::image_segment_t;
    std::vector<const image_segment_t*> retained;
    retained.reserve(caps.static_items);
    const auto compare = [](const image_segment_t& lhs, const image_segment_t& rhs) {
        return std::tie(lhs.virtual_address, lhs.index) <
            std::tie(rhs.virtual_address, rhs.index);
    };
    const std::size_t scan_count = (std::min)(
        image.segments.size(), limits.max_analysis_scan_items);
    for (std::size_t index = 0; index < scan_count; ++index) {
        if (!interrupt.checkpoint()) {
            return false;
        }
        retain_bounded(retained, image.segments[index], caps.static_items, compare);
    }
    if (image.segments.size() > scan_count) {
        diagnostics.add(
            "source_scan_cap", "segments",
            "segment source scan was capped",
            static_cast<std::uint64_t>(limits.max_analysis_scan_items),
            static_cast<std::uint64_t>(image.segments.size()));
    }
    if (image.segments.size() > retained.size()) {
        diagnostics.add(
            "static_cap_applied", "segments",
            "segment layout was capped",
            static_cast<std::uint64_t>(caps.static_items),
            static_cast<std::uint64_t>(image.segments.size()));
    }
    json segments = json::array();
    for (const auto* segment : retained) {
        std::uint64_t start = 0;
        std::uint64_t end = 0;
        if (!checked_add(image.image_base, segment->virtual_address, start) ||
            !checked_add(start, segment->virtual_size, end)) {
            diagnostics.add(
                "invalid_range", "segments",
                "a segment address range overflowed");
            continue;
        }
        segments.push_back(json{
            {"name", bounded_string(
                segment->name, limits.max_text_bytes, diagnostics, "segments.name")},
            {"start", hex_value(start)},
            {"end", hex_value(end)},
            {"size", hex_value(segment->virtual_size)},
            {"permissions", permissions_name(segment->permissions)},
        });
    }
    output["segments"] = std::move(segments);
    return true;
}

struct entry_candidate_t final {
    const aida::analysis::image_entry_point_t* entry = nullptr;
    std::size_t ordinal = 0;
};

void retain_entry(std::vector<entry_candidate_t>& retained,
                  entry_candidate_t candidate,
    std::size_t maximum) {
    const auto compare = [](const entry_candidate_t& lhs, const entry_candidate_t& rhs) {
        return std::tie(lhs.entry->address.value, lhs.ordinal) <
            std::tie(rhs.entry->address.value, rhs.ordinal);
    };
    const auto position = std::lower_bound(retained.begin(), retained.end(), candidate, compare);
    if (retained.size() < maximum) {
        retained.insert(position, candidate);
    } else if (position != retained.end()) {
        retained.insert(position, candidate);
        retained.pop_back();
    }
}

bool append_entrypoints(json& output,
                        const aida::analysis::workspace_image_t& image,
                        const effective_caps_t& caps,
                        const survey_handler_limits_t& limits,
                        survey_diagnostics_t& diagnostics,
                        summary_interrupt_t& interrupt) {
    std::vector<entry_candidate_t> retained;
    retained.reserve(caps.static_items);
    const std::size_t entry_scan_count = (std::min)(
        image.entry_points.size(), limits.max_analysis_scan_items);
    for (std::size_t index = 0; index < entry_scan_count; ++index) {
        if (!interrupt.checkpoint()) {
            return false;
        }
        retain_entry(retained, entry_candidate_t{&image.entry_points[index], index},
                     caps.static_items);
    }
    if (image.entry_points.size() > entry_scan_count) {
        diagnostics.add(
            "source_scan_cap", "entrypoints",
            "entry point source scan was capped",
            static_cast<std::uint64_t>(limits.max_analysis_scan_items),
            static_cast<std::uint64_t>(image.entry_points.size()));
    }
    if (image.entry_points.size() > retained.size()) {
        diagnostics.add(
            "static_cap_applied", "entrypoints",
            "entry points were capped",
            static_cast<std::uint64_t>(caps.static_items),
            static_cast<std::uint64_t>(image.entry_points.size()));
    }
    std::unordered_map<std::uint64_t, const aida::analysis::image_symbol_t*> entry_symbols;
    entry_symbols.reserve(retained.size());
    for (const auto& candidate : retained) {
        entry_symbols.try_emplace(candidate.entry->address.value, nullptr);
    }
    const std::size_t symbol_scan_count = (std::min)(
        image.symbols.size(), limits.max_analysis_scan_items);
    for (std::size_t index = 0; index < symbol_scan_count; ++index) {
        if (!interrupt.checkpoint()) {
            return false;
        }
        const auto& symbol = image.symbols[index];
        if (symbol.name.empty()) {
            continue;
        }
        const auto selected = entry_symbols.find(symbol.address.value);
        if (selected != entry_symbols.end() && selected->second == nullptr) {
            selected->second = &symbol;
        }
    }
    if (image.symbols.size() > symbol_scan_count) {
        diagnostics.add(
            "source_scan_cap", "entrypoint_symbols",
            "entry point symbol source scan was capped",
            static_cast<std::uint64_t>(limits.max_analysis_scan_items),
            static_cast<std::uint64_t>(image.symbols.size()));
    }
    json entrypoints = json::array();
    for (const auto& candidate : retained) {
        const auto selected = entry_symbols.find(candidate.entry->address.value);
        const auto* symbol = selected == entry_symbols.end() ? nullptr : selected->second;
        std::string name;
        if (symbol != nullptr) {
            name = bounded_string(
                symbol->name, limits.max_text_bytes, diagnostics, "entrypoints.name");
        } else if (!candidate.entry->provenance.empty()) {
            name = bounded_string(
                candidate.entry->provenance, limits.max_text_bytes,
                diagnostics, "entrypoints.name");
        } else {
            name = "entry_" + std::to_string(candidate.ordinal);
        }
        entrypoints.push_back(json{
            {"addr", hex_value(candidate.entry->address.value)},
            {"name", std::move(name)},
            {"ordinal", candidate.ordinal},
        });
    }
    output["entrypoints"] = std::move(entrypoints);
    return true;
}

enum class import_category_t : std::size_t {
    crypto = 0,
    network,
    file_io,
    process,
    registry,
    other,
    count,
};

constexpr std::array<std::string_view,
    static_cast<std::size_t>(import_category_t::count)> k_import_categories{{
    "crypto", "network", "file_io", "process", "registry", "other",
}};

import_category_t import_category(const aida::analysis::image_import_t& item,
                                  std::size_t maximum_text_scan) {
    const auto contains = [&item, maximum_text_scan](
                              std::initializer_list<std::string_view> needles) {
        return contains_any_ascii_case_insensitive(
                   item.library, needles, maximum_text_scan) ||
            (item.name && contains_any_ascii_case_insensitive(
                *item.name, needles, maximum_text_scan));
    };
    if (contains({
            "crypto", "bcrypt", "crypt32", "openssl", "libssl", "libcrypto",
            "sodium", "sha", "aes", "tls"})) {
        return import_category_t::crypto;
    }
    if (contains({
            "socket", "ws2_", "winhttp", "wininet", "internet", "curl",
            "connect", "accept", "recv", "send", "dns"})) {
        return import_category_t::network;
    }
    if (contains({
            "regopen", "regquery", "regset", "regdelete", "registry"})) {
        return import_category_t::registry;
    }
    if (contains({
            "createfile", "readfile", "writefile", "deletefile", "fopen",
            "fread", "fwrite", "filesystem", "directory"})) {
        return import_category_t::file_io;
    }
    if (contains({
            "process", "thread", "virtualalloc", "virtualprotect", "loadlibrary",
            "getprocaddress", "createremotethread", "openprocess"})) {
        return import_category_t::process;
    }
    return import_category_t::other;
}

std::string bounded_import_name(const aida::analysis::image_import_t& item,
                                const survey_handler_limits_t& limits,
                                survey_diagnostics_t& diagnostics) {
    if (item.name && !item.name->empty()) {
        return bounded_string(
            *item.name, limits.max_text_bytes, diagnostics, "imports.name");
    }
    if (item.ordinal) {
        return "ordinal_" + std::to_string(*item.ordinal);
    }
    return "unnamed_import";
}

bool append_imports(json& output,
                    const aida::analysis::workspace_image_t& image,
                    const effective_caps_t& caps,
                    const survey_handler_limits_t& limits,
                    survey_diagnostics_t& diagnostics,
                    summary_interrupt_t& interrupt) {
    using aida::analysis::image_import_t;
    constexpr std::size_t category_count =
        static_cast<std::size_t>(import_category_t::count);
    std::array<std::vector<const image_import_t*>, category_count> retained;
    std::array<std::size_t, category_count> source_counts{};
    for (auto& category : retained) {
        category.reserve(caps.collection_items);
    }
    const auto compare = [](const image_import_t& lhs, const image_import_t& rhs) {
        return std::tie(lhs.address.value, lhs.lookup_address.value, lhs.ordinal, lhs.delayed) <
            std::tie(rhs.address.value, rhs.lookup_address.value, rhs.ordinal, rhs.delayed);
    };
    const std::size_t scan_count = (std::min)(
        image.imports.size(), limits.max_analysis_scan_items);
    for (std::size_t index = 0; index < scan_count; ++index) {
        if (!interrupt.checkpoint()) {
            return false;
        }
        const auto& item = image.imports[index];
        if (item.library.size() > limits.max_text_bytes ||
            (item.name && item.name->size() > limits.max_text_bytes)) {
            diagnostics.add(
                "text_scan_cap", "imports",
                "import classification text exceeded the bounded scan window",
                static_cast<std::uint64_t>(limits.max_text_bytes),
                static_cast<std::uint64_t>((std::max)(
                    item.library.size(), item.name ? item.name->size() : std::size_t{0})));
        }
        const auto category = static_cast<std::size_t>(
            import_category(item, limits.max_text_bytes));
        ++source_counts[category];
        retain_bounded(retained[category], item, caps.collection_items, compare);
    }
    if (image.imports.size() > scan_count) {
        diagnostics.add(
            "source_scan_cap", "imports",
            "import source scan was capped",
            static_cast<std::uint64_t>(limits.max_analysis_scan_items),
            static_cast<std::uint64_t>(image.imports.size()));
    }
    json categories = json::object();
    for (std::size_t category = 0; category < category_count; ++category) {
        if (source_counts[category] > retained[category].size()) {
            diagnostics.add(
                "collection_cap_applied",
                "imports." + std::string(k_import_categories[category]),
                "import category was capped",
                static_cast<std::uint64_t>(caps.collection_items),
                static_cast<std::uint64_t>(source_counts[category]));
        }
        json values = json::array();
        for (const auto* item : retained[category]) {
            values.push_back(json{
                {"addr", hex_value(item->address.value)},
                {"name", bounded_import_name(*item, limits, diagnostics)},
                {"module", bounded_string(
                    item->library, limits.max_text_bytes,
                    diagnostics, "imports.module")},
            });
        }
        categories[std::string(k_import_categories[category])] = std::move(values);
    }
    output["imports_by_category"] = std::move(categories);
    return true;
}

struct call_pair_t final {
    std::size_t source = 0;
    std::size_t target = 0;

    bool operator==(const call_pair_t& other) const noexcept {
        return source == other.source && target == other.target;
    }
};

struct call_pair_hash_t final {
    std::size_t operator()(const call_pair_t& value) const noexcept {
        std::size_t hash = value.source;
        hash ^= value.target + 0x9e3779b9U + (hash << 6U) + (hash >> 2U);
        return hash;
    }
};

struct analysis_index_t final {
    std::unordered_map<aida::analysis::entity_id_t,
                       const aida::analysis::symbol_record_t*> symbols_by_id;
    std::unordered_map<std::uint64_t,
                       const aida::analysis::image_symbol_t*> image_symbols_by_address;
    std::unordered_map<std::uint64_t, std::size_t> functions_by_start;
    std::unordered_map<std::uint64_t, std::size_t> strings_by_address;
    std::vector<std::size_t> functions_by_address;
    std::vector<std::uint64_t> function_xrefs;
    std::vector<std::uint64_t> string_xrefs;
    std::vector<std::uint64_t> incoming_calls;
    std::vector<std::uint64_t> outgoing_calls;
    std::uint64_t call_edges = 0;
};

bool analysis_within_index_caps(const aida::analysis::analysis_snapshot_t& analysis,
                                const aida::analysis::workspace_image_t& image,
                                const survey_handler_limits_t& limits,
                                survey_diagnostics_t& diagnostics) {
    const std::array<std::pair<std::string_view, std::size_t>, 4> indexed{{
        {"functions", analysis.functions.size()},
        {"strings", analysis.strings.size()},
        {"symbols", analysis.symbols.size()},
        {"image_symbols", image.symbols.size()},
    }};
    bool within = true;
    for (const auto& item : indexed) {
        if (item.second > limits.max_analysis_index_items) {
            diagnostics.add(
                "analysis_index_cap", std::string(item.first),
                "analysis collection exceeds the bounded index quota",
                static_cast<std::uint64_t>(limits.max_analysis_index_items),
                static_cast<std::uint64_t>(item.second));
            within = false;
        }
    }
    const std::array<std::pair<std::string_view, std::size_t>, 2> scanned{{
        {"xrefs", analysis.xrefs.size()},
        {"edges", analysis.edges.size()},
    }};
    for (const auto& item : scanned) {
        if (item.second > limits.max_analysis_scan_items) {
            diagnostics.add(
                "analysis_scan_cap", std::string(item.first),
                "analysis collection exceeds the bounded scan quota",
                static_cast<std::uint64_t>(limits.max_analysis_scan_items),
                static_cast<std::uint64_t>(item.second));
            within = false;
        }
    }
    return within;
}

std::optional<std::size_t> containing_function(
    const aida::analysis::analysis_snapshot_t& analysis,
    const analysis_index_t& index,
    std::uint64_t address) noexcept {
    const auto upper = std::upper_bound(
        index.functions_by_address.begin(), index.functions_by_address.end(), address,
        [&analysis](std::uint64_t value, std::size_t function_index) {
            return value < analysis.functions[function_index].start.value;
        });
    if (upper == index.functions_by_address.begin()) {
        return std::nullopt;
    }
    const std::size_t candidate = *std::prev(upper);
    const auto& function = analysis.functions[candidate];
    if (address < function.start.value || address >= function.end.value) {
        return std::nullopt;
    }
    return candidate;
}

bool build_analysis_index(const aida::analysis::analysis_snapshot_t& analysis,
                          const aida::analysis::workspace_image_t& image,
                          analysis_index_t& index,
                          summary_interrupt_t& interrupt) {
    index.symbols_by_id.reserve(analysis.symbols.size());
    for (const auto& symbol : analysis.symbols) {
        if (!interrupt.checkpoint()) {
            return false;
        }
        index.symbols_by_id.emplace(symbol.id, &symbol);
    }
    index.image_symbols_by_address.reserve(image.symbols.size());
    for (const auto& symbol : image.symbols) {
        if (!interrupt.checkpoint()) {
            return false;
        }
        if (!symbol.name.empty()) {
            index.image_symbols_by_address.emplace(symbol.address.value, &symbol);
        }
    }
    index.functions_by_start.reserve(analysis.functions.size());
    index.functions_by_address.resize(analysis.functions.size());
    std::iota(index.functions_by_address.begin(), index.functions_by_address.end(), 0U);
    for (std::size_t i = 0; i < analysis.functions.size(); ++i) {
        index.functions_by_start.emplace(analysis.functions[i].start.value, i);
    }
    std::sort(
        index.functions_by_address.begin(), index.functions_by_address.end(),
        [&analysis](std::size_t lhs, std::size_t rhs) {
            return std::tie(analysis.functions[lhs].start.value, analysis.functions[lhs].id) <
                std::tie(analysis.functions[rhs].start.value, analysis.functions[rhs].id);
        });
    index.strings_by_address.reserve(analysis.strings.size());
    for (std::size_t i = 0; i < analysis.strings.size(); ++i) {
        index.strings_by_address.emplace(analysis.strings[i].address.value, i);
    }
    index.function_xrefs.assign(analysis.functions.size(), 0);
    index.string_xrefs.assign(analysis.strings.size(), 0);
    index.incoming_calls.assign(analysis.functions.size(), 0);
    index.outgoing_calls.assign(analysis.functions.size(), 0);
    for (const auto& xref : analysis.xrefs) {
        if (!interrupt.checkpoint()) {
            return false;
        }
        if (const auto function = index.functions_by_start.find(xref.target.value);
            function != index.functions_by_start.end()) {
            ++index.function_xrefs[function->second];
        }
        if (const auto string = index.strings_by_address.find(xref.target.value);
            string != index.strings_by_address.end()) {
            ++index.string_xrefs[string->second];
        }
    }
    std::unordered_set<call_pair_t, call_pair_hash_t> unique_calls;
    unique_calls.reserve(analysis.edges.size());
    for (const auto& edge : analysis.edges) {
        if (!interrupt.checkpoint()) {
            return false;
        }
        if (edge.kind != aida::analysis::edge_kind_t::call &&
            edge.kind != aida::analysis::edge_kind_t::tail_call) {
            continue;
        }
        const auto source = containing_function(analysis, index, edge.source.value);
        const auto target = index.functions_by_start.find(edge.target.value);
        if (!source || target == index.functions_by_start.end()) {
            continue;
        }
        const call_pair_t pair{*source, target->second};
        if (unique_calls.insert(pair).second) {
            ++index.outgoing_calls[pair.source];
            ++index.incoming_calls[pair.target];
        }
    }
    index.call_edges = static_cast<std::uint64_t>(unique_calls.size());
    return true;
}

const aida::analysis::symbol_record_t* function_symbol(
    const aida::analysis::function_record_t& function,
    const analysis_index_t& index) noexcept {
    if (!function.symbol_id) {
        return nullptr;
    }
    const auto symbol = index.symbols_by_id.find(*function.symbol_id);
    return symbol == index.symbols_by_id.end() ? nullptr : symbol->second;
}

const std::string* published_function_name(
    const aida::analysis::function_record_t& function,
    const analysis_index_t& index) noexcept {
    if (const auto* symbol = function_symbol(function, index);
        symbol != nullptr && !symbol->name.empty()) {
        return &symbol->name;
    }
    if (const auto symbol = index.image_symbols_by_address.find(function.start.value);
        symbol != index.image_symbols_by_address.end() && !symbol->second->name.empty()) {
        return &symbol->second->name;
    }
    return nullptr;
}

std::string bounded_function_name(
    const aida::analysis::function_record_t& function,
    const analysis_index_t& index,
    const survey_handler_limits_t& limits,
    survey_diagnostics_t& diagnostics,
    std::string_view section) {
    if (const auto* name = published_function_name(function, index)) {
        return bounded_string(*name, limits.max_text_bytes, diagnostics, section);
    }
    std::string generated = hex_value(function.start.value);
    generated.replace(0, 2, "sub_");
    return generated;
}

bool generated_name(std::string_view name) {
    return starts_with_ascii_case_insensitive(name, "sub_") ||
        starts_with_ascii_case_insensitive(name, "loc_") ||
        starts_with_ascii_case_insensitive(name, "fun_") ||
        starts_with_ascii_case_insensitive(name, "func_");
}

bool library_function(const aida::analysis::function_record_t& function,
                      const analysis_index_t& index) noexcept {
    if (const auto* symbol = function_symbol(function, index);
        symbol != nullptr && symbol->kind == aida::analysis::symbol_kind_t::import_symbol) {
        return true;
    }
    const auto symbol = index.image_symbols_by_address.find(function.start.value);
    return symbol != index.image_symbols_by_address.end() &&
        (symbol->second->kind == aida::analysis::image_symbol_kind_t::import_symbol ||
         symbol->second->binding == aida::analysis::image_symbol_binding_t::external);
}

std::string function_type(const aida::analysis::function_record_t& function,
                          std::uint64_t callees) {
    if (function.thunk) {
        return "thunk";
    }
    if (callees == 0) {
        return "leaf";
    }
    if (callees == 1 && function.block_count <= 3) {
        return "wrapper";
    }
    if (callees >= 8) {
        return "dispatcher";
    }
    return "complex";
}

template <typename compare_t>
void retain_index(std::vector<std::size_t>& retained,
                  std::size_t candidate,
                  std::size_t maximum,
                  compare_t compare) {
    const auto position = std::lower_bound(
        retained.begin(), retained.end(), candidate, compare);
    if (retained.size() < maximum) {
        retained.insert(position, candidate);
    } else if (position != retained.end()) {
        retained.insert(position, candidate);
        retained.pop_back();
    }
}

bool append_analysis(json& output,
                     const aida::analysis::analysis_snapshot_t& analysis,
                     const aida::analysis::workspace_image_t& image,
                     const analysis_index_t& index,
                     const effective_caps_t& caps,
                     const survey_handler_limits_t& limits,
                     survey_diagnostics_t& diagnostics,
                     summary_interrupt_t& interrupt) {
    std::uint64_t named_functions = 0;
    std::uint64_t library_functions = 0;
    for (const auto& function : analysis.functions) {
        if (!interrupt.checkpoint()) {
            return false;
        }
        const auto* name = published_function_name(function, index);
        if (name != nullptr && !generated_name(*name)) {
            ++named_functions;
        }
        if (library_function(function, index)) {
            ++library_functions;
        }
    }
    const std::uint64_t total_functions =
        static_cast<std::uint64_t>(analysis.functions.size());
    const std::uint64_t unnamed_functions =
        total_functions >= named_functions ? total_functions - named_functions : 0;
    output["statistics"] = json{
        {"total_functions", total_functions},
        {"named_functions", named_functions},
        {"library_functions", library_functions},
        {"unnamed_functions", unnamed_functions},
        {"total_strings", static_cast<std::uint64_t>(analysis.strings.size())},
        {"total_segments", static_cast<std::uint64_t>(image.segments.size())},
    };

    std::vector<std::size_t> interesting_functions;
    interesting_functions.reserve(caps.collection_items);
    const auto function_compare = [&analysis, &index](std::size_t lhs, std::size_t rhs) {
        if (index.function_xrefs[lhs] != index.function_xrefs[rhs]) {
            return index.function_xrefs[lhs] > index.function_xrefs[rhs];
        }
        return std::tie(analysis.functions[lhs].start.value, analysis.functions[lhs].id) <
            std::tie(analysis.functions[rhs].start.value, analysis.functions[rhs].id);
    };
    for (std::size_t i = 0; i < analysis.functions.size(); ++i) {
        if (!interrupt.checkpoint()) {
            return false;
        }
        retain_index(interesting_functions, i, caps.collection_items, function_compare);
    }
    if (analysis.functions.size() > interesting_functions.size()) {
        diagnostics.add(
            "collection_cap_applied", "interesting_functions",
            "ranked functions were capped",
            static_cast<std::uint64_t>(caps.collection_items),
            static_cast<std::uint64_t>(analysis.functions.size()));
    }
    json function_output = json::array();
    for (const auto i : interesting_functions) {
        const auto& function = analysis.functions[i];
        const std::uint64_t size = function.end.value >= function.start.value
            ? function.end.value - function.start.value : 0;
        if (function.end.value < function.start.value) {
            diagnostics.add(
                "invalid_range", "interesting_functions",
                "a function range is inverted");
        }
        function_output.push_back(json{
            {"addr", hex_value(function.start.value)},
            {"name", bounded_function_name(
                function, index, limits, diagnostics,
                "interesting_functions.name")},
            {"size", size},
            {"xref_count", index.function_xrefs[i]},
            {"callee_count", index.outgoing_calls[i]},
            {"type", function_type(function, index.outgoing_calls[i])},
        });
    }
    output["interesting_functions"] = std::move(function_output);

    std::vector<std::size_t> interesting_strings;
    interesting_strings.reserve(caps.collection_items);
    const auto string_compare = [&analysis, &index](std::size_t lhs, std::size_t rhs) {
        if (index.string_xrefs[lhs] != index.string_xrefs[rhs]) {
            return index.string_xrefs[lhs] > index.string_xrefs[rhs];
        }
        return std::tie(analysis.strings[lhs].address.value, analysis.strings[lhs].id) <
            std::tie(analysis.strings[rhs].address.value, analysis.strings[rhs].id);
    };
    for (std::size_t i = 0; i < analysis.strings.size(); ++i) {
        if (!interrupt.checkpoint()) {
            return false;
        }
        retain_index(interesting_strings, i, caps.collection_items, string_compare);
    }
    if (analysis.strings.size() > interesting_strings.size()) {
        diagnostics.add(
            "collection_cap_applied", "interesting_strings",
            "ranked strings were capped",
            static_cast<std::uint64_t>(caps.collection_items),
            static_cast<std::uint64_t>(analysis.strings.size()));
    }
    json string_output = json::array();
    for (const auto i : interesting_strings) {
        const auto& string = analysis.strings[i];
        string_output.push_back(json{
            {"addr", hex_value(string.address.value)},
            {"string", bounded_string(
                string.value, limits.max_text_bytes,
                diagnostics, "interesting_strings.string")},
            {"xref_count", index.string_xrefs[i]},
        });
    }
    output["interesting_strings"] = std::move(string_output);

    std::vector<std::size_t> roots;
    roots.reserve(caps.collection_items);
    std::uint64_t leaves = 0;
    const auto root_compare = [&analysis](std::size_t lhs, std::size_t rhs) {
        return std::tie(analysis.functions[lhs].start.value, analysis.functions[lhs].id) <
            std::tie(analysis.functions[rhs].start.value, analysis.functions[rhs].id);
    };
    std::size_t root_count = 0;
    for (std::size_t i = 0; i < analysis.functions.size(); ++i) {
        if (!interrupt.checkpoint()) {
            return false;
        }
        if (index.outgoing_calls[i] == 0) {
            ++leaves;
        }
        if (index.incoming_calls[i] == 0) {
            ++root_count;
            retain_index(roots, i, caps.collection_items, root_compare);
        }
    }
    if (root_count > roots.size()) {
        diagnostics.add(
            "collection_cap_applied", "call_graph.root_functions",
            "call graph roots were capped",
            static_cast<std::uint64_t>(caps.collection_items),
            static_cast<std::uint64_t>(root_count));
    }
    json root_names = json::array();
    for (const auto i : roots) {
        root_names.push_back(bounded_function_name(
            analysis.functions[i], index, limits, diagnostics,
            "call_graph.root_functions"));
    }
    output["call_graph_summary"] = json{
        {"total_edges", index.call_edges},
        {"max_depth_estimate", nullptr},
        {"root_functions", std::move(root_names)},
        {"leaf_functions_count", leaves},
    };
    return true;
}

}

const std::array<std::string_view, k_survey_tool_count>& survey_tool_names() noexcept {
    return k_survey_names;
}

survey_handlers_t::survey_handlers_t(survey_generation_acquire_t acquire_generation,
                                     protocol::schema_runtime_t& schemas,
                                     survey_handler_limits_t limits)
    : acquire_generation_(std::move(acquire_generation)),
      schemas_(schemas),
      limits_(std::move(limits)) {
    if (!acquire_generation_) {
        throw std::invalid_argument("survey generation lease acquisition must not be null");
    }
    if (!valid_limits(limits_)) {
        throw std::invalid_argument("survey handler limits are invalid or weaken pinned maxima");
    }
    const auto* descriptor = aida::standalone::mcp::compat::find_contract("survey_binary");
    if (descriptor == nullptr) {
        throw std::runtime_error("generated survey_binary descriptor is missing");
    }
    validate_generated_descriptor(*descriptor);
    contracts_[0] = make_tool_contract(*descriptor);
    const auto validation = protocol::validate_tool_contract(contracts_[0], schemas_);
    if (!validation.valid) {
        throw std::runtime_error(
            "generated survey contract validation failed: " + validation.reason);
    }
}

std::size_t survey_handlers_t::size() const noexcept {
    return contracts_.size();
}

const protocol::tool_contract_t& survey_handlers_t::contract_at(std::size_t index) const {
    return contracts_.at(index);
}

const protocol::tool_contract_t* survey_handlers_t::find(std::string_view name) const noexcept {
    const auto found = std::find_if(
        contracts_.begin(), contracts_.end(),
        [name](const protocol::tool_contract_t& contract) { return contract.name == name; });
    return found == contracts_.end() ? nullptr : &*found;
}

const survey_handler_limits_t& survey_handlers_t::limits() const noexcept {
    return limits_;
}

protocol::mcp_result_t survey_handlers_t::invoke(
    std::string_view name, const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation,
    const protocol::json& aida_metadata) const {
    if (!aida_metadata.is_object()) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::internal_error,
            "Survey tool provenance metadata must be a JSON object.",
            protocol::json{{"field", "aida_metadata"}});
    }
    const auto found = std::find_if(
        contracts_.begin(), contracts_.end(),
        [name](const protocol::tool_contract_t& contract) { return contract.name == name; });
    if (found == contracts_.end()) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::invalid_contract,
            "Survey tool is not registered in the pinned contract group.",
            protocol::json{{"tool", std::string(name)}},
            aida_metadata);
    }
    const std::size_t index = static_cast<std::size_t>(std::distance(contracts_.begin(), found));
    return protocol::invoke_tool_contract(
        *found,
        arguments,
        [this, index](const protocol::json& validated_arguments,
                       const protocol::cancellation_token_t& token) {
            return dispatch(index, validated_arguments, token);
        },
        schemas_,
        cancellation,
        aida_metadata);
}

protocol::mcp_result_t survey_handlers_t::dispatch(
    std::size_t index, const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation) const {
    const auto name = k_survey_names.at(index);
    const auto& contract = contracts_.at(index);
    if (cancellation.cancelled()) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::cancelled,
            "Survey tool invocation was cancelled before lease acquisition.",
            protocol::json{{"phase", "survey_pre_lease"}});
    }

    std::string serialized_arguments;
    try {
        serialized_arguments = arguments.dump();
    } catch (const std::exception&) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::invalid_input,
            "Survey tool arguments cannot be serialized.",
            protocol::json{{"phase", "survey_request_serialization"}});
    }
    if (serialized_arguments.size() > limits_.max_request_bytes) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::invalid_input,
            "Survey tool request exceeds the bounded handler quota.",
            exceeded_value(
                "request_bytes", static_cast<std::uint64_t>(limits_.max_request_bytes),
                static_cast<std::uint64_t>(serialized_arguments.size())));
    }
    if (auto failure = validate_arguments(arguments, limits_)) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::invalid_input,
            "Survey tool arguments violate the bounded handler policy.",
            *failure);
    }

    const std::string detail_level = arguments.value("detail_level", std::string("standard"));
    const auto deadline = std::chrono::steady_clock::now() +
        execution_timeout(contract, limits_.max_execution_time);
    auto acquired = acquire_generation_(target_selector(arguments), deadline);
    if (!acquired) {
        return lease_failure(acquired.error());
    }
    auto lease = std::move(acquired).take_value();
    if (auto failure = validate_lease(lease, limits_)) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::handler_failed,
            "Survey generation lease is inconsistent.",
            *failure);
    }

    summary_interrupt_t interrupt(cancellation, deadline);
    survey_diagnostics_t diagnostics(limits_.max_diagnostics);
    const auto caps = effective_caps(
        limits_, detail_level == "minimal", lease.identity.live);
    const auto* image = leased_image(lease);
    json output = json::object();

    if (image == nullptr) {
        diagnostics.add(
            "metadata_unavailable", "image",
            "the immutable generation has no normalized image metadata");
    } else {
        append_metadata(output, lease, *image, limits_, diagnostics);
        if (!append_segments(output, *image, caps, limits_, diagnostics, interrupt)) {
            return interrupt_failure(interrupt, "survey_segments");
        }
        if (!append_entrypoints(output, *image, caps, limits_, diagnostics, interrupt)) {
            return interrupt_failure(interrupt, "survey_entrypoints");
        }
        if (!append_imports(output, *image, caps, limits_, diagnostics, interrupt)) {
            return interrupt_failure(interrupt, "survey_imports");
        }
    }

    bool analysis_allowed = image != nullptr && lease.analysis != nullptr;
    if (!lease.analysis) {
        diagnostics.add(
            "analysis_unavailable", "analysis",
            "no analysis snapshot is published for the leased generation");
    } else if (!lease.analysis->baseline_complete) {
        diagnostics.add(
            "analysis_partial", "analysis",
            "the published analysis generation is partial");
    }
    if (lease.identity.live && !lease.identity.live_snapshot_current) {
        diagnostics.add(
            "live_snapshot_stale", "live",
            "the immutable live snapshot no longer matches its process identity");
        analysis_allowed = false;
    }
    if (lease.identity.live && image != nullptr &&
        image->provider_size > limits_.max_live_snapshot_bytes) {
        diagnostics.add(
            "live_snapshot_cap", "live",
            "live snapshot analysis collections exceed the survey byte cap",
            limits_.max_live_snapshot_bytes,
            image->provider_size);
        analysis_allowed = false;
    }
    if (analysis_allowed && image != nullptr && lease.analysis != nullptr) {
        if (analysis_within_index_caps(*lease.analysis, *image, limits_, diagnostics)) {
            analysis_index_t analysis_index;
            if (!build_analysis_index(*lease.analysis, *image, analysis_index, interrupt)) {
                return interrupt_failure(interrupt, "survey_analysis_index");
            }
            if (!append_analysis(
                    output, *lease.analysis, *image, analysis_index, caps,
                    limits_, diagnostics, interrupt)) {
                return interrupt_failure(interrupt, "survey_analysis_summary");
            }
        }
    }
    if (interrupt.stopped()) {
        return interrupt_failure(interrupt, "survey_pre_output");
    }

    output["_note"] = diagnostics.note(lease.identity.generation);
    std::string serialized_output;
    try {
        serialized_output = output.dump();
    } catch (const std::exception&) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::invalid_output,
            "Survey output cannot be serialized.",
            protocol::json{{"phase", "survey_output_serialization"}});
    }
    if (serialized_output.size() > limits_.max_response_bytes) {
        diagnostics.add(
            "response_cap", "output",
            "survey sections were omitted because the serialized response exceeded its cap",
            static_cast<std::uint64_t>(limits_.max_response_bytes),
            static_cast<std::uint64_t>(serialized_output.size()));
        output = json{{"_note", diagnostics.note(lease.identity.generation)}};
        serialized_output = output.dump();
        if (serialized_output.size() > limits_.max_response_bytes) {
            return protocol::mcp_result_t::failure(
                protocol::result_error_code_t::invalid_output,
                "Survey partial diagnostic exceeds the response cap.",
                exceeded_value(
                    "response_bytes",
                    static_cast<std::uint64_t>(limits_.max_response_bytes),
                    static_cast<std::uint64_t>(serialized_output.size())));
        }
    }

    const auto output_validation = schemas_.validate(contract.output_schema, output);
    json metadata = lease_metadata(
        lease, limits_, caps, detail_level, diagnostics);
    metadata["output_bytes"] = serialized_output.size();
    metadata["output_schema_source"] = "generated";
    if (!output_validation.valid) {
        metadata["output_schema_validation"] = "failed";
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::invalid_output,
            "Survey output does not satisfy the generated schema.",
            protocol::json{
                {"phase", "survey_output_validation"},
                {"schema", output_validation.diagnostics()},
            },
            metadata);
    }
    metadata["output_schema_validation"] = "passed";
    metadata["handler"] = std::string(name);
    return protocol::mcp_result_t::success(
        std::move(serialized_output), output, metadata);
}

}

namespace aida::standalone::mcp::compat::adapters {

protocol::mcp_result_t survey_binary(const handlers::survey_handlers_t& handlers,
                                     const protocol::json& arguments,
                                     const protocol::cancellation_token_t& cancellation,
                                     const protocol::json& aida_metadata) {
    return handlers.invoke("survey_binary", arguments, cancellation, aida_metadata);
}

}
