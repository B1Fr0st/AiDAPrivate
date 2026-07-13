#include "composite.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <chrono>
#include <deque>
#include <limits>
#include <map>
#include <mutex>
#include <set>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace aida::standalone::mcp::compat::handlers {

namespace {

using protocol::cancellation_token_t;
using protocol::effect_lock_t;
using protocol::json;
using protocol::mcp_result_t;
using protocol::result_error_code_t;
using protocol::target_requirement_t;
using protocol::tool_contract_t;
using protocol::tool_effect_t;

constexpr std::uint64_t k_internal_schema_version = 1;
constexpr std::array<std::string_view, k_composite_tool_count> k_composite_names = {
    "analyze_component",
    "analyze_function",
    "diff_before_after",
    "trace_data_flow",
};

bool is_composite_name(std::string_view name) noexcept {
    return std::binary_search(k_composite_names.begin(), k_composite_names.end(), name);
}

tool_effect_t protocol_effect(contract_effect_t effect) noexcept {
    switch (effect) {
    case contract_effect_t::workspace_read:
        return tool_effect_t::workspace_read;
    case contract_effect_t::workspace_checkpoint:
        return tool_effect_t::workspace_checkpoint;
    case contract_effect_t::workspace_overlay_mutation:
        return tool_effect_t::workspace_overlay_mutation;
    case contract_effect_t::debugger_read:
        return tool_effect_t::debugger_read;
    case contract_effect_t::debugger_control:
        return tool_effect_t::debugger_control;
    case contract_effect_t::debugger_write:
        return tool_effect_t::debugger_write;
    case contract_effect_t::isolated_python:
        return tool_effect_t::isolated_python;
    case contract_effect_t::registry_read:
        return tool_effect_t::registry_read;
    }
    return tool_effect_t::unspecified;
}

effect_lock_t protocol_lock(contract_lock_t lock) noexcept {
    switch (lock) {
    case contract_lock_t::workspace_shared:
        return effect_lock_t::workspace_shared;
    case contract_lock_t::workspace_checkpoint:
        return effect_lock_t::workspace_checkpoint;
    case contract_lock_t::workspace_overlay_transaction:
        return effect_lock_t::workspace_overlay_transaction;
    case contract_lock_t::debugger_lane:
        return effect_lock_t::debugger_lane;
    case contract_lock_t::python_worker:
        return effect_lock_t::python_worker;
    case contract_lock_t::registry_read:
        return effect_lock_t::registry_read;
    }
    return effect_lock_t::unspecified;
}

std::optional<tool_contract_t> protocol_contract_for(
    const contract_descriptor_t& descriptor) {
    auto input = json::parse(
        descriptor.input_schema_json.begin(), descriptor.input_schema_json.end(), nullptr, false);
    auto output = json::parse(
        descriptor.output_schema_json.begin(), descriptor.output_schema_json.end(), nullptr, false);
    auto annotations = json::parse(
        descriptor.annotations_json.begin(), descriptor.annotations_json.end(), nullptr, false);
    if (input.is_discarded() || output.is_discarded() || annotations.is_discarded()) {
        return std::nullopt;
    }

    tool_contract_t contract;
    contract.name.assign(descriptor.name.data(), descriptor.name.size());
    contract.description.assign(descriptor.description.data(), descriptor.description.size());
    contract.input_schema = std::move(input);
    contract.output_schema = std::move(output);
    contract.annotations = std::move(annotations);
    contract.target_policy.requirement = descriptor.target_dependent
        ? target_requirement_t::optional
        : target_requirement_t::independent;
    contract.target_policy.accepts_pid = descriptor.accepts_pid;
    contract.target_policy.accepts_bin_name = descriptor.accepts_bin_name;
    contract.effect_policy.effect = protocol_effect(descriptor.effect);
    contract.effect_policy.lock = protocol_lock(descriptor.lock);
    contract.effect_policy.read_only = descriptor.read_only;
    contract.effect_policy.unsafe = descriptor.unsafe;
    return contract;
}

std::string trim_ascii(std::string_view value) {
    std::size_t first = 0;
    while (first < value.size() && std::isspace(static_cast<unsigned char>(value[first])) != 0) {
        ++first;
    }
    std::size_t last = value.size();
    while (last > first && std::isspace(static_cast<unsigned char>(value[last - 1])) != 0) {
        --last;
    }
    return std::string(value.substr(first, last - first));
}

bool valid_utf8(std::string_view value) noexcept {
    std::size_t offset = 0;
    while (offset < value.size()) {
        const auto lead = static_cast<unsigned char>(value[offset]);
        if (lead <= 0x7fU) {
            ++offset;
            continue;
        }
        if (lead >= 0xc2U && lead <= 0xdfU) {
            if (offset + 1 >= value.size()) {
                return false;
            }
            const auto c1 = static_cast<unsigned char>(value[offset + 1]);
            if (c1 < 0x80U || c1 > 0xbfU) {
                return false;
            }
            offset += 2;
            continue;
        }
        if (lead >= 0xe0U && lead <= 0xefU) {
            if (offset + 2 >= value.size()) {
                return false;
            }
            const auto c1 = static_cast<unsigned char>(value[offset + 1]);
            const auto c2 = static_cast<unsigned char>(value[offset + 2]);
            const bool first_valid = lead == 0xe0U
                ? c1 >= 0xa0U && c1 <= 0xbfU
                : lead == 0xedU
                    ? c1 >= 0x80U && c1 <= 0x9fU
                    : c1 >= 0x80U && c1 <= 0xbfU;
            if (!first_valid || c2 < 0x80U || c2 > 0xbfU) {
                return false;
            }
            offset += 3;
            continue;
        }
        if (lead >= 0xf0U && lead <= 0xf4U) {
            if (offset + 3 >= value.size()) {
                return false;
            }
            const auto c1 = static_cast<unsigned char>(value[offset + 1]);
            const auto c2 = static_cast<unsigned char>(value[offset + 2]);
            const auto c3 = static_cast<unsigned char>(value[offset + 3]);
            const bool first_valid = lead == 0xf0U
                ? c1 >= 0x90U && c1 <= 0xbfU
                : lead == 0xf4U
                    ? c1 >= 0x80U && c1 <= 0x8fU
                    : c1 >= 0x80U && c1 <= 0xbfU;
            if (!first_valid || c2 < 0x80U || c2 > 0xbfU || c3 < 0x80U || c3 > 0xbfU) {
                return false;
            }
            offset += 4;
            continue;
        }
        return false;
    }
    return true;
}

bool valid_text(std::string_view value, std::uint64_t maximum, bool allow_empty = false) noexcept {
    return (allow_empty || !value.empty()) && value.size() <= maximum && valid_utf8(value);
}

std::string normalized_code(std::string_view value, std::string_view fallback) {
    if (value.empty() || value.size() > 96) {
        return std::string(fallback);
    }
    std::string result;
    result.reserve(value.size());
    for (const unsigned char character : value) {
        if (std::isalnum(character) == 0 && character != '_' && character != '-' && character != '.') {
            return std::string(fallback);
        }
        result.push_back(static_cast<char>(std::toupper(character)));
    }
    return result;
}

std::string normalized_message(std::string_view value) {
    std::string result;
    result.reserve((std::min<std::size_t>)(value.size(), 256));
    bool prior_space = false;
    for (const unsigned char character : value) {
        if (result.size() == 256) {
            break;
        }
        const bool whitespace = character <= 0x20U || character == 0x7fU;
        if (whitespace) {
            if (!result.empty() && !prior_space) {
                result.push_back(' ');
                prior_space = true;
            }
            continue;
        }
        result.push_back(character <= 0x7eU ? static_cast<char>(character) : '?');
        prior_space = false;
    }
    while (!result.empty() && result.back() == ' ') {
        result.pop_back();
    }
    return result;
}

std::uint64_t saturated_add(std::uint64_t left, std::uint64_t right) noexcept {
    if (right > (std::numeric_limits<std::uint64_t>::max)() - left) {
        return (std::numeric_limits<std::uint64_t>::max)();
    }
    return left + right;
}

std::uint64_t json_bytes(const json& value) noexcept {
    try {
        return static_cast<std::uint64_t>(value.dump().size());
    } catch (...) {
        return (std::numeric_limits<std::uint64_t>::max)();
    }
}

void sort_unique(std::vector<std::string>& values) {
    std::sort(values.begin(), values.end());
    values.erase(std::unique(values.begin(), values.end()), values.end());
}

struct diagnostic_t final {
    std::uint32_t rank = 0;
    std::string phase;
    std::string subject;
    std::string code;
    std::string message;
};

class diagnostic_log_t final {
public:
    explicit diagnostic_log_t(std::uint64_t maximum)
        : maximum_(maximum) {
    }

    void add(std::uint32_t rank, std::string_view phase, std::string_view subject,
             std::string_view code, std::string_view message) {
        if (entries_.size() < maximum_) {
            entries_.push_back({
                rank,
                normalized_code(phase, "phase"),
                normalized_message(subject),
                normalized_code(code, "COMPOSITE_STEP_FAILED"),
                normalized_message(message),
            });
        } else {
            truncated_ = true;
        }
    }

    bool empty() const noexcept {
        return entries_.empty() && !truncated_;
    }

    json ordered_json() const {
        auto ordered = entries_;
        std::sort(ordered.begin(), ordered.end(), [](const diagnostic_t& left, const diagnostic_t& right) {
            return std::tie(left.rank, left.phase, left.subject, left.code, left.message) <
                std::tie(right.rank, right.phase, right.subject, right.code, right.message);
        });
        json result = json::array();
        for (const auto& entry : ordered) {
            result.push_back(json{
                {"phase", entry.phase},
                {"subject", entry.subject},
                {"code", entry.code},
                {"message", entry.message},
            });
        }
        if (truncated_) {
            result.push_back(json{
                {"phase", "DIAGNOSTICS"},
                {"subject", ""},
                {"code", "COMPOSITE_DIAGNOSTICS_TRUNCATED"},
                {"message", "additional diagnostics were suppressed by the configured bound"},
            });
        }
        return result;
    }

    std::string summary() const {
        const auto ordered = ordered_json();
        std::string result = "partial:";
        std::set<std::pair<std::string, std::string>> emitted;
        for (const auto& entry : ordered) {
            const auto key = std::make_pair(
                entry.value("phase", std::string("PHASE")),
                entry.value("code", std::string("COMPOSITE_STEP_FAILED")));
            if (!emitted.insert(key).second) {
                continue;
            }
            const std::string fragment = " " + key.first + "/" + key.second + ";";
            if (result.size() + fragment.size() > 2048) {
                result += " COMPOSITE_DIAGNOSTIC_SUMMARY_TRUNCATED;";
                break;
            }
            result += fragment;
        }
        return result;
    }

private:
    std::uint64_t maximum_ = 0;
    std::vector<diagnostic_t> entries_;
    bool truncated_ = false;
};

struct budget_t final {
    composite_quota_t quota;
    std::uint64_t steps = 0;
    std::uint64_t items = 0;
    std::uint64_t bytes = 0;

    std::uint64_t remaining_items() const noexcept {
        return items >= quota.max_backend_items ? 0 : quota.max_backend_items - items;
    }

    std::uint64_t remaining_bytes() const noexcept {
        return bytes >= quota.max_backend_bytes ? 0 : quota.max_backend_bytes - bytes;
    }
};

struct bound_outcome_t final {
    bool success = false;
    result_error_code_t error_code = result_error_code_t::handler_failed;
    std::string text;
    json structured_content = json::object();
    json details = json::object();
    json metadata = json::object();
    bool truncated = false;
};

struct step_execution_t final {
    bool accepted = false;
    bool cancelled = false;
    bool quota_exhausted = false;
    composite_step_response_t response;
};

class scope_exit_t final {
public:
    explicit scope_exit_t(std::function<void()> action)
        : action_(std::move(action)) {
    }

    ~scope_exit_t() {
        if (action_) {
            action_();
        }
    }

    scope_exit_t(const scope_exit_t&) = delete;
    scope_exit_t& operator=(const scope_exit_t&) = delete;

private:
    std::function<void()> action_;
};

bool valid_quota(const composite_quota_t& quota) noexcept {
    return quota.max_steps != 0 && quota.max_backend_items != 0 &&
        quota.max_backend_bytes >= 1024 && quota.max_output_bytes >= 1024;
}

bool quota_within(const composite_quota_t& value, const composite_quota_t& hard) noexcept {
    return value.max_steps <= hard.max_steps &&
        value.max_backend_items <= hard.max_backend_items &&
        value.max_backend_bytes <= hard.max_backend_bytes &&
        value.max_output_bytes <= hard.max_output_bytes;
}

bool valid_limits(const composite_limits_t& limits) noexcept {
    return valid_quota(limits.hard_quota) &&
        limits.max_component_functions != 0 &&
        limits.max_trace_nodes != 0 && limits.max_trace_edges != 0 &&
        limits.max_neighbors_per_node != 0 && limits.max_collection_items != 0 &&
        limits.max_diagnostics != 0 && limits.max_input_bytes >= 1024 &&
        limits.max_address_bytes != 0 && limits.max_identifier_bytes != 0 &&
        limits.max_text_bytes != 0 && limits.read_timeout.count() > 0 &&
        limits.component_timeout.count() > 0 && limits.mutation_timeout.count() > 0;
}

std::optional<std::uint64_t> json_unsigned(const json& value) noexcept {
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
    } catch (...) {
    }
    return std::nullopt;
}

std::uint64_t payload_items(const composite_step_payload_t& payload) noexcept {
    if (const auto* batch = std::get_if<composite_xref_batch_t>(&payload)) {
        return static_cast<std::uint64_t>(batch->neighbors.size());
    }
    if (std::holds_alternative<std::monostate>(payload)) {
        return 0;
    }
    return 1;
}

std::uint64_t payload_bytes(const composite_step_payload_t& payload) noexcept {
    std::uint64_t total = 0;
    const auto add_string = [&total](std::string_view value) {
        total = saturated_add(total, static_cast<std::uint64_t>(value.size()));
    };
    if (const auto* snapshot = std::get_if<composite_function_snapshot_t>(&payload)) {
        add_string(snapshot->addr);
        add_string(snapshot->name);
        if (snapshot->prototype) {
            add_string(*snapshot->prototype);
        }
        total = saturated_add(total, json_bytes(snapshot->comments));
        total = saturated_add(total, json_bytes(snapshot->xrefs));
        for (const auto& value : snapshot->strings) {
            add_string(value);
        }
        for (const auto& value : snapshot->constants) {
            total = saturated_add(total, json_bytes(value));
        }
        for (const auto& value : snapshot->callers) {
            add_string(value);
        }
        for (const auto& value : snapshot->callees) {
            add_string(value);
        }
        for (const auto& value : snapshot->globals) {
            add_string(value.addr);
            add_string(value.name);
        }
    } else if (const auto* text = std::get_if<composite_text_snapshot_t>(&payload)) {
        if (text->text) {
            add_string(*text->text);
        }
        add_string(text->error);
    } else if (const auto* batch = std::get_if<composite_xref_batch_t>(&payload)) {
        for (const auto& neighbor : batch->neighbors) {
            add_string(neighbor.addr);
            add_string(neighbor.type);
        }
    } else if (const auto* snapshot = std::get_if<composite_address_snapshot_t>(&payload)) {
        add_string(snapshot->addr);
        if (snapshot->function) {
            add_string(*snapshot->function);
        }
        if (snapshot->instruction) {
            add_string(*snapshot->instruction);
        }
        add_string(snapshot->type);
        if (snapshot->name) {
            add_string(*snapshot->name);
        }
    } else if (const auto* mutation = std::get_if<composite_overlay_result_t>(&payload)) {
        add_string(mutation->action_applied);
    }
    return total;
}

bool payload_matches(composite_step_kind_t kind, const composite_step_payload_t& payload) noexcept {
    switch (kind) {
    case composite_step_kind_t::function_snapshot:
        return std::holds_alternative<composite_function_snapshot_t>(payload);
    case composite_step_kind_t::decompile_function:
    case composite_step_kind_t::disassemble_function:
        return std::holds_alternative<composite_text_snapshot_t>(payload);
    case composite_step_kind_t::xref_neighbors:
        return std::holds_alternative<composite_xref_batch_t>(payload);
    case composite_step_kind_t::address_snapshot:
        return std::holds_alternative<composite_address_snapshot_t>(payload);
    case composite_step_kind_t::apply_overlay_action:
        return std::holds_alternative<composite_overlay_result_t>(payload);
    }
    return false;
}

json target_metadata(const adapter_call_context_t& context) {
    if (!context.target) {
        return json::object();
    }
    const auto& target = context.target->target();
    return json{
        {"target_id", target.target_id},
        {"pid", target.pid},
        {"bin_name", target.bin_name},
        {"generation", target.generation},
        {"attach_generation", target.attach_generation},
        {"live", target.live},
    };
}

bound_outcome_t failed_outcome(
    result_error_code_t code, std::string text, json details = json::object(),
    json metadata = json::object()) {
    bound_outcome_t outcome;
    outcome.error_code = code;
    outcome.text = std::move(text);
    outcome.details = std::move(details);
    outcome.metadata = std::move(metadata);
    return outcome;
}

json serialize_outcome(const bound_outcome_t& outcome) {
    if (outcome.success) {
        return json{
            {"status", "success"},
            {"text", outcome.text},
            {"structured_content", outcome.structured_content},
            {"aida_metadata", outcome.metadata},
            {"truncated", outcome.truncated},
        };
    }
    return json{
        {"status", "error"},
        {"error_code", std::string(protocol::canonical_error_code(outcome.error_code))},
        {"text", outcome.text},
        {"details", outcome.details},
        {"aida_metadata", outcome.metadata},
    };
}

std::optional<result_error_code_t> result_code_from_name(std::string_view name) noexcept {
    constexpr std::array<result_error_code_t, 8> codes = {
        result_error_code_t::cancelled,
        result_error_code_t::invalid_input,
        result_error_code_t::invalid_output,
        result_error_code_t::target_policy_rejected,
        result_error_code_t::effect_policy_rejected,
        result_error_code_t::invalid_contract,
        result_error_code_t::handler_failed,
        result_error_code_t::internal_error,
    };
    for (const auto code : codes) {
        if (protocol::canonical_error_code(code) == name) {
            return code;
        }
    }
    return std::nullopt;
}

result_error_code_t adapter_result_code(adapter_error_code_t code) noexcept {
    switch (code) {
    case adapter_error_code_t::target_resolution_failed:
        return result_error_code_t::target_policy_rejected;
    case adapter_error_code_t::operation_not_permitted:
    case adapter_error_code_t::effect_policy_failed:
    case adapter_error_code_t::effect_lock_busy:
        return result_error_code_t::effect_policy_rejected;
    case adapter_error_code_t::contract_not_found:
        return result_error_code_t::invalid_contract;
    case adapter_error_code_t::invalid_request:
        return result_error_code_t::invalid_input;
    case adapter_error_code_t::none:
    case adapter_error_code_t::backend_unavailable:
    case adapter_error_code_t::backend_rejected:
    case adapter_error_code_t::live_snapshot_denied:
    case adapter_error_code_t::live_snapshot_bounds:
    case adapter_error_code_t::live_snapshot_invalid:
        return result_error_code_t::handler_failed;
    }
    return result_error_code_t::handler_failed;
}

}

struct composite_handlers_t::impl_t final {
    struct invocation_state_t final {
        std::string tool_name;
        cancellation_token_t cancellation;
        composite_invocation_options_t options;
        composite_quota_t quota;
        std::chrono::steady_clock::time_point deadline;
    };

    composite_backend_t backend;
    composite_limits_t limits;
    std::atomic<std::uint64_t> next_invocation_id{1};
    std::mutex invocation_mutex;
    std::unordered_map<std::uint64_t, std::shared_ptr<const invocation_state_t>> invocations;

    std::uint64_t register_invocation(std::shared_ptr<const invocation_state_t> state) {
        for (;;) {
            std::uint64_t id = next_invocation_id.fetch_add(1, std::memory_order_relaxed);
            if (id == 0) {
                continue;
            }
            std::lock_guard lock(invocation_mutex);
            if (invocations.emplace(id, state).second) {
                return id;
            }
        }
    }

    void unregister_invocation(std::uint64_t id) {
        std::lock_guard lock(invocation_mutex);
        invocations.erase(id);
    }

    std::shared_ptr<const invocation_state_t> find_invocation(std::uint64_t id) {
        std::lock_guard lock(invocation_mutex);
        const auto iterator = invocations.find(id);
        return iterator == invocations.end() ? nullptr : iterator->second;
    }

    step_execution_t run_step(
        const adapter_call_context_t& context,
        const invocation_state_t& state,
        budget_t& budget,
        diagnostic_log_t& diagnostics,
        std::uint32_t rank,
        std::string_view phase,
        composite_step_request_t request) const;

    bound_outcome_t analyze_function(
        const adapter_call_context_t& context,
        const json& arguments,
        const invocation_state_t& state) const;
    bound_outcome_t analyze_component(
        const adapter_call_context_t& context,
        const json& arguments,
        const invocation_state_t& state) const;
    bound_outcome_t diff_before_after(
        const adapter_call_context_t& context,
        const json& arguments,
        const invocation_state_t& state) const;
    bound_outcome_t trace_data_flow(
        const adapter_call_context_t& context,
        const json& arguments,
        const invocation_state_t& state) const;

    bound_outcome_t finalize(
        std::string_view tool_name,
        std::string text,
        json output,
        diagnostic_log_t& diagnostics,
        const budget_t& budget,
        const adapter_call_context_t& context,
        std::optional<std::uint64_t> overlay_before,
        std::optional<std::uint64_t> overlay_after) const;
};

step_execution_t composite_handlers_t::impl_t::run_step(
    const adapter_call_context_t& context,
    const invocation_state_t& state,
    budget_t& budget,
    diagnostic_log_t& diagnostics,
    std::uint32_t rank,
    std::string_view phase,
    composite_step_request_t request) const {
    step_execution_t execution;
    if (!context.target) {
        diagnostics.add(rank, phase, request.subject, "COMPOSITE_TARGET_MISSING",
                        "the routed workspace target is unavailable");
        return execution;
    }
    if (state.cancellation.cancelled()) {
        execution.cancelled = true;
        return execution;
    }
    const auto now = std::chrono::steady_clock::now();
    if (now >= state.deadline) {
        diagnostics.add(rank, phase, request.subject, "COMPOSITE_DEADLINE_EXCEEDED",
                        "the composition deadline elapsed before the step started");
        execution.quota_exhausted = true;
        return execution;
    }
    if (budget.steps >= budget.quota.max_steps || budget.remaining_items() == 0 ||
        budget.remaining_bytes() == 0) {
        diagnostics.add(rank, phase, request.subject, "COMPOSITE_QUOTA_EXHAUSTED",
                        "the composition quota was exhausted before the step started");
        execution.quota_exhausted = true;
        return execution;
    }

    ++budget.steps;
    request.workspace_generation = context.target->target().generation;
    request.deadline = state.deadline;
    request.max_items = request.max_items == 0
        ? budget.remaining_items()
        : (std::min)(request.max_items, budget.remaining_items());
    request.max_bytes = request.max_bytes == 0
        ? budget.remaining_bytes()
        : (std::min)(request.max_bytes, budget.remaining_bytes());
    request.permit_baseline_start = false;
    request.permit_unrequested_deep_work = false;
    if (request.max_items == 0 || request.max_bytes == 0) {
        diagnostics.add(rank, phase, request.subject, "COMPOSITE_QUOTA_EXHAUSTED",
                        "the step received an empty item or byte allowance");
        execution.quota_exhausted = true;
        return execution;
    }
    if (!backend) {
        diagnostics.add(rank, phase, request.subject, "COMPOSITE_BACKEND_UNAVAILABLE",
                        "the composite backend is not configured");
        return execution;
    }

    try {
        execution.response = backend(context, request, state.cancellation);
    } catch (...) {
        diagnostics.add(rank, phase, request.subject, "COMPOSITE_BACKEND_EXCEPTION",
                        "the composite backend rejected the bounded step");
        return execution;
    }

    auto& response = execution.response;
    if (response.status == composite_step_status_t::cancelled) {
        execution.cancelled = true;
        return execution;
    }
    if (response.baseline_started || response.unrequested_deep_work_started) {
        diagnostics.add(rank, phase, request.subject, "COMPOSITE_HIDDEN_WORK_REJECTED",
                        "the backend reported baseline or unrequested deep work");
        return execution;
    }
    if (!response.workspace_generation ||
        *response.workspace_generation != request.workspace_generation) {
        diagnostics.add(rank, phase, request.subject, "COMPOSITE_WORKSPACE_GENERATION_STALE",
                        "the backend response does not belong to the pinned workspace generation");
        return execution;
    }
    if (!response.observed_overlay_generation) {
        diagnostics.add(rank, phase, request.subject, "COMPOSITE_OVERLAY_GENERATION_MISSING",
                        "the backend response omitted its overlay generation");
        return execution;
    }
    if (request.expected_overlay_generation &&
        *response.observed_overlay_generation != *request.expected_overlay_generation) {
        diagnostics.add(rank, phase, request.subject, "COMPOSITE_OVERLAY_GENERATION_STALE",
                        "the backend response does not match the pinned overlay generation");
        return execution;
    }
    if (request.kind != composite_step_kind_t::apply_overlay_action &&
        response.committed_overlay_generation) {
        diagnostics.add(rank, phase, request.subject, "COMPOSITE_UNEXPECTED_OVERLAY_MUTATION",
                        "a read step reported an overlay commit");
        return execution;
    }

    switch (response.status) {
    case composite_step_status_t::complete:
        break;
    case composite_step_status_t::partial:
        diagnostics.add(
            rank, phase, request.subject,
            normalized_code(response.diagnostic_code, "COMPOSITE_BACKEND_PARTIAL"),
            response.diagnostic_message.empty()
                ? "the backend returned a bounded partial result"
                : response.diagnostic_message);
        break;
    case composite_step_status_t::quota_exhausted:
        diagnostics.add(
            rank, phase, request.subject,
            normalized_code(response.diagnostic_code, "COMPOSITE_BACKEND_QUOTA_EXHAUSTED"),
            response.diagnostic_message.empty()
                ? "the backend exhausted its bounded step quota"
                : response.diagnostic_message);
        execution.quota_exhausted = true;
        return execution;
    case composite_step_status_t::unavailable:
    case composite_step_status_t::rejected:
        diagnostics.add(
            rank, phase, request.subject,
            normalized_code(response.diagnostic_code, "COMPOSITE_BACKEND_REJECTED"),
            response.diagnostic_message.empty()
                ? "the backend did not produce the requested bounded result"
                : response.diagnostic_message);
        return execution;
    case composite_step_status_t::cancelled:
        execution.cancelled = true;
        return execution;
    }

    if (!payload_matches(request.kind, response.payload)) {
        diagnostics.add(rank, phase, request.subject, "COMPOSITE_BACKEND_PAYLOAD_INVALID",
                        "the backend response type does not match the requested step");
        return execution;
    }
    const std::uint64_t actual_items = payload_items(response.payload);
    const std::uint64_t actual_bytes = payload_bytes(response.payload);
    const std::uint64_t charged_items = (std::max)(response.items_consumed, actual_items);
    const std::uint64_t charged_bytes = (std::max)(response.bytes_consumed, actual_bytes);
    if (charged_items > request.max_items || charged_items > budget.remaining_items() ||
        charged_bytes > request.max_bytes || charged_bytes > budget.remaining_bytes()) {
        diagnostics.add(rank, phase, request.subject, "COMPOSITE_BACKEND_QUOTA_VIOLATION",
                        "the backend response exceeded the granted item or byte allowance");
        execution.quota_exhausted = true;
        return execution;
    }
    budget.items = saturated_add(budget.items, charged_items);
    budget.bytes = saturated_add(budget.bytes, charged_bytes);
    execution.accepted = true;
    return execution;
}

bound_outcome_t composite_handlers_t::impl_t::finalize(
    std::string_view tool_name,
    std::string text,
    json output,
    diagnostic_log_t& diagnostics,
    const budget_t& budget,
    const adapter_call_context_t& context,
    std::optional<std::uint64_t> overlay_before,
    std::optional<std::uint64_t> overlay_after) const {
    if (!diagnostics.empty()) {
        output["error"] = diagnostics.summary();
    }
    if (json_bytes(output) > budget.quota.max_output_bytes) {
        diagnostics.add(0xffffffffU, "output", tool_name, "COMPOSITE_OUTPUT_QUOTA_EXCEEDED",
                        "the composed output exceeded its serialized byte allowance");
        output = json{{"error", diagnostics.summary()}};
    }

    json metadata = target_metadata(context);
    if (overlay_before) {
        metadata["overlay_revision_before"] = *overlay_before;
    }
    if (overlay_after) {
        metadata["overlay_revision"] = *overlay_after;
    } else if (overlay_before) {
        metadata["overlay_revision"] = *overlay_before;
    }
    metadata["composite"] = json{
        {"schema_version", k_internal_schema_version},
        {"complete", diagnostics.empty()},
        {"partial", !diagnostics.empty()},
        {"baseline_started", false},
        {"unrequested_deep_work_started", false},
        {"quota", json{
            {"steps_used", budget.steps},
            {"steps_limit", budget.quota.max_steps},
            {"items_used", budget.items},
            {"items_limit", budget.quota.max_backend_items},
            {"bytes_used", budget.bytes},
            {"bytes_limit", budget.quota.max_backend_bytes},
            {"output_bytes", json_bytes(output)},
            {"output_limit", budget.quota.max_output_bytes},
        }},
        {"diagnostics", diagnostics.ordered_json()},
    };

    bound_outcome_t outcome;
    outcome.success = true;
    outcome.text = diagnostics.empty() ? std::move(text) : std::move(text) + " Partial results returned.";
    outcome.structured_content = std::move(output);
    outcome.metadata = std::move(metadata);
    outcome.truncated = !diagnostics.empty();
    return outcome;
}

namespace {

std::vector<std::string> bounded_strings(
    const std::vector<std::string>& source,
    const composite_limits_t& limits,
    diagnostic_log_t& diagnostics,
    std::uint32_t rank,
    std::string_view phase,
    std::string_view subject) {
    std::vector<std::string> result;
    result.reserve((std::min<std::size_t>)(
        source.size(), static_cast<std::size_t>(limits.max_collection_items)));
    for (const auto& value : source) {
        if (result.size() >= limits.max_collection_items) {
            diagnostics.add(rank, phase, subject, "COMPOSITE_COLLECTION_TRUNCATED",
                            "the collection exceeded its configured item bound");
            break;
        }
        if (!valid_text(value, limits.max_identifier_bytes)) {
            diagnostics.add(rank, phase, subject, "COMPOSITE_TEXT_INVALID",
                            "the backend collection contained an invalid string");
            continue;
        }
        result.push_back(value);
    }
    sort_unique(result);
    return result;
}

std::optional<std::string> bounded_optional_text(
    const std::optional<std::string>& value,
    std::uint64_t maximum,
    diagnostic_log_t& diagnostics,
    std::uint32_t rank,
    std::string_view phase,
    std::string_view subject) {
    if (!value) {
        return std::nullopt;
    }
    if (!valid_text(*value, maximum, true)) {
        diagnostics.add(rank, phase, subject, "COMPOSITE_TEXT_INVALID",
                        "the backend returned invalid or oversized text");
        return std::nullopt;
    }
    return value;
}

std::optional<std::string> required_argument_string(
    const json& arguments, const char* name, std::uint64_t maximum) {
    const auto iterator = arguments.find(name);
    if (iterator == arguments.end() || !iterator->is_string()) {
        return std::nullopt;
    }
    std::string value = trim_ascii(iterator->get_ref<const std::string&>());
    if (!valid_text(value, maximum)) {
        return std::nullopt;
    }
    return value;
}

bound_outcome_t cancelled_outcome(const adapter_call_context_t& context, std::string_view phase) {
    return failed_outcome(
        result_error_code_t::cancelled,
        "Composite invocation was cancelled.",
        json{{"phase", phase}},
        target_metadata(context));
}

bound_outcome_t invalid_input_outcome(
    const adapter_call_context_t& context, std::string_view field, std::string_view reason) {
    return failed_outcome(
        result_error_code_t::invalid_input,
        "Composite arguments are invalid.",
        json{{"field", field}, {"reason", reason}},
        target_metadata(context));
}

bound_outcome_t generation_failure(
    const adapter_call_context_t& context, std::string_view phase,
    std::optional<std::uint64_t> expected, std::optional<std::uint64_t> actual) {
    json details{{"phase", phase}};
    if (expected) {
        details["expected_overlay_generation"] = *expected;
    }
    if (actual) {
        details["actual_overlay_generation"] = *actual;
    }
    return failed_outcome(
        result_error_code_t::handler_failed,
        "Composite overlay generation changed.",
        std::move(details),
        target_metadata(context));
}

}

bound_outcome_t composite_handlers_t::impl_t::analyze_function(
    const adapter_call_context_t& context,
    const json& arguments,
    const invocation_state_t& state) const {
    if (state.cancellation.cancelled()) {
        return cancelled_outcome(context, "analyze_function.preflight");
    }
    const auto address = required_argument_string(arguments, "addr", limits.max_address_bytes);
    if (!address) {
        return invalid_input_outcome(context, "addr", "address must be non-empty bounded UTF-8 text");
    }
    const bool include_assembly = arguments.value("include_asm", false);
    budget_t budget{state.quota};
    diagnostic_log_t diagnostics(limits.max_diagnostics);
    std::optional<std::uint64_t> overlay_generation = state.options.expected_overlay_generation;

    json output{
        {"addr", *address},
        {"name", *address},
        {"size", 0},
        {"prototype", nullptr},
        {"comments", json::object()},
        {"strings", json::array()},
        {"constants", json::array()},
        {"callers", json::array()},
        {"callees", json::array()},
        {"xrefs", json::object()},
        {"basic_blocks", json{{"count", 0}, {"cyclomatic_complexity", 0}}},
        {"decompiled", nullptr},
        {"decompile_error", nullptr},
        {"decompile_truncated", 0},
        {"assembly", nullptr},
        {"error", nullptr},
    };

    composite_step_request_t summary_request;
    summary_request.kind = composite_step_kind_t::function_snapshot;
    summary_request.subject = *address;
    summary_request.expected_overlay_generation = overlay_generation;
    summary_request.max_items = limits.max_collection_items;
    summary_request.max_bytes = (std::min)(limits.max_text_bytes * 2, budget.remaining_bytes());
    const auto summary = run_step(
        context, state, budget, diagnostics, 10, "function_snapshot", std::move(summary_request));
    if (summary.cancelled) {
        return cancelled_outcome(context, "analyze_function.function_snapshot");
    }
    if (summary.accepted) {
        overlay_generation = summary.response.observed_overlay_generation;
        const auto& snapshot = std::get<composite_function_snapshot_t>(summary.response.payload);
        if (valid_text(snapshot.addr, limits.max_address_bytes)) {
            output["addr"] = snapshot.addr;
        } else {
            diagnostics.add(10, "function_snapshot", *address, "COMPOSITE_ADDRESS_INVALID",
                            "the function snapshot returned an invalid address");
        }
        if (valid_text(snapshot.name, limits.max_identifier_bytes)) {
            output["name"] = snapshot.name;
        } else {
            diagnostics.add(10, "function_snapshot", *address, "COMPOSITE_NAME_INVALID",
                            "the function snapshot returned an invalid name");
        }
        output["size"] = snapshot.size;
        const auto prototype = bounded_optional_text(
            snapshot.prototype, limits.max_text_bytes, diagnostics, 10,
            "function_snapshot", *address);
        output["prototype"] = prototype ? json(*prototype) : json(nullptr);
        if (snapshot.comments.is_object()) {
            output["comments"] = snapshot.comments;
        } else {
            diagnostics.add(10, "function_snapshot", *address, "COMPOSITE_COMMENTS_INVALID",
                            "the function snapshot comments are not an object");
        }
        output["strings"] = bounded_strings(
            snapshot.strings, limits, diagnostics, 10, "function_snapshot", *address);
        output["callers"] = bounded_strings(
            snapshot.callers, limits, diagnostics, 10, "function_snapshot", *address);
        output["callees"] = bounded_strings(
            snapshot.callees, limits, diagnostics, 10, "function_snapshot", *address);
        json constants = json::array();
        for (const auto& constant : snapshot.constants) {
            if (constants.size() >= limits.max_collection_items) {
                diagnostics.add(10, "function_snapshot", *address, "COMPOSITE_COLLECTION_TRUNCATED",
                                "the constants collection exceeded its configured item bound");
                break;
            }
            if (!constant.is_object()) {
                diagnostics.add(10, "function_snapshot", *address, "COMPOSITE_CONSTANT_INVALID",
                                "a function constant is not an object");
                continue;
            }
            constants.push_back(constant);
        }
        output["constants"] = std::move(constants);
        if (snapshot.xrefs.is_object()) {
            output["xrefs"] = snapshot.xrefs;
        } else {
            diagnostics.add(10, "function_snapshot", *address, "COMPOSITE_XREFS_INVALID",
                            "the function snapshot xrefs are not an object");
        }
        output["basic_blocks"] = json{
            {"count", snapshot.basic_block_count},
            {"cyclomatic_complexity", snapshot.cyclomatic_complexity},
        };
    }

    composite_step_request_t decompile_request;
    decompile_request.kind = composite_step_kind_t::decompile_function;
    decompile_request.subject = *address;
    decompile_request.expected_overlay_generation = overlay_generation;
    decompile_request.max_items = 1;
    decompile_request.max_bytes = (std::min)(limits.max_text_bytes, budget.remaining_bytes());
    const auto decompiled = run_step(
        context, state, budget, diagnostics, 20, "decompile", std::move(decompile_request));
    if (decompiled.cancelled) {
        return cancelled_outcome(context, "analyze_function.decompile");
    }
    if (decompiled.accepted) {
        overlay_generation = decompiled.response.observed_overlay_generation;
        const auto& snapshot = std::get<composite_text_snapshot_t>(decompiled.response.payload);
        const auto text = bounded_optional_text(
            snapshot.text, limits.max_text_bytes, diagnostics, 20, "decompile", *address);
        output["decompiled"] = text ? json(*text) : json(nullptr);
        output["decompile_truncated"] = snapshot.truncated;
        if (!snapshot.error.empty()) {
            if (valid_text(snapshot.error, limits.max_text_bytes, true)) {
                output["decompile_error"] = snapshot.error;
            } else {
                output["decompile_error"] = "decompiler returned invalid diagnostic text";
            }
            diagnostics.add(20, "decompile", *address, "COMPOSITE_DECOMPILER_PARTIAL",
                            snapshot.error);
        } else if (!text) {
            output["decompile_error"] = "decompilation did not produce text";
            diagnostics.add(20, "decompile", *address, "COMPOSITE_DECOMPILER_EMPTY",
                            "decompilation did not produce text");
        }
    } else {
        output["decompile_error"] = "decompilation unavailable within the bounded composition";
    }

    if (include_assembly) {
        composite_step_request_t disassemble_request;
        disassemble_request.kind = composite_step_kind_t::disassemble_function;
        disassemble_request.subject = *address;
        disassemble_request.expected_overlay_generation = overlay_generation;
        disassemble_request.max_items = limits.max_collection_items;
        disassemble_request.max_bytes = (std::min)(limits.max_text_bytes, budget.remaining_bytes());
        const auto disassembled = run_step(
            context, state, budget, diagnostics, 30, "disassemble", std::move(disassemble_request));
        if (disassembled.cancelled) {
            return cancelled_outcome(context, "analyze_function.disassemble");
        }
        if (disassembled.accepted) {
            overlay_generation = disassembled.response.observed_overlay_generation;
            const auto& snapshot = std::get<composite_text_snapshot_t>(disassembled.response.payload);
            const auto text = bounded_optional_text(
                snapshot.text, limits.max_text_bytes, diagnostics, 30, "disassemble", *address);
            output["assembly"] = text ? json(*text) : json(nullptr);
            if (!snapshot.error.empty()) {
                diagnostics.add(30, "disassemble", *address, "COMPOSITE_DISASSEMBLY_PARTIAL",
                                snapshot.error);
            }
        }
    }

    return finalize(
        "analyze_function", "Function analysis completed.", std::move(output), diagnostics,
        budget, context, overlay_generation, overlay_generation);
}

bound_outcome_t composite_handlers_t::impl_t::analyze_component(
    const adapter_call_context_t& context,
    const json& arguments,
    const invocation_state_t& state) const {
    if (state.cancellation.cancelled()) {
        return cancelled_outcome(context, "analyze_component.preflight");
    }
    const auto addrs_iterator = arguments.find("addrs");
    if (addrs_iterator == arguments.end()) {
        return invalid_input_outcome(context, "addrs", "at least one function address is required");
    }

    std::vector<std::string> addresses;
    std::unordered_set<std::string> seen;
    const auto append_address = [&](std::string_view raw) {
        std::string address = trim_ascii(raw);
        if (!valid_text(address, limits.max_address_bytes) || !seen.insert(address).second) {
            return;
        }
        addresses.push_back(std::move(address));
    };
    if (addrs_iterator->is_string()) {
        const auto& value = addrs_iterator->get_ref<const std::string&>();
        std::size_t offset = 0;
        while (offset <= value.size()) {
            const auto comma = value.find(',', offset);
            const auto length = comma == std::string::npos ? value.size() - offset : comma - offset;
            append_address(std::string_view(value).substr(offset, length));
            if (comma == std::string::npos) {
                break;
            }
            offset = comma + 1;
        }
    } else if (addrs_iterator->is_array()) {
        for (const auto& value : *addrs_iterator) {
            if (value.is_string()) {
                append_address(value.get_ref<const std::string&>());
            }
        }
    }
    if (addresses.empty()) {
        return invalid_input_outcome(
            context, "addrs", "function addresses must be unique non-empty bounded UTF-8 strings");
    }

    budget_t budget{state.quota};
    diagnostic_log_t diagnostics(limits.max_diagnostics);
    if (addresses.size() > limits.max_component_functions) {
        addresses.resize(static_cast<std::size_t>(limits.max_component_functions));
        diagnostics.add(1, "component_input", "addrs", "COMPOSITE_COMPONENT_FUNCTION_LIMIT",
                        "function addresses beyond the configured component bound were omitted");
    }
    std::optional<std::uint64_t> overlay_generation = state.options.expected_overlay_generation;

    struct component_record_t final {
        composite_function_snapshot_t snapshot;
        std::string canonical_addr;
        std::string display_name;
        std::vector<std::string> strings;
        std::vector<std::string> callers;
        std::vector<std::string> callees;
        std::vector<composite_global_reference_t> globals;
    };
    std::vector<component_record_t> records;
    json functions = json::array();
    bool quota_exhausted = false;
    for (std::size_t index = 0; index < addresses.size(); ++index) {
        const auto& address = addresses[index];
        if (quota_exhausted) {
            functions.push_back(json{{"addr", address}, {"error", "COMPOSITE_QUOTA_EXHAUSTED"}});
            continue;
        }
        composite_step_request_t request;
        request.kind = composite_step_kind_t::function_snapshot;
        request.subject = address;
        request.expected_overlay_generation = overlay_generation;
        request.max_items = limits.max_collection_items;
        request.max_bytes = (std::min)(limits.max_text_bytes * 2, budget.remaining_bytes());
        const auto step = run_step(
            context, state, budget, diagnostics,
            static_cast<std::uint32_t>(10 + index), "component_function", std::move(request));
        if (step.cancelled) {
            return cancelled_outcome(context, "analyze_component.function_snapshot");
        }
        if (!step.accepted) {
            functions.push_back(json{{"addr", address}, {"error", "COMPOSITE_FUNCTION_UNAVAILABLE"}});
            quota_exhausted = step.quota_exhausted;
            continue;
        }
        overlay_generation = step.response.observed_overlay_generation;
        const auto& snapshot = std::get<composite_function_snapshot_t>(step.response.payload);
        if (!valid_text(snapshot.addr, limits.max_address_bytes) ||
            !valid_text(snapshot.name, limits.max_identifier_bytes)) {
            diagnostics.add(
                static_cast<std::uint32_t>(10 + index), "component_function", address,
                "COMPOSITE_FUNCTION_IDENTITY_INVALID",
                "the function snapshot returned an invalid address or name");
            functions.push_back(json{{"addr", address}, {"error", "COMPOSITE_FUNCTION_IDENTITY_INVALID"}});
            continue;
        }

        component_record_t record;
        record.snapshot = snapshot;
        record.canonical_addr = snapshot.addr;
        record.display_name = snapshot.name;
        record.strings = bounded_strings(
            snapshot.strings, limits, diagnostics, static_cast<std::uint32_t>(10 + index),
            "component_function", address);
        record.callers = bounded_strings(
            snapshot.callers, limits, diagnostics, static_cast<std::uint32_t>(10 + index),
            "component_function", address);
        record.callees = bounded_strings(
            snapshot.callees, limits, diagnostics, static_cast<std::uint32_t>(10 + index),
            "component_function", address);
        for (const auto& global : snapshot.globals) {
            if (record.globals.size() >= limits.max_collection_items) {
                diagnostics.add(
                    static_cast<std::uint32_t>(10 + index), "component_function", address,
                    "COMPOSITE_COLLECTION_TRUNCATED",
                    "the global reference collection exceeded its configured item bound");
                break;
            }
            if (!valid_text(global.addr, limits.max_address_bytes) ||
                !valid_text(global.name, limits.max_identifier_bytes)) {
                diagnostics.add(
                    static_cast<std::uint32_t>(10 + index), "component_function", address,
                    "COMPOSITE_GLOBAL_INVALID",
                    "the function snapshot returned an invalid global reference");
                continue;
            }
            record.globals.push_back(global);
        }
        std::sort(record.globals.begin(), record.globals.end(), [](const auto& left, const auto& right) {
            return std::tie(left.addr, left.name) < std::tie(right.addr, right.name);
        });
        record.globals.erase(
            std::unique(record.globals.begin(), record.globals.end(), [](const auto& left, const auto& right) {
                return left.addr == right.addr && left.name == right.name;
            }),
            record.globals.end());

        const auto prototype = bounded_optional_text(
            snapshot.prototype, limits.max_text_bytes, diagnostics,
            static_cast<std::uint32_t>(10 + index), "component_function", address);
        functions.push_back(json{
            {"addr", record.canonical_addr},
            {"name", record.display_name},
            {"size", snapshot.size},
            {"prototype", prototype ? json(*prototype) : json(nullptr)},
            {"basic_blocks", snapshot.basic_block_count},
            {"complexity", snapshot.cyclomatic_complexity},
            {"callees", record.callees},
            {"strings", record.strings},
        });
        records.push_back(std::move(record));
    }

    std::map<std::string, std::string> alias_to_addr;
    std::map<std::string, std::string> name_by_addr;
    for (const auto& record : records) {
        alias_to_addr.emplace(record.canonical_addr, record.canonical_addr);
        alias_to_addr.emplace(record.display_name, record.canonical_addr);
        name_by_addr.emplace(record.canonical_addr, record.display_name);
    }

    std::set<std::tuple<std::string, std::string, std::string>> edge_set;
    std::vector<std::string> interface_functions;
    std::vector<std::string> internal_only;
    std::map<std::pair<std::string, std::string>, std::set<std::string>> global_users;
    std::map<std::string, std::set<std::string>> string_users;
    for (const auto& record : records) {
        bool has_external_interface = false;
        for (const auto& callee : record.callees) {
            const auto internal = alias_to_addr.find(callee);
            if (internal == alias_to_addr.end()) {
                has_external_interface = true;
                continue;
            }
            const auto name = name_by_addr.find(internal->second);
            edge_set.emplace(
                record.canonical_addr, internal->second,
                name == name_by_addr.end() ? internal->second : name->second);
        }
        for (const auto& caller : record.callers) {
            if (alias_to_addr.find(caller) == alias_to_addr.end()) {
                has_external_interface = true;
            }
        }
        (has_external_interface ? interface_functions : internal_only).push_back(record.canonical_addr);
        for (const auto& global : record.globals) {
            global_users[{global.addr, global.name}].insert(record.canonical_addr);
        }
        for (const auto& value : record.strings) {
            string_users[value].insert(record.canonical_addr);
        }
    }

    std::vector<std::string> nodes;
    nodes.reserve(name_by_addr.size());
    for (const auto& [address, name] : name_by_addr) {
        static_cast<void>(name);
        nodes.push_back(address);
    }
    sort_unique(interface_functions);
    sort_unique(internal_only);
    json edges = json::array();
    for (const auto& [from, to, name] : edge_set) {
        edges.push_back(json{{"from", from}, {"to", to}, {"name", name}});
    }
    json shared_globals = json::array();
    for (const auto& [identity, users] : global_users) {
        if (users.size() < 2) {
            continue;
        }
        shared_globals.push_back(json{
            {"addr", identity.first},
            {"name", identity.second},
            {"accessed_by", std::vector<std::string>(users.begin(), users.end())},
        });
    }
    json string_usage = json::object();
    for (const auto& [value, users] : string_users) {
        string_usage[value] = std::vector<std::string>(users.begin(), users.end());
    }
    json output{
        {"functions", std::move(functions)},
        {"internal_call_graph", json{{"nodes", nodes}, {"edges", std::move(edges)}}},
        {"interface_functions", interface_functions},
        {"internal_only", internal_only},
        {"shared_globals", std::move(shared_globals)},
        {"string_usage", std::move(string_usage)},
    };
    return finalize(
        "analyze_component", "Component analysis completed.", std::move(output), diagnostics,
        budget, context, overlay_generation, overlay_generation);
}

bound_outcome_t composite_handlers_t::impl_t::diff_before_after(
    const adapter_call_context_t& context,
    const json& arguments,
    const invocation_state_t& state) const {
    if (state.cancellation.cancelled()) {
        return cancelled_outcome(context, "diff_before_after.preflight");
    }
    const auto address = required_argument_string(arguments, "addr", limits.max_address_bytes);
    const auto action = required_argument_string(arguments, "action", 64);
    const auto action_arguments = arguments.find("action_args");
    if (!address) {
        return invalid_input_outcome(context, "addr", "address must be non-empty bounded UTF-8 text");
    }
    if (!action || (*action != "rename_func" && *action != "set_type" && *action != "set_comment")) {
        return invalid_input_outcome(
            context, "action", "action must be rename_func, set_type, or set_comment");
    }
    if (action_arguments == arguments.end() || !action_arguments->is_object()) {
        return invalid_input_outcome(context, "action_args", "action arguments must be an object");
    }

    const char* argument_name = *action == "rename_func"
        ? "name"
        : *action == "set_type" ? "type" : "comment";
    const auto value = action_arguments->find(argument_name);
    if (value == action_arguments->end() || !value->is_string()) {
        return invalid_input_outcome(context, argument_name, "the selected action requires a string value");
    }
    const auto& raw_value = value->get_ref<const std::string&>();
    const bool allow_empty = *action == "set_comment";
    const std::uint64_t maximum = *action == "rename_func"
        ? limits.max_identifier_bytes
        : limits.max_text_bytes;
    if (!valid_text(raw_value, maximum, allow_empty)) {
        return invalid_input_outcome(
            context, argument_name, "the selected action value is invalid or exceeds its bound");
    }

    budget_t budget{state.quota};
    diagnostic_log_t diagnostics(limits.max_diagnostics);
    std::optional<std::uint64_t> overlay_before = state.options.expected_overlay_generation;
    std::optional<std::string> before_text;
    std::optional<std::string> after_text;

    composite_step_request_t before_request;
    before_request.kind = composite_step_kind_t::decompile_function;
    before_request.subject = *address;
    before_request.expected_overlay_generation = overlay_before;
    before_request.max_items = 1;
    before_request.max_bytes = (std::min)(limits.max_text_bytes, budget.remaining_bytes());
    const auto before = run_step(
        context, state, budget, diagnostics, 10, "before_decompile", std::move(before_request));
    if (before.cancelled) {
        return cancelled_outcome(context, "diff_before_after.before_decompile");
    }
    if (!before.accepted) {
        if (state.options.expected_overlay_generation && before.response.observed_overlay_generation &&
            *state.options.expected_overlay_generation != *before.response.observed_overlay_generation) {
            return generation_failure(
                context, "before_decompile", state.options.expected_overlay_generation,
                before.response.observed_overlay_generation);
        }
        return failed_outcome(
            result_error_code_t::handler_failed,
            "Before-state decompilation could not be pinned.",
            json{{"phase", "before_decompile"}, {"diagnostics", diagnostics.ordered_json()}},
            target_metadata(context));
    }
    overlay_before = before.response.observed_overlay_generation;
    const auto& before_snapshot = std::get<composite_text_snapshot_t>(before.response.payload);
    before_text = bounded_optional_text(
        before_snapshot.text, limits.max_text_bytes, diagnostics, 10,
        "before_decompile", *address);
    if (!before_snapshot.error.empty()) {
        diagnostics.add(10, "before_decompile", *address, "COMPOSITE_DECOMPILER_PARTIAL",
                        before_snapshot.error);
    }
    if (state.cancellation.cancelled()) {
        return cancelled_outcome(context, "diff_before_after.pre_mutation");
    }

    composite_step_request_t mutation_request;
    mutation_request.kind = composite_step_kind_t::apply_overlay_action;
    mutation_request.subject = *address;
    mutation_request.action = *action;
    mutation_request.action_arguments = *action_arguments;
    mutation_request.expected_overlay_generation = overlay_before;
    mutation_request.max_items = 1;
    mutation_request.max_bytes = (std::min)(limits.max_text_bytes, budget.remaining_bytes());
    const auto mutation = run_step(
        context, state, budget, diagnostics, 20, "overlay_mutation", std::move(mutation_request));
    if (mutation.cancelled) {
        return cancelled_outcome(context, "diff_before_after.overlay_mutation");
    }
    if (!mutation.accepted) {
        if (mutation.response.observed_overlay_generation && overlay_before &&
            *mutation.response.observed_overlay_generation != *overlay_before) {
            return generation_failure(
                context, "overlay_mutation", overlay_before,
                mutation.response.observed_overlay_generation);
        }
        return failed_outcome(
            result_error_code_t::handler_failed,
            "Overlay action was not applied.",
            json{{"phase", "overlay_mutation"}, {"diagnostics", diagnostics.ordered_json()}},
            target_metadata(context));
    }
    const auto& mutation_result = std::get<composite_overlay_result_t>(mutation.response.payload);
    if (mutation.response.status != composite_step_status_t::complete || !mutation_result.applied ||
        !mutation.response.committed_overlay_generation || !overlay_before ||
        *mutation.response.committed_overlay_generation <= *overlay_before) {
        return failed_outcome(
            result_error_code_t::handler_failed,
            "Overlay action did not produce a committed generation.",
            json{
                {"phase", "overlay_mutation"},
                {"observed_overlay_generation", mutation.response.observed_overlay_generation},
                {"committed_overlay_generation", mutation.response.committed_overlay_generation},
            },
            target_metadata(context));
    }
    const auto overlay_after = mutation.response.committed_overlay_generation;

    if (state.cancellation.cancelled()) {
        diagnostics.add(25, "post_commit", *address, "COMPOSITE_CANCELLED_AFTER_COMMIT",
                        "the overlay action committed before cancellation was observed");
    } else {
        composite_step_request_t after_request;
        after_request.kind = composite_step_kind_t::decompile_function;
        after_request.subject = *address;
        after_request.expected_overlay_generation = overlay_after;
        after_request.max_items = 1;
        after_request.max_bytes = (std::min)(limits.max_text_bytes, budget.remaining_bytes());
        const auto after = run_step(
            context, state, budget, diagnostics, 30, "after_decompile", std::move(after_request));
        if (after.cancelled) {
            diagnostics.add(30, "after_decompile", *address, "COMPOSITE_CANCELLED_AFTER_COMMIT",
                            "the overlay action committed before cancellation was observed");
        } else if (after.accepted) {
            const auto& after_snapshot = std::get<composite_text_snapshot_t>(after.response.payload);
            after_text = bounded_optional_text(
                after_snapshot.text, limits.max_text_bytes, diagnostics, 30,
                "after_decompile", *address);
            if (!after_snapshot.error.empty()) {
                diagnostics.add(30, "after_decompile", *address, "COMPOSITE_DECOMPILER_PARTIAL",
                                after_snapshot.error);
            }
        }
    }

    const std::string applied = valid_text(
        mutation_result.action_applied, limits.max_identifier_bytes, true)
        ? mutation_result.action_applied
        : *action;
    json output{
        {"before", before_text ? json(*before_text) : json(nullptr)},
        {"after", after_text ? json(*after_text) : json(nullptr)},
        {"action_applied", applied},
        {"changes_detected", before_text && after_text && *before_text != *after_text},
    };
    return finalize(
        "diff_before_after", "Overlay action and comparison completed.", std::move(output),
        diagnostics, budget, context, overlay_before, overlay_after);
}

bound_outcome_t composite_handlers_t::impl_t::trace_data_flow(
    const adapter_call_context_t& context,
    const json& arguments,
    const invocation_state_t& state) const {
    if (state.cancellation.cancelled()) {
        return cancelled_outcome(context, "trace_data_flow.preflight");
    }
    const auto start = required_argument_string(arguments, "addr", limits.max_address_bytes);
    if (!start) {
        return invalid_input_outcome(context, "addr", "address must be non-empty bounded UTF-8 text");
    }
    const std::string direction = arguments.value("direction", std::string("forward"));
    if (direction != "forward" && direction != "backward") {
        return invalid_input_outcome(context, "direction", "direction must be forward or backward");
    }
    std::uint64_t requested_depth = 5;
    const auto depth_iterator = arguments.find("max_depth");
    if (depth_iterator != arguments.end()) {
        const auto parsed = json_unsigned(*depth_iterator);
        if (!parsed) {
            return invalid_input_outcome(context, "max_depth", "maximum depth must be a non-negative integer");
        }
        requested_depth = *parsed;
    }

    budget_t budget{state.quota};
    diagnostic_log_t diagnostics(limits.max_diagnostics);
    constexpr std::uint64_t maximum_contract_depth = 20;
    const std::uint64_t maximum_depth = (std::min)(requested_depth, maximum_contract_depth);
    if (requested_depth > maximum_contract_depth) {
        diagnostics.add(1, "trace_input", *start, "COMPOSITE_TRACE_DEPTH_LIMIT",
                        "maximum traversal depth was clamped to the contract limit");
    }
    std::optional<std::uint64_t> overlay_generation = state.options.expected_overlay_generation;

    struct queue_entry_t final {
        std::string addr;
        std::uint64_t depth = 0;
    };
    struct node_t final {
        std::string addr;
        std::optional<std::string> function;
        std::optional<std::string> instruction;
        std::string type;
        std::optional<std::string> name;
        std::uint64_t depth = 0;
    };

    std::deque<queue_entry_t> queue;
    queue.push_back({*start, 0});
    std::unordered_set<std::string> visited;
    visited.insert(*start);
    std::vector<node_t> nodes;
    std::set<std::tuple<std::string, std::string, std::string>> edges;
    std::uint64_t depth_reached = 0;
    bool capacity_reached = false;

    while (!queue.empty()) {
        if (state.cancellation.cancelled()) {
            return cancelled_outcome(context, "trace_data_flow.traversal");
        }
        const queue_entry_t current = std::move(queue.front());
        queue.pop_front();
        depth_reached = (std::max)(depth_reached, current.depth);

        node_t node;
        node.addr = current.addr;
        node.type = "unknown";
        node.depth = current.depth;
        composite_step_request_t node_request;
        node_request.kind = composite_step_kind_t::address_snapshot;
        node_request.subject = current.addr;
        node_request.expected_overlay_generation = overlay_generation;
        node_request.max_items = 1;
        node_request.max_bytes = (std::min)(limits.max_text_bytes, budget.remaining_bytes());
        const auto snapshot = run_step(
            context, state, budget, diagnostics,
            static_cast<std::uint32_t>(10 + current.depth * 2),
            "trace_node", std::move(node_request));
        if (snapshot.cancelled) {
            return cancelled_outcome(context, "trace_data_flow.address_snapshot");
        }
        if (snapshot.accepted) {
            overlay_generation = snapshot.response.observed_overlay_generation;
            const auto& value = std::get<composite_address_snapshot_t>(snapshot.response.payload);
            if (valid_text(value.addr, limits.max_address_bytes)) {
                node.addr = value.addr;
            } else {
                diagnostics.add(
                    static_cast<std::uint32_t>(10 + current.depth * 2), "trace_node", current.addr,
                    "COMPOSITE_ADDRESS_INVALID", "the address snapshot returned an invalid address");
            }
            node.function = bounded_optional_text(
                value.function, limits.max_identifier_bytes, diagnostics,
                static_cast<std::uint32_t>(10 + current.depth * 2), "trace_node", current.addr);
            node.instruction = bounded_optional_text(
                value.instruction, limits.max_text_bytes, diagnostics,
                static_cast<std::uint32_t>(10 + current.depth * 2), "trace_node", current.addr);
            node.name = bounded_optional_text(
                value.name, limits.max_identifier_bytes, diagnostics,
                static_cast<std::uint32_t>(10 + current.depth * 2), "trace_node", current.addr);
            if (valid_text(value.type, limits.max_identifier_bytes)) {
                node.type = value.type;
            }
        }
        nodes.push_back(std::move(node));
        if (snapshot.quota_exhausted || current.depth >= maximum_depth) {
            if (snapshot.quota_exhausted) {
                capacity_reached = true;
                break;
            }
            continue;
        }

        composite_step_request_t neighbors_request;
        neighbors_request.kind = composite_step_kind_t::xref_neighbors;
        neighbors_request.subject = current.addr;
        neighbors_request.direction = direction;
        neighbors_request.expected_overlay_generation = overlay_generation;
        neighbors_request.max_items = limits.max_neighbors_per_node;
        neighbors_request.max_bytes = (std::min)(limits.max_text_bytes, budget.remaining_bytes());
        const auto neighbors_step = run_step(
            context, state, budget, diagnostics,
            static_cast<std::uint32_t>(11 + current.depth * 2),
            "trace_neighbors", std::move(neighbors_request));
        if (neighbors_step.cancelled) {
            return cancelled_outcome(context, "trace_data_flow.xref_neighbors");
        }
        if (!neighbors_step.accepted) {
            if (neighbors_step.quota_exhausted) {
                capacity_reached = true;
                break;
            }
            continue;
        }
        overlay_generation = neighbors_step.response.observed_overlay_generation;
        auto neighbors = std::get<composite_xref_batch_t>(neighbors_step.response.payload).neighbors;
        std::sort(neighbors.begin(), neighbors.end(), [](const auto& left, const auto& right) {
            return std::tie(left.addr, left.type) < std::tie(right.addr, right.type);
        });
        neighbors.erase(
            std::unique(neighbors.begin(), neighbors.end(), [](const auto& left, const auto& right) {
                return left.addr == right.addr && left.type == right.type;
            }),
            neighbors.end());
        for (const auto& neighbor : neighbors) {
            if (!valid_text(neighbor.addr, limits.max_address_bytes) ||
                !valid_text(neighbor.type, limits.max_identifier_bytes)) {
                diagnostics.add(
                    static_cast<std::uint32_t>(11 + current.depth * 2), "trace_neighbors", current.addr,
                    "COMPOSITE_XREF_INVALID", "the xref batch returned an invalid neighbor");
                continue;
            }
            if (edges.size() >= limits.max_trace_edges) {
                diagnostics.add(500, "trace_capacity", current.addr, "COMPOSITE_TRACE_EDGE_LIMIT",
                                "additional trace edges were omitted by the configured bound");
                capacity_reached = true;
                break;
            }
            if (direction == "forward") {
                edges.emplace(current.addr, neighbor.addr, neighbor.type);
            } else {
                edges.emplace(neighbor.addr, current.addr, neighbor.type);
            }
            if (visited.find(neighbor.addr) != visited.end()) {
                continue;
            }
            if (visited.size() >= limits.max_trace_nodes) {
                diagnostics.add(500, "trace_capacity", current.addr, "COMPOSITE_TRACE_NODE_LIMIT",
                                "additional trace nodes were omitted by the configured bound");
                capacity_reached = true;
                break;
            }
            visited.insert(neighbor.addr);
            queue.push_back({neighbor.addr, current.depth + 1});
        }
        if (capacity_reached) {
            break;
        }
    }

    std::sort(nodes.begin(), nodes.end(), [](const node_t& left, const node_t& right) {
        return std::tie(left.depth, left.addr) < std::tie(right.depth, right.addr);
    });
    json output_nodes = json::array();
    for (const auto& node : nodes) {
        output_nodes.push_back(json{
            {"addr", node.addr},
            {"func", node.function ? json(*node.function) : json(nullptr)},
            {"instruction", node.instruction ? json(*node.instruction) : json(nullptr)},
            {"type", node.type},
            {"name", node.name ? json(*node.name) : json(nullptr)},
            {"depth", node.depth},
        });
    }
    json output_edges = json::array();
    for (const auto& [from, to, type] : edges) {
        output_edges.push_back(json{{"from", from}, {"to", to}, {"type", type}});
    }
    json output{
        {"start", *start},
        {"direction", direction},
        {"depth_reached", depth_reached},
        {"nodes", std::move(output_nodes)},
        {"edges", std::move(output_edges)},
    };
    return finalize(
        "trace_data_flow", "Data-flow trace completed.", std::move(output), diagnostics,
        budget, context, overlay_generation, overlay_generation);
}

composite_handlers_t::composite_handlers_t(
    composite_backend_t backend,
    composite_limits_t limits)
    : impl_(std::make_unique<impl_t>()) {
    impl_->backend = std::move(backend);
    impl_->limits = std::move(limits);
}

composite_handlers_t::~composite_handlers_t() = default;

const composite_limits_t& composite_handlers_t::limits() const noexcept {
    return impl_->limits;
}

protocol::mcp_result_t composite_handlers_t::invoke(
    std::string_view tool_name,
    const protocol::json& arguments,
    workspace_adapter_t& adapter,
    protocol::schema_runtime_t& schemas,
    const protocol::cancellation_token_t& cancellation,
    const composite_invocation_options_t& options,
    const protocol::json& aida_metadata) {
    if (!is_composite_name(tool_name)) {
        return mcp_result_t::failure(
            result_error_code_t::invalid_contract,
            "Composite tool contract is not supported.",
            json{{"tool", std::string(tool_name)}});
    }
    const auto* descriptor = find_contract(tool_name);
    if (descriptor == nullptr) {
        return mcp_result_t::failure(
            result_error_code_t::invalid_contract,
            "Generated composite tool contract is unavailable.",
            json{{"tool", std::string(tool_name)}});
    }
    const bool mutation = tool_name == "diff_before_after";
    const std::string expected_adapter =
        "aida::standalone::mcp::compat::adapters::" + std::string(tool_name);
    const bool descriptor_identity_valid = descriptor->name == tool_name &&
        descriptor->adapter_symbol == expected_adapter && descriptor->archive_backed;
    const bool descriptor_effect_valid = mutation
        ? descriptor->effect == contract_effect_t::workspace_overlay_mutation &&
            descriptor->lock == contract_lock_t::workspace_overlay_transaction &&
            !descriptor->read_only && descriptor->unsafe
        : descriptor->effect == contract_effect_t::workspace_read &&
            descriptor->lock == contract_lock_t::workspace_shared && descriptor->read_only &&
            !descriptor->unsafe;
    if (!descriptor_identity_valid || !descriptor_effect_valid ||
        !descriptor->target_dependent || !descriptor->accepts_pid ||
        !descriptor->accepts_bin_name) {
        return mcp_result_t::failure(
            result_error_code_t::invalid_contract,
            "Generated composite identity, effect, or routing policy is invalid.",
            json{{"tool", std::string(tool_name)}});
    }
    const auto contract = protocol_contract_for(*descriptor);
    if (!contract) {
        return mcp_result_t::failure(
            result_error_code_t::invalid_contract,
            "Generated composite schemas could not be decoded.",
            json{{"tool", std::string(tool_name)}});
    }
    const auto contract_validation = protocol::validate_tool_contract(*contract, schemas);
    if (!contract_validation.valid) {
        return mcp_result_t::failure(
            contract_validation.error_code,
            "Generated composite contract validation failed.",
            contract_validation.diagnostics());
    }
    if (!valid_limits(impl_->limits) || !impl_->backend) {
        return mcp_result_t::failure(
            result_error_code_t::invalid_contract,
            "Composite limits or backend configuration is invalid.",
            json{{"tool", std::string(tool_name)}});
    }

    const composite_quota_t quota = options.quota.value_or(impl_->limits.hard_quota);
    if (!valid_quota(quota) || !quota_within(quota, impl_->limits.hard_quota)) {
        return mcp_result_t::failure(
            result_error_code_t::invalid_input,
            "Composite invocation quota is invalid.",
            json{{"field", "invocation_options.quota"}});
    }
    const auto now = std::chrono::steady_clock::now();
    const auto timeout = tool_name == "analyze_component"
        ? impl_->limits.component_timeout
        : mutation ? impl_->limits.mutation_timeout : impl_->limits.read_timeout;
    auto deadline = now + timeout;
    if (options.deadline && *options.deadline < deadline) {
        deadline = *options.deadline;
    }
    if (deadline <= now) {
        return mcp_result_t::failure(
            result_error_code_t::handler_failed,
            "Composite invocation deadline has already elapsed.",
            json{{"field", "invocation_options.deadline"}});
    }

    auto state = std::make_shared<impl_t::invocation_state_t>();
    state->tool_name.assign(tool_name.data(), tool_name.size());
    state->cancellation = cancellation;
    state->options = options;
    state->quota = quota;
    state->deadline = deadline;
    const std::uint64_t invocation_id = impl_->register_invocation(state);
    scope_exit_t cleanup([this, invocation_id] {
        impl_->unregister_invocation(invocation_id);
    });

    const auto handler = [this, &adapter, invocation_id, state](
                             const json& validated_arguments,
                             const cancellation_token_t&) -> mcp_result_t {
        const std::uint64_t encoded_input_bytes = json_bytes(validated_arguments);
        if (encoded_input_bytes == (std::numeric_limits<std::uint64_t>::max)() ||
            encoded_input_bytes > impl_->limits.max_input_bytes) {
            return mcp_result_t::failure(
                result_error_code_t::invalid_input,
                "Composite arguments exceed the bounded input size.",
                json{{"limit", impl_->limits.max_input_bytes}, {"actual", encoded_input_bytes}});
        }

        adapter_request_t request;
        const auto pid = validated_arguments.find("pid");
        if (pid != validated_arguments.end()) {
            const auto parsed = json_unsigned(*pid);
            if (!parsed || *parsed == 0 || *parsed > (std::numeric_limits<std::uint32_t>::max)()) {
                return mcp_result_t::failure(
                    result_error_code_t::invalid_input,
                    "The pid selector is outside the supported range.",
                    json{{"field", "pid"}});
            }
            request.target.pid = static_cast<std::uint32_t>(*parsed);
        }
        const auto bin_name = validated_arguments.find("bin_name");
        if (bin_name != validated_arguments.end()) {
            std::string value = trim_ascii(bin_name->get_ref<const std::string&>());
            if (!valid_text(value, impl_->limits.max_identifier_bytes)) {
                return mcp_result_t::failure(
                    result_error_code_t::invalid_input,
                    "The bin_name selector is invalid.",
                    json{{"field", "bin_name"}});
            }
            request.target.bin_name = std::move(value);
        }
        request.expected_generation = state->options.expected_workspace_generation;
        request.deadline = state->deadline;
        const json envelope{
            {"schema_version", k_internal_schema_version},
            {"invocation_id", invocation_id},
            {"arguments", validated_arguments},
        };
        try {
            request.payload = envelope.dump();
        } catch (...) {
            return mcp_result_t::failure(
                result_error_code_t::invalid_input,
                "Composite arguments could not be encoded.",
                json{{"field", "arguments"}});
        }

        auto response = state->tool_name == "diff_before_after"
            ? adapter.overlay(state->tool_name, request)
            : adapter.analyze(state->tool_name, request);
        if (!response) {
            const auto& error = response.error();
            return mcp_result_t::failure(
                adapter_result_code(error.code),
                "Composite routing or effect policy rejected the invocation.",
                json{
                    {"adapter_code", std::string(error.stable_code)},
                    {"expected", error.expected},
                    {"actual", error.actual},
                });
        }

        json bound = json::parse(response.value().payload, nullptr, false);
        if (bound.is_discarded() || !bound.is_object() || !bound.contains("status") ||
            !bound["status"].is_string()) {
            return mcp_result_t::failure(
                result_error_code_t::invalid_output,
                "Composite backend returned an invalid envelope.",
                json{{"phase", "bound_response"}});
        }
        const auto status = bound["status"].get_ref<const std::string&>();
        if (status == "success") {
            if (!bound.contains("text") || !bound["text"].is_string() ||
                !bound.contains("structured_content") || !bound["structured_content"].is_object() ||
                !bound.contains("aida_metadata") || !bound["aida_metadata"].is_object()) {
                return mcp_result_t::failure(
                    result_error_code_t::invalid_output,
                    "Composite backend success envelope is invalid.",
                    json{{"phase", "bound_response"}});
            }
            return mcp_result_t::success(
                bound["text"].get<std::string>(),
                bound["structured_content"],
                bound["aida_metadata"]);
        }
        if (status != "error" || !bound.contains("error_code") ||
            !bound["error_code"].is_string() || !bound.contains("text") ||
            !bound["text"].is_string() || !bound.contains("details") ||
            !bound["details"].is_object() || !bound.contains("aida_metadata") ||
            !bound["aida_metadata"].is_object()) {
            return mcp_result_t::failure(
                result_error_code_t::invalid_output,
                "Composite backend error envelope is invalid.",
                json{{"phase", "bound_response"}});
        }
        const auto code = result_code_from_name(bound["error_code"].get_ref<const std::string&>());
        if (!code) {
            return mcp_result_t::failure(
                result_error_code_t::invalid_output,
                "Composite backend returned an unknown error code.",
                json{{"phase", "bound_response"}});
        }
        return mcp_result_t::failure(
            *code,
            bound["text"].get<std::string>(),
            bound["details"],
            bound["aida_metadata"]);
    };

    const cancellation_token_t protocol_cancellation = mutation
        ? cancellation_token_t::create(cancellation.cancelled())
        : cancellation;
    return protocol::invoke_tool_contract(
        *contract, arguments, handler, schemas, protocol_cancellation, aida_metadata);
}

adapter_result_t<adapter_response_t> composite_handlers_t::execute_bound(
    const adapter_call_context_t& context,
    const adapter_request_t& request) {
    const auto reject = [](std::string_view code) {
        return adapter_result_t<adapter_response_t>::failure(adapter_error_t{
            adapter_error_code_t::backend_rejected, code, 0, 0});
    };
    if (context.contract == nullptr || !context.target ||
        !is_composite_name(context.contract->name) || request.payload.empty() ||
        request.payload.size() > impl_->limits.max_input_bytes + 4096) {
        return reject("composite_bound_request_invalid");
    }
    const bool mutation = context.contract->name == "diff_before_after";
    if (mutation) {
        if (context.effect.effect != contract_effect_t::workspace_overlay_mutation ||
            context.effect.contract_lock != contract_lock_t::workspace_overlay_transaction ||
            context.effect.mode != effect_lock_mode_t::unique || !context.effect.mutates_workspace) {
            return reject("composite_bound_effect_invalid");
        }
    } else if (context.effect.effect != contract_effect_t::workspace_read ||
               context.effect.contract_lock != contract_lock_t::workspace_shared ||
               context.effect.mode != effect_lock_mode_t::shared || context.effect.mutates_workspace) {
        return reject("composite_bound_effect_invalid");
    }

    json envelope = json::parse(request.payload, nullptr, false);
    if (envelope.is_discarded() || !envelope.is_object() ||
        envelope.value("schema_version", 0ULL) != k_internal_schema_version ||
        !envelope.contains("invocation_id") || !envelope.contains("arguments") ||
        !envelope["arguments"].is_object()) {
        return reject("composite_bound_envelope_invalid");
    }
    const auto invocation_id = json_unsigned(envelope["invocation_id"]);
    if (!invocation_id || *invocation_id == 0) {
        return reject("composite_bound_invocation_invalid");
    }
    const auto state = impl_->find_invocation(*invocation_id);
    if (!state || state->tool_name != context.contract->name) {
        return reject("composite_bound_invocation_missing");
    }

    bound_outcome_t outcome;
    try {
        if (state->tool_name == "analyze_function") {
            outcome = impl_->analyze_function(context, envelope["arguments"], *state);
        } else if (state->tool_name == "analyze_component") {
            outcome = impl_->analyze_component(context, envelope["arguments"], *state);
        } else if (state->tool_name == "diff_before_after") {
            outcome = impl_->diff_before_after(context, envelope["arguments"], *state);
        } else if (state->tool_name == "trace_data_flow") {
            outcome = impl_->trace_data_flow(context, envelope["arguments"], *state);
        } else {
            return reject("composite_bound_tool_invalid");
        }
        const json serialized = serialize_outcome(outcome);
        adapter_response_t response;
        response.payload = serialized.dump();
        response.truncated = outcome.truncated;
        return adapter_result_t<adapter_response_t>::success(std::move(response));
    } catch (...) {
        return reject("composite_bound_execution_failed");
    }
}

}

namespace aida::standalone::mcp::compat::adapters {

protocol::mcp_result_t analyze_function(
    handlers::composite_handlers_t& handlers,
    workspace_adapter_t& adapter,
    protocol::schema_runtime_t& schemas,
    const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation,
    const handlers::composite_invocation_options_t& options,
    const protocol::json& aida_metadata) {
    return handlers.invoke(
        "analyze_function", arguments, adapter, schemas, cancellation, options, aida_metadata);
}

protocol::mcp_result_t analyze_component(
    handlers::composite_handlers_t& handlers,
    workspace_adapter_t& adapter,
    protocol::schema_runtime_t& schemas,
    const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation,
    const handlers::composite_invocation_options_t& options,
    const protocol::json& aida_metadata) {
    return handlers.invoke(
        "analyze_component", arguments, adapter, schemas, cancellation, options, aida_metadata);
}

protocol::mcp_result_t diff_before_after(
    handlers::composite_handlers_t& handlers,
    workspace_adapter_t& adapter,
    protocol::schema_runtime_t& schemas,
    const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation,
    const handlers::composite_invocation_options_t& options,
    const protocol::json& aida_metadata) {
    return handlers.invoke(
        "diff_before_after", arguments, adapter, schemas, cancellation, options, aida_metadata);
}

protocol::mcp_result_t trace_data_flow(
    handlers::composite_handlers_t& handlers,
    workspace_adapter_t& adapter,
    protocol::schema_runtime_t& schemas,
    const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation,
    const handlers::composite_invocation_options_t& options,
    const protocol::json& aida_metadata) {
    return handlers.invoke(
        "trace_data_flow", arguments, adapter, schemas, cancellation, options, aida_metadata);
}

}
