#include "semantic_refiner.hpp"
#include "pseudocode_readability.hpp"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#endif

namespace aida::analysis {

struct semantic_refiner_execution_state_t {
    std::atomic<bool> adapter_busy{false};
};

namespace {

constexpr auto k_worker_poll_interval = std::chrono::milliseconds(1);
constexpr auto k_worker_cancel_grace = std::chrono::milliseconds(2);

decompiler_diagnostic_t make_diagnostic(
    decompiler_diagnostic_code_t code,
    std::string key,
    const source_coordinate_t* coordinate,
    std::uint32_t& ordinal)
{
    decompiler_diagnostic_t result;
    result.severity = code == decompiler_diagnostic_code_t::invalid_contract ||
                             code == decompiler_diagnostic_code_t::unsupported_provider
        ? decompiler_diagnostic_severity_t::error
        : decompiler_diagnostic_severity_t::warning;
    result.code = code;
    result.localization_key = std::move(key);
    if (coordinate)
        result.coordinate = *coordinate;
    result.ordinal = ordinal++;
    return result;
}

decompiler_unknown_t make_unknown(
    const semantic_refinement_query_t& query,
    decompiler_unknown_reason_t reason,
    std::string token)
{
    decompiler_unknown_t result;
    result.reason = reason;
    result.stable_token = std::move(token);
    result.coordinate = query.coordinate;
    result.provenance = decompiler_fact_provenance_t::semantic_proof;
    return result;
}

bool valid_query(const semantic_refinement_query_t& query,
                 const decompiler_entity_key_t& entity,
                 std::uint32_t max_ir_nodes)
{
    triton_z3_proof_request_t request;
    request.entity = entity;
    request.coordinate = query.coordinate;
    request.ordinal = query.ordinal;
    request.stable_id = query.stable_id;
    request.static_ir = query.static_ir;
    request.refinement_key = query.refinement_key;
    request.limits = {1, 1, 1, max_ir_nodes};
    return valid_triton_z3_proof_request(request);
}

std::uint32_t profile_ir_limit(const decompiler_profile_budget_t& profile) noexcept
{
    constexpr auto adapter_limit = static_cast<std::uint64_t>(4096);
    return static_cast<std::uint32_t>(
        std::min(std::min(profile.max_hir_nodes, profile.max_ast_nodes), adapter_limit));
}

bool query_sequence_valid(const std::vector<semantic_refinement_query_t>& queries,
                          const decompiler_entity_key_t& entity,
                          std::uint32_t max_ir_nodes)
{
    if (max_ir_nodes == 0)
        return queries.empty();
    std::string previous_id;
    std::uint64_t expected_ordinal = 1;
    for (const auto& query : queries) {
        if (!valid_query(query, entity, max_ir_nodes) || query.ordinal != expected_ordinal ||
            (!previous_id.empty() && query.stable_id <= previous_id))
            return false;
        previous_id = query.stable_id;
        ++expected_ordinal;
    }
    return true;
}

decompiler_unknown_reason_t map_unknown_reason(triton_z3_unknown_reason_t value)
{
    switch (value) {
    case triton_z3_unknown_reason_t::solver_unknown:
        return decompiler_unknown_reason_t::provider_abstained;
    case triton_z3_unknown_reason_t::unsupported_semantics:
        return decompiler_unknown_reason_t::unsupported_instruction;
    case triton_z3_unknown_reason_t::resource_limit:
        return decompiler_unknown_reason_t::bounded_analysis_limit;
    case triton_z3_unknown_reason_t::dependency_unavailable:
    case triton_z3_unknown_reason_t::none:
        return decompiler_unknown_reason_t::provider_abstained;
    }
    return decompiler_unknown_reason_t::provider_abstained;
}

void append_pending_unknowns(
    semantic_refinement_result_t& result,
    const std::vector<semantic_refinement_query_t>& queries,
    std::size_t first,
    decompiler_unknown_reason_t reason,
    const std::string& prefix)
{
    for (std::size_t index = first; index < queries.size(); ++index)
        result.unknowns.push_back(make_unknown(queries[index], reason, prefix + ":" + queries[index].stable_id));
}

bool response_within_claimed_limits(
    const triton_z3_proof_response_t& response,
    const triton_z3_proof_limits_t& limits) noexcept
{
    return response.elapsed_wall_clock_ms <= limits.max_wall_clock_ms &&
           response.elapsed_cpu_ms <= limits.max_cpu_ms &&
           response.peak_memory_bytes <= limits.max_memory_bytes;
}

std::chrono::steady_clock::time_point deadline_after(
    std::chrono::steady_clock::time_point now,
    std::uint64_t milliseconds) noexcept
{
    const auto available = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::time_point::max() - now).count();
    if (available <= 0 || milliseconds >= static_cast<std::uint64_t>(available))
        return std::chrono::steady_clock::time_point::max();
    return now + std::chrono::milliseconds(milliseconds);
}

std::uint64_t remaining_milliseconds(
    std::chrono::steady_clock::time_point now,
    std::chrono::steady_clock::time_point deadline) noexcept
{
    if (now >= deadline)
        return 0;
    const auto nanoseconds = std::chrono::duration_cast<std::chrono::nanoseconds>(deadline - now).count();
    constexpr std::int64_t per_millisecond = 1000000;
    return static_cast<std::uint64_t>((nanoseconds + per_millisecond - 1) / per_millisecond);
}

bool remaining_limits(
    const decompiler_profile_budget_t& profile,
    std::chrono::steady_clock::time_point function_deadline,
    std::uint64_t consumed_cpu_ms,
    triton_z3_proof_limits_t& result) noexcept
{
    const auto now = std::chrono::steady_clock::now();
    if (now >= function_deadline || consumed_cpu_ms >= profile.max_cpu_ms)
        return false;
    result.max_wall_clock_ms = remaining_milliseconds(now, function_deadline);
    result.max_cpu_ms = profile.max_cpu_ms - consumed_cpu_ms;
    result.max_memory_bytes = profile.max_memory_bytes;
    result.max_ir_nodes = profile_ir_limit(profile);
    return valid_triton_z3_proof_limits(result);
}

std::uint64_t saturating_add(std::uint64_t lhs, std::uint64_t rhs) noexcept
{
    return rhs > std::numeric_limits<std::uint64_t>::max() - lhs
        ? std::numeric_limits<std::uint64_t>::max()
        : lhs + rhs;
}

std::uint64_t elapsed_milliseconds(
    std::chrono::steady_clock::time_point begin,
    std::chrono::steady_clock::time_point end) noexcept
{
    const auto nanoseconds = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin).count();
    if (nanoseconds <= 0)
        return 0;
    constexpr std::int64_t per_millisecond = 1000000;
    return static_cast<std::uint64_t>((nanoseconds + per_millisecond - 1) / per_millisecond);
}

#if defined(_WIN32)
bool thread_cpu_milliseconds(HANDLE thread, std::uint64_t& result) noexcept
{
    FILETIME created{};
    FILETIME exited{};
    FILETIME kernel{};
    FILETIME user{};
    if (GetThreadTimes(thread, &created, &exited, &kernel, &user) == 0)
        return false;
    ULARGE_INTEGER kernel_ticks{};
    kernel_ticks.LowPart = kernel.dwLowDateTime;
    kernel_ticks.HighPart = kernel.dwHighDateTime;
    ULARGE_INTEGER user_ticks{};
    user_ticks.LowPart = user.dwLowDateTime;
    user_ticks.HighPart = user.dwHighDateTime;
    const auto ticks = kernel_ticks.QuadPart + user_ticks.QuadPart;
    result = ticks == 0 ? 0 : (ticks + 9999ULL) / 10000ULL;
    return true;
}
#else
bool thread_cpu_milliseconds(std::thread::native_handle_type, std::uint64_t&) noexcept
{
    return false;
}
#endif

enum class proof_worker_terminal_t : std::uint8_t {
    completed = 1,
    caller_cancelled = 2,
    caller_deadline = 3,
    wall_limit = 4,
    cpu_limit = 5,
    adapter_busy = 6,
    launch_failure = 7,
    adapter_failure = 8,
    cpu_measurement_failure = 9
};

struct proof_worker_result_t {
    proof_worker_terminal_t terminal = proof_worker_terminal_t::launch_failure;
    triton_z3_proof_response_t response;
    std::uint64_t measured_wall_clock_ms = 0;
    std::uint64_t measured_cpu_ms = 0;
    bool invoked = false;
};

struct proof_worker_state_t {
    std::mutex mutex;
    std::condition_variable condition;
    triton_z3_proof_response_t response;
    bool complete = false;
    bool failed = false;
    bool cpu_valid = false;
    std::uint64_t cpu_ms = 0;
};

proof_worker_result_t bounded_prove(
    const std::shared_ptr<triton_z3_adapter_t>& adapter,
    const std::shared_ptr<semantic_refiner_execution_state_t>& execution_state,
    const triton_z3_proof_request_t& request,
    const cancellation_token_t& caller_cancel)
{
    proof_worker_result_t result;
    bool expected = false;
    if (!execution_state->adapter_busy.compare_exchange_strong(
            expected, true, std::memory_order_acq_rel, std::memory_order_acquire)) {
        result.terminal = proof_worker_terminal_t::adapter_busy;
        return result;
    }

    const auto begin = std::chrono::steady_clock::now();
    auto query_deadline = deadline_after(begin, request.limits.max_wall_clock_ms);
    const auto caller_deadline = caller_cancel.deadline();
    if (caller_deadline && *caller_deadline < query_deadline)
        query_deadline = *caller_deadline;
    cancellation_source_t worker_cancel(query_deadline);
    const auto worker_token = worker_cancel.token();
    const auto state = std::make_shared<proof_worker_state_t>();

    std::thread worker;
    try {
        worker = std::thread([adapter, execution_state, request, state, worker_token] {
            triton_z3_proof_response_t response;
            bool failed = false;
            try {
                response = adapter->prove(request, worker_token);
            } catch (...) {
                failed = true;
            }
            std::uint64_t cpu_ms = 0;
#if defined(_WIN32)
            const bool cpu_valid = thread_cpu_milliseconds(GetCurrentThread(), cpu_ms);
#else
            const bool cpu_valid = false;
#endif
            {
                std::lock_guard<std::mutex> lock(state->mutex);
                state->response = std::move(response);
                state->failed = failed;
                state->cpu_valid = cpu_valid;
                state->cpu_ms = cpu_ms;
                state->complete = true;
            }
            execution_state->adapter_busy.store(false, std::memory_order_release);
            state->condition.notify_all();
        });
        result.invoked = true;
    } catch (...) {
        execution_state->adapter_busy.store(false, std::memory_order_release);
        result.terminal = proof_worker_terminal_t::launch_failure;
        return result;
    }

    const auto finish_early = [&](proof_worker_terminal_t terminal) {
        worker_cancel.request_cancel();
        bool complete = false;
        {
            std::unique_lock<std::mutex> lock(state->mutex);
            state->condition.wait_for(lock, k_worker_cancel_grace, [&] { return state->complete; });
            complete = state->complete;
        }
        if (complete)
            worker.join();
        else
            worker.detach();
        result.terminal = terminal;
        result.measured_wall_clock_ms = elapsed_milliseconds(begin, std::chrono::steady_clock::now());
        return result;
    };

    for (;;) {
        {
            std::lock_guard<std::mutex> lock(state->mutex);
            if (state->complete)
                break;
        }
        if (caller_cancel.cancellation_requested())
            return finish_early(proof_worker_terminal_t::caller_cancelled);
        if (caller_cancel.deadline_exceeded())
            return finish_early(proof_worker_terminal_t::caller_deadline);
        if (std::chrono::steady_clock::now() >= query_deadline) {
            const auto terminal = caller_deadline && query_deadline == *caller_deadline
                ? proof_worker_terminal_t::caller_deadline
                : proof_worker_terminal_t::wall_limit;
            return finish_early(terminal);
        }
        std::uint64_t cpu_ms = 0;
        if (thread_cpu_milliseconds(worker.native_handle(), cpu_ms) && cpu_ms > request.limits.max_cpu_ms)
            return finish_early(proof_worker_terminal_t::cpu_limit);
        std::unique_lock<std::mutex> lock(state->mutex);
        auto wake = std::chrono::steady_clock::now() + k_worker_poll_interval;
        if (query_deadline < wake)
            wake = query_deadline;
        state->condition.wait_until(lock, wake, [&] { return state->complete; });
    }

    worker.join();
    result.measured_wall_clock_ms = elapsed_milliseconds(begin, std::chrono::steady_clock::now());
    {
        std::lock_guard<std::mutex> lock(state->mutex);
        result.response = state->response;
        result.measured_cpu_ms = state->cpu_ms;
        if (state->failed) {
            result.terminal = proof_worker_terminal_t::adapter_failure;
            return result;
        }
        if (!state->cpu_valid) {
            result.terminal = proof_worker_terminal_t::cpu_measurement_failure;
            return result;
        }
    }
    if (caller_cancel.cancellation_requested()) {
        result.terminal = proof_worker_terminal_t::caller_cancelled;
        return result;
    }
    if (caller_cancel.deadline_exceeded()) {
        result.terminal = proof_worker_terminal_t::caller_deadline;
        return result;
    }
    if (result.measured_wall_clock_ms > request.limits.max_wall_clock_ms) {
        result.terminal = proof_worker_terminal_t::wall_limit;
        return result;
    }
    if (result.measured_cpu_ms > request.limits.max_cpu_ms) {
        result.terminal = proof_worker_terminal_t::cpu_limit;
        return result;
    }
    result.terminal = proof_worker_terminal_t::completed;
    return result;
}

}

namespace {

bool rt_is_expression_kind(const typed_pseudocode_ast_node_kind_t kind) noexcept
{
    return kind == typed_pseudocode_ast_node_kind_t::assignment_expression ||
           kind == typed_pseudocode_ast_node_kind_t::unary_expression ||
           kind == typed_pseudocode_ast_node_kind_t::binary_expression ||
           kind == typed_pseudocode_ast_node_kind_t::cast_expression ||
           kind == typed_pseudocode_ast_node_kind_t::call_expression ||
           kind == typed_pseudocode_ast_node_kind_t::member_expression ||
           kind == typed_pseudocode_ast_node_kind_t::index_expression ||
           kind == typed_pseudocode_ast_node_kind_t::identifier ||
           kind == typed_pseudocode_ast_node_kind_t::literal ||
           kind == typed_pseudocode_ast_node_kind_t::unknown_expression;
}

bool rt_visible_text(const std::string& value) noexcept
{
    return !value.empty() && std::none_of(value.begin(), value.end(), [](const char c) {
        return c == '\r' || c == '\n' || c == '\0';
    });
}

bool rt_identifier_text(const std::string& value) noexcept
{
    if (!rt_visible_text(value))
        return false;
    bool component_start = true;
    for (std::size_t i = 0; i < value.size(); ++i) {
        const auto c = static_cast<unsigned char>(value[i]);
        if (component_start) {
            if (!(std::isalpha(c) != 0 || value[i] == '_' || value[i] == '$'))
                return false;
            component_start = false;
            continue;
        }
        if (std::isalnum(c) != 0 || value[i] == '_' || value[i] == '$')
            continue;
        if (value[i] == ':' && i + 1 < value.size() && value[i + 1] == ':') {
            ++i;
            component_start = true;
            continue;
        }
        return false;
    }
    return !component_start;
}

bool rt_is_unary_operator(const std::string& value) noexcept
{
    return value == "!" || value == "~" || value == "+" || value == "-" ||
           value == "*" || value == "&" || value == "++" || value == "--";
}

bool rt_is_binary_operator(const std::string& value) noexcept
{
    static const std::set<std::string> operators{
        "*", "/", "%", "+", "-", "<<", ">>", "<", "<=", ">", ">=",
        "==", "!=", "&", "^", "|", "&&", "||"};
    return operators.find(value) != operators.end();
}

bool rt_is_generated_name(const std::string& name)
{
    if (name.empty())
        return false;
    static const std::vector<std::pair<std::string, bool>> prefixes = {
        {"local_", true}, {"var_", true}, {"tmp_", true}, {"stack_", true},
        {"in_", true}, {"out_", true}, {"param_", true}, {"unaff_", false},
        {"unnamed_", false}, {"uVar", true}, {"puVar", true}, {"pVar", true},
        {"iVar", true}, {"uStack", true}, {"extraout_", false},
    };
    for (const auto& [prefix, require_digits] : prefixes) {
        if (name.size() > prefix.size() && name.compare(0, prefix.size(), prefix) == 0) {
            if (!require_digits)
                return true;
            const auto rest = name.substr(prefix.size());
            if (!rest.empty() && std::all_of(rest.begin(), rest.end(),
                    [](const unsigned char c) { return std::isdigit(c) != 0; }))
                return true;
        }
    }
    if (name.size() > 1 && name[0] == 'v' && std::all_of(name.begin() + 1, name.end(),
            [](const unsigned char c) { return std::isdigit(c) != 0; }))
        return true;
    if (name.size() > 3 && name.compare(0, 3, "arg") == 0 && std::all_of(name.begin() + 3, name.end(),
            [](const unsigned char c) { return std::isdigit(c) != 0; }))
        return true;
    return false;
}

std::string rt_sanitize_identifier(const std::string& value)
{
    if (value.empty())
        return "renamed";
    std::string result;
    result.reserve(value.size());
    bool first = true;
    for (const char c : value) {
        if (first) {
            if (std::isalpha(static_cast<unsigned char>(c)) != 0 || c == '_')
                result.push_back(c);
            else
                result.push_back('_');
            first = false;
        } else {
            if (std::isalnum(static_cast<unsigned char>(c)) != 0 || c == '_')
                result.push_back(c);
        }
    }
    if (result.empty())
        return "renamed";
    return result;
}

std::string rt_to_camel_case(const std::string& value)
{
    if (value.empty())
        return {};
    std::string result;
    result.reserve(value.size());
    bool capitalize_next = false;
    bool first_word = true;
    for (std::size_t i = 0; i < value.size(); ++i) {
        const auto c = static_cast<unsigned char>(value[i]);
        if (std::isalnum(c) != 0 || c == '_') {
            if (c == '_') {
                capitalize_next = true;
                continue;
            }
            if (first_word) {
                result.push_back(static_cast<char>(std::tolower(c)));
                first_word = false;
            } else if (capitalize_next) {
                result.push_back(static_cast<char>(std::toupper(c)));
                capitalize_next = false;
            } else {
                result.push_back(static_cast<char>(std::tolower(c)));
            }
        } else {
            capitalize_next = true;
        }
    }
    if (result.empty())
        return {};
    return rt_sanitize_identifier(result);
}

std::optional<std::int64_t> rt_parse_signed(const std::string& text)
{
    if (text.empty())
        return std::nullopt;
    std::string cleaned = text;
    if (cleaned.size() > 2 && cleaned[0] == '0' && (cleaned[1] == 'x' || cleaned[1] == 'X')) {
        try {
            return static_cast<std::int64_t>(std::stoull(cleaned, nullptr, 16));
        } catch (...) {
            return std::nullopt;
        }
    }
    if (!cleaned.empty() && cleaned.back() == 'L') {
        cleaned.pop_back();
        if (!cleaned.empty() && cleaned.back() == 'L')
            cleaned.pop_back();
    }
    if (!cleaned.empty() && cleaned.back() == 'U') {
        cleaned.pop_back();
        if (!cleaned.empty() && cleaned.back() == 'U')
            cleaned.pop_back();
    }
    try {
        std::size_t pos = 0;
        const auto value = std::stoll(cleaned, &pos);
        if (pos != cleaned.size())
            return std::nullopt;
        return value;
    } catch (...) {
        return std::nullopt;
    }
}

std::optional<std::uint64_t> rt_parse_unsigned(const std::string& text)
{
    if (text.empty())
        return std::nullopt;
    std::string cleaned = text;
    if (cleaned.size() > 2 && cleaned[0] == '0' && (cleaned[1] == 'x' || cleaned[1] == 'X')) {
        try {
            return std::stoull(cleaned, nullptr, 16);
        } catch (...) {
            return std::nullopt;
        }
    }
    if (!cleaned.empty() && cleaned.back() == 'L') {
        cleaned.pop_back();
        if (!cleaned.empty() && cleaned.back() == 'L')
            cleaned.pop_back();
    }
    if (!cleaned.empty() && cleaned.back() == 'U') {
        cleaned.pop_back();
        if (!cleaned.empty() && cleaned.back() == 'U')
            cleaned.pop_back();
    }
    try {
        std::size_t pos = 0;
        const auto value = std::stoull(cleaned, &pos);
        if (pos != cleaned.size())
            return std::nullopt;
        return value;
    } catch (...) {
        return std::nullopt;
    }
}

std::string rt_format_integer(std::uint64_t value)
{
    return std::to_string(value);
}

std::string rt_format_signed(std::int64_t value)
{
    return std::to_string(value);
}

const std::unordered_map<std::string, std::vector<std::string>>& rt_api_param_names()
{
    static const std::unordered_map<std::string, std::vector<std::string>> table{
        {"CreateFileW", {"filename", "access", "share_mode", "security", "creation_disposition", "flags", "template_handle"}},
        {"CreateFileA", {"filename", "access", "share_mode", "security", "creation_disposition", "flags", "template_handle"}},
        {"ReadFile", {"handle", "buffer", "bytes_to_read", "bytes_read", "overlapped"}},
        {"WriteFile", {"handle", "buffer", "bytes_to_write", "bytes_written", "overlapped"}},
        {"CloseHandle", {"handle"}},
        {"malloc", {"size"}},
        {"calloc", {"count", "size"}},
        {"realloc", {"ptr", "size"}},
        {"free", {"ptr"}},
        {"memcpy", {"dst", "src", "size"}},
        {"memmove", {"dst", "src", "size"}},
        {"memset", {"dst", "value", "size"}},
        {"memcmp", {"lhs", "rhs", "size"}},
        {"strcpy", {"dst", "src"}},
        {"strncpy", {"dst", "src", "count"}},
        {"strcat", {"dst", "src"}},
        {"strncat", {"dst", "src", "count"}},
        {"strcmp", {"lhs", "rhs"}},
        {"strncmp", {"lhs", "rhs", "count"}},
        {"strlen", {"str"}},
        {"strchr", {"str", "character"}},
        {"strrchr", {"str", "character"}},
        {"strstr", {"str", "substr"}},
        {"sprintf", {"buffer", "format"}},
        {"snprintf", {"buffer", "size", "format"}},
        {"_snprintf", {"buffer", "size", "format"}},
        {"printf", {"format"}},
        {"fprintf", {"stream", "format"}},
        {"fopen", {"filename", "mode"}},
        {"fopen_s", {"file_ptr", "filename", "mode"}},
        {"fclose", {"stream"}},
        {"fread", {"buffer", "size", "count", "stream"}},
        {"fwrite", {"buffer", "size", "count", "stream"}},
        {"fseek", {"stream", "offset", "origin"}},
        {"ftell", {"stream"}},
        {"VirtualAlloc", {"address", "size", "allocation_type", "protect"}},
        {"VirtualFree", {"address", "size", "free_type"}},
        {"VirtualProtect", {"address", "size", "new_protect", "old_protect"}},
        {"HeapAlloc", {"heap", "flags", "size"}},
        {"HeapFree", {"heap", "flags", "ptr"}},
        {"LoadLibraryW", {"filename"}},
        {"LoadLibraryA", {"filename"}},
        {"LoadLibraryExW", {"filename", "file", "flags"}},
        {"LoadLibraryExA", {"filename", "file", "flags"}},
        {"GetProcAddress", {"module", "name"}},
        {"GetModuleHandleW", {"module_name"}},
        {"GetModuleHandleA", {"module_name"}},
        {"GetLastError", {}},
        {"SetLastError", {"error_code"}},
        {"GetProcessId", {"process"}},
        {"GetThreadId", {"thread"}},
        {"CreateThread", {"attributes", "stack_size", "start_address", "parameter", "creation_flags", "thread_id"}},
        {"TerminateProcess", {"process", "exit_code"}},
        {"GetExitCodeProcess", {"process", "exit_code"}},
        {"WaitForSingleObject", {"handle", "milliseconds"}},
        {"WaitForMultipleObjects", {"count", "handles", "wait_all", "milliseconds"}},
        {"Sleep", {"milliseconds"}},
        {"GetEnvironmentVariableW", {"name", "buffer", "size"}},
        {"GetEnvironmentVariableA", {"name", "buffer", "size"}},
        {"SetEnvironmentVariableW", {"name", "value"}},
        {"SetEnvironmentVariableA", {"name", "value"}},
        {"GetCommandLineW", {}},
        {"GetCommandLineA", {}},
        {"lstrcpyW", {"dst", "src"}},
        {"lstrcpyA", {"dst", "src"}},
        {"lstrcpynW", {"dst", "src", "length"}},
        {"lstrcpynA", {"dst", "src", "length"}},
        {"lstrlenW", {"str"}},
        {"lstrlenA", {"str"}},
        {"MultiByteToWideChar", {"code_page", "flags", "multi_byte_str", "cb_multi_byte", "wide_char_str", "cch_wide_char"}},
        {"WideCharToMultiByte", {"code_page", "flags", "wide_char_str", "cch_wide_char", "multi_byte_str", "cb_multi_byte", "default_char", "used_default_char"}},
        {"RegOpenKeyExW", {"key", "subkey", "reserved", "access", "result"}},
        {"RegOpenKeyExA", {"key", "subkey", "reserved", "access", "result"}},
        {"RegQueryValueExW", {"key", "value_name", "reserved", "type", "data", "cbdata"}},
        {"RegSetValueExW", {"key", "value_name", "reserved", "type", "data", "cbdata"}},
        {"RegCloseKey", {"key"}},
        {"WSASocketW", {"af", "type", "protocol", "protocol_info", "group", "flags"}},
        {"socket", {"af", "type", "protocol"}},
        {"connect", {"sock", "address", "address_len"}},
        {"send", {"sock", "buffer", "length", "flags"}},
        {"recv", {"sock", "buffer", "length", "flags"}},
        {"bind", {"sock", "address", "address_len"}},
        {"listen", {"sock", "backlog"}},
        {"accept", {"sock", "address", "address_len"}},
        {"closesocket", {"sock"}},
    };
    return table;
}

std::optional<std::string> rt_suggest_api_name(const std::string& api_name, std::size_t param_index)
{
    const auto& table = rt_api_param_names();
    const auto it = table.find(api_name);
    if (it == table.end())
        return std::nullopt;
    if (param_index >= it->second.size())
        return std::nullopt;
    return it->second[param_index];
}

std::optional<std::string> rt_suggest_type_name(const std::string& type_display)
{
    if (type_display.empty())
        return std::nullopt;
    static const std::vector<std::pair<std::string, std::string>> exact_matches{
        {"HANDLE", "handle"}, {"PHANDLE", "handle_ptr"}, {"HMODULE", "module"},
        {"HINSTANCE", "instance"}, {"HWND", "hwnd"}, {"HMENU", "menu"},
        {"HBITMAP", "bitmap"}, {"HBRUSH", "brush"}, {"HCURSOR", "cursor"},
        {"HICON", "icon"}, {"HFONT", "font"}, {"HPEN", "pen"},
        {"HRGN", "region"}, {"HDC", "dc"}, {"PWSTR", "string"},
        {"LPWSTR", "string"}, {"LPCWSTR", "string"}, {"PSTR", "string"},
        {"LPSTR", "string"}, {"LPCSTR", "string"}, {"SIZE_T", "size"},
        {"DWORD", "value"}, {"ULONG", "value"}, {"ULONG_PTR", "value"},
        {"UINT", "value"}, {"UINT32", "value"}, {"UINT64", "value"},
        {"INT", "value"}, {"INT32", "value"}, {"INT64", "value"},
        {"LONG", "value"}, {"LONGLONG", "value"}, {"BOOL", "result"},
        {"BYTE", "byte"}, {"WORD", "word"}, {"QWORD", "qword"},
        {"PVOID", "ptr"}, {"LPVOID", "ptr"}, {"HKEY", "key"},
        {"SC_HANDLE", "service_handle"}, {"SOCKET", "sock"},
        {"time_t", "time"}, {"pid_t", "pid"}, {"size_t", "size"},
        {"ssize_t", "size"}, {"ptrdiff_t", "offset"}, {"wchar_t", "wchar"},
        {"char", "ch"}, {"FILE", "file"},
    };
    for (const auto& [pattern, name] : exact_matches) {
        if (type_display == pattern)
            return name;
    }
    static const std::vector<std::pair<std::string, std::string>> suffix_matches{
        {"*", "ptr"}, {"Ptr", "ptr"}, {"Pointer", "ptr"},
        {"Handle", "handle"}, {"Context", "ctx"}, {"Buffer", "buffer"},
        {"Callback", "callback"}, {"Event", "event"}, {"Stream", "stream"},
    };
    for (const auto& [pattern, name] : suffix_matches) {
        if (type_display.size() > pattern.size() && type_display.compare(
                type_display.size() - pattern.size(), pattern.size(), pattern) == 0)
            return name;
    }
    if (type_display.size() > 6 && type_display.compare(0, 4, "LPWC") == 0)
        return "string";
    if (type_display.size() > 5 && type_display.compare(0, 3, "LPW") == 0)
        return "string";
    if (type_display.size() > 5 && type_display.compare(0, 3, "LPC") == 0)
        return "string";
    return std::nullopt;
}

bool rt_node_has_side_effects(const typed_pseudocode_ast_v2_t& ast,
    std::uint64_t node_id,
    const std::unordered_map<std::uint64_t, std::size_t>& index,
    std::unordered_set<std::uint64_t>& visited,
    std::size_t& depth,
    std::size_t max_depth)
{
    if (depth >= max_depth || !visited.insert(node_id).second)
        return true;
    ++depth;
    const auto it = index.find(node_id);
    if (it == index.end()) {
        --depth;
        return true;
    }
    const auto& node = ast.nodes[it->second];
    if (node.kind == typed_pseudocode_ast_node_kind_t::call_expression ||
        node.kind == typed_pseudocode_ast_node_kind_t::assignment_expression ||
        node.kind == typed_pseudocode_ast_node_kind_t::unknown_expression) {
        --depth;
        return true;
    }
    for (const auto child_id : node.child_ids) {
        if (rt_node_has_side_effects(ast, child_id, index, visited, depth, max_depth)) {
            --depth;
            return true;
        }
    }
    --depth;
    return false;
}

bool rt_node_has_side_effects(const typed_pseudocode_ast_v2_t& ast,
    std::uint64_t node_id,
    const std::unordered_map<std::uint64_t, std::size_t>& index)
{
    std::unordered_set<std::uint64_t> visited;
    std::size_t depth = 0;
    return rt_node_has_side_effects(ast, node_id, index, visited, depth, 512);
}

struct rt_variable_info_t {
    std::string name;
    std::uint64_t type_id = 0;
    std::vector<std::uint64_t> declaration_ids;
    std::vector<std::uint64_t> identifier_ids;
    std::vector<std::uint64_t> assignment_target_ids;
    bool is_parameter = false;
    bool is_generated = false;
    bool is_loop_counter = false;
    int loop_depth = 0;
    std::optional<std::string> api_suggested_name;
    std::optional<std::string> type_suggested_name;
    std::optional<std::string> string_suggested_name;
    std::string final_suggested_name;
};

struct rt_def_use_entry_t {
    std::string variable;
    std::uint64_t statement_id = 0;
    std::uint64_t definition_node_id = 0;
    std::uint64_t initializer_node_id = 0;
    bool is_declaration = false;
    bool has_side_effects = false;
};

constexpr std::size_t k_max_transform_nodes = 10000;
constexpr std::size_t k_max_parent_chain_depth = 512;

class rt_transformer_t {
public:
    rt_transformer_t(
        typed_pseudocode_ast_v2_t& ast,
        const type_graph_t& type_graph,
        const readability_transform_settings_t& settings)
        : ast_(ast), type_graph_(type_graph), settings_(settings)
    {
        for (const auto& type : type_graph_.nodes)
            types_.emplace(type.id, &type);
    }

    readability_transform_result_t run()
    {
        readability_transform_result_t result;
        if (ast_.nodes.empty()) {
            result.diagnostics.push_back(rt_make_diagnostic(
                decompiler_diagnostic_code_t::malformed_ast,
                "readability.empty_ast", std::nullopt));
            return result;
        }
        if (ast_.nodes.size() > k_max_transform_nodes) {
            result.diagnostics.push_back(rt_make_diagnostic(
                decompiler_diagnostic_code_t::resource_limit,
                "readability.node_limit_exceeded", std::nullopt));
            return result;
        }
        build_index();
        collect_variable_info(ast_.root_node_id, 0, false, false);
        if (settings_.enable_loop_counter_naming)
            detect_loop_counters(ast_.root_node_id, 0);
        if (settings_.enable_api_call_naming)
            detect_api_calls(ast_.root_node_id);
        if (settings_.enable_string_reference_naming)
            detect_string_references(ast_.root_node_id);
        if (settings_.enable_type_based_naming)
            compute_type_based_names();
        compute_final_suggested_names();

        if (settings_.enable_variable_renaming && !variables_.empty())
            apply_renaming();

        for (std::size_t iteration = 0; iteration < settings_.max_transform_iterations; ++iteration) {
            bool changed = false;
            if (settings_.enable_expression_simplification)
                changed = simplify_expressions(ast_.root_node_id, 0, false) || changed;
            if (settings_.enable_temporary_coalescing) {
                definitions_.clear();
                uses_.clear();
                std::unordered_set<std::uint64_t> def_use_visited;
                collect_def_use(ast_.root_node_id, 0, def_use_visited);
                if (settings_.enable_single_use_inlining)
                    changed = apply_single_use_inlining() || changed;
                if (settings_.enable_copy_propagation)
                    changed = apply_copy_propagation() || changed;
                if (settings_.enable_dead_store_elimination)
                    changed = apply_dead_store_elimination() || changed;
            }
            if (!changed)
                break;
        }

        compact_ast();

        result.transformed = metrics_.variables_renamed > 0 ||
            metrics_.constants_folded > 0 || metrics_.identities_simplified > 0 ||
            metrics_.casts_simplified > 0 || metrics_.double_negations_simplified > 0 ||
            metrics_.comparisons_normalized > 0 || metrics_.compound_assignments_marked > 0 ||
            metrics_.temporaries_inlined > 0 || metrics_.copies_propagated > 0 ||
            metrics_.dead_stores_eliminated > 0 || metrics_.nodes_removed > 0;
        result.metrics = metrics_;
        result.diagnostics = std::move(diagnostics_);
        return result;
    }

private:
    typed_pseudocode_ast_v2_t& ast_;
    const type_graph_t& type_graph_;
    const readability_transform_settings_t settings_;
    readability_transform_metrics_t metrics_;
    std::vector<decompiler_diagnostic_t> diagnostics_;
    std::unordered_map<std::uint64_t, std::size_t> id_index_;
    std::unordered_map<std::uint64_t, std::pair<std::uint64_t, std::size_t>> parent_map_;
    std::unordered_map<std::uint64_t, const decompiler_type_node_t*> types_;
    std::map<std::string, rt_variable_info_t> variables_;
    std::vector<rt_def_use_entry_t> definitions_;
    std::unordered_map<std::string, std::vector<std::uint64_t>> uses_;
    std::uint32_t diagnostic_ordinal_ = 1;

    decompiler_diagnostic_t rt_make_diagnostic(
        decompiler_diagnostic_code_t code,
        std::string key,
        std::optional<source_coordinate_t> coordinate)
    {
        decompiler_diagnostic_t diag;
        diag.severity = decompiler_diagnostic_severity_t::warning;
        diag.code = code;
        diag.localization_key = std::move(key);
        diag.coordinate = std::move(coordinate);
        diag.confidence = 100;
        diag.ordinal = diagnostic_ordinal_++;
        return diag;
    }

    typed_pseudocode_ast_node_t* node(std::uint64_t id)
    {
        const auto it = id_index_.find(id);
        if (it == id_index_.end())
            return nullptr;
        return &ast_.nodes[it->second];
    }

    const typed_pseudocode_ast_node_t* node(std::uint64_t id) const
    {
        const auto it = id_index_.find(id);
        if (it == id_index_.end())
            return nullptr;
        return &ast_.nodes[it->second];
    }

    void build_index()
    {
        id_index_.clear();
        parent_map_.clear();
        for (std::size_t i = 0; i < ast_.nodes.size(); ++i) {
            id_index_.emplace(ast_.nodes[i].id, i);
            for (std::size_t j = 0; j < ast_.nodes[i].child_ids.size(); ++j)
                parent_map_.emplace(ast_.nodes[i].child_ids[j],
                    std::make_pair(ast_.nodes[i].id, j));
        }
    }

    void collect_variable_info(std::uint64_t node_id, int loop_depth, bool in_loop, bool is_param_context)
    {
        std::unordered_set<std::uint64_t> visited;
        collect_variable_info_impl(node_id, loop_depth, in_loop, is_param_context, 0, visited);
    }

    void collect_variable_info_impl(std::uint64_t node_id, int loop_depth, bool in_loop,
                                     bool is_param_context, std::size_t depth,
                                     std::unordered_set<std::uint64_t>& visited)
    {
        if (depth >= settings_.max_expression_depth ||
            !visited.insert(node_id).second)
            return;
        const auto* n = node(node_id);
        if (n == nullptr)
            return;
        const auto kind = n->kind;
        if (kind == typed_pseudocode_ast_node_kind_t::declaration) {
            auto& info = variables_[n->stable_text];
            info.name = n->stable_text;
            info.type_id = n->type_id;
            info.declaration_ids.push_back(node_id);
            info.is_parameter = is_param_context;
            info.is_generated = rt_is_generated_name(n->stable_text);
            if (!n->child_ids.empty()) {
                for (const auto child_id : n->child_ids)
                    collect_variable_info_impl(child_id, loop_depth, in_loop, false, depth + 1, visited);
            }
            return;
        }
        if (kind == typed_pseudocode_ast_node_kind_t::identifier) {
            const auto parent_it = parent_map_.find(node_id);
            bool is_assignment_target = false;
            if (parent_it != parent_map_.end()) {
                const auto* parent = node(parent_it->second.first);
                if (parent != nullptr &&
                    parent->kind == typed_pseudocode_ast_node_kind_t::assignment_expression &&
                    parent_it->second.second == 0) {
                    is_assignment_target = true;
                }
            }
            auto& info = variables_[n->stable_text];
            info.name = n->stable_text;
            info.type_id = n->type_id;
            if (is_assignment_target)
                info.assignment_target_ids.push_back(node_id);
            else
                info.identifier_ids.push_back(node_id);
            info.is_generated = rt_is_generated_name(n->stable_text);
            return;
        }
        if (kind == typed_pseudocode_ast_node_kind_t::function_definition) {
            for (std::size_t i = 0; i + 1 < n->child_ids.size(); ++i)
                collect_variable_info_impl(n->child_ids[i], loop_depth, in_loop, true, depth + 1, visited);
            if (!n->child_ids.empty())
                collect_variable_info_impl(n->child_ids.back(), loop_depth, in_loop, false, depth + 1, visited);
            return;
        }
        bool child_in_loop = in_loop ||
            kind == typed_pseudocode_ast_node_kind_t::while_statement ||
            kind == typed_pseudocode_ast_node_kind_t::do_while_statement ||
            kind == typed_pseudocode_ast_node_kind_t::for_statement;
        int child_loop_depth = loop_depth;
        if (kind == typed_pseudocode_ast_node_kind_t::while_statement ||
            kind == typed_pseudocode_ast_node_kind_t::do_while_statement ||
            kind == typed_pseudocode_ast_node_kind_t::for_statement)
            ++child_loop_depth;
        for (const auto child_id : n->child_ids)
            collect_variable_info_impl(child_id, child_loop_depth, child_in_loop, false, depth + 1, visited);
    }

    void detect_loop_counters(std::uint64_t node_id, int depth)
    {
        std::unordered_set<std::uint64_t> visited;
        detect_loop_counters_impl(node_id, depth, visited, 0);
    }

    void detect_loop_counters_impl(std::uint64_t node_id, int depth,
                                    std::unordered_set<std::uint64_t>& visited,
                                    std::size_t traversal_depth)
    {
        if (traversal_depth >= settings_.max_expression_depth ||
            !visited.insert(node_id).second)
            return;
        const auto* n = node(node_id);
        if (n == nullptr)
            return;
        if (n->kind == typed_pseudocode_ast_node_kind_t::for_statement) {
            if (n->child_ids.size() == 4) {
                const auto* init = node(n->child_ids[0]);
                std::string counter_name;
                if (init != nullptr && init->kind == typed_pseudocode_ast_node_kind_t::declaration)
                    counter_name = init->stable_text;
                else if (init != nullptr && init->kind == typed_pseudocode_ast_node_kind_t::expression_statement && !init->child_ids.empty()) {
                    const auto* expr = node(init->child_ids[0]);
                    if (expr != nullptr && expr->kind == typed_pseudocode_ast_node_kind_t::assignment_expression && !expr->child_ids.empty()) {
                        const auto* left = node(expr->child_ids[0]);
                        if (left != nullptr && left->kind == typed_pseudocode_ast_node_kind_t::identifier)
                            counter_name = left->stable_text;
                    }
                }
                if (!counter_name.empty()) {
                    const auto cond_id = n->child_ids[1];
                    const auto iter_id = n->child_ids[2];
                    bool in_condition = subtree_contains_identifier(cond_id, counter_name);
                    bool modified_in_iter = subtree_modifies_identifier(iter_id, counter_name);
                    if (in_condition && modified_in_iter) {
                        auto it = variables_.find(counter_name);
                        if (it != variables_.end() && it->second.is_generated) {
                            it->second.is_loop_counter = true;
                            it->second.loop_depth = depth;
                            ++metrics_.loop_counters_named;
                        }
                    }
                }
            }
            for (const auto child_id : n->child_ids)
                detect_loop_counters_impl(child_id, depth + 1, visited, traversal_depth + 1);
            return;
        }
        if (n->kind == typed_pseudocode_ast_node_kind_t::while_statement ||
            n->kind == typed_pseudocode_ast_node_kind_t::do_while_statement) {
            const auto cond_index = n->kind == typed_pseudocode_ast_node_kind_t::while_statement ? 0 : 1;
            if (cond_index < n->child_ids.size()) {
                std::vector<std::string> cond_vars;
                collect_identifier_names(n->child_ids[cond_index], cond_vars);
                for (const auto& var_name : cond_vars) {
                    auto it = variables_.find(var_name);
                    if (it != variables_.end() && it->second.is_generated) {
                        const auto body_index = n->kind == typed_pseudocode_ast_node_kind_t::while_statement ? 1 : 0;
                        if (body_index < n->child_ids.size() &&
                            subtree_modifies_identifier(n->child_ids[body_index], var_name)) {
                            it->second.is_loop_counter = true;
                            it->second.loop_depth = depth;
                            ++metrics_.loop_counters_named;
                        }
                    }
                }
            }
            for (const auto child_id : n->child_ids)
                detect_loop_counters_impl(child_id, depth + 1, visited, traversal_depth + 1);
            return;
        }
        for (const auto child_id : n->child_ids)
            detect_loop_counters_impl(child_id, depth, visited, traversal_depth + 1);
    }

    void collect_identifier_names(std::uint64_t node_id, std::vector<std::string>& names)
    {
        std::unordered_set<std::uint64_t> visited;
        collect_identifier_names_impl(node_id, names, visited, 0);
    }

    void collect_identifier_names_impl(std::uint64_t node_id, std::vector<std::string>& names,
                                        std::unordered_set<std::uint64_t>& visited,
                                        std::size_t depth)
    {
        if (depth >= settings_.max_expression_depth ||
            !visited.insert(node_id).second)
            return;
        const auto* n = node(node_id);
        if (n == nullptr)
            return;
        if (n->kind == typed_pseudocode_ast_node_kind_t::identifier)
            names.push_back(n->stable_text);
        for (const auto child_id : n->child_ids)
            collect_identifier_names_impl(child_id, names, visited, depth + 1);
    }

    bool subtree_contains_identifier(std::uint64_t node_id, const std::string& name)
    {
        std::unordered_set<std::uint64_t> visited;
        return subtree_contains_identifier_impl(node_id, name, visited, 0);
    }

    bool subtree_contains_identifier_impl(std::uint64_t node_id, const std::string& name,
                                           std::unordered_set<std::uint64_t>& visited,
                                           std::size_t depth)
    {
        if (depth >= settings_.max_expression_depth ||
            !visited.insert(node_id).second)
            return false;
        const auto* n = node(node_id);
        if (n == nullptr)
            return false;
        if (n->kind == typed_pseudocode_ast_node_kind_t::identifier && n->stable_text == name)
            return true;
        for (const auto child_id : n->child_ids) {
            if (subtree_contains_identifier_impl(child_id, name, visited, depth + 1))
                return true;
        }
        return false;
    }

    bool subtree_modifies_identifier(std::uint64_t node_id, const std::string& name)
    {
        std::unordered_set<std::uint64_t> visited;
        return subtree_modifies_identifier_impl(node_id, name, visited, 0);
    }

    bool subtree_modifies_identifier_impl(std::uint64_t node_id, const std::string& name,
                                           std::unordered_set<std::uint64_t>& visited,
                                           std::size_t depth)
    {
        if (depth >= settings_.max_expression_depth ||
            !visited.insert(node_id).second)
            return false;
        const auto* n = node(node_id);
        if (n == nullptr)
            return false;
        if (n->kind == typed_pseudocode_ast_node_kind_t::assignment_expression && !n->child_ids.empty()) {
            const auto* left = node(n->child_ids[0]);
            if (left != nullptr && left->kind == typed_pseudocode_ast_node_kind_t::identifier &&
                left->stable_text == name)
                return true;
        }
        if (n->kind == typed_pseudocode_ast_node_kind_t::unary_expression &&
            (n->stable_text == "++" || n->stable_text == "--") && !n->child_ids.empty()) {
            const auto* operand = node(n->child_ids[0]);
            if (operand != nullptr && operand->kind == typed_pseudocode_ast_node_kind_t::identifier &&
                operand->stable_text == name)
                return true;
        }
        for (const auto child_id : n->child_ids) {
            if (subtree_modifies_identifier_impl(child_id, name, visited, depth + 1))
                return true;
        }
        return false;
    }

    void detect_api_calls(std::uint64_t node_id)
    {
        std::unordered_set<std::uint64_t> visited;
        detect_api_calls_impl(node_id, visited, 0);
    }

    void detect_api_calls_impl(std::uint64_t node_id,
                                std::unordered_set<std::uint64_t>& visited,
                                std::size_t depth)
    {
        if (depth >= settings_.max_expression_depth ||
            !visited.insert(node_id).second)
            return;
        const auto* n = node(node_id);
        if (n == nullptr)
            return;
        if (n->kind == typed_pseudocode_ast_node_kind_t::call_expression && n->child_ids.size() >= 2) {
            const auto* callee = node(n->child_ids[0]);
            if (callee != nullptr && callee->kind == typed_pseudocode_ast_node_kind_t::identifier) {
                for (std::size_t i = 1; i < n->child_ids.size(); ++i) {
                    const auto* arg = node(n->child_ids[i]);
                    if (arg != nullptr && arg->kind == typed_pseudocode_ast_node_kind_t::identifier) {
                        const auto suggested = rt_suggest_api_name(callee->stable_text, i - 1);
                        if (suggested) {
                            auto it = variables_.find(arg->stable_text);
                            if (it != variables_.end() && it->second.is_generated) {
                                if (!it->second.api_suggested_name)
                                    it->second.api_suggested_name = *suggested;
                            }
                        }
                    }
                }
            }
        }
        for (const auto child_id : n->child_ids)
            detect_api_calls_impl(child_id, visited, depth + 1);
    }

    void detect_string_references(std::uint64_t node_id)
    {
        std::unordered_set<std::uint64_t> visited;
        detect_string_references_impl(node_id, visited, 0);
    }

    void detect_string_references_impl(std::uint64_t node_id,
                                        std::unordered_set<std::uint64_t>& visited,
                                        std::size_t depth)
    {
        if (depth >= settings_.max_expression_depth ||
            !visited.insert(node_id).second)
            return;
        const auto* n = node(node_id);
        if (n == nullptr)
            return;
        if (n->kind == typed_pseudocode_ast_node_kind_t::declaration &&
            n->child_ids.size() == 1 && rt_is_generated_name(n->stable_text)) {
            const auto* init = node(n->child_ids[0]);
            if (init != nullptr && init->kind == typed_pseudocode_ast_node_kind_t::literal) {
                const auto& text = init->stable_text;
                if (text.size() >= 2 && text.front() == '"') {
                    std::string content = text.substr(1);
                    if (!content.empty() && content.back() == '"')
                        content.pop_back();
                    std::string first_word;
                    for (const char c : content) {
                        if (std::isalnum(static_cast<unsigned char>(c)) != 0 || c == '_')
                            first_word.push_back(c);
                        else if (!first_word.empty())
                            break;
                    }
                    if (first_word.size() > 0) {
                        auto camel = rt_to_camel_case(first_word);
                        if (!camel.empty()) {
                            auto it = variables_.find(n->stable_text);
                            if (it != variables_.end())
                                it->second.string_suggested_name = camel;
                        }
                    }
                }
            }
        }
        for (const auto child_id : n->child_ids)
            detect_string_references_impl(child_id, visited, depth + 1);
    }

    void compute_type_based_names()
    {
        for (auto& [name, info] : variables_) {
            if (!info.is_generated || info.type_id == 0)
                continue;
            const auto type_it = types_.find(info.type_id);
            if (type_it == types_.end())
                continue;
            const auto suggested = rt_suggest_type_name(type_it->second->display_name);
            if (suggested)
                info.type_suggested_name = *suggested;
        }
    }

    void compute_final_suggested_names()
    {
        std::set<std::string> used_names;
        for (const auto& [name, info] : variables_) {
            if (!info.is_generated)
                used_names.insert(name);
        }
        std::map<std::string, std::string> rename_map;
        for (auto& [name, info] : variables_) {
            if (!info.is_generated)
                continue;
            std::string suggested;
            if (info.is_loop_counter && settings_.enable_loop_counter_naming) {
                const char* counters[] = {"i", "j", "k", "m", "n"};
                const int idx = info.loop_depth < 5 ? info.loop_depth : 4;
                suggested = counters[idx];
            }
            if (suggested.empty() && info.api_suggested_name && settings_.enable_api_call_naming)
                suggested = *info.api_suggested_name;
            if (suggested.empty() && info.string_suggested_name && settings_.enable_string_reference_naming)
                suggested = *info.string_suggested_name;
            if (suggested.empty() && info.type_suggested_name && settings_.enable_type_based_naming)
                suggested = *info.type_suggested_name;
            if (suggested.empty())
                continue;
            std::string final_name = suggested;
            int suffix = 2;
            while (used_names.find(final_name) != used_names.end() ||
                   rename_map.find(final_name) != rename_map.end()) {
                final_name = suggested + std::to_string(suffix);
                ++suffix;
            }
            info.final_suggested_name = final_name;
            rename_map[final_name] = name;
            used_names.insert(final_name);
        }
    }

    void apply_renaming()
    {
        std::map<std::string, std::string> rename_map;
        for (const auto& [name, info] : variables_) {
            if (!info.is_generated || info.final_suggested_name.empty())
                continue;
            rename_map[name] = info.final_suggested_name;
        }
        if (rename_map.empty())
            return;
        for (auto& n : ast_.nodes) {
            if ((n.kind == typed_pseudocode_ast_node_kind_t::declaration ||
                 n.kind == typed_pseudocode_ast_node_kind_t::identifier) &&
                !n.stable_text.empty()) {
                const auto it = rename_map.find(n.stable_text);
                if (it != rename_map.end()) {
                    n.stable_text = it->second;
                    ++metrics_.variables_renamed;
                }
            }
        }
        for (const auto& [old_name, new_name] : rename_map) {
            const auto& info = variables_.at(old_name);
            if (!info.is_loop_counter && info.api_suggested_name && settings_.enable_api_call_naming)
                ++metrics_.api_call_names_applied;
            else if (!info.is_loop_counter && !info.api_suggested_name &&
                     info.string_suggested_name && settings_.enable_string_reference_naming)
                ++metrics_.string_reference_names_applied;
            else if (!info.is_loop_counter && !info.api_suggested_name &&
                     !info.string_suggested_name && info.type_suggested_name &&
                     settings_.enable_type_based_naming)
                ++metrics_.type_based_names_applied;
        }
    }

    bool simplify_expressions(std::uint64_t node_id, std::size_t depth, bool boolean_context)
    {
        std::unordered_set<std::uint64_t> visited;
        return simplify_expressions_impl(node_id, depth, boolean_context, visited);
    }

    bool simplify_expressions_impl(std::uint64_t node_id, std::size_t depth, bool boolean_context,
                                    std::unordered_set<std::uint64_t>& visited)
    {
        if (depth >= settings_.max_expression_depth ||
            !visited.insert(node_id).second)
            return false;
        auto* n = node(node_id);
        if (n == nullptr)
            return false;
        bool changed = false;
        bool child_boolean_context = false;
        if (n->kind == typed_pseudocode_ast_node_kind_t::if_statement ||
            n->kind == typed_pseudocode_ast_node_kind_t::while_statement) {
            for (std::size_t i = 0; i < n->child_ids.size(); ++i) {
                if (i == 0)
                    changed = simplify_expressions_impl(n->child_ids[i], depth + 1, true, visited) || changed;
                else
                    changed = simplify_expressions_impl(n->child_ids[i], depth + 1, false, visited) || changed;
            }
            return changed;
        }
        if (n->kind == typed_pseudocode_ast_node_kind_t::do_while_statement) {
            for (std::size_t i = 0; i < n->child_ids.size(); ++i) {
                if (i == 1)
                    changed = simplify_expressions_impl(n->child_ids[i], depth + 1, true, visited) || changed;
                else
                    changed = simplify_expressions_impl(n->child_ids[i], depth + 1, false, visited) || changed;
            }
            return changed;
        }
        if (n->kind == typed_pseudocode_ast_node_kind_t::for_statement) {
            for (std::size_t i = 0; i < n->child_ids.size(); ++i) {
                if (i == 1)
                    changed = simplify_expressions_impl(n->child_ids[i], depth + 1, true, visited) || changed;
                else
                    changed = simplify_expressions_impl(n->child_ids[i], depth + 1, false, visited) || changed;
            }
            return changed;
        }
        if (n->kind == typed_pseudocode_ast_node_kind_t::binary_expression &&
            (n->stable_text == "&&" || n->stable_text == "||"))
            child_boolean_context = true;
        for (const auto child_id : n->child_ids)
            changed = simplify_expressions_impl(child_id, depth + 1, child_boolean_context, visited) || changed;
        if (n->kind == typed_pseudocode_ast_node_kind_t::binary_expression) {
            if (settings_.enable_constant_folding)
                changed = try_fold_constant_binary(*n) || changed;
            if (settings_.enable_identity_simplification)
                changed = try_simplify_identity(*n) || changed;
            if (settings_.enable_comparison_normalization && boolean_context)
                changed = try_normalize_comparison(*n) || changed;
        }
        if (n->kind == typed_pseudocode_ast_node_kind_t::unary_expression) {
            if (settings_.enable_double_negation_simplification)
                changed = try_simplify_double_negation(*n) || changed;
        }
        if (n->kind == typed_pseudocode_ast_node_kind_t::cast_expression) {
            if (settings_.enable_cast_simplification)
                changed = try_simplify_redundant_cast(*n) || changed;
        }
        if (n->kind == typed_pseudocode_ast_node_kind_t::assignment_expression) {
            if (settings_.enable_compound_assignment_marking)
                changed = try_mark_compound_assignment(*n) || changed;
        }
        return changed;
    }

    bool try_fold_constant_binary(typed_pseudocode_ast_node_t& n)
    {
        if (n.child_ids.size() != 2)
            return false;
        const auto* left = node(n.child_ids[0]);
        const auto* right = node(n.child_ids[1]);
        if (left == nullptr || right == nullptr)
            return false;
        if (left->kind != typed_pseudocode_ast_node_kind_t::literal ||
            right->kind != typed_pseudocode_ast_node_kind_t::literal)
            return false;
        const auto lhs = rt_parse_signed(left->stable_text);
        const auto rhs = rt_parse_signed(right->stable_text);
        if (!lhs || !rhs)
            return false;
        const std::string op = n.stable_text;
        std::optional<std::int64_t> result;
        if (op == "+") {
            if ((*lhs > 0 && *rhs > 0 && *lhs > std::numeric_limits<std::int64_t>::max() - *rhs) ||
                (*lhs < 0 && *rhs < 0 && *lhs < std::numeric_limits<std::int64_t>::min() - *rhs))
                return false;
            result = *lhs + *rhs;
        } else if (op == "-") {
            if ((*lhs > 0 && *rhs < 0 && *lhs > std::numeric_limits<std::int64_t>::max() + *rhs) ||
                (*lhs < 0 && *rhs > 0 && *lhs < std::numeric_limits<std::int64_t>::min() + *rhs))
                return false;
            result = *lhs - *rhs;
        } else if (op == "*") {
            result = *lhs * *rhs;
        } else if (op == "<<") {
            if (*rhs < 0 || *rhs >= 64)
                return false;
            result = *lhs << *rhs;
        } else if (op == ">>") {
            if (*rhs < 0 || *rhs >= 64)
                return false;
            result = *lhs >> *rhs;
        } else if (op == "&") {
            result = *lhs & *rhs;
        } else if (op == "|") {
            result = *lhs | *rhs;
        } else if (op == "^") {
            result = *lhs ^ *rhs;
        } else if (op == "/") {
            if (*rhs == 0)
                return false;
            result = *lhs / *rhs;
        } else if (op == "%") {
            if (*rhs == 0)
                return false;
            result = *lhs % *rhs;
        } else {
            return false;
        }
        n.kind = typed_pseudocode_ast_node_kind_t::literal;
        n.stable_text = rt_format_signed(*result);
        n.child_ids.clear();
        ++metrics_.constants_folded;
        return true;
    }

    bool try_simplify_identity(typed_pseudocode_ast_node_t& n)
    {
        if (n.child_ids.size() != 2)
            return false;
        const auto* left = node(n.child_ids[0]);
        const auto* right = node(n.child_ids[1]);
        if (left == nullptr || right == nullptr)
            return false;
        const std::string op = n.stable_text;
        const bool left_is_literal = left->kind == typed_pseudocode_ast_node_kind_t::literal;
        const bool right_is_literal = right->kind == typed_pseudocode_ast_node_kind_t::literal;
        auto right_val = right_is_literal ? rt_parse_signed(right->stable_text) : std::optional<std::int64_t>{};
        auto left_val = left_is_literal ? rt_parse_signed(left->stable_text) : std::optional<std::int64_t>{};
        if (op == "+" && right_is_literal && right_val && *right_val == 0) {
            copy_node_content(n, *left);
            ++metrics_.identities_simplified;
            return true;
        }
        if (op == "+" && left_is_literal && left_val && *left_val == 0) {
            copy_node_content(n, *right);
            ++metrics_.identities_simplified;
            return true;
        }
        if (op == "-" && right_is_literal && right_val && *right_val == 0) {
            copy_node_content(n, *left);
            ++metrics_.identities_simplified;
            return true;
        }
        if (op == "*" && right_is_literal && right_val && *right_val == 1) {
            copy_node_content(n, *left);
            ++metrics_.identities_simplified;
            return true;
        }
        if (op == "*" && left_is_literal && left_val && *left_val == 1) {
            copy_node_content(n, *right);
            ++metrics_.identities_simplified;
            return true;
        }
        if (op == "*" && right_is_literal && right_val && *right_val == 0) {
            n.kind = typed_pseudocode_ast_node_kind_t::literal;
            n.stable_text = "0";
            n.child_ids.clear();
            ++metrics_.identities_simplified;
            return true;
        }
        if (op == "*" && left_is_literal && left_val && *left_val == 0) {
            n.kind = typed_pseudocode_ast_node_kind_t::literal;
            n.stable_text = "0";
            n.child_ids.clear();
            ++metrics_.identities_simplified;
            return true;
        }
        if (op == "|" && right_is_literal && right_val && *right_val == 0) {
            copy_node_content(n, *left);
            ++metrics_.identities_simplified;
            return true;
        }
        if (op == "|" && left_is_literal && left_val && *left_val == 0) {
            copy_node_content(n, *right);
            ++metrics_.identities_simplified;
            return true;
        }
        if (op == "&" && right_is_literal && right_val && *right_val == 0) {
            n.kind = typed_pseudocode_ast_node_kind_t::literal;
            n.stable_text = "0";
            n.child_ids.clear();
            ++metrics_.identities_simplified;
            return true;
        }
        if (op == "&" && left_is_literal && left_val && *left_val == 0) {
            n.kind = typed_pseudocode_ast_node_kind_t::literal;
            n.stable_text = "0";
            n.child_ids.clear();
            ++metrics_.identities_simplified;
            return true;
        }
        if (op == "&&" && left_is_literal && left_val && *left_val == 0) {
            n.kind = typed_pseudocode_ast_node_kind_t::literal;
            n.stable_text = "0";
            n.child_ids.clear();
            ++metrics_.identities_simplified;
            return true;
        }
        if (op == "||" && left_is_literal && left_val && *left_val != 0) {
            n.kind = typed_pseudocode_ast_node_kind_t::literal;
            n.stable_text = "1";
            n.child_ids.clear();
            ++metrics_.identities_simplified;
            return true;
        }
        if (op == "/" && right_is_literal && right_val && *right_val == 1) {
            copy_node_content(n, *left);
            ++metrics_.identities_simplified;
            return true;
        }
        return false;
    }

    void copy_node_content(typed_pseudocode_ast_node_t& dst, const typed_pseudocode_ast_node_t& src)
    {
        dst.kind = src.kind;
        dst.type_id = src.type_id;
        dst.child_ids = src.child_ids;
        dst.stable_text = src.stable_text;
    }

    bool try_simplify_double_negation(typed_pseudocode_ast_node_t& n)
    {
        if (n.stable_text != "!" || n.child_ids.size() != 1)
            return false;
        const auto* child = node(n.child_ids[0]);
        if (child == nullptr || child->kind != typed_pseudocode_ast_node_kind_t::unary_expression ||
            child->stable_text != "!" || child->child_ids.size() != 1)
            return false;
        const auto* grandchild = node(child->child_ids[0]);
        if (grandchild == nullptr)
            return false;
        copy_node_content(n, *grandchild);
        ++metrics_.double_negations_simplified;
        return true;
    }

    bool try_simplify_redundant_cast(typed_pseudocode_ast_node_t& n)
    {
        if (n.child_ids.size() != 1)
            return false;
        const auto* child = node(n.child_ids[0]);
        if (child == nullptr)
            return false;
        if (child->kind == typed_pseudocode_ast_node_kind_t::cast_expression &&
            child->stable_text == n.stable_text) {
            copy_node_content(n, *child);
            ++metrics_.casts_simplified;
            return true;
        }
        if (child->kind == typed_pseudocode_ast_node_kind_t::cast_expression &&
            child->child_ids.size() == 1) {
            const auto* grandchild = node(child->child_ids[0]);
            if (grandchild != nullptr) {
                const auto child_type_it = types_.find(child->type_id);
                const auto grandchild_type_it = types_.find(grandchild->type_id);
                if (child_type_it != types_.end() && grandchild_type_it != types_.end()) {
                    const auto& ct = child_type_it->second;
                    const auto& gt = grandchild_type_it->second;
                    if (ct->kind == decompiler_type_kind_t::pointer &&
                        gt->kind == decompiler_type_kind_t::pointer &&
                        n.stable_text == child->stable_text) {
                        copy_node_content(n, *grandchild);
                        ++metrics_.casts_simplified;
                        return true;
                    }
                }
            }
        }
        return false;
    }

    bool try_mark_compound_assignment(typed_pseudocode_ast_node_t& n)
    {
        if (n.stable_text != "=" || n.child_ids.size() != 2)
            return false;
        const auto* left = node(n.child_ids[0]);
        const auto* right = node(n.child_ids[1]);
        if (left == nullptr || right == nullptr)
            return false;
        if (left->kind != typed_pseudocode_ast_node_kind_t::identifier)
            return false;
        if (right->kind != typed_pseudocode_ast_node_kind_t::binary_expression ||
            right->child_ids.size() != 2)
            return false;
        const auto* rhs_left = node(right->child_ids[0]);
        if (rhs_left == nullptr || rhs_left->kind != typed_pseudocode_ast_node_kind_t::identifier)
            return false;
        if (rhs_left->stable_text != left->stable_text)
            return false;
        const auto op = right->stable_text;
        if (op == "+" || op == "-" || op == "*" || op == "/" || op == "%" ||
            op == "<<" || op == ">>" || op == "&" || op == "|" || op == "^") {
            n.stable_text = op + "=";
            ++metrics_.compound_assignments_marked;
            return true;
        }
        return false;
    }

    bool try_normalize_comparison(typed_pseudocode_ast_node_t& n)
    {
        if (n.child_ids.size() != 2)
            return false;
        const auto* left = node(n.child_ids[0]);
        const auto* right = node(n.child_ids[1]);
        if (left == nullptr || right == nullptr)
            return false;
        if (right->kind != typed_pseudocode_ast_node_kind_t::literal)
            return false;
        const auto val = rt_parse_signed(right->stable_text);
        if (!val)
            return false;
        if (n.stable_text == "==" && *val == 0) {
            n.kind = typed_pseudocode_ast_node_kind_t::unary_expression;
            n.stable_text = "!";
            n.child_ids = {n.child_ids[0]};
            ++metrics_.comparisons_normalized;
            return true;
        }
        if (n.stable_text == "!=" && *val == 0) {
            copy_node_content(n, *left);
            ++metrics_.comparisons_normalized;
            return true;
        }
        return false;
    }

    void collect_def_use(std::uint64_t node_id, std::uint64_t parent_statement_id,
                         std::unordered_set<std::uint64_t>& visited)
    {
        if (!visited.insert(node_id).second)
            return;
        const auto* n = node(node_id);
        if (n == nullptr)
            return;
        if (n->kind == typed_pseudocode_ast_node_kind_t::compound_statement) {
            for (const auto child_id : n->child_ids)
                collect_def_use(child_id, child_id, visited);
            return;
        }
        if (n->kind == typed_pseudocode_ast_node_kind_t::declaration) {
            if (!n->child_ids.empty()) {
                rt_def_use_entry_t entry;
                entry.variable = n->stable_text;
                entry.statement_id = parent_statement_id;
                entry.definition_node_id = node_id;
                entry.initializer_node_id = n->child_ids[0];
                entry.is_declaration = true;
                entry.has_side_effects = rt_node_has_side_effects(ast_, n->child_ids[0], id_index_);
                definitions_.push_back(entry);
            }
            for (const auto child_id : n->child_ids)
                collect_def_use(child_id, parent_statement_id, visited);
            return;
        }
        if (n->kind == typed_pseudocode_ast_node_kind_t::expression_statement && n->child_ids.size() == 1) {
            const auto* expr = node(n->child_ids[0]);
            if (expr != nullptr && expr->kind == typed_pseudocode_ast_node_kind_t::assignment_expression &&
                expr->child_ids.size() == 2) {
                const auto* target = node(expr->child_ids[0]);
                if (target != nullptr && target->kind == typed_pseudocode_ast_node_kind_t::identifier) {
                    rt_def_use_entry_t entry;
                    entry.variable = target->stable_text;
                    entry.statement_id = parent_statement_id;
                    entry.definition_node_id = expr->child_ids[0];
                    entry.initializer_node_id = expr->child_ids[1];
                    entry.is_declaration = false;
                    entry.has_side_effects = rt_node_has_side_effects(ast_, expr->child_ids[1], id_index_);
                    definitions_.push_back(entry);
                }
            }
            for (const auto child_id : n->child_ids)
                collect_def_use(child_id, parent_statement_id, visited);
            return;
        }
        if (n->kind == typed_pseudocode_ast_node_kind_t::identifier) {
            const auto parent_it = parent_map_.find(node_id);
            bool is_write = false;
            if (parent_it != parent_map_.end()) {
                const auto* parent = node(parent_it->second.first);
                if (parent != nullptr &&
                    parent->kind == typed_pseudocode_ast_node_kind_t::assignment_expression &&
                    parent_it->second.second == 0)
                    is_write = true;
            }
            if (!is_write)
                uses_[n->stable_text].push_back(node_id);
            return;
        }
        if (n->kind == typed_pseudocode_ast_node_kind_t::if_statement ||
            n->kind == typed_pseudocode_ast_node_kind_t::while_statement ||
            n->kind == typed_pseudocode_ast_node_kind_t::do_while_statement ||
            n->kind == typed_pseudocode_ast_node_kind_t::for_statement ||
            n->kind == typed_pseudocode_ast_node_kind_t::switch_statement ||
            n->kind == typed_pseudocode_ast_node_kind_t::try_statement) {
            for (const auto child_id : n->child_ids)
                collect_def_use(child_id, child_id, visited);
            return;
        }
        for (const auto child_id : n->child_ids)
            collect_def_use(child_id, parent_statement_id, visited);
    }

    std::size_t count_definitions(const std::string& var) const
    {
        std::size_t count = 0;
        for (const auto& def : definitions_)
            if (def.variable == var)
                ++count;
        return count;
    }

    std::size_t count_uses(const std::string& var) const
    {
        const auto it = uses_.find(var);
        return it == uses_.end() ? 0 : it->second.size();
    }

    const rt_def_use_entry_t* find_single_definition(const std::string& var) const
    {
        const rt_def_use_entry_t* result = nullptr;
        std::size_t count = 0;
        for (const auto& def : definitions_) {
            if (def.variable == var) {
                result = &def;
                ++count;
            }
        }
        return count == 1 ? result : nullptr;
    }

    std::uint64_t find_parent_compound(std::uint64_t node_id) const
    {
        std::uint64_t current = node_id;
        std::unordered_set<std::uint64_t> visited;
        for (std::size_t guard = 0; guard < k_max_parent_chain_depth; ++guard) {
            if (!visited.insert(current).second)
                return 0;
            const auto it = parent_map_.find(current);
            if (it == parent_map_.end())
                return 0;
            const auto parent_id = it->second.first;
            const auto* parent = node(parent_id);
            if (parent == nullptr)
                return 0;
            if (parent->kind == typed_pseudocode_ast_node_kind_t::compound_statement)
                return parent_id;
            current = parent_id;
        }
        return 0;
    }

    bool remove_statement_from_compound(std::uint64_t statement_id)
    {
        const auto compound_id = find_parent_compound(statement_id);
        if (compound_id == 0)
            return false;
        auto* compound = node(compound_id);
        if (compound == nullptr)
            return false;
        const auto it = std::find(compound->child_ids.begin(), compound->child_ids.end(), statement_id);
        if (it == compound->child_ids.end())
            return false;
        if (compound_id == ast_.body_node_id && compound->child_ids.size() <= 1)
            return false;
        compound->child_ids.erase(it);
        return true;
    }

    bool apply_single_use_inlining()
    {
        bool changed = false;
        for (const auto& def : definitions_) {
            if (count_definitions(def.variable) != 1)
                continue;
            if (count_uses(def.variable) != 1)
                continue;
            if (def.has_side_effects)
                continue;
            if (def.initializer_node_id == 0)
                continue;
            const auto* init_node = node(def.initializer_node_id);
            if (init_node == nullptr)
                continue;
            if (init_node->kind == typed_pseudocode_ast_node_kind_t::call_expression ||
                init_node->kind == typed_pseudocode_ast_node_kind_t::unknown_expression)
                continue;
            const auto uses_it = uses_.find(def.variable);
            if (uses_it == uses_.end() || uses_it->second.size() != 1)
                continue;
            const auto use_id = uses_it->second[0];
            auto* use_node = node(use_id);
            if (use_node == nullptr)
                continue;
            copy_node_content(*use_node, *init_node);
            remove_statement_from_compound(def.statement_id);
            uses_.erase(def.variable);
            ++metrics_.temporaries_inlined;
            changed = true;
        }
        return changed;
    }

    bool apply_copy_propagation()
    {
        bool changed = false;
        for (const auto& def : definitions_) {
            if (def.has_side_effects)
                continue;
            if (def.initializer_node_id == 0)
                continue;
            if (count_definitions(def.variable) != 1)
                continue;
            const auto* init_node = node(def.initializer_node_id);
            if (init_node == nullptr ||
                init_node->kind != typed_pseudocode_ast_node_kind_t::identifier)
                continue;
            const auto& source_var = init_node->stable_text;
            if (count_definitions(source_var) > 1)
                continue;
            const auto uses_it = uses_.find(def.variable);
            if (uses_it == uses_.end())
                continue;
            for (const auto use_id : uses_it->second) {
                auto* use_node = node(use_id);
                if (use_node == nullptr)
                    continue;
                use_node->stable_text = source_var;
                use_node->type_id = init_node->type_id;
                ++metrics_.copies_propagated;
                changed = true;
            }
        }
        return changed;
    }

    bool apply_dead_store_elimination()
    {
        bool changed = false;
        std::set<std::string> processed;
        for (const auto& def : definitions_) {
            if (processed.find(def.variable) != processed.end())
                continue;
            processed.insert(def.variable);
            if (count_uses(def.variable) > 0)
                continue;
            std::size_t def_count = count_definitions(def.variable);
            if (def_count == 0)
                continue;
            bool all_safe = true;
            for (const auto& d : definitions_) {
                if (d.variable == def.variable && d.has_side_effects) {
                    all_safe = false;
                    break;
                }
            }
            if (!all_safe)
                continue;
            for (const auto& d : definitions_) {
                if (d.variable != def.variable)
                    continue;
                remove_statement_from_compound(d.statement_id);
                ++metrics_.dead_stores_eliminated;
                changed = true;
            }
        }
        return changed;
    }

    void compact_ast()
    {
        std::unordered_set<std::uint64_t> reachable;
        mark_reachable(ast_.root_node_id, reachable);
        std::size_t original_size = ast_.nodes.size();
        std::vector<typed_pseudocode_ast_node_t> new_nodes;
        new_nodes.reserve(reachable.size());
        for (auto& n : ast_.nodes) {
            if (reachable.find(n.id) != reachable.end())
                new_nodes.push_back(std::move(n));
        }
        const std::size_t removed = original_size - new_nodes.size();
        if (removed > 0) {
            ast_.nodes = std::move(new_nodes);
            metrics_.nodes_removed += removed;
            build_index();
        }
    }

    void mark_reachable(std::uint64_t node_id, std::unordered_set<std::uint64_t>& reachable) const
    {
        if (reachable.find(node_id) != reachable.end())
            return;
        const auto it = id_index_.find(node_id);
        if (it == id_index_.end())
            return;
        reachable.insert(node_id);
        const auto& n = ast_.nodes[it->second];
        for (const auto child_id : n.child_ids)
            mark_reachable(child_id, reachable);
    }
};

}

readability_transform_result_t apply_readability_transforms(
    typed_pseudocode_ast_v2_t& ast,
    const type_graph_t& type_graph,
    const readability_transform_settings_t& settings)
{
    rt_transformer_t transformer(ast, type_graph, settings);
    return transformer.run();
}

semantic_refiner_t::semantic_refiner_t(std::shared_ptr<triton_z3_adapter_t> adapter)
    : adapter_(adapter ? std::move(adapter) : make_triton_z3_adapter()),
      execution_state_(std::make_shared<semantic_refiner_execution_state_t>()) {}

semantic_refinement_result_t semantic_refiner_t::refine(
    const semantic_refinement_request_t& request,
    const cancellation_token_t& cancel) const
{
    semantic_refinement_result_t result;
    result.unknowns = request.function.unknowns;
    std::uint32_t diagnostic_ordinal = 1;

    const auto profile_validation = validate_decompiler_profile(request.profile);
    if (!profile_validation.valid()) {
        result.status = semantic_refinement_status_t::input_rejected;
        result.diagnostics.push_back(make_diagnostic(
            decompiler_diagnostic_code_t::invalid_contract,
            "semantic_refiner.profile.invalid",
            nullptr,
            diagnostic_ordinal));
        return result;
    }
    if (request.profile.profile != decompiler_profile_id_t::thorough ||
        !request.profile.semantic_proofs_enabled || request.profile.max_semantic_queries == 0) {
        result.status = semantic_refinement_status_t::profile_rejected;
        result.diagnostics.push_back(make_diagnostic(
            decompiler_diagnostic_code_t::invalid_contract,
            "semantic_refiner.profile.thorough_required",
            nullptr,
            diagnostic_ordinal));
        return result;
    }
    if (!validate_hir_function(request.function).valid() ||
        !query_sequence_valid(request.queries, request.function.entity, profile_ir_limit(request.profile))) {
        result.status = semantic_refinement_status_t::input_rejected;
        result.diagnostics.push_back(make_diagnostic(
            decompiler_diagnostic_code_t::invalid_contract,
            "semantic_refiner.request.invalid",
            nullptr,
            diagnostic_ordinal));
        return result;
    }
    if (cancel.stop_requested()) {
        result.status = semantic_refinement_status_t::cancelled;
        append_pending_unknowns(result, request.queries, 0,
            decompiler_unknown_reason_t::bounded_analysis_limit, "semantic_cancelled");
        result.diagnostics.push_back(make_diagnostic(
            cancel.deadline_exceeded() ? decompiler_diagnostic_code_t::deadline_exceeded
                                      : decompiler_diagnostic_code_t::cancelled,
            cancel.deadline_exceeded() ? "semantic_refiner.cancelled.deadline" : "semantic_refiner.cancelled",
            request.queries.empty() ? nullptr : &request.queries.front().coordinate,
            diagnostic_ordinal));
        return result;
    }

    triton_z3_adapter_capabilities_t capabilities;
    try {
        capabilities = adapter_->capabilities();
    } catch (...) {
        result.status = semantic_refinement_status_t::adapter_denied;
        append_pending_unknowns(result, request.queries, 0,
            decompiler_unknown_reason_t::provider_abstained, "semantic_adapter_denied");
        result.diagnostics.push_back(make_diagnostic(
            decompiler_diagnostic_code_t::unsupported_provider,
            "semantic_refiner.adapter.capability_failure",
            request.queries.empty() ? nullptr : &request.queries.front().coordinate,
            diagnostic_ordinal));
        return result;
    }
    if (capabilities.target_execution_supported) {
        result.status = semantic_refinement_status_t::adapter_denied;
        append_pending_unknowns(result, request.queries, 0,
            decompiler_unknown_reason_t::provider_abstained, "semantic_adapter_denied");
        result.diagnostics.push_back(make_diagnostic(
            decompiler_diagnostic_code_t::unsupported_provider,
            "semantic_refiner.adapter.target_execution_forbidden",
            request.queries.empty() ? nullptr : &request.queries.front().coordinate,
            diagnostic_ordinal));
        return result;
    }
    if (!capabilities.valid()) {
        result.status = semantic_refinement_status_t::adapter_denied;
        append_pending_unknowns(result, request.queries, 0,
            decompiler_unknown_reason_t::provider_abstained, "semantic_adapter_denied");
        result.diagnostics.push_back(make_diagnostic(
            decompiler_diagnostic_code_t::unsupported_provider,
            "semantic_refiner.adapter.invalid_capability_contract",
            request.queries.empty() ? nullptr : &request.queries.front().coordinate,
            diagnostic_ordinal));
        return result;
    }
    if (!capabilities.available()) {
        result.status = semantic_refinement_status_t::adapter_denied;
        append_pending_unknowns(result, request.queries, 0,
            decompiler_unknown_reason_t::provider_abstained, "semantic_adapter_denied");
        result.diagnostics.push_back(make_diagnostic(
            decompiler_diagnostic_code_t::unsupported_provider,
            "semantic_refiner.adapter." + triton_z3_adapter_availability_key(capabilities.availability),
            request.queries.empty() ? nullptr : &request.queries.front().coordinate,
            diagnostic_ordinal));
        return result;
    }

    const auto function_deadline = deadline_after(
        std::chrono::steady_clock::now(), request.profile.max_wall_clock_ms);
    std::uint64_t consumed_cpu_ms = 0;
    bool has_semantic_unknown = false;
    for (std::size_t index = 0; index < request.queries.size(); ++index) {
        const auto& query = request.queries[index];
        if (index >= request.profile.max_semantic_queries) {
            append_pending_unknowns(result, request.queries, index,
                decompiler_unknown_reason_t::bounded_analysis_limit, "semantic_budget_exhausted");
            result.diagnostics.push_back(make_diagnostic(
                decompiler_diagnostic_code_t::resource_limit,
                "semantic_refiner.budget.query_limit",
                &query.coordinate,
                diagnostic_ordinal));
            has_semantic_unknown = true;
            break;
        }
        if (cancel.stop_requested()) {
            append_pending_unknowns(result, request.queries, index,
                decompiler_unknown_reason_t::bounded_analysis_limit, "semantic_cancelled");
            result.diagnostics.push_back(make_diagnostic(
                cancel.deadline_exceeded() ? decompiler_diagnostic_code_t::deadline_exceeded
                                          : decompiler_diagnostic_code_t::cancelled,
                cancel.deadline_exceeded() ? "semantic_refiner.cancelled.deadline" : "semantic_refiner.cancelled",
                &query.coordinate,
                diagnostic_ordinal));
            result.status = semantic_refinement_status_t::cancelled;
            return result;
        }

        triton_z3_proof_limits_t limits;
        if (!remaining_limits(request.profile, function_deadline, consumed_cpu_ms, limits)) {
            append_pending_unknowns(result, request.queries, index,
                decompiler_unknown_reason_t::bounded_analysis_limit, "semantic_budget_exhausted");
            result.diagnostics.push_back(make_diagnostic(
                decompiler_diagnostic_code_t::resource_limit,
                "semantic_refiner.budget.elapsed_limit",
                &query.coordinate,
                diagnostic_ordinal));
            has_semantic_unknown = true;
            break;
        }

        triton_z3_proof_request_t proof_request;
        proof_request.entity = request.function.entity;
        proof_request.coordinate = query.coordinate;
        proof_request.ordinal = query.ordinal;
        proof_request.stable_id = query.stable_id;
        proof_request.static_ir = query.static_ir;
        proof_request.refinement_key = query.refinement_key;
        proof_request.limits = limits;

        const auto worker = bounded_prove(adapter_, execution_state_, proof_request, cancel);
        if (worker.invoked)
            ++result.adapter_invocations;
        consumed_cpu_ms = saturating_add(consumed_cpu_ms, worker.measured_cpu_ms);

        if (worker.terminal == proof_worker_terminal_t::caller_cancelled ||
            worker.terminal == proof_worker_terminal_t::caller_deadline) {
            append_pending_unknowns(result, request.queries, index,
                decompiler_unknown_reason_t::bounded_analysis_limit, "semantic_cancelled");
            const bool deadline = worker.terminal == proof_worker_terminal_t::caller_deadline;
            result.diagnostics.push_back(make_diagnostic(
                deadline ? decompiler_diagnostic_code_t::deadline_exceeded
                         : decompiler_diagnostic_code_t::cancelled,
                deadline ? "semantic_refiner.cancelled.deadline" : "semantic_refiner.cancelled",
                &query.coordinate,
                diagnostic_ordinal));
            result.status = semantic_refinement_status_t::cancelled;
            return result;
        }
        const bool function_wall_exhausted = worker.terminal == proof_worker_terminal_t::completed &&
                                             std::chrono::steady_clock::now() >= function_deadline;
        if (worker.terminal == proof_worker_terminal_t::wall_limit ||
            worker.terminal == proof_worker_terminal_t::cpu_limit || function_wall_exhausted) {
            const bool wall_limit = worker.terminal == proof_worker_terminal_t::wall_limit ||
                                    function_wall_exhausted;
            result.unknowns.push_back(make_unknown(query,
                wall_limit
                    ? decompiler_unknown_reason_t::semantic_timeout
                    : decompiler_unknown_reason_t::bounded_analysis_limit,
                wall_limit
                    ? "semantic_timeout:" + query.stable_id
                    : "semantic_cpu_limit:" + query.stable_id));
            append_pending_unknowns(result, request.queries, index + 1,
                decompiler_unknown_reason_t::bounded_analysis_limit, "semantic_budget_exhausted");
            result.diagnostics.push_back(make_diagnostic(
                wall_limit
                    ? decompiler_diagnostic_code_t::deadline_exceeded
                    : decompiler_diagnostic_code_t::resource_limit,
                wall_limit
                    ? "semantic_refiner.worker.deadline"
                    : "semantic_refiner.worker.cpu_limit",
                &query.coordinate,
                diagnostic_ordinal));
            has_semantic_unknown = true;
            break;
        }
        if (worker.terminal == proof_worker_terminal_t::adapter_busy ||
            worker.terminal == proof_worker_terminal_t::launch_failure) {
            append_pending_unknowns(result, request.queries, index,
                decompiler_unknown_reason_t::provider_abstained, "semantic_adapter_denied");
            result.diagnostics.push_back(make_diagnostic(
                decompiler_diagnostic_code_t::unsupported_provider,
                worker.terminal == proof_worker_terminal_t::adapter_busy
                    ? "semantic_refiner.adapter.worker_busy"
                    : "semantic_refiner.adapter.worker_launch_failure",
                &query.coordinate,
                diagnostic_ordinal));
            result.status = semantic_refinement_status_t::adapter_denied;
            return result;
        }
        if (worker.terminal == proof_worker_terminal_t::adapter_failure ||
            worker.terminal == proof_worker_terminal_t::cpu_measurement_failure) {
            result.unknowns.push_back(make_unknown(query,
                decompiler_unknown_reason_t::provider_abstained,
                "semantic_adapter_failure:" + query.stable_id));
            result.diagnostics.push_back(make_diagnostic(
                decompiler_diagnostic_code_t::provider_failure,
                worker.terminal == proof_worker_terminal_t::adapter_failure
                    ? "semantic_refiner.adapter.exception"
                    : "semantic_refiner.adapter.cpu_measurement_unavailable",
                &query.coordinate,
                diagnostic_ordinal));
            has_semantic_unknown = true;
            continue;
        }

        const auto& response = worker.response;
        if (!valid_triton_z3_proof_response(response)) {
            result.unknowns.push_back(make_unknown(query,
                decompiler_unknown_reason_t::provider_abstained,
                "semantic_adapter_invalid_response:" + query.stable_id));
            result.diagnostics.push_back(make_diagnostic(
                decompiler_diagnostic_code_t::provider_failure,
                "semantic_refiner.adapter.invalid_response",
                &query.coordinate,
                diagnostic_ordinal));
            has_semantic_unknown = true;
            continue;
        }
        if (!response_within_claimed_limits(response, limits)) {
            const bool timing_limit = response.elapsed_wall_clock_ms > limits.max_wall_clock_ms ||
                                      response.elapsed_cpu_ms > limits.max_cpu_ms;
            result.unknowns.push_back(make_unknown(query,
                timing_limit ? decompiler_unknown_reason_t::semantic_timeout
                             : decompiler_unknown_reason_t::bounded_analysis_limit,
                timing_limit ? "semantic_timeout:" + query.stable_id
                             : "semantic_memory_limit:" + query.stable_id));
            append_pending_unknowns(result, request.queries, index + 1,
                decompiler_unknown_reason_t::bounded_analysis_limit, "semantic_budget_exhausted");
            result.diagnostics.push_back(make_diagnostic(
                timing_limit ? decompiler_diagnostic_code_t::deadline_exceeded
                             : decompiler_diagnostic_code_t::resource_limit,
                "semantic_refiner.adapter.reported_limit_exceeded",
                &query.coordinate,
                diagnostic_ordinal));
            has_semantic_unknown = true;
            break;
        }

        switch (response.status) {
        case triton_z3_proof_status_t::proved: {
            if (response.refinement_key != query.refinement_key) {
                result.unknowns.push_back(make_unknown(query,
                    decompiler_unknown_reason_t::provider_abstained,
                    "semantic_adapter_mismatched_proof:" + query.stable_id));
                result.diagnostics.push_back(make_diagnostic(
                    decompiler_diagnostic_code_t::provider_failure,
                    "semantic_refiner.adapter.mismatched_proof",
                    &query.coordinate,
                    diagnostic_ordinal));
                has_semantic_unknown = true;
                break;
            }
            semantic_refinement_fact_t fact;
            fact.ordinal = query.ordinal;
            fact.stable_id = query.stable_id;
            fact.refinement_key = query.refinement_key;
            fact.coordinate = query.coordinate;
            result.facts.push_back(std::move(fact));
            break;
        }
        case triton_z3_proof_status_t::disproved:
            break;
        case triton_z3_proof_status_t::unknown:
            result.unknowns.push_back(make_unknown(query,
                map_unknown_reason(response.unknown_reason), "semantic_unknown:" + query.stable_id));
            result.diagnostics.push_back(make_diagnostic(
                decompiler_diagnostic_code_t::resource_limit,
                response.diagnostic_key.empty() ? "semantic_refiner.adapter.unknown" : response.diagnostic_key,
                &query.coordinate,
                diagnostic_ordinal));
            has_semantic_unknown = true;
            break;
        case triton_z3_proof_status_t::timeout:
            result.unknowns.push_back(make_unknown(query,
                decompiler_unknown_reason_t::semantic_timeout, "semantic_timeout:" + query.stable_id));
            result.diagnostics.push_back(make_diagnostic(
                decompiler_diagnostic_code_t::deadline_exceeded,
                response.diagnostic_key.empty() ? "semantic_refiner.adapter.timeout" : response.diagnostic_key,
                &query.coordinate,
                diagnostic_ordinal));
            has_semantic_unknown = true;
            break;
        case triton_z3_proof_status_t::cancelled:
            result.unknowns.push_back(make_unknown(query,
                decompiler_unknown_reason_t::provider_abstained,
                "semantic_adapter_cancelled:" + query.stable_id));
            result.diagnostics.push_back(make_diagnostic(
                decompiler_diagnostic_code_t::provider_failure,
                response.diagnostic_key.empty() ? "semantic_refiner.adapter.unexpected_cancel" : response.diagnostic_key,
                &query.coordinate,
                diagnostic_ordinal));
            has_semantic_unknown = true;
            break;
        case triton_z3_proof_status_t::denied:
            append_pending_unknowns(result, request.queries, index,
                decompiler_unknown_reason_t::provider_abstained, "semantic_adapter_denied");
            result.diagnostics.push_back(make_diagnostic(
                decompiler_diagnostic_code_t::unsupported_provider,
                response.diagnostic_key.empty() ? "semantic_refiner.adapter.denied" : response.diagnostic_key,
                &query.coordinate,
                diagnostic_ordinal));
            result.status = semantic_refinement_status_t::adapter_denied;
            return result;
        }
    }

    result.status = has_semantic_unknown
        ? semantic_refinement_status_t::completed_with_unknowns
        : semantic_refinement_status_t::completed;
    return result;
}

}
