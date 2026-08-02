#include "decompiler_service.hpp"

#include "native_worker_host.hpp"

#include "../builtin_typelib.hpp"
#include "../flirt/static_recognition_service.hpp"
#include "../workspace/analysis_metrics.hpp"
#include "../workspace/pe_image.hpp"
#include "../workspace/workspace_database.hpp"
#include "../workspace/workspace_registry.hpp"
#include "../../infra/cancellation_watchdog.hpp"
#include "../../../helpers/diag_log.hpp"
#include "../../../../workers/native_decompiler/snapshot_sidecar.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <charconv>
#include <chrono>
#include <condition_variable>
#include <limits>
#include <mutex>
#include <set>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <variant>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")

namespace aida::analysis {
namespace {

struct render_evidence_cache_entry_t {
    std::shared_ptr<const decompiler_render_evidence_t> evidence;
    std::uint64_t touch = 0;
};

struct service_state_data_t {
    std::shared_ptr<decompiler_provider_registry_t> providers;
    std::shared_ptr<decompiler_cache_v9_t> cache;
    std::shared_ptr<semantic_refiner_t> semantic_refiner;
    decompiler_pipeline_service_config_t config;
    mutable std::mutex gate_mutex;
    std::condition_variable gate_cv;
    std::atomic<bool> accepting{true};
    std::size_t active_requests = 0;
    cancellation_source_t stop_source;
    mutable std::mutex metrics_mutex;
    decompiler_pipeline_service_snapshot_t metrics;
    mutable std::mutex attest_mutex;
    std::condition_variable attest_cv;
    std::size_t attest_in_flight = 0;
    std::size_t attest_in_flight_peak = 0;
    std::uint64_t attest_submitted = 0;
    std::uint64_t attest_inline = 0;
    std::uint64_t attest_completed = 0;
    double dispatch_stage_ewm_ms = 0.0;
    double attest_stage_ewm_ms = 0.0;
    std::uint64_t attest_ratio_samples = 0;
    std::array<std::uint8_t, 32> attestation_sample_key{};
    std::uint64_t attestation_sampled_full = 0;
    std::uint64_t attestation_validated = 0;
    std::uint64_t attestation_mismatch = 0;
    mutable std::mutex evidence_mutex;
    std::unordered_map<std::string, render_evidence_cache_entry_t> evidence_cache;
    std::uint64_t evidence_clock = 0;
};

decompiler_diagnostic_t pipeline_diagnostic(
    const decompiler_diagnostic_severity_t severity,
    const decompiler_diagnostic_code_t code,
    std::string localization_key,
    const bool retryable = false,
    std::optional<source_coordinate_t> coordinate = {})
{
    decompiler_diagnostic_t diagnostic;
    diagnostic.severity = severity;
    diagnostic.code = code;
    diagnostic.localization_key = std::move(localization_key);
    diagnostic.coordinate = std::move(coordinate);
    diagnostic.confidence = 100;
    diagnostic.retryable = retryable;
    return diagnostic;
}

workspace_error_t service_error(
    const workspace_error_code_t code,
    std::string message)
{
    return make_workspace_error(code, std::move(message), "decompiler.pipeline_service");
}

void normalize_diagnostics(
    std::vector<decompiler_diagnostic_t>& diagnostics,
    const std::size_t limit)
{
    if (diagnostics.size() > limit) {
        diagnostics.resize(limit - 1);
        diagnostics.push_back(pipeline_diagnostic(
            decompiler_diagnostic_severity_t::warning,
            decompiler_diagnostic_code_t::resource_limit,
            "decompiler.pipeline.diagnostic_limit"));
    }
    for (std::size_t index = 0; index < diagnostics.size(); ++index)
        diagnostics[index].ordinal = static_cast<std::uint32_t>(index + 1);
}

void append_diagnostics(
    std::vector<decompiler_diagnostic_t>& target,
    const std::vector<decompiler_diagnostic_t>& source)
{
    target.insert(target.end(), source.begin(), source.end());
}

bool valid_invocation(const decompiler_pipeline_invocation_t value) noexcept
{
    return value == decompiler_pipeline_invocation_t::explicit_ui ||
           value == decompiler_pipeline_invocation_t::explicit_mcp ||
           value == decompiler_pipeline_invocation_t::explicit_api ||
           value == decompiler_pipeline_invocation_t::background_batch;
}

bool valid_cache_mode(const decompiler_pipeline_cache_mode_t value) noexcept
{
    return value == decompiler_pipeline_cache_mode_t::read_write ||
           value == decompiler_pipeline_cache_mode_t::read_only ||
           value == decompiler_pipeline_cache_mode_t::refresh ||
           value == decompiler_pipeline_cache_mode_t::bypass;
}

bool cache_reads_enabled(const decompiler_pipeline_cache_mode_t value) noexcept
{
    return value == decompiler_pipeline_cache_mode_t::read_write ||
           value == decompiler_pipeline_cache_mode_t::read_only;
}

bool cache_writes_enabled(const decompiler_pipeline_cache_mode_t value) noexcept
{
    return value == decompiler_pipeline_cache_mode_t::read_write ||
           value == decompiler_pipeline_cache_mode_t::refresh;
}

const decompiler_profile_budget_t* profile_budget(
    const decompiler_profile_policy_t& policy,
    const decompiler_profile_id_t profile) noexcept
{
    switch (profile) {
    case decompiler_profile_id_t::fast:
        return &policy.fast;
    case decompiler_profile_id_t::balanced:
        return &policy.balanced;
    case decompiler_profile_id_t::thorough:
        return &policy.thorough;
    }
    return nullptr;
}

bool budget_within(
    const decompiler_profile_budget_t& value,
    const decompiler_profile_budget_t& ceiling) noexcept
{
    return value.profile == ceiling.profile && value.schema_version == ceiling.schema_version &&
           value.max_wall_clock_ms <= ceiling.max_wall_clock_ms &&
           value.max_cpu_ms <= ceiling.max_cpu_ms &&
           value.max_memory_bytes <= ceiling.max_memory_bytes &&
           value.max_provider_ir_nodes <= ceiling.max_provider_ir_nodes &&
           value.max_hir_nodes <= ceiling.max_hir_nodes &&
           value.max_ast_nodes <= ceiling.max_ast_nodes &&
           value.max_semantic_queries <= ceiling.max_semantic_queries &&
           value.semantic_proofs_enabled == ceiling.semantic_proofs_enabled;
}

std::optional<decompiler_profile_budget_t> effective_budget(
    const decompiler_pipeline_request_t& request,
    const decompiler_profile_policy_t& policy)
{
    const auto* ceiling = profile_budget(policy, request.profile);
    if (!ceiling)
        return std::nullopt;
    if (!request.budget)
        return *ceiling;
    if (!validate_decompiler_profile(*request.budget).valid() ||
        !budget_within(*request.budget, *ceiling))
        return std::nullopt;
    return *request.budget;
}

bool valid_profile_policy(const decompiler_profile_policy_t& policy) noexcept
{
    return policy.fast.profile == decompiler_profile_id_t::fast &&
           policy.balanced.profile == decompiler_profile_id_t::balanced &&
           policy.thorough.profile == decompiler_profile_id_t::thorough &&
           validate_decompiler_profile(policy.fast).valid() &&
           validate_decompiler_profile(policy.balanced).valid() &&
           validate_decompiler_profile(policy.thorough).valid();
}

bool valid_config(const decompiler_pipeline_service_config_t& value) noexcept
{
    return value.max_parallel_requests != 0 && value.max_diagnostics >= 2 &&
           value.max_diagnostics <= std::numeric_limits<std::uint32_t>::max() &&
           value.max_provider_payload_bytes != 0 && value.max_normalized_payload_bytes != 0 &&
           value.ast_limits.max_hir_values != 0 && value.ast_limits.max_ast_nodes >= 3 &&
            value.ast_limits.max_expression_nesting != 0 && value.renderer_limits.max_ast_nodes != 0 &&
            value.renderer_limits.max_output_bytes != 0 && value.renderer_limits.max_tokens != 0 &&
            value.renderer_limits.max_source_maps != 0 && value.renderer_limits.max_nesting != 0 &&
            value.readability_limits.max_ast_nodes != 0 &&
            value.readability_limits.max_traversal_edges != 0 &&
            value.readability_limits.max_nesting != 0 &&
            value.readability_limits.max_document_bytes != 0 &&
            value.readability_limits.max_tokens != 0 &&
            value.readability_limits.max_source_maps != 0 &&
            value.readability_limits.max_diagnostics != 0 &&
            value.readability_limits.max_unknowns != 0 &&
            valid_profile_policy(value.profiles);
}

std::chrono::steady_clock::time_point minimum_deadline(
    const std::chrono::steady_clock::time_point start,
    const decompiler_profile_budget_t& budget,
    const decompiler_pipeline_request_t& request,
    const cancellation_token_t& cancel)
{
    auto deadline = start + std::chrono::milliseconds(budget.max_wall_clock_ms);
    if (request.deadline && *request.deadline < deadline)
        deadline = *request.deadline;
    const auto caller_deadline = cancel.deadline();
    if (caller_deadline && *caller_deadline < deadline)
        deadline = *caller_deadline;
    return deadline;
}

class cancellation_bridge_t final {
public:
    cancellation_bridge_t(
        const cancellation_token_t& caller,
        const cancellation_token_t& service,
        const std::chrono::steady_clock::time_point deadline)
        : state_(std::make_shared<bridge_state_t>(caller, service, deadline))
    {
        if (caller.stop_requested() || service.stop_requested()) {
            state_->source.request_cancel();
            state_->finished.store(true, std::memory_order_release);
            return;
        }
        arm_watch(state_);
    }

    ~cancellation_bridge_t()
    {
        infra::cancellation_watchdog::watch_id_t outstanding;
        {
            std::lock_guard lock(state_->watch_mutex);
            state_->finished.store(true, std::memory_order_release);
            outstanding = state_->watch;
            state_->watch = infra::cancellation_watchdog::watch_id_t{};
        }
        if (outstanding.valid())
            static_cast<void>(infra::cancellation_watchdog::unregister_watch(outstanding));
    }

    cancellation_bridge_t(const cancellation_bridge_t&) = delete;
    cancellation_bridge_t& operator=(const cancellation_bridge_t&) = delete;

    cancellation_token_t token() const noexcept
    {
        return state_->source.token();
    }

private:
    struct bridge_state_t {
        bridge_state_t(
            const cancellation_token_t& caller_value,
            const cancellation_token_t& service_value,
            const std::chrono::steady_clock::time_point deadline_value)
            : source(deadline_value), caller(caller_value), service(service_value),
              deadline(deadline_value)
        {
        }

        cancellation_source_t source;
        cancellation_token_t caller;
        cancellation_token_t service;
        std::chrono::steady_clock::time_point deadline;
        std::atomic<bool> finished{false};
        std::mutex watch_mutex;
        infra::cancellation_watchdog::watch_id_t watch{};
    };

    static void arm_watch(const std::shared_ptr<bridge_state_t>& state)
    {
        if (state->finished.load(std::memory_order_acquire))
            return;
        infra::cancellation_watchdog::watch_descriptor_t descriptor;
        descriptor.deadline_ms =
            static_cast<std::uint64_t>(GetTickCount64()) +
            infra::cancellation_watchdog::sweep_interval_ms;
        descriptor.on_fire = [state] {
            if (state->finished.load(std::memory_order_acquire))
                return;
            if (state->caller.stop_requested() || state->service.stop_requested() ||
                std::chrono::steady_clock::now() >= state->deadline) {
                state->source.request_cancel();
                return;
            }
            arm_watch(state);
        };
        std::lock_guard lock(state->watch_mutex);
        if (state->finished.load(std::memory_order_acquire))
            return;
        state->watch = infra::cancellation_watchdog::register_watch(std::move(descriptor));
        if (!state->watch.valid()) {
            ::diag::log_tagged_fmt("decompiler",
                "cancellation_bridge_watch_rejected propagation=deadline_only");
        }
    }

    std::shared_ptr<bridge_state_t> state_;
};

class request_slot_t final {
public:
    request_slot_t() = default;
    explicit request_slot_t(service_state_data_t* state) : state_(state) {}

    request_slot_t(request_slot_t&& other) noexcept : state_(std::exchange(other.state_, nullptr)) {}
    request_slot_t& operator=(request_slot_t&& other) noexcept
    {
        if (this != &other) {
            release();
            state_ = std::exchange(other.state_, nullptr);
        }
        return *this;
    }

    ~request_slot_t()
    {
        release();
    }

    request_slot_t(const request_slot_t&) = delete;
    request_slot_t& operator=(const request_slot_t&) = delete;

private:
    void release() noexcept
    {
        if (!state_)
            return;
        {
            std::lock_guard lock(state_->gate_mutex);
            --state_->active_requests;
        }
        state_->gate_cv.notify_one();
        state_ = nullptr;
    }

    service_state_data_t* state_ = nullptr;
};

workspace_result_t<request_slot_t> acquire_slot(
    service_state_data_t& state,
    const cancellation_token_t& cancel,
    const std::chrono::steady_clock::time_point deadline)
{
    std::unique_lock lock(state.gate_mutex);
    while (state.accepting && state.active_requests >= state.config.max_parallel_requests &&
           !cancel.stop_requested()) {
        if (std::chrono::steady_clock::now() >= deadline)
            break;
        state.gate_cv.wait_until(lock, std::min(deadline, std::chrono::steady_clock::now() + std::chrono::milliseconds(5)));
    }
    if (!state.accepting) {
        return workspace_result_t<request_slot_t>::failure(
            service_error(workspace_error_code_t::workspace_closing, "decompiler service is stopped"));
    }
    if (cancel.stop_requested()) {
        return workspace_result_t<request_slot_t>::failure(
            service_error(cancel.deadline_exceeded() ? workspace_error_code_t::deadline_exceeded
                                                     : workspace_error_code_t::cancelled,
                          "decompiler request was cancelled while queued"));
    }
    if (std::chrono::steady_clock::now() >= deadline) {
        return workspace_result_t<request_slot_t>::failure(
            service_error(workspace_error_code_t::deadline_exceeded,
                          "decompiler request exceeded its queue deadline"));
    }
    ++state.active_requests;
    return workspace_result_t<request_slot_t>::success(request_slot_t(&state));
}

std::size_t attest_in_flight_cap(service_state_data_t& state) noexcept
{
    const std::size_t slots = (std::max<std::size_t>)(1, state.config.max_parallel_requests);
    if (state.attest_ratio_samples < 16 || state.dispatch_stage_ewm_ms <= 0.0 ||
        state.attest_stage_ewm_ms <= 0.0)
        return slots * 2;
    const double ratio = state.attest_stage_ewm_ms / state.dispatch_stage_ewm_ms;
    const double scaled = static_cast<double>(slots) * ratio;
    const std::size_t rounded = scaled < 0.0 ? slots
        : static_cast<std::size_t>(scaled + 0.5);
    return (std::max)((std::min)(rounded, slots * 2), slots);
}

void attest_ratio_sample(
    service_state_data_t& state,
    const double dispatch_ms,
    const double attest_ms) noexcept
{
    std::lock_guard lock(state.attest_mutex);
    const auto fold = [](const double current, const double sample) {
        return current <= 0.0 ? sample : current + (sample - current) / 16.0;
    };
    state.dispatch_stage_ewm_ms = fold(state.dispatch_stage_ewm_ms, dispatch_ms);
    state.attest_stage_ewm_ms = fold(state.attest_stage_ewm_ms, attest_ms);
    ++state.attest_ratio_samples;
}

BCRYPT_ALG_HANDLE attestation_hmac_provider() noexcept
{
    static BCRYPT_ALG_HANDLE handle = [] {
        BCRYPT_ALG_HANDLE opened = nullptr;
        if (BCryptOpenAlgorithmProvider(&opened, BCRYPT_SHA256_ALGORITHM, nullptr,
                BCRYPT_ALG_HANDLE_HMAC_FLAG) != 0)
            return static_cast<BCRYPT_ALG_HANDLE>(nullptr);
        return opened;
    }();
    return handle;
}

bool attestation_hmac_sha256(
    const std::array<std::uint8_t, 32>& key,
    const void* data,
    const std::size_t data_size,
    std::array<std::uint8_t, 32>& out) noexcept
{
    BCRYPT_ALG_HANDLE provider = attestation_hmac_provider();
    if (provider == nullptr)
        return false;
    BCRYPT_HASH_HANDLE hash = nullptr;
    if (BCryptCreateHash(provider, &hash, nullptr, 0,
            const_cast<PUCHAR>(key.data()), static_cast<ULONG>(key.size()), 0) != 0 || hash == nullptr)
        return false;
    bool ok = data_size <= static_cast<std::size_t>((std::numeric_limits<ULONG>::max)()) &&
        BCryptHashData(hash, reinterpret_cast<PUCHAR>(const_cast<void*>(data)),
            static_cast<ULONG>(data_size), 0) == 0 &&
        BCryptFinishHash(hash, out.data(), static_cast<ULONG>(out.size()), 0) == 0;
    BCryptDestroyHash(hash);
    return ok;
}

void attestation_message_append_u64(std::string& message, const std::uint64_t value)
{
    for (unsigned shift = 0; shift < 64; shift += 8)
        message.push_back(static_cast<char>((value >> shift) & 0xffU));
}

bool attestation_sampled_for_job(
    const service_state_data_t& state,
    const decompiler_pipeline_request_t& request,
    const decompiler_provider_identity_t& provider,
    const std::uint64_t function_rva) noexcept
{
    const std::uint32_t rate = state.config.batch_attestation_sample_rate;
    if (rate <= 1)
        return true;
    std::string message;
    message.reserve(request.workspace_id.size() + 1 + 24 + provider.provider_binary_hash.bytes.size());
    message.append(request.workspace_id);
    message.push_back('\x1f');
    attestation_message_append_u64(message, request.workspace_generation);
    attestation_message_append_u64(message, request.analysis_revision);
    attestation_message_append_u64(message, function_rva);
    message.append(reinterpret_cast<const char*>(provider.provider_binary_hash.bytes.data()),
        provider.provider_binary_hash.bytes.size());
    std::array<std::uint8_t, 32> tag{};
    if (!attestation_hmac_sha256(state.attestation_sample_key, message.data(), message.size(), tag)) {
        ::diag::log_tagged_fmt("decompiler", "attestation_sampler_hmac_failed fail_closed=full");
        return true;
    }
    std::uint64_t selector = 0;
    for (unsigned index = 0; index < 8; ++index)
        selector |= static_cast<std::uint64_t>(tag[index]) << (index * 8);
    return selector % rate == 0;
}

class attest_slot_t final {
public:
    attest_slot_t() = default;
    explicit attest_slot_t(service_state_data_t* state) : state_(state) {}

    attest_slot_t(attest_slot_t&& other) noexcept : state_(std::exchange(other.state_, nullptr)) {}
    attest_slot_t& operator=(attest_slot_t&& other) noexcept
    {
        if (this != &other) {
            release();
            state_ = std::exchange(other.state_, nullptr);
        }
        return *this;
    }

    ~attest_slot_t()
    {
        release();
    }

    attest_slot_t(const attest_slot_t&) = delete;
    attest_slot_t& operator=(const attest_slot_t&) = delete;

private:
    void release() noexcept
    {
        if (!state_)
            return;
        {
            std::lock_guard lock(state_->attest_mutex);
            if (state_->attest_in_flight != 0)
                --state_->attest_in_flight;
        }
        state_->attest_cv.notify_one();
        state_ = nullptr;
    }

    service_state_data_t* state_ = nullptr;
};

workspace_result_t<attest_slot_t> acquire_attest_slot(
    service_state_data_t& state,
    const cancellation_token_t& cancel,
    const std::chrono::steady_clock::time_point deadline)
{
    std::unique_lock lock(state.attest_mutex);
    const auto cap = attest_in_flight_cap(state);
    while (state.accepting && state.attest_in_flight >= cap && !cancel.stop_requested()) {
        if (std::chrono::steady_clock::now() >= deadline)
            break;
        state.attest_cv.wait_until(lock, std::min(deadline, std::chrono::steady_clock::now() + std::chrono::milliseconds(5)));
    }
    if (!state.accepting) {
        return workspace_result_t<attest_slot_t>::failure(
            service_error(workspace_error_code_t::workspace_closing, "decompiler service is stopped"));
    }
    if (cancel.stop_requested()) {
        return workspace_result_t<attest_slot_t>::failure(
            service_error(cancel.deadline_exceeded() ? workspace_error_code_t::deadline_exceeded
                                                     : workspace_error_code_t::cancelled,
                          "decompiler attest stage was cancelled while queued"));
    }
    if (std::chrono::steady_clock::now() >= deadline) {
        return workspace_result_t<attest_slot_t>::failure(
            service_error(workspace_error_code_t::deadline_exceeded,
                          "decompiler attest stage exceeded its queue deadline"));
    }
    ++state.attest_in_flight;
    if (state.attest_in_flight > state.attest_in_flight_peak)
        state.attest_in_flight_peak = state.attest_in_flight;
    return workspace_result_t<attest_slot_t>::success(attest_slot_t(&state));
}

bool equal_provider(
    const decompiler_provider_identity_t& left,
    const decompiler_provider_identity_t& right) noexcept
{
    return left.provider == right.provider && left.provider_name == right.provider_name &&
           left.provider_version == right.provider_version &&
           left.provider_binary_hash == right.provider_binary_hash &&
           left.worker_build_id == right.worker_build_id &&
           left.worker_build_hash == right.worker_build_hash;
}

bool equivalent_attested_document(
    const decompiler_document_t& attested,
    const decompiler_document_t& rendered)
{
    if (!validate_decompiler_document(attested).valid() ||
        !validate_decompiler_document(rendered).valid())
        return false;
    auto canonical_attested = attested;
    auto canonical_rendered = rendered;
    canonical_attested.diagnostics.clear();
    canonical_rendered.diagnostics.clear();
    return serialize_decompiler_document(canonical_attested) ==
           serialize_decompiler_document(canonical_rendered);
}

constexpr std::size_t k_semantic_condition_max_ir_nodes = 24;

struct semantic_condition_encoder_t {
    const type_graph_t* types = nullptr;
    std::unordered_map<std::uint64_t, const hir_value_t*> values;
    std::unordered_map<std::uint64_t, std::uint32_t> memo;
    triton_z3_static_ir_t ir;
    bool unsupported = false;

    std::uint32_t add_node(triton_z3_ir_opcode_t opcode, std::uint32_t width,
                           std::uint64_t literal, std::string symbol,
                           std::uint32_t lhs, std::uint32_t rhs) {
        if (unsupported || ir.nodes.size() >= k_semantic_condition_max_ir_nodes) {
            unsupported = true;
            return 0;
        }
        triton_z3_ir_node_t node;
        node.id = static_cast<std::uint32_t>(ir.nodes.size() + 1);
        node.opcode = opcode;
        node.bit_width = width;
        node.literal = literal;
        node.symbol = std::move(symbol);
        node.lhs_id = lhs;
        node.rhs_id = rhs;
        ir.nodes.push_back(std::move(node));
        return ir.nodes.back().id;
    }

    std::uint32_t value_width(const hir_value_t& value) const {
        if (types && value.type_id != 0) {
            if (const auto* node = type_graph::find_type_node(*types, value.type_id)) {
                if (node->byte_size && *node->byte_size != 0 && *node->byte_size <= 8)
                    return static_cast<std::uint32_t>(*node->byte_size * 8);
            }
        }
        return 64;
    }

    static bool parse_literal(std::string_view text, std::uint64_t& out) noexcept {
        if (text.empty())
            return false;
        auto begin = text.data();
        auto end = begin + text.size();
        int base = 10;
        if (text.size() > 2 && text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) {
            begin += 2;
            base = 16;
        }
        const auto parsed = std::from_chars(begin, end, out, base);
        return parsed.ec == std::errc{} && parsed.ptr == end;
    }

    static std::string operator_token(const hir_value_t& value) {
        std::string token = value.stable_value;
        std::string lowered;
        lowered.reserve(token.size());
        for (const char ch : token)
            if (ch >= 'A' && ch <= 'Z')
                lowered.push_back(static_cast<char>(ch - 'A' + 'a'));
            else if (ch != ' ' && ch != '\t')
                lowered.push_back(ch);
        return lowered;
    }

    std::uint32_t encode(std::uint64_t value_id, std::uint32_t depth) {
        if (unsupported || depth > k_semantic_condition_max_ir_nodes) {
            unsupported = true;
            return 0;
        }
        const auto memoized = memo.find(value_id);
        if (memoized != memo.end())
            return memoized->second;
        const auto found = values.find(value_id);
        if (found == values.end() || !found->second) {
            unsupported = true;
            return 0;
        }
        const hir_value_t& value = *found->second;
        std::uint32_t node_id = 0;
        switch (value.kind) {
        case hir_node_kind_t::literal: {
            std::uint64_t literal = 0;
            if (!parse_literal(value.stable_value, literal)) {
                unsupported = true;
                return 0;
            }
            node_id = add_node(triton_z3_ir_opcode_t::bitvector_constant, 64, literal, {}, 0, 0);
            break;
        }
        case hir_node_kind_t::parameter:
        case hir_node_kind_t::local:
        case hir_node_kind_t::reference: {
            node_id = add_node(triton_z3_ir_opcode_t::symbolic_variable,
                               value_width(value), 0, "v" + std::to_string(value.id), 0, 0);
            break;
        }
        case hir_node_kind_t::cast: {
            if (value.operand_ids.size() != 1) {
                unsupported = true;
                return 0;
            }
            const auto operand = values.find(value.operand_ids.front());
            if (operand == values.end() || !operand->second ||
                value_width(value) != value_width(*operand->second)) {
                unsupported = true;
                return 0;
            }
            node_id = encode(value.operand_ids.front(), depth + 1);
            break;
        }
        case hir_node_kind_t::unary: {
            if (value.operand_ids.size() != 1) {
                unsupported = true;
                return 0;
            }
            const std::uint32_t operand = encode(value.operand_ids.front(), depth + 1);
            if (unsupported)
                return 0;
            const std::string op = operator_token(value);
            const std::uint32_t width = value_width(value);
            if (op == "-") {
                const std::uint32_t zero = add_node(
                    triton_z3_ir_opcode_t::bitvector_constant, width, 0, {}, 0, 0);
                node_id = add_node(triton_z3_ir_opcode_t::subtract, width, 0, {}, zero, operand);
            } else if (op == "~") {
                const std::uint64_t ones = width == 64 ? ~std::uint64_t{0}
                    : ((std::uint64_t{1} << width) - 1);
                const std::uint32_t all_ones = add_node(
                    triton_z3_ir_opcode_t::bitvector_constant, width, ones, {}, 0, 0);
                node_id = add_node(triton_z3_ir_opcode_t::bitwise_xor, width, 0, {}, operand, all_ones);
            } else if (op == "!") {
                const std::uint32_t zero = add_node(
                    triton_z3_ir_opcode_t::bitvector_constant, width, 0, {}, 0, 0);
                node_id = add_node(triton_z3_ir_opcode_t::equal, 1, 0, {}, operand, zero);
            } else {
                unsupported = true;
                return 0;
            }
            break;
        }
        case hir_node_kind_t::binary: {
            if (value.operand_ids.size() != 2) {
                unsupported = true;
                return 0;
            }
            const std::uint32_t lhs = encode(value.operand_ids[0], depth + 1);
            const std::uint32_t rhs = encode(value.operand_ids[1], depth + 1);
            if (unsupported)
                return 0;
            const std::string op = operator_token(value);
            const std::uint32_t width = value_width(value);
            const auto binary_width = [&](triton_z3_ir_opcode_t opcode) {
                return add_node(opcode, width, 0, {}, lhs, rhs);
            };
            const auto zero = [&] {
                return add_node(triton_z3_ir_opcode_t::bitvector_constant, width, 0, {}, 0, 0);
            };
            const auto compare1 = [&](triton_z3_ir_opcode_t opcode, std::uint32_t a, std::uint32_t b) {
                return add_node(opcode, 1, 0, {}, a, b);
            };
            if (op == "+") node_id = binary_width(triton_z3_ir_opcode_t::add);
            else if (op == "-") node_id = binary_width(triton_z3_ir_opcode_t::subtract);
            else if (op == "*") node_id = binary_width(triton_z3_ir_opcode_t::multiply);
            else if (op == "&") node_id = binary_width(triton_z3_ir_opcode_t::bitwise_and);
            else if (op == "|") node_id = binary_width(triton_z3_ir_opcode_t::bitwise_or);
            else if (op == "^") node_id = binary_width(triton_z3_ir_opcode_t::bitwise_xor);
            else if (op == "<<") node_id = binary_width(triton_z3_ir_opcode_t::shift_left);
            else if (op == ">>") node_id = binary_width(triton_z3_ir_opcode_t::logical_shift_right);
            else if (op == ">>a" || op == "sar") node_id = binary_width(triton_z3_ir_opcode_t::arithmetic_shift_right);
            else if (op == "==") node_id = compare1(triton_z3_ir_opcode_t::equal, lhs, rhs);
            else if (op == "!=") node_id = compare1(triton_z3_ir_opcode_t::distinct, lhs, rhs);
            else if (op == "<u") node_id = compare1(triton_z3_ir_opcode_t::unsigned_less_than, lhs, rhs);
            else if (op == "<" || op == "<s") node_id = compare1(triton_z3_ir_opcode_t::signed_less_than, lhs, rhs);
            else if (op == ">u") node_id = compare1(triton_z3_ir_opcode_t::unsigned_less_than, rhs, lhs);
            else if (op == ">" || op == ">s") node_id = compare1(triton_z3_ir_opcode_t::signed_less_than, rhs, lhs);
            else if (op == "<=u") {
                const std::uint32_t inner = compare1(triton_z3_ir_opcode_t::unsigned_less_than, rhs, lhs);
                node_id = add_node(triton_z3_ir_opcode_t::logical_not, 1, 0, {}, inner, 0);
            } else if (op == "<=" || op == "<=s") {
                const std::uint32_t inner = compare1(triton_z3_ir_opcode_t::signed_less_than, rhs, lhs);
                node_id = add_node(triton_z3_ir_opcode_t::logical_not, 1, 0, {}, inner, 0);
            } else if (op == ">=u") {
                const std::uint32_t inner = compare1(triton_z3_ir_opcode_t::unsigned_less_than, lhs, rhs);
                node_id = add_node(triton_z3_ir_opcode_t::logical_not, 1, 0, {}, inner, 0);
            } else if (op == ">=" || op == ">=s") {
                const std::uint32_t inner = compare1(triton_z3_ir_opcode_t::signed_less_than, lhs, rhs);
                node_id = add_node(triton_z3_ir_opcode_t::logical_not, 1, 0, {}, inner, 0);
            } else if (op == "&&") {
                const std::uint32_t lhs_bool = compare1(triton_z3_ir_opcode_t::distinct, lhs, zero());
                const std::uint32_t rhs_bool = compare1(triton_z3_ir_opcode_t::distinct, rhs, zero());
                node_id = add_node(triton_z3_ir_opcode_t::logical_and, 1, 0, {}, lhs_bool, rhs_bool);
            } else if (op == "||") {
                const std::uint32_t lhs_bool = compare1(triton_z3_ir_opcode_t::distinct, lhs, zero());
                const std::uint32_t rhs_bool = compare1(triton_z3_ir_opcode_t::distinct, rhs, zero());
                const std::uint32_t lhs_not = add_node(triton_z3_ir_opcode_t::logical_not, 1, 0, {}, lhs_bool, 0);
                const std::uint32_t rhs_not = add_node(triton_z3_ir_opcode_t::logical_not, 1, 0, {}, rhs_bool, 0);
                const std::uint32_t both = add_node(triton_z3_ir_opcode_t::logical_and, 1, 0, {}, lhs_not, rhs_not);
                node_id = add_node(triton_z3_ir_opcode_t::logical_not, 1, 0, {}, both, 0);
            } else {
                unsupported = true;
                return 0;
            }
            break;
        }
        default:
            unsupported = true;
            return 0;
        }
        if (!unsupported && node_id != 0)
            memo.emplace(value_id, node_id);
        return node_id;
    }
};

std::uint64_t semantic_ir_structural_hash(const triton_z3_static_ir_t& ir) noexcept
{
    std::uint64_t hash = 1469598103934665603ULL;
    const auto mix = [&hash](const void* data, std::size_t size) {
        const auto* bytes = static_cast<const std::uint8_t*>(data);
        for (std::size_t index = 0; index < size; ++index) {
            hash ^= bytes[index];
            hash *= 1099511628211ULL;
        }
    };
    for (const auto& node : ir.nodes) {
        const std::uint8_t opcode = static_cast<std::uint8_t>(node.opcode);
        mix(&opcode, sizeof(opcode));
        mix(&node.bit_width, sizeof(node.bit_width));
        mix(&node.literal, sizeof(node.literal));
        mix(node.symbol.data(), node.symbol.size());
        const std::uint8_t terminator = 0xFF;
        mix(&terminator, sizeof(terminator));
        mix(&node.lhs_id, sizeof(node.lhs_id));
        mix(&node.rhs_id, sizeof(node.rhs_id));
    }
    return hash;
}

std::vector<semantic_refinement_query_t> produce_semantic_queries(
    const hir_function_t& hir,
    const type_graph_t& type_graph,
    const std::uint32_t maximum)
{
    std::vector<semantic_refinement_query_t> result;
    if (maximum == 0)
        return result;
    result.reserve((std::min<std::size_t>)(maximum, 256));
    std::unordered_map<std::uint64_t, const hir_value_t*> values;
    bool collision = false;
    for (const auto& block : hir.blocks) {
        for (const auto& value : block.values) {
            if (!values.emplace(value.id, &value).second)
                collision = true;
        }
    }
    if (collision) {
        ::diag::log_tagged_fmt("decompiler",
            "semantic_producer skipped reason=hir_value_id_collision");
        return result;
    }
    std::unordered_set<std::uint64_t> emitted;
    for (const auto& block : hir.blocks) {
        for (const auto& value : block.values) {
            if (result.size() >= maximum)
                return result;
            if ((value.kind != hir_node_kind_t::branch && value.kind != hir_node_kind_t::conditional) ||
                value.operand_ids.empty() ||
                value.coordinate.layer != decompiler_coordinate_layer_t::hir)
                continue;
            const std::uint64_t condition_id = value.operand_ids.front();
            const auto condition = values.find(condition_id);
            if (condition == values.end() || !condition->second)
                continue;
            semantic_condition_encoder_t encoder;
            encoder.types = &type_graph;
            encoder.values = values;
            encoder.ir.domain = triton_z3_semantic_domain_t::condition;
            const std::uint32_t encoded = encoder.encode(condition_id, 0);
            if (encoder.unsupported || encoded == 0 || encoder.ir.nodes.empty())
                continue;
            std::uint32_t condition_node = encoded;
            const auto& encoded_root = encoder.ir.nodes.back();
            if (encoded_root.bit_width != 1) {
                triton_z3_ir_node_t zero;
                zero.id = static_cast<std::uint32_t>(encoder.ir.nodes.size() + 1);
                zero.opcode = triton_z3_ir_opcode_t::bitvector_constant;
                zero.bit_width = encoded_root.bit_width;
                zero.literal = 0;
                encoder.ir.nodes.push_back(zero);
                triton_z3_ir_node_t wrapped;
                wrapped.id = static_cast<std::uint32_t>(encoder.ir.nodes.size() + 1);
                wrapped.opcode = triton_z3_ir_opcode_t::distinct;
                wrapped.bit_width = 1;
                wrapped.lhs_id = encoded;
                wrapped.rhs_id = zero.id;
                encoder.ir.nodes.push_back(wrapped);
                condition_node = wrapped.id;
            }
            triton_z3_ir_node_t one;
            one.id = static_cast<std::uint32_t>(encoder.ir.nodes.size() + 1);
            one.opcode = triton_z3_ir_opcode_t::bitvector_constant;
            one.bit_width = 1;
            one.literal = 0;
            encoder.ir.nodes.push_back(one);
            triton_z3_ir_node_t root;
            root.id = static_cast<std::uint32_t>(encoder.ir.nodes.size() + 1);
            root.opcode = triton_z3_ir_opcode_t::equal;
            root.bit_width = 1;
            root.lhs_id = condition_node;
            root.rhs_id = one.id;
            encoder.ir.nodes.push_back(root);
            encoder.ir.root_node_id = root.id;
            if (!valid_triton_z3_static_ir(encoder.ir))
                continue;
            const std::uint64_t structural = semantic_ir_structural_hash(encoder.ir);
            if (!emitted.insert(structural).second)
                continue;
            semantic_refinement_query_t query;
            query.ordinal = static_cast<std::uint64_t>(result.size() + 1);
            query.stable_id = "branchcond_" + std::to_string(value.id);
            query.coordinate = value.coordinate;
            query.refinement_key = "branch_cond_eq0.v" + std::to_string(value.id);
            query.static_ir = std::move(encoder.ir);
            result.push_back(std::move(query));
        }
    }
    return result;
}

workspace_result_t<pseudocode_readability_report_t> readability_report(
    const decompiler_document_t& document,
    const decompiler_pipeline_service_config_t& config)
{
    pseudocode_readability_request_t request;
    request.limits = config.readability_limits;
    request.require_complete_source_map = config.require_complete_source_map;
    auto analyzed = analyze_pseudocode_readability(document.ast, document, request);
    if (!analyzed.succeeded() || !analyzed.report) {
        return workspace_result_t<pseudocode_readability_report_t>::failure(make_workspace_error(
            workspace_error_code_t::integrity_failure,
            "rendered pseudocode failed the readability contract",
            "decompiler.pipeline.readability"));
    }
    return workspace_result_t<pseudocode_readability_report_t>::success(
        std::move(*analyzed.report));
}

bool equal_language(
    const decompiler_language_identity_t& left,
    const decompiler_language_identity_t& right) noexcept
{
    return left.language_id == right.language_id && left.language_version == right.language_version &&
           left.compiler_spec_id == right.compiler_spec_id &&
           left.language_spec_hash == right.language_spec_hash &&
           left.architecture == right.architecture && left.mode == right.mode &&
           left.endian == right.endian;
}

decompiler_renderer_settings_t renderer_settings(const decompiler_pipeline_request_t& request)
{
    if (request.renderer)
        return *request.renderer;
    switch (request.profile) {
    case decompiler_profile_id_t::fast:
        return pseudocode_renderer_v2_style_settings(pseudocode_renderer_v2_style_profile_t::compact);
    case decompiler_profile_id_t::balanced:
        return pseudocode_renderer_v2_style_settings(pseudocode_renderer_v2_style_profile_t::balanced);
    case decompiler_profile_id_t::thorough:
        return pseudocode_renderer_v2_style_settings(pseudocode_renderer_v2_style_profile_t::audit);
    }
    return {};
}

std::string sidecar_hex_text(std::uint64_t value)
{
    static constexpr char k_hex[] = "0123456789abcdef";
    char digits[16];
    std::size_t count = 0;
    do {
        digits[count++] = k_hex[value & 0xFULL];
        value >>= 4U;
    } while (value != 0 && count < 16);
    std::string text;
    text.reserve(count);
    while (count != 0)
        text.push_back(digits[--count]);
    return text;
}

std::string sidecar_prefixed_unresolved_text(
    const char* prefix,
    const std::uint64_t image_base,
    const std::uint64_t rva)
{
    if (rva > (std::numeric_limits<std::uint64_t>::max)() - image_base)
        return {};
    return std::string(prefix) + sidecar_hex_text(image_base + rva);
}

std::string sidecar_unresolved_text(const std::uint64_t image_base, const std::uint64_t rva)
{
    return sidecar_prefixed_unresolved_text("sub_", image_base, rva);
}

bool sidecar_identifier_text(const std::string& text) noexcept
{
    if (text.empty())
        return false;
    const auto letter = [](const char value) {
        return (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z') || value == '_';
    };
    if (!letter(text.front()))
        return false;
    return std::all_of(text.begin() + 1, text.end(), [&](const char value) {
        return letter(value) || (value >= '0' && value <= '9');
    });
}

bool sidecar_convention_token(const std::string& token) noexcept
{
    static const char* const k_conventions[] = {
        "__stdcall", "__cdecl", "__fastcall", "__thiscall", "__vectorcall", "__clrcall",
        "WINAPI", "WINAPIV", "CALLBACK", "NTAPI", "APIENTRY", "STDCALL", "CDECL", "FASTCALL"
    };
    for (const auto* convention : k_conventions) {
        if (token == convention)
            return true;
    }
    return false;
}

std::string sidecar_trim(const std::string& text)
{
    const auto begin = text.find_first_not_of(" \t\r\n");
    if (begin == std::string::npos)
        return {};
    const auto end = text.find_last_not_of(" \t\r\n");
    return text.substr(begin, end - begin + 1);
}

std::vector<std::string> sidecar_split_ws(const std::string& text)
{
    std::vector<std::string> tokens;
    std::size_t cursor = 0;
    while (cursor < text.size()) {
        const auto begin = text.find_first_not_of(" \t\r\n", cursor);
        if (begin == std::string::npos)
            break;
        const auto end = text.find_first_of(" \t\r\n", begin);
        tokens.push_back(text.substr(begin, end == std::string::npos ? end : end - begin));
        cursor = end == std::string::npos ? text.size() : end + 1;
    }
    return tokens;
}

struct sidecar_prototype_parse_t {
    std::string name;
    std::string return_type;
    std::vector<std::string> argument_names;
    std::vector<std::string> argument_types;
    bool is_variadic = false;
};

std::optional<sidecar_prototype_parse_t> parse_sidecar_prototype_text(const std::string& text)
{
    const auto open = text.find('(');
    const auto close = text.rfind(')');
    if (open == std::string::npos || close == std::string::npos || close <= open + 1)
        return std::nullopt;
    const auto head = sidecar_trim(text.substr(0, open));
    if (head.empty())
        return std::nullopt;
    auto tokens = sidecar_split_ws(head);
    if (tokens.empty())
        return std::nullopt;
    sidecar_prototype_parse_t result;
    result.name = tokens.back();
    tokens.pop_back();
    if (!sidecar_identifier_text(result.name))
        return std::nullopt;
    std::string return_type;
    for (const auto& token : tokens) {
        if (sidecar_convention_token(token))
            continue;
        if (!return_type.empty())
            return_type.push_back(' ');
        return_type += token;
    }
    result.return_type = std::move(return_type);
    const std::string params = text.substr(open + 1, close - open - 1);
    std::vector<std::string> segments;
    std::size_t depth = 0;
    std::size_t segment_begin = 0;
    for (std::size_t index = 0; index < params.size(); ++index) {
        const char value = params[index];
        if (value == '(')
            ++depth;
        else if (value == ')' && depth != 0)
            --depth;
        else if (value == ',' && depth == 0) {
            segments.push_back(params.substr(segment_begin, index - segment_begin));
            segment_begin = index + 1;
        }
    }
    segments.push_back(params.substr(segment_begin));
    const bool single_void = segments.size() == 1 && sidecar_trim(segments.front()) == "void";
    if (!single_void) {
        for (const auto& raw : segments) {
            auto parameter = sidecar_trim(raw);
            if (parameter.empty())
                continue;
            if (parameter == "...") {
                result.is_variadic = true;
                continue;
            }
            while (!parameter.empty() && parameter.back() == ']') {
                const auto bracket = parameter.rfind('[');
                if (bracket == std::string::npos)
                    break;
                parameter = sidecar_trim(parameter.substr(0, bracket));
            }
            std::string argument_name;
            std::string argument_type = parameter;
            const auto space = parameter.find_last_of(" \t");
            if (space != std::string::npos) {
                const auto tail = parameter.substr(space + 1);
                std::string candidate = tail;
                while (!candidate.empty() && (candidate.front() == '*' || candidate.front() == '&'))
                    candidate.erase(candidate.begin());
                if (sidecar_identifier_text(candidate)) {
                    argument_name = tail;
                    argument_type = sidecar_trim(parameter.substr(0, space));
                }
            }
            if (argument_type.empty())
                argument_type = parameter;
            result.argument_names.push_back(std::move(argument_name));
            result.argument_types.push_back(std::move(argument_type));
        }
    }
    return result;
}

std::shared_ptr<const static_recognition::recognition_records_t>
recognition_records_for_sidecar(const std::uint64_t image_base) noexcept
{
    if (image_base == 0)
        return {};
    try {
        std::shared_ptr<analysis_workspace_t> matched;
        std::size_t matches = 0;
        for (const auto& workspace : workspace_registry().list()) {
            if (!workspace || workspace->closing() || workspace->closed() ||
                workspace->target_kind() != target_kind_t::static_file)
                continue;
            const auto image = workspace->image();
            if (!image || image->image_base() != image_base)
                continue;
            matched = workspace;
            ++matches;
        }
        if (matches != 1 || !matched)
            return {};
        return static_recognition::records_for(matched);
    } catch (...) {
        return {};
    }
}

std::shared_ptr<const decompiler_render_evidence_t> resolve_render_evidence(
    service_state_data_t& state,
    const decompiler_pipeline_request_t& request)
{
    if (request.entity.kind != decompiler_entity_kind_t::native_function ||
        !request.provider_context)
        return nullptr;
    const auto* native = dynamic_cast<const ghidra_native_provider_context_t*>(
        request.provider_context.get());
    if (!native || !native->snapshot() || native->snapshot()->empty() ||
        native->snapshot_hash().empty())
        return nullptr;
    const auto cache_key = native->snapshot_hash().to_hex();
    {
        std::lock_guard lock(state.evidence_mutex);
        const auto found = state.evidence_cache.find(cache_key);
        if (found != state.evidence_cache.end()) {
            found->second.touch = ++state.evidence_clock;
            return found->second.evidence;
        }
    }
    native_worker::native_provider_snapshot_views_t views;
    std::vector<decompiler_diagnostic_t> parse_diagnostics;
    if (!native_worker::parse_native_provider_snapshot_views(
            std::string_view(reinterpret_cast<const char*>(native->snapshot()->data()),
                             native->snapshot()->size()),
            views, parse_diagnostics) ||
        views.sidecar.empty())
        return nullptr;
    auto evidence = build_render_evidence_from_sidecar(
        views.sidecar.data(), views.sidecar.size(), views.image_base);
    if (!evidence)
        return nullptr;
    try {
        auto merged = std::make_shared<decompiler_render_evidence_t>(*evidence);
        build_render_evidence_typelib_overlay(*merged);
        if (validate_decompiler_render_evidence(*merged).valid())
            evidence = std::move(merged);
    } catch (...) {
    }
    {
        std::lock_guard lock(state.evidence_mutex);
        const auto found = state.evidence_cache.find(cache_key);
        if (found != state.evidence_cache.end()) {
            found->second.touch = ++state.evidence_clock;
            return found->second.evidence;
        }
        while (state.evidence_cache.size() >= 4) {
            const auto oldest = std::min_element(
                state.evidence_cache.begin(), state.evidence_cache.end(),
                [](const auto& left, const auto& right) {
                    return left.second.touch < right.second.touch;
                });
            if (oldest == state.evidence_cache.end())
                break;
            state.evidence_cache.erase(oldest);
        }
        render_evidence_cache_entry_t entry;
        entry.evidence = evidence;
        entry.touch = ++state.evidence_clock;
        state.evidence_cache.emplace(cache_key, std::move(entry));
        ::diag::log_tagged_fmt("decompiler",
            "render_evidence_built snapshot_hash=%s symbols=%zu prototypes=%zu strings=%zu members=%zu vtables=%zu comments=%zu scalars=%zu",
            cache_key.c_str(), evidence->symbols.size(), evidence->prototypes.size(),
            evidence->strings.size(), evidence->members.size(), evidence->vtable_slots.size(),
            evidence->user_comments.size(), evidence->global_scalars.size());
    }
    return evidence;
}

decompiler_pipeline_cache_key_t make_cache_key(
    const decompiler_pipeline_request_t& request,
    const decompiler_provider_descriptor_t& provider,
    const decompiler_profile_budget_t& budget,
    const decompiler_renderer_settings_t& renderer,
    const decompiler_cache_stage_t stage,
    const std::shared_ptr<const decompiler_render_evidence_t>& evidence = {})
{
    decompiler_pipeline_cache_key_t key;
    key.stage = stage;
    key.workspace_id = request.workspace_id;
    key.workspace_generation = request.workspace_generation;
    key.analysis_revision = request.analysis_revision;
    key.entity = request.entity;
    key.provider = provider.identity;
    key.worker_protocol_hash = request.cache_identity.worker_protocol_hash;
    key.language = request.language;
    key.loader_layout_hash = request.cache_identity.loader_layout_hash;
    key.function_bytes_hash = request.cache_identity.function_bytes_hash;
    key.chunk_fingerprints = request.cache_identity.chunk_fingerprints;
    key.metadata_revision = request.cache_identity.metadata_revision;
    key.type_graph_revision = request.cache_identity.type_graph_revision;
    key.overlay_revision = request.cache_identity.overlay_revision;
    key.profile = budget;
    key.renderer = renderer;
    key.dependencies = request.cache_identity.dependencies;
    if (stage == decompiler_cache_stage_t::rendered_document) {
        const auto pass_chain = decompiler_render_pass_chain(
            renderer.readability, renderer, evidence.get());
        decompiler_dependency_version_t pass_dependency;
        pass_dependency.name = "aida.render.pass_chain";
        pass_dependency.version = "1";
        pass_dependency.content_hash = decompiler_render_pass_chain_hash(pass_chain);
        key.dependencies.push_back(std::move(pass_dependency));
        if (evidence) {
            decompiler_dependency_version_t evidence_dependency;
            evidence_dependency.name = "aida.render.evidence";
            evidence_dependency.version =
                std::to_string(k_decompiler_render_evidence_schema_version);
            evidence_dependency.content_hash = stable_serialization_hash(*evidence);
            key.dependencies.push_back(std::move(evidence_dependency));
        }
        std::sort(key.dependencies.begin(), key.dependencies.end(),
            [](const decompiler_dependency_version_t& left,
               const decompiler_dependency_version_t& right) {
                return left.name < right.name;
            });
    }
    return key;
}

bool batch_intermediate_stores_skipped(
    const decompiler_pipeline_service_config_t& config,
    const decompiler_pipeline_request_t& request) noexcept
{
    return config.batch_rendered_only_memory_cache &&
           request.invocation == decompiler_pipeline_invocation_t::background_batch &&
           request.cache_mode == decompiler_pipeline_cache_mode_t::read_write;
}

source_coordinate_t coordinate_layer(
    source_coordinate_t value,
    const decompiler_coordinate_layer_t layer)
{
    value.layer = layer;
    if (layer != decompiler_coordinate_layer_t::document)
        value.document_range.reset();
    return value;
}

hir_node_kind_t hir_kind(const provider_ir_opcode_t opcode) noexcept
{
    switch (opcode) {
    case provider_ir_opcode_t::parameter:
        return hir_node_kind_t::parameter;
    case provider_ir_opcode_t::local:
        return hir_node_kind_t::local;
    case provider_ir_opcode_t::constant:
        return hir_node_kind_t::literal;
    case provider_ir_opcode_t::copy:
        return hir_node_kind_t::reference;
    case provider_ir_opcode_t::unary:
        return hir_node_kind_t::unary;
    case provider_ir_opcode_t::binary:
        return hir_node_kind_t::binary;
    case provider_ir_opcode_t::cast:
        return hir_node_kind_t::cast;
    case provider_ir_opcode_t::load:
        return hir_node_kind_t::load;
    case provider_ir_opcode_t::store:
    case provider_ir_opcode_t::field_store:
    case provider_ir_opcode_t::array_store:
        return hir_node_kind_t::store;
    case provider_ir_opcode_t::field_load:
        return hir_node_kind_t::field;
    case provider_ir_opcode_t::array_load:
        return hir_node_kind_t::index;
    case provider_ir_opcode_t::call:
    case provider_ir_opcode_t::indirect_call:
        return hir_node_kind_t::call;
    case provider_ir_opcode_t::phi:
        return hir_node_kind_t::phi;
    case provider_ir_opcode_t::branch:
        return hir_node_kind_t::branch;
    case provider_ir_opcode_t::conditional_branch:
        return hir_node_kind_t::conditional;
    case provider_ir_opcode_t::switch_branch:
        return hir_node_kind_t::switch_branch;
    case provider_ir_opcode_t::return_value:
        return hir_node_kind_t::return_value;
    case provider_ir_opcode_t::throw_value:
        return hir_node_kind_t::throw_value;
    case provider_ir_opcode_t::monitor_enter:
    case provider_ir_opcode_t::monitor_exit:
    case provider_ir_opcode_t::unknown:
        return hir_node_kind_t::unknown;
    }
    return hir_node_kind_t::unknown;
}

hir_function_t normalize_provider_ir(
    const decompiler_provider_ir_cache_value_t& provider_stage)
{
    const auto& provider_ir = provider_stage.provider_ir;
    hir_function_t hir;
    hir.entity = provider_ir.entity;
    hir.provider_ir_hash = stable_serialization_hash(provider_ir);
    hir.type_graph_revision = provider_stage.provider_type_graph.revision;
    hir.return_type_id = provider_stage.return_type_id;

    for (const auto& provider_block : provider_ir.blocks) {
        hir_block_t block;
        block.id = provider_block.id;
        block.predecessor_ids = provider_block.predecessor_ids;
        block.successor_ids = provider_block.successor_ids;
        block.exception_successor_ids = provider_block.exception_successor_ids;
        block.coordinate = coordinate_layer(provider_block.coordinate, decompiler_coordinate_layer_t::hir);
        for (const auto& provider_value : provider_block.values) {
            hir_value_t value;
            value.id = provider_value.id;
            value.kind = hir_kind(provider_value.opcode);
            value.type_id = provider_value.type_id;
            value.operand_ids = provider_value.operand_ids;
            value.stable_value = !provider_value.stable_immediate.empty()
                ? provider_value.stable_immediate
                : provider_value.stable_symbol;
            value.coordinate = coordinate_layer(provider_value.coordinate, decompiler_coordinate_layer_t::hir);
            value.confidence = provider_value.confidence;
            value.provenance = provider_value.provenance;
            if (value.stable_value.empty() && value.kind == hir_node_kind_t::unknown) {
                value.stable_value = "unknown_" + std::to_string(value.id);
                decompiler_unknown_t unknown;
                unknown.reason = decompiler_unknown_reason_t::provider_abstained;
                unknown.stable_token = value.stable_value;
                unknown.coordinate = value.coordinate;
                unknown.confidence = value.confidence;
                unknown.provenance = value.provenance;
                hir.unknowns.push_back(std::move(unknown));
            }
            if ((value.kind == hir_node_kind_t::parameter || value.kind == hir_node_kind_t::local) &&
                !provider_value.stable_symbol.empty()) {
                hir_variable_t variable;
                variable.id = provider_value.id;
                variable.stable_name = provider_value.stable_symbol;
                variable.type_id = provider_value.type_id;
                variable.coordinate = value.coordinate;
                variable.confidence = provider_value.confidence;
                variable.provenance = provider_value.provenance;
                if (value.kind == hir_node_kind_t::parameter)
                    hir.parameters.push_back(std::move(variable));
                else
                    hir.locals.push_back(std::move(variable));
            }
            block.values.push_back(std::move(value));
        }
        hir.blocks.push_back(std::move(block));
    }
    for (const auto& coordinate : provider_ir.source_coordinates)
        hir.source_coordinates.push_back(coordinate_layer(coordinate, decompiler_coordinate_layer_t::hir));
    for (auto unknown : provider_ir.unknowns) {
        unknown.coordinate = coordinate_layer(std::move(unknown.coordinate), decompiler_coordinate_layer_t::hir);
        hir.unknowns.push_back(std::move(unknown));
    }
    for (auto diagnostic : provider_ir.diagnostics) {
        if (diagnostic.coordinate)
            diagnostic.coordinate = coordinate_layer(std::move(*diagnostic.coordinate), decompiler_coordinate_layer_t::hir);
        hir.diagnostics.push_back(std::move(diagnostic));
    }
    normalize_diagnostics(hir.diagnostics, std::numeric_limits<std::uint32_t>::max());
    return hir;
}

std::uint64_t provider_ir_nodes(const provider_ir_t& value) noexcept
{
    std::uint64_t count = 0;
    for (const auto& block : value.blocks) {
        if (block.values.size() > std::numeric_limits<std::uint64_t>::max() - count)
            return std::numeric_limits<std::uint64_t>::max();
        count += block.values.size();
    }
    return count;
}

std::uint64_t hir_nodes(const hir_function_t& value) noexcept
{
    std::uint64_t count = 0;
    for (const auto& block : value.blocks) {
        if (block.values.size() > std::numeric_limits<std::uint64_t>::max() - count)
            return std::numeric_limits<std::uint64_t>::max();
        count += block.values.size();
    }
    return count;
}

bool graph_has_type(const type_graph_t& graph, const std::uint64_t id) noexcept
{
    const auto found = std::lower_bound(graph.nodes.begin(), graph.nodes.end(), id,
        [](const decompiler_type_node_t& node, const std::uint64_t candidate) {
            return node.id < candidate;
        });
    return found != graph.nodes.end() && found->id == id;
}

bool coordinate_generation_matches(
    const source_coordinate_t& coordinate,
    const decompiler_pipeline_request_t& request) noexcept
{
    return coordinate.workspace_generation == request.workspace_generation &&
           coordinate.entity == request.entity;
}

bool provider_generation_matches(
    const decompiler_provider_ir_cache_value_t& value,
    const decompiler_pipeline_request_t& request) noexcept
{
    for (const auto& block : value.provider_ir.blocks) {
        if (!coordinate_generation_matches(block.coordinate, request))
            return false;
        for (const auto& node : block.values) {
            if (!coordinate_generation_matches(node.coordinate, request))
                return false;
        }
    }
    for (const auto& query : value.semantic_queries) {
        if (query.coordinate.layer != decompiler_coordinate_layer_t::hir ||
            !coordinate_generation_matches(query.coordinate, request) ||
            !valid_triton_z3_static_ir(query.static_ir))
            return false;
    }
    return true;
}

std::optional<std::uint64_t> provider_payload_size(
    const decompiler_provider_ir_cache_value_t& value)
{
    try {
        std::uint64_t size = serialize_provider_ir(value.provider_ir).size();
        const auto add = [&size](const std::size_t bytes) {
            if (bytes > std::numeric_limits<std::uint64_t>::max() - size)
                return false;
            size += bytes;
            return true;
        };
        if (value.provider_hir && !add(serialize_hir_function(*value.provider_hir).size()))
            return std::nullopt;
        if (!add(serialize_type_graph(value.provider_type_graph).size()))
            return std::nullopt;
        for (const auto& diagnostic : value.diagnostics) {
            if (!add(serialize_decompiler_diagnostic(diagnostic).size()))
                return std::nullopt;
        }
        return size;
    } catch (...) {
        return std::nullopt;
    }
}

std::optional<std::uint64_t> normalized_payload_size(
    const decompiler_normalized_cache_value_t& value)
{
    try {
        std::uint64_t size = serialize_hir_function(value.hir).size();
        const auto add = [&size](const std::size_t bytes) {
            if (bytes > std::numeric_limits<std::uint64_t>::max() - size)
                return false;
            size += bytes;
            return true;
        };
        if (!add(serialize_type_graph(value.type_graph).size()) ||
            !add(serialize_typed_pseudocode_ast(value.ast).size()))
            return std::nullopt;
        for (const auto& diagnostic : value.diagnostics) {
            if (!add(serialize_decompiler_diagnostic(diagnostic).size()))
                return std::nullopt;
        }
        return size;
    } catch (...) {
        return std::nullopt;
    }
}

decompiler_pipeline_status_t provider_failure_status(
    const decompiler_provider_execution_status_t status,
    const cancellation_token_t& cancel) noexcept
{
    if (status == decompiler_provider_execution_status_t::crashed)
        return decompiler_pipeline_status_t::provider_crashed;
    if (status == decompiler_provider_execution_status_t::timed_out || cancel.deadline_exceeded())
        return decompiler_pipeline_status_t::deadline_exceeded;
    if (status == decompiler_provider_execution_status_t::cancelled || cancel.cancellation_requested())
        return decompiler_pipeline_status_t::cancelled;
    if (status == decompiler_provider_execution_status_t::unsupported)
        return decompiler_pipeline_status_t::provider_unavailable;
    return decompiler_pipeline_status_t::provider_failed;
}

void record_status(
    service_state_data_t& state,
    const decompiler_pipeline_status_t status)
{
    std::lock_guard lock(state.metrics_mutex);
    switch (status) {
    case decompiler_pipeline_status_t::completed:
        ++state.metrics.completed;
        break;
    case decompiler_pipeline_status_t::invalid_request:
    case decompiler_pipeline_status_t::explicit_request_required:
        ++state.metrics.invalid_requests;
        break;
    case decompiler_pipeline_status_t::provider_unavailable:
    case decompiler_pipeline_status_t::provider_failed:
    case decompiler_pipeline_status_t::provider_crashed:
    case decompiler_pipeline_status_t::normalization_failed:
    case decompiler_pipeline_status_t::rendering_failed:
    case decompiler_pipeline_status_t::cache_integrity_failure:
        ++state.metrics.provider_failures;
        break;
    case decompiler_pipeline_status_t::cancelled:
    case decompiler_pipeline_status_t::service_stopped:
        ++state.metrics.cancellations;
        break;
    case decompiler_pipeline_status_t::deadline_exceeded:
        ++state.metrics.deadline_exceeded;
        break;
    case decompiler_pipeline_status_t::stale_generation:
        ++state.metrics.stale_generations;
        break;
    case decompiler_pipeline_status_t::resource_limit:
        ++state.metrics.resource_limits;
        break;
    }
}

decompiler_pipeline_status_t cache_error_status(const workspace_error_t& error) noexcept
{
    if (error.code == workspace_error_code_t::stale_generation)
        return decompiler_pipeline_status_t::stale_generation;
    if (error.code == workspace_error_code_t::limit_exceeded)
        return decompiler_pipeline_status_t::resource_limit;
    return decompiler_pipeline_status_t::cache_integrity_failure;
}

decompiler_diagnostic_t cache_failure_diagnostic(const workspace_error_t& error)
{
    const auto code = error.code == workspace_error_code_t::stale_generation
        ? decompiler_diagnostic_code_t::cache_key_rejected
        : error.code == workspace_error_code_t::limit_exceeded
            ? decompiler_diagnostic_code_t::resource_limit
            : decompiler_diagnostic_code_t::malformed_serialization;
    return pipeline_diagnostic(
        decompiler_diagnostic_severity_t::error,
        code,
        "decompiler.pipeline.cache." + error.stable_code(),
        error.code == workspace_error_code_t::persistence_failure);
}

decompiler_pipeline_status_t provider_context_error_status(
    const workspace_error_t& error,
    const cancellation_token_t& cancel) noexcept
{
    if (error.code == workspace_error_code_t::deadline_exceeded || cancel.deadline_exceeded())
        return decompiler_pipeline_status_t::deadline_exceeded;
    if (error.code == workspace_error_code_t::cancelled || cancel.cancellation_requested())
        return decompiler_pipeline_status_t::cancelled;
    if (error.code == workspace_error_code_t::stale_generation ||
        error.code == workspace_error_code_t::target_stale)
        return decompiler_pipeline_status_t::stale_generation;
    if (error.code == workspace_error_code_t::limit_exceeded)
        return decompiler_pipeline_status_t::resource_limit;
    return decompiler_pipeline_status_t::provider_unavailable;
}

decompiler_diagnostic_t provider_context_error_diagnostic(const workspace_error_t& error)
{
    decompiler_diagnostic_code_t code = decompiler_diagnostic_code_t::provider_failure;
    if (error.code == workspace_error_code_t::deadline_exceeded)
        code = decompiler_diagnostic_code_t::deadline_exceeded;
    else if (error.code == workspace_error_code_t::cancelled)
        code = decompiler_diagnostic_code_t::cancelled;
    else if (error.code == workspace_error_code_t::stale_generation ||
             error.code == workspace_error_code_t::target_stale)
        code = decompiler_diagnostic_code_t::cache_key_rejected;
    else if (error.code == workspace_error_code_t::limit_exceeded)
        code = decompiler_diagnostic_code_t::resource_limit;
    else if (error.code == workspace_error_code_t::provider_unavailable ||
             error.code == workspace_error_code_t::unsupported_format ||
             error.code == workspace_error_code_t::unsupported_pe_arch)
        code = decompiler_diagnostic_code_t::unsupported_provider;
    auto diagnostic = pipeline_diagnostic(
        decompiler_diagnostic_severity_t::error,
        code,
        "decompiler.pipeline.provider.context." + error.stable_code(),
        error.code == workspace_error_code_t::provider_unavailable ||
            error.code == workspace_error_code_t::analysis_in_progress);
    diagnostic.localization_arguments.push_back(error.phase);
    return diagnostic;
}

std::uint64_t utc_now_ms()
{
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
}

void metrics_add(const std::shared_ptr<analysis_metrics_t>& sink,
                 const analysis_metric_t metric,
                 const std::uint64_t value = 1) noexcept
{
    if (sink)
        sink->add(metric, value);
}

bool native_entity_rva(const decompiler_entity_key_t& entity, std::uint64_t& rva) noexcept
{
    const auto* native = std::get_if<native_decompiler_entity_identity_t>(&entity.identity);
    if (entity.kind != decompiler_entity_kind_t::native_function || !native)
        return false;
    rva = native->entry.value;
    return true;
}

std::vector<std::uint8_t> serialize_diagnostics_blob(
    const std::vector<decompiler_diagnostic_t>& diagnostics)
{
    std::string output;
    const auto append_u64 = [&output](const std::uint64_t value) {
        for (unsigned shift = 0; shift < 64; shift += 8)
            output.push_back(static_cast<char>((value >> shift) & 0xffU));
    };
    const auto append_blob = [&output, &append_u64](const std::string& value) {
        append_u64(value.size());
        output.append(value);
    };
    append_u64(diagnostics.size());
    for (const auto& diagnostic : diagnostics)
        append_blob(serialize_decompiler_diagnostic(diagnostic));
    const auto* begin = reinterpret_cast<const std::uint8_t*>(output.data());
    return std::vector<std::uint8_t>(begin, begin + output.size());
}

void discard_persistent_rendered(
    service_state_data_t& state,
    const std::uint64_t function_rva,
    const char* reason) noexcept
{
    if (!state.config.database)
        return;
    try {
        auto ticket = state.config.database->invalidate_pipeline_cache(
            std::optional<std::vector<std::uint64_t>>({function_rva}), {});
        ::diag::log_tagged_fmt("decompiler",
            "pipeline_cache_discard reason=%s function_rva=0x%llx accepted=%d",
            reason, static_cast<unsigned long long>(function_rva),
            ticket.accepted ? 1 : 0);
    } catch (...) {
    }
}

struct persistent_rendered_load_t {
    std::shared_ptr<const decompiler_rendered_cache_value_t> value;
};

persistent_rendered_load_t load_persistent_rendered(
    service_state_data_t& state,
    const decompiler_pipeline_request_t& request,
    const decompiler_pipeline_cache_key_t& rendered_key)
{
    persistent_rendered_load_t result;
    std::uint64_t function_rva = 0;
    if (!state.config.database ||
        request.entity.kind != decompiler_entity_kind_t::native_function ||
        !native_entity_rva(request.entity, function_rva))
        return result;
    std::string canonical;
    try {
        canonical = serialize_decompiler_pipeline_cache_key(rendered_key);
    } catch (...) {
        return result;
    }
    if (canonical.empty())
        return result;
    const auto* key_begin = reinterpret_cast<const std::uint8_t*>(canonical.data());
    const std::vector<std::uint8_t> key_bytes(key_begin, key_begin + canonical.size());
    auto loaded = state.config.database->load_pipeline_cache(key_bytes, {});
    if (!loaded) {
        ::diag::log_tagged_fmt("decompiler",
            "pipeline_cache_load function_rva=0x%llx status=read_error code=%s",
            static_cast<unsigned long long>(function_rva),
            loaded.error().stable_code().c_str());
        return result;
    }
    if (!loaded.value())
        return result;
    const auto& row = *loaded.value();
    bool corrupt = row.stage !=
            static_cast<std::int64_t>(decompiler_cache_stage_t::rendered_document) ||
        row.workspace_id != request.workspace_id ||
        row.generation != request.workspace_generation ||
        row.analysis_revision != request.analysis_revision ||
        row.overlay_revision != request.cache_identity.overlay_revision ||
        row.function_rva != function_rva;
    std::optional<decompiler_rendered_cache_value_t> parsed;
    if (!corrupt) {
        try {
            parsed = deserialize_decompiler_rendered_cache_value(
                std::string_view(reinterpret_cast<const char*>(row.value.data()),
                                 row.value.size()));
        } catch (...) {
            parsed.reset();
        }
        corrupt = !parsed.has_value();
    }
    if (!corrupt && !readability_report(parsed->document, state.config))
        corrupt = true;
    if (corrupt) {
        discard_persistent_rendered(state, function_rva, "validation");
        return result;
    }
    if (!(parsed->document.entity == request.entity) ||
        parsed->document.profile != request.profile) {
        discard_persistent_rendered(state, function_rva, "binding");
        return result;
    }
    auto generation = state.cache->activate_workspace_generation(
        request.workspace_id, request.workspace_generation);
    if (!generation)
        return result;
    auto stored = state.cache->store_rendered(rendered_key, *parsed);
    if (!stored) {
        if (stored.error().code == workspace_error_code_t::integrity_failure)
            discard_persistent_rendered(state, function_rva, "integrity");
        return result;
    }
    auto hydrated = state.cache->lookup_rendered(rendered_key);
    if (!hydrated || !hydrated.value().hit())
        return result;
    result.value = hydrated.value().value;
    return result;
}

void persist_rendered_row(
    service_state_data_t& state,
    const decompiler_pipeline_request_t& request,
    const decompiler_pipeline_cache_key_t& rendered_key,
    const decompiler_rendered_cache_value_t& rendered,
    std::string serialized) noexcept
{
    if (!state.config.database)
        return;
    std::uint64_t function_rva = 0;
    if (!native_entity_rva(request.entity, function_rva))
        return;
    try {
        const std::string canonical = serialize_decompiler_pipeline_cache_key(rendered_key);
        if (canonical.empty())
            return;
        if (serialized.empty())
            serialized = serialize_decompiler_rendered_cache_value(rendered);
        if (serialized.empty())
            return;
        decompiler_pipeline_cache_v1_row_t row;
        const auto* key_begin = reinterpret_cast<const std::uint8_t*>(canonical.data());
        row.cache_key.assign(key_begin, key_begin + canonical.size());
        row.stage = static_cast<std::int64_t>(decompiler_cache_stage_t::rendered_document);
        row.workspace_id = request.workspace_id;
        row.generation = request.workspace_generation;
        row.analysis_revision = request.analysis_revision;
        row.overlay_revision = request.cache_identity.overlay_revision;
        row.function_rva = function_rva;
        const auto* value_begin = reinterpret_cast<const std::uint8_t*>(serialized.data());
        row.value.assign(value_begin, value_begin + serialized.size());
        row.diagnostics = serialize_diagnostics_blob(rendered.diagnostics);
        row.created_utc_ms = static_cast<std::int64_t>(utc_now_ms());
        row.last_access_utc_ms = row.created_utc_ms;
        auto ticket = state.config.database->store_pipeline_cache(std::move(row), {});
        if (!ticket.accepted) {
            ::diag::log_tagged_fmt("decompiler",
                "pipeline_cache_store function_rva=0x%llx status=enqueue_rejected",
                static_cast<unsigned long long>(function_rva));
        }
    } catch (...) {
        ::diag::log_tagged_fmt("decompiler",
            "pipeline_cache_store function_rva=0x%llx status=exception",
            static_cast<unsigned long long>(function_rva));
    }
}

}

std::shared_ptr<const decompiler_render_evidence_t> build_render_evidence_from_sidecar(
    const void* sidecar_data,
    const std::size_t sidecar_size,
    const std::uint64_t image_base)
{
    namespace sidecar_ns = native_worker::snapshot_sidecar;
    if (sidecar_data == nullptr || sidecar_size == 0)
        return nullptr;
    const auto decoded = sidecar_ns::decode(sidecar_data, sidecar_size);
    if (!decoded)
        return nullptr;
    std::unordered_set<std::uint64_t> noreturn_rvas;
    noreturn_rvas.reserve(decoded->noreturn.size());
    for (const auto rva : decoded->noreturn)
        noreturn_rvas.insert(rva);
    decompiler_render_evidence_t evidence;
    evidence.symbols.reserve(decoded->names.size() + decoded->imports.size());
    const auto noreturn_at = [&noreturn_rvas](const std::uint64_t rva) {
        return noreturn_rvas.find(rva) != noreturn_rvas.end();
    };
    const auto clamp_confidence = [](const std::uint8_t confidence) {
        return confidence > 100 ? static_cast<std::uint8_t>(100) : confidence;
    };
    const auto absolute_address = [image_base](const std::uint64_t rva) {
        return rva > (std::numeric_limits<std::uint64_t>::max)() - image_base
            ? std::uint64_t{0} : image_base + rva;
    };
    for (const auto& record : decoded->names) {
        if (record.rva == 0 || record.name.empty())
            continue;
        const char* prefix = nullptr;
        switch (record.kind) {
        case sidecar_ns::name_kind_t::function:
        case sidecar_ns::name_kind_t::import:
        case sidecar_ns::name_kind_t::export_:
            prefix = "sub_";
            break;
        case sidecar_ns::name_kind_t::data:
            prefix = "DAT_";
            break;
        case sidecar_ns::name_kind_t::label:
            prefix = "LAB_";
            break;
        default:
            break;
        }
        if (prefix == nullptr)
            continue;
        auto unresolved = sidecar_prefixed_unresolved_text(prefix, image_base, record.rva);
        if (unresolved.empty())
            continue;
        decompiler_symbol_evidence_t symbol;
        symbol.unresolved_text = std::move(unresolved);
        symbol.resolved_name = record.name;
        symbol.is_import = record.kind == sidecar_ns::name_kind_t::import;
        symbol.is_noreturn = record.is_noreturn || noreturn_at(record.rva);
        symbol.confidence = 100;
        evidence.symbols.push_back(std::move(symbol));
    }
    for (const auto& record : decoded->imports) {
        if (record.thunk_rva == 0 || record.name.empty())
            continue;
        auto unresolved = sidecar_unresolved_text(image_base, record.thunk_rva);
        if (unresolved.empty())
            continue;
        decompiler_symbol_evidence_t symbol;
        symbol.unresolved_text = std::move(unresolved);
        symbol.resolved_name = record.name;
        symbol.module_name = record.module;
        symbol.is_import = true;
        symbol.is_noreturn = record.is_noreturn || noreturn_at(record.thunk_rva);
        symbol.confidence = 100;
        evidence.symbols.push_back(std::move(symbol));
    }
    evidence.prototypes.reserve(decoded->prototypes.size());
    for (const auto& record : decoded->prototypes) {
        if (record.prototype.empty())
            continue;
        const auto parsed = parse_sidecar_prototype_text(record.prototype);
        if (!parsed)
            continue;
        decompiler_prototype_evidence_t prototype;
        prototype.api_name = !record.name.empty() ? record.name : parsed->name;
        if (prototype.api_name.empty())
            continue;
        prototype.return_type_display = parsed->return_type;
        prototype.argument_names = parsed->argument_names;
        prototype.argument_type_displays = parsed->argument_types;
        prototype.is_variadic = parsed->is_variadic;
        prototype.is_noreturn = record.is_noreturn || noreturn_at(record.rva);
        prototype.confidence = clamp_confidence(record.confidence);
        evidence.prototypes.push_back(std::move(prototype));
    }
    evidence.strings.reserve(decoded->strings.size());
    for (const auto& record : decoded->strings) {
        if (record.rva == 0 || record.content.empty())
            continue;
        const std::uint64_t address = absolute_address(record.rva);
        if (address == 0)
            continue;
        auto reference = sidecar_unresolved_text(image_base, record.rva);
        if (reference.empty())
            continue;
        decompiler_string_evidence_t entry;
        entry.reference_text = std::move(reference);
        entry.utf8_content = record.content;
        entry.is_wide = record.is_wide();
        entry.confidence = clamp_confidence(record.confidence);
        entry.absolute_address = address;
        entry.truncated = record.truncated();
        entry.original_byte_length = record.original_byte_length;
        evidence.strings.push_back(std::move(entry));
    }
    evidence.global_scalars.reserve(decoded->global_scalars.size());
    for (const auto& record : decoded->global_scalars) {
        if (record.rva == 0 || record.size_log2 > 3U)
            continue;
        const std::uint64_t address = absolute_address(record.rva);
        if (address == 0)
            continue;
        decompiler_global_scalar_evidence_t entry;
        entry.absolute_address = address;
        entry.value = record.value;
        entry.size_log2 = record.size_log2;
        evidence.global_scalars.push_back(entry);
    }
    evidence.members.reserve(decoded->members.size());
    for (const auto& record : decoded->members) {
        if (record.field_name.empty())
            continue;
        decompiler_member_evidence_t entry;
        entry.object_type_canonical = record.object_type_canonical;
        entry.byte_offset = record.byte_offset;
        entry.field_name = record.field_name;
        entry.selector_hint = record.selector_hint;
        entry.confidence = clamp_confidence(record.confidence);
        evidence.members.push_back(std::move(entry));
    }
    if (!decoded->vtables.empty()) {
        std::unordered_map<std::uint64_t, std::string> names_by_rva;
        names_by_rva.reserve(decoded->names.size());
        for (const auto& record : decoded->names) {
            if (record.rva != 0 && !record.name.empty())
                names_by_rva.emplace(record.rva, record.name);
        }
        evidence.vtable_slots.reserve(decoded->vtables.size());
        for (const auto& record : decoded->vtables) {
            if (record.method_name.empty())
                continue;
            const std::uint64_t address = absolute_address(record.vtable_rva);
            if (address == 0)
                continue;
            decompiler_vtable_slot_evidence_t entry;
            const auto named = names_by_rva.find(record.vtable_rva);
            entry.vtable_selector = named != names_by_rva.end()
                ? named->second
                : "vtable_" + sidecar_hex_text(record.vtable_rva);
            entry.slot_index = record.slot_index;
            entry.method_name = record.method_name;
            entry.confidence = clamp_confidence(record.confidence);
            entry.vtable_rva = address;
            evidence.vtable_slots.push_back(std::move(entry));
        }
    }
    evidence.user_comments.reserve(decoded->comments.size());
    for (const auto& record : decoded->comments) {
        if (record.rva == 0 || record.text.empty())
            continue;
        const std::uint64_t address = absolute_address(record.rva);
        if (address == 0)
            continue;
        decompiler_user_comment_evidence_t entry;
        entry.comment_text = record.text;
        entry.before_statement = record.before_statement();
        entry.confidence = 100;
        entry.rva = address;
        entry.function_rva = 0;
        evidence.user_comments.push_back(std::move(entry));
    }
    if (const auto recognition = recognition_records_for_sidecar(image_base)) {
        if (!recognition->names.empty()) {
            std::unordered_set<std::string> symbol_texts;
            symbol_texts.reserve(evidence.symbols.size() + recognition->names.size());
            for (const auto& symbol : evidence.symbols)
                symbol_texts.insert(symbol.unresolved_text);
            for (const auto& record : recognition->names) {
                if (evidence.symbols.size() >= k_decompiler_render_evidence_max_entries)
                    break;
                if (record.rva == 0 || record.name.empty() ||
                    record.name.size() > k_decompiler_render_evidence_max_text_bytes)
                    continue;
                auto unresolved = sidecar_unresolved_text(image_base, record.rva);
                if (unresolved.empty() || !symbol_texts.insert(unresolved).second)
                    continue;
                decompiler_symbol_evidence_t symbol;
                symbol.unresolved_text = std::move(unresolved);
                symbol.resolved_name = record.name;
                symbol.is_import = false;
                symbol.is_noreturn = noreturn_at(record.rva);
                symbol.confidence = clamp_confidence(record.confidence);
                evidence.symbols.push_back(std::move(symbol));
            }
        }
        if (!recognition->prototypes.empty()) {
            std::unordered_set<std::uint64_t> prototype_rvas;
            prototype_rvas.reserve(decoded->prototypes.size() + recognition->prototypes.size());
            for (const auto& record : decoded->prototypes)
                prototype_rvas.insert(record.rva);
            for (const auto& record : recognition->prototypes) {
                if (evidence.prototypes.size() >= k_decompiler_render_evidence_max_entries)
                    break;
                if (record.rva == 0 || record.prototype_text.empty() ||
                    prototype_rvas.count(record.rva) != 0)
                    continue;
                const auto parsed = parse_sidecar_prototype_text(record.prototype_text);
                if (!parsed)
                    continue;
                decompiler_prototype_evidence_t prototype;
                prototype.api_name = !record.name.empty() ? record.name : parsed->name;
                if (prototype.api_name.empty())
                    continue;
                prototype.return_type_display = parsed->return_type;
                prototype.argument_names = parsed->argument_names;
                prototype.argument_type_displays = parsed->argument_types;
                prototype.is_variadic = parsed->is_variadic;
                prototype.is_noreturn = record.is_noreturn || noreturn_at(record.rva);
                prototype.confidence = clamp_confidence(record.confidence);
                prototype_rvas.insert(record.rva);
                evidence.prototypes.push_back(std::move(prototype));
            }
        }
        if (!recognition->vtable_slots.empty()) {
            std::unordered_map<std::uint64_t, std::string> names_by_rva;
            names_by_rva.reserve(decoded->names.size());
            for (const auto& record : decoded->names) {
                if (record.rva != 0 && !record.name.empty())
                    names_by_rva.emplace(record.rva, record.name);
            }
            std::set<std::pair<std::uint64_t, std::uint64_t>> occupied_slots;
            for (const auto& slot : evidence.vtable_slots)
                occupied_slots.emplace(slot.vtable_rva, slot.slot_index);
            for (const auto& record : recognition->vtable_slots) {
                if (evidence.vtable_slots.size() >= k_decompiler_render_evidence_max_entries)
                    break;
                if (record.method_name.empty() ||
                    record.method_name.size() > k_decompiler_render_evidence_max_text_bytes)
                    continue;
                const std::uint64_t address = absolute_address(record.vtable_rva);
                if (address == 0)
                    continue;
                if (!occupied_slots.emplace(address, record.slot_index).second)
                    continue;
                decompiler_vtable_slot_evidence_t entry;
                const auto named = names_by_rva.find(record.vtable_rva);
                entry.vtable_selector = named != names_by_rva.end()
                    ? named->second
                    : "vtable_" + sidecar_hex_text(record.vtable_rva);
                entry.slot_index = record.slot_index;
                entry.method_name = record.method_name;
                entry.confidence = clamp_confidence(record.confidence);
                entry.vtable_rva = address;
                evidence.vtable_slots.push_back(std::move(entry));
            }
        }
    }
    const auto symbol_order = [](const decompiler_symbol_evidence_t& left,
                                 const decompiler_symbol_evidence_t& right) {
        return std::tie(left.unresolved_text, left.resolved_name, left.module_name) <
               std::tie(right.unresolved_text, right.resolved_name, right.module_name);
    };
    std::sort(evidence.symbols.begin(), evidence.symbols.end(), symbol_order);
    evidence.symbols.erase(
        std::unique(evidence.symbols.begin(), evidence.symbols.end(),
            [](const auto& left, const auto& right) {
                return left.unresolved_text == right.unresolved_text &&
                       left.resolved_name == right.resolved_name &&
                       left.module_name == right.module_name &&
                       left.is_import == right.is_import;
            }),
        evidence.symbols.end());
    std::sort(evidence.prototypes.begin(), evidence.prototypes.end(),
        [](const auto& left, const auto& right) {
            return left.api_name < right.api_name;
        });
    std::sort(evidence.strings.begin(), evidence.strings.end(),
        [](const auto& left, const auto& right) {
            return std::tie(left.absolute_address, left.utf8_content) <
                   std::tie(right.absolute_address, right.utf8_content);
        });
    evidence.strings.erase(
        std::unique(evidence.strings.begin(), evidence.strings.end(),
            [](const auto& left, const auto& right) {
                return left.absolute_address == right.absolute_address &&
                       left.utf8_content == right.utf8_content;
            }),
        evidence.strings.end());
    std::sort(evidence.global_scalars.begin(), evidence.global_scalars.end(),
        [](const auto& left, const auto& right) {
            return left.absolute_address < right.absolute_address;
        });
    evidence.global_scalars.erase(
        std::unique(evidence.global_scalars.begin(), evidence.global_scalars.end(),
            [](const auto& left, const auto& right) {
                return left.absolute_address == right.absolute_address &&
                       left.size_log2 == right.size_log2 &&
                       left.value == right.value;
            }),
        evidence.global_scalars.end());
    std::sort(evidence.members.begin(), evidence.members.end(),
        [](const auto& left, const auto& right) {
            return std::tie(left.object_type_canonical, left.byte_offset, left.field_name) <
                   std::tie(right.object_type_canonical, right.byte_offset, right.field_name);
        });
    evidence.members.erase(
        std::unique(evidence.members.begin(), evidence.members.end(),
            [](const auto& left, const auto& right) {
                return left.object_type_canonical == right.object_type_canonical &&
                       left.byte_offset == right.byte_offset &&
                       left.field_name == right.field_name;
            }),
        evidence.members.end());
    std::sort(evidence.vtable_slots.begin(), evidence.vtable_slots.end(),
        [](const auto& left, const auto& right) {
            return std::tie(left.vtable_selector, left.slot_index, left.method_name) <
                   std::tie(right.vtable_selector, right.slot_index, right.method_name);
        });
    evidence.vtable_slots.erase(
        std::unique(evidence.vtable_slots.begin(), evidence.vtable_slots.end(),
            [](const auto& left, const auto& right) {
                return left.vtable_selector == right.vtable_selector &&
                       left.slot_index == right.slot_index &&
                       left.method_name == right.method_name;
            }),
        evidence.vtable_slots.end());
    std::sort(evidence.user_comments.begin(), evidence.user_comments.end(),
        [](const auto& left, const auto& right) {
            return std::tie(left.rva, left.before_statement, left.comment_text) <
                   std::tie(right.rva, right.before_statement, right.comment_text);
        });
    evidence.user_comments.erase(
        std::unique(evidence.user_comments.begin(), evidence.user_comments.end(),
            [](const auto& left, const auto& right) {
                return left.rva == right.rva &&
                       left.before_statement == right.before_statement &&
                       left.comment_text == right.comment_text;
            }),
        evidence.user_comments.end());
    if (evidence.empty())
        return nullptr;
    if (!validate_decompiler_render_evidence(evidence).valid())
        return nullptr;
    try {
        return std::make_shared<const decompiler_render_evidence_t>(std::move(evidence));
    } catch (...) {
        return nullptr;
    }
}

void build_render_evidence_typelib_overlay(decompiler_render_evidence_t& evidence)
{
    std::set<std::pair<std::string, std::uint64_t>> occupied;
    for (const auto& entry : evidence.members)
        occupied.emplace(entry.object_type_canonical, entry.byte_offset);
    for (const auto& structure : builtin_typelib::kBuiltinStructs) {
        if (structure.name == nullptr || structure.members == nullptr)
            continue;
        const std::string canonical(structure.name);
        for (std::size_t index = 0; index < structure.member_count; ++index) {
            const auto& member = structure.members[index];
            if (member.name == nullptr || member.name[0] == '\0')
                continue;
            if (!occupied.emplace(canonical, member.offset).second)
                continue;
            decompiler_member_evidence_t entry;
            entry.object_type_canonical = canonical;
            entry.byte_offset = member.offset;
            entry.field_name = member.name;
            entry.confidence = 100;
            evidence.members.push_back(std::move(entry));
        }
    }
    std::sort(evidence.members.begin(), evidence.members.end(),
        [](const auto& left, const auto& right) {
            return std::tie(left.object_type_canonical, left.byte_offset, left.field_name) <
                   std::tie(right.object_type_canonical, right.byte_offset, right.field_name);
        });
}

struct decompiler_pipeline_service_t::state_t : service_state_data_t {
};

decompiler_profile_policy_t default_decompiler_profile_policy()
{
    decompiler_profile_policy_t policy;
    policy.fast.profile = decompiler_profile_id_t::fast;
    policy.fast.max_wall_clock_ms = 1'500;
    policy.fast.max_cpu_ms = 1'000;
    policy.fast.max_memory_bytes = 256ULL << 20;
    policy.fast.max_provider_ir_nodes = 100'000;
    policy.fast.max_hir_nodes = 100'000;
    policy.fast.max_ast_nodes = 200'000;

    policy.balanced.profile = decompiler_profile_id_t::balanced;
    policy.balanced.max_wall_clock_ms = 5'000;
    policy.balanced.max_cpu_ms = 4'000;
    policy.balanced.max_memory_bytes = 512ULL << 20;
    policy.balanced.max_provider_ir_nodes = 500'000;
    policy.balanced.max_hir_nodes = 500'000;
    policy.balanced.max_ast_nodes = 750'000;

    policy.thorough.profile = decompiler_profile_id_t::thorough;
    policy.thorough.max_wall_clock_ms = 60'000;
    policy.thorough.max_cpu_ms = 30'000;
    policy.thorough.max_memory_bytes = 1ULL << 30;
    policy.thorough.max_provider_ir_nodes = 1'000'000;
    policy.thorough.max_hir_nodes = 1'000'000;
    policy.thorough.max_ast_nodes = 1'500'000;
    policy.thorough.max_semantic_queries = 64;
    policy.thorough.semantic_proofs_enabled = true;
    return policy;
}

bool decompiler_pipeline_result_t::succeeded() const noexcept
{
    return status == decompiler_pipeline_status_t::completed && rendered_stage &&
           validate_decompiler_document(rendered_stage->document).valid();
}

workspace_result_t<std::shared_ptr<decompiler_pipeline_service_t>> decompiler_pipeline_service_t::create(
    std::shared_ptr<decompiler_provider_registry_t> providers,
    std::shared_ptr<decompiler_cache_v9_t> cache,
    std::shared_ptr<semantic_refiner_t> semantic_refiner,
    decompiler_pipeline_service_config_t config)
{
    if (!providers || !cache || !valid_config(config)) {
        return workspace_result_t<std::shared_ptr<decompiler_pipeline_service_t>>::failure(
            service_error(workspace_error_code_t::invalid_argument,
                          "decompiler service dependencies or limits are invalid"));
    }
    try {
        auto state = std::make_shared<state_t>();
        state->providers = std::move(providers);
        state->cache = std::move(cache);
        state->semantic_refiner = semantic_refiner
            ? std::move(semantic_refiner)
            : std::make_shared<semantic_refiner_t>();
        state->config = std::move(config);
        if (state->config.batch_attestation_sample_rate == 0)
            state->config.batch_attestation_sample_rate = 1;
        if (BCryptGenRandom(nullptr, state->attestation_sample_key.data(),
                static_cast<ULONG>(state->attestation_sample_key.size()),
                BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
            ::diag::log_tagged_fmt("decompiler", "attestation_sample_key_rng_failed");
            return workspace_result_t<std::shared_ptr<decompiler_pipeline_service_t>>::failure(
                service_error(workspace_error_code_t::integrity_failure,
                              "decompiler service attestation sampler key could not be generated"));
        }
        state->metrics.accepting = true;
        return workspace_result_t<std::shared_ptr<decompiler_pipeline_service_t>>::success(
            std::shared_ptr<decompiler_pipeline_service_t>(new decompiler_pipeline_service_t(std::move(state))));
    } catch (...) {
        return workspace_result_t<std::shared_ptr<decompiler_pipeline_service_t>>::failure(
            service_error(workspace_error_code_t::limit_exceeded,
                          "decompiler service allocation failed"));
    }
}

decompiler_pipeline_service_t::decompiler_pipeline_service_t(std::shared_ptr<state_t> state)
    : state_(std::move(state))
{
}

decompiler_pipeline_service_t::~decompiler_pipeline_service_t()
{
    request_stop();
}

namespace {

struct pipeline_operation_t {
    std::shared_ptr<service_state_data_t> state;
    decompiler_pipeline_request_t request;
    cancellation_token_t caller_cancel;
    decompiler_pipeline_result_t result;
    std::chrono::steady_clock::time_point started;
    std::chrono::steady_clock::time_point operation_deadline;
    std::shared_ptr<cancellation_bridge_t> cancellation;
    cancellation_token_t operation_cancel;
    decompiler_profile_budget_t budget;
    decompiler_renderer_settings_t renderer;
    std::shared_ptr<const decompiler_render_evidence_t> evidence;
    decompiler_pipeline_cache_key_t provider_key;
    decompiler_pipeline_cache_key_t normalized_key;
    decompiler_pipeline_cache_key_t rendered_key;
    std::optional<decompiler_document_t> attested_document;
    bool deferred_intermediate_cache_writes = false;
    bool attestation_sampled = false;
    bool attestation_validated = false;
    request_slot_t slot;
    std::uint64_t dispatch_stage_ms = 0;
    decompiler_pipeline_service_t::decompiler_completion_t completion;
};

decompiler_pipeline_result_t pipeline_finish(
    pipeline_operation_t& op,
    const decompiler_pipeline_status_t status)
{
    auto& state = *op.state;
    auto& result = op.result;
    result.status = status;
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - op.started).count();
    result.elapsed_wall_clock_ms = elapsed < 0 ? 0 : static_cast<std::uint64_t>(elapsed);
    normalize_diagnostics(result.diagnostics, state.config.max_diagnostics);
    record_status(state, status);
    return result;
}

std::optional<decompiler_pipeline_status_t> pipeline_front(pipeline_operation_t& op)
{
    auto& state = *op.state;
    auto& request = op.request;
    auto& result = op.result;
    {
        std::lock_guard lock(state.metrics_mutex);
        ++state.metrics.requests;
    }

    if (!valid_invocation(request.invocation)) {
        result.diagnostics.push_back(pipeline_diagnostic(
            decompiler_diagnostic_severity_t::error,
            decompiler_diagnostic_code_t::invalid_contract,
            request.invocation == decompiler_pipeline_invocation_t::baseline_analysis
                ? "decompiler.pipeline.explicit_only"
                : "decompiler.pipeline.invocation_required"));
        return decompiler_pipeline_status_t::explicit_request_required;
    }
    if (!valid_cache_mode(request.cache_mode) || request.workspace_id.empty() ||
        request.workspace_generation == 0 || request.cache_identity.type_graph_revision == 0 ||
        !validate_decompiler_entity_key(request.entity).valid() ||
        (request.provider_context && request.provider_context_factory)) {
        result.diagnostics.push_back(pipeline_diagnostic(
            decompiler_diagnostic_severity_t::error,
            decompiler_diagnostic_code_t::invalid_contract,
            "decompiler.pipeline.request.invalid"));
        return decompiler_pipeline_status_t::invalid_request;
    }

    const auto budget = effective_budget(request, state.config.profiles);
    if (!budget) {
        result.diagnostics.push_back(pipeline_diagnostic(
            decompiler_diagnostic_severity_t::error,
            decompiler_diagnostic_code_t::invalid_contract,
            "decompiler.pipeline.profile.invalid"));
        return decompiler_pipeline_status_t::invalid_request;
    }
    op.budget = *budget;
    result.effective_budget = *budget;
    op.operation_deadline = minimum_deadline(op.started, *budget, request, op.caller_cancel);
    op.cancellation = std::make_shared<cancellation_bridge_t>(
        op.caller_cancel, state.stop_source.token(), op.operation_deadline);
    op.operation_cancel = op.cancellation->token();
    if (op.operation_cancel.stop_requested()) {
        result.diagnostics.push_back(pipeline_diagnostic(
            decompiler_diagnostic_severity_t::error,
            op.operation_cancel.deadline_exceeded() ? decompiler_diagnostic_code_t::deadline_exceeded
                                                    : decompiler_diagnostic_code_t::cancelled,
            op.operation_cancel.deadline_exceeded()
                ? "decompiler.pipeline.deadline.preflight"
                : "decompiler.pipeline.cancelled.preflight"));
        return op.operation_cancel.deadline_exceeded()
            ? decompiler_pipeline_status_t::deadline_exceeded
            : decompiler_pipeline_status_t::cancelled;
    }

    auto slot_result = acquire_slot(state, op.operation_cancel, op.operation_deadline);
    if (!slot_result) {
        result.diagnostics.push_back(pipeline_diagnostic(
            decompiler_diagnostic_severity_t::error,
            slot_result.error().code == workspace_error_code_t::deadline_exceeded
                ? decompiler_diagnostic_code_t::deadline_exceeded
                : decompiler_diagnostic_code_t::cancelled,
            "decompiler.pipeline.queue." + slot_result.error().stable_code()));
        if (slot_result.error().code == workspace_error_code_t::workspace_closing)
            return decompiler_pipeline_status_t::service_stopped;
        return slot_result.error().code == workspace_error_code_t::deadline_exceeded
            ? decompiler_pipeline_status_t::deadline_exceeded
            : decompiler_pipeline_status_t::cancelled;
    }
    op.slot = std::move(slot_result.value());

    auto generation = state.cache->activate_workspace_generation(
        request.workspace_id, request.workspace_generation);
    if (!generation) {
        result.diagnostics.push_back(cache_failure_diagnostic(generation.error()));
        return cache_error_status(generation.error());
    }

    auto route = state.providers->resolve(
        request.entity, request.language, *budget, request.provider_registration_id);
    if (!route) {
        result.diagnostics.push_back(pipeline_diagnostic(
            decompiler_diagnostic_severity_t::error,
            decompiler_diagnostic_code_t::unsupported_provider,
            "decompiler.pipeline.provider.unavailable",
            false));
        return decompiler_pipeline_status_t::provider_unavailable;
    }
    result.provider = route.value().descriptor;
    std::uint64_t attestation_rva = 0;
    op.attestation_sampled =
        request.invocation == decompiler_pipeline_invocation_t::background_batch &&
        route.value().descriptor.isolated &&
        native_entity_rva(request.entity, attestation_rva) &&
        request.type_evidence.empty() &&
        state.config.batch_attestation_enabled &&
        state.config.batch_attestation_sample_rate > 1 &&
        attestation_sampled_for_job(state, request, route.value().descriptor.identity,
            attestation_rva);
    op.renderer = renderer_settings(request);
    op.evidence = resolve_render_evidence(state, request);
    op.provider_key = make_cache_key(
        request, route.value().descriptor, *budget, op.renderer, decompiler_cache_stage_t::provider_ir);
    op.normalized_key = make_cache_key(
        request, route.value().descriptor, *budget, op.renderer, decompiler_cache_stage_t::normalized_hir_ast);
    op.rendered_key = make_cache_key(
        request, route.value().descriptor, *budget, op.renderer, decompiler_cache_stage_t::rendered_document,
        op.evidence);
    if (!validate_decompiler_pipeline_cache_key(op.provider_key).valid() ||
        !validate_decompiler_pipeline_cache_key(op.normalized_key).valid() ||
        !validate_decompiler_pipeline_cache_key(op.rendered_key).valid()) {
        result.diagnostics.push_back(pipeline_diagnostic(
            decompiler_diagnostic_severity_t::error,
            decompiler_diagnostic_code_t::cache_key_rejected,
            "decompiler.pipeline.cache_key.invalid"));
        return decompiler_pipeline_status_t::invalid_request;
    }

    if (cache_reads_enabled(request.cache_mode)) {
        auto rendered_lookup = state.cache->lookup_rendered(op.rendered_key);
        if (!rendered_lookup) {
            result.diagnostics.push_back(cache_failure_diagnostic(rendered_lookup.error()));
            return cache_error_status(rendered_lookup.error());
        }
        if (rendered_lookup.value().hit()) {
            result.rendered_stage = rendered_lookup.value().value;
            result.cache_hit_stage = decompiler_cache_stage_t::rendered_document;
            result.diagnostics = result.rendered_stage->diagnostics;
            auto readability = readability_report(
                result.rendered_stage->document, state.config);
            if (!readability) {
                result.diagnostics.push_back(pipeline_diagnostic(
                    decompiler_diagnostic_severity_t::error,
                    decompiler_diagnostic_code_t::malformed_document,
                    "decompiler.pipeline.readability.rejected"));
                return decompiler_pipeline_status_t::rendering_failed;
            }
            result.readability = readability.take_value();
            {
                std::lock_guard lock(state.metrics_mutex);
                ++state.metrics.rendered_cache_hits;
            }
            if (request.invocation == decompiler_pipeline_invocation_t::background_batch)
                metrics_add(state.config.metrics_sink,
                    analysis_metric_t::decompile_memory_cache_hits);
            return decompiler_pipeline_status_t::completed;
        }

        if (state.config.database &&
            request.entity.kind == decompiler_entity_kind_t::native_function) {
            auto persistent = load_persistent_rendered(state, request, op.rendered_key);
            if (persistent.value) {
                result.rendered_stage = std::move(persistent.value);
                result.cache_hit_stage = decompiler_cache_stage_t::rendered_document;
                result.diagnostics = result.rendered_stage->diagnostics;
                auto readability = readability_report(
                    result.rendered_stage->document, state.config);
                if (!readability) {
                    result.diagnostics.push_back(pipeline_diagnostic(
                        decompiler_diagnostic_severity_t::error,
                        decompiler_diagnostic_code_t::malformed_document,
                        "decompiler.pipeline.readability.rejected"));
                    return decompiler_pipeline_status_t::rendering_failed;
                }
                result.readability = readability.take_value();
                {
                    std::lock_guard lock(state.metrics_mutex);
                    ++state.metrics.rendered_cache_hits;
                }
                if (request.invocation == decompiler_pipeline_invocation_t::background_batch)
                    metrics_add(state.config.metrics_sink,
                        analysis_metric_t::decompile_persistent_cache_hits);
                return decompiler_pipeline_status_t::completed;
            }
        }

        auto normalized_lookup = state.cache->lookup_normalized(op.normalized_key);
        if (!normalized_lookup) {
            result.diagnostics.push_back(cache_failure_diagnostic(normalized_lookup.error()));
            return cache_error_status(normalized_lookup.error());
        }
        if (normalized_lookup.value().hit()) {
            result.normalized_stage = normalized_lookup.value().value;
            result.cache_hit_stage = decompiler_cache_stage_t::normalized_hir_ast;
            {
                std::lock_guard lock(state.metrics_mutex);
                ++state.metrics.normalized_cache_hits;
            }
            if (request.invocation == decompiler_pipeline_invocation_t::background_batch)
                metrics_add(state.config.metrics_sink,
                    analysis_metric_t::decompile_memory_cache_hits);
        }
    }

    if (!result.normalized_stage && cache_reads_enabled(request.cache_mode)) {
        auto provider_lookup = state.cache->lookup_provider_ir(op.provider_key);
        if (!provider_lookup) {
            result.diagnostics.push_back(cache_failure_diagnostic(provider_lookup.error()));
            return cache_error_status(provider_lookup.error());
        }
        if (provider_lookup.value().hit()) {
            result.provider_stage = provider_lookup.value().value;
            result.cache_hit_stage = decompiler_cache_stage_t::provider_ir;
            {
                std::lock_guard lock(state.metrics_mutex);
                ++state.metrics.provider_ir_cache_hits;
            }
            if (request.invocation == decompiler_pipeline_invocation_t::background_batch)
                metrics_add(state.config.metrics_sink,
                    analysis_metric_t::decompile_memory_cache_hits);
        }
    }

    if (!result.normalized_stage && !result.provider_stage) {
        if (op.operation_cancel.stop_requested()) {
            result.diagnostics.push_back(pipeline_diagnostic(
                decompiler_diagnostic_severity_t::error,
                op.operation_cancel.deadline_exceeded() ? decompiler_diagnostic_code_t::deadline_exceeded
                                                        : decompiler_diagnostic_code_t::cancelled,
                "decompiler.pipeline.cancelled.before_provider"));
            return op.operation_cancel.deadline_exceeded()
                ? decompiler_pipeline_status_t::deadline_exceeded
                : decompiler_pipeline_status_t::cancelled;
        }
        decompiler_provider_request_t provider_request;
        provider_request.cache_key = op.provider_key;
        provider_request.deadline = op.operation_deadline;
        provider_request.context = request.provider_context;
        provider_request.interactive =
            request.invocation == decompiler_pipeline_invocation_t::explicit_ui;
        std::shared_ptr<decompiler_isolated_provider_host_t> isolated_host;
        if (route.value().descriptor.isolated) {
            isolated_host = state.config.isolated_provider_host;
            if (!isolated_host || !isolated_host->supports(route.value().descriptor)) {
                {
                    std::lock_guard lock(state.metrics_mutex);
                    ++state.metrics.isolated_host_rejections;
                }
                result.diagnostics.push_back(pipeline_diagnostic(
                    decompiler_diagnostic_severity_t::error,
                    decompiler_diagnostic_code_t::worker_protocol_failure,
                    "decompiler.pipeline.provider.isolated_host_required"));
                return decompiler_pipeline_status_t::provider_unavailable;
            }
        }
        if (!provider_request.context && request.provider_context_factory) {
            try {
                auto context = request.provider_context_factory(provider_request, op.operation_cancel);
                if (!context) {
                    result.diagnostics.push_back(provider_context_error_diagnostic(context.error()));
                    return provider_context_error_status(context.error(), op.operation_cancel);
                }
                provider_request.context = std::move(context.value());
                if (!provider_request.context) {
                    result.diagnostics.push_back(pipeline_diagnostic(
                        decompiler_diagnostic_severity_t::error,
                        decompiler_diagnostic_code_t::provider_failure,
                        "decompiler.pipeline.provider.context.empty"));
                    return decompiler_pipeline_status_t::provider_unavailable;
                }
            } catch (const std::bad_alloc&) {
                result.diagnostics.push_back(pipeline_diagnostic(
                    decompiler_diagnostic_severity_t::error,
                    decompiler_diagnostic_code_t::resource_limit,
                    "decompiler.pipeline.provider.context.allocation"));
                return decompiler_pipeline_status_t::resource_limit;
            } catch (...) {
                result.diagnostics.push_back(pipeline_diagnostic(
                    decompiler_diagnostic_severity_t::error,
                    decompiler_diagnostic_code_t::provider_failure,
                    "decompiler.pipeline.provider.context.exception",
                    true));
                return decompiler_pipeline_status_t::provider_unavailable;
            }
        }
        decompiler_provider_result_t provider_result;
        const auto provider_started = std::chrono::steady_clock::now();
        try {
            if (route.value().descriptor.isolated) {
                {
                    std::lock_guard lock(state.metrics_mutex);
                    ++state.metrics.isolated_provider_invocations;
                }
                provider_result = isolated_host->execute(
                    route.value(), provider_request, op.operation_cancel);
            } else {
                provider_result = route.value().provider->decompile(provider_request, op.operation_cancel);
            }
        } catch (...) {
            provider_result.status = decompiler_provider_execution_status_t::crashed;
            provider_result.diagnostics.push_back(pipeline_diagnostic(
                decompiler_diagnostic_severity_t::error,
                decompiler_diagnostic_code_t::provider_failure,
                "decompiler.pipeline.provider.exception",
                true));
        }
        const auto measured_provider_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - provider_started).count();
        {
            std::lock_guard lock(state.metrics_mutex);
            ++state.metrics.provider_invocations;
        }
        append_diagnostics(result.diagnostics, provider_result.diagnostics);
        if (!provider_result.succeeded()) {
            if (provider_result.diagnostics.empty()) {
                result.diagnostics.push_back(pipeline_diagnostic(
                    decompiler_diagnostic_severity_t::error,
                    provider_result.status == decompiler_provider_execution_status_t::timed_out
                        ? decompiler_diagnostic_code_t::deadline_exceeded
                        : provider_result.status == decompiler_provider_execution_status_t::cancelled
                            ? decompiler_diagnostic_code_t::cancelled
                            : decompiler_diagnostic_code_t::provider_failure,
                    "decompiler.pipeline.provider.failed",
                    provider_result.status == decompiler_provider_execution_status_t::crashed));
            }
            return provider_failure_status(provider_result.status, op.operation_cancel);
        }
        if (route.value().descriptor.isolated && !provider_result.authenticated_artifacts) {
            result.diagnostics.push_back(pipeline_diagnostic(
                decompiler_diagnostic_severity_t::error,
                decompiler_diagnostic_code_t::worker_protocol_failure,
                "decompiler.pipeline.provider.authenticated_artifacts_required"));
            return decompiler_pipeline_status_t::provider_failed;
        }
        op.deferred_intermediate_cache_writes = provider_result.attested_document.has_value();
        op.attested_document = std::move(provider_result.attested_document);
        if (op.operation_cancel.stop_requested() || measured_provider_ms < 0 ||
            static_cast<std::uint64_t>(measured_provider_ms) > budget->max_wall_clock_ms ||
            provider_result.elapsed_wall_clock_ms > budget->max_wall_clock_ms ||
            provider_result.elapsed_cpu_ms > budget->max_cpu_ms ||
            provider_result.peak_memory_bytes > budget->max_memory_bytes) {
            result.diagnostics.push_back(pipeline_diagnostic(
                decompiler_diagnostic_severity_t::error,
                op.operation_cancel.deadline_exceeded() ||
                        static_cast<std::uint64_t>(std::max<std::int64_t>(measured_provider_ms, 0)) > budget->max_wall_clock_ms ||
                        provider_result.elapsed_wall_clock_ms > budget->max_wall_clock_ms
                    ? decompiler_diagnostic_code_t::deadline_exceeded
                    : decompiler_diagnostic_code_t::resource_limit,
                "decompiler.pipeline.provider.budget_exceeded"));
            if (op.operation_cancel.cancellation_requested() && !op.operation_cancel.deadline_exceeded())
                return decompiler_pipeline_status_t::cancelled;
            return op.operation_cancel.deadline_exceeded() ||
                    static_cast<std::uint64_t>(std::max<std::int64_t>(measured_provider_ms, 0)) > budget->max_wall_clock_ms ||
                    provider_result.elapsed_wall_clock_ms > budget->max_wall_clock_ms
                ? decompiler_pipeline_status_t::deadline_exceeded
                : decompiler_pipeline_status_t::resource_limit;
        }

        decompiler_provider_ir_cache_value_t provider_stage;
        provider_stage.provider_ir = std::move(provider_result.artifacts->provider_ir);
        provider_stage.provider_hir = std::move(provider_result.artifacts->hir);
        provider_stage.provider_type_graph = std::move(provider_result.artifacts->type_graph);
        provider_stage.return_type_id = provider_result.artifacts->return_type_id;
        provider_stage.semantic_queries = std::move(provider_result.artifacts->semantic_queries);
        provider_stage.diagnostics = std::move(result.diagnostics);
        normalize_diagnostics(provider_stage.diagnostics, state.config.max_diagnostics);
        provider_stage.evidence = op.evidence;
        provider_stage.provider_wall_clock_ms = provider_result.elapsed_wall_clock_ms != 0
            ? provider_result.elapsed_wall_clock_ms
            : static_cast<std::uint64_t>(measured_provider_ms);
        provider_stage.provider_cpu_ms = provider_result.elapsed_cpu_ms;
        provider_stage.provider_peak_memory_bytes = provider_result.peak_memory_bytes;

        if (!request.type_evidence.empty() &&
            request.entity.kind != decompiler_entity_kind_t::native_function) {
            auto merged_types = type_graph::merge_type_evidence(
                std::move(provider_stage.provider_type_graph), request.type_evidence);
            if (!merged_types) {
                provider_stage.diagnostics.push_back(pipeline_diagnostic(
                    decompiler_diagnostic_severity_t::error,
                    decompiler_diagnostic_code_t::malformed_type_graph,
                    "decompiler.pipeline.type_evidence.rejected"));
                result.diagnostics = std::move(provider_stage.diagnostics);
                return merged_types.error().code == workspace_error_code_t::limit_exceeded
                    ? decompiler_pipeline_status_t::resource_limit
                    : decompiler_pipeline_status_t::normalization_failed;
            }
            provider_stage.provider_type_graph = merged_types.take_value();
        }

        if (!validate_provider_ir(provider_stage.provider_ir).valid() ||
            !validate_type_graph(provider_stage.provider_type_graph).valid() ||
            provider_stage.provider_ir.entity != request.entity ||
            provider_stage.provider_type_graph.entity != request.entity ||
            provider_stage.provider_type_graph.revision != request.cache_identity.type_graph_revision ||
            !equal_provider(provider_stage.provider_ir.provider, route.value().descriptor.identity) ||
            !equal_language(provider_stage.provider_ir.language, request.language) ||
            provider_stage.return_type_id == 0 ||
            !graph_has_type(provider_stage.provider_type_graph, provider_stage.return_type_id) ||
            !provider_generation_matches(provider_stage, request) ||
            (provider_stage.provider_hir &&
                (!validate_hir_function(*provider_stage.provider_hir).valid() ||
                 provider_stage.provider_hir->provider_ir_hash != stable_serialization_hash(provider_stage.provider_ir)))) {
            result.diagnostics = std::move(provider_stage.diagnostics);
            result.diagnostics.push_back(pipeline_diagnostic(
                decompiler_diagnostic_severity_t::error,
                decompiler_diagnostic_code_t::malformed_provider_ir,
                "decompiler.pipeline.provider.contract_rejected"));
            return decompiler_pipeline_status_t::provider_failed;
        }
        const auto payload_size = provider_payload_size(provider_stage);
        if (!payload_size || *payload_size > state.config.max_provider_payload_bytes ||
            provider_ir_nodes(provider_stage.provider_ir) > budget->max_provider_ir_nodes) {
            result.diagnostics = std::move(provider_stage.diagnostics);
            result.diagnostics.push_back(pipeline_diagnostic(
                decompiler_diagnostic_severity_t::error,
                decompiler_diagnostic_code_t::resource_limit,
                "decompiler.pipeline.provider.payload_limit"));
            return decompiler_pipeline_status_t::resource_limit;
        }
        result.provider_stage = std::make_shared<const decompiler_provider_ir_cache_value_t>(provider_stage);
        if (cache_writes_enabled(request.cache_mode) && !op.deferred_intermediate_cache_writes &&
            !batch_intermediate_stores_skipped(state.config, request)) {
            auto stored = state.cache->store_provider_ir(op.provider_key, std::move(provider_stage));
            if (!stored) {
                result.diagnostics = result.provider_stage->diagnostics;
                result.diagnostics.push_back(cache_failure_diagnostic(stored.error()));
                if (stored.error().code == workspace_error_code_t::stale_generation ||
                    stored.error().code == workspace_error_code_t::integrity_failure)
                    return cache_error_status(stored.error());
            }
        }
    }

    op.dispatch_stage_ms = static_cast<std::uint64_t>((std::max<std::int64_t>)(0,
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - op.started).count()));
    op.slot = request_slot_t{};
    return std::nullopt;
}

bool renderer_settings_equal(
    const decompiler_renderer_settings_t& left,
    const decompiler_renderer_settings_t& right) noexcept
{
    return left.schema_version == right.schema_version && left.style_id == right.style_id &&
           left.indentation_spaces == right.indentation_spaces &&
           left.emit_type_annotations == right.emit_type_annotations &&
           left.emit_provenance_annotations == right.emit_provenance_annotations &&
           left.emit_unknown_tokens == right.emit_unknown_tokens &&
           left.emit_comments == right.emit_comments &&
           left.emit_resolved_symbols == right.emit_resolved_symbols &&
           left.emit_enum_case_names == right.emit_enum_case_names &&
           left.readability == right.readability;
}

void record_attestation_mismatch(
    service_state_data_t& state,
    const decompiler_pipeline_request_t& request,
    const pipeline_operation_t& op) noexcept
{
    std::uint64_t function_rva = 0;
    native_entity_rva(request.entity, function_rva);
    const auto identity_hash = stable_serialization_hash(op.provider_key).to_hex();
    {
        std::lock_guard lock(state.attest_mutex);
        ++state.attestation_mismatch;
    }
    ::diag::log_tagged_fmt("decompiler",
        "attestation_mismatch function_rva=0x%llx generation=%llu job_identity_hash=%s",
        static_cast<unsigned long long>(function_rva),
        static_cast<unsigned long long>(request.workspace_generation),
        identity_hash.c_str());
}

decompiler_pipeline_status_t pipeline_back_attestation_validated(
    pipeline_operation_t& op,
    std::vector<semantic_refinement_fact_t> semantic_facts,
    std::vector<decompiler_diagnostic_t> diagnostics)
{
    auto& state = *op.state;
    auto& request = op.request;
    auto& result = op.result;
    const auto& renderer = op.renderer;

    if (!state.cache->is_current_generation(request.workspace_id, request.workspace_generation)) {
        diagnostics.push_back(pipeline_diagnostic(
            decompiler_diagnostic_severity_t::error,
            decompiler_diagnostic_code_t::cache_key_rejected,
            "decompiler.pipeline.generation.stale"));
        result.diagnostics = std::move(diagnostics);
        return decompiler_pipeline_status_t::stale_generation;
    }
    if (op.operation_cancel.stop_requested()) {
        diagnostics.push_back(pipeline_diagnostic(
            decompiler_diagnostic_severity_t::error,
            op.operation_cancel.deadline_exceeded() ? decompiler_diagnostic_code_t::deadline_exceeded
                                                    : decompiler_diagnostic_code_t::cancelled,
            "decompiler.pipeline.cancelled.before_render"));
        result.diagnostics = std::move(diagnostics);
        return op.operation_cancel.deadline_exceeded()
            ? decompiler_pipeline_status_t::deadline_exceeded
            : decompiler_pipeline_status_t::cancelled;
    }
    if (!op.attested_document || !result.provider_stage) {
        diagnostics.push_back(pipeline_diagnostic(
            decompiler_diagnostic_severity_t::error,
            decompiler_diagnostic_code_t::worker_protocol_failure,
            "decompiler.pipeline.provider.attested_document_required"));
        result.diagnostics = std::move(diagnostics);
        return decompiler_pipeline_status_t::provider_failed;
    }
    const auto& worker_document = *op.attested_document;
    if (!validate_decompiler_document(worker_document).valid() ||
        worker_document.entity != request.entity ||
        worker_document.profile != request.profile ||
        !renderer_settings_equal(worker_document.renderer, renderer)) {
        diagnostics.push_back(pipeline_diagnostic(
            decompiler_diagnostic_severity_t::error,
            decompiler_diagnostic_code_t::worker_protocol_failure,
            "decompiler.pipeline.provider.attested_document_binding"));
        result.diagnostics = std::move(diagnostics);
        record_attestation_mismatch(state, request, op);
        return decompiler_pipeline_status_t::provider_failed;
    }
    auto readability = readability_report(worker_document, state.config);
    if (!readability) {
        diagnostics.push_back(pipeline_diagnostic(
            decompiler_diagnostic_severity_t::error,
            decompiler_diagnostic_code_t::malformed_document,
            "decompiler.pipeline.readability.rejected"));
        result.diagnostics = std::move(diagnostics);
        return decompiler_pipeline_status_t::rendering_failed;
    }
    result.readability = readability.take_value();

    decompiler_rendered_cache_value_t rendered;
    rendered.document = std::move(*op.attested_document);
    rendered.semantic_facts = std::move(semantic_facts);
    rendered.diagnostics = std::move(diagnostics);
    normalize_diagnostics(rendered.diagnostics, state.config.max_diagnostics);
    rendered.provider_wall_clock_ms = result.provider_stage->provider_wall_clock_ms;
    rendered.provider_cpu_ms = result.provider_stage->provider_cpu_ms;
    rendered.provider_peak_memory_bytes = result.provider_stage->provider_peak_memory_bytes;
    result.rendered_stage = std::make_shared<const decompiler_rendered_cache_value_t>(rendered);
    result.diagnostics = result.rendered_stage->diagnostics;
    if (cache_writes_enabled(request.cache_mode)) {
        std::string serialized;
        auto stored = state.cache->store_rendered(op.rendered_key, std::move(rendered), &serialized);
        if (!stored) {
            result.diagnostics.push_back(cache_failure_diagnostic(stored.error()));
            if (stored.error().code == workspace_error_code_t::stale_generation ||
                stored.error().code == workspace_error_code_t::integrity_failure)
                return cache_error_status(stored.error());
        }
        persist_rendered_row(state, request, op.rendered_key, *result.rendered_stage,
            std::move(serialized));
    }
    if (!state.cache->is_current_generation(request.workspace_id, request.workspace_generation)) {
        result.diagnostics.push_back(pipeline_diagnostic(
            decompiler_diagnostic_severity_t::error,
            decompiler_diagnostic_code_t::cache_key_rejected,
            "decompiler.pipeline.generation.stale"));
        return decompiler_pipeline_status_t::stale_generation;
    }
    return decompiler_pipeline_status_t::completed;
}

decompiler_pipeline_status_t pipeline_back_impl(pipeline_operation_t& op)
{
    auto& state = *op.state;
    auto& request = op.request;
    auto& result = op.result;
    const auto& budget = op.budget;
    const auto& renderer = op.renderer;
    const auto& operation_cancel = op.operation_cancel;

    if (!state.cache->is_current_generation(request.workspace_id, request.workspace_generation)) {
        result.diagnostics.push_back(pipeline_diagnostic(
            decompiler_diagnostic_severity_t::error,
            decompiler_diagnostic_code_t::cache_key_rejected,
            "decompiler.pipeline.generation.stale"));
        return decompiler_pipeline_status_t::stale_generation;
    }

    const bool batch_validated_attestation =
        request.invocation == decompiler_pipeline_invocation_t::background_batch &&
        !op.attestation_sampled &&
        op.attested_document.has_value() &&
        request.type_evidence.empty() &&
        state.config.batch_attestation_enabled &&
        state.config.batch_attestation_sample_rate > 1 &&
        !result.normalized_stage;
    std::vector<semantic_refinement_fact_t> attestation_facts;
    std::vector<decompiler_diagnostic_t> attestation_diagnostics;

    if (!result.normalized_stage) {
        auto hir = result.provider_stage->provider_hir
            ? *result.provider_stage->provider_hir
            : normalize_provider_ir(*result.provider_stage);
        auto type_graph = result.provider_stage->provider_type_graph;
        std::vector<semantic_refinement_fact_t> semantic_facts;
        std::vector<decompiler_diagnostic_t> diagnostics = result.provider_stage->diagnostics;
        const auto& transform_evidence = result.provider_stage->evidence
            ? result.provider_stage->evidence : op.evidence;

        if (!validate_hir_function(hir).valid() || !validate_type_graph(type_graph).valid() ||
            hir.entity != request.entity || type_graph.entity != request.entity ||
            hir.provider_ir_hash != stable_serialization_hash(result.provider_stage->provider_ir) ||
            hir.type_graph_revision != request.cache_identity.type_graph_revision ||
            type_graph.revision != request.cache_identity.type_graph_revision ||
            hir_nodes(hir) > budget.max_hir_nodes) {
            diagnostics.push_back(pipeline_diagnostic(
                decompiler_diagnostic_severity_t::error,
                decompiler_diagnostic_code_t::malformed_hir,
                "decompiler.pipeline.normalization.rejected"));
            result.diagnostics = std::move(diagnostics);
            return hir_nodes(hir) > budget.max_hir_nodes
                ? decompiler_pipeline_status_t::resource_limit
                 : decompiler_pipeline_status_t::normalization_failed;
        }

        if (request.entity.kind == decompiler_entity_kind_t::native_function) {
            auto merged_types = type_graph::merge_type_evidence(
                std::move(type_graph), request.type_evidence, hir);
            if (!merged_types) {
                diagnostics.push_back(pipeline_diagnostic(
                    decompiler_diagnostic_severity_t::error,
                    decompiler_diagnostic_code_t::malformed_type_graph,
                    "decompiler.pipeline.type_evidence.rejected"));
                result.diagnostics = std::move(diagnostics);
                return merged_types.error().code == workspace_error_code_t::limit_exceeded
                    ? decompiler_pipeline_status_t::resource_limit
                    : decompiler_pipeline_status_t::normalization_failed;
            }
            type_graph = merged_types.take_value();
        }

        auto semantic_queries = result.provider_stage->semantic_queries;
        if (budget.profile == decompiler_profile_id_t::thorough &&
            budget.semantic_proofs_enabled && semantic_queries.empty())
            semantic_queries = produce_semantic_queries(hir, type_graph, budget.max_semantic_queries);
        if (budget.profile == decompiler_profile_id_t::thorough &&
            budget.semantic_proofs_enabled && !semantic_queries.empty()) {
            semantic_refinement_request_t refinement_request;
            refinement_request.profile = budget;
            refinement_request.function = hir;
            refinement_request.queries = std::move(semantic_queries);
            const auto refinement = state.semantic_refiner->refine(refinement_request, operation_cancel);
            append_diagnostics(diagnostics, refinement.diagnostics);
            result.semantic_proof_availability = refinement.availability;
            {
                std::lock_guard lock(state.metrics_mutex);
                ++state.metrics.semantic_proof_requests;
                if (refinement.availability != decompiler_semantic_proof_availability_t::ready &&
                    refinement.availability != decompiler_semantic_proof_availability_t::not_requested)
                    ++state.metrics.semantic_proof_adapter_denials;
            }
            ::diag::log_tagged_fmt("decompiler",
                "semantic_proof_availability state=%u adapter_invocations=%u refiner_status=%u",
                static_cast<unsigned int>(refinement.availability),
                static_cast<unsigned int>(refinement.adapter_invocations),
                static_cast<unsigned int>(refinement.status));
            if (refinement.status == semantic_refinement_status_t::cancelled) {
                result.diagnostics = std::move(diagnostics);
                return operation_cancel.deadline_exceeded()
                    ? decompiler_pipeline_status_t::deadline_exceeded
                    : decompiler_pipeline_status_t::cancelled;
            }
            if (refinement.status == semantic_refinement_status_t::input_rejected ||
                refinement.status == semantic_refinement_status_t::profile_rejected) {
                result.diagnostics = std::move(diagnostics);
                return decompiler_pipeline_status_t::normalization_failed;
            }
            hir.unknowns = refinement.unknowns;
            append_diagnostics(hir.diagnostics, refinement.diagnostics);
            normalize_diagnostics(hir.diagnostics, state.config.max_diagnostics);
            semantic_facts = refinement.facts;
        }

        if (batch_validated_attestation) {
            attestation_facts = std::move(semantic_facts);
            attestation_diagnostics = std::move(diagnostics);
        }
        if (!batch_validated_attestation) {
        typed_ast_v2_build_request_t ast_request;
        ast_request.limits = state.config.ast_limits;
        ast_request.limits.max_hir_values = static_cast<std::size_t>(
            std::min<std::uint64_t>(ast_request.limits.max_hir_values, budget.max_hir_nodes));
        ast_request.limits.max_ast_nodes = static_cast<std::size_t>(
            std::min<std::uint64_t>(ast_request.limits.max_ast_nodes, budget.max_ast_nodes));
        auto ast_build = build_typed_ast_v2(hir, type_graph, ast_request);
        append_diagnostics(diagnostics, ast_build.diagnostics);
        if (!ast_build.succeeded() || !ast_build.ast ||
            ast_build.ast->nodes.size() > budget.max_ast_nodes) {
            diagnostics.push_back(pipeline_diagnostic(
                decompiler_diagnostic_severity_t::error,
                ast_build.ast && ast_build.ast->nodes.size() > budget.max_ast_nodes
                    ? decompiler_diagnostic_code_t::resource_limit
                    : decompiler_diagnostic_code_t::malformed_ast,
                "decompiler.pipeline.ast.rejected"));
            result.diagnostics = std::move(diagnostics);
            return ast_build.ast && ast_build.ast->nodes.size() > budget.max_ast_nodes
                ? decompiler_pipeline_status_t::resource_limit
                : decompiler_pipeline_status_t::normalization_failed;
        }
        if (hir.entity.kind == decompiler_entity_kind_t::native_function &&
            readability_transforms_enabled(renderer.readability)) {
            auto readability_result = transform_evidence
                ? apply_readability_transforms(
                      *ast_build.ast, type_graph, to_rt_settings(renderer.readability),
                      *transform_evidence)
                : apply_readability_transforms(
                      *ast_build.ast, type_graph, to_rt_settings(renderer.readability));
            append_diagnostics(diagnostics, readability_result.diagnostics);
            if (readability_result.succeeded()) {
                ::diag::log_tagged_fmt("decompiler", "readability_transforms applied renamed=%u folded=%u simplified=%u inlined=%u dead_stores=%u string_literals=%u cast_masks=%u bit_ops=%u loop_intrinsics=%u magic_divisions=%u evidence=%d",
                    static_cast<unsigned int>(readability_result.metrics.variables_renamed),
                    static_cast<unsigned int>(readability_result.metrics.constants_folded),
                    static_cast<unsigned int>(readability_result.metrics.identities_simplified),
                    static_cast<unsigned int>(readability_result.metrics.temporaries_inlined),
                    static_cast<unsigned int>(readability_result.metrics.dead_stores_eliminated),
                    static_cast<unsigned int>(readability_result.metrics.string_literals_inlined),
                    static_cast<unsigned int>(readability_result.metrics.cast_masks_folded),
                    static_cast<unsigned int>(readability_result.metrics.bit_operation_idioms_rewritten),
                    static_cast<unsigned int>(readability_result.metrics.loop_intrinsics_rewritten),
                    static_cast<unsigned int>(readability_result.metrics.magic_divisions_recognized),
                    transform_evidence ? 1 : 0);
            } else {
                ::diag::log_tagged_fmt("decompiler", "readability_transforms status=warning_no_transform continuing_with_unmodified_ast");
            }
        }

        decompiler_normalized_cache_value_t normalized;
        normalized.provider_ir_hash = stable_serialization_hash(result.provider_stage->provider_ir);
        normalized.hir = std::move(hir);
        normalized.type_graph = std::move(type_graph);
        normalized.ast = std::move(*ast_build.ast);
        normalized.semantic_facts = std::move(semantic_facts);
        normalized.diagnostics = std::move(diagnostics);
        normalize_diagnostics(normalized.diagnostics, state.config.max_diagnostics);
        normalized.evidence = transform_evidence;
        normalized.provider_wall_clock_ms = result.provider_stage->provider_wall_clock_ms;
        normalized.provider_cpu_ms = result.provider_stage->provider_cpu_ms;
        normalized.provider_peak_memory_bytes = result.provider_stage->provider_peak_memory_bytes;
        const auto payload_size = normalized_payload_size(normalized);
        if (!payload_size || *payload_size > state.config.max_normalized_payload_bytes) {
            result.diagnostics = std::move(normalized.diagnostics);
            result.diagnostics.push_back(pipeline_diagnostic(
                decompiler_diagnostic_severity_t::error,
                decompiler_diagnostic_code_t::resource_limit,
                "decompiler.pipeline.normalized.payload_limit"));
            return decompiler_pipeline_status_t::resource_limit;
        }
        result.normalized_stage = std::make_shared<const decompiler_normalized_cache_value_t>(normalized);
        if (cache_writes_enabled(request.cache_mode) && !op.deferred_intermediate_cache_writes &&
            !batch_intermediate_stores_skipped(state.config, request)) {
            auto stored = state.cache->store_normalized(op.normalized_key, std::move(normalized));
            if (!stored) {
                result.diagnostics = result.normalized_stage->diagnostics;
                result.diagnostics.push_back(cache_failure_diagnostic(stored.error()));
                if (stored.error().code == workspace_error_code_t::stale_generation ||
                    stored.error().code == workspace_error_code_t::integrity_failure)
                    return cache_error_status(stored.error());
            }
        }
        }
    }

    if (batch_validated_attestation) {
        op.attestation_validated = true;
        return pipeline_back_attestation_validated(
            op, std::move(attestation_facts), std::move(attestation_diagnostics));
    }

    if (!state.cache->is_current_generation(request.workspace_id, request.workspace_generation)) {
        result.diagnostics = result.normalized_stage->diagnostics;
        result.diagnostics.push_back(pipeline_diagnostic(
            decompiler_diagnostic_severity_t::error,
            decompiler_diagnostic_code_t::cache_key_rejected,
            "decompiler.pipeline.generation.stale"));
        return decompiler_pipeline_status_t::stale_generation;
    }
    if (operation_cancel.stop_requested()) {
        result.diagnostics = result.normalized_stage->diagnostics;
        result.diagnostics.push_back(pipeline_diagnostic(
            decompiler_diagnostic_severity_t::error,
            operation_cancel.deadline_exceeded() ? decompiler_diagnostic_code_t::deadline_exceeded
                                                 : decompiler_diagnostic_code_t::cancelled,
            "decompiler.pipeline.cancelled.before_render"));
        return operation_cancel.deadline_exceeded()
            ? decompiler_pipeline_status_t::deadline_exceeded
            : decompiler_pipeline_status_t::cancelled;
    }

    pseudocode_renderer_v2_request_t render_request;
    render_request.profile = budget.profile;
    render_request.settings = renderer;
    render_request.limits = state.config.renderer_limits;
    render_request.limits.max_ast_nodes = static_cast<std::size_t>(
        std::min<std::uint64_t>(render_request.limits.max_ast_nodes, budget.max_ast_nodes));
    render_request.require_complete_source_map = state.config.require_complete_source_map;
    render_request.evidence = result.normalized_stage->evidence
        ? result.normalized_stage->evidence : op.evidence;
    auto rendering = render_pseudocode_v2(
        result.normalized_stage->ast, result.normalized_stage->type_graph, render_request);
    std::vector<decompiler_diagnostic_t> diagnostics = result.normalized_stage->diagnostics;
    append_diagnostics(diagnostics, rendering.diagnostics);
    if (!rendering.succeeded() || !rendering.document ||
        !validate_decompiler_document(*rendering.document).valid()) {
        diagnostics.push_back(pipeline_diagnostic(
            decompiler_diagnostic_severity_t::error,
            decompiler_diagnostic_code_t::malformed_document,
            "decompiler.pipeline.render.rejected"));
        result.diagnostics = std::move(diagnostics);
        return decompiler_pipeline_status_t::rendering_failed;
    }
    auto readability = readability_report(*rendering.document, state.config);
    if (!readability) {
        diagnostics.push_back(pipeline_diagnostic(
            decompiler_diagnostic_severity_t::error,
            decompiler_diagnostic_code_t::malformed_document,
            "decompiler.pipeline.readability.rejected"));
        result.diagnostics = std::move(diagnostics);
        return decompiler_pipeline_status_t::rendering_failed;
    }
    result.readability = readability.take_value();
    if (op.attested_document && request.type_evidence.empty() &&
        result.normalized_stage->semantic_facts.empty() &&
        !equivalent_attested_document(*op.attested_document, *rendering.document)) {
        diagnostics.push_back(pipeline_diagnostic(
            decompiler_diagnostic_severity_t::error,
            decompiler_diagnostic_code_t::worker_protocol_failure,
            "decompiler.pipeline.provider.attested_document_mismatch"));
        result.diagnostics = std::move(diagnostics);
        record_attestation_mismatch(state, request, op);
        return decompiler_pipeline_status_t::provider_failed;
    }
    if (op.deferred_intermediate_cache_writes && cache_writes_enabled(request.cache_mode) &&
        !batch_intermediate_stores_skipped(state.config, request)) {
        auto provider_stored = state.cache->store_provider_ir(
            op.provider_key, *result.provider_stage);
        if (!provider_stored) {
            diagnostics.push_back(cache_failure_diagnostic(provider_stored.error()));
            if (provider_stored.error().code == workspace_error_code_t::stale_generation ||
                provider_stored.error().code == workspace_error_code_t::integrity_failure) {
                result.diagnostics = std::move(diagnostics);
                return cache_error_status(provider_stored.error());
            }
        }
        auto normalized_stored = state.cache->store_normalized(
            op.normalized_key, *result.normalized_stage);
        if (!normalized_stored) {
            diagnostics.push_back(cache_failure_diagnostic(normalized_stored.error()));
            if (normalized_stored.error().code == workspace_error_code_t::stale_generation ||
                normalized_stored.error().code == workspace_error_code_t::integrity_failure) {
                result.diagnostics = std::move(diagnostics);
                return cache_error_status(normalized_stored.error());
            }
        }
    }

    decompiler_rendered_cache_value_t rendered;
    rendered.document = std::move(*rendering.document);
    rendered.semantic_facts = result.normalized_stage->semantic_facts;
    rendered.diagnostics = std::move(diagnostics);
    normalize_diagnostics(rendered.diagnostics, state.config.max_diagnostics);
    rendered.provider_wall_clock_ms = result.normalized_stage->provider_wall_clock_ms;
    rendered.provider_cpu_ms = result.normalized_stage->provider_cpu_ms;
    rendered.provider_peak_memory_bytes = result.normalized_stage->provider_peak_memory_bytes;
    result.rendered_stage = std::make_shared<const decompiler_rendered_cache_value_t>(rendered);
    result.diagnostics = result.rendered_stage->diagnostics;
    if (cache_writes_enabled(request.cache_mode)) {
        std::string serialized;
        auto stored = state.cache->store_rendered(op.rendered_key, std::move(rendered), &serialized);
        if (!stored) {
            result.diagnostics.push_back(cache_failure_diagnostic(stored.error()));
            if (stored.error().code == workspace_error_code_t::stale_generation ||
                stored.error().code == workspace_error_code_t::integrity_failure)
                return cache_error_status(stored.error());
        }
        persist_rendered_row(state, request, op.rendered_key, *result.rendered_stage,
            std::move(serialized));
    }
    if (!state.cache->is_current_generation(request.workspace_id, request.workspace_generation)) {
        result.diagnostics.push_back(pipeline_diagnostic(
            decompiler_diagnostic_severity_t::error,
            decompiler_diagnostic_code_t::cache_key_rejected,
            "decompiler.pipeline.generation.stale"));
        return decompiler_pipeline_status_t::stale_generation;
    }
    return decompiler_pipeline_status_t::completed;
}

decompiler_pipeline_status_t pipeline_back(pipeline_operation_t& op)
{
    const auto back_started = std::chrono::steady_clock::now();
    const auto status = pipeline_back_impl(op);
    const double dispatch_ms = static_cast<double>(op.dispatch_stage_ms);
    const double attest_ms = static_cast<double>((std::max<std::int64_t>)(0,
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - back_started).count()));
    attest_ratio_sample(*op.state, dispatch_ms, attest_ms);
    if (status == decompiler_pipeline_status_t::completed &&
        op.request.invocation == decompiler_pipeline_invocation_t::background_batch &&
        op.attested_document.has_value()) {
        std::lock_guard lock(op.state->attest_mutex);
        if (op.attestation_sampled)
            ++op.state->attestation_sampled_full;
        else if (op.attestation_validated)
            ++op.state->attestation_validated;
    }
    return status;
}

}

decompiler_pipeline_result_t decompiler_pipeline_service_t::decompile(
    const decompiler_pipeline_request_t& request,
    const cancellation_token_t& cancel)
{
    pipeline_operation_t op;
    op.state = state_;
    op.request = request;
    op.caller_cancel = cancel;
    op.started = std::chrono::steady_clock::now();
    const auto early = pipeline_front(op);
    if (early)
        return pipeline_finish(op, *early);
    return pipeline_finish(op, pipeline_back(op));
}

void decompiler_pipeline_service_t::decompile_async(
    const decompiler_pipeline_request_t& request,
    const cancellation_token_t& cancel,
    decompiler_completion_t completion)
{
    auto op = std::make_shared<pipeline_operation_t>();
    op->state = state_;
    op->request = request;
    op->caller_cancel = cancel;
    op->started = std::chrono::steady_clock::now();
    op->completion = std::move(completion);
    const auto early = pipeline_front(*op);
    if (early) {
        auto final = pipeline_finish(*op, *early);
        if (op->completion) {
            try {
                op->completion(std::move(final));
            } catch (...) {
                ::diag::log_tagged_fmt("decompiler", "attest_stage_completion_exception path=early");
            }
        }
        return;
    }
    if (!op->completion) {
        pipeline_finish(*op, pipeline_back(*op));
        return;
    }
    auto attest_slot = acquire_attest_slot(*state_, op->operation_cancel, op->operation_deadline);
    if (!attest_slot) {
        const auto status = attest_slot.error().code == workspace_error_code_t::workspace_closing
            ? decompiler_pipeline_status_t::service_stopped
            : attest_slot.error().code == workspace_error_code_t::deadline_exceeded
                ? decompiler_pipeline_status_t::deadline_exceeded
                : decompiler_pipeline_status_t::cancelled;
        op->result.diagnostics.push_back(pipeline_diagnostic(
            decompiler_diagnostic_severity_t::error,
            status == decompiler_pipeline_status_t::deadline_exceeded
                ? decompiler_diagnostic_code_t::deadline_exceeded
                : decompiler_diagnostic_code_t::cancelled,
            "decompiler.pipeline.attest_queue." + attest_slot.error().stable_code()));
        auto final = pipeline_finish(*op, status);
        try {
            op->completion(std::move(final));
        } catch (...) {
            ::diag::log_tagged_fmt("decompiler", "attest_stage_completion_exception path=queue_reject");
        }
        return;
    }
    auto guard = std::make_shared<attest_slot_t>(std::move(attest_slot.value()));
    infra::taskflow_runtime::task_descriptor_t descriptor;
    descriptor.domain = infra::taskflow_runtime::executor_domain_t::general;
    descriptor.owner_subsystem = "decompiler";
    descriptor.label = "decompiler.attest";
    descriptor.priority = 5;
    descriptor.shutdown_policy = "drain";
    descriptor.cancellable_body = [op, guard](const infra::taskflow_runtime::cancellation_token_t&) {
        const auto status = pipeline_back(*op);
        {
            std::lock_guard lock(op->state->attest_mutex);
            ++op->state->attest_completed;
        }
        auto final = pipeline_finish(*op, status);
        if (op->completion) {
            try {
                op->completion(std::move(final));
            } catch (...) {
                ::diag::log_tagged_fmt("decompiler", "attest_stage_completion_exception path=fabric");
            }
        }
    };
    auto submitted = infra::taskflow_runtime::submit(std::move(descriptor));
    if (!submitted.submitted) {
        ::diag::log_tagged_fmt("decompiler",
            "attest_stage_submit_rejected reason=%s fallback=inline",
            submitted.reject_reason.c_str());
        {
            std::lock_guard lock(state_->attest_mutex);
            ++state_->attest_inline;
        }
        guard.reset();
        const auto status = pipeline_back(*op);
        {
            std::lock_guard lock(state_->attest_mutex);
            ++state_->attest_completed;
        }
        auto final = pipeline_finish(*op, status);
        try {
            op->completion(std::move(final));
        } catch (...) {
            ::diag::log_tagged_fmt("decompiler", "attest_stage_completion_exception path=inline");
        }
        return;
    }
    {
        std::lock_guard lock(state_->attest_mutex);
        ++state_->attest_submitted;
        if ((state_->attest_submitted & 63ULL) == 0ULL) {
            ::diag::log_tagged_fmt("decompiler",
                "attest_governance submitted=%llu completed=%llu inline=%llu in_flight=%zu peak=%zu cap=%zu dispatch_ewm_ms=%.2f attest_ewm_ms=%.2f samples=%llu",
                static_cast<unsigned long long>(state_->attest_submitted),
                static_cast<unsigned long long>(state_->attest_completed),
                static_cast<unsigned long long>(state_->attest_inline),
                state_->attest_in_flight,
                state_->attest_in_flight_peak,
                attest_in_flight_cap(*state_),
                state_->dispatch_stage_ewm_ms,
                state_->attest_stage_ewm_ms,
                static_cast<unsigned long long>(state_->attest_ratio_samples));
        }
    }
}

decompiler_rendered_probe_result_t decompiler_pipeline_service_t::probe_rendered_cache(
    const decompiler_pipeline_request_t& request)
{
    decompiler_rendered_probe_result_t result;
    if (!valid_invocation(request.invocation) ||
        !cache_reads_enabled(request.cache_mode) || request.workspace_id.empty() ||
        request.workspace_generation == 0 ||
        !validate_decompiler_entity_key(request.entity).valid())
        return result;
    const auto budget = effective_budget(request, state_->config.profiles);
    if (!budget)
        return result;
    auto route = state_->providers->resolve(
        request.entity, request.language, *budget, request.provider_registration_id);
    if (!route)
        return result;
    const auto rendered_key = make_cache_key(
        request, route.value().descriptor, *budget, renderer_settings(request),
        decompiler_cache_stage_t::rendered_document,
        resolve_render_evidence(*state_, request));
    if (!validate_decompiler_pipeline_cache_key(rendered_key).valid())
        return result;
    auto lookup = state_->cache->lookup_rendered(rendered_key);
    if (lookup && lookup.value().hit()) {
        if (readability_report(lookup.value().value->document, state_->config)) {
            result.hit_stage = decompiler_rendered_probe_stage_t::memory_rendered;
            result.rendered = lookup.value().value;
        }
        return result;
    }
    auto persistent = load_persistent_rendered(*state_, request, rendered_key);
    if (persistent.value) {
        result.hit_stage = decompiler_rendered_probe_stage_t::persistent_rendered;
        result.rendered = std::move(persistent.value);
    }
    return result;
}

workspace_result_t<void> decompiler_pipeline_service_t::invalidate_workspace(
    const std::string& workspace_id,
    const std::uint64_t generation)
{
    auto result = state_->cache->invalidate_workspace(workspace_id, generation);
    if (state_->config.database) {
        try {
            auto ticket = state_->config.database->invalidate_pipeline_cache(std::nullopt, {});
            if (!ticket.accepted) {
                ::diag::log_tagged_fmt("decompiler",
                    "pipeline_cache_invalidate scope=workspace status=enqueue_rejected");
            }
        } catch (...) {
        }
    }
    return result;
}

workspace_result_t<void> decompiler_pipeline_service_t::invalidate_entities(
    const std::string& workspace_id,
    const std::uint64_t generation,
    const std::vector<decompiler_entity_key_t>& entities)
{
    auto invalidated = state_->cache->invalidate_entities(workspace_id, generation, entities);
    if (!invalidated)
        return invalidated;
    if (state_->config.database && !entities.empty()) {
        std::vector<std::uint64_t> rvas;
        rvas.reserve(entities.size());
        for (const auto& entity : entities) {
            std::uint64_t rva = 0;
            if (native_entity_rva(entity, rva))
                rvas.push_back(rva);
        }
        if (!rvas.empty()) {
            try {
                auto ticket = state_->config.database->invalidate_pipeline_cache(
                    std::move(rvas), {});
                if (!ticket.accepted) {
                    ::diag::log_tagged_fmt("decompiler",
                        "pipeline_cache_invalidate scope=entities count=%zu status=enqueue_rejected",
                        entities.size());
                }
            } catch (...) {
            }
        }
    }
    return workspace_result_t<void>::success();
}

decompiler_pipeline_service_snapshot_t decompiler_pipeline_service_t::snapshot() const
{
    decompiler_pipeline_service_snapshot_t result;
    {
        std::lock_guard lock(state_->metrics_mutex);
        result = state_->metrics;
    }
    {
        std::lock_guard lock(state_->gate_mutex);
        result.active_requests = state_->active_requests;
        result.accepting = state_->accepting;
    }
    {
        std::lock_guard lock(state_->attest_mutex);
        result.attest_stage_submitted = state_->attest_submitted;
        result.attest_stage_inline = state_->attest_inline;
        result.attest_stage_completed = state_->attest_completed;
        result.attest_in_flight = state_->attest_in_flight;
        result.attest_in_flight_peak = state_->attest_in_flight_peak;
        result.attestation_sampled_full = state_->attestation_sampled_full;
        result.attestation_validated = state_->attestation_validated;
        result.attestation_mismatch = state_->attestation_mismatch;
    }
    return result;
}

void decompiler_pipeline_service_t::request_stop() noexcept
{
    if (!state_->accepting.exchange(false, std::memory_order_acq_rel))
        return;
    state_->stop_source.request_cancel();
    state_->gate_cv.notify_all();
    state_->attest_cv.notify_all();
    std::lock_guard lock(state_->metrics_mutex);
    state_->metrics.accepting = false;
}

}
