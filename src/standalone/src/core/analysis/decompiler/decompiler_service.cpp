#include "decompiler_service.hpp"

#include <algorithm>
#include <charconv>
#include <condition_variable>
#include <limits>
#include <mutex>
#include <thread>
#include <utility>

namespace aida::analysis {
namespace {

struct service_state_data_t {
    std::shared_ptr<decompiler_provider_registry_t> providers;
    std::shared_ptr<decompiler_cache_v9_t> cache;
    std::shared_ptr<semantic_refiner_t> semantic_refiner;
    decompiler_pipeline_service_config_t config;
    mutable std::mutex gate_mutex;
    std::condition_variable gate_cv;
    bool accepting = true;
    std::size_t active_requests = 0;
    cancellation_source_t stop_source;
    mutable std::mutex metrics_mutex;
    decompiler_pipeline_service_snapshot_t metrics;
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
           value == decompiler_pipeline_invocation_t::explicit_api;
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
        : source_(deadline), caller_(caller), service_(service)
    {
        if (caller_.stop_requested() || service_.stop_requested())
            source_.request_cancel();
        monitor_ = std::thread([this] { monitor(); });
    }

    ~cancellation_bridge_t()
    {
        {
            std::lock_guard lock(mutex_);
            finished_ = true;
        }
        cv_.notify_all();
        if (monitor_.joinable())
            monitor_.join();
    }

    cancellation_bridge_t(const cancellation_bridge_t&) = delete;
    cancellation_bridge_t& operator=(const cancellation_bridge_t&) = delete;

    cancellation_token_t token() const noexcept
    {
        return source_.token();
    }

private:
    void monitor()
    {
        std::unique_lock lock(mutex_);
        while (!finished_) {
            lock.unlock();
            const bool stop = caller_.stop_requested() || service_.stop_requested();
            lock.lock();
            if (stop) {
                source_.request_cancel();
                return;
            }
            cv_.wait_for(lock, std::chrono::milliseconds(1), [this] { return finished_; });
        }
    }

    cancellation_source_t source_;
    cancellation_token_t caller_;
    cancellation_token_t service_;
    mutable std::mutex mutex_;
    std::condition_variable cv_;
    bool finished_ = false;
    std::thread monitor_;
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

std::vector<semantic_refinement_query_t> produce_semantic_queries(
    const hir_function_t& hir,
    const std::uint32_t maximum)
{
    std::vector<semantic_refinement_query_t> result;
    if (maximum == 0)
        return result;
    result.reserve((std::min<std::size_t>)(maximum, 256));
    for (const auto& block : hir.blocks) {
        for (const auto& value : block.values) {
            if (result.size() >= maximum)
                return result;
            if (value.kind != hir_node_kind_t::literal || value.stable_value.empty() ||
                value.coordinate.layer != decompiler_coordinate_layer_t::hir)
                continue;
            std::uint64_t literal = 0;
            auto begin = value.stable_value.data();
            auto end = begin + value.stable_value.size();
            int base = 10;
            if (value.stable_value.size() > 2 && value.stable_value[0] == '0' &&
                (value.stable_value[1] == 'x' || value.stable_value[1] == 'X')) {
                begin += 2;
                base = 16;
            }
            const auto parsed = std::from_chars(begin, end, literal, base);
            if (parsed.ec != std::errc{} || parsed.ptr != end)
                continue;
            semantic_refinement_query_t query;
            query.ordinal = static_cast<std::uint64_t>(result.size() + 1);
            query.stable_id = "literal_" + std::to_string(value.id);
            query.coordinate = value.coordinate;
            query.refinement_key = "literal_constant_" + std::to_string(value.id);
            query.static_ir.domain = triton_z3_semantic_domain_t::constant;
            triton_z3_ir_node_t observed;
            observed.id = 1;
            observed.opcode = triton_z3_ir_opcode_t::bitvector_constant;
            observed.bit_width = 64;
            observed.literal = literal;
            triton_z3_ir_node_t expected = observed;
            expected.id = 2;
            triton_z3_ir_node_t equality;
            equality.id = 3;
            equality.opcode = triton_z3_ir_opcode_t::equal;
            equality.bit_width = 1;
            equality.lhs_id = observed.id;
            equality.rhs_id = expected.id;
            query.static_ir.nodes = {observed, expected, equality};
            query.static_ir.root_node_id = equality.id;
            if (valid_triton_z3_static_ir(query.static_ir))
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

decompiler_pipeline_cache_key_t make_cache_key(
    const decompiler_pipeline_request_t& request,
    const decompiler_provider_descriptor_t& provider,
    const decompiler_profile_budget_t& budget,
    const decompiler_renderer_settings_t& renderer,
    const decompiler_cache_stage_t stage)
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
    return key;
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
    policy.thorough.max_wall_clock_ms = 15'000;
    policy.thorough.max_cpu_ms = 12'000;
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

decompiler_pipeline_result_t decompiler_pipeline_service_t::decompile(
    const decompiler_pipeline_request_t& request,
    const cancellation_token_t& cancel)
{
    const auto started = std::chrono::steady_clock::now();
    decompiler_pipeline_result_t result;
    std::optional<decompiler_document_t> attested_document;
    bool deferred_intermediate_cache_writes = false;
    {
        std::lock_guard lock(state_->metrics_mutex);
        ++state_->metrics.requests;
    }
    const auto finish = [&](const decompiler_pipeline_status_t status) {
        result.status = status;
        const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - started).count();
        result.elapsed_wall_clock_ms = elapsed < 0 ? 0 : static_cast<std::uint64_t>(elapsed);
        normalize_diagnostics(result.diagnostics, state_->config.max_diagnostics);
        record_status(*state_, status);
        return result;
    };

    if (!valid_invocation(request.invocation)) {
        result.diagnostics.push_back(pipeline_diagnostic(
            decompiler_diagnostic_severity_t::error,
            decompiler_diagnostic_code_t::invalid_contract,
            request.invocation == decompiler_pipeline_invocation_t::baseline_analysis
                ? "decompiler.pipeline.explicit_only"
                : "decompiler.pipeline.invocation_required"));
        return finish(decompiler_pipeline_status_t::explicit_request_required);
    }
    if (!valid_cache_mode(request.cache_mode) || request.workspace_id.empty() ||
        request.workspace_generation == 0 || request.cache_identity.type_graph_revision == 0 ||
        !validate_decompiler_entity_key(request.entity).valid() ||
        (request.provider_context && request.provider_context_factory)) {
        result.diagnostics.push_back(pipeline_diagnostic(
            decompiler_diagnostic_severity_t::error,
            decompiler_diagnostic_code_t::invalid_contract,
            "decompiler.pipeline.request.invalid"));
        return finish(decompiler_pipeline_status_t::invalid_request);
    }

    const auto budget = effective_budget(request, state_->config.profiles);
    if (!budget) {
        result.diagnostics.push_back(pipeline_diagnostic(
            decompiler_diagnostic_severity_t::error,
            decompiler_diagnostic_code_t::invalid_contract,
            "decompiler.pipeline.profile.invalid"));
        return finish(decompiler_pipeline_status_t::invalid_request);
    }
    result.effective_budget = *budget;
    const auto operation_deadline = minimum_deadline(started, *budget, request, cancel);
    cancellation_bridge_t cancellation(cancel, state_->stop_source.token(), operation_deadline);
    const auto operation_cancel = cancellation.token();
    if (operation_cancel.stop_requested()) {
        result.diagnostics.push_back(pipeline_diagnostic(
            decompiler_diagnostic_severity_t::error,
            operation_cancel.deadline_exceeded() ? decompiler_diagnostic_code_t::deadline_exceeded
                                                 : decompiler_diagnostic_code_t::cancelled,
            operation_cancel.deadline_exceeded()
                ? "decompiler.pipeline.deadline.preflight"
                : "decompiler.pipeline.cancelled.preflight"));
        return finish(operation_cancel.deadline_exceeded()
            ? decompiler_pipeline_status_t::deadline_exceeded
            : decompiler_pipeline_status_t::cancelled);
    }

    auto slot_result = acquire_slot(*state_, operation_cancel, operation_deadline);
    if (!slot_result) {
        result.diagnostics.push_back(pipeline_diagnostic(
            decompiler_diagnostic_severity_t::error,
            slot_result.error().code == workspace_error_code_t::deadline_exceeded
                ? decompiler_diagnostic_code_t::deadline_exceeded
                : decompiler_diagnostic_code_t::cancelled,
            "decompiler.pipeline.queue." + slot_result.error().stable_code()));
        if (slot_result.error().code == workspace_error_code_t::workspace_closing)
            return finish(decompiler_pipeline_status_t::service_stopped);
        return finish(slot_result.error().code == workspace_error_code_t::deadline_exceeded
            ? decompiler_pipeline_status_t::deadline_exceeded
            : decompiler_pipeline_status_t::cancelled);
    }
    auto slot = std::move(slot_result.value());

    auto generation = state_->cache->activate_workspace_generation(
        request.workspace_id, request.workspace_generation);
    if (!generation) {
        result.diagnostics.push_back(cache_failure_diagnostic(generation.error()));
        return finish(cache_error_status(generation.error()));
    }

    auto route = state_->providers->resolve(
        request.entity, request.language, *budget, request.provider_registration_id);
    if (!route) {
        result.diagnostics.push_back(pipeline_diagnostic(
            decompiler_diagnostic_severity_t::error,
            decompiler_diagnostic_code_t::unsupported_provider,
            "decompiler.pipeline.provider.unavailable",
            false));
        return finish(decompiler_pipeline_status_t::provider_unavailable);
    }
    result.provider = route.value().descriptor;
    const auto renderer = renderer_settings(request);
    const auto provider_key = make_cache_key(
        request, route.value().descriptor, *budget, renderer, decompiler_cache_stage_t::provider_ir);
    const auto normalized_key = make_cache_key(
        request, route.value().descriptor, *budget, renderer, decompiler_cache_stage_t::normalized_hir_ast);
    const auto rendered_key = make_cache_key(
        request, route.value().descriptor, *budget, renderer, decompiler_cache_stage_t::rendered_document);
    if (!validate_decompiler_pipeline_cache_key(provider_key).valid() ||
        !validate_decompiler_pipeline_cache_key(normalized_key).valid() ||
        !validate_decompiler_pipeline_cache_key(rendered_key).valid()) {
        result.diagnostics.push_back(pipeline_diagnostic(
            decompiler_diagnostic_severity_t::error,
            decompiler_diagnostic_code_t::cache_key_rejected,
            "decompiler.pipeline.cache_key.invalid"));
        return finish(decompiler_pipeline_status_t::invalid_request);
    }

    if (cache_reads_enabled(request.cache_mode)) {
        auto rendered_lookup = state_->cache->lookup_rendered(rendered_key);
        if (!rendered_lookup) {
            result.diagnostics.push_back(cache_failure_diagnostic(rendered_lookup.error()));
            return finish(cache_error_status(rendered_lookup.error()));
        }
        if (rendered_lookup.value().hit()) {
            result.rendered_stage = rendered_lookup.value().value;
            result.cache_hit_stage = decompiler_cache_stage_t::rendered_document;
            result.diagnostics = result.rendered_stage->diagnostics;
            auto readability = readability_report(
                result.rendered_stage->document, state_->config);
            if (!readability) {
                result.diagnostics.push_back(pipeline_diagnostic(
                    decompiler_diagnostic_severity_t::error,
                    decompiler_diagnostic_code_t::malformed_document,
                    "decompiler.pipeline.readability.rejected"));
                return finish(decompiler_pipeline_status_t::rendering_failed);
            }
            result.readability = readability.take_value();
            {
                std::lock_guard lock(state_->metrics_mutex);
                ++state_->metrics.rendered_cache_hits;
            }
            return finish(decompiler_pipeline_status_t::completed);
        }

        auto normalized_lookup = state_->cache->lookup_normalized(normalized_key);
        if (!normalized_lookup) {
            result.diagnostics.push_back(cache_failure_diagnostic(normalized_lookup.error()));
            return finish(cache_error_status(normalized_lookup.error()));
        }
        if (normalized_lookup.value().hit()) {
            result.normalized_stage = normalized_lookup.value().value;
            result.cache_hit_stage = decompiler_cache_stage_t::normalized_hir_ast;
            {
                std::lock_guard lock(state_->metrics_mutex);
                ++state_->metrics.normalized_cache_hits;
            }
        }
    }

    if (!result.normalized_stage && cache_reads_enabled(request.cache_mode)) {
        auto provider_lookup = state_->cache->lookup_provider_ir(provider_key);
        if (!provider_lookup) {
            result.diagnostics.push_back(cache_failure_diagnostic(provider_lookup.error()));
            return finish(cache_error_status(provider_lookup.error()));
        }
        if (provider_lookup.value().hit()) {
            result.provider_stage = provider_lookup.value().value;
            result.cache_hit_stage = decompiler_cache_stage_t::provider_ir;
            {
                std::lock_guard lock(state_->metrics_mutex);
                ++state_->metrics.provider_ir_cache_hits;
            }
        }
    }

    if (!result.normalized_stage && !result.provider_stage) {
        if (operation_cancel.stop_requested()) {
            result.diagnostics.push_back(pipeline_diagnostic(
                decompiler_diagnostic_severity_t::error,
                operation_cancel.deadline_exceeded() ? decompiler_diagnostic_code_t::deadline_exceeded
                                                     : decompiler_diagnostic_code_t::cancelled,
                "decompiler.pipeline.cancelled.before_provider"));
            return finish(operation_cancel.deadline_exceeded()
                ? decompiler_pipeline_status_t::deadline_exceeded
                : decompiler_pipeline_status_t::cancelled);
        }
        decompiler_provider_request_t provider_request;
        provider_request.cache_key = provider_key;
        provider_request.deadline = operation_deadline;
        provider_request.context = request.provider_context;
        std::shared_ptr<decompiler_isolated_provider_host_t> isolated_host;
        if (route.value().descriptor.isolated) {
            isolated_host = state_->config.isolated_provider_host;
            if (!isolated_host || !isolated_host->supports(route.value().descriptor)) {
                {
                    std::lock_guard lock(state_->metrics_mutex);
                    ++state_->metrics.isolated_host_rejections;
                }
                result.diagnostics.push_back(pipeline_diagnostic(
                    decompiler_diagnostic_severity_t::error,
                    decompiler_diagnostic_code_t::worker_protocol_failure,
                    "decompiler.pipeline.provider.isolated_host_required"));
                return finish(decompiler_pipeline_status_t::provider_unavailable);
            }
        }
        if (!provider_request.context && request.provider_context_factory) {
            try {
                auto context = request.provider_context_factory(provider_request, operation_cancel);
                if (!context) {
                    result.diagnostics.push_back(provider_context_error_diagnostic(context.error()));
                    return finish(provider_context_error_status(context.error(), operation_cancel));
                }
                provider_request.context = std::move(context.value());
                if (!provider_request.context) {
                    result.diagnostics.push_back(pipeline_diagnostic(
                        decompiler_diagnostic_severity_t::error,
                        decompiler_diagnostic_code_t::provider_failure,
                        "decompiler.pipeline.provider.context.empty"));
                    return finish(decompiler_pipeline_status_t::provider_unavailable);
                }
            } catch (const std::bad_alloc&) {
                result.diagnostics.push_back(pipeline_diagnostic(
                    decompiler_diagnostic_severity_t::error,
                    decompiler_diagnostic_code_t::resource_limit,
                    "decompiler.pipeline.provider.context.allocation"));
                return finish(decompiler_pipeline_status_t::resource_limit);
            } catch (...) {
                result.diagnostics.push_back(pipeline_diagnostic(
                    decompiler_diagnostic_severity_t::error,
                    decompiler_diagnostic_code_t::provider_failure,
                    "decompiler.pipeline.provider.context.exception",
                    true));
                return finish(decompiler_pipeline_status_t::provider_unavailable);
            }
        }
        decompiler_provider_result_t provider_result;
        const auto provider_started = std::chrono::steady_clock::now();
        try {
            if (route.value().descriptor.isolated) {
                {
                    std::lock_guard lock(state_->metrics_mutex);
                    ++state_->metrics.isolated_provider_invocations;
                }
                provider_result = isolated_host->execute(
                    route.value(), provider_request, operation_cancel);
            } else {
                provider_result = route.value().provider->decompile(provider_request, operation_cancel);
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
            std::lock_guard lock(state_->metrics_mutex);
            ++state_->metrics.provider_invocations;
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
            return finish(provider_failure_status(provider_result.status, operation_cancel));
        }
        if (route.value().descriptor.isolated && !provider_result.authenticated_artifacts) {
            result.diagnostics.push_back(pipeline_diagnostic(
                decompiler_diagnostic_severity_t::error,
                decompiler_diagnostic_code_t::worker_protocol_failure,
                "decompiler.pipeline.provider.authenticated_artifacts_required"));
            return finish(decompiler_pipeline_status_t::provider_failed);
        }
        deferred_intermediate_cache_writes = provider_result.attested_document.has_value();
        attested_document = std::move(provider_result.attested_document);
        if (operation_cancel.stop_requested() || measured_provider_ms < 0 ||
            static_cast<std::uint64_t>(measured_provider_ms) > budget->max_wall_clock_ms ||
            provider_result.elapsed_wall_clock_ms > budget->max_wall_clock_ms ||
            provider_result.elapsed_cpu_ms > budget->max_cpu_ms ||
            provider_result.peak_memory_bytes > budget->max_memory_bytes) {
            result.diagnostics.push_back(pipeline_diagnostic(
                decompiler_diagnostic_severity_t::error,
                operation_cancel.deadline_exceeded() ||
                        static_cast<std::uint64_t>(std::max<std::int64_t>(measured_provider_ms, 0)) > budget->max_wall_clock_ms ||
                        provider_result.elapsed_wall_clock_ms > budget->max_wall_clock_ms
                    ? decompiler_diagnostic_code_t::deadline_exceeded
                    : decompiler_diagnostic_code_t::resource_limit,
                "decompiler.pipeline.provider.budget_exceeded"));
            if (operation_cancel.cancellation_requested() && !operation_cancel.deadline_exceeded())
                return finish(decompiler_pipeline_status_t::cancelled);
            return finish(operation_cancel.deadline_exceeded() ||
                    static_cast<std::uint64_t>(std::max<std::int64_t>(measured_provider_ms, 0)) > budget->max_wall_clock_ms ||
                    provider_result.elapsed_wall_clock_ms > budget->max_wall_clock_ms
                ? decompiler_pipeline_status_t::deadline_exceeded
                : decompiler_pipeline_status_t::resource_limit);
        }

        decompiler_provider_ir_cache_value_t provider_stage;
        provider_stage.provider_ir = std::move(provider_result.artifacts->provider_ir);
        provider_stage.provider_hir = std::move(provider_result.artifacts->hir);
        provider_stage.provider_type_graph = std::move(provider_result.artifacts->type_graph);
        provider_stage.return_type_id = provider_result.artifacts->return_type_id;
        provider_stage.semantic_queries = std::move(provider_result.artifacts->semantic_queries);
        provider_stage.diagnostics = std::move(result.diagnostics);
        normalize_diagnostics(provider_stage.diagnostics, state_->config.max_diagnostics);
        provider_stage.provider_wall_clock_ms = provider_result.elapsed_wall_clock_ms != 0
            ? provider_result.elapsed_wall_clock_ms
            : static_cast<std::uint64_t>(measured_provider_ms);
        provider_stage.provider_cpu_ms = provider_result.elapsed_cpu_ms;
        provider_stage.provider_peak_memory_bytes = provider_result.peak_memory_bytes;

        if (!request.type_evidence.empty()) {
            auto merged_types = type_graph::merge_type_evidence(
                std::move(provider_stage.provider_type_graph), request.type_evidence);
            if (!merged_types) {
                provider_stage.diagnostics.push_back(pipeline_diagnostic(
                    decompiler_diagnostic_severity_t::error,
                    decompiler_diagnostic_code_t::malformed_type_graph,
                    "decompiler.pipeline.type_evidence.rejected"));
                result.diagnostics = std::move(provider_stage.diagnostics);
                return finish(merged_types.error().code == workspace_error_code_t::limit_exceeded
                    ? decompiler_pipeline_status_t::resource_limit
                    : decompiler_pipeline_status_t::normalization_failed);
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
            return finish(decompiler_pipeline_status_t::provider_failed);
        }
        const auto payload_size = provider_payload_size(provider_stage);
        if (!payload_size || *payload_size > state_->config.max_provider_payload_bytes ||
            provider_ir_nodes(provider_stage.provider_ir) > budget->max_provider_ir_nodes) {
            result.diagnostics = std::move(provider_stage.diagnostics);
            result.diagnostics.push_back(pipeline_diagnostic(
                decompiler_diagnostic_severity_t::error,
                decompiler_diagnostic_code_t::resource_limit,
                "decompiler.pipeline.provider.payload_limit"));
            return finish(decompiler_pipeline_status_t::resource_limit);
        }
        result.provider_stage = std::make_shared<const decompiler_provider_ir_cache_value_t>(provider_stage);
        if (cache_writes_enabled(request.cache_mode) && !deferred_intermediate_cache_writes) {
            auto stored = state_->cache->store_provider_ir(provider_key, std::move(provider_stage));
            if (!stored) {
                result.diagnostics = result.provider_stage->diagnostics;
                result.diagnostics.push_back(cache_failure_diagnostic(stored.error()));
                if (stored.error().code == workspace_error_code_t::stale_generation ||
                    stored.error().code == workspace_error_code_t::integrity_failure)
                    return finish(cache_error_status(stored.error()));
            }
        }
    }

    if (!state_->cache->is_current_generation(request.workspace_id, request.workspace_generation)) {
        result.diagnostics.push_back(pipeline_diagnostic(
            decompiler_diagnostic_severity_t::error,
            decompiler_diagnostic_code_t::cache_key_rejected,
            "decompiler.pipeline.generation.stale"));
        return finish(decompiler_pipeline_status_t::stale_generation);
    }

    if (!result.normalized_stage) {
        auto hir = result.provider_stage->provider_hir
            ? *result.provider_stage->provider_hir
            : normalize_provider_ir(*result.provider_stage);
        auto type_graph = result.provider_stage->provider_type_graph;
        std::vector<semantic_refinement_fact_t> semantic_facts;
        std::vector<decompiler_diagnostic_t> diagnostics = result.provider_stage->diagnostics;

        if (!validate_hir_function(hir).valid() || !validate_type_graph(type_graph).valid() ||
            hir.entity != request.entity || type_graph.entity != request.entity ||
            hir.provider_ir_hash != stable_serialization_hash(result.provider_stage->provider_ir) ||
            hir.type_graph_revision != request.cache_identity.type_graph_revision ||
            type_graph.revision != request.cache_identity.type_graph_revision ||
            hir_nodes(hir) > budget->max_hir_nodes) {
            diagnostics.push_back(pipeline_diagnostic(
                decompiler_diagnostic_severity_t::error,
                decompiler_diagnostic_code_t::malformed_hir,
                "decompiler.pipeline.normalization.rejected"));
            result.diagnostics = std::move(diagnostics);
            return finish(hir_nodes(hir) > budget->max_hir_nodes
                ? decompiler_pipeline_status_t::resource_limit
                : decompiler_pipeline_status_t::normalization_failed);
        }

        auto semantic_queries = result.provider_stage->semantic_queries;
        if (budget->profile == decompiler_profile_id_t::thorough &&
            budget->semantic_proofs_enabled && semantic_queries.empty())
            semantic_queries = produce_semantic_queries(hir, budget->max_semantic_queries);
        if (budget->profile == decompiler_profile_id_t::thorough &&
            budget->semantic_proofs_enabled && !semantic_queries.empty()) {
            semantic_refinement_request_t refinement_request;
            refinement_request.profile = *budget;
            refinement_request.function = hir;
            refinement_request.queries = std::move(semantic_queries);
            const auto refinement = state_->semantic_refiner->refine(refinement_request, operation_cancel);
            append_diagnostics(diagnostics, refinement.diagnostics);
            if (refinement.status == semantic_refinement_status_t::cancelled) {
                result.diagnostics = std::move(diagnostics);
                return finish(operation_cancel.deadline_exceeded()
                    ? decompiler_pipeline_status_t::deadline_exceeded
                    : decompiler_pipeline_status_t::cancelled);
            }
            if (refinement.status == semantic_refinement_status_t::input_rejected ||
                refinement.status == semantic_refinement_status_t::profile_rejected) {
                result.diagnostics = std::move(diagnostics);
                return finish(decompiler_pipeline_status_t::normalization_failed);
            }
            hir.unknowns = refinement.unknowns;
            append_diagnostics(hir.diagnostics, refinement.diagnostics);
            normalize_diagnostics(hir.diagnostics, state_->config.max_diagnostics);
            semantic_facts = refinement.facts;
        }

        typed_ast_v2_build_request_t ast_request;
        ast_request.limits = state_->config.ast_limits;
        ast_request.limits.max_hir_values = static_cast<std::size_t>(
            std::min<std::uint64_t>(ast_request.limits.max_hir_values, budget->max_hir_nodes));
        ast_request.limits.max_ast_nodes = static_cast<std::size_t>(
            std::min<std::uint64_t>(ast_request.limits.max_ast_nodes, budget->max_ast_nodes));
        auto ast_build = build_typed_ast_v2(hir, type_graph, ast_request);
        append_diagnostics(diagnostics, ast_build.diagnostics);
        if (!ast_build.succeeded() || !ast_build.ast ||
            ast_build.ast->nodes.size() > budget->max_ast_nodes) {
            diagnostics.push_back(pipeline_diagnostic(
                decompiler_diagnostic_severity_t::error,
                ast_build.ast && ast_build.ast->nodes.size() > budget->max_ast_nodes
                    ? decompiler_diagnostic_code_t::resource_limit
                    : decompiler_diagnostic_code_t::malformed_ast,
                "decompiler.pipeline.ast.rejected"));
            result.diagnostics = std::move(diagnostics);
            return finish(ast_build.ast && ast_build.ast->nodes.size() > budget->max_ast_nodes
                ? decompiler_pipeline_status_t::resource_limit
                : decompiler_pipeline_status_t::normalization_failed);
        }

        decompiler_normalized_cache_value_t normalized;
        normalized.provider_ir_hash = stable_serialization_hash(result.provider_stage->provider_ir);
        normalized.hir = std::move(hir);
        normalized.type_graph = std::move(type_graph);
        normalized.ast = std::move(*ast_build.ast);
        normalized.semantic_facts = std::move(semantic_facts);
        normalized.diagnostics = std::move(diagnostics);
        normalize_diagnostics(normalized.diagnostics, state_->config.max_diagnostics);
        normalized.provider_wall_clock_ms = result.provider_stage->provider_wall_clock_ms;
        normalized.provider_cpu_ms = result.provider_stage->provider_cpu_ms;
        normalized.provider_peak_memory_bytes = result.provider_stage->provider_peak_memory_bytes;
        const auto payload_size = normalized_payload_size(normalized);
        if (!payload_size || *payload_size > state_->config.max_normalized_payload_bytes) {
            result.diagnostics = std::move(normalized.diagnostics);
            result.diagnostics.push_back(pipeline_diagnostic(
                decompiler_diagnostic_severity_t::error,
                decompiler_diagnostic_code_t::resource_limit,
                "decompiler.pipeline.normalized.payload_limit"));
            return finish(decompiler_pipeline_status_t::resource_limit);
        }
        result.normalized_stage = std::make_shared<const decompiler_normalized_cache_value_t>(normalized);
        if (cache_writes_enabled(request.cache_mode) && !deferred_intermediate_cache_writes) {
            auto stored = state_->cache->store_normalized(normalized_key, std::move(normalized));
            if (!stored) {
                result.diagnostics = result.normalized_stage->diagnostics;
                result.diagnostics.push_back(cache_failure_diagnostic(stored.error()));
                if (stored.error().code == workspace_error_code_t::stale_generation ||
                    stored.error().code == workspace_error_code_t::integrity_failure)
                    return finish(cache_error_status(stored.error()));
            }
        }
    }

    if (!state_->cache->is_current_generation(request.workspace_id, request.workspace_generation)) {
        result.diagnostics = result.normalized_stage->diagnostics;
        result.diagnostics.push_back(pipeline_diagnostic(
            decompiler_diagnostic_severity_t::error,
            decompiler_diagnostic_code_t::cache_key_rejected,
            "decompiler.pipeline.generation.stale"));
        return finish(decompiler_pipeline_status_t::stale_generation);
    }
    if (operation_cancel.stop_requested()) {
        result.diagnostics = result.normalized_stage->diagnostics;
        result.diagnostics.push_back(pipeline_diagnostic(
            decompiler_diagnostic_severity_t::error,
            operation_cancel.deadline_exceeded() ? decompiler_diagnostic_code_t::deadline_exceeded
                                                 : decompiler_diagnostic_code_t::cancelled,
            "decompiler.pipeline.cancelled.before_render"));
        return finish(operation_cancel.deadline_exceeded()
            ? decompiler_pipeline_status_t::deadline_exceeded
            : decompiler_pipeline_status_t::cancelled);
    }

    pseudocode_renderer_v2_request_t render_request;
    render_request.profile = budget->profile;
    render_request.settings = renderer;
    render_request.limits = state_->config.renderer_limits;
    render_request.limits.max_ast_nodes = static_cast<std::size_t>(
        std::min<std::uint64_t>(render_request.limits.max_ast_nodes, budget->max_ast_nodes));
    render_request.require_complete_source_map = state_->config.require_complete_source_map;
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
        return finish(decompiler_pipeline_status_t::rendering_failed);
    }
    auto readability = readability_report(*rendering.document, state_->config);
    if (!readability) {
        diagnostics.push_back(pipeline_diagnostic(
            decompiler_diagnostic_severity_t::error,
            decompiler_diagnostic_code_t::malformed_document,
            "decompiler.pipeline.readability.rejected"));
        result.diagnostics = std::move(diagnostics);
        return finish(decompiler_pipeline_status_t::rendering_failed);
    }
    result.readability = readability.take_value();
    if (attested_document && request.type_evidence.empty() &&
        result.normalized_stage->semantic_facts.empty() &&
        !equivalent_attested_document(*attested_document, *rendering.document)) {
        diagnostics.push_back(pipeline_diagnostic(
            decompiler_diagnostic_severity_t::error,
            decompiler_diagnostic_code_t::worker_protocol_failure,
            "decompiler.pipeline.provider.attested_document_mismatch"));
        result.diagnostics = std::move(diagnostics);
        return finish(decompiler_pipeline_status_t::provider_failed);
    }
    if (deferred_intermediate_cache_writes && cache_writes_enabled(request.cache_mode)) {
        auto provider_stored = state_->cache->store_provider_ir(
            provider_key, *result.provider_stage);
        if (!provider_stored) {
            diagnostics.push_back(cache_failure_diagnostic(provider_stored.error()));
            if (provider_stored.error().code == workspace_error_code_t::stale_generation ||
                provider_stored.error().code == workspace_error_code_t::integrity_failure) {
                result.diagnostics = std::move(diagnostics);
                return finish(cache_error_status(provider_stored.error()));
            }
        }
        auto normalized_stored = state_->cache->store_normalized(
            normalized_key, *result.normalized_stage);
        if (!normalized_stored) {
            diagnostics.push_back(cache_failure_diagnostic(normalized_stored.error()));
            if (normalized_stored.error().code == workspace_error_code_t::stale_generation ||
                normalized_stored.error().code == workspace_error_code_t::integrity_failure) {
                result.diagnostics = std::move(diagnostics);
                return finish(cache_error_status(normalized_stored.error()));
            }
        }
    }

    decompiler_rendered_cache_value_t rendered;
    rendered.document = std::move(*rendering.document);
    rendered.semantic_facts = result.normalized_stage->semantic_facts;
    rendered.diagnostics = std::move(diagnostics);
    normalize_diagnostics(rendered.diagnostics, state_->config.max_diagnostics);
    rendered.provider_wall_clock_ms = result.normalized_stage->provider_wall_clock_ms;
    rendered.provider_cpu_ms = result.normalized_stage->provider_cpu_ms;
    rendered.provider_peak_memory_bytes = result.normalized_stage->provider_peak_memory_bytes;
    result.rendered_stage = std::make_shared<const decompiler_rendered_cache_value_t>(rendered);
    result.diagnostics = result.rendered_stage->diagnostics;
    if (cache_writes_enabled(request.cache_mode)) {
        auto stored = state_->cache->store_rendered(rendered_key, std::move(rendered));
        if (!stored) {
            result.diagnostics.push_back(cache_failure_diagnostic(stored.error()));
            if (stored.error().code == workspace_error_code_t::stale_generation ||
                stored.error().code == workspace_error_code_t::integrity_failure)
                return finish(cache_error_status(stored.error()));
        }
    }
    if (!state_->cache->is_current_generation(request.workspace_id, request.workspace_generation)) {
        result.diagnostics.push_back(pipeline_diagnostic(
            decompiler_diagnostic_severity_t::error,
            decompiler_diagnostic_code_t::cache_key_rejected,
            "decompiler.pipeline.generation.stale"));
        return finish(decompiler_pipeline_status_t::stale_generation);
    }
    return finish(decompiler_pipeline_status_t::completed);
}

workspace_result_t<void> decompiler_pipeline_service_t::invalidate_workspace(
    const std::string& workspace_id,
    const std::uint64_t generation)
{
    return state_->cache->invalidate_workspace(workspace_id, generation);
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
    return result;
}

void decompiler_pipeline_service_t::request_stop() noexcept
{
    {
        std::lock_guard lock(state_->gate_mutex);
        if (!state_->accepting)
            return;
        state_->accepting = false;
    }
    state_->stop_source.request_cancel();
    state_->gate_cv.notify_all();
    std::lock_guard lock(state_->metrics_mutex);
    state_->metrics.accepting = false;
}

}
