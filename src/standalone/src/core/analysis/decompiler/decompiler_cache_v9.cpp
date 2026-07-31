#include "decompiler_cache_v9.hpp"

#include "typed_ast_v2.hpp"

#include <algorithm>
#include <limits>
#include <mutex>
#include <tuple>
#include <type_traits>
#include <unordered_map>
#include <utility>
#include <variant>

namespace aida::analysis {
namespace {

using cache_payload_t = std::variant<
    std::shared_ptr<const decompiler_provider_ir_cache_value_t>,
    std::shared_ptr<const decompiler_normalized_cache_value_t>,
    std::shared_ptr<const decompiler_rendered_cache_value_t>>;

struct cache_entry_t {
    decompiler_cache_stage_t stage = decompiler_cache_stage_t::provider_ir;
    decompiler_entity_key_t entity;
    cache_payload_t payload;
    sha256_digest_t content_hash;
    std::uint64_t resident_bytes = 0;
    std::uint64_t touch = 0;
};

struct cache_workspace_t {
    std::uint64_t generation = 0;
    std::uint64_t resident_bytes = 0;
    std::unordered_map<std::string, cache_entry_t> entries;
};

struct cache_state_data_t {
    mutable std::mutex mutex;
    decompiler_cache_v9_limits_t limits;
    std::unordered_map<std::string, cache_workspace_t> workspaces;
    decompiler_cache_v9_stage_snapshot_t provider_ir;
    decompiler_cache_v9_stage_snapshot_t normalized;
    decompiler_cache_v9_stage_snapshot_t rendered;
    std::size_t total_entries = 0;
    std::uint64_t total_bytes = 0;
    std::uint64_t touch_clock = 0;
    std::uint64_t generation_invalidations = 0;
    std::uint64_t explicit_invalidations = 0;
};

workspace_error_t cache_error(
    const workspace_error_code_t code,
    std::string message,
    const std::string& workspace_id = {})
{
    auto error = make_workspace_error(code, std::move(message), "decompiler.cache_v9");
    if (!workspace_id.empty())
        error.details.emplace_back("workspace_id", workspace_id);
    return error;
}

bool valid_limits(const decompiler_cache_v9_limits_t& value) noexcept
{
    return value.max_workspaces != 0 && value.max_entries_per_workspace != 0 &&
           value.max_bytes_per_workspace != 0 && value.max_total_entries != 0 &&
           value.max_total_bytes != 0 && value.max_entry_bytes != 0 &&
           value.max_cache_key_bytes != 0 && value.max_workspace_id_bytes != 0 &&
           value.max_entries_per_workspace <= value.max_total_entries &&
           value.max_bytes_per_workspace <= value.max_total_bytes &&
           value.max_entry_bytes <= value.max_bytes_per_workspace;
}

decompiler_cache_v9_stage_snapshot_t& stage_snapshot(
    cache_state_data_t& state,
    const decompiler_cache_stage_t stage)
{
    switch (stage) {
    case decompiler_cache_stage_t::provider_ir:
        return state.provider_ir;
    case decompiler_cache_stage_t::normalized_hir_ast:
        return state.normalized;
    case decompiler_cache_stage_t::rendered_document:
        return state.rendered;
    }
    return state.provider_ir;
}

void append_u64(std::string& output, const std::uint64_t value)
{
    for (unsigned shift = 0; shift < 64; shift += 8)
        output.push_back(static_cast<char>((value >> shift) & 0xffU));
}

void append_blob(std::string& output, const std::string& value)
{
    append_u64(output, value.size());
    output.append(value);
}

void append_bool(std::string& output, const bool value)
{
    output.push_back(value ? '\x01' : '\x00');
}

void append_diagnostics(
    std::string& output,
    const std::vector<decompiler_diagnostic_t>& diagnostics)
{
    append_u64(output, diagnostics.size());
    for (const auto& diagnostic : diagnostics)
        append_blob(output, serialize_decompiler_diagnostic(diagnostic));
}

void append_semantic_queries(
    std::string& output,
    const std::vector<semantic_refinement_query_t>& queries)
{
    append_u64(output, queries.size());
    for (const auto& query : queries) {
        append_u64(output, query.ordinal);
        append_blob(output, query.stable_id);
        append_blob(output, serialize_source_coordinate(query.coordinate));
        append_u64(output, static_cast<std::uint64_t>(query.static_ir.domain));
        append_u64(output, query.static_ir.root_node_id);
        append_u64(output, query.static_ir.nodes.size());
        for (const auto& node : query.static_ir.nodes) {
            append_u64(output, node.id);
            append_u64(output, static_cast<std::uint64_t>(node.opcode));
            append_u64(output, node.bit_width);
            append_u64(output, node.literal);
            append_blob(output, node.symbol);
            append_u64(output, node.lhs_id);
            append_u64(output, node.rhs_id);
        }
        append_blob(output, query.refinement_key);
    }
}

void append_semantic_facts(
    std::string& output,
    const std::vector<semantic_refinement_fact_t>& facts)
{
    append_u64(output, facts.size());
    for (const auto& fact : facts) {
        append_u64(output, fact.ordinal);
        append_blob(output, fact.stable_id);
        append_blob(output, fact.refinement_key);
        append_blob(output, serialize_source_coordinate(fact.coordinate));
        append_u64(output, fact.confidence);
        append_u64(output, static_cast<std::uint64_t>(fact.provenance));
    }
}

std::string serialize_cache_value(const decompiler_provider_ir_cache_value_t& value)
{
    std::string output;
    append_blob(output, serialize_provider_ir(value.provider_ir));
    append_bool(output, value.provider_hir.has_value());
    if (value.provider_hir)
        append_blob(output, serialize_hir_function(*value.provider_hir));
    append_blob(output, serialize_type_graph(value.provider_type_graph));
    append_u64(output, value.return_type_id);
    append_semantic_queries(output, value.semantic_queries);
    append_diagnostics(output, value.diagnostics);
    return output;
}

std::string serialize_cache_value(const decompiler_normalized_cache_value_t& value)
{
    std::string output;
    append_blob(output, value.provider_ir_hash.to_hex());
    append_blob(output, serialize_hir_function(value.hir));
    append_blob(output, serialize_type_graph(value.type_graph));
    append_blob(output, serialize_typed_pseudocode_ast(value.ast));
    append_semantic_facts(output, value.semantic_facts);
    append_diagnostics(output, value.diagnostics);
    return output;
}

std::string serialize_cache_value(const decompiler_rendered_cache_value_t& value)
{
    std::string output;
    append_blob(output, serialize_decompiler_document(value.document));
    append_semantic_facts(output, value.semantic_facts);
    append_diagnostics(output, value.diagnostics);
    return output;
}

class bounded_reader_t final {
public:
    explicit bounded_reader_t(std::string_view bytes) noexcept : bytes_(bytes) {}

    bool complete() const noexcept { return valid_ && offset_ == bytes_.size(); }

    bool u64(std::uint64_t& value) noexcept
    {
        if (!valid_ || bytes_.size() - offset_ < 8) {
            valid_ = false;
            return false;
        }
        value = 0;
        for (unsigned shift = 0; shift < 64; shift += 8)
            value |= static_cast<std::uint64_t>(
                static_cast<std::uint8_t>(bytes_[offset_++])) << shift;
        return true;
    }

    bool blob(std::string& value)
    {
        std::uint64_t size = 0;
        if (!u64(size) || size > bytes_.size() - offset_) {
            valid_ = false;
            return false;
        }
        try {
            value.assign(bytes_.data() + offset_, static_cast<std::size_t>(size));
        } catch (...) {
            valid_ = false;
            return false;
        }
        offset_ += static_cast<std::size_t>(size);
        return true;
    }

private:
    std::string_view bytes_;
    std::size_t offset_ = 0;
    bool valid_ = true;
};

bool read_semantic_facts(
    bounded_reader_t& reader,
    std::vector<semantic_refinement_fact_t>& facts)
{
    std::uint64_t count = 0;
    if (!reader.u64(count) || count > (1U << 20))
        return false;
    facts.clear();
    facts.reserve(static_cast<std::size_t>(count));
    for (std::uint64_t index = 0; index < count; ++index) {
        semantic_refinement_fact_t fact;
        std::uint64_t confidence = 0;
        std::uint64_t provenance = 0;
        std::string coordinate;
        if (!reader.u64(fact.ordinal) || !reader.blob(fact.stable_id) ||
            !reader.blob(fact.refinement_key) || !reader.blob(coordinate) ||
            !reader.u64(confidence) || !reader.u64(provenance))
            return false;
        auto decoded = deserialize_source_coordinate(coordinate);
        if (!decoded.valid())
            return false;
        fact.coordinate = std::move(*decoded.value);
        if (confidence > 100 ||
            provenance > static_cast<std::uint64_t>(
                std::numeric_limits<std::underlying_type_t<decompiler_fact_provenance_t>>::max()))
            return false;
        fact.confidence = static_cast<std::uint8_t>(confidence);
        fact.provenance = static_cast<decompiler_fact_provenance_t>(provenance);
        facts.push_back(std::move(fact));
    }
    return true;
}

bool read_diagnostics(
    bounded_reader_t& reader,
    std::vector<decompiler_diagnostic_t>& diagnostics)
{
    std::uint64_t count = 0;
    if (!reader.u64(count) || count > (1U << 20))
        return false;
    diagnostics.clear();
    diagnostics.reserve(static_cast<std::size_t>(count));
    for (std::uint64_t index = 0; index < count; ++index) {
        std::string encoded;
        if (!reader.blob(encoded))
            return false;
        auto decoded = deserialize_decompiler_diagnostic(encoded);
        if (!decoded.valid())
            return false;
        diagnostics.push_back(std::move(*decoded.value));
    }
    return true;
}

bool entity_matches_invalidation_probe(
    const decompiler_entity_key_t& stored,
    const decompiler_entity_key_t& probe) noexcept
{
    if (stored.kind != probe.kind || stored.format != probe.format ||
        stored.architecture != probe.architecture || stored.mode != probe.mode ||
        stored.endian != probe.endian)
        return false;
    if (stored.kind == decompiler_entity_kind_t::native_function) {
        const auto* left = std::get_if<native_decompiler_entity_identity_t>(&stored.identity);
        const auto* right = std::get_if<native_decompiler_entity_identity_t>(&probe.identity);
        if (!left || !right)
            return false;
        return left->function_id == right->function_id &&
               left->entry == right->entry && left->end == right->end;
    }
    return stable_serialization_hash(stored) == stable_serialization_hash(probe);
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

bool equal_language(
    const decompiler_language_identity_t& left,
    const decompiler_language_identity_t& right) noexcept
{
    return left.language_id == right.language_id &&
           left.language_version == right.language_version &&
           left.compiler_spec_id == right.compiler_spec_id &&
           left.language_spec_hash == right.language_spec_hash &&
           left.architecture == right.architecture && left.mode == right.mode &&
           left.endian == right.endian;
}

bool equal_renderer(
    const decompiler_renderer_settings_t& left,
    const decompiler_renderer_settings_t& right) noexcept
{
    return left.schema_version == right.schema_version && left.style_id == right.style_id &&
           left.indentation_spaces == right.indentation_spaces &&
           left.emit_type_annotations == right.emit_type_annotations &&
           left.emit_provenance_annotations == right.emit_provenance_annotations &&
           left.emit_unknown_tokens == right.emit_unknown_tokens &&
           left.readability == right.readability;
}

bool coordinate_matches(
    const source_coordinate_t& coordinate,
    const decompiler_pipeline_cache_key_t& key) noexcept
{
    return coordinate.workspace_generation == key.workspace_generation &&
           coordinate.entity == key.entity;
}

bool diagnostic_coordinates_match(
    const std::vector<decompiler_diagnostic_t>& diagnostics,
    const decompiler_pipeline_cache_key_t& key) noexcept
{
    return std::all_of(diagnostics.begin(), diagnostics.end(), [&key](const decompiler_diagnostic_t& value) {
        return !value.coordinate || coordinate_matches(*value.coordinate, key);
    });
}

bool provider_coordinates_match(
    const provider_ir_t& value,
    const decompiler_pipeline_cache_key_t& key) noexcept
{
    for (const auto& block : value.blocks) {
        if (!coordinate_matches(block.coordinate, key))
            return false;
        for (const auto& node : block.values) {
            if (!coordinate_matches(node.coordinate, key))
                return false;
        }
    }
    return std::all_of(value.source_coordinates.begin(), value.source_coordinates.end(),
               [&key](const source_coordinate_t& coordinate) { return coordinate_matches(coordinate, key); }) &&
           std::all_of(value.unknowns.begin(), value.unknowns.end(),
               [&key](const decompiler_unknown_t& unknown) { return coordinate_matches(unknown.coordinate, key); }) &&
           diagnostic_coordinates_match(value.diagnostics, key);
}

bool hir_coordinates_match(
    const hir_function_t& value,
    const decompiler_pipeline_cache_key_t& key) noexcept
{
    for (const auto& variable : value.parameters) {
        if (!coordinate_matches(variable.coordinate, key))
            return false;
    }
    for (const auto& variable : value.locals) {
        if (!coordinate_matches(variable.coordinate, key))
            return false;
    }
    for (const auto& block : value.blocks) {
        if (!coordinate_matches(block.coordinate, key))
            return false;
        for (const auto& node : block.values) {
            if (!coordinate_matches(node.coordinate, key))
                return false;
        }
    }
    return std::all_of(value.source_coordinates.begin(), value.source_coordinates.end(),
               [&key](const source_coordinate_t& coordinate) { return coordinate_matches(coordinate, key); }) &&
           std::all_of(value.unknowns.begin(), value.unknowns.end(),
               [&key](const decompiler_unknown_t& unknown) { return coordinate_matches(unknown.coordinate, key); }) &&
           diagnostic_coordinates_match(value.diagnostics, key);
}

bool type_graph_coordinates_match(
    const type_graph_t& value,
    const decompiler_pipeline_cache_key_t& key) noexcept
{
    for (const auto& node : value.nodes) {
        if (!std::all_of(node.coordinates.begin(), node.coordinates.end(),
                [&key](const source_coordinate_t& coordinate) { return coordinate_matches(coordinate, key); }))
            return false;
    }
    return std::all_of(value.unknowns.begin(), value.unknowns.end(),
               [&key](const decompiler_unknown_t& unknown) { return coordinate_matches(unknown.coordinate, key); }) &&
           diagnostic_coordinates_match(value.diagnostics, key);
}

bool ast_coordinates_match(
    const typed_pseudocode_ast_v2_t& value,
    const decompiler_pipeline_cache_key_t& key) noexcept
{
    return std::all_of(value.nodes.begin(), value.nodes.end(),
               [&key](const typed_pseudocode_ast_node_t& node) { return coordinate_matches(node.coordinate, key); }) &&
           std::all_of(value.source_coordinates.begin(), value.source_coordinates.end(),
               [&key](const source_coordinate_t& coordinate) { return coordinate_matches(coordinate, key); }) &&
           std::all_of(value.unknowns.begin(), value.unknowns.end(),
               [&key](const decompiler_unknown_t& unknown) { return coordinate_matches(unknown.coordinate, key); }) &&
           diagnostic_coordinates_match(value.diagnostics, key);
}

bool has_type(const type_graph_t& graph, const std::uint64_t id) noexcept
{
    const auto found = std::lower_bound(graph.nodes.begin(), graph.nodes.end(), id,
        [](const decompiler_type_node_t& node, const std::uint64_t candidate) {
            return node.id < candidate;
        });
    return found != graph.nodes.end() && found->id == id;
}

bool valid_semantic_queries(
    const std::vector<semantic_refinement_query_t>& queries,
    const decompiler_pipeline_cache_key_t& key) noexcept
{
    std::uint64_t previous = 0;
    for (const auto& query : queries) {
        if (query.ordinal == 0 || query.ordinal <= previous || query.stable_id.empty() ||
            query.refinement_key.empty() || query.coordinate.layer != decompiler_coordinate_layer_t::hir ||
            !coordinate_matches(query.coordinate, key) || !valid_triton_z3_static_ir(query.static_ir))
            return false;
        previous = query.ordinal;
    }
    return true;
}

bool valid_semantic_facts(
    const std::vector<semantic_refinement_fact_t>& facts,
    const decompiler_pipeline_cache_key_t& key) noexcept
{
    std::uint64_t previous = 0;
    for (const auto& fact : facts) {
        if (fact.ordinal == 0 || fact.ordinal <= previous || fact.stable_id.empty() ||
            fact.refinement_key.empty() || fact.coordinate.layer != decompiler_coordinate_layer_t::hir ||
            !coordinate_matches(fact.coordinate, key) || fact.confidence > 100 ||
            fact.provenance != decompiler_fact_provenance_t::semantic_proof)
            return false;
        previous = fact.ordinal;
    }
    return true;
}

bool valid_basic_diagnostics(const std::vector<decompiler_diagnostic_t>& diagnostics) noexcept
{
    if (diagnostics.empty())
        return true;
    std::uint32_t previous = 0;
    for (const auto& diagnostic : diagnostics) {
        if (diagnostic.localization_key.empty() || diagnostic.ordinal == 0 ||
            diagnostic.ordinal <= previous || diagnostic.confidence > 100)
            return false;
        previous = diagnostic.ordinal;
    }
    return true;
}

bool validate_value(
    const decompiler_pipeline_cache_key_t& key,
    const decompiler_provider_ir_cache_value_t& value)
{
    const auto provider_validation = validate_provider_ir(value.provider_ir);
    const auto type_validation = validate_type_graph(value.provider_type_graph);
    if (!provider_validation.valid() || !type_validation.valid() ||
        value.provider_ir.entity != key.entity || value.provider_type_graph.entity != key.entity ||
        !equal_provider(value.provider_ir.provider, key.provider) ||
        !equal_language(value.provider_ir.language, key.language) ||
        value.provider_type_graph.revision != key.type_graph_revision || value.return_type_id == 0 ||
        !has_type(value.provider_type_graph, value.return_type_id) ||
        !provider_coordinates_match(value.provider_ir, key) ||
        !type_graph_coordinates_match(value.provider_type_graph, key) ||
        !valid_semantic_queries(value.semantic_queries, key) ||
        !valid_basic_diagnostics(value.diagnostics) ||
        !diagnostic_coordinates_match(value.diagnostics, key))
        return false;
    if (value.provider_hir) {
        return validate_hir_function(*value.provider_hir).valid() &&
               value.provider_hir->entity == key.entity &&
               value.provider_hir->provider_ir_hash == stable_serialization_hash(value.provider_ir) &&
               value.provider_hir->type_graph_revision == key.type_graph_revision &&
               hir_coordinates_match(*value.provider_hir, key);
    }
    return true;
}

bool validate_value(
    const decompiler_pipeline_cache_key_t& key,
    const decompiler_normalized_cache_value_t& value)
{
    return !value.provider_ir_hash.empty() && value.provider_ir_hash == value.hir.provider_ir_hash &&
           validate_hir_function(value.hir).valid() && validate_type_graph(value.type_graph).valid() &&
           validate_typed_pseudocode_ast(value.ast).valid() &&
           validate_typed_ast_v2_semantics(value.ast, value.type_graph).valid() &&
           value.hir.entity == key.entity && value.type_graph.entity == key.entity && value.ast.entity == key.entity &&
           value.hir.type_graph_revision == key.type_graph_revision &&
           value.type_graph.revision == key.type_graph_revision &&
           value.ast.hir_hash == stable_serialization_hash(value.hir) &&
           value.ast.type_graph_hash == stable_serialization_hash(value.type_graph) &&
           hir_coordinates_match(value.hir, key) && type_graph_coordinates_match(value.type_graph, key) &&
           ast_coordinates_match(value.ast, key) && valid_semantic_facts(value.semantic_facts, key) &&
           valid_basic_diagnostics(value.diagnostics) && diagnostic_coordinates_match(value.diagnostics, key);
}

bool validate_value(
    const decompiler_pipeline_cache_key_t& key,
    const decompiler_rendered_cache_value_t& value)
{
    if (!validate_decompiler_document(value.document).valid() || value.document.entity != key.entity ||
        value.document.profile != key.profile.profile || !equal_renderer(value.document.renderer, key.renderer) ||
        !ast_coordinates_match(value.document.ast, key) ||
        !valid_semantic_facts(value.semantic_facts, key) ||
        !valid_basic_diagnostics(value.diagnostics) ||
        !diagnostic_coordinates_match(value.diagnostics, key))
        return false;
    for (const auto& map : value.document.source_maps) {
        if (!std::all_of(map.coordinates.begin(), map.coordinates.end(),
                [&key](const source_coordinate_t& coordinate) { return coordinate_matches(coordinate, key); }))
            return false;
    }
    return true;
}

workspace_result_t<std::string> canonical_key(
    const decompiler_pipeline_cache_key_t& key,
    const decompiler_cache_stage_t expected_stage,
    const decompiler_cache_v9_limits_t& limits)
{
    if (key.stage != expected_stage || key.workspace_id.size() > limits.max_workspace_id_bytes ||
        !validate_decompiler_pipeline_cache_key(key).valid()) {
        return workspace_result_t<std::string>::failure(
            cache_error(workspace_error_code_t::invalid_argument, "cache key was rejected", key.workspace_id));
    }
    try {
        auto canonical = serialize_decompiler_pipeline_cache_key(key);
        if (canonical.empty() || canonical.size() > limits.max_cache_key_bytes) {
            return workspace_result_t<std::string>::failure(
                cache_error(workspace_error_code_t::limit_exceeded, "cache key exceeds the configured limit", key.workspace_id));
        }
        return workspace_result_t<std::string>::success(std::move(canonical));
    } catch (...) {
        return workspace_result_t<std::string>::failure(
            cache_error(workspace_error_code_t::integrity_failure, "cache key serialization failed", key.workspace_id));
    }
}

void normalize_touch_clock(cache_state_data_t& state)
{
    if (state.touch_clock != std::numeric_limits<std::uint64_t>::max())
        return;
    std::vector<std::tuple<std::uint64_t, std::string, std::string, cache_entry_t*>> ordered;
    ordered.reserve(state.total_entries);
    for (auto& workspace : state.workspaces) {
        for (auto& entry : workspace.second.entries)
            ordered.emplace_back(entry.second.touch, workspace.first, entry.first, &entry.second);
    }
    std::sort(ordered.begin(), ordered.end(), [](const auto& left, const auto& right) {
        return std::tie(std::get<0>(left), std::get<1>(left), std::get<2>(left)) <
               std::tie(std::get<0>(right), std::get<1>(right), std::get<2>(right));
    });
    state.touch_clock = 0;
    for (auto& item : ordered)
        std::get<3>(item)->touch = ++state.touch_clock;
}

std::uint64_t next_touch(cache_state_data_t& state)
{
    normalize_touch_clock(state);
    return ++state.touch_clock;
}

void erase_entry(
    cache_state_data_t& state,
    cache_workspace_t& workspace,
    const std::unordered_map<std::string, cache_entry_t>::iterator entry,
    const bool eviction)
{
    const auto bytes = entry->second.resident_bytes;
    if (eviction)
        ++stage_snapshot(state, entry->second.stage).evictions;
    workspace.resident_bytes -= bytes;
    state.total_bytes -= bytes;
    --state.total_entries;
    workspace.entries.erase(entry);
}

auto oldest_entry(cache_workspace_t& workspace)
{
    return std::min_element(workspace.entries.begin(), workspace.entries.end(),
        [](const auto& left, const auto& right) {
            if (left.second.touch != right.second.touch)
                return left.second.touch < right.second.touch;
            return left.first < right.first;
        });
}

void enforce_limits(cache_state_data_t& state, cache_workspace_t& workspace)
{
    while (workspace.entries.size() > state.limits.max_entries_per_workspace ||
           workspace.resident_bytes > state.limits.max_bytes_per_workspace) {
        const auto candidate = oldest_entry(workspace);
        if (candidate == workspace.entries.end())
            break;
        erase_entry(state, workspace, candidate, true);
    }
    while (state.total_entries > state.limits.max_total_entries ||
           state.total_bytes > state.limits.max_total_bytes) {
        auto selected_workspace = state.workspaces.end();
        std::unordered_map<std::string, cache_entry_t>::iterator selected_entry;
        for (auto workspace_it = state.workspaces.begin(); workspace_it != state.workspaces.end(); ++workspace_it) {
            auto candidate = oldest_entry(workspace_it->second);
            if (candidate == workspace_it->second.entries.end())
                continue;
            if (selected_workspace == state.workspaces.end() ||
                candidate->second.touch < selected_entry->second.touch ||
                (candidate->second.touch == selected_entry->second.touch &&
                 std::tie(workspace_it->first, candidate->first) <
                     std::tie(selected_workspace->first, selected_entry->first))) {
                selected_workspace = workspace_it;
                selected_entry = candidate;
            }
        }
        if (selected_workspace == state.workspaces.end())
            break;
        erase_entry(state, selected_workspace->second, selected_entry, true);
    }
}

void clear_workspace(cache_state_data_t& state, cache_workspace_t& workspace)
{
    state.total_entries -= workspace.entries.size();
    state.total_bytes -= workspace.resident_bytes;
    workspace.entries.clear();
    workspace.resident_bytes = 0;
}

template <typename T>
workspace_result_t<decompiler_cache_v9_lookup_t<T>> lookup_value(
    cache_state_data_t& state,
    const decompiler_pipeline_cache_key_t& key,
    const decompiler_cache_stage_t stage)
{
    auto canonical = canonical_key(key, stage, state.limits);
    if (!canonical) {
        std::lock_guard lock(state.mutex);
        ++stage_snapshot(state, stage).rejections;
        return workspace_result_t<decompiler_cache_v9_lookup_t<T>>::failure(canonical.error());
    }

    std::lock_guard lock(state.mutex);
    auto workspace = state.workspaces.find(key.workspace_id);
    if (workspace == state.workspaces.end()) {
        ++stage_snapshot(state, stage).misses;
        return workspace_result_t<decompiler_cache_v9_lookup_t<T>>::success({});
    }
    if (workspace->second.generation != key.workspace_generation) {
        return workspace_result_t<decompiler_cache_v9_lookup_t<T>>::failure(
            cache_error(workspace_error_code_t::stale_generation,
                        "cache lookup generation is stale", key.workspace_id));
    }
    auto entry = workspace->second.entries.find(canonical.value());
    if (entry == workspace->second.entries.end()) {
        ++stage_snapshot(state, stage).misses;
        return workspace_result_t<decompiler_cache_v9_lookup_t<T>>::success({});
    }
    const auto* typed = std::get_if<std::shared_ptr<const T>>(&entry->second.payload);
    if (!typed || !*typed || entry->second.stage != stage) {
        ++stage_snapshot(state, stage).rejections;
        return workspace_result_t<decompiler_cache_v9_lookup_t<T>>::failure(
            cache_error(workspace_error_code_t::integrity_failure,
                        "cache payload type does not match its stage", key.workspace_id));
    }
    entry->second.touch = next_touch(state);
    ++stage_snapshot(state, stage).hits;
    return workspace_result_t<decompiler_cache_v9_lookup_t<T>>::success({*typed});
}

template <typename T>
workspace_result_t<void> store_value(
    cache_state_data_t& state,
    decompiler_pipeline_cache_key_t key,
    T value,
    const decompiler_cache_stage_t stage)
{
    auto canonical = canonical_key(key, stage, state.limits);
    if (!canonical) {
        std::lock_guard lock(state.mutex);
        ++stage_snapshot(state, stage).rejections;
        return workspace_result_t<void>::failure(canonical.error());
    }
    if (!validate_value(key, value)) {
        std::lock_guard lock(state.mutex);
        ++stage_snapshot(state, stage).rejections;
        return workspace_result_t<void>::failure(
            cache_error(workspace_error_code_t::integrity_failure,
                        "cache payload failed stage validation", key.workspace_id));
    }

    std::string serialized;
    std::shared_ptr<const T> payload;
    try {
        serialized = serialize_cache_value(value);
        payload = std::make_shared<const T>(std::move(value));
    } catch (...) {
        std::lock_guard lock(state.mutex);
        ++stage_snapshot(state, stage).rejections;
        return workspace_result_t<void>::failure(
            cache_error(workspace_error_code_t::limit_exceeded,
                        "cache payload allocation or serialization failed", key.workspace_id));
    }
    const auto key_bytes = static_cast<std::uint64_t>(canonical.value().size());
    const auto payload_bytes = static_cast<std::uint64_t>(serialized.size());
    if (payload_bytes > std::numeric_limits<std::uint64_t>::max() - key_bytes ||
        payload_bytes + key_bytes > state.limits.max_entry_bytes) {
        std::lock_guard lock(state.mutex);
        ++stage_snapshot(state, stage).rejections;
        return workspace_result_t<void>::failure(
            cache_error(workspace_error_code_t::limit_exceeded,
                        "cache payload exceeds the configured entry limit", key.workspace_id));
    }
    const auto resident_bytes = payload_bytes + key_bytes;
    const auto content_hash = stable_serialization_hash(serialized);

    std::lock_guard lock(state.mutex);
    auto workspace = state.workspaces.find(key.workspace_id);
    if (workspace == state.workspaces.end() || workspace->second.generation != key.workspace_generation) {
        return workspace_result_t<void>::failure(
            cache_error(workspace_error_code_t::stale_generation,
                        "cache store generation is stale", key.workspace_id));
    }
    auto existing = workspace->second.entries.find(canonical.value());
    if (existing != workspace->second.entries.end()) {
        if (existing->second.stage != stage || existing->second.content_hash != content_hash) {
            ++stage_snapshot(state, stage).rejections;
            return workspace_result_t<void>::failure(
                cache_error(workspace_error_code_t::integrity_failure,
                            "cache key produced nondeterministic artifacts", key.workspace_id));
        }
        existing->second.touch = next_touch(state);
        ++stage_snapshot(state, stage).stores;
        return workspace_result_t<void>::success();
    }

    cache_entry_t entry;
    entry.stage = stage;
    entry.entity = key.entity;
    entry.payload = std::move(payload);
    entry.content_hash = content_hash;
    entry.resident_bytes = resident_bytes;
    entry.touch = next_touch(state);
    workspace->second.resident_bytes += resident_bytes;
    state.total_bytes += resident_bytes;
    ++state.total_entries;
    workspace->second.entries.emplace(std::move(canonical.value()), std::move(entry));
    ++stage_snapshot(state, stage).stores;
    enforce_limits(state, workspace->second);
    return workspace_result_t<void>::success();
}

}

std::string serialize_decompiler_rendered_cache_value(
    const decompiler_rendered_cache_value_t& value)
{
    return serialize_cache_value(value);
}

std::optional<decompiler_rendered_cache_value_t>
    deserialize_decompiler_rendered_cache_value(std::string_view bytes) noexcept
{
    if (bytes.empty() || bytes.size() > (64ULL << 20))
        return std::nullopt;
    try {
        bounded_reader_t reader(bytes);
        std::string document;
        if (!reader.blob(document))
            return std::nullopt;
        auto decoded_document = deserialize_decompiler_document(document);
        if (!decoded_document.valid())
            return std::nullopt;
        decompiler_rendered_cache_value_t value;
        value.document = std::move(*decoded_document.value);
        if (!read_semantic_facts(reader, value.semantic_facts) ||
            !read_diagnostics(reader, value.diagnostics) || !reader.complete())
            return std::nullopt;
        return value;
    } catch (...) {
        return std::nullopt;
    }
}

struct decompiler_cache_v9_t::state_t : cache_state_data_t {
};

workspace_result_t<std::shared_ptr<decompiler_cache_v9_t>> decompiler_cache_v9_t::create(
    decompiler_cache_v9_limits_t limits)
{
    if (!valid_limits(limits)) {
        return workspace_result_t<std::shared_ptr<decompiler_cache_v9_t>>::failure(
            cache_error(workspace_error_code_t::invalid_argument, "cache limits are invalid"));
    }
    try {
        auto state = std::make_shared<state_t>();
        state->limits = limits;
        return workspace_result_t<std::shared_ptr<decompiler_cache_v9_t>>::success(
            std::shared_ptr<decompiler_cache_v9_t>(new decompiler_cache_v9_t(std::move(state))));
    } catch (...) {
        return workspace_result_t<std::shared_ptr<decompiler_cache_v9_t>>::failure(
            cache_error(workspace_error_code_t::limit_exceeded, "cache allocation failed"));
    }
}

decompiler_cache_v9_t::decompiler_cache_v9_t(std::shared_ptr<state_t> state)
    : state_(std::move(state))
{
}

decompiler_cache_v9_t::~decompiler_cache_v9_t() = default;

workspace_result_t<void> decompiler_cache_v9_t::activate_workspace_generation(
    const std::string& workspace_id,
    const std::uint64_t generation)
{
    if (workspace_id.empty() || workspace_id.size() > state_->limits.max_workspace_id_bytes || generation == 0) {
        return workspace_result_t<void>::failure(
            cache_error(workspace_error_code_t::invalid_argument,
                        "workspace generation identity is invalid", workspace_id));
    }

    std::lock_guard lock(state_->mutex);
    auto workspace = state_->workspaces.find(workspace_id);
    if (workspace == state_->workspaces.end()) {
        if (state_->workspaces.size() >= state_->limits.max_workspaces) {
            return workspace_result_t<void>::failure(
                cache_error(workspace_error_code_t::limit_exceeded,
                            "cache workspace limit is exhausted", workspace_id));
        }
        cache_workspace_t value;
        value.generation = generation;
        state_->workspaces.emplace(workspace_id, std::move(value));
        return workspace_result_t<void>::success();
    }
    if (generation < workspace->second.generation) {
        return workspace_result_t<void>::failure(
            cache_error(workspace_error_code_t::stale_generation,
                        "workspace generation moved backwards", workspace_id));
    }
    if (generation > workspace->second.generation) {
        clear_workspace(*state_, workspace->second);
        workspace->second.generation = generation;
        ++state_->generation_invalidations;
    }
    return workspace_result_t<void>::success();
}

bool decompiler_cache_v9_t::is_current_generation(
    const std::string& workspace_id,
    const std::uint64_t generation) const
{
    std::lock_guard lock(state_->mutex);
    const auto workspace = state_->workspaces.find(workspace_id);
    return workspace != state_->workspaces.end() && workspace->second.generation == generation;
}

workspace_result_t<decompiler_cache_v9_lookup_t<decompiler_provider_ir_cache_value_t>>
decompiler_cache_v9_t::lookup_provider_ir(const decompiler_pipeline_cache_key_t& key)
{
    return lookup_value<decompiler_provider_ir_cache_value_t>(*state_, key, decompiler_cache_stage_t::provider_ir);
}

workspace_result_t<decompiler_cache_v9_lookup_t<decompiler_normalized_cache_value_t>>
decompiler_cache_v9_t::lookup_normalized(const decompiler_pipeline_cache_key_t& key)
{
    return lookup_value<decompiler_normalized_cache_value_t>(*state_, key, decompiler_cache_stage_t::normalized_hir_ast);
}

workspace_result_t<decompiler_cache_v9_lookup_t<decompiler_rendered_cache_value_t>>
decompiler_cache_v9_t::lookup_rendered(const decompiler_pipeline_cache_key_t& key)
{
    return lookup_value<decompiler_rendered_cache_value_t>(*state_, key, decompiler_cache_stage_t::rendered_document);
}

workspace_result_t<void> decompiler_cache_v9_t::store_provider_ir(
    decompiler_pipeline_cache_key_t key,
    decompiler_provider_ir_cache_value_t value)
{
    return store_value(*state_, std::move(key), std::move(value), decompiler_cache_stage_t::provider_ir);
}

workspace_result_t<void> decompiler_cache_v9_t::store_normalized(
    decompiler_pipeline_cache_key_t key,
    decompiler_normalized_cache_value_t value)
{
    return store_value(*state_, std::move(key), std::move(value), decompiler_cache_stage_t::normalized_hir_ast);
}

workspace_result_t<void> decompiler_cache_v9_t::store_rendered(
    decompiler_pipeline_cache_key_t key,
    decompiler_rendered_cache_value_t value)
{
    return store_value(*state_, std::move(key), std::move(value), decompiler_cache_stage_t::rendered_document);
}

workspace_result_t<void> decompiler_cache_v9_t::invalidate_stage(
    const std::string& workspace_id,
    const std::uint64_t generation,
    const decompiler_cache_stage_t stage)
{
    if (stage != decompiler_cache_stage_t::provider_ir &&
        stage != decompiler_cache_stage_t::normalized_hir_ast &&
        stage != decompiler_cache_stage_t::rendered_document) {
        return workspace_result_t<void>::failure(
            cache_error(workspace_error_code_t::invalid_argument, "cache stage is invalid", workspace_id));
    }
    std::lock_guard lock(state_->mutex);
    auto workspace = state_->workspaces.find(workspace_id);
    if (workspace == state_->workspaces.end() || workspace->second.generation != generation) {
        return workspace_result_t<void>::failure(
            cache_error(workspace_error_code_t::stale_generation,
                        "cache invalidation generation is stale", workspace_id));
    }
    for (auto entry = workspace->second.entries.begin(); entry != workspace->second.entries.end();) {
        if (entry->second.stage != stage) {
            ++entry;
            continue;
        }
        auto erase = entry++;
        erase_entry(*state_, workspace->second, erase, false);
    }
    ++state_->explicit_invalidations;
    return workspace_result_t<void>::success();
}

workspace_result_t<void> decompiler_cache_v9_t::invalidate_entities(
    const std::string& workspace_id,
    const std::uint64_t generation,
    const std::vector<decompiler_entity_key_t>& entities)
{
    if (workspace_id.empty() || workspace_id.size() > state_->limits.max_workspace_id_bytes) {
        return workspace_result_t<void>::failure(
            cache_error(workspace_error_code_t::invalid_argument,
                        "cache invalidation workspace identity is invalid", workspace_id));
    }
    std::lock_guard lock(state_->mutex);
    auto workspace = state_->workspaces.find(workspace_id);
    if (workspace == state_->workspaces.end() || workspace->second.generation != generation) {
        return workspace_result_t<void>::failure(
            cache_error(workspace_error_code_t::stale_generation,
                        "cache entity invalidation generation is stale", workspace_id));
    }
    if (entities.empty())
        return workspace_result_t<void>::success();
    for (auto entry = workspace->second.entries.begin(); entry != workspace->second.entries.end();) {
        const bool evict = std::any_of(entities.begin(), entities.end(),
            [&entry](const decompiler_entity_key_t& probe) {
                return entity_matches_invalidation_probe(entry->second.entity, probe);
            });
        if (!evict) {
            ++entry;
            continue;
        }
        auto erase = entry++;
        erase_entry(*state_, workspace->second, erase, false);
    }
    ++state_->explicit_invalidations;
    return workspace_result_t<void>::success();
}

workspace_result_t<void> decompiler_cache_v9_t::invalidate_workspace(
    const std::string& workspace_id,
    const std::uint64_t generation)
{
    std::lock_guard lock(state_->mutex);
    auto workspace = state_->workspaces.find(workspace_id);
    if (workspace == state_->workspaces.end() || workspace->second.generation != generation) {
        return workspace_result_t<void>::failure(
            cache_error(workspace_error_code_t::stale_generation,
                        "cache invalidation generation is stale", workspace_id));
    }
    clear_workspace(*state_, workspace->second);
    ++state_->explicit_invalidations;
    return workspace_result_t<void>::success();
}

workspace_result_t<void> decompiler_cache_v9_t::retire_workspace(
    const std::string& workspace_id,
    const std::uint64_t generation)
{
    std::lock_guard lock(state_->mutex);
    auto workspace = state_->workspaces.find(workspace_id);
    if (workspace == state_->workspaces.end() || workspace->second.generation != generation) {
        return workspace_result_t<void>::failure(
            cache_error(workspace_error_code_t::stale_generation,
                        "cache retirement generation is stale", workspace_id));
    }
    clear_workspace(*state_, workspace->second);
    state_->workspaces.erase(workspace);
    ++state_->explicit_invalidations;
    return workspace_result_t<void>::success();
}

void decompiler_cache_v9_t::clear() noexcept
{
    std::lock_guard lock(state_->mutex);
    state_->workspaces.clear();
    state_->total_entries = 0;
    state_->total_bytes = 0;
    state_->touch_clock = 0;
    ++state_->explicit_invalidations;
}

decompiler_cache_v9_snapshot_t decompiler_cache_v9_t::snapshot() const
{
    decompiler_cache_v9_snapshot_t result;
    std::lock_guard lock(state_->mutex);
    result.provider_ir = state_->provider_ir;
    result.normalized_hir_ast = state_->normalized;
    result.rendered_document = state_->rendered;
    result.workspaces = state_->workspaces.size();
    result.entries = state_->total_entries;
    result.resident_bytes = state_->total_bytes;
    result.generation_invalidations = state_->generation_invalidations;
    result.explicit_invalidations = state_->explicit_invalidations;
    return result;
}

}
