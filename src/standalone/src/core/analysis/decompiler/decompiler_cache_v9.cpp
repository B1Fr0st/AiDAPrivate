#include "decompiler_cache_v9.hpp"

#include "typed_ast_v2.hpp"

#include <algorithm>
#include <array>
#include <atomic>
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

constexpr std::size_t k_stripe_count = 32;

std::size_t stage_index(const decompiler_cache_stage_t stage) noexcept
{
    switch (stage) {
    case decompiler_cache_stage_t::provider_ir:
        return 0;
    case decompiler_cache_stage_t::normalized_hir_ast:
        return 1;
    case decompiler_cache_stage_t::rendered_document:
        return 2;
    }
    return 0;
}

struct cache_entry_t {
    decompiler_cache_stage_t stage = decompiler_cache_stage_t::provider_ir;
    decompiler_entity_key_t entity;
    cache_payload_t payload;
    sha256_digest_t content_hash;
    std::uint64_t resident_bytes = 0;
    std::uint64_t touch = 0;
};

struct cache_directory_entry_t {
    std::atomic<std::uint64_t> generation{0};
    std::atomic<std::uint64_t> resident_bytes{0};
    std::array<std::atomic<std::size_t>, 3> stage_counts{};
};

struct cache_partition_t {
    std::shared_ptr<cache_directory_entry_t> directory;
    std::unordered_map<std::string, cache_entry_t> entries;
};

struct cache_stripe_t {
    mutable std::mutex mutex;
    std::unordered_map<std::string, cache_partition_t> partitions;
};

struct cache_state_data_t {
    decompiler_cache_v9_limits_t limits;
    std::array<cache_stripe_t, k_stripe_count> stripes;
    mutable std::mutex directory_mutex;
    std::unordered_map<std::string, std::shared_ptr<cache_directory_entry_t>> directory;
    std::array<std::atomic<std::uint64_t>, 3> hits{};
    std::array<std::atomic<std::uint64_t>, 3> misses{};
    std::array<std::atomic<std::uint64_t>, 3> stores{};
    std::array<std::atomic<std::uint64_t>, 3> rejections{};
    std::array<std::atomic<std::uint64_t>, 3> evictions{};
    std::atomic<std::size_t> total_entries{0};
    std::atomic<std::uint64_t> total_bytes{0};
    std::atomic<std::uint64_t> touch_clock{0};
    std::atomic<std::uint64_t> generation_invalidations{0};
    std::atomic<std::uint64_t> explicit_invalidations{0};
    std::atomic<bool> eviction_running{false};
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
           value.max_rendered_entries_per_workspace != 0 &&
           value.max_bytes_per_workspace != 0 && value.max_total_entries != 0 &&
           value.max_total_bytes != 0 && value.max_entry_bytes != 0 &&
           value.max_cache_key_bytes != 0 && value.max_workspace_id_bytes != 0 &&
           value.max_entries_per_workspace <= value.max_total_entries &&
           value.max_rendered_entries_per_workspace <= value.max_total_entries &&
           value.max_bytes_per_workspace <= value.max_total_bytes &&
           value.max_entry_bytes <= value.max_bytes_per_workspace;
}

std::size_t entries_cap_for(
    const decompiler_cache_v9_limits_t& limits,
    const decompiler_cache_stage_t stage) noexcept
{
    return stage == decompiler_cache_stage_t::rendered_document
        ? limits.max_rendered_entries_per_workspace
        : limits.max_entries_per_workspace;
}

std::size_t stripe_index_for(
    const std::string& workspace_id,
    const decompiler_cache_stage_t stage) noexcept
{
    std::uint64_t hash = 14695981039346656037ULL;
    for (const char byte : workspace_id) {
        hash ^= static_cast<std::uint8_t>(byte);
        hash *= 1099511628211ULL;
    }
    hash ^= static_cast<std::uint64_t>(stage_index(stage));
    hash *= 1099511628211ULL;
    return static_cast<std::size_t>(hash & (k_stripe_count - 1));
}

std::string partition_key_for(
    const std::string& workspace_id,
    const decompiler_cache_stage_t stage)
{
    std::string key = workspace_id;
    key.push_back('\x1f');
    key.push_back(static_cast<char>('0' + stage_index(stage)));
    return key;
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
           left.emit_comments == right.emit_comments &&
           left.emit_resolved_symbols == right.emit_resolved_symbols &&
           left.emit_enum_case_names == right.emit_enum_case_names &&
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

std::uint64_t next_touch(cache_state_data_t& state) noexcept
{
    return state.touch_clock.fetch_add(1, std::memory_order_acq_rel) + 1;
}

void erase_entry(
    cache_state_data_t& state,
    cache_partition_t& partition,
    const std::unordered_map<std::string, cache_entry_t>::iterator entry,
    const bool eviction) noexcept
{
    const auto bytes = entry->second.resident_bytes;
    const auto stage_idx = stage_index(entry->second.stage);
    if (eviction)
        state.evictions[stage_idx].fetch_add(1, std::memory_order_acq_rel);
    if (partition.directory) {
        partition.directory->resident_bytes.fetch_sub(bytes, std::memory_order_acq_rel);
        partition.directory->stage_counts[stage_idx].fetch_sub(1, std::memory_order_acq_rel);
    }
    state.total_bytes.fetch_sub(bytes, std::memory_order_acq_rel);
    state.total_entries.fetch_sub(1, std::memory_order_acq_rel);
    partition.entries.erase(entry);
}

auto oldest_entry(cache_partition_t& partition)
{
    return std::min_element(partition.entries.begin(), partition.entries.end(),
        [](const auto& left, const auto& right) {
            if (left.second.touch != right.second.touch)
                return left.second.touch < right.second.touch;
            return left.first < right.first;
        });
}

void erase_partition(
    cache_state_data_t& state,
    cache_partition_t& partition) noexcept
{
    for (auto entry = partition.entries.begin(); entry != partition.entries.end();)
        erase_entry(state, partition, entry++, false);
}

void enforce_partition_limit(
    cache_state_data_t& state,
    cache_partition_t& partition,
    const decompiler_cache_stage_t stage)
{
    const auto cap = entries_cap_for(state.limits, stage);
    while (partition.entries.size() > cap) {
        const auto candidate = oldest_entry(partition);
        if (candidate == partition.entries.end())
            break;
        erase_entry(state, partition, candidate, true);
    }
}

bool partition_key_matches(
    const std::string& partition_key,
    const std::string& workspace_prefix) noexcept
{
    return partition_key.size() > workspace_prefix.size() &&
           partition_key.compare(0, workspace_prefix.size(), workspace_prefix) == 0;
}

void rebalance_workspace_bytes(
    cache_state_data_t& state,
    const std::string& workspace_id)
{
    std::shared_ptr<cache_directory_entry_t> directory;
    {
        std::lock_guard lock(state.directory_mutex);
        const auto found = state.directory.find(workspace_id);
        if (found == state.directory.end())
            return;
        directory = found->second;
    }
    const auto prefix = workspace_id + '\x1f';
    for (std::size_t stripe_index = 0; stripe_index < k_stripe_count; ++stripe_index) {
        if (directory->resident_bytes.load(std::memory_order_acquire) <=
            state.limits.max_bytes_per_workspace)
            return;
        auto& stripe = state.stripes[stripe_index];
        std::lock_guard lock(stripe.mutex);
        for (auto& partition : stripe.partitions) {
            if (directory->resident_bytes.load(std::memory_order_acquire) <=
                state.limits.max_bytes_per_workspace)
                return;
            if (!partition_key_matches(partition.first, prefix) ||
                partition.second.entries.empty())
                continue;
            const auto candidate = oldest_entry(partition.second);
            if (candidate == partition.second.entries.end())
                continue;
            erase_entry(state, partition.second, candidate, true);
        }
    }
}

void rebalance_global_totals(cache_state_data_t& state)
{
    for (;;) {
        if (state.total_entries.load(std::memory_order_acquire) <= state.limits.max_total_entries &&
            state.total_bytes.load(std::memory_order_acquire) <= state.limits.max_total_bytes)
            return;
        bool evicted = false;
        for (std::size_t stripe_index = 0; stripe_index < k_stripe_count; ++stripe_index) {
            if (state.total_entries.load(std::memory_order_acquire) <= state.limits.max_total_entries &&
                state.total_bytes.load(std::memory_order_acquire) <= state.limits.max_total_bytes)
                return;
            auto& stripe = state.stripes[stripe_index];
            std::lock_guard lock(stripe.mutex);
            cache_partition_t* oldest_partition = nullptr;
            std::unordered_map<std::string, cache_entry_t>::iterator oldest_candidate;
            std::string oldest_key;
            bool have_oldest = false;
            for (auto partition = stripe.partitions.begin();
                 partition != stripe.partitions.end(); ++partition) {
                if (partition->second.entries.empty())
                    continue;
                auto candidate = oldest_entry(partition->second);
                if (candidate == partition->second.entries.end())
                    continue;
                if (!have_oldest ||
                    candidate->second.touch < oldest_candidate->second.touch ||
                    (candidate->second.touch == oldest_candidate->second.touch &&
                     partition->first < oldest_key)) {
                    oldest_candidate = candidate;
                    oldest_key = partition->first;
                    oldest_partition = &partition->second;
                    have_oldest = true;
                }
            }
            if (!oldest_partition || !have_oldest)
                continue;
            erase_entry(state, *oldest_partition, oldest_candidate, true);
            evicted = true;
        }
        if (!evicted)
            return;
    }
}

void maybe_rebalance(
    cache_state_data_t& state,
    const std::string& workspace_id)
{
    bool expected = false;
    if (!state.eviction_running.compare_exchange_strong(expected, true,
            std::memory_order_acq_rel, std::memory_order_acquire))
        return;
    struct eviction_guard_t {
        cache_state_data_t& state;
        ~eviction_guard_t()
        {
            state.eviction_running.store(false, std::memory_order_release);
        }
    } guard{state};
    rebalance_workspace_bytes(state, workspace_id);
    rebalance_global_totals(state);
}

template <typename T>
workspace_result_t<decompiler_cache_v9_lookup_t<T>> lookup_value(
    cache_state_data_t& state,
    const decompiler_pipeline_cache_key_t& key,
    const decompiler_cache_stage_t stage)
{
    const auto stage_idx = stage_index(stage);
    auto canonical = canonical_key(key, stage, state.limits);
    if (!canonical) {
        state.rejections[stage_idx].fetch_add(1, std::memory_order_acq_rel);
        return workspace_result_t<decompiler_cache_v9_lookup_t<T>>::failure(canonical.error());
    }

    auto& stripe = state.stripes[stripe_index_for(key.workspace_id, stage)];
    std::unique_lock lock(stripe.mutex);
    const auto partition = stripe.partitions.find(partition_key_for(key.workspace_id, stage));
    if (partition == stripe.partitions.end()) {
        lock.unlock();
        std::shared_ptr<cache_directory_entry_t> directory;
        {
            std::lock_guard directory_lock(state.directory_mutex);
            const auto workspace = state.directory.find(key.workspace_id);
            if (workspace != state.directory.end())
                directory = workspace->second;
        }
        if (directory &&
            directory->generation.load(std::memory_order_acquire) != key.workspace_generation) {
            return workspace_result_t<decompiler_cache_v9_lookup_t<T>>::failure(
                cache_error(workspace_error_code_t::stale_generation,
                            "cache lookup generation is stale", key.workspace_id));
        }
        state.misses[stage_idx].fetch_add(1, std::memory_order_acq_rel);
        return workspace_result_t<decompiler_cache_v9_lookup_t<T>>::success({});
    }
    if (!partition->second.directory ||
        partition->second.directory->generation.load(std::memory_order_acquire) !=
            key.workspace_generation) {
        return workspace_result_t<decompiler_cache_v9_lookup_t<T>>::failure(
            cache_error(workspace_error_code_t::stale_generation,
                        "cache lookup generation is stale", key.workspace_id));
    }
    auto entry = partition->second.entries.find(canonical.value());
    if (entry == partition->second.entries.end()) {
        state.misses[stage_idx].fetch_add(1, std::memory_order_acq_rel);
        return workspace_result_t<decompiler_cache_v9_lookup_t<T>>::success({});
    }
    const auto* typed = std::get_if<std::shared_ptr<const T>>(&entry->second.payload);
    if (!typed || !*typed || entry->second.stage != stage) {
        state.rejections[stage_idx].fetch_add(1, std::memory_order_acq_rel);
        return workspace_result_t<decompiler_cache_v9_lookup_t<T>>::failure(
            cache_error(workspace_error_code_t::integrity_failure,
                        "cache payload type does not match its stage", key.workspace_id));
    }
    entry->second.touch = next_touch(state);
    state.hits[stage_idx].fetch_add(1, std::memory_order_acq_rel);
    return workspace_result_t<decompiler_cache_v9_lookup_t<T>>::success({*typed});
}

std::uint64_t live_bytes_add(std::uint64_t left, std::uint64_t right) noexcept
{
    return right > (std::numeric_limits<std::uint64_t>::max)() - left
        ? (std::numeric_limits<std::uint64_t>::max)() : left + right;
}

std::uint64_t live_bytes_string(const std::string& value) noexcept
{
    return live_bytes_add(static_cast<std::uint64_t>(sizeof(std::string)),
        static_cast<std::uint64_t>(value.capacity()));
}

template <typename T>
std::uint64_t live_bytes_vector(const std::vector<T>& values) noexcept
{
    const std::uint64_t capacity = static_cast<std::uint64_t>(values.capacity());
    const std::uint64_t elements = capacity >
            (std::numeric_limits<std::uint64_t>::max)() / sizeof(T)
        ? (std::numeric_limits<std::uint64_t>::max)() : capacity * sizeof(T);
    return live_bytes_add(static_cast<std::uint64_t>(sizeof(std::vector<T>)), elements);
}

std::uint64_t estimate_resident_bytes(const decompiler_entity_key_t& value) noexcept;

std::uint64_t estimate_resident_bytes(const source_coordinate_t& value) noexcept
{
    std::uint64_t total = live_bytes_add(static_cast<std::uint64_t>(sizeof(source_coordinate_t)),
        estimate_resident_bytes(value.entity));
    if (value.source_origin)
        total = live_bytes_add(total, live_bytes_string(value.source_origin->source_path));
    return total;
}

std::uint64_t estimate_resident_bytes(const decompiler_entity_key_t& value) noexcept
{
    std::uint64_t total = sizeof(decompiler_entity_key_t);
    if (const auto* native = std::get_if<native_decompiler_entity_identity_t>(&value.identity)) {
        total = live_bytes_add(total, live_bytes_string(native->canonical_symbol));
    } else if (const auto* cli = std::get_if<cli_decompiler_entity_identity_t>(&value.identity)) {
        total = live_bytes_add(total, live_bytes_string(cli->assembly_identity));
        total = live_bytes_add(total, live_bytes_string(cli->module_name));
        total = live_bytes_add(total, live_bytes_string(cli->declaring_type));
        total = live_bytes_add(total, live_bytes_string(cli->method_name));
        total = live_bytes_add(total, live_bytes_string(cli->method_signature));
    } else if (const auto* jvm = std::get_if<jvm_decompiler_entity_identity_t>(&value.identity)) {
        total = live_bytes_add(total, live_bytes_string(jvm->class_internal_name));
        total = live_bytes_add(total, live_bytes_string(jvm->method_name));
        total = live_bytes_add(total, live_bytes_string(jvm->method_descriptor));
    } else if (const auto* dalvik = std::get_if<dalvik_decompiler_entity_identity_t>(&value.identity)) {
        total = live_bytes_add(total, live_bytes_string(dalvik->class_descriptor));
        total = live_bytes_add(total, live_bytes_string(dalvik->method_name));
        total = live_bytes_add(total, live_bytes_string(dalvik->prototype));
    }
    return total;
}

std::uint64_t estimate_resident_bytes(const decompiler_diagnostic_t& value) noexcept
{
    std::uint64_t total = live_bytes_add(static_cast<std::uint64_t>(sizeof(decompiler_diagnostic_t)),
        live_bytes_string(value.localization_key));
    total = live_bytes_add(total, live_bytes_vector(value.localization_arguments));
    for (const auto& argument : value.localization_arguments)
        total = live_bytes_add(total, live_bytes_string(argument));
    if (value.coordinate)
        total = live_bytes_add(total, estimate_resident_bytes(*value.coordinate));
    return total;
}

std::uint64_t estimate_resident_bytes(const decompiler_unknown_t& value) noexcept
{
    return live_bytes_add(
        live_bytes_add(static_cast<std::uint64_t>(sizeof(decompiler_unknown_t)),
            live_bytes_string(value.stable_token)),
        estimate_resident_bytes(value.coordinate));
}

template <typename T>
std::uint64_t estimate_resident_bytes_vector(const std::vector<T>& values) noexcept;

std::uint64_t estimate_resident_bytes(const provider_ir_value_t& value) noexcept
{
    std::uint64_t total = live_bytes_add(static_cast<std::uint64_t>(sizeof(provider_ir_value_t)),
        live_bytes_vector(value.operand_ids));
    total = live_bytes_add(total, live_bytes_string(value.stable_immediate));
    total = live_bytes_add(total, live_bytes_string(value.stable_symbol));
    return live_bytes_add(total, estimate_resident_bytes(value.coordinate));
}

std::uint64_t estimate_resident_bytes(const provider_ir_block_t& value) noexcept
{
    std::uint64_t total = live_bytes_add(static_cast<std::uint64_t>(sizeof(provider_ir_block_t)),
        live_bytes_vector(value.predecessor_ids));
    total = live_bytes_add(total, live_bytes_vector(value.successor_ids));
    total = live_bytes_add(total, live_bytes_vector(value.exception_successor_ids));
    total = live_bytes_add(total, estimate_resident_bytes_vector(value.values));
    return live_bytes_add(total, estimate_resident_bytes(value.coordinate));
}

std::uint64_t estimate_resident_bytes(const provider_ir_t& value) noexcept
{
    std::uint64_t total = live_bytes_add(static_cast<std::uint64_t>(sizeof(provider_ir_t)),
        estimate_resident_bytes(value.entity));
    total = live_bytes_add(total, live_bytes_string(value.provider.provider_name));
    total = live_bytes_add(total, live_bytes_string(value.provider.provider_version));
    total = live_bytes_add(total, live_bytes_string(value.provider.worker_build_id));
    total = live_bytes_add(total, live_bytes_string(value.language.language_id));
    total = live_bytes_add(total, live_bytes_string(value.language.language_version));
    total = live_bytes_add(total, live_bytes_string(value.language.compiler_spec_id));
    total = live_bytes_add(total, estimate_resident_bytes_vector(value.blocks));
    total = live_bytes_add(total, estimate_resident_bytes_vector(value.source_coordinates));
    total = live_bytes_add(total, estimate_resident_bytes_vector(value.unknowns));
    return live_bytes_add(total, estimate_resident_bytes_vector(value.diagnostics));
}

std::uint64_t estimate_resident_bytes(const hir_value_t& value) noexcept
{
    std::uint64_t total = live_bytes_add(static_cast<std::uint64_t>(sizeof(hir_value_t)),
        live_bytes_vector(value.operand_ids));
    total = live_bytes_add(total, live_bytes_string(value.stable_value));
    return live_bytes_add(total, estimate_resident_bytes(value.coordinate));
}

std::uint64_t estimate_resident_bytes(const hir_variable_t& value) noexcept
{
    return live_bytes_add(
        live_bytes_add(static_cast<std::uint64_t>(sizeof(hir_variable_t)),
            live_bytes_string(value.stable_name)),
        estimate_resident_bytes(value.coordinate));
}

std::uint64_t estimate_resident_bytes(const hir_block_t& value) noexcept
{
    std::uint64_t total = live_bytes_add(static_cast<std::uint64_t>(sizeof(hir_block_t)),
        live_bytes_vector(value.predecessor_ids));
    total = live_bytes_add(total, live_bytes_vector(value.successor_ids));
    total = live_bytes_add(total, live_bytes_vector(value.exception_successor_ids));
    total = live_bytes_add(total, estimate_resident_bytes_vector(value.values));
    return live_bytes_add(total, estimate_resident_bytes(value.coordinate));
}

std::uint64_t estimate_resident_bytes(const hir_function_t& value) noexcept
{
    std::uint64_t total = live_bytes_add(static_cast<std::uint64_t>(sizeof(hir_function_t)),
        estimate_resident_bytes(value.entity));
    total = live_bytes_add(total, estimate_resident_bytes_vector(value.parameters));
    total = live_bytes_add(total, estimate_resident_bytes_vector(value.locals));
    total = live_bytes_add(total, estimate_resident_bytes_vector(value.blocks));
    total = live_bytes_add(total, estimate_resident_bytes_vector(value.source_coordinates));
    total = live_bytes_add(total, estimate_resident_bytes_vector(value.unknowns));
    return live_bytes_add(total, estimate_resident_bytes_vector(value.diagnostics));
}

std::uint64_t estimate_resident_bytes(const decompiler_type_node_t& value) noexcept
{
    std::uint64_t total = live_bytes_add(static_cast<std::uint64_t>(sizeof(decompiler_type_node_t)),
        live_bytes_string(value.canonical_name));
    total = live_bytes_add(total, live_bytes_string(value.display_name));
    return live_bytes_add(total, estimate_resident_bytes_vector(value.coordinates));
}

std::uint64_t estimate_resident_bytes(const decompiler_type_edge_t& value) noexcept
{
    return live_bytes_add(static_cast<std::uint64_t>(sizeof(decompiler_type_edge_t)),
        live_bytes_string(value.stable_name));
}

std::uint64_t estimate_resident_bytes(const type_graph_t& value) noexcept
{
    std::uint64_t total = live_bytes_add(static_cast<std::uint64_t>(sizeof(type_graph_t)),
        estimate_resident_bytes(value.entity));
    total = live_bytes_add(total, estimate_resident_bytes_vector(value.nodes));
    total = live_bytes_add(total, estimate_resident_bytes_vector(value.edges));
    total = live_bytes_add(total, estimate_resident_bytes_vector(value.unknowns));
    return live_bytes_add(total, estimate_resident_bytes_vector(value.diagnostics));
}

std::uint64_t estimate_resident_bytes(const typed_pseudocode_ast_node_t& value) noexcept
{
    std::uint64_t total = live_bytes_add(
        static_cast<std::uint64_t>(sizeof(typed_pseudocode_ast_node_t)),
        live_bytes_vector(value.child_ids));
    total = live_bytes_add(total, live_bytes_string(value.stable_text));
    return live_bytes_add(total, estimate_resident_bytes(value.coordinate));
}

std::uint64_t estimate_resident_bytes(const typed_pseudocode_ast_v2_t& value) noexcept
{
    std::uint64_t total = live_bytes_add(
        static_cast<std::uint64_t>(sizeof(typed_pseudocode_ast_v2_t)),
        estimate_resident_bytes(value.entity));
    total = live_bytes_add(total, estimate_resident_bytes_vector(value.nodes));
    total = live_bytes_add(total, estimate_resident_bytes_vector(value.source_coordinates));
    total = live_bytes_add(total, estimate_resident_bytes_vector(value.unknowns));
    return live_bytes_add(total, estimate_resident_bytes_vector(value.diagnostics));
}

std::uint64_t estimate_resident_bytes(const decompiler_document_source_map_t& value) noexcept
{
    return live_bytes_add(
        static_cast<std::uint64_t>(sizeof(decompiler_document_source_map_t)),
        estimate_resident_bytes_vector(value.coordinates));
}

std::uint64_t estimate_resident_bytes(const decompiler_document_t& value) noexcept
{
    std::uint64_t total = live_bytes_add(static_cast<std::uint64_t>(sizeof(decompiler_document_t)),
        estimate_resident_bytes(value.entity));
    total = live_bytes_add(total, estimate_resident_bytes(value.ast));
    total = live_bytes_add(total, live_bytes_string(value.renderer.style_id));
    total = live_bytes_add(total, live_bytes_string(value.rendered_text));
    total = live_bytes_add(total, live_bytes_vector(value.tokens));
    total = live_bytes_add(total, estimate_resident_bytes_vector(value.source_maps));
    total = live_bytes_add(total, estimate_resident_bytes_vector(value.unknowns));
    return live_bytes_add(total, estimate_resident_bytes_vector(value.diagnostics));
}

std::uint64_t estimate_resident_bytes(const semantic_refinement_query_t& value) noexcept
{
    std::uint64_t total = live_bytes_add(
        static_cast<std::uint64_t>(sizeof(semantic_refinement_query_t)),
        live_bytes_string(value.stable_id));
    total = live_bytes_add(total, live_bytes_string(value.refinement_key));
    total = live_bytes_add(total, estimate_resident_bytes(value.coordinate));
    total = live_bytes_add(total, live_bytes_vector(value.static_ir.nodes));
    for (const auto& node : value.static_ir.nodes)
        total = live_bytes_add(total, live_bytes_string(node.symbol));
    return total;
}

std::uint64_t estimate_resident_bytes(const semantic_refinement_fact_t& value) noexcept
{
    std::uint64_t total = live_bytes_add(
        static_cast<std::uint64_t>(sizeof(semantic_refinement_fact_t)),
        live_bytes_string(value.stable_id));
    total = live_bytes_add(total, live_bytes_string(value.refinement_key));
    return live_bytes_add(total, estimate_resident_bytes(value.coordinate));
}

template <typename T>
std::uint64_t estimate_resident_bytes_vector(const std::vector<T>& values) noexcept
{
    std::uint64_t total = live_bytes_vector(values);
    for (const auto& value : values)
        total = live_bytes_add(total, estimate_resident_bytes(value));
    return total;
}

std::uint64_t estimate_resident_bytes(const decompiler_provider_ir_cache_value_t& value) noexcept
{
    std::uint64_t total = live_bytes_add(
        static_cast<std::uint64_t>(sizeof(decompiler_provider_ir_cache_value_t)),
        estimate_resident_bytes(value.provider_ir));
    if (value.provider_hir)
        total = live_bytes_add(total, estimate_resident_bytes(*value.provider_hir));
    total = live_bytes_add(total, estimate_resident_bytes(value.provider_type_graph));
    total = live_bytes_add(total, estimate_resident_bytes_vector(value.semantic_queries));
    total = live_bytes_add(total, estimate_resident_bytes_vector(value.diagnostics));
    return live_bytes_add(total, static_cast<std::uint64_t>(sizeof(value.evidence)));
}

std::uint64_t estimate_resident_bytes(const decompiler_normalized_cache_value_t& value) noexcept
{
    std::uint64_t total = live_bytes_add(
        static_cast<std::uint64_t>(sizeof(decompiler_normalized_cache_value_t)),
        estimate_resident_bytes(value.hir));
    total = live_bytes_add(total, estimate_resident_bytes(value.type_graph));
    total = live_bytes_add(total, estimate_resident_bytes(value.ast));
    total = live_bytes_add(total, estimate_resident_bytes_vector(value.semantic_facts));
    total = live_bytes_add(total, estimate_resident_bytes_vector(value.diagnostics));
    return live_bytes_add(total, static_cast<std::uint64_t>(sizeof(value.evidence)));
}

std::uint64_t estimate_resident_bytes(const decompiler_rendered_cache_value_t& value) noexcept
{
    std::uint64_t total = live_bytes_add(
        static_cast<std::uint64_t>(sizeof(decompiler_rendered_cache_value_t)),
        estimate_resident_bytes(value.document));
    total = live_bytes_add(total, estimate_resident_bytes_vector(value.semantic_facts));
    return live_bytes_add(total, estimate_resident_bytes_vector(value.diagnostics));
}

template <typename T>
workspace_result_t<void> store_value(
    cache_state_data_t& state,
    decompiler_pipeline_cache_key_t key,
    T value,
    const decompiler_cache_stage_t stage,
    std::string* serialized_out = nullptr)
{
    const auto stage_idx = stage_index(stage);
    auto canonical = canonical_key(key, stage, state.limits);
    if (!canonical) {
        state.rejections[stage_idx].fetch_add(1, std::memory_order_acq_rel);
        return workspace_result_t<void>::failure(canonical.error());
    }
    if (!validate_value(key, value)) {
        state.rejections[stage_idx].fetch_add(1, std::memory_order_acq_rel);
        return workspace_result_t<void>::failure(
            cache_error(workspace_error_code_t::integrity_failure,
                        "cache payload failed stage validation", key.workspace_id));
    }

    const std::uint64_t estimated_payload_bytes = estimate_resident_bytes(value);
    std::string serialized;
    std::shared_ptr<const T> payload;
    try {
        serialized = serialize_cache_value(value);
        payload = std::make_shared<const T>(std::move(value));
    } catch (...) {
        state.rejections[stage_idx].fetch_add(1, std::memory_order_acq_rel);
        return workspace_result_t<void>::failure(
            cache_error(workspace_error_code_t::limit_exceeded,
                        "cache payload allocation or serialization failed", key.workspace_id));
    }
    const auto key_bytes = static_cast<std::uint64_t>(canonical.value().size());
    if (estimated_payload_bytes > (std::numeric_limits<std::uint64_t>::max)() - key_bytes ||
        estimated_payload_bytes + key_bytes > state.limits.max_entry_bytes) {
        state.rejections[stage_idx].fetch_add(1, std::memory_order_acq_rel);
        return workspace_result_t<void>::failure(
            cache_error(workspace_error_code_t::limit_exceeded,
                        "cache payload exceeds the configured entry limit", key.workspace_id));
    }
    const auto resident_bytes = estimated_payload_bytes + key_bytes;
    const auto content_hash = stable_serialization_hash(serialized);
    if (serialized_out != nullptr)
        *serialized_out = std::move(serialized);

    std::shared_ptr<cache_directory_entry_t> directory;
    {
        std::lock_guard lock(state.directory_mutex);
        const auto found = state.directory.find(key.workspace_id);
        if (found == state.directory.end()) {
            return workspace_result_t<void>::failure(
                cache_error(workspace_error_code_t::stale_generation,
                            "cache store generation is stale", key.workspace_id));
        }
        directory = found->second;
    }
    if (directory->generation.load(std::memory_order_acquire) != key.workspace_generation) {
        return workspace_result_t<void>::failure(
            cache_error(workspace_error_code_t::stale_generation,
                        "cache store generation is stale", key.workspace_id));
    }

    {
        auto& stripe = state.stripes[stripe_index_for(key.workspace_id, stage)];
        std::lock_guard lock(stripe.mutex);
        auto& partition = stripe.partitions[partition_key_for(key.workspace_id, stage)];
        if (!partition.directory)
            partition.directory = directory;
        auto existing = partition.entries.find(canonical.value());
        if (existing != partition.entries.end()) {
            if (existing->second.stage != stage || existing->second.content_hash != content_hash) {
                state.rejections[stage_idx].fetch_add(1, std::memory_order_acq_rel);
                return workspace_result_t<void>::failure(
                    cache_error(workspace_error_code_t::integrity_failure,
                                "cache key produced nondeterministic artifacts", key.workspace_id));
            }
            existing->second.touch = next_touch(state);
            state.stores[stage_idx].fetch_add(1, std::memory_order_acq_rel);
            return workspace_result_t<void>::success();
        }

        cache_entry_t entry;
        entry.stage = stage;
        entry.entity = key.entity;
        entry.payload = std::move(payload);
        entry.content_hash = content_hash;
        entry.resident_bytes = resident_bytes;
        entry.touch = next_touch(state);
        directory->resident_bytes.fetch_add(resident_bytes, std::memory_order_acq_rel);
        directory->stage_counts[stage_idx].fetch_add(1, std::memory_order_acq_rel);
        state.total_bytes.fetch_add(resident_bytes, std::memory_order_acq_rel);
        state.total_entries.fetch_add(1, std::memory_order_acq_rel);
        partition.entries.emplace(std::move(canonical.value()), std::move(entry));
        state.stores[stage_idx].fetch_add(1, std::memory_order_acq_rel);
        enforce_partition_limit(state, partition, stage);
    }
    if (directory->resident_bytes.load(std::memory_order_acquire) >
            state.limits.max_bytes_per_workspace ||
        state.total_entries.load(std::memory_order_acquire) > state.limits.max_total_entries ||
        state.total_bytes.load(std::memory_order_acquire) > state.limits.max_total_bytes)
        maybe_rebalance(state, key.workspace_id);
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

    std::shared_ptr<cache_directory_entry_t> directory;
    {
        std::lock_guard lock(state_->directory_mutex);
        auto workspace = state_->directory.find(workspace_id);
        if (workspace == state_->directory.end()) {
            if (state_->directory.size() >= state_->limits.max_workspaces) {
                return workspace_result_t<void>::failure(
                    cache_error(workspace_error_code_t::limit_exceeded,
                                "cache workspace limit is exhausted", workspace_id));
            }
            directory = std::make_shared<cache_directory_entry_t>();
            directory->generation.store(generation, std::memory_order_release);
            state_->directory.emplace(workspace_id, std::move(directory));
            return workspace_result_t<void>::success();
        }
        directory = workspace->second;
    }
    const auto current = directory->generation.load(std::memory_order_acquire);
    if (generation < current) {
        return workspace_result_t<void>::failure(
            cache_error(workspace_error_code_t::stale_generation,
                        "workspace generation moved backwards", workspace_id));
    }
    if (generation == current)
        return workspace_result_t<void>::success();
    directory->generation.store(generation, std::memory_order_release);
    const auto prefix = workspace_id + '\x1f';
    for (std::size_t stripe_index = 0; stripe_index < k_stripe_count; ++stripe_index) {
        auto& stripe = state_->stripes[stripe_index];
        std::lock_guard lock(stripe.mutex);
        for (auto partition = stripe.partitions.begin();
             partition != stripe.partitions.end();) {
            if (!partition_key_matches(partition->first, prefix)) {
                ++partition;
                continue;
            }
            auto erase = partition++;
            erase_partition(*state_, erase->second);
            stripe.partitions.erase(erase);
        }
    }
    state_->generation_invalidations.fetch_add(1, std::memory_order_acq_rel);
    return workspace_result_t<void>::success();
}

bool decompiler_cache_v9_t::is_current_generation(
    const std::string& workspace_id,
    const std::uint64_t generation) const
{
    std::shared_ptr<cache_directory_entry_t> directory;
    {
        std::lock_guard lock(state_->directory_mutex);
        const auto workspace = state_->directory.find(workspace_id);
        if (workspace == state_->directory.end())
            return false;
        directory = workspace->second;
    }
    return directory->generation.load(std::memory_order_acquire) == generation;
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

workspace_result_t<void> decompiler_cache_v9_t::store_rendered(
    decompiler_pipeline_cache_key_t key,
    decompiler_rendered_cache_value_t value,
    std::string* serialized_out)
{
    return store_value(*state_, std::move(key), std::move(value),
        decompiler_cache_stage_t::rendered_document, serialized_out);
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
    std::shared_ptr<cache_directory_entry_t> directory;
    {
        std::lock_guard lock(state_->directory_mutex);
        const auto workspace = state_->directory.find(workspace_id);
        if (workspace == state_->directory.end()) {
            return workspace_result_t<void>::failure(
                cache_error(workspace_error_code_t::stale_generation,
                            "cache invalidation generation is stale", workspace_id));
        }
        directory = workspace->second;
    }
    if (directory->generation.load(std::memory_order_acquire) != generation) {
        return workspace_result_t<void>::failure(
            cache_error(workspace_error_code_t::stale_generation,
                        "cache invalidation generation is stale", workspace_id));
    }
    auto& stripe = state_->stripes[stripe_index_for(workspace_id, stage)];
    std::lock_guard lock(stripe.mutex);
    const auto partition = stripe.partitions.find(partition_key_for(workspace_id, stage));
    if (partition != stripe.partitions.end())
        erase_partition(*state_, partition->second);
    state_->explicit_invalidations.fetch_add(1, std::memory_order_acq_rel);
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
    std::shared_ptr<cache_directory_entry_t> directory;
    {
        std::lock_guard lock(state_->directory_mutex);
        const auto workspace = state_->directory.find(workspace_id);
        if (workspace == state_->directory.end()) {
            return workspace_result_t<void>::failure(
                cache_error(workspace_error_code_t::stale_generation,
                            "cache entity invalidation generation is stale", workspace_id));
        }
        directory = workspace->second;
    }
    if (directory->generation.load(std::memory_order_acquire) != generation) {
        return workspace_result_t<void>::failure(
            cache_error(workspace_error_code_t::stale_generation,
                        "cache entity invalidation generation is stale", workspace_id));
    }
    if (entities.empty())
        return workspace_result_t<void>::success();
    const std::array<decompiler_cache_stage_t, 3> stages{
        decompiler_cache_stage_t::provider_ir,
        decompiler_cache_stage_t::normalized_hir_ast,
        decompiler_cache_stage_t::rendered_document};
    for (const auto stage : stages) {
        auto& stripe = state_->stripes[stripe_index_for(workspace_id, stage)];
        std::lock_guard lock(stripe.mutex);
        const auto partition = stripe.partitions.find(partition_key_for(workspace_id, stage));
        if (partition == stripe.partitions.end())
            continue;
        for (auto entry = partition->second.entries.begin();
             entry != partition->second.entries.end();) {
            const bool evict = std::any_of(entities.begin(), entities.end(),
                [&entry](const decompiler_entity_key_t& probe) {
                    return entity_matches_invalidation_probe(entry->second.entity, probe);
                });
            if (!evict) {
                ++entry;
                continue;
            }
            auto erase = entry++;
            erase_entry(*state_, partition->second, erase, false);
        }
    }
    state_->explicit_invalidations.fetch_add(1, std::memory_order_acq_rel);
    return workspace_result_t<void>::success();
}

workspace_result_t<void> decompiler_cache_v9_t::invalidate_workspace(
    const std::string& workspace_id,
    const std::uint64_t generation)
{
    std::shared_ptr<cache_directory_entry_t> directory;
    {
        std::lock_guard lock(state_->directory_mutex);
        const auto workspace = state_->directory.find(workspace_id);
        if (workspace == state_->directory.end()) {
            return workspace_result_t<void>::failure(
                cache_error(workspace_error_code_t::stale_generation,
                            "cache invalidation generation is stale", workspace_id));
        }
        directory = workspace->second;
    }
    if (directory->generation.load(std::memory_order_acquire) != generation) {
        return workspace_result_t<void>::failure(
            cache_error(workspace_error_code_t::stale_generation,
                        "cache invalidation generation is stale", workspace_id));
    }
    const auto prefix = workspace_id + '\x1f';
    for (std::size_t stripe_index = 0; stripe_index < k_stripe_count; ++stripe_index) {
        auto& stripe = state_->stripes[stripe_index];
        std::lock_guard lock(stripe.mutex);
        for (auto partition = stripe.partitions.begin();
             partition != stripe.partitions.end();) {
            if (!partition_key_matches(partition->first, prefix)) {
                ++partition;
                continue;
            }
            auto erase = partition++;
            erase_partition(*state_, erase->second);
            stripe.partitions.erase(erase);
        }
    }
    state_->explicit_invalidations.fetch_add(1, std::memory_order_acq_rel);
    return workspace_result_t<void>::success();
}

workspace_result_t<void> decompiler_cache_v9_t::retire_workspace(
    const std::string& workspace_id,
    const std::uint64_t generation)
{
    auto invalidated = invalidate_workspace(workspace_id, generation);
    if (!invalidated)
        return invalidated;
    std::lock_guard lock(state_->directory_mutex);
    const auto workspace = state_->directory.find(workspace_id);
    if (workspace == state_->directory.end() ||
        workspace->second->generation.load(std::memory_order_acquire) != generation) {
        return workspace_result_t<void>::failure(
            cache_error(workspace_error_code_t::stale_generation,
                        "cache retirement generation is stale", workspace_id));
    }
    state_->directory.erase(workspace);
    return workspace_result_t<void>::success();
}

void decompiler_cache_v9_t::clear() noexcept
{
    for (std::size_t stripe_index = 0; stripe_index < k_stripe_count; ++stripe_index) {
        auto& stripe = state_->stripes[stripe_index];
        std::lock_guard lock(stripe.mutex);
        stripe.partitions.clear();
    }
    {
        std::lock_guard lock(state_->directory_mutex);
        state_->directory.clear();
    }
    state_->total_entries.store(0, std::memory_order_release);
    state_->total_bytes.store(0, std::memory_order_release);
    state_->touch_clock.store(0, std::memory_order_release);
    state_->explicit_invalidations.fetch_add(1, std::memory_order_acq_rel);
}

decompiler_cache_v9_snapshot_t decompiler_cache_v9_t::snapshot() const
{
    decompiler_cache_v9_snapshot_t result;
    const auto load_stage = [this](const std::size_t index, decompiler_cache_v9_stage_snapshot_t& stage) {
        stage.hits = state_->hits[index].load(std::memory_order_acquire);
        stage.misses = state_->misses[index].load(std::memory_order_acquire);
        stage.stores = state_->stores[index].load(std::memory_order_acquire);
        stage.rejections = state_->rejections[index].load(std::memory_order_acquire);
        stage.evictions = state_->evictions[index].load(std::memory_order_acquire);
    };
    load_stage(0, result.provider_ir);
    load_stage(1, result.normalized_hir_ast);
    load_stage(2, result.rendered_document);
    {
        std::lock_guard lock(state_->directory_mutex);
        result.workspaces = state_->directory.size();
    }
    result.entries = state_->total_entries.load(std::memory_order_acquire);
    result.resident_bytes = state_->total_bytes.load(std::memory_order_acquire);
    result.generation_invalidations = state_->generation_invalidations.load(std::memory_order_acquire);
    result.explicit_invalidations = state_->explicit_invalidations.load(std::memory_order_acquire);
    return result;
}

}
