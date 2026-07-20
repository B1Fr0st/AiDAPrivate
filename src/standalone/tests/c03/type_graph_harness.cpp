#include "type_graph_harness.hpp"
#include "assertion_telemetry/assertion_telemetry.hpp"
#include "../../src/core/analysis/decompiler/type_graph_builder.hpp"
#include "../../src/core/analysis/decompiler/decompiler_contracts.hpp"

#include <algorithm>
#include <iostream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>

namespace aida::analysis::c03_test {
namespace {

using namespace ::aida::analysis::type_graph;

void require(bool condition, const char* message)
{
	assertion_telemetry::record_assertion(condition, message, __FILE__, __LINE__);
    if (!condition)
        throw std::runtime_error(message);
}

sha256_digest_t digest(const std::string& value)
{
    return stable_serialization_hash(value);
}

address_t address(std::uint64_t value)
{
    address_t result;
    result.space = address_space_id_t::relative_virtual;
    result.value = value;
    result.architecture = architecture_id_t::x86_64;
    result.mode = architecture_mode_t::x86_64;
    return result;
}

decompiler_entity_key_t native_entity()
{
    native_decompiler_entity_identity_t identity;
    identity.function_id = 42;
    identity.entry = address(0x1000);
    identity.end = address(0x1010);
    identity.function_bytes_hash = digest("type-graph-fixture");
    identity.canonical_symbol = "fixture::type_graph_test";
    decompiler_entity_key_t result;
    result.schema_version = k_decompiler_contract_schema_version;
    result.kind = decompiler_entity_kind_t::native_function;
    result.format = format_id_t::pe32_plus;
    result.architecture = architecture_id_t::x86_64;
    result.mode = architecture_mode_t::x86_64;
    result.endian = endian_t::little;
    result.identity = std::move(identity);
    return result;
}

source_coordinate_t make_coord(const decompiler_entity_key_t& entity, std::uint64_t addr_value)
{
    source_coordinate_t coordinate;
    coordinate.layer = decompiler_coordinate_layer_t::hir;
    coordinate.workspace_generation = 1;
    coordinate.entity = entity;
    decompiler_address_range_t range;
    range.begin.space = address_space_id_t::relative_virtual;
    range.begin.value = addr_value;
    range.begin.architecture = entity.architecture;
    range.begin.mode = entity.mode;
    range.end = range.begin;
    range.end.value = addr_value + 1;
    coordinate.address_range = range;
    return coordinate;
}

type_candidate_t make_candidate(
    const std::string& canonical_name,
    decompiler_type_kind_t kind,
    std::uint64_t byte_size,
    decompiler_fact_provenance_t provenance,
    std::uint8_t confidence,
    const decompiler_entity_key_t& entity)
{
    type_candidate_t candidate;
    candidate.kind = kind;
    candidate.canonical_name = canonical_name;
    candidate.display_name = canonical_name;
    candidate.byte_size = byte_size;
    candidate.alignment = 8;
    candidate.confidence = confidence;
    candidate.provenance = provenance;
    candidate.source_detail = "test_fixture";
    candidate.coordinate = make_coord(entity, 0x2000);
    return candidate;
}

type_edge_candidate_t make_edge(
    decompiler_type_edge_kind_t kind,
    const std::string& target,
    const std::string& name,
    decompiler_fact_provenance_t provenance,
    std::uint8_t confidence,
    std::uint64_t offset = 0)
{
    type_edge_candidate_t edge;
    edge.kind = kind;
    edge.target_canonical_name = target;
    edge.stable_name = name;
    edge.byte_offset = offset;
    edge.confidence = confidence;
    edge.provenance = provenance;
    edge.source_detail = "test_fixture";
    return edge;
}

const decompiler_type_node_t* find_node(const type_graph_t& graph, const std::string& canonical_name)
{
    for (const auto& node : graph.nodes)
        if (node.canonical_name == canonical_name)
            return &node;
    return nullptr;
}

bool has_edge(const type_graph_t& graph, std::uint64_t source_id, std::uint64_t target_id,
             decompiler_type_edge_kind_t kind, const std::string& stable_name)
{
    for (const auto& edge : graph.edges) {
        if (edge.source_type_id == source_id && edge.target_type_id == target_id &&
            edge.kind == kind && edge.stable_name == stable_name)
            return true;
    }
    return false;
}

bool has_unknown(const type_graph_t& graph, const std::string& token)
{
    for (const auto& unknown : graph.unknowns)
        if (unknown.stable_token == token)
            return true;
    return false;
}

bool has_diagnostic(const type_graph_t& graph, const std::string& key_prefix)
{
    for (const auto& diagnostic : graph.diagnostics)
        if (diagnostic.localization_key.find(key_prefix) == 0)
            return true;
    return false;
}

void test_conflict_and_recursive_types()
{
    auto entity = native_entity();
    type_graph_builder_config_t config;
    config.max_nodes = 1024;
    config.max_edges_per_node = 256;
    config.max_total_edges = 4096;
    config.preserve_unknowns = true;
    config.strict_conflict_reporting = true;

    type_graph_builder_t builder(entity, config);

    type_seed_batch_t pdb_batch;
    pdb_batch.source = decompiler_fact_provenance_t::debug_metadata;
    pdb_batch.source_label = "PDB";

    auto linked_list = make_candidate("LinkedList", decompiler_type_kind_t::structure, 24,
                                      decompiler_fact_provenance_t::debug_metadata, 95, entity);
    linked_list.edges.push_back(make_edge(decompiler_type_edge_kind_t::member, "LinkedList", "next",
                                          decompiler_fact_provenance_t::debug_metadata, 95, 0));
    linked_list.edges.push_back(make_edge(decompiler_type_edge_kind_t::member, "int", "data",
                                          decompiler_fact_provenance_t::debug_metadata, 95, 8));
    pdb_batch.candidates.push_back(linked_list);

    auto int_type = make_candidate("int", decompiler_type_kind_t::signed_integer, 4,
                                   decompiler_fact_provenance_t::debug_metadata, 100, entity);
    int_type.is_signed = true;
    pdb_batch.candidates.push_back(int_type);

    builder.add_seed_batch(std::move(pdb_batch));

    type_seed_batch_t rtti_batch;
    rtti_batch.source = decompiler_fact_provenance_t::rtti;
    rtti_batch.source_label = "RTTI";

    auto linked_list_rtti = make_candidate("LinkedList", decompiler_type_kind_t::structure, 32,
                                           decompiler_fact_provenance_t::rtti, 70, entity);
    rtti_batch.candidates.push_back(linked_list_rtti);

    auto animal = make_candidate("Animal", decompiler_type_kind_t::class_type, 48,
                                 decompiler_fact_provenance_t::rtti, 80, entity);
    animal.edges.push_back(make_edge(decompiler_type_edge_kind_t::base, "Creature", "base",
                                     decompiler_fact_provenance_t::rtti, 80, 0));
    rtti_batch.candidates.push_back(animal);

    auto creature = make_candidate("Creature", decompiler_type_kind_t::class_type, 32,
                                   decompiler_fact_provenance_t::rtti, 80, entity);
    creature.edges.push_back(make_edge(decompiler_type_edge_kind_t::member, "int", "legs",
                                       decompiler_fact_provenance_t::rtti, 80, 0));
    rtti_batch.candidates.push_back(creature);

    builder.add_seed_batch(std::move(rtti_batch));

    auto graph = builder.build();

    const auto validation = validate_type_graph(graph);
    require(validation.valid(), "recursive/conflict type graph failed validation");

    const auto* ll_node = find_node(graph, "LinkedList");
    require(ll_node != nullptr, "LinkedList node missing from graph");
    require(ll_node->kind == decompiler_type_kind_t::structure, "LinkedList kind wrong");
    require(ll_node->byte_size.has_value(), "LinkedList byte_size missing");
    require(*ll_node->byte_size == 24, "LinkedList byte_size should be 24 (debug_metadata wins over rtti)");
    require(ll_node->confidence == 95, "LinkedList confidence should be 95 from debug_metadata");
    require(ll_node->provenance == decompiler_fact_provenance_t::debug_metadata,
            "LinkedList provenance should be debug_metadata");

    require(builder.stats().recursive_types > 0, "Recursive type (LinkedList->LinkedList) not detected");

    const auto* animal_node = find_node(graph, "Animal");
    require(animal_node != nullptr, "Animal node missing");
    require(animal_node->kind == decompiler_type_kind_t::class_type, "Animal kind wrong");

    const auto* creature_node = find_node(graph, "Creature");
    require(creature_node != nullptr, "Creature node missing");
    require(has_edge(graph, animal_node->id, creature_node->id,
                     decompiler_type_edge_kind_t::base, "base"),
            "Animal->Creature base edge missing");
    require(has_edge(graph, ll_node->id, ll_node->id,
                     decompiler_type_edge_kind_t::member, "next"),
            "LinkedList self-referential edge missing");
    require(has_edge(graph, ll_node->id, find_node(graph, "int")->id,
                     decompiler_type_edge_kind_t::member, "data"),
            "LinkedList->int member edge missing");
}

void test_no_silent_overwrite()
{
    auto entity = native_entity();
    type_graph_builder_config_t config;
    config.preserve_unknowns = true;

    type_graph_builder_t builder(entity, config);

    type_seed_batch_t dwarf_batch;
    dwarf_batch.source = decompiler_fact_provenance_t::debug_metadata;
    dwarf_batch.source_label = "DWARF";

    auto my_struct = make_candidate("MyStruct", decompiler_type_kind_t::structure, 16,
                                    decompiler_fact_provenance_t::debug_metadata, 90, entity);
    my_struct.is_signed = false;
    dwarf_batch.candidates.push_back(my_struct);
    builder.add_seed_batch(std::move(dwarf_batch));

    type_seed_batch_t loader_batch;
    loader_batch.source = decompiler_fact_provenance_t::loader_metadata;
    loader_batch.source_label = "loader";

    auto my_struct_loader = make_candidate("MyStruct", decompiler_type_kind_t::union_type, 32,
                                           decompiler_fact_provenance_t::loader_metadata, 50, entity);
    loader_batch.candidates.push_back(my_struct_loader);
    builder.add_seed_batch(std::move(loader_batch));

    auto graph = builder.build();
    const auto validation = validate_type_graph(graph);
    require(validation.valid(), "no-silent-overwrite graph failed validation");

    const auto* node = find_node(graph, "MyStruct");
    require(node != nullptr, "MyStruct node missing");
    require(node->kind == decompiler_type_kind_t::structure,
            "MyStruct kind should be structure (debug_metadata wins)");
    require(*node->byte_size == 16,
            "MyStruct byte_size should be 16 (debug_metadata wins)");
    require(node->provenance == decompiler_fact_provenance_t::debug_metadata,
            "MyStruct provenance should be debug_metadata");

    const auto& conflicts = builder.conflicts();
    require(!conflicts.empty(), "No conflicts recorded for MyStruct disagreement");

    bool found_kind_conflict = false;
    bool found_size_conflict = false;
    for (const auto& conflict : conflicts) {
        if (conflict.canonical_name == "MyStruct" && conflict.field_name == "kind")
            found_kind_conflict = true;
        if (conflict.canonical_name == "MyStruct" && conflict.field_name == "byte_size")
            found_size_conflict = true;
    }
    require(found_kind_conflict, "kind conflict not recorded");
    require(found_size_conflict, "byte_size conflict not recorded");

    require(has_diagnostic(graph, "type_graph.conflict.MyStruct"),
            "conflict diagnostic not emitted in graph");
}

void test_stable_ids()
{
    auto entity = native_entity();
    type_graph_builder_config_t config;
    config.preserve_unknowns = true;

    std::vector<std::string> names = {"Zeta", "Alpha", "Midway", "Bravo", "Charlie"};

    type_graph_builder_t builder_a(entity, config);
    for (std::size_t i = 0; i < names.size(); ++i) {
        type_seed_batch_t batch;
        batch.source = decompiler_fact_provenance_t::debug_metadata;
        batch.source_label = "batch_" + std::to_string(i);
        auto candidate = make_candidate(names[i], decompiler_type_kind_t::structure, 8,
                                        decompiler_fact_provenance_t::debug_metadata, 80, entity);
        batch.candidates.push_back(candidate);
        builder_a.add_seed_batch(std::move(batch));
    }
    auto graph_a = builder_a.build();
    const auto validation_a = validate_type_graph(graph_a);
    require(validation_a.valid(), "stable-ids graph A failed validation");

    type_graph_builder_t builder_b(entity, config);
    for (std::size_t i = names.size(); i > 0; --i) {
        type_seed_batch_t batch;
        batch.source = decompiler_fact_provenance_t::debug_metadata;
        batch.source_label = "batch_" + std::to_string(i);
        auto candidate = make_candidate(names[i - 1], decompiler_type_kind_t::structure, 8,
                                        decompiler_fact_provenance_t::debug_metadata, 80, entity);
        batch.candidates.push_back(candidate);
        builder_b.add_seed_batch(std::move(batch));
    }
    auto graph_b = builder_b.build();
    const auto validation_b = validate_type_graph(graph_b);
    require(validation_b.valid(), "stable-ids graph B failed validation");

    require(graph_a.nodes.size() == graph_b.nodes.size(),
            "stable IDs: node count differs between insertion orders");

    for (std::size_t i = 0; i < graph_a.nodes.size(); ++i) {
        require(graph_a.nodes[i].id == graph_b.nodes[i].id,
                "stable IDs: ID differs for same canonical name");
        require(graph_a.nodes[i].canonical_name == graph_b.nodes[i].canonical_name,
                "stable IDs: canonical name differs at same position");
    }

    std::vector<std::string> sorted_a;
    for (const auto& node : graph_a.nodes)
        sorted_a.push_back(node.canonical_name);
    std::vector<std::string> sorted_b = sorted_a;
    std::sort(sorted_b.begin(), sorted_b.end());
    require(sorted_a == sorted_b, "stable IDs: nodes not in lexicographic order");
}

void test_bounded_graph()
{
    auto entity = native_entity();
    type_graph_builder_config_t config;
    config.max_nodes = 5;
    config.max_edges_per_node = 4;
    config.max_total_edges = 16;
    config.preserve_unknowns = true;

    type_graph_builder_t builder(entity, config);

    type_seed_batch_t batch;
    batch.source = decompiler_fact_provenance_t::debug_metadata;
    batch.source_label = "overflow";

    for (std::uint32_t i = 0; i < 20; ++i) {
        auto candidate = make_candidate("Type" + std::to_string(i),
                                        decompiler_type_kind_t::structure, 16,
                                        decompiler_fact_provenance_t::debug_metadata, 80, entity);
        for (std::uint32_t e = 0; e < 6; ++e) {
            candidate.edges.push_back(make_edge(
                decompiler_type_edge_kind_t::member,
                "Type" + std::to_string(e),
                "field" + std::to_string(e),
                decompiler_fact_provenance_t::debug_metadata, 80, e * 8));
        }
        batch.candidates.push_back(candidate);
    }
    builder.add_seed_batch(std::move(batch));

    auto graph = builder.build();
    const auto validation = validate_type_graph(graph);
    require(validation.valid(), "bounded graph failed validation");

    require(graph.nodes.size() <= config.max_nodes,
            "bounded graph: node count exceeds max_nodes");
    require(static_cast<std::uint32_t>(graph.edges.size()) <= config.max_total_edges,
            "bounded graph: edge count exceeds max_total_edges");

    std::unordered_map<std::uint64_t, std::uint32_t> per_node_edges;
    for (const auto& edge : graph.edges)
        per_node_edges[edge.source_type_id]++;
    for (const auto& [id, count] : per_node_edges) {
        require(count <= config.max_edges_per_node,
                "bounded graph: per-node edge count exceeds limit");
    }

    require(builder.stats().nodes_bounded > 0, "bounded graph: nodes_bounded not recorded");
    require(builder.stats().edges_bounded > 0, "bounded graph: edges_bounded not recorded");
    require(has_diagnostic(graph, "type_graph.bounded"),
            "bounded graph: diagnostic not emitted");
}

void test_confidence_ordering()
{
    auto entity = native_entity();
    type_graph_builder_config_t config;
    config.preserve_unknowns = true;

    type_graph_builder_t builder(entity, config);

    type_seed_batch_t low_confidence_batch;
    low_confidence_batch.source = decompiler_fact_provenance_t::loader_metadata;
    low_confidence_batch.source_label = "loader_low";

    auto low_candidate = make_candidate("Counter", decompiler_type_kind_t::signed_integer, 8,
                                        decompiler_fact_provenance_t::loader_metadata, 30, entity);
    low_candidate.is_signed = true;
    low_confidence_batch.candidates.push_back(low_candidate);
    builder.add_seed_batch(std::move(low_confidence_batch));

    type_seed_batch_t high_confidence_batch;
    high_confidence_batch.source = decompiler_fact_provenance_t::debug_metadata;
    high_confidence_batch.source_label = "pdb_high";

    auto high_candidate = make_candidate("Counter", decompiler_type_kind_t::signed_integer, 8,
                                         decompiler_fact_provenance_t::debug_metadata, 95, entity);
    high_candidate.is_signed = true;
    high_confidence_batch.candidates.push_back(high_candidate);
    builder.add_seed_batch(std::move(high_confidence_batch));

    auto graph = builder.build();
    const auto validation = validate_type_graph(graph);
    require(validation.valid(), "confidence ordering graph failed validation");

    const auto* node = find_node(graph, "Counter");
    require(node != nullptr, "Counter node missing");
    require(node->provenance == decompiler_fact_provenance_t::debug_metadata,
            "confidence ordering: debug_metadata should win over loader_metadata");
    require(node->confidence == 95,
            "confidence ordering: confidence should be 95 from debug_metadata");

    type_graph_builder_t builder2(entity, config);

    type_seed_batch_t same_source_low;
    same_source_low.source = decompiler_fact_provenance_t::debug_metadata;
    same_source_low.source_label = "pdb_low_conf";
    auto low2 = make_candidate("Timer", decompiler_type_kind_t::signed_integer, 4,
                               decompiler_fact_provenance_t::debug_metadata, 50, entity);
    same_source_low.candidates.push_back(low2);
    builder2.add_seed_batch(std::move(same_source_low));

    type_seed_batch_t same_source_high;
    same_source_high.source = decompiler_fact_provenance_t::debug_metadata;
    same_source_high.source_label = "pdb_high_conf";
    auto high2 = make_candidate("Timer", decompiler_type_kind_t::signed_integer, 4,
                                decompiler_fact_provenance_t::debug_metadata, 90, entity);
    same_source_high.candidates.push_back(high2);
    builder2.add_seed_batch(std::move(same_source_high));

    auto graph2 = builder2.build();
    const auto validation2 = validate_type_graph(graph2);
    require(validation2.valid(), "confidence ordering graph 2 failed validation");

    const auto* node2 = find_node(graph2, "Timer");
    require(node2 != nullptr, "Timer node missing");
    require(node2->confidence == 90,
            "confidence ordering: higher confidence should win within same provenance");

    type_graph_builder_t builder3(entity, config);

    type_seed_batch_t rtti_batch;
    rtti_batch.source = decompiler_fact_provenance_t::rtti;
    rtti_batch.source_label = "rtti";
    auto rtti_candidate = make_candidate("Signal", decompiler_type_kind_t::enumeration, 4,
                                         decompiler_fact_provenance_t::rtti, 100, entity);
    rtti_batch.candidates.push_back(rtti_candidate);
    builder3.add_seed_batch(std::move(rtti_batch));

    type_seed_batch_t user_batch;
    user_batch.source = decompiler_fact_provenance_t::user_overlay;
    user_batch.source_label = "user";
    auto user_candidate = make_candidate("Signal", decompiler_type_kind_t::structure, 16,
                                         decompiler_fact_provenance_t::user_overlay, 10, entity);
    user_batch.candidates.push_back(user_candidate);
    builder3.add_seed_batch(std::move(user_batch));

    auto graph3 = builder3.build();
    const auto validation3 = validate_type_graph(graph3);
    require(validation3.valid(), "confidence ordering graph 3 failed validation");

    const auto* node3 = find_node(graph3, "Signal");
    require(node3 != nullptr, "Signal node missing");
    require(node3->provenance == decompiler_fact_provenance_t::user_overlay,
            "confidence ordering: user_overlay should win over rtti regardless of confidence");
    require(node3->kind == decompiler_type_kind_t::structure,
            "confidence ordering: user_overlay kind should win");
}

void test_unknown_preservation()
{
    auto entity = native_entity();
    type_graph_builder_config_t config;
    config.preserve_unknowns = true;

    type_graph_builder_t builder(entity, config);

    type_seed_batch_t batch;
    batch.source = decompiler_fact_provenance_t::provider_semantics;
    batch.source_label = "provider";

    auto known_type = make_candidate("KnownStruct", decompiler_type_kind_t::structure, 24,
                                     decompiler_fact_provenance_t::provider_semantics, 70, entity);
    known_type.edges.push_back(make_edge(decompiler_type_edge_kind_t::member,
                                         "UnknownType", "field",
                                         decompiler_fact_provenance_t::provider_semantics, 70, 0));
    batch.candidates.push_back(known_type);

    auto unknown_type = make_candidate("OpaqueType", decompiler_type_kind_t::unknown, 0,
                                       decompiler_fact_provenance_t::provider_semantics, 30, entity);
    unknown_type.byte_size.reset();
    batch.candidates.push_back(unknown_type);

    builder.add_seed_batch(std::move(batch));

    auto graph = builder.build();
    const auto validation = validate_type_graph(graph);
    require(validation.valid(), "unknown preservation graph failed validation");

    const auto* opaque_node = find_node(graph, "OpaqueType");
    require(opaque_node != nullptr, "unknown preservation: OpaqueType node missing");
    require(opaque_node->kind == decompiler_type_kind_t::unknown,
            "unknown preservation: OpaqueType should remain unknown");

    const auto* unknown_placeholder = find_node(graph, "unknown.UnknownType");
    require(unknown_placeholder != nullptr,
            "unknown preservation: unresolved UnknownType placeholder node missing");
    require(unknown_placeholder->kind == decompiler_type_kind_t::unknown,
            "unknown preservation: placeholder should be unknown kind");

    require(has_unknown(graph, "UnknownType"),
            "unknown preservation: unresolved reference unknown not recorded");
    require(has_unknown(graph, "OpaqueType"),
            "unknown preservation: OpaqueType unknown not recorded");

    require(builder.stats().unresolved_references > 0,
            "unknown preservation: unresolved_references not counted");
    require(builder.stats().unknowns_preserved > 0,
            "unknown preservation: unknowns_preserved not counted");

    const auto* known_node = find_node(graph, "KnownStruct");
    require(known_node != nullptr, "KnownStruct node missing");
    require(has_edge(graph, known_node->id, unknown_placeholder->id,
                     decompiler_type_edge_kind_t::member, "field"),
            "unknown preservation: KnownStruct->UnknownType edge missing");

    type_graph_builder_config_t no_preserve_config;
    no_preserve_config.preserve_unknowns = false;

    type_graph_builder_t builder2(entity, no_preserve_config);

    type_seed_batch_t batch2;
    batch2.source = decompiler_fact_provenance_t::provider_semantics;
    batch2.source_label = "provider2";
    auto known2 = make_candidate("StructA", decompiler_type_kind_t::structure, 8,
                                 decompiler_fact_provenance_t::provider_semantics, 70, entity);
    known2.edges.push_back(make_edge(decompiler_type_edge_kind_t::member,
                                     "UnresolvedB", "val",
                                     decompiler_fact_provenance_t::provider_semantics, 70, 0));
    batch2.candidates.push_back(known2);
    builder2.add_seed_batch(std::move(batch2));

    auto graph2 = builder2.build();
    const auto validation2 = validate_type_graph(graph2);
    require(validation2.valid(), "no-preserve graph failed validation");

    const auto* placeholder2 = find_node(graph2, "unknown.UnresolvedB");
    require(placeholder2 == nullptr,
            "preserve_unknowns=false should not create placeholder nodes");
}

void test_multi_source_merge()
{
    auto entity = native_entity();
    type_graph_builder_config_t config;
    config.preserve_unknowns = true;

    type_graph_builder_t builder(entity, config);

    type_seed_batch_t pdb_batch;
    pdb_batch.source = decompiler_fact_provenance_t::debug_metadata;
    pdb_batch.source_label = "PDB";
    auto pdb_struct = make_candidate("Widget", decompiler_type_kind_t::structure, 16,
                                     decompiler_fact_provenance_t::debug_metadata, 90, entity);
    pdb_struct.edges.push_back(make_edge(decompiler_type_edge_kind_t::member, "int", "id",
                                         decompiler_fact_provenance_t::debug_metadata, 90, 0));
    pdb_struct.edges.push_back(make_edge(decompiler_type_edge_kind_t::member, "char*", "name",
                                         decompiler_fact_provenance_t::debug_metadata, 90, 8));
    pdb_batch.candidates.push_back(pdb_struct);
    auto pdb_int = make_candidate("int", decompiler_type_kind_t::signed_integer, 4,
                                  decompiler_fact_provenance_t::debug_metadata, 100, entity);
    pdb_int.is_signed = true;
    pdb_batch.candidates.push_back(pdb_int);
    auto pdb_charp = make_candidate("char*", decompiler_type_kind_t::pointer, 8,
                                    decompiler_fact_provenance_t::debug_metadata, 100, entity);
    pdb_charp.edges.push_back(make_edge(decompiler_type_edge_kind_t::pointee, "char", "pointee",
                                        decompiler_fact_provenance_t::debug_metadata, 100));
    pdb_batch.candidates.push_back(pdb_charp);
    auto pdb_char = make_candidate("char", decompiler_type_kind_t::signed_integer, 1,
                                   decompiler_fact_provenance_t::debug_metadata, 100, entity);
    pdb_char.is_signed = true;
    pdb_batch.candidates.push_back(pdb_char);
    builder.add_seed_batch(std::move(pdb_batch));

    type_seed_batch_t call_batch;
    call_batch.source = decompiler_fact_provenance_t::call_signature;
    call_batch.source_label = "call_signatures";
    auto call_widget = make_candidate("Widget", decompiler_type_kind_t::structure, 16,
                                      decompiler_fact_provenance_t::call_signature, 60, entity);
    call_widget.edges.push_back(make_edge(decompiler_type_edge_kind_t::member, "int", "id",
                                          decompiler_fact_provenance_t::call_signature, 60, 0));
    call_batch.candidates.push_back(call_widget);
    builder.add_seed_batch(std::move(call_batch));

    type_seed_batch_t objc_batch;
    objc_batch.source = decompiler_fact_provenance_t::objc_metadata;
    objc_batch.source_label = "objc";
    auto objc_view = make_candidate("UIView", decompiler_type_kind_t::class_type, 64,
                                    decompiler_fact_provenance_t::objc_metadata, 85, entity);
    objc_batch.candidates.push_back(objc_view);
    builder.add_seed_batch(std::move(objc_batch));

    type_seed_batch_t swift_batch;
    swift_batch.source = decompiler_fact_provenance_t::swift_metadata;
    swift_batch.source_label = "swift";
    auto swift_array = make_candidate("Swift.Array", decompiler_type_kind_t::generic_instance, 24,
                                      decompiler_fact_provenance_t::swift_metadata, 85, entity);
    swift_array.edges.push_back(make_edge(decompiler_type_edge_kind_t::generic_argument,
                                          "Element", "Element",
                                          decompiler_fact_provenance_t::swift_metadata, 85, 0));
    swift_batch.candidates.push_back(swift_array);
    builder.add_seed_batch(std::move(swift_batch));

    auto graph = builder.build();
    const auto validation = validate_type_graph(graph);
    require(validation.valid(), "multi-source merge graph failed validation");

    const auto* widget = find_node(graph, "Widget");
    require(widget != nullptr, "multi-source: Widget node missing");
    require(widget->provenance == decompiler_fact_provenance_t::debug_metadata,
            "multi-source: Widget provenance should be debug_metadata");
    require(widget->byte_size.has_value() && *widget->byte_size == 16,
            "multi-source: Widget byte_size should be 16");

    const auto* int_node = find_node(graph, "int");
    require(int_node != nullptr, "multi-source: int node missing");

    const auto* charp_node = find_node(graph, "char*");
    require(charp_node != nullptr, "multi-source: char* node missing");

    const auto* char_node = find_node(graph, "char");
    require(char_node != nullptr, "multi-source: char node missing");

    require(has_edge(graph, widget->id, int_node->id,
                     decompiler_type_edge_kind_t::member, "id"),
            "multi-source: Widget->int member edge missing");
    require(has_edge(graph, widget->id, charp_node->id,
                     decompiler_type_edge_kind_t::member, "name"),
            "multi-source: Widget->char* member edge missing");
    require(has_edge(graph, charp_node->id, char_node->id,
                     decompiler_type_edge_kind_t::pointee, "pointee"),
            "multi-source: char*->char pointee edge missing");

    const auto* uiview = find_node(graph, "UIView");
    require(uiview != nullptr, "multi-source: UIView node missing");
    require(uiview->provenance == decompiler_fact_provenance_t::objc_metadata,
            "multi-source: UIView provenance should be objc_metadata");

    const auto* swift_arr = find_node(graph, "Swift.Array");
    require(swift_arr != nullptr, "multi-source: Swift.Array node missing");
    require(swift_arr->provenance == decompiler_fact_provenance_t::swift_metadata,
            "multi-source: Swift.Array provenance should be swift_metadata");

    const auto* element_placeholder = find_node(graph, "unknown.Element");
    require(element_placeholder != nullptr,
            "multi-source: Element generic argument placeholder missing");

    require(has_edge(graph, swift_arr->id, element_placeholder->id,
                     decompiler_type_edge_kind_t::generic_argument, "Element"),
            "multi-source: Swift.Array->Element generic_argument edge missing");

    std::uint32_t prev_ordinal = 0;
    for (const auto& edge : graph.edges) {
        require(edge.ordinal > prev_ordinal, "multi-source: edge ordinals not strictly increasing");
        prev_ordinal = edge.ordinal;
    }

    std::uint64_t prev_id = 0;
    for (const auto& node : graph.nodes) {
        require(node.id > prev_id, "multi-source: node IDs not strictly increasing");
        prev_id = node.id;
    }

    std::uint32_t prev_diag = 0;
    for (const auto& diag : graph.diagnostics) {
        require(diag.ordinal > prev_diag, "multi-source: diagnostic ordinals not strictly increasing");
        prev_diag = diag.ordinal;
    }
}

}

void run_type_graph_harness()
{
    test_conflict_and_recursive_types();
    test_no_silent_overwrite();
    test_stable_ids();
    test_bounded_graph();
    test_confidence_ordering();
    test_unknown_preservation();
    test_multi_source_merge();
}

}

int main()
{
    try {
        aida::analysis::c03_test::run_type_graph_harness();
        std::cout << "type_graph_harness: all fixtures satisfied\n";
        return 0;
    } catch (const std::exception& error) {
		aida::analysis::c03_test::assertion_telemetry::record_exception(error.what());
        std::cerr << "type_graph_harness FAILED: " << error.what() << '\n';
        return 1;
    }
}
