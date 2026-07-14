#include "type_graph_builder.hpp"

#include <algorithm>
#include <functional>
#include <limits>
#include <map>
#include <new>
#include <set>
#include <sstream>
#include <tuple>
#include <unordered_set>

namespace aida::analysis::type_graph {

namespace {

std::string edge_stable_name(const type_edge_candidate_t& edge)
{
    if (!edge.stable_name.empty())
        return edge.stable_name;
    switch (edge.kind) {
    case decompiler_type_edge_kind_t::pointee:
        return "pointee";
    case decompiler_type_edge_kind_t::element:
        return "element";
    case decompiler_type_edge_kind_t::return_type:
        return "return";
    case decompiler_type_edge_kind_t::base:
        return "base";
    case decompiler_type_edge_kind_t::alias:
        return "alias";
    case decompiler_type_edge_kind_t::constraint:
        return "constraint";
    case decompiler_type_edge_kind_t::member:
        return "member";
    case decompiler_type_edge_kind_t::parameter:
        return "parameter";
    case decompiler_type_edge_kind_t::generic_argument:
        return "generic_argument";
    }
    return "edge";
}

std::string kind_label(decompiler_type_kind_t kind)
{
    switch (kind) {
    case decompiler_type_kind_t::unknown:
        return "unknown";
    case decompiler_type_kind_t::void_type:
        return "void";
    case decompiler_type_kind_t::boolean:
        return "boolean";
    case decompiler_type_kind_t::signed_integer:
        return "signed_integer";
    case decompiler_type_kind_t::unsigned_integer:
        return "unsigned_integer";
    case decompiler_type_kind_t::floating_point:
        return "floating_point";
    case decompiler_type_kind_t::pointer:
        return "pointer";
    case decompiler_type_kind_t::reference:
        return "reference";
    case decompiler_type_kind_t::array:
        return "array";
    case decompiler_type_kind_t::vector:
        return "vector";
    case decompiler_type_kind_t::structure:
        return "structure";
    case decompiler_type_kind_t::union_type:
        return "union";
    case decompiler_type_kind_t::enumeration:
        return "enumeration";
    case decompiler_type_kind_t::function:
        return "function";
    case decompiler_type_kind_t::class_type:
        return "class";
    case decompiler_type_kind_t::interface_type:
        return "interface";
    case decompiler_type_kind_t::generic_parameter:
        return "generic_parameter";
    case decompiler_type_kind_t::generic_instance:
        return "generic_instance";
    case decompiler_type_kind_t::managed_by_reference:
        return "managed_by_reference";
    }
    return "unknown";
}

std::string size_string(std::optional<std::uint64_t> size)
{
    if (!size)
        return "<absent>";
    std::ostringstream ss;
    ss << *size;
    return ss.str();
}

std::string bool_string(bool value)
{
    return value ? "true" : "false";
}

type_provenance_record_t to_provenance_record(const type_candidate_t& candidate)
{
    type_provenance_record_t record;
    record.source = candidate.provenance;
    record.confidence = candidate.confidence;
    record.source_detail = candidate.source_detail;
    record.coordinate = candidate.coordinate;
    return record;
}

type_provenance_record_t to_provenance_record(const type_edge_candidate_t& edge)
{
    type_provenance_record_t record;
    record.source = edge.provenance;
    record.confidence = edge.confidence;
    record.source_detail = edge.source_detail;
    return record;
}

}

type_graph_builder_t::type_graph_builder_t(decompiler_entity_key_t entity, type_graph_builder_config_t config)
    : entity_(std::move(entity))
    , config_(std::move(config))
{
}

void type_graph_builder_t::add_seed_batch(type_seed_batch_t batch)
{
    stats_.total_candidates += static_cast<std::uint32_t>(batch.candidates.size());
    batches_.push_back(std::move(batch));
}

source_coordinate_t type_graph_builder_t::make_coordinate(std::uint64_t address_value) const
{
    source_coordinate_t coordinate;
    coordinate.layer = decompiler_coordinate_layer_t::hir;
    coordinate.workspace_generation = 1;
    coordinate.entity = entity_;
    decompiler_address_range_t range;
    range.begin.space = address_space_id_t::relative_virtual;
    range.begin.value = address_value;
    range.begin.architecture = entity_.architecture;
    range.begin.mode = entity_.mode;
    range.end = range.begin;
    range.end.value = address_value + 1;
    coordinate.address_range = range;
    return coordinate;
}

void type_graph_builder_t::merge_field_conflict(
    const std::string& canonical_name, const std::string& field_name,
    const std::string& resolved, const std::string& rejected,
    const type_provenance_record_t& resolved_prov,
    const type_provenance_record_t& rejected_prov)
{
    if (!config_.strict_conflict_reporting && rejected_prov.source == decompiler_fact_provenance_t::unknown)
        return;
    type_conflict_record_t conflict;
    conflict.canonical_name = canonical_name;
    conflict.field_name = field_name;
    conflict.resolved_value = resolved;
    conflict.rejected_value = rejected;
    conflict.resolved_provenance = resolved_prov;
    conflict.rejected_provenance = rejected_prov;
    conflicts_.push_back(std::move(conflict));
    stats_.conflicts++;
}

void type_graph_builder_t::merge_candidates(const std::vector<type_candidate_t>& candidates, merged_node_t& merged)
{
    const type_candidate_t* winner = nullptr;
    type_provenance_record_t winner_record{};

    for (const auto& candidate : candidates) {
        auto candidate_record = to_provenance_record(candidate);

        provenance_.record(merged.canonical_name, "kind",
                           type_provenance_record_t{candidate.provenance, candidate.confidence, candidate.source_detail, candidate.coordinate});

        if (candidate.byte_size) {
            provenance_.record(merged.canonical_name, "byte_size",
                               type_provenance_record_t{candidate.provenance, candidate.confidence, candidate.source_detail, candidate.coordinate});
        }
        if (candidate.alignment > 0) {
            provenance_.record(merged.canonical_name, "alignment",
                               type_provenance_record_t{candidate.provenance, candidate.confidence, candidate.source_detail, candidate.coordinate});
        }

        merged.provenance_records.push_back(candidate_record);
        merged.coordinates.push_back(candidate.coordinate);

        if (!winner || strictly_higher(candidate_record, winner_record)) {
            winner = &candidate;
            winner_record = candidate_record;
        }
    }

    if (!winner)
        return;

    merged.kind = winner->kind;
    merged.confidence = winner->confidence;
    merged.provenance = winner->provenance;
    if (winner->display_name.empty())
        merged.display_name = merged.canonical_name;
    else
        merged.display_name = winner->display_name;
    merged.byte_size = winner->byte_size;
    merged.alignment = winner->alignment;
    merged.is_signed = winner->is_signed;

    for (const auto& candidate : candidates) {
        if (&candidate == winner)
            continue;

        auto candidate_record = to_provenance_record(candidate);

        if (candidate.kind != winner->kind && candidate.kind != decompiler_type_kind_t::unknown) {
            merge_field_conflict(merged.canonical_name, "kind",
                                kind_label(winner->kind), kind_label(candidate.kind),
                                winner_record, candidate_record);
        }

        if (candidate.byte_size && winner->byte_size &&
            *candidate.byte_size != *winner->byte_size) {
            merge_field_conflict(merged.canonical_name, "byte_size",
                                size_string(winner->byte_size), size_string(candidate.byte_size),
                                winner_record, candidate_record);
        }

        if (candidate.alignment != winner->alignment && candidate.alignment > 0) {
            std::ostringstream lhs_ss, rhs_ss;
            lhs_ss << winner->alignment;
            rhs_ss << candidate.alignment;
            merge_field_conflict(merged.canonical_name, "alignment",
                                lhs_ss.str(), rhs_ss.str(),
                                winner_record, candidate_record);
        }

        if (candidate.is_signed != winner->is_signed) {
            merge_field_conflict(merged.canonical_name, "is_signed",
                                bool_string(winner->is_signed), bool_string(candidate.is_signed),
                                winner_record, candidate_record);
        }

        if (!candidate.display_name.empty() && candidate.display_name != winner->display_name) {
            merge_field_conflict(merged.canonical_name, "display_name",
                                winner->display_name, candidate.display_name,
                                winner_record, candidate_record);
        }
    }

    for (const auto& candidate : candidates)
        merge_edges(merged, candidate);
}

void type_graph_builder_t::merge_edges(merged_node_t& merged, const type_candidate_t& candidate)
{
    for (const auto& edge : candidate.edges) {
        bool found_duplicate = false;
        for (auto& existing : merged.edges) {
            if (existing.kind == edge.kind &&
                existing.target_canonical_name == edge.target_canonical_name &&
                edge_stable_name(existing) == edge_stable_name(edge)) {
                found_duplicate = true;
                auto existing_score = effective_score(to_provenance_record(existing));
                auto incoming_score = effective_score(to_provenance_record(edge));
                if (incoming_score > existing_score) {
                    if (config_.strict_conflict_reporting ||
                        to_provenance_record(existing).source != decompiler_fact_provenance_t::unknown) {
                        provenance_conflict_t econflict;
                        econflict.canonical_name = merged.canonical_name;
                        econflict.field_name = edge_stable_name(edge);
                        econflict.winner = to_provenance_record(edge);
                        econflict.loser = to_provenance_record(existing);
                        econflict.winner_value = edge.target_canonical_name;
                        econflict.loser_value = existing.target_canonical_name;
                        edge_conflicts_.push_back(std::move(econflict));
                        stats_.conflicts++;
                    }
                    existing = edge;
                }
                break;
            }
        }
        if (!found_duplicate) {
            merged.edges.push_back(edge);
        }
    }
}

void type_graph_builder_t::detect_recursive_types(std::unordered_map<std::string, merged_node_t>& merged_nodes)
{
    for (auto& [name, node] : merged_nodes) {
        std::unordered_set<std::string> visited;
        std::function<bool(const std::string&, std::uint32_t)> check_recursive = [&](const std::string& current, std::uint32_t depth) -> bool {
            if (depth >= config_.max_recursion_depth)
                return false;
            if (visited.count(current))
                return current == name;
            visited.insert(current);
            auto it = merged_nodes.find(current);
            if (it == merged_nodes.end())
                return false;
            for (const auto& edge : it->second.edges) {
                if (edge.kind == decompiler_type_edge_kind_t::pointee ||
                    edge.kind == decompiler_type_edge_kind_t::member ||
                    edge.kind == decompiler_type_edge_kind_t::base ||
                    edge.kind == decompiler_type_edge_kind_t::element) {
                    if (edge.target_canonical_name == name)
                        return true;
                    if (check_recursive(edge.target_canonical_name, depth + 1))
                        return true;
                }
            }
            return false;
        };

        if (check_recursive(name, 0)) {
            node.is_recursive = true;
            stats_.recursive_types++;
        }
    }
}

void type_graph_builder_t::assign_stable_ids(
    std::unordered_map<std::string, merged_node_t>& merged_nodes,
    std::vector<std::string>& sorted_names) const
{
    sorted_names.clear();
    sorted_names.reserve(merged_nodes.size());
    for (const auto& [name, node] : merged_nodes) {
        if (!node.is_unknown_placeholder)
            sorted_names.push_back(name);
    }

    std::sort(sorted_names.begin(), sorted_names.end());

    std::uint64_t next_id = 1;
    for (const auto& name : sorted_names) {
        merged_nodes[name].assigned_id = next_id++;
    }

    std::vector<std::string> placeholder_names;
    for (const auto& [name, node] : merged_nodes) {
        if (node.is_unknown_placeholder)
            placeholder_names.push_back(name);
    }
    std::sort(placeholder_names.begin(), placeholder_names.end());

    for (const auto& name : placeholder_names) {
        if (next_id > config_.max_nodes)
            break;
        merged_nodes[name].assigned_id = next_id++;
    }
}

void type_graph_builder_t::resolve_edges(
    const std::unordered_map<std::string, merged_node_t>& merged_nodes,
    std::vector<merged_edge_t>& resolved_edges,
    std::vector<decompiler_unknown_t>& unknowns)
{
    for (const auto& [name, node] : merged_nodes) {
        if (node.assigned_id == 0)
            continue;

        for (const auto& edge : node.edges) {
            auto target_it = merged_nodes.find(edge.target_canonical_name);
            std::uint64_t target_id = 0;

            if (target_it != merged_nodes.end() && target_it->second.assigned_id != 0) {
                target_id = target_it->second.assigned_id;
            } else {
                stats_.unresolved_references++;
                if (config_.preserve_unknowns) {
                    auto unknown = make_unknown(edge.target_canonical_name,
                                                decompiler_unknown_reason_t::unresolved_reference,
                                                edge.confidence, edge.provenance);
                    unknowns.push_back(unknown);
                    stats_.unknowns_preserved++;
                }
            }

            if (target_id == 0)
                continue;

            merged_edge_t resolved;
            resolved.source_id = node.assigned_id;
            resolved.target_id = target_id;
            resolved.kind = edge.kind;
            resolved.stable_name = edge_stable_name(edge);
            resolved.byte_offset = edge.byte_offset;
            resolved.confidence = edge.confidence;
            resolved.provenance = edge.provenance;
            resolved_edges.push_back(resolved);
        }
    }
}

void type_graph_builder_t::enforce_bounds(
    std::vector<merged_node_t>& nodes,
    std::vector<merged_edge_t>& edges,
    std::vector<decompiler_unknown_t>& unknowns)
{
    if (nodes.size() > config_.max_nodes) {
        std::uint32_t excess = static_cast<std::uint32_t>(nodes.size()) - config_.max_nodes;
        stats_.nodes_bounded += excess;
        nodes.resize(config_.max_nodes);

        std::set<std::uint64_t> valid_ids;
        for (const auto& node : nodes)
            valid_ids.insert(node.assigned_id);

        std::vector<merged_edge_t> filtered_edges;
        filtered_edges.reserve(edges.size());
        for (const auto& edge : edges) {
            if (valid_ids.count(edge.source_id) && valid_ids.count(edge.target_id))
                filtered_edges.push_back(edge);
            else
                stats_.edges_bounded++;
        }
        edges = std::move(filtered_edges);
    }

    std::unordered_map<std::uint64_t, std::uint32_t> edge_counts;
    for (const auto& edge : edges)
        edge_counts[edge.source_id]++;

    std::vector<merged_edge_t> bounded_edges;
    bounded_edges.reserve(edges.size());
    std::unordered_map<std::uint64_t, std::uint32_t> per_node_count;

    for (const auto& edge : edges) {
        if (per_node_count[edge.source_id] >= config_.max_edges_per_node) {
            stats_.edges_bounded++;
            continue;
        }
        if (bounded_edges.size() >= config_.max_total_edges) {
            stats_.edges_bounded++;
            break;
        }
        bounded_edges.push_back(edge);
        per_node_count[edge.source_id]++;
    }
    edges = std::move(bounded_edges);

    if (unknowns.size() > config_.max_nodes) {
        unknowns.resize(config_.max_nodes);
    }
}

decompiler_unknown_t type_graph_builder_t::make_unknown(
    const std::string& token,
    decompiler_unknown_reason_t reason,
    std::uint8_t confidence,
    decompiler_fact_provenance_t provenance) const
{
    decompiler_unknown_t unknown;
    unknown.reason = reason;
    unknown.stable_token = token;
    unknown.coordinate = make_coordinate(0);
    unknown.confidence = std::min(confidence, static_cast<std::uint8_t>(100));
    unknown.provenance = provenance;
    return unknown;
}

decompiler_diagnostic_t type_graph_builder_t::make_diagnostic(
    decompiler_diagnostic_severity_t severity,
    decompiler_diagnostic_code_t code,
    const std::string& key,
    std::uint32_t ordinal,
    std::uint8_t confidence) const
{
    decompiler_diagnostic_t diagnostic;
    diagnostic.severity = severity;
    diagnostic.code = code;
    diagnostic.localization_key = key;
    diagnostic.confidence = std::min(confidence, static_cast<std::uint8_t>(100));
    diagnostic.retryable = false;
    diagnostic.ordinal = ordinal;
    return diagnostic;
}

void type_graph_builder_t::emit_diagnostics(type_graph_t& graph, std::uint32_t& ordinal_counter)
{
    for (const auto& conflict : conflicts_) {
        std::ostringstream ss;
        ss << "type_graph.conflict." << conflict.canonical_name << "." << conflict.field_name;
        auto diagnostic = make_diagnostic(
            decompiler_diagnostic_severity_t::warning,
            decompiler_diagnostic_code_t::malformed_type_graph,
            ss.str(),
            ++ordinal_counter,
            conflict.resolved_provenance.confidence);
        diagnostic.localization_arguments = {
            conflict.canonical_name,
            conflict.field_name,
            conflict.resolved_value,
            conflict.rejected_value,
            provenance_label(conflict.resolved_provenance.source),
            provenance_label(conflict.rejected_provenance.source),
        };
        graph.diagnostics.push_back(diagnostic);
    }

    for (const auto& conflict : edge_conflicts_) {
        std::ostringstream ss;
        ss << "type_graph.edge_conflict." << conflict.canonical_name << "." << conflict.field_name;
        auto diagnostic = make_diagnostic(
            decompiler_diagnostic_severity_t::note,
            decompiler_diagnostic_code_t::malformed_type_graph,
            ss.str(),
            ++ordinal_counter,
            conflict.winner.confidence);
        diagnostic.localization_arguments = {
            conflict.canonical_name,
            conflict.field_name,
            conflict.winner_value,
            conflict.loser_value,
            provenance_label(conflict.winner.source),
            provenance_label(conflict.loser.source),
        };
        graph.diagnostics.push_back(diagnostic);
    }

    if (stats_.nodes_bounded > 0) {
        auto diagnostic = make_diagnostic(
            decompiler_diagnostic_severity_t::warning,
            decompiler_diagnostic_code_t::resource_limit,
            "type_graph.bounded.nodes",
            ++ordinal_counter,
            100);
        std::ostringstream ss;
        ss << stats_.nodes_bounded;
        diagnostic.localization_arguments = {ss.str()};
        graph.diagnostics.push_back(diagnostic);
    }

    if (stats_.edges_bounded > 0) {
        auto diagnostic = make_diagnostic(
            decompiler_diagnostic_severity_t::warning,
            decompiler_diagnostic_code_t::resource_limit,
            "type_graph.bounded.edges",
            ++ordinal_counter,
            100);
        std::ostringstream ss;
        ss << stats_.edges_bounded;
        diagnostic.localization_arguments = {ss.str()};
        graph.diagnostics.push_back(diagnostic);
    }

    if (stats_.unresolved_references > 0) {
        auto diagnostic = make_diagnostic(
            decompiler_diagnostic_severity_t::note,
            decompiler_diagnostic_code_t::unresolved_type,
            "type_graph.unresolved_references",
            ++ordinal_counter,
            50);
        std::ostringstream ss;
        ss << stats_.unresolved_references;
        diagnostic.localization_arguments = {ss.str()};
        graph.diagnostics.push_back(diagnostic);
    }
}

type_graph_t type_graph_builder_t::build()
{
    std::unordered_map<std::string, std::vector<std::pair<std::size_t, std::size_t>>> name_to_candidates;
    for (std::size_t batch_idx = 0; batch_idx < batches_.size(); ++batch_idx) {
        for (std::size_t cand_idx = 0; cand_idx < batches_[batch_idx].candidates.size(); ++cand_idx) {
            const auto& candidate = batches_[batch_idx].candidates[cand_idx];
            if (candidate.canonical_name.empty())
                continue;
            name_to_candidates[candidate.canonical_name].emplace_back(batch_idx, cand_idx);
        }
    }

    std::unordered_map<std::string, merged_node_t> merged_nodes;
    for (const auto& [name, indices] : name_to_candidates) {
        std::vector<type_candidate_t> candidates;
        candidates.reserve(indices.size());
        for (const auto& [batch_idx, cand_idx] : indices)
            candidates.push_back(batches_[batch_idx].candidates[cand_idx]);

        merged_node_t merged;
        merged.canonical_name = name;
        merge_candidates(candidates, merged);

        if (merged.display_name.empty())
            merged.display_name = name;

        merged_nodes[name] = std::move(merged);
    }

    detect_recursive_types(merged_nodes);

    for (const auto& [name, node] : merged_nodes) {
        for (const auto& edge : node.edges) {
            if (merged_nodes.find(edge.target_canonical_name) == merged_nodes.end()) {
                if (config_.preserve_unknowns) {
                    std::string placeholder_name = "unknown." + edge.target_canonical_name;
                    if (merged_nodes.find(placeholder_name) == merged_nodes.end()) {
                        merged_node_t placeholder;
                        placeholder.canonical_name = placeholder_name;
                        placeholder.display_name = edge.target_canonical_name;
                        placeholder.kind = decompiler_type_kind_t::unknown;
                        placeholder.is_unknown_placeholder = true;
                        placeholder.confidence = edge.confidence;
                        placeholder.provenance = edge.provenance;
                        merged_nodes[placeholder_name] = std::move(placeholder);
                    }
                }
            }
        }
    }

    std::vector<std::string> sorted_names;
    assign_stable_ids(merged_nodes, sorted_names);

    std::vector<merged_edge_t> resolved_edges;
    std::vector<decompiler_unknown_t> unknowns;
    resolve_edges(merged_nodes, resolved_edges, unknowns);

    std::vector<merged_node_t> node_list;
    for (const auto& name : sorted_names) {
        auto it = merged_nodes.find(name);
        if (it == merged_nodes.end() || it->second.assigned_id == 0)
            continue;
        node_list.push_back(it->second);
    }

    for (auto& [name, node] : merged_nodes) {
        if (node.is_unknown_placeholder && node.assigned_id != 0) {
            bool already_present = false;
            for (const auto& existing : node_list) {
                if (existing.assigned_id == node.assigned_id) {
                    already_present = true;
                    break;
                }
            }
            if (!already_present)
                node_list.push_back(node);
        }
    }

    for (auto& node : node_list) {
        if (node.coordinates.empty())
            node.coordinates.push_back(make_coordinate(0));
    }

    std::sort(node_list.begin(), node_list.end(),
              [](const merged_node_t& a, const merged_node_t& b) { return a.assigned_id < b.assigned_id; });

    std::sort(resolved_edges.begin(), resolved_edges.end(),
              [](const merged_edge_t& a, const merged_edge_t& b) {
                  if (a.source_id != b.source_id)
                      return a.source_id < b.source_id;
                  if (a.kind != b.kind)
                      return static_cast<std::uint8_t>(a.kind) < static_cast<std::uint8_t>(b.kind);
                  return a.stable_name < b.stable_name;
              });

    enforce_bounds(node_list, resolved_edges, unknowns);

    type_graph_t graph;
    graph.schema_version = k_type_graph_schema_version;
    graph.entity = entity_;
    graph.revision = 1;

    for (const auto& merged : node_list) {
        decompiler_type_node_t node;
        node.id = merged.assigned_id;
        node.kind = merged.kind;
        node.canonical_name = merged.canonical_name;
        node.display_name = merged.display_name;
        if (merged.byte_size && *merged.byte_size != 0)
            node.byte_size = merged.byte_size;
        else
            node.byte_size.reset();
        node.alignment = merged.alignment;
        node.is_signed = merged.is_signed;
        node.confidence = std::min(merged.confidence, static_cast<std::uint8_t>(100));
        node.provenance = merged.provenance;
        for (const auto& coord : merged.coordinates) {
            source_coordinate_t fixed_coord = coord;
            fixed_coord.entity = entity_;
            if (fixed_coord.workspace_generation == 0)
                fixed_coord.workspace_generation = 1;
            if (!fixed_coord.address_range && !fixed_coord.token_range &&
                !fixed_coord.instruction_range && !fixed_coord.document_range &&
                !fixed_coord.source_origin) {
                fixed_coord = make_coordinate(0);
            }
            node.coordinates.push_back(fixed_coord);
        }
        if (node.coordinates.empty())
            node.coordinates.push_back(make_coordinate(0));
        graph.nodes.push_back(node);
    }

    std::uint32_t global_ordinal = 0;
    for (const auto& resolved : resolved_edges) {
        decompiler_type_edge_t edge;
        edge.source_type_id = resolved.source_id;
        edge.target_type_id = resolved.target_id;
        edge.kind = resolved.kind;
        edge.stable_name = resolved.stable_name;
        edge.byte_offset = resolved.byte_offset;
        edge.ordinal = ++global_ordinal;
        edge.confidence = std::min(resolved.confidence, static_cast<std::uint8_t>(100));
        edge.provenance = resolved.provenance;
        graph.edges.push_back(edge);
    }

    stats_.total_edges = static_cast<std::uint32_t>(graph.edges.size());
    stats_.unique_types = static_cast<std::uint32_t>(graph.nodes.size());

    for (const auto& merged : node_list) {
        if (merged.kind == decompiler_type_kind_t::unknown && config_.preserve_unknowns) {
            auto unknown = make_unknown(merged.canonical_name,
                                        decompiler_unknown_reason_t::incomplete_debug_information,
                                        merged.confidence, merged.provenance);
            unknowns.push_back(unknown);
            stats_.unknowns_preserved++;
        }
    }

    std::set<std::string> seen_unknowns;
    for (const auto& unknown : unknowns) {
        if (seen_unknowns.insert(unknown.stable_token).second)
            graph.unknowns.push_back(unknown);
    }

    std::uint32_t diagnostic_ordinal = 0;
    emit_diagnostics(graph, diagnostic_ordinal);

    return graph;
}

workspace_result_t<type_graph_t> merge_type_evidence(
    type_graph_t provider_graph,
    std::vector<type_seed_batch_t> evidence,
    const type_graph_builder_config_t& config)
{
    const auto invalid = [](std::string message) {
        return workspace_result_t<type_graph_t>::failure(make_workspace_error(
            workspace_error_code_t::integrity_failure, std::move(message),
            "decompiler.type_graph.merge"));
    };
    if (!validate_type_graph(provider_graph).valid())
        return invalid("provider type graph is invalid");
    if (evidence.empty())
        return workspace_result_t<type_graph_t>::success(std::move(provider_graph));
    try {
        std::unordered_map<std::uint64_t, const decompiler_type_node_t*> source_nodes;
        source_nodes.reserve(provider_graph.nodes.size());
        for (const auto& node : provider_graph.nodes)
            source_nodes.emplace(node.id, &node);
        type_seed_batch_t provider_seed;
        provider_seed.source = decompiler_fact_provenance_t::provider_semantics;
        provider_seed.source_label = "provider_type_graph";
        provider_seed.candidates.reserve(provider_graph.nodes.size());
        for (const auto& node : provider_graph.nodes) {
            type_candidate_t candidate;
            candidate.kind = node.kind;
            candidate.canonical_name = node.canonical_name;
            candidate.display_name = node.display_name;
            candidate.byte_size = node.byte_size;
            candidate.alignment = node.alignment;
            candidate.is_signed = node.is_signed;
            candidate.confidence = node.confidence;
            candidate.provenance = node.provenance;
            candidate.source_detail = "provider_type_graph";
            if (!node.coordinates.empty())
                candidate.coordinate = node.coordinates.front();
            for (const auto& edge : provider_graph.edges) {
                if (edge.source_type_id != node.id)
                    continue;
                const auto target = source_nodes.find(edge.target_type_id);
                if (target == source_nodes.end())
                    return invalid("provider type graph edge target is absent");
                type_edge_candidate_t converted;
                converted.kind = edge.kind;
                converted.target_canonical_name = target->second->canonical_name;
                converted.stable_name = edge.stable_name;
                converted.byte_offset = edge.byte_offset;
                converted.local_ordinal = edge.ordinal;
                converted.confidence = edge.confidence;
                converted.provenance = edge.provenance;
                converted.source_detail = "provider_type_graph";
                candidate.edges.push_back(std::move(converted));
            }
            provider_seed.candidates.push_back(std::move(candidate));
        }
        type_graph_builder_t builder(provider_graph.entity, config);
        builder.add_seed_batch(std::move(provider_seed));
        for (auto& batch : evidence)
            builder.add_seed_batch(std::move(batch));
        auto merged = builder.build();
        if (!validate_type_graph(merged).valid())
            return invalid("merged evidence graph is invalid");

        std::unordered_map<std::string, std::uint64_t> retained_ids;
        retained_ids.reserve(provider_graph.nodes.size());
        std::uint64_t next_id = 1;
        for (const auto& node : provider_graph.nodes) {
            if (!retained_ids.emplace(node.canonical_name, node.id).second)
                return invalid("provider type graph contains duplicate canonical identities");
            if (node.id == (std::numeric_limits<std::uint64_t>::max)())
                return invalid("provider type graph exhausted the type identifier space");
            next_id = (std::max)(next_id, node.id + 1);
        }
        std::unordered_map<std::uint64_t, std::uint64_t> remap;
        remap.reserve(merged.nodes.size());
        for (auto& node : merged.nodes) {
            const auto retained = retained_ids.find(node.canonical_name);
            std::uint64_t id = 0;
            if (retained == retained_ids.end()) {
                if (next_id == 0 || next_id == (std::numeric_limits<std::uint64_t>::max)())
                    return invalid("merged type graph exhausted the type identifier space");
                id = next_id++;
            } else {
                id = retained->second;
            }
            remap.emplace(node.id, id);
            node.id = id;
        }
        for (auto& edge : merged.edges) {
            const auto source = remap.find(edge.source_type_id);
            const auto target = remap.find(edge.target_type_id);
            if (source == remap.end() || target == remap.end())
                return invalid("merged evidence edge cannot be remapped");
            edge.source_type_id = source->second;
            edge.target_type_id = target->second;
        }
        std::sort(merged.nodes.begin(), merged.nodes.end(), [](const auto& left, const auto& right) {
            return left.id < right.id;
        });
        std::sort(merged.edges.begin(), merged.edges.end(), [](const auto& left, const auto& right) {
            return std::tie(left.ordinal, left.source_type_id, left.target_type_id,
                       left.kind, left.stable_name) <
                   std::tie(right.ordinal, right.source_type_id, right.target_type_id,
                       right.kind, right.stable_name);
        });
        merged.revision = provider_graph.revision;
        if (!validate_type_graph(merged).valid())
            return invalid("remapped evidence graph is invalid");
        return workspace_result_t<type_graph_t>::success(std::move(merged));
    } catch (const std::bad_alloc&) {
        return workspace_result_t<type_graph_t>::failure(make_workspace_error(
            workspace_error_code_t::limit_exceeded,
            "type evidence merge allocation failed", "decompiler.type_graph.merge"));
    } catch (...) {
        return invalid("type evidence merge failed");
    }
}

}
