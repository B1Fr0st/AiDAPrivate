#include "graph_document.hpp"

#include <algorithm>
#include <limits>
#include <utility>

namespace aida {
namespace workbench {
namespace graph_document {
namespace {

constexpr std::uint64_t k_fnv_offset = 14695981039346656037ULL;
constexpr std::uint64_t k_fnv_prime = 1099511628211ULL;

std::uint64_t fnv1a(std::uint64_t value) noexcept
{
    std::uint64_t hash = k_fnv_offset;
    for (int shift = 0; shift < 64; shift += 8) {
        const auto byte = static_cast<std::uint8_t>((value >> shift) & 0xFF);
        hash ^= byte;
        hash *= k_fnv_prime;
    }
    return hash;
}

void fnv1a_append(std::uint64_t value, std::uint64_t& hash) noexcept
{
    for (int shift = 0; shift < 64; shift += 8) {
        hash ^= static_cast<std::uint8_t>((value >> shift) & 0xFF);
        hash *= k_fnv_prime;
    }
}

bool cancellation_requested(const graph_cancellation_t* cancellation) noexcept
{
    return cancellation != nullptr && cancellation->cancelled();
}

bool graph_kind_valid(graph_kind_t kind) noexcept
{
    return kind <= graph_kind_t::custom;
}

bool graph_node_kind_valid(graph_node_kind_t kind) noexcept
{
    return kind <= graph_node_kind_t::unknown;
}

bool graph_edge_kind_valid(graph_edge_kind_t kind) noexcept
{
    return kind <= graph_edge_kind_t::data_reference;
}

bool graph_node_valid(const graph_node_view_t& node) noexcept
{
    return node.id.valid() && graph_node_kind_valid(node.kind) &&
           node.label.size() <= k_graph_document_max_label_bytes;
}

bool graph_edge_valid(const graph_edge_view_t& edge) noexcept
{
    if (!edge.id.valid() || edge.label.size() > k_graph_document_max_label_bytes)
        return false;
    return graph_edge_identity_valid({edge.source, edge.target, edge.kind,
                                      edge.site_address, edge.parallel_ordinal});
}

}

graph_node_id_t compute_deterministic_node_id(std::uint64_t address) noexcept
{
    if (address == 0)
        return {};
    const auto hash = fnv1a(address);
    if (hash == 0)
        return {1};
    return {hash};
}

bool graph_edge_identity_valid(const graph_edge_identity_t& identity) noexcept
{
    return identity.source.valid() && identity.target.valid() &&
           graph_edge_kind_valid(identity.kind);
}

graph_edge_id_t compute_deterministic_edge_id(
    const graph_edge_identity_t& identity) noexcept
{
    if (!graph_edge_identity_valid(identity))
        return {};
    std::uint64_t hash = k_fnv_offset;
    fnv1a_append(identity.source.value, hash);
    fnv1a_append(identity.target.value, hash);
    fnv1a_append(static_cast<std::uint64_t>(identity.kind), hash);
    fnv1a_append(identity.site_address, hash);
    fnv1a_append(identity.parallel_ordinal, hash);
    if (hash == 0)
        return {1};
    return {hash};
}

bool graph_page_request_valid(const graph_page_request_t& request) noexcept
{
    return request.limit != 0 && request.limit <= k_graph_document_max_page_size &&
           graph_kind_valid(request.graph_kind);
}

bool graph_layout_request_valid(const graph_layout_request_t& request) noexcept
{
    if (request.max_nodes == 0 || request.max_nodes > k_graph_document_max_layout_nodes)
        return false;
    if (request.max_edges == 0 || request.max_edges > k_graph_document_max_layout_edges)
        return false;
    if (request.max_iterations == 0 || request.max_iterations > k_graph_document_max_layout_iterations)
        return false;
    if (!graph_kind_valid(request.graph_kind))
        return false;
    if (request.canvas_width <= 0.0f || request.canvas_height <= 0.0f)
        return false;
    return true;
}

bool graph_selection_valid(const graph_selection_t& selection) noexcept
{
    if (selection.kind == selection_kind_t::none)
        return !selection.has_address && selection.address == 0 &&
               !selection.node.valid() && !selection.edge.valid();
    if (selection.kind == selection_kind_t::address)
        return selection.has_address && selection.address != 0 &&
               !selection.edge.valid();
    if (selection.kind == selection_kind_t::entity) {
        return selection.node.valid() != selection.edge.valid() &&
               (selection.has_address ? selection.address != 0
                                      : selection.address == 0);
    }
    return false;
}

graph_error_t graph_document_model_t::fail(graph_error_code_t code,
                                             std::uint64_t subject) const noexcept
{
    return {code, subject};
}

graph_error_t graph_document_model_t::stale() const noexcept
{
    return {graph_error_code_t::stale_generation, bound_generation_};
}

graph_document_model_t::graph_document_model_t(
    const graph_source_adapter_t& source,
    const graph_overlay_adapter_t* overlays) noexcept
    : source_(&source)
    , overlays_(overlays)
    , bound_generation_(source.current_generation())
{
}

graph_error_t graph_document_model_t::page(
    const graph_page_request_t& request,
    const graph_cancellation_t* cancellation,
    graph_page_t& output) const
{
    output = {};
    if (!graph_page_request_valid(request))
        return fail(graph_error_code_t::invalid_page, request.limit);

    const auto gen = bound_generation_;
    if (!source_->generation_current(gen))
        return stale();
    if (!source_->supports_kind(request.graph_kind))
        return fail(graph_error_code_t::adapter_rejected,
                    static_cast<std::uint64_t>(request.graph_kind));
    if (cancellation_requested(cancellation))
        return fail(graph_error_code_t::cancelled, request.offset);

    const auto total = request.edges
        ? source_->edge_count(gen, request.graph_kind, request.function_address)
        : source_->node_count(gen, request.graph_kind, request.function_address);
    if (!source_->generation_current(gen))
        return stale();
    const auto cap = request.edges ? k_graph_document_max_edges
                                   : k_graph_document_max_nodes;
    if (total > cap)
        return fail(graph_error_code_t::graph_too_large, total);
    if (!request.edges && overlays_) {
        const auto overlay_count = overlays_->overlay_count(gen);
        if (!source_->generation_current(gen))
            return stale();
        if (overlay_count > k_graph_document_max_overlays)
            return fail(graph_error_code_t::resource_exhausted, overlay_count);
    }

    output.snapshot_generation = gen;
    output.graph_kind = request.graph_kind;
    output.total_items = total;
    output.offset = request.offset;

    if (total == 0 || request.offset >= total) {
        if (!source_->generation_current(gen)) {
            output = {};
            return stale();
        }
        output.next_offset = 0;
        return {};
    }

    const auto remaining = total - request.offset;
    const auto to_read = (std::min)(static_cast<std::uint64_t>(request.limit), remaining);

    if (request.edges) {
        output.edges.reserve(static_cast<std::size_t>(to_read));
        for (std::uint64_t i = 0; i < to_read; ++i) {
            if (cancellation_requested(cancellation)) {
                output = {};
                return fail(graph_error_code_t::cancelled, i);
            }
            graph_edge_view_t edge;
            const auto ordinal = request.offset + i;
            if (!source_->edge_at(gen, request.graph_kind, request.function_address,
                                  ordinal, edge) || !graph_edge_valid(edge)) {
                output = {};
                return fail(graph_error_code_t::adapter_rejected, ordinal);
            }
            if (!source_->generation_current(gen)) {
                output = {};
                return stale();
            }
            const auto expected_id = compute_deterministic_edge_id(
                {edge.source, edge.target, edge.kind, edge.site_address,
                 edge.parallel_ordinal});
            if (edge.id != expected_id) {
                output = {};
                return fail(graph_error_code_t::adapter_rejected, ordinal);
            }
            output.edges.push_back(std::move(edge));
        }
        output.next_offset = request.offset + output.edges.size();
    } else {
        output.nodes.reserve(static_cast<std::size_t>(to_read));
        for (std::uint64_t i = 0; i < to_read; ++i) {
            if (cancellation_requested(cancellation)) {
                output = {};
                return fail(graph_error_code_t::cancelled, i);
            }
            graph_node_view_t node;
            const auto ordinal = request.offset + i;
            if (!source_->node_at(gen, request.graph_kind, request.function_address,
                                  ordinal, node) || !graph_node_valid(node)) {
                output = {};
                return fail(graph_error_code_t::adapter_rejected, ordinal);
            }
            if (!source_->generation_current(gen)) {
                output = {};
                return stale();
            }
            if (overlays_) {
                std::string projected_label;
                if (overlays_->overlay_node(gen, node.id, projected_label)) {
                    if (projected_label.size() > k_graph_document_max_label_bytes) {
                        output = {};
                        return fail(graph_error_code_t::resource_exhausted,
                                    projected_label.size());
                    }
                    node.label = std::move(projected_label);
                }
                if (!source_->generation_current(gen)) {
                    output = {};
                    return stale();
                }
            }
            output.nodes.push_back(std::move(node));
        }
        output.next_offset = request.offset + output.nodes.size();
    }

    if (output.next_offset >= total)
        output.next_offset = 0;

    if (!source_->generation_current(gen)) {
        output = {};
        return stale();
    }

    return {};
}

graph_error_t graph_document_model_t::navigate(
    const graph_navigation_request_t& request,
    std::uint64_t expected_generation,
    graph_kind_t kind,
    std::uint64_t function_address,
    graph_navigation_result_t& output)
{
    output = {};
    if (expected_generation != bound_generation_ ||
        !source_->generation_current(bound_generation_))
        return stale();
    if (request.address == 0 || !graph_kind_valid(kind))
        return fail(graph_error_code_t::invalid_argument, request.address);
    if (request.page_size == 0 ||
        request.page_size > k_graph_document_max_page_size) {
        return fail(graph_error_code_t::invalid_argument, request.page_size);
    }
    if (!source_->supports_kind(kind))
        return fail(graph_error_code_t::adapter_rejected,
                    static_cast<std::uint64_t>(kind));

    graph_node_view_t node;
    std::uint64_t ordinal = 0;
    if (!source_->node_by_address(bound_generation_, kind, function_address,
                                  request.address, node, ordinal)) {
        return source_->generation_current(bound_generation_)
            ? fail(graph_error_code_t::node_not_found, request.address) : stale();
    }
    if (!source_->generation_current(bound_generation_))
        return stale();
    if (!graph_node_valid(node))
        return fail(graph_error_code_t::adapter_rejected, ordinal);

    output.found = true;
    output.node = node.id;
    output.page_offset = (ordinal / request.page_size) * request.page_size;
    output.focus_requested = request.request_focus;
    if (request.select_node) {
        graph_selection_t synchronized_selection;
        synchronized_selection.kind = selection_kind_t::entity;
        synchronized_selection.has_address = node.address != 0;
        synchronized_selection.address = node.address;
        synchronized_selection.node = node.id;
        selection_ = synchronized_selection;
        output.selection = std::move(synchronized_selection);
    }
    return {};
}

graph_error_t graph_document_model_t::select(
    const graph_selection_t& selection, std::uint64_t expected_generation)
{
    if (expected_generation != bound_generation_ ||
        !source_->generation_current(bound_generation_))
        return stale();
    if (selection.kind == selection_kind_t::none) {
        selection_ = {};
        return {};
    }
    const graph_kind_t kinds[] = {graph_kind_t::cfg, graph_kind_t::call_graph,
                                  graph_kind_t::data_flow, graph_kind_t::custom};
    for (const auto kind : kinds) {
        if (!source_->supports_kind(kind))
            continue;
        graph_selection_t canonical;
        const auto error = canonicalize_selection(selection, kind, 0, canonical);
        if (error) {
            selection_ = std::move(canonical);
            return {};
        }
        if (error.code == graph_error_code_t::stale_generation)
            return error;
    }
    return fail(graph_error_code_t::selection_rejected,
                static_cast<std::uint64_t>(selection.kind));
}

graph_error_t graph_document_model_t::select(
    const graph_selection_t& selection,
    std::uint64_t expected_generation,
    graph_kind_t kind,
    std::uint64_t function_address)
{
    if (expected_generation != bound_generation_ ||
        !source_->generation_current(bound_generation_))
        return stale();
    if (!source_->supports_kind(kind))
        return fail(graph_error_code_t::adapter_rejected,
                    static_cast<std::uint64_t>(kind));
    graph_selection_t canonical;
    const auto error = canonicalize_selection(selection, kind, function_address,
                                              canonical);
    if (!error)
        return error;
    selection_ = std::move(canonical);
    return {};
}

graph_error_t graph_document_model_t::canonicalize_selection(
    const graph_selection_t& selection,
    graph_kind_t kind,
    std::uint64_t function_address,
    graph_selection_t& output) const
{
    output = {};
    if (!graph_selection_valid(selection))
        return fail(graph_error_code_t::selection_rejected,
                    static_cast<std::uint64_t>(selection.kind));
    if (selection.kind == selection_kind_t::none)
        return {};

    graph_node_view_t node;
    graph_edge_view_t edge;
    std::uint64_t ordinal = 0;
    if (selection.kind == selection_kind_t::address) {
        if (!source_->node_by_address(bound_generation_, kind, function_address,
                                      selection.address, node, ordinal)) {
            return source_->generation_current(bound_generation_)
                ? fail(graph_error_code_t::selection_rejected, selection.address)
                : stale();
        }
        if (!graph_node_valid(node) ||
            (selection.node.valid() && selection.node != node.id))
            return fail(graph_error_code_t::selection_rejected, selection.address);
        output = selection;
        output.node = node.id;
        output.address = node.address;
    } else if (selection.node.valid()) {
        if (!source_->node_by_id(bound_generation_, kind, function_address,
                                 selection.node, node, ordinal)) {
            return source_->generation_current(bound_generation_)
                ? fail(graph_error_code_t::node_not_found, selection.node.value)
                : stale();
        }
        if (!graph_node_valid(node) ||
            (selection.has_address && selection.address != node.address))
            return fail(graph_error_code_t::selection_rejected,
                        selection.node.value);
        output = selection;
        output.has_address = node.address != 0;
        output.address = node.address;
    } else {
        if (!source_->edge_by_id(bound_generation_, kind, function_address,
                                 selection.edge, edge, ordinal)) {
            return source_->generation_current(bound_generation_)
                ? fail(graph_error_code_t::edge_not_found, selection.edge.value)
                : stale();
        }
        if (!graph_edge_valid(edge) ||
            (selection.has_address && selection.address != edge.site_address))
            return fail(graph_error_code_t::selection_rejected,
                        selection.edge.value);
        output = selection;
        output.has_address = edge.site_address != 0;
        output.address = edge.site_address;
    }
    if (!source_->generation_current(bound_generation_)) {
        output = {};
        return stale();
    }
    return {};
}

graph_error_t graph_document_model_t::clear_selection(
    std::uint64_t expected_generation) noexcept
{
    if (expected_generation != bound_generation_ ||
        !source_->generation_current(bound_generation_))
        return stale();
    selection_ = {};
    return {};
}

graph_error_t graph_document_model_t::layout_layered(
    std::uint64_t generation, graph_kind_t kind,
    std::uint64_t function_address,
    const graph_layout_request_t& request,
    const graph_layout_cancellation_t* cancellation,
    graph_layout_t& output) const
{
    const auto nc = source_->node_count(generation, kind, function_address);
    const auto ec = source_->edge_count(generation, kind, function_address);
    output.snapshot_generation = generation;
    output.graph_kind = kind;
    output.node_count = static_cast<std::uint32_t>(nc);
    output.edge_count = static_cast<std::uint32_t>(ec);

    auto cancelled = [&](std::uint64_t subject) {
        output.cancelled = true;
        output.complete = false;
        return fail(graph_error_code_t::layout_cancelled, subject);
    };

    if (cancellation_requested(cancellation))
        return cancelled(0);

    std::vector<graph_node_id_t> nodes;
    nodes.reserve(static_cast<std::size_t>(nc));
    for (std::uint64_t i = 0; i < nc; ++i) {
        if (cancellation_requested(cancellation))
            return cancelled(i);
        graph_node_view_t node;
        if (!source_->node_at(generation, kind, function_address, i, node) ||
            !graph_node_valid(node)) {
            return fail(graph_error_code_t::adapter_rejected, i);
        }
        nodes.push_back(node.id);
    }

    if (cancellation_requested(cancellation))
        return cancelled(nc);

    std::sort(nodes.begin(), nodes.end());
    if (cancellation_requested(cancellation))
        return cancelled(nc);
    if (std::adjacent_find(nodes.begin(), nodes.end()) != nodes.end())
        return fail(graph_error_code_t::adapter_rejected, 0);

    struct edge_record_t {
        graph_edge_id_t id;
        graph_node_id_t source;
        graph_node_id_t target;
    };

    std::vector<edge_record_t> edges;
    std::vector<graph_edge_id_t> edge_ids;
    edges.reserve(static_cast<std::size_t>(ec));
    edge_ids.reserve(static_cast<std::size_t>(ec));
    output.edges.reserve(static_cast<std::size_t>(ec));
    for (std::uint64_t i = 0; i < ec; ++i) {
        if (cancellation_requested(cancellation))
            return cancelled(nc + i);
        graph_edge_view_t edge;
        if (!source_->edge_at(generation, kind, function_address, i, edge) ||
            !graph_edge_valid(edge)) {
            return fail(graph_error_code_t::adapter_rejected, i);
        }
        const auto expected_id = compute_deterministic_edge_id(
            {edge.source, edge.target, edge.kind, edge.site_address,
             edge.parallel_ordinal});
        if (edge.id != expected_id)
            return fail(graph_error_code_t::adapter_rejected, i);
        edges.push_back({edge.id, edge.source, edge.target});
        edge_ids.push_back(edge.id);
        graph_layout_edge_t le;
        le.id = edge.id;
        le.source = edge.source;
        le.target = edge.target;
        output.edges.push_back(std::move(le));
    }

    if (cancellation_requested(cancellation))
        return cancelled(nc + ec);

    std::sort(edge_ids.begin(), edge_ids.end());
    if (cancellation_requested(cancellation))
        return cancelled(nc + ec);
    if (std::adjacent_find(edge_ids.begin(), edge_ids.end()) != edge_ids.end())
        return fail(graph_error_code_t::adapter_rejected, 0);

    auto find_node_index = [&](graph_node_id_t id) -> std::uint64_t {
        auto it = std::lower_bound(nodes.begin(), nodes.end(), id,
            [](graph_node_id_t node, graph_node_id_t value) { return node < value; });
        if (it == nodes.end() || *it != id)
            return nodes.size();
        return static_cast<std::uint64_t>(it - nodes.begin());
    };

    std::vector<std::vector<std::uint64_t>> successors(nodes.size());
    for (std::size_t i = 0; i < edges.size(); ++i) {
        if (cancellation_requested(cancellation))
            return cancelled(nc + ec + i);
        const auto& edge = edges[i];
        auto src_idx = find_node_index(edge.source);
        auto tgt_idx = find_node_index(edge.target);
        if (src_idx >= nodes.size() || tgt_idx >= nodes.size())
            return fail(graph_error_code_t::adapter_rejected, edge.id.value);
        successors[src_idx].push_back(tgt_idx);
    }

    for (std::size_t i = 0; i < successors.size(); ++i) {
        if (cancellation_requested(cancellation))
            return cancelled(nc + 2 * ec + i);
        auto& adjacent = successors[i];
        std::sort(adjacent.begin(), adjacent.end());
        adjacent.erase(std::unique(adjacent.begin(), adjacent.end()), adjacent.end());
    }

    std::vector<std::uint32_t> layer(nodes.size(), 0);
    std::vector<bool> visited(nodes.size(), false);
    std::vector<std::uint64_t> stack;
    for (std::uint64_t i = 0; i < nodes.size(); ++i) {
        if (cancellation_requested(cancellation))
            return cancelled(nc + 2 * ec + i);
        if (visited[i])
            continue;
        stack.push_back(i);
        while (!stack.empty()) {
            if (cancellation_requested(cancellation))
                return cancelled(nc + 2 * ec + i);
            auto idx = stack.back();
            stack.pop_back();
            if (idx >= nodes.size() || visited[idx])
                continue;
            visited[idx] = true;
            for (auto tgt : successors[idx]) {
                if (cancellation_requested(cancellation))
                    return cancelled(nc + 2 * ec + i);
                if (tgt < nodes.size() && !visited[tgt]) {
                    layer[tgt] = (std::max)(layer[tgt], layer[idx] + 1);
                    stack.push_back(tgt);
                }
            }
        }
    }

    std::uint32_t max_layer = 0;
    for (std::size_t i = 0; i < layer.size(); ++i) {
        if (cancellation_requested(cancellation))
            return cancelled(nc + 2 * ec + i);
        max_layer = (std::max)(max_layer, layer[i]);
    }

    const float layer_height = request.canvas_height / (max_layer + 2);
    const float node_width = 120.0f;
    const float node_height = 40.0f;

    std::vector<std::uint32_t> nodes_per_layer(max_layer + 1, 0);
    for (std::size_t i = 0; i < layer.size(); ++i) {
        if (cancellation_requested(cancellation))
            return cancelled(nc + 2 * ec + i);
        ++nodes_per_layer[layer[i]];
    }

    std::vector<std::uint32_t> layer_cursor(max_layer + 1, 0);
    output.nodes.reserve(nodes.size());
    for (std::uint64_t i = 0; i < nodes.size(); ++i) {
        if (cancellation_requested(cancellation))
            return cancelled(nc + 2 * ec + i);
        graph_layout_node_t ln;
        ln.id = nodes[i];
        const auto l = layer[i];
        const auto pos_in_layer = layer_cursor[l]++;
        const auto count_in_layer = nodes_per_layer[l];
        const float col_width = request.canvas_width / (count_in_layer + 1);
        ln.x = col_width * (pos_in_layer + 1) - node_width / 2.0f;
        ln.y = layer_height * (l + 1);
        ln.width = node_width;
        ln.height = node_height;
        ln.layer = l;
        output.nodes.push_back(std::move(ln));
    }

    output.iterations = 1;
    output.cancelled = false;
    output.complete = true;
    return {};
}

graph_error_t graph_document_model_t::compute_layout(
    const graph_layout_request_t& request,
    const graph_layout_cancellation_t* cancellation,
    graph_layout_t& output) const
{
    output = {};
    if (!graph_layout_request_valid(request))
        return fail(graph_error_code_t::invalid_argument, request.max_nodes);

    if (request.expected_generation != bound_generation_ ||
        !source_->generation_current(bound_generation_))
        return stale();
    if (!source_->supports_kind(request.graph_kind))
        return fail(graph_error_code_t::adapter_rejected,
                    static_cast<std::uint64_t>(request.graph_kind));

    const auto gen = bound_generation_;
    const auto nc = source_->node_count(gen, request.graph_kind, request.function_address);
    const auto ec = source_->edge_count(gen, request.graph_kind, request.function_address);
    if (!source_->generation_current(gen))
        return stale();

    output.snapshot_generation = gen;
    output.graph_kind = request.graph_kind;
    output.node_count = static_cast<std::uint32_t>(
        (std::min)(nc, static_cast<std::uint64_t>(
                           (std::numeric_limits<std::uint32_t>::max)())));
    output.edge_count = static_cast<std::uint32_t>(
        (std::min)(ec, static_cast<std::uint64_t>(
                           (std::numeric_limits<std::uint32_t>::max)())));

    if (cancellation_requested(cancellation)) {
        output.cancelled = true;
        last_layout_ = output;
        return fail(graph_error_code_t::layout_cancelled, 0);
    }

    if (nc > k_graph_document_max_nodes)
        return fail(graph_error_code_t::graph_too_large, nc);
    if (ec > k_graph_document_max_edges)
        return fail(graph_error_code_t::graph_too_large, ec);

    if (nc > request.max_nodes || ec > request.max_edges) {
        output.cancelled = false;
        output.complete = false;
        last_layout_ = output;
        return fail(graph_error_code_t::layout_capacity,
                    nc > request.max_nodes ? nc : ec);
    }

    const auto error = layout_layered(gen, request.graph_kind,
                                      request.function_address, request,
                                      cancellation, output);
    if (!source_->generation_current(gen)) {
        output = {};
        last_layout_ = output;
        return stale();
    }
    last_layout_ = output;
    return error;
}

graph_error_t graph_document_model_t::diff_generations(
    std::uint64_t old_generation,
    std::uint64_t new_generation,
    graph_kind_t kind,
    std::uint64_t function_address,
    const graph_cancellation_t* cancellation,
    graph_diff_result_t& output) const
{
    output = {};
    output.old_generation = old_generation;
    output.new_generation = new_generation;

    if (old_generation == 0 || new_generation == 0 ||
        old_generation == new_generation || !graph_kind_valid(kind)) {
        return fail(graph_error_code_t::invalid_argument, new_generation);
    }
    if (new_generation != bound_generation_ ||
        !source_->generation_current(bound_generation_))
        return stale();
    if (!source_->generation_available(old_generation) ||
        !source_->generation_available(new_generation))
        return fail(graph_error_code_t::adapter_rejected, old_generation);
    if (!source_->supports_kind(kind))
        return fail(graph_error_code_t::adapter_rejected,
                    static_cast<std::uint64_t>(kind));
    if (cancellation_requested(cancellation))
        return fail(graph_error_code_t::cancelled, 0);

    const auto old_nc = source_->node_count(old_generation, kind, function_address);
    const auto new_nc = source_->node_count(new_generation, kind, function_address);
    const auto old_ec = source_->edge_count(old_generation, kind, function_address);
    const auto new_ec = source_->edge_count(new_generation, kind, function_address);

    if (old_nc > k_graph_document_max_nodes || new_nc > k_graph_document_max_nodes)
        return fail(graph_error_code_t::graph_too_large,
                    (std::max)(old_nc, new_nc));
    if (old_ec > k_graph_document_max_edges || new_ec > k_graph_document_max_edges)
        return fail(graph_error_code_t::graph_too_large,
                    (std::max)(old_ec, new_ec));

    if (overlays_) {
        const auto old_overlay_count = overlays_->overlay_count(old_generation);
        const auto new_overlay_count = overlays_->overlay_count(new_generation);
        if (old_overlay_count > k_graph_document_max_overlays ||
            new_overlay_count > k_graph_document_max_overlays) {
            return fail(graph_error_code_t::resource_exhausted,
                        (std::max)(old_overlay_count, new_overlay_count));
        }
    }

    const auto reserve_count = old_nc + new_nc + old_ec + new_ec;
    output.entries.reserve(static_cast<std::size_t>(reserve_count));

    std::vector<graph_node_view_t> old_nodes;
    std::vector<graph_node_view_t> new_nodes;
    old_nodes.reserve(static_cast<std::size_t>(old_nc));
    new_nodes.reserve(static_cast<std::size_t>(new_nc));

    for (std::uint64_t i = 0; i < old_nc; ++i) {
        if (cancellation_requested(cancellation))
            return fail(graph_error_code_t::cancelled, i);
        graph_node_view_t node;
        if (!source_->node_at(old_generation, kind, function_address, i, node) ||
            !graph_node_valid(node)) {
            return fail(graph_error_code_t::adapter_rejected, i);
        }
        if (overlays_) {
            std::string projected_label;
            if (overlays_->overlay_node(old_generation, node.id, projected_label)) {
                if (projected_label.size() > k_graph_document_max_label_bytes)
                    return fail(graph_error_code_t::resource_exhausted,
                                projected_label.size());
                node.label = std::move(projected_label);
            }
        }
        old_nodes.push_back(std::move(node));
    }
    for (std::uint64_t i = 0; i < new_nc; ++i) {
        if (cancellation_requested(cancellation))
            return fail(graph_error_code_t::cancelled, old_nc + i);
        graph_node_view_t node;
        if (!source_->node_at(new_generation, kind, function_address, i, node) ||
            !graph_node_valid(node)) {
            return fail(graph_error_code_t::adapter_rejected, i);
        }
        if (overlays_) {
            std::string projected_label;
            if (overlays_->overlay_node(new_generation, node.id, projected_label)) {
                if (projected_label.size() > k_graph_document_max_label_bytes)
                    return fail(graph_error_code_t::resource_exhausted,
                                projected_label.size());
                node.label = std::move(projected_label);
            }
        }
        new_nodes.push_back(std::move(node));
    }

    std::sort(old_nodes.begin(), old_nodes.end(),
              [](const auto& a, const auto& b) { return a.id < b.id; });
    std::sort(new_nodes.begin(), new_nodes.end(),
              [](const auto& a, const auto& b) { return a.id < b.id; });

    if (cancellation_requested(cancellation))
        return fail(graph_error_code_t::cancelled, old_nc + new_nc);
    const auto duplicate_node = [](const auto& nodes) {
        return std::adjacent_find(nodes.begin(), nodes.end(),
            [](const auto& lhs, const auto& rhs) { return lhs.id == rhs.id; }) != nodes.end();
    };
    if (duplicate_node(old_nodes) || duplicate_node(new_nodes))
        return fail(graph_error_code_t::adapter_rejected, 0);

    const auto append_entry = [&](graph_diff_entry_t entry) {
        if (output.entries.size() >= k_graph_document_max_diff_entries)
            return false;
        output.entries.push_back(std::move(entry));
        return true;
    };

    const auto nodes_equal = [](const graph_node_view_t& lhs,
                                const graph_node_view_t& rhs) {
        return lhs.kind == rhs.kind && lhs.address == rhs.address &&
               lhs.label == rhs.label &&
               lhs.instruction_count == rhs.instruction_count &&
               lhs.in_degree == rhs.in_degree &&
               lhs.out_degree == rhs.out_degree;
    };

    std::size_t oi = 0, ni = 0;
    while (oi < old_nodes.size() && ni < new_nodes.size()) {
        if (cancellation_requested(cancellation))
            return fail(graph_error_code_t::cancelled, oi + ni);
        if (old_nodes[oi].id < new_nodes[ni].id) {
            graph_diff_entry_t entry;
            entry.kind = graph_diff_entry_t::kind_t::node_removed;
            entry.node = old_nodes[oi].id;
            entry.address = old_nodes[oi].address;
            entry.label = old_nodes[oi].label;
            if (!append_entry(std::move(entry)))
                return fail(graph_error_code_t::resource_exhausted,
                            output.entries.size());
            ++oi;
        } else if (new_nodes[ni].id < old_nodes[oi].id) {
            graph_diff_entry_t entry;
            entry.kind = graph_diff_entry_t::kind_t::node_added;
            entry.node = new_nodes[ni].id;
            entry.address = new_nodes[ni].address;
            entry.label = new_nodes[ni].label;
            if (!append_entry(std::move(entry)))
                return fail(graph_error_code_t::resource_exhausted,
                            output.entries.size());
            ++ni;
        } else {
            if (!nodes_equal(old_nodes[oi], new_nodes[ni])) {
                graph_diff_entry_t entry;
                entry.kind = graph_diff_entry_t::kind_t::node_modified;
                entry.node = new_nodes[ni].id;
                entry.address = new_nodes[ni].address;
                entry.label = new_nodes[ni].label;
                if (!append_entry(std::move(entry)))
                    return fail(graph_error_code_t::resource_exhausted,
                                output.entries.size());
            }
            ++oi;
            ++ni;
        }
    }
    while (oi < old_nodes.size()) {
        if (cancellation_requested(cancellation))
            return fail(graph_error_code_t::cancelled, oi + ni);
        graph_diff_entry_t entry;
        entry.kind = graph_diff_entry_t::kind_t::node_removed;
        entry.node = old_nodes[oi].id;
        entry.address = old_nodes[oi].address;
        entry.label = old_nodes[oi].label;
        if (!append_entry(std::move(entry)))
            return fail(graph_error_code_t::resource_exhausted,
                        output.entries.size());
        ++oi;
    }
    while (ni < new_nodes.size()) {
        if (cancellation_requested(cancellation))
            return fail(graph_error_code_t::cancelled, oi + ni);
        graph_diff_entry_t entry;
        entry.kind = graph_diff_entry_t::kind_t::node_added;
        entry.node = new_nodes[ni].id;
        entry.address = new_nodes[ni].address;
        entry.label = new_nodes[ni].label;
        if (!append_entry(std::move(entry)))
            return fail(graph_error_code_t::resource_exhausted,
                        output.entries.size());
        ++ni;
    }

    struct edge_key_t {
        graph_edge_id_t id;
        std::uint64_t site_address = 0;
        std::string label;
    };

    std::vector<edge_key_t> old_edges;
    std::vector<edge_key_t> new_edges;
    old_edges.reserve(static_cast<std::size_t>(old_ec));
    new_edges.reserve(static_cast<std::size_t>(new_ec));

    for (std::uint64_t i = 0; i < old_ec; ++i) {
        if (cancellation_requested(cancellation))
            return fail(graph_error_code_t::cancelled, old_nc + new_nc + i);
        graph_edge_view_t edge;
        if (!source_->edge_at(old_generation, kind, function_address, i, edge) ||
            !graph_edge_valid(edge)) {
            return fail(graph_error_code_t::adapter_rejected, i);
        }
        const auto expected_id = compute_deterministic_edge_id(
            {edge.source, edge.target, edge.kind, edge.site_address,
             edge.parallel_ordinal});
        if (edge.id != expected_id)
            return fail(graph_error_code_t::adapter_rejected, i);
        old_edges.push_back({edge.id, edge.site_address, std::move(edge.label)});
    }
    for (std::uint64_t i = 0; i < new_ec; ++i) {
        if (cancellation_requested(cancellation))
            return fail(graph_error_code_t::cancelled,
                        old_nc + new_nc + old_ec + i);
        graph_edge_view_t edge;
        if (!source_->edge_at(new_generation, kind, function_address, i, edge) ||
            !graph_edge_valid(edge)) {
            return fail(graph_error_code_t::adapter_rejected, i);
        }
        const auto expected_id = compute_deterministic_edge_id(
            {edge.source, edge.target, edge.kind, edge.site_address,
             edge.parallel_ordinal});
        if (edge.id != expected_id)
            return fail(graph_error_code_t::adapter_rejected, i);
        new_edges.push_back({edge.id, edge.site_address, std::move(edge.label)});
    }

    const auto edge_less = [](const edge_key_t& lhs, const edge_key_t& rhs) {
        return lhs.id < rhs.id;
    };
    std::sort(old_edges.begin(), old_edges.end(), edge_less);
    std::sort(new_edges.begin(), new_edges.end(), edge_less);

    if (cancellation_requested(cancellation))
        return fail(graph_error_code_t::cancelled,
                    old_nc + new_nc + old_ec + new_ec);
    const auto duplicate_edge = [](const auto& edges) {
        return std::adjacent_find(edges.begin(), edges.end(),
            [](const auto& lhs, const auto& rhs) { return lhs.id == rhs.id; }) != edges.end();
    };
    if (duplicate_edge(old_edges) || duplicate_edge(new_edges))
        return fail(graph_error_code_t::adapter_rejected, 0);

    oi = 0; ni = 0;
    while (oi < old_edges.size() && ni < new_edges.size()) {
        if (cancellation_requested(cancellation))
            return fail(graph_error_code_t::cancelled, oi + ni);
        if (old_edges[oi].id < new_edges[ni].id) {
            graph_diff_entry_t entry;
            entry.kind = graph_diff_entry_t::kind_t::edge_removed;
            entry.edge = old_edges[oi].id;
            entry.address = old_edges[oi].site_address;
            entry.label = old_edges[oi].label;
            if (!append_entry(std::move(entry)))
                return fail(graph_error_code_t::resource_exhausted,
                            output.entries.size());
            ++oi;
        } else if (new_edges[ni].id < old_edges[oi].id) {
            graph_diff_entry_t entry;
            entry.kind = graph_diff_entry_t::kind_t::edge_added;
            entry.edge = new_edges[ni].id;
            entry.address = new_edges[ni].site_address;
            entry.label = new_edges[ni].label;
            if (!append_entry(std::move(entry)))
                return fail(graph_error_code_t::resource_exhausted,
                            output.entries.size());
            ++ni;
        } else {
            if (old_edges[oi].label != new_edges[ni].label) {
                graph_diff_entry_t entry;
                entry.kind = graph_diff_entry_t::kind_t::edge_modified;
                entry.edge = new_edges[ni].id;
                entry.address = new_edges[ni].site_address;
                entry.label = new_edges[ni].label;
                if (!append_entry(std::move(entry)))
                    return fail(graph_error_code_t::resource_exhausted,
                                output.entries.size());
            }
            ++oi;
            ++ni;
        }
    }
    while (oi < old_edges.size()) {
        if (cancellation_requested(cancellation))
            return fail(graph_error_code_t::cancelled, oi + ni);
        graph_diff_entry_t entry;
        entry.kind = graph_diff_entry_t::kind_t::edge_removed;
        entry.edge = old_edges[oi].id;
        entry.address = old_edges[oi].site_address;
        entry.label = old_edges[oi].label;
        if (!append_entry(std::move(entry)))
            return fail(graph_error_code_t::resource_exhausted,
                        output.entries.size());
        ++oi;
    }
    while (ni < new_edges.size()) {
        if (cancellation_requested(cancellation))
            return fail(graph_error_code_t::cancelled, oi + ni);
        graph_diff_entry_t entry;
        entry.kind = graph_diff_entry_t::kind_t::edge_added;
        entry.edge = new_edges[ni].id;
        entry.address = new_edges[ni].site_address;
        entry.label = new_edges[ni].label;
        if (!append_entry(std::move(entry)))
            return fail(graph_error_code_t::resource_exhausted,
                        output.entries.size());
        ++ni;
    }

    if (!source_->generation_current(bound_generation_)) {
        output = {};
        return stale();
    }

    return {};
}

const graph_layout_t& graph_document_model_t::last_layout() const noexcept
{
    return last_layout_;
}

const graph_selection_t& graph_document_model_t::selection() const noexcept
{
    return selection_;
}

std::uint64_t graph_document_model_t::current_generation() const noexcept
{
    return source_->current_generation();
}

bool graph_document_model_t::generation_current(
    std::uint64_t generation) const noexcept
{
    return source_->generation_current(generation);
}

bool graph_document_model_t::is_stale() const noexcept
{
    return !source_->generation_current(bound_generation_);
}

std::uint64_t graph_document_model_t::bound_generation() const noexcept
{
    return bound_generation_;
}

std::uint64_t graph_document_model_t::node_count(
    graph_kind_t kind, std::uint64_t function_address) const noexcept
{
    if (!source_->generation_current(bound_generation_) ||
        !source_->supports_kind(kind))
        return 0;
    return source_->node_count(bound_generation_, kind, function_address);
}

std::uint64_t graph_document_model_t::edge_count(
    graph_kind_t kind, std::uint64_t function_address) const noexcept
{
    if (!source_->generation_current(bound_generation_) ||
        !source_->supports_kind(kind))
        return 0;
    return source_->edge_count(bound_generation_, kind, function_address);
}

}
}
}
