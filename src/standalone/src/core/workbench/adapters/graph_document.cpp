#include "graph_document.hpp"

#include <algorithm>
#include <cmath>
#include <limits>

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

bool cancellation_requested(const graph_cancellation_t* cancellation) noexcept
{
    return cancellation != nullptr && cancellation->cancelled();
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

graph_edge_id_t compute_deterministic_edge_id(graph_node_id_t source,
                                              graph_node_id_t target) noexcept
{
    if (!source.valid() || !target.valid())
        return {};
    std::uint64_t hash = k_fnv_offset;
    for (int shift = 0; shift < 64; shift += 8) {
        hash ^= static_cast<std::uint8_t>((source.value >> shift) & 0xFF);
        hash *= k_fnv_prime;
    }
    for (int shift = 0; shift < 64; shift += 8) {
        hash ^= static_cast<std::uint8_t>((target.value >> shift) & 0xFF);
        hash *= k_fnv_prime;
    }
    if (hash == 0)
        return {1};
    return {hash};
}

bool graph_page_request_valid(const graph_page_request_t& request) noexcept
{
    return request.limit != 0 && request.limit <= k_graph_document_max_page_size;
}

bool graph_layout_request_valid(const graph_layout_request_t& request) noexcept
{
    if (request.max_nodes == 0 || request.max_nodes > k_graph_document_max_layout_nodes)
        return false;
    if (request.max_iterations == 0 || request.max_iterations > k_graph_document_max_layout_iterations)
        return false;
    if (request.canvas_width <= 0.0f || request.canvas_height <= 0.0f)
        return false;
    return true;
}

bool graph_selection_valid(const graph_selection_t& selection) noexcept
{
    if (selection.kind == selection_kind_t::none)
        return true;
    if (selection.kind > selection_kind_t::source)
        return false;
    return true;
}

graph_error_t graph_document_model_t::fail(graph_error_code_t code,
                                            std::uint64_t subject) noexcept
{
    return {code, subject};
}

graph_error_t graph_document_model_t::stale() noexcept
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
    if (!graph_page_request_valid(request))
        return fail(graph_error_code_t::invalid_page, request.limit);

    const auto gen = bound_generation_;
    if (!source_->generation_current(gen))
        return stale();

    const auto kind = source_->supported_kind();
    const auto total = request.edges
        ? source_->edge_count(gen, kind, 0)
        : source_->node_count(gen, kind, 0);

    output.snapshot_generation = gen;
    output.graph_kind = kind;
    output.total_items = total;
    output.offset = request.offset;

    if (total == 0 || request.offset >= total) {
        output.next_offset = 0;
        return {};
    }

    const auto remaining = total - request.offset;
    const auto to_read = (std::min)(static_cast<std::uint64_t>(request.limit), remaining);

    if (request.edges) {
        output.edges.clear();
        output.edges.reserve(static_cast<std::size_t>(to_read));
        for (std::uint64_t i = 0; i < to_read; ++i) {
            if (cancellation_requested(cancellation))
                return fail(graph_error_code_t::cancelled, i);
            graph_edge_view_t edge;
            if (!source_->edge_at(gen, kind, 0, request.offset + i, edge))
                break;
            output.edges.push_back(edge);
        }
        output.next_offset = request.offset + output.edges.size();
    } else {
        output.nodes.clear();
        output.nodes.reserve(static_cast<std::size_t>(to_read));
        for (std::uint64_t i = 0; i < to_read; ++i) {
            if (cancellation_requested(cancellation))
                return fail(graph_error_code_t::cancelled, i);
            graph_node_view_t node;
            if (!source_->node_at(gen, kind, 0, request.offset + i, node))
                break;
            output.nodes.push_back(node);
        }
        output.next_offset = request.offset + output.nodes.size();
    }

    if (output.next_offset >= total)
        output.next_offset = 0;

    return {};
}

graph_error_t graph_document_model_t::navigate(
    const graph_navigation_request_t& request,
    std::uint64_t expected_generation,
    graph_kind_t kind,
    std::uint64_t function_address,
    graph_navigation_result_t& output) const
{
    if (!source_->generation_current(expected_generation))
        return stale();

    graph_node_view_t node;
    std::uint64_t ordinal = 0;
    if (!source_->node_by_address(expected_generation, kind, function_address,
                                  request.address, node, ordinal)) {
        output.found = false;
        return fail(graph_error_code_t::node_not_found, request.address);
    }

    output.found = true;
    output.node = node.id;
    output.page_offset = (ordinal / k_graph_document_max_page_size) *
                         k_graph_document_max_page_size;
    return {};
}

graph_error_t graph_document_model_t::select(const graph_selection_t& selection)
{
    if (!graph_selection_valid(selection))
        return fail(graph_error_code_t::selection_rejected,
                    static_cast<std::uint64_t>(selection.kind));
    selection_ = selection;
    return {};
}

void graph_document_model_t::clear_selection() noexcept
{
    selection_ = {};
}

void graph_document_model_t::layout_layered(
    std::uint64_t generation, graph_kind_t kind,
    std::uint64_t function_address,
    const graph_layout_request_t& request,
    const graph_layout_cancellation_t* cancellation,
    graph_layout_t& output) const
{
    const auto nc = source_->node_count(generation, kind, function_address);
    const auto ec = source_->edge_count(generation, kind, function_address);

    if (nc > request.max_nodes) {
        output.cancelled = false;
        output.complete = false;
        output.node_count = static_cast<std::uint32_t>(nc);
        output.edge_count = static_cast<std::uint32_t>(ec);
        return;
    }

    output.snapshot_generation = generation;
    output.graph_kind = kind;
    output.node_count = static_cast<std::uint32_t>(nc);
    output.edge_count = static_cast<std::uint32_t>(ec);
    output.nodes.reserve(static_cast<std::size_t>(nc));

    std::vector<graph_node_view_t> nodes;
    nodes.reserve(static_cast<std::size_t>(nc));
    for (std::uint64_t i = 0; i < nc; ++i) {
        if (cancellation_requested(cancellation)) {
            output.cancelled = true;
            output.complete = false;
            return;
        }
        graph_node_view_t node;
        if (!source_->node_at(generation, kind, function_address, i, node))
            break;
        nodes.push_back(node);
    }

    std::vector<graph_edge_view_t> edges;
    edges.reserve(static_cast<std::size_t>(ec));
    for (std::uint64_t i = 0; i < ec; ++i) {
        if (cancellation_requested(cancellation)) {
            output.cancelled = true;
            output.complete = false;
            return;
        }
        graph_edge_view_t edge;
        if (!source_->edge_at(generation, kind, function_address, i, edge))
            break;
        edges.push_back(edge);
        graph_layout_edge_t le;
        le.id = edge.id;
        le.source = edge.source;
        le.target = edge.target;
        output.edges.push_back(le);
    }

    std::sort(nodes.begin(), nodes.end(),
              [](const auto& a, const auto& b) { return a.id < b.id; });

    auto find_node_index = [&](graph_node_id_t id) -> std::uint64_t {
        auto it = std::lower_bound(nodes.begin(), nodes.end(), id,
            [](const auto& n, graph_node_id_t v) { return n.id < v; });
        if (it == nodes.end() || it->id != id)
            return nodes.size();
        return static_cast<std::uint64_t>(it - nodes.begin());
    };

    std::vector<std::vector<std::uint64_t>> successors(nodes.size());
    for (const auto& edge : edges) {
        auto src_idx = find_node_index(edge.source);
        auto tgt_idx = find_node_index(edge.target);
        if (src_idx < nodes.size() && tgt_idx < nodes.size())
            successors[src_idx].push_back(tgt_idx);
    }

    std::vector<std::uint32_t> layer(nodes.size(), 0);
    std::vector<bool> visited(nodes.size(), false);
    std::vector<std::uint64_t> stack;
    for (std::uint64_t i = 0; i < nodes.size(); ++i) {
        if (visited[i])
            continue;
        stack.push_back(i);
        while (!stack.empty()) {
            auto idx = stack.back();
            stack.pop_back();
            if (idx >= nodes.size() || visited[idx])
                continue;
            visited[idx] = true;
            for (auto tgt : successors[idx]) {
                if (tgt < nodes.size() && !visited[tgt]) {
                    layer[tgt] = layer[idx] + 1;
                    stack.push_back(tgt);
                }
            }
        }
    }

    std::uint32_t max_layer = 0;
    for (auto l : layer)
        max_layer = (std::max)(max_layer, l);

    const float layer_height = request.canvas_height / (max_layer + 2);
    const float node_width = 120.0f;
    const float node_height = 40.0f;

    std::vector<std::uint32_t> nodes_per_layer(max_layer + 1, 0);
    for (auto l : layer)
        nodes_per_layer[l]++;

    std::vector<std::uint32_t> layer_cursor(max_layer + 1, 0);
    for (std::uint64_t i = 0; i < nodes.size(); ++i) {
        graph_layout_node_t ln;
        ln.id = nodes[i].id;
        const auto l = layer[i];
        const auto pos_in_layer = layer_cursor[l]++;
        const auto count_in_layer = nodes_per_layer[l];
        const float col_width = request.canvas_width / (count_in_layer + 1);
        ln.x = col_width * (pos_in_layer + 1) - node_width / 2.0f;
        ln.y = layer_height * (l + 1);
        ln.width = node_width;
        ln.height = node_height;
        ln.layer = l;
        output.nodes.push_back(ln);
    }

    output.iterations = 1;
    output.cancelled = false;
    output.complete = true;
}

graph_error_t graph_document_model_t::compute_layout(
    const graph_layout_request_t& request,
    const graph_layout_cancellation_t* cancellation,
    graph_layout_t& output) const
{
    if (!graph_layout_request_valid(request))
        return fail(graph_error_code_t::invalid_argument, request.max_nodes);

    if (!source_->generation_current(request.expected_generation))
        return stale();

    const auto gen = request.expected_generation;
    const auto nc = source_->node_count(gen, request.graph_kind, request.function_address);

    if (nc > k_graph_document_max_nodes)
        return fail(graph_error_code_t::graph_too_large, nc);

    if (nc > request.max_nodes) {
        output.snapshot_generation = gen;
        output.graph_kind = request.graph_kind;
        output.node_count = static_cast<std::uint32_t>(nc);
        output.edge_count = 0;
        output.cancelled = false;
        output.complete = false;
        last_layout_ = output;
        return fail(graph_error_code_t::layout_capacity, nc);
    }

    layout_layered(gen, request.graph_kind, request.function_address,
                   request, cancellation, output);

    if (output.cancelled) {
        last_layout_ = output;
        return fail(graph_error_code_t::layout_cancelled, 0);
    }

    last_layout_ = output;
    return {};
}

graph_error_t graph_document_model_t::diff_generations(
    std::uint64_t old_generation,
    std::uint64_t new_generation,
    graph_kind_t kind,
    std::uint64_t function_address,
    graph_diff_result_t& output) const
{
    output.old_generation = old_generation;
    output.new_generation = new_generation;

    const auto old_nc = source_->node_count(old_generation, kind, function_address);
    const auto new_nc = source_->node_count(new_generation, kind, function_address);

    struct node_key_t {
        graph_node_id_t id;
        std::uint64_t address;
    };

    std::vector<node_key_t> old_nodes;
    std::vector<node_key_t> new_nodes;
    old_nodes.reserve(static_cast<std::size_t>(old_nc));
    new_nodes.reserve(static_cast<std::size_t>(new_nc));

    for (std::uint64_t i = 0; i < old_nc; ++i) {
        graph_node_view_t node;
        if (source_->node_at(old_generation, kind, function_address, i, node))
            old_nodes.push_back({node.id, node.address});
    }
    for (std::uint64_t i = 0; i < new_nc; ++i) {
        graph_node_view_t node;
        if (source_->node_at(new_generation, kind, function_address, i, node))
            new_nodes.push_back({node.id, node.address});
    }

    std::sort(old_nodes.begin(), old_nodes.end(),
              [](const auto& a, const auto& b) { return a.id < b.id; });
    std::sort(new_nodes.begin(), new_nodes.end(),
              [](const auto& a, const auto& b) { return a.id < b.id; });

    std::size_t oi = 0, ni = 0;
    while (oi < old_nodes.size() && ni < new_nodes.size()) {
        if (old_nodes[oi].id < new_nodes[ni].id) {
            graph_diff_entry_t entry;
            entry.kind = graph_diff_entry_t::kind_t::node_removed;
            entry.node = old_nodes[oi].id;
            entry.address = old_nodes[oi].address;
            output.entries.push_back(entry);
            ++oi;
        } else if (new_nodes[ni].id < old_nodes[oi].id) {
            graph_diff_entry_t entry;
            entry.kind = graph_diff_entry_t::kind_t::node_added;
            entry.node = new_nodes[ni].id;
            entry.address = new_nodes[ni].address;
            output.entries.push_back(entry);
            ++ni;
        } else {
            if (old_nodes[oi].address != new_nodes[ni].address) {
                graph_diff_entry_t entry;
                entry.kind = graph_diff_entry_t::kind_t::node_modified;
                entry.node = new_nodes[ni].id;
                entry.address = new_nodes[ni].address;
                output.entries.push_back(entry);
            }
            ++oi;
            ++ni;
        }
    }
    while (oi < old_nodes.size()) {
        graph_diff_entry_t entry;
        entry.kind = graph_diff_entry_t::kind_t::node_removed;
        entry.node = old_nodes[oi].id;
        entry.address = old_nodes[oi].address;
        output.entries.push_back(entry);
        ++oi;
    }
    while (ni < new_nodes.size()) {
        graph_diff_entry_t entry;
        entry.kind = graph_diff_entry_t::kind_t::node_added;
        entry.node = new_nodes[ni].id;
        entry.address = new_nodes[ni].address;
        output.entries.push_back(entry);
        ++ni;
    }

    const auto old_ec = source_->edge_count(old_generation, kind, function_address);
    const auto new_ec = source_->edge_count(new_generation, kind, function_address);

    std::vector<graph_edge_id_t> old_edges;
    std::vector<graph_edge_id_t> new_edges;
    old_edges.reserve(static_cast<std::size_t>(old_ec));
    new_edges.reserve(static_cast<std::size_t>(new_ec));

    for (std::uint64_t i = 0; i < old_ec; ++i) {
        graph_edge_view_t edge;
        if (source_->edge_at(old_generation, kind, function_address, i, edge))
            old_edges.push_back(edge.id);
    }
    for (std::uint64_t i = 0; i < new_ec; ++i) {
        graph_edge_view_t edge;
        if (source_->edge_at(new_generation, kind, function_address, i, edge))
            new_edges.push_back(edge.id);
    }

    std::sort(old_edges.begin(), old_edges.end());
    std::sort(new_edges.begin(), new_edges.end());

    oi = 0; ni = 0;
    while (oi < old_edges.size() && ni < new_edges.size()) {
        if (old_edges[oi] < new_edges[ni]) {
            graph_diff_entry_t entry;
            entry.kind = graph_diff_entry_t::kind_t::edge_removed;
            entry.edge = old_edges[oi];
            output.entries.push_back(entry);
            ++oi;
        } else if (new_edges[ni] < old_edges[oi]) {
            graph_diff_entry_t entry;
            entry.kind = graph_diff_entry_t::kind_t::edge_added;
            entry.edge = new_edges[ni];
            output.entries.push_back(entry);
            ++ni;
        } else {
            ++oi;
            ++ni;
        }
    }
    while (oi < old_edges.size()) {
        graph_diff_entry_t entry;
        entry.kind = graph_diff_entry_t::kind_t::edge_removed;
        entry.edge = old_edges[oi];
        output.entries.push_back(entry);
        ++oi;
    }
    while (ni < new_edges.size()) {
        graph_diff_entry_t entry;
        entry.kind = graph_diff_entry_t::kind_t::edge_added;
        entry.edge = new_edges[ni];
        output.entries.push_back(entry);
        ++ni;
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
    return source_->node_count(bound_generation_, kind, function_address);
}

std::uint64_t graph_document_model_t::edge_count(
    graph_kind_t kind, std::uint64_t function_address) const noexcept
{
    return source_->edge_count(bound_generation_, kind, function_address);
}

}
}
}
