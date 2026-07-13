#include "graph_document.hpp"

#include <algorithm>
#include <cstddef>
#include <limits>
#include <tuple>
#include <unordered_set>
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

void increment_subject(std::uint64_t& value) noexcept
{
    if (value != (std::numeric_limits<std::uint64_t>::max)())
        ++value;
}

template <typename T, typename Less>
bool cancellable_sort(std::vector<T>& values, Less less,
                      const graph_cancellation_t* cancellation,
                      std::uint64_t& subject)
{
    if (values.size() < 2)
        return !cancellation_requested(cancellation);

    std::vector<T> scratch;
    scratch.reserve(values.size());
    std::size_t width = 1;
    while (width < values.size()) {
        scratch.clear();
        std::size_t left = 0;
        while (left < values.size()) {
            if (cancellation_requested(cancellation))
                return false;
            const auto middle = width > values.size() - left
                ? values.size() : left + width;
            const auto remaining = values.size() - middle;
            const auto right_width = (std::min)(width, remaining);
            const auto right = middle + right_width;
            auto first = left;
            auto second = middle;
            while (first < middle || second < right) {
                if (cancellation_requested(cancellation))
                    return false;
                if (first == middle ||
                    (second < right && less(values[second], values[first]))) {
                    scratch.push_back(std::move(values[second++]));
                } else {
                    scratch.push_back(std::move(values[first++]));
                }
                increment_subject(subject);
            }
            left = right;
        }
        values.swap(scratch);
        if (width > values.size() / 2)
            width = values.size();
        else
            width *= 2;
    }
    return !cancellation_requested(cancellation);
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
           graph_edge_kind_valid(identity.kind) &&
           identity.parallel_ordinal < k_graph_document_max_edges;
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

bool graph_source_limits_valid(const graph_source_limits_t& limits) noexcept
{
    return limits.max_nodes != 0 &&
           limits.max_nodes <= k_graph_document_max_nodes &&
           limits.max_edges != 0 &&
           limits.max_edges <= k_graph_document_max_edges;
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

graph_error_t graph_document_model_t::read_counts(
    std::uint64_t generation, graph_kind_t kind,
    std::uint64_t function_address, const graph_source_limits_t& limits,
    const graph_cancellation_t* cancellation,
    graph_error_code_t limit_error,
    graph_source_counts_t& output) const
{
    output = {};
    if (!graph_source_limits_valid(limits))
        return fail(graph_error_code_t::invalid_argument, limits.max_nodes);
    if (cancellation_requested(cancellation))
        return fail(graph_error_code_t::cancelled, 0);

    const auto result = source_->counts(generation, kind, function_address,
                                        limits, cancellation, output);
    if (cancellation_requested(cancellation) ||
        result == graph_source_result_t::cancelled) {
        output = {};
        return fail(graph_error_code_t::cancelled, 0);
    }
    if (!source_->generation_current(bound_generation_)) {
        output = {};
        return stale();
    }

    const auto exceeded_subject = [&]() {
        if (output.nodes > limits.max_nodes)
            return output.nodes;
        if (output.edges > limits.max_edges)
            return output.edges;
        const auto limit = (std::max)(limits.max_nodes, limits.max_edges);
        return limit + 1U;
    };
    if (result == graph_source_result_t::limit_exceeded ||
        output.nodes > limits.max_nodes || output.edges > limits.max_edges) {
        const auto subject = exceeded_subject();
        output = {};
        return fail(limit_error, subject);
    }
    if (result != graph_source_result_t::success) {
        output = {};
        return fail(graph_error_code_t::adapter_rejected, generation);
    }
    if (output.edges != 0 && output.nodes == 0) {
        const auto subject = output.edges;
        output = {};
        return fail(graph_error_code_t::adapter_rejected, subject);
    }
    return {};
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

    const graph_source_limits_t limits;
    graph_source_counts_t counts;
    const auto counts_error = read_counts(
        gen, request.graph_kind, request.function_address, limits,
        cancellation, graph_error_code_t::graph_too_large, counts);
    if (!counts_error.ok())
        return counts_error;
    const auto total = request.edges ? counts.edges : counts.nodes;

    if (!request.edges && overlays_) {
        std::uint32_t overlay_count = 0;
        const auto overlay_result = overlays_->overlay_count(
            gen, k_graph_document_max_overlays, cancellation, overlay_count);
        if (cancellation_requested(cancellation) ||
            overlay_result == graph_source_result_t::cancelled) {
            return fail(graph_error_code_t::cancelled, request.offset);
        }
        if (!source_->generation_current(gen))
            return stale();
        if (overlay_result == graph_source_result_t::limit_exceeded ||
            overlay_count > k_graph_document_max_overlays) {
            return fail(graph_error_code_t::resource_exhausted,
                        overlay_count > k_graph_document_max_overlays
                            ? overlay_count
                            : k_graph_document_max_overlays + 1U);
        }
        if (overlay_result != graph_source_result_t::success)
            return fail(graph_error_code_t::adapter_rejected, gen);
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
        std::unordered_set<std::uint64_t> page_ids;
        page_ids.reserve(static_cast<std::size_t>(to_read));
        for (std::uint64_t i = 0; i < to_read; ++i) {
            if (cancellation_requested(cancellation)) {
                output = {};
                return fail(graph_error_code_t::cancelled, i);
            }
            graph_edge_view_t edge;
            const auto ordinal = request.offset + i;
            const auto source_result = source_->edge_at(
                gen, request.graph_kind, request.function_address, ordinal,
                limits, cancellation, edge);
            if (cancellation_requested(cancellation) ||
                source_result == graph_source_result_t::cancelled) {
                output = {};
                return fail(graph_error_code_t::cancelled, ordinal);
            }
            if (source_result == graph_source_result_t::limit_exceeded) {
                output = {};
                return fail(graph_error_code_t::graph_too_large, ordinal);
            }
            if (source_result != graph_source_result_t::success ||
                !graph_edge_valid(edge)) {
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
            if (edge.id != expected_id ||
                !page_ids.insert(edge.id.value).second) {
                output = {};
                return fail(graph_error_code_t::adapter_rejected, ordinal);
            }
            output.edges.push_back(std::move(edge));
        }
        output.next_offset = request.offset + output.edges.size();
    } else {
        output.nodes.reserve(static_cast<std::size_t>(to_read));
        std::unordered_set<std::uint64_t> page_ids;
        page_ids.reserve(static_cast<std::size_t>(to_read));
        for (std::uint64_t i = 0; i < to_read; ++i) {
            if (cancellation_requested(cancellation)) {
                output = {};
                return fail(graph_error_code_t::cancelled, i);
            }
            graph_node_view_t node;
            const auto ordinal = request.offset + i;
            const auto source_result = source_->node_at(
                gen, request.graph_kind, request.function_address, ordinal,
                limits, cancellation, node);
            if (cancellation_requested(cancellation) ||
                source_result == graph_source_result_t::cancelled) {
                output = {};
                return fail(graph_error_code_t::cancelled, ordinal);
            }
            if (source_result == graph_source_result_t::limit_exceeded) {
                output = {};
                return fail(graph_error_code_t::graph_too_large, ordinal);
            }
            if (source_result != graph_source_result_t::success ||
                !graph_node_valid(node) ||
                !page_ids.insert(node.id.value).second) {
                output = {};
                return fail(graph_error_code_t::adapter_rejected, ordinal);
            }
            if (!source_->generation_current(gen)) {
                output = {};
                return stale();
            }
            if (overlays_) {
                std::string projected_label;
                const auto overlay_result = overlays_->overlay_node(
                    gen, node.id, k_graph_document_max_label_bytes,
                    cancellation, projected_label);
                if (cancellation_requested(cancellation) ||
                    overlay_result == graph_source_result_t::cancelled) {
                    output = {};
                    return fail(graph_error_code_t::cancelled, ordinal);
                }
                if (overlay_result == graph_source_result_t::limit_exceeded) {
                    output = {};
                    return fail(graph_error_code_t::resource_exhausted,
                                projected_label.size() >
                                        k_graph_document_max_label_bytes
                                    ? projected_label.size()
                                    : k_graph_document_max_label_bytes + 1U);
                }
                if (overlay_result == graph_source_result_t::success) {
                    if (projected_label.size() > k_graph_document_max_label_bytes) {
                        output = {};
                        return fail(graph_error_code_t::resource_exhausted,
                                    projected_label.size());
                    }
                    node.label = std::move(projected_label);
                } else if (overlay_result != graph_source_result_t::not_found) {
                    output = {};
                    return fail(graph_error_code_t::adapter_rejected, ordinal);
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
    graph_navigation_result_t& output,
    const graph_cancellation_t* cancellation)
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
    if (cancellation_requested(cancellation))
        return fail(graph_error_code_t::cancelled, request.address);

    const graph_source_limits_t limits;
    graph_source_counts_t counts;
    const auto counts_error = read_counts(
        bound_generation_, kind, function_address, limits, cancellation,
        graph_error_code_t::graph_too_large, counts);
    if (!counts_error.ok())
        return counts_error;

    graph_node_view_t node;
    std::uint64_t ordinal = 0;
    const auto source_result = source_->node_by_address(
        bound_generation_, kind, function_address, request.address, limits,
        cancellation, node, ordinal);
    if (cancellation_requested(cancellation) ||
        source_result == graph_source_result_t::cancelled) {
        return fail(graph_error_code_t::cancelled, request.address);
    }
    if (!source_->generation_current(bound_generation_))
        return stale();
    if (source_result == graph_source_result_t::not_found)
        return fail(graph_error_code_t::node_not_found, request.address);
    if (source_result == graph_source_result_t::limit_exceeded)
        return fail(graph_error_code_t::graph_too_large, counts.nodes);
    if (source_result != graph_source_result_t::success ||
        ordinal >= counts.nodes || !graph_node_valid(node) ||
        node.address == 0) {
        return fail(graph_error_code_t::adapter_rejected, ordinal);
    }

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
    const graph_selection_t& selection, std::uint64_t expected_generation,
    const graph_cancellation_t* cancellation)
{
    if (expected_generation != bound_generation_ ||
        !source_->generation_current(bound_generation_))
        return stale();
    if (!graph_selection_valid(selection))
        return fail(graph_error_code_t::selection_rejected,
                    static_cast<std::uint64_t>(selection.kind));
    if (selection.kind == selection_kind_t::none) {
        selection_ = {};
        return {};
    }
    if (cancellation_requested(cancellation))
        return fail(graph_error_code_t::cancelled,
                    static_cast<std::uint64_t>(selection.kind));
    const graph_kind_t kinds[] = {graph_kind_t::cfg, graph_kind_t::call_graph,
                                  graph_kind_t::data_flow, graph_kind_t::custom};
    for (const auto kind : kinds) {
        if (!source_->supports_kind(kind))
            continue;
        graph_selection_t canonical;
        const auto error = canonicalize_selection(
            selection, kind, 0, cancellation, canonical);
        if (error.ok()) {
            selection_ = std::move(canonical);
            return {};
        }
        if (error.code != graph_error_code_t::node_not_found &&
            error.code != graph_error_code_t::edge_not_found &&
            error.code != graph_error_code_t::selection_rejected) {
            return error;
        }
    }
    return fail(graph_error_code_t::selection_rejected,
                static_cast<std::uint64_t>(selection.kind));
}

graph_error_t graph_document_model_t::select(
    const graph_selection_t& selection,
    std::uint64_t expected_generation,
    graph_kind_t kind,
    std::uint64_t function_address,
    const graph_cancellation_t* cancellation)
{
    if (expected_generation != bound_generation_ ||
        !source_->generation_current(bound_generation_))
        return stale();
    if (!source_->supports_kind(kind))
        return fail(graph_error_code_t::adapter_rejected,
                    static_cast<std::uint64_t>(kind));
    graph_selection_t canonical;
    const auto error = canonicalize_selection(
        selection, kind, function_address, cancellation, canonical);
    if (!error.ok())
        return error;
    selection_ = std::move(canonical);
    return {};
}

graph_error_t graph_document_model_t::canonicalize_selection(
    const graph_selection_t& selection,
    graph_kind_t kind,
    std::uint64_t function_address,
    const graph_cancellation_t* cancellation,
    graph_selection_t& output) const
{
    output = {};
    if (!graph_selection_valid(selection))
        return fail(graph_error_code_t::selection_rejected,
                    static_cast<std::uint64_t>(selection.kind));
    if (selection.kind == selection_kind_t::none)
        return {};
    if (cancellation_requested(cancellation))
        return fail(graph_error_code_t::cancelled,
                    static_cast<std::uint64_t>(selection.kind));

    const graph_source_limits_t limits;
    graph_source_counts_t counts;
    const auto counts_error = read_counts(
        bound_generation_, kind, function_address, limits, cancellation,
        graph_error_code_t::graph_too_large, counts);
    if (!counts_error.ok())
        return counts_error;

    graph_node_view_t node;
    graph_edge_view_t edge;
    std::uint64_t ordinal = 0;
    graph_source_result_t source_result = graph_source_result_t::rejected;
    if (selection.kind == selection_kind_t::address) {
        source_result = source_->node_by_address(
            bound_generation_, kind, function_address, selection.address,
            limits, cancellation, node, ordinal);
        if (cancellation_requested(cancellation) ||
            source_result == graph_source_result_t::cancelled)
            return fail(graph_error_code_t::cancelled, selection.address);
        if (!source_->generation_current(bound_generation_))
            return stale();
        if (source_result == graph_source_result_t::not_found)
            return fail(graph_error_code_t::selection_rejected,
                        selection.address);
        if (source_result == graph_source_result_t::limit_exceeded)
            return fail(graph_error_code_t::graph_too_large, counts.nodes);
        if (source_result != graph_source_result_t::success ||
            ordinal >= counts.nodes)
            return fail(graph_error_code_t::adapter_rejected, ordinal);
        if (!graph_node_valid(node) || node.address == 0 ||
            (selection.node.valid() && selection.node != node.id))
            return fail(graph_error_code_t::selection_rejected, selection.address);
        output = selection;
        output.node = node.id;
        output.address = node.address;
    } else if (selection.node.valid()) {
        source_result = source_->node_by_id(
            bound_generation_, kind, function_address, selection.node,
            limits, cancellation, node, ordinal);
        if (cancellation_requested(cancellation) ||
            source_result == graph_source_result_t::cancelled)
            return fail(graph_error_code_t::cancelled, selection.node.value);
        if (!source_->generation_current(bound_generation_))
            return stale();
        if (source_result == graph_source_result_t::not_found)
            return fail(graph_error_code_t::node_not_found,
                        selection.node.value);
        if (source_result == graph_source_result_t::limit_exceeded)
            return fail(graph_error_code_t::graph_too_large, counts.nodes);
        if (source_result != graph_source_result_t::success ||
            ordinal >= counts.nodes)
            return fail(graph_error_code_t::adapter_rejected, ordinal);
        if (!graph_node_valid(node) || node.id != selection.node ||
            (selection.has_address && selection.address != node.address))
            return fail(graph_error_code_t::selection_rejected,
                        selection.node.value);
        output = selection;
        output.has_address = node.address != 0;
        output.address = node.address;
    } else {
        source_result = source_->edge_by_id(
            bound_generation_, kind, function_address, selection.edge,
            limits, cancellation, edge, ordinal);
        if (cancellation_requested(cancellation) ||
            source_result == graph_source_result_t::cancelled)
            return fail(graph_error_code_t::cancelled, selection.edge.value);
        if (!source_->generation_current(bound_generation_))
            return stale();
        if (source_result == graph_source_result_t::not_found)
            return fail(graph_error_code_t::edge_not_found,
                        selection.edge.value);
        if (source_result == graph_source_result_t::limit_exceeded)
            return fail(graph_error_code_t::graph_too_large, counts.edges);
        if (source_result != graph_source_result_t::success ||
            ordinal >= counts.edges)
            return fail(graph_error_code_t::adapter_rejected, ordinal);
        const auto expected_id = compute_deterministic_edge_id(
            {edge.source, edge.target, edge.kind, edge.site_address,
             edge.parallel_ordinal});
        if (!graph_edge_valid(edge) || edge.id != selection.edge ||
            edge.id != expected_id ||
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
    const graph_source_counts_t& counts,
    const graph_layout_cancellation_t* cancellation,
    graph_layout_t& output) const
{
    const auto nc = counts.nodes;
    const auto ec = counts.edges;
    const graph_source_limits_t limits;
    output.snapshot_generation = generation;
    output.graph_kind = kind;
    output.node_count = static_cast<std::uint32_t>(nc);
    output.edge_count = static_cast<std::uint32_t>(ec);
    std::uint64_t subject = 0;

    auto cancelled = [&]() {
        output.cancelled = true;
        output.complete = false;
        return fail(graph_error_code_t::layout_cancelled, subject);
    };

    if (cancellation_requested(cancellation))
        return cancelled();

    std::vector<graph_node_id_t> nodes;
    nodes.reserve(static_cast<std::size_t>(nc));
    std::unordered_set<std::uint64_t> node_ids;
    node_ids.reserve(static_cast<std::size_t>(nc));
    for (std::uint64_t i = 0; i < nc; ++i) {
        if (cancellation_requested(cancellation))
            return cancelled();
        graph_node_view_t node;
        const auto source_result = source_->node_at(
            generation, kind, function_address, i, limits, cancellation, node);
        if (cancellation_requested(cancellation) ||
            source_result == graph_source_result_t::cancelled)
            return cancelled();
        if (!source_->generation_current(bound_generation_)) {
            output = {};
            return stale();
        }
        if (source_result == graph_source_result_t::limit_exceeded)
            return fail(graph_error_code_t::graph_too_large, i);
        if (source_result != graph_source_result_t::success ||
            !graph_node_valid(node) ||
            !node_ids.insert(node.id.value).second) {
            return fail(graph_error_code_t::adapter_rejected, i);
        }
        nodes.push_back(node.id);
        increment_subject(subject);
    }

    if (!cancellable_sort(
            nodes,
            [](graph_node_id_t lhs, graph_node_id_t rhs) { return lhs < rhs; },
            cancellation, subject))
        return cancelled();

    struct edge_record_t {
        graph_edge_id_t id;
        graph_node_id_t source;
        graph_node_id_t target;
        graph_edge_kind_t kind = graph_edge_kind_t::unconditional;
        std::uint64_t site_address = 0;
        std::uint64_t parallel_ordinal = 0;
    };

    std::vector<edge_record_t> edges;
    edges.reserve(static_cast<std::size_t>(ec));
    std::unordered_set<std::uint64_t> edge_ids;
    edge_ids.reserve(static_cast<std::size_t>(ec));
    for (std::uint64_t i = 0; i < ec; ++i) {
        if (cancellation_requested(cancellation))
            return cancelled();
        graph_edge_view_t edge;
        const auto source_result = source_->edge_at(
            generation, kind, function_address, i, limits, cancellation, edge);
        if (cancellation_requested(cancellation) ||
            source_result == graph_source_result_t::cancelled)
            return cancelled();
        if (!source_->generation_current(bound_generation_)) {
            output = {};
            return stale();
        }
        if (source_result == graph_source_result_t::limit_exceeded)
            return fail(graph_error_code_t::graph_too_large, i);
        if (source_result != graph_source_result_t::success ||
            !graph_edge_valid(edge)) {
            return fail(graph_error_code_t::adapter_rejected, i);
        }
        const auto expected_id = compute_deterministic_edge_id(
            {edge.source, edge.target, edge.kind, edge.site_address,
             edge.parallel_ordinal});
        if (edge.id != expected_id ||
            !edge_ids.insert(edge.id.value).second)
            return fail(graph_error_code_t::adapter_rejected, i);
        edges.push_back({edge.id, edge.source, edge.target, edge.kind,
                         edge.site_address, edge.parallel_ordinal});
        increment_subject(subject);
    }

    const auto edge_less = [](const edge_record_t& lhs,
                              const edge_record_t& rhs) {
        return std::tie(lhs.source.value, lhs.target.value, lhs.kind,
                        lhs.site_address, lhs.parallel_ordinal, lhs.id.value) <
               std::tie(rhs.source.value, rhs.target.value, rhs.kind,
                        rhs.site_address, rhs.parallel_ordinal, rhs.id.value);
    };
    if (!cancellable_sort(edges, edge_less, cancellation, subject))
        return cancelled();

    std::tuple<std::uint64_t, std::uint64_t, graph_edge_kind_t,
               std::uint64_t> previous_identity{};
    bool have_previous_identity = false;
    std::uint64_t expected_parallel_ordinal = 0;
    output.edges.reserve(static_cast<std::size_t>(ec));
    for (const auto& edge : edges) {
        if (cancellation_requested(cancellation))
            return cancelled();
        const auto identity = std::make_tuple(
            edge.source.value, edge.target.value, edge.kind,
            edge.site_address);
        if (!have_previous_identity || identity != previous_identity) {
            expected_parallel_ordinal = 0;
            previous_identity = identity;
            have_previous_identity = true;
        } else {
            increment_subject(expected_parallel_ordinal);
        }
        if (edge.parallel_ordinal != expected_parallel_ordinal)
            return fail(graph_error_code_t::adapter_rejected, edge.id.value);
        graph_layout_edge_t layout_edge;
        layout_edge.id = edge.id;
        layout_edge.source = edge.source;
        layout_edge.target = edge.target;
        output.edges.push_back(std::move(layout_edge));
        increment_subject(subject);
    }

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
            return cancelled();
        const auto& edge = edges[i];
        auto src_idx = find_node_index(edge.source);
        auto tgt_idx = find_node_index(edge.target);
        if (src_idx >= nodes.size() || tgt_idx >= nodes.size())
            return fail(graph_error_code_t::adapter_rejected, edge.id.value);
        successors[src_idx].push_back(tgt_idx);
        increment_subject(subject);
    }

    for (std::size_t i = 0; i < successors.size(); ++i) {
        if (cancellation_requested(cancellation))
            return cancelled();
        auto& adjacent = successors[i];
        if (!cancellable_sort(
                adjacent,
                [](std::uint64_t lhs, std::uint64_t rhs) { return lhs < rhs; },
                cancellation, subject))
            return cancelled();
        std::size_t write = 0;
        for (std::size_t read = 0; read < adjacent.size(); ++read) {
            if (cancellation_requested(cancellation))
                return cancelled();
            if (write == 0 || adjacent[read] != adjacent[write - 1])
                adjacent[write++] = adjacent[read];
            increment_subject(subject);
        }
        adjacent.resize(write);
    }

    std::vector<std::uint32_t> layer(nodes.size(), 0);
    std::vector<bool> visited(nodes.size(), false);
    std::vector<std::uint64_t> stack;
    stack.reserve(nodes.size());
    for (std::uint64_t i = 0; i < nodes.size(); ++i) {
        if (cancellation_requested(cancellation))
            return cancelled();
        if (visited[i])
            continue;
        stack.push_back(i);
        while (!stack.empty()) {
            if (cancellation_requested(cancellation))
                return cancelled();
            auto idx = stack.back();
            stack.pop_back();
            if (idx >= nodes.size() || visited[idx])
                continue;
            visited[idx] = true;
            increment_subject(subject);
            for (auto tgt : successors[idx]) {
                if (cancellation_requested(cancellation))
                    return cancelled();
                if (tgt < nodes.size() && !visited[tgt]) {
                    layer[tgt] = (std::max)(layer[tgt], layer[idx] + 1);
                    stack.push_back(tgt);
                }
                increment_subject(subject);
            }
        }
    }

    std::uint32_t max_layer = 0;
    for (std::size_t i = 0; i < layer.size(); ++i) {
        if (cancellation_requested(cancellation))
            return cancelled();
        max_layer = (std::max)(max_layer, layer[i]);
        increment_subject(subject);
    }

    const float layer_height = request.canvas_height / (max_layer + 2);
    const float node_width = 120.0f;
    const float node_height = 40.0f;

    std::vector<std::uint32_t> nodes_per_layer(max_layer + 1, 0);
    for (std::size_t i = 0; i < layer.size(); ++i) {
        if (cancellation_requested(cancellation))
            return cancelled();
        ++nodes_per_layer[layer[i]];
        increment_subject(subject);
    }

    std::vector<std::uint32_t> layer_cursor(max_layer + 1, 0);
    output.nodes.reserve(nodes.size());
    for (std::uint64_t i = 0; i < nodes.size(); ++i) {
        if (cancellation_requested(cancellation))
            return cancelled();
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
        increment_subject(subject);
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
    if (cancellation_requested(cancellation)) {
        output.snapshot_generation = gen;
        output.graph_kind = request.graph_kind;
        output.cancelled = true;
        last_layout_ = output;
        return fail(graph_error_code_t::layout_cancelled, 0);
    }

    const graph_source_limits_t limits;
    graph_source_counts_t counts;
    const auto counts_error = read_counts(
        gen, request.graph_kind, request.function_address, limits,
        cancellation, graph_error_code_t::graph_too_large, counts);
    if (!counts_error.ok()) {
        output.snapshot_generation = gen;
        output.graph_kind = request.graph_kind;
        if (counts_error.code == graph_error_code_t::cancelled) {
            output.cancelled = true;
            last_layout_ = output;
            return fail(graph_error_code_t::layout_cancelled,
                        counts_error.subject);
        }
        last_layout_ = output;
        return counts_error;
    }

    output.snapshot_generation = gen;
    output.graph_kind = request.graph_kind;
    output.node_count = static_cast<std::uint32_t>(counts.nodes);
    output.edge_count = static_cast<std::uint32_t>(counts.edges);

    if (cancellation_requested(cancellation)) {
        output.cancelled = true;
        last_layout_ = output;
        return fail(graph_error_code_t::layout_cancelled, 0);
    }

    if (counts.nodes > request.max_nodes || counts.edges > request.max_edges) {
        output.cancelled = false;
        output.complete = false;
        last_layout_ = output;
        return fail(graph_error_code_t::layout_capacity,
                    counts.nodes > request.max_nodes ? counts.nodes
                                                     : counts.edges);
    }

    const auto error = layout_layered(gen, request.graph_kind,
                                      request.function_address, request,
                                      counts, cancellation, output);
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
    const auto cancelled_error = [this, &output](std::uint64_t subject) {
        output = {};
        return fail(graph_error_code_t::cancelled, subject);
    };
    if (cancellation_requested(cancellation))
        return cancelled_error(0);

    const graph_source_limits_t limits;
    graph_source_counts_t old_counts;
    graph_source_counts_t new_counts;
    auto counts_error = read_counts(
        old_generation, kind, function_address, limits, cancellation,
        graph_error_code_t::graph_too_large, old_counts);
    if (!counts_error.ok())
        return counts_error.code == graph_error_code_t::cancelled
            ? cancelled_error(counts_error.subject) : counts_error;
    counts_error = read_counts(
        new_generation, kind, function_address, limits, cancellation,
        graph_error_code_t::graph_too_large, new_counts);
    if (!counts_error.ok())
        return counts_error.code == graph_error_code_t::cancelled
            ? cancelled_error(counts_error.subject) : counts_error;

    const auto old_nc = old_counts.nodes;
    const auto new_nc = new_counts.nodes;
    const auto old_ec = old_counts.edges;
    const auto new_ec = new_counts.edges;

    if (overlays_) {
        std::uint32_t old_overlay_count = 0;
        std::uint32_t new_overlay_count = 0;
        const auto old_overlay_result = overlays_->overlay_count(
            old_generation, k_graph_document_max_overlays, cancellation,
            old_overlay_count);
        if (cancellation_requested(cancellation) ||
            old_overlay_result == graph_source_result_t::cancelled)
            return cancelled_error(0);
        const auto new_overlay_result = overlays_->overlay_count(
            new_generation, k_graph_document_max_overlays, cancellation,
            new_overlay_count);
        if (cancellation_requested(cancellation) ||
            new_overlay_result == graph_source_result_t::cancelled)
            return cancelled_error(0);
        if (!source_->generation_current(bound_generation_)) {
            output = {};
            return stale();
        }
        if ((old_overlay_result != graph_source_result_t::success &&
             old_overlay_result != graph_source_result_t::limit_exceeded) ||
            (new_overlay_result != graph_source_result_t::success &&
             new_overlay_result != graph_source_result_t::limit_exceeded)) {
            return fail(graph_error_code_t::adapter_rejected, old_generation);
        }
        if (old_overlay_count > k_graph_document_max_overlays ||
            new_overlay_count > k_graph_document_max_overlays ||
            old_overlay_result == graph_source_result_t::limit_exceeded ||
            new_overlay_result == graph_source_result_t::limit_exceeded) {
            const auto reported = (std::max)(old_overlay_count,
                                              new_overlay_count);
            return fail(graph_error_code_t::resource_exhausted,
                        reported > k_graph_document_max_overlays
                            ? reported
                            : k_graph_document_max_overlays + 1U);
        }
    }

    std::uint64_t reserve_count = 0;
    const auto add_reserve = [&reserve_count](std::uint64_t value) {
        if (value > k_graph_document_max_diff_entries - reserve_count)
            return false;
        reserve_count += value;
        return true;
    };
    if (!add_reserve(old_nc) || !add_reserve(new_nc) ||
        !add_reserve(old_ec) || !add_reserve(new_ec)) {
        return fail(graph_error_code_t::resource_exhausted, reserve_count);
    }
    if (cancellation_requested(cancellation))
        return cancelled_error(0);
    output.entries.reserve(static_cast<std::size_t>(reserve_count));

    std::vector<graph_node_view_t> old_nodes;
    std::vector<graph_node_view_t> new_nodes;
    old_nodes.reserve(static_cast<std::size_t>(old_nc));
    new_nodes.reserve(static_cast<std::size_t>(new_nc));
    std::unordered_set<std::uint64_t> old_node_ids;
    std::unordered_set<std::uint64_t> new_node_ids;
    old_node_ids.reserve(static_cast<std::size_t>(old_nc));
    new_node_ids.reserve(static_cast<std::size_t>(new_nc));
    std::uint64_t work_subject = 0;

    for (std::uint64_t i = 0; i < old_nc; ++i) {
        if (cancellation_requested(cancellation))
            return cancelled_error(work_subject);
        graph_node_view_t node;
        const auto source_result = source_->node_at(
            old_generation, kind, function_address, i, limits,
            cancellation, node);
        if (cancellation_requested(cancellation) ||
            source_result == graph_source_result_t::cancelled)
            return cancelled_error(work_subject);
        if (!source_->generation_current(bound_generation_)) {
            output = {};
            return stale();
        }
        if (source_result == graph_source_result_t::limit_exceeded)
            return fail(graph_error_code_t::graph_too_large, i);
        if (source_result != graph_source_result_t::success ||
            !graph_node_valid(node) ||
            !old_node_ids.insert(node.id.value).second) {
            return fail(graph_error_code_t::adapter_rejected, i);
        }
        if (overlays_) {
            std::string projected_label;
            const auto overlay_result = overlays_->overlay_node(
                old_generation, node.id, k_graph_document_max_label_bytes,
                cancellation, projected_label);
            if (cancellation_requested(cancellation) ||
                overlay_result == graph_source_result_t::cancelled)
                return cancelled_error(work_subject);
            if (!source_->generation_current(bound_generation_)) {
                output = {};
                return stale();
            }
            if (overlay_result == graph_source_result_t::limit_exceeded)
                return fail(graph_error_code_t::resource_exhausted,
                            projected_label.size() >
                                    k_graph_document_max_label_bytes
                                ? projected_label.size()
                                : k_graph_document_max_label_bytes + 1U);
            if (overlay_result == graph_source_result_t::success) {
                if (projected_label.size() > k_graph_document_max_label_bytes)
                    return fail(graph_error_code_t::resource_exhausted,
                                projected_label.size());
                node.label = std::move(projected_label);
            } else if (overlay_result != graph_source_result_t::not_found) {
                return fail(graph_error_code_t::adapter_rejected, i);
            }
        }
        old_nodes.push_back(std::move(node));
        increment_subject(work_subject);
    }
    for (std::uint64_t i = 0; i < new_nc; ++i) {
        if (cancellation_requested(cancellation))
            return cancelled_error(work_subject);
        graph_node_view_t node;
        const auto source_result = source_->node_at(
            new_generation, kind, function_address, i, limits,
            cancellation, node);
        if (cancellation_requested(cancellation) ||
            source_result == graph_source_result_t::cancelled)
            return cancelled_error(work_subject);
        if (!source_->generation_current(bound_generation_)) {
            output = {};
            return stale();
        }
        if (source_result == graph_source_result_t::limit_exceeded)
            return fail(graph_error_code_t::graph_too_large, i);
        if (source_result != graph_source_result_t::success ||
            !graph_node_valid(node) ||
            !new_node_ids.insert(node.id.value).second) {
            return fail(graph_error_code_t::adapter_rejected, i);
        }
        if (overlays_) {
            std::string projected_label;
            const auto overlay_result = overlays_->overlay_node(
                new_generation, node.id, k_graph_document_max_label_bytes,
                cancellation, projected_label);
            if (cancellation_requested(cancellation) ||
                overlay_result == graph_source_result_t::cancelled)
                return cancelled_error(work_subject);
            if (!source_->generation_current(bound_generation_)) {
                output = {};
                return stale();
            }
            if (overlay_result == graph_source_result_t::limit_exceeded)
                return fail(graph_error_code_t::resource_exhausted,
                            projected_label.size() >
                                    k_graph_document_max_label_bytes
                                ? projected_label.size()
                                : k_graph_document_max_label_bytes + 1U);
            if (overlay_result == graph_source_result_t::success) {
                if (projected_label.size() > k_graph_document_max_label_bytes)
                    return fail(graph_error_code_t::resource_exhausted,
                                projected_label.size());
                node.label = std::move(projected_label);
            } else if (overlay_result != graph_source_result_t::not_found) {
                return fail(graph_error_code_t::adapter_rejected, i);
            }
        }
        new_nodes.push_back(std::move(node));
        increment_subject(work_subject);
    }

    const auto node_less = [](const graph_node_view_t& lhs,
                              const graph_node_view_t& rhs) {
        return lhs.id < rhs.id;
    };
    if (!cancellable_sort(old_nodes, node_less, cancellation, work_subject) ||
        !cancellable_sort(new_nodes, node_less, cancellation, work_subject))
        return cancelled_error(work_subject);

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
            return cancelled_error(work_subject);
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
        increment_subject(work_subject);
    }
    while (oi < old_nodes.size()) {
        if (cancellation_requested(cancellation))
            return cancelled_error(work_subject);
        graph_diff_entry_t entry;
        entry.kind = graph_diff_entry_t::kind_t::node_removed;
        entry.node = old_nodes[oi].id;
        entry.address = old_nodes[oi].address;
        entry.label = old_nodes[oi].label;
        if (!append_entry(std::move(entry)))
            return fail(graph_error_code_t::resource_exhausted,
                        output.entries.size());
        ++oi;
        increment_subject(work_subject);
    }
    while (ni < new_nodes.size()) {
        if (cancellation_requested(cancellation))
            return cancelled_error(work_subject);
        graph_diff_entry_t entry;
        entry.kind = graph_diff_entry_t::kind_t::node_added;
        entry.node = new_nodes[ni].id;
        entry.address = new_nodes[ni].address;
        entry.label = new_nodes[ni].label;
        if (!append_entry(std::move(entry)))
            return fail(graph_error_code_t::resource_exhausted,
                        output.entries.size());
        ++ni;
        increment_subject(work_subject);
    }

    struct edge_key_t {
        graph_edge_id_t id;
        graph_node_id_t source;
        graph_node_id_t target;
        graph_edge_kind_t kind = graph_edge_kind_t::unconditional;
        std::uint64_t site_address = 0;
        std::uint64_t parallel_ordinal = 0;
        std::string label;
    };

    std::vector<edge_key_t> old_edges;
    std::vector<edge_key_t> new_edges;
    old_edges.reserve(static_cast<std::size_t>(old_ec));
    new_edges.reserve(static_cast<std::size_t>(new_ec));
    std::unordered_set<std::uint64_t> old_edge_ids;
    std::unordered_set<std::uint64_t> new_edge_ids;
    old_edge_ids.reserve(static_cast<std::size_t>(old_ec));
    new_edge_ids.reserve(static_cast<std::size_t>(new_ec));

    for (std::uint64_t i = 0; i < old_ec; ++i) {
        if (cancellation_requested(cancellation))
            return cancelled_error(work_subject);
        graph_edge_view_t edge;
        const auto source_result = source_->edge_at(
            old_generation, kind, function_address, i, limits,
            cancellation, edge);
        if (cancellation_requested(cancellation) ||
            source_result == graph_source_result_t::cancelled)
            return cancelled_error(work_subject);
        if (!source_->generation_current(bound_generation_)) {
            output = {};
            return stale();
        }
        if (source_result == graph_source_result_t::limit_exceeded)
            return fail(graph_error_code_t::graph_too_large, i);
        if (source_result != graph_source_result_t::success ||
            !graph_edge_valid(edge)) {
            return fail(graph_error_code_t::adapter_rejected, i);
        }
        const auto expected_id = compute_deterministic_edge_id(
            {edge.source, edge.target, edge.kind, edge.site_address,
             edge.parallel_ordinal});
        if (edge.id != expected_id ||
            !old_edge_ids.insert(edge.id.value).second)
            return fail(graph_error_code_t::adapter_rejected, i);
        old_edges.push_back({edge.id, edge.source, edge.target, edge.kind,
                             edge.site_address, edge.parallel_ordinal,
                             std::move(edge.label)});
        increment_subject(work_subject);
    }
    for (std::uint64_t i = 0; i < new_ec; ++i) {
        if (cancellation_requested(cancellation))
            return cancelled_error(work_subject);
        graph_edge_view_t edge;
        const auto source_result = source_->edge_at(
            new_generation, kind, function_address, i, limits,
            cancellation, edge);
        if (cancellation_requested(cancellation) ||
            source_result == graph_source_result_t::cancelled)
            return cancelled_error(work_subject);
        if (!source_->generation_current(bound_generation_)) {
            output = {};
            return stale();
        }
        if (source_result == graph_source_result_t::limit_exceeded)
            return fail(graph_error_code_t::graph_too_large, i);
        if (source_result != graph_source_result_t::success ||
            !graph_edge_valid(edge)) {
            return fail(graph_error_code_t::adapter_rejected, i);
        }
        const auto expected_id = compute_deterministic_edge_id(
            {edge.source, edge.target, edge.kind, edge.site_address,
             edge.parallel_ordinal});
        if (edge.id != expected_id ||
            !new_edge_ids.insert(edge.id.value).second)
            return fail(graph_error_code_t::adapter_rejected, i);
        new_edges.push_back({edge.id, edge.source, edge.target, edge.kind,
                             edge.site_address, edge.parallel_ordinal,
                             std::move(edge.label)});
        increment_subject(work_subject);
    }

    const auto edge_less = [](const edge_key_t& lhs, const edge_key_t& rhs) {
        return std::tie(lhs.source.value, lhs.target.value, lhs.kind,
                        lhs.site_address, lhs.parallel_ordinal) <
               std::tie(rhs.source.value, rhs.target.value, rhs.kind,
                        rhs.site_address, rhs.parallel_ordinal);
    };
    if (!cancellable_sort(old_edges, edge_less, cancellation, work_subject) ||
        !cancellable_sort(new_edges, edge_less, cancellation, work_subject))
        return cancelled_error(work_subject);

    const auto validate_parallel_edges = [&](const auto& edges,
                                             std::uint64_t& invalid_id) {
        std::tuple<std::uint64_t, std::uint64_t, graph_edge_kind_t,
                   std::uint64_t> previous{};
        bool have_previous = false;
        std::uint64_t expected = 0;
        for (const auto& edge : edges) {
            if (cancellation_requested(cancellation))
                return false;
            const auto identity = std::make_tuple(
                edge.source.value, edge.target.value, edge.kind,
                edge.site_address);
            if (!have_previous || identity != previous) {
                expected = 0;
                previous = identity;
                have_previous = true;
            } else {
                increment_subject(expected);
            }
            if (edge.parallel_ordinal != expected) {
                invalid_id = edge.id.value;
                return false;
            }
            increment_subject(work_subject);
        }
        return true;
    };
    std::uint64_t invalid_edge_id = 0;
    if (!validate_parallel_edges(old_edges, invalid_edge_id) ||
        !validate_parallel_edges(new_edges, invalid_edge_id)) {
        if (cancellation_requested(cancellation))
            return cancelled_error(work_subject);
        return fail(graph_error_code_t::adapter_rejected, invalid_edge_id);
    }

    oi = 0; ni = 0;
    while (oi < old_edges.size() && ni < new_edges.size()) {
        if (cancellation_requested(cancellation))
            return cancelled_error(work_subject);
        if (edge_less(old_edges[oi], new_edges[ni])) {
            graph_diff_entry_t entry;
            entry.kind = graph_diff_entry_t::kind_t::edge_removed;
            entry.edge = old_edges[oi].id;
            entry.address = old_edges[oi].site_address;
            entry.label = old_edges[oi].label;
            if (!append_entry(std::move(entry)))
                return fail(graph_error_code_t::resource_exhausted,
                            output.entries.size());
            ++oi;
        } else if (edge_less(new_edges[ni], old_edges[oi])) {
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
        increment_subject(work_subject);
    }
    while (oi < old_edges.size()) {
        if (cancellation_requested(cancellation))
            return cancelled_error(work_subject);
        graph_diff_entry_t entry;
        entry.kind = graph_diff_entry_t::kind_t::edge_removed;
        entry.edge = old_edges[oi].id;
        entry.address = old_edges[oi].site_address;
        entry.label = old_edges[oi].label;
        if (!append_entry(std::move(entry)))
            return fail(graph_error_code_t::resource_exhausted,
                        output.entries.size());
        ++oi;
        increment_subject(work_subject);
    }
    while (ni < new_edges.size()) {
        if (cancellation_requested(cancellation))
            return cancelled_error(work_subject);
        graph_diff_entry_t entry;
        entry.kind = graph_diff_entry_t::kind_t::edge_added;
        entry.edge = new_edges[ni].id;
        entry.address = new_edges[ni].site_address;
        entry.label = new_edges[ni].label;
        if (!append_entry(std::move(entry)))
            return fail(graph_error_code_t::resource_exhausted,
                        output.entries.size());
        ++ni;
        increment_subject(work_subject);
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

graph_error_t graph_document_model_t::counts(
    graph_kind_t kind, std::uint64_t function_address,
    const graph_cancellation_t* cancellation,
    graph_source_counts_t& output) const
{
    output = {};
    if (!graph_kind_valid(kind))
        return fail(graph_error_code_t::invalid_argument,
                    static_cast<std::uint64_t>(kind));
    if (!source_->generation_current(bound_generation_))
        return stale();
    if (!source_->supports_kind(kind))
        return fail(graph_error_code_t::adapter_rejected,
                    static_cast<std::uint64_t>(kind));
    const graph_source_limits_t limits;
    return read_counts(bound_generation_, kind, function_address, limits,
                       cancellation, graph_error_code_t::graph_too_large,
                       output);
}

std::uint64_t graph_document_model_t::node_count(
    graph_kind_t kind, std::uint64_t function_address) const noexcept
{
    try {
        graph_source_counts_t source_counts;
        const auto error = counts(kind, function_address, nullptr,
                                  source_counts);
        return error.ok() ? source_counts.nodes : 0;
    } catch (...) {
        return 0;
    }
}

std::uint64_t graph_document_model_t::edge_count(
    graph_kind_t kind, std::uint64_t function_address) const noexcept
{
    try {
        graph_source_counts_t source_counts;
        const auto error = counts(kind, function_address, nullptr,
                                  source_counts);
        return error.ok() ? source_counts.edges : 0;
    } catch (...) {
        return 0;
    }
}

}
}
}
