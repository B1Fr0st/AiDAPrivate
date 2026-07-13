#pragma once

#include "../workbench_contracts.h"

#include <cstdint>
#include <string>
#include <vector>

namespace aida {
namespace workbench {
namespace graph_document {

inline constexpr std::uint32_t k_graph_document_schema_version = 2;
inline constexpr std::uint32_t k_graph_document_max_page_size = 512;
inline constexpr std::uint64_t k_graph_document_max_nodes = 100'000;
inline constexpr std::uint64_t k_graph_document_max_edges = 500'000;
inline constexpr std::uint32_t k_graph_document_max_layout_nodes = 4096;
inline constexpr std::uint32_t k_graph_document_max_layout_edges = 65'536;
inline constexpr std::uint32_t k_graph_document_max_layout_iterations = 1024;
inline constexpr std::uint32_t k_graph_document_max_overlays = 2048;
inline constexpr std::uint32_t k_graph_document_max_label_bytes = 4096;
inline constexpr std::uint64_t k_graph_document_max_diff_entries =
    2ULL * (k_graph_document_max_nodes + k_graph_document_max_edges);

enum class graph_error_code_t : std::uint16_t {
    none = 0,
    invalid_argument,
    invalid_page,
    stale_generation,
    adapter_rejected,
    graph_too_large,
    layout_cancelled,
    layout_capacity,
    selection_rejected,
    navigation_rejected,
    node_not_found,
    edge_not_found,
    resource_exhausted,
    cancelled
};

struct graph_error_t {
    graph_error_code_t code = graph_error_code_t::none;
    std::uint64_t subject = 0;

    constexpr bool ok() const noexcept { return code == graph_error_code_t::none; }
    constexpr explicit operator bool() const noexcept { return ok(); }
};

struct graph_node_id_t {
    std::uint64_t value = 0;

    constexpr bool valid() const noexcept { return value != 0; }
};

constexpr bool operator==(graph_node_id_t lhs, graph_node_id_t rhs) noexcept
{
    return lhs.value == rhs.value;
}

constexpr bool operator!=(graph_node_id_t lhs, graph_node_id_t rhs) noexcept
{
    return !(lhs == rhs);
}

constexpr bool operator<(graph_node_id_t lhs, graph_node_id_t rhs) noexcept
{
    return lhs.value < rhs.value;
}

struct graph_edge_id_t {
    std::uint64_t value = 0;

    constexpr bool valid() const noexcept { return value != 0; }
};

constexpr bool operator==(graph_edge_id_t lhs, graph_edge_id_t rhs) noexcept
{
    return lhs.value == rhs.value;
}

constexpr bool operator!=(graph_edge_id_t lhs, graph_edge_id_t rhs) noexcept
{
    return !(lhs == rhs);
}

constexpr bool operator<(graph_edge_id_t lhs, graph_edge_id_t rhs) noexcept
{
    return lhs.value < rhs.value;
}

enum class graph_kind_t : std::uint8_t {
    cfg = 0,
    call_graph = 1,
    data_flow = 2,
    custom = 3
};

enum class graph_node_kind_t : std::uint8_t {
    basic_block = 0,
    function = 1,
    data = 2,
    external = 3,
    unknown = 4
};

enum class graph_edge_kind_t : std::uint8_t {
    unconditional = 0,
    conditional_true = 1,
    conditional_false = 2,
    switch_case = 3,
    call = 4,
    indirect_call = 5,
    return_edge = 6,
    data_reference = 7
};

struct graph_node_view_t {
    graph_node_id_t id;
    graph_node_kind_t kind = graph_node_kind_t::unknown;
    std::uint64_t address = 0;
    std::string label;
    std::uint32_t instruction_count = 0;
    std::uint32_t in_degree = 0;
    std::uint32_t out_degree = 0;
};

struct graph_edge_view_t {
    graph_edge_id_t id;
    graph_node_id_t source;
    graph_node_id_t target;
    graph_edge_kind_t kind = graph_edge_kind_t::unconditional;
    std::uint64_t site_address = 0;
    std::uint64_t parallel_ordinal = 0;
    std::string label;
};

struct graph_edge_identity_t {
    graph_node_id_t source;
    graph_node_id_t target;
    graph_edge_kind_t kind = graph_edge_kind_t::unconditional;
    std::uint64_t site_address = 0;
    std::uint64_t parallel_ordinal = 0;
};

struct graph_layout_node_t {
    graph_node_id_t id;
    float x = 0.0f;
    float y = 0.0f;
    float width = 0.0f;
    float height = 0.0f;
    std::uint32_t layer = 0;
};

struct graph_layout_edge_t {
    graph_edge_id_t id;
    graph_node_id_t source;
    graph_node_id_t target;
    std::vector<float> bend_x;
    std::vector<float> bend_y;
};

struct graph_layout_t {
    std::uint64_t snapshot_generation = 0;
    graph_kind_t graph_kind = graph_kind_t::cfg;
    std::uint32_t node_count = 0;
    std::uint32_t edge_count = 0;
    std::uint32_t iterations = 0;
    bool cancelled = false;
    bool complete = false;
    std::vector<graph_layout_node_t> nodes;
    std::vector<graph_layout_edge_t> edges;
};

struct graph_layout_request_t {
    std::uint64_t expected_generation = 0;
    graph_kind_t graph_kind = graph_kind_t::cfg;
    std::uint32_t max_nodes = k_graph_document_max_layout_nodes;
    std::uint32_t max_edges = k_graph_document_max_layout_edges;
    std::uint32_t max_iterations = k_graph_document_max_layout_iterations;
    std::uint64_t function_address = 0;
    float canvas_width = 1024.0f;
    float canvas_height = 768.0f;
};

struct graph_page_request_t {
    std::uint64_t offset = 0;
    std::uint32_t limit = 0;
    bool edges = false;
    graph_kind_t graph_kind = graph_kind_t::cfg;
    std::uint64_t function_address = 0;
};

struct graph_page_t {
    std::uint64_t snapshot_generation = 0;
    graph_kind_t graph_kind = graph_kind_t::cfg;
    std::uint64_t total_items = 0;
    std::uint64_t offset = 0;
    std::uint64_t next_offset = 0;
    std::vector<graph_node_view_t> nodes;
    std::vector<graph_edge_view_t> edges;
};

struct graph_selection_t {
    selection_kind_t kind = selection_kind_t::none;
    bool has_address = false;
    std::uint64_t address = 0;
    graph_node_id_t node;
    graph_edge_id_t edge;
};

struct graph_navigation_request_t {
    std::uint64_t address = 0;
    std::uint32_t page_size = k_graph_document_max_page_size;
    bool select_node = true;
    bool request_focus = true;
};

struct graph_navigation_result_t {
    bool found = false;
    graph_node_id_t node;
    std::uint64_t page_offset = 0;
    bool focus_requested = false;
    graph_selection_t selection;
};

struct graph_diff_entry_t {
    enum class kind_t : std::uint8_t {
        node_added = 0,
        node_removed = 1,
        node_modified = 2,
        edge_added = 3,
        edge_removed = 4,
        edge_modified = 5
    };
    kind_t kind = kind_t::node_added;
    graph_node_id_t node;
    graph_edge_id_t edge;
    std::uint64_t address = 0;
    std::string label;
};

struct graph_diff_result_t {
    std::uint64_t old_generation = 0;
    std::uint64_t new_generation = 0;
    std::vector<graph_diff_entry_t> entries;
};

class graph_cancellation_t {
public:
    virtual ~graph_cancellation_t() = default;
    virtual bool cancelled() const noexcept = 0;
};

enum class graph_source_result_t : std::uint8_t {
    success = 0,
    not_found,
    limit_exceeded,
    cancelled,
    rejected
};

struct graph_source_limits_t {
    std::uint64_t max_nodes = k_graph_document_max_nodes;
    std::uint64_t max_edges = k_graph_document_max_edges;
};

struct graph_source_counts_t {
    std::uint64_t nodes = 0;
    std::uint64_t edges = 0;
};

class graph_source_adapter_t {
public:
    virtual ~graph_source_adapter_t() = default;
    virtual std::uint64_t current_generation() const noexcept = 0;
    virtual bool generation_current(std::uint64_t generation) const noexcept = 0;
    virtual bool generation_available(std::uint64_t generation) const noexcept = 0;
    virtual bool supports_kind(graph_kind_t kind) const noexcept = 0;
    virtual graph_source_result_t counts(
        std::uint64_t generation, graph_kind_t kind,
        std::uint64_t function_address, const graph_source_limits_t& limits,
        const graph_cancellation_t* cancellation,
        graph_source_counts_t& output) const noexcept = 0;
    virtual graph_source_result_t node_at(
        std::uint64_t generation, graph_kind_t kind,
        std::uint64_t function_address, std::uint64_t ordinal,
        const graph_source_limits_t& limits,
        const graph_cancellation_t* cancellation,
        graph_node_view_t& output) const noexcept = 0;
    virtual graph_source_result_t edge_at(
        std::uint64_t generation, graph_kind_t kind,
        std::uint64_t function_address, std::uint64_t ordinal,
        const graph_source_limits_t& limits,
        const graph_cancellation_t* cancellation,
        graph_edge_view_t& output) const noexcept = 0;
    virtual graph_source_result_t node_by_address(
        std::uint64_t generation, graph_kind_t kind,
        std::uint64_t function_address, std::uint64_t address,
        const graph_source_limits_t& limits,
        const graph_cancellation_t* cancellation,
        graph_node_view_t& output, std::uint64_t& ordinal) const noexcept = 0;
    virtual graph_source_result_t node_by_id(
        std::uint64_t generation, graph_kind_t kind,
        std::uint64_t function_address, graph_node_id_t id,
        const graph_source_limits_t& limits,
        const graph_cancellation_t* cancellation,
        graph_node_view_t& output, std::uint64_t& ordinal) const noexcept = 0;
    virtual graph_source_result_t edge_by_id(
        std::uint64_t generation, graph_kind_t kind,
        std::uint64_t function_address, graph_edge_id_t id,
        const graph_source_limits_t& limits,
        const graph_cancellation_t* cancellation,
        graph_edge_view_t& output, std::uint64_t& ordinal) const noexcept = 0;
};

class graph_overlay_adapter_t {
public:
    virtual ~graph_overlay_adapter_t() = default;
    virtual graph_source_result_t overlay_count(
        std::uint64_t generation, std::uint32_t limit,
        const graph_cancellation_t* cancellation,
        std::uint32_t& output) const noexcept = 0;
    virtual graph_source_result_t overlay_node(
        std::uint64_t generation, graph_node_id_t node,
        std::uint32_t max_label_bytes,
        const graph_cancellation_t* cancellation,
        std::string& text) const noexcept = 0;
};

class graph_layout_cancellation_t : public graph_cancellation_t {};

class graph_document_model_t final {
public:
    graph_document_model_t(const graph_source_adapter_t& source,
                           const graph_overlay_adapter_t* overlays = nullptr) noexcept;

    graph_error_t page(const graph_page_request_t& request,
                       const graph_cancellation_t* cancellation,
                       graph_page_t& output) const;

    graph_error_t navigate(const graph_navigation_request_t& request,
                           std::uint64_t expected_generation,
                           graph_kind_t kind,
                           std::uint64_t function_address,
                           graph_navigation_result_t& output,
                           const graph_cancellation_t* cancellation = nullptr);

    graph_error_t select(const graph_selection_t& selection,
                         std::uint64_t expected_generation,
                         const graph_cancellation_t* cancellation = nullptr);
    graph_error_t select(const graph_selection_t& selection,
                         std::uint64_t expected_generation,
                         graph_kind_t kind,
                         std::uint64_t function_address,
                         const graph_cancellation_t* cancellation = nullptr);

    graph_error_t clear_selection(std::uint64_t expected_generation) noexcept;

    graph_error_t compute_layout(const graph_layout_request_t& request,
                                 const graph_layout_cancellation_t* cancellation,
                                 graph_layout_t& output) const;

    graph_error_t diff_generations(std::uint64_t old_generation,
                                   std::uint64_t new_generation,
                                   graph_kind_t kind,
                                   std::uint64_t function_address,
                                   const graph_cancellation_t* cancellation,
                                   graph_diff_result_t& output) const;

    const graph_layout_t& last_layout() const noexcept;
    const graph_selection_t& selection() const noexcept;
    std::uint64_t current_generation() const noexcept;
    bool generation_current(std::uint64_t generation) const noexcept;
    bool is_stale() const noexcept;
    std::uint64_t bound_generation() const noexcept;
    graph_error_t counts(graph_kind_t kind,
                         std::uint64_t function_address,
                         const graph_cancellation_t* cancellation,
                         graph_source_counts_t& output) const;
    std::uint64_t node_count(graph_kind_t kind, std::uint64_t function_address) const noexcept;
    std::uint64_t edge_count(graph_kind_t kind, std::uint64_t function_address) const noexcept;

private:
    graph_error_t fail(graph_error_code_t code,
                       std::uint64_t subject = 0) const noexcept;
    graph_error_t stale() const noexcept;
    graph_error_t layout_layered(std::uint64_t generation, graph_kind_t kind,
                                 std::uint64_t function_address,
                                 const graph_layout_request_t& request,
                                 const graph_source_counts_t& counts,
                                 const graph_layout_cancellation_t* cancellation,
                                 graph_layout_t& output) const;
    graph_error_t read_counts(
        std::uint64_t generation, graph_kind_t kind,
        std::uint64_t function_address, const graph_source_limits_t& limits,
        const graph_cancellation_t* cancellation,
        graph_error_code_t limit_error,
        graph_source_counts_t& output) const;
    graph_error_t canonicalize_selection(
        const graph_selection_t& selection,
        graph_kind_t kind,
        std::uint64_t function_address,
        const graph_cancellation_t* cancellation,
        graph_selection_t& output) const;

    const graph_source_adapter_t* source_;
    const graph_overlay_adapter_t* overlays_;
    std::uint64_t bound_generation_;
    graph_selection_t selection_;
    mutable graph_layout_t last_layout_;
};

graph_node_id_t compute_deterministic_node_id(std::uint64_t address) noexcept;
graph_edge_id_t compute_deterministic_edge_id(
    const graph_edge_identity_t& identity) noexcept;
bool graph_edge_identity_valid(const graph_edge_identity_t& identity) noexcept;
bool graph_source_limits_valid(const graph_source_limits_t& limits) noexcept;
bool graph_page_request_valid(const graph_page_request_t& request) noexcept;
bool graph_layout_request_valid(const graph_layout_request_t& request) noexcept;
bool graph_selection_valid(const graph_selection_t& selection) noexcept;

}
}
}
