#pragma once

#include "../workbench_contracts.h"

#include <cstdint>
#include <string>
#include <vector>

namespace aida::workbench::document_host {

constexpr std::uint32_t k_document_host_contract_schema_version = 1;
constexpr std::uint32_t k_document_host_dpi_base = 96;
constexpr std::uint32_t k_document_host_min_dpi = 48;
constexpr std::uint32_t k_document_host_max_dpi = 768;
constexpr std::uint32_t k_document_host_min_character_width_pixels = 4;
constexpr std::uint32_t k_document_host_max_character_width_pixels = 64;
constexpr std::uint32_t k_document_host_tab_min_width_pixels = 96;
constexpr std::uint32_t k_document_host_tab_max_width_pixels = 280;
constexpr std::uint32_t k_document_host_toolbar_button_pixels = 28;
constexpr std::uint32_t k_document_host_tab_padding_pixels = 16;
constexpr std::uint32_t k_document_host_close_button_pixels = 18;
constexpr std::uint32_t k_document_host_max_state_message_bytes = 512;

enum class document_host_layout_mode_t : std::uint8_t {
    desktop = 0,
    compact = 1,
    constrained = 2
};

enum class document_host_presentation_kind_t : std::uint8_t {
    ready = 0,
    loading = 1,
    error = 2,
    empty = 3
};

enum class document_host_toolbar_action_t : std::uint8_t {
    previous_view = 0,
    next_view = 1,
    split_horizontal = 2,
    split_vertical = 3,
    history_back = 4,
    history_forward = 5,
    close_document = 6
};

enum class document_host_source_assertion_kind_t : std::uint8_t {
    bounds = 0,
    chrome_non_overlap = 1,
    split_non_overlap = 2,
    tab_non_overlap = 3,
    tab_text_fit = 4,
    toolbar_non_overlap = 5,
    no_nested_cards = 6
};

struct document_host_rect_t {
    std::uint32_t x = 0;
    std::uint32_t y = 0;
    std::uint32_t width = 0;
    std::uint32_t height = 0;
};

struct document_host_layout_request_t {
    layout_extent_t client_extent;
    std::uint32_t dpi = k_document_host_dpi_base;
    std::uint32_t average_character_width_pixels = 8;
};

struct document_host_presentation_state_t {
    document_host_presentation_kind_t kind = document_host_presentation_kind_t::ready;
    std::string message;
    bool retryable = false;
};

struct document_host_tab_t {
    document_id_t document;
    std::string title;
    std::string label;
    document_host_rect_t bounds;
    document_host_rect_t label_bounds;
    document_host_rect_t close_bounds;
    bool selected = false;
    bool visible = false;
    bool closeable = false;
    bool close_visible = false;
};

struct document_host_toolbar_item_t {
    document_host_toolbar_action_t action = document_host_toolbar_action_t::next_view;
    document_host_rect_t bounds;
    std::string tooltip;
    bool visible = false;
    bool enabled = false;
};

struct document_host_leaf_t {
    split_node_id_t node;
    view_id_t view;
    document_id_t document;
    document_host_rect_t bounds;
    document_host_presentation_state_t presentation;
    bool focused = false;
    bool constrained = false;
};

struct document_host_splitter_t {
    split_node_id_t node;
    split_orientation_t orientation = split_orientation_t::horizontal;
    document_host_rect_t bounds;
};

struct document_host_source_assertion_t {
    document_host_source_assertion_kind_t kind = document_host_source_assertion_kind_t::bounds;
    bool passed = false;
};

struct document_host_chrome_t {
    std::uint32_t schema_version = k_document_host_contract_schema_version;
    workspace_id_t workspace;
    workspace_revision_t revision;
    document_host_layout_request_t request;
    document_host_layout_mode_t layout_mode = document_host_layout_mode_t::desktop;
    document_host_rect_t client_bounds;
    document_host_rect_t left_rail_bounds;
    document_host_rect_t navigator_bounds;
    document_host_rect_t inspector_bounds;
    document_host_rect_t bottom_panel_bounds;
    document_host_rect_t tab_strip_bounds;
    document_host_rect_t tab_overflow_bounds;
    document_host_rect_t toolbar_bounds;
    document_host_rect_t toolbar_overflow_bounds;
    document_host_rect_t document_bounds;
    bool navigator_visible = false;
    bool inspector_visible = false;
    bool bottom_panel_visible = false;
    bool tab_overflow_visible = false;
    std::uint32_t tab_overflow_count = 0;
    std::uint32_t toolbar_overflow_count = 0;
    std::vector<document_host_tab_t> tabs;
    std::vector<document_host_toolbar_item_t> toolbar;
    std::vector<document_host_leaf_t> leaves;
    std::vector<document_host_splitter_t> splitters;
    std::vector<document_host_source_assertion_t> source_assertions;
};

class document_host_state_adapter_t {
public:
    virtual ~document_host_state_adapter_t() = default;
    virtual workbench_error_t presentation(const workspace_view_context_t& context,
                                           document_host_presentation_state_t& output) const = 0;
};

bool document_host_rect_contains(document_host_rect_t outer, document_host_rect_t inner) noexcept;
bool document_host_rects_intersect(document_host_rect_t lhs, document_host_rect_t rhs) noexcept;
bool document_host_text_fits(const std::string& text, std::uint32_t available_pixels,
                             std::uint32_t average_character_width_pixels) noexcept;
std::string document_host_fit_text(const std::string& text, std::uint32_t available_pixels,
                                   std::uint32_t average_character_width_pixels);
std::uint32_t document_host_scale_pixels(std::uint32_t logical_pixels,
                                         std::uint32_t dpi) noexcept;
workbench_error_t validate_document_host_layout_request(
    const document_host_layout_request_t& request) noexcept;
workbench_error_t validate_document_host_chrome(const document_host_chrome_t& chrome);
void populate_document_host_source_assertions(document_host_chrome_t& chrome);

}
