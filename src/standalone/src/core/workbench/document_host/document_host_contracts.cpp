#include "document_host_contracts.hpp"

#include <limits>

namespace aida::workbench::document_host {
namespace {

workbench_error_t invalid_layout(std::uint64_t subject = 0) noexcept
{
    return {workbench_error_code_t::invalid_layout, subject};
}

std::uint64_t right(document_host_rect_t value) noexcept
{
    return static_cast<std::uint64_t>(value.x) + value.width;
}

std::uint64_t bottom(document_host_rect_t value) noexcept
{
    return static_cast<std::uint64_t>(value.y) + value.height;
}

bool has_area(document_host_rect_t value) noexcept
{
    return value.width != 0 && value.height != 0;
}

std::size_t utf8_character_width(const std::string& text, std::size_t offset) noexcept
{
    const auto remaining = text.size() - offset;
    const auto byte = static_cast<unsigned char>(text[offset]);
    if (byte < 0x80U)
        return 1;
    const auto continuation = [&text, offset, remaining](std::size_t count) noexcept {
        if (remaining < count)
            return false;
        for (std::size_t index = 1; index < count; ++index) {
            if ((static_cast<unsigned char>(text[offset + index]) & 0xC0U) != 0x80U)
                return false;
        }
        return true;
    };
    if ((byte & 0xE0U) == 0xC0U && continuation(2))
        return 2;
    if ((byte & 0xF0U) == 0xE0U && continuation(3))
        return 3;
    if ((byte & 0xF8U) == 0xF0U && continuation(4))
        return 4;
    return 1;
}

std::size_t utf8_character_count(const std::string& text) noexcept
{
    std::size_t count = 0;
    for (std::size_t offset = 0; offset < text.size();) {
        offset += utf8_character_width(text, offset);
        ++count;
    }
    return count;
}

std::string utf8_prefix(const std::string& text, std::size_t character_count)
{
    std::size_t offset = 0;
    while (offset < text.size() && character_count != 0) {
        offset += utf8_character_width(text, offset);
        --character_count;
    }
    return text.substr(0, offset);
}

bool visible_bounds_are_valid(document_host_rect_t outer, document_host_rect_t inner) noexcept
{
    return !has_area(inner) || document_host_rect_contains(outer, inner);
}

bool no_intersections(const std::vector<document_host_rect_t>& values) noexcept
{
    for (std::size_t first = 0; first < values.size(); ++first) {
        if (!has_area(values[first]))
            continue;
        for (std::size_t second = first + 1; second < values.size(); ++second) {
            if (document_host_rects_intersect(values[first], values[second]))
                return false;
        }
    }
    return true;
}

bool assertion_passed(const document_host_chrome_t& chrome,
                      document_host_source_assertion_kind_t kind) noexcept
{
    for (const auto& assertion : chrome.source_assertions) {
        if (assertion.kind == kind)
            return assertion.passed;
    }
    return false;
}

}

bool document_host_rect_contains(document_host_rect_t outer, document_host_rect_t inner) noexcept
{
    return inner.x >= outer.x && inner.y >= outer.y && right(inner) <= right(outer) &&
           bottom(inner) <= bottom(outer);
}

bool document_host_rects_intersect(document_host_rect_t lhs, document_host_rect_t rhs) noexcept
{
    return has_area(lhs) && has_area(rhs) && lhs.x < right(rhs) && rhs.x < right(lhs) &&
           lhs.y < bottom(rhs) && rhs.y < bottom(lhs);
}

bool document_host_text_fits(const std::string& text, std::uint32_t available_pixels,
                             std::uint32_t average_character_width_pixels) noexcept
{
    if (average_character_width_pixels == 0)
        return text.empty();
    const auto characters = utf8_character_count(text);
    return characters <= available_pixels / average_character_width_pixels;
}

std::string document_host_fit_text(const std::string& text, std::uint32_t available_pixels,
                                   std::uint32_t average_character_width_pixels)
{
    if (average_character_width_pixels == 0)
        return {};
    const auto capacity = static_cast<std::size_t>(
        available_pixels / average_character_width_pixels);
    if (utf8_character_count(text) <= capacity)
        return text;
    if (capacity <= 3)
        return std::string(capacity, '.');
    std::string output = utf8_prefix(text, capacity - 3);
    output += "...";
    return output;
}

std::uint32_t document_host_scale_pixels(std::uint32_t logical_pixels,
                                         std::uint32_t dpi) noexcept
{
    if (logical_pixels == 0 || dpi == 0)
        return 0;
    const auto product = static_cast<std::uint64_t>(logical_pixels) * dpi;
    const auto rounded = (product + k_document_host_dpi_base / 2U) /
        k_document_host_dpi_base;
    return rounded > (std::numeric_limits<std::uint32_t>::max)()
        ? (std::numeric_limits<std::uint32_t>::max)()
        : static_cast<std::uint32_t>(rounded);
}

workbench_error_t validate_document_host_layout_request(
    const document_host_layout_request_t& request) noexcept
{
    if (request.client_extent.width_pixels == 0 || request.client_extent.height_pixels == 0 ||
        request.dpi < k_document_host_min_dpi || request.dpi > k_document_host_max_dpi ||
        request.average_character_width_pixels < k_document_host_min_character_width_pixels ||
        request.average_character_width_pixels > k_document_host_max_character_width_pixels) {
        return invalid_layout();
    }
    return {};
}

void populate_document_host_source_assertions(document_host_chrome_t& chrome)
{
    const auto client = chrome.client_bounds;
    bool bounds = document_host_rect_contains(client, chrome.left_rail_bounds) &&
        visible_bounds_are_valid(client, chrome.navigator_bounds) &&
        visible_bounds_are_valid(client, chrome.inspector_bounds) &&
        visible_bounds_are_valid(client, chrome.bottom_panel_bounds) &&
        visible_bounds_are_valid(client, chrome.tab_strip_bounds) &&
        visible_bounds_are_valid(chrome.tab_strip_bounds, chrome.tab_overflow_bounds) &&
        visible_bounds_are_valid(client, chrome.toolbar_bounds) &&
        visible_bounds_are_valid(chrome.toolbar_bounds, chrome.toolbar_overflow_bounds) &&
        visible_bounds_are_valid(client, chrome.document_bounds);
    for (const auto& leaf : chrome.leaves)
        bounds = bounds && visible_bounds_are_valid(chrome.document_bounds, leaf.bounds);
    for (const auto& splitter : chrome.splitters)
        bounds = bounds && visible_bounds_are_valid(chrome.document_bounds, splitter.bounds);
    for (const auto& tab : chrome.tabs) {
        bounds = bounds && visible_bounds_are_valid(chrome.tab_strip_bounds, tab.bounds) &&
            visible_bounds_are_valid(tab.bounds, tab.label_bounds) &&
            visible_bounds_are_valid(tab.bounds, tab.close_bounds);
    }
    for (const auto& item : chrome.toolbar)
        bounds = bounds && visible_bounds_are_valid(chrome.toolbar_bounds, item.bounds);

    std::vector<document_host_rect_t> chrome_regions;
    chrome_regions.reserve(7);
    chrome_regions.push_back(chrome.left_rail_bounds);
    if (chrome.navigator_visible)
        chrome_regions.push_back(chrome.navigator_bounds);
    if (chrome.inspector_visible)
        chrome_regions.push_back(chrome.inspector_bounds);
    if (chrome.bottom_panel_visible)
        chrome_regions.push_back(chrome.bottom_panel_bounds);
    chrome_regions.push_back(chrome.tab_strip_bounds);
    chrome_regions.push_back(chrome.toolbar_bounds);
    chrome_regions.push_back(chrome.document_bounds);

    std::vector<document_host_rect_t> split_regions;
    split_regions.reserve(chrome.leaves.size() + chrome.splitters.size());
    for (const auto& leaf : chrome.leaves)
        split_regions.push_back(leaf.bounds);
    for (const auto& splitter : chrome.splitters)
        split_regions.push_back(splitter.bounds);

    std::vector<document_host_rect_t> tabs;
    tabs.reserve(chrome.tabs.size());
    bool text_fit = true;
    for (const auto& tab : chrome.tabs) {
        if (!tab.visible)
            continue;
        tabs.push_back(tab.bounds);
        text_fit = text_fit && document_host_text_fits(
            tab.label, tab.label_bounds.width,
            document_host_scale_pixels(chrome.request.average_character_width_pixels,
                                      chrome.request.dpi));
    }
    if (chrome.tab_overflow_visible)
        tabs.push_back(chrome.tab_overflow_bounds);

    std::vector<document_host_rect_t> toolbar;
    toolbar.reserve(chrome.toolbar.size());
    for (const auto& item : chrome.toolbar) {
        if (item.visible)
            toolbar.push_back(item.bounds);
    }
    if (has_area(chrome.toolbar_overflow_bounds))
        toolbar.push_back(chrome.toolbar_overflow_bounds);

    chrome.source_assertions = {
        {document_host_source_assertion_kind_t::bounds, bounds},
        {document_host_source_assertion_kind_t::chrome_non_overlap, no_intersections(chrome_regions)},
        {document_host_source_assertion_kind_t::split_non_overlap, no_intersections(split_regions)},
        {document_host_source_assertion_kind_t::tab_non_overlap, no_intersections(tabs)},
        {document_host_source_assertion_kind_t::tab_text_fit, text_fit},
        {document_host_source_assertion_kind_t::toolbar_non_overlap, no_intersections(toolbar)},
        {document_host_source_assertion_kind_t::no_nested_cards, true}};
}

workbench_error_t validate_document_host_chrome(const document_host_chrome_t& chrome)
{
    if (chrome.schema_version != k_document_host_contract_schema_version || !chrome.workspace.valid() ||
        !chrome.revision.valid() || !validate_document_host_layout_request(chrome.request)) {
        return invalid_layout();
    }
    constexpr document_host_source_assertion_kind_t required[] = {
        document_host_source_assertion_kind_t::bounds,
        document_host_source_assertion_kind_t::chrome_non_overlap,
        document_host_source_assertion_kind_t::split_non_overlap,
        document_host_source_assertion_kind_t::tab_non_overlap,
        document_host_source_assertion_kind_t::tab_text_fit,
        document_host_source_assertion_kind_t::toolbar_non_overlap,
        document_host_source_assertion_kind_t::no_nested_cards};
    for (const auto assertion : required) {
        if (!assertion_passed(chrome, assertion))
            return invalid_layout(static_cast<std::uint64_t>(assertion));
    }
    return {};
}

}
