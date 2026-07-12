#include "document_host.hpp"

#include <algorithm>
#include <array>
#include <utility>

namespace aida::workbench::document_host {
namespace {

struct scaled_layout_t {
    std::uint32_t left_rail = 0;
    std::uint32_t navigator = 0;
    std::uint32_t inspector = 0;
    std::uint32_t bottom_panel = 0;
    std::uint32_t tab_strip = 0;
    std::uint32_t toolbar = 0;
    std::uint32_t splitter = 0;
    std::uint32_t minimum_document_width = 0;
    std::uint32_t minimum_document_height = 0;
    std::uint32_t tab_min_width = 0;
    std::uint32_t tab_max_width = 0;
    std::uint32_t tab_padding = 0;
    std::uint32_t close_button = 0;
    std::uint32_t toolbar_button = 0;
    std::uint32_t character_width = 0;
};

workbench_error_t error(workbench_error_code_t code, std::uint64_t subject = 0) noexcept
{
    return {code, subject};
}

std::uint32_t subtract_clamped(std::uint32_t value, std::uint32_t amount) noexcept
{
    return value > amount ? value - amount : 0;
}

std::uint32_t scaled(std::uint32_t value, std::uint32_t dpi) noexcept
{
    return (std::max)(1U, document_host_scale_pixels(value, dpi));
}

scaled_layout_t make_scaled_layout(const fixed_layout_constraints_t& constraints,
                                   const document_host_layout_request_t& request) noexcept
{
    return {
        scaled(constraints.left_rail_pixels, request.dpi),
        scaled(constraints.navigator_pixels, request.dpi),
        scaled(constraints.inspector_pixels, request.dpi),
        scaled(constraints.bottom_panel_pixels, request.dpi),
        scaled(constraints.tab_strip_pixels, request.dpi),
        scaled(constraints.toolbar_pixels, request.dpi),
        scaled(constraints.splitter_pixels, request.dpi),
        scaled(constraints.minimum_document_width_pixels, request.dpi),
        scaled(constraints.minimum_document_height_pixels, request.dpi),
        scaled(k_document_host_tab_min_width_pixels, request.dpi),
        scaled(k_document_host_tab_max_width_pixels, request.dpi),
        scaled(k_document_host_tab_padding_pixels, request.dpi),
        scaled(k_document_host_close_button_pixels, request.dpi),
        scaled(k_document_host_toolbar_button_pixels, request.dpi),
        scaled(request.average_character_width_pixels, request.dpi)};
}

document_host_rect_t rect(std::uint32_t x, std::uint32_t y, std::uint32_t width,
                          std::uint32_t height) noexcept
{
    return {x, y, width, height};
}

const document_persistence_dto_t* find_document(const workbench_persistence_dto_t& persistence,
                                                 document_id_t id) noexcept
{
    const auto found = std::find_if(persistence.documents.begin(), persistence.documents.end(),
                                    [id](const auto& document) { return document.id == id; });
    return found == persistence.documents.end() ? nullptr : &*found;
}

const view_persistence_dto_t* find_view(const workbench_persistence_dto_t& persistence,
                                        view_id_t id) noexcept
{
    const auto found = std::find_if(persistence.views.begin(), persistence.views.end(),
                                    [id](const auto& view) { return view.id == id; });
    return found == persistence.views.end() ? nullptr : &*found;
}

const split_node_dto_t* find_node(const split_tree_dto_t& tree, split_node_id_t id) noexcept
{
    const auto found = std::find_if(tree.nodes.begin(), tree.nodes.end(),
                                    [id](const auto& node) { return node.id == id; });
    return found == tree.nodes.end() ? nullptr : &*found;
}

bool panel_requested(const workbench_persistence_dto_t& persistence, panel_kind_t kind) noexcept
{
    bool found = false;
    bool visible = false;
    for (const auto& panel : persistence.panels) {
        if (panel.kind != kind)
            continue;
        found = true;
        visible = visible || panel.visible;
    }
    return !found || visible;
}

std::vector<const document_persistence_dto_t*> ordered_documents(
    const workbench_persistence_dto_t& persistence)
{
    std::vector<const document_persistence_dto_t*> output;
    output.reserve(persistence.documents.size());
    for (const auto& document : persistence.documents)
        output.push_back(&document);
    std::sort(output.begin(), output.end(), [](const auto* lhs, const auto* rhs) {
        return lhs->id < rhs->id;
    });
    return output;
}

std::vector<const view_persistence_dto_t*> ordered_views(
    const workbench_persistence_dto_t& persistence)
{
    std::vector<const view_persistence_dto_t*> output;
    output.reserve(persistence.views.size());
    for (const auto& view : persistence.views)
        output.push_back(&view);
    std::sort(output.begin(), output.end(), [](const auto* lhs, const auto* rhs) {
        return lhs->id < rhs->id;
    });
    return output;
}

workspace_view_context_t make_context(const workbench_persistence_dto_t& persistence,
                                      const view_persistence_dto_t& view)
{
    workspace_view_context_t context;
    context.workspace = persistence.workspace;
    context.document = view.document;
    context.view = view.id;
    context.synchronization_group = view.synchronization_group;
    context.synchronization_policy = view.synchronization_policy;
    if (const auto* document = find_document(persistence, view.document)) {
        context.selection = document->local_state.selection;
        context.cursor = document->local_state.cursor;
    }
    return context;
}

document_host_presentation_state_t presentation_for(
    const document_host_services_t& services, const workbench_persistence_dto_t& persistence,
    const view_persistence_dto_t& view)
{
    document_host_presentation_state_t output;
    if (!services.state)
        return output;
    const auto result = services.state->presentation(make_context(persistence, view), output);
    if (!result || output.message.size() > k_document_host_max_state_message_bytes) {
        output.kind = document_host_presentation_kind_t::error;
        output.message = "Document presentation is unavailable";
        output.retryable = true;
    }
    return output;
}

void build_tabs(const workbench_persistence_dto_t& persistence, const scaled_layout_t& metrics,
                document_host_chrome_t& output)
{
    const auto documents = ordered_documents(persistence);
    output.tabs.clear();
    output.tabs.reserve(documents.size());
    for (const auto* document : documents) {
        document_host_tab_t tab;
        tab.document = document->id;
        tab.title = document->title;
        tab.selected = document->id == persistence.active_document;
        tab.closeable = document->closeable && !document->pinned;
        output.tabs.push_back(std::move(tab));
    }
    const auto available = output.tab_strip_bounds.width;
    if (output.tabs.empty() || available == 0)
        return;

    std::size_t active = 0;
    for (std::size_t index = 0; index < output.tabs.size(); ++index) {
        if (output.tabs[index].selected) {
            active = index;
            break;
        }
    }

    std::uint32_t overflow_width = 0;
    std::size_t visible_count = output.tabs.size();
    if (static_cast<std::uint64_t>(metrics.tab_min_width) * visible_count > available) {
        overflow_width = (std::min)(metrics.toolbar_button, available);
        const auto tab_space = subtract_clamped(available, overflow_width);
        visible_count = tab_space / metrics.tab_min_width;
        if (visible_count == 0)
            visible_count = 1;
        visible_count = (std::min)(visible_count, output.tabs.size());
    }

    std::vector<std::size_t> visible_indices;
    visible_indices.reserve(visible_count);
    visible_indices.push_back(active);
    for (std::size_t offset = 1; visible_indices.size() < visible_count; ++offset) {
        const auto candidate = (active + offset) % output.tabs.size();
        visible_indices.push_back(candidate);
    }
    std::sort(visible_indices.begin(), visible_indices.end());
    output.tab_overflow_count = static_cast<std::uint32_t>(output.tabs.size() - visible_indices.size());
    output.tab_overflow_visible = output.tab_overflow_count != 0 && overflow_width != 0;
    output.tab_overflow_bounds = output.tab_overflow_visible
        ? rect(output.tab_strip_bounds.x + available - overflow_width, output.tab_strip_bounds.y,
               overflow_width, output.tab_strip_bounds.height)
        : document_host_rect_t{};

    const auto tab_space = subtract_clamped(available, overflow_width);
    const auto equal_width = static_cast<std::uint32_t>(tab_space / visible_indices.size());
    std::uint32_t x = output.tab_strip_bounds.x;
    for (const auto index : visible_indices) {
        auto& tab = output.tabs[index];
        const auto remaining = output.tab_strip_bounds.x + tab_space - x;
        const auto width = index == visible_indices.back() ? remaining : equal_width;
        tab.bounds = rect(x, output.tab_strip_bounds.y, width, output.tab_strip_bounds.height);
        tab.visible = width != 0;
        const auto left_padding = (std::min)(metrics.tab_padding, width);
        const auto right_padding = (std::min)(metrics.tab_padding, subtract_clamped(width, left_padding));
        const auto label_x = x + left_padding;
        auto label_width = subtract_clamped(width, left_padding + right_padding);
        if (tab.closeable && label_width > metrics.close_button + metrics.character_width) {
            tab.close_visible = true;
            tab.close_bounds = rect(x + width - right_padding - metrics.close_button,
                                    output.tab_strip_bounds.y +
                                        (output.tab_strip_bounds.height > metrics.close_button
                                            ? (output.tab_strip_bounds.height - metrics.close_button) / 2U
                                            : 0),
                                    metrics.close_button,
                                    (std::min)(metrics.close_button, output.tab_strip_bounds.height));
            label_width = subtract_clamped(label_width, metrics.close_button);
        }
        tab.label_bounds = rect(label_x, output.tab_strip_bounds.y, label_width,
                                output.tab_strip_bounds.height);
        tab.label = document_host_fit_text(tab.title, label_width, metrics.character_width);
        x += width;
    }
}

void build_toolbar(const workbench_persistence_dto_t& persistence, const scaled_layout_t& metrics,
                   document_host_chrome_t& output)
{
    constexpr std::array<document_host_toolbar_action_t, 7> actions{
        document_host_toolbar_action_t::previous_view,
        document_host_toolbar_action_t::next_view,
        document_host_toolbar_action_t::split_horizontal,
        document_host_toolbar_action_t::split_vertical,
        document_host_toolbar_action_t::history_back,
        document_host_toolbar_action_t::history_forward,
        document_host_toolbar_action_t::close_document};
    constexpr std::array<const char*, 7> tooltips{
        "Previous split", "Next split", "Split horizontally", "Split vertically",
        "Back", "Forward", "Close document"};
    output.toolbar.clear();
    output.toolbar.reserve(actions.size());
    const auto requires_overflow = static_cast<std::uint64_t>(metrics.toolbar_button) *
        actions.size() > output.toolbar_bounds.width;
    const auto overflow_width = requires_overflow
        ? (std::min)(metrics.toolbar_button, output.toolbar_bounds.width) : 0U;
    const auto action_width = subtract_clamped(output.toolbar_bounds.width, overflow_width);
    const auto capacity = action_width / metrics.toolbar_button;
    const auto visible_count = (std::min)(static_cast<std::size_t>(capacity), actions.size());
    output.toolbar_overflow_count = static_cast<std::uint32_t>(actions.size() - visible_count);
    output.toolbar_overflow_bounds = {};
    if (output.toolbar_overflow_count != 0 && overflow_width != 0) {
        output.toolbar_overflow_bounds = rect(
            output.toolbar_bounds.x + output.toolbar_bounds.width - overflow_width,
            output.toolbar_bounds.y, overflow_width, output.toolbar_bounds.height);
    }
    for (std::size_t index = 0; index < actions.size(); ++index) {
        document_host_toolbar_item_t item;
        item.action = actions[index];
        item.tooltip = tooltips[index];
        item.visible = index < visible_count;
        item.enabled = item.visible;
        if (item.visible) {
            item.bounds = rect(output.toolbar_bounds.x +
                                   static_cast<std::uint32_t>(index) * metrics.toolbar_button,
                               output.toolbar_bounds.y, metrics.toolbar_button,
                               output.toolbar_bounds.height);
        }
        if ((item.action == document_host_toolbar_action_t::history_back &&
             persistence.history.back.empty()) ||
            (item.action == document_host_toolbar_action_t::history_forward &&
             persistence.history.forward.empty()) ||
            (item.action == document_host_toolbar_action_t::close_document &&
             persistence.documents.size() <= 1U)) {
            item.enabled = false;
        }
        output.toolbar.push_back(std::move(item));
    }
}

workbench_error_t append_split_chrome(const workbench_persistence_dto_t& persistence,
                                      const document_host_services_t& services,
                                      const scaled_layout_t& metrics, split_node_id_t node_id,
                                      document_host_rect_t bounds,
                                      document_host_chrome_t& output)
{
    const auto* node = find_node(persistence.split_tree, node_id);
    if (!node)
        return error(workbench_error_code_t::invalid_split_tree, node_id.value);
    if (node->kind == split_node_kind_t::leaf) {
        const auto* view = find_view(persistence, node->view);
        if (!view)
            return error(workbench_error_code_t::invalid_view, node->view.value);
        document_host_leaf_t leaf;
        leaf.node = node->id;
        leaf.view = view->id;
        leaf.document = view->document;
        leaf.bounds = bounds;
        leaf.focused = view->focused;
        leaf.constrained = bounds.width < metrics.minimum_document_width ||
            bounds.height < metrics.minimum_document_height;
        leaf.presentation = presentation_for(services, persistence, *view);
        output.leaves.push_back(std::move(leaf));
        return {};
    }

    const auto axis = node->orientation == split_orientation_t::horizontal ? bounds.width : bounds.height;
    const auto splitter_size = (std::min)(metrics.splitter, axis);
    const auto distributable = subtract_clamped(axis, splitter_size);
    const auto first_axis = static_cast<std::uint32_t>(
        static_cast<std::uint64_t>(distributable) * node->ratio_basis_points / 10000U);
    const auto second_axis = distributable - first_axis;
    document_host_rect_t first = bounds;
    document_host_rect_t second = bounds;
    document_host_splitter_t splitter;
    splitter.node = node->id;
    splitter.orientation = node->orientation;
    if (node->orientation == split_orientation_t::horizontal) {
        first.width = first_axis;
        splitter.bounds = rect(bounds.x + first_axis, bounds.y, splitter_size, bounds.height);
        second.x = bounds.x + first_axis + splitter_size;
        second.width = second_axis;
    } else {
        first.height = first_axis;
        splitter.bounds = rect(bounds.x, bounds.y + first_axis, bounds.width, splitter_size);
        second.y = bounds.y + first_axis + splitter_size;
        second.height = second_axis;
    }
    output.splitters.push_back(splitter);
    const auto first_result = append_split_chrome(persistence, services, metrics, node->first,
                                                  first, output);
    if (!first_result)
        return first_result;
    return append_split_chrome(persistence, services, metrics, node->second, second, output);
}

workbench_command_result_t failed_result(workbench_error_t failure,
                                         workbench_snapshot_ptr_t snapshot = {})
{
    workbench_command_result_t output;
    output.error = failure;
    output.snapshot = std::move(snapshot);
    return output;
}

workbench_error_t focused_view(const workbench_persistence_dto_t& persistence, view_id_t& output) noexcept
{
    output = {};
    for (const auto& view : persistence.views) {
        if (!view.focused)
            continue;
        if (output.valid())
            return error(workbench_error_code_t::invalid_view, view.id.value);
        output = view.id;
    }
    return output.valid() ? workbench_error_t{} : error(workbench_error_code_t::invalid_view);
}

workbench_error_t select_cycle_document(const workbench_persistence_dto_t& persistence,
                                        bool reverse, document_id_t& output)
{
    const auto documents = ordered_documents(persistence);
    if (documents.empty())
        return error(workbench_error_code_t::invalid_document);
    std::size_t active = 0;
    for (std::size_t index = 0; index < documents.size(); ++index) {
        if (documents[index]->id == persistence.active_document) {
            active = index;
            break;
        }
    }
    output = documents[reverse ? (active + documents.size() - 1U) % documents.size()
                               : (active + 1U) % documents.size()]->id;
    return {};
}

workbench_error_t select_cycle_view(const workbench_persistence_dto_t& persistence, bool reverse,
                                    view_id_t& output)
{
    const auto views = ordered_views(persistence);
    if (views.empty())
        return error(workbench_error_code_t::invalid_view);
    std::size_t active = 0;
    for (std::size_t index = 0; index < views.size(); ++index) {
        if (views[index]->focused) {
            active = index;
            break;
        }
    }
    output = views[reverse ? (active + views.size() - 1U) % views.size()
                           : (active + 1U) % views.size()]->id;
    return {};
}

workbench_error_t command_from_input(const document_host_dispatch_t& input,
                                     const workbench_persistence_dto_t& persistence,
                                     workbench_command_t& output)
{
    output.workspace = input.workspace;
    output.expected_revision = input.expected_revision;
    output.request_focus = input.request_focus;
    auto target_view = input.view;
    if (!target_view.valid()) {
        const auto focus_result = focused_view(persistence, target_view);
        if (!focus_result)
            return focus_result;
    }
    switch (input.kind) {
        case document_host_dispatch_kind_t::open_document:
            output.kind = workbench_command_kind_t::open_document;
            output.document_identity = input.document_identity;
            output.view = target_view;
            return validate_document_identity(output.document_identity);
        case document_host_dispatch_kind_t::select_document: {
            const auto* document = find_document(persistence, input.document);
            if (!document)
                return error(workbench_error_code_t::invalid_document, input.document.value);
            output.kind = workbench_command_kind_t::open_document;
            output.document_identity = document->identity;
            output.view = target_view;
            output.request_focus = true;
            return {};
        }
        case document_host_dispatch_kind_t::close_document:
            output.kind = workbench_command_kind_t::close_document;
            output.document = input.document.valid() ? input.document : persistence.active_document;
            return {};
        case document_host_dispatch_kind_t::focus_view:
            output.kind = workbench_command_kind_t::focus_view;
            output.view = input.view;
            return output.view.valid() ? workbench_error_t{} : error(workbench_error_code_t::invalid_view);
        case document_host_dispatch_kind_t::split_horizontal:
        case document_host_dispatch_kind_t::split_vertical:
            output.kind = workbench_command_kind_t::split_view;
            output.view = target_view;
            output.document = input.document;
            output.orientation = input.kind == document_host_dispatch_kind_t::split_horizontal
                ? split_orientation_t::horizontal : split_orientation_t::vertical;
            output.ratio_basis_points = input.ratio_basis_points;
            return {};
        case document_host_dispatch_kind_t::history_back:
            output.kind = workbench_command_kind_t::history_back;
            return {};
        case document_host_dispatch_kind_t::history_forward:
            output.kind = workbench_command_kind_t::history_forward;
            return {};
        case document_host_dispatch_kind_t::navigate:
            output.kind = workbench_command_kind_t::navigate;
            output.navigation = input.navigation;
            return {};
        case document_host_dispatch_kind_t::toolbar:
            switch (input.toolbar_action) {
                case document_host_toolbar_action_t::previous_view:
                    output.kind = workbench_command_kind_t::focus_view;
                    return select_cycle_view(persistence, true, output.view);
                case document_host_toolbar_action_t::next_view:
                    output.kind = workbench_command_kind_t::focus_view;
                    return select_cycle_view(persistence, false, output.view);
                case document_host_toolbar_action_t::split_horizontal:
                    output.kind = workbench_command_kind_t::split_view;
                    output.view = target_view;
                    output.orientation = split_orientation_t::horizontal;
                    output.ratio_basis_points = input.ratio_basis_points;
                    return {};
                case document_host_toolbar_action_t::split_vertical:
                    output.kind = workbench_command_kind_t::split_view;
                    output.view = target_view;
                    output.orientation = split_orientation_t::vertical;
                    output.ratio_basis_points = input.ratio_basis_points;
                    return {};
                case document_host_toolbar_action_t::history_back:
                    output.kind = workbench_command_kind_t::history_back;
                    return {};
                case document_host_toolbar_action_t::history_forward:
                    output.kind = workbench_command_kind_t::history_forward;
                    return {};
                case document_host_toolbar_action_t::close_document:
                    output.kind = workbench_command_kind_t::close_document;
                    output.document = persistence.active_document;
                    return {};
            }
            return error(workbench_error_code_t::invalid_persistence);
        case document_host_dispatch_kind_t::keyboard:
            if (input.key.control && input.key.key == document_host_key_t::w) {
                output.kind = workbench_command_kind_t::close_document;
                output.document = persistence.active_document;
                return {};
            }
            if (input.key.control && input.key.key == document_host_key_t::tab) {
                document_id_t document;
                const auto selected = select_cycle_document(persistence, input.key.shift, document);
                if (!selected)
                    return selected;
                const auto* descriptor = find_document(persistence, document);
                if (!descriptor)
                    return error(workbench_error_code_t::invalid_document, document.value);
                output.kind = workbench_command_kind_t::open_document;
                output.document_identity = descriptor->identity;
                output.view = target_view;
                output.request_focus = true;
                return {};
            }
            if (input.key.alt && input.key.key == document_host_key_t::left) {
                output.kind = workbench_command_kind_t::history_back;
                return {};
            }
            if (input.key.alt && input.key.key == document_host_key_t::right) {
                output.kind = workbench_command_kind_t::history_forward;
                return {};
            }
            if (input.key.key == document_host_key_t::f6) {
                output.kind = workbench_command_kind_t::focus_view;
                return select_cycle_view(persistence, input.key.shift, output.view);
            }
            return error(workbench_error_code_t::invalid_persistence);
    }
    return error(workbench_error_code_t::invalid_persistence);
}

}

document_host_t::document_host_t(workbench_model_t& model, document_host_services_t services)
    : model_(model), services_(services)
{
}

workbench_error_t document_host_t::compose(workspace_id_t workspace,
                                            const document_host_layout_request_t& request,
                                            document_host_chrome_t& output) const
{
    output = {};
    const auto request_result = validate_document_host_layout_request(request);
    if (!request_result)
        return request_result;
    workbench_snapshot_ptr_t snapshot;
    const auto snapshot_result = model_.snapshot(workspace, snapshot);
    if (!snapshot_result)
        return snapshot_result;
    const auto& persistence = snapshot->persistence();
    const auto layout_result = validate_fixed_layout_constraints(persistence.layout);
    if (!layout_result)
        return layout_result;

    const auto metrics = make_scaled_layout(persistence.layout, request);
    output.schema_version = k_document_host_contract_schema_version;
    output.workspace = workspace;
    output.revision = snapshot->revision();
    output.request = request;
    output.client_bounds = rect(0, 0, request.client_extent.width_pixels, request.client_extent.height_pixels);

    std::uint32_t x = 0;
    std::uint32_t width = request.client_extent.width_pixels;
    const auto rail_width = (std::min)(metrics.left_rail, width);
    output.left_rail_bounds = rect(0, 0, rail_width, request.client_extent.height_pixels);
    x += rail_width;
    width -= rail_width;

    const bool navigator_requested = panel_requested(persistence, panel_kind_t::navigator);
    const bool inspector_requested = panel_requested(persistence, panel_kind_t::inspector);
    if (navigator_requested && width >= metrics.navigator + metrics.splitter +
                                  metrics.minimum_document_width) {
        output.navigator_visible = true;
        output.navigator_bounds = rect(x, 0, metrics.navigator, request.client_extent.height_pixels);
        x += metrics.navigator + metrics.splitter;
        width -= metrics.navigator + metrics.splitter;
    }
    if (inspector_requested && width >= metrics.inspector + metrics.splitter +
                                  metrics.minimum_document_width) {
        output.inspector_visible = true;
        output.inspector_bounds = rect(x + width - metrics.inspector, 0, metrics.inspector,
                                       request.client_extent.height_pixels);
        width -= metrics.inspector + metrics.splitter;
    }

    std::uint32_t y = 0;
    std::uint32_t height = request.client_extent.height_pixels;
    const auto tab_height = (std::min)(metrics.tab_strip, height);
    output.tab_strip_bounds = rect(x, y, width, tab_height);
    y += tab_height;
    height -= tab_height;
    const auto toolbar_height = (std::min)(metrics.toolbar, height);
    output.toolbar_bounds = rect(x, y, width, toolbar_height);
    y += toolbar_height;
    height -= toolbar_height;

    const bool bottom_requested = panel_requested(persistence, panel_kind_t::output);
    std::uint32_t document_height = height;
    if (bottom_requested && height >= metrics.bottom_panel + metrics.splitter +
                                metrics.minimum_document_height) {
        output.bottom_panel_visible = true;
        document_height = height - metrics.bottom_panel - metrics.splitter;
        output.bottom_panel_bounds = rect(x, y + document_height + metrics.splitter, width,
                                          metrics.bottom_panel);
    }
    output.document_bounds = rect(x, y, width, document_height);
    build_tabs(persistence, metrics, output);
    build_toolbar(persistence, metrics, output);
    const auto split_result = append_split_chrome(persistence, services_, metrics,
                                                  persistence.split_tree.root,
                                                  output.document_bounds, output);
    if (!split_result) {
        output = {};
        return split_result;
    }

    output.layout_mode = output.navigator_visible && output.inspector_visible &&
        output.bottom_panel_visible ? document_host_layout_mode_t::desktop
                                    : document_host_layout_mode_t::compact;
    for (const auto& leaf : output.leaves) {
        if (leaf.constrained) {
            output.layout_mode = document_host_layout_mode_t::constrained;
            break;
        }
    }
    populate_document_host_source_assertions(output);
    const auto validation = validate_document_host_chrome(output);
    if (!validation)
        output = {};
    return validation;
}

workbench_command_result_t document_host_t::dispatch(const document_host_dispatch_t& input)
{
    if (!input.workspace.valid())
        return failed_result(error(workbench_error_code_t::invalid_workspace));
    workbench_snapshot_ptr_t snapshot;
    const auto snapshot_result = model_.snapshot(input.workspace, snapshot);
    if (!snapshot_result)
        return failed_result(snapshot_result);
    if (!revision_matches(input.expected_revision, snapshot->revision())) {
        return failed_result(error(workbench_error_code_t::revision_mismatch,
                                   input.expected_revision.value), snapshot);
    }
    workbench_command_t command;
    const auto command_result = command_from_input(input, snapshot->persistence(), command);
    if (!command_result)
        return failed_result(command_result, snapshot);
    return model_.execute(command, {services_.documents, services_.navigation});
}

}
