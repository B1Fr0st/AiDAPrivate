#include "workbench_persistence.hpp"

#include "../analysis/workspace/workspace_database.hpp"
#include "split_tree.h"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <exception>
#include <future>
#include <limits>
#include <unordered_set>
#include <utility>

namespace aida {
namespace workbench {

namespace {

using json = nlohmann::json;

persistence_codec_result_t codec_error(persistence_codec_code_t code,
                                       std::string detail = {}) noexcept
{
    persistence_codec_result_t result;
    result.code = code;
    result.detail = std::move(detail);
    return result;
}

std::optional<persistence_codec_result_t> preflight_json(
    std::string_view input, const persistence_codec_limits_t& limits) noexcept
{
    if (limits.max_serialized_bytes == 0 ||
        limits.max_serialized_bytes > k_persistence_codec_max_serialized_bytes ||
        limits.max_json_depth == 0 ||
        limits.max_json_depth > k_persistence_codec_max_json_depth ||
        limits.max_field_count == 0 ||
        limits.max_field_count > k_persistence_codec_max_field_count)
        return codec_error(persistence_codec_code_t::oversized_payload,
                           "codec limits exceed hard production bounds");
    if (input.size() > limits.max_serialized_bytes)
        return codec_error(persistence_codec_code_t::oversized_payload,
                           "input exceeds max_serialized_bytes");
    struct container_frame_t final {
        unsigned char type = 0;
        std::size_t array_items = 0;
        bool array_expects_value = true;
    };
    std::array<container_frame_t, k_persistence_codec_max_json_depth> containers{};
    std::size_t depth = 0;
    std::size_t fields = 0;
    std::size_t structural_values = 0;
    bool in_string = false;
    bool escaped = false;
    const auto mark_array_value = [&]() noexcept {
        if (depth == 0 || containers[depth - 1].type != '[' ||
            !containers[depth - 1].array_expects_value)
            return true;
        auto& frame = containers[depth - 1];
        if (frame.array_items >= k_max_split_nodes_per_workspace ||
            structural_values >= k_persistence_codec_max_collection_elements)
            return false;
        ++frame.array_items;
        ++structural_values;
        frame.array_expects_value = false;
        return true;
    };
    for (const unsigned char byte : input) {
        if (in_string) {
            if (escaped) {
                escaped = false;
            } else if (byte == '\\') {
                escaped = true;
            } else if (byte == '"') {
                in_string = false;
            }
            continue;
        }
        if (byte == '"') {
            if (!mark_array_value())
                return codec_error(persistence_codec_code_t::oversized_payload,
                                   "JSON structural value count exceeds hard bounds");
            in_string = true;
        } else if (byte == '{' || byte == '[') {
            if (!mark_array_value())
                return codec_error(persistence_codec_code_t::oversized_payload,
                                   "JSON structural value count exceeds hard bounds");
            if (depth >= limits.max_json_depth)
                return codec_error(persistence_codec_code_t::oversized_payload,
                                   "JSON depth exceeds max_json_depth");
            containers[depth].type = byte;
            containers[depth].array_items = 0;
            containers[depth].array_expects_value = true;
            ++depth;
        } else if (byte == '}' || byte == ']') {
            if (depth == 0 ||
                containers[depth - 1].type !=
                    static_cast<unsigned char>(byte == '}' ? '{' : '[') ||
                (byte == ']' && containers[depth - 1].array_items != 0 &&
                 containers[depth - 1].array_expects_value))
                return codec_error(persistence_codec_code_t::invalid_json,
                                   "JSON delimiters are unbalanced");
            --depth;
        } else if (byte == ':') {
            if (fields >= limits.max_field_count)
                return codec_error(persistence_codec_code_t::field_count_exceeded,
                                   "total field count exceeds max_field_count");
            ++fields;
        } else if (byte == ',' && depth != 0 &&
                   containers[depth - 1].type == '[') {
            if (containers[depth - 1].array_expects_value)
                return codec_error(persistence_codec_code_t::invalid_json,
                                   "JSON array separators are malformed");
            containers[depth - 1].array_expects_value = true;
        } else if (byte != ' ' && byte != '\t' && byte != '\r' && byte != '\n' &&
                   byte != ',') {
            if (!mark_array_value())
                return codec_error(persistence_codec_code_t::oversized_payload,
                                   "JSON structural value count exceeds hard bounds");
        }
    }
    if (in_string || escaped || depth != 0)
        return codec_error(persistence_codec_code_t::invalid_json,
                           "JSON structure is incomplete");
    return std::nullopt;
}

bool valid_document_kind_ordinal(std::uint64_t value) noexcept
{
    return value <= static_cast<unsigned>(document_kind_t::diff);
}

bool valid_view_role_ordinal(std::uint64_t value) noexcept
{
    return value <= static_cast<unsigned>(view_role_t::transient);
}

bool valid_selection_kind_ordinal(std::uint64_t value) noexcept
{
    return value <= static_cast<unsigned>(selection_kind_t::source);
}

bool valid_sync_policy_ordinal(std::uint64_t value) noexcept
{
    return value <= static_cast<unsigned>(view_synchronization_policy_t::cursor_and_selection);
}

bool valid_nav_origin_ordinal(std::uint64_t value) noexcept
{
    return value <= static_cast<unsigned>(navigation_origin_t::mcp);
}

bool valid_split_node_kind_ordinal(std::uint64_t value) noexcept
{
    return value <= static_cast<unsigned>(split_node_kind_t::branch);
}

bool valid_split_orientation_ordinal(std::uint64_t value) noexcept
{
    return value <= static_cast<unsigned>(split_orientation_t::vertical);
}

bool valid_panel_kind_ordinal(std::uint64_t value) noexcept
{
    return value <= static_cast<unsigned>(panel_kind_t::custom);
}

template <typename Integer>
bool parse_decimal(const json& value, Integer& result) noexcept
{
    if (!value.is_string())
        return false;
    const auto& text = value.get_ref<const std::string&>();
    if (text.empty())
        return false;
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), result, 10);
    return parsed.ec == std::errc{} && parsed.ptr == text.data() + text.size();
}

template <std::size_t Size>
bool exact_fields(const json& value, const std::array<const char*, Size>& fields) noexcept
{
    if (!value.is_object() || value.size() != Size)
        return false;
    return std::all_of(fields.begin(), fields.end(),
                       [&](const char* field) { return value.contains(field); });
}

json layout_json(const fixed_layout_constraints_t& layout)
{
    return json{
        {"left_rail_pixels", std::to_string(layout.left_rail_pixels)},
        {"navigator_pixels", std::to_string(layout.navigator_pixels)},
        {"inspector_pixels", std::to_string(layout.inspector_pixels)},
        {"bottom_panel_pixels", std::to_string(layout.bottom_panel_pixels)},
        {"tab_strip_pixels", std::to_string(layout.tab_strip_pixels)},
        {"toolbar_pixels", std::to_string(layout.toolbar_pixels)},
        {"splitter_pixels", std::to_string(layout.splitter_pixels)},
        {"minimum_document_width_pixels", std::to_string(layout.minimum_document_width_pixels)},
        {"minimum_document_height_pixels", std::to_string(layout.minimum_document_height_pixels)}
    };
}

std::optional<fixed_layout_constraints_t> parse_layout_json(const json& value) noexcept
{
    try {
        static constexpr std::array<const char*, 9> fields{{
            "bottom_panel_pixels", "inspector_pixels", "left_rail_pixels",
            "minimum_document_height_pixels", "minimum_document_width_pixels",
            "navigator_pixels", "splitter_pixels", "tab_strip_pixels", "toolbar_pixels"
        }};
        if (!exact_fields(value, fields))
            return std::nullopt;
        fixed_layout_constraints_t layout;
        if (!parse_decimal(value["left_rail_pixels"], layout.left_rail_pixels) ||
            !parse_decimal(value["navigator_pixels"], layout.navigator_pixels) ||
            !parse_decimal(value["inspector_pixels"], layout.inspector_pixels) ||
            !parse_decimal(value["bottom_panel_pixels"], layout.bottom_panel_pixels) ||
            !parse_decimal(value["tab_strip_pixels"], layout.tab_strip_pixels) ||
            !parse_decimal(value["toolbar_pixels"], layout.toolbar_pixels) ||
            !parse_decimal(value["splitter_pixels"], layout.splitter_pixels) ||
            !parse_decimal(value["minimum_document_width_pixels"], layout.minimum_document_width_pixels) ||
            !parse_decimal(value["minimum_document_height_pixels"], layout.minimum_document_height_pixels))
            return std::nullopt;
        return layout;
    } catch (...) {
        return std::nullopt;
    }
}

std::optional<fixed_layout_constraints_t> parse_layout_json_v8(const json& value) noexcept
{
    try {
        static constexpr std::array<const char*, 6> v8_fields{{
            "bottom_panel_pixels", "inspector_pixels", "left_rail_pixels",
            "navigator_pixels", "tab_strip_pixels", "toolbar_pixels"
        }};
        if (!exact_fields(value, v8_fields))
            return std::nullopt;
        fixed_layout_constraints_t layout;
        if (!parse_decimal(value["left_rail_pixels"], layout.left_rail_pixels) ||
            !parse_decimal(value["navigator_pixels"], layout.navigator_pixels) ||
            !parse_decimal(value["inspector_pixels"], layout.inspector_pixels) ||
            !parse_decimal(value["bottom_panel_pixels"], layout.bottom_panel_pixels) ||
            !parse_decimal(value["tab_strip_pixels"], layout.tab_strip_pixels) ||
            !parse_decimal(value["toolbar_pixels"], layout.toolbar_pixels))
            return std::nullopt;
        return layout;
    } catch (...) {
        return std::nullopt;
    }
}

json split_node_json(const split_node_dto_t& node)
{
    return json{
        {"id", std::to_string(node.id.value)},
        {"kind", static_cast<std::uint8_t>(node.kind)},
        {"orientation", static_cast<std::uint8_t>(node.orientation)},
        {"ratio_basis_points", std::to_string(node.ratio_basis_points)},
        {"view", std::to_string(node.view.value)},
        {"first", std::to_string(node.first.value)},
        {"second", std::to_string(node.second.value)}
    };
}

std::optional<split_node_dto_t> parse_split_node_json(const json& value) noexcept
{
    try {
        static constexpr std::array<const char*, 7> fields{{
            "first", "id", "kind", "orientation", "ratio_basis_points", "second", "view"
        }};
        if (!exact_fields(value, fields) || !value["kind"].is_number_unsigned() ||
            !value["orientation"].is_number_unsigned())
            return std::nullopt;
        const auto kind_ordinal = value["kind"].get<std::uint64_t>();
        const auto orientation_ordinal = value["orientation"].get<std::uint64_t>();
        if (!valid_split_node_kind_ordinal(kind_ordinal) ||
            !valid_split_orientation_ordinal(orientation_ordinal))
            return std::nullopt;
        split_node_dto_t node;
        node.kind = static_cast<split_node_kind_t>(kind_ordinal);
        node.orientation = static_cast<split_orientation_t>(orientation_ordinal);
        if (!parse_decimal(value["id"], node.id.value) ||
            !parse_decimal(value["ratio_basis_points"], node.ratio_basis_points) ||
            !parse_decimal(value["view"], node.view.value) ||
            !parse_decimal(value["first"], node.first.value) ||
            !parse_decimal(value["second"], node.second.value))
            return std::nullopt;
        return node;
    } catch (...) {
        return std::nullopt;
    }
}

json split_tree_json(const split_tree_dto_t& tree)
{
    json nodes = json::array();
    for (const auto& node : tree.nodes)
        nodes.push_back(split_node_json(node));
    return json{{"root", std::to_string(tree.root.value)}, {"nodes", std::move(nodes)}};
}

std::optional<split_tree_dto_t> parse_split_tree_json(const json& value) noexcept
{
    try {
        static constexpr std::array<const char*, 2> fields{{"nodes", "root"}};
        if (!exact_fields(value, fields) || !value["nodes"].is_array())
            return std::nullopt;
        split_tree_dto_t tree;
        if (!parse_decimal(value["root"], tree.root.value))
            return std::nullopt;
        if (value["nodes"].size() > k_max_split_nodes_per_workspace)
            return std::nullopt;
        tree.nodes.reserve(value["nodes"].size());
        for (const auto& node_json : value["nodes"]) {
            auto node = parse_split_node_json(node_json);
            if (!node)
                return std::nullopt;
            tree.nodes.push_back(std::move(*node));
        }
        return tree;
    } catch (...) {
        return std::nullopt;
    }
}

json selection_json(const selection_context_t& selection)
{
    return json{
        {"kind", static_cast<std::uint8_t>(selection.kind)},
        {"has_address", selection.has_address},
        {"address", std::to_string(selection.address)},
        {"extent", std::to_string(selection.extent)},
        {"entity_key", selection.entity_key}
    };
}

std::optional<selection_context_t> parse_selection_json(const json& value) noexcept
{
    try {
        static constexpr std::array<const char*, 5> fields{{
            "address", "entity_key", "extent", "has_address", "kind"
        }};
        if (!exact_fields(value, fields) || !value["kind"].is_number_unsigned() ||
            !value["has_address"].is_boolean() || !value["entity_key"].is_string())
            return std::nullopt;
        const auto kind_ordinal = value["kind"].get<std::uint64_t>();
        if (!valid_selection_kind_ordinal(kind_ordinal))
            return std::nullopt;
        const auto& entity_key = value["entity_key"].get_ref<const std::string&>();
        if (entity_key.size() > k_max_document_key_bytes)
            return std::nullopt;
        selection_context_t selection;
        selection.kind = static_cast<selection_kind_t>(kind_ordinal);
        selection.has_address = value["has_address"].get<bool>();
        selection.entity_key = entity_key;
        if (!parse_decimal(value["address"], selection.address) ||
            !parse_decimal(value["extent"], selection.extent))
            return std::nullopt;
        return selection;
    } catch (...) {
        return std::nullopt;
    }
}

json cursor_json(const document_local_cursor_t& cursor)
{
    return json{
        {"has_position", cursor.has_position},
        {"position", std::to_string(cursor.position)}
    };
}

std::optional<document_local_cursor_t> parse_cursor_json(const json& value) noexcept
{
    try {
        static constexpr std::array<const char*, 2> fields{{"has_position", "position"}};
        if (!exact_fields(value, fields) || !value["has_position"].is_boolean())
            return std::nullopt;
        document_local_cursor_t cursor;
        cursor.has_position = value["has_position"].get<bool>();
        if (!parse_decimal(value["position"], cursor.position))
            return std::nullopt;
        return cursor;
    } catch (...) {
        return std::nullopt;
    }
}

json local_state_json(const document_local_state_t& state)
{
    return json{{"cursor", cursor_json(state.cursor)}, {"selection", selection_json(state.selection)}};
}

std::optional<document_local_state_t> parse_local_state_json(const json& value) noexcept
{
    try {
        static constexpr std::array<const char*, 2> fields{{"cursor", "selection"}};
        if (!exact_fields(value, fields))
            return std::nullopt;
        auto cursor = parse_cursor_json(value["cursor"]);
        auto selection = parse_selection_json(value["selection"]);
        if (!cursor || !selection)
            return std::nullopt;
        document_local_state_t state;
        state.cursor = std::move(*cursor);
        state.selection = std::move(*selection);
        return state;
    } catch (...) {
        return std::nullopt;
    }
}

json document_identity_json(const document_identity_t& identity)
{
    return json{
        {"workspace", std::to_string(identity.workspace.value)},
        {"kind", static_cast<std::uint8_t>(identity.kind)},
        {"object_id", std::to_string(identity.object_id)},
        {"variant_id", std::to_string(identity.variant_id)},
        {"provider_key", identity.provider_key},
        {"has_address", identity.has_address},
        {"address", std::to_string(identity.address)}
    };
}

std::optional<document_identity_t> parse_document_identity_json(const json& value) noexcept
{
    try {
        static constexpr std::array<const char*, 7> fields{{
            "address", "has_address", "kind", "object_id", "provider_key", "variant_id", "workspace"
        }};
        if (!exact_fields(value, fields) || !value["kind"].is_number_unsigned() ||
            !value["has_address"].is_boolean() || !value["provider_key"].is_string())
            return std::nullopt;
        const auto kind_ordinal = value["kind"].get<std::uint64_t>();
        if (!valid_document_kind_ordinal(kind_ordinal))
            return std::nullopt;
        const auto& provider_key =
            value["provider_key"].get_ref<const std::string&>();
        if (provider_key.size() > k_max_document_key_bytes)
            return std::nullopt;
        document_identity_t identity;
        identity.kind = static_cast<document_kind_t>(kind_ordinal);
        identity.has_address = value["has_address"].get<bool>();
        identity.provider_key = provider_key;
        if (!parse_decimal(value["workspace"], identity.workspace.value) ||
            !parse_decimal(value["object_id"], identity.object_id) ||
            !parse_decimal(value["variant_id"], identity.variant_id) ||
            !parse_decimal(value["address"], identity.address))
            return std::nullopt;
        return identity;
    } catch (...) {
        return std::nullopt;
    }
}

json document_dto_json(const document_persistence_dto_t& document)
{
    return json{
        {"id", std::to_string(document.id.value)},
        {"identity", document_identity_json(document.identity)},
        {"title", document.title},
        {"state_token", document.state_token},
        {"local_state", local_state_json(document.local_state)},
        {"pinned", document.pinned},
        {"closeable", document.closeable}
    };
}

std::optional<document_persistence_dto_t> parse_document_dto_json(const json& value) noexcept
{
    try {
        static constexpr std::array<const char*, 7> fields{{
            "closeable", "id", "identity", "local_state", "pinned", "state_token", "title"
        }};
        if (!exact_fields(value, fields) || !value["pinned"].is_boolean() ||
            !value["closeable"].is_boolean() || !value["title"].is_string() ||
            !value["state_token"].is_string())
            return std::nullopt;
        const auto& title = value["title"].get_ref<const std::string&>();
        const auto& state_token =
            value["state_token"].get_ref<const std::string&>();
        if (title.size() > k_max_document_title_bytes ||
            state_token.size() > k_max_panel_state_bytes)
            return std::nullopt;
        document_persistence_dto_t document;
        document.pinned = value["pinned"].get<bool>();
        document.closeable = value["closeable"].get<bool>();
        document.title = title;
        document.state_token = state_token;
        if (!parse_decimal(value["id"], document.id.value))
            return std::nullopt;
        auto identity = parse_document_identity_json(value["identity"]);
        auto local_state = parse_local_state_json(value["local_state"]);
        if (!identity || !local_state)
            return std::nullopt;
        document.identity = std::move(*identity);
        document.local_state = std::move(*local_state);
        return document;
    } catch (...) {
        return std::nullopt;
    }
}

json view_dto_json(const view_persistence_dto_t& view)
{
    return json{
        {"id", std::to_string(view.id.value)},
        {"workspace", std::to_string(view.workspace.value)},
        {"document", std::to_string(view.document.value)},
        {"role", static_cast<std::uint8_t>(view.role)},
        {"synchronization_group", std::to_string(view.synchronization_group)},
        {"synchronization_policy", static_cast<std::uint8_t>(view.synchronization_policy)},
        {"focused", view.focused}
    };
}

std::optional<view_persistence_dto_t> parse_view_dto_json(const json& value) noexcept
{
    try {
        static constexpr std::array<const char*, 7> fields{{
            "document", "focused", "id", "role", "synchronization_group",
            "synchronization_policy", "workspace"
        }};
        if (!exact_fields(value, fields) || !value["role"].is_number_unsigned() ||
            !value["synchronization_policy"].is_number_unsigned() ||
            !value["focused"].is_boolean())
            return std::nullopt;
        const auto role_ordinal = value["role"].get<std::uint64_t>();
        const auto policy_ordinal = value["synchronization_policy"].get<std::uint64_t>();
        if (!valid_view_role_ordinal(role_ordinal) ||
            !valid_sync_policy_ordinal(policy_ordinal))
            return std::nullopt;
        view_persistence_dto_t view;
        view.role = static_cast<view_role_t>(role_ordinal);
        view.synchronization_policy = static_cast<view_synchronization_policy_t>(policy_ordinal);
        view.focused = value["focused"].get<bool>();
        if (!parse_decimal(value["id"], view.id.value) ||
            !parse_decimal(value["workspace"], view.workspace.value) ||
            !parse_decimal(value["document"], view.document.value) ||
            !parse_decimal(value["synchronization_group"], view.synchronization_group))
            return std::nullopt;
        return view;
    } catch (...) {
        return std::nullopt;
    }
}

json panel_dto_json(const panel_state_dto_t& panel)
{
    return json{
        {"id", std::to_string(panel.id.value)},
        {"workspace", std::to_string(panel.workspace.value)},
        {"kind", static_cast<std::uint8_t>(panel.kind)},
        {"visible", panel.visible},
        {"pinned", panel.pinned},
        {"extent_pixels", std::to_string(panel.extent_pixels)},
        {"selected_document", std::to_string(panel.selected_document.value)},
        {"state_token", panel.state_token},
        {"revision", std::to_string(panel.revision.value)}
    };
}

std::optional<panel_state_dto_t> parse_panel_dto_json(const json& value) noexcept
{
    try {
        static constexpr std::array<const char*, 9> fields{{
            "extent_pixels", "id", "kind", "pinned", "revision", "selected_document",
            "state_token", "visible", "workspace"
        }};
        if (!exact_fields(value, fields) || !value["kind"].is_number_unsigned() ||
            !value["visible"].is_boolean() || !value["pinned"].is_boolean() ||
            !value["state_token"].is_string())
            return std::nullopt;
        const auto kind_ordinal = value["kind"].get<std::uint64_t>();
        if (!valid_panel_kind_ordinal(kind_ordinal))
            return std::nullopt;
        const auto& state_token =
            value["state_token"].get_ref<const std::string&>();
        if (state_token.size() > k_max_panel_state_bytes)
            return std::nullopt;
        panel_state_dto_t panel;
        panel.kind = static_cast<panel_kind_t>(kind_ordinal);
        panel.visible = value["visible"].get<bool>();
        panel.pinned = value["pinned"].get<bool>();
        panel.state_token = state_token;
        if (!parse_decimal(value["id"], panel.id.value) ||
            !parse_decimal(value["workspace"], panel.workspace.value) ||
            !parse_decimal(value["extent_pixels"], panel.extent_pixels) ||
            !parse_decimal(value["selected_document"], panel.selected_document.value) ||
            !parse_decimal(value["revision"], panel.revision.value))
            return std::nullopt;
        return panel;
    } catch (...) {
        return std::nullopt;
    }
}

json view_context_json(const workspace_view_context_t& context)
{
    return json{
        {"workspace", std::to_string(context.workspace.value)},
        {"document", std::to_string(context.document.value)},
        {"view", std::to_string(context.view.value)},
        {"selection", selection_json(context.selection)},
        {"cursor", cursor_json(context.cursor)},
        {"synchronization_group", std::to_string(context.synchronization_group)},
        {"synchronization_policy", static_cast<std::uint8_t>(context.synchronization_policy)}
    };
}

std::optional<workspace_view_context_t> parse_view_context_json(const json& value) noexcept
{
    try {
        static constexpr std::array<const char*, 7> fields{{
            "cursor", "document", "selection", "synchronization_group",
            "synchronization_policy", "view", "workspace"
        }};
        if (!exact_fields(value, fields) ||
            !value["synchronization_policy"].is_number_unsigned())
            return std::nullopt;
        const auto policy_ordinal = value["synchronization_policy"].get<std::uint64_t>();
        if (!valid_sync_policy_ordinal(policy_ordinal))
            return std::nullopt;
        workspace_view_context_t context;
        context.synchronization_policy =
            static_cast<view_synchronization_policy_t>(policy_ordinal);
        if (!parse_decimal(value["workspace"], context.workspace.value) ||
            !parse_decimal(value["document"], context.document.value) ||
            !parse_decimal(value["view"], context.view.value) ||
            !parse_decimal(value["synchronization_group"], context.synchronization_group))
            return std::nullopt;
        auto selection = parse_selection_json(value["selection"]);
        auto cursor = parse_cursor_json(value["cursor"]);
        if (!selection || !cursor)
            return std::nullopt;
        context.selection = std::move(*selection);
        context.cursor = std::move(*cursor);
        return context;
    } catch (...) {
        return std::nullopt;
    }
}

json navigation_target_json(const navigation_target_t& target)
{
    return json{
        {"document", document_identity_json(target.document)},
        {"selection", selection_json(target.selection)},
        {"cursor", cursor_json(target.cursor)}
    };
}

std::optional<navigation_target_t> parse_navigation_target_json(const json& value) noexcept
{
    try {
        static constexpr std::array<const char*, 3> fields{{"cursor", "document", "selection"}};
        if (!exact_fields(value, fields))
            return std::nullopt;
        auto identity = parse_document_identity_json(value["document"]);
        auto selection = parse_selection_json(value["selection"]);
        auto cursor = parse_cursor_json(value["cursor"]);
        if (!identity || !selection || !cursor)
            return std::nullopt;
        navigation_target_t target;
        target.document = std::move(*identity);
        target.selection = std::move(*selection);
        target.cursor = std::move(*cursor);
        return target;
    } catch (...) {
        return std::nullopt;
    }
}

json navigation_event_json(const navigation_event_t& event)
{
    json result = json{
        {"id", std::to_string(event.id.value)},
        {"workspace", std::to_string(event.workspace.value)},
        {"has_source", event.has_source},
        {"target", navigation_target_json(event.target)},
        {"origin", static_cast<std::uint8_t>(event.origin)},
        {"sequence", std::to_string(event.sequence)},
        {"request_focus", event.request_focus}
    };
    if (event.has_source)
        result["source"] = view_context_json(event.source);
    else
        result["source"] = nullptr;
    return result;
}

std::optional<navigation_event_t> parse_navigation_event_json(const json& value) noexcept
{
    try {
        static constexpr std::array<const char*, 8> fields{{
            "has_source", "id", "origin", "request_focus", "sequence",
            "source", "target", "workspace"
        }};
        if (!exact_fields(value, fields) || !value["has_source"].is_boolean() ||
            !value["origin"].is_number_unsigned() || !value["request_focus"].is_boolean())
            return std::nullopt;
        const auto origin_ordinal = value["origin"].get<std::uint64_t>();
        if (!valid_nav_origin_ordinal(origin_ordinal))
            return std::nullopt;
        navigation_event_t event;
        event.origin = static_cast<navigation_origin_t>(origin_ordinal);
        event.has_source = value["has_source"].get<bool>();
        event.request_focus = value["request_focus"].get<bool>();
        if (!parse_decimal(value["id"], event.id.value) ||
            !parse_decimal(value["workspace"], event.workspace.value) ||
            !parse_decimal(value["sequence"], event.sequence))
            return std::nullopt;
        auto target = parse_navigation_target_json(value["target"]);
        if (!target)
            return std::nullopt;
        event.target = std::move(*target);
        if (event.has_source) {
            if (value["source"].is_null())
                return std::nullopt;
            auto source = parse_view_context_json(value["source"]);
            if (!source)
                return std::nullopt;
            event.source = std::move(*source);
        } else if (!value["source"].is_null())
            return std::nullopt;
        return event;
    } catch (...) {
        return std::nullopt;
    }
}

json history_json(const navigation_history_dto_t& history)
{
    json back = json::array();
    for (const auto& event : history.back)
        back.push_back(navigation_event_json(event));
    json forward = json::array();
    for (const auto& event : history.forward)
        forward.push_back(navigation_event_json(event));
    return json{
        {"workspace", std::to_string(history.workspace.value)},
        {"capacity", std::to_string(history.capacity)},
        {"back", std::move(back)},
        {"forward", std::move(forward)}
    };
}

std::optional<navigation_history_dto_t> parse_history_json(const json& value) noexcept
{
    try {
        static constexpr std::array<const char*, 4> fields{{
            "back", "capacity", "forward", "workspace"
        }};
        if (!exact_fields(value, fields) || !value["back"].is_array() ||
            !value["forward"].is_array())
            return std::nullopt;
        navigation_history_dto_t history;
        if (!parse_decimal(value["workspace"], history.workspace.value) ||
            !parse_decimal(value["capacity"], history.capacity))
            return std::nullopt;
        if (history.capacity == 0 || history.capacity > k_max_history_capacity ||
            value["back"].size() > history.capacity ||
            value["forward"].size() > history.capacity ||
            value["back"].size() >
                history.capacity - value["forward"].size())
            return std::nullopt;
        history.back.reserve(value["back"].size());
        for (const auto& event_json : value["back"]) {
            auto event = parse_navigation_event_json(event_json);
            if (!event)
                return std::nullopt;
            history.back.push_back(std::move(*event));
        }
        history.forward.reserve(value["forward"].size());
        for (const auto& event_json : value["forward"]) {
            auto event = parse_navigation_event_json(event_json);
            if (!event)
                return std::nullopt;
            history.forward.push_back(std::move(*event));
        }
        return history;
    } catch (...) {
        return std::nullopt;
    }
}

json payload_json_v9(const workbench_persistence_dto_t& dto)
{
    json documents = json::array();
    for (const auto& document : dto.documents)
        documents.push_back(document_dto_json(document));
    json views = json::array();
    for (const auto& view : dto.views)
        views.push_back(view_dto_json(view));
    json panels = json::array();
    for (const auto& panel : dto.panels)
        panels.push_back(panel_dto_json(panel));
    return json{
        {"schema_version", std::to_string(dto.schema_version)},
        {"workspace", std::to_string(dto.workspace.value)},
        {"revision", std::to_string(dto.revision.value)},
        {"active_document", std::to_string(dto.active_document.value)},
        {"layout", layout_json(dto.layout)},
        {"split_tree", split_tree_json(dto.split_tree)},
        {"documents", std::move(documents)},
        {"views", std::move(views)},
        {"panels", std::move(panels)},
        {"history", history_json(dto.history)}
    };
}

std::optional<workbench_persistence_dto_t> parse_payload_json_v9(const json& payload) noexcept
{
    try {
        static constexpr std::array<const char*, 10> fields{{
            "active_document", "documents", "history", "layout", "panels",
            "revision", "schema_version", "split_tree", "views", "workspace"
        }};
        if (!exact_fields(payload, fields) || !payload["documents"].is_array() ||
            !payload["views"].is_array() || !payload["panels"].is_array())
            return std::nullopt;
        if (payload["documents"].size() > k_max_documents_per_workspace ||
            payload["views"].size() > k_max_views_per_workspace ||
            payload["panels"].size() > k_max_panels_per_workspace)
            return std::nullopt;
        workbench_persistence_dto_t dto;
        if (!parse_decimal(payload["schema_version"], dto.schema_version) ||
            !parse_decimal(payload["workspace"], dto.workspace.value) ||
            !parse_decimal(payload["revision"], dto.revision.value) ||
            !parse_decimal(payload["active_document"], dto.active_document.value))
            return std::nullopt;
        auto layout = parse_layout_json(payload["layout"]);
        auto split_tree = parse_split_tree_json(payload["split_tree"]);
        auto history = parse_history_json(payload["history"]);
        if (!layout || !split_tree || !history)
            return std::nullopt;
        dto.layout = std::move(*layout);
        dto.split_tree = std::move(*split_tree);
        dto.history = std::move(*history);
        dto.documents.reserve(payload["documents"].size());
        for (const auto& doc_json : payload["documents"]) {
            auto document = parse_document_dto_json(doc_json);
            if (!document)
                return std::nullopt;
            dto.documents.push_back(std::move(*document));
        }
        dto.views.reserve(payload["views"].size());
        for (const auto& view_json : payload["views"]) {
            auto view = parse_view_dto_json(view_json);
            if (!view)
                return std::nullopt;
            dto.views.push_back(std::move(*view));
        }
        dto.panels.reserve(payload["panels"].size());
        for (const auto& panel_json : payload["panels"]) {
            auto panel = parse_panel_dto_json(panel_json);
            if (!panel)
                return std::nullopt;
            dto.panels.push_back(std::move(*panel));
        }
        return dto;
    } catch (...) {
        return std::nullopt;
    }
}

std::optional<workbench_persistence_dto_t> parse_payload_json_v8(const json& payload) noexcept
{
    try {
        static constexpr std::array<const char*, 8> v8_fields{{
            "active_document", "documents", "history", "layout",
            "revision", "schema_version", "views", "workspace"
        }};
        if (!exact_fields(payload, v8_fields) || !payload["documents"].is_array() ||
            !payload["views"].is_array())
            return std::nullopt;
        if (payload["documents"].size() > k_max_documents_per_workspace ||
            payload["views"].size() > k_max_views_per_workspace)
            return std::nullopt;
        workbench_persistence_dto_t dto;
        if (!parse_decimal(payload["schema_version"], dto.schema_version) ||
            !parse_decimal(payload["workspace"], dto.workspace.value) ||
            !parse_decimal(payload["revision"], dto.revision.value) ||
            !parse_decimal(payload["active_document"], dto.active_document.value))
            return std::nullopt;
        auto layout = parse_layout_json_v8(payload["layout"]);
        auto history = parse_history_json(payload["history"]);
        if (!layout || !history)
            return std::nullopt;
        dto.layout = std::move(*layout);
        dto.history = std::move(*history);
        dto.split_tree = split_tree_dto_t{};
        dto.panels.clear();
        dto.documents.reserve(payload["documents"].size());
        for (const auto& doc_json : payload["documents"]) {
            auto document = parse_document_dto_json(doc_json);
            if (!document)
                return std::nullopt;
            dto.documents.push_back(std::move(*document));
        }
        dto.views.reserve(payload["views"].size());
        for (const auto& view_json : payload["views"]) {
            auto view = parse_view_dto_json(view_json);
            if (!view)
                return std::nullopt;
            dto.views.push_back(std::move(*view));
        }
        return dto;
    } catch (...) {
        return std::nullopt;
    }
}

bool count_fields_recursive(const json& value, std::size_t& count,
                             std::size_t depth, std::size_t max_depth) noexcept
{
    if (depth > max_depth)
        return false;
    if (value.is_object()) {
        count += value.size();
        for (auto it = value.begin(); it != value.end(); ++it) {
            if (!count_fields_recursive(it.value(), count, depth + 1, max_depth))
                return false;
        }
    } else if (value.is_array()) {
        for (const auto& element : value) {
            if (!count_fields_recursive(element, count, depth + 1, max_depth))
                return false;
        }
    }
    return true;
}

bool recover_unknown_documents(workbench_persistence_dto_t& dto,
                               unknown_document_recovery_t recovery,
                               std::string& detail)
{
    bool found_unknown = false;
    for (const auto& document : dto.documents) {
        if (document.identity.kind == document_kind_t::unknown) {
            found_unknown = true;
            break;
        }
    }
    if (!found_unknown)
        return true;

    if (recovery == unknown_document_recovery_t::reject)
        return false;

    if (recovery == unknown_document_recovery_t::upgrade) {
        for (auto& document : dto.documents)
            if (document.identity.kind == document_kind_t::unknown)
                document.identity.kind = document_kind_t::custom;
        detail = "upgraded unknown-kind documents to custom";
        return true;
    }

    std::unordered_set<std::uint64_t> removed_doc_ids;
    std::vector<document_identity_t> removed_identities;
    for (auto it = dto.documents.begin(); it != dto.documents.end(); ) {
        if (it->identity.kind == document_kind_t::unknown) {
            removed_doc_ids.insert(it->id.value);
            removed_identities.push_back(it->identity);
            it = dto.documents.erase(it);
        } else {
            ++it;
        }
    }

    if (dto.documents.empty()) {
        detail = "all documents had unknown kind";
        return false;
    }

    std::vector<std::uint64_t> removed_view_ids;
    for (const auto& view : dto.views) {
        if (removed_doc_ids.count(view.document.value))
            removed_view_ids.push_back(view.id.value);
    }
    std::sort(removed_view_ids.begin(), removed_view_ids.end());

    if (!dto.split_tree.nodes.empty() && !removed_view_ids.empty()) {
        for (const auto view_id : removed_view_ids) {
            const auto remove_result = split_tree_remove_view(dto.split_tree, {view_id});
            if (!remove_result.ok()) {
                dto.split_tree = {};
                break;
            }
        }
    }

    dto.views.erase(
        std::remove_if(dto.views.begin(), dto.views.end(),
            [&](const view_persistence_dto_t& v) {
                return removed_doc_ids.count(v.document.value) != 0;
            }),
        dto.views.end());

    if (removed_doc_ids.count(dto.active_document.value) != 0)
        dto.active_document = dto.documents.front().id;

    for (auto& panel : dto.panels) {
        if (removed_doc_ids.count(panel.selected_document.value) != 0)
            panel.selected_document = {};
    }

    const auto scrub = [&removed_doc_ids, &removed_identities](
            std::vector<navigation_event_t>& events) {
        events.erase(
            std::remove_if(events.begin(), events.end(),
                [&](const navigation_event_t& event) {
                    if (event.has_source &&
                        removed_doc_ids.count(event.source.document.value) != 0)
                        return true;
                    for (const auto& identity : removed_identities)
                        if (document_identity_equal(event.target.document, identity))
                            return true;
                    return false;
                }),
            events.end());
    };
    scrub(dto.history.back);
    scrub(dto.history.forward);

    detail = "omitted " + std::to_string(removed_doc_ids.size()) +
             " unknown-kind document(s)";
    return true;
}

workbench_error_t persistence_adapter_error(
    const analysis::workspace_error_t& error, std::uint64_t subject) noexcept
{
    switch (error.code) {
    case analysis::workspace_error_code_t::target_conflict:
        return {workbench_error_code_t::revision_mismatch, subject};
    case analysis::workspace_error_code_t::invalid_argument:
    case analysis::workspace_error_code_t::integrity_failure:
    case analysis::workspace_error_code_t::limit_exceeded:
        return {workbench_error_code_t::invalid_persistence, subject};
    default:
        return {workbench_error_code_t::adapter_rejected, subject};
    }
}

}

persistence_codec_result_t workbench_persistence_codec_t::encode(
    const workbench_persistence_dto_t& dto,
    std::string& output,
    const persistence_codec_limits_t& limits)
{
    output.clear();
    if (auto limit_error = preflight_json({}, limits))
        return *limit_error;
    workbench_persistence_dto_t normalized = dto;
    const auto norm_result = normalize_persistence_dto(normalized);
    if (!norm_result)
        return codec_error(persistence_codec_code_t::normalization_failed,
                           "normalize_persistence_dto rejected the input");
    const auto validate_result = validate_persistence_dto(normalized);
    if (!validate_result)
        return codec_error(persistence_codec_code_t::validation_failed,
                           "validate_persistence_dto rejected the normalized input");
    const auto fingerprint = persistence_fingerprint(normalized);
    if (!fingerprint.value)
        return codec_error(persistence_codec_code_t::fingerprint_mismatch,
                           "fingerprint computation produced zero");
    try {
        json envelope = json{
            {"schema", k_persistence_codec_schema_v9},
            {"kind", k_persistence_codec_kind_v9},
            {"payload", payload_json_v9(normalized)}
        };
        output = envelope.dump();
    } catch (const std::exception& exc) {
        return codec_error(persistence_codec_code_t::corrupt_payload, exc.what());
    } catch (...) {
        return codec_error(persistence_codec_code_t::corrupt_payload,
                           "unknown serialization exception");
    }
    if (auto preflight_error = preflight_json(output, limits)) {
        output.clear();
        return *preflight_error;
    }
    persistence_codec_result_t result;
    result.code = persistence_codec_code_t::ok;
    result.fingerprint = fingerprint;
    result.decoded_schema = k_persistence_codec_schema_v9;
    return result;
}

persistence_codec_result_t workbench_persistence_codec_t::decode(
    std::string_view input,
    workspace_id_t expected_workspace,
    workbench_persistence_dto_t& output,
    const persistence_codec_limits_t& limits)
{
    if (input.empty())
        return codec_error(persistence_codec_code_t::empty_input);
    if (auto preflight_error = preflight_json(input, limits))
        return *preflight_error;
    json envelope;
    try {
        envelope = json::parse(input.begin(), input.end(), nullptr, false);
    } catch (...) {
        return codec_error(persistence_codec_code_t::invalid_json);
    }
    if (envelope.is_discarded() || !envelope.is_object())
        return codec_error(persistence_codec_code_t::invalid_json,
                           "top-level is not a JSON object");
    static constexpr std::array<const char*, 3> envelope_fields{{"kind", "payload", "schema"}};
    if (!exact_fields(envelope, envelope_fields) ||
        !envelope["schema"].is_number_unsigned() ||
        !envelope["kind"].is_string() ||
        !envelope["payload"].is_object())
        return codec_error(persistence_codec_code_t::corrupt_payload,
                           "envelope missing required fields");
    const auto schema = envelope["schema"].get<std::uint64_t>();
    if (schema != k_persistence_codec_schema_v9)
        return codec_error(persistence_codec_code_t::schema_mismatch,
                           "expected schema v9, got " + std::to_string(schema));
    const auto& kind = envelope["kind"].get_ref<const std::string&>();
    if (kind != k_persistence_codec_kind_v9)
        return codec_error(persistence_codec_code_t::unknown_kind,
                           "unexpected kind: " + kind);
    std::size_t field_count = 0;
    if (!count_fields_recursive(envelope, field_count, 0, limits.max_json_depth))
        return codec_error(persistence_codec_code_t::oversized_payload,
                           "JSON depth or field count exceeds limits");
    if (field_count > limits.max_field_count)
        return codec_error(persistence_codec_code_t::field_count_exceeded,
                           "total field count exceeds max_field_count");
    auto dto = parse_payload_json_v9(envelope["payload"]);
    if (!dto)
        return codec_error(persistence_codec_code_t::corrupt_payload,
                           "failed to parse v9 payload");
    if (dto->workspace != expected_workspace)
        return codec_error(persistence_codec_code_t::workspace_isolation_violation,
                           "payload workspace does not match expected workspace");
    const auto norm_result = normalize_persistence_dto(*dto);
    if (!norm_result)
        return codec_error(persistence_codec_code_t::normalization_failed,
                           "normalize_persistence_dto rejected the decoded input");
    const auto validate_result = validate_persistence_dto(*dto);
    if (!validate_result)
        return codec_error(persistence_codec_code_t::validation_failed,
                           "validate_persistence_dto rejected the decoded normalized input");
    const auto fingerprint = persistence_fingerprint(*dto);
    if (!fingerprint.value)
        return codec_error(persistence_codec_code_t::fingerprint_mismatch,
                           "decoded fingerprint is zero");
    output = std::move(*dto);
    persistence_codec_result_t result;
    result.code = persistence_codec_code_t::ok;
    result.fingerprint = fingerprint;
    result.decoded_schema = k_persistence_codec_schema_v9;
    return result;
}

persistence_codec_result_t workbench_persistence_codec_t::decode_v8_default(
    std::string_view input,
    workspace_id_t expected_workspace,
    workbench_persistence_dto_t& output,
    const persistence_codec_limits_t& limits)
{
    if (input.empty())
        return codec_error(persistence_codec_code_t::empty_input);
    if (auto preflight_error = preflight_json(input, limits))
        return *preflight_error;
    json envelope;
    try {
        envelope = json::parse(input.begin(), input.end(), nullptr, false);
    } catch (...) {
        return codec_error(persistence_codec_code_t::invalid_json);
    }
    if (envelope.is_discarded() || !envelope.is_object())
        return codec_error(persistence_codec_code_t::invalid_json);
    static constexpr std::array<const char*, 2> v8_envelope_fields{{"payload", "schema"}};
    if (!exact_fields(envelope, v8_envelope_fields) ||
        !envelope["schema"].is_number_unsigned() ||
        !envelope["payload"].is_object())
        return codec_error(persistence_codec_code_t::corrupt_payload,
                           "v8 envelope missing required fields");
    const auto schema = envelope["schema"].get<std::uint64_t>();
    if (schema != k_persistence_codec_schema_v8)
        return codec_error(persistence_codec_code_t::v8_legacy_unsupported,
                           "expected schema v8, got " + std::to_string(schema));
    std::size_t field_count = 0;
    if (!count_fields_recursive(envelope, field_count, 0, limits.max_json_depth))
        return codec_error(persistence_codec_code_t::oversized_payload,
                           "JSON depth exceeds max_json_depth");
    if (field_count > limits.max_field_count)
        return codec_error(persistence_codec_code_t::field_count_exceeded,
                           "total field count exceeds max_field_count");
    auto dto = parse_payload_json_v8(envelope["payload"]);
    if (!dto)
        return codec_error(persistence_codec_code_t::corrupt_payload,
                           "failed to parse v8 payload");
    if (dto->workspace != expected_workspace)
        return codec_error(persistence_codec_code_t::workspace_isolation_violation,
                           "v8 payload workspace does not match expected workspace");
    dto->schema_version = k_workbench_contract_schema_version;
    normalize_fixed_layout_constraints(dto->layout);
    if (dto->history.capacity == 0)
        dto->history.capacity = k_default_history_capacity;
    dto->history.workspace = dto->workspace;
    if (dto->split_tree.nodes.empty())
        dto->split_tree.root = split_node_id_t{0};
    for (auto& view : dto->views) {
        if (view.workspace.value == 0)
            view.workspace = dto->workspace;
    }
    const auto norm_result = normalize_persistence_dto(*dto);
    if (!norm_result)
        return codec_error(persistence_codec_code_t::normalization_failed,
                           "normalize_persistence_dto rejected the v8-upgraded input");
    const auto fingerprint = persistence_fingerprint(*dto);
    if (!fingerprint.value)
        return codec_error(persistence_codec_code_t::fingerprint_mismatch,
                           "decoded v8 fingerprint is zero");
    output = std::move(*dto);
    persistence_codec_result_t result;
    result.code = persistence_codec_code_t::ok;
    result.fingerprint = fingerprint;
    result.decoded_schema = k_persistence_codec_schema_v8;
    return result;
}

persistence_codec_result_t workbench_persistence_codec_t::round_trip(
    const workbench_persistence_dto_t& dto,
    persistence_fingerprint_t& encode_fingerprint,
    persistence_fingerprint_t& decode_fingerprint,
    const persistence_codec_limits_t& limits)
{
    std::string encoded;
    const auto encode_result = encode(dto, encoded, limits);
    if (!encode_result)
        return encode_result;
    encode_fingerprint = encode_result.fingerprint;
    workbench_persistence_dto_t decoded;
    const auto decode_result = decode(encoded, dto.workspace, decoded, limits);
    if (!decode_result)
        return decode_result;
    decode_fingerprint = decode_result.fingerprint;
    if (encode_fingerprint != decode_fingerprint)
        return codec_error(persistence_codec_code_t::fingerprint_mismatch,
                           "encode and decode fingerprints differ");
    persistence_codec_result_t result;
    result.code = persistence_codec_code_t::ok;
    result.fingerprint = decode_fingerprint;
    result.decoded_schema = k_persistence_codec_schema_v9;
    return result;
}

bool workbench_persistence_codec_t::is_corrupt(std::string_view input) noexcept
{
    if (input.empty())
        return true;
    if (preflight_json(input, {}).has_value())
        return true;
    try {
        auto value = json::parse(input.begin(), input.end(), nullptr, false);
        if (value.is_discarded() || !value.is_object())
            return true;
        if (!value.contains("schema") || !value["schema"].is_number_unsigned())
            return true;
        if (!value.contains("payload") || !value["payload"].is_object())
            return true;
        const auto schema = value["schema"].get<std::uint64_t>();
        if (schema != k_persistence_codec_schema_v9 && schema != k_persistence_codec_schema_v8)
            return true;
        return false;
    } catch (...) {
        return true;
    }
}

bool workbench_persistence_codec_t::is_oversized(
    std::string_view input,
    const persistence_codec_limits_t& limits) noexcept
{
    const auto result = preflight_json(input, limits);
    return result &&
        (result->code == persistence_codec_code_t::oversized_payload ||
         result->code == persistence_codec_code_t::field_count_exceeded);
}

std::optional<persistence_envelope_t> workbench_persistence_codec_t::peek_envelope(
    std::string_view input) noexcept
{
    if (input.empty() || input.size() > k_persistence_codec_max_envelope_bytes ||
        preflight_json(input, {}).has_value())
        return std::nullopt;
    try {
        auto value = json::parse(input.begin(), input.end(), nullptr, false);
        if (value.is_discarded() || !value.is_object() ||
            !value.contains("schema") || !value["schema"].is_number_unsigned())
            return std::nullopt;
        persistence_envelope_t envelope;
        const auto schema = value["schema"].get<std::uint64_t>();
        if (schema > (std::numeric_limits<std::uint32_t>::max)())
            return std::nullopt;
        envelope.schema = static_cast<std::uint32_t>(schema);
        if (value.contains("kind") && value["kind"].is_string())
            envelope.kind = value["kind"].get<std::string>();
        envelope.is_v8_legacy = envelope.schema == k_persistence_codec_schema_v8;
        return envelope;
    } catch (...) {
        return std::nullopt;
    }
}

std::string workbench_persistence_codec_t::normalize_and_encode(
    const workbench_persistence_dto_t& dto,
    persistence_codec_result_t& result,
    const persistence_codec_limits_t& limits)
{
    std::string output;
    result = encode(dto, output, limits);
    return output;
}

persistence_codec_result_t workbench_persistence_codec_t::decode_and_normalize(
    std::string_view input,
    workspace_id_t expected_workspace,
    workbench_persistence_dto_t& output,
    persistence_fingerprint_t& fingerprint,
    const persistence_codec_limits_t& limits)
{
    const auto result = decode(input, expected_workspace, output, limits);
    if (result)
        fingerprint = result.fingerprint;
    return result;
}

persistence_codec_result_t workbench_persistence_codec_t::check_revision_conflict(
    workspace_revision_t expected,
    workspace_revision_t observed) noexcept
{
    persistence_codec_result_t result;
    if (!expected.valid())
        return result;
    if (!observed.valid() || expected != observed) {
        result.code = persistence_codec_code_t::revision_conflict;
        return result;
    }
    return result;
}

persistence_codec_result_t workbench_persistence_codec_t::decode_with_recovery(
    std::string_view input,
    workspace_id_t expected_workspace,
    workspace_revision_t expected_revision,
    unknown_document_recovery_t recovery,
    workbench_persistence_dto_t& output,
    const persistence_codec_limits_t& limits)
{
    if (input.empty())
        return codec_error(persistence_codec_code_t::empty_input);
    if (auto preflight_error = preflight_json(input, limits))
        return *preflight_error;
    json envelope;
    try {
        envelope = json::parse(input.begin(), input.end(), nullptr, false);
    } catch (...) {
        return codec_error(persistence_codec_code_t::invalid_json);
    }
    if (envelope.is_discarded() || !envelope.is_object())
        return codec_error(persistence_codec_code_t::invalid_json,
                           "top-level is not a JSON object");
    static constexpr std::array<const char*, 3> envelope_fields{{"kind", "payload", "schema"}};
    if (!exact_fields(envelope, envelope_fields) ||
        !envelope["schema"].is_number_unsigned() ||
        !envelope["kind"].is_string() ||
        !envelope["payload"].is_object())
        return codec_error(persistence_codec_code_t::corrupt_payload,
                           "envelope missing required fields");
    const auto schema = envelope["schema"].get<std::uint64_t>();
    if (schema != k_persistence_codec_schema_v9)
        return codec_error(persistence_codec_code_t::schema_mismatch,
                           "expected schema v9, got " + std::to_string(schema));
    const auto& kind = envelope["kind"].get_ref<const std::string&>();
    if (kind != k_persistence_codec_kind_v9)
        return codec_error(persistence_codec_code_t::unknown_kind,
                           "unexpected kind: " + kind);
    std::size_t field_count = 0;
    if (!count_fields_recursive(envelope, field_count, 0, limits.max_json_depth))
        return codec_error(persistence_codec_code_t::oversized_payload,
                           "JSON depth or field count exceeds limits");
    if (field_count > limits.max_field_count)
        return codec_error(persistence_codec_code_t::field_count_exceeded,
                           "total field count exceeds max_field_count");
    auto dto = parse_payload_json_v9(envelope["payload"]);
    if (!dto)
        return codec_error(persistence_codec_code_t::corrupt_payload,
                           "failed to parse v9 payload");
    if (dto->workspace != expected_workspace)
        return codec_error(persistence_codec_code_t::workspace_isolation_violation,
                           "payload workspace does not match expected workspace");

    if (expected_revision.valid()) {
        const auto conflict_result = check_revision_conflict(expected_revision, dto->revision);
        if (!conflict_result)
            return conflict_result;
    }

    std::string recovery_detail;
    if (recovery != unknown_document_recovery_t::reject) {
        const auto recovery_ok = recover_unknown_documents(*dto, recovery, recovery_detail);
        if (!recovery_ok)
            return codec_error(persistence_codec_code_t::recovery_exhausted,
                               recovery_detail.empty() ?
                                   "all documents recovered as unknown" : recovery_detail);
    }

    const auto norm_result = normalize_persistence_dto(*dto);
    if (!norm_result)
        return codec_error(persistence_codec_code_t::normalization_failed,
                           "normalize_persistence_dto rejected the recovered input");
    const auto validate_result = validate_persistence_dto(*dto);
    if (!validate_result)
        return codec_error(persistence_codec_code_t::validation_failed,
                           "validate_persistence_dto rejected the recovered normalized input");
    const auto fingerprint = persistence_fingerprint(*dto);
    if (!fingerprint.value)
        return codec_error(persistence_codec_code_t::fingerprint_mismatch,
                           "recovered fingerprint is zero");
    output = std::move(*dto);
    persistence_codec_result_t result;
    result.code = persistence_codec_code_t::ok;
    result.fingerprint = fingerprint;
    result.decoded_schema = k_persistence_codec_schema_v9;
    result.detail = std::move(recovery_detail);
    return result;
}

workspace_database_workbench_persistence_adapter_t::
workspace_database_workbench_persistence_adapter_t(
    std::shared_ptr<analysis::workspace_database_t> database,
    workspace_id_t workspace,
    persistence_codec_limits_t limits)
    : database_(std::move(database)), workspace_(workspace), limits_(limits)
{
}

workbench_error_t workspace_database_workbench_persistence_adapter_t::load(
    workspace_id_t workspace, workbench_persistence_dto_t& output) const
{
    if (!database_ || !workspace_.valid() || workspace != workspace_)
        return {workbench_error_code_t::workspace_mismatch, workspace.value};
    const auto deadline = std::chrono::steady_clock::now() +
        std::chrono::milliseconds(database_->options().candidate_operation_timeout_ms);
    analysis::cancellation_source_t cancellation(deadline);
    const auto read = database_->load_workbench_state(cancellation.token());
    if (!read)
        return persistence_adapter_error(read.error(), workspace.value);
    if (!read.value())
        return {workbench_error_code_t::adapter_rejected, workspace.value};
    const auto& record = *read.value();
    if (record.workspace_id != workspace.value)
        return {workbench_error_code_t::workspace_mismatch, record.workspace_id};
    workbench_persistence_dto_t decoded;
    const auto decoded_result = workbench_persistence_codec_t::decode(
        record.payload_json, workspace, decoded, limits_);
    if (!decoded_result || decoded.schema_version != record.contract_schema_version ||
        decoded.revision.value != record.revision ||
        decoded_result.fingerprint.value != record.fingerprint)
        return {workbench_error_code_t::invalid_persistence, record.revision};
    output = std::move(decoded);
    return {};
}

workbench_error_t workspace_database_workbench_persistence_adapter_t::store(
    const workbench_persistence_dto_t& input)
{
    if (!database_ || !workspace_.valid() || input.workspace != workspace_)
        return {workbench_error_code_t::workspace_mismatch, input.workspace.value};
    workbench_persistence_dto_t normalized = input;
    const auto normalized_result = normalized.normalize();
    if (!normalized_result)
        return normalized_result;
    const auto validation_result = normalized.validate();
    if (!validation_result)
        return validation_result;
    std::string payload;
    const auto encoded = workbench_persistence_codec_t::encode(
        normalized, payload, limits_);
    if (!encoded)
        return {workbench_error_code_t::invalid_persistence,
                normalized.revision.value};
    analysis::workbench_state_record_t record;
    record.workspace_id = normalized.workspace.value;
    record.contract_schema_version = normalized.schema_version;
    record.revision = normalized.revision.value;
    record.fingerprint = encoded.fingerprint.value;
    record.payload_json = std::move(payload);
    const auto deadline = std::chrono::steady_clock::now() +
        std::chrono::milliseconds(database_->options().candidate_operation_timeout_ms);
    analysis::cancellation_source_t cancellation(deadline);
    auto ticket = database_->store_workbench_state(
        std::move(record), cancellation.token());
    if (!ticket.accepted || !ticket.completion.valid())
        return {workbench_error_code_t::adapter_rejected,
                normalized.revision.value};
    if (ticket.completion.wait_until(deadline) != std::future_status::ready) {
        cancellation.request_cancel();
        return {workbench_error_code_t::adapter_rejected,
                normalized.revision.value};
    }
    try {
        const auto& stored = ticket.completion.get();
        if (!stored)
            return persistence_adapter_error(stored.error(),
                                             normalized.revision.value);
    } catch (...) {
        return {workbench_error_code_t::adapter_rejected,
                normalized.revision.value};
    }
    return {};
}

}
}
