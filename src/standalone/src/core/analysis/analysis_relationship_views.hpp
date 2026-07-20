#pragma once

#include "analysis_list_views.hpp"
#include "../ui/empty_state.hpp"
#include "../ui/fonts.hpp"
#include "../ui/theme.hpp"
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../../preview/studio_semantics.hpp"
#endif
#include "imgui/imgui.h"
#include <Zydis/Zydis.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace analysis_relationship_views {

inline std::string address_text(std::uint64_t address) {
    return analysis_list_views::address_text(address);
}

inline std::string register_text(std::uint16_t value) {
    const char* name = ZydisRegisterGetString(static_cast<ZydisRegister>(value));
    if (name && *name) {
        std::string result(name);
        std::transform(result.begin(), result.end(), result.begin(), [](unsigned char ch) {
            return static_cast<char>(std::toupper(ch));
        });
        return result;
    }
    return "Register #" + std::to_string(value);
}

inline const char* provenance_text(aida::analysis::fact_provenance_t provenance) {
    using value_t = aida::analysis::fact_provenance_t;
    switch (provenance) {
    case value_t::gap_recovery: return "Gap recovery";
    case value_t::linear_validation: return "Linear validation";
    case value_t::recursive_decode: return "Recursive decode";
    case value_t::relocation: return "Relocation";
    case value_t::call_target: return "Call target";
    case value_t::export_entry: return "Export entry";
    case value_t::tls_entry: return "TLS entry";
    case value_t::image_entry: return "Image entry";
    case value_t::unwind_metadata: return "Unwind metadata";
    case value_t::debug_symbol: return "Debug symbol";
    case value_t::user_definition: return "User definition";
    case value_t::decompiler_feedback: return "Decompiler feedback";
    default: return "Decoded fact";
    }
}

inline bool contains(const std::string& value, const std::string& query) {
    return analysis_list_views::contains_case_insensitive(value, query);
}

namespace segment_registers {

struct row_t {
    std::uint64_t address = 0;
    std::uint64_t end_address = 0;
    aida::analysis::entity_id_t instruction_id = 0;
    std::uint16_t register_id = 0;
    std::uint8_t operand_index = 0;
    bool segment_relative = false;
    aida::analysis::fact_provenance_t provenance = aida::analysis::fact_provenance_t::unknown;
    std::uint8_t confidence = 0;
    std::uint64_t observations = 0;
};

struct group_identity_t {
    std::uint64_t scope = 0;
    std::uint16_t register_id = 0;
    bool segment_relative = false;

    bool operator==(const group_identity_t& other) const noexcept {
        return scope == other.scope && register_id == other.register_id &&
            segment_relative == other.segment_relative;
    }
};

struct group_identity_hash_t {
    std::size_t operator()(const group_identity_t& value) const noexcept {
        std::uint64_t hash = value.scope ^
            (static_cast<std::uint64_t>(value.register_id) * 0x9E3779B97F4A7C15ULL);
        if (value.segment_relative) hash ^= 0xD6E8FEB86659FD93ULL;
        return static_cast<std::size_t>(hash);
    }
};

struct state_t {
    bool initialized = false;
    std::uint64_t generation = 0;
    std::uint64_t revision = 0;
    std::uint64_t overlay_revision = 0;
    std::size_t instruction_cursor = 0;
    bool complete = false;
    std::vector<row_t> rows;
    std::unordered_map<group_identity_t, std::size_t, group_identity_hash_t> groups;
    std::uint64_t observations = 0;
    std::vector<std::size_t> visible;
    char filter[160]{};
    std::string applied_filter;
    bool filter_dirty = true;
    std::size_t selected = static_cast<std::size_t>(-1);
};

inline std::unordered_map<std::string, std::shared_ptr<state_t>>& states() {
    static std::unordered_map<std::string, std::shared_ptr<state_t>> value;
    return value;
}

inline std::shared_ptr<state_t> state_for(
    const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace) {
    const std::string key = workspace ? workspace->identity().binary_id().to_hex() : "none";
    auto& value = states()[key];
    if (!value) value = std::make_shared<state_t>();
    return value;
}

inline void reset_if_needed(state_t& state,
                            const disasm_view::workspace_context_t& context) {
    const auto& publication = *context.publication;
    if (state.initialized && state.generation == publication.generation &&
        state.revision == publication.analysis_revision &&
        state.overlay_revision == publication.overlay_revision)
        return;
    state.initialized = true;
    state.generation = publication.generation;
    state.revision = publication.analysis_revision;
    state.overlay_revision = publication.overlay_revision;
    state.instruction_cursor = 0;
    state.complete = false;
    state.rows.clear();
    state.groups.clear();
    state.observations = 0;
    state.visible.clear();
    state.filter_dirty = true;
    state.selected = static_cast<std::size_t>(-1);
}

inline void advance_projection(state_t& state,
                               const disasm_view::workspace_context_t& context) {
    if (state.complete || !context.publication || !context.publication->snapshot) return;
    const auto& snapshot = *context.publication->snapshot;
    const std::size_t begin = state.instruction_cursor;
    const std::size_t end = (std::min)(snapshot.instructions.size(), begin + 2048U);
    disasm_view::request_format_range(context, begin, end);
    for (std::size_t index = begin; index < end; ++index) {
        const auto& instruction = snapshot.instructions[index];
        const std::size_t operand_begin = instruction.operand_fact_begin;
        const std::size_t operand_end = (std::min)(snapshot.operand_facts.size(),
            operand_begin + static_cast<std::size_t>(instruction.operand_fact_count));
        for (std::size_t operand_index = operand_begin; operand_index < operand_end; ++operand_index) {
            const auto& operand = snapshot.operand_facts[operand_index];
            if (operand.kind != aida::analysis::operand_kind_t::memory || operand.segment_reg == 0)
                continue;
            const auto runtime = disasm_view::runtime_address(context, instruction.address);
            if (!runtime || *runtime == 0) continue;
            const bool segment_relative = operand.address_expression ==
                aida::analysis::address_expression_kind_t::segment_relative;
            const std::uint64_t function = disasm_view::enclosing_function_start(*runtime, context);
            const std::uint64_t scope = function != 0 ? function : (*runtime & ~0xFFFULL);
            const group_identity_t identity{scope, operand.segment_reg, segment_relative};
            const auto found = state.groups.find(identity);
            if (found == state.groups.end()) {
                const std::size_t row_index = state.rows.size();
                state.groups.emplace(identity, row_index);
                row_t row;
                row.address = *runtime;
                row.end_address = *runtime;
                row.instruction_id = instruction.id;
                row.register_id = operand.segment_reg;
                row.operand_index = operand.operand_index;
                row.segment_relative = segment_relative;
                row.provenance = instruction.provenance;
                row.confidence = instruction.confidence;
                row.observations = 1;
                state.rows.push_back(std::move(row));
            } else {
                auto& row = state.rows[found->second];
                row.address = (std::min)(row.address, *runtime);
                row.end_address = (std::max)(row.end_address, *runtime);
                ++row.observations;
                if (instruction.confidence > row.confidence) {
                    row.instruction_id = instruction.id;
                    row.operand_index = operand.operand_index;
                    row.provenance = instruction.provenance;
                    row.confidence = instruction.confidence;
                }
            }
            ++state.observations;
        }
    }
    state.instruction_cursor = end;
    state.complete = end >= snapshot.instructions.size();
    state.filter_dirty = true;
}

inline std::string instruction_text(const row_t& row,
                                    const disasm_view::workspace_context_t& context) {
    const auto formatted = disasm_view::formatted_instruction(context, row.instruction_id);
    if (formatted && !formatted->text.empty()) return formatted->text;
    return "Decoded memory operand " + std::to_string(row.operand_index);
}

inline std::string observed_span(const row_t& row) {
    if (row.address == row.end_address) return address_text(row.address);
    return address_text(row.address) + " - " + address_text(row.end_address);
}

inline void rebuild_visible(state_t& state,
                            const disasm_view::workspace_context_t& context) {
    const std::string requested = analysis_list_views::lower(state.filter);
    if (!state.filter_dirty && requested == state.applied_filter) return;
    state.applied_filter = requested;
    state.visible.clear();
    state.visible.reserve(state.rows.size());
    for (std::size_t index = 0; index < state.rows.size(); ++index) {
        const auto& row = state.rows[index];
        const std::string reg = register_text(row.register_id);
        const std::string instruction = instruction_text(row, context);
        if (requested.empty() || contains(reg, requested) || contains(instruction, requested) ||
            contains(observed_span(row), requested) ||
            contains(provenance_text(row.provenance), requested))
            state.visible.push_back(index);
    }
    std::stable_sort(state.visible.begin(), state.visible.end(), [&](std::size_t left, std::size_t right) {
        const auto& lhs = state.rows[left];
        const auto& rhs = state.rows[right];
        if (lhs.register_id != rhs.register_id) return lhs.register_id < rhs.register_id;
        return lhs.address < rhs.address;
    });
    if (state.selected >= state.rows.size() ||
        std::find(state.visible.begin(), state.visible.end(), state.selected) == state.visible.end())
        state.selected = static_cast<std::size_t>(-1);
    state.filter_dirty = false;
}

inline analysis_list_views::row_t action_row(const row_t& row) {
    analysis_list_views::row_t result;
    result.address = row.address;
    result.has_address = true;
    result.name = register_text(row.register_id);
    result.context = row.segment_relative ? "Segment-relative decoded fact" : "Decoded segment component";
    result.detail = std::to_string(row.observations) + " decoded observation" +
        (row.observations == 1 ? "" : "s") + " in " + observed_span(row);
    return result;
}

inline void render() {
    const auto workspace = aida::analysis::workspace_registry().selected_for_ui();
    const auto context = disasm_view::capture_workspace(workspace);
    const ImVec2 available = ImGui::GetContentRegionAvail();
    if (!context) {
        aida::ui::empty_state::config_t empty;
        empty.glyph = aida::ui::empty_state::glyph_t::binary_file;
        empty.title = "No analysis workspace";
        empty.body = "Open and analyze a binary to inspect decoded segment-register components.";
        aida::ui::empty_state::render(ImGui::GetCursorScreenPos(), available, empty);
        return;
    }
    const auto state = state_for(workspace);
    reset_if_needed(*state, context);
    advance_projection(*state, context);
    rebuild_visible(*state, context);

    ImGui::PushID("view.analysis.segment_registers");
    const float toolbar_start_y = ImGui::GetCursorScreenPos().y;
    ImGui::PushFont(aida::ui::fonts::body_strong() ? aida::ui::fonts::body_strong() : ImGui::GetFont());
    ImGui::AlignTextToFramePadding();
    ImGui::TextUnformatted("Segment Registers");
    ImGui::PopFont();
    ImGui::SameLine();
    ImGui::TextDisabled("%zu groups | %llu facts%s", state->visible.size(),
        static_cast<unsigned long long>(state->observations), state->complete ? "" : " | scanning");
    ImGui::SetNextItemWidth(-1.0f);
    if (aida::ui::input_text("##filter", state->filter, sizeof(state->filter),
            "Filter register, address, instruction...", false, ImVec2(0.0f, 25.0f)))
        state->filter_dirty = true;
    if (!state->complete) {
        const auto total = context.publication->snapshot->instructions.size();
        const float fraction = total == 0 ? 1.0f :
            static_cast<float>(state->instruction_cursor) / static_cast<float>(total);
        ImGui::ProgressBar(fraction, ImVec2(-1.0f, 3.0f), "");
    }
    const float toolbar_height = (std::max)(0.0f,
        ImGui::GetCursorScreenPos().y - toolbar_start_y);

    if (state->rows.empty() && state->complete) {
        aida::ui::empty_state::config_t empty;
        empty.glyph = aida::ui::empty_state::glyph_t::search;
        empty.title = "No decoded segment components";
        empty.body = "No decoded memory operand publishes a segment-register component. Live CS, DS, ES, FS, GS and SS selector values remain in Debugger CPU while a target is paused.";
        aida::ui::empty_state::render(ImGui::GetCursorScreenPos(),
            ImVec2(available.x, (std::max)(1.0f, available.y - toolbar_height)), empty);
        ImGui::PopID();
        return;
    }
    if (state->visible.empty() && !state->rows.empty()) {
        aida::ui::empty_state::config_t empty;
        empty.glyph = aida::ui::empty_state::glyph_t::search;
        empty.title = "No matches";
        empty.body = "No decoded segment-register component matches the current filter.";
        aida::ui::empty_state::render(ImGui::GetCursorScreenPos(),
            ImVec2(available.x, (std::max)(1.0f, available.y - toolbar_height)), empty);
        ImGui::PopID();
        return;
    }

    const float table_height = (std::max)(1.0f, ImGui::GetContentRegionAvail().y);
    const ImGuiTableFlags flags = ImGuiTableFlags_Resizable | ImGuiTableFlags_Reorderable |
        ImGuiTableFlags_Hideable | ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV |
        ImGuiTableFlags_ScrollX | ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingStretchProp;
    std::size_t pointer_context = static_cast<std::size_t>(-1);
    if (ImGui::BeginTable("##segment_registers", 6, flags,
            ImVec2(available.x, table_height), 820.0f)) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Register", ImGuiTableColumnFlags_WidthFixed, 90.0f);
        ImGui::TableSetupColumn("Observed span", ImGuiTableColumnFlags_WidthFixed, 220.0f);
        ImGui::TableSetupColumn("Facts", ImGuiTableColumnFlags_WidthFixed, 54.0f);
        ImGui::TableSetupColumn("Instruction", ImGuiTableColumnFlags_WidthStretch, 1.7f);
        ImGui::TableSetupColumn("Evidence", ImGuiTableColumnFlags_WidthStretch, 0.8f);
        ImGui::TableSetupColumn("Confidence", ImGuiTableColumnFlags_WidthFixed, 76.0f);
        ImGui::TableHeadersRow();
        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(state->visible.size()), 22.0f);
        while (clipper.Step()) {
            for (int visible = clipper.DisplayStart; visible < clipper.DisplayEnd; ++visible) {
                const std::size_t source = state->visible[static_cast<std::size_t>(visible)];
                const auto& row = state->rows[source];
                ImGui::TableNextRow(0, 22.0f);
                ImGui::TableSetColumnIndex(0);
                ImGui::PushID(static_cast<int>(source));
                const bool activated = ImGui::Selectable("##row", state->selected == source,
                    ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowDoubleClick,
                    ImVec2(0.0f, 20.0f));
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
                const std::string row_identity = std::to_string(row.address) + ":" +
                    std::to_string(row.register_id) + ":" +
                    std::to_string(row.segment_relative);
                const std::string row_semantic = aida::preview::semantics::stable_id(
                    "aida.segment-register-row",
                    aida::preview::semantics::entity_token(row_identity));
                static_cast<void>(aida::preview::semantics::register_last_item(row_semantic,
                    "relationship-row", false, false,
                    "aida.dock-window.view.analysis.segment-registers"));
#endif
                if (activated) {
                    state->selected = source;
                    disasm_view::select_address(row.address, context);
                    if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left))
                        analysis_list_views::open_disassembly(action_row(row), context);
                }
                if (ImGui::IsItemClicked(ImGuiMouseButton_Right)) {
                    state->selected = source;
                    disasm_view::select_address(row.address, context, false);
                    pointer_context = source;
                }
                ImGui::SameLine();
                ImGui::TextUnformatted(register_text(row.register_id).c_str());
                ImGui::TableSetColumnIndex(1);
                ImGui::PushFont(aida::ui::fonts::code() ? aida::ui::fonts::code() : ImGui::GetFont());
                ImGui::TextUnformatted(observed_span(row).c_str());
                ImGui::PopFont();
                ImGui::TableSetColumnIndex(2);
                ImGui::Text("%llu", static_cast<unsigned long long>(row.observations));
                ImGui::TableSetColumnIndex(3);
                ImGui::TextUnformatted(instruction_text(row, context).c_str());
                ImGui::TableSetColumnIndex(4);
                ImGui::TextUnformatted(row.segment_relative ? "Segment-relative" : provenance_text(row.provenance));
                ImGui::TableSetColumnIndex(5);
                ImGui::Text("%u%%", static_cast<unsigned>(row.confidence));
                ImGui::PopID();
            }
        }
        clipper.End();
        ImGui::EndTable();
    }

    const bool focused = ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows) &&
        !ImGui::IsAnyItemActive() && !ImGui::GetIO().WantTextInput;
    if (focused && !state->visible.empty()) {
        auto position = std::find(state->visible.begin(), state->visible.end(), state->selected);
        std::ptrdiff_t selected = position == state->visible.end() ? 0 :
            std::distance(state->visible.begin(), position);
        int delta = 0;
        if (ImGui::IsKeyPressed(ImGuiKey_UpArrow, false)) delta = -1;
        if (ImGui::IsKeyPressed(ImGuiKey_DownArrow, false)) delta = 1;
        if (ImGui::IsKeyPressed(ImGuiKey_PageUp, false)) delta = -10;
        if (ImGui::IsKeyPressed(ImGuiKey_PageDown, false)) delta = 10;
        if (ImGui::IsKeyPressed(ImGuiKey_Home, false)) selected = 0;
        else if (ImGui::IsKeyPressed(ImGuiKey_End, false))
            selected = static_cast<std::ptrdiff_t>(state->visible.size() - 1);
        else if (delta != 0)
            selected = (std::max<std::ptrdiff_t>)(0, (std::min<std::ptrdiff_t>)(
                static_cast<std::ptrdiff_t>(state->visible.size() - 1), selected + delta));
        state->selected = state->visible[static_cast<std::size_t>(selected)];
        const auto& row = state->rows[state->selected];
        if (delta != 0 || ImGui::IsKeyPressed(ImGuiKey_Home, false) ||
            ImGui::IsKeyPressed(ImGuiKey_End, false))
            disasm_view::select_address(row.address, context, false);
        if (ImGui::GetIO().KeyCtrl &&
            (ImGui::IsKeyPressed(ImGuiKey_C, false) ||
             ImGui::IsKeyPressed(ImGuiKey_Insert, false))) {
            const auto retained_row = action_row(row);
            aida::ui::analysis_context_menu::execute_shortcut(
                analysis_list_views::make_context(retained_row, context,
                    [state, expected = state->selected,
                     identity = analysis_list_views::row_identity(retained_row)] {
                        return state->selected == expected && expected < state->rows.size() &&
                            analysis_list_views::row_identity(action_row(state->rows[expected])) == identity
                            ? aida::ui::capability_state_t::available()
                            : aida::ui::capability_state_t::unavailable(
                                "The selected segment-register entity changed");
                    }),
                "analysis.copy.address");
        }
    }
    aida::ui::context_menu_open_origin_t keyboard_origin{};
    const bool keyboard_context = focused && state->selected < state->rows.size() &&
        aida::ui::analysis_context_menu::keyboard_request(keyboard_origin);
    if (pointer_context < state->rows.size())
        analysis_list_views::open_context(action_row(state->rows[pointer_context]), context,
            aida::ui::context_menu_open_origin_t::pointer,
            [state, expected = pointer_context,
             identity = analysis_list_views::row_identity(action_row(state->rows[pointer_context]))] {
                return state->selected == expected && expected < state->rows.size() &&
                    analysis_list_views::row_identity(action_row(state->rows[expected])) == identity
                    ? aida::ui::capability_state_t::available()
                    : aida::ui::capability_state_t::unavailable(
                        "The selected segment-register entity changed");
            });
    else if (keyboard_context)
        analysis_list_views::open_context(action_row(state->rows[state->selected]), context,
            keyboard_origin,
            [state, expected = state->selected,
             identity = analysis_list_views::row_identity(action_row(state->rows[state->selected]))] {
                return state->selected == expected && expected < state->rows.size() &&
                    analysis_list_views::row_identity(action_row(state->rows[expected])) == identity
                    ? aida::ui::capability_state_t::available()
                    : aida::ui::capability_state_t::unavailable(
                        "The selected segment-register entity changed");
            });
    aida::ui::analysis_context_menu::render();
    rename_dialog::render();
    comment_dialog::render();
    ImGui::PopID();
}

}

namespace proximity {

enum class relation_kind_t : std::uint8_t {
    xref,
    call,
    control_flow
};

struct relation_t {
    std::uint64_t source = 0;
    std::uint64_t target = 0;
    relation_kind_t kind = relation_kind_t::xref;
};

struct relation_identity_t {
    std::uint64_t source = 0;
    std::uint64_t target = 0;
    relation_kind_t kind = relation_kind_t::xref;

    bool operator==(const relation_identity_t& other) const noexcept {
        return source == other.source && target == other.target && kind == other.kind;
    }
};

struct relation_identity_hash_t {
    std::size_t operator()(const relation_identity_t& value) const noexcept {
        std::uint64_t hash = value.source ^ (value.target + 0x9E3779B97F4A7C15ULL +
            (value.source << 6U) + (value.source >> 2U));
        hash ^= static_cast<std::uint64_t>(value.kind) * 0xD6E8FEB86659FD93ULL;
        return static_cast<std::size_t>(hash);
    }
};

struct node_t {
    std::uint64_t address = 0;
    std::string name;
    std::string kind;
    std::uint32_t depth = 0;
    std::uint32_t incoming = 0;
    std::uint32_t outgoing = 0;
    std::array<std::uint32_t, 3> relation_counts{};
};

struct state_t {
    bool initialized = false;
    std::uint64_t generation = 0;
    std::uint64_t revision = 0;
    std::uint64_t overlay_revision = 0;
    std::uint64_t root = 0;
    int depth_limit = 2;
    int node_limit = 192;
    int pass = 0;
    std::size_t xref_cursor = 0;
    std::size_t call_cursor = 0;
    std::size_t edge_cursor = 0;
    bool complete = false;
    bool capped = false;
    std::uint64_t skipped_relations = 0;
    std::vector<node_t> nodes;
    std::vector<relation_t> relations;
    std::unordered_map<std::uint64_t, std::size_t> node_by_address;
    std::unordered_set<std::uint64_t> frontier;
    std::unordered_set<std::uint64_t> next_frontier;
    std::unordered_set<relation_identity_t, relation_identity_hash_t> relation_keys;
    std::vector<std::uint64_t> history;
    std::size_t history_index = 0;
    std::vector<std::size_t> visible;
    char filter[160]{};
    std::string applied_filter;
    bool filter_dirty = true;
    std::size_t selected = static_cast<std::size_t>(-1);
};

inline std::unordered_map<std::string, std::shared_ptr<state_t>>& states() {
    static std::unordered_map<std::string, std::shared_ptr<state_t>> value;
    return value;
}

inline std::shared_ptr<state_t> state_for(
    const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace) {
    const std::string key = workspace ? workspace->identity().binary_id().to_hex() : "none";
    auto& value = states()[key];
    if (!value) value = std::make_shared<state_t>();
    return value;
}

inline std::string node_name(const disasm_view::workspace_context_t& context,
                             std::uint64_t address) {
    if (const auto typed = disasm_view::typed_address(context, address)) {
        const auto name = disasm_view::resolve_name(context, *typed);
        if (!name.empty()) return name;
    }
    return address_text(address);
}

inline std::string node_kind(const disasm_view::workspace_context_t& context,
                             std::uint64_t address) {
    if (!disasm_view::typed_address(context, address)) return "External address";
    return disasm_view::enclosing_function_start(address, context) == address ? "Function" : "Symbol / address";
}

inline void begin_projection(state_t& state,
                             const disasm_view::workspace_context_t& context,
                             std::uint64_t root) {
    state.root = root;
    state.pass = 0;
    state.xref_cursor = 0;
    state.call_cursor = 0;
    state.edge_cursor = 0;
    state.complete = root == 0;
    state.capped = false;
    state.skipped_relations = 0;
    state.nodes.clear();
    state.relations.clear();
    state.node_by_address.clear();
    state.frontier.clear();
    state.next_frontier.clear();
    state.relation_keys.clear();
    state.visible.clear();
    state.selected = static_cast<std::size_t>(-1);
    state.filter_dirty = true;
    if (root != 0) {
        state.node_by_address[root] = 0;
        state.nodes.push_back(node_t{root, node_name(context, root), node_kind(context, root), 0});
        state.frontier.insert(root);
        state.selected = 0;
        disasm_view::select_address(root, context, false);
    }
}

inline std::uint64_t default_root(const disasm_view::workspace_context_t& context) {
    const auto view_state = context.workspace ? context.workspace->view_state()
        : aida::analysis::workspace_view_state_t{};
    if (view_state.selection) {
        const auto runtime = disasm_view::runtime_address(context, *view_state.selection);
        if (runtime && *runtime != 0) {
            const auto function = disasm_view::enclosing_function_start(*runtime, context);
            return function != 0 ? function : *runtime;
        }
    }
    if (!context.publication || !context.publication->snapshot) return 0;
    const auto& snapshot = *context.publication->snapshot;
    if (!snapshot.functions.empty())
        return analysis_list_views::runtime_address_value(context, snapshot.functions.front().start);
    if (!snapshot.symbols.empty())
        return analysis_list_views::runtime_address_value(context, snapshot.symbols.front().address);
    if (!snapshot.xrefs.empty())
        return analysis_list_views::runtime_address_value(context, snapshot.xrefs.front().source);
    return 0;
}

inline void reset_if_needed(state_t& state,
                            const disasm_view::workspace_context_t& context) {
    const auto& publication = *context.publication;
    if (state.initialized && state.generation == publication.generation &&
        state.revision == publication.analysis_revision &&
        state.overlay_revision == publication.overlay_revision)
        return;
    state.initialized = true;
    state.generation = publication.generation;
    state.revision = publication.analysis_revision;
    state.overlay_revision = publication.overlay_revision;
    const std::uint64_t root = default_root(context);
    state.history.clear();
    if (root != 0) state.history.push_back(root);
    state.history_index = 0;
    begin_projection(state, context, root);
}

inline void add_relation(state_t& state,
                         const disasm_view::workspace_context_t& context,
                         relation_t relation) {
    if (relation.source == 0 || relation.target == 0) {
        ++state.skipped_relations;
        return;
    }
    if (relation.source == relation.target) return;
    const bool source_frontier = state.frontier.find(relation.source) != state.frontier.end();
    const bool target_frontier = state.frontier.find(relation.target) != state.frontier.end();
    if (!source_frontier && !target_frontier) return;
    const std::uint64_t neighbor = source_frontier ? relation.target : relation.source;
    auto found = state.node_by_address.find(neighbor);
    if (found == state.node_by_address.end()) {
        if (state.nodes.size() >= static_cast<std::size_t>(state.node_limit)) {
            state.capped = true;
            return;
        }
        const std::size_t index = state.nodes.size();
        state.node_by_address[neighbor] = index;
        state.nodes.push_back(node_t{neighbor, node_name(context, neighbor), node_kind(context, neighbor),
            static_cast<std::uint32_t>(state.pass + 1)});
        state.next_frontier.insert(neighbor);
    }
    const auto source_node = state.node_by_address.find(relation.source);
    const auto target_node = state.node_by_address.find(relation.target);
    if (source_node == state.node_by_address.end() || target_node == state.node_by_address.end()) return;
    const relation_identity_t identity{relation.source, relation.target, relation.kind};
    if (!state.relation_keys.insert(identity).second) return;
    state.relations.push_back(relation);
    auto& source = state.nodes[source_node->second];
    auto& target = state.nodes[target_node->second];
    ++source.outgoing;
    ++target.incoming;
    const auto kind = static_cast<std::size_t>(relation.kind);
    ++source.relation_counts[kind];
    ++target.relation_counts[kind];
    state.filter_dirty = true;
}

inline bool consume_relation(state_t& state,
                             const disasm_view::workspace_context_t& context,
                             const aida::analysis::address_t& source,
                             const aida::analysis::address_t& target,
                             relation_kind_t kind) {
    std::uint64_t source_runtime = analysis_list_views::runtime_address_value(context, source);
    std::uint64_t target_runtime = analysis_list_views::runtime_address_value(context, target);
    if (source_runtime == 0 || target_runtime == 0) {
        ++state.skipped_relations;
        return false;
    }
    const std::uint64_t source_function = disasm_view::enclosing_function_start(source_runtime, context);
    const std::uint64_t target_function = disasm_view::enclosing_function_start(target_runtime, context);
    if (source_function != 0) source_runtime = source_function;
    if (target_function != 0) target_runtime = target_function;
    add_relation(state, context, relation_t{source_runtime, target_runtime, kind});
    return true;
}

inline void finish_pass(state_t& state) {
    ++state.pass;
    if (state.pass >= state.depth_limit || state.next_frontier.empty() || state.capped) {
        state.complete = true;
        return;
    }
    state.frontier = std::move(state.next_frontier);
    state.next_frontier.clear();
    state.xref_cursor = 0;
    state.call_cursor = 0;
    state.edge_cursor = 0;
}

inline void advance_projection(state_t& state,
                               const disasm_view::workspace_context_t& context) {
    if (state.complete || !context.publication || !context.publication->snapshot) return;
    const auto& snapshot = *context.publication->snapshot;
    std::size_t budget = 1024;
    while (budget != 0 && !state.capped && state.xref_cursor < snapshot.xrefs.size()) {
        const auto& item = snapshot.xrefs[state.xref_cursor++];
        consume_relation(state, context, item.source, item.target, relation_kind_t::xref);
        --budget;
    }
    while (budget != 0 && !state.capped && state.xref_cursor >= snapshot.xrefs.size() &&
           state.call_cursor < snapshot.call_graph.edges.size()) {
        const auto& item = snapshot.call_graph.edges[state.call_cursor++];
        consume_relation(state, context, item.call_site, item.target, relation_kind_t::call);
        --budget;
    }
    while (budget != 0 && !state.capped && state.xref_cursor >= snapshot.xrefs.size() &&
           state.call_cursor >= snapshot.call_graph.edges.size() &&
           state.edge_cursor < snapshot.edges.size()) {
        const auto& item = snapshot.edges[state.edge_cursor++];
        consume_relation(state, context, item.source, item.target,
            item.kind == aida::analysis::edge_kind_t::call ||
            item.kind == aida::analysis::edge_kind_t::tail_call
                ? relation_kind_t::call : relation_kind_t::control_flow);
        --budget;
    }
    if (state.capped) {
        state.complete = true;
        return;
    }
    if (state.xref_cursor >= snapshot.xrefs.size() &&
        state.call_cursor >= snapshot.call_graph.edges.size() &&
        state.edge_cursor >= snapshot.edges.size())
        finish_pass(state);
}

inline std::string relation_summary(const node_t& node) {
    std::string result;
    if (node.relation_counts[0] != 0)
        result += std::to_string(node.relation_counts[0]) + " xref" +
            (node.relation_counts[0] == 1 ? "" : "s");
    if (node.relation_counts[1] != 0) {
        if (!result.empty()) result += " | ";
        result += std::to_string(node.relation_counts[1]) + " call" +
            (node.relation_counts[1] == 1 ? "" : "s");
    }
    if (node.relation_counts[2] != 0) {
        if (!result.empty()) result += " | ";
        result += std::to_string(node.relation_counts[2]) + " flow";
    }
    return result.empty() ? "Root entity" : result;
}

inline void rebuild_visible(state_t& state) {
    const std::string requested = analysis_list_views::lower(state.filter);
    if (!state.filter_dirty && requested == state.applied_filter) return;
    state.applied_filter = requested;
    state.visible.clear();
    for (std::size_t index = 0; index < state.nodes.size(); ++index) {
        const auto& node = state.nodes[index];
        if (requested.empty() || contains(node.name, requested) || contains(node.kind, requested) ||
            contains(address_text(node.address), requested) || contains(relation_summary(node), requested))
            state.visible.push_back(index);
    }
    std::stable_sort(state.visible.begin(), state.visible.end(), [&](std::size_t left, std::size_t right) {
        const auto& lhs = state.nodes[left];
        const auto& rhs = state.nodes[right];
        if (lhs.depth != rhs.depth) return lhs.depth < rhs.depth;
        if (lhs.name != rhs.name) return lhs.name < rhs.name;
        return lhs.address < rhs.address;
    });
    if (state.selected >= state.nodes.size() ||
        std::find(state.visible.begin(), state.visible.end(), state.selected) == state.visible.end())
        state.selected = state.visible.empty() ? static_cast<std::size_t>(-1) : state.visible.front();
    state.filter_dirty = false;
}

inline void navigate_root(state_t& state,
                          const disasm_view::workspace_context_t& context,
                          std::uint64_t root, bool record_history) {
    if (root == 0) return;
    if (record_history) {
        if (!state.history.empty() && state.history_index + 1 < state.history.size())
            state.history.erase(state.history.begin() + static_cast<std::ptrdiff_t>(state.history_index + 1),
                state.history.end());
        if (state.history.empty() || state.history.back() != root) state.history.push_back(root);
        state.history_index = state.history.size() - 1;
    }
    begin_projection(state, context, root);
}

inline analysis_list_views::row_t action_row(const node_t& node) {
    analysis_list_views::row_t result;
    result.address = node.address;
    result.has_address = true;
    result.name = node.name;
    result.context = node.kind;
    result.detail = relation_summary(node);
    return result;
}

inline aida::ui::analysis_context_menu::context_t make_context(
                         const node_t& node, state_t& state,
                         const disasm_view::workspace_context_t& context) {
    using namespace aida::ui::analysis_context_menu;
    using aida::ui::action_handler_result_t;
    context_t menu;
    menu.kind = menu_kind_t::function;
    menu.entity_id = "proximity:" + std::to_string(node.address) + ":" + node.name +
        ":" + node.kind;
    menu.generation = context.publication->generation ^
        (context.publication->analysis_revision + 0x9E3779B97F4A7C15ULL) ^ state.root;
    menu.live_generation = [workspace = context.workspace, state = &state]() {
        return workspace ? workspace->generation() ^
            (workspace->analysis_revision() + 0x9E3779B97F4A7C15ULL) ^ state->root : 0;
    };
    const auto retained_address = node.address;
    const auto retained_name = node.name;
    menu.validate_identity = [&state, retained_address, retained_name]() {
        return state.selected < state.nodes.size() &&
            state.nodes[state.selected].address == retained_address &&
            state.nodes[state.selected].name == retained_name
            ? aida::ui::capability_state_t::available()
            : aida::ui::capability_state_t::unavailable(
                "The selected proximity entity changed");
    };
    const auto row = action_row(node);
    const bool mapped = disasm_view::typed_address(context, node.address).has_value();
    const auto unavailable = [&](const char* id) {
        menu.actions[id].capability = aida::ui::capability_state_t::unavailable(
            "The published entity is outside the mapped workspace address space");
    };
    menu.actions["analysis.navigate.follow"].invoke = [&state, context, address = node.address]() {
        navigate_root(state, context, address, true);
        return action_handler_result_t::completed();
    };
    if (mapped) {
        menu.actions["analysis.navigate.disassembly"].invoke = [row, context]() {
            analysis_list_views::open_disassembly(row, context);
            return action_handler_result_t::completed();
        };
    } else unavailable("analysis.navigate.disassembly");
    if (mapped && disasm_view::enclosing_function_start(node.address, context) != 0) {
        menu.actions["analysis.navigate.graph"].invoke = [row, context]() {
            analysis_list_views::open_graph(row, context);
            return action_handler_result_t::completed();
        };
        menu.actions["analysis.navigate.pseudocode"].invoke = [row, context]() {
            analysis_list_views::open_pseudocode(row, context);
            return action_handler_result_t::completed();
        };
    }
    if (mapped) {
        menu.actions["analysis.navigate.hex"].invoke = [row, context]() {
            analysis_list_views::open_related_view(row, context, "document.hex");
            return action_handler_result_t::completed();
        };
        menu.actions["analysis.navigate.functions"].invoke = [row, context]() {
            analysis_list_views::open_related_view(row, context, "view.analysis.functions");
            return action_handler_result_t::completed();
        };
        menu.actions["analysis.navigate.types"].invoke = [row, context]() {
            analysis_list_views::open_related_view(row, context, "view.analysis.local_types");
            return action_handler_result_t::completed();
        };
        menu.actions["analysis.navigate.structures"].invoke = [row, context]() {
            analysis_list_views::open_related_view(row, context, "view.types.structures");
            return action_handler_result_t::completed();
        };
        menu.actions["analysis.navigate.xrefs"].invoke = [row, context]() {
            analysis_list_views::open_xrefs(row, context);
            return action_handler_result_t::completed();
        };
        menu.actions["analysis.navigate.xrefs_from"].invoke = [row, context]() {
            analysis_list_views::open_xrefs_from(row, context);
            return action_handler_result_t::completed();
        };
        menu.actions["analysis.modify.rename"].invoke = [row, context]() {
            analysis_list_views::open_rename(row, context);
            return action_handler_result_t::completed();
        };
        menu.actions["analysis.modify.comment"].invoke = [row, context]() {
            analysis_list_views::open_comment(row, context);
            return action_handler_result_t::completed();
        };
        menu.actions["analysis.modify.bookmark"].invoke = [context, address = node.address,
            label = node.name]() {
            const auto typed = disasm_view::typed_address(context, address);
            return typed && disasm_view::queue_bookmark(context, *typed, label)
                ? action_handler_result_t::completed()
                : action_handler_result_t::failed("The workspace rejected the bookmark request");
        };
    } else {
        unavailable("analysis.navigate.hex");
        unavailable("analysis.navigate.functions");
        unavailable("analysis.navigate.types");
        unavailable("analysis.navigate.structures");
        unavailable("analysis.navigate.xrefs");
        unavailable("analysis.navigate.xrefs_from");
        unavailable("analysis.modify.rename");
        unavailable("analysis.modify.comment");
        unavailable("analysis.modify.bookmark");
    }
    menu.actions["analysis.copy.address"].invoke = [value = address_text(node.address)]() {
        ImGui::SetClipboardText(value.c_str());
        return action_handler_result_t::completed();
    };
    menu.actions["analysis.copy.address_va"].invoke = [value = address_text(node.address)]() {
        ImGui::SetClipboardText(value.c_str());
        return action_handler_result_t::completed();
    };
    menu.actions["analysis.copy.name"].invoke = [value = node.name]() {
        ImGui::SetClipboardText(value.c_str());
        return action_handler_result_t::completed();
    };
    menu.actions["analysis.copy.text"].invoke = [value = relation_summary(node)]() {
        ImGui::SetClipboardText(value.c_str());
        return action_handler_result_t::completed();
    };
    menu.actions["analysis.copy.line"].invoke = [value = address_text(node.address) + "\t" +
        node.name + "\t" + relation_summary(node)]() {
        ImGui::SetClipboardText(value.c_str());
        return action_handler_result_t::completed();
    };
    return menu;
}

inline void open_context(const node_t& node, state_t& state,
                         const disasm_view::workspace_context_t& context,
                         aida::ui::context_menu_open_origin_t origin) {
    aida::ui::analysis_context_menu::open(
        make_context(node, state, context), origin);
}

inline void render() {
    const auto workspace = aida::analysis::workspace_registry().selected_for_ui();
    const auto context = disasm_view::capture_workspace(workspace);
    const ImVec2 available = ImGui::GetContentRegionAvail();
    if (!context) {
        aida::ui::empty_state::config_t empty;
        empty.glyph = aida::ui::empty_state::glyph_t::binary_file;
        empty.title = "No analysis workspace";
        empty.body = "Open and analyze a binary to browse related functions, symbols and references.";
        aida::ui::empty_state::render(ImGui::GetCursorScreenPos(), available, empty);
        return;
    }
    const auto state = state_for(workspace);
    reset_if_needed(*state, context);
    advance_projection(*state, context);
    rebuild_visible(*state);

    ImGui::PushID("view.analysis.proximity");
    ImGui::BeginDisabled(state->history.empty() || state->history_index == 0);
    if (ImGui::SmallButton("<")) {
        --state->history_index;
        navigate_root(*state, context, state->history[state->history_index], false);
    }
    ImGui::EndDisabled();
    ImGui::SameLine();
    ImGui::BeginDisabled(state->history.empty() || state->history_index + 1 >= state->history.size());
    if (ImGui::SmallButton(">")) {
        ++state->history_index;
        navigate_root(*state, context, state->history[state->history_index], false);
    }
    ImGui::EndDisabled();
    ImGui::SameLine();
    if (ImGui::SmallButton("Use selection")) {
        const auto root = default_root(context);
        if (root != 0) navigate_root(*state, context, root, true);
    }
    ImGui::SameLine();
    ImGui::SetNextItemWidth(70.0f);
    const char* depths[] = {"1 hop", "2 hops", "3 hops", "4 hops"};
    int depth = state->depth_limit - 1;
    if (ImGui::Combo("##depth", &depth, depths, 4)) {
        state->depth_limit = depth + 1;
        begin_projection(*state, context, state->root);
    }
    ImGui::SameLine();
    ImGui::SetNextItemWidth(78.0f);
    const char* node_limits[] = {"96 nodes", "192 nodes", "384 nodes"};
    int limit = state->node_limit == 96 ? 0 : (state->node_limit == 384 ? 2 : 1);
    if (ImGui::Combo("##node_limit", &limit, node_limits, 3)) {
        state->node_limit = limit == 0 ? 96 : (limit == 2 ? 384 : 192);
        begin_projection(*state, context, state->root);
    }
    if (available.x >= 700.0f) ImGui::SameLine();
    if (state->skipped_relations != 0)
        ImGui::TextDisabled("%zu nodes | %zu edges | %llu unmapped%s",
            state->nodes.size(), state->relations.size(),
            static_cast<unsigned long long>(state->skipped_relations),
            state->capped ? " | capped" : (state->complete ? "" : " | scanning"));
    else
        ImGui::TextDisabled("%zu nodes | %zu edges%s", state->nodes.size(), state->relations.size(),
            state->capped ? " | capped" : (state->complete ? "" : " | scanning"));
    ImGui::SetNextItemWidth(-1.0f);
    if (aida::ui::input_text("##filter", state->filter, sizeof(state->filter),
            "Filter neighborhood...", false, ImVec2(0.0f, 25.0f)))
        state->filter_dirty = true;
    if (!state->complete) {
        const auto& snapshot = *context.publication->snapshot;
        const std::size_t total = snapshot.xrefs.size() + snapshot.call_graph.edges.size() +
            snapshot.edges.size();
        const std::size_t current = state->xref_cursor + state->call_cursor + state->edge_cursor;
        const float pass_fraction = total == 0 ? 1.0f :
            static_cast<float>(current) / static_cast<float>(total);
        const float fraction = (static_cast<float>(state->pass) + pass_fraction) /
            static_cast<float>((std::max)(1, state->depth_limit));
        ImGui::ProgressBar((std::min)(1.0f, fraction), ImVec2(-1.0f, 3.0f), "");
    }

    if (state->root == 0) {
        aida::ui::empty_state::config_t empty;
        empty.glyph = aida::ui::empty_state::glyph_t::search;
        empty.title = "No navigable analysis entity";
        empty.body = "The current publication contains no function, symbol or reference address that can seed a proximity neighborhood.";
        aida::ui::empty_state::render(ImGui::GetCursorScreenPos(), ImGui::GetContentRegionAvail(), empty);
        ImGui::PopID();
        return;
    }
    if (state->complete && state->nodes.size() == 1) {
        aida::ui::empty_state::config_t empty;
        empty.glyph = aida::ui::empty_state::glyph_t::search;
        empty.title = "No published neighbors";
        empty.body = "No xref, call-graph or control-flow publication connects to the selected root within the requested depth.";
        aida::ui::empty_state::render(ImGui::GetCursorScreenPos(), ImGui::GetContentRegionAvail(), empty);
        ImGui::PopID();
        return;
    }
    if (state->visible.empty()) {
        aida::ui::empty_state::config_t empty;
        empty.glyph = aida::ui::empty_state::glyph_t::search;
        empty.title = "No matches";
        empty.body = "No neighborhood entity matches the current filter.";
        aida::ui::empty_state::render(ImGui::GetCursorScreenPos(), ImGui::GetContentRegionAvail(), empty);
        ImGui::PopID();
        return;
    }

    std::size_t pointer_context = static_cast<std::size_t>(-1);
    std::uint64_t pointer_drill = 0;
    const ImGuiTableFlags flags = ImGuiTableFlags_Resizable | ImGuiTableFlags_Reorderable |
        ImGuiTableFlags_Hideable | ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV |
        ImGuiTableFlags_ScrollX | ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingStretchProp;
    if (ImGui::BeginTable("##proximity", 6, flags, ImGui::GetContentRegionAvail(), 780.0f)) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Depth", ImGuiTableColumnFlags_WidthFixed, 48.0f);
        ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 142.0f);
        ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthStretch, 1.4f);
        ImGui::TableSetupColumn("Kind", ImGuiTableColumnFlags_WidthStretch, 0.6f);
        ImGui::TableSetupColumn("In / Out", ImGuiTableColumnFlags_WidthFixed, 62.0f);
        ImGui::TableSetupColumn("Relationships", ImGuiTableColumnFlags_WidthStretch, 1.0f);
        ImGui::TableHeadersRow();
        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(state->visible.size()), 22.0f);
        while (clipper.Step()) {
            for (int visible = clipper.DisplayStart; visible < clipper.DisplayEnd; ++visible) {
                const std::size_t source = state->visible[static_cast<std::size_t>(visible)];
                const auto& node = state->nodes[source];
                ImGui::TableNextRow(0, 22.0f);
                ImGui::TableSetColumnIndex(0);
                ImGui::PushID(static_cast<int>(source));
                const bool activated = ImGui::Selectable("##row", state->selected == source,
                    ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowDoubleClick,
                    ImVec2(0.0f, 20.0f));
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
                const std::string node_identity = std::to_string(node.address);
                const std::string node_semantic = aida::preview::semantics::stable_id(
                    "aida.proximity-row",
                    aida::preview::semantics::entity_token(node_identity));
                static_cast<void>(aida::preview::semantics::register_last_item(node_semantic,
                    "relationship-row", false, false,
                    "aida.dock-window.view.analysis.proximity"));
#endif
                if (activated) {
                    state->selected = source;
                    disasm_view::select_address(node.address, context);
                    if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left))
                        pointer_drill = node.address;
                }
                if (ImGui::IsItemClicked(ImGuiMouseButton_Right)) {
                    state->selected = source;
                    disasm_view::select_address(node.address, context, false);
                    pointer_context = source;
                }
                ImGui::SameLine();
                ImGui::Text("%u", node.depth);
                ImGui::TableSetColumnIndex(1);
                ImGui::PushFont(aida::ui::fonts::code() ? aida::ui::fonts::code() : ImGui::GetFont());
                ImGui::TextUnformatted(address_text(node.address).c_str());
                ImGui::PopFont();
                ImGui::TableSetColumnIndex(2);
                ImGui::TextUnformatted(node.name.c_str());
                ImGui::TableSetColumnIndex(3);
                ImGui::TextUnformatted(node.kind.c_str());
                ImGui::TableSetColumnIndex(4);
                ImGui::Text("%u / %u", node.incoming, node.outgoing);
                ImGui::TableSetColumnIndex(5);
                ImGui::TextUnformatted(relation_summary(node).c_str());
                ImGui::PopID();
            }
        }
        clipper.End();
        ImGui::EndTable();
    }
    if (pointer_drill != 0) navigate_root(*state, context, pointer_drill, true);

    const bool focused = ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows) &&
        !ImGui::IsAnyItemActive() && !ImGui::GetIO().WantTextInput;
    if (focused && !state->visible.empty()) {
        auto position = std::find(state->visible.begin(), state->visible.end(), state->selected);
        std::ptrdiff_t selected = position == state->visible.end() ? 0 :
            std::distance(state->visible.begin(), position);
        int delta = 0;
        if (ImGui::IsKeyPressed(ImGuiKey_UpArrow, false)) delta = -1;
        if (ImGui::IsKeyPressed(ImGuiKey_DownArrow, false)) delta = 1;
        if (ImGui::IsKeyPressed(ImGuiKey_PageUp, false)) delta = -10;
        if (ImGui::IsKeyPressed(ImGuiKey_PageDown, false)) delta = 10;
        if (ImGui::IsKeyPressed(ImGuiKey_Home, false)) selected = 0;
        else if (ImGui::IsKeyPressed(ImGuiKey_End, false))
            selected = static_cast<std::ptrdiff_t>(state->visible.size() - 1);
        else if (delta != 0)
            selected = (std::max<std::ptrdiff_t>)(0, (std::min<std::ptrdiff_t>)(
                static_cast<std::ptrdiff_t>(state->visible.size() - 1), selected + delta));
        state->selected = state->visible[static_cast<std::size_t>(selected)];
        const auto& node = state->nodes[state->selected];
        if (delta != 0 || ImGui::IsKeyPressed(ImGuiKey_Home, false) ||
            ImGui::IsKeyPressed(ImGuiKey_End, false))
            disasm_view::select_address(node.address, context, false);
        if (ImGui::GetIO().KeyCtrl &&
            (ImGui::IsKeyPressed(ImGuiKey_C, false) ||
             ImGui::IsKeyPressed(ImGuiKey_Insert, false)))
            aida::ui::analysis_context_menu::execute_shortcut(
                make_context(node, *state, context), "analysis.copy.address");
    }
    aida::ui::context_menu_open_origin_t keyboard_origin{};
    const bool keyboard_context = focused && state->selected < state->nodes.size() &&
        aida::ui::analysis_context_menu::keyboard_request(keyboard_origin);
    if (pointer_context < state->nodes.size())
        open_context(state->nodes[pointer_context], *state, context,
            aida::ui::context_menu_open_origin_t::pointer);
    else if (keyboard_context)
        open_context(state->nodes[state->selected], *state, context, keyboard_origin);
    aida::ui::analysis_context_menu::render();
    rename_dialog::render();
    comment_dialog::render();
    ImGui::PopID();
}

inline aida::ui::capability_state_t selected_drill_capability() {
    const auto context = disasm_view::capture_selected_workspace();
    if (!context || !context.publication || !context.publication->snapshot)
        return aida::ui::capability_state_t::unavailable(
            "Open an analyzed workspace before drilling the Proximity Browser");
    const auto state = state_for(context.workspace);
    if (!state->initialized || state->generation != context.publication->generation ||
        state->revision != context.publication->analysis_revision ||
        state->overlay_revision != context.publication->overlay_revision)
        return aida::ui::capability_state_t::unavailable(
            "The Proximity Browser selection is stale; select a current node");
    if (state->selected >= state->nodes.size())
        return aida::ui::capability_state_t::unavailable(
            "Select a Proximity Browser node first");
    return aida::ui::capability_state_t::available();
}

inline bool drill_selected() {
    if (!selected_drill_capability().enabled)
        return false;
    const auto context = disasm_view::capture_selected_workspace();
    const auto state = state_for(context.workspace);
    navigate_root(*state, context, state->nodes[state->selected].address, true);
    return true;
}

}

}
