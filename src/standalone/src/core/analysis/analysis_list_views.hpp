#pragma once

#include "../disasm/cfg_view.hpp"
#include "../disasm/disasm_view.hpp"
#include "../disasm/pseudocode_view.hpp"
#include "../disasm/rename_dialog.hpp"
#include "../disasm/comment_dialog.hpp"
#include "../ui/analysis_context_menu.hpp"
#include "../ui/application_view_registry.hpp"
#include "xref_db_view.hpp"
#include "workspace/workspace_registry.hpp"
#include "../ui/components.hpp"
#include "../ui/empty_state.hpp"
#include "../ui/fonts.hpp"
#include "../ui/theme.hpp"
#include "imgui/imgui.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace analysis_list_views {

enum class domain_t : std::uint8_t {
    imports,
    exports,
    names,
    strings,
    segments,
    local_types
};

struct row_t {
    std::uint64_t address = 0;
    bool has_address = false;
    std::string name;
    std::string context;
    std::string detail;
};

inline std::string row_identity(const row_t& row) {
    return std::string(row.has_address ? "address:" : "entity:") +
        std::to_string(row.address) + ":" + row.name + ":" + row.context + ":" +
        row.detail;
}

struct state_t {
    bool projected = false;
    std::uint64_t generation = 0;
    std::uint64_t revision = 0;
    std::uint64_t overlay_revision = 0;
    std::vector<row_t> rows;
    std::vector<std::size_t> visible;
    std::string filter_lower;
    char filter[192]{};
    bool filter_dirty = true;
    bool sort_dirty = true;
    int sort_column = 0;
    bool sort_ascending = true;
    std::size_t page = 0;
    std::size_t page_size = 1000;
    std::uint64_t selected_address = 0;
    std::size_t selected_source = static_cast<std::size_t>(-1);
    std::size_t context_source = static_cast<std::size_t>(-1);
};

struct descriptor_t {
    const char* stable_id;
    const char* title;
    const char* empty_title;
    const char* empty_body;
};

inline const descriptor_t& descriptor(domain_t domain) {
    static constexpr std::array<descriptor_t, 6> values{{
        {"view.analysis.imports", "Imports", "No imports", "The analyzed image does not publish imported symbols."},
        {"view.analysis.exports", "Exports", "No exports", "The analyzed image does not publish exported symbols."},
        {"view.analysis.names", "Names", "No names", "Analysis has not published named symbols for this target."},
        {"view.analysis.strings", "Strings", "No strings", "Analysis has not discovered strings for this target."},
        {"view.analysis.segments", "Segments", "No segments", "The normalized image does not publish segment records."},
        {"view.analysis.local_types", "Local Types", "No local types", "Analysis has not published local type candidates."}
    }};
    return values[static_cast<std::size_t>(domain)];
}

inline std::mutex& states_mutex() {
    static std::mutex value;
    return value;
}

inline std::unordered_map<std::string, std::shared_ptr<state_t>>& states() {
    static std::unordered_map<std::string, std::shared_ptr<state_t>> value;
    return value;
}

inline std::string lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value;
}

inline bool contains_case_insensitive(const std::string& value, const std::string& query) {
    if (query.empty()) return true;
    if (query.size() > value.size()) return false;
    return std::search(value.begin(), value.end(), query.begin(), query.end(),
        [](unsigned char left, unsigned char right) {
            return std::tolower(left) == std::tolower(right);
        }) != value.end();
}

inline std::string address_text(std::uint64_t address) {
    char value[32]{};
    std::snprintf(value, sizeof(value), "0x%016llX",
        static_cast<unsigned long long>(address));
    return value;
}

inline std::uint64_t runtime_address_value(const disasm_view::workspace_context_t& context,
                                           const aida::analysis::address_t& address) {
    return disasm_view::runtime_address(context, address).value_or(address.value);
}

inline const char* string_encoding(aida::analysis::string_encoding_t encoding) {
    switch (encoding) {
    case aida::analysis::string_encoding_t::ascii: return "ASCII";
    case aida::analysis::string_encoding_t::utf8: return "UTF-8";
    case aida::analysis::string_encoding_t::utf16_le: return "UTF-16 LE";
    default: return "Unknown";
    }
}

inline const char* symbol_kind(aida::analysis::symbol_kind_t kind) {
    switch (kind) {
    case aida::analysis::symbol_kind_t::function: return "Function";
    case aida::analysis::symbol_kind_t::data: return "Data";
    case aida::analysis::symbol_kind_t::import_symbol: return "Import";
    case aida::analysis::symbol_kind_t::export_symbol: return "Export";
    case aida::analysis::symbol_kind_t::debug_symbol: return "Debug";
    case aida::analysis::symbol_kind_t::type_symbol: return "Type";
    case aida::analysis::symbol_kind_t::metadata: return "Metadata";
    default: return "Unknown";
    }
}

inline const char* type_kind(aida::analysis::symbol_type_candidate_kind_t kind) {
    using kind_t = aida::analysis::symbol_type_candidate_kind_t;
    switch (kind) {
    case kind_t::function_prototype: return "Function prototype";
    case kind_t::import_prototype: return "Import prototype";
    case kind_t::global_object: return "Global object";
    case kind_t::pointer_object: return "Pointer object";
    case kind_t::rtti_type: return "RTTI type";
    case kind_t::virtual_table: return "Virtual table";
    case kind_t::type_information: return "Type information";
    case kind_t::objective_c_class: return "Objective-C class";
    case kind_t::objective_c_protocol: return "Objective-C protocol";
    case kind_t::objective_c_selector: return "Objective-C selector";
    case kind_t::swift_type: return "Swift type";
    case kind_t::swift_protocol: return "Swift protocol";
    case kind_t::managed_type: return "Managed type";
    case kind_t::managed_method: return "Managed method";
    case kind_t::managed_field: return "Managed field";
    case kind_t::debug_type: return "Debug type";
    case kind_t::metadata_region: return "Metadata region";
    default: return "Unknown";
    }
}

inline std::string segment_permissions(std::uint32_t permissions) {
    std::string value;
    value.push_back((permissions & aida::analysis::image_permission_read) != 0 ? 'R' : '-');
    value.push_back((permissions & aida::analysis::image_permission_write) != 0 ? 'W' : '-');
    value.push_back((permissions & aida::analysis::image_permission_execute) != 0 ? 'X' : '-');
    return value;
}

inline std::shared_ptr<state_t> state_for(
    domain_t domain, const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace) {
    const std::string binary = workspace ? workspace->identity().binary_id().to_hex() : "none";
    const std::string key = binary + ":" + descriptor(domain).stable_id;
    std::lock_guard<std::mutex> lock(states_mutex());
    auto& value = states()[key];
    if (!value) value = std::make_shared<state_t>();
    return value;
}

inline void rebuild_rows(domain_t domain, state_t& state,
                         const disasm_view::workspace_context_t& context) {
    const auto publication = context.publication;
    if (!publication || !publication->snapshot) return;
    if (state.projected && state.generation == publication->generation &&
        state.revision == publication->analysis_revision &&
        state.overlay_revision == publication->overlay_revision)
        return;
    const auto& snapshot = *publication->snapshot;
    const auto normalized = snapshot.normalized_image;
    std::vector<row_t> rows;
    if (domain == domain_t::imports && normalized) {
        rows.reserve(normalized->imports.size());
        for (const auto& item : normalized->imports) {
            const auto& source = item.address.value != 0 ? item.address : item.lookup_address;
            row_t row;
            row.address = runtime_address_value(context, source);
            row.has_address = row.address != 0;
            row.name = item.name.value_or(item.ordinal ? "Ordinal " + std::to_string(*item.ordinal) : "Unnamed import");
            row.context = item.library;
            row.detail = item.delayed ? "Delay-loaded" : "Import";
            rows.push_back(std::move(row));
        }
    } else if (domain == domain_t::exports && normalized) {
        rows.reserve(normalized->exports.size());
        for (const auto& item : normalized->exports) {
            row_t row;
            row.address = runtime_address_value(context, item.address);
            row.has_address = row.address != 0;
            row.name = item.name.value_or("Ordinal " + std::to_string(item.ordinal));
            row.context = "Ordinal " + std::to_string(item.ordinal);
            row.detail = item.forwarder.value_or("Export");
            rows.push_back(std::move(row));
        }
    } else if (domain == domain_t::names) {
        rows.reserve(snapshot.symbols.size());
        for (const auto& item : snapshot.symbols) {
            row_t row;
            row.address = runtime_address_value(context, item.address);
            row.has_address = row.address != 0;
            row.name = disasm_view::resolve_name(context, item.address);
            if (row.name.empty()) row.name = item.name.empty() ? "Unnamed symbol" : item.name;
            row.context = symbol_kind(item.kind);
            row.detail = "Confidence " + std::to_string(item.confidence) + "%";
            rows.push_back(std::move(row));
        }
    } else if (domain == domain_t::strings) {
        rows.reserve(snapshot.strings.size());
        for (const auto& item : snapshot.strings) {
            row_t row;
            row.address = runtime_address_value(context, item.address);
            row.has_address = row.address != 0;
            row.name = item.value;
            row.context = string_encoding(item.encoding);
            row.detail = std::to_string(item.byte_length) + " bytes";
            rows.push_back(std::move(row));
        }
    } else if (domain == domain_t::segments && normalized) {
        rows.reserve(normalized->segments.size());
        for (const auto& item : normalized->segments) {
            row_t row;
            row.address = normalized->image_base + item.virtual_address;
            row.has_address = true;
            row.name = item.name.empty() ? "Segment " + std::to_string(item.index) : item.name;
            row.context = segment_permissions(item.permissions);
            char detail[96]{};
            std::snprintf(detail, sizeof(detail), "VA size 0x%llX | file 0x%llX + 0x%llX",
                static_cast<unsigned long long>(item.virtual_size),
                static_cast<unsigned long long>(item.file_offset),
                static_cast<unsigned long long>(item.file_size));
            row.detail = detail;
            rows.push_back(std::move(row));
        }
    } else if (domain == domain_t::local_types) {
        rows.reserve(snapshot.rich_facts.type_candidates.size());
        for (const auto& item : snapshot.rich_facts.type_candidates) {
            row_t row;
            if (item.address) {
                row.address = runtime_address_value(context, *item.address);
                row.has_address = row.address != 0;
            }
            row.name = item.display_name.empty() ? item.canonical_type : item.display_name;
            if (row.name.empty()) row.name = "Unnamed type";
            row.context = type_kind(item.kind);
            row.detail = item.canonical_type.empty()
                ? "Confidence " + std::to_string(item.confidence) + "%"
                : item.canonical_type;
            rows.push_back(std::move(row));
        }
    }
    state.rows = std::move(rows);
    state.projected = true;
    state.generation = publication->generation;
    state.revision = publication->analysis_revision;
    state.overlay_revision = publication->overlay_revision;
    state.filter_dirty = true;
    state.sort_dirty = true;
    state.page = 0;
    state.selected_source = static_cast<std::size_t>(-1);
    state.selected_address = 0;
}

inline int compare_text(const std::string& left, const std::string& right) {
    const std::size_t shared = (std::min)(left.size(), right.size());
    for (std::size_t index = 0; index < shared; ++index) {
        const int lhs = std::tolower(static_cast<unsigned char>(left[index]));
        const int rhs = std::tolower(static_cast<unsigned char>(right[index]));
        if (lhs < rhs) return -1;
        if (lhs > rhs) return 1;
    }
    if (left.size() < right.size()) return -1;
    if (left.size() > right.size()) return 1;
    return 0;
}

inline void rebuild_visible(state_t& state) {
    const std::string requested = lower(state.filter);
    if (!state.filter_dirty && requested == state.filter_lower && !state.sort_dirty) return;
    if (state.filter_dirty || requested != state.filter_lower) {
        state.filter_lower = requested;
        state.visible.clear();
        state.visible.reserve(state.rows.size());
        for (std::size_t index = 0; index < state.rows.size(); ++index) {
            const auto& row = state.rows[index];
            const bool match = requested.empty() || contains_case_insensitive(row.name, requested) ||
                contains_case_insensitive(row.context, requested) ||
                contains_case_insensitive(row.detail, requested) ||
                (row.has_address && lower(address_text(row.address)).find(requested) != std::string::npos);
            if (match) state.visible.push_back(index);
        }
        state.page = 0;
        state.filter_dirty = false;
        state.sort_dirty = true;
    }
    if (!state.sort_dirty) return;
    const int column = state.sort_column;
    const bool ascending = state.sort_ascending;
    std::stable_sort(state.visible.begin(), state.visible.end(), [&](std::size_t left, std::size_t right) {
        const auto& lhs = state.rows[left];
        const auto& rhs = state.rows[right];
        int result = 0;
        if (column == 0) {
            if (lhs.address < rhs.address) result = -1;
            else if (lhs.address > rhs.address) result = 1;
        } else if (column == 1) result = compare_text(lhs.name, rhs.name);
        else if (column == 2) result = compare_text(lhs.context, rhs.context);
        else result = compare_text(lhs.detail, rhs.detail);
        if (result == 0) result = left < right ? -1 : (left > right ? 1 : 0);
        return ascending ? result < 0 : result > 0;
    });
    if (state.selected_source != static_cast<std::size_t>(-1) &&
        std::find(state.visible.begin(), state.visible.end(), state.selected_source) == state.visible.end()) {
        state.selected_source = static_cast<std::size_t>(-1);
        state.selected_address = 0;
    }
    state.sort_dirty = false;
}

inline void select_row(const row_t& row, state_t& state, std::size_t source,
                       const disasm_view::workspace_context_t& context) {
    state.selected_source = source;
    state.selected_address = row.has_address ? row.address : 0;
    if (row.has_address) disasm_view::select_address(row.address, context);
}

inline void open_disassembly(const row_t& row,
                             const disasm_view::workspace_context_t& context) {
    if (!row.has_address) return;
    disasm_view::goto_address(row.address, context);
    aida::ui::application_views::open_or_focus(
        aida::ui::stable_view_id_t("document.disassembly"));
}

inline void open_graph(const row_t& row,
                       const disasm_view::workspace_context_t& context) {
    if (!row.has_address) return;
    const auto function = disasm_view::enclosing_function_start(row.address, context);
    if (function == 0) return;
    cfg_view::build_cfg(context, function);
    aida::ui::application_views::open_or_focus(
        aida::ui::stable_view_id_t("document.graph"));
}

inline void open_pseudocode(const row_t& row,
                            const disasm_view::workspace_context_t& context) {
    if (!row.has_address) return;
    const auto function = disasm_view::enclosing_function_start(row.address, context);
    if (function == 0) return;
    pseudocode_view::request_decompile(context, function, false);
    aida::ui::application_views::open_or_focus(
        aida::ui::stable_view_id_t("document.pseudocode"));
}

inline void open_xrefs(const row_t& row,
                       const disasm_view::workspace_context_t& context) {
    if (!row.has_address) return;
    disasm_view::open_xrefs(row.address, context);
    aida::ui::application_views::open_or_focus(
        aida::ui::stable_view_id_t("view.analysis.references"));
}

inline void open_xrefs_from(const row_t& row,
                            const disasm_view::workspace_context_t& context) {
    if (!row.has_address) return;
    const auto typed = disasm_view::typed_address(context, row.address);
    const auto state = xref_db_view::state_for(context);
    if (!typed || !state) return;
    xref_db_view::submit_query(context, state, *typed, false);
    aida::ui::application_views::open_or_focus(
        aida::ui::stable_view_id_t("view.analysis.references"));
}

inline void open_rename(const row_t& row,
                        const disasm_view::workspace_context_t& context) {
    if (!row.has_address) return;
    rename_dialog::open(context,
        aida::analysis::address_t{aida::analysis::address_space_id_t::virtual_address, row.address});
}

inline void open_comment(const row_t& row,
                         const disasm_view::workspace_context_t& context) {
    if (!row.has_address) return;
    comment_dialog::open(context,
        aida::analysis::address_t{aida::analysis::address_space_id_t::virtual_address, row.address});
}

inline void open_related_view(const row_t& row,
                              const disasm_view::workspace_context_t& context,
                              const char* stable_id) {
    if (!row.has_address) return;
    disasm_view::select_address(row.address, context);
    aida::ui::application_views::open_or_focus(aida::ui::stable_view_id_t(stable_id));
}

inline void open_context(const row_t& row,
                         const disasm_view::workspace_context_t& context,
                         aida::ui::context_menu_open_origin_t origin,
                         std::function<aida::ui::capability_state_t()> validate_identity) {
    using namespace aida::ui::analysis_context_menu;
    using aida::ui::action_handler_result_t;
    context_t menu;
    menu.kind = menu_kind_t::function;
    menu.entity_id = row_identity(row);
    menu.generation = context.publication->generation ^
        (context.publication->analysis_revision + 0x9E3779B97F4A7C15ull);
    menu.live_generation = [workspace = context.workspace]() {
        return workspace ? workspace->generation() ^
            (workspace->analysis_revision() + 0x9E3779B97F4A7C15ull) : 0;
    };
    menu.validate_identity = std::move(validate_identity);
    if (row.has_address) {
        menu.actions["analysis.navigate.disassembly"].invoke = [row, context]() {
            open_disassembly(row, context);
            return action_handler_result_t::completed();
        };
        if (disasm_view::enclosing_function_start(row.address, context) != 0) {
            menu.actions["analysis.navigate.graph"].invoke = [row, context]() {
                open_graph(row, context);
                return action_handler_result_t::completed();
            };
            menu.actions["analysis.navigate.pseudocode"].invoke = [row, context]() {
                open_pseudocode(row, context);
                return action_handler_result_t::completed();
            };
        }
        menu.actions["analysis.navigate.hex"].invoke = [row, context]() {
            open_related_view(row, context, "document.hex");
            return action_handler_result_t::completed();
        };
        menu.actions["analysis.navigate.types"].invoke = [row, context]() {
            open_related_view(row, context, "view.types.inferred");
            return action_handler_result_t::completed();
        };
        menu.actions["analysis.navigate.structures"].invoke = [row, context]() {
            open_related_view(row, context, "view.types.structures");
            return action_handler_result_t::completed();
        };
        menu.actions["analysis.navigate.xrefs"].invoke = [row, context]() {
            open_xrefs(row, context);
            return action_handler_result_t::completed();
        };
        menu.actions["analysis.navigate.xrefs_from"].invoke = [row, context]() {
            open_xrefs_from(row, context);
            return action_handler_result_t::completed();
        };
        menu.actions["analysis.modify.rename"].invoke = [row, context]() {
            open_rename(row, context);
            return action_handler_result_t::completed();
        };
        menu.actions["analysis.modify.comment"].invoke = [row, context]() {
            open_comment(row, context);
            return action_handler_result_t::completed();
        };
        menu.actions["analysis.copy.address"].invoke = [value = address_text(row.address)]() {
            ImGui::SetClipboardText(value.c_str());
            return action_handler_result_t::completed();
        };
        menu.actions["analysis.copy.address_va"].invoke = [value = address_text(row.address)]() {
            ImGui::SetClipboardText(value.c_str());
            return action_handler_result_t::completed();
        };
    }
    menu.actions["analysis.copy.name"].invoke = [value = row.name]() {
        ImGui::SetClipboardText(value.c_str());
        return action_handler_result_t::completed();
    };
    menu.actions["analysis.copy.text"].invoke = [value = row.name + "\t" + row.context + "\t" + row.detail]() {
        ImGui::SetClipboardText(value.c_str());
        return action_handler_result_t::completed();
    };
    menu.actions["analysis.copy.line"].invoke = [value =
        (row.has_address ? address_text(row.address) : std::string("-")) + "\t" +
        row.name + "\t" + row.context + "\t" + row.detail]() {
        ImGui::SetClipboardText(value.c_str());
        return action_handler_result_t::completed();
    };
    open(std::move(menu), origin);
}

inline void render(domain_t domain) {
    const auto workspace = aida::analysis::workspace_registry().selected_for_ui();
    const auto context = disasm_view::capture_workspace(workspace);
    const auto& info = descriptor(domain);
    const ImVec2 available = ImGui::GetContentRegionAvail();
    if (!context) {
        aida::ui::empty_state::config_t empty;
        empty.glyph = aida::ui::empty_state::glyph_t::binary_file;
        empty.title = "No analysis workspace";
        empty.body = "Open and analyze a binary to populate this view.";
        aida::ui::empty_state::render(ImGui::GetCursorScreenPos(), available, empty);
        return;
    }
    const auto state = state_for(domain, workspace);
    rebuild_rows(domain, *state, context);
    rebuild_visible(*state);
    auto page_count = (std::max<std::size_t>)(1,
        (state->visible.size() + state->page_size - 1) / state->page_size);
    if (state->page >= page_count) state->page = page_count - 1;
    const float toolbar_start_y = ImGui::GetCursorScreenPos().y;
    const bool narrow_toolbar = available.x < 520.0f;
    ImGui::PushID(info.stable_id);
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(6.0f, 4.0f));
    ImGui::PushFont(aida::ui::fonts::body_strong() ? aida::ui::fonts::body_strong() : ImGui::GetFont());
    ImGui::AlignTextToFramePadding();
    ImGui::TextUnformatted(info.title);
    ImGui::PopFont();
    if (narrow_toolbar) {
        ImGui::SameLine();
        ImGui::BeginDisabled(state->page == 0);
        if (ImGui::SmallButton("<")) --state->page;
        ImGui::EndDisabled();
        ImGui::SameLine();
        ImGui::BeginDisabled(state->page + 1 >= page_count);
        if (ImGui::SmallButton(">")) ++state->page;
        ImGui::EndDisabled();
        ImGui::SameLine();
        ImGui::TextDisabled("%zu/%zu | %zu", state->page + 1, page_count,
            state->visible.size());
    } else {
        ImGui::SameLine();
    }
    ImGui::SetNextItemWidth(narrow_toolbar ? available.x
        : (std::max)(120.0f, available.x - 310.0f));
    if (aida::ui::input_text("##filter", state->filter, sizeof(state->filter),
            "Filter by address, name, or detail...", false, ImVec2(0.0f, 25.0f)))
        state->filter_dirty = true;
    rebuild_visible(*state);
    page_count = (std::max<std::size_t>)(1,
        (state->visible.size() + state->page_size - 1) / state->page_size);
    if (state->page >= page_count) state->page = page_count - 1;
    if (!narrow_toolbar) {
        ImGui::SameLine();
        ImGui::BeginDisabled(state->page == 0);
        if (ImGui::SmallButton("<")) --state->page;
        ImGui::EndDisabled();
        ImGui::SameLine();
        ImGui::BeginDisabled(state->page + 1 >= page_count);
        if (ImGui::SmallButton(">")) ++state->page;
        ImGui::EndDisabled();
        ImGui::SameLine();
        ImGui::TextDisabled("%zu/%zu | %zu", state->page + 1, page_count, state->visible.size());
    }
    ImGui::PopStyleVar();
    const float toolbar_height = (std::max)(0.0f,
        ImGui::GetCursorScreenPos().y - toolbar_start_y);
    const float content_height = (std::max)(1.0f, available.y - toolbar_height);

    if (state->rows.empty()) {
        aida::ui::empty_state::config_t empty;
        empty.glyph = aida::ui::empty_state::glyph_t::binary_file;
        empty.title = info.empty_title;
        empty.body = info.empty_body;
        aida::ui::empty_state::render(ImGui::GetCursorScreenPos(),
            ImVec2(available.x, content_height), empty);
        ImGui::PopID();
        return;
    }
    if (state->visible.empty()) {
        aida::ui::empty_state::config_t empty;
        empty.glyph = aida::ui::empty_state::glyph_t::search;
        empty.title = "No matches";
        empty.body = "No published item matches the current filter.";
        aida::ui::empty_state::render(ImGui::GetCursorScreenPos(),
            ImVec2(available.x, content_height), empty);
        ImGui::PopID();
        return;
    }

    const ImGuiTableFlags flags = ImGuiTableFlags_Resizable | ImGuiTableFlags_Reorderable |
        ImGuiTableFlags_Hideable | ImGuiTableFlags_Sortable | ImGuiTableFlags_RowBg |
        ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingStretchProp;
    row_t context_row;
    bool request_pointer_context = false;
    if (ImGui::BeginTable("##analysis_list", 4, flags,
            ImVec2(available.x, content_height))) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 142.0f);
        ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthStretch, 1.4f);
        ImGui::TableSetupColumn("Kind / Source", ImGuiTableColumnFlags_WidthStretch, 0.7f);
        ImGui::TableSetupColumn("Details", ImGuiTableColumnFlags_WidthStretch, 1.0f);
        ImGui::TableHeadersRow();
        if (auto* specs = ImGui::TableGetSortSpecs(); specs && specs->SpecsDirty && specs->SpecsCount != 0) {
            state->sort_column = specs->Specs[0].ColumnIndex;
            state->sort_ascending = specs->Specs[0].SortDirection != ImGuiSortDirection_Descending;
            state->sort_dirty = true;
            specs->SpecsDirty = false;
            rebuild_visible(*state);
        }
        const std::size_t first = state->page * state->page_size;
        const std::size_t last = (std::min)(state->visible.size(), first + state->page_size);
        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(last - first), 22.0f);
        while (clipper.Step()) {
            for (int page_row = clipper.DisplayStart; page_row < clipper.DisplayEnd; ++page_row) {
                const std::size_t source = state->visible[first + static_cast<std::size_t>(page_row)];
                const auto& row = state->rows[source];
                ImGui::TableNextRow(0, 22.0f);
                ImGui::TableSetColumnIndex(0);
                ImGui::PushID(static_cast<int>(source));
                const bool selected = state->selected_source == source;
                const bool activated = ImGui::Selectable("##row", selected,
                    ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowDoubleClick,
                    ImVec2(0.0f, 20.0f));
                if (activated) {
                    select_row(row, *state, source, context);
                    if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left))
                        open_disassembly(row, context);
                }
                if (ImGui::IsItemClicked(ImGuiMouseButton_Right)) {
                    select_row(row, *state, source, context);
                    state->context_source = source;
                    context_row = row;
                    request_pointer_context = true;
                }
                ImGui::SameLine();
                ImGui::PushFont(aida::ui::fonts::code() ? aida::ui::fonts::code() : ImGui::GetFont());
                ImGui::TextUnformatted(row.has_address ? address_text(row.address).c_str() : "-");
                ImGui::PopFont();
                ImGui::TableSetColumnIndex(1);
                ImGui::TextUnformatted(row.name.c_str());
                ImGui::TableSetColumnIndex(2);
                ImGui::TextUnformatted(row.context.c_str());
                ImGui::TableSetColumnIndex(3);
                ImGui::TextUnformatted(row.detail.c_str());
                ImGui::PopID();
            }
        }
        clipper.End();
        ImGui::EndTable();
    }

    const row_t* selected = state->selected_source < state->rows.size()
        ? &state->rows[state->selected_source] : nullptr;
    const bool accepts_shortcuts = selected &&
        ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows) &&
        !ImGui::IsAnyItemActive() && !ImGui::GetIO().WantTextInput;
    if (accepts_shortcuts) {
        int navigation_delta = 0;
        if (ImGui::IsKeyPressed(ImGuiKey_UpArrow, false)) navigation_delta = -1;
        if (ImGui::IsKeyPressed(ImGuiKey_DownArrow, false)) navigation_delta = 1;
        if (ImGui::IsKeyPressed(ImGuiKey_PageUp, false)) navigation_delta = -10;
        if (ImGui::IsKeyPressed(ImGuiKey_PageDown, false)) navigation_delta = 10;
        if (navigation_delta != 0 || ImGui::IsKeyPressed(ImGuiKey_Home, false) ||
            ImGui::IsKeyPressed(ImGuiKey_End, false)) {
            auto current = std::find(state->visible.begin(), state->visible.end(), state->selected_source);
            std::ptrdiff_t position = current == state->visible.end() ? 0 :
                std::distance(state->visible.begin(), current);
            if (ImGui::IsKeyPressed(ImGuiKey_Home, false)) position = 0;
            else if (ImGui::IsKeyPressed(ImGuiKey_End, false))
                position = static_cast<std::ptrdiff_t>(state->visible.size() - 1);
            else position = (std::max<std::ptrdiff_t>)(0,
                (std::min<std::ptrdiff_t>)(static_cast<std::ptrdiff_t>(state->visible.size() - 1),
                    position + navigation_delta));
            const std::size_t source = state->visible[static_cast<std::size_t>(position)];
            select_row(state->rows[source], *state, source, context);
            state->page = static_cast<std::size_t>(position) / state->page_size;
        }
        if (ImGui::GetIO().KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_C, false))
            ImGui::SetClipboardText(selected->name.c_str());
    }
    aida::ui::context_menu_open_origin_t keyboard_origin{};
    const bool request_keyboard_context = selected && accepts_shortcuts &&
        aida::ui::analysis_context_menu::keyboard_request(keyboard_origin);
    const auto selection_validator = [state, expected = state->selected_source,
                                      identity = selected ? row_identity(*selected)
                                                          : row_identity(context_row)] {
        return state->selected_source < state->rows.size() &&
            state->selected_source == expected &&
            row_identity(state->rows[state->selected_source]) == identity
            ? aida::ui::capability_state_t::available()
            : aida::ui::capability_state_t::unavailable(
                "The selected analysis-list entity changed");
    };
    if (request_pointer_context)
        open_context(context_row, context,
            aida::ui::context_menu_open_origin_t::pointer, selection_validator);
    else if (request_keyboard_context)
        open_context(*selected, context, keyboard_origin, selection_validator);
    aida::ui::analysis_context_menu::render();
    rename_dialog::render();
    comment_dialog::render();
    ImGui::PopID();
}

}
