#include "pseudocode_view.hpp"

#include "comment_dialog.hpp"
#include "rename_dialog.hpp"
#include "../analysis/workspace/decompiler_service.hpp"
#include "../analysis/workspace/workspace_registry.hpp"
#include "../infra/taskflow_runtime.hpp"
#include "../ui/theme.hpp"
#include "../../helpers/globals.h"

#include "imgui/imgui.h"

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace pseudocode_view {

namespace {

enum class tab_status_t : std::uint8_t {
    queued = 0,
    decompiling = 1,
    ready = 2,
    failed = 3,
    cancelled = 4
};

struct rendered_result_t {
    aida::analysis::decompiler_result_t result;
    std::vector<std::size_t> line_offsets;
};

struct tab_t {
    aida::analysis::address_t address;
    std::string label;
    tab_status_t status = tab_status_t::queued;
    std::string error;
    bool error_acknowledged = false;
    std::shared_ptr<const rendered_result_t> rendered;
    std::shared_ptr<aida::analysis::cancellation_source_t> cancellation;
    std::uint64_t serial = 0;
    std::uint64_t generation = 0;
};

struct state_t {
    std::mutex mutex;
    std::vector<tab_t> tabs;
    int active = -1;
    int selected_line = -1;
    std::atomic<std::uint64_t> next_serial{1};
};

std::mutex& state_registry_mutex() {
    static std::mutex value;
    return value;
}

std::unordered_map<aida::analysis::binary_id_t, std::shared_ptr<state_t>,
    aida::analysis::binary_id_hash_t>& state_registry() {
    static std::unordered_map<aida::analysis::binary_id_t, std::shared_ptr<state_t>,
        aida::analysis::binary_id_hash_t> value;
    return value;
}

std::shared_ptr<state_t> state_for(const disasm_view::workspace_context_t& context) {
    if (!context.workspace)
        return {};
    const auto id = context.workspace->identity().binary_id();
    std::lock_guard<std::mutex> lock(state_registry_mutex());
    auto& registry = state_registry();
    auto found = registry.find(id);
    if (found != registry.end())
        return found->second;
    auto created = std::make_shared<state_t>();
    registry.emplace(id, created);
    return created;
}

std::vector<std::size_t> line_offsets(const std::string& text) {
    std::vector<std::size_t> output;
    output.reserve((std::min)(text.size() / 24 + 1, static_cast<std::size_t>(1U << 20)));
    output.push_back(0);
    for (std::size_t index = 0; index < text.size(); ++index) {
        if (text[index] == '\n' && index + 1 < text.size())
            output.push_back(index + 1);
    }
    return output;
}

std::string label_for(const disasm_view::workspace_context_t& context,
                      const aida::analysis::address_t& address) {
    std::string label = disasm_view::resolve_name(context, address);
    if (!label.empty())
        return label;
    char buffer[40]{};
    std::snprintf(buffer, sizeof(buffer), "sub_%llX",
        static_cast<unsigned long long>(disasm_view::runtime_address(context, address).value_or(
            address.value)));
    return buffer;
}

std::optional<std::size_t> find_tab(const state_t& state,
                                    const aida::analysis::address_t& address) {
    for (std::size_t index = 0; index < state.tabs.size(); ++index) {
        if (state.tabs[index].address == address)
            return index;
    }
    return {};
}

void finish_request(const disasm_view::workspace_context_t& context,
                    const std::shared_ptr<state_t>& state,
                    const aida::analysis::address_t& address,
                    std::uint64_t serial,
                    aida::analysis::workspace_result_t<aida::analysis::decompiler_result_t> result) {
    std::lock_guard<std::mutex> lock(state->mutex);
    const auto index = find_tab(*state, address);
    if (!index)
        return;
    auto& tab = state->tabs[*index];
    if (tab.serial != serial || tab.generation != context.publication->generation)
        return;
    if (!result) {
        tab.error = result.error().stable_code() + ": " + result.error().message;
        tab.error_acknowledged = false;
        tab.status = result.error().cancellation ? tab_status_t::cancelled : tab_status_t::failed;
        tab.rendered.reset();
        return;
    }
    auto rendered = std::make_shared<rendered_result_t>();
    rendered->result = result.take_value();
    rendered->line_offsets = line_offsets(rendered->result.pseudocode);
    tab.label = rendered->result.function_name.empty() ? tab.label :
        rendered->result.function_name;
    tab.rendered = std::move(rendered);
    tab.error.clear();
    tab.status = tab_status_t::ready;
}

void submit_request(const disasm_view::workspace_context_t& context,
                    const std::shared_ptr<state_t>& state,
                    const aida::analysis::address_t& address,
                    std::uint64_t serial,
                    const std::shared_ptr<aida::analysis::cancellation_source_t>& cancellation) {
    const std::string target_id = context.workspace->identity().binary_id().to_hex();
    aida::infra::taskflow_runtime::task_descriptor_t descriptor;
    descriptor.domain = aida::infra::taskflow_runtime::executor_domain_t::feature_worker;
    descriptor.owner_subsystem = "pseudocode_view";
    descriptor.label = "workspace_decompile";
    descriptor.target_id = target_id.c_str();
    descriptor.generation = context.publication->generation;
    descriptor.cancellable_body = [context, state, address, serial, cancellation](
        const aida::infra::taskflow_runtime::cancellation_token_t& runtime_cancel) {
        if (runtime_cancel.requested.load(std::memory_order_acquire))
            cancellation->request_cancel();
        {
            std::lock_guard<std::mutex> lock(state->mutex);
            const auto index = find_tab(*state, address);
            if (!index || state->tabs[*index].serial != serial)
                return;
            state->tabs[*index].status = tab_status_t::decompiling;
        }
        auto service = context.workspace->decompiler();
        if (!service) {
            finish_request(context, state, address, serial,
                aida::analysis::workspace_result_t<aida::analysis::decompiler_result_t>::failure(
                    aida::analysis::make_workspace_error(
                        aida::analysis::workspace_error_code_t::service_conflict,
                        "workspace decompiler service is unavailable", "ui_decompile")));
            return;
        }
        auto result = service->decompile(address, {}, cancellation->token());
        finish_request(context, state, address, serial, std::move(result));
    };
    const auto submitted = aida::infra::taskflow_runtime::submit(std::move(descriptor));
    if (!submitted.submitted) {
        finish_request(context, state, address, serial,
            aida::analysis::workspace_result_t<aida::analysis::decompiler_result_t>::failure(
                aida::analysis::make_workspace_error(
                    aida::analysis::workspace_error_code_t::service_conflict,
                    submitted.reject_reason.empty() ? "decompiler queue rejected the request" :
                        submitted.reject_reason,
                    "ui_decompile")));
    }
}

std::optional<aida::analysis::address_t> function_address(
    const disasm_view::workspace_context_t& context, std::uint64_t address) {
    const auto function = disasm_view::enclosing_function_start(address, context);
    if (function == 0)
        return {};
    return disasm_view::typed_address(context, function);
}

std::optional<aida::analysis::address_t> line_address(
    const rendered_result_t& rendered, int line,
    const disasm_view::workspace_context_t& context) {
    std::uint64_t best = 0;
    for (const auto& mapping : rendered.result.line_to_address) {
        if (mapping.first > line)
            break;
        best = mapping.second;
    }
    return best == 0 ? std::nullopt : disasm_view::typed_address(context, best);
}

std::string line_text(const rendered_result_t& rendered, std::size_t index) {
    if (index >= rendered.line_offsets.size())
        return {};
    const auto begin = rendered.line_offsets[index];
    auto end = index + 1 < rendered.line_offsets.size()
        ? rendered.line_offsets[index + 1] : rendered.result.pseudocode.size();
    while (end > begin && (rendered.result.pseudocode[end - 1] == '\n' ||
           rendered.result.pseudocode[end - 1] == '\r'))
        --end;
    return rendered.result.pseudocode.substr(begin, end - begin);
}

disasm_view::workspace_context_t selected_context() {
    return disasm_view::capture_selected_workspace();
}

}

void request_decompile(const disasm_view::workspace_context_t& context,
                       std::uint64_t address, bool force_refresh) {
    if (!context || context.workspace->closing() || context.workspace->closed())
        return;
    const auto typed = function_address(context, address);
    if (!typed)
        return;
    auto state = state_for(context);
    if (!state)
        return;
    std::shared_ptr<aida::analysis::cancellation_source_t> cancellation;
    std::uint64_t serial = 0;
    {
        std::lock_guard<std::mutex> lock(state->mutex);
        const auto existing = find_tab(*state, *typed);
        if (existing) {
            state->active = static_cast<int>(*existing);
            auto& tab = state->tabs[*existing];
            if (!force_refresh && (tab.status == tab_status_t::ready ||
                                   tab.status == tab_status_t::queued ||
                                   tab.status == tab_status_t::decompiling))
                return;
            if (tab.cancellation)
                tab.cancellation->request_cancel();
            cancellation = std::make_shared<aida::analysis::cancellation_source_t>();
            serial = state->next_serial.fetch_add(1, std::memory_order_acq_rel);
            tab.cancellation = cancellation;
            tab.serial = serial;
            tab.generation = context.publication->generation;
            tab.status = tab_status_t::queued;
            tab.error.clear();
            tab.error_acknowledged = false;
            tab.rendered.reset();
        } else {
            tab_t tab;
            tab.address = *typed;
            tab.label = label_for(context, *typed);
            tab.cancellation = std::make_shared<aida::analysis::cancellation_source_t>();
            tab.serial = state->next_serial.fetch_add(1, std::memory_order_acq_rel);
            tab.generation = context.publication->generation;
            cancellation = tab.cancellation;
            serial = tab.serial;
            state->tabs.push_back(std::move(tab));
            state->active = static_cast<int>(state->tabs.size() - 1);
        }
        state->selected_line = -1;
    }
    submit_request(context, state, *typed, serial, cancellation);
}

void request_decompile(std::uint64_t address, const DisasmFile*, bool force_refresh) {
    request_decompile(selected_context(), address, force_refresh);
}

void close_active_tab(const disasm_view::workspace_context_t& context) {
    auto state = state_for(context);
    if (!state)
        return;
    std::lock_guard<std::mutex> lock(state->mutex);
    if (state->active < 0 || static_cast<std::size_t>(state->active) >= state->tabs.size())
        return;
    if (state->tabs[static_cast<std::size_t>(state->active)].cancellation)
        state->tabs[static_cast<std::size_t>(state->active)].cancellation->request_cancel();
    state->tabs.erase(state->tabs.begin() + state->active);
    state->active = state->tabs.empty() ? -1 :
        (std::min)(state->active, static_cast<int>(state->tabs.size() - 1));
    state->selected_line = -1;
}

void close_all_tabs(const disasm_view::workspace_context_t& context) {
    auto state = state_for(context);
    if (!state)
        return;
    std::lock_guard<std::mutex> lock(state->mutex);
    for (auto& tab : state->tabs) {
        if (tab.cancellation)
            tab.cancellation->request_cancel();
    }
    state->tabs.clear();
    state->active = -1;
    state->selected_line = -1;
}

void close_tab_by_addr(const disasm_view::workspace_context_t& context,
                       std::uint64_t address) {
    auto state = state_for(context);
    const auto typed = function_address(context, address);
    if (!state || !typed)
        return;
    std::lock_guard<std::mutex> lock(state->mutex);
    const auto index = find_tab(*state, *typed);
    if (!index)
        return;
    if (state->tabs[*index].cancellation)
        state->tabs[*index].cancellation->request_cancel();
    state->tabs.erase(state->tabs.begin() + static_cast<std::ptrdiff_t>(*index));
    if (state->tabs.empty())
        state->active = -1;
    else if (state->active >= static_cast<int>(state->tabs.size()))
        state->active = static_cast<int>(state->tabs.size() - 1);
}

void activate_tab_by_addr(const disasm_view::workspace_context_t& context,
                          std::uint64_t address) {
    auto state = state_for(context);
    const auto typed = function_address(context, address);
    if (!state || !typed)
        return;
    std::lock_guard<std::mutex> lock(state->mutex);
    const auto index = find_tab(*state, *typed);
    if (index) {
        state->active = static_cast<int>(*index);
        state->selected_line = -1;
    }
}

void cancel_active_decompile(const disasm_view::workspace_context_t& context) {
    auto state = state_for(context);
    if (!state)
        return;
    std::lock_guard<std::mutex> lock(state->mutex);
    if (state->active >= 0 && static_cast<std::size_t>(state->active) < state->tabs.size() &&
        state->tabs[static_cast<std::size_t>(state->active)].cancellation)
        state->tabs[static_cast<std::size_t>(state->active)].cancellation->request_cancel();
}

void refresh_active_tab(const disasm_view::workspace_context_t& context) {
    const auto address = active_tab_address(context);
    if (address != 0)
        request_decompile(context, address, true);
}

void refresh_all_tabs(const disasm_view::workspace_context_t& context) {
    const auto tabs = snapshot_tabs(context);
    for (const auto& tab : tabs)
        request_decompile(context, tab.addr, true);
}

bool has_active_tab(const disasm_view::workspace_context_t& context) {
    auto state = state_for(context);
    if (!state)
        return false;
    std::lock_guard<std::mutex> lock(state->mutex);
    return state->active >= 0 && static_cast<std::size_t>(state->active) < state->tabs.size();
}

bool has_tab_for(const disasm_view::workspace_context_t& context,
                 std::uint64_t address) {
    auto state = state_for(context);
    const auto typed = function_address(context, address);
    if (!state || !typed)
        return false;
    std::lock_guard<std::mutex> lock(state->mutex);
    return find_tab(*state, *typed).has_value();
}

std::uint64_t active_tab_address(const disasm_view::workspace_context_t& context) {
    auto state = state_for(context);
    if (!state)
        return 0;
    std::lock_guard<std::mutex> lock(state->mutex);
    if (state->active < 0 || static_cast<std::size_t>(state->active) >= state->tabs.size())
        return 0;
    const auto& address = state->tabs[static_cast<std::size_t>(state->active)].address;
    return disasm_view::runtime_address(context, address).value_or(address.value);
}

int tab_count(const disasm_view::workspace_context_t& context) {
    auto state = state_for(context);
    if (!state)
        return 0;
    std::lock_guard<std::mutex> lock(state->mutex);
    return static_cast<int>((std::min)(state->tabs.size(),
        static_cast<std::size_t>((std::numeric_limits<int>::max)())));
}

std::vector<tab_info_t> snapshot_tabs(const disasm_view::workspace_context_t& context) {
    std::vector<tab_info_t> output;
    auto state = state_for(context);
    if (!state)
        return output;
    std::lock_guard<std::mutex> lock(state->mutex);
    output.reserve(state->tabs.size());
    for (const auto& tab : state->tabs) {
        tab_info_t info;
        info.addr = disasm_view::runtime_address(context, tab.address).value_or(tab.address.value);
        info.label = tab.label;
        info.function_name = tab.rendered && !tab.rendered->result.function_name.empty()
            ? tab.rendered->result.function_name : tab.label;
        info.loaded = tab.status == tab_status_t::ready;
        info.decompiling = tab.status == tab_status_t::queued ||
                           tab.status == tab_status_t::decompiling;
        info.is_error = tab.status == tab_status_t::failed;
        output.push_back(std::move(info));
    }
    return output;
}

void render(float, float, float width, float height,
            float alpha, float, float, float,
            const disasm_view::workspace_context_t& context) {
    if (!context) {
        ImGui::BeginChild("##workspace_pseudocode_empty", ImVec2(width, height), false);
        ImGui::TextUnformatted("No analysis workspace is selected.");
        ImGui::EndChild();
        return;
    }
    auto state = state_for(context);
    if (!state)
        return;
    const std::string id = context.workspace->identity().binary_id().to_hex();
    ImGui::PushID(id.c_str());
    ImGui::BeginChild("##workspace_pseudocode", ImVec2(width, height), false);
    const auto& theme = aida::ui::resolved();
    ImGui::PushStyleColor(ImGuiCol_Text, aida::ui::with_alpha(theme.text_primary, alpha));
    int active = -1;
    std::vector<tab_info_t> tabs = snapshot_tabs(context);
    {
        std::lock_guard<std::mutex> lock(state->mutex);
        active = state->active;
    }
    for (std::size_t index = 0; index < tabs.size(); ++index) {
        if (index != 0)
            ImGui::SameLine();
        ImGui::PushID(static_cast<int>(index));
        const std::string label = tabs[index].label +
            (tabs[index].decompiling ? "  *" : tabs[index].is_error ? "  !" : "");
        if (ImGui::Selectable(label.c_str(), active == static_cast<int>(index), 0,
                ImVec2(0.0f, ImGui::GetFrameHeight()))) {
            std::lock_guard<std::mutex> lock(state->mutex);
            state->active = static_cast<int>(index);
            state->selected_line = -1;
            active = state->active;
        }
        ImGui::SameLine();
        if (ImGui::SmallButton("x")) {
            close_tab_by_addr(context, tabs[index].addr);
            ImGui::PopID();
            break;
        }
        ImGui::PopID();
    }
    ImGui::Separator();
    if (ImGui::Button("Refresh"))
        refresh_active_tab(context);
    ImGui::SameLine();
    if (ImGui::Button("Cancel"))
        cancel_active_decompile(context);
    ImGui::SameLine();
    if (ImGui::Button("Disasm")) {
        const auto address = active_tab_address(context);
        if (address != 0) {
            disasm_view::goto_address(address, context);
            globals::ui::active_center_view = center_view_t::disassembly;
        }
    }
    std::shared_ptr<const rendered_result_t> rendered;
    tab_status_t status = tab_status_t::failed;
    std::string error;
    int selected_line = -1;
    bool error_acknowledged = false;
    {
        std::lock_guard<std::mutex> lock(state->mutex);
        if (state->active >= 0 && static_cast<std::size_t>(state->active) < state->tabs.size()) {
            const auto& tab = state->tabs[static_cast<std::size_t>(state->active)];
            rendered = tab.rendered;
            status = tab.status;
            error = tab.error;
            error_acknowledged = tab.error_acknowledged;
            selected_line = state->selected_line;
        }
    }
    if (rendered && ImGui::Button("Copy"))
        ImGui::SetClipboardText(rendered->result.pseudocode.c_str());
    if ((status == tab_status_t::failed || status == tab_status_t::cancelled) &&
        ImGui::Button("Retry"))
        refresh_active_tab(context);
    if ((status == tab_status_t::failed || status == tab_status_t::cancelled) &&
        !error_acknowledged) {
        ImGui::SameLine();
        if (ImGui::Button("OK")) {
            std::lock_guard<std::mutex> lock(state->mutex);
            if (state->active >= 0 &&
                static_cast<std::size_t>(state->active) < state->tabs.size())
                state->tabs[static_cast<std::size_t>(state->active)].error_acknowledged = true;
            error_acknowledged = true;
        }
    }
    if (active < 0 || tabs.empty()) {
        ImGui::TextUnformatted("Press F5 in disassembly or choose Decompile function.");
    } else if (status == tab_status_t::queued || status == tab_status_t::decompiling) {
        ImGui::TextUnformatted("Decompiling the selected function...");
    } else if (status == tab_status_t::cancelled) {
        ImGui::TextUnformatted(error.empty() ? "Decompilation was cancelled." : error.c_str());
    } else if (status == tab_status_t::failed || !rendered) {
        if (!error_acknowledged)
            ImGui::TextWrapped("%s", error.empty() ? "Decompilation failed without a result." :
                error.c_str());
        else
            ImGui::TextUnformatted("The decompilation error was acknowledged. Press Retry to run it again.");
    } else {
        ImGui::BeginChild("##pseudocode_lines", ImVec2(0.0f, 0.0f), false,
            ImGuiWindowFlags_HorizontalScrollbar);
        const int line_count = rendered->line_offsets.size() >
            static_cast<std::size_t>((std::numeric_limits<int>::max)())
            ? (std::numeric_limits<int>::max)() :
              static_cast<int>(rendered->line_offsets.size());
        ImGuiListClipper clipper;
        clipper.Begin(line_count, ImGui::GetTextLineHeightWithSpacing());
        while (clipper.Step()) {
            for (int line = clipper.DisplayStart; line < clipper.DisplayEnd; ++line) {
                const std::string text = line_text(*rendered, static_cast<std::size_t>(line));
                ImGui::PushID(line);
                if (ImGui::Selectable("##pseudocode_line", selected_line == line,
                        ImGuiSelectableFlags_AllowDoubleClick,
                        ImVec2(0.0f, ImGui::GetTextLineHeightWithSpacing()))) {
                    {
                        std::lock_guard<std::mutex> lock(state->mutex);
                        state->selected_line = line;
                    }
                    selected_line = line;
                    if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
                        if (const auto address = line_address(*rendered, line, context)) {
                            disasm_view::goto_address(
                                disasm_view::runtime_address(context, *address).value_or(address->value),
                                context);
                            globals::ui::active_center_view = center_view_t::disassembly;
                        }
                    }
                }
                ImGui::SameLine(0.0f, 0.0f);
                ImGui::TextUnformatted(text.c_str());
                if (ImGui::BeginPopupContextItem("##pseudocode_actions")) {
                    if (ImGui::MenuItem("Copy line"))
                        ImGui::SetClipboardText(text.c_str());
                    const auto address = line_address(*rendered, line, context);
                    if (address && ImGui::MenuItem("Go to disassembly")) {
                        disasm_view::goto_address(
                            disasm_view::runtime_address(context, *address).value_or(address->value),
                            context);
                        globals::ui::active_center_view = center_view_t::disassembly;
                    }
                    if (address && ImGui::MenuItem("Rename"))
                        rename_dialog::open(context, *address);
                    if (address && ImGui::MenuItem("Edit comment"))
                        comment_dialog::open(context, *address);
                    ImGui::EndPopup();
                }
                ImGui::PopID();
            }
        }
        if (ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows) &&
            ImGui::IsKeyPressed(ImGuiKey_F5, false))
            refresh_active_tab(context);
        ImGui::EndChild();
    }
    ImGui::PopStyleColor();
    ImGui::EndChild();
    ImGui::PopID();
    comment_dialog::render();
    rename_dialog::render();
}

void render(float pos_x, float pos_y, float width, float height,
            float alpha, float accent_r, float accent_g, float accent_b) {
    render(pos_x, pos_y, width, height, alpha, accent_r, accent_g, accent_b,
        selected_context());
}

void close_active_tab() { close_active_tab(selected_context()); }
void close_all_tabs() { close_all_tabs(selected_context()); }
void close_tab_by_addr(std::uint64_t address) {
    close_tab_by_addr(selected_context(), address);
}
void activate_tab_by_addr(std::uint64_t address) {
    activate_tab_by_addr(selected_context(), address);
}
void cancel_active_decompile() { cancel_active_decompile(selected_context()); }
void refresh_active_tab() { refresh_active_tab(selected_context()); }
void refresh_all_tabs() { refresh_all_tabs(selected_context()); }
bool has_active_tab() { return has_active_tab(selected_context()); }
bool has_tab_for(std::uint64_t address) { return has_tab_for(selected_context(), address); }
std::uint64_t active_tab_address() { return active_tab_address(selected_context()); }
int tab_count() { return tab_count(selected_context()); }
std::vector<tab_info_t> snapshot_tabs() { return snapshot_tabs(selected_context()); }

}
