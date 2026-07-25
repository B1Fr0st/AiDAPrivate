#include "../../../src/core/mcp/compat/c03_compatibility_registration.hpp"
#include "../../../src/core/testlab/test_all_features.hpp"
#include "../../../src/core/ai/provider_view.hpp"
#include "../../../src/core/ai/settings_overlay.hpp"
#include "../../../src/core/analysis/struct_recon_view.hpp"
#include "../../../src/core/analysis/types_hub_view_api.hpp"
#include "../../../src/core/auth/auth_view.hpp"
#include "../../../src/core/debugger/debugger_view.hpp"
#include "../../../src/core/disasm/disasm_view.hpp"
#include "../../../src/core/disasm/pseudocode_view.hpp"
#include "../../../src/core/editor/code_editor.hpp"
#include "../../../src/core/mcp/mcp_marketplace.hpp"
#include "../../../src/core/network/burp/burp_module.hpp"
#include "../../../src/core/network/network_view.hpp"
#include "../../../src/core/runtime/run_target.hpp"
#include "../../../src/core/scanner/memory_scanner_view.hpp"
#include "../../../src/core/ui/application_view_registry.hpp"
#include "../../../src/core/ui/chat_render.hpp"
#include "../../../src/core/ui/context_menu_renderer.hpp"
#include "../../../src/core/ui/design_system.hpp"
#include "../../../src/core/ui/explorer_views.hpp"
#include "../../../src/core/ui/fonts.hpp"
#include "../../../src/core/ui/output_views.hpp"
#include "../../../src/core/ui/programming_language_views.hpp"
#include "../../../src/core/ui/programming_tasks.hpp"
#include "../../../src/core/ui/task_center.hpp"
#include "../../../src/core/ui/ui_thread_dispatcher.hpp"
#include "../../../src/core/ui/workspace_layout.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

struct ID3D11Device;

namespace {

constexpr char kHeadlessUnavailable[] =
    "Unavailable in the C03 safe headless runtime";

aida::ui::view_operation_result_t unavailable_view_operation()
{
    return {aida::ui::view_operation_status_t::unavailable, kHeadlessUnavailable};
}

aida::ui::output_views::operation_result_t unavailable_output_operation()
{
    return {false, kHeadlessUnavailable};
}

aida::ui::programming_tasks::operation_result_t unavailable_programming_operation()
{
    return {false, kHeadlessUnavailable};
}

constexpr std::array<aida::ui::workspace_layout::workspace_preset_descriptor_t, 8>
    kHeadlessWorkspacePresets{{
        {aida::ui::workspace_layout::workspace_preset_t::analysis,
         "analysis", "Analysis",
         "Disassembly, pseudocode, graph, symbols, references and inspection", 3},
        {aida::ui::workspace_layout::workspace_preset_t::debugging,
         "debugging", "Debugging",
         "Execution controls, CPU, registers, breakpoints, threads, stack and trace", 3},
        {aida::ui::workspace_layout::workspace_preset_t::memory,
         "memory", "Memory",
         "Process sessions, scans, results, memory map, hex, pointers and patches", 3},
        {aida::ui::workspace_layout::workspace_preset_t::types_structures,
         "types-structures", "Types and Structures",
         "Type catalogs, structure layouts, live values and propagation", 3},
        {aida::ui::workspace_layout::workspace_preset_t::network,
         "network", "Network",
         "Proxy history, repeater, browser, protocol streams and evidence", 3},
        {aida::ui::workspace_layout::workspace_preset_t::automation_ai,
         "automation-ai", "Automation and AI",
         "Chat, agents, skills, MCP activity, evidence review and tasks", 3},
        {aida::ui::workspace_layout::workspace_preset_t::programming,
         "programming", "Programming",
         "Project explorer, source editing, search, terminal, problems and debugging", 3},
        {aida::ui::workspace_layout::workspace_preset_t::safe,
         "safe", "Safe Layout",
         "Recovery workspace with Start Center, diagnostics and essential navigation", 3}
    }};

}

wchar_t g_aidaWindowTitle[128] = L"AiDA C03 Safe Headless";
wchar_t g_aidaClassName[128] = L"AiDAC03SafeHeadlessBoundary";
ImFont* g_font_ui_600 = nullptr;
ImFont* g_font_ui_500_sm = nullptr;
HWND g_hwnd = nullptr;
ID3D11Device* g_pd3dDevice = nullptr;

struct ConversationSummary {
    std::string id;
    std::string title;
    int64_t created = 0;
    int msg_count = 0;
    bool pinned = false;
    std::uint64_t revision = 0;
};

namespace mcp_standalone {

c03_compatibility_runtime_config_t
make_application_c03_compatibility_runtime_config()
{
    return {};
}

}

namespace test_all_features {

bool is_running()
{
    return false;
}

bool is_unattended_full_test_active()
{
    return false;
}

}

namespace aida::ui_thread {

DWORD owner_tid()
{
    return 0;
}

bool is_owner_thread()
{
    return false;
}

enqueue_result_t post(task_t, post_options_t)
{
    return enqueue_result_t::rejected_shutdown;
}

bool post(task_t, const char*, const char*, const char*)
{
    return false;
}

std::size_t pending_count()
{
    return 0;
}

void format_snapshot(char* out, std::size_t cap)
{
    if (out == nullptr || cap == 0)
        return;
    constexpr char snapshot[] =
        "headless=1 ready=0 destroying=0 shutdown=1 pending=0 "
        "enqueued=0 executed=0 rejected=0 discarded=0 max_depth=0 "
        "oldest_age_ms=0 wake_pending=0 wake_posted=0 wake_coalesced=0 "
        "wake_failed=0 budget_hits=0 drain_calls=0 drain_cancelled=0 "
        "last_drain_ms=0 active_task=0";
    constexpr std::size_t snapshot_size = sizeof(snapshot) - 1;
    const std::size_t copy_size = snapshot_size < cap - 1
        ? snapshot_size
        : cap - 1;
    std::memcpy(out, snapshot, copy_size);
    out[copy_size] = '\0';
}

std::uint64_t affinity_violation_count()
{
    return 0;
}

std::uint64_t last_drain_timestamp()
{
    return 0;
}

std::uint64_t last_wake_timestamp()
{
    return 0;
}

std::uint64_t task_budget_hit_count()
{
    return 0;
}

std::uint64_t time_budget_hit_count()
{
    return 0;
}

std::string top_queued_labels(std::size_t)
{
    return {};
}

}

namespace aida::ui::application_views {

void initialize()
{
}

view_registry_t& registry()
{
    static view_registry_t headless_registry;
    return headless_registry;
}

view_operation_result_t open_or_focus(const stable_view_id_t&)
{
    return unavailable_view_operation();
}

view_operation_result_t close(const stable_view_id_t&)
{
    return unavailable_view_operation();
}

view_operation_result_t close_instance(const view_instance_id_t&)
{
    return unavailable_view_operation();
}

view_operation_result_t close_other_instances(const view_instance_id_t&)
{
    return unavailable_view_operation();
}

view_operation_result_t toggle_pin(const view_instance_id_t&)
{
    return unavailable_view_operation();
}

view_operation_result_t request_reset_state(const view_instance_id_t&)
{
    return unavailable_view_operation();
}

view_operation_result_t duplicate_instance(const view_instance_id_t&)
{
    return unavailable_view_operation();
}

view_operation_result_t reopen_last_closed()
{
    return unavailable_view_operation();
}

view_operation_result_t open_default_missing()
{
    return unavailable_view_operation();
}

bool is_open(const stable_view_id_t&) noexcept
{
    return false;
}

bool is_pinned(const view_instance_id_t&) noexcept
{
    return false;
}

bool can_duplicate(const view_instance_id_t&) noexcept
{
    return false;
}

bool can_reset_state(const view_instance_id_t&) noexcept
{
    return false;
}

bool can_reopen_last_closed() noexcept
{
    return false;
}

const char* category_label(view_category_t category) noexcept
{
    switch (category) {
    case view_category_t::shell: return "Shell";
    case view_category_t::explorer: return "Explore";
    case view_category_t::document: return "Documents";
    case view_category_t::analysis: return "Analysis";
    case view_category_t::debugger: return "Debugging";
    case view_category_t::memory: return "Memory";
    case view_category_t::types: return "Types and Structures";
    case view_category_t::network: return "Network";
    case view_category_t::automation: return "Automation and AI";
    case view_category_t::programming: return "Programming";
    case view_category_t::output: return "Output";
    case view_category_t::settings: return "Settings";
    }
    return "Views";
}

}

namespace aida::ui::design {

void set_preferences(preferences_t)
{
}

scaled_metrics_t metrics()
{
    return {};
}

void text(text_role_t, const char*)
{
}

void tooltip_for_last_item(const char*, const char*, const char*)
{
}

action_result_t render_toolbar(const char*, const action_t*, std::size_t, float)
{
    return {};
}

action_result_t render_state(const state_presentation_t&, ImVec2)
{
    return {};
}

bool begin_dialog(const char*, const char*, ImVec2, ImVec2)
{
    return false;
}

bool begin_dialog_exact(const char*, ImVec2, ImVec2, bool*, ImGuiWindowFlags)
{
    return false;
}

void open_dialog(const char*, const char*)
{
}

float dialog_footer_reserve_height(const char*, const char*)
{
    return 0.0f;
}

bool begin_dialog_body(const char*, float)
{
    return false;
}

void end_dialog_body()
{
}

dialog_result_t dialog_footer(const char*, const char*, bool, bool, const char*, bool, bool)
{
    return {};
}

void render_confirmation_content(const confirmation_t&)
{
}

dialog_result_t confirmation_dialog(const char*, const confirmation_t&)
{
    return {};
}

bool publish_notification(notification_t)
{
    return false;
}

}

namespace aida::ui::explorer_views {

bool can_restore_previous_session()
{
    return false;
}

bool request_restore_previous_session()
{
    return false;
}

file_operation_capability_t file_operation_capability(
    file_operation_t, const std::vector<file_operation_target_t>&)
{
    return {false, kHeadlessUnavailable};
}

file_operation_result_t request_file_operation(
    file_operation_t, const std::vector<file_operation_target_t>&)
{
    return {false, kHeadlessUnavailable};
}

file_operation_result_t request_search_scope(const std::string&, bool)
{
    return {false, kHeadlessUnavailable};
}

}

namespace aida::ui::output_views {

operation_result_t copy_all(bottom_tab_t)
{
    return unavailable_output_operation();
}

operation_result_t clear(bottom_tab_t)
{
    return unavailable_output_operation();
}

operation_result_t select_all(bottom_tab_t)
{
    return unavailable_output_operation();
}

operation_result_t toggle_follow(bottom_tab_t)
{
    return unavailable_output_operation();
}

operation_result_t focus_filter(bottom_tab_t)
{
    return unavailable_output_operation();
}

operation_result_t export_all(bottom_tab_t)
{
    return unavailable_output_operation();
}

operation_result_t terminal_new()
{
    return unavailable_output_operation();
}

operation_result_t terminal_close()
{
    return unavailable_output_operation();
}

operation_result_t terminal_restart()
{
    return unavailable_output_operation();
}

operation_result_t terminal_next()
{
    return unavailable_output_operation();
}

operation_result_t terminal_previous()
{
    return unavailable_output_operation();
}

operation_result_t terminal_split_vertical()
{
    return unavailable_output_operation();
}

operation_result_t terminal_split_horizontal()
{
    return unavailable_output_operation();
}

operation_result_t terminal_unsplit()
{
    return unavailable_output_operation();
}

operation_result_t terminal_focus_search()
{
    return unavailable_output_operation();
}

operation_result_t terminal_paste()
{
    return unavailable_output_operation();
}

bool has_content(bottom_tab_t)
{
    return false;
}

bool supports_filter(bottom_tab_t) noexcept
{
    return false;
}

bool follows_tail(bottom_tab_t)
{
    return false;
}

bool source_available(bottom_tab_t) noexcept
{
    return false;
}

std::size_t terminal_session_count() noexcept
{
    return 0;
}

bool terminal_is_split() noexcept
{
    return false;
}

}

namespace aida::ui::programming_tasks {

operation_result_t request_run_selected()
{
    return unavailable_programming_operation();
}

operation_result_t request_run_selected_for_file(const std::string&, bool)
{
    return unavailable_programming_operation();
}

operation_result_t request_test_selected_for_file(const std::string&)
{
    return unavailable_programming_operation();
}

operation_result_t request_cancel_active()
{
    return unavailable_programming_operation();
}

operation_result_t request_retry_last()
{
    return unavailable_programming_operation();
}

operation_result_t open_configurations()
{
    return unavailable_programming_operation();
}

operation_result_t reload_configurations()
{
    return unavailable_programming_operation();
}

std::string run_unavailable_reason()
{
    return kHeadlessUnavailable;
}

std::string run_for_file_unavailable_reason(const std::string&, bool)
{
    return kHeadlessUnavailable;
}

std::string test_for_file_unavailable_reason(const std::string&)
{
    return kHeadlessUnavailable;
}

std::string cancel_unavailable_reason()
{
    return kHeadlessUnavailable;
}

std::string retry_unavailable_reason()
{
    return kHeadlessUnavailable;
}

}

namespace aida::ui::workspace_layout {

ImGuiID node_id(dock_role_t) noexcept
{
    return 0;
}

}

namespace code_editor_widget {

bool load_document(std::uint64_t, std::uint64_t, std::string_view,
                   std::string_view, std::string_view, bool, int, int,
                   float, float, bool, int, int, bool,
                   const std::vector<int>&, std::string_view)
{
    return false;
}

}

namespace debugger_view {

execution_capability_t execution_capability(execution_command_t)
{
    return {false, kHeadlessUnavailable};
}

bool execute_command(execution_command_t, std::string* error)
{
    if (error)
        *error = kHeadlessUnavailable;
    return false;
}

execution_capability_t patch_panel_capability(patch_panel_command_t)
{
    return {false, kHeadlessUnavailable};
}

bool execute_patch_panel_command(patch_panel_command_t, std::string* error)
{
    if (error)
        *error = kHeadlessUnavailable;
    return false;
}

bool stage_exact_patch_review(std::uint64_t,
                              const std::vector<std::uint8_t>&,
                              const std::vector<std::uint8_t>&,
                              std::uint32_t, const std::string&,
                              std::string* error)
{
    if (error)
        *error = kHeadlessUnavailable;
    return false;
}

execution_capability_t address_mutation_capability(
    std::uint64_t, bool, std::uint32_t)
{
    return {false, kHeadlessUnavailable};
}

execution_capability_t address_mutation_capability(
    const debugger_interaction::context_t&, bool)
{
    return {false, kHeadlessUnavailable};
}

bool queue_run_to_address(std::uint64_t, std::uint32_t, std::string* error)
{
    if (error)
        *error = kHeadlessUnavailable;
    return false;
}

bool queue_run_to_address(const debugger_interaction::context_t&, std::string* error)
{
    if (error)
        *error = kHeadlessUnavailable;
    return false;
}

bool queue_toggle_breakpoint(std::uint64_t, std::uint32_t, std::string* error)
{
    if (error)
        *error = kHeadlessUnavailable;
    return false;
}

bool queue_toggle_breakpoint(const debugger_interaction::context_t&, std::string* error)
{
    if (error)
        *error = kHeadlessUnavailable;
    return false;
}

}

namespace types_hub_view {

bool stage_type_application(const disasm_view::workspace_context_t&,
                            const aida::analysis::address_t&,
                            std::string* error)
{
    if (error)
        *error = kHeadlessUnavailable;
    return false;
}

}

namespace memory_scanner_view {

scan_command_state_t scan_command_capability(scan_command_t)
{
    return {false, kHeadlessUnavailable};
}

scan_command_result_t execute_scan_command(scan_command_t)
{
    return {false, kHeadlessUnavailable};
}

}

namespace network_view {

intercept_command_capability_t intercept_command_capability(intercept_command_t)
{
    return {false, kHeadlessUnavailable};
}

bool execute_intercept_command(intercept_command_t, std::string* error)
{
    if (error)
        *error = kHeadlessUnavailable;
    return false;
}

operational_command_capability_t operational_command_capability(
    operational_command_t)
{
    operational_command_capability_t capability;
    capability.disabled_reason = kHeadlessUnavailable;
    return capability;
}

bool prepare_operational_command_confirmation(
    operational_command_t, std::string* error)
{
    if (error)
        *error = kHeadlessUnavailable;
    return false;
}

void cancel_operational_command_confirmation(operational_command_t) noexcept
{
}

bool execute_operational_command(operational_command_t, std::string* error)
{
    if (error)
        *error = kHeadlessUnavailable;
    return false;
}

bool resolve_artifact(const artifact_identity_t&, artifact_snapshot_t& snapshot,
                      std::string& unavailable_reason)
{
    snapshot = {};
    unavailable_reason = kHeadlessUnavailable;
    return false;
}

bool validate_reviewed_request(const artifact_identity_t&,
                               const std::vector<std::uint8_t>&,
                               artifact_identity_t& canonical_source,
                               std::string& unavailable_reason)
{
    canonical_source = {};
    unavailable_reason = kHeadlessUnavailable;
    return false;
}

bool stage_validated_reviewed_request(const artifact_identity_t&,
                                      const std::vector<std::uint8_t>&,
                                      const std::string&,
                                      artifact_identity_t& staged_identity,
                                      std::string& unavailable_reason)
{
    staged_identity = {};
    unavailable_reason = kHeadlessUnavailable;
    return false;
}

}

namespace struct_recon_view {

command_result_t copy_current_declaration()
{
    return {false, kHeadlessUnavailable};
}

command_result_t declare_and_apply_current()
{
    return {false, kHeadlessUnavailable};
}

bool has_current_structure()
{
    return false;
}

}

namespace pseudocode_view {

void request_decompile(const disasm_view::workspace_context_t&,
                       std::uint64_t, bool)
{
}

}

namespace file_browser {

void refresh(const std::string&)
{
}

}

namespace disasm_view {

workspace_context_t capture_workspace(
    const std::shared_ptr<aida::analysis::analysis_workspace_t>&)
{
    return {};
}

workspace_context_t capture_selected_workspace()
{
    return {};
}

std::optional<aida::analysis::address_t> typed_address(
    const workspace_context_t&, std::uint64_t)
{
    return std::nullopt;
}

std::optional<std::uint64_t> runtime_address(
    const workspace_context_t&, const aida::analysis::address_t&)
{
    return std::nullopt;
}

std::optional<std::uint64_t> provider_offset(
    const workspace_context_t&, const aida::analysis::address_t&)
{
    return std::nullopt;
}

aida::analysis::workspace_result_t<std::vector<std::uint8_t>> read_bytes(
    const workspace_context_t&, const aida::analysis::address_t&, std::size_t)
{
    aida::analysis::workspace_error_t error;
    error.code = aida::analysis::workspace_error_code_t::provider_unavailable;
    error.message = kHeadlessUnavailable;
    error.phase = "c03_safe_headless";
    return aida::analysis::workspace_result_t<std::vector<std::uint8_t>>::failure(
        std::move(error));
}

std::string resolve_name(const workspace_context_t&,
                         const aida::analysis::address_t&)
{
    return {};
}

std::string comment(const workspace_context_t&,
                    const aida::analysis::address_t&)
{
    return {};
}

bool queue_comment(const workspace_context_t&,
                   const aida::analysis::address_t&, std::string,
                   std::optional<std::uint64_t>,
                   std::optional<std::uint64_t>,
                   std::optional<std::uint64_t>, overlay_completion_t)
{
    return false;
}

bool queue_rename(const workspace_context_t&,
                  const aida::analysis::address_t&, std::string,
                  std::optional<std::uint64_t>,
                  std::optional<std::uint64_t>,
                  std::optional<std::uint64_t>, overlay_completion_t)
{
    return false;
}

bool queue_bookmark(const workspace_context_t&,
                    const aida::analysis::address_t&, std::string)
{
    return false;
}

bool open_exact_static_patch_review(
    const workspace_context_t&, const aida::analysis::address_t&,
    const std::vector<std::uint8_t>&, const std::vector<std::uint8_t>&,
    const std::string&, std::uint64_t, std::uint64_t, std::uint64_t,
    std::string* error)
{
    if (error)
        *error = kHeadlessUnavailable;
    return false;
}

bool open_selected_patch_review(static_patch_mode_t, std::string* error)
{
    if (error)
        *error = kHeadlessUnavailable;
    return false;
}

bool queue_type_application(const workspace_context_t&,
                            const aida::analysis::address_t&, std::string,
                            std::optional<std::uint64_t>,
                            std::optional<std::uint64_t>,
                            std::optional<std::uint64_t>, overlay_completion_t)
{
    return false;
}

mutation_state_t mutation_state(const workspace_context_t&)
{
    mutation_state_t state;
    state.error = kHeadlessUnavailable;
    return state;
}

bool queue_overlay_undo(const workspace_context_t&)
{
    return false;
}

bool queue_overlay_redo(const workspace_context_t&)
{
    return false;
}

void goto_address(std::uint64_t, const workspace_context_t&)
{
}

bool request_goto(const workspace_context_t&)
{
    return false;
}

bool request_rebase(const workspace_context_t&, std::string* error)
{
    if (error)
        *error = kHeadlessUnavailable;
    return false;
}

bool request_listing_export(const workspace_context_t&, std::string* error)
{
    if (error)
        *error = kHeadlessUnavailable;
    return false;
}

void select_address(std::uint64_t, const workspace_context_t&, bool)
{
}

void navigate_back(const workspace_context_t&)
{
}

void navigate_forward(const workspace_context_t&)
{
}

void open_xrefs(std::uint64_t, const workspace_context_t&)
{
}

std::uint64_t enclosing_function_start(std::uint64_t,
                                       const workspace_context_t&)
{
    return 0;
}

}

namespace file_browser {

bool set_workspace_root(const std::string&, std::string* error)
{
    if (error)
        *error = kHeadlessUnavailable;
    return false;
}

bool binary_analysis_candidate(const std::string&)
{
    return false;
}

void toggle_dir(int)
{
}

void open_file(int)
{
}

bool reveal_path(const std::string&)
{
    return false;
}

void request_open_confirmation(const std::string&)
{
}

}

namespace code_editor_widget {

document_state_t document_state()
{
    document_state_t state;
    state.stream_error = kHeadlessUnavailable;
    return state;
}

document_capabilities_t document_capabilities()
{
    return {};
}

bool request_document_action(document_action_t)
{
    return false;
}

void discard_document_state(std::uint64_t)
{
}

bool select_document_for_actions(std::uint64_t)
{
    return false;
}

std::uint64_t active_document_id()
{
    return 0;
}

std::uint64_t document_revision()
{
    return 0;
}

bool get_document_caret(std::uint64_t, int& line, int& column)
{
    line = 0;
    column = 0;
    return false;
}

bool set_document_caret(std::uint64_t, int, int)
{
    return false;
}

document_metadata_snapshot_t document_metadata(std::uint64_t)
{
    return {};
}

document_payload_snapshot_t document_payload(std::uint64_t, std::uint64_t)
{
    return {};
}

std::string caret_identifier()
{
    return {};
}

void mark_document_saved(std::uint64_t, std::uint64_t,
                         std::string_view, std::string_view)
{
}

bool request_streamed_document(std::uint64_t, std::uint64_t,
                               std::string_view, std::string_view,
                               std::uint64_t)
{
    return false;
}

void trigger_undo()
{
}

void trigger_redo()
{
}

void trigger_cut()
{
}

void trigger_copy()
{
}

void trigger_paste()
{
}

void trigger_delete()
{
}

void trigger_select_all()
{
}

void open_find()
{
}

void open_replace()
{
}

void open_goto_line()
{
}

bool can_undo()
{
    return false;
}

bool can_redo()
{
    return false;
}

bool can_paste()
{
    return false;
}

bool has_selection()
{
    return false;
}

std::string selected_text(std::size_t)
{
    return {};
}

bool selected_range(int& start_line, int& start_column,
                    int& end_line, int& end_column)
{
    start_line = 0;
    start_column = 0;
    end_line = 0;
    end_column = 0;
    return false;
}

std::string last_error()
{
    return kHeadlessUnavailable;
}

std::uint64_t document_content_fingerprint()
{
    return 0;
}

bool begin_agent_edit(std::string_view)
{
    return false;
}

bool propose_full_content(std::string_view)
{
    return false;
}

bool propose_document_content(std::uint64_t, std::uint64_t, std::uint64_t,
                              std::string_view, std::string_view,
                              std::string_view)
{
    return false;
}

bool has_pending_diff()
{
    return false;
}

const pending_diff_t& pending_diff()
{
    static const pending_diff_t empty_diff;
    return empty_diff;
}

int pending_hunk_count()
{
    return 0;
}

bool has_pending_review_hunks()
{
    return false;
}

review_hunk_identity_t review_hunk_identity(int)
{
    return {};
}

review_hunk_identity_t selected_review_hunk_identity()
{
    return {};
}

int resolve_review_hunk(const review_hunk_identity_t&, bool)
{
    return -1;
}

bool select_next_pending_hunk()
{
    return false;
}

bool select_previous_pending_hunk()
{
    return false;
}

bool accept_hunk(int)
{
    return false;
}

bool reject_hunk(int)
{
    return false;
}

void accept_all()
{
}

void reject_all()
{
}

bool commit_resolved_diff()
{
    return false;
}

void cancel_agent_edit()
{
}

}

namespace aida::ui::workspace_layout {

window_placement_state_t inspect_window_placement(std::string_view) noexcept
{
    return {};
}

workspace_request_result_t float_window(std::string_view) noexcept
{
    return workspace_request_result_t::unavailable;
}

workspace_request_result_t dock_window(std::string_view, dock_role_t) noexcept
{
    return workspace_request_result_t::unavailable;
}

workspace_request_result_t split_window(
    std::string_view, std::string_view, dock_split_direction_t) noexcept
{
    return workspace_request_result_t::unavailable;
}

void settle_pending_operation_for_shutdown() noexcept
{
}

const workspace_preset_descriptor_t* presets(std::size_t& count) noexcept
{
    count = kHeadlessWorkspacePresets.size();
    return kHeadlessWorkspacePresets.data();
}

workspace_preset_t active_preset() noexcept
{
    return workspace_preset_t::safe;
}

workspace_identity_t active_identity() noexcept
{
    workspace_identity_t identity;
    identity.preset = workspace_preset_t::safe;
    return identity;
}

bool user_layout_catalog_ready() noexcept
{
    return false;
}

bool layout_locked() noexcept
{
    return true;
}

workspace_request_result_t set_layout_locked(bool) noexcept
{
    return workspace_request_result_t::unavailable;
}

bool operation_pending() noexcept
{
    return false;
}

std::string operation_status() noexcept
{
    return kHeadlessUnavailable;
}

workspace_request_result_t switch_to(workspace_preset_t) noexcept
{
    return workspace_request_result_t::unavailable;
}

workspace_request_result_t save_active_user_layout() noexcept
{
    return workspace_request_result_t::unavailable;
}

workspace_request_result_t restore_builtin(workspace_preset_t) noexcept
{
    return workspace_request_result_t::unavailable;
}

workspace_request_result_t reset_current() noexcept
{
    return workspace_request_result_t::unavailable;
}

workspace_request_result_t activate_safe_layout() noexcept
{
    return workspace_request_result_t::unavailable;
}

workspace_request_result_t open_missing_views() noexcept
{
    return workspace_request_result_t::unavailable;
}

}

namespace aida::burp {

bool initialize()
{
    return false;
}

void register_all_tools(mcp_standalone::server_t&)
{
}

}

namespace aida::ui::task_center {

bool register_task(task_registration_t)
{
    return false;
}

bool register_executor_job(std::uint64_t, task_registration_t)
{
    return false;
}

bool try_register_executor_job(std::uint64_t, task_registration_t)
{
    return false;
}

bool update_task(const std::string&, task_state_t, float, std::string,
                 std::string, std::string, std::string)
{
    return false;
}

bool raise_diagnostic(diagnostic_registration_t)
{
    return false;
}

immutable_snapshot_ptr snapshot()
{
    static const immutable_snapshot_ptr empty_snapshot =
        std::make_shared<const immutable_snapshot_t>();
    return empty_snapshot;
}

}

namespace run_target {

bool launch(const launch_options_t&, launch_result_t& out)
{
    out = {};
    out.error = kHeadlessUnavailable;
    return false;
}

bool cleanup(launch_result_t& result)
{
    result.ok = false;
    result.error = kHeadlessUnavailable;
    return false;
}

capability_probe_t probe_capabilities()
{
    return {};
}

}

namespace mcp_marketplace {

std::vector<installed_server_t> get_installed()
{
    return {};
}

void activate_server(const installed_server_t&)
{
}

void load_installed(const std::string&)
{
}

std::string save_installed()
{
    return "[]";
}

void shutdown()
{
}

}

namespace conversations {

void save_current()
{
}

void load_conversation(const std::string&)
{
}

void new_chat()
{
}

void refresh_history()
{
}

void delete_conversation(const std::string&, std::uint64_t)
{
}

bool set_pinned(const std::string&, bool)
{
    return false;
}

bool fork_conversation(const std::string&, std::string& forked_id)
{
    forked_id.clear();
    return false;
}

bool export_markdown(const std::string&, const std::string&, std::string& error)
{
    error = kHeadlessUnavailable;
    return false;
}

void process_store_completion(bool)
{
}

bool commit_shutdown(std::string& error)
{
    error = kHeadlessUnavailable;
    return false;
}

std::shared_ptr<const std::vector<ConversationSummary>> catalog_snapshot()
{
    static const auto empty_catalog =
        std::make_shared<const std::vector<ConversationSummary>>();
    return empty_catalog;
}

}

namespace aida::settings_overlay {

void initialize()
{
}

void shutdown()
{
}

void open()
{
}

void toggle()
{
}

bool is_open()
{
    return false;
}

void set_active_tab(tab_index_t)
{
}

void open_to_provider(const std::string&)
{
}

}

namespace aida::auth_view {

void initialize()
{
}

void shutdown()
{
}

bool is_provider_authenticated(const std::string&)
{
    return false;
}

}

namespace aida::provider_view {

void initialize()
{
}

void shutdown()
{
}

}

namespace chat_render {

render_result_t render_rich_message(
    ImDrawList*, ImVec2, float, const std::string&, float, float, float, float,
    int, float, bool)
{
    render_result_t result{};
    result.action_msg_index = -1;
    return result;
}

}

namespace network_view {

bool make_sitemap_artifact(std::uint64_t, artifact_kind_t,
                           artifact_identity_t& identity,
                           std::string& unavailable_reason)
{
    identity = {};
    unavailable_reason = kHeadlessUnavailable;
    return false;
}

void open_exchange_context(artifact_identity_t, artifact_identity_t,
                           exchange_context_origin_t, bool)
{
}

}

namespace aida::ui {

context_menu_render_result_t render_context_menu_popup(
    const char*, const context_menu_presenter_t&,
    const context_menu_open_request_t&, const interaction_context_t&)
{
    return {};
}

}

namespace aida::ui::programming_language_views {

void open_rename_dialog()
{
}

}
