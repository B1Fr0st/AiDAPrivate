#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "file_context_tracker.hpp"
#include "mcp_standalone.hpp"


void init_standalone_chat();
void shutdown_standalone_chat();
void mark_ide_ready_for_mcp_services();
void start_authorized_mcp_services();


void tick_ai_chat();
void poll_ai_chat();
void render_tool_approval_dialog();
bool is_ai_busy();
void chat_request_cancel();
std::atomic<bool>* chat_cancel_flag();


void        chat_bind_session(const std::string& session_id);
std::string chat_active_session();
void        chat_record_assistant_message_id(const std::string& message_id);
std::string start_new_conversation();


namespace mcp_client { class manager_t; }
mcp_client::manager_t& get_mcp_client_manager();

mcp_standalone::server_t& get_local_mcp_server();
std::vector<mcp_standalone::tool_def_t> snapshot_local_tools();
std::string execute_local_tool(const std::string& name, const nlohmann::json& arguments);


file_context::tracker_t& get_file_tracker();

void do_process_attach(unsigned long pid);
void do_process_detach();
bool is_process_attached();
std::string get_attached_process_name();
unsigned long get_attached_pid();

void chat_handle_agent_shortcuts();
void chat_render_agent_pill(float anchor_x, float anchor_y, float alpha);
float chat_agent_pill_width();
void chat_render_model_pill(float anchor_x, float anchor_y, float alpha);
float chat_model_pill_width();
void chat_render_skills_pill(float anchor_x, float anchor_y, float alpha, char* chat_buf, std::size_t chat_buf_size);
float chat_skills_pill_width();
void chat_render_mcp_pill(float anchor_x, float anchor_y, float alpha);
float chat_mcp_pill_width();

namespace aida::automation_ui {

enum class message_action_t : std::uint8_t {
    copy_text = 0,
    copy_reasoning,
    copy_tool_name,
    send_to_chat_input,
    create_evidence_handoff,
    edit_message,
    retry_from_here,
    delete_message,
    inspect_tool_activity,
    review_change,
    apply_change,
    reject_change,
    cancel_active_operation
};

enum class context_open_origin_t : std::uint8_t {
    pointer = 0,
    menu_key,
    shift_f10
};

struct message_identity_t {
    std::string session_id;
    std::size_t index = 0;
    std::int64_t timestamp = 0;
    std::uint64_t fingerprint = 0;
};

struct message_selection_t {
    message_identity_t identity;
    std::string text;
    std::string reasoning;
    std::string tool_name;
    std::string model_id;
    bool is_user = false;
    bool is_tool_result = false;
    bool streaming = false;
};

struct message_context_request_t {
    context_open_origin_t origin = context_open_origin_t::pointer;
    message_selection_t selection;
};

struct evidence_handoff_t {
    message_identity_t source;
    std::string evidence_id;
    std::string source_kind;
    std::string text;
    std::string tool_name;
    bool truncated = false;
};

struct evidence_envelope_t {
    std::string id;
    std::string project_id;
    std::string workspace_id;
    std::string session_id;
    std::string source_view_id;
    std::string source_kind;
    std::string entity_id;
    std::string display_label;
    std::string return_target;
    std::string excerpt;
    std::uint64_t address = 0;
    std::uint64_t revision = 0;
    std::uint64_t generation = 0;
    std::uint64_t snapshot_hash = 0;
    std::uint64_t content_hash = 0;
    std::uint64_t created_ms = 0;
    bool truncated = false;
    bool sensitive = false;
    bool stale = false;
    std::string stale_reason;
};

struct action_capability_t {
    bool visible = true;
    bool enabled = false;
    std::string disabled_reason;
};

struct action_result_t {
    bool succeeded = false;
    std::string detail;
    std::string target_view_id;
    evidence_handoff_t evidence;
};

struct editor_proposal_snapshot_t {
    std::string id;
    message_identity_t source;
    std::string target_document_id;
    std::uint64_t base_content_hash = 0;
    std::uint64_t generation = 0;
    bool pending = false;
    bool applying = false;
    bool applied = false;
    bool rejected = false;
    bool stale = false;
    std::string detail;
};

struct message_window_t {
    std::size_t first = 0;
    std::size_t last = 0;
    std::size_t total = 0;
    bool bounded = false;
};

struct tool_approval_snapshot_t {
    bool pending = false;
    std::uint64_t identity = 0;
    std::string tool_name;
    std::string arguments_preview;
};

struct surface_capabilities_t {
    bool chat = true;
    bool agents = true;
    bool skills = true;
    bool providers = true;
    bool settings = true;
    bool mcp_marketplace = true;
    bool evidence_pane = false;
    bool mcp_activity_pane = false;
    bool scripts_pane = false;
    bool background_tasks_pane = false;
    std::string evidence_reason;
    std::string mcp_activity_reason;
    std::string scripts_reason;
    std::string background_tasks_reason;
};

std::size_t message_count();
message_identity_t message_identity(std::size_t index);
bool message_selection(const message_identity_t& identity, message_selection_t& selection, std::string& reason);
bool open_message_context(const message_identity_t& identity, context_open_origin_t origin, message_context_request_t& request, std::string& reason);
action_capability_t message_action_capability(const message_identity_t& identity, message_action_t action);
action_result_t execute_message_action(const message_identity_t& identity, message_action_t action);
message_window_t bounded_message_window(std::size_t first_visible, std::size_t visible_count, std::size_t overscan = 4);
tool_approval_snapshot_t tool_approval_snapshot();
action_result_t respond_to_tool_approval(std::uint64_t identity, bool approve);
surface_capabilities_t surface_capabilities();
std::string register_evidence(evidence_envelope_t envelope);
std::vector<evidence_envelope_t> evidence_snapshot();
bool queue_evidence_for_chat(const std::string& evidence_id, std::string& reason);
bool queue_evidence_for_agent(const std::string& evidence_id, std::string& reason);
bool navigate_to_evidence_source(const std::string& evidence_id, std::string& reason);
void render_evidence_view(float width, float height);
void render_chat_view(float width, float height);
action_result_t stage_editor_proposal(const message_identity_t& source,
                                      const std::string& proposed_content);
editor_proposal_snapshot_t editor_proposal_snapshot();

}
