#pragma once

#include <atomic>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "file_context_tracker.hpp"
#include "mcp_standalone.hpp"


void init_standalone_chat();
void shutdown_standalone_chat();


void tick_ai_chat();
void poll_ai_chat();
void render_settings_inline(float panel_w, float panel_h);
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

extern bool g_settings_open;
