#pragma once

#include <string>
#include <vector>


void init_standalone_chat();
void shutdown_standalone_chat();


void tick_ai_chat();
void poll_ai_chat();
void render_settings_inline(float panel_w, float panel_h);
void render_tool_approval_dialog();


namespace mcp_client { class manager_t; }
mcp_client::manager_t& get_mcp_client_manager();


void do_process_attach(unsigned long pid);
void do_process_detach();
bool is_process_attached();
std::string get_attached_process_name();
unsigned long get_attached_pid();

extern bool g_settings_open;
