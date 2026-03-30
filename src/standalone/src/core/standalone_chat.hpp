#pragma once


void init_standalone_chat();
void shutdown_standalone_chat();


void tick_ai_chat();
void poll_ai_chat();
void render_settings_popup();

extern bool g_settings_open;
