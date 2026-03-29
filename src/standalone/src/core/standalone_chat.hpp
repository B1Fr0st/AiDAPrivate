#pragma once

/*
 * standalone_chat.hpp
 *
 * Public API for the real AI chat integration.
 * Call init / shutdown from main(), the rest from the render loop.
 */

void init_standalone_chat();
void shutdown_standalone_chat();

// Call every frame after the chat child window is drawn:
void tick_ai_chat();       // detects new user messages and spawns AI worker
void poll_ai_chat();       // drains thread-safe update queue into ChatMessage list
void render_settings_popup(); // ImGui modal for provider/key/model configuration

extern bool g_settings_open;
