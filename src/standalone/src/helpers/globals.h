#pragma once
#include "imgui/imgui_internal.h"
#include <iostream>
#include <d3d11.h>


struct ChatMessage {
	std::string text;
	std::string thinking_text;
	bool is_user = false;
	bool has_thinking = false;
	bool streaming = false;
};

inline bool  g_dummy_triggered = false;
inline float g_think_timer = 0.f;
inline bool  g_think_done = false;

inline std::vector<ChatMessage> g_chat_messages;
inline char                     g_chat_buf[4096] = {};
inline bool                     g_chat_scroll_to_bottom = false;
inline float g_chat_demo_timer = 0.f;
inline int   g_chat_demo_stage = 0;


// Real AI chat integration  (see core/standalone_chat.hpp)
void tick_ai_chat();
void poll_ai_chat();
void render_settings_popup();
extern bool g_settings_open;

namespace globals
{

	inline ID3D11ShaderResourceView* bullet_srv = nullptr;

	namespace ui
	{
		inline ImVec4 accent = ImVec4(134.f / 255.f, 135.f / 255.f, 254.f / 255.f, 1.f);
		inline ImVec4 alpha_bar_nigger_thing = ImVec4(134.f / 255.f, 135.f / 255.f, 254.f / 255.f, 1.f);


		inline float load_timer = 0.f;
		inline float window_w = 250;
		inline float window_h = 200;
		inline float ui_alpha = 0.f;
		inline bool test = false;

		inline float test2 = 0.0f;

		inline ImVec4 accents[] = {
			ImVec4(134.f / 255.f, 135.f / 255.f, 254.f / 255.f, 1.f),
			ImVec4(0.85f, 0.15f, 0.15f, 1.f),
			ImVec4(0.55f, 0.55f, 0.55f, 1.f),
			ImVec4(0.55f, 0.45f, 0.85f, 1.f),
			ImVec4(0.25f, 0.55f, 0.85f, 1.f),
		};

		inline int theme = 0;

		inline bool is_moving = false;

		inline int welcome_set = -1;
		inline float welcome_timer = 0.f;
		inline float welcome_alpha = 0.f;
		inline float welcome_text_y_offset = 30.f;
		inline bool welcome_done = false;
	}

	namespace cfg {

		inline bool aimbot_enabled = false;
		inline bool aimbot_silent = false;
		inline bool aimbot_visible_only = false;
		inline bool aimbot_auto_shoot = false;
		inline bool esp_enabled = false;
		inline bool esp_boxes = false;
		inline bool esp_skeletons = false;
		inline bool esp_health = false;
		inline bool misc_bhop = false;
		inline bool misc_no_recoil = false;

		inline float aimbot_fov = 10.f;
		inline float aimbot_smooth = 5.f;
		inline float esp_distance = 100.f;
		inline float misc_speed = 1.f;

		inline int aimbot_hitbox = 0;
		inline int aimbot_bone = 0;
		inline int esp_box_type = 0;
		inline int misc_weapon = 0;
	}


}
