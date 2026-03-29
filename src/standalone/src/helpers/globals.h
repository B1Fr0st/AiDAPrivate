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

static bool  g_dummy_triggered = false;
static float g_think_timer = 0.f;
static bool  g_think_done = false;

inline std::vector<ChatMessage> g_chat_messages;
inline char                     g_chat_buf[4096] = {};
inline bool                     g_chat_scroll_to_bottom = false;
inline float g_chat_demo_timer = 0.f;
inline int   g_chat_demo_stage = 0;


static void tick_dummy_ai()
{
    if (g_chat_messages.empty()) return;
    auto& last = g_chat_messages.back();
    if (!last.is_user || g_dummy_triggered) return;

    g_dummy_triggered = true;
    g_think_timer = 0.f;
    g_think_done = false;

    ChatMessage ai_msg;
    ai_msg.is_user = false;
    ai_msg.has_thinking = true;
    ai_msg.streaming = false;
    ai_msg.thinking_text = "The user sent a message. Let me think about this... "
        "sub_140001000 sets up a stack frame, loads a vtable pointer at +0x28, "
        "calls a resolver, then does a guarded virtual dispatch at slot +0x10. "
        "I'll explain this clearly.";
    ai_msg.text = "";
    g_chat_messages.push_back(ai_msg);
    g_chat_scroll_to_bottom = true;
}

static void stream_dummy_ai()
{
    if (g_chat_messages.empty()) return;
    auto& last = g_chat_messages.back();
    if (last.is_user) return;

    float dt = ImGui::GetIO().DeltaTime;


    if (!g_think_done)
    {
        g_think_timer += dt;
        if (g_think_timer >= 2.5f)
            g_think_done = true;
        return;
    }


    if (!last.streaming && last.text.empty())
        last.streaming = true;

    if (!last.streaming) return;

    static float accum = 0.f;
    static int   char_idx = 0;

    const char* full =
        "This is a guarded virtual dispatch. It loads a pointer 0x28 bytes into "
        "the passed object - likely a vtable - validates it with sub_140001050, "
        "then calls the method at vtable slot +0x10. "
        "The 0x20 byte stack frame is standard x64 shadow space. "
        "If the pointer is null the je at 0x140001018 skips the call entirely.";

    accum += dt;
    if (accum < 0.018f) return;
    accum = 0.f;

    if (char_idx < (int)strlen(full))
    {
        last.text += full[char_idx++];
        g_chat_scroll_to_bottom = true;
    }
    else
    {
        last.streaming = false;
        char_idx = 0;
        g_dummy_triggered = false;
    }
}

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
