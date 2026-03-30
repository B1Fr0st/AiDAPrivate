#include "helpers.h"
#include "globals.h"
#include <commdlg.h>
#include <fstream>
#include <map>
#include <algorithm>
#include <iostream>
#include <string>
#include <thread>
#include <chrono>
#include <nlohmann/json.hpp>
#include "blur.h"
#include "../assets/icons.h"
#include "../core/zydis_disasm.hpp"
#include "../core/standalone_chat.hpp"
#include "../core/standalone_license.hpp"
#include "../core/standalone_settings.hpp"

static ID3D11ShaderResourceView* g_send_icon_srv    = nullptr;
static ID3D11ShaderResourceView* g_loader_icon_srv  = nullptr;
static int                        g_loader_icon_w    = 0;
static int                        g_loader_icon_h    = 0;
DisasmState                       g_disasm;


#include "../assets/theme_icons/kaneki.h"
#include "../assets/theme_icons/rias.h"
#include "../assets/theme_icons/nagi.h"
#include "../assets/theme_icons/mio_akiyama.h"

ID3D11ShaderResourceView* helpers::theme_rias = nullptr;
ID3D11ShaderResourceView* helpers::theme_nagi = nullptr;
ID3D11ShaderResourceView* helpers::theme_mio = nullptr;
ID3D11ShaderResourceView* helpers::theme_kaneki = nullptr;
bool helpers::themes_loaded = false;


extern unsigned char background[];
extern unsigned char aidalogo[];
static ID3D11ShaderResourceView* g_bg_art_srv = nullptr;
static int g_bg_art_w = 0, g_bg_art_h = 0;
static bool g_bg_art_loaded = false;

static int g_theme_icon_w[4] = {}, g_theme_icon_h[4] = {};
static ID3D11ShaderResourceView* g_custom_theme_icon_srv = nullptr;
static int g_custom_theme_icon_w = 0;
static int g_custom_theme_icon_h = 0;
static std::string g_custom_theme_icon_path;

int helpers::active_tab = 0;
int helpers::active_subsection = 0;
bool helpers::init = false;
static float fadeout = 1.f;

ID3D11ShaderResourceView* helpers::icon_aim = nullptr;
ID3D11ShaderResourceView* helpers::icon_see = nullptr;
ID3D11ShaderResourceView* helpers::icon_misc = nullptr;
ID3D11ShaderResourceView* helpers::icon_settings = nullptr;
ID3D11ShaderResourceView* helpers::icon_player = nullptr;
ID3D11ShaderResourceView* helpers::icon_solitude = nullptr;

int helpers::icon_w = 0;
int helpers::icon_h = 0;
bool helpers::icons_loaded = false;

bool helpers::tab(const char* label, int index, ImVec2 pos, ImVec2 size)
{
	ImDrawList* dl = ImGui::GetWindowDrawList();
	ImVec2 wp = ImGui::GetWindowPos();
	ImVec2 tab_min = ImVec2(wp.x + pos.x, wp.y + pos.y);
	ImVec2 tab_max = ImVec2(tab_min.x + size.x, tab_min.y + size.y);

	bool hovered = ImGui::IsMouseHoveringRect(tab_min, tab_max, false);
	bool clicked = hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left);
	if (clicked) active_tab = index;
	bool active = active_tab == index;

	ImGuiStorage* storage = ImGui::GetStateStorage();
	ImGuiID anim_id = 1000 + index;
	ImGuiID hover_id = 3000 + index;

	float t = storage->GetFloat(anim_id, active ? 1.0f : 0.0f);
	float ht = storage->GetFloat(hover_id, 0.0f);

	t += ((active ? 1.0f : 0.0f) - t) * std::min(8.0f * ImGui::GetIO().DeltaTime, 1.0f);
	ht += ((hovered ? 1.0f : 0.0f) - ht) * std::min(12.0f * ImGui::GetIO().DeltaTime, 1.0f);

	storage->SetFloat(anim_id, t);
	storage->SetFloat(hover_id, ht);

	float ax = globals::ui::accent.x * 255;
	float ay = globals::ui::accent.y * 255;
	float az = globals::ui::accent.z * 255;

	if (t > 0.01f)
	{
		for (int i = 4; i >= 1; i--)
		{
			float spread = i * 3.0f;
			dl->AddRectFilled(
				ImVec2(tab_min.x - spread, tab_min.y - spread),
				ImVec2(tab_max.x + spread, tab_max.y + spread),
				IM_COL32((int)ax, (int)ay, (int)az, (int)(8 * t * (5 - i))),
				6.f + spread
			);
		}
	}

	dl->AddRectFilled(tab_min, tab_max, IM_COL32(
		(int)(255 * 0.08f * ht * (1.0f - t)),
		(int)(255 * 0.08f * ht * (1.0f - t)),
		(int)(255 * 0.08f * ht * (1.0f - t)),
		(int)(255 * 0.08f * ht * (1.0f - t))
	), 6.f);

	if (t > 0.01f)
	{
		dl->AddRectFilled(tab_min, tab_max, IM_COL32(
			(int)(ax * 0.18f + 15),
			(int)(ay * 0.18f + 15),
			(int)(az * 0.18f + 20),
			(int)(220 * t)
		), 6.f);

		dl->AddRectFilled(
			tab_min,
			ImVec2(tab_max.x, tab_min.y + 1),
			IM_COL32(255, 255, 255, (int)(20 * t)),
			6.f
		);
	}

	ImVec2 ts = ImGui::CalcTextSize(label);
	ImVec2 tp = ImVec2(
		tab_min.x + (size.x - ts.x) * 0.5f,
		tab_min.y + (size.y - ts.y) * 0.5f
	);

	ImU32 text_col = IM_COL32(
		(int)(120 + (ax - 120) * t + 30 * ht * (1.0f - t)),
		(int)(120 + (ay - 120) * t + 30 * ht * (1.0f - t)),
		(int)(120 + (az - 120) * t + 30 * ht * (1.0f - t)),
		255
	);

	dl->AddText(tp, text_col, label);

	return clicked;
}

void helpers::begin_child(const char* str_id, ImVec2 pos, ImVec2 size, float alpha, ImGuiWindowFlags flags)
{
	ImDrawList* dl = ImGui::GetWindowDrawList();
	ImVec2 wp = ImGui::GetWindowPos();

	ImVec2 r_min = ImVec2(std::round(wp.x + pos.x), std::round(wp.y + pos.y));
	ImVec2 r_max = ImVec2(std::round(r_min.x + size.x), std::round(r_min.y + size.y));

	dl->AddRectFilled(r_min, r_max, IM_COL32(22, 22, 28, (int)(210 * alpha)), 8.f);

	bool has_label = str_id && str_id[0] != '\0';
	std::string uid = has_label ? str_id : std::string("##child_") + std::to_string((uintptr_t)&pos);
	float padding = 6;
	ImGui::SetCursorPos(ImVec2(pos.x + padding, pos.y + padding));
	ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));
	ImGui::BeginChild(uid.c_str(), ImVec2(size.x - (2 * padding), size.y - (2 * padding)), false,
		ImGuiWindowFlags_NoBackground | flags);

}

void helpers::end_child()
{
	ImGui::EndChild();
	ImGui::PopStyleVar();
}

int helpers::subsection(const char** labels, int count, ImVec2 pos)
{
	ImDrawList* dl  = ImGui::GetWindowDrawList();
	ImVec2      wp  = ImGui::GetWindowPos();
	float spacing   = 3.0f;
	float avail_w   = ImGui::GetCurrentWindow()->Size.x - (pos.x * 2.0f) + 10.0f;
	float btn_w     = (avail_w - spacing * (count - 1)) / count;
	float x_off     = pos.x - 5.0f;
	float fh        = ImGui::GetFontSize();
	float btn_h     = fh + 6.0f;

	static std::map<int, float> anim;

	for (int i = 0; i < count; i++)
	{
		ImVec2 ts      = ImGui::CalcTextSize(labels[i]);
		ImVec2 btn_min = ImVec2(std::round(wp.x + x_off),         std::round(wp.y + pos.y));
		ImVec2 btn_max = ImVec2(std::round(btn_min.x + btn_w),    std::round(btn_min.y + btn_h));

		bool hovered = ImGui::IsMouseHoveringRect(btn_min, btn_max);
		if (hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
			active_subsection = i;

		if (anim.find(i) == anim.end()) anim[i] = (active_subsection == i) ? 1.0f : 0.0f;
		float spd = 10.0f * ImGui::GetIO().DeltaTime;
		float tgt = (active_subsection == i) ? 1.0f : 0.0f;
		anim[i] += (tgt - anim[i]) * std::min(spd, 1.0f);
		float t = anim[i];


		if (hovered)
			dl->AddRectFilled(btn_min, btn_max, IM_COL32(255, 255, 255, 8), 4.f);


		ImU32 text_col = IM_COL32(
			(int)((0.65f + (globals::ui::accent.x - 0.65f) * t) * 255),
			(int)((0.60f + (globals::ui::accent.y - 0.60f) * t) * 255),
			(int)((0.70f + (globals::ui::accent.z - 0.70f) * t) * 255),
			(int)((0.45f + 0.55f * t) * 255)
		);
		ImVec2 tp = ImVec2(btn_min.x + (btn_w - ts.x) * 0.5f, btn_min.y + (btn_h - fh) * 0.5f);
		dl->AddText(tp, text_col, labels[i]);


		float line_hw = btn_w * 0.5f * t;
		float line_cx = btn_min.x + btn_w * 0.5f;
		float line_y  = btn_max.y - 1.0f;
		if (line_hw > 0.5f)
		{
			ImU32 lc = IM_COL32(
				(int)(globals::ui::accent.x * 255),
				(int)(globals::ui::accent.y * 255),
				(int)(globals::ui::accent.z * 255),
				(int)(210 * t));
			dl->AddLine(ImVec2(line_cx - line_hw, line_y),
				        ImVec2(line_cx + line_hw, line_y), lc, 1.5f);
		}

		x_off += btn_w + spacing;
	}
	return active_subsection;
}

int helpers::subsection(const char** labels, int count, ImVec2 pos, int& state)
{
	ImDrawList* dl  = ImGui::GetWindowDrawList();
	ImVec2      wp  = ImGui::GetWindowPos();
	float spacing   = 3.0f;
	float avail_w   = ImGui::GetCurrentWindow()->Size.x - (pos.x * 2.0f) + 10.0f;
	float btn_w     = (avail_w - spacing * (count - 1)) / count;
	float x_off     = pos.x - 5.0f;
	float fh        = ImGui::GetFontSize();
	float btn_h     = fh + 6.0f;

	static std::map<int*, float> anim;

	for (int i = 0; i < count; i++)
	{
		ImVec2 ts      = ImGui::CalcTextSize(labels[i]);
		ImVec2 btn_min = ImVec2(std::round(wp.x + x_off),       std::round(wp.y + pos.y));
		ImVec2 btn_max = ImVec2(std::round(btn_min.x + btn_w),  std::round(btn_min.y + btn_h));

		bool hovered = ImGui::IsMouseHoveringRect(btn_min, btn_max);
		if (hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
			state = i;

		if (anim.find(&state) == anim.end()) anim[&state] = (state == i) ? 1.0f : 0.0f;
		anim[&state] += ((state == i ? 1.0f : 0.0f) - anim[&state])
			* std::min(10.0f * ImGui::GetIO().DeltaTime, 1.0f);
		float t = anim[&state];

		if (hovered)
			dl->AddRectFilled(btn_min, btn_max, IM_COL32(255, 255, 255, 8), 4.f);

		ImU32 text_col = IM_COL32(
			(int)((0.65f + (globals::ui::accent.x - 0.65f) * t) * 255),
			(int)((0.60f + (globals::ui::accent.y - 0.60f) * t) * 255),
			(int)((0.70f + (globals::ui::accent.z - 0.70f) * t) * 255),
			(int)((0.45f + 0.55f * t) * 255)
		);
		ImVec2 tp = ImVec2(btn_min.x + (btn_w - ts.x) * 0.5f, btn_min.y + (btn_h - fh) * 0.5f);
		dl->AddText(tp, text_col, labels[i]);

		float line_hw = btn_w * 0.5f * t;
		float line_cx = btn_min.x + btn_w * 0.5f;
		float line_y  = btn_max.y - 1.0f;
		if (line_hw > 0.5f)
		{
			ImU32 lc = IM_COL32(
				(int)(globals::ui::accent.x * 255),
				(int)(globals::ui::accent.y * 255),
				(int)(globals::ui::accent.z * 255),
				(int)(210 * t));
			dl->AddLine(ImVec2(line_cx - line_hw, line_y),
				        ImVec2(line_cx + line_hw, line_y), lc, 1.5f);
		}

		x_off += btn_w + spacing;
	}
	return state;
}

void helpers::add_key(const char* label, CKeybind* keybind)
{
	(void)label;
	ImDrawList* dl = ImGui::GetForegroundDrawList();
	ImVec2 wp = ImGui::GetWindowPos();
	ImU32 accent_col = IM_COL32(globals::ui::accent.x * 255, globals::ui::accent.y * 255, globals::ui::accent.z * 255, 255);

	static std::map<CKeybind*, bool>  menu_open;
	static std::map<CKeybind*, float> height_anim;
	static std::map<CKeybind*, float> width_anim;

	if (menu_open.find(keybind) == menu_open.end())   menu_open[keybind] = false;
	if (height_anim.find(keybind) == height_anim.end()) height_anim[keybind] = 0.0f;
	if (width_anim.find(keybind) == width_anim.end())  width_anim[keybind] = 0.0f;

	std::string key_name = keybind->waiting_for_input ? "..." : keybind->get_key_name();
	if (key_name == "lbutton")  key_name = "lmb";
	else if (key_name == "rbutton")  key_name = "rmb";
	else if (key_name == "mbutton")  key_name = "mmb";
	else if (key_name == "xbutton1") key_name = "xb1";
	else if (key_name == "xbutton2") key_name = "xb2";

	const char* options[] = { "Toggle", "Hold", "Always" };

	ImVec2 key_ts = ImGui::CalcTextSize(key_name.c_str());
	float max_opt_w = 0.0f;
	for (int i = 0; i < 3; i++) max_opt_w = std::max(max_opt_w, ImGui::CalcTextSize(options[i]).x);

	float min_w = 30.0f;
	float closed_w = std::max(min_w, key_ts.x + 8.0f);
	float open_w = std::max(min_w, max_opt_w + 14.0f);
	float closed_h = 13.0f;
	float open_h = 45.0f;

	ImVec2 cursor_pos = ImGui::GetCursorPos();
	float child_w = ImGui::GetCurrentWindow()->Size.x;
	float anim_spd = 10.0f * ImGui::GetIO().DeltaTime;
	float tgt = menu_open[keybind] ? 1.0f : 0.0f;

	if (height_anim[keybind] < tgt) height_anim[keybind] = std::min(height_anim[keybind] + anim_spd, tgt);
	else if (height_anim[keybind] > tgt) height_anim[keybind] = std::max(height_anim[keybind] - anim_spd, tgt);
	if (width_anim[keybind] < tgt) width_anim[keybind] = std::min(width_anim[keybind] + anim_spd, tgt);
	else if (width_anim[keybind] > tgt) width_anim[keybind] = std::max(width_anim[keybind] - anim_spd, tgt);

	float cur_w = closed_w + (open_w - closed_w) * width_anim[keybind];
	float cur_h = closed_h + (open_h - closed_h) * height_anim[keybind];
	float x_pos = child_w - cur_w - 5.0f + 5.0f;

	ImGui::SameLine();
	ImGui::SetCursorPosX(x_pos);

	ImVec2 btn_min = ImVec2(wp.x + x_pos, wp.y + cursor_pos.y);
	ImVec2 btn_max = ImVec2(btn_min.x + cur_w, btn_min.y + cur_h);

	bool hovered = ImGui::IsMouseHoveringRect(btn_min, btn_max);
	bool left_click = hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left);
	bool right_click = hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Right);

	if (right_click) { menu_open[keybind] = !menu_open[keybind]; keybind->waiting_for_input = false; }
	if (left_click && !menu_open[keybind])
	{
		keybind->waiting_for_input = !keybind->waiting_for_input;
		if (!keybind->waiting_for_input) ImGui::ClearActiveID();
	}
	if (keybind->waiting_for_input && keybind->set_key())
	{
		keybind->waiting_for_input = false;
		ImGui::ClearActiveID();
	}

	dl->AddRect(btn_min, btn_max, IM_COL32(0, 0, 0, 255));
	dl->AddRect(ImVec2(btn_min.x + 1, btn_min.y + 1), ImVec2(btn_max.x - 1, btn_max.y - 1), IM_COL32(25, 25, 35, 255));
	dl->AddRectFilledMultiColor(
		ImVec2(btn_min.x + 2, btn_min.y + 2), ImVec2(btn_max.x - 2, btn_max.y - 2),
		IM_COL32(30, 30, 30, 255), IM_COL32(30, 30, 30, 255),
		IM_COL32(15, 15, 15, 255), IM_COL32(15, 15, 15, 255)
	);

	float key_op = 1.0f - height_anim[keybind];
	if (key_op > 0.01f)
	{
		ImU32 tc = keybind->waiting_for_input ? accent_col : IM_COL32(255, 255, 255, (int)(255 * key_op));
		ImVec2 tp = ImVec2(std::round(btn_min.x + (cur_w - key_ts.x) * 0.5f), std::round(btn_min.y + (closed_h - key_ts.y) * 0.5f - 1.0f));

		dl->AddText(tp, tc, key_name.c_str());
	}

	if (height_anim[keybind] > 0.01f)
	{
		float opt_h = 13.0f;
		for (int i = 0; i < 3; i++)
		{
			float oy = btn_min.y + 3.0f + i * opt_h;
			if (oy + opt_h > btn_max.y) break;

			ImVec2 opt_min = ImVec2(btn_min.x + 2, oy + 2);
			ImVec2 opt_max = ImVec2(btn_max.x - 2, std::min(oy + opt_h, btn_max.y - 2));

			if (ImGui::IsMouseHoveringRect(opt_min, opt_max) && height_anim[keybind] > 0.99f && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
			{
				keybind->type = static_cast<CKeybind::c_keybind_type>(i);
				menu_open[keybind] = false;
			}

			bool sel = keybind->type == i;
			ImVec2 ots = ImGui::CalcTextSize(options[i]);
			ImVec2 otp = ImVec2(std::round(btn_min.x + (cur_w - ots.x) * 0.5f), std::round(oy + (opt_h - ots.y) * 0.5f - 1.0f));
			float op = height_anim[keybind];
			ImU32 oc = sel ?
				IM_COL32((int)(globals::ui::accent.x * 255), (int)(globals::ui::accent.y * 255), (int)(globals::ui::accent.z * 255), (int)(255 * op)) :
				IM_COL32(255, 255, 255, (int)(255 * op));

			if (otp.y + ots.y <= btn_max.y - 2.0f)
			{
				dl->AddText(otp, oc, options[i]);
			}
		}
	}

	if (menu_open[keybind] && ImGui::IsMouseClicked(ImGuiMouseButton_Left) && !hovered)
		menu_open[keybind] = false;
}

void helpers::render_title()
{
	float dt = ImGui::GetIO().DeltaTime;
	globals::ui::load_timer += dt;


	if (custom_themes::active_custom >= 0 &&
	    custom_themes::active_custom < (int)custom_themes::list.size()) {
		auto& ct = custom_themes::list[custom_themes::active_custom];
		snprintf(themes::resolved_name_buf, sizeof(themes::resolved_name_buf), "%s", ct.name.c_str());
		themes::resolved.name          = themes::resolved_name_buf;
		themes::resolved.accent        = ImVec4(ct.accent[0], ct.accent[1], ct.accent[2], 1.f);
		themes::resolved.bg_base       = ct.bg_base;
		themes::resolved.panel_bg      = ct.panel_bg;
		themes::resolved.panel_header  = ct.panel_header;
		themes::resolved.title_bar     = ct.title_bar;
		themes::resolved.text_primary  = ct.text_primary;
		themes::resolved.text_secondary= ct.text_secondary;
		themes::resolved.text_dim      = ct.text_dim;
		themes::resolved.acrylic_color = ct.acrylic_color;
	} else {
		themes::resolved = themes::presets[themes::active];
	}
	globals::ui::accent = themes::resolved.accent;


	if (!helpers::themes_loaded && g_pd3dDevice) {
		icon_loader::load(kaneki, sizeof(kaneki), &helpers::theme_kaneki,
			&g_theme_icon_w[0], &g_theme_icon_h[0], false);
		icon_loader::load(rias, sizeof(rias), &helpers::theme_rias,
			&g_theme_icon_w[1], &g_theme_icon_h[1], false);
		icon_loader::load(nagi, sizeof(nagi), &helpers::theme_nagi,
			&g_theme_icon_w[2], &g_theme_icon_h[2], false);
		icon_loader::load(mio, sizeof(mio), &helpers::theme_mio,
			&g_theme_icon_w[3], &g_theme_icon_h[3], false);
		helpers::themes_loaded = true;
	}


	if (!g_bg_art_loaded && g_pd3dDevice) {
		icon_loader::load(background, 8640831, &g_bg_art_srv,
			&g_bg_art_w, &g_bg_art_h, false);
		g_bg_art_loaded = true;
	}

	std::string active_custom_icon_path;
	if (custom_themes::active_custom >= 0 &&
	    custom_themes::active_custom < (int)custom_themes::list.size()) {
		active_custom_icon_path = custom_themes::list[custom_themes::active_custom].icon_file_path;
	} else if (!g_sa_settings.custom_icon_path.empty()) {
		active_custom_icon_path = g_sa_settings.custom_icon_path;
	}

	if (!active_custom_icon_path.empty() &&
	    active_custom_icon_path != g_custom_theme_icon_path &&
	    g_pd3dDevice) {
		if (g_custom_theme_icon_srv) {
			g_custom_theme_icon_srv->Release();
			g_custom_theme_icon_srv = nullptr;
		}
		g_custom_theme_icon_w = g_custom_theme_icon_h = 0;
		if (icon_loader::load_file(active_custom_icon_path.c_str(), &g_custom_theme_icon_srv,
			&g_custom_theme_icon_w, &g_custom_theme_icon_h, false))
			g_custom_theme_icon_path = active_custom_icon_path;
		else
			g_custom_theme_icon_path.clear();
	}
	if (active_custom_icon_path.empty() && g_custom_theme_icon_srv) {
		g_custom_theme_icon_srv->Release();
		g_custom_theme_icon_srv = nullptr;
		g_custom_theme_icon_w = g_custom_theme_icon_h = 0;
		g_custom_theme_icon_path.clear();
	}


	auto get_active_theme_icon = []() -> ID3D11ShaderResourceView* {
		if (custom_themes::active_custom >= 0 &&
		    custom_themes::active_custom < (int)custom_themes::list.size()) {
			auto& ct = custom_themes::list[custom_themes::active_custom];
			if (ct.icon_index < 0 && g_custom_theme_icon_srv)
				return g_custom_theme_icon_srv;
		}
		int idx = g_sa_settings.theme_icon_index;
		if (custom_themes::active_custom >= 0 &&
		    custom_themes::active_custom < (int)custom_themes::list.size())
			idx = custom_themes::list[custom_themes::active_custom].icon_index;
		switch (idx) {
			case 0: return helpers::theme_kaneki;
			case 1: return helpers::theme_rias;
			case 2: return helpers::theme_nagi;
			case 3: default: return helpers::theme_mio;
		}
	};

	bool loading = globals::ui::load_timer < 1.5f;

	if (!loading)
	{
		float tw, th;
		if (!globals::ui::welcome_done) {
			tw = 500.f; th = 300.f;
		} else if (!license::validated) {
			tw = 480.f; th = 320.f;
		} else {
			tw = (float)GetSystemMetrics(SM_CXSCREEN) * 0.75f; th = (float)GetSystemMetrics(SM_CYSCREEN) * 0.75f;
		}


		static bool initial_grow_done = false;
		if (globals::ui::welcome_done && license::validated && globals::ui::window_w >= 1000.f) {
			initial_grow_done = true;
		}
		if (!initial_grow_done) {


			if (globals::ui::welcome_done && license::validated) {
				globals::ui::window_w = tw;
				globals::ui::window_h = th;
			} else {
				globals::ui::window_w += (tw - globals::ui::window_w) * std::min(6.f * dt, 1.f);
				globals::ui::window_h += (th - globals::ui::window_h) * std::min(6.f * dt, 1.f);
			}
		}
	}

	bool welcome_ready = !loading && globals::ui::window_w >= 499.f && globals::ui::window_h >= 299.f;
	bool ui_ready      = globals::ui::window_w >= 1000.f && globals::ui::window_h >= 600.f;

	if (ui_ready && globals::ui::welcome_done && license::validated)
	{
		static float raw = 0.f;
		raw += dt;
		if (raw > 1.f) raw = 1.f;
		globals::ui::ui_alpha = raw * raw;
	}


	ImGui::SetNextWindowPos(ImVec2(0, 0), ImGuiCond_Always);
	ImGui::SetNextWindowSize(ImVec2(globals::ui::window_w, globals::ui::window_h));
	ImGui::Begin("##main", nullptr, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoBackground | ImGuiWindowFlags_NoMove);

	{
		ImVec2 bgwp = ImGui::GetWindowPos();
		auto& th = themes::resolved;
		ImGui::GetWindowDrawList()->AddRectFilled(
			bgwp,
			ImVec2(bgwp.x + globals::ui::window_w, bgwp.y + globals::ui::window_h),
			th.bg_base, 8.f);
	}

	if (!globals::ui::welcome_done && (loading || !welcome_ready || fadeout > 0.f))
	{
		static float text_alpha = 0.f;
		static float text_dir  = 1.f;

		if (loading)
		{
			fadeout = 1.f;
			text_alpha += text_dir * dt * 1.2f;
			if (text_alpha >= 1.f) { text_alpha = 1.f; text_dir = -1.f; }
			if (text_alpha <= 0.f) { text_alpha = 0.f; text_dir =  1.f; }
		}
		else
		{
			fadeout -= dt * 1.5f;
			if (fadeout < 0.f) fadeout = 0.f;
			text_alpha = fadeout;
		}

		float vis = loading ? 1.f : text_alpha;

		ImVec2 wp = ImGui::GetWindowPos();
		float cx  = wp.x + globals::ui::window_w * 0.5f;
		float cy  = wp.y + globals::ui::window_h * 0.5f - 10.f;
		ImDrawList* dl = ImGui::GetWindowDrawList();


		if (g_bg_art_srv && g_bg_art_w > 0 && g_bg_art_h > 0) {
			float ww_l = globals::ui::window_w;
			float wh_l = globals::ui::window_h;
			float scale = std::max(ww_l / (float)g_bg_art_w, wh_l / (float)g_bg_art_h);
			float draw_w = g_bg_art_w * scale;
			float draw_h = g_bg_art_h * scale;
			float ox = wp.x + (ww_l - draw_w) * 0.5f;
			float oy = wp.y + (wh_l - draw_h) * 0.5f;
			dl->AddImage((ImTextureID)g_bg_art_srv,
				ImVec2(ox, oy), ImVec2(ox + draw_w, oy + draw_h),
				ImVec2(0, 0), ImVec2(1, 1),
				IM_COL32(255, 255, 255, (int)(255 * 0.30f)));
		}


		const float dot_r  = 5.f;
		const float dot_sp = 20.f;
		for (int i = 0; i < 3; i++)
		{
			float phase  = globals::ui::load_timer * 4.f + i * (2.f * 3.14159f / 3.f);
			float bounce = sinf(phase) * 8.f;
			float dot_a  = (sinf(phase) * 0.5f + 0.5f) * 0.6f + 0.4f;
			dl->AddCircleFilled(
				ImVec2(cx + (i - 1) * dot_sp, cy + bounce),
				dot_r,
				IM_COL32(255, 255, 255, (int)(255 * dot_a * vis)));
		}


		static POINT drag_start_wnd   = {};
		static POINT drag_start_mouse = {};
		static bool  dragging  = false;
		static bool  last_lmb  = false;


		bool lmb = GetAsyncKeyState(VK_LBUTTON) & 0x8000;
		if (lmb && !last_lmb) {
			POINT cp; GetCursorPos(&cp);
			RECT wr; GetWindowRect(g_hwnd, &wr);
			if (cp.x >= wr.left && cp.x <= wr.right && cp.y >= wr.top && cp.y <= wr.bottom) {
				dragging = true;
				drag_start_mouse = cp;
				drag_start_wnd = { wr.left, wr.top };
			}
		}
		if (!lmb) dragging = false;
		if (dragging) {
			POINT cp; GetCursorPos(&cp);
			int nx = drag_start_wnd.x + (cp.x - drag_start_mouse.x);
			int ny = drag_start_wnd.y + (cp.y - drag_start_mouse.y);
			SetWindowPos(g_hwnd, nullptr, nx, ny, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
		}
		last_lmb = lmb;

		ImGui::End();
		return;
	}


	if (!globals::ui::welcome_done)
	{
		globals::ui::welcome_timer += dt;
		if (globals::ui::welcome_timer >= 2.0f) { globals::ui::welcome_done = true; globals::ui::ui_alpha = 0.f; }

		ImVec2      wp  = ImGui::GetWindowPos();
		ImDrawList* dl  = ImGui::GetWindowDrawList();
		float       t   = globals::ui::welcome_timer;
		float       ww  = globals::ui::window_w;
		float       wh  = globals::ui::window_h;
		float       cx  = wp.x + ww * 0.5f;
		float       cy  = wp.y + wh * 0.5f;


		if (g_bg_art_srv && g_bg_art_w > 0 && g_bg_art_h > 0) {
			float scale_bg = std::max(ww / (float)g_bg_art_w, wh / (float)g_bg_art_h);
			float dw_bg = g_bg_art_w * scale_bg;
			float dh_bg = g_bg_art_h * scale_bg;
			float ox_bg = wp.x + (ww - dw_bg) * 0.5f;
			float oy_bg = wp.y + (wh - dh_bg) * 0.5f;
			dl->AddImage((ImTextureID)g_bg_art_srv,
				ImVec2(ox_bg, oy_bg), ImVec2(ox_bg + dw_bg, oy_bg + dh_bg),
				ImVec2(0, 0), ImVec2(1, 1),
				IM_COL32(255, 255, 255, (int)(255 * 0.30f)));
		}

		float ax = globals::ui::accent.x * 255.f;
		float ay = globals::ui::accent.y * 255.f;
		float az = globals::ui::accent.z * 255.f;

		float fh       = ImGui::GetFontSize();
		float fade_in  = std::min(t / 0.4f, 1.f);
		float fade_out = t > 1.4f ? std::max(0.f, 1.f - (t - 1.4f) / 0.6f) : 1.f;
		float base_a   = fade_in * fade_out;

		const char* letters[4]  = { "A", "I", "D", "A" };
		float       tracking    = 22.f;
		float chars_w = 0.f;
		for (int li = 0; li < 4; li++) chars_w += ImGui::CalcTextSize(letters[li]).x;
		float title_total_w = chars_w + tracking * 3.f;
		float title_x0      = cx - title_total_w * 0.5f;
		float title_y       = cy - fh * 0.5f - 24.f;

		float rule_x0 = 0.f, rule_x1 = 0.f;
		float cur_x   = title_x0;
		for (int li = 0; li < 4; li++)
		{
			float la   = std::min(std::max(t - li * 0.12f, 0.f) / 0.35f, 1.f) * base_a;
			ImVec2 lts = ImGui::CalcTextSize(letters[li]);

			if (li == 0) rule_x0 = cur_x;
			dl->AddText(ImVec2(cur_x, title_y),
				IM_COL32(238, 235, 255, (int)(250 * la)), letters[li]);
			cur_x += lts.x;
			if (li == 3) rule_x1 = cur_x;
			cur_x += tracking;
		}


		float rule_t  = sqrtf(std::min(std::max(t - 0.2f, 0.f) / 0.42f, 1.f));
		float rule_y  = title_y + fh + 5.f;
		float rule_cx = (rule_x0 + rule_x1) * 0.5f;
		float rule_hw = ((rule_x1 - rule_x0) * 0.5f + 3.f) * rule_t;
		if (rule_hw > 0.5f)
			dl->AddLine(ImVec2(rule_cx - rule_hw, rule_y), ImVec2(rule_cx + rule_hw, rule_y),
				IM_COL32((int)ax, (int)ay, (int)az, (int)(220 * base_a)), 1.f);


		float sub_a = std::min(std::max(t - 0.45f, 0.f) / 0.45f, 1.f) * fade_out;
		if (sub_a > 0.01f)
		{
			const char* subtitle = "Artificial Intelligence Disassembly Assistant";
			ImVec2 sub_ts = ImGui::CalcTextSize(subtitle);
			dl->AddText(ImVec2(cx - sub_ts.x * 0.5f, rule_y + 8.f),
				IM_COL32(148, 143, 188, (int)(180 * sub_a)), subtitle);

			float msg_a = std::min(std::max(t - 0.9f, 0.f) / 0.4f, 1.f) * fade_out;
			if (msg_a > 0.01f)
			{
				const char* msg = "Your session is ready.";
				ImVec2 msg_ts = ImGui::CalcTextSize(msg);
				dl->AddText(ImVec2(cx - msg_ts.x * 0.5f, rule_y + 8.f + sub_ts.y + 12.f),
					IM_COL32(95, 90, 128, (int)(140 * msg_a)), msg);
			}
		}

		ImGui::End();
		return;
	}


	if (!license::validated)
	{
		static float license_alpha = 0.f;
		license_alpha += (1.f - license_alpha) * std::min(6.f * dt, 1.f);

		ImVec2 wp   = ImGui::GetWindowPos();
		float  ww   = globals::ui::window_w;
		float  wh   = globals::ui::window_h;
		float  cx   = wp.x + ww * 0.5f;
		float  cy   = wp.y + wh * 0.5f;
		ImDrawList* dl = ImGui::GetWindowDrawList();

		float ax = globals::ui::accent.x * 255.f;
		float ay = globals::ui::accent.y * 255.f;
		float az = globals::ui::accent.z * 255.f;
		float la  = license_alpha;


		const char* title = "Enter License Key";
		ImVec2 title_ts = ImGui::CalcTextSize(title);
		dl->AddText(ImVec2(cx - title_ts.x * 0.5f, cy - 70.f),
			IM_COL32(230, 228, 255, (int)(240 * la)), title);


		float rule_hw = title_ts.x * 0.4f;
		dl->AddLine(ImVec2(cx - rule_hw, cy - 70.f + title_ts.y + 4.f),
			ImVec2(cx + rule_hw, cy - 70.f + title_ts.y + 4.f),
			IM_COL32((int)ax, (int)ay, (int)az, (int)(180 * la)), 1.f);


		float input_w = 280.f;
		float input_h = 28.f;
		float input_x = (ww - input_w) * 0.5f;
		float input_y_rel = wh * 0.5f - 30.f;

		ImGui::SetCursorPos(ImVec2(input_x, input_y_rel));
		ImGui::PushStyleColor(ImGuiCol_FrameBg,   ImVec4(0.08f, 0.08f, 0.12f, 0.9f * la));
		ImGui::PushStyleColor(ImGuiCol_Border,     ImVec4(1, 1, 1, 0.1f * la));
		ImGui::PushStyleColor(ImGuiCol_Text,       ImVec4(0.92f, 0.91f, 1.f, la));
		ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 6.f);
		ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(10.f, 6.f));
		ImGui::PushItemWidth(input_w);

		if (ImGui::GetFrameCount() < 5)
			ImGui::SetKeyboardFocusHere();

		bool enter = ImGui::InputText("##license_key", license::key_buf, sizeof(license::key_buf),
			ImGuiInputTextFlags_EnterReturnsTrue | ImGuiInputTextFlags_Password);

		ImGui::PopItemWidth();
		ImGui::PopStyleVar(2);
		ImGui::PopStyleColor(3);


		if (license::key_buf[0] == '\0' && !ImGui::IsItemActive()) {
			ImVec2 ip = ImGui::GetItemRectMin();
			dl->AddText(ImVec2(ip.x + 10.f, ip.y + 6.f),
				IM_COL32(110, 105, 145, (int)(140 * la)), "XXXX-XXXX-XXXX-XXXX");
		}


		float btn_w = 120.f;
		float btn_h = 28.f;
		float btn_x = (ww - btn_w) * 0.5f;
		float btn_y_rel = input_y_rel + input_h + 14.f;

		ImGui::SetCursorPos(ImVec2(btn_x, btn_y_rel));
		ImVec2 btn_min = ImGui::GetCursorScreenPos();
		ImVec2 btn_max(btn_min.x + btn_w, btn_min.y + btn_h);

		bool btn_hov = ImGui::IsMouseHoveringRect(btn_min, btn_max);
		static float btn_ht = 0.f;
		btn_ht += ((btn_hov ? 1.f : 0.f) - btn_ht) * std::min(10.f * dt, 1.f);

		ImU32 btn_bg = IM_COL32(
			(int)(ax * 0.25f + 20), (int)(ay * 0.25f + 15), (int)(az * 0.25f + 30),
			(int)((180 + 40 * btn_ht) * la));
		dl->AddRectFilled(btn_min, btn_max, btn_bg, 6.f);
		if (btn_ht > 0.01f)
			dl->AddRect(btn_min, btn_max, IM_COL32((int)ax, (int)ay, (int)az, (int)(60 * btn_ht * la)), 6.f);

		const char* btn_label = license::checking ? "Checking..." : "Activate";
		ImVec2 btn_ts = ImGui::CalcTextSize(btn_label);
		dl->AddText(ImVec2(btn_min.x + (btn_w - btn_ts.x) * 0.5f, btn_min.y + (btn_h - btn_ts.y) * 0.5f),
			IM_COL32(230, 228, 255, (int)(240 * la)), btn_label);

		ImGui::InvisibleButton("##activate_btn", ImVec2(btn_w, btn_h));
		bool btn_clicked = ImGui::IsItemClicked();

		if ((enter || btn_clicked) && !license::checking && strlen(license::key_buf) > 0)
		{
			license::checking    = true;
			license::check_failed = false;
			license::error_msg.clear();

			std::string key_copy(license::key_buf);
			std::thread([key_copy]() {
				std::string error_text;
				if (standalone_license::activate(g_sa_settings, key_copy, error_text)) {
					license::saved_key  = key_copy;
					license::validated  = true;
					license::checking   = false;
					license::error_msg.clear();
				} else {
					license::error_msg   = error_text.empty() ? "License validation failed." : error_text;
					license::check_failed = true;
					license::checking    = false;
				}
			}).detach();
		}


		if (license::check_failed && !license::error_msg.empty())
		{
			ImVec2 err_ts = ImGui::CalcTextSize(license::error_msg.c_str());
			dl->AddText(ImVec2(cx - err_ts.x * 0.5f, wp.y + btn_y_rel + btn_h + 14.f),
				IM_COL32(220, 80, 80, (int)(220 * la)), license::error_msg.c_str());
		}


		{
			static POINT lic_drag_wnd = {};
			static POINT lic_drag_mouse = {};
			static bool  lic_dragging = false;
			static bool  lic_last_lmb = false;
			bool lmb = GetAsyncKeyState(VK_LBUTTON) & 0x8000;
			if (lmb && !lic_last_lmb) {
				POINT cp; GetCursorPos(&cp);
				RECT wr; GetWindowRect(g_hwnd, &wr);

				int local_y = cp.y - wr.top;
				if (cp.x >= wr.left && cp.x <= wr.right && cp.y >= wr.top && cp.y <= wr.bottom && local_y < (wr.bottom - wr.top) / 2) {
					lic_dragging = true;
					lic_drag_mouse = cp;
					lic_drag_wnd = { wr.left, wr.top };
				}
			}
			if (!lmb) lic_dragging = false;
			if (lic_dragging) {
				POINT cp; GetCursorPos(&cp);
				int nx = lic_drag_wnd.x + (cp.x - lic_drag_mouse.x);
				int ny = lic_drag_wnd.y + (cp.y - lic_drag_mouse.y);
				SetWindowPos(g_hwnd, nullptr, nx, ny, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
			}
			lic_last_lmb = lmb;
		}

		ImGui::End();
		return;
	}


	float a = globals::ui::ui_alpha;


	const float pad      = 6.f;
	const float gap      = 4.f;
	const float title_h  = 28.f;
	float ww = globals::ui::window_w;
	float wh = globals::ui::window_h;


	float usable = ww - pad * 2.f - gap * 2.f;
	float min_panel = 80.f;
	float max_left  = usable * 0.3f;
	float max_right = usable * 0.4f;
	float left_w   = globals::ui::panel_left_w;
	float right_w  = globals::ui::panel_right_w;
	float center_w = usable - left_w - right_w;
	if (center_w < 200.f) {

		float excess = 200.f - center_w;
		float total_panels = left_w + right_w;
		if (total_panels > 0.f) {
			left_w  -= excess * (left_w / total_panels);
			right_w -= excess * (right_w / total_panels);
		}
		center_w = 200.f;
	}
	if (left_w  < min_panel) left_w  = min_panel;
	if (right_w < min_panel) right_w = min_panel;
	globals::ui::panel_left_w  = left_w;
	globals::ui::panel_right_w = right_w;
	center_w = usable - left_w - right_w;
	if (center_w < 100.f) center_w = 100.f;
	float total_h  = wh - pad * 2.f - title_h;

	ImGui::PushStyleVar(ImGuiStyleVar_Alpha, a);


	{
		ImVec2 wp   = ImGui::GetWindowPos();
		ImDrawList* dl = ImGui::GetWindowDrawList();
		float ax = globals::ui::accent.x * 255.f;
		float ay = globals::ui::accent.y * 255.f;
		float az = globals::ui::accent.z * 255.f;


		auto& th_tb = themes::resolved;
		dl->AddRectFilled(ImVec2(wp.x, wp.y), ImVec2(wp.x + ww, wp.y + title_h),
			th_tb.title_bar, 8.f, ImDrawFlags_RoundCornersTop);
		dl->AddLine(ImVec2(wp.x, wp.y + title_h), ImVec2(wp.x + ww, wp.y + title_h),
			IM_COL32(255, 255, 255, (int)(8 * a)));


		const char* app_name = "AiDA Standalone";
		ImVec2 name_ts = ImGui::CalcTextSize(app_name);
		dl->AddText(ImVec2(wp.x + 12.f, wp.y + (title_h - name_ts.y) * 0.5f),
			IM_COL32((int)(ax * 0.6f + 100), (int)(ay * 0.6f + 100), (int)(az * 0.6f + 100), (int)(220 * a)),
			app_name);


		float close_sz = 14.f;
		ImVec2 close_pos(wp.x + ww - close_sz - 10.f, wp.y + (title_h - close_sz) * 0.5f);
		ImVec2 close_max(close_pos.x + close_sz, close_pos.y + close_sz);
		bool close_hov = ImGui::IsMouseHoveringRect(close_pos, close_max);
		if (close_hov) {
			dl->AddRectFilled(close_pos, close_max, IM_COL32(200, 60, 60, (int)(120 * a)), 3.f);
			if (ImGui::IsMouseClicked(ImGuiMouseButton_Left))
				DestroyWindow(g_hwnd);
		}
		ImVec2 xc(close_pos.x + close_sz * 0.5f, close_pos.y + close_sz * 0.5f);
		float xr = 4.f;
		dl->AddLine(ImVec2(xc.x - xr, xc.y - xr), ImVec2(xc.x + xr, xc.y + xr),
			IM_COL32(200, 200, 210, (int)(180 * a)), 1.5f);
		dl->AddLine(ImVec2(xc.x + xr, xc.y - xr), ImVec2(xc.x - xr, xc.y + xr),
			IM_COL32(200, 200, 210, (int)(180 * a)), 1.5f);


		ImVec2 max_pos(close_pos.x - close_sz - 8.f, close_pos.y);
		ImVec2 max_max(max_pos.x + close_sz, max_pos.y + close_sz);
		bool max_hov = ImGui::IsMouseHoveringRect(max_pos, max_max);
		if (max_hov) {
			dl->AddRectFilled(max_pos, max_max, IM_COL32(255, 255, 255, (int)(30 * a)), 3.f);
			if (ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
				if (globals::ui::maximized) {

					globals::ui::maximized = false;
					globals::ui::window_w = globals::ui::pre_max_w;
					globals::ui::window_h = globals::ui::pre_max_h;
					SetWindowPos(g_hwnd, nullptr,
						(int)globals::ui::pre_max_x, (int)globals::ui::pre_max_y,
						(int)globals::ui::pre_max_w, (int)globals::ui::pre_max_h,
						SWP_NOZORDER);
				} else {

					RECT wr; GetWindowRect(g_hwnd, &wr);
					globals::ui::pre_max_x = (float)wr.left;
					globals::ui::pre_max_y = (float)wr.top;
					globals::ui::pre_max_w = globals::ui::window_w;
					globals::ui::pre_max_h = globals::ui::window_h;
					globals::ui::maximized = true;
					MONITORINFO mi = { sizeof(mi) };
					GetMonitorInfoW(MonitorFromWindow(g_hwnd, MONITOR_DEFAULTTONEAREST), &mi);
					float mw = (float)(mi.rcWork.right - mi.rcWork.left);
					float mh = (float)(mi.rcWork.bottom - mi.rcWork.top);
					globals::ui::window_w = mw;
					globals::ui::window_h = mh;
					SetWindowPos(g_hwnd, nullptr,
						mi.rcWork.left, mi.rcWork.top, (int)mw, (int)mh,
						SWP_NOZORDER);
				}
			}
		}
		if (globals::ui::maximized) {

			float ir = 3.5f;
			ImVec2 mc(max_pos.x + close_sz * 0.5f, max_pos.y + close_sz * 0.5f);
			dl->AddRect(ImVec2(mc.x - ir, mc.y - ir + 1.5f), ImVec2(mc.x + ir - 1.5f, mc.y + ir),
				IM_COL32(200, 200, 210, (int)(180 * a)), 0.f, 0, 1.2f);
			dl->AddRect(ImVec2(mc.x - ir + 1.5f, mc.y - ir), ImVec2(mc.x + ir, mc.y + ir - 1.5f),
				IM_COL32(200, 200, 210, (int)(180 * a)), 0.f, 0, 1.2f);
		} else {

			float ir = 3.5f;
			ImVec2 mc(max_pos.x + close_sz * 0.5f, max_pos.y + close_sz * 0.5f);
			dl->AddRect(ImVec2(mc.x - ir, mc.y - ir), ImVec2(mc.x + ir, mc.y + ir),
				IM_COL32(200, 200, 210, (int)(180 * a)), 0.f, 0, 1.2f);
		}


		ImVec2 min_pos(max_pos.x - close_sz - 8.f, max_pos.y);
		ImVec2 min_max(min_pos.x + close_sz, min_pos.y + close_sz);
		bool min_hov = ImGui::IsMouseHoveringRect(min_pos, min_max);
		if (min_hov) {
			dl->AddRectFilled(min_pos, min_max, IM_COL32(255, 255, 255, (int)(30 * a)), 3.f);
			if (ImGui::IsMouseClicked(ImGuiMouseButton_Left))
				ShowWindow(g_hwnd, SW_MINIMIZE);
		}
		dl->AddLine(ImVec2(min_pos.x + 3.f, min_pos.y + close_sz * 0.5f),
			ImVec2(min_max.x - 3.f, min_pos.y + close_sz * 0.5f),
			IM_COL32(200, 200, 210, (int)(180 * a)), 1.5f);


		{
			static bool theme_popup_open = false;
			float theme_btn_sz = close_sz;
			ImVec2 th_pos(min_pos.x - theme_btn_sz - 8.f, min_pos.y);
			ImVec2 th_max(th_pos.x + theme_btn_sz, th_pos.y + theme_btn_sz);
			bool th_hov = ImGui::IsMouseHoveringRect(th_pos, th_max);
			if (th_hov) {
				dl->AddRectFilled(th_pos, th_max, IM_COL32(255, 255, 255, (int)(30 * a)), 3.f);
				if (ImGui::IsMouseClicked(ImGuiMouseButton_Left))
					theme_popup_open = !theme_popup_open;
			}

			float dot_r = 2.5f;
			float dot_cx = th_pos.x + theme_btn_sz * 0.5f;
			float dot_cy = th_pos.y + theme_btn_sz * 0.5f;
			dl->AddCircleFilled(ImVec2(dot_cx - 4.f, dot_cy), dot_r,
				IM_COL32((int)(ax*255), (int)(ay*255), (int)(az*255), (int)(200*a)));
			dl->AddCircleFilled(ImVec2(dot_cx, dot_cy), dot_r,
				IM_COL32(200, 200, 200, (int)(180*a)));
			dl->AddCircleFilled(ImVec2(dot_cx + 4.f, dot_cy), dot_r,
				IM_COL32(120, 200, 160, (int)(180*a)));

			if (theme_popup_open) {
				ImGui::SetNextWindowPos(ImVec2(th_pos.x - 100.f, wp.y + title_h + 2.f));
				ImGui::SetNextWindowBgAlpha(0.96f);
				ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 8.f);
				ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(8.f, 8.f));
				ImGui::PushStyleColor(ImGuiCol_PopupBg, ImVec4(0.07f, 0.07f, 0.10f, 1.f));
				ImGui::PushStyleColor(ImGuiCol_Border, ImVec4(1, 1, 1, 0.08f));

				if (ImGui::Begin("##theme_popup", &theme_popup_open,
					ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
					ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_NoSavedSettings))
				{
					ImDrawList* pdl = ImGui::GetWindowDrawList();
					float item_w = 200.f;
					float item_h = 22.f;


					ImGui::TextColored(ImVec4(0.6f, 0.58f, 0.75f, 1.f), "Built-in Themes");
					ImGui::Spacing();
					for (int ti = 0; ti < themes::count; ti++) {
						auto& tp = themes::presets[ti];
						bool is_active = (custom_themes::active_custom < 0 && themes::active == ti);

						ImVec2 cp = ImGui::GetCursorScreenPos();
						ImVec2 rmin = cp;
						ImVec2 rmax(cp.x + item_w, cp.y + item_h);

						bool ti_hov = ImGui::IsMouseHoveringRect(rmin, rmax);
						if (ti_hov) pdl->AddRectFilled(rmin, rmax, IM_COL32(255, 255, 255, 14), 4.f);
						if (is_active) pdl->AddRectFilled(rmin, rmax, IM_COL32(255, 255, 255, 8), 4.f);

						pdl->AddCircleFilled(
							ImVec2(cp.x + 10.f, cp.y + item_h * 0.5f), 4.f,
							IM_COL32((int)(tp.accent.x*255), (int)(tp.accent.y*255),
								(int)(tp.accent.z*255), 255));

						ImU32 name_col = is_active
							? IM_COL32((int)(ax*255), (int)(ay*255), (int)(az*255), 255)
							: IM_COL32(200, 200, 210, 220);
						pdl->AddText(ImVec2(cp.x + 24.f, cp.y + (item_h - ImGui::GetFontSize()) * 0.5f),
							name_col, tp.name);

						ImGui::Dummy(ImVec2(item_w, item_h));
						if (ti_hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
							themes::active = ti;
							custom_themes::active_custom = -1;
							themes::changed = true;
							g_sa_settings.active_theme_idx = ti;
							g_sa_settings.active_custom_theme_idx = -1;
							g_sa_settings.save();
						}
					}


					if (!custom_themes::list.empty()) {
						ImGui::Dummy(ImVec2(0, 4));
						ImGui::Separator();
						ImGui::Dummy(ImVec2(0, 2));
						ImGui::TextColored(ImVec4(0.6f, 0.58f, 0.75f, 1.f), "Custom Themes");
						ImGui::Spacing();
						for (int ci = 0; ci < (int)custom_themes::list.size(); ci++) {
							auto& ct = custom_themes::list[ci];
							bool is_active = (custom_themes::active_custom == ci);

							ImVec2 cp = ImGui::GetCursorScreenPos();
							ImVec2 rmin = cp;
							ImVec2 rmax(cp.x + item_w, cp.y + item_h);

							bool ci_hov = ImGui::IsMouseHoveringRect(rmin, rmax);
							if (ci_hov) pdl->AddRectFilled(rmin, rmax, IM_COL32(255, 255, 255, 14), 4.f);
							if (is_active) pdl->AddRectFilled(rmin, rmax, IM_COL32(255, 255, 255, 8), 4.f);

							pdl->AddCircleFilled(
								ImVec2(cp.x + 10.f, cp.y + item_h * 0.5f), 4.f,
								IM_COL32((int)(ct.accent[0]*255), (int)(ct.accent[1]*255),
									(int)(ct.accent[2]*255), 255));

							ImU32 nc = is_active
								? IM_COL32((int)(ax*255), (int)(ay*255), (int)(az*255), 255)
								: IM_COL32(200, 200, 210, 220);
							pdl->AddText(ImVec2(cp.x + 24.f, cp.y + (item_h - ImGui::GetFontSize()) * 0.5f),
								nc, ct.name.c_str());


							float edit_w = ImGui::CalcTextSize("Edit").x + 8.f;
							ImVec2 emin(cp.x + item_w - edit_w - 4.f, cp.y + 2.f);
							ImVec2 emax(emin.x + edit_w, cp.y + item_h - 2.f);
							bool ehov = ImGui::IsMouseHoveringRect(emin, emax);
							if (ehov) pdl->AddRectFilled(emin, emax, IM_COL32(255, 255, 255, 20), 3.f);
							pdl->AddText(ImVec2(emin.x + 4.f, emin.y + 1.f),
								IM_COL32(160, 160, 180, ehov ? 255 : 160), "Edit");
							if (ehov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
								custom_themes::editing_idx = ci;
								custom_themes::editing_copy = ct;
								custom_themes::editor_open = true;
							}

							ImGui::Dummy(ImVec2(item_w, item_h));
							if (ci_hov && !ehov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
								custom_themes::active_custom = ci;
								themes::changed = true;
								g_sa_settings.active_custom_theme_idx = ci;
								g_sa_settings.save();
							}
						}
					}


					ImGui::Dummy(ImVec2(0, 4));
					ImGui::Separator();
					ImGui::Dummy(ImVec2(0, 2));


					{
						ImVec2 cp = ImGui::GetCursorScreenPos();
						ImVec2 rmin = cp;
						ImVec2 rmax(cp.x + item_w, cp.y + item_h);
						bool hov = ImGui::IsMouseHoveringRect(rmin, rmax);
						if (hov) pdl->AddRectFilled(rmin, rmax, IM_COL32(255, 255, 255, 14), 4.f);
						pdl->AddText(ImVec2(cp.x + 8.f, cp.y + (item_h - ImGui::GetFontSize()) * 0.5f),
							IM_COL32(100, 220, 140, hov ? 255 : 200), "+ Create New Theme");
						ImGui::Dummy(ImVec2(item_w, item_h));
						if (hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
							custom_themes::editing_idx = -1;
							custom_themes::editing_copy = CustomThemeData{};
							custom_themes::editing_copy.name = "My Theme " + std::to_string(custom_themes::list.size() + 1);
							custom_themes::editor_open = true;
						}
					}


					{
						ImVec2 cp = ImGui::GetCursorScreenPos();
						ImVec2 rmin = cp;
						ImVec2 rmax(cp.x + item_w, cp.y + item_h);
						bool hov = ImGui::IsMouseHoveringRect(rmin, rmax);
						if (hov) pdl->AddRectFilled(rmin, rmax, IM_COL32(255, 255, 255, 14), 4.f);
						pdl->AddText(ImVec2(cp.x + 8.f, cp.y + (item_h - ImGui::GetFontSize()) * 0.5f),
							IM_COL32(140, 180, 220, hov ? 255 : 200), "Import Theme...");
						ImGui::Dummy(ImVec2(item_w, item_h));
						if (hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
							char buf[MAX_PATH] = {};
							OPENFILENAMEA ofn = {};
							ofn.lStructSize = sizeof(ofn);
							ofn.hwndOwner = g_hwnd;
							ofn.lpstrFile = buf;
							ofn.nMaxFile = MAX_PATH;
							ofn.lpstrFilter = "AiDA Theme (*.json)\0*.json\0All Files\0*.*\0\0";
							ofn.nFilterIndex = 1;
							ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_NOCHANGEDIR;
							if (GetOpenFileNameA(&ofn)) {
								std::ifstream ifs(buf);
								if (ifs.is_open()) {
									try {
										nlohmann::json j;
										ifs >> j;
										CustomThemeData ct;
										ct.name = j.value("name", "Imported Theme");
										if (j.contains("accent") && j["accent"].is_array() && j["accent"].size() >= 3) {
											ct.accent[0] = j["accent"][0].get<float>();
											ct.accent[1] = j["accent"][1].get<float>();
											ct.accent[2] = j["accent"][2].get<float>();
										}
										ct.bg_base       = j.value("bg_base", (uint32_t)ct.bg_base);
										ct.panel_bg      = j.value("panel_bg", (uint32_t)ct.panel_bg);
										ct.panel_header  = j.value("panel_header", (uint32_t)ct.panel_header);
										ct.title_bar     = j.value("title_bar", (uint32_t)ct.title_bar);
										ct.text_primary  = j.value("text_primary", (uint32_t)ct.text_primary);
										ct.text_secondary= j.value("text_secondary", (uint32_t)ct.text_secondary);
										ct.text_dim      = j.value("text_dim", (uint32_t)ct.text_dim);
										ct.acrylic_color = j.value("acrylic_color", (DWORD)ct.acrylic_color);
										ct.icon_index    = j.value("icon_index", ct.icon_index);
										ct.icon_file_path= j.value("icon_file_path", std::string{});
										custom_themes::list.push_back(std::move(ct));
									} catch (...) {}
								}
							}
						}
					}
				}
				ImGui::End();
				ImGui::PopStyleColor(2);
				ImGui::PopStyleVar(2);

				if (!ImGui::IsWindowHovered(ImGuiHoveredFlags_AnyWindow) && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
					theme_popup_open = false;
			}


			if (custom_themes::editor_open) {
				float ew = 380.f, eh = 520.f;
				ImGui::SetNextWindowPos(ImVec2((ww - ew) * 0.5f, (globals::ui::window_h - eh) * 0.5f), ImGuiCond_Appearing);
				ImGui::SetNextWindowSize(ImVec2(ew, eh));
				ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 10.f);
				ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(14.f, 12.f));
				ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 6.f);
				ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(8.f, 5.f));
				ImGui::PushStyleColor(ImGuiCol_WindowBg, ImVec4(0.08f, 0.08f, 0.11f, 0.98f));
				ImGui::PushStyleColor(ImGuiCol_Border, ImVec4(1, 1, 1, 0.08f));
				ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0.12f, 0.12f, 0.16f, 1.f));
				ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.88f, 0.87f, 0.94f, 1.f));

				if (ImGui::Begin("##theme_editor", &custom_themes::editor_open,
					ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
					ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoCollapse))
				{
					auto& ed = custom_themes::editing_copy;
					float iw2 = ew - 28.f;

					ImGui::TextColored(ImVec4(ax, ay, az, 1.f),
						custom_themes::editing_idx < 0 ? "Create Theme" : "Edit Theme");
					ImGui::Dummy(ImVec2(0, 4));


					static char name_buf[128] = {};
					static bool name_init = false;
					if (!name_init || custom_themes::editing_idx != custom_themes::editing_idx) {
						snprintf(name_buf, sizeof(name_buf), "%s", ed.name.c_str());
						name_init = true;
					}
					ImGui::Text("Name");
					ImGui::SetNextItemWidth(iw2);
					if (ImGui::InputText("##te_name", name_buf, sizeof(name_buf)))
						ed.name = name_buf;


					ImGui::Text("Accent Color");
					ImGui::SetNextItemWidth(iw2);
					ImGui::ColorEdit3("##te_accent", ed.accent, ImGuiColorEditFlags_NoInputs | ImGuiColorEditFlags_NoLabel);


					auto u32_edit = [&](const char* label, const char* id, ImU32& col) {
						ImGui::Text("%s", label);
						float c[4];
						c[0] = (float)((col >> 0) & 0xFF) / 255.f;
						c[1] = (float)((col >> 8) & 0xFF) / 255.f;
						c[2] = (float)((col >> 16) & 0xFF) / 255.f;
						c[3] = (float)((col >> 24) & 0xFF) / 255.f;
						ImGui::SetNextItemWidth(iw2);
						if (ImGui::ColorEdit4(id, c, ImGuiColorEditFlags_AlphaBar))
							col = IM_COL32((int)(c[0]*255), (int)(c[1]*255), (int)(c[2]*255), (int)(c[3]*255));
					};
					u32_edit("Background", "##te_bg", ed.bg_base);
					u32_edit("Panel Background", "##te_pbg", ed.panel_bg);
					u32_edit("Panel Header", "##te_phdr", ed.panel_header);
					u32_edit("Title Bar", "##te_tb", ed.title_bar);


					ImGui::Text("Theme Icon");
					ImGui::SetNextItemWidth(iw2);
					const char* icon_names[] = {"Kaneki", "Rias", "Nagi", "Mio Akiyama", "Custom File..."};
					int icon_sel = ed.icon_index >= 0 ? ed.icon_index : 4;
					if (ImGui::Combo("##te_icon", &icon_sel, icon_names, 5)) {
						if (icon_sel < 4) {
							ed.icon_index = icon_sel;
							ed.icon_file_path.clear();
						} else {
							char icon_buf[MAX_PATH] = {};
							OPENFILENAMEA ofn2 = {};
							ofn2.lStructSize = sizeof(ofn2);
							ofn2.hwndOwner = g_hwnd;
							ofn2.lpstrFile = icon_buf;
							ofn2.nMaxFile = MAX_PATH;
							ofn2.lpstrFilter = "Images\0*.png;*.jpg;*.jpeg;*.bmp\0All Files\0*.*\0\0";
							ofn2.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_NOCHANGEDIR;
							if (GetOpenFileNameA(&ofn2)) {
								ed.icon_index = -1;
								ed.icon_file_path = icon_buf;
							}
						}
					}
					if (!ed.icon_file_path.empty()) {
						ImGui::TextColored(ImVec4(0.5f, 0.7f, 0.5f, 1.f), "File: %s",
							ed.icon_file_path.substr(ed.icon_file_path.find_last_of("\\/") + 1).c_str());
					}

					ImGui::Dummy(ImVec2(0, 8));


					float btn_w2 = 70.f;
					if (ImGui::Button("Save", ImVec2(btn_w2, 26))) {
						ed.name = name_buf;
						if (custom_themes::editing_idx >= 0 &&
						    custom_themes::editing_idx < (int)custom_themes::list.size()) {
							custom_themes::list[custom_themes::editing_idx] = ed;
						} else {
							custom_themes::list.push_back(ed);
							custom_themes::editing_idx = (int)custom_themes::list.size() - 1;
						}
						custom_themes::active_custom = custom_themes::editing_idx;
						themes::changed = true;
						custom_themes::editor_open = false;
						name_init = false;


						nlohmann::json arr = nlohmann::json::array();
						for (auto& ct2 : custom_themes::list) {
							nlohmann::json jt;
							jt["name"] = ct2.name;
							jt["accent"] = { ct2.accent[0], ct2.accent[1], ct2.accent[2] };
							jt["bg_base"] = (uint32_t)ct2.bg_base;
							jt["panel_bg"] = (uint32_t)ct2.panel_bg;
							jt["panel_header"] = (uint32_t)ct2.panel_header;
							jt["title_bar"] = (uint32_t)ct2.title_bar;
							jt["text_primary"] = (uint32_t)ct2.text_primary;
							jt["text_secondary"] = (uint32_t)ct2.text_secondary;
							jt["text_dim"] = (uint32_t)ct2.text_dim;
							jt["acrylic_color"] = (uint32_t)ct2.acrylic_color;
							jt["icon_index"] = ct2.icon_index;
							jt["icon_file_path"] = ct2.icon_file_path;
							arr.push_back(jt);
						}
						g_sa_settings.custom_themes_json = arr.dump();
						g_sa_settings.active_custom_theme_idx = custom_themes::active_custom;
						g_sa_settings.save();
					}
					ImGui::SameLine();


					if (ImGui::Button("Export", ImVec2(btn_w2, 26))) {
						char export_buf[MAX_PATH] = {};
						snprintf(export_buf, sizeof(export_buf), "%s.json", name_buf);
						OPENFILENAMEA sfn = {};
						sfn.lStructSize = sizeof(sfn);
						sfn.hwndOwner = g_hwnd;
						sfn.lpstrFile = export_buf;
						sfn.nMaxFile = MAX_PATH;
						sfn.lpstrFilter = "AiDA Theme (*.json)\0*.json\0\0";
						sfn.lpstrDefExt = "json";
						sfn.Flags = OFN_OVERWRITEPROMPT | OFN_NOCHANGEDIR;
						if (GetSaveFileNameA(&sfn)) {
							nlohmann::json jt;
							jt["name"] = std::string(name_buf);
							jt["accent"] = { ed.accent[0], ed.accent[1], ed.accent[2] };
							jt["bg_base"] = (uint32_t)ed.bg_base;
							jt["panel_bg"] = (uint32_t)ed.panel_bg;
							jt["panel_header"] = (uint32_t)ed.panel_header;
							jt["title_bar"] = (uint32_t)ed.title_bar;
							jt["text_primary"] = (uint32_t)ed.text_primary;
							jt["text_secondary"] = (uint32_t)ed.text_secondary;
							jt["text_dim"] = (uint32_t)ed.text_dim;
							jt["acrylic_color"] = (uint32_t)ed.acrylic_color;
							jt["icon_index"] = ed.icon_index;
							std::ofstream ofs(export_buf, std::ios::trunc);
							if (ofs.is_open()) ofs << jt.dump(2);
						}
					}
					ImGui::SameLine();


					if (custom_themes::editing_idx >= 0) {
						ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.5f, 0.1f, 0.1f, 0.7f));
						ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.7f, 0.15f, 0.15f, 0.9f));
						if (ImGui::Button("Delete", ImVec2(btn_w2, 26))) {
							int idx = custom_themes::editing_idx;
							custom_themes::list.erase(custom_themes::list.begin() + idx);
							if (custom_themes::active_custom == idx) custom_themes::active_custom = -1;
							else if (custom_themes::active_custom > idx) custom_themes::active_custom--;
							themes::changed = true;
							custom_themes::editor_open = false;
							name_init = false;
						}
						ImGui::PopStyleColor(2);
						ImGui::SameLine();
					}

					ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.22f, 0.22f, 0.28f, 0.8f));
					if (ImGui::Button("Cancel", ImVec2(btn_w2, 26))) {
						custom_themes::editor_open = false;
						name_init = false;
					}
					ImGui::PopStyleColor();
				}
				ImGui::End();
				ImGui::PopStyleColor(4);
				ImGui::PopStyleVar(4);
			}
		}

		{
			static POINT tb_drag_wnd = {};
			static POINT tb_drag_mouse = {};
			static bool  tb_dragging = false;
			static bool  tb_last_lmb = false;
			bool lmb = GetAsyncKeyState(VK_LBUTTON) & 0x8000;
			if (lmb && !tb_last_lmb) {
				POINT cp; GetCursorPos(&cp);
				RECT wr; GetWindowRect(g_hwnd, &wr);
				int local_y = cp.y - wr.top;
				int local_x = cp.x - wr.left;

				if (local_y >= 0 && local_y < (int)title_h && local_x >= 0 && local_x < (int)(ww - 140.f)
					&& !globals::ui::dragging_left_splitter && !globals::ui::dragging_right_splitter) {
					tb_dragging = true;
					tb_drag_mouse = cp;
					tb_drag_wnd = { wr.left, wr.top };
				}
			}
			if (!lmb) tb_dragging = false;
			if (tb_dragging) {
				POINT cp; GetCursorPos(&cp);
				int nx = tb_drag_wnd.x + (cp.x - tb_drag_mouse.x);
				int ny = tb_drag_wnd.y + (cp.y - tb_drag_mouse.y);
				SetWindowPos(g_hwnd, nullptr, nx, ny, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
			}
			tb_last_lmb = lmb;
		}
	}


	{
		ImVec2 wp = ImGui::GetWindowPos();
		float  sp_w = 5.f;


		float ls_x = wp.x + pad + left_w;
		ImVec2 ls_min(ls_x - sp_w * 0.5f, wp.y + title_h + pad);
		ImVec2 ls_max(ls_x + sp_w * 0.5f + gap, wp.y + title_h + pad + total_h);

		bool ls_hov = ImGui::IsMouseHoveringRect(ls_min, ls_max);
		if (ls_hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
			globals::ui::dragging_left_splitter = true;
		if (!ImGui::IsMouseDown(ImGuiMouseButton_Left))
			globals::ui::dragging_left_splitter = false;
		if (globals::ui::dragging_left_splitter) {
			float mx = ImGui::GetIO().MousePos.x - wp.x - pad;
			globals::ui::panel_left_w = std::clamp(mx, min_panel, max_left);
			if (ls_hov || globals::ui::dragging_left_splitter)
				ImGui::SetMouseCursor(ImGuiMouseCursor_ResizeEW);
		}
		if (ls_hov) ImGui::SetMouseCursor(ImGuiMouseCursor_ResizeEW);


		float rs_x = wp.x + ww - pad - right_w;
		ImVec2 rs_min(rs_x - sp_w * 0.5f - gap, wp.y + title_h + pad);
		ImVec2 rs_max(rs_x + sp_w * 0.5f, wp.y + title_h + pad + total_h);

		bool rs_hov = ImGui::IsMouseHoveringRect(rs_min, rs_max);
		if (rs_hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
			globals::ui::dragging_right_splitter = true;
		if (!ImGui::IsMouseDown(ImGuiMouseButton_Left))
			globals::ui::dragging_right_splitter = false;
		if (globals::ui::dragging_right_splitter) {
			float mx = wp.x + ww - ImGui::GetIO().MousePos.x - pad;
			globals::ui::panel_right_w = std::clamp(mx, min_panel, max_right);
			if (rs_hov || globals::ui::dragging_right_splitter)
				ImGui::SetMouseCursor(ImGuiMouseCursor_ResizeEW);
		}
		if (rs_hov) ImGui::SetMouseCursor(ImGuiMouseCursor_ResizeEW);


		left_w   = globals::ui::panel_left_w;
		right_w  = globals::ui::panel_right_w;
		center_w = ww - left_w - right_w - pad * 2.f - gap * 2.f;
		if (center_w < 200.f) center_w = 200.f;
	}

	float ax3 = globals::ui::accent.x, ay3 = globals::ui::accent.y, az3 = globals::ui::accent.z;
	ImU32 ac_full = IM_COL32((int)(ax3*255),(int)(ay3*255),(int)(az3*255),(int)(255*a));
	ImU32 ac_dim  = IM_COL32((int)(ax3*255),(int)(ay3*255),(int)(az3*255),(int)(35*a));


	const float hdr_pad  = 10.f;
	const float row_h    = 22.f;
	const float row_gap  = 1.f;
	const float tb_vpad  = 8.f;
	const float hdr_h    = tb_vpad * 2.f + row_h * 2.f + row_gap;

	ImDrawList* wdl  = ImGui::GetWindowDrawList();
	ImVec2      wp_m = ImGui::GetWindowPos();


	float fb_x = pad;
	float fb_y = pad + title_h;
	ImGui::SetCursorPos(ImVec2(fb_x, fb_y));
	begin_child("##filebrowser", ImVec2(fb_x, fb_y), ImVec2(left_w, total_h), a);
	{
		ImDrawList* fdl = ImGui::GetWindowDrawList();
		ImVec2 fwp = ImGui::GetWindowPos();
		float fw = ImGui::GetWindowWidth();
		float fh = ImGui::GetWindowHeight();


		const char* explorer_lbl = "EXPLORER";
		ImVec2 elbl_ts = ImGui::CalcTextSize(explorer_lbl);
		fdl->AddText(ImVec2(fwp.x + 10.f, fwp.y + 8.f),
			IM_COL32(130, 128, 155, (int)(180 * a)), explorer_lbl);

		float tree_y = 28.f;
		ImGui::SetCursorPos(ImVec2(0.f, tree_y));
		ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.f, 0.f));
		ImGui::BeginChild("##fb_scroll", ImVec2(fw, fh - tree_y), false, ImGuiWindowFlags_NoBackground);
		{
			if (file_browser::needs_refresh || file_browser::entries.empty()) {
				file_browser::refresh();
			}

			for (int fi = 0; fi < (int)file_browser::entries.size(); fi++) {
				auto& ent = file_browser::entries[fi];
				float indent = ent.depth * 16.f + 6.f;
				float item_h = 20.f;
				ImVec2 cp = ImGui::GetCursorScreenPos();
				ImVec2 rmin(cp.x, cp.y);
				ImVec2 rmax(cp.x + fw, cp.y + item_h);
				bool hov = ImGui::IsMouseHoveringRect(rmin, rmax, false);
				bool sel = (fi == file_browser::selected_idx);

				if (sel) fdl->AddRectFilled(rmin, rmax, IM_COL32((int)(ax3*60), (int)(ay3*60), (int)(az3*60), (int)(80*a)));
				else if (hov) fdl->AddRectFilled(rmin, rmax, IM_COL32(255, 255, 255, (int)(12*a)));


				const char* icon = ent.is_dir ? (ent.expanded ? "v " : "> ") : "  ";
				ImU32 icon_col = ent.is_dir
					? IM_COL32((int)(ax3*180+60), (int)(ay3*180+60), (int)(az3*180+60), (int)(200*a))
					: IM_COL32(170, 175, 190, (int)(180*a));
				ImU32 text_col = ent.is_dir
					? IM_COL32(200, 198, 220, (int)(220*a))
					: IM_COL32(170, 175, 190, (int)(200*a));

				fdl->AddText(ImVec2(rmin.x + indent, rmin.y + 2.f), icon_col, icon);
				fdl->AddText(ImVec2(rmin.x + indent + ImGui::CalcTextSize(icon).x, rmin.y + 2.f), text_col, ent.name.c_str());

				ImGui::Dummy(ImVec2(fw, item_h));
				if (hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
					file_browser::selected_idx = fi;
					if (ent.is_dir)
						file_browser::toggle_dir(fi);
					else
						file_browser::open_file(fi);
				}
			}
		}
		ImGui::EndChild();
		ImGui::PopStyleVar();
	}
	end_child();


	float hx0 = wp_m.x + pad + left_w + gap, hy0 = wp_m.y + pad + title_h;
	float hx1  = hx0 + center_w;
	float hy1  = hy0 + hdr_h;
	float dc_y1 = wp_m.y + pad + title_h + total_h;

	auto& th_cp = themes::resolved;

	wdl->AddRectFilled(ImVec2(hx0, hy0), ImVec2(hx1, dc_y1),
		th_cp.panel_bg, 8.f);


	wdl->AddRectFilled(ImVec2(hx0, hy0), ImVec2(hx1, hy1),
		th_cp.panel_header, 8.f, ImDrawFlags_RoundCornersTop);


	const float sep_y = hy0 + hdr_h * 0.5f;
	const float r1_cy = hy0 + hdr_h * 0.25f;
	const float r2_cy = hy0 + hdr_h * 0.75f;


	wdl->AddLine(ImVec2(hx0, sep_y), ImVec2(hx1, sep_y),
		IM_COL32(255,255,255,(int)(8*a)), 1.f);

	wdl->AddLine(ImVec2(hx0, hy1), ImVec2(hx1, hy1),
		IM_COL32(255,255,255,(int)(10*a)), 1.f);


	auto ghost_btn = [&](const char* label, ImGuiID id_hv, ImGuiID id_fl,
		float bx0, float cy, float bw2) -> bool
	{
		ImGuiStorage* st = ImGui::GetStateStorage();
		ImVec2 ts  = ImGui::CalcTextSize(label);
		float  bh2 = row_h - 6.f;
		float  by0 = cy - bh2 * 0.5f;
		float  bx1 = bx0 + bw2, by1 = by0 + bh2;
		bool   bhv = ImGui::IsMouseHoveringRect(ImVec2(bx0,by0), ImVec2(bx1,by1), false);
		bool   bck = bhv && ImGui::IsMouseClicked(ImGuiMouseButton_Left);
		float  bht = st->GetFloat(id_hv, 0.f);
		float  bft = st->GetFloat(id_fl, 0.f);
		bht += ((bhv ? 1.f : 0.f) - bht) * std::min(12.f * dt, 1.f);
		bft += ((bck ? 1.f : 0.f) - bft) * std::min(22.f * dt, 1.f);
		st->SetFloat(id_hv, bht);
		st->SetFloat(id_fl, bft);
		float bg_a  = (bht * 0.10f + bft * 0.08f) * a;
		float brd_a = (0.14f + bht * 0.10f) * a;
		float txt_a = (0.55f + bht * 0.30f) * a;
		wdl->AddRectFilled(ImVec2(bx0,by0), ImVec2(bx1,by1),
			IM_COL32(255,255,255,(int)(bg_a*255)), 3.f);
		wdl->AddRect(ImVec2(bx0,by0), ImVec2(bx1,by1),
			IM_COL32(255,255,255,(int)(brd_a*255)), 3.f, 0, 0.75f);
		wdl->AddText(ImVec2(bx0 + (bw2 - ts.x) * 0.5f, by0 + (bh2 - ts.y) * 0.5f),
			IM_COL32(255,255,255,(int)(txt_a*255)), label);
		return bck;
	};


	auto flat_btn = [&](const char* label, ImGuiID id_hv, float lx, float cy) -> bool
	{
		ImGuiStorage* st = ImGui::GetStateStorage();
		ImVec2 ts  = ImGui::CalcTextSize(label);
		float  tx  = lx;
		float  ty  = cy - ts.y * 0.5f;
		ImVec2 hr0 = ImVec2(tx - 2.f, ty - 2.f);
		ImVec2 hr1 = ImVec2(tx + ts.x + 2.f, ty + ts.y + 2.f);
		bool   bhv = ImGui::IsMouseHoveringRect(hr0, hr1, false);
		bool   bck = bhv && ImGui::IsMouseClicked(ImGuiMouseButton_Left);
		float  bht = st->GetFloat(id_hv, 0.f);
		bht += ((bhv ? 1.f : 0.f) - bht) * std::min(12.f * dt, 1.f);
		st->SetFloat(id_hv, bht);
		float txt_a = (0.55f + bht * 0.40f) * a;
		wdl->AddText(ImVec2(tx, ty), IM_COL32(255,255,255,(int)(txt_a*255)), label);

		float uw  = ts.x * bht;
		float ux0 = tx + ts.x * 0.5f - uw * 0.5f;
		float uy  = ty + ts.y + 1.f;
		if (uw > 0.5f)
			wdl->AddLine(ImVec2(ux0, uy), ImVec2(ux0 + uw, uy),
				IM_COL32((int)(ax3*255),(int)(ay3*255),(int)(az3*255),(int)(bht*180*a)), 1.f);
		return bck;
	};


	const float rbtn_w  = std::max(
		ImGui::CalcTextSize("Choose File").x,
		ImGui::CalcTextSize("Run").x) + 22.f;
	const float rbtn_x0 = hx1 - hdr_pad - rbtn_w;


	{

		std::string fn_disp = "No file";
		bool has_file = false;
		if (code_editor::active && !code_editor::filename.empty()) {
			fn_disp = code_editor::filename;
			if (code_editor::dirty) fn_disp += " *";
			has_file = true;
		} else if (g_disasm.file.loaded && !g_disasm.file.filename.empty()) {
			fn_disp = g_disasm.file.filename;
			has_file = true;
		}
		if (has_file) {
			float avail_w = rbtn_x0 - hx0 - hdr_pad * 2.f - 4.f;
			ImVec2 full_ts = ImGui::CalcTextSize(fn_disp.c_str());
			if (full_ts.x > avail_w && fn_disp.size() > 12) {
				while (fn_disp.size() > 6) {
					fn_disp.pop_back();
					std::string test = fn_disp + "...";
					if (ImGui::CalcTextSize(test.c_str()).x <= avail_w) { fn_disp = test; break; }
				}
			}
		}
		ImVec2 fn_ts = ImGui::CalcTextSize(fn_disp.c_str());
		float  fn_y  = r1_cy - fn_ts.y * 0.5f;
		wdl->AddText(ImVec2(hx0 + hdr_pad, fn_y),
			has_file
				? ac_full
				: IM_COL32(120,120,140,(int)(140*a)),
			fn_disp.c_str());


		bool cf_clicked = ghost_btn("Choose File",
			ImGui::GetID("##cfhv"), ImGui::GetID("##cffl"),
			rbtn_x0, r1_cy, rbtn_w);

		if (cf_clicked) {
			std::string fpath = disasm::open_file_dialog(g_hwnd);
			if (!fpath.empty()) {
				g_disasm.file = DisasmFile{};
				disasm::load_pe(fpath, g_disasm.file);
				if (g_disasm.file.loaded)
					disasm::decode_section(g_disasm.file);
			}
		}
	}


	{

		ImVec2 ib_ts = ImGui::CalcTextSize("Index Binary");
		float  ib_ty = r2_cy - ib_ts.y * 0.5f;
		wdl->AddText(ImVec2(hx0 + hdr_pad, ib_ty),
			IM_COL32(255,255,255,(int)(0.35f*a*255)), "Index Binary");

		bool run_clicked = ghost_btn("Run",
			ImGui::GetID("##drhv"), ImGui::GetID("##drfl"),
			rbtn_x0, r2_cy, rbtn_w);
		(void)run_clicked;
	}


	float disasm_child_y = pad + title_h + hdr_h + 1.f;
	float disasm_child_h = total_h - hdr_h - 1.f;
	const float di_pad   = 6.f;
	ImGui::SetCursorPos(ImVec2(pad + left_w + gap + di_pad, disasm_child_y + di_pad));
	ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.f,0.f));
	ImGui::BeginChild("##center_content_scroll",
		ImVec2(center_w - di_pad*2.f, disasm_child_h - di_pad*2.f),
		false, ImGuiWindowFlags_NoBackground);
	{


	if (code_editor::active && !code_editor::buffer.empty())
	{
		float tw = center_w - di_pad * 2.f;
		float th = disasm_child_h - di_pad * 2.f;


		if (ImGui::GetIO().KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_S)) {
			code_editor::save();
		}


		const float gutter_w = 48.f;
		ImDrawList* tdl = ImGui::GetWindowDrawList();
		ImVec2 torig = ImGui::GetWindowPos();


		float editor_x = gutter_w + 4.f;
		float editor_w = tw - gutter_w - 8.f;
		ImGui::SetCursorPos(ImVec2(editor_x, 0.f));


		bool ac_active = editor_config::auto_complete && autocomplete::enabled;
		if (ac_active && autocomplete::popup_visible) {
			if (ImGui::IsKeyPressed(ImGuiKey_Escape, false)) {
				autocomplete::popup_visible = false;
				autocomplete::matches.clear();
			}
			if (ImGui::IsKeyPressed(ImGuiKey_UpArrow, true) && !autocomplete::matches.empty()) {
				autocomplete::selected = (autocomplete::selected - 1 + (int)autocomplete::matches.size())
					% (int)autocomplete::matches.size();
			}
			if (ImGui::IsKeyPressed(ImGuiKey_DownArrow, true) && !autocomplete::matches.empty()) {
				autocomplete::selected = (autocomplete::selected + 1) % (int)autocomplete::matches.size();
			}
		}

		ImGuiInputTextFlags ed_flags = ImGuiInputTextFlags_CallbackAlways;
		if (ac_active && autocomplete::popup_visible)
			ed_flags |= ImGuiInputTextFlags_CallbackCompletion;
		else
			ed_flags |= ImGuiInputTextFlags_AllowTabInput;

		ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0.f, 0.f, 0.f, 0.f));
		ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.82f, 0.82f, 0.92f, a));
		ImGui::PushStyleColor(ImGuiCol_ScrollbarBg, ImVec4(0.f, 0.f, 0.f, 0.f));
		ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(4.f, 2.f));
		ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 0.f);

		if (ImGui::InputTextMultiline("##code_editor",
			code_editor::buffer.data(), code_editor::buffer.size(),
			ImVec2(editor_w, th),
			ed_flags,
			[](ImGuiInputTextCallbackData* data) -> int {

				if (data->EventFlag == ImGuiInputTextFlags_CallbackCompletion) {
					if (!autocomplete::matches.empty() &&
						autocomplete::selected < (int)autocomplete::matches.size()) {
						int cursor = data->CursorPos;
						int ws = cursor;
						while (ws > 0 && (isalnum((unsigned char)data->Buf[ws-1]) || data->Buf[ws-1] == '_'))
							ws--;
						data->DeleteChars(ws, cursor - ws);
						data->InsertChars(ws, autocomplete::matches[autocomplete::selected].c_str());
					}
					autocomplete::popup_visible = false;
					autocomplete::matches.clear();
					return 1;
				}

				if (data->EventFlag == ImGuiInputTextFlags_CallbackAlways) {
					autocomplete::cursor_byte = data->CursorPos;
					int cursor = data->CursorPos;
					int ws = cursor;
					while (ws > 0 && (isalnum((unsigned char)data->Buf[ws-1]) || data->Buf[ws-1] == '_'))
						ws--;
					if (cursor > ws) {
						autocomplete::partial = std::string(data->Buf + ws, cursor - ws);
						autocomplete::find_matches(autocomplete::partial);
						autocomplete::popup_visible = !autocomplete::matches.empty();
					} else {
						autocomplete::partial.clear();
						autocomplete::popup_visible = false;
						autocomplete::matches.clear();
					}
					int line = 0, col = 0;
					for (int i = 0; i < data->CursorPos && i < data->BufTextLen; i++) {
						if (data->Buf[i] == '\n') { line++; col = 0; }
						else col++;
					}
					autocomplete::cursor_line = line;
					autocomplete::cursor_col = col;
				}
				code_editor::dirty = true;
				return 0;
			}))
		{
			code_editor::dirty = true;
		}

		ImGui::PopStyleVar(2);
		ImGui::PopStyleColor(3);


		float line_h = ImGui::GetFontSize() + 2.f;
		float scroll_y = ImGui::GetScrollY();
		float vis_h = th;


		if (ac_active && autocomplete::popup_visible && !autocomplete::matches.empty()) {
			float popup_w = 220.f;
			float ac_item_h = 22.f;
			float popup_h = std::min((float)autocomplete::matches.size(), 8.f) * ac_item_h + 8.f;
			float char_w  = ImGui::CalcTextSize("A").x;
			float sx = torig.x + editor_x + 4.f + char_w * autocomplete::cursor_col;
			float sy = torig.y + line_h * (autocomplete::cursor_line + 1) - scroll_y + 4.f;


			if (sx + popup_w > torig.x + tw) sx = torig.x + tw - popup_w - 4.f;
			if (sy + popup_h > torig.y + th) sy = torig.y + line_h * autocomplete::cursor_line - scroll_y - popup_h;

			ImDrawList* acdl = ImGui::GetForegroundDrawList();
			acdl->AddRectFilled(ImVec2(sx, sy), ImVec2(sx + popup_w, sy + popup_h),
				IM_COL32(20, 20, 30, 240), 6.f);
			acdl->AddRect(ImVec2(sx, sy), ImVec2(sx + popup_w, sy + popup_h),
				IM_COL32(80, 80, 130, 100), 6.f);

			for (int mi = 0; mi < (int)autocomplete::matches.size() && mi < 8; mi++) {
				float iy = sy + 4.f + mi * ac_item_h;
				if (mi == autocomplete::selected) {
					acdl->AddRectFilled(ImVec2(sx + 2.f, iy), ImVec2(sx + popup_w - 2.f, iy + ac_item_h),
						IM_COL32((int)(ax3*255), (int)(ay3*255), (int)(az3*255), 50), 4.f);
				}
				auto& match = autocomplete::matches[mi];
				size_t plen = autocomplete::partial.size();
				if (plen > 0 && plen <= match.size()) {
					acdl->AddText(ImVec2(sx + 8.f, iy + 2.f),
						IM_COL32((int)(ax3*255), (int)(ay3*255), (int)(az3*255), 255),
						match.c_str(), match.c_str() + plen);
					float prefix_w = ImGui::CalcTextSize(match.c_str(), match.c_str() + plen).x;
					acdl->AddText(ImVec2(sx + 8.f + prefix_w, iy + 2.f),
						IM_COL32(200, 200, 220, 220), match.c_str() + plen);
				} else {
					acdl->AddText(ImVec2(sx + 8.f, iy + 2.f),
						IM_COL32(200, 200, 220, 220), match.c_str());
				}
			}
		}


		const char* txt = code_editor::buffer.data();
		int n_lines = 1;
		for (const char* p = txt; *p; p++)
			if (*p == '\n') n_lines++;


		tdl->AddLine(ImVec2(torig.x + gutter_w, torig.y),
			ImVec2(torig.x + gutter_w, torig.y + vis_h),
			IM_COL32(255, 255, 255, (int)(10 * a)), 1.f);

		int first_row = std::max(0, (int)(scroll_y / line_h) - 1);
		int last_row = std::min(n_lines - 1, (int)((scroll_y + vis_h) / line_h) + 1);

		for (int i = first_row; i <= last_row; i++) {
			float y = torig.y + i * line_h - scroll_y + 2.f;

			if (i & 1)
				tdl->AddRectFilled(ImVec2(torig.x, y), ImVec2(torig.x + gutter_w, y + line_h - 1.f),
					IM_COL32(255, 255, 255, (int)(3.f * a)));

			char ln_buf[8];
			snprintf(ln_buf, sizeof(ln_buf), "%4d", i + 1);
			tdl->AddText(ImVec2(torig.x + 4.f, y + 1.f),
				IM_COL32(75, 85, 120, (int)(140 * a)), ln_buf);
		}

		if (ID3D11ShaderResourceView* icon_srv = get_active_theme_icon()) {
			float src_w = 0.f;
			float src_h = 0.f;
			int icon_idx = g_sa_settings.theme_icon_index;
			if (custom_themes::active_custom >= 0 &&
			    custom_themes::active_custom < (int)custom_themes::list.size())
				icon_idx = custom_themes::list[custom_themes::active_custom].icon_index;
			if (icon_idx < 0 && g_custom_theme_icon_w > 0 && g_custom_theme_icon_h > 0) {
				src_w = (float)g_custom_theme_icon_w;
				src_h = (float)g_custom_theme_icon_h;
			} else if (icon_idx >= 0 && icon_idx < 4) {
				src_w = (float)g_theme_icon_w[icon_idx];
				src_h = (float)g_theme_icon_h[icon_idx];
			}

			if (src_w > 0.f && src_h > 0.f) {
				const float max_h = th * 0.38f;
				const float max_w = editor_w * 0.28f;
				const float scale = std::min(max_w / src_w, max_h / src_h);
				const float draw_w = src_w * scale;
				const float draw_h = src_h * scale;
				const float icon_pad = 18.f;
				const ImVec2 img_min(torig.x + gutter_w + 4.f + editor_w - draw_w - icon_pad,
				                     torig.y + th - draw_h - icon_pad);
				const ImVec2 img_max(img_min.x + draw_w, img_min.y + draw_h);
				tdl->AddImage((ImTextureID)icon_srv, img_min, img_max,
					ImVec2(0, 0), ImVec2(1, 1), IM_COL32(255, 255, 255, (int)(172 * a)));
			}
		}
	}

	else
	{
		ImDrawList* cdl  = ImGui::GetWindowDrawList();
		ImVec2      orig = ImGui::GetWindowPos();
		float       iw   = center_w - di_pad*2.f;


		static float addr_col_w = 0.f;
		if (addr_col_w == 0.f)
			addr_col_w = ImGui::CalcTextSize("0000000140001000").x + 6.f;

		const float lh     = 18.f;
		const float x_addr = orig.x + 4.f;
		const float x_vsep = x_addr + addr_col_w;
		const float x_mnem = x_vsep + 10.f;
		const float x_ops  = x_mnem + 72.f;

		const bool has_instrs = !g_disasm.file.instrs.empty();
		if (!has_instrs)
		{

			ID3D11ShaderResourceView* icon_srv = get_active_theme_icon();
			if (icon_srv) {
				int icon_idx = g_sa_settings.theme_icon_index;
				if (custom_themes::active_custom >= 0 &&
				    custom_themes::active_custom < (int)custom_themes::list.size())
					icon_idx = custom_themes::list[custom_themes::active_custom].icon_index;
				float src_w = 0.f;
				float src_h = 0.f;
				if (icon_idx < 0 && g_custom_theme_icon_w > 0 && g_custom_theme_icon_h > 0) {
					src_w = (float)g_custom_theme_icon_w;
					src_h = (float)g_custom_theme_icon_h;
				} else {
					if (icon_idx < 0) icon_idx = 3;
					src_w = (float)g_theme_icon_w[icon_idx];
					src_h = (float)g_theme_icon_h[icon_idx];
				}
				if (src_w > 0 && src_h > 0) {
					float window_h = ImGui::GetWindowHeight();
					float max_h = window_h * 0.75f;
					float max_w = iw * 0.6f;
					float scale = std::min(max_w / src_w, max_h / src_h);
					float dw = src_w * scale;
					float dh = src_h * scale;
					float ix = orig.x + iw * 0.5f - dw * 0.5f;
					float iy = orig.y + window_h * 0.5f - dh * 0.5f - 20.f;
					cdl->AddImage((ImTextureID)icon_srv,
						ImVec2(ix, iy), ImVec2(ix + dw, iy + dh),
						ImVec2(0, 0), ImVec2(1, 1),
						IM_COL32(255, 255, 255, (int)(200 * a)));
				}
			}

			const char* hint = !g_disasm.file.err.empty()     ? g_disasm.file.err.c_str()
				             : !g_disasm.file.loaded           ? "Choose a file to begin"
				             :                                   "Click 'Index Binary' to disassemble";
			ImVec2 ht2 = ImGui::CalcTextSize(hint);
			float  window_h  = ImGui::GetWindowHeight();
			cdl->AddText(ImVec2(orig.x + iw*0.5f - ht2.x*0.5f, orig.y + window_h * 0.85f - ht2.y*0.5f),
				IM_COL32(100,100,120,(int)(120*a)), hint);
		}
		else
		{
			auto& instrs   = g_disasm.file.instrs;
			int   n        = (int)instrs.size();
			float scroll_y = ImGui::GetScrollY();
			float vis_h    = ImGui::GetWindowHeight();

			cdl->AddLine(ImVec2(x_vsep, orig.y), ImVec2(x_vsep, orig.y + vis_h),
				IM_COL32(255,255,255,(int)(10*a)), 1.f);

			int first_row = std::max(0,   (int)(scroll_y / lh) - 1);
			int last_row  = std::min(n-1, (int)((scroll_y + vis_h) / lh) + 1);

			for (int i = first_row; i <= last_row; i++)
			{
				float y = orig.y + i * lh - scroll_y;
				const AsmInstr& ins = instrs[i];


				if (i & 1)
					cdl->AddRectFilled(ImVec2(orig.x, y), ImVec2(orig.x + iw, y + lh - 1.f),
						IM_COL32(255,255,255,(int)(3.f * a)));

				ImGuiID rhid = ImGui::GetID((void*)(intptr_t)(0xD000 + i));
				float   rh   = ImGui::GetStateStorage()->GetFloat(rhid, 0.f);
				bool    rhv  = ImGui::IsMouseHoveringRect(
					ImVec2(orig.x, y), ImVec2(orig.x + iw, y + lh - 1.f), false);
				rh += ((rhv?1.f:0.f)-rh)*std::min(12.f*dt,1.f);
				ImGui::GetStateStorage()->SetFloat(rhid, rh);

				if (rh > 0.002f)
					cdl->AddRectFilled(ImVec2(orig.x, y), ImVec2(orig.x + iw, y + lh - 1.f),
						IM_COL32(255,255,255,(int)(rh * 12.f * a)));
				if (ins.is_branch || ins.is_call)
					cdl->AddRectFilled(ImVec2(orig.x, y), ImVec2(orig.x + iw, y + lh - 1.f), ac_dim);


				char addr_buf[20];
				snprintf(addr_buf, sizeof(addr_buf), "%016llX", (unsigned long long)ins.addr);
				cdl->AddText(ImVec2(x_addr, y+1.f), IM_COL32(75,95,155,(int)(170*a)), addr_buf);


				ImU32 mc = (ins.is_branch||ins.is_call) ? ac_full
					: ins.is_ret   ? IM_COL32(220,150,150,(int)(230*a))
					: ins.is_nop   ? IM_COL32(100,100,110,(int)(140*a))
					: ins.is_priv  ? IM_COL32(220,180,100,(int)(230*a))
					: IM_COL32(200,200,240,(int)(235*a));
				cdl->AddText(ImVec2(x_mnem, y+1.f), mc, ins.mnem);

				if (ins.ops[0]) {
					ImU32 oc = (ins.is_branch||ins.is_call)
						? IM_COL32(210,215,255,(int)(160*a))
						: ins.is_nop  ? IM_COL32(80,80,90,(int)(120*a))
						: ins.is_priv ? IM_COL32(200,170,95,(int)(180*a))
						: IM_COL32(165,170,190,(int)(210*a));
					cdl->AddText(ImVec2(x_ops, y+1.f), oc, ins.ops);
				}

				if (rhv && ImGui::IsMouseClicked(ImGuiMouseButton_Right)) {
					g_disasm.ctx_row = i;
					ImGui::OpenPopup("##disasm_ctx");
				}
			}

			ImGui::SetCursorPos(ImVec2(0.f, n * lh));
			ImGui::Dummy(ImVec2(1.f, 1.f));

			static float ctx_t       = 0.f;
			static bool  ctx_closing = false;
			static bool  ctx_prev    = false;

			bool ctx_now = ImGui::IsPopupOpen("##disasm_ctx");
			if (ctx_now && !ctx_prev) { ctx_t = 0.f; ctx_closing = false; }
			if (!ctx_now) ctx_closing = false;
			ctx_prev = ctx_now;
			ctx_t += ((ctx_closing ? 0.f : 1.f) - ctx_t) * std::min(24.f * dt, 1.f);
			float ctx_a = std::max(0.001f, ctx_t);

			ImGui::SetNextWindowBgAlpha(ctx_a);
			ImGui::SetNextWindowSizeConstraints(ImVec2(190.f, 0.f), ImVec2(320.f, 400.f));
			ImGui::PushStyleVar(ImGuiStyleVar_Alpha,          ctx_a * a);
			ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 7.f);
			ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding,  ImVec2(0.f, 6.f));
			ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing,    ImVec2(0.f, 0.f));
			ImGui::PushStyleColor(ImGuiCol_PopupBg,       ImVec4(0.11f, 0.11f, 0.15f, 1.f));
			ImGui::PushStyleColor(ImGuiCol_Border,        ImVec4(1.f, 1.f, 1.f, 0.08f));
			ImGui::PushStyleColor(ImGuiCol_HeaderHovered, ImVec4(1.f, 1.f, 1.f, 0.07f));
			ImGui::PushStyleColor(ImGuiCol_Header,        ImVec4(1.f, 1.f, 1.f, 0.05f));
			ImGui::PushStyleColor(ImGuiCol_Text,          ImVec4(0.86f, 0.86f, 0.90f, 1.f));

			if (ImGui::BeginPopup("##disasm_ctx"))
			{
				if (ctx_closing && ctx_t < 0.05f) ImGui::CloseCurrentPopup();

				if (g_disasm.ctx_row >= 0 && g_disasm.ctx_row < n)
				{
					const AsmInstr& ci = instrs[g_disasm.ctx_row];

					char buf_addr[20], buf_line[128], buf_bytes[64] = {};
					snprintf(buf_addr, sizeof(buf_addr), "%016llX", (unsigned long long)ci.addr);
					if (ci.ops[0])
						snprintf(buf_line, sizeof(buf_line), "%016llX  %-8s %s",
							(unsigned long long)ci.addr, ci.mnem, ci.ops);
					else
						snprintf(buf_line, sizeof(buf_line), "%016llX  %s",
							(unsigned long long)ci.addr, ci.mnem);
					int boff = 0;
					for (int b = 0; b < ci.len && boff + 3 < 64; b++)
						boff += snprintf(buf_bytes + boff, 64 - boff, b ? " %02X" : "%02X", ci.raw[b]);

					ImDrawList* pdl = ImGui::GetWindowDrawList();
					float pw = ImGui::GetWindowWidth();


					ImGui::Dummy(ImVec2(0.f, 2.f));
					{
						ImVec2 cp = ImGui::GetCursorScreenPos();
						char addr_short[22];
						snprintf(addr_short, sizeof(addr_short), "0x%llX", (unsigned long long)ci.addr);
						float tw = ImGui::CalcTextSize(addr_short).x;
						float lh2 = ImGui::GetTextLineHeight();
						pdl->AddText(ImVec2(cp.x + (pw - tw) * 0.5f, cp.y),
							IM_COL32((int)(ax3*255),(int)(ay3*255),(int)(az3*255),(int)(200*ctx_a)), addr_short);
						ImGui::Dummy(ImVec2(pw, lh2 + 5.f));
					}


					{
						ImVec2 cp = ImGui::GetCursorScreenPos();
						pdl->AddLine(ImVec2(cp.x + 8.f, cp.y), ImVec2(cp.x + pw - 8.f, cp.y),
							IM_COL32(255,255,255,18), 1.f);
						ImGui::Dummy(ImVec2(0.f, 5.f));
					}


					float item_h = ImGui::GetTextLineHeight() + 10.f;
					auto ctx_item = [&](const char* label, const char* copy_text) {
						ImVec2 cp  = ImGui::GetCursorScreenPos();
						ImVec2 rmin = cp;
						ImVec2 rmax = ImVec2(cp.x + pw, cp.y + item_h);
						bool   hov = ImGui::IsMouseHoveringRect(rmin, rmax);
						bool   clk = hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left);
						if (hov) pdl->AddRectFilled(rmin, rmax, IM_COL32(255,255,255,14));
						if (clk) pdl->AddRectFilled(rmin, rmax, IM_COL32(255,255,255,8));
						float ty = cp.y + (item_h - ImGui::GetTextLineHeight()) * 0.5f;
						pdl->AddText(ImVec2(cp.x + 14.f, ty),
							IM_COL32(210, 212, 220, (int)(220 * ctx_a)), label);
						ImGui::Dummy(ImVec2(pw, item_h));
						if (clk) { ImGui::SetClipboardText(copy_text); ctx_closing = true; }
					};

					ctx_item("Copy address", buf_addr);
					ctx_item("Copy line",    buf_line);
					ctx_item("Copy bytes",   buf_bytes);

					ImGui::Dummy(ImVec2(0.f, 2.f));
				}
				ImGui::EndPopup();
			}

			ImGui::PopStyleColor(5);
			ImGui::PopStyleVar(4);
		}
	}
	}
	ImGui::EndChild();
	ImGui::PopStyleVar();


	begin_child("##chat", ImVec2(pad + left_w + gap + center_w + gap, pad + title_h), ImVec2(right_w, total_h), a);
	{
		float ax = globals::ui::accent.x * 255.f;
		float ay = globals::ui::accent.y * 255.f;
		float az = globals::ui::accent.z * 255.f;

		float cw = ImGui::GetWindowWidth();
		float ch = ImGui::GetWindowHeight();
		float frame_h    = ImGui::GetFrameHeight();


		float line_h     = ImGui::GetFontSize();
		float input_pad  = 8.f;
		int   num_lines  = 1;
		{
			for (const char* p = g_chat_buf; *p; ++p)
				if (*p == '\n') ++num_lines;

			float text_w = cw - frame_h - 4.f - 16.f;
			if (text_w > 0.f) {
				ImVec2 ts = ImGui::CalcTextSize(g_chat_buf, nullptr, false, text_w);
				int wrapped_lines = (int)(ts.y / line_h);
				if (wrapped_lines > num_lines) num_lines = wrapped_lines;
			}
		}
		int   max_lines  = 8;
		int   vis_lines  = std::max(1, std::min(num_lines, max_lines));
		float input_h    = vis_lines * line_h + input_pad * 2.f;
		float bot_pad    = 4.f;
		float input_y    = ch - input_h - bot_pad;
		float chat_sep_y = input_y - 6.f;
		float msg_area_h = chat_sep_y - 24.f;


		{
			float gear_sz = 18.f;
			ImVec2 btn_pos(cw - gear_sz - 8.f, 3.f);
			ImGui::SetCursorPos(btn_pos);
			ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0,0,0,0));
			ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(1,1,1,0.08f));
			ImGui::PushStyleColor(ImGuiCol_ButtonActive,  ImVec4(1,1,1,0.12f));
			ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.55f,0.55f,0.60f,1.f));
			if (ImGui::Button("\xe2\x9a\x99##chat_settings", ImVec2(gear_sz, gear_sz)))
				g_settings_open = true;
			ImGui::PopStyleColor(4);
			if (ImGui::IsItemHovered())
				ImGui::SetTooltip("AI Settings");
			ImGui::SetCursorPosY(24.f);
		}

		ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));
		ImGui::BeginChild("##chat_msgs", ImVec2(cw, msg_area_h), false,
			ImGuiWindowFlags_NoBackground | ImGuiWindowFlags_NoScrollbar);

		ImDrawList* dl = ImGui::GetWindowDrawList();
		ImVec2      wp2 = ImGui::GetWindowPos();
		wp2.y -= ImGui::GetScrollY();
		ImGuiStorage* s = ImGui::GetStateStorage();

		float cursor_y = 6.f;

		for (int mi = 0; mi < (int)g_chat_messages.size(); mi++)
		{
			auto& msg = g_chat_messages[mi];


			ImGuiID appear_id = ImGui::GetID(("appear_" + std::to_string(mi)).c_str());
			float   appear = s->GetFloat(appear_id, 0.f);
			appear += (1.f - appear) * std::min(9.f * ImGui::GetIO().DeltaTime, 1.f);
			s->SetFloat(appear_id, appear);

			float wrap_w = cw - 20.f;

			if (msg.is_user)
			{

				ImVec2 ts = ImGui::CalcTextSize(msg.text.c_str(), nullptr, false, wrap_w * 0.78f);
				float  bw = ts.x + 16.f;
				float  bh = ts.y + 10.f;


				float target_x = cw - bw - 8.f;
				float bx = target_x + (1.f - appear) * 40.f;
				float by = cursor_y;


				ImVec4 col_bg = ImVec4(
					(ax * 0.22f + 18.f) / 255.f,
					(ay * 0.22f + 12.f) / 255.f,
					(az * 0.22f + 28.f) / 255.f,
					(220.f / 255.f) * appear * a);

				ImVec2 bmin = ImVec2(wp2.x + bx, wp2.y + by);
				ImVec2 bmax = ImVec2(bmin.x + bw, bmin.y + bh);

				dl->AddRectFilled(bmin, bmax,
					IM_COL32((int)(ax * 0.22f + 18), (int)(ay * 0.22f + 12), (int)(az * 0.22f + 28),
						(int)(220 * appear * a)), 8.f);
				dl->AddText(ImGui::GetFont(), ImGui::GetFontSize(),
					ImVec2(bmin.x + 8.f, bmin.y + 5.f),
					IM_COL32(230, 228, 255, (int)(240 * appear * a)),
					msg.text.c_str(), nullptr, wrap_w * 0.78f);


				{
					ImGuiID mtime_id = ImGui::GetID(("mtu_" + std::to_string(mi)).c_str());
					float mtime = s->GetFloat(mtime_id, -1.f);
					if (mtime < 0.f) { mtime = (float)ImGui::GetTime(); s->SetFloat(mtime_id, mtime); }
					float elapsed = (float)ImGui::GetTime() - mtime;
					char ts_buf[16];
					if (elapsed < 60.f)        snprintf(ts_buf, sizeof(ts_buf), "just now");
					else if (elapsed < 3600.f) snprintf(ts_buf, sizeof(ts_buf), "%.0fm ago", elapsed / 60.f);
					else                       snprintf(ts_buf, sizeof(ts_buf), "%.0fh ago", elapsed / 3600.f);

					ImGuiID hov_id = ImGui::GetID(("mhu_" + std::to_string(mi)).c_str());
					float hov_a = s->GetFloat(hov_id, 0.f);
					hov_a += ((ImGui::IsMouseHoveringRect(bmin, bmax) ? 1.f : 0.f) - hov_a)
						* std::min(8.f * ImGui::GetIO().DeltaTime, 1.f);
					s->SetFloat(hov_id, hov_a);

					if (hov_a > 0.01f)
					{
						ImVec2 tts2 = ImGui::CalcTextSize(ts_buf);

						dl->AddText(
							ImVec2(bmin.x - tts2.x - 6.f, bmin.y + (bh - tts2.y) * 0.5f),
							IM_COL32(120, 115, 155, (int)(170 * hov_a * appear * a)), ts_buf);
					}
				}

				cursor_y += bh + 8.f;
			}
			else
			{
				if (msg.has_thinking)
				{
					bool still_thinking = !g_think_done && mi == (int)g_chat_messages.size() - 1;

					ImGuiID tid = ImGui::GetID(("think_open_" + std::to_string(mi)).c_str());
					bool    open = s->GetBool(tid, false);


					if (!still_thinking && open)
					{
						s->SetBool(tid, false);
						open = false;
					}

					ImGuiID toa = ImGui::GetID(("toa_" + std::to_string(mi)).c_str());
					float   topen = s->GetFloat(toa, 0.f);
					topen += ((open ? 1.f : 0.f) - topen) * std::min(10.f * ImGui::GetIO().DeltaTime, 1.f);
					s->SetFloat(toa, topen);


					ImGuiID tvid = ImGui::GetID(("tv_" + std::to_string(mi)).c_str());
					float think_vis = s->GetFloat(tvid, 1.f);
					if (!still_thinking && topen < 0.05f)
					{
						think_vis = std::max(0.f, think_vis - 4.f * ImGui::GetIO().DeltaTime);
						s->SetFloat(tvid, think_vis);
					}


					ImGuiID tstart_id = ImGui::GetID(("tstart_" + std::to_string(mi)).c_str());
					float   tstart    = s->GetFloat(tstart_id, -1.f);
					if (still_thinking && tstart < 0.f) { tstart = (float)ImGui::GetTime(); s->SetFloat(tstart_id, tstart); }
					ImGuiID tdur_id   = ImGui::GetID(("tdur_" + std::to_string(mi)).c_str());
					float   tdur      = s->GetFloat(tdur_id, -1.f);
					if (!still_thinking && tstart > 0.f && tdur < 0.f) { tdur = (float)ImGui::GetTime() - tstart; s->SetFloat(tdur_id, tdur); }

					if (think_vis > 0.01f)
					{

						char think_label[20];
						if (still_thinking) {
							int dots = 1 + (int)(ImGui::GetTime() * 2.0) % 3;
							snprintf(think_label, sizeof(think_label), "Thinking%.*s", dots, "...");
						} else {
							snprintf(think_label, sizeof(think_label), "Thinking...");
						}

						ImVec2 label_ts = ImGui::CalcTextSize(think_label);
						float  pill_h   = 18.f;
						float  pill_w   = 10.f + label_ts.x + 10.f;
						float  vis_a    = think_vis * appear * a;

						ImVec2 pmin = ImVec2(wp2.x + 6.f, wp2.y + cursor_y);
						ImVec2 pmax = ImVec2(pmin.x + pill_w, pmin.y + pill_h);

						bool phover = ImGui::IsMouseHoveringRect(pmin, pmax);
						if (phover && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
						{
							s->SetBool(tid, !open); open = !open;
						}

						dl->AddRectFilled(pmin, pmax,
							IM_COL32(255, 255, 255, phover ? (int)(22 * vis_a) : (int)(12 * vis_a)), 9.f);
						dl->AddRect(pmin, pmax,
							IM_COL32(255, 255, 255, (int)(22 * vis_a)), 9.f, 0, 0.5f);

						dl->AddText(
							ImVec2(pmin.x + 10.f, pmin.y + (pill_h - label_ts.y) * 0.5f),
							IM_COL32(165, 158, 205, (int)(200 * vis_a)), think_label);

						cursor_y += (pill_h + 4.f) * think_vis;

						if (!msg.thinking_text.empty())
						{
							float pad2  = 10.f;
							float bk_w  = cw - 14.f;
							ImVec2 tts  = ImGui::CalcTextSize(
								msg.thinking_text.c_str(), nullptr, false, bk_w - pad2 * 2.f);
							float full_bk_h = tts.y + pad2 * 2.f;

							ImGuiID bkha = ImGui::GetID(("bkh_" + std::to_string(mi)).c_str());
							float   bk_h = s->GetFloat(bkha, 0.f);
							bk_h += ((topen > 0.5f ? full_bk_h : 0.f) - bk_h)
								* std::min(10.f * ImGui::GetIO().DeltaTime, 1.f);
							s->SetFloat(bkha, bk_h);

							if (bk_h > 1.f)
							{
								ImVec2 bkmin = ImVec2(wp2.x + 6.f, wp2.y + cursor_y);
								ImVec2 bkmax = ImVec2(bkmin.x + bk_w, bkmin.y + bk_h);

								dl->AddRectFilled(bkmin, bkmax,
									IM_COL32(28, 26, 44, (int)(210 * topen * vis_a)), 7.f);
								dl->AddRect(bkmin, bkmax,
									IM_COL32(255, 255, 255, (int)(18 * topen * vis_a)), 7.f, 0, 0.5f);

								dl->PushClipRect(bkmin, bkmax, true);
								dl->AddText(ImGui::GetFont(), ImGui::GetFontSize(),
									ImVec2(bkmin.x + pad2, bkmin.y + pad2),
									IM_COL32(148, 140, 190, (int)(200 * topen * vis_a)),
									msg.thinking_text.c_str(), nullptr, bk_w - pad2 * 2.f);
								dl->PopClipRect();

								cursor_y += (bk_h + 5.f) * think_vis;
							}
						}
					}
				}

				if (!msg.text.empty() || msg.streaming)
				{
					ImVec2 ts = msg.text.empty()
						? ImVec2(0.f, ImGui::GetFontSize())
						: ImGui::CalcTextSize(msg.text.c_str(), nullptr, false, wrap_w * 0.82f);

					float target_bw = ts.x + 16.f;
					float target_bh = ts.y + 10.f;


					ImGuiID bwa = ImGui::GetID(("bw_" + std::to_string(mi)).c_str());
					ImGuiID bha = ImGui::GetID(("bh_" + std::to_string(mi)).c_str());
					float   bw = s->GetFloat(bwa, 10.f);
					float   bh = s->GetFloat(bha, target_bh);
					bw += (target_bw - bw) * std::min(12.f * ImGui::GetIO().DeltaTime, 1.f);
					bh += (target_bh - bh) * std::min(12.f * ImGui::GetIO().DeltaTime, 1.f);
					s->SetFloat(bwa, bw);
					s->SetFloat(bha, bh);


					ImGuiID fda = ImGui::GetID(("fda_" + std::to_string(mi)).c_str());
					float   falpha = s->GetFloat(fda, 0.f);
					falpha += (1.f - falpha) * std::min(6.f * ImGui::GetIO().DeltaTime, 1.f);
					s->SetFloat(fda, falpha);

					float bx = 6.f;
					float by = cursor_y;

					ImVec2 bmin = ImVec2(wp2.x + bx, wp2.y + by);
					ImVec2 bmax = ImVec2(bmin.x + bw, bmin.y + bh);

					dl->AddRectFilled(bmin, bmax,
						IM_COL32(34, 32, 52, (int)(210 * falpha * a)), 8.f);

					if (!msg.text.empty())
					{
						dl->PushClipRect(bmin, bmax, true);
						dl->AddText(ImGui::GetFont(), ImGui::GetFontSize(),
							ImVec2(bmin.x + 8.f, bmin.y + 5.f),
							IM_COL32(220, 218, 240, (int)(230 * falpha * a)),
							msg.text.c_str(), nullptr, wrap_w * 0.82f);
						dl->PopClipRect();
					}


					{
						ImGuiID mtime_id = ImGui::GetID(("mta_" + std::to_string(mi)).c_str());
						float mtime = s->GetFloat(mtime_id, -1.f);
						if (mtime < 0.f) { mtime = (float)ImGui::GetTime(); s->SetFloat(mtime_id, mtime); }
						float elapsed = (float)ImGui::GetTime() - mtime;
						char ts_buf[32];
						float tdur_val = s->GetFloat(ImGui::GetID(("tdur_" + std::to_string(mi)).c_str()), -1.f);
						if (elapsed < 60.f)        snprintf(ts_buf, sizeof(ts_buf), "just now");
						else if (elapsed < 3600.f) snprintf(ts_buf, sizeof(ts_buf), "%.0fm ago", elapsed / 60.f);
						else                       snprintf(ts_buf, sizeof(ts_buf), "%.0fh ago", elapsed / 3600.f);

						if (msg.has_thinking && tdur_val > 0.f)
						{
							char extra[20];
							snprintf(extra, sizeof(extra), "  |  %.1fs", tdur_val);
							strncat_s(ts_buf, extra, _TRUNCATE);
						}

						ImGuiID hov_id = ImGui::GetID(("mha_" + std::to_string(mi)).c_str());
						float hov_a = s->GetFloat(hov_id, 0.f);
						hov_a += ((ImGui::IsMouseHoveringRect(bmin, bmax) ? 1.f : 0.f) - hov_a)
							* std::min(8.f * ImGui::GetIO().DeltaTime, 1.f);
						s->SetFloat(hov_id, hov_a);

						if (hov_a > 0.01f)
						{
							ImVec2 tts2 = ImGui::CalcTextSize(ts_buf);
							dl->AddText(
								ImVec2(bmax.x + 6.f, bmin.y + (bh - tts2.y) * 0.5f),
								IM_COL32(120, 115, 155, (int)(170 * hov_a * falpha * a)), ts_buf);
						}
					}

					cursor_y += bh + 8.f;
				}
			}

			ImGui::SetCursorPosY(cursor_y);
			ImGui::Dummy(ImVec2(1.f, 0.f));
		}

		ImGui::SetCursorPosY(cursor_y + 4.f);
		ImGui::Dummy(ImVec2(1.f, 1.f));

		if (g_chat_scroll_to_bottom)
		{
			ImGui::SetScrollHereY(1.f);
			g_chat_scroll_to_bottom = false;
		}

		float chat_scroll_y   = ImGui::GetScrollY();
		ImVec2 msgs_screen_pos = ImGui::GetWindowPos();

		ImGui::EndChild();
		ImGui::PopStyleVar();

		{
			float fade_h  = 22.f;
			float fade_x0 = msgs_screen_pos.x - 6.f;
			float fade_x1 = msgs_screen_pos.x + cw + 6.f;

			dl->PushClipRect(ImVec2(fade_x0, msgs_screen_pos.y),
				ImVec2(fade_x1, msgs_screen_pos.y + msg_area_h), false);


			if (chat_scroll_y > 1.f)
			{
				float top_a = std::min(chat_scroll_y / fade_h, 1.f);
				dl->AddRectFilledMultiColor(
					ImVec2(fade_x0, msgs_screen_pos.y),
					ImVec2(fade_x1, msgs_screen_pos.y + fade_h),
					IM_COL32(10, 8, 22, (int)(200 * top_a * a)),
					IM_COL32(10, 8, 22, (int)(200 * top_a * a)),
					IM_COL32(10, 8, 22, 0),
					IM_COL32(10, 8, 22, 0));
			}

			float bot_y = msgs_screen_pos.y + msg_area_h;
			dl->AddRectFilledMultiColor(
				ImVec2(fade_x0, bot_y - fade_h),
				ImVec2(fade_x1, bot_y),
				IM_COL32(10, 8, 22, 0), IM_COL32(10, 8, 22, 0),
				IM_COL32(10, 8, 22, (int)(200 * a)),
				IM_COL32(10, 8, 22, (int)(200 * a)));

			dl->PopClipRect();
		}

		{
			ImVec2 wp3  = ImGui::GetWindowPos();
			float  sy   = wp3.y + sep_y;
			float  lx0  = wp3.x - 6.f;
			float  lx1  = wp3.x + cw + 6.f;

			dl->PushClipRect(ImVec2(lx0, sy - 2.f), ImVec2(lx1, sy + 2.f), false);

			dl->AddLine(ImVec2(lx0, sy), ImVec2(lx1, sy),
				IM_COL32(255, 255, 255, (int)(10 * a)));

			float st       = (sinf((float)ImGui::GetTime() * 1.1f) + 1.f) * 0.5f;
			float cx3      = lx0 + st * (lx1 - lx0);
			float hw       = 40.f;
			float glow_lx0 = std::max(cx3 - hw, lx0);
			float glow_lx1 = std::min(cx3 + hw, lx1);

			dl->AddRectFilledMultiColor(
				ImVec2(glow_lx0, sy - 1.f), ImVec2(cx3, sy + 1.f),
				IM_COL32(0, 0, 0, 0),
				IM_COL32((int)ax, (int)ay, (int)az, (int)(80 * a)),
				IM_COL32((int)ax, (int)ay, (int)az, (int)(80 * a)),
				IM_COL32(0, 0, 0, 0));
			dl->AddRectFilledMultiColor(
				ImVec2(cx3, sy - 1.f), ImVec2(glow_lx1, sy + 1.f),
				IM_COL32((int)ax, (int)ay, (int)az, (int)(80 * a)),
				IM_COL32(0, 0, 0, 0),
				IM_COL32(0, 0, 0, 0),
				IM_COL32((int)ax, (int)ay, (int)az, (int)(80 * a)));

			dl->PopClipRect();
		}

		{
			if (!g_send_icon_srv)
			{
				int _w = 0, _h = 0;
				icon_loader::load(send_icon, sizeof(send_icon), &g_send_icon_srv, &_w, &_h, true);
			}

			float btn_sz = frame_h;
			float igap   = 4.f;


			{
				static bool model_open = false;
				auto* active_profile = g_sa_settings.get_active_profile();
				std::string provider = active_profile ? active_profile->display_name : "No profile";
				std::string model    = active_profile ? active_profile->model : "No model";

				if (model.empty()) model = "Select model";
				std::string pill_text = provider + " / " + model;

				float max_pill_w = cw * 0.7f;
				ImVec2 pill_ts = ImGui::CalcTextSize(pill_text.c_str());
				if (pill_ts.x > max_pill_w && pill_text.size() > 20) {
					pill_text.resize(20);
					pill_text += "...";
					pill_ts = ImGui::CalcTextSize(pill_text.c_str());
				}

				float pill_h  = 18.f;
				float pill_y  = input_y - pill_h - 4.f;
				float pill_w  = pill_ts.x + 16.f;
				float pill_x  = 4.f;

				ImGui::SetCursorPos(ImVec2(pill_x, pill_y));
				ImVec2 pmin = ImGui::GetCursorScreenPos();
				ImVec2 pmax(pmin.x + pill_w, pmin.y + pill_h);

				bool pill_hov = ImGui::IsMouseHoveringRect(pmin, pmax);
				static float pill_ht = 0.f;
				pill_ht += ((pill_hov ? 1.f : 0.f) - pill_ht) * std::min(10.f * dt, 1.f);

				dl->AddRectFilled(pmin, pmax,
					IM_COL32(40, 38, 60, (int)((160 + 40 * pill_ht) * a)), 9.f);
				dl->AddRect(pmin, pmax,
					IM_COL32(255, 255, 255, (int)((15 + 20 * pill_ht) * a)), 9.f, 0, 0.75f);
				dl->AddText(ImVec2(pmin.x + 8.f, pmin.y + (pill_h - pill_ts.y) * 0.5f),
					IM_COL32(160, 158, 190, (int)((200 + 40 * pill_ht) * a)), pill_text.c_str());

				ImGui::InvisibleButton("##model_pill", ImVec2(pill_w, pill_h));
				if (ImGui::IsItemClicked())
					model_open = !model_open;
				if (ImGui::IsItemHovered())
					ImGui::SetTooltip("Click to change model");


				if (model_open) {
					ImGui::SetNextWindowPos(ImVec2(pmin.x, pmin.y - 6.f), ImGuiCond_Always, ImVec2(0.f, 1.f));
					ImGui::SetNextWindowBgAlpha(0.96f);
					ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 8.f);
					ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(6.f, 6.f));
					ImGui::PushStyleColor(ImGuiCol_PopupBg, ImVec4(0.09f, 0.09f, 0.13f, 1.f));
					ImGui::PushStyleColor(ImGuiCol_Border, ImVec4(1, 1, 1, 0.08f));

					if (ImGui::Begin("##model_popup", &model_open,
						ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
						ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_NoSavedSettings))
					{
						for (auto& profile : g_sa_settings.provider_profiles) {
							bool is_active = (profile.id == g_sa_settings.active_provider_profile_id);
							if (is_active) ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(ax3, ay3, az3, 1.f));
							if (ImGui::Selectable(profile.display_name.c_str(), is_active, 0, ImVec2(180.f, 0.f))) {
								g_sa_settings.active_provider_profile_id = profile.id;
								g_sa_settings.sync_legacy_fields_from_active_profile();
								g_sa_settings.save();
							}
							if (is_active) ImGui::PopStyleColor();
						}

						ImGui::Separator();

						if (auto* current_profile = g_sa_settings.get_active_profile()) {
							const auto& model_list = settings_sa_t::models_for_kind(current_profile->kind);
							for (const auto& m : model_list) {
								bool is_sel = (current_profile->model == m);
								if (is_sel) ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(ax3, ay3, az3, 1.f));
								if (ImGui::Selectable(m.c_str(), is_sel, 0, ImVec2(200.f, 0.f))) {
									current_profile->model = m;
									g_sa_settings.sync_legacy_fields_from_active_profile();
									g_sa_settings.save();
									model_open = false;
								}
								if (is_sel) ImGui::PopStyleColor();
							}
						}
					}
					ImGui::End();
					ImGui::PopStyleColor(2);
					ImGui::PopStyleVar(2);


					if (!ImGui::IsWindowHovered(ImGuiHoveredFlags_AnyWindow) && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
						model_open = false;
				}
			}

			ImGui::SetCursorPos(ImVec2(0.f, input_y));
			ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0.08f, 0.08f, 0.12f, 0.85f * a));
			ImGui::PushStyleColor(ImGuiCol_Border,  ImVec4(1, 1, 1, 0.08f * a));
			ImGui::PushStyleColor(ImGuiCol_Text,    ImVec4(0.92f, 0.91f, 1.f, a));
			ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 8.f);
			ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(8.f, input_pad));
			ImU32 input_bg_col = ImGui::GetColorU32(ImGuiCol_FrameBg);


			static bool s_enter_pressed = false;
			auto input_callback = [](ImGuiInputTextCallbackData* data) -> int {
				if (data->EventFlag == ImGuiInputTextFlags_CallbackAlways) {
					bool enter_now = ImGui::IsKeyPressed(ImGuiKey_Enter, false) || ImGui::IsKeyPressed(ImGuiKey_KeypadEnter, false);
					bool shift = ImGui::GetIO().KeyShift;
					if (enter_now && !shift) {
						s_enter_pressed = true;
					}
				}
				return 0;
			};

			float input_w = cw - btn_sz - igap;
			ImGui::InputTextMultiline("##chatinput", g_chat_buf, sizeof(g_chat_buf),
				ImVec2(input_w, input_h),
				ImGuiInputTextFlags_CallbackAlways | ImGuiInputTextFlags_CtrlEnterForNewLine,
				input_callback);
			bool enter_pressed = s_enter_pressed;
			s_enter_pressed = false;

			bool input_active = ImGui::IsItemActive();
			ImVec2 input_min  = ImGui::GetItemRectMin();
			ImVec2 input_max  = ImGui::GetItemRectMax();
			ImGui::PopStyleVar(2);
			ImGui::PopStyleColor(3);


			if (!input_active && g_chat_buf[0] == '\0')
			{
				float ph_y = input_min.y + input_pad;
				dl->AddText(ImVec2(input_min.x + 8.f, ph_y),
					IM_COL32(110, 105, 145, (int)(140 * a)), "Ask anything...");
			}


			float btn_y = input_y + input_h - btn_sz;
			ImGui::SetCursorPos(ImVec2(input_w + igap, btn_y));
			ImVec2 btn_min = ImGui::GetCursorScreenPos();
			ImVec2 btn_max = ImVec2(btn_min.x + btn_sz, btn_min.y + btn_sz);
			ImVec2 btn_ctr = ImVec2((btn_min.x + btn_max.x) * 0.5f, (btn_min.y + btn_max.y) * 0.5f);

			bool btn_hovered = ImGui::IsMouseHoveringRect(btn_min, btn_max);
			ImGui::InvisibleButton("##sendbtn", ImVec2(btn_sz, btn_sz));
			bool btn_clicked = ImGui::IsItemClicked();

			static float btn_ht    = 0.f;
			static float btn_flash = 0.f;

			btn_ht    += ((btn_hovered ? 1.f : 0.f) - btn_ht) * std::min(10.f * dt, 1.f);
			btn_flash  = std::max(0.f, btn_flash - 5.f * dt);

			if (btn_clicked)
				btn_flash = 1.f;

			ImVec4 bg_f = ImGui::ColorConvertU32ToFloat4(input_bg_col);
			float btn_alpha = bg_f.w + btn_ht * 0.07f + btn_flash * 0.55f;
			dl->AddRectFilled(btn_min, btn_max,
				IM_COL32(255, 255, 255, (int)(btn_alpha * 255.f)), 8.f);

			if (g_send_icon_srv)
			{
				float icon_sz = btn_sz * 0.52f;
				float ix = btn_ctr.x - icon_sz * 0.5f;
				float iy = btn_ctr.y - icon_sz * 0.5f;
				dl->AddImage((ImTextureID)g_send_icon_srv,
					ImVec2(ix, iy), ImVec2(ix + icon_sz, iy + icon_sz),
					ImVec2(0, 0), ImVec2(1, 1),
					IM_COL32(255, 255, 255, (int)(220 * a)));
			}

			if ((enter_pressed || btn_clicked) && strlen(g_chat_buf) > 0)
			{

				size_t len = strlen(g_chat_buf);
				while (len > 0 && (g_chat_buf[len-1] == '\n' || g_chat_buf[len-1] == '\r'))
					g_chat_buf[--len] = '\0';
				if (len > 0) {
					g_chat_messages.push_back({ g_chat_buf, "", true, false, false });
					g_chat_scroll_to_bottom = true;
				}
				g_chat_buf[0] = '\0';
			}
		}
	}
	end_child();

	tick_ai_chat();
	poll_ai_chat();
	render_settings_popup();
	ImGui::PopStyleVar();
	ImGui::End();
}
