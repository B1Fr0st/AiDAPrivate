#include "helpers.h"
#include "globals.h"
#include <commdlg.h>
#include <shlobj.h>
#include <fstream>
#include <filesystem>
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
#include "../core/code_editor.hpp"
#include "../core/disasm_view.hpp"
#include "../core/hex_view.hpp"
#include "../core/chat_render.hpp"
#include "../core/standalone_driver.hpp"
#include "../core/mcp_client.hpp"
#include "../core/sandbox.hpp"
#include "../core/workspace_search.hpp"
#include "../core/terminal_view.hpp"
#include "../core/mcp_marketplace.hpp"

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


#include <filesystem>
#include <shlobj.h>

std::string conversations::get_storage_dir()
{
	wchar_t* appdata = nullptr;
	if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, nullptr, &appdata))) {
		auto p = std::filesystem::path(appdata) / L"AiDA" / L"Standalone" / L"conversations";
		CoTaskMemFree(appdata);
		std::filesystem::create_directories(p);
		return p.string();
	}
	return {};
}

void conversations::save_current()
{
	if (g_chat_messages.empty()) return;
	std::string dir = get_storage_dir();
	if (dir.empty()) return;

	if (current_id.empty()) {
		auto now = std::chrono::system_clock::now().time_since_epoch();
		current_id = std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(now).count());
	}

	nlohmann::json j;
	j["id"] = current_id;
	std::string title;
	for (auto& m : g_chat_messages) {
		if (m.is_user && !m.text.empty()) {
			title = m.text.substr(0, 80);
			break;
		}
	}
	j["title"] = title;
	j["created"] = g_chat_messages.front().timestamp;
	nlohmann::json msgs = nlohmann::json::array();
	for (auto& m : g_chat_messages) {
		nlohmann::json mj;
		mj["text"] = m.text;
		mj["thinking_text"] = m.thinking_text;
		mj["is_user"] = m.is_user;
		mj["has_thinking"] = m.has_thinking;
		mj["timestamp"] = m.timestamp;
		mj["input_tokens"] = m.input_tokens;
		mj["output_tokens"] = m.output_tokens;
		mj["cache_read_tokens"] = m.cache_read_tokens;
		mj["cache_write_tokens"] = m.cache_write_tokens;
		msgs.push_back(mj);
	}
	j["messages"] = msgs;

	std::string path = dir + "\\" + current_id + ".json";
	std::ofstream ofs(path, std::ios::trunc);
	if (ofs.is_open()) ofs << j.dump(2);
}

void conversations::load_conversation(const std::string& id)
{
	std::string dir = get_storage_dir();
	if (dir.empty()) return;
	std::string path = dir + "\\" + id + ".json";
	std::ifstream ifs(path);
	if (!ifs.is_open()) return;
	auto j = nlohmann::json::parse(ifs, nullptr, false);
	if (j.is_discarded() || !j.is_object()) return;

	g_chat_messages.clear();
	current_id = j.value("id", id);
	for (auto& mj : j.value("messages", nlohmann::json::array())) {
		ChatMessage m;
		m.text = mj.value("text", "");
		m.thinking_text = mj.value("thinking_text", "");
		m.is_user = mj.value("is_user", false);
		m.has_thinking = mj.value("has_thinking", false);
		m.streaming = false;
		m.timestamp = mj.value("timestamp", (int64_t)0);
		m.input_tokens = mj.value("input_tokens", 0);
		m.output_tokens = mj.value("output_tokens", 0);
		m.cache_read_tokens = mj.value("cache_read_tokens", 0);
		m.cache_write_tokens = mj.value("cache_write_tokens", 0);
		g_chat_messages.push_back(m);
	}
	g_chat_scroll_to_bottom = true;
}

void conversations::new_chat()
{
	save_current();
	g_chat_messages.clear();
	g_chat_buf[0] = '\0';
	current_id.clear();
	g_chat_scroll_to_bottom = true;
	refresh_history();
}

void conversations::refresh_history()
{
	history.clear();
	std::string dir = get_storage_dir();
	if (dir.empty()) return;
	for (auto& entry : std::filesystem::directory_iterator(dir)) {
		if (!entry.is_regular_file()) continue;
		if (entry.path().extension() != ".json") continue;
		std::ifstream ifs(entry.path());
		auto j = nlohmann::json::parse(ifs, nullptr, false);
		if (j.is_discarded() || !j.is_object()) continue;
		ConversationSummary s;
		s.id = j.value("id", entry.path().stem().string());
		s.title = j.value("title", "Untitled");
		s.created = j.value("created", (int64_t)0);
		auto msgs = j.value("messages", nlohmann::json::array());
		s.msg_count = (int)msgs.size();
		history.push_back(s);
	}
	std::sort(history.begin(), history.end(), [](auto& a, auto& b) { return a.created > b.created; });
}

void conversations::delete_conversation(const std::string& id)
{
	std::string dir = get_storage_dir();
	if (dir.empty()) return;
	std::string path = dir + "\\" + id + ".json";
	std::filesystem::remove(path);
	refresh_history();
}

void helpers::render_title()
{
	float dt = ImGui::GetIO().DeltaTime;
	globals::ui::load_timer += dt;


	{
		static uint64_t s_frame_ctr = 0;
		standalone_license::cross_validation_sweep(s_frame_ctr++);
	}


	{
		uint64_t gt = standalone_license::inline_gate_check(
			standalone_license::gate_ui_render_loop);
		(void)standalone_license::verify_gate_token(
			standalone_license::gate_ui_render_loop, gt);
	}

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


	if (!ImGui::GetIO().WantTextInput) {
		bool ctrl  = ImGui::GetIO().KeyCtrl;
		bool shift = ImGui::GetIO().KeyShift;


		if (ctrl && !shift && ImGui::IsKeyPressed(ImGuiKey_B, false)) {
			globals::ui::panel_left_visible = !globals::ui::panel_left_visible;
			g_sa_settings.workspace.left_visible = globals::ui::panel_left_visible;
			g_sa_settings.save();
		}

		if (ctrl && !shift && ImGui::IsKeyPressed(ImGuiKey_J, false)) {
			globals::ui::panel_right_visible = !globals::ui::panel_right_visible;
			g_sa_settings.workspace.right_visible = globals::ui::panel_right_visible;
			g_sa_settings.save();
		}

		if (ctrl && ImGui::IsKeyPressed(ImGuiKey_GraveAccent, false)) {
			globals::ui::panel_bottom_visible = !globals::ui::panel_bottom_visible;
			g_sa_settings.workspace.bottom_visible = globals::ui::panel_bottom_visible;
			g_sa_settings.save();
		}

		if (ctrl && !shift && ImGui::IsKeyPressed(ImGuiKey_S, false) && code_editor::active) {
			code_editor::save();
		}

		if (ctrl && !shift && ImGui::IsKeyPressed(ImGuiKey_N, false)) {
			file_tabs::open_or_focus("", "untitled", "");
		}

		if (ctrl && !shift && ImGui::IsKeyPressed(ImGuiKey_W, false)) {
			file_tabs::close_tab(file_tabs::active_tab);
		}

		if (ctrl && !shift && ImGui::IsKeyPressed(ImGuiKey_Tab, false)) {
			if (!file_tabs::tabs.empty()) {
				file_tabs::active_tab = (file_tabs::active_tab + 1) % (int)file_tabs::tabs.size();
				auto& t = file_tabs::tabs[file_tabs::active_tab];
				std::string c; FILE* ff = nullptr; fopen_s(&ff, t.filepath.c_str(), "rb");
				if (ff) { fseek(ff,0,SEEK_END); long sz=ftell(ff); fseek(ff,0,SEEK_SET); c.resize(sz); fread(&c[0],1,sz,ff); fclose(ff); }
				code_editor::load(c, t.filename, t.filepath);
			}
		}

		if (ctrl && shift && ImGui::IsKeyPressed(ImGuiKey_Tab, false)) {
			if (!file_tabs::tabs.empty()) {
				file_tabs::active_tab = (file_tabs::active_tab - 1 + (int)file_tabs::tabs.size()) % (int)file_tabs::tabs.size();
				auto& t = file_tabs::tabs[file_tabs::active_tab];
				std::string c; FILE* ff = nullptr; fopen_s(&ff, t.filepath.c_str(), "rb");
				if (ff) { fseek(ff,0,SEEK_END); long sz=ftell(ff); fseek(ff,0,SEEK_SET); c.resize(sz); fread(&c[0],1,sz,ff); fclose(ff); }
				code_editor::load(c, t.filename, t.filepath);
			}
		}

		if (ctrl && ImGui::IsKeyPressed(ImGuiKey_Comma, false)) {
			g_settings_open = true;
		}

		if (ctrl && shift && ImGui::IsKeyPressed(ImGuiKey_P, false)) {
			globals::ui::command_palette_open = !globals::ui::command_palette_open;
		}

		if (ctrl && shift && ImGui::IsKeyPressed(ImGuiKey_F, false)) {
			globals::ui::active_activity = activity_item_t::search;
			globals::ui::panel_left_visible = true;
		}
	}

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
	const float menu_h   = 22.f;
	const float status_h = 24.f;
	float ww = globals::ui::window_w;
	float wh = globals::ui::window_h;


	{
		static bool s_layout_synced = false;
		if (!s_layout_synced) {
			globals::ui::panel_left_w  = g_sa_settings.workspace.left_width;
			globals::ui::panel_right_w = g_sa_settings.workspace.right_width;
			globals::ui::panel_bottom_h = g_sa_settings.workspace.bottom_height;
			globals::ui::panel_left_visible  = g_sa_settings.workspace.left_visible;
			globals::ui::panel_right_visible = g_sa_settings.workspace.right_visible;
			globals::ui::panel_bottom_visible = g_sa_settings.workspace.bottom_visible;
			s_layout_synced = true;
		}
	}

	float usable = ww - pad * 2.f - gap * 2.f;
	float min_panel = 80.f;
	float max_left  = usable * 0.3f;
	float max_right = usable * 0.4f;
	float left_w   = globals::ui::panel_left_visible ? globals::ui::panel_left_w : 0.f;
	float right_w  = globals::ui::panel_right_visible ? globals::ui::panel_right_w : 0.f;
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
	if (globals::ui::panel_left_visible && left_w < min_panel) left_w = min_panel;
	if (globals::ui::panel_right_visible && right_w < min_panel) right_w = min_panel;
	if (globals::ui::panel_left_visible) globals::ui::panel_left_w = left_w;
	if (globals::ui::panel_right_visible) globals::ui::panel_right_w = right_w;
	center_w = usable - left_w - right_w;
	if (center_w < 100.f) center_w = 100.f;

	float bottom_h = globals::ui::panel_bottom_visible ? globals::ui::panel_bottom_h : 0.f;
	float chrome_h = title_h + menu_h + status_h;
	float total_h  = wh - pad * 2.f - chrome_h - (globals::ui::panel_bottom_visible ? (bottom_h + gap) : 0.f);
	float content_top = pad + title_h + menu_h;

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
		ImDrawList* dl = ImGui::GetWindowDrawList();
		float ax = globals::ui::accent.x * 255.f;
		float ay = globals::ui::accent.y * 255.f;
		float az = globals::ui::accent.z * 255.f;
		float my0 = wp.y + title_h;
		float my1 = my0 + menu_h;


		dl->AddRectFilled(ImVec2(wp.x, my0), ImVec2(wp.x + ww, my1),
			IM_COL32(18, 18, 24, (int)(230 * a)));
		dl->AddLine(ImVec2(wp.x, my1), ImVec2(wp.x + ww, my1),
			IM_COL32(255, 255, 255, (int)(6 * a)));

		struct MenuItem {
			const char* label;
			int         id;
		};
		static const MenuItem menus[] = {
			{"File", 0}, {"Edit", 1}, {"View", 2}, {"Tools", 3}, {"AI", 4}, {"Help", 5}
		};

		float mx_cursor = wp.x + 12.f;
		for (int i = 0; i < 6; i++) {
			ImVec2 ts = ImGui::CalcTextSize(menus[i].label);
			float btn_w = ts.x + 16.f;
			ImVec2 bmin(mx_cursor, my0 + 1.f);
			ImVec2 bmax(mx_cursor + btn_w, my1 - 1.f);
			bool hov = ImGui::IsMouseHoveringRect(bmin, bmax);
			bool is_open = (menu_bar::open_menu == i);

			if (hov || is_open)
				dl->AddRectFilled(bmin, bmax, IM_COL32(255, 255, 255, is_open ? (int)(18 * a) : (int)(10 * a)), 3.f);

			dl->AddText(ImVec2(mx_cursor + 8.f, my0 + (menu_h - ts.y) * 0.5f),
				IM_COL32(200, 200, 215, (int)((hov || is_open ? 255 : 180) * a)), menus[i].label);

			if (hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
				menu_bar::open_menu = is_open ? -1 : i;
				menu_bar::any_open = (menu_bar::open_menu >= 0);
			}
			if (hov && menu_bar::any_open && !is_open) {
				menu_bar::open_menu = i;
			}


			if (is_open) {
				ImGui::SetNextWindowPos(ImVec2(bmin.x, my1 + 1.f));
				ImGui::SetNextWindowBgAlpha(0.97f);
				ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 6.f);
				ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(4.f, 6.f));
				ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(0.f, 0.f));
				ImGui::PushStyleColor(ImGuiCol_PopupBg, ImVec4(0.09f, 0.09f, 0.13f, 1.f));
				ImGui::PushStyleColor(ImGuiCol_Border, ImVec4(1, 1, 1, 0.06f));

				char popup_id[32];
				snprintf(popup_id, sizeof(popup_id), "##menu_%d", i);
				ImGui::OpenPopup(popup_id);

				if (ImGui::BeginPopup(popup_id)) {
					float mw = 210.f;
					float ih = 24.f;

					auto menu_item = [&](const char* label, const char* shortcut, bool enabled = true) -> bool {
						ImVec2 cp = ImGui::GetCursorScreenPos();
						ImVec2 rmin = cp;
						ImVec2 rmax(cp.x + mw, cp.y + ih);
						bool mhov = enabled && ImGui::IsMouseHoveringRect(rmin, rmax);
						if (mhov) ImGui::GetWindowDrawList()->AddRectFilled(rmin, rmax, IM_COL32(255, 255, 255, 14), 3.f);
						ImU32 tc = enabled ? IM_COL32(210, 210, 220, 230) : IM_COL32(100, 100, 110, 120);
						ImGui::GetWindowDrawList()->AddText(ImVec2(cp.x + 12.f, cp.y + (ih - ImGui::GetFontSize()) * 0.5f), tc, label);
						if (shortcut && shortcut[0]) {
							ImVec2 sts = ImGui::CalcTextSize(shortcut);
							ImGui::GetWindowDrawList()->AddText(ImVec2(cp.x + mw - sts.x - 12.f, cp.y + (ih - ImGui::GetFontSize()) * 0.5f),
								IM_COL32(100, 100, 120, 150), shortcut);
						}
						ImGui::Dummy(ImVec2(mw, ih));
						bool clicked = mhov && ImGui::IsMouseClicked(ImGuiMouseButton_Left);
						if (clicked) { menu_bar::open_menu = -1; menu_bar::any_open = false; ImGui::CloseCurrentPopup(); }
						return clicked;
					};

					auto menu_sep = [&]() {
						ImVec2 cp = ImGui::GetCursorScreenPos();
						ImGui::GetWindowDrawList()->AddLine(ImVec2(cp.x + 8.f, cp.y + 3.f), ImVec2(cp.x + mw - 8.f, cp.y + 3.f),
							IM_COL32(255, 255, 255, 14));
						ImGui::Dummy(ImVec2(mw, 7.f));
					};

					switch (i) {
					case 0:
					{
						if (menu_item("New File", "Ctrl+N")) {
							code_editor::load("", "untitled", "");
							file_tabs::open_or_focus("", "untitled", "");
						}
						if (menu_item("Open File...", "Ctrl+O")) {
							char buf[MAX_PATH] = {};
							OPENFILENAMEA ofn = {};
							ofn.lStructSize = sizeof(ofn);
							ofn.hwndOwner = g_hwnd;
							ofn.lpstrFile = buf;
							ofn.nMaxFile = MAX_PATH;
							ofn.lpstrFilter = "All Files\0*.*\0C/C++\0*.c;*.cpp;*.h;*.hpp\0";
							ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_NOCHANGEDIR;
							if (GetOpenFileNameA(&ofn)) {
								std::string content;
								FILE* f = nullptr;
								fopen_s(&f, buf, "rb");
								if (f) {
									fseek(f, 0, SEEK_END);
									long sz = ftell(f);
									fseek(f, 0, SEEK_SET);
									content.resize(sz);
									fread(&content[0], 1, sz, f);
									fclose(f);
								}
								std::string fname = buf;
								auto pos = fname.find_last_of("\\/");
								if (pos != std::string::npos) fname = fname.substr(pos + 1);
								file_tabs::open_or_focus(buf, fname, content);
							}
						}
						if (menu_item("Open Folder...", "Ctrl+K")) {
							char folder[MAX_PATH] = {};
							BROWSEINFOA bi = {};
							bi.lpszTitle = "Open Workspace Folder";
							bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
							PIDLIST_ABSOLUTE pid = SHBrowseForFolderA(&bi);
							if (pid) {
								SHGetPathFromIDListA(pid, folder);
								CoTaskMemFree(pid);
								file_browser::refresh(folder);
								g_sa_settings.workspace.root_path = folder;
								g_sa_settings.save();
							}
						}
						menu_sep();
						if (menu_item("Save", "Ctrl+S", code_editor::active)) {
							code_editor::save();
						}
						if (menu_item("Save As...", "Ctrl+Shift+S", code_editor::active)) {
							char buf[MAX_PATH] = {};
							if (!code_editor::filename.empty())
								strncpy_s(buf, code_editor::filename.c_str(), _TRUNCATE);
							OPENFILENAMEA sfn = {};
							sfn.lStructSize = sizeof(sfn);
							sfn.hwndOwner = g_hwnd;
							sfn.lpstrFile = buf;
							sfn.nMaxFile = MAX_PATH;
							sfn.lpstrFilter = "All Files\0*.*\0";
							sfn.Flags = OFN_OVERWRITEPROMPT | OFN_NOCHANGEDIR;
							if (GetSaveFileNameA(&sfn)) {
								code_editor::filepath = buf;
								std::string fn = buf;
								auto p = fn.find_last_of("\\/");
								if (p != std::string::npos) fn = fn.substr(p + 1);
								code_editor::filename = fn;
								code_editor::save();
							}
						}
						menu_sep();
						if (menu_item("Exit", "Alt+F4")) {
							DestroyWindow(g_hwnd);
						}
						break;
					}
					case 1:
					{
						if (menu_item("Undo",    "Ctrl+Z", code_editor::active)) {
							code_editor_widget::trigger_undo();
						}
						if (menu_item("Redo",    "Ctrl+Y", code_editor::active)) {
							code_editor_widget::trigger_redo();
						}
						menu_sep();
						menu_item("Cut",     "Ctrl+X", false);
						menu_item("Copy",    "Ctrl+C", false);
						menu_item("Paste",   "Ctrl+V", false);
						menu_sep();
						if (menu_item("Find",    "Ctrl+F", code_editor::active)) {
							code_editor_widget::open_find();
						}
						if (menu_item("Replace", "Ctrl+H", code_editor::active)) {
							code_editor_widget::open_replace();
						}
						break;
					}
					case 2:
					{
						if (menu_item(globals::ui::panel_left_visible ? "Hide Explorer" : "Show Explorer", "Ctrl+B")) {
							globals::ui::panel_left_visible = !globals::ui::panel_left_visible;
							g_sa_settings.workspace.left_visible = globals::ui::panel_left_visible;
							g_sa_settings.save();
						}
						if (menu_item(globals::ui::panel_right_visible ? "Hide Chat" : "Show Chat", "Ctrl+J")) {
							globals::ui::panel_right_visible = !globals::ui::panel_right_visible;
							g_sa_settings.workspace.right_visible = globals::ui::panel_right_visible;
							g_sa_settings.save();
						}
						if (menu_item(globals::ui::panel_bottom_visible ? "Hide Output" : "Show Output", "Ctrl+`")) {
							globals::ui::panel_bottom_visible = !globals::ui::panel_bottom_visible;
							g_sa_settings.workspace.bottom_visible = globals::ui::panel_bottom_visible;
							g_sa_settings.save();
						}
						menu_sep();
						menu_item("Zoom In",  "Ctrl+=", false);
						menu_item("Zoom Out", "Ctrl+-", false);
						break;
					}
					case 3:
					{
						if (menu_item("Load PE File...", "")) {
							std::string fpath = disasm::open_file_dialog(g_hwnd);
							if (!fpath.empty()) {
								g_disasm.file = DisasmFile{};
								disasm::load_pe(fpath, g_disasm.file);
								if (g_disasm.file.loaded) disasm::decode_section(g_disasm.file);
							}
						}
						if (menu_item("Attach to Process...", "")) {
							globals::ui::process_attach_open = true;
						}
						menu_sep();
						if (menu_item("MCP Servers", "")) {
							g_settings_open = true;
						}
						if (menu_item("Driver Status", "")) {
							globals::ui::driver_status_open = true;
						}
						break;
					}
					case 4:
					{
						if (menu_item("New Chat", "Ctrl+L")) {
							conversations::new_chat();
						}
						if (menu_item("Model Settings", "")) {
							g_settings_open = true;
						}
						break;
					}
					case 5:
					{
						if (menu_item("About", "")) {
							globals::ui::about_dialog_open = true;
						}
						if (menu_item("Keyboard Shortcuts", "Ctrl+K Ctrl+S")) {
							globals::ui::shortcuts_dialog_open = true;
						}
						break;
					}
					}
					ImGui::EndPopup();
				} else {
					menu_bar::open_menu = -1;
					menu_bar::any_open = false;
				}
				ImGui::PopStyleColor(2);
				ImGui::PopStyleVar(3);
			}

			mx_cursor += btn_w;
		}


		if (menu_bar::any_open && ImGui::IsMouseClicked(ImGuiMouseButton_Left) &&
			!ImGui::IsMouseHoveringRect(ImVec2(wp.x, my0), ImVec2(wp.x + ww, my1)) &&
			!ImGui::IsPopupOpen(nullptr, ImGuiPopupFlags_AnyPopupId | ImGuiPopupFlags_AnyPopupLevel)) {
			menu_bar::open_menu = -1;
			menu_bar::any_open = false;
		}


		if (ImGui::GetIO().KeyCtrl) {
			if (ImGui::IsKeyPressed(ImGuiKey_S) && code_editor::active)
				code_editor::save();
			if (ImGui::IsKeyPressed(ImGuiKey_B)) {
				globals::ui::panel_left_visible = !globals::ui::panel_left_visible;
				g_sa_settings.workspace.left_visible = globals::ui::panel_left_visible;
			}
			if (ImGui::IsKeyPressed(ImGuiKey_J)) {
				globals::ui::panel_right_visible = !globals::ui::panel_right_visible;
				g_sa_settings.workspace.right_visible = globals::ui::panel_right_visible;
			}
			if (ImGui::IsKeyPressed(ImGuiKey_GraveAccent)) {
				globals::ui::panel_bottom_visible = !globals::ui::panel_bottom_visible;
				g_sa_settings.workspace.bottom_visible = globals::ui::panel_bottom_visible;
			}
			if (ImGui::IsKeyPressed(ImGuiKey_L)) {
				conversations::new_chat();
			}
			if (ImGui::GetIO().KeyShift && ImGui::IsKeyPressed(ImGuiKey_P)) {
				globals::ui::command_palette_open = !globals::ui::command_palette_open;
				globals::ui::command_palette_buf[0] = '\0';
			}
		}
	}


	{
		ImVec2 wp = ImGui::GetWindowPos();
		float  sp_w = 5.f;


		float ls_x = wp.x + pad + left_w;
		ImVec2 ls_min(ls_x - sp_w * 0.5f, wp.y + content_top);
		ImVec2 ls_max(ls_x + sp_w * 0.5f + gap, wp.y + content_top + total_h);

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
		ImVec2 rs_min(rs_x - sp_w * 0.5f - gap, wp.y + content_top);
		ImVec2 rs_max(rs_x + sp_w * 0.5f, wp.y + content_top + total_h);

		bool rs_hov = globals::ui::panel_right_visible && ImGui::IsMouseHoveringRect(rs_min, rs_max);
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


		if (globals::ui::panel_bottom_visible) {
			float bs_y = wp.y + content_top + total_h;
			ImVec2 bs_min(wp.x + pad, bs_y - sp_w * 0.5f);
			ImVec2 bs_max(wp.x + ww - pad, bs_y + sp_w * 0.5f + gap);
			bool bs_hov = ImGui::IsMouseHoveringRect(bs_min, bs_max);
			if (bs_hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
				globals::ui::dragging_bottom_splitter = true;
			if (!ImGui::IsMouseDown(ImGuiMouseButton_Left))
				globals::ui::dragging_bottom_splitter = false;
			if (globals::ui::dragging_bottom_splitter) {
				float my = wp.y + wh - pad - status_h - ImGui::GetIO().MousePos.y;
				globals::ui::panel_bottom_h = std::clamp(my, 80.f, wh * 0.5f);

			}
			if (bs_hov || globals::ui::dragging_bottom_splitter)
				ImGui::SetMouseCursor(ImGuiMouseCursor_ResizeNS);
		}

		left_w   = globals::ui::panel_left_visible ? globals::ui::panel_left_w : 0.f;
		right_w  = globals::ui::panel_right_visible ? globals::ui::panel_right_w : 0.f;
		center_w = ww - left_w - right_w - pad * 2.f - gap * 2.f;
		if (center_w < 200.f) center_w = 200.f;

		bottom_h = globals::ui::panel_bottom_visible ? globals::ui::panel_bottom_h : 0.f;
		total_h = wh - pad * 2.f - chrome_h - (globals::ui::panel_bottom_visible ? (bottom_h + gap) : 0.f);
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
	float fb_y = content_top;


	if (g_sa_settings.activity_bar_visible) {
		const float ab_w = globals::ui::activity_bar_w;
		ImVec2 ab_pos(wp_m.x + pad, wp_m.y + content_top);
		ImVec2 ab_end(ab_pos.x + ab_w, ab_pos.y + total_h);

		wdl->AddRectFilled(ab_pos, ab_end, IM_COL32(18, 18, 26, (int)(230 * a)), 8.f, ImDrawFlags_RoundCornersLeft);
		wdl->AddLine(ImVec2(ab_end.x, ab_pos.y), ImVec2(ab_end.x, ab_end.y), IM_COL32(255, 255, 255, (int)(6 * a)));

		struct ab_entry { const char* icon; activity_item_t item; };
		static const ab_entry ab_items[] = {
			{ "\xEE\x80\x80", activity_item_t::explorer },
			{ "\xEE\x80\x81", activity_item_t::search },
			{ "\xEE\x80\x82", activity_item_t::debug },
			{ "\xEE\x80\x83", activity_item_t::extensions },
		};

		static const char* ab_labels[] = { "E", "S", "D", "X" };

		float iy = ab_pos.y + 8.f;
		for (int ai = 0; ai < 4; ai++) {
			bool active = (globals::ui::active_activity == ab_items[ai].item);
			float icon_sz = 28.f;
			ImVec2 imin(ab_pos.x + (ab_w - icon_sz) * 0.5f, iy);
			ImVec2 imax(imin.x + icon_sz, imin.y + icon_sz);
			bool ihov = ImGui::IsMouseHoveringRect(imin, imax);

			if (active) {
				wdl->AddRectFilled(imin, imax, IM_COL32((int)(ax3 * 60), (int)(ay3 * 60), (int)(az3 * 60), (int)(100 * a)), 4.f);
				wdl->AddLine(ImVec2(ab_pos.x, imin.y), ImVec2(ab_pos.x, imax.y),
					IM_COL32((int)(ax3 * 255), (int)(ay3 * 255), (int)(az3 * 255), (int)(220 * a)), 2.f);
			} else if (ihov) {
				wdl->AddRectFilled(imin, imax, IM_COL32(255, 255, 255, (int)(10 * a)), 4.f);
			}

			ImVec2 lts = ImGui::CalcTextSize(ab_labels[ai]);
			ImU32 ic = active ? IM_COL32(220, 220, 240, (int)(240 * a))
			                  : IM_COL32(110, 110, 130, (int)(160 * a));
			wdl->AddText(ImVec2(imin.x + (icon_sz - lts.x) * 0.5f, imin.y + (icon_sz - lts.y) * 0.5f), ic, ab_labels[ai]);

			if (ihov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
				if (globals::ui::active_activity == ab_items[ai].item && globals::ui::panel_left_visible) {
					globals::ui::panel_left_visible = false;
				} else {
					globals::ui::active_activity = ab_items[ai].item;
					globals::ui::panel_left_visible = true;
				}
			}
			iy += icon_sz + 6.f;
		}


		{
			float gear_sz = 28.f;
			ImVec2 gmin(ab_pos.x + (ab_w - gear_sz) * 0.5f, ab_end.y - gear_sz - 8.f);
			ImVec2 gmax(gmin.x + gear_sz, gmin.y + gear_sz);
			bool ghov = ImGui::IsMouseHoveringRect(gmin, gmax);
			if (ghov) wdl->AddRectFilled(gmin, gmax, IM_COL32(255, 255, 255, (int)(10 * a)), 4.f);
			ImVec2 gts = ImGui::CalcTextSize("*");
			ImU32 gc = ghov ? IM_COL32(220, 220, 240, (int)(220 * a)) : IM_COL32(110, 110, 130, (int)(160 * a));
			wdl->AddText(ImVec2(gmin.x + (gear_sz - gts.x) * 0.5f, gmin.y + (gear_sz - gts.y) * 0.5f), gc, "*");
			if (ghov && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
				g_settings_open = true;
		}

		fb_x = pad + ab_w;
	}

	if (globals::ui::panel_left_visible) {
	ImGui::SetCursorPos(ImVec2(fb_x, fb_y));
	begin_child("##filebrowser", ImVec2(fb_x, fb_y), ImVec2(left_w, total_h), a);
	{
		ImDrawList* fdl = ImGui::GetWindowDrawList();
		ImVec2 fwp = ImGui::GetWindowPos();
		float fw = ImGui::GetWindowWidth();
		float fh = ImGui::GetWindowHeight();

		if (globals::ui::active_activity == activity_item_t::search) {

			const char* search_lbl = "SEARCH";
			fdl->AddText(ImVec2(fwp.x + 10.f, fwp.y + 8.f),
				IM_COL32(130, 128, 155, (int)(180 * a)), search_lbl);

			float sy = 28.f;
			ImGui::SetCursorPos(ImVec2(6.f, sy));
			ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(6.f, 4.f));
			ImGui::PushStyleColor(ImGuiCol_FrameBg, IM_COL32(30, 30, 42, (int)(200 * a)));
			ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(200, 200, 215, (int)(230 * a)));
			ImGui::PushItemWidth(fw - 12.f);

			bool changed = ImGui::InputText("##ws_query", workspace_search::g_search.query_buf, sizeof(workspace_search::g_search.query_buf),
				ImGuiInputTextFlags_EnterReturnsTrue);
			if (changed || (ImGui::IsItemFocused() && ImGui::IsKeyPressed(ImGuiKey_Enter, false))) {
				workspace_search::start_search(file_browser::current_dir);
			}

			sy += 28.f;
			ImGui::SetCursorPos(ImVec2(6.f, sy));


			bool case_changed = ImGui::Checkbox("Aa", &workspace_search::g_search.case_sensitive);
			ImGui::SameLine();
			bool word_changed = ImGui::Checkbox("W", &workspace_search::g_search.whole_word);
			ImGui::SameLine();
			bool regex_changed = ImGui::Checkbox(".*", &workspace_search::g_search.use_regex);
			(void)case_changed; (void)word_changed; (void)regex_changed;

			sy += 24.f;
			ImGui::SetCursorPos(ImVec2(6.f, sy));
			ImGui::InputText("##ws_include", workspace_search::g_search.include_buf, sizeof(workspace_search::g_search.include_buf));
			sy += 24.f;
			ImGui::SetCursorPos(ImVec2(6.f, sy));
			ImGui::InputText("##ws_exclude", workspace_search::g_search.exclude_buf, sizeof(workspace_search::g_search.exclude_buf));

			ImGui::PopItemWidth();
			ImGui::PopStyleColor(2);
			ImGui::PopStyleVar();

			sy += 28.f;


			if (workspace_search::g_search.searching.load()) {
				fdl->AddText(ImVec2(fwp.x + 10.f, fwp.y + sy),
					IM_COL32(180, 180, 60, (int)(200 * a)), "Searching...");
				sy += 18.f;
			} else if (!workspace_search::g_search.results.empty()) {
				char count_buf[64];
				snprintf(count_buf, sizeof(count_buf), "%d results", (int)workspace_search::g_search.results.size());
				fdl->AddText(ImVec2(fwp.x + 10.f, fwp.y + sy),
					IM_COL32(130, 130, 155, (int)(160 * a)), count_buf);
				sy += 18.f;
			}


			ImGui::SetCursorPos(ImVec2(0.f, sy));
			ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.f, 0.f));
			ImGui::BeginChild("##ws_results", ImVec2(fw, fh - sy), false, ImGuiWindowFlags_NoBackground);
			{
				auto& results = workspace_search::g_search.results;
				float item_h2 = 36.f;
				for (int ri = 0; ri < (int)results.size() && ri < 500; ri++) {
					auto& r = results[ri];
					ImVec2 cp2 = ImGui::GetCursorScreenPos();
					ImVec2 rmin2(cp2.x, cp2.y);
					ImVec2 rmax2(cp2.x + fw, cp2.y + item_h2);
					bool rhov = ImGui::IsMouseHoveringRect(rmin2, rmax2, false);
					if (rhov) fdl->AddRectFilled(rmin2, rmax2, IM_COL32(255, 255, 255, (int)(10 * a)));


					std::string flabel = std::filesystem::path(r.filepath).filename().string()
						+ ":" + std::to_string(r.line_number);
					fdl->AddText(ImVec2(rmin2.x + 6.f, rmin2.y + 2.f),
						IM_COL32((int)(ax3*180+60), (int)(ay3*180+60), (int)(az3*180+60), (int)(200*a)),
						flabel.c_str());

					std::string preview = r.line_text.substr(0, (std::min)((size_t)80, r.line_text.size()));
					fdl->AddText(ImVec2(rmin2.x + 6.f, rmin2.y + 18.f),
						IM_COL32(160, 160, 180, (int)(170 * a)),
						preview.c_str());

					ImGui::Dummy(ImVec2(fw, item_h2));
					if (rhov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {

						std::ifstream ifs(r.filepath, std::ios::binary);
						if (ifs.is_open()) {
							std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
							auto fname = std::filesystem::path(r.filepath).filename().string();
							file_tabs::open_or_focus(r.filepath, fname, content);
							code_editor::load(content, fname, r.filepath);

							autocomplete::cursor_line = r.line_number - 1;
							autocomplete::cursor_col = r.col_start;
						}
					}
				}
			}
			ImGui::EndChild();
			ImGui::PopStyleVar();
		} else if (globals::ui::active_activity == activity_item_t::extensions) {


			const char* mkt_lbl = "EXTENSIONS";
			fdl->AddText(ImVec2(fwp.x + 10.f, fwp.y + 8.f),
				IM_COL32(130, 128, 155, static_cast<int>(180 * a)), mkt_lbl);

			float sy = 28.f;


			{
				ImGui::SetCursorPos(ImVec2(6.f, sy));
				ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(8.f, 3.f));
				ImGui::PushStyleColor(ImGuiCol_Button, IM_COL32(0, 0, 0, 0));
				ImGui::PushStyleColor(ImGuiCol_ButtonHovered, IM_COL32(255, 255, 255, static_cast<int>(20 * a)));

				ImU32 active_col = IM_COL32(
					static_cast<int>(ax3 * 200 + 55),
					static_cast<int>(ay3 * 200 + 55),
					static_cast<int>(az3 * 200 + 55),
					static_cast<int>(230 * a));
				ImU32 inactive_col = IM_COL32(130, 130, 155, static_cast<int>(160 * a));

				if (marketplace_ui::active_tab == 0)
					ImGui::PushStyleColor(ImGuiCol_Text, active_col);
				else
					ImGui::PushStyleColor(ImGuiCol_Text, inactive_col);
				if (ImGui::SmallButton("Browse")) marketplace_ui::active_tab = 0;
				ImGui::PopStyleColor();

				ImGui::SameLine();

				if (marketplace_ui::active_tab == 1)
					ImGui::PushStyleColor(ImGuiCol_Text, active_col);
				else
					ImGui::PushStyleColor(ImGuiCol_Text, inactive_col);
				if (ImGui::SmallButton("Installed")) marketplace_ui::active_tab = 1;
				ImGui::PopStyleColor();

				ImGui::PopStyleColor(2);
				ImGui::PopStyleVar();
				sy += 26.f;
			}

			if (marketplace_ui::active_tab == 0) {


				ImGui::SetCursorPos(ImVec2(6.f, sy));
				ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(6.f, 4.f));
				ImGui::PushStyleColor(ImGuiCol_FrameBg, IM_COL32(30, 30, 42, static_cast<int>(200 * a)));
				ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(200, 200, 215, static_cast<int>(230 * a)));
				ImGui::PushItemWidth(fw - 12.f);

				bool search_enter = ImGui::InputText("##mkt_search", marketplace_ui::search_buf,
					sizeof(marketplace_ui::search_buf), ImGuiInputTextFlags_EnterReturnsTrue);
				if (search_enter && marketplace_ui::search_buf[0] != '\0') {
					auto reg = marketplace_ui::registry_idx == 1
						? mcp_marketplace::registry_t::pypi
						: mcp_marketplace::registry_t::npm;
					mcp_marketplace::search_async(marketplace_ui::search_buf, reg);
				}

				ImGui::PopItemWidth();
				ImGui::PopStyleColor(2);
				ImGui::PopStyleVar();
				sy += 28.f;


				ImGui::SetCursorPos(ImVec2(6.f, sy));
				ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(4.f, 2.f));
				ImGui::PushStyleColor(ImGuiCol_FrameBg, IM_COL32(30, 30, 42, static_cast<int>(180 * a)));
				ImGui::PushItemWidth(80.f);
				const char* reg_items[] = { "npm", "PyPI" };
				ImGui::Combo("##mkt_reg", &marketplace_ui::registry_idx, reg_items, 2);
				ImGui::PopItemWidth();
				ImGui::PopStyleColor();
				ImGui::PopStyleVar();
				sy += 26.f;


				auto search_st = mcp_marketplace::get_search_state();
				if (search_st == mcp_marketplace::search_state_t::searching) {
					fdl->AddText(ImVec2(fwp.x + 10.f, fwp.y + sy),
						IM_COL32(180, 180, 60, static_cast<int>(200 * a)), "Searching...");
					sy += 18.f;
				} else if (search_st == mcp_marketplace::search_state_t::error_state) {
					auto& err = mcp_marketplace::get_search_error();
					fdl->AddText(ImVec2(fwp.x + 10.f, fwp.y + sy),
						IM_COL32(220, 80, 80, static_cast<int>(200 * a)),
						err.substr(0, 60).c_str());
					sy += 18.f;
				}


				ImGui::SetCursorPos(ImVec2(0.f, sy));
				ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.f, 0.f));
				ImGui::BeginChild("##mkt_results", ImVec2(fw, fh - sy), false, ImGuiWindowFlags_NoBackground);
				{
					auto results = mcp_marketplace::get_search_results();
					float item_h2 = 48.f;
					for (int ri = 0; ri < static_cast<int>(results.size()); ri++) {
						auto& r = results[ri];
						ImVec2 cp2 = ImGui::GetCursorScreenPos();
						ImVec2 rmin2(cp2.x, cp2.y);
						ImVec2 rmax2(cp2.x + fw, cp2.y + item_h2);
						bool rhov = ImGui::IsMouseHoveringRect(rmin2, rmax2, false);
						bool rsel = (ri == marketplace_ui::selected_idx);

						if (rsel)
							fdl->AddRectFilled(rmin2, rmax2,
								IM_COL32(static_cast<int>(ax3 * 60), static_cast<int>(ay3 * 60),
								         static_cast<int>(az3 * 60), static_cast<int>(80 * a)));
						else if (rhov)
							fdl->AddRectFilled(rmin2, rmax2, IM_COL32(255, 255, 255, static_cast<int>(10 * a)));


						fdl->AddText(ImVec2(rmin2.x + 6.f, rmin2.y + 2.f),
							IM_COL32(static_cast<int>(ax3 * 180 + 60), static_cast<int>(ay3 * 180 + 60),
							         static_cast<int>(az3 * 180 + 60), static_cast<int>(220 * a)),
							r.display_name.c_str());


						std::string ver_str = "v" + r.version;
						if (r.is_installed) ver_str += "  [installed]";
						fdl->AddText(ImVec2(rmin2.x + 6.f + ImGui::CalcTextSize(r.display_name.c_str()).x + 8.f, rmin2.y + 3.f),
							IM_COL32(100, 100, 120, static_cast<int>(160 * a)),
							ver_str.c_str());


						std::string desc = r.description.substr(0, 80);
						fdl->AddText(ImVec2(rmin2.x + 6.f, rmin2.y + 18.f),
							IM_COL32(160, 160, 180, static_cast<int>(170 * a)),
							desc.c_str());


						if (!r.author.empty()) {
							fdl->AddText(ImVec2(rmin2.x + 6.f, rmin2.y + 33.f),
								IM_COL32(110, 110, 130, static_cast<int>(140 * a)),
								r.author.c_str());
						}

						ImGui::Dummy(ImVec2(fw, item_h2));
						if (rhov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
							marketplace_ui::selected_idx = ri;
						}


						if (rhov && !r.is_installed) {
							ImVec2 btn_pos(rmax2.x - 60.f, rmin2.y + 14.f);
							ImVec2 btn_end(rmax2.x - 4.f, rmin2.y + 32.f);
							fdl->AddRectFilled(btn_pos, btn_end,
								IM_COL32(static_cast<int>(ax3 * 200 + 40), static_cast<int>(ay3 * 200 + 40),
								         static_cast<int>(az3 * 200 + 40), static_cast<int>(180 * a)), 3.f);
							fdl->AddText(ImVec2(btn_pos.x + 8.f, btn_pos.y + 2.f),
								IM_COL32(255, 255, 255, static_cast<int>(220 * a)), "Install");

							if (ImGui::IsMouseHoveringRect(btn_pos, btn_end, false) &&
								ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
								mcp_marketplace::install_async(r);
							}
						}
					}
				}
				ImGui::EndChild();
				ImGui::PopStyleVar();
			} else {

				ImGui::SetCursorPos(ImVec2(0.f, sy));
				ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.f, 0.f));
				ImGui::BeginChild("##mkt_installed", ImVec2(fw, fh - sy), false, ImGuiWindowFlags_NoBackground);
				{
					auto installed = mcp_marketplace::get_installed();
					if (installed.empty()) {
						fdl->AddText(ImVec2(fwp.x + 10.f, fwp.y + sy + 10.f),
							IM_COL32(130, 130, 155, static_cast<int>(160 * a)),
							"No MCP servers installed.");
					}
					float item_h2 = 40.f;
					for (int ii = 0; ii < static_cast<int>(installed.size()); ii++) {
						auto& srv = installed[ii];
						ImVec2 cp2 = ImGui::GetCursorScreenPos();
						ImVec2 rmin2(cp2.x, cp2.y);
						ImVec2 rmax2(cp2.x + fw, cp2.y + item_h2);
						bool rhov = ImGui::IsMouseHoveringRect(rmin2, rmax2, false);
						if (rhov)
							fdl->AddRectFilled(rmin2, rmax2, IM_COL32(255, 255, 255, static_cast<int>(10 * a)));


						fdl->AddText(ImVec2(rmin2.x + 6.f, rmin2.y + 2.f),
							IM_COL32(static_cast<int>(ax3 * 180 + 60), static_cast<int>(ay3 * 180 + 60),
							         static_cast<int>(az3 * 180 + 60), static_cast<int>(220 * a)),
							srv.package_name.c_str());


						std::string info_str = "v" + srv.version + " (" +
							(srv.registry == mcp_marketplace::registry_t::pypi ? "PyPI" : "npm") + ")";
						fdl->AddText(ImVec2(rmin2.x + 6.f, rmin2.y + 18.f),
							IM_COL32(130, 130, 150, static_cast<int>(160 * a)),
							info_str.c_str());


						if (rhov) {

							const char* toggle_lbl = srv.enabled ? "Off" : "On";
							ImVec2 t_pos(rmax2.x - 100.f, rmin2.y + 10.f);
							ImVec2 t_end(rmax2.x - 65.f, rmin2.y + 28.f);
							fdl->AddRectFilled(t_pos, t_end,
								IM_COL32(60, 60, 80, static_cast<int>(180 * a)), 3.f);
							fdl->AddText(ImVec2(t_pos.x + 5.f, t_pos.y + 1.f),
								IM_COL32(200, 200, 220, static_cast<int>(200 * a)), toggle_lbl);
							if (ImGui::IsMouseHoveringRect(t_pos, t_end, false) &&
								ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
								if (srv.enabled)
									mcp_marketplace::deactivate_server(srv.package_name);
								else
									mcp_marketplace::activate_server(srv);
							}


							ImVec2 u_pos(rmax2.x - 58.f, rmin2.y + 10.f);
							ImVec2 u_end(rmax2.x - 4.f, rmin2.y + 28.f);
							fdl->AddRectFilled(u_pos, u_end,
								IM_COL32(180, 50, 50, static_cast<int>(180 * a)), 3.f);
							fdl->AddText(ImVec2(u_pos.x + 4.f, u_pos.y + 1.f),
								IM_COL32(255, 255, 255, static_cast<int>(220 * a)), "Remove");
							if (ImGui::IsMouseHoveringRect(u_pos, u_end, false) &&
								ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
								mcp_marketplace::uninstall(srv.package_name);
							}
						}

						ImGui::Dummy(ImVec2(fw, item_h2));
					}
				}
				ImGui::EndChild();
				ImGui::PopStyleVar();
			}


			auto inst_st = mcp_marketplace::get_install_state();
			if (inst_st == mcp_marketplace::install_state_t::installing) {
				fdl->AddText(ImVec2(fwp.x + 10.f, fwp.y + fh - 20.f),
					IM_COL32(180, 180, 60, static_cast<int>(200 * a)), "Installing...");
			} else if (inst_st == mcp_marketplace::install_state_t::error_state) {
				auto& err = mcp_marketplace::get_install_error();
				fdl->AddText(ImVec2(fwp.x + 10.f, fwp.y + fh - 20.f),
					IM_COL32(220, 80, 80, static_cast<int>(200 * a)),
					err.substr(0, 50).c_str());
			} else if (inst_st == mcp_marketplace::install_state_t::done) {
				fdl->AddText(ImVec2(fwp.x + 10.f, fwp.y + fh - 20.f),
					IM_COL32(80, 200, 80, static_cast<int>(200 * a)), "Installed!");
			}

		} else {


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
	}
	end_child();
	}

	float ab_extra = g_sa_settings.activity_bar_visible ? globals::ui::activity_bar_w : 0.f;
	float left_gap = globals::ui::panel_left_visible ? (left_w + gap + ab_extra) : ab_extra;
	float right_gap_w = globals::ui::panel_right_visible ? (right_w + gap) : 0.f;
	float hx0 = wp_m.x + pad + left_gap, hy0 = wp_m.y + content_top;
	float hx1  = hx0 + center_w;
	float hy1  = hy0 + hdr_h;
	float dc_y1 = wp_m.y + content_top + total_h;

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


		if (!file_tabs::tabs.empty()) {
			const float tab_pad_x = 10.f;
			const float tab_gap   = 2.f;
			const float close_sz  = 10.f;
			const float tab_h     = row_h - 2.f;
			float tab_x = hx0 + hdr_pad;
			float tab_y = r1_cy - tab_h * 0.5f;
			float max_tab_x = rbtn_x0 - 8.f;

			int close_idx = -1;
			int click_idx = -1;

			for (int ti = 0; ti < (int)file_tabs::tabs.size(); ti++) {
				auto& tab = file_tabs::tabs[ti];
				bool is_active = (ti == file_tabs::active_tab);


				std::string label = tab.filename;
				if (tab.dirty) label += " *";

				ImVec2 lts = ImGui::CalcTextSize(label.c_str());
				float tw = tab_pad_x * 2.f + lts.x + close_sz + 6.f;


				if (tab_x + tw > max_tab_x) break;

				float tx0 = tab_x, ty0 = tab_y;
				float tx1 = tab_x + tw, ty1 = tab_y + tab_h;

				bool tab_hov = ImGui::IsMouseHoveringRect(ImVec2(tx0, ty0), ImVec2(tx1, ty1), false);


				if (is_active) {
					wdl->AddRectFilled(ImVec2(tx0, ty0), ImVec2(tx1, ty1),
						IM_COL32(255,255,255,(int)(16*a)), 4.f, ImDrawFlags_RoundCornersTop);

					wdl->AddLine(ImVec2(tx0 + 2.f, ty1), ImVec2(tx1 - 2.f, ty1),
						IM_COL32((int)(ax3*255),(int)(ay3*255),(int)(az3*255),(int)(200*a)), 2.f);
				} else if (tab_hov) {
					wdl->AddRectFilled(ImVec2(tx0, ty0), ImVec2(tx1, ty1),
						IM_COL32(255,255,255,(int)(8*a)), 4.f, ImDrawFlags_RoundCornersTop);
				}


				ImU32 tab_col = is_active ? ac_full
				              : IM_COL32(170, 175, 190, (int)((tab_hov ? 220.f : 160.f)*a));
				wdl->AddText(ImVec2(tx0 + tab_pad_x, ty0 + (tab_h - lts.y) * 0.5f),
					tab_col, label.c_str());


				float cx0 = tx1 - tab_pad_x - close_sz;
				float cy0 = ty0 + (tab_h - close_sz) * 0.5f;
				float cx1 = cx0 + close_sz, cy1 = cy0 + close_sz;
				bool close_hov = ImGui::IsMouseHoveringRect(ImVec2(cx0, cy0), ImVec2(cx1, cy1), false);
				if (close_hov) {
					wdl->AddRectFilled(ImVec2(cx0 - 1, cy0 - 1), ImVec2(cx1 + 1, cy1 + 1),
						IM_COL32(255,80,80,(int)(40*a)), 3.f);
				}
				ImU32 close_col = close_hov
					? IM_COL32(255,100,100,(int)(220*a))
					: IM_COL32(150,150,160,(int)((is_active ? 140.f : 80.f)*a));
				float cmx = (cx0 + cx1) * 0.5f, cmy = (cy0 + cy1) * 0.5f;
				float cr = 3.f;
				wdl->AddLine(ImVec2(cmx - cr, cmy - cr), ImVec2(cmx + cr, cmy + cr), close_col, 1.2f);
				wdl->AddLine(ImVec2(cmx + cr, cmy - cr), ImVec2(cmx - cr, cmy + cr), close_col, 1.2f);


				if (close_hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
					close_idx = ti;
				else if (tab_hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
					click_idx = ti;


				if (ti < (int)file_tabs::tabs.size() - 1) {
					wdl->AddLine(ImVec2(tx1, ty0 + 3.f), ImVec2(tx1, ty1 - 3.f),
						IM_COL32(255,255,255,(int)(8*a)), 1.f);
				}

				tab_x = tx1 + tab_gap;
			}


			if (close_idx >= 0)
				file_tabs::close_tab(close_idx);
			else if (click_idx >= 0 && click_idx != file_tabs::active_tab) {
				file_tabs::active_tab = click_idx;
				auto& t = file_tabs::tabs[click_idx];
				std::string content;
				FILE* f = nullptr;
				fopen_s(&f, t.filepath.c_str(), "rb");
				if (f) {
					fseek(f, 0, SEEK_END);
					long sz = ftell(f);
					fseek(f, 0, SEEK_SET);
					content.resize(sz);
					fread(&content[0], 1, sz, f);
					fclose(f);
				}
				code_editor::load(content, t.filename, t.filepath);
			}

		} else {

			const char* fn_disp = "No file";
			ImVec2 fn_ts = ImGui::CalcTextSize(fn_disp);
			float  fn_y  = r1_cy - fn_ts.y * 0.5f;
			wdl->AddText(ImVec2(hx0 + hdr_pad, fn_y),
				IM_COL32(120,120,140,(int)(140*a)), fn_disp);
		}


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


		if (file_tabs::active_tab >= 0 && file_tabs::active_tab < (int)file_tabs::tabs.size())
			file_tabs::tabs[file_tabs::active_tab].dirty = code_editor::dirty;
	}


	{


		const char* desc_text = "";
		if (code_editor::active) desc_text = "Code Editor";
		else if (hex_view::g_state.active) desc_text = "Hex View";
		else if (g_disasm.file.loaded) desc_text = "Disassembly";
		if (desc_text[0]) {
			ImVec2 dt_ts = ImGui::CalcTextSize(desc_text);
			float  dt_ty = r2_cy - dt_ts.y * 0.5f;
			wdl->AddText(ImVec2(hx0 + hdr_pad, dt_ty),
				IM_COL32(255,255,255,(int)(0.35f*a*255)), desc_text);
		}

		static bool s_sandbox_running = false;
		bool run_clicked = ghost_btn(s_sandbox_running ? "Running..." : "Run",
			ImGui::GetID("##drhv"), ImGui::GetID("##drfl"),
			rbtn_x0, r2_cy, rbtn_w);

		if (run_clicked && !s_sandbox_running) {

			std::string exe_path;
			std::string work_dir;

			if (g_disasm.file.loaded && !g_disasm.file.path.empty()) {
				exe_path = g_disasm.file.path;
			} else if (code_editor::active && !file_tabs::tabs.empty() && file_tabs::active_tab < (int)file_tabs::tabs.size()) {

				auto& tab = file_tabs::tabs[file_tabs::active_tab];
				exe_path = tab.filepath;
			}

			if (!exe_path.empty()) {
				s_sandbox_running = true;
				output_log::push(bottom_tab_t::sandbox_log, "[Sandbox] Starting: " + exe_path);

				std::thread([exe_path, work_dir]() {

					auto to_wide = [](const std::string& s) -> std::wstring {
						if (s.empty()) return {};
						int len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
						std::wstring ws(len - 1, 0);
						MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, ws.data(), len);
						return ws;
					};
					sandbox::config cfg;
					cfg.exe_path = to_wide(exe_path);
					cfg.working_dir = to_wide(work_dir);
					cfg.timeout_ms = 30000;
					cfg.capture_stdout = true;
					cfg.capture_stderr = true;
					cfg.allow_network = false;

					auto result = sandbox::execute(cfg);

					if (!result.error.empty()) {
						output_log::push(bottom_tab_t::sandbox_log, "[Sandbox] Error: " + result.error);
					} else {
						char line[256];
						snprintf(line, sizeof(line), "[Sandbox] Exit code: %u, Elapsed: %u ms",
						         result.exit_code, result.elapsed_ms);
						output_log::push(bottom_tab_t::sandbox_log, line);
						if (!result.stdout_data.empty())
							output_log::push(bottom_tab_t::sandbox_log, "[stdout] " + result.stdout_data);
						if (!result.stderr_data.empty())
							output_log::push(bottom_tab_t::sandbox_log, "[stderr] " + result.stderr_data);
					}
					s_sandbox_running = false;
				}).detach();
			} else {
				output_log::push(bottom_tab_t::sandbox_log, "[Sandbox] No file to run. Open a PE or file first.");
			}
		}
	}


	float disasm_child_y = content_top + hdr_h + 1.f;
	float disasm_child_h = total_h - hdr_h - 1.f;
	const float di_pad   = 6.f;
	ImGui::SetCursorPos(ImVec2(pad + left_gap + di_pad, disasm_child_y + di_pad));
	ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.f,0.f));
	ImGui::BeginChild("##center_content_scroll",
		ImVec2(center_w - di_pad*2.f, disasm_child_h - di_pad*2.f),
		false, ImGuiWindowFlags_NoBackground);
	{


	auto cv = globals::ui::active_center_view;


	if (cv == center_view_t::welcome) {
		if (code_editor::active && !code_editor::buffer.empty())
			cv = center_view_t::code_editor;
		else if (g_disasm.file.loaded && !g_disasm.file.instrs.empty())
			cv = center_view_t::disassembly;
		else if (hex_view::g_state.active)
			cv = center_view_t::hex_view;
	}

	float vw = center_w - di_pad * 2.f;
	float vh = disasm_child_h - di_pad * 2.f;

	if (cv == center_view_t::code_editor && code_editor::active && !code_editor::buffer.empty())
	{
		ImGui::SetCursorPos(ImVec2(0.f, 0.f));
		code_editor_widget::render(0.f, 0.f, vw, vh, a, ax3, ay3, az3);


		if (ID3D11ShaderResourceView* icon_srv = get_active_theme_icon()) {
			ImDrawList* tdl = ImGui::GetWindowDrawList();
			ImVec2 torig = ImGui::GetWindowPos();
			float src_w = 0.f, src_h = 0.f;
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
				const float max_h = vh * 0.38f;
				const float max_w = vw * 0.28f;
				const float scale = std::min(max_w / src_w, max_h / src_h);
				const float draw_w = src_w * scale;
				const float draw_h = src_h * scale;
				const float icon_pad = 18.f;
				const ImVec2 img_min(torig.x + vw - draw_w - icon_pad,
				                     torig.y + vh - draw_h - icon_pad);
				const ImVec2 img_max(img_min.x + draw_w, img_min.y + draw_h);
				tdl->AddImage((ImTextureID)icon_srv, img_min, img_max,
					ImVec2(0, 0), ImVec2(1, 1), IM_COL32(255, 255, 255, (int)(172 * a)));
			}
		}
	}


	else if (cv == center_view_t::hex_view && hex_view::g_state.active)
	{
		hex_view::render(0.f, 0.f, vw, vh, a, ax3, ay3, az3);
	}

	else if (cv == center_view_t::disassembly && g_disasm.file.loaded && !g_disasm.file.instrs.empty())
	{
		disasm_view::render(0.f, 0.f, vw, vh, a, ax3, ay3, az3, g_disasm, dt);
	}

	else
	{

		ImDrawList* cdl  = ImGui::GetWindowDrawList();
		ImVec2      orig = ImGui::GetWindowPos();

		ID3D11ShaderResourceView* icon_srv = get_active_theme_icon();
		if (icon_srv) {
			int icon_idx = g_sa_settings.theme_icon_index;
			if (custom_themes::active_custom >= 0 &&
			    custom_themes::active_custom < (int)custom_themes::list.size())
				icon_idx = custom_themes::list[custom_themes::active_custom].icon_index;
			float src_w = 0.f, src_h = 0.f;
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
				float max_w = vw * 0.6f;
				float scale = std::min(max_w / src_w, max_h / src_h);
				float dw = src_w * scale;
				float dh = src_h * scale;
				float ix = orig.x + vw * 0.5f - dw * 0.5f;
				float iy = orig.y + window_h * 0.5f - dh * 0.5f - 20.f;
				cdl->AddImage((ImTextureID)icon_srv,
					ImVec2(ix, iy), ImVec2(ix + dw, iy + dh),
					ImVec2(0, 0), ImVec2(1, 1),
					IM_COL32(255, 255, 255, (int)(200 * a)));
			}
		}

		const char* hint = !g_disasm.file.err.empty()     ? g_disasm.file.err.c_str()
			             : !g_disasm.file.loaded           ? "Choose a file to begin"
			             :                                   "Click 'Run' to execute in sandbox";
		ImVec2 ht2 = ImGui::CalcTextSize(hint);
		float  window_h = ImGui::GetWindowHeight();
		cdl->AddText(ImVec2(orig.x + vw*0.5f - ht2.x*0.5f, orig.y + window_h * 0.85f - ht2.y*0.5f),
			IM_COL32(100,100,120,(int)(120*a)), hint);
	}

	}
	ImGui::EndChild();
	ImGui::PopStyleVar();

	if (globals::ui::panel_right_visible) {
	begin_child("##chat", ImVec2(pad + left_gap + center_w + gap, content_top), ImVec2(right_w, total_h), a);
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


			ImVec2 hist_pos(cw - gear_sz * 3.f - 20.f, 3.f);
			ImGui::SetCursorPos(hist_pos);
			ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0,0,0,0));
			ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(1,1,1,0.08f));
			ImGui::PushStyleColor(ImGuiCol_ButtonActive,  ImVec4(1,1,1,0.12f));
			ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.55f,0.55f,0.60f,1.f));
			if (ImGui::Button("\xf0\x9f\x93\x8b##chat_history", ImVec2(gear_sz, gear_sz))) {
				conversations::refresh_history();
				conversations::browser_open = !conversations::browser_open;
			}
			ImGui::PopStyleColor(4);
			if (ImGui::IsItemHovered())
				ImGui::SetTooltip("Conversation history");


			ImVec2 clr_pos(cw - gear_sz * 2.f - 14.f, 3.f);
			ImGui::SetCursorPos(clr_pos);
			ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0,0,0,0));
			ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(1,1,1,0.08f));
			ImGui::PushStyleColor(ImGuiCol_ButtonActive,  ImVec4(1,1,1,0.12f));
			ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.55f,0.55f,0.60f,1.f));
			if (ImGui::Button("+##new_chat", ImVec2(gear_sz, gear_sz))) {
				conversations::new_chat();
			}
			ImGui::PopStyleColor(4);
			if (ImGui::IsItemHovered())
				ImGui::SetTooltip("New chat");


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


		if (conversations::browser_open) {
			float hist_w = std::min(cw - 8.f, 320.f);
			float hist_h = std::min(ch * 0.6f, 400.f);
			ImGui::SetNextWindowPos(ImVec2(ImGui::GetWindowPos().x + cw - hist_w - 4.f,
			                               ImGui::GetWindowPos().y + 22.f));
			ImGui::SetNextWindowSize(ImVec2(hist_w, hist_h));
			ImGui::PushStyleColor(ImGuiCol_WindowBg, ImVec4(0.08f, 0.08f, 0.12f, 0.95f));
			ImGui::PushStyleColor(ImGuiCol_Border, ImVec4(1,1,1,0.1f));
			ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 8.f);
			ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(8.f, 8.f));
			if (ImGui::Begin("##conv_history", &conversations::browser_open,
			                 ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
			                 ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoSavedSettings)) {
				ImGui::TextColored(ImVec4(0.7f,0.7f,0.8f,1.f), "Conversations");
				ImGui::Separator();
				ImGui::BeginChild("##conv_list", ImVec2(0, 0), false);
				for (int i = 0; i < (int)conversations::history.size(); i++) {
					auto& c = conversations::history[i];
					bool is_current = (c.id == conversations::current_id);
					std::string label = c.title.empty() ? "Untitled" : c.title;
					if (label.size() > 50) label = label.substr(0, 47) + "...";
					char count_str[32];
					snprintf(count_str, sizeof(count_str), " (%d msgs)", c.msg_count);
					label += count_str;

					if (is_current) ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(ax/255.f, ay/255.f, az/255.f, 1.f));
					if (ImGui::Selectable(("##conv_" + c.id).c_str(), is_current, 0, ImVec2(hist_w - 40.f, 0))) {
						if (!is_current) {
							conversations::save_current();
							conversations::load_conversation(c.id);
							conversations::browser_open = false;
						}
					}
					ImGui::SameLine(0, 0);
					ImGui::SetCursorPosX(0);
					ImGui::Text("%s", label.c_str());
					if (is_current) ImGui::PopStyleColor();

					ImGui::SameLine(hist_w - 32.f);
					ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0,0,0,0));
					ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.5f,0.3f,0.3f,0.8f));
					char del_id[32];
					snprintf(del_id, sizeof(del_id), "x##del_%d", i);
					if (ImGui::SmallButton(del_id)) {
						conversations::delete_conversation(c.id);
						if (is_current) {
							g_chat_messages.clear();
							conversations::current_id.clear();
						}
					}
					ImGui::PopStyleColor(2);
				}
				if (conversations::history.empty())
					ImGui::TextColored(ImVec4(0.5f,0.5f,0.55f,1.f), "No saved conversations");
				ImGui::EndChild();
			}
			ImGui::End();
			ImGui::PopStyleVar(2);
			ImGui::PopStyleColor(2);

			if (!ImGui::IsWindowHovered(ImGuiHoveredFlags_AnyWindow) && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
				conversations::browser_open = false;
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

					float rich_max_w = wrap_w * 0.86f;


					ImGuiID fda = ImGui::GetID(("fda_" + std::to_string(mi)).c_str());
					float   falpha = s->GetFloat(fda, 0.f);
					falpha += (1.f - falpha) * std::min(6.f * ImGui::GetIO().DeltaTime, 1.f);
					s->SetFloat(fda, falpha);

					float bx = 6.f;
					float by = cursor_y;


					auto spans = chat_render::parse_markdown(msg.text);
					bool has_code_blocks = false;
					for (auto& sp : spans)
						if (sp.type == chat_render::span_type::code_block) { has_code_blocks = true; break; }


					ImVec2 plain_ts = msg.text.empty()
						? ImVec2(0.f, ImGui::GetFontSize())
						: ImGui::CalcTextSize(msg.text.c_str(), nullptr, false, rich_max_w);


					float est_h = plain_ts.y + 10.f;
					if (has_code_blocks) est_h *= 1.5f;


					ImGuiID bwa = ImGui::GetID(("bw_" + std::to_string(mi)).c_str());
					ImGuiID bha = ImGui::GetID(("bh_" + std::to_string(mi)).c_str());
					float   bw = s->GetFloat(bwa, 10.f);
					float   anim_bh = s->GetFloat(bha, est_h);
					float target_bw = rich_max_w + 16.f;
					bw += (target_bw - bw) * std::min(12.f * ImGui::GetIO().DeltaTime, 1.f);
					s->SetFloat(bwa, bw);

					ImVec2 bmin = ImVec2(wp2.x + bx, wp2.y + by);


					auto rr = chat_render::render_rich_message(
						dl, bmin, bw, msg.text,
						falpha * a, ax, ay, az,
						mi, ImGui::GetIO().DeltaTime, !msg.streaming);

					float real_h = std::max(rr.height, ImGui::GetFontSize() + 10.f);


					anim_bh += (real_h - anim_bh) * std::min(12.f * ImGui::GetIO().DeltaTime, 1.f);
					s->SetFloat(bha, anim_bh);


					ImVec2 bmax = ImVec2(bmin.x + bw, bmin.y + anim_bh);
					dl->AddRectFilled(bmin, bmax,
						IM_COL32(34, 32, 52, (int)(210 * falpha * a)), 8.f);


					chat_render::render_rich_message(
						dl, bmin, bw, msg.text,
						falpha * a, ax, ay, az,
						mi, ImGui::GetIO().DeltaTime, !msg.streaming);


					if (rr.action == chat_render::action_t::retry && mi > 0) {

						for (int ri = mi - 1; ri >= 0; ri--) {
							if (g_chat_messages[ri].is_user) {
								strncpy_s(g_chat_buf, g_chat_messages[ri].text.c_str(), _TRUNCATE);
								g_chat_messages.push_back({ g_chat_buf, "", true, false, false });
								g_chat_scroll_to_bottom = true;
								g_chat_buf[0] = '\0';
								break;
							}
						}
					} else if (rr.action == chat_render::action_t::delete_msg) {
						if (mi >= 0 && mi < (int)g_chat_messages.size()) {
							g_chat_messages.erase(g_chat_messages.begin() + mi);
							mi--;
							continue;
						}
					} else if (rr.action == chat_render::action_t::edit_msg) {

						ImGui::SetClipboardText(msg.text.c_str());
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
								ImVec2(bmax.x + 6.f, bmin.y + (anim_bh - tts2.y) * 0.5f),
								IM_COL32(120, 115, 155, (int)(170 * hov_a * falpha * a)), ts_buf);
						}
					}

					cursor_y += anim_bh + 8.f;
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
					ImGui::SetNextWindowSizeConstraints(ImVec2(220.f, 60.f), ImVec2(320.f, 400.f));
					ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 8.f);
					ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(6.f, 6.f));
					ImGui::PushStyleColor(ImGuiCol_PopupBg, ImVec4(0.09f, 0.09f, 0.13f, 1.f));
					ImGui::PushStyleColor(ImGuiCol_Border, ImVec4(1, 1, 1, 0.08f));

					if (ImGui::Begin("##model_popup", &model_open,
						ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
						ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_NoSavedSettings))
					{

						static char model_filter[64] = {};
						ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 4.f);
						ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(6.f, 4.f));
						ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0.06f, 0.06f, 0.09f, 1.f));
						ImGui::SetNextItemWidth(ImGui::GetContentRegionAvail().x);
						ImGui::InputTextWithHint("##model_search", "Search models...", model_filter, sizeof(model_filter));
						ImGui::PopStyleColor();
						ImGui::PopStyleVar(2);

						ImGui::Spacing();
						std::string filter_lower;
						for (const char* p = model_filter; *p; p++)
							filter_lower += (char)tolower(*p);


						ImGui::TextColored(ImVec4(0.5f, 0.5f, 0.6f, 1.f), "Providers");
						ImGui::Separator();
						for (auto& profile : g_sa_settings.provider_profiles) {
							if (!filter_lower.empty()) {
								std::string pname_lower;
								for (char ch : profile.display_name)
									pname_lower += (char)tolower(ch);
								if (pname_lower.find(filter_lower) == std::string::npos)
									continue;
							}
							bool is_active = (profile.id == g_sa_settings.active_provider_profile_id);
							if (is_active) ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(ax3, ay3, az3, 1.f));
							if (ImGui::Selectable(profile.display_name.c_str(), is_active, 0, ImVec2(200.f, 0.f))) {
								g_sa_settings.active_provider_profile_id = profile.id;
								g_sa_settings.sync_legacy_fields_from_active_profile();
								g_sa_settings.save();
							}
							if (is_active) ImGui::PopStyleColor();
						}

						ImGui::Spacing();
						ImGui::TextColored(ImVec4(0.5f, 0.5f, 0.6f, 1.f), "Models");
						ImGui::Separator();

						if (auto* current_profile = g_sa_settings.get_active_profile()) {
							const auto& model_list = settings_sa_t::models_for_kind(current_profile->kind);
							for (const auto& m : model_list) {
								if (!filter_lower.empty()) {
									std::string m_lower;
									for (char ch : m)
										m_lower += (char)tolower(ch);
									if (m_lower.find(filter_lower) == std::string::npos)
										continue;
								}
								bool is_sel = (current_profile->model == m);
								if (is_sel) ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(ax3, ay3, az3, 1.f));
								if (ImGui::Selectable(m.c_str(), is_sel, 0, ImVec2(220.f, 0.f))) {
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
	}


	if (globals::ui::panel_bottom_visible && bottom_h > 20.f) {
		float bp_x = pad;
		float bp_y = content_top + total_h + gap;
		float bp_w = ww - pad * 2.f;

		ImGui::SetCursorPos(ImVec2(bp_x, bp_y));
		begin_child("##bottom_panel", ImVec2(bp_x, bp_y), ImVec2(bp_w, bottom_h), a);
		{
			ImDrawList* bdl = ImGui::GetWindowDrawList();
			ImVec2 bwp = ImGui::GetWindowPos();
			float bfw = ImGui::GetWindowWidth();
			float bfh = ImGui::GetWindowHeight();

			float bax = globals::ui::accent.x * 255.f;
			float bay = globals::ui::accent.y * 255.f;
			float baz = globals::ui::accent.z * 255.f;


			const char* btab_names[] = { "Output", "MCP Log", "Driver", "Sandbox", "Terminal" };
			float btab_x = 8.f;
			float btab_h = 24.f;
			for (int bt = 0; bt < (int)bottom_tab_t::COUNT; bt++) {
				ImVec2 bts = ImGui::CalcTextSize(btab_names[bt]);
				float btw = bts.x + 16.f;
				ImVec2 btmin(bwp.x + btab_x, bwp.y + 2.f);
				ImVec2 btmax(btmin.x + btw, btmin.y + btab_h - 2.f);
				bool bthov = ImGui::IsMouseHoveringRect(btmin, btmax);
				bool btact = (static_cast<int>(globals::ui::active_bottom_tab) == bt);

				if (btact)
					bdl->AddRectFilled(btmin, btmax, IM_COL32(255, 255, 255, (int)(14 * a)), 3.f);
				else if (bthov)
					bdl->AddRectFilled(btmin, btmax, IM_COL32(255, 255, 255, (int)(8 * a)), 3.f);

				if (btact) {
					bdl->AddLine(ImVec2(btmin.x + 4.f, btmax.y), ImVec2(btmax.x - 4.f, btmax.y),
						IM_COL32((int)bax, (int)bay, (int)baz, (int)(180 * a)), 1.5f);
				}

				ImU32 btc = btact ? IM_COL32(220, 220, 235, (int)(240 * a))
				                  : IM_COL32(140, 140, 160, (int)(180 * a));
				bdl->AddText(ImVec2(btmin.x + 8.f, btmin.y + (btab_h - 2.f - bts.y) * 0.5f), btc, btab_names[bt]);

				if (bthov && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
					globals::ui::active_bottom_tab = static_cast<bottom_tab_t>(bt);

				btab_x += btw + 2.f;
			}


			{
				const char* clr = "Clear";
				ImVec2 cts = ImGui::CalcTextSize(clr);
				ImVec2 cmin(bwp.x + bfw - cts.x - 16.f, bwp.y + 4.f);
				ImVec2 cmax(cmin.x + cts.x + 8.f, cmin.y + btab_h - 6.f);
				bool chov = ImGui::IsMouseHoveringRect(cmin, cmax);
				if (chov) bdl->AddRectFilled(cmin, cmax, IM_COL32(255, 255, 255, (int)(12 * a)), 3.f);
				bdl->AddText(ImVec2(cmin.x + 4.f, cmin.y + 1.f), IM_COL32(160, 160, 175, (int)((chov ? 220 : 140) * a)), clr);
				if (chov && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
					output_log::clear(globals::ui::active_bottom_tab);
			}


			bdl->AddLine(ImVec2(bwp.x, bwp.y + btab_h), ImVec2(bwp.x + bfw, bwp.y + btab_h),
				IM_COL32(255, 255, 255, (int)(8 * a)));


			float log_y = btab_h + 4.f;
			ImGui::SetCursorPos(ImVec2(0.f, log_y));
			ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.f, 0.f));
			ImGui::BeginChild("##bottom_scroll", ImVec2(bfw, bfh - log_y), false, ImGuiWindowFlags_NoBackground);
			{
			if (globals::ui::active_bottom_tab == bottom_tab_t::terminal) {

				auto& tmgr = globals::terminal_mgr;
				if (tmgr.sessions.empty()) {
					std::wstring wshell(g_sa_settings.terminal_shell.begin(), g_sa_settings.terminal_shell.end());
					tmgr.create_terminal(wshell.c_str());
				}
				if (!tmgr.sessions.empty()) {
					auto* ts = tmgr.sessions[0];
					ImU32 term_bg = IM_COL32(22, 20, 38, (int)(230 * a));
					ImU32 term_accent = IM_COL32(
						(int)(ax3 * 255), (int)(ay3 * 255), (int)(az3 * 255), (int)(255 * a));
					terminal_view::render_terminal(*ts,
						ImVec2(bfw, bfh - log_y), term_bg, term_accent);

					if (ImGui::IsWindowFocused(ImGuiFocusedFlags_ChildWindows)) {
						auto& io = ImGui::GetIO();
						for (int i = 0; i < io.InputQueueCharacters.Size; i++) {
							ImWchar c = io.InputQueueCharacters[i];
							if (c >= 32 && c < 127) {
								terminal_view::send_key(*ts, static_cast<char>(c));
							}
						}
						if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_C, false))
							terminal_view::send_input(*ts, "\x03", 1);
						if (ImGui::IsKeyPressed(ImGuiKey_Enter, false))
							terminal_view::send_input(*ts, "\r", 1);
						if (ImGui::IsKeyPressed(ImGuiKey_Backspace, false))
							terminal_view::send_input(*ts, "\x7f", 1);
						if (ImGui::IsKeyPressed(ImGuiKey_Tab, false))
							terminal_view::send_input(*ts, "\t", 1);
						if (ImGui::IsKeyPressed(ImGuiKey_Escape, false))
							terminal_view::send_input(*ts, "\x1b", 1);
					}
				}
			} else {

				int tab_idx = static_cast<int>(globals::ui::active_bottom_tab);
				auto& log_lines = output_log::lines[tab_idx];
				float line_h = ImGui::GetFontSize() + 2.f;
				ImDrawList* ldl = ImGui::GetWindowDrawList();
				ImVec2 lorig = ImGui::GetWindowPos();
				float scroll_y = ImGui::GetScrollY();
				float vis_h = ImGui::GetWindowHeight();

				int first = std::max(0, (int)(scroll_y / line_h) - 1);
				int last = std::min((int)log_lines.size() - 1, (int)((scroll_y + vis_h) / line_h) + 1);

				for (int li = first; li <= last; li++) {
					float ly = lorig.y + li * line_h - scroll_y;
					if (li & 1) ldl->AddRectFilled(ImVec2(lorig.x, ly), ImVec2(lorig.x + bfw, ly + line_h),
						IM_COL32(255, 255, 255, (int)(2 * a)));


					const auto& ln = log_lines[li];
					ImU32 lc = IM_COL32(180, 180, 195, (int)(200 * a));
					if (ln.find("Error") != std::string::npos || ln.find("ERR") != std::string::npos)
						lc = IM_COL32(220, 100, 100, (int)(230 * a));
					else if (ln.find("[init]") != std::string::npos)
						lc = IM_COL32(100, 180, 100, (int)(210 * a));
					else if (ln.find("[tool]") != std::string::npos || ln.find("[mcp") != std::string::npos)
						lc = IM_COL32((int)(bax*0.6f+100), (int)(bay*0.6f+100), (int)(baz*0.6f+100), (int)(210 * a));
					else if (ln.find("[ai]") != std::string::npos)
						lc = IM_COL32(150, 160, 220, (int)(220 * a));
					else if (ln.find("[driver]") != std::string::npos)
						lc = IM_COL32(200, 170, 100, (int)(210 * a));

					ldl->AddText(ImVec2(lorig.x + 8.f, ly + 1.f), lc, ln.c_str());
				}

				ImGui::SetCursorPosY((float)log_lines.size() * line_h);
				ImGui::Dummy(ImVec2(1.f, 1.f));

				if (output_log::auto_scroll[tab_idx] && !log_lines.empty())
					ImGui::SetScrollHereY(1.f);
			}
			}
			ImGui::EndChild();
			ImGui::PopStyleVar();
		}
		end_child();
	}


	{
		static int s_lic_check_counter = 0;
		if (++s_lic_check_counter >= 120) {
			s_lic_check_counter = 0;
			if (license::validated && !standalone_license::is_valid()) {
				license::validated = false;
				license::error_msg = standalone_license::last_error();
				output_log::push(bottom_tab_t::output, "[license] Session invalidated: " + license::error_msg);
			}
		}
	}


	{
		ImVec2 wp = ImGui::GetWindowPos();
		ImDrawList* dl = ImGui::GetWindowDrawList();
		float sx0 = wp.x;
		float sy0 = wp.y + wh - status_h;
		float sx1 = wp.x + ww;
		float sy1 = wp.y + wh;

		float sax = globals::ui::accent.x * 255.f;
		float say = globals::ui::accent.y * 255.f;
		float saz = globals::ui::accent.z * 255.f;

		dl->AddRectFilled(ImVec2(sx0, sy0), ImVec2(sx1, sy1),
			IM_COL32(14, 14, 20, (int)(235 * a)), 8.f, ImDrawFlags_RoundCornersBottom);
		dl->AddLine(ImVec2(sx0, sy0), ImVec2(sx1, sy0),
			IM_COL32(255, 255, 255, (int)(6 * a)));

		float text_y = sy0 + (status_h - ImGui::GetFontSize()) * 0.5f;


		{
			bool lic_ok = license::validated && standalone_license::is_valid();
			float dot_r = 3.5f;
			float dot_x = sx0 + 8.f + dot_r;
			float dot_y = text_y + ImGui::GetFontSize() * 0.5f;
			ImU32 dot_col = lic_ok
				? IM_COL32(80, 200, 80, (int)(220 * a))
				: IM_COL32(220, 60, 60, (int)(220 * a));
			dl->AddCircleFilled(ImVec2(dot_x, dot_y), dot_r, dot_col);
		}
		const float lic_dot_offset = 20.f;


		{
			std::string info;
			if (code_editor::active && !code_editor::filename.empty()) {
				info = code_editor::filename;
				if (code_editor::dirty) info += " [modified]";
				info += "  Ln " + std::to_string(autocomplete::cursor_line + 1) +
				        ", Col " + std::to_string(autocomplete::cursor_col + 1);
			} else if (g_disasm.file.loaded) {
				info = g_disasm.file.filename + "  (" + std::to_string(g_disasm.file.instrs.size()) + " instructions)";
			} else {
				info = "No file open";
			}
			dl->AddText(ImVec2(sx0 + lic_dot_offset, text_y), IM_COL32(150, 150, 170, (int)(200 * a)), info.c_str());
		}


		{
			auto* prof = g_sa_settings.get_active_profile();
			std::string model_str = prof ? (prof->display_name + " / " + prof->model) : "No model";
			ImVec2 mts = ImGui::CalcTextSize(model_str.c_str());


			float rx = sx1 - mts.x - 16.f;
			ImU32 dim_col = IM_COL32(120, 120, 145, (int)(160 * a));

			const char* encoding = "UTF-8";
			const char* line_end = "LF";
			const char* indent_str = "Spaces: 4";
			const char* lang = "Plain Text";

			if (code_editor::active && !code_editor::filename.empty()) {
				auto ext = std::filesystem::path(code_editor::filename).extension().string();
				if (ext == ".cpp" || ext == ".cc" || ext == ".cxx") lang = "C++";
				else if (ext == ".c") lang = "C";
				else if (ext == ".h" || ext == ".hpp" || ext == ".hxx") lang = "C/C++ Header";
				else if (ext == ".py") lang = "Python";
				else if (ext == ".js") lang = "JavaScript";
				else if (ext == ".ts") lang = "TypeScript";
				else if (ext == ".rs") lang = "Rust";
				else if (ext == ".go") lang = "Go";
				else if (ext == ".java") lang = "Java";
				else if (ext == ".json") lang = "JSON";
				else if (ext == ".xml") lang = "XML";
				else if (ext == ".md") lang = "Markdown";
				else if (ext == ".asm" || ext == ".s") lang = "Assembly";
				else if (ext == ".cmake") lang = "CMake";
				else if (ext == ".txt") lang = "Plain Text";
				indent_str = editor_config::tab_size == 4 ? "Spaces: 4" : "Spaces: 2";
			}


			dl->AddText(ImVec2(rx, text_y),
				IM_COL32((int)(sax * 0.6f + 60), (int)(say * 0.6f + 60), (int)(saz * 0.6f + 60), (int)(180 * a)),
				model_str.c_str());
			rx -= 12.f;

			ImVec2 lang_ts = ImGui::CalcTextSize(lang);
			rx -= lang_ts.x;
			dl->AddText(ImVec2(rx, text_y), dim_col, lang);
			rx -= 12.f;

			ImVec2 enc_ts = ImGui::CalcTextSize(encoding);
			rx -= enc_ts.x;
			dl->AddText(ImVec2(rx, text_y), dim_col, encoding);
			rx -= 12.f;

			ImVec2 le_ts = ImGui::CalcTextSize(line_end);
			rx -= le_ts.x;
			dl->AddText(ImVec2(rx, text_y), dim_col, line_end);
			rx -= 12.f;

			ImVec2 ind_ts = ImGui::CalcTextSize(indent_str);
			rx -= ind_ts.x;
			dl->AddText(ImVec2(rx, text_y), dim_col, indent_str);
		}


		{
			std::string driver_str;
			if (driver_bridge::attached_pid() != 0) {
				driver_str = "Driver: " + driver_bridge::attached_process_name() +
				             " (PID " + std::to_string(driver_bridge::attached_pid()) + ")";
			} else {
				driver_str = "Driver: Detached";
			}

			ImU32 driver_col;
			if (driver_bridge::attached_pid() != 0)
				driver_col = IM_COL32(100, 200, 100, (int)(200 * a));
			else
				driver_col = IM_COL32(120, 120, 140, (int)(160 * a));

			ImVec2 dts = ImGui::CalcTextSize(driver_str.c_str());
			float dcx = (sx0 + sx1) * 0.5f - dts.x * 0.5f;
			dl->AddText(ImVec2(dcx, text_y), driver_col, driver_str.c_str());
		}


		{
			auto& mgr = get_mcp_client_manager();
			auto statuses = mgr.get_status();
			int connected = 0, total = (int)statuses.size();
			for (auto& s : statuses)
				if (s.state == mcp_client::connection_state_t::connected) connected++;

			if (total > 0) {
				char mcp_buf[64];
				snprintf(mcp_buf, sizeof(mcp_buf), "MCP %d/%d", connected, total);
				ImVec2 mts2 = ImGui::CalcTextSize(mcp_buf);
				float mx = sx1 - mts2.x - 12.f;

				auto* prof = g_sa_settings.get_active_profile();
				if (prof) {
					std::string model_str2 = prof->display_name + " / " + prof->model;
					ImVec2 model_ts = ImGui::CalcTextSize(model_str2.c_str());
					mx = sx1 - model_ts.x - mts2.x - 28.f;
				}

				ImU32 mcp_col = (connected == total)
					? IM_COL32(100, 200, 100, (int)(200 * a))
					: (connected > 0)
						? IM_COL32(220, 180, 60, (int)(200 * a))
						: IM_COL32(200, 100, 100, (int)(200 * a));

				float dot_r = 3.f;
				dl->AddCircleFilled(ImVec2(mx - dot_r - 4.f, text_y + ImGui::GetFontSize() * 0.5f), dot_r, mcp_col);
				dl->AddText(ImVec2(mx, text_y), IM_COL32(150, 150, 170, (int)(180 * a)), mcp_buf);
			}
		}


		{
			if (cost_tracking::session_input_tokens > 0 || cost_tracking::session_output_tokens > 0) {
				std::string tok_str = cost_tracking::format_tokens(cost_tracking::session_input_tokens) + " in / " +
				                      cost_tracking::format_tokens(cost_tracking::session_output_tokens) + " out";
				float cost = (float)cost_tracking::session_cost_usd;
				if (cost > 0.001f) {
					char cost_buf[32];
					snprintf(cost_buf, sizeof(cost_buf), "  ~$%.2f", cost);
					tok_str += cost_buf;
				}
				ImVec2 tts = ImGui::CalcTextSize(tok_str.c_str());

				float file_info_w = 0.f;
				{
					std::string info2;
					if (code_editor::active && !code_editor::filename.empty()) {
						info2 = code_editor::filename;
						if (code_editor::dirty) info2 += " [modified]";
						info2 += "  Ln " + std::to_string(autocomplete::cursor_line + 1) +
						          ", Col " + std::to_string(autocomplete::cursor_col + 1);
					}
					file_info_w = ImGui::CalcTextSize(info2.c_str()).x;
				}
				float tx = sx0 + file_info_w + 30.f;
				dl->AddText(ImVec2(tx, text_y), IM_COL32(130, 130, 155, (int)(160 * a)), tok_str.c_str());
			}
		}
	}

	tick_ai_chat();
	poll_ai_chat();


	if (globals::ui::command_palette_open) {
		struct PaletteCmd {
			const char* label;
			const char* shortcut;
			int id;
		};
		static const PaletteCmd all_cmds[] = {
			{ "Toggle Explorer Panel",      "Ctrl+B",         1  },
			{ "Toggle Chat Panel",           "Ctrl+J",         2  },
			{ "Toggle Output Panel",         "Ctrl+`",         3  },
			{ "Save File",                   "Ctrl+S",         4  },
			{ "New File",                    "Ctrl+N",         5  },
			{ "Close Tab",                   "Ctrl+W",         6  },
			{ "Next Tab",                    "Ctrl+Tab",       7  },
			{ "Previous Tab",               "Ctrl+Shift+Tab",  8  },
			{ "Open Settings",               "Ctrl+,",         9  },
			{ "New Chat",                    "Ctrl+L",         10 },
			{ "Open File for Disassembly",   "",                11 },
			{ "Toggle Fullscreen",           "F11",             12 },
			{ "Change Theme",                "",                13 },
			{ "Focus Chat Input",            "",                14 },
			{ "Show Output Tab",             "",                15 },
			{ "Show MCP Log Tab",            "",                16 },
			{ "Show Driver Log Tab",         "",                17 },
			{ "Attach to Process",           "",                18 },
			{ "Driver Status",               "",                19 },
			{ "About",                       "",                20 },
			{ "Keyboard Shortcuts",          "Ctrl+K Ctrl+S",   21 },
			{ "Find",                        "Ctrl+F",          22 },
			{ "Replace",                     "Ctrl+H",          23 },
			{ "Undo",                        "Ctrl+Z",          24 },
			{ "Redo",                        "Ctrl+Y",          25 },
		};
		static const int cmd_count = sizeof(all_cmds) / sizeof(all_cmds[0]);
		static int palette_sel = 0;


		std::string filter_str(globals::ui::command_palette_buf);
		std::vector<int> filtered;
		filtered.reserve(cmd_count);
		if (filter_str.empty()) {
			for (int i = 0; i < cmd_count; i++) filtered.push_back(i);
		} else {

			std::string flo = filter_str;
			for (auto& c : flo) c = (char)std::tolower((unsigned char)c);
			for (int i = 0; i < cmd_count; i++) {
				std::string lbl(all_cmds[i].label);
				for (auto& c : lbl) c = (char)std::tolower((unsigned char)c);
				if (lbl.find(flo) != std::string::npos)
					filtered.push_back(i);
			}
		}
		if (palette_sel >= (int)filtered.size()) palette_sel = (int)filtered.size() - 1;
		if (palette_sel < 0) palette_sel = 0;

		auto execute_cmd = [&](int cmd_id) {
			switch (cmd_id) {
			case 1: globals::ui::panel_left_visible = !globals::ui::panel_left_visible;
				g_sa_settings.workspace.left_visible = globals::ui::panel_left_visible; g_sa_settings.save(); break;
			case 2: globals::ui::panel_right_visible = !globals::ui::panel_right_visible;
				g_sa_settings.workspace.right_visible = globals::ui::panel_right_visible; g_sa_settings.save(); break;
			case 3: globals::ui::panel_bottom_visible = !globals::ui::panel_bottom_visible;
				g_sa_settings.workspace.bottom_visible = globals::ui::panel_bottom_visible; g_sa_settings.save(); break;
			case 4: if (code_editor::active) code_editor::save(); break;
			case 5: file_tabs::open_or_focus("", "untitled", ""); break;
			case 6: file_tabs::close_tab(file_tabs::active_tab); break;
			case 7:
				if (!file_tabs::tabs.empty()) {
					file_tabs::active_tab = (file_tabs::active_tab + 1) % (int)file_tabs::tabs.size();
					auto& t7 = file_tabs::tabs[file_tabs::active_tab];
					std::string c7; FILE* f7 = nullptr; fopen_s(&f7, t7.filepath.c_str(), "rb");
					if (f7) { fseek(f7,0,SEEK_END); long sz=ftell(f7); fseek(f7,0,SEEK_SET); c7.resize(sz); fread(&c7[0],1,sz,f7); fclose(f7); }
					code_editor::load(c7, t7.filename, t7.filepath);
				} break;
			case 8:
				if (!file_tabs::tabs.empty()) {
					file_tabs::active_tab = (file_tabs::active_tab - 1 + (int)file_tabs::tabs.size()) % (int)file_tabs::tabs.size();
					auto& t8 = file_tabs::tabs[file_tabs::active_tab];
					std::string c8; FILE* f8 = nullptr; fopen_s(&f8, t8.filepath.c_str(), "rb");
					if (f8) { fseek(f8,0,SEEK_END); long sz=ftell(f8); fseek(f8,0,SEEK_SET); c8.resize(sz); fread(&c8[0],1,sz,f8); fclose(f8); }
					code_editor::load(c8, t8.filename, t8.filepath);
				} break;
			case 9: g_settings_open = true; break;
			case 10: conversations::new_chat(); break;
			case 11: {
				std::string fpath = disasm::open_file_dialog(g_hwnd);
				if (!fpath.empty()) {
					g_disasm.file = DisasmFile{};
					disasm::load_pe(fpath, g_disasm.file);
					if (g_disasm.file.loaded)
						disasm::decode_section(g_disasm.file);
				}
			} break;
			case 12: {
				globals::ui::maximized = !globals::ui::maximized;
				if (globals::ui::maximized) {
					RECT r; GetWindowRect(g_hwnd, &r);
					globals::ui::pre_max_x = (float)r.left;
					globals::ui::pre_max_y = (float)r.top;
					globals::ui::pre_max_w = (float)(r.right - r.left);
					globals::ui::pre_max_h = (float)(r.bottom - r.top);
					HMONITOR mon = MonitorFromWindow(g_hwnd, MONITOR_DEFAULTTONEAREST);
					MONITORINFO mi = { sizeof(mi) };
					GetMonitorInfo(mon, &mi);
					SetWindowPos(g_hwnd, nullptr, mi.rcWork.left, mi.rcWork.top,
						mi.rcWork.right - mi.rcWork.left, mi.rcWork.bottom - mi.rcWork.top,
						SWP_NOZORDER | SWP_NOACTIVATE);
				} else {
					SetWindowPos(g_hwnd, nullptr,
						(int)globals::ui::pre_max_x, (int)globals::ui::pre_max_y,
						(int)globals::ui::pre_max_w, (int)globals::ui::pre_max_h,
						SWP_NOZORDER | SWP_NOACTIVATE);
				}
			} break;
			case 13: g_settings_open = true; break;
			case 14:  break;
			case 15: globals::ui::panel_bottom_visible = true; globals::ui::active_bottom_tab = bottom_tab_t::output; break;
			case 16: globals::ui::panel_bottom_visible = true; globals::ui::active_bottom_tab = bottom_tab_t::mcp_log; break;
			case 17: globals::ui::panel_bottom_visible = true; globals::ui::active_bottom_tab = bottom_tab_t::driver_log; break;
			case 18: globals::ui::process_attach_open = true; break;
			case 19: globals::ui::driver_status_open = true; break;
			case 20: globals::ui::about_dialog_open = true; break;
			case 21: globals::ui::shortcuts_dialog_open = true; break;
			case 22: if (code_editor::active) code_editor_widget::open_find(); break;
			case 23: if (code_editor::active) code_editor_widget::open_replace(); break;
			case 24: if (code_editor::active) code_editor_widget::trigger_undo(); break;
			case 25: if (code_editor::active) code_editor_widget::trigger_redo(); break;
			}
			globals::ui::command_palette_open = false;
			globals::ui::command_palette_buf[0] = '\0';
			palette_sel = 0;
		};


		ImDrawList* fdl = ImGui::GetForegroundDrawList();
		ImVec2 vp = ImGui::GetIO().DisplaySize;
		fdl->AddRectFilled(ImVec2(0, 0), vp, IM_COL32(0, 0, 0, 120));


		float pw = 520.f;
		float max_h = 400.f;
		float px = (vp.x - pw) * 0.5f;
		float py = 80.f;

		ImGui::SetNextWindowPos(ImVec2(px, py));
		ImGui::SetNextWindowSize(ImVec2(pw, 0));
		ImGui::SetNextWindowSizeConstraints(ImVec2(pw, 0), ImVec2(pw, max_h));

		ImGui::PushStyleColor(ImGuiCol_WindowBg, IM_COL32(30, 30, 38, 245));
		ImGui::PushStyleColor(ImGuiCol_Border, IM_COL32(70, 70, 90, 200));
		ImGui::PushStyleColor(ImGuiCol_FrameBg, IM_COL32(40, 40, 52, 255));
		ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 8.f);
		ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(10, 10));
		ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 4.f);

		if (ImGui::Begin("##CommandPalette", nullptr,
				ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
				ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoScrollbar |
				ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_NoSavedSettings)) {


			ImGui::PushItemWidth(-1);
			if (ImGui::IsWindowAppearing()) ImGui::SetKeyboardFocusHere();
			bool enter = ImGui::InputText("##palette_input", globals::ui::command_palette_buf,
				sizeof(globals::ui::command_palette_buf),
				ImGuiInputTextFlags_EnterReturnsTrue);
			ImGui::PopItemWidth();


			if (ImGui::IsKeyPressed(ImGuiKey_DownArrow, true) && palette_sel < (int)filtered.size() - 1) palette_sel++;
			if (ImGui::IsKeyPressed(ImGuiKey_UpArrow,   true) && palette_sel > 0) palette_sel--;
			if (ImGui::IsKeyPressed(ImGuiKey_Escape, false)) {
				globals::ui::command_palette_open = false;
				globals::ui::command_palette_buf[0] = '\0';
				palette_sel = 0;
			}
			if (enter && !filtered.empty()) {
				execute_cmd(all_cmds[filtered[palette_sel]].id);
			}


			ImGui::Separator();
			float item_h = ImGui::GetTextLineHeightWithSpacing() + 4.f;
			float list_h = std::min((float)filtered.size() * item_h, max_h - 60.f);
			if (list_h < item_h) list_h = item_h;

			ImGui::BeginChild("##palette_list", ImVec2(-1, list_h), false);
			ImVec4 acc = themes::resolved.accent;
			ImU32 acc_col = IM_COL32((int)(acc.x * 255), (int)(acc.y * 255), (int)(acc.z * 255), 255);
			for (int i = 0; i < (int)filtered.size(); i++) {
				int ci = filtered[i];
				bool selected = (i == palette_sel);
				ImVec2 cp = ImGui::GetCursorScreenPos();
				float w = ImGui::GetContentRegionAvail().x;

				if (selected) {
					ImGui::GetWindowDrawList()->AddRectFilled(cp, ImVec2(cp.x + w, cp.y + item_h),
						IM_COL32((int)(acc.x * 60), (int)(acc.y * 60), (int)(acc.z * 60), 100), 4.f);
				}


				if (ImGui::IsMouseHoveringRect(cp, ImVec2(cp.x + w, cp.y + item_h))) {
					if (!selected)
						ImGui::GetWindowDrawList()->AddRectFilled(cp, ImVec2(cp.x + w, cp.y + item_h),
							IM_COL32(60, 60, 80, 80), 4.f);
					if (ImGui::IsMouseClicked(0)) {
						execute_cmd(all_cmds[ci].id);
					}
					palette_sel = i;
				}


				ImGui::SetCursorScreenPos(ImVec2(cp.x + 8, cp.y + 2));
				ImGui::TextColored(selected ? ImVec4(1, 1, 1, 1) : ImVec4(0.8f, 0.8f, 0.85f, 1.f),
					"%s", all_cmds[ci].label);


				if (all_cmds[ci].shortcut[0]) {
					std::string sc(all_cmds[ci].shortcut);
					ImVec2 sts = ImGui::CalcTextSize(sc.c_str());
					ImGui::SameLine();
					ImGui::SetCursorScreenPos(ImVec2(cp.x + w - sts.x - 12, cp.y + 2));
					ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(130, 130, 160, 200));
					ImGui::TextUnformatted(sc.c_str());
					ImGui::PopStyleColor();
				}

				ImGui::SetCursorScreenPos(ImVec2(cp.x, cp.y + item_h));
			}

			if (palette_sel >= 0 && palette_sel < (int)filtered.size()) {
				float target_y = palette_sel * item_h;
				float scroll_y = ImGui::GetScrollY();
				if (target_y < scroll_y) ImGui::SetScrollY(target_y);
				if (target_y + item_h > scroll_y + list_h) ImGui::SetScrollY(target_y + item_h - list_h);
			}
			ImGui::EndChild();
		}
		ImGui::End();
		ImGui::PopStyleVar(3);
		ImGui::PopStyleColor(3);


		if (ImGui::IsMouseClicked(0) && !ImGui::IsWindowHovered(ImGuiHoveredFlags_AnyWindow)) {
			globals::ui::command_palette_open = false;
			globals::ui::command_palette_buf[0] = '\0';
			palette_sel = 0;
		}
	}


	if (globals::ui::process_attach_open) {
		ImDrawList* fdl = ImGui::GetForegroundDrawList();
		ImVec2 vp = ImGui::GetIO().DisplaySize;
		fdl->AddRectFilled(ImVec2(0, 0), vp, IM_COL32(0, 0, 0, 120));

		float pw = 480.f, ph = 420.f;
		float px = (vp.x - pw) * 0.5f, py = (vp.y - ph) * 0.5f;

		ImGui::SetNextWindowPos(ImVec2(px, py));
		ImGui::SetNextWindowSize(ImVec2(pw, ph));
		ImGui::PushStyleColor(ImGuiCol_WindowBg, IM_COL32(28, 28, 36, 245));
		ImGui::PushStyleColor(ImGuiCol_Border, IM_COL32(70, 70, 90, 200));
		ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 8.f);
		ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(12, 12));

		if (ImGui::Begin("Attach to Process##pa_dlg", &globals::ui::process_attach_open,
				ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove |
				ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoSavedSettings)) {

			ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 4.f);
			ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0.06f, 0.06f, 0.09f, 1.f));
			ImGui::SetNextItemWidth(-1);
			ImGui::InputTextWithHint("##proc_filter", "Filter processes...",
				globals::ui::process_filter_buf, sizeof(globals::ui::process_filter_buf));
			ImGui::PopStyleColor();
			ImGui::PopStyleVar();
			ImGui::Spacing();

			static std::vector<driver_bridge::process_info_t> proc_list;
			static float refresh_timer = 0.f;
			static int selected_proc = -1;
			refresh_timer -= ImGui::GetIO().DeltaTime;
			if (refresh_timer <= 0.f) {
				proc_list = driver_bridge::enumerate_processes();
				refresh_timer = 2.f;
			}

			std::string filt(globals::ui::process_filter_buf);
			for (auto& c : filt) c = (char)tolower((unsigned char)c);

			ImGui::BeginChild("##proc_list", ImVec2(-1, ph - 110.f), true);
			for (int i = 0; i < (int)proc_list.size(); i++) {
				auto& p = proc_list[i];
				if (!filt.empty()) {
					std::string name_lower = p.name;
					for (auto& c : name_lower) c = (char)tolower((unsigned char)c);
					std::string pid_str = std::to_string(p.pid);
					if (name_lower.find(filt) == std::string::npos &&
						pid_str.find(filt) == std::string::npos)
						continue;
				}
				char label[256];
				snprintf(label, sizeof(label), "%-6u  %s", (unsigned)p.pid, p.name.c_str());
				if (ImGui::Selectable(label, selected_proc == i))
					selected_proc = i;
			}
			ImGui::EndChild();
			ImGui::Spacing();

			float btn_w = 80.f;
			bool can_attach = selected_proc >= 0 && selected_proc < (int)proc_list.size();
			if (!can_attach) ImGui::BeginDisabled();
			if (ImGui::Button("Attach", ImVec2(btn_w, 26))) {
				auto& p = proc_list[selected_proc];
				driver_bridge::attach(p.pid);
				globals::ui::process_attach_open = false;
				selected_proc = -1;
				globals::ui::process_filter_buf[0] = '\0';
			}
			if (!can_attach) ImGui::EndDisabled();
			ImGui::SameLine();
			if (ImGui::Button("Cancel", ImVec2(btn_w, 26))) {
				globals::ui::process_attach_open = false;
				selected_proc = -1;
				globals::ui::process_filter_buf[0] = '\0';
			}
		}
		ImGui::End();
		ImGui::PopStyleVar(2);
		ImGui::PopStyleColor(2);
	}


	if (globals::ui::driver_status_open) {
		ImDrawList* fdl = ImGui::GetForegroundDrawList();
		ImVec2 vp = ImGui::GetIO().DisplaySize;
		fdl->AddRectFilled(ImVec2(0, 0), vp, IM_COL32(0, 0, 0, 120));

		float pw = 500.f, ph = 380.f;
		float px = (vp.x - pw) * 0.5f, py = (vp.y - ph) * 0.5f;

		ImGui::SetNextWindowPos(ImVec2(px, py));
		ImGui::SetNextWindowSize(ImVec2(pw, ph));
		ImGui::PushStyleColor(ImGuiCol_WindowBg, IM_COL32(28, 28, 36, 245));
		ImGui::PushStyleColor(ImGuiCol_Border, IM_COL32(70, 70, 90, 200));
		ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 8.f);
		ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(12, 12));

		if (ImGui::Begin("Driver Status##drv_dlg", &globals::ui::driver_status_open,
				ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove |
				ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoSavedSettings)) {

			bool is_attached = driver_bridge::attached_pid() != 0;
			ImGui::TextColored(is_attached ? ImVec4(0.4f, 0.8f, 0.4f, 1.f) : ImVec4(0.6f, 0.6f, 0.7f, 1.f),
				is_attached ? "Status: Attached" : "Status: Detached");

			if (is_attached) {
				ImGui::Text("Process: %s", driver_bridge::attached_process_name().c_str());
				ImGui::Text("PID: %u", (unsigned)driver_bridge::attached_pid());
				ImGui::Separator();

				static int drv_tab = 0;
				if (ImGui::BeginTabBar("##drv_tabs")) {
					if (ImGui::BeginTabItem("Modules")) {
						drv_tab = 0;
						auto mods = driver_bridge::enumerate_modules();
						ImGui::BeginChild("##mod_list", ImVec2(-1, ph - 180.f));
						for (auto& m : mods) {
							ImGui::Text("0x%llX  %s", (unsigned long long)m.base, m.name.c_str());
						}
						ImGui::EndChild();
						ImGui::EndTabItem();
					}
					if (ImGui::BeginTabItem("Threads")) {
						drv_tab = 1;
						auto threads = driver_bridge::enumerate_threads();
						ImGui::BeginChild("##thr_list", ImVec2(-1, ph - 180.f));
						for (auto& t : threads) {
							ImGui::Text("TID %u  Priority %d", (unsigned)t.tid, t.priority);
						}
						ImGui::EndChild();
						ImGui::EndTabItem();
					}
					ImGui::EndTabBar();
				}
			}

			ImGui::Spacing();
			float btn_w = 80.f;
			if (is_attached) {
				if (ImGui::Button("Detach", ImVec2(btn_w, 26))) {
					driver_bridge::detach();
				}
				ImGui::SameLine();
			}
			if (ImGui::Button("Close", ImVec2(btn_w, 26))) {
				globals::ui::driver_status_open = false;
			}
		}
		ImGui::End();
		ImGui::PopStyleVar(2);
		ImGui::PopStyleColor(2);
	}


	if (globals::ui::about_dialog_open) {
		ImDrawList* fdl = ImGui::GetForegroundDrawList();
		ImVec2 vp = ImGui::GetIO().DisplaySize;
		fdl->AddRectFilled(ImVec2(0, 0), vp, IM_COL32(0, 0, 0, 120));

		float pw = 360.f, ph = 220.f;
		float px = (vp.x - pw) * 0.5f, py = (vp.y - ph) * 0.5f;

		ImGui::SetNextWindowPos(ImVec2(px, py));
		ImGui::SetNextWindowSize(ImVec2(pw, ph));
		ImGui::PushStyleColor(ImGuiCol_WindowBg, IM_COL32(28, 28, 36, 245));
		ImGui::PushStyleColor(ImGuiCol_Border, IM_COL32(70, 70, 90, 200));
		ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 8.f);
		ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(20, 16));

		if (ImGui::Begin("About AiDA##about_dlg", &globals::ui::about_dialog_open,
				ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove |
				ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoSavedSettings)) {

			ImVec4 ac = globals::ui::accent;
			ImGui::TextColored(ac, "AiDA Standalone IDE");
			ImGui::Spacing();
			ImGui::Text("Version 1.0.0");
			ImGui::Text("AI-Powered Disassembly & Analysis");
			ImGui::Spacing();
			ImGui::Separator();
			ImGui::Spacing();
			ImGui::TextWrapped("Built with ImGui, Zydis, Unicorn, and MCP protocol support.");
			ImGui::TextWrapped("Multi-provider AI: Anthropic, OpenAI, Google, OpenRouter, Local.");
			ImGui::Spacing();
			if (ImGui::Button("OK", ImVec2(80, 26))) {
				globals::ui::about_dialog_open = false;
			}
		}
		ImGui::End();
		ImGui::PopStyleVar(2);
		ImGui::PopStyleColor(2);
	}


	if (globals::ui::shortcuts_dialog_open) {
		ImDrawList* fdl = ImGui::GetForegroundDrawList();
		ImVec2 vp = ImGui::GetIO().DisplaySize;
		fdl->AddRectFilled(ImVec2(0, 0), vp, IM_COL32(0, 0, 0, 120));

		float pw = 500.f, ph = 440.f;
		float px = (vp.x - pw) * 0.5f, py = (vp.y - ph) * 0.5f;

		ImGui::SetNextWindowPos(ImVec2(px, py));
		ImGui::SetNextWindowSize(ImVec2(pw, ph));
		ImGui::PushStyleColor(ImGuiCol_WindowBg, IM_COL32(28, 28, 36, 245));
		ImGui::PushStyleColor(ImGuiCol_Border, IM_COL32(70, 70, 90, 200));
		ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 8.f);
		ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(16, 12));

		if (ImGui::Begin("Keyboard Shortcuts##kb_dlg", &globals::ui::shortcuts_dialog_open,
				ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove |
				ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoSavedSettings)) {

			struct ShortcutEntry { const char* keys; const char* desc; };
			static const ShortcutEntry general[] = {
				{ "Ctrl+Shift+P", "Command Palette" },
				{ "Ctrl+N",       "New File" },
				{ "Ctrl+O",       "Open File" },
				{ "Ctrl+S",       "Save File" },
				{ "Ctrl+K",       "Open Folder" },
				{ "F11",          "Toggle Fullscreen" },
			};
			static const ShortcutEntry editor[] = {
				{ "Ctrl+Z",       "Undo" },
				{ "Ctrl+Y",       "Redo" },
				{ "Ctrl+F",       "Find" },
				{ "Ctrl+H",       "Find & Replace" },
				{ "Ctrl+G",       "Go to Line" },
				{ "Ctrl+A",       "Select All" },
				{ "Ctrl+C",       "Copy" },
				{ "Ctrl+X",       "Cut" },
				{ "Ctrl+V",       "Paste" },
			};
			static const ShortcutEntry panels[] = {
				{ "Ctrl+B",       "Toggle Explorer" },
				{ "Ctrl+J",       "Toggle Chat" },
				{ "Ctrl+`",       "Toggle Output" },
				{ "Ctrl+L",       "New Chat" },
				{ "Ctrl+W",       "Close Tab" },
				{ "Ctrl+Tab",     "Next Tab" },
				{ "Ctrl+Shift+Tab", "Previous Tab" },
			};

			auto render_section = [](const char* title, const ShortcutEntry* entries, int count) {
				ImGui::TextColored(ImVec4(0.5f, 0.5f, 0.6f, 1.f), "%s", title);
				ImGui::Separator();
				for (int i = 0; i < count; i++) {
					ImGui::Text("%-18s %s", entries[i].keys, entries[i].desc);
				}
				ImGui::Spacing();
			};

			ImGui::BeginChild("##kb_scroll", ImVec2(-1, ph - 80.f));
			render_section("General", general, 6);
			render_section("Editor", editor, 9);
			render_section("Panels", panels, 7);
			ImGui::EndChild();

			ImGui::Spacing();
			if (ImGui::Button("Close", ImVec2(80, 26))) {
				globals::ui::shortcuts_dialog_open = false;
			}
		}
		ImGui::End();
		ImGui::PopStyleVar(2);
		ImGui::PopStyleColor(2);
	}

	render_settings_popup();
	render_tool_approval_dialog();
	ImGui::PopStyleVar();
	ImGui::End();
}
