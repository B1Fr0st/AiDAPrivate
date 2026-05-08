#include "helpers.h"
#include "globals.h"
#include <commdlg.h>
#include <shlobj.h>
#include <shellapi.h>
#include <dwmapi.h>
#include <fstream>
#include <filesystem>
#include <map>
#include <unordered_set>
#include <algorithm>
#include <iostream>
#include <string>
#include <thread>
#include <chrono>
#include <nlohmann/json.hpp>
#include "blur.h"
#include "../assets/icons.h"
#include "../ide_icons.h"
#include "zydis_disasm.hpp"
#include "standalone_chat.hpp"
#include "standalone_license.hpp"
#include "anti-tamper/orchestrator.hpp"
#include "standalone_settings.hpp"
#include "code_editor.hpp"
#include "disasm_view.hpp"
#include "hex_view.hpp"
#include "chat_render.hpp"
#include "standalone_driver.hpp"
#include "mcp_client.hpp"
#include "sandbox.hpp"
#include "workspace_search.hpp"
#include "terminal_view.hpp"
#include "network_view.hpp"
#include "debugger_view.hpp"
#include "decompiler_view.hpp"
#include "scan_hub_view.hpp"
#include "types_hub_view.hpp"
#include "analysis_hub_view.hpp"
#include "source_reconstruct_view.hpp"
#include "work_queue.hpp"
#include "session_history_view.hpp"
#include "binary_map_view.hpp"
#include "agent_picker_view.hpp"

static ID3D11ShaderResourceView* g_send_icon_srv    = nullptr;
static ID3D11ShaderResourceView* g_loader_icon_srv  = nullptr;
static int                        g_loader_icon_w    = 0;
static int                        g_loader_icon_h    = 0;
DisasmState                       g_disasm;
const char*                       g_render_section = "idle";

static bool trusted_get_open_file_name(OPENFILENAMEA& ofn)
{
	anti_tamper::token_chain::trusted_interaction_scope_t trusted_scope;
	return GetOpenFileNameA(&ofn) != FALSE;
}

static bool trusted_get_save_file_name(OPENFILENAMEA& ofn)
{
	anti_tamper::token_chain::trusted_interaction_scope_t trusted_scope;
	return GetSaveFileNameA(&ofn) != FALSE;
}

static HRESULT trusted_show_file_dialog(IFileOpenDialog* dialog, HWND owner)
{
	anti_tamper::token_chain::trusted_interaction_scope_t trusted_scope;
	return dialog ? dialog->Show(owner) : E_POINTER;
}

static bool license_activate_impl(const char* key_str,
                                  char* err_buf,
                                  size_t err_buf_size)
{
	if (err_buf && err_buf_size) err_buf[0] = '\0';
	std::string key(key_str ? key_str : "");
	std::string err;
	bool ok = false;
	try {
		ok = standalone_license::activate(g_sa_settings, key, err);
	} catch (const std::exception& ex) {
		err = std::string("Activation worker exception: ") + ex.what();
		ok = false;
	} catch (...) {
		err = "Activation worker threw unknown exception.";
		ok = false;
	}
	if (err_buf && err_buf_size) {
		size_t copy = err.size();
		if (copy >= err_buf_size) copy = err_buf_size - 1;
		memcpy(err_buf, err.data(), copy);
		err_buf[copy] = '\0';
	}
	return ok;
}

__declspec(noinline) static DWORD seh_license_activate(const char* key_str,
                                                       BOOL* out_ok,
                                                       char* err_buf,
                                                       size_t err_buf_size)
{
	*out_ok = FALSE;
	__try {
		bool ok = license_activate_impl(key_str, err_buf, err_buf_size);
		*out_ok = ok ? TRUE : FALSE;
		return 0;
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		return GetExceptionCode();
	}
}



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
static ID3D11ShaderResourceView* g_aida_logo_srv = nullptr;
static int g_aida_logo_w = 0, g_aida_logo_h = 0;
static bool g_aida_logo_loaded = false;

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
	const auto& th = aida::ui::resolved();
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

	float dt = aida::ui::clock::dt();
	t += ((active ? 1.0f : 0.0f) - t) * std::min(8.0f * dt, 1.0f);
	ht += ((hovered ? 1.0f : 0.0f) - ht) * std::min(12.0f * dt, 1.0f);

	storage->SetFloat(anim_id, t);
	storage->SetFloat(hover_id, ht);

	if (t > 0.01f)
	{
		for (int i = 4; i >= 1; i--)
		{
			float spread = i * 3.0f;
			dl->AddRectFilled(
				ImVec2(tab_min.x - spread, tab_min.y - spread),
				ImVec2(tab_max.x + spread, tab_max.y + spread),
				aida::ui::with_alpha(th.accent_glow, 0.08f * t * (5 - i)),
				6.f + spread);
		}
	}

	if (ht > 0.01f && t < 0.99f)
		dl->AddRectFilled(tab_min, tab_max,
			aida::ui::with_alpha(th.hover_wash, ht * (1.0f - t)), 6.f);

	if (t > 0.01f)
	{
		dl->AddRectFilled(tab_min, tab_max,
			aida::ui::with_alpha(th.selection_strong, t * 0.85f), 6.f);
		dl->AddRectFilled(tab_min, ImVec2(tab_max.x, tab_min.y + 1.f),
			aida::ui::with_alpha(IM_COL32(255, 255, 255, 255), 0.08f * t), 6.f);
	}

	ImVec2 ts = ImGui::CalcTextSize(label);
	ImVec2 tp = ImVec2(
		tab_min.x + (size.x - ts.x) * 0.5f,
		tab_min.y + (size.y - ts.y) * 0.5f);

	ImU32 text_col = aida::ui::mix(
		aida::ui::mix(th.text_secondary, th.text_primary, ht),
		th.text_primary, t);

	dl->AddText(tp, text_col, label);

	return clicked;
}

void helpers::begin_child(const char* str_id, ImVec2 pos, ImVec2 size, float alpha, ImGuiWindowFlags flags)
{
	ImDrawList* dl = ImGui::GetWindowDrawList();
	ImVec2 wp = ImGui::GetWindowPos();

	ImVec2 r_min = ImVec2(std::round(wp.x + pos.x), std::round(wp.y + pos.y));
	ImVec2 r_max = ImVec2(std::round(r_min.x + size.x), std::round(r_min.y + size.y));

	ImU32 pbg = themes::resolved.panel_bg;
	int pr = (pbg >> 0) & 0xFF, pg = (pbg >> 8) & 0xFF, pb = (pbg >> 16) & 0xFF, pa = (pbg >> 24) & 0xFF;
	dl->AddRectFilled(r_min, r_max, IM_COL32(pr, pg, pb, (int)(pa * alpha)), 8.f);

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
		mj["model_id"] = m.model_id;
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
		m.model_id = mj.value("model_id", std::string());
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
	g_render_section = "entry";
	float dt = ImGui::GetIO().DeltaTime;
	globals::ui::load_timer += dt;

	static bool bg_completed = false;
	static float bg_completed_at = 0.f;
	if (!bg_completed && globals::ui::bg_init_done && globals::ui::bg_init_done->load(std::memory_order_acquire)) {
		bg_completed = true;
		bg_completed_at = globals::ui::load_timer;
	}

	g_render_section = "inline_checks";
	{
		static uint64_t s_frame_ctr = 0;
		standalone_license::cross_validation_sweep(static_cast<int>(s_frame_ctr++));
	}

	{
		uint64_t tok = anti_tamper::run_inline_check(anti_tamper::CHECK_FAST);
		standalone_license::fold_integrity_token(tok);
		static uint64_t s_inline_log_ctr = 0;
		++s_inline_log_ctr;

		if ((s_inline_log_ctr % 1000) == 0) {
			anti_tamper::run_inline_check(anti_tamper::CHECK_CODE_INTEGRITY);
		}
	}

	{
		uint64_t gt = standalone_license::inline_gate_check(
			standalone_license::gate_ui_render_loop);
		(void)standalone_license::verify_gate_token(
			standalone_license::gate_ui_render_loop, gt);
	}

	g_render_section = "theme_resolve";
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

	const int th_ph_r = (themes::resolved.panel_header >>  0) & 0xFF;
	const int th_ph_g = (themes::resolved.panel_header >>  8) & 0xFF;
	const int th_ph_b = (themes::resolved.panel_header >> 16) & 0xFF;
	const int th_pb_r = (themes::resolved.panel_bg >>  0) & 0xFF;
	const int th_pb_g = (themes::resolved.panel_bg >>  8) & 0xFF;
	const int th_pb_b = (themes::resolved.panel_bg >> 16) & 0xFF;
	const int th_bb_r = (themes::resolved.bg_base >>  0) & 0xFF;
	const int th_bb_g = (themes::resolved.bg_base >>  8) & 0xFF;
	const int th_bb_b = (themes::resolved.bg_base >> 16) & 0xFF;


	chat_handle_agent_shortcuts();


	if (!ImGui::GetIO().WantTextInput) {
		bool ctrl  = ImGui::GetIO().KeyCtrl;
		bool shift = ImGui::GetIO().KeyShift;

		if (ImGui::IsKeyPressed(ImGuiKey_F11, false)) {
			globals::ui::maximized = !globals::ui::maximized;
			if (globals::ui::maximized) {
				RECT r; GetWindowRect(g_hwnd, &r);
				globals::ui::pre_max_x = (float)r.left;
				globals::ui::pre_max_y = (float)r.top;
				globals::ui::pre_max_w = (float)(r.right - r.left);
				globals::ui::pre_max_h = (float)(r.bottom - r.top);
				MONITORINFO mi = { sizeof(mi) };
				GetMonitorInfoW(MonitorFromWindow(g_hwnd, MONITOR_DEFAULTTONEAREST), &mi);
				float mw = (float)(mi.rcWork.right - mi.rcWork.left);
				float mh = (float)(mi.rcWork.bottom - mi.rcWork.top);
				globals::ui::window_w = mw;
				globals::ui::window_h = mh;
				SetWindowPos(g_hwnd, nullptr,
					mi.rcWork.left, mi.rcWork.top, (int)mw, (int)mh,
					SWP_NOZORDER);
				SetWindowRgn(g_hwnd, nullptr, TRUE);
				DWM_WINDOW_CORNER_PREFERENCE cp = DWMWCP_DONOTROUND;
				DwmSetWindowAttribute(g_hwnd, DWMWA_WINDOW_CORNER_PREFERENCE, &cp, sizeof(cp));
			} else {
				globals::ui::window_w = globals::ui::pre_max_w;
				globals::ui::window_h = globals::ui::pre_max_h;
				SetWindowPos(g_hwnd, nullptr,
					(int)globals::ui::pre_max_x, (int)globals::ui::pre_max_y,
					(int)globals::ui::pre_max_w, (int)globals::ui::pre_max_h,
					SWP_NOZORDER);
				HRGN rgn = CreateRoundRectRgn(0, 0, (int)globals::ui::pre_max_w, (int)globals::ui::pre_max_h, 16, 16);
				SetWindowRgn(g_hwnd, rgn, TRUE);
				DWM_WINDOW_CORNER_PREFERENCE cp = DWMWCP_ROUND;
				DwmSetWindowAttribute(g_hwnd, DWMWA_WINDOW_CORNER_PREFERENCE, &cp, sizeof(cp));
			}
		}

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
			int ci = file_tabs::active_tab;
			if (ci >= 0 && ci < (int)file_tabs::tabs.size() && file_tabs::tabs[ci].dirty) {
				file_tabs::pending_close_idx = ci;
				file_tabs::show_close_confirm = true;
			} else {
				file_tabs::close_tab(ci);
			}
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

		if (ctrl && shift && ImGui::IsKeyPressed(ImGuiKey_N, false)) {
			globals::ui::active_center_view = center_view_t::network_view;
		}

		if (ctrl && shift && ImGui::IsKeyPressed(ImGuiKey_M, false)) {
			globals::ui::active_center_view = center_view_t::scan_hub;
		}

		if (ctrl && shift && ImGui::IsKeyPressed(ImGuiKey_D, false)) {
			globals::ui::active_center_view = center_view_t::debugger_view;
		}

		if (ctrl && shift && ImGui::IsKeyPressed(ImGuiKey_B, false)) {
			globals::ui::active_center_view = center_view_t::binary_map;
		}

		if (ImGui::IsKeyPressed(ImGuiKey_F5, false)) {
			uint64_t dec_addr = decompiler_engine::g_state.current.function_addr;
			if (dec_addr == 0)
				dec_addr = globals::ui::decompile_popup_addr;
			if (globals::ui::decompile_default_mode == 0) {
				if (dec_addr)
					decompiler_engine::decompile_function(dec_addr, g_sa_settings);
				globals::ui::active_center_view = center_view_t::decompiler;
			} else if (globals::ui::decompile_default_mode == 1) {
				if (dec_addr)
					decompiler_engine::decompile_function_native(dec_addr);
				globals::ui::active_center_view = center_view_t::decompiler;
			} else if (globals::ui::decompile_default_mode == 2) {
				if (dec_addr)
					decompiler_engine::decompile_function_hybrid(dec_addr, g_sa_settings);
				globals::ui::active_center_view = center_view_t::decompiler;
			} else {
				globals::ui::show_decompile_popup = true;
			}
		}

		if (ctrl && shift && ImGui::IsKeyPressed(ImGuiKey_X, false)) {
			scan_hub_view::set_sub_tab(scan_hub_view::sub_tab_t::xrefs);
			globals::ui::active_center_view = center_view_t::scan_hub;
		}

		if (ctrl && shift && ImGui::IsKeyPressed(ImGuiKey_O, false)) {
			analysis_hub_view::set_sub_tab(analysis_hub_view::sub_tab_t::deobfuscation);
			globals::ui::active_center_view = center_view_t::analysis_hub;
		}
	}

	if (globals::ui::show_decompile_popup) {
		ImGui::OpenPopup("##decompile_choice");
		globals::ui::show_decompile_popup = false;
	}

	static bool remember_choice = false;
	if (ImGui::BeginPopupModal("##decompile_choice", nullptr,
	    ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoMove)) {
		ImVec2 display = ImGui::GetIO().DisplaySize;
		ImVec2 win_size = ImGui::GetWindowSize();
		ImGui::SetWindowPos(ImVec2(display.x * 0.5f - win_size.x * 0.5f,
		                            display.y * 0.5f - win_size.y * 0.5f));

		ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.9f, 0.9f, 0.95f, 1.f));
		ImGui::Text("Decompile Function");
		ImGui::PopStyleColor();
		ImGui::Separator();
		ImGui::Spacing();

		float btn_w = 260.f;
		float btn_h = 52.f;

		uint64_t popup_addr = globals::ui::decompile_popup_addr;
		if (popup_addr == 0)
			popup_addr = decompiler_engine::g_state.current.function_addr;

		if (aida::ui::components::button("AI Decompiler##dec_ai",
			aida::ui::components::button_kind_t::primary,
			aida::ui::components::size_t_::md,
			ImVec2(btn_w, btn_h))) {
			if (popup_addr)
				decompiler_engine::decompile_function(popup_addr, g_sa_settings);
			globals::ui::active_center_view = center_view_t::decompiler;
			if (remember_choice) {
				globals::ui::decompile_default_mode = 0;
				g_sa_settings.decompile_default_mode = 0;
				g_sa_settings.save();
			}
			ImGui::CloseCurrentPopup();
		}
		if (ImGui::IsItemHovered()) {
			ImGui::SetTooltip("Uses AI to generate high-quality pseudocode with variable naming.\nRequires API key. ~3-15 seconds.");
		}

		ImGui::Spacing();

		if (aida::ui::components::button("Ghidra Decompiler##dec_ghidra",
			aida::ui::components::button_kind_t::primary,
			aida::ui::components::size_t_::md,
			ImVec2(btn_w, btn_h))) {
			if (popup_addr)
				decompiler_engine::decompile_function_native(popup_addr);
			globals::ui::active_center_view = center_view_t::decompiler;
			if (remember_choice) {
				globals::ui::decompile_default_mode = 1;
				g_sa_settings.decompile_default_mode = 1;
				g_sa_settings.save();
			}
			ImGui::CloseCurrentPopup();
		}
		if (ImGui::IsItemHovered()) {
			ImGui::SetTooltip("Native decompilation engine. Instant results (~100ms).\nNo API key needed. Deterministic output.");
		}

		ImGui::Spacing();

		if (aida::ui::components::button("Hybrid (Ghidra + AI)##dec_hybrid",
			aida::ui::components::button_kind_t::primary,
			aida::ui::components::size_t_::md,
			ImVec2(btn_w, btn_h))) {
			if (popup_addr)
				decompiler_engine::decompile_function_hybrid(popup_addr, g_sa_settings);
			globals::ui::active_center_view = center_view_t::decompiler;
			if (remember_choice) {
				globals::ui::decompile_default_mode = 2;
				g_sa_settings.decompile_default_mode = 2;
				g_sa_settings.save();
			}
			ImGui::CloseCurrentPopup();
		}
		if (ImGui::IsItemHovered()) {
			ImGui::SetTooltip("Ghidra for instant structure, then AI refines variable names.\nBest of both worlds.");
		}

		ImGui::Spacing();
		ImGui::Separator();

		ImGui::Checkbox("Remember my choice", &remember_choice);

		ImGui::SameLine();
		if (aida::ui::components::button("Cancel",
			aida::ui::components::button_kind_t::secondary,
			aida::ui::components::size_t_::md)) {
			ImGui::CloseCurrentPopup();
		}

		ImGui::EndPopup();
	}

	if (!helpers::themes_loaded) {
		helpers::theme_kaneki = nullptr;
		helpers::theme_rias = nullptr;
		helpers::theme_nagi = nullptr;
		helpers::theme_mio = nullptr;
		for (int i = 0; i < 4; ++i) {
			g_theme_icon_w[i] = 0;
			g_theme_icon_h[i] = 0;
		}
		helpers::themes_loaded = true;
	}


	if (!g_bg_art_loaded && g_pd3dDevice) {
		icon_loader::load(background, 8640831, &g_bg_art_srv,
			&g_bg_art_w, &g_bg_art_h, false);
		g_bg_art_loaded = true;
	}

	if (!g_aida_logo_loaded && g_pd3dDevice) {
		icon_loader::load(aidalogo, 1273853, &g_aida_logo_srv,
			&g_aida_logo_w, &g_aida_logo_h, false);
		g_aida_logo_loaded = true;
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
		return nullptr;
	};

	bool loading = !bg_completed || globals::ui::load_timer < 3.0f;

	g_render_section = loading ? "loading_screen" : "post_loading";

	if (!loading)
	{
		float tw, th;
		if (!globals::ui::welcome_done) {
			tw = 560.f; th = 360.f;
		} else if (!license::validated) {
			tw = 620.f; th = 540.f;
		} else {
			MONITORINFO mi = { sizeof(mi) };
			GetMonitorInfoW(MonitorFromWindow(g_hwnd, MONITOR_DEFAULTTONEAREST), &mi);
			tw = static_cast<float>(mi.rcWork.right - mi.rcWork.left) * 0.75f;
			th = static_cast<float>(mi.rcWork.bottom - mi.rcWork.top) * 0.75f;
		}


		static bool initial_grow_done = false;
		if (!initial_grow_done) {
			if (globals::ui::welcome_done && license::validated) {
				initial_grow_done = true;
				globals::ui::maximized = true;
				MONITORINFO mi2 = { sizeof(mi2) };
				GetMonitorInfoW(MonitorFromWindow(g_hwnd, MONITOR_DEFAULTTONEAREST), &mi2);
				float mw = static_cast<float>(mi2.rcWork.right - mi2.rcWork.left);
				float mh = static_cast<float>(mi2.rcWork.bottom - mi2.rcWork.top);
				globals::ui::pre_max_x = static_cast<float>(mi2.rcWork.left) + (mw - mw * 0.75f) * 0.5f;
				globals::ui::pre_max_y = static_cast<float>(mi2.rcWork.top) + (mh - mh * 0.75f) * 0.5f;
				globals::ui::pre_max_w = mw * 0.75f;
				globals::ui::pre_max_h = mh * 0.75f;
				globals::ui::window_w = mw;
				globals::ui::window_h = mh;
				SetWindowPos(g_hwnd, nullptr,
					mi2.rcWork.left, mi2.rcWork.top,
					static_cast<int>(mw), static_cast<int>(mh), SWP_NOZORDER);
				SetWindowRgn(g_hwnd, nullptr, TRUE);
				DWM_WINDOW_CORNER_PREFERENCE cp = DWMWCP_DONOTROUND;
				DwmSetWindowAttribute(g_hwnd, DWMWA_WINDOW_CORNER_PREFERENCE, &cp, sizeof(cp));
			} else {
				float spd = 12.f;
				float dw = tw - globals::ui::window_w;
				float dh = th - globals::ui::window_h;
				globals::ui::window_w += dw * std::min(spd * dt, 1.f);
				globals::ui::window_h += dh * std::min(spd * dt, 1.f);


				if (std::abs(dw) < 2.f) globals::ui::window_w = tw;
				if (std::abs(dh) < 2.f) globals::ui::window_h = th;

				if (globals::ui::load_timer > 5.0f && !globals::ui::welcome_done) {
					globals::ui::window_w = tw;
					globals::ui::window_h = th;
				}
			}
		}
	}


	bool welcome_ready = !loading && globals::ui::window_w >= 470.f && globals::ui::window_h >= 270.f;
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
		const auto& th = aida::ui::resolved();
		ImVec2 wp = ImGui::GetWindowPos();
		float ww_l = globals::ui::window_w;
		float wh_l = globals::ui::window_h;
		float cx   = wp.x + ww_l * 0.5f;
		float cy   = wp.y + wh_l * 0.5f - 8.f;
		ImDrawList* dl = ImGui::GetWindowDrawList();

		if (loading) {
			fadeout = 1.f;
		} else {
			fadeout -= dt * 1.5f;
			if (fadeout < 0.f) fadeout = 0.f;
		}
		float vis = loading ? 1.f : fadeout;

		dl->AddRectFilled(wp, ImVec2(wp.x + ww_l, wp.y + wh_l),
			th.bg_base, 14.f);

		if (g_bg_art_srv && g_bg_art_w > 0 && g_bg_art_h > 0) {
			float aspect_img = (float)g_bg_art_w / (float)g_bg_art_h;
			float aspect_win = ww_l / wh_l;
			float bg_w, bg_h;
			if (aspect_img > aspect_win) {
				bg_h = wh_l;
				bg_w = bg_h * aspect_img;
			} else {
				bg_w = ww_l;
				bg_h = bg_w / aspect_img;
			}
			float bg_x = wp.x + (ww_l - bg_w) * 0.5f;
			float bg_y = wp.y + (wh_l - bg_h) * 0.5f;
			ImU32 bg_tint = aida::ui::with_alpha(IM_COL32_WHITE, 0.42f * vis);
			dl->AddImageRounded((ImTextureID)g_bg_art_srv,
				ImVec2(bg_x, bg_y), ImVec2(bg_x + bg_w, bg_y + bg_h),
				ImVec2(0.f, 0.f), ImVec2(1.f, 1.f),
				bg_tint, 14.f);
			dl->AddRectFilled(wp, ImVec2(wp.x + ww_l, wp.y + wh_l),
				aida::ui::with_alpha(th.bg_base, 0.55f * vis), 14.f);
		}

		float aura_r = ww_l * 0.55f;
		ImU32 aura = aida::ui::with_alpha(th.accent_glow, 0.45f * vis);
		for (int i = 0; i < 5; ++i) {
			float rr = aura_r + (float)i * 14.f;
			float fa = (1.f - (float)i / 5.f) * 0.55f;
			dl->AddCircleFilled(ImVec2(cx, cy), rr, aida::ui::with_alpha(aura, fa), 64);
		}

		float reveal_t = std::min(globals::ui::load_timer / 0.480f, 1.f);
		float reveal_eased = aida::motion::ease::out_back(reveal_t);
		float pulse = aida::ui::clock::pulse(0.6f, 0.0f, 1.0f);

		aida::ui::brand::render_constellation(
			dl, ImVec2(cx, cy), 80.f, 12,
			aida::ui::clock::seconds() * 0.4f,
			aida::ui::with_alpha(th.accent_u32, vis), nullptr);

		float logo_size = 96.f;
		if (g_aida_logo_srv && g_aida_logo_w > 0 && g_aida_logo_h > 0) {
			float scale = reveal_eased;
			float ls = logo_size * (0.6f + 0.4f * scale);
			float lcx = cx;
			float lcy = cy - 18.f;
			float aspect = (float)g_aida_logo_w / (float)g_aida_logo_h;
			float lw = ls * aspect;
			float lh = ls;
			ImU32 logo_tint = aida::ui::with_alpha(IM_COL32_WHITE, vis * (0.85f + 0.15f * pulse));
			dl->AddImage((ImTextureID)g_aida_logo_srv,
				ImVec2(lcx - lw * 0.5f, lcy - lh * 0.5f),
				ImVec2(lcx + lw * 0.5f, lcy + lh * 0.5f),
				ImVec2(0.f, 0.f), ImVec2(1.f, 1.f), logo_tint);
		} else {
			aida::ui::brand::render_logomark(
				dl, ImVec2(cx, cy - 18.f), logo_size,
				reveal_eased, pulse, vis);
		}

		ImFont* display_font = aida::ui::fonts::display();
		if (!display_font) display_font = ImGui::GetFont();
		float wm_scale = 1.0f;
		float wm_size  = 32.f * wm_scale;
		float wm_total_w = aida::ui::brand::wordmark_total_width(display_font, wm_scale);
		float wm_x = cx - wm_total_w * 0.5f;
		float wm_y = cy + logo_size * 0.5f + 12.f;
		float wm_reveal = std::min((globals::ui::load_timer - 0.18f) / 0.62f, 1.f);
		if (wm_reveal < 0.f) wm_reveal = 0.f;
		aida::ui::brand::render_wordmark(dl, ImVec2(wm_x, wm_y), wm_scale,
			display_font, wm_reveal, vis);

		float tag_a = std::min(std::max(globals::ui::load_timer - 1.6f, 0.f) / 0.5f, 1.f) * vis;
		if (tag_a > 0.01f) {
			const char* tag = "Reverse engineering, reimagined.";
			ImFont* body = aida::ui::fonts::body();
			if (!body) body = ImGui::GetFont();
			float ts_x = body->CalcTextSizeA(18.f, FLT_MAX, 0.f, tag).x;
			dl->AddText(body, 18.f,
				ImVec2(cx - ts_x * 0.5f, wm_y + wm_size + 18.f),
				aida::ui::with_alpha(th.text_secondary, tag_a), tag);
		}

		float bar_w = std::min(ww_l * 0.55f, 280.f);
		float bar_h = 3.f;
		float bar_x = cx - bar_w * 0.5f;
		float bar_y = wp.y + wh_l - 60.f;

		int total_steps = globals::ui::bg_init_total.load(std::memory_order_acquire);
		int cur_step    = globals::ui::bg_init_step.load(std::memory_order_acquire);
		if (total_steps < 1) total_steps = 1;
		if (cur_step > total_steps) cur_step = total_steps;
		float prog = (float)cur_step / (float)total_steps;

		static float anim_prog = 0.f;
		anim_prog += (prog - anim_prog) * std::min(8.f * dt, 1.f);

		dl->AddRectFilled(ImVec2(bar_x, bar_y),
			ImVec2(bar_x + bar_w, bar_y + bar_h),
			aida::ui::with_alpha(th.panel_header, 0.85f * vis), bar_h * 0.5f);

		float fw = bar_w * anim_prog;
		if (fw > 1.f) {
			dl->AddRectFilledMultiColor(
				ImVec2(bar_x, bar_y), ImVec2(bar_x + fw, bar_y + bar_h),
				aida::ui::with_alpha(th.accent_grad_top, vis),
				aida::ui::with_alpha(th.accent_grad_top, vis),
				aida::ui::with_alpha(th.accent_grad_bot, vis),
				aida::ui::with_alpha(th.accent_grad_bot, vis));

			float sweep_period = 1.4f;
			float ph = fmodf(aida::ui::clock::seconds() / sweep_period, 1.f);
			float sx = bar_x + fw * ph - fw * 0.18f;
			float sw = fw * 0.36f;
			if (sw > 4.f) {
				dl->PushClipRect(ImVec2(bar_x, bar_y), ImVec2(bar_x + fw, bar_y + bar_h), true);
				dl->AddRectFilledMultiColor(
					ImVec2(sx, bar_y), ImVec2(sx + sw * 0.5f, bar_y + bar_h),
					IM_COL32(255,255,255,0), aida::ui::with_alpha(IM_COL32(255,255,255,90), vis),
					aida::ui::with_alpha(IM_COL32(255,255,255,90), vis), IM_COL32(255,255,255,0));
				dl->AddRectFilledMultiColor(
					ImVec2(sx + sw * 0.5f, bar_y), ImVec2(sx + sw, bar_y + bar_h),
					aida::ui::with_alpha(IM_COL32(255,255,255,90), vis), IM_COL32(255,255,255,0),
					IM_COL32(255,255,255,0), aida::ui::with_alpha(IM_COL32(255,255,255,90), vis));
				dl->PopClipRect();
			}
		}

		static const char* k_phase_labels[] = {
			"Bootstrapping",
			"Initializing chat engine",
			"Probing network surface",
			"Arming memory scanner",
			"Spinning up MITM proxy",
			"Loading script engine",
			"Fingerprinting code surface",
			"Activating tamper guard",
			"Ready"
		};
		int phase_idx = cur_step;
		if (phase_idx < 0) phase_idx = 0;
		if (phase_idx > 8) phase_idx = 8;

		static int last_phase = -1;
		static aida::ui::transition_t phase_swap;
		static const char* prev_phase_label = k_phase_labels[0];
		static const char* cur_phase_label  = k_phase_labels[0];
		if (phase_idx != last_phase) {
			prev_phase_label = cur_phase_label;
			cur_phase_label  = k_phase_labels[phase_idx];
			phase_swap.start(0.140f, aida::motion::ease::out_cubic);
			last_phase = phase_idx;
		}
		phase_swap.tick(dt);
		float swap_e = phase_swap.eased();

		ImFont* cap = aida::ui::fonts::caption();
		if (!cap) cap = ImGui::GetFont();
		float cap_size = 12.f;
		float ph_y = bar_y - 22.f;

		ImU32 ph_col = aida::ui::with_alpha(th.text_secondary, vis);
		if (!phase_swap.is_finished() && prev_phase_label) {
			float prev_a = (1.f - swap_e) * vis;
			float prev_y = ph_y - swap_e * 6.f;
			ImVec2 ts_p = cap->CalcTextSizeA(cap_size, FLT_MAX, 0.f, prev_phase_label);
			dl->AddText(cap, cap_size, ImVec2(cx - ts_p.x * 0.5f, prev_y),
				aida::ui::with_alpha(th.text_secondary, prev_a), prev_phase_label);

			float cur_y = ph_y + (1.f - swap_e) * 6.f;
			ImVec2 ts_c = cap->CalcTextSizeA(cap_size, FLT_MAX, 0.f, cur_phase_label);
			dl->AddText(cap, cap_size, ImVec2(cx - ts_c.x * 0.5f, cur_y),
				aida::ui::with_alpha(th.text_secondary, swap_e * vis), cur_phase_label);
		} else {
			ImVec2 ts_c = cap->CalcTextSizeA(cap_size, FLT_MAX, 0.f, cur_phase_label);
			dl->AddText(cap, cap_size, ImVec2(cx - ts_c.x * 0.5f, ph_y), ph_col, cur_phase_label);
		}

		char step_buf[32];
		snprintf(step_buf, sizeof(step_buf), "%d / %d", cur_step, total_steps);
		ImVec2 sb_ts = cap->CalcTextSizeA(14.f, FLT_MAX, 0.f, step_buf);
		dl->AddText(cap, 14.f, ImVec2(cx + bar_w * 0.5f - sb_ts.x, bar_y + bar_h + 10.f),
			aida::ui::with_alpha(th.text_dim, vis), step_buf);

		static POINT drag_start_wnd   = {};
		static POINT drag_start_mouse = {};
		static bool  dragging  = false;
		static bool  last_lmb  = false;
		bool lmb = (GetAsyncKeyState(VK_LBUTTON) & 0x8000) && (GetForegroundWindow() == g_hwnd);
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

		if (!loading && fadeout <= 0.001f && !globals::ui::welcome_done) {
			globals::ui::welcome_done = true;
			globals::ui::ui_alpha = 0.f;
			globals::ui::welcome_timer = 3.5f;
		}

		ImGui::End();
		return;
	}


	if (!globals::ui::welcome_done)
	{
		globals::ui::welcome_done = true;
		globals::ui::ui_alpha = 0.f;
		globals::ui::welcome_timer = 3.5f;
		const auto& th = aida::ui::resolved();
		globals::ui::welcome_timer += dt;
		if (globals::ui::welcome_timer >= 3.5f) { globals::ui::welcome_done = true; globals::ui::ui_alpha = 0.f; }

		ImVec2      wp  = ImGui::GetWindowPos();
		ImDrawList* dl  = ImGui::GetWindowDrawList();
		float       t   = globals::ui::welcome_timer;
		float       ww  = globals::ui::window_w;
		float       wh  = globals::ui::window_h;
		float       cx  = wp.x + ww * 0.5f;
		float       cy  = wp.y + wh * 0.5f - 4.f;

		float fade_in  = std::min(t / 0.6f, 1.f);
		float fade_out = t > 2.6f ? std::max(0.f, 1.f - (t - 2.6f) / 0.9f) : 1.f;
		float base_a   = fade_in * fade_out;

		dl->AddRectFilled(wp, ImVec2(wp.x + ww, wp.y + wh), th.bg_base, 14.f);

		float aura_r = ww * 0.45f;
		for (int i = 0; i < 5; ++i) {
			float rr = aura_r + (float)i * 18.f;
			float fa = (1.f - (float)i / 5.f) * 0.40f * base_a;
			dl->AddCircleFilled(ImVec2(cx, cy),
				rr, aida::ui::with_alpha(th.accent_glow, fa), 64);
		}

		aida::ui::brand::render_constellation(
			dl, ImVec2(cx, cy), 92.f, 12,
			aida::ui::clock::seconds() * 0.4f,
			aida::ui::with_alpha(th.accent_u32, base_a), nullptr);

		float reveal = aida::motion::ease::out_back(std::min(t / 0.480f, 1.f));
		float pulse = aida::ui::clock::pulse(0.6f, 0.0f, 1.0f);
		aida::ui::brand::render_logomark(dl, ImVec2(cx, cy - 26.f), 84.f,
			reveal, pulse, base_a);

		ImFont* display_font = aida::ui::fonts::display();
		if (!display_font) display_font = ImGui::GetFont();
		float wm_total_w = aida::ui::brand::wordmark_total_width(display_font, 1.0f);
		float wm_x = cx - wm_total_w * 0.5f;
		float wm_y = cy + 38.f;
		float wm_reveal = std::min(std::max(t - 0.18f, 0.f) / 0.62f, 1.f);
		aida::ui::brand::render_wordmark(dl, ImVec2(wm_x, wm_y), 1.0f,
			display_font, wm_reveal, base_a);

		float sub_a = std::min(std::max(t - 0.7f, 0.f) / 0.5f, 1.f) * fade_out;
		if (sub_a > 0.01f)
		{
			ImFont* body = aida::ui::fonts::body();
			if (!body) body = ImGui::GetFont();
			const char* tagline = "Reverse engineering, reimagined.";
			ImVec2 ts_t = body->CalcTextSizeA(14.f, FLT_MAX, 0.f, tagline);
			dl->AddText(body, 14.f,
				ImVec2(cx - ts_t.x * 0.5f, wm_y + 32.f + 14.f),
				aida::ui::with_alpha(th.text_secondary, sub_a), tagline);

			float msg_a = std::min(std::max(t - 1.4f, 0.f) / 0.5f, 1.f) * fade_out;
			if (msg_a > 0.01f)
			{
				const char* msg = license::validated
					? "Your session is ready."
					: "Enter your license key to continue.";
				ImVec2 ts_m = body->CalcTextSizeA(13.f, FLT_MAX, 0.f, msg);
				dl->AddText(body, 13.f,
					ImVec2(cx - ts_m.x * 0.5f, wm_y + 32.f + 14.f + 22.f),
					aida::ui::with_alpha(th.text_dim, msg_a), msg);
			}
		}

		ImGui::End();
		return;
	}


	if (!license::validated)
	{
		const auto& th = aida::ui::resolved();
		static float license_alpha = 0.f;
		license_alpha += (1.f - license_alpha) * std::min(6.f * dt, 1.f);

		static aida::ui::transition_t card_intro;
		static bool card_intro_started = false;
		if (!card_intro_started) {
			card_intro.start(0.380f, aida::motion::ease::out_back);
			card_intro_started = true;
		}
		card_intro.tick(dt);
		float intro_e = card_intro.eased();
		float intro_scale = 0.94f + 0.06f * intro_e;

		ImVec2 wp   = ImGui::GetWindowPos();
		float  ww   = globals::ui::window_w;
		float  wh   = globals::ui::window_h;
		float  cx   = wp.x + ww * 0.5f;
		float  cy   = wp.y + wh * 0.5f;
		ImDrawList* dl = ImGui::GetWindowDrawList();
		float la  = license_alpha;

		dl->AddRectFilled(wp, ImVec2(wp.x + ww, wp.y + wh), th.bg_base, 14.f);

		if (g_bg_art_srv && g_bg_art_w > 0 && g_bg_art_h > 0) {
			float aspect_img = (float)g_bg_art_w / (float)g_bg_art_h;
			float aspect_win = ww / wh;
			float bg_w, bg_h;
			if (aspect_img > aspect_win) {
				bg_h = wh;
				bg_w = bg_h * aspect_img;
			} else {
				bg_w = ww;
				bg_h = bg_w / aspect_img;
			}
			float bg_x = wp.x + (ww - bg_w) * 0.5f;
			float bg_y = wp.y + (wh - bg_h) * 0.5f;
			ImU32 bg_tint = aida::ui::with_alpha(IM_COL32_WHITE, 0.36f * la);
			dl->AddImageRounded((ImTextureID)g_bg_art_srv,
				ImVec2(bg_x, bg_y), ImVec2(bg_x + bg_w, bg_y + bg_h),
				ImVec2(0.f, 0.f), ImVec2(1.f, 1.f),
				bg_tint, 14.f);
			dl->AddRectFilled(wp, ImVec2(wp.x + ww, wp.y + wh),
				aida::ui::with_alpha(th.bg_base, 0.55f * la), 14.f);
		}

		float aura_r = ww * 0.45f;
		for (int i = 0; i < 5; ++i) {
			float rr = aura_r + (float)i * 18.f;
			float fa = (1.f - (float)i / 5.f) * 0.30f * la;
			dl->AddCircleFilled(ImVec2(cx, cy), rr,
				aida::ui::with_alpha(th.accent_glow, fa), 64);
		}

		float card_w = std::min(ww - 80.f, 420.f);
		float card_h = std::min(wh - 80.f, 320.f);
		card_w *= intro_scale;
		card_h *= intro_scale;

		static aida::ui::transition_t shake;
		static int shake_seed = 0;
		float shake_x = 0.f;
		if (license::check_failed) {
			static bool shake_started = false;
			if (!shake_started) {
				shake.start(0.280f, aida::motion::ease::out_quint);
				shake_started = true;
				shake_seed++;
			}
			shake.tick(dt);
			if (shake.is_finished()) shake_started = false;
			float sp = shake.progress;
			shake_x = sinf(sp * 18.84955f) * 6.f * (1.f - sp);
		} else {
			shake.reset();
		}

		ImVec2 card_a(cx - card_w * 0.5f + shake_x, cy - card_h * 0.5f);
		ImVec2 card_b(card_a.x + card_w, card_a.y + card_h);

		aida::ui::blur::layer_request_t req;
		req.pos = card_a;
		req.size = ImVec2(card_w, card_h);
		req.radius = 16.f;
		req.strength = 0.7f;
		req.alpha = la;
		aida::ui::blur::schedule(req);

		float pad = 22.f;
		float inner_w = card_w - pad * 2.f;
		float content_x = card_a.x + pad;
		float content_y = card_a.y + pad;

		ImVec2 lock_c(cx + shake_x, content_y + 32.f);
		aida::ui::brand::render_lock_icon(dl, lock_c, 52.f,
			th.text_primary, th.accent_u32, la * intro_e);

		ImFont* h1f = aida::ui::fonts::h1();
		ImFont* body = aida::ui::fonts::body();
		ImFont* body_em = aida::ui::fonts::body_em();
		if (!h1f) h1f = ImGui::GetFont();
		if (!body) body = ImGui::GetFont();
		if (!body_em) body_em = ImGui::GetFont();

		float gs = ImGui::GetIO().FontGlobalScale;
		const char* title = "Welcome to AiDA";
		float title_size = 22.f;
		ImVec2 title_ts = h1f->CalcTextSizeA(title_size, FLT_MAX, 0.f, title);
		dl->AddText(h1f, title_size,
			ImVec2(cx - title_ts.x * 0.5f + shake_x, content_y + 70.f),
			aida::ui::with_alpha(th.text_primary, la), title);

		const char* sub = "Enter your license key to continue.";
		float sub_size = 14.f;
		ImVec2 sub_ts = body->CalcTextSizeA(sub_size, FLT_MAX, 0.f, sub);
		dl->AddText(body, sub_size,
			ImVec2(cx - sub_ts.x * 0.5f + shake_x, content_y + 70.f + 30.f),
			aida::ui::with_alpha(th.text_secondary, la), sub);

		float input_w = inner_w;
		float input_h = 42.f;
		float input_x_screen = content_x;
		float input_y_screen = content_y + 134.f;

		ImVec2 in_a(input_x_screen, input_y_screen);
		ImVec2 in_b(input_x_screen + input_w, input_y_screen + input_h);

		static aida::ui::hover_state_t input_focus;
		static aida::ui::hover_state_t input_hover;

		bool input_active = false;
		bool enter = false;
		bool input_hovered = ImGui::IsMouseHoveringRect(in_a, in_b);

		input_hover.tick(input_hovered, dt, aida::motion::spring::balanced);

		ImGui::SetCursorScreenPos(ImVec2(in_a.x + 14.f, in_a.y + (input_h - ImGui::GetFontSize()) * 0.5f));
		ImGui::PushID("license_input");
		ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0,0,0,0));
		ImGui::PushStyleColor(ImGuiCol_FrameBgHovered, ImVec4(0,0,0,0));
		ImGui::PushStyleColor(ImGuiCol_FrameBgActive, ImVec4(0,0,0,0));
		ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.f, 0.f, 0.f, 0.f));
		ImGui::PushStyleColor(ImGuiCol_TextSelectedBg, ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.accent_u32, 0.45f * la)));
		ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(0.f, 0.f));
		ImGui::SetNextItemWidth(input_w - 28.f);

		auto lic_callback = [](ImGuiInputTextCallbackData* data) -> int {
			if (data->EventFlag == ImGuiInputTextFlags_CallbackCharFilter) {
				ImWchar c = data->EventChar;
				if (c >= 'a' && c <= 'z') {
					data->EventChar = (ImWchar)(c - 'a' + 'A');
					return 0;
				}
				if ((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-')
					return 0;
				return 1;
			}
			if (data->EventFlag == ImGuiInputTextFlags_CallbackEdit) {
				char tmp[256] = {};
				int j = 0;
				int alnum = 0;
				for (int i = 0; i < data->BufTextLen && j < (int)sizeof(tmp) - 1; ++i) {
					char ch = data->Buf[i];
					if (ch == '-') continue;
					if (alnum == 4 && j < (int)sizeof(tmp) - 1) { tmp[j++] = '-'; alnum = 0; }
					tmp[j++] = ch;
					alnum++;
				}
				tmp[j] = '\0';
				if (strcmp(tmp, data->Buf) != 0) {
					data->DeleteChars(0, data->BufTextLen);
					data->InsertChars(0, tmp);
				}
			}
			return 0;
		};

		if (ImGui::GetFrameCount() < 5)
			ImGui::SetKeyboardFocusHere();

		ImGuiInputTextFlags flags = ImGuiInputTextFlags_EnterReturnsTrue |
			ImGuiInputTextFlags_CallbackCharFilter | ImGuiInputTextFlags_CallbackEdit;
		enter = ImGui::InputText("##license_key", license::key_buf, sizeof(license::key_buf),
			flags, lic_callback);
		input_active = ImGui::IsItemActive();

		ImGui::PopStyleVar();
		ImGui::PopStyleColor(5);
		ImGui::PopID();

		float focus_v = input_focus.tick(input_active, dt, aida::motion::spring::balanced);
		float ring_thick = focus_v * 2.5f + (1.f - focus_v) * 1.2f;
		float input_radius = 12.f;
		aida::ui::blur::layer_request_t in_req;
		in_req.pos = in_a;
		in_req.size = ImVec2(in_b.x - in_a.x, in_b.y - in_a.y);
		in_req.radius = input_radius;
		in_req.strength = 0.55f;
		in_req.alpha = la;
		aida::ui::blur::schedule(in_req);
		ImU32 fill_col = aida::ui::with_alpha(IM_COL32(10, 10, 22, 200), 0.55f * la);
		dl->AddRectFilled(in_a, in_b, fill_col, input_radius);
		ImU32 ring = aida::ui::mix(th.border_subtle, th.border_focus, focus_v);
		dl->AddRect(in_a, in_b, aida::ui::with_alpha(ring, la), input_radius, 0, ring_thick);

		if (license::key_buf[0] == '\0' && !input_active) {
			ImFont* code = aida::ui::fonts::code();
			if (!code) code = ImGui::GetFont();
			dl->AddText(code, 15.f,
				ImVec2(in_a.x + 16.f, in_a.y + (input_h - 15.f) * 0.5f),
				aida::ui::with_alpha(th.text_dim, la), "AiDA-XXXX-XXXX-XXXX-XXXX");
		} else {
			ImFont* code = aida::ui::fonts::code();
			if (!code) code = ImGui::GetFont();
			dl->AddText(code, 15.f,
				ImVec2(in_a.x + 16.f, in_a.y + (input_h - 15.f) * 0.5f),
				aida::ui::with_alpha(th.text_primary, la), license::key_buf);
			if (input_active) {
				float caret_a = aida::ui::clock::pulse(2.0f, 0.3f, 1.0f);
				float text_w = code->CalcTextSizeA(15.f, FLT_MAX, 0.f, license::key_buf).x;
				float cax = in_a.x + 16.f + text_w + 1.f;
				dl->AddLine(ImVec2(cax, in_a.y + 10.f), ImVec2(cax, in_b.y - 10.f),
					aida::ui::with_alpha(th.text_primary, la * caret_a), 1.7f);
			}
		}

		float btn_h = 42.f;
		float btn_y_screen = input_y_screen + input_h + 16.f;
		ImVec2 btn_a(input_x_screen, btn_y_screen);
		ImVec2 btn_b(input_x_screen + input_w, btn_y_screen + btn_h);

		static aida::ui::hover_state_t btn_hover;
		static aida::ui::press_state_t btn_press;
		static aida::ui::flash_t btn_flash;
		bool btn_hov = !license::checking && ImGui::IsMouseHoveringRect(btn_a, btn_b);
		bool btn_held = btn_hov && (GetAsyncKeyState(VK_LBUTTON) & 0x8000);
		float bhov_v = btn_hover.tick(btn_hov, dt, aida::motion::spring::balanced);
		float bprs_v = btn_press.tick(btn_held, dt);
		float bf = btn_flash.tick(dt);

		ImGui::SetCursorScreenPos(btn_a);
		ImGui::InvisibleButton("##activate_btn", ImVec2(input_w, btn_h));
		bool btn_clicked = ImGui::IsItemDeactivated() && ImGui::IsItemHovered() && !license::checking;

		float lift = bhov_v * 2.5f - bprs_v * 2.f;
		float scl = 1.f - (1.f - 0.97f) * bprs_v;
		ImVec2 cb_a(btn_a.x + (1.f - scl) * input_w * 0.5f, btn_a.y + (1.f - scl) * btn_h * 0.5f - lift);
		ImVec2 cb_b(btn_b.x - (1.f - scl) * input_w * 0.5f, btn_b.y - (1.f - scl) * btn_h * 0.5f - lift);
		float btn_radius = 10.f;

		aida::ui::blur::render_drop_shadow(dl, cb_a, cb_b, btn_radius, 4,
			(0.32f + 0.18f * bhov_v) * la, ImVec2(0.f, 4.f + 2.f * bhov_v));

		aida::ui::blur::layer_request_t btn_blur_req;
		btn_blur_req.pos = cb_a;
		btn_blur_req.size = ImVec2(cb_b.x - cb_a.x, cb_b.y - cb_a.y);
		btn_blur_req.radius = btn_radius;
		btn_blur_req.strength = 0.7f;
		btn_blur_req.alpha = la;
		aida::ui::blur::schedule(btn_blur_req);

		ImU32 fill_base = aida::ui::with_alpha(IM_COL32(255, 255, 255, 14), la * (0.6f + 0.4f * bhov_v));
		dl->AddRectFilled(cb_a, cb_b, fill_base, btn_radius);

		ImU32 fill_top = aida::ui::with_alpha(th.accent_grad_top, (0.45f + 0.30f * bhov_v) * la);
		ImU32 fill_bot = aida::ui::with_alpha(th.accent_grad_bot, (0.55f + 0.30f * bhov_v) * la);
		ImU32 fill_avg = aida::ui::mix(fill_top, fill_bot, 0.6f);
		dl->AddRectFilled(cb_a, cb_b, fill_avg, btn_radius);

		dl->PushClipRect(cb_a, cb_b, true);
		dl->AddRectFilledMultiColor(
			cb_a, ImVec2(cb_b.x, cb_a.y + (cb_b.y - cb_a.y) * 0.5f),
			aida::ui::with_alpha(IM_COL32(255, 255, 255, 70), la),
			aida::ui::with_alpha(IM_COL32(255, 255, 255, 70), la),
			aida::ui::with_alpha(IM_COL32(255, 255, 255,  0), la),
			aida::ui::with_alpha(IM_COL32(255, 255, 255,  0), la));
		dl->PopClipRect();

		dl->AddRect(cb_a, cb_b,
			aida::ui::with_alpha(IM_COL32(255, 255, 255, 180), (0.55f + 0.40f * bhov_v) * la),
			btn_radius, 0, 1.2f);

		if (bf > 0.f) {
			dl->AddRectFilled(cb_a, cb_b,
				aida::ui::with_alpha(IM_COL32(255,255,255,255), bf * 0.22f), btn_radius);
		}
		if (btn_clicked) btn_flash.trigger();

		if (license::checking) {
			ImVec2 ring_c((cb_a.x + cb_b.x) * 0.5f, (cb_a.y + cb_b.y) * 0.5f);
			float t_sec = aida::ui::clock::seconds() * 4.f;
			float arc_len = 1.4f;
			for (int i = 0; i < 24; ++i) {
				float a0 = t_sec + (float)i / 24.f * arc_len;
				float a1 = t_sec + (float)(i + 1) / 24.f * arc_len;
				float fade = 1.f - (float)i / 24.f;
				dl->PathArcTo(ring_c, 10.f, a0, a1, 4);
				dl->PathStroke(aida::ui::with_alpha(IM_COL32(255,255,255,255),
					la * fade), 0, 2.2f);
			}
		} else {
			ImFont* h2f = aida::ui::fonts::h2();
			if (!h2f) h2f = ImGui::GetFont();
			const char* btn_label = "Activate";
			float lbl_size = 16.f;
			ImVec2 ts = h2f->CalcTextSizeA(lbl_size, FLT_MAX, 0.f, btn_label);
			dl->AddText(h2f, lbl_size,
				ImVec2((cb_a.x + cb_b.x) * 0.5f - ts.x * 0.5f, (cb_a.y + cb_b.y) * 0.5f - ts.y * 0.5f),
				aida::ui::with_alpha(IM_COL32(255,255,255,255), la), btn_label);
		}

		if (license::checking) {
			static const char* k_act_phases[] = {
				"Resolving license server...",
				"Verifying signature...",
				"Issuing session...",
				"Downloading runtime...",
				"Sealing..."
			};
			int act_phase = globals::ui::license_activation_phase.load(std::memory_order_acquire);
			if (act_phase < 0) act_phase = 0;
			if (act_phase > 4) act_phase = 4;

			float pb_x = input_x_screen;
			float pb_y = btn_y_screen + btn_h + 16.f;
			float pb_w = input_w;
			ImGui::GetWindowDrawList();
			ImGui::SetCursorScreenPos(ImVec2(pb_x, pb_y));
			aida::ui::render_progress_bar(ImVec2(pb_x, pb_y), pb_w, 4.f,
				(float)(act_phase + 1) / 5.f, false, true);

			static int last_act_phase = -1;
			static aida::ui::transition_t act_swap;
			static const char* prev_lbl = k_act_phases[0];
			static const char* cur_lbl  = k_act_phases[0];
			if (act_phase != last_act_phase) {
				prev_lbl = cur_lbl;
				cur_lbl  = k_act_phases[act_phase];
				act_swap.start(0.120f, aida::motion::ease::out_cubic);
				last_act_phase = act_phase;
			}
			act_swap.tick(dt);
			float sw = act_swap.eased();
			ImFont* phase_font = aida::ui::fonts::body();
			if (!phase_font) phase_font = ImGui::GetFont();
			float phase_size = 16.f;
			float lbl_y = pb_y + 14.f;
			if (!act_swap.is_finished() && prev_lbl) {
				ImVec2 ts_p = phase_font->CalcTextSizeA(phase_size, FLT_MAX, 0.f, prev_lbl);
				dl->AddText(phase_font, phase_size,
					ImVec2(cx - ts_p.x * 0.5f + shake_x, lbl_y - sw * 6.f),
					aida::ui::with_alpha(th.text_secondary, (1.f - sw) * la), prev_lbl);
				ImVec2 ts_c = phase_font->CalcTextSizeA(phase_size, FLT_MAX, 0.f, cur_lbl);
				dl->AddText(phase_font, phase_size,
					ImVec2(cx - ts_c.x * 0.5f + shake_x, lbl_y + (1.f - sw) * 6.f),
					aida::ui::with_alpha(th.text_secondary, sw * la), cur_lbl);
			} else {
				ImVec2 ts_c = phase_font->CalcTextSizeA(phase_size, FLT_MAX, 0.f, cur_lbl);
				dl->AddText(phase_font, phase_size,
					ImVec2(cx - ts_c.x * 0.5f + shake_x, lbl_y),
					aida::ui::with_alpha(th.text_secondary, la), cur_lbl);
			}
		}

		int arc_phase = globals::ui::arc_unseal_phase.load(std::memory_order_acquire);
		if (arc_phase == 1) {
			ImFont* arc_font = aida::ui::fonts::body();
			if (!arc_font) arc_font = ImGui::GetFont();
			const char* msg = "Decrypting runtime core...";
			float arc_size = 16.f;
			float pill_y = card_b.y + 18.f;
			ImVec2 ts = arc_font->CalcTextSizeA(arc_size, FLT_MAX, 0.f, msg);
			float pill_w = ts.x + 56.f;
			float pill_h = 34.f;
			ImVec2 pa(cx - pill_w * 0.5f, pill_y);
			ImVec2 pb(pa.x + pill_w, pa.y + pill_h);
			dl->AddRectFilled(pa, pb, aida::ui::with_alpha(th.info_soft, la), pill_h * 0.5f);
			dl->AddRect(pa, pb, aida::ui::with_alpha(th.info, 0.55f * la), pill_h * 0.5f, 0, 1.f);
			ImVec2 ring_c(pa.x + 20.f, (pa.y + pb.y) * 0.5f);
			aida::ui::render_progress_ring(ring_c, 9.f, 1.6f, 0.f, true);
			dl->AddText(arc_font, arc_size,
				ImVec2(pa.x + 38.f, pa.y + (pill_h - arc_size) * 0.5f),
				aida::ui::with_alpha(th.info, la), msg);
		}

		if ((enter || btn_clicked) && !license::checking && strlen(license::key_buf) > 0)
		{
			license::checking    = true;
			license::check_failed = false;
			license::error_msg.clear();
			globals::ui::license_activation_phase.store(0, std::memory_order_release);

			std::string key_copy(license::key_buf);
			work_queue::post([key_copy]() {
				BOOL activation_ok = FALSE;
				char err_buf[1024] = {};
				DWORD seh_code = seh_license_activate(key_copy.c_str(),
				                                     &activation_ok,
				                                     err_buf, sizeof(err_buf));

				try {
					if (seh_code != 0) {
						char dbg[160];
						_snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
							"Activation crashed (SEH 0x%08X). Please retry.",
							static_cast<unsigned int>(seh_code));
						license::error_msg = dbg;
						license::check_failed = true;
					}
					else if (activation_ok) {
						license::saved_key = key_copy;
						license::validated = true;
						license::error_msg.clear();
					}
					else {
						license::error_msg = (err_buf[0] != '\0')
						    ? std::string(err_buf)
						    : std::string("License validation failed.");
						license::check_failed = true;
					}
				} catch (...) {
					license::check_failed = true;
				}
				license::checking = false;
			});
		}


		if (license::check_failed && !license::error_msg.empty())
		{
			ImFont* err_font = aida::ui::fonts::body();
			if (!err_font) err_font = ImGui::GetFont();
			float err_font_size = 14.f;
			float err_y = btn_y_screen + btn_h + 22.f;

			float ic_x = card_a.x + pad;
			float ic_y = err_y + 4.f;
			ImVec2 ic_c(ic_x + 9.f, ic_y + 9.f);
			dl->AddCircleFilled(ic_c, 9.f, aida::ui::with_alpha(th.error_soft, la), 16);
			dl->AddCircle(ic_c, 9.f, aida::ui::with_alpha(th.error, la), 16, 1.2f);
			dl->AddText(err_font, 13.f, ImVec2(ic_c.x - 2.f, ic_c.y - 7.f),
				aida::ui::with_alpha(th.error, la), "!");

			float msg_x = ic_x + 26.f;
			float msg_w = inner_w - 26.f - 110.f;
			std::string mapped = license::error_msg;
			if (mapped.find("not_found") != std::string::npos) {
				mapped = "This license/session is no longer present on the server. Activate the current key.";
			}
			dl->AddText(err_font, err_font_size, ImVec2(msg_x, err_y),
				aida::ui::with_alpha(th.error, la),
				mapped.c_str(), nullptr, msg_w);

			ImVec2 disc_a(card_b.x - pad - 108.f, err_y - 4.f);
			ImVec2 disc_b(disc_a.x + 108.f, err_y - 4.f + 30.f);
			static aida::ui::hover_state_t disc_h;
			bool disc_hov = ImGui::IsMouseHoveringRect(disc_a, disc_b);
			float dhv = disc_h.tick(disc_hov, dt, aida::motion::spring::balanced);
			ImGui::SetCursorScreenPos(disc_a);
			ImGui::InvisibleButton("##disc_btn", ImVec2(108.f, 30.f));
			bool disc_clk = ImGui::IsItemDeactivated() && ImGui::IsItemHovered();
			float disc_radius = 10.f;
			aida::ui::blur::layer_request_t disc_req;
			disc_req.pos = disc_a;
			disc_req.size = ImVec2(108.f, 30.f);
			disc_req.radius = disc_radius;
			disc_req.strength = 0.55f;
			disc_req.alpha = la;
			aida::ui::blur::schedule(disc_req);
			ImU32 disc_fill = aida::ui::with_alpha(IM_COL32(255, 255, 255, 12), la * (0.6f + 0.6f * dhv));
			dl->AddRectFilled(disc_a, disc_b, disc_fill, disc_radius);
			ImU32 disc_border = aida::ui::with_alpha(th.border_subtle, la * (0.7f + 0.5f * dhv));
			dl->AddRect(disc_a, disc_b, disc_border, disc_radius, 0, 1.2f);
			ImFont* sm_font = aida::ui::fonts::caption();
			if (!sm_font) sm_font = ImGui::GetFont();
			float disc_lbl = 13.f;
			ImVec2 dts = sm_font->CalcTextSizeA(disc_lbl, FLT_MAX, 0.f, "Get a key");
			dl->AddText(sm_font, disc_lbl,
				ImVec2((disc_a.x + disc_b.x) * 0.5f - dts.x * 0.5f, (disc_a.y + disc_b.y) * 0.5f - dts.y * 0.5f),
				aida::ui::with_alpha(th.text_primary, la), "Get a key");
			if (disc_clk) {
				ShellExecuteA(nullptr, "open", "https://discord.gg/aida", nullptr, nullptr, SW_SHOWNORMAL);
			}
		}

		if (license::validated) {
			static aida::ui::transition_t check_anim;
			static aida::ui::transition_t burst_anim;
			static bool started = false;
			if (!started) {
				check_anim.start(0.220f, aida::motion::ease::out_quint);
				burst_anim.start(0.480f, aida::motion::ease::out_quint, 0.220f);
				started = true;
			}
			check_anim.tick(dt);
			burst_anim.tick(dt);
			ImVec2 cm_c((cb_a.x + cb_b.x) * 0.5f, (cb_a.y + cb_b.y) * 0.5f);
			aida::ui::brand::render_check_drawn(dl, cm_c, 24.f,
				check_anim.eased(), aida::ui::with_alpha(IM_COL32(255,255,255,255), la), 2.5f);
			aida::ui::brand::render_sparkle_burst(dl, cm_c, burst_anim.progress, 36.f,
				aida::ui::with_alpha(th.accent_u32, la), 10);
		}

		{
			static POINT lic_drag_wnd = {};
			static POINT lic_drag_mouse = {};
			static bool  lic_dragging = false;
			static bool  lic_last_lmb = false;
			bool lmb = (GetAsyncKeyState(VK_LBUTTON) & 0x8000) && (GetForegroundWindow() == g_hwnd);
			if (lmb && !lic_last_lmb) {
				POINT cp; GetCursorPos(&cp);
				RECT wr; GetWindowRect(g_hwnd, &wr);
				int local_y = cp.y - wr.top;
				bool over_card = cp.x >= (int)card_a.x && cp.x <= (int)card_b.x &&
				                 cp.y >= (int)card_a.y && cp.y <= (int)card_b.y;
				if (cp.x >= wr.left && cp.x <= wr.right && cp.y >= wr.top && cp.y <= wr.bottom &&
					local_y < (wr.bottom - wr.top) / 2 && !over_card) {
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


	g_render_section = "ide_layout";
	float a = globals::ui::ui_alpha;


	const float pad      = 6.f;
	const float gap      = 4.f;
	const float title_h  = 32.f;
	const float menu_h   = 24.f;
	const float status_h = 28.f;
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
			globals::ui::decompile_default_mode = g_sa_settings.decompile_default_mode;
			s_layout_synced = true;
		}
	}

	float ab_for_layout = g_sa_settings.activity_bar_visible ? globals::ui::activity_bar_w : 0.f;
	float usable = ww - pad * 2.f - gap * 2.f - ab_for_layout;
	float min_panel = 80.f;
	float max_left  = usable * 0.3f;
	float max_right = usable * 0.5f;

	static float s_anim_left_w  = 0.f;
	static float s_anim_right_w = 0.f;
	static float s_anim_bottom_h = 0.f;
	{
		float target_left  = globals::ui::panel_left_visible  ? globals::ui::panel_left_w  : 0.f;
		float target_right = globals::ui::panel_right_visible ? globals::ui::panel_right_w : 0.f;
		float target_bot   = globals::ui::panel_bottom_visible ? globals::ui::panel_bottom_h : 0.f;
		float anim_speed = std::min(14.f * dt, 1.f);
		s_anim_left_w  += (target_left  - s_anim_left_w)  * anim_speed;
		s_anim_right_w += (target_right - s_anim_right_w) * anim_speed;
		s_anim_bottom_h += (target_bot  - s_anim_bottom_h) * anim_speed;
		if (std::abs(s_anim_left_w  - target_left)  < 1.f) s_anim_left_w  = target_left;
		if (std::abs(s_anim_right_w - target_right) < 1.f) s_anim_right_w = target_right;
		if (std::abs(s_anim_bottom_h - target_bot)  < 1.f) s_anim_bottom_h = target_bot;
	}
	float left_w   = s_anim_left_w;
	float right_w  = s_anim_right_w;
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
	if (globals::ui::panel_left_visible && s_anim_left_w >= globals::ui::panel_left_w - 1.f && left_w < min_panel) left_w = min_panel;
	if (globals::ui::panel_right_visible && s_anim_right_w >= globals::ui::panel_right_w - 1.f && right_w < min_panel) right_w = min_panel;
	if (globals::ui::panel_left_visible && s_anim_left_w >= globals::ui::panel_left_w - 1.f)
		globals::ui::panel_left_w = left_w;
	if (globals::ui::panel_right_visible && s_anim_right_w >= globals::ui::panel_right_w - 1.f)
		globals::ui::panel_right_w = right_w;
	center_w = usable - left_w - right_w;
	if (center_w < 100.f) center_w = 100.f;

	float bottom_h = s_anim_bottom_h;
	float chrome_h = title_h + menu_h + status_h;
	float total_h  = wh - pad * 2.f - chrome_h - (bottom_h > 1.f ? (bottom_h + gap) : 0.f);
	float right_total_h = wh - pad * 2.f - chrome_h;
	float content_top = pad + title_h + menu_h;

	g_render_section = "title_bar";
	ImGui::PushStyleVar(ImGuiStyleVar_Alpha, a);


	{
		ImVec2 wp   = ImGui::GetWindowPos();
		ImDrawList* dl = ImGui::GetWindowDrawList();
		const auto& th_tb = aida::ui::resolved();

		ImVec2 tb_a(wp.x, wp.y);
		ImVec2 tb_b(wp.x + ww, wp.y + title_h);

		aida::ui::blur::layer_request_t tb_req;
		tb_req.pos = tb_a;
		tb_req.size = ImVec2(ww, title_h);
		tb_req.radius = 0.f;
		tb_req.strength = 0.55f;
		tb_req.alpha = a;
		aida::ui::blur::schedule(tb_req);
		dl->AddRectFilled(tb_a, tb_b, aida::ui::with_alpha(th_tb.title_bar, a), 8.f, ImDrawFlags_RoundCornersTop);
		dl->AddRectFilled(tb_a, tb_b, aida::ui::with_alpha(th_tb.glass_tint, a * 0.5f), 8.f, ImDrawFlags_RoundCornersTop);
		dl->AddLine(ImVec2(wp.x, wp.y + title_h), ImVec2(wp.x + ww, wp.y + title_h),
			aida::ui::with_alpha(th_tb.border_subtle, a));

		float pulse = aida::ui::clock::pulse(0.6f, 0.0f, 1.0f);
		ImVec2 logo_c(wp.x + 22.f, wp.y + title_h * 0.5f);
		if (g_aida_logo_srv && g_aida_logo_w > 0 && g_aida_logo_h > 0) {
			float ls = 22.f * (0.95f + 0.05f * pulse);
			float aspect = (float)g_aida_logo_w / (float)g_aida_logo_h;
			float lw = ls * aspect;
			float lh = ls;
			ImU32 logo_tint = aida::ui::with_alpha(IM_COL32_WHITE, a);
			dl->AddImage((ImTextureID)g_aida_logo_srv,
				ImVec2(logo_c.x - lw * 0.5f, logo_c.y - lh * 0.5f),
				ImVec2(logo_c.x + lw * 0.5f, logo_c.y + lh * 0.5f),
				ImVec2(0.f, 0.f), ImVec2(1.f, 1.f), logo_tint);
		} else {
			aida::ui::brand::render_logomark(dl, logo_c, 22.f, 1.0f, pulse, a);
		}

		ImFont* h2f = aida::ui::fonts::h2();
		if (!h2f) h2f = ImGui::GetFont();
		const char* app_name = "AiDA";
		ImVec2 name_ts = h2f->CalcTextSizeA(14.f, FLT_MAX, 0.f, app_name);
		dl->AddText(h2f, 14.f,
			ImVec2(wp.x + 38.f, wp.y + (title_h - 14.f) * 0.5f),
			aida::ui::with_alpha(th_tb.text_primary, a), app_name);

		{
			ImFont* body = aida::ui::fonts::body();
			if (!body) body = ImGui::GetFont();
			float bc_x = wp.x + 38.f + name_ts.x + 10.f;
			float bc_y = wp.y + (title_h - 12.f) * 0.5f;
			std::vector<std::string> segs;
			if (g_disasm.file.loaded) segs.push_back(g_disasm.file.filename);
			if (code_editor::active && !code_editor::filename.empty())
				segs.push_back(code_editor::filename);
			switch (globals::ui::active_center_view) {
				case center_view_t::disassembly: segs.push_back("Disassembly"); break;
				case center_view_t::decompiler:  segs.push_back("Decompiler"); break;
				case center_view_t::hex_view:    segs.push_back("Hex"); break;
				case center_view_t::network_view:segs.push_back("Network"); break;
				case center_view_t::scan_hub:    segs.push_back("Scan"); break;
				case center_view_t::types_hub:   segs.push_back("Types"); break;
				case center_view_t::analysis_hub:segs.push_back("Analysis"); break;
				case center_view_t::binary_map:  segs.push_back("Binary Map"); break;
				case center_view_t::debugger_view:segs.push_back("Debugger"); break;
				case center_view_t::welcome:
				default: break;
			}
			float sep_w = body->CalcTextSizeA(12.f, FLT_MAX, 0.f, "›").x;
			for (size_t si = 0; si < segs.size(); ++si) {
				dl->AddText(body, 12.f, ImVec2(bc_x, bc_y),
					aida::ui::with_alpha(th_tb.text_dim, a), "›");
				bc_x += sep_w + 8.f;
				ImVec2 ss = body->CalcTextSizeA(12.f, FLT_MAX, 0.f, segs[si].c_str());
				ImVec2 sa(bc_x - 4.f, bc_y - 2.f);
				ImVec2 sb_pt(bc_x + ss.x + 4.f, bc_y + ss.y + 2.f);
				bool h_seg = ImGui::IsMouseHoveringRect(sa, sb_pt);
				if (h_seg) dl->AddRectFilled(sa, sb_pt, aida::ui::with_alpha(th_tb.hover_wash, a), 4.f);
				ImU32 col = (si == segs.size() - 1) ? th_tb.text_primary : th_tb.text_secondary;
				dl->AddText(body, 12.f, ImVec2(bc_x, bc_y - (h_seg ? 1.f : 0.f)),
					aida::ui::with_alpha(col, a), segs[si].c_str());
				bc_x += ss.x + 8.f;
			}
		}

		auto draw_ctl = [&](float right_offset, const char* tag) -> std::pair<ImVec2, ImVec2> {
			float ctl_sz = 22.f;
			ImVec2 cp(wp.x + ww - right_offset - ctl_sz, wp.y + (title_h - ctl_sz) * 0.5f);
			ImVec2 ce(cp.x + ctl_sz, cp.y + ctl_sz);
			(void)tag;
			return {cp, ce};
		};

		float ctl_off = 8.f;

		auto [close_a, close_b] = draw_ctl(ctl_off, "x");
		bool close_hov = ImGui::IsMouseHoveringRect(close_a, close_b);
		static aida::ui::hover_state_t close_h;
		float chv = close_h.tick(close_hov, dt, aida::motion::spring::balanced);
		if (chv > 0.01f) {
			dl->AddRectFilled(close_a, close_b,
				aida::ui::with_alpha(IM_COL32(220, 70, 80, 255), 0.20f * chv * a), 6.f);
		}
		ImVec2 xc((close_a.x + close_b.x) * 0.5f, (close_a.y + close_b.y) * 0.5f);
		float xr = 5.f;
		ImU32 xcol = aida::ui::mix(th_tb.text_primary, IM_COL32(255, 130, 138, 255), chv);
		float xth = 1.7f + chv * 0.6f;
		dl->AddLine(ImVec2(xc.x - xr, xc.y - xr), ImVec2(xc.x + xr, xc.y + xr),
			aida::ui::with_alpha(xcol, a), xth);
		dl->AddLine(ImVec2(xc.x + xr, xc.y - xr), ImVec2(xc.x - xr, xc.y + xr),
			aida::ui::with_alpha(xcol, a), xth);
		if (close_hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
			DestroyWindow(g_hwnd);
			PostQuitMessage(0);
			ExitProcess(0);
		}
		ctl_off += 22.f + 6.f;

		auto [max_a, max_b] = draw_ctl(ctl_off, "m");
		bool max_hov = ImGui::IsMouseHoveringRect(max_a, max_b);
		static aida::ui::hover_state_t max_h;
		float mhv = max_h.tick(max_hov, dt, aida::motion::spring::balanced);
		if (mhv > 0.01f) {
			dl->AddRectFilled(max_a, max_b,
				aida::ui::with_alpha(th_tb.hover_wash, mhv * a), 6.f);
		}
		ImVec2 mc((max_a.x + max_b.x) * 0.5f, (max_a.y + max_b.y) * 0.5f);
		float mr = 5.f;
		ImU32 mcol = th_tb.text_primary;
		if (globals::ui::maximized) {
			dl->AddRect(ImVec2(mc.x - mr, mc.y - mr + 1.5f), ImVec2(mc.x + mr - 1.5f, mc.y + mr),
				aida::ui::with_alpha(mcol, a), 1.f, 0, 1.4f);
			dl->AddRect(ImVec2(mc.x - mr + 1.5f, mc.y - mr), ImVec2(mc.x + mr, mc.y + mr - 1.5f),
				aida::ui::with_alpha(mcol, a), 1.f, 0, 1.4f);
		} else {
			dl->AddRect(ImVec2(mc.x - mr, mc.y - mr), ImVec2(mc.x + mr, mc.y + mr),
				aida::ui::with_alpha(mcol, a), 1.f, 0, 1.4f);
		}
		if (max_hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
			if (globals::ui::maximized) {
				globals::ui::maximized = false;
				globals::ui::window_w = globals::ui::pre_max_w;
				globals::ui::window_h = globals::ui::pre_max_h;
				SetWindowPos(g_hwnd, nullptr,
					(int)globals::ui::pre_max_x, (int)globals::ui::pre_max_y,
					(int)globals::ui::pre_max_w, (int)globals::ui::pre_max_h,
					SWP_NOZORDER);
				HRGN rgn = CreateRoundRectRgn(0, 0, (int)globals::ui::pre_max_w, (int)globals::ui::pre_max_h, 16, 16);
				SetWindowRgn(g_hwnd, rgn, TRUE);
				DWM_WINDOW_CORNER_PREFERENCE cp_w = DWMWCP_ROUND;
				DwmSetWindowAttribute(g_hwnd, DWMWA_WINDOW_CORNER_PREFERENCE, &cp_w, sizeof(cp_w));
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
				SetWindowRgn(g_hwnd, nullptr, TRUE);
				DWM_WINDOW_CORNER_PREFERENCE cp_w = DWMWCP_DONOTROUND;
				DwmSetWindowAttribute(g_hwnd, DWMWA_WINDOW_CORNER_PREFERENCE, &cp_w, sizeof(cp_w));
			}
		}
		ctl_off += 22.f + 6.f;

		auto [min_a, min_b] = draw_ctl(ctl_off, "n");
		bool min_hov = ImGui::IsMouseHoveringRect(min_a, min_b);
		static aida::ui::hover_state_t min_hh;
		float mnv = min_hh.tick(min_hov, dt, aida::motion::spring::balanced);
		if (mnv > 0.01f) {
			dl->AddRectFilled(min_a, min_b,
				aida::ui::with_alpha(th_tb.hover_wash, mnv * a), 6.f);
		}
		ImU32 mncol = th_tb.text_primary;
		float minc_x = (min_a.x + min_b.x) * 0.5f;
		float minc_y = (min_a.y + min_b.y) * 0.5f + mnv * 2.f;
		dl->AddLine(ImVec2(minc_x - 5.f, minc_y), ImVec2(minc_x + 5.f, minc_y),
			aida::ui::with_alpha(mncol, a), 1.7f);
		if (min_hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
			ShowWindow(g_hwnd, SW_MINIMIZE);
		ctl_off += 22.f + 12.f;


		{
			ImFont* sm_font = aida::ui::fonts::caption();
			if (!sm_font) sm_font = ImGui::GetFont();
			float bell_sz = 22.f;
			ImVec2 bell_a(wp.x + ww - ctl_off - bell_sz, wp.y + (title_h - bell_sz) * 0.5f);
			ImVec2 bell_b(bell_a.x + bell_sz, bell_a.y + bell_sz);
			bool bell_hov = ImGui::IsMouseHoveringRect(bell_a, bell_b);
			static aida::ui::hover_state_t bell_h;
			float bhv = bell_h.tick(bell_hov, dt, aida::motion::spring::balanced);
			if (bhv > 0.01f) {
				dl->AddRectFilled(bell_a, bell_b,
					aida::ui::with_alpha(th_tb.hover_wash, bhv * a), 6.f);
			}
			ImU32 bcol = aida::ui::mix(th_tb.text_secondary, th_tb.text_primary, bhv);
			ImVec2 bcc((bell_a.x + bell_b.x) * 0.5f, (bell_a.y + bell_b.y) * 0.5f);
			dl->PathArcTo(ImVec2(bcc.x, bcc.y - 1.f), 5.f, 3.6651915f, 5.7595864f, 12);
			dl->PathLineTo(ImVec2(bcc.x + 5.5f, bcc.y + 4.f));
			dl->PathLineTo(ImVec2(bcc.x - 5.5f, bcc.y + 4.f));
			dl->PathStroke(aida::ui::with_alpha(bcol, a), ImDrawFlags_Closed, 1.5f);
			dl->AddCircleFilled(ImVec2(bcc.x, bcc.y + 6.5f), 1.5f, aida::ui::with_alpha(bcol, a), 8);
			ctl_off += bell_sz + 8.f;
		}

		{
			float av_sz = 22.f;
			ImVec2 av_a(wp.x + ww - ctl_off - av_sz, wp.y + (title_h - av_sz) * 0.5f);
			ImVec2 av_b(av_a.x + av_sz, av_a.y + av_sz);
			bool av_hov = ImGui::IsMouseHoveringRect(av_a, av_b);
			static aida::ui::hover_state_t av_h;
			float ahv = av_h.tick(av_hov, dt, aida::motion::spring::balanced);
			if (ahv > 0.01f) {
				dl->AddRectFilled(av_a, av_b,
					aida::ui::with_alpha(th_tb.hover_wash, ahv * a), av_sz * 0.5f);
			}
			ImVec2 ac((av_a.x + av_b.x) * 0.5f, (av_a.y + av_b.y) * 0.5f);
			std::string seed = license::saved_key.empty() ? std::string("aida") : license::saved_key;
			aida::ui::avatar::render(dl, ac, av_sz * 0.45f,
				seed, aida::ui::avatar::kind_t::gradient, true, a);
			ctl_off += av_sz + 8.f;
		}

		{
			static int theme_popup_open_frame = 0;
			ImVec2 th_pos(wp.x + ww - 200.f, wp.y + 8.f);
			(void)th_pos;
			ImVec2 fake_pos(wp.x + ww - ctl_off - 22.f, wp.y + (title_h - 22.f) * 0.5f);
			(void)fake_pos;
			bool dummy_hov = false;
			(void)dummy_hov;
			(void)theme_popup_open_frame;

			{
				float popup_x = std::min(th_pos.x - 100.f, wp.x + ww - 220.f - 8.f);
				popup_x = std::max(wp.x + 8.f, popup_x);
				ImGui::SetNextWindowPos(ImVec2(popup_x, wp.y + title_h + 2.f));
				ImGui::SetNextWindowBgAlpha(0.96f);
				ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 8.f);
				ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(8.f, 8.f));
				ImGui::PushStyleColor(ImGuiCol_PopupBg, ImVec4(0.07f, 0.07f, 0.10f, 1.f));
				ImGui::PushStyleColor(ImGuiCol_Border, ImVec4(1, 1, 1, 0.08f));

				if (ImGui::BeginPopup("##theme_popup",
					ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
					ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_NoSavedSettings))
				{
					ImDrawList* pdl = ImGui::GetWindowDrawList();
					float item_w = 200.f;
					float item_h = 22.f;
					bool popup_clicks_ok = (ImGui::GetFrameCount() > theme_popup_open_frame + 1);


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
							? IM_COL32((int)(tp.accent.x*255), (int)(tp.accent.y*255), (int)(tp.accent.z*255), 255)
							: IM_COL32(200, 200, 210, 220);
						pdl->AddText(ImVec2(cp.x + 24.f, cp.y + (item_h - ImGui::GetFontSize()) * 0.5f),
							name_col, tp.name);

						ImGui::Dummy(ImVec2(item_w, item_h));
						if (popup_clicks_ok && ti_hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
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
								? IM_COL32((int)(ct.accent[0]*255), (int)(ct.accent[1]*255), (int)(ct.accent[2]*255), 255)
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
							if (popup_clicks_ok && ehov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
								custom_themes::editing_idx = ci;
								custom_themes::editing_copy = ct;
								custom_themes::editor_open = true;
							}

							ImGui::Dummy(ImVec2(item_w, item_h));
							if (popup_clicks_ok && ci_hov && !ehov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
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
						if (popup_clicks_ok && hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
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
						if (popup_clicks_ok && hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
							char buf[MAX_PATH] = {};
							OPENFILENAMEA ofn = {};
							ofn.lStructSize = sizeof(ofn);
							ofn.hwndOwner = g_hwnd;
							ofn.lpstrFile = buf;
							ofn.nMaxFile = MAX_PATH;
							ofn.lpstrFilter = "AiDA Theme (*.json)\0*.json\0All Files\0*.*\0\0";
							ofn.nFilterIndex = 1;
							ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_NOCHANGEDIR;
							if (trusted_get_open_file_name(ofn)) {
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
					ImGui::EndPopup();
				}
				ImGui::PopStyleColor(2);
				ImGui::PopStyleVar(2);
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

					ImGui::TextColored(aida::ui::resolved().accent,
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


					ImGui::Text("Theme Icon (optional)");
					ImGui::SetNextItemWidth(iw2);
					if (aida::ui::components::button("Choose Image File...##te_icon",
						aida::ui::components::button_kind_t::primary,
						aida::ui::components::size_t_::md,
						ImVec2(iw2, 0.f))) {
						char icon_buf[MAX_PATH] = {};
						OPENFILENAMEA ofn2 = {};
						ofn2.lStructSize = sizeof(ofn2);
						ofn2.hwndOwner = g_hwnd;
						ofn2.lpstrFile = icon_buf;
						ofn2.nMaxFile = MAX_PATH;
						ofn2.lpstrFilter = "Images\0*.png;*.jpg;*.jpeg;*.bmp\0All Files\0*.*\0\0";
						ofn2.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_NOCHANGEDIR;
						if (trusted_get_open_file_name(ofn2)) {
							ed.icon_index = -1;
							ed.icon_file_path = icon_buf;
						}
					}
					if (!ed.icon_file_path.empty()) {
						ImGui::TextColored(ImVec4(0.5f, 0.7f, 0.5f, 1.f), "File: %s",
							ed.icon_file_path.substr(ed.icon_file_path.find_last_of("\\/") + 1).c_str());
						if (aida::ui::components::button("Clear Icon##te_clear",
							aida::ui::components::button_kind_t::ghost,
							aida::ui::components::size_t_::sm)) {
							ed.icon_file_path.clear();
							ed.icon_index = -1;
						}
					}

					ImGui::Dummy(ImVec2(0, 8));


					float btn_w2 = 70.f;
					if (aida::ui::components::button("Save",
						aida::ui::components::button_kind_t::primary,
						aida::ui::components::size_t_::md,
						ImVec2(btn_w2, 26.f))) {
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


					if (aida::ui::components::button("Export",
						aida::ui::components::button_kind_t::secondary,
						aida::ui::components::size_t_::md,
						ImVec2(btn_w2, 26.f))) {
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
						if (trusted_get_save_file_name(sfn)) {
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
						if (aida::ui::components::button("Delete",
							aida::ui::components::button_kind_t::destructive,
							aida::ui::components::size_t_::md,
							ImVec2(btn_w2, 26.f))) {
							int idx = custom_themes::editing_idx;
							custom_themes::list.erase(custom_themes::list.begin() + idx);
							if (custom_themes::active_custom == idx) custom_themes::active_custom = -1;
							else if (custom_themes::active_custom > idx) custom_themes::active_custom--;
							themes::changed = true;
							custom_themes::editor_open = false;
							name_init = false;
						}
						ImGui::SameLine();
					}

					if (aida::ui::components::button("Cancel",
						aida::ui::components::button_kind_t::secondary,
						aida::ui::components::size_t_::md,
						ImVec2(btn_w2, 26.f))) {
						custom_themes::editor_open = false;
						name_init = false;
					}
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
			bool lmb = (GetAsyncKeyState(VK_LBUTTON) & 0x8000) && (GetForegroundWindow() == g_hwnd);
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
		const auto& th_mb = aida::ui::resolved();
		float my0 = wp.y + title_h;
		float my1 = my0 + menu_h;

		aida::ui::blur::layer_request_t mb_req;
		mb_req.pos = ImVec2(wp.x, my0);
		mb_req.size = ImVec2(ww, menu_h);
		mb_req.radius = 0.f;
		mb_req.strength = 0.4f;
		mb_req.alpha = a;
		aida::ui::blur::schedule(mb_req);
		dl->AddRectFilled(ImVec2(wp.x, my0), ImVec2(wp.x + ww, my1),
			aida::ui::with_alpha(th_mb.panel_header, a));
		dl->AddLine(ImVec2(wp.x, my1), ImVec2(wp.x + ww, my1),
			aida::ui::with_alpha(th_mb.border_subtle, a));

		struct MenuItem {
			const char* label;
			int         id;
		};
		static const MenuItem menus[] = {
			{"File", 0}, {"Edit", 1}, {"View", 2}, {"Tools", 3}, {"AI", 4}, {"Help", 5}
		};

		ImFont* body = aida::ui::fonts::body();
		if (!body) body = ImGui::GetFont();
		float mx_cursor = wp.x + 14.f;
		ImGuiStorage* mb_storage = ImGui::GetStateStorage();
		for (int i = 0; i < 6; i++) {
			ImVec2 ts = body->CalcTextSizeA(13.f, FLT_MAX, 0.f, menus[i].label);
			float btn_w = ts.x + 18.f;
			ImVec2 bmin(mx_cursor, my0 + 2.f);
			ImVec2 bmax(mx_cursor + btn_w, my1 - 2.f);
			bool hov = ImGui::IsMouseHoveringRect(bmin, bmax);
			bool is_open = (menu_bar::open_menu == i);

			ImGuiID mb_hov_id = ImGui::GetID(menus[i].label);
			float h_v = mb_storage->GetFloat(mb_hov_id, 0.f);
			float h_target = (hov || is_open) ? 1.f : 0.f;
			h_v += (h_target - h_v) * std::min(12.f * dt, 1.f);
			mb_storage->SetFloat(mb_hov_id, h_v);

			if (h_v > 0.01f) {
				ImU32 mfill = is_open ? th_mb.selection_strong : th_mb.hover_wash;
				dl->AddRectFilled(bmin, bmax, aida::ui::with_alpha(mfill, h_v * a), 6.f);
			}

			ImU32 tcol = (hov || is_open) ? th_mb.text_primary : th_mb.text_secondary;
			dl->AddText(body, 13.f,
				ImVec2(mx_cursor + 9.f, my0 + (menu_h - 13.f) * 0.5f),
				aida::ui::with_alpha(tcol, a), menus[i].label);

			if (hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
				menu_bar::open_menu = is_open ? -1 : i;
				menu_bar::any_open = (menu_bar::open_menu >= 0);
			}
			if (hov && menu_bar::any_open && !is_open) {
				menu_bar::open_menu = i;
			}


			if (is_open) {
				ImGui::SetNextWindowPos(ImVec2(bmin.x, my1 + 4.f));
				ImGui::SetNextWindowBgAlpha(0.0f);
				ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 10.f);
				ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(6.f, 8.f));
				ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(0.f, 0.f));
				ImGui::PushStyleColor(ImGuiCol_PopupBg, ImVec4(0,0,0,0));
				ImGui::PushStyleColor(ImGuiCol_Border, ImVec4(0,0,0,0));

				char popup_id[32];
				snprintf(popup_id, sizeof(popup_id), "##menu_%d", i);
				ImGui::OpenPopup(popup_id);

				if (ImGui::BeginPopup(popup_id)) {
					float mw = 220.f;
					float ih = 26.f;

					ImVec2 pwp = ImGui::GetWindowPos();
					ImVec2 pws = ImGui::GetWindowSize();
					ImVec2 pa(pwp.x, pwp.y);
					ImVec2 pb(pwp.x + pws.x, pwp.y + pws.y);
					ImDrawList* pdl = ImGui::GetWindowDrawList();
					aida::ui::blur::layer_request_t pr;
					pr.pos = pa; pr.size = pws; pr.radius = 10.f; pr.strength = 0.85f; pr.alpha = 1.f;
					aida::ui::blur::schedule(pr);
					aida::ui::blur::render_drop_shadow(pdl, pa, pb, 10.f, 5, 0.55f, ImVec2(0.f, 8.f));
					{
						const auto& th_pp = aida::ui::resolved();
						pdl->AddRectFilled(pa, pb,
							aida::ui::with_alpha(th_pp.panel_bg, 0.92f), 10.f);
					}
					aida::ui::blur::render_glass_border(pdl, pa, pb, 10.f, 1.f, 1.f);

					auto menu_item = [&](const char* label, const char* shortcut, bool enabled = true) -> bool {
						const auto& th_p = aida::ui::resolved();
						ImVec2 cp = ImGui::GetCursorScreenPos();
						ImVec2 rmin = cp;
						ImVec2 rmax(cp.x + mw, cp.y + ih);
						bool mhov = enabled && ImGui::IsMouseHoveringRect(rmin, rmax);
						ImDrawList* idl = ImGui::GetWindowDrawList();
						if (mhov) idl->AddRectFilled(rmin, rmax,
							aida::ui::with_alpha(th_p.hover_wash, 1.f), 6.f);
						ImU32 tc = enabled ? th_p.text_primary : th_p.text_dim;
						ImFont* f = aida::ui::fonts::body();
						if (!f) f = ImGui::GetFont();
						idl->AddText(f, 13.f,
							ImVec2(cp.x + 14.f, cp.y + (ih - 13.f) * 0.5f), tc, label);
						if (shortcut && shortcut[0]) {
							ImVec2 sts = f->CalcTextSizeA(11.f, FLT_MAX, 0.f, shortcut);
							idl->AddText(f, 11.f,
								ImVec2(cp.x + mw - sts.x - 12.f, cp.y + (ih - 11.f) * 0.5f),
								aida::ui::with_alpha(th_p.text_dim, 1.f), shortcut);
						}
						ImGui::Dummy(ImVec2(mw, ih));
						bool clicked = mhov && ImGui::IsMouseClicked(ImGuiMouseButton_Left);
						if (clicked) { menu_bar::open_menu = -1; menu_bar::any_open = false; ImGui::CloseCurrentPopup(); }
						return clicked;
					};

					auto menu_sep = [&]() {
						const auto& th_p = aida::ui::resolved();
						ImVec2 cp = ImGui::GetCursorScreenPos();
						ImGui::GetWindowDrawList()->AddLine(
							ImVec2(cp.x + 10.f, cp.y + 4.f), ImVec2(cp.x + mw - 10.f, cp.y + 4.f),
							aida::ui::with_alpha(th_p.border_subtle, 1.f));
						ImGui::Dummy(ImVec2(mw, 9.f));
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
							if (trusted_get_open_file_name(ofn)) {
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
							IFileOpenDialog* pfd = nullptr;
							HRESULT hr = CoCreateInstance(CLSID_FileOpenDialog, nullptr, CLSCTX_INPROC_SERVER,
								IID_IFileOpenDialog, reinterpret_cast<void**>(&pfd));
							if (SUCCEEDED(hr) && pfd) {
								DWORD opts = 0;
								pfd->GetOptions(&opts);
								pfd->SetOptions(opts | FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM);
								pfd->SetTitle(L"Open Workspace Folder");
								hr = trusted_show_file_dialog(pfd, g_hwnd);
								if (SUCCEEDED(hr)) {
									IShellItem* psi = nullptr;
									hr = pfd->GetResult(&psi);
									if (SUCCEEDED(hr) && psi) {
										PWSTR wpath = nullptr;
										psi->GetDisplayName(SIGDN_FILESYSPATH, &wpath);
										if (wpath) {
											WideCharToMultiByte(CP_UTF8, 0, wpath, -1, folder, MAX_PATH, nullptr, nullptr);
											CoTaskMemFree(wpath);
											file_browser::refresh(folder);
											g_sa_settings.workspace.root_path = folder;
											g_sa_settings.save();
										}
										psi->Release();
									}
								}
								pfd->Release();
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
							if (trusted_get_save_file_name(sfn)) {
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
							PostQuitMessage(0);
							ExitProcess(0);
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
								if (g_disasm.file.loaded) disasm::decode_section_async(g_disasm.file);
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
			!ImGui::IsWindowHovered(ImGuiHoveredFlags_AnyWindow)) {
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


		float ab_offset = g_sa_settings.activity_bar_visible ? globals::ui::activity_bar_w : 0.f;
		float ls_x = wp.x + pad + ab_offset + left_w;
		ImVec2 ls_min(ls_x - sp_w * 0.5f, wp.y + content_top);
		ImVec2 ls_max(ls_x + sp_w * 0.5f + gap, wp.y + content_top + total_h);

		bool ls_hov = globals::ui::panel_left_visible && ImGui::IsMouseHoveringRect(ls_min, ls_max);
		if (ls_hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
			globals::ui::dragging_left_splitter = true;
		if (!ImGui::IsMouseDown(ImGuiMouseButton_Left))
			globals::ui::dragging_left_splitter = false;
		if (globals::ui::dragging_left_splitter) {
			float mx = ImGui::GetIO().MousePos.x - wp.x - pad - ab_offset;
			globals::ui::panel_left_w = std::clamp(mx, min_panel, max_left);
			g_sa_settings.workspace.left_width = globals::ui::panel_left_w;
		}
		if (ls_hov || globals::ui::dragging_left_splitter)
			ImGui::SetMouseCursor(ImGuiMouseCursor_ResizeEW);


		float rs_x = wp.x + ww - pad - right_w;
		{


			ImVec2 mpos = ImGui::GetIO().MousePos;
			float rs_y0 = wp.y + content_top;
			float rs_y1 = wp.y + content_top + right_total_h;
			bool rs_in_rect = mpos.x >= (rs_x - 8.f) && mpos.x <= (rs_x + 8.f)
			               && mpos.y >= rs_y0 && mpos.y <= rs_y1;
			bool rs_hov = globals::ui::panel_right_visible && rs_in_rect
			           && !globals::ui::dragging_left_splitter && !globals::ui::dragging_bottom_splitter;
			if (rs_hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
				globals::ui::dragging_right_splitter = true;
			if (!ImGui::IsMouseDown(ImGuiMouseButton_Left))
				globals::ui::dragging_right_splitter = false;
			if (globals::ui::dragging_right_splitter) {
				float mx = wp.x + ww - mpos.x - pad;
				globals::ui::panel_right_w = std::clamp(mx, min_panel, max_right);
				g_sa_settings.workspace.right_width = globals::ui::panel_right_w;
			}
			if (rs_hov || globals::ui::dragging_right_splitter)
				ImGui::SetMouseCursor(ImGuiMouseCursor_ResizeEW);
		}


		if (bottom_h > 1.f) {
			float right_gap_bs = (right_w > 1.f) ? (right_w + gap) : 0.f;
			float bs_y = wp.y + content_top + total_h;
			ImVec2 bs_min(wp.x + pad, bs_y - sp_w * 0.5f);
			ImVec2 bs_max(wp.x + ww - pad - right_gap_bs, bs_y + sp_w * 0.5f + gap);
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

		left_w   = globals::ui::dragging_left_splitter ? (globals::ui::panel_left_visible ? globals::ui::panel_left_w : 0.f) : s_anim_left_w;
		right_w  = globals::ui::dragging_right_splitter ? (globals::ui::panel_right_visible ? globals::ui::panel_right_w : 0.f) : s_anim_right_w;
		bottom_h = globals::ui::dragging_bottom_splitter ? (globals::ui::panel_bottom_visible ? globals::ui::panel_bottom_h : 0.f) : s_anim_bottom_h;
		if (globals::ui::dragging_left_splitter)   s_anim_left_w  = left_w;
		if (globals::ui::dragging_right_splitter)  s_anim_right_w = right_w;
		if (globals::ui::dragging_bottom_splitter) s_anim_bottom_h = bottom_h;
		center_w = ww - left_w - right_w - pad * 2.f - gap * 2.f - ab_for_layout;
		if (center_w < 200.f) {
			float excess = 200.f - center_w;
			float tp = left_w + right_w;
			if (tp > 0.f) { left_w -= excess * (left_w / tp); right_w -= excess * (right_w / tp); }
			center_w = 200.f;
		}
		total_h = wh - pad * 2.f - chrome_h - (bottom_h > 1.f ? (bottom_h + gap) : 0.f);
		right_total_h = wh - pad * 2.f - chrome_h;
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
		const auto& th_ab = aida::ui::resolved();
		const float ab_w = globals::ui::activity_bar_w;
		ImVec2 ab_pos(wp_m.x + pad, wp_m.y + content_top);
		ImVec2 ab_end(ab_pos.x + ab_w, ab_pos.y + total_h);

		aida::ui::blur::layer_request_t ab_req;
		ab_req.pos = ab_pos;
		ab_req.size = ImVec2(ab_w, total_h);
		ab_req.radius = 10.f;
		ab_req.strength = 0.55f;
		ab_req.alpha = a;
		aida::ui::blur::schedule(ab_req);
		aida::ui::blur::render_glass_fill(wdl, ab_pos, ab_end, 10.f, a);
		wdl->AddLine(ImVec2(ab_end.x, ab_pos.y), ImVec2(ab_end.x, ab_end.y),
			aida::ui::with_alpha(th_ab.border_subtle, a));

		struct ab_entry { const char* icon; activity_item_t item; const char* tip; };
		static const ab_entry ab_items[] = {
			{ ICON_FILES_EMPTY, activity_item_t::explorer, "Explorer" },
			{ ICON_SEARCH,      activity_item_t::search,   "Search" },
		};
		static const int ab_count = sizeof(ab_items) / sizeof(ab_items[0]);

		float iy = ab_pos.y + 12.f;
		float ab_active_y0 = -1.f, ab_active_y1 = -1.f;
		ImGuiStorage* ab_storage = ImGui::GetStateStorage();
		for (int ai = 0; ai < ab_count; ai++) {
			bool active = (globals::ui::active_activity == ab_items[ai].item);
			float icon_sz = 36.f;
			ImVec2 imin(ab_pos.x + (ab_w - icon_sz) * 0.5f, iy);
			ImVec2 imax(imin.x + icon_sz, imin.y + icon_sz);
			bool ihov = ImGui::IsMouseHoveringRect(imin, imax);

			ImGuiID ab_h_id = ImGui::GetID(ab_items[ai].tip);
			float ah_v = ab_storage->GetFloat(ab_h_id, 0.f);
			float ah_target = ihov ? 1.f : 0.f;
			ah_v += (ah_target - ah_v) * std::min(14.f * dt, 1.f);
			ab_storage->SetFloat(ab_h_id, ah_v);

			float lift = ah_v * 2.f;
			ImVec2 ima(imin.x, imin.y - lift);
			ImVec2 imb(imax.x, imax.y - lift);

			if (active) {
				wdl->AddRectFilled(ima, imb,
					aida::ui::with_alpha(th_ab.selection, a), 8.f);
				aida::ui::blur::render_inner_glow(wdl, ima, imb, 8.f, th_ab.accent_glow, 3);
				ab_active_y0 = ima.y;
				ab_active_y1 = imb.y;
			} else if (ah_v > 0.01f) {
				wdl->AddRectFilled(ima, imb,
					aida::ui::with_alpha(th_ab.hover_wash, ah_v * a), 8.f);
			}

			ImVec2 lts = ImGui::CalcTextSize(ab_items[ai].icon);
			ImU32 ic = active ? aida::ui::with_alpha(th_ab.text_primary, a)
			                  : aida::ui::with_alpha(th_ab.text_dim, a);
			wdl->AddText(ImVec2(ima.x + (icon_sz - lts.x) * 0.5f, ima.y + (icon_sz - lts.y) * 0.5f),
				ic, ab_items[ai].icon);

			if (ihov) {
				ImGui::SetCursorScreenPos(imin);
				ImGui::InvisibleButton(ab_items[ai].tip, ImVec2(icon_sz, icon_sz));
				aida::ui::tooltip_blur(ab_items[ai].tip, 0.6f);
			}

			if (ihov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
				if (globals::ui::active_activity == ab_items[ai].item && globals::ui::panel_left_visible) {
					globals::ui::panel_left_visible = false;
				} else {
					globals::ui::active_activity = ab_items[ai].item;
					globals::ui::panel_left_visible = true;
				}
			}
			iy += icon_sz + 8.f;
		}

		if (ab_active_y0 >= 0.f && globals::ui::panel_left_visible) {
			ImGuiID ab_uly = ImGui::GetID("##ab_ul_y");
			ImGuiID ab_uly_v = ImGui::GetID("##ab_ul_yv");
			float ab_cy = ab_storage->GetFloat(ab_uly, ab_active_y0);
			float ab_vy = ab_storage->GetFloat(ab_uly_v, 0.f);
			ab_cy = aida::motion::spring_step(ab_cy, ab_active_y0, ab_vy,
				aida::motion::spring::balanced, dt);
			ab_storage->SetFloat(ab_uly, ab_cy);
			ab_storage->SetFloat(ab_uly_v, ab_vy);
			float ab_line_h = ab_active_y1 - ab_active_y0;
			wdl->AddRectFilled(
				ImVec2(ab_pos.x + 4.f, ab_cy + ab_line_h * 0.18f),
				ImVec2(ab_pos.x + 7.f, ab_cy + ab_line_h * 0.82f),
				aida::ui::with_alpha(th_ab.accent_u32, a), 1.5f);
		}


		{
			float footer_h = 52.f;
			ImVec2 fmin(ab_pos.x, ab_end.y - footer_h);
			ImVec2 fmax(ab_pos.x + ab_w, ab_end.y);
			wdl->AddLine(ImVec2(fmin.x + 6.f, fmin.y),
				ImVec2(fmax.x - 6.f, fmin.y),
				aida::ui::with_alpha(th_ab.border_subtle, a * 0.7f), 1.f);

			float gear_sz = 32.f;
			ImVec2 gmin(ab_pos.x + (ab_w - gear_sz) * 0.5f, fmin.y + (footer_h - gear_sz) * 0.5f);
			ImVec2 gmax(gmin.x + gear_sz, gmin.y + gear_sz);
			bool ghov = ImGui::IsMouseHoveringRect(gmin, gmax);
			static aida::ui::hover_state_t gear_h;
			float ghv = gear_h.tick(ghov, dt, aida::motion::spring::balanced);
			if (ghv > 0.01f) {
				wdl->AddRectFilled(gmin, gmax,
					aida::ui::with_alpha(th_ab.hover_wash, ghv * a), 8.f);
			}
			ImVec2 gts = ImGui::CalcTextSize(ICON_COG);
			ImU32 gc = ghov ? aida::ui::with_alpha(th_ab.text_primary, a)
			               : aida::ui::with_alpha(th_ab.text_dim, a);
			wdl->AddText(ImVec2(gmin.x + (gear_sz - gts.x) * 0.5f, gmin.y + (gear_sz - gts.y) * 0.5f),
				gc, ICON_COG);
			if (ghov) {
				ImGui::SetCursorScreenPos(gmin);
				ImGui::InvisibleButton("##gear_btn", ImVec2(gear_sz, gear_sz));
				aida::ui::tooltip_blur("Settings", 0.6f);
			}
			if (ghov && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
				g_settings_open = true;
		}

		fb_x = pad + ab_w;
	}

	if (left_w > 1.f && globals::ui::panel_left_visible) {
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
			ImGui::PushStyleColor(ImGuiCol_FrameBg, IM_COL32(th_ph_r, th_ph_g, th_ph_b, (int)(200 * a)));
			ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(200, 200, 215, (int)(230 * a)));
			ImGui::PushItemWidth(fw - 12.f);

			bool changed = ImGui::InputText("##ws_query", workspace_search::g_search.query_buf, sizeof(workspace_search::g_search.query_buf),
				ImGuiInputTextFlags_EnterReturnsTrue);
			if (changed || (ImGui::IsItemFocused() && ImGui::IsKeyPressed(ImGuiKey_Enter, false))) {
				workspace_search::start_search(file_browser::current_dir);
			}

			ImGui::PopItemWidth();
			ImGui::PopStyleColor(2);
			ImGui::PopStyleVar();

			sy += 28.f;

			{
				auto toggle_btn = [&](const char* label, const char* tooltip, bool& state, const char* id) {
					ImVec2 cp = ImGui::GetCursorScreenPos();
					ImVec2 lts = ImGui::CalcTextSize(label);
					float btn_w = lts.x + 10.f;
					float btn_h = 20.f;
					ImVec2 bmin = cp;
					ImVec2 bmax(cp.x + btn_w, cp.y + btn_h);
					bool hov = ImGui::IsMouseHoveringRect(bmin, bmax, false);

					ImU32 bg_col;
					if (state) {
						bg_col = IM_COL32((int)(ax3*180+40), (int)(ay3*180+40), (int)(az3*180+40), (int)(80*a));
					} else if (hov) {
						bg_col = IM_COL32(255, 255, 255, (int)(12*a));
					} else {
						bg_col = IM_COL32(0, 0, 0, 0);
					}

					if (state || hov)
						fdl->AddRectFilled(bmin, bmax, bg_col, 3.f);
					if (state)
						fdl->AddRect(bmin, bmax, IM_COL32((int)(ax3*200+55), (int)(ay3*200+55), (int)(az3*200+55), (int)(140*a)), 3.f);

					ImU32 txt_col = state
						? IM_COL32((int)(ax3*200+55), (int)(ay3*200+55), (int)(az3*200+55), (int)(240*a))
						: IM_COL32(160, 160, 180, (int)((hov ? 220.f : 160.f)*a));
					fdl->AddText(ImVec2(bmin.x + 5.f, bmin.y + (btn_h - lts.y) * 0.5f), txt_col, label);

					ImGui::SetCursorScreenPos(cp);
					if (ImGui::InvisibleButton(id, ImVec2(btn_w, btn_h)))
						state = !state;
					if (ImGui::IsItemHovered())
						ImGui::SetTooltip("%s", tooltip);
					ImGui::SameLine(0.f, 4.f);
				};

				ImGui::SetCursorPos(ImVec2(6.f, sy));
				toggle_btn("Aa", "Match Case", workspace_search::g_search.case_sensitive, "##ws_case");
				toggle_btn("W",  "Match Whole Word", workspace_search::g_search.whole_word, "##ws_word");
				toggle_btn(".*", "Use Regular Expression", workspace_search::g_search.use_regex, "##ws_regex");
			}

			sy += 24.f;

			fdl->AddText(ImVec2(fwp.x + 8.f, fwp.y + sy + 2.f),
				IM_COL32(100, 100, 120, (int)(140 * a)), "files to include");
			sy += 16.f;
			ImGui::SetCursorPos(ImVec2(6.f, sy));
			ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(6.f, 4.f));
			ImGui::PushStyleColor(ImGuiCol_FrameBg, IM_COL32(th_ph_r, th_ph_g, th_ph_b, (int)(200 * a)));
			ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(200, 200, 215, (int)(230 * a)));
			ImGui::PushItemWidth(fw - 12.f);
			ImGui::InputText("##ws_include", workspace_search::g_search.include_buf, sizeof(workspace_search::g_search.include_buf));
			sy += 28.f;

			fdl->AddText(ImVec2(fwp.x + 8.f, fwp.y + sy + 2.f),
				IM_COL32(100, 100, 120, (int)(140 * a)), "files to exclude");
			sy += 16.f;
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

				struct file_group {
					std::string filepath;
					std::string filename;
					int first_idx;
					int count;
				};
				std::vector<file_group> groups;
				for (int ri = 0; ri < (int)results.size() && ri < 500; ri++) {
					auto& r = results[ri];
					if (groups.empty() || groups.back().filepath != r.filepath) {
						file_group g;
						g.filepath = r.filepath;
						g.filename = std::filesystem::path(r.filepath).filename().string();
						g.first_idx = ri;
						g.count = 1;
						groups.push_back(std::move(g));
					} else {
						groups.back().count++;
					}
				}

				static std::unordered_set<std::string> collapsed_files;

				for (auto& grp : groups) {
					ImVec2 gcp = ImGui::GetCursorScreenPos();
					float gh = 22.f;
					ImVec2 gmin(gcp.x, gcp.y);
					ImVec2 gmax(gcp.x + fw, gcp.y + gh);
					bool ghov = ImGui::IsMouseHoveringRect(gmin, gmax, false);

					if (ghov) fdl->AddRectFilled(gmin, gmax, IM_COL32(255, 255, 255, (int)(8 * a)));
					fdl->AddRectFilled(gmin, gmax, IM_COL32(255, 255, 255, (int)(4 * a)));

					bool is_collapsed = collapsed_files.count(grp.filepath) > 0;
					const char* arrow = is_collapsed ? ">" : "v";
					fdl->AddText(ImVec2(gmin.x + 4.f, gmin.y + (gh - ImGui::GetFontSize()) * 0.5f),
						IM_COL32(140, 140, 160, (int)(180 * a)), arrow);

					fdl->AddText(ImVec2(gmin.x + 16.f, gmin.y + (gh - ImGui::GetFontSize()) * 0.5f),
						IM_COL32(200, 200, 220, (int)(220 * a)), grp.filename.c_str());

					char cnt_buf[16];
					snprintf(cnt_buf, sizeof(cnt_buf), "%d", grp.count);
					ImVec2 cnt_sz = ImGui::CalcTextSize(cnt_buf);
					float badge_x = gmin.x + 18.f + ImGui::CalcTextSize(grp.filename.c_str()).x + 6.f;
					fdl->AddRectFilled(
						ImVec2(badge_x, gmin.y + 3.f),
						ImVec2(badge_x + cnt_sz.x + 8.f, gmin.y + gh - 3.f),
						IM_COL32((int)(ax3*100+30), (int)(ay3*100+30), (int)(az3*100+30), (int)(120*a)), 6.f);
					fdl->AddText(ImVec2(badge_x + 4.f, gmin.y + (gh - cnt_sz.y) * 0.5f),
						IM_COL32(200, 200, 220, (int)(200 * a)), cnt_buf);

					ImGui::Dummy(ImVec2(fw, gh));
					if (ghov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
						if (is_collapsed) collapsed_files.erase(grp.filepath);
						else collapsed_files.insert(grp.filepath);
					}

					if (!is_collapsed) {
						for (int ri = grp.first_idx; ri < grp.first_idx + grp.count; ri++) {
							auto& r = results[ri];
							float item_h2 = 22.f;
							ImVec2 cp2 = ImGui::GetCursorScreenPos();
							ImVec2 rmin2(cp2.x, cp2.y);
							ImVec2 rmax2(cp2.x + fw, cp2.y + item_h2);
							bool rhov = ImGui::IsMouseHoveringRect(rmin2, rmax2, false);
							if (rhov) fdl->AddRectFilled(rmin2, rmax2, IM_COL32(255, 255, 255, (int)(10 * a)));

							char ln_buf[16];
							snprintf(ln_buf, sizeof(ln_buf), "%d", r.line_number);
							fdl->AddText(ImVec2(rmin2.x + 22.f, rmin2.y + (item_h2 - ImGui::GetFontSize()) * 0.5f),
								IM_COL32(100, 100, 120, (int)(140 * a)), ln_buf);

							float txt_x = rmin2.x + 22.f + ImGui::CalcTextSize("9999").x + 6.f;
							std::string preview = r.line_text.substr(0, (std::min)((size_t)80, r.line_text.size()));
							fdl->AddText(ImVec2(txt_x, rmin2.y + (item_h2 - ImGui::GetFontSize()) * 0.5f),
								IM_COL32(170, 170, 190, (int)(190 * a)),
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
				}
			}
			ImGui::EndChild();
			ImGui::PopStyleVar();
		} else {


		static bool   s_sessions_section_expanded = true;
		static float  s_sessions_frac = 0.40f;
		static bool   s_sessions_dragging = false;

		const char* sessions_lbl = "SESSIONS";
		float sess_hdr_y = 6.f;
		const char* sess_arrow = s_sessions_section_expanded ? u8"▾" : u8"▸";
		ImU32 sess_label_col = IM_COL32(130, 128, 155, (int)(200 * a));
		fdl->AddText(ImVec2(fwp.x + 10.f, fwp.y + sess_hdr_y), sess_label_col, sess_arrow);
		fdl->AddText(ImVec2(fwp.x + 24.f, fwp.y + sess_hdr_y), sess_label_col, sessions_lbl);
		{
			ImGui::SetCursorPos(ImVec2(0.f, sess_hdr_y - 2.f));
			ImGui::InvisibleButton("##sess_hdr_btn", ImVec2(fw, 18.f));
			if (ImGui::IsItemClicked(ImGuiMouseButton_Left)) {
				s_sessions_section_expanded = !s_sessions_section_expanded;
			}
		}

		const float sh_hdr_total = 24.f;
		float avail_below_hdr = fh - sh_hdr_total;
		if (avail_below_hdr < 60.f) avail_below_hdr = 60.f;

		float sess_h = 0.f;
		float splitter_h = 0.f;
		if (s_sessions_section_expanded) {
			s_sessions_frac = std::clamp(s_sessions_frac, 0.10f, 0.85f);
			sess_h = avail_below_hdr * s_sessions_frac - 6.f;
			if (sess_h < 60.f) sess_h = 60.f;
			splitter_h = 6.f;
		}

		float sess_y = sh_hdr_total;
		if (s_sessions_section_expanded) {
			ImGui::SetCursorPos(ImVec2(0.f, sess_y));
			ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.f, 0.f));
			ImGui::BeginChild("##sessions_panel", ImVec2(fw, sess_h), false, ImGuiWindowFlags_NoBackground);
			aida::session_history::render(fw, sess_h);
			ImGui::EndChild();
			ImGui::PopStyleVar();

			float spl_y = sess_y + sess_h;
			ImVec2 spl_min(fwp.x, fwp.y + spl_y);
			ImVec2 spl_max(fwp.x + fw, fwp.y + spl_y + splitter_h);
			bool spl_hov = ImGui::IsMouseHoveringRect(spl_min, spl_max, false);
			ImU32 spl_col = (spl_hov || s_sessions_dragging)
				? IM_COL32((int)(ax3*200+50), (int)(ay3*200+50), (int)(az3*200+50), (int)(180 * a))
				: IM_COL32(255, 255, 255, (int)(20 * a));
			fdl->AddRectFilled(ImVec2(spl_min.x + 4.f, spl_min.y + 2.f),
				ImVec2(spl_max.x - 4.f, spl_max.y - 2.f), spl_col, 1.5f);

			ImGui::SetCursorPos(ImVec2(0.f, spl_y));
			ImGui::InvisibleButton("##sess_split", ImVec2(fw, splitter_h));
			if (ImGui::IsItemActive()) {
				s_sessions_dragging = true;
				float dy = ImGui::GetIO().MouseDelta.y;
				if (avail_below_hdr > 1.f) s_sessions_frac += dy / avail_below_hdr;
			} else {
				s_sessions_dragging = false;
			}
			if (ImGui::IsItemHovered() || s_sessions_dragging) {
				ImGui::SetMouseCursor(ImGuiMouseCursor_ResizeNS);
			}
		}

		float fb_label_y = sh_hdr_total + sess_h + splitter_h + 6.f;
		fdl->AddLine(ImVec2(fwp.x + 8.f, fwp.y + fb_label_y - 4.f),
			ImVec2(fwp.x + fw - 8.f, fwp.y + fb_label_y - 4.f),
			IM_COL32(255, 255, 255, (int)(18 * a)), 1.f);
		const char* explorer_lbl = "EXPLORER";
		fdl->AddText(ImVec2(fwp.x + 10.f, fwp.y + fb_label_y), IM_COL32(130, 128, 155, (int)(200 * a)), u8"▾");
		fdl->AddText(ImVec2(fwp.x + 24.f, fwp.y + fb_label_y),
			IM_COL32(130, 128, 155, (int)(200 * a)), explorer_lbl);

		float tree_y = fb_label_y + 20.f;
		float fb_scroll_h = fh - tree_y;
		if (fb_scroll_h < 24.f) fb_scroll_h = 24.f;
		ImGui::SetCursorPos(ImVec2(0.f, tree_y));
		ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.f, 0.f));
		ImGui::BeginChild("##fb_scroll", ImVec2(fw, fb_scroll_h), false, ImGuiWindowFlags_NoBackground);
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


				const char* icon = ent.is_dir ? (ent.expanded ? u8"▾ " : u8"▸ ") : u8"   ";
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


		{
			ID3D11ShaderResourceView* icon_srv = get_active_theme_icon();
			if (icon_srv) {
				int icon_idx = g_sa_settings.theme_icon_index;
				if (custom_themes::active_custom >= 0 &&
				    custom_themes::active_custom < (int)custom_themes::list.size())
					icon_idx = custom_themes::list[custom_themes::active_custom].icon_index;
				float src_w = 0.f, src_h = 0.f;
				if (icon_idx < 0 && g_custom_theme_icon_w > 0 && g_custom_theme_icon_h > 0) {
					src_w = static_cast<float>(g_custom_theme_icon_w);
					src_h = static_cast<float>(g_custom_theme_icon_h);
				} else {
					if (icon_idx < 0) icon_idx = 3;
					src_w = static_cast<float>(g_theme_icon_w[icon_idx]);
					src_h = static_cast<float>(g_theme_icon_h[icon_idx]);
				}
				if (src_w > 0 && src_h > 0) {
					float max_icon_w = fw * 0.8f;
					float max_icon_h = fh * 0.35f;
					float scale = std::min(max_icon_w / src_w, max_icon_h / src_h);
					float dw = src_w * scale;
					float dh = src_h * scale;
					float ix = fwp.x + fw * 0.5f - dw * 0.5f;
					float iy = fwp.y + fh - dh - 8.f;
					fdl->AddImage(reinterpret_cast<ImTextureID>(icon_srv),
						ImVec2(ix, iy), ImVec2(ix + dw, iy + dh),
						ImVec2(0, 0), ImVec2(1, 1),
						IM_COL32(255, 255, 255, static_cast<int>(100 * a)));
				}
			}
		}
	}
	end_child();
	}

	float ab_extra = g_sa_settings.activity_bar_visible ? globals::ui::activity_bar_w : 0.f;
	float left_gap = (left_w > 1.f) ? (left_w + gap + ab_extra) : ab_extra;
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
			float active_tx0 = -1.f, active_tx1 = -1.f, active_ty1 = 0.f;

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
					active_tx0 = tx0 + 2.f;
					active_tx1 = tx1 - 2.f;
					active_ty1 = ty1;
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


			if (close_idx >= 0) {
				if (close_idx < (int)file_tabs::tabs.size() &&
				    file_tabs::tabs[close_idx].dirty) {
					file_tabs::pending_close_idx = close_idx;
					file_tabs::show_close_confirm = true;
				} else {
					file_tabs::close_tab(close_idx);
				}
			}
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

			if (active_tx0 >= 0.f) {
				ImGuiID ct_ulx = ImGui::GetID("##ct_ul_x");
				ImGuiID ct_ulw = ImGui::GetID("##ct_ul_w");
				float ct_x = ImGui::GetStateStorage()->GetFloat(ct_ulx, active_tx0);
				float ct_w = ImGui::GetStateStorage()->GetFloat(ct_ulw, active_tx1 - active_tx0);
				float tgt_w = active_tx1 - active_tx0;
				ct_x += (active_tx0 - ct_x) * std::min(14.f * dt, 1.f);
				ct_w += (tgt_w - ct_w) * std::min(14.f * dt, 1.f);
				ImGui::GetStateStorage()->SetFloat(ct_ulx, ct_x);
				ImGui::GetStateStorage()->SetFloat(ct_ulw, ct_w);
				wdl->AddLine(ImVec2(ct_x - 2.f, active_ty1), ImVec2(ct_x + ct_w + 2.f, active_ty1),
					IM_COL32((int)(ax3*255),(int)(ay3*255),(int)(az3*255),(int)(50*a)), 4.f);
				wdl->AddLine(ImVec2(ct_x, active_ty1), ImVec2(ct_x + ct_w, active_ty1),
					IM_COL32((int)(ax3*255),(int)(ay3*255),(int)(az3*255),(int)(200*a)), 2.f);
			}

		} else if (!(g_disasm.file.loaded && !g_disasm.file.filename.empty()) && !hex_view::g_state.active) {

			const char* fn_disp = "No file open";
			ImVec2 fn_ts = ImGui::CalcTextSize(fn_disp);
			float  fn_y  = r1_cy - fn_ts.y * 0.5f;
			wdl->AddText(ImVec2(hx0 + hdr_pad, fn_y),
				IM_COL32(150,150,170,(int)(170*a)), fn_disp);
		}


		if (g_disasm.file.loaded && !g_disasm.file.filename.empty()) {
			bool disasm_is_active = (!code_editor::active || code_editor::buffer.empty()) &&
			                        g_disasm.file.loaded && (g_disasm.live_mode || !g_disasm.file.instrs.empty());
			std::string disasm_label = g_disasm.file.filename;
			ImVec2 dts = ImGui::CalcTextSize(disasm_label.c_str());
			const float close_sz = 10.f;
			float dtw = 10.f * 2.f + dts.x + close_sz + 12.f;
			float tab_h2 = row_h - 2.f;

			float dtx0, dtx1;
			if (!file_tabs::tabs.empty()) {
				float last_tab_end = hx0 + hdr_pad;
				for (int ti = 0; ti < (int)file_tabs::tabs.size(); ti++) {
					auto& tab = file_tabs::tabs[ti];
					std::string label = tab.filename;
					if (tab.dirty) label += " *";
					ImVec2 lts = ImGui::CalcTextSize(label.c_str());
					float tw = 10.f * 2.f + lts.x + 10.f + 6.f;
					last_tab_end += tw + 2.f;
				}
				dtx0 = last_tab_end + 4.f;
			} else {
				dtx0 = hx0 + hdr_pad;
			}
			if (dtx0 + dtw < rbtn_x0 - 8.f) {
				float dty0 = r1_cy - tab_h2 * 0.5f;
				dtx1 = dtx0 + dtw;
				float dty1 = dty0 + tab_h2;

				bool dtab_hov = ImGui::IsMouseHoveringRect(ImVec2(dtx0, dty0), ImVec2(dtx1, dty1), false);

				if (disasm_is_active) {
					wdl->AddRectFilled(ImVec2(dtx0, dty0), ImVec2(dtx1, dty1),
						IM_COL32(255,255,255,(int)(16*a)), 4.f, ImDrawFlags_RoundCornersTop);
					wdl->AddLine(ImVec2(dtx0 + 2.f, dty1), ImVec2(dtx1 - 2.f, dty1),
						IM_COL32((int)(ax3*255),(int)(ay3*255),(int)(az3*255),(int)(200*a)), 2.f);
				} else if (dtab_hov) {
					wdl->AddRectFilled(ImVec2(dtx0, dty0), ImVec2(dtx1, dty1),
						IM_COL32(255,255,255,(int)(8*a)), 4.f, ImDrawFlags_RoundCornersTop);
				}

				ImU32 dtab_col = disasm_is_active ? ac_full
				               : IM_COL32(170, 175, 190, (int)((dtab_hov ? 220.f : 160.f)*a));
				wdl->AddText(ImVec2(dtx0 + 10.f, dty0 + (tab_h2 - dts.y) * 0.5f),
					dtab_col, disasm_label.c_str());


				float cx0 = dtx1 - close_sz - 6.f;
				float cy0 = dty0 + (tab_h2 - close_sz) * 0.5f;
				float cx1 = cx0 + close_sz;
				float cy1 = cy0 + close_sz;
				bool close_hov = ImGui::IsMouseHoveringRect(ImVec2(cx0 - 2, cy0 - 2), ImVec2(cx1 + 2, cy1 + 2), false);
				if (close_hov) {
					wdl->AddRectFilled(ImVec2(cx0 - 1, cy0 - 1), ImVec2(cx1 + 1, cy1 + 1),
						IM_COL32(255,80,80,(int)(40*a)), 3.f);
				}
				ImU32 close_col = close_hov
					? IM_COL32(255,100,100,(int)(220*a))
					: IM_COL32(150,150,160,(int)((disasm_is_active ? 140.f : 80.f)*a));
				float cmx = (cx0 + cx1) * 0.5f, cmy = (cy0 + cy1) * 0.5f;
				float cr = 3.f;
				wdl->AddLine(ImVec2(cmx - cr, cmy - cr), ImVec2(cmx + cr, cmy + cr), close_col, 1.2f);
				wdl->AddLine(ImVec2(cmx + cr, cmy - cr), ImVec2(cmx - cr, cmy + cr), close_col, 1.2f);

				if (close_hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
					if (g_disasm.live_mode)
						disasm::stop_live(g_disasm);
					g_disasm.file = DisasmFile{};
					if (globals::ui::active_center_view == center_view_t::disassembly)
						globals::ui::active_center_view = center_view_t::code_editor;
				} else if (dtab_hov && !close_hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
					globals::ui::active_center_view = center_view_t::disassembly;
				}
			}
		}

		if (hex_view::g_state.active) {
			bool hex_is_active = (globals::ui::active_center_view == center_view_t::hex_view);
			std::string hex_label_str = hex_view::g_state.source_name.empty()
				? std::string("Hex View")
				: hex_view::g_state.source_name + " (Hex)";
			const char* hex_label = hex_label_str.c_str();
			ImVec2 hts = ImGui::CalcTextSize(hex_label);
			const float hex_close_sz = 10.f;
			float htw = 10.f * 2.f + hts.x + hex_close_sz + 12.f;
			float tab_h3 = row_h - 2.f;

			float htx0;
			if (g_disasm.file.loaded && !g_disasm.file.instrs.empty()) {
				std::string dl2 = g_disasm.file.filename;
				ImVec2 dl2s = ImGui::CalcTextSize(dl2.c_str());
				float dlw = 10.f * 2.f + dl2s.x + 10.f + 12.f;
				float dtx0_base;
				if (!file_tabs::tabs.empty()) {
					float last = hx0 + hdr_pad;
					for (int ti = 0; ti < (int)file_tabs::tabs.size(); ti++) {
						auto& tab = file_tabs::tabs[ti];
						std::string lb = tab.filename;
						if (tab.dirty) lb += " *";
						ImVec2 ls = ImGui::CalcTextSize(lb.c_str());
						last += 10.f * 2.f + ls.x + 10.f + 6.f + 2.f;
					}
					dtx0_base = last + 4.f;
				} else {
					dtx0_base = hx0 + hdr_pad;
				}
				htx0 = dtx0_base + dlw + 6.f;
			} else if (!file_tabs::tabs.empty()) {
				float last = hx0 + hdr_pad;
				for (int ti = 0; ti < (int)file_tabs::tabs.size(); ti++) {
					auto& tab = file_tabs::tabs[ti];
					std::string lb = tab.filename;
					if (tab.dirty) lb += " *";
					ImVec2 ls = ImGui::CalcTextSize(lb.c_str());
					last += 10.f * 2.f + ls.x + 10.f + 6.f + 2.f;
				}
				htx0 = last + 4.f;
			} else {
				htx0 = hx0 + hdr_pad;
			}

			float htx1 = htx0 + htw;
			if (htx1 < rbtn_x0 - 8.f) {
				float hty0 = r1_cy - tab_h3 * 0.5f;
				float hty1 = hty0 + tab_h3;
				bool htab_hov = ImGui::IsMouseHoveringRect(ImVec2(htx0, hty0), ImVec2(htx1, hty1), false);

				if (hex_is_active) {
					wdl->AddRectFilled(ImVec2(htx0, hty0), ImVec2(htx1, hty1),
						IM_COL32(255,255,255,(int)(16*a)), 4.f, ImDrawFlags_RoundCornersTop);
					wdl->AddLine(ImVec2(htx0 + 2.f, hty1), ImVec2(htx1 - 2.f, hty1),
						IM_COL32((int)(ax3*255),(int)(ay3*255),(int)(az3*255),(int)(200*a)), 2.f);
				} else if (htab_hov) {
					wdl->AddRectFilled(ImVec2(htx0, hty0), ImVec2(htx1, hty1),
						IM_COL32(255,255,255,(int)(8*a)), 4.f, ImDrawFlags_RoundCornersTop);
				}

				ImU32 htab_col = hex_is_active ? ac_full
				               : IM_COL32(170, 175, 190, (int)((htab_hov ? 220.f : 160.f)*a));
				wdl->AddText(ImVec2(htx0 + 10.f, hty0 + (tab_h3 - hts.y) * 0.5f),
					htab_col, hex_label);


				float hcx0 = htx1 - hex_close_sz - 6.f;
				float hcy0 = hty0 + (tab_h3 - hex_close_sz) * 0.5f;
				float hcx1 = hcx0 + hex_close_sz;
				float hcy1 = hcy0 + hex_close_sz;
				bool hclose_hov = ImGui::IsMouseHoveringRect(ImVec2(hcx0 - 2, hcy0 - 2), ImVec2(hcx1 + 2, hcy1 + 2), false);
				if (hclose_hov) {
					wdl->AddRectFilled(ImVec2(hcx0 - 1, hcy0 - 1), ImVec2(hcx1 + 1, hcy1 + 1),
						IM_COL32(255,80,80,(int)(40*a)), 3.f);
				}
				ImU32 hclose_col = hclose_hov
					? IM_COL32(255,100,100,(int)(220*a))
					: IM_COL32(150,150,160,(int)((hex_is_active ? 140.f : 80.f)*a));
				float hcmx = (hcx0 + hcx1) * 0.5f, hcmy = (hcy0 + hcy1) * 0.5f;
				float hcr = 3.f;
				wdl->AddLine(ImVec2(hcmx - hcr, hcmy - hcr), ImVec2(hcmx + hcr, hcmy + hcr), hclose_col, 1.2f);
				wdl->AddLine(ImVec2(hcmx + hcr, hcmy - hcr), ImVec2(hcmx - hcr, hcmy + hcr), hclose_col, 1.2f);

				if (hclose_hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
					hex_view::g_state.active = false;
					hex_view::g_state.data.clear();
					hex_view::g_state.source_name.clear();
					if (globals::ui::active_center_view == center_view_t::hex_view)
						globals::ui::active_center_view = center_view_t::code_editor;
				} else if (htab_hov && !hclose_hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
					globals::ui::active_center_view = center_view_t::hex_view;
				}
			}
		}


		float hub_active_x0 = 0.f;
		float hub_active_x1 = 0.f;
		float hub_active_y1 = 0.f;
		bool  hub_has_active = false;
		float hub_hover_x0 = 0.f;
		float hub_hover_x1 = 0.f;
		float hub_hover_y1 = 0.f;
		bool  hub_has_hover = false;

		{
			bool net_is_active = (globals::ui::active_center_view == center_view_t::network_view);
			const char* net_label = "Network";
			ImVec2 nts = ImGui::CalcTextSize(net_label);
			float ntw = 10.f * 2.f + nts.x;
			float ntx0 = rbtn_x0 - ntw - 8.f;
			float ntx1 = ntx0 + ntw;
			float tab_h4 = row_h - 2.f;
			float nty0 = r1_cy - tab_h4 * 0.5f;
			float nty1 = nty0 + tab_h4;

			if (ntx0 > hx0 + hdr_pad + 4.f) {
				bool ntab_hov = ImGui::IsMouseHoveringRect(ImVec2(ntx0, nty0), ImVec2(ntx1, nty1), false);

				if (net_is_active) {
					wdl->AddRectFilled(ImVec2(ntx0, nty0), ImVec2(ntx1, nty1),
						IM_COL32(255,255,255,(int)(16*a)), 4.f, ImDrawFlags_RoundCornersTop);
					hub_active_x0 = ntx0; hub_active_x1 = ntx1; hub_active_y1 = nty1;
					hub_has_active = true;
				} else if (ntab_hov) {
					wdl->AddRectFilled(ImVec2(ntx0, nty0), ImVec2(ntx1, nty1),
						IM_COL32(255,255,255,(int)(8*a)), 4.f, ImDrawFlags_RoundCornersTop);
					hub_hover_x0 = ntx0; hub_hover_x1 = ntx1; hub_hover_y1 = nty1;
					hub_has_hover = true;
				}

				ImU32 ntab_col = net_is_active ? ac_full
				               : IM_COL32(170, 175, 190, (int)((ntab_hov ? 220.f : 160.f)*a));
				wdl->AddText(ImVec2(ntx0 + 10.f, nty0 + (tab_h4 - nts.y) * 0.5f),
					ntab_col, net_label);

				if (ntab_hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
					globals::ui::active_center_view = center_view_t::network_view;
				}
			}
		}


		{
			auto scv = globals::ui::active_center_view;
			bool scan_is_active = (scv == center_view_t::scan_hub
				|| scv == center_view_t::memory_scanner
				|| scv == center_view_t::crypto_scanner
				|| scv == center_view_t::aob_generator
				|| scv == center_view_t::xref_browser
				|| scv == center_view_t::snapshot_diff
				|| scv == center_view_t::pointer_scanner
				|| scv == center_view_t::decrypt_oracle
				|| scv == center_view_t::integrity_hunter);
			const char* scan_label = "Scan";
			ImVec2 sts = ImGui::CalcTextSize(scan_label);
			float stw = 10.f * 2.f + sts.x;

			float net_tab_w = 10.f * 2.f + ImGui::CalcTextSize("Network").x;
			float net_tab_x0 = rbtn_x0 - net_tab_w - 8.f;
			float tab_h_s = row_h - 2.f;
			float stx0 = net_tab_x0 - stw - 6.f;
			float stx1 = stx0 + stw;
			float sty0 = r1_cy - tab_h_s * 0.5f;
			float sty1 = sty0 + tab_h_s;

			if (stx0 > hx0 + hdr_pad + 4.f) {
				bool stab_hov = ImGui::IsMouseHoveringRect(ImVec2(stx0, sty0), ImVec2(stx1, sty1), false);

				if (scan_is_active) {
					wdl->AddRectFilled(ImVec2(stx0, sty0), ImVec2(stx1, sty1),
						IM_COL32(255,255,255,(int)(16*a)), 4.f, ImDrawFlags_RoundCornersTop);
					hub_active_x0 = stx0; hub_active_x1 = stx1; hub_active_y1 = sty1;
					hub_has_active = true;
				} else if (stab_hov) {
					wdl->AddRectFilled(ImVec2(stx0, sty0), ImVec2(stx1, sty1),
						IM_COL32(255,255,255,(int)(8*a)), 4.f, ImDrawFlags_RoundCornersTop);
					hub_hover_x0 = stx0; hub_hover_x1 = stx1; hub_hover_y1 = sty1;
					hub_has_hover = true;
				}

				ImU32 stab_col = scan_is_active ? ac_full
				               : IM_COL32(170, 175, 190, (int)((stab_hov ? 220.f : 160.f)*a));
				wdl->AddText(ImVec2(stx0 + 10.f, sty0 + (tab_h_s - sts.y) * 0.5f),
					stab_col, scan_label);

				if (stab_hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
					globals::ui::active_center_view = center_view_t::scan_hub;
				}
			}
		}


		float dtx0 = 0.f;
		{
			bool dbg_is_active = (globals::ui::active_center_view == center_view_t::debugger_view);
			const char* dbg_label = "Debugger";
			ImVec2 dts = ImGui::CalcTextSize(dbg_label);
			float dtw = 10.f * 2.f + dts.x;

			float net_tw = 10.f * 2.f + ImGui::CalcTextSize("Network").x;
			float net_x0 = rbtn_x0 - net_tw - 8.f;
			float scan_tw = 10.f * 2.f + ImGui::CalcTextSize("Scan").x;
			float scan_x0 = net_x0 - scan_tw - 6.f;
			float tab_h_d = row_h - 2.f;
			dtx0 = scan_x0 - dtw - 6.f;
			float dtx1 = dtx0 + dtw;
			float dty0 = r1_cy - tab_h_d * 0.5f;
			float dty1 = dty0 + tab_h_d;

			if (dtx0 > hx0 + hdr_pad + 4.f) {
				bool dtab_hov = ImGui::IsMouseHoveringRect(ImVec2(dtx0, dty0), ImVec2(dtx1, dty1), false);

				if (dbg_is_active) {
					wdl->AddRectFilled(ImVec2(dtx0, dty0), ImVec2(dtx1, dty1),
						IM_COL32(255,255,255,(int)(16*a)), 4.f, ImDrawFlags_RoundCornersTop);
					hub_active_x0 = dtx0; hub_active_x1 = dtx1; hub_active_y1 = dty1;
					hub_has_active = true;
				} else if (dtab_hov) {
					wdl->AddRectFilled(ImVec2(dtx0, dty0), ImVec2(dtx1, dty1),
						IM_COL32(255,255,255,(int)(8*a)), 4.f, ImDrawFlags_RoundCornersTop);
					hub_hover_x0 = dtx0; hub_hover_x1 = dtx1; hub_hover_y1 = dty1;
					hub_has_hover = true;
				}

				ImU32 dtab_col = dbg_is_active ? ac_full
				               : IM_COL32(170, 175, 190, (int)((dtab_hov ? 220.f : 160.f)*a));
				wdl->AddText(ImVec2(dtx0 + 10.f, dty0 + (tab_h_d - dts.y) * 0.5f),
					dtab_col, dbg_label);

				if (dtab_hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
					globals::ui::active_center_view = center_view_t::debugger_view;
				}
			}
		}


		{
			auto acv = globals::ui::active_center_view;

			auto is_hub_active = [&](center_view_t hub) -> bool {
				if (acv == hub) return true;
				if (hub == center_view_t::types_hub)
					return acv == center_view_t::struct_recon;
				if (hub == center_view_t::analysis_hub)
					return acv == center_view_t::symbolic_view
						|| acv == center_view_t::taint_view
						|| acv == center_view_t::deobfuscation_view
						|| acv == center_view_t::stealth_view
						|| acv == center_view_t::fuzzer_view;
				return false;
			};

			auto add_right_tab = [&](const char* label, center_view_t view_id, float anchor_x0) {
				bool is_active = (acv == view_id) || is_hub_active(view_id);
				ImVec2 lsz = ImGui::CalcTextSize(label);
				float tw = 10.f * 2.f + lsz.x;
				float tx0 = anchor_x0 - tw - 4.f;
				float tx1 = tx0 + tw;
				float th = row_h - 2.f;
				float ty0 = r1_cy - th * 0.5f;
				float ty1 = ty0 + th;
				if (tx0 > hx0 + hdr_pad + 4.f) {
					bool hov = ImGui::IsMouseHoveringRect(ImVec2(tx0, ty0), ImVec2(tx1, ty1), false);
					if (is_active) {
						wdl->AddRectFilled(ImVec2(tx0, ty0), ImVec2(tx1, ty1),
							IM_COL32(255,255,255,(int)(16*a)), 4.f, ImDrawFlags_RoundCornersTop);
						hub_active_x0 = tx0; hub_active_x1 = tx1; hub_active_y1 = ty1;
						hub_has_active = true;
					} else if (hov) {
						wdl->AddRectFilled(ImVec2(tx0, ty0), ImVec2(tx1, ty1),
							IM_COL32(255,255,255,(int)(8*a)), 4.f, ImDrawFlags_RoundCornersTop);
						hub_hover_x0 = tx0; hub_hover_x1 = tx1; hub_hover_y1 = ty1;
						hub_has_hover = true;
					}
					ImU32 tc = is_active ? ac_full : IM_COL32(170, 175, 190, (int)((hov ? 220.f : 160.f)*a));
					wdl->AddText(ImVec2(tx0 + 10.f, ty0 + (th - lsz.y) * 0.5f), tc, label);
					if (hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
						globals::ui::active_center_view = view_id;
				}
				return tx0;
			};

			float anchor = dtx0;
			anchor = add_right_tab("Decompiler", center_view_t::decompiler, anchor);
			anchor = add_right_tab("Types",      center_view_t::types_hub, anchor);
			anchor = add_right_tab("Analysis",   center_view_t::analysis_hub, anchor);
			anchor = add_right_tab("Binary Map", center_view_t::binary_map, anchor);
		}

		{
			ImGuiStorage* hub_st = ImGui::GetStateStorage();
			ImGuiID hub_id_x   = ImGui::GetID("##hub_ul_x");
			ImGuiID hub_id_w   = ImGui::GetID("##hub_ul_w");
			ImGuiID hub_id_v   = ImGui::GetID("##hub_ul_v");
			ImGuiID hub_id_y   = ImGui::GetID("##hub_ul_y");
			ImGuiID hub_id_a   = ImGui::GetID("##hub_ul_a");
			ImGuiID hub_id_init= ImGui::GetID("##hub_ul_init");

			float hub_ul_x = hub_st->GetFloat(hub_id_x, 0.f);
			float hub_ul_w = hub_st->GetFloat(hub_id_w, 0.f);
			float hub_ul_v = hub_st->GetFloat(hub_id_v, 0.f);
			float hub_ul_y = hub_st->GetFloat(hub_id_y, 0.f);
			float hub_ul_a = hub_st->GetFloat(hub_id_a, 0.f);
			bool  hub_init = hub_st->GetInt(hub_id_init, 0) != 0;

			float target_x = hub_ul_x;
			float target_w = hub_ul_w;
			float target_y = hub_ul_y;
			float target_a = 0.f;
			if (hub_has_active) {
				target_x = hub_active_x0 + 4.f;
				target_w = (hub_active_x1 - hub_active_x0) - 8.f;
				target_y = hub_active_y1;
				target_a = 1.f;
			}

			if (!hub_init && hub_has_active) {
				hub_ul_x = target_x;
				hub_ul_w = target_w;
				hub_ul_y = target_y;
				hub_ul_a = target_a;
				hub_init = true;
			}

			if (hub_has_active) {
				hub_ul_x = aida::motion::spring_step(hub_ul_x, target_x, hub_ul_v,
					aida::motion::spring::balanced, dt);
				hub_ul_w = aida::motion::smooth_lerp(hub_ul_w, target_w, 16.f, dt);
				hub_ul_y = aida::motion::smooth_lerp(hub_ul_y, target_y, 18.f, dt);
				hub_ul_a = aida::motion::smooth_lerp(hub_ul_a, target_a, 12.f, dt);
			} else {
				hub_ul_a = aida::motion::smooth_lerp(hub_ul_a, 0.f, 10.f, dt);
			}

			hub_st->SetFloat(hub_id_x, hub_ul_x);
			hub_st->SetFloat(hub_id_w, hub_ul_w);
			hub_st->SetFloat(hub_id_v, hub_ul_v);
			hub_st->SetFloat(hub_id_y, hub_ul_y);
			hub_st->SetFloat(hub_id_a, hub_ul_a);
			hub_st->SetInt(hub_id_init, hub_init ? 1 : 0);

			if (hub_ul_w > 0.5f && hub_ul_a > 0.005f) {
				const auto& th_hub = aida::ui::resolved();
				float ul_thickness = 3.f;
				float ul_x0 = hub_ul_x;
				float ul_x1 = hub_ul_x + hub_ul_w;
				float ul_y0 = hub_ul_y - ul_thickness * 0.5f;
				float ul_y1 = hub_ul_y + ul_thickness * 0.5f;

				for (int g_pass = 0; g_pass < 3; ++g_pass) {
					float spread = 2.f + static_cast<float>(g_pass) * 2.5f;
					float halo_a = (0.32f - static_cast<float>(g_pass) * 0.09f) * a * hub_ul_a;
					if (halo_a <= 0.f) continue;
					ImU32 halo_col = aida::ui::with_alpha(th_hub.accent_glow, halo_a);
					wdl->AddRectFilled(
						ImVec2(ul_x0 - spread, ul_y0 - spread),
						ImVec2(ul_x1 + spread, ul_y1 + spread),
						halo_col,
						3.f + static_cast<float>(g_pass));
				}

				ImU32 grad_top = aida::ui::with_alpha(th_hub.accent_grad_top, a * hub_ul_a);
				ImU32 grad_bot = aida::ui::with_alpha(th_hub.accent_grad_bot, a * hub_ul_a);
				wdl->AddRectFilledMultiColor(
					ImVec2(ul_x0, ul_y0),
					ImVec2(ul_x1, ul_y1),
					grad_top, grad_top, grad_bot, grad_bot);
			}

			ImGuiID hub_id_hx = ImGui::GetID("##hub_uh_x");
			ImGuiID hub_id_hw = ImGui::GetID("##hub_uh_w");
			ImGuiID hub_id_hy = ImGui::GetID("##hub_uh_y");
			ImGuiID hub_id_ha = ImGui::GetID("##hub_uh_a");

			bool show_hover_preview = hub_has_hover
				&& (!hub_has_active
					|| std::abs(hub_hover_x0 - hub_active_x0) > 0.5f);

			if (show_hover_preview) {
				const auto& th_hub2 = aida::ui::resolved();
				float hub_uh_x = hub_st->GetFloat(hub_id_hx, hub_hover_x0 + 4.f);
				float hub_uh_w = hub_st->GetFloat(hub_id_hw, (hub_hover_x1 - hub_hover_x0) - 8.f);
				float hub_uh_y = hub_st->GetFloat(hub_id_hy, hub_hover_y1);
				float hub_uh_a = hub_st->GetFloat(hub_id_ha, 0.f);

				float th_x = hub_hover_x0 + 4.f;
				float th_w = (hub_hover_x1 - hub_hover_x0) - 8.f;
				float th_y = hub_hover_y1;

				hub_uh_x = aida::motion::smooth_lerp(hub_uh_x, th_x, 22.f, dt);
				hub_uh_w = aida::motion::smooth_lerp(hub_uh_w, th_w, 22.f, dt);
				hub_uh_y = aida::motion::smooth_lerp(hub_uh_y, th_y, 22.f, dt);
				hub_uh_a = aida::motion::smooth_lerp(hub_uh_a, 1.f, 14.f, dt);

				hub_st->SetFloat(hub_id_hx, hub_uh_x);
				hub_st->SetFloat(hub_id_hw, hub_uh_w);
				hub_st->SetFloat(hub_id_hy, hub_uh_y);
				hub_st->SetFloat(hub_id_ha, hub_uh_a);

				if (hub_uh_w > 0.5f && hub_uh_a > 0.01f) {
					ImU32 hov_col = aida::ui::with_alpha(th_hub2.accent_u32, a * hub_uh_a * 0.45f);
					wdl->AddLine(
						ImVec2(hub_uh_x, hub_uh_y),
						ImVec2(hub_uh_x + hub_uh_w, hub_uh_y),
						hov_col, 1.5f);
				}
			} else {
				float hub_uh_a = hub_st->GetFloat(hub_id_ha, 0.f);
				hub_uh_a = aida::motion::smooth_lerp(hub_uh_a, 0.f, 14.f, dt);
				hub_st->SetFloat(hub_id_ha, hub_uh_a);
			}
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
					disasm::decode_section_async(g_disasm.file);
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

		if (g_disasm.file.loaded) {
			bool is_hex_view = (globals::ui::active_center_view == center_view_t::hex_view);
			const char* vt_label = is_hex_view ? "View Disassembly" : "View Hex";
			float vtbtn_w = ImGui::CalcTextSize(vt_label).x + 22.f;
			float vtbtn_x = rbtn_x0 - vtbtn_w - 8.f;

			bool vt_clicked = ghost_btn(vt_label,
				ImGui::GetID("##vthv2"), ImGui::GetID("##vtfl2"),
				vtbtn_x, r2_cy, vtbtn_w);

			if (vt_clicked) {
				if (is_hex_view) {
					globals::ui::active_center_view = center_view_t::disassembly;
				} else {
					if (!hex_view::g_state.active || hex_view::g_state.data.empty())
						hex_view::load_from_file(g_disasm.file.path);
					globals::ui::active_center_view = center_view_t::hex_view;
				}
			}
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


	g_render_section = "center_view_dispatch";
	auto cv = globals::ui::active_center_view;


	if (cv == center_view_t::welcome) {
		if (code_editor::active && !code_editor::buffer.empty())
			cv = center_view_t::code_editor;
		else if (g_disasm.file.loaded && (g_disasm.live_mode || g_disasm.file.decoding || !g_disasm.file.instrs.empty()))
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
	}


	else if (cv == center_view_t::hex_view && hex_view::g_state.active)
	{
		hex_view::render(0.f, 0.f, vw, vh, a, ax3, ay3, az3);
	}

	else if (cv == center_view_t::disassembly && g_disasm.file.loaded && (g_disasm.live_mode || g_disasm.file.decoding || !g_disasm.file.instrs.empty()))
	{
		disasm_view::render(0.f, 0.f, vw, vh, a, ax3, ay3, az3, g_disasm, dt);
	}

	else if (cv == center_view_t::network_view)
	{
		network_view::render(0.f, 0.f, vw, vh, a, ax3, ay3, az3);
	}

	else if (cv == center_view_t::debugger_view)
	{
		debugger_view::render(0.f, 0.f, vw, vh, a, ax3, ay3, az3);
	}

	else if (cv == center_view_t::decompiler)
	{
		decompiler_view::render(0.f, 0.f, vw, vh, a, ax3, ay3, az3);
	}

	else if (cv == center_view_t::scan_hub || cv == center_view_t::memory_scanner
		|| cv == center_view_t::crypto_scanner || cv == center_view_t::aob_generator
		|| cv == center_view_t::xref_browser || cv == center_view_t::snapshot_diff
		|| cv == center_view_t::pointer_scanner || cv == center_view_t::decrypt_oracle
		|| cv == center_view_t::integrity_hunter)
	{
		scan_hub_view::render(0.f, 0.f, vw, vh, a, ax3, ay3, az3);
	}

	else if (cv == center_view_t::types_hub || cv == center_view_t::struct_recon)
	{
		types_hub_view::render(0.f, 0.f, vw, vh, a, ax3, ay3, az3);
	}

	else if (cv == center_view_t::analysis_hub || cv == center_view_t::symbolic_view
		|| cv == center_view_t::taint_view || cv == center_view_t::deobfuscation_view
		|| cv == center_view_t::stealth_view || cv == center_view_t::fuzzer_view)
	{
		analysis_hub_view::render(0.f, 0.f, vw, vh, a, ax3, ay3, az3);
	}

	else if (cv == center_view_t::binary_map)
	{
		aida::binary_map_view::render(0, 0, vw, vh, a, ax3, ay3, az3);
	}

	else
	{

		ImDrawList* cdl  = ImGui::GetWindowDrawList();
		ImVec2      orig = ImGui::GetWindowPos();

		const char* hint = !g_disasm.file.err.empty()     ? g_disasm.file.err.c_str()
			             : !g_disasm.file.loaded           ? "Choose a file to begin"
			             :                                   "Click 'Run' to execute in sandbox";
		ImVec2 ht2 = ImGui::CalcTextSize(hint);
		float  window_h = ImGui::GetWindowHeight();
		cdl->AddText(ImVec2(orig.x + vw*0.5f - ht2.x*0.5f, orig.y + window_h * 0.5f - ht2.y*0.5f),
			IM_COL32(100,100,120,(int)(120*a)), hint);
	}

	}
	ImGui::EndChild();
	ImGui::PopStyleVar();

	g_render_section = "file_tabs_popup";
	{
		bool popup_active = (file_tabs::pending_close_idx >= 0);


		float target = popup_active ? 1.f : 0.f;
		float speed = popup_active ? 12.f : 8.f;
		file_tabs::close_confirm_anim += (target - file_tabs::close_confirm_anim) *
			std::min(speed * dt, 1.f);
		if (!popup_active && file_tabs::close_confirm_anim < 0.01f)
			file_tabs::close_confirm_anim = 0.f;
		file_tabs::show_close_confirm = false;

		float anim = file_tabs::close_confirm_anim;
		if (anim > 0.01f) {
			ImDrawList* fdl = ImGui::GetForegroundDrawList();
			ImVec2 display = ImGui::GetIO().DisplaySize;


			fdl->AddRectFilled(ImVec2(0, 0), display,
				IM_COL32(0, 0, 0, (int)(120 * anim)));


			float pw = 380.f, ph = 150.f;
			float scale = 0.92f + 0.08f * anim;
			float sw = pw * scale, sh = ph * scale;
			float px = display.x * 0.5f - sw * 0.5f;
			float py = display.y * 0.5f - sh * 0.5f - 20.f * (1.f - anim);
			float popup_alpha = anim;


			for (int s = 0; s < 4; s++) {
				float off = 4.f + s * 3.f;
				fdl->AddRectFilled(
					ImVec2(px + off, py + off),
					ImVec2(px + sw + off, py + sh + off),
					IM_COL32(0, 0, 0, (int)(30 * popup_alpha * (4 - s) / 4.f)), 12.f);
			}


			float ax3 = globals::ui::accent.x;
			float ay3 = globals::ui::accent.y;
			float az3 = globals::ui::accent.z;
			fdl->AddRectFilled(ImVec2(px, py), ImVec2(px + sw, py + sh),
				IM_COL32(28, 28, 38, (int)(245 * popup_alpha)), 12.f);
			fdl->AddRect(ImVec2(px, py), ImVec2(px + sw, py + sh),
				IM_COL32(80, 80, 120, (int)(60 * popup_alpha)), 12.f);


			fdl->AddRectFilled(ImVec2(px + 1.f, py + 1.f), ImVec2(px + sw - 1.f, py + 3.f),
				IM_COL32((int)(ax3 * 255), (int)(ay3 * 255), (int)(az3 * 255),
				         (int)(180 * popup_alpha)), 2.f);


			int ci = file_tabs::pending_close_idx;
			std::string fname = (ci >= 0 && ci < (int)file_tabs::tabs.size())
				? file_tabs::tabs[ci].filename : "this file";

			std::string title = "Unsaved Changes";
			ImVec2 tts = ImGui::CalcTextSize(title.c_str());
			fdl->AddText(ImVec2(px + sw * 0.5f - tts.x * 0.5f, py + 18.f),
				IM_COL32(220, 220, 240, (int)(240 * popup_alpha)), title.c_str());

			std::string msg = "Do you want to save '" + fname + "'?";
			ImVec2 mts = ImGui::CalcTextSize(msg.c_str());
			fdl->AddText(ImVec2(px + sw * 0.5f - mts.x * 0.5f, py + 46.f),
				IM_COL32(160, 160, 180, (int)(200 * popup_alpha)), msg.c_str());


			fdl->AddLine(ImVec2(px + 20.f, py + 76.f), ImVec2(px + sw - 20.f, py + 76.f),
				IM_COL32(255, 255, 255, (int)(15 * popup_alpha)));


			ImGui::SetMouseCursor(ImGuiMouseCursor_Arrow);

			struct btn_t { const char* label; float w; ImU32 bg; ImU32 bg_hov; };
			btn_t buttons[] = {
				{"Save",        90.f,
				 IM_COL32((int)(ax3*180), (int)(ay3*180), (int)(az3*180), (int)(60 * popup_alpha)),
				 IM_COL32((int)(ax3*220), (int)(ay3*220), (int)(az3*220), (int)(100 * popup_alpha))},
				{"Don't Save",  100.f,
				 IM_COL32(180, 60, 60, (int)(40 * popup_alpha)),
				 IM_COL32(200, 70, 70, (int)(80 * popup_alpha))},
				{"Cancel",      90.f,
				 IM_COL32(60, 60, 80, (int)(50 * popup_alpha)),
				 IM_COL32(80, 80, 110, (int)(90 * popup_alpha))},
			};

			float btn_h = 34.f;
			float total_btn_w = buttons[0].w + buttons[1].w + buttons[2].w + 16.f;
			float bx = px + sw * 0.5f - total_btn_w * 0.5f;
			float by = py + 90.f;

			ImVec2 mpos = ImGui::GetIO().MousePos;
			bool clicked = ImGui::IsMouseClicked(ImGuiMouseButton_Left);
			int action = -1;

			for (int bi = 0; bi < 3; bi++) {
				float bx0 = bx, by0 = by;
				float bx1 = bx + buttons[bi].w, by1 = by + btn_h;
				bool hov = (mpos.x >= bx0 && mpos.x <= bx1 && mpos.y >= by0 && mpos.y <= by1);

				if (hov) ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);

				ImU32 bg = hov ? buttons[bi].bg_hov : buttons[bi].bg;
				fdl->AddRectFilled(ImVec2(bx0, by0), ImVec2(bx1, by1), bg, 8.f);

				if (hov) {
					fdl->AddRect(ImVec2(bx0, by0), ImVec2(bx1, by1),
						IM_COL32(255, 255, 255, (int)(25 * popup_alpha)), 8.f);
				}

				ImVec2 bts = ImGui::CalcTextSize(buttons[bi].label);
				float tx = bx0 + (buttons[bi].w - bts.x) * 0.5f;
				float ty = by0 + (btn_h - bts.y) * 0.5f;
				fdl->AddText(ImVec2(tx, ty),
					IM_COL32(220, 220, 240, (int)((hov ? 255 : 200) * popup_alpha)),
					buttons[bi].label);

				if (hov && clicked) action = bi;
				bx = bx1 + 8.f;
			}

			if (action == 0) {
				if (ci >= 0 && ci < (int)file_tabs::tabs.size()) {
					if (ci == file_tabs::active_tab)
						code_editor::save();
				}
				file_tabs::close_tab(ci);
				file_tabs::pending_close_idx = -1;
			} else if (action == 1) {
				file_tabs::close_tab(ci);
				file_tabs::pending_close_idx = -1;
			} else if (action == 2) {
				file_tabs::pending_close_idx = -1;
			}


			if (popup_active && clicked && action == -1) {

			}
		}
	}

	g_render_section = "right_panel";
	if (right_w > 1.f) {
	begin_child("##chat", ImVec2(pad + left_gap + center_w + gap, content_top), ImVec2(right_w, right_total_h), a);


	static float s_settings_slide = 0.f;
	{
		float dt_s = ImGui::GetIO().DeltaTime;
		float slide_target = g_settings_open ? 1.f : 0.f;
		s_settings_slide += (slide_target - s_settings_slide) * (std::min)(dt_s * 12.f, 1.f);
		if (std::abs(s_settings_slide - slide_target) < 0.003f) s_settings_slide = slide_target;
	}
	bool settings_visible = g_settings_open || s_settings_slide > 0.005f;


	{
		float ax = globals::ui::accent.x * 255.f;
		float ay = globals::ui::accent.y * 255.f;
		float az = globals::ui::accent.z * 255.f;

		float cw = ImGui::GetWindowWidth();
		float ch = ImGui::GetWindowHeight();
		float frame_h    = ImGui::GetFrameHeight();
		float chat_scroll_y_persistent = 0.f;
		bool  chat_user_scrolled_up = false;


		float line_h     = ImGui::GetFontSize();
		float input_pad  = 10.f;
		float pill_zone_h = 28.f;
		int   num_lines  = 1;
		{
			for (const char* p = g_chat_buf; *p; ++p)
				if (*p == '\n') ++num_lines;

			float text_w = cw - frame_h - 4.f - 24.f;
			if (text_w > 0.f) {
				ImVec2 ts = ImGui::CalcTextSize(g_chat_buf, nullptr, false, text_w);
				int wrapped_lines = (int)((ts.y + line_h - 1.f) / line_h);
				if (wrapped_lines > num_lines) num_lines = wrapped_lines;
			}
		}
		int   max_lines  = 8;
		int   vis_lines  = std::max(1, std::min(num_lines, max_lines));
		float input_h    = vis_lines * line_h + input_pad * 2.f + pill_zone_h;
		float bot_pad    = 4.f;
		float input_y    = ch - input_h - bot_pad;
		float chat_sep_y = input_y - 6.f;
		float msg_area_h = chat_sep_y - 24.f;


		{
			const auto& th_ch = aida::ui::resolved();
			ImDrawList* hdr_dl = ImGui::GetWindowDrawList();
			ImVec2 wpos_ch = ImGui::GetWindowPos();
			float gear_sz = 28.f;
			float btn_gap = 6.f;
			float btn_area = gear_sz * 3.f + btn_gap * 2.f + 8.f;
			float bx = cw - btn_area;
			if (bx < 4.f) bx = 4.f;

			ImGuiStorage* hs = ImGui::GetStateStorage();
			auto draw_circle_btn = [&](const char* label, const char* tip,
				const char* icon_render, float bx_local, float by_local,
				ImU32 icon_col_resting) -> bool
			{
				ImVec2 ba(wpos_ch.x + bx_local, wpos_ch.y + by_local);
				ImVec2 bb(ba.x + gear_sz, ba.y + gear_sz);
				bool hov = ImGui::IsMouseHoveringRect(ba, bb);
				ImGuiID hid = ImGui::GetID(label);
				float hv = hs->GetFloat(hid, 0.f);
				hv += ((hov ? 1.f : 0.f) - hv) * std::min(12.f * dt, 1.f);
				hs->SetFloat(hid, hv);
				if (hv > 0.01f) {
					hdr_dl->AddRectFilled(ba, bb,
						aida::ui::with_alpha(th_ch.hover_wash, hv * a), gear_sz * 0.5f);
				}
				ImU32 ic = aida::ui::mix(icon_col_resting, th_ch.text_primary, hv);
				ImVec2 ic_ts = ImGui::CalcTextSize(icon_render);
				hdr_dl->AddText(
					ImVec2((ba.x + bb.x) * 0.5f - ic_ts.x * 0.5f,
					       (ba.y + bb.y) * 0.5f - ic_ts.y * 0.5f),
					aida::ui::with_alpha(ic, a), icon_render);

				ImGui::SetCursorPos(ImVec2(bx_local, by_local));
				ImGui::InvisibleButton(label, ImVec2(gear_sz, gear_sz));
				bool clicked = ImGui::IsItemDeactivated() && ImGui::IsItemHovered();
				if (ImGui::IsItemHovered() && tip) ImGui::SetTooltip("%s", tip);
				return clicked;
			};

			if (draw_circle_btn("##chat_history", "Conversation history", "H", bx, 4.f, th_ch.text_primary)) {
				conversations::refresh_history();
				conversations::browser_open = !conversations::browser_open;
			}
			bx += gear_sz + btn_gap;
			if (draw_circle_btn("##new_chat", "New chat", "+", bx, 4.f, th_ch.text_primary)) {
				conversations::new_chat();
			}
			bx += gear_sz + btn_gap;
			if (draw_circle_btn("##chat_settings", "AI Settings", ICON_COG, bx, 4.f, th_ch.text_primary)) {
				g_settings_open = true;
			}
			ImGui::SetCursorPosY(28.f);
		}


		if (conversations::browser_open) {
			static float history_appear = 0.f;
			static float history_appear_v = 0.f;
			history_appear = aida::motion::spring_step(history_appear, 1.f, history_appear_v,
				aida::motion::spring::balanced, dt);

			ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));
			ImGui::BeginChild("##history_panel", ImVec2(cw, msg_area_h), false,
				ImGuiWindowFlags_NoBackground | ImGuiWindowFlags_NoScrollbar);

			ImDrawList* hdl = ImGui::GetWindowDrawList();
			ImVec2 hp = ImGui::GetWindowPos();
			{
				const auto& hth = aida::ui::resolved();
				ImVec2 ha(hp.x, hp.y);
				ImVec2 hb(hp.x + cw, hp.y + msg_area_h);
				aida::ui::blur::layer_request_t hr;
				hr.pos = ha; hr.size = ImVec2(cw, msg_area_h);
				hr.radius = 10.f; hr.strength = 0.6f; hr.alpha = history_appear * a;
				aida::ui::blur::schedule(hr);
				aida::ui::blur::render_glass_fill(hdl, ha, hb, 10.f, history_appear * a);
				aida::ui::blur::render_glass_border(hdl, ha, hb, 10.f, history_appear * a, 1.f);
				(void)hth;
			}

			float pad = 8.f;
			float header_h = 32.f;

			hdl->AddText(ImVec2(hp.x + pad + 2.f, hp.y + (header_h - ImGui::GetFontSize()) * 0.5f),
				IM_COL32(200, 200, 220, (int)(220 * history_appear * a)), "Conversations");

			float close_sz = 20.f;
			float close_x = hp.x + cw - close_sz - pad;
			float close_y = hp.y + (header_h - close_sz) * 0.5f;
			ImVec2 cmin(close_x, close_y);
			ImVec2 cmax(close_x + close_sz, close_y + close_sz);
			bool close_hov = ImGui::IsMouseHoveringRect(cmin, cmax);
			hdl->AddRectFilled(cmin, cmax,
				IM_COL32(255, 255, 255, close_hov ? (int)(25 * a) : 0), 4.f);
			float cx_m = 5.f;
			hdl->AddLine(ImVec2(cmin.x + cx_m, cmin.y + cx_m), ImVec2(cmax.x - cx_m, cmax.y - cx_m),
				IM_COL32(180, 180, 200, (int)(180 * a)), 1.5f);
			hdl->AddLine(ImVec2(cmax.x - cx_m, cmin.y + cx_m), ImVec2(cmin.x + cx_m, cmax.y - cx_m),
				IM_COL32(180, 180, 200, (int)(180 * a)), 1.5f);
			ImGui::SetCursorPos(ImVec2(cw - close_sz - pad, (header_h - close_sz) * 0.5f));
			if (ImGui::InvisibleButton("##hist_close", ImVec2(close_sz, close_sz))) {
				conversations::browser_open = false;
				history_appear = 0.f;
			}

			float sep_y = hp.y + header_h;
			hdl->AddLine(ImVec2(hp.x + pad, sep_y), ImVec2(hp.x + cw - pad, sep_y),
				IM_COL32(255, 255, 255, (int)(12 * a)));

			static char hist_filter[64] = {};
			ImGui::SetCursorPos(ImVec2(pad, header_h + 4.f));
			ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 6.f);
			ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(8.f, 5.f));
			ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0.06f, 0.06f, 0.09f, 0.8f));
			ImGui::PushStyleColor(ImGuiCol_Border, ImVec4(1, 1, 1, 0.06f));
			ImGui::SetNextItemWidth(cw - pad * 2.f);
			ImGui::InputTextWithHint("##hist_search", "Search conversations...", hist_filter, sizeof(hist_filter));
			ImGui::PopStyleColor(2);
			ImGui::PopStyleVar(2);

			float search_h = ImGui::GetItemRectSize().y + 8.f;
			float list_top = header_h + 4.f + search_h;

			std::string filter_lower;
			for (const char* p = hist_filter; *p; p++)
				filter_lower += static_cast<char>(tolower(*p));

			ImGui::SetCursorPos(ImVec2(0, list_top));
			ImGui::BeginChild("##hist_scroll", ImVec2(cw, msg_area_h - list_top), false);

			ImDrawList* ldl = ImGui::GetWindowDrawList();
			ImVec2 lp = ImGui::GetWindowPos();
			ImGuiStorage* hs = ImGui::GetStateStorage();
			float ly = 0.f;
			float card_h = 56.f;
			float card_gap = 4.f;
			float card_pad = pad;
			float card_w = cw - card_pad * 2.f;
			int visible_count = 0;

			for (int i = 0; i < static_cast<int>(conversations::history.size()); i++) {
				auto& c = conversations::history[i];

				if (!filter_lower.empty()) {
					std::string title_lower;
					std::string t = c.title.empty() ? "untitled" : c.title;
					for (char ch2 : t) title_lower += static_cast<char>(tolower(ch2));
					if (title_lower.find(filter_lower) == std::string::npos)
						continue;
				}

				bool is_current = (c.id == conversations::current_id);

				ImGuiID hov_id = ImGui::GetID(("hist_hov_" + std::to_string(i)).c_str());
				float hov_t = hs->GetFloat(hov_id, 0.f);

				ImVec2 card_min(lp.x + card_pad, lp.y + ly - ImGui::GetScrollY());
				ImVec2 card_max(card_min.x + card_w, card_min.y + card_h);

				bool card_hov = ImGui::IsMouseHoveringRect(card_min, card_max);
				hov_t += ((card_hov ? 1.f : 0.f) - hov_t) * std::min(12.f * dt, 1.f);
				hs->SetFloat(hov_id, hov_t);

				float item_alpha = std::min(history_appear * 3.f - static_cast<float>(visible_count) * 0.15f, 1.f);
				if (item_alpha < 0.f) item_alpha = 0.f;
				float ia = item_alpha * a;

				ImU32 card_bg = is_current
					? IM_COL32(static_cast<int>(ax * 0.15f), static_cast<int>(ay * 0.15f), static_cast<int>(az * 0.15f), static_cast<int>((100 + 30 * hov_t) * ia))
					: IM_COL32(255, 255, 255, static_cast<int>((6 + 14 * hov_t) * ia));
				ldl->AddRectFilled(card_min, card_max, card_bg, 8.f);

				if (is_current) {
					ldl->AddRect(card_min, card_max,
						IM_COL32(static_cast<int>(ax), static_cast<int>(ay), static_cast<int>(az), static_cast<int>(100 * ia)), 8.f, 0, 1.2f);
				} else {
					ldl->AddRect(card_min, card_max,
						IM_COL32(255, 255, 255, static_cast<int>((5 + 8 * hov_t) * ia)), 8.f, 0, 0.6f);
				}

				std::string title = c.title.empty() ? "Untitled" : c.title;
				float title_max_w = card_w - 50.f;
				ImVec2 title_ts = ImGui::CalcTextSize(title.c_str());
				if (title_ts.x > title_max_w) {
					while (title.size() > 3 && ImGui::CalcTextSize(title.c_str()).x > title_max_w - 20.f)
						title.pop_back();
					title += "...";
				}

				ImU32 title_col = is_current
					? IM_COL32(static_cast<int>(ax), static_cast<int>(ay), static_cast<int>(az), static_cast<int>(240 * ia))
					: IM_COL32(210, 210, 225, static_cast<int>(220 * ia));
				ldl->AddText(ImVec2(card_min.x + 12.f, card_min.y + 10.f), title_col, title.c_str());

				char meta[64];
				snprintf(meta, sizeof(meta), "%d messages", c.msg_count);
				ldl->AddText(ImVec2(card_min.x + 12.f, card_min.y + 10.f + ImGui::GetFontSize() + 4.f),
					IM_COL32(130, 130, 150, static_cast<int>(160 * ia)), meta);

				float del_sz = 22.f;
				float del_x = card_max.x - del_sz - 8.f;
				float del_y = card_min.y + (card_h - del_sz) * 0.5f;
				ImVec2 dmin(del_x, del_y);
				ImVec2 dmax(del_x + del_sz, del_y + del_sz);
				bool del_hov = ImGui::IsMouseHoveringRect(dmin, dmax) && card_hov;

				if (hov_t > 0.1f) {
					ldl->AddRectFilled(dmin, dmax,
						IM_COL32(200, 80, 80, del_hov ? static_cast<int>(50 * ia) : static_cast<int>(20 * hov_t * ia)), 4.f);
					float dm = 6.f;
					ImU32 del_col = IM_COL32(200, 100, 100, static_cast<int>((120 + 80 * (del_hov ? 1.f : 0.f)) * hov_t * ia));
					ldl->AddLine(ImVec2(dmin.x + dm, dmin.y + dm), ImVec2(dmax.x - dm, dmax.y - dm), del_col, 1.5f);
					ldl->AddLine(ImVec2(dmax.x - dm, dmin.y + dm), ImVec2(dmin.x + dm, dmax.y - dm), del_col, 1.5f);
				}

				ImGui::SetCursorPos(ImVec2(card_pad, ly));
				if (ImGui::InvisibleButton(("##hcard_" + c.id).c_str(), ImVec2(card_w - del_sz - 12.f, card_h))) {
					if (!is_current) {
						conversations::save_current();
						conversations::load_conversation(c.id);
						conversations::browser_open = false;
						history_appear = 0.f;
					}
				}

				ImGui::SetCursorPos(ImVec2(card_w + card_pad - del_sz - 8.f, ly + (card_h - del_sz) * 0.5f));
				if (ImGui::InvisibleButton(("##hdel_" + std::to_string(i)).c_str(), ImVec2(del_sz, del_sz))) {
					conversations::delete_conversation(c.id);
					if (is_current) {
						g_chat_messages.clear();
						conversations::current_id.clear();
					}
					conversations::refresh_history();
				}

				ly += card_h + card_gap;
				visible_count++;
			}

			if (visible_count == 0) {
				const char* empty_text = filter_lower.empty()
					? "No saved conversations"
					: "No matching conversations";
				ImVec2 ets = ImGui::CalcTextSize(empty_text);
				float ey = (msg_area_h - list_top) * 0.35f;
				ldl->AddText(ImVec2(lp.x + (cw - ets.x) * 0.5f, lp.y + ey),
					IM_COL32(130, 130, 150, static_cast<int>(140 * a)), empty_text);
			}

			ImGui::SetCursorPos(ImVec2(0, ly));
			ImGui::EndChild();
			ImGui::EndChild();
			ImGui::PopStyleVar();
		} else {

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

			if (msg.is_user && msg.text.find("<plan_exit_handoff>") != std::string::npos)
			{
				std::string rendered = msg.text;
				size_t spos = rendered.find("<plan_exit_handoff>");
				if (spos != std::string::npos) rendered.erase(spos, sizeof("<plan_exit_handoff>") - 1);
				while (!rendered.empty() && (rendered.back() == '\n' || rendered.back() == ' '))
					rendered.pop_back();
				std::string display = "[plan -> build]";
				if (!rendered.empty()) display += "\n" + rendered;

				ImVec2 ts = ImGui::CalcTextSize(display.c_str(), nullptr, false, wrap_w * 0.78f);
				float bw = ts.x + 16.f;
				float bh = ts.y + 10.f;
				float target_x = (cw - bw) * 0.5f;
				float bx = target_x;
				float by = cursor_y;
				ImVec2 bmin = ImVec2(wp2.x + bx, wp2.y + by);
				ImVec2 bmax = ImVec2(bmin.x + bw, bmin.y + bh);
				dl->AddRectFilled(bmin, bmax,
					IM_COL32((int)(ax * 0.30f + 30), (int)(ay * 0.30f + 25), (int)(az * 0.30f + 60),
						(int)(200 * appear * a)), 8.f);
				dl->AddRect(bmin, bmax,
					IM_COL32((int)(ax * 0.7f), (int)(ay * 0.7f), (int)(az * 0.9f),
						(int)(120 * appear * a)), 8.f, 0, 1.5f);
				dl->AddText(ImGui::GetFont(), ImGui::GetFontSize(),
					ImVec2(bmin.x + 8.f, bmin.y + 5.f),
					IM_COL32(220, 220, 255, (int)(245 * appear * a)),
					display.c_str(), nullptr, wrap_w * 0.78f);
				cursor_y += bh + 8.f;
			}
			else if (msg.is_user)
			{

				if (chat_edit::active && chat_edit::msg_idx == mi) {
					float edit_w = wrap_w - 8.f;
					float edit_pad = 8.f;
					float by = cursor_y;


					ImVec2 edit_ts = ImGui::CalcTextSize(chat_edit::buf, nullptr, false, edit_w - 24.f);
					float text_h = std::max(edit_ts.y + 8.f, ImGui::GetFontSize() * 2.f + 8.f);
					float model_row_h = 22.f;
					float total_edit_h = edit_pad + text_h + edit_pad + model_row_h + edit_pad;

					ImVec2 bmin = ImVec2(wp2.x + 4.f, wp2.y + by);
					ImVec2 bmax = ImVec2(bmin.x + edit_w, bmin.y + total_edit_h);


					dl->AddRectFilled(bmin, bmax,
						IM_COL32((int)(ax * 0.15f + 20), (int)(ay * 0.15f + 15), (int)(az * 0.15f + 30),
							(int)(240 * appear * a)), 8.f);
					dl->AddRect(bmin, bmax,
						IM_COL32((int)(ax * 0.7f), (int)(ay * 0.7f), (int)(az * 0.7f),
							(int)(120 * appear * a)), 8.f, 0, 1.f);


					ImGui::SetCursorPos(ImVec2(4.f + edit_pad, by + edit_pad - ImGui::GetScrollY() + ImGui::GetWindowPos().y - wp2.y - ImGui::GetWindowPos().y));

					float input_y_screen = bmin.y + edit_pad;
					ImGui::SetCursorScreenPos(ImVec2(bmin.x + edit_pad, input_y_screen));
					ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(4.f, 4.f));
					ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 4.f);
					ImGui::PushStyleColor(ImGuiCol_FrameBg, IM_COL32(0, 0, 0, 0));
					ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(230, 228, 255, (int)(240 * a)));
					ImGui::PushItemWidth(edit_w - edit_pad * 2.f - 40.f);
					ImGui::InputTextMultiline("##chat_edit_input", chat_edit::buf,
						sizeof(chat_edit::buf),
						ImVec2(edit_w - edit_pad * 2.f - 40.f, text_h),
						ImGuiInputTextFlags_CtrlEnterForNewLine);
					bool send_edit = ImGui::IsItemFocused() && ImGui::IsKeyPressed(ImGuiKey_Enter, false)
						&& !ImGui::GetIO().KeyShift && !ImGui::GetIO().KeyCtrl;
					ImGui::PopItemWidth();
					ImGui::PopStyleColor(2);
					ImGui::PopStyleVar(2);


					float row_y = bmin.y + edit_pad + text_h + 4.f;
					float row_x = bmin.x + edit_pad;


					const char* model_name = g_sa_settings.active_provider_profile_id.empty()
						? "No Model" : nullptr;
					std::string model_display;
					if (!model_name) {
						for (auto& pp : g_sa_settings.provider_profiles) {
							if (pp.id == g_sa_settings.active_provider_profile_id) {
								model_display = pp.display_name + " / " + pp.model;
								break;
							}
						}
						if (model_display.empty()) model_display = "No Model";
					} else {
						model_display = model_name;
					}
					ImVec2 mts = ImGui::CalcTextSize(model_display.c_str());
					dl->AddRectFilled(ImVec2(row_x, row_y), ImVec2(row_x + mts.x + 12.f, row_y + model_row_h - 2.f),
						IM_COL32(40, 38, 55, (int)(200 * a)), 4.f);
					dl->AddText(ImVec2(row_x + 6.f, row_y + 2.f),
						IM_COL32(150, 148, 180, (int)(200 * a)), model_display.c_str());


					const char* send_label = "Send";
					ImVec2 sts2 = ImGui::CalcTextSize(send_label);
					float send_w = sts2.x + 16.f;
					float send_x = bmax.x - edit_pad - send_w;
					ImVec2 smin(send_x, row_y);
					ImVec2 smax(send_x + send_w, row_y + model_row_h - 2.f);
					bool send_hov = ImGui::IsMouseHoveringRect(smin, smax);

					ImGuiID send_anim_id = ImGui::GetID("##chat_edit_send_anim");
					float send_anim = s->GetFloat(send_anim_id, 0.f);
					send_anim += ((send_hov ? 1.f : 0.f) - send_anim) * std::min(12.f * ImGui::GetIO().DeltaTime, 1.f);
					s->SetFloat(send_anim_id, send_anim);

					dl->AddRectFilled(smin, smax,
						IM_COL32((int)(ax * (0.5f + 0.3f * send_anim)),
								 (int)(ay * (0.5f + 0.3f * send_anim)),
								 (int)(az * (0.5f + 0.3f * send_anim)),
								 (int)((180 + 60 * send_anim) * a)), 4.f);
					dl->AddText(ImVec2(smin.x + 8.f, smin.y + 2.f),
						IM_COL32(230, 230, 255, (int)(240 * a)), send_label);


					if ((send_hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) || send_edit) {

						std::string new_text(chat_edit::buf);
						if (!new_text.empty()) {

							g_chat_messages.erase(g_chat_messages.begin() + mi, g_chat_messages.end());

							ChatMessage um;
							um.text = new_text;
							um.is_user = true;
							um.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
								std::chrono::system_clock::now().time_since_epoch()).count();
							g_chat_messages.push_back(um);
							g_chat_scroll_to_bottom = true;
						}
						chat_edit::active = false;
						chat_edit::msg_idx = -1;
					}


					if (ImGui::IsMouseClicked(ImGuiMouseButton_Left) &&
						!ImGui::IsMouseHoveringRect(bmin, bmax) && !send_hov) {
						chat_edit::active = false;
						chat_edit::msg_idx = -1;
					}


					if (ImGui::IsKeyPressed(ImGuiKey_Escape, false)) {
						chat_edit::active = false;
						chat_edit::msg_idx = -1;
					}

					cursor_y += total_edit_h + 8.f;
				}
				else
				{


				ImVec2 ts = ImGui::CalcTextSize(msg.text.c_str(), nullptr, false, wrap_w * 0.78f);
				float  bw = ts.x + 16.f;
				float  bh = ts.y + 10.f;


				float target_x = cw - bw - 8.f;
				float bx = target_x + (1.f - appear) * 40.f;
				float by = cursor_y;


				ImVec2 bmin = ImVec2(wp2.x + bx, wp2.y + by);
				ImVec2 bmax = ImVec2(bmin.x + bw, bmin.y + bh);


				ImGuiID uhov_id = ImGui::GetID(("uhov_" + std::to_string(mi)).c_str());
				float uhov_a = s->GetFloat(uhov_id, 0.f);
				bool user_msg_hov = ImGui::IsMouseHoveringRect(bmin, bmax);
				uhov_a += ((user_msg_hov ? 1.f : 0.f) - uhov_a) * std::min(10.f * ImGui::GetIO().DeltaTime, 1.f);
				s->SetFloat(uhov_id, uhov_a);

				dl->AddRectFilled(bmin, bmax,
					IM_COL32((int)(ax * 0.22f + 18), (int)(ay * 0.22f + 12), (int)(az * 0.22f + 28),
						(int)((220 + uhov_a * 25.f) * appear * a)), 8.f);


				if (uhov_a > 0.01f) {
					dl->AddRect(bmin, bmax,
						IM_COL32((int)(ax * 0.6f), (int)(ay * 0.6f), (int)(az * 0.6f),
							(int)(uhov_a * 60.f * appear * a)), 8.f, 0, 1.f);
				}

				dl->AddText(ImGui::GetFont(), ImGui::GetFontSize(),
					ImVec2(bmin.x + 8.f, bmin.y + 5.f),
					IM_COL32(230, 228, 255, (int)(240 * appear * a)),
					msg.text.c_str(), nullptr, wrap_w * 0.78f);


				if (user_msg_hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
					chat_edit::active = true;
					chat_edit::msg_idx = mi;
					strncpy_s(chat_edit::buf, msg.text.c_str(), _TRUNCATE);
				}


				if (user_msg_hov && ImGui::IsMouseClicked(ImGuiMouseButton_Right)) {
					ImGui::OpenPopup(("##user_msg_ctx_" + std::to_string(mi)).c_str());
				}
				if (ImGui::BeginPopup(("##user_msg_ctx_" + std::to_string(mi)).c_str())) {
					if (ImGui::MenuItem("Copy"))
						ImGui::SetClipboardText(msg.text.c_str());
					if (ImGui::MenuItem("Edit")) {
						chat_edit::active = true;
						chat_edit::msg_idx = mi;
						strncpy_s(chat_edit::buf, msg.text.c_str(), _TRUNCATE);
					}
					if (ImGui::MenuItem("Delete")) {
						g_chat_messages.erase(g_chat_messages.begin() + mi);
						mi--;
						ImGui::EndPopup();
						continue;
					}
					ImGui::EndPopup();
				}


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

				cursor_y += bh + 18.f;
				}
			}
			else
			{
				if (msg.has_thinking)
				{
					bool still_thinking = !g_ai_thinking_active && mi == (int)g_chat_messages.size() - 1;

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
						if (msg.is_user && mi >= 0 && mi < (int)g_chat_messages.size()) {
							chat_edit::active = true;
							chat_edit::msg_idx = mi;
							strncpy_s(chat_edit::buf, msg.text.c_str(), _TRUNCATE);
						}
					}


					{
						ImGuiID hov_id = ImGui::GetID(("mha_" + std::to_string(mi)).c_str());
						float hov_a = s->GetFloat(hov_id, 0.f);
						hov_a += ((ImGui::IsMouseHoveringRect(bmin, bmax) ? 1.f : 0.f) - hov_a)
							* std::min(8.f * ImGui::GetIO().DeltaTime, 1.f);
						s->SetFloat(hov_id, hov_a);

						if (hov_a > 0.01f && !msg.model_id.empty())
						{
							ImVec2 tts2 = ImGui::CalcTextSize(msg.model_id.c_str());
							dl->AddText(
								ImVec2(bmax.x + 6.f, bmin.y + (anim_bh - tts2.y) * 0.5f),
								IM_COL32(120, 115, 155, (int)(170 * hov_a * falpha * a)), msg.model_id.c_str());
						}
					}

					cursor_y += anim_bh + 18.f;
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
		float chat_scroll_max = ImGui::GetScrollMaxY();
		static bool s_chat_user_scrolled_up = false;
		static float s_chat_scroll_y_persistent = 0.f;
		s_chat_scroll_y_persistent = chat_scroll_y;
		s_chat_user_scrolled_up = (chat_scroll_max > 4.f) && (chat_scroll_max - chat_scroll_y) > 32.f;
		chat_scroll_y_persistent = s_chat_scroll_y_persistent;
		chat_user_scrolled_up = s_chat_user_scrolled_up;
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
					IM_COL32(th_bb_r, th_bb_g, th_bb_b, (int)(200 * top_a * a)),
					IM_COL32(th_bb_r, th_bb_g, th_bb_b, (int)(200 * top_a * a)),
					IM_COL32(th_bb_r, th_bb_g, th_bb_b, 0),
					IM_COL32(th_bb_r, th_bb_g, th_bb_b, 0));
			}

			float bot_y = msgs_screen_pos.y + msg_area_h;
			dl->AddRectFilledMultiColor(
				ImVec2(fade_x0, bot_y - fade_h),
				ImVec2(fade_x1, bot_y),
				IM_COL32(th_bb_r, th_bb_g, th_bb_b, 0), IM_COL32(th_bb_r, th_bb_g, th_bb_b, 0),
				IM_COL32(th_bb_r, th_bb_g, th_bb_b, (int)(200 * a)),
				IM_COL32(th_bb_r, th_bb_g, th_bb_b, (int)(200 * a)));

			dl->PopClipRect();
		}
		}

		ImDrawList* dl = ImGui::GetWindowDrawList();

		{
			ImVec2 wp3  = ImGui::GetWindowPos();
			float  sy   = wp3.y + chat_sep_y;
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

			float pill_strip_h = 26.f;
			float pill_strip_x = 4.f;
			ImVec2 pill_anchor_window = ImVec2(pill_strip_x, input_y - pill_strip_h - 2.f);
			ImVec2 pill_anchor_screen = ImVec2(ImGui::GetWindowPos().x + pill_anchor_window.x,
				ImGui::GetWindowPos().y + pill_anchor_window.y);
			chat_render_agent_pill(pill_anchor_screen.x, pill_anchor_screen.y, a);


			ImGui::SetCursorPos(ImVec2(0.f, input_y));
			ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(th_pb_r/255.f, th_pb_g/255.f, th_pb_b/255.f, 0.85f * a));
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
					bool ctrl  = ImGui::GetIO().KeyCtrl;
					if (enter_now && !shift && !ctrl) {
						s_enter_pressed = true;
					}
					if (enter_now && shift && !ctrl) {
						data->InsertChars(data->CursorPos, "\n");
					}
				}
				return 0;
			};

			float input_w = cw - btn_sz - igap;
			ImGui::SetNextItemWidth(input_w);
			ImGui::InputTextMultiline("##chatinput", g_chat_buf, sizeof(g_chat_buf),
				ImVec2(input_w, input_h),
				ImGuiInputTextFlags_CallbackAlways | ImGuiInputTextFlags_CtrlEnterForNewLine | ImGuiInputTextFlags_NoHorizontalScroll,
				input_callback);
			bool enter_pressed = s_enter_pressed;
			s_enter_pressed = false;

			bool input_active = ImGui::IsItemActive();
			ImVec2 input_min  = ImGui::GetItemRectMin();
			ImVec2 input_max  = ImGui::GetItemRectMax();
			ImGui::PopStyleVar(2);
			ImGui::PopStyleColor(3);

			aida::agent_picker::notify_chat_buffer_changed(g_chat_buf);
			aida::agent_picker::apply_pending_inject_to_buffer(g_chat_buf, sizeof(g_chat_buf));


			if (!input_active && g_chat_buf[0] == '\0')
			{
				float ph_y = input_min.y + input_pad;
				dl->AddText(ImVec2(input_min.x + 8.f, ph_y),
					IM_COL32(110, 105, 145, (int)(140 * a)), "Ask anything...");
			}

			{
				static float popup_alpha = 0.f;
				auto* active_profile = g_sa_settings.get_active_profile();
				std::string provider = active_profile ? active_profile->display_name : "No profile";
				std::string model    = active_profile ? active_profile->model : "No model";

				if (model.empty()) model = "Select model";
				std::string pill_text = model;

				float max_pill_w = (input_max.x - input_min.x) * 0.85f;
				ImVec2 pill_ts = ImGui::CalcTextSize(pill_text.c_str());
				if (pill_ts.x > max_pill_w) {
					while (pill_text.size() > 6) {
						pill_text.pop_back();
						std::string candidate = pill_text + "...";
						ImVec2 cts = ImGui::CalcTextSize(candidate.c_str());
						if (cts.x <= max_pill_w) {
							pill_text = candidate;
							break;
						}
					}
				}
				pill_ts = ImGui::CalcTextSize(pill_text.c_str());

				float pill_h  = 22.f;
				float pill_w  = pill_ts.x + 24.f;
				float pill_x  = input_min.x + 8.f;
				float pill_y_abs = input_max.y - pill_h - 4.f;

				ImVec2 pmin(pill_x, pill_y_abs);
				ImVec2 pmax(pill_x + pill_w, pill_y_abs + pill_h);

				bool pill_hov = ImGui::IsMouseHoveringRect(pmin, pmax);
				static float pill_ht = 0.f;
				pill_ht += ((pill_hov ? 1.f : 0.f) - pill_ht) * std::min(10.f * dt, 1.f);

				dl->AddRectFilled(pmin, pmax,
					IM_COL32(40, 38, 60, (int)((160 + 40 * pill_ht) * a)), 11.f);
				dl->AddRect(pmin, pmax,
					IM_COL32(255, 255, 255, (int)((15 + 20 * pill_ht) * a)), 11.f, 0, 0.75f);
				dl->AddText(ImVec2(pmin.x + 12.f, pmin.y + (pill_h - pill_ts.y) * 0.5f),
					IM_COL32(160, 158, 190, (int)((200 + 40 * pill_ht) * a)), pill_text.c_str());

				ImVec2 wp = ImGui::GetWindowPos();
				ImGui::SetCursorPos(ImVec2(pmin.x - wp.x, pmin.y - wp.y));
				ImGui::InvisibleButton("##model_pill", ImVec2(pill_w, pill_h));
				if (ImGui::IsItemClicked())
					ImGui::OpenPopup("##model_popup");
				if (ImGui::IsItemHovered())
					ImGui::SetTooltip("Click to change model");

				bool popup_open = ImGui::IsPopupOpen("##model_popup");
				float popup_target = popup_open ? 1.f : 0.f;
				popup_alpha += (popup_target - popup_alpha) * std::min(12.f * dt, 1.f);
				if (popup_alpha < 0.01f) popup_alpha = 0.f;

				ImGui::SetNextWindowPos(ImVec2(pmin.x, pmin.y - 6.f * std::min(popup_alpha * 2.f, 1.f)), ImGuiCond_Always, ImVec2(0.f, 1.f));
				ImGui::SetNextWindowSizeConstraints(ImVec2(260.f, 60.f), ImVec2(380.f, 400.f));
				ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 8.f);
				ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(6.f, 6.f));
				ImGui::PushStyleVar(ImGuiStyleVar_Alpha, std::min(popup_alpha * 2.f, 1.f));
				ImGui::PushStyleColor(ImGuiCol_PopupBg, ImVec4(th_ph_r/255.f, th_ph_g/255.f, th_ph_b/255.f, 0.96f));
				ImGui::PushStyleColor(ImGuiCol_Border, ImVec4(1, 1, 1, 0.08f));

				if (ImGui::BeginPopup("##model_popup", ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
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
							if (ImGui::Selectable(m.c_str(), is_sel, 0, ImVec2(260.f, 0.f))) {
								current_profile->model = m;
								g_sa_settings.sync_legacy_fields_from_active_profile();
								g_sa_settings.save();
								ImGui::CloseCurrentPopup();
							}
							if (is_sel) ImGui::PopStyleColor();
						}
					}
					ImGui::EndPopup();
				}
				ImGui::PopStyleColor(2);
				ImGui::PopStyleVar(3);
			}


			const auto& th_chat = aida::ui::resolved();
			float btn_y = input_y + input_h - btn_sz;
			float send_x = input_w + igap;

			bool ai_busy = is_ai_busy();
			static aida::ui::transition_t stop_slide;
			static bool stop_shown_prev = false;
			if (ai_busy && !stop_shown_prev) { stop_slide.start(0.180f, aida::motion::ease::out_back); stop_shown_prev = true; }
			if (!ai_busy && stop_shown_prev) { stop_slide.start_reverse(0.180f, aida::motion::ease::out_cubic); stop_shown_prev = false; }
			stop_slide.tick(dt);
			float stop_e = stop_slide.eased();

			float stop_w = btn_sz * stop_e;

			ImGui::SetCursorPos(ImVec2(send_x, btn_y));
			ImVec2 btn_min = ImGui::GetCursorScreenPos();
			ImVec2 btn_max = ImVec2(btn_min.x + btn_sz, btn_min.y + btn_sz);
			ImVec2 btn_ctr = ImVec2((btn_min.x + btn_max.x) * 0.5f, (btn_min.y + btn_max.y) * 0.5f);

			bool btn_hovered = ImGui::IsMouseHoveringRect(btn_min, btn_max);
			ImGui::InvisibleButton("##sendbtn", ImVec2(btn_sz, btn_sz));
			bool btn_clicked = ImGui::IsItemClicked();

			static aida::ui::hover_state_t s_send_hover;
			static aida::ui::press_state_t s_send_press;
			static aida::ui::flash_t       s_send_flash;
			float sh_v = s_send_hover.tick(btn_hovered, dt, aida::motion::spring::balanced);
			float sp_v = s_send_press.tick(btn_hovered && (GetAsyncKeyState(VK_LBUTTON) & 0x8000), dt);
			float sf_v = s_send_flash.tick(dt);
			if (btn_clicked) s_send_flash.trigger();

			float scl = 1.f - (1.f - 0.94f) * sp_v;
			ImVec2 cb_a(btn_min.x + (1.f - scl) * btn_sz * 0.5f, btn_min.y + (1.f - scl) * btn_sz * 0.5f);
			ImVec2 cb_b(btn_max.x - (1.f - scl) * btn_sz * 0.5f, btn_max.y - (1.f - scl) * btn_sz * 0.5f);

			dl->AddRectFilledMultiColor(cb_a, cb_b,
				aida::ui::with_alpha(th_chat.accent_grad_top, a),
				aida::ui::with_alpha(th_chat.accent_grad_top, a),
				aida::ui::with_alpha(th_chat.accent_grad_bot, a),
				aida::ui::with_alpha(th_chat.accent_grad_bot, a));
			dl->AddRect(cb_a, cb_b,
				aida::ui::with_alpha(th_chat.accent_hover, (0.5f + sh_v * 0.5f) * a), 8.f, 0, 1.f);
			if (sf_v > 0.f) {
				dl->AddRectFilled(cb_a, cb_b,
					aida::ui::with_alpha(IM_COL32(255,255,255,255), sf_v * 0.25f), 8.f);
			}

			if (g_send_icon_srv)
			{
				float icon_sz = btn_sz * 0.50f;
				float ix = btn_ctr.x - icon_sz * 0.5f;
				float iy = btn_ctr.y - icon_sz * 0.5f;
				dl->AddImage((ImTextureID)g_send_icon_srv,
					ImVec2(ix, iy), ImVec2(ix + icon_sz, iy + icon_sz),
					ImVec2(0, 0), ImVec2(1, 1),
					aida::ui::with_alpha(IM_COL32(255, 255, 255, 245), a));
			}

			if (stop_e > 0.005f) {
				float stop_x = send_x - stop_w - 6.f;
				ImGui::SetCursorPos(ImVec2(stop_x, btn_y));
				ImVec2 sb_a = ImGui::GetCursorScreenPos();
				ImVec2 sb_b(sb_a.x + stop_w, sb_a.y + btn_sz);
				bool stop_hov = ImGui::IsMouseHoveringRect(sb_a, sb_b);
				ImGui::InvisibleButton("##stopbtn", ImVec2(stop_w, btn_sz));
				bool stop_clicked = ImGui::IsItemClicked();
				static aida::ui::hover_state_t stop_h;
				float sthv = stop_h.tick(stop_hov, dt, aida::motion::spring::balanced);
				ImU32 stop_top = IM_COL32(238, 99, 109, 255);
				ImU32 stop_bot = IM_COL32(196, 51, 64, 255);
				dl->AddRectFilledMultiColor(sb_a, sb_b,
					aida::ui::with_alpha(stop_top, a * stop_e),
					aida::ui::with_alpha(stop_top, a * stop_e),
					aida::ui::with_alpha(stop_bot, a * stop_e),
					aida::ui::with_alpha(stop_bot, a * stop_e));
				dl->AddRect(sb_a, sb_b,
					aida::ui::with_alpha(IM_COL32(255,255,255,255), 0.25f * sthv * a * stop_e), 8.f, 0, 1.f);
				float sq = btn_sz * 0.30f;
				ImVec2 sqc((sb_a.x + sb_b.x) * 0.5f, (sb_a.y + sb_b.y) * 0.5f);
				dl->AddRectFilled(
					ImVec2(sqc.x - sq * 0.5f, sqc.y - sq * 0.5f),
					ImVec2(sqc.x + sq * 0.5f, sqc.y + sq * 0.5f),
					aida::ui::with_alpha(IM_COL32(255,255,255,255), a * stop_e), 1.5f);
				if (ImGui::IsItemHovered()) ImGui::SetTooltip("Stop generation");
				if (stop_clicked) chat_request_cancel();
			}

			{
				bool show_pill = false;
				static float scroll_pill_appear = 0.f;
				if (ai_busy) {
					float scr_y = chat_scroll_y_persistent;
					(void)scr_y;
					show_pill = chat_user_scrolled_up;
				}
				float pill_target = show_pill ? 1.f : 0.f;
				scroll_pill_appear += (pill_target - scroll_pill_appear) * std::min(10.f * dt, 1.f);
				if (scroll_pill_appear > 0.005f) {
					float pill_h = 28.f;
					float pill_w = 130.f;
					float pill_y_local = chat_sep_y - pill_h - 12.f;
					float pill_x_local = (cw - pill_w) * 0.5f;
					ImVec2 pa(ImGui::GetWindowPos().x + pill_x_local,
					           ImGui::GetWindowPos().y + pill_y_local);
					ImVec2 pb(pa.x + pill_w, pa.y + pill_h);
					ImGui::SetCursorPos(ImVec2(pill_x_local, pill_y_local));
					ImGui::InvisibleButton("##scroll_btm_pill", ImVec2(pill_w, pill_h));
					bool s_h = ImGui::IsItemHovered();
					bool s_c = ImGui::IsItemClicked();
					float pa_alpha = scroll_pill_appear * a;
					float ring_factor = s_h ? 0.9f : 0.6f;
					aida::ui::blur::render_drop_shadow(dl, pa, pb, pill_h * 0.5f, 3, 0.30f * pa_alpha, ImVec2(0.f, 3.f));
					dl->AddRectFilled(pa, pb,
						aida::ui::with_alpha(th_chat.panel_bg, pa_alpha), pill_h * 0.5f);
					dl->AddRect(pa, pb,
						aida::ui::with_alpha(th_chat.accent_dim, ring_factor * pa_alpha), pill_h * 0.5f, 0, 1.f);
					ImFont* sf = aida::ui::fonts::caption();
					if (!sf) sf = ImGui::GetFont();
					const char* lbl = "Jump to latest";
					ImVec2 lts = sf->CalcTextSizeA(11.f, FLT_MAX, 0.f, lbl);
					dl->AddText(sf, 11.f,
						ImVec2((pa.x + pb.x) * 0.5f - lts.x * 0.5f - 6.f,
						       (pa.y + pb.y) * 0.5f - lts.y * 0.5f),
						aida::ui::with_alpha(th_chat.text_primary, pa_alpha), lbl);
					float ax_arr = pb.x - 14.f;
					float ay_arr = (pa.y + pb.y) * 0.5f;
					dl->AddLine(ImVec2(ax_arr - 4.f, ay_arr - 2.f), ImVec2(ax_arr, ay_arr + 2.f),
						aida::ui::with_alpha(th_chat.accent_u32, pa_alpha), 1.5f);
					dl->AddLine(ImVec2(ax_arr + 4.f, ay_arr - 2.f), ImVec2(ax_arr, ay_arr + 2.f),
						aida::ui::with_alpha(th_chat.accent_u32, pa_alpha), 1.5f);
					if (s_c) g_chat_scroll_to_bottom = true;
				}
			}

			{
				bool slash_active = (g_chat_buf[0] == '/');
				size_t buf_len = strlen(g_chat_buf);
				bool slash_alone = slash_active && (buf_len <= 64);
				static float slash_alpha = 0.f;
				slash_alpha += ((slash_alone ? 1.f : 0.f) - slash_alpha) * std::min(12.f * dt, 1.f);
				if (slash_alpha > 0.01f) {
					struct slash_cmd_t { const char* name; const char* desc; const char* icon; };
					static const slash_cmd_t k_cmds[] = {
						{ "/clear",     "Clear conversation",        "*" },
						{ "/new",       "Start new chat",            "+" },
						{ "/explain",   "Explain selected code",     "?" },
						{ "/refactor",  "Refactor selected code",    "~" },
						{ "/test",      "Generate tests",            "T" },
						{ "/doc",       "Generate documentation",    "D" },
						{ "/agent",     "Switch agent",              "@" },
						{ "/settings",  "Open settings",             "G" }
					};
					std::string flt;
					for (size_t i = 1; i < buf_len; ++i) flt += (char)tolower((unsigned char)g_chat_buf[i]);

					float pop_w = std::min(cw - 16.f, 360.f);
					float row_h = 30.f;
					int show_n = 0;
					int matches[8] = {};
					for (int i = 0; i < 8; ++i) {
						std::string nm = k_cmds[i].name + 1;
						std::string nm_l;
						for (char c : nm) nm_l += (char)tolower((unsigned char)c);
						if (flt.empty() || nm_l.find(flt) != std::string::npos) {
							matches[show_n++] = i;
						}
					}
					if (show_n > 0) {
						float pop_h = row_h * show_n + 12.f;
						float pop_x = 8.f;
						float pop_y = input_y - pop_h - 6.f;
						ImVec2 pa(ImGui::GetWindowPos().x + pop_x, ImGui::GetWindowPos().y + pop_y);
						ImVec2 pb(pa.x + pop_w, pa.y + pop_h);
						aida::ui::blur::render_drop_shadow(dl, pa, pb, 10.f, 4, 0.40f * slash_alpha * a, ImVec2(0.f, 4.f));
						dl->AddRectFilled(pa, pb,
							aida::ui::with_alpha(th_chat.bg_overlay, slash_alpha * a), 10.f);
						dl->AddRect(pa, pb,
							aida::ui::with_alpha(th_chat.border_subtle, slash_alpha * a), 10.f, 0, 1.f);

						ImFont* sf = aida::ui::fonts::body();
						ImFont* csf = aida::ui::fonts::caption();
						if (!sf) sf = ImGui::GetFont();
						if (!csf) csf = ImGui::GetFont();
						for (int j = 0; j < show_n; ++j) {
							int idx = matches[j];
							ImVec2 ra(pa.x + 6.f, pa.y + 6.f + j * row_h);
							ImVec2 rb(pb.x - 6.f, ra.y + row_h - 4.f);
							bool rh = ImGui::IsMouseHoveringRect(ra, rb);
							if (rh) {
								dl->AddRectFilled(ra, rb,
									aida::ui::with_alpha(th_chat.hover_wash, slash_alpha * a), 6.f);
							}
							dl->AddCircleFilled(ImVec2(ra.x + 14.f, (ra.y + rb.y) * 0.5f), 8.f,
								aida::ui::with_alpha(th_chat.accent_dim, slash_alpha * a), 16);
							dl->AddText(sf, 11.f,
								ImVec2(ra.x + 10.f, (ra.y + rb.y) * 0.5f - 5.5f),
								aida::ui::with_alpha(th_chat.text_primary, slash_alpha * a), k_cmds[idx].icon);
							dl->AddText(sf, 13.f,
								ImVec2(ra.x + 30.f, (ra.y + rb.y) * 0.5f - 13.f),
								aida::ui::with_alpha(th_chat.text_primary, slash_alpha * a), k_cmds[idx].name);
							dl->AddText(csf, 11.f,
								ImVec2(ra.x + 30.f, (ra.y + rb.y) * 0.5f + 0.5f),
								aida::ui::with_alpha(th_chat.text_dim, slash_alpha * a), k_cmds[idx].desc);
						}
					}
				}
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


	if (settings_visible) {
		ImVec2 parent_sz = ImGui::GetWindowSize();
		ImVec2 parent_pos_screen = ImGui::GetWindowPos();
		float offset_x = (1.f - s_settings_slide) * parent_sz.x;

		{
			ImDrawList* scrim_dl = ImGui::GetWindowDrawList();
			float scrim_alpha = s_settings_slide * 0.55f;
			ImU32 scrim_col = IM_COL32(8, 10, 18, (int)(scrim_alpha * 255.f));
			scrim_dl->AddRectFilled(parent_pos_screen,
				ImVec2(parent_pos_screen.x + parent_sz.x,
					parent_pos_screen.y + parent_sz.y),
				scrim_col);
		}

		ImGui::SetCursorPos(ImVec2(offset_x, 0.f));
		ImGui::BeginChild("##settings_slide_wrap", parent_sz, false,
			ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_NoBackground);


		ImDrawList* sdl = ImGui::GetWindowDrawList();
		ImVec2 swp = ImGui::GetWindowPos();
		ImVec2 sws = ImGui::GetWindowSize();
		ImU32 settings_bg = themes::resolved.panel_bg;
		int sr = (settings_bg >> 0) & 0xFF, sg = (settings_bg >> 8) & 0xFF;
		int sb = (settings_bg >> 16) & 0xFF;
		sdl->AddRectFilled(swp, ImVec2(swp.x + sws.x, swp.y + sws.y), IM_COL32(sr, sg, sb, 255));

		render_settings_inline(parent_sz.x, parent_sz.y);
		ImGui::EndChild();
	}

	end_child();
	}

	g_render_section = "bottom_panel";
	if (bottom_h > 5.f) {
		float right_gap_bp = (right_w > 1.f) ? (right_w + gap) : 0.f;
		float bp_x = pad;
		float bp_y = content_top + total_h + gap;
		float bp_w = ww - pad * 2.f - right_gap_bp;

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

			ImGuiID ul_xid = ImGui::GetID("##bt_ul_x");
			ImGuiID ul_wid = ImGui::GetID("##bt_ul_w");
			float ul_cur_x = ImGui::GetStateStorage()->GetFloat(ul_xid, -1.f);
			float ul_cur_w = ImGui::GetStateStorage()->GetFloat(ul_wid, 0.f);
			float ul_tgt_x = -1.f, ul_tgt_w = 0.f;

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
					ul_tgt_x = btmin.x + 4.f;
					ul_tgt_w = btw - 8.f;
				}

				ImU32 btc = btact ? IM_COL32(220, 220, 235, (int)(240 * a))
				                  : IM_COL32(140, 140, 160, (int)(180 * a));
				bdl->AddText(ImVec2(btmin.x + 8.f, btmin.y + (btab_h - 2.f - bts.y) * 0.5f), btc, btab_names[bt]);

				if (bthov && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
					globals::ui::active_bottom_tab = static_cast<bottom_tab_t>(bt);

				btab_x += btw + 2.f;
			}

			if (ul_tgt_x >= 0.f) {
				if (ul_cur_x < 0.f) { ul_cur_x = ul_tgt_x; ul_cur_w = ul_tgt_w; }
				ul_cur_x += (ul_tgt_x - ul_cur_x) * std::min(14.f * dt, 1.f);
				ul_cur_w += (ul_tgt_w - ul_cur_w) * std::min(14.f * dt, 1.f);
				ImGui::GetStateStorage()->SetFloat(ul_xid, ul_cur_x);
				ImGui::GetStateStorage()->SetFloat(ul_wid, ul_cur_w);

				float ul_y = bwp.y + btab_h;
				bdl->AddLine(ImVec2(ul_cur_x - 2.f, ul_y), ImVec2(ul_cur_x + ul_cur_w + 2.f, ul_y),
					IM_COL32((int)bax, (int)bay, (int)baz, (int)(50 * a)), 4.f);
				bdl->AddLine(ImVec2(ul_cur_x, ul_y), ImVec2(ul_cur_x + ul_cur_w, ul_y),
					IM_COL32((int)bax, (int)bay, (int)baz, (int)(200 * a)), 1.5f);
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

				static bool s_term_select_all = false;

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


						if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_A, false)) {
							s_term_select_all = true;
						}

						if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_C, false)) {
							if (s_term_select_all) {
								std::string all_text;
								{
									std::lock_guard<std::mutex> lk(ts->buffer_mtx);
									for (auto& row : ts->lines) {
										for (auto& cell : row)
											all_text += cell.ch;

										while (!all_text.empty() && all_text.back() == ' ')
											all_text.pop_back();
										all_text += '\n';
									}
								}
								if (!all_text.empty())
									ImGui::SetClipboardText(all_text.c_str());
								s_term_select_all = false;
							} else {
								terminal_view::send_input(*ts, "\x03", 1);
							}
						} else {
							for (int i = 0; i < io.InputQueueCharacters.Size; i++) {
								ImWchar c = io.InputQueueCharacters[i];
								if (c >= 32 && c < 127) {
									terminal_view::send_key(*ts, static_cast<char>(c));
								}
							}
							if (ImGui::IsKeyPressed(ImGuiKey_Enter, false))
								terminal_view::send_input(*ts, "\r", 1);
							if (ImGui::IsKeyPressed(ImGuiKey_Backspace, false))
								terminal_view::send_input(*ts, "\x7f", 1);
							if (ImGui::IsKeyPressed(ImGuiKey_Tab, false))
								terminal_view::send_input(*ts, "\t", 1);
							if (ImGui::IsKeyPressed(ImGuiKey_Escape, false))
								terminal_view::send_input(*ts, "\x1b", 1);
						}


						if (ImGui::IsMouseClicked(ImGuiMouseButton_Left) ||
						    (!io.KeyCtrl && io.InputQueueCharacters.Size > 0))
							s_term_select_all = false;
					} else {
						s_term_select_all = false;
					}


					if (s_term_select_all) {
						ImVec2 wp2 = ImGui::GetWindowPos();
						ImGui::GetWindowDrawList()->AddRectFilled(
							wp2, ImVec2(wp2.x + bfw, wp2.y + bfh - log_y),
							IM_COL32((int)(bax * 0.3f), (int)(bay * 0.3f), (int)(baz * 0.3f), (int)(40 * a)));
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


				bool focused = ImGui::IsWindowFocused(ImGuiFocusedFlags_ChildWindows);
				if (focused) {
					auto& io = ImGui::GetIO();
					if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_A, false))
						output_log::select_all[tab_idx] = true;
					if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_C, false) && output_log::select_all[tab_idx]) {
						std::string all_text;
						all_text.reserve(log_lines.size() * 80);
						for (const auto& ln : log_lines) {
							all_text += ln;
							all_text += '\n';
						}
						if (!all_text.empty())
							ImGui::SetClipboardText(all_text.c_str());
					}

					if (ImGui::IsMouseClicked(ImGuiMouseButton_Left))
						output_log::select_all[tab_idx] = false;
				} else {
					output_log::select_all[tab_idx] = false;
				}

				int first = std::max(0, (int)(scroll_y / line_h) - 1);
				int last = std::min((int)log_lines.size() - 1, (int)((scroll_y + vis_h) / line_h) + 1);

				for (int li = first; li <= last; li++) {
					float ly = lorig.y + li * line_h - scroll_y;


					if (output_log::select_all[tab_idx])
						ldl->AddRectFilled(ImVec2(lorig.x, ly), ImVec2(lorig.x + bfw, ly + line_h),
							IM_COL32((int)(bax * 0.3f), (int)(bay * 0.3f), (int)(baz * 0.3f), (int)(50 * a)));
					else if (li & 1)
						ldl->AddRectFilled(ImVec2(lorig.x, ly), ImVec2(lorig.x + bfw, ly + line_h),
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

	g_render_section = "status_bar";
	{
		const auto& th_sb = aida::ui::resolved();
		ImVec2 wp = ImGui::GetWindowPos();
		ImDrawList* dl = ImGui::GetWindowDrawList();
		float sx0 = wp.x;
		float sy0 = wp.y + wh - status_h;
		float sx1 = wp.x + ww;
		float sy1 = wp.y + wh;

		ImVec2 sb_a(sx0, sy0);
		ImVec2 sb_b(sx1, sy1);
		aida::ui::blur::layer_request_t sb_req;
		sb_req.pos = sb_a;
		sb_req.size = ImVec2(ww, status_h);
		sb_req.radius = 0.f;
		sb_req.strength = 0.55f;
		sb_req.alpha = a;
		aida::ui::blur::schedule(sb_req);
		dl->AddRectFilled(sb_a, sb_b,
			aida::ui::with_alpha(th_sb.title_bar, a), 8.f, ImDrawFlags_RoundCornersBottom);
		dl->AddRectFilled(sb_a, sb_b,
			aida::ui::with_alpha(th_sb.glass_tint, a * 0.4f), 8.f, ImDrawFlags_RoundCornersBottom);
		dl->AddLine(sb_a, ImVec2(sx1, sy0),
			aida::ui::with_alpha(th_sb.border_subtle, a));

		ImFont* body = aida::ui::fonts::body();
		ImFont* cap = aida::ui::fonts::caption();
		if (!body) body = ImGui::GetFont();
		if (!cap) cap = ImGui::GetFont();
		float text_y = sy0 + (status_h - 12.f) * 0.5f;

		const float zone_pad = 12.f;
		const float chip_gap = 8.f;
		const float chip_h_v = 20.f;
		const float chip_pad_x = 8.f;
		float chip_y0 = sy0 + (status_h - chip_h_v) * 0.5f;
		float chip_y1 = chip_y0 + chip_h_v;

		float total_w = sx1 - sx0;
		float zone_w = total_w / 3.f;
		float left_x  = sx0 + zone_pad;
		float ctr_x0  = sx0 + zone_w;
		float ctr_x1  = sx0 + zone_w * 2.f;
		float right_x = sx1 - zone_pad;

		float left_clip_x = ctr_x0 - zone_pad;
		float right_clip_x0 = ctr_x1 + zone_pad;

		dl->AddLine(ImVec2(ctr_x0, sy0 + 6.f), ImVec2(ctr_x0, sy1 - 6.f),
			aida::ui::with_alpha(th_sb.border_subtle, a));
		dl->AddLine(ImVec2(ctr_x1, sy0 + 6.f), ImVec2(ctr_x1, sy1 - 6.f),
			aida::ui::with_alpha(th_sb.border_subtle, a));

		auto truncate_to_width = [&](std::string s, float max_w) -> std::string {
			if (s.empty()) return s;
			ImVec2 ts = body->CalcTextSizeA(12.f, FLT_MAX, 0.f, s.c_str());
			if (ts.x <= max_w) return s;
			const std::string ell = "...";
			while (s.size() > ell.size()) {
				s.pop_back();
				std::string candidate = s + ell;
				float cw_ = body->CalcTextSizeA(12.f, FLT_MAX, 0.f, candidate.c_str()).x;
				if (cw_ <= max_w) return candidate;
			}
			return ell;
		};

		bool has_file = (code_editor::active && !code_editor::filename.empty()) || g_disasm.file.loaded;

		{
			ImU32 dot_col = has_file ? th_sb.accent_dim : th_sb.text_dim;
			float pulse = aida::ui::clock::pulse(1.0f, 0.55f, 1.f);
			float halo_r = 4.f + pulse * 1.f;
			dl->AddCircleFilled(ImVec2(left_x + 4.f, text_y + 6.f), halo_r,
				aida::ui::with_alpha(dot_col, 0.18f * a), 16);
			dl->AddCircleFilled(ImVec2(left_x + 4.f, text_y + 6.f), 3.f,
				aida::ui::with_alpha(dot_col, a), 16);
		}

		{
			std::string info;
			if (code_editor::active && !code_editor::filename.empty()) {
				info = code_editor::filename;
				if (code_editor::dirty) info += " [modified]";
				info += "  Ln " + std::to_string(autocomplete::cursor_line + 1) +
				        ", Col " + std::to_string(autocomplete::cursor_col + 1);
			} else if (g_disasm.file.loaded) {
				info = g_disasm.file.filename + "  (" +
					std::to_string(g_disasm.file.instrs.size()) + " instructions)";
			} else {
				info = "No file open";
			}
			float info_x = left_x + 18.f;
			float info_max_w = std::max(0.f, left_clip_x - info_x);
			info = truncate_to_width(info, info_max_w);
			dl->AddText(body, 12.f, ImVec2(info_x, text_y),
				aida::ui::with_alpha(th_sb.text_secondary, a), info.c_str());
		}

		{
			std::string driver_name;
			ImU32 driver_col;
			if (driver_bridge::attached_pid() != 0) {
				driver_name = driver_bridge::attached_process_name() +
				              " (PID " + std::to_string(driver_bridge::attached_pid()) + ")";
				driver_col = th_sb.success;
			} else {
				driver_name = "Detached";
				driver_col = th_sb.warning;
			}
			float ctr_max_w = std::max(0.f, (ctr_x1 - zone_pad) - (ctr_x0 + zone_pad));
			std::string label = std::string("Driver: ") + driver_name;
			float dot_w = 10.f;
			float pill_max = std::max(0.f, ctr_max_w);
			float text_budget = pill_max - dot_w - chip_pad_x * 2.f;
			label = truncate_to_width(label, std::max(0.f, text_budget));
			ImVec2 lts = body->CalcTextSizeA(12.f, FLT_MAX, 0.f, label.c_str());
			float pill_w = lts.x + dot_w + chip_pad_x * 2.f;
			if (pill_w > pill_max) pill_w = pill_max;
			float pill_x0 = (ctr_x0 + ctr_x1) * 0.5f - pill_w * 0.5f;
			float pill_x1 = pill_x0 + pill_w;
			dl->AddRectFilled(ImVec2(pill_x0, chip_y0), ImVec2(pill_x1, chip_y1),
				aida::ui::with_alpha(driver_col, 0.14f * a), chip_h_v * 0.5f);
			dl->AddRect(ImVec2(pill_x0, chip_y0), ImVec2(pill_x1, chip_y1),
				aida::ui::with_alpha(th_sb.border_subtle, a), chip_h_v * 0.5f, 0, 1.f);
			float pulse = aida::ui::clock::pulse(1.4f, 0.4f, 1.f);
			float halo = 4.f + pulse * 1.5f;
			float dot_cx = pill_x0 + chip_pad_x + 3.f;
			float dot_cy = chip_y0 + chip_h_v * 0.5f;
			dl->AddCircleFilled(ImVec2(dot_cx, dot_cy), halo,
				aida::ui::with_alpha(driver_col, 0.18f * a), 16);
			dl->AddCircleFilled(ImVec2(dot_cx, dot_cy), 3.f,
				aida::ui::with_alpha(driver_col, a), 16);
			float text_x = pill_x0 + chip_pad_x + dot_w;
			dl->AddText(body, 12.f, ImVec2(text_x, text_y),
				aida::ui::with_alpha(driver_col, a), label.c_str());
		}

		auto* prof = g_sa_settings.get_active_profile();
		std::string model_str = prof ? (prof->display_name + " / " + prof->model) : "No model";

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

		float rx = right_x;

		auto draw_chip_rtl = [&](const std::string& raw_label, ImU32 fg, ImU32 dot_col, bool has_dot) {
			if (raw_label.empty()) return;
			if (rx <= right_clip_x0) return;
			float available = rx - right_clip_x0;
			float dot_w = has_dot ? 10.f : 0.f;
			float text_budget = available - dot_w - chip_pad_x * 2.f;
			if (text_budget <= 4.f) return;
			std::string trunc = truncate_to_width(raw_label, text_budget);
			if (trunc.empty()) return;
			ImVec2 ts = body->CalcTextSizeA(12.f, FLT_MAX, 0.f, trunc.c_str());
			float chip_w_v = ts.x + dot_w + chip_pad_x * 2.f;
			if (chip_w_v > available) chip_w_v = available;
			float cx0 = rx - chip_w_v;
			float cx1 = rx;
			dl->AddRectFilled(ImVec2(cx0, chip_y0), ImVec2(cx1, chip_y1),
				aida::ui::with_alpha(th_sb.border_subtle, a * 0.85f), chip_h_v * 0.5f);
			dl->AddRect(ImVec2(cx0, chip_y0), ImVec2(cx1, chip_y1),
				aida::ui::with_alpha(th_sb.border_subtle, a), chip_h_v * 0.5f, 0, 1.f);
			float tx = cx0 + chip_pad_x;
			if (has_dot) {
				float dcy = chip_y0 + chip_h_v * 0.5f;
				dl->AddCircleFilled(ImVec2(tx + 3.f, dcy), 3.f,
					aida::ui::with_alpha(dot_col, a), 12);
				tx += dot_w;
			}
			dl->AddText(body, 12.f, ImVec2(tx, text_y),
				aida::ui::with_alpha(fg, a), trunc.c_str());
			rx = cx0 - chip_gap;
		};

		draw_chip_rtl(model_str, th_sb.accent_dim, 0, false);
		bool editor_visible = code_editor::active && !code_editor::filename.empty();
		if (editor_visible) {
			draw_chip_rtl(lang, th_sb.text_dim, 0, false);
			draw_chip_rtl(encoding, th_sb.text_dim, 0, false);
			draw_chip_rtl(line_end, th_sb.text_dim, 0, false);
			draw_chip_rtl(indent_str, th_sb.text_dim, 0, false);
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
				ImU32 mcp_col = (connected == total) ? th_sb.success
					: (connected > 0 ? th_sb.warning : th_sb.error);
				draw_chip_rtl(mcp_buf, th_sb.text_secondary, mcp_col, true);
			}
		}

		if (cost_tracking::session_input_tokens > 0 || cost_tracking::session_output_tokens > 0) {
			static float anim_in_tokens = 0.f;
			static float anim_in_vel = 0.f;
			static float anim_out_tokens = 0.f;
			static float anim_out_vel = 0.f;
			static float anim_cost = 0.f;
			static float anim_cost_vel = 0.f;
			anim_in_tokens = aida::motion::critically_damped_step(
				anim_in_tokens, (float)cost_tracking::session_input_tokens, anim_in_vel, 0.40f, dt);
			anim_out_tokens = aida::motion::critically_damped_step(
				anim_out_tokens, (float)cost_tracking::session_output_tokens, anim_out_vel, 0.40f, dt);
			anim_cost = aida::motion::critically_damped_step(
				anim_cost, (float)cost_tracking::session_cost_usd, anim_cost_vel, 0.50f, dt);

			std::string tok_str =
				cost_tracking::format_tokens((uint64_t)anim_in_tokens) + " in / " +
				cost_tracking::format_tokens((uint64_t)anim_out_tokens) + " out";
			draw_chip_rtl(tok_str, th_sb.text_secondary, 0, false);

			if (anim_cost > 0.001f) {
				char cost_buf[32];
				snprintf(cost_buf, sizeof(cost_buf), "~$%.2f", anim_cost);
				draw_chip_rtl(cost_buf, th_sb.warning, 0, false);
			}
		}
	}

	tick_ai_chat();
	poll_ai_chat();

	g_render_section = "popups";


	g_render_section = "popups_attach_dialog";
	static int pa_open_frame = -1;
	static float pa_anim = 0.f;
	static bool pa_closing = false;
	static std::vector<driver_bridge::process_info_t> pa_proc_list;
	static float pa_refresh_timer = 0.f;
	static int pa_selected = -1;

	{
		float dt_pa = ImGui::GetIO().DeltaTime;
		float pa_target = (globals::ui::process_attach_open && !pa_closing) ? 1.f : 0.f;
		pa_anim += (pa_target - pa_anim) * (std::min)(dt_pa * 14.f, 1.f);
		if (std::abs(pa_anim - pa_target) < 0.003f) pa_anim = pa_target;

		if (pa_closing && pa_anim < 0.01f) {
			pa_closing = false;
			globals::ui::process_attach_open = false;
			pa_open_frame = -1;
			pa_anim = 0.f;
			pa_selected = -1;
			globals::ui::process_filter_buf[0] = '\0';
		}
	}

	bool pa_render = globals::ui::process_attach_open || pa_anim > 0.005f;
	if (pa_render) {
		if (pa_open_frame < 0) pa_open_frame = ImGui::GetFrameCount();

		float ax_pa = globals::ui::accent.x, ay_pa = globals::ui::accent.y, az_pa = globals::ui::accent.z;
		int ca = static_cast<int>(255.f * pa_anim);

		ImVec2 vp = ImGui::GetIO().DisplaySize;


		ImGui::GetForegroundDrawList()->AddRectFilled({0, 0}, vp,
			IM_COL32(0, 0, 0, static_cast<int>(140.f * pa_anim)));


		float pw = 620.f, ph = 490.f;
		float pa_scale = 0.96f + 0.04f * pa_anim;
		float sw = pw * pa_scale, sh = ph * pa_scale;
		float px = (vp.x - sw) * 0.5f, py = (vp.y - sh) * 0.5f;


		if (ImGui::GetFrameCount() > pa_open_frame + 1 && !pa_closing &&
			ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
			ImVec2 mp = ImGui::GetIO().MousePos;
			if (mp.x < px || mp.x > px + sw || mp.y < py || mp.y > py + sh)
				pa_closing = true;
		}


		ImGui::SetNextWindowPos({px, py});
		ImGui::SetNextWindowSize({sw, sh});
		ImGui::PushStyleColor(ImGuiCol_WindowBg, IM_COL32(20, 20, 28, static_cast<int>(252.f * pa_anim)));
		ImGui::PushStyleColor(ImGuiCol_Border, IM_COL32(65, 65, 90, static_cast<int>(160.f * pa_anim)));
		ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 10.f);
		ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));

		ImGui::Begin("##pa_popup", nullptr,
			ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove |
			ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoSavedSettings |
			ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
		{
			ImDrawList* dl = ImGui::GetWindowDrawList();
			ImVec2 wp = ImGui::GetWindowPos();
			ImVec2 ws = ImGui::GetWindowSize();


			ImDrawList* bgdl = ImGui::GetBackgroundDrawList();
			for (int si = 4; si >= 0; --si) {
				float e = static_cast<float>(si) * 5.f;
				int sa = static_cast<int>(22.f * pa_anim * (1.f - si * 0.2f));
				bgdl->AddRectFilled(ImVec2(wp.x - e, wp.y - e), ImVec2(wp.x + ws.x + e, wp.y + ws.y + e),
					IM_COL32(0, 0, 0, sa), 12.f + e);
			}


			float hdr_h = 44.f;
			dl->AddRectFilled({wp.x + 1, wp.y + 1}, {wp.x + ws.x - 1, wp.y + hdr_h},
				IM_COL32(static_cast<int>(ax_pa * 30), static_cast<int>(ay_pa * 30),
					static_cast<int>(az_pa * 30), static_cast<int>(220.f * pa_anim)),
				9.f, ImDrawFlags_RoundCornersTop);
			dl->AddLine({wp.x, wp.y + hdr_h}, {wp.x + ws.x, wp.y + hdr_h},
				IM_COL32(255, 255, 255, static_cast<int>(15.f * pa_anim)));


			dl->AddText(ImVec2(wp.x + 18.f, wp.y + (hdr_h - ImGui::GetFontSize()) * 0.5f),
				IM_COL32(225, 222, 240, ca), "Attach to Process");


			{
				float xsz = 18.f;
				float xx = wp.x + ws.x - xsz - 14.f, xy = wp.y + (hdr_h - xsz) * 0.5f;
				ImVec2 mpos = ImGui::GetIO().MousePos;
				bool x_hov = mpos.x >= xx && mpos.x <= xx + xsz && mpos.y >= xy && mpos.y <= xy + xsz;
				if (x_hov)
					dl->AddRectFilled({xx - 3, xy - 3}, {xx + xsz + 3, xy + xsz + 3},
						IM_COL32(255, 60, 60, 35), 4.f);
				float xc = xx + xsz * 0.5f, yc = xy + xsz * 0.5f;
				dl->AddLine({xc - 4, yc - 4}, {xc + 4, yc + 4}, IM_COL32(180, 180, 195, ca), 1.5f);
				dl->AddLine({xc + 4, yc - 4}, {xc - 4, yc + 4}, IM_COL32(180, 180, 195, ca), 1.5f);
				if (x_hov && ImGui::IsMouseClicked(0) && !pa_closing) pa_closing = true;
			}


			ImGui::SetCursorPos(ImVec2(1.f, hdr_h + 1.f));
			ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(14, 10));
			ImGui::BeginChild("##pa_inner", ImVec2(ws.x - 2.f, ws.y - hdr_h - 2.f), false,
				ImGuiWindowFlags_NoBackground);
			{

				ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 6.f);
				ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(10, 7));
				ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0.04f, 0.04f, 0.07f, 1.f));
				ImGui::PushStyleColor(ImGuiCol_FrameBgHovered, ImVec4(0.06f, 0.06f, 0.10f, 1.f));
				ImGui::PushStyleColor(ImGuiCol_FrameBgActive, ImVec4(0.07f, 0.07f, 0.12f, 1.f));
				ImGui::SetNextItemWidth(-1);
				ImGui::InputTextWithHint("##pa_filter", "Search processes...",
					globals::ui::process_filter_buf, sizeof(globals::ui::process_filter_buf));
				ImGui::PopStyleColor(3);
				ImGui::PopStyleVar(2);
				ImGui::Spacing();


				pa_refresh_timer -= ImGui::GetIO().DeltaTime;
				if (pa_refresh_timer <= 0.f || pa_proc_list.empty()) {
					try {
						pa_proc_list = driver_bridge::enumerate_processes();
					} catch (...) {
						OutputDebugStringA("AiDA Standalone: EXCEPTION in enumerate_processes()\n");
					}
					pa_refresh_timer = 2.f;
				}


				std::string filt(globals::ui::process_filter_buf);
				for (auto& c : filt) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));


				float list_h = ws.y - hdr_h - 108.f;

				ImGui::PushStyleColor(ImGuiCol_TableHeaderBg, ImVec4(0.05f, 0.05f, 0.09f, 1.f));
				ImGui::PushStyleColor(ImGuiCol_TableBorderLight, ImVec4(1.f, 1.f, 1.f, 0.04f));
				ImGui::PushStyleColor(ImGuiCol_TableBorderStrong, ImVec4(1.f, 1.f, 1.f, 0.06f));
				ImGui::PushStyleColor(ImGuiCol_TableRowBg, ImVec4(0, 0, 0, 0));
				ImGui::PushStyleColor(ImGuiCol_TableRowBgAlt, ImVec4(1, 1, 1, 0.012f));
				ImGui::PushStyleColor(ImGuiCol_Header, ImVec4(ax_pa * 0.2f, ay_pa * 0.2f, az_pa * 0.2f, 0.45f));
				ImGui::PushStyleColor(ImGuiCol_HeaderHovered, ImVec4(ax_pa * 0.28f, ay_pa * 0.28f, az_pa * 0.28f, 0.55f));
				ImGui::PushStyleColor(ImGuiCol_HeaderActive, ImVec4(ax_pa * 0.35f, ay_pa * 0.35f, az_pa * 0.35f, 0.65f));
				ImGui::PushStyleVar(ImGuiStyleVar_CellPadding, ImVec2(8, 5));
				ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 3.f);

				bool do_attach = false;
				if (ImGui::BeginTable("##pa_table", 3,
					ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerH |
					ImGuiTableFlags_Resizable | ImGuiTableFlags_SizingStretchProp,
					ImVec2(-1, list_h))) {

					ImGui::TableSetupScrollFreeze(0, 1);
					ImGui::TableSetupColumn("PID", ImGuiTableColumnFlags_WidthFixed, 55.f);
					ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthFixed, 175.f);
					ImGui::TableSetupColumn("Window Title", ImGuiTableColumnFlags_WidthStretch);
					ImGui::TableHeadersRow();

					for (int i = 0; i < static_cast<int>(pa_proc_list.size()); i++) {
						auto& p = pa_proc_list[i];
						if (!filt.empty()) {
							std::string nl = p.name;
							for (auto& c2 : nl) c2 = static_cast<char>(tolower(static_cast<unsigned char>(c2)));
							std::string ps = std::to_string(p.pid);
							std::string tl = p.window_title;
							for (auto& c2 : tl) c2 = static_cast<char>(tolower(static_cast<unsigned char>(c2)));
							std::string pl = p.path;
							for (auto& c2 : pl) c2 = static_cast<char>(tolower(static_cast<unsigned char>(c2)));
							if (nl.find(filt) == std::string::npos &&
								ps.find(filt) == std::string::npos &&
								tl.find(filt) == std::string::npos &&
								pl.find(filt) == std::string::npos)
								continue;
						}

						ImGui::TableNextRow();
						ImGui::TableSetColumnIndex(0);
						ImGui::PushID(i);

						bool sel = (pa_selected == i);
						if (ImGui::Selectable("##ps", sel,
							ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowOverlap,
							ImVec2(0, 20))) {
							pa_selected = i;
						}
						if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(0)) {
							pa_selected = i;
							do_attach = true;
						}

						ImGui::SameLine();
						ImGui::Text("%u", static_cast<unsigned>(p.pid));

						ImGui::TableSetColumnIndex(1);
						if (!p.window_title.empty())
							ImGui::TextColored(ImVec4(0.85f, 0.88f, 1.f, 1.f), "%s", p.name.c_str());
						else
							ImGui::TextColored(ImVec4(0.55f, 0.55f, 0.6f, 1.f), "%s", p.name.c_str());

						ImGui::TableSetColumnIndex(2);
						if (!p.window_title.empty())
							ImGui::TextColored(ImVec4(0.5f, 0.65f, 0.9f, 1.f), "%s", p.window_title.c_str());
						else if (!p.path.empty()) {
							auto slash = p.path.find_last_of("\\/");
							std::string dir = (slash != std::string::npos) ? p.path.substr(0, slash) : p.path;
							ImGui::TextColored(ImVec4(0.32f, 0.32f, 0.38f, 1.f), "%s", dir.c_str());
						}
						ImGui::PopID();
					}
					ImGui::EndTable();
				}
				ImGui::PopStyleVar(2);
				ImGui::PopStyleColor(8);

				ImGui::Spacing();


				bool can_attach = pa_selected >= 0 && pa_selected < static_cast<int>(pa_proc_list.size());
				float btn_w = 100.f, btn_h = 30.f;
				float total_btn_w = btn_w * 2.f + 12.f;
				ImGui::SetCursorPosX((ImGui::GetWindowWidth() - total_btn_w) * 0.5f);

				if (aida::ui::components::button("Attach",
					aida::ui::components::button_kind_t::primary,
					aida::ui::components::size_t_::md,
					ImVec2(btn_w, btn_h),
					!can_attach) && can_attach) {
					do_attach = true;
				}

				ImGui::SameLine(0, 12.f);
				if (aida::ui::components::button("Cancel",
					aida::ui::components::button_kind_t::secondary,
					aida::ui::components::size_t_::md,
					ImVec2(btn_w, btn_h))) {
					pa_closing = true;
				}


				if (do_attach && can_attach) {
				  try {
					auto& p = pa_proc_list[pa_selected];
					driver_bridge::debug_log("ATTACH: attempting pid=%u name=%s\n", p.pid, p.name.c_str());
					if (!driver_bridge::attach(p.pid)) {
						driver_bridge::debug_log("ATTACH: FAILED for pid=%u err=%s\n", p.pid, driver_bridge::last_error().c_str());
						output_log::push(bottom_tab_t::output,
							"[Driver] Failed to attach to PID " + std::to_string(p.pid) + ": " +
							driver_bridge::last_error() + "\n");
						pa_closing = true;
					} else {
						driver_bridge::debug_log("ATTACH: SUCCESS pid=%u, enumerating modules...\n", p.pid);
						auto modules = driver_bridge::enumerate_modules();
						driver_bridge::debug_log("ATTACH: enumerate_modules returned %llu modules\n", (unsigned long long)modules.size());
						if (!modules.empty()) {
							const auto* target_mod = &modules[0];
							for (const auto& m : modules) {
								std::string mn = m.name;
								for (auto& c : mn) c = static_cast<char>(::tolower(static_cast<unsigned char>(c)));
								std::string pn = p.name;
								for (auto& c : pn) c = static_cast<char>(::tolower(static_cast<unsigned char>(c)));
								if (mn == pn) { target_mod = &m; break; }
							}
							uint64_t mod_size = target_mod->size;
							if (mod_size == 0) mod_size = 0x100000;
							driver_bridge::debug_log("ATTACH: calling start_live pid=%u base=0x%llX size=0x%llX mod=%s\n",
								p.pid, (unsigned long long)target_mod->base, (unsigned long long)mod_size, target_mod->name.c_str());
							disasm::start_live(g_disasm, p.pid, target_mod->base, mod_size, target_mod->name);
							globals::ui::active_center_view = center_view_t::disassembly;
						} else {
							g_disasm.file = DisasmFile{};
							output_log::push(bottom_tab_t::output,
								"[Driver] Attached to PID " + std::to_string(p.pid) + " but could not enumerate modules.\n");
						}
						pa_closing = true;
					}
				  } catch (const std::exception& e) {
					char dbg[512];
					snprintf(dbg, sizeof(dbg), "AiDA Standalone: EXCEPTION in attach handler: %s\n", e.what());
					OutputDebugStringA(dbg);
					pa_closing = true;
				  } catch (...) {
					OutputDebugStringA("AiDA Standalone: UNKNOWN EXCEPTION in attach handler\n");
					pa_closing = true;
				  }
				}
			}
			ImGui::EndChild();
			ImGui::PopStyleVar();
		}
		ImGui::End();
		ImGui::PopStyleVar(2);
		ImGui::PopStyleColor(2);
	} else {
		pa_open_frame = -1;
	}


	g_render_section = "popups_driver_status";
	static int ds_open_frame = -1;
	static float ds_anim = 0.f;
	static bool ds_closing = false;

	{
		float dt_ds = ImGui::GetIO().DeltaTime;
		float ds_target = (globals::ui::driver_status_open && !ds_closing) ? 1.f : 0.f;
		ds_anim += (ds_target - ds_anim) * (std::min)(dt_ds * 14.f, 1.f);
		if (std::abs(ds_anim - ds_target) < 0.003f) ds_anim = ds_target;

		if (ds_closing && ds_anim < 0.01f) {
			ds_closing = false;
			globals::ui::driver_status_open = false;
			ds_open_frame = -1;
			ds_anim = 0.f;
		}
	}

	if (globals::ui::driver_status_open || ds_anim > 0.005f) {
		if (ds_open_frame < 0) ds_open_frame = ImGui::GetFrameCount();

		ImVec2 vp = ImGui::GetIO().DisplaySize;
		ImGui::GetForegroundDrawList()->AddRectFilled(ImVec2(0, 0), vp,
			IM_COL32(0, 0, 0, static_cast<int>(140.f * ds_anim)));

		float pw = 500.f, ph = 380.f;
		float ds_scale = 0.96f + 0.04f * ds_anim;
		float sw = pw * ds_scale, sh = ph * ds_scale;
		float px = (vp.x - sw) * 0.5f, py = (vp.y - sh) * 0.5f;

		if (ImGui::IsKeyPressed(ImGuiKey_Escape, false) && !ds_closing)
			ds_closing = true;

		if (ImGui::GetFrameCount() > ds_open_frame + 1 && !ds_closing &&
			ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
			ImVec2 mp = ImGui::GetIO().MousePos;
			if (mp.x < px || mp.x > px + sw || mp.y < py || mp.y > py + sh)
				ds_closing = true;
		}

		ImGui::SetNextWindowPos(ImVec2(px, py));
		ImGui::SetNextWindowSize(ImVec2(sw, sh));
		ImGui::SetNextWindowFocus();
		ImGui::PushStyleColor(ImGuiCol_WindowBg, IM_COL32(28, 28, 36, static_cast<int>(245.f * ds_anim)));
		ImGui::PushStyleColor(ImGuiCol_Border, IM_COL32(70, 70, 90, static_cast<int>(200.f * ds_anim)));
		ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 8.f);
		ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(12, 12));

		ImGui::Begin("Driver Status##drv_dlg", nullptr,
				ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove |
				ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoSavedSettings);
		{
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
						ImGui::BeginChild("##mod_list", ImVec2(-1, sh - 180.f));
						for (auto& m : mods) {
							ImGui::Text("0x%llX  %s", (unsigned long long)m.base, m.name.c_str());
						}
						ImGui::EndChild();
						ImGui::EndTabItem();
					}
					if (ImGui::BeginTabItem("Threads")) {
						drv_tab = 1;
						auto threads = driver_bridge::enumerate_threads();
						ImGui::BeginChild("##thr_list", ImVec2(-1, sh - 180.f));
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
				if (aida::ui::components::button("Detach",
					aida::ui::components::button_kind_t::destructive,
					aida::ui::components::size_t_::md,
					ImVec2(btn_w, 26.f))) {
					driver_bridge::detach();
				}
				ImGui::SameLine();
			}
			if (aida::ui::components::button("Close",
				aida::ui::components::button_kind_t::secondary,
				aida::ui::components::size_t_::md,
				ImVec2(btn_w, 26.f))) {
				ds_closing = true;
			}
		}
		ImGui::End();
		ImGui::PopStyleVar(2);
		ImGui::PopStyleColor(2);
	}


	static int ab_open_frame = -1;
	static float ab_anim = 0.f;
	static bool ab_closing = false;

	{
		float dt_ab = ImGui::GetIO().DeltaTime;
		float ab_target = (globals::ui::about_dialog_open && !ab_closing) ? 1.f : 0.f;
		ab_anim += (ab_target - ab_anim) * (std::min)(dt_ab * 14.f, 1.f);
		if (std::abs(ab_anim - ab_target) < 0.003f) ab_anim = ab_target;

		if (ab_closing && ab_anim < 0.01f) {
			ab_closing = false;
			globals::ui::about_dialog_open = false;
			ab_open_frame = -1;
			ab_anim = 0.f;
		}
	}

	g_render_section = "popups_about";
	if (globals::ui::about_dialog_open || ab_anim > 0.005f) {
		if (ab_open_frame < 0) ab_open_frame = ImGui::GetFrameCount();

		ImVec2 vp = ImGui::GetIO().DisplaySize;
		ImGui::GetForegroundDrawList()->AddRectFilled(ImVec2(0, 0), vp,
			IM_COL32(0, 0, 0, static_cast<int>(140.f * ab_anim)));

		float pw = 360.f, ph = 220.f;
		float ab_scale = 0.96f + 0.04f * ab_anim;
		float sw = pw * ab_scale, sh = ph * ab_scale;
		float px = (vp.x - sw) * 0.5f, py = (vp.y - sh) * 0.5f;

		if (ImGui::IsKeyPressed(ImGuiKey_Escape, false) && !ab_closing)
			ab_closing = true;

		if (ImGui::GetFrameCount() > ab_open_frame + 1 && !ab_closing &&
			ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
			ImVec2 mp = ImGui::GetIO().MousePos;
			if (mp.x < px || mp.x > px + sw || mp.y < py || mp.y > py + sh)
				ab_closing = true;
		}

		ImGui::SetNextWindowPos(ImVec2(px, py));
		ImGui::SetNextWindowSize(ImVec2(sw, sh));
		ImGui::SetNextWindowFocus();
		ImGui::PushStyleColor(ImGuiCol_WindowBg, IM_COL32(28, 28, 36, static_cast<int>(245.f * ab_anim)));
		ImGui::PushStyleColor(ImGuiCol_Border, IM_COL32(70, 70, 90, static_cast<int>(200.f * ab_anim)));
		ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 8.f);
		ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(20, 16));

		ImGui::Begin("About AiDA##about_dlg", nullptr,
				ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove |
				ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoSavedSettings);
		{
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
			if (aida::ui::components::button("OK",
				aida::ui::components::button_kind_t::primary,
				aida::ui::components::size_t_::md,
				ImVec2(80.f, 26.f))) {
				ab_closing = true;
			}
		}
		ImGui::End();
		ImGui::PopStyleVar(2);
		ImGui::PopStyleColor(2);
	}


	static int kb_open_frame = -1;
	static float kb_anim = 0.f;
	static bool kb_closing = false;

	{
		float dt_kb = ImGui::GetIO().DeltaTime;
		float kb_target = (globals::ui::shortcuts_dialog_open && !kb_closing) ? 1.f : 0.f;
		kb_anim += (kb_target - kb_anim) * (std::min)(dt_kb * 14.f, 1.f);
		if (std::abs(kb_anim - kb_target) < 0.003f) kb_anim = kb_target;

		if (kb_closing && kb_anim < 0.01f) {
			kb_closing = false;
			globals::ui::shortcuts_dialog_open = false;
			kb_open_frame = -1;
			kb_anim = 0.f;
		}
	}

	g_render_section = "popups_shortcuts";
	if (globals::ui::shortcuts_dialog_open || kb_anim > 0.005f) {
		if (kb_open_frame < 0) kb_open_frame = ImGui::GetFrameCount();

		ImVec2 vp = ImGui::GetIO().DisplaySize;
		ImGui::GetForegroundDrawList()->AddRectFilled(ImVec2(0, 0), vp,
			IM_COL32(0, 0, 0, static_cast<int>(140.f * kb_anim)));

		float pw = 500.f, ph = 440.f;
		float kb_scale = 0.96f + 0.04f * kb_anim;
		float sw = pw * kb_scale, sh = ph * kb_scale;
		float px = (vp.x - sw) * 0.5f, py = (vp.y - sh) * 0.5f;

		if (ImGui::IsKeyPressed(ImGuiKey_Escape, false) && !kb_closing)
			kb_closing = true;

		if (ImGui::GetFrameCount() > kb_open_frame + 1 && !kb_closing &&
			ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
			ImVec2 mp = ImGui::GetIO().MousePos;
			if (mp.x < px || mp.x > px + sw || mp.y < py || mp.y > py + sh)
				kb_closing = true;
		}

		ImGui::SetNextWindowPos(ImVec2(px, py));
		ImGui::SetNextWindowSize(ImVec2(sw, sh));
		ImGui::SetNextWindowFocus();
		ImGui::PushStyleColor(ImGuiCol_WindowBg, IM_COL32(28, 28, 36, static_cast<int>(245.f * kb_anim)));
		ImGui::PushStyleColor(ImGuiCol_Border, IM_COL32(70, 70, 90, static_cast<int>(200.f * kb_anim)));
		ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 8.f);
		ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(16, 12));

		ImGui::Begin("Keyboard Shortcuts##kb_dlg", nullptr,
				ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove |
				ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoSavedSettings);
		{
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
				{ "Ctrl+Shift+B", "Binary Map View" },
			};

			auto render_section = [&](const char* title, const ShortcutEntry* entries, int count) {
				ImGui::TextColored(ImVec4(0.5f, 0.5f, 0.6f, 1.f), "%s", title);
				ImGui::Separator();
				for (int i = 0; i < count; i++) {
					ImGui::Text("%-18s %s", entries[i].keys, entries[i].desc);
				}
				ImGui::Spacing();
			};

			ImGui::BeginChild("##kb_scroll", ImVec2(-1, sh - 80.f));
			render_section("General", general, 6);
			render_section("Editor", editor, 9);
			render_section("Panels", panels, 8);
			ImGui::EndChild();

			ImGui::Spacing();
			if (aida::ui::components::button("Close",
				aida::ui::components::button_kind_t::secondary,
				aida::ui::components::size_t_::md,
				ImVec2(80.f, 26.f))) {
				kb_closing = true;
			}
		}
		ImGui::End();
		ImGui::PopStyleVar(2);
		ImGui::PopStyleColor(2);
	}

	g_render_section = "popups_tool_approval";
	render_tool_approval_dialog();
	ImGui::PopStyleVar();
	ImGui::End();
	g_render_section = "done";
}
