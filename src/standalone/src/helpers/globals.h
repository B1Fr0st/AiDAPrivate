#pragma once
#include "imgui/imgui_internal.h"
#include "../core/standalone_license.hpp"
#include "../core/terminal_view.hpp"
#include "../core/workspace_search.hpp"
#include <iostream>
#include <d3d11.h>
#include <string>
#include <vector>
#include <deque>
#include <cstdint>
#include <functional>


enum class center_view_t : int {
	code_editor = 0,
	disassembly,
	hex_view,
	welcome,
	settings_view
};


enum class activity_item_t : int {
	explorer = 0,
	search,
	debug,
	extensions,
	settings,
	COUNT
};

enum class bottom_tab_t : int {
	output = 0,
	mcp_log,
	driver_log,
	sandbox_log,
	terminal,
	COUNT
};


namespace output_log {
	inline std::deque<std::string> lines[static_cast<int>(bottom_tab_t::COUNT)];
	inline constexpr size_t MAX_LINES = 4096;
	inline bool auto_scroll[static_cast<int>(bottom_tab_t::COUNT)] = { true, true, true, true, true };

	inline void push(bottom_tab_t tab, const std::string& line) {
		if (tab == bottom_tab_t::terminal) return;
		auto& q = lines[static_cast<int>(tab)];
		q.push_back(line);
		if (q.size() > MAX_LINES) q.pop_front();
	}
	inline void clear(bottom_tab_t tab) {
		lines[static_cast<int>(tab)].clear();
	}
}


namespace menu_bar {
	inline int  open_menu = -1;
	inline bool any_open  = false;
}


struct ChatMessage {
	std::string text;
	std::string thinking_text;
	bool is_user = false;
	bool has_thinking = false;
	bool streaming = false;
	int64_t timestamp = 0;
	int input_tokens = 0;
	int output_tokens = 0;
	int cache_read_tokens = 0;
	int cache_write_tokens = 0;
};

inline bool  g_dummy_triggered = false;
inline float g_think_timer = 0.f;
inline bool  g_think_done = false;

inline std::vector<ChatMessage> g_chat_messages;
inline char                     g_chat_buf[4096] = {};
inline bool                     g_chat_scroll_to_bottom = false;
inline float g_chat_demo_timer = 0.f;
inline int   g_chat_demo_stage = 0;


namespace chat_edit {
	inline bool  active = false;
	inline int   msg_idx = -1;
	inline char  buf[4096] = {};
}

struct ConversationSummary {
	std::string id;
	std::string title;
	int64_t     created = 0;
	int         msg_count = 0;
};

namespace conversations {
	inline std::vector<ConversationSummary> history;
	inline std::string current_id;
	inline bool browser_open = false;

	std::string get_storage_dir();
	void save_current();
	void load_conversation(const std::string& id);
	void new_chat();
	void refresh_history();
	void delete_conversation(const std::string& id);
}


void tick_ai_chat();
void poll_ai_chat();
void render_settings_inline(float panel_w, float panel_h);
extern bool g_settings_open;

inline ImFont* g_code_font = nullptr;


namespace license
{
	inline bool  validated       = false;
	inline bool  checking        = false;
	inline bool  check_failed    = false;
	inline char  key_buf[128]    = {};
	inline std::string error_msg;
	inline std::string saved_key;
}


struct FileBrowserEntry {
	std::string name;
	std::string full_path;
	bool        is_dir     = false;
	bool        expanded   = false;
	int         depth      = 0;
};

namespace file_browser
{
	inline std::vector<FileBrowserEntry> entries;
	inline std::string                   current_dir;
	inline int                           selected_idx = -1;
	inline bool                          needs_refresh = true;
	inline char                          path_buf[512] = {};

	void refresh(const std::string& dir = "");
	void toggle_dir(int idx);
	void open_file(int idx);
}


namespace code_editor_widget { void on_text_changed(); }

namespace code_editor
{
	inline std::vector<char> buffer;
	inline std::string filename;
	inline std::string filepath;
	inline bool        active = false;
	inline bool        dirty  = false;
	inline float       scroll_y = 0.f;


	inline void load(const std::string& content, const std::string& fname, const std::string& fpath) {
		buffer.resize(content.size() + 1024 * 64);
		memcpy(buffer.data(), content.c_str(), content.size());
		buffer[content.size()] = '\0';
		filename = fname;
		filepath = fpath;
		active = true;
		dirty = false;
		scroll_y = 0.f;
		code_editor_widget::on_text_changed();
	}


	inline std::string get_content() {
		if (buffer.empty()) return {};
		return std::string(buffer.data());
	}


	inline bool save() {
		if (filepath.empty() || buffer.empty()) return false;


		if (!standalone_license::is_valid()) return false;


		{
			uint64_t gt = standalone_license::inline_gate_check(
				standalone_license::gate_editor_save);
			if (standalone_license::verify_gate_token(
					standalone_license::gate_editor_save, gt) < 0.5)
				return false;
		}

		FILE* f = nullptr;
		fopen_s(&f, filepath.c_str(), "wb");
		if (!f) return false;
		size_t len = strlen(buffer.data());
		fwrite(buffer.data(), 1, len, f);
		fclose(f);
		dirty = false;
		return true;
	}
}


struct ThemePreset {
	const char* name;
	ImVec4      accent;
	ImU32       bg_base;
	ImU32       panel_bg;
	ImU32       panel_header;
	ImU32       title_bar;
	ImU32       text_primary;
	ImU32       text_secondary;
	ImU32       text_dim;
	DWORD       acrylic_color;
};

namespace themes
{
	inline const ThemePreset presets[] = {

		{ "Midnight",
		  ImVec4(134.f/255.f, 135.f/255.f, 254.f/255.f, 1.f),
		  IM_COL32(4, 8, 30, 235),
		  IM_COL32(22, 22, 28, 210),
		  IM_COL32(34, 34, 44, 230),
		  IM_COL32(16, 16, 22, 230),
		  IM_COL32(230, 228, 255, 240),
		  IM_COL32(170, 175, 190, 200),
		  IM_COL32(110, 105, 145, 140),
		  (DWORD)((5) | (12 << 8) | (65 << 16) | (0x70 << 24))
		},

		{ "Cyberpunk",
		  ImVec4(1.0f, 0.2f, 0.6f, 1.f),
		  IM_COL32(10, 2, 15, 235),
		  IM_COL32(18, 8, 22, 215),
		  IM_COL32(35, 12, 40, 235),
		  IM_COL32(20, 5, 25, 235),
		  IM_COL32(255, 230, 245, 245),
		  IM_COL32(200, 160, 190, 200),
		  IM_COL32(140, 80, 120, 140),
		  (DWORD)((15) | (2 << 8) | (30 << 16) | (0x70 << 24))
		},

		{ "Nord",
		  ImVec4(136.f/255.f, 192.f/255.f, 208.f/255.f, 1.f),
		  IM_COL32(6, 12, 18, 235),
		  IM_COL32(22, 28, 34, 210),
		  IM_COL32(30, 40, 50, 230),
		  IM_COL32(16, 22, 28, 230),
		  IM_COL32(216, 222, 233, 240),
		  IM_COL32(160, 180, 200, 200),
		  IM_COL32(100, 120, 145, 140),
		  (DWORD)((8) | (18 << 8) | (35 << 16) | (0x70 << 24))
		},

		{ "Monokai",
		  ImVec4(166.f/255.f, 226.f/255.f, 46.f/255.f, 1.f),
		  IM_COL32(12, 10, 6, 235),
		  IM_COL32(30, 28, 22, 210),
		  IM_COL32(42, 40, 32, 230),
		  IM_COL32(22, 20, 14, 230),
		  IM_COL32(248, 248, 242, 240),
		  IM_COL32(190, 190, 180, 200),
		  IM_COL32(117, 113, 94, 140),
		  (DWORD)((10) | (8 << 8) | (4 << 16) | (0x70 << 24))
		},

		{ "Dracula",
		  ImVec4(189.f/255.f, 147.f/255.f, 249.f/255.f, 1.f),
		  IM_COL32(10, 6, 18, 235),
		  IM_COL32(28, 24, 38, 210),
		  IM_COL32(40, 36, 54, 230),
		  IM_COL32(18, 14, 28, 230),
		  IM_COL32(248, 248, 242, 240),
		  IM_COL32(200, 190, 220, 200),
		  IM_COL32(130, 120, 160, 140),
		  (DWORD)((12) | (6 << 8) | (28 << 16) | (0x70 << 24))
		},

		{ "Solarized",
		  ImVec4(38.f/255.f, 139.f/255.f, 210.f/255.f, 1.f),
		  IM_COL32(0, 12, 16, 235),
		  IM_COL32(0, 28, 36, 210),
		  IM_COL32(4, 40, 50, 230),
		  IM_COL32(0, 20, 28, 230),
		  IM_COL32(238, 232, 213, 240),
		  IM_COL32(147, 161, 161, 200),
		  IM_COL32(88, 110, 117, 140),
		  (DWORD)((0) | (14 << 8) | (22 << 16) | (0x70 << 24))
		},

		{ "Blood",
		  ImVec4(0.85f, 0.12f, 0.12f, 1.f),
		  IM_COL32(18, 4, 4, 235),
		  IM_COL32(28, 14, 14, 210),
		  IM_COL32(42, 18, 18, 230),
		  IM_COL32(22, 8, 8, 230),
		  IM_COL32(255, 230, 230, 240),
		  IM_COL32(200, 165, 165, 200),
		  IM_COL32(140, 90, 90, 140),
		  (DWORD)((25) | (4 << 8) | (4 << 16) | (0x70 << 24))
		},
	};
	inline constexpr int count = sizeof(presets) / sizeof(presets[0]);
	inline int active = 0;
	inline bool changed = true;
	inline ThemePreset resolved = {};
	inline char resolved_name_buf[128] = {};
}

namespace globals
{

	inline ID3D11ShaderResourceView* bullet_srv = nullptr;


	inline terminal_view::TerminalManager terminal_mgr;

	namespace ui
	{
		inline ImVec4 accent = ImVec4(134.f / 255.f, 135.f / 255.f, 254.f / 255.f, 1.f);


		inline float load_timer = 0.f;
		inline float window_w = 250;
		inline float window_h = 200;
		inline float ui_alpha = 0.f;
		inline bool test = false;

		inline float test2 = 0.0f;


		inline float panel_left_w  = 220.f;
		inline float panel_right_w = 350.f;
		inline float panel_bottom_h = 180.f;

		inline bool  panel_left_visible   = true;
		inline bool  panel_right_visible  = true;
		inline bool  panel_bottom_visible = false;

		inline bool  dragging_left_splitter  = false;
		inline bool  dragging_right_splitter = false;
		inline bool  dragging_bottom_splitter = false;

		inline bottom_tab_t active_bottom_tab = bottom_tab_t::output;


		inline activity_item_t active_activity = activity_item_t::explorer;
		inline constexpr float activity_bar_w = 48.f;

		inline center_view_t active_center_view = center_view_t::welcome;


		inline bool command_palette_open = false;
		inline char command_palette_buf[128] = {};


		inline bool process_attach_open = false;
		inline char process_filter_buf[128] = {};


		inline bool driver_status_open = false;


		inline bool shortcuts_dialog_open = false;


		inline bool find_bar_open = false;
		inline char find_buf[256] = {};
		inline char replace_buf[256] = {};
		inline bool find_case_sensitive = false;
		inline bool find_whole_word = false;
		inline bool find_regex = false;
		inline bool find_show_replace = false;
		inline int  find_match_count = 0;
		inline int  find_current_match = -1;
		inline std::vector<int> find_match_positions;


		inline bool mcp_servers_dialog_open = false;


		inline bool about_dialog_open = false;


		inline bool  ctx_menu_open = false;
		inline ImVec2 ctx_menu_pos = ImVec2(0, 0);
		inline int    ctx_menu_target = -1;
		enum class ctx_menu_source_t { none, file_browser, code_editor, chat_message };
		inline ctx_menu_source_t ctx_menu_source = ctx_menu_source_t::none;


		inline bool        ghost_text_active = false;
		inline std::string ghost_text_suggestion;
		inline int         ghost_text_cursor_pos = -1;
		inline float       ghost_text_timer = 0.f;
		inline bool        ghost_text_requesting = false;


		inline std::vector<std::string> breadcrumb_segments;
		inline bool breadcrumb_dropdown_open = false;
		inline int  breadcrumb_dropdown_idx = -1;


		inline std::string current_language = "Plain Text";
		inline std::string current_encoding = "UTF-8";
		inline std::string current_line_ending = "CRLF";
		inline std::string current_indent = "Spaces: 4";


		inline bool tool_approval_pending = false;
		inline std::string tool_approval_name;
		inline std::string tool_approval_args;
		inline std::function<void(bool)> tool_approval_callback;


		inline std::string status_file_info;
		inline std::string status_driver_info;
		inline std::string status_model_info;

		inline int theme = 0;

		inline bool is_moving = false;

		inline int welcome_set = -1;
		inline float welcome_timer = 0.f;
		inline float welcome_alpha = 0.f;
		inline float welcome_text_y_offset = 30.f;
		inline bool welcome_done = false;


		inline bool  maximized = false;
		inline float pre_max_x = 0.f;
		inline float pre_max_y = 0.f;
		inline float pre_max_w = 1200.f;
		inline float pre_max_h = 700.f;
	}


}


struct CustomThemeData {
	std::string name = "Custom Theme";
	float accent[3] = { 0.53f, 0.53f, 1.0f };
	ImU32 bg_base      = IM_COL32(4, 8, 30, 235);
	ImU32 panel_bg     = IM_COL32(22, 22, 28, 210);
	ImU32 panel_header = IM_COL32(34, 34, 44, 230);
	ImU32 title_bar    = IM_COL32(16, 16, 22, 230);
	ImU32 text_primary   = IM_COL32(230, 228, 255, 240);
	ImU32 text_secondary = IM_COL32(170, 175, 190, 200);
	ImU32 text_dim       = IM_COL32(110, 105, 145, 140);
	DWORD acrylic_color  = (DWORD)((5) | (12 << 8) | (65 << 16) | (0x70 << 24));
	int   icon_index     = 3;
	std::string icon_file_path;
};

namespace custom_themes {
	inline std::vector<CustomThemeData> list;
	inline int  active_custom = -1;
	inline bool editor_open   = false;
	inline int  editing_idx   = -1;
	inline CustomThemeData editing_copy;
}


namespace autocomplete {
	inline bool enabled       = true;
	inline bool popup_visible = false;
	inline int  selected      = 0;
	inline int  cursor_byte   = 0;
	inline int  cursor_line   = 0;
	inline int  cursor_col    = 0;
	inline std::string partial;
	inline std::vector<std::string> matches;

	inline const std::vector<std::string>& keywords() {
		static const std::vector<std::string> kw = {
			"alignas","alignof","auto","bool","break","case","catch","char",
			"char16_t","char32_t","class","const","constexpr","continue",
			"decltype","default","delete","do","double","dynamic_cast","else",
			"enum","explicit","extern","false","float","for","friend","goto",
			"if","inline","int","long","mutable","namespace","new","noexcept",
			"nullptr","operator","override","private","protected","public",
			"register","reinterpret_cast","requires","return","short","signed",
			"sizeof","static","static_assert","static_cast","struct","switch",
			"template","this","thread_local","throw","true","try","typedef",
			"typeid","typename","union","unsigned","using","virtual","void",
			"volatile","wchar_t","while",

			"int8_t","int16_t","int32_t","int64_t","uint8_t","uint16_t",
			"uint32_t","uint64_t","size_t","uintptr_t","intptr_t","ptrdiff_t",
			"string","vector","map","unordered_map","set","unordered_set",
			"array","deque","list","pair","tuple","shared_ptr","unique_ptr",
			"optional","variant","any","function","thread","mutex","atomic",

			"printf","sprintf","snprintf","fprintf","memcpy","memset","memmove",
			"strlen","strcmp","strncmp","strcpy","strncpy","malloc","calloc",
			"realloc","free",

			"DWORD","HANDLE","HMODULE","LPVOID","LPCSTR","LPCWSTR","BOOL",
			"INVALID_HANDLE_VALUE","CreateFile","ReadFile","WriteFile",
			"CloseHandle","GetLastError","VirtualAlloc","VirtualFree",
			"VirtualProtect","LoadLibrary","GetProcAddress","FreeLibrary",
			"CreateThread","WaitForSingleObject","TerminateProcess",
			"CreateProcess","OpenProcess","ReadProcessMemory","WriteProcessMemory",

			"IMAGE_DOS_HEADER","IMAGE_NT_HEADERS","IMAGE_SECTION_HEADER",
			"IMAGE_IMPORT_DESCRIPTOR","IMAGE_EXPORT_DIRECTORY",
			"PIMAGE_DOS_HEADER","PIMAGE_NT_HEADERS",
			"RtlInitUnicodeString","ZwQuerySystemInformation",
			"NtQueryInformationProcess","PsLookupProcessByProcessId",
		};
		return kw;
	}

	inline void find_matches(const std::string& prefix) {
		matches.clear();
		if (prefix.size() < 2) return;
		std::string lp = prefix;
		for (auto& c : lp) c = (char)tolower((unsigned char)c);
		for (auto& kw : keywords()) {
			std::string lk = kw;
			for (auto& c : lk) c = (char)tolower((unsigned char)c);
			if (lk.size() >= lp.size() && lk.substr(0, lp.size()) == lp && lk != lp) {
				matches.push_back(kw);
				if (matches.size() >= 10) break;
			}
		}
		selected = 0;
	}
}


namespace editor_config {
	inline int   tab_size               = 4;
	inline bool  show_line_numbers      = true;
	inline float font_size              = 14.0f;
	inline bool  auto_complete          = true;
	inline bool  highlight_current_line = true;
	inline bool  word_wrap              = false;
	inline bool  minimap                = false;
	inline bool  bracket_match          = true;
}


namespace cost_tracking {
	inline int64_t session_input_tokens   = 0;
	inline int64_t session_output_tokens  = 0;
	inline int64_t session_cache_read     = 0;
	inline int64_t session_cache_write    = 0;
	inline int64_t session_thinking_tokens = 0;
	inline double  session_cost_usd       = 0.0;
	inline int     session_request_count  = 0;

	inline void reset() {
		session_input_tokens = session_output_tokens = 0;
		session_cache_read = session_cache_write = 0;
		session_thinking_tokens = 0;
		session_cost_usd = 0.0;
		session_request_count = 0;
	}

	inline double estimate_cost(const std::string& model, int64_t in_tok, int64_t out_tok,
	                            int64_t cache_read = 0, int64_t cache_write = 0) {

		double in_price = 3.0, out_price = 15.0;
		double cache_read_price = 0.30, cache_write_price = 3.75;
		if (model.find("opus") != std::string::npos || model.find("gpt-5") != std::string::npos) {
			in_price = 15.0; out_price = 75.0; cache_read_price = 1.50; cache_write_price = 18.75;
		} else if (model.find("sonnet-4") != std::string::npos || model.find("gpt-4.1") != std::string::npos ||
		           model.find("4o") != std::string::npos) {
			in_price = 3.0; out_price = 15.0; cache_read_price = 0.30; cache_write_price = 3.75;
		} else if (model.find("mini") != std::string::npos || model.find("flash") != std::string::npos ||
		           model.find("nano") != std::string::npos || model.find("haiku") != std::string::npos) {
			in_price = 0.25; out_price = 1.25; cache_read_price = 0.025; cache_write_price = 0.30;
		} else if (model.find("gemini") != std::string::npos && model.find("pro") != std::string::npos) {
			in_price = 1.25; out_price = 10.0; cache_read_price = 0.315; cache_write_price = 4.50;
		} else if (model.find("local") != std::string::npos || model.find("llama") != std::string::npos ||
		           model.find("ollama") != std::string::npos || model.find("127.0.0.1") != std::string::npos) {
			return 0.0;
		}
		return (in_tok * in_price + out_tok * out_price +
		        cache_read * cache_read_price + cache_write * cache_write_price) / 1000000.0;
	}

	inline std::string format_tokens(int64_t count) {
		if (count >= 1000000) return std::to_string(count / 1000000) + "." + std::to_string((count % 1000000) / 100000) + "M";
		if (count >= 1000) return std::to_string(count / 1000) + "." + std::to_string((count % 1000) / 100) + "K";
		return std::to_string(count);
	}
}


struct OpenTab {
	std::string filename;
	std::string filepath;
	bool dirty  = false;
};

namespace file_tabs {
	inline std::vector<OpenTab> tabs;
	inline int active_tab = -1;
	inline int  pending_close_idx = -1;
	inline bool show_close_confirm = false;
	inline float close_confirm_anim = 0.f;
	inline int   close_confirm_hovered = -1;

	inline void open_or_focus(const std::string& fpath, const std::string& fname,
	                          const std::string& content) {
		for (int i = 0; i < (int)tabs.size(); i++) {
			if (tabs[i].filepath == fpath) {
				active_tab = i;
				code_editor::load(content, fname, fpath);
				return;
			}
		}
		OpenTab t;
		t.filename = fname;
		t.filepath = fpath;
		tabs.push_back(std::move(t));
		active_tab = (int)tabs.size() - 1;
		code_editor::load(content, fname, fpath);
	}

	inline void close_tab(int idx) {
		if (idx < 0 || idx >= (int)tabs.size()) return;
		tabs.erase(tabs.begin() + idx);
		if (active_tab >= (int)tabs.size()) active_tab = (int)tabs.size() - 1;
		if (active_tab >= 0 && active_tab < (int)tabs.size()) {
			auto& t = tabs[active_tab];
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
		} else {
			code_editor::active = false;
			code_editor::buffer.clear();
			code_editor::filename.clear();
			code_editor::filepath.clear();
		}
	}
}


namespace marketplace_ui
{
	inline char  search_buf[256] = {};
	inline int   selected_idx = -1;
	inline int   active_tab = 0;
	inline bool  show_detail = false;
	inline int   registry_idx = 0;
}
