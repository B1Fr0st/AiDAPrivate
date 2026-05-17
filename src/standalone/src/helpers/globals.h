#pragma once
#include "imgui/imgui_internal.h"
#include "standalone_license.hpp"
#include "terminal_view.hpp"
#include "workspace_search.hpp"
#include "work_queue.hpp"
#include <iostream>
#include <d3d11.h>
#include <string>
#include <vector>
#include <deque>
#include <cstdint>
#include <cstring>
#include <functional>
#include <atomic>
#include <mutex>
#include <chrono>
#include <unordered_map>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <system_error>
#include <shlobj.h>
#include <objbase.h>


enum class center_view_t : int {
	code_editor = 0,
	disassembly,
	hex_view,
	welcome,
	settings_view,
	network_view,
	memory_scanner,
	debugger_view,
	pseudocode,
	struct_recon,
	crypto_scanner,
	aob_generator,
	fuzzer_view,
	xref_browser,
	snapshot_diff,
	pointer_scanner,
	decrypt_oracle,
	integrity_hunter,
	symbolic_view,
	taint_view,
	deobfuscation_view,
	stealth_view,
	scan_hub,
	types_hub,
	analysis_hub,
	binary_map,
	graph_view,
	image_view
};


enum class activity_item_t : int {
	explorer = 0,
	search,
	recent,
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
	inline bool select_all[static_cast<int>(bottom_tab_t::COUNT)] = { false, false, false, false, false };

	inline void push(bottom_tab_t tab, const std::string& line) {
		if (tab == bottom_tab_t::terminal) return;
		auto& q = lines[static_cast<int>(tab)];
		q.push_back(line);
		if (q.size() > MAX_LINES) q.pop_front();
	}
	inline void clear(bottom_tab_t tab) {
		lines[static_cast<int>(tab)].clear();
		select_all[static_cast<int>(tab)] = false;
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


	bool is_summary = false;
	std::string condense_id;
	std::string condense_parent;
	bool is_truncation_marker = false;
	std::string truncation_id;
	std::string truncation_parent;


	double cost = 0.0;


	std::string tool_name;
	bool is_tool_result = false;


	std::string model_id;
};

inline bool  g_ai_thinking_active = false;

inline std::vector<ChatMessage> g_chat_messages;
inline char                     g_chat_buf[4096] = {};
inline bool                     g_chat_scroll_to_bottom = false;

namespace chat_inject {

	inline std::mutex&        queue_mutex() { static std::mutex m; return m; }
	inline std::deque<std::string>& queue()       { static std::deque<std::string> q; return q; }

	inline void post(const std::string& text)
	{
		if (text.empty()) return;
		std::lock_guard<std::mutex> lk(queue_mutex());
		queue().push_back(text);
	}

	inline bool drain_into_buffer()
	{
		std::deque<std::string> local;
		{
			std::lock_guard<std::mutex> lk(queue_mutex());
			if (queue().empty()) return false;
			local.swap(queue());
		}

		const size_t cap = sizeof(g_chat_buf) - 1u;
		bool any_appended = false;
		for (const auto& text : local) {
			if (text.empty()) continue;
			size_t cur = std::strlen(g_chat_buf);
			if (cur + text.size() >= cap) continue;
			if (cur > 0 && cur + 2u < cap) {
				g_chat_buf[cur] = '\n';
				g_chat_buf[cur + 1u] = '\n';
				g_chat_buf[cur + 2u] = '\0';
				cur += 2u;
			}
			const size_t room = cap - cur;
			const size_t copy = (text.size() < room) ? text.size() : room;
			std::memcpy(g_chat_buf + cur, text.data(), copy);
			g_chat_buf[cur + copy] = '\0';
			any_appended = true;
		}
		return any_appended;
	}

}


inline std::vector<const ChatMessage*> get_effective_api_history()
{
	std::vector<const ChatMessage*> result;
	for (const auto& msg : g_chat_messages) {

		if (!msg.condense_parent.empty()) continue;

		if (!msg.truncation_parent.empty()) continue;
		result.push_back(&msg);
	}
	return result;
}


namespace chat_edit {
	inline bool  active = false;
	inline int   msg_idx = -1;
	inline char  buf[4096] = {};
}

namespace chat_select_popup {
	inline bool        open = false;
	inline std::string text;
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

	inline std::string                   pending_open_path;
	inline std::string                   pending_open_filename;
	inline bool                          pending_open_modal_visible = false;
	inline bool                          pending_open_should_open   = false;

	void refresh(const std::string& dir = "");
	void toggle_dir(int idx);
	void open_file(int idx);
	void open_path(const std::string& path);
	void render_pending_confirm_modal();
	void record_recent_workspace(const std::string& path);
	void tick_watcher();
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


	inline bool save();
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

		{ "AiDA Dark",
		  ImVec4(56.f/255.f, 134.f/255.f, 240.f/255.f, 1.f),
		  IM_COL32(10, 14, 26, 235),
		  IM_COL32(15, 21, 38, 214),
		  IM_COL32(26, 35, 60, 232),
		  IM_COL32(12, 17, 31, 232),
		  IM_COL32(226, 234, 250, 242),
		  IM_COL32(158, 174, 206, 206),
		  IM_COL32(108, 124, 160, 182),
		  (DWORD)((10) | (17 << 8) | (44 << 16) | (0x7A << 24))
		},

		{ "AiDA Light",
		  ImVec4(42.f/255.f, 104.f/255.f, 216.f/255.f, 1.f),
		  IM_COL32(244, 246, 251, 250),
		  IM_COL32(251, 252, 255, 232),
		  IM_COL32(231, 237, 248, 234),
		  IM_COL32(231, 237, 248, 232),
		  IM_COL32(22, 28, 44, 252),
		  IM_COL32(78, 92, 122, 232),
		  IM_COL32(140, 152, 178, 220),
		  (DWORD)((240) | (244 << 8) | (251 << 16) | (0xA8 << 24))
		},

		{ "Claude Dark",
		  ImVec4(0xF4/255.f, 0x84/255.f, 0x5F/255.f, 1.f),
		  IM_COL32(0x26, 0x26, 0x24, 235),
		  IM_COL32(0x26, 0x26, 0x24, 222),
		  IM_COL32(0x1E, 0x1E, 0x1C, 232),
		  IM_COL32(0x1A, 0x1A, 0x18, 232),
		  IM_COL32(0xE8, 0xE4, 0xDC, 242),
		  IM_COL32(0xB8, 0xB1, 0xA4, 218),
		  IM_COL32(0x88, 0x88, 0x88, 200),
		  (DWORD)((0x1A) | (0x1A << 8) | (0x18 << 16) | (0x84 << 24))
		},

		{ "Claude Light",
		  ImVec4(0xC1/255.f, 0x5F/255.f, 0x3C/255.f, 1.f),
		  IM_COL32(0xF4, 0xF3, 0xEE, 250),
		  IM_COL32(0xFA, 0xF9, 0xF5, 232),
		  IM_COL32(0xE9, 0xEC, 0xEC, 234),
		  IM_COL32(0xE9, 0xEC, 0xEC, 232),
		  IM_COL32(0x1F, 0x1E, 0x1D, 252),
		  IM_COL32(0x6F, 0x6F, 0x78, 232),
		  IM_COL32(0xB1, 0xAD, 0xA1, 220),
		  (DWORD)((0xEE) | (0xF3 << 8) | (0xF4 << 16) | (0xA8 << 24))
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
		inline std::atomic<bool>* bg_init_done = nullptr;
		inline std::atomic<int>  bg_init_step{0};
		inline std::atomic<int>  bg_init_total{6};
		inline std::atomic<int>  arc_unseal_phase{0};
		inline std::atomic<int>  license_activation_phase{0};
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
		inline constexpr float activity_bar_w = 56.f;

		inline center_view_t active_center_view = center_view_t::welcome;


		inline std::atomic<bool>     decompile_popup_active{false};
		inline std::atomic<uint64_t> decompile_popup_addr{0};
		inline std::atomic<int>      decompile_popup_anim_frame{0};


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


		inline float dpi_scale = 1.0f;

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
	inline int   tab_size                  = 4;
	inline bool  show_line_numbers         = true;
	inline float font_size                 = 14.0f;
	inline bool  auto_complete             = true;
	inline bool  highlight_current_line    = true;
	inline bool  word_wrap                 = false;
	inline bool  minimap                   = true;
	inline bool  bracket_match             = true;
	inline bool  disasm_full_line_select   = false;
}


namespace cost_tracking {
	inline int64_t session_input_tokens   = 0;
	inline int64_t session_output_tokens  = 0;
	inline int64_t session_cache_read     = 0;
	inline int64_t session_cache_write    = 0;
	inline int64_t session_thinking_tokens = 0;
	inline double  session_cost_usd       = 0.0;
	inline int     session_request_count  = 0;
	inline std::string session_provider;

	inline void reset() {
		session_input_tokens = session_output_tokens = 0;
		session_cache_read = session_cache_write = 0;
		session_thinking_tokens = 0;
		session_cost_usd = 0.0;
		session_request_count = 0;
		session_provider.clear();
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

	inline void accumulate(const std::string& model, int64_t in_tok, int64_t out_tok,
	                        int64_t cache_read = 0, int64_t cache_write = 0, int64_t thinking = 0) {
		session_input_tokens += in_tok;
		session_output_tokens += out_tok;
		session_cache_read += cache_read;
		session_cache_write += cache_write;
		session_thinking_tokens += thinking;
		session_cost_usd += estimate_cost(model, in_tok, out_tok, cache_read, cache_write);
		++session_request_count;
	}

	inline std::string format_tokens(int64_t count) {
		if (count >= 1000000) return std::to_string(count / 1000000) + "." + std::to_string((count % 1000000) / 100000) + "M";
		if (count >= 1000) return std::to_string(count / 1000) + "." + std::to_string((count % 1000) / 100) + "K";
		return std::to_string(count);
	}

	inline std::string format_cost() {
		char buf[32];
		snprintf(buf, sizeof(buf), "$%.4f", session_cost_usd);
		return buf;
	}
}


struct OpenTab {
	std::string filename;
	std::string filepath;
	std::string buffer;
	bool        buffer_loaded = false;
	bool        dirty          = false;
};

namespace file_tabs {
	inline std::vector<OpenTab> tabs;
	inline int active_tab = -1;
	inline int  pending_close_idx = -1;
	inline bool show_close_confirm = false;
	inline float close_confirm_anim = 0.f;
	inline int   close_confirm_hovered = -1;

	inline std::string hot_exit_dir() {
		wchar_t* appdata = nullptr;
		if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, nullptr, &appdata))) {
			auto p = std::filesystem::path(appdata) / L"AiDA" / L"Standalone" / L"hot_exit";
			CoTaskMemFree(appdata);
			std::error_code ec;
			std::filesystem::create_directories(p, ec);
			return p.string();
		}
		return {};
	}

	inline std::string hot_exit_key_for_path(const std::string& fpath) {
		uint64_t h = 0xCBF29CE484222325ULL;
		for (unsigned char c : fpath) {
			h ^= c;
			h *= 0x100000001B3ULL;
		}
		char buf[40];
		std::snprintf(buf, sizeof(buf), "%016llx.snapshot",
		              static_cast<unsigned long long>(h));
		return buf;
	}

	inline bool try_load_hot_exit(const std::string& fpath, std::string& out_buffer) {
		if (fpath.empty()) return false;
		std::string dir = hot_exit_dir();
		if (dir.empty()) return false;
		auto p = std::filesystem::path(dir) / hot_exit_key_for_path(fpath);
		std::error_code ec;
		if (!std::filesystem::exists(p, ec) || ec) return false;
		std::ifstream ifs(p, std::ios::binary);
		if (!ifs.is_open()) return false;
		std::ostringstream ss;
		ss << ifs.rdbuf();
		out_buffer = ss.str();
		ifs.close();
		std::filesystem::remove(p, ec);
		return true;
	}

	inline bool write_hot_exit_entry(const std::string& fpath, const std::string& contents) {
		if (fpath.empty()) return false;
		std::string dir = hot_exit_dir();
		if (dir.empty()) return false;
		auto p = std::filesystem::path(dir) / hot_exit_key_for_path(fpath);
		std::ofstream ofs(p, std::ios::binary | std::ios::trunc);
		if (!ofs.is_open()) return false;
		ofs.write(contents.data(), static_cast<std::streamsize>(contents.size()));
		return ofs.good();
	}

	inline void clear_all_hot_exit() {
		std::string dir = hot_exit_dir();
		if (dir.empty()) return;
		std::error_code ec;
		for (auto& e : std::filesystem::directory_iterator(dir, ec)) {
			if (ec) break;
			std::filesystem::remove(e.path(), ec);
		}
	}

	inline std::string read_file_contents(const std::string& fpath) {
		std::string out;
		if (fpath.empty()) return out;
		std::error_code ec;
		uintmax_t fsize = std::filesystem::file_size(fpath, ec);
		if (ec) return out;
		if (fsize > (8ULL * 1024ULL * 1024ULL)) return out;
		FILE* f = nullptr;
		fopen_s(&f, fpath.c_str(), "rb");
		if (!f) return out;
		fseek(f, 0, SEEK_END);
		long sz = ftell(f);
		fseek(f, 0, SEEK_SET);
		if (sz > 0) {
			out.resize(static_cast<size_t>(sz));
			fread(&out[0], 1, static_cast<size_t>(sz), f);
		}
		fclose(f);
		return out;
	}

	inline void snapshot_active_to_tab() {
		if (active_tab < 0 || active_tab >= (int)tabs.size()) return;
		if (!code_editor::active) return;
		auto& t = tabs[active_tab];
		if (t.filepath != code_editor::filepath) return;
		t.buffer = code_editor::get_content();
		t.buffer_loaded = true;
		t.dirty = code_editor::dirty;
	}

	inline void load_tab_into_editor(int idx) {
		if (idx < 0 || idx >= (int)tabs.size()) return;
		auto& t = tabs[idx];
		if (t.buffer_loaded) {
			code_editor::load(t.buffer, t.filename, t.filepath);
			code_editor::dirty = t.dirty;
			return;
		}
		std::error_code ec;
		uintmax_t fsize = t.filepath.empty() ? 0 : std::filesystem::file_size(t.filepath, ec);
		if (ec) fsize = 0;
		if (fsize <= (256ULL * 1024ULL)) {
			std::string content = read_file_contents(t.filepath);
			t.buffer = content;
			t.buffer_loaded = true;
			t.dirty = false;
			code_editor::load(content, t.filename, t.filepath);
		} else {
			std::string fname = t.filename;
			std::string fpath = t.filepath;
			code_editor::load(std::string("Loading..."), fname, fpath);
			work_queue::post([fname, fpath]() {
				std::string c = read_file_contents(fpath);
				for (auto& tab : tabs) {
					if (tab.filepath == fpath) {
						tab.buffer = c;
						tab.buffer_loaded = true;
						tab.dirty = false;
						break;
					}
				}
				code_editor::load(c, fname, fpath);
			});
		}
	}

	inline void switch_to(int idx) {
		if (idx < 0 || idx >= (int)tabs.size()) return;
		if (idx == active_tab && code_editor::active &&
		    code_editor::filepath == tabs[idx].filepath) {
			return;
		}
		snapshot_active_to_tab();
		active_tab = idx;
		load_tab_into_editor(idx);
	}

	inline bool save_tab_to_disk(int idx) {
		if (idx < 0 || idx >= (int)tabs.size()) return false;
		auto& t = tabs[idx];
		if (t.filepath.empty()) return false;
		if (!standalone_license::is_valid()) return false;
		{
			uint64_t gt = standalone_license::inline_gate_check(
				standalone_license::gate_editor_save);
			if (standalone_license::verify_gate_token(
					standalone_license::gate_editor_save, gt) < 0.5)
				return false;
		}
		if (idx == active_tab && code_editor::active &&
		    code_editor::filepath == t.filepath) {
			t.buffer = code_editor::get_content();
			t.buffer_loaded = true;
		}
		if (!t.buffer_loaded) return false;
		FILE* f = nullptr;
		fopen_s(&f, t.filepath.c_str(), "wb");
		if (!f) return false;
		fwrite(t.buffer.data(), 1, t.buffer.size(), f);
		fclose(f);
		t.dirty = false;
		if (idx == active_tab && code_editor::active &&
		    code_editor::filepath == t.filepath) {
			code_editor::dirty = false;
		}
		return true;
	}

	inline bool save_active_to_disk() {
		return save_tab_to_disk(active_tab);
	}

	inline void open_or_focus(const std::string& fpath, const std::string& fname,
	                          const std::string& content) {
		for (int i = 0; i < (int)tabs.size(); i++) {
			if (tabs[i].filepath == fpath && !fpath.empty()) {
				switch_to(i);
				return;
			}
		}
		snapshot_active_to_tab();
		OpenTab t;
		t.filename = fname;
		t.filepath = fpath;
		std::string snap;
		if (!fpath.empty() && try_load_hot_exit(fpath, snap)) {
			t.buffer = snap;
			t.buffer_loaded = true;
			t.dirty = (snap != content);
		} else {
			t.buffer = content;
			t.buffer_loaded = true;
			t.dirty = false;
		}
		tabs.push_back(std::move(t));
		active_tab = (int)tabs.size() - 1;
		auto& nt = tabs[active_tab];
		code_editor::load(nt.buffer, nt.filename, nt.filepath);
		code_editor::dirty = nt.dirty;
	}

	inline void close_tab(int idx) {
		if (idx < 0 || idx >= (int)tabs.size()) return;
		bool was_active = (idx == active_tab);
		tabs.erase(tabs.begin() + idx);
		if (active_tab >= (int)tabs.size()) active_tab = (int)tabs.size() - 1;
		else if (idx < active_tab) active_tab--;
		if (active_tab >= 0 && active_tab < (int)tabs.size()) {
			if (was_active || code_editor::filepath != tabs[active_tab].filepath)
				load_tab_into_editor(active_tab);
		} else {
			code_editor::active = false;
			code_editor::buffer.clear();
			code_editor::filename.clear();
			code_editor::filepath.clear();
			code_editor::dirty = false;
		}
	}

	inline void write_hot_exit_snapshot_all() {
		snapshot_active_to_tab();
		std::string dir = hot_exit_dir();
		if (dir.empty()) return;
		std::error_code ec;
		for (auto& e : std::filesystem::directory_iterator(dir, ec)) {
			if (ec) break;
			std::filesystem::remove(e.path(), ec);
		}
		for (const auto& t : tabs) {
			if (!t.dirty || t.filepath.empty() || !t.buffer_loaded) continue;
			write_hot_exit_entry(t.filepath, t.buffer);
		}
	}
}

namespace code_editor
{
	inline bool save() {
		if (file_tabs::active_tab < 0 ||
		    file_tabs::active_tab >= (int)file_tabs::tabs.size())
			return false;
		auto& t = file_tabs::tabs[file_tabs::active_tab];
		if (t.filepath != code_editor::filepath || code_editor::filepath.empty())
			return false;
		return file_tabs::save_tab_to_disk(file_tabs::active_tab);
	}
}
