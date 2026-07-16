#pragma once
#include "imgui/imgui_internal.h"
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "standalone_license.hpp"
#endif
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../preview/shell_preview_platform.hpp"
#else
#include "terminal_view.hpp"
#include "workspace_search.hpp"
#include "../core/infra/executor.hpp"
#include "diag_log.hpp"
#include "../core/ui/ui_thread_dispatcher.hpp"
#endif
#include <iostream>
#include <cstdio>
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include <cstdint>
struct ID3D11ShaderResourceView;
using DWORD = std::uint32_t;
#else
#include <d3d11.h>
#endif
#include <string>
#include <vector>
#include <deque>
#include <cstdint>
#include <cstring>
#include <functional>
#include <atomic>
#include <mutex>
#include <chrono>
#include <algorithm>
#include <unordered_map>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <system_error>
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include <shlobj.h>
#include <objbase.h>
#endif

namespace aida::shell_platform
{
	inline unsigned long long tick_ms()
	{
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		return static_cast<unsigned long long>(ImGui::GetTime() * 1000.0);
#else
		return GetTickCount64();
#endif
	}

	inline unsigned long thread_id()
	{
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		return 1;
#else
		return GetCurrentThreadId();
#endif
	}
}


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
	image_view,
	test_lab,
	workbench,
	functions_panel,
	xref_database
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
	inline constexpr size_t MAX_RENDER_LINES = 512;
	inline std::mutex mutex;
	inline uint64_t version[static_cast<int>(bottom_tab_t::COUNT)] = {};
	inline bool auto_scroll[static_cast<int>(bottom_tab_t::COUNT)] = { true, true, true, true, true };
	inline bool select_all[static_cast<int>(bottom_tab_t::COUNT)] = { false, false, false, false, false };
	inline std::atomic<unsigned long> owner_tid{0};
	inline std::atomic<unsigned long long> owner_since_ms{0};
	inline std::atomic<int> owner_tab{-1};
	inline std::atomic<int> owner_op{0};

	inline const char* op_name(int op) {
		switch (op) {
			case 1: return "push";
			case 2: return "clear";
			case 3: return "set_select_all";
			case 4: return "is_select_all";
			case 5: return "is_auto_scroll";
			case 6: return "size";
			case 7: return "empty";
			case 8: return "current_version";
			case 9: return "snapshot_all";
			case 10: return "snapshot_tail";
			case 11: return "try_snapshot_all";
			case 12: return "try_snapshot_tail_if_changed";
			case 13: return "try_is_auto_scroll";
			case 14: return "state_guard_snapshot";
			case 15: return "state_guard_restore";
			case 16: return "try_clear";
			case 17: return "try_set_auto_scroll";
			default: return "unknown";
		}
	}

	inline void set_owner(int op, int idx) {
		owner_op.store(op, std::memory_order_relaxed);
		owner_tab.store(idx, std::memory_order_relaxed);
		owner_since_ms.store(aida::shell_platform::tick_ms(), std::memory_order_relaxed);
		owner_tid.store(aida::shell_platform::thread_id(), std::memory_order_release);
	}

	inline void clear_owner() {
		owner_tid.store(0, std::memory_order_release);
		owner_since_ms.store(0, std::memory_order_relaxed);
		owner_tab.store(-1, std::memory_order_relaxed);
		owner_op.store(0, std::memory_order_relaxed);
	}

	struct owner_scope {
		owner_scope(int op, int idx) { set_owner(op, idx); }
		~owner_scope() { clear_owner(); }
		owner_scope(const owner_scope&) = delete;
		owner_scope& operator=(const owner_scope&) = delete;
	};

	inline void snapshot_owner(unsigned long& tid, unsigned long long& age_ms, int& tab, int& op) {
		tid = owner_tid.load(std::memory_order_acquire);
		op = owner_op.load(std::memory_order_relaxed);
		tab = owner_tab.load(std::memory_order_relaxed);
		unsigned long long since = owner_since_ms.load(std::memory_order_relaxed);
		unsigned long long now = aida::shell_platform::tick_ms();
		age_ms = (tid != 0 && since != 0 && now >= since) ? (now - since) : 0ULL;
	}

	inline int tab_index(bottom_tab_t tab) {
		int idx = static_cast<int>(tab);
		if (idx < 0 || idx >= static_cast<int>(bottom_tab_t::COUNT))
			return static_cast<int>(bottom_tab_t::output);
		return idx;
	}
	inline void push(bottom_tab_t tab, const std::string& line) {
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
		if (tab == bottom_tab_t::terminal) return;
#endif
		int idx = tab_index(tab);
		std::lock_guard<std::mutex> lk(mutex);
		owner_scope owner(1, idx);
		auto& q = lines[idx];
		q.push_back(line);
		while (q.size() > MAX_LINES) q.pop_front();
		++version[idx];
	}
	inline void clear(bottom_tab_t tab) {
		int idx = tab_index(tab);
		std::lock_guard<std::mutex> lk(mutex);
		owner_scope owner(2, idx);
		lines[idx].clear();
		select_all[idx] = false;
		++version[idx];
	}
	inline void set_select_all(bottom_tab_t tab, bool enabled) {
		int idx = tab_index(tab);
		std::lock_guard<std::mutex> lk(mutex);
		owner_scope owner(3, idx);
		select_all[idx] = enabled;
	}
	inline bool is_select_all(bottom_tab_t tab) {
		int idx = tab_index(tab);
		std::lock_guard<std::mutex> lk(mutex);
		owner_scope owner(4, idx);
		return select_all[idx];
	}
	inline bool is_auto_scroll(bottom_tab_t tab) {
		int idx = tab_index(tab);
		std::lock_guard<std::mutex> lk(mutex);
		owner_scope owner(5, idx);
		return auto_scroll[idx];
	}
	inline size_t size(bottom_tab_t tab) {
		int idx = tab_index(tab);
		std::lock_guard<std::mutex> lk(mutex);
		owner_scope owner(6, idx);
		return lines[idx].size();
	}
	inline bool empty(bottom_tab_t tab) {
		int idx = tab_index(tab);
		std::lock_guard<std::mutex> lk(mutex);
		owner_scope owner(7, idx);
		return lines[idx].empty();
	}
	inline uint64_t current_version(bottom_tab_t tab) {
		int idx = tab_index(tab);
		std::lock_guard<std::mutex> lk(mutex);
		owner_scope owner(8, idx);
		return version[idx];
	}
	inline void snapshot_all(bottom_tab_t tab, std::deque<std::string>& out, uint64_t* out_version = nullptr) {
		int idx = tab_index(tab);
		std::lock_guard<std::mutex> lk(mutex);
		owner_scope owner(9, idx);
		out = lines[idx];
		if (out_version) *out_version = version[idx];
	}
	inline void snapshot_tail(bottom_tab_t tab, size_t max_lines, std::vector<std::string>& out, size_t* total_lines = nullptr, uint64_t* out_version = nullptr) {
		int idx = tab_index(tab);
		std::lock_guard<std::mutex> lk(mutex);
		owner_scope owner(10, idx);
		const auto& q = lines[idx];
		size_t total = q.size();
		size_t count = (std::min)(total, max_lines);
		size_t skip = total - count;
		out.clear();
		out.reserve(count);
		size_t pos = 0;
		for (const auto& line : q) {
			if (pos++ >= skip) out.push_back(line);
		}
		if (total_lines) *total_lines = total;
		if (out_version) *out_version = version[idx];
	}
	inline bool try_snapshot_all(bottom_tab_t tab, std::deque<std::string>& out, uint64_t* out_version = nullptr) {
		int idx = tab_index(tab);
		std::unique_lock<std::mutex> lk(mutex, std::try_to_lock);
		if (!lk.owns_lock())
			return false;
		owner_scope owner(11, idx);
		out = lines[idx];
		if (out_version) *out_version = version[idx];
		return true;
	}
	inline bool try_snapshot_tail_if_changed(bottom_tab_t tab, size_t max_lines, uint64_t& known_version, std::vector<std::string>& out, size_t* total_lines = nullptr, bool* changed = nullptr) {
		int idx = tab_index(tab);
		std::unique_lock<std::mutex> lk(mutex, std::try_to_lock);
		if (!lk.owns_lock())
			return false;
		owner_scope owner(12, idx);
		const auto& q = lines[idx];
		size_t total = q.size();
		if (total_lines) *total_lines = total;
		if (version[idx] == known_version) {
			if (changed) *changed = false;
			return true;
		}
		size_t count = (std::min)(total, max_lines);
		size_t skip = total - count;
		out.clear();
		out.reserve(count);
		size_t pos = 0;
		for (const auto& line : q) {
			if (pos++ >= skip) out.push_back(line);
		}
		known_version = version[idx];
		if (changed) *changed = true;
		return true;
	}
	inline bool try_is_auto_scroll(bottom_tab_t tab, bool& enabled) {
		int idx = tab_index(tab);
		std::unique_lock<std::mutex> lk(mutex, std::try_to_lock);
		if (!lk.owns_lock())
			return false;
		owner_scope owner(13, idx);
		enabled = auto_scroll[idx];
		return true;
	}
	inline bool try_clear(bottom_tab_t tab) {
		int idx = tab_index(tab);
		std::unique_lock<std::mutex> lk(mutex, std::try_to_lock);
		if (!lk.owns_lock())
			return false;
		owner_scope owner(16, idx);
		lines[idx].clear();
		select_all[idx] = false;
		++version[idx];
		return true;
	}
	inline bool try_set_auto_scroll(bottom_tab_t tab, bool enabled) {
		int idx = tab_index(tab);
		std::unique_lock<std::mutex> lk(mutex, std::try_to_lock);
		if (!lk.owns_lock())
			return false;
		owner_scope owner(17, idx);
		auto_scroll[idx] = enabled;
		return true;
	}
}


namespace menu_bar {
	inline int  open_menu = -1;
	inline bool any_open  = false;
	inline int  suppress_frames = 0;
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

inline ImFont* g_code_font = nullptr;


namespace license
{
	inline bool  validated       = false;
	inline bool  checking        = false;
	inline std::atomic<bool> activation_worker_active{false};
	inline bool  check_failed    = false;
	inline char  key_buf[128]    = {};
	inline std::string error_msg;
	inline std::string saved_key;

	inline bool preserve_valid_state(bool runtime_locked, bool full_test_running)
	{
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		return validated && !runtime_locked && full_test_running;
#else
		return validated && !runtime_locked && full_test_running && standalone_license::is_arc_loaded();
#endif
	}

	inline bool runtime_ready(bool runtime_locked, bool full_test_running)
	{
		if (runtime_locked)
			return false;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		return validated || preserve_valid_state(runtime_locked, full_test_running);
#else
		if (standalone_license::is_valid())
			return true;
		return preserve_valid_state(runtime_locked, full_test_running);
#endif
	}
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
	void request_open_confirmation(const std::string& path);
	void render_pending_confirm_modal();
	void record_recent_workspace(const std::string& path);
	void tick_watcher();
}


namespace code_editor_widget {
	void on_text_changed();
	void get_caret(int& line, int& col);
	void set_caret(int line, int col);
}

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


#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	struct terminal_fixture_manager_t {};
	inline terminal_fixture_manager_t terminal_mgr;
#else
	inline terminal_view::TerminalManager terminal_mgr;
#endif

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


		inline bool test_all_visible = false;


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
	struct usage_snapshot_t {
		int64_t input_tokens = 0;
		int64_t output_tokens = 0;
		int64_t cache_read = 0;
		int64_t cache_write = 0;
		int64_t thinking_tokens = 0;
		double cost_usd = 0.0;
		int request_count = 0;
		std::string provider;
	};

	namespace detail {
		inline std::mutex mutex;
		inline usage_snapshot_t value;
	}

	inline usage_snapshot_t snapshot() {
		std::lock_guard<std::mutex> lock(detail::mutex);
		return detail::value;
	}

	inline void reset() {
		std::lock_guard<std::mutex> lock(detail::mutex);
		detail::value = {};
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
		return (static_cast<double>(in_tok) * in_price +
		        static_cast<double>(out_tok) * out_price +
		        static_cast<double>(cache_read) * cache_read_price +
		        static_cast<double>(cache_write) * cache_write_price) / 1000000.0;
	}

	inline void accumulate(const std::string& model, int64_t in_tok, int64_t out_tok,
	                        int64_t cache_read = 0, int64_t cache_write = 0, int64_t thinking = 0) {
		std::lock_guard<std::mutex> lock(detail::mutex);
		detail::value.input_tokens += in_tok;
		detail::value.output_tokens += out_tok;
		detail::value.cache_read += cache_read;
		detail::value.cache_write += cache_write;
		detail::value.thinking_tokens += thinking;
		detail::value.cost_usd += estimate_cost(model, in_tok, out_tok, cache_read, cache_write);
		++detail::value.request_count;
		detail::value.provider = model;
	}

	inline std::string format_tokens(int64_t count) {
		if (count >= 1000000) return std::to_string(count / 1000000) + "." + std::to_string((count % 1000000) / 100000) + "M";
		if (count >= 1000) return std::to_string(count / 1000) + "." + std::to_string((count % 1000) / 100) + "K";
		return std::to_string(count);
	}

	inline std::string format_cost() {
		const auto current = snapshot();
		char buf[32];
		snprintf(buf, sizeof(buf), "$%.4f", current.cost_usd);
		return buf;
	}
}


struct OpenTab {
	std::string filename;
	std::string filepath;
	std::string buffer;
	bool        buffer_loaded = false;
	bool        dirty          = false;
	std::uint64_t document_id  = 0;
	std::uint32_t group_id     = 0;
	bool          pinned       = false;
	std::int64_t  disk_write_version = 0;
	bool          external_conflict = false;
	bool          external_overwrite_approved = false;
	int           caret_line = 0;
	int           caret_column = 0;
};

namespace file_tabs {
	struct navigation_entry_t {
		std::uint64_t document_id = 0;
		int caret_line = 0;
		int caret_column = 0;
	};

	struct group_navigation_t {
		std::deque<navigation_entry_t> back;
		std::deque<navigation_entry_t> forward;
	};

	inline std::vector<OpenTab> tabs;
	inline int active_tab = -1;
	inline std::uint64_t next_document_id = 1;
	inline std::uint32_t next_group_id = 1;
	inline std::unordered_map<std::uint32_t, std::uint64_t> active_document_by_group;
	inline std::unordered_map<std::uint32_t, group_navigation_t> navigation_by_group;
	inline std::uint64_t last_external_poll_ms = 0;
	inline std::size_t external_poll_index = 0;
	inline int  pending_close_idx = -1;
	inline bool show_close_confirm = false;
	inline float close_confirm_anim = 0.f;
	inline int   close_confirm_hovered = -1;

	inline std::string hot_exit_dir() {
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		return {};
#else
		wchar_t* appdata = nullptr;
		if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, nullptr, &appdata))) {
			auto p = std::filesystem::path(appdata) / L"AiDA" / L"Standalone" / L"hot_exit";
			CoTaskMemFree(appdata);
			std::error_code ec;
			std::filesystem::create_directories(p, ec);
			return p.string();
		}
		return {};
#endif
	}

	inline std::string hot_exit_key_for_path(const std::string& fpath) {
		uint64_t h = 0xCBF29CE484222325ULL;
		for (char c : fpath) {
			h ^= static_cast<unsigned char>(c);
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
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		f = std::fopen(fpath.c_str(), "rb");
#else
		fopen_s(&f, fpath.c_str(), "rb");
#endif
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

	inline bool is_valid_tab_index(int idx) {
		return idx >= 0 && static_cast<size_t>(idx) < tabs.size();
	}

	inline size_t tab_index(int idx) {
		return static_cast<size_t>(idx);
	}

	inline std::int64_t disk_write_version(const std::string& fpath) {
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		(void)fpath;
		return 0;
#else
		if (fpath.empty()) return 0;
		std::error_code ec;
		const auto value = std::filesystem::last_write_time(fpath, ec);
		return ec ? 0 : static_cast<std::int64_t>(value.time_since_epoch().count());
#endif
	}

	inline void poll_external_changes() {
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
		const std::uint64_t now = aida::shell_platform::tick_ms();
		if (tabs.empty() || now - last_external_poll_ms < 1000)
			return;
		last_external_poll_ms = now;
		external_poll_index %= tabs.size();
		auto& tab = tabs[external_poll_index++];
		if (tab.filepath.empty()) return;
		const std::int64_t observed = disk_write_version(tab.filepath);
		if (observed == 0) return;
		if (tab.disk_write_version == 0) {
			tab.disk_write_version = observed;
			return;
		}
		if (observed != tab.disk_write_version) {
			tab.external_conflict = true;
			tab.external_overwrite_approved = false;
		}
#endif
	}

	inline void load_tab_into_editor(int idx);

	inline bool reload_external(int idx) {
		if (!is_valid_tab_index(idx)) return false;
		auto& tab = tabs[tab_index(idx)];
		if (tab.dirty || tab.filepath.empty()) return false;
		tab.buffer.clear();
		tab.buffer_loaded = false;
		tab.external_conflict = false;
		tab.external_overwrite_approved = false;
		tab.disk_write_version = disk_write_version(tab.filepath);
		if (idx == active_tab)
			load_tab_into_editor(idx);
		return true;
	}

	inline bool keep_editor_version(int idx) {
		if (!is_valid_tab_index(idx)) return false;
		auto& tab = tabs[tab_index(idx)];
		if (!tab.external_conflict) return false;
		tab.disk_write_version = disk_write_version(tab.filepath);
		tab.external_conflict = false;
		tab.external_overwrite_approved = true;
		return true;
	}

	inline void normalize_document_identities() {
		std::uint64_t maximum_document_id = 0;
		std::uint32_t maximum_group_id = 0;
		std::vector<std::uint64_t> identities;
		identities.reserve(tabs.size());
		for (auto& tab : tabs) {
			if (tab.document_id == 0 ||
				std::find(identities.begin(), identities.end(), tab.document_id) != identities.end())
				tab.document_id = next_document_id++;
			identities.push_back(tab.document_id);
			maximum_document_id = (std::max)(maximum_document_id, tab.document_id);
			maximum_group_id = (std::max)(maximum_group_id, tab.group_id);
			if (active_document_by_group.find(tab.group_id) == active_document_by_group.end())
				active_document_by_group.emplace(tab.group_id, tab.document_id);
		}
		next_document_id = (std::max)(next_document_id, maximum_document_id + 1);
		next_group_id = (std::max)(next_group_id, maximum_group_id + 1);
	}

	inline int find_document(std::uint64_t document_id) {
		for (std::size_t index = 0; index < tabs.size(); ++index)
			if (tabs[index].document_id == document_id)
				return static_cast<int>(index);
		return -1;
	}

	inline std::string group_instance_key(std::uint32_t group_id) {
		return std::string("group.") + std::to_string(group_id);
	}

	inline int active_in_group(std::uint32_t group_id) {
		normalize_document_identities();
		const auto selected = active_document_by_group.find(group_id);
		if (selected != active_document_by_group.end()) {
			const int index = find_document(selected->second);
			if (is_valid_tab_index(index) && tabs[tab_index(index)].group_id == group_id)
				return index;
		}
		for (std::size_t index = 0; index < tabs.size(); ++index) {
			if (tabs[index].group_id == group_id) {
				active_document_by_group[group_id] = tabs[index].document_id;
				return static_cast<int>(index);
			}
		}
		return -1;
	}

	inline void record_navigation(int from_index) {
		if (!is_valid_tab_index(from_index)) return;
		normalize_document_identities();
		const auto& source = tabs[tab_index(from_index)];
		int line = 0;
		int column = 0;
		if (from_index == active_tab && code_editor::active)
			code_editor_widget::get_caret(line, column);
		auto& history = navigation_by_group[source.group_id];
		if (!history.back.empty() && history.back.back().document_id == source.document_id &&
			history.back.back().caret_line == line && history.back.back().caret_column == column)
			return;
		history.back.push_back({source.document_id, line, column});
		constexpr std::size_t k_navigation_capacity = 128;
		if (history.back.size() > k_navigation_capacity)
			history.back.pop_front();
		history.forward.clear();
	}

	inline void snapshot_active_to_tab() {
		if (!is_valid_tab_index(active_tab)) return;
		if (!code_editor::active) return;
		auto& t = tabs[tab_index(active_tab)];
		if (t.filepath != code_editor::filepath) return;
		t.buffer = code_editor::get_content();
		t.buffer_loaded = true;
		t.dirty = code_editor::dirty;
		code_editor_widget::get_caret(t.caret_line, t.caret_column);
	}

	inline void load_tab_into_editor(int idx) {
		if (!is_valid_tab_index(idx)) return;
		auto& t = tabs[tab_index(idx)];
		if (t.buffer_loaded) {
			code_editor::load(t.buffer, t.filename, t.filepath);
			code_editor::dirty = t.dirty;
			code_editor_widget::set_caret(t.caret_line, t.caret_column);
			return;
		}
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		t.buffer.clear();
		t.buffer_loaded = true;
			t.dirty = false;
			code_editor::load(t.buffer, t.filename, t.filepath);
			code_editor_widget::set_caret(t.caret_line, t.caret_column);
#else
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
			aida::infra::executor::submission_t sub;
			sub.owner_subsystem = "file_tabs";
			sub.label = "file_tabs.large_file_load";
			sub.thread_class = "blocking_file_io";
			sub.domain = aida::infra::executor::domain_t::long_running;
			sub.priority = 3;
			sub.body = [fname, fpath]() {
				std::string c = read_file_contents(fpath);
				const bool posted = aida::ui_thread::post(
					[fname, fpath, content = std::move(c)]() mutable {
						for (auto& tab : tabs) {
							if (tab.filepath == fpath) {
								tab.buffer = content;
								tab.buffer_loaded = true;
								tab.dirty = false;
								break;
							}
						}
						const bool active_matches_tab = is_valid_tab_index(active_tab) &&
							tabs[tab_index(active_tab)].filepath == fpath;
						const bool active_matches_editor = code_editor::active &&
							code_editor::filepath == fpath;
						if (active_matches_tab || active_matches_editor)
							code_editor::load(content, fname, fpath);
					},
					"file_tabs",
					"large_file_load_result",
					"worker_result");
				if (!posted) {
					diag::log_tagged_critical_fmt("file_tabs",
						"large_file_load_dispatch_failed worker_tid=%lu ui_tid=%lu path=%.260s",
						static_cast<unsigned long>(aida::shell_platform::thread_id()),
						static_cast<unsigned long>(aida::ui_thread::owner_tid()),
						fpath.c_str());
				}
			};
			const bool submitted = aida::infra::executor::submit(std::move(sub)).submitted;
			if (!submitted)
				diag::log_tagged_critical_fmt("file_tabs", "large_file_load_submit_failed path=%.260s", fpath.c_str());
		}
#endif
	}

	inline void switch_to(int idx, bool record_history = true) {
		if (!is_valid_tab_index(idx)) return;
		normalize_document_identities();
		if (idx == active_tab && code_editor::active &&
		    code_editor::filepath == tabs[tab_index(idx)].filepath) {
			return;
		}
		if (record_history)
			record_navigation(active_tab);
		snapshot_active_to_tab();
		active_tab = idx;
		active_document_by_group[tabs[tab_index(idx)].group_id] =
			tabs[tab_index(idx)].document_id;
		load_tab_into_editor(idx);
	}

	inline bool navigate_group_history(std::uint32_t group_id, bool forward) {
		normalize_document_identities();
		auto found = navigation_by_group.find(group_id);
		if (found == navigation_by_group.end()) return false;
		auto& source = forward ? found->second.forward : found->second.back;
		auto& destination = forward ? found->second.back : found->second.forward;
		while (!source.empty()) {
			const navigation_entry_t target = source.back();
			source.pop_back();
			const int target_index = find_document(target.document_id);
			if (!is_valid_tab_index(target_index) || tabs[tab_index(target_index)].group_id != group_id)
				continue;
			if (is_valid_tab_index(active_tab)) {
				int line = 0;
				int column = 0;
				code_editor_widget::get_caret(line, column);
				destination.push_back({tabs[tab_index(active_tab)].document_id, line, column});
			}
			switch_to(target_index, false);
			code_editor_widget::set_caret(target.caret_line, target.caret_column);
			tabs[tab_index(target_index)].caret_line = target.caret_line;
			tabs[tab_index(target_index)].caret_column = target.caret_column;
			return true;
		}
		return false;
	}

	inline std::uint32_t create_group_for_tab(int idx) {
		if (!is_valid_tab_index(idx)) return 0;
		normalize_document_identities();
		const std::uint32_t group = next_group_id++;
		tabs[tab_index(idx)].group_id = group;
		active_document_by_group[group] = tabs[tab_index(idx)].document_id;
		return group;
	}

	inline bool move_to_group(int idx, std::uint32_t group_id) {
		if (!is_valid_tab_index(idx)) return false;
		normalize_document_identities();
		const std::uint32_t old_group = tabs[tab_index(idx)].group_id;
		if (old_group == group_id) return true;
		const std::uint64_t document_id = tabs[tab_index(idx)].document_id;
		tabs[tab_index(idx)].group_id = group_id;
		active_document_by_group[group_id] = document_id;
		if (active_document_by_group[old_group] == document_id)
			active_document_by_group.erase(old_group);
		active_in_group(old_group);
		return true;
	}

	inline bool save_tab_to_disk(int idx) {
		if (!is_valid_tab_index(idx)) return false;
		auto& t = tabs[tab_index(idx)];
		if (t.filepath.empty()) return false;
		if (t.external_conflict && !t.external_overwrite_approved) return false;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		if (idx == active_tab && code_editor::active && code_editor::filepath == t.filepath) {
			t.buffer = code_editor::get_content();
			t.buffer_loaded = true;
			code_editor::dirty = false;
		}
		t.dirty = false;
		t.external_conflict = false;
		t.external_overwrite_approved = false;
		t.disk_write_version = disk_write_version(t.filepath);
		return true;
#else
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
		t.external_conflict = false;
		t.external_overwrite_approved = false;
		t.disk_write_version = disk_write_version(t.filepath);
		if (idx == active_tab && code_editor::active &&
		    code_editor::filepath == t.filepath) {
			code_editor::dirty = false;
		}
		return true;
#endif
	}

	inline bool save_active_to_disk() {
		return save_tab_to_disk(active_tab);
	}

	inline void open_or_focus(const std::string& fpath, const std::string& fname,
	                          const std::string& content) {
		for (size_t i = 0; i < tabs.size(); i++) {
			if (tabs[i].filepath == fpath && !fpath.empty()) {
				switch_to(static_cast<int>(i));
				return;
			}
		}
		const std::uint32_t target_group = is_valid_tab_index(active_tab)
			? tabs[tab_index(active_tab)].group_id : 0;
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
		t.group_id = target_group;
		t.disk_write_version = disk_write_version(fpath);
		tabs.push_back(std::move(t));
		active_tab = static_cast<int>(tabs.size()) - 1;
		normalize_document_identities();
		auto& nt = tabs[tab_index(active_tab)];
		active_document_by_group[nt.group_id] = nt.document_id;
		code_editor::load(nt.buffer, nt.filename, nt.filepath);
		code_editor::dirty = nt.dirty;
	}

	inline void close_tab(int idx) {
		if (!is_valid_tab_index(idx)) return;
		normalize_document_identities();
		const std::uint64_t removed_document = tabs[tab_index(idx)].document_id;
		const std::uint32_t removed_group = tabs[tab_index(idx)].group_id;
		bool was_active = (idx == active_tab);
		tabs.erase(tabs.begin() + static_cast<std::vector<OpenTab>::difference_type>(idx));
		for (auto& entry : navigation_by_group) {
			auto erase_removed = [removed_document](std::deque<navigation_entry_t>& history) {
				history.erase(std::remove_if(history.begin(), history.end(),
					[removed_document](const navigation_entry_t& value) {
						return value.document_id == removed_document;
					}), history.end());
			};
			erase_removed(entry.second.back);
			erase_removed(entry.second.forward);
		}
		if (active_document_by_group[removed_group] == removed_document)
			active_document_by_group.erase(removed_group);
		if (was_active) {
			active_tab = -1;
			for (std::size_t index = 0; index < tabs.size(); ++index) {
				if (tabs[index].group_id == removed_group) {
					active_tab = static_cast<int>(index);
					break;
				}
			}
			if (active_tab < 0 && !tabs.empty())
				active_tab = (std::min)(idx, static_cast<int>(tabs.size()) - 1);
		} else if (active_tab >= static_cast<int>(tabs.size())) {
			active_tab = static_cast<int>(tabs.size()) - 1;
		} else if (idx < active_tab) {
			active_tab--;
		}
		if (is_valid_tab_index(active_tab)) {
			if (was_active || code_editor::filepath != tabs[tab_index(active_tab)].filepath)
				load_tab_into_editor(active_tab);
			active_document_by_group[tabs[tab_index(active_tab)].group_id] =
				tabs[tab_index(active_tab)].document_id;
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
		if (!file_tabs::is_valid_tab_index(file_tabs::active_tab))
			return false;
		auto& t = file_tabs::tabs[file_tabs::tab_index(file_tabs::active_tab)];
		if (t.filepath != code_editor::filepath || code_editor::filepath.empty())
			return false;
		return file_tabs::save_tab_to_disk(file_tabs::active_tab);
	}
}
