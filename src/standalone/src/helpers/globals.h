#pragma once
#include "imgui/imgui_internal.h"
#include "../core/editor/code_editor.hpp"
#include "../core/editor/programming_document_service.hpp"
#include "../core/ui/task_center.hpp"
#include "../core/ui/terminal_view.hpp"
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../preview/shell_preview_platform.hpp"
#else
#include "workspace_search.hpp"
#include "../core/infra/executor.hpp"
#include "diag_log.hpp"
#include "../core/ui/ui_thread_dispatcher.hpp"
#endif
#include <iostream>
#include <cstdio>
#include <cctype>
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include <cstdint>
struct ID3D11ShaderResourceView;
using DWORD = std::uint32_t;
#else
#include <d3d11.h>
#endif
#include <string>
#include <string_view>
#include <vector>
#include <deque>
#include <cstdint>
#include <cstring>
#include <functional>
#include <atomic>
#include <mutex>
#include <memory>
#include <new>
#include <chrono>
#include <algorithm>
#include <unordered_map>
#include <unordered_set>
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
	inline bool open_request = false;
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
	bool        pinned = false;
	std::uint64_t revision = 0;
};

namespace conversations {
	inline std::vector<ConversationSummary> history;
	inline std::shared_ptr<const std::vector<ConversationSummary>> published_history =
		std::make_shared<const std::vector<ConversationSummary>>();
	inline std::string current_id;
	inline bool browser_open = false;
	inline std::uint64_t current_revision = 0;
	inline bool current_identity_uncommitted = false;
	inline std::uint64_t catalog_generation = 0;
	inline std::string persistence_error;

	void save_current();
	void load_conversation(const std::string& id);
	void new_chat();
	void refresh_history();
	void delete_conversation(const std::string& id, std::uint64_t reviewed_revision);
	bool set_pinned(const std::string& id, bool pinned);
	bool fork_conversation(const std::string& id, std::string& forked_id);
	bool export_markdown(const std::string& id, const std::string& output_path,
		std::string& error);
	void process_store_completion(bool allow_deferred = true);
	bool commit_shutdown(std::string& error);
	std::shared_ptr<const std::vector<ConversationSummary>> catalog_snapshot();
}


void tick_ai_chat();
void poll_ai_chat();

inline ImFont* g_code_font = nullptr;


struct FileBrowserEntry {
	std::string name;
	std::string full_path;
	bool        is_dir     = false;
	bool        expanded   = false;
	int         depth      = 0;
	std::uint64_t root_id  = 0;
	std::uint64_t entry_id = 0;
	std::uint64_t parent_id = 0;
	std::uint64_t generation = 0;
	bool        is_root = false;
};

namespace file_browser
{
	enum class index_state_t : std::uint8_t {
		idle,
		loading,
		ready,
		cancelled,
		error
	};

	inline std::vector<FileBrowserEntry> entries;
	inline std::string                   current_dir;
	inline std::vector<std::string>      roots;
	inline std::unordered_set<std::string> expanded_paths;
	inline int                           selected_idx = -1;
	inline std::unordered_set<std::string> selected_paths;
	inline std::string                   selection_anchor_path;
	inline std::string                   selection_error;
	inline std::uint64_t                 selection_revision = 0;
	inline std::uint64_t                 selection_interaction_generation = 0;
	inline bool                          needs_refresh = true;
	inline char                          path_buf[512] = {};
	inline index_state_t                 index_state = index_state_t::idle;
	inline std::string                   index_error;
	inline std::uint64_t                 index_generation = 0;
	inline std::size_t                   indexed_directory_count = 0;
	inline std::size_t                   indexed_entry_count = 0;
	inline bool                          index_truncated = false;

	inline std::string                   pending_open_path;
	inline std::string                   pending_open_filename;
	inline std::string                   pending_reveal_path;
	inline bool                          pending_open_modal_visible = false;
	inline bool                          pending_open_should_open   = false;

	void refresh(const std::string& dir = "");
	void set_roots(std::vector<std::string> requested_roots);
	bool set_workspace_root(const std::string& path, std::string* error = nullptr);
	bool binary_analysis_candidate(const std::string& path);
	void cancel_refresh();
	void toggle_dir(int idx);
	void open_file(int idx);
	void open_path(const std::string& path);
	bool reveal_path(const std::string& path);
	void request_open_confirmation(const std::string& path);
	void render_pending_confirm_modal();
	void record_recent_workspace(const std::string& path);
	void tick_watcher();
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
		  IM_COL32(108, 124, 160, 182)
		},

		{ "AiDA Light",
		  ImVec4(42.f/255.f, 104.f/255.f, 216.f/255.f, 1.f),
		  IM_COL32(244, 246, 251, 250),
		  IM_COL32(251, 252, 255, 232),
		  IM_COL32(231, 237, 248, 234),
		  IM_COL32(231, 237, 248, 232),
		  IM_COL32(22, 28, 44, 252),
		  IM_COL32(78, 92, 122, 232),
		  IM_COL32(140, 152, 178, 220)
		},

		{ "Claude Dark",
		  ImVec4(0xF4/255.f, 0x84/255.f, 0x5F/255.f, 1.f),
		  IM_COL32(0x26, 0x26, 0x24, 235),
		  IM_COL32(0x26, 0x26, 0x24, 222),
		  IM_COL32(0x1E, 0x1E, 0x1C, 232),
		  IM_COL32(0x1A, 0x1A, 0x18, 232),
		  IM_COL32(0xE8, 0xE4, 0xDC, 242),
		  IM_COL32(0xB8, 0xB1, 0xA4, 218),
		  IM_COL32(0x88, 0x88, 0x88, 200)
		},

		{ "Claude Light",
		  ImVec4(0xC1/255.f, 0x5F/255.f, 0x3C/255.f, 1.f),
		  IM_COL32(0xF4, 0xF3, 0xEE, 250),
		  IM_COL32(0xFA, 0xF9, 0xF5, 232),
		  IM_COL32(0xE9, 0xEC, 0xEC, 234),
		  IM_COL32(0xE9, 0xEC, 0xEC, 232),
		  IM_COL32(0x1F, 0x1E, 0x1D, 252),
		  IM_COL32(0x6F, 0x6F, 0x78, 232),
		  IM_COL32(0xB1, 0xAD, 0xA1, 220)
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
		inline bool quick_open_open = false;
		inline char quick_open_buf[128] = {};


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
	std::int64_t  external_observed_write_version = 0;
	bool          external_conflict = false;
	bool          external_overwrite_approved = false;
	int           caret_line = 0;
	int           caret_column = 0;
	int           selection_anchor_line = 0;
	int           selection_anchor_column = 0;
	bool          selection_active = false;
	float         scroll_x = 0.f;
	float         scroll_y = 0.f;
	std::vector<int> folded_lines;
	std::string   language_override;
	std::uint64_t revision = 1;
	std::uint64_t content_hash = 0;
	std::uint64_t base_fingerprint = 0;
	aida::editor::programming_documents::text_metadata_t text_metadata;
	aida::editor::programming_documents::recovery_reference_t recovery;
	std::string   recovery_error;
	std::uint64_t recovery_checkpoint_hash = 0;
	std::uint64_t recovery_checkpoint_ms = 0;
	std::uint64_t recovery_checkpoint_generation = 0;
	bool          recovery_checkpoint_pending = false;
	bool          recovery_probe_completed = false;
	bool          recovery_operation_pending = false;
	std::uint64_t recovery_operation_generation = 0;
	std::string   recovery_operation_label;
	std::shared_ptr<std::atomic<bool>> recovery_dispatch_failed;
	std::shared_ptr<std::atomic<bool>> recovery_checkpoint_dispatch_failed;
	bool          proposal_pending = false;
	bool          load_in_progress = false;
	bool          load_failed = false;
	std::string   load_error;
	std::uint64_t load_generation = 0;
	std::shared_ptr<std::atomic<bool>> load_dispatch_failed;
	bool          pending_caret_navigation = false;
	bool          streamed_document = false;
	std::uint64_t streamed_byte_length = 0;
	bool          save_in_progress = false;
	std::uint64_t save_generation = 0;
	std::string   save_error;
	std::shared_ptr<std::atomic<bool>> save_dispatch_failed;
	bool          watch_in_progress = false;
	std::uint64_t watch_generation = 0;
	std::shared_ptr<std::atomic<bool>> watch_dispatch_failed;
};

namespace file_tabs {
	struct document_load_control_t {
		std::shared_ptr<std::atomic<bool>> cancelled;
		std::uint64_t task_id = 0;
	};

	struct navigation_entry_t {
		std::uint64_t document_id = 0;
		int caret_line = 0;
		int caret_column = 0;
	};

	struct group_navigation_t {
		std::deque<navigation_entry_t> back;
		std::deque<navigation_entry_t> forward;
	};

	struct closed_document_t {
		std::string filepath;
		std::string filename;
		std::uint32_t group_id = 0;
		int caret_line = 0;
		int caret_column = 0;
	};

	inline std::vector<OpenTab> tabs;
	inline int active_tab = -1;
	inline std::uint64_t next_document_id = 1;
	inline std::uint32_t next_group_id = 1;
	inline std::unordered_map<std::uint32_t, std::uint64_t> active_document_by_group;
	inline std::unordered_map<std::uint32_t, group_navigation_t> navigation_by_group;
	inline std::unordered_map<std::uint64_t, document_load_control_t> document_load_controls;
	inline std::deque<closed_document_t> closed_documents;
	inline std::uint64_t last_external_poll_ms = 0;
	inline std::size_t external_poll_index = 0;
	inline int  pending_close_idx = -1;
	inline bool show_close_confirm = false;
	inline std::string close_confirm_error;
	inline std::deque<std::uint64_t> pending_close_all_document_ids;
	inline std::uint64_t pending_close_after_save_document_id = 0;
	inline bool exit_review_requested = false;
	inline bool exit_review_ready = false;
	inline bool exit_review_committed = false;
	inline std::unordered_map<std::uint64_t, std::uint64_t> exit_review_snapshot_revisions;
	inline std::unordered_map<std::uint64_t, std::uint64_t> exit_review_resolved_revisions;
	inline std::unordered_map<std::uint64_t, std::uint64_t> exit_review_discard_revisions;
	inline std::unordered_map<std::uint64_t, std::uint64_t> exit_review_cleanup_requested_revisions;
	inline std::unordered_map<std::uint64_t, std::uint64_t> exit_review_cleanup_completed_revisions;
	inline std::uint64_t pending_recovery_discard_document = 0;
	inline float close_confirm_anim = 0.f;
	inline int   close_confirm_hovered = -1;

	inline bool close_review_in_progress() {
		return pending_close_idx >= 0 || pending_close_after_save_document_id != 0 ||
			!pending_close_all_document_ids.empty() || exit_review_requested;
	}

	inline bool is_valid_tab_index(int idx) {
		return idx >= 0 && static_cast<size_t>(idx) < tabs.size();
	}

	inline size_t tab_index(int idx) {
		return static_cast<size_t>(idx);
	}

	inline int find_document(std::uint64_t document_id);

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
		for (auto& pending : tabs) {
			if (pending.watch_dispatch_failed &&
				pending.watch_dispatch_failed->exchange(false, std::memory_order_acq_rel)) {
				pending.watch_in_progress = false;
				++pending.watch_generation;
				pending.watch_dispatch_failed.reset();
				pending.save_error = "The external-change probe completed, but its result could not return to the UI owner; the next probe will retry.";
			}
		}
		const std::uint64_t now = aida::shell_platform::tick_ms();
		if (tabs.empty() || now - last_external_poll_ms < 1000)
			return;
		last_external_poll_ms = now;
		external_poll_index %= tabs.size();
		auto& tab = tabs[external_poll_index++];
		if (tab.filepath.empty() || tab.watch_in_progress) return;
		tab.watch_in_progress = true;
		const std::uint64_t document_id = tab.document_id;
		const std::uint64_t generation = ++tab.watch_generation;
		const std::string path = tab.filepath;
		auto dispatch_failed = std::make_shared<std::atomic<bool>>(false);
		tab.watch_dispatch_failed = dispatch_failed;
		aida::infra::executor::submission_t submission;
		submission.owner_subsystem = "file_tabs";
		submission.label = "file_tabs.external_change_probe";
		submission.thread_class = "bounded_file_metadata";
		submission.domain = aida::infra::executor::domain_t::feature_worker;
		submission.priority = 1;
		submission.generation = generation;
		submission.body = [document_id, generation, path, dispatch_failed]() {
			const std::int64_t observed = disk_write_version(path);
			aida::ui_thread::post_options_t options;
			options.subsystem = "file_tabs";
			options.label = "external_change_probe_result";
			options.phase = "worker_result";
			options.owner = "file_tabs.external_change_probe";
			options.priority = aida::ui_thread::priority_t::normal;
			const bool posted = aida::ui_thread::post([document_id, generation, path, observed] {
				const int index = find_document(document_id);
				if (!is_valid_tab_index(index)) return;
				auto& current = tabs[tab_index(index)];
				if (current.filepath != path || current.watch_generation != generation) return;
				current.watch_in_progress = false;
				current.watch_dispatch_failed.reset();
				if (observed == 0) return;
				if (current.disk_write_version == 0) {
					current.disk_write_version = observed;
					return;
				}
				if (observed != current.disk_write_version) {
					current.external_conflict = true;
					current.external_observed_write_version = observed;
					current.external_overwrite_approved = false;
				}
			}, std::move(options)) == aida::ui_thread::enqueue_result_t::accepted;
			if (!posted)
				dispatch_failed->store(true, std::memory_order_release);
		};
		const auto submitted = aida::infra::executor::submit(std::move(submission));
		if (!submitted.submitted) {
			tab.watch_in_progress = false;
			tab.watch_dispatch_failed.reset();
			tab.save_error = "The external-change probe could not be scheduled: " + submitted.reject_reason;
		}
#endif
	}

	inline void load_tab_into_editor(int idx);
	inline void switch_to(int idx, bool record_history = true);
	inline bool request_document_open(const std::string& fpath, const std::string& fname,
		int caret_line = -1, int caret_column = -1);
	inline bool cancel_document_load(std::uint64_t document_id);
	inline std::uint64_t content_fingerprint(std::string_view content);
	inline aida::editor::programming_documents::document_record_t recovery_record(
		const OpenTab& tab);
	inline void checkpoint_recovery(int idx);

	inline bool reload_external(int idx) {
		if (!is_valid_tab_index(idx)) return false;
		auto& tab = tabs[tab_index(idx)];
		if (tab.dirty || tab.filepath.empty()) return false;
		tab.buffer.clear();
		tab.buffer_loaded = false;
		tab.load_failed = false;
		tab.load_error.clear();
		tab.content_hash = 0;
		++tab.revision;
		tab.proposal_pending = false;
		code_editor_widget::discard_document_state(tab.document_id);
		tab.external_conflict = false;
		tab.external_overwrite_approved = false;
		tab.disk_write_version = 0;
		if (idx == active_tab)
			load_tab_into_editor(idx);
		return true;
	}

	inline bool keep_editor_version(int idx) {
		if (!is_valid_tab_index(idx)) return false;
		auto& tab = tabs[tab_index(idx)];
		if (!tab.external_conflict) return false;
		tab.disk_write_version = tab.external_observed_write_version;
		tab.external_observed_write_version = 0;
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
		code_editor_widget::get_document_caret(source.document_id, line, column);
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
		auto& t = tabs[tab_index(active_tab)];
		const auto metadata = code_editor_widget::document_metadata(t.document_id);
		if (!metadata.found) return;
		t.dirty = metadata.dirty;
		t.caret_line = metadata.caret_line;
		t.caret_column = metadata.caret_column;
		t.selection_anchor_line = metadata.selection_anchor_line;
		t.selection_anchor_column = metadata.selection_anchor_column;
		t.selection_active = metadata.selection_active;
		t.scroll_x = metadata.scroll_x;
		t.scroll_y = metadata.scroll_y;
		t.folded_lines = metadata.folded_lines;
		t.language_override = metadata.language_override;
		t.revision = metadata.revision;
		t.proposal_pending = metadata.proposal_pending;
		if (metadata.dirty) t.content_hash = 0;
	}

	inline void load_tab_into_editor(int idx) {
		if (!is_valid_tab_index(idx)) return;
		auto& t = tabs[tab_index(idx)];
		if (t.buffer_loaded && t.content_hash == 0)
			t.content_hash = content_fingerprint(t.buffer);
		if (t.buffer_loaded) {
			static_cast<void>(code_editor_widget::load_document(t.document_id, t.revision,
				t.buffer, t.filename, t.filepath, t.dirty, t.caret_line, t.caret_column,
				t.scroll_x, t.scroll_y, false, t.selection_anchor_line,
				t.selection_anchor_column, t.selection_active, t.folded_lines,
				t.language_override));
			if (t.pending_caret_navigation) {
				code_editor_widget::set_document_caret(t.document_id,
					t.caret_line, t.caret_column);
				t.pending_caret_navigation = false;
			}
			return;
		}
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		t.buffer.clear();
		t.buffer_loaded = true;
			t.dirty = false;
			static_cast<void>(code_editor_widget::load_document(t.document_id, t.revision,
				t.buffer, t.filename, t.filepath, false, t.caret_line, t.caret_column,
				t.scroll_x, t.scroll_y, false, t.selection_anchor_line,
				t.selection_anchor_column, t.selection_active, t.folded_lines,
				t.language_override));
#else
		if (t.load_in_progress)
			return;
		t.load_in_progress = true;
		t.load_failed = false;
		t.load_error.clear();
		auto load_dispatch_failed = std::make_shared<std::atomic<bool>>(false);
		t.load_dispatch_failed = load_dispatch_failed;
		const std::string fname = t.filename;
		const std::string fpath = t.filepath;
		const std::uint64_t document_id = t.document_id;
		const std::uint64_t generation = ++t.load_generation;
		const std::string load_task_id = "editor.load." +
			std::to_string(document_id) + "." + std::to_string(generation);
		auto recovery_identity = recovery_record(t);
		auto cancel = std::make_shared<std::atomic<bool>>(false);
		document_load_controls[document_id] = {cancel, 0};
		aida::infra::executor::submission_t sub;
		sub.owner_subsystem = "file_tabs";
		sub.label = "file_tabs.document_load";
		sub.thread_class = "blocking_file_io";
		sub.domain = aida::infra::executor::domain_t::feature_worker;
		sub.priority = 3;
		sub.generation = generation;
		sub.cancel_hook = [cancel]() { cancel->store(true, std::memory_order_release); };
		sub.body = [fname, fpath, document_id, generation, load_task_id, cancel, load_dispatch_failed,
			recovery_identity = std::move(recovery_identity)]() mutable {
			constexpr std::uintmax_t k_editable_document_limit =
				aida::editor::programming_documents::maximum_editable_document_bytes;
			constexpr std::uintmax_t k_viewable_document_limit =
				aida::editor::programming_documents::maximum_viewable_document_bytes;
			std::string content;
			std::string error;
			aida::editor::programming_documents::text_metadata_t text_metadata;
			std::uintmax_t file_size = 0;
			bool streamed = false;
			std::int64_t write_version = 0;
			aida::editor::programming_documents::recovery_reference_t recovery;
			std::error_code ec;
			file_size = std::filesystem::file_size(fpath, ec);
			if (ec) {
				error = "The file size could not be read: " + ec.message();
			} else if (file_size > k_viewable_document_limit) {
				error = "The artifact exceeds the 500 MiB text-view limit; open it in Hex View or Binary Map.";
			} else if (file_size > k_editable_document_limit) {
				streamed = true;
			} else if (!cancel->load(std::memory_order_acquire)) {
				std::ifstream input(fpath, std::ios::binary);
				if (!input.is_open()) {
					error = "The file could not be opened for reading.";
				} else {
					content.resize(static_cast<std::size_t>(file_size));
					if (!content.empty())
						input.read(content.data(), static_cast<std::streamsize>(content.size()));
					if ((!content.empty() && input.gcount() != static_cast<std::streamsize>(content.size())) || input.bad())
						error = "The complete file could not be read.";
				}
			}
			if (error.empty() && !streamed && !cancel->load(std::memory_order_acquire)) {
				auto decoded = aida::editor::programming_documents::decode_file_bytes(content);
				if (!decoded.succeeded) {
					error = std::move(decoded.detail);
					content.clear();
				} else {
					content = std::move(decoded.text);
					text_metadata = std::move(decoded.metadata);
					if (content.size() > k_editable_document_limit) {
						error = "The decoded text exceeds the 1 MiB bounded editable model; open it in Hex View or convert it to UTF-8 for mapped read-only viewing.";
						content.clear();
					}
				}
			}
			if (!cancel->load(std::memory_order_acquire)) {
				aida::editor::programming_documents::operation_result_t migrated{true, {}};
				if (!streamed) {
					recovery_identity.content = content;
					recovery_identity.base_fingerprint = content_fingerprint(content);
					recovery_identity.text = text_metadata;
					migrated = aida::editor::programming_documents::migrate_legacy_snapshot(
						recovery_identity, fpath);
				}
				recovery = aida::editor::programming_documents::probe(document_id, fpath);
				if (!migrated.succeeded && recovery.diagnostic.empty())
					recovery.diagnostic = migrated.detail;
				write_version = disk_write_version(fpath);
			}
			aida::ui_thread::post_options_t dispatch_options;
			dispatch_options.subsystem = "file_tabs";
			dispatch_options.label = "document_load_result";
			dispatch_options.phase = "worker_result";
			dispatch_options.owner = "file_tabs.document_load";
			dispatch_options.priority = aida::ui_thread::priority_t::critical;
			dispatch_options.cancelled = [cancel]() {
				return cancel->load(std::memory_order_acquire);
			};
			const bool posted = aida::ui_thread::post(
				[fname, fpath, document_id, generation, cancel, content = std::move(content),
				 error = std::move(error), recovery = std::move(recovery), write_version, load_task_id,
				 file_size, streamed, text_metadata = std::move(text_metadata)]() mutable {
					const int index = find_document(document_id);
					if (!is_valid_tab_index(index)) return;
					auto& tab = tabs[tab_index(index)];
					if (tab.filepath != fpath || tab.load_generation != generation) return;
					document_load_controls.erase(document_id);
					tab.load_in_progress = false;
					tab.load_dispatch_failed.reset();
					tab.recovery = std::move(recovery);
					tab.recovery_probe_completed = true;
					tab.recovery_error = tab.recovery.diagnostic;
					if (cancel->load(std::memory_order_acquire)) {
						tab.load_failed = true;
						tab.load_error = "Document loading was cancelled.";
						static_cast<void>(aida::ui::task_center::update_task(load_task_id,
							aida::ui::task_center::task_state_t::cancelled, 1.f,
							"Load cancelled", tab.load_error));
						return;
					}
					if (!error.empty()) {
						tab.load_failed = true;
						tab.load_error = std::move(error);
						static_cast<void>(aida::ui::task_center::update_task(load_task_id,
							aida::ui::task_center::task_state_t::failed, 1.f,
							"Load failed", tab.load_error));
						if (tab.recovery.available) {
							tab.buffer.clear();
							tab.buffer_loaded = true;
							tab.base_fingerprint = 0;
							tab.content_hash = content_fingerprint(tab.buffer);
							static_cast<void>(code_editor_widget::load_document(document_id,
								tab.revision, tab.buffer, fname, fpath, false,
								tab.caret_line, tab.caret_column, tab.scroll_x, tab.scroll_y,
								true));
						}
						return;
					}
					if (streamed) {
						tab.buffer.clear();
						tab.buffer_loaded = true;
						tab.load_failed = false;
						tab.load_error.clear();
						tab.dirty = false;
						tab.streamed_document = true;
						tab.streamed_byte_length = static_cast<std::uint64_t>(file_size);
						tab.disk_write_version = write_version;
						tab.external_observed_write_version = 0;
						tab.content_hash = 0;
						tab.base_fingerprint = 0;
						tab.text_metadata = {};
						const bool mapped_scheduled =
							code_editor_widget::request_streamed_document(document_id,
								tab.revision, fname, fpath, tab.streamed_byte_length);
						if (!mapped_scheduled) {
							tab.load_failed = true;
							tab.load_error = "The memory-mapped large-file view could not be scheduled.";
						}
						static_cast<void>(aida::ui::task_center::update_task(load_task_id,
							mapped_scheduled
								? aida::ui::task_center::task_state_t::completed
								: aida::ui::task_center::task_state_t::failed,
							1.f, mapped_scheduled ? "File classified for mapped viewing"
								: "Mapped viewing could not start",
							mapped_scheduled
								? "Large-file indexing was handed to the mapped editor task."
								: tab.load_error));
						if (find_document(document_id) == active_tab)
							code_editor_widget::select_document_for_actions(document_id);
						return;
					}
					tab.buffer = std::move(content);
					tab.buffer_loaded = true;
					tab.load_failed = false;
					tab.load_error.clear();
					tab.dirty = false;
					tab.streamed_document = false;
					tab.streamed_byte_length = 0;
					tab.disk_write_version = write_version;
					tab.external_observed_write_version = 0;
					tab.content_hash = content_fingerprint(tab.buffer);
					tab.base_fingerprint = tab.content_hash;
					tab.text_metadata = std::move(text_metadata);
					static_cast<void>(aida::ui::task_center::update_task(load_task_id,
						aida::ui::task_center::task_state_t::completed, 1.f,
						"Load complete", "Decoded exact text and recovery metadata."));
					if (tab.recovery.available &&
						tab.recovery.metadata.base_fingerprint != 0 &&
						tab.recovery.metadata.base_fingerprint != tab.base_fingerprint)
						tab.recovery_error = "The disk base changed after this journal was captured. Compare before recovering.";
					static_cast<void>(code_editor_widget::load_document(document_id,
						tab.revision, tab.buffer, fname, fpath, tab.dirty,
						tab.caret_line, tab.caret_column, tab.scroll_x, tab.scroll_y,
						true));
					if (find_document(document_id) == active_tab)
						code_editor_widget::select_document_for_actions(document_id);
					if (tab.pending_caret_navigation)
						tab.pending_caret_navigation = false;
				}, std::move(dispatch_options)) == aida::ui_thread::enqueue_result_t::accepted;
			if (!posted && !cancel->load(std::memory_order_acquire)) {
				load_dispatch_failed->store(true, std::memory_order_release);
				diag::log_tagged_critical_fmt("file_tabs",
					"document_load_dispatch_failed document_id=%llu generation=%llu path=%.260s",
					static_cast<unsigned long long>(document_id),
					static_cast<unsigned long long>(generation), fpath.c_str());
			}
		};
		const auto submitted = aida::infra::executor::submit(std::move(sub));
		if (!submitted.submitted) {
			t.load_in_progress = false;
			t.load_failed = true;
			t.load_error = "The document load worker could not be scheduled: " + submitted.reject_reason;
			t.load_dispatch_failed.reset();
			document_load_controls.erase(document_id);
			diag::log_tagged_critical_fmt("file_tabs", "document_load_submit_failed path=%.260s reason=%s",
				fpath.c_str(), submitted.reject_reason.c_str());
		} else {
			document_load_controls[document_id].task_id = submitted.task_id;
			aida::ui::task_center::task_registration_t registration;
			registration.id = load_task_id;
			registration.source = "file_tabs";
			registration.owner = "Code Editor";
			registration.owner_view = "document.code";
			registration.owner_action = "file.open";
			registration.target = fpath;
			registration.label = "Load document";
			registration.stage = "Reading, decoding, and checking recovery state";
			registration.affected_entity = std::to_string(document_id);
			registration.cancellation_is_safe = true;
			registration.callbacks.focus = [document_id]() {
				const int target = find_document(document_id);
				if (!is_valid_tab_index(target)) return;
				switch_to(target);
			};
			if (!aida::ui::task_center::register_executor_job(
					submitted.task_id, std::move(registration))) {
				cancel->store(true, std::memory_order_release);
				aida::infra::executor::cancel(submitted.task_id);
				document_load_controls.erase(document_id);
				++t.load_generation;
				t.load_in_progress = false;
				t.load_failed = true;
				t.load_dispatch_failed.reset();
				t.load_error = "Task Center could not own document loading; the operation was cancelled.";
			}
		}
#endif
	}

	inline void observe_document_load_dispatch_failure(int idx) {
		if (!is_valid_tab_index(idx)) return;
		auto& tab = tabs[tab_index(idx)];
		if (!tab.load_dispatch_failed ||
			!tab.load_dispatch_failed->exchange(false, std::memory_order_acq_rel))
			return;
		const std::string task_id = "editor.load." +
			std::to_string(tab.document_id) + "." +
			std::to_string(tab.load_generation);
		const auto loading = document_load_controls.find(tab.document_id);
		if (loading != document_load_controls.end()) {
			if (loading->second.cancelled)
				loading->second.cancelled->store(true, std::memory_order_release);
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
			if (loading->second.task_id != 0)
				aida::infra::executor::cancel(loading->second.task_id);
#endif
			document_load_controls.erase(loading);
		}
		++tab.load_generation;
		tab.load_in_progress = false;
		tab.load_failed = true;
		tab.load_error = "Document loading completed, but its result could not return to the UI owner. Retry loading the document.";
		tab.load_dispatch_failed.reset();
		static_cast<void>(aida::ui::task_center::update_task(task_id,
			aida::ui::task_center::task_state_t::failed, 1.f,
			"Load result dispatch failed", tab.load_error));
	}

	inline void observe_document_save_dispatch_failure(int idx) {
		static_cast<void>(idx);
		for (auto& tab : tabs) {
			if (!tab.save_dispatch_failed ||
				!tab.save_dispatch_failed->exchange(false, std::memory_order_acq_rel))
				continue;
			const std::string task_id = "editor.save." +
				std::to_string(tab.document_id) + "." +
				std::to_string(tab.save_generation);
			++tab.save_generation;
			tab.save_in_progress = false;
			tab.dirty = true;
			tab.save_error = "The save worker completed, but its result could not return to the UI owner. The document remains unsaved; retry Save.";
			tab.save_dispatch_failed.reset();
			static_cast<void>(aida::ui::task_center::update_task(task_id,
				aida::ui::task_center::task_state_t::failed, 1.f,
				"Save result dispatch failed", tab.save_error));
		}
	}

	inline void switch_to(int idx, bool record_history) {
		if (!is_valid_tab_index(idx)) return;
		normalize_document_identities();
		if (idx == active_tab &&
			code_editor_widget::document_metadata(tabs[tab_index(idx)].document_id).found) {
			return;
		}
		if (record_history)
			record_navigation(active_tab);
		const int previous_active = active_tab;
		snapshot_active_to_tab();
		checkpoint_recovery(previous_active);
		active_tab = idx;
		active_document_by_group[tabs[tab_index(idx)].group_id] =
			tabs[tab_index(idx)].document_id;
		load_tab_into_editor(idx);
		code_editor_widget::select_document_for_actions(
			tabs[tab_index(idx)].document_id);
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
				code_editor_widget::get_document_caret(
					tabs[tab_index(active_tab)].document_id, line, column);
				destination.push_back({tabs[tab_index(active_tab)].document_id, line, column});
			}
			switch_to(target_index, false);
			code_editor_widget::set_document_caret(target.document_id,
				target.caret_line, target.caret_column);
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

	struct save_result_t {
		bool succeeded = false;
		std::string detail;
	};

	inline std::optional<save_result_t> shell_save_as_result;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	inline std::function<std::optional<save_result_t>(int)> preview_save_interceptor;
#endif

	inline save_result_t verify_tab_save_gate(int idx, bool require_destination) {
		if (!is_valid_tab_index(idx))
			return {false, "The document is no longer open."};
		const auto& tab = tabs[tab_index(idx)];
		if (tab.save_in_progress)
			return {false, "A save is already in progress for this document."};
		if (tab.recovery_operation_pending || tab.recovery_checkpoint_pending)
			return {false, "Wait for the active recovery operation to finish before saving."};
		if (tab.external_conflict && !tab.external_overwrite_approved)
			return {false, "The file changed on disk. Resolve the conflict before saving."};
		if (require_destination && tab.filepath.empty())
			return {false, "Use Save As to choose a destination."};
		return {true, {}};
	}

	struct save_all_preflight_t {
		save_result_t result;
		std::vector<std::uint64_t> documents;
	};

	inline save_all_preflight_t preflight_save_all() {
		save_all_preflight_t output{{true, {}}, {}};
		output.documents.reserve(tabs.size());
		for (std::size_t index = 0; index < tabs.size(); ++index) {
			const auto& tab = tabs[index];
			const auto metadata = code_editor_widget::document_metadata(tab.document_id);
			const bool dirty = metadata.found ? metadata.dirty : tab.dirty;
			if (!dirty)
				continue;
			const auto gate = verify_tab_save_gate(static_cast<int>(index), true);
			if (!gate.succeeded) {
				output.result = {false, tab.filename + ": " + gate.detail};
				output.documents.clear();
				return output;
			}
			output.documents.push_back(tab.document_id);
		}
		return output;
	}

	inline bool close_operation_pending(const OpenTab& tab) noexcept {
		return tab.save_in_progress || tab.recovery_operation_pending ||
			tab.recovery_checkpoint_pending;
	}

	inline std::string close_operation_detail(const OpenTab& tab) {
		if (tab.save_in_progress)
			return "Wait for the active atomic save to finish before closing this document.";
		if (tab.recovery_operation_pending)
			return "Wait for the active recovery operation to finish before closing this document.";
		if (tab.recovery_checkpoint_pending)
			return "Wait for the active recovery checkpoint to finish before closing this document.";
		return {};
	}

	inline std::uint64_t content_fingerprint(std::string_view content) {
		std::uint64_t hash = 14695981039346656037ULL;
		for (const char character : content) {
			hash ^= static_cast<unsigned char>(character);
			hash *= 1099511628211ULL;
		}
		hash ^= static_cast<std::uint64_t>(content.size());
		hash *= 1099511628211ULL;
		return hash == 0 ? 1 : hash;
	}

	inline aida::editor::programming_documents::document_record_t recovery_metadata_record(
			const OpenTab& tab) {
		aida::editor::programming_documents::document_record_t record;
		record.filename = tab.filename.empty() ? "Untitled" : tab.filename;
		record.canonical_path =
			aida::editor::programming_documents::canonical_path(tab.filepath);
		record.document_id = tab.document_id;
		record.base_fingerprint = tab.base_fingerprint;
		record.revision = tab.revision;
		record.content_hash = tab.content_hash == 0
			? content_fingerprint(tab.buffer) : tab.content_hash;
		record.byte_length = tab.buffer.size();
		record.group_id = tab.group_id;
		record.pinned = tab.pinned;
		record.dirty = tab.dirty;
		record.caret_line = tab.caret_line;
		record.caret_column = tab.caret_column;
		record.selection_anchor_line = tab.selection_anchor_line;
		record.selection_anchor_column = tab.selection_anchor_column;
		record.selection_active = tab.selection_active;
		record.scroll_x = tab.scroll_x;
		record.scroll_y = tab.scroll_y;
		record.folded_lines = tab.folded_lines;
		record.language_override = tab.language_override;
		record.text = tab.text_metadata;
		return record;
	}

	inline aida::editor::programming_documents::document_record_t recovery_record(
			const OpenTab& tab) {
		auto record = recovery_metadata_record(tab);
		record.content = tab.buffer;
		return record;
	}

	inline void observe_recovery_dispatch_failure(int idx) {
		if (!is_valid_tab_index(idx)) return;
		auto& tab = tabs[tab_index(idx)];
		if (tab.recovery_dispatch_failed &&
			tab.recovery_dispatch_failed->exchange(false, std::memory_order_acq_rel)) {
			const bool probe_failed =
				tab.recovery_operation_label == "Checking recovery journal";
			tab.recovery_operation_pending = false;
			tab.recovery_operation_label.clear();
			if (probe_failed)
				tab.recovery_probe_completed = true;
			tab.recovery_error = "Recovery completion could not return to the UI owner; retry the operation.";
			tab.recovery_dispatch_failed.reset();
		}
		if (tab.recovery_checkpoint_dispatch_failed &&
			tab.recovery_checkpoint_dispatch_failed->exchange(false, std::memory_order_acq_rel)) {
			tab.recovery_checkpoint_pending = false;
			tab.recovery_error = "Recovery checkpoint completion could not return to the UI owner; the next checkpoint will retry.";
			tab.recovery_checkpoint_dispatch_failed.reset();
		}
	}

	inline void request_recovery_probe(int idx) {
		if (!is_valid_tab_index(idx)) return;
		auto& tab = tabs[tab_index(idx)];
		observe_recovery_dispatch_failure(idx);
		if (tab.recovery_probe_completed || tab.recovery_operation_pending)
			return;
		const std::uint64_t document_id = tab.document_id;
		const std::uint64_t generation = ++tab.recovery_operation_generation;
		const std::string original_path = tab.filepath;
		const auto identity = recovery_metadata_record(tab);
		auto dispatch_failed = std::make_shared<std::atomic<bool>>(false);
		tab.recovery_dispatch_failed = dispatch_failed;
		tab.recovery_operation_pending = true;
		tab.recovery_operation_label = "Checking recovery journal";
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		static_cast<void>(document_id);
		static_cast<void>(generation);
		static_cast<void>(original_path);
		static_cast<void>(identity);
		static_cast<void>(dispatch_failed);
		tab.recovery_probe_completed = true;
		tab.recovery_operation_pending = false;
		tab.recovery_operation_label.clear();
		tab.recovery_dispatch_failed.reset();
#else
		aida::infra::executor::submission_t sub;
		sub.owner_subsystem = "file_tabs";
		sub.label = "file_tabs.recovery_probe";
		sub.thread_class = "blocking_file_io";
		sub.domain = aida::infra::executor::domain_t::feature_worker;
		sub.priority = 2;
		sub.generation = generation;
		sub.body = [identity, original_path, document_id, generation,
			dispatch_failed]() mutable {
			const auto migrated =
				aida::editor::programming_documents::migrate_legacy_snapshot(
					identity, original_path);
			auto recovery = aida::editor::programming_documents::probe(
				document_id, original_path);
			if (!migrated.succeeded && recovery.diagnostic.empty())
				recovery.diagnostic = migrated.detail;
			else if (!migrated.detail.empty())
				recovery.diagnostic = recovery.diagnostic.empty() ? migrated.detail
					: recovery.diagnostic + " " + migrated.detail;
			const bool posted = aida::ui_thread::post(
				[document_id, generation, recovery = std::move(recovery)]() mutable {
					const int current = find_document(document_id);
					if (!is_valid_tab_index(current)) return;
					auto& target = tabs[tab_index(current)];
					if (target.recovery_operation_generation != generation) return;
					target.recovery = std::move(recovery);
					target.recovery_probe_completed = true;
					target.recovery_operation_pending = false;
					target.recovery_operation_label.clear();
					target.recovery_dispatch_failed.reset();
					target.recovery_error = target.recovery.diagnostic;
					if (target.recovery.available &&
						target.recovery.metadata.content_hash == target.base_fingerprint)
						target.recovery_error = "The retained journal matches the current disk content; discard it after confirming no recovery is needed.";
					else if (target.recovery.available && target.base_fingerprint != 0 &&
						target.recovery.metadata.base_fingerprint != 0 &&
						target.recovery.metadata.base_fingerprint != target.base_fingerprint)
						target.recovery_error = "The disk base changed after this journal was captured. Compare before recovering.";
				}, "file_tabs", "recovery_probe_result", "worker_result");
			if (!posted)
				dispatch_failed->store(true, std::memory_order_release);
		};
		const auto submitted = aida::infra::executor::submit(std::move(sub));
		if (!submitted.submitted) {
			tab.recovery_operation_pending = false;
			tab.recovery_operation_label.clear();
			tab.recovery_dispatch_failed.reset();
			tab.recovery_probe_completed = true;
			tab.recovery_error = "Recovery probe scheduling failed: " + submitted.reject_reason;
		}
#endif
	}

	enum class recovery_load_mode_t : std::uint8_t { recover, compare };

	inline save_result_t request_recovery_load(int idx, recovery_load_mode_t mode) {
		if (!is_valid_tab_index(idx)) return {false, "The document is no longer open."};
		if (idx != active_tab)
			switch_to(idx);
		auto& tab = tabs[tab_index(idx)];
		observe_recovery_dispatch_failure(idx);
		if (!tab.recovery.available)
			return {false, "No verified recovery journal is available."};
		if (tab.recovery_operation_pending)
			return {false, "Another recovery operation is still running."};
		snapshot_active_to_tab();
		if (mode == recovery_load_mode_t::recover && tab.dirty)
			return {false, "Compare first or save the current changes; recovery will not overwrite newer unsaved work."};
		const auto reference = tab.recovery;
		const std::uint64_t document_id = tab.document_id;
		const std::uint64_t revision = tab.revision;
		const std::uint64_t content_hash = tab.content_hash;
		const std::uint64_t generation = ++tab.recovery_operation_generation;
		auto dispatch_failed = std::make_shared<std::atomic<bool>>(false);
		tab.recovery_dispatch_failed = dispatch_failed;
		tab.recovery_operation_pending = true;
		tab.recovery_operation_label = mode == recovery_load_mode_t::recover
			? "Loading recovery content" : "Preparing recovery comparison";
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		static_cast<void>(reference);
		static_cast<void>(document_id);
		static_cast<void>(revision);
		static_cast<void>(content_hash);
		static_cast<void>(generation);
		static_cast<void>(dispatch_failed);
		tab.recovery_operation_pending = false;
		tab.recovery_operation_label.clear();
		tab.recovery_dispatch_failed.reset();
		return {false, "Recovery storage is intentionally unavailable in deterministic Preview."};
#else
		aida::infra::executor::submission_t sub;
		sub.owner_subsystem = "file_tabs";
		sub.label = mode == recovery_load_mode_t::recover
			? "file_tabs.recovery_load" : "file_tabs.recovery_compare";
		sub.thread_class = "blocking_file_io";
		sub.domain = aida::infra::executor::domain_t::feature_worker;
		sub.priority = 2;
		sub.generation = generation;
		sub.body = [reference, document_id, revision, content_hash, generation,
			mode, dispatch_failed]() mutable {
			auto loaded = aida::editor::programming_documents::load(reference);
			const bool posted = aida::ui_thread::post(
				[document_id, revision, content_hash, generation, mode,
				 loaded = std::move(loaded)]() mutable {
					const int current = find_document(document_id);
					if (!is_valid_tab_index(current)) return;
					auto& target = tabs[tab_index(current)];
					if (target.recovery_operation_generation != generation) return;
					target.recovery_operation_pending = false;
					target.recovery_operation_label.clear();
					target.recovery_dispatch_failed.reset();
					if (!loaded.succeeded) {
						target.recovery_error = loaded.detail;
						return;
					}
					if (target.revision != revision || target.content_hash != content_hash) {
						target.recovery_error = "The editor changed while recovery content was loading; retry against the current revision.";
						return;
					}
					if (current != active_tab) {
						target.recovery_error = "The document lost editor focus while recovery content was loading; activate it and retry.";
						return;
					}
					if (mode == recovery_load_mode_t::compare) {
						if (!code_editor_widget::propose_document_content(target.document_id,
							target.revision, target.content_hash, target.buffer,
							loaded.document.content, "Crash recovery comparison")) {
							target.recovery_error = "The recovery comparison could not be bound to the current document revision.";
							return;
						}
						target.proposal_pending = true;
						return;
					}
					if (target.dirty) {
						target.recovery_error = "The editor became dirty while recovery content was loading; no content was replaced.";
						return;
					}
					target.buffer = std::move(loaded.document.content);
					target.buffer_loaded = true;
					target.dirty = true;
					target.load_failed = false;
					target.load_error.clear();
					target.revision = (std::max)(target.revision + 1, loaded.document.revision);
					target.content_hash = loaded.document.content_hash;
					target.text_metadata = loaded.document.text;
					target.caret_line = loaded.document.caret_line;
					target.caret_column = loaded.document.caret_column;
					target.scroll_x = loaded.document.scroll_x;
					target.scroll_y = loaded.document.scroll_y;
					target.recovery_error = "Recovered content is open as unsaved work; the journal remains retained until Save or confirmed discard.";
					static_cast<void>(code_editor_widget::load_document(
						target.document_id, target.revision, target.buffer,
						target.filename, target.filepath, true, target.caret_line,
						target.caret_column, target.scroll_x, target.scroll_y, true));
				}, "file_tabs", "recovery_load_result", "worker_result");
			if (!posted)
				dispatch_failed->store(true, std::memory_order_release);
		};
		const auto submitted = aida::infra::executor::submit(std::move(sub));
		if (!submitted.submitted) {
			tab.recovery_operation_pending = false;
			tab.recovery_operation_label.clear();
			tab.recovery_dispatch_failed.reset();
			tab.recovery_error = "Recovery load scheduling failed: " + submitted.reject_reason;
			return {false, tab.recovery_error};
		}
		return {true, {}};
#endif
	}

	inline save_result_t recover_from_journal(int idx) {
		return request_recovery_load(idx, recovery_load_mode_t::recover);
	}

	inline save_result_t compare_with_journal(int idx) {
		return request_recovery_load(idx, recovery_load_mode_t::compare);
	}

	inline save_result_t compare_with_disk(int idx) {
		if (!is_valid_tab_index(idx)) return {false, "The document is no longer open."};
		if (idx != active_tab) switch_to(idx);
		auto& tab = tabs[tab_index(idx)];
		observe_recovery_dispatch_failure(idx);
		if (tab.filepath.empty() || !tab.buffer_loaded)
			return {false, "Open a path-backed text document before comparing with disk."};
		if (tab.recovery_operation_pending)
			return {false, "Another document comparison or recovery operation is still running."};
		snapshot_active_to_tab();
		const std::uint64_t document_id = tab.document_id;
		const std::uint64_t revision = tab.revision;
		const std::uint64_t content_hash = tab.content_hash;
		const std::uint64_t generation = ++tab.recovery_operation_generation;
		const std::string path = tab.filepath;
		auto dispatch_failed = std::make_shared<std::atomic<bool>>(false);
		tab.recovery_dispatch_failed = dispatch_failed;
		tab.recovery_operation_pending = true;
		tab.recovery_operation_label = "Preparing disk comparison";
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		static_cast<void>(document_id);
		static_cast<void>(revision);
		static_cast<void>(content_hash);
		static_cast<void>(generation);
		static_cast<void>(path);
		static_cast<void>(dispatch_failed);
		tab.recovery_operation_pending = false;
		tab.recovery_operation_label.clear();
		tab.recovery_dispatch_failed.reset();
		return {false, "Disk comparison is intentionally unavailable in deterministic Preview."};
#else
		aida::infra::executor::submission_t sub;
		sub.owner_subsystem = "file_tabs";
		sub.label = "file_tabs.disk_compare";
		sub.thread_class = "blocking_file_io";
		sub.domain = aida::infra::executor::domain_t::feature_worker;
		sub.priority = 2;
		sub.generation = generation;
		sub.body = [document_id, revision, content_hash, generation, path,
			dispatch_failed]() mutable {
			std::string content;
			std::string error;
			std::error_code ec;
			const auto size = std::filesystem::file_size(path, ec);
			if (ec)
				error = "The disk file size could not be read: " + ec.message();
			else if (size > aida::editor::programming_documents::maximum_editable_document_bytes)
				error = "Disk comparison is limited to the 1 MiB bounded editable text model.";
			else {
				std::ifstream input(path, std::ios::binary);
				if (!input.is_open())
					error = "The disk file could not be opened for comparison.";
				else {
					content.resize(static_cast<std::size_t>(size));
					if (!content.empty())
						input.read(content.data(), static_cast<std::streamsize>(content.size()));
					if ((!content.empty() && input.gcount() !=
							static_cast<std::streamsize>(content.size())) || input.bad())
						error = "The complete disk file could not be read for comparison.";
				}
			}
			if (error.empty()) {
				auto decoded = aida::editor::programming_documents::decode_file_bytes(content);
				if (!decoded.succeeded)
					error = std::move(decoded.detail);
				else
					content = std::move(decoded.text);
			}
			const bool posted = aida::ui_thread::post(
				[document_id, revision, content_hash, generation,
				 content = std::move(content), error = std::move(error)]() mutable {
					const int current = find_document(document_id);
					if (!is_valid_tab_index(current)) return;
					auto& target = tabs[tab_index(current)];
					if (target.recovery_operation_generation != generation) return;
					target.recovery_operation_pending = false;
					target.recovery_operation_label.clear();
					target.recovery_dispatch_failed.reset();
					if (!error.empty()) {
						target.recovery_error = std::move(error);
						return;
					}
					if (target.revision != revision || target.content_hash != content_hash ||
						current != active_tab) {
						target.recovery_error = "The editor changed or lost focus while disk content was loading; activate it and retry.";
						return;
					}
					if (!code_editor_widget::propose_document_content(target.document_id,
							target.revision, target.content_hash, target.buffer,
							content, "Disk comparison")) {
						target.recovery_error = "The disk comparison could not be bound to the current document revision.";
						return;
					}
					target.proposal_pending = true;
				}, "file_tabs", "disk_compare_result", "worker_result");
			if (!posted)
				dispatch_failed->store(true, std::memory_order_release);
		};
		const auto submitted = aida::infra::executor::submit(std::move(sub));
		if (!submitted.submitted) {
			tab.recovery_operation_pending = false;
			tab.recovery_operation_label.clear();
			tab.recovery_dispatch_failed.reset();
			tab.recovery_error = "Disk comparison scheduling failed: " + submitted.reject_reason;
			return {false, tab.recovery_error};
		}
		return {true, {}};
#endif
	}

	inline save_result_t discard_recovery(int idx) {
		if (!is_valid_tab_index(idx)) return {false, "The document is no longer open."};
		auto& tab = tabs[tab_index(idx)];
		observe_recovery_dispatch_failure(idx);
		if (!tab.recovery.available)
			return {false, "No verified recovery journal is available."};
		if (tab.recovery_operation_pending)
			return {false, "Another recovery operation is still running."};
		const auto reference = tab.recovery;
		const std::uint64_t document_id = tab.document_id;
		const std::uint64_t generation = ++tab.recovery_operation_generation;
		auto dispatch_failed = std::make_shared<std::atomic<bool>>(false);
		tab.recovery_dispatch_failed = dispatch_failed;
		tab.recovery_operation_pending = true;
		tab.recovery_operation_label = "Discarding recovery journals";
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		static_cast<void>(reference);
		static_cast<void>(document_id);
		static_cast<void>(generation);
		static_cast<void>(dispatch_failed);
		tab.recovery_operation_pending = false;
		tab.recovery_operation_label.clear();
		tab.recovery_dispatch_failed.reset();
		return {true, {}};
#else
		aida::infra::executor::submission_t sub;
		sub.owner_subsystem = "file_tabs";
		sub.label = "file_tabs.recovery_discard";
		sub.thread_class = "blocking_file_io";
		sub.domain = aida::infra::executor::domain_t::feature_worker;
		sub.priority = 2;
		sub.generation = generation;
		sub.body = [reference, document_id, generation, dispatch_failed]() mutable {
			const auto discarded =
				aida::editor::programming_documents::discard(reference);
			const bool posted = aida::ui_thread::post(
				[document_id, generation, discarded]() mutable {
					const int current = find_document(document_id);
					if (!is_valid_tab_index(current)) return;
					auto& target = tabs[tab_index(current)];
					if (target.recovery_operation_generation != generation) return;
					target.recovery_operation_pending = false;
					target.recovery_operation_label.clear();
					target.recovery_dispatch_failed.reset();
					if (!discarded.succeeded) {
						target.recovery_error = discarded.detail;
						return;
					}
					target.recovery = {};
					target.recovery_error.clear();
					target.recovery_probe_completed = true;
				}, "file_tabs", "recovery_discard_result", "worker_result");
			if (!posted)
				dispatch_failed->store(true, std::memory_order_release);
		};
		const auto submitted = aida::infra::executor::submit(std::move(sub));
		if (!submitted.submitted) {
			tab.recovery_operation_pending = false;
			tab.recovery_operation_label.clear();
			tab.recovery_dispatch_failed.reset();
			tab.recovery_error = "Recovery discard scheduling failed: " + submitted.reject_reason;
			return {false, tab.recovery_error};
		}
		return {true, {}};
#endif
	}

	inline save_result_t request_recovery_discard(int idx) {
		if (!is_valid_tab_index(idx)) return {false, "The document is no longer open."};
		if (!tabs[tab_index(idx)].recovery.available)
			return {false, "No verified recovery journal is available."};
		if (tabs[tab_index(idx)].recovery_operation_pending)
			return {false, "Another recovery operation is still running."};
		pending_recovery_discard_document = tabs[tab_index(idx)].document_id;
		if (idx != active_tab)
			switch_to(idx);
		return {true, {}};
	}

	inline void schedule_confirmed_recovery_cleanup(
			aida::editor::programming_documents::document_record_t identity,
			std::uint64_t outcome_revision) {
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		static_cast<void>(identity);
		static_cast<void>(outcome_revision);
#else
		const std::uint64_t document_id = identity.document_id;
		aida::infra::executor::submission_t sub;
		sub.owner_subsystem = "file_tabs";
		sub.label = "file_tabs.recovery_cleanup";
		sub.thread_class = "blocking_file_io";
		sub.domain = aida::infra::executor::domain_t::feature_worker;
		sub.priority = 1;
		sub.body = [document_id, outcome_revision, identity]() mutable {
			const auto sealed =
				aida::editor::programming_documents::seal_clean_outcome(
					identity, outcome_revision);
			if (!sealed.succeeded)
				diag::log_tagged_critical_fmt("file_tabs",
					"recovery_cleanup_failed document_id=%llu reason=%.512s",
					static_cast<unsigned long long>(document_id),
					sealed.detail.c_str());
			else if (!sealed.changed && !sealed.detail.empty())
				diag::log_tagged_fmt("file_tabs",
					"recovery_cleanup_preserved document_id=%llu outcome_revision=%llu detail=%.512s",
					static_cast<unsigned long long>(document_id),
					static_cast<unsigned long long>(outcome_revision),
					sealed.detail.c_str());
		};
		const auto submitted = aida::infra::executor::submit(std::move(sub));
		if (!submitted.submitted)
			diag::log_tagged_critical_fmt("file_tabs",
				"recovery_cleanup_submit_failed document_id=%llu reason=%.512s",
				static_cast<unsigned long long>(document_id),
				submitted.reject_reason.c_str());
#endif
	}

	inline void schedule_confirmed_recovery_cleanup(const OpenTab& tab) {
		schedule_confirmed_recovery_cleanup(recovery_metadata_record(tab), tab.revision);
	}

	inline int find_path_document(const std::string& path) {
		std::string expected = std::filesystem::path(path).lexically_normal().generic_string();
		std::transform(expected.begin(), expected.end(), expected.begin(),
			[](unsigned char value) { return static_cast<char>(std::tolower(value)); });
		for (std::size_t index = 0; index < tabs.size(); ++index) {
			std::string candidate = std::filesystem::path(tabs[index].filepath)
				.lexically_normal().generic_string();
			std::transform(candidate.begin(), candidate.end(), candidate.begin(),
				[](unsigned char value) { return static_cast<char>(std::tolower(value)); });
			if (!candidate.empty() && candidate == expected)
				return static_cast<int>(index);
		}
		return -1;
	}

	inline bool request_document_open(const std::string& fpath, const std::string& fname,
		int caret_line, int caret_column) {
		if (fpath.empty()) return false;
		int index = find_path_document(fpath);
		if (!is_valid_tab_index(index)) {
			const std::uint32_t target_group = is_valid_tab_index(active_tab)
				? tabs[tab_index(active_tab)].group_id : 0;
			snapshot_active_to_tab();
			OpenTab tab;
			tab.filename = fname.empty() ? std::filesystem::path(fpath).filename().string() : fname;
			tab.filepath = fpath;
			tab.group_id = target_group;
			tabs.push_back(std::move(tab));
			index = static_cast<int>(tabs.size()) - 1;
			normalize_document_identities();
		}
		auto& tab = tabs[tab_index(index)];
		if (caret_line >= 0) {
			tab.caret_line = caret_line;
			tab.caret_column = (std::max)(0, caret_column);
			tab.pending_caret_navigation = !tab.buffer_loaded;
		}
		switch_to(index);
		if (tab.buffer_loaded && caret_line >= 0)
			code_editor_widget::set_document_caret(tab.document_id,
				tab.caret_line, tab.caret_column);
		return tab.buffer_loaded || tab.load_in_progress || tab.load_failed;
	}

	inline bool cancel_document_load(std::uint64_t document_id) {
		const int index = find_document(document_id);
		if (!is_valid_tab_index(index)) return false;
		auto& tab = tabs[tab_index(index)];
		const auto loading = document_load_controls.find(document_id);
		if (loading == document_load_controls.end()) return false;
		if (loading->second.cancelled)
			loading->second.cancelled->store(true, std::memory_order_release);
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
		if (loading->second.task_id != 0)
			aida::infra::executor::cancel(loading->second.task_id);
#endif
		document_load_controls.erase(loading);
		++tab.load_generation;
		tab.load_in_progress = false;
		tab.load_dispatch_failed.reset();
		tab.load_failed = true;
		tab.load_error = "Document loading was cancelled.";
		return true;
	}

	inline bool stage_external_proposal(const std::string& path,
			const std::string& proposed_content, const std::string& origin,
			std::string& detail) {
		const int index = find_path_document(path);
		if (!is_valid_tab_index(index))
			return false;
		snapshot_active_to_tab();
		auto& tab = tabs[tab_index(index)];
		const auto metadata = code_editor_widget::document_metadata(tab.document_id);
		if (metadata.found) {
			tab.dirty = metadata.dirty;
			tab.revision = metadata.revision;
		}
		if (!tab.dirty)
			return false;
		const auto payload = code_editor_widget::document_payload(
			tab.document_id, tab.revision);
		if (!payload.found || payload.read_only) {
			detail = "The current document revision could not be captured for review.";
			return true;
		}
		tab.buffer = payload.content;
		tab.content_hash = payload.content_hash;
		if (!code_editor_widget::propose_document_content(tab.document_id,
				payload.revision, payload.content_hash, payload.content,
				proposed_content, origin)) {
			detail = "The editor could not create a revision-bound review.";
			return true;
		}
		tab.proposal_pending = true;
		detail = "The file has unsaved human edits. The requested change is pending in the editor review and was not written to disk.";
		return true;
	}

	inline void accept_external_write(const std::string& path,
			const std::string& content) {
		const int index = find_path_document(path);
		if (!is_valid_tab_index(index)) return;
		auto& tab = tabs[tab_index(index)];
		const auto metadata = code_editor_widget::document_metadata(tab.document_id);
		if ((metadata.found && metadata.dirty) || tab.dirty) return;
		tab.buffer = content;
		tab.buffer_loaded = true;
		tab.content_hash = content_fingerprint(content);
		++tab.revision;
		tab.proposal_pending = false;
		tab.disk_write_version = 0;
		static_cast<void>(code_editor_widget::load_document(tab.document_id,
			tab.revision, tab.buffer, tab.filename, tab.filepath, false,
			tab.caret_line, tab.caret_column, tab.scroll_x, tab.scroll_y, true));
	}

	inline save_result_t atomic_write_file(const std::string& path,
			const std::string& content) {
		if (path.empty()) return {false, "No destination path was selected."};
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		static_cast<void>(content);
		return {true, {}};
#else
		const std::filesystem::path destination(path);
		const auto parent = destination.parent_path();
		std::error_code ec;
		if (!parent.empty() && !std::filesystem::exists(parent, ec))
			return {false, "The destination directory does not exist."};
		static std::atomic<std::uint64_t> sequence{1};
		std::filesystem::path temporary;
		HANDLE handle = INVALID_HANDLE_VALUE;
		for (int attempt = 0; attempt < 32 && handle == INVALID_HANDLE_VALUE; ++attempt) {
			temporary = destination;
			temporary += L".aida-save-" + std::to_wstring(GetCurrentProcessId()) + L"-" +
				std::to_wstring(sequence.fetch_add(1, std::memory_order_relaxed)) + L".tmp";
			handle = CreateFileW(temporary.c_str(), GENERIC_WRITE, 0, nullptr,
				CREATE_NEW, FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_WRITE_THROUGH, nullptr);
		}
		if (handle == INVALID_HANDLE_VALUE)
			return {false, "Could not create a same-directory temporary save file (Win32 " +
				std::to_string(GetLastError()) + ")."};
		bool write_ok = true;
		std::size_t offset = 0;
		while (offset < content.size()) {
			const DWORD requested = static_cast<DWORD>((std::min)(
				content.size() - offset, static_cast<std::size_t>(0x7ffff000U)));
			DWORD written = 0;
			if (!WriteFile(handle, content.data() + offset, requested, &written, nullptr) ||
				written != requested) {
				write_ok = false;
				break;
			}
			offset += written;
		}
		if (write_ok)
			write_ok = FlushFileBuffers(handle) != FALSE;
		DWORD io_error = write_ok ? ERROR_SUCCESS : GetLastError();
		if (!CloseHandle(handle) && write_ok) {
			write_ok = false;
			io_error = GetLastError();
		}
		if (write_ok) {
			const auto bytes = std::filesystem::file_size(temporary, ec);
			write_ok = !ec && bytes == content.size();
			if (!write_ok)
				io_error = ec ? static_cast<DWORD>(ec.value()) : ERROR_WRITE_FAULT;
		}
		if (!write_ok) {
			DeleteFileW(temporary.c_str());
			return {false, "The complete file could not be written and flushed (Win32 " +
				std::to_string(io_error) + ")."};
		}
		const bool exists = std::filesystem::exists(destination, ec) && !ec;
		BOOL replaced = exists
			? ReplaceFileW(destination.c_str(), temporary.c_str(), nullptr,
				REPLACEFILE_WRITE_THROUGH, nullptr, nullptr)
			: MoveFileExW(temporary.c_str(), destination.c_str(), MOVEFILE_WRITE_THROUGH);
		if (!replaced) {
			const DWORD error = GetLastError();
			DeleteFileW(temporary.c_str());
			return {false, "Atomic destination replacement failed (Win32 " +
				std::to_string(error) + ")."};
		}
		return {true, {}};
#endif
	}

	inline save_result_t save_tab_to_disk_result(int idx,
			const std::string* destination_override = nullptr,
			bool gate_preflight_complete = false) {
		if (!is_valid_tab_index(idx))
			return {false, "The document is no longer open."};
		if (!gate_preflight_complete) {
			const auto gate = verify_tab_save_gate(idx, destination_override == nullptr);
			if (!gate.succeeded) return gate;
		}
		auto& t = tabs[tab_index(idx)];
		const std::string destination = destination_override ? *destination_override : t.filepath;
		if (destination.empty()) return {false, "Use Save As to choose a destination."};
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		if (preview_save_interceptor) {
			if (auto intercepted = preview_save_interceptor(idx))
				return *intercepted;
		}
#endif
		code_editor_widget::document_payload_snapshot_t payload;
		try {
			payload = code_editor_widget::document_payload(t.document_id);
		} catch (const std::bad_alloc&) {
			return {false, "The bounded document revision could not be captured because memory allocation failed."};
		}
		if (!payload.found || payload.read_only)
			return {false, "The current editable document revision could not be captured."};
		if (payload.content.size() >
			aida::editor::programming_documents::maximum_editable_document_bytes)
			return {false, "The document exceeds the bounded editable save payload."};
		const std::uint64_t document_id = t.document_id;
		const std::uint64_t revision = payload.revision;
		const std::uint64_t content_hash = payload.content_hash;
		const std::string saved_filename = destination_override
			? std::filesystem::path(destination).filename().string() : t.filename;
		const auto text_metadata = t.text_metadata;
		const bool save_as = destination_override != nullptr;
		const std::uint64_t generation = ++t.save_generation;
		const std::string save_task_id = "editor.save." +
			std::to_string(document_id) + "." + std::to_string(generation);
		t.save_in_progress = true;
		t.save_error.clear();
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		const auto encoded = aida::editor::programming_documents::encode_file_text(
			payload.content, text_metadata);
		if (!encoded.succeeded) {
			t.save_in_progress = false;
			t.save_error = encoded.detail;
			return {false, encoded.detail};
		}
		const auto written = atomic_write_file(destination, encoded.bytes);
		if (!written.succeeded) {
			t.save_in_progress = false;
			t.save_error = written.detail;
			return written;
		}
		t.save_in_progress = false;
		t.buffer = payload.content;
		t.buffer_loaded = true;
		t.revision = revision;
		++t.recovery_operation_generation;
		t.recovery_operation_pending = false;
		t.recovery_operation_label.clear();
		t.recovery_dispatch_failed.reset();
		t.dirty = false;
		t.base_fingerprint = content_hash;
		t.content_hash = content_hash;
		t.recovery = {};
		t.recovery_error.clear();
		t.recovery_probe_completed = true;
		t.external_conflict = false;
		t.external_overwrite_approved = false;
		if (save_as) {
			t.filepath = destination;
			t.filename = saved_filename;
		}
		t.disk_write_version = disk_write_version(t.filepath);
		code_editor_widget::mark_document_saved(document_id, revision,
			t.filename, t.filepath);
		schedule_confirmed_recovery_cleanup(t);
		return {true, {}};
#else
		const std::int64_t expected_disk_version = save_as ? 0 : t.disk_write_version;
		auto dispatch_failed = std::make_shared<std::atomic<bool>>(false);
		auto cancelled = std::make_shared<std::atomic<bool>>(false);
		t.save_dispatch_failed = dispatch_failed;
		aida::infra::executor::submission_t sub;
		sub.owner_subsystem = "file_tabs";
		sub.label = "file_tabs.document_save";
		sub.thread_class = "blocking_file_io";
		sub.domain = aida::infra::executor::domain_t::feature_worker;
		sub.priority = 3;
		sub.generation = generation;
		sub.ui_access_policy = "immutable_document_revision";
		sub.failure_policy = "retain_dirty_document";
		sub.shutdown_policy = "finish_atomic_write";
		sub.cancel_hook = [cancelled]() {
			cancelled->store(true, std::memory_order_release);
		};
		sub.body = [document_id, revision, content_hash, generation, destination,
			saved_filename, save_as, expected_disk_version, text_metadata,
			save_task_id, content = payload.content, dispatch_failed, cancelled]() mutable {
			save_result_t result;
			try {
				if (cancelled->load(std::memory_order_acquire)) {
					result = {false, "The save was cancelled before destination replacement."};
				} else if (!save_as && expected_disk_version != 0 &&
					disk_write_version(destination) != expected_disk_version) {
					result = {false, "The file changed on disk after save was requested. Resolve the conflict and retry."};
				} else {
					auto encoded = aida::editor::programming_documents::encode_file_text(
						content, text_metadata);
					result = encoded.succeeded
						? atomic_write_file(destination, encoded.bytes)
						: save_result_t{false, encoded.detail};
				}
			} catch (const std::bad_alloc&) {
				result = {false, "The bounded save payload could not be encoded because memory allocation failed."};
			}
			const std::int64_t completed_write_version = result.succeeded
				? disk_write_version(destination) : 0;
			const bool posted = aida::ui_thread::post(
				[document_id, revision, content_hash, generation, destination,
				 saved_filename, save_as, text_metadata, content = std::move(content),
				 save_task_id, result = std::move(result), completed_write_version]() mutable {
					const int current = find_document(document_id);
					if (!is_valid_tab_index(current)) return;
					auto& tab = tabs[tab_index(current)];
					if (tab.save_generation != generation) return;
					tab.save_in_progress = false;
					tab.save_dispatch_failed.reset();
					if (!result.succeeded) {
						tab.save_error = result.detail;
						static_cast<void>(aida::ui::task_center::update_task(save_task_id,
							aida::ui::task_center::task_state_t::failed, 1.f,
							"Save failed", result.detail));
						if (result.detail.find("changed on disk") != std::string::npos)
							tab.external_conflict = true;
						return;
					}
					if (save_as) {
						tab.filepath = destination;
						tab.filename = saved_filename;
					}
					tab.disk_write_version = completed_write_version;
					tab.external_observed_write_version = 0;
					tab.text_metadata = text_metadata;
					tab.external_conflict = false;
					tab.external_overwrite_approved = false;
					tab.base_fingerprint = content_hash;
					tab.save_error.clear();
					code_editor_widget::mark_document_saved(document_id, revision,
						tab.filename, tab.filepath);
					auto identity = recovery_metadata_record(tab);
					identity.filename = saved_filename;
					identity.canonical_path =
						aida::editor::programming_documents::canonical_path(destination);
					identity.original_path = destination;
					identity.revision = revision;
					identity.content_hash = content_hash;
					identity.base_fingerprint = content_hash;
					identity.byte_length = content.size();
					identity.dirty = false;
					identity.text = text_metadata;
					schedule_confirmed_recovery_cleanup(std::move(identity), revision);
					const auto current_payload =
						code_editor_widget::document_payload(document_id, revision);
					if (current_payload.found && current_payload.content_hash == content_hash) {
						tab.buffer = std::move(content);
						tab.buffer_loaded = true;
						tab.revision = revision;
						tab.dirty = false;
						tab.base_fingerprint = content_hash;
						tab.content_hash = content_hash;
						tab.recovery = {};
						tab.recovery_error.clear();
						tab.recovery_probe_completed = true;
						static_cast<void>(aida::ui::task_center::update_task(save_task_id,
							aida::ui::task_center::task_state_t::completed, 1.f,
							"Save complete", "Saved exact document revision."));
					} else {
						tab.dirty = true;
						tab.content_hash = 0;
						if (tab.recovery.available &&
							tab.recovery.metadata.revision <= revision)
							tab.recovery = {};
						tab.save_error = "Saved the requested revision; newer edits remain unsaved.";
						static_cast<void>(aida::ui::task_center::update_task(save_task_id,
							aida::ui::task_center::task_state_t::partial, 1.f,
							"Saved requested revision; newer edits remain",
							tab.save_error));
					}
				}, "file_tabs", "document_save_result", "worker_result");
			if (!posted)
				dispatch_failed->store(true, std::memory_order_release);
		};
		const auto submitted = aida::infra::executor::submit(std::move(sub));
		if (!submitted.submitted) {
			t.save_in_progress = false;
			t.save_dispatch_failed.reset();
			t.save_error = "The document save worker could not be scheduled: " +
				submitted.reject_reason;
			return {false, t.save_error};
		}
		aida::ui::task_center::task_registration_t registration;
		registration.id = save_task_id;
		registration.source = "file_tabs";
		registration.owner = "Code Editor";
		registration.owner_view = "document.code";
		registration.owner_action = save_as ? "file.save_as" : "file.save";
		registration.target = destination;
		registration.label = save_as ? "Save document as" : "Save document";
		registration.stage = "Encoding and atomically replacing destination";
		registration.affected_entity = std::to_string(document_id);
		registration.callbacks.focus = [document_id]() {
			const int target = find_document(document_id);
			if (!is_valid_tab_index(target)) return;
			switch_to(target);
		};
		if (!aida::ui::task_center::register_executor_job(
				submitted.task_id, std::move(registration))) {
			aida::infra::executor::cancel(submitted.task_id);
			++t.save_generation;
			t.save_in_progress = false;
			t.save_dispatch_failed.reset();
			t.save_error = "Task Center could not own the save operation. Cancellation was requested; if destination replacement had already begun, verify the file before retrying.";
			return {false, t.save_error};
		}
		return {true, "Save scheduled in Task Center."};
#endif
	}

	inline bool save_tab_to_disk(int idx) {
		return save_tab_to_disk_result(idx).succeeded;
	}

	inline save_result_t save_tab_as(int idx, const std::string& destination) {
		return save_tab_to_disk_result(idx, &destination);
	}

	struct save_all_item_t {
		std::uint64_t document_id = 0;
		std::uint64_t revision = 0;
		std::uint64_t content_hash = 0;
		std::uint64_t generation = 0;
		std::int64_t expected_disk_version = 0;
		std::string destination;
		std::string filename;
		std::string content;
		aida::editor::programming_documents::text_metadata_t text_metadata;
		std::shared_ptr<std::atomic<bool>> dispatch_failed;
	};

	inline save_result_t save_all_tabs_result() {
		const auto gated = preflight_save_all();
		if (!gated.result.succeeded)
			return gated.result;
		if (gated.documents.empty())
			return {false, "No modified documents need saving."};
		std::vector<save_all_item_t> items;
		try {
			items.reserve(gated.documents.size());
			for (const auto document_id : gated.documents) {
				const int index = find_document(document_id);
				if (!is_valid_tab_index(index))
					return {false, "A modified document closed during Save All preflight."};
				auto& tab = tabs[tab_index(index)];
				const auto gate = verify_tab_save_gate(index, true);
				if (!gate.succeeded)
					return {false, tab.filename + ": " + gate.detail};
				auto payload = code_editor_widget::document_payload(document_id);
				if (!payload.found || payload.read_only)
					return {false, tab.filename +
						": The exact editable revision could not be captured."};
				if (payload.content.size() >
					aida::editor::programming_documents::maximum_editable_document_bytes)
					return {false, tab.filename +
						": The document exceeds the bounded editable save payload."};
				save_all_item_t item;
				item.document_id = document_id;
				item.revision = payload.revision;
				item.content_hash = payload.content_hash;
				item.expected_disk_version = tab.disk_write_version;
				item.destination = tab.filepath;
				item.filename = tab.filename;
				item.content = std::move(payload.content);
				item.text_metadata = tab.text_metadata;
				item.dispatch_failed = std::make_shared<std::atomic<bool>>(false);
				items.push_back(std::move(item));
			}
		} catch (const std::bad_alloc&) {
			return {false, "The complete bounded Save All revision set could not be captured."};
		}
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		for (auto& item : items) {
			const int index = find_document(item.document_id);
			if (!is_valid_tab_index(index))
				return {false, "A modified document closed after Save All preflight."};
			const auto result = save_tab_to_disk_result(index, nullptr, true);
			if (!result.succeeded)
				return result;
		}
		return {true, {}};
#else
		std::shared_ptr<std::vector<save_all_item_t>> batch;
		try {
			batch = std::make_shared<std::vector<save_all_item_t>>(std::move(items));
		} catch (const std::bad_alloc&) {
			return {false, "The complete bounded Save All batch could not be allocated."};
		}
		for (auto& item : *batch) {
			const int index = find_document(item.document_id);
			if (!is_valid_tab_index(index))
				return {false, "A modified document closed after Save All preflight."};
			auto& tab = tabs[tab_index(index)];
			item.generation = ++tab.save_generation;
			tab.save_in_progress = true;
			tab.save_error.clear();
			tab.save_dispatch_failed = item.dispatch_failed;
		}
		auto cancelled = std::make_shared<std::atomic<bool>>(false);
		static std::atomic<std::uint64_t> save_all_serial{0};
		const std::string task_id = "editor.save_all." +
			std::to_string(aida::shell_platform::tick_ms()) + "." +
			std::to_string(save_all_serial.fetch_add(1, std::memory_order_relaxed) + 1);
		aida::infra::executor::submission_t submission;
		submission.owner_subsystem = "file_tabs";
		submission.label = "file_tabs.document_save_all";
		submission.thread_class = "blocking_file_io";
		submission.domain = aida::infra::executor::domain_t::feature_worker;
		submission.priority = 3;
		submission.ui_access_policy = "immutable_document_revision_set";
		submission.failure_policy = "retain_dirty_document_set";
		submission.shutdown_policy = "finish_atomic_write_set";
		submission.cancel_hook = [cancelled]() {
			cancelled->store(true, std::memory_order_release);
		};
		submission.body = [batch, cancelled, task_id]() mutable {
			struct outcome_t {
				std::size_t item_index = 0;
				save_result_t result;
				std::int64_t completed_write_version = 0;
			};
			std::vector<outcome_t> outcomes;
			try {
				outcomes.reserve(batch->size());
			} catch (const std::bad_alloc&) {
				for (const auto& item : *batch)
					item.dispatch_failed->store(true, std::memory_order_release);
				return;
			}
			for (std::size_t item_index = 0; item_index < batch->size(); ++item_index) {
				const auto& item = (*batch)[item_index];
				save_result_t result;
				try {
					if (cancelled->load(std::memory_order_acquire))
						result = {false, "Save All was cancelled before destination replacement."};
					else if (item.expected_disk_version != 0 &&
						disk_write_version(item.destination) != item.expected_disk_version)
						result = {false, "The file changed on disk after Save All was requested."};
					else {
						auto encoded = aida::editor::programming_documents::encode_file_text(
							item.content, item.text_metadata);
						result = encoded.succeeded
							? atomic_write_file(item.destination, encoded.bytes)
							: save_result_t{false, encoded.detail};
					}
				} catch (const std::bad_alloc&) {
					result = {false, "The bounded save payload could not be encoded."};
				}
				const auto completed = result.succeeded
					? disk_write_version(item.destination) : 0;
				outcomes.push_back({item_index, std::move(result), completed});
			}
			const bool posted = aida::ui_thread::post(
				[batch, outcomes = std::move(outcomes), task_id]() mutable {
					std::size_t failures = 0;
					for (auto& outcome : outcomes) {
						auto& item = (*batch)[outcome.item_index];
						const int index = find_document(item.document_id);
						if (!is_valid_tab_index(index))
							continue;
						auto& tab = tabs[tab_index(index)];
						if (tab.save_generation != item.generation)
							continue;
						tab.save_in_progress = false;
						tab.save_dispatch_failed.reset();
						if (!outcome.result.succeeded) {
							++failures;
							tab.save_error = outcome.result.detail;
							if (outcome.result.detail.find("changed on disk") != std::string::npos)
								tab.external_conflict = true;
							continue;
						}
						tab.disk_write_version = outcome.completed_write_version;
						tab.external_observed_write_version = 0;
						tab.text_metadata = item.text_metadata;
						tab.external_conflict = false;
						tab.external_overwrite_approved = false;
						tab.base_fingerprint = item.content_hash;
						tab.save_error.clear();
						code_editor_widget::mark_document_saved(item.document_id,
							item.revision, tab.filename, tab.filepath);
						auto identity = recovery_metadata_record(tab);
						identity.revision = item.revision;
						identity.content_hash = item.content_hash;
						identity.base_fingerprint = item.content_hash;
						identity.byte_length = item.content.size();
						identity.dirty = false;
						identity.text = item.text_metadata;
						schedule_confirmed_recovery_cleanup(std::move(identity),
							item.revision);
						const auto current_payload = code_editor_widget::document_payload(
							item.document_id, item.revision);
						if (current_payload.found &&
							current_payload.content_hash == item.content_hash) {
							tab.buffer = std::move(item.content);
							tab.buffer_loaded = true;
							tab.revision = item.revision;
							tab.dirty = false;
							tab.content_hash = item.content_hash;
							tab.recovery = {};
							tab.recovery_error.clear();
							tab.recovery_probe_completed = true;
						} else {
							tab.dirty = true;
							tab.content_hash = 0;
							tab.save_error = "Saved the requested revision; newer edits remain unsaved.";
						}
					}
					static_cast<void>(aida::ui::task_center::update_task(task_id,
						failures == 0 ? aida::ui::task_center::task_state_t::completed
							: aida::ui::task_center::task_state_t::partial,
						1.f, failures == 0 ? "Save All complete" : "Save All completed with failures",
						failures == 0 ? "Saved the complete captured revision set."
							: std::to_string(failures) + " document save(s) failed."));
				}, "file_tabs", "document_save_all_result", "worker_result");
			if (!posted)
				for (const auto& item : *batch)
					item.dispatch_failed->store(true, std::memory_order_release);
		};
		const auto submitted = aida::infra::executor::submit(std::move(submission));
		if (!submitted.submitted) {
			for (const auto& item : *batch) {
				const int index = find_document(item.document_id);
				if (!is_valid_tab_index(index)) continue;
				auto& tab = tabs[tab_index(index)];
				if (tab.save_generation != item.generation) continue;
				tab.save_in_progress = false;
				tab.save_dispatch_failed.reset();
				tab.save_error = "Save All could not be scheduled: " + submitted.reject_reason;
			}
			return {false, "Save All could not be scheduled: " + submitted.reject_reason};
		}
		aida::ui::task_center::task_registration_t registration;
		registration.id = task_id;
		registration.source = "file_tabs";
		registration.owner = "Code Editor";
		registration.owner_view = "document.code";
		registration.owner_action = "file.save_all";
		registration.target = std::to_string(batch->size()) + " documents";
		registration.label = "Save all documents";
		registration.stage = "Encoding and atomically replacing captured revisions";
		if (!aida::ui::task_center::register_executor_job(
				submitted.task_id, std::move(registration))) {
			aida::infra::executor::cancel(submitted.task_id);
			for (const auto& item : *batch) {
				const int index = find_document(item.document_id);
				if (!is_valid_tab_index(index)) continue;
				auto& tab = tabs[tab_index(index)];
				if (tab.save_generation != item.generation) continue;
				++tab.save_generation;
				tab.save_in_progress = false;
				tab.save_dispatch_failed.reset();
				tab.save_error = "Task Center could not own Save All; cancellation was requested.";
			}
			return {false, "Task Center could not own Save All; cancellation was requested."};
		}
		return {true, "The complete captured revision set was scheduled as one Save All task."};
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
		t.buffer = content;
		t.buffer_loaded = true;
		t.dirty = false;
		t.base_fingerprint = content_fingerprint(content);
		t.content_hash = t.base_fingerprint;
		t.text_metadata = aida::editor::programming_documents::inspect_text(content);
		t.group_id = target_group;
		t.disk_write_version = 0;
		tabs.push_back(std::move(t));
		active_tab = static_cast<int>(tabs.size()) - 1;
		normalize_document_identities();
		auto& nt = tabs[tab_index(active_tab)];
		request_recovery_probe(active_tab);
		active_document_by_group[nt.group_id] = nt.document_id;
		static_cast<void>(code_editor_widget::load_document(nt.document_id,
			nt.revision, nt.buffer, nt.filename, nt.filepath, nt.dirty,
			nt.caret_line, nt.caret_column, nt.scroll_x, nt.scroll_y, true,
			nt.selection_anchor_line, nt.selection_anchor_column, nt.selection_active,
			nt.folded_lines, nt.language_override));
	}

	inline save_result_t restore_programming_session(const std::string& serialized,
			int legacy_active_index = -1) {
		aida::editor::programming_documents::session_state_t session;
		const auto decoded =
			aida::editor::programming_documents::decode_session(serialized, session);
		if (!decoded.succeeded)
			return {false, decoded.detail};
		std::size_t restored = 0;
		for (const auto& record : session.documents) {
			if (restored >= aida::editor::programming_documents::maximum_documents)
				break;
			if (!record.canonical_path.empty() &&
				is_valid_tab_index(find_path_document(record.canonical_path)))
				continue;
			OpenTab tab;
			tab.filename = record.filename.empty()
				? (record.canonical_path.empty() ? "Untitled"
					: std::filesystem::path(record.canonical_path).filename().string())
				: record.filename;
			tab.filepath = record.original_path.empty()
				? record.canonical_path : record.original_path;
			tab.document_id = record.document_id;
			tab.group_id = record.group_id;
			tab.pinned = record.pinned;
			tab.caret_line = record.caret_line;
			tab.caret_column = record.caret_column;
			tab.selection_anchor_line = record.selection_anchor_line;
			tab.selection_anchor_column = record.selection_anchor_column;
			tab.selection_active = record.selection_active;
			tab.scroll_x = record.scroll_x;
			tab.scroll_y = record.scroll_y;
			tab.folded_lines = record.folded_lines;
			tab.language_override = record.language_override;
			tab.revision = record.revision;
			tab.content_hash = record.content_hash;
			tab.base_fingerprint = record.base_fingerprint;
			tab.text_metadata = record.text;
			tab.buffer_loaded = record.canonical_path.empty();
			tab.disk_write_version = 0;
			tabs.push_back(std::move(tab));
			++restored;
		}
		normalize_document_identities();
		for (const auto& group : session.groups) {
			const int active = find_document(group.active_document_id);
			if (is_valid_tab_index(active) &&
				tabs[tab_index(active)].group_id == group.group_id)
				active_document_by_group[group.group_id] = group.active_document_id;
			auto& history = navigation_by_group[group.group_id];
			const auto append = [&](const std::vector<
					aida::editor::programming_documents::navigation_record_t>& source,
					std::deque<navigation_entry_t>& destination) {
				for (const auto& value : source) {
					const int index = find_document(value.document_id);
					if (is_valid_tab_index(index) &&
						tabs[tab_index(index)].group_id == group.group_id)
						destination.push_back({value.document_id, value.line, value.column});
				}
			};
			append(group.back, history.back);
			append(group.forward, history.forward);
		}
		int selected = find_document(session.active_document_id);
		if (!is_valid_tab_index(selected) && legacy_active_index >= 0 &&
			legacy_active_index < static_cast<int>(tabs.size()))
			selected = legacy_active_index;
		if (!is_valid_tab_index(selected) && !tabs.empty())
			selected = 0;
		if (is_valid_tab_index(selected)) {
			active_tab = -1;
			switch_to(selected, false);
		}
		return {true, decoded.detail};
	}

	inline std::string serialize_programming_session() {
		snapshot_active_to_tab();
		normalize_document_identities();
		for (auto& tab : tabs) {
			const auto metadata = code_editor_widget::document_metadata(tab.document_id);
			if (!metadata.found) continue;
			tab.dirty = metadata.dirty;
			tab.revision = metadata.revision;
			tab.caret_line = metadata.caret_line;
			tab.caret_column = metadata.caret_column;
			tab.selection_anchor_line = metadata.selection_anchor_line;
			tab.selection_anchor_column = metadata.selection_anchor_column;
			tab.selection_active = metadata.selection_active;
			tab.scroll_x = metadata.scroll_x;
			tab.scroll_y = metadata.scroll_y;
			tab.folded_lines = metadata.folded_lines;
			tab.language_override = metadata.language_override;
			tab.proposal_pending = metadata.proposal_pending;
			if (metadata.dirty) tab.content_hash = 0;
		}
		aida::editor::programming_documents::session_state_t session;
		if (is_valid_tab_index(active_tab))
			session.active_document_id = tabs[tab_index(active_tab)].document_id;
		for (const auto& tab : tabs)
			session.documents.push_back(recovery_metadata_record(tab));
		std::vector<std::uint32_t> persisted_groups;
		for (const auto& tab : tabs) {
			if (std::find(persisted_groups.begin(), persisted_groups.end(), tab.group_id) !=
				persisted_groups.end())
				continue;
			persisted_groups.push_back(tab.group_id);
			aida::editor::programming_documents::group_record_t group;
			group.group_id = tab.group_id;
			group.active_document_id = active_document_by_group[tab.group_id];
			const auto found = navigation_by_group.find(tab.group_id);
			if (found != navigation_by_group.end()) {
				const auto append = [](const std::deque<navigation_entry_t>& source,
						std::vector<aida::editor::programming_documents::navigation_record_t>& destination) {
					for (const auto& entry : source)
						destination.push_back({entry.document_id, entry.caret_line,
							entry.caret_column});
				};
				append(found->second.back, group.back);
				append(found->second.forward, group.forward);
			}
			session.groups.push_back(std::move(group));
		}
		return aida::editor::programming_documents::encode_session(session);
	}

	inline void close_tab(int idx, bool confirmed_discard = false) {
		if (!is_valid_tab_index(idx)) return;
		if (idx == active_tab)
			snapshot_active_to_tab();
		if (close_operation_pending(tabs[tab_index(idx)])) {
			tabs[tab_index(idx)].save_error = close_operation_detail(tabs[tab_index(idx)]);
			return;
		}
		normalize_document_identities();
		const auto& closing = tabs[tab_index(idx)];
		if (!closing.filepath.empty()) {
			const closed_document_t closed{closing.filepath, closing.filename,
				closing.group_id, closing.caret_line, closing.caret_column};
			closed_documents.erase(std::remove_if(closed_documents.begin(),
				closed_documents.end(), [&closed](const closed_document_t& entry) {
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
					return std::filesystem::path(entry.filepath).lexically_normal() ==
						std::filesystem::path(closed.filepath).lexically_normal();
#else
					return std::filesystem::u8path(entry.filepath).lexically_normal() ==
						std::filesystem::u8path(closed.filepath).lexically_normal();
#endif
				}), closed_documents.end());
			closed_documents.push_front(closed);
			constexpr std::size_t maximum_closed_documents = 32;
			while (closed_documents.size() > maximum_closed_documents)
				closed_documents.pop_back();
		}
		if (confirmed_discard)
			schedule_confirmed_recovery_cleanup(tabs[tab_index(idx)]);
		const std::uint64_t removed_document = tabs[tab_index(idx)].document_id;
		const auto loading = document_load_controls.find(removed_document);
		if (loading != document_load_controls.end()) {
			if (loading->second.cancelled)
				loading->second.cancelled->store(true, std::memory_order_release);
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
			if (loading->second.task_id != 0)
				aida::infra::executor::cancel(loading->second.task_id);
#endif
			document_load_controls.erase(loading);
		}
		code_editor_widget::discard_document_state(removed_document);
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
			if (was_active ||
				!code_editor_widget::document_metadata(
					tabs[tab_index(active_tab)].document_id).found)
				load_tab_into_editor(active_tab);
			active_document_by_group[tabs[tab_index(active_tab)].group_id] =
				tabs[tab_index(active_tab)].document_id;
		}
	}

	inline void checkpoint_recovery(int idx) {
		if (!is_valid_tab_index(idx)) return;
		auto& tab = tabs[tab_index(idx)];
		const auto metadata = code_editor_widget::document_metadata(tab.document_id);
		if (metadata.found) {
			tab.dirty = metadata.dirty;
			tab.revision = metadata.revision;
			tab.caret_line = metadata.caret_line;
			tab.caret_column = metadata.caret_column;
			tab.scroll_x = metadata.scroll_x;
			tab.scroll_y = metadata.scroll_y;
		}
		if (!tab.dirty || !tab.buffer_loaded || tab.streamed_document ||
			tab.recovery_checkpoint_pending)
			return;
		const std::uint64_t now = aida::shell_platform::tick_ms();
		if ((now - tab.recovery_checkpoint_ms) < 10000ULL)
			return;
		const auto payload = code_editor_widget::document_payload(tab.document_id, tab.revision);
		if (!payload.found || payload.read_only || payload.content.size() >
				aida::editor::programming_documents::maximum_document_bytes) {
			tab.recovery_error = "The current editor revision could not be captured for crash recovery.";
			return;
		}
		const std::uint64_t hash = payload.content_hash;
		if (hash == tab.recovery_checkpoint_hash) return;
		tab.buffer = payload.content;
		tab.content_hash = payload.content_hash;
		tab.recovery_checkpoint_pending = true;
		tab.recovery_checkpoint_ms = now;
		const std::uint64_t document_id = tab.document_id;
		const std::uint64_t generation = ++tab.recovery_checkpoint_generation;
		const auto record = recovery_record(tab);
		auto dispatch_failed = std::make_shared<std::atomic<bool>>(false);
		tab.recovery_checkpoint_dispatch_failed = dispatch_failed;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		static_cast<void>(document_id);
		static_cast<void>(generation);
		static_cast<void>(record);
		static_cast<void>(dispatch_failed);
		tab.recovery_checkpoint_pending = false;
		tab.recovery_checkpoint_hash = hash;
		tab.recovery_checkpoint_dispatch_failed.reset();
#else
		aida::infra::executor::submission_t sub;
		sub.owner_subsystem = "file_tabs";
		sub.label = "file_tabs.recovery_checkpoint";
		sub.thread_class = "blocking_file_io";
		sub.domain = aida::infra::executor::domain_t::feature_worker;
		sub.priority = 1;
		sub.generation = generation;
		sub.body = [record, document_id, generation, hash, dispatch_failed]() mutable {
			const auto committed = aida::editor::programming_documents::commit(record);
			aida::editor::programming_documents::recovery_reference_t recovery;
			if (committed.succeeded)
				recovery = aida::editor::programming_documents::probe(document_id,
					record.canonical_path);
			const bool posted = aida::ui_thread::post(
				[document_id, generation, hash, committed,
				 recovery = std::move(recovery)]() mutable {
					const int current = find_document(document_id);
					if (!is_valid_tab_index(current)) return;
					auto& target = tabs[tab_index(current)];
					if (target.recovery_checkpoint_generation != generation) return;
					target.recovery_checkpoint_pending = false;
					target.recovery_checkpoint_dispatch_failed.reset();
					if (committed.succeeded) {
						target.recovery_checkpoint_hash = hash;
						target.recovery = std::move(recovery);
						target.recovery_error = target.recovery.diagnostic;
					} else {
						target.recovery_error = committed.detail;
						diag::log_tagged_critical_fmt("file_tabs",
							"recovery_checkpoint_failed document_id=%llu generation=%llu reason=%.512s",
							static_cast<unsigned long long>(document_id),
							static_cast<unsigned long long>(generation), committed.detail.c_str());
					}
				}, "file_tabs", "recovery_checkpoint_result", "worker_result");
			if (!posted) {
				dispatch_failed->store(true, std::memory_order_release);
				diag::log_tagged_critical_fmt("file_tabs",
					"recovery_checkpoint_dispatch_failed document_id=%llu generation=%llu",
					static_cast<unsigned long long>(document_id),
					static_cast<unsigned long long>(generation));
			}
		};
		const auto submitted = aida::infra::executor::submit(std::move(sub));
		if (!submitted.submitted) {
			tab.recovery_checkpoint_pending = false;
			tab.recovery_checkpoint_dispatch_failed.reset();
			tab.recovery_error = "Recovery checkpoint scheduling failed: " +
				submitted.reject_reason;
			diag::log_tagged_critical_fmt("file_tabs",
				"recovery_checkpoint_submit_failed document_id=%llu reason=%.512s",
				static_cast<unsigned long long>(document_id), submitted.reject_reason.c_str());
		}
#endif
	}

	inline void write_hot_exit_snapshot_all() {
		snapshot_active_to_tab();
		for (auto& t : tabs) {
			if (!t.dirty || !t.buffer_loaded) continue;
			const auto payload = code_editor_widget::document_payload(t.document_id);
			if (!payload.found || payload.read_only) {
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
				diag::log_tagged_critical_fmt("file_tabs",
					"hot_exit_capture_failed document_id=%llu",
					static_cast<unsigned long long>(t.document_id));
#endif
				continue;
			}
			t.buffer = payload.content;
			t.revision = payload.revision;
			t.content_hash = payload.content_hash;
			t.caret_line = payload.caret_line;
			t.caret_column = payload.caret_column;
			t.scroll_x = payload.scroll_x;
			t.scroll_y = payload.scroll_y;
			const auto committed =
				aida::editor::programming_documents::commit(recovery_record(t));
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
			if (!committed.succeeded)
				diag::log_tagged_critical_fmt("file_tabs",
					"recovery_commit_failed document_id=%llu path=%.260s reason=%.512s",
					static_cast<unsigned long long>(t.document_id), t.filepath.c_str(),
					committed.detail.c_str());
#endif
		}
	}

	inline int find_document_index(std::uint64_t document_id) {
		for (std::size_t index = 0; index < tabs.size(); ++index) {
			if (tabs[index].document_id == document_id)
				return static_cast<int>(index);
		}
		return -1;
	}

	inline void cancel_close_all() {
		pending_close_all_document_ids.clear();
		pending_close_after_save_document_id = 0;
		exit_review_requested = false;
		exit_review_ready = false;
		exit_review_committed = false;
		exit_review_snapshot_revisions.clear();
		exit_review_resolved_revisions.clear();
		exit_review_discard_revisions.clear();
		exit_review_cleanup_requested_revisions.clear();
		exit_review_cleanup_completed_revisions.clear();
	}

	inline void finish_close_all_document(std::uint64_t document_id) {
		const auto found = std::find(pending_close_all_document_ids.begin(),
			pending_close_all_document_ids.end(), document_id);
		if (found != pending_close_all_document_ids.end())
			pending_close_all_document_ids.erase(found);
	}

	inline void advance_close_all() {
		pending_close_idx = -1;
		while (!pending_close_all_document_ids.empty()) {
			const std::uint64_t document_id = pending_close_all_document_ids.front();
			const int index = find_document_index(document_id);
			if (!is_valid_tab_index(index)) {
				pending_close_all_document_ids.pop_front();
				continue;
			}
			auto& tab = tabs[tab_index(index)];
			if (!exit_review_requested && tab.pinned) {
				pending_close_all_document_ids.pop_front();
				continue;
			}
			if (close_operation_pending(tab))
				return;
			const auto metadata = code_editor_widget::document_metadata(document_id);
			if (metadata.found) {
				tab.dirty = metadata.dirty;
				tab.revision = metadata.revision;
			}
			if (tab.dirty) {
				const auto resolved = exit_review_resolved_revisions.find(document_id);
				if (exit_review_requested && resolved != exit_review_resolved_revisions.end() &&
					resolved->second == tab.revision) {
					pending_close_all_document_ids.pop_front();
					continue;
				}
				pending_close_idx = index;
				show_close_confirm = true;
				return;
			}
			if (!exit_review_requested)
				close_tab(index);
			pending_close_all_document_ids.pop_front();
		}
	}

	inline std::size_t request_close_all() {
		if (pending_close_idx >= 0 || pending_close_after_save_document_id != 0)
			return 0;
		if (!pending_close_all_document_ids.empty())
			return pending_close_all_document_ids.size();
		snapshot_active_to_tab();
		for (const auto& tab : tabs) {
			if (!tab.pinned && close_operation_pending(tab))
				return 0;
		}
		for (const auto& tab : tabs) {
			if (!tab.pinned)
				pending_close_all_document_ids.push_back(tab.document_id);
		}
		const std::size_t requested = pending_close_all_document_ids.size();
		advance_close_all();
		return requested;
	}

	inline void resolve_pending_close_after_save() {
		if (pending_close_after_save_document_id == 0)
			return;
		const std::uint64_t document_id = pending_close_after_save_document_id;
		const int index = find_document_index(document_id);
		if (!is_valid_tab_index(index)) {
			pending_close_after_save_document_id = 0;
			finish_close_all_document(document_id);
			advance_close_all();
			return;
		}
		auto& tab = tabs[tab_index(index)];
		if (close_operation_pending(tab)) {
			pending_close_idx = -1;
			return;
		}
		if (!exit_review_requested && tab.pinned) {
			pending_close_after_save_document_id = 0;
			pending_close_idx = -1;
			close_confirm_error.clear();
			finish_close_all_document(document_id);
			advance_close_all();
			return;
		}
		if (tab.dirty) {
			pending_close_after_save_document_id = 0;
			pending_close_idx = index;
			show_close_confirm = true;
			close_confirm_error = tab.save_error.empty()
				? "The document changed while its previous revision was being saved."
				: tab.save_error;
			return;
		}
		pending_close_after_save_document_id = 0;
		pending_close_idx = -1;
		close_confirm_error.clear();
		if (!exit_review_requested)
			close_tab(index);
		finish_close_all_document(document_id);
		advance_close_all();
	}

	inline void resolve_exit_review_document(std::uint64_t document_id,
		std::uint64_t revision, bool confirmed_discard) {
		if (!exit_review_requested || document_id == 0 ||
			exit_review_snapshot_revisions.find(document_id) ==
				exit_review_snapshot_revisions.end())
			return;
		exit_review_resolved_revisions[document_id] = revision;
		if (confirmed_discard)
			exit_review_discard_revisions[document_id] = revision;
		else
			exit_review_discard_revisions.erase(document_id);
		finish_close_all_document(document_id);
		advance_close_all();
	}

	inline void fail_exit_discard_cleanup(std::uint64_t document_id,
		std::string detail) {
		exit_review_cleanup_requested_revisions.erase(document_id);
		exit_review_cleanup_completed_revisions.erase(document_id);
		exit_review_resolved_revisions.erase(document_id);
		exit_review_discard_revisions.erase(document_id);
		exit_review_ready = false;
		close_confirm_error = detail.empty()
			? "The discarded recovery state could not be sealed." : std::move(detail);
		const int index = find_document_index(document_id);
		if (!is_valid_tab_index(index))
			return;
		auto& tab = tabs[tab_index(index)];
		tab.recovery_operation_pending = false;
		tab.recovery_operation_label.clear();
		tab.recovery_dispatch_failed.reset();
		tab.recovery_error = close_confirm_error;
		if (std::find(pending_close_all_document_ids.begin(),
				pending_close_all_document_ids.end(), document_id) ==
			pending_close_all_document_ids.end())
			pending_close_all_document_ids.push_front(document_id);
	}

	inline save_result_t begin_exit_discard_cleanup(std::uint64_t document_id,
		std::uint64_t revision) {
		if (!exit_review_requested || exit_review_committed)
			return {false, "Application exit review is no longer active."};
		const int index = find_document_index(document_id);
		if (!is_valid_tab_index(index))
			return {false, "The discarded document is no longer open."};
		auto& tab = tabs[tab_index(index)];
		const auto metadata = code_editor_widget::document_metadata(document_id);
		if (!metadata.found || !metadata.dirty || metadata.revision != revision)
			return {false, "The discarded document changed before recovery cleanup began."};
		if (tab.save_in_progress || tab.recovery_operation_pending ||
			tab.recovery_checkpoint_pending)
			return {false, "Wait for active save and recovery operations to finish."};
		const auto identity = recovery_metadata_record(tab);
		const std::uint64_t generation = ++tab.recovery_operation_generation;
		auto dispatch_failed = std::make_shared<std::atomic<bool>>(false);
		tab.recovery_dispatch_failed = dispatch_failed;
		tab.recovery_operation_pending = true;
		tab.recovery_operation_label = "Sealing discarded recovery state";
		tab.recovery_error.clear();
		exit_review_cleanup_requested_revisions[document_id] = revision;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		static_cast<void>(identity);
		static_cast<void>(generation);
		static_cast<void>(dispatch_failed);
		tab.recovery_operation_pending = false;
		tab.recovery_operation_label.clear();
		tab.recovery_dispatch_failed.reset();
		exit_review_cleanup_completed_revisions[document_id] = revision;
		return {true, {}};
#else
		aida::infra::executor::submission_t sub;
		sub.owner_subsystem = "file_tabs";
		sub.label = "file_tabs.exit_discard_cleanup";
		sub.thread_class = "blocking_file_io";
		sub.domain = aida::infra::executor::domain_t::feature_worker;
		sub.priority = 3;
		sub.generation = generation;
		sub.shutdown_policy = "complete_before_exit_commit";
		sub.body = [identity, document_id, revision, generation, dispatch_failed]() mutable {
			const auto sealed = aida::editor::programming_documents::seal_clean_outcome(
				identity, revision);
			const bool posted = aida::ui_thread::post(
				[document_id, revision, generation, sealed]() mutable {
					const int current = find_document_index(document_id);
					if (!is_valid_tab_index(current)) {
						if (sealed.succeeded && sealed.changed)
							exit_review_cleanup_completed_revisions[document_id] = revision;
						else
							fail_exit_discard_cleanup(document_id, sealed.detail);
						return;
					}
					auto& target = tabs[tab_index(current)];
					if (target.recovery_operation_generation != generation)
						return;
					target.recovery_operation_pending = false;
					target.recovery_operation_label.clear();
					target.recovery_dispatch_failed.reset();
					const auto current_metadata =
						code_editor_widget::document_metadata(document_id);
					if (!sealed.succeeded || !sealed.changed) {
						fail_exit_discard_cleanup(document_id,
							sealed.detail.empty()
								? "A newer recovery revision prevented discard cleanup."
								: sealed.detail);
						return;
					}
					if (!current_metadata.found || !current_metadata.dirty ||
						current_metadata.revision != revision) {
						fail_exit_discard_cleanup(document_id,
							"The document changed while discarded recovery state was being sealed.");
						return;
					}
					target.recovery_error.clear();
					exit_review_cleanup_completed_revisions[document_id] = revision;
				}, "file_tabs", "exit_discard_cleanup_result", "worker_result");
			if (!posted)
				dispatch_failed->store(true, std::memory_order_release);
		};
		const auto submitted = aida::infra::executor::submit(std::move(sub));
		if (!submitted.submitted) {
			tab.recovery_operation_pending = false;
			tab.recovery_operation_label.clear();
			tab.recovery_dispatch_failed.reset();
			exit_review_cleanup_requested_revisions.erase(document_id);
			return {false, "Recovery cleanup scheduling failed: " + submitted.reject_reason};
		}
		return {true, {}};
#endif
	}

	inline void poll_exit_review() {
		if (!exit_review_requested || exit_review_committed)
			return;
		snapshot_active_to_tab();
		bool operation_pending = pending_close_after_save_document_id != 0;
		for (std::size_t index = 0; index < tabs.size(); ++index) {
			auto& tab = tabs[index];
			observe_recovery_dispatch_failure(static_cast<int>(index));
			const auto cleanup_requested =
				exit_review_cleanup_requested_revisions.find(tab.document_id);
			if (cleanup_requested != exit_review_cleanup_requested_revisions.end() &&
				exit_review_cleanup_completed_revisions.find(tab.document_id) ==
					exit_review_cleanup_completed_revisions.end() &&
				!tab.recovery_operation_pending) {
				fail_exit_discard_cleanup(tab.document_id, tab.recovery_error);
			}
			const auto metadata = code_editor_widget::document_metadata(tab.document_id);
			if (metadata.found) {
				tab.dirty = metadata.dirty;
				tab.revision = metadata.revision;
			}
			operation_pending = operation_pending || tab.save_in_progress ||
				tab.recovery_operation_pending || tab.recovery_checkpoint_pending;
			if (!tab.dirty)
				continue;
			exit_review_snapshot_revisions.try_emplace(tab.document_id, tab.revision);
			const auto resolved = exit_review_resolved_revisions.find(tab.document_id);
			if (resolved != exit_review_resolved_revisions.end() &&
				resolved->second == tab.revision)
				continue;
			if (std::find(pending_close_all_document_ids.begin(),
					pending_close_all_document_ids.end(), tab.document_id) ==
				pending_close_all_document_ids.end() &&
				(!is_valid_tab_index(pending_close_idx) ||
				 tabs[tab_index(pending_close_idx)].document_id != tab.document_id))
				pending_close_all_document_ids.push_back(tab.document_id);
		}
		if (pending_close_idx < 0 && pending_close_after_save_document_id == 0)
			advance_close_all();
		exit_review_ready = !operation_pending && pending_close_idx < 0 &&
			pending_close_after_save_document_id == 0 &&
			pending_close_all_document_ids.empty();
	}

	inline save_result_t request_exit_review() {
		if (exit_review_requested)
			return {true, exit_review_committed
				? "Application shutdown is already committed."
				: "Application shutdown review is already in progress."};
		if (pending_close_idx >= 0 || pending_close_after_save_document_id != 0 ||
			!pending_close_all_document_ids.empty())
			return {false, "Finish the current document-close review first."};
		exit_review_requested = true;
		exit_review_ready = false;
		exit_review_committed = false;
		exit_review_snapshot_revisions.clear();
		exit_review_resolved_revisions.clear();
		exit_review_discard_revisions.clear();
		exit_review_cleanup_requested_revisions.clear();
		exit_review_cleanup_completed_revisions.clear();
		poll_exit_review();
		return {true, {}};
	}

	inline bool consume_exit_review_ready() {
		poll_exit_review();
		if (!exit_review_requested || !exit_review_ready || exit_review_committed)
			return false;
		for (const auto& discarded : exit_review_discard_revisions) {
			const int index = find_document_index(discarded.first);
			if (!is_valid_tab_index(index))
				continue;
			const auto metadata = code_editor_widget::document_metadata(discarded.first);
			if (!metadata.found || metadata.revision != discarded.second ||
				!metadata.dirty) {
				exit_review_ready = false;
				exit_review_resolved_revisions.erase(discarded.first);
				return false;
			}
		}
		for (const auto& discarded : exit_review_discard_revisions) {
			const auto completed = exit_review_cleanup_completed_revisions.find(discarded.first);
			if (completed != exit_review_cleanup_completed_revisions.end() &&
				completed->second == discarded.second)
				continue;
			if (exit_review_cleanup_requested_revisions.find(discarded.first) !=
				exit_review_cleanup_requested_revisions.end()) {
				exit_review_ready = false;
				return false;
			}
			const auto started = begin_exit_discard_cleanup(discarded.first, discarded.second);
			if (!started.succeeded)
				fail_exit_discard_cleanup(discarded.first, started.detail);
			exit_review_ready = false;
			return false;
		}
		for (const auto& discarded : exit_review_discard_revisions) {
			const int index = find_document_index(discarded.first);
			if (!is_valid_tab_index(index))
				continue;
			auto& tab = tabs[tab_index(index)];
			tab.dirty = false;
			tab.recovery = {};
			tab.recovery_error.clear();
			code_editor_widget::mark_document_saved(tab.document_id, tab.revision,
				tab.filename, tab.filepath);
		}
		exit_review_committed = true;
		return true;
	}

	inline bool can_reopen_closed_document() {
		return !closed_documents.empty();
	}

	inline bool reopen_closed_document() {
		while (!closed_documents.empty()) {
			const closed_document_t entry = std::move(closed_documents.front());
			closed_documents.pop_front();
			if (entry.filepath.empty())
				continue;
			const int existing = find_path_document(entry.filepath);
			if (is_valid_tab_index(existing)) {
				switch_to(existing);
				return true;
			}
			const int previous_active = active_tab;
			if (request_document_open(entry.filepath, entry.filename,
					entry.caret_line, entry.caret_column)) {
				const int reopened = find_path_document(entry.filepath);
				if (is_valid_tab_index(reopened)) {
					tabs[tab_index(reopened)].group_id = entry.group_id;
					active_document_by_group[entry.group_id] =
						tabs[tab_index(reopened)].document_id;
				}
				return true;
			}
			const int reopened = find_path_document(entry.filepath);
			if (is_valid_tab_index(reopened)) {
				tabs[tab_index(reopened)].group_id = entry.group_id;
				active_document_by_group[entry.group_id] =
					tabs[tab_index(reopened)].document_id;
				return true;
			}
			active_tab = previous_active;
		}
		return false;
	}
}

namespace code_editor
{
	inline bool save() {
		if (!file_tabs::is_valid_tab_index(file_tabs::active_tab))
			return false;
		return file_tabs::save_tab_to_disk_result(file_tabs::active_tab).succeeded;
	}
}
