#include "pseudocode_view.hpp"
#include "decompiler_engine.hpp"
#include "ghidra_adapters/aida_code_xml_parse.hpp"
#include "syntax_highlight.hpp"
#include "ui_anim.hpp"
#include "disasm_view.hpp"
#include "cfg_view.hpp"
#include "rename_dialog.hpp"
#include "comment_dialog.hpp"
#include "../../helpers/globals.h"
#include "../../helpers/diag_log.hpp"
#include "../analysis/pdb_events.hpp"
#include "../analysis/symbol_store.hpp"
#include "rename_store.hpp"
#include "../infra/event_bus.hpp"
#include "../infra/work_queue.hpp"
#include "../ui/theme.hpp"
#include "../ui/motion.hpp"
#include "../ui/clock.hpp"
#include "../ui/transition.hpp"
#include "../ui/components.hpp"
#include "../ui/blur_layer.hpp"
#include "../ui/empty_state.hpp"
#include "../ui/fonts.hpp"

#include "imgui/imgui.h"

#include <algorithm>
#include <atomic>
#include <cfloat>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#endif

extern DisasmState g_disasm;

namespace pseudocode_view {

namespace {

static constexpr const char* kPopupDecompId = "##decomp_popup";
static constexpr const char* kPopupErrorId  = "##error_popup";

inline void dismiss_popup_if_addr_locked(uint64_t addr);

struct line_info_t {
	std::string text;
	int         indent_spaces = 0;
};

struct tab_t {
	uint64_t                                            addr = 0;
	std::string                                         label;
	std::string                                         function_name;
	std::string                                         pseudocode;
	std::string                                         parameters;
	std::vector<std::string>                            callees;
	std::vector<std::pair<std::string, uint64_t>>       callee_targets;
	std::vector<aida_ghidra::code_annotation_t>         annotations;
	std::vector<std::pair<int, uint64_t>>               line_addr_map;
	std::string                                         sleigh_id;
	std::string                                         error_text;
	bool                                                loaded = false;
	bool                                                is_error = false;
	bool                                                pending = true;
	bool                                                decompiling = true;
	std::vector<line_info_t>                            lines;
	float                                               scroll_y = 0.f;
	float                                               target_scroll_y = 0.f;
	float                                               appear_anim = 0.f;
	float                                               appear_vel = 0.f;
	int                                                 cursor_line = -1;
	float                                               cursor_pulse = 0.f;
	float                                               entrance_time = 0.f;
};

struct view_state_t {
	std::vector<std::shared_ptr<tab_t>> tabs;
	int                                 active_index = -1;
	float                               popup_anim = 0.f;
	float                               popup_vel = 0.f;
	float                               popup_target = 0.f;
	bool                                scrollbar_dragging = false;
	float                               scrollbar_drag_offset = 0.f;
	uint64_t                            last_popup_addr = 0;
	bool                                error_popup_active = false;
	float                               error_popup_anim = 0.f;
	float                               error_popup_vel = 0.f;
	std::string                         error_popup_message;
	std::string                         error_popup_label;
	uint64_t                            error_popup_addr = 0;
};

inline view_state_t& state()
{
	static view_state_t s;
	return s;
}

inline bool is_synthetic_function_label(const std::string& s)
{
	if (s.size() < 5) return false;
	bool sub = (s[0] == 's' || s[0] == 'S') &&
	           (s[1] == 'u' || s[1] == 'U') &&
	           (s[2] == 'b' || s[2] == 'B') && s[3] == '_';
	bool fun = (s[0] == 'F' || s[0] == 'f') &&
	           (s[1] == 'U' || s[1] == 'u') &&
	           (s[2] == 'N' || s[2] == 'n') && s[3] == '_';
	bool ghidra_func = (s.size() >= 4 &&
	                    (s.rfind("func_0x", 0) == 0 ||
	                     s.rfind("FUN_", 0) == 0 ||
	                     s.rfind("sub_", 0) == 0));
	return sub || fun || ghidra_func;
}

inline std::string resolve_tab_display_name(uint64_t addr, const std::string& fallback)
{
	if (addr == 0) {
		if (!fallback.empty()) return fallback;
		return std::string("sub_0");
	}
	std::string rn = rename_store::get(addr);
	if (!rn.empty()) return rn;
	std::string pdb_name = symbol_store::resolve_function_display_name(addr);
	if (!pdb_name.empty()) return pdb_name;
	if (!fallback.empty() && !is_synthetic_function_label(fallback)) return fallback;
	char buf[40];
	std::snprintf(buf, sizeof(buf), "sub_%llX", static_cast<unsigned long long>(addr));
	return std::string(buf);
}

inline std::mutex& state_mutex()
{
	static std::mutex m;
	return m;
}

inline std::atomic<bool>& pdb_subscription_armed_flag()
{
	static std::atomic<bool> armed{false};
	return armed;
}

inline aida::events::subscription_handle_t& pdb_subscription_slot()
{
	static aida::events::subscription_handle_t slot;
	return slot;
}

void rebuild_lines(tab_t& t);

inline void on_pdb_loaded_invalidate(const aida::events::event_pdb_loaded& ev)
{
	if (!ev.success) return;
	refresh_all_tabs();
}

inline void ensure_pdb_subscription()
{
	auto& armed = pdb_subscription_armed_flag();
	if (armed.load(std::memory_order_acquire)) return;
	bool expected = false;
	if (!armed.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) return;
	pdb_subscription_slot() = aida::events::subscribe(
		aida::events::event_pdb_loaded_def,
		[](const aida::events::event_pdb_loaded& ev) {
			on_pdb_loaded_invalidate(ev);
		});
	if (!pdb_subscription_slot().valid()) {
		armed.store(false, std::memory_order_release);
	}
}

std::shared_ptr<tab_t> find_tab_for_addr_locked(uint64_t addr)
{
	auto& s = state();
	for (auto& t : s.tabs) {
		if (t->addr == addr) return t;
	}
	return {};
}

int active_tab_index_locked()
{
	auto& s = state();
	if (s.active_index < 0) return -1;
	if (s.active_index >= static_cast<int>(s.tabs.size())) return -1;
	return s.active_index;
}

std::shared_ptr<tab_t> active_tab_locked()
{
	int idx = active_tab_index_locked();
	if (idx < 0) return {};
	return state().tabs[static_cast<size_t>(idx)];
}

inline uint64_t resolve_disasm_cursor_addr()
{
	const auto& dst = disasm_view::g_state;
	const auto& instrs = g_disasm.file.instrs;
	int row = dst.selected_row;
	int n = static_cast<int>(instrs.size());
	if (row >= 0 && row < n) return instrs[static_cast<size_t>(row)].addr;
	if (n > 0) return instrs[0].addr;
	return 0;
}

inline uint64_t follow_thunk_chain(uint64_t entry)
{
	uint64_t cur = entry;
	for (int hops = 0; hops < 8; ++hops) {
		if (cur == 0) break;
		if (!function_index::is_thunk(cur)) break;
		uint64_t next = function_index::thunk_target(cur);
		if (next == 0 || next == cur) break;
		cur = next;
	}
	return cur;
}

inline bool match_synthetic_function_prefix(const std::string& text, size_t pos,
                                            size_t& out_prefix_len)
{
	if (pos + 4 > text.size()) return false;
	if (text[pos + 3] != '_') return false;
	char a = text[pos];
	char b = text[pos + 1];
	char c = text[pos + 2];
	auto eq = [](char x, char y) {
		if (x >= 'A' && x <= 'Z') x = static_cast<char>(x - 'A' + 'a');
		if (y >= 'A' && y <= 'Z') y = static_cast<char>(y - 'A' + 'a');
		return x == y;
	};
	if (eq(a, 's') && eq(b, 'u') && eq(c, 'b')) {
		out_prefix_len = 4;
		return true;
	}
	if (eq(a, 'f') && eq(b, 'u') && eq(c, 'n')) {
		out_prefix_len = 4;
		return true;
	}
	return false;
}

inline std::string substitute_synthetic_function_names(const std::string& text)
{
	std::string out;
	out.reserve(text.size());
	size_t i = 0;
	while (i < text.size()) {
		bool token_boundary = (i == 0) ||
			(!(std::isalnum(static_cast<unsigned char>(text[i - 1])) || text[i - 1] == '_'));
		size_t prefix_len = 0;
		if (token_boundary && match_synthetic_function_prefix(text, i, prefix_len)) {
			size_t hex_start = i + prefix_len;
			size_t hex_end = hex_start;
			while (hex_end < text.size() &&
			       std::isxdigit(static_cast<unsigned char>(text[hex_end])))
				++hex_end;
			if (hex_end > hex_start && hex_end - hex_start >= 4 && hex_end - hex_start <= 16) {
				bool after_ok = (hex_end == text.size()) ||
					!(std::isalnum(static_cast<unsigned char>(text[hex_end])) || text[hex_end] == '_');
				if (after_ok) {
					std::string hex_part = text.substr(hex_start, hex_end - hex_start);
					char* end = nullptr;
					uint64_t addr = std::strtoull(hex_part.c_str(), &end, 16);
					if (end && *end == '\0' && addr != 0) {
						std::string resolved = rename_store::get(addr);
						if (resolved.empty())
							resolved = symbol_store::resolve_function_display_name(addr);
						if (!resolved.empty()) {
							out.append(resolved);
							i = hex_end;
							continue;
						}
					}
				}
			}
		}
		out.push_back(text[i]);
		++i;
	}
	return out;
}

void rebuild_lines(tab_t& t)
{
	diag::log_tagged_fmt("pcode_view", "rebuild_lines addr=0x%llX pseudocode_bytes=%zu",
		static_cast<unsigned long long>(t.addr), t.pseudocode.size());
	t.lines.clear();
	if (t.pseudocode.empty()) return;
	size_t start = 0;
	while (start <= t.pseudocode.size()) {
		size_t end = t.pseudocode.find('\n', start);
		if (end == std::string::npos) end = t.pseudocode.size();
		line_info_t li;
		std::string raw_line = t.pseudocode.substr(start, end - start);
		li.text = substitute_synthetic_function_names(raw_line);
		int spaces = 0;
		for (char c : li.text) {
			if (c == ' ') ++spaces;
			else if (c == '\t') spaces += 4;
			else break;
		}
		li.indent_spaces = spaces;
		t.lines.push_back(std::move(li));
		start = end + 1;
		if (end == t.pseudocode.size()) break;
	}
	diag::log_tagged_fmt("pcode_view", "rebuild_lines_done addr=0x%llX line_count=%zu",
		static_cast<unsigned long long>(t.addr), t.lines.size());
}

bool sync_tab_from_cache(tab_t& t)
{
	diag::log_tagged_fmt("pcode_view", "sync_tab_from_cache addr=0x%llX pending=%d",
		static_cast<unsigned long long>(t.addr), t.pending ? 1 : 0);
	auto& st = decompiler_engine::g_state;
	std::lock_guard<std::mutex> lk(st.mutex);
	auto it = st.cache.find(t.addr);
	if (it == st.cache.end()) {
		if (!st.decompiling.load() && st.current.function_addr == t.addr && st.current.is_error) {
			diag::log_tagged_fmt("pcode_view", "sync_tab_cache_miss_error addr=0x%llX error=%s",
				static_cast<unsigned long long>(t.addr), st.current.error_text.c_str());
			t.is_error = true;
			t.error_text = st.current.error_text;
			t.loaded = false;
			t.pending = false;
			t.decompiling = false;
			return true;
		}
		diag::log_tagged_fmt("pcode_view", "sync_tab_cache_miss addr=0x%llX not_ready",
			static_cast<unsigned long long>(t.addr));
		return false;
	}
	auto& r = it->second;
	if (!r.complete) return false;
	t.function_name = r.function_name;
	t.pseudocode = r.pseudocode;
	t.parameters = r.parameters;
	t.callees = r.callees;
	t.callee_targets = r.callee_targets;
	t.annotations = r.annotations;
	t.line_addr_map = r.line_addr_map;
	t.sleigh_id = r.sleigh_id;
	t.is_error = r.is_error;
	t.error_text = r.error_text;
	t.loaded = !r.is_error;
	t.pending = false;
	t.decompiling = false;
	diag::log_tagged_fmt("pcode_view", "sync_tab_cache_hit addr=0x%llX func=%s is_error=%d lines_before_rebuild=0",
		static_cast<unsigned long long>(t.addr), t.function_name.c_str(), t.is_error ? 1 : 0);
	rebuild_lines(t);
	return true;
}

inline bool error_text_is_cancellation(const std::string& msg)
{
	if (msg.empty()) return false;
	std::string lower;
	lower.reserve(msg.size());
	for (char c : msg) {
		if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
		lower.push_back(c);
	}
	return lower.find("cancel") != std::string::npos;
}

void poll_pending_tabs()
{
	auto& s = state();
	for (auto& t : s.tabs) {
		if (!t->pending) continue;
		diag::log_tagged_fmt("pcode_view", "poll_pending_tab addr=0x%llX label=%s",
			static_cast<unsigned long long>(t->addr), t->label.c_str());
		bool was_pending = t->pending;
		bool advanced = sync_tab_from_cache(*t);
		if (advanced && was_pending && t->is_error) {
			diag::log_tagged_fmt("pcode_view", "poll_tab_error addr=0x%llX error=%s",
				static_cast<unsigned long long>(t->addr), t->error_text.c_str());
			if (error_text_is_cancellation(t->error_text)) {
				diag::log_tagged_fmt("pcode_view", "poll_tab_cancelled addr=0x%llX",
					static_cast<unsigned long long>(t->addr));
				globals::ui::decompile_popup_active.store(false, std::memory_order_release);
				continue;
			}
			if (!s.error_popup_active) {
				s.error_popup_active = true;
				s.error_popup_message = t->error_text;
				s.error_popup_label = t->label;
				s.error_popup_addr = t->addr;
				globals::ui::decompile_popup_active.store(false, std::memory_order_release);
#ifdef _WIN32
				MessageBeep(MB_ICONERROR);
#endif
			}
		}
	}
}

ImU32 token_color_for_type(syntax::token_type t, float alpha)
{
	const auto& tk = aida::ui::resolved();
	switch (t) {
	case syntax::token_type::keyword:       return aida::ui::with_alpha(tk.syn_keyword, alpha);
	case syntax::token_type::type_name:     return aida::ui::with_alpha(tk.syn_type, alpha);
	case syntax::token_type::string_lit:    return aida::ui::with_alpha(tk.syn_string, alpha);
	case syntax::token_type::number:        return aida::ui::with_alpha(tk.syn_number, alpha);
	case syntax::token_type::comment_line:  return aida::ui::with_alpha(tk.syn_comment, alpha);
	case syntax::token_type::comment_block: return aida::ui::with_alpha(tk.syn_comment, alpha);
	case syntax::token_type::preprocessor:  return aida::ui::with_alpha(tk.syn_preprocessor, alpha);
	case syntax::token_type::operator_sym:  return aida::ui::with_alpha(tk.syn_operator, alpha);
	case syntax::token_type::function_call: return aida::ui::with_alpha(tk.syn_function, alpha);
	case syntax::token_type::boolean_lit:   return aida::ui::with_alpha(tk.syn_number, alpha);
	case syntax::token_type::punctuation:   return aida::ui::with_alpha(tk.syn_operator, alpha * 0.85f);
	case syntax::token_type::register_name: return aida::ui::with_alpha(tk.syn_register, alpha);
	case syntax::token_type::decorator:     return aida::ui::with_alpha(tk.syn_preprocessor, alpha);
	case syntax::token_type::directive:     return aida::ui::with_alpha(tk.syn_preprocessor, alpha);
	default:                                return aida::ui::with_alpha(tk.syn_identifier, alpha);
	}
}

ImU32 annotation_color(aida_ghidra::annotation_kind_t kind, float alpha)
{
	const auto& tk = aida::ui::resolved();
	using k = aida_ghidra::annotation_kind_t;
	switch (kind) {
	case k::syntax_keyword:       return aida::ui::with_alpha(tk.syn_keyword, alpha);
	case k::syntax_type:          return aida::ui::with_alpha(tk.syn_type, alpha);
	case k::syntax_comment:       return aida::ui::with_alpha(tk.syn_comment, alpha);
	case k::syntax_funcname:      return aida::ui::with_alpha(tk.syn_function, alpha);
	case k::function_name:        return aida::ui::with_alpha(tk.syn_function, alpha);
	case k::syntax_var:           return aida::ui::with_alpha(tk.syn_identifier, alpha);
	case k::local_variable:       return aida::ui::with_alpha(tk.syn_identifier, alpha);
	case k::function_parameter:   return aida::ui::with_alpha(tk.syn_register, alpha);
	case k::syntax_param:         return aida::ui::with_alpha(tk.syn_register, alpha);
	case k::syntax_const:         return aida::ui::with_alpha(tk.syn_number, alpha);
	case k::constant_variable:    return aida::ui::with_alpha(tk.syn_number, alpha);
	case k::syntax_global:        return aida::ui::with_alpha(tk.syn_preprocessor, alpha);
	case k::global_variable:      return aida::ui::with_alpha(tk.syn_preprocessor, alpha);
	case k::syntax_special:       return aida::ui::with_alpha(tk.syn_string, alpha);
	case k::offset:               return aida::ui::with_alpha(tk.text_address, alpha);
	default:                      return 0;
	}
}

void copy_to_clipboard(const std::string& text)
{
#ifdef _WIN32
	if (OpenClipboard(nullptr)) {
		EmptyClipboard();
		HGLOBAL hg = GlobalAlloc(GMEM_MOVEABLE, text.size() + 1);
		if (hg) {
			memcpy(GlobalLock(hg), text.c_str(), text.size() + 1);
			GlobalUnlock(hg);
			SetClipboardData(CF_TEXT, hg);
		}
		CloseClipboard();
	}
#else
	(void)text;
#endif
}

uint64_t address_for_line(const tab_t& t, int line_index)
{
	uint64_t out = 0;
	for (auto& kv : t.line_addr_map) {
		if (kv.first <= line_index) {
			if (kv.second > 0) out = kv.second;
		} else {
			break;
		}
	}
	return out;
}

void draw_spinner(ImDrawList* dl, ImVec2 center, float radius, float thickness, float t, ImU32 base_color, float alpha)
{
	const int segments = 36;
	float two_pi = 6.28318530718f;
	float arc = two_pi * 0.65f;
	float spin = t * 4.5f;
	float head = spin;
	float tail = spin - arc;
	for (int i = 0; i < segments; ++i) {
		float a0 = tail + (head - tail) * (static_cast<float>(i) / segments);
		float a1 = tail + (head - tail) * (static_cast<float>(i + 1) / segments);
		float fade = static_cast<float>(i) / static_cast<float>(segments);
		float aa = alpha * fade;
		uint32_t r = (base_color >> 0) & 0xFF;
		uint32_t g = (base_color >> 8) & 0xFF;
		uint32_t b = (base_color >> 16) & 0xFF;
		uint32_t pa = static_cast<uint32_t>(aa * 255.f);
		ImU32 col = (r) | (g << 8) | (b << 16) | (pa << 24);
		dl->AddLine(
			ImVec2(center.x + cosf(a0) * radius, center.y + sinf(a0) * radius),
			ImVec2(center.x + cosf(a1) * radius, center.y + sinf(a1) * radius),
			col, thickness);
	}
}

void render_loading_state(ImDrawList* dl, tab_t& tab, float ox, float oy, float width, float height, float alpha)
{
	const auto& tk = aida::ui::resolved();
	float t = static_cast<float>(ImGui::GetTime());
	float pulse = 0.5f + 0.5f * std::sin(t * 1.8f);

	float panel_w = std::min(360.f, width * 0.55f);
	float panel_h = 132.f;
	float px = ox + (width - panel_w) * 0.5f;
	float py = oy + (height - panel_h) * 0.5f;
	ImVec2 a(px, py);
	ImVec2 b(px + panel_w, py + panel_h);

	aida::ui::blur::render_drop_shadow(dl, a, b, 14.f, 5, 0.22f * alpha);
	aida::ui::blur::render_glass_fill(dl, a, b, 14.f, alpha * 0.92f);
	aida::ui::blur::render_glass_border(dl, a, b, 14.f, alpha);

	ImVec2 sc(px + panel_w * 0.5f, py + 46.f);
	draw_spinner(dl, sc, 16.f, 2.6f, t, tk.accent_u32, alpha);
	dl->AddCircle(sc, 24.f,
		aida::ui::with_alpha(tk.accent_glow, alpha * (0.30f + pulse * 0.25f)), 48, 1.2f);

	ImFont* hf = aida::ui::fonts::body_em();
	if (!hf) hf = ImGui::GetFont();
	const char* title = "Decompiling...";
	ImVec2 ts = hf->CalcTextSizeA(15.f, FLT_MAX, 0.f, title);
	dl->AddText(hf, 15.f,
		ImVec2(px + (panel_w - ts.x) * 0.5f, py + 82.f),
		aida::ui::with_alpha(tk.text_primary, alpha), title);

	if (tab.addr) {
		char ab[40];
		std::snprintf(ab, sizeof(ab), "0x%llX", static_cast<unsigned long long>(tab.addr));
		ImVec2 as = ImGui::GetFont()->CalcTextSizeA(12.f, FLT_MAX, 0.f, ab);
		dl->AddText(aida::ui::fonts::caption(), 12.f,
			ImVec2(px + (panel_w - as.x) * 0.5f, py + 102.f),
			aida::ui::with_alpha(tk.text_address, alpha), ab);
	}
}

void render_error_state(ImDrawList* dl, tab_t& tab, float ox, float oy, float width, float height, float alpha)
{
	const auto& tk = aida::ui::resolved();
	float panel_w = std::min(460.f, width * 0.7f);
	std::string msg = tab.error_text.empty()
		? std::string("Decompilation failed. The function may be malformed or unsupported.")
		: tab.error_text;
	ImVec2 msg_size = ImGui::CalcTextSize(msg.c_str(), nullptr, false, panel_w - 72.f);
	float panel_h = 96.f + msg_size.y + 48.f;
	if (panel_h < 168.f) panel_h = 168.f;
	float px = ox + (width - panel_w) * 0.5f;
	float py = oy + (height - panel_h) * 0.5f;
	ImVec2 a(px, py);
	ImVec2 b(px + panel_w, py + panel_h);

	aida::ui::blur::render_drop_shadow(dl, a, b, 14.f, 5, 0.28f * alpha);
	aida::ui::blur::render_glass_fill(dl, a, b, 14.f, alpha * 0.94f);
	aida::ui::blur::render_glass_border(dl, a, b, 14.f, alpha);

	float chip_w = 160.f;
	float chip_h = 26.f;
	ImVec2 ca(px + (panel_w - chip_w) * 0.5f, py + 18.f);
	ImVec2 cb(ca.x + chip_w, ca.y + chip_h);
	dl->AddRectFilled(ca, cb, aida::ui::with_alpha(tk.error_soft, alpha), chip_h * 0.5f);
	dl->AddRect(ca, cb, aida::ui::with_alpha(tk.error, alpha * 0.6f), chip_h * 0.5f, 0, 1.f);
	const char* chip_text = "Decompilation failed";
	ImVec2 cts = aida::ui::fonts::body_em()->CalcTextSizeA(12.f, FLT_MAX, 0.f, chip_text);
	dl->AddText(aida::ui::fonts::body_em(), 12.f,
		ImVec2(ca.x + (chip_w - cts.x) * 0.5f, ca.y + (chip_h - cts.y) * 0.5f),
		aida::ui::with_alpha(tk.error, alpha), chip_text);

	dl->AddText(nullptr, 0.f,
		ImVec2(px + 36.f, py + 58.f),
		aida::ui::with_alpha(tk.text_secondary, alpha),
		msg.c_str(), msg.c_str() + msg.size(), panel_w - 72.f);

	float btn_w = 96.f;
	float btn_h = 28.f;
	float btn_y = py + panel_h - btn_h - 16.f;
	ImGui::SetCursorScreenPos(ImVec2(px + (panel_w - btn_w) * 0.5f, btn_y));
	if (aida::ui::components::button("Retry",
	    aida::ui::components::button_kind_t::primary,
	    aida::ui::components::size_t_::sm, ImVec2(btn_w, btn_h))) {
		diag::log_tagged_fmt("pcode_view", "retry_decompile addr=0x%llX",
			static_cast<unsigned long long>(tab.addr));
		tab.pending = true;
		tab.decompiling = true;
		tab.loaded = false;
		tab.is_error = false;
		tab.error_text.clear();
		decompiler_engine::erase_cache_entry(tab.addr);
		globals::ui::decompile_popup_addr.store(tab.addr, std::memory_order_release);
		globals::ui::decompile_popup_active.store(true, std::memory_order_release);
		decompiler_engine::decompile_function_native(tab.addr, &g_disasm.file);
	}
}

void render_code_panel(ImDrawList* dl, tab_t& tab, float ox, float oy, float width, float height, float alpha)
{
	const auto& tk = aida::ui::resolved();
	auto _ta = [alpha](ImU32 c) -> ImU32 { return aida::ui::with_alpha(c, alpha); };

	dl->AddRectFilled(ImVec2(ox, oy), ImVec2(ox + width, oy + height), _ta(tk.bg_base));

	if (tab.pending || tab.decompiling) {
		render_loading_state(dl, tab, ox, oy, width, height, alpha);
		return;
	}

	if (tab.is_error) {
		render_error_state(dl, tab, ox, oy, width, height, alpha);
		return;
	}

	if (tab.loaded && tab.lines.empty()) {
		ImFont* hf = aida::ui::fonts::body_em();
		if (!hf) hf = ImGui::GetFont();
		const char* msg = "Function decompiled, but produced no output.";
		ImVec2 ts = hf->CalcTextSizeA(15.f, FLT_MAX, 0.f, msg);
		dl->AddText(hf, 15.f,
			ImVec2(ox + (width - ts.x) * 0.5f, oy + (height - ts.y) * 0.5f),
			aida::ui::with_alpha(tk.text_secondary, alpha), msg);
		return;
	}

	if (!tab.loaded) return;

	float dt = aida::ui::clock::dt();
	tab.entrance_time += dt;

	float outer_pad_x = 26.f;
	float outer_pad_top = 18.f;
	float outer_pad_bottom = 14.f;

	ImVec2 panel_a(ox + outer_pad_x * 0.5f, oy + outer_pad_top * 0.4f);
	ImVec2 panel_b(ox + width - outer_pad_x * 0.5f, oy + height - outer_pad_bottom * 0.5f);
	aida::ui::blur::render_drop_shadow(dl, panel_a, panel_b, 14.f, 4, 0.22f * alpha);
	aida::ui::blur::render_glass_fill(dl, panel_a, panel_b, 14.f, alpha * 0.96f);
	aida::ui::blur::render_glass_border(dl, panel_a, panel_b, 14.f, alpha);

	ImFont* code_font = aida::ui::fonts::code();
	if (!code_font) code_font = ImGui::GetFont();
	const float code_size = 19.f;
	const float line_h    = 28.f;
	const float gutter_font_size = 14.f;

	float code_area_x0 = panel_a.x + 4.f;
	float code_area_y0 = panel_a.y + 14.f;
	float code_area_x1 = panel_b.x - 4.f;
	float code_area_y1 = panel_b.y - 4.f;
	float code_area_w  = code_area_x1 - code_area_x0;
	float code_area_h  = code_area_y1 - code_area_y0;

	float gutter_pad_l = 16.f;
	float gutter_lineno_w = code_font->CalcTextSizeA(gutter_font_size, FLT_MAX, 0.f, "99999").x;
	float gutter_addr_w   = code_font->CalcTextSizeA(gutter_font_size, FLT_MAX, 0.f, "FFFFFFFF").x;
	float gutter_gap = 14.f;
	float gutter_w = gutter_pad_l + gutter_lineno_w + 10.f + gutter_addr_w + gutter_gap;
	float code_left_pad = 14.f;

	float content_h = static_cast<float>(tab.lines.size()) * line_h;
	float visible_h = code_area_h;
	bool hov = ImGui::IsMouseHoveringRect(ImVec2(code_area_x0, code_area_y0),
	                                       ImVec2(code_area_x1, code_area_y1), false);
	if (hov) {
		ui_anim::handle_scroll_input(tab.target_scroll_y, 0.f,
		                              std::max(0.f, content_h - visible_h), line_h);
	}
	ui_anim::smooth_scroll(tab.scroll_y, tab.target_scroll_y, 15.f, dt);

	int first_vis = static_cast<int>(tab.scroll_y / line_h);
	if (first_vis < 0) first_vis = 0;
	int vis_count = static_cast<int>(visible_h / line_h) + 2;
	int last_vis = std::min(first_vis + vis_count, static_cast<int>(tab.lines.size()));

	dl->PushClipRect(ImVec2(code_area_x0, code_area_y0), ImVec2(code_area_x1, code_area_y1), true);

	dl->AddRectFilled(
		ImVec2(code_area_x0, code_area_y0),
		ImVec2(code_area_x0 + gutter_w, code_area_y1),
		aida::ui::with_alpha(tk.panel_header, alpha * 0.45f));
	dl->AddLine(
		ImVec2(code_area_x0 + gutter_w, code_area_y0),
		ImVec2(code_area_x0 + gutter_w, code_area_y1),
		aida::ui::with_alpha(tk.border_subtle, alpha * 0.85f));

	float indent_unit = code_font->CalcTextSizeA(code_size, FLT_MAX, 0.f, " ").x;

	static auto cpp_lang = syntax::lang_cpp();
	std::vector<syntax::token_t> tokens;

	size_t line_byte_start = 0;
	for (int li = 0; li < first_vis; ++li) {
		line_byte_start += tab.lines[li].text.size() + 1;
	}

	tab.cursor_pulse += dt;

	for (int i = first_vis; i < last_vis; ++i) {
		auto& ln = tab.lines[i];
		float ly = code_area_y0 + 4.f + static_cast<float>(i) * line_h - tab.scroll_y;

		float entrance_t = ui_anim::render_row_entrance(i - first_vis, tab.entrance_time, 0.012f, 0.28f);
		float row_alpha = alpha * entrance_t;
		float row_offset = (1.f - entrance_t) * 6.f;
		ly += row_offset;

		ImVec2 line_a(code_area_x0 + gutter_w, ly);
		ImVec2 line_b(code_area_x1, ly + line_h);
		bool line_hov = ImGui::IsMouseHoveringRect(line_a, line_b, false);
		uint64_t line_addr = address_for_line(tab, i);
		bool is_cursor = (tab.cursor_line == i);

		if (is_cursor || line_hov) {
			float strength = is_cursor ? 1.f : 0.5f;
			ImU32 wash = is_cursor
				? aida::ui::with_alpha(tk.selection, row_alpha * 0.55f)
				: aida::ui::with_alpha(tk.hover_wash, row_alpha);
			dl->AddRectFilled(line_a, line_b, wash, 6.f);
			float bar_a = strength * row_alpha;
			float pulse = is_cursor ? (0.78f + 0.22f * std::sin(tab.cursor_pulse * 3.4f)) : 1.f;
			ImU32 bar_col = aida::ui::with_alpha(tk.accent_u32, bar_a * pulse);
			dl->AddRectFilled(
				ImVec2(line_a.x + 2.f, line_a.y + 3.f),
				ImVec2(line_a.x + 5.f, line_b.y - 3.f),
				bar_col, 1.5f);
		}

		if (line_hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
			tab.cursor_line = i;
			tab.cursor_pulse = 0.f;
		}
		if (line_hov && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
			diag::log_tagged_fmt("pcode_view", "double_click_line line=%d addr=0x%llX",
				i, static_cast<unsigned long long>(line_addr));
			tab.cursor_line = i;
			tab.cursor_pulse = 0.f;
			if (line_addr != 0) {
				globals::ui::active_center_view = center_view_t::disassembly;
				disasm_view::goto_address(line_addr, g_disasm);
			}
		}

		if (line_addr != 0) {
			char addr_buf[24];
			std::snprintf(addr_buf, sizeof(addr_buf), "%08llX",
			              static_cast<unsigned long long>(line_addr));
			float ax = code_area_x0 + gutter_pad_l + gutter_lineno_w + 10.f;
			dl->AddText(code_font, gutter_font_size,
				ImVec2(ax, ly + (line_h - gutter_font_size) * 0.5f),
				aida::ui::with_alpha(tk.text_address, row_alpha * 0.92f), addr_buf);
		}

		char num_buf[16];
		std::snprintf(num_buf, sizeof(num_buf), "%4d", i + 1);
		ImVec2 ns = code_font->CalcTextSizeA(gutter_font_size, FLT_MAX, 0.f, num_buf);
		dl->AddText(code_font, gutter_font_size,
			ImVec2(code_area_x0 + gutter_pad_l + gutter_lineno_w - ns.x,
			       ly + (line_h - gutter_font_size) * 0.5f),
			aida::ui::with_alpha(tk.text_lineno, row_alpha * 0.7f), num_buf);

		float code_x0 = code_area_x0 + gutter_w + code_left_pad;
		int indent_levels = ln.indent_spaces / 3;
		for (int g = 1; g <= indent_levels; ++g) {
			float gx = code_x0 + indent_unit * static_cast<float>(g * 3) - indent_unit * 0.5f;
			dl->AddLine(ImVec2(gx, ly + 2.f), ImVec2(gx, ly + line_h - 2.f),
				aida::ui::with_alpha(tk.border_subtle, row_alpha * 0.55f));
		}

		tokens.clear();
		syntax::tokenize(ln.text, cpp_lang, tokens);

		float tx = code_x0;
		for (auto& tok : tokens) {
			std::string_view sv(ln.text.data() + tok.start, tok.length);

			ImU32 col = token_color_for_type(tok.type, row_alpha);
			size_t abs_start = line_byte_start + tok.start;
			size_t abs_end = abs_start + tok.length;
			for (auto& an : tab.annotations) {
				if (an.start < abs_end && an.end > abs_start) {
					ImU32 ac = annotation_color(an.kind, row_alpha);
					if (ac != 0) col = ac;
					break;
				}
			}

			dl->AddText(code_font, code_size,
				ImVec2(tx, ly + (line_h - code_size) * 0.5f),
				col, sv.data(), sv.data() + sv.size());
			tx += code_font->CalcTextSizeA(code_size, FLT_MAX, 0.f, sv.data(), sv.data() + sv.size()).x;
		}

		line_byte_start += ln.text.size() + 1;
	}

	if (content_h > visible_h) {
		float sb_x = code_area_x1 - 10.f;
		auto& s = state();
		ui_anim::render_custom_scrollbar(dl, sb_x, code_area_y0, 8.f, code_area_h,
		                                  tab.scroll_y, content_h, visible_h,
		                                  alpha, s.scrollbar_dragging, s.scrollbar_drag_offset);
		if (s.scrollbar_dragging) {
			if (ImGui::IsMouseReleased(ImGuiMouseButton_Left))
				s.scrollbar_dragging = false;
			else {
				float track = code_area_h - std::max(code_area_h * visible_h / content_h, 20.f);
				float mouse_y = ImGui::GetMousePos().y - code_area_y0 - s.scrollbar_drag_offset;
				float ratio = mouse_y / track;
				if (ratio < 0.f) ratio = 0.f;
				if (ratio > 1.f) ratio = 1.f;
				tab.target_scroll_y = ratio * (content_h - visible_h);
				tab.scroll_y = tab.target_scroll_y;
			}
		}
	}

	dl->PopClipRect();
}

void render_decompiling_popup(ImDrawList* dl, float ox, float oy, float width, float height, float alpha)
{
	const auto& tk = aida::ui::resolved();
	auto& s = state();
	float dt = aida::ui::clock::dt();
	bool active = globals::ui::decompile_popup_active.load(std::memory_order_acquire);
	s.popup_target = active ? 1.f : 0.f;
	s.popup_anim = aida::motion::spring_step(s.popup_anim, s.popup_target, s.popup_vel,
	                                          aida::motion::spring::snappy, dt);
	if (s.popup_anim < 0.005f) return;

	ImGui::PushID(kPopupDecompId);

	bool init_active = decompiler_engine::g_state.init_progress_active.load(std::memory_order_acquire);

	float overlay_a = alpha * s.popup_anim * 0.55f;
	(void)overlay_a;

	float panel_w = std::min(440.f, width * 0.7f);
	float panel_h = init_active ? 178.f : 156.f;
	float scale = 0.94f + 0.06f * s.popup_anim;
	float pw = panel_w * scale;
	float ph = panel_h * scale;
	float px = ox + (width - pw) * 0.5f;
	float py = oy + (height - ph) * 0.5f;
	ImVec2 a(px, py);
	ImVec2 b(px + pw, py + ph);

	float panel_a = alpha * std::min(1.f, s.popup_anim);
	aida::ui::blur::render_drop_shadow(dl, a, b, 14.f, 6, 0.40f * panel_a);
	aida::ui::blur::render_glass_fill(dl, a, b, 14.f, panel_a);
	aida::ui::blur::render_glass_border(dl, a, b, 14.f, panel_a);

	float t = static_cast<float>(ImGui::GetTime());
	ImVec2 sc(px + 38.f, py + ph * 0.5f);
	draw_spinner(dl, sc, 16.f, 2.6f, t, tk.accent_u32, panel_a);
	dl->AddCircle(sc, 16.f, aida::ui::with_alpha(tk.border_subtle, panel_a * 0.6f), 36, 1.4f);

	const char* title_text = init_active ? "Initializing decompiler..." : "Decompiling...";
	dl->AddText(aida::ui::fonts::body_em(), 17.f,
	            ImVec2(px + 70.f, py + 30.f),
	            aida::ui::with_alpha(tk.text_primary, panel_a),
	            title_text);

	if (init_active) {
		dl->AddText(aida::ui::fonts::caption(), 13.f,
		            ImVec2(px + 70.f, py + 56.f),
		            aida::ui::with_alpha(tk.text_secondary, panel_a),
		            "First-time setup, this may take a few seconds");
	} else {
		uint64_t addr = globals::ui::decompile_popup_addr.load(std::memory_order_acquire);
		if (addr) {
			char ab[64];
			std::snprintf(ab, sizeof(ab), "0x%llX", static_cast<unsigned long long>(addr));
			dl->AddText(aida::ui::fonts::caption(), 13.f,
			            ImVec2(px + 70.f, py + 56.f),
			            aida::ui::with_alpha(tk.text_secondary, panel_a),
			            ab);
		}
	}

	aida::ui::components::render_progress_bar(
		ImVec2(px + 20.f, py + ph - 54.f),
		pw - 40.f, 4.f, 0.f, true, true);

	float btn_w = 96.f;
	float btn_h = 28.f;
	ImGui::SetCursorScreenPos(ImVec2(px + pw - btn_w - 18.f, py + ph - btn_h - 14.f));
	if (aida::ui::components::button("Cancel",
	    aida::ui::components::button_kind_t::ghost,
	    aida::ui::components::size_t_::sm, ImVec2(btn_w, btn_h))) {
		diag::log_tagged_fmt("pcode_view", "cancel_decompile_popup addr=0x%llX",
			static_cast<unsigned long long>(globals::ui::decompile_popup_addr.load(std::memory_order_acquire)));
		decompiler_engine::cancel_decompile();
		globals::ui::decompile_popup_active.store(false, std::memory_order_release);
	}

	ImGui::PopID();
}

void render_error_popup(ImDrawList* dl, float ox, float oy, float width, float height, float alpha)
{
	const auto& tk = aida::ui::resolved();
	auto& s = state();
	float dt = aida::ui::clock::dt();
	float target = s.error_popup_active ? 1.f : 0.f;
	s.error_popup_anim = aida::motion::spring_step(s.error_popup_anim, target, s.error_popup_vel,
	                                               aida::motion::spring::snappy, dt);
	if (s.error_popup_anim < 0.005f) return;

	ImGui::PushID(kPopupErrorId);

	float overlay_a = alpha * s.error_popup_anim * 0.55f;
	dl->AddRectFilled(ImVec2(ox, oy), ImVec2(ox + width, oy + height),
	                  IM_COL32(0, 0, 0, static_cast<int>(150.f * overlay_a)));

	float panel_w = std::min(480.f, width * 0.75f);
	std::string msg = s.error_popup_message;
	if (msg.empty()) msg = "An unexpected error occurred during decompilation.";
	ImVec2 msg_size = ImGui::CalcTextSize(msg.c_str(), nullptr, false, panel_w - 96.f);
	float panel_h = 84.f + msg_size.y + 56.f;
	if (panel_h < 168.f) panel_h = 168.f;

	float scale = 0.94f + 0.06f * s.error_popup_anim;
	float pw = panel_w * scale;
	float ph = panel_h * scale;
	float px = ox + (width - pw) * 0.5f;
	float py = oy + (height - ph) * 0.5f;
	ImVec2 a(px, py);
	ImVec2 b(px + pw, py + ph);

	float panel_a = alpha * std::min(1.f, s.error_popup_anim);
	aida::ui::blur::render_drop_shadow(dl, a, b, 14.f, 6, 0.45f * panel_a);
	aida::ui::blur::render_glass_fill(dl, a, b, 14.f, panel_a);
	aida::ui::blur::render_glass_border(dl, a, b, 14.f, panel_a);

	float icon_cx = px + 36.f;
	float icon_cy = py + 36.f;
	dl->AddCircleFilled(ImVec2(icon_cx, icon_cy), 16.f,
		aida::ui::with_alpha(tk.error, panel_a * 0.95f));
	dl->AddCircle(ImVec2(icon_cx, icon_cy), 16.f,
		aida::ui::with_alpha(tk.error, panel_a), 32, 1.6f);
	ImFont* glyph_font = aida::ui::fonts::body_em();
	if (!glyph_font) glyph_font = ImGui::GetFont();
	ImVec2 ex_size = glyph_font->CalcTextSizeA(20.f, FLT_MAX, 0.f, "!");
	dl->AddText(glyph_font, 20.f,
	            ImVec2(icon_cx - ex_size.x * 0.5f, icon_cy - ex_size.y * 0.5f),
	            aida::ui::with_alpha(IM_COL32(255, 255, 255, 255), panel_a),
	            "!");

	ImFont* h_font = aida::ui::fonts::body_em();
	if (!h_font) h_font = ImGui::GetFont();
	dl->AddText(h_font, 15.f,
	            ImVec2(px + 64.f, py + 20.f),
	            aida::ui::with_alpha(tk.text_primary, panel_a),
	            "Cannot decompile this function");

	if (!s.error_popup_label.empty() || s.error_popup_addr) {
		char sub[160];
		if (!s.error_popup_label.empty() && s.error_popup_addr)
			std::snprintf(sub, sizeof(sub), "%s   0x%llX",
				s.error_popup_label.c_str(),
				static_cast<unsigned long long>(s.error_popup_addr));
		else if (s.error_popup_addr)
			std::snprintf(sub, sizeof(sub), "0x%llX",
				static_cast<unsigned long long>(s.error_popup_addr));
		else
			std::snprintf(sub, sizeof(sub), "%s", s.error_popup_label.c_str());
		dl->AddText(aida::ui::fonts::caption(), 12.f,
		            ImVec2(px + 64.f, py + 42.f),
		            aida::ui::with_alpha(tk.text_secondary, panel_a),
		            sub);
	}

	dl->AddText(nullptr, 0.f,
	            ImVec2(px + 64.f, py + 76.f),
	            aida::ui::with_alpha(tk.text_secondary, panel_a),
	            msg.c_str(),
	            msg.c_str() + msg.size(),
	            pw - 96.f);

	float btn_w = 96.f;
	float btn_h = 28.f;
	float btn_x = px + pw - btn_w - 16.f;
	float btn_y = py + ph - btn_h - 14.f;
	ImGui::SetCursorScreenPos(ImVec2(btn_x, btn_y));
	if (aida::ui::components::button("OK",
	    aida::ui::components::button_kind_t::primary,
	    aida::ui::components::size_t_::sm, ImVec2(btn_w, btn_h))) {
		s.error_popup_active = false;
	}

	ImGuiIO& io = ImGui::GetIO();
	if (!io.WantTextInput && !ImGui::IsAnyItemActive()) {
		if (ImGui::IsKeyPressed(ImGuiKey_Enter, false) ||
		    ImGui::IsKeyPressed(ImGuiKey_KeypadEnter, false) ||
		    ImGui::IsKeyPressed(ImGuiKey_Escape, false)) {
			s.error_popup_active = false;
		}
	}

	ImGui::PopID();
}

void check_popup_dismiss()
{
	if (!globals::ui::decompile_popup_active.load(std::memory_order_acquire)) return;
	uint64_t target = globals::ui::decompile_popup_addr.load(std::memory_order_acquire);
	if (target == 0) return;
	auto& st = decompiler_engine::g_state;
	{
		std::lock_guard<std::mutex> lk(st.mutex);
		auto it = st.cache.find(target);
		if (it != st.cache.end() && it->second.complete) {
			globals::ui::decompile_popup_active.store(false, std::memory_order_release);
			return;
		}
		if (!st.decompiling.load() && st.current.function_addr == target && st.current.is_error) {
			globals::ui::decompile_popup_active.store(false, std::memory_order_release);
			return;
		}
	}
}

}

void request_decompile(uint64_t addr, const DisasmFile* file, bool force_refresh)
{
	diag::log_tagged_fmt("pcode_view", "request_decompile_enter addr=0x%llX force=%d",
		static_cast<unsigned long long>(addr), force_refresh ? 1 : 0);
	if (addr == 0) return;

	ensure_pdb_subscription();

	bool need_dispatch = false;
	bool suppress_new_log = false;
	bool cache_busted = false;
	std::string log_label;

	{
		std::lock_guard<std::mutex> guard(state_mutex());
		auto& s = state();
		diag::log_tagged_critical_fmt("psv",
			"request_decompile_state_locked addr=0x%llX tabs=%zu active=%d force=%d",
			static_cast<unsigned long long>(addr),
			s.tabs.size(),
			s.active_index,
			force_refresh ? 1 : 0);
		globals::ui::active_center_view = center_view_t::pseudocode;

		auto existing = find_tab_for_addr_locked(addr);
		if (existing) {
			for (size_t i = 0; i < s.tabs.size(); ++i) {
				if (s.tabs[i].get() == existing.get()) {
					s.active_index = static_cast<int>(i);
					break;
				}
			}
			if (force_refresh) {
				existing->pending = true;
				existing->decompiling = true;
				existing->loaded = false;
				existing->is_error = false;
				existing->error_text.clear();
				globals::ui::decompile_popup_addr.store(addr, std::memory_order_release);
				globals::ui::decompile_popup_active.store(true, std::memory_order_release);
				need_dispatch = true;
				suppress_new_log = true;
				cache_busted = true;
				log_label = existing->label;
			} else if (existing->loaded || existing->is_error) {
				diag::log_tagged_critical_fmt("psv", "request_decompile_existing addr=0x%llX label=%s loaded=%d",
					static_cast<unsigned long long>(addr),
					existing->label.c_str(),
					existing->loaded ? 1 : 0);
				return;
			} else {
				globals::ui::decompile_popup_addr.store(addr, std::memory_order_release);
				globals::ui::decompile_popup_active.store(true, std::memory_order_release);
				need_dispatch = true;
				suppress_new_log = true;
				log_label = existing->label;
			}
		} else {
			auto t = std::make_shared<tab_t>();
			diag::log_tagged_critical_fmt("psv",
				"request_decompile_create_tab addr=0x%llX tab_raw=%p tabs_before=%zu",
				static_cast<unsigned long long>(addr),
				t.get(),
				s.tabs.size());
			t->addr = addr;
			char nm[64];
			std::snprintf(nm, sizeof(nm), "sub_%llX", static_cast<unsigned long long>(addr));
			t->label = nm;
			t->function_name = nm;
			t->pending = true;
			t->decompiling = true;
			t->loaded = false;
			t->is_error = false;
			s.tabs.push_back(t);
			s.active_index = static_cast<int>(s.tabs.size()) - 1;

			if (!force_refresh) {
				auto& st = decompiler_engine::g_state;
				std::lock_guard<std::mutex> lk(st.mutex);
				auto it = st.cache.find(addr);
				if (it != st.cache.end() && it->second.complete) {
					auto& r = it->second;
					t->function_name = r.function_name;
					t->pseudocode = r.pseudocode;
					t->parameters = r.parameters;
					t->callees = r.callees;
					t->callee_targets = r.callee_targets;
					t->annotations = r.annotations;
					t->line_addr_map = r.line_addr_map;
					t->sleigh_id = r.sleigh_id;
					t->is_error = r.is_error;
					t->error_text = r.error_text;
					t->loaded = !r.is_error;
					t->pending = false;
					t->decompiling = false;
					rebuild_lines(*t);
					diag::log_tagged_critical_fmt("psv", "request_decompile_cache_hit addr=0x%llX label=%s",
						static_cast<unsigned long long>(addr),
						t->label.c_str());
					return;
				}
			} else {
				cache_busted = true;
			}

			globals::ui::decompile_popup_addr.store(addr, std::memory_order_release);
			globals::ui::decompile_popup_active.store(true, std::memory_order_release);
			need_dispatch = true;
			log_label = t->label;
		}
	}

	if (cache_busted) {
		decompiler_engine::erase_cache_entry(addr);
		diag::log_tagged_critical_fmt("psv", "request_decompile_force_refresh addr=0x%llX label=%s",
			static_cast<unsigned long long>(addr),
			log_label.c_str());
	}

	if (need_dispatch) {
		if (!suppress_new_log) {
			diag::log_tagged_critical_fmt("psv", "request_decompile_new addr=0x%llX label=%s",
				static_cast<unsigned long long>(addr),
				log_label.c_str());
		}
		diag::log_tagged_critical_fmt("psv",
			"request_decompile_dispatch addr=0x%llX label=%s file=%p",
			static_cast<unsigned long long>(addr),
			log_label.c_str(),
			file);
		decompiler_engine::decompile_function_native(addr, file);
		diag::log_tagged_critical_fmt("psv",
			"request_decompile_dispatch_returned addr=0x%llX label=%s",
			static_cast<unsigned long long>(addr),
			log_label.c_str());
	}
}

namespace {
inline void dismiss_popup_if_addr_locked(uint64_t addr)
{
	if (addr == 0) return;
	uint64_t cur = globals::ui::decompile_popup_addr.load(std::memory_order_acquire);
	if (cur == addr) {
		decompiler_engine::cancel_decompile();
		globals::ui::decompile_popup_active.store(false, std::memory_order_release);
	}
}
}

void close_active_tab()
{
	std::lock_guard<std::mutex> guard(state_mutex());
	auto& s = state();
	if (s.active_index < 0 || s.active_index >= static_cast<int>(s.tabs.size())) return;
	int idx = s.active_index;
	uint64_t closed_addr = s.tabs[idx]->addr;
	diag::log_tagged_fmt("pcode_view", "close_active_tab addr=0x%llX idx=%d",
		static_cast<unsigned long long>(closed_addr), idx);
	s.tabs.erase(s.tabs.begin() + idx);
	if (s.tabs.empty()) s.active_index = -1;
	else s.active_index = std::min(idx, static_cast<int>(s.tabs.size()) - 1);
	dismiss_popup_if_addr_locked(closed_addr);
	s.scrollbar_dragging = false;
}

void close_tab_by_addr(uint64_t addr)
{
	diag::log_tagged_fmt("pcode_view", "close_tab_by_addr addr=0x%llX",
		static_cast<unsigned long long>(addr));
	std::lock_guard<std::mutex> guard(state_mutex());
	auto& s = state();
	int found = -1;
	for (size_t i = 0; i < s.tabs.size(); ++i) {
		if (s.tabs[i]->addr == addr) {
			found = static_cast<int>(i);
			break;
		}
	}
	if (found < 0) return;
	bool was_active = (found == s.active_index);
	s.tabs.erase(s.tabs.begin() + found);
	if (s.tabs.empty()) {
		s.active_index = -1;
	} else if (was_active) {
		s.active_index = std::min(found, static_cast<int>(s.tabs.size()) - 1);
	} else if (found < s.active_index) {
		--s.active_index;
	}
	dismiss_popup_if_addr_locked(addr);
	s.scrollbar_dragging = false;
}

void activate_tab_by_addr(uint64_t addr)
{
	diag::log_tagged_fmt("pcode_view", "activate_tab_by_addr addr=0x%llX",
		static_cast<unsigned long long>(addr));
	std::lock_guard<std::mutex> guard(state_mutex());
	auto& s = state();
	for (size_t i = 0; i < s.tabs.size(); ++i) {
		if (s.tabs[i]->addr == addr) {
			diag::log_tagged_fmt("pcode_view", "activate_tab_found addr=0x%llX idx=%zu",
				static_cast<unsigned long long>(addr), i);
			s.active_index = static_cast<int>(i);
			globals::ui::active_center_view = center_view_t::pseudocode;
			return;
		}
	}
	diag::log_tagged_fmt("pcode_view", "activate_tab_not_found addr=0x%llX",
		static_cast<unsigned long long>(addr));
}

void close_all_tabs()
{
	std::lock_guard<std::mutex> guard(state_mutex());
	auto& s = state();
	diag::log_tagged_fmt("pcode_view", "close_all_tabs count=%zu",
		s.tabs.size());
	s.tabs.clear();
	s.active_index = -1;
	decompiler_engine::cancel_decompile();
	globals::ui::decompile_popup_active.store(false, std::memory_order_release);
	s.error_popup_active = false;
	s.scrollbar_dragging = false;
}

void cancel_active_decompile()
{
	decompiler_engine::cancel_decompile();
	globals::ui::decompile_popup_active.store(false, std::memory_order_release);
}

void refresh_active_tab()
{
	diag::log_tagged_fmt("pcode_view", "refresh_active_tab_enter");
	uint64_t addr = 0;
	{
		std::lock_guard<std::mutex> guard(state_mutex());
		auto at = active_tab_locked();
		if (!at) {
			diag::log_tagged_fmt("pcode_view", "refresh_active_tab_no_active_tab");
			return;
		}
		addr = at->addr;
		at->pending = true;
		at->decompiling = true;
		at->loaded = false;
		at->is_error = false;
	}
	diag::log_tagged_fmt("pcode_view", "refresh_active_tab_dispatch addr=0x%llX",
		static_cast<unsigned long long>(addr));
	decompiler_engine::erase_cache_entry(addr);
	globals::ui::decompile_popup_addr.store(addr, std::memory_order_release);
	globals::ui::decompile_popup_active.store(true, std::memory_order_release);
	decompiler_engine::decompile_function_native(addr, &g_disasm.file);
}

void refresh_all_tabs()
{
	diag::log_tagged_fmt("pcode_view", "refresh_all_tabs_enter");
	std::vector<uint64_t> addrs;
	uint64_t active_addr = 0;
	{
		std::lock_guard<std::mutex> guard(state_mutex());
		auto& s = state();
		diag::log_tagged_fmt("pcode_view", "refresh_all_tabs_count=%zu", s.tabs.size());
		addrs.reserve(s.tabs.size());
		for (auto& t : s.tabs) {
			if (!t) continue;
			t->pending = true;
			t->decompiling = true;
			t->loaded = false;
			t->is_error = false;
			t->error_text.clear();
			addrs.push_back(t->addr);
		}
		auto at = active_tab_locked();
		if (at) active_addr = at->addr;
	}
	for (uint64_t a : addrs) {
		decompiler_engine::erase_cache_entry(a);
	}
	if (active_addr != 0) {
		globals::ui::decompile_popup_addr.store(active_addr, std::memory_order_release);
		globals::ui::decompile_popup_active.store(true, std::memory_order_release);
		decompiler_engine::decompile_function_native(active_addr, &g_disasm.file);
	}
}

bool has_active_tab()
{
	std::lock_guard<std::mutex> guard(state_mutex());
	return active_tab_index_locked() >= 0;
}

bool has_tab_for(uint64_t addr)
{
	std::lock_guard<std::mutex> guard(state_mutex());
	return static_cast<bool>(find_tab_for_addr_locked(addr));
}

uint64_t active_tab_address()
{
	std::lock_guard<std::mutex> guard(state_mutex());
	auto t = active_tab_locked();
	return t ? t->addr : 0;
}

int tab_count()
{
	std::lock_guard<std::mutex> guard(state_mutex());
	return static_cast<int>(state().tabs.size());
}

std::vector<tab_info_t> snapshot_tabs()
{
	std::vector<tab_info_t> out;
	diag::log_tagged_critical_fmt("psv", "snapshot_tabs ENTER tid=%lu",
		static_cast<unsigned long>(GetCurrentThreadId()));
	std::lock_guard<std::mutex> guard(state_mutex());
	auto& s = state();
	diag::log_tagged_critical_fmt("psv", "snapshot_tabs locked tabs=%zu active=%d",
		s.tabs.size(), s.active_index);
	out.reserve(s.tabs.size());
	for (auto& t : s.tabs) {
		diag::log_tagged_critical_fmt("psv",
			"snapshot_tabs tab_raw=%p addr=0x%llX label=%s loaded=%d pending=%d decompiling=%d error=%d",
			t.get(),
			static_cast<unsigned long long>(t->addr),
			t->label.c_str(),
			t->loaded ? 1 : 0,
			t->pending ? 1 : 0,
			t->decompiling ? 1 : 0,
			t->is_error ? 1 : 0);
		tab_info_t ti;
		ti.addr = t->addr;
		ti.label = t->label;
		ti.function_name = resolve_tab_display_name(t->addr, t->function_name);
		ti.loaded = t->loaded;
		ti.decompiling = t->decompiling || t->pending;
		ti.is_error = t->is_error;
		out.push_back(std::move(ti));
	}
	diag::log_tagged_critical_fmt("psv", "snapshot_tabs EXIT count=%zu", out.size());
	return out;
}

void render(float pos_x, float pos_y, float width, float height,
            float alpha, float accent_r, float accent_g, float accent_b)
{
	(void)accent_r; (void)accent_g; (void)accent_b;

	diag::log_tagged_fmt("pcode_view", "render_enter tabs=%zu active_idx=%d alpha=%.2f",
		state().tabs.size(), state().active_index, static_cast<double>(alpha));

	bool deferred_dispatch_native = false;
	uint64_t deferred_dispatch_addr = 0;
	const DisasmFile* deferred_dispatch_file = nullptr;

	bool deferred_request_decompile = false;
	uint64_t deferred_request_addr = 0;
	const DisasmFile* deferred_request_file = nullptr;
	bool deferred_request_force = false;

	std::unique_lock<std::mutex> guard(state_mutex());
	poll_pending_tabs();
	check_popup_dismiss();

	const auto& tk = aida::ui::resolved();
	ImDrawList* dl = ImGui::GetWindowDrawList();
	ImVec2 origin = ImGui::GetWindowPos();
	float ox = origin.x + pos_x;
	float oy = origin.y + pos_y;
	auto _ta = [alpha](ImU32 c) -> ImU32 { return aida::ui::with_alpha(c, alpha); };

	dl->AddRectFilled(ImVec2(ox, oy), ImVec2(ox + width, oy + height), _ta(tk.bg_base));

	auto& s = state();

	if (s.tabs.empty()) {
		aida::ui::empty_state::config_t cfg;
		cfg.glyph = aida::ui::empty_state::glyph_t::binary_file;
		cfg.title = "No pseudocode tabs";
		cfg.body  = "Press F5 in the disassembly view, or right-click a function and choose Decompile Function.";
		cfg.hints = { { "F5" }, { "Tab" }, { "Right-click" } };
		aida::ui::empty_state::render(ImVec2(ox, oy), ImVec2(width, height), cfg);
		render_decompiling_popup(dl, ox, oy, width, height, alpha);
		render_error_popup(dl, ox, oy, width, height, alpha);
		return;
	}

	auto active = active_tab_locked();
	if (!active) {
		s.active_index = 0;
		active = state().tabs[0];
	}

	float toolbar_h = 44.f;
	dl->AddRectFilled(ImVec2(ox, oy), ImVec2(ox + width, oy + toolbar_h),
	                  aida::ui::with_alpha(tk.panel_header, alpha * 0.85f));
	dl->AddLine(ImVec2(ox, oy + toolbar_h), ImVec2(ox + width, oy + toolbar_h),
	            aida::ui::with_alpha(tk.border_subtle, alpha));

	{
		ImFont* hint_font = aida::ui::fonts::caption();
		if (!hint_font) hint_font = ImGui::GetFont();
		const char* hint = "PSEUDOCODE";
		dl->AddText(hint_font, 10.f,
			ImVec2(ox + 16.f, oy + (toolbar_h - 10.f) * 0.5f - 5.f),
			aida::ui::with_alpha(tk.text_dim, alpha * 0.85f), hint);

		ImFont* th_font = aida::ui::fonts::body_em();
		if (!th_font) th_font = ImGui::GetFont();
		std::string base_title = active->loaded && !active->function_name.empty()
			? active->function_name
			: active->label;
		std::string title = resolve_tab_display_name(active->addr, base_title);
		dl->AddText(th_font, 15.f,
			ImVec2(ox + 16.f, oy + (toolbar_h - 15.f) * 0.5f + 6.f),
			aida::ui::with_alpha(tk.text_primary, alpha), title.c_str());
	}

	float btn_pad = 8.f;
	float btn_h = 30.f;
	float btn_w = 90.f;
	float btn_y = oy + (toolbar_h - btn_h) * 0.5f;
	float btn_x_right = ox + width - 12.f;

	auto place_button_right = [&](float w) -> ImVec2 {
		btn_x_right -= w + btn_pad;
		ImGui::SetCursorScreenPos(ImVec2(btn_x_right, btn_y));
		return ImVec2(btn_x_right, btn_y);
	};

	{
		place_button_right(btn_w);
		if (aida::ui::components::button("Copy",
		    aida::ui::components::button_kind_t::secondary,
		    aida::ui::components::size_t_::md, ImVec2(btn_w, btn_h))) {
			diag::log_tagged_fmt("pcode_view", "toolbar_copy addr=0x%llX pseudocode_bytes=%zu",
				static_cast<unsigned long long>(active->addr), active->pseudocode.size());
			if (!active->pseudocode.empty()) copy_to_clipboard(active->pseudocode);
		}
	}
	{
		place_button_right(btn_w);
		if (aida::ui::components::button("Refresh",
		    aida::ui::components::button_kind_t::secondary,
		    aida::ui::components::size_t_::md, ImVec2(btn_w, btn_h))) {
			diag::log_tagged_fmt("pcode_view", "toolbar_refresh addr=0x%llX label=%s",
				static_cast<unsigned long long>(active->addr), active->label.c_str());
			active->pending = true;
			active->decompiling = true;
			active->loaded = false;
			active->is_error = false;
			decompiler_engine::erase_cache_entry(active->addr);
			globals::ui::decompile_popup_addr.store(active->addr, std::memory_order_release);
			globals::ui::decompile_popup_active.store(true, std::memory_order_release);
			deferred_dispatch_native = true;
			deferred_dispatch_addr = active->addr;
			deferred_dispatch_file = &g_disasm.file;
		}
	}
	if (active->addr) {
		place_button_right(btn_w);
		if (aida::ui::components::button("Disasm",
		    aida::ui::components::button_kind_t::primary,
		    aida::ui::components::size_t_::md, ImVec2(btn_w, btn_h))) {
			diag::log_tagged_fmt("pcode_view", "toolbar_goto_disasm addr=0x%llX",
				static_cast<unsigned long long>(active->addr));
			globals::ui::active_center_view = center_view_t::disassembly;
			disasm_view::goto_address(active->addr, g_disasm);
		}
	}

	float content_y = oy + toolbar_h;
	float content_h = height - toolbar_h;

	render_code_panel(dl, *active, ox, content_y, width, content_h, alpha);

	render_decompiling_popup(dl, ox, content_y, width, content_h, alpha);
	render_error_popup(dl, ox, content_y, width, content_h, alpha);

	{
		ImGuiIO& io = ImGui::GetIO();
		bool psv_panel_hovered = ImGui::IsMouseHoveringRect(
			ImVec2(ox, oy), ImVec2(ox + width, oy + height), false);
		bool psv_text_lock = io.WantTextInput || ImGui::IsAnyItemActive();

		if (psv_panel_hovered) {
			auto cursor_addr_or_entry = [&]() -> uint64_t {
				uint64_t out = active->addr;
				for (auto& kv : active->line_addr_map) {
					if (kv.first == active->cursor_line && kv.second != 0) {
						out = kv.second;
						break;
					}
				}
				return out;
			};

			if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_W, false)) {
				int idx = s.active_index;
				if (idx >= 0 && idx < static_cast<int>(s.tabs.size())) {
					uint64_t closed_addr = s.tabs[idx]->addr;
					diag::log_tagged_fmt("pcode_view", "key_close_tab addr=0x%llX idx=%d",
						static_cast<unsigned long long>(closed_addr), idx);
					s.tabs.erase(s.tabs.begin() + idx);
					if (s.tabs.empty()) s.active_index = -1;
					else s.active_index = std::min(idx, static_cast<int>(s.tabs.size()) - 1);
					dismiss_popup_if_addr_locked(closed_addr);
					s.scrollbar_dragging = false;
				}
			}

			if (io.KeyCtrl && !io.KeyShift && !io.KeyAlt && ImGui::IsKeyPressed(ImGuiKey_C, false)) {
				if (!psv_text_lock && !active->pseudocode.empty()) {
					diag::log_tagged_fmt("pcode_view", "key_copy_pseudocode addr=0x%llX bytes=%zu",
						static_cast<unsigned long long>(active->addr), active->pseudocode.size());
					copy_to_clipboard(active->pseudocode);
				}
			}

			if (!psv_text_lock && !io.KeyCtrl && !io.KeyAlt
			    && ImGui::IsKeyPressed(ImGuiKey_F5, false)) {
				uint64_t f5_cursor = resolve_disasm_cursor_addr();
				uint64_t f5_entry = 0;
				if (f5_cursor != 0) {
					f5_entry = disasm_view::enclosing_function_start(f5_cursor, g_disasm.file);
					if (f5_entry == 0) f5_entry = f5_cursor;
					f5_entry = follow_thunk_chain(f5_entry);
				}
				uint64_t f5_active_addr = active->addr;
				if (f5_entry == 0) {
					if (!s.error_popup_active) {
						s.error_popup_active = true;
						s.error_popup_message = "no cursor address available; place the cursor on an instruction in the disassembly view and press F5 again";
						s.error_popup_label = active->label;
						s.error_popup_addr = f5_active_addr;
						globals::ui::decompile_popup_active.store(false, std::memory_order_release);
#ifdef _WIN32
						MessageBeep(MB_ICONERROR);
#endif
					}
					diag::log_tagged_critical_fmt("f5", "psv_f5_no_cursor active_addr=0x%llX",
						static_cast<unsigned long long>(f5_active_addr));
				} else {
					bool same_addr = (f5_entry == f5_active_addr);
					diag::log_tagged_critical_fmt("f5",
						"psv_f5_resolved cursor=0x%llX entry=0x%llX active=0x%llX same=%d",
						static_cast<unsigned long long>(f5_cursor),
						static_cast<unsigned long long>(f5_entry),
						static_cast<unsigned long long>(f5_active_addr),
						same_addr ? 1 : 0);
					deferred_request_decompile = true;
					deferred_request_addr = f5_entry;
					deferred_request_file = &g_disasm.file;
					deferred_request_force = same_addr;
				}
			}

			if (ImGui::IsKeyPressed(ImGuiKey_Escape, false)) {
				if (globals::ui::decompile_popup_active.load(std::memory_order_acquire)) {
					decompiler_engine::cancel_decompile();
					globals::ui::decompile_popup_active.store(false, std::memory_order_release);
				} else if (s.error_popup_active) {
					s.error_popup_active = false;
				} else if (s.scrollbar_dragging) {
					s.scrollbar_dragging = false;
				}
			}

			if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_Tab, false)) {
				if (!s.tabs.empty()) {
					if (io.KeyShift)
						s.active_index = (s.active_index - 1 + static_cast<int>(s.tabs.size())) % static_cast<int>(s.tabs.size());
					else
						s.active_index = (s.active_index + 1) % static_cast<int>(s.tabs.size());
				}
			}

			if (!psv_text_lock && !io.KeyCtrl && !io.KeyAlt
			    && !globals::ui::decompile_popup_active.load(std::memory_order_acquire)
			    && !s.error_popup_active) {

				if (ImGui::IsKeyPressed(ImGuiKey_Space, false)) {
					uint64_t cursor_addr = cursor_addr_or_entry();
					diag::log_tagged_fmt("pcode_view", "key_space_cfg cursor=0x%llX",
						static_cast<unsigned long long>(cursor_addr));
					if (cursor_addr != 0) {
						uint64_t entry = disasm_view::enclosing_function_start(cursor_addr, g_disasm.file);
						if (entry == 0) entry = cursor_addr;
						cfg_view::g_state.current_rip = cursor_addr;
						cfg_view::g_state.last_cursor_addr = cursor_addr;
						if (cfg_view::g_state.entry_addr != entry || !cfg_view::g_state.built)
							cfg_view::build_cfg(entry);
						cfg_view::g_state.fit_request = true;
						globals::ui::active_center_view = center_view_t::graph_view;
					}
				}

				if (ImGui::IsKeyPressed(ImGuiKey_X, false)) {
					uint64_t cursor_addr = cursor_addr_or_entry();
					diag::log_tagged_fmt("pcode_view", "key_x_goto_disasm cursor=0x%llX",
						static_cast<unsigned long long>(cursor_addr));
					if (cursor_addr != 0) {
						globals::ui::active_center_view = center_view_t::disassembly;
						disasm_view::goto_address(cursor_addr, g_disasm);
					}
				}

				if (!comment_dialog::is_open() && ImGui::IsKeyPressed(ImGuiKey_Semicolon, false)) {
					uint64_t cmt_addr = cursor_addr_or_entry();
					diag::log_tagged_fmt("pcode_view", "key_comment addr=0x%llX",
						static_cast<unsigned long long>(cmt_addr));
					if (cmt_addr != 0)
						comment_dialog::open(cmt_addr);
				}

				if (!rename_dialog::is_open() && ImGui::IsKeyPressed(ImGuiKey_N, false)) {
					uint64_t rename_addr = cursor_addr_or_entry();
					diag::log_tagged_fmt("pcode_view", "key_rename addr=0x%llX",
						static_cast<unsigned long long>(rename_addr));
					if (rename_addr != 0)
						rename_dialog::open(rename_addr);
				}

				if (ImGui::IsKeyPressed(ImGuiKey_G, false)) {
					uint64_t goto_addr = cursor_addr_or_entry();
					diag::log_tagged_fmt("pcode_view", "key_g_goto addr=0x%llX",
						static_cast<unsigned long long>(goto_addr));
					globals::ui::active_center_view = center_view_t::disassembly;
					if (goto_addr != 0)
						disasm_view::goto_address(goto_addr, g_disasm);
					disasm_view::g_state.goto_visible = true;
					disasm_view::g_state.goto_buf[0] = '\0';
				}

				if (ImGui::IsKeyPressed(ImGuiKey_Tab, false)) {
					uint64_t tab_target = cursor_addr_or_entry();
					if (tab_target == 0) tab_target = active->addr;
					diag::log_tagged_fmt("pcode_view", "key_tab_switch_disasm addr=0x%llX",
						static_cast<unsigned long long>(tab_target));
					if (tab_target != 0) {
						globals::ui::active_center_view = center_view_t::disassembly;
						disasm_view::goto_address(tab_target, g_disasm);
					}
				}
			}

			if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_G, false)) {
				uint64_t goto_addr = cursor_addr_or_entry();
				diag::log_tagged_fmt("pcode_view", "key_ctrl_g_goto addr=0x%llX",
					static_cast<unsigned long long>(goto_addr));
				globals::ui::active_center_view = center_view_t::disassembly;
				if (goto_addr != 0)
					disasm_view::goto_address(goto_addr, g_disasm);
				disasm_view::g_state.goto_visible = true;
				disasm_view::g_state.goto_buf[0] = '\0';
			}
		}
	}

	guard.unlock();

	if (deferred_dispatch_native && deferred_dispatch_addr != 0) {
		decompiler_engine::decompile_function_native(deferred_dispatch_addr, deferred_dispatch_file);
	}

	if (deferred_request_decompile && deferred_request_addr != 0) {
		request_decompile(deferred_request_addr, deferred_request_file, deferred_request_force);
	}
}

}
