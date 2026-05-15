#pragma once

#include "ui/hub_strip.hpp"
#include "ui/clock.hpp"
#include "ui/theme.hpp"
#include "ui/components.hpp"
#include "ui/empty_state.hpp"
#include "ui/motion.hpp"
#include "ui/fonts.hpp"
#include "struct_recon_view.hpp"
#include "struct_dissector_view.hpp"
#include "struct_dissector.hpp"
#include "pdb_parser.hpp"
#include "symbol_store.hpp"
#include "../infra/work_queue.hpp"
#include "../disasm/disasm_view.hpp"
#include "../disasm/zydis_disasm.hpp"
#include "../../helpers/globals.h"

#include "imgui/imgui.h"
#include "imgui/imgui_internal.h"

#include <windows.h>
#include <commdlg.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

extern HWND g_hwnd;
extern DisasmState g_disasm;

namespace types_hub_view {

enum class sub_tab_t : int {
	structs = 0,
	unions,
	enums,
	typedefs,
	functions,
	inferred,
	dissector,
	COUNT
};

struct stats_t {
	std::string module_name;
	std::string pdb_path;
	size_t struct_count = 0;
	size_t union_count = 0;
	size_t enum_count = 0;
	size_t typedef_count = 0;
	size_t function_count = 0;
	size_t symbol_count = 0;
	bool loaded = false;
	bool loading = false;
	bool failed = false;
	std::string status_text;
};

struct loading_job_t {
	std::shared_ptr<pdb_parser::pdb_info_t> info;
	std::shared_ptr<std::atomic<float>> progress;
	std::shared_ptr<std::atomic<bool>> done;
	std::shared_ptr<std::atomic<bool>> ok;
	std::string pdb_path;
	std::string module_key;
};

struct state_t {
	aida::ui::hub_strip::state_t strip;

	char  search_struct[96] = {};
	char  search_union[96] = {};
	char  search_enum[96] = {};
	char  search_typedef[96] = {};
	char  search_function[96] = {};
	char  apply_addr_buf[20] = {};

	int   sel_struct = -1;
	int   sel_union = -1;
	int   sel_enum = -1;
	int   sel_typedef = -1;
	int   sel_function = -1;

	float scroll_list = 0.f;
	float target_scroll_list = 0.f;
	float scroll_detail = 0.f;
	float target_scroll_detail = 0.f;

	int   last_sel_tab = -1;
	std::string flash_message;
	float       flash_remaining = 0.f;
	uint32_t    flash_color = 0;

	std::vector<size_t> visible_struct_idx;
	std::vector<size_t> visible_union_idx;
	std::vector<size_t> visible_enum_idx;
	std::vector<size_t> visible_typedef_idx;
	std::vector<size_t> visible_function_idx;

	std::shared_ptr<loading_job_t> manual_job;
};

inline state_t g_state;

inline void set_sub_tab(sub_tab_t tab)
{
	int idx = static_cast<int>(tab);
	aida::ui::hub_strip::notify_select(g_state.strip, idx);
}

inline constexpr aida::ui::hub_strip::tab_t s_tabs[] = {
	{ "Structures", "PDB structs / classes" },
	{ "Unions",     "PDB unions" },
	{ "Enums",      "PDB enumerations" },
	{ "Typedefs",   "named type aliases" },
	{ "Functions",  "function signatures" },
	{ "Inferred",   "reconstructed from memory" },
	{ "Dissector",  "live struct dissector" },
};

inline void flash(const std::string& msg, ImU32 col)
{
	g_state.flash_message = msg;
	g_state.flash_remaining = 2.6f;
	g_state.flash_color = col;
}

inline bool ci_contains(const std::string& hay, const char* needle)
{
	if (!needle || !*needle) return true;
	std::string n = needle;
	std::string h = hay;
	std::transform(n.begin(), n.end(), n.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
	std::transform(h.begin(), h.end(), h.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
	return h.find(n) != std::string::npos;
}

inline std::string format_size_short(uint64_t bytes)
{
	char buf[32];
	if (bytes < 1024) std::snprintf(buf, sizeof(buf), "%llu B", static_cast<unsigned long long>(bytes));
	else if (bytes < 1024ull * 1024ull) std::snprintf(buf, sizeof(buf), "%.1f KB", static_cast<double>(bytes) / 1024.0);
	else std::snprintf(buf, sizeof(buf), "%.1f MB", static_cast<double>(bytes) / (1024.0 * 1024.0));
	return std::string(buf);
}

inline std::string typedef_target_name(const pdb_parser::pdb_info_t& pdb, uint32_t ti)
{
	(void)pdb;
	char buf[32];
	std::snprintf(buf, sizeof(buf), "ti_%u", ti);
	return buf;
}

inline std::string function_signature_for(const pdb_parser::pdb_info_t& pdb, const pdb_parser::pdb_symbol_t& sym)
{
	(void)pdb;
	std::string out;
	out.reserve(sym.name.size() + 16);
	out += sym.name;
	out += "()";
	return out;
}

inline stats_t snapshot_active_pdb()
{
	stats_t st;
	std::lock_guard<std::mutex> lk(symbol_store::g_state.mutex);

	const symbol_store::module_symbols_t* best = nullptr;
	for (auto& kv : symbol_store::g_state.modules) {
		auto& ms = kv.second;
		if (ms.pdb.loaded) {
			if (!best || ms.pdb.structs.size() > best->pdb.structs.size())
				best = &ms;
		}
	}

	if (!best) {
		for (auto& kv : symbol_store::g_state.modules) {
			auto& ms = kv.second;
			if (ms.loading) {
				st.loading = true;
				st.status_text = ms.status_text;
				st.module_name = ms.module_name;
				return st;
			}
		}
		for (auto& kv : symbol_store::g_state.modules) {
			auto& ms = kv.second;
			if (ms.failed) {
				st.failed = true;
				st.status_text = ms.status_text;
				st.module_name = ms.module_name;
				return st;
			}
		}
		return st;
	}

	st.module_name = best->module_name;
	st.pdb_path = best->pdb.file_path;
	st.symbol_count = best->pdb.symbols.size();
	st.struct_count = 0;
	st.union_count = 0;
	st.function_count = 0;
	for (auto& s : best->pdb.structs) {
		if (s.is_union) ++st.union_count;
		else ++st.struct_count;
	}
	for (auto& s : best->pdb.symbols) {
		if (s.is_function) ++st.function_count;
	}
	st.enum_count = best->pdb.enums.size();
	st.typedef_count = 0;
	st.loaded = true;
	char buf[96];
	std::snprintf(buf, sizeof(buf), "%zu structs, %zu enums, %zu symbols",
		st.struct_count + st.union_count, st.enum_count, st.symbol_count);
	st.status_text = buf;
	return st;
}

inline const pdb_parser::pdb_info_t* active_pdb_locked()
{
	const pdb_parser::pdb_info_t* best = nullptr;
	for (auto& kv : symbol_store::g_state.modules) {
		auto& ms = kv.second;
		if (ms.pdb.loaded) {
			if (!best || ms.pdb.structs.size() > best->structs.size())
				best = &ms.pdb;
		}
	}
	return best;
}

inline std::string browse_for_pdb()
{
	char buf[MAX_PATH] = {};
	OPENFILENAMEA ofn = {};
	ofn.lStructSize  = sizeof(ofn);
	ofn.hwndOwner    = g_hwnd;
	ofn.lpstrFile    = buf;
	ofn.nMaxFile     = MAX_PATH;
	ofn.lpstrFilter  = "PDB Symbol Files\0*.pdb\0All Files\0*.*\0\0";
	ofn.nFilterIndex = 1;
	ofn.Flags        = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_NOCHANGEDIR;
	if (GetOpenFileNameA(&ofn))
		return std::string(buf);
	return {};
}

inline void start_manual_pdb_load(const std::string& pdb_path)
{
	if (pdb_path.empty()) return;

	auto job = std::make_shared<loading_job_t>();
	job->info = std::make_shared<pdb_parser::pdb_info_t>();
	job->progress = std::make_shared<std::atomic<float>>(0.f);
	job->done = std::make_shared<std::atomic<bool>>(false);
	job->ok = std::make_shared<std::atomic<bool>>(false);
	job->pdb_path = pdb_path;

	auto stem = std::filesystem::path(pdb_path).stem().string();
	job->module_key = stem + ".pdb";

	g_state.manual_job = job;

	work_queue::post([job]() {
		bool ok = pdb_parser::parse_pdb(job->pdb_path, std::string{}, *job->info, job->progress.get());
		job->ok->store(ok, std::memory_order_release);
		job->done->store(true, std::memory_order_release);

		if (!ok) return;

		symbol_store::module_symbols_t ms;
		ms.module_name = job->module_key;
		ms.base = 0;
		ms.size = 0;
		ms.loading = false;
		ms.failed = false;
		ms.pdb = std::move(*job->info);
		char buf[64];
		std::snprintf(buf, sizeof(buf), "Loaded: %zu symbols, %zu types",
			ms.pdb.symbols.size(), ms.pdb.structs.size());
		ms.status_text = buf;
		{
			std::lock_guard<std::mutex> lk(symbol_store::g_state.mutex);
			symbol_store::g_state.modules[ms.module_name] = std::move(ms);
		}
	});
}

inline void poll_manual_job()
{
	if (!g_state.manual_job) return;
	if (!g_state.manual_job->done->load(std::memory_order_acquire)) return;

	if (g_state.manual_job->ok->load(std::memory_order_acquire)) {
		flash("PDB loaded: " + g_state.manual_job->module_key, aida::ui::resolved().success);
	} else {
		flash("Failed to parse PDB", aida::ui::resolved().error);
	}
	g_state.manual_job.reset();
}

inline void render_stat_bar(ImDrawList* dl, ImVec2 origin, float width, float height,
                            const stats_t& st, float alpha)
{
	const auto& th = aida::ui::resolved();
	ImVec2 a = origin;
	ImVec2 b = ImVec2(origin.x + width, origin.y + height);

	dl->AddRectFilled(a, b, aida::ui::with_alpha(th.panel_bg, alpha * 0.92f), 8.f);
	dl->AddRect(a, b, aida::ui::with_alpha(th.border_subtle, alpha), 8.f, 0, 1.f);

	ImFont* head = aida::ui::fonts::body_em();
	if (!head) head = ImGui::GetFont();
	ImFont* body = aida::ui::fonts::body();
	if (!body) body = ImGui::GetFont();
	ImFont* code = aida::ui::fonts::code();
	if (!code) code = ImGui::GetFont();

	float row_y = a.y + 8.f;

	std::string title;
	if (st.loaded) {
		title = st.module_name.empty() ? "Type database" : st.module_name;
	} else if (st.loading) {
		title = "Loading PDB...";
	} else {
		title = "No PDB loaded";
	}
	dl->AddText(head, 15.f, ImVec2(a.x + 14.f, row_y), aida::ui::with_alpha(th.text_primary, alpha), title.c_str());

	if (st.loaded) {
		ImU32 ok = aida::ui::with_alpha(th.success, alpha);
		dl->AddCircleFilled(ImVec2(b.x - 18.f, row_y + 8.f), 4.f, ok, 12);
		const char* live = "LIVE";
		ImVec2 lsz = head->CalcTextSizeA(11.f, FLT_MAX, 0.f, live);
		dl->AddText(head, 11.f, ImVec2(b.x - 24.f - lsz.x, row_y + 2.f),
			aida::ui::with_alpha(th.success, alpha), live);
	} else if (st.loading) {
		ImU32 c = aida::ui::with_alpha(th.warning, alpha);
		dl->AddCircleFilled(ImVec2(b.x - 18.f, row_y + 8.f), 4.f, c, 12);
		dl->AddText(head, 11.f, ImVec2(b.x - 60.f, row_y + 2.f), c, "BUSY");
	} else if (st.failed) {
		ImU32 c = aida::ui::with_alpha(th.error, alpha);
		dl->AddCircleFilled(ImVec2(b.x - 18.f, row_y + 8.f), 4.f, c, 12);
		dl->AddText(head, 11.f, ImVec2(b.x - 70.f, row_y + 2.f), c, "FAILED");
	}

	float stat_y = row_y + 24.f;
	float x = a.x + 14.f;

	struct stat_chip_t {
		const char* label;
		size_t      value;
		ImU32       color;
	};
	stat_chip_t chips[] = {
		{ "structs",   st.struct_count,   th.syn_keyword },
		{ "unions",    st.union_count,    th.warning },
		{ "enums",     st.enum_count,     th.syn_type },
		{ "functions", st.function_count, th.syn_function },
		{ "symbols",   st.symbol_count,   th.text_address },
	};
	for (auto& c : chips) {
		char value_buf[24];
		std::snprintf(value_buf, sizeof(value_buf), "%zu", c.value);
		ImVec2 vsz = code->CalcTextSizeA(15.f, FLT_MAX, 0.f, value_buf);
		ImVec2 lsz = body->CalcTextSizeA(11.f, FLT_MAX, 0.f, c.label);
		float chip_w = std::max(vsz.x, lsz.x) + 22.f;
		float chip_h = 36.f;
		ImVec2 ca = ImVec2(x, stat_y);
		ImVec2 cb = ImVec2(x + chip_w, stat_y + chip_h);
		dl->AddRectFilled(ca, cb, aida::ui::with_alpha(c.color, alpha * 0.10f), 6.f);
		dl->AddRect(ca, cb, aida::ui::with_alpha(c.color, alpha * 0.42f), 6.f, 0, 1.f);
		dl->AddText(code, 15.f, ImVec2(ca.x + (chip_w - vsz.x) * 0.5f, ca.y + 4.f),
			aida::ui::with_alpha(c.color, alpha), value_buf);
		dl->AddText(body, 11.f, ImVec2(ca.x + (chip_w - lsz.x) * 0.5f, ca.y + 22.f),
			aida::ui::with_alpha(th.text_dim, alpha), c.label);
		x += chip_w + 8.f;
	}

	if (!st.pdb_path.empty()) {
		std::string path_label = st.pdb_path;
		if (path_label.size() > 64) {
			path_label = "..." + path_label.substr(path_label.size() - 60);
		}
		ImVec2 psz = code->CalcTextSizeA(11.f, FLT_MAX, 0.f, path_label.c_str());
		float py = stat_y + 12.f;
		if (b.x - psz.x - 14.f > x + 8.f) {
			dl->AddText(code, 11.f, ImVec2(b.x - psz.x - 14.f, py),
				aida::ui::with_alpha(th.text_dim, alpha), path_label.c_str());
		}
	}
}

inline void render_search_bar(float origin_x, float origin_y, float width,
                              const char* hint, char* buf, size_t buf_size,
                              float alpha)
{
	const auto& th = aida::ui::resolved();
	float h = 32.f;
	ImDrawList* dl = ImGui::GetWindowDrawList();
	ImVec2 a = ImVec2(origin_x, origin_y);
	ImVec2 b = ImVec2(origin_x + width, origin_y + h);

	dl->AddRectFilled(a, b, aida::ui::with_alpha(th.panel_header, alpha * 0.55f), 8.f);
	dl->AddRect(a, b, aida::ui::with_alpha(th.border_subtle, alpha), 8.f, 0, 1.f);

	float r = 6.f;
	ImVec2 ic = ImVec2(a.x + 14.f, a.y + h * 0.5f);
	dl->AddCircle(ic, r, aida::ui::with_alpha(th.text_dim, alpha), 24, 1.4f);
	dl->AddLine(ImVec2(ic.x + r * 0.7071f, ic.y + r * 0.7071f),
	            ImVec2(ic.x + r * 1.4f, ic.y + r * 1.4f),
	            aida::ui::with_alpha(th.text_dim, alpha), 1.6f);

	ImGui::SetCursorScreenPos(ImVec2(a.x + 30.f, a.y + 5.f));
	ImGui::PushStyleColor(ImGuiCol_FrameBg, ImGui::ColorConvertU32ToFloat4(IM_COL32(0, 0, 0, 0)));
	ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(
		aida::ui::with_alpha(th.text_primary, alpha)));
	ImGui::PushStyleColor(ImGuiCol_TextDisabled, ImGui::ColorConvertU32ToFloat4(
		aida::ui::with_alpha(th.text_dim, alpha)));
	ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(0.f, 4.f));
	ImGui::PushItemWidth(width - 40.f);
	ImGui::InputTextWithHint("##types_search", hint, buf, buf_size);
	ImGui::PopItemWidth();
	ImGui::PopStyleVar();
	ImGui::PopStyleColor(3);
}

inline void render_empty_pdb_state(ImVec2 region_pos, ImVec2 region_size, bool loading, bool failed,
                                    const std::string& status_text, float progress_value)
{
	const auto& th = aida::ui::resolved();
	ImDrawList* dl = ImGui::GetWindowDrawList();

	ImVec2 center = ImVec2(region_pos.x + region_size.x * 0.5f,
	                        region_pos.y + region_size.y * 0.5f);
	float glyph_size = 64.f;

	ImU32 glyph_col = th.accent_dim;
	if (failed) glyph_col = th.error;
	if (loading) glyph_col = th.warning;

	aida::ui::empty_state::render_glyph(
		loading ? aida::ui::empty_state::glyph_t::cpu
		        : (failed ? aida::ui::empty_state::glyph_t::shield
		                  : aida::ui::empty_state::glyph_t::binary_file),
		dl, ImVec2(center.x, center.y - 80.f), glyph_size, glyph_col, 1.f);

	ImFont* title_font = aida::ui::fonts::body_strong();
	if (!title_font) title_font = ImGui::GetFont();
	ImFont* body_font = ImGui::GetFont();

	const char* title;
	if (loading) title = "Parsing PDB symbols";
	else if (failed) title = "PDB load failed";
	else title = "No symbol database available";

	ImVec2 tsz = title_font->CalcTextSizeA(20.f, FLT_MAX, 0.f, title);
	dl->AddText(title_font, 20.f, ImVec2(center.x - tsz.x * 0.5f, center.y - 30.f),
		th.text_primary, title);

	const char* body;
	if (loading) body = "Walking type records, this can take a few seconds for large modules.";
	else if (failed) body = status_text.empty()
		? "DbgHelp could not parse the file. Verify the path and try a different PDB."
		: status_text.c_str();
	else body = "Load a PDB to browse structures, unions, enumerations, typedefs and function signatures discovered in the target binary.";

	float wrap = 460.f;
	ImVec2 bsz = body_font->CalcTextSizeA(14.f, FLT_MAX, wrap, body);
	dl->AddText(body_font, 14.f, ImVec2(center.x - bsz.x * 0.5f, center.y + 2.f),
		th.text_secondary, body, nullptr, wrap);

	if (loading) {
		float bar_w = 280.f;
		aida::ui::render_progress_bar(ImVec2(center.x - bar_w * 0.5f, center.y + 60.f),
			bar_w, 6.f, progress_value, progress_value <= 0.f, true);
	} else {
		float btn_w = 180.f;
		ImGui::SetCursorScreenPos(ImVec2(center.x - btn_w * 0.5f, center.y + 64.f));
		if (aida::ui::button("Load PDB", aida::ui::button_kind_t::primary,
			aida::ui::size_t_::md, ImVec2(btn_w, 0.f))) {
			std::string p = browse_for_pdb();
			if (!p.empty()) start_manual_pdb_load(p);
		}
	}
}

inline void render_struct_detail(const pdb_parser::struct_def_t& def, float origin_x, float origin_y,
                                  float width, float height, float alpha)
{
	const auto& th = aida::ui::resolved();
	ImDrawList* dl = ImGui::GetWindowDrawList();
	ImFont* head = aida::ui::fonts::body_em();
	if (!head) head = ImGui::GetFont();
	ImFont* body = ImGui::GetFont();
	ImFont* code = aida::ui::fonts::code();
	if (!code) code = ImGui::GetFont();

	ImVec2 a = ImVec2(origin_x, origin_y);
	ImVec2 b = ImVec2(origin_x + width, origin_y + height);
	dl->AddRectFilled(a, b, aida::ui::with_alpha(th.panel_bg, alpha * 0.55f), 8.f);
	dl->AddRect(a, b, aida::ui::with_alpha(th.border_subtle, alpha), 8.f, 0, 1.f);

	float top_h = 56.f;
	dl->AddRectFilled(a, ImVec2(b.x, a.y + top_h),
		aida::ui::with_alpha(th.panel_header, alpha * 0.55f), 8.f);
	dl->AddLine(ImVec2(a.x + 8.f, a.y + top_h - 1.f), ImVec2(b.x - 8.f, a.y + top_h - 1.f),
		aida::ui::with_alpha(th.border_subtle, alpha));

	dl->AddText(head, 16.f, ImVec2(a.x + 14.f, a.y + 8.f),
		aida::ui::with_alpha(th.text_primary, alpha), def.name.c_str());

	char meta[96];
	std::snprintf(meta, sizeof(meta), "%s  %llu bytes  (0x%llX)  %zu fields  ti=%u",
		def.is_union ? "union" : "struct",
		static_cast<unsigned long long>(def.size),
		static_cast<unsigned long long>(def.size),
		def.members.size(),
		def.type_index);
	dl->AddText(code, 12.f, ImVec2(a.x + 14.f, a.y + 30.f),
		aida::ui::with_alpha(th.text_dim, alpha), meta);

	ImGui::SetCursorScreenPos(ImVec2(b.x - 320.f, a.y + 16.f));
	if (aida::ui::button("Copy C", aida::ui::button_kind_t::ghost,
		aida::ui::size_t_::sm, ImVec2(74.f, 28.f))) {
		std::string cpp = pdb_parser::struct_to_cpp(def);
		ImGui::SetClipboardText(cpp.c_str());
		flash("Copied " + def.name + " as C", th.success);
	}
	ImGui::SameLine();
	if (aida::ui::button("To Dissector", aida::ui::button_kind_t::secondary,
		aida::ui::size_t_::sm, ImVec2(108.f, 28.f))) {
		int idx = struct_dissector::create_struct(def.name);
		for (auto& m : def.members) {
			struct_dissector::field_def_t fd;
			fd.name = m.name.empty() ? std::string("field_") + std::to_string(m.offset) : m.name;
			fd.offset = static_cast<uint32_t>(m.offset);
			fd.size = static_cast<uint32_t>(m.size > 0 ? m.size : 1);
			if (m.is_pointer) fd.type = struct_dissector::field_type_t::pointer;
			else if (m.size == 1) fd.type = struct_dissector::field_type_t::uint8;
			else if (m.size == 2) fd.type = struct_dissector::field_type_t::uint16;
			else if (m.size == 4) fd.type = struct_dissector::field_type_t::uint32;
			else if (m.size == 8) fd.type = struct_dissector::field_type_t::uint64;
			else fd.type = struct_dissector::field_type_t::byte_array;
			fd.description = m.type_name;
			struct_dissector::add_field(idx, fd);
		}
		flash("Pushed " + def.name + " into dissector (" + std::to_string(def.members.size()) + " fields)", th.success);
	}
	ImGui::SameLine();
	if (aida::ui::button("Open Dissector", aida::ui::button_kind_t::primary,
		aida::ui::size_t_::sm, ImVec2(122.f, 28.f))) {
		set_sub_tab(sub_tab_t::dissector);
	}

	float body_y = a.y + top_h + 10.f;
	float body_h = height - top_h - 10.f - 12.f;

	const float col_off = 70.f;
	const float col_size = 60.f;
	const float col_type = 220.f;
	float col_name = (b.x - 12.f) - (a.x + 14.f) - col_off - col_size - col_type - 12.f;
	if (col_name < 120.f) col_name = 120.f;

	float hdr_h = 24.f;
	ImVec2 ha = ImVec2(a.x + 8.f, body_y);
	ImVec2 hb = ImVec2(b.x - 8.f, body_y + hdr_h);
	dl->AddRectFilled(ha, hb, aida::ui::with_alpha(th.panel_header, alpha * 0.6f), 4.f);
	float hx = ha.x + 6.f;
	dl->AddText(head, 11.f, ImVec2(hx, ha.y + 5.f), aida::ui::with_alpha(th.text_secondary, alpha), "OFFSET");
	hx += col_off;
	dl->AddText(head, 11.f, ImVec2(hx, ha.y + 5.f), aida::ui::with_alpha(th.text_secondary, alpha), "SIZE");
	hx += col_size;
	dl->AddText(head, 11.f, ImVec2(hx, ha.y + 5.f), aida::ui::with_alpha(th.text_secondary, alpha), "TYPE");
	hx += col_type;
	dl->AddText(head, 11.f, ImVec2(hx, ha.y + 5.f), aida::ui::with_alpha(th.text_secondary, alpha), "NAME");

	float list_y = body_y + hdr_h + 4.f;
	float list_h = body_h - hdr_h - 4.f;
	const float row_h = 22.f;

	g_state.scroll_detail = aida::motion::smooth_lerp(g_state.scroll_detail,
		g_state.target_scroll_detail, 18.f, aida::ui::clock::dt());

	bool hovered = ImGui::IsMouseHoveringRect(
		ImVec2(a.x + 8.f, list_y), ImVec2(b.x - 8.f, list_y + list_h));
	if (hovered) {
		float wheel = ImGui::GetIO().MouseWheel;
		if (wheel != 0.f) g_state.target_scroll_detail -= wheel * row_h * 3.f;
	}

	int count = static_cast<int>(def.members.size());
	float content_h = static_cast<float>(count) * row_h;
	if (g_state.target_scroll_detail < 0.f) g_state.target_scroll_detail = 0.f;
	float ms = std::max(0.f, content_h - list_h);
	if (g_state.target_scroll_detail > ms) g_state.target_scroll_detail = ms;

	ImGui::PushClipRect(ImVec2(a.x + 8.f, list_y), ImVec2(b.x - 8.f, list_y + list_h), true);
	uint64_t last_end = 0;
	for (int i = 0; i < count; ++i) {
		float ry = list_y + static_cast<float>(i) * row_h - g_state.scroll_detail;
		if (ry + row_h < list_y || ry > list_y + list_h) {
			last_end = def.members[i].offset + def.members[i].size;
			continue;
		}
		const auto& m = def.members[i];
		ImVec2 ra = ImVec2(a.x + 8.f, ry);
		ImVec2 rb = ImVec2(b.x - 8.f, ry + row_h);

		bool hov = ImGui::IsMouseHoveringRect(ra, rb);
		if (i & 1) dl->AddRectFilled(ra, rb, aida::ui::with_alpha(th.panel_header, alpha * 0.25f));
		if (hov) dl->AddRectFilled(ra, rb, aida::ui::with_alpha(th.hover_wash, alpha));

		if (m.offset > last_end) {
			char gap_buf[32];
			std::snprintf(gap_buf, sizeof(gap_buf), "+0x%llX  gap", static_cast<unsigned long long>(m.offset - last_end));
			dl->AddText(code, 11.f, ImVec2(ra.x + 6.f, ry - 12.f),
				aida::ui::with_alpha(th.warning, alpha * 0.55f), gap_buf);
		}

		float fx = ra.x + 6.f;
		char off_buf[16];
		std::snprintf(off_buf, sizeof(off_buf), "+0x%03llX", static_cast<unsigned long long>(m.offset));
		dl->AddText(code, 12.f, ImVec2(fx, ry + 4.f),
			aida::ui::with_alpha(th.text_address, alpha), off_buf);
		fx += col_off;

		char size_buf[12];
		std::snprintf(size_buf, sizeof(size_buf), "%llu", static_cast<unsigned long long>(m.size));
		dl->AddText(code, 12.f, ImVec2(fx, ry + 4.f),
			aida::ui::with_alpha(th.text_dim, alpha), size_buf);
		fx += col_size;

		std::string type_text = m.type_name;
		if (m.is_array) {
			char ab_buf[16];
			std::snprintf(ab_buf, sizeof(ab_buf), "[%d]", m.array_count);
			type_text += ab_buf;
		}
		if (m.bit_size >= 0) {
			char bb[16];
			std::snprintf(bb, sizeof(bb), " :%d", m.bit_size);
			type_text += bb;
		}
		dl->AddText(code, 12.f, ImVec2(fx, ry + 4.f),
			aida::ui::with_alpha(m.is_pointer ? th.syn_function : th.syn_type, alpha),
			type_text.c_str());
		fx += col_type;

		dl->AddText(body, 13.f, ImVec2(fx, ry + 3.f),
			aida::ui::with_alpha(th.text_primary, alpha),
			m.name.c_str());

		last_end = m.offset + m.size;
	}
	if (last_end < def.size) {
		float ry = list_y + static_cast<float>(count) * row_h - g_state.scroll_detail;
		if (ry < list_y + list_h) {
			char tail_buf[48];
			std::snprintf(tail_buf, sizeof(tail_buf), "+0x%03llX  trailing pad  %llu bytes",
				static_cast<unsigned long long>(last_end),
				static_cast<unsigned long long>(def.size - last_end));
			dl->AddText(code, 12.f, ImVec2(a.x + 14.f, ry + 4.f),
				aida::ui::with_alpha(th.text_dim, alpha), tail_buf);
		}
	}
	ImGui::PopClipRect();
}

inline void render_enum_detail(const pdb_parser::enum_def_t& def, float origin_x, float origin_y,
                                float width, float height, float alpha)
{
	const auto& th = aida::ui::resolved();
	ImDrawList* dl = ImGui::GetWindowDrawList();
	ImFont* head = aida::ui::fonts::body_em();
	if (!head) head = ImGui::GetFont();
	ImFont* body = ImGui::GetFont();
	ImFont* code = aida::ui::fonts::code();
	if (!code) code = ImGui::GetFont();

	ImVec2 a = ImVec2(origin_x, origin_y);
	ImVec2 b = ImVec2(origin_x + width, origin_y + height);
	dl->AddRectFilled(a, b, aida::ui::with_alpha(th.panel_bg, alpha * 0.55f), 8.f);
	dl->AddRect(a, b, aida::ui::with_alpha(th.border_subtle, alpha), 8.f, 0, 1.f);

	float top_h = 50.f;
	dl->AddRectFilled(a, ImVec2(b.x, a.y + top_h),
		aida::ui::with_alpha(th.panel_header, alpha * 0.55f), 8.f);
	dl->AddLine(ImVec2(a.x + 8.f, a.y + top_h - 1.f), ImVec2(b.x - 8.f, a.y + top_h - 1.f),
		aida::ui::with_alpha(th.border_subtle, alpha));

	dl->AddText(head, 16.f, ImVec2(a.x + 14.f, a.y + 8.f),
		aida::ui::with_alpha(th.text_primary, alpha), def.name.c_str());
	char meta[64];
	std::snprintf(meta, sizeof(meta), "enum  %zu members  ti=%u",
		def.members.size(), def.type_index);
	dl->AddText(code, 12.f, ImVec2(a.x + 14.f, a.y + 28.f),
		aida::ui::with_alpha(th.text_dim, alpha), meta);

	ImGui::SetCursorScreenPos(ImVec2(b.x - 100.f, a.y + 12.f));
	if (aida::ui::button("Copy C", aida::ui::button_kind_t::ghost,
		aida::ui::size_t_::sm, ImVec2(76.f, 28.f))) {
		std::string out = "enum " + def.name + " {\n";
		for (auto& m : def.members) {
			char line[128];
			std::snprintf(line, sizeof(line), "    %s = 0x%llX,\n",
				m.name.c_str(), static_cast<unsigned long long>(m.value));
			out += line;
		}
		out += "};\n";
		ImGui::SetClipboardText(out.c_str());
		flash("Copied " + def.name + " as C", th.success);
	}

	float list_y = a.y + top_h + 8.f;
	float list_h = height - top_h - 8.f - 8.f;
	const float row_h = 22.f;

	int count = static_cast<int>(def.members.size());

	ImGui::PushClipRect(ImVec2(a.x + 8.f, list_y), ImVec2(b.x - 8.f, list_y + list_h), true);
	for (int i = 0; i < count; ++i) {
		float ry = list_y + static_cast<float>(i) * row_h;
		if (ry + row_h < list_y || ry > list_y + list_h) continue;
		const auto& m = def.members[i];
		ImVec2 ra = ImVec2(a.x + 8.f, ry);
		ImVec2 rb = ImVec2(b.x - 8.f, ry + row_h);
		if (i & 1) dl->AddRectFilled(ra, rb, aida::ui::with_alpha(th.panel_header, alpha * 0.22f));

		char hex_buf[24];
		std::snprintf(hex_buf, sizeof(hex_buf), "0x%llX", static_cast<unsigned long long>(m.value));
		dl->AddText(code, 12.f, ImVec2(ra.x + 6.f, ry + 4.f),
			aida::ui::with_alpha(th.syn_number, alpha), hex_buf);

		char dec_buf[24];
		std::snprintf(dec_buf, sizeof(dec_buf), "%lld", static_cast<long long>(m.value));
		dl->AddText(code, 12.f, ImVec2(ra.x + 130.f, ry + 4.f),
			aida::ui::with_alpha(th.text_dim, alpha), dec_buf);

		dl->AddText(body, 13.f, ImVec2(ra.x + 220.f, ry + 3.f),
			aida::ui::with_alpha(th.text_primary, alpha), m.name.c_str());
	}
	ImGui::PopClipRect();
}

inline void render_function_detail(const pdb_parser::pdb_info_t& pdb,
                                    const pdb_parser::pdb_symbol_t& sym,
                                    float origin_x, float origin_y, float width, float height,
                                    float alpha)
{
	const auto& th = aida::ui::resolved();
	ImDrawList* dl = ImGui::GetWindowDrawList();
	ImFont* head = aida::ui::fonts::body_em();
	if (!head) head = ImGui::GetFont();
	ImFont* code = aida::ui::fonts::code();
	if (!code) code = ImGui::GetFont();

	ImVec2 a = ImVec2(origin_x, origin_y);
	ImVec2 b = ImVec2(origin_x + width, origin_y + height);
	dl->AddRectFilled(a, b, aida::ui::with_alpha(th.panel_bg, alpha * 0.55f), 8.f);
	dl->AddRect(a, b, aida::ui::with_alpha(th.border_subtle, alpha), 8.f, 0, 1.f);

	dl->AddText(head, 15.f, ImVec2(a.x + 14.f, a.y + 12.f),
		aida::ui::with_alpha(th.text_primary, alpha), sym.name.c_str());

	char meta[128];
	std::snprintf(meta, sizeof(meta), "rva=0x%llX  size=%u  ti=%u  module=%s",
		static_cast<unsigned long long>(sym.rva), sym.size, sym.type_index,
		pdb.module_name.c_str());
	dl->AddText(code, 12.f, ImVec2(a.x + 14.f, a.y + 34.f),
		aida::ui::with_alpha(th.text_dim, alpha), meta);

	std::string sig = function_signature_for(pdb, sym);
	dl->AddText(code, 14.f, ImVec2(a.x + 14.f, a.y + 60.f),
		aida::ui::with_alpha(th.syn_function, alpha), sig.c_str());

	ImGui::SetCursorScreenPos(ImVec2(a.x + 14.f, a.y + 90.f));
	if (aida::ui::button("Copy name", aida::ui::button_kind_t::ghost,
		aida::ui::size_t_::sm, ImVec2(108.f, 28.f))) {
		ImGui::SetClipboardText(sym.name.c_str());
		flash("Copied symbol name", th.success);
	}
	ImGui::SameLine();
	if (aida::ui::button("Copy RVA", aida::ui::button_kind_t::ghost,
		aida::ui::size_t_::sm, ImVec2(96.f, 28.f))) {
		char rb[24];
		std::snprintf(rb, sizeof(rb), "0x%llX", static_cast<unsigned long long>(sym.rva));
		ImGui::SetClipboardText(rb);
		flash("Copied RVA", th.success);
	}
	ImGui::SameLine();
	if (aida::ui::button("Jump", aida::ui::button_kind_t::primary,
		aida::ui::size_t_::sm, ImVec2(96.f, 28.f))) {
		uint64_t addr = symbol_store::resolve_name_to_addr(sym.name);
		if (addr == 0 && g_disasm.file.image_base != 0) {
			addr = g_disasm.file.image_base + sym.rva;
		}
		if (addr != 0) {
			globals::ui::active_center_view = center_view_t::disassembly;
			disasm_view::goto_address(addr, g_disasm);
			flash("Jumped to disassembly", th.success);
		} else {
			flash("No active disassembly target", th.error);
		}
	}
}

inline void render_list_pane(float origin_x, float origin_y, float width, float height,
                              const std::vector<std::string>& labels,
                              const std::vector<std::string>& sublabels,
                              int& selection, float alpha)
{
	const auto& th = aida::ui::resolved();
	ImDrawList* dl = ImGui::GetWindowDrawList();
	ImFont* body = ImGui::GetFont();
	ImFont* code = aida::ui::fonts::code();
	if (!code) code = ImGui::GetFont();

	ImVec2 a = ImVec2(origin_x, origin_y);
	ImVec2 b = ImVec2(origin_x + width, origin_y + height);
	dl->AddRectFilled(a, b, aida::ui::with_alpha(th.panel_bg, alpha * 0.40f), 8.f);
	dl->AddRect(a, b, aida::ui::with_alpha(th.border_subtle, alpha), 8.f, 0, 1.f);

	const float row_h = 30.f;
	int count = static_cast<int>(labels.size());
	float content_h = static_cast<float>(count) * row_h;

	g_state.scroll_list = aida::motion::smooth_lerp(g_state.scroll_list,
		g_state.target_scroll_list, 18.f, aida::ui::clock::dt());

	bool hovered = ImGui::IsMouseHoveringRect(a, b);
	if (hovered) {
		float wheel = ImGui::GetIO().MouseWheel;
		if (wheel != 0.f) g_state.target_scroll_list -= wheel * row_h * 3.f;
	}
	if (g_state.target_scroll_list < 0.f) g_state.target_scroll_list = 0.f;
	float ms = std::max(0.f, content_h - height);
	if (g_state.target_scroll_list > ms) g_state.target_scroll_list = ms;

	ImGui::PushClipRect(a, b, true);

	if (count == 0) {
		ImFont* head = aida::ui::fonts::body_em();
		if (!head) head = body;
		const char* msg = "No matches";
		ImVec2 sz = head->CalcTextSizeA(13.f, FLT_MAX, 0.f, msg);
		dl->AddText(head, 13.f, ImVec2(a.x + (width - sz.x) * 0.5f, a.y + height * 0.5f - 8.f),
			aida::ui::with_alpha(th.text_dim, alpha), msg);
	}

	for (int i = 0; i < count; ++i) {
		float ry = a.y + static_cast<float>(i) * row_h - g_state.scroll_list;
		if (ry + row_h < a.y || ry > b.y) continue;

		ImVec2 ra = ImVec2(a.x + 4.f, ry);
		ImVec2 rb = ImVec2(b.x - 4.f, ry + row_h);
		bool hov = ImGui::IsMouseHoveringRect(ra, rb);
		bool sel = (selection == i);

		if (sel) {
			dl->AddRectFilled(ra, rb, aida::ui::with_alpha(th.selection, alpha), 6.f);
			dl->AddRectFilled(ImVec2(ra.x, ra.y + 4.f), ImVec2(ra.x + 3.f, rb.y - 4.f),
				aida::ui::with_alpha(th.accent_u32, alpha), 1.5f);
		} else if (hov) {
			dl->AddRectFilled(ra, rb, aida::ui::with_alpha(th.hover_wash, alpha), 6.f);
		}

		if (hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
			selection = i;
			g_state.target_scroll_detail = 0.f;
		}

		dl->AddText(body, 13.f, ImVec2(ra.x + 10.f, ry + 4.f),
			aida::ui::with_alpha(sel ? th.text_primary : th.text_secondary, alpha),
			labels[static_cast<size_t>(i)].c_str());
		if (i < static_cast<int>(sublabels.size()) && !sublabels[static_cast<size_t>(i)].empty()) {
			dl->AddText(code, 11.f, ImVec2(ra.x + 10.f, ry + 17.f),
				aida::ui::with_alpha(th.text_dim, alpha),
				sublabels[static_cast<size_t>(i)].c_str());
		}
	}

	ImGui::PopClipRect();

	if (content_h > height && height > 0.f) {
		float bar_x = b.x - 6.f;
		float ratio = height / content_h;
		float thumb_h = std::max(height * ratio, 24.f);
		float track = height - thumb_h;
		float scroll_ratio = (content_h - height > 0.f) ? g_state.scroll_list / (content_h - height) : 0.f;
		float thumb_y = a.y + track * scroll_ratio;
		dl->AddRectFilled(ImVec2(bar_x, a.y + 4.f), ImVec2(bar_x + 4.f, b.y - 4.f),
			aida::ui::with_alpha(th.panel_header, alpha * 0.4f), 2.f);
		dl->AddRectFilled(ImVec2(bar_x, thumb_y), ImVec2(bar_x + 4.f, thumb_y + thumb_h),
			aida::ui::with_alpha(th.accent_dim, alpha), 2.f);
	}
}

inline void render_browser_pane(sub_tab_t tab, float origin_x, float origin_y,
                                 float width, float height, float alpha)
{
	const auto& th = aida::ui::resolved();
	(void)th;

	const float search_h = 38.f;
	const float gutter = 10.f;

	float list_w = std::floor(width * 0.36f);
	if (list_w < 220.f) list_w = 220.f;
	if (list_w > 360.f) list_w = 360.f;
	float detail_w = width - list_w - gutter;
	if (detail_w < 200.f) detail_w = 200.f;

	char* buf = nullptr;
	size_t buf_size = 0;
	const char* hint = "search";
	switch (tab) {
		case sub_tab_t::structs:   buf = g_state.search_struct;   buf_size = sizeof(g_state.search_struct);   hint = "filter structs"; break;
		case sub_tab_t::unions:    buf = g_state.search_union;    buf_size = sizeof(g_state.search_union);    hint = "filter unions"; break;
		case sub_tab_t::enums:     buf = g_state.search_enum;     buf_size = sizeof(g_state.search_enum);     hint = "filter enums"; break;
		case sub_tab_t::typedefs:  buf = g_state.search_typedef;  buf_size = sizeof(g_state.search_typedef);  hint = "filter typedefs"; break;
		case sub_tab_t::functions: buf = g_state.search_function; buf_size = sizeof(g_state.search_function); hint = "filter by name / signature"; break;
		default: break;
	}

	if (buf) {
		render_search_bar(origin_x, origin_y, list_w, hint, buf, buf_size, alpha);
	}

	float list_y = origin_y + search_h;
	float list_h = height - search_h;

	std::vector<std::string> labels;
	std::vector<std::string> sublabels;
	int* selection = nullptr;

	const pdb_parser::struct_def_t* sel_struct_ref = nullptr;
	const pdb_parser::enum_def_t*   sel_enum_ref = nullptr;
	pdb_parser::pdb_symbol_t        sel_function_copy;
	const pdb_parser::pdb_info_t*   pdb_for_detail = nullptr;
	bool have_function = false;

	{
		std::lock_guard<std::mutex> lk(symbol_store::g_state.mutex);
		const pdb_parser::pdb_info_t* pdb = active_pdb_locked();
		if (pdb) {
			pdb_for_detail = pdb;

			if (tab == sub_tab_t::structs) {
				g_state.visible_struct_idx.clear();
				labels.reserve(pdb->structs.size());
				sublabels.reserve(pdb->structs.size());
				for (size_t i = 0; i < pdb->structs.size(); ++i) {
					const auto& s = pdb->structs[i];
					if (s.is_union) continue;
					if (!ci_contains(s.name, buf)) continue;
					g_state.visible_struct_idx.push_back(i);
					labels.push_back(s.name);
					char sub[64];
					std::snprintf(sub, sizeof(sub), "%llu B  %zu fields",
						static_cast<unsigned long long>(s.size), s.members.size());
					sublabels.push_back(sub);
				}
				selection = &g_state.sel_struct;
				if (*selection >= static_cast<int>(g_state.visible_struct_idx.size())) *selection = -1;
				if (*selection >= 0) {
					size_t i = g_state.visible_struct_idx[static_cast<size_t>(*selection)];
					sel_struct_ref = &pdb->structs[i];
				}
			}
			else if (tab == sub_tab_t::unions) {
				g_state.visible_union_idx.clear();
				for (size_t i = 0; i < pdb->structs.size(); ++i) {
					const auto& s = pdb->structs[i];
					if (!s.is_union) continue;
					if (!ci_contains(s.name, buf)) continue;
					g_state.visible_union_idx.push_back(i);
					labels.push_back(s.name);
					char sub[64];
					std::snprintf(sub, sizeof(sub), "%llu B  %zu fields",
						static_cast<unsigned long long>(s.size), s.members.size());
					sublabels.push_back(sub);
				}
				selection = &g_state.sel_union;
				if (*selection >= static_cast<int>(g_state.visible_union_idx.size())) *selection = -1;
				if (*selection >= 0) {
					size_t i = g_state.visible_union_idx[static_cast<size_t>(*selection)];
					sel_struct_ref = &pdb->structs[i];
				}
			}
			else if (tab == sub_tab_t::enums) {
				g_state.visible_enum_idx.clear();
				for (size_t i = 0; i < pdb->enums.size(); ++i) {
					const auto& e = pdb->enums[i];
					if (!ci_contains(e.name, buf)) continue;
					g_state.visible_enum_idx.push_back(i);
					labels.push_back(e.name);
					char sub[48];
					std::snprintf(sub, sizeof(sub), "%zu values", e.members.size());
					sublabels.push_back(sub);
				}
				selection = &g_state.sel_enum;
				if (*selection >= static_cast<int>(g_state.visible_enum_idx.size())) *selection = -1;
				if (*selection >= 0) {
					size_t i = g_state.visible_enum_idx[static_cast<size_t>(*selection)];
					sel_enum_ref = &pdb->enums[i];
				}
			}
			else if (tab == sub_tab_t::typedefs) {
				g_state.visible_typedef_idx.clear();
				selection = &g_state.sel_typedef;
				*selection = -1;
			}
			else if (tab == sub_tab_t::functions) {
				g_state.visible_function_idx.clear();
				for (size_t i = 0; i < pdb->symbols.size(); ++i) {
					const auto& s = pdb->symbols[i];
					if (!s.is_function) continue;
					if (!ci_contains(s.name, buf)) continue;
					g_state.visible_function_idx.push_back(i);
				}
				labels.reserve(g_state.visible_function_idx.size());
				sublabels.reserve(g_state.visible_function_idx.size());
				for (size_t idx : g_state.visible_function_idx) {
					const auto& s = pdb->symbols[idx];
					labels.push_back(s.name);
					char sub[48];
					std::snprintf(sub, sizeof(sub), "rva=0x%llX  %u B",
						static_cast<unsigned long long>(s.rva), s.size);
					sublabels.push_back(sub);
				}
				selection = &g_state.sel_function;
				if (*selection >= static_cast<int>(g_state.visible_function_idx.size())) *selection = -1;
				if (*selection >= 0) {
					size_t i = g_state.visible_function_idx[static_cast<size_t>(*selection)];
					sel_function_copy = pdb->symbols[i];
					have_function = true;
				}
			}
		}
	}

	int fake = -1;
	int* sel_ptr = selection ? selection : &fake;
	render_list_pane(origin_x, list_y, list_w, list_h, labels, sublabels, *sel_ptr, alpha);

	float detail_x = origin_x + list_w + gutter;
	float detail_y = origin_y;
	float detail_h = height;

	if (tab == sub_tab_t::typedefs) {
		const auto& th2 = aida::ui::resolved();
		ImDrawList* dl = ImGui::GetWindowDrawList();
		ImVec2 a = ImVec2(detail_x, detail_y);
		ImVec2 b = ImVec2(detail_x + detail_w, detail_y + detail_h);
		dl->AddRectFilled(a, b, aida::ui::with_alpha(th2.panel_bg, alpha * 0.55f), 8.f);
		dl->AddRect(a, b, aida::ui::with_alpha(th2.border_subtle, alpha), 8.f, 0, 1.f);
		aida::ui::empty_state::config_t cfg;
		cfg.glyph = aida::ui::empty_state::glyph_t::layers;
		cfg.title = "Typedefs";
		cfg.body = "DbgHelp exposes typedefs as resolved type names on each field rather than as standalone records. Use Structures and Enums to inspect alias targets in context.";
		cfg.max_width = 380.f;
		aida::ui::empty_state::render(a, ImVec2(detail_w, detail_h), cfg);
		return;
	}

	if (sel_struct_ref) {
		render_struct_detail(*sel_struct_ref, detail_x, detail_y, detail_w, detail_h, alpha);
	} else if (sel_enum_ref) {
		render_enum_detail(*sel_enum_ref, detail_x, detail_y, detail_w, detail_h, alpha);
	} else if (have_function && pdb_for_detail) {
		render_function_detail(*pdb_for_detail, sel_function_copy, detail_x, detail_y, detail_w, detail_h, alpha);
	} else {
		const auto& th2 = aida::ui::resolved();
		ImDrawList* dl = ImGui::GetWindowDrawList();
		ImVec2 a = ImVec2(detail_x, detail_y);
		ImVec2 b = ImVec2(detail_x + detail_w, detail_y + detail_h);
		dl->AddRectFilled(a, b, aida::ui::with_alpha(th2.panel_bg, alpha * 0.30f), 8.f);
		dl->AddRect(a, b, aida::ui::with_alpha(th2.border_subtle, alpha), 8.f, 0, 1.f);
		aida::ui::empty_state::config_t cfg;
		cfg.glyph = aida::ui::empty_state::glyph_t::search;
		cfg.title = "Select an entry";
		cfg.body = "Pick an item from the list to inspect its full layout, members, or signature.";
		cfg.max_width = 360.f;
		aida::ui::empty_state::render(a, ImVec2(detail_w, detail_h), cfg);
	}
}

inline void render_active(int idx, float cw, float ch, float fa, float ar, float ag, float ab)
{
	(void)ar; (void)ag; (void)ab;
	auto tab = static_cast<sub_tab_t>(idx);

	stats_t st = snapshot_active_pdb();
	bool manual_busy = (g_state.manual_job && !g_state.manual_job->done->load(std::memory_order_acquire));
	if (manual_busy) {
		st.loading = true;
		st.status_text = "Parsing PDB...";
	}

	const float stat_h = 76.f;
	const float stat_gap = 10.f;

	ImDrawList* dl = ImGui::GetWindowDrawList();
	ImVec2 win_pos = ImGui::GetWindowPos();
	render_stat_bar(dl, ImVec2(win_pos.x + 8.f, win_pos.y + 4.f),
		cw - 16.f, stat_h, st, fa);

	if (st.loaded) {
		float pdb_btn_x = win_pos.x + cw - 8.f - 124.f;
		ImGui::SetCursorScreenPos(ImVec2(pdb_btn_x, win_pos.y + 4.f + stat_h - 36.f));
		if (aida::ui::button("Load PDB...", aida::ui::button_kind_t::ghost,
			aida::ui::size_t_::sm, ImVec2(118.f, 28.f))) {
			std::string p = browse_for_pdb();
			if (!p.empty()) start_manual_pdb_load(p);
		}
	}

	float body_y = 4.f + stat_h + stat_gap;
	float body_h = ch - body_y - 8.f;
	if (body_h < 80.f) body_h = 80.f;

	float manual_progress = 0.f;
	if (g_state.manual_job) {
		manual_progress = g_state.manual_job->progress->load(std::memory_order_relaxed);
	}

	if (tab == sub_tab_t::inferred) {
		struct_recon_view::render(8.f, body_y, cw - 16.f, body_h, fa, ar, ag, ab);
		return;
	}
	if (tab == sub_tab_t::dissector) {
		struct_dissector_view::render(8.f, body_y, cw - 16.f, body_h, fa, ar, ag, ab);
		return;
	}

	if (!st.loaded) {
		ImGui::SetCursorPos(ImVec2(8.f, body_y));
		ImGui::BeginChild("##types_empty_region", ImVec2(cw - 16.f, body_h), false,
			ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_NoBackground);
		ImVec2 wp = ImGui::GetWindowPos();
		render_empty_pdb_state(wp, ImVec2(cw - 16.f, body_h),
			st.loading || manual_busy, st.failed, st.status_text, manual_progress);
		ImGui::EndChild();
		return;
	}

	if (g_state.last_sel_tab != idx) {
		g_state.last_sel_tab = idx;
		g_state.target_scroll_list = 0.f;
		g_state.target_scroll_detail = 0.f;
		g_state.scroll_list = 0.f;
		g_state.scroll_detail = 0.f;
	}

	float pane_x = win_pos.x + 8.f;
	float pane_y = win_pos.y + body_y;
	render_browser_pane(tab, pane_x, pane_y, cw - 16.f, body_h, fa);
}

inline void render(float pos_x, float pos_y, float width, float height,
                   float alpha, float accent_r, float accent_g, float accent_b)
{
	float dt = aida::ui::clock::dt();
	aida::ui::hub_strip::tick_swap(g_state.strip, dt);

	poll_manual_job();

	if (g_state.flash_remaining > 0.f) {
		g_state.flash_remaining -= dt;
		if (g_state.flash_remaining < 0.f) g_state.flash_remaining = 0.f;
	}

	ImDrawList* dl = ImGui::GetWindowDrawList();
	ImVec2 origin = ImGui::GetWindowPos();

	const int count = static_cast<int>(sub_tab_t::COUNT);
	aida::ui::hub_strip::render_strip(dl, origin, pos_x, pos_y, width,
		s_tabs, count, g_state.strip, alpha);

	const float tab_h = 30.f;
	float content_y = pos_y + tab_h + 6.f;
	float content_h = height - tab_h - 6.f;
	if (content_h < 1.f) return;

	ImGui::SetCursorPos(ImVec2(pos_x, content_y));
	ImGui::BeginChild("##types_hub_content", ImVec2(width, content_h), false,
		ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_NoBackground);

	float cw = ImGui::GetWindowSize().x;
	float ch = ImGui::GetWindowSize().y;

	int prev_idx = g_state.strip.prev;
	int new_idx  = g_state.strip.active;

	aida::ui::hub_strip::render_swap_content(g_state.strip, cw,
		[&]() { render_active(prev_idx, cw, ch, alpha, accent_r, accent_g, accent_b); },
		[&]() { render_active(new_idx,  cw, ch, alpha, accent_r, accent_g, accent_b); }
	);

	ImGui::EndChild();

	if (g_state.flash_remaining > 0.f && !g_state.flash_message.empty()) {
		const auto& th = aida::ui::resolved();
		ImFont* head = aida::ui::fonts::body_em();
		if (!head) head = ImGui::GetFont();
		ImVec2 win_pos = ImGui::GetWindowPos();
		float t = g_state.flash_remaining / 2.6f;
		float ease = t < 0.18f ? (t / 0.18f) : 1.f;
		float fade_alpha = alpha * ease;
		ImVec2 sz = head->CalcTextSizeA(13.f, FLT_MAX, 0.f, g_state.flash_message.c_str());
		float pad_x = 14.f, pad_y = 8.f;
		ImVec2 a = ImVec2(win_pos.x + width * 0.5f - (sz.x + pad_x * 2.f) * 0.5f,
		                  win_pos.y + height - 56.f);
		ImVec2 b = ImVec2(a.x + sz.x + pad_x * 2.f, a.y + sz.y + pad_y * 2.f);
		dl->AddRectFilled(a, b, aida::ui::with_alpha(th.bg_overlay, fade_alpha), 8.f);
		dl->AddRect(a, b, aida::ui::with_alpha(g_state.flash_color, fade_alpha), 8.f, 0, 1.f);
		dl->AddCircleFilled(ImVec2(a.x + 10.f, a.y + (b.y - a.y) * 0.5f), 3.f,
			aida::ui::with_alpha(g_state.flash_color, fade_alpha), 12);
		dl->AddText(head, 13.f, ImVec2(a.x + pad_x + 8.f, a.y + pad_y),
			aida::ui::with_alpha(th.text_primary, fade_alpha), g_state.flash_message.c_str());
	}
}

}
