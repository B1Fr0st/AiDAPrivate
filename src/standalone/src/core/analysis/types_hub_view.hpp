#pragma once

#include "ui/hub_strip.hpp"
#include "ui/clock.hpp"
#include "ui/theme.hpp"
#include "ui/components.hpp"
#include "ui/empty_state.hpp"
#include "ui/no_target_overlay.hpp"
#include "ui/motion.hpp"
#include "ui/fonts.hpp"
#include "struct_recon_view.hpp"
#include "struct_dissector_view.hpp"
#include "struct_dissector.hpp"
#include "pdb_parser.hpp"
#include "symbol_store.hpp"
#include "builtin_typelib.hpp"
#include "functions_panel.hpp"
#include "../infra/work_queue.hpp"
#include "../disasm/disasm_view.hpp"
#include "../disasm/zydis_disasm.hpp"
#include "../disasm/function_index.hpp"
#include "../disasm/pseudocode_view.hpp"
#include "../testlab/test_all_features.hpp"
#include "../anti-tamper/webhook.hpp"
#include "../../helpers/globals.h"
#include "../../helpers/diag_log.hpp"
#include "../../helpers/win32_dialog.hpp"

#include "imgui/imgui.h"
#include "imgui/imgui_internal.h"

#include <windows.h>
#include <commdlg.h>

namespace analysis_session {
bool has_active_target();
}

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
#include <shared_mutex>
#include <string>
#include <unordered_set>
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

struct snapshot_t {
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

inline std::unique_ptr<snapshot_t> detach_snapshot() {
	auto out = std::make_unique<snapshot_t>();
	out->strip = g_state.strip;
	std::memcpy(out->search_struct, g_state.search_struct, sizeof(out->search_struct));
	std::memcpy(out->search_union, g_state.search_union, sizeof(out->search_union));
	std::memcpy(out->search_enum, g_state.search_enum, sizeof(out->search_enum));
	std::memcpy(out->search_typedef, g_state.search_typedef, sizeof(out->search_typedef));
	std::memcpy(out->search_function, g_state.search_function, sizeof(out->search_function));
	std::memcpy(out->apply_addr_buf, g_state.apply_addr_buf, sizeof(out->apply_addr_buf));
	out->sel_struct = g_state.sel_struct;
	out->sel_union = g_state.sel_union;
	out->sel_enum = g_state.sel_enum;
	out->sel_typedef = g_state.sel_typedef;
	out->sel_function = g_state.sel_function;
	out->scroll_list = g_state.scroll_list;
	out->target_scroll_list = g_state.target_scroll_list;
	out->scroll_detail = g_state.scroll_detail;
	out->target_scroll_detail = g_state.target_scroll_detail;
	out->last_sel_tab = g_state.last_sel_tab;
	out->flash_message = std::move(g_state.flash_message);
	out->flash_remaining = g_state.flash_remaining;
	out->flash_color = g_state.flash_color;
	out->visible_struct_idx = std::move(g_state.visible_struct_idx);
	out->visible_union_idx = std::move(g_state.visible_union_idx);
	out->visible_enum_idx = std::move(g_state.visible_enum_idx);
	out->visible_typedef_idx = std::move(g_state.visible_typedef_idx);
	out->visible_function_idx = std::move(g_state.visible_function_idx);
	out->manual_job = std::move(g_state.manual_job);
	g_state = state_t{};
	return out;
}

inline void attach_snapshot(std::unique_ptr<snapshot_t> snap) {
	if (!snap) {
		g_state = state_t{};
		return;
	}
	g_state.strip = snap->strip;
	std::memcpy(g_state.search_struct, snap->search_struct, sizeof(g_state.search_struct));
	std::memcpy(g_state.search_union, snap->search_union, sizeof(g_state.search_union));
	std::memcpy(g_state.search_enum, snap->search_enum, sizeof(g_state.search_enum));
	std::memcpy(g_state.search_typedef, snap->search_typedef, sizeof(g_state.search_typedef));
	std::memcpy(g_state.search_function, snap->search_function, sizeof(g_state.search_function));
	std::memcpy(g_state.apply_addr_buf, snap->apply_addr_buf, sizeof(g_state.apply_addr_buf));
	g_state.sel_struct = snap->sel_struct;
	g_state.sel_union = snap->sel_union;
	g_state.sel_enum = snap->sel_enum;
	g_state.sel_typedef = snap->sel_typedef;
	g_state.sel_function = snap->sel_function;
	g_state.scroll_list = snap->scroll_list;
	g_state.target_scroll_list = snap->target_scroll_list;
	g_state.scroll_detail = snap->scroll_detail;
	g_state.target_scroll_detail = snap->target_scroll_detail;
	g_state.last_sel_tab = snap->last_sel_tab;
	g_state.flash_message = std::move(snap->flash_message);
	g_state.flash_remaining = snap->flash_remaining;
	g_state.flash_color = snap->flash_color;
	g_state.visible_struct_idx = std::move(snap->visible_struct_idx);
	g_state.visible_union_idx = std::move(snap->visible_union_idx);
	g_state.visible_enum_idx = std::move(snap->visible_enum_idx);
	g_state.visible_typedef_idx = std::move(snap->visible_typedef_idx);
	g_state.visible_function_idx = std::move(snap->visible_function_idx);
	g_state.manual_job = std::move(snap->manual_job);
}

enum class origin_t : int {
	pdb = 0,
	builtin,
	synthesized,
};

inline const char* origin_badge_label(origin_t o)
{
	switch (o) {
		case origin_t::pdb:         return "PDB";
		case origin_t::builtin:     return "BUILTIN";
		case origin_t::synthesized: return "SYNTH";
	}
	return "";
}

inline ImU32 origin_badge_color(origin_t o, const aida::ui::theme_t& th)
{
	switch (o) {
		case origin_t::pdb:         return th.success;
		case origin_t::builtin:     return th.syn_type;
		case origin_t::synthesized: return th.warning;
	}
	return th.text_dim;
}

struct merged_struct_entry_t {
	pdb_parser::struct_def_t def;
	origin_t                 origin = origin_t::pdb;
	std::string              lib_tag;
};

struct merged_enum_entry_t {
	pdb_parser::enum_def_t def;
	origin_t               origin = origin_t::pdb;
	std::string            lib_tag;
};

struct merged_typedef_entry_t {
	std::string name;
	std::string target;
	std::string lib_tag;
	uint32_t    size = 0;
	origin_t    origin = origin_t::builtin;
};

struct merged_function_entry_t {
	std::string name;
	std::string signature;
	std::string module_tag;
	uint64_t    rva = 0;
	uint32_t    size = 0;
	uint32_t    type_index = 0;
	origin_t    origin = origin_t::pdb;
};

struct merged_types_t {
	std::vector<merged_struct_entry_t>   structs;
	std::vector<merged_struct_entry_t>   unions;
	std::vector<merged_enum_entry_t>     enums;
	std::vector<merged_typedef_entry_t>  typedefs;
	std::vector<merged_function_entry_t> functions;
	size_t pdb_struct_count = 0;
	size_t pdb_enum_count = 0;
	size_t pdb_function_count = 0;
	size_t builtin_struct_count = 0;
	size_t builtin_enum_count = 0;
	size_t builtin_typedef_count = 0;
	size_t synthesized_function_count = 0;
	bool   any_pdb_loaded = false;
	bool   any_pdb_loading = false;
	bool   any_pdb_failed = false;
	std::string pdb_status_text;
	std::string pdb_module_name;
	std::string pdb_file_path;
};

inline std::string struct_to_ida_syntax(const pdb_parser::struct_def_t& def)
{
	std::string out;
	out += def.is_union ? "union " : "struct ";
	out += def.name;
	out += "\n{\n";
	uint64_t last_end = 0;
	int pad_idx = 0;
	for (const auto& m : def.members) {
		if (m.offset > last_end) {
			uint64_t gap = m.offset - last_end;
			char buf[80];
			std::snprintf(buf, sizeof(buf),
				"  _BYTE pad_%d[%llu];\n", pad_idx++,
				static_cast<unsigned long long>(gap));
			out += buf;
		}
		std::string type_text = m.type_name;
		if (type_text == "uint8_t" || type_text == "int8_t" || type_text == "char" || type_text == "BYTE")
			type_text = "_BYTE";
		else if (type_text == "uint16_t" || type_text == "int16_t" || type_text == "WORD" || type_text == "USHORT" || type_text == "short")
			type_text = "_WORD";
		else if (type_text == "uint32_t" || type_text == "int32_t" || type_text == "DWORD" || type_text == "ULONG" || type_text == "LONG" || type_text == "long")
			type_text = "_DWORD";
		else if (type_text == "uint64_t" || type_text == "int64_t" || type_text == "QWORD" || type_text == "ULONGLONG" || type_text == "__int64")
			type_text = "_QWORD";

		char head[40];
		std::snprintf(head, sizeof(head), "  /*0x%03llX*/ ",
			static_cast<unsigned long long>(m.offset));
		out += head;
		if (m.bit_size >= 0) {
			char buf[160];
			std::snprintf(buf, sizeof(buf), "%s %s : %d;\n",
				type_text.c_str(), m.name.c_str(), m.bit_size);
			out += buf;
		} else if (m.is_array) {
			char buf[160];
			std::snprintf(buf, sizeof(buf), "%s %s[%d];\n",
				type_text.c_str(), m.name.c_str(), m.array_count);
			out += buf;
		} else {
			char buf[160];
			std::snprintf(buf, sizeof(buf), "%s %s;\n",
				type_text.c_str(), m.name.c_str());
			out += buf;
		}
		last_end = m.offset + m.size;
	}
	if (last_end < def.size) {
		uint64_t gap = def.size - last_end;
		char buf[80];
		std::snprintf(buf, sizeof(buf), "  _BYTE pad_%d[%llu];\n", pad_idx,
			static_cast<unsigned long long>(gap));
		out += buf;
	}
	out += "};\n";
	return out;
}

inline pdb_parser::struct_def_t build_struct_def_from_builtin(const builtin_typelib::struct_desc_t& src)
{
	pdb_parser::struct_def_t def;
	def.name = src.name;
	def.size = src.size;
	def.type_index = 0;
	def.is_union = src.is_union;
	def.members.reserve(src.member_count);
	for (size_t i = 0; i < src.member_count; ++i) {
		const auto& m = src.members[i];
		pdb_parser::struct_member_t mm;
		mm.name = m.name;
		mm.type_name = m.type_name;
		mm.offset = m.offset;
		mm.size = m.size;
		mm.type_index = 0;
		mm.bit_offset = -1;
		mm.bit_size = -1;
		mm.is_pointer = m.is_pointer;
		mm.pointer_depth = m.is_pointer ? 1 : 0;
		mm.is_array = m.is_array;
		mm.array_count = m.array_count;
		def.members.push_back(std::move(mm));
	}
	return def;
}

inline pdb_parser::enum_def_t build_enum_def_from_builtin(const builtin_typelib::enum_desc_t& src)
{
	pdb_parser::enum_def_t def;
	def.name = src.name;
	def.type_index = 0;
	def.members.reserve(src.value_count);
	for (size_t i = 0; i < src.value_count; ++i) {
		pdb_parser::enum_member_t em;
		em.name = src.values[i].name;
		em.value = src.values[i].value;
		def.members.push_back(std::move(em));
	}
	return def;
}

inline pdb_parser::enum_def_t build_enum_def_from_status_table(const char* enum_name,
	const builtin_typelib::entry_t* table, size_t count)
{
	pdb_parser::enum_def_t def;
	def.name = enum_name;
	def.type_index = 0;
	def.members.reserve(count);
	for (size_t i = 0; i < count; ++i) {
		pdb_parser::enum_member_t em;
		em.name = table[i].second;
		em.value = static_cast<int64_t>(static_cast<int32_t>(static_cast<uint32_t>(table[i].first)));
		def.members.push_back(std::move(em));
	}
	return def;
}

inline std::string strip_imp_prefix(const std::string& s)
{
	if (s.size() >= 6 && s.compare(0, 6, "__imp_") == 0) return s.substr(6);
	if (s.size() >= 5 && s.compare(0, 5, "__imp") == 0) return s.substr(5);
	return s;
}

inline std::string synthesize_prototype_signature(const std::string& fn_name)
{
	std::string stripped = strip_imp_prefix(fn_name);
	const function_index::detail::prototype_entry_t* proto =
		function_index::detail::lookup_prototype_entry(stripped);
	std::string out;
	out.reserve(stripped.size() + 64);
	out += stripped;
	out += "(";
	if (proto) {
		bool any = false;
		for (size_t i = 0; i < sizeof(proto->params) / sizeof(proto->params[0]); ++i) {
			const char* pn = proto->params[i];
			if (!pn) break;
			if (any) out += ", ";
			out += "__int64 ";
			out += pn;
			any = true;
		}
		if (!any) {
			out += "void";
		}
	} else {
		out += "__int64 a1, __int64 a2, __int64 a3, __int64 a4";
	}
	out += ")";
	return out;
}

struct import_snapshot_entry_t {
	std::string function_name;
	std::string module_name;
};

inline std::vector<import_snapshot_entry_t> snapshot_iat_entries()
{
	std::vector<import_snapshot_entry_t> snap;
	auto& fc = function_index::detail::cache();
	std::shared_lock<std::shared_mutex> lk(fc.mutex);
	snap.reserve(fc.iat_lookup.size());
	for (const auto& kv : fc.iat_lookup) {
		const auto& e = kv.second;
		if (e.function_name.empty()) continue;
		import_snapshot_entry_t s;
		s.function_name = e.function_name;
		s.module_name = e.module_name;
		snap.push_back(std::move(s));
	}
	return snap;
}

inline void append_synthesized_imports(std::vector<merged_function_entry_t>& out,
	std::unordered_set<std::string>& taken_names,
	const std::vector<import_snapshot_entry_t>& iat)
{
	out.reserve(out.size() + iat.size());
	for (const auto& e : iat) {
		std::string stripped = strip_imp_prefix(e.function_name);
		if (stripped.empty()) continue;
		if (!taken_names.insert(stripped).second) continue;
		merged_function_entry_t mfe;
		mfe.name = stripped;
		mfe.signature = synthesize_prototype_signature(stripped);
		mfe.module_tag = e.module_name;
		mfe.rva = 0;
		mfe.size = 0;
		mfe.type_index = 0;
		mfe.origin = origin_t::synthesized;
		out.push_back(std::move(mfe));
	}
}

inline void build_merged_types_locked(merged_types_t& out,
	const std::vector<import_snapshot_entry_t>& iat_snapshot)
{
	const pdb_parser::pdb_info_t* best = nullptr;
	for (auto& kv : symbol_store::g_state.modules) {
		auto& ms = kv.second;
		if (ms.loading) {
			out.any_pdb_loading = true;
			if (out.pdb_status_text.empty()) {
				out.pdb_status_text = ms.status_text;
				out.pdb_module_name = ms.module_name;
			}
		}
		if (ms.failed) {
			out.any_pdb_failed = true;
			if (out.pdb_status_text.empty()) {
				out.pdb_status_text = ms.status_text;
				out.pdb_module_name = ms.module_name;
			}
		}
		if (ms.pdb.loaded) {
			out.any_pdb_loaded = true;
			if (!best || ms.pdb.structs.size() > best->structs.size())
				best = &ms.pdb;
		}
	}

	std::unordered_set<std::string> struct_names;
	std::unordered_set<std::string> union_names;
	std::unordered_set<std::string> enum_names;
	std::unordered_set<std::string> typedef_names;
	std::unordered_set<std::string> function_names;

	if (best) {
		out.pdb_module_name = best->module_name;
		out.pdb_file_path = best->file_path;
		for (const auto& s : best->structs) {
			merged_struct_entry_t e;
			e.def = s;
			e.origin = origin_t::pdb;
			e.lib_tag = best->module_name.empty() ? std::string("PDB") : best->module_name;
			if (s.is_union) {
				union_names.insert(s.name);
				out.unions.push_back(std::move(e));
			} else {
				struct_names.insert(s.name);
				out.structs.push_back(std::move(e));
			}
			++out.pdb_struct_count;
		}
		for (const auto& en : best->enums) {
			merged_enum_entry_t e;
			e.def = en;
			e.origin = origin_t::pdb;
			e.lib_tag = best->module_name.empty() ? std::string("PDB") : best->module_name;
			enum_names.insert(en.name);
			out.enums.push_back(std::move(e));
			++out.pdb_enum_count;
		}
		for (const auto& sym : best->symbols) {
			if (!sym.is_function) continue;
			merged_function_entry_t mfe;
			mfe.name = sym.name;
			mfe.signature = sym.name + "()";
			mfe.module_tag = best->module_name;
			mfe.rva = sym.rva;
			mfe.size = sym.size;
			mfe.type_index = sym.type_index;
			mfe.origin = origin_t::pdb;
			function_names.insert(sym.name);
			out.functions.push_back(std::move(mfe));
			++out.pdb_function_count;
		}
	}

	for (const auto& bs : builtin_typelib::kBuiltinStructs) {
		if (bs.is_union) {
			if (!union_names.insert(bs.name).second) continue;
			merged_struct_entry_t e;
			e.def = build_struct_def_from_builtin(bs);
			e.origin = origin_t::builtin;
			e.lib_tag = bs.lib ? bs.lib : "builtin";
			out.unions.push_back(std::move(e));
		} else {
			if (!struct_names.insert(bs.name).second) continue;
			merged_struct_entry_t e;
			e.def = build_struct_def_from_builtin(bs);
			e.origin = origin_t::builtin;
			e.lib_tag = bs.lib ? bs.lib : "builtin";
			out.structs.push_back(std::move(e));
		}
		++out.builtin_struct_count;
	}

	for (const auto& be : builtin_typelib::kBuiltinEnums) {
		if (!enum_names.insert(be.name).second) continue;
		merged_enum_entry_t e;
		e.def = build_enum_def_from_builtin(be);
		e.origin = origin_t::builtin;
		e.lib_tag = be.lib ? be.lib : "builtin";
		out.enums.push_back(std::move(e));
		++out.builtin_enum_count;
	}

	if (enum_names.insert("NTSTATUS_VALUES").second) {
		merged_enum_entry_t e;
		e.def = build_enum_def_from_status_table("NTSTATUS_VALUES",
			builtin_typelib::kNtstatusTable.data(), builtin_typelib::kNtstatusTable.size());
		e.origin = origin_t::builtin;
		e.lib_tag = "ntstatus";
		out.enums.push_back(std::move(e));
		++out.builtin_enum_count;
	}
	if (enum_names.insert("HRESULT_VALUES").second) {
		merged_enum_entry_t e;
		e.def = build_enum_def_from_status_table("HRESULT_VALUES",
			builtin_typelib::kHresultTable.data(), builtin_typelib::kHresultTable.size());
		e.origin = origin_t::builtin;
		e.lib_tag = "mssdk";
		out.enums.push_back(std::move(e));
		++out.builtin_enum_count;
	}

	for (const auto& td : builtin_typelib::kBuiltinTypedefs) {
		if (!typedef_names.insert(td.name).second) continue;
		merged_typedef_entry_t e;
		e.name = td.name;
		e.target = td.target ? td.target : "";
		e.lib_tag = td.lib ? td.lib : "builtin";
		e.size = td.size;
		e.origin = origin_t::builtin;
		out.typedefs.push_back(std::move(e));
		++out.builtin_typedef_count;
	}

	append_synthesized_imports(out.functions, function_names, iat_snapshot);
	for (const auto& f : out.functions) {
		if (f.origin == origin_t::synthesized) ++out.synthesized_function_count;
	}

	std::sort(out.structs.begin(), out.structs.end(),
		[](const merged_struct_entry_t& a, const merged_struct_entry_t& b) {
			return a.def.name < b.def.name;
		});
	std::sort(out.unions.begin(), out.unions.end(),
		[](const merged_struct_entry_t& a, const merged_struct_entry_t& b) {
			return a.def.name < b.def.name;
		});
	std::sort(out.enums.begin(), out.enums.end(),
		[](const merged_enum_entry_t& a, const merged_enum_entry_t& b) {
			return a.def.name < b.def.name;
		});
	std::sort(out.typedefs.begin(), out.typedefs.end(),
		[](const merged_typedef_entry_t& a, const merged_typedef_entry_t& b) {
			return a.name < b.name;
		});
	std::sort(out.functions.begin(), out.functions.end(),
		[](const merged_function_entry_t& a, const merged_function_entry_t& b) {
			if (a.origin != b.origin)
				return static_cast<int>(a.origin) < static_cast<int>(b.origin);
			return a.name < b.name;
		});
}

inline merged_types_t build_merged_types_snapshot()
{
	std::vector<import_snapshot_entry_t> iat_snap = snapshot_iat_entries();
	merged_types_t out;
	{
		std::lock_guard<std::mutex> lk(symbol_store::g_state.mutex);
		build_merged_types_locked(out, iat_snap);
	}
	return out;
}

struct merged_cache_t {
	std::shared_ptr<merged_types_t> data;
	uint64_t                        last_built_ms = 0;
	std::mutex                      mtx;
};

inline merged_cache_t& merged_cache()
{
	static merged_cache_t s_cache;
	return s_cache;
}

inline std::shared_ptr<const merged_types_t> get_merged_types_cached()
{
	auto& mc = merged_cache();
	uint64_t now = GetTickCount64();
	std::shared_ptr<merged_types_t> cached;
	uint64_t last_built = 0;
	{
		std::lock_guard<std::mutex> lk(mc.mtx);
		cached = mc.data;
		last_built = mc.last_built_ms;
	}
	bool stale = (!cached) || (now - last_built >= 350);
	if (!stale) return cached;

	auto fresh = std::make_shared<merged_types_t>(build_merged_types_snapshot());
	{
		std::lock_guard<std::mutex> lk(mc.mtx);
		mc.data = fresh;
		mc.last_built_ms = now;
	}
	diag::log_tagged_fmt("types",
		"merged_cache_rebuilt structs=%zu unions=%zu enums=%zu typedefs=%zu funcs=%zu pdb_loaded=%d",
		fresh->structs.size(),
		fresh->unions.size(),
		fresh->enums.size(),
		fresh->typedefs.size(),
		fresh->functions.size(),
		fresh->any_pdb_loaded ? 1 : 0);
	return fresh;
}

inline void render_origin_badge(ImDrawList* dl, ImFont* font, ImVec2 pos,
	origin_t origin, const std::string& lib_tag, float alpha)
{
	const auto& th = aida::ui::resolved();
	const char* label = origin_badge_label(origin);
	ImU32 col = origin_badge_color(origin, th);
	const float fs = aida::ui::components::detail::ui_fs() * 0.85f;
	ImVec2 ts = font->CalcTextSizeA(fs, FLT_MAX, 0.f, label);
	float pad_x = 6.f;
	float pad_y = 2.f;
	ImVec2 a = pos;
	ImVec2 b = ImVec2(pos.x + ts.x + pad_x * 2.f, pos.y + ts.y + pad_y * 2.f);
	dl->AddRectFilled(a, b, aida::ui::with_alpha(col, alpha * 0.18f), 4.f);
	dl->AddRect(a, b, aida::ui::with_alpha(col, alpha * 0.55f), 4.f, 0, 1.f);
	dl->AddText(font, fs, ImVec2(a.x + pad_x, a.y + pad_y),
		aida::ui::with_alpha(col, alpha), label);
	if (!lib_tag.empty()) {
		ImVec2 lt = font->CalcTextSizeA(fs, FLT_MAX, 0.f, lib_tag.c_str());
		float lx = b.x + 6.f;
		ImVec2 la = ImVec2(lx, a.y);
		ImVec2 lb = ImVec2(lx + lt.x + pad_x * 2.f, b.y);
		dl->AddRectFilled(la, lb, aida::ui::with_alpha(th.panel_header, alpha * 0.45f), 4.f);
		dl->AddRect(la, lb, aida::ui::with_alpha(th.border_subtle, alpha * 0.55f), 4.f, 0, 1.f);
		dl->AddText(font, fs, ImVec2(la.x + pad_x, la.y + pad_y),
			aida::ui::with_alpha(th.text_secondary, alpha), lib_tag.c_str());
	}
}

inline void set_sub_tab(sub_tab_t tab)
{
	int idx = static_cast<int>(tab);
	aida::ui::hub_strip::notify_select(g_state.strip, idx);
}

inline constexpr aida::ui::hub_strip::tab_t s_tabs[] = {
	{ "Structures", "PDB structs / classes", "Struct" },
	{ "Unions",     "PDB unions",            "Union" },
	{ "Enums",      "PDB enumerations",      "Enum" },
	{ "Typedefs",   "named type aliases",    "Type" },
	{ "Functions",  "function signatures",   "Fn" },
	{ "Inferred",   "reconstructed from memory", "Inf" },
	{ "Dissector",  "live struct dissector", "Dis" },
};

inline sub_tab_t active_sub_tab()
{
	return static_cast<sub_tab_t>(g_state.strip.active);
}

inline const char* sub_tab_label(sub_tab_t tab)
{
	int idx = static_cast<int>(tab);
	if (idx < 0 || idx >= static_cast<int>(sub_tab_t::COUNT))
		return "";
	return s_tabs[idx].label;
}

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

inline stats_t snapshot_active_pdb(const merged_types_t& merged)
{
	stats_t st;
	st.module_name = merged.pdb_module_name;
	st.pdb_path = merged.pdb_file_path;

	size_t struct_total = 0;
	size_t union_total = 0;
	for (const auto& e : merged.structs) {
		(void)e;
		++struct_total;
	}
	for (const auto& e : merged.unions) {
		(void)e;
		++union_total;
	}
	st.struct_count = struct_total;
	st.union_count = union_total;
	st.enum_count = merged.enums.size();
	st.typedef_count = merged.typedefs.size();
	st.function_count = merged.functions.size();
	st.symbol_count = merged.pdb_function_count;

	st.loaded = merged.any_pdb_loaded
		|| !merged.structs.empty()
		|| !merged.unions.empty()
		|| !merged.enums.empty()
		|| !merged.typedefs.empty()
		|| !merged.functions.empty();
	st.loading = merged.any_pdb_loading;
	st.failed = !merged.any_pdb_loaded && merged.any_pdb_failed;
	st.status_text = merged.pdb_status_text;

	char buf[160];
	if (merged.any_pdb_loaded) {
		std::snprintf(buf, sizeof(buf),
			"%zu types (PDB %zu / builtin %zu) %zu enums %zu typedefs %zu funcs",
			struct_total + union_total,
			merged.pdb_struct_count,
			merged.builtin_struct_count,
			st.enum_count, st.typedef_count, st.function_count);
	} else {
		std::snprintf(buf, sizeof(buf),
			"no PDB: %zu builtin types %zu enums %zu typedefs %zu synthesized funcs",
			merged.builtin_struct_count,
			st.enum_count, st.typedef_count, merged.synthesized_function_count);
	}
	st.status_text = buf;
	return st;
}

inline std::string browse_for_pdb()
{
	const auto automation = symbol_store::pdb_automation_context();
	if (automation.pdb_skip_active) {
		diag::log_tagged_critical_fmt("pdb",
			"pdb_native_dialog_attempt source=types_hub_view::browse_for_pdb title=\"Load PDB\" suppressed=1 decision=do_not_load_pdb is_running=%d anti_tamper_full_test_running=%d full_test_env_active=%d unattended_active=%d post_suppression_active=%d post_suppression_remaining_ms=%llu pdb_automation_active=%d user_default_skip_active=%d pdb_skip_active=%d",
			automation.is_running ? 1 : 0,
			automation.anti_tamper_full_test_running ? 1 : 0,
			automation.full_test_env_active ? 1 : 0,
			automation.unattended_active ? 1 : 0,
			automation.post_suppression_active ? 1 : 0,
			static_cast<unsigned long long>(automation.post_suppression_remaining_ms),
			automation.pdb_automation_active ? 1 : 0,
			automation.user_default_skip_active ? 1 : 0,
			automation.pdb_skip_active ? 1 : 0);
		return {};
	}
	char buf[MAX_PATH] = {};
	static const char k_pdb_filter[] =
		"PDB Symbol Files (*.pdb)\0*.pdb\0"
		"All files (*.*)\0*.*\0\0";
	bool ok = win32_dialog::show_open_file_dialog(g_hwnd,
			"Load PDB",
			k_pdb_filter,
			buf, sizeof(buf),
			"types_hub_view::browse_for_pdb");
	if (ok) {
		diag::log_tagged_fmt("pdb",
			"browse_for_pdb selected path='%s'", buf);
		return std::string(buf);
	}
	diag::log_tagged_fmt("pdb",
		"browse_for_pdb cancelled");
	return {};
}

inline void start_manual_pdb_load(const std::string& pdb_path)
{
	if (pdb_path.empty()) {
		diag::log_tagged_fmt("pdb", "manual_load_skipped reason='empty_path'");
		return;
	}

	auto job = std::make_shared<loading_job_t>();
	job->info = std::make_shared<pdb_parser::pdb_info_t>();
	job->progress = std::make_shared<std::atomic<float>>(0.f);
	job->done = std::make_shared<std::atomic<bool>>(false);
	job->ok = std::make_shared<std::atomic<bool>>(false);
	job->pdb_path = pdb_path;

	auto stem = std::filesystem::path(pdb_path).stem().string();
	job->module_key = stem + ".pdb";

	g_state.manual_job = job;

	diag::log_tagged_fmt("pdb",
		"manual_load_begin path='%s' module='%s'",
		pdb_path.c_str(), job->module_key.c_str());

	work_queue::post([job]() {
		uint64_t t0 = GetTickCount64();
		bool ok = pdb_parser::parse_pdb_bounded(job->pdb_path, std::string{}, *job->info, job->progress.get(),
			nullptr, symbol_store::k_explicit_pdb_load_timeout_ms);
		uint64_t elapsed_ms = GetTickCount64() - t0;
		job->ok->store(ok, std::memory_order_release);
		job->done->store(true, std::memory_order_release);

		if (!ok) {
			diag::log_tagged_fmt("pdb",
				"manual_load_failed path='%s' elapsed_ms=%llu",
				job->pdb_path.c_str(),
				static_cast<unsigned long long>(elapsed_ms));
			return;
		}

		size_t sym_count = job->info->symbols.size();
		size_t struct_count = job->info->structs.size();
		size_t enum_count = job->info->enums.size();

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

		diag::log_tagged_fmt("pdb",
			"manual_load_done path='%s' module='%s' syms=%zu structs=%zu enums=%zu elapsed_ms=%llu",
			job->pdb_path.c_str(),
			job->module_key.c_str(),
			sym_count, struct_count, enum_count,
			static_cast<unsigned long long>(elapsed_ms));
	});
}

inline void invalidate_merged_cache()
{
	auto& mc = merged_cache();
	std::lock_guard<std::mutex> lk(mc.mtx);
	mc.data.reset();
	mc.last_built_ms = 0;
}

inline void poll_manual_job()
{
	if (!g_state.manual_job) return;
	if (!g_state.manual_job->done->load(std::memory_order_acquire)) return;

	bool ok = g_state.manual_job->ok->load(std::memory_order_acquire);
	std::string mod_key = g_state.manual_job->module_key;
	if (ok) {
		flash("PDB loaded: " + mod_key, aida::ui::resolved().success);
		diag::log_tagged_fmt("pdb",
			"manual_job_polled status='ok' module='%s'", mod_key.c_str());
		invalidate_merged_cache();
	} else {
		flash("Failed to parse PDB", aida::ui::resolved().error);
		diag::log_tagged_fmt("pdb",
			"manual_job_polled status='fail' module='%s'", mod_key.c_str());
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
	const float fs_base   = aida::ui::components::detail::ui_fs();
	const float fs_title  = fs_base * 1.22f;
	const float fs_status = fs_base * 0.88f;
	dl->AddText(head, fs_title, ImVec2(a.x + 14.f, row_y), aida::ui::with_alpha(th.text_primary, alpha), title.c_str());

	if (st.loaded) {
		ImU32 ok = aida::ui::with_alpha(th.success, alpha);
		dl->AddCircleFilled(ImVec2(b.x - 18.f, row_y + 8.f), 4.f, ok, 12);
		const char* live = "LIVE";
		ImVec2 lsz = head->CalcTextSizeA(fs_status, FLT_MAX, 0.f, live);
		dl->AddText(head, fs_status, ImVec2(b.x - 24.f - lsz.x, row_y + 2.f),
			aida::ui::with_alpha(th.success, alpha), live);
	} else if (st.loading) {
		ImU32 c = aida::ui::with_alpha(th.warning, alpha);
		dl->AddCircleFilled(ImVec2(b.x - 18.f, row_y + 8.f), 4.f, c, 12);
		dl->AddText(head, fs_status, ImVec2(b.x - 60.f, row_y + 2.f), c, "BUSY");
	} else if (st.failed) {
		ImU32 c = aida::ui::with_alpha(th.error, alpha);
		dl->AddCircleFilled(ImVec2(b.x - 18.f, row_y + 8.f), 4.f, c, 12);
		dl->AddText(head, fs_status, ImVec2(b.x - 70.f, row_y + 2.f), c, "FAILED");
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
	const float fs_chip_value = fs_base * 1.22f;
	const float fs_chip_label = fs_base * 1.0f;
	const float chip_pad_top = 6.f;
	const float chip_value_gap = 4.f;
	const float chip_pad_bot = 8.f;
	for (auto& c : chips) {
		char value_buf[24];
		std::snprintf(value_buf, sizeof(value_buf), "%zu", c.value);
		ImVec2 vsz = code->CalcTextSizeA(fs_chip_value, FLT_MAX, 0.f, value_buf);
		ImVec2 lsz = body->CalcTextSizeA(fs_chip_label, FLT_MAX, 0.f, c.label);
		float chip_w = std::max(vsz.x, lsz.x) + 22.f;
		float content_h_raw = chip_pad_top + vsz.y + chip_value_gap + lsz.y + chip_pad_bot;
		float chip_h = std::max(content_h_raw, 48.f);
		ImVec2 ca = ImVec2(x, stat_y);
		ImVec2 cb = ImVec2(x + chip_w, stat_y + chip_h);
		float inner_content_h = vsz.y + chip_value_gap + lsz.y;
		float vert_offset = (chip_h - inner_content_h) * 0.5f;
		float value_y = ca.y + vert_offset;
		float caption_y = value_y + vsz.y + chip_value_gap;
		dl->AddRectFilled(ca, cb, aida::ui::with_alpha(c.color, alpha * 0.10f), 6.f);
		dl->AddRect(ca, cb, aida::ui::with_alpha(c.color, alpha * 0.42f), 6.f, 0, 1.f);
		dl->AddText(code, fs_chip_value, ImVec2(ca.x + (chip_w - vsz.x) * 0.5f, value_y),
			aida::ui::with_alpha(c.color, alpha), value_buf);
		dl->AddText(body, fs_chip_label, ImVec2(ca.x + (chip_w - lsz.x) * 0.5f, caption_y),
			aida::ui::with_alpha(th.text_dim, alpha), c.label);
		x += chip_w + 8.f;
	}

	if (!st.pdb_path.empty()) {
		const float fs_path = fs_base * 0.88f;
		std::string path_label = st.pdb_path;
		if (path_label.size() > 64) {
			path_label = "..." + path_label.substr(path_label.size() - 60);
		}
		ImVec2 psz = code->CalcTextSizeA(fs_path, FLT_MAX, 0.f, path_label.c_str());
		float py = stat_y + 14.f;
		if (b.x - psz.x - 14.f > x + 8.f) {
			dl->AddText(code, fs_path, ImVec2(b.x - psz.x - 14.f, py),
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

inline void render_struct_detail(const pdb_parser::struct_def_t& def, float origin_x, float origin_y,
                                  float width, float height, float alpha,
                                  origin_t origin, const std::string& lib_tag)
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

	float top_h = 68.f;
	dl->AddRectFilled(a, ImVec2(b.x, a.y + top_h),
		aida::ui::with_alpha(th.panel_header, alpha * 0.55f), 8.f);
	dl->AddLine(ImVec2(a.x + 8.f, a.y + top_h - 1.f), ImVec2(b.x - 8.f, a.y + top_h - 1.f),
		aida::ui::with_alpha(th.border_subtle, alpha));

	const float fs_struct_base  = aida::ui::components::detail::ui_fs();
	const float fs_struct_title = fs_struct_base * 1.30f;
	const float fs_struct_meta  = fs_struct_base * 0.92f;
	dl->AddText(head, fs_struct_title, ImVec2(a.x + 14.f, a.y + 8.f),
		aida::ui::with_alpha(th.text_primary, alpha), def.name.c_str());

	ImVec2 name_sz = head->CalcTextSizeA(fs_struct_title, FLT_MAX, 0.f, def.name.c_str());
	render_origin_badge(dl, code, ImVec2(a.x + 14.f + name_sz.x + 10.f, a.y + 14.f),
		origin, lib_tag, alpha);

	char meta[96];
	std::snprintf(meta, sizeof(meta), "%s  %llu bytes  (0x%llX)  %zu fields  ti=%u",
		def.is_union ? "union" : "struct",
		static_cast<unsigned long long>(def.size),
		static_cast<unsigned long long>(def.size),
		def.members.size(),
		def.type_index);
	dl->AddText(code, fs_struct_meta, ImVec2(a.x + 14.f, a.y + 38.f),
		aida::ui::with_alpha(th.text_dim, alpha), meta);

	ImGui::SetCursorScreenPos(ImVec2(b.x - 410.f, a.y + 16.f));
	if (aida::ui::button("Copy C", aida::ui::button_kind_t::ghost,
		aida::ui::size_t_::sm, ImVec2(74.f, 28.f))) {
		std::string cpp = pdb_parser::struct_to_cpp(def);
		ImGui::SetClipboardText(cpp.c_str());
		flash("Copied " + def.name + " as C", th.success);
		diag::log_tagged_fmt("types",
			"copy_struct_c name='%s' bytes=%zu",
			def.name.c_str(), cpp.size());
	}
	ImGui::SameLine();
	if (aida::ui::button("Copy IDA", aida::ui::button_kind_t::ghost,
		aida::ui::size_t_::sm, ImVec2(82.f, 28.f))) {
		std::string ida = struct_to_ida_syntax(def);
		ImGui::SetClipboardText(ida.c_str());
		flash("Copied " + def.name + " as IDA", th.success);
		diag::log_tagged_fmt("types",
			"copy_struct_ida name='%s' bytes=%zu",
			def.name.c_str(), ida.size());
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
		diag::log_tagged_fmt("types",
			"push_to_dissector name='%s' fields=%zu dissector_idx=%d",
			def.name.c_str(), def.members.size(), idx);
	}
	ImGui::SameLine();
	if (aida::ui::button("Open Dissector", aida::ui::button_kind_t::primary,
		aida::ui::size_t_::sm, ImVec2(122.f, 28.f))) {
		set_sub_tab(sub_tab_t::dissector);
		diag::log_tagged_fmt("types", "open_dissector_tab");
	}

	float body_y = a.y + top_h + 10.f;
	float body_h = height - top_h - 10.f - 12.f;

	const float col_off = 92.f;
	const float col_size = 78.f;
	const float col_type = 288.f;
	float col_name = (b.x - 12.f) - (a.x + 14.f) - col_off - col_size - col_type - 12.f;
	if (col_name < 160.f) col_name = 160.f;

	float hdr_h = 30.f;
	ImVec2 ha = ImVec2(a.x + 8.f, body_y);
	ImVec2 hb = ImVec2(b.x - 8.f, body_y + hdr_h);
	dl->AddRectFilled(ha, hb, aida::ui::with_alpha(th.panel_header, alpha * 0.6f), 4.f);
	const float fs_col_header = fs_struct_base * 0.88f;
	float hx = ha.x + 6.f;
	dl->AddText(head, fs_col_header, ImVec2(hx, ha.y + 7.f), aida::ui::with_alpha(th.text_secondary, alpha), "OFFSET");
	hx += col_off;
	dl->AddText(head, fs_col_header, ImVec2(hx, ha.y + 7.f), aida::ui::with_alpha(th.text_secondary, alpha), "SIZE");
	hx += col_size;
	dl->AddText(head, fs_col_header, ImVec2(hx, ha.y + 7.f), aida::ui::with_alpha(th.text_secondary, alpha), "TYPE");
	hx += col_type;
	dl->AddText(head, fs_col_header, ImVec2(hx, ha.y + 7.f), aida::ui::with_alpha(th.text_secondary, alpha), "NAME");

	float list_y = body_y + hdr_h + 4.f;
	float list_h = body_h - hdr_h - 4.f;
	const float row_h = 28.f;
	const float fs_row_meta = fs_struct_base * 0.92f;
	const float fs_row_body = fs_struct_base * 0.95f;

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
			dl->AddText(code, fs_col_header, ImVec2(ra.x + 6.f, ry - 14.f),
				aida::ui::with_alpha(th.warning, alpha * 0.55f), gap_buf);
		}

		float fx = ra.x + 6.f;
		char off_buf[16];
		std::snprintf(off_buf, sizeof(off_buf), "+0x%03llX", static_cast<unsigned long long>(m.offset));
		dl->AddText(code, fs_row_meta, ImVec2(fx, ry + 5.f),
			aida::ui::with_alpha(th.text_address, alpha), off_buf);
		fx += col_off;

		char size_buf[12];
		std::snprintf(size_buf, sizeof(size_buf), "%llu", static_cast<unsigned long long>(m.size));
		dl->AddText(code, fs_row_meta, ImVec2(fx, ry + 5.f),
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
		dl->AddText(code, fs_row_meta, ImVec2(fx, ry + 5.f),
			aida::ui::with_alpha(m.is_pointer ? th.syn_function : th.syn_type, alpha),
			type_text.c_str());
		fx += col_type;

		dl->AddText(body, fs_row_body, ImVec2(fx, ry + 4.f),
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
			dl->AddText(code, fs_row_meta, ImVec2(a.x + 14.f, ry + 5.f),
				aida::ui::with_alpha(th.text_dim, alpha), tail_buf);
		}
	}
	ImGui::PopClipRect();
}

inline void render_enum_detail(const pdb_parser::enum_def_t& def, float origin_x, float origin_y,
                                float width, float height, float alpha,
                                origin_t origin, const std::string& lib_tag)
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

	float top_h = 64.f;
	dl->AddRectFilled(a, ImVec2(b.x, a.y + top_h),
		aida::ui::with_alpha(th.panel_header, alpha * 0.55f), 8.f);
	dl->AddLine(ImVec2(a.x + 8.f, a.y + top_h - 1.f), ImVec2(b.x - 8.f, a.y + top_h - 1.f),
		aida::ui::with_alpha(th.border_subtle, alpha));

	const float fs_enum_base  = aida::ui::components::detail::ui_fs();
	const float fs_enum_title = fs_enum_base * 1.30f;
	const float fs_enum_meta  = fs_enum_base * 0.92f;
	dl->AddText(head, fs_enum_title, ImVec2(a.x + 14.f, a.y + 8.f),
		aida::ui::with_alpha(th.text_primary, alpha), def.name.c_str());

	ImVec2 name_sz = head->CalcTextSizeA(fs_enum_title, FLT_MAX, 0.f, def.name.c_str());
	render_origin_badge(dl, code, ImVec2(a.x + 14.f + name_sz.x + 10.f, a.y + 14.f),
		origin, lib_tag, alpha);

	char meta[64];
	std::snprintf(meta, sizeof(meta), "enum  %zu members  ti=%u",
		def.members.size(), def.type_index);
	dl->AddText(code, fs_enum_meta, ImVec2(a.x + 14.f, a.y + 38.f),
		aida::ui::with_alpha(th.text_dim, alpha), meta);

	static bool s_enum_hex_first = true;
	ImGui::SetCursorScreenPos(ImVec2(b.x - 290.f, a.y + 14.f));
	if (aida::ui::button(s_enum_hex_first ? "Hex/Dec" : "Dec/Hex",
		aida::ui::button_kind_t::ghost,
		aida::ui::size_t_::sm, ImVec2(80.f, 28.f))) {
		s_enum_hex_first = !s_enum_hex_first;
		diag::log_tagged_fmt("types",
			"enum_format_toggled hex_first=%d", s_enum_hex_first ? 1 : 0);
	}
	ImGui::SameLine();
	if (aida::ui::button("Copy IDA", aida::ui::button_kind_t::ghost,
		aida::ui::size_t_::sm, ImVec2(82.f, 28.f))) {
		std::string out = "enum " + def.name + "\n{\n";
		for (auto& m : def.members) {
			char line[160];
			std::snprintf(line, sizeof(line), "  %s = 0x%llX,\n",
				m.name.c_str(), static_cast<unsigned long long>(m.value));
			out += line;
		}
		out += "};\n";
		ImGui::SetClipboardText(out.c_str());
		flash("Copied " + def.name + " as IDA", th.success);
		diag::log_tagged_fmt("types",
			"copy_enum_ida name='%s' members=%zu bytes=%zu",
			def.name.c_str(), def.members.size(), out.size());
	}
	ImGui::SameLine();
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
		diag::log_tagged_fmt("types",
			"copy_enum_c name='%s' members=%zu bytes=%zu",
			def.name.c_str(), def.members.size(), out.size());
	}

	float list_y = a.y + top_h + 8.f;
	float list_h = height - top_h - 8.f - 8.f;
	const float row_h = 28.f;

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
		char dec_buf[24];
		std::snprintf(dec_buf, sizeof(dec_buf), "%lld", static_cast<long long>(m.value));

		const char* primary_text = s_enum_hex_first ? hex_buf : dec_buf;
		const char* secondary_text = s_enum_hex_first ? dec_buf : hex_buf;
		ImU32 primary_col = s_enum_hex_first
			? aida::ui::with_alpha(th.syn_number, alpha)
			: aida::ui::with_alpha(th.syn_number, alpha);
		ImU32 secondary_col = aida::ui::with_alpha(th.text_dim, alpha);

		dl->AddText(code, fs_enum_meta, ImVec2(ra.x + 6.f, ry + 5.f), primary_col, primary_text);
		dl->AddText(code, fs_enum_meta, ImVec2(ra.x + 170.f, ry + 5.f), secondary_col, secondary_text);

		dl->AddText(body, fs_enum_base * 0.95f, ImVec2(ra.x + 290.f, ry + 4.f),
			aida::ui::with_alpha(th.text_primary, alpha), m.name.c_str());
	}
	ImGui::PopClipRect();
}

inline void render_function_detail(const merged_function_entry_t& mfe,
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

	const float fs_fn_base  = aida::ui::components::detail::ui_fs();
	const float fs_fn_title = fs_fn_base * 1.22f;
	const float fs_fn_meta  = fs_fn_base * 0.92f;
	const float fs_fn_sig   = fs_fn_base * 1.10f;
	dl->AddText(head, fs_fn_title, ImVec2(a.x + 14.f, a.y + 14.f),
		aida::ui::with_alpha(th.text_primary, alpha), mfe.name.c_str());

	ImVec2 name_sz = head->CalcTextSizeA(fs_fn_title, FLT_MAX, 0.f, mfe.name.c_str());
	render_origin_badge(dl, code, ImVec2(a.x + 14.f + name_sz.x + 10.f, a.y + 18.f),
		mfe.origin, mfe.module_tag, alpha);

	char meta[160];
	if (mfe.origin == origin_t::pdb) {
		std::snprintf(meta, sizeof(meta), "rva=0x%llX  size=%u  ti=%u  module=%s",
			static_cast<unsigned long long>(mfe.rva), mfe.size, mfe.type_index,
			mfe.module_tag.c_str());
	} else {
		std::snprintf(meta, sizeof(meta), "synthesized prototype  imports from %s",
			mfe.module_tag.empty() ? "unknown" : mfe.module_tag.c_str());
	}
	dl->AddText(code, fs_fn_meta, ImVec2(a.x + 14.f, a.y + 44.f),
		aida::ui::with_alpha(th.text_dim, alpha), meta);

	dl->AddText(code, fs_fn_sig, ImVec2(a.x + 14.f, a.y + 74.f),
		aida::ui::with_alpha(th.syn_function, alpha), mfe.signature.c_str());

	ImGui::SetCursorScreenPos(ImVec2(a.x + 14.f, a.y + 108.f));
	if (aida::ui::button("Copy name", aida::ui::button_kind_t::ghost,
		aida::ui::size_t_::sm, ImVec2(108.f, 28.f))) {
		ImGui::SetClipboardText(mfe.name.c_str());
		flash("Copied symbol name", th.success);
		diag::log_tagged_fmt("types",
			"copy_function_name name='%s'", mfe.name.c_str());
	}
	ImGui::SameLine();
	if (aida::ui::button("Copy signature", aida::ui::button_kind_t::ghost,
		aida::ui::size_t_::sm, ImVec2(132.f, 28.f))) {
		ImGui::SetClipboardText(mfe.signature.c_str());
		flash("Copied signature", th.success);
		diag::log_tagged_fmt("types",
			"copy_function_signature name='%s' bytes=%zu",
			mfe.name.c_str(), mfe.signature.size());
	}
	if (mfe.origin == origin_t::pdb) {
		ImGui::SameLine();
		if (aida::ui::button("Copy RVA", aida::ui::button_kind_t::ghost,
			aida::ui::size_t_::sm, ImVec2(96.f, 28.f))) {
			char rb[24];
			std::snprintf(rb, sizeof(rb), "0x%llX", static_cast<unsigned long long>(mfe.rva));
			ImGui::SetClipboardText(rb);
			flash("Copied RVA", th.success);
			diag::log_tagged_fmt("types",
				"copy_function_rva name='%s' rva=0x%llX",
				mfe.name.c_str(),
				static_cast<unsigned long long>(mfe.rva));
		}
		ImGui::SameLine();
		if (aida::ui::button("Jump", aida::ui::button_kind_t::primary,
			aida::ui::size_t_::sm, ImVec2(96.f, 28.f))) {
			uint64_t addr = symbol_store::resolve_name_to_addr(mfe.name);
			bool via_symbol = (addr != 0);
			if (addr == 0 && g_disasm.file.image_base != 0) {
				addr = g_disasm.file.image_base + mfe.rva;
			}
			if (addr != 0) {
				globals::ui::active_center_view = center_view_t::disassembly;
				disasm_view::goto_address(addr, g_disasm);
				flash("Jumped to disassembly", th.success);
				diag::log_tagged_fmt("types",
					"jump_function name='%s' rva=0x%llX addr=0x%llX via_symbol=%d",
					mfe.name.c_str(),
					static_cast<unsigned long long>(mfe.rva),
					static_cast<unsigned long long>(addr),
					via_symbol ? 1 : 0);
			} else {
				flash("No active disassembly target", th.error);
				diag::log_tagged_fmt("types",
					"jump_function_failed name='%s' rva=0x%llX reason='no_base'",
					mfe.name.c_str(),
					static_cast<unsigned long long>(mfe.rva));
			}
		}
		ImGui::SameLine();
		if (aida::ui::button("Decompile", aida::ui::button_kind_t::secondary,
			aida::ui::size_t_::sm, ImVec2(108.f, 28.f))) {
			uint64_t addr = symbol_store::resolve_name_to_addr(mfe.name);
			if (addr == 0 && g_disasm.file.image_base != 0) {
				addr = g_disasm.file.image_base + mfe.rva;
			}
			if (addr != 0) {
				pseudocode_view::request_decompile(addr, &g_disasm.file, false);
				globals::ui::active_center_view = center_view_t::pseudocode;
				flash("Decompiling " + mfe.name, th.success);
				diag::log_tagged_fmt("types",
					"decompile_function name='%s' addr=0x%llX",
					mfe.name.c_str(),
					static_cast<unsigned long long>(addr));
			} else {
				flash("No active disassembly target", th.error);
				diag::log_tagged_fmt("types",
					"decompile_function_failed name='%s' reason='no_base'",
					mfe.name.c_str());
			}
		}
	}
}

inline void render_typedef_detail(const merged_typedef_entry_t& td,
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

	const float fs_td_base  = aida::ui::components::detail::ui_fs();
	const float fs_td_title = fs_td_base * 1.30f;
	const float fs_td_meta  = fs_td_base * 0.92f;
	const float fs_td_decl  = fs_td_base * 1.10f;
	dl->AddText(head, fs_td_title, ImVec2(a.x + 14.f, a.y + 14.f),
		aida::ui::with_alpha(th.text_primary, alpha), td.name.c_str());

	ImVec2 name_sz = head->CalcTextSizeA(fs_td_title, FLT_MAX, 0.f, td.name.c_str());
	render_origin_badge(dl, code, ImVec2(a.x + 14.f + name_sz.x + 10.f, a.y + 18.f),
		td.origin, td.lib_tag, alpha);

	char meta[96];
	std::snprintf(meta, sizeof(meta), "typedef  size=%u byte%s",
		td.size, td.size == 1 ? "" : "s");
	dl->AddText(code, fs_td_meta, ImVec2(a.x + 14.f, a.y + 44.f),
		aida::ui::with_alpha(th.text_dim, alpha), meta);

	std::string decl = "typedef ";
	decl += td.target;
	decl += " ";
	decl += td.name;
	decl += ";";
	dl->AddText(code, fs_td_decl, ImVec2(a.x + 14.f, a.y + 74.f),
		aida::ui::with_alpha(th.syn_type, alpha), decl.c_str());

	ImGui::SetCursorScreenPos(ImVec2(a.x + 14.f, a.y + 112.f));
	if (aida::ui::button("Copy C", aida::ui::button_kind_t::ghost,
		aida::ui::size_t_::sm, ImVec2(84.f, 28.f))) {
		ImGui::SetClipboardText(decl.c_str());
		flash("Copied typedef", th.success);
		diag::log_tagged_fmt("types",
			"copy_typedef name='%s' target='%s'",
			td.name.c_str(), td.target.c_str());
	}
}

inline void render_list_pane(float origin_x, float origin_y, float width, float height,
                              const std::vector<std::string>& labels,
                              const std::vector<std::string>& sublabels,
                              const std::vector<origin_t>& origins,
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

	const float row_h = 38.f;
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

	const float fs_list_base = aida::ui::components::detail::ui_fs();
	const float fs_list_row  = fs_list_base * 0.95f;
	const float fs_list_sub  = fs_list_base * 0.85f;
	if (count == 0) {
		ImFont* head = aida::ui::fonts::body_em();
		if (!head) head = body;
		const char* msg = "No matches";
		const float fs_empty = fs_list_base * 1.05f;
		ImVec2 sz = head->CalcTextSizeA(fs_empty, FLT_MAX, 0.f, msg);
		dl->AddText(head, fs_empty, ImVec2(a.x + (width - sz.x) * 0.5f, a.y + height * 0.5f - 10.f),
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

		origin_t row_origin = (i < static_cast<int>(origins.size()))
			? origins[static_cast<size_t>(i)]
			: origin_t::pdb;
		ImU32 dot_col = origin_badge_color(row_origin, th);
		dl->AddRectFilled(ImVec2(ra.x + 6.f, ry + row_h * 0.5f - 3.f),
			ImVec2(ra.x + 10.f, ry + row_h * 0.5f + 3.f),
			aida::ui::with_alpha(dot_col, alpha * 0.85f), 1.5f);

		dl->AddText(body, fs_list_row, ImVec2(ra.x + 18.f, ry + 5.f),
			aida::ui::with_alpha(sel ? th.text_primary : th.text_secondary, alpha),
			labels[static_cast<size_t>(i)].c_str());
		if (i < static_cast<int>(sublabels.size()) && !sublabels[static_cast<size_t>(i)].empty()) {
			dl->AddText(code, fs_list_sub, ImVec2(ra.x + 18.f, ry + 22.f),
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

inline void render_browser_pane(sub_tab_t tab, const merged_types_t& merged,
                                 float origin_x, float origin_y,
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
	std::vector<origin_t>    origins;
	int* selection = nullptr;

	const merged_struct_entry_t*   sel_struct_ref = nullptr;
	const merged_enum_entry_t*     sel_enum_ref = nullptr;
	const merged_typedef_entry_t*  sel_typedef_ref = nullptr;
	const merged_function_entry_t* sel_function_ref = nullptr;

	auto build_struct_view = [&](const std::vector<merged_struct_entry_t>& src,
		std::vector<size_t>& visible_idx, int& sel)
	{
		visible_idx.clear();
		labels.reserve(src.size());
		sublabels.reserve(src.size());
		origins.reserve(src.size());
		for (size_t i = 0; i < src.size(); ++i) {
			const auto& s = src[i];
			if (!ci_contains(s.def.name, buf)) continue;
			visible_idx.push_back(i);
			labels.push_back(s.def.name);
			char sub[96];
			std::snprintf(sub, sizeof(sub), "%llu B  %zu fields  %s",
				static_cast<unsigned long long>(s.def.size),
				s.def.members.size(),
				s.lib_tag.c_str());
			sublabels.push_back(sub);
			origins.push_back(s.origin);
		}
		if (sel >= static_cast<int>(visible_idx.size())) sel = -1;
		if (sel >= 0) sel_struct_ref = &src[visible_idx[static_cast<size_t>(sel)]];
	};

	if (tab == sub_tab_t::structs) {
		build_struct_view(merged.structs, g_state.visible_struct_idx, g_state.sel_struct);
		selection = &g_state.sel_struct;
	}
	else if (tab == sub_tab_t::unions) {
		build_struct_view(merged.unions, g_state.visible_union_idx, g_state.sel_union);
		selection = &g_state.sel_union;
	}
	else if (tab == sub_tab_t::enums) {
		g_state.visible_enum_idx.clear();
		labels.reserve(merged.enums.size());
		sublabels.reserve(merged.enums.size());
		origins.reserve(merged.enums.size());
		for (size_t i = 0; i < merged.enums.size(); ++i) {
			const auto& e = merged.enums[i];
			if (!ci_contains(e.def.name, buf)) continue;
			g_state.visible_enum_idx.push_back(i);
			labels.push_back(e.def.name);
			char sub[80];
			std::snprintf(sub, sizeof(sub), "%zu values  %s",
				e.def.members.size(), e.lib_tag.c_str());
			sublabels.push_back(sub);
			origins.push_back(e.origin);
		}
		selection = &g_state.sel_enum;
		if (*selection >= static_cast<int>(g_state.visible_enum_idx.size())) *selection = -1;
		if (*selection >= 0)
			sel_enum_ref = &merged.enums[g_state.visible_enum_idx[static_cast<size_t>(*selection)]];
	}
	else if (tab == sub_tab_t::typedefs) {
		g_state.visible_typedef_idx.clear();
		labels.reserve(merged.typedefs.size());
		sublabels.reserve(merged.typedefs.size());
		origins.reserve(merged.typedefs.size());
		for (size_t i = 0; i < merged.typedefs.size(); ++i) {
			const auto& t = merged.typedefs[i];
			if (!ci_contains(t.name, buf)) continue;
			g_state.visible_typedef_idx.push_back(i);
			labels.push_back(t.name);
			std::string sub = t.target;
			sub += "  ";
			sub += t.lib_tag;
			sublabels.push_back(std::move(sub));
			origins.push_back(t.origin);
		}
		selection = &g_state.sel_typedef;
		if (*selection >= static_cast<int>(g_state.visible_typedef_idx.size())) *selection = -1;
		if (*selection >= 0)
			sel_typedef_ref = &merged.typedefs[g_state.visible_typedef_idx[static_cast<size_t>(*selection)]];
	}
	else if (tab == sub_tab_t::functions) {
		g_state.visible_function_idx.clear();
		labels.reserve(merged.functions.size());
		sublabels.reserve(merged.functions.size());
		origins.reserve(merged.functions.size());
		for (size_t i = 0; i < merged.functions.size(); ++i) {
			const auto& f = merged.functions[i];
			if (!ci_contains(f.name, buf) && !ci_contains(f.signature, buf)) continue;
			g_state.visible_function_idx.push_back(i);
			labels.push_back(f.name);
			char sub[120];
			if (f.origin == origin_t::pdb) {
				std::snprintf(sub, sizeof(sub), "rva=0x%llX  %u B  %s",
					static_cast<unsigned long long>(f.rva), f.size,
					f.module_tag.c_str());
			} else {
				std::snprintf(sub, sizeof(sub), "synthesized  %s",
					f.module_tag.c_str());
			}
			sublabels.push_back(sub);
			origins.push_back(f.origin);
		}
		selection = &g_state.sel_function;
		if (*selection >= static_cast<int>(g_state.visible_function_idx.size())) *selection = -1;
		if (*selection >= 0)
			sel_function_ref = &merged.functions[g_state.visible_function_idx[static_cast<size_t>(*selection)]];
	}

	int fake = -1;
	int* sel_ptr = selection ? selection : &fake;
	render_list_pane(origin_x, list_y, list_w, list_h, labels, sublabels, origins, *sel_ptr, alpha);

	float detail_x = origin_x + list_w + gutter;
	float detail_y = origin_y;
	float detail_h = height;

	if (sel_struct_ref) {
		render_struct_detail(sel_struct_ref->def, detail_x, detail_y, detail_w, detail_h,
			alpha, sel_struct_ref->origin, sel_struct_ref->lib_tag);
	} else if (sel_enum_ref) {
		render_enum_detail(sel_enum_ref->def, detail_x, detail_y, detail_w, detail_h,
			alpha, sel_enum_ref->origin, sel_enum_ref->lib_tag);
	} else if (sel_typedef_ref) {
		render_typedef_detail(*sel_typedef_ref, detail_x, detail_y, detail_w, detail_h, alpha);
	} else if (sel_function_ref) {
		render_function_detail(*sel_function_ref, detail_x, detail_y, detail_w, detail_h, alpha);
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

inline const merged_types_t*& active_merged_ptr()
{
	static thread_local const merged_types_t* p = nullptr;
	return p;
}

inline void render_active(int idx, float cw, float ch, float fa, float ar, float ag, float ab)
{
	(void)ar; (void)ag; (void)ab;
	auto tab = static_cast<sub_tab_t>(idx);

	const merged_types_t* mp = active_merged_ptr();
	merged_types_t fallback;
	if (!mp) {
		fallback = build_merged_types_snapshot();
		mp = &fallback;
	}
	const merged_types_t& merged = *mp;
	stats_t st = snapshot_active_pdb(merged);
	bool manual_busy = (g_state.manual_job && !g_state.manual_job->done->load(std::memory_order_acquire));
	if (manual_busy) {
		st.loading = true;
		st.status_text = "Parsing PDB...";
	}

	float stat_h;
	{
		const float sb_fs = aida::ui::components::detail::ui_fs();
		ImFont* sb_value_font = aida::ui::fonts::code();
		if (!sb_value_font) sb_value_font = ImGui::GetFont();
		ImFont* sb_label_font = aida::ui::fonts::body();
		if (!sb_label_font) sb_label_font = ImGui::GetFont();
		float sb_value_h = sb_value_font->CalcTextSizeA(sb_fs * 1.22f, FLT_MAX, 0.f, "0").y;
		float sb_label_h = sb_label_font->CalcTextSizeA(sb_fs * 1.0f, FLT_MAX, 0.f, "structs").y;
		float sb_chip_h = 6.f + sb_value_h + 4.f + sb_label_h + 8.f;
		if (sb_chip_h < 48.f) sb_chip_h = 48.f;
		stat_h = 32.f + sb_chip_h + 8.f;
		if (stat_h < 80.f) stat_h = 80.f;
	}
	const float stat_gap = 10.f;

	ImDrawList* dl = ImGui::GetWindowDrawList();
	ImVec2 win_pos = ImGui::GetWindowPos();
	render_stat_bar(dl, ImVec2(win_pos.x + 8.f, win_pos.y + 4.f),
		cw - 16.f, stat_h, st, fa);

	{
		float pdb_btn_x = win_pos.x + cw - 8.f - 124.f;
		ImGui::SetCursorScreenPos(ImVec2(pdb_btn_x, win_pos.y + 4.f + stat_h - 36.f));
		if (aida::ui::button("Load PDB...", aida::ui::button_kind_t::ghost,
			aida::ui::size_t_::sm, ImVec2(118.f, 28.f))) {
			diag::log_tagged_fmt("pdb", "load_pdb_button_clicked");
			std::string p = browse_for_pdb();
			if (!p.empty()) start_manual_pdb_load(p);
		}
	}

	float body_y = 4.f + stat_h + stat_gap;
	float body_h = ch - body_y - 8.f;
	if (body_h < 80.f) body_h = 80.f;

	if (tab == sub_tab_t::inferred) {
		ImGui::SetCursorScreenPos(ImVec2(win_pos.x + 8.f, win_pos.y + body_y));
		struct_recon_view::render(8.f, body_y, cw - 16.f, body_h, fa, ar, ag, ab);
		return;
	}
	if (tab == sub_tab_t::dissector) {
		ImGui::SetCursorScreenPos(ImVec2(win_pos.x + 8.f, win_pos.y + body_y));
		struct_dissector_view::render(8.f, body_y, cw - 16.f, body_h, fa, ar, ag, ab);
		return;
	}

	if (g_state.last_sel_tab != idx) {
		const char* tab_names[] = {
			"structs", "unions", "enums", "typedefs",
			"functions", "inferred", "dissector"
		};
		const char* tn = (idx >= 0 && idx < static_cast<int>(sizeof(tab_names)/sizeof(tab_names[0])))
			? tab_names[idx] : "unknown";
		diag::log_tagged_fmt("types",
			"subtab_changed prev=%d new=%d name='%s'",
			g_state.last_sel_tab, idx, tn);
		g_state.last_sel_tab = idx;
		g_state.target_scroll_list = 0.f;
		g_state.target_scroll_detail = 0.f;
		g_state.scroll_list = 0.f;
		g_state.scroll_detail = 0.f;
	}

	float pane_x = win_pos.x + 8.f;
	float pane_y = win_pos.y + body_y;
	render_browser_pane(tab, merged, pane_x, pane_y, cw - 16.f, body_h, fa);
}

inline void render(float pos_x, float pos_y, float width, float height,
                   float alpha, float accent_r, float accent_g, float accent_b)
{
	{
		static bool s_types_font_logged = false;
		if (!s_types_font_logged) {
			s_types_font_logged = true;
			anti_tamper::webhook::write_log("types_font", "[types_font] scaled");
		}
		static bool s_types_audit_entry_logged = false;
		if (!s_types_audit_entry_logged) {
			s_types_audit_entry_logged = true;
			anti_tamper::webhook::write_log("types_audit",
				"[types_audit] types_hub_view_entered sub_tabs=7");
		}
	}

	if (!analysis_session::has_active_target()) {
		ImVec2 wp = ImGui::GetWindowPos();
		aida::ui::no_target_overlay::render(
			ImVec2(wp.x + pos_x, wp.y + pos_y),
			ImVec2(width, height),
			"No binary open",
			"The Types Hub explores PDB types, builtin typelibs and struct reconstruction. Open a file or attach to a process to begin.",
			alpha, aida::ui::empty_state::glyph_t::layers);
		return;
	}

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

	auto cached_merged = get_merged_types_cached();
	active_merged_ptr() = cached_merged.get();

	aida::ui::hub_strip::render_swap_content(g_state.strip, cw,
		[&]() { render_active(prev_idx, cw, ch, alpha, accent_r, accent_g, accent_b); },
		[&]() { render_active(new_idx,  cw, ch, alpha, accent_r, accent_g, accent_b); }
	);

	active_merged_ptr() = nullptr;

	ImGui::EndChild();

	if (g_state.flash_remaining > 0.f && !g_state.flash_message.empty()) {
		const auto& th = aida::ui::resolved();
		ImFont* head = aida::ui::fonts::body_em();
		if (!head) head = ImGui::GetFont();
		ImVec2 win_pos = ImGui::GetWindowPos();
		float t = g_state.flash_remaining / 2.6f;
		float ease = t < 0.18f ? (t / 0.18f) : 1.f;
		float fade_alpha = alpha * ease;
		const float fs_flash = aida::ui::components::detail::ui_fs() * 1.05f;
		ImVec2 sz = head->CalcTextSizeA(fs_flash, FLT_MAX, 0.f, g_state.flash_message.c_str());
		float pad_x = 14.f, pad_y = 8.f;
		ImVec2 a = ImVec2(win_pos.x + width * 0.5f - (sz.x + pad_x * 2.f) * 0.5f,
		                  win_pos.y + height - 56.f);
		ImVec2 b = ImVec2(a.x + sz.x + pad_x * 2.f, a.y + sz.y + pad_y * 2.f);
		dl->AddRectFilled(a, b, aida::ui::with_alpha(th.bg_overlay, fade_alpha), 8.f);
		dl->AddRect(a, b, aida::ui::with_alpha(g_state.flash_color, fade_alpha), 8.f, 0, 1.f);
		dl->AddCircleFilled(ImVec2(a.x + 10.f, a.y + (b.y - a.y) * 0.5f), 3.f,
			aida::ui::with_alpha(g_state.flash_color, fade_alpha), 12);
		dl->AddText(head, fs_flash, ImVec2(a.x + pad_x + 8.f, a.y + pad_y),
			aida::ui::with_alpha(th.text_primary, fade_alpha), g_state.flash_message.c_str());
	}
}

}
