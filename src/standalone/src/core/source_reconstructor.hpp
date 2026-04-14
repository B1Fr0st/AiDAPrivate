#pragma once

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <deque>
#include <filesystem>
#include <fstream>
#include <map>
#include <mutex>
#include <numeric>
#include <set>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "standalone_driver.hpp"
#include "pe_parser.hpp"
#include "ghidra_decompiler.hpp"
#include "zydis_disasm.hpp"

#include <Zydis/Zydis.h>

namespace source_reconstructor {

enum class stage_t : int {
	idle = 0,
	collect,
	decompile,
	cluster,
	headers,
	modules,
	metadata,
	done,
	failed
};

struct reconstruction_config_t {
	std::string project_name = "reconstructed";
	std::string output_dir;
	std::string module_name;
	uint64_t    module_base = 0;
	uint32_t    module_size = 0;
	bool        include_imports = true;
	bool        include_exports = true;
	bool        generate_cmake = true;
	bool        use_ai_refinement = true;
	int         max_functions = 0;
};

struct reconstruction_result_t {
	bool        success = false;
	std::string error;
	int         total_functions = 0;
	int         decompiled_functions = 0;
	int         modules_created = 0;
	std::vector<std::string> files_created;
	std::string output_dir;
};

struct function_info_t {
	uint64_t    address = 0;
	std::string name;
	std::string pseudocode;
	std::vector<uint64_t> callees;
	bool        is_export = false;
	bool        decompiled = false;
	bool        hostile = false;
	std::string asm_fallback;
	int         cluster_id = -1;
};

struct state_t {
	std::atomic<bool>    running{false};
	std::atomic<bool>    cancel_requested{false};
	std::atomic<float>   progress{0.f};
	std::atomic<int>     stage{static_cast<int>(stage_t::idle)};
	std::mutex           mutex;
	std::string          status_text;
	reconstruction_result_t last_result;
};

inline state_t g_state;

inline bool is_running() {
	return g_state.running.load(std::memory_order_acquire);
}

inline float get_progress() {
	return g_state.progress.load(std::memory_order_relaxed);
}

inline std::string get_status() {
	std::lock_guard<std::mutex> lk(g_state.mutex);
	return g_state.status_text;
}

inline stage_t get_stage() {
	return static_cast<stage_t>(g_state.stage.load(std::memory_order_relaxed));
}

inline reconstruction_result_t& get_last_result() {
	return g_state.last_result;
}

inline void cancel() {
	g_state.cancel_requested.store(true, std::memory_order_release);
}

inline int get_total_functions() {
	std::lock_guard<std::mutex> lk(g_state.mutex);
	return g_state.last_result.total_functions;
}

inline int get_decompiled_count() {
	std::lock_guard<std::mutex> lk(g_state.mutex);
	return g_state.last_result.decompiled_functions;
}

namespace detail {

inline void set_status(const std::string& s) {
	std::lock_guard<std::mutex> lk(g_state.mutex);
	g_state.status_text = s;
}

inline void set_stage(stage_t s) {
	g_state.stage.store(static_cast<int>(s), std::memory_order_release);
}

inline bool cancelled() {
	return g_state.cancel_requested.load(std::memory_order_acquire);
}

inline std::string to_hex(uint64_t v) {
	char buf[32];
	snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(v));
	return buf;
}

inline std::string sanitize_name(const std::string& raw) {
	std::string out;
	out.reserve(raw.size());
	for (char c : raw) {
		if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		    (c >= '0' && c <= '9') || c == '_')
			out.push_back(c);
		else
			out.push_back('_');
	}
	if (!out.empty() && out[0] >= '0' && out[0] <= '9')
		out.insert(out.begin(), '_');
	return out;
}

inline std::vector<function_info_t> collect_functions(
	uint64_t base, uint32_t size,
	const pe_parser::pe_info_t& pe,
	int max_functions)
{
	std::vector<function_info_t> funcs;
	std::set<uint64_t> seen;

	for (auto& exp : pe.exports) {
		if (exp.is_forwarded) continue;
		uint64_t addr = base + exp.rva;
		if (addr < base || addr >= base + size) continue;
		if (!seen.insert(addr).second) continue;

		function_info_t fi;
		fi.address = addr;
		fi.name = exp.name.empty() ? ("ordinal_" + std::to_string(exp.ordinal)) : sanitize_name(exp.name);
		fi.is_export = true;
		funcs.push_back(std::move(fi));
	}

	for (auto& sec : pe.sections) {
		if (!(sec.characteristics & 0x20000000)) continue;

		uint64_t sec_start = base + sec.virtual_address;
		uint64_t sec_end = sec_start + sec.virtual_size;
		const size_t chunk_size = 0x10000;

		for (uint64_t scan_off = 0; scan_off < sec.virtual_size; scan_off += chunk_size) {
			if (cancelled()) return funcs;

			uint64_t scan_addr = sec_start + scan_off;
			size_t to_read = chunk_size;
			if (scan_addr + to_read > sec_end)
				to_read = static_cast<size_t>(sec_end - scan_addr);

			std::vector<uint8_t> mem;
			driver_bridge::read_memory(scan_addr, to_read, mem);
			if (mem.size() < 4) continue;

			for (size_t i = 0; i + 5 <= mem.size(); ++i) {
				if (mem[i] == 0xE8) {
					int32_t rel = 0;
					std::memcpy(&rel, &mem[i + 1], 4);
					uint64_t target = scan_addr + i + 5 + rel;
					if (target >= sec_start && target < sec_end && seen.find(target) == seen.end()) {
						uint8_t prologue[2] = {};
						std::vector<uint8_t> pb;
						driver_bridge::read_memory(target, 2, pb);
						if (pb.size() >= 2) {
							prologue[0] = pb[0];
							prologue[1] = pb[1];
						}
						bool looks_like_fn = (prologue[0] == 0x55) ||
							(prologue[0] == 0x48 && prologue[1] == 0x89) ||
							(prologue[0] == 0x48 && prologue[1] == 0x83) ||
							(prologue[0] == 0x40 && prologue[1] == 0x53) ||
							(prologue[0] == 0x40 && prologue[1] == 0x55) ||
							(prologue[0] == 0x40 && prologue[1] == 0x57) ||
							(prologue[0] == 0x48 && prologue[1] == 0x8B) ||
							(prologue[0] == 0x4C && prologue[1] == 0x8B) ||
							(prologue[0] == 0x44 && prologue[1] == 0x89) ||
							(prologue[0] == 0xCC);

						if (looks_like_fn && prologue[0] != 0xCC) {
							seen.insert(target);
							function_info_t fi;
							fi.address = target;
							char nm[64];
							snprintf(nm, sizeof(nm), "sub_%llX", static_cast<unsigned long long>(target));
							fi.name = nm;
							funcs.push_back(std::move(fi));
						}
					}
				}
			}
		}
	}

	std::sort(funcs.begin(), funcs.end(), [](const function_info_t& a, const function_info_t& b) {
		return a.address < b.address;
	});

	if (max_functions > 0 && static_cast<int>(funcs.size()) > max_functions)
		funcs.resize(max_functions);

	return funcs;
}

inline void decompile_single_ghidra(
	function_info_t& fi,
	std::atomic<bool>& cancel_flag,
	uint64_t module_base)
{
	auto result = ghidra_decompiler::decompile_function(fi.address, &cancel_flag);

	if (result.complete && !result.is_error && !result.pseudocode.empty()) {
		fi.pseudocode = std::move(result.pseudocode);
		fi.decompiled = true;
		if (!result.function_name.empty() && result.function_name.find("FUN_") != 0)
			fi.name = sanitize_name(result.function_name);
		return;
	}

	fi.hostile = true;
	fi.decompiled = false;

	std::vector<uint8_t> mem;
	driver_bridge::read_memory(fi.address, 0x200, mem);
	if (mem.empty()) {
		fi.asm_fallback = "  __asm { nop }\n";
		return;
	}

	ZydisDecoder decoder;
	ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
	ZydisFormatter formatter;
	ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);

	std::string asm_block;
	asm_block.reserve(4096);
	size_t offset = 0;

	while (offset < mem.size()) {
		ZydisDecodedInstruction instr;
		ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
		auto status = ZydisDecoderDecodeFull(
			&decoder, mem.data() + offset, mem.size() - offset, &instr, operands);

		if (!ZYAN_SUCCESS(status)) break;

		char line[256];
		ZydisFormatterFormatInstruction(
			&formatter, &instr, operands, instr.operand_count_visible,
			line, sizeof(line), fi.address + offset, ZYAN_NULL);

		char full[320];
		snprintf(full, sizeof(full), "    %s\n", line);
		asm_block += full;

		offset += instr.length;

		if (instr.mnemonic == ZYDIS_MNEMONIC_RET ||
		    instr.mnemonic == ZYDIS_MNEMONIC_INT3)
			break;
	}

	fi.asm_fallback = asm_block;
}

inline void extract_callees(
	function_info_t& fi,
	uint64_t module_base,
	uint32_t module_size,
	const std::set<uint64_t>& known_addrs)
{
	std::vector<uint8_t> mem;
	driver_bridge::read_memory(fi.address, 0x1000, mem);
	if (mem.empty()) return;

	ZydisDecoder decoder;
	ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

	size_t offset = 0;
	while (offset < mem.size()) {
		ZydisDecodedInstruction instr;
		ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
		auto status = ZydisDecoderDecodeFull(
			&decoder, mem.data() + offset, mem.size() - offset, &instr, operands);
		if (!ZYAN_SUCCESS(status)) break;

		if (instr.mnemonic == ZYDIS_MNEMONIC_CALL && instr.operand_count_visible >= 1) {
			if (operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
				uint64_t target = fi.address + offset + instr.length;
				if (operands[0].imm.is_signed)
					target = static_cast<uint64_t>(
						static_cast<int64_t>(fi.address + offset + instr.length) +
						static_cast<int64_t>(operands[0].imm.value.s));
				else
					target += operands[0].imm.value.u;

				if (target >= module_base && target < module_base + module_size) {
					if (known_addrs.count(target))
						fi.callees.push_back(target);
				}
			}
		}

		offset += instr.length;
		if (instr.mnemonic == ZYDIS_MNEMONIC_RET || instr.mnemonic == ZYDIS_MNEMONIC_INT3)
			break;
	}
}

inline std::map<int, std::vector<int>> cluster_functions(
	std::vector<function_info_t>& funcs,
	const std::set<uint64_t>& addr_set)
{
	std::unordered_map<uint64_t, int> addr_to_idx;
	for (int i = 0; i < static_cast<int>(funcs.size()); ++i)
		addr_to_idx[funcs[i].address] = i;

	std::vector<std::vector<int>> adj(funcs.size());
	for (int i = 0; i < static_cast<int>(funcs.size()); ++i) {
		for (auto callee_addr : funcs[i].callees) {
			auto it = addr_to_idx.find(callee_addr);
			if (it != addr_to_idx.end()) {
				adj[i].push_back(it->second);
				adj[it->second].push_back(i);
			}
		}
	}

	int cluster_id = 0;
	std::vector<bool> visited(funcs.size(), false);

	for (int i = 0; i < static_cast<int>(funcs.size()); ++i) {
		if (visited[i]) continue;

		std::deque<int> queue;
		queue.push_back(i);
		visited[i] = true;
		std::vector<int> component;

		while (!queue.empty()) {
			int cur = queue.front();
			queue.pop_front();
			component.push_back(cur);
			funcs[cur].cluster_id = cluster_id;

			for (int nb : adj[cur]) {
				if (!visited[nb]) {
					visited[nb] = true;
					queue.push_back(nb);
				}
			}
		}

		cluster_id++;
	}

	const int max_cluster_size = 200;
	for (int c = 0; c < cluster_id; ++c) {
		std::vector<int> members;
		for (int i = 0; i < static_cast<int>(funcs.size()); ++i)
			if (funcs[i].cluster_id == c)
				members.push_back(i);

		if (static_cast<int>(members.size()) > max_cluster_size) {
			int sub = 0;
			int new_base = cluster_id;
			for (int j = 0; j < static_cast<int>(members.size()); ++j) {
				if (j > 0 && j % max_cluster_size == 0) {
					sub++;
				}
				funcs[members[j]].cluster_id = (sub == 0) ? c : (new_base + sub - 1);
			}
			cluster_id = new_base + sub;
		}
	}

	std::map<int, std::vector<int>> clusters;
	for (int i = 0; i < static_cast<int>(funcs.size()); ++i)
		clusters[funcs[i].cluster_id].push_back(i);

	return clusters;
}

inline std::string guess_module_name(const std::vector<function_info_t>& funcs,
                                     const std::vector<int>& indices)
{
	std::unordered_map<std::string, int> prefix_counts;
	for (int idx : indices) {
		auto& name = funcs[idx].name;
		auto pos = name.find('_');
		if (pos != std::string::npos && pos > 1 && pos < 20) {
			std::string prefix = name.substr(0, pos);
			bool all_lower = true;
			for (char c : prefix) {
				if (c < 'a' || c > 'z') { all_lower = false; break; }
			}
			if (all_lower) prefix_counts[prefix]++;
		}
	}

	std::string best;
	int best_count = 0;
	for (auto& [k, v] : prefix_counts) {
		if (v > best_count) { best = k; best_count = v; }
	}

	if (best_count >= 3)
		return "module_" + best;

	return "";
}

inline void generate_common_header(
	const std::string& dir,
	const std::string& project_name,
	const pe_parser::pe_info_t& pe,
	bool include_imports,
	std::vector<std::string>& files_created)
{
	std::filesystem::path hdr_path = std::filesystem::path(dir) / "include" / (project_name + "_types.h");
	std::filesystem::create_directories(hdr_path.parent_path());

	std::ofstream ofs(hdr_path, std::ios::binary);
	if (!ofs) return;

	ofs << "#pragma once\n\n";
	ofs << "#include <stdint.h>\n";
	ofs << "#include <stddef.h>\n\n";

	ofs << "typedef unsigned char  BYTE;\n";
	ofs << "typedef unsigned short WORD;\n";
	ofs << "typedef unsigned long  DWORD;\n";
	ofs << "typedef unsigned long long QWORD;\n";
	ofs << "typedef int BOOL;\n";
	ofs << "typedef void* PVOID;\n";
	ofs << "typedef void* HANDLE;\n\n";

	if (include_imports && !pe.imports.empty()) {
		ofs << "\n";
		std::set<std::string> import_modules;
		for (auto& imp : pe.imports)
			import_modules.insert(imp.module_name);

		for (auto& mod : import_modules) {
			ofs << "// imports from " << mod << "\n";
		}
		ofs << "\n";

		for (auto& imp : pe.imports) {
			if (imp.function_name.empty()) continue;
			ofs << "extern void* __imp_" << sanitize_name(imp.function_name) << ";\n";
		}
		ofs << "\n";
	}

	ofs.close();
	files_created.push_back(hdr_path.string());
}

inline void generate_exports_header(
	const std::string& dir,
	const std::string& project_name,
	const std::vector<function_info_t>& funcs,
	std::vector<std::string>& files_created)
{
	std::filesystem::path hdr_path = std::filesystem::path(dir) / "include" / (project_name + "_exports.h");
	std::filesystem::create_directories(hdr_path.parent_path());

	std::ofstream ofs(hdr_path, std::ios::binary);
	if (!ofs) return;

	ofs << "#pragma once\n\n";
	ofs << "#include \"" << project_name << "_types.h\"\n\n";

	for (auto& fi : funcs) {
		if (!fi.is_export) continue;
		if (fi.decompiled && !fi.pseudocode.empty()) {
			auto first_line = fi.pseudocode.substr(0, fi.pseudocode.find('\n'));
			if (!first_line.empty() && first_line.back() == '{')
				first_line.pop_back();
			while (!first_line.empty() && (first_line.back() == ' ' || first_line.back() == '\t'))
				first_line.pop_back();
			ofs << first_line << ";\n";
		} else {
			ofs << "void " << fi.name << "(void);\n";
		}
	}

	ofs.close();
	files_created.push_back(hdr_path.string());
}

inline void generate_module_source(
	const std::string& dir,
	const std::string& project_name,
	const std::string& module_name,
	const std::vector<function_info_t>& funcs,
	const std::vector<int>& indices,
	std::vector<std::string>& files_created)
{
	std::filesystem::path src_path = std::filesystem::path(dir) / "src" / (module_name + ".cpp");
	std::filesystem::create_directories(src_path.parent_path());

	std::ofstream ofs(src_path, std::ios::binary);
	if (!ofs) return;

	ofs << "#include \"../include/" << project_name << "_types.h\"\n";
	ofs << "#include \"../include/" << project_name << "_exports.h\"\n\n";

	for (int idx : indices) {
		auto& fi = funcs[idx];

		if (fi.decompiled && !fi.pseudocode.empty()) {
			ofs << fi.pseudocode << "\n\n";
		} else if (fi.hostile) {
			ofs << "void " << fi.name << "(void) {\n";
			ofs << "#ifdef _MSC_VER\n";
			ofs << "  __asm {\n";
			if (!fi.asm_fallback.empty())
				ofs << fi.asm_fallback;
			else
				ofs << "    nop\n";
			ofs << "  }\n";
			ofs << "#else\n";
			ofs << "  __asm__ __volatile__(\"nop\");\n";
			ofs << "#endif\n";
			ofs << "}\n\n";
		} else {
			ofs << "void " << fi.name << "(void) {\n";
			ofs << "}\n\n";
		}
	}

	ofs.close();
	files_created.push_back(src_path.string());
}

inline void generate_cmake(
	const std::string& dir,
	const std::string& project_name,
	const std::vector<std::string>& source_files,
	std::vector<std::string>& files_created)
{
	std::filesystem::path cmake_path = std::filesystem::path(dir) / "CMakeLists.txt";

	std::ofstream ofs(cmake_path, std::ios::binary);
	if (!ofs) return;

	ofs << "cmake_minimum_required(VERSION 3.15)\n";
	ofs << "project(" << project_name << " LANGUAGES CXX)\n\n";
	ofs << "set(CMAKE_CXX_STANDARD 17)\n";
	ofs << "set(CMAKE_CXX_STANDARD_REQUIRED ON)\n\n";
	ofs << "include_directories(include)\n\n";
	ofs << "add_library(" << project_name << " STATIC\n";

	for (auto& sf : source_files) {
		auto rel = std::filesystem::relative(sf, dir);
		ofs << "    " << rel.generic_string() << "\n";
	}

	ofs << ")\n";

	ofs.close();
	files_created.push_back(cmake_path.string());
}

inline void generate_xref_json(
	const std::string& dir,
	const std::vector<function_info_t>& funcs,
	std::vector<std::string>& files_created)
{
	std::filesystem::path json_path = std::filesystem::path(dir) / "xrefs.json";

	std::ofstream ofs(json_path, std::ios::binary);
	if (!ofs) return;

	ofs << "{\n";
	bool first = true;
	for (auto& fi : funcs) {
		if (fi.callees.empty()) continue;
		if (!first) ofs << ",\n";
		first = false;
		ofs << "  \"" << to_hex(fi.address) << "\": {\n";
		ofs << "    \"name\": \"" << fi.name << "\",\n";
		ofs << "    \"callees\": [";
		for (size_t j = 0; j < fi.callees.size(); ++j) {
			if (j > 0) ofs << ", ";
			ofs << "\"" << to_hex(fi.callees[j]) << "\"";
		}
		ofs << "]\n  }";
	}
	ofs << "\n}\n";

	ofs.close();
	files_created.push_back(json_path.string());
}

inline void generate_module_map_json(
	const std::string& dir,
	const std::vector<function_info_t>& funcs,
	const std::map<int, std::string>& cluster_names,
	std::vector<std::string>& files_created)
{
	std::filesystem::path json_path = std::filesystem::path(dir) / "module_map.json";

	std::ofstream ofs(json_path, std::ios::binary);
	if (!ofs) return;

	ofs << "{\n";
	bool first = true;
	for (auto& fi : funcs) {
		if (!first) ofs << ",\n";
		first = false;

		std::string mod_name = "unknown";
		auto it = cluster_names.find(fi.cluster_id);
		if (it != cluster_names.end()) mod_name = it->second;

		ofs << "  \"" << to_hex(fi.address) << "\": {\n";
		ofs << "    \"name\": \"" << fi.name << "\",\n";
		ofs << "    \"module\": \"" << mod_name << "\",\n";
		ofs << "    \"export\": " << (fi.is_export ? "true" : "false") << ",\n";
		ofs << "    \"decompiled\": " << (fi.decompiled ? "true" : "false") << "\n";
		ofs << "  }";
	}
	ofs << "\n}\n";

	ofs.close();
	files_created.push_back(json_path.string());
}

}

inline void reconstruct(const reconstruction_config_t& config) {
	if (g_state.running.load(std::memory_order_acquire)) return;

	g_state.running.store(true, std::memory_order_release);
	g_state.cancel_requested.store(false, std::memory_order_release);
	g_state.progress.store(0.f);
	g_state.stage.store(static_cast<int>(stage_t::collect));

	{
		std::lock_guard<std::mutex> lk(g_state.mutex);
		g_state.status_text = "Starting reconstruction...";
		g_state.last_result = {};
		g_state.last_result.output_dir = config.output_dir;
	}

	std::thread([config]() {
		reconstruction_result_t result;
		result.output_dir = config.output_dir;

		auto finish = [&](bool success, const std::string& err = "") {
			result.success = success;
			result.error = err;
			{
				std::lock_guard<std::mutex> lk(g_state.mutex);
				g_state.last_result = result;
				g_state.status_text = success ? "Reconstruction complete." : ("Failed: " + err);
			}
			detail::set_stage(success ? stage_t::done : stage_t::failed);
			g_state.progress.store(success ? 1.f : g_state.progress.load());
			g_state.running.store(false, std::memory_order_release);
		};

		std::filesystem::path out_dir(config.output_dir);
		try {
			std::filesystem::create_directories(out_dir / "src");
			std::filesystem::create_directories(out_dir / "include");
		} catch (...) {
			finish(false, "Failed to create output directories.");
			return;
		}

		detail::set_stage(stage_t::collect);
		detail::set_status("Parsing PE headers...");
		g_state.progress.store(0.01f);

		pe_parser::pe_info_t pe;
		if (!pe_parser::parse(config.module_base, pe)) {
			finish(false, "Failed to parse PE headers at base " + detail::to_hex(config.module_base));
			return;
		}

		detail::set_status("Collecting functions...");
		g_state.progress.store(0.02f);

		auto funcs = detail::collect_functions(
			config.module_base, config.module_size, pe, config.max_functions);

		if (detail::cancelled()) { finish(false, "Cancelled."); return; }

		result.total_functions = static_cast<int>(funcs.size());
		{
			std::lock_guard<std::mutex> lk(g_state.mutex);
			g_state.last_result.total_functions = result.total_functions;
		}

		if (funcs.empty()) {
			finish(false, "No functions found in module.");
			return;
		}

		char collect_msg[256];
		snprintf(collect_msg, sizeof(collect_msg), "Collected %d functions.",
		         static_cast<int>(funcs.size()));
		detail::set_status(collect_msg);
		g_state.progress.store(0.05f);

		detail::set_stage(stage_t::decompile);

		bool ghidra_ok = ghidra_decompiler::is_initialized();
		if (!ghidra_ok) {
			ghidra_ok = ghidra_decompiler::init();
		}

		if (!ghidra_ok) {
			finish(false, "Ghidra decompiler not initialized.");
			return;
		}

		// --- Bulk pipeline: preload entire module + parallel batch decompile ---
		// WHY: The old sequential loop called decompile_function() per function,
		//      each doing its own 256KB driver read.  For 15,000 functions, that
		//      is 15,000 separate IOCTLs.  Instead, we read the entire module
		//      once (one IOCTL), then feed the buffer to a parallel thread pool
		//      where each worker has its own Architecture instance.
		detail::set_status("Preloading module memory...");
		g_state.progress.store(0.06f);

		std::vector<uint8_t> module_mem;
		bool preloaded = ghidra_decompiler::preload_module(
			config.module_base, config.module_size, module_mem);

		if (!preloaded) {
			finish(false, "Failed to preload module memory.");
			return;
		}

		if (detail::cancelled()) { finish(false, "Cancelled."); return; }

		// Collect entry addresses for batch
		std::vector<uint64_t> entries;
		entries.reserve(funcs.size());
		for (auto& fi : funcs)
			entries.push_back(fi.address);

		// Progress tracking — the batch_decompile increments this atomically
		std::atomic<int> decompile_count{0};
		const int total = static_cast<int>(funcs.size());

		// Start a progress-reporting thread so the UI stays updated
		std::atomic<bool> progress_done{false};
		std::thread progress_thread([&]() {
			while (!progress_done.load(std::memory_order_acquire)) {
				int done = decompile_count.load(std::memory_order_relaxed);
				float pct = 0.07f + 0.63f * (static_cast<float>(done) / static_cast<float>(total));
				g_state.progress.store(pct);

				char dmsg[256];
				snprintf(dmsg, sizeof(dmsg), "Decompiling %d / %d (parallel)", done, total);
				detail::set_status(dmsg);

				{
					std::lock_guard<std::mutex> lk(g_state.mutex);
					g_state.last_result.decompiled_functions = done;
				}

				std::this_thread::sleep_for(std::chrono::milliseconds(50));
			}
		});

		// Parallel batch decompile — all functions at once
		std::vector<ghidra_decompiler::ghidra_result_t> batch_results;
		ghidra_decompiler::batch_decompile(
			module_mem.data(), module_mem.size(), config.module_base,
			entries, batch_results, &decompile_count, &g_state.cancel_requested);

		progress_done.store(true, std::memory_order_release);
		progress_thread.join();

		// Map batch results back to function_info_t entries
		for (size_t i = 0; i < funcs.size() && i < batch_results.size(); ++i) {
			auto& r = batch_results[i];
			if (r.complete && !r.is_error && !r.pseudocode.empty()) {
				funcs[i].pseudocode = std::move(r.pseudocode);
				funcs[i].decompiled = true;
				if (!r.function_name.empty() && r.function_name.find("FUN_") != 0)
					funcs[i].name = detail::sanitize_name(r.function_name);
			} else {
				// Fallback: disassemble hostile functions
				funcs[i].hostile = true;
				funcs[i].decompiled = false;

				std::vector<uint8_t> asm_mem;
				// Read from preloaded buffer instead of driver
				uint64_t off = funcs[i].address - config.module_base;
				if (off < module_mem.size()) {
					size_t avail = (std::min)(static_cast<size_t>(0x200), module_mem.size() - static_cast<size_t>(off));
					asm_mem.assign(module_mem.data() + off, module_mem.data() + off + avail);
				}

				if (asm_mem.empty()) {
					funcs[i].asm_fallback = "  __asm { nop }\n";
				} else {
					ZydisDecoder decoder;
					ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
					ZydisFormatter formatter;
					ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);

					std::string asm_block;
					asm_block.reserve(4096);
					size_t aoff = 0;

					while (aoff < asm_mem.size()) {
						ZydisDecodedInstruction instr;
						ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
						auto status = ZydisDecoderDecodeFull(
							&decoder, asm_mem.data() + aoff, asm_mem.size() - aoff, &instr, operands);
						if (!ZYAN_SUCCESS(status)) break;

						char line[256];
						ZydisFormatterFormatInstruction(
							&formatter, &instr, operands, instr.operand_count_visible,
							line, sizeof(line), funcs[i].address + aoff, ZYAN_NULL);
						char full[320];
						snprintf(full, sizeof(full), "    %s\n", line);
						asm_block += full;
						aoff += instr.length;

						if (instr.mnemonic == ZYDIS_MNEMONIC_RET ||
						    instr.mnemonic == ZYDIS_MNEMONIC_INT3)
							break;
					}
					funcs[i].asm_fallback = asm_block;
				}
			}
		}

		{
			std::lock_guard<std::mutex> lk(g_state.mutex);
			g_state.last_result.decompiled_functions = static_cast<int>(funcs.size());
		}

		if (detail::cancelled()) { finish(false, "Cancelled."); return; }

		result.decompiled_functions = 0;
		for (auto& fi : funcs)
			if (fi.decompiled) result.decompiled_functions++;

		detail::set_stage(stage_t::cluster);
		detail::set_status("Extracting call graph...");
		g_state.progress.store(0.72f);

		std::set<uint64_t> addr_set;
		for (auto& fi : funcs) addr_set.insert(fi.address);

		for (int i = 0; i < static_cast<int>(funcs.size()); ++i) {
			if (detail::cancelled()) { finish(false, "Cancelled."); return; }
			detail::extract_callees(funcs[i], config.module_base, config.module_size, addr_set);
		}

		detail::set_status("Clustering functions into modules...");
		g_state.progress.store(0.75f);

		auto clusters = detail::cluster_functions(funcs, addr_set);

		std::map<int, std::string> cluster_names;
		int unnamed_idx = 0;
		for (auto& [cid, indices] : clusters) {
			std::string guessed = detail::guess_module_name(funcs, indices);
			if (guessed.empty()) {
				char nm[64];
				snprintf(nm, sizeof(nm), "module_%03d", unnamed_idx++);
				guessed = nm;
			}
			cluster_names[cid] = guessed;
		}

		if (detail::cancelled()) { finish(false, "Cancelled."); return; }

		detail::set_stage(stage_t::headers);
		detail::set_status("Generating headers...");
		g_state.progress.store(0.80f);

		detail::generate_common_header(
			config.output_dir, config.project_name, pe,
			config.include_imports, result.files_created);

		if (config.include_exports) {
			detail::generate_exports_header(
				config.output_dir, config.project_name, funcs, result.files_created);
		}

		if (detail::cancelled()) { finish(false, "Cancelled."); return; }

		detail::set_stage(stage_t::modules);
		detail::set_status("Generating source modules...");
		g_state.progress.store(0.82f);

		std::vector<std::string> source_files;
		int module_idx = 0;
		int total_clusters = static_cast<int>(clusters.size());

		for (auto& [cid, indices] : clusters) {
			if (detail::cancelled()) { finish(false, "Cancelled."); return; }

			float mod_pct = 0.82f + 0.10f * (static_cast<float>(module_idx) / static_cast<float>((std::max)(total_clusters, 1)));
			g_state.progress.store(mod_pct);

			std::string mod_name = cluster_names[cid];
			detail::generate_module_source(
				config.output_dir, config.project_name, mod_name,
				funcs, indices, result.files_created);

			source_files.push_back(
				(std::filesystem::path(config.output_dir) / "src" / (mod_name + ".cpp")).string());
			module_idx++;
		}

		result.modules_created = module_idx;

		detail::set_stage(stage_t::metadata);
		detail::set_status("Generating metadata...");
		g_state.progress.store(0.93f);

		if (config.generate_cmake) {
			detail::generate_cmake(
				config.output_dir, config.project_name,
				source_files, result.files_created);
		}

		detail::generate_xref_json(config.output_dir, funcs, result.files_created);
		detail::generate_module_map_json(config.output_dir, funcs, cluster_names, result.files_created);

		g_state.progress.store(0.98f);
		detail::set_status("Finalizing...");

		result.total_functions = static_cast<int>(funcs.size());

		finish(true);
	}).detach();
}

}
