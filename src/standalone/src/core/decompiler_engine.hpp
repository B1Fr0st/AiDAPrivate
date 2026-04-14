#pragma once

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <functional>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "cfg_view.hpp"
#include "pe_parser.hpp"
#include "standalone_ai_client.hpp"
#include "standalone_driver.hpp"
#include "standalone_settings.hpp"
#include "xref_engine.hpp"
#include "zydis_disasm.hpp"
#include "ghidra_decompiler.hpp"

#include <nlohmann/json.hpp>

#ifdef __NT__
#include "emulation_engine.hpp"
#endif

namespace decompiler_engine {

enum class decompile_mode_t {
	ai = 0,
	native_ghidra = 1,
	hybrid = 2
};

struct decompile_result_t {
	uint64_t    function_addr = 0;
	std::string function_name;
	std::string pseudocode;
	std::string parameters;
	std::string local_vars;
	std::vector<std::string> callees;
	std::vector<std::pair<int, uint64_t>> line_addr_map;
	bool        complete = false;
	bool        is_error = false;
	std::string error_text;
};

struct history_entry_t {
	uint64_t addr = 0;
	std::string name;
};

struct state_t {
	decompile_result_t current;
	std::string        streaming_text;
	std::mutex         mutex;
	std::atomic<bool>  decompiling{false};
	std::atomic<bool>  emulating{false};
	std::atomic<bool>  cancel{false};
	std::atomic<float> emulation_progress{0.f};
	bool               active = false;

	std::vector<history_entry_t> history;
	int history_pos = -1;

	float scroll_y = 0.f;
	float target_scroll_y = 0.f;

	std::unordered_map<uint64_t, decompile_result_t> cache;

	std::atomic<bool>  batch_running{false};
	std::atomic<int>   batch_total{0};
	std::atomic<int>   batch_done{0};
	std::vector<uint64_t> batch_queue;

	decompile_mode_t active_mode = decompile_mode_t::ai;
};

inline state_t g_state;

namespace detail {

inline std::string build_block_text(const std::vector<cfg_view::basic_block_t>& blocks,
                                    const std::vector<cfg_view::instruction_line_t>* extra_instrs = nullptr)
{
	std::string out;
	out.reserve(8192);

	for (int i = 0; i < static_cast<int>(blocks.size()); ++i) {
		auto& blk = blocks[i];
		char hdr[128];
		snprintf(hdr, sizeof(hdr), "block_%d (0x%llX - 0x%llX):",
		         i, static_cast<unsigned long long>(blk.start_addr),
		         static_cast<unsigned long long>(blk.end_addr));
		out += hdr;
		out += "\n";

		for (auto& ins : blk.instructions) {
			char line[256];
			snprintf(line, sizeof(line), "  0x%llX: %s",
			         static_cast<unsigned long long>(ins.addr), ins.text.c_str());
			out += line;
			out += "\n";
		}

		if (!blk.successors.empty()) {
			out += "  -> successors: ";
			for (int j = 0; j < static_cast<int>(blk.successors.size()); ++j) {
				if (j > 0) out += ", ";
				char sb[32];
				snprintf(sb, sizeof(sb), "block_%d", blk.successors[j]);
				out += sb;
			}
			out += "\n";
		}
		out += "\n";
	}

	return out;
}

inline std::string build_xref_text(uint64_t func_addr)
{
	std::string out;
	std::vector<uint8_t> mem;
	driver_bridge::read_memory(func_addr, 0x1000, mem);
	if (mem.empty()) return out;

	out += "Cross-references from this function:\n";

	const uint8_t* data = mem.data();
	int sz = static_cast<int>(mem.size());
	int pos = 0;
	int count = 0;

	while (pos < sz && count < 200) {
		int avail = (std::min)(sz - pos, 15);
		uint64_t va = func_addr + pos;
		AsmInstr ins = zydis_decode_one(data + pos, avail, va);

		if (ins.is_call && ins.len == 5 && data[pos] == 0xE8) {
			int32_t rel = 0;
			std::memcpy(&rel, data + pos + 1, 4);
			uint64_t target = va + ins.len + rel;
			char buf[128];
			snprintf(buf, sizeof(buf), "  CALL 0x%llX from 0x%llX",
			         static_cast<unsigned long long>(target),
			         static_cast<unsigned long long>(va));
			out += buf;
			out += "\n";
		}

		if (ins.is_ret) break;
		pos += ins.len;
		++count;
	}

	return out;
}

inline std::string resolve_module_symbols(uint64_t func_addr)
{
	std::string out;
	auto modules = driver_bridge::enumerate_modules();
	for (auto& m : modules) {
		if (func_addr >= m.base && func_addr < m.base + m.size) {
			char buf[512];
			snprintf(buf, sizeof(buf), "Module: %s (base=0x%llX, size=0x%X)\nFunction offset: +0x%llX\n",
			         m.name.c_str(),
			         static_cast<unsigned long long>(m.base),
			         m.size,
			         static_cast<unsigned long long>(func_addr - m.base));
			out = buf;
			break;
		}
	}
	return out;
}

struct import_lookup_t {
	std::unordered_map<uint64_t, std::string> iat_map;
	std::unordered_map<uint64_t, std::string> export_map;
	std::vector<driver_bridge::module_info_t> modules;
};

inline import_lookup_t build_import_lookup(uint64_t func_addr)
{
	import_lookup_t result;
	result.modules = driver_bridge::enumerate_modules();

	driver_bridge::module_info_t target_module{};
	bool found_module = false;
	for (auto& m : result.modules) {
		if (func_addr >= m.base && func_addr < m.base + m.size) {
			target_module = m;
			found_module = true;
			break;
		}
	}

	if (!found_module) return result;

	pe_parser::pe_info_t pe;
	if (!pe_parser::parse(target_module.base, pe)) return result;

	std::vector<pe_parser::import_entry_t> imports;
	if (pe_parser::parse_imports(target_module.base, pe, imports)) {
		for (auto& imp : imports) {
			if (imp.iat_address == 0 || imp.function_name.empty()) continue;
			std::string mod_short = imp.module_name;
			size_t dot = mod_short.rfind('.');
			if (dot != std::string::npos) mod_short = mod_short.substr(0, dot);
			result.iat_map[imp.iat_address] = mod_short + "!" + imp.function_name;
			if (imp.bound_address != 0)
				result.export_map[imp.bound_address] = mod_short + "!" + imp.function_name;
		}
	}

	return result;
}

inline std::string resolve_call_name(import_lookup_t& lookup, uint64_t call_target, uint64_t iat_addr = 0)
{
	if (iat_addr != 0) {
		auto it = lookup.iat_map.find(iat_addr);
		if (it != lookup.iat_map.end()) return it->second;
	}

	auto eit = lookup.export_map.find(call_target);
	if (eit != lookup.export_map.end()) return eit->second;

	for (auto& m : lookup.modules) {
		if (call_target < m.base || call_target >= m.base + m.size) continue;

		pe_parser::pe_info_t mod_pe;
		if (!pe_parser::parse(m.base, mod_pe)) break;

		std::vector<pe_parser::export_entry_t> exports;
		if (!pe_parser::parse_exports(m.base, mod_pe, exports)) break;

		std::string mod_short = m.name;
		size_t dot = mod_short.rfind('.');
		if (dot != std::string::npos) mod_short = mod_short.substr(0, dot);

		for (auto& exp : exports) {
			if (!exp.name.empty() && !exp.is_forwarded)
				lookup.export_map[exp.address] = mod_short + "!" + exp.name;
		}

		auto eit2 = lookup.export_map.find(call_target);
		if (eit2 != lookup.export_map.end()) return eit2->second;
		break;
	}

	return {};
}

inline std::string try_read_string_at(uint64_t addr, size_t max_len = 128)
{
	std::vector<uint8_t> data;
	driver_bridge::read_memory(addr, max_len, data);
	if (data.size() < 4) return {};

	int printable = 0;
	int total = 0;
	for (size_t i = 0; i < data.size(); ++i) {
		uint8_t c = data[i];
		if (c == 0) break;
		total++;
		if (c >= 0x20 && c < 0x7F) printable++;
	}

	if (total >= 4 && printable * 2 > total) {
		std::string result;
		result.reserve(static_cast<size_t>(total));
		for (int i = 0; i < total && static_cast<size_t>(i) < data.size() && data[i] != 0; ++i)
			result.push_back(static_cast<char>(data[i]));
		return result;
	}

	printable = 0;
	total = 0;
	for (size_t i = 0; i + 2 <= data.size(); i += 2) {
		uint16_t c = 0;
		std::memcpy(&c, data.data() + i, 2);
		if (c == 0) break;
		total++;
		if (c >= 0x20 && c < 0x7F) printable++;
	}

	if (total >= 4 && printable * 2 > total) {
		std::string result;
		result.reserve(static_cast<size_t>(total));
		for (size_t i = 0; i + 2 <= data.size(); i += 2) {
			uint16_t c = 0;
			std::memcpy(&c, data.data() + i, 2);
			if (c == 0) break;
			if (c < 0x80) result.push_back(static_cast<char>(c));
			else result += '?';
		}
		return result;
	}

	return {};
}

inline void annotate_instructions(std::vector<cfg_view::basic_block_t>& blocks,
                                   const uint8_t* mem, uint64_t mem_base, size_t mem_size,
                                   import_lookup_t& lookup)
{
	for (auto& blk : blocks) {
		for (auto& ins : blk.instructions) {
			if (ins.addr < mem_base) continue;
			uint64_t off = ins.addr - mem_base;
			if (off >= mem_size) continue;

			const uint8_t* raw = mem + off;
			int avail = static_cast<int>((std::min)(mem_size - off, static_cast<size_t>(15)));

			if (avail >= 5 && raw[0] == 0xE8) {
				int32_t rel = 0;
				std::memcpy(&rel, raw + 1, 4);
				uint64_t target = ins.addr + 5 + rel;
				std::string name = resolve_call_name(lookup, target);
				if (!name.empty()) {
					ins.text += " ; ";
					ins.text += name;
				}
			}
			else if (avail >= 6 && raw[0] == 0xFF && raw[1] == 0x15) {
				int32_t disp = 0;
				std::memcpy(&disp, raw + 2, 4);
				uint64_t iat_addr = ins.addr + 6 + disp;
				std::string name = resolve_call_name(lookup, 0, iat_addr);
				if (!name.empty()) {
					ins.text += " ; ";
					ins.text += name;
				}
			}
			else {
				bool is_lea = false;
				int lea_disp_offset = 0;
				int lea_insn_len = 0;

				if (avail >= 7 && (raw[0] == 0x48 || raw[0] == 0x4C) && raw[1] == 0x8D) {
					uint8_t modrm = raw[2];
					uint8_t mod_field = (modrm >> 6) & 3;
					uint8_t rm_field = modrm & 7;
					if (mod_field == 0 && rm_field == 5) {
						is_lea = true;
						lea_disp_offset = 3;
						lea_insn_len = 7;
					}
				}

				if (!is_lea && avail >= 7 && raw[0] == 0x48 && raw[1] == 0x8B) {
					uint8_t modrm = raw[2];
					uint8_t mod_field = (modrm >> 6) & 3;
					uint8_t rm_field = modrm & 7;
					if (mod_field == 0 && rm_field == 5) {
						is_lea = true;
						lea_disp_offset = 3;
						lea_insn_len = 7;
					}
				}

				if (is_lea && lea_disp_offset + 4 <= avail) {
					int32_t disp = 0;
					std::memcpy(&disp, raw + lea_disp_offset, 4);
					uint64_t target = ins.addr + lea_insn_len + disp;

					std::string str = try_read_string_at(target);
					if (!str.empty()) {
						if (str.size() > 64) {
							str.resize(64);
							str += "...";
						}
						ins.text += " ; \"";
						ins.text += str;
						ins.text += "\"";
					}
				}
			}
		}
	}
}

inline std::string get_cache_dir()
{
	const char* appdata = std::getenv("APPDATA");
	if (!appdata) return {};
	return std::string(appdata) + "\\AiDA\\Standalone\\decompiler_cache";
}

inline void save_cache_entry_to_disk(uint64_t func_addr, const decompile_result_t& result)
{
	std::string dir = get_cache_dir();
	if (dir.empty()) return;

	std::error_code ec;
	std::filesystem::create_directories(dir, ec);
	if (ec) return;

	std::string module_name;
	uint64_t rva = func_addr;
	auto modules = driver_bridge::enumerate_modules();
	for (auto& m : modules) {
		if (func_addr >= m.base && func_addr < m.base + m.size) {
			module_name = m.name;
			rva = func_addr - m.base;
			break;
		}
	}

	if (module_name.empty()) {
		char buf[32];
		std::snprintf(buf, sizeof(buf), "unk_%llX", static_cast<unsigned long long>(func_addr));
		module_name = buf;
	}

	for (auto& c : module_name) {
		if (c == '\\' || c == '/' || c == ':' || c == '*' || c == '?' || c == '"' || c == '<' || c == '>' || c == '|')
			c = '_';
	}

	char fname[256];
	std::snprintf(fname, sizeof(fname), "%s\\%s_%llX.json",
	              dir.c_str(), module_name.c_str(), static_cast<unsigned long long>(rva));

	nlohmann::json j;
	j["function_addr"] = func_addr;
	j["function_name"] = result.function_name;
	j["pseudocode"] = result.pseudocode;
	j["parameters"] = result.parameters;
	j["callees"] = result.callees;

	std::ofstream ofs(fname);
	if (ofs.is_open()) {
		ofs << j.dump(2);
	}
}

inline void save_all_cache_to_disk()
{
	std::lock_guard<std::mutex> lk(g_state.mutex);
	for (auto& [addr, result] : g_state.cache) {
		save_cache_entry_to_disk(addr, result);
	}
}

inline void load_cache_from_disk()
{
	std::string dir = get_cache_dir();
	if (dir.empty()) return;

	std::error_code ec;
	if (!std::filesystem::exists(dir, ec)) return;

	for (auto& entry : std::filesystem::directory_iterator(dir, ec)) {
		if (ec) break;
		if (!entry.is_regular_file()) continue;
		if (entry.path().extension() != ".json") continue;

		std::ifstream ifs(entry.path());
		if (!ifs.is_open()) continue;

		try {
			nlohmann::json j;
			ifs >> j;

			decompile_result_t result;
			result.function_addr = j.value("function_addr", uint64_t(0));
			result.function_name = j.value("function_name", std::string{});
			result.pseudocode = j.value("pseudocode", std::string{});
			result.parameters = j.value("parameters", std::string{});
			if (j.contains("callees") && j["callees"].is_array()) {
				for (auto& c : j["callees"])
					result.callees.push_back(c.get<std::string>());
			}
			result.complete = true;

			if (result.function_addr != 0 && !result.pseudocode.empty()) {
				std::lock_guard<std::mutex> lk(g_state.mutex);
				if (g_state.cache.find(result.function_addr) == g_state.cache.end())
					g_state.cache[result.function_addr] = std::move(result);
			}
		} catch (...) {}
	}
}

inline std::string build_decompile_prompt(uint64_t func_addr,
                                          const std::vector<cfg_view::basic_block_t>& blocks)
{
	std::string prompt;
	prompt.reserve(16384);

	prompt += "You are the world's best x86-64 decompiler. Your task is to take the following "
	          "disassembled function and produce clean, compilable C/C++ pseudocode.\n\n";

	prompt += "RULES:\n";
	prompt += "1. Output ONLY the C/C++ function. No explanations, no markdown fences.\n";
	prompt += "2. Use descriptive variable names based on context (e.g., player_health, buffer_ptr).\n";
	prompt += "3. Reconstruct control flow: if/else, while, for, switch/case, do-while.\n";
	prompt += "4. Use stdint types: uint64_t, int32_t, uint8_t*, etc.\n";
	prompt += "5. Mark uncertain casts or type assumptions with /* inferred */ comments.\n";
	prompt += "6. Identify calling convention (fastcall: rcx,rdx,r8,r9 = first 4 args).\n";
	prompt += "7. Recognize common patterns: vtable dispatch, string operations, memory allocation.\n";
	prompt += "8. If a CALL target is known, use a descriptive name like sub_ADDR or the module export name.\n";
	prompt += "9. Preserve the semantic meaning. Do NOT skip any logic.\n\n";

	std::string module_info = resolve_module_symbols(func_addr);
	if (!module_info.empty()) {
		prompt += "CONTEXT:\n";
		prompt += module_info;
		prompt += "\n";
	}

	prompt += "CONTROL FLOW GRAPH:\n";
	prompt += build_block_text(blocks);

	std::string xrefs = build_xref_text(func_addr);
	if (!xrefs.empty()) {
		prompt += xrefs;
		prompt += "\n";
	}

	prompt += "\nDecompile the above function into C/C++ pseudocode now:\n";

	return prompt;
}

#ifdef __NT__
inline std::string build_deobfuscated_prompt(uint64_t func_addr,
                                              const emulation::emulation_result_t& emu_result,
                                              const emulation::vm_analysis_result_t& vm_analysis)
{
	std::string prompt;
	prompt.reserve(32768);

	prompt += "You are the world's best x86-64 decompiler specialized in deobfuscation. "
	          "The following is an EMULATION TRACE of a function that was protected by "
	          "code virtualization/obfuscation (e.g., VMProtect, Themida, custom VM). "
	          "The trace was captured at runtime from live process memory, so all "
	          "packing/encryption has been resolved. Junk instructions have been "
	          "pre-filtered by static analysis.\n\n";

	prompt += "RULES:\n";
	prompt += "1. Output ONLY the C/C++ function. No explanations, no markdown fences.\n";
	prompt += "2. Focus on the EFFECTIVE operations — ignore any remaining VM handler scaffolding.\n";
	prompt += "3. Use descriptive variable names based on register usage patterns.\n";
	prompt += "4. Reconstruct control flow from the instruction sequence and branch patterns.\n";
	prompt += "5. Use stdint types: uint64_t, int32_t, uint8_t*, etc.\n";
	prompt += "6. Windows x64 fastcall convention (rcx, rdx, r8, r9 = first 4 args).\n";
	prompt += "7. Pay attention to memory reads/writes — they reveal the actual data flow.\n";
	prompt += "8. Recognize common patterns: vtable dispatch, string operations, memory allocation.\n\n";

	std::string module_info = resolve_module_symbols(func_addr);
	if (!module_info.empty()) {
		prompt += "CONTEXT:\n";
		prompt += module_info;
		prompt += "\n";
	}

	prompt += "ANALYSIS SUMMARY:\n";
	char summary_buf[512];
	snprintf(summary_buf, sizeof(summary_buf),
	         "Total instructions executed: %u\n"
	         "Junk instructions filtered: %u\n"
	         "Effective instructions: %u\n",
	         vm_analysis.total_instructions,
	         vm_analysis.junk_instructions,
	         vm_analysis.effective_instructions);
	prompt += summary_buf;

	if (!vm_analysis.net_reg_changes.empty()) {
		prompt += "\nNET REGISTER CHANGES (before -> after):\n";
		for (auto& delta : vm_analysis.net_reg_changes) {
			char rbuf[128];
			snprintf(rbuf, sizeof(rbuf), "  %s: 0x%llX -> 0x%llX\n",
			         delta.name.c_str(),
			         static_cast<unsigned long long>(delta.before),
			         static_cast<unsigned long long>(delta.after));
			prompt += rbuf;
		}
	}

	if (!vm_analysis.net_mem_writes.empty()) {
		prompt += "\nNET MEMORY WRITES:\n";
		int mem_count = 0;
		for (auto& mw : vm_analysis.net_mem_writes) {
			if (mem_count >= 50) {
				prompt += "  ... (truncated)\n";
				break;
			}
			char mbuf[128];
			snprintf(mbuf, sizeof(mbuf), "  [0x%llX] size=%llu from RIP 0x%llX\n",
			         static_cast<unsigned long long>(mw.address),
			         static_cast<unsigned long long>(mw.size),
			         static_cast<unsigned long long>(mw.insn_address));
			prompt += mbuf;
			++mem_count;
		}
	}

	if (!vm_analysis.effective_ops.empty()) {
		prompt += "\nEFFECTIVE OPERATIONS (VM handler junk removed):\n";
		int op_count = 0;
		for (auto& op : vm_analysis.effective_ops) {
			if (op_count >= 500) {
				prompt += "  ... (truncated)\n";
				break;
			}
			prompt += "  ";
			prompt += op;
			prompt += "\n";
			++op_count;
		}
	} else if (!emu_result.trace.empty()) {
		prompt += "\nEXECUTION TRACE (sequential instructions):\n";
		int trace_count = 0;
		for (auto& t : emu_result.trace) {
			if (trace_count >= 500) {
				prompt += "  ... (truncated)\n";
				break;
			}
			char tbuf[256];
			snprintf(tbuf, sizeof(tbuf), "  0x%llX: %s",
			         static_cast<unsigned long long>(t.address), t.disasm.c_str());
			prompt += tbuf;
			prompt += "\n";
			++trace_count;
		}
	}

	if (!emu_result.mem_reads.empty()) {
		prompt += "\nMEMORY READS (data flow inputs):\n";
		int read_count = 0;
		for (auto& mr : emu_result.mem_reads) {
			if (read_count >= 30) {
				prompt += "  ... (truncated)\n";
				break;
			}
			char rbuf[128];
			snprintf(rbuf, sizeof(rbuf), "  [0x%llX] size=%llu read at RIP 0x%llX\n",
			         static_cast<unsigned long long>(mr.address),
			         static_cast<unsigned long long>(mr.size),
			         static_cast<unsigned long long>(mr.insn_address));
			prompt += rbuf;
			++read_count;
		}
	}

	prompt += "\nDecompile the above deobfuscated trace into clean C/C++ pseudocode now:\n";

	return prompt;
}
#endif

}

inline void decompile_function(uint64_t func_addr, const settings_sa_t& settings)
{
	if (g_state.decompiling.load()) return;

	{
		std::lock_guard<std::mutex> lk(g_state.mutex);
		auto cache_it = g_state.cache.find(func_addr);
		if (cache_it != g_state.cache.end()) {
			g_state.current = cache_it->second;
			g_state.streaming_text.clear();
			g_state.active = true;

			if (g_state.history_pos < 0 ||
			    g_state.history_pos >= static_cast<int>(g_state.history.size()) ||
			    g_state.history[g_state.history_pos].addr != func_addr) {
				if (g_state.history_pos + 1 < static_cast<int>(g_state.history.size()))
					g_state.history.erase(g_state.history.begin() + g_state.history_pos + 1,
					                      g_state.history.end());
				g_state.history.push_back({func_addr, g_state.current.function_name});
				g_state.history_pos = static_cast<int>(g_state.history.size()) - 1;
			}
			return;
		}
	}

	g_state.decompiling.store(true);
	g_state.cancel.store(false);

	{
		std::lock_guard<std::mutex> lk(g_state.mutex);
		g_state.streaming_text.clear();
		g_state.current = {};
		g_state.current.function_addr = func_addr;
		g_state.active = true;

		char name[64];
		snprintf(name, sizeof(name), "sub_%llX", static_cast<unsigned long long>(func_addr));
		g_state.current.function_name = name;

		if (g_state.history_pos < 0 ||
		    g_state.history_pos >= static_cast<int>(g_state.history.size()) ||
		    g_state.history[g_state.history_pos].addr != func_addr) {
			if (g_state.history_pos + 1 < static_cast<int>(g_state.history.size()))
				g_state.history.erase(g_state.history.begin() + g_state.history_pos + 1,
				                      g_state.history.end());
			g_state.history.push_back({func_addr, g_state.current.function_name});
			g_state.history_pos = static_cast<int>(g_state.history.size()) - 1;
		}
	}

	std::thread([func_addr, &settings]() {
		const size_t max_bytes = 0x10000;
		std::vector<uint8_t> mem;
		driver_bridge::read_memory(func_addr, max_bytes, mem);

		if (mem.empty()) {
			std::lock_guard<std::mutex> lk(g_state.mutex);
			g_state.current.is_error = true;
			g_state.current.error_text = "Failed to read memory at target address.";
			g_state.current.complete = true;
			g_state.decompiling.store(false);
			return;
		}

		std::vector<cfg_view::basic_block_t> blocks;
		{
			std::map<uint64_t, bool> leaders;
			leaders[func_addr] = true;

			struct decoded_t {
				AsmInstr ins;
				uint64_t branch_target = 0;
				bool has_target = false;
			};

			std::vector<decoded_t> all_insns;
			all_insns.reserve(4096);

			const uint8_t* data = mem.data();
			int sz = static_cast<int>(mem.size());
			int pos = 0;

			std::set<uint64_t> known_targets;
			known_targets.insert(func_addr);
			bool after_terminator = false;

			while (pos < sz && all_insns.size() < 4096) {
				uint64_t va = func_addr + pos;

				if (after_terminator) {
					if (known_targets.find(va) == known_targets.end()) {
						auto it = known_targets.upper_bound(va);
						if (it != known_targets.end() && *it < func_addr + max_bytes) {
							int pad_end = pos;
							bool is_padding = true;
							while (pad_end < sz && static_cast<uint64_t>(pad_end) < (*it - func_addr)) {
								if (data[pad_end] != 0xCC && data[pad_end] != 0x90 && data[pad_end] != 0x00) {
									is_padding = false;
									break;
								}
								pad_end++;
							}
							if (is_padding || *it - func_addr - pos <= 16) {
								pos = static_cast<int>(*it - func_addr);
								after_terminator = false;
								continue;
							}
						}
						break;
					}
					after_terminator = false;
				}

				int avail = (std::min)(sz - pos, 15);
				AsmInstr ins = zydis_decode_one(data + pos, avail, va);

				decoded_t d;
				d.ins = ins;

				if (ins.is_call || ins.is_branch) {
					if (ins.len == 5 && (data[pos] == 0xE8 || data[pos] == 0xE9)) {
						int32_t rel = 0;
						std::memcpy(&rel, data + pos + 1, 4);
						d.branch_target = va + ins.len + rel;
						d.has_target = true;
					} else if (ins.len == 2 && (data[pos] >= 0x70 && data[pos] <= 0x7F)) {
						int8_t rel = static_cast<int8_t>(data[pos + 1]);
						d.branch_target = va + ins.len + rel;
						d.has_target = true;
					} else if (ins.len == 6 && data[pos] == 0x0F && (data[pos+1] >= 0x80 && data[pos+1] <= 0x8F)) {
						int32_t rel = 0;
						std::memcpy(&rel, data + pos + 2, 4);
						d.branch_target = va + ins.len + rel;
						d.has_target = true;
					} else if (ins.len == 2 && data[pos] == 0xEB) {
						int8_t rel = static_cast<int8_t>(data[pos + 1]);
						d.branch_target = va + ins.len + rel;
						d.has_target = true;
					}
				}

				if (d.has_target && !d.ins.is_call) {
					if (d.branch_target >= func_addr && d.branch_target < func_addr + max_bytes)
						known_targets.insert(d.branch_target);
				}

				all_insns.push_back(d);
				pos += ins.len;

				if (ins.is_ret) {
					after_terminator = true;
				} else if (d.has_target && !d.ins.is_call) {
					bool is_uncond = (std::strcmp(d.ins.mnem, "jmp") == 0 || std::strcmp(d.ins.mnem, "JMP") == 0);
					if (is_uncond)
						after_terminator = true;
				}
			}

			for (auto& d2 : all_insns) {
				if (d2.has_target && !d2.ins.is_call) {
					leaders[d2.branch_target] = true;
					leaders[d2.ins.addr + d2.ins.len] = true;
				}
				if (d2.ins.is_ret) leaders[d2.ins.addr + d2.ins.len] = true;
			}

			std::map<uint64_t, int> addr_to_block;
			int cur_block = -1;

			for (auto& d2 : all_insns) {
				if (leaders.count(d2.ins.addr)) {
					auto it = addr_to_block.find(d2.ins.addr);
					if (it != addr_to_block.end()) {
						cur_block = it->second;
					} else {
						cur_block = static_cast<int>(blocks.size());
						blocks.emplace_back();
						blocks.back().start_addr = d2.ins.addr;
						addr_to_block[d2.ins.addr] = cur_block;
					}
					if (d2.ins.addr == func_addr)
						blocks[cur_block].is_entry = true;
				}
				if (cur_block < 0) {
					cur_block = static_cast<int>(blocks.size());
					blocks.emplace_back();
					blocks.back().start_addr = d2.ins.addr;
					addr_to_block[d2.ins.addr] = cur_block;
				}

				cfg_view::instruction_line_t line;
				line.addr = d2.ins.addr;
				char buf[192];
				snprintf(buf, sizeof(buf), "%s %s", d2.ins.mnem, d2.ins.ops);
				line.text = buf;
				blocks[cur_block].instructions.push_back(std::move(line));
				blocks[cur_block].end_addr = d2.ins.addr + d2.ins.len;

				if (d2.ins.is_ret) continue;

				if (d2.has_target && !d2.ins.is_call) {
					auto it_t = addr_to_block.find(d2.branch_target);
					if (it_t != addr_to_block.end()) {
						blocks[cur_block].successors.push_back(it_t->second);
					} else {
						int tidx = static_cast<int>(blocks.size());
						blocks.emplace_back();
						blocks.back().start_addr = d2.branch_target;
						addr_to_block[d2.branch_target] = tidx;
						blocks[cur_block].successors.push_back(tidx);
					}

					bool is_uncond = (std::strcmp(d2.ins.mnem, "jmp") == 0 ||
					                  std::strcmp(d2.ins.mnem, "JMP") == 0);
					if (!is_uncond) {
						uint64_t fall = d2.ins.addr + d2.ins.len;
						auto it_f = addr_to_block.find(fall);
						if (it_f != addr_to_block.end()) {
							blocks[cur_block].successors.push_back(it_f->second);
						} else {
							int fidx = static_cast<int>(blocks.size());
							blocks.emplace_back();
							blocks.back().start_addr = fall;
							addr_to_block[fall] = fidx;
							blocks[cur_block].successors.push_back(fidx);
						}
					}
					cur_block = -1;
				}
			}
		}

		if (blocks.empty()) {
			std::lock_guard<std::mutex> lk(g_state.mutex);
			g_state.current.is_error = true;
			g_state.current.error_text = "Could not build CFG — no instructions decoded.";
			g_state.current.complete = true;
			g_state.decompiling.store(false);
			return;
		}

		for (auto& blk : blocks) {
			for (auto& ins : blk.instructions) {
				if (ins.text.find("call") != std::string::npos ||
				    ins.text.find("CALL") != std::string::npos) {
					char target_str[64];
					uint64_t target = 0;
					if (sscanf_s(ins.text.c_str() + ins.text.find("call") + 4, " %llx", &target) == 1 ||
					    sscanf_s(ins.text.c_str() + ins.text.find("call") + 4, " 0x%llx", &target) == 1) {
						snprintf(target_str, sizeof(target_str), "sub_%llX",
						         static_cast<unsigned long long>(target));
						std::lock_guard<std::mutex> lk(g_state.mutex);
						bool found = false;
						for (auto& c : g_state.current.callees) {
							if (c == target_str) { found = true; break; }
						}
						if (!found) g_state.current.callees.push_back(target_str);
					}
				}
			}
		}

		if (g_state.cancel.load()) {
			g_state.decompiling.store(false);
			return;
		}

		detail::import_lookup_t lookup = detail::build_import_lookup(func_addr);
		detail::annotate_instructions(blocks, mem.data(), func_addr, mem.size(), lookup);

		std::string prompt = detail::build_decompile_prompt(func_addr, blocks);

		std::string system_prompt =
			"You are a world-class binary reverse engineering decompiler. "
			"You receive x86-64 assembly organized into basic blocks with control flow edges. "
			"You output clean, compilable C/C++ pseudocode. Use Windows x64 fastcall convention "
			"(rcx, rdx, r8, r9 = first 4 integer/pointer args). "
			"Use stdint.h types. Reconstruct all control flow structures. "
			"Output ONLY the function code, no markdown fences, no explanations before or after.";

		auto ai = std::make_unique<standalone_ai_client_t>(settings);
		if (!ai->is_available()) {
			std::lock_guard<std::mutex> lk(g_state.mutex);
			g_state.current.is_error = true;
			g_state.current.error_text = "AI provider not configured or unavailable.";
			g_state.current.complete = true;
			g_state.decompiling.store(false);
			return;
		}

		std::vector<std::pair<std::string, std::string>> history;
		std::string result = ai->chat_blocking(
			prompt,
			history,
			[](const std::string& chunk) {
				std::lock_guard<std::mutex> lk(g_state.mutex);
				g_state.streaming_text += chunk;
			},
			[](const std::string&) -> bool {
				return g_state.cancel.load();
			}
		);

		{
			std::lock_guard<std::mutex> lk(g_state.mutex);
			if (!result.empty()) {
				g_state.current.pseudocode = result;
			} else {
				g_state.current.pseudocode = g_state.streaming_text;
			}

			size_t fn_start = g_state.current.pseudocode.find('(');
			if (fn_start != std::string::npos) {
				size_t fn_end = g_state.current.pseudocode.find(')', fn_start);
				if (fn_end != std::string::npos) {
					g_state.current.parameters = g_state.current.pseudocode.substr(fn_start + 1, fn_end - fn_start - 1);
				}
			}

			g_state.current.complete = true;
			g_state.streaming_text.clear();
			if (!g_state.current.is_error) {
				g_state.cache[func_addr] = g_state.current;
				detail::save_cache_entry_to_disk(func_addr, g_state.current);
			}
		}

		g_state.decompiling.store(false);
	}).detach();
}

inline void cancel_decompile()
{
	g_state.cancel.store(true);
}

#ifdef __NT__
inline void decompile_with_deobfuscation(uint64_t func_addr, const settings_sa_t& settings)
{
	if (g_state.decompiling.load() || g_state.emulating.load()) return;

	g_state.emulating.store(true);
	g_state.decompiling.store(true);
	g_state.cancel.store(false);
	g_state.emulation_progress.store(0.f);

	{
		std::lock_guard<std::mutex> lk(g_state.mutex);
		g_state.streaming_text.clear();
		g_state.current = {};
		g_state.current.function_addr = func_addr;
		g_state.active = true;

		char name[64];
		snprintf(name, sizeof(name), "sub_%llX", static_cast<unsigned long long>(func_addr));
		g_state.current.function_name = name;

		if (g_state.history_pos < 0 ||
		    g_state.history_pos >= static_cast<int>(g_state.history.size()) ||
		    g_state.history[g_state.history_pos].addr != func_addr) {
			if (g_state.history_pos + 1 < static_cast<int>(g_state.history.size()))
				g_state.history.erase(g_state.history.begin() + g_state.history_pos + 1,
				                      g_state.history.end());
			g_state.history.push_back({func_addr, g_state.current.function_name});
			g_state.history_pos = static_cast<int>(g_state.history.size()) - 1;
		}
	}

	std::thread([func_addr, &settings]() {
		uint32_t pid = driver_bridge::attached_pid();
		if (pid == 0) {
			std::lock_guard<std::mutex> lk(g_state.mutex);
			g_state.current.is_error = true;
			g_state.current.error_text = "No process attached. Attach to a process first.";
			g_state.current.complete = true;
			g_state.emulating.store(false);
			g_state.decompiling.store(false);
			return;
		}

		auto threads = driver_bridge::enumerate_threads();
		if (threads.empty()) {
			std::lock_guard<std::mutex> lk(g_state.mutex);
			g_state.current.is_error = true;
			g_state.current.error_text = "No threads found in target process.";
			g_state.current.complete = true;
			g_state.emulating.store(false);
			g_state.decompiling.store(false);
			return;
		}

		uint32_t tid = threads[0].tid;

		g_state.emulation_progress.store(0.1f);

		{
			std::lock_guard<std::mutex> lk(g_state.mutex);
			g_state.streaming_text = "Taking process snapshot...\n";
		}

		emulation::process_snapshot_t snapshot = emulation::driver_snapshot(pid, tid, func_addr, 0x200000);

		if (!snapshot.success) {
			std::lock_guard<std::mutex> lk(g_state.mutex);
			g_state.current.is_error = true;
			g_state.current.error_text = "Snapshot failed: " + snapshot.error;
			g_state.current.complete = true;
			g_state.emulating.store(false);
			g_state.decompiling.store(false);
			return;
		}

		if (g_state.cancel.load()) {
			g_state.emulating.store(false);
			g_state.decompiling.store(false);
			return;
		}

		g_state.emulation_progress.store(0.3f);

		{
			std::lock_guard<std::mutex> lk(g_state.mutex);
			g_state.streaming_text = "Emulating function (max 50000 instructions)...\n";
		}

		emulation::emulation_config_t emu_cfg;
		emu_cfg.start_address = func_addr;
		emu_cfg.max_instructions = 50000;
		emu_cfg.max_trace_entries = 10000;
		emu_cfg.record_mem_reads = true;
		emu_cfg.record_mem_writes = true;
		emu_cfg.record_registers = true;
		emu_cfg.analyze_effective_ops = true;
		emu_cfg.timeout_us = 15000000;

		emulation::emulation_result_t emu_result = emulation::emulate_from_snapshot(snapshot, emu_cfg);

		g_state.emulation_progress.store(0.6f);

		if (!emu_result.success && emu_result.trace.empty()) {
			std::lock_guard<std::mutex> lk(g_state.mutex);
			g_state.current.is_error = true;
			g_state.current.error_text = "Emulation failed: " + emu_result.error;
			g_state.current.complete = true;
			g_state.emulating.store(false);
			g_state.decompiling.store(false);
			return;
		}

		if (g_state.cancel.load()) {
			g_state.emulating.store(false);
			g_state.decompiling.store(false);
			return;
		}

		{
			std::lock_guard<std::mutex> lk(g_state.mutex);
			char progress_msg[256];
			snprintf(progress_msg, sizeof(progress_msg),
			         "Emulation complete: %u instructions traced.\nAnalyzing VM handlers...\n",
			         emu_result.total_instructions);
			g_state.streaming_text = progress_msg;
		}

		emulation::vm_analysis_result_t vm_analysis = emulation::analyze_vm_trace(emu_result);

		g_state.emulation_progress.store(0.8f);

		{
			std::lock_guard<std::mutex> lk(g_state.mutex);
			char analysis_msg[512];
			snprintf(analysis_msg, sizeof(analysis_msg),
			         "Emulation: %u instructions, %u junk filtered, %u effective ops.\n"
			         "Sending to AI for decompilation...\n",
			         vm_analysis.total_instructions,
			         vm_analysis.junk_instructions,
			         vm_analysis.effective_instructions);
			g_state.streaming_text = analysis_msg;
		}

		g_state.emulating.store(false);
		g_state.emulation_progress.store(1.f);

		if (g_state.cancel.load()) {
			g_state.decompiling.store(false);
			return;
		}

		std::string prompt = detail::build_deobfuscated_prompt(func_addr, emu_result, vm_analysis);

		std::string system_prompt =
			"You are a world-class binary reverse engineering decompiler specialized in "
			"deobfuscating virtualized/packed code. You receive emulation traces captured from "
			"live process memory after VM protection has been resolved at runtime. "
			"Junk instructions have been pre-filtered. You output clean, compilable C/C++ pseudocode. "
			"Use Windows x64 fastcall convention (rcx, rdx, r8, r9 = first 4 args). "
			"Use stdint.h types. Reconstruct all control flow structures. "
			"Output ONLY the function code, no markdown fences, no explanations before or after.";

		auto ai = std::make_unique<standalone_ai_client_t>(settings);
		if (!ai->is_available()) {
			std::lock_guard<std::mutex> lk(g_state.mutex);
			g_state.current.is_error = true;
			g_state.current.error_text = "AI provider not configured or unavailable.";
			g_state.current.complete = true;
			g_state.decompiling.store(false);
			return;
		}

		{
			std::lock_guard<std::mutex> lk(g_state.mutex);
			g_state.streaming_text.clear();
		}

		std::vector<std::pair<std::string, std::string>> history;
		std::string result = ai->chat_blocking(
			prompt,
			history,
			[](const std::string& chunk) {
				std::lock_guard<std::mutex> lk(g_state.mutex);
				g_state.streaming_text += chunk;
			},
			[](const std::string&) -> bool {
				return g_state.cancel.load();
			}
		);

		{
			std::lock_guard<std::mutex> lk(g_state.mutex);
			if (!result.empty()) {
				g_state.current.pseudocode = result;
			} else {
				g_state.current.pseudocode = g_state.streaming_text;
			}

			size_t fn_start = g_state.current.pseudocode.find('(');
			if (fn_start != std::string::npos) {
				size_t fn_end = g_state.current.pseudocode.find(')', fn_start);
				if (fn_end != std::string::npos) {
					g_state.current.parameters = g_state.current.pseudocode.substr(fn_start + 1, fn_end - fn_start - 1);
				}
			}

			for (auto& t : emu_result.trace) {
				if (!t.disasm.empty() && (t.disasm.find("call") != std::string::npos || t.disasm.find("CALL") != std::string::npos)) {
					char target_str[64];
					snprintf(target_str, sizeof(target_str), "sub_%llX", static_cast<unsigned long long>(t.address));
					bool found = false;
					for (auto& c : g_state.current.callees) {
						if (c == target_str) { found = true; break; }
					}
					if (!found) g_state.current.callees.push_back(target_str);
				}
			}

			g_state.current.complete = true;
			g_state.streaming_text.clear();
			if (!g_state.current.is_error) {
				g_state.cache[func_addr] = g_state.current;
			}
		}

		g_state.decompiling.store(false);
	}).detach();
}
#endif

inline void navigate_back()
{
	if (g_state.history_pos > 0) {
		g_state.history_pos--;
		auto& entry = g_state.history[g_state.history_pos];
		decompile_function(entry.addr, g_sa_settings);
	}
}

inline void navigate_forward()
{
	if (g_state.history_pos + 1 < static_cast<int>(g_state.history.size())) {
		g_state.history_pos++;
		auto& entry = g_state.history[g_state.history_pos];
		decompile_function(entry.addr, g_sa_settings);
	}
}

inline void clear_cache()
{
	std::lock_guard<std::mutex> lk(g_state.mutex);
	g_state.cache.clear();
}

inline size_t cache_size()
{
	std::lock_guard<std::mutex> lk(g_state.mutex);
	return g_state.cache.size();
}

inline void batch_decompile(const std::vector<uint64_t>& addresses)
{
	if (g_state.batch_running.load() || g_state.decompiling.load()) return;

	g_state.batch_running.store(true);
	g_state.cancel.store(false);
	g_state.batch_total.store(static_cast<int>(addresses.size()));
	g_state.batch_done.store(0);

	{
		std::lock_guard<std::mutex> lk(g_state.mutex);
		g_state.batch_queue = addresses;
	}

	std::thread([addresses]() {
		auto& settings = g_sa_settings;

		for (int i = 0; i < static_cast<int>(addresses.size()); ++i) {
			if (g_state.cancel.load()) break;

			uint64_t addr = addresses[i];

			{
				std::lock_guard<std::mutex> lk(g_state.mutex);
				if (g_state.cache.count(addr)) {
					g_state.batch_done.store(i + 1);
					continue;
				}
			}

			g_state.decompiling.store(true);

			{
				std::lock_guard<std::mutex> lk(g_state.mutex);
				g_state.streaming_text.clear();
				g_state.current = {};
				g_state.current.function_addr = addr;
				g_state.active = true;

				char name[64];
				snprintf(name, sizeof(name), "sub_%llX", static_cast<unsigned long long>(addr));
				g_state.current.function_name = name;
			}

			const size_t max_bytes = 0x10000;
			std::vector<uint8_t> mem;
			driver_bridge::read_memory(addr, max_bytes, mem);

			if (mem.empty()) {
				std::lock_guard<std::mutex> lk(g_state.mutex);
				g_state.current.is_error = true;
				g_state.current.error_text = "Failed to read memory.";
				g_state.current.complete = true;
				g_state.batch_done.store(i + 1);
				g_state.decompiling.store(false);
				continue;
			}

			std::vector<cfg_view::basic_block_t> blocks;
			{
				std::map<uint64_t, bool> leaders;
				leaders[addr] = true;

				struct decoded_t { AsmInstr ins; uint64_t branch_target = 0; bool has_target = false; };
				std::vector<decoded_t> all_insns;
				all_insns.reserve(4096);

				const uint8_t* data = mem.data();
				int sz = static_cast<int>(mem.size());
				int pos = 0;

				std::set<uint64_t> known_targets;
				known_targets.insert(addr);
				bool after_terminator = false;

				while (pos < sz && all_insns.size() < 4096) {
					uint64_t va = addr + pos;

					if (after_terminator) {
						if (known_targets.find(va) == known_targets.end()) {
							auto it = known_targets.upper_bound(va);
							if (it != known_targets.end() && *it < addr + max_bytes) {
								int pad_end = pos;
								bool is_padding = true;
								while (pad_end < sz && static_cast<uint64_t>(pad_end) < (*it - addr)) {
									if (data[pad_end] != 0xCC && data[pad_end] != 0x90 && data[pad_end] != 0x00) {
										is_padding = false;
										break;
									}
									pad_end++;
								}
								if (is_padding || *it - addr - pos <= 16) {
									pos = static_cast<int>(*it - addr);
									after_terminator = false;
									continue;
								}
							}
							break;
						}
						after_terminator = false;
					}

					int avail = (std::min)(sz - pos, 15);
					AsmInstr ins = zydis_decode_one(data + pos, avail, va);

					decoded_t d; d.ins = ins;
					if (ins.is_call || ins.is_branch) {
						if (ins.len == 5 && (data[pos] == 0xE8 || data[pos] == 0xE9)) {
							int32_t rel = 0; std::memcpy(&rel, data + pos + 1, 4);
							d.branch_target = va + ins.len + rel; d.has_target = true;
						} else if (ins.len == 2 && (data[pos] >= 0x70 && data[pos] <= 0x7F)) {
							int8_t rel = static_cast<int8_t>(data[pos + 1]);
							d.branch_target = va + ins.len + rel; d.has_target = true;
						} else if (ins.len == 6 && data[pos] == 0x0F && (data[pos+1] >= 0x80 && data[pos+1] <= 0x8F)) {
							int32_t rel = 0; std::memcpy(&rel, data + pos + 2, 4);
							d.branch_target = va + ins.len + rel; d.has_target = true;
						} else if (ins.len == 2 && data[pos] == 0xEB) {
							int8_t rel = static_cast<int8_t>(data[pos + 1]);
							d.branch_target = va + ins.len + rel; d.has_target = true;
						}
					}

					if (d.has_target && !d.ins.is_call) {
						if (d.branch_target >= addr && d.branch_target < addr + max_bytes)
							known_targets.insert(d.branch_target);
					}

					all_insns.push_back(d);
					pos += ins.len;

					if (ins.is_ret) {
						after_terminator = true;
					} else if (d.has_target && !d.ins.is_call) {
						bool is_uncond = (std::strcmp(d.ins.mnem, "jmp") == 0 || std::strcmp(d.ins.mnem, "JMP") == 0);
						if (is_uncond)
							after_terminator = true;
					}
				}

				for (auto& d2 : all_insns) {
					if (d2.has_target && !d2.ins.is_call) {
						leaders[d2.branch_target] = true;
						leaders[d2.ins.addr + d2.ins.len] = true;
					}
					if (d2.ins.is_ret) leaders[d2.ins.addr + d2.ins.len] = true;
				}

				std::map<uint64_t, int> addr_to_block;
				int cur_block = -1;

				for (auto& d2 : all_insns) {
					if (leaders.count(d2.ins.addr)) {
						auto it = addr_to_block.find(d2.ins.addr);
						if (it != addr_to_block.end()) cur_block = it->second;
						else {
							cur_block = static_cast<int>(blocks.size());
							blocks.emplace_back();
							blocks.back().start_addr = d2.ins.addr;
							addr_to_block[d2.ins.addr] = cur_block;
						}
						if (d2.ins.addr == addr) blocks[cur_block].is_entry = true;
					}
					if (cur_block < 0) {
						cur_block = static_cast<int>(blocks.size());
						blocks.emplace_back();
						blocks.back().start_addr = d2.ins.addr;
						addr_to_block[d2.ins.addr] = cur_block;
					}

					cfg_view::instruction_line_t line;
					line.addr = d2.ins.addr;
					char buf[192];
					snprintf(buf, sizeof(buf), "%s %s", d2.ins.mnem, d2.ins.ops);
					line.text = buf;
					blocks[cur_block].instructions.push_back(std::move(line));
					blocks[cur_block].end_addr = d2.ins.addr + d2.ins.len;

					if (d2.ins.is_ret) continue;
					if (d2.has_target && !d2.ins.is_call) {
						auto it_t = addr_to_block.find(d2.branch_target);
						if (it_t != addr_to_block.end())
							blocks[cur_block].successors.push_back(it_t->second);
						else {
							int tidx = static_cast<int>(blocks.size());
							blocks.emplace_back();
							blocks.back().start_addr = d2.branch_target;
							addr_to_block[d2.branch_target] = tidx;
							blocks[cur_block].successors.push_back(tidx);
						}
						bool is_uncond = (std::strcmp(d2.ins.mnem, "jmp") == 0 || std::strcmp(d2.ins.mnem, "JMP") == 0);
						if (!is_uncond) {
							uint64_t fall = d2.ins.addr + d2.ins.len;
							auto it_f = addr_to_block.find(fall);
							if (it_f != addr_to_block.end())
								blocks[cur_block].successors.push_back(it_f->second);
							else {
								int fidx = static_cast<int>(blocks.size());
								blocks.emplace_back();
								blocks.back().start_addr = fall;
								addr_to_block[fall] = fidx;
								blocks[cur_block].successors.push_back(fidx);
							}
						}
						cur_block = -1;
					}
				}
			}

			if (blocks.empty()) {
				std::lock_guard<std::mutex> lk(g_state.mutex);
				g_state.current.is_error = true;
				g_state.current.error_text = "No CFG blocks.";
				g_state.current.complete = true;
				g_state.batch_done.store(i + 1);
				g_state.decompiling.store(false);
				continue;
			}

			for (auto& blk : blocks) {
				for (auto& ins : blk.instructions) {
					if (ins.text.find("call") != std::string::npos || ins.text.find("CALL") != std::string::npos) {
						uint64_t target = 0;
						if (sscanf_s(ins.text.c_str() + ins.text.find("call") + 4, " %llx", &target) == 1 ||
						    sscanf_s(ins.text.c_str() + ins.text.find("call") + 4, " 0x%llx", &target) == 1) {
							char target_str[64];
							snprintf(target_str, sizeof(target_str), "sub_%llX", static_cast<unsigned long long>(target));
							std::lock_guard<std::mutex> lk(g_state.mutex);
							bool found = false;
							for (auto& c : g_state.current.callees) { if (c == target_str) { found = true; break; } }
							if (!found) g_state.current.callees.push_back(target_str);
						}
					}
				}
			}

			if (g_state.cancel.load()) break;

			detail::import_lookup_t batch_lookup = detail::build_import_lookup(addr);
			detail::annotate_instructions(blocks, mem.data(), addr, mem.size(), batch_lookup);

			std::string prompt = detail::build_decompile_prompt(addr, blocks);

			auto ai = std::make_unique<standalone_ai_client_t>(settings);
			if (!ai->is_available()) {
				std::lock_guard<std::mutex> lk(g_state.mutex);
				g_state.current.is_error = true;
				g_state.current.error_text = "AI unavailable.";
				g_state.current.complete = true;
				g_state.batch_done.store(i + 1);
				g_state.decompiling.store(false);
				continue;
			}

			std::vector<std::pair<std::string, std::string>> history;
			std::string result = ai->chat_blocking(
				prompt, history,
				[](const std::string& chunk) {
					std::lock_guard<std::mutex> lk(g_state.mutex);
					g_state.streaming_text += chunk;
				},
				[](const std::string&) -> bool { return g_state.cancel.load(); }
			);

			{
				std::lock_guard<std::mutex> lk(g_state.mutex);
				if (!result.empty()) g_state.current.pseudocode = result;
				else g_state.current.pseudocode = g_state.streaming_text;

				size_t fn_start = g_state.current.pseudocode.find('(');
				if (fn_start != std::string::npos) {
					size_t fn_end = g_state.current.pseudocode.find(')', fn_start);
					if (fn_end != std::string::npos)
						g_state.current.parameters = g_state.current.pseudocode.substr(fn_start + 1, fn_end - fn_start - 1);
				}

				g_state.current.complete = true;
				g_state.streaming_text.clear();

				if (!g_state.current.is_error) {
					g_state.cache[addr] = g_state.current;
					detail::save_cache_entry_to_disk(addr, g_state.current);
				}
			}

			g_state.decompiling.store(false);
			g_state.batch_done.store(i + 1);
		}

		g_state.batch_running.store(false);
		g_state.decompiling.store(false);
	}).detach();
}

inline void decompile_function_native(uint64_t func_addr) {
	if (g_state.decompiling.load())
		return;

	// Check cache first — instant return if we already have it
	{
		std::lock_guard<std::mutex> lk(g_state.mutex);
		auto cache_it = g_state.cache.find(func_addr);
		if (cache_it != g_state.cache.end()) {
			g_state.current = cache_it->second;
			g_state.streaming_text.clear();
			g_state.active = true;
			if (g_state.history_pos < 0 ||
			    g_state.history_pos >= static_cast<int>(g_state.history.size()) ||
			    g_state.history[g_state.history_pos].addr != func_addr) {
				if (g_state.history_pos + 1 < static_cast<int>(g_state.history.size()))
					g_state.history.erase(g_state.history.begin() + g_state.history_pos + 1,
					                      g_state.history.end());
				g_state.history.push_back({func_addr, g_state.current.function_name});
				g_state.history_pos = static_cast<int>(g_state.history.size()) - 1;
			}
			return;
		}
	}

	g_state.decompiling.store(true);
	g_state.cancel.store(false);
	g_state.active_mode = decompile_mode_t::native_ghidra;

	{
		std::lock_guard<std::mutex> lk(g_state.mutex);
		g_state.current = {};
		g_state.current.function_addr = func_addr;
		g_state.streaming_text.clear();
		g_state.active = true;

		char name[64];
		snprintf(name, sizeof(name), "sub_%llX", static_cast<unsigned long long>(func_addr));
		g_state.current.function_name = name;
	}

	std::thread([func_addr]() {
		// WHY: Pre-read 256KB in one driver call instead of letting Ghidra's
		// loadFill make hundreds of individual IOCTLs.  This is the single
		// biggest change that eliminates the UI freeze.
		constexpr size_t PREREAD_SIZE = 0x40000;  // 256 KB
		std::vector<uint8_t> mem;
		driver_bridge::read_memory(func_addr, PREREAD_SIZE, mem);

		if (mem.empty()) {
			std::lock_guard<std::mutex> lk(g_state.mutex);
			g_state.current.is_error = true;
			g_state.current.error_text = "failed to read memory at target address";
			g_state.current.complete = true;
			g_state.decompiling.store(false);
			return;
		}

		// WHY: decompile_buffer() creates a temporary Architecture + BufferLoader
		// with no global mutex held.  This means the render thread is never blocked.
		auto ghidra_result = ghidra_decompiler::decompile_buffer(
			mem.data(), mem.size(), func_addr, func_addr, &g_state.cancel);

		if (g_state.cancel.load()) {
			std::lock_guard<std::mutex> lk(g_state.mutex);
			g_state.current.is_error = true;
			g_state.current.error_text = "decompilation cancelled";
			g_state.current.complete = true;
			g_state.decompiling.store(false);
			return;
		}

		std::lock_guard<std::mutex> lk(g_state.mutex);
		g_state.current.function_addr = func_addr;
		g_state.current.function_name = ghidra_result.function_name;
		g_state.current.pseudocode = ghidra_result.pseudocode;
		g_state.current.complete = ghidra_result.complete;
		g_state.current.is_error = ghidra_result.is_error;
		g_state.current.error_text = ghidra_result.error_text;
		g_state.streaming_text = ghidra_result.pseudocode;

		if (!g_state.current.is_error) {
			g_state.cache[func_addr] = g_state.current;
			detail::save_cache_entry_to_disk(func_addr, g_state.current);
		}

		if (g_state.history_pos < 0 ||
		    g_state.history_pos >= static_cast<int>(g_state.history.size()) ||
		    g_state.history[g_state.history_pos].addr != func_addr) {
			if (g_state.history_pos + 1 < static_cast<int>(g_state.history.size()))
				g_state.history.erase(g_state.history.begin() + g_state.history_pos + 1,
				                      g_state.history.end());
			g_state.history.push_back({func_addr, g_state.current.function_name});
			g_state.history_pos = static_cast<int>(g_state.history.size()) - 1;
		}
		g_state.decompiling.store(false);
	}).detach();
}

inline void decompile_function_hybrid(uint64_t func_addr, const settings_sa_t& settings) {
	if (g_state.decompiling.load())
		return;

	g_state.decompiling.store(true);
	g_state.cancel.store(false);
	g_state.active_mode = decompile_mode_t::hybrid;

	{
		std::lock_guard<std::mutex> lk(g_state.mutex);
		g_state.current = {};
		g_state.current.function_addr = func_addr;
		g_state.streaming_text.clear();
		g_state.active = true;
	}

	std::thread([func_addr, settings]() {
		// WHY: Pre-read memory once; used by both the Ghidra decompilation
		// (via decompile_buffer) and the CFG annotation (via the raw bytes).
		constexpr size_t PREREAD_SIZE = 0x40000;  // 256 KB
		std::vector<uint8_t> mem;
		driver_bridge::read_memory(func_addr, PREREAD_SIZE, mem);

		if (mem.empty()) {
			std::lock_guard<std::mutex> lk(g_state.mutex);
			g_state.current.is_error = true;
			g_state.current.error_text = "failed to read memory at target address";
			g_state.current.complete = true;
			g_state.decompiling.store(false);
			return;
		}

		auto ghidra_result = ghidra_decompiler::decompile_buffer(
			mem.data(), mem.size(), func_addr, func_addr, &g_state.cancel);

		if (ghidra_result.is_error) {
			std::lock_guard<std::mutex> lk(g_state.mutex);
			g_state.current.is_error = true;
			g_state.current.error_text = "ghidra: " + ghidra_result.error_text;
			g_state.current.complete = true;
			g_state.decompiling.store(false);
			return;
		}

		{
			std::lock_guard<std::mutex> lk(g_state.mutex);
			g_state.current.pseudocode = ghidra_result.pseudocode;
			g_state.current.function_name = ghidra_result.function_name;
			g_state.streaming_text = ghidra_result.pseudocode;
		}

		std::string ghidra_code = ghidra_result.pseudocode;

		cfg_view::build_cfg(func_addr);
		while (cfg_view::g_state.building.load())
			std::this_thread::sleep_for(std::chrono::milliseconds(5));
		std::vector<cfg_view::basic_block_t> blocks;
		{
			std::lock_guard<std::mutex> lk(cfg_view::g_state.mutex);
			blocks = cfg_view::g_state.blocks;
		}
		std::string block_text = detail::build_block_text(blocks);
		std::string xref_text = detail::build_xref_text(func_addr);
		std::string mod_text = detail::resolve_module_symbols(func_addr);
		auto import_lookup = detail::build_import_lookup(func_addr);
		if (!mem.empty())
			detail::annotate_instructions(blocks, mem.data(), func_addr, mem.size(), import_lookup);
		std::string annotated = detail::build_block_text(blocks);

		std::string system_prompt =
			"You are an expert reverse engineer. The user provides Ghidra's raw decompiler output "
			"for a function, along with disassembly and cross-reference context. "
			"Your task is to IMPROVE the Ghidra output by:\n"
			"1. Renaming variables and parameters to meaningful names based on usage context\n"
			"2. Adding brief inline comments for complex logic\n"
			"3. Fixing type casts and pointer arithmetic to be more readable\n"
			"4. Identifying common patterns (vtable dispatch, string operations, memory allocation)\n"
			"Output ONLY the improved C pseudocode. No explanations.";

		std::string user_prompt;
		user_prompt.reserve(ghidra_code.size() + annotated.size() + xref_text.size() + mod_text.size() + 512);
		user_prompt += "## Ghidra Decompiler Output\n```c\n";
		user_prompt += ghidra_code;
		user_prompt += "\n```\n\n";
		user_prompt += "## Disassembly Context\n```\n";
		user_prompt += annotated;
		user_prompt += "\n```\n\n";
		if (!xref_text.empty()) {
			user_prompt += "## Cross References\n```\n";
			user_prompt += xref_text;
			user_prompt += "\n```\n\n";
		}
		if (!mod_text.empty()) {
			user_prompt += "## Module Info\n";
			user_prompt += mod_text;
			user_prompt += "\n\n";
		}
		user_prompt += "Improve this decompiled function. Output only the improved C pseudocode.";

		std::string full_prompt = system_prompt + "\n\n---\n\n" + user_prompt;
		auto ai = std::make_unique<standalone_ai_client_t>(settings);
		std::vector<std::pair<std::string, std::string>> history;
		std::string ai_result = ai->chat_blocking(
			full_prompt, history,
			[](const std::string& chunk) {
				std::lock_guard<std::mutex> lk(g_state.mutex);
				g_state.streaming_text += chunk;
			},
			[](const std::string&) -> bool { return g_state.cancel.load(); }
		);

		{
			std::lock_guard<std::mutex> lk(g_state.mutex);
			std::string full = ai_result;
			auto fence_start = full.find("```");
			if (fence_start != std::string::npos) {
				auto nl = full.find('\n', fence_start);
				if (nl != std::string::npos) {
					auto fence_end = full.find("```", nl);
					if (fence_end != std::string::npos)
						full = full.substr(nl + 1, fence_end - nl - 1);
					else
						full = full.substr(nl + 1);
				}
			}

			if (full.empty()) {
				g_state.current.is_error = true;
				g_state.current.error_text = "AI returned empty result";
				g_state.current.complete = true;
				g_state.decompiling.store(false);
				return;
			}

			g_state.current.pseudocode = full;
			g_state.current.function_addr = func_addr;
			g_state.current.complete = true;
			g_state.streaming_text = full;

			g_state.cache[func_addr] = g_state.current;
			detail::save_cache_entry_to_disk(func_addr, g_state.current);

			if (g_state.history_pos < 0 ||
			    g_state.history_pos >= static_cast<int>(g_state.history.size()) ||
			    g_state.history[g_state.history_pos].addr != func_addr) {
				if (g_state.history_pos + 1 < static_cast<int>(g_state.history.size()))
					g_state.history.erase(g_state.history.begin() + g_state.history_pos + 1,
					                      g_state.history.end());
				g_state.history.push_back({func_addr, g_state.current.function_name});
				g_state.history_pos = static_cast<int>(g_state.history.size()) - 1;
			}
			g_state.decompiling.store(false);
		}
	}).detach();
}

// ---------------------------------------------------------------------------
//  batch_decompile_native() — bulk Ghidra decompilation using thread pool
//  WHY: The old batch_decompile() used AI (network-bound, $$$ per function).
//       This new function uses the Ghidra thread pool to decompile hundreds
//       of functions per second locally.  It pre-reads the module memory
//       once from the driver, then distributes work across all CPU cores.
// ---------------------------------------------------------------------------

inline void batch_decompile_native(const std::vector<uint64_t>& addresses) {
	if (g_state.batch_running.load() || g_state.decompiling.load()) return;

	g_state.batch_running.store(true);
	g_state.cancel.store(false);
	g_state.batch_total.store(static_cast<int>(addresses.size()));
	g_state.batch_done.store(0);

	{
		std::lock_guard<std::mutex> lk(g_state.mutex);
		g_state.batch_queue = addresses;
	}

	std::thread([addresses]() {
		if (addresses.empty()) {
			g_state.batch_running.store(false);
			return;
		}

		// Find the memory range spanning all requested addresses
		uint64_t min_addr = *std::min_element(addresses.begin(), addresses.end());
		uint64_t max_addr = *std::max_element(addresses.begin(), addresses.end());
		// Add 256KB past the last address for function body coverage
		constexpr size_t TAIL_SIZE = 0x40000;
		size_t total_size = static_cast<size_t>(max_addr - min_addr) + TAIL_SIZE;
		if (total_size > 0x10000000) total_size = 0x10000000; // 256 MB cap

		// Pre-read the full range in one driver call
		std::vector<uint8_t> module_mem;
		driver_bridge::read_memory(min_addr, total_size, module_mem);

		if (module_mem.empty()) {
			g_state.batch_running.store(false);
			return;
		}

		// Use Ghidra's parallel batch_decompile
		std::vector<ghidra_decompiler::ghidra_result_t> results;
		ghidra_decompiler::batch_decompile(
			module_mem.data(), module_mem.size(), min_addr,
			addresses, results,
			&g_state.batch_done, &g_state.cancel);

		// Store results into the decompiler cache
		{
			std::lock_guard<std::mutex> lk(g_state.mutex);
			for (size_t i = 0; i < results.size(); ++i) {
				if (results[i].complete && !results[i].is_error) {
					decompile_result_t dr;
					dr.function_addr = results[i].function_addr;
					dr.function_name = results[i].function_name;
					dr.pseudocode = results[i].pseudocode;
					dr.complete = true;
					g_state.cache[dr.function_addr] = dr;
				}
			}
		}

		g_state.batch_running.store(false);
		g_state.decompiling.store(false);
	}).detach();
}

}
