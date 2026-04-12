#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "cfg_view.hpp"
#include "standalone_ai_client.hpp"
#include "standalone_driver.hpp"
#include "standalone_settings.hpp"
#include "xref_engine.hpp"
#include "zydis_disasm.hpp"

#ifdef __NT__
#include "emulation_engine.hpp"
#endif

namespace decompiler_engine {

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

			while (pos < sz && all_insns.size() < 4096) {
				int avail = (std::min)(sz - pos, 15);
				uint64_t va = func_addr + pos;
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

				all_insns.push_back(d);
				if (ins.is_ret) break;
				pos += ins.len;
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
		extern const settings_sa_t& get_standalone_settings();
		decompile_function(entry.addr, get_standalone_settings());
	}
}

inline void navigate_forward()
{
	if (g_state.history_pos + 1 < static_cast<int>(g_state.history.size())) {
		g_state.history_pos++;
		auto& entry = g_state.history[g_state.history_pos];
		extern const settings_sa_t& get_standalone_settings();
		decompile_function(entry.addr, get_standalone_settings());
	}
}

}
