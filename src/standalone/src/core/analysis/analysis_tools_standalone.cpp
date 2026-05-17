
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "standalone_compat.hpp"
#include "../disasm/ghidra_decompiler.hpp"
#include "../disasm/zydis_disasm.hpp"
#include "crypto_scanner.hpp"
#include "aob_generator.hpp"
#include "struct_recon_engine.hpp"
#include "fuzzer_engine.hpp"
#include "decrypt_oracle.hpp"
#include "integrity_hunter.hpp"
#include "struct_monitor.hpp"
#include "symbolic_engine.hpp"
#include "deobfuscation_engine.hpp"
#include "stealth_engine.hpp"
#include "pe_parser.hpp"
#include "symbol_store.hpp"
#include "xref_db.hpp"
#include "binary_map.hpp"
#include "standalone_driver.hpp"
#include "../helpers/globals.h"
#include "../../helpers/diag_log.hpp"

#include <algorithm>
#include <cctype>
#include <cinttypes>
#include <sstream>
#include <string>
#include <vector>
#include <chrono>

using json = nlohmann::json;
using tool_result_t = mcp_standalone::tool_result_t;

extern DisasmState g_disasm;

namespace analysis_tools {

void register_analysis_tools(mcp_standalone::server_t& srv)
{
	srv.register_tool({
		"scan_crypto_constants",
		"Scan the attached process memory for well-known cryptographic constants (AES S-Box, SHA-256, MD5, CRC32, Blowfish, DES, ChaCha20, Base64, etc).",
		{},
		true,
		[](const json&) -> tool_result_t {
			if (crypto_scanner::g_state.scanning.load()) {
				return tool_result_t::error("A crypto scan is already in progress.");
			}
			crypto_scanner::scan_process();

			int wait = 0;
			while (crypto_scanner::g_state.scanning.load() && wait < 600) {
				Sleep(100);
				++wait;
			}

			std::lock_guard<std::mutex> lk(crypto_scanner::g_state.mutex);
			auto& results = crypto_scanner::g_state.results;

			json arr = json::array();
			for (auto& r : results) {
				json obj;
				obj["signature"] = r.signature_name;
				obj["algorithm"] = r.algorithm;
				obj["category"] = crypto_scanner::category_name(r.category);
				char addr_buf[32];
				std::snprintf(addr_buf, sizeof(addr_buf), "0x%llX", static_cast<unsigned long long>(r.address));
				obj["address"] = addr_buf;
				obj["module"] = r.module_name;
				char off_buf[32];
				std::snprintf(off_buf, sizeof(off_buf), "0x%llX", static_cast<unsigned long long>(r.module_offset));
				obj["module_offset"] = off_buf;
				arr.push_back(obj);
			}

			json result;
			result["count"] = results.size();
			result["results"] = arr;
			return tool_result_t::ok(result);
		}
	});

	srv.register_tool({
		"generate_aob_signature",
		"Generate an AOB (Array of Bytes) signature from a given address. Automatically wildcards RIP-relative and large immediate bytes.",
		{
			{"address", "string", "Hex address to generate signature from (e.g. '0x7FF6A1234567')", true},
			{"instruction_count", "integer", "Number of instructions to include (default: 16)", false}
		},
		true,
		[](const json& params) -> tool_result_t {
			std::string addr_str = params.value("address", "");
			int count = params.value("instruction_count", 16);

			if (addr_str.empty()) {
				return tool_result_t::error("address parameter is required");
			}

			uint64_t addr = std::strtoull(addr_str.c_str(), nullptr, 16);
			if (addr == 0) {
				return tool_result_t::error("invalid address");
			}

			aob_generator::generate_from_address(addr, count, true);

			int wait = 0;
			while (aob_generator::g_state.generating.load() && wait < 100) {
				Sleep(100);
				++wait;
			}

			aob_generator::signature_t sig;
			std::string tool_last_error;
			{
				std::lock_guard<std::mutex> lk(aob_generator::g_state.mutex);
				sig = aob_generator::g_state.current;
				tool_last_error = aob_generator::g_state.last_error;
			}

			if (sig.bytes.empty() || sig.address != addr) {
				std::string err_msg = tool_last_error.empty()
					? std::string("Failed to generate signature (could not read memory or decode instructions)")
					: tool_last_error;
				return tool_result_t::error(err_msg);
			}

			json result;
			char abuf[32];
			std::snprintf(abuf, sizeof(abuf), "0x%llX", static_cast<unsigned long long>(sig.address));
			result["address"] = abuf;
			result["module"] = sig.module_name;
			result["byte_count"] = sig.bytes.size();
			result["standard"] = aob_generator::format_signature(sig);
			result["ida_style"] = aob_generator::format_ida_signature(sig);
			result["code_pattern"] = aob_generator::format_code_signature(sig);

			int wc = 0;
			for (auto& b : sig.bytes) if (b.wildcard) ++wc;
			result["wildcard_bytes"] = wc;

			return tool_result_t::ok(result);
		}
	});

	srv.register_tool({
		"reconstruct_struct",
		"Reconstruct a C++ struct/class layout from a memory address by analyzing memory contents, detecting VTables, and inferring field types.",
		{
			{"address", "string", "Base address of the struct instance in hex", true},
			{"size", "integer", "Size in bytes to analyze (default: 256)", false},
			{"name", "string", "Name for the struct (default: 'struct_t')", false}
		},
		true,
		[](const json& params) -> tool_result_t {
			std::string addr_str = params.value("address", "");
			int size = params.value("size", 256);
			std::string name = params.value("name", "struct_t");

			if (addr_str.empty()) {
				return tool_result_t::error("address parameter is required");
			}

			uint64_t addr = std::strtoull(addr_str.c_str(), nullptr, 16);
			if (addr == 0) {
				return tool_result_t::error("invalid address");
			}

			struct_recon::reconstruct_from_snapshot(addr, size, name);

			int wait = 0;
			while (struct_recon::g_state.monitoring.load() && wait < 300) {
				Sleep(100);
				++wait;
			}

			struct_recon::reconstructed_struct_t result_struct;
			{
				std::lock_guard<std::mutex> lk(struct_recon::g_state.mutex);
				result_struct = struct_recon::g_state.current;
			}

			std::string cpp_output = struct_recon::export_as_cpp(result_struct);

			json result;
			result["name"] = result_struct.name;
			char abuf[32];
			std::snprintf(abuf, sizeof(abuf), "0x%llX", static_cast<unsigned long long>(result_struct.base_address));
			result["base_address"] = abuf;
			result["total_size"] = result_struct.total_size;
			result["field_count"] = result_struct.fields.size();
			result["has_vtable"] = result_struct.has_vtable;
			result["cpp_definition"] = cpp_output;

			json fields_arr = json::array();
			for (auto& f : result_struct.fields) {
				json fobj;
				char off_buf[16];
				std::snprintf(off_buf, sizeof(off_buf), "0x%04llX", static_cast<unsigned long long>(f.offset));
				fobj["offset"] = off_buf;
				fobj["size"] = f.size;
				fobj["type"] = struct_recon::field_type_name(f.type);
				fobj["name"] = f.name;
				if (f.type == struct_recon::field_type_t::vtable_ptr) {
					fobj["vtable_entries"] = static_cast<int>(f.vtable_entries.size());
				}
				fields_arr.push_back(fobj);
			}
			result["fields"] = fields_arr;

			return tool_result_t::ok(result);
		}
	});

	srv.register_tool({
		"start_fuzz",
		"Start snapshot-based fuzzing of a target function using Unicorn emulation. Mutates input buffer and tracks coverage/crashes.",
		{
			{"target_address", "string", "Hex address of the function to fuzz", true},
			{"end_address", "string", "Hex address where execution should stop", false},
			{"input_address", "string", "Hex address of the input buffer in target memory", false},
			{"input_size", "integer", "Size of input buffer in bytes (default: 256)", false},
			{"max_iterations", "integer", "Maximum fuzzing iterations (default: 10000)", false}
		},
		true,
		[](const json& params) -> tool_result_t {
			auto& cfg = fuzzer_engine::g_state.config;

			std::string target = params.value("target_address", "");
			std::string end = params.value("end_address", "");
			std::string input = params.value("input_address", "");

			if (target.empty()) {
				return tool_result_t::error("target_address is required");
			}

			cfg.target_address = std::strtoull(target.c_str(), nullptr, 16);
			if (!end.empty()) cfg.end_address = std::strtoull(end.c_str(), nullptr, 16);
			if (!input.empty()) cfg.input_address = std::strtoull(input.c_str(), nullptr, 16);
			cfg.input_size = params.value("input_size", 256);
			cfg.max_iterations = params.value("max_iterations", 10000);

			cfg.pid = driver_bridge::attached_pid();
			auto threads_snap = driver_bridge::enumerate_threads();
			cfg.tid = threads_snap.empty() ? 0 : threads_snap.front().tid;

			if (cfg.pid == 0 || cfg.tid == 0)
				return tool_result_t::error("fuzzer requires an attached process and at least one thread for snapshotting");

			fuzzer_engine::start_fuzzing();

			return tool_result_t::ok("Fuzzing started. Use get_fuzz_results to check progress.");
		}
	});

	srv.register_tool({
		"stop_fuzz",
		"Stop the currently running fuzzer.",
		{},
		false,
		[](const json&) -> tool_result_t {
			fuzzer_engine::stop_fuzzing();
			return tool_result_t::ok("Fuzzer stop requested.");
		}
	});

	srv.register_tool({
		"get_fuzz_results",
		"Get current fuzzing statistics and crash results.",
		{},
		true,
		[](const json&) -> tool_result_t {
			std::lock_guard<std::mutex> lk(fuzzer_engine::g_state.mutex);
			auto& stats = fuzzer_engine::g_state.stats;

			json result;
			result["running"] = fuzzer_engine::g_state.running.load();
			result["total_executions"] = stats.total_executions;
			result["executions_per_second"] = stats.executions_per_second;
			result["total_crashes"] = stats.total_crashes;
			result["unique_crashes"] = stats.total_unique_crashes;
			result["edge_coverage"] = stats.edge_coverage;
			result["new_coverage_finds"] = stats.new_coverage_finds;
			result["corpus_size"] = stats.corpus_size;
			result["elapsed_seconds"] = stats.elapsed_seconds;

			json crashes_arr = json::array();
			for (auto& c : fuzzer_engine::g_state.unique_crashes) {
				json cobj;
				cobj["type"] = fuzzer_engine::crash_type_name(c.type);
				char abuf[32];
				std::snprintf(abuf, sizeof(abuf), "0x%llX", static_cast<unsigned long long>(c.instruction_address));
				cobj["instruction_address"] = abuf;
				cobj["description"] = c.description;
				crashes_arr.push_back(cobj);
			}
			result["crashes"] = crashes_arr;

			return tool_result_t::ok(result);
		}
	});

	srv.register_tool({
		"auto_decrypt_strings",
		"Automatically decrypt obfuscated strings by emulating functions that reference a suspected encrypted region. Finds xrefs to the region, emulates each referencing function, and captures memory writes that produce printable strings.",
		{
			{"region_address", "string", "Hex address of the encrypted string region", true},
			{"region_size", "integer", "Size of the region in bytes (default: 4096)", false}
		},
		true,
		[](const json& params) -> tool_result_t {
			std::string addr_str = params.value("region_address", "");
			uint64_t size = params.value("region_size", 4096);

			if (addr_str.empty()) {
				return tool_result_t::error("region_address parameter is required");
			}

			uint64_t addr = std::strtoull(addr_str.c_str(), nullptr, 16);
			if (addr == 0) {
				return tool_result_t::error("invalid region_address");
			}

			decrypt_oracle::scan_and_decrypt(addr, size);

			int wait = 0;
			while (decrypt_oracle::g_state.scanning.load() && wait < 600) {
				Sleep(100);
				++wait;
			}

			std::lock_guard<std::mutex> lk(decrypt_oracle::g_state.mutex);
			auto& results = decrypt_oracle::g_state.results;

			json arr = json::array();
			for (auto& r : results) {
				json obj;
				char fbuf[32];
				std::snprintf(fbuf, sizeof(fbuf), "0x%llX", static_cast<unsigned long long>(r.source_function));
				obj["source_function"] = fbuf;
				char obuf[32];
				std::snprintf(obuf, sizeof(obuf), "0x%llX", static_cast<unsigned long long>(r.encrypted_offset));
				obj["encrypted_offset"] = obuf;
				obj["decrypted_string"] = r.decrypted;
				obj["length"] = r.length;
				obj["confidence"] = r.confidence;
				obj["is_utf16"] = r.is_utf16;
				arr.push_back(obj);
			}

			json result;
			result["count"] = results.size();
			result["results"] = arr;
			return tool_result_t::ok(result);
		}
	});

	srv.register_tool({
		"hunt_integrity_checkers",
		"Find integrity checker threads by monitoring reads on a code region using page guards. Returns discovered checker RIPs, their read frequency, and associated hash comparison addresses.",
		{
			{"target_address", "string", "Hex address of the code region to protect", true},
			{"target_size", "integer", "Size of the region to monitor (default: 4096)", false},
			{"duration_ms", "integer", "How long to monitor in milliseconds (default: 10000)", false}
		},
		true,
		[](const json& params) -> tool_result_t {
			std::string addr_str = params.value("target_address", "");
			uint64_t size = params.value("target_size", 4096);
			int duration = params.value("duration_ms", 10000);

			if (addr_str.empty()) {
				return tool_result_t::error("target_address parameter is required");
			}

			uint64_t addr = std::strtoull(addr_str.c_str(), nullptr, 16);
			if (addr == 0) {
				return tool_result_t::error("invalid target_address");
			}

			diag::log_tagged_fmt("integrity_hunter",
				"mcp_hunt_request addr=0x%llX size=%llu duration_ms=%d",
				static_cast<unsigned long long>(addr),
				static_cast<unsigned long long>(size), duration);

			integrity_hunter::start_hunt(addr, size);

			int wait = 0;
			int max_wait = duration / 100;
			while (integrity_hunter::g_state.hunting.load() && wait < max_wait) {
				Sleep(100);
				++wait;
			}

			integrity_hunter::stop_hunt();

			int stop_wait = 0;
			while (integrity_hunter::g_state.hunting.load() && stop_wait < 50) {
				Sleep(100);
				++stop_wait;
			}

			std::lock_guard<std::mutex> lk(integrity_hunter::g_state.mutex);
			auto& nodes = integrity_hunter::g_state.nodes;

			json arr = json::array();
			for (size_t i = 0; i < nodes.size(); ++i) {
				auto& n = nodes[i];
				json obj;
				obj["index"] = static_cast<int>(i);
				char rbuf[32];
				std::snprintf(rbuf, sizeof(rbuf), "0x%llX", static_cast<unsigned long long>(n.reader_rip));
				obj["reader_rip"] = rbuf;
				obj["module"] = n.module_name;
				obj["read_count"] = n.read_count;
				obj["reads_per_second"] = n.reads_per_second;
				if (n.hash_compare_addr != 0) {
					char cbuf[32];
					std::snprintf(cbuf, sizeof(cbuf), "0x%llX", static_cast<unsigned long long>(n.hash_compare_addr));
					obj["hash_compare_addr"] = cbuf;
				}
				obj["disasm"] = n.disasm_text;
				obj["neutralized"] = n.neutralized;
				arr.push_back(obj);
			}

			json result;
			result["count"] = nodes.size();
			result["total_reads"] = integrity_hunter::g_state.total_reads.load();
			result["nodes"] = arr;
			return tool_result_t::ok(result);
		}
	});

	srv.register_tool({
		"neutralize_integrity_node",
		"Neutralize a discovered integrity checker by patching its conditional branch to always pass. Use hunt_integrity_checkers first to discover nodes.",
		{
			{"node_index", "integer", "Index of the integrity node to neutralize (from hunt_integrity_checkers results)", true}
		},
		true,
		[](const json& params) -> tool_result_t {
			int index = params.value("node_index", -1);
			if (index < 0) {
				return tool_result_t::error("node_index parameter is required");
			}

			bool ok = integrity_hunter::neutralize(index);

			json result;
			result["success"] = ok;
			result["node_index"] = index;
			if (ok) {
				std::lock_guard<std::mutex> lk(integrity_hunter::g_state.mutex);
				if (index < static_cast<int>(integrity_hunter::g_state.nodes.size())) {
					auto& n = integrity_hunter::g_state.nodes[static_cast<size_t>(index)];
					char rbuf[32];
					std::snprintf(rbuf, sizeof(rbuf), "0x%llX", static_cast<unsigned long long>(n.reader_rip));
					result["reader_rip"] = rbuf;
					result["status"] = "neutralized";
				}
			} else {
				result["error"] = "Failed to neutralize node (no conditional branch found near RIP)";
			}
			return tool_result_t::ok(result);
		}
	});

	srv.register_tool({
		"start_live_monitor",
		"Start continuous live struct monitoring using page guards or hardware breakpoints. Watches memory accesses to a struct region and infers field types from instruction analysis.",
		{
			{"address", "string", "Base address of the struct in hex", true},
			{"size", "integer", "Size of the struct in bytes (default: 256)", false},
			{"name", "string", "Name for the struct (default: 'struct_t')", false}
		},
		true,
		[](const json& params) -> tool_result_t {
			std::string addr_str = params.value("address", "");
			int size = params.value("size", 256);
			std::string name = params.value("name", "struct_t");

			if (addr_str.empty()) {
				return tool_result_t::error("address parameter is required");
			}

			uint64_t addr = std::strtoull(addr_str.c_str(), nullptr, 16);
			if (addr == 0) {
				return tool_result_t::error("invalid address");
			}

			if (struct_monitor::g_state.active.load()) {
				return tool_result_t::error("Live monitor already active. Stop it first.");
			}

			struct_monitor::start(addr, size, name);

			json result;
			char abuf[32];
			std::snprintf(abuf, sizeof(abuf), "0x%llX", static_cast<unsigned long long>(addr));
			result["address"] = abuf;
			result["size"] = size;
			result["status"] = "monitoring";
			return tool_result_t::ok(result);
		}
	});

	srv.register_tool({
		"stop_live_monitor",
		"Stop the active live struct monitoring session and return accumulated access data.",
		{},
		true,
		[](const json&) -> tool_result_t {
			if (!struct_monitor::g_state.active.load()) {
				return tool_result_t::error("No active live monitor session.");
			}

			struct_monitor::stop();

			int wait = 0;
			while (struct_monitor::g_state.active.load() && wait < 50) {
				Sleep(100);
				++wait;
			}

			auto accesses = struct_monitor::get_access_snapshot();

			json arr = json::array();
			for (auto& a : accesses) {
				json obj;
				char obuf[16];
				std::snprintf(obuf, sizeof(obuf), "0x%04llX", static_cast<unsigned long long>(a.field_offset));
				obj["offset"] = obuf;
				obj["access_size"] = a.access_size;
				obj["is_write"] = a.is_write;
				obj["inferred_type"] = struct_recon::field_type_name(a.inferred_type);
				obj["hit_count"] = a.hit_count;
				obj["disasm"] = a.disasm;
				char rbuf[32];
				std::snprintf(rbuf, sizeof(rbuf), "0x%llX", static_cast<unsigned long long>(a.rip));
				obj["rip"] = rbuf;
				arr.push_back(obj);
			}

			json result;
			result["total_captures"] = struct_monitor::g_state.total_captures.load();
			result["unique_offsets"] = accesses.size();
			result["accesses"] = arr;
			return tool_result_t::ok(result);
		}
	});

	srv.register_tool({
		"symbolic_deobfuscate",
		"Run symbolic execution-based deobfuscation on a function. Detects opaque predicates, removes junk code, resolves constants, and recovers the clean control flow graph. Returns cleaned instructions with statistics.",
		{{"entry_address", "string", "Entry address of the function to deobfuscate (hex)", true},
		 {"max_instructions", "number", "Maximum instructions to process (default 10000)", false}},
		true,
		[](const json& params) -> tool_result_t {
			std::string addr_str = params.value("entry_address", "");
			if (addr_str.empty())
				return tool_result_t::error("entry_address is required");

			uint64_t entry = std::strtoull(addr_str.c_str(), nullptr, 16);
			if (entry == 0)
				return tool_result_t::error("invalid entry_address");

			uint32_t max_insns = static_cast<uint32_t>(params.value("max_instructions", 10000));

			auto result = deobfuscation_engine::deobfuscate_function(entry, max_insns);

			json out;
			out["statistics"] = {
				{"total_instructions", result.total_original},
				{"clean_instructions", result.total_clean},
				{"junk_removed", result.removed_junk},
				{"opaque_predicates", result.opaque_predicates_found},
				{"constants_resolved", result.constants_resolved}
			};

			json insns = json::array();
			for (auto& ci : result.clean_instructions) {
				json obj;
				char abuf[32];
				std::snprintf(abuf, sizeof(abuf), "0x%llX", static_cast<unsigned long long>(ci.address));
				obj["address"] = abuf;
				obj["disasm"] = ci.disasm;
				obj["is_original"] = !ci.was_junk;
				obj["was_constant_folded"] = ci.was_constant_folded;
				insns.push_back(obj);
			}
			out["clean_instructions"] = insns;

			json opaques = json::array();
			for (auto& op : result.opaques) {
				json obj;
				char abuf[32];
				std::snprintf(abuf, sizeof(abuf), "0x%llX", static_cast<unsigned long long>(op.address));
				obj["address"] = abuf;
				obj["condition_str"] = op.condition_ast;
				obj["always_true"] = op.always_taken;
				opaques.push_back(obj);
			}
			out["opaque_predicates"] = opaques;

			json constants = json::array();
			for (auto& cf : result.constants) {
				json obj;
				char abuf[32];
				std::snprintf(abuf, sizeof(abuf), "0x%llX", static_cast<unsigned long long>(cf.address));
				obj["address"] = abuf;
				obj["original_expression"] = cf.original_ast;
				char vbuf[32];
				std::snprintf(vbuf, sizeof(vbuf), "0x%llX", static_cast<unsigned long long>(cf.concrete_value));
				obj["resolved_value"] = vbuf;
				constants.push_back(obj);
			}
			out["constants"] = constants;

			return tool_result_t::ok(out);
		}
	});

	srv.register_tool({
		"symbolic_slice_function",
		"Perform backward program slicing using symbolic execution. Returns only the instructions that contribute to the final value of the target register, removing all irrelevant code.",
		{{"start_address", "string", "Start address for the slice range (hex)", true},
		 {"end_address", "string", "End address for the slice range (hex)", true},
		 {"target_register", "string", "Target register to slice to (e.g. rax, rcx, rdi)", true},
		 {"max_instructions", "number", "Maximum instructions to process (default 5000)", false}},
		true,
		[](const json& params) -> tool_result_t {
			std::string start_str = params.value("start_address", "");
			std::string end_str = params.value("end_address", "");
			std::string reg = params.value("target_register", "");
			if (start_str.empty() || end_str.empty() || reg.empty())
				return tool_result_t::error("start_address, end_address, and target_register are required");

			uint64_t start = std::strtoull(start_str.c_str(), nullptr, 16);
			uint64_t end = std::strtoull(end_str.c_str(), nullptr, 16);
			uint32_t max_insns = static_cast<uint32_t>(params.value("max_instructions", 5000));

			auto result = symbolic_engine::slice_to_register(start, end, max_insns, reg);

			json out;
			out["target_register"] = reg;
			out["total_instructions"] = result.total_instructions;
			out["effective_instructions"] = result.effective_count;
			out["removed_count"] = result.total_instructions - result.effective_count;

			json insns = json::array();
			for (auto& ti : result.effective_instructions) {
				json obj;
				char abuf[32];
				std::snprintf(abuf, sizeof(abuf), "0x%llX", static_cast<unsigned long long>(ti.address));
				obj["address"] = abuf;
				obj["disasm"] = ti.disasm;
				insns.push_back(obj);
			}
			out["instructions"] = insns;

			return tool_result_t::ok(out);
		}
	});

	srv.register_tool({
		"symbolic_solve_path",
		"Use Z3 constraint solver to find concrete register values that force execution to reach a specific target address from a start address. Returns SAT/UNSAT and the required register values.",
		{{"start_address", "string", "Starting address of execution (hex)", true},
		 {"target_address", "string", "Target address to reach (hex)", true},
		 {"symbolic_registers", "string", "Comma-separated register names to make symbolic (e.g. rax,rcx)", true},
		 {"max_instructions", "number", "Maximum instructions to process (default 5000)", false}},
		true,
		[](const json& params) -> tool_result_t {
			std::string start_str = params.value("start_address", "");
			std::string target_str = params.value("target_address", "");
			std::string regs_str = params.value("symbolic_registers", "");
			if (start_str.empty() || target_str.empty() || regs_str.empty())
				return tool_result_t::error("start_address, target_address, and symbolic_registers are required");

			uint64_t start = std::strtoull(start_str.c_str(), nullptr, 16);
			uint64_t target = std::strtoull(target_str.c_str(), nullptr, 16);
			uint32_t max_insns = static_cast<uint32_t>(params.value("max_instructions", 5000));

			std::vector<std::string> sym_regs;
			{
				std::istringstream iss(regs_str);
				std::string tok;
				while (std::getline(iss, tok, ',')) {
					while (!tok.empty() && tok.front() == ' ') tok.erase(tok.begin());
					while (!tok.empty() && tok.back() == ' ') tok.pop_back();
					if (!tok.empty())
						sym_regs.push_back(tok);
				}
			}

			auto result = symbolic_engine::solve_for_path(start, target, max_insns, sym_regs);

			json out;
			out["satisfiable"] = result.satisfiable;
			out["solving_time_ms"] = result.solving_time_ms;

			if (result.satisfiable) {
				json vars = json::object();
				for (auto& [name, val] : result.variable_values) {
					char vbuf[32];
					std::snprintf(vbuf, sizeof(vbuf), "0x%llX", static_cast<unsigned long long>(val));
					vars[name] = vbuf;
				}
				out["solution"] = vars;
			}

			return tool_result_t::ok(out);
		}
	});

	srv.register_tool({
		"taint_trace_register",
		"Perform taint analysis starting from specified registers or memory addresses. Traces taint propagation through all instructions to identify every instruction that touches the tainted data.",
		{{"start_address", "string", "Start address for taint tracing (hex)", true},
		 {"end_address", "string", "End address for taint tracing (hex)", true},
		 {"taint_registers", "string", "Comma-separated register names to taint initially (e.g. rdi,rsi)", false},
		 {"taint_memory", "string", "Comma-separated memory addresses to taint initially (hex)", false},
		 {"max_instructions", "number", "Maximum instructions to process (default 5000)", false}},
		true,
		[](const json& params) -> tool_result_t {
			std::string start_str = params.value("start_address", "");
			std::string end_str = params.value("end_address", "");
			if (start_str.empty() || end_str.empty())
				return tool_result_t::error("start_address and end_address are required");

			uint64_t start = std::strtoull(start_str.c_str(), nullptr, 16);
			uint64_t end = std::strtoull(end_str.c_str(), nullptr, 16);
			uint32_t max_insns = static_cast<uint32_t>(params.value("max_instructions", 5000));

			std::vector<std::string> taint_regs;
			{
				std::string regs_str = params.value("taint_registers", "");
				std::istringstream iss(regs_str);
				std::string tok;
				while (std::getline(iss, tok, ',')) {
					while (!tok.empty() && tok.front() == ' ') tok.erase(tok.begin());
					while (!tok.empty() && tok.back() == ' ') tok.pop_back();
					if (!tok.empty())
						taint_regs.push_back(tok);
				}
			}

			std::vector<std::pair<uint64_t, uint32_t>> taint_mem;
			{
				std::string mem_str = params.value("taint_memory", "");
				std::istringstream iss(mem_str);
				std::string tok;
				while (std::getline(iss, tok, ',')) {
					while (!tok.empty() && tok.front() == ' ') tok.erase(tok.begin());
					while (!tok.empty() && tok.back() == ' ') tok.pop_back();
					if (!tok.empty())
						taint_mem.push_back({std::strtoull(tok.c_str(), nullptr, 16), 1});
				}
			}

			auto result = symbolic_engine::taint_trace(start, end, max_insns, taint_regs, taint_mem);

			json out;
			out["total_instructions"] = result.total_processed;
			out["tainted_instructions"] = result.tainted_count;

			json insns = json::array();
			for (auto& ti : result.tainted_instructions) {
				json obj;
				char abuf[32];
				std::snprintf(abuf, sizeof(abuf), "0x%llX", static_cast<unsigned long long>(ti.address));
				obj["address"] = abuf;
				obj["disasm"] = ti.disasm;

				json src = json::array();
				for (auto& r : ti.read_regs) src.push_back(r);
				obj["source_regs"] = src;

				json dst = json::array();
				for (auto& r : ti.written_regs) dst.push_back(r);
				obj["dest_regs"] = dst;

				insns.push_back(obj);
			}
			out["instructions"] = insns;

			json tainted_regs_out = json::array();
			for (auto& r : result.tainted_registers)
				tainted_regs_out.push_back(r);
			out["final_tainted_registers"] = tainted_regs_out;

			json tainted_mem_out = json::array();
			for (auto addr : result.tainted_memory_addresses) {
				char abuf[32];
				std::snprintf(abuf, sizeof(abuf), "0x%llX", static_cast<unsigned long long>(addr));
				tainted_mem_out.push_back(abuf);
			}
			out["final_tainted_memory"] = tainted_mem_out;

			return tool_result_t::ok(out);
		}
	});

	srv.register_tool({
		"decompile_function",
		"Decompile a function using the embedded Ghidra decompiler engine. Returns pseudocode instantly (~100ms) without requiring an API key. Works in either driver-attached mode or static (on-disk) mode - if no process is attached, the bytes are read from the currently loaded PE file.",
		{{"address", "string", "Function entry point address in hex (e.g. 0x7FF6A1230000)", true}},
		true,
		[](const json& params) -> tool_result_t {
			std::string addr_str = params.value("address", "");
			if (addr_str.empty())
				return tool_result_t::error("address is required");

			uint64_t addr = std::strtoull(addr_str.c_str(), nullptr, 16);
			if (addr == 0)
				return tool_result_t::error("invalid address");

			if (!ghidra_decompiler::g_state.initialized.load()) {
				if (!ghidra_decompiler::init())
					return tool_result_t::error("failed to initialize Ghidra decompiler - specs directory not found");
			}

			constexpr size_t kPrereadSize = 0x40000;
			std::vector<uint8_t> mem;
			bool has_static = (g_disasm.file.loaded && !g_disasm.file.sections.empty());
			driver_bridge::read_memory(addr, kPrereadSize, mem);
			bool driver_provided = !mem.empty();
			if (mem.empty() && has_static) {
				static_analysis::read_bytes_from_pe(g_disasm.file, addr, kPrereadSize, mem);
			}
			if (mem.empty()) {
				uint32_t pid_post = driver_bridge::attached_pid();
				if (pid_post != 0 && has_static)
					return tool_result_t::error("no executable bytes at this address (driver returned 0 bytes and address is outside loaded PE sections)");
				if (pid_post != 0)
					return tool_result_t::error("driver returned no bytes at this address (open a PE file in the standalone to enable static fallback)");
				if (has_static)
					return tool_result_t::error("address is outside the loaded PE's executable sections");
				if (g_disasm.file.loaded)
					return tool_result_t::error("driver session lost - re-attach via File > Attach, or open the PE on disk via File > Open");
				return tool_result_t::error("no source available: open a PE file via File > Open or attach a process via File > Attach");
			}

			auto result = ghidra_decompiler::decompile_buffer(
				mem.data(), mem.size(), addr, addr, nullptr,
				g_disasm.file.loaded ? &g_disasm.file : nullptr);
			if (result.is_error)
				return tool_result_t::error(result.error_text);

			json out;
			char abuf[32];
			std::snprintf(abuf, sizeof(abuf), "0x%llX", static_cast<unsigned long long>(result.function_addr));
			out["address"] = abuf;
			out["function_name"] = result.function_name;
			out["pseudocode"] = result.pseudocode;
			out["elapsed_ms"] = result.elapsed_ms;
			out["sleigh_id"] = result.sleigh_id;
			json callees = json::array();
			for (auto& kv : result.callees) {
				char cbuf[32];
				std::snprintf(cbuf, sizeof(cbuf), "0x%llX", static_cast<unsigned long long>(kv.second));
				json c;
				c["name"] = kv.first;
				c["address"] = cbuf;
				callees.push_back(c);
			}
			out["callees"] = callees;
			out["source"] = driver_provided ? "driver" : "file";
			return tool_result_t::ok(out);
		}
	});

	srv.register_tool({
		"enable_stealth_context",
		"Install anti-debug hooks in the target process: PEB flag spoofing, RDTSC timing patch, and optional debug context scrubbing. Hides hardware breakpoints from anti-cheat context inspection. Call this before setting hardware breakpoints to ensure the target cannot detect analysis.",
		{{"pid", "string", "Target process PID as decimal string. Leave empty to use the currently attached PID.", false},
		 {"spoof_peb", "boolean", "Patch PEB BeingDebugged / NtGlobalFlag (default: true)", false},
		 {"hook_rdtsc", "boolean", "Install RDTSC trampoline hooks for timing-based detection (default: true)", false},
		 {"scrub_context", "boolean", "Zero DR0-DR7 on all target threads (default: false)", false}},
		true,
		[](const json& params) -> tool_result_t {
			uint32_t pid = 0;
			std::string pid_str = params.value("pid", "");
			if (!pid_str.empty())
				pid = static_cast<uint32_t>(std::strtoul(pid_str.c_str(), nullptr, 10));
			if (pid == 0)
				pid = driver_bridge::attached_pid();
			if (pid == 0) {
				diag::log_tagged("stealth", "mcp_enable_reject reason=no_pid");
				return tool_result_t::error("no target PID: attach driver first or provide pid parameter");
			}

			if (stealth_engine::is_active())
				return tool_result_t::ok(json{{"status", stealth_engine::get_status()}, {"already_active", true}});

			stealth_engine::stealth_options_t opts;
			opts.spoof_peb = params.value("spoof_peb", true);
			opts.hook_rdtsc = params.value("hook_rdtsc", true);
			opts.scrub_context = params.value("scrub_context", false);
			diag::log_tagged_fmt("stealth",
				"mcp_enable_request pid=%u peb=%d rdtsc=%d ctx=%d",
				pid, opts.spoof_peb ? 1 : 0,
				opts.hook_rdtsc ? 1 : 0, opts.scrub_context ? 1 : 0);
			stealth_engine::enable_stealth(pid, opts);

			json out;
			out["pid"] = pid;
			out["status"] = stealth_engine::get_status();
			out["active"] = stealth_engine::is_active();
			{
				std::lock_guard<std::mutex> lk(stealth_engine::g_state.mutex);
				out["peb_spoofed"] = stealth_engine::g_state.session.peb_spoofed;
				out["rdtsc_hooks"] = static_cast<int>(stealth_engine::g_state.session.hooks.size());
				out["context_scrubbed"] = stealth_engine::g_state.session.context_hooked;
			}
			return tool_result_t::ok(out);
		}
	});

	srv.register_tool({
		"disable_stealth_context",
		"Remove all stealth hooks installed by enable_stealth_context and restore original bytes. Safe to call even if stealth is not active.",
		{},
		true,
		[](const json& params) -> tool_result_t {
			if (!stealth_engine::is_active())
				return tool_result_t::ok(json{{"status", "stealth was not active"}, {"hooks_removed", 0}});

			int hook_count = 0;
			{
				std::lock_guard<std::mutex> lk(stealth_engine::g_state.mutex);
				hook_count = static_cast<int>(stealth_engine::g_state.session.hooks.size());
			}

			stealth_engine::disable_stealth();

			json out;
			out["status"] = stealth_engine::get_status();
			out["hooks_removed"] = hook_count;
			return tool_result_t::ok(out);
		}
	});

	srv.register_tool({
		"analysis_get_imports",
		"List the IAT imports of the attached process's main module (module, function name, ordinal, IAT virtual address, bound address).",
		{},
		true,
		[](const json&) -> tool_result_t {
			if (driver_bridge::attached_pid() == 0)
				return tool_result_t::error("No process is attached; call driver_attach first.");
			auto modules = driver_bridge::enumerate_modules();
			if (modules.empty())
				return tool_result_t::error("Module enumeration returned no entries.");
			pe_parser::pe_info_t pe;
			if (!pe_parser::parse(modules.front().base, pe, true))
				return tool_result_t::error("pe_parser::parse failed on the main module.");
			json arr = json::array();
			char buf[32];
			for (const auto& imp : pe.imports) {
				json o;
				o["module"]   = imp.module_name;
				o["function"] = imp.function_name;
				o["ordinal"]  = imp.ordinal;
				o["hint"]     = imp.hint;
				std::snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(imp.iat_address));
				o["iat_address"]   = buf;
				std::snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(imp.bound_address));
				o["bound_address"] = buf;
				arr.push_back(std::move(o));
			}
			json result;
			result["module"] = modules.front().name;
			result["count"]  = arr.size();
			result["imports"] = std::move(arr);
			return tool_result_t::ok(result);
		}
	});

	srv.register_tool({
		"analysis_get_exports",
		"List the exports of the attached process's main module (ordinal, name, RVA, absolute address, forwarder info).",
		{},
		true,
		[](const json&) -> tool_result_t {
			if (driver_bridge::attached_pid() == 0)
				return tool_result_t::error("No process is attached; call driver_attach first.");
			auto modules = driver_bridge::enumerate_modules();
			if (modules.empty())
				return tool_result_t::error("Module enumeration returned no entries.");
			pe_parser::pe_info_t pe;
			if (!pe_parser::parse(modules.front().base, pe, true))
				return tool_result_t::error("pe_parser::parse failed on the main module.");
			json arr = json::array();
			char buf[32];
			for (const auto& exp : pe.exports) {
				json o;
				o["ordinal"] = exp.ordinal;
				o["name"]    = exp.name;
				std::snprintf(buf, sizeof(buf), "0x%X", exp.rva);
				o["rva"]     = buf;
				std::snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(exp.address));
				o["address"] = buf;
				if (exp.is_forwarded) {
					o["forwarded"] = true;
					o["forward_to"] = exp.forward_name;
				}
				arr.push_back(std::move(o));
			}
			json result;
			result["module"]  = modules.front().name;
			result["count"]   = arr.size();
			result["exports"] = std::move(arr);
			return tool_result_t::ok(result);
		}
	});

	srv.register_tool({
		"analysis_get_types",
		"List user-defined types (structs, unions, enums) discovered in any loaded module's PDB. Supports a case-insensitive substring filter on the type name.",
		{{"filter", "string", "Optional substring filter (case-insensitive)", false},
		 {"limit",  "number", "Maximum types to return (default 200, max 5000)", false}},
		true,
		[](const json& params) -> tool_result_t {
			std::string filter;
			if (params.contains("filter") && params["filter"].is_string()) {
				filter = params["filter"].get<std::string>();
				std::transform(filter.begin(), filter.end(), filter.begin(), [](unsigned char c) {
					return static_cast<char>(std::tolower(c));
				});
			}
			size_t limit = 200;
			if (params.contains("limit") && params["limit"].is_number_unsigned()) {
				size_t v = params["limit"].get<size_t>();
				if (v > 0 && v <= 5000) limit = v;
			}
			json arr = json::array();
			size_t total = 0;
			{
				std::lock_guard<std::mutex> lk(symbol_store::g_state.mutex);
				for (const auto& kv : symbol_store::g_state.modules) {
					const auto& mod = kv.second;
					for (const auto& s : mod.pdb.structs) {
						std::string lname = s.name;
						std::transform(lname.begin(), lname.end(), lname.begin(),
							[](unsigned char c) { return static_cast<char>(std::tolower(c)); });
						if (!filter.empty() && lname.find(filter) == std::string::npos)
							continue;
						++total;
						if (arr.size() >= limit) continue;
						json o;
						o["module"] = mod.module_name;
						o["name"]   = s.name;
						o["kind"]   = s.is_union ? "union" : "struct";
						o["size"]   = s.size;
						o["member_count"] = s.members.size();
						arr.push_back(std::move(o));
					}
					for (const auto& e : mod.pdb.enums) {
						std::string lname = e.name;
						std::transform(lname.begin(), lname.end(), lname.begin(),
							[](unsigned char c) { return static_cast<char>(std::tolower(c)); });
						if (!filter.empty() && lname.find(filter) == std::string::npos)
							continue;
						++total;
						if (arr.size() >= limit) continue;
						json o;
						o["module"] = mod.module_name;
						o["name"]   = e.name;
						o["kind"]   = "enum";
						o["member_count"] = e.members.size();
						arr.push_back(std::move(o));
					}
				}
			}
			json result;
			result["total"]    = total;
			result["returned"] = arr.size();
			result["types"]    = std::move(arr);
			return tool_result_t::ok(result);
		}
	});

	srv.register_tool({
		"analysis_get_type_definition",
		"Return the full member layout of a struct/union/enum loaded from any module's PDB.",
		{{"name",   "string", "Type name (exact, case-sensitive match preferred)", true},
		 {"module", "string", "Optional module name to narrow the lookup", false}},
		true,
		[](const json& params) -> tool_result_t {
			if (!params.contains("name") || !params["name"].is_string())
				return tool_result_t::error("'name' is required.");
			std::string want = params["name"].get<std::string>();
			std::string want_module;
			if (params.contains("module") && params["module"].is_string())
				want_module = params["module"].get<std::string>();

			std::lock_guard<std::mutex> lk(symbol_store::g_state.mutex);
			for (const auto& kv : symbol_store::g_state.modules) {
				const auto& mod = kv.second;
				if (!want_module.empty() && mod.module_name != want_module) continue;
				for (const auto& s : mod.pdb.structs) {
					if (s.name != want) continue;
					json members = json::array();
					for (const auto& m : s.members) {
						json mj;
						mj["name"]    = m.name;
						mj["type"]    = m.type_name;
						mj["offset"]  = m.offset;
						mj["size"]    = m.size;
						if (m.is_pointer) {
							mj["pointer"]       = true;
							mj["pointer_depth"] = m.pointer_depth;
						}
						if (m.is_array) {
							mj["array"]       = true;
							mj["array_count"] = m.array_count;
						}
						if (m.bit_offset >= 0) mj["bit_offset"] = m.bit_offset;
						if (m.bit_size   >= 0) mj["bit_size"]   = m.bit_size;
						members.push_back(std::move(mj));
					}
					json result;
					result["module"]  = mod.module_name;
					result["name"]    = s.name;
					result["kind"]    = s.is_union ? "union" : "struct";
					result["size"]    = s.size;
					result["members"] = std::move(members);
					return tool_result_t::ok(result);
				}
				for (const auto& e : mod.pdb.enums) {
					if (e.name != want) continue;
					json members = json::array();
					for (const auto& em : e.members) {
						json mj;
						mj["name"]  = em.name;
						mj["value"] = em.value;
						members.push_back(std::move(mj));
					}
					json result;
					result["module"]  = mod.module_name;
					result["name"]    = e.name;
					result["kind"]    = "enum";
					result["members"] = std::move(members);
					return tool_result_t::ok(result);
				}
			}
			return tool_result_t::error("Type not found in any loaded module's PDB.");
		}
	});

	srv.register_tool({
		"analysis_get_pdb_symbols",
		"List PDB symbols across all loaded modules (function and data). Supports a case-insensitive substring filter on the symbol name.",
		{{"filter", "string", "Optional substring filter (case-insensitive)", false},
		 {"module", "string", "Optional module-name filter", false},
		 {"functions_only", "boolean", "If true return only function symbols", false},
		 {"limit",  "number", "Maximum symbols to return (default 500, max 10000)", false}},
		true,
		[](const json& params) -> tool_result_t {
			std::string filter;
			if (params.contains("filter") && params["filter"].is_string()) {
				filter = params["filter"].get<std::string>();
				std::transform(filter.begin(), filter.end(), filter.begin(),
					[](unsigned char c) { return static_cast<char>(std::tolower(c)); });
			}
			std::string want_module;
			if (params.contains("module") && params["module"].is_string())
				want_module = params["module"].get<std::string>();
			bool funcs_only = false;
			if (params.contains("functions_only") && params["functions_only"].is_boolean())
				funcs_only = params["functions_only"].get<bool>();
			size_t limit = 500;
			if (params.contains("limit") && params["limit"].is_number_unsigned()) {
				size_t v = params["limit"].get<size_t>();
				if (v > 0 && v <= 10000) limit = v;
			}

			json arr = json::array();
			size_t total = 0;
			char buf[32];
			{
				std::lock_guard<std::mutex> lk(symbol_store::g_state.mutex);
				for (const auto& kv : symbol_store::g_state.modules) {
					const auto& mod = kv.second;
					if (!want_module.empty() && mod.module_name != want_module) continue;
					for (const auto& sym : mod.pdb.symbols) {
						if (funcs_only && !sym.is_function) continue;
						if (!filter.empty()) {
							std::string ln = sym.name;
							std::transform(ln.begin(), ln.end(), ln.begin(),
								[](unsigned char c) { return static_cast<char>(std::tolower(c)); });
							if (ln.find(filter) == std::string::npos) continue;
						}
						++total;
						if (arr.size() >= limit) continue;
						json o;
						o["module"] = mod.module_name;
						o["name"]   = sym.name;
						std::snprintf(buf, sizeof(buf), "0x%llX",
							static_cast<unsigned long long>(mod.base + sym.rva));
						o["address"]     = buf;
						std::snprintf(buf, sizeof(buf), "0x%llX",
							static_cast<unsigned long long>(sym.rva));
						o["rva"]         = buf;
						o["size"]        = sym.size;
						o["is_function"] = sym.is_function;
						arr.push_back(std::move(o));
					}
				}
			}

			json result;
			result["total"]    = total;
			result["returned"] = arr.size();
			result["symbols"]  = std::move(arr);
			return tool_result_t::ok(result);
		}
	});

	srv.register_tool({
		"analysis_get_binary_map_overview",
		"Generate the binary map overview (top functions, globals, sections, imports/exports) used by the Binary Map panel and return it as JSON.",
		{{"max_functions", "number", "Maximum functions to include (default 50)", false},
		 {"max_globals",   "number", "Maximum globals to include (default 30)", false}},
		true,
		[](const json& params) -> tool_result_t {
			aida::binary_map::map_options_t opts;
			if (params.contains("max_functions") && params["max_functions"].is_number_integer())
				opts.max_functions = params["max_functions"].get<int>();
			if (params.contains("max_globals") && params["max_globals"].is_number_integer())
				opts.max_globals = params["max_globals"].get<int>();

			aida::binary_map::map_t m;
			if (!aida::binary_map::generate(opts, m))
				return tool_result_t::error(aida::binary_map::last_error());

			char buf[32];
			json sections = json::array();
			for (const auto& s : m.sections) {
				json o;
				o["name"] = s.name;
				std::snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(s.va));
				o["va"]   = buf;
				o["size"] = s.size;
				o["executable"] = s.executable;
				o["readable"]   = s.readable;
				o["writable"]   = s.writable;
				sections.push_back(std::move(o));
			}
			json functions = json::array();
			for (const auto& f : m.functions) {
				json o;
				std::snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(f.va));
				o["va"]   = buf;
				o["name"] = f.name;
				o["xref_count"]   = f.xref_count;
				o["callee_count"] = f.callee_count;
				if (!f.section_name.empty()) o["section"] = f.section_name;
				if (!f.top_callees.empty()) o["top_callees"] = f.top_callees;
				if (f.pinned) o["pinned"] = true;
				functions.push_back(std::move(o));
			}
			json globals = json::array();
			for (const auto& g : m.globals) {
				json o;
				std::snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(g.va));
				o["va"]   = buf;
				o["name"] = g.name;
				o["xref_count"] = g.xref_count;
				o["writable"]   = g.writable;
				if (!g.section_name.empty()) o["section"] = g.section_name;
				globals.push_back(std::move(o));
			}

			json result;
			result["module_name"]  = m.module_name;
			result["module_path"]  = m.module_path;
			result["architecture"] = m.architecture;
			result["format"]       = m.format;
			std::snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(m.image_base));
			result["image_base"]   = buf;
			result["image_size"]   = m.image_size;
			result["sections"]     = std::move(sections);
			result["functions"]    = std::move(functions);
			result["globals"]      = std::move(globals);
			result["imports"]      = m.imports;
			result["exports"]      = m.exports;
			return tool_result_t::ok(result);
		}
	});

	srv.register_tool({
		"analysis_get_xref_db_stats",
		"Return aggregate statistics from the xref_db (per-module xref counts, indexed flag, total xrefs across all modules).",
		{},
		true,
		[](const json&) -> tool_result_t {
			std::lock_guard<std::mutex> lk(xref_db::g_state.mutex);
			json arr = json::array();
			size_t total = 0;
			size_t built = 0;
			for (const auto& kv : xref_db::g_state.modules) {
				const auto& mod = kv.second;
				json o;
				o["module"]      = mod.name;
				o["base"]        = mod.base;
				o["size"]        = mod.size;
				o["total_xrefs"] = mod.total_xrefs;
				o["built"]       = mod.built;
				arr.push_back(std::move(o));
				if (mod.built) {
					++built;
					total += mod.total_xrefs;
				}
			}
			json result;
			result["module_count"] = xref_db::g_state.modules.size();
			result["modules_built"] = built;
			result["total_xrefs"]  = total;
			result["building"]     = xref_db::g_state.building.load();
			result["progress"]     = xref_db::g_state.progress.load();
			result["modules"]      = std::move(arr);
			return tool_result_t::ok(result);
		}
	});

	srv.register_tool({
		"crypto_scanner_run",
		"Trigger a fresh crypto-constant scan over the attached process memory (AES S-Box, SHA, MD5, CRC32, Blowfish, ChaCha20, Base64, etc.). Blocks until the scan worker finishes (up to 60s).",
		{},
		false,
		[](const json&) -> tool_result_t {
			if (crypto_scanner::g_state.scanning.load())
				return tool_result_t::error("A crypto scan is already in progress.");
			crypto_scanner::scan_process();
			int wait = 0;
			while (crypto_scanner::g_state.scanning.load() && wait < 600) {
				Sleep(100);
				++wait;
			}
			std::lock_guard<std::mutex> lk(crypto_scanner::g_state.mutex);
			json result;
			result["status"] = crypto_scanner::g_state.scanning.load() ? "still_running" : "complete";
			result["count"]  = crypto_scanner::g_state.results.size();
			return tool_result_t::ok(result);
		}
	});

	srv.register_tool({
		"crypto_scanner_get_results",
		"Return the cached results of the most recent crypto-constant scan.",
		{{"limit", "number", "Maximum hits to return (default 500, max 5000)", false}},
		true,
		[](const json& params) -> tool_result_t {
			size_t limit = 500;
			if (params.contains("limit") && params["limit"].is_number_unsigned()) {
				size_t v = params["limit"].get<size_t>();
				if (v > 0 && v <= 5000) limit = v;
			}
			std::lock_guard<std::mutex> lk(crypto_scanner::g_state.mutex);
			json arr = json::array();
			char buf[32];
			size_t n = std::min(crypto_scanner::g_state.results.size(), limit);
			for (size_t i = 0; i < n; ++i) {
				const auto& r = crypto_scanner::g_state.results[i];
				json o;
				o["signature"] = r.signature_name;
				o["algorithm"] = r.algorithm;
				o["category"]  = crypto_scanner::category_name(r.category);
				std::snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(r.address));
				o["address"]   = buf;
				o["module"]    = r.module_name;
				std::snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(r.module_offset));
				o["module_offset"]      = buf;
				o["reference_count"]    = r.referencing_functions.size();
				arr.push_back(std::move(o));
			}
			json result;
			result["total"]    = crypto_scanner::g_state.results.size();
			result["returned"] = n;
			result["results"]  = std::move(arr);
			return tool_result_t::ok(result);
		}
	});
}

}
