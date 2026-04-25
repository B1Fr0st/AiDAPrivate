
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "standalone_compat.hpp"
#include "decompiler_engine.hpp"
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
#include "../helpers/globals.h"

#include <cinttypes>
#include <sstream>
#include <string>
#include <vector>
#include <chrono>

using json = nlohmann::json;
using tool_result_t = mcp_standalone::tool_result_t;

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
			{
				std::lock_guard<std::mutex> lk(aob_generator::g_state.mutex);
				sig = aob_generator::g_state.current;
			}

			if (sig.bytes.empty()) {
				return tool_result_t::error("Failed to generate signature (could not read memory or decode instructions)");
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
		"decompile_function_native",
		"Decompile a function using the embedded Ghidra decompiler engine. Returns pseudocode instantly (~100ms) without requiring an API key. The target process must be attached via the kernel driver.",
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

			auto result = ghidra_decompiler::decompile_function(addr);
			if (result.is_error)
				return tool_result_t::error(result.error_text);

			json out;
			char abuf[32];
			std::snprintf(abuf, sizeof(abuf), "0x%llX", static_cast<unsigned long long>(result.function_addr));
			out["address"] = abuf;
			out["function_name"] = result.function_name;
			out["pseudocode"] = result.pseudocode;
			out["elapsed_ms"] = result.elapsed_ms;
			return tool_result_t::ok(out);
		}
	});

	srv.register_tool({
		"decompile_function_hybrid",
		"Decompile a function using Ghidra for instant structure recovery, then AI to refine variable names and add context. Returns high-quality pseudocode with meaningful identifiers. Requires both driver attachment and API key.",
		{{"address", "string", "Function entry point address in hex (e.g. 0x7FF6A1230000)", true}},
		true,
		[](const json& params) -> tool_result_t {
			std::string addr_str = params.value("address", "");
			if (addr_str.empty())
				return tool_result_t::error("address is required");

			uint64_t addr = std::strtoull(addr_str.c_str(), nullptr, 16);
			if (addr == 0)
				return tool_result_t::error("invalid address");

			decompiler_engine::decompile_function_hybrid(addr, g_sa_settings);

			auto& st = decompiler_engine::g_state;
			int timeout_ms = 60000;
			int waited = 0;
			while (st.decompiling.load() && waited < timeout_ms) {
				std::this_thread::sleep_for(std::chrono::milliseconds(100));
				waited += 100;
			}

			if (st.decompiling.load())
				return tool_result_t::error("decompilation timed out after 60 seconds");

			std::lock_guard<std::mutex> lock(st.mutex);
			if (st.current.pseudocode.empty())
				return tool_result_t::error("decompilation produced no output");

			json out;
			char abuf[32];
			std::snprintf(abuf, sizeof(abuf), "0x%llX", static_cast<unsigned long long>(st.current.function_addr));
			out["address"] = abuf;
			out["function_name"] = st.current.function_name;
			out["pseudocode"] = st.current.pseudocode;
			out["mode"] = "hybrid";
			return tool_result_t::ok(out);
		}
	});

	srv.register_tool({
		"enable_stealth_context",
		"Install anti-debug hooks in the target process: PEB flag spoofing and RDTSC timing patch. Hides hardware breakpoints from anti-cheat context inspection. Call this before setting hardware breakpoints to ensure the target cannot detect analysis.",
		{{"pid", "string", "Target process PID as decimal string. Leave empty to use the currently attached PID.", false}},
		true,
		[](const json& params) -> tool_result_t {
			uint32_t pid = 0;
			std::string pid_str = params.value("pid", "");
			if (!pid_str.empty())
				pid = static_cast<uint32_t>(std::strtoul(pid_str.c_str(), nullptr, 10));
			if (pid == 0)
				pid = driver_bridge::attached_pid();
			if (pid == 0)
				return tool_result_t::error("no target PID: attach driver first or provide pid parameter");

			if (stealth_engine::is_active())
				return tool_result_t::ok(json{{"status", stealth_engine::get_status()}, {"already_active", true}});

			stealth_engine::enable_stealth(pid);

			json out;
			out["pid"] = pid;
			out["status"] = stealth_engine::get_status();
			out["active"] = stealth_engine::is_active();
			{
				std::lock_guard<std::mutex> lk(stealth_engine::g_state.mutex);
				out["peb_spoofed"] = stealth_engine::g_state.session.peb_spoofed;
				out["rdtsc_hooks"] = static_cast<int>(stealth_engine::g_state.session.hooks.size());
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
}

}
