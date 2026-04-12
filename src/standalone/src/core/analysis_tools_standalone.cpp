
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "standalone_compat.hpp"
#include "decompiler_engine.hpp"
#include "crypto_scanner.hpp"
#include "aob_generator.hpp"
#include "struct_recon_engine.hpp"
#include "fuzzer_engine.hpp"
#include "../helpers/globals.h"

#include <cinttypes>
#include <sstream>
#include <string>
#include <vector>

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
}

}
