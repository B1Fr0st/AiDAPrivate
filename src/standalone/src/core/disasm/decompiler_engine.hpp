#pragma once

#include <algorithm>
#include "work_queue.hpp"
#include "zydis_disasm.hpp"
#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <functional>
#include <list>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "standalone_driver.hpp"
#include "standalone_settings.hpp"
#include "ghidra_decompiler.hpp"
#include "ghidra_adapters/aida_code_xml_parse.hpp"
#include "function_index.hpp"
#include "../../helpers/diag_log.hpp"

#include <nlohmann/json.hpp>

namespace decompiler_engine {

struct decompile_result_t {
	uint64_t    function_addr = 0;
	std::string function_name;
	std::string pseudocode;
	std::string parameters;
	std::string local_vars;
	std::vector<std::string> callees;
	std::vector<std::pair<std::string, uint64_t>> callee_targets;
	std::vector<aida_ghidra::code_annotation_t> annotations;
	std::vector<std::pair<int, uint64_t>> line_addr_map;
	std::string sleigh_id;
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
	std::mutex         mutex;
	std::atomic<bool>  decompiling{false};
	std::atomic<bool>  cancel{false};
	std::atomic<bool>  init_progress_active{false};
	bool               active = false;

	std::vector<history_entry_t> history;
	int history_pos = -1;

	float scroll_y = 0.f;
	float target_scroll_y = 0.f;

	std::unordered_map<uint64_t, decompile_result_t> cache;
	std::list<uint64_t> cache_lru_order;
	std::unordered_map<uint64_t, std::list<uint64_t>::iterator> cache_lru_iters;
	uint32_t cache_max_entries = 256;

	std::atomic<bool>  batch_running{false};
	std::atomic<int>   batch_total{0};
	std::atomic<int>   batch_done{0};
	std::vector<uint64_t> batch_queue;

	std::atomic<const DisasmFile*> file_fallback{nullptr};

	std::atomic<bool>     next_pending{false};
	std::atomic<uint64_t> next_addr{0};
	std::atomic<const DisasmFile*> next_file{nullptr};
};

inline state_t g_state;

namespace detail {

inline uint32_t crc32_byte(uint32_t c) {
	for (int j = 0; j < 8; ++j) {
		c = (c & 1u) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
	}
	return c;
}

inline uint32_t crc32_table_at(uint32_t i) {
	return crc32_byte(i);
}

inline uint32_t crc32_compute(const void* data, size_t len) {
	const uint8_t* p = static_cast<const uint8_t*>(data);
	uint32_t crc = 0xFFFFFFFFu;
	for (size_t i = 0; i < len; ++i) {
		uint32_t idx = (crc ^ p[i]) & 0xFFu;
		crc = (crc >> 8) ^ crc32_table_at(idx);
	}
	return crc ^ 0xFFFFFFFFu;
}

inline void cache_touch_lru_locked(uint64_t addr) {
	auto it = g_state.cache_lru_iters.find(addr);
	if (it == g_state.cache_lru_iters.end()) return;
	g_state.cache_lru_order.erase(it->second);
	g_state.cache_lru_order.push_back(addr);
	auto last = g_state.cache_lru_order.end();
	--last;
	it->second = last;
}

inline void cache_evict_lru_locked() {
	if (g_state.cache_lru_order.empty()) return;
	uint64_t victim = g_state.cache_lru_order.front();
	g_state.cache_lru_order.pop_front();
	g_state.cache_lru_iters.erase(victim);
	g_state.cache.erase(victim);
}

inline void cache_insert_lru_locked(uint64_t addr, decompile_result_t&& r) {
	auto cit = g_state.cache.find(addr);
	if (cit != g_state.cache.end()) {
		cit->second = std::move(r);
		cache_touch_lru_locked(addr);
		return;
	}
	g_state.cache.emplace(addr, std::move(r));
	g_state.cache_lru_order.push_back(addr);
	auto last = g_state.cache_lru_order.end();
	--last;
	g_state.cache_lru_iters[addr] = last;
	while (g_state.cache.size() > g_state.cache_max_entries) {
		cache_evict_lru_locked();
	}
}

inline std::string get_cache_dir()
{
	const char* appdata = std::getenv("APPDATA");
	if (!appdata) return {};
	return std::string(appdata) + "\\AiDA\\Standalone\\decompiler_cache";
}

inline std::string canonical_serialize(const decompile_result_t& r) {
	nlohmann::json j;
	j["function_addr"] = r.function_addr;
	j["function_name"] = r.function_name;
	j["pseudocode"] = r.pseudocode;
	j["parameters"] = r.parameters;
	j["callees"] = r.callees;
	return j.dump();
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

	std::string canonical_payload = canonical_serialize(result);
	uint32_t crc = crc32_compute(canonical_payload.data(), canonical_payload.size());

	nlohmann::json j;
	j["version"] = 2;
	j["crc32"] = crc;
	j["payload"] = nlohmann::json::parse(canonical_payload, nullptr, false);
	if (j["payload"].is_discarded()) {
		return;
	}

	std::string tmp_fname = std::string(fname) + ".tmp";
	{
		std::ofstream ofs(tmp_fname, std::ios::binary | std::ios::trunc);
		if (!ofs.is_open()) return;
		std::string out = j.dump(2);
		ofs.write(out.data(), static_cast<std::streamsize>(out.size()));
		if (!ofs) {
			ofs.close();
			std::error_code rm_ec;
			std::filesystem::remove(tmp_fname, rm_ec);
			return;
		}
	}

	if (!::MoveFileExA(tmp_fname.c_str(), fname,
	                    MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
		std::error_code rm_ec;
		std::filesystem::remove(tmp_fname, rm_ec);
	}
}

inline void save_all_cache_to_disk()
{
	std::vector<std::pair<uint64_t, decompile_result_t>> snapshot;
	{
		std::lock_guard<std::mutex> lk(g_state.mutex);
		snapshot.reserve(g_state.cache.size());
		for (auto& [addr, result] : g_state.cache) {
			snapshot.emplace_back(addr, result);
		}
	}
	for (auto& [addr, result] : snapshot) {
		save_cache_entry_to_disk(addr, result);
	}
}

}

inline bool validate_decompile_result(const decompile_result_t& r,
                                       uint64_t expected_addr,
                                       std::string* out_reason)
{
	auto fail = [out_reason](const char* msg) -> bool {
		if (out_reason) *out_reason = msg;
		return false;
	};

	if (r.function_addr != expected_addr) {
		return fail("function_addr does not match expected address");
	}
	if (r.function_addr == 0xDEADBEEFull) {
		return fail("function_addr is sentinel 0xDEADBEEF");
	}
	if (r.function_name.empty() && !r.is_error) {
		return fail("function_name is empty");
	}
	if (r.complete && !r.is_error) {
		if (r.pseudocode.empty()) {
			return fail("complete result has empty pseudocode");
		}
	}
	int last_line = -1;
	for (auto& kv : r.line_addr_map) {
		if (kv.first < last_line) {
			return fail("line_addr_map line numbers not monotonic");
		}
		last_line = kv.first;
		if (kv.second == 0xDEADBEEFull) {
			return fail("line_addr_map contains sentinel address");
		}
	}
	for (auto& kv : r.callee_targets) {
		if (kv.second == 0xDEADBEEFull) {
			return fail("callee_targets contains sentinel address");
		}
	}
	return true;
}

namespace detail {

inline void load_cache_from_disk()
{
	std::string dir = get_cache_dir();
	if (dir.empty()) return;

	std::error_code ec;
	if (!std::filesystem::exists(dir, ec)) return;

	std::vector<std::filesystem::path> to_delete;

	for (auto& entry : std::filesystem::directory_iterator(dir, ec)) {
		if (ec) break;
		if (!entry.is_regular_file()) continue;
		if (entry.path().extension() != ".json") continue;

		std::ifstream ifs(entry.path(), std::ios::binary);
		if (!ifs.is_open()) continue;

		std::string content((std::istreambuf_iterator<char>(ifs)),
		                    std::istreambuf_iterator<char>());
		ifs.close();

		auto j = nlohmann::json::parse(content, nullptr, false);
		if (j.is_discarded()) {
			to_delete.push_back(entry.path());
			continue;
		}

		if (!j.contains("version") || !j["version"].is_number_integer() ||
		    j["version"].get<int>() < 2) {
			to_delete.push_back(entry.path());
			continue;
		}

		if (!j.contains("crc32") || !j["crc32"].is_number_unsigned() ||
		    !j.contains("payload") || !j["payload"].is_object()) {
			to_delete.push_back(entry.path());
			continue;
		}

		uint32_t stored_crc = j["crc32"].get<uint32_t>();
		std::string canonical_payload = j["payload"].dump();
		uint32_t computed_crc = crc32_compute(canonical_payload.data(),
		                                       canonical_payload.size());
		if (stored_crc != computed_crc) {
			to_delete.push_back(entry.path());
			continue;
		}

		const auto& payload = j["payload"];
		decompile_result_t result;
		result.function_addr = payload.value("function_addr", uint64_t(0));
		result.function_name = payload.value("function_name", std::string{});
		result.pseudocode = payload.value("pseudocode", std::string{});
		result.parameters = payload.value("parameters", std::string{});
		if (payload.contains("callees") && payload["callees"].is_array()) {
			for (auto& c : payload["callees"]) {
				if (c.is_string())
					result.callees.push_back(c.get<std::string>());
			}
		}
		result.complete = true;

		if (result.function_addr == 0 || result.pseudocode.empty()) {
			to_delete.push_back(entry.path());
			continue;
		}

		std::string reason;
		if (!validate_decompile_result(result, result.function_addr, &reason)) {
			diag::log_tagged_critical_fmt("dec",
				"load_cache_from_disk_validate_fail addr=0x%llX reason=%s",
				static_cast<unsigned long long>(result.function_addr),
				reason.c_str());
			to_delete.push_back(entry.path());
			continue;
		}

		{
			std::lock_guard<std::mutex> lk(g_state.mutex);
			if (g_state.cache.find(result.function_addr) == g_state.cache.end()) {
				uint64_t addr_key = result.function_addr;
				cache_insert_lru_locked(addr_key, std::move(result));
			}
		}
	}

	for (auto& p : to_delete) {
		std::error_code rm_ec;
		std::filesystem::remove(p, rm_ec);
	}
}

inline bool derive_function_extents(uint64_t func_addr,
                                     uint64_t* out_start,
                                     uint64_t* out_end)
{
	if (function_index::func_extent(func_addr, out_start, out_end)) {
		return true;
	}
	if (out_start) *out_start = func_addr;
	if (out_end) *out_end = func_addr + 0x40000ull;
	return false;
}

inline size_t plan_preread_size(uint64_t func_addr)
{
	uint64_t start = 0;
	uint64_t end = 0;
	derive_function_extents(func_addr, &start, &end);
	uint64_t span = (end > start) ? (end - start) : 0x40000ull;
	if (span > 0x40000ull) {
		uint64_t padded = span + 0x1000ull;
		if (padded > 0x400000ull) padded = 0x400000ull;
		return static_cast<size_t>(padded);
	}
	return static_cast<size_t>(0x40000ull);
}

}

inline void cancel_decompile()
{
	diag::log_tagged_critical("dec", "cancel_decompile_enter");
	g_state.cancel.store(true);
	diag::log_tagged_critical("dec", "cancel_decompile_exit");
}

inline void decompile_function_native(uint64_t func_addr, const DisasmFile* file_fallback = nullptr) {
	uint32_t dfn_pid = driver_bridge::attached_pid();
	diag::log_tagged_critical_fmt("dec", "decompile_function_native_enter addr=0x%llX pid=%u file_fallback=%p",
		static_cast<unsigned long long>(func_addr), dfn_pid,
		static_cast<const void*>(file_fallback));

	if (file_fallback) {
		g_state.file_fallback.store(file_fallback, std::memory_order_release);
	}
	const DisasmFile* effective_file = file_fallback
		? file_fallback
		: g_state.file_fallback.load(std::memory_order_acquire);

	if (g_state.decompiling.load()) {
		g_state.next_addr.store(func_addr, std::memory_order_release);
		g_state.next_file.store(file_fallback, std::memory_order_release);
		g_state.next_pending.store(true, std::memory_order_release);
		diag::log_tagged_critical_fmt("dec", "decompile_function_native_queued addr=0x%llX reason=already_decompiling",
			static_cast<unsigned long long>(func_addr));
		return;
	}

	diag::log_tagged_critical_fmt("dec", "decompile_function_native_pre_cache_lock addr=0x%llX",
		static_cast<unsigned long long>(func_addr));
	{
		std::lock_guard<std::mutex> lk(g_state.mutex);
		diag::log_tagged_critical_fmt("dec", "decompile_function_native_post_cache_lock addr=0x%llX",
			static_cast<unsigned long long>(func_addr));
		auto cache_it = g_state.cache.find(func_addr);
		if (cache_it != g_state.cache.end()) {
			g_state.current = cache_it->second;
			g_state.active = true;
			detail::cache_touch_lru_locked(func_addr);
			if (g_state.history_pos < 0 ||
			    g_state.history_pos >= static_cast<int>(g_state.history.size()) ||
			    g_state.history[g_state.history_pos].addr != func_addr) {
				if (g_state.history_pos + 1 < static_cast<int>(g_state.history.size()))
					g_state.history.erase(g_state.history.begin() + g_state.history_pos + 1,
					                      g_state.history.end());
				g_state.history.push_back({func_addr, g_state.current.function_name});
				g_state.history_pos = static_cast<int>(g_state.history.size()) - 1;
			}
			diag::log_tagged_critical_fmt("dec", "decompile_function_native_exit addr=0x%llX reason=cache_hit",
				static_cast<unsigned long long>(func_addr));
			return;
		}
	}

	g_state.decompiling.store(true);
	g_state.cancel.store(false);

	{
		std::lock_guard<std::mutex> lk(g_state.mutex);
		g_state.current = {};
		g_state.current.function_addr = func_addr;
		g_state.active = true;

		char name[64];
		snprintf(name, sizeof(name), "sub_%llX", static_cast<unsigned long long>(func_addr));
		g_state.current.function_name = name;
	}

	diag::log_tagged_critical_fmt("dec", "decompile_function_native_pre_thread_spawn addr=0x%llX",
		static_cast<unsigned long long>(func_addr));

	auto worker = [func_addr, effective_file]() {
		diag::log_tagged_critical_fmt("dec", "decompile_function_native_lambda_enter addr=0x%llX tid=%lu",
			static_cast<unsigned long long>(func_addr),
			static_cast<unsigned long>(GetCurrentThreadId()));

		auto publish_error = [func_addr](const std::string& msg) {
			std::lock_guard<std::mutex> lk(g_state.mutex);
			g_state.current.function_addr = func_addr;
			g_state.current.is_error = true;
			g_state.current.error_text = msg;
			g_state.current.complete = true;
			g_state.decompiling.store(false);
			g_state.init_progress_active.store(false, std::memory_order_release);
		};

		try {
			if (!ghidra_decompiler::g_state.initialized.load(std::memory_order_acquire)) {
				g_state.init_progress_active.store(true, std::memory_order_release);
			}
			auto PREREAD_SIZE = detail::plan_preread_size(func_addr);
			std::vector<uint8_t> mem;
			uint32_t pid_now = driver_bridge::attached_pid();
			bool has_static = (effective_file && effective_file->loaded
			                   && !effective_file->sections.empty());

			diag::log_tagged_critical_fmt("dec", "decompile_function_native_pre_read_memory addr=0x%llX size=%llu pid=%u has_static=%d",
				static_cast<unsigned long long>(func_addr),
				static_cast<unsigned long long>(static_cast<uint64_t>(PREREAD_SIZE)),
				pid_now,
				has_static ? 1 : 0);
			driver_bridge::read_memory(func_addr, PREREAD_SIZE, mem);
			diag::log_tagged_critical_fmt("dec", "decompile_function_native_post_read_memory addr=0x%llX bytes=%llu",
				static_cast<unsigned long long>(func_addr),
				static_cast<unsigned long long>(mem.size()));

			if (mem.empty() && has_static) {
				diag::log_tagged_critical_fmt("dec", "decompile_function_native_pre_static_read addr=0x%llX size=%llu",
					static_cast<unsigned long long>(func_addr),
					static_cast<unsigned long long>(static_cast<uint64_t>(PREREAD_SIZE)));
				static_analysis::read_bytes_from_pe(*effective_file, func_addr, PREREAD_SIZE, mem);
				diag::log_tagged_critical_fmt("dec", "decompile_function_native_post_static_read addr=0x%llX bytes=%llu",
					static_cast<unsigned long long>(func_addr),
					static_cast<unsigned long long>(mem.size()));
			}

			if (mem.empty()) {
				uint32_t pid_post = driver_bridge::attached_pid();
				std::string err;
				if (pid_post != 0 && has_static) {
					err = "no executable bytes at this address (driver returned 0 bytes and address is outside loaded PE sections)";
				} else if (pid_post != 0) {
					err = "driver returned no bytes at this address (load a PE file via File > Open to enable static fallback)";
				} else if (has_static) {
					err = "address is outside the loaded PE's executable sections";
				} else if (effective_file && effective_file->loaded) {
					err = "driver session lost - re-attach via File > Attach, or open the PE on disk via File > Open";
				} else {
					err = "no source available: open a PE file via File > Open or attach a process via File > Attach";
				}
				publish_error(err);
				diag::log_tagged_critical_fmt("dec", "decompile_function_native_exit addr=0x%llX reason=read_failed pid_post=%u has_static=%d",
					static_cast<unsigned long long>(func_addr),
					pid_post,
					has_static ? 1 : 0);
				return;
			}

			diag::log_tagged_critical_fmt("dec", "decompile_function_native_pre_decompile_buffer addr=0x%llX bytes=%llu",
				static_cast<unsigned long long>(func_addr),
				static_cast<unsigned long long>(mem.size()));
			auto ghidra_result = ghidra_decompiler::decompile_buffer(
				mem.data(), mem.size(), func_addr, func_addr,
				&g_state.cancel, effective_file);
			g_state.init_progress_active.store(false, std::memory_order_release);
			diag::log_tagged_critical_fmt("dec", "decompile_function_native_post_decompile_buffer addr=0x%llX ok=%d err=%d ps_len=%llu annot=%llu",
				static_cast<unsigned long long>(func_addr),
				ghidra_result.complete ? 1 : 0,
				ghidra_result.is_error ? 1 : 0,
				static_cast<unsigned long long>(ghidra_result.pseudocode.size()),
				static_cast<unsigned long long>(ghidra_result.annotations.size()));

			if (g_state.cancel.load()) {
				publish_error("decompilation cancelled");
				diag::log_tagged_critical_fmt("dec", "decompile_function_native_exit addr=0x%llX reason=cancelled",
					static_cast<unsigned long long>(func_addr));
				return;
			}

			decompile_result_t staged;
			staged.function_addr = func_addr;
			staged.function_name = ghidra_result.function_name;
			staged.pseudocode = ghidra_result.pseudocode;
			staged.annotations = ghidra_result.annotations;
			staged.line_addr_map = ghidra_result.line_to_address;
			staged.callees.clear();
			staged.callee_targets = ghidra_result.callees;
			for (auto& kv : ghidra_result.callees)
				staged.callees.push_back(kv.first);
			staged.sleigh_id = ghidra_result.sleigh_id;
			staged.complete = ghidra_result.complete || ghidra_result.is_error;
			staged.is_error = ghidra_result.is_error;
			staged.error_text = ghidra_result.error_text;

			if (!staged.is_error) {
				std::string reason;
				if (!validate_decompile_result(staged, func_addr, &reason)) {
					diag::log_tagged_critical_fmt("dec",
						"decompile_function_native_validate_fail addr=0x%llX reason=%s",
						static_cast<unsigned long long>(func_addr),
						reason.c_str());
					staged.is_error = true;
					staged.complete = true;
					staged.error_text = std::string("decompiler produced invalid output: ") + reason;
				}
			}

			decompile_result_t native_persist_copy;
			bool native_persist_ok = false;
			{
				std::lock_guard<std::mutex> lk(g_state.mutex);
				g_state.current = staged;

				if (!g_state.current.is_error) {
					native_persist_copy = g_state.current;
					native_persist_ok = true;
					decompile_result_t to_cache = g_state.current;
					detail::cache_insert_lru_locked(func_addr, std::move(to_cache));
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
			}
			if (native_persist_ok) {
				detail::save_cache_entry_to_disk(func_addr, native_persist_copy);
			}
			diag::log_tagged_critical_fmt("dec", "decompile_function_native_published addr=0x%llX reason=normal",
				static_cast<unsigned long long>(func_addr));
		}
		catch (const std::exception& ex) {
			publish_error(std::string("decompiler threw: ") + ex.what());
			diag::log_tagged_critical_fmt("dec", "decompile_function_native_exit addr=0x%llX reason=std_exception err=%s",
				static_cast<unsigned long long>(func_addr), ex.what());
		}
		catch (...) {
			publish_error("decompiler threw an unknown exception");
			diag::log_tagged_critical_fmt("dec", "decompile_function_native_exit addr=0x%llX reason=unknown_exception",
				static_cast<unsigned long long>(func_addr));
		}
	};

	auto worker_with_drain = [worker]() mutable {
		worker();
		if (g_state.next_pending.load(std::memory_order_acquire)) {
			uint64_t na = g_state.next_addr.load(std::memory_order_acquire);
			const DisasmFile* nf = g_state.next_file.load(std::memory_order_acquire);
			g_state.next_pending.store(false, std::memory_order_release);
			if (na != 0)
				decompile_function_native(na, nf);
		}
	};

	if (!work_queue::post(std::move(worker_with_drain))) {
		diag::log_tagged_critical_fmt("dec",
			"decompile_function_native_dispatch_failed addr=0x%llX reason=work_queue_unavailable",
			static_cast<unsigned long long>(func_addr));
		std::lock_guard<std::mutex> lk(g_state.mutex);
		g_state.current.function_addr = func_addr;
		g_state.current.is_error = true;
		g_state.current.error_text = "work queue not available";
		g_state.current.complete = true;
		g_state.decompiling.store(false);
		return;
	}
	diag::log_tagged_critical_fmt("dec", "decompile_function_native_post_thread_spawn addr=0x%llX",
		static_cast<unsigned long long>(func_addr));
}

inline void navigate_back()
{
	diag::log_tagged_critical_fmt("dec", "navigate_back_enter history_pos=%d size=%llu",
		g_state.history_pos,
		static_cast<unsigned long long>(g_state.history.size()));
	if (g_state.history_pos > 0) {
		g_state.history_pos--;
		auto& entry = g_state.history[g_state.history_pos];
		diag::log_tagged_critical_fmt("dec", "navigate_back_calling_decompile addr=0x%llX",
			static_cast<unsigned long long>(entry.addr));
		decompile_function_native(entry.addr);
	}
	diag::log_tagged_critical("dec", "navigate_back_exit");
}

inline void navigate_forward()
{
	diag::log_tagged_critical_fmt("dec", "navigate_forward_enter history_pos=%d size=%llu",
		g_state.history_pos,
		static_cast<unsigned long long>(g_state.history.size()));
	if (g_state.history_pos + 1 < static_cast<int>(g_state.history.size())) {
		g_state.history_pos++;
		auto& entry = g_state.history[g_state.history_pos];
		diag::log_tagged_critical_fmt("dec", "navigate_forward_calling_decompile addr=0x%llX",
			static_cast<unsigned long long>(entry.addr));
		decompile_function_native(entry.addr);
	}
	diag::log_tagged_critical("dec", "navigate_forward_exit");
}

inline void clear_cache()
{
	std::lock_guard<std::mutex> lk(g_state.mutex);
	g_state.cache.clear();
	g_state.cache_lru_order.clear();
	g_state.cache_lru_iters.clear();
}

inline void erase_cache_entry(uint64_t addr)
{
	std::lock_guard<std::mutex> lk(g_state.mutex);
	auto it = g_state.cache_lru_iters.find(addr);
	if (it != g_state.cache_lru_iters.end()) {
		g_state.cache_lru_order.erase(it->second);
		g_state.cache_lru_iters.erase(it);
	}
	g_state.cache.erase(addr);
}

inline size_t cache_size()
{
	std::lock_guard<std::mutex> lk(g_state.mutex);
	return g_state.cache.size();
}

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

	if (!work_queue::post([addresses]() {
		if (addresses.empty()) {
			g_state.batch_running.store(false);
			return;
		}


		uint64_t min_addr = *std::min_element(addresses.begin(), addresses.end());
		uint64_t max_addr = *std::max_element(addresses.begin(), addresses.end());

		constexpr size_t TAIL_SIZE = 0x40000;
		size_t total_size = static_cast<size_t>(max_addr - min_addr) + TAIL_SIZE;
		if (total_size > 0x10000000) total_size = 0x10000000;


		std::vector<uint8_t> module_mem;
		driver_bridge::read_memory(min_addr, total_size, module_mem);

		if (module_mem.empty()) {
			g_state.batch_running.store(false);
			return;
		}


		std::vector<ghidra_decompiler::ghidra_result_t> results;
		const DisasmFile* batch_file = g_state.file_fallback.load(std::memory_order_acquire);
		ghidra_decompiler::batch_decompile(
			module_mem.data(), module_mem.size(), min_addr,
			addresses, results,
			&g_state.batch_done, &g_state.cancel,
			batch_file);


		{
			std::lock_guard<std::mutex> lk(g_state.mutex);
			for (size_t i = 0; i < results.size(); ++i) {
				if (results[i].complete && !results[i].is_error) {
					decompile_result_t dr;
					dr.function_addr = results[i].function_addr;
					dr.function_name = results[i].function_name;
					dr.pseudocode = results[i].pseudocode;
					dr.annotations = results[i].annotations;
					dr.line_addr_map = results[i].line_to_address;
					dr.callee_targets = results[i].callees;
					dr.callees.clear();
					for (auto& kv : results[i].callees)
						dr.callees.push_back(kv.first);
					dr.sleigh_id = results[i].sleigh_id;
					dr.complete = true;
					std::string reason;
					if (validate_decompile_result(dr, dr.function_addr, &reason)) {
						uint64_t addr_key = dr.function_addr;
						detail::cache_insert_lru_locked(addr_key, std::move(dr));
					} else {
						diag::log_tagged_critical_fmt("dec",
							"batch_decompile_validate_fail addr=0x%llX reason=%s",
							static_cast<unsigned long long>(results[i].function_addr),
							reason.c_str());
					}
				}
			}
		}

		g_state.batch_running.store(false);
		g_state.decompiling.store(false);
	})) {
		diag::log_tagged_critical("dec",
			"batch_decompile_native_dispatch_failed reason=work_queue_unavailable");
		g_state.batch_running.store(false);
	}
}

}
