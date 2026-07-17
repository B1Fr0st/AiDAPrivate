#pragma once

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../../preview/scan_decrypt_preview.hpp"
#else

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_set>
#include <utility>
#include <vector>

#include "../infra/executor.hpp"
#include "standalone_driver.hpp"
#include "xref_engine.hpp"

#ifdef __NT__
#include "emulation_engine.hpp"
#endif

namespace decrypt_oracle {

inline constexpr std::size_t maximum_results = 65536;

struct decrypted_string_t {
	uint64_t    source_function = 0;
	uint64_t    xref_addr = 0;
	uint64_t    encrypted_offset = 0;
	uint64_t    write_addr = 0;
	std::string decrypted;
	int         length = 0;
	float       confidence = 0.f;
	bool        is_utf16 = false;
	int         insn_count = 0;
	int         mem_writes = 0;
};

struct scan_config_t {
	uint64_t region_address = 0;
	uint64_t region_size = 0;
	uint32_t max_instructions = 50000;
	uint32_t timeout_ms = 5000;
	int      min_string_length = 4;
	float    min_printable_ratio = 0.75f;
};

struct state_t {
	std::vector<decrypted_string_t> results;
	std::shared_ptr<const std::vector<decrypted_string_t>> published_results =
		std::make_shared<const std::vector<decrypted_string_t>>();
	std::mutex mutex;
	std::atomic<bool> scanning{false};
	std::atomic<bool> cancel{false};
	std::atomic<bool> timed_out{false};
	std::atomic<float> progress{0.f};
	std::atomic<int> total_xrefs{0};
	std::atomic<int> processed_xrefs{0};
	scan_config_t config;
	char address_input[32] = {};
	char size_input[16] = "4096";
	std::string status_text;
};

inline state_t g_state;

inline std::shared_ptr<const std::vector<decrypted_string_t>> capture_results()
{
	return std::atomic_load_explicit(&g_state.published_results, std::memory_order_acquire);
}

namespace detail {

inline bool is_printable_ascii(uint8_t c)
{
	return c >= 0x20 && c <= 0x7E;
}

inline bool is_printable_utf16(uint16_t c)
{
	return c >= 0x20 && c <= 0x7E;
}

inline std::string try_extract_ascii(const std::vector<uint8_t>& data, uint64_t addr,
                                     uint64_t write_addr, int min_len, float min_ratio)
{
	if (data.empty()) return {};

	uint64_t offset = 0;
	if (write_addr >= addr && write_addr < addr + data.size()) {
		offset = write_addr - addr;
	}

	int printable = 0;
	int total = 0;
	std::string candidate;

	for (uint64_t i = offset; i < data.size() && total < 2048; ++i) {
		uint8_t c = data[static_cast<size_t>(i)];
		if (c == 0) break;
		++total;
		if (is_printable_ascii(c)) ++printable;
		candidate += static_cast<char>(c);
	}

	if (total < min_len) return {};
	if (total == 0) return {};
	float ratio = static_cast<float>(printable) / static_cast<float>(total);
	if (ratio < min_ratio) return {};

	return candidate;
}

inline std::string try_extract_utf16(const std::vector<uint8_t>& data, uint64_t addr,
                                      uint64_t write_addr, int min_len, float min_ratio)
{
	if (data.size() < 4) return {};

	uint64_t offset = 0;
	if (write_addr >= addr && write_addr < addr + data.size()) {
		offset = write_addr - addr;
	}
	if (offset % 2 != 0) return {};

	int printable = 0;
	int total = 0;
	std::string candidate;

	for (uint64_t i = offset; i + 1 < data.size() && total < 2048; i += 2) {
		uint16_t wc = 0;
		std::memcpy(&wc, data.data() + i, 2);
		if (wc == 0) break;
		++total;
		if (is_printable_utf16(wc)) {
			++printable;
			candidate += static_cast<char>(wc & 0xFF);
		} else {
			candidate += '?';
		}
	}

	if (total < min_len) return {};
	if (total == 0) return {};
	float ratio = static_cast<float>(printable) / static_cast<float>(total);
	if (ratio < min_ratio) return {};

	return candidate;
}

inline uint64_t find_function_start(uint64_t addr)
{
	for (uint64_t scan = addr; scan > addr - 0x1000 && scan > 0x1000; --scan) {
		std::vector<uint8_t> bytes;
		driver_bridge::read_memory(scan, 4, bytes);
		if (bytes.size() < 4) continue;

		if (bytes[0] == 0xCC && bytes[1] != 0xCC) {
			return scan + 1;
		}

		if (bytes[0] == 0x40 && bytes[1] == 0x53) return scan;
		if (bytes[0] == 0x40 && bytes[1] == 0x55) return scan;
		if (bytes[0] == 0x40 && bytes[1] == 0x56) return scan;
		if (bytes[0] == 0x40 && bytes[1] == 0x57) return scan;
		if (bytes[0] == 0x48 && bytes[1] == 0x89 && bytes[2] == 0x5C) return scan;
		if (bytes[0] == 0x48 && bytes[1] == 0x8B && bytes[2] == 0xC4) return scan;
		if (bytes[0] == 0x48 && bytes[1] == 0x83 && bytes[2] == 0xEC) return scan;
		if (bytes[0] == 0x48 && bytes[1] == 0x81 && bytes[2] == 0xEC) return scan;
		if (bytes[0] == 0x55 && bytes[1] == 0x48 && bytes[2] == 0x8B && bytes[3] == 0xEC) return scan;

		if (scan > 0 && scan < addr) {
			std::vector<uint8_t> prev_bytes;
			driver_bridge::read_memory(scan - 1, 1, prev_bytes);
			if (!prev_bytes.empty() && prev_bytes[0] == 0xC3 &&
			    bytes[0] != 0xC3 && bytes[0] != 0xCC) {
				return scan;
			}
		}
	}
	return addr;
}

inline std::vector<decrypted_string_t> collect_plaintext_candidates(uint64_t region_address, uint64_t region_size,
	int min_len, float min_ratio)
{
	std::vector<decrypted_string_t> out;
	if (region_address == 0 || region_size == 0)
		return out;
	const uint64_t read_size64 = (std::min)(region_size, 1024ull * 1024ull);
	std::vector<uint8_t> data;
	if (!driver_bridge::read_memory(region_address, static_cast<size_t>(read_size64), data) || data.empty())
		return out;
	size_t i = 0;
	while (i < data.size() && out.size() < 128) {
		while (i < data.size() && !is_printable_ascii(data[i]))
			++i;
		const size_t start = i;
		while (i < data.size() && is_printable_ascii(data[i]) && i - start < 2048)
			++i;
		const size_t len = i - start;
		if (len >= static_cast<size_t>((std::max)(min_len, 1))) {
			float ratio = 1.0f;
			if (ratio >= min_ratio) {
				decrypted_string_t ds;
				ds.source_function = 0;
				ds.xref_addr = 0;
				ds.encrypted_offset = static_cast<uint64_t>(start);
				ds.write_addr = region_address + static_cast<uint64_t>(start);
				ds.decrypted.assign(reinterpret_cast<const char*>(data.data() + start), len);
				ds.length = static_cast<int>(len);
				ds.confidence = ratio;
				ds.is_utf16 = false;
				ds.insn_count = 0;
				ds.mem_writes = 0;
				out.push_back(std::move(ds));
			}
		}
		if (i == start)
			++i;
	}
	return out;
}

}

inline void scan_and_decrypt(uint64_t region_address, uint64_t region_size, uint32_t timeout_ms = 5000,
	uint64_t search_start = 0, uint64_t search_size = 0)
{
#ifdef __NT__
	if (g_state.scanning.load()) return;
	g_state.scanning.store(true);
	g_state.cancel.store(false);
	g_state.timed_out.store(false);
	g_state.progress.store(0.f);
	g_state.total_xrefs.store(0);
	g_state.processed_xrefs.store(0);

	{
		std::lock_guard<std::mutex> lk(g_state.mutex);
		g_state.results.clear();
		std::atomic_store_explicit(&g_state.published_results,
			std::make_shared<const std::vector<decrypted_string_t>>(), std::memory_order_release);
		g_state.status_text = "Scanning xrefs...";
	}

	g_state.config.region_address = region_address;
	g_state.config.region_size = region_size;
	g_state.config.timeout_ms = timeout_ms == 0 ? 5000 : timeout_ms;

	auto worker = [region_address, region_size, search_start, search_size]() {
		uint32_t pid = driver_bridge::attached_pid();
		if (pid == 0) {
			std::lock_guard<std::mutex> lk(g_state.mutex);
			g_state.status_text = "Not attached to a process";
			g_state.scanning.store(false);
			return;
		}

		auto threads = driver_bridge::enumerate_threads();
		uint32_t tid = threads.empty() ? 0 : threads[0].tid;

		std::vector<xref_engine::xref_t> xrefs;
		auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(g_state.config.timeout_ms);
		if (search_start != 0 && search_size != 0)
			xref_engine::find_xrefs_to(region_address, search_start, search_size);
		else
			xref_engine::find_xrefs_to(region_address);

		while (xref_engine::is_scanning() && std::chrono::steady_clock::now() < deadline) {
			std::this_thread::sleep_for(std::chrono::milliseconds(50));
			if (g_state.cancel.load()) {
				xref_engine::cancel_scan();
				g_state.scanning.store(false);
				return;
			}
		}
		if (xref_engine::is_scanning()) {
			g_state.timed_out.store(true);
			xref_engine::cancel_scan();
			g_state.scanning.store(false);
			return;
		}

		{
			std::lock_guard<std::mutex> xlk(xref_engine::g_state.mutex);
			xrefs = xref_engine::g_state.results;
		}

		if (xrefs.empty()) {
			auto candidates = detail::collect_plaintext_candidates(region_address, region_size,
				g_state.config.min_string_length, g_state.config.min_printable_ratio);
			std::lock_guard<std::mutex> lk(g_state.mutex);
			if (!candidates.empty()) {
				g_state.results = std::move(candidates);
				std::atomic_store_explicit(&g_state.published_results,
					std::make_shared<const std::vector<decrypted_string_t>>(g_state.results),
					std::memory_order_release);
				g_state.status_text = "No xrefs found; reported plaintext candidates already present in region";
			} else {
				g_state.status_text = "No xrefs found to target region";
			}
			g_state.scanning.store(false);
			return;
		}

		g_state.total_xrefs.store(static_cast<int>(xrefs.size()));

		{
			std::lock_guard<std::mutex> lk(g_state.mutex);
			g_state.status_text = "Emulating " + std::to_string(xrefs.size()) + " xref targets...";
		}

		std::map<uint64_t, bool> processed_functions;
		std::unordered_set<std::string> seen_results;
		int processed = 0;

		for (auto& xref : xrefs) {
			if (g_state.cancel.load()) break;
			auto now = std::chrono::steady_clock::now();
			if (now >= deadline) {
				g_state.timed_out.store(true);
				g_state.cancel.store(true);
				break;
			}

			uint64_t func_start = detail::find_function_start(xref.from_addr);

			if (processed_functions.count(func_start)) {
				++processed;
				g_state.processed_xrefs.store(processed);
				g_state.progress.store(static_cast<float>(processed) / static_cast<float>(xrefs.size()));
				continue;
			}
			processed_functions[func_start] = true;

			emulation::emulation_config_t config;
			config.start_address = func_start;
			config.stop_address = 0;
			config.max_instructions = g_state.config.max_instructions;
			config.record_mem_reads = false;
			config.record_mem_writes = true;
			config.record_registers = false;
			config.analyze_effective_ops = false;
			uint64_t remaining_ms = static_cast<uint64_t>(
				std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count());
			if (remaining_ms == 0) remaining_ms = 1;
			if (remaining_ms > g_state.config.timeout_ms) remaining_ms = g_state.config.timeout_ms;
			config.timeout_us = remaining_ms * 1000;

			auto result = emulation::driver_snapshot_and_emulate(pid, tid, config, 0, 0);

			if (result.success && !result.mem_writes.empty()) {
				for (auto& write : result.mem_writes) {
					if (write.data.size() < static_cast<size_t>(g_state.config.min_string_length))
						continue;

					std::string ascii = detail::try_extract_ascii(
						write.data, write.address, write.address,
						g_state.config.min_string_length, g_state.config.min_printable_ratio);

					std::string utf16;
					bool found_utf16 = false;
					if (ascii.empty()) {
						utf16 = detail::try_extract_utf16(
							write.data, write.address, write.address,
							g_state.config.min_string_length, g_state.config.min_printable_ratio);
						found_utf16 = !utf16.empty();
					}

					if (ascii.empty() && utf16.empty()) continue;

					decrypted_string_t ds;
					ds.source_function = func_start;
					ds.xref_addr = xref.from_addr;
					ds.encrypted_offset = xref.to_addr - region_address;
					ds.write_addr = write.address;
					ds.decrypted = found_utf16 ? utf16 : ascii;
					ds.length = static_cast<int>(ds.decrypted.size());
					ds.is_utf16 = found_utf16;
					ds.insn_count = static_cast<int>(result.total_instructions);
					ds.mem_writes = static_cast<int>(result.mem_writes.size());

					int printable = 0;
					for (char c : ds.decrypted) {
						if (detail::is_printable_ascii(static_cast<uint8_t>(c))) ++printable;
					}
					ds.confidence = ds.length > 0
						? static_cast<float>(printable) / static_cast<float>(ds.length)
						: 0.f;

					std::string identity(sizeof(ds.write_addr), '\0');
					std::memcpy(identity.data(), &ds.write_addr, sizeof(ds.write_addr));
					identity.append(ds.decrypted);
					if (seen_results.insert(std::move(identity)).second) {
						std::lock_guard<std::mutex> lk(g_state.mutex);
						if (g_state.results.size() < maximum_results)
							g_state.results.push_back(std::move(ds));
					}
				}
			}

			++processed;
			g_state.processed_xrefs.store(processed);
			g_state.progress.store(static_cast<float>(processed) / static_cast<float>(xrefs.size()));
		}

		auto candidates = detail::collect_plaintext_candidates(region_address, region_size,
			g_state.config.min_string_length, g_state.config.min_printable_ratio);
		{
			std::lock_guard<std::mutex> lk(g_state.mutex);
			if (g_state.results.empty()) {
				if (!candidates.empty())
					g_state.results = std::move(candidates);
			}
			std::atomic_store_explicit(&g_state.published_results,
				std::make_shared<const std::vector<decrypted_string_t>>(g_state.results),
				std::memory_order_release);
			g_state.status_text = "Complete: " + std::to_string(g_state.results.size()) + " strings decrypted";
		}

		g_state.progress.store(1.f);
		g_state.scanning.store(false);
	};
	aida::infra::executor::submission_t sub;
	sub.owner_subsystem = "analysis";
	sub.label = "analysis.decrypt_oracle.scan";
	sub.thread_class = "bounded_task";
	sub.domain = aida::infra::executor::domain_t::feature_worker;
	sub.priority = 2;
	sub.body = std::move(worker);
	if (!aida::infra::executor::submit(std::move(sub)).submitted)
		g_state.scanning.store(false);
#endif
}

inline std::string export_as_json()
{
	std::lock_guard<std::mutex> lk(g_state.mutex);
	std::string out = "[\n";
	for (size_t i = 0; i < g_state.results.size(); ++i) {
		auto& r = g_state.results[i];
		char buf[1024];
		std::string escaped;
		for (char c : r.decrypted) {
			if (c == '"') escaped += "\\\"";
			else if (c == '\\') escaped += "\\\\";
			else if (c == '\n') escaped += "\\n";
			else if (c == '\r') escaped += "\\r";
			else if (c == '\t') escaped += "\\t";
			else escaped += c;
		}
		std::snprintf(buf, sizeof(buf),
			"  {\"source_function\": \"0x%llX\", \"xref\": \"0x%llX\", "
			"\"encrypted_offset\": \"0x%llX\", \"write_addr\": \"0x%llX\", "
			"\"decrypted\": \"%s\", \"length\": %d, \"confidence\": %.2f, "
			"\"utf16\": %s}%s\n",
			static_cast<unsigned long long>(r.source_function),
			static_cast<unsigned long long>(r.xref_addr),
			static_cast<unsigned long long>(r.encrypted_offset),
			static_cast<unsigned long long>(r.write_addr),
			escaped.c_str(), r.length, r.confidence,
			r.is_utf16 ? "true" : "false",
			(i + 1 < g_state.results.size()) ? "," : "");
		out += buf;
	}
	out += "]\n";
	return out;
}

}

#endif
