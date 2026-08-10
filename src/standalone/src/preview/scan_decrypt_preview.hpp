#pragma once

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include "scan_preview_runtime.hpp"

namespace decrypt_oracle {

struct decrypted_string_t {
	std::uint64_t source_function = 0;
	std::uint64_t xref_addr = 0;
	std::uint64_t encrypted_offset = 0;
	std::uint64_t write_addr = 0;
	std::string decrypted;
	int length = 0;
	float confidence = 0.f;
	bool is_utf16 = false;
	int insn_count = 0;
	int mem_writes = 0;
};

struct scan_config_t {
	std::uint64_t region_address = 0;
	std::uint64_t region_size = 0;
	std::uint32_t max_instructions = 50000;
	std::uint32_t timeout_ms = 5000;
	int min_string_length = 4;
	float min_printable_ratio = .75f;
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
	char address_input[32] = "00007FF7A4C31000";
	char size_input[16] = "4096";
	std::string status_text = "Ready to trace decryptors";
};

inline state_t g_state;

inline std::shared_ptr<const std::vector<decrypted_string_t>> capture_results()
{
	return std::atomic_load_explicit(&g_state.published_results, std::memory_order_acquire);
}

inline void scan_and_decrypt(std::uint64_t address, std::uint64_t size,
	std::uint32_t = 5000, int = 4, float = .75f)
{
	g_state.scanning.store(true);
	g_state.progress.store(.35f);
	g_state.total_xrefs.store(4);
	std::vector<decrypted_string_t> results{
		{address + 0x140, address + 0x2A8, address + 0x20, address + 0x918,
			"modules/updater/sync.dll", 24, .97f, false, 86, 3},
		{address + 0x3D0, address + 0x458, address + 0x1C0, address + 0xA40,
			"Runtime integrity verified", 26, .93f, false, 114, 5},
		{address + 0x720, address + 0x7C8, address + 0x2E0, address + 0xB10,
			"AIDA_REVERSE_SESSION", 20, .89f, true, 132, 7},
		{address + 0x940, address + 0x9F0, address + (size > 0x400 ? 0x400 : size / 2), address + 0xC60,
			"Protected command channel", 25, .84f, false, 151, 8}
	};
	{
		std::lock_guard<std::mutex> lock(g_state.mutex);
		g_state.results = std::move(results);
		std::atomic_store_explicit(&g_state.published_results,
			std::make_shared<const std::vector<decrypted_string_t>>(g_state.results),
			std::memory_order_release);
		g_state.config.region_address = address;
		g_state.config.region_size = size;
		g_state.status_text = "Recovered 4 candidate strings from 4 decryptor references";
	}
	g_state.processed_xrefs.store(4);
	g_state.progress.store(1.f);
	g_state.scanning.store(false);
	aida::preview::scan::record("decrypt.scan", std::to_string(address) + ":" + std::to_string(size));
}

inline std::string export_as_json()
{
	std::lock_guard<std::mutex> lock(g_state.mutex);
	return "{\"results\":" + std::to_string(g_state.results.size()) + "}";
}

}
