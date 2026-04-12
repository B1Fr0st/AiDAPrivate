#pragma once

#include <atomic>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "standalone_driver.hpp"
#include "zydis_disasm.hpp"

namespace stealth_engine {

struct hook_entry_t {
	uint64_t target_addr = 0;
	uint64_t trampoline_addr = 0;
	std::vector<uint8_t> original_bytes;
	int hook_size = 0;
	bool active = false;
};

struct stealth_session_t {
	uint32_t pid = 0;
	bool     peb_spoofed = false;
	bool     context_hooked = false;
	bool     rdtsc_hooked = false;
	std::vector<hook_entry_t> hooks;
	std::vector<uint64_t> allocated_regions;
};

struct state_t {
	stealth_session_t session;
	std::mutex mutex;
	std::atomic<bool> active{false};
	std::string status;
};

inline state_t g_state;

namespace detail {

inline bool spoof_peb_flags(uint32_t pid)
{
	bool ok = driver_bridge::spoof_debug_flags();
	return ok;
}

inline std::vector<uint64_t> find_rdtsc_sites(uint64_t base, uint64_t size, int max_sites)
{
	std::vector<uint64_t> sites;
	if (size == 0 || size > 0x10000000) return sites;

	std::vector<uint8_t> code;
	const uint64_t chunk_size = 0x10000;

	for (uint64_t offset = 0; offset < size && static_cast<int>(sites.size()) < max_sites; offset += chunk_size) {
		uint64_t read_size = (std::min)(chunk_size, size - offset);
		code.clear();
		driver_bridge::read_memory(base + offset, static_cast<size_t>(read_size), code);
		if (code.empty()) continue;

		for (size_t i = 0; i + 1 < code.size(); ++i) {
			if (code[i] == 0x0F && code[i + 1] == 0x31) {
				sites.push_back(base + offset + i);
				if (static_cast<int>(sites.size()) >= max_sites) break;
			}
		}
	}

	return sites;
}

inline bool install_rdtsc_hook(uint64_t rdtsc_addr, uint32_t pid, stealth_session_t& session)
{
	std::vector<uint8_t> original;
	driver_bridge::read_memory(rdtsc_addr, 16, original);
	if (original.size() < 16) return false;

	uint64_t cave = driver_bridge::allocate_memory(64, 0x40);
	if (cave == 0) return false;

	session.allocated_regions.push_back(cave);

	static uint64_t s_fake_tsc = 0x1000000000ULL;

	uint8_t shellcode[] = {
		0x50,
		0x51,
		0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x48, 0x8B, 0x00,
		0x48, 0x05, 0xA0, 0x0F, 0x00, 0x00,
		0x48, 0x89, 0xC2,
		0x48, 0xC1, 0xEA, 0x20,
		0x59,
		0x58,
		0xC3
	};

	std::memcpy(shellcode + 4, &s_fake_tsc, 8);

	std::vector<uint8_t> shellcode_vec(shellcode, shellcode + sizeof(shellcode));
	driver_bridge::write_memory(cave, shellcode_vec);

	hook_entry_t hook;
	hook.target_addr = rdtsc_addr;
	hook.trampoline_addr = cave;
	hook.original_bytes.assign(original.begin(), original.begin() + 5);
	hook.hook_size = 5;

	uint8_t jmp_patch[5];
	jmp_patch[0] = 0xE8;
	int32_t rel = static_cast<int32_t>(cave - (rdtsc_addr + 5));
	std::memcpy(jmp_patch + 1, &rel, 4);

	std::vector<uint8_t> patch_vec(jmp_patch, jmp_patch + 5);
	driver_bridge::write_memory(rdtsc_addr, patch_vec);

	hook.active = true;
	session.hooks.push_back(hook);

	return true;
}

inline void remove_hook(hook_entry_t& hook)
{
	if (!hook.active || hook.original_bytes.empty()) return;
	driver_bridge::write_memory(hook.target_addr, hook.original_bytes);
	hook.active = false;
}

}

inline bool enable_stealth(uint32_t pid)
{
	if (g_state.active.load()) return true;

	std::lock_guard<std::mutex> lk(g_state.mutex);

	g_state.session = {};
	g_state.session.pid = pid;

	bool peb_ok = detail::spoof_peb_flags(pid);
	g_state.session.peb_spoofed = peb_ok;

	std::string status_parts;
	if (peb_ok) {
		status_parts = "PEB spoofed";
	} else {
		status_parts = "PEB spoof failed";
	}

	auto modules = driver_bridge::enumerate_modules();
	driver_bridge::module_info_t main_module{};
	bool found_main = false;
	for (auto& m : modules) {
		if (m.base != 0 && !m.name.empty()) {
			std::string lower_name = m.name;
			for (auto& c : lower_name) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
			if (lower_name.find(".exe") != std::string::npos) {
				main_module = m;
				found_main = true;
				break;
			}
		}
	}

	if (found_main && main_module.size > 0) {
		auto rdtsc_sites = detail::find_rdtsc_sites(main_module.base, main_module.size, 16);
		int hooked = 0;
		for (auto addr : rdtsc_sites) {
			if (detail::install_rdtsc_hook(addr, pid, g_state.session)) {
				++hooked;
			}
		}
		if (hooked > 0) {
			g_state.session.rdtsc_hooked = true;
			status_parts += ", " + std::to_string(hooked) + " RDTSC hooks";
		}
	}

	g_state.status = "Stealth active: " + status_parts;
	g_state.active.store(true);
	return true;
}

inline void disable_stealth()
{
	if (!g_state.active.load()) return;

	std::lock_guard<std::mutex> lk(g_state.mutex);

	for (auto& hook : g_state.session.hooks) {
		detail::remove_hook(hook);
	}

	g_state.session = {};
	g_state.status = "Stealth disabled";
	g_state.active.store(false);
}

inline bool is_active()
{
	return g_state.active.load();
}

inline std::string get_status()
{
	std::lock_guard<std::mutex> lk(g_state.mutex);
	return g_state.status;
}

}
