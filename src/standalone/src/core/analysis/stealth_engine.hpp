#pragma once

#include <atomic>
#include "work_queue.hpp"
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

inline bool spoof_peb_flags()
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

	uint64_t cave = driver_bridge::allocate_memory(64);
	if (cave == 0) return false;
	driver_bridge::protect_memory(cave, 64, 0x40);

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

	bool peb_ok = detail::spoof_peb_flags();
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

inline stealth_session_t get_session_info()
{
	std::lock_guard<std::mutex> lk(g_state.mutex);
	return g_state.session;
}

enum class finding_severity_t { info, low, medium, high, critical };
enum class finding_category_t {
	anticheat_driver, memory_guard, suspicious_module,
	suspicious_thread, debug_state, hook_detection, wfp_callback
};

struct finding_t {
	finding_severity_t severity = finding_severity_t::info;
	finding_category_t category = finding_category_t::anticheat_driver;
	uint64_t address = 0;
	std::string title;
	std::string detail;
	std::string module;
};

struct scan_state_t {
	std::vector<finding_t> findings;
	std::mutex mutex;
	std::atomic<bool> scanning{false};
	std::atomic<bool> cancel{false};
	std::atomic<float> progress{0.f};
	std::string scan_status;
};

inline scan_state_t g_scan;

inline const char* severity_name(finding_severity_t s)
{
	switch (s) {
	case finding_severity_t::info:     return "Info";
	case finding_severity_t::low:      return "Low";
	case finding_severity_t::medium:   return "Medium";
	case finding_severity_t::high:     return "High";
	case finding_severity_t::critical: return "Critical";
	}
	return "Unknown";
}

inline const char* category_name(finding_category_t c)
{
	switch (c) {
	case finding_category_t::anticheat_driver:  return "AC Driver";
	case finding_category_t::memory_guard:      return "Memory Guard";
	case finding_category_t::suspicious_module: return "Suspicious Module";
	case finding_category_t::suspicious_thread: return "Thread";
	case finding_category_t::debug_state:       return "Debug State";
	case finding_category_t::hook_detection:    return "Hook";
	case finding_category_t::wfp_callback:      return "WFP Callback";
	}
	return "Unknown";
}

namespace known_ac {

struct driver_sig_t {
	const char* filename;
	const char* display_name;
	finding_severity_t severity;
};

inline const driver_sig_t signatures[] = {
	{"easyanticheat.sys",      "EasyAntiCheat",       finding_severity_t::critical},
	{"easyanticheat_eos.sys",  "EasyAntiCheat EOS",   finding_severity_t::critical},
	{"bedaisy.sys",            "BattlEye",            finding_severity_t::critical},
	{"beservice.sys",          "BattlEye Service",    finding_severity_t::critical},
	{"vgk.sys",                "Vanguard",            finding_severity_t::critical},
	{"faceit.sys",             "FACEIT AC",           finding_severity_t::critical},
	{"eseadriver2.sys",        "ESEA AC",             finding_severity_t::critical},
	{"mhyprot2.sys",           "miHoYo Protect v2",   finding_severity_t::critical},
	{"mhyprot3.sys",           "miHoYo Protect v3",   finding_severity_t::critical},
	{"ace-base.sys",           "Tencent ACE",         finding_severity_t::critical},
	{"sguard64.sys",           "Tencent SGuard",      finding_severity_t::high},
	{"tessafe.sys",            "Tencent TesSafe",     finding_severity_t::critical},
	{"atc_devmon.sys",         "nProtect GameGuard",  finding_severity_t::critical},
	{"npggsvc.sys",            "nProtect GG Service", finding_severity_t::high},
	{"wellbia.sys",            "XIGNCODE3",           finding_severity_t::critical},
	{"xhunter1.sys",           "XHUNTER",             finding_severity_t::critical},
	{"hoyoprotect.sys",        "HoYoverse Protect",   finding_severity_t::critical},
	{"uncheater.sys",          "Uncheater",           finding_severity_t::high},
	{"ricochet.sys",           "RICOCHET",            finding_severity_t::critical},
	{"iqvw64e.sys",            "Vulnerable Intel NIC", finding_severity_t::medium},
	{"amsdk.sys",              "Themida/WinLicense",   finding_severity_t::medium},
	{"denuvo64.sys",           "Denuvo",              finding_severity_t::medium},
};

inline constexpr int signature_count = sizeof(signatures) / sizeof(signatures[0]);

}

namespace detail_scan {

inline void scan_drivers(std::vector<finding_t>& out, std::atomic<bool>& cancel)
{
	auto modules = driver_bridge::enumerate_modules();
	for (auto& m : modules) {
		if (cancel.load()) return;
		if (m.name.empty()) continue;
		std::string lower = m.name;
		for (auto& c : lower) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));

		for (int i = 0; i < known_ac::signature_count; ++i) {
			if (lower.find(known_ac::signatures[i].filename) != std::string::npos) {
				finding_t f;
				f.severity = known_ac::signatures[i].severity;
				f.category = finding_category_t::anticheat_driver;
				f.address = m.base;
				f.title = std::string(known_ac::signatures[i].display_name) + " detected";
				char buf[192];
				std::snprintf(buf, sizeof(buf), "%s at 0x%llX (size: 0x%X)",
					m.name.c_str(), static_cast<unsigned long long>(m.base), m.size);
				f.detail = buf;
				f.module = m.name;
				out.push_back(std::move(f));
				break;
			}
		}
	}
}

inline void scan_memory_guards(std::vector<finding_t>& out, std::atomic<bool>& cancel)
{
	auto regions = driver_bridge::enumerate_memory_regions(4096);
	int count = 0;
	for (auto& r : regions) {
		if (cancel.load()) return;
		if (r.protect & 0x100) {
			finding_t f;
			f.severity = finding_severity_t::medium;
			f.category = finding_category_t::memory_guard;
			f.address = r.base;
			f.title = "Guard page detected";
			char buf[128];
			std::snprintf(buf, sizeof(buf), "0x%llX (size: 0x%llX, protect: 0x%X)",
				static_cast<unsigned long long>(r.base),
				static_cast<unsigned long long>(r.size), r.protect);
			f.detail = buf;
			out.push_back(std::move(f));
			if (++count >= 256) break;
		}
	}
}

inline void scan_suspicious_modules(std::vector<finding_t>& out, std::atomic<bool>& cancel)
{
	auto modules = driver_bridge::enumerate_modules();
	for (auto& m : modules) {
		if (cancel.load()) return;
		if (m.name.empty() || m.base == 0) continue;

		std::string lower = m.name;
		for (auto& c : lower) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));

		bool is_known_ac = false;
		for (int i = 0; i < known_ac::signature_count; ++i) {
			if (lower.find(known_ac::signatures[i].filename) != std::string::npos) {
				is_known_ac = true;
				break;
			}
		}
		if (is_known_ac) continue;

		bool has_ext = (lower.find(".dll") != std::string::npos ||
		                lower.find(".exe") != std::string::npos ||
		                lower.find(".sys") != std::string::npos ||
		                lower.find(".drv") != std::string::npos);

		if (!has_ext) {
			finding_t f;
			f.severity = finding_severity_t::high;
			f.category = finding_category_t::suspicious_module;
			f.address = m.base;
			f.title = "Module without standard extension";
			char buf[192];
			std::snprintf(buf, sizeof(buf), "%s at 0x%llX (size: 0x%X)",
				m.name.c_str(), static_cast<unsigned long long>(m.base), m.size);
			f.detail = buf;
			f.module = m.name;
			out.push_back(std::move(f));
		}
	}
}

inline void scan_threads(std::vector<finding_t>& out, std::atomic<bool>& cancel)
{
	auto threads = driver_bridge::enumerate_threads();
	auto modules = driver_bridge::enumerate_modules();

	for (auto& t : threads) {
		if (cancel.load()) return;
		if (t.rip == 0) continue;

		bool in_module = false;
		for (auto& m : modules) {
			if (t.rip >= m.base && t.rip < m.base + m.size) {
				in_module = true;
				break;
			}
		}

		if (!in_module) {
			finding_t f;
			f.severity = finding_severity_t::high;
			f.category = finding_category_t::suspicious_thread;
			f.address = t.rip;
			char buf[128];
			std::snprintf(buf, sizeof(buf), "TID %u executing at 0x%llX (outside known modules)",
				t.tid, static_cast<unsigned long long>(t.rip));
			f.title = "Thread outside module bounds";
			f.detail = buf;
			out.push_back(std::move(f));
		}
	}
}

inline void scan_debug_state(std::vector<finding_t>& out, std::atomic<bool>& cancel)
{
	if (cancel.load()) return;

	driver_bridge::peb_info_t peb{};
	if (driver_bridge::read_peb(peb)) {
		if (peb.being_debugged) {
			finding_t f;
			f.severity = finding_severity_t::low;
			f.category = finding_category_t::debug_state;
			f.address = peb.peb_address;
			f.title = "BeingDebugged flag set in PEB";
			char buf[64];
			std::snprintf(buf, sizeof(buf), "PEB at 0x%llX, NtGlobalFlag: 0x%X",
				static_cast<unsigned long long>(peb.peb_address), peb.nt_global_flag);
			f.detail = buf;
			out.push_back(std::move(f));
		}
		if (peb.nt_global_flag & 0x70) {
			finding_t f;
			f.severity = finding_severity_t::low;
			f.category = finding_category_t::debug_state;
			f.address = peb.peb_address;
			f.title = "Debug-related NtGlobalFlag bits set";
			char buf[64];
			std::snprintf(buf, sizeof(buf), "NtGlobalFlag: 0x%X (FLG_HEAP_ENABLE_*)",
				peb.nt_global_flag);
			f.detail = buf;
			out.push_back(std::move(f));
		}
	}

	auto threads = driver_bridge::enumerate_threads();
	if (!threads.empty()) {
		driver_bridge::thread_context_t ctx{};
		if (driver_bridge::get_thread_context(threads[0].tid, ctx)) {
			if (ctx.dr0 != 0 || ctx.dr1 != 0 || ctx.dr2 != 0 || ctx.dr3 != 0) {
				finding_t f;
				f.severity = finding_severity_t::medium;
				f.category = finding_category_t::debug_state;
				char buf[256];
				std::snprintf(buf, sizeof(buf),
					"DR0=0x%llX DR1=0x%llX DR2=0x%llX DR3=0x%llX DR7=0x%llX",
					static_cast<unsigned long long>(ctx.dr0),
					static_cast<unsigned long long>(ctx.dr1),
					static_cast<unsigned long long>(ctx.dr2),
					static_cast<unsigned long long>(ctx.dr3),
					static_cast<unsigned long long>(ctx.dr7));
				f.title = "Hardware breakpoints active";
				f.detail = buf;
				out.push_back(std::move(f));
			}
		}
	}
}

inline void scan_wfp_callbacks(std::vector<finding_t>& out, std::atomic<bool>& cancel)
{
	if (cancel.load()) return;

	auto callouts = driver_bridge::enumerate_wfp_callouts();
	for (auto& co : callouts) {
		if (cancel.load()) return;

		std::string lower = co.owning_module;
		for (auto& c : lower) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));

		bool is_system = (lower.find("tcpip.sys") != std::string::npos ||
		                  lower.find("netio.sys") != std::string::npos ||
		                  lower.find("fwpkclnt.sys") != std::string::npos ||
		                  lower.find("ndu.sys") != std::string::npos ||
		                  lower.find("mpsdrv.sys") != std::string::npos ||
		                  lower.find("wfplwfs.sys") != std::string::npos ||
		                  lower.empty());
		if (is_system) continue;

		finding_severity_t sev = finding_severity_t::medium;
		for (int i = 0; i < known_ac::signature_count; ++i) {
			if (lower.find(known_ac::signatures[i].filename) != std::string::npos) {
				sev = finding_severity_t::high;
				break;
			}
		}

		finding_t f;
		f.severity = sev;
		f.category = finding_category_t::wfp_callback;
		f.address = co.classify_fn;
		f.title = "WFP callout from " + co.owning_module;
		char buf[192];
		std::snprintf(buf, sizeof(buf), "Classify=0x%llX Notify=0x%llX Layer=%u ID=%u",
			static_cast<unsigned long long>(co.classify_fn),
			static_cast<unsigned long long>(co.notify_fn),
			co.layer_id, co.callout_id);
		f.detail = buf;
		f.module = co.owning_module;
		out.push_back(std::move(f));
	}
}

}

inline void run_protection_scan()
{
	if (g_scan.scanning.load()) return;
	g_scan.scanning.store(true);
	g_scan.cancel.store(false);
	g_scan.progress.store(0.f);

	work_queue::post([] {
		{
			std::lock_guard<std::mutex> lk(g_scan.mutex);
			g_scan.findings.clear();
			g_scan.scan_status = "Scanning drivers...";
		}

		std::vector<finding_t> results;

		g_scan.progress.store(0.05f);
		detail_scan::scan_drivers(results, g_scan.cancel);

		g_scan.progress.store(0.2f);
		{
			std::lock_guard<std::mutex> lk(g_scan.mutex);
			g_scan.scan_status = "Scanning memory regions...";
		}
		detail_scan::scan_memory_guards(results, g_scan.cancel);

		g_scan.progress.store(0.4f);
		{
			std::lock_guard<std::mutex> lk(g_scan.mutex);
			g_scan.scan_status = "Analyzing modules...";
		}
		detail_scan::scan_suspicious_modules(results, g_scan.cancel);

		g_scan.progress.store(0.55f);
		{
			std::lock_guard<std::mutex> lk(g_scan.mutex);
			g_scan.scan_status = "Inspecting threads...";
		}
		detail_scan::scan_threads(results, g_scan.cancel);

		g_scan.progress.store(0.7f);
		{
			std::lock_guard<std::mutex> lk(g_scan.mutex);
			g_scan.scan_status = "Checking debug state...";
		}
		detail_scan::scan_debug_state(results, g_scan.cancel);

		g_scan.progress.store(0.85f);
		{
			std::lock_guard<std::mutex> lk(g_scan.mutex);
			g_scan.scan_status = "Enumerating WFP callbacks...";
		}
		detail_scan::scan_wfp_callbacks(results, g_scan.cancel);

		std::sort(results.begin(), results.end(), [](const finding_t& a, const finding_t& b) {
			return static_cast<int>(a.severity) > static_cast<int>(b.severity);
		});

		{
			std::lock_guard<std::mutex> lk(g_scan.mutex);
			g_scan.findings = std::move(results);
			char buf[64];
			std::snprintf(buf, sizeof(buf), "Scan complete: %zu findings", g_scan.findings.size());
			g_scan.scan_status = buf;
		}

		g_scan.progress.store(1.f);
		g_scan.scanning.store(false);
	});
}

inline void stop_protection_scan()
{
	g_scan.cancel.store(true);
}

}
