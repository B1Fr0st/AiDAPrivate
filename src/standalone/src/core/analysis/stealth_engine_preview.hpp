#pragma once

#include "../../preview/re_hubs_preview_adapter.hpp"

#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

namespace stealth_engine {

struct stealth_options_t {
	bool spoof_peb = true;
	bool hook_rdtsc = true;
	bool scrub_context = false;
};

struct hook_entry_t {
	uint64_t target_addr = 0;
	uint64_t trampoline_addr = 0;
	std::vector<uint8_t> original_bytes;
	int hook_size = 0;
	bool active = false;
};

struct stealth_session_t {
	uint32_t pid = 4242;
	bool peb_spoofed = true;
	bool context_hooked = true;
	bool rdtsc_hooked = true;
	std::vector<hook_entry_t> hooks = {
		{0x140002184, 0x7FF6A01F0000, {0x0F, 0x31}, 2, true},
		{0x1400042A1, 0x7FF6A01F0100, {0x0F, 0x31}, 2, true}
	};
	std::vector<uint64_t> allocated_regions = {0x7FF6A01F0000, 0x7FF6A01F0100};
};

struct state_t {
	stealth_session_t session;
	std::mutex mutex;
	std::atomic<bool> active{true};
	std::string status = "Stealth active: PEB normalized, RDTSC sites virtualized, debug context scrubbed";
};

inline state_t g_state;

enum class finding_severity_t { info, low, medium, high, critical };
enum class finding_category_t { anticheat_driver, memory_guard, suspicious_module, suspicious_thread, debug_state, hook_detection, wfp_callback };

struct finding_t {
	finding_severity_t severity = finding_severity_t::info;
	finding_category_t category = finding_category_t::anticheat_driver;
	uint64_t address = 0;
	std::string title;
	std::string detail;
	std::string module;
};

inline std::vector<finding_t> preview_findings()
{
	return {
		{finding_severity_t::critical, finding_category_t::anticheat_driver, 0xFFFFF80741200000,
			"Kernel monitor detected", "vgk.sys at 0xFFFFF80741200000 (size: 0x1D8000)", "vgk.sys"},
		{finding_severity_t::high, finding_category_t::suspicious_thread, 0x7FF6A0337000,
			"Thread outside module bounds", "TID 6812 executing at 0x7FF6A0337000 (outside known modules)", ""},
		{finding_severity_t::medium, finding_category_t::memory_guard, 0x7FF6A0128000,
			"Guard page detected", "0x7FF6A0128000 (size: 0x1000, protect: 0x120)", ""},
		{finding_severity_t::low, finding_category_t::debug_state, 0x7FF6A0100000,
			"Debug-related NtGlobalFlag bits set", "NtGlobalFlag: 0x70 (FLG_HEAP_ENABLE_*)", ""},
		{finding_severity_t::info, finding_category_t::wfp_callback, 0xFFFFF80752311240,
			"WFP callout inventory", "Classify=0xFFFFF80752311240 Notify=0xFFFFF80752311890 Layer=44 ID=118", "netfilter.sys"}
	};
}

struct scan_state_t {
	std::vector<finding_t> findings = preview_findings();
	std::mutex mutex;
	std::atomic<bool> scanning{false};
	std::atomic<bool> cancel{false};
	std::atomic<float> progress{1.f};
	std::string scan_status = "Scan complete: 5 findings";
};

inline scan_state_t g_scan;

inline const char* severity_name(finding_severity_t severity)
{
	switch (severity) {
	case finding_severity_t::info: return "Info";
	case finding_severity_t::low: return "Low";
	case finding_severity_t::medium: return "Medium";
	case finding_severity_t::high: return "High";
	case finding_severity_t::critical: return "Critical";
	}
	return "Unknown";
}

inline const char* category_name(finding_category_t category)
{
	switch (category) {
	case finding_category_t::anticheat_driver: return "AC Driver";
	case finding_category_t::memory_guard: return "Memory Guard";
	case finding_category_t::suspicious_module: return "Suspicious Module";
	case finding_category_t::suspicious_thread: return "Thread";
	case finding_category_t::debug_state: return "Debug State";
	case finding_category_t::hook_detection: return "Hook";
	case finding_category_t::wfp_callback: return "WFP Callback";
	}
	return "Unknown";
}

inline bool enable_stealth(uint32_t pid, const stealth_options_t& = {})
{
	std::lock_guard<std::mutex> lock(g_state.mutex);
	g_state.session.pid = pid == 0 ? 4242 : pid;
	g_state.active.store(true);
	g_state.status = "Stealth active: PEB normalized, RDTSC sites virtualized, debug context scrubbed";
	return true;
}

inline bool is_active_for_pid(uint32_t pid)
{
	return g_state.active.load() && g_state.session.pid == pid;
}

inline void disable_stealth()
{
	std::lock_guard<std::mutex> lock(g_state.mutex);
	g_state.active.store(false);
	g_state.status = "Stealth disabled";
}

inline bool ensure_default_enabled(uint32_t pid, const char*)
{
	return enable_stealth(pid);
}

inline void disable_for_detach(uint32_t pid, const char*)
{
	if (is_active_for_pid(pid)) disable_stealth();
}

inline bool is_active()
{
	return g_state.active.load();
}

inline std::string get_status()
{
	std::lock_guard<std::mutex> lock(g_state.mutex);
	return g_state.status;
}

inline stealth_session_t get_session_info()
{
	std::lock_guard<std::mutex> lock(g_state.mutex);
	return g_state.session;
}

inline void run_protection_scan()
{
	g_scan.cancel.store(false);
	g_scan.progress.store(1.f);
	g_scan.scanning.store(false);
	std::lock_guard<std::mutex> lock(g_scan.mutex);
	g_scan.findings = preview_findings();
	g_scan.scan_status = "Scan complete: " + std::to_string(g_scan.findings.size()) + " findings";
	aida::preview::re_hubs::action(aida::preview::re_hubs::domain_t::protection, 0, "protection.scan", g_scan.scan_status);
}

inline void stop_protection_scan()
{
	g_scan.cancel.store(true);
	g_scan.scanning.store(false);
	aida::preview::re_hubs::action(aida::preview::re_hubs::domain_t::protection, 0, "protection.stop");
}

}
