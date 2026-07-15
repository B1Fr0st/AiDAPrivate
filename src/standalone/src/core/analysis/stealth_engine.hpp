#pragma once

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)

#include "stealth_engine_preview.hpp"

#else

#include <atomic>
#include <algorithm>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "standalone_driver.hpp"
#include "zydis_disasm.hpp"
#include "../infra/executor.hpp"
#include "../../helpers/diag_log.hpp"

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
	uint64_t decoded = 0;
	uint64_t raw_pairs = 0;
	uint64_t embedded_pairs = 0;

	for (uint64_t offset = 0; offset < size && static_cast<int>(sites.size()) < max_sites; offset += chunk_size) {
		uint64_t read_size = (std::min)(chunk_size, size - offset);
		code.clear();
		driver_bridge::read_memory(base + offset, static_cast<size_t>(read_size), code);
		if (code.empty()) continue;

		for (size_t i = 0; i < code.size() && static_cast<int>(sites.size()) < max_sites;) {
			if (i + 1 < code.size() && code[i] == 0x0F && code[i + 1] == 0x31)
				++raw_pairs;
			const int avail = static_cast<int>((std::min)(static_cast<size_t>(16), code.size() - i));
			AsmInstr ins = zydis_decode_one(code.data() + i, avail, base + offset + i);
			const int len = (std::max)(1, ins.len);
			++decoded;
			bool raw_inside = false;
			for (int j = 1; j + 1 < len && i + static_cast<size_t>(j + 1) < code.size(); ++j) {
				if (code[i + static_cast<size_t>(j)] == 0x0F && code[i + static_cast<size_t>(j + 1)] == 0x31) {
					raw_inside = true;
					break;
				}
			}
			if (raw_inside)
				++embedded_pairs;
			std::string mnem = ins.mnem;
			for (auto& c : mnem) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
			if (mnem == "rdtsc")
				sites.push_back(ins.addr);
			i += static_cast<size_t>(len);
		}
	}

	diag::log_tagged_fmt("stealth",
		"rdtsc_scan_decoded base=0x%llX size=0x%llX decoded=%llu raw_pairs=%llu embedded_pairs=%llu sites=%zu max_sites=%d",
		static_cast<unsigned long long>(base),
		static_cast<unsigned long long>(size),
		static_cast<unsigned long long>(decoded),
		static_cast<unsigned long long>(raw_pairs),
		static_cast<unsigned long long>(embedded_pairs),
		sites.size(),
		max_sites);
	return sites;
}

inline bool install_rdtsc_hook(uint64_t rdtsc_addr, uint32_t pid, stealth_session_t& session)
{
	std::vector<uint8_t> original;
	driver_bridge::read_memory(rdtsc_addr, 16, original);
	if (original.size() < 16) return false;
	AsmInstr first = zydis_decode_one(original.data(), static_cast<int>(original.size()), rdtsc_addr);
	std::string first_mnem = first.mnem;
	for (auto& c : first_mnem) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
	if (first_mnem != "rdtsc" || first.len != 2) {
		diag::log_tagged_fmt("stealth",
			"rdtsc_hook_skip reason=not_decoded_rdtsc addr=0x%llX mnem=%s len=%d",
			static_cast<unsigned long long>(rdtsc_addr),
			first.mnem,
			first.len);
		return false;
	}
	bool safe_padding = true;
	for (size_t i = 2; i < 5; ++i) {
		const uint8_t b = original[i];
		if (b != 0x90 && b != 0xCC) {
			safe_padding = false;
			break;
		}
	}
	if (!safe_padding) {
		diag::log_tagged_fmt("stealth",
			"rdtsc_hook_skip reason=unsafe_inline_patch_window addr=0x%llX bytes=%02X%02X%02X%02X%02X",
			static_cast<unsigned long long>(rdtsc_addr),
			original[0],
			original[1],
			original[2],
			original[3],
			original[4]);
		return false;
	}

	uint64_t cave = driver_bridge::allocate_memory(64);
	if (cave == 0) return false;
	driver_bridge::protect_memory(cave, 64, 0x40);

	session.allocated_regions.push_back(cave);

	uint64_t fake_tsc_storage = driver_bridge::allocate_memory(8);
	if (fake_tsc_storage == 0) {
		driver_bridge::free_memory(cave);
		session.allocated_regions.pop_back();
		return false;
	}
	session.allocated_regions.push_back(fake_tsc_storage);
	uint64_t initial_tsc = 0x1000000000ULL;
	std::vector<uint8_t> tsc_seed(8);
	std::memcpy(tsc_seed.data(), &initial_tsc, 8);
	driver_bridge::write_memory(fake_tsc_storage, tsc_seed);

	uint8_t shellcode[] = {
		0x51,
		0x57,
		0x48, 0xBF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x48, 0x8B, 0x0F,
		0x48, 0x81, 0xC1, 0xA0, 0x0F, 0x00, 0x00,
		0x48, 0x89, 0x0F,
		0x89, 0xC8,
		0x48, 0x89, 0xCA,
		0x48, 0xC1, 0xEA, 0x20,
		0x5F,
		0x59,
		0xC3
	};

	std::memcpy(shellcode + 4, &fake_tsc_storage, 8);

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

inline bool enable_stealth(uint32_t pid, const stealth_options_t& opts)
{
	if (pid == 0) {
		diag::log_tagged("stealth", "enable_reject reason=zero_pid");
		std::lock_guard<std::mutex> lk(g_state.mutex);
		g_state.status = "Stealth start failed: no target PID";
		return false;
	}

	diag::log_tagged_fmt("stealth",
		"enable_start pid=%u opt_peb=%d opt_rdtsc=%d opt_context=%d",
		pid, opts.spoof_peb ? 1 : 0,
		opts.hook_rdtsc ? 1 : 0,
		opts.scrub_context ? 1 : 0);

	std::lock_guard<std::mutex> lk(g_state.mutex);

	if (g_state.active.load()) {
		const uint32_t active_pid = g_state.session.pid;
		if (active_pid == pid) {
			diag::log_tagged_fmt("stealth", "enable_skip reason=already_active pid=%u", pid);
			return true;
		}
		diag::log_tagged_fmt("stealth",
			"enable_reject reason=active_other_pid requested=%u active=%u",
			pid, active_pid);
		g_state.status = "Stealth already active for PID " + std::to_string(active_pid);
		return false;
	}

	g_state.session = {};
	g_state.session.pid = pid;

	std::string status_parts;
	bool peb_ok = false;
	if (opts.spoof_peb) {
		peb_ok = detail::spoof_peb_flags();
		g_state.session.peb_spoofed = peb_ok;
		status_parts = peb_ok ? "PEB spoofed" : "PEB spoof failed";
		diag::log_tagged_fmt("stealth", "peb_spoof ok=%d", peb_ok ? 1 : 0);
	} else {
		status_parts = "PEB skipped";
		diag::log_tagged("stealth", "peb_spoof skipped_by_user");
	}

	if (opts.hook_rdtsc) {
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
			diag::log_tagged_fmt("stealth",
				"rdtsc_hook module='%s' base=0x%llX size=0x%X sites=%zu hooked=%d",
				main_module.name.c_str(),
				static_cast<unsigned long long>(main_module.base),
				main_module.size, rdtsc_sites.size(), hooked);
		} else {
			diag::log_tagged("stealth", "rdtsc_hook skipped reason=no_main_module");
			status_parts += ", no .exe module";
		}
	} else {
		diag::log_tagged("stealth", "rdtsc_hook skipped_by_user");
	}

	if (opts.scrub_context) {
		auto threads = driver_bridge::enumerate_threads();
		int scrubbed = 0;
		for (auto& thr : threads) {
			driver_bridge::thread_context_t ctx{};
			if (!driver_bridge::get_thread_context(thr.tid, ctx)) continue;
			ctx.dr0 = 0; ctx.dr1 = 0; ctx.dr2 = 0; ctx.dr3 = 0;
			ctx.dr6 = 0; ctx.dr7 = 0;
			const uint64_t kCtxDebug = (1ULL << 18) | (1ULL << 19) | (1ULL << 20) | (1ULL << 21) | (1ULL << 22) | (1ULL << 23);
			if (driver_bridge::set_thread_context(thr.tid, ctx, kCtxDebug)) ++scrubbed;
		}
		g_state.session.context_hooked = scrubbed > 0;
		if (scrubbed > 0) {
			status_parts += ", " + std::to_string(scrubbed) + " contexts scrubbed";
		} else {
			status_parts += ", context scrub failed";
		}
		diag::log_tagged_fmt("stealth",
			"context_scrub threads=%zu scrubbed=%d", threads.size(), scrubbed);
	}

	g_state.status = "Stealth active: " + status_parts;
	g_state.active.store(true);
	diag::log_tagged_fmt("stealth",
		"enable_done pid=%u peb=%d rdtsc=%d context=%d hooks=%zu",
		pid,
		g_state.session.peb_spoofed ? 1 : 0,
		g_state.session.rdtsc_hooked ? 1 : 0,
		g_state.session.context_hooked ? 1 : 0,
		g_state.session.hooks.size());
	return true;
}

inline bool enable_stealth(uint32_t pid)
{
	stealth_options_t opts;
	return enable_stealth(pid, opts);
}

inline bool is_active_for_pid(uint32_t pid)
{
	std::lock_guard<std::mutex> lk(g_state.mutex);
	return g_state.active.load() && g_state.session.pid == pid;
}

inline void disable_stealth()
{
	if (!g_state.active.load()) {
		diag::log_tagged("stealth", "disable_skip reason=not_active");
		return;
	}

	std::lock_guard<std::mutex> lk(g_state.mutex);

	const uint32_t attached_pid = driver_bridge::attached_pid();
	if (attached_pid != 0 && g_state.session.pid != 0 && attached_pid != g_state.session.pid) {
		diag::log_tagged_fmt("stealth",
			"disable_reject reason=attached_pid_mismatch active_pid=%u attached_pid=%u hooks=%zu",
			g_state.session.pid, attached_pid, g_state.session.hooks.size());
		g_state.status = "Stealth restore deferred: active target mismatch";
		return;
	}

	size_t hooks = g_state.session.hooks.size();
	for (auto& hook : g_state.session.hooks) {
		detail::remove_hook(hook);
	}

	diag::log_tagged_fmt("stealth",
		"disable_done pid=%u removed_hooks=%zu",
		g_state.session.pid, hooks);

	g_state.session = {};
	g_state.status = "Stealth disabled";
	g_state.active.store(false);
}

inline bool ensure_default_enabled(uint32_t pid, const char* source)
{
	if (pid == 0) {
		diag::log_tagged_fmt("stealth", "default_enable_reject source=%s reason=zero_pid",
			source ? source : "");
		return false;
	}

	{
		std::lock_guard<std::mutex> lk(g_state.mutex);
		if (g_state.active.load() && g_state.session.pid == pid) {
			diag::log_tagged_fmt("stealth",
				"default_enable_skip source=%s reason=already_active pid=%u",
				source ? source : "", pid);
			return true;
		}
	}

	stealth_session_t previous_session;
	{
		std::lock_guard<std::mutex> lk(g_state.mutex);
		if (g_state.active.load())
			previous_session = g_state.session;
	}
	if (previous_session.pid != 0 && previous_session.pid != pid) {
		const uint32_t restore_pid = driver_bridge::attached_pid();
		bool previous_known = restore_pid == previous_session.pid;
		if (!previous_known) {
			for (uint32_t attached : driver_bridge::attached_pids()) {
				if (attached == previous_session.pid) {
					previous_known = true;
					break;
				}
			}
		}

		bool restored_previous = false;
		if (previous_known) {
			if (restore_pid == previous_session.pid || driver_bridge::set_active_pid(previous_session.pid)) {
				disable_stealth();
				restored_previous = !is_active_for_pid(previous_session.pid);
			}
		}

		if (restore_pid != 0 && restore_pid != previous_session.pid)
			(void)driver_bridge::set_active_pid(restore_pid);

		diag::log_tagged_fmt("stealth",
			"default_enable_previous_session_cleanup source=%s requested=%u previous=%u known=%d restored=%d restore_pid=%u",
			source ? source : "",
			pid,
			previous_session.pid,
			previous_known ? 1 : 0,
			restored_previous ? 1 : 0,
			restore_pid);
	}

	stealth_options_t opts;
	const bool ok = enable_stealth(pid, opts);
	std::string status_snapshot;
	{
		std::lock_guard<std::mutex> lk(g_state.mutex);
		status_snapshot = g_state.status;
	}
	diag::log_tagged_fmt("stealth",
		"default_enable_result source=%s pid=%u ok=%d status='%s'",
		source ? source : "",
		pid,
		ok ? 1 : 0,
		status_snapshot.c_str());
	return ok;
}

inline void disable_for_detach(uint32_t pid, const char* source)
{
	if (pid == 0) {
		diag::log_tagged_fmt("stealth", "detach_disable_skip source=%s reason=zero_pid",
			source ? source : "");
		return;
	}
	if (!is_active_for_pid(pid)) {
		diag::log_tagged_fmt("stealth",
			"detach_disable_skip source=%s reason=not_active_for_pid pid=%u",
			source ? source : "", pid);
		return;
	}
	diag::log_tagged_fmt("stealth", "detach_disable_start source=%s pid=%u",
		source ? source : "", pid);
	disable_stealth();
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
	if (g_scan.scanning.load()) {
		diag::log_tagged("stealth", "scan_skip reason=already_scanning");
		return;
	}
	g_scan.scanning.store(true);
	g_scan.cancel.store(false);
	g_scan.progress.store(0.f);

	uint32_t pid_at_start = driver_bridge::attached_pid();
	diag::log_tagged_fmt("stealth", "scan_begin pid=%u", pid_at_start);

	aida::infra::executor::submission_t sub;
	sub.owner_subsystem = "analysis";
	sub.label = "analysis.stealth.scan";
	sub.thread_class = "bounded_task";
	sub.domain = aida::infra::executor::domain_t::feature_worker;
	sub.priority = 2;
	sub.target_pid = pid_at_start;
	sub.body = [] {
		auto t0 = std::chrono::steady_clock::now();
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

		size_t finding_count = 0;
		int crit_n = 0, hi_n = 0, med_n = 0;
		for (auto& f : results) {
			if (f.severity == finding_severity_t::critical) ++crit_n;
			else if (f.severity == finding_severity_t::high) ++hi_n;
			else if (f.severity == finding_severity_t::medium) ++med_n;
		}
		{
			std::lock_guard<std::mutex> lk(g_scan.mutex);
			finding_count = results.size();
			g_scan.findings = std::move(results);
			char buf[64];
			std::snprintf(buf, sizeof(buf), "Scan complete: %zu findings", g_scan.findings.size());
			g_scan.scan_status = buf;
		}

		auto t1 = std::chrono::steady_clock::now();
		auto dur = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
		diag::log_tagged_fmt("stealth",
			"scan_done findings=%zu critical=%d high=%d medium=%d duration_ms=%lld cancelled=%d",
			finding_count, crit_n, hi_n, med_n,
			static_cast<long long>(dur), g_scan.cancel.load() ? 1 : 0);

		g_scan.progress.store(1.f);
		g_scan.scanning.store(false);
	};
	if (!aida::infra::executor::submit(std::move(sub)).submitted) {
		g_scan.scanning.store(false);
		diag::log_tagged_fmt("stealth",
			"scan_post_failed pid=%u",
			pid_at_start);
	}
}

inline void stop_protection_scan()
{
	diag::log_tagged("stealth", "scan_stop_requested");
	g_scan.cancel.store(true);
}

}

#endif
