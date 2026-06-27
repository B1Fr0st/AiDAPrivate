#pragma once

#include <windows.h>
#include <shlobj.h>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <exception>
#include "work_queue.hpp"
#include <filesystem>
#include <memory>
#include <mutex>
#include <string>
#include <system_error>
#include <thread>
#include <unordered_map>
#include <vector>

#include "pdb_events.hpp"
#include "pdb_parser.hpp"
#include "pdb_downloader.hpp"
#include "standalone_driver.hpp"
#include "standalone_settings.hpp"
#include "../testlab/test_all_features.hpp"
#include "../anti-tamper/state.hpp"
#include "../infra/critical_work_queue.hpp"
#include "../../helpers/diag_log.hpp"

extern settings_sa_t g_settings;

namespace symbol_store {

struct module_symbols_t {
	std::string                               module_name;
	uint64_t                                  base = 0;
	uint64_t                                  size = 0;
	pdb_parser::pdb_info_t                    pdb;
	bool                                      loading = false;
	bool                                      failed = false;
	bool                                      load_declined = false;
	std::string                               status_text;
	std::string                               pdb_path;
	uint64_t                                  pdb_file_size = 0;
	bool                                      parse_completed = false;
	std::string                               load_failure_detail;
	std::string                               load_phase;
	uint64_t                                  load_generation = 0;
	uint64_t                                  load_started_ms = 0;
	uint32_t                                  load_timeout_ms = 0;
	float                                     parse_progress = 0.0f;
	uint64_t                                  parse_progress_ms = 0;
	std::string                               parse_diagnostic;
	uint64_t                                  download_total = 0;
	uint64_t                                  download_received = 0;
	int                                       download_percent = 0;
	bool                                      downloading = false;
};

struct state_t {
	std::unordered_map<std::string, module_symbols_t> modules;
	std::mutex                                        mutex;
	std::vector<std::string>                          search_paths;
	std::string                                       cache_dir;
	bool                                              auto_download = false;
	std::string                                       symbol_server_url = "https://msdl.microsoft.com/download/symbols";
};

inline state_t g_state;
inline std::atomic<uint64_t> g_load_generation{1};
inline constexpr uint32_t k_explicit_pdb_load_timeout_ms = 120000;

struct pdb_automation_context_t {
	bool is_running = false;
	bool anti_tamper_full_test_running = false;
	bool full_test_env_active = false;
	bool unattended_active = false;
	bool post_suppression_active = false;
	uint64_t post_suppression_remaining_ms = 0;
	bool pdb_automation_active = false;
	bool user_default_skip_active = false;
	bool pdb_skip_active = false;
};

inline bool full_test_env_active_for_pdb()
{
	char value[16] = {};
	DWORD n = GetEnvironmentVariableA("AIDA_FULL_TEST_RUNNING", value, static_cast<DWORD>(sizeof(value)));
	if (n == 0) return false;
	if (n >= sizeof(value)) return true;
	return value[0] != '\0' && !(value[0] == '0' && value[1] == '\0');
}

inline pdb_automation_context_t pdb_automation_context()
{
	pdb_automation_context_t ctx;
	ctx.is_running = test_all_features::is_running();
	ctx.anti_tamper_full_test_running = anti_tamper::state::get().full_test_running.load(std::memory_order_acquire);
	ctx.full_test_env_active = full_test_env_active_for_pdb();
	ctx.unattended_active = test_all_features::is_unattended_full_test_active();
	ctx.post_suppression_active = anti_tamper::state::full_test_suppression_active(&ctx.post_suppression_remaining_ms);
	ctx.pdb_automation_active = ctx.unattended_active || ctx.post_suppression_active;
	ctx.pdb_skip_active = ctx.pdb_automation_active;
	return ctx;
}

inline bool pdb_automation_active()
{
	return pdb_automation_context().pdb_automation_active;
}

inline bool pdb_skip_active()
{
	return pdb_automation_context().pdb_skip_active;
}

inline uint64_t next_load_generation()
{
	return g_load_generation.fetch_add(1, std::memory_order_acq_rel);
}

struct load_timeout_context_t {
	std::string module_name;
	std::string phase;
	uint64_t generation = 0;
	uint32_t timeout_ms = 0;
	uint64_t scheduled_ms = 0;
	HANDLE timer = nullptr;
};

inline void apply_loading_timeout(const load_timeout_context_t& ctx) noexcept
{
	try {
		const std::string parser_diag = pdb_parser::dbghelp_load_diagnostic();
		aida::events::event_pdb_loaded ev_payload;
		bool publish_event = false;
		{
			std::lock_guard<std::mutex> lk(g_state.mutex);
			auto it = g_state.modules.find(ctx.module_name);
			if (it == g_state.modules.end())
				return;
			auto& ms = it->second;
			if (!ms.loading || ms.load_generation != ctx.generation || ms.load_phase != ctx.phase)
				return;
			ms.loading = false;
			ms.downloading = false;
			ms.failed = true;
			ms.load_declined = false;
			ms.parse_completed = false;
			ms.load_failure_detail = parser_diag;
			ms.parse_diagnostic = parser_diag;
			ms.parse_progress_ms = ms.load_started_ms ? GetTickCount64() - ms.load_started_ms : 0;
			ms.load_phase.clear();
			char buf[768];
			snprintf(buf, sizeof(buf), "Failed: PDB %s timed out after %u ms; progress=%.1f%% elapsed=%llu ms; %s",
				ctx.phase.c_str(),
				ctx.timeout_ms,
				static_cast<double>(ms.parse_progress) * 100.0,
				static_cast<unsigned long long>(ms.parse_progress_ms),
				parser_diag.c_str());
			ms.status_text = buf;
			ev_payload.module_name = ms.module_name;
			ev_payload.base = ms.base;
			ev_payload.size = ms.size;
			ev_payload.success = false;
			publish_event = true;
			diag::log_tagged_fmt("symbol_store",
				"pdb_load_timeout module=%s generation=%llu phase=%s timeout_ms=%u started_ms=%llu scheduled_ms=%llu fired_ms=%llu path='%s' file_size=%llu progress=%.3f progress_ms=%llu parser_diag=\"%s\"",
				ctx.module_name.c_str(),
				static_cast<unsigned long long>(ctx.generation),
				ctx.phase.c_str(),
				ctx.timeout_ms,
				static_cast<unsigned long long>(ms.load_started_ms),
				static_cast<unsigned long long>(ctx.scheduled_ms),
				static_cast<unsigned long long>(GetTickCount64()),
				ms.pdb_path.c_str(),
				static_cast<unsigned long long>(ms.pdb_file_size),
				static_cast<double>(ms.parse_progress),
				static_cast<unsigned long long>(ms.parse_progress_ms),
				parser_diag.c_str());
		}
		if (publish_event)
			aida::events::publish(aida::events::event_pdb_loaded_def, ev_payload);
	} catch (const std::exception& ex) {
		auto wq = work_queue::stats();
		auto sq = work_queue::service_stats();
		auto cq = critical_work_queue::stats();
		diag::log_tagged_fmt("symbol_store",
			"pdb_timeout_task_exception module=%s generation=%llu phase=%s timeout_ms=%u err=%s work_pending=%zu work_active=%u work_rejected=%llu service_pending=%zu service_active=%u service_rejected=%llu critical_pending=%zu critical_active=%u critical_rejected=%llu",
			ctx.module_name.c_str(),
			static_cast<unsigned long long>(ctx.generation),
			ctx.phase.c_str(),
			ctx.timeout_ms,
			ex.what(),
			wq.pending,
			wq.active,
			static_cast<unsigned long long>(wq.rejected),
			sq.pending,
			sq.active,
			static_cast<unsigned long long>(sq.rejected),
			cq.pending,
			cq.active,
			static_cast<unsigned long long>(cq.rejected));
	} catch (...) {
		auto wq = work_queue::stats();
		auto sq = work_queue::service_stats();
		auto cq = critical_work_queue::stats();
		diag::log_tagged_fmt("symbol_store",
			"pdb_timeout_task_exception module=%s generation=%llu phase=%s timeout_ms=%u err=<unknown> work_pending=%zu work_active=%u work_rejected=%llu service_pending=%zu service_active=%u service_rejected=%llu critical_pending=%zu critical_active=%u critical_rejected=%llu",
			ctx.module_name.c_str(),
			static_cast<unsigned long long>(ctx.generation),
			ctx.phase.c_str(),
			ctx.timeout_ms,
			wq.pending,
			wq.active,
			static_cast<unsigned long long>(wq.rejected),
			sq.pending,
			sq.active,
			static_cast<unsigned long long>(sq.rejected),
			cq.pending,
			cq.active,
			static_cast<unsigned long long>(cq.rejected));
	}
}

inline void CALLBACK load_timeout_timer_cb(PVOID param, BOOLEAN) noexcept
{
	std::unique_ptr<load_timeout_context_t> ctx(static_cast<load_timeout_context_t*>(param));
	if (!ctx)
		return;
	HANDLE timer = ctx->timer;
	apply_loading_timeout(*ctx);
	if (timer && !DeleteTimerQueueTimer(nullptr, timer, nullptr)) {
		DWORD gle = GetLastError();
		if (gle != ERROR_IO_PENDING) {
			diag::log_tagged_fmt("symbol_store",
				"pdb_timeout_timer_delete_failed module=%s generation=%llu phase=%s timeout_ms=%u gle=%lu",
				ctx->module_name.c_str(),
				static_cast<unsigned long long>(ctx->generation),
				ctx->phase.c_str(),
				ctx->timeout_ms,
				static_cast<unsigned long>(gle));
		}
	}
}

inline bool schedule_loading_timeout(const std::string& module_name, uint64_t generation, uint32_t timeout_ms, const std::string& phase) noexcept
{
	try {
		auto ctx = std::make_unique<load_timeout_context_t>();
		ctx->module_name = module_name;
		ctx->generation = generation;
		ctx->timeout_ms = timeout_ms;
		ctx->phase = phase;
		ctx->scheduled_ms = GetTickCount64();

		HANDLE timer = nullptr;
		if (!CreateTimerQueueTimer(&timer, nullptr, load_timeout_timer_cb, ctx.get(), timeout_ms, 0, WT_EXECUTEDEFAULT)) {
			DWORD gle = GetLastError();
			auto wq = work_queue::stats();
			auto sq = work_queue::service_stats();
			auto cq = critical_work_queue::stats();
			diag::log_tagged_fmt("symbol_store",
				"pdb_timeout_schedule_failed module=%s generation=%llu phase=%s timeout_ms=%u gle=%lu work_alive=%d work_pending=%zu work_active=%u work_rejected=%llu service_alive=%d service_pending=%zu service_active=%u service_rejected=%llu critical_alive=%d critical_pending=%zu critical_active=%u critical_rejected=%llu",
				module_name.c_str(),
				static_cast<unsigned long long>(generation),
				phase.c_str(),
				timeout_ms,
				static_cast<unsigned long>(gle),
				wq.alive ? 1 : 0,
				wq.pending,
				wq.active,
				static_cast<unsigned long long>(wq.rejected),
				sq.alive ? 1 : 0,
				sq.pending,
				sq.active,
				static_cast<unsigned long long>(sq.rejected),
				cq.alive ? 1 : 0,
				cq.pending,
				cq.active,
				static_cast<unsigned long long>(cq.rejected));
			return false;
		}

		ctx->timer = timer;
		ctx.release();
		auto wq = work_queue::stats();
		auto sq = work_queue::service_stats();
		auto cq = critical_work_queue::stats();
		diag::log_tagged_fmt("symbol_store",
			"pdb_timeout_schedule_ok module=%s generation=%llu phase=%s timeout_ms=%u work_pending=%zu work_active=%u service_pending=%zu service_active=%u critical_pending=%zu critical_active=%u",
			module_name.c_str(),
			static_cast<unsigned long long>(generation),
			phase.c_str(),
			timeout_ms,
			wq.pending,
			wq.active,
			sq.pending,
			sq.active,
			cq.pending,
			cq.active);
		return true;
	} catch (const std::exception& ex) {
		auto wq = work_queue::stats();
		auto sq = work_queue::service_stats();
		auto cq = critical_work_queue::stats();
		diag::log_tagged_fmt("symbol_store",
			"pdb_timeout_schedule_outer_exception module=%s generation=%llu phase=%s timeout_ms=%u err=%s work_pending=%zu work_active=%u work_rejected=%llu service_pending=%zu service_active=%u service_rejected=%llu critical_pending=%zu critical_active=%u critical_rejected=%llu",
			module_name.c_str(),
			static_cast<unsigned long long>(generation),
			phase.c_str(),
			timeout_ms,
			ex.what(),
			wq.pending,
			wq.active,
			static_cast<unsigned long long>(wq.rejected),
			sq.pending,
			sq.active,
			static_cast<unsigned long long>(sq.rejected),
			cq.pending,
			cq.active,
			static_cast<unsigned long long>(cq.rejected));
		return false;
	} catch (...) {
		auto wq = work_queue::stats();
		auto sq = work_queue::service_stats();
		auto cq = critical_work_queue::stats();
		diag::log_tagged_fmt("symbol_store",
			"pdb_timeout_schedule_outer_exception module=%s generation=%llu phase=%s timeout_ms=%u err=<unknown> work_pending=%zu work_active=%u work_rejected=%llu service_pending=%zu service_active=%u service_rejected=%llu critical_pending=%zu critical_active=%u critical_rejected=%llu",
			module_name.c_str(),
			static_cast<unsigned long long>(generation),
			phase.c_str(),
			timeout_ms,
			wq.pending,
			wq.active,
			static_cast<unsigned long long>(wq.rejected),
			sq.pending,
			sq.active,
			static_cast<unsigned long long>(sq.rejected),
			cq.pending,
			cq.active,
			static_cast<unsigned long long>(cq.rejected));
		return false;
	}
}

inline void publish_failed_load_result(const std::string& module_name, uint64_t generation, const std::string& status_text, const char* diag_name, const char* detail_text, uint64_t elapsed_ms) noexcept
{
	try {
		aida::events::event_pdb_loaded ev_payload;
		bool publish_event = false;
		{
			std::lock_guard<std::mutex> lk(g_state.mutex);
			auto it = g_state.modules.find(module_name);
			if (it == g_state.modules.end()) {
				diag::log_tagged_fmt("symbol_store", "%s_missing module=%s generation=%llu detail=%s",
					diag_name ? diag_name : "pdb_load_failed",
					module_name.c_str(),
					static_cast<unsigned long long>(generation),
					detail_text ? detail_text : "<empty>");
				return;
			}
			auto& ms = it->second;
			if (ms.load_generation != generation) {
				diag::log_tagged_fmt("symbol_store", "%s_stale module=%s generation=%llu current_generation=%llu detail=%s",
					diag_name ? diag_name : "pdb_load_failed",
					module_name.c_str(),
					static_cast<unsigned long long>(generation),
					static_cast<unsigned long long>(ms.load_generation),
					detail_text ? detail_text : "<empty>");
				return;
			}
			if (!ms.loading) {
				diag::log_tagged_fmt("symbol_store", "%s_inactive module=%s generation=%llu status='%s' detail=%s",
					diag_name ? diag_name : "pdb_load_failed",
					module_name.c_str(),
					static_cast<unsigned long long>(generation),
					ms.status_text.c_str(),
					detail_text ? detail_text : "<empty>");
				return;
			}
			ms.loading = false;
			ms.downloading = false;
			ms.failed = true;
			ms.load_declined = false;
			ms.parse_completed = false;
			ms.load_failure_detail = detail_text ? detail_text : "";
			ms.load_phase.clear();
			ms.status_text = status_text;
			ev_payload.module_name = ms.module_name;
			ev_payload.base = ms.base;
			ev_payload.size = ms.size;
			ev_payload.success = false;
			publish_event = true;
		}
		diag::log_tagged_fmt("symbol_store", "%s module=%s generation=%llu elapsed_ms=%llu detail=%s",
			diag_name ? diag_name : "pdb_load_failed",
			module_name.c_str(),
			static_cast<unsigned long long>(generation),
			static_cast<unsigned long long>(elapsed_ms),
			detail_text ? detail_text : "<empty>");
		if (publish_event)
			aida::events::publish(aida::events::event_pdb_loaded_def, ev_payload);
	} catch (...) {
		diag::log_tagged_fmt("symbol_store", "pdb_load_failed_publish_exception module=%s generation=%llu diag=%s",
			module_name.c_str(),
			static_cast<unsigned long long>(generation),
			diag_name ? diag_name : "<empty>");
	}
}

inline std::string pdb_parse_failure_status(const char* prefix)
{
	const std::string detail = pdb_parser::last_error();
	const std::string loader = pdb_parser::dbghelp_load_diagnostic();
	std::string out = prefix ? std::string(prefix) : std::string("Failed to parse PDB");
	if (!detail.empty())
		out += ": " + detail;
	if (!loader.empty())
		out += " [" + loader + "]";
	return out;
}

struct snapshot_t {
	std::unordered_map<std::string, module_symbols_t> modules;
	std::vector<std::string>                          search_paths;
	std::string                                       cache_dir;
	bool                                              auto_download = false;
	std::string                                       symbol_server_url = "https://msdl.microsoft.com/download/symbols";
};

inline std::unique_ptr<snapshot_t> detach_snapshot() {
	std::lock_guard<std::mutex> lk(g_state.mutex);
	auto out = std::make_unique<snapshot_t>();
	out->modules = std::move(g_state.modules);
	out->search_paths = std::move(g_state.search_paths);
	out->cache_dir = std::move(g_state.cache_dir);
	out->auto_download = g_state.auto_download;
	out->symbol_server_url = std::move(g_state.symbol_server_url);
	g_state.modules.clear();
	g_state.search_paths.clear();
	g_state.cache_dir.clear();
	g_state.auto_download = false;
	g_state.symbol_server_url = "https://msdl.microsoft.com/download/symbols";
	return out;
}

inline void attach_snapshot(std::unique_ptr<snapshot_t> snap) {
	std::lock_guard<std::mutex> lk(g_state.mutex);
	if (!snap) {
		g_state.modules.clear();
		g_state.search_paths.clear();
		g_state.cache_dir.clear();
		g_state.auto_download = false;
		g_state.symbol_server_url = "https://msdl.microsoft.com/download/symbols";
		return;
	}
	g_state.modules = std::move(snap->modules);
	g_state.search_paths = std::move(snap->search_paths);
	g_state.cache_dir = std::move(snap->cache_dir);
	g_state.auto_download = snap->auto_download;
	g_state.symbol_server_url = std::move(snap->symbol_server_url);
}

namespace detail {

inline std::filesystem::path get_cache_dir()
{
	if (!g_state.cache_dir.empty())
		return std::filesystem::path(g_state.cache_dir);

	wchar_t* appdata = nullptr;
	if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, nullptr, &appdata))) {
		auto path = std::filesystem::path(appdata) / L"AiDA" / L"Standalone" / L"symbols";
		CoTaskMemFree(appdata);
		std::filesystem::create_directories(path);
		return path;
	}
	return std::filesystem::current_path() / "symbols";
}

inline std::string build_search_path()
{
	std::string sp;
	for (auto& p : g_state.search_paths) {
		if (!sp.empty()) sp += ";";
		sp += p;
	}

	auto cache = get_cache_dir().string();
	if (!sp.empty()) sp += ";";
	sp += cache;

	if (g_state.auto_download && !g_state.symbol_server_url.empty()) {
		if (!sp.empty()) sp += ";";
		sp += "srv*" + cache + "*" + g_state.symbol_server_url;
	}

	return sp;
}

inline std::string find_pdb_local(const std::string& module_name)
{
	std::string pdb_name = module_name;
	auto dot = pdb_name.rfind('.');
	if (dot != std::string::npos)
		pdb_name = pdb_name.substr(0, dot);
	pdb_name += ".pdb";

	for (auto& sp : g_state.search_paths) {
		auto candidate = std::filesystem::path(sp) / pdb_name;
		if (std::filesystem::exists(candidate))
			return candidate.string();
	}

	auto cache = get_cache_dir();
	for (auto& entry : std::filesystem::recursive_directory_iterator(cache, std::filesystem::directory_options::skip_permission_denied)) {
		if (!entry.is_regular_file()) continue;
		auto fn = entry.path().filename().string();
		if (_stricmp(fn.c_str(), pdb_name.c_str()) == 0)
			return entry.path().string();
	}

	return {};
}

}

inline void init_from_settings()
{
	g_state.search_paths.clear();

	std::string paths_str = g_settings.pdb_search_paths;
	if (!paths_str.empty()) {
		size_t pos = 0;
		while (pos < paths_str.size()) {
			size_t sep = paths_str.find(';', pos);
			if (sep == std::string::npos) sep = paths_str.size();
			std::string p = paths_str.substr(pos, sep - pos);
			if (!p.empty()) g_state.search_paths.push_back(p);
			pos = sep + 1;
		}
	}

	g_state.cache_dir = g_settings.symbol_cache_dir;
	g_state.auto_download = g_settings.symbol_auto_download;
	g_state.symbol_server_url = g_settings.symbol_server_url;
}

inline const char* log_value(const std::string& s)
{
	return s.empty() ? "<none>" : s.c_str();
}

inline std::string fallback_pdb_name_for_module(const std::string& module_name)
{
	std::filesystem::path p(module_name);
	std::string stem = p.stem().string();
	if (stem.empty()) stem = module_name;
	return stem + ".pdb";
}

inline std::string expected_cache_path_for_hint(const std::string& pdb_name,
                                                const std::string& pdb_guid,
                                                uint32_t pdb_age)
{
	if (pdb_name.empty() || pdb_guid.empty()) return {};
	char age_buf[16] = {};
	std::snprintf(age_buf, sizeof(age_buf), "%X", static_cast<unsigned>(pdb_age));
	return (detail::get_cache_dir() / pdb_name / (pdb_guid + age_buf) / pdb_name).string();
}

inline std::string safe_find_local_pdb_for_suppression(const std::string& module_name,
                                                       const char* source) noexcept
{
	try {
		return detail::find_pdb_local(module_name);
	} catch (const std::exception& ex) {
		diag::log_tagged_fmt("symbol_store",
			"fulltest_symbol_store_pdb_candidate_error source=%s module=%s err=%s",
			source && *source ? source : "<unknown>",
			log_value(module_name),
			ex.what());
	} catch (...) {
		diag::log_tagged_fmt("symbol_store",
			"fulltest_symbol_store_pdb_candidate_error source=%s module=%s err=<unknown>",
			source && *source ? source : "<unknown>",
			log_value(module_name));
	}
	return {};
}

inline bool suppress_full_test_pdb_load(const char* source,
                                        const std::string& module_name,
                                        uint64_t base,
                                        uint64_t size,
                                        const std::string& pdb_name,
                                        const std::string& pdb_guid,
                                        uint32_t pdb_age,
                                        const std::string& local_candidate,
                                        const std::string& cache_path,
                                        const std::string& explicit_path,
                                        const char* reason,
                                        bool update_module_state = true)
{
	const auto automation = pdb_automation_context();
	if (!automation.pdb_skip_active) return false;
	const uint64_t generation = next_load_generation();
	bool module_present = false;
	bool already_loaded = false;
	bool already_loading = false;
	bool final_failed = false;
	bool final_declined = false;
	bool state_updated = false;
	if (update_module_state && !module_name.empty()) {
		std::lock_guard<std::mutex> lk(g_state.mutex);
		auto it = g_state.modules.find(module_name);
		module_present = it != g_state.modules.end();
		auto& ms = module_present ? it->second : g_state.modules[module_name];
		already_loaded = ms.pdb.loaded;
		already_loading = ms.loading;
		if (!already_loaded && !already_loading) {
			ms.module_name = module_name;
			ms.base = base;
			ms.size = size;
			ms.loading = false;
			ms.downloading = false;
			ms.failed = false;
			ms.load_declined = true;
			ms.parse_completed = false;
			ms.load_phase.clear();
			ms.load_generation = generation;
			ms.load_started_ms = GetTickCount64();
			ms.load_timeout_ms = 0;
			ms.parse_progress = 0.0f;
			ms.parse_progress_ms = 0;
			ms.parse_diagnostic.clear();
			ms.load_failure_detail.clear();
			ms.pdb_path = explicit_path.empty() ? local_candidate : explicit_path;
			ms.status_text = "PDB load skipped by full-test policy";
			state_updated = true;
		}
		final_failed = ms.failed;
		final_declined = ms.load_declined;
	}
	if (!update_module_state) {
		final_failed = false;
		final_declined = true;
	}

	diag::log_tagged_fmt("symbol_store",
		"fulltest_pdb_final_decision source=%s module=%s base=0x%llX size=0x%llX pdb=%s guid=%s age=%u decision=do_not_load_pdb reason=%s local_candidate=%s cache_path=%s explicit_path=%s prompt_suppressed=1 is_running=%d anti_tamper_full_test_running=%d full_test_env_active=%d unattended_active=%d post_suppression_active=%d post_suppression_remaining_ms=%llu pdb_automation_active=%d user_default_skip_active=%d pdb_skip_active=%d",
		source && *source ? source : "<unknown>",
		log_value(module_name),
		static_cast<unsigned long long>(base),
		static_cast<unsigned long long>(size),
		log_value(pdb_name),
		log_value(pdb_guid),
		static_cast<unsigned>(pdb_age),
		reason && *reason ? reason : "full_test_declined_pdb_load",
		log_value(local_candidate),
		log_value(cache_path),
		log_value(explicit_path),
		automation.is_running ? 1 : 0,
		automation.anti_tamper_full_test_running ? 1 : 0,
		automation.full_test_env_active ? 1 : 0,
		automation.unattended_active ? 1 : 0,
		automation.post_suppression_active ? 1 : 0,
		static_cast<unsigned long long>(automation.post_suppression_remaining_ms),
		automation.pdb_automation_active ? 1 : 0,
		automation.user_default_skip_active ? 1 : 0,
		automation.pdb_skip_active ? 1 : 0);
	diag::log_tagged_fmt("symbol_store",
		"fulltest_symbol_store_pdb_suppressed decision=do_not_load_pdb source=%s module=%s base=0x%llX size=0x%llX pdb=%s guid=%s age=%u local_candidate=%s cache_path=%s explicit_path=%s reason=%s generation=%llu prompt_created=0 prompt_suppressed=1 module_present=%d loaded=%d loading=%d failed=%d declined=%d state_updated=%d is_running=%d anti_tamper_full_test_running=%d full_test_env_active=%d unattended_active=%d post_suppression_active=%d post_suppression_remaining_ms=%llu pdb_automation_active=%d user_default_skip_active=%d pdb_skip_active=%d",
		source && *source ? source : "<unknown>",
		log_value(module_name),
		static_cast<unsigned long long>(base),
		static_cast<unsigned long long>(size),
		log_value(pdb_name),
		log_value(pdb_guid),
		static_cast<unsigned>(pdb_age),
		log_value(local_candidate),
		log_value(cache_path),
		log_value(explicit_path),
		reason && *reason ? reason : "full_test_declined_pdb_load",
		static_cast<unsigned long long>(generation),
		module_present ? 1 : 0,
		already_loaded ? 1 : 0,
		already_loading ? 1 : 0,
		final_failed ? 1 : 0,
		final_declined ? 1 : 0,
		state_updated ? 1 : 0,
		automation.is_running ? 1 : 0,
		automation.anti_tamper_full_test_running ? 1 : 0,
		automation.full_test_env_active ? 1 : 0,
		automation.unattended_active ? 1 : 0,
		automation.post_suppression_active ? 1 : 0,
		static_cast<unsigned long long>(automation.post_suppression_remaining_ms),
		automation.pdb_automation_active ? 1 : 0,
		automation.user_default_skip_active ? 1 : 0,
		automation.pdb_skip_active ? 1 : 0);
	return true;
}

inline void load_pdb_for_module(const std::string& module_name, uint64_t base, uint64_t size)
{
	if (pdb_skip_active()) {
		const std::string pdb_name = fallback_pdb_name_for_module(module_name);
		const std::string local_candidate = safe_find_local_pdb_for_suppression(module_name, "load_pdb_for_module");
		suppress_full_test_pdb_load("load_pdb_for_module", module_name, base, size,
			pdb_name, {}, 0, local_candidate, {}, {},
			g_state.auto_download ? "full_test_declined_auto_symbol_server_load" : "full_test_declined_auto_local_pdb_scan");
		return;
	}
	uint64_t generation = next_load_generation();
	{
		std::lock_guard<std::mutex> lk(g_state.mutex);
		auto it = g_state.modules.find(module_name);
		if (it != g_state.modules.end()) {
			if (it->second.pdb.loaded || it->second.loading)
				return;
		}

		auto& ms = g_state.modules[module_name];
		ms.module_name = module_name;
		ms.base = base;
		ms.size = size;
		ms.loading = true;
		ms.failed = false;
		ms.load_declined = false;
		ms.load_phase = "queue";
		ms.load_generation = generation;
		ms.load_started_ms = GetTickCount64();
		ms.load_timeout_ms = 30000;
		ms.status_text = "Searching for PDB...";
	}

	const bool posted = work_queue::post([module_name, generation]() {
		std::string pdb_path = detail::find_pdb_local(module_name);

		if (pdb_path.empty()) {
			std::lock_guard<std::mutex> lk(g_state.mutex);
			auto& ms = g_state.modules[module_name];
			if (ms.load_generation != generation || !ms.loading) {
				diag::log_tagged_fmt("symbol_store", "load_pdb_for_module_stale_before_download module=%s generation=%llu",
					module_name.c_str(), static_cast<unsigned long long>(generation));
				return;
			}

			if (g_state.auto_download) {
				ms.status_text = "Attempting symbol server download...";
			} else {
				ms.loading = false;
				ms.failed = true;
				ms.load_declined = false;
				ms.load_phase.clear();
				ms.status_text = "PDB not found";
				return;
			}
		}

		std::string search_path = detail::build_search_path();

		if (pdb_path.empty()) {
			std::string pdb_name = module_name;
			auto dot = pdb_name.rfind('.');
			if (dot != std::string::npos)
				pdb_name = pdb_name.substr(0, dot);
			pdb_path = pdb_name + ".pdb";
		}

		{
			std::lock_guard<std::mutex> lk(g_state.mutex);
			auto& ms = g_state.modules[module_name];
			if (ms.load_generation != generation || !ms.loading) {
				diag::log_tagged_fmt("symbol_store", "load_pdb_for_module_stale_before_parse module=%s generation=%llu",
					module_name.c_str(), static_cast<unsigned long long>(generation));
				return;
			}
			ms.status_text = "Parsing PDB...";
			ms.load_phase = "parse";
			ms.load_started_ms = GetTickCount64();
			ms.load_timeout_ms = 30000;
		}
		schedule_loading_timeout(module_name, generation, 30000, "parse");

		pdb_parser::pdb_info_t info;
		std::atomic<float> progress{0.f};
		bool ok = pdb_parser::parse_pdb(pdb_path, search_path, info, &progress);

		aida::events::event_pdb_loaded ev_payload;
		bool publish_event = false;

		{
			std::lock_guard<std::mutex> lk(g_state.mutex);
			auto& ms = g_state.modules[module_name];
			if (ms.load_generation != generation || !ms.loading) {
				diag::log_tagged_fmt("symbol_store", "load_pdb_for_module_late_result_ignored module=%s generation=%llu ok=%d progress=%.3f",
					module_name.c_str(), static_cast<unsigned long long>(generation), ok ? 1 : 0,
					static_cast<double>(progress.load()));
				return;
			}
			ms.loading = false;
			ms.load_phase.clear();

			if (ok) {
				ms.pdb = std::move(info);
				ms.load_declined = false;
				char buf[64];
				snprintf(buf, sizeof(buf), "Loaded: %zu symbols, %zu types",
				         ms.pdb.symbols.size(), ms.pdb.structs.size());
				ms.status_text = buf;

				ev_payload.module_name = ms.module_name;
				ev_payload.base = ms.base;
				ev_payload.size = ms.size;
				ev_payload.success = true;
				ev_payload.symbol_count = static_cast<uint32_t>(ms.pdb.symbols.size());
				ev_payload.struct_count = static_cast<uint32_t>(ms.pdb.structs.size());
				ev_payload.enum_count = static_cast<uint32_t>(ms.pdb.enums.size());
				publish_event = true;
			} else {
				ms.failed = true;
				ms.load_declined = false;
				ms.load_phase.clear();
				ms.status_text = pdb_parse_failure_status("Failed to parse PDB");

				ev_payload.module_name = ms.module_name;
				ev_payload.base = ms.base;
				ev_payload.size = ms.size;
				ev_payload.success = false;
				ev_payload.symbol_count = 0;
				ev_payload.struct_count = 0;
				ev_payload.enum_count = 0;
				publish_event = true;
			}
		}

		if (publish_event) {
			aida::events::publish(aida::events::event_pdb_loaded_def, ev_payload);
		}
	});
	if (!posted) {
		aida::events::event_pdb_loaded ev_payload;
		{
			std::lock_guard<std::mutex> lk(g_state.mutex);
			auto& ms = g_state.modules[module_name];
			if (ms.load_generation != generation)
				return;
			ms.loading = false;
			ms.failed = true;
			ms.load_declined = false;
			ms.load_phase.clear();
			ms.status_text = "Failed to queue PDB parse";
			ev_payload.module_name = ms.module_name;
			ev_payload.base = ms.base;
			ev_payload.size = ms.size;
			ev_payload.success = false;
		}
		diag::log_tagged_fmt("symbol_store", "load_pdb_for_module_post_failed module=%s generation=%llu",
			module_name.c_str(), static_cast<unsigned long long>(generation));
		aida::events::publish(aida::events::event_pdb_loaded_def, ev_payload);
	} else {
		schedule_loading_timeout(module_name, generation, 30000, "queue");
	}
}

inline void load_pdb_with_hint(const std::string& module_name, uint64_t base, uint64_t size,
                               const std::string& pdb_name, const std::string& pdb_guid,
                               uint32_t pdb_age, const std::string& symbol_server_base)
{
	if (pdb_skip_active()) {
		std::string cache_path;
		try {
			cache_path = expected_cache_path_for_hint(pdb_name, pdb_guid, pdb_age);
		} catch (const std::exception& ex) {
			diag::log_tagged_fmt("symbol_store",
				"fulltest_symbol_store_pdb_cache_error source=load_pdb_with_hint module=%s pdb=%s guid=%s age=%u err=%s",
				log_value(module_name),
				log_value(pdb_name),
				log_value(pdb_guid),
				static_cast<unsigned>(pdb_age),
				ex.what());
		} catch (...) {
			diag::log_tagged_fmt("symbol_store",
				"fulltest_symbol_store_pdb_cache_error source=load_pdb_with_hint module=%s pdb=%s guid=%s age=%u err=<unknown>",
				log_value(module_name),
				log_value(pdb_name),
				log_value(pdb_guid),
				static_cast<unsigned>(pdb_age));
		}
		std::string local_candidate;
		if (!cache_path.empty()) {
			std::error_code ec;
			if (std::filesystem::is_regular_file(cache_path, ec) && !ec)
				local_candidate = cache_path;
		}
		suppress_full_test_pdb_load("load_pdb_with_hint", module_name, base, size,
			pdb_name, pdb_guid, pdb_age, local_candidate, cache_path, {},
			symbol_server_base.empty()
				? "full_test_declined_hinted_symbol_load_default_server"
				: "full_test_declined_hinted_symbol_load_configured_server");
		return;
	}
	uint64_t generation = next_load_generation();
	{
		std::lock_guard<std::mutex> lk(g_state.mutex);
		auto it = g_state.modules.find(module_name);
		if (it != g_state.modules.end()) {
			if (it->second.pdb.loaded || it->second.loading)
				return;
		}

		auto& ms = g_state.modules[module_name];
		ms.module_name = module_name;
		ms.base = base;
		ms.size = size;
		ms.loading = true;
		ms.failed = false;
		ms.load_declined = false;
		ms.load_phase = "queue";
		ms.load_generation = generation;
		ms.load_started_ms = GetTickCount64();
		ms.load_timeout_ms = 60000;
		ms.downloading = false;
		ms.download_total = 0;
		ms.download_received = 0;
		ms.download_percent = 0;
		ms.status_text = "Resolving PDB...";
	}

	std::string mod_copy = module_name;
	std::string pdb_name_copy = pdb_name;
	std::string pdb_guid_copy = pdb_guid;
	std::string server_copy = symbol_server_base;

	const bool posted = work_queue::post([mod_copy, pdb_name_copy, pdb_guid_copy, pdb_age, server_copy, generation]() {
		std::string cache_root = detail::get_cache_dir().string();

		pdb_downloader::download_request_t req;
		req.pdb_name = pdb_name_copy;
		req.pdb_guid = pdb_guid_copy;
		req.pdb_age = pdb_age;
		req.cache_root = cache_root;
		req.server_base = server_copy.empty()
			? std::string("http://msdl.microsoft.com/download/symbols")
			: server_copy;

		std::string local_path;
		bool from_cache = pdb_downloader::resolve_cache_path(req, local_path);

		if (!from_cache) {
			{
				std::lock_guard<std::mutex> lk(g_state.mutex);
				auto& ms = g_state.modules[mod_copy];
				if (ms.load_generation != generation || !ms.loading) {
					diag::log_tagged_fmt("symbol_store", "hint_pdb_stale_before_download module=%s generation=%llu",
						mod_copy.c_str(), static_cast<unsigned long long>(generation));
					return;
				}
				ms.downloading = true;
				ms.status_text = "Downloading PDB...";
				ms.load_phase = "download";
				ms.load_started_ms = GetTickCount64();
				ms.load_timeout_ms = 60000;
			}
			schedule_loading_timeout(mod_copy, generation, 60000, "download");

			pdb_downloader::download_result_t result;
			auto on_progress = [&mod_copy, generation](const pdb_downloader::progress_t& p) {
				std::lock_guard<std::mutex> lk(g_state.mutex);
				auto it = g_state.modules.find(mod_copy);
				if (it == g_state.modules.end()) return;
				if (it->second.load_generation != generation || !it->second.loading) return;
				it->second.download_percent = p.percent;
				it->second.download_received = p.bytes_received;
				it->second.download_total = p.bytes_total;
				char buf[96];
				if (p.bytes_total > 0) {
					snprintf(buf, sizeof(buf), "Downloading PDB: %d%% (%llu / %llu bytes)",
					         p.percent,
					         static_cast<unsigned long long>(p.bytes_received),
					         static_cast<unsigned long long>(p.bytes_total));
				} else {
					snprintf(buf, sizeof(buf), "Downloading PDB: %llu bytes",
					         static_cast<unsigned long long>(p.bytes_received));
				}
				it->second.status_text = buf;
			};

			bool dl_ok = pdb_downloader::download_pdb_sync(req, on_progress, nullptr, result);

			if (!dl_ok) {
				aida::events::event_pdb_loaded ev_payload;
				{
					std::lock_guard<std::mutex> lk(g_state.mutex);
					auto& ms = g_state.modules[mod_copy];
					if (ms.load_generation != generation || !ms.loading) {
						diag::log_tagged_fmt("symbol_store", "hint_pdb_late_download_failure_ignored module=%s generation=%llu",
							mod_copy.c_str(), static_cast<unsigned long long>(generation));
						return;
					}
					ms.loading = false;
					ms.downloading = false;
					ms.failed = true;
					ms.load_declined = false;
					ms.load_phase.clear();
					ms.status_text = "Download failed: " + result.error;
					ev_payload.module_name = ms.module_name;
					ev_payload.base = ms.base;
					ev_payload.size = ms.size;
					ev_payload.success = false;
				}
				aida::events::publish(aida::events::event_pdb_loaded_def, ev_payload);
				return;
			}

			local_path = result.local_path;
		}

		{
			std::lock_guard<std::mutex> lk(g_state.mutex);
			auto& ms = g_state.modules[mod_copy];
			if (ms.load_generation != generation || !ms.loading) {
				diag::log_tagged_fmt("symbol_store", "hint_pdb_stale_before_parse module=%s generation=%llu",
					mod_copy.c_str(), static_cast<unsigned long long>(generation));
				return;
			}
			ms.downloading = false;
			ms.download_percent = 100;
			ms.status_text = from_cache ? "Parsing cached PDB..." : "Parsing PDB...";
			ms.load_phase = "parse";
			ms.load_started_ms = GetTickCount64();
			ms.load_timeout_ms = 30000;
		}
		schedule_loading_timeout(mod_copy, generation, 30000, "parse");

		pdb_parser::pdb_info_t info;
		std::atomic<float> parse_progress{0.f};
		bool parse_ok = pdb_parser::parse_pdb(local_path, "", info, &parse_progress);

		aida::events::event_pdb_loaded ev_payload;
		{
			std::lock_guard<std::mutex> lk(g_state.mutex);
			auto& ms = g_state.modules[mod_copy];
			if (ms.load_generation != generation || !ms.loading) {
				diag::log_tagged_fmt("symbol_store", "hint_pdb_late_parse_result_ignored module=%s generation=%llu ok=%d progress=%.3f",
					mod_copy.c_str(), static_cast<unsigned long long>(generation), parse_ok ? 1 : 0,
					static_cast<double>(parse_progress.load()));
				return;
			}
			ms.loading = false;
			ms.load_phase.clear();
			if (parse_ok) {
				ms.load_declined = false;
				ms.pdb = std::move(info);
				char buf[96];
				snprintf(buf, sizeof(buf), "Loaded: %zu symbols, %zu types",
				         ms.pdb.symbols.size(), ms.pdb.structs.size());
				ms.status_text = buf;
				ev_payload.module_name = ms.module_name;
				ev_payload.base = ms.base;
				ev_payload.size = ms.size;
				ev_payload.success = true;
				ev_payload.symbol_count = static_cast<uint32_t>(ms.pdb.symbols.size());
				ev_payload.struct_count = static_cast<uint32_t>(ms.pdb.structs.size());
				ev_payload.enum_count = static_cast<uint32_t>(ms.pdb.enums.size());
			} else {
				ms.failed = true;
				ms.load_declined = false;
				ms.load_phase.clear();
				ms.status_text = pdb_parse_failure_status("Failed to parse PDB");
				ev_payload.module_name = ms.module_name;
				ev_payload.base = ms.base;
				ev_payload.size = ms.size;
				ev_payload.success = false;
			}
		}
		aida::events::publish(aida::events::event_pdb_loaded_def, ev_payload);
	});
	if (!posted) {
		aida::events::event_pdb_loaded ev_payload;
		{
			std::lock_guard<std::mutex> lk(g_state.mutex);
			auto& ms = g_state.modules[module_name];
			if (ms.load_generation != generation)
				return;
			ms.loading = false;
			ms.downloading = false;
			ms.failed = true;
			ms.load_declined = false;
			ms.load_phase.clear();
			ms.status_text = "Failed to queue hinted PDB load";
			ev_payload.module_name = ms.module_name;
			ev_payload.base = ms.base;
			ev_payload.size = ms.size;
			ev_payload.success = false;
		}
		diag::log_tagged_fmt("symbol_store", "hint_pdb_post_failed module=%s generation=%llu",
			module_name.c_str(), static_cast<unsigned long long>(generation));
		aida::events::publish(aida::events::event_pdb_loaded_def, ev_payload);
	} else {
		schedule_loading_timeout(module_name, generation, 60000, "queue");
	}
}

inline void load_pdb_from_explicit_path(const std::string& module_name, uint64_t base, uint64_t size,
                                        const std::string& pdb_path)
{
	uint64_t generation = next_load_generation();
	std::error_code path_ec;
	std::filesystem::path exact_path_fs = std::filesystem::absolute(std::filesystem::path(pdb_path), path_ec);
	const std::string exact_path = path_ec ? pdb_path : exact_path_fs.string();
	std::error_code size_ec;
	uint64_t file_size = 0;
	auto explicit_size = std::filesystem::file_size(exact_path, size_ec);
	if (!size_ec)
		file_size = static_cast<uint64_t>(explicit_size);
	diag::log_tagged_fmt("symbol_store",
		"explicit_pdb_request module=%s generation=%llu input_path='%s' exact_path='%s' file_size=%llu file_size_ok=%d file_size_ec=%d base=0x%llX size=0x%llX parser_diag=\"%s\"",
		module_name.c_str(),
		static_cast<unsigned long long>(generation),
		pdb_path.c_str(),
		exact_path.c_str(),
		static_cast<unsigned long long>(file_size),
		size_ec ? 0 : 1,
		size_ec ? size_ec.value() : 0,
		static_cast<unsigned long long>(base),
		static_cast<unsigned long long>(size),
		pdb_parser::dbghelp_load_diagnostic().c_str());
	{
		std::lock_guard<std::mutex> lk(g_state.mutex);
		auto& ms = g_state.modules[module_name];
		if (ms.pdb.loaded) {
			diag::log_tagged_fmt("symbol_store", "explicit_pdb_parse_already_loaded module=%s generation=%llu requested_path='%s' loaded_path='%s' file_size=%llu symbols=%zu structs=%zu enums=%zu types=%zu parse_completed=%d status='%s' failure_detail='%s'",
				module_name.c_str(),
				static_cast<unsigned long long>(ms.load_generation),
				exact_path.c_str(),
				ms.pdb_path.c_str(),
				static_cast<unsigned long long>(ms.pdb_file_size),
				ms.pdb.symbols.size(),
				ms.pdb.structs.size(),
				ms.pdb.enums.size(),
				ms.pdb.structs.size() + ms.pdb.enums.size(),
				ms.parse_completed ? 1 : 0,
				ms.status_text.c_str(),
				ms.load_failure_detail.c_str());
			return;
		}
		if (ms.loading) {
			const uint64_t now = GetTickCount64();
			const uint64_t elapsed = ms.load_started_ms ? now - ms.load_started_ms : 0;
			const std::string parser_diag = pdb_parser::dbghelp_load_diagnostic();
			char status[256];
			snprintf(status, sizeof(status), "PDB load already in progress (%s, %llu / %u ms); %s",
				ms.load_phase.empty() ? "unknown" : ms.load_phase.c_str(),
				static_cast<unsigned long long>(elapsed),
				ms.load_timeout_ms,
				parser_diag.c_str());
			ms.status_text = status;
			ms.load_failure_detail = parser_diag;
			diag::log_tagged_fmt("symbol_store", "explicit_pdb_parse_already_loading module=%s generation=%llu phase=%s elapsed_ms=%llu timeout_ms=%u requested_path='%s' active_path='%s' file_size=%llu parse_completed=%d parser_diag=\"%s\" status='%s'",
				module_name.c_str(),
				static_cast<unsigned long long>(ms.load_generation),
				ms.load_phase.c_str(),
				static_cast<unsigned long long>(elapsed),
				ms.load_timeout_ms,
				exact_path.c_str(),
				ms.pdb_path.c_str(),
				static_cast<unsigned long long>(ms.pdb_file_size),
				ms.parse_completed ? 1 : 0,
				parser_diag.c_str(),
				ms.status_text.c_str());
			return;
		}
		ms.module_name = module_name;
		ms.base = base;
		ms.size = size;
		ms.loading = true;
		ms.failed = false;
		ms.load_declined = false;
		ms.pdb_path = exact_path;
		ms.pdb_file_size = file_size;
		ms.parse_completed = false;
		ms.load_failure_detail.clear();
		ms.load_phase = "queue";
		ms.load_generation = generation;
		ms.load_started_ms = GetTickCount64();
		ms.load_timeout_ms = k_explicit_pdb_load_timeout_ms;
		ms.parse_progress = 0.0f;
		ms.parse_progress_ms = 0;
		ms.parse_diagnostic.clear();
		ms.downloading = false;
		ms.download_total = 0;
		ms.download_received = 0;
		ms.download_percent = 0;
		ms.status_text = "Parsing user-supplied PDB...";
	}

	std::string mod_copy = module_name;
	std::string path_copy = exact_path;
	uint64_t file_size_copy = file_size;

	auto parse_job = [mod_copy, path_copy, file_size_copy, generation]() {
		uint64_t job_start = GetTickCount64();
		const DWORD worker_pid = GetCurrentProcessId();
		const DWORD worker_tid = GetCurrentThreadId();
		bool parser_called = false;
		bool parse_monitor_unavailable = false;
		std::string parse_monitor_error;
		try {
			diag::log_tagged_fmt("symbol_store", "explicit_pdb_parse_start module=%s path='%s' file_size=%llu generation=%llu worker_pid=%lu worker_tid=%lu parser_diag=\"%s\"",
				mod_copy.c_str(),
				path_copy.c_str(),
				static_cast<unsigned long long>(file_size_copy),
				static_cast<unsigned long long>(generation),
				worker_pid,
				worker_tid,
				pdb_parser::dbghelp_load_diagnostic().c_str());
			{
				std::lock_guard<std::mutex> lk(g_state.mutex);
				auto& ms = g_state.modules[mod_copy];
				if (ms.load_generation != generation || !ms.loading) {
					diag::log_tagged_fmt("symbol_store", "explicit_pdb_parse_stale_before_parse module=%s generation=%llu path='%s' status='%s'",
						mod_copy.c_str(), static_cast<unsigned long long>(generation), path_copy.c_str(), ms.status_text.c_str());
					return;
				}
				ms.load_phase = "parse";
				ms.load_started_ms = GetTickCount64();
				ms.load_timeout_ms = k_explicit_pdb_load_timeout_ms;
				ms.parse_progress = 0.0f;
				ms.parse_progress_ms = 0;
				ms.parse_diagnostic = pdb_parser::dbghelp_load_diagnostic();
				char status[384];
				snprintf(status, sizeof(status), "Parsing user-supplied PDB: progress=0.0%% elapsed=0 ms; %s", ms.parse_diagnostic.c_str());
				ms.status_text = status;
			}
			auto wq_before_timeout = work_queue::stats();
			auto sq_before_timeout = work_queue::service_stats();
			auto cq_before_timeout = critical_work_queue::stats();
			diag::log_tagged_fmt("symbol_store",
				"explicit_pdb_timeout_schedule_begin module=%s path='%s' file_size=%llu generation=%llu phase=parse timeout_ms=%u work_pending=%zu work_active=%u work_rejected=%llu service_pending=%zu service_active=%u service_rejected=%llu critical_pending=%zu critical_active=%u critical_rejected=%llu",
				mod_copy.c_str(),
				path_copy.c_str(),
				static_cast<unsigned long long>(file_size_copy),
				static_cast<unsigned long long>(generation),
				k_explicit_pdb_load_timeout_ms,
				wq_before_timeout.pending,
				wq_before_timeout.active,
				static_cast<unsigned long long>(wq_before_timeout.rejected),
				sq_before_timeout.pending,
				sq_before_timeout.active,
				static_cast<unsigned long long>(sq_before_timeout.rejected),
				cq_before_timeout.pending,
				cq_before_timeout.active,
				static_cast<unsigned long long>(cq_before_timeout.rejected));
			const bool parse_timeout_scheduled = schedule_loading_timeout(mod_copy, generation, k_explicit_pdb_load_timeout_ms, "parse");
			auto wq_after_timeout = work_queue::stats();
			auto sq_after_timeout = work_queue::service_stats();
			auto cq_after_timeout = critical_work_queue::stats();
			diag::log_tagged_fmt("symbol_store",
				"explicit_pdb_timeout_schedule_end module=%s path='%s' file_size=%llu generation=%llu phase=parse scheduled=%d timeout_ms=%u work_pending=%zu work_active=%u work_rejected=%llu service_pending=%zu service_active=%u service_rejected=%llu critical_pending=%zu critical_active=%u critical_rejected=%llu",
				mod_copy.c_str(),
				path_copy.c_str(),
				static_cast<unsigned long long>(file_size_copy),
				static_cast<unsigned long long>(generation),
				parse_timeout_scheduled ? 1 : 0,
				k_explicit_pdb_load_timeout_ms,
				wq_after_timeout.pending,
				wq_after_timeout.active,
				static_cast<unsigned long long>(wq_after_timeout.rejected),
				sq_after_timeout.pending,
				sq_after_timeout.active,
				static_cast<unsigned long long>(sq_after_timeout.rejected),
				cq_after_timeout.pending,
				cq_after_timeout.active,
				static_cast<unsigned long long>(cq_after_timeout.rejected));
			pdb_parser::pdb_info_t info;
			std::atomic<float> parse_progress{0.f};
			std::string search_path = std::filesystem::path(path_copy).parent_path().string();
			std::atomic<bool> parse_monitor_done{false};
			std::unique_ptr<std::thread> parse_monitor;
			auto parse_monitor_body = [&]() {
				uint64_t last_log_ms = 0;
				while (!parse_monitor_done.load(std::memory_order_acquire)) {
					Sleep(1000);
					const uint64_t now_ms = GetTickCount64();
					const float progress_value = parse_progress.load(std::memory_order_acquire);
					const std::string parser_diag = pdb_parser::dbghelp_load_diagnostic();
					uint64_t elapsed = 0;
					bool updated = false;
					{
						std::lock_guard<std::mutex> lk(g_state.mutex);
						auto it = g_state.modules.find(mod_copy);
						if (it != g_state.modules.end() && it->second.load_generation == generation && it->second.loading && it->second.load_phase == "parse") {
							auto& ms = it->second;
							elapsed = ms.load_started_ms ? now_ms - ms.load_started_ms : 0;
							ms.parse_progress = progress_value;
							ms.parse_progress_ms = elapsed;
							ms.parse_diagnostic = parser_diag;
							char status[512];
							snprintf(status, sizeof(status), "Parsing user-supplied PDB: progress=%.1f%% elapsed=%llu / %u ms; %s",
								static_cast<double>(progress_value) * 100.0,
								static_cast<unsigned long long>(elapsed),
								ms.load_timeout_ms,
								parser_diag.c_str());
							ms.status_text = status;
							updated = true;
						}
					}
					if (updated && now_ms - last_log_ms >= 5000) {
						last_log_ms = now_ms;
						diag::log_tagged_fmt("symbol_store",
							"explicit_pdb_parse_progress module=%s generation=%llu path='%s' progress=%.3f elapsed_ms=%llu parser_diag=\"%s\"",
							mod_copy.c_str(),
							static_cast<unsigned long long>(generation),
							path_copy.c_str(),
							static_cast<double>(progress_value),
							static_cast<unsigned long long>(elapsed),
							parser_diag.c_str());
					}
				}
			};
			try {
				parse_monitor = std::make_unique<std::thread>(parse_monitor_body);
			} catch (const std::system_error& ex) {
				parse_monitor_unavailable = true;
				parse_monitor_error = ex.what();
				const std::string parser_diag = pdb_parser::dbghelp_load_diagnostic();
				auto wq = work_queue::stats();
				auto sq = work_queue::service_stats();
				auto cq = critical_work_queue::stats();
				{
					std::lock_guard<std::mutex> lk(g_state.mutex);
					auto it = g_state.modules.find(mod_copy);
					if (it != g_state.modules.end() && it->second.load_generation == generation && it->second.loading && it->second.load_phase == "parse") {
						auto& ms = it->second;
						ms.parse_diagnostic = parser_diag;
						ms.load_failure_detail = std::string("parse monitor unavailable: ") + parse_monitor_error + " | " + parser_diag;
					}
				}
				diag::log_tagged_fmt("symbol_store",
					"explicit_pdb_parse_monitor_unavailable module=%s generation=%llu path='%s' file_size=%llu err=%s code=%d category=%s parser_called=%d parser_diag=\"%s\" work_pending=%zu work_active=%u work_rejected=%llu service_pending=%zu service_active=%u service_rejected=%llu critical_pending=%zu critical_active=%u critical_rejected=%llu",
					mod_copy.c_str(),
					static_cast<unsigned long long>(generation),
					path_copy.c_str(),
					static_cast<unsigned long long>(file_size_copy),
					ex.what(),
					ex.code().value(),
					ex.code().category().name(),
					parser_called ? 1 : 0,
					parser_diag.c_str(),
					wq.pending,
					wq.active,
					static_cast<unsigned long long>(wq.rejected),
					sq.pending,
					sq.active,
					static_cast<unsigned long long>(sq.rejected),
					cq.pending,
					cq.active,
					static_cast<unsigned long long>(cq.rejected));
			}
			auto stop_parse_monitor = [&]() {
				parse_monitor_done.store(true, std::memory_order_release);
				if (parse_monitor && parse_monitor->joinable())
					parse_monitor->join();
			};
			bool parse_ok = false;
			try {
				diag::log_tagged_fmt("symbol_store",
					"explicit_pdb_parse_call_enter module=%s generation=%llu path='%s' file_size=%llu search_path='%s' monitor_available=%d monitor_error='%s' parser_diag=\"%s\"",
					mod_copy.c_str(),
					static_cast<unsigned long long>(generation),
					path_copy.c_str(),
					static_cast<unsigned long long>(file_size_copy),
					search_path.c_str(),
					parse_monitor ? 1 : 0,
					parse_monitor_error.c_str(),
					pdb_parser::dbghelp_load_diagnostic().c_str());
				parser_called = true;
				parse_ok = pdb_parser::parse_pdb(path_copy, search_path, info, &parse_progress);
				stop_parse_monitor();
			} catch (...) {
				stop_parse_monitor();
				throw;
			}
			const bool parse_completed = parse_ok && info.loaded;
			const std::string parser_status = pdb_parser::last_error();
			const std::string parser_diag = pdb_parser::dbghelp_load_diagnostic();
			diag::log_tagged_fmt("symbol_store", "explicit_pdb_parse_done module=%s generation=%llu ok=%d parse_completed=%d path='%s' file_size=%llu symbols=%zu structs=%zu enums=%zu types=%zu progress=%.3f elapsed_ms=%llu parser_status='%s' parser_diag=\"%s\"",
				mod_copy.c_str(),
				static_cast<unsigned long long>(generation),
				parse_ok ? 1 : 0,
				parse_completed ? 1 : 0,
				path_copy.c_str(),
				static_cast<unsigned long long>(file_size_copy),
				info.symbols.size(),
				info.structs.size(),
				info.enums.size(),
				info.structs.size() + info.enums.size(),
				static_cast<double>(parse_progress.load()),
				static_cast<unsigned long long>(GetTickCount64() - job_start),
				parser_status.c_str(),
				parser_diag.c_str());

			aida::events::event_pdb_loaded ev_payload;
			{
				std::lock_guard<std::mutex> lk(g_state.mutex);
				auto& ms = g_state.modules[mod_copy];
				if (ms.load_generation != generation || !ms.loading) {
					diag::log_tagged_fmt("symbol_store", "explicit_pdb_parse_late_result_ignored module=%s generation=%llu ok=%d parse_completed=%d path='%s' file_size=%llu progress=%.3f elapsed_ms=%llu status='%s' parser_status='%s' parser_diag=\"%s\"",
						mod_copy.c_str(),
						static_cast<unsigned long long>(generation),
						parse_ok ? 1 : 0,
						parse_completed ? 1 : 0,
						path_copy.c_str(),
						static_cast<unsigned long long>(file_size_copy),
						static_cast<double>(parse_progress.load()),
						static_cast<unsigned long long>(GetTickCount64() - job_start),
						ms.status_text.c_str(),
						parser_status.c_str(),
						parser_diag.c_str());
					return;
				}
				ms.loading = false;
				ms.load_phase.clear();
				if (parse_completed) {
					ms.pdb = std::move(info);
					ms.parse_completed = ms.pdb.loaded;
					ms.failed = false;
					ms.load_declined = false;
					ms.pdb_path = path_copy;
					ms.pdb_file_size = file_size_copy;
					ms.load_failure_detail.clear();
					ms.parse_progress = parse_progress.load();
					ms.parse_progress_ms = GetTickCount64() - job_start;
					ms.parse_diagnostic = parser_diag;
					char buf[192];
					snprintf(buf, sizeof(buf), "Loaded from %s: %zu symbols, %zu types",
					         std::filesystem::path(path_copy).filename().string().c_str(),
					         ms.pdb.symbols.size(), ms.pdb.structs.size() + ms.pdb.enums.size());
					ms.status_text = buf;
					ev_payload.module_name = ms.module_name;
					ev_payload.base = ms.base;
					ev_payload.size = ms.size;
					ev_payload.success = true;
					ev_payload.symbol_count = static_cast<uint32_t>(ms.pdb.symbols.size());
					ev_payload.struct_count = static_cast<uint32_t>(ms.pdb.structs.size());
					ev_payload.enum_count = static_cast<uint32_t>(ms.pdb.enums.size());
				} else {
					ms.failed = true;
					ms.load_declined = false;
					ms.parse_completed = false;
					ms.load_phase.clear();
					ms.load_failure_detail = parser_status.empty() ? parser_diag : parser_status + " | " + parser_diag;
					ms.parse_progress = parse_progress.load();
					ms.parse_progress_ms = GetTickCount64() - job_start;
					ms.parse_diagnostic = parser_diag;
					ms.status_text = pdb_parse_failure_status("Failed to parse user-supplied PDB");
					ev_payload.module_name = ms.module_name;
					ev_payload.base = ms.base;
					ev_payload.size = ms.size;
					ev_payload.success = false;
				}
				diag::log_tagged_fmt("symbol_store",
					"explicit_pdb_state_commit module=%s generation=%llu success=%d parse_completed=%d path='%s' file_size=%llu symbols=%zu structs=%zu enums=%zu types=%zu status='%s' failure_detail='%s'",
					ms.module_name.c_str(),
					static_cast<unsigned long long>(generation),
					ev_payload.success ? 1 : 0,
					ms.parse_completed ? 1 : 0,
					ms.pdb_path.c_str(),
					static_cast<unsigned long long>(ms.pdb_file_size),
					ms.pdb.symbols.size(),
					ms.pdb.structs.size(),
					ms.pdb.enums.size(),
					ms.pdb.structs.size() + ms.pdb.enums.size(),
					ms.status_text.c_str(),
					ms.load_failure_detail.c_str());
			}

			auto parent_dir = std::filesystem::path(path_copy).parent_path().string();
			if (!parent_dir.empty()) {
				bool already = false;
				{
					std::lock_guard<std::mutex> lk(g_state.mutex);
					for (auto& sp : g_state.search_paths) {
						if (_stricmp(sp.c_str(), parent_dir.c_str()) == 0) { already = true; break; }
					}
					if (!already) g_state.search_paths.push_back(parent_dir);
				}
			}

			aida::events::publish(aida::events::event_pdb_loaded_def, ev_payload);
		} catch (const std::exception& ex) {
			char status[512];
			const std::string parser_diag = pdb_parser::dbghelp_load_diagnostic();
			if (parser_called) {
				snprintf(status, sizeof(status), "Failed to parse user-supplied PDB: %s; %s", ex.what(), parser_diag.c_str());
			} else {
				snprintf(status, sizeof(status), "PDB pre-parser resource failure: %s; %s", ex.what(), parser_diag.c_str());
			}
			std::string detail = std::string("parser_called=") + (parser_called ? "1" : "0") +
				" monitor_unavailable=" + (parse_monitor_unavailable ? "1" : "0") +
				" monitor_error='" + parse_monitor_error + "' exception='" + ex.what() + "' | " + parser_diag;
			publish_failed_load_result(mod_copy, generation, status,
				parser_called ? "explicit_pdb_parse_exception" : "explicit_pdb_preparser_exception",
				detail.c_str(), GetTickCount64() - job_start);
		} catch (...) {
			const std::string parser_diag = pdb_parser::dbghelp_load_diagnostic();
			std::string status = parser_called
				? "Failed to parse user-supplied PDB: unknown exception; " + parser_diag
				: "PDB pre-parser resource failure: unknown exception; " + parser_diag;
			std::string detail = std::string("parser_called=") + (parser_called ? "1" : "0") +
				" monitor_unavailable=" + (parse_monitor_unavailable ? "1" : "0") +
				" monitor_error='" + parse_monitor_error + "' exception='<unknown>' | " + parser_diag;
			publish_failed_load_result(mod_copy, generation, status,
				parser_called ? "explicit_pdb_parse_exception" : "explicit_pdb_preparser_exception",
				detail.c_str(), GetTickCount64() - job_start);
		}
	};
	auto wq_before_post = work_queue::stats();
	auto sq_before_post = work_queue::service_stats();
	auto cq_before_post = critical_work_queue::stats();
	diag::log_tagged_fmt("symbol_store",
		"explicit_pdb_parse_queue_begin module=%s path='%s' file_size=%llu generation=%llu work_pending=%zu work_active=%u work_rejected=%llu service_pending=%zu service_active=%u service_rejected=%llu critical_pending=%zu critical_active=%u critical_rejected=%llu parser_diag=\"%s\"",
		mod_copy.c_str(),
		path_copy.c_str(),
		static_cast<unsigned long long>(file_size_copy),
		static_cast<unsigned long long>(generation),
		wq_before_post.pending,
		wq_before_post.active,
		static_cast<unsigned long long>(wq_before_post.rejected),
		sq_before_post.pending,
		sq_before_post.active,
		static_cast<unsigned long long>(sq_before_post.rejected),
		cq_before_post.pending,
		cq_before_post.active,
		static_cast<unsigned long long>(cq_before_post.rejected),
		pdb_parser::dbghelp_load_diagnostic().c_str());
	bool posted = false;
	const char* posted_queue = "none";
	try {
		posted = critical_work_queue::post(parse_job);
		if (posted)
			posted_queue = "critical";
	} catch (const std::exception& ex) {
		diag::log_tagged_fmt("symbol_store", "explicit_pdb_parse_queue_exception queue=critical module=%s path='%s' file_size=%llu generation=%llu err=%s",
			mod_copy.c_str(), path_copy.c_str(), static_cast<unsigned long long>(file_size_copy), static_cast<unsigned long long>(generation), ex.what());
	} catch (...) {
		diag::log_tagged_fmt("symbol_store", "explicit_pdb_parse_queue_exception queue=critical module=%s path='%s' file_size=%llu generation=%llu err=<unknown>",
			mod_copy.c_str(), path_copy.c_str(), static_cast<unsigned long long>(file_size_copy), static_cast<unsigned long long>(generation));
	}
	if (!posted) {
		try {
			posted = work_queue::post(parse_job);
			if (posted)
				posted_queue = "work";
		} catch (const std::exception& ex) {
			diag::log_tagged_fmt("symbol_store", "explicit_pdb_parse_queue_exception queue=work module=%s path='%s' file_size=%llu generation=%llu err=%s",
				mod_copy.c_str(), path_copy.c_str(), static_cast<unsigned long long>(file_size_copy), static_cast<unsigned long long>(generation), ex.what());
		} catch (...) {
			diag::log_tagged_fmt("symbol_store", "explicit_pdb_parse_queue_exception queue=work module=%s path='%s' file_size=%llu generation=%llu err=<unknown>",
				mod_copy.c_str(), path_copy.c_str(), static_cast<unsigned long long>(file_size_copy), static_cast<unsigned long long>(generation));
		}
	}
	auto wq_after_post = work_queue::stats();
	auto sq_after_post = work_queue::service_stats();
	auto cq_after_post = critical_work_queue::stats();
	diag::log_tagged_fmt("symbol_store",
		"explicit_pdb_parse_queue_end module=%s path='%s' file_size=%llu generation=%llu posted=%d queue=%s work_pending=%zu work_active=%u work_rejected=%llu service_pending=%zu service_active=%u service_rejected=%llu critical_pending=%zu critical_active=%u critical_rejected=%llu parser_diag=\"%s\"",
		mod_copy.c_str(),
		path_copy.c_str(),
		static_cast<unsigned long long>(file_size_copy),
		static_cast<unsigned long long>(generation),
		posted ? 1 : 0,
		posted_queue,
		wq_after_post.pending,
		wq_after_post.active,
		static_cast<unsigned long long>(wq_after_post.rejected),
		sq_after_post.pending,
		sq_after_post.active,
		static_cast<unsigned long long>(sq_after_post.rejected),
		cq_after_post.pending,
		cq_after_post.active,
		static_cast<unsigned long long>(cq_after_post.rejected),
		pdb_parser::dbghelp_load_diagnostic().c_str());
	if (!posted) {
		const std::string parser_diag = pdb_parser::dbghelp_load_diagnostic();
		diag::log_tagged_fmt("symbol_store", "explicit_pdb_parse_post_failed module=%s path='%s' file_size=%llu generation=%llu parser_diag=\"%s\"",
			mod_copy.c_str(), path_copy.c_str(), static_cast<unsigned long long>(file_size_copy), static_cast<unsigned long long>(generation), parser_diag.c_str());
		aida::events::event_pdb_loaded ev_payload;
		{
			std::lock_guard<std::mutex> lk(g_state.mutex);
			auto& ms = g_state.modules[mod_copy];
			if (ms.load_generation != generation)
				return;
			ms.loading = false;
			ms.failed = true;
			ms.load_declined = false;
			ms.parse_completed = false;
			ms.load_failure_detail = parser_diag;
			ms.load_phase.clear();
			char status[768];
			snprintf(status, sizeof(status), "Failed to queue user-supplied PDB parse; %s", parser_diag.c_str());
			ms.status_text = status;
			ev_payload.module_name = ms.module_name;
			ev_payload.base = ms.base;
			ev_payload.size = ms.size;
			ev_payload.success = false;
		}
		aida::events::publish(aida::events::event_pdb_loaded_def, ev_payload);
	} else {
		auto wq_before_timeout = work_queue::stats();
		auto sq_before_timeout = work_queue::service_stats();
		auto cq_before_timeout = critical_work_queue::stats();
		diag::log_tagged_fmt("symbol_store",
			"explicit_pdb_timeout_schedule_begin module=%s path='%s' file_size=%llu generation=%llu phase=queue timeout_ms=%u work_pending=%zu work_active=%u work_rejected=%llu service_pending=%zu service_active=%u service_rejected=%llu critical_pending=%zu critical_active=%u critical_rejected=%llu parser_diag=\"%s\"",
			module_name.c_str(),
			path_copy.c_str(),
			static_cast<unsigned long long>(file_size_copy),
			static_cast<unsigned long long>(generation),
			k_explicit_pdb_load_timeout_ms,
			wq_before_timeout.pending,
			wq_before_timeout.active,
			static_cast<unsigned long long>(wq_before_timeout.rejected),
			sq_before_timeout.pending,
			sq_before_timeout.active,
			static_cast<unsigned long long>(sq_before_timeout.rejected),
			cq_before_timeout.pending,
			cq_before_timeout.active,
			static_cast<unsigned long long>(cq_before_timeout.rejected),
			pdb_parser::dbghelp_load_diagnostic().c_str());
		const bool queue_timeout_scheduled = schedule_loading_timeout(module_name, generation, k_explicit_pdb_load_timeout_ms, "queue");
		auto wq_after_timeout = work_queue::stats();
		auto sq_after_timeout = work_queue::service_stats();
		auto cq_after_timeout = critical_work_queue::stats();
		diag::log_tagged_fmt("symbol_store",
			"explicit_pdb_timeout_schedule_end module=%s path='%s' file_size=%llu generation=%llu phase=queue scheduled=%d timeout_ms=%u work_pending=%zu work_active=%u work_rejected=%llu service_pending=%zu service_active=%u service_rejected=%llu critical_pending=%zu critical_active=%u critical_rejected=%llu parser_diag=\"%s\"",
			module_name.c_str(),
			path_copy.c_str(),
			static_cast<unsigned long long>(file_size_copy),
			static_cast<unsigned long long>(generation),
			queue_timeout_scheduled ? 1 : 0,
			k_explicit_pdb_load_timeout_ms,
			wq_after_timeout.pending,
			wq_after_timeout.active,
			static_cast<unsigned long long>(wq_after_timeout.rejected),
			sq_after_timeout.pending,
			sq_after_timeout.active,
			static_cast<unsigned long long>(sq_after_timeout.rejected),
			cq_after_timeout.pending,
			cq_after_timeout.active,
			static_cast<unsigned long long>(cq_after_timeout.rejected),
			pdb_parser::dbghelp_load_diagnostic().c_str());
	}
}

inline void auto_load_attached_modules()
{
	if (pdb_skip_active()) {
		suppress_full_test_pdb_load("auto_load_attached_modules", "<attached_modules>",
			0, 0, "<auto>", {}, 0, {}, {}, {},
			"full_test_declined_attached_module_auto_load", false);
		return;
	}
	auto modules = driver_bridge::enumerate_modules();
	for (auto& m : modules) {
		bool worth_loading = true;
		{
			std::lock_guard<std::mutex> lk(g_state.mutex);
			if (g_state.modules.find(m.name) == g_state.modules.end()) {
				std::string lower_name = m.name;
				std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(), ::tolower);

				worth_loading = (lower_name.find(".exe") != std::string::npos ||
				                 lower_name.find("game") != std::string::npos ||
				                 lower_name.find("engine") != std::string::npos);
			}
		}

		if (!worth_loading) continue;

		load_pdb_for_module(m.name, m.base, m.size);
	}
}

inline std::string resolve_symbol(uint64_t address)
{
	std::lock_guard<std::mutex> lk(g_state.mutex);

	for (auto& [mod_name, ms] : g_state.modules) {
		if (!ms.pdb.loaded) continue;
		if (address < ms.base || address >= ms.base + ms.size) continue;

		uint64_t rva = address - ms.base;

		auto it = ms.pdb.symbol_by_rva.find(rva);
		if (it != ms.pdb.symbol_by_rva.end()) {
			return mod_name + "!" + ms.pdb.symbols[it->second].name;
		}

		std::string best_name;
		uint64_t best_rva = 0;
		for (auto& sym : ms.pdb.symbols) {
			if (sym.is_function && sym.rva <= rva && sym.rva > best_rva) {
				best_rva = sym.rva;
				best_name = sym.name;
			}
		}

		if (!best_name.empty() && (rva - best_rva) < 0x10000) {
			char buf[256];
			snprintf(buf, sizeof(buf), "%s!%s+0x%llX", mod_name.c_str(), best_name.c_str(),
			         static_cast<unsigned long long>(rva - best_rva));
			return buf;
		}
	}

	return {};
}

inline std::string resolve_function_display_name(uint64_t address)
{
	std::lock_guard<std::mutex> lk(g_state.mutex);

	for (auto& [mod_name, ms] : g_state.modules) {
		if (!ms.pdb.loaded) continue;
		if (address < ms.base || address >= ms.base + ms.size) continue;

		uint64_t rva = address - ms.base;
		auto it = ms.pdb.symbol_by_rva.find(rva);
		if (it != ms.pdb.symbol_by_rva.end())
			return ms.pdb.symbols[it->second].name;

		const std::string* best_name = nullptr;
		uint64_t best_rva = 0;
		for (auto& sym : ms.pdb.symbols) {
			if (sym.is_function && sym.rva <= rva && sym.rva > best_rva &&
			    (rva - sym.rva) < 0x10000) {
				best_rva = sym.rva;
				best_name = &sym.name;
			}
		}
		if (best_name && best_rva == rva)
			return *best_name;
	}

	return {};
}

inline std::string resolve_symbol_exact(uint64_t address)
{
	std::lock_guard<std::mutex> lk(g_state.mutex);

	for (auto& [mod_name, ms] : g_state.modules) {
		if (!ms.pdb.loaded) continue;
		if (address < ms.base || address >= ms.base + ms.size) continue;

		uint64_t rva = address - ms.base;
		auto it = ms.pdb.symbol_by_rva.find(rva);
		if (it != ms.pdb.symbol_by_rva.end())
			return ms.pdb.symbols[it->second].name;
	}

	return {};
}

inline uint64_t resolve_name_to_addr(const std::string& input)
{
	if (input.empty())
		return 0;

	std::string trimmed = input;
	while (!trimmed.empty() && (trimmed.front() == ' ' || trimmed.front() == '\t'))
		trimmed.erase(trimmed.begin());
	while (!trimmed.empty() && (trimmed.back() == ' ' || trimmed.back() == '\t'))
		trimmed.pop_back();
	if (trimmed.empty())
		return 0;

	std::string mod_filter;
	std::string name = trimmed;
	auto bang = trimmed.find('!');
	if (bang != std::string::npos) {
		mod_filter = trimmed.substr(0, bang);
		name = trimmed.substr(bang + 1);
	}

	int64_t extra_offset = 0;
	auto plus = name.rfind('+');
	if (plus != std::string::npos && plus > 0) {
		std::string off_str = name.substr(plus + 1);
		std::string base_name = name.substr(0, plus);
		if (!off_str.empty()) {
			uint64_t off_val = 0;
			const char* off_cstr = off_str.c_str();
			if (off_str.size() > 2 && off_str[0] == '0' && (off_str[1] == 'x' || off_str[1] == 'X'))
				off_cstr = off_str.c_str() + 2;
			char* end = nullptr;
			off_val = std::strtoull(off_cstr, &end, 16);
			if (end && *end == '\0') {
				extra_offset = static_cast<int64_t>(off_val);
				name = base_name;
			}
		}
	}

	if (name.empty())
		return 0;

	auto eq_ci = [](const std::string& a, const std::string& b) {
		if (a.size() != b.size()) return false;
		for (size_t i = 0; i < a.size(); ++i) {
			char ca = a[i];
			char cb = b[i];
			if (ca >= 'A' && ca <= 'Z') ca = static_cast<char>(ca - 'A' + 'a');
			if (cb >= 'A' && cb <= 'Z') cb = static_cast<char>(cb - 'A' + 'a');
			if (ca != cb) return false;
		}
		return true;
	};

	if (name.size() > 4) {
		bool prefix_match = (name[0] == 's' || name[0] == 'S')
			&& (name[1] == 'u' || name[1] == 'U')
			&& (name[2] == 'b' || name[2] == 'B')
			&& name[3] == '_';
		if (prefix_match) {
			std::string hex_part = name.substr(4);
			if (!hex_part.empty()) {
				char* end = nullptr;
				uint64_t addr = std::strtoull(hex_part.c_str(), &end, 16);
				if (end && *end == '\0' && addr != 0)
					return addr + static_cast<uint64_t>(extra_offset);
			}
		}
	}

	std::lock_guard<std::mutex> lk(g_state.mutex);

	for (auto& [mod_name, ms] : g_state.modules) {
		if (!ms.pdb.loaded) continue;
		if (!mod_filter.empty()) {
			std::string mod_no_ext = mod_name;
			auto dot = mod_no_ext.rfind('.');
			if (dot != std::string::npos) mod_no_ext = mod_no_ext.substr(0, dot);
			if (!eq_ci(mod_filter, mod_name) && !eq_ci(mod_filter, mod_no_ext))
				continue;
		}

		auto it = ms.pdb.symbol_by_name.find(name);
		if (it != ms.pdb.symbol_by_name.end()) {
			uint64_t rva = ms.pdb.symbols[it->second].rva;
			return ms.base + rva + static_cast<uint64_t>(extra_offset);
		}
	}

	for (auto& [mod_name, ms] : g_state.modules) {
		if (!ms.pdb.loaded) continue;
		if (!mod_filter.empty()) {
			std::string mod_no_ext = mod_name;
			auto dot = mod_no_ext.rfind('.');
			if (dot != std::string::npos) mod_no_ext = mod_no_ext.substr(0, dot);
			if (!eq_ci(mod_filter, mod_name) && !eq_ci(mod_filter, mod_no_ext))
				continue;
		}

		for (auto& sym : ms.pdb.symbols) {
			if (eq_ci(sym.name, name))
				return ms.base + sym.rva + static_cast<uint64_t>(extra_offset);
		}
	}

	return 0;
}

inline const pdb_parser::struct_def_t* find_struct(const std::string& name)
{
	std::lock_guard<std::mutex> lk(g_state.mutex);

	for (auto& [mod_name, ms] : g_state.modules) {
		if (!ms.pdb.loaded) continue;
		auto it = ms.pdb.struct_by_name.find(name);
		if (it != ms.pdb.struct_by_name.end())
			return &ms.pdb.structs[it->second];
	}

	return nullptr;
}

inline std::vector<std::string> list_loaded_modules()
{
	std::lock_guard<std::mutex> lk(g_state.mutex);
	std::vector<std::string> out;
	out.reserve(g_state.modules.size());
	for (auto& [name, ms] : g_state.modules)
		out.push_back(name);
	return out;
}

inline const module_symbols_t* get_module(const std::string& name)
{
	std::lock_guard<std::mutex> lk(g_state.mutex);
	auto it = g_state.modules.find(name);
	if (it != g_state.modules.end())
		return &it->second;
	return nullptr;
}

inline void clear_all()
{
	std::vector<std::string> unloaded_names;
	{
		std::lock_guard<std::mutex> lk(g_state.mutex);
		unloaded_names.reserve(g_state.modules.size());
		for (auto& kv : g_state.modules) {
			if (kv.second.pdb.loaded)
				unloaded_names.push_back(kv.first);
		}
		g_state.modules.clear();
	}

	for (auto& name : unloaded_names) {
		aida::events::event_pdb_unloaded ev;
		ev.module_name = name;
		aida::events::publish(aida::events::event_pdb_unloaded_def, ev);
	}
}

inline void add_search_path(const std::string& path)
{
	for (auto& p : g_state.search_paths) {
		if (p == path) return;
	}
	g_state.search_paths.push_back(path);
}

}
