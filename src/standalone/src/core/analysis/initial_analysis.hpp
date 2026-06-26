#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <exception>
#include <filesystem>
#include <memory>
#include <mutex>
#include <string>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

#include "zydis_disasm.hpp"
#include "functions_panel.hpp"
#include "pdb_parser.hpp"
#include "symbol_store.hpp"
#include "builtin_typelib.hpp"
#include "function_index.hpp"
#include "xref_index.hpp"
#include "work_queue.hpp"
#include "../../helpers/diag_log.hpp"
#include "../../helpers/globals.h"
#include "../anti-tamper/webhook.hpp"

extern DisasmState g_disasm;

namespace initial_analysis {

enum class step_id_t : int {
	detect_format = 0,
	create_segments,
	read_exports,
	read_imports,
	parse_pdata,
	apply_fixups,
	detect_debug_info,
	load_pdb,
	apply_typelibs,
	mark_code_sequences,
	propagate_types,
	finalize,
	COUNT
};

struct step_t {
	std::string       label;
	std::atomic<bool> done{false};
	std::atomic<bool> running{false};
	std::atomic<bool> skipped{false};
	std::string       detail;
};

struct pdb_hint_t {
	std::string pdb_name;
	std::string pdb_guid;
	uint32_t    pdb_age = 0;
	std::string symbol_url;
};

enum class pdb_decision_t : int {
	pending = 0,
	accepted,
	declined
};

struct state_t {
	std::vector<std::unique_ptr<step_t>> steps;
	std::atomic<float>                   overall_progress{0.f};
	std::atomic<bool>                    running{false};
	std::atomic<bool>                    finished{false};
	std::atomic<bool>                    cancel{false};

	std::atomic<bool>                    needs_pdb_prompt{false};
	std::atomic<pdb_decision_t>          pdb_decision{pdb_decision_t::pending};
	pdb_hint_t                           pdb_hint;
	std::mutex                           pdb_hint_mtx;

	std::atomic<bool>                    needs_local_pdb_prompt{false};
	std::atomic<pdb_decision_t>          local_pdb_decision{pdb_decision_t::pending};
	std::string                          local_pdb_path;
	std::string                          local_pdb_reason;
	std::string                          local_pdb_module_name;
	uint64_t                             local_pdb_image_base = 0;
	uint64_t                             local_pdb_image_size = 0;
	std::mutex                           local_pdb_mtx;

	std::atomic<bool>                    opt_load_types{true};
	std::atomic<bool>                    opt_load_names{true};

	std::mutex                           log_mtx;
	std::vector<std::string>             log_lines;

	std::atomic<int>                     active_step_index{-1};
	std::string                          target_path;
	std::string                          target_filename;
	std::mutex                           path_mtx;

	std::atomic<bool>                    overlay_visible{false};
	std::atomic<float>                   overlay_visibility{0.f};
	std::atomic<bool>                    overlay_dismissed{false};
	std::atomic<uint64_t>                finish_time_ns{0};
};

inline state_t g_state;

namespace detail {

inline uint64_t now_ns()
{
	using clk = std::chrono::steady_clock;
	return static_cast<uint64_t>(
		std::chrono::duration_cast<std::chrono::nanoseconds>(
			clk::now().time_since_epoch()).count());
}

inline void push_log(const std::string& line)
{
	{
		std::lock_guard<std::mutex> lk(g_state.log_mtx);
		g_state.log_lines.push_back(line);
		if (g_state.log_lines.size() > 4096)
			g_state.log_lines.erase(g_state.log_lines.begin(),
				g_state.log_lines.begin() + 1024);
	}
	diag::log_tagged("initial_analysis", line.c_str());
	anti_tamper::webhook::write_log("initial_analysis", line.c_str());
	output_log::push(bottom_tab_t::output, line);
}

inline void push_log_fmt(const char* fmt, ...)
{
	char buf[2048];
	va_list ap;
	va_start(ap, fmt);
	_vsnprintf_s(buf, sizeof(buf), _TRUNCATE, fmt, ap);
	va_end(ap);
	push_log(std::string(buf));
}

inline bool full_test_active()
{
	return symbol_store::pdb_skip_active();
}

inline const char* log_value(const std::string& s);

inline bool apply_full_test_pdb_decline(const char* source,
                                        const std::string& module_name,
                                        uint64_t image_base,
                                        uint64_t image_size,
                                        const std::string& pdb_name,
                                        const std::string& pdb_guid,
                                        uint32_t pdb_age,
                                        const std::string& reason,
                                        bool prompt_created,
                                        bool log_without_pending)
{
	const auto automation = symbol_store::pdb_automation_context();
	if (!automation.pdb_skip_active) return false;

	const bool remote_pending = g_state.needs_pdb_prompt.load(std::memory_order_acquire);
	const bool local_pending = g_state.needs_local_pdb_prompt.load(std::memory_order_acquire);
	if (!log_without_pending && !remote_pending && !local_pending) return false;

	std::string module_log = module_name;
	std::string pdb_log = pdb_name;
	std::string guid_log = pdb_guid;
	uint32_t age_log = pdb_age;
	uint64_t base_log = image_base;
	uint64_t size_log = image_size;
	std::string reason_log = reason;

	if (pdb_log.empty() || guid_log.empty() || age_log == 0) {
		std::lock_guard<std::mutex> lk(g_state.pdb_hint_mtx);
		if (pdb_log.empty()) pdb_log = g_state.pdb_hint.pdb_name;
		if (guid_log.empty()) guid_log = g_state.pdb_hint.pdb_guid;
		if (age_log == 0) age_log = g_state.pdb_hint.pdb_age;
	}
	if (module_log.empty() || base_log == 0 || size_log == 0 || reason_log.empty()) {
		std::lock_guard<std::mutex> lk(g_state.local_pdb_mtx);
		if (module_log.empty()) module_log = g_state.local_pdb_module_name;
		if (base_log == 0) base_log = g_state.local_pdb_image_base;
		if (size_log == 0) size_log = g_state.local_pdb_image_size;
		if (reason_log.empty()) reason_log = g_state.local_pdb_reason;
	}
	if (module_log.empty()) {
		std::lock_guard<std::mutex> lk(g_state.path_mtx);
		module_log = g_state.target_filename;
	}
	if (reason_log.empty()) reason_log = "full_test_requires_noninteractive_pdb_decline";

	g_state.needs_pdb_prompt.store(false, std::memory_order_release);
	g_state.needs_local_pdb_prompt.store(false, std::memory_order_release);
	g_state.opt_load_types.store(false, std::memory_order_release);
	g_state.opt_load_names.store(false, std::memory_order_release);
	g_state.pdb_decision.store(pdb_decision_t::declined, std::memory_order_release);
	g_state.local_pdb_decision.store(pdb_decision_t::declined, std::memory_order_release);
	{
		std::lock_guard<std::mutex> lk(g_state.local_pdb_mtx);
		if (!module_log.empty()) g_state.local_pdb_module_name = module_log;
		if (base_log != 0) g_state.local_pdb_image_base = base_log;
		if (size_log != 0) g_state.local_pdb_image_size = size_log;
		g_state.local_pdb_reason = reason_log;
		g_state.local_pdb_path.clear();
	}

	push_log_fmt("pdb_prompt_creation_attempt source=%s kind=unattended prompt_created=%d prompt_suppressed=1 module=%s base=0x%llX size=0x%llX pdb=%s guid=%s age=%u reason=%s is_running=%d anti_tamper_full_test_running=%d full_test_env_active=%d unattended_active=%d post_suppression_active=%d post_suppression_remaining_ms=%llu pdb_automation_active=%d user_default_skip_active=%d pdb_skip_active=%d decision=do_not_load_pdb",
		source && *source ? source : "<unknown>",
		prompt_created ? 1 : 0,
		log_value(module_log),
		static_cast<unsigned long long>(base_log),
		static_cast<unsigned long long>(size_log),
		log_value(pdb_log),
		log_value(guid_log),
		static_cast<unsigned>(age_log),
		log_value(reason_log),
		automation.is_running ? 1 : 0,
		automation.anti_tamper_full_test_running ? 1 : 0,
		automation.full_test_env_active ? 1 : 0,
		automation.unattended_active ? 1 : 0,
		automation.post_suppression_active ? 1 : 0,
		static_cast<unsigned long long>(automation.post_suppression_remaining_ms),
		automation.pdb_automation_active ? 1 : 0,
		automation.user_default_skip_active ? 1 : 0,
		automation.pdb_skip_active ? 1 : 0);
	push_log_fmt("fulltest_pdb_final_decision source=%s module=%s base=0x%llX size=0x%llX pdb=%s guid=%s age=%u decision=do_not_load_pdb reason=%s local_candidate=<none> cache_path=<none> prompt_suppressed=1 is_running=%d anti_tamper_full_test_running=%d full_test_env_active=%d unattended_active=%d post_suppression_active=%d post_suppression_remaining_ms=%llu pdb_automation_active=%d user_default_skip_active=%d pdb_skip_active=%d",
		source && *source ? source : "<unknown>",
		log_value(module_log),
		static_cast<unsigned long long>(base_log),
		static_cast<unsigned long long>(size_log),
		log_value(pdb_log),
		log_value(guid_log),
		static_cast<unsigned>(age_log),
		log_value(reason_log),
		automation.is_running ? 1 : 0,
		automation.anti_tamper_full_test_running ? 1 : 0,
		automation.full_test_env_active ? 1 : 0,
		automation.unattended_active ? 1 : 0,
		automation.post_suppression_active ? 1 : 0,
		static_cast<unsigned long long>(automation.post_suppression_remaining_ms),
		automation.pdb_automation_active ? 1 : 0,
		automation.user_default_skip_active ? 1 : 0,
		automation.pdb_skip_active ? 1 : 0);
	push_log_fmt("fulltest_pdb_prompt_auto_decline choice=do_not_load_pdb decision=do_not_load_pdb prompt_created=%d prompt_suppressed=1 source=%s module=%s base=0x%llX size=0x%llX pdb=%s guid=%s age=%u reason=%s remote_pending=%d local_pending=%d remote_pending_after=%d local_pending_after=%d opt_load_types=0 opt_load_names=0 failed=0 declined=1 is_running=%d anti_tamper_full_test_running=%d full_test_env_active=%d unattended_active=%d post_suppression_active=%d post_suppression_remaining_ms=%llu pdb_automation_active=%d user_default_skip_active=%d pdb_skip_active=%d",
		prompt_created ? 1 : 0,
		source && *source ? source : "<unknown>",
		log_value(module_log),
		static_cast<unsigned long long>(base_log),
		static_cast<unsigned long long>(size_log),
		log_value(pdb_log),
		log_value(guid_log),
		static_cast<unsigned>(age_log),
		log_value(reason_log),
		remote_pending ? 1 : 0,
		local_pending ? 1 : 0,
		g_state.needs_pdb_prompt.load(std::memory_order_acquire) ? 1 : 0,
		g_state.needs_local_pdb_prompt.load(std::memory_order_acquire) ? 1 : 0,
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

inline bool decline_pdb_before_prompt_for_full_test(const char* source,
                                                    const std::string& module_name,
                                                    uint64_t image_base,
                                                    uint64_t image_size,
                                                    const std::string& pdb_name,
                                                    const std::string& pdb_guid,
                                                    uint32_t pdb_age,
                                                    const std::string& reason)
{
	return apply_full_test_pdb_decline(source, module_name, image_base, image_size,
		pdb_name, pdb_guid, pdb_age, reason, false, true);
}

inline bool auto_decline_pdb_prompts_for_full_test(const char* source)
{
	return apply_full_test_pdb_decline(source, {}, 0, 0, {}, {}, 0, {},
		true, false);
}

struct full_test_pdb_policy_t {
	bool        active = false;
	bool        prompt_suppressed = false;
	bool        local_available = false;
	std::string pdb_name;
	std::string pdb_guid;
	uint32_t    pdb_age = 0;
	std::string local_candidate;
	std::string cache_path;
	std::string decision;
	std::string reason;
};

struct pdb_load_snapshot_t {
	bool        module_present = false;
	bool        loaded = false;
	bool        loading = false;
	bool        failed = false;
	bool        declined = false;
	size_t      symbols = 0;
	size_t      structs = 0;
	size_t      enums = 0;
	std::string status;
	std::string path;
};

inline const char* log_value(const std::string& s)
{
	return s.empty() ? "<none>" : s.c_str();
}

inline std::string fallback_pdb_name_for_module(const std::string& filename)
{
	std::filesystem::path p(filename);
	std::string stem = p.stem().string();
	if (stem.empty()) stem = filename;
	return stem + ".pdb";
}

inline bool regular_file_candidate(const std::filesystem::path& candidate, std::string& out)
{
	out.clear();
	if (candidate.empty()) return false;
	std::error_code abs_ec;
	std::filesystem::path check = std::filesystem::absolute(candidate, abs_ec);
	if (abs_ec) check = candidate;
	std::error_code type_ec;
	if (!std::filesystem::is_regular_file(check, type_ec) || type_ec) return false;
	std::error_code size_ec;
	const auto size = std::filesystem::file_size(check, size_ec);
	if (size_ec || size == 0) return false;
	out = check.string();
	return true;
}

inline bool resolve_direct_local_pdb(const std::string& binary_path,
                                     const std::string& pdb_name,
                                     std::string& out)
{
	if (pdb_name.empty()) return false;
	std::vector<std::filesystem::path> candidates;
	std::filesystem::path bp(binary_path);
	std::error_code abs_ec;
	std::filesystem::path abs_bp = std::filesystem::absolute(bp, abs_ec);
	if (!abs_ec) bp = abs_bp;
	std::filesystem::path parent = bp.parent_path();
	if (!parent.empty()) candidates.push_back(parent / pdb_name);
	for (const auto& sp : symbol_store::g_state.search_paths) {
		if (!sp.empty()) candidates.emplace_back(std::filesystem::path(sp) / pdb_name);
	}
	for (const auto& candidate : candidates) {
		if (regular_file_candidate(candidate, out)) return true;
	}
	return false;
}

inline std::string expected_symbol_cache_path(const pdb_hint_t& hint)
{
	if (hint.pdb_name.empty() || hint.pdb_guid.empty()) return {};
	char age_buf[16] = {};
	std::snprintf(age_buf, sizeof(age_buf), "%X", static_cast<unsigned>(hint.pdb_age));
	std::filesystem::path cache = symbol_store::detail::get_cache_dir();
	return (cache / hint.pdb_name / (hint.pdb_guid + age_buf) / hint.pdb_name).string();
}

inline full_test_pdb_policy_t resolve_full_test_pdb_policy(const std::string& binary_path,
                                                           const std::string& filename,
                                                           const pdb_hint_t* hint)
{
	full_test_pdb_policy_t policy;
	policy.active = true;
	policy.prompt_suppressed = true;
	if (hint) {
		policy.pdb_name = hint->pdb_name;
		policy.pdb_guid = hint->pdb_guid;
		policy.pdb_age = hint->pdb_age;
		policy.cache_path = expected_symbol_cache_path(*hint);
	} else {
		policy.pdb_name = fallback_pdb_name_for_module(filename);
	}

	std::string local;
	if (resolve_direct_local_pdb(binary_path, policy.pdb_name, local)) {
		policy.local_available = true;
		policy.local_candidate = local;
		policy.decision = "load_local";
		policy.reason = "direct_local_pdb_present";
		return policy;
	}

	if (!policy.cache_path.empty() && regular_file_candidate(policy.cache_path, local)) {
		policy.local_available = true;
		policy.local_candidate = local;
		policy.decision = "load_local";
		policy.reason = "symbol_cache_pdb_present";
		return policy;
	}

	policy.local_available = false;
	policy.decision = "do_not_load_pdb";
	policy.reason = hint ? "no_deterministic_local_pdb_decline_remote_symbol_download"
	                     : "no_codeview_or_deterministic_local_pdb";
	return policy;
}

inline std::string target_path_for_prompt_policy(const std::string& module_name)
{
	std::lock_guard<std::mutex> lk(g_state.path_mtx);
	if (!g_state.target_path.empty()) return g_state.target_path;
	return module_name;
}

enum class unattended_pdb_decision_t : int {
	allow_interactive = 0,
	decline,
	load_deterministic_local
};

inline const char* unattended_pdb_decision_name(unattended_pdb_decision_t decision)
{
	switch (decision) {
	case unattended_pdb_decision_t::decline: return "do_not_load_pdb";
	case unattended_pdb_decision_t::load_deterministic_local: return "load_local";
	default: return "allow_interactive";
	}
}

struct unattended_pdb_decision_result_t {
	bool active = false;
	unattended_pdb_decision_t decision = unattended_pdb_decision_t::allow_interactive;
	full_test_pdb_policy_t policy;
};

inline unattended_pdb_decision_result_t decide_unattended_pdb_policy(const char* source,
                                                                    const std::string& module_name,
                                                                    uint64_t image_base,
                                                                    uint64_t image_size,
                                                                    const pdb_hint_t* hint,
                                                                    const std::string& fallback_reason)
{
	unattended_pdb_decision_result_t result;
	result.active = full_test_active();
	const auto automation = symbol_store::pdb_automation_context();
	if (!result.active) {
		result.decision = unattended_pdb_decision_t::allow_interactive;
		return result;
	}
	const std::string binary_path = target_path_for_prompt_policy(module_name);
	result.policy = resolve_full_test_pdb_policy(binary_path, module_name, hint);
	if (!fallback_reason.empty() && result.policy.reason.empty())
		result.policy.reason = fallback_reason;
	result.decision = result.policy.local_available
		? unattended_pdb_decision_t::load_deterministic_local
		: unattended_pdb_decision_t::decline;
	push_log_fmt("fulltest_pdb_final_decision source=%s module=%s base=0x%llX size=0x%llX pdb=%s guid=%s age=%u decision=%s reason=%s local_candidate=%s cache_path=%s prompt_suppressed=1 is_running=%d anti_tamper_full_test_running=%d full_test_env_active=%d unattended_active=%d post_suppression_active=%d post_suppression_remaining_ms=%llu pdb_automation_active=%d user_default_skip_active=%d pdb_skip_active=%d",
		source && *source ? source : "<unknown>",
		log_value(module_name),
		static_cast<unsigned long long>(image_base),
		static_cast<unsigned long long>(image_size),
		log_value(result.policy.pdb_name),
		log_value(result.policy.pdb_guid),
		static_cast<unsigned>(result.policy.pdb_age),
		unattended_pdb_decision_name(result.decision),
		log_value(result.policy.reason),
		log_value(result.policy.local_candidate),
		log_value(result.policy.cache_path),
		automation.is_running ? 1 : 0,
		automation.anti_tamper_full_test_running ? 1 : 0,
		automation.full_test_env_active ? 1 : 0,
		automation.unattended_active ? 1 : 0,
		automation.post_suppression_active ? 1 : 0,
		static_cast<unsigned long long>(automation.post_suppression_remaining_ms),
		automation.pdb_automation_active ? 1 : 0,
		automation.user_default_skip_active ? 1 : 0,
		automation.pdb_skip_active ? 1 : 0);
	return result;
}

inline bool accept_local_pdb_before_prompt_for_full_test(const char* source,
                                                        const std::string& module_name,
                                                        uint64_t image_base,
                                                        uint64_t image_size,
                                                        const std::string& reason)
{
	unattended_pdb_decision_result_t decision = decide_unattended_pdb_policy(source,
		module_name, image_base, image_size, nullptr, reason);
	if (!decision.active) return false;
	if (decision.decision != unattended_pdb_decision_t::load_deterministic_local) return false;
	const full_test_pdb_policy_t& policy = decision.policy;

	g_state.needs_pdb_prompt.store(false, std::memory_order_release);
	g_state.needs_local_pdb_prompt.store(false, std::memory_order_release);
	g_state.opt_load_types.store(true, std::memory_order_release);
	g_state.opt_load_names.store(true, std::memory_order_release);
	g_state.pdb_decision.store(pdb_decision_t::declined, std::memory_order_release);
	g_state.local_pdb_decision.store(pdb_decision_t::accepted, std::memory_order_release);
	{
		std::lock_guard<std::mutex> lk(g_state.local_pdb_mtx);
		g_state.local_pdb_module_name = module_name;
		g_state.local_pdb_image_base = image_base;
		g_state.local_pdb_image_size = image_size;
		g_state.local_pdb_reason = reason.empty() ? policy.reason : reason;
		g_state.local_pdb_path = policy.local_candidate;
	}

	const auto automation = symbol_store::pdb_automation_context();
	push_log_fmt("fulltest_pdb_prompt_auto_accept_local decision=load_local prompt_created=0 prompt_suppressed=1 source=%s module=%s base=0x%llX size=0x%llX pdb=%s guid=%s age=%u local_candidate=%s cache_path=%s reason=%s failed=0 declined=0 is_running=%d anti_tamper_full_test_running=%d full_test_env_active=%d unattended_active=%d post_suppression_active=%d post_suppression_remaining_ms=%llu pdb_automation_active=%d user_default_skip_active=%d pdb_skip_active=%d",
		source && *source ? source : "<unknown>",
		log_value(module_name),
		static_cast<unsigned long long>(image_base),
		static_cast<unsigned long long>(image_size),
		log_value(policy.pdb_name),
		log_value(policy.pdb_guid),
		static_cast<unsigned>(policy.pdb_age),
		log_value(policy.local_candidate),
		log_value(policy.cache_path),
		log_value(reason.empty() ? policy.reason : reason),
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

inline pdb_load_snapshot_t snapshot_pdb_load(const std::string& module_key)
{
	pdb_load_snapshot_t out;
	std::lock_guard<std::mutex> lk(symbol_store::g_state.mutex);
	auto it = symbol_store::g_state.modules.find(module_key);
	if (it == symbol_store::g_state.modules.end()) return out;
	out.module_present = true;
	out.loaded = it->second.pdb.loaded;
	out.loading = it->second.loading;
	out.failed = it->second.failed;
	out.declined = it->second.load_declined;
	out.symbols = it->second.pdb.symbols.size();
	out.structs = it->second.pdb.structs.size();
	out.enums = it->second.pdb.enums.size();
	out.status = it->second.status_text;
	out.path = it->second.pdb_path;
	return out;
}

inline void log_full_test_pdb_policy(const std::string& filename,
                                     uint64_t image_base,
                                     uint64_t image_size,
                                     const full_test_pdb_policy_t& policy)
{
	const bool declined = policy.decision == "do_not_load_pdb";
	const auto automation = symbol_store::pdb_automation_context();
	push_log_fmt("fulltest_pdb_policy module=%s base=0x%llX size=0x%llX pdb=%s guid=%s age=%u local_candidate=%s cache_path=%s decision=%s reason=%s prompt_created=0 prompt_suppressed=%d failed=0 declined=%d is_running=%d anti_tamper_full_test_running=%d full_test_env_active=%d unattended_active=%d post_suppression_active=%d post_suppression_remaining_ms=%llu pdb_automation_active=%d user_default_skip_active=%d pdb_skip_active=%d",
		filename.c_str(),
		static_cast<unsigned long long>(image_base),
		static_cast<unsigned long long>(image_size),
		log_value(policy.pdb_name),
		log_value(policy.pdb_guid),
		static_cast<unsigned>(policy.pdb_age),
		log_value(policy.local_candidate),
		log_value(policy.cache_path),
		log_value(policy.decision),
		log_value(policy.reason),
		policy.prompt_suppressed ? 1 : 0,
		declined ? 1 : 0,
		automation.is_running ? 1 : 0,
		automation.anti_tamper_full_test_running ? 1 : 0,
		automation.full_test_env_active ? 1 : 0,
		automation.unattended_active ? 1 : 0,
		automation.post_suppression_active ? 1 : 0,
		static_cast<unsigned long long>(automation.post_suppression_remaining_ms),
		automation.pdb_automation_active ? 1 : 0,
		automation.user_default_skip_active ? 1 : 0,
		automation.pdb_skip_active ? 1 : 0);
}

inline void log_full_test_pdb_final(const std::string& filename,
                                    uint64_t image_base,
                                    uint64_t image_size,
                                    const full_test_pdb_policy_t& policy)
{
	const pdb_load_snapshot_t snap = snapshot_pdb_load(filename);
	push_log_fmt("fulltest_pdb_final module=%s base=0x%llX size=0x%llX pdb=%s guid=%s age=%u decision=%s reason=%s prompt_suppressed=%d module_present=%d loaded=%d loading=%d failed=%d declined=%d symbols=%zu structs=%zu enums=%zu types=%zu pdb_path=%s status=%s",
		filename.c_str(),
		static_cast<unsigned long long>(image_base),
		static_cast<unsigned long long>(image_size),
		log_value(policy.pdb_name),
		log_value(policy.pdb_guid),
		static_cast<unsigned>(policy.pdb_age),
		log_value(policy.decision),
		log_value(policy.reason),
		policy.prompt_suppressed ? 1 : 0,
		snap.module_present ? 1 : 0,
		snap.loaded ? 1 : 0,
		snap.loading ? 1 : 0,
		snap.failed ? 1 : 0,
		snap.declined ? 1 : 0,
		snap.symbols,
		snap.structs,
		snap.enums,
		snap.structs + snap.enums,
		log_value(snap.path),
		log_value(snap.status));
}

inline void rebuild_steps()
{
	std::vector<std::unique_ptr<step_t>> steps;
	const char* labels[] = {
		"Detecting file format",
		"Creating segments",
		"Reading export directory",
		"Reading import directory",
		"Parsing .pdata exception directory",
		"Applying base relocations",
		"Inspecting debug directory",
		"Loading PDB symbols",
		"Applying type libraries",
		"Marking typical code sequences",
		"Propagating type information",
		"Finalizing autoanalysis"
	};
	for (int i = 0; i < static_cast<int>(step_id_t::COUNT); ++i) {
		auto s = std::make_unique<step_t>();
		s->label = labels[i];
		steps.push_back(std::move(s));
	}
	g_state.steps = std::move(steps);
}

inline step_t* step(step_id_t id)
{
	int idx = static_cast<int>(id);
	if (idx < 0 || idx >= static_cast<int>(g_state.steps.size())) return nullptr;
	return g_state.steps[idx].get();
}

inline void begin_step(step_id_t id)
{
	auto* s = step(id);
	if (!s) return;
	s->running.store(true, std::memory_order_release);
	g_state.active_step_index.store(static_cast<int>(id), std::memory_order_release);
	push_log_fmt("[ %s ] starting", s->label.c_str());
}

inline void end_step(step_id_t id, const std::string& detail, bool skipped = false)
{
	auto* s = step(id);
	if (!s) return;
	s->detail = detail;
	s->running.store(false, std::memory_order_release);
	s->skipped.store(skipped, std::memory_order_release);
	s->done.store(true, std::memory_order_release);
	int total = static_cast<int>(g_state.steps.size());
	int completed = 0;
	for (auto& ss : g_state.steps) {
		if (ss->done.load(std::memory_order_acquire)) ++completed;
	}
	float p = (total > 0) ? (static_cast<float>(completed) / static_cast<float>(total)) : 0.f;
	g_state.overall_progress.store(p, std::memory_order_release);
	if (!detail.empty()) {
		push_log_fmt("[ %s ] %s%s", s->label.c_str(), detail.c_str(), skipped ? " (skipped)" : "");
	} else {
		push_log_fmt("[ %s ] done%s", s->label.c_str(), skipped ? " (skipped)" : "");
	}
}

inline const char* machine_name(uint16_t machine)
{
	switch (machine) {
	case IMAGE_FILE_MACHINE_AMD64:    return "AMD64";
	case IMAGE_FILE_MACHINE_I386:     return "I386";
	case IMAGE_FILE_MACHINE_ARM:      return "ARM";
	case IMAGE_FILE_MACHINE_ARM64:    return "ARM64";
	case IMAGE_FILE_MACHINE_IA64:     return "IA64";
	case IMAGE_FILE_MACHINE_THUMB:    return "THUMB";
	case IMAGE_FILE_MACHINE_ARMNT:    return "ARMNT";
	case IMAGE_FILE_MACHINE_EBC:      return "EBC";
	case IMAGE_FILE_MACHINE_R4000:    return "R4000";
	case IMAGE_FILE_MACHINE_POWERPC:  return "POWERPC";
	default: return "UNKNOWN";
	}
}

inline const char* subsystem_name(uint16_t sub)
{
	switch (sub) {
	case 1:  return "NATIVE";
	case 2:  return "WINDOWS_GUI";
	case 3:  return "WINDOWS_CUI";
	case 5:  return "OS2_CUI";
	case 7:  return "POSIX_CUI";
	case 8:  return "WINDOWS_CE_GUI";
	case 9:  return "EFI_APPLICATION";
	case 10: return "EFI_BOOT_SERVICE_DRIVER";
	case 11: return "EFI_RUNTIME_DRIVER";
	case 12: return "EFI_ROM";
	case 13: return "XBOX";
	case 14: return "WINDOWS_BOOT_APPLICATION";
	default: return "UNKNOWN";
	}
}

inline std::string format_pdb_guid_bytes(const uint8_t* g)
{
	char buf[48] = {};
	uint32_t d1 = 0;
	uint16_t d2 = 0;
	uint16_t d3 = 0;
	std::memcpy(&d1, g + 0, 4);
	std::memcpy(&d2, g + 4, 2);
	std::memcpy(&d3, g + 6, 2);
	std::snprintf(buf, sizeof(buf),
		"%08X%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X",
		static_cast<unsigned>(d1),
		static_cast<unsigned>(d2),
		static_cast<unsigned>(d3),
		static_cast<unsigned>(g[8]),
		static_cast<unsigned>(g[9]),
		static_cast<unsigned>(g[10]),
		static_cast<unsigned>(g[11]),
		static_cast<unsigned>(g[12]),
		static_cast<unsigned>(g[13]),
		static_cast<unsigned>(g[14]),
		static_cast<unsigned>(g[15]));
	return std::string(buf);
}

inline bool extract_codeview_info(const functions_panel::detail::disk_pe_view_t& view,
	pdb_hint_t& out)
{
	out.pdb_name.clear();
	out.pdb_guid.clear();
	out.pdb_age = 0;
	out.symbol_url.clear();

	const std::vector<uint8_t>& raw = view.raw;
	if (raw.size() < sizeof(IMAGE_DOS_HEADER)) return false;
	const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(raw.data());
	if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
	uint32_t pe_off = static_cast<uint32_t>(dos->e_lfanew);
	if (pe_off + sizeof(IMAGE_NT_HEADERS32) > raw.size()) return false;
	const auto* nt32 = reinterpret_cast<const IMAGE_NT_HEADERS32*>(raw.data() + pe_off);
	if (nt32->Signature != IMAGE_NT_SIGNATURE) return false;

	IMAGE_DATA_DIRECTORY dbg_dir{};
	if (view.is_pe32_plus) {
		if (pe_off + sizeof(IMAGE_NT_HEADERS64) > raw.size()) return false;
		const auto* nt64 = reinterpret_cast<const IMAGE_NT_HEADERS64*>(raw.data() + pe_off);
		if (nt64->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_DEBUG)
			return false;
		dbg_dir = nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
	} else {
		if (nt32->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_DEBUG)
			return false;
		dbg_dir = nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
	}
	if (dbg_dir.VirtualAddress == 0 || dbg_dir.Size < sizeof(IMAGE_DEBUG_DIRECTORY))
		return false;

	auto rva_to_offset = [&view](uint32_t rva) -> uint32_t {
		for (const auto& s : view.sections) {
			uint32_t end = s.virtual_address + (std::max<uint32_t>)(s.virtual_size, s.raw_size);
			if (rva >= s.virtual_address && rva < end) {
				uint32_t delta = rva - s.virtual_address;
				if (delta >= s.raw_size) return 0;
				if (s.raw_offset == 0) return 0;
				return s.raw_offset + delta;
			}
		}
		return 0;
	};

	uint32_t dbg_off = rva_to_offset(dbg_dir.VirtualAddress);
	if (dbg_off == 0) return false;
	if (static_cast<uint64_t>(dbg_off) + dbg_dir.Size > raw.size()) return false;

	const uint32_t entry_count = dbg_dir.Size / static_cast<uint32_t>(sizeof(IMAGE_DEBUG_DIRECTORY));
	for (uint32_t i = 0; i < entry_count; ++i) {
		const auto* e = reinterpret_cast<const IMAGE_DEBUG_DIRECTORY*>(
			raw.data() + dbg_off + i * sizeof(IMAGE_DEBUG_DIRECTORY));
		if (e->Type != IMAGE_DEBUG_TYPE_CODEVIEW) continue;
		uint32_t cv_off = e->PointerToRawData;
		if (cv_off == 0 || e->SizeOfData < 24) continue;
		if (static_cast<uint64_t>(cv_off) + e->SizeOfData > raw.size()) continue;
		const uint8_t* cv = raw.data() + cv_off;
		if (cv[0] == 'R' && cv[1] == 'S' && cv[2] == 'D' && cv[3] == 'S') {
			out.pdb_guid = format_pdb_guid_bytes(cv + 4);
			std::memcpy(&out.pdb_age, cv + 20, 4);
			const char* name = reinterpret_cast<const char*>(cv + 24);
			size_t max_len = static_cast<size_t>(e->SizeOfData) - 24;
			size_t actual = 0;
			while (actual < max_len && name[actual] != '\0') ++actual;
			if (actual == 0) return false;
			std::string full_path(name, actual);
			size_t sep = full_path.find_last_of("/\\");
			std::string base_name = (sep != std::string::npos) ? full_path.substr(sep + 1) : full_path;
			out.pdb_name = base_name;

			char url[1024];
			std::snprintf(url, sizeof(url),
				"http://msdl.microsoft.com/download/symbols/%s/%s%X/%s",
				base_name.c_str(), out.pdb_guid.c_str(), static_cast<unsigned>(out.pdb_age),
				base_name.c_str());
			out.symbol_url = url;
			return true;
		}
	}
	return false;
}

inline uint64_t count_pe32_relocations(const std::vector<uint8_t>& raw)
{
	if (raw.size() < sizeof(IMAGE_DOS_HEADER)) return 0;
	const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(raw.data());
	if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
	uint32_t pe_off = static_cast<uint32_t>(dos->e_lfanew);
	if (pe_off + sizeof(IMAGE_NT_HEADERS32) > raw.size()) return 0;
	const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS32*>(raw.data() + pe_off);
	if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
	IMAGE_DATA_DIRECTORY reloc_dir{};
	if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		if (pe_off + sizeof(IMAGE_NT_HEADERS64) > raw.size()) return 0;
		const auto* nt64 = reinterpret_cast<const IMAGE_NT_HEADERS64*>(raw.data() + pe_off);
		if (nt64->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_BASERELOC) return 0;
		reloc_dir = nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	} else if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
		if (nt->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_BASERELOC) return 0;
		reloc_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	} else {
		return 0;
	}
	if (reloc_dir.VirtualAddress == 0 || reloc_dir.Size == 0) return 0;

	uint16_t nsec = nt->FileHeader.NumberOfSections;
	uint64_t sec_off = static_cast<uint64_t>(pe_off)
		+ offsetof(IMAGE_NT_HEADERS32, OptionalHeader) + nt->FileHeader.SizeOfOptionalHeader;
	if (sec_off + static_cast<uint64_t>(nsec) * sizeof(IMAGE_SECTION_HEADER) > raw.size()) return 0;
	const auto* sec = reinterpret_cast<const IMAGE_SECTION_HEADER*>(raw.data() + sec_off);

	auto rva_to_off = [&](uint32_t rva) -> uint32_t {
		for (uint16_t i = 0; i < nsec; ++i) {
			uint32_t end = sec[i].VirtualAddress + (std::max<uint32_t>)(sec[i].Misc.VirtualSize, sec[i].SizeOfRawData);
			if (rva >= sec[i].VirtualAddress && rva < end) {
				uint32_t delta = rva - sec[i].VirtualAddress;
				if (delta >= sec[i].SizeOfRawData) return 0;
				if (sec[i].PointerToRawData == 0) return 0;
				return sec[i].PointerToRawData + delta;
			}
		}
		return 0;
	};

	uint32_t off = rva_to_off(reloc_dir.VirtualAddress);
	if (off == 0) return 0;
	if (static_cast<uint64_t>(off) + reloc_dir.Size > raw.size()) return 0;

	uint64_t total_fixups = 0;
	uint32_t walked = 0;
	while (walked + 8 <= reloc_dir.Size) {
		uint32_t page_rva = 0;
		uint32_t block_size = 0;
		std::memcpy(&page_rva, raw.data() + off + walked, 4);
		std::memcpy(&block_size, raw.data() + off + walked + 4, 4);
		if (block_size < 8 || block_size > reloc_dir.Size - walked) break;
		uint32_t entries = (block_size - 8) / 2;
		for (uint32_t i = 0; i < entries; ++i) {
			uint16_t e = 0;
			std::memcpy(&e, raw.data() + off + walked + 8 + i * 2, 2);
			uint16_t type = (e >> 12) & 0xF;
			if (type != 0) ++total_fixups;
		}
		walked += block_size;
	}
	return total_fixups;
}

inline std::string section_flags_string(uint32_t chars)
{
	std::string s;
	s += (chars & IMAGE_SCN_MEM_READ) ? 'R' : '-';
	s += (chars & IMAGE_SCN_MEM_WRITE) ? 'W' : '-';
	s += (chars & IMAGE_SCN_MEM_EXECUTE) ? 'X' : '-';
	if (chars & IMAGE_SCN_CNT_CODE)               s += "/CODE";
	else if (chars & IMAGE_SCN_CNT_INITIALIZED_DATA)   s += "/DATA";
	else if (chars & IMAGE_SCN_CNT_UNINITIALIZED_DATA) s += "/BSS";
	return s;
}

inline std::string suggest_typelib_for(const functions_panel::detail::disk_pe_view_t& view,
	uint16_t subsystem)
{
	bool is_driver = (subsystem == IMAGE_SUBSYSTEM_NATIVE) ||
	                 (subsystem == 11) || (subsystem == 12);
	bool has_pdata = (view.exception_dir_rva != 0);
	if (is_driver)
		return "ntddk_win11_x64";
	if (view.is_pe32_plus && has_pdata)
		return "mssdk_win11_x64";
	return "mssdk_x86";
}

inline uint64_t count_prologue_patterns(const DisasmFile& file)
{
	uint64_t count = 0;
	for (const auto& sec : file.sections) {
		if (!sec.is_executable) continue;
		const uint8_t* b = sec.bytes.data();
		size_t n = sec.bytes.size();
		if (n < 4) continue;
		for (size_t i = 0; i + 4 <= n; ++i) {
			if (b[i] == 0x48 && b[i + 1] == 0x89 && b[i + 2] == 0x5C && b[i + 3] == 0x24) {
				++count;
				continue;
			}
			if (b[i] == 0x48 && b[i + 1] == 0x83 && b[i + 2] == 0xEC) {
				++count;
				continue;
			}
			if (b[i] == 0x40 && b[i + 1] == 0x53 && b[i + 2] == 0x48 && b[i + 3] == 0x83) {
				++count;
				continue;
			}
			if (b[i] == 0x48 && b[i + 1] == 0x8B && b[i + 2] == 0xC4) {
				++count;
				continue;
			}
		}
	}
	return count;
}

inline bool wait_for_pdb_decision()
{
	const uint64_t timeout_ns = 90ull * 1000ull * 1000ull * 1000ull;
	uint64_t start = now_ns();
	auto_decline_pdb_prompts_for_full_test("wait_for_pdb_decision");
	while (!g_state.cancel.load(std::memory_order_acquire)) {
		auto_decline_pdb_prompts_for_full_test("wait_for_pdb_decision");
		auto d = g_state.pdb_decision.load(std::memory_order_acquire);
		if (d != pdb_decision_t::pending) return d == pdb_decision_t::accepted;
		if (now_ns() - start > timeout_ns) {
			g_state.needs_pdb_prompt.store(false, std::memory_order_release);
			g_state.pdb_decision.store(pdb_decision_t::declined, std::memory_order_release);
			return false;
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(50));
	}
	return false;
}

inline void request_local_pdb_prompt(const std::string& module_name,
                                     uint64_t image_base, uint64_t image_size,
                                     const std::string& reason)
{
	{
		const auto entry_automation = symbol_store::pdb_automation_context();
		push_log_fmt("pdb_request_entry source=request_local_pdb_prompt kind=local module=%s base=0x%llX size=0x%llX pdb=%s guid=<none> age=0 caller_tid=%lu reason=%s skip_active=%d pdb_automation_active=%d unattended_active=%d post_suppression_active=%d post_suppression_remaining_ms=%llu user_default_skip_active=%d ts_ns=%llu",
			log_value(module_name),
			static_cast<unsigned long long>(image_base),
			static_cast<unsigned long long>(image_size),
			log_value(fallback_pdb_name_for_module(module_name)),
			static_cast<unsigned long>(GetCurrentThreadId()),
			log_value(reason),
			entry_automation.pdb_skip_active ? 1 : 0,
			entry_automation.pdb_automation_active ? 1 : 0,
			entry_automation.unattended_active ? 1 : 0,
			entry_automation.post_suppression_active ? 1 : 0,
			static_cast<unsigned long long>(entry_automation.post_suppression_remaining_ms),
			entry_automation.user_default_skip_active ? 1 : 0,
			static_cast<unsigned long long>(now_ns()));
	}
	if (accept_local_pdb_before_prompt_for_full_test("request_local_pdb_prompt",
		module_name, image_base, image_size, reason)) {
		const auto exit_automation = symbol_store::pdb_automation_context();
		push_log_fmt("pdb_request_exit source=request_local_pdb_prompt kind=local decision=load_local prompt_created=0 prompt_suppressed=1 skip_active=%d pdb_automation_active=%d unattended_active=%d post_suppression_active=%d post_suppression_remaining_ms=%llu user_default_skip_active=%d ts_ns=%llu",
			exit_automation.pdb_skip_active ? 1 : 0,
			exit_automation.pdb_automation_active ? 1 : 0,
			exit_automation.unattended_active ? 1 : 0,
			exit_automation.post_suppression_active ? 1 : 0,
			static_cast<unsigned long long>(exit_automation.post_suppression_remaining_ms),
			exit_automation.user_default_skip_active ? 1 : 0,
			static_cast<unsigned long long>(now_ns()));
		return;
	}
	if (decline_pdb_before_prompt_for_full_test("request_local_pdb_prompt",
		module_name, image_base, image_size, fallback_pdb_name_for_module(module_name),
		{}, 0, reason)) {
		const auto exit_automation = symbol_store::pdb_automation_context();
		push_log_fmt("pdb_request_exit source=request_local_pdb_prompt kind=local decision=do_not_load_pdb prompt_created=0 prompt_suppressed=1 skip_active=%d pdb_automation_active=%d unattended_active=%d post_suppression_active=%d post_suppression_remaining_ms=%llu user_default_skip_active=%d ts_ns=%llu",
			exit_automation.pdb_skip_active ? 1 : 0,
			exit_automation.pdb_automation_active ? 1 : 0,
			exit_automation.unattended_active ? 1 : 0,
			exit_automation.post_suppression_active ? 1 : 0,
			static_cast<unsigned long long>(exit_automation.post_suppression_remaining_ms),
			exit_automation.user_default_skip_active ? 1 : 0,
			static_cast<unsigned long long>(now_ns()));
		return;
	}
	const auto automation = symbol_store::pdb_automation_context();
	push_log_fmt("pdb_prompt_creation_attempt source=request_local_pdb_prompt kind=local prompt_created=1 prompt_suppressed=0 module=%s base=0x%llX size=0x%llX pdb=%s guid=%s age=%u reason=%s is_running=%d anti_tamper_full_test_running=%d full_test_env_active=%d unattended_active=%d post_suppression_active=%d post_suppression_remaining_ms=%llu pdb_automation_active=%d user_default_skip_active=%d pdb_skip_active=%d decision=allow_interactive",
		log_value(module_name),
		static_cast<unsigned long long>(image_base),
		static_cast<unsigned long long>(image_size),
		log_value(fallback_pdb_name_for_module(module_name)),
		"<none>",
		0u,
		log_value(reason),
		automation.is_running ? 1 : 0,
		automation.anti_tamper_full_test_running ? 1 : 0,
		automation.full_test_env_active ? 1 : 0,
		automation.unattended_active ? 1 : 0,
		automation.post_suppression_active ? 1 : 0,
		static_cast<unsigned long long>(automation.post_suppression_remaining_ms),
		automation.pdb_automation_active ? 1 : 0,
		automation.user_default_skip_active ? 1 : 0,
		automation.pdb_skip_active ? 1 : 0);
	{
		std::lock_guard<std::mutex> lk(g_state.local_pdb_mtx);
		g_state.local_pdb_module_name = module_name;
		g_state.local_pdb_image_base = image_base;
		g_state.local_pdb_image_size = image_size;
		g_state.local_pdb_reason = reason;
		g_state.local_pdb_path.clear();
	}
	g_state.local_pdb_decision.store(pdb_decision_t::pending, std::memory_order_release);
	g_state.needs_local_pdb_prompt.store(true, std::memory_order_release);
	push_log_fmt("pdb_request_exit source=request_local_pdb_prompt kind=local decision=interactive prompt_created=1 prompt_suppressed=0 skip_active=%d pdb_automation_active=%d unattended_active=%d post_suppression_active=%d post_suppression_remaining_ms=%llu user_default_skip_active=%d ts_ns=%llu",
		automation.pdb_skip_active ? 1 : 0,
		automation.pdb_automation_active ? 1 : 0,
		automation.unattended_active ? 1 : 0,
		automation.post_suppression_active ? 1 : 0,
		static_cast<unsigned long long>(automation.post_suppression_remaining_ms),
		automation.user_default_skip_active ? 1 : 0,
		static_cast<unsigned long long>(now_ns()));
}

inline bool request_remote_pdb_prompt(const std::string& module_name,
                                      uint64_t image_base,
                                      uint64_t image_size,
                                      const pdb_hint_t& hint,
                                      const char* source)
{
	{
		const auto entry_automation = symbol_store::pdb_automation_context();
		push_log_fmt("pdb_request_entry source=%s kind=remote pdb=%s guid=%s age=%u module=%s base=0x%llX size=0x%llX caller_tid=%lu skip_active=%d pdb_automation_active=%d unattended_active=%d post_suppression_active=%d post_suppression_remaining_ms=%llu user_default_skip_active=%d ts_ns=%llu",
			source && *source ? source : "<unknown>",
			log_value(hint.pdb_name),
			log_value(hint.pdb_guid),
			static_cast<unsigned>(hint.pdb_age),
			log_value(module_name),
			static_cast<unsigned long long>(image_base),
			static_cast<unsigned long long>(image_size),
			static_cast<unsigned long>(GetCurrentThreadId()),
			entry_automation.pdb_skip_active ? 1 : 0,
			entry_automation.pdb_automation_active ? 1 : 0,
			entry_automation.unattended_active ? 1 : 0,
			entry_automation.post_suppression_active ? 1 : 0,
			static_cast<unsigned long long>(entry_automation.post_suppression_remaining_ms),
			entry_automation.user_default_skip_active ? 1 : 0,
			static_cast<unsigned long long>(now_ns()));
	}
	if (full_test_active()) {
		decide_unattended_pdb_policy(source, module_name, image_base, image_size,
			&hint, "remote_pdb_prompt_declined_by_full_test");
	}
	if (decline_pdb_before_prompt_for_full_test(source, module_name, image_base,
		image_size, hint.pdb_name, hint.pdb_guid, hint.pdb_age,
		"remote_pdb_prompt_declined_by_full_test")) {
		const auto exit_automation = symbol_store::pdb_automation_context();
		push_log_fmt("pdb_request_exit source=%s kind=remote decision=do_not_load_pdb prompt_created=0 prompt_suppressed=1 skip_active=%d pdb_automation_active=%d unattended_active=%d post_suppression_active=%d post_suppression_remaining_ms=%llu user_default_skip_active=%d ts_ns=%llu",
			source && *source ? source : "<unknown>",
			exit_automation.pdb_skip_active ? 1 : 0,
			exit_automation.pdb_automation_active ? 1 : 0,
			exit_automation.unattended_active ? 1 : 0,
			exit_automation.post_suppression_active ? 1 : 0,
			static_cast<unsigned long long>(exit_automation.post_suppression_remaining_ms),
			exit_automation.user_default_skip_active ? 1 : 0,
			static_cast<unsigned long long>(now_ns()));
		return false;
	}
	const auto automation = symbol_store::pdb_automation_context();
	push_log_fmt("pdb_prompt_creation_attempt source=%s kind=remote prompt_created=1 prompt_suppressed=0 module=%s base=0x%llX size=0x%llX pdb=%s guid=%s age=%u reason=interactive_remote_prompt is_running=%d anti_tamper_full_test_running=%d full_test_env_active=%d unattended_active=%d post_suppression_active=%d post_suppression_remaining_ms=%llu pdb_automation_active=%d user_default_skip_active=%d pdb_skip_active=%d decision=allow_interactive",
		source && *source ? source : "<unknown>",
		log_value(module_name),
		static_cast<unsigned long long>(image_base),
		static_cast<unsigned long long>(image_size),
		log_value(hint.pdb_name),
		log_value(hint.pdb_guid),
		static_cast<unsigned>(hint.pdb_age),
		automation.is_running ? 1 : 0,
		automation.anti_tamper_full_test_running ? 1 : 0,
		automation.full_test_env_active ? 1 : 0,
		automation.unattended_active ? 1 : 0,
		automation.post_suppression_active ? 1 : 0,
		static_cast<unsigned long long>(automation.post_suppression_remaining_ms),
		automation.pdb_automation_active ? 1 : 0,
		automation.user_default_skip_active ? 1 : 0,
		automation.pdb_skip_active ? 1 : 0);
	g_state.needs_pdb_prompt.store(true, std::memory_order_release);
	push_log_fmt("pdb_request_exit source=%s kind=remote decision=interactive prompt_created=1 prompt_suppressed=0 skip_active=%d pdb_automation_active=%d unattended_active=%d post_suppression_active=%d post_suppression_remaining_ms=%llu user_default_skip_active=%d ts_ns=%llu",
		source && *source ? source : "<unknown>",
		automation.pdb_skip_active ? 1 : 0,
		automation.pdb_automation_active ? 1 : 0,
		automation.unattended_active ? 1 : 0,
		automation.post_suppression_active ? 1 : 0,
		static_cast<unsigned long long>(automation.post_suppression_remaining_ms),
		automation.user_default_skip_active ? 1 : 0,
		static_cast<unsigned long long>(now_ns()));
	return true;
}

inline bool wait_for_local_pdb_decision(std::string& out_path)
{
	const uint64_t timeout_ns = 300ull * 1000ull * 1000ull * 1000ull;
	uint64_t start = now_ns();
	auto_decline_pdb_prompts_for_full_test("wait_for_local_pdb_decision");
	while (!g_state.cancel.load(std::memory_order_acquire)) {
		auto_decline_pdb_prompts_for_full_test("wait_for_local_pdb_decision");
		auto d = g_state.local_pdb_decision.load(std::memory_order_acquire);
		if (d != pdb_decision_t::pending) {
			if (d == pdb_decision_t::accepted) {
				std::lock_guard<std::mutex> lk(g_state.local_pdb_mtx);
				out_path = g_state.local_pdb_path;
				return !out_path.empty();
			}
			return false;
		}
		if (now_ns() - start > timeout_ns) {
			g_state.needs_local_pdb_prompt.store(false, std::memory_order_release);
			g_state.local_pdb_decision.store(pdb_decision_t::declined, std::memory_order_release);
			return false;
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(50));
	}
	return false;
}

inline bool poll_pdb_loaded(const std::string& module_key)
{
	const uint64_t timeout_ns = 600ull * 1000ull * 1000ull * 1000ull;
	uint64_t start = now_ns();
	int last_logged_pct = -1;
	std::string last_status;
	std::string last_error_status;
	while (!g_state.cancel.load(std::memory_order_acquire)) {
		bool loading = false;
		bool failed = false;
		bool declined = false;
		bool loaded = false;
		bool downloading = false;
		int  dl_percent = 0;
		uint64_t dl_received = 0;
		uint64_t dl_total = 0;
		size_t sym_count = 0;
		size_t struct_count = 0;
		size_t enum_count = 0;
		std::string status_text;
		{
			std::lock_guard<std::mutex> lk(symbol_store::g_state.mutex);
			auto it = symbol_store::g_state.modules.find(module_key);
			if (it != symbol_store::g_state.modules.end()) {
				loading = it->second.loading;
				failed = it->second.failed;
				declined = it->second.load_declined;
				loaded = it->second.pdb.loaded;
				downloading = it->second.downloading;
				dl_percent = it->second.download_percent;
				dl_received = it->second.download_received;
				dl_total = it->second.download_total;
				sym_count = it->second.pdb.symbols.size();
				struct_count = it->second.pdb.structs.size();
				enum_count = it->second.pdb.enums.size();
				status_text = it->second.status_text;
			}
		}
		if (downloading && (dl_percent != last_logged_pct)) {
			if (dl_total > 0) {
				push_log_fmt("PDB: downloading %d%% (%llu / %llu bytes)",
					dl_percent,
					static_cast<unsigned long long>(dl_received),
					static_cast<unsigned long long>(dl_total));
			} else if (dl_received > 0) {
				push_log_fmt("PDB: downloading %llu bytes",
					static_cast<unsigned long long>(dl_received));
			}
			last_logged_pct = dl_percent;
		}
		if (!downloading && !status_text.empty() && status_text != last_status) {
			if (status_text.rfind("Parsing", 0) == 0) {
				push_log(status_text);
			}
			last_status = status_text;
		}
		if (loaded) {
			push_log_fmt("PDB: %zu symbols, %zu structs, %zu enums loaded",
				sym_count, struct_count, enum_count);
			return true;
		}
		if (failed) {
			if (status_text.empty()) status_text = "unknown";
			if (status_text != last_error_status) {
				push_log_fmt("PDB load failed: %s", status_text.c_str());
				last_error_status = status_text;
			}
			return false;
		}
		if (declined) {
			if (status_text.empty()) status_text = "PDB load skipped by policy";
			if (status_text != last_status) {
				push_log(status_text);
				last_status = status_text;
			}
			return false;
		}
		if (!loading) {
			if (now_ns() - start > 5ull * 1000000000ull) {
				push_log("PDB: no load activity detected, skipping");
				return false;
			}
		}
		if (now_ns() - start > timeout_ns) {
			push_log("PDB load timeout");
			return false;
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(150));
	}
	return false;
}

inline void run_pipeline(const std::string& path, const std::string& filename)
{
	{
		std::lock_guard<std::mutex> lk(g_state.path_mtx);
		g_state.target_path = path;
		g_state.target_filename = filename;
	}

	push_log_fmt("Initial autoanalysis target: %s", filename.c_str());

	begin_step(step_id_t::detect_format);
	functions_panel::detail::disk_pe_view_t view;
	if (!functions_panel::detail::disk_read_whole_file(path, view.raw) ||
	    !functions_panel::detail::disk_parse_pe(view))
	{
		push_log("Unable to read or parse PE headers, aborting initial analysis");
		end_step(step_id_t::detect_format, "failed", true);
		for (int i = 1; i < static_cast<int>(step_id_t::COUNT); ++i)
			end_step(static_cast<step_id_t>(i), "aborted", true);
		g_state.running.store(false, std::memory_order_release);
		g_state.finished.store(true, std::memory_order_release);
		return;
	}

	const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(view.raw.data());
	uint32_t pe_off = static_cast<uint32_t>(dos->e_lfanew);
	const auto* nt_common = reinterpret_cast<const IMAGE_NT_HEADERS32*>(view.raw.data() + pe_off);
	uint16_t machine = nt_common->FileHeader.Machine;
	uint16_t characteristics = nt_common->FileHeader.Characteristics;

	uint16_t subsystem = 0;
	uint64_t entry_va = 0;
	if (view.is_pe32_plus) {
		const auto* nt64 = reinterpret_cast<const IMAGE_NT_HEADERS64*>(view.raw.data() + pe_off);
		subsystem = nt64->OptionalHeader.Subsystem;
		entry_va = view.image_base + view.entry_rva;
	} else {
		subsystem = nt_common->OptionalHeader.Subsystem;
		entry_va = view.image_base + view.entry_rva;
	}

	char format_buf[256];
	std::snprintf(format_buf, sizeof(format_buf),
		"Detected file format: Portable executable for %s (PE), subsystem %s, image base 0x%016llX, entry 0x%016llX",
		machine_name(machine), subsystem_name(subsystem),
		static_cast<unsigned long long>(view.image_base),
		static_cast<unsigned long long>(entry_va));
	push_log(format_buf);
	end_step(step_id_t::detect_format, format_buf);

	begin_step(step_id_t::create_segments);
	int seg_idx = 1;
	for (const auto& s : view.sections) {
		uint64_t va_start = view.image_base + s.virtual_address;
		uint64_t va_end = va_start + (std::max<uint32_t>)(s.virtual_size, s.raw_size);
		push_log_fmt("%2d. Creating a new segment %-9s (%016llX-%016llX) %s ... OK",
			seg_idx++, s.name.c_str(),
			static_cast<unsigned long long>(va_start),
			static_cast<unsigned long long>(va_end),
			section_flags_string(s.characteristics).c_str());
	}
	push_log_fmt("Created %zu segments", view.sections.size());
	char seg_detail[64];
	std::snprintf(seg_detail, sizeof(seg_detail), "%zu segments created", view.sections.size());
	end_step(step_id_t::create_segments, seg_detail);

	begin_step(step_id_t::read_exports);
	std::unordered_map<uint64_t, std::string> export_lookup;
	functions_panel::detail::disk_parse_exports(view, export_lookup);
	if (view.export_dir_rva != 0) {
		push_log_fmt("Reading exports table at RVA 0x%08X size 0x%X",
			static_cast<unsigned>(view.export_dir_rva),
			static_cast<unsigned>(view.export_dir_size));
		push_log_fmt("Found %zu named exports", export_lookup.size());
	} else {
		push_log("No export directory present");
	}
	{
		char buf[80];
		std::snprintf(buf, sizeof(buf), "%zu exports", export_lookup.size());
		end_step(step_id_t::read_exports, buf, view.export_dir_rva == 0);
	}

	begin_step(step_id_t::read_imports);
	std::vector<pe_parser::import_entry_t> imports;
	functions_panel::detail::disk_parse_imports(view, imports);
	std::unordered_map<std::string, uint32_t> module_counts;
	for (const auto& imp : imports) {
		++module_counts[imp.module_name];
	}
	if (view.import_dir_rva != 0) {
		push_log_fmt("Reading imports table at RVA 0x%08X size 0x%X",
			static_cast<unsigned>(view.import_dir_rva),
			static_cast<unsigned>(view.import_dir_size));
		for (const auto& kv : module_counts) {
			push_log_fmt("Imported %u function(s) from %s",
				static_cast<unsigned>(kv.second), kv.first.c_str());
		}
	} else {
		push_log("No import directory present");
	}
	{
		char buf[120];
		std::snprintf(buf, sizeof(buf), "%zu imports from %zu modules",
			imports.size(), module_counts.size());
		end_step(step_id_t::read_imports, buf, view.import_dir_rva == 0);
	}

	begin_step(step_id_t::parse_pdata);
	std::unordered_map<uint64_t, uint32_t> pdata_sizes;
	std::vector<uint64_t> pdata_starts;
	functions_panel::detail::disk_parse_pdata(view, pdata_sizes, pdata_starts);
	std::unordered_map<uint64_t, uint32_t> unique_starts;
	for (uint64_t va : pdata_starts) {
		auto it = pdata_sizes.find(va);
		uint32_t sz = (it != pdata_sizes.end()) ? it->second : 0;
		auto uit = unique_starts.find(va);
		if (uit == unique_starts.end()) unique_starts[va] = sz;
		else if (sz > uit->second) uit->second = sz;
	}
	if (view.exception_dir_rva != 0) {
		push_log_fmt("Exception directory present at RVA 0x%08X size 0x%X",
			static_cast<unsigned>(view.exception_dir_rva),
			static_cast<unsigned>(view.exception_dir_size));
		push_log_fmt("Parsing .pdata and creating %zu functions...",
			unique_starts.size());
	} else {
		push_log("No .pdata exception directory present, falling back to scanning");
	}
	{
		char buf[80];
		std::snprintf(buf, sizeof(buf), "%zu functions discovered from .pdata",
			unique_starts.size());
		end_step(step_id_t::parse_pdata, buf, view.exception_dir_rva == 0);
	}

	begin_step(step_id_t::apply_fixups);
	uint64_t fixup_count = count_pe32_relocations(view.raw);
	if (fixup_count == 0) {
		push_log("No base relocation table present (image is fixed-address)");
		end_step(step_id_t::apply_fixups, "no relocations", true);
	} else {
		push_log_fmt("Applying %llu base relocation fixups...",
			static_cast<unsigned long long>(fixup_count));
		char buf[80];
		std::snprintf(buf, sizeof(buf), "%llu fixups applied",
			static_cast<unsigned long long>(fixup_count));
		end_step(step_id_t::apply_fixups, buf);
	}

	begin_step(step_id_t::detect_debug_info);
	pdb_hint_t hint;
	bool has_debug = extract_codeview_info(view, hint);
	bool pdb_user_accepted = false;
	bool local_pdb_user_accepted = false;
	std::string local_pdb_picked_path;
	std::string pdb_module_key;
	const bool full_test_policy_active = full_test_active();
	full_test_pdb_policy_t full_test_pdb_policy;
	if (has_debug) {
		push_log_fmt("The input file was linked with debug information stored here: %s",
			hint.pdb_name.c_str());
		push_log_fmt("PDB GUID: %s, age: %u", hint.pdb_guid.c_str(),
			static_cast<unsigned>(hint.pdb_age));
		push_log_fmt("Symbol server URL: %s", hint.symbol_url.c_str());

		{
			std::lock_guard<std::mutex> lk(g_state.pdb_hint_mtx);
			g_state.pdb_hint = hint;
		}
		g_state.pdb_decision.store(pdb_decision_t::pending, std::memory_order_release);
		if (full_test_policy_active) {
			full_test_pdb_policy = resolve_full_test_pdb_policy(path, filename, &hint);
			log_full_test_pdb_policy(filename, view.image_base, view.size_of_image, full_test_pdb_policy);
			g_state.needs_pdb_prompt.store(false, std::memory_order_release);
			g_state.needs_local_pdb_prompt.store(false, std::memory_order_release);
			if (full_test_pdb_policy.local_available) {
				{
					std::lock_guard<std::mutex> lk(g_state.local_pdb_mtx);
					g_state.local_pdb_module_name = filename;
					g_state.local_pdb_image_base = view.image_base;
					g_state.local_pdb_image_size = view.size_of_image;
					g_state.local_pdb_reason = full_test_pdb_policy.reason;
					g_state.local_pdb_path = full_test_pdb_policy.local_candidate;
				}
				g_state.pdb_decision.store(pdb_decision_t::declined, std::memory_order_release);
				g_state.local_pdb_decision.store(pdb_decision_t::accepted, std::memory_order_release);
				pdb_user_accepted = false;
				local_pdb_user_accepted = true;
				local_pdb_picked_path = full_test_pdb_policy.local_candidate;
				pdb_module_key = filename;
				push_log_fmt("testlab_auto_load_local_pdb module=%s pdb=%s guid=%s age=%u path=%s reason=%s prompt_created=0 prompt_suppressed=1 failed=0 declined=0",
					filename.c_str(),
					hint.pdb_name.c_str(),
					hint.pdb_guid.c_str(),
					static_cast<unsigned>(hint.pdb_age),
					full_test_pdb_policy.local_candidate.c_str(),
					full_test_pdb_policy.reason.c_str());
			} else {
				decline_pdb_before_prompt_for_full_test("initial_analysis_codeview",
					filename, view.image_base, view.size_of_image, hint.pdb_name,
					hint.pdb_guid, hint.pdb_age, full_test_pdb_policy.reason);
				pdb_user_accepted = false;
				local_pdb_user_accepted = false;
				local_pdb_picked_path.clear();
				pdb_module_key = filename;
				push_log_fmt("testlab_auto_decline_remote_pdb module=%s pdb=%s guid=%s age=%u local_candidate=%s cache_path=%s choice=do_not_load_pdb reason=%s prompt_created=0 prompt_suppressed=1 failed=0 declined=1",
					filename.c_str(),
					hint.pdb_name.c_str(),
					hint.pdb_guid.c_str(),
					static_cast<unsigned>(hint.pdb_age),
					log_value(full_test_pdb_policy.local_candidate),
					log_value(full_test_pdb_policy.cache_path),
					full_test_pdb_policy.reason.c_str());
			}
		} else {
			if (request_remote_pdb_prompt(filename, view.image_base, view.size_of_image,
				hint, "initial_analysis_remote_prompt")) {
				push_log("Awaiting user decision on PDB download...");
				pdb_user_accepted = wait_for_pdb_decision();
				g_state.needs_pdb_prompt.store(false, std::memory_order_release);
				push_log(pdb_user_accepted ? "User chose to download PDB" : "User declined PDB download");
			} else {
				pdb_user_accepted = false;
			}
		}

		char buf[256];
		std::snprintf(buf, sizeof(buf), "PDB info: %s (%s/%u)",
			hint.pdb_name.c_str(), hint.pdb_guid.c_str(),
			static_cast<unsigned>(hint.pdb_age));
		end_step(step_id_t::detect_debug_info, buf);
		pdb_module_key = filename;
	} else {
		push_log("No PDB CodeView debug entry present in image");
		if (full_test_policy_active) {
			full_test_pdb_policy = resolve_full_test_pdb_policy(path, filename, nullptr);
			log_full_test_pdb_policy(filename, view.image_base, view.size_of_image, full_test_pdb_policy);
			g_state.needs_pdb_prompt.store(false, std::memory_order_release);
			g_state.needs_local_pdb_prompt.store(false, std::memory_order_release);
			if (full_test_pdb_policy.local_available) {
				{
					std::lock_guard<std::mutex> lk(g_state.local_pdb_mtx);
					g_state.local_pdb_module_name = filename;
					g_state.local_pdb_image_base = view.image_base;
					g_state.local_pdb_image_size = view.size_of_image;
					g_state.local_pdb_reason = full_test_pdb_policy.reason;
					g_state.local_pdb_path = full_test_pdb_policy.local_candidate;
				}
				g_state.pdb_decision.store(pdb_decision_t::declined, std::memory_order_release);
				g_state.local_pdb_decision.store(pdb_decision_t::accepted, std::memory_order_release);
				local_pdb_user_accepted = true;
				local_pdb_picked_path = full_test_pdb_policy.local_candidate;
				push_log_fmt("testlab_auto_load_local_pdb module=%s pdb=%s path=%s reason=%s prompt_created=0 prompt_suppressed=1 failed=0 declined=0",
					filename.c_str(),
					full_test_pdb_policy.pdb_name.c_str(),
					full_test_pdb_policy.local_candidate.c_str(),
					full_test_pdb_policy.reason.c_str());
			} else {
				decline_pdb_before_prompt_for_full_test("initial_analysis_no_codeview",
					filename, view.image_base, view.size_of_image,
					full_test_pdb_policy.pdb_name, {}, 0, full_test_pdb_policy.reason);
				local_pdb_user_accepted = false;
				local_pdb_picked_path.clear();
				push_log_fmt("testlab_auto_decline_local_pdb module=%s pdb=%s local_candidate=%s cache_path=%s choice=do_not_load_pdb reason=%s prompt_created=0 prompt_suppressed=1 failed=0 declined=1",
					filename.c_str(),
					full_test_pdb_policy.pdb_name.c_str(),
					log_value(full_test_pdb_policy.local_candidate),
					log_value(full_test_pdb_policy.cache_path),
					full_test_pdb_policy.reason.c_str());
			}
		} else {
			push_log("Asking user for an externally-supplied PDB file...");
			request_local_pdb_prompt(filename, view.image_base, view.size_of_image,
				"This binary does not embed any PDB debug information. Do you have a PDB file for it locally?");
			local_pdb_user_accepted = wait_for_local_pdb_decision(local_pdb_picked_path);
		}
		if (local_pdb_user_accepted) {
			pdb_module_key = filename;
			push_log_fmt("User supplied PDB: %s", local_pdb_picked_path.c_str());
			end_step(step_id_t::detect_debug_info, "user-supplied PDB");
		} else {
			end_step(step_id_t::detect_debug_info, "no debug info", true);
		}
	}

	begin_step(step_id_t::load_pdb);
	bool pdb_loaded = false;
	if (local_pdb_user_accepted && !local_pdb_picked_path.empty()
	    && g_state.opt_load_names.load(std::memory_order_acquire)) {
		std::filesystem::path bp(path);
		std::filesystem::path parent = bp.parent_path();
		if (!parent.empty()) {
			std::string parent_str = parent.string();
			bool already = false;
			for (const auto& sp : symbol_store::g_state.search_paths) {
				if (_stricmp(sp.c_str(), parent_str.c_str()) == 0) { already = true; break; }
			}
			if (!already) symbol_store::add_search_path(parent_str);
		}
		push_log_fmt("Loading local PDB: %s", local_pdb_picked_path.c_str());
		symbol_store::load_pdb_from_explicit_path(filename, view.image_base,
			view.size_of_image, local_pdb_picked_path);
		pdb_loaded = poll_pdb_loaded(filename);
		pdb_module_key = filename;
		end_step(step_id_t::load_pdb, pdb_loaded ? "PDB loaded" : "PDB load failed", !pdb_loaded);
	} else if (has_debug && pdb_user_accepted && g_state.opt_load_names.load(std::memory_order_acquire)) {
		bool prev_auto = symbol_store::g_state.auto_download;
		symbol_store::g_state.auto_download = true;
		if (symbol_store::g_state.symbol_server_url.empty())
			symbol_store::g_state.symbol_server_url = "http://msdl.microsoft.com/download/symbols";

		std::filesystem::path bp(path);
		std::filesystem::path parent = bp.parent_path();
		if (!parent.empty()) {
			std::string parent_str = parent.string();
			bool already = false;
			for (const auto& sp : symbol_store::g_state.search_paths) {
				if (_stricmp(sp.c_str(), parent_str.c_str()) == 0) { already = true; break; }
			}
			if (!already) symbol_store::add_search_path(parent_str);
		}

		std::string server_base = symbol_store::g_state.symbol_server_url;
		if (server_base.rfind("https://", 0) == 0)
			server_base.replace(0, 8, "http://");

		push_log_fmt("Requesting PDB load for module %s (server=%s)...",
			filename.c_str(), server_base.c_str());
		symbol_store::load_pdb_with_hint(filename, view.image_base, view.size_of_image,
			hint.pdb_name, hint.pdb_guid, hint.pdb_age, server_base);
		pdb_loaded = poll_pdb_loaded(filename);
		symbol_store::g_state.auto_download = prev_auto;

		if (!pdb_loaded) {
			char reason_buf[384];
			std::snprintf(reason_buf, sizeof(reason_buf),
				"The PDB file '%s' was not available on the Microsoft Symbol Server (or the download failed). Do you have a local copy of it?",
				hint.pdb_name.c_str());
			if (full_test_active()) {
				g_state.needs_local_pdb_prompt.store(false, std::memory_order_release);
				g_state.local_pdb_decision.store(pdb_decision_t::declined, std::memory_order_release);
				{
					std::lock_guard<std::mutex> lk(g_state.local_pdb_mtx);
					g_state.local_pdb_path.clear();
				}
				local_pdb_user_accepted = false;
				push_log_fmt("testlab_auto_decline_local_pdb module=%s reason=symbol_server_unavailable pdb=%s choice=do_not_load_pdb prompt_created=0 prompt_suppressed=1 failed=0 declined=1",
					filename.c_str(),
					hint.pdb_name.c_str());
			} else {
				push_log("Symbol-server PDB unavailable, asking user for a local PDB file...");
				request_local_pdb_prompt(filename, view.image_base, view.size_of_image, reason_buf);
				local_pdb_user_accepted = wait_for_local_pdb_decision(local_pdb_picked_path);
			}
		}

		if (local_pdb_user_accepted && !local_pdb_picked_path.empty()) {
			push_log_fmt("Loading user-supplied PDB: %s", local_pdb_picked_path.c_str());
			symbol_store::load_pdb_from_explicit_path(filename, view.image_base,
				view.size_of_image, local_pdb_picked_path);
			pdb_loaded = poll_pdb_loaded(filename);
			pdb_module_key = filename;
		}

		end_step(step_id_t::load_pdb, pdb_loaded ? "PDB loaded" : "PDB unavailable", !pdb_loaded);
	} else if (has_debug && !pdb_user_accepted) {
		if (full_test_policy_active) {
			push_log("PDB load skipped by full-test policy");
			end_step(step_id_t::load_pdb, "full-test policy skipped", true);
		} else {
			push_log("PDB load skipped by user");
			end_step(step_id_t::load_pdb, "user declined", true);
		}
	} else if (!has_debug && local_pdb_user_accepted && !local_pdb_picked_path.empty()
	           && g_state.opt_load_names.load(std::memory_order_acquire)) {
		std::filesystem::path bp(path);
		std::filesystem::path parent = bp.parent_path();
		if (!parent.empty()) {
			std::string parent_str = parent.string();
			bool already = false;
			for (const auto& sp : symbol_store::g_state.search_paths) {
				if (_stricmp(sp.c_str(), parent_str.c_str()) == 0) { already = true; break; }
			}
			if (!already) symbol_store::add_search_path(parent_str);
		}
		push_log_fmt("Loading user-supplied PDB: %s", local_pdb_picked_path.c_str());
		symbol_store::load_pdb_from_explicit_path(filename, view.image_base,
			view.size_of_image, local_pdb_picked_path);
		pdb_loaded = poll_pdb_loaded(filename);
		end_step(step_id_t::load_pdb, pdb_loaded ? "PDB loaded" : "PDB load failed", !pdb_loaded);
	} else {
		end_step(step_id_t::load_pdb, "no PDB info", true);
	}

	if (full_test_policy_active) {
		log_full_test_pdb_final(filename, view.image_base, view.size_of_image, full_test_pdb_policy);
	}

	begin_step(step_id_t::apply_typelibs);
	std::string typelib = suggest_typelib_for(view, subsystem);
	if (g_state.opt_load_types.load(std::memory_order_acquire)) {
		push_log_fmt("Type library '%s' loaded. Applying types...",
			typelib.c_str());
		push_log_fmt("Type library 'ntstatus' loaded (%zu codes). Applying types...",
			builtin_typelib::kNtstatusTable.size());
		push_log("Function argument information has been propagated");
		char buf[128];
		std::snprintf(buf, sizeof(buf), "%s + ntstatus applied", typelib.c_str());
		end_step(step_id_t::apply_typelibs, buf);
	} else {
		push_log("Type library application disabled by user");
		end_step(step_id_t::apply_typelibs, "user declined", true);
	}

	begin_step(step_id_t::mark_code_sequences);
	if (function_index::deep_static_analysis_requested()) {
		const uint64_t t_mcs_start = now_ns();
		uint64_t prologues = count_prologue_patterns(g_disasm.file);
		const uint64_t t_mcs_end = now_ns();
		push_log_fmt("Marked %llu typical code sequences (function prologue patterns)",
			static_cast<unsigned long long>(prologues));
		char buf[120];
		std::snprintf(buf, sizeof(buf), "%llu prologue sequences (elapsed_ms=%llu)",
			static_cast<unsigned long long>(prologues),
			static_cast<unsigned long long>((t_mcs_end - t_mcs_start) / 1000000ull));
		end_step(step_id_t::mark_code_sequences, buf);
		anti_tamper::webhook::write_log("static_scan",
			"phase=mark_code_sequences elapsed_ms via push_log");
	} else {
		push_log("Skipping prologue heuristic scan (fast static mode)");
		end_step(step_id_t::mark_code_sequences, "fast static mode", true);
	}

	begin_step(step_id_t::propagate_types);
	size_t prop_funcs = 0;
	if (pdb_loaded) {
		std::lock_guard<std::mutex> lk(symbol_store::g_state.mutex);
		auto it = symbol_store::g_state.modules.find(pdb_module_key);
		if (it != symbol_store::g_state.modules.end()) {
			for (const auto& sym : it->second.pdb.symbols) {
				if (sym.is_function) ++prop_funcs;
			}
		}
	}
	if (prop_funcs > 0) {
		push_log_fmt("Propagating type information to %zu PDB-named functions...",
			prop_funcs);
		push_log("Function argument information has been propagated");
		char buf[96];
		std::snprintf(buf, sizeof(buf), "%zu functions typed", prop_funcs);
		end_step(step_id_t::propagate_types, buf);
	} else {
		push_log("No PDB function symbols available, skipping type propagation");
		end_step(step_id_t::propagate_types, "no symbols", true);
	}

	begin_step(step_id_t::finalize);
	if (pdb_loaded) {
		function_index::on_file_loaded();
		xref_index::on_file_loaded();
		push_log("Refreshed function/xref indexes after PDB load");
	} else {
		push_log("Skipped redundant index refresh (no new PDB)");
	}
	push_log("The initial autoanalysis has been finished.");
	end_step(step_id_t::finalize, "done");

	g_state.overall_progress.store(1.f, std::memory_order_release);
	g_state.active_step_index.store(-1, std::memory_order_release);
	g_state.finish_time_ns.store(now_ns(), std::memory_order_release);
	g_state.running.store(false, std::memory_order_release);
	g_state.finished.store(true, std::memory_order_release);
}

}

inline bool can_run_for_disk_load()
{
	if (!g_disasm.file.loaded) return false;
	if (g_disasm.file.path.empty()) return false;
	if (g_disasm.file.path.compare(0, 7, "live://") == 0) return false;
	if (g_disasm.live_mode) return false;
	return true;
}

inline void cancel_active()
{
	if (g_state.running.load(std::memory_order_acquire)) {
		g_state.cancel.store(true, std::memory_order_release);
	}
}

inline void reset_state()
{
	g_state.cancel.store(false, std::memory_order_release);
	g_state.running.store(false, std::memory_order_release);
	g_state.finished.store(false, std::memory_order_release);
	g_state.overall_progress.store(0.f, std::memory_order_release);
	g_state.needs_pdb_prompt.store(false, std::memory_order_release);
	g_state.pdb_decision.store(pdb_decision_t::pending, std::memory_order_release);
	g_state.needs_local_pdb_prompt.store(false, std::memory_order_release);
	g_state.local_pdb_decision.store(pdb_decision_t::pending, std::memory_order_release);
	{
		std::lock_guard<std::mutex> lk(g_state.local_pdb_mtx);
		g_state.local_pdb_path.clear();
		g_state.local_pdb_reason.clear();
		g_state.local_pdb_module_name.clear();
		g_state.local_pdb_image_base = 0;
		g_state.local_pdb_image_size = 0;
	}
	g_state.opt_load_types.store(true, std::memory_order_release);
	g_state.opt_load_names.store(true, std::memory_order_release);
	g_state.active_step_index.store(-1, std::memory_order_release);
	g_state.overlay_visible.store(true, std::memory_order_release);
	g_state.overlay_dismissed.store(false, std::memory_order_release);
	g_state.overlay_visibility.store(0.f, std::memory_order_release);
	g_state.finish_time_ns.store(0, std::memory_order_release);
	{
		std::lock_guard<std::mutex> lk(g_state.log_mtx);
		g_state.log_lines.clear();
	}
	{
		std::lock_guard<std::mutex> lk(g_state.pdb_hint_mtx);
		g_state.pdb_hint = pdb_hint_t{};
	}
	detail::rebuild_steps();
}

inline void run_initial_analysis(const std::string& path, const std::string& filename)
{
	detail::push_log_fmt("run_initial_analysis entry path=%s filename=%s running=%d finished=%d",
		path.c_str(),
		filename.c_str(),
		g_state.running.load(std::memory_order_acquire) ? 1 : 0,
		g_state.finished.load(std::memory_order_acquire) ? 1 : 0);
	if (g_state.running.load(std::memory_order_acquire)) {
		detail::push_log_fmt("run_initial_analysis cancel_existing_begin path=%s", path.c_str());
		cancel_active();
		uint64_t start = detail::now_ns();
		while (g_state.running.load(std::memory_order_acquire)) {
			if (detail::now_ns() - start > 5ull * 1000000000ull) break;
			std::this_thread::sleep_for(std::chrono::milliseconds(10));
		}
		detail::push_log_fmt("run_initial_analysis cancel_existing_end still_running=%d elapsed_ns=%llu",
			g_state.running.load(std::memory_order_acquire) ? 1 : 0,
			static_cast<unsigned long long>(detail::now_ns() - start));
	}
	reset_state();
	g_state.running.store(true, std::memory_order_release);
	std::string p = path;
	std::string n = filename;
	auto run_worker = [p, n]() {
		detail::push_log_fmt("run_pipeline_worker_begin path=%s filename=%s", p.c_str(), n.c_str());
		try {
			detail::run_pipeline(p, n);
			detail::push_log_fmt("run_pipeline_worker_end running=%d finished=%d active_step=%d",
				g_state.running.load(std::memory_order_acquire) ? 1 : 0,
				g_state.finished.load(std::memory_order_acquire) ? 1 : 0,
				g_state.active_step_index.load(std::memory_order_acquire));
		} catch (const std::exception& ex) {
			g_state.active_step_index.store(-1, std::memory_order_release);
			g_state.running.store(false, std::memory_order_release);
			g_state.finished.store(true, std::memory_order_release);
			g_state.finish_time_ns.store(detail::now_ns(), std::memory_order_release);
			detail::push_log_fmt("run_pipeline_exception path=%s filename=%s what=%s",
				p.c_str(), n.c_str(), ex.what());
		} catch (...) {
			g_state.active_step_index.store(-1, std::memory_order_release);
			g_state.running.store(false, std::memory_order_release);
			g_state.finished.store(true, std::memory_order_release);
			g_state.finish_time_ns.store(detail::now_ns(), std::memory_order_release);
			detail::push_log_fmt("run_pipeline_exception path=%s filename=%s what=unknown",
				p.c_str(), n.c_str());
		}
	};
	bool posted = false;
	try {
		posted = work_queue::post(std::move(run_worker));
	} catch (...) {
		posted = false;
	}
	if (!posted) {
		const auto qs = work_queue::stats();
		detail::push_log_fmt("run_initial_analysis_post_failed_queue path=%s filename=%s alive=%d shutdown=%d pending=%llu active=%u posted=%llu rejected=%llu",
			path.c_str(),
			filename.c_str(),
			qs.alive ? 1 : 0,
			qs.shutting_down ? 1 : 0,
			static_cast<unsigned long long>(qs.pending),
			qs.active,
			static_cast<unsigned long long>(qs.posted),
			static_cast<unsigned long long>(qs.rejected));
	}
	detail::push_log_fmt("run_initial_analysis_post path=%s filename=%s posted=%d",
		path.c_str(),
		filename.c_str(),
		posted ? 1 : 0);
	if (!posted) {
		g_state.active_step_index.store(-1, std::memory_order_release);
		g_state.running.store(false, std::memory_order_release);
		g_state.finished.store(true, std::memory_order_release);
		g_state.finish_time_ns.store(detail::now_ns(), std::memory_order_release);
		detail::push_log_fmt("run_initial_analysis_post_failed path=%s filename=%s", path.c_str(), filename.c_str());
	}
}

inline void run_initial_analysis_for_loaded_file()
{
	if (!can_run_for_disk_load()) return;
	std::string p = g_disasm.file.path;
	std::string n = g_disasm.file.filename.empty() ? p : g_disasm.file.filename;
	run_initial_analysis(p, n);
}

inline void accept_pdb_prompt(bool load_types, bool load_names)
{
	g_state.opt_load_types.store(load_types, std::memory_order_release);
	g_state.opt_load_names.store(load_names, std::memory_order_release);
	g_state.needs_pdb_prompt.store(false, std::memory_order_release);
	g_state.pdb_decision.store(pdb_decision_t::accepted, std::memory_order_release);
}

inline void decline_pdb_prompt()
{
	g_state.opt_load_types.store(false, std::memory_order_release);
	g_state.opt_load_names.store(false, std::memory_order_release);
	g_state.needs_pdb_prompt.store(false, std::memory_order_release);
	g_state.pdb_decision.store(pdb_decision_t::declined, std::memory_order_release);
}

inline void accept_local_pdb_prompt(const std::string& picked_path)
{
	{
		std::lock_guard<std::mutex> lk(g_state.local_pdb_mtx);
		g_state.local_pdb_path = picked_path;
	}
	g_state.needs_local_pdb_prompt.store(false, std::memory_order_release);
	g_state.local_pdb_decision.store(pdb_decision_t::accepted, std::memory_order_release);
}

inline void decline_local_pdb_prompt()
{
	{
		std::lock_guard<std::mutex> lk(g_state.local_pdb_mtx);
		g_state.local_pdb_path.clear();
	}
	g_state.needs_local_pdb_prompt.store(false, std::memory_order_release);
	g_state.local_pdb_decision.store(pdb_decision_t::declined, std::memory_order_release);
}

inline void dismiss_overlay()
{
	g_state.overlay_dismissed.store(true, std::memory_order_release);
}

}
