#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "imgui/imgui.h"
#include "imgui/imgui_internal.h"

#include "theme.hpp"
#include "fonts.hpp"
#include "ui_anim.hpp"

#include "../../helpers/globals.h"
#include "../../helpers/diag_log.hpp"
#include "../disasm/zydis_disasm.hpp"
#include "../disasm/function_index.hpp"
#include "../disasm/xref_index.hpp"
#include "../editor/hex_view.hpp"
#include "../infra/work_queue.hpp"
#include "../infra/event_bus.hpp"
#include "../analysis/initial_analysis.hpp"
#include "../analysis/symbol_store.hpp"
#include "../anti-tamper/webhook.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <exception>
#include <functional>
#include <mutex>
#include <string>

extern DisasmState g_disasm;

namespace loading_binary_overlay {

enum class completion_action_t : unsigned int {
	none = 0,
	switch_to_disassembly = 1,
	switch_to_disassembly_or_hex = 2,
};

enum class phase_t : unsigned int {
	idle = 0,
	loading = 1,
	awaiting_analysis = 2,
	awaiting_pdb_decision = 3,
	loading_pdb = 4,
	finalizing = 5,
	complete = 6
};

namespace detail {

struct state_t {
	std::atomic<unsigned int>  phase{static_cast<unsigned int>(phase_t::idle)};
	std::atomic<bool>          worker_finished{false};
	std::atomic<bool>          completion_applied{false};
	std::atomic<float>         progress{0.f};
	std::atomic<float>         visual_progress{0.f};
	std::atomic<unsigned int>  milestone_id{0};
	std::atomic<unsigned int>  completion_action{0};
	std::atomic<bool>          load_succeeded{false};
	std::mutex                 text_mtx;
	std::string                path;
	std::string                filename;
	std::string                milestone_label;
	std::string                dynamic_label;
	std::string                pdb_module_key;
	std::atomic<float>         visual_alpha{0.f};
	std::atomic<float>         modal_dim_t{0.f};
};

inline state_t& state()
{
	static state_t s;
	return s;
}

inline void set_phase(phase_t p)
{
	state().phase.store(static_cast<unsigned int>(p), std::memory_order_release);
}

inline phase_t get_phase()
{
	return static_cast<phase_t>(state().phase.load(std::memory_order_acquire));
}

inline const char* phase_name(phase_t p)
{
	switch (p) {
	case phase_t::idle: return "idle";
	case phase_t::loading: return "loading";
	case phase_t::awaiting_analysis: return "awaiting_analysis";
	case phase_t::awaiting_pdb_decision: return "awaiting_pdb_decision";
	case phase_t::loading_pdb: return "loading_pdb";
	case phase_t::finalizing: return "finalizing";
	case phase_t::complete: return "complete";
	default: return "unknown";
	}
}

inline void set_milestone(float pct, const char* label, unsigned int id)
{
	state_t& s = state();
	s.progress.store(pct, std::memory_order_release);
	s.milestone_id.fetch_add(1u, std::memory_order_acq_rel);
	{
		std::lock_guard<std::mutex> lk(s.text_mtx);
		s.milestone_label = label ? label : "";
	}
	(void)id;
}

inline std::string derive_filename(const std::string& path)
{
	size_t sl = path.find_last_of("/\\");
	return (sl != std::string::npos) ? path.substr(sl + 1) : path;
}

inline uint64_t monotonic_ms_now()
{
	auto tp = std::chrono::steady_clock::now().time_since_epoch();
	return static_cast<uint64_t>(
		std::chrono::duration_cast<std::chrono::milliseconds>(tp).count());
}

inline void emit_phase_log(const char* phase, uint64_t elapsed_ms, const char* extra)
{
	char buf[512];
	if (extra && *extra) {
		std::snprintf(buf, sizeof(buf),
			"phase=%s elapsed_ms=%llu %s",
			phase,
			static_cast<unsigned long long>(elapsed_ms),
			extra);
	} else {
		std::snprintf(buf, sizeof(buf),
			"phase=%s elapsed_ms=%llu",
			phase,
			static_cast<unsigned long long>(elapsed_ms));
	}
	diag::log_tagged("pe_load", buf);
	anti_tamper::webhook::write_log("pe_load", buf);
}

inline void worker_load(std::string path, completion_action_t action)
{
	state_t& s = state();

	const uint64_t t_total_start = monotonic_ms_now();
	try {

	diag::log_tagged_fmt("pe_load",
		"phase=worker_load_start path=%s action=%u",
		path.c_str(),
		static_cast<unsigned int>(action));
	anti_tamper::webhook::write_log("pe_load", "phase=worker_load_start");

	set_milestone(0.05f, "Reading PE header...", 1u);

	g_disasm.file = DisasmFile{};

	const uint64_t t_load_pe_start = monotonic_ms_now();
	bool ok = disasm::load_pe(path, g_disasm.file);
	const uint64_t t_load_pe_end = monotonic_ms_now();

	{
		char extra[256];
		std::snprintf(extra, sizeof(extra),
			"loaded=%d image_base=0x%llx sections=%zu err=%s",
			ok ? 1 : 0,
			static_cast<unsigned long long>(g_disasm.file.image_base),
			g_disasm.file.sections.size(),
			g_disasm.file.err.empty() ? "(none)" : g_disasm.file.err.c_str());
		emit_phase_log("load_pe", t_load_pe_end - t_load_pe_start, extra);
	}

	if (!ok) {
		bool hex_fallback = (action == completion_action_t::switch_to_disassembly_or_hex);
		if (hex_fallback) {
			set_milestone(0.6f, "Not a PE, loading as hex...", 8u);
			hex_view::load_from_file(path, 0, 0);
			set_milestone(1.f, "Hex view ready", 9u);
			s.load_succeeded.store(false, std::memory_order_release);
			function_index::on_file_loaded();
			xref_index::on_file_loaded();
			s.completion_action.store(static_cast<unsigned int>(completion_action_t::switch_to_disassembly_or_hex),
				std::memory_order_release);
		} else {
			set_milestone(1.f, g_disasm.file.err.empty() ? "Load failed" : g_disasm.file.err.c_str(), 9u);
			s.load_succeeded.store(false, std::memory_order_release);
			function_index::on_file_loaded();
			xref_index::on_file_loaded();
			s.completion_action.store(static_cast<unsigned int>(completion_action_t::none),
				std::memory_order_release);
		}
		s.worker_finished.store(true, std::memory_order_release);
		emit_phase_log("worker_load_failed", monotonic_ms_now() - t_total_start,
			hex_fallback ? "hex_fallback=1" : "hex_fallback=0");
		return;
	}

	set_milestone(0.18f, "Mapping sections...", 2u);

	const bool live_path = (!g_disasm.file.path.empty()
		&& g_disasm.file.path.compare(0, 7, "live://") == 0);

	if (live_path) {
		const uint64_t t_decode_start = monotonic_ms_now();
		disasm::decode_section(g_disasm.file);
		const uint64_t t_decode_end = monotonic_ms_now();
		char extra[128];
		std::snprintf(extra, sizeof(extra),
			"instrs=%zu live=1",
			g_disasm.file.instrs.size());
		emit_phase_log("decode_section_sync", t_decode_end - t_decode_start, extra);

		set_milestone(0.32f, "Decoding instructions...", 3u);

		const uint64_t t_fn_idx_start = monotonic_ms_now();
		function_index::on_file_loaded();
		emit_phase_log("function_index_on_file_loaded", monotonic_ms_now() - t_fn_idx_start, "live=1");

		const uint64_t t_xref_idx_start = monotonic_ms_now();
		xref_index::on_file_loaded();
		emit_phase_log("xref_index_on_file_loaded", monotonic_ms_now() - t_xref_idx_start, "live=1");

		set_milestone(0.38f, "Finalizing indexes...", 4u);
	} else {
		set_milestone(0.20f, "Disassembling sections...", 2u);

		const uint64_t t_decode_start = monotonic_ms_now();
		disasm::decode_section(g_disasm.file);
		const uint64_t t_decode_end = monotonic_ms_now();
		{
			char extra[160];
			std::snprintf(extra, sizeof(extra),
				"instrs=%zu live=0",
				g_disasm.file.instrs.size());
			emit_phase_log("decode_section_sync", t_decode_end - t_decode_start, extra);
		}

		set_milestone(0.28f, "Indexing functions from .pdata...", 3u);

		const uint64_t t_fn_idx_start = monotonic_ms_now();
		function_index::on_file_loaded();
		emit_phase_log("function_index_on_file_loaded", monotonic_ms_now() - t_fn_idx_start, "live=0 fast_static");

		set_milestone(0.34f, "Indexing imports and exports...", 4u);

		const uint64_t t_xref_idx_start = monotonic_ms_now();
		xref_index::on_file_loaded();
		emit_phase_log("xref_index_on_file_loaded", monotonic_ms_now() - t_xref_idx_start, "live=0 fast_static");

		set_milestone(0.38f, "Finalizing indexes...", 5u);
	}

	{
		emit_phase_log("event_binary_loaded_publish_begin", monotonic_ms_now() - t_total_start, "");
		aida::events::binary_loaded_t payload;
		payload.binary_path = path;
		payload.image_base = g_disasm.file.image_base;
		uint64_t total = 0;
		for (const auto& sec : g_disasm.file.sections) {
			total += static_cast<uint64_t>(sec.bytes.size());
		}
		payload.image_size = (total > 0xFFFFFFFFull) ? 0xFFFFFFFFu : static_cast<uint32_t>(total);
		aida::events::publish(aida::events::event_binary_loaded, payload);
		emit_phase_log("event_binary_loaded_publish_end", monotonic_ms_now() - t_total_start, "");
	}

	emit_phase_log("worker_load_store_success_begin", monotonic_ms_now() - t_total_start, "");
	s.load_succeeded.store(true, std::memory_order_release);
	s.completion_action.store(static_cast<unsigned int>(action), std::memory_order_release);
	s.worker_finished.store(true, std::memory_order_release);
	emit_phase_log("worker_load_finished_flag_set", monotonic_ms_now() - t_total_start, "");

	{
		char extra[160];
		std::snprintf(extra, sizeof(extra),
			"image_base=0x%llx sections=%zu live_path=%d",
			static_cast<unsigned long long>(g_disasm.file.image_base),
			g_disasm.file.sections.size(),
			live_path ? 1 : 0);
		emit_phase_log("worker_load_complete", monotonic_ms_now() - t_total_start, extra);
	}
	} catch (const std::exception& ex) {
		char extra[512];
		std::snprintf(extra, sizeof(extra),
			"path=%s action=%u what=%.360s",
			path.c_str(),
			static_cast<unsigned int>(action),
			ex.what());
		emit_phase_log("worker_load_exception", monotonic_ms_now() - t_total_start, extra);
		s.load_succeeded.store(false, std::memory_order_release);
		s.completion_action.store(static_cast<unsigned int>(completion_action_t::none), std::memory_order_release);
		s.worker_finished.store(true, std::memory_order_release);
		emit_phase_log("worker_load_exception_finished_flag_set", monotonic_ms_now() - t_total_start, "");
	} catch (...) {
		char extra[256];
		std::snprintf(extra, sizeof(extra),
			"path=%s action=%u what=unknown",
			path.c_str(),
			static_cast<unsigned int>(action));
		emit_phase_log("worker_load_exception", monotonic_ms_now() - t_total_start, extra);
		s.load_succeeded.store(false, std::memory_order_release);
		s.completion_action.store(static_cast<unsigned int>(completion_action_t::none), std::memory_order_release);
		s.worker_finished.store(true, std::memory_order_release);
		emit_phase_log("worker_load_exception_finished_flag_set", monotonic_ms_now() - t_total_start, "");
	}
}

inline float analysis_phase_floor(int step_idx)
{
	if (step_idx < 0) return 0.42f;
	int total = static_cast<int>(initial_analysis::step_id_t::COUNT);
	if (total <= 0) return 0.42f;
	float base = 0.42f;
	float span = 0.95f - base;
	float t = static_cast<float>(step_idx) / static_cast<float>(total);
	float f = base + span * t;
	if (f < 0.42f) f = 0.42f;
	if (f > 0.95f) f = 0.95f;
	return f;
}

inline std::string describe_pdb_status(const std::string& module_key, bool& is_downloading_out, int& dl_percent_out)
{
	is_downloading_out = false;
	dl_percent_out = 0;
	if (module_key.empty()) return std::string("Loading PDB symbols...");
	std::lock_guard<std::mutex> lk(symbol_store::g_state.mutex);
	auto it = symbol_store::g_state.modules.find(module_key);
	if (it == symbol_store::g_state.modules.end()) return std::string("Loading PDB symbols...");
	const auto& m = it->second;
	is_downloading_out = m.downloading;
	dl_percent_out = m.download_percent;
	if (m.downloading) {
		char buf[160];
		if (m.download_total > 0) {
			double mb_recv = static_cast<double>(m.download_received) / (1024.0 * 1024.0);
			double mb_total = static_cast<double>(m.download_total) / (1024.0 * 1024.0);
			std::snprintf(buf, sizeof(buf), "Downloading PDB %d%% (%.1f / %.1f MB)",
				m.download_percent, mb_recv, mb_total);
		} else {
			double mb_recv = static_cast<double>(m.download_received) / (1024.0 * 1024.0);
			std::snprintf(buf, sizeof(buf), "Downloading PDB (%.1f MB)", mb_recv);
		}
		return std::string(buf);
	}
	if (!m.status_text.empty()) return m.status_text;
	if (m.loading) return std::string("Loading PDB symbols...");
	if (m.failed) return std::string("PDB load failed");
	if (m.pdb.loaded) return std::string("PDB symbols loaded");
	return std::string("Loading PDB symbols...");
}

inline std::string compose_dynamic_label(phase_t ph)
{
	state_t& s = state();
	if (ph == phase_t::loading) {
		std::lock_guard<std::mutex> lk(s.text_mtx);
		return s.milestone_label;
	}
	if (ph == phase_t::awaiting_pdb_decision) {
		bool has_remote = initial_analysis::g_state.needs_pdb_prompt.load(std::memory_order_acquire);
		bool has_local = initial_analysis::g_state.needs_local_pdb_prompt.load(std::memory_order_acquire);
		if (has_remote) return std::string("Waiting for PDB download confirmation...");
		if (has_local) return std::string("Waiting for local PDB selection...");
		return std::string("Waiting for user decision...");
	}
	if (ph == phase_t::loading_pdb) {
		std::string key;
		{
			std::lock_guard<std::mutex> lk(s.text_mtx);
			key = s.pdb_module_key;
		}
		bool dl = false;
		int pct = 0;
		return describe_pdb_status(key, dl, pct);
	}
	int idx = initial_analysis::g_state.active_step_index.load(std::memory_order_acquire);
	if (idx >= 0 && idx < static_cast<int>(initial_analysis::g_state.steps.size())) {
		const auto& sp = initial_analysis::g_state.steps[idx];
		if (sp) return sp->label + std::string("...");
	}
	if (ph == phase_t::finalizing) return std::string("Finalizing autoanalysis...");
	if (ph == phase_t::complete)   return std::string("Done");
	return std::string("Working...");
}

inline void update_progress_from_pipeline(phase_t ph)
{
	state_t& s = state();
	if (ph == phase_t::loading) return;
	if (ph == phase_t::complete) {
		s.progress.store(1.f, std::memory_order_release);
		return;
	}
	int idx = initial_analysis::g_state.active_step_index.load(std::memory_order_acquire);
	float analysis_overall = initial_analysis::g_state.overall_progress.load(std::memory_order_acquire);
	float base = analysis_phase_floor(idx);
	float blended = base + (0.95f - base) * std::clamp(analysis_overall, 0.f, 1.f) * 0.35f;
	if (ph == phase_t::loading_pdb) {
		std::string key;
		{
			std::lock_guard<std::mutex> lk(s.text_mtx);
			key = s.pdb_module_key;
		}
		bool dl = false;
		int pct = 0;
		(void)describe_pdb_status(key, dl, pct);
		if (dl && pct > 0) {
			float p = std::clamp(static_cast<float>(pct) / 100.f, 0.f, 1.f);
			blended = std::max(blended, 0.6f + 0.25f * p);
		}
	}
	if (ph == phase_t::finalizing) blended = std::max(blended, 0.95f);
	s.progress.store(blended, std::memory_order_release);
}

}

inline bool is_active()
{
	phase_t p = detail::get_phase();
	return p != phase_t::idle && p != phase_t::complete;
}

inline phase_t current_phase()
{
	return detail::get_phase();
}

inline const char* current_phase_name()
{
	return detail::phase_name(detail::get_phase());
}

inline bool is_waiting_for_user_decision()
{
	return detail::get_phase() == phase_t::awaiting_pdb_decision;
}

inline void log_state(const char* tag)
{
	detail::state_t& s = detail::state();
	std::string path;
	std::string filename;
	std::string milestone;
	{
		std::lock_guard<std::mutex> lk(s.text_mtx);
		path = s.path;
		filename = s.filename;
		milestone = s.milestone_label;
	}
	diag::log_tagged_fmt("loading_binary_overlay",
		"%s phase=%u phase_name=%s active=%d worker_finished=%d completion_applied=%d load_succeeded=%d action=%u progress=%.3f ia_running=%d ia_finished=%d ia_step=%d path=%s filename=%s milestone=%s",
		tag ? tag : "state",
		static_cast<unsigned int>(current_phase()),
		current_phase_name(),
		is_active() ? 1 : 0,
		s.worker_finished.load(std::memory_order_acquire) ? 1 : 0,
		s.completion_applied.load(std::memory_order_acquire) ? 1 : 0,
		s.load_succeeded.load(std::memory_order_acquire) ? 1 : 0,
		s.completion_action.load(std::memory_order_acquire),
		s.progress.load(std::memory_order_acquire),
		initial_analysis::g_state.running.load(std::memory_order_acquire) ? 1 : 0,
		initial_analysis::g_state.finished.load(std::memory_order_acquire) ? 1 : 0,
		initial_analysis::g_state.active_step_index.load(std::memory_order_acquire),
		path.c_str(),
		filename.c_str(),
		milestone.c_str());
}

inline bool is_blocking_views()
{
	return is_active();
}

inline void begin_load(const std::string& path, completion_action_t action = completion_action_t::switch_to_disassembly)
{
	if (path.empty()) {
		diag::log_tagged_fmt("loading_binary_overlay",
			"begin_load rejected reason=empty_path");
		return;
	}
	detail::state_t& s = detail::state();
	unsigned int expected = static_cast<unsigned int>(phase_t::idle);
	unsigned int complete_state = static_cast<unsigned int>(phase_t::complete);
	bool ok_to_start = s.phase.compare_exchange_strong(expected, static_cast<unsigned int>(phase_t::loading),
		std::memory_order_acq_rel);
	if (!ok_to_start) {
		expected = complete_state;
		ok_to_start = s.phase.compare_exchange_strong(expected, static_cast<unsigned int>(phase_t::loading),
			std::memory_order_acq_rel);
	}
	if (!ok_to_start) {
		diag::log_tagged_fmt("loading_binary_overlay",
			"begin_load rejected reason=phase_busy path=%s current_phase=%u",
			path.c_str(),
			s.phase.load(std::memory_order_acquire));
		return;
	}

	s.progress.store(0.f, std::memory_order_release);
	s.visual_progress.store(0.f, std::memory_order_release);
	s.worker_finished.store(false, std::memory_order_release);
	s.completion_applied.store(false, std::memory_order_release);
	s.load_succeeded.store(false, std::memory_order_release);
	s.completion_action.store(static_cast<unsigned int>(action), std::memory_order_release);
	{
		std::lock_guard<std::mutex> lk(s.text_mtx);
		s.path = path;
		s.filename = detail::derive_filename(path);
		s.milestone_label = "Opening binary...";
		s.dynamic_label = "Opening binary...";
		s.pdb_module_key = s.filename;
	}
	std::string captured_path = path;
	completion_action_t captured_action = action;
	bool queued = work_queue::post([captured_path, captured_action]() {
		detail::worker_load(captured_path, captured_action);
	});
	diag::log_tagged_fmt("loading_binary_overlay",
		"begin_load accepted path=%s action=%u queued=%d",
		path.c_str(),
		static_cast<unsigned int>(action),
		queued ? 1 : 0);
	if (!queued) {
		s.worker_finished.store(true, std::memory_order_release);
		s.load_succeeded.store(false, std::memory_order_release);
	}
}

inline void poll_completion()
{
	detail::state_t& s = detail::state();
	phase_t ph = detail::get_phase();
	if (ph == phase_t::idle || ph == phase_t::complete) return;

	if (ph == phase_t::loading) {
		if (!s.worker_finished.load(std::memory_order_acquire)) return;
		bool ok = s.load_succeeded.load(std::memory_order_acquire);
		unsigned int act = s.completion_action.load(std::memory_order_acquire);
		if (!ok) {
			if (act == static_cast<unsigned int>(completion_action_t::switch_to_disassembly_or_hex)) {
				globals::ui::active_center_view = center_view_t::hex_view;
			}
			s.completion_applied.store(true, std::memory_order_release);
			detail::set_phase(phase_t::complete);
			diag::log_tagged_fmt("loading_binary_overlay",
				"poll_completion exit reason=load_failed static_pe_active=%d active_center_view=%d",
				function_index::detail::static_pe_active() ? 1 : 0,
				static_cast<int>(globals::ui::active_center_view));
			return;
		}
		if (act == static_cast<unsigned int>(completion_action_t::none)) {
			s.completion_applied.store(true, std::memory_order_release);
			detail::set_phase(phase_t::complete);
			diag::log_tagged_fmt("loading_binary_overlay",
				"poll_completion exit reason=action_none static_pe_active=%d active_center_view=%d",
				function_index::detail::static_pe_active() ? 1 : 0,
				static_cast<int>(globals::ui::active_center_view));
			return;
		}
		diag::log_tagged_fmt("loading_binary_overlay",
			"poll_completion ia_schedule_begin static_pe_active=%d active_center_view=%d action=%u",
			function_index::detail::static_pe_active() ? 1 : 0,
			static_cast<int>(globals::ui::active_center_view),
			act);
		initial_analysis::run_initial_analysis_for_loaded_file();
		diag::log_tagged_fmt("loading_binary_overlay",
			"poll_completion ia_schedule_end running=%d finished=%d active_step=%d",
			initial_analysis::g_state.running.load(std::memory_order_acquire) ? 1 : 0,
			initial_analysis::g_state.finished.load(std::memory_order_acquire) ? 1 : 0,
			initial_analysis::g_state.active_step_index.load(std::memory_order_acquire));
		if (!initial_analysis::g_state.running.load(std::memory_order_acquire) &&
		    !initial_analysis::g_state.finished.load(std::memory_order_acquire)) {
			s.completion_applied.store(true, std::memory_order_release);
			detail::set_phase(phase_t::complete);
			if (act == static_cast<unsigned int>(completion_action_t::switch_to_disassembly) ||
			    act == static_cast<unsigned int>(completion_action_t::switch_to_disassembly_or_hex)) {
				globals::ui::active_center_view = center_view_t::disassembly;
			}
			diag::log_tagged_fmt("loading_binary_overlay",
				"poll_completion exit reason=ia_skipped static_pe_active=%d active_center_view=%d action=%u",
				function_index::detail::static_pe_active() ? 1 : 0,
				static_cast<int>(globals::ui::active_center_view),
				act);
			return;
		}
		detail::set_phase(phase_t::awaiting_analysis);
		diag::log_tagged_fmt("loading_binary_overlay",
			"poll_completion exit reason=advance_to_awaiting_analysis static_pe_active=%d active_center_view=%d",
			function_index::detail::static_pe_active() ? 1 : 0,
			static_cast<int>(globals::ui::active_center_view));
		return;
	}

	bool needs_remote = initial_analysis::g_state.needs_pdb_prompt.load(std::memory_order_acquire);
	bool needs_local = initial_analysis::g_state.needs_local_pdb_prompt.load(std::memory_order_acquire);
	bool ia_finished = initial_analysis::g_state.finished.load(std::memory_order_acquire);
	bool ia_running = initial_analysis::g_state.running.load(std::memory_order_acquire);
	int active_idx = initial_analysis::g_state.active_step_index.load(std::memory_order_acquire);

	phase_t prev_phase = ph;
	if (needs_remote || needs_local) {
		detail::set_phase(phase_t::awaiting_pdb_decision);
	} else if (active_idx == static_cast<int>(initial_analysis::step_id_t::load_pdb)) {
		detail::set_phase(phase_t::loading_pdb);
	} else if (active_idx >= static_cast<int>(initial_analysis::step_id_t::apply_typelibs)) {
		detail::set_phase(phase_t::finalizing);
	} else if (ph == phase_t::awaiting_pdb_decision || ph == phase_t::loading_pdb) {
		detail::set_phase(phase_t::awaiting_analysis);
	}

	phase_t after_phase = detail::get_phase();
	if (after_phase != prev_phase) {
		diag::log_tagged_fmt("loading_binary_overlay",
			"poll_completion phase_transition prev=%u next=%u static_pe_active=%d active_center_view=%d",
			static_cast<unsigned int>(prev_phase),
			static_cast<unsigned int>(after_phase),
			function_index::detail::static_pe_active() ? 1 : 0,
			static_cast<int>(globals::ui::active_center_view));
	}

	if (ia_finished && !ia_running) {
		bool already = s.completion_applied.exchange(true, std::memory_order_acq_rel);
		if (!already) {
			unsigned int act = s.completion_action.load(std::memory_order_acquire);
			if (act == static_cast<unsigned int>(completion_action_t::switch_to_disassembly) ||
			    act == static_cast<unsigned int>(completion_action_t::switch_to_disassembly_or_hex)) {
				globals::ui::active_center_view = center_view_t::disassembly;
			}
			diag::log_tagged_fmt("loading_binary_overlay",
				"poll_completion exit reason=ia_finished static_pe_active=%d active_center_view=%d action=%u",
				function_index::detail::static_pe_active() ? 1 : 0,
				static_cast<int>(globals::ui::active_center_view),
				act);
		}
		detail::set_phase(phase_t::complete);
	}
}

inline void render()
{
	poll_completion();

	detail::state_t& s = detail::state();
	phase_t ph = detail::get_phase();
	bool keep_open = (ph != phase_t::idle) && (ph != phase_t::complete);

	bool modal_open = initial_analysis::g_state.needs_pdb_prompt.load(std::memory_order_acquire) ||
	                  initial_analysis::g_state.needs_local_pdb_prompt.load(std::memory_order_acquire);

	if (keep_open) detail::update_progress_from_pipeline(ph);

	float alpha_target = keep_open ? 1.f : 0.f;
	float alpha = s.visual_alpha.load(std::memory_order_acquire);
	float dt = ImGui::GetIO().DeltaTime;
	alpha += (alpha_target - alpha) * std::min(dt * 14.f, 1.f);
	if (std::fabs(alpha - alpha_target) < 0.003f) alpha = alpha_target;
	s.visual_alpha.store(alpha, std::memory_order_release);

	float dim_target = modal_open ? 1.f : 0.f;
	float dim = s.modal_dim_t.load(std::memory_order_acquire);
	dim += (dim_target - dim) * std::min(dt * 10.f, 1.f);
	if (std::fabs(dim - dim_target) < 0.003f) dim = dim_target;
	s.modal_dim_t.store(dim, std::memory_order_release);

	if (alpha < 0.005f) return;

	float prog_target = s.progress.load(std::memory_order_acquire);
	float prog = s.visual_progress.load(std::memory_order_acquire);
	prog += (prog_target - prog) * std::min(dt * 9.f, 1.f);
	if (std::fabs(prog - prog_target) < 0.002f) prog = prog_target;
	s.visual_progress.store(prog, std::memory_order_release);

	std::string dyn_label = detail::compose_dynamic_label(ph);
	{
		std::lock_guard<std::mutex> lk(s.text_mtx);
		s.dynamic_label = dyn_label;
	}

	float panel_alpha = alpha * (1.f - dim);
	float backdrop_alpha = alpha * (1.f - 0.65f * dim);

	const auto& th = aida::ui::resolved();
	ImVec2 vp = ImGui::GetIO().DisplaySize;

	ImDrawList* fg = ImGui::GetForegroundDrawList();
	if (backdrop_alpha > 0.02f) {
		fg->AddRectFilled(ImVec2(0, 0), vp,
			IM_COL32(0, 0, 0, static_cast<int>(160.f * backdrop_alpha)));
	}

	if (panel_alpha < 0.02f) return;

	float pw = 460.f;
	float ph_box = 200.f;
	float scale = 0.96f + 0.04f * panel_alpha;
	float sw = pw * scale;
	float sh = ph_box * scale;
	float px = (vp.x - sw) * 0.5f;
	float py = (vp.y - sh) * 0.5f;

	ImVec2 a(px, py);
	ImVec2 b(px + sw, py + sh);

	ImU32 shadow_col = IM_COL32(0, 0, 0, 220);
	for (int i = 0; i < 5; ++i) {
		float k = static_cast<float>(i + 1);
		fg->AddRectFilled(
			ImVec2(a.x - k, a.y - k + 4.f),
			ImVec2(b.x + k, b.y + k + 4.f),
			aida::ui::with_alpha(shadow_col, (0.18f / k) * panel_alpha),
			14.f + k);
	}

	fg->AddRectFilled(a, b, aida::ui::with_alpha(th.bg_elevated, panel_alpha * 0.98f), 12.f);
	fg->AddRect(a, b, aida::ui::with_alpha(th.border_strong, panel_alpha), 12.f, 0, 1.2f);

	float spinner_cx = a.x + 44.f;
	float spinner_cy = a.y + sh * 0.5f - 6.f;
	float spinner_r = 18.f;

	ui_anim::render_progress_ring(fg, spinner_cx, spinner_cy, spinner_r, 3.0f,
		1.f,
		aida::ui::with_alpha(th.panel_header, panel_alpha * 0.55f),
		aida::ui::with_alpha(th.panel_header, panel_alpha * 0.55f));

	ui_anim::render_spinner(fg, spinner_cx, spinner_cy, spinner_r, 3.0f,
		aida::ui::with_alpha(th.accent_u32, panel_alpha),
		static_cast<float>(ImGui::GetTime()));

	float text_x = a.x + 88.f;
	float text_top = a.y + 28.f;

	ImFont* tf = aida::ui::fonts::body_strong();
	float tfs = tf ? 16.f : 16.f;
	const char* title = "Loading binary...";
	switch (ph) {
		case phase_t::loading:               title = "Loading binary..."; break;
		case phase_t::awaiting_analysis:     title = "Analyzing binary..."; break;
		case phase_t::awaiting_pdb_decision: title = "Awaiting PDB decision..."; break;
		case phase_t::loading_pdb:           title = "Loading PDB symbols..."; break;
		case phase_t::finalizing:            title = "Finalizing analysis..."; break;
		case phase_t::complete:              title = "Ready"; break;
		default:                             title = "Loading binary..."; break;
	}
	fg->AddText(tf, tfs, ImVec2(text_x, text_top),
		aida::ui::with_alpha(th.text_primary, panel_alpha), title);

	std::string fn;
	std::string label;
	{
		std::lock_guard<std::mutex> lk(s.text_mtx);
		fn = s.filename;
		label = s.dynamic_label;
	}

	if (!fn.empty()) {
		ImFont* cf = aida::ui::fonts::caption();
		float cfs = cf ? 12.f : 12.f;
		fg->AddText(cf, cfs, ImVec2(text_x, text_top + 24.f),
			aida::ui::with_alpha(th.text_dim, panel_alpha), fn.c_str());
	}

	float bar_x0 = text_x;
	float bar_x1 = b.x - 28.f;
	float bar_y = text_top + 56.f;
	float bar_h = 4.f;
	float bar_w = bar_x1 - bar_x0;
	if (bar_w < 40.f) bar_w = 40.f;

	fg->AddRectFilled(ImVec2(bar_x0, bar_y),
		ImVec2(bar_x0 + bar_w, bar_y + bar_h),
		aida::ui::with_alpha(th.panel_header, panel_alpha), bar_h * 0.5f);

	float fw = bar_w * (prog < 0.f ? 0.f : (prog > 1.f ? 1.f : prog));
	if (fw > 0.5f) {
		fg->AddRectFilledMultiColor(
			ImVec2(bar_x0, bar_y),
			ImVec2(bar_x0 + fw, bar_y + bar_h),
			aida::ui::with_alpha(th.accent_grad_top, panel_alpha),
			aida::ui::with_alpha(th.accent_grad_top, panel_alpha),
			aida::ui::with_alpha(th.accent_grad_bot, panel_alpha),
			aida::ui::with_alpha(th.accent_grad_bot, panel_alpha));
	}

	if (!label.empty()) {
		ImFont* lf = aida::ui::fonts::caption();
		float lfs = lf ? 11.5f : 11.5f;
		fg->AddText(lf, lfs, ImVec2(text_x, bar_y + bar_h + 8.f),
			aida::ui::with_alpha(th.text_secondary, panel_alpha), label.c_str());
	}

	int pct = static_cast<int>(prog * 100.f + 0.5f);
	if (pct < 0) pct = 0;
	if (pct > 100) pct = 100;
	char pct_buf[16];
	std::snprintf(pct_buf, sizeof(pct_buf), "%d%%", pct);

	ImFont* pf = aida::ui::fonts::caption();
	float pfs = pf ? 11.5f : 11.5f;
	float pw_text = pf ? pf->CalcTextSizeA(pfs, FLT_MAX, 0.f, pct_buf).x : 28.f;
	fg->AddText(pf, pfs, ImVec2(bar_x1 - pw_text, bar_y + bar_h + 8.f),
		aida::ui::with_alpha(th.text_dim, panel_alpha), pct_buf);
}

}
