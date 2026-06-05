#include "analysis_session.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <mutex>
#include <string>

#include "../ui/loading_binary_overlay.hpp"
#include "../runtime/standalone_driver.hpp"
#include "../analysis/stealth_engine.hpp"
#include "../../helpers/diag_log.hpp"

extern DisasmState g_disasm;

namespace analysis_session {

namespace {

struct session_state_t {
	std::vector<std::unique_ptr<analysis_session_t>> sessions;
	int                                              active_idx = -1;
	uint64_t                                         id_counter = 0;
	std::mutex                                       mu;
	std::string                                      last_error;
};

inline session_state_t& state() {
	static session_state_t s;
	return s;
}

inline uint64_t now_steady_ms() {
	auto tp = std::chrono::steady_clock::now().time_since_epoch();
	return static_cast<uint64_t>(
		std::chrono::duration_cast<std::chrono::milliseconds>(tp).count());
}

inline std::string derive_filename(const std::string& path) {
	size_t sl = path.find_last_of("/\\");
	return (sl != std::string::npos) ? path.substr(sl + 1) : path;
}

inline std::string make_session_id(uint64_t counter) {
	char buf[40];
	std::snprintf(buf, sizeof(buf), "as_%016llx", static_cast<unsigned long long>(counter));
	return std::string(buf);
}

inline bool paths_equal(const std::string& a, const std::string& b) {
	if (a.size() != b.size()) return false;
	for (size_t i = 0; i < a.size(); ++i) {
		char ca = a[i];
		char cb = b[i];
		if (ca == '/' ) ca = '\\';
		if (cb == '/') cb = '\\';
		if (ca >= 'A' && ca <= 'Z') ca = static_cast<char>(ca - 'A' + 'a');
		if (cb >= 'A' && cb <= 'Z') cb = static_cast<char>(cb - 'A' + 'a');
		if (ca != cb) return false;
	}
	return true;
}

inline std::wstring widen_utf8(const std::string& s) {
	if (s.empty()) return {};
	int needed = MultiByteToWideChar(CP_UTF8, 0, s.c_str(),
		static_cast<int>(s.size()), nullptr, 0);
	if (needed <= 0) return {};
	std::wstring out(static_cast<size_t>(needed), L'\0');
	MultiByteToWideChar(CP_UTF8, 0, s.c_str(),
		static_cast<int>(s.size()), out.data(), needed);
	return out;
}

inline void capture_live_into_session_locked(analysis_session_t& dst) {
	dst.disasm_file = std::make_unique<DisasmFile>(std::move(g_disasm.file));
	g_disasm.file = DisasmFile{};
	dst.fn_cache = function_index::detach_snapshot();
	dst.xref_registry = xref_index::detach_snapshot();
	dst.symbol_snap = symbol_store::detach_snapshot();
	dst.decomp_snap = decompiler_engine::detach_snapshot();
	dst.disasm_view_snap = disasm_view::detach_snapshot();
	dst.types_hub_snap = types_hub_view::detach_snapshot();
	dst.crypto_snap = crypto_scanner::detach_snapshot();
	dst.xref_db_snap = xref_db::detach_snapshot();

	if (dst.attached_pid != 0) {
		auto live = std::make_unique<live_attach_snapshot_t>();
		live->breakpoints = debugger_engine::snapshot_breakpoints();
		live->watches = debugger_engine::snapshot_watches();
		dst.live_snap = std::move(live);
		debugger_engine::clear_breakpoints_and_watches();
	}
}

inline void restore_session_into_live_locked(analysis_session_t& src) {
	if (src.disasm_file) {
		g_disasm.file = std::move(*src.disasm_file);
		src.disasm_file.reset();
	} else {
		g_disasm.file = DisasmFile{};
	}
	function_index::attach_snapshot(std::move(src.fn_cache));
	xref_index::attach_snapshot(std::move(src.xref_registry));
	symbol_store::attach_snapshot(std::move(src.symbol_snap));
	decompiler_engine::attach_snapshot(std::move(src.decomp_snap));
	disasm_view::attach_snapshot(std::move(src.disasm_view_snap));
	types_hub_view::attach_snapshot(std::move(src.types_hub_snap));
	crypto_scanner::attach_snapshot(std::move(src.crypto_snap));
	xref_db::attach_snapshot(std::move(src.xref_db_snap));

	const uint32_t previous_pid = driver_bridge::attached_pid();
	if (src.attached_pid != 0) {
		if (previous_pid != 0 && previous_pid != src.attached_pid)
			stealth_engine::disable_for_detach(previous_pid, "analysis_session.restore.replace");
		bool active_ok = driver_bridge::set_active_pid(src.attached_pid);
		if (!active_ok) {
			(void)driver_bridge::attach_additional(src.attached_pid);
			active_ok = driver_bridge::set_active_pid(src.attached_pid);
		}
		if (active_ok && driver_bridge::attached_pid() == src.attached_pid) {
			(void)stealth_engine::ensure_default_enabled(src.attached_pid, "analysis_session.restore");
		} else if (previous_pid != 0 && driver_bridge::attached_pid() == previous_pid) {
			(void)stealth_engine::ensure_default_enabled(previous_pid, "analysis_session.restore_failed_switch");
		}
	} else {
		if (previous_pid != 0)
			stealth_engine::disable_for_detach(previous_pid, "analysis_session.restore.clear");
		(void)driver_bridge::clear_active_pid();
	}

	if (src.live_snap) {
		debugger_engine::restore_breakpoints_and_watches(
			std::move(src.live_snap->breakpoints),
			std::move(src.live_snap->watches));
		src.live_snap.reset();
	} else {
		debugger_engine::clear_breakpoints_and_watches();
	}
}

inline void reset_live_to_default_locked() {
	const uint32_t pid_before = driver_bridge::attached_pid();
	const std::string name_before = driver_bridge::attached_process_name();
	diag::log_tagged_fmt("analysis_session",
		"reset_live_to_default_begin pid_before=%u name='%s' active_idx=%d sessions=%llu path='%s'",
		pid_before,
		name_before.c_str(),
		state().active_idx,
		static_cast<unsigned long long>(state().sessions.size()),
		g_disasm.file.path.c_str());
	g_disasm.file = DisasmFile{};
	function_index::attach_snapshot(nullptr);
	xref_index::attach_snapshot(nullptr);
	symbol_store::attach_snapshot(nullptr);
	decompiler_engine::attach_snapshot(nullptr);
	disasm_view::attach_snapshot(nullptr);
	types_hub_view::attach_snapshot(nullptr);
	crypto_scanner::attach_snapshot(nullptr);
	xref_db::attach_snapshot(nullptr);
	debugger_engine::clear_breakpoints_and_watches();
	stealth_engine::disable_for_detach(pid_before, "analysis_session.reset_live");
	const bool clear_ok = driver_bridge::clear_active_pid();
	diag::log_tagged_fmt("analysis_session",
		"reset_live_to_default_end pid_before=%u clear_ok=%d pid_after=%u last_error='%s'",
		pid_before,
		clear_ok ? 1 : 0,
		driver_bridge::attached_pid(),
		driver_bridge::last_error().c_str());
}

inline void evict_lru_if_needed_locked() {
	if (state().sessions.size() <= kMaxSessions) return;
	size_t victim = 0;
	uint64_t oldest = UINT64_MAX;
	bool found = false;
	for (size_t i = 0; i < state().sessions.size(); ++i) {
		if (static_cast<int>(i) == state().active_idx) continue;
		if (state().sessions[i]->last_active_steady_ms < oldest) {
			oldest = state().sessions[i]->last_active_steady_ms;
			victim = i;
			found = true;
		}
	}
	if (!found) return;
	auto& vs = *state().sessions[victim];
	if (vs.attached_pid != 0) {
		(void)driver_bridge::detach_one(vs.attached_pid);
	}
	if (static_cast<int>(victim) < state().active_idx) {
		state().active_idx -= 1;
	}
	state().sessions.erase(state().sessions.begin() + victim);
}

}

bool open_session(const std::string& path) {
	if (path.empty()) {
		state().last_error = "empty_path";
		return false;
	}

	if (loading_binary_overlay::is_active()) {
		state().last_error = "load_in_flight";
		return false;
	}

	{
		std::lock_guard<std::mutex> lk(state().mu);
		for (size_t i = 0; i < state().sessions.size(); ++i) {
			if (paths_equal(state().sessions[i]->path, path)) {
				if (static_cast<int>(i) == state().active_idx) {
					state().sessions[i]->last_active_steady_ms = now_steady_ms();
					return false;
				}
				int cur = state().active_idx;
				if (cur >= 0 && cur < static_cast<int>(state().sessions.size())) {
					auto& src = *state().sessions[cur];
					capture_live_into_session_locked(src);
					src.last_active_steady_ms = now_steady_ms();
				}
				auto& dst = *state().sessions[i];
				restore_session_into_live_locked(dst);
				dst.last_active_steady_ms = now_steady_ms();
				state().active_idx = static_cast<int>(i);
				return false;
			}
		}

		int cur = state().active_idx;
		if (cur >= 0 && cur < static_cast<int>(state().sessions.size())) {
			auto& src = *state().sessions[cur];
			capture_live_into_session_locked(src);
			src.last_active_steady_ms = now_steady_ms();
		}

		reset_live_to_default_locked();

		auto sess = std::make_unique<analysis_session_t>();
		sess->id = make_session_id(++state().id_counter);
		sess->path = path;
		sess->filename = derive_filename(path);
		sess->last_active_steady_ms = now_steady_ms();
		state().sessions.push_back(std::move(sess));
		state().active_idx = static_cast<int>(state().sessions.size()) - 1;

		evict_lru_if_needed_locked();
	}

	loading_binary_overlay::begin_load(path,
		loading_binary_overlay::completion_action_t::switch_to_disassembly_or_hex);
	return true;
}

bool open_attach_session(uint32_t pid, std::string* out_err) {
	if (pid == 0) {
		state().last_error = "invalid_pid";
		if (out_err) *out_err = "invalid_pid";
		diag::log_tagged("analysis_session", "open_attach_session_invalid_pid");
		return false;
	}

	if (loading_binary_overlay::is_active() &&
		!loading_binary_overlay::is_waiting_for_user_decision()) {
		state().last_error = "load_in_flight";
		if (out_err) *out_err = "load_in_flight";
		diag::log_tagged_fmt("analysis_session",
			"open_attach_session_load_in_flight pid=%u phase=%s", pid,
			loading_binary_overlay::current_phase_name());
		return false;
	}

	std::lock_guard<std::mutex> lk(state().mu);

	for (size_t i = 0; i < state().sessions.size(); ++i) {
		if (state().sessions[i]->attached_pid == pid) {
			if (static_cast<int>(i) == state().active_idx) {
				state().sessions[i]->last_active_steady_ms = now_steady_ms();
				return true;
			}
			int cur = state().active_idx;
			if (cur >= 0 && cur < static_cast<int>(state().sessions.size())) {
				auto& src = *state().sessions[cur];
				capture_live_into_session_locked(src);
				src.last_active_steady_ms = now_steady_ms();
			}
			auto& dst = *state().sessions[i];
			restore_session_into_live_locked(dst);
			dst.last_active_steady_ms = now_steady_ms();
			state().active_idx = static_cast<int>(i);
			return true;
		}
	}

	uint32_t prev_active = driver_bridge::attached_pid();
	bool attach_ok = false;
	if (prev_active == pid) {
		attach_ok = true;
	} else {
		if (prev_active != 0)
			stealth_engine::disable_for_detach(prev_active, "analysis_session.open_attach.replace");
		attach_ok = driver_bridge::attach(pid);
	}
	if (!attach_ok) {
		if (prev_active != 0 && driver_bridge::attached_pid() == prev_active)
			(void)stealth_engine::ensure_default_enabled(prev_active, "analysis_session.open_attach.restore_failed_switch");
		state().last_error = std::string("attach_failed: ") + driver_bridge::last_error();
		if (out_err) *out_err = state().last_error;
		diag::log_tagged_fmt("analysis_session",
			"open_attach_session pid=%u attach_failed err='%s'",
			pid, state().last_error.c_str());
		return false;
	}
	const bool stealth_ok = stealth_engine::ensure_default_enabled(pid, "analysis_session.open_attach");
	diag::log_tagged_fmt("analysis_session",
		"open_attach_session pid=%u attach_ok stealth_ok=%d name='%s'",
		pid, stealth_ok ? 1 : 0, driver_bridge::attached_process_name().c_str());

	int cur = state().active_idx;
	if (cur >= 0 && cur < static_cast<int>(state().sessions.size())) {
		auto& src = *state().sessions[cur];
		capture_live_into_session_locked(src);
		src.last_active_steady_ms = now_steady_ms();
	}

	g_disasm.file = DisasmFile{};
	function_index::attach_snapshot(nullptr);
	xref_index::attach_snapshot(nullptr);
	symbol_store::attach_snapshot(nullptr);
	decompiler_engine::attach_snapshot(nullptr);
	disasm_view::attach_snapshot(nullptr);
	types_hub_view::attach_snapshot(nullptr);
	crypto_scanner::attach_snapshot(nullptr);
	xref_db::attach_snapshot(nullptr);
	debugger_engine::clear_breakpoints_and_watches();

	auto sess = std::make_unique<analysis_session_t>();
	sess->id = make_session_id(++state().id_counter);
	sess->attached_pid = pid;
	std::string pname = driver_bridge::attached_process_name();
	sess->process_name = widen_utf8(pname);
	sess->filename = pname.empty() ? (std::string("PID ") + std::to_string(pid)) : pname;
	char path_buf[128];
	std::snprintf(path_buf, sizeof(path_buf), "live://pid/%u", pid);
	sess->path = path_buf;
	sess->last_active_steady_ms = now_steady_ms();
	state().sessions.push_back(std::move(sess));
	state().active_idx = static_cast<int>(state().sessions.size()) - 1;

	evict_lru_if_needed_locked();
	return true;
}

bool switch_session(size_t idx) {
	std::lock_guard<std::mutex> lk(state().mu);
	if (idx >= state().sessions.size()) {
		state().last_error = "idx_out_of_range";
		diag::log_tagged_fmt("analysis_session",
			"switch_session_idx_out_of_range requested_idx=%llu count=%llu",
			static_cast<unsigned long long>(idx),
			static_cast<unsigned long long>(state().sessions.size()));
		return false;
	}
	uint32_t dst_pid = state().sessions[idx]->attached_pid;
	int src_idx = state().active_idx;
	diag::log_tagged_fmt("analysis_session",
		"switch_session src=%lld dst=%llu live_pid=%u path='%s'",
		static_cast<long long>(src_idx),
		static_cast<unsigned long long>(idx),
		dst_pid,
		state().sessions[idx]->path.c_str());
	if (state().active_idx == static_cast<int>(idx)) {
		state().sessions[idx]->last_active_steady_ms = now_steady_ms();
		diag::log_tagged_fmt("analysis_session",
			"switch_session_noop idx=%llu phase=%s",
			static_cast<unsigned long long>(idx),
			loading_binary_overlay::current_phase_name());
		return true;
	}
	if (loading_binary_overlay::is_active() &&
		!loading_binary_overlay::is_waiting_for_user_decision()) {
		state().last_error = "load_in_flight";
		diag::log_tagged_fmt("analysis_session",
			"switch_session_refused_load_in_flight requested_idx=%llu phase=%s",
			static_cast<unsigned long long>(idx),
			loading_binary_overlay::current_phase_name());
		return false;
	}
	int cur = state().active_idx;
	if (cur >= 0 && cur < static_cast<int>(state().sessions.size())) {
		auto& src = *state().sessions[cur];
		capture_live_into_session_locked(src);
		src.last_active_steady_ms = now_steady_ms();
	}
	auto& dst = *state().sessions[idx];
	restore_session_into_live_locked(dst);
	dst.last_active_steady_ms = now_steady_ms();
	state().active_idx = static_cast<int>(idx);
	return true;
}

bool close_session(size_t idx) {
	if (loading_binary_overlay::is_active() &&
		!loading_binary_overlay::is_waiting_for_user_decision()) {
		state().last_error = "load_in_flight";
		diag::log_tagged_fmt("analysis_session",
			"close_session_refused_load_in_flight idx=%llu phase=%s",
			static_cast<unsigned long long>(idx),
			loading_binary_overlay::current_phase_name());
		return false;
	}
	std::lock_guard<std::mutex> lk(state().mu);
	if (idx >= state().sessions.size()) {
		state().last_error = "idx_out_of_range";
		diag::log_tagged_fmt("analysis_session",
			"close_session_idx_out_of_range idx=%llu count=%llu",
			static_cast<unsigned long long>(idx),
			static_cast<unsigned long long>(state().sessions.size()));
		return false;
	}

	int cur = state().active_idx;
	bool was_active = (cur == static_cast<int>(idx));
	uint32_t closed_pid = state().sessions[idx]->attached_pid;
	diag::log_tagged_fmt("analysis_session",
		"close_session idx=%llu attached_pid=%u was_active=%d",
		static_cast<unsigned long long>(idx), closed_pid, was_active ? 1 : 0);

	if (was_active) {
		if (state().sessions.size() == 1) {
			reset_live_to_default_locked();
			if (closed_pid != 0) {
				(void)driver_bridge::detach_one(closed_pid);
			}
			state().sessions.clear();
			state().active_idx = -1;
			return true;
		}
		size_t neighbor = (idx + 1 < state().sessions.size()) ? (idx + 1) : (idx - 1);
		auto& dst = *state().sessions[neighbor];
		restore_session_into_live_locked(dst);
		dst.last_active_steady_ms = now_steady_ms();
		if (closed_pid != 0 && closed_pid != dst.attached_pid) {
			(void)driver_bridge::detach_one(closed_pid);
		}
		state().sessions.erase(state().sessions.begin() + idx);
		if (neighbor > idx) {
			state().active_idx = static_cast<int>(neighbor - 1);
		} else {
			state().active_idx = static_cast<int>(neighbor);
		}
		return true;
	}

	if (closed_pid != 0) {
		(void)driver_bridge::detach_one(closed_pid);
	}
	state().sessions.erase(state().sessions.begin() + idx);
	if (cur > static_cast<int>(idx)) {
		state().active_idx = cur - 1;
	}
	return true;
}

size_t active_session_idx() {
	std::lock_guard<std::mutex> lk(state().mu);
	int a = state().active_idx;
	if (a < 0) return static_cast<size_t>(-1);
	return static_cast<size_t>(a);
}

size_t session_count() {
	std::lock_guard<std::mutex> lk(state().mu);
	return state().sessions.size();
}

const analysis_session_t* session_at(size_t idx) {
	std::lock_guard<std::mutex> lk(state().mu);
	if (idx >= state().sessions.size()) return nullptr;
	return state().sessions[idx].get();
}

bool find_session_by_path(const std::string& path, size_t* out_idx) {
	std::lock_guard<std::mutex> lk(state().mu);
	for (size_t i = 0; i < state().sessions.size(); ++i) {
		if (paths_equal(state().sessions[i]->path, path)) {
			if (out_idx) *out_idx = i;
			return true;
		}
	}
	return false;
}

bool find_session_by_pid(uint32_t pid, size_t* out_idx) {
	if (pid == 0) return false;
	std::lock_guard<std::mutex> lk(state().mu);
	for (size_t i = 0; i < state().sessions.size(); ++i) {
		if (state().sessions[i]->attached_pid == pid) {
			if (out_idx) *out_idx = i;
			return true;
		}
	}
	return false;
}

void prune_lru(size_t max_keep) {
	std::lock_guard<std::mutex> lk(state().mu);
	if (max_keep == 0) max_keep = 1;
	while (state().sessions.size() > max_keep) {
		size_t victim = 0;
		uint64_t oldest = UINT64_MAX;
		bool found = false;
		for (size_t i = 0; i < state().sessions.size(); ++i) {
			if (static_cast<int>(i) == state().active_idx) continue;
			if (state().sessions[i]->last_active_steady_ms < oldest) {
				oldest = state().sessions[i]->last_active_steady_ms;
				victim = i;
				found = true;
			}
		}
		if (!found) break;
		auto& vs = *state().sessions[victim];
		if (vs.attached_pid != 0) {
			(void)driver_bridge::detach_one(vs.attached_pid);
		}
		if (static_cast<int>(victim) < state().active_idx) {
			state().active_idx -= 1;
		}
		state().sessions.erase(state().sessions.begin() + victim);
	}
}

const char* last_error() {
	std::lock_guard<std::mutex> lk(state().mu);
	return state().last_error.c_str();
}

bool find_session_by_id(const std::string& session_id, size_t* out_idx) {
	if (session_id.empty()) return false;
	std::lock_guard<std::mutex> lk(state().mu);
	for (size_t i = 0; i < state().sessions.size(); ++i) {
		if (state().sessions[i]->id == session_id) {
			if (out_idx) *out_idx = i;
			return true;
		}
	}
	return false;
}

bool has_active_target() {
	if (driver_bridge::attached_pid() != 0) return true;
	if (g_disasm.file.loaded && !g_disasm.file.path.empty() && g_disasm.file.image_base != 0) return true;
	{
		std::lock_guard<std::mutex> lk(state().mu);
		if (!state().sessions.empty()) return true;
	}
	return false;
}

std::vector<session_summary_t> list_session_summaries() {
	std::vector<session_summary_t> out;
	std::lock_guard<std::mutex> lk(state().mu);
	out.reserve(state().sessions.size());
	for (size_t i = 0; i < state().sessions.size(); ++i) {
		const auto& s = *state().sessions[i];
		session_summary_t sum;
		sum.id = s.id;
		sum.kind = (s.attached_pid != 0)
			? session_kind_t::live_attach
			: session_kind_t::static_file;
		sum.path = s.path;
		sum.filename = s.filename;
		sum.pid = s.attached_pid;
		if (!s.process_name.empty()) {
			int needed = WideCharToMultiByte(CP_UTF8, 0, s.process_name.c_str(),
				static_cast<int>(s.process_name.size()), nullptr, 0, nullptr, nullptr);
			if (needed > 0) {
				std::string utf8(static_cast<size_t>(needed), '\0');
				WideCharToMultiByte(CP_UTF8, 0, s.process_name.c_str(),
					static_cast<int>(s.process_name.size()), utf8.data(), needed, nullptr, nullptr);
				sum.process_name = std::move(utf8);
			}
		}
		sum.is_active = (static_cast<int>(i) == state().active_idx);
		sum.is_alive = true;
		sum.last_active_steady_ms = s.last_active_steady_ms;
		out.push_back(std::move(sum));
	}
	return out;
}

session_summary_t summarize_session_at(size_t idx) {
	session_summary_t sum;
	std::lock_guard<std::mutex> lk(state().mu);
	if (idx >= state().sessions.size()) return sum;
	const auto& s = *state().sessions[idx];
	sum.id = s.id;
	sum.kind = (s.attached_pid != 0)
		? session_kind_t::live_attach
		: session_kind_t::static_file;
	sum.path = s.path;
	sum.filename = s.filename;
	sum.pid = s.attached_pid;
	if (!s.process_name.empty()) {
		int needed = WideCharToMultiByte(CP_UTF8, 0, s.process_name.c_str(),
			static_cast<int>(s.process_name.size()), nullptr, 0, nullptr, nullptr);
		if (needed > 0) {
			std::string utf8(static_cast<size_t>(needed), '\0');
			WideCharToMultiByte(CP_UTF8, 0, s.process_name.c_str(),
				static_cast<int>(s.process_name.size()), utf8.data(), needed, nullptr, nullptr);
			sum.process_name = std::move(utf8);
		}
	}
	sum.is_active = (static_cast<int>(idx) == state().active_idx);
	sum.is_alive = true;
	sum.last_active_steady_ms = s.last_active_steady_ms;
	return sum;
}

}
