#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdint>
#include <memory>
#include <mutex>
#include <random>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

#include "../mcp/downstream_producer_governor.hpp"

namespace command_sessions
{

struct command_session_t
{
	std::string id;
	std::string command;
	std::atomic<bool> alive{true};
	std::atomic<int64_t> exit_code{-1};
	std::atomic<bool> timed_out{false};
	std::mutex output_mutex;
	std::string stdout_buf;
	std::string stderr_buf;
	std::chrono::steady_clock::time_point started_at;
	std::chrono::steady_clock::time_point finished_at;
	PROCESS_INFORMATION process_info{};
	HANDLE stdout_read = nullptr;
	HANDLE stderr_read = nullptr;
	std::atomic<bool> reader_done{true};
	int timeout_ms = 0;
	std::uint64_t downstream_token{0};
	std::string principal_id;
	std::atomic<bool> downstream_released{false};

	command_session_t() = default;
	command_session_t(const command_session_t&) = delete;
	command_session_t& operator=(const command_session_t&) = delete;

	~command_session_t()
	{
		alive.store(false);
		while (!reader_done.load(std::memory_order_acquire))
			std::this_thread::sleep_for(std::chrono::milliseconds(1));
		if (stdout_read) { CloseHandle(stdout_read); stdout_read = nullptr; }
		if (stderr_read) { CloseHandle(stderr_read); stderr_read = nullptr; }
		if (process_info.hProcess) {
			DWORD code = 0;
			if (GetExitCodeProcess(process_info.hProcess, &code) && code == STILL_ACTIVE)
				TerminateProcess(process_info.hProcess, 1);
			CloseHandle(process_info.hProcess);
			process_info.hProcess = nullptr;
		}
		if (process_info.hThread) {
			CloseHandle(process_info.hThread);
			process_info.hThread = nullptr;
		}
		if (!downstream_released.exchange(true, std::memory_order_acq_rel)) {
			if (downstream_token != 0) {
				mcp_standalone::downstream::governor_t::instance().release(
					downstream_token, "session_destructor");
				diag::log_tagged_fmt("mcp_srv",
					"BACKGROUND-COMMAND-RELEASE token=%llu principal=%s reason=session_destructor",
					static_cast<unsigned long long>(downstream_token),
					principal_id.c_str());
			}
		}
	}
};

struct registry_t
{
	std::mutex mtx;
	std::unordered_map<std::string, std::unique_ptr<command_session_t>> sessions;
};

struct stats_t
{
	size_t total = 0;
	size_t running = 0;
	size_t finished = 0;
	size_t reader_active = 0;
	size_t reader_done = 0;
	size_t timed_out = 0;
	uint64_t oldest_running_ms = 0;
	uint64_t oldest_reader_active_ms = 0;
	bool registry_lock_busy = false;
	std::string active_summary;
	size_t downstream_active_background_commands = 0;
	size_t downstream_rejected_background_commands = 0;
	uint64_t downstream_oldest_active_ms = 0;
	bool downstream_registry_lock_busy = false;
};

inline registry_t& registry()
{
	static registry_t r;
	return r;
}

inline std::string generate_session_id()
{
	static std::atomic<uint64_t> counter{0};
	std::random_device rd;
	std::mt19937_64 rng(rd() ^ static_cast<uint64_t>(
		std::chrono::steady_clock::now().time_since_epoch().count()));
	uint64_t a = rng();
	uint64_t b = counter.fetch_add(1, std::memory_order_relaxed);
	char buf[33];
	std::snprintf(buf, sizeof(buf), "sess_%016llx%08x",
		static_cast<unsigned long long>(a),
		static_cast<unsigned int>(b & 0xFFFFFFFFu));
	return std::string(buf);
}

inline std::atomic<DWORD>& ui_thread_id_storage()
{
	static std::atomic<DWORD> tid{0};
	return tid;
}

inline void set_ui_thread_id(DWORD tid)
{
	ui_thread_id_storage().store(tid, std::memory_order_release);
}

inline DWORD get_ui_thread_id()
{
	return ui_thread_id_storage().load(std::memory_order_acquire);
}

inline mcp_standalone::downstream::admission_result_t
acquire_background_command_admission(const std::string& principal_id,
                                     const std::string& session_id,
                                     const std::string& command_label)
{
	using namespace mcp_standalone::downstream;
	const DWORD caller_tid = GetCurrentThreadId();
	const DWORD ui_tid = get_ui_thread_id();
	if (ui_tid != 0 && caller_tid == ui_tid) {
		diag::log_tagged_fmt("mcp_srv",
			"BACKGROUND-COMMAND-REJECT principal=%s session=%s command_label=%s "
			"reason=ui_thread_blocked caller_tid=%lu ui_tid=%lu",
			principal_id.c_str(), session_id.c_str(), command_label.c_str(),
			static_cast<unsigned long>(caller_tid),
			static_cast<unsigned long>(ui_tid));
		return admission_result_t::rejected_result(
			"ui_thread_blocked", "ui_thread_policy", "thread", 0, 0);
	}
	producer_identity_t identity;
	identity.kind = producer_kind_t::background_command;
	identity.principal_id = principal_id;
	identity.session_id = session_id;
	identity.command_label = command_label;
	auto result = governor_t::instance().try_admit(identity);
	if (result.admitted) {
		diag::log_tagged_fmt("mcp_srv",
			"BACKGROUND-COMMAND-ADMIT token=%llu principal=%s session=%s command_label=%s "
			"caller_tid=%lu",
			static_cast<unsigned long long>(result.admission_token),
			principal_id.c_str(), session_id.c_str(), command_label.c_str(),
			static_cast<unsigned long>(caller_tid));
	} else {
		diag::log_tagged_fmt("mcp_srv",
			"BACKGROUND-COMMAND-REJECT principal=%s session=%s command_label=%s "
			"reason=%s quota=%s scope=%s observed=%zu limit=%zu caller_tid=%lu",
			principal_id.c_str(), session_id.c_str(), command_label.c_str(),
			result.reason.c_str(), result.quota_name.c_str(),
			result.quota_scope.c_str(), result.observed, result.limit,
			static_cast<unsigned long>(caller_tid));
	}
	return result;
}

inline std::string background_command_rejection_json(
	const mcp_standalone::downstream::admission_result_t& result,
	const std::string& principal_id,
	const std::string& session_id,
	const std::string& command_label)
{
	using namespace mcp_standalone::downstream;
	producer_identity_t id;
	id.kind = producer_kind_t::background_command;
	id.principal_id = principal_id;
	id.session_id = session_id;
	id.command_label = command_label;
	return rejection_json(result, id).dump();
}

inline void release_downstream_token(command_session_t& sess, const char* reason)
{
	if (sess.downstream_released.exchange(true, std::memory_order_acq_rel))
		return;
	if (sess.downstream_token == 0)
		return;
	mcp_standalone::downstream::governor_t::instance().release(
		sess.downstream_token, reason);
	diag::log_tagged_fmt("mcp_srv",
		"BACKGROUND-COMMAND-RELEASE token=%llu principal=%s reason=%s",
		static_cast<unsigned long long>(sess.downstream_token),
		sess.principal_id.c_str(), reason ? reason : "unknown");
	sess.downstream_token = 0;
}

inline command_session_t* register_session(std::unique_ptr<command_session_t> sess)
{
	auto& reg = registry();
	std::lock_guard<std::mutex> lk(reg.mtx);
	std::string id = sess->id;
	command_session_t* raw = sess.get();
	reg.sessions[id] = std::move(sess);
	return raw;
}

inline command_session_t* register_session_with_admission(
	std::unique_ptr<command_session_t> sess,
	std::uint64_t admission_token,
	const std::string& principal_id)
{
	sess->downstream_token = admission_token;
	sess->principal_id = principal_id;
	return register_session(std::move(sess));
}

inline command_session_t* get_session(const std::string& id)
{
	auto& reg = registry();
	std::lock_guard<std::mutex> lk(reg.mtx);
	auto it = reg.sessions.find(id);
	if (it == reg.sessions.end()) return nullptr;
	return it->second.get();
}

template <typename F>
inline bool with_session(const std::string& id, F&& fn)
{
	auto& reg = registry();
	std::lock_guard<std::mutex> lk(reg.mtx);
	auto it = reg.sessions.find(id);
	if (it == reg.sessions.end()) return false;
	fn(*it->second);
	return true;
}

inline bool remove_session(const std::string& id)
{
	auto& reg = registry();
	std::unique_ptr<command_session_t> victim;
	{
		std::lock_guard<std::mutex> lk(reg.mtx);
		auto it = reg.sessions.find(id);
		if (it == reg.sessions.end()) return false;
		if (!it->second->reader_done.load(std::memory_order_acquire)) return false;
		victim = std::move(it->second);
		reg.sessions.erase(it);
	}
	release_downstream_token(*victim, "remove_session");
	victim.reset();
	return true;
}

inline std::vector<std::string> list_sessions()
{
	auto& reg = registry();
	std::lock_guard<std::mutex> lk(reg.mtx);
	std::vector<std::string> out;
	out.reserve(reg.sessions.size());
	for (const auto& kv : reg.sessions)
		out.push_back(kv.first);
	return out;
}

inline stats_t stats(size_t max_summary = 8)
{
	stats_t out;
	auto& reg = registry();
	std::unique_lock<std::mutex> lk(reg.mtx, std::try_to_lock);
	if (!lk.owns_lock()) {
		out.registry_lock_busy = true;
		return out;
	}
	const auto now = std::chrono::steady_clock::now();
	size_t summarized = 0;
	for (const auto& kv : reg.sessions) {
		const auto& sess = kv.second;
		if (!sess)
			continue;
		++out.total;
		const bool running = sess->alive.load(std::memory_order_acquire);
		const bool reader_done = sess->reader_done.load(std::memory_order_acquire);
		const bool timed_out = sess->timed_out.load(std::memory_order_acquire);
		if (running)
			++out.running;
		else
			++out.finished;
		if (reader_done)
			++out.reader_done;
		else
			++out.reader_active;
		if (timed_out)
			++out.timed_out;
		uint64_t age_ms = 0;
		if (sess->started_at.time_since_epoch().count() != 0 && now >= sess->started_at)
			age_ms = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(now - sess->started_at).count());
		if (running && out.oldest_running_ms < age_ms)
			out.oldest_running_ms = age_ms;
		if (!reader_done && out.oldest_reader_active_ms < age_ms)
			out.oldest_reader_active_ms = age_ms;
		if (summarized < max_summary && (running || !reader_done)) {
			char item[360] = {};
			std::snprintf(item, sizeof(item),
				"%s%s:pid=%lu:running=%d:reader_done=%d:timed_out=%d:age_ms=%llu:timeout_ms=%d",
				out.active_summary.empty() ? "" : ";",
				kv.first.c_str(),
				static_cast<unsigned long>(sess->process_info.dwProcessId),
				running ? 1 : 0,
				reader_done ? 1 : 0,
				timed_out ? 1 : 0,
				static_cast<unsigned long long>(age_ms),
				sess->timeout_ms);
			out.active_summary += item;
			++summarized;
		}
	}
	{
		auto snap = mcp_standalone::downstream::governor_t::instance().snapshot();
		const auto bg_it = snap.by_kind.find("background_command");
		if (bg_it != snap.by_kind.end()) {
			out.downstream_active_background_commands = bg_it->second.active;
			out.downstream_rejected_background_commands = bg_it->second.rejected;
			out.downstream_oldest_active_ms = bg_it->second.oldest_active_ms;
		}
		out.downstream_registry_lock_busy = snap.registry_lock_busy;
	}
	return out;
}

inline void prune_finished(size_t keep_max = 32)
{
	auto& reg = registry();
	std::vector<std::unique_ptr<command_session_t>> victims;
	{
		std::lock_guard<std::mutex> lk(reg.mtx);
		if (reg.sessions.size() <= keep_max) return;
		std::vector<std::pair<std::chrono::steady_clock::time_point, std::string>> finished;
		for (const auto& kv : reg.sessions) {
			if (!kv.second->alive.load(std::memory_order_acquire) &&
				kv.second->reader_done.load(std::memory_order_acquire))
				finished.emplace_back(kv.second->finished_at, kv.first);
		}
		std::sort(finished.begin(), finished.end(),
			[](const auto& a, const auto& b) { return a.first < b.first; });
		size_t to_remove = (reg.sessions.size() > keep_max)
			? (reg.sessions.size() - keep_max) : 0;
		for (size_t i = 0; i < finished.size() && i < to_remove; ++i) {
			auto it = reg.sessions.find(finished[i].second);
			if (it != reg.sessions.end()) {
				victims.push_back(std::move(it->second));
				reg.sessions.erase(it);
			}
		}
	}
	for (auto& v : victims)
		release_downstream_token(*v, "prune_finished");
}

inline size_t release_all_for_shutdown(const char* reason)
{
	auto& reg = registry();
	std::vector<std::pair<std::string, std::uint64_t>> to_release;
	{
		std::lock_guard<std::mutex> lk(reg.mtx);
		to_release.reserve(reg.sessions.size());
		for (const auto& kv : reg.sessions) {
			if (kv.second && !kv.second->downstream_released.load(std::memory_order_acquire) &&
				kv.second->downstream_token != 0)
				to_release.emplace_back(kv.first, kv.second->downstream_token);
		}
	}
	size_t released = 0;
	for (const auto& entry : to_release) {
		bool did_release = false;
		command_sessions::with_session(entry.first,
			[&](command_sessions::command_session_t& sess) {
				if (sess.downstream_token == entry.second)
					did_release = true;
			});
		if (did_release) {
			command_sessions::with_session(entry.first,
				[&](command_sessions::command_session_t& sess) {
					release_downstream_token(sess, reason);
				});
			++released;
		} else {
			mcp_standalone::downstream::governor_t::instance().release(
				entry.second, reason ? reason : "shutdown_orphaned");
			++released;
		}
	}
	if (released != 0)
		diag::log_tagged_fmt("mcp_srv",
			"BACKGROUND-COMMAND-SHUTDOWN-RELEASE count=%zu reason=%s",
			released, reason ? reason : "unknown");
	return released;
}

inline std::string admission_stats_json()
{
	using json = nlohmann::json;
	auto snap = mcp_standalone::downstream::governor_t::instance().snapshot();
	const auto& q = mcp_standalone::downstream::governor_t::instance().quotas();
	json out;
	out["producer_kind"] = "background_command";
	const auto bg_it = snap.by_kind.find("background_command");
	if (bg_it != snap.by_kind.end()) {
		out["active"] = bg_it->second.active;
		out["rejected"] = bg_it->second.rejected;
		out["released"] = bg_it->second.released;
		out["oldest_active_ms"] = bg_it->second.oldest_active_ms;
		out["total_admitted"] = bg_it->second.total_admitted;
		out["total_rejected"] = bg_it->second.total_rejected;
		out["total_released"] = bg_it->second.total_released;
	} else {
		out["active"] = 0;
		out["rejected"] = 0;
		out["released"] = 0;
		out["oldest_active_ms"] = 0;
		out["total_admitted"] = 0;
		out["total_rejected"] = 0;
		out["total_released"] = 0;
	}
	out["quota"]["global_active"] = q.global_active_background_commands;
	out["quota"]["per_principal_active"] = q.per_principal_active_background_commands;
	out["quota"]["queued"] = q.global_queued_background_commands;
	out["total_active_all_kinds"] = snap.total_active;
	out["shutdown_pending"] = snap.shutdown_pending;
	out["p0_reserve_available"] = snap.p0_reserve_available;
	out["p1_reserve_available"] = snap.p1_reserve_available;
	out["registry_lock_busy"] = snap.registry_lock_busy;
	json per_principal = json::array();
	for (const auto& kv : snap.active_per_principal)
		per_principal.push_back({{"principal", kv.first}, {"active", kv.second}});
	out["per_principal"] = per_principal;
	return out.dump();
}

}
