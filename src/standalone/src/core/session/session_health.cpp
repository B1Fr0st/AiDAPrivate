#include "session_health.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <atomic>
#include <chrono>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <vector>

#include "analysis_session.hpp"
#include "../infra/work_queue.hpp"
#include "../../helpers/diag_log.hpp"

namespace session_health {

namespace {

struct state_t {
	std::atomic<bool>                    running{false};
	std::atomic<bool>                    stop_requested{false};
	std::mutex                           mu;
	std::unordered_map<uint32_t, bool>   alive_map;
};

state_t& state() {
	static state_t s;
	return s;
}

bool check_process_alive(uint32_t pid) {
	if (pid == 0) return false;
	HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
	if (!h) {
		DWORD err = GetLastError();
		if (err == ERROR_ACCESS_DENIED) {
			h = OpenProcess(SYNCHRONIZE, FALSE, pid);
			if (!h) return false;
		} else {
			return false;
		}
	}
	DWORD exit_code = 0;
	bool ok = GetExitCodeProcess(h, &exit_code) != FALSE;
	CloseHandle(h);
	if (!ok) return false;
	return exit_code == STILL_ACTIVE;
}

void watcher_loop() {
	diag::log_tagged("session_health", "thread_entry");
	auto& st = state();
	while (!st.stop_requested.load(std::memory_order_acquire)) {
		uint32_t alive_count = 0;
		uint32_t dead_count = 0;

		std::vector<uint32_t> pids;
		size_t count = analysis_session::session_count();
		pids.reserve(count);
		for (size_t i = 0; i < count; ++i) {
			const auto* sess = analysis_session::session_at(i);
			if (!sess) continue;
			if (sess->attached_pid != 0)
				pids.push_back(sess->attached_pid);
		}

		std::vector<uint32_t> newly_dead;
		newly_dead.reserve(pids.size());
		{
			std::lock_guard<std::mutex> lk(st.mu);
			for (uint32_t pid : pids) {
				bool alive_now = check_process_alive(pid);
				auto it = st.alive_map.find(pid);
				bool prev_alive = (it == st.alive_map.end()) ? true : it->second;
				st.alive_map[pid] = alive_now;
				if (alive_now) ++alive_count; else ++dead_count;
				if (prev_alive && !alive_now) {
					newly_dead.push_back(pid);
				}
			}

			for (auto it = st.alive_map.begin(); it != st.alive_map.end(); ) {
				bool present = false;
				for (uint32_t pid : pids) {
					if (pid == it->first) { present = true; break; }
				}
				if (!present) it = st.alive_map.erase(it);
				else ++it;
			}
		}

		diag::log_tagged_fmt("session_health",
			"tick alive=%u dead=%u tracked=%llu",
			alive_count, dead_count,
			static_cast<unsigned long long>(pids.size()));

		for (uint32_t dead_pid : newly_dead) {
			diag::log_tagged_fmt("session_health",
				"session_died pid=%u", dead_pid);
		}

		for (int slept = 0; slept < 20; ++slept) {
			if (st.stop_requested.load(std::memory_order_acquire))
				break;
			std::this_thread::sleep_for(std::chrono::milliseconds(100));
		}
	}
	st.running.store(false, std::memory_order_release);
	diag::log_tagged("session_health", "thread_exit");
}

}

bool initialize() {
	auto& st = state();
	bool expected = false;
	if (!st.running.compare_exchange_strong(expected, true)) {
		return true;
	}
	st.stop_requested.store(false, std::memory_order_release);
	bool posted = work_queue::post([]() {
		watcher_loop();
	});
	if (!posted) {
		st.running.store(false, std::memory_order_release);
		diag::log_tagged("session_health", "initialize_failed work_queue_post_failed");
		return false;
	}
	diag::log_tagged("session_health", "initialize_ok");
	return true;
}

void shutdown() {
	auto& st = state();
	st.stop_requested.store(true, std::memory_order_release);
}

bool is_alive(uint32_t pid) {
	if (pid == 0) return false;
	auto& st = state();
	std::lock_guard<std::mutex> lk(st.mu);
	auto it = st.alive_map.find(pid);
	if (it == st.alive_map.end()) return true;
	return it->second;
}

}
