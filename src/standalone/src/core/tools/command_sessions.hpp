#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
#include <random>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

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
	std::thread reader_thread;
	int timeout_ms = 0;

	command_session_t() = default;
	command_session_t(const command_session_t&) = delete;
	command_session_t& operator=(const command_session_t&) = delete;

	~command_session_t()
	{
		if (reader_thread.joinable()) {
			alive.store(false);
			reader_thread.join();
		}
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
	}
};

struct registry_t
{
	std::mutex mtx;
	std::unordered_map<std::string, std::unique_ptr<command_session_t>> sessions;
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

inline command_session_t* register_session(std::unique_ptr<command_session_t> sess)
{
	auto& reg = registry();
	std::lock_guard<std::mutex> lk(reg.mtx);
	std::string id = sess->id;
	command_session_t* raw = sess.get();
	reg.sessions[id] = std::move(sess);
	return raw;
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
		victim = std::move(it->second);
		reg.sessions.erase(it);
	}
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

inline void prune_finished(size_t keep_max = 32)
{
	auto& reg = registry();
	std::vector<std::unique_ptr<command_session_t>> victims;
	{
		std::lock_guard<std::mutex> lk(reg.mtx);
		if (reg.sessions.size() <= keep_max) return;
		std::vector<std::pair<std::chrono::steady_clock::time_point, std::string>> finished;
		for (const auto& kv : reg.sessions) {
			if (!kv.second->alive.load())
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
}

}
