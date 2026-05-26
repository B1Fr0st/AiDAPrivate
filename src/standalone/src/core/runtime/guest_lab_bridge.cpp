#define WIN32_LEAN_AND_MEAN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include "guest_lab_bridge.hpp"
#include "../../helpers/diag_log.hpp"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <exception>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <string>
#include <thread>
#include <utility>

namespace fs = std::filesystem;

namespace guest_lab {
namespace {

std::mutex g_mtx;
active_session_t g_session;
std::atomic<uint64_t> g_request_seq{1};

std::string narrow_utf8(const std::wstring& text) {
	if (text.empty()) return {};
	int needed = WideCharToMultiByte(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
	if (needed <= 0) return {};
	std::string out(static_cast<size_t>(needed), '\0');
	WideCharToMultiByte(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), out.data(), needed, nullptr, nullptr);
	return out;
}

std::wstring widen_utf8(const std::string& text) {
	if (text.empty()) return {};
	int needed = MultiByteToWideChar(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), nullptr, 0);
	if (needed <= 0) return {};
	std::wstring out(static_cast<size_t>(needed), L'\0');
	MultiByteToWideChar(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), out.data(), needed);
	return out;
}

uint64_t now_ms() {
	return static_cast<uint64_t>(GetTickCount64());
}

bool write_text_file(const fs::path& path, const std::string& text) {
	std::ofstream ofs(path, std::ios::binary | std::ios::trunc);
	if (!ofs.is_open()) return false;
	ofs.write(text.data(), static_cast<std::streamsize>(text.size()));
	return ofs.good();
}

bool write_json_atomic(const fs::path& path, const nlohmann::json& value) {
	std::error_code ec;
	fs::create_directories(path.parent_path(), ec);
	const fs::path tmp = path.wstring() + L".tmp";
	if (!write_text_file(tmp, value.dump(2))) return false;
	fs::rename(tmp, path, ec);
	if (!ec) return true;
	ec.clear();
	fs::remove(path, ec);
	ec.clear();
	fs::rename(tmp, path, ec);
	return !ec;
}

bool read_json_limited(const fs::path& path, nlohmann::json& out, std::string* error_out) {
	std::error_code ec;
	uintmax_t size = fs::file_size(path, ec);
	if (ec) {
		if (error_out) *error_out = "response file is unavailable: " + ec.message();
		return false;
	}
	if (size > 10u * 1024u * 1024u) {
		if (error_out) *error_out = "guest response exceeded 10 MiB";
		return false;
	}
	std::ifstream ifs(path, std::ios::binary);
	if (!ifs.is_open()) {
		if (error_out) *error_out = "failed to open guest response";
		return false;
	}
	std::string text(static_cast<size_t>(size), '\0');
	if (size > 0) ifs.read(text.data(), static_cast<std::streamsize>(text.size()));
	try {
		out = nlohmann::json::parse(text);
		return true;
	} catch (const std::exception& e) {
		if (error_out) *error_out = std::string("failed to parse guest response: ") + e.what();
		return false;
	}
}

std::string make_request_id() {
	uint64_t seq = g_request_seq.fetch_add(1, std::memory_order_acq_rel);
	char buf[96];
	std::snprintf(buf, sizeof(buf), "%lu_%llu_%llu",
		static_cast<unsigned long>(GetCurrentProcessId()),
		static_cast<unsigned long long>(GetTickCount64()),
		static_cast<unsigned long long>(seq));
	return std::string(buf);
}

}

void activate(const std::wstring& session_dir, const std::wstring& sample_path) {
	std::lock_guard<std::mutex> lk(g_mtx);
	active_session_t next;
	next.active = true;
	next.session_dir = session_dir;
	next.bridge_dir = (fs::path(session_dir) / L"output").wstring();
	next.sample_path = sample_path;
	next.started_ms = now_ms();
	std::error_code ec;
	fs::create_directories(fs::path(next.bridge_dir) / L"requests", ec);
	ec.clear();
	fs::create_directories(fs::path(next.bridge_dir) / L"responses", ec);
	ec.clear();
	fs::create_directories(fs::path(next.bridge_dir) / L"artifacts", ec);
	g_session = std::move(next);
	diag::log_tagged_fmt("guest_lab",
		"activated session_dir='%s' bridge_dir='%s' sample='%s'",
		narrow_utf8(g_session.session_dir).c_str(),
		narrow_utf8(g_session.bridge_dir).c_str(),
		narrow_utf8(g_session.sample_path).c_str());
}

void deactivate() {
	std::lock_guard<std::mutex> lk(g_mtx);
	if (g_session.active) {
		diag::log_tagged_fmt("guest_lab",
			"deactivated session_dir='%s'",
			narrow_utf8(g_session.session_dir).c_str());
	}
	g_session = active_session_t{};
}

bool is_active() {
	std::lock_guard<std::mutex> lk(g_mtx);
	return g_session.active;
}

active_session_t current() {
	std::lock_guard<std::mutex> lk(g_mtx);
	return g_session;
}

nlohmann::json request(const std::string& command,
                       const nlohmann::json& params,
                       uint32_t timeout_ms,
                       std::string* error_out) {
	active_session_t session;
	{
		std::lock_guard<std::mutex> lk(g_mtx);
		session = g_session;
	}
	if (!session.active) {
		if (error_out) *error_out = "no active Windows Sandbox guest lab";
		return {};
	}
	if (timeout_ms == 0) timeout_ms = 5000;
	if (timeout_ms > 300000) timeout_ms = 300000;
	fs::path bridge = session.bridge_dir;
	fs::path requests = bridge / L"requests";
	fs::path responses = bridge / L"responses";
	std::error_code ec;
	fs::create_directories(requests, ec);
	ec.clear();
	fs::create_directories(responses, ec);
	std::string id = make_request_id();
	nlohmann::json req;
	req["id"] = id;
	req["command"] = command;
	req["params"] = params.is_null() ? nlohmann::json::object() : params;
	req["created_host_ms"] = now_ms();
	fs::path request_path = requests / (widen_utf8(id) + L".json");
	fs::path response_path = responses / (widen_utf8(id) + L".json");
	if (!write_json_atomic(request_path, req)) {
		if (error_out) *error_out = "failed to write guest request";
		return {};
	}
	diag::log_tagged_fmt("guest_lab",
		"request id='%s' command='%s' timeout_ms=%u",
		id.c_str(), command.c_str(), static_cast<unsigned>(timeout_ms));
	auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
	while (std::chrono::steady_clock::now() < deadline) {
		if (fs::exists(response_path, ec)) {
			nlohmann::json response;
			if (!read_json_limited(response_path, response, error_out)) return {};
			ec.clear();
			fs::remove(response_path, ec);
			bool ok = response.value("ok", false);
			if (!ok) {
				if (error_out) *error_out = response.value("error", std::string("guest command failed"));
				return response;
			}
			return response;
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(50));
	}
	if (error_out) *error_out = "guest agent timed out waiting for command: " + command;
	return {};
}

std::string artifact_host_path(const std::string& artifact_name) {
	if (artifact_name.empty()) return {};
	active_session_t session = current();
	if (!session.active) return {};
	fs::path artifact = fs::path(session.bridge_dir) / L"artifacts" / widen_utf8(artifact_name);
	return narrow_utf8(artifact.wstring());
}

}
