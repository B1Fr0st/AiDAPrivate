#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <tlhelp32.h>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <limits>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <type_traits>
#include <vector>

namespace fs = std::filesystem;
using json = nlohmann::json;

namespace {

struct handle_closer_t {
	void operator()(HANDLE h) const {
		if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h);
	}
};

using unique_handle_t = std::unique_ptr<std::remove_pointer_t<HANDLE>, handle_closer_t>;

unique_handle_t make_handle(HANDLE h) {
	return unique_handle_t((h && h != INVALID_HANDLE_VALUE) ? h : nullptr);
}

struct state_t {
	fs::path bridge_dir;
	fs::path requests_dir;
	fs::path responses_dir;
	fs::path artifacts_dir;
	std::wstring sample_path;
	std::wstring sample_args;
	HANDLE sample_process = nullptr;
	uint32_t sample_pid = 0;
	std::atomic<uint32_t> active_pid{0};
	std::atomic<bool> shutdown{false};
	std::string launch_error;
};

std::string wide_to_utf8(const std::wstring& text) {
	if (text.empty()) return {};
	int needed = WideCharToMultiByte(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
	if (needed <= 0) return {};
	std::string out(static_cast<size_t>(needed), '\0');
	WideCharToMultiByte(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), out.data(), needed, nullptr, nullptr);
	return out;
}

std::wstring utf8_to_wide(const std::string& text) {
	if (text.empty()) return {};
	int needed = MultiByteToWideChar(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), nullptr, 0);
	if (needed <= 0) return {};
	std::wstring out(static_cast<size_t>(needed), L'\0');
	MultiByteToWideChar(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), out.data(), needed);
	return out;
}

std::string lower_copy(std::string text) {
	std::transform(text.begin(), text.end(), text.begin(), [](unsigned char c) {
		return static_cast<char>(std::tolower(c));
	});
	return text;
}

std::string hex_u64(uint64_t value) {
	char buf[24];
	std::snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(value));
	return buf;
}

std::string win_error(DWORD err) {
	LPSTR buf = nullptr;
	DWORD n = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		nullptr, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), reinterpret_cast<LPSTR>(&buf), 0, nullptr);
	std::string out;
	if (n > 0 && buf) {
		while (n > 0 && (buf[n - 1] == '\r' || buf[n - 1] == '\n' || buf[n - 1] == '.' || buf[n - 1] == ' ')) buf[--n] = '\0';
		out.assign(buf, buf + n);
	} else {
		char tmp[64];
		std::snprintf(tmp, sizeof(tmp), "Win32 error %lu", static_cast<unsigned long>(err));
		out = tmp;
	}
	if (buf) LocalFree(buf);
	return out;
}

bool parse_u64(const json& value, uint64_t& out) {
	if (value.is_number_unsigned()) {
		out = value.get<uint64_t>();
		return true;
	}
	if (value.is_number_integer()) {
		int64_t v = value.get<int64_t>();
		if (v < 0) return false;
		out = static_cast<uint64_t>(v);
		return true;
	}
	if (value.is_string()) {
		try {
			std::string s = value.get<std::string>();
			size_t idx = 0;
			out = std::stoull(s, &idx, 0);
			return idx == s.size();
		} catch (...) {
			return false;
		}
	}
	return false;
}

uint32_t parse_pid_value(const json& value) {
	uint64_t v = 0;
	if (!parse_u64(value, v) || v == 0 || v > std::numeric_limits<uint32_t>::max()) return 0;
	return static_cast<uint32_t>(v);
}

uint32_t requested_pid(const json& params, const state_t& state) {
	if (params.contains("pid")) {
		uint32_t pid = parse_pid_value(params["pid"]);
		if (pid != 0) return pid;
	}
	return state.active_pid.load(std::memory_order_acquire);
}

bool write_text_file(const fs::path& path, const std::string& text) {
	std::ofstream ofs(path, std::ios::binary | std::ios::trunc);
	if (!ofs.is_open()) return false;
	ofs.write(text.data(), static_cast<std::streamsize>(text.size()));
	return ofs.good();
}

bool write_json_atomic(const fs::path& path, const json& value) {
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

std::optional<json> read_json_file(const fs::path& path, size_t max_bytes = 16u * 1024u * 1024u) {
	std::error_code ec;
	uintmax_t size = fs::file_size(path, ec);
	if (ec || size > max_bytes) return std::nullopt;
	std::ifstream ifs(path, std::ios::binary);
	if (!ifs.is_open()) return std::nullopt;
	std::string text(static_cast<size_t>(size), '\0');
	if (size > 0) ifs.read(text.data(), static_cast<std::streamsize>(text.size()));
	try {
		return json::parse(text);
	} catch (...) {
		return std::nullopt;
	}
}

std::wstring quote_command_arg(const std::wstring& arg) {
	if (arg.empty()) return L"\"\"";
	bool needs_quote = false;
	for (wchar_t c : arg) {
		if (c == L' ' || c == L'\t' || c == L'\n' || c == L'\v' || c == L'"') {
			needs_quote = true;
			break;
		}
	}
	if (!needs_quote) return arg;
	std::wstring out;
	out.push_back(L'"');
	size_t backslashes = 0;
	for (wchar_t c : arg) {
		if (c == L'\\') {
			++backslashes;
		} else if (c == L'"') {
			out.append(backslashes * 2 + 1, L'\\');
			out.push_back(c);
			backslashes = 0;
		} else {
			out.append(backslashes, L'\\');
			backslashes = 0;
			out.push_back(c);
		}
	}
	out.append(backslashes * 2, L'\\');
	out.push_back(L'"');
	return out;
}

bool process_alive(uint32_t pid, DWORD* exit_code_out = nullptr) {
	if (pid == 0) return false;
	auto h = make_handle(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
	if (!h) return false;
	DWORD code = 0;
	if (!GetExitCodeProcess(h.get(), &code)) return false;
	if (exit_code_out) *exit_code_out = code;
	return code == STILL_ACTIVE;
}

std::string process_path(uint32_t pid) {
	auto h = make_handle(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
	if (!h) return {};
	wchar_t buf[32768] = {};
	DWORD n = static_cast<DWORD>(_countof(buf));
	if (!QueryFullProcessImageNameW(h.get(), 0, buf, &n) || n == 0) return {};
	return wide_to_utf8(std::wstring(buf, buf + n));
}

json process_list(const std::string& filter) {
	std::string filter_lower = lower_copy(filter);
	json arr = json::array();
	auto snap = make_handle(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
	if (!snap) return arr;
	PROCESSENTRY32W pe{};
	pe.dwSize = sizeof(pe);
	if (!Process32FirstW(snap.get(), &pe)) return arr;
	do {
		std::string name = wide_to_utf8(pe.szExeFile);
		if (!filter_lower.empty() && lower_copy(name).find(filter_lower) == std::string::npos) continue;
		json item;
		item["pid"] = static_cast<uint32_t>(pe.th32ProcessID);
		item["parent_pid"] = static_cast<uint32_t>(pe.th32ParentProcessID);
		item["threads"] = static_cast<uint32_t>(pe.cntThreads);
		item["name"] = name;
		std::string path = process_path(pe.th32ProcessID);
		if (!path.empty()) item["path"] = path;
		arr.push_back(std::move(item));
	} while (Process32NextW(snap.get(), &pe));
	return arr;
}

uint32_t find_process_by_name(const std::string& name) {
	std::string target = lower_copy(name);
	auto snap = make_handle(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
	if (!snap) return 0;
	PROCESSENTRY32W pe{};
	pe.dwSize = sizeof(pe);
	if (!Process32FirstW(snap.get(), &pe)) return 0;
	do {
		std::string cur = lower_copy(wide_to_utf8(pe.szExeFile));
		if (cur == target) return pe.th32ProcessID;
	} while (Process32NextW(snap.get(), &pe));
	return 0;
}

std::string memory_state(uint32_t state) {
	switch (state) {
		case MEM_COMMIT: return "COMMIT";
		case MEM_RESERVE: return "RESERVE";
		case MEM_FREE: return "FREE";
		default: return hex_u64(state);
	}
}

std::string memory_type(uint32_t type) {
	switch (type) {
		case MEM_IMAGE: return "IMAGE";
		case MEM_MAPPED: return "MAPPED";
		case MEM_PRIVATE: return "PRIVATE";
		default: return type ? hex_u64(type) : "";
	}
}

std::string protect_string(uint32_t protect) {
	uint32_t base = protect & 0xFFu;
	std::string out;
	switch (base) {
		case PAGE_NOACCESS: out = "---"; break;
		case PAGE_READONLY: out = "R--"; break;
		case PAGE_READWRITE: out = "RW-"; break;
		case PAGE_WRITECOPY: out = "RWC"; break;
		case PAGE_EXECUTE: out = "--X"; break;
		case PAGE_EXECUTE_READ: out = "R-X"; break;
		case PAGE_EXECUTE_READWRITE: out = "RWX"; break;
		case PAGE_EXECUTE_WRITECOPY: out = "RWXC"; break;
		default: out = hex_u64(protect); break;
	}
	if (protect & PAGE_GUARD) out += "|GUARD";
	if (protect & PAGE_NOCACHE) out += "|NOCACHE";
	if (protect & PAGE_WRITECOMBINE) out += "|WRITECOMBINE";
	return out;
}

bool is_readable_page(uint32_t state, uint32_t protect) {
	if (state != MEM_COMMIT) return false;
	if (protect & PAGE_GUARD) return false;
	switch (protect & 0xFFu) {
		case PAGE_READONLY:
		case PAGE_READWRITE:
		case PAGE_WRITECOPY:
		case PAGE_EXECUTE_READ:
		case PAGE_EXECUTE_READWRITE:
		case PAGE_EXECUTE_WRITECOPY:
			return true;
		default:
			return false;
	}
}

json region_json(const MEMORY_BASIC_INFORMATION& mbi) {
	json o;
	o["base"] = hex_u64(reinterpret_cast<uint64_t>(mbi.BaseAddress));
	o["allocation_base"] = hex_u64(reinterpret_cast<uint64_t>(mbi.AllocationBase));
	o["size"] = static_cast<uint64_t>(mbi.RegionSize);
	o["state"] = memory_state(mbi.State);
	o["state_raw"] = static_cast<uint32_t>(mbi.State);
	o["protect"] = protect_string(mbi.Protect);
	o["protect_raw"] = static_cast<uint32_t>(mbi.Protect);
	o["allocation_protect"] = protect_string(mbi.AllocationProtect);
	o["allocation_protect_raw"] = static_cast<uint32_t>(mbi.AllocationProtect);
	o["type"] = memory_type(mbi.Type);
	o["type_raw"] = static_cast<uint32_t>(mbi.Type);
	o["readable"] = is_readable_page(mbi.State, mbi.Protect);
	return o;
}

unique_handle_t open_target_process(uint32_t pid, DWORD access, std::string& err) {
	auto h = make_handle(OpenProcess(access, FALSE, pid));
	if (!h) err = "OpenProcess failed: " + win_error(GetLastError());
	return h;
}

bool read_process_bytes(HANDLE process, uint64_t address, size_t size, std::vector<uint8_t>& out, std::string& err) {
	out.clear();
	if (size == 0) return true;
	if (size > 1024u * 1024u) {
		err = "read_memory is capped at 1048576 bytes per call";
		return false;
	}
	out.resize(size);
	SIZE_T got = 0;
	BOOL ok = ReadProcessMemory(process, reinterpret_cast<LPCVOID>(address), out.data(), out.size(), &got);
	if (!ok && got == 0) {
		err = "ReadProcessMemory failed: " + win_error(GetLastError());
		out.clear();
		return false;
	}
	out.resize(static_cast<size_t>(got));
	return true;
}

std::string bytes_to_hex(const std::vector<uint8_t>& bytes) {
	static constexpr char kHex[] = "0123456789ABCDEF";
	std::string out;
	out.resize(bytes.size() * 2);
	for (size_t i = 0; i < bytes.size(); ++i) {
		out[i * 2] = kHex[(bytes[i] >> 4) & 0xF];
		out[i * 2 + 1] = kHex[bytes[i] & 0xF];
	}
	return out;
}

std::string bytes_to_ascii(const std::vector<uint8_t>& bytes) {
	std::string out;
	out.reserve(bytes.size());
	for (uint8_t b : bytes) out.push_back((b >= 32 && b < 127) ? static_cast<char>(b) : '.');
	return out;
}

bool from_hex_digit(char c, uint8_t& out) {
	if (c >= '0' && c <= '9') {
		out = static_cast<uint8_t>(c - '0');
		return true;
	}
	if (c >= 'a' && c <= 'f') {
		out = static_cast<uint8_t>(c - 'a' + 10);
		return true;
	}
	if (c >= 'A' && c <= 'F') {
		out = static_cast<uint8_t>(c - 'A' + 10);
		return true;
	}
	return false;
}

bool parse_hex_pattern(const std::string& text, std::vector<int>& out, std::string& err) {
	out.clear();
	std::string compact;
	for (char c : text) {
		if (c == ' ' || c == '\t' || c == '\r' || c == '\n') continue;
		compact.push_back(c);
	}
	if (compact.empty() || compact.size() % 2 != 0) {
		err = "pattern must contain full hex bytes";
		return false;
	}
	for (size_t i = 0; i < compact.size(); i += 2) {
		if (compact[i] == '?' && compact[i + 1] == '?') {
			out.push_back(-1);
			continue;
		}
		uint8_t hi = 0, lo = 0;
		if (!from_hex_digit(compact[i], hi) || !from_hex_digit(compact[i + 1], lo)) {
			err = "pattern contains a non-hex byte";
			return false;
		}
		out.push_back(static_cast<int>((hi << 4) | lo));
	}
	if (out.empty()) {
		err = "pattern is empty";
		return false;
	}
	return true;
}

bool match_pattern_at(const std::vector<uint8_t>& data, size_t off, const std::vector<int>& pattern) {
	if (off + pattern.size() > data.size()) return false;
	for (size_t i = 0; i < pattern.size(); ++i) {
		if (pattern[i] >= 0 && data[off + i] != static_cast<uint8_t>(pattern[i])) return false;
	}
	return true;
}

json cmd_status(const state_t& state) {
	json out;
	out["agent_pid"] = static_cast<uint32_t>(GetCurrentProcessId());
	out["active_pid"] = state.active_pid.load(std::memory_order_acquire);
	out["sample_pid"] = state.sample_pid;
	out["sample_path"] = wide_to_utf8(state.sample_path);
	out["sample_args"] = wide_to_utf8(state.sample_args);
	out["bridge_dir"] = wide_to_utf8(state.bridge_dir.wstring());
	out["process_alive"] = process_alive(state.active_pid.load(std::memory_order_acquire));
	out["sample_alive"] = process_alive(state.sample_pid);
	if (!state.launch_error.empty()) out["launch_error"] = state.launch_error;
	if (state.sample_process) {
		DWORD code = 0;
		if (GetExitCodeProcess(state.sample_process, &code) && code != STILL_ACTIVE) out["sample_exit_code"] = code;
	}
	return out;
}

json cmd_list_processes(const json& params) {
	std::string filter = params.value("filter", std::string());
	json out;
	out["processes"] = process_list(filter);
	out["count"] = out["processes"].size();
	return out;
}

json cmd_attach(const json& params, state_t& state) {
	uint32_t pid = 0;
	if (params.contains("pid")) pid = parse_pid_value(params["pid"]);
	if (pid == 0 && params.contains("process") && params["process"].is_string()) pid = find_process_by_name(params["process"].get<std::string>());
	if (pid == 0) throw std::runtime_error("attach requires pid or process");
	if (!process_alive(pid)) throw std::runtime_error("target process is not alive or cannot be opened");
	state.active_pid.store(pid, std::memory_order_release);
	json out;
	out["attached_pid"] = pid;
	out["process_alive"] = true;
	out["path"] = process_path(pid);
	return out;
}

json cmd_detach(state_t& state) {
	state.active_pid.store(0, std::memory_order_release);
	return json{{"attached_pid", 0}};
}

json cmd_modules(const json& params, const state_t& state) {
	uint32_t pid = requested_pid(params, state);
	if (pid == 0) throw std::runtime_error("no active guest process; call guest_lab_attach first");
	auto snap = make_handle(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid));
	if (!snap) throw std::runtime_error("CreateToolhelp32Snapshot(modules) failed: " + win_error(GetLastError()));
	json arr = json::array();
	MODULEENTRY32W me{};
	me.dwSize = sizeof(me);
	if (Module32FirstW(snap.get(), &me)) {
		do {
			arr.push_back({
				{"base", hex_u64(reinterpret_cast<uint64_t>(me.modBaseAddr))},
				{"size", static_cast<uint32_t>(me.modBaseSize)},
				{"name", wide_to_utf8(me.szModule)},
				{"path", wide_to_utf8(me.szExePath)}
			});
		} while (Module32NextW(snap.get(), &me));
	}
	return json{{"pid", pid}, {"modules", arr}, {"count", arr.size()}};
}

json cmd_threads(const json& params, const state_t& state) {
	uint32_t pid = requested_pid(params, state);
	if (pid == 0) throw std::runtime_error("no active guest process; call guest_lab_attach first");
	auto snap = make_handle(CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0));
	if (!snap) throw std::runtime_error("CreateToolhelp32Snapshot(threads) failed: " + win_error(GetLastError()));
	json arr = json::array();
	THREADENTRY32 te{};
	te.dwSize = sizeof(te);
	if (Thread32First(snap.get(), &te)) {
		do {
			if (te.th32OwnerProcessID != pid) continue;
			arr.push_back({
				{"tid", static_cast<uint32_t>(te.th32ThreadID)},
				{"owner_pid", static_cast<uint32_t>(te.th32OwnerProcessID)},
				{"base_priority", te.tpBasePri},
				{"delta_priority", te.tpDeltaPri}
			});
		} while (Thread32Next(snap.get(), &te));
	}
	return json{{"pid", pid}, {"threads", arr}, {"count", arr.size()}};
}

json cmd_memory_map(const json& params, const state_t& state) {
	uint32_t pid = requested_pid(params, state);
	if (pid == 0) throw std::runtime_error("no active guest process; call guest_lab_attach first");
	std::string err;
	auto h = open_target_process(pid, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, err);
	if (!h) throw std::runtime_error(err);
	size_t limit = static_cast<size_t>(params.value("limit", 2048));
	if (limit == 0 || limit > 65536) limit = 2048;
	bool readable_only = params.value("readable_only", false);
	SYSTEM_INFO si{};
	GetNativeSystemInfo(&si);
	uintptr_t cur = 0;
	uintptr_t max_addr = reinterpret_cast<uintptr_t>(si.lpMaximumApplicationAddress);
	json arr = json::array();
	while (cur < max_addr && arr.size() < limit) {
		MEMORY_BASIC_INFORMATION mbi{};
		SIZE_T got = VirtualQueryEx(h.get(), reinterpret_cast<LPCVOID>(cur), &mbi, sizeof(mbi));
		if (got == 0) break;
		if (!readable_only || is_readable_page(mbi.State, mbi.Protect)) arr.push_back(region_json(mbi));
		uintptr_t base = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
		uintptr_t next = base + mbi.RegionSize;
		if (next <= cur) break;
		cur = next;
	}
	return json{{"pid", pid}, {"regions", arr}, {"count", arr.size()}, {"truncated", arr.size() >= limit}};
}

json cmd_query_memory(const json& params, const state_t& state) {
	uint32_t pid = requested_pid(params, state);
	if (pid == 0) throw std::runtime_error("no active guest process; call guest_lab_attach first");
	if (!params.contains("address")) throw std::runtime_error("address is required");
	uint64_t address = 0;
	if (!parse_u64(params["address"], address)) throw std::runtime_error("invalid address");
	std::string err;
	auto h = open_target_process(pid, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, err);
	if (!h) throw std::runtime_error(err);
	MEMORY_BASIC_INFORMATION mbi{};
	if (VirtualQueryEx(h.get(), reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi)) == 0) {
		throw std::runtime_error("VirtualQueryEx failed: " + win_error(GetLastError()));
	}
	return json{{"pid", pid}, {"region", region_json(mbi)}};
}

json cmd_read_memory(const json& params, const state_t& state) {
	uint32_t pid = requested_pid(params, state);
	if (pid == 0) throw std::runtime_error("no active guest process; call guest_lab_attach first");
	if (!params.contains("address")) throw std::runtime_error("address is required");
	uint64_t address = 0;
	if (!parse_u64(params["address"], address)) throw std::runtime_error("invalid address");
	size_t size = static_cast<size_t>(params.value("size", 256));
	std::string err;
	auto h = open_target_process(pid, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, err);
	if (!h) throw std::runtime_error(err);
	std::vector<uint8_t> bytes;
	if (!read_process_bytes(h.get(), address, size, bytes, err)) throw std::runtime_error(err);
	return json{{"pid", pid}, {"address", hex_u64(address)}, {"size", bytes.size()}, {"hex", bytes_to_hex(bytes)}, {"ascii", bytes_to_ascii(bytes)}};
}

json cmd_read_string(const json& params, const state_t& state) {
	uint32_t pid = requested_pid(params, state);
	if (pid == 0) throw std::runtime_error("no active guest process; call guest_lab_attach first");
	if (!params.contains("address")) throw std::runtime_error("address is required");
	uint64_t address = 0;
	if (!parse_u64(params["address"], address)) throw std::runtime_error("invalid address");
	size_t max_length = static_cast<size_t>(params.value("max_length", 256));
	if (max_length == 0 || max_length > 65536) max_length = 256;
	std::string encoding = lower_copy(params.value("encoding", std::string("ascii")));
	std::string err;
	auto h = open_target_process(pid, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, err);
	if (!h) throw std::runtime_error(err);
	size_t bytes_to_read = (encoding == "utf16" || encoding == "utf-16") ? max_length * sizeof(wchar_t) : max_length;
	std::vector<uint8_t> bytes;
	if (!read_process_bytes(h.get(), address, bytes_to_read, bytes, err)) throw std::runtime_error(err);
	std::string text;
	if (encoding == "utf16" || encoding == "utf-16") {
		std::wstring ws;
		for (size_t i = 0; i + 1 < bytes.size(); i += 2) {
			wchar_t ch = static_cast<wchar_t>(bytes[i] | (static_cast<uint16_t>(bytes[i + 1]) << 8));
			if (ch == 0) break;
			ws.push_back(ch);
		}
		text = wide_to_utf8(ws);
	} else {
		for (uint8_t b : bytes) {
			if (b == 0) break;
			text.push_back((b >= 32 && b < 127) ? static_cast<char>(b) : '.');
		}
	}
	return json{{"pid", pid}, {"address", hex_u64(address)}, {"encoding", encoding}, {"text", text}};
}

json cmd_dump_region(const json& params, const state_t& state) {
	uint32_t pid = requested_pid(params, state);
	if (pid == 0) throw std::runtime_error("no active guest process; call guest_lab_attach first");
	if (!params.contains("address")) throw std::runtime_error("address is required");
	uint64_t address = 0;
	if (!parse_u64(params["address"], address)) throw std::runtime_error("invalid address");
	size_t size = static_cast<size_t>(params.value("size", 0));
	std::string err;
	auto h = open_target_process(pid, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, err);
	if (!h) throw std::runtime_error(err);
	if (size == 0) {
		MEMORY_BASIC_INFORMATION mbi{};
		if (VirtualQueryEx(h.get(), reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi)) == 0) throw std::runtime_error("VirtualQueryEx failed: " + win_error(GetLastError()));
		uint64_t base = reinterpret_cast<uint64_t>(mbi.BaseAddress);
		uint64_t offset = address - base;
		size = static_cast<size_t>(std::min<uint64_t>(mbi.RegionSize - offset, 64ull * 1024ull * 1024ull));
	}
	if (size > 128u * 1024u * 1024u) throw std::runtime_error("dump_region is capped at 134217728 bytes");
	char name_buf[128];
	std::snprintf(name_buf, sizeof(name_buf), "dump_%u_%llX_%zu.bin", pid, static_cast<unsigned long long>(address), size);
	fs::path artifact = state.artifacts_dir / name_buf;
	std::ofstream ofs(artifact, std::ios::binary | std::ios::trunc);
	if (!ofs.is_open()) throw std::runtime_error("failed to open artifact file");
	const size_t chunk_size = 1024u * 1024u;
	std::vector<uint8_t> buf(chunk_size);
	size_t written = 0;
	while (written < size) {
		size_t want = std::min(chunk_size, size - written);
		SIZE_T got = 0;
		BOOL ok = ReadProcessMemory(h.get(), reinterpret_cast<LPCVOID>(address + written), buf.data(), want, &got);
		if (!ok && got == 0) break;
		ofs.write(reinterpret_cast<const char*>(buf.data()), static_cast<std::streamsize>(got));
		written += static_cast<size_t>(got);
		if (got < want) break;
	}
	return json{{"pid", pid}, {"address", hex_u64(address)}, {"requested_size", size}, {"bytes_written", written}, {"artifact_name", std::string(name_buf)}, {"artifact_path", wide_to_utf8(artifact.wstring())}};
}

json cmd_search_memory(const json& params, const state_t& state) {
	uint32_t pid = requested_pid(params, state);
	if (pid == 0) throw std::runtime_error("no active guest process; call guest_lab_attach first");
	std::string pattern_text = params.value("pattern", std::string());
	std::vector<int> pattern;
	std::string err;
	if (!parse_hex_pattern(pattern_text, pattern, err)) throw std::runtime_error(err);
	auto h = open_target_process(pid, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, err);
	if (!h) throw std::runtime_error(err);
	size_t max_hits = static_cast<size_t>(params.value("max_hits", 64));
	if (max_hits == 0 || max_hits > 4096) max_hits = 64;
	uint64_t max_scan = static_cast<uint64_t>(params.value("max_scan_mb", 256)) * 1024ull * 1024ull;
	if (max_scan == 0 || max_scan > 4ull * 1024ull * 1024ull * 1024ull) max_scan = 256ull * 1024ull * 1024ull;
	SYSTEM_INFO si{};
	GetNativeSystemInfo(&si);
	uintptr_t cur = 0;
	uintptr_t max_addr = reinterpret_cast<uintptr_t>(si.lpMaximumApplicationAddress);
	json hits = json::array();
	uint64_t scanned = 0;
	const size_t chunk_size = 1024u * 1024u;
	std::vector<uint8_t> chunk(chunk_size + pattern.size());
	while (cur < max_addr && hits.size() < max_hits && scanned < max_scan) {
		MEMORY_BASIC_INFORMATION mbi{};
		if (VirtualQueryEx(h.get(), reinterpret_cast<LPCVOID>(cur), &mbi, sizeof(mbi)) == 0) break;
		uintptr_t base = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
		uintptr_t next = base + mbi.RegionSize;
		if (is_readable_page(mbi.State, mbi.Protect)) {
			uint64_t region_pos = 0;
			uint64_t region_size = static_cast<uint64_t>(mbi.RegionSize);
			std::vector<uint8_t> carry;
			while (region_pos < region_size && hits.size() < max_hits && scanned < max_scan) {
				size_t want = static_cast<size_t>(std::min<uint64_t>(chunk_size, region_size - region_pos));
				SIZE_T got = 0;
				BOOL ok = ReadProcessMemory(h.get(), reinterpret_cast<LPCVOID>(base + region_pos), chunk.data(), want, &got);
				if (ok || got > 0) {
					std::vector<uint8_t> data;
					data.reserve(carry.size() + static_cast<size_t>(got));
					data.insert(data.end(), carry.begin(), carry.end());
					data.insert(data.end(), chunk.begin(), chunk.begin() + static_cast<ptrdiff_t>(got));
					uint64_t data_base = static_cast<uint64_t>(base) + region_pos - carry.size();
					for (size_t i = 0; i + pattern.size() <= data.size() && hits.size() < max_hits; ++i) {
						if (match_pattern_at(data, i, pattern)) hits.push_back(hex_u64(data_base + i));
					}
					carry.clear();
					if (pattern.size() > 1 && data.size() >= pattern.size() - 1) {
						carry.insert(carry.end(), data.end() - static_cast<ptrdiff_t>(pattern.size() - 1), data.end());
					}
					scanned += static_cast<uint64_t>(got);
				}
				region_pos += want;
			}
		}
		if (next <= cur) break;
		cur = next;
	}
	return json{{"pid", pid}, {"pattern", pattern_text}, {"hits", hits}, {"hit_count", hits.size()}, {"scanned_bytes", scanned}, {"truncated", hits.size() >= max_hits || scanned >= max_scan}};
}

json execute_command(const std::string& command, const json& params, state_t& state) {
	if (command == "status") return cmd_status(state);
	if (command == "list_processes") return cmd_list_processes(params);
	if (command == "attach") return cmd_attach(params, state);
	if (command == "detach") return cmd_detach(state);
	if (command == "modules") return cmd_modules(params, state);
	if (command == "threads") return cmd_threads(params, state);
	if (command == "memory_map") return cmd_memory_map(params, state);
	if (command == "query_memory") return cmd_query_memory(params, state);
	if (command == "read_memory") return cmd_read_memory(params, state);
	if (command == "read_string") return cmd_read_string(params, state);
	if (command == "dump_region") return cmd_dump_region(params, state);
	if (command == "search_memory") return cmd_search_memory(params, state);
	if (command == "shutdown") {
		state.shutdown.store(true, std::memory_order_release);
		return json{{"shutdown", true}};
	}
	throw std::runtime_error("unknown command: " + command);
}

bool load_launch_config(state_t& state) {
	fs::path cfg_path = state.bridge_dir / L"launch_config.json";
	auto cfg = read_json_file(cfg_path, 1024u * 1024u);
	if (!cfg) return false;
	if (cfg->contains("sample") && (*cfg)["sample"].is_string()) state.sample_path = utf8_to_wide((*cfg)["sample"].get<std::string>());
	if (cfg->contains("args") && (*cfg)["args"].is_string()) state.sample_args = utf8_to_wide((*cfg)["args"].get<std::string>());
	return true;
}

bool launch_sample(state_t& state) {
	if (state.sample_path.empty()) return true;
	std::wstring cmd = quote_command_arg(state.sample_path);
	if (!state.sample_args.empty()) {
		cmd.push_back(L' ');
		cmd += state.sample_args;
	}
	std::vector<wchar_t> cmd_buf(cmd.begin(), cmd.end());
	cmd_buf.push_back(L'\0');
	fs::path sample_path(state.sample_path);
	std::wstring cwd = sample_path.parent_path().wstring();
	STARTUPINFOW si{};
	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_SHOWNORMAL;
	PROCESS_INFORMATION pi{};
	BOOL ok = CreateProcessW(nullptr, cmd_buf.data(), nullptr, nullptr, FALSE, CREATE_NEW_CONSOLE | CREATE_DEFAULT_ERROR_MODE, nullptr, cwd.empty() ? nullptr : cwd.c_str(), &si, &pi);
	if (!ok) {
		state.launch_error = "CreateProcessW(sample) failed: " + win_error(GetLastError());
		return false;
	}
	state.sample_process = pi.hProcess;
	state.sample_pid = pi.dwProcessId;
	state.active_pid.store(pi.dwProcessId, std::memory_order_release);
	CloseHandle(pi.hThread);
	return true;
}

void write_status(const state_t& state) {
	(void)write_json_atomic(state.bridge_dir / L"status.json", cmd_status(state));
}

void process_request_file(const fs::path& path, state_t& state) {
	auto req = read_json_file(path);
	if (!req) return;
	std::wstring response_stem = path.stem().wstring();
	std::string id = req->value("id", wide_to_utf8(response_stem));
	std::string command = req->value("command", std::string());
	json params = req->value("params", json::object());
	json response;
	response["id"] = id;
	response["command"] = command;
	try {
		response["data"] = execute_command(command, params, state);
		response["ok"] = true;
	} catch (const std::exception& e) {
		response["ok"] = false;
		response["error"] = e.what();
	} catch (...) {
		response["ok"] = false;
		response["error"] = "unknown exception";
	}
	(void)write_json_atomic(state.responses_dir / (response_stem + L".json"), response);
	std::error_code ec;
	fs::remove(path, ec);
}

void service_requests(state_t& state) {
	std::error_code ec;
	fs::create_directories(state.requests_dir, ec);
	fs::create_directories(state.responses_dir, ec);
	fs::create_directories(state.artifacts_dir, ec);
	auto last_status = std::chrono::steady_clock::now() - std::chrono::seconds(2);
	while (!state.shutdown.load(std::memory_order_acquire)) {
		ec.clear();
		for (const auto& entry : fs::directory_iterator(state.requests_dir, ec)) {
			if (ec) break;
			if (!entry.is_regular_file(ec)) continue;
			if (entry.path().extension() != L".json") continue;
			process_request_file(entry.path(), state);
		}
		auto now = std::chrono::steady_clock::now();
		if (now - last_status >= std::chrono::seconds(1)) {
			write_status(state);
			last_status = now;
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(100));
	}
	write_status(state);
}

} 

int wmain(int argc, wchar_t** argv) {
	state_t state;
	for (int i = 1; i < argc; ++i) {
		std::wstring arg = argv[i] ? argv[i] : L"";
		if (arg == L"--bridge" && i + 1 < argc) {
			state.bridge_dir = argv[++i];
		} else if (arg == L"--sample" && i + 1 < argc) {
			state.sample_path = argv[++i];
		} else if (arg == L"--args" && i + 1 < argc) {
			state.sample_args = argv[++i];
		}
	}
	if (state.bridge_dir.empty()) return 2;
	state.requests_dir = state.bridge_dir / L"requests";
	state.responses_dir = state.bridge_dir / L"responses";
	state.artifacts_dir = state.bridge_dir / L"artifacts";
	std::error_code ec;
	fs::create_directories(state.requests_dir, ec);
	fs::create_directories(state.responses_dir, ec);
	fs::create_directories(state.artifacts_dir, ec);
	if (state.sample_path.empty()) load_launch_config(state);
	launch_sample(state);
	write_status(state);
	service_requests(state);
	if (state.sample_process) CloseHandle(state.sample_process);
	return 0;
}
