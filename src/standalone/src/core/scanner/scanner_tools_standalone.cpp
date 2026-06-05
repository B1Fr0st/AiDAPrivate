
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "standalone_compat.hpp"
#include "memory_scanner.hpp"
#include "obfuscation.hpp"
#include "struct_dissector.hpp"
#include "../debugger/page_guard_engine.hpp"
#include "../runtime/standalone_driver.hpp"
#include "../helpers/diag_log.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cinttypes>
#include <cctype>
#include <cmath>
#include <cstring>
#include <iomanip>
#include <limits>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

using json = nlohmann::json;
using tool_result_t = mcp_standalone::tool_result_t;

namespace scanner_tools {

namespace {

std::atomic<uint64_t> g_scan_session_counter{1};
std::atomic<uint64_t> g_active_scan_session{0};
std::atomic<uint64_t> g_pointer_session_counter{1};
std::atomic<uint64_t> g_active_pointer_session{0};

static uint64_t next_scan_session_id()
{
	return g_scan_session_counter.fetch_add(1, std::memory_order_relaxed);
}

static uint64_t next_pointer_session_id()
{
	return g_pointer_session_counter.fetch_add(1, std::memory_order_relaxed);
}

static std::string lower_copy(std::string s)
{
	for (char& c : s)
		c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
	return s;
}

}

static memory_scanner::value_type_t parse_value_type(const std::string& s) {
	const std::string v = lower_copy(s);
	if (v == "byte")    return memory_scanner::value_type_t::byte_val;
	if (v == "int16")   return memory_scanner::value_type_t::int16_val;
	if (v == "int32")   return memory_scanner::value_type_t::int32_val;
	if (v == "int" || v == "integer" || v == "exact" || v == "unknown") return memory_scanner::value_type_t::int32_val;
	if (v == "int64")   return memory_scanner::value_type_t::int64_val;
	if (v == "float")   return memory_scanner::value_type_t::float_val;
	if (v == "double")  return memory_scanner::value_type_t::double_val;
	if (v == "string" || v == "ascii" || v == "str")  return memory_scanner::value_type_t::string_ascii;
	if (v == "utf16" || v == "wstring") return memory_scanner::value_type_t::string_utf16;
	if (v == "aob" || v == "byte_array") return memory_scanner::value_type_t::byte_array;
	return memory_scanner::value_type_t::int32_val;
}

static memory_scanner::scan_mode_t parse_scan_mode(const std::string& s) {
	const std::string v = lower_copy(s);
	if (v == "exact")      return memory_scanner::scan_mode_t::exact;
	if (v == "bigger" || v == "greater" || v == "greater_than") return memory_scanner::scan_mode_t::bigger_than;
	if (v == "smaller" || v == "less" || v == "less_than") return memory_scanner::scan_mode_t::smaller_than;
	if (v == "between")    return memory_scanner::scan_mode_t::value_between;
	if (v == "changed")    return memory_scanner::scan_mode_t::changed;
	if (v == "unchanged")  return memory_scanner::scan_mode_t::unchanged;
	if (v == "increased")  return memory_scanner::scan_mode_t::increased;
	if (v == "decreased")  return memory_scanner::scan_mode_t::decreased;
	if (v == "unknown")    return memory_scanner::scan_mode_t::unknown_initial;
	return memory_scanner::scan_mode_t::exact;
}

static bool parse_u64_param(const json& params, const char* key, uint64_t& out) {
	if (!params.contains(key))
		return false;
	const auto& v = params[key];
	if (v.is_string()) {
		auto parsed = sa_parse_address(v.get<std::string>());
		if (!parsed) return false;
		out = *parsed;
		return true;
	}
	if (v.is_number_unsigned()) {
		out = v.get<uint64_t>();
		return true;
	}
	if (v.is_number_integer()) {
		int64_t s = v.get<int64_t>();
		if (s < 0) return false;
		out = static_cast<uint64_t>(s);
		return true;
	}
	return false;
}

static int clamp_wait_ms(const json& params, int default_ms) {
	int wait_ms = default_ms;
	if (params.contains("wait_ms") && params["wait_ms"].is_number_integer())
		wait_ms = params["wait_ms"].get<int>();
	else if (params.contains("timeout_ms") && params["timeout_ms"].is_number_integer())
		wait_ms = params["timeout_ms"].get<int>();
	if (wait_ms < 0) wait_ms = 0;
	if (wait_ms > 60000) wait_ms = 60000;
	return wait_ms;
}

static size_t limit_param(const json& params, size_t default_limit, size_t max_limit) {
	size_t limit = default_limit;
	if (params.contains("limit") && params["limit"].is_number_integer()) {
		const int requested = params["limit"].get<int>();
		if (requested > 0)
			limit = static_cast<size_t>(requested);
	}
	return std::min(limit, max_limit);
}

static bool wait_for_scan_idle(int wait_ms) {
	const int loops = (wait_ms + 49) / 50;
	for (int i = 0; i < loops; ++i) {
		if (!memory_scanner::g_state.scanning.load()) return true;
		Sleep(50);
	}
	return !memory_scanner::g_state.scanning.load();
}

static bool wait_for_pointer_idle(int wait_ms) {
	const int loops = (wait_ms + 49) / 50;
	for (int i = 0; i < loops; ++i) {
		if (!memory_scanner::g_state.pointer_scanning.load()) return true;
		Sleep(50);
	}
	return !memory_scanner::g_state.pointer_scanning.load();
}

static bool wait_budget_active(int wait_ms) {
	return wait_ms > 0;
}

static void apply_region_filter(memory_scanner::scan_config_t& cfg, const std::string& filter) {
	const std::string v = lower_copy(filter);
	if (v.empty() || v == "default" || v == "writable") {
		cfg.writable_only = true;
		cfg.executable_exclude = true;
		return;
	}
	if (v == "all") {
		cfg.writable_only = false;
		cfg.executable_exclude = false;
		return;
	}
	if (v == "non_executable" || v == "noexec") {
		cfg.writable_only = false;
		cfg.executable_exclude = true;
		return;
	}
	if (v == "executable" || v == "code") {
		cfg.writable_only = false;
		cfg.executable_exclude = false;
		return;
	}
}

static json scan_summary_json(size_t limit) {
	auto& st = memory_scanner::g_state;
	std::lock_guard<std::mutex> lk(st.results_mutex);
	json arr = json::array();
	const size_t n = std::min(st.results.size(), limit);
	for (size_t i = 0; i < n; ++i) {
		const auto& r = st.results[i];
		json obj;
		obj["address"] = sa_format_address(r.address);
		obj["value"] = memory_scanner::format_value(r.current_value, st.config.value_type);
		if (!r.previous_value.empty())
			obj["previous"] = memory_scanner::format_value(r.previous_value, st.config.value_type);
		if (!r.module_name.empty()) {
			obj["module"] = r.module_name;
			obj["module_offset"] = sa_format_address(r.module_offset);
			obj["module_expr"] = r.module_name + "+" + sa_format_address(r.module_offset);
		}
		arr.push_back(std::move(obj));
	}
	json result;
	result["session_id"] = g_active_scan_session.load(std::memory_order_relaxed);
	result["scanning"] = st.scanning.load();
	result["scan_count"] = st.scan_count;
	result["total_found"] = st.total_found;
	result["returned"] = arr.size();
	result["value_type"] = memory_scanner::value_type_name(st.config.value_type);
	result["results"] = std::move(arr);
	return result;
}

static json pointer_results_json(size_t limit) {
	auto& st = memory_scanner::g_state;
	std::lock_guard<std::mutex> lk(st.pointer_mutex);
	json arr = json::array();
	const size_t n = std::min(st.pointer_results.size(), limit);
	for (size_t i = 0; i < n; ++i) {
		const auto& p = st.pointer_results[i];
		json obj;
		obj["base"] = sa_format_address(p.base_address);
		if (!p.module_name.empty()) {
			obj["module"] = p.module_name;
			obj["module_offset"] = sa_format_address(p.module_offset);
			obj["module_expr"] = p.module_name + "+" + sa_format_address(p.module_offset);
		}
		json offsets = json::array();
		std::ostringstream expr;
		if (!p.module_name.empty())
			expr << p.module_name << "+" << sa_format_address(p.module_offset);
		else
			expr << sa_format_address(p.base_address);
		for (auto off : p.offsets) {
			offsets.push_back(off);
			if (off >= 0)
				expr << " -> +0x" << std::uppercase << std::hex << off << std::dec;
			else
				expr << " -> -0x" << std::uppercase << std::hex << -off << std::dec;
		}
		obj["offsets"] = std::move(offsets);
		obj["path"] = expr.str();
		arr.push_back(std::move(obj));
	}
	json result;
	result["session_id"] = g_active_pointer_session.load(std::memory_order_relaxed);
	result["scanning"] = st.pointer_scanning.load();
	result["completed"] = !st.pointer_scanning.load();
	result["progress"] = st.pointer_progress.load();
	result["total"] = st.pointer_results.size();
	result["returned"] = arr.size();
	result["results"] = std::move(arr);
	return result;
}

static uint32_t access_type_code(const std::string& type) {
	const std::string v = lower_copy(type);
	if (v == "execute" || v == "exec" || v == "x") return 8;
	if (v == "write" || v == "w") return 1;
	if (v == "read" || v == "r") return 0;
	return std::numeric_limits<uint32_t>::max();
}

static std::string access_type_name(uint32_t access_type) {
	if (access_type == 8) return "execute";
	if (access_type == 1) return "write";
	return "read";
}

static json captured_register_json(const page_guard_engine::pg_capture_t& meta) {
	json regs;
	regs["rip"] = sa_format_address(meta.rip);
	regs["rax"] = sa_format_address(meta.ctx_rax);
	regs["rcx"] = sa_format_address(meta.ctx_rcx);
	regs["rdx"] = sa_format_address(meta.ctx_rdx);
	regs["rbx"] = nullptr;
	regs["rsi"] = nullptr;
	regs["rdi"] = nullptr;
	regs["rbp"] = nullptr;
	regs["rsp"] = nullptr;
	regs["r8"] = nullptr;
	regs["r9"] = nullptr;
	regs["r10"] = nullptr;
	regs["r11"] = nullptr;
	regs["r12"] = nullptr;
	regs["r13"] = nullptr;
	regs["r14"] = nullptr;
	regs["r15"] = nullptr;
	regs["rflags"] = nullptr;
	return regs;
}

template <typename T>
static bool read_scalar_le(const std::vector<uint8_t>& bytes, T& out) {
	if (bytes.size() < sizeof(T))
		return false;
	std::memcpy(&out, bytes.data(), sizeof(T));
	return true;
}

static std::string bytes_hex_preview(const std::vector<uint8_t>& bytes, size_t limit = 64) {
	std::ostringstream os;
	const size_t n = std::min(bytes.size(), limit);
	for (size_t i = 0; i < n; ++i) {
		if (i != 0)
			os << ' ';
		os << std::uppercase << std::hex << std::setw(2) << std::setfill('0')
		   << static_cast<unsigned>(bytes[i]);
	}
	if (bytes.size() > n)
		os << " ...";
	return os.str();
}

static bool parse_field_type(const std::string& text, struct_dissector::field_type_t& out) {
	const std::string v = lower_copy(text);
	if (v == "int8" || v == "i8") { out = struct_dissector::field_type_t::int8; return true; }
	if (v == "uint8" || v == "u8" || v == "byte") { out = struct_dissector::field_type_t::uint8; return true; }
	if (v == "int16" || v == "i16" || v == "short") { out = struct_dissector::field_type_t::int16; return true; }
	if (v == "uint16" || v == "u16" || v == "ushort") { out = struct_dissector::field_type_t::uint16; return true; }
	if (v == "int32" || v == "i32" || v == "int" || v == "integer") { out = struct_dissector::field_type_t::int32; return true; }
	if (v == "uint32" || v == "u32" || v == "dword") { out = struct_dissector::field_type_t::uint32; return true; }
	if (v == "int64" || v == "i64" || v == "long") { out = struct_dissector::field_type_t::int64; return true; }
	if (v == "uint64" || v == "u64" || v == "qword") { out = struct_dissector::field_type_t::uint64; return true; }
	if (v == "float" || v == "float32" || v == "single") { out = struct_dissector::field_type_t::float32; return true; }
	if (v == "double" || v == "float64") { out = struct_dissector::field_type_t::float64; return true; }
	if (v == "pointer" || v == "ptr") { out = struct_dissector::field_type_t::pointer; return true; }
	if (v == "string" || v == "ascii" || v == "ascii_string") { out = struct_dissector::field_type_t::ascii_string; return true; }
	if (v == "utf16" || v == "utf16_string" || v == "wstring") { out = struct_dissector::field_type_t::utf16_string; return true; }
	if (v == "aob" || v == "byte_array" || v == "bytes") { out = struct_dissector::field_type_t::byte_array; return true; }
	if (v == "padding" || v == "pad") { out = struct_dissector::field_type_t::padding; return true; }
	return false;
}

static bool parse_address_param(const json& params, const char* key, uint64_t& out, std::string& error) {
	if (!params.contains(key)) {
		error = OBFSTR("'") + std::string(key) + OBFSTR("' is required.");
		return false;
	}
	const auto& v = params[key];
	if (v.is_string()) {
		auto parsed = sa_parse_address(v.get<std::string>());
		if (!parsed) {
			error = OBFSTR("Invalid ") + std::string(key) + OBFSTR(".");
			return false;
		}
		out = *parsed;
		return true;
	}
	if (v.is_number_unsigned()) {
		out = v.get<uint64_t>();
		return true;
	}
	if (v.is_number_integer()) {
		const int64_t s = v.get<int64_t>();
		if (s < 0) {
			error = OBFSTR("Negative ") + std::string(key) + OBFSTR(" is invalid.");
			return false;
		}
		out = static_cast<uint64_t>(s);
		return true;
	}
	error = OBFSTR("'") + std::string(key) + OBFSTR("' must be a string or integer address.");
	return false;
}

static bool parse_i64_param(const json& params, const char* key, int64_t& out, std::string& error) {
	if (!params.contains(key)) {
		error = OBFSTR("'") + std::string(key) + OBFSTR("' is required.");
		return false;
	}
	const auto& v = params[key];
	if (v.is_number_integer()) {
		out = v.get<int64_t>();
		return true;
	}
	if (v.is_number_unsigned()) {
		const uint64_t u = v.get<uint64_t>();
		if (u > static_cast<uint64_t>(std::numeric_limits<int64_t>::max())) {
			error = OBFSTR("'") + std::string(key) + OBFSTR("' is too large.");
			return false;
		}
		out = static_cast<int64_t>(u);
		return true;
	}
	if (v.is_string()) {
		try {
			const std::string s = v.get<std::string>();
			size_t idx = 0;
			out = std::stoll(s, &idx, 0);
			if (idx == s.size())
				return true;
		} catch (...) {
		}
	}
	error = OBFSTR("'") + std::string(key) + OBFSTR("' must be an integer offset.");
	return false;
}

static uint64_t add_signed_offset(uint64_t base, int64_t offset, bool& ok) {
	ok = false;
	if (offset < -0x10000000LL || offset > 0x10000000LL)
		return 0;
	if (offset >= 0) {
		const uint64_t delta = static_cast<uint64_t>(offset);
		if (base > std::numeric_limits<uint64_t>::max() - delta)
			return 0;
		ok = true;
		return base + delta;
	}
	const uint64_t delta = static_cast<uint64_t>(-offset);
	if (base < delta)
		return 0;
	ok = true;
	return base - delta;
}

static size_t field_effective_size(const struct_dissector::field_def_t& f) {
	size_t base = f.size != 0 ? static_cast<size_t>(f.size) : struct_dissector::field_type_size(f.type);
	if (base == 0)
		base = 1;
	const uint32_t count = f.array_count == 0 ? 1 : f.array_count;
	if (base > 0x10000 / count)
		return 0x10000;
	return base * count;
}

static size_t assertion_read_size(struct_dissector::field_type_t type, const json& params) {
	size_t size = struct_dissector::field_type_size(type);
	if (size == 0) {
		if (type == struct_dissector::field_type_t::ascii_string)
			size = 64;
		else if (type == struct_dissector::field_type_t::utf16_string)
			size = 128;
		else
			size = 32;
	}
	if (params.contains("size") && params["size"].is_number_integer()) {
		const int requested = params["size"].get<int>();
		if (requested > 0)
			size = static_cast<size_t>(requested);
	}
	if (size == 0)
		size = 1;
	if (size > 256)
		size = 256;
	return size;
}

static json field_value_json(const std::vector<uint8_t>& bytes, struct_dissector::field_type_t type) {
	json out;
	out["display"] = struct_dissector::format_field_value(bytes, type);
	out["raw_hex"] = bytes_hex_preview(bytes);
	switch (type) {
	case struct_dissector::field_type_t::int8: {
		int8_t v = 0;
		if (read_scalar_le(bytes, v)) out["signed"] = static_cast<int>(v);
		break;
	}
	case struct_dissector::field_type_t::uint8: {
		uint8_t v = 0;
		if (read_scalar_le(bytes, v)) { out["unsigned"] = static_cast<unsigned>(v); out["hex"] = sa_format_address(v); }
		break;
	}
	case struct_dissector::field_type_t::int16: {
		int16_t v = 0;
		if (read_scalar_le(bytes, v)) out["signed"] = static_cast<int>(v);
		break;
	}
	case struct_dissector::field_type_t::uint16: {
		uint16_t v = 0;
		if (read_scalar_le(bytes, v)) { out["unsigned"] = static_cast<unsigned>(v); out["hex"] = sa_format_address(v); }
		break;
	}
	case struct_dissector::field_type_t::int32: {
		int32_t v = 0;
		if (read_scalar_le(bytes, v)) { out["signed"] = v; out["hex"] = sa_format_address(static_cast<uint32_t>(v)); }
		break;
	}
	case struct_dissector::field_type_t::uint32: {
		uint32_t v = 0;
		if (read_scalar_le(bytes, v)) { out["unsigned"] = v; out["hex"] = sa_format_address(v); }
		break;
	}
	case struct_dissector::field_type_t::int64: {
		int64_t v = 0;
		if (read_scalar_le(bytes, v)) { out["signed"] = v; out["hex"] = sa_format_address(static_cast<uint64_t>(v)); }
		break;
	}
	case struct_dissector::field_type_t::uint64: {
		uint64_t v = 0;
		if (read_scalar_le(bytes, v)) { out["unsigned"] = std::to_string(v); out["hex"] = sa_format_address(v); }
		break;
	}
	case struct_dissector::field_type_t::float32: {
		float v = 0.f;
		if (read_scalar_le(bytes, v)) { out["number"] = v; out["finite"] = std::isfinite(v); }
		break;
	}
	case struct_dissector::field_type_t::float64: {
		double v = 0.0;
		if (read_scalar_le(bytes, v)) { out["number"] = v; out["finite"] = std::isfinite(v); }
		break;
	}
	case struct_dissector::field_type_t::pointer: {
		uint64_t v = 0;
		if (read_scalar_le(bytes, v)) out["pointer"] = sa_format_address(v);
		break;
	}
	default:
		break;
	}
	return out;
}

static bool numeric_sample_value(struct_dissector::field_type_t type, const std::vector<uint8_t>& bytes, double& value, bool& finite) {
	finite = true;
	switch (type) {
	case struct_dissector::field_type_t::int8: { int8_t v = 0; if (!read_scalar_le(bytes, v)) return false; value = static_cast<double>(v); return true; }
	case struct_dissector::field_type_t::uint8: { uint8_t v = 0; if (!read_scalar_le(bytes, v)) return false; value = static_cast<double>(v); return true; }
	case struct_dissector::field_type_t::int16: { int16_t v = 0; if (!read_scalar_le(bytes, v)) return false; value = static_cast<double>(v); return true; }
	case struct_dissector::field_type_t::uint16: { uint16_t v = 0; if (!read_scalar_le(bytes, v)) return false; value = static_cast<double>(v); return true; }
	case struct_dissector::field_type_t::int32: { int32_t v = 0; if (!read_scalar_le(bytes, v)) return false; value = static_cast<double>(v); return true; }
	case struct_dissector::field_type_t::uint32: { uint32_t v = 0; if (!read_scalar_le(bytes, v)) return false; value = static_cast<double>(v); return true; }
	case struct_dissector::field_type_t::int64: { int64_t v = 0; if (!read_scalar_le(bytes, v)) return false; value = static_cast<double>(v); return true; }
	case struct_dissector::field_type_t::uint64: { uint64_t v = 0; if (!read_scalar_le(bytes, v)) return false; value = static_cast<double>(v); return true; }
	case struct_dissector::field_type_t::float32: { float v = 0.f; if (!read_scalar_le(bytes, v)) return false; finite = std::isfinite(v); value = static_cast<double>(v); return true; }
	case struct_dissector::field_type_t::float64: { double v = 0.0; if (!read_scalar_le(bytes, v)) return false; finite = std::isfinite(v); value = v; return true; }
	default:
		return false;
	}
}

static bool pointer_sample_value(struct_dissector::field_type_t type, const std::vector<uint8_t>& bytes, uint64_t& value) {
	if (type != struct_dissector::field_type_t::pointer)
		return false;
	return read_scalar_le(bytes, value);
}

static bool string_sample_printable(struct_dissector::field_type_t type, const std::vector<uint8_t>& bytes) {
	if (type == struct_dissector::field_type_t::ascii_string) {
		for (uint8_t b : bytes) {
			if (b == 0)
				return true;
			if (b < 0x20 || b > 0x7E)
				return false;
		}
		return !bytes.empty();
	}
	if (type == struct_dissector::field_type_t::utf16_string) {
		for (size_t i = 0; i + 1 < bytes.size(); i += 2) {
			uint16_t ch = 0;
			std::memcpy(&ch, bytes.data() + i, sizeof(ch));
			if (ch == 0)
				return true;
			if (ch < 0x20 || ch > 0x7E)
				return false;
		}
		return bytes.size() >= 2;
	}
	return true;
}

static std::string available_struct_names_text() {
	std::lock_guard<std::mutex> lk(struct_dissector::g_state.mtx);
	std::ostringstream os;
	for (size_t i = 0; i < struct_dissector::g_state.structs.size(); ++i) {
		if (i != 0)
			os << ", ";
		os << struct_dissector::g_state.structs[i].name;
	}
	return os.str();
}

static json struct_snapshot_json(int struct_index, const struct_dissector::struct_def_t& sd,
	uint64_t base, const std::vector<uint8_t>& block) {
	json fields = json::array();
	for (size_t i = 0; i < sd.fields.size(); ++i) {
		const auto& f = sd.fields[i];
		const size_t fsz = field_effective_size(f);
		json item;
		item["index"] = i;
		item["name"] = f.name;
		item["offset"] = f.offset;
		if (base <= std::numeric_limits<uint64_t>::max() - f.offset)
			item["address"] = sa_format_address(base + f.offset);
		else
			item["address"] = nullptr;
		item["type"] = struct_dissector::field_type_name(f.type);
		item["declared_size"] = f.size;
		item["array_count"] = f.array_count;
		item["read_size"] = fsz;
		if (fsz == 0 || static_cast<uint64_t>(f.offset) + static_cast<uint64_t>(fsz) > block.size()) {
			item["read_ok"] = false;
			item["value"] = nullptr;
		} else {
			std::vector<uint8_t> bytes(block.begin() + f.offset, block.begin() + f.offset + fsz);
			const bool truncated = bytes.size() > 256;
			if (truncated)
				bytes.resize(256);
			item["read_ok"] = true;
			item["value_truncated"] = truncated;
			item["value"] = field_value_json(bytes, f.type);
		}
		fields.push_back(std::move(item));
	}
	json result;
	result["struct_index"] = struct_index;
	result["struct_name"] = sd.name;
	result["base_address"] = sa_format_address(base);
	result["total_size"] = sd.total_size;
	result["field_count"] = sd.fields.size();
	result["fields"] = std::move(fields);
	return result;
}

static std::string results_to_json(size_t limit = 100) {
	auto& st = memory_scanner::g_state;
	std::lock_guard<std::mutex> lk(st.results_mutex);

	json arr = json::array();
	size_t n = std::min(st.results.size(), limit);
	for (size_t i = 0; i < n; ++i) {
		auto& r = st.results[i];
		json obj;
		char buf[20];
		snprintf(buf, sizeof(buf), "0x%" PRIX64, r.address);
		obj["address"] = buf;
		obj["value"] = memory_scanner::format_value(r.current_value, st.config.value_type);
		if (!r.previous_value.empty())
			obj["previous"] = memory_scanner::format_value(r.previous_value, st.config.value_type);
		if (!r.module_name.empty()) {
			snprintf(buf, sizeof(buf), "0x%" PRIX64, r.module_offset);
			obj["module"] = r.module_name + "+" + buf;
		}
		arr.push_back(std::move(obj));
	}

	json result;
	result["total_found"] = st.total_found;
	result["showing"] = n;
	result["scan_count"] = st.scan_count;
	result["results"] = std::move(arr);
	return result.dump(2);
}


static tool_result_t handle_first_scan(const json& params) {
	memory_scanner::scan_config_t cfg;

	if (params.contains("value_type"))
		cfg.value_type = parse_value_type(params["value_type"].get<std::string>());
	if (params.contains("scan_mode"))
		cfg.scan_mode = parse_scan_mode(params["scan_mode"].get<std::string>());
	if (params.contains("value"))
		cfg.value_text = params["value"].get<std::string>();
	if (params.contains("value2"))
		cfg.value_text2 = params["value2"].get<std::string>();
	if (params.contains("hex") && params["hex"].is_boolean())
		cfg.hex_input = params["hex"].get<bool>();
	if (params.contains("writable_only") && params["writable_only"].is_boolean())
		cfg.writable_only = params["writable_only"].get<bool>();
	if (params.contains("executable_exclude") && params["executable_exclude"].is_boolean())
		cfg.executable_exclude = params["executable_exclude"].get<bool>();
	if (params.contains("alignment") && params["alignment"].is_number())
		cfg.alignment = params["alignment"].get<size_t>();
	parse_u64_param(params, "range_base", cfg.range_base);
	parse_u64_param(params, "range_size", cfg.range_size);

	diag::log_tagged_fmt("scanner", "mcp first_scan request value='%s' type=%s mode=%s writable_only=%d executable_exclude=%d alignment=%zu range=0x%llX+0x%llX",
		cfg.value_text.c_str(),
		memory_scanner::value_type_name(cfg.value_type),
		memory_scanner::scan_mode_name(cfg.scan_mode),
		cfg.writable_only ? 1 : 0,
		cfg.executable_exclude ? 1 : 0,
		cfg.alignment,
		static_cast<unsigned long long>(cfg.range_base),
		static_cast<unsigned long long>(cfg.range_size));

	if (!memory_scanner::first_scan(cfg)) {
		diag::log_tagged("scanner", "mcp first_scan refused");
		return tool_result_t::error(OBFSTR("Scanner busy or not attached to a process."));
	}


	for (int i = 0; i < 300; ++i) {
		if (!memory_scanner::g_state.scanning.load()) break;
		Sleep(100);
	}

	diag::log_tagged_fmt("scanner", "mcp first_scan completed total=%zu scan_count=%d scanning=%d",
		memory_scanner::g_state.total_found,
		memory_scanner::g_state.scan_count,
		memory_scanner::g_state.scanning.load() ? 1 : 0);
	if (memory_scanner::g_state.scanning.load()) {
		json result = scan_summary_json(100);
		result["completed"] = false;
		result["timeout_ms"] = 30000;
		diag::log_tagged_fmt("scanner", "mcp first_scan timeout total=%zu scan_count=%d",
			memory_scanner::g_state.total_found,
			memory_scanner::g_state.scan_count);
		memory_scanner::reset_scan();
		return tool_result_t{false, OBFSTR("Memory scan did not complete within the wait budget."), result};
	}

	return tool_result_t::ok(results_to_json());
}

static tool_result_t handle_next_scan(const json& params) {
	auto mode = memory_scanner::scan_mode_t::exact;
	std::string val, val2;

	if (params.contains("scan_mode"))
		mode = parse_scan_mode(params["scan_mode"].get<std::string>());
	if (params.contains("value"))
		val = params["value"].get<std::string>();
	if (params.contains("value2"))
		val2 = params["value2"].get<std::string>();

	diag::log_tagged_fmt("scanner", "mcp next_scan request mode=%s val='%s'",
		memory_scanner::scan_mode_name(mode), val.c_str());

	if (!memory_scanner::next_scan(mode, val, val2)) {
		diag::log_tagged("scanner", "mcp next_scan refused");
		return tool_result_t::error(OBFSTR("Scanner busy or no initial scan performed."));
	}

	for (int i = 0; i < 300; ++i) {
		if (!memory_scanner::g_state.scanning.load()) break;
		Sleep(100);
	}

	diag::log_tagged_fmt("scanner", "mcp next_scan completed total=%zu",
		memory_scanner::g_state.total_found);
	if (memory_scanner::g_state.scanning.load()) {
		json result = scan_summary_json(100);
		result["completed"] = false;
		result["timeout_ms"] = 30000;
		diag::log_tagged_fmt("scanner", "mcp next_scan timeout total=%zu scan_count=%d",
			memory_scanner::g_state.total_found,
			memory_scanner::g_state.scan_count);
		memory_scanner::reset_scan();
		return tool_result_t{false, OBFSTR("Next memory scan did not complete within the wait budget."), result};
	}

	return tool_result_t::ok(results_to_json());
}

static tool_result_t handle_get_results(const json& params) {
	size_t limit = 100;
	if (params.contains("limit") && params["limit"].is_number())
		limit = params["limit"].get<size_t>();
	diag::log_tagged_fmt("scanner", "mcp get_results limit=%zu total=%zu scan_count=%d scanning=%d",
		limit,
		memory_scanner::g_state.total_found,
		memory_scanner::g_state.scan_count,
		memory_scanner::g_state.scanning.load() ? 1 : 0);
	return tool_result_t::ok(results_to_json(limit));
}

static tool_result_t handle_scan_mem_start(const json& params) {
	memory_scanner::scan_config_t cfg;
	std::string value_type = params.value("value_type", "exact");
	if (value_type == "unknown") {
		cfg.scan_mode = memory_scanner::scan_mode_t::unknown_initial;
	} else {
		cfg.scan_mode = memory_scanner::scan_mode_t::exact;
	}
	cfg.value_type = parse_value_type(value_type);
	if (params.contains("value") && params["value"].is_string())
		cfg.value_text = params["value"].get<std::string>();
	if (cfg.scan_mode != memory_scanner::scan_mode_t::unknown_initial && cfg.value_text.empty())
		return tool_result_t::error(OBFSTR("'value' is required unless value_type is 'unknown'."));
	if (params.contains("alignment") && params["alignment"].is_number_integer()) {
		int alignment = params["alignment"].get<int>();
		if (alignment > 0)
			cfg.alignment = static_cast<size_t>(alignment);
	}
	if (params.contains("region_filter") && params["region_filter"].is_string())
		apply_region_filter(cfg, params["region_filter"].get<std::string>());
	if (params.contains("writable_only") && params["writable_only"].is_boolean())
		cfg.writable_only = params["writable_only"].get<bool>();
	if (params.contains("executable_exclude") && params["executable_exclude"].is_boolean())
		cfg.executable_exclude = params["executable_exclude"].get<bool>();
	if (params.contains("hex") && params["hex"].is_boolean())
		cfg.hex_input = params["hex"].get<bool>();
	parse_u64_param(params, "range_base", cfg.range_base);
	parse_u64_param(params, "range_size", cfg.range_size);

	const int wait_ms = clamp_wait_ms(params, 30000);
	const uint64_t session_id = next_scan_session_id();
	if (!memory_scanner::first_scan(cfg))
		return tool_result_t::error(OBFSTR("Scanner busy or not attached to a process."));
	g_active_scan_session.store(session_id, std::memory_order_relaxed);
	const bool completed = wait_for_scan_idle(wait_ms);
	json result = scan_summary_json(limit_param(params, 100, 10000));
	result["session_id"] = session_id;
	result["completed"] = completed;
	result["wait_ms"] = wait_ms;
	if (!completed && wait_budget_active(wait_ms)) {
		diag::log_tagged_fmt("scanner",
			"mcp scan_mem_start timeout session=%llu total=%zu scan_count=%d scanning=%d wait_ms=%d",
			static_cast<unsigned long long>(session_id),
			memory_scanner::g_state.total_found,
			memory_scanner::g_state.scan_count,
			memory_scanner::g_state.scanning.load() ? 1 : 0,
			wait_ms);
		memory_scanner::reset_scan();
		g_active_scan_session.store(0, std::memory_order_relaxed);
		result["scanning"] = false;
		return tool_result_t{false, OBFSTR("Memory scan did not complete within the wait budget."), result};
	}
	return tool_result_t::ok(result);
}

static tool_result_t handle_scan_mem_next(const json& params) {
	if (g_active_scan_session.load(std::memory_order_relaxed) == 0)
		return tool_result_t::error(OBFSTR("No active scan session. Call scan_mem_start first."));
	std::string compare_type = params.value("compare_type", "exact");
	auto mode = parse_scan_mode(compare_type);
	std::string value;
	if (params.contains("value") && params["value"].is_string())
		value = params["value"].get<std::string>();
	if ((mode == memory_scanner::scan_mode_t::exact ||
		 mode == memory_scanner::scan_mode_t::bigger_than ||
		 mode == memory_scanner::scan_mode_t::smaller_than ||
		 mode == memory_scanner::scan_mode_t::value_between) && value.empty())
		return tool_result_t::error(OBFSTR("'value' is required for this compare_type."));
	if (!memory_scanner::next_scan(mode, value))
		return tool_result_t::error(OBFSTR("Scanner busy or no initial scan performed."));
	const int wait_ms = clamp_wait_ms(params, 30000);
	const bool completed = wait_for_scan_idle(wait_ms);
	json result = scan_summary_json(limit_param(params, 100, 10000));
	result["completed"] = completed;
	result["compare_type"] = compare_type;
	result["wait_ms"] = wait_ms;
	if (!completed && wait_budget_active(wait_ms)) {
		diag::log_tagged_fmt("scanner",
			"mcp scan_mem_next timeout session=%llu total=%zu scan_count=%d scanning=%d wait_ms=%d",
			static_cast<unsigned long long>(g_active_scan_session.load(std::memory_order_relaxed)),
			memory_scanner::g_state.total_found,
			memory_scanner::g_state.scan_count,
			memory_scanner::g_state.scanning.load() ? 1 : 0,
			wait_ms);
		memory_scanner::reset_scan();
		g_active_scan_session.store(0, std::memory_order_relaxed);
		result["scanning"] = false;
		return tool_result_t{false, OBFSTR("Next memory scan did not complete within the wait budget."), result};
	}
	return tool_result_t::ok(result);
}

static tool_result_t handle_scan_mem_results(const json& params) {
	const size_t limit = limit_param(params, 100, 10000);
	const int wait_ms = clamp_wait_ms(params, params.value("wait", false) ? 30000 : 0);
	if (params.value("wait", false) || wait_ms > 0) {
		const bool completed = wait_for_scan_idle(wait_ms);
		if (!completed && wait_budget_active(wait_ms)) {
			json result = scan_summary_json(limit);
			result["completed"] = false;
			result["wait_ms"] = wait_ms;
			diag::log_tagged_fmt("scanner",
				"mcp scan_mem_results timeout session=%llu total=%zu scan_count=%d scanning=%d wait_ms=%d",
				static_cast<unsigned long long>(g_active_scan_session.load(std::memory_order_relaxed)),
				memory_scanner::g_state.total_found,
				memory_scanner::g_state.scan_count,
				memory_scanner::g_state.scanning.load() ? 1 : 0,
				wait_ms);
			return tool_result_t{false, OBFSTR("Memory scan did not complete within the wait budget."), result};
		}
	}
	return tool_result_t::ok(scan_summary_json(limit));
}

static tool_result_t handle_scan_mem_reset(const json&) {
	memory_scanner::reset_scan();
	g_active_scan_session.store(0, std::memory_order_relaxed);
	json result;
	result["reset"] = true;
	result["session_id"] = nullptr;
	return tool_result_t::ok(result);
}

static tool_result_t handle_reset_scan(const json&) {
	memory_scanner::reset_scan();
	return tool_result_t::ok(OBFSTR("Scanner reset."));
}

static tool_result_t handle_undo_scan(const json&) {
	memory_scanner::undo_scan();
	auto& st = memory_scanner::g_state;
	json result;
	result["total_found"] = st.total_found;
	result["scan_count"] = st.scan_count;
	return tool_result_t::ok(result.dump());
}

static tool_result_t handle_add_address(const json& params) {
	if (!params.contains("address"))
		return tool_result_t::error(OBFSTR("Missing 'address' parameter."));

	uint64_t addr = 0;
	auto& v = params["address"];
	if (v.is_string()) {
		auto parsed = sa_parse_address(v.get<std::string>());
		if (!parsed) return tool_result_t::error(OBFSTR("Invalid address format."));
		addr = *parsed;
	} else if (v.is_number()) {
		addr = v.get<uint64_t>();
	}

	std::string desc;
	if (params.contains("description"))
		desc = params["description"].get<std::string>();

	auto vtype = memory_scanner::value_type_t::int32_val;
	if (params.contains("value_type"))
		vtype = parse_value_type(params["value_type"].get<std::string>());

	memory_scanner::add_address(addr, desc, vtype);

	char buf[20];
	snprintf(buf, sizeof(buf), "0x%" PRIX64, addr);
	return tool_result_t::ok(std::string(OBFSTR("Address ")) + buf + OBFSTR(" added to list."));
}

static tool_result_t handle_remove_address(const json& params) {
	if (!params.contains("index"))
		return tool_result_t::error(OBFSTR("Missing 'index' parameter."));
	size_t idx = params["index"].get<size_t>();
	memory_scanner::remove_address(idx);
	return tool_result_t::ok(OBFSTR("Address removed."));
}

static tool_result_t handle_freeze_address(const json& params) {
	if (!params.contains("index"))
		return tool_result_t::error(OBFSTR("Missing 'index' parameter."));
	size_t idx = params["index"].get<size_t>();
	bool enable = true;
	if (params.contains("enable") && params["enable"].is_boolean())
		enable = params["enable"].get<bool>();
	memory_scanner::freeze_address(idx, enable);
	return tool_result_t::ok(enable ? OBFSTR("Address frozen.") : OBFSTR("Address unfrozen."));
}

static tool_result_t handle_read_value(const json& params) {
	if (!params.contains("address"))
		return tool_result_t::error(OBFSTR("Missing 'address' parameter."));

	uint64_t addr = 0;
	auto& v = params["address"];
	if (v.is_string()) {
		auto parsed = sa_parse_address(v.get<std::string>());
		if (!parsed) return tool_result_t::error(OBFSTR("Invalid address format."));
		addr = *parsed;
	} else if (v.is_number()) {
		addr = v.get<uint64_t>();
	}

	auto vtype = memory_scanner::value_type_t::int32_val;
	if (params.contains("value_type"))
		vtype = parse_value_type(params["value_type"].get<std::string>());

	std::string result = memory_scanner::read_value_string(addr, vtype);
	json obj;
	char abuf[20];
	snprintf(abuf, sizeof(abuf), "0x%" PRIX64, addr);
	obj["address"] = abuf;
	obj["type"] = memory_scanner::value_type_name(vtype);
	obj["value"] = result;
	return tool_result_t::ok(obj.dump(2));
}

static tool_result_t handle_get_address_list(const json&) {
	auto& st = memory_scanner::g_state;
	memory_scanner::refresh_address_list();

	std::lock_guard<std::mutex> lk(st.address_mutex);
	json arr = json::array();
	for (size_t i = 0; i < st.address_list.size(); ++i) {
		auto& e = st.address_list[i];
		json obj;
		obj["index"] = i;
		char buf[20];
		snprintf(buf, sizeof(buf), "0x%" PRIX64, e.address);
		obj["address"] = buf;
		obj["description"] = e.description;
		obj["type"] = memory_scanner::value_type_name(e.value_type);
		obj["frozen"] = e.frozen;
		obj["value"] = memory_scanner::format_value(e.last_value, e.value_type);
		arr.push_back(std::move(obj));
	}
	return tool_result_t::ok(arr.dump(2));
}

static tool_result_t handle_pointer_scan(const json& params) {
	if (!params.contains("address"))
		return tool_result_t::error(OBFSTR("Missing 'address' parameter."));

	uint64_t addr = 0;
	auto& v = params["address"];
	if (v.is_string()) {
		auto parsed = sa_parse_address(v.get<std::string>());
		if (!parsed) return tool_result_t::error(OBFSTR("Invalid address format."));
		addr = *parsed;
	} else if (v.is_number()) {
		addr = v.get<uint64_t>();
	}

	int max_depth = 4, max_offset = 0x1000;
	if (params.contains("max_depth") && params["max_depth"].is_number())
		max_depth = params["max_depth"].get<int>();
	if (params.contains("max_offset") && params["max_offset"].is_number())
		max_offset = params["max_offset"].get<int>();
	int timeout_ms = 4500;
	if (params.contains("timeout_ms") && params["timeout_ms"].is_number_integer()) {
		timeout_ms = params["timeout_ms"].get<int>();
		if (timeout_ms < 100) timeout_ms = 100;
		if (timeout_ms > 30000) timeout_ms = 30000;
	}
	uint64_t scan_base = 0;
	uint64_t scan_size = 0;
	parse_u64_param(params, "range_base", scan_base);
	parse_u64_param(params, "range_size", scan_size);
	const bool allow_partial = params.value("allow_partial", false);

	diag::log_tagged_fmt("scanner", "mcp pointer_scan request addr=0x%llX depth=%d offset=0x%X timeout_ms=%d range=0x%llX+0x%llX",
		static_cast<unsigned long long>(addr), max_depth, max_offset, timeout_ms,
		static_cast<unsigned long long>(scan_base),
		static_cast<unsigned long long>(scan_size));

	const bool started = memory_scanner::start_pointer_scan(addr, max_depth, max_offset, scan_base, scan_size);
	if (!started)
		return tool_result_t::error(OBFSTR("Pointer scan did not start. Ensure the driver is loaded and a process is attached."));
	{
		std::lock_guard<std::mutex> lk(memory_scanner::g_state.pointer_mutex);
		diag::log_tagged_fmt("scanner", "mcp pointer_scan started scanning=%d current_results=%zu",
			memory_scanner::g_state.pointer_scanning.load() ? 1 : 0,
			memory_scanner::g_state.pointer_results.size());
	}

	const int loops = (timeout_ms + 49) / 50;
	for (int i = 0; i < loops; ++i) {
		if (!memory_scanner::g_state.pointer_scanning.load()) break;
		if (i == 0 || ((i + 1) % 20) == 0) {
			std::lock_guard<std::mutex> lk(memory_scanner::g_state.pointer_mutex);
			diag::log_tagged_fmt("scanner", "mcp pointer_scan wait tick=%d/%d results=%zu",
				i + 1, loops, memory_scanner::g_state.pointer_results.size());
		}
		Sleep(50);
	}
	const bool timed_out = memory_scanner::g_state.pointer_scanning.load();
	if (timed_out) {
		{
			std::lock_guard<std::mutex> lk(memory_scanner::g_state.pointer_mutex);
			diag::log_tagged_fmt("scanner", "mcp pointer_scan timeout addr=0x%llX results_before_cancel=%zu allow_partial=%d",
				static_cast<unsigned long long>(addr),
				memory_scanner::g_state.pointer_results.size(),
				allow_partial ? 1 : 0);
		}
		memory_scanner::cancel_pointer_scan();
	}

	auto& st = memory_scanner::g_state;
	std::lock_guard<std::mutex> lk(st.pointer_mutex);
	diag::log_tagged_fmt("scanner", "mcp pointer_scan collect timed_out=%d total=%zu scanning=%d",
		timed_out ? 1 : 0, st.pointer_results.size(), st.pointer_scanning.load() ? 1 : 0);

	json arr = json::array();
	size_t n = std::min(st.pointer_results.size(), static_cast<size_t>(200));
	for (size_t i = 0; i < n; ++i) {
		auto& p = st.pointer_results[i];
		json obj;
		char buf[20];
		snprintf(buf, sizeof(buf), "0x%" PRIX64, p.base_address);
		obj["base"] = buf;
		if (!p.module_name.empty()) {
			snprintf(buf, sizeof(buf), "0x%" PRIX64, p.module_offset);
			obj["module"] = p.module_name + "+" + buf;
		}
		json offsets = json::array();
		for (auto off : p.offsets)
			offsets.push_back(off);
		obj["offsets"] = std::move(offsets);
		arr.push_back(std::move(obj));
	}

	json result;
	result["total"] = st.pointer_results.size();
	result["showing"] = n;
	result["timed_out"] = timed_out && !allow_partial;
	result["partial"] = timed_out;
	result["results"] = std::move(arr);
	if (timed_out && !allow_partial)
		return tool_result_t{false, OBFSTR("Pointer scan did not complete within the timeout."), result};
	return tool_result_t::ok(result.dump(2));
}

static tool_result_t handle_pointer_scan_start(const json& params) {
	if (!params.contains("target_address") || !params["target_address"].is_string())
		return tool_result_t::error(OBFSTR("'target_address' is required."));
	auto target = sa_parse_address(params["target_address"].get<std::string>());
	if (!target)
		return tool_result_t::error(OBFSTR("Invalid target_address."));
	if (memory_scanner::g_state.pointer_scanning.load())
		return tool_result_t::error(OBFSTR("Pointer scan already running."));
	int max_depth = params.value("max_depth", 4);
	int max_offset = params.value("max_offset", 0x1000);
	if (max_depth < 1) max_depth = 1;
	if (max_depth > 7) max_depth = 7;
	if (max_offset < 0x10) max_offset = 0x10;
	if (max_offset > 0x100000) max_offset = 0x100000;
	uint64_t scan_base = 0;
	uint64_t scan_size = 0;
	parse_u64_param(params, "range_base", scan_base);
	parse_u64_param(params, "range_size", scan_size);
	const uint64_t session_id = next_pointer_session_id();
	g_active_pointer_session.store(session_id, std::memory_order_relaxed);
	const bool started = memory_scanner::start_pointer_scan(*target, max_depth, max_offset, scan_base, scan_size);
	if (!started) {
		g_active_pointer_session.store(0, std::memory_order_relaxed);
		return tool_result_t::error(OBFSTR("Pointer scan did not start. Ensure the driver is loaded and a process is attached."));
	}
	json result;
	result["session_id"] = session_id;
	result["target_address"] = sa_format_address(*target);
	result["max_depth"] = max_depth;
	result["max_offset"] = max_offset;
	result["range_base"] = sa_format_address(scan_base);
	result["range_size"] = scan_size;
	result["scanning"] = memory_scanner::g_state.pointer_scanning.load();
	result["completed"] = !memory_scanner::g_state.pointer_scanning.load();
	{
		std::lock_guard<std::mutex> lk(memory_scanner::g_state.pointer_mutex);
		result["current_total"] = memory_scanner::g_state.pointer_results.size();
	}
	return tool_result_t::ok(result);
}

static tool_result_t handle_pointer_scan_results(const json& params) {
	const size_t limit = limit_param(params, 100, 10000);
	const int wait_ms = clamp_wait_ms(params, 30000);
	if (params.value("wait", false)) {
		const bool completed = wait_for_pointer_idle(wait_ms);
		if (!completed && wait_budget_active(wait_ms)) {
			json result = pointer_results_json(limit);
			result["wait_ms"] = wait_ms;
			diag::log_tagged_fmt("scanner",
				"mcp pointer_scan_results timeout session=%llu total=%zu scanning=%d wait_ms=%d",
				static_cast<unsigned long long>(g_active_pointer_session.load(std::memory_order_relaxed)),
				memory_scanner::g_state.pointer_results.size(),
				memory_scanner::g_state.pointer_scanning.load() ? 1 : 0,
				wait_ms);
			memory_scanner::cancel_pointer_scan();
			return tool_result_t{false, OBFSTR("Pointer scan did not complete within the wait budget."), result};
		}
	}
	return tool_result_t::ok(pointer_results_json(limit));
}

static tool_result_t handle_find_what_accesses(const json& params) {
	if (!params.contains("address") || !params["address"].is_string())
		return tool_result_t::error(OBFSTR("'address' is required."));
	auto address = sa_parse_address(params["address"].get<std::string>());
	if (!address)
		return tool_result_t::error(OBFSTR("Invalid address."));
	uint64_t size = 4;
	if (params.contains("size") && params["size"].is_number_integer()) {
		int requested = params["size"].get<int>();
		if (requested > 0)
			size = static_cast<uint64_t>(std::min(requested, 4096));
	}
	std::string type = "write";
	if (params.contains("type")) {
		if (!params["type"].is_string())
			return tool_result_t::error(OBFSTR("'type' must be read, write, or execute."));
		type = params["type"].get<std::string>();
	}
	const uint32_t wanted_access = access_type_code(type);
	if (wanted_access == std::numeric_limits<uint32_t>::max())
		return tool_result_t::error(OBFSTR("'type' must be read, write, or execute."));
	const int wait_ms = clamp_wait_ms(params, 5000);
	const size_t limit = limit_param(params, 32, 256);
	if (!driver_bridge::using_kernel_driver())
		return tool_result_t::error(OBFSTR("find_what_accesses requires the kernel driver page-guard backend."));
	const uint32_t pid = driver_bridge::attached_pid();
	if (pid == 0)
		return tool_result_t::error(OBFSTR("No attached process."));
	SYSTEM_INFO si{};
	GetSystemInfo(&si);
	const uint64_t page_size = si.dwPageSize ? si.dwPageSize : 0x1000;
	if (*address > std::numeric_limits<uint64_t>::max() - size)
		return tool_result_t::error(OBFSTR("Watched address range overflows."));
	const uint64_t end = *address + size;
	if (end > std::numeric_limits<uint64_t>::max() - (page_size - 1))
		return tool_result_t::error(OBFSTR("Guard address range overflows."));
	const uint64_t page_base = *address & ~(page_size - 1);
	const uint64_t guard_end = (end + page_size - 1) & ~(page_size - 1);
	const uint64_t guard_size = std::max<uint64_t>(page_size, guard_end - page_base);
	uint32_t sid = page_guard_engine::g_pg_engine.install(pid, page_base, guard_size);
	if (sid == 0)
		return tool_result_t::error(OBFSTR("Failed to install page-guard access monitor."));
	std::this_thread::sleep_for(std::chrono::milliseconds(wait_ms));
	auto captures = page_guard_engine::g_pg_engine.get_capture_records(sid);
	page_guard_engine::g_pg_engine.uninstall(sid);
	json arr = json::array();
	for (const auto& c : captures) {
		if (arr.size() >= limit)
			break;
		const auto& meta = c.metadata;
		if (wanted_access != meta.access_type)
			continue;
		if (meta.fault_addr < *address || meta.fault_addr >= end)
			continue;
		json o;
		o["fault_address"] = sa_format_address(meta.fault_addr);
		o["rip"] = sa_format_address(meta.rip);
		o["access_type"] = access_type_name(meta.access_type);
		o["exception_code"] = meta.exception_code;
		o["timestamp_tsc"] = meta.timestamp;
		o["registers"] = captured_register_json(meta);
		o["register_state_source"] = "veh_exception_context";
		o["register_state_complete"] = false;
		o["captured_registers"] = {"rip", "rax", "rcx", "rdx"};
		o["unavailable_registers"] = {"rbx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rflags"};
		page_guard_engine::serialize_payload_fields(o, c);
		arr.push_back(std::move(o));
	}
	json result;
	result["address"] = sa_format_address(*address);
	result["size"] = size;
	result["type"] = type;
	result["pid"] = pid;
	result["session_id"] = sid;
	result["guard_base"] = sa_format_address(page_base);
	result["guard_size"] = guard_size;
	result["wait_ms"] = wait_ms;
	result["total_captures"] = captures.size();
	result["returned"] = arr.size();
	result["accesses"] = std::move(arr);
	return tool_result_t::ok(result);
}

static tool_result_t handle_watch_memory_layout(const json& params) {
	uint64_t address = 0;
	std::string error;
	if (!parse_address_param(params, "address", address, error))
		return tool_result_t::error(error);
	std::string struct_name;
	if (params.contains("struct_name") && params["struct_name"].is_string())
		struct_name = params["struct_name"].get<std::string>();
	int refresh_rate_ms = 1000;
	if (params.contains("refresh_rate_ms") && params["refresh_rate_ms"].is_number_integer())
		refresh_rate_ms = params["refresh_rate_ms"].get<int>();
	if (refresh_rate_ms < 0) refresh_rate_ms = 0;
	if (refresh_rate_ms > 60000) refresh_rate_ms = 60000;

	int struct_index = -1;
	struct_dissector::struct_def_t sd;
	bool missing_struct = false;
	{
		std::lock_guard<std::mutex> lk(struct_dissector::g_state.mtx);
		if (!struct_name.empty()) {
			const std::string wanted = lower_copy(struct_name);
			for (size_t i = 0; i < struct_dissector::g_state.structs.size(); ++i) {
				if (lower_copy(struct_dissector::g_state.structs[i].name) == wanted) {
					struct_index = static_cast<int>(i);
					break;
				}
			}
		} else {
			struct_index = struct_dissector::g_state.active_struct;
		}
		if (struct_index < 0 || struct_index >= static_cast<int>(struct_dissector::g_state.structs.size())) {
			missing_struct = true;
		} else {
			struct_dissector::g_state.active_struct = struct_index;
			struct_dissector::g_state.base_address = address;
			struct_dissector::g_state.auto_refresh = refresh_rate_ms > 0;
			struct_dissector::g_state.refresh_interval = refresh_rate_ms > 0
				? static_cast<float>(refresh_rate_ms) / 1000.0f
				: 0.0f;
			sd = struct_dissector::g_state.structs[static_cast<size_t>(struct_index)];
		}
	}
	if (missing_struct)
		return tool_result_t::error(OBFSTR("Struct definition not found. Available structs: ") + available_struct_names_text());

	if (sd.total_size == 0)
		return tool_result_t::error(OBFSTR("Struct definition has no fields."));
	if (sd.total_size > 0x10000)
		return tool_result_t::error(OBFSTR("Struct snapshot size exceeds 65536 bytes."));
	if (address > std::numeric_limits<uint64_t>::max() - sd.total_size)
		return tool_result_t::error(OBFSTR("Struct snapshot address range overflows."));
	if (!driver_bridge::can_read_memory())
		return tool_result_t::error(OBFSTR("Memory reader is unavailable or no process is attached."));

	std::vector<uint8_t> block;
	if (!driver_bridge::read_memory(address, sd.total_size, block) || block.size() < sd.total_size)
		return tool_result_t::error(OBFSTR("Failed to read struct memory snapshot."));

	json result = struct_snapshot_json(struct_index, sd, address, block);
	result["watch_active"] = refresh_rate_ms > 0;
	result["refresh_rate_ms"] = refresh_rate_ms;
	result["snapshot_bytes"] = block.size();
	return tool_result_t::ok(result);
}

static tool_result_t handle_assert_memory_type(const json& params) {
	uint64_t address = 0;
	std::string error;
	if (!parse_address_param(params, "address", address, error))
		return tool_result_t::error(error);
	int64_t offset = 0;
	if (!parse_i64_param(params, "offset", offset, error))
		return tool_result_t::error(error);
	if (!params.contains("expected_type") || !params["expected_type"].is_string())
		return tool_result_t::error(OBFSTR("'expected_type' is required."));
	struct_dissector::field_type_t expected_type = struct_dissector::field_type_t::int32;
	const std::string expected_text = params["expected_type"].get<std::string>();
	if (!parse_field_type(expected_text, expected_type))
		return tool_result_t::error(OBFSTR("Unsupported expected_type: ") + expected_text);
	if (expected_type == struct_dissector::field_type_t::nested_struct)
		return tool_result_t::error(OBFSTR("nested_struct assertions require watch_memory_layout."));

	bool offset_ok = false;
	const uint64_t effective = add_signed_offset(address, offset, offset_ok);
	if (!offset_ok)
		return tool_result_t::error(OBFSTR("Effective address overflow or offset outside allowed range."));
	if (!driver_bridge::can_read_memory())
		return tool_result_t::error(OBFSTR("Memory reader is unavailable or no process is attached."));

	const size_t read_size = assertion_read_size(expected_type, params);
	if (effective > std::numeric_limits<uint64_t>::max() - read_size)
		return tool_result_t::error(OBFSTR("Assertion read address range overflows."));
	int duration_ms = 5000;
	if (params.contains("duration_ms") && params["duration_ms"].is_number_integer())
		duration_ms = params["duration_ms"].get<int>();
	if (duration_ms < 0) duration_ms = 0;
	if (duration_ms > 10000) duration_ms = 10000;
	int sample_interval_ms = 250;
	if (params.contains("sample_interval_ms") && params["sample_interval_ms"].is_number_integer())
		sample_interval_ms = params["sample_interval_ms"].get<int>();
	if (sample_interval_ms < 50) sample_interval_ms = 50;
	if (sample_interval_ms > 1000) sample_interval_ms = 1000;
	int sample_count = duration_ms == 0 ? 1 : (duration_ms / sample_interval_ms) + 1;
	if (sample_count < 1) sample_count = 1;
	if (sample_count > 64) sample_count = 64;

	bool has_bounds = false;
	double min_bound = 0.0;
	double max_bound = 0.0;
	std::string range_source;
	if (params.contains("min") && params["min"].is_number() && params.contains("max") && params["max"].is_number()) {
		min_bound = params["min"].get<double>();
		max_bound = params["max"].get<double>();
		has_bounds = min_bound <= max_bound;
		range_source = "provided";
	} else if (expected_type == struct_dissector::field_type_t::float32 ||
	           expected_type == struct_dissector::field_type_t::float64) {
		min_bound = -1000.0;
		max_bound = 1000.0;
		has_bounds = true;
		range_source = "default_float_sanity";
	}

	json samples = json::array();
	std::vector<uint8_t> previous;
	int read_errors = 0;
	int valid_samples = 0;
	int changed_count = 0;
	int nonfinite_count = 0;
	int out_of_range_count = 0;
	int pointer_invalid_count = 0;
	int string_invalid_count = 0;
	double observed_min = std::numeric_limits<double>::infinity();
	double observed_max = -std::numeric_limits<double>::infinity();

	for (int i = 0; i < sample_count; ++i) {
		std::vector<uint8_t> bytes;
		const bool read_ok = driver_bridge::read_memory(effective, read_size, bytes) && bytes.size() >= read_size;
		json sample;
		sample["index"] = i;
		sample["read_ok"] = read_ok;
		if (!read_ok) {
			++read_errors;
		} else {
			if (!previous.empty() && bytes != previous)
				++changed_count;
			previous = bytes;
			++valid_samples;
			sample["value"] = field_value_json(bytes, expected_type);
			double numeric = 0.0;
			bool finite = true;
			if (numeric_sample_value(expected_type, bytes, numeric, finite)) {
				if (!finite) {
					++nonfinite_count;
				} else {
					observed_min = std::min(observed_min, numeric);
					observed_max = std::max(observed_max, numeric);
					if (has_bounds && (numeric < min_bound || numeric > max_bound))
						++out_of_range_count;
				}
			}
			uint64_t pointer = 0;
			if (pointer_sample_value(expected_type, bytes, pointer)) {
				const bool plausible_pointer = pointer == 0 ||
					(pointer >= 0x10000ULL && pointer <= 0x00007FFFFFFFFFFFULL);
				if (!plausible_pointer)
					++pointer_invalid_count;
			}
			if (!string_sample_printable(expected_type, bytes))
				++string_invalid_count;
		}
		samples.push_back(std::move(sample));
		if (i + 1 < sample_count)
			Sleep(sample_interval_ms);
	}

	json result;
	result["address"] = sa_format_address(address);
	result["offset"] = offset;
	result["effective_address"] = sa_format_address(effective);
	result["expected_type"] = expected_text;
	result["normalized_type"] = struct_dissector::field_type_name(expected_type);
	result["read_size"] = read_size;
	result["duration_ms"] = duration_ms;
	result["sample_interval_ms"] = sample_interval_ms;
	result["sample_count"] = sample_count;
	result["valid_samples"] = valid_samples;
	result["read_errors"] = read_errors;
	result["changed_samples"] = changed_count;
	result["stable"] = changed_count == 0 && valid_samples > 0;
	result["nonfinite_count"] = nonfinite_count;
	result["out_of_range_count"] = out_of_range_count;
	result["pointer_invalid_count"] = pointer_invalid_count;
	result["string_invalid_count"] = string_invalid_count;
	result["plausible"] = valid_samples > 0 && read_errors == 0 && nonfinite_count == 0 &&
		out_of_range_count == 0 && pointer_invalid_count == 0 && string_invalid_count == 0;
	if (std::isfinite(observed_min) && std::isfinite(observed_max)) {
		result["observed_min"] = observed_min;
		result["observed_max"] = observed_max;
	}
	if (has_bounds) {
		result["range"] = {{"min", min_bound}, {"max", max_bound}, {"source", range_source}};
	}
	result["samples"] = std::move(samples);
	return tool_result_t::ok(result);
}

static tool_result_t handle_write_value(const json& params) {
	if (!params.contains("address") || !params.contains("value"))
		return tool_result_t::error(OBFSTR("Missing 'address' or 'value' parameter."));

	uint64_t addr = 0;
	auto& v = params["address"];
	if (v.is_string()) {
		auto parsed = sa_parse_address(v.get<std::string>());
		if (!parsed) return tool_result_t::error(OBFSTR("Invalid address format."));
		addr = *parsed;
	} else if (v.is_number()) {
		addr = v.get<uint64_t>();
	}

	auto vtype = memory_scanner::value_type_t::int32_val;
	if (params.contains("value_type"))
		vtype = parse_value_type(params["value_type"].get<std::string>());

	bool hex = false;
	if (params.contains("hex") && params["hex"].is_boolean())
		hex = params["hex"].get<bool>();

	std::string val_str = params["value"].get<std::string>();

	memory_scanner::write_value(addr, vtype, val_str, hex);

	return tool_result_t::ok(OBFSTR("Value written successfully."));
}


void register_scanner_tools(mcp_standalone::server_t& srv) {

	register_compat(srv, {OBFSTR("scan_mem_start"), OBFSTR("memory_scanner"),
		OBFSTR("Start a Cheat Engine-style stateful memory scan over the attached process. Use value_type exact, unknown, float, double, string, aob, byte, int16, int32, or int64. Returns a scan session id and initial matches."),
		{{OBFSTR("value_type"), OBFSTR("string"), OBFSTR("Scan type: exact, unknown, float, double, string, aob, byte, int16, int32, int64"), true},
		 {OBFSTR("value"), OBFSTR("string"), OBFSTR("Value to scan for; omit only for value_type=unknown"), false},
		 {OBFSTR("alignment"), OBFSTR("number"), OBFSTR("Scan alignment in bytes"), false},
		 {OBFSTR("region_filter"), OBFSTR("string"), OBFSTR("Region filter: writable, all, non_executable, executable"), false},
		 {OBFSTR("range_base"), OBFSTR("string"), OBFSTR("Optional scan range base address"), false},
		 {OBFSTR("range_size"), OBFSTR("number"), OBFSTR("Optional scan range size in bytes"), false},
		 {OBFSTR("hex"), OBFSTR("boolean"), OBFSTR("Interpret numeric value as hexadecimal"), false},
		 {OBFSTR("wait_ms"), OBFSTR("number"), OBFSTR("Maximum wait for initial scan completion, default 30000"), false},
		 {OBFSTR("limit"), OBFSTR("number"), OBFSTR("Maximum results to return, default 100"), false}},
		handle_scan_mem_start, false});

	register_compat(srv, {OBFSTR("scan_mem_next"), OBFSTR("memory_scanner"),
		OBFSTR("Refine the active stateful memory scan after the target value changes. compare_type supports increased, decreased, unchanged, changed, exact, bigger, smaller, and between."),
		{{OBFSTR("compare_type"), OBFSTR("string"), OBFSTR("Comparison: increased, decreased, unchanged, changed, exact, bigger, smaller, between"), true},
		 {OBFSTR("value"), OBFSTR("string"), OBFSTR("Value for exact/bigger/smaller/between comparisons"), false},
		 {OBFSTR("wait_ms"), OBFSTR("number"), OBFSTR("Maximum wait for refinement completion, default 30000"), false},
		 {OBFSTR("limit"), OBFSTR("number"), OBFSTR("Maximum results to return, default 100"), false}},
		handle_scan_mem_next, false});

	register_compat(srv, {OBFSTR("scan_mem_results"), OBFSTR("memory_scanner"),
		OBFSTR("Return current stateful memory scan matches with addresses, current values, previous values, and module offsets."),
		{{OBFSTR("limit"), OBFSTR("number"), OBFSTR("Maximum results to return, default 100"), false}},
		handle_scan_mem_results, true});

	register_compat(srv, {OBFSTR("scan_mem_reset"), OBFSTR("memory_scanner"),
		OBFSTR("Clear the active stateful memory scan session and free scan result memory."),
		{}, handle_scan_mem_reset, false});

	register_compat(srv, {OBFSTR("pointer_scan_start"), OBFSTR("memory_scanner"),
		OBFSTR("Start a background pointer scan for static module pointer paths to a dynamic address. Use pointer_scan_results to poll discovered paths."),
		{{OBFSTR("target_address"), OBFSTR("string"), OBFSTR("Dynamic address to resolve to stable pointer paths"), true},
		 {OBFSTR("max_depth"), OBFSTR("number"), OBFSTR("Maximum pointer chain depth, 1-7, default 4"), false},
		 {OBFSTR("max_offset"), OBFSTR("number"), OBFSTR("Maximum pointer offset, default 0x1000"), false},
		 {OBFSTR("range_base"), OBFSTR("string"), OBFSTR("Optional pointer-slot scan range base address"), false},
		 {OBFSTR("range_size"), OBFSTR("number"), OBFSTR("Optional pointer-slot scan range size in bytes"), false}},
		handle_pointer_scan_start, false});

	register_compat(srv, {OBFSTR("pointer_scan_results"), OBFSTR("memory_scanner"),
		OBFSTR("Return current pointer scan paths such as module+offset followed by pointer offsets. Can optionally wait for scan completion."),
		{{OBFSTR("limit"), OBFSTR("number"), OBFSTR("Maximum pointer paths to return, default 100"), false},
		 {OBFSTR("wait"), OBFSTR("boolean"), OBFSTR("Wait for pointer scan completion before returning"), false},
		 {OBFSTR("wait_ms"), OBFSTR("number"), OBFSTR("Maximum wait when wait=true, default 30000"), false}},
		handle_pointer_scan_results, true});

	register_compat(srv, {OBFSTR("find_what_accesses"), OBFSTR("memory_scanner"),
		OBFSTR("Monitor reads, writes, or executes touching an address range using the page-guard backend. Returns access RIP, fault address, captured exception-context registers, and payload preview."),
		{{OBFSTR("address"), OBFSTR("string"), OBFSTR("Address to monitor"), true},
		 {OBFSTR("size"), OBFSTR("number"), OBFSTR("Watched byte count, default 4, capped at 4096"), false},
		 {OBFSTR("type"), OBFSTR("string"), OBFSTR("Access type: read, write, execute"), false},
		 {OBFSTR("wait_ms"), OBFSTR("number"), OBFSTR("Capture duration, default 5000, capped at 60000"), false},
		 {OBFSTR("limit"), OBFSTR("number"), OBFSTR("Maximum matching access records to return, default 32"), false}},
		handle_find_what_accesses, false});

	register_compat(srv, {OBFSTR("watch_memory_layout"), OBFSTR("memory_scanner"),
		OBFSTR("Read a live ReClass-style snapshot at an address using an existing struct_dissector definition by name, or the active struct when struct_name is omitted."),
		{{OBFSTR("address"), OBFSTR("string"), OBFSTR("Base address to read"), true},
		 {OBFSTR("struct_name"), OBFSTR("string"), OBFSTR("Struct definition name; omit to use the active struct"), false},
		 {OBFSTR("refresh_rate_ms"), OBFSTR("number"), OBFSTR("Refresh interval to arm in the struct dissector state, 0 disables auto refresh"), false}},
		handle_watch_memory_layout, false});

	register_compat(srv, {OBFSTR("assert_memory_type"), OBFSTR("memory_scanner"),
		OBFSTR("Sample address+offset for a bounded interval and report whether the observed bytes plausibly match an expected scalar, pointer, string, or byte-array type."),
		{{OBFSTR("address"), OBFSTR("string"), OBFSTR("Base address to test"), true},
		 {OBFSTR("offset"), OBFSTR("number"), OBFSTR("Offset from base address"), true},
		 {OBFSTR("expected_type"), OBFSTR("string"), OBFSTR("Type: int8/uint8/int16/uint16/int32/uint32/int64/uint64/float/double/pointer/string/utf16/aob"), true},
		 {OBFSTR("duration_ms"), OBFSTR("number"), OBFSTR("Sampling duration, default 5000, capped at 10000"), false},
		 {OBFSTR("sample_interval_ms"), OBFSTR("number"), OBFSTR("Sampling interval, default 250, clamped 50-1000"), false},
		 {OBFSTR("size"), OBFSTR("number"), OBFSTR("Read size for string or byte-array assertions, capped at 256"), false},
		 {OBFSTR("min"), OBFSTR("number"), OBFSTR("Optional numeric lower bound"), false},
		 {OBFSTR("max"), OBFSTR("number"), OBFSTR("Optional numeric upper bound"), false}},
		handle_assert_memory_type, true});

	register_compat(srv, {OBFSTR("scanner_first_scan"), OBFSTR("memory_scanner"),
		OBFSTR("Start a new memory scan. Scans all committed memory of the attached process for values matching the criteria. Operates on the currently active binary_id session; pass binary_id explicitly in multi-target sessions."),
		{{OBFSTR("value"), OBFSTR("string"), OBFSTR("Value to search for"), true},
		 {OBFSTR("value_type"), OBFSTR("string"), OBFSTR("Type: byte/int16/int32/int64/float/double/ascii/utf16/aob"), false},
		 {OBFSTR("scan_mode"), OBFSTR("string"), OBFSTR("Mode: exact/bigger/smaller/between/unknown"), false},
		 {OBFSTR("value2"), OBFSTR("string"), OBFSTR("Second value for 'between' mode"), false},
		 {OBFSTR("hex"), OBFSTR("boolean"), OBFSTR("Interpret value as hexadecimal"), false},
		 {OBFSTR("writable_only"), OBFSTR("boolean"), OBFSTR("Only scan writable pages (default true)"), false},
		 {OBFSTR("executable_exclude"), OBFSTR("boolean"), OBFSTR("Exclude executable pages (default true)"), false},
		 {OBFSTR("alignment"), OBFSTR("number"), OBFSTR("Scan alignment in bytes (default: type size)"), false},
		 {OBFSTR("range_base"), OBFSTR("string"), OBFSTR("Optional scan range base address"), false},
		 {OBFSTR("range_size"), OBFSTR("number"), OBFSTR("Optional scan range size in bytes"), false}},
		handle_first_scan, false});

	register_compat(srv, {OBFSTR("scanner_next_scan"), OBFSTR("memory_scanner"),
		OBFSTR("Refine previous scan results by applying a new comparison. Narrows down results from the last scan."),
		{{OBFSTR("scan_mode"), OBFSTR("string"), OBFSTR("Mode: exact/bigger/smaller/between/changed/unchanged/increased/decreased"), true},
		 {OBFSTR("value"), OBFSTR("string"), OBFSTR("Value for comparison (not needed for changed/unchanged/increased/decreased)"), false},
		 {OBFSTR("value2"), OBFSTR("string"), OBFSTR("Second value for 'between' mode"), false}},
		handle_next_scan, false});

	register_compat(srv, {OBFSTR("scanner_get_results"), OBFSTR("memory_scanner"),
		OBFSTR("Get current scan results. Returns addresses, values, and module info."),
		{{OBFSTR("limit"), OBFSTR("number"), OBFSTR("Maximum results to return (default 100)"), false}},
		handle_get_results, true});

	register_compat(srv, {OBFSTR("scanner_reset"), OBFSTR("memory_scanner"),
		OBFSTR("Reset the scanner, clearing all results and scan history."),
		{}, handle_reset_scan, false});

	register_compat(srv, {OBFSTR("scanner_undo"), OBFSTR("memory_scanner"),
		OBFSTR("Undo the last scan refinement, restoring previous results."),
		{}, handle_undo_scan, false});

	register_compat(srv, {OBFSTR("scanner_add_address"), OBFSTR("memory_scanner"),
		OBFSTR("Add an address to the watch/address list for monitoring."),
		{{OBFSTR("address"), OBFSTR("string"), OBFSTR("Memory address (hex)"), true},
		 {OBFSTR("description"), OBFSTR("string"), OBFSTR("Description label"), false},
		 {OBFSTR("value_type"), OBFSTR("string"), OBFSTR("Type: byte/int16/int32/int64/float/double/ascii/utf16"), false}},
		handle_add_address, false});

	register_compat(srv, {OBFSTR("scanner_remove_address"), OBFSTR("memory_scanner"),
		OBFSTR("Remove an address from the watch list by index."),
		{{OBFSTR("index"), OBFSTR("number"), OBFSTR("Index in the address list"), true}},
		handle_remove_address, false});

	register_compat(srv, {OBFSTR("scanner_freeze_address"), OBFSTR("memory_scanner"),
		OBFSTR("Freeze or unfreeze an address to keep its value constant."),
		{{OBFSTR("index"), OBFSTR("number"), OBFSTR("Index in the address list"), true},
		 {OBFSTR("enable"), OBFSTR("boolean"), OBFSTR("True to freeze, false to unfreeze"), false}},
		handle_freeze_address, false});

	register_compat(srv, {OBFSTR("scanner_read_value"), OBFSTR("memory_scanner"),
		OBFSTR("Read the current value at a memory address."),
		{{OBFSTR("address"), OBFSTR("string"), OBFSTR("Memory address (hex)"), true},
		 {OBFSTR("value_type"), OBFSTR("string"), OBFSTR("Type: byte/int16/int32/int64/float/double/ascii/utf16"), false}},
		handle_read_value, true});

	register_compat(srv, {OBFSTR("scanner_write_value"), OBFSTR("memory_scanner"),
		OBFSTR("Write a value to a memory address in the attached process."),
		{{OBFSTR("address"), OBFSTR("string"), OBFSTR("Memory address (hex)"), true},
		 {OBFSTR("value"), OBFSTR("string"), OBFSTR("Value to write"), true},
		 {OBFSTR("value_type"), OBFSTR("string"), OBFSTR("Type: byte/int16/int32/int64/float/double"), false},
		 {OBFSTR("hex"), OBFSTR("boolean"), OBFSTR("Interpret value as hex"), false}},
		handle_write_value, false});

	register_compat(srv, {OBFSTR("scanner_get_address_list"), OBFSTR("memory_scanner"),
		OBFSTR("Get all entries in the address watch list with current values."),
		{}, handle_get_address_list, true});

	register_compat(srv, {OBFSTR("scanner_pointer_scan"), OBFSTR("memory_scanner"),
		OBFSTR("Perform a pointer scan to find pointer chains that lead to the target address. Useful for finding stable pointers. Operates on the currently active binary_id session; pass binary_id explicitly in multi-target sessions."),
		{{OBFSTR("address"), OBFSTR("string"), OBFSTR("Target address to find pointers to"), true},
		 {OBFSTR("max_depth"), OBFSTR("number"), OBFSTR("Maximum pointer chain depth (1-7, default 4)"), false},
		 {OBFSTR("max_offset"), OBFSTR("number"), OBFSTR("Maximum offset from pointer base (default 0x1000)"), false},
		 {OBFSTR("range_base"), OBFSTR("string"), OBFSTR("Optional pointer-slot scan range base address"), false},
		 {OBFSTR("range_size"), OBFSTR("number"), OBFSTR("Optional pointer-slot scan range size in bytes"), false},
		 {OBFSTR("timeout_ms"), OBFSTR("number"), OBFSTR("Maximum wait time, capped at 30000 ms"), false},
		 {OBFSTR("allow_partial"), OBFSTR("boolean"), OBFSTR("Return partial results without marking the payload as timed out"), false}},
		handle_pointer_scan, true});

	register_compat(srv, {OBFSTR("scanner_cancel_pointer_scan"), OBFSTR("memory_scanner"),
		OBFSTR("Cancel a running pointer scan."),
		{},
		[](const json&) -> tool_result_t {
			memory_scanner::cancel_pointer_scan();
			return tool_result_t::ok(OBFSTR("Pointer scan cancelled."));
		}, false});

	register_compat(srv, {OBFSTR("scanner_define_struct"), OBFSTR("memory_scanner"),
		OBFSTR("Define a new structure for memory analysis at a base address."),
		{{OBFSTR("name"), OBFSTR("string"), OBFSTR("Structure name"), true},
		 {OBFSTR("base_address"), OBFSTR("string"), OBFSTR("Base address for live reading (hex)"), true}},
		[](const json& params) -> tool_result_t {
			if (!params.contains("name") || !params["name"].is_string())
				return tool_result_t::error(OBFSTR("'name' is required."));
			if (!params.contains("base_address") || !params["base_address"].is_string())
				return tool_result_t::error(OBFSTR("'base_address' is required."));
			auto addr = sa_parse_address(params["base_address"].get<std::string>());
			if (!addr) return tool_result_t::error(OBFSTR("Invalid base_address."));
			int idx = struct_dissector::create_struct(params["name"].get<std::string>());
			if (idx < 0)
				return tool_result_t::error(OBFSTR("Failed to create struct."));
			{
				std::lock_guard<std::mutex> lk(struct_dissector::g_state.mtx);
				struct_dissector::g_state.active_struct = idx;
				struct_dissector::g_state.base_address = *addr;
			}
			json result;
			result["struct_index"] = idx;
			result["name"] = params["name"].get<std::string>();
			result["base_address"] = sa_format_address(*addr);
			return tool_result_t::ok(
				OBFSTR("Structure '") + params["name"].get<std::string>() + OBFSTR("' created at index ") + std::to_string(idx), result);
		}, false});

	register_compat(srv, {OBFSTR("scanner_add_struct_field"), OBFSTR("memory_scanner"),
		OBFSTR("Add a field to a structure definition."),
		{{OBFSTR("struct_index"), OBFSTR("number"), OBFSTR("Index of the structure to modify"), true},
		 {OBFSTR("name"), OBFSTR("string"), OBFSTR("Field name"), true},
		 {OBFSTR("offset"), OBFSTR("number"), OBFSTR("Offset from struct base in bytes"), true},
		 {OBFSTR("field_type"), OBFSTR("string"), OBFSTR("Type: int8/uint8/int16/uint16/int32/uint32/int64/uint64/float32/float64/pointer/ascii_string/utf16_string/byte_array/padding"), true}},
		[](const json& params) -> tool_result_t {
			if (!params.contains("struct_index") || !params["struct_index"].is_number())
				return tool_result_t::error(OBFSTR("'struct_index' is required."));
			if (!params.contains("name") || !params["name"].is_string())
				return tool_result_t::error(OBFSTR("'name' is required."));
			if (!params.contains("offset") || !params["offset"].is_number())
				return tool_result_t::error(OBFSTR("'offset' is required."));
			if (!params.contains("field_type") || !params["field_type"].is_string())
				return tool_result_t::error(OBFSTR("'field_type' is required."));
			int si = params["struct_index"].get<int>();
			std::string type_str = params["field_type"].get<std::string>();
			struct_dissector::field_type_t ft = struct_dissector::field_type_t::int32;
			if (type_str == "int8") ft = struct_dissector::field_type_t::int8;
			else if (type_str == "uint8") ft = struct_dissector::field_type_t::uint8;
			else if (type_str == "int16") ft = struct_dissector::field_type_t::int16;
			else if (type_str == "uint16") ft = struct_dissector::field_type_t::uint16;
			else if (type_str == "int32") ft = struct_dissector::field_type_t::int32;
			else if (type_str == "uint32") ft = struct_dissector::field_type_t::uint32;
			else if (type_str == "int64") ft = struct_dissector::field_type_t::int64;
			else if (type_str == "uint64") ft = struct_dissector::field_type_t::uint64;
			else if (type_str == "float32") ft = struct_dissector::field_type_t::float32;
			else if (type_str == "float64") ft = struct_dissector::field_type_t::float64;
			else if (type_str == "pointer") ft = struct_dissector::field_type_t::pointer;
			else if (type_str == "ascii_string") ft = struct_dissector::field_type_t::ascii_string;
			else if (type_str == "utf16_string") ft = struct_dissector::field_type_t::utf16_string;
			else if (type_str == "byte_array") ft = struct_dissector::field_type_t::byte_array;
			else if (type_str == "padding") ft = struct_dissector::field_type_t::padding;
			else return tool_result_t::error(OBFSTR("Unknown field_type: ") + type_str);
			struct_dissector::field_def_t fld;
			fld.name = params["name"].get<std::string>();
			fld.type = ft;
			fld.offset = static_cast<uint32_t>(params["offset"].get<int>());
			int fi = struct_dissector::add_field(si, fld);
			if (fi < 0)
				return tool_result_t::error(OBFSTR("Failed to add field."));
			json result;
			result["field_index"] = fi;
			result["name"] = fld.name;
			result["offset"] = fld.offset;
			result["type"] = type_str;
			return tool_result_t::ok(
				OBFSTR("Field '") + fld.name + OBFSTR("' added at offset ") + std::to_string(fld.offset), result);
		}, false});

	register_compat(srv, {OBFSTR("scanner_get_struct"), OBFSTR("memory_scanner"),
		OBFSTR("Get a structure definition with live values read from memory."),
		{{OBFSTR("struct_index"), OBFSTR("number"), OBFSTR("Index of the structure"), true}},
		[](const json& params) -> tool_result_t {
			if (!params.contains("struct_index") || !params["struct_index"].is_number())
				return tool_result_t::error(OBFSTR("'struct_index' is required."));
			int si = params["struct_index"].get<int>();
			{
				std::lock_guard<std::mutex> lk(struct_dissector::g_state.mtx);
				if (si < 0 || si >= static_cast<int>(struct_dissector::g_state.structs.size()))
					return tool_result_t::error(OBFSTR("Invalid struct_index."));
				struct_dissector::g_state.active_struct = si;
			}
			struct_dissector::refresh_values();
			std::lock_guard<std::mutex> lk(struct_dissector::g_state.mtx);
			const auto& sd = struct_dissector::g_state.structs[static_cast<size_t>(si)];
			json fields_arr = json::array();
			for (size_t fi = 0; fi < sd.fields.size(); ++fi) {
				const auto& f = sd.fields[fi];
				json fj;
				fj["index"] = fi;
				fj["name"] = f.name;
				fj["offset"] = f.offset;
				fj["type"] = struct_dissector::field_type_name(f.type);
				fj["size"] = f.size;
				if (fi < struct_dissector::g_state.cached_values.size())
					fj["value"] = struct_dissector::g_state.cached_values[fi].display_text;
				fields_arr.push_back(std::move(fj));
			}
			json result;
			result["name"] = sd.name;
			result["base_address"] = sa_format_address(struct_dissector::g_state.base_address);
			result["total_size"] = sd.total_size;
			result["field_count"] = sd.fields.size();
			result["fields"] = std::move(fields_arr);
			return tool_result_t::ok(
				OBFSTR("Struct '") + sd.name + OBFSTR("': ") + std::to_string(sd.fields.size()) + OBFSTR(" field(s)."), result);
		}, true});

	register_compat(srv, {OBFSTR("scanner_export_struct_c"), OBFSTR("memory_scanner"),
		OBFSTR("Export a structure definition as C source code."),
		{{OBFSTR("struct_index"), OBFSTR("number"), OBFSTR("Index of the structure to export"), true}},
		[](const json& params) -> tool_result_t {
			if (!params.contains("struct_index") || !params["struct_index"].is_number())
				return tool_result_t::error(OBFSTR("'struct_index' is required."));
			int si = params["struct_index"].get<int>();
			std::string code = struct_dissector::export_to_c(si);
			if (code.empty())
				return tool_result_t::error(OBFSTR("Invalid struct_index or empty struct."));
			json result;
			result["c_code"] = code;
			return tool_result_t::ok(code, result);
		}, true});

}

}
