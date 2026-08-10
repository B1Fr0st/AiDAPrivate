#include "test_lab_features_c03_safe_headless.hpp"

#include "test_lab_format.hpp"

#include "imgui/imgui.h"

#include <windows.h>
#include <bcrypt.h>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <charconv>
#include <chrono>
#include <cctype>
#include <cwctype>
#include <cstring>
#include <exception>
#include <limits>
#include <set>
#include <string_view>
#include <system_error>
#include <unordered_set>
#include <utility>

#pragma comment(lib, "bcrypt.lib")

namespace test_lab::c03_safe_headless {
namespace {

using json = nlohmann::json;

constexpr std::string_view k_manifest_schema = "aida.c03.safe-headless.manifest.v2";
constexpr std::string_view k_result_schema = "aida.c03.safe-headless.result.v1";
constexpr std::string_view k_multi_process_entry_id = "decompiler.quality_scorer";
constexpr std::string_view k_multi_process_source_target = "aida_c03_a06_decompiler_quality_scorer_harness";
constexpr std::uint32_t k_default_active_processes = 1;
constexpr std::uint32_t k_multi_process_active_processes = 4;
constexpr std::uint32_t k_default_wall_ms = 120'000U;
constexpr std::uint32_t k_multi_process_wall_ms = 1'800'000U;
constexpr std::uint64_t k_min_private_bytes = 16ULL * 1024ULL * 1024ULL;
constexpr std::uint64_t k_max_private_bytes = 8ULL * 1024ULL * 1024ULL * 1024ULL;
constexpr std::uint64_t k_max_executable_bytes = 512ULL * 1024ULL * 1024ULL;
constexpr std::uint32_t k_min_wall_ms = 100;
constexpr std::uint32_t k_max_wall_ms = 30U * 60U * 1000U;
constexpr std::uint32_t k_max_argument_bytes = 16384;
constexpr std::uint32_t k_max_entry_count = 512;
constexpr std::uint32_t k_max_source_count = 1024;
constexpr std::uint32_t k_max_runtime_file_count = 512;
constexpr std::uint32_t k_max_requirement_count = 128;
constexpr std::uint32_t k_max_evidence_count = 256;
constexpr std::uint32_t k_max_assertion_count = 1'000'000U;
constexpr std::uint32_t k_max_reporting_threads = 64U;
constexpr std::uint64_t k_suite_capture_max_bytes = 64ULL * 1024ULL * 1024ULL;
constexpr std::uint64_t k_max_runtime_file_bytes = 2ULL * 1024ULL * 1024ULL * 1024ULL;
constexpr auto k_suite_wall_limit = std::chrono::hours(4);
constexpr DWORD k_runner_termination_code = 0xA1DA0301U;

std::atomic<bool> g_cancellation_requested{false};

class handle_t final {
public:
	handle_t() = default;
	explicit handle_t(HANDLE value) noexcept : value_(value) {}
	~handle_t() { reset(); }
	handle_t(const handle_t&) = delete;
	handle_t& operator=(const handle_t&) = delete;
	handle_t(handle_t&& other) noexcept : value_(other.release()) {}
	handle_t& operator=(handle_t&& other) noexcept {
		if (this != &other) reset(other.release());
		return *this;
	}
	HANDLE get() const noexcept { return value_; }
	explicit operator bool() const noexcept { return value_ != nullptr && value_ != INVALID_HANDLE_VALUE; }
	HANDLE release() noexcept {
		HANDLE value = value_;
		value_ = nullptr;
		return value;
	}
	void reset(HANDLE value = nullptr) noexcept {
		if (*this) CloseHandle(value_);
		value_ = value;
	}
private:
	HANDLE value_ = nullptr;
};

class algorithm_t final {
public:
	algorithm_t() = default;
	~algorithm_t() { if (value_) BCryptCloseAlgorithmProvider(value_, 0); }
	BCRYPT_ALG_HANDLE* put() noexcept { return &value_; }
	BCRYPT_ALG_HANDLE get() const noexcept { return value_; }
private:
	BCRYPT_ALG_HANDLE value_ = nullptr;
};

class hash_t final {
public:
	hash_t() = default;
	~hash_t() { if (value_) BCryptDestroyHash(value_); }
	BCRYPT_HASH_HANDLE* put() noexcept { return &value_; }
	BCRYPT_HASH_HANDLE get() const noexcept { return value_; }
private:
	BCRYPT_HASH_HANDLE value_ = nullptr;
};

struct file_identity_t {
	std::uint64_t size = 0;
	std::string sha256;
	DWORD volume_serial = 0;
	DWORD file_index_high = 0;
	DWORD file_index_low = 0;
	DWORD write_time_high = 0;
	DWORD write_time_low = 0;
};

struct pipe_pair_t {
	handle_t read;
	handle_t write;
};

struct process_capture_t {
	entry_result_t result;
	bool stdout_overflow = false;
	bool stderr_overflow = false;
	bool result_overflow = false;
	std::string result_bytes;
};

bool same_identity(const file_identity_t& lhs, const file_identity_t& rhs) noexcept {
	return lhs.size == rhs.size && lhs.sha256 == rhs.sha256 &&
		lhs.volume_serial == rhs.volume_serial && lhs.file_index_high == rhs.file_index_high &&
		lhs.file_index_low == rhs.file_index_low && lhs.write_time_high == rhs.write_time_high &&
		lhs.write_time_low == rhs.write_time_low;
}

std::string win32_error(std::string_view operation, DWORD code = GetLastError()) {
	return std::string(operation) + " failed with Win32 error " + std::to_string(code);
}

std::string nt_error(std::string_view operation, NTSTATUS status) {
	return std::string(operation) + " failed with NTSTATUS " + std::to_string(static_cast<long>(status));
}

bool ascii_identifier(std::string_view value, std::size_t maximum, bool allow_dot) noexcept {
	if (value.empty() || value.size() > maximum) return false;
	for (const unsigned char ch : value) {
		if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
			(ch >= '0' && ch <= '9') || ch == '_' || ch == '-' || (allow_dot && ch == '.')) continue;
		return false;
	}
	return true;
}

bool hex_digest(std::string_view value) noexcept {
	if (value.size() != 64) return false;
	for (const unsigned char ch : value) {
		if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f'))) return false;
	}
	return true;
}

bool requirement_identifier(std::string_view value) noexcept {
	if (value.size() < 4 || value.size() > 48) return false;
	bool digit = false;
	bool separator = false;
	for (const unsigned char ch : value) {
		if (ch >= '0' && ch <= '9') {
			digit = true;
			continue;
		}
		if (ch >= 'A' && ch <= 'Z') continue;
		if (ch == '-') {
			separator = true;
			continue;
		}
		return false;
	}
	return digit && separator && value.front() != '-' && value.back() != '-';
}

bool exact_keys(const json& value, std::initializer_list<std::string_view> expected, std::string& error) {
	if (!value.is_object()) {
		error = "JSON value is not an object";
		return false;
	}
	std::set<std::string, std::less<>> keys;
	for (const auto key : expected) keys.emplace(key);
	if (value.size() != keys.size()) {
		error = "JSON object field cardinality is invalid";
		return false;
	}
	for (auto it = value.begin(); it != value.end(); ++it) {
		if (keys.find(it.key()) == keys.end()) {
			error = "JSON object contains unknown field: " + it.key();
			return false;
		}
	}
	for (const auto& key : keys) {
		if (!value.contains(key)) {
			error = "JSON object is missing required field: " + key;
			return false;
		}
	}
	return true;
}

bool safe_relative_path(const std::filesystem::path& value, bool executable) {
	if (value.empty() || value.is_absolute() || value.has_root_name() || value.has_root_directory()) return false;
	if (value == L".") return !executable;
	for (const auto& part : value) {
		if (part.empty() || part == L"." || part == L"..") return false;
		std::wstring component = part.wstring();
		if (component.empty() || component.back() == L'.' || component.back() == L' ') return false;
		for (const wchar_t ch : component) {
			if (ch < 32 || ch == L':' || ch == L'"' || ch == L'<' || ch == L'>' || ch == L'|' ||
				ch == L'?' || ch == L'*') return false;
		}
		std::transform(component.begin(), component.end(), component.begin(),
			[](wchar_t ch) { return static_cast<wchar_t>(towlower(ch)); });
		const auto dot = component.find(L'.');
		const auto stem = component.substr(0, dot);
		if (stem == L"con" || stem == L"prn" || stem == L"aux" || stem == L"nul" ||
			(stem.size() == 4 && (stem.rfind(L"com", 0) == 0 || stem.rfind(L"lpt", 0) == 0) &&
			stem[3] >= L'1' && stem[3] <= L'9')) return false;
	}
	const auto normalized = value.lexically_normal();
	if (normalized.empty() || normalized.native().size() > 1024) return false;
	if (executable) {
		std::wstring extension = normalized.extension().wstring();
		std::transform(extension.begin(), extension.end(), extension.begin(),
			[](wchar_t ch) { return static_cast<wchar_t>(towlower(ch)); });
		if (extension != L".exe") return false;
	}
	return true;
}

bool safe_source_path(std::string_view value) {
	if (value.empty() || value.size() > 1024 || value.front() == '/' || value.front() == '\\') return false;
	if (value.size() >= 2 && std::isalpha(static_cast<unsigned char>(value[0])) && value[1] == ':') return false;
	if (value.find('\\') != std::string_view::npos || value.find('\0') != std::string_view::npos) return false;
	std::size_t offset = 0;
	while (offset <= value.size()) {
		const auto end = value.find('/', offset);
		const auto part = value.substr(offset, end == std::string_view::npos ? value.size() - offset : end - offset);
		if (part.empty() || part == "." || part == "..") return false;
		if (end == std::string_view::npos) break;
		offset = end + 1;
	}
	return true;
}

bool category_allowed(std::string_view category) noexcept {
	static constexpr std::array<std::string_view, 18> allowed{{
		"contract", "fixture", "provider", "layout", "store", "scheduler",
		"reader", "container", "decode", "recovery", "query", "persistence", "decompiler",
		"worker", "mcp", "workbench", "performance", "surface"
	}};
	return std::find(allowed.begin(), allowed.end(), category) != allowed.end();
}

bool argument_safe(std::string_view argument) noexcept {
	if (argument.empty() || argument.size() > k_max_argument_bytes) return false;
	if (argument.rfind("--aida-c03-", 0) == 0) return false;
	for (const unsigned char ch : argument) {
		if (ch == 0 || ch == '\r' || ch == '\n') return false;
	}
	return true;
}

bool safety_contract_allowed(const safety_contract_t& safety) noexcept {
	return safety.safe_headless && !safety.requires_driver && !safety.requires_network &&
		!safety.launches_application && !safety.launches_bootstrap && !safety.performs_packaging &&
		!safety.performs_deployment && !safety.performs_live_operation &&
		!safety.performs_debugger_operation && !safety.executes_target_artifact &&
		!safety.mutates_source_or_repository;
}

bool resource_contract_allowed(const manifest_entry_t& entry) noexcept {
	const bool approved = entry.id == k_multi_process_entry_id &&
		entry.source_target == k_multi_process_source_target;
	return entry.max_active_processes ==
		(approved ? k_multi_process_active_processes : k_default_active_processes) &&
		entry.max_wall_ms == (approved ? k_multi_process_wall_ms : k_default_wall_ms);
}

bool entry_contract_valid(const manifest_entry_t& entry) {
	if (!ascii_identifier(entry.id, 96, true) || !category_allowed(entry.category) ||
		!ascii_identifier(entry.source_target, 160, true) ||
		!safe_relative_path(entry.executable_relative_path, true) ||
		!safe_relative_path(entry.working_directory_relative_path, false) ||
		!hex_digest(entry.executable_sha256) || !hex_digest(entry.build_identity) ||
		entry.expected_result_schema != k_result_schema || entry.executable_size == 0 ||
		entry.executable_size > k_max_executable_bytes || entry.max_wall_ms < k_min_wall_ms ||
		entry.max_wall_ms > k_max_wall_ms || entry.max_private_bytes < k_min_private_bytes ||
		entry.max_private_bytes > k_max_private_bytes || entry.max_stdout_bytes == 0 ||
		entry.max_stdout_bytes > k_stream_max_bytes || entry.max_stderr_bytes == 0 ||
		entry.max_stderr_bytes > k_stream_max_bytes || entry.max_result_bytes == 0 ||
		entry.max_result_bytes > k_result_max_bytes || !resource_contract_allowed(entry) ||
		!safety_contract_allowed(entry.safety) ||
		entry.requirement_ids.empty() || entry.requirement_ids.size() > k_max_requirement_count ||
		entry.source_files.empty() || entry.source_files.size() > k_max_source_count ||
		entry.runtime_files.size() > k_max_runtime_file_count) return false;
	std::unordered_set<std::string> requirements;
	for (const auto& value : entry.requirement_ids) {
		if (!requirement_identifier(value) || !requirements.emplace(value).second) return false;
	}
	std::unordered_set<std::string> sources;
	for (const auto& value : entry.source_files) {
		if (!safe_source_path(value) || !sources.emplace(value).second) return false;
	}
	std::unordered_set<std::string> runtime_paths;
	std::uint64_t runtime_bytes = 0;
	for (const auto& value : entry.runtime_files) {
		if (!safe_relative_path(value.relative_path, false) || value.relative_path == L"." ||
			value.size == 0 || value.size > k_max_executable_bytes || !hex_digest(value.sha256) ||
			!runtime_paths.emplace(value.relative_path.generic_u8string()).second ||
			runtime_bytes > k_max_runtime_file_bytes - value.size) return false;
		runtime_bytes += value.size;
	}
	std::size_t argument_bytes = 0;
	for (const auto& value : entry.arguments) {
		if (!argument_safe(value)) return false;
		argument_bytes += value.size();
		if (argument_bytes > k_max_argument_bytes) return false;
	}
	return true;
}

bool path_components_are_non_reparse(const std::filesystem::path& path, bool allow_missing_leaf,
	std::string& error) {
	std::error_code ec;
	auto absolute = std::filesystem::absolute(path, ec).lexically_normal();
	if (ec) {
		error = "path could not be made absolute";
		return false;
	}
	std::filesystem::path current = absolute.root_path();
	for (const auto& part : absolute.relative_path()) {
		current /= part;
		const DWORD attributes = GetFileAttributesW(current.c_str());
		if (attributes == INVALID_FILE_ATTRIBUTES) {
			if (allow_missing_leaf && current == absolute &&
				GetLastError() == ERROR_FILE_NOT_FOUND) return true;
			error = win32_error("GetFileAttributesW");
			return false;
		}
		if ((attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
			error = "path contains a reparse point";
			return false;
		}
	}
	return true;
}

std::wstring lower_path(std::filesystem::path value) {
	std::wstring text = value.lexically_normal().wstring();
	std::transform(text.begin(), text.end(), text.begin(),
		[](wchar_t ch) { return static_cast<wchar_t>(towlower(ch)); });
	return text;
}

bool path_is_within(const std::filesystem::path& root, const std::filesystem::path& candidate) {
	const auto root_text = lower_path(std::filesystem::absolute(root));
	const auto candidate_text = lower_path(std::filesystem::absolute(candidate));
	if (candidate_text == root_text) return true;
	if (candidate_text.size() <= root_text.size() || candidate_text.compare(0, root_text.size(), root_text) != 0) return false;
	const wchar_t separator = candidate_text[root_text.size()];
	return separator == L'\\' || separator == L'/';
}

bool compute_file_identity(const std::filesystem::path& path, file_identity_t& identity, std::string& error,
	const cancellation_probe_t& cancellation = {}) {
	handle_t file(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE,
		nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
	if (!file) {
		error = win32_error("CreateFileW");
		return false;
	}
	FILE_ATTRIBUTE_TAG_INFO tag{};
	if (!GetFileInformationByHandleEx(file.get(), FileAttributeTagInfo, &tag, sizeof(tag))) {
		error = win32_error("GetFileInformationByHandleEx");
		return false;
	}
	if ((tag.FileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0) {
		error = "identity target is not a regular non-reparse file";
		return false;
	}
	BY_HANDLE_FILE_INFORMATION info{};
	if (!GetFileInformationByHandle(file.get(), &info)) {
		error = win32_error("GetFileInformationByHandle");
		return false;
	}
	identity.size = (static_cast<std::uint64_t>(info.nFileSizeHigh) << 32) | info.nFileSizeLow;
	if (identity.size == 0 || identity.size > 8ULL * 1024ULL * 1024ULL * 1024ULL) {
		error = "identity target size is outside the supported range";
		return false;
	}
	identity.volume_serial = info.dwVolumeSerialNumber;
	identity.file_index_high = info.nFileIndexHigh;
	identity.file_index_low = info.nFileIndexLow;
	identity.write_time_high = info.ftLastWriteTime.dwHighDateTime;
	identity.write_time_low = info.ftLastWriteTime.dwLowDateTime;
	algorithm_t algorithm;
	NTSTATUS status = BCryptOpenAlgorithmProvider(algorithm.put(), BCRYPT_SHA256_ALGORITHM, nullptr, 0);
	if (!BCRYPT_SUCCESS(status)) {
		error = nt_error("BCryptOpenAlgorithmProvider", status);
		return false;
	}
	DWORD object_bytes = 0;
	DWORD received = 0;
	status = BCryptGetProperty(algorithm.get(), BCRYPT_OBJECT_LENGTH,
		reinterpret_cast<PUCHAR>(&object_bytes), sizeof(object_bytes), &received, 0);
	if (!BCRYPT_SUCCESS(status) || received != sizeof(object_bytes) || object_bytes == 0) {
		error = nt_error("BCryptGetProperty", status);
		return false;
	}
	std::vector<std::uint8_t> object(object_bytes);
	hash_t hash;
	status = BCryptCreateHash(algorithm.get(), hash.put(), object.data(), object_bytes, nullptr, 0, 0);
	if (!BCRYPT_SUCCESS(status)) {
		error = nt_error("BCryptCreateHash", status);
		return false;
	}
	std::vector<std::uint8_t> buffer(1024 * 1024);
	std::uint64_t consumed = 0;
	while (consumed < identity.size) {
		if (g_cancellation_requested.load(std::memory_order_acquire) || (cancellation && cancellation())) {
			error = "file identity computation was cancelled";
			return false;
		}
		DWORD count = 0;
		const DWORD wanted = static_cast<DWORD>((std::min)(identity.size - consumed,
			static_cast<std::uint64_t>(buffer.size())));
		if (!ReadFile(file.get(), buffer.data(), wanted, &count, nullptr) || count == 0) {
			error = win32_error("ReadFile");
			return false;
		}
		status = BCryptHashData(hash.get(), buffer.data(), count, 0);
		if (!BCRYPT_SUCCESS(status)) {
			error = nt_error("BCryptHashData", status);
			return false;
		}
		consumed += count;
	}
	std::array<std::uint8_t, 32> digest{};
	status = BCryptFinishHash(hash.get(), digest.data(), static_cast<ULONG>(digest.size()), 0);
	if (!BCRYPT_SUCCESS(status)) {
		error = nt_error("BCryptFinishHash", status);
		return false;
	}
	static constexpr char hex[] = "0123456789abcdef";
	identity.sha256.resize(64);
	for (std::size_t index = 0; index < digest.size(); ++index) {
		identity.sha256[index * 2] = hex[digest[index] >> 4];
		identity.sha256[index * 2 + 1] = hex[digest[index] & 0x0f];
	}
	return true;
}

bool read_bounded_file(const std::filesystem::path& path, std::uint64_t maximum,
	std::string& bytes, file_identity_t& identity, std::string& error) {
	if (!compute_file_identity(path, identity, error)) return false;
	if (identity.size > maximum) {
		error = "file exceeds its bounded read limit";
		return false;
	}
	handle_t file(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
	if (!file) {
		error = win32_error("CreateFileW");
		return false;
	}
	file_identity_t locked_identity;
	if (!compute_file_identity(path, locked_identity, error) || !same_identity(identity, locked_identity)) {
		error = "file identity changed before its bounded read";
		return false;
	}
	identity = std::move(locked_identity);
	try {
		bytes.resize(static_cast<std::size_t>(identity.size));
	} catch (...) {
		error = "bounded file buffer allocation failed";
		return false;
	}
	std::size_t offset = 0;
	while (offset < bytes.size()) {
		DWORD count = 0;
		const DWORD wanted = static_cast<DWORD>((std::min)(bytes.size() - offset,
			static_cast<std::size_t>(1024 * 1024)));
		if (!ReadFile(file.get(), bytes.data() + offset, wanted, &count, nullptr) || count == 0) {
			error = win32_error("ReadFile");
			return false;
		}
		offset += count;
	}
	return true;
}

bool parse_string_array(const json& value, std::uint32_t maximum, std::vector<std::string>& out,
	const std::function<bool(std::string_view)>& validator, std::string& error) {
	if (!value.is_array() || value.empty() || value.size() > maximum) {
		error = "string array cardinality is invalid";
		return false;
	}
	std::unordered_set<std::string> unique;
	for (const auto& item : value) {
		if (!item.is_string()) {
			error = "string array contains a non-string value";
			return false;
		}
		const auto text = item.get<std::string>();
		if (!validator(text) || !unique.emplace(text).second) {
			error = "string array contains an invalid or duplicate value";
			return false;
		}
		out.push_back(text);
	}
	return true;
}

bool parse_safety(const json& value, safety_contract_t& safety, std::string& error) {
	if (!exact_keys(value, {"safe_headless", "requires_driver", "requires_network",
		"launches_application", "launches_bootstrap", "performs_packaging", "performs_deployment",
		"performs_live_operation", "performs_debugger_operation", "executes_target_artifact",
		"mutates_source_or_repository"}, error)) return false;
	for (auto it = value.begin(); it != value.end(); ++it) {
		if (!it.value().is_boolean()) {
			error = "safety field is not boolean";
			return false;
		}
	}
	safety.safe_headless = value.at("safe_headless").get<bool>();
	safety.requires_driver = value.at("requires_driver").get<bool>();
	safety.requires_network = value.at("requires_network").get<bool>();
	safety.launches_application = value.at("launches_application").get<bool>();
	safety.launches_bootstrap = value.at("launches_bootstrap").get<bool>();
	safety.performs_packaging = value.at("performs_packaging").get<bool>();
	safety.performs_deployment = value.at("performs_deployment").get<bool>();
	safety.performs_live_operation = value.at("performs_live_operation").get<bool>();
	safety.performs_debugger_operation = value.at("performs_debugger_operation").get<bool>();
	safety.executes_target_artifact = value.at("executes_target_artifact").get<bool>();
	safety.mutates_source_or_repository = value.at("mutates_source_or_repository").get<bool>();
	if (!safety_contract_allowed(safety)) {
		error = "manifest entry violates the safe-headless effect policy";
		return false;
	}
	return true;
}

bool parse_runtime_files(const json& value, std::vector<runtime_file_identity_t>& files,
	std::string& error) {
	if (!value.is_array() || value.size() > k_max_runtime_file_count) {
		error = "runtime file inventory cardinality is invalid";
		return false;
	}
	std::unordered_set<std::string> paths;
	std::uint64_t total_size = 0;
	for (const auto& item : value) {
		if (!exact_keys(item, {"relative_path", "size", "sha256"}, error) ||
			!item.at("relative_path").is_string() || !item.at("size").is_number_unsigned() ||
			!item.at("sha256").is_string()) {
			if (error.empty()) error = "runtime file identity field is invalid";
			return false;
		}
		runtime_file_identity_t file;
		file.relative_path = std::filesystem::u8path(item.at("relative_path").get<std::string>());
		file.size = item.at("size").get<std::uint64_t>();
		file.sha256 = item.at("sha256").get<std::string>();
		if (!safe_relative_path(file.relative_path, false) || file.relative_path == L"." ||
			file.size == 0 || file.size > k_max_executable_bytes || !hex_digest(file.sha256) ||
			!paths.emplace(file.relative_path.generic_u8string()).second ||
			total_size > k_max_runtime_file_bytes - file.size) {
			error = "runtime file identity violates path, size, hash, uniqueness, or aggregate limits";
			return false;
		}
		total_size += file.size;
		files.push_back(std::move(file));
	}
	return true;
}

bool parse_entry(const json& value, manifest_entry_t& entry, std::string& error) {
	if (!exact_keys(value, {"id", "category", "requirement_ids", "source_target", "source_files",
		"runtime_files", "executable_relative_path", "working_directory_relative_path", "arguments", "executable_size",
		"executable_sha256", "build_identity", "max_active_processes", "max_wall_ms", "max_private_bytes", "max_stdout_bytes",
		"max_stderr_bytes", "max_result_bytes", "expected_result_schema", "safety"}, error)) return false;
	if (!value.at("id").is_string() || !value.at("category").is_string() ||
		!value.at("source_target").is_string() || !value.at("executable_relative_path").is_string() ||
		!value.at("working_directory_relative_path").is_string() || !value.at("executable_sha256").is_string() ||
		!value.at("build_identity").is_string() || !value.at("expected_result_schema").is_string()) {
		error = "manifest entry contains an invalid string field";
		return false;
	}
	entry.id = value.at("id").get<std::string>();
	entry.category = value.at("category").get<std::string>();
	entry.source_target = value.at("source_target").get<std::string>();
	entry.executable_relative_path = std::filesystem::u8path(value.at("executable_relative_path").get<std::string>());
	entry.working_directory_relative_path = std::filesystem::u8path(value.at("working_directory_relative_path").get<std::string>());
	entry.executable_sha256 = value.at("executable_sha256").get<std::string>();
	entry.build_identity = value.at("build_identity").get<std::string>();
	entry.expected_result_schema = value.at("expected_result_schema").get<std::string>();
	if (!ascii_identifier(entry.id, 96, true) || !category_allowed(entry.category) ||
		!ascii_identifier(entry.source_target, 160, true) || !safe_relative_path(entry.executable_relative_path, true) ||
		!safe_relative_path(entry.working_directory_relative_path, false) || !hex_digest(entry.executable_sha256) ||
		!hex_digest(entry.build_identity) || entry.expected_result_schema != k_result_schema) {
		error = "manifest entry identity, path, category, hash, or result schema is invalid";
		return false;
	}
	if (!parse_string_array(value.at("requirement_ids"), k_max_requirement_count, entry.requirement_ids,
		[](std::string_view text) { return requirement_identifier(text); }, error)) return false;
	if (!parse_string_array(value.at("source_files"), k_max_source_count, entry.source_files,
		[](std::string_view text) { return safe_source_path(text); }, error)) return false;
	if (!parse_runtime_files(value.at("runtime_files"), entry.runtime_files, error)) return false;
	if (!value.at("arguments").is_array() || value.at("arguments").size() > 128) {
		error = "manifest argument array is invalid";
		return false;
	}
	std::size_t argument_bytes = 0;
	for (const auto& argument : value.at("arguments")) {
		if (!argument.is_string()) {
			error = "manifest argument is not a string";
			return false;
		}
		auto text = argument.get<std::string>();
		if (!argument_safe(text)) {
			error = "manifest argument violates the fixed argument policy";
			return false;
		}
		argument_bytes += text.size();
		if (argument_bytes > k_max_argument_bytes) {
			error = "manifest arguments exceed the aggregate limit";
			return false;
		}
		entry.arguments.push_back(std::move(text));
	}
	const auto read_u64 = [&](const char* key, std::uint64_t& output) {
		const auto& field = value.at(key);
		if (!field.is_number_unsigned()) return false;
		output = field.get<std::uint64_t>();
		return true;
	};
	std::uint64_t wall = 0;
	std::uint64_t active_processes = 0;
	std::uint64_t stdout_limit = 0;
	std::uint64_t stderr_limit = 0;
	std::uint64_t result_limit = 0;
	if (!read_u64("executable_size", entry.executable_size) ||
		!read_u64("max_active_processes", active_processes) || !read_u64("max_wall_ms", wall) ||
		!read_u64("max_private_bytes", entry.max_private_bytes) || !read_u64("max_stdout_bytes", stdout_limit) ||
		!read_u64("max_stderr_bytes", stderr_limit) || !read_u64("max_result_bytes", result_limit) ||
		entry.executable_size == 0 || entry.executable_size > k_max_executable_bytes ||
		active_processes == 0 || active_processes > k_multi_process_active_processes ||
		wall < k_min_wall_ms || wall > k_max_wall_ms ||
		entry.max_private_bytes < k_min_private_bytes || entry.max_private_bytes > k_max_private_bytes ||
		stdout_limit == 0 || stdout_limit > k_stream_max_bytes || stderr_limit == 0 ||
		stderr_limit > k_stream_max_bytes || result_limit == 0 || result_limit > k_result_max_bytes) {
		error = "manifest entry resource limits are invalid";
		return false;
	}
	entry.max_active_processes = static_cast<std::uint32_t>(active_processes);
	entry.max_wall_ms = static_cast<std::uint32_t>(wall);
	if (!resource_contract_allowed(entry)) {
		error = "manifest entry process-and-wall resource contract is unauthorized";
		return false;
	}
	entry.max_stdout_bytes = static_cast<std::uint32_t>(stdout_limit);
	entry.max_stderr_bytes = static_cast<std::uint32_t>(stderr_limit);
	entry.max_result_bytes = static_cast<std::uint32_t>(result_limit);
	return parse_safety(value.at("safety"), entry.safety, error);
}

std::wstring quote_argument(std::wstring_view value) {
	if (value.find_first_of(L" \t\"") == std::wstring_view::npos) return std::wstring(value);
	std::wstring result(1, L'\"');
	std::size_t slashes = 0;
	for (const wchar_t ch : value) {
		if (ch == L'\\') {
			++slashes;
			continue;
		}
		if (ch == L'\"') {
			result.append(slashes * 2 + 1, L'\\');
			result.push_back(L'\"');
			slashes = 0;
			continue;
		}
		result.append(slashes, L'\\');
		slashes = 0;
		result.push_back(ch);
	}
	result.append(slashes * 2, L'\\');
	result.push_back(L'\"');
	return result;
}

std::wstring utf8_to_wide(std::string_view value) {
	if (value.empty()) return {};
	const int count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
		static_cast<int>(value.size()), nullptr, 0);
	if (count <= 0) return {};
	std::wstring output(static_cast<std::size_t>(count), L'\0');
	if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()),
		output.data(), count) != count) return {};
	return output;
}

bool create_pipe_pair(pipe_pair_t& output, std::string& error) {
	SECURITY_ATTRIBUTES attributes{};
	attributes.nLength = sizeof(attributes);
	attributes.bInheritHandle = TRUE;
	HANDLE read = nullptr;
	HANDLE write = nullptr;
	if (!CreatePipe(&read, &write, &attributes, 0)) {
		error = win32_error("CreatePipe");
		return false;
	}
	output.read.reset(read);
	output.write.reset(write);
	if (!SetHandleInformation(output.read.get(), HANDLE_FLAG_INHERIT, 0)) {
		error = win32_error("SetHandleInformation");
		return false;
	}
	return true;
}

bool drain_pipe(HANDLE pipe, std::string& output, std::uint32_t maximum, bool& overflow,
	std::string& error) {
	for (;;) {
		DWORD available = 0;
		if (!PeekNamedPipe(pipe, nullptr, 0, nullptr, &available, nullptr)) {
			const DWORD code = GetLastError();
			if (code == ERROR_BROKEN_PIPE) return true;
			error = win32_error("PeekNamedPipe", code);
			return false;
		}
		if (available == 0) return true;
		std::array<char, 16384> buffer{};
		const DWORD requested = (std::min)(available, static_cast<DWORD>(buffer.size()));
		DWORD received = 0;
		if (!ReadFile(pipe, buffer.data(), requested, &received, nullptr)) {
			const DWORD code = GetLastError();
			if (code == ERROR_BROKEN_PIPE) return true;
			error = win32_error("ReadFile", code);
			return false;
		}
		if (received == 0) return true;
		if (output.size() + received > maximum) {
			const auto remaining = maximum > output.size() ? maximum - output.size() : 0;
			output.append(buffer.data(), remaining);
			overflow = true;
			return true;
		}
		output.append(buffer.data(), received);
	}
}

bool crash_exit_code(DWORD code) noexcept {
	return (code & 0xF0000000U) == 0xC0000000U || code == k_runner_termination_code;
}

bool parse_result_envelope(const manifest_entry_t& entry, const std::string& bytes,
	DWORD exit_code, entry_result_t& result) {
	json value;
	try {
		value = json::parse(bytes);
	} catch (...) {
		result.error = "child result envelope is not valid JSON";
		return false;
	}
	std::string error;
	if (!exact_keys(value, {"schema", "version", "id", "source_target", "build_identity",
		"outcome", "assertions", "ledger", "elapsed_us", "evidence"}, error)) {
		result.error = std::move(error);
		return false;
	}
	if (!value.at("schema").is_string() || value.at("schema").get<std::string>() != entry.expected_result_schema ||
		!value.at("version").is_number_unsigned() || value.at("version").get<std::uint64_t>() != k_result_version ||
		!value.at("id").is_string() || value.at("id").get<std::string>() != entry.id ||
		!value.at("source_target").is_string() || value.at("source_target").get<std::string>() != entry.source_target ||
		!value.at("build_identity").is_string() || value.at("build_identity").get<std::string>() != entry.build_identity ||
		!value.at("outcome").is_string() || !value.at("elapsed_us").is_number_unsigned()) {
		result.error = "child result identity or schema does not match the manifest";
		return false;
	}
	const auto outcome = value.at("outcome").get<std::string>();
	entry_outcome_e parsed_outcome = entry_outcome_e::malformed_result;
	if (outcome == "passed") parsed_outcome = entry_outcome_e::passed;
	else if (outcome == "failed") parsed_outcome = entry_outcome_e::failed;
	else if (outcome == "not_run") parsed_outcome = entry_outcome_e::not_run;
	else {
		result.error = "child result contains an invalid outcome";
		return false;
	}
	const auto& assertions = value.at("assertions");
	if (!exact_keys(assertions, {"total", "passed", "failed", "skipped", "not_run"}, error)) {
		result.error = std::move(error);
		return false;
	}
	if (!assertions.at("total").is_number_unsigned() || !assertions.at("passed").is_number_unsigned() ||
		!assertions.at("failed").is_number_unsigned() || !assertions.at("skipped").is_number_unsigned() ||
		!assertions.at("not_run").is_boolean()) {
		result.error = "child assertion counts are not unsigned integers";
		return false;
	}
	const auto total = assertions.at("total").get<std::uint64_t>();
	const auto passed = assertions.at("passed").get<std::uint64_t>();
	const auto failed = assertions.at("failed").get<std::uint64_t>();
	const auto skipped = assertions.at("skipped").get<std::uint64_t>();
	const bool not_run = assertions.at("not_run").get<bool>();
	if (total > k_max_assertion_count || skipped > k_max_assertion_count || passed > total || failed > total ||
		passed + failed != total ||
		(parsed_outcome == entry_outcome_e::passed &&
			(total == 0 || failed != 0 || skipped != 0 || not_run || exit_code != 0)) ||
		(parsed_outcome == entry_outcome_e::failed &&
			(total == 0 || failed == 0 || skipped != 0 || not_run || exit_code == 0)) ||
		(parsed_outcome == entry_outcome_e::not_run &&
			(total != 0 || skipped == 0 || !not_run || exit_code != 0))) {
		result.error = "child assertion counts, outcome, and exit code are inconsistent";
		return false;
	}
	const auto& ledger = value.at("ledger");
	if (!exact_keys(ledger, {"epoch", "finalized", "event_digest", "reporting_threads",
		"late_writes", "error_flags"}, error) || !ledger.at("epoch").is_number_unsigned() ||
		!ledger.at("finalized").is_boolean() || !ledger.at("event_digest").is_string() ||
		!ledger.at("reporting_threads").is_number_unsigned() ||
		!ledger.at("late_writes").is_number_unsigned() || !ledger.at("error_flags").is_number_unsigned()) {
		result.error = error.empty() ? "child assertion ledger is invalid" : std::move(error);
		return false;
	}
	const auto epoch = ledger.at("epoch").get<std::uint64_t>();
	const bool finalized = ledger.at("finalized").get<bool>();
	const auto event_digest = ledger.at("event_digest").get<std::string>();
	const auto reporting_threads = ledger.at("reporting_threads").get<std::uint64_t>();
	const auto late_writes = ledger.at("late_writes").get<std::uint64_t>();
	const auto error_flags = ledger.at("error_flags").get<std::uint64_t>();
	if (epoch == 0 || !finalized || event_digest.size() != 32 ||
		reporting_threads == 0 || reporting_threads > k_max_reporting_threads ||
		late_writes != 0 || error_flags != 0) {
		result.error = "child assertion ledger state violates the finalized contract";
		return false;
	}
	for (const unsigned char ch : event_digest) {
		if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f'))) {
			result.error = "child assertion ledger digest is not canonical hexadecimal";
			return false;
		}
	}
	const auto elapsed_us = value.at("elapsed_us").get<std::uint64_t>();
	const auto& evidence = value.at("evidence");
	if (!evidence.is_array() || evidence.size() > k_max_evidence_count) {
		result.error = "child evidence array is invalid";
		return false;
	}
	std::unordered_set<std::string> names;
	std::string adapter_exit_code;
	std::string ledger_epoch;
	std::string ledger_digest;
	std::string evidence_reporting_threads;
	bool first_failure_present = false;
	bool first_failure_nonempty = false;
	std::vector<evidence_field_t> parsed_evidence;
	parsed_evidence.reserve(evidence.size());
	for (const auto& field : evidence) {
		if (!exact_keys(field, {"name", "value"}, error) || !field.at("name").is_string() ||
			!field.at("value").is_string()) {
			result.error = error.empty() ? "child evidence field is invalid" : std::move(error);
			return false;
		}
		evidence_field_t parsed;
		parsed.name = field.at("name").get<std::string>();
		parsed.value = field.at("value").get<std::string>();
		if (!ascii_identifier(parsed.name, 96, true) || parsed.value.size() > 4096 ||
			!names.emplace(parsed.name).second) {
			result.error = "child evidence field violates bounds or uniqueness";
			return false;
		}
		if (parsed.name == "adapter_exit_code") adapter_exit_code = parsed.value;
		else if (parsed.name == "ledger_epoch") ledger_epoch = parsed.value;
		else if (parsed.name == "ledger_digest") ledger_digest = parsed.value;
		else if (parsed.name == "reporting_threads") evidence_reporting_threads = parsed.value;
		else if (parsed.name == "first_failure") {
			first_failure_present = true;
			first_failure_nonempty = !parsed.value.empty();
		}
		parsed_evidence.push_back(std::move(parsed));
	}
	const auto parse_decimal = [](std::string_view text, std::uint64_t& output) noexcept {
		if (text.empty()) return false;
		const auto parsed = std::from_chars(text.data(), text.data() + text.size(), output, 10);
		return parsed.ec == std::errc{} && parsed.ptr == text.data() + text.size();
	};
	std::uint64_t parsed_exit = 0;
	std::uint64_t parsed_epoch = 0;
	std::uint64_t parsed_threads = 0;
	if (!parse_decimal(adapter_exit_code, parsed_exit) || parsed_exit != exit_code ||
		!parse_decimal(ledger_epoch, parsed_epoch) || parsed_epoch != epoch ||
		ledger_digest != event_digest || !parse_decimal(evidence_reporting_threads, parsed_threads) ||
		parsed_threads != reporting_threads ||
		(parsed_outcome == entry_outcome_e::failed ?
			(!first_failure_present || !first_failure_nonempty) : first_failure_present)) {
		result.error = "child assertion evidence does not bind the finalized ledger";
		return false;
	}
	result.outcome = parsed_outcome;
	result.assertions.total = static_cast<std::uint32_t>(total);
	result.assertions.passed = static_cast<std::uint32_t>(passed);
	result.assertions.failed = static_cast<std::uint32_t>(failed);
	result.assertions.skipped = static_cast<std::uint32_t>(skipped);
	result.assertions.not_run = not_run;
	result.elapsed_us = elapsed_us;
	result.evidence = std::move(parsed_evidence);
	return true;
}

entry_outcome_e aggregate_outcome(const suite_result_t& suite) noexcept {
	if (suite.integrity_failure != 0) return entry_outcome_e::integrity_failure;
	if (suite.malformed_result != 0) return entry_outcome_e::malformed_result;
	if (suite.crashed != 0) return entry_outcome_e::crashed;
	if (suite.timed_out != 0) return entry_outcome_e::timed_out;
	if (suite.failed != 0) return entry_outcome_e::failed;
	if (suite.missing != 0) return entry_outcome_e::missing;
	if (suite.cancelled != 0) return entry_outcome_e::cancelled;
	if (suite.not_run != 0) return entry_outcome_e::not_run;
	return entry_outcome_e::passed;
}

void increment_outcome(suite_result_t& suite, entry_outcome_e outcome) noexcept {
	switch (outcome) {
		case entry_outcome_e::not_run: ++suite.not_run; break;
		case entry_outcome_e::missing: ++suite.missing; break;
		case entry_outcome_e::passed: ++suite.passed; break;
		case entry_outcome_e::failed: ++suite.failed; break;
		case entry_outcome_e::timed_out: ++suite.timed_out; break;
		case entry_outcome_e::crashed: ++suite.crashed; break;
		case entry_outcome_e::cancelled: ++suite.cancelled; break;
		case entry_outcome_e::malformed_result: ++suite.malformed_result; break;
		case entry_outcome_e::integrity_failure: ++suite.integrity_failure; break;
	}
}

std::filesystem::path executable_directory() {
	std::wstring buffer(32768, L'\0');
	const DWORD size = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
	if (size == 0 || size >= buffer.size()) return {};
	buffer.resize(size);
	return std::filesystem::path(buffer).parent_path();
}

void render_inputs(state_t&) {
	const auto root = executable_directory() / L"c03-safe-headless";
	const auto manifest = root / L"manifest.json";
	ImGui::TextWrapped("Approved root: %ls", root.c_str());
	ImGui::TextWrapped("Manifest: %ls", manifest.c_str());
	ImGui::TextDisabled("This driverless lane executes only build-verified safe-headless harnesses.");
	if (cancellation_requested()) ImGui::TextUnformatted("Cancellation requested");
	if (ImGui::Button("Cancel C03 lane", ImVec2(150.0f, 26.0f))) request_cancellation();
}

void run_feature(state_t&, result_t& result) {
	try {
		reset_cancellation();
		const auto executable_root = executable_directory();
		if (executable_root.empty()) {
			result.outcome = outcome_e::integrity_failure;
			result.error = "C03 safe-headless executable directory is unavailable";
			return;
		}
		const auto root = executable_root / L"c03-safe-headless";
		const auto manifest_path = root / L"manifest.json";
		const auto loaded = load_manifest(root, manifest_path);
		if (!loaded.accepted) {
			result.outcome = cancellation_requested() ? outcome_e::cancelled : outcome_e::integrity_failure;
			result.skipped = result.outcome == outcome_e::cancelled;
			result.error = loaded.error;
			return;
		}
		diag::log_tagged_fmt("testlab.c03_safe_headless",
			"suite_start manifest_sha256=%s build_identity=%s contract_identity=%s entries=%zu",
			loaded.manifest_sha256.c_str(), loaded.manifest.build_identity.c_str(),
			loaded.manifest.contract_identity.c_str(), loaded.manifest.entries.size());
		const auto suite = execute_manifest(root, loaded, [] { return cancellation_requested(); },
			[](std::size_t completed, std::size_t total, const entry_result_t& entry) {
				diag::log_tagged_fmt("testlab.c03_safe_headless",
					"suite_progress completed=%zu total=%zu id=%s outcome=%s pid=%u exit=0x%08X elapsed_us=%llu",
					completed, total, entry.id.c_str(), outcome_name(entry.outcome), entry.process_id,
					entry.exit_code, static_cast<unsigned long long>(entry.elapsed_us));
			});
		const auto aggregate = aggregate_outcome(suite);
		result.outcome = to_testlab_outcome(aggregate);
		result.ok = aggregate == entry_outcome_e::passed;
		result.skipped = aggregate == entry_outcome_e::not_run || aggregate == entry_outcome_e::cancelled;
		result.elapsed_us = suite.elapsed_us;
		std::uint64_t assertion_total = 0;
		for (const auto& entry : suite.entries) {
			assertion_total += entry.assertions.total;
			result.parsed.push_back({entry.id, outcome_name(entry.outcome)});
		}
		result.bytes_returned = static_cast<std::uint32_t>((std::min)(assertion_total,
			static_cast<std::uint64_t>(std::numeric_limits<std::uint32_t>::max())));
		result.parsed.insert(result.parsed.begin(), {
			{"manifest_sha256", suite.manifest_sha256},
			{"build_identity", suite.build_identity},
			{"contract_identity", suite.contract_identity},
			{"passed", std::to_string(suite.passed)},
			{"failed", std::to_string(suite.failed)},
			{"missing", std::to_string(suite.missing)},
			{"timed_out", std::to_string(suite.timed_out)},
			{"crashed", std::to_string(suite.crashed)},
			{"cancelled", std::to_string(suite.cancelled)},
			{"malformed_result", std::to_string(suite.malformed_result)},
			{"integrity_failure", std::to_string(suite.integrity_failure)},
			{"not_run", std::to_string(suite.not_run)}
		});
		const auto serialized = serialize_suite_result(suite);
		if (serialized.size() <= k_result_max_bytes) {
			result.raw.assign(serialized.begin(), serialized.end());
		} else {
			result.parsed.push_back({"suite_result", "omitted_size_limit"});
		}
		if (!result.ok) result.error = "C03 safe-headless suite completed with outcome " + std::string(outcome_name(aggregate));
		diag::log_tagged_fmt("testlab.c03_safe_headless",
			"suite_exit outcome=%s entries=%zu passed=%u failed=%u missing=%u timed_out=%u crashed=%u cancelled=%u malformed=%u integrity=%u not_run=%u elapsed_us=%llu",
			outcome_name(aggregate), suite.entries.size(), suite.passed, suite.failed, suite.missing,
			suite.timed_out, suite.crashed, suite.cancelled, suite.malformed_result,
			suite.integrity_failure, suite.not_run, static_cast<unsigned long long>(suite.elapsed_us));
	} catch (const std::exception& exception) {
		result.ok = false;
		result.skipped = false;
		result.outcome = outcome_e::failed;
		result.raw.clear();
		result.parsed.clear();
		result.error = std::string("C03 safe-headless execution failed: ") + exception.what();
	} catch (...) {
		result.ok = false;
		result.skipped = false;
		result.outcome = outcome_e::failed;
		result.raw.clear();
		result.parsed.clear();
		result.error = "C03 safe-headless execution failed with a non-standard exception";
	}
}

}

const char* outcome_name(entry_outcome_e outcome) noexcept {
	switch (outcome) {
		case entry_outcome_e::not_run: return "not_run";
		case entry_outcome_e::missing: return "missing";
		case entry_outcome_e::passed: return "passed";
		case entry_outcome_e::failed: return "failed";
		case entry_outcome_e::timed_out: return "timed_out";
		case entry_outcome_e::crashed: return "crashed";
		case entry_outcome_e::cancelled: return "cancelled";
		case entry_outcome_e::malformed_result: return "malformed_result";
		case entry_outcome_e::integrity_failure: return "integrity_failure";
	}
	return "not_run";
}

outcome_e to_testlab_outcome(entry_outcome_e outcome) noexcept {
	switch (outcome) {
		case entry_outcome_e::not_run: return outcome_e::not_run;
		case entry_outcome_e::missing: return outcome_e::missing;
		case entry_outcome_e::passed: return outcome_e::passed;
		case entry_outcome_e::failed: return outcome_e::failed;
		case entry_outcome_e::timed_out: return outcome_e::timed_out;
		case entry_outcome_e::crashed: return outcome_e::crashed;
		case entry_outcome_e::cancelled: return outcome_e::cancelled;
		case entry_outcome_e::malformed_result: return outcome_e::malformed_result;
		case entry_outcome_e::integrity_failure: return outcome_e::integrity_failure;
	}
	return outcome_e::integrity_failure;
}

manifest_load_result_t load_manifest(const std::filesystem::path& approved_root,
	const std::filesystem::path& manifest_path) {
	manifest_load_result_t result;
	std::string error;
	if (approved_root.empty() || manifest_path.empty() ||
		!path_components_are_non_reparse(approved_root, false, error) ||
		!path_components_are_non_reparse(manifest_path, false, error) ||
		!path_is_within(approved_root, manifest_path)) {
		result.error = error.empty() ? "manifest path escapes the approved root" : std::move(error);
		return result;
	}
	file_identity_t identity;
	std::string bytes;
	if (!read_bounded_file(manifest_path, k_manifest_max_bytes, bytes, identity, result.error)) return result;
	result.manifest_sha256 = identity.sha256;
	json root;
	try {
		root = json::parse(bytes);
	} catch (...) {
		result.error = "manifest is not valid JSON";
		return result;
	}
	if (!exact_keys(root, {"schema", "version", "build_identity", "contract_identity", "entries"}, result.error))
		return result;
	if (!root.at("schema").is_string() || root.at("schema").get<std::string>() != k_manifest_schema ||
		!root.at("version").is_number_unsigned() || root.at("version").get<std::uint64_t>() != k_manifest_version ||
		!root.at("build_identity").is_string() || !root.at("contract_identity").is_string() ||
		!root.at("entries").is_array() || root.at("entries").empty() || root.at("entries").size() > k_max_entry_count) {
		result.error = "manifest schema, version, identities, or entry cardinality is invalid";
		return result;
	}
	result.manifest.build_identity = root.at("build_identity").get<std::string>();
	result.manifest.contract_identity = root.at("contract_identity").get<std::string>();
	if (!hex_digest(result.manifest.build_identity) || !hex_digest(result.manifest.contract_identity)) {
		result.error = "manifest build or contract identity is invalid";
		return result;
	}
	std::unordered_set<std::string> ids;
	std::unordered_set<std::string> targets;
	std::unordered_set<std::string> paths;
	std::unordered_set<std::string> categories;
	for (const auto& item : root.at("entries")) {
		manifest_entry_t entry;
		if (!parse_entry(item, entry, result.error)) return result;
		if (entry.build_identity != result.manifest.build_identity || !ids.emplace(entry.id).second ||
			!targets.emplace(entry.source_target).second ||
			!paths.emplace(entry.executable_relative_path.generic_u8string()).second) {
			result.error = "manifest contains a duplicate identity, target, executable, or mismatched build";
			return result;
		}
		categories.emplace(entry.category);
		result.manifest.entries.push_back(std::move(entry));
	}
	static constexpr std::array<std::string_view, 18> required_categories{{
		"contract", "fixture", "provider", "layout", "store", "scheduler",
		"reader", "container", "decode", "recovery", "query", "persistence", "decompiler",
		"worker", "mcp", "workbench", "performance", "surface"
	}};
	for (const auto category : required_categories) {
		if (categories.find(std::string(category)) == categories.end()) {
			result.error = "manifest is missing required category coverage: " + std::string(category);
			return result;
		}
	}
	file_identity_t after;
	if (!compute_file_identity(manifest_path, after, result.error) || !same_identity(identity, after)) {
		result.error = "manifest identity changed while it was parsed";
		return result;
	}
	result.accepted = true;
	return result;
}

entry_result_t execute_entry(const std::filesystem::path& approved_root, const manifest_entry_t& entry,
	const cancellation_probe_t& cancellation, const deadline_probe_t& deadline) {
	entry_result_t result;
	result.id = entry.id;
	if (!entry_contract_valid(entry)) {
		result.outcome = entry_outcome_e::integrity_failure;
		result.error = "entry contract is invalid at execution time";
		diag::log_tagged_fmt("testlab.c03_safe_headless", "entry_rejected reason=invalid_contract");
		return result;
	}
	const auto audit_started = std::chrono::steady_clock::now();
	struct audit_scope_t {
		const manifest_entry_t& entry;
		entry_result_t& result;
		std::chrono::steady_clock::time_point started;
		~audit_scope_t() {
			const auto observed_us = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(
				std::chrono::steady_clock::now() - started).count());
			diag::log_tagged_fmt("testlab.c03_safe_headless",
				"entry_exit host_pid=%lu host_tid=%lu id=%s category=%s target=%s outcome=%s pid=%u exit=0x%08X elapsed_us=%llu observed_us=%llu peak_job_memory=%llu stdout=%zu stderr=%zu evidence=%zu error=\"%.512s\"",
				static_cast<unsigned long>(GetCurrentProcessId()), static_cast<unsigned long>(GetCurrentThreadId()),
				entry.id.c_str(), entry.category.c_str(), entry.source_target.c_str(), outcome_name(result.outcome),
				result.process_id, result.exit_code,
				static_cast<unsigned long long>(result.elapsed_us),
				static_cast<unsigned long long>(observed_us),
				static_cast<unsigned long long>(result.peak_job_memory_bytes),
				result.stdout_text.size(), result.stderr_text.size(), result.evidence.size(), result.error.c_str());
		}
	} audit_scope{entry, result, audit_started};
	diag::log_tagged_fmt("testlab.c03_safe_headless",
		"entry_start host_pid=%lu host_tid=%lu id=%s category=%s target=%s executable=%s active_processes=%u wall_ms=%u private_bytes=%llu runtime_files=%zu",
		static_cast<unsigned long>(GetCurrentProcessId()), static_cast<unsigned long>(GetCurrentThreadId()),
		entry.id.c_str(), entry.category.c_str(), entry.source_target.c_str(),
		entry.executable_relative_path.generic_u8string().c_str(), entry.max_active_processes, entry.max_wall_ms,
		static_cast<unsigned long long>(entry.max_private_bytes), entry.runtime_files.size());
	const auto cancelled = [&] {
		return g_cancellation_requested.load(std::memory_order_acquire) || (cancellation && cancellation());
	};
	if (cancelled()) {
		result.outcome = entry_outcome_e::cancelled;
		result.error = "execution was cancelled before launch";
		return result;
	}
	const auto executable = (approved_root / entry.executable_relative_path).lexically_normal();
	const auto working_directory = (approved_root / entry.working_directory_relative_path).lexically_normal();
	std::string error;
	if (!path_is_within(approved_root, executable) || !path_is_within(approved_root, working_directory) ||
		!path_components_are_non_reparse(approved_root, false, error) ||
		!path_components_are_non_reparse(working_directory, false, error)) {
		result.outcome = entry_outcome_e::integrity_failure;
		result.error = error.empty() ? "entry path escapes the approved root" : std::move(error);
		return result;
	}
	const DWORD working_attributes = GetFileAttributesW(working_directory.c_str());
	if (working_attributes == INVALID_FILE_ATTRIBUTES ||
		(working_attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != FILE_ATTRIBUTE_DIRECTORY) {
		result.outcome = entry_outcome_e::integrity_failure;
		result.error = "entry working directory is not a regular non-reparse directory";
		return result;
	}
	const DWORD attributes = GetFileAttributesW(executable.c_str());
	if (attributes == INVALID_FILE_ATTRIBUTES) {
		const DWORD code = GetLastError();
		result.outcome = code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND ?
			entry_outcome_e::missing : entry_outcome_e::integrity_failure;
		result.error = result.outcome == entry_outcome_e::missing ?
			"registered harness executable is missing" : win32_error("GetFileAttributesW(harness)", code);
		return result;
	}
	if (!path_components_are_non_reparse(executable, false, error)) {
		result.outcome = entry_outcome_e::integrity_failure;
		result.error = std::move(error);
		return result;
	}
	handle_t executable_lock(CreateFileW(executable.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN | FILE_FLAG_OPEN_REPARSE_POINT,
		nullptr));
	if (!executable_lock) {
		result.outcome = entry_outcome_e::integrity_failure;
		result.error = win32_error("CreateFileW(harness lock)");
		return result;
	}
	file_identity_t before;
	if (!compute_file_identity(executable, before, result.error, cancelled) || before.size != entry.executable_size ||
		before.sha256 != entry.executable_sha256) {
		result.outcome = cancelled() ? entry_outcome_e::cancelled : entry_outcome_e::integrity_failure;
		if (result.error.empty()) result.error = "harness executable identity does not match the manifest";
		return result;
	}
	diag::log_tagged_fmt("testlab.c03_safe_headless",
		"entry_identity_verified id=%s executable_size=%llu executable_sha256=%s",
		entry.id.c_str(), static_cast<unsigned long long>(before.size), before.sha256.c_str());
	std::vector<handle_t> runtime_locks;
	runtime_locks.reserve(entry.runtime_files.size());
	for (const auto& runtime_file : entry.runtime_files) {
		const auto path = (approved_root / runtime_file.relative_path).lexically_normal();
		if (!path_is_within(approved_root, path)) {
			result.outcome = entry_outcome_e::integrity_failure;
			result.error = "runtime fixture path escapes the approved root";
			return result;
		}
		if (!path_components_are_non_reparse(path, false, error)) {
			const DWORD path_error = GetLastError();
			result.outcome = path_error == ERROR_FILE_NOT_FOUND || path_error == ERROR_PATH_NOT_FOUND ?
				entry_outcome_e::missing : entry_outcome_e::integrity_failure;
			result.error = result.outcome == entry_outcome_e::missing ?
				"registered runtime fixture is missing" :
				(error.empty() ? "runtime fixture path is unsafe" : std::move(error));
			return result;
		}
		handle_t lock(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
		if (!lock) {
			const DWORD code = GetLastError();
			result.outcome = code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND ?
				entry_outcome_e::missing : entry_outcome_e::integrity_failure;
			result.error = win32_error("CreateFileW(runtime fixture)", code);
			return result;
		}
		file_identity_t identity;
		if (!compute_file_identity(path, identity, result.error, cancelled) ||
			identity.size != runtime_file.size || identity.sha256 != runtime_file.sha256) {
			result.outcome = cancelled() ? entry_outcome_e::cancelled : entry_outcome_e::integrity_failure;
			if (result.error.empty()) result.error = "runtime fixture identity does not match the manifest";
			return result;
		}
		runtime_locks.push_back(std::move(lock));
	}
	pipe_pair_t stdout_pipe;
	pipe_pair_t stderr_pipe;
	pipe_pair_t result_pipe;
	if (!create_pipe_pair(stdout_pipe, result.error) || !create_pipe_pair(stderr_pipe, result.error) ||
		!create_pipe_pair(result_pipe, result.error)) {
		result.outcome = entry_outcome_e::failed;
		return result;
	}
	SECURITY_ATTRIBUTES null_attributes{};
	null_attributes.nLength = sizeof(null_attributes);
	null_attributes.bInheritHandle = TRUE;
	handle_t null_input(CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
		&null_attributes, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
	if (!null_input) {
		result.outcome = entry_outcome_e::failed;
		result.error = win32_error("CreateFileW(NUL)");
		return result;
	}
	handle_t job(CreateJobObjectW(nullptr, nullptr));
	if (!job) {
		result.outcome = entry_outcome_e::failed;
		result.error = win32_error("CreateJobObjectW");
		return result;
	}
	JOBOBJECT_EXTENDED_LIMIT_INFORMATION job_limits{};
	job_limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_ACTIVE_PROCESS |
		JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION |
		JOB_OBJECT_LIMIT_PROCESS_MEMORY | JOB_OBJECT_LIMIT_JOB_MEMORY;
	job_limits.BasicLimitInformation.ActiveProcessLimit = entry.max_active_processes;
	job_limits.ProcessMemoryLimit = static_cast<SIZE_T>(entry.max_private_bytes);
	job_limits.JobMemoryLimit = static_cast<SIZE_T>(entry.max_private_bytes);
	if (!SetInformationJobObject(job.get(), JobObjectExtendedLimitInformation, &job_limits, sizeof(job_limits))) {
		result.outcome = entry_outcome_e::failed;
		result.error = win32_error("SetInformationJobObject");
		return result;
	}
	JOBOBJECT_BASIC_UI_RESTRICTIONS ui_limits{};
	ui_limits.UIRestrictionsClass = JOB_OBJECT_UILIMIT_DESKTOP | JOB_OBJECT_UILIMIT_DISPLAYSETTINGS |
		JOB_OBJECT_UILIMIT_EXITWINDOWS | JOB_OBJECT_UILIMIT_GLOBALATOMS | JOB_OBJECT_UILIMIT_HANDLES |
		JOB_OBJECT_UILIMIT_READCLIPBOARD | JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS | JOB_OBJECT_UILIMIT_WRITECLIPBOARD;
	if (!SetInformationJobObject(job.get(), JobObjectBasicUIRestrictions, &ui_limits, sizeof(ui_limits))) {
		result.outcome = entry_outcome_e::failed;
		result.error = win32_error("SetInformationJobObject(UI)");
		return result;
	}
	SIZE_T attribute_bytes = 0;
	InitializeProcThreadAttributeList(nullptr, 1, 0, &attribute_bytes);
	if (attribute_bytes == 0) {
		result.outcome = entry_outcome_e::failed;
		result.error = win32_error("InitializeProcThreadAttributeList");
		return result;
	}
	std::vector<std::uint8_t> attribute_storage(attribute_bytes);
	auto* attributes_list = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attribute_storage.data());
	if (!InitializeProcThreadAttributeList(attributes_list, 1, 0, &attribute_bytes)) {
		result.outcome = entry_outcome_e::failed;
		result.error = win32_error("InitializeProcThreadAttributeList");
		return result;
	}
	struct attribute_guard_t {
		LPPROC_THREAD_ATTRIBUTE_LIST value;
		~attribute_guard_t() { if (value) DeleteProcThreadAttributeList(value); }
	} attribute_guard{attributes_list};
	std::array<HANDLE, 4> inherited{{null_input.get(), stdout_pipe.write.get(), stderr_pipe.write.get(), result_pipe.write.get()}};
	if (!UpdateProcThreadAttribute(attributes_list, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
		inherited.data(), inherited.size() * sizeof(HANDLE), nullptr, nullptr)) {
		result.outcome = entry_outcome_e::failed;
		result.error = win32_error("UpdateProcThreadAttribute");
		return result;
	}
	std::wstring command = quote_argument(executable.wstring());
	for (const auto& argument : entry.arguments) {
		const auto wide = utf8_to_wide(argument);
		if (wide.empty()) {
			result.outcome = entry_outcome_e::integrity_failure;
			result.error = "manifest argument is not valid UTF-8";
			return result;
		}
		command.push_back(L' ');
		command.append(quote_argument(wide));
	}
	const auto append_control = [&](std::wstring_view name, std::wstring value) {
		command.push_back(L' ');
		command.append(name);
		command.append(quote_argument(value));
	};
	append_control(L"--aida-c03-result-handle=", std::to_wstring(reinterpret_cast<std::uintptr_t>(result_pipe.write.get())));
	append_control(L"--aida-c03-entry-id=", utf8_to_wide(entry.id));
	append_control(L"--aida-c03-source-target=", utf8_to_wide(entry.source_target));
	append_control(L"--aida-c03-build-identity=", utf8_to_wide(entry.build_identity));
	if (command.size() >= 32767) {
		result.outcome = entry_outcome_e::integrity_failure;
		result.error = "harness command line exceeds the Windows process limit";
		return result;
	}
	STARTUPINFOEXW startup{};
	startup.StartupInfo.cb = sizeof(startup);
	startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
	startup.StartupInfo.wShowWindow = SW_HIDE;
	startup.StartupInfo.hStdInput = null_input.get();
	startup.StartupInfo.hStdOutput = stdout_pipe.write.get();
	startup.StartupInfo.hStdError = stderr_pipe.write.get();
	startup.lpAttributeList = attributes_list;
	PROCESS_INFORMATION process_info{};
	std::vector<wchar_t> command_buffer(command.begin(), command.end());
	command_buffer.push_back(L'\0');
	const auto started = std::chrono::steady_clock::now();
	if (!CreateProcessW(executable.c_str(), command_buffer.data(), nullptr, nullptr, TRUE,
		CREATE_SUSPENDED | CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT,
		nullptr, working_directory.c_str(), &startup.StartupInfo, &process_info)) {
		result.outcome = entry_outcome_e::failed;
		result.error = win32_error("CreateProcessW");
		return result;
	}
	handle_t process(process_info.hProcess);
	handle_t thread(process_info.hThread);
	result.process_id = process_info.dwProcessId;
	stdout_pipe.write.reset();
	stderr_pipe.write.reset();
	result_pipe.write.reset();
	null_input.reset();
	diag::log_tagged_fmt("testlab.c03_safe_headless",
		"entry_process_created_suspended id=%s pid=%lu tid=%lu",
		entry.id.c_str(), static_cast<unsigned long>(process_info.dwProcessId),
		static_cast<unsigned long>(process_info.dwThreadId));
	if (!AssignProcessToJobObject(job.get(), process.get())) {
		TerminateProcess(process.get(), k_runner_termination_code);
		WaitForSingleObject(process.get(), 5000);
		result.outcome = entry_outcome_e::failed;
		result.error = win32_error("AssignProcessToJobObject");
		return result;
	}
	file_identity_t after_launch;
	if (!compute_file_identity(executable, after_launch, result.error, cancelled) || !same_identity(before, after_launch)) {
		TerminateJobObject(job.get(), k_runner_termination_code);
		WaitForSingleObject(process.get(), 5000);
		result.outcome = cancelled() ? entry_outcome_e::cancelled : entry_outcome_e::integrity_failure;
		if (result.outcome == entry_outcome_e::integrity_failure)
			result.error = "harness executable identity changed during launch";
		return result;
	}
	if (ResumeThread(thread.get()) == static_cast<DWORD>(-1)) {
		TerminateJobObject(job.get(), k_runner_termination_code);
		WaitForSingleObject(process.get(), 5000);
		result.outcome = entry_outcome_e::failed;
		result.error = win32_error("ResumeThread");
		return result;
	}
	diag::log_tagged_fmt("testlab.c03_safe_headless",
		"entry_process_resumed id=%s pid=%lu job_active_limit=%u wall_ms=%u private_bytes=%llu",
		entry.id.c_str(), static_cast<unsigned long>(process_info.dwProcessId), entry.max_active_processes,
		entry.max_wall_ms,
		static_cast<unsigned long long>(entry.max_private_bytes));
	thread.reset();
	process_capture_t capture;
	capture.result.id = entry.id;
	capture.result.process_id = result.process_id;
	bool terminated_by_runner = false;
	for (;;) {
		if (!drain_pipe(stdout_pipe.read.get(), capture.result.stdout_text, entry.max_stdout_bytes,
			capture.stdout_overflow, error) || !drain_pipe(stderr_pipe.read.get(), capture.result.stderr_text,
			entry.max_stderr_bytes, capture.stderr_overflow, error) || !drain_pipe(result_pipe.read.get(),
			capture.result_bytes, entry.max_result_bytes, capture.result_overflow, error)) {
			capture.result.outcome = entry_outcome_e::failed;
			capture.result.error = std::move(error);
			terminated_by_runner = true;
			TerminateJobObject(job.get(), k_runner_termination_code);
			break;
		}
		if (capture.stdout_overflow || capture.stderr_overflow || capture.result_overflow) {
			capture.result.outcome = entry_outcome_e::failed;
			capture.result.error = "child output exceeded a manifest-bound capture limit";
			terminated_by_runner = true;
			TerminateJobObject(job.get(), k_runner_termination_code);
			break;
		}
		if (cancelled()) {
			capture.result.outcome = entry_outcome_e::cancelled;
			capture.result.error = "execution was cancelled";
			terminated_by_runner = true;
			TerminateJobObject(job.get(), ERROR_CANCELLED);
			break;
		}
		const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
			std::chrono::steady_clock::now() - started).count();
		const bool probe_expired = deadline && deadline();
		if (probe_expired || elapsed > entry.max_wall_ms) {
			capture.result.outcome = entry_outcome_e::timed_out;
			capture.result.error = probe_expired ? "execution deadline probe expired" :
				"harness exceeded its manifest wall deadline";
			terminated_by_runner = true;
			TerminateJobObject(job.get(), WAIT_TIMEOUT);
			break;
		}
		const DWORD wait = WaitForSingleObject(process.get(), 10);
		if (wait == WAIT_OBJECT_0) break;
		if (wait != WAIT_TIMEOUT) {
			capture.result.outcome = entry_outcome_e::failed;
			capture.result.error = win32_error("WaitForSingleObject");
			terminated_by_runner = true;
			TerminateJobObject(job.get(), k_runner_termination_code);
			break;
		}
	}
	DWORD final_wait = WaitForSingleObject(process.get(), 5000);
	if (final_wait == WAIT_TIMEOUT) {
		TerminateProcess(process.get(), k_runner_termination_code);
		final_wait = WaitForSingleObject(process.get(), 5000);
	}
	if (final_wait != WAIT_OBJECT_0) {
		capture.result.outcome = entry_outcome_e::failed;
		capture.result.error = "harness process could not be reaped after termination";
		terminated_by_runner = true;
	}
	const bool final_drain_ok = drain_pipe(stdout_pipe.read.get(), capture.result.stdout_text,
		entry.max_stdout_bytes, capture.stdout_overflow, error) &&
		drain_pipe(stderr_pipe.read.get(), capture.result.stderr_text, entry.max_stderr_bytes,
			capture.stderr_overflow, error) &&
		drain_pipe(result_pipe.read.get(), capture.result_bytes, entry.max_result_bytes,
			capture.result_overflow, error);
	if (!terminated_by_runner && (!final_drain_ok || capture.stdout_overflow || capture.stderr_overflow ||
		capture.result_overflow)) {
		capture.result.outcome = entry_outcome_e::failed;
		capture.result.error = final_drain_ok ? "child output exceeded a manifest-bound capture limit" : std::move(error);
		terminated_by_runner = true;
	}
	DWORD exit_code = 0;
	if (!GetExitCodeProcess(process.get(), &exit_code)) {
		capture.result.outcome = entry_outcome_e::failed;
		capture.result.error = win32_error("GetExitCodeProcess");
	} else {
		capture.result.exit_code = exit_code;
	}
	JOBOBJECT_EXTENDED_LIMIT_INFORMATION observed{};
	if (QueryInformationJobObject(job.get(), JobObjectExtendedLimitInformation, &observed,
		sizeof(observed), nullptr)) {
		capture.result.peak_job_memory_bytes = static_cast<std::uint64_t>(observed.PeakJobMemoryUsed);
	}
	const auto finished = std::chrono::steady_clock::now();
	const auto observed_us = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(
		finished - started).count());
	file_identity_t after_exit;
	if (!compute_file_identity(executable, after_exit, error, cancelled) || !same_identity(before, after_exit)) {
		capture.result.outcome = cancelled() ? entry_outcome_e::cancelled : entry_outcome_e::integrity_failure;
		capture.result.error = capture.result.outcome == entry_outcome_e::cancelled ?
			"execution was cancelled before result acceptance" :
			"harness executable identity changed before result acceptance";
		result = std::move(capture.result);
		return result;
	}
	if (!terminated_by_runner) {
		if (crash_exit_code(exit_code)) {
			capture.result.outcome = entry_outcome_e::crashed;
			capture.result.error = "harness terminated with an exception status";
		} else if (!parse_result_envelope(entry, capture.result_bytes, exit_code, capture.result)) {
			capture.result.outcome = entry_outcome_e::malformed_result;
		}
	}
	if (capture.result.elapsed_us == 0) capture.result.elapsed_us = observed_us;
	result = std::move(capture.result);
	return result;
}

suite_result_t execute_manifest(const std::filesystem::path& approved_root,
	const manifest_load_result_t& loaded, const cancellation_probe_t& cancellation,
	const progress_sink_t& progress) {
	suite_result_t suite;
	suite.manifest_sha256 = loaded.manifest_sha256;
	suite.build_identity = loaded.manifest.build_identity;
	suite.contract_identity = loaded.manifest.contract_identity;
	const auto started = std::chrono::steady_clock::now();
	suite.entries.reserve(loaded.manifest.entries.size());
	if (loaded.manifest.entries.empty()) {
		entry_result_t rejected;
		rejected.id = "manifest";
		rejected.outcome = entry_outcome_e::integrity_failure;
		rejected.error = loaded.error.empty() ? "manifest contains no executable entries" : loaded.error;
		increment_outcome(suite, rejected.outcome);
		suite.entries.push_back(std::move(rejected));
		if (progress) progress(1, 1, suite.entries.back());
	}
	std::uint64_t captured_bytes = 0;
	bool suite_budget_exhausted = false;
	for (std::size_t index = 0; index < loaded.manifest.entries.size(); ++index) {
		entry_result_t current;
		const bool skipped_for_budget = suite_budget_exhausted ||
			std::chrono::steady_clock::now() - started > k_suite_wall_limit;
		if (!loaded.accepted) {
			current.id = loaded.manifest.entries[index].id;
			current.outcome = entry_outcome_e::integrity_failure;
			current.error = loaded.error.empty() ? "manifest was not accepted" : loaded.error;
		} else if (skipped_for_budget) {
			current.id = loaded.manifest.entries[index].id;
			current.outcome = entry_outcome_e::not_run;
			current.error = "suite aggregate resource budget was exhausted";
			suite_budget_exhausted = true;
		} else if (g_cancellation_requested.load(std::memory_order_acquire) || (cancellation && cancellation())) {
			current.id = loaded.manifest.entries[index].id;
			current.outcome = entry_outcome_e::not_run;
			current.error = "suite was cancelled before this entry started";
		} else {
			current = execute_entry(approved_root, loaded.manifest.entries[index], cancellation);
		}
		if (!skipped_for_budget) {
			captured_bytes += current.stdout_text.size() + current.stderr_text.size() + current.error.size();
			for (const auto& field : current.evidence) captured_bytes += field.name.size() + field.value.size();
			if (captured_bytes > k_suite_capture_max_bytes) {
				current.stdout_text.clear();
				current.stderr_text.clear();
				current.evidence.clear();
				current.outcome = entry_outcome_e::failed;
				current.error = "suite aggregate capture budget was exceeded";
				suite_budget_exhausted = true;
			}
		}
		increment_outcome(suite, current.outcome);
		suite.entries.push_back(std::move(current));
		if (progress) progress(index + 1, loaded.manifest.entries.size(), suite.entries.back());
	}
	suite.elapsed_us = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(
		std::chrono::steady_clock::now() - started).count());
	return suite;
}

std::string serialize_suite_result(const suite_result_t& result) {
	json root = {
		{"schema", "aida.c03.safe-headless.suite-result.v1"},
		{"version", 1},
		{"build_identity", result.build_identity},
		{"contract_identity", result.contract_identity},
		{"manifest_sha256", result.manifest_sha256},
		{"elapsed_us", result.elapsed_us},
		{"counts", {
			{"not_run", result.not_run}, {"missing", result.missing}, {"passed", result.passed},
			{"failed", result.failed}, {"timed_out", result.timed_out}, {"crashed", result.crashed},
			{"cancelled", result.cancelled}, {"malformed_result", result.malformed_result},
			{"integrity_failure", result.integrity_failure}
		}},
		{"entries", json::array()}
	};
	for (const auto& entry : result.entries) {
		json evidence = json::array();
		for (const auto& field : entry.evidence) evidence.push_back({{"name", field.name}, {"value", field.value}});
		root["entries"].push_back({
			{"id", entry.id}, {"outcome", outcome_name(entry.outcome)},
			{"assertions", {{"total", entry.assertions.total}, {"passed", entry.assertions.passed},
				{"failed", entry.assertions.failed}, {"skipped", entry.assertions.skipped},
				{"not_run", entry.assertions.not_run}}},
			{"elapsed_us", entry.elapsed_us}, {"process_id", entry.process_id}, {"exit_code", entry.exit_code},
			{"peak_job_memory_bytes", entry.peak_job_memory_bytes}, {"stdout", entry.stdout_text},
			{"stderr", entry.stderr_text}, {"evidence", std::move(evidence)}, {"error", entry.error}
		});
	}
	return root.dump();
}

void request_cancellation() noexcept {
	g_cancellation_requested.store(true, std::memory_order_release);
}

void reset_cancellation() noexcept {
	g_cancellation_requested.store(false, std::memory_order_release);
}

bool cancellation_requested() noexcept {
	return g_cancellation_requested.load(std::memory_order_acquire);
}

bool is_feature(const feature_t& feature) noexcept {
	return feature.driver == driver_e::driverless && feature.category != nullptr && feature.name != nullptr &&
		std::strcmp(feature.category, "c03-safe-headless") == 0 &&
		std::strcmp(feature.name, "C03 Safe Headless") == 0;
}

TESTLAB_REGISTER(g_c03_safe_headless_feature, "c03-safe-headless", test_lab::driver_e::driverless,
	"C03 Safe Headless", "Runs the verified, driverless C03 safe-headless manifest under bounded Job Object isolation.",
	render_inputs, run_feature)

}
