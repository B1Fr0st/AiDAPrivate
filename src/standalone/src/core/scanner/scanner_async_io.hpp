#pragma once

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <system_error>

#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#endif

namespace scanner_async_io {

inline constexpr std::size_t max_serialized_bytes = 64ULL * 1024ULL * 1024ULL;
inline constexpr std::uint8_t operation_reversible = 0;
inline constexpr std::uint8_t operation_cancelled = 1;
inline constexpr std::uint8_t operation_committing = 2;

struct result_t {
	bool success = false;
	bool cancelled = false;
	std::string error;
};

inline bool cancellation_requested(const std::shared_ptr<std::atomic<bool>>& cancellation)
{
	return cancellation && cancellation->load(std::memory_order_acquire);
}

#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)

inline std::atomic<std::uint64_t> temporary_sequence{1};

inline result_t read_bounded(const std::string& path, std::size_t limit,
	const std::shared_ptr<std::atomic<bool>>& cancellation, std::string& output)
{
	result_t result;
	output.clear();
	if (path.empty() || path.size() > 4096 || limit == 0 || limit > max_serialized_bytes) {
		result.error = "The scanner input path or size limit is invalid";
		return result;
	}
	if (cancellation_requested(cancellation)) {
		result.cancelled = true;
		result.error = "Scanner file read cancelled";
		return result;
	}
	HANDLE file = CreateFileA(path.c_str(), GENERIC_READ,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
	if (file == INVALID_HANDLE_VALUE) {
		result.error = "Cannot open scanner input (Win32 " + std::to_string(GetLastError()) + ")";
		return result;
	}
	LARGE_INTEGER size{};
	if (!GetFileSizeEx(file, &size) || size.QuadPart < 0 ||
		static_cast<unsigned long long>(size.QuadPart) > limit) {
		result.error = "Scanner input exceeds the bounded file-size limit";
		CloseHandle(file);
		return result;
	}
	output.resize(static_cast<std::size_t>(size.QuadPart));
	std::size_t offset = 0;
	while (offset < output.size()) {
		if (cancellation_requested(cancellation)) {
			result.cancelled = true;
			result.error = "Scanner file read cancelled";
			break;
		}
		const DWORD chunk = static_cast<DWORD>((std::min)(output.size() - offset,
			static_cast<std::size_t>(1024 * 1024)));
		DWORD read = 0;
		if (!ReadFile(file, output.data() + offset, chunk, &read, nullptr) || read != chunk) {
			result.error = "Scanner input read was partial or failed (Win32 " +
				std::to_string(GetLastError()) + ")";
			break;
		}
		offset += read;
	}
	CloseHandle(file);
	if (!result.error.empty()) {
		output.clear();
		return result;
	}
	result.success = true;
	return result;
}

template <typename Precommit>
inline result_t atomic_replace(const std::string& destination, const std::string& payload,
	bool create_parent, const std::shared_ptr<std::atomic<bool>>& cancellation,
	Precommit&& precommit,
	const std::shared_ptr<std::atomic<std::uint8_t>>& commit_gate = {})
{
	result_t result;
	if (destination.empty() || destination.size() > 4096 || payload.size() > max_serialized_bytes) {
		result.error = "The scanner export destination or payload is invalid";
		return result;
	}
	if (cancellation_requested(cancellation)) {
		result.cancelled = true;
		result.error = "Scanner export cancelled";
		return result;
	}
	if (create_parent) {
		std::error_code error;
		const auto parent = std::filesystem::path(destination).parent_path();
		if (!parent.empty()) std::filesystem::create_directories(parent, error);
		if (error) {
			result.error = "Cannot create scanner export directory: " + error.message();
			return result;
		}
	}
	const std::string temporary = destination + ".aida-tmp-" +
		std::to_string(GetCurrentProcessId()) + "-" +
		std::to_string(temporary_sequence.fetch_add(1, std::memory_order_acq_rel));
	HANDLE file = CreateFileA(temporary.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
		FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_WRITE_THROUGH, nullptr);
	if (file == INVALID_HANDLE_VALUE) {
		result.error = "Cannot create scanner export temporary (Win32 " +
			std::to_string(GetLastError()) + ")";
		return result;
	}
	std::size_t offset = 0;
	while (offset < payload.size()) {
		if (cancellation_requested(cancellation)) {
			result.cancelled = true;
			result.error = "Scanner export cancelled";
			break;
		}
		const DWORD chunk = static_cast<DWORD>((std::min)(payload.size() - offset,
			static_cast<std::size_t>(1024 * 1024)));
		DWORD written = 0;
		if (!WriteFile(file, payload.data() + offset, chunk, &written, nullptr) || written != chunk) {
			result.error = "Scanner export write was partial or failed (Win32 " +
				std::to_string(GetLastError()) + ")";
			break;
		}
		offset += written;
	}
	LARGE_INTEGER size{};
	if (result.error.empty() && (!FlushFileBuffers(file) || !GetFileSizeEx(file, &size) ||
		size.QuadPart != static_cast<LONGLONG>(payload.size())))
		result.error = "Scanner export flush or open-handle size verification failed";
	if (!CloseHandle(file) && result.error.empty())
		result.error = "Scanner export close failed (Win32 " + std::to_string(GetLastError()) + ")";
	WIN32_FILE_ATTRIBUTE_DATA attributes{};
	if (result.error.empty() && (!GetFileAttributesExA(temporary.c_str(), GetFileExInfoStandard,
		&attributes) || ((static_cast<std::uint64_t>(attributes.nFileSizeHigh) << 32) |
		static_cast<std::uint64_t>(attributes.nFileSizeLow)) != payload.size()))
		result.error = "Scanner export closed-file size verification failed";
	if (result.error.empty() && cancellation_requested(cancellation)) {
		result.cancelled = true;
		result.error = "Scanner export cancelled";
	}
	if (result.error.empty() && !precommit())
		result.error = "Scanner workspace, target, or source generation changed before commit";
	if (result.error.empty() && commit_gate) {
		std::uint8_t expected = operation_reversible;
		if (!commit_gate->compare_exchange_strong(expected, operation_committing,
			std::memory_order_acq_rel, std::memory_order_acquire)) {
			result.cancelled = expected == operation_cancelled;
			result.error = result.cancelled ? "Scanner export cancelled before commit" :
				"Scanner export commit ownership was unavailable";
		}
	}
	if (result.error.empty() && !MoveFileExA(temporary.c_str(), destination.c_str(),
		MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
		result.error = "Scanner export atomic replacement failed (Win32 " +
			std::to_string(GetLastError()) + ")";
	if (!result.error.empty()) {
		DeleteFileA(temporary.c_str());
		return result;
	}
	result.success = true;
	return result;
}

#endif

}
