#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include "live_snapshot_provider.hpp"

#include "../../runtime/standalone_driver.hpp"
#include "checked_range.hpp"

#include <algorithm>
#include <cstring>
#include <limits>
#include <utility>

namespace aida::analysis {
namespace {

struct handle_closer_t {
    void operator()(void* value) const noexcept {
        if (value && value != INVALID_HANDLE_VALUE)
            CloseHandle(static_cast<HANDLE>(value));
    }
};

using unique_handle_t = std::unique_ptr<void, handle_closer_t>;

workspace_error_t stop_error(const cancellation_token_t& cancel) {
    if (cancel.deadline_exceeded()) {
        auto error = make_workspace_error(workspace_error_code_t::deadline_exceeded,
                                          "snapshot deadline exceeded", "live_snapshot");
        error.deadline = true;
        return error;
    }
    auto error = make_workspace_error(workspace_error_code_t::cancelled,
                                      "snapshot cancelled", "live_snapshot");
    error.cancellation = true;
    return error;
}

workspace_result_t<std::string> wide_to_utf8(const std::wstring& text) {
    if (text.empty() || text.size() > static_cast<std::size_t>(std::numeric_limits<int>::max()))
        return workspace_result_t<std::string>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "process path length is invalid", "live_snapshot"));
    const int needed = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
                                           text.data(), static_cast<int>(text.size()),
                                           nullptr, 0, nullptr, nullptr);
    if (needed <= 0) {
        auto error = make_workspace_error(workspace_error_code_t::io_failure,
                                          "failed to encode process path", "live_snapshot");
        error.win32_status = GetLastError();
        return workspace_result_t<std::string>::failure(std::move(error));
    }
    std::string utf8(static_cast<std::size_t>(needed), '\0');
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
                            text.data(), static_cast<int>(text.size()),
                            utf8.data(), needed, nullptr, nullptr) != needed) {
        auto error = make_workspace_error(workspace_error_code_t::io_failure,
                                          "failed to encode process path", "live_snapshot");
        error.win32_status = GetLastError();
        return workspace_result_t<std::string>::failure(std::move(error));
    }
    return workspace_result_t<std::string>::success(std::move(utf8));
}

std::uint64_t filetime_value(const FILETIME& time) noexcept {
    ULARGE_INTEGER value{};
    value.LowPart = time.dwLowDateTime;
    value.HighPart = time.dwHighDateTime;
    return value.QuadPart;
}

workspace_result_t<process_identity_t> query_process_identity(std::uint32_t pid) {
    HANDLE raw_process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,
                                     FALSE, pid);
    if (!raw_process) {
        auto error = make_workspace_error(workspace_error_code_t::target_stale,
                                          "target process cannot be queried", "live_snapshot");
        error.win32_status = GetLastError();
        return workspace_result_t<process_identity_t>::failure(std::move(error));
    }
    unique_handle_t process(raw_process);
    DWORD exit_code = 0;
    if (!GetExitCodeProcess(raw_process, &exit_code)) {
        auto error = make_workspace_error(workspace_error_code_t::target_stale,
                                          "target process status is unavailable", "live_snapshot");
        error.win32_status = GetLastError();
        return workspace_result_t<process_identity_t>::failure(std::move(error));
    }
    if (exit_code != STILL_ACTIVE) {
        auto error = make_workspace_error(workspace_error_code_t::target_stale,
                                          "target process is no longer active", "live_snapshot");
        error.details.emplace_back("exit_code", std::to_string(exit_code));
        return workspace_result_t<process_identity_t>::failure(std::move(error));
    }
    FILETIME creation{};
    FILETIME exit{};
    FILETIME kernel{};
    FILETIME user{};
    if (!GetProcessTimes(raw_process, &creation, &exit, &kernel, &user)) {
        auto error = make_workspace_error(workspace_error_code_t::target_stale,
                                          "target process creation time is unavailable",
                                          "live_snapshot");
        error.win32_status = GetLastError();
        return workspace_result_t<process_identity_t>::failure(std::move(error));
    }
    std::wstring path(32768, L'\0');
    DWORD path_size = static_cast<DWORD>(path.size());
    if (!QueryFullProcessImageNameW(raw_process, 0, path.data(), &path_size) || path_size == 0) {
        auto error = make_workspace_error(workspace_error_code_t::target_stale,
                                          "target process path is unavailable", "live_snapshot");
        error.win32_status = GetLastError();
        return workspace_result_t<process_identity_t>::failure(std::move(error));
    }
    path.resize(path_size);
    auto utf8_result = wide_to_utf8(path);
    if (!utf8_result)
        return workspace_result_t<process_identity_t>::failure(utf8_result.error());
    auto normalized_result = normalize_utf8_path(utf8_result.value(), false);
    if (!normalized_result)
        return workspace_result_t<process_identity_t>::failure(normalized_result.error());
    process_identity_t identity;
    identity.pid = pid;
    identity.creation_time_100ns = filetime_value(creation);
    identity.normalized_process_path = normalize_target_name(normalized_result.take_value());
    return workspace_result_t<process_identity_t>::success(std::move(identity));
}

std::string normalize_module_component(std::string value) {
    std::replace(value.begin(), value.end(), '/', '\\');
    return normalize_target_name(std::move(value));
}

workspace_result_t<std::string> normalize_module_path(std::string value) {
    if (value.empty() || value.size() > 131072)
        return workspace_result_t<std::string>::failure(
            make_workspace_error(workspace_error_code_t::target_stale,
                                 "target module path is unavailable", "live_snapshot"));
    std::replace(value.begin(), value.end(), '/', '\\');
    const auto folded = normalize_target_name(value);
    if (folded.rfind("\\device\\", 0) == 0 ||
        folded.rfind("\\systemroot\\", 0) == 0 ||
        folded.rfind("\\??\\", 0) == 0)
        return workspace_result_t<std::string>::success(folded);
    auto normalized = normalize_utf8_path(value, false);
    if (normalized)
        return workspace_result_t<std::string>::success(
            normalize_target_name(normalized.take_value()));
    return workspace_result_t<std::string>::failure(normalized.error());
}

workspace_result_t<module_identity_t> query_module_identity(
    const live_snapshot_request_t& request) {
    const auto modules = driver_bridge::enumerate_modules_for(request.pid);
    const auto iterator = std::find_if(modules.begin(), modules.end(), [&](const auto& module) {
        return module.base == request.module_base;
    });
    if (iterator == modules.end()) {
        auto error = make_workspace_error(workspace_error_code_t::target_stale,
                                          "target module is no longer present", "live_snapshot");
        error.address = address_t{address_space_id_t::live_virtual, request.module_base,
                                  architecture_id_t::unknown, architecture_mode_t::unknown};
        return workspace_result_t<module_identity_t>::failure(std::move(error));
    }
    if (iterator->size == 0 ||
        (request.module_size != 0 && iterator->size != request.module_size)) {
        auto error = make_workspace_error(workspace_error_code_t::target_stale,
                                          "target module size changed", "live_snapshot");
        error.details.emplace_back("observed_size", std::to_string(iterator->size));
        error.details.emplace_back("expected_size", std::to_string(request.module_size));
        return workspace_result_t<module_identity_t>::failure(std::move(error));
    }
    const std::string observed_name = normalize_module_component(iterator->name);
    auto observed_path_result = normalize_module_path(iterator->path);
    if (observed_name.empty() || observed_name.size() > 32768 || !observed_path_result)
        return workspace_result_t<module_identity_t>::failure(
            !observed_path_result
                ? observed_path_result.error()
                : make_workspace_error(workspace_error_code_t::target_stale,
                                       "target module name is unavailable", "live_snapshot"));
    const std::string observed_path = observed_path_result.take_value();
    if (!request.module_name.empty() &&
        observed_name != normalize_module_component(request.module_name)) {
        return workspace_result_t<module_identity_t>::failure(
            make_workspace_error(workspace_error_code_t::target_stale,
                                 "target module name changed", "live_snapshot"));
    }
    if (!request.module_path.empty()) {
        auto requested_path = normalize_module_path(request.module_path);
        if (!requested_path || observed_path != requested_path.value())
            return workspace_result_t<module_identity_t>::failure(
                make_workspace_error(workspace_error_code_t::target_stale,
                                     "target module path changed", "live_snapshot"));
    }
    std::uint64_t module_end = 0;
    if (!checked_add_u64(iterator->base, iterator->size, module_end))
        return workspace_result_t<module_identity_t>::failure(
            make_workspace_error(workspace_error_code_t::range_overflow,
                                 "target module range overflowed", "live_snapshot"));
    module_identity_t identity;
    identity.base = iterator->base;
    identity.size = iterator->size;
    identity.normalized_name = observed_name;
    identity.normalized_path = observed_path;
    return workspace_result_t<module_identity_t>::success(std::move(identity));
}

workspace_result_t<void> compare_live_identity(const process_identity_t& expected_process,
                                               const module_identity_t& expected_module,
                                               const process_identity_t& observed_process,
                                               const module_identity_t& observed_module) {
    if (!(expected_process == observed_process)) {
        auto error = make_workspace_error(workspace_error_code_t::target_stale,
                                          "target process identity changed", "live_snapshot");
        error.details.emplace_back("pid", std::to_string(expected_process.pid));
        return workspace_result_t<void>::failure(std::move(error));
    }
    module_identity_t expected = expected_module;
    module_identity_t observed = observed_module;
    expected.content_hash.reset();
    observed.content_hash.reset();
    if (!(expected == observed))
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::target_stale,
                                 "target module identity changed", "live_snapshot"));
    return workspace_result_t<void>::success();
}

}

workspace_result_t<std::shared_ptr<live_snapshot_provider_t>>
live_snapshot_provider_t::capture_function(const live_function_snapshot_request_t& request,
                                           const cancellation_token_t& cancel) {
    if (request.pid == 0)
        return workspace_result_t<std::shared_ptr<live_snapshot_provider_t>>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "function snapshot PID must be positive", "live_snapshot"));
    if (request.pid == GetCurrentProcessId())
        return workspace_result_t<std::shared_ptr<live_snapshot_provider_t>>::failure(
            make_workspace_error(workspace_error_code_t::self_target_refused,
                                 "AiDA cannot snapshot its own process", "live_snapshot"));
    if (request.function_va == 0 || request.function_size == 0)
        return workspace_result_t<std::shared_ptr<live_snapshot_provider_t>>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "function snapshot VA and size must be positive", "live_snapshot"));
    if (request.maximum_capture_size == 0 ||
        request.maximum_capture_size > 256ULL * 1024ULL * 1024ULL)
        return workspace_result_t<std::shared_ptr<live_snapshot_provider_t>>::failure(
            make_workspace_error(workspace_error_code_t::limit_exceeded,
                                 "function snapshot maximum capture size is invalid",
                                 "live_snapshot"));
    if (request.module_name.size() > 32768 ||
        request.module_path.size() > 131072)
        return workspace_result_t<std::shared_ptr<live_snapshot_provider_t>>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "function snapshot module identity is invalid", "live_snapshot"));
    if (cancel.stop_requested())
        return workspace_result_t<std::shared_ptr<live_snapshot_provider_t>>::failure(
            stop_error(cancel));

    const std::uint64_t capture_size =
        std::min<std::uint64_t>(request.function_size, request.maximum_capture_size);

    live_snapshot_request_t snapshot_request;
    snapshot_request.pid = request.pid;
    snapshot_request.module_base = request.module_base;
    snapshot_request.module_size = request.module_size;
    snapshot_request.module_name = request.module_name;
    snapshot_request.module_path = request.module_path;
    snapshot_request.capture_address = address_t{address_space_id_t::live_virtual,
                                                  request.function_va,
                                                  architecture_id_t::x86_64,
                                                  architecture_mode_t::x86_64};
    snapshot_request.capture_size = capture_size;
    snapshot_request.maximum_capture_size = request.maximum_capture_size;

    return capture(snapshot_request, cancel);
}

workspace_result_t<std::shared_ptr<live_snapshot_provider_t>>
live_snapshot_provider_t::capture(const live_snapshot_request_t& request,
                                  const cancellation_token_t& cancel) {
    if (request.pid == 0)
        return workspace_result_t<std::shared_ptr<live_snapshot_provider_t>>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "live snapshot PID must be positive", "live_snapshot"));
    if (request.module_base == 0 || request.module_name.size() > 32768 ||
        request.module_path.size() > 131072)
        return workspace_result_t<std::shared_ptr<live_snapshot_provider_t>>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "live snapshot module identity is invalid", "live_snapshot"));
    if (request.capture_address.space != address_space_id_t::live_virtual ||
        (request.capture_address.architecture != architecture_id_t::x86 &&
         request.capture_address.architecture != architecture_id_t::x86_64) ||
        (request.capture_address.architecture == architecture_id_t::x86 &&
         request.capture_address.mode != architecture_mode_t::x86_32) ||
        (request.capture_address.architecture == architecture_id_t::x86_64 &&
         request.capture_address.mode != architecture_mode_t::x86_64))
        return workspace_result_t<std::shared_ptr<live_snapshot_provider_t>>::failure(
            make_workspace_error(workspace_error_code_t::unsupported_address_space,
                                 "snapshot address must be a typed live x86/x86-64 address",
                                 "live_snapshot"));
    if (request.pid == GetCurrentProcessId())
        return workspace_result_t<std::shared_ptr<live_snapshot_provider_t>>::failure(
            make_workspace_error(workspace_error_code_t::self_target_refused,
                                 "AiDA cannot snapshot its own process", "live_snapshot"));
    if (request.capture_size == 0 || request.maximum_capture_size == 0 ||
        request.maximum_capture_size > 256ULL * 1024ULL * 1024ULL ||
        request.capture_size > request.maximum_capture_size) {
        auto error = make_workspace_error(workspace_error_code_t::limit_exceeded,
                                          "live snapshot size exceeds its capture budget",
                                          "live_snapshot");
        error.size = request.capture_size;
        error.details.emplace_back("maximum_capture_size",
                                   std::to_string(request.maximum_capture_size));
        return workspace_result_t<std::shared_ptr<live_snapshot_provider_t>>::failure(
            std::move(error));
    }
    if (cancel.stop_requested())
        return workspace_result_t<std::shared_ptr<live_snapshot_provider_t>>::failure(
            stop_error(cancel));
    auto process_before = query_process_identity(request.pid);
    if (!process_before)
        return workspace_result_t<std::shared_ptr<live_snapshot_provider_t>>::failure(
            process_before.error());
    auto module_before = query_module_identity(request);
    if (!module_before)
        return workspace_result_t<std::shared_ptr<live_snapshot_provider_t>>::failure(
            module_before.error());
    std::uint64_t capture_end = 0;
    std::uint64_t module_end = 0;
    const bool valid_absolute_range =
        checked_add_u64(request.capture_address.value, request.capture_size, capture_end) &&
        checked_add_u64(module_before.value().base, module_before.value().size, module_end);
    if (!valid_absolute_range || request.capture_address.value < module_before.value().base ||
        capture_end > module_end) {
        auto error = make_workspace_error(workspace_error_code_t::out_of_range,
                                          "snapshot span lies outside the selected module",
                                          "live_snapshot");
        error.address = request.capture_address;
        error.size = request.capture_size;
        return workspace_result_t<std::shared_ptr<live_snapshot_provider_t>>::failure(
            std::move(error));
    }
    std::size_t capture_size = 0;
    if (!u64_to_size(request.capture_size, capture_size))
        return workspace_result_t<std::shared_ptr<live_snapshot_provider_t>>::failure(
            make_workspace_error(workspace_error_code_t::range_overflow,
                                 "snapshot span cannot be represented in memory", "live_snapshot"));
    auto bytes = std::make_shared<std::vector<std::uint8_t>>(capture_size);
    std::uint64_t completed = 0;
    while (completed < request.capture_size) {
        if (cancel.stop_requested())
            return workspace_result_t<std::shared_ptr<live_snapshot_provider_t>>::failure(
                stop_error(cancel));
        const std::uint64_t amount_u64 = std::min<std::uint64_t>(
            request.capture_size - completed, 1ULL * 1024ULL * 1024ULL);
        std::uint64_t read_address = 0;
        if (!checked_add_u64(request.capture_address.value, completed, read_address))
            return workspace_result_t<std::shared_ptr<live_snapshot_provider_t>>::failure(
                make_workspace_error(workspace_error_code_t::range_overflow,
                                     "snapshot read address overflowed", "live_snapshot"));
        std::vector<std::uint8_t> chunk;
        if (!driver_bridge::read_memory_for(request.pid, read_address,
                                            static_cast<std::size_t>(amount_u64), chunk) ||
            chunk.size() != static_cast<std::size_t>(amount_u64)) {
            auto error = make_workspace_error(workspace_error_code_t::provider_unavailable,
                                              "driver-backed snapshot read failed", "live_snapshot");
            error.address = address_t{address_space_id_t::live_virtual,
                                      read_address,
                                      request.capture_address.architecture,
                                      request.capture_address.mode};
            error.size = amount_u64;
            return workspace_result_t<std::shared_ptr<live_snapshot_provider_t>>::failure(
                std::move(error));
        }
        std::memcpy(bytes->data() + static_cast<std::size_t>(completed), chunk.data(), chunk.size());
        completed += amount_u64;
    }
    auto process_after = query_process_identity(request.pid);
    if (!process_after)
        return workspace_result_t<std::shared_ptr<live_snapshot_provider_t>>::failure(
            process_after.error());
    auto module_after = query_module_identity(request);
    if (!module_after)
        return workspace_result_t<std::shared_ptr<live_snapshot_provider_t>>::failure(
            module_after.error());
    auto identity_result = compare_live_identity(process_before.value(), module_before.value(),
                                                 process_after.value(), module_after.value());
    if (!identity_result)
        return workspace_result_t<std::shared_ptr<live_snapshot_provider_t>>::failure(
            identity_result.error());
    auto hash_result = sha256_bytes(bytes->data(), bytes->size(), cancel);
    if (!hash_result)
        return workspace_result_t<std::shared_ptr<live_snapshot_provider_t>>::failure(
            hash_result.error());
    FILETIME capture_time{};
    GetSystemTimeAsFileTime(&capture_time);
    live_snapshot_metadata_t metadata;
    metadata.process = process_before.take_value();
    metadata.module = module_before.take_value();
    metadata.capture_address = request.capture_address.value;
    metadata.capture_size = request.capture_size;
    metadata.capture_time_100ns = filetime_value(capture_time);
    metadata.capture_hash = hash_result.take_value();
    metadata.module.content_hash = metadata.capture_hash;
    byte_provider_identity_t provider_identity;
    provider_identity.normalized_source =
        "live://" + std::to_string(request.pid) + "/" + metadata.module.normalized_name + "@" +
        std::to_string(request.capture_address.value);
    provider_identity.size = request.capture_size;
    provider_identity.volume_serial = metadata.process.creation_time_100ns;
    std::copy_n(metadata.capture_hash.bytes.begin(), provider_identity.file_id.size(),
                provider_identity.file_id.begin());
    provider_identity.last_write_time_100ns = metadata.capture_time_100ns;
    provider_identity.immutable_snapshot = true;
    return workspace_result_t<std::shared_ptr<live_snapshot_provider_t>>::success(
        std::shared_ptr<live_snapshot_provider_t>(new live_snapshot_provider_t(
            std::move(metadata), std::move(provider_identity), std::move(bytes))));
}

live_snapshot_provider_t::live_snapshot_provider_t(
    live_snapshot_metadata_t metadata, byte_provider_identity_t identity,
    std::shared_ptr<const std::vector<std::uint8_t>> bytes)
    : metadata_(std::move(metadata)), identity_(std::move(identity)), bytes_(std::move(bytes)) {}

workspace_result_t<byte_view_t> live_snapshot_provider_t::lease(
    std::uint64_t offset, std::uint64_t size_value,
    const cancellation_token_t& cancel) const {
    if (cancel.stop_requested())
        return workspace_result_t<byte_view_t>::failure(stop_error(cancel));
    auto range_result = validate_span(offset, size_value, metadata_.capture_size,
                                      "live_snapshot_lease");
    if (!range_result)
        return workspace_result_t<byte_view_t>::failure(range_result.error());
    return workspace_result_t<byte_view_t>::success(byte_view_t(
        std::static_pointer_cast<const void>(bytes_),
        size_value == 0 ? nullptr : bytes_->data() + static_cast<std::size_t>(offset),
        static_cast<std::size_t>(size_value)));
}

workspace_result_t<void> live_snapshot_provider_t::validate_current_identity() const {
    live_snapshot_request_t request;
    request.pid = metadata_.process.pid;
    request.module_base = metadata_.module.base;
    request.module_size = metadata_.module.size;
    request.module_name = metadata_.module.normalized_name;
    request.module_path = metadata_.module.normalized_path;
    auto process_result = query_process_identity(request.pid);
    if (!process_result)
        return workspace_result_t<void>::failure(process_result.error());
    auto module_result = query_module_identity(request);
    if (!module_result)
        return workspace_result_t<void>::failure(module_result.error());
    return compare_live_identity(metadata_.process, metadata_.module,
                                 process_result.value(), module_result.value());
}

}
