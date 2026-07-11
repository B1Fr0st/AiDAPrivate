#include "patched_export.hpp"

#include "checked_range.hpp"
#include "workspace_identity.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <algorithm>
#include <cstring>
#include <cwctype>
#include <filesystem>
#include <limits>
#include <vector>

namespace aida::analysis {

namespace {

struct export_patch_t {
    std::uint64_t file_offset = 0;
    std::vector<std::uint8_t> bytes;
};

workspace_error_t win32_export_error(std::string message, DWORD status,
                                     const char* phase) {
    auto error = make_workspace_error(workspace_error_code_t::io_failure,
                                      std::move(message), phase);
    error.win32_status = status;
    return error;
}

workspace_result_t<std::uint64_t> patch_file_offset(
    const analysis_workspace_t& workspace, const overlay_operation_t& operation) {
    if (operation.address.space == address_space_id_t::file_offset)
        return workspace_result_t<std::uint64_t>::success(operation.address.value);
    auto image = workspace.image();
    if (!image) {
        return workspace_result_t<std::uint64_t>::failure(make_workspace_error(
            workspace_error_code_t::unsupported_address_space,
            "patch address cannot be translated without parsed image metadata",
            "patched_export"));
    }
    if (operation.address.space == address_space_id_t::relative_virtual)
        return image->rva_to_file_offset(operation.address.value, operation.bytes.size());
    if (operation.address.space == address_space_id_t::virtual_address) {
        auto rva = image->va_to_rva(operation.address.value);
        if (!rva) return workspace_result_t<std::uint64_t>::failure(rva.error());
        return image->rva_to_file_offset(rva.value(), operation.bytes.size());
    }
    return workspace_result_t<std::uint64_t>::failure(make_workspace_error(
        workspace_error_code_t::unsupported_address_space,
        "patch address space cannot be exported to a disk image",
        "patched_export"));
}

workspace_result_t<std::wstring> canonical_destination(const std::string& path) {
    if (path.empty()) {
        return workspace_result_t<std::wstring>::failure(make_workspace_error(
            workspace_error_code_t::invalid_argument,
            "patched export destination is empty", "patched_export"));
    }
    try {
        std::filesystem::path destination = std::filesystem::absolute(
            std::filesystem::u8path(path)).lexically_normal();
        auto parent = destination.parent_path();
        if (parent.empty() || !std::filesystem::is_directory(parent)) {
            return workspace_result_t<std::wstring>::failure(make_workspace_error(
                workspace_error_code_t::io_failure,
                "patched export destination directory does not exist",
                "patched_export"));
        }
        destination = std::filesystem::weakly_canonical(parent) / destination.filename();
        return workspace_result_t<std::wstring>::success(destination.wstring());
    } catch (const std::filesystem::filesystem_error& error) {
        auto result = make_workspace_error(workspace_error_code_t::io_failure,
                                           "unable to canonicalize patched export destination",
                                           "patched_export");
        result.provider_status = error.code().value();
        return workspace_result_t<std::wstring>::failure(std::move(result));
    }
}

std::wstring lower_path(std::wstring path) {
    std::transform(path.begin(), path.end(), path.begin(), [](wchar_t value) {
        return static_cast<wchar_t>(towlower(value));
    });
    return path;
}

workspace_result_t<void> write_all(HANDLE file, const std::uint8_t* data,
                                   std::size_t size) {
    std::size_t offset = 0;
    while (offset < size) {
        const DWORD request = static_cast<DWORD>((std::min<std::size_t>)(
            size - offset, static_cast<std::size_t>((std::numeric_limits<DWORD>::max)())));
        DWORD written = 0;
        if (!WriteFile(file, data + offset, request, &written, nullptr) || written == 0) {
            return workspace_result_t<void>::failure(win32_export_error(
                "unable to write patched export", GetLastError(), "patched_export"));
        }
        offset += written;
    }
    return workspace_result_t<void>::success();
}

}

workspace_result_t<patched_export_result_t> patched_export_t::export_copy(
    const std::shared_ptr<analysis_workspace_t>& workspace,
    const std::string& destination_path,
    const patched_export_options_t& options,
    const cancellation_token_t& cancel) {
    if (!workspace || workspace->closing()) {
        return workspace_result_t<patched_export_result_t>::failure(make_workspace_error(
            workspace_error_code_t::workspace_closing,
            "workspace is unavailable for patched export", "patched_export"));
    }
    if (workspace->target_kind() != target_kind_t::static_file) {
        return workspace_result_t<patched_export_result_t>::failure(make_workspace_error(
            workspace_error_code_t::live_target_bulk_analysis_unsupported,
            "live target overlays cannot be exported as process writes",
            "patched_export"));
    }
    if (options.chunk_size == 0 || options.chunk_size > 64ULL * 1024ULL * 1024ULL) {
        return workspace_result_t<patched_export_result_t>::failure(make_workspace_error(
            workspace_error_code_t::invalid_argument,
            "patched export chunk size is outside the allowed range",
            "patched_export"));
    }
    auto destination_result = canonical_destination(destination_path);
    if (!destination_result)
        return workspace_result_t<patched_export_result_t>::failure(destination_result.error());
    const std::wstring destination = destination_result.take_value();
    std::wstring source;
    try {
        source = std::filesystem::weakly_canonical(std::filesystem::u8path(
            workspace->identity().normalized_source_path())).wstring();
    } catch (...) {
        return workspace_result_t<patched_export_result_t>::failure(make_workspace_error(
            workspace_error_code_t::io_failure,
            "unable to canonicalize workspace source path", "patched_export"));
    }
    if (lower_path(source) == lower_path(destination)) {
        return workspace_result_t<patched_export_result_t>::failure(make_workspace_error(
            workspace_error_code_t::invalid_argument,
            "patched export destination must differ from the immutable source",
            "patched_export"));
    }
    const DWORD destination_attributes = GetFileAttributesW(destination.c_str());
    if (destination_attributes != INVALID_FILE_ATTRIBUTES) {
        std::error_code equivalent_error;
        if (std::filesystem::equivalent(std::filesystem::path(source),
                                        std::filesystem::path(destination),
                                        equivalent_error) && !equivalent_error) {
            return workspace_result_t<patched_export_result_t>::failure(make_workspace_error(
                workspace_error_code_t::invalid_argument,
                "patched export destination resolves to the immutable source",
                "patched_export"));
        }
    }
    if (destination_attributes != INVALID_FILE_ATTRIBUTES && !options.allow_overwrite) {
        return workspace_result_t<patched_export_result_t>::failure(make_workspace_error(
            workspace_error_code_t::revision_conflict,
            "patched export destination already exists",
            "patched_export"));
    }

    std::shared_lock<std::shared_mutex> revision_lock(workspace->mutation_mutex());
    auto overlay = workspace->overlay();
    std::vector<overlay_operation_t> operations = overlay
        ? overlay->patch_operations() : std::vector<overlay_operation_t>{};
    const std::uint64_t overlay_revision = workspace->overlay_revision();
    revision_lock.unlock();
    std::vector<export_patch_t> patches;
    patches.reserve(operations.size());
    for (const auto& operation : operations) {
        if (operation.bytes.empty())
            continue;
        auto offset = patch_file_offset(*workspace, operation);
        if (!offset)
            return workspace_result_t<patched_export_result_t>::failure(offset.error());
        auto span = validate_span(offset.value(), operation.bytes.size(),
                                  workspace->provider().size(), "patched_export");
        if (!span)
            return workspace_result_t<patched_export_result_t>::failure(span.error());
        patches.push_back({offset.value(), operation.bytes});
    }
    std::sort(patches.begin(), patches.end(), [](const auto& lhs, const auto& rhs) {
        return lhs.file_offset < rhs.file_offset;
    });
    std::uint64_t previous_end = 0;
    for (std::size_t index = 0; index < patches.size(); ++index) {
        std::uint64_t end = 0;
        if (!checked_add_u64(patches[index].file_offset, patches[index].bytes.size(), end)) {
            return workspace_result_t<patched_export_result_t>::failure(make_workspace_error(
                workspace_error_code_t::range_overflow,
                "patched export range overflows", "patched_export"));
        }
        if (index != 0 && patches[index].file_offset < previous_end) {
            return workspace_result_t<patched_export_result_t>::failure(make_workspace_error(
                workspace_error_code_t::revision_conflict,
                "patched export contains overlapping patch records",
                "patched_export"));
        }
        previous_end = end;
    }

    const std::filesystem::path destination_fs(destination);
    wchar_t temporary_path[MAX_PATH] = {};
    if (destination_fs.parent_path().wstring().size() >= MAX_PATH - 16 ||
        !GetTempFileNameW(destination_fs.parent_path().c_str(), L"AID", 0, temporary_path)) {
        return workspace_result_t<patched_export_result_t>::failure(win32_export_error(
            "unable to create same-directory temporary export path",
            GetLastError(), "patched_export"));
    }
    HANDLE output = CreateFileW(temporary_path, GENERIC_WRITE, 0, nullptr,
                                TRUNCATE_EXISTING,
                                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
                                nullptr);
    if (output == INVALID_HANDLE_VALUE) {
        const DWORD status = GetLastError();
        DeleteFileW(temporary_path);
        return workspace_result_t<patched_export_result_t>::failure(win32_export_error(
            "unable to open temporary patched export",
            status, "patched_export"));
    }

    bool keep_temporary = true;
    auto cleanup = [&]() {
        if (output != INVALID_HANDLE_VALUE) {
            CloseHandle(output);
            output = INVALID_HANDLE_VALUE;
        }
        if (keep_temporary)
            DeleteFileW(temporary_path);
    };

    patched_export_result_t export_result;
    export_result.destination_path = std::filesystem::path(destination).u8string();
    export_result.patch_records = patches.size();
    export_result.overlay_revision = overlay_revision;
    std::vector<std::uint8_t> buffer(static_cast<std::size_t>(options.chunk_size));
    std::size_t patch_index = 0;
    for (std::uint64_t offset = 0; offset < workspace->provider().size();) {
        if (cancel.stop_requested()) {
            cleanup();
            auto error = make_workspace_error(cancel.deadline_exceeded()
                                                  ? workspace_error_code_t::deadline_exceeded
                                                  : workspace_error_code_t::cancelled,
                                              "patched export cancelled", "patched_export");
            error.deadline = cancel.deadline_exceeded();
            error.cancellation = !error.deadline;
            return workspace_result_t<patched_export_result_t>::failure(std::move(error));
        }
        const std::uint64_t remaining = workspace->provider().size() - offset;
        const std::size_t request = static_cast<std::size_t>((std::min<std::uint64_t>)(
            remaining, options.chunk_size));
        auto read = workspace->provider().read_exact(offset, buffer.data(), request, cancel);
        if (!read) {
            cleanup();
            return workspace_result_t<patched_export_result_t>::failure(read.error());
        }
        const std::uint64_t chunk_end = offset + request;
        while (patch_index < patches.size() &&
               patches[patch_index].file_offset + patches[patch_index].bytes.size() <= offset)
            ++patch_index;
        for (std::size_t index = patch_index; index < patches.size(); ++index) {
            const std::uint64_t patch_begin = patches[index].file_offset;
            const std::uint64_t patch_end = patch_begin + patches[index].bytes.size();
            if (patch_begin >= chunk_end)
                break;
            const std::uint64_t overlap_begin = (std::max)(patch_begin, offset);
            const std::uint64_t overlap_end = (std::min)(patch_end, chunk_end);
            if (overlap_begin < overlap_end) {
                const std::size_t destination_offset = static_cast<std::size_t>(overlap_begin - offset);
                const std::size_t source_offset = static_cast<std::size_t>(overlap_begin - patch_begin);
                const std::size_t length = static_cast<std::size_t>(overlap_end - overlap_begin);
                std::memcpy(buffer.data() + destination_offset,
                            patches[index].bytes.data() + source_offset, length);
                export_result.patched_bytes += length;
            }
        }
        auto written = write_all(output, buffer.data(), request);
        if (!written) {
            cleanup();
            return workspace_result_t<patched_export_result_t>::failure(written.error());
        }
        export_result.bytes_written += request;
        offset = chunk_end;
    }
    if (!FlushFileBuffers(output)) {
        const DWORD status = GetLastError();
        cleanup();
        return workspace_result_t<patched_export_result_t>::failure(win32_export_error(
            "unable to flush patched export", status, "patched_export"));
    }
    CloseHandle(output);
    output = INVALID_HANDLE_VALUE;

    auto output_provider = mapped_file_provider_t::open(
        std::filesystem::path(temporary_path).u8string());
    if (!output_provider) {
        cleanup();
        return workspace_result_t<patched_export_result_t>::failure(output_provider.error());
    }
    auto hash = sha256_provider(*output_provider.value(), cancel);
    output_provider.value().reset();
    if (!hash) {
        cleanup();
        return workspace_result_t<patched_export_result_t>::failure(hash.error());
    }
    export_result.output_hash = hash.take_value();

    DWORD move_flags = MOVEFILE_WRITE_THROUGH;
    if (options.allow_overwrite)
        move_flags |= MOVEFILE_REPLACE_EXISTING;
    if (!MoveFileExW(temporary_path, destination.c_str(), move_flags)) {
        const DWORD status = GetLastError();
        cleanup();
        return workspace_result_t<patched_export_result_t>::failure(win32_export_error(
            "unable to atomically commit patched export", status, "patched_export"));
    }
    keep_temporary = false;
    return workspace_result_t<patched_export_result_t>::success(std::move(export_result));
}

}
