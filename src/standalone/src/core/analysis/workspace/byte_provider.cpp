#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>

#include "byte_provider.hpp"

#include "workspace_identity.hpp"

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

workspace_error_t stop_error(const cancellation_token_t& cancel, const char* phase) {
    if (cancel.deadline_exceeded()) {
        auto error = make_workspace_error(workspace_error_code_t::deadline_exceeded,
                                          "operation deadline exceeded", phase);
        error.deadline = true;
        return error;
    }
    auto error = make_workspace_error(workspace_error_code_t::cancelled,
                                      "operation cancelled", phase);
    error.cancellation = true;
    return error;
}

workspace_result_t<std::wstring> utf8_to_wide(const std::string& text) {
    if (text.empty() ||
        text.size() > static_cast<std::size_t>(std::numeric_limits<int>::max()))
        return workspace_result_t<std::wstring>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "source path length is invalid", "byte_provider_open"));
    const int needed = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(),
                                           static_cast<int>(text.size()), nullptr, 0);
    if (needed <= 0) {
        auto error = make_workspace_error(workspace_error_code_t::invalid_argument,
                                          "source path is not valid UTF-8", "byte_provider_open");
        error.win32_status = GetLastError();
        return workspace_result_t<std::wstring>::failure(std::move(error));
    }
    std::wstring result(static_cast<std::size_t>(needed), L'\0');
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(),
                            static_cast<int>(text.size()), result.data(), needed) != needed) {
        auto error = make_workspace_error(workspace_error_code_t::invalid_argument,
                                          "source path conversion failed", "byte_provider_open");
        error.win32_status = GetLastError();
        return workspace_result_t<std::wstring>::failure(std::move(error));
    }
    return workspace_result_t<std::wstring>::success(std::move(result));
}

workspace_result_t<byte_provider_identity_t> query_identity(HANDLE file,
                                                            const std::string& source) {
    FILE_STANDARD_INFO standard{};
    if (!GetFileInformationByHandleEx(file, FileStandardInfo, &standard, sizeof(standard))) {
        auto error = make_workspace_error(workspace_error_code_t::io_failure,
                                          "failed to query source size", "byte_provider_open");
        error.win32_status = GetLastError();
        return workspace_result_t<byte_provider_identity_t>::failure(std::move(error));
    }
    if (standard.Directory || standard.EndOfFile.QuadPart < 0) {
        return workspace_result_t<byte_provider_identity_t>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "source is not a regular file", "byte_provider_open"));
    }
    FILE_BASIC_INFO basic{};
    if (!GetFileInformationByHandleEx(file, FileBasicInfo, &basic, sizeof(basic))) {
        auto error = make_workspace_error(workspace_error_code_t::io_failure,
                                          "failed to query source timestamps", "byte_provider_open");
        error.win32_status = GetLastError();
        return workspace_result_t<byte_provider_identity_t>::failure(std::move(error));
    }
    FILE_ID_INFO id_info{};
    if (!GetFileInformationByHandleEx(file, FileIdInfo, &id_info, sizeof(id_info))) {
        auto error = make_workspace_error(workspace_error_code_t::io_failure,
                                          "failed to query source file identity", "byte_provider_open");
        error.win32_status = GetLastError();
        return workspace_result_t<byte_provider_identity_t>::failure(std::move(error));
    }
    byte_provider_identity_t identity;
    identity.normalized_source = source;
    identity.size = static_cast<std::uint64_t>(standard.EndOfFile.QuadPart);
    identity.volume_serial = id_info.VolumeSerialNumber;
    std::memcpy(identity.file_id.data(), id_info.FileId.Identifier, identity.file_id.size());
    identity.last_write_time_100ns = static_cast<std::uint64_t>(basic.LastWriteTime.QuadPart);
    identity.immutable_snapshot = false;
    return workspace_result_t<byte_provider_identity_t>::success(std::move(identity));
}

bool same_identity(const byte_provider_identity_t& lhs,
                   const byte_provider_identity_t& rhs) noexcept {
    return lhs.size == rhs.size && lhs.volume_serial == rhs.volume_serial &&
           lhs.file_id == rhs.file_id && lhs.last_write_time_100ns == rhs.last_write_time_100ns;
}

}

struct mapped_file_provider_t::state_t {
    unique_handle_t file;
    unique_handle_t mapping;
    byte_provider_identity_t identity;
    mapped_file_provider_options_t options;
    std::uint64_t allocation_granularity = 0;
};

namespace {

struct mapped_view_t {
    std::shared_ptr<const void> state;
    void* base = nullptr;

    ~mapped_view_t() {
        if (base)
            UnmapViewOfFile(base);
    }
};

}

workspace_result_t<void> byte_provider_t::read_exact(
    std::uint64_t offset, void* destination, std::uint64_t size_value,
    const cancellation_token_t& cancel) const {
    if (size_value != 0 && !destination)
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "read destination is null", "byte_provider_read"));
    if (size_value > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
        auto error = make_workspace_error(workspace_error_code_t::range_overflow,
                                          "read size exceeds the process address space",
                                          "byte_provider_read");
        error.size = size_value;
        return workspace_result_t<void>::failure(std::move(error));
    }
    auto range_result = validate_span(offset, size_value, size(), "byte_provider_read");
    if (!range_result)
        return workspace_result_t<void>::failure(range_result.error());
    auto* output = static_cast<std::uint8_t*>(destination);
    std::uint64_t chunk_size = 4ULL * 1024ULL * 1024ULL;
    if (const auto* mapped = dynamic_cast<const mapped_file_provider_t*>(this))
        chunk_size = mapped->state_->options.read_chunk_size;
    std::uint64_t completed = 0;
    while (completed < size_value) {
        if (cancel.stop_requested())
            return workspace_result_t<void>::failure(stop_error(cancel, "byte_provider_read"));
        const std::uint64_t amount = std::min<std::uint64_t>(
            size_value - completed, chunk_size);
        auto lease_result = lease(offset + completed, amount, cancel);
        if (!lease_result)
            return workspace_result_t<void>::failure(lease_result.error());
        std::memcpy(output + static_cast<std::size_t>(completed), lease_result.value().data(),
                    lease_result.value().size());
        completed += amount;
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<std::size_t> byte_provider_t::read_some(
    std::uint64_t offset, void* destination, std::size_t capacity,
    const cancellation_token_t& cancel) const {
    if (capacity != 0 && !destination)
        return workspace_result_t<std::size_t>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "read destination is null", "byte_provider_read"));
    if (offset > size()) {
        auto error = make_workspace_error(workspace_error_code_t::out_of_range,
                                          "read offset exceeds provider size", "byte_provider_read");
        error.offset = offset;
        return workspace_result_t<std::size_t>::failure(std::move(error));
    }
    const std::uint64_t amount = std::min<std::uint64_t>(capacity, size() - offset);
    auto result = read_exact(offset, destination, amount, cancel);
    if (!result)
        return workspace_result_t<std::size_t>::failure(result.error());
    return workspace_result_t<std::size_t>::success(static_cast<std::size_t>(amount));
}

workspace_result_t<std::vector<std::uint8_t>> byte_provider_t::read_vector(
    std::uint64_t offset, std::uint64_t size_value, std::uint64_t hard_limit,
    const cancellation_token_t& cancel) const {
    constexpr std::uint64_t absolute_limit = 64ULL * 1024ULL * 1024ULL;
    const std::uint64_t effective_limit = std::min(hard_limit, absolute_limit);
    if (size_value > effective_limit) {
        auto error = make_workspace_error(workspace_error_code_t::limit_exceeded,
                                          "requested byte vector exceeds its hard limit",
                                          "byte_provider_read");
        error.size = size_value;
        error.details.emplace_back("hard_limit", std::to_string(effective_limit));
        return workspace_result_t<std::vector<std::uint8_t>>::failure(std::move(error));
    }
    std::size_t allocation = 0;
    if (!u64_to_size(size_value, allocation)) {
        auto error = make_workspace_error(workspace_error_code_t::range_overflow,
                                          "requested byte vector exceeds addressable memory",
                                          "byte_provider_read");
        error.size = size_value;
        return workspace_result_t<std::vector<std::uint8_t>>::failure(std::move(error));
    }
    std::vector<std::uint8_t> bytes(allocation);
    auto result = read_exact(offset, bytes.data(), size_value, cancel);
    if (!result)
        return workspace_result_t<std::vector<std::uint8_t>>::failure(result.error());
    return workspace_result_t<std::vector<std::uint8_t>>::success(std::move(bytes));
}

workspace_result_t<std::shared_ptr<mapped_file_provider_t>>
mapped_file_provider_t::open(const std::string& utf8_path,
                             mapped_file_provider_options_t options) {
    if (options.max_lease_size == 0 || options.read_chunk_size == 0 ||
        options.max_lease_size > 256ULL * 1024ULL * 1024ULL ||
        options.read_chunk_size > options.max_lease_size ||
        options.max_lease_size > static_cast<std::uint64_t>(std::numeric_limits<SIZE_T>::max()))
        return workspace_result_t<std::shared_ptr<mapped_file_provider_t>>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "mapped-file provider limits are invalid", "byte_provider_open"));
    auto normalized_result = normalize_utf8_path(utf8_path, true);
    if (!normalized_result)
        return workspace_result_t<std::shared_ptr<mapped_file_provider_t>>::failure(
            normalized_result.error());
    auto wide_result = utf8_to_wide(normalized_result.value());
    if (!wide_result)
        return workspace_result_t<std::shared_ptr<mapped_file_provider_t>>::failure(
            wide_result.error());
    HANDLE raw_file = CreateFileW(wide_result.value().c_str(), GENERIC_READ,
                                  FILE_SHARE_READ,
                                  nullptr, OPEN_EXISTING,
                                  FILE_ATTRIBUTE_NORMAL | FILE_FLAG_RANDOM_ACCESS, nullptr);
    if (raw_file == INVALID_HANDLE_VALUE) {
        auto error = make_workspace_error(workspace_error_code_t::io_failure,
                                          "failed to open mapped source", "byte_provider_open");
        error.win32_status = GetLastError();
        return workspace_result_t<std::shared_ptr<mapped_file_provider_t>>::failure(
            std::move(error));
    }
    unique_handle_t file(raw_file);
    auto identity_result = query_identity(raw_file, normalized_result.value());
    if (!identity_result)
        return workspace_result_t<std::shared_ptr<mapped_file_provider_t>>::failure(
            identity_result.error());
    unique_handle_t mapping;
    if (identity_result.value().size != 0) {
        HANDLE raw_mapping = CreateFileMappingW(raw_file, nullptr, PAGE_READONLY, 0, 0, nullptr);
        if (!raw_mapping) {
            auto error = make_workspace_error(workspace_error_code_t::io_failure,
                                              "failed to create read-only file mapping",
                                              "byte_provider_open");
            error.win32_status = GetLastError();
            return workspace_result_t<std::shared_ptr<mapped_file_provider_t>>::failure(
                std::move(error));
        }
        mapping.reset(raw_mapping);
    }
    SYSTEM_INFO system_info{};
    GetSystemInfo(&system_info);
    if (system_info.dwAllocationGranularity == 0)
        return workspace_result_t<std::shared_ptr<mapped_file_provider_t>>::failure(
            make_workspace_error(workspace_error_code_t::provider_unavailable,
                                 "system allocation granularity is zero", "byte_provider_open"));
    auto state = std::make_shared<state_t>();
    state->file = std::move(file);
    state->mapping = std::move(mapping);
    state->identity = identity_result.take_value();
    state->options = options;
    state->allocation_granularity = system_info.dwAllocationGranularity;
    return workspace_result_t<std::shared_ptr<mapped_file_provider_t>>::success(
        std::shared_ptr<mapped_file_provider_t>(new mapped_file_provider_t(std::move(state))));
}

mapped_file_provider_t::mapped_file_provider_t(std::shared_ptr<state_t> state)
    : state_(std::move(state)) {}

mapped_file_provider_t::~mapped_file_provider_t() = default;

const byte_provider_identity_t& mapped_file_provider_t::identity() const noexcept {
    return state_->identity;
}

std::uint64_t mapped_file_provider_t::size() const noexcept {
    return state_->identity.size;
}

workspace_result_t<void> mapped_file_provider_t::revalidate() const {
    auto current_result = query_identity(static_cast<HANDLE>(state_->file.get()),
                                         state_->identity.normalized_source);
    if (!current_result)
        return workspace_result_t<void>::failure(current_result.error());
    if (!same_identity(state_->identity, current_result.value())) {
        auto error = make_workspace_error(workspace_error_code_t::file_changed,
                                          "mapped source identity changed", "byte_provider_revalidate");
        error.details.emplace_back("source", state_->identity.normalized_source);
        return workspace_result_t<void>::failure(std::move(error));
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<byte_view_t> mapped_file_provider_t::lease(
    std::uint64_t offset, std::uint64_t size_value,
    const cancellation_token_t& cancel) const {
    if (cancel.stop_requested())
        return workspace_result_t<byte_view_t>::failure(stop_error(cancel, "byte_provider_lease"));
    auto range_result = validate_span(offset, size_value, state_->identity.size,
                                      "byte_provider_lease");
    if (!range_result)
        return workspace_result_t<byte_view_t>::failure(range_result.error());
    if (size_value > state_->options.max_lease_size) {
        auto error = make_workspace_error(workspace_error_code_t::limit_exceeded,
                                          "mapped view exceeds configured lease limit",
                                          "byte_provider_lease");
        error.offset = offset;
        error.size = size_value;
        error.details.emplace_back("max_lease_size", std::to_string(state_->options.max_lease_size));
        return workspace_result_t<byte_view_t>::failure(std::move(error));
    }
    auto revalidate_result = revalidate();
    if (!revalidate_result)
        return workspace_result_t<byte_view_t>::failure(revalidate_result.error());
    if (size_value == 0)
        return workspace_result_t<byte_view_t>::success(
            byte_view_t(std::static_pointer_cast<const void>(state_), nullptr, 0));
    const std::uint64_t aligned = offset - (offset % state_->allocation_granularity);
    const std::uint64_t delta = offset - aligned;
    std::uint64_t mapped_size_u64 = 0;
    if (!checked_add_u64(delta, size_value, mapped_size_u64) ||
        mapped_size_u64 > static_cast<std::uint64_t>(std::numeric_limits<SIZE_T>::max())) {
        auto error = make_workspace_error(workspace_error_code_t::range_overflow,
                                          "mapped view size exceeds the process address space",
                                          "byte_provider_lease");
        error.offset = offset;
        error.size = size_value;
        return workspace_result_t<byte_view_t>::failure(std::move(error));
    }
    const DWORD high = static_cast<DWORD>(aligned >> 32);
    const DWORD low = static_cast<DWORD>(aligned & 0xffffffffULL);
    void* mapped = MapViewOfFile(static_cast<HANDLE>(state_->mapping.get()), FILE_MAP_READ,
                                 high, low, static_cast<SIZE_T>(mapped_size_u64));
    if (!mapped) {
        auto error = make_workspace_error(workspace_error_code_t::io_failure,
                                          "failed to map source window", "byte_provider_lease");
        error.offset = offset;
        error.size = size_value;
        error.win32_status = GetLastError();
        return workspace_result_t<byte_view_t>::failure(std::move(error));
    }
    auto owner = std::make_shared<mapped_view_t>();
    owner->state = state_;
    owner->base = mapped;
    revalidate_result = revalidate();
    if (!revalidate_result)
        return workspace_result_t<byte_view_t>::failure(revalidate_result.error());
    auto* bytes = static_cast<const std::uint8_t*>(mapped) + static_cast<std::size_t>(delta);
    return workspace_result_t<byte_view_t>::success(
        byte_view_t(std::static_pointer_cast<const void>(owner), bytes,
                    static_cast<std::size_t>(size_value)));
}

workspace_result_t<std::shared_ptr<subrange_provider_t>> subrange_provider_t::create(
    std::shared_ptr<const byte_provider_t> parent, std::uint64_t base,
    std::uint64_t length, std::string identity_suffix) {
    if (!parent)
        return workspace_result_t<std::shared_ptr<subrange_provider_t>>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "subrange parent is null", "subrange_create"));
    if (identity_suffix.empty() || identity_suffix.size() > 32768)
        return workspace_result_t<std::shared_ptr<subrange_provider_t>>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "subrange identity suffix is invalid", "subrange_create"));
    auto range_result = validate_span(base, length, parent->size(), "subrange_create");
    if (!range_result)
        return workspace_result_t<std::shared_ptr<subrange_provider_t>>::failure(range_result.error());
    byte_provider_identity_t identity = parent->identity();
    identity.normalized_source += "#" + identity_suffix;
    identity.size = length;
    return workspace_result_t<std::shared_ptr<subrange_provider_t>>::success(
        std::shared_ptr<subrange_provider_t>(new subrange_provider_t(
            std::move(parent), base, length, std::move(identity))));
}

workspace_result_t<std::shared_ptr<subrange_provider_t>> subrange_provider_t::create_member(
    std::shared_ptr<const byte_provider_t> parent, std::uint64_t base,
    std::uint64_t length, provider_member_metadata_t member) {
    if (!parent)
        return workspace_result_t<std::shared_ptr<subrange_provider_t>>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "member provider parent is null", "subrange_member_create"));
    if (member.normalized_member_path.empty() ||
        member.normalized_member_path.size() > 32768 ||
        member.normalized_member_path.front() == '/' ||
        member.normalized_member_path.find('\\') != std::string::npos ||
        member.normalized_member_path.find('\0') != std::string::npos ||
        member.compressed || member.container_offset != base ||
        member.uncompressed_size != length || member.compressed_size != length ||
        member.depth == 0 || member.depth > 64) {
        return workspace_result_t<std::shared_ptr<subrange_provider_t>>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "member provider metadata is invalid", "subrange_member_create"));
    }
    const auto& parent_member = parent->member_metadata();
    if ((!parent_member && member.depth != 1) ||
        (parent_member &&
         (parent_member->depth >= 64 || member.depth != parent_member->depth + 1))) {
        return workspace_result_t<std::shared_ptr<subrange_provider_t>>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "member provider depth is inconsistent with its parent",
                                 "subrange_member_create"));
    }
    std::size_t component_start = 0;
    while (component_start < member.normalized_member_path.size()) {
        const auto separator = member.normalized_member_path.find('/', component_start);
        const auto component_length = (separator == std::string::npos
            ? member.normalized_member_path.size() : separator) - component_start;
        if (component_length == 0 ||
            (component_length == 1 && member.normalized_member_path[component_start] == '.') ||
            (component_length == 2 && member.normalized_member_path[component_start] == '.' &&
             member.normalized_member_path[component_start + 1] == '.')) {
            return workspace_result_t<std::shared_ptr<subrange_provider_t>>::failure(
                make_workspace_error(workspace_error_code_t::invalid_argument,
                                     "member provider path is not normalized",
                                     "subrange_member_create"));
        }
        if (separator == std::string::npos)
            break;
        component_start = separator + 1;
    }
    auto range_result = validate_span(base, length, parent->size(), "subrange_member_create");
    if (!range_result)
        return workspace_result_t<std::shared_ptr<subrange_provider_t>>::failure(range_result.error());
    byte_provider_identity_t identity = parent->identity();
    identity.normalized_source += "#member:" + member.normalized_member_path;
    identity.size = length;
    identity.member = std::move(member);
    return workspace_result_t<std::shared_ptr<subrange_provider_t>>::success(
        std::shared_ptr<subrange_provider_t>(new subrange_provider_t(
            std::move(parent), base, length, std::move(identity))));
}

subrange_provider_t::subrange_provider_t(std::shared_ptr<const byte_provider_t> parent,
                                         std::uint64_t base, std::uint64_t length,
                                         byte_provider_identity_t identity)
    : parent_(std::move(parent)), base_(base), length_(length), identity_(std::move(identity)) {}

workspace_result_t<byte_view_t> subrange_provider_t::lease(
    std::uint64_t offset, std::uint64_t size_value,
    const cancellation_token_t& cancel) const {
    auto range_result = validate_span(offset, size_value, length_, "subrange_lease");
    if (!range_result)
        return workspace_result_t<byte_view_t>::failure(range_result.error());
    std::uint64_t parent_offset = 0;
    if (!checked_add_u64(base_, offset, parent_offset)) {
        auto error = make_workspace_error(workspace_error_code_t::range_overflow,
                                          "subrange parent offset overflowed", "subrange_lease");
        error.offset = offset;
        error.size = size_value;
        return workspace_result_t<byte_view_t>::failure(std::move(error));
    }
    auto parent_result = parent_->lease(parent_offset, size_value, cancel);
    if (!parent_result)
        return workspace_result_t<byte_view_t>::failure(parent_result.error());
    auto parent_view = parent_result.take_value();
    return workspace_result_t<byte_view_t>::success(
        byte_view_t(std::move(parent_view.lifetime_), parent_view.data_, parent_view.size_));
}

}
