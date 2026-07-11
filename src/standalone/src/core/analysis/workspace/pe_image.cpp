#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>

#include "pe_image.hpp"

#include "checked_range.hpp"
#include "compact_ir.hpp"

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstring>
#include <limits>
#include <map>
#include <new>
#include <string_view>
#include <type_traits>
#include <unordered_set>
#include <unordered_map>
#include <utility>
namespace aida::analysis {
namespace {

struct delay_descriptor_t {
    std::uint32_t attributes;
    std::uint32_t name;
    std::uint32_t module_handle;
    std::uint32_t iat;
    std::uint32_t int_table;
    std::uint32_t bound_iat;
    std::uint32_t unload_iat;
    std::uint32_t timestamp;
};

static_assert(sizeof(delay_descriptor_t) == 32);
static_assert(static_cast<std::uint8_t>(pe_guard_function_flag_t::fid_suppressed) ==
              IMAGE_GUARD_FLAG_FID_SUPPRESSED);
static_assert(static_cast<std::uint8_t>(pe_guard_function_flag_t::export_suppressed) ==
              IMAGE_GUARD_FLAG_EXPORT_SUPPRESSED);
static_assert(static_cast<std::uint8_t>(pe_guard_function_flag_t::language_exception_handler) ==
              IMAGE_GUARD_FLAG_FID_LANGEXCPTHANDLER);
static_assert(static_cast<std::uint8_t>(pe_guard_function_flag_t::xfg) ==
              IMAGE_GUARD_FLAG_FID_XFG);
static_assert((IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK >>
               IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT) == 15);
static_assert(sizeof(IMAGE_DYNAMIC_RELOCATION_TABLE) == 8);
static_assert(sizeof(pe_unwind_scope_t) == 16);

workspace_error_t pe_error(std::string message, std::optional<std::uint64_t> offset = {},
                           std::optional<std::uint64_t> size = {}) {
    auto error = make_workspace_error(workspace_error_code_t::malformed_pe,
                                      std::move(message), "pe_parse");
    error.offset = offset;
    error.size = size;
    return error;
}

workspace_error_t limit_error(std::string message, std::uint64_t value,
                              std::uint64_t limit) {
    auto error = make_workspace_error(workspace_error_code_t::limit_exceeded,
                                      std::move(message), "pe_parse");
    error.details.emplace_back("value", std::to_string(value));
    error.details.emplace_back("limit", std::to_string(limit));
    return error;
}

workspace_error_t stop_error(const cancellation_token_t& cancel) {
    if (cancel.deadline_exceeded()) {
        auto error = make_workspace_error(workspace_error_code_t::deadline_exceeded,
                                          "PE parsing deadline exceeded", "pe_parse");
        error.deadline = true;
        return error;
    }
    auto error = make_workspace_error(workspace_error_code_t::cancelled,
                                      "PE parsing cancelled", "pe_parse");
    error.cancellation = true;
    return error;
}

std::string section_name(const IMAGE_SECTION_HEADER& section) {
    static constexpr char hex[] = "0123456789abcdef";
    std::string result;
    for (std::size_t index = 0;
         index < IMAGE_SIZEOF_SHORT_NAME && section.Name[index] != 0; ++index) {
        const auto value = static_cast<std::uint8_t>(section.Name[index]);
        if (value >= 0x20 && value <= 0x7e) {
            result.push_back(static_cast<char>(value));
        } else {
            result.push_back('\\');
            result.push_back('x');
            result.push_back(hex[value >> 4]);
            result.push_back(hex[value & 0x0f]);
        }
    }
    return result;
}

bool valid_utf8_text(const std::string& text) {
    if (text.empty())
        return true;
    if (std::any_of(text.begin(), text.end(), [](unsigned char value) {
            return value < 0x20 || value == 0x7f;
        }))
        return false;
    return MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(),
                               static_cast<int>(text.size()), nullptr, 0) > 0;
}

bool ends_with(std::string_view value, std::string_view suffix) {
    if (value.size() < suffix.size())
        return false;
    const auto tail = value.substr(value.size() - suffix.size());
    return std::equal(tail.begin(), tail.end(), suffix.begin(), suffix.end(),
                      [](unsigned char lhs, unsigned char rhs) {
                          return std::tolower(lhs) == std::tolower(rhs);
                      });
}

}

std::array<std::uint8_t, pe_parser_profile_t::canonical_byte_count>
pe_parser_profile_t::canonical_bytes() const noexcept {
    const std::array<std::uint64_t, 20> words{{
        0x5250455041446941ULL,
        schema_version,
        feature_mask,
        limits.max_sections,
        limits.max_import_descriptors,
        limits.max_imports,
        limits.max_exports,
        limits.max_relocations,
        limits.max_tls_callbacks,
        limits.max_runtime_functions,
        limits.max_unwind_codes,
        limits.max_unwind_chain_depth,
        limits.max_language_scopes,
        limits.max_load_config_entries,
        limits.max_resources,
        limits.max_resource_depth,
        limits.max_string_bytes,
        limits.max_dynamic_relocation_records,
        limits.max_dynamic_relocation_bytes,
        limits.max_total_metadata_bytes
    }};
    std::array<std::uint8_t, canonical_byte_count> bytes{};
    for (std::size_t word = 0; word < words.size(); ++word) {
        for (std::size_t byte = 0; byte < sizeof(std::uint64_t); ++byte)
            bytes[word * sizeof(std::uint64_t) + byte] =
                static_cast<std::uint8_t>(words[word] >> (byte * 8));
    }
    return bytes;
}

pe_parser_profile_t make_pe_parser_profile(const pe_parse_limits_t& limits) noexcept {
    pe_parser_profile_t profile;
    profile.limits = limits;
    return profile;
}

workspace_result_t<void> validate_pe_parser_profile(const pe_parser_profile_t& profile) {
    const pe_parser_profile_t canonical;
    const auto& limits = profile.limits;
    if (profile.feature_mask != canonical.feature_mask ||
        limits.max_sections == 0 || limits.max_import_descriptors == 0 ||
        limits.max_imports == 0 || limits.max_exports == 0 ||
        limits.max_relocations == 0 || limits.max_tls_callbacks == 0 ||
        limits.max_runtime_functions == 0 || limits.max_unwind_codes == 0 ||
        limits.max_unwind_chain_depth == 0 || limits.max_language_scopes == 0 ||
        limits.max_load_config_entries == 0 || limits.max_resources == 0 ||
        limits.max_resource_depth == 0 || limits.max_string_bytes == 0 ||
        limits.max_dynamic_relocation_records == 0 ||
        limits.max_dynamic_relocation_bytes == 0 ||
        limits.max_total_metadata_bytes == 0 || limits.max_sections > 65535 ||
        limits.max_unwind_chain_depth > 32 || limits.max_resource_depth > 64 ||
        limits.max_string_bytes > 16U * 1024U * 1024U ||
        limits.max_dynamic_relocation_bytes > 1024ULL * 1024ULL * 1024ULL ||
        limits.max_total_metadata_bytes > 1024ULL * 1024ULL * 1024ULL) {
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "PE parser profile is outside supported safety bounds",
                                 "pe_parse"));
    }
    return workspace_result_t<void>::success();
}

class pe_parser_t {
public:
    pe_parser_t(const byte_provider_t& provider, const pe_parse_limits_t& limits,
                const cancellation_token_t& cancel)
        : provider_(provider), limits_(limits), cancel_(cancel),
          image_(std::make_shared<pe_image_t>()) {
        image_->parser_profile_ = make_pe_parser_profile(limits);
    }

    workspace_result_t<std::shared_ptr<const pe_image_t>> parse() {
        auto result = parse_headers();
        if (!result)
            return workspace_result_t<std::shared_ptr<const pe_image_t>>::failure(result.error());
        result = parse_import_directory(false);
        if (!result)
            return workspace_result_t<std::shared_ptr<const pe_image_t>>::failure(result.error());
        result = parse_import_directory(true);
        if (!result)
            return workspace_result_t<std::shared_ptr<const pe_image_t>>::failure(result.error());
        result = parse_exports();
        if (!result)
            return workspace_result_t<std::shared_ptr<const pe_image_t>>::failure(result.error());
        result = parse_relocations();
        if (!result)
            return workspace_result_t<std::shared_ptr<const pe_image_t>>::failure(result.error());
        result = parse_tls();
        if (!result)
            return workspace_result_t<std::shared_ptr<const pe_image_t>>::failure(result.error());
        result = parse_exception_directory();
        if (!result)
            return workspace_result_t<std::shared_ptr<const pe_image_t>>::failure(result.error());
        result = parse_load_config();
        if (!result)
            return workspace_result_t<std::shared_ptr<const pe_image_t>>::failure(result.error());
        result = parse_debug_directory();
        if (!result)
            return workspace_result_t<std::shared_ptr<const pe_image_t>>::failure(result.error());
        result = parse_resources();
        if (!result)
            return workspace_result_t<std::shared_ptr<const pe_image_t>>::failure(result.error());
        if (cancel_.stop_requested())
            return workspace_result_t<std::shared_ptr<const pe_image_t>>::failure(
                stop_error(cancel_));
        sort_results();
        if (cancel_.stop_requested())
            return workspace_result_t<std::shared_ptr<const pe_image_t>>::failure(
                stop_error(cancel_));
        return workspace_result_t<std::shared_ptr<const pe_image_t>>::success(
            std::static_pointer_cast<const pe_image_t>(image_));
    }

private:
    workspace_result_t<const std::uint8_t*> cached_data(
        std::uint64_t offset, std::uint64_t size_value) const {
        if (cancel_.stop_requested())
            return workspace_result_t<const std::uint8_t*>::failure(stop_error(cancel_));
        auto requested = validate_span(offset, size_value, provider_.size(), "pe_parse");
        if (!requested)
            return workspace_result_t<const std::uint8_t*>::failure(requested.error());
        std::uint64_t requested_end = 0;
        std::uint64_t cache_end = 0;
        if (checked_add_u64(offset, size_value, requested_end) &&
            checked_add_u64(read_cache_offset_, read_cache_.size(), cache_end) &&
            read_cache_.data() && offset >= read_cache_offset_ && requested_end <= cache_end)
            return workspace_result_t<const std::uint8_t*>::success(
                read_cache_.data() + static_cast<std::size_t>(offset - read_cache_offset_));
        constexpr std::uint64_t locality_window = 64ULL * 1024ULL;
        const std::uint64_t aligned = offset - (offset % locality_window);
        const std::uint64_t desired = std::max<std::uint64_t>(
            size_value, std::min<std::uint64_t>(locality_window, provider_.size() - aligned));
        auto lease = provider_.lease(aligned, desired, cancel_);
        std::uint64_t lease_offset = aligned;
        if (!lease && lease.error().code == workspace_error_code_t::limit_exceeded &&
            (aligned != offset || desired != size_value)) {
            lease = provider_.lease(offset, size_value, cancel_);
            lease_offset = offset;
        }
        if (!lease)
            return workspace_result_t<const std::uint8_t*>::failure(lease.error());
        read_cache_ = lease.take_value();
        read_cache_offset_ = lease_offset;
        if (read_cache_.size() < size_value || offset < read_cache_offset_ ||
            offset - read_cache_offset_ > read_cache_.size() - size_value)
            return workspace_result_t<const std::uint8_t*>::failure(
                pe_error("PE locality view does not contain the requested bytes",
                         offset, size_value));
        return workspace_result_t<const std::uint8_t*>::success(
            read_cache_.data() + static_cast<std::size_t>(offset - read_cache_offset_));
    }

    workspace_result_t<void> consume_metadata_bytes(std::uint64_t amount) {
        std::uint64_t next = 0;
        if (!checked_add_u64(metadata_bytes_, amount, next))
            return workspace_result_t<void>::failure(
                pe_error("PE metadata byte accounting overflowed"));
        if (next > limits_.max_total_metadata_bytes)
            return workspace_result_t<void>::failure(
                limit_error("PE metadata exceeds its aggregate byte limit", next,
                            limits_.max_total_metadata_bytes));
        metadata_bytes_ = next;
        return workspace_result_t<void>::success();
    }

    workspace_result_t<void> add_entry_point(std::uint32_t rva,
                                             std::string provenance) {
        auto budget = consume_metadata_bytes(sizeof(pe_entry_point_t) + provenance.size());
        if (!budget)
            return budget;
        image_->entry_points_.push_back({rva, std::move(provenance)});
        return workspace_result_t<void>::success();
    }

    template <typename T>
    workspace_result_t<T> read_file(std::uint64_t offset) const {
        static_assert(std::is_trivially_copyable_v<T>);
        auto bytes = cached_data(offset, sizeof(T));
        if (!bytes)
            return workspace_result_t<T>::failure(bytes.error());
        T value{};
        std::memcpy(&value, bytes.value(), sizeof(value));
        return workspace_result_t<T>::success(value);
    }

    template <typename T>
    workspace_result_t<T> read_rva(std::uint64_t rva) const {
        auto offset_result = image_->rva_to_file_offset(rva, sizeof(T));
        if (!offset_result)
            return workspace_result_t<T>::failure(offset_result.error());
        return read_file<T>(offset_result.value());
    }

    const pe_data_directory_t* directory(std::uint32_t index) const noexcept {
        const auto iterator = std::find_if(image_->directories_.begin(), image_->directories_.end(),
                                           [index](const auto& item) { return item.index == index; });
        if (iterator == image_->directories_.end() || iterator->rva == 0 || iterator->size == 0)
            return nullptr;
        return &*iterator;
    }

    workspace_result_t<std::string> read_cstring_rva(std::uint32_t rva,
                                                     std::uint32_t limit = 0) {
        const std::uint32_t hard_limit = limit == 0 ? limits_.max_string_bytes
                                                    : std::min(limit, limits_.max_string_bytes);
        if (hard_limit == 0)
            return workspace_result_t<std::string>::failure(
                limit_error("PE string limit is zero", 0, 0));
        auto offset_result = image_->rva_to_file_offset(rva, 1);
        if (!offset_result)
            return workspace_result_t<std::string>::failure(offset_result.error());
        std::uint64_t available = 0;
        if (const auto* section = image_->section_for_rva(rva, 1)) {
            const std::uint64_t delta = rva - section->virtual_address;
            available = section->raw_size - delta;
        } else if (rva < image_->headers_size_) {
            available = image_->headers_size_ - rva;
        }
        available = std::min<std::uint64_t>(available, hard_limit);
        if (available == 0)
            return workspace_result_t<std::string>::failure(pe_error("PE string has no mapped bytes", rva));
        std::string text;
        std::uint64_t consumed = 0;
        while (consumed < available) {
            auto data_result = cached_data(offset_result.value() + consumed, 1);
            if (!data_result)
                return workspace_result_t<std::string>::failure(data_result.error());
            std::uint64_t cache_end = 0;
            if (!checked_add_u64(read_cache_offset_, read_cache_.size(), cache_end))
                return workspace_result_t<std::string>::failure(
                    pe_error("PE string cache range overflowed"));
            const auto cursor = offset_result.value() + consumed;
            const auto chunk = std::min<std::uint64_t>(available - consumed,
                                                       cache_end - cursor);
            const auto* bytes = data_result.value();
            const auto* terminator = std::find(bytes, bytes + static_cast<std::size_t>(chunk),
                                               static_cast<std::uint8_t>(0));
            const auto append_size = static_cast<std::size_t>(terminator - bytes);
            text.append(reinterpret_cast<const char*>(bytes), append_size);
            consumed += append_size;
            if (terminator != bytes + static_cast<std::size_t>(chunk)) {
                if (!valid_utf8_text(text))
                    return workspace_result_t<std::string>::failure(
                        pe_error("PE string is not valid printable UTF-8", rva,
                                 text.size()));
                auto budget = consume_metadata_bytes(text.size());
                if (!budget)
                    return workspace_result_t<std::string>::failure(budget.error());
                return workspace_result_t<std::string>::success(std::move(text));
            }
        }
        return workspace_result_t<std::string>::failure(
            pe_error("PE string is not terminated", rva, available));
    }

    workspace_result_t<std::uint32_t> va_field_to_rva(std::uint64_t value,
                                                      const char* field) const {
        if (value == 0)
            return workspace_result_t<std::uint32_t>::success(0);
        auto result = image_->va_to_rva(value);
        if (!result || result.value() > std::numeric_limits<std::uint32_t>::max()) {
            auto error = pe_error(std::string(field) + " VA is outside the image");
            error.address = address_t{address_space_id_t::virtual_address, value,
                                      image_->architecture_, image_->mode_};
            return workspace_result_t<std::uint32_t>::failure(std::move(error));
        }
        return workspace_result_t<std::uint32_t>::success(
            static_cast<std::uint32_t>(result.value()));
    }

    workspace_result_t<void> parse_headers() {
        if (provider_.size() < sizeof(IMAGE_DOS_HEADER))
            return workspace_result_t<void>::failure(pe_error("file is smaller than a DOS header"));
        auto dos_result = read_file<IMAGE_DOS_HEADER>(0);
        if (!dos_result)
            return workspace_result_t<void>::failure(dos_result.error());
        const auto& dos = dos_result.value();
        if (dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < 0)
            return workspace_result_t<void>::failure(pe_error("DOS header signature or NT offset is invalid"));
        const std::uint64_t nt_offset = static_cast<std::uint32_t>(dos.e_lfanew);
        std::uint64_t file_header_offset = 0;
        if (!checked_add_u64(nt_offset, sizeof(std::uint32_t), file_header_offset))
            return workspace_result_t<void>::failure(pe_error("NT header offset overflowed", nt_offset));
        auto signature_result = read_file<std::uint32_t>(nt_offset);
        if (!signature_result)
            return workspace_result_t<void>::failure(signature_result.error());
        if (signature_result.value() != IMAGE_NT_SIGNATURE)
            return workspace_result_t<void>::failure(pe_error("NT signature is invalid", nt_offset));
        auto file_header_result = read_file<IMAGE_FILE_HEADER>(file_header_offset);
        if (!file_header_result)
            return workspace_result_t<void>::failure(file_header_result.error());
        const auto file_header = file_header_result.value();
        if (file_header.NumberOfSections == 0 || file_header.NumberOfSections > limits_.max_sections)
            return workspace_result_t<void>::failure(
                limit_error("PE section count is outside its limit",
                            file_header.NumberOfSections, limits_.max_sections));
        if (file_header.Machine == IMAGE_FILE_MACHINE_I386) {
            image_->architecture_ = architecture_id_t::x86;
            image_->mode_ = architecture_mode_t::x86_32;
            image_->abi_ = abi_id_t::windows_x86;
        } else if (file_header.Machine == IMAGE_FILE_MACHINE_AMD64) {
            image_->architecture_ = architecture_id_t::x86_64;
            image_->mode_ = architecture_mode_t::x86_64;
            image_->abi_ = abi_id_t::windows_x64;
        } else {
            auto error = make_workspace_error(workspace_error_code_t::unsupported_pe_arch,
                                              "PE machine is not x86 or x86-64", "pe_parse");
            error.details.emplace_back("machine", std::to_string(file_header.Machine));
            return workspace_result_t<void>::failure(std::move(error));
        }
        image_->machine_ = file_header.Machine;
        image_->characteristics_ = file_header.Characteristics;
        image_->timestamp_ = file_header.TimeDateStamp;
        std::uint64_t optional_offset = 0;
        if (!checked_add_u64(file_header_offset, sizeof(IMAGE_FILE_HEADER), optional_offset))
            return workspace_result_t<void>::failure(pe_error("optional header offset overflowed"));
        if (file_header.SizeOfOptionalHeader == 0 || file_header.SizeOfOptionalHeader > 4096)
            return workspace_result_t<void>::failure(pe_error("optional header size is invalid", optional_offset,
                                                              file_header.SizeOfOptionalHeader));
        auto optional_bytes_result = provider_.read_vector(optional_offset,
                                                           file_header.SizeOfOptionalHeader,
                                                           4096, cancel_);
        if (!optional_bytes_result)
            return workspace_result_t<void>::failure(optional_bytes_result.error());
        const auto& optional_bytes = optional_bytes_result.value();
        if (optional_bytes.size() < sizeof(std::uint16_t))
            return workspace_result_t<void>::failure(pe_error("optional header is truncated", optional_offset));
        std::uint16_t magic = 0;
        std::memcpy(&magic, optional_bytes.data(), sizeof(magic));
        std::uint32_t directory_count = 0;
        std::size_t directory_offset = 0;
        if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
            if (image_->architecture_ != architecture_id_t::x86 ||
                optional_bytes.size() < offsetof(IMAGE_OPTIONAL_HEADER32, DataDirectory))
                return workspace_result_t<void>::failure(pe_error("PE32 optional header is inconsistent"));
            IMAGE_OPTIONAL_HEADER32 header{};
            std::memcpy(&header, optional_bytes.data(), std::min(optional_bytes.size(), sizeof(header)));
            image_->format_ = format_id_t::pe32;
            image_->image_base_ = header.ImageBase;
            image_->image_size_ = header.SizeOfImage;
            image_->headers_size_ = header.SizeOfHeaders;
            image_->entry_rva_ = header.AddressOfEntryPoint;
            image_->subsystem_ = header.Subsystem;
            image_->dll_characteristics_ = header.DllCharacteristics;
            directory_count = header.NumberOfRvaAndSizes;
            directory_offset = offsetof(IMAGE_OPTIONAL_HEADER32, DataDirectory);
        } else if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            if (image_->architecture_ != architecture_id_t::x86_64 ||
                optional_bytes.size() < offsetof(IMAGE_OPTIONAL_HEADER64, DataDirectory))
                return workspace_result_t<void>::failure(pe_error("PE32+ optional header is inconsistent"));
            IMAGE_OPTIONAL_HEADER64 header{};
            std::memcpy(&header, optional_bytes.data(), std::min(optional_bytes.size(), sizeof(header)));
            image_->format_ = format_id_t::pe32_plus;
            image_->image_base_ = header.ImageBase;
            image_->image_size_ = header.SizeOfImage;
            image_->headers_size_ = header.SizeOfHeaders;
            image_->entry_rva_ = header.AddressOfEntryPoint;
            image_->subsystem_ = header.Subsystem;
            image_->dll_characteristics_ = header.DllCharacteristics;
            directory_count = header.NumberOfRvaAndSizes;
            directory_offset = offsetof(IMAGE_OPTIONAL_HEADER64, DataDirectory);
        } else {
            return workspace_result_t<void>::failure(pe_error("optional header magic is unsupported"));
        }
        if (image_->image_size_ == 0 || image_->headers_size_ == 0 ||
            image_->headers_size_ > provider_.size() || image_->headers_size_ > image_->image_size_)
            return workspace_result_t<void>::failure(pe_error("image or header size is invalid"));
        const std::size_t available_directories =
            (optional_bytes.size() - directory_offset) / sizeof(IMAGE_DATA_DIRECTORY);
        if (directory_count > available_directories ||
            directory_count > IMAGE_NUMBEROF_DIRECTORY_ENTRIES)
            return workspace_result_t<void>::failure(
                pe_error("optional header data-directory count is invalid"));
        for (std::uint32_t index = 0; index < directory_count; ++index) {
            IMAGE_DATA_DIRECTORY item{};
            std::memcpy(&item, optional_bytes.data() + directory_offset +
                                   index * sizeof(IMAGE_DATA_DIRECTORY), sizeof(item));
            if (item.VirtualAddress == 0 && item.Size == 0)
                continue;
            if (item.VirtualAddress == 0 || item.Size == 0)
                return workspace_result_t<void>::failure(
                    pe_error("data directory has an incomplete range"));
            std::uint64_t end = 0;
            if (!checked_add_u64(item.VirtualAddress, item.Size, end))
                return workspace_result_t<void>::failure(pe_error("data directory range overflowed"));
            if (index == IMAGE_DIRECTORY_ENTRY_SECURITY) {
                if (end > provider_.size())
                    return workspace_result_t<void>::failure(
                        pe_error("certificate directory exceeds file bounds",
                                 item.VirtualAddress, item.Size));
            } else if (end > image_->image_size_)
                return workspace_result_t<void>::failure(pe_error("data directory exceeds image bounds",
                                                                  item.VirtualAddress, item.Size));
            image_->directories_.push_back({index, item.VirtualAddress, item.Size});
        }
        std::uint64_t section_table = 0;
        if (!checked_add_u64(optional_offset, file_header.SizeOfOptionalHeader, section_table))
            return workspace_result_t<void>::failure(pe_error("section table offset overflowed"));
        std::uint64_t section_bytes = 0;
        if (!checked_mul_u64(file_header.NumberOfSections, sizeof(IMAGE_SECTION_HEADER), section_bytes))
            return workspace_result_t<void>::failure(pe_error("section table size overflowed"));
        auto section_range = validate_span(section_table, section_bytes, provider_.size(), "pe_parse");
        if (!section_range)
            return workspace_result_t<void>::failure(pe_error("section table is outside the file",
                                                              section_table, section_bytes));
        auto section_header_range = validate_span(section_table, section_bytes,
                                                  image_->headers_size_, "pe_parse");
        if (!section_header_range)
            return workspace_result_t<void>::failure(
                pe_error("section table exceeds SizeOfHeaders", section_table, section_bytes));
        image_->sections_.reserve(file_header.NumberOfSections);
        for (std::uint32_t index = 0; index < file_header.NumberOfSections; ++index) {
            auto section_result = read_file<IMAGE_SECTION_HEADER>(
                section_table + index * sizeof(IMAGE_SECTION_HEADER));
            if (!section_result)
                return workspace_result_t<void>::failure(section_result.error());
            const auto section = section_result.value();
            const std::uint64_t raw_end = static_cast<std::uint64_t>(section.PointerToRawData) +
                                          section.SizeOfRawData;
            if ((section.SizeOfRawData != 0 && section.PointerToRawData < image_->headers_size_) ||
                raw_end > provider_.size())
                return workspace_result_t<void>::failure(pe_error("section raw range exceeds file bounds",
                                                                  section.PointerToRawData,
                                                                  section.SizeOfRawData));
            const std::uint64_t virtual_extent =
                std::max<std::uint64_t>(section.Misc.VirtualSize, section.SizeOfRawData);
            const std::uint64_t virtual_end = static_cast<std::uint64_t>(section.VirtualAddress) +
                                              virtual_extent;
            if ((virtual_extent != 0 && section.VirtualAddress < image_->headers_size_) ||
                virtual_end > image_->image_size_)
                return workspace_result_t<void>::failure(pe_error("section virtual range exceeds image bounds",
                                                                  section.VirtualAddress,
                                                                  virtual_extent));
            pe_section_t normalized;
            normalized.index = index;
            normalized.name = section_name(section);
            normalized.virtual_address = section.VirtualAddress;
            normalized.virtual_size = section.Misc.VirtualSize;
            normalized.raw_offset = section.PointerToRawData;
            normalized.raw_size = section.SizeOfRawData;
            normalized.characteristics = section.Characteristics;
            normalized.readable = (section.Characteristics & IMAGE_SCN_MEM_READ) != 0;
            normalized.writable = (section.Characteristics & IMAGE_SCN_MEM_WRITE) != 0;
            normalized.executable = (section.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
            normalized.discardable = (section.Characteristics & IMAGE_SCN_MEM_DISCARDABLE) != 0;
            auto section_budget = consume_metadata_bytes(sizeof(pe_section_t) +
                                                         normalized.name.size());
            if (!section_budget)
                return section_budget;
            image_->sections_.push_back(std::move(normalized));
        }
        auto raw_sections = image_->sections_;
        raw_sections.erase(std::remove_if(raw_sections.begin(), raw_sections.end(),
                                          [](const auto& item) { return item.raw_size == 0; }),
                           raw_sections.end());
        std::sort(raw_sections.begin(), raw_sections.end(),
                  [](const auto& lhs, const auto& rhs) { return lhs.raw_offset < rhs.raw_offset; });
        for (std::size_t index = 1; index < raw_sections.size(); ++index) {
            const std::uint64_t previous_end =
                static_cast<std::uint64_t>(raw_sections[index - 1].raw_offset) +
                raw_sections[index - 1].raw_size;
            if (previous_end > raw_sections[index].raw_offset)
                return workspace_result_t<void>::failure(pe_error("section raw ranges overlap"));
        }
        auto virtual_sections = image_->sections_;
        virtual_sections.erase(std::remove_if(virtual_sections.begin(), virtual_sections.end(),
            [](const auto& item) { return std::max(item.virtual_size, item.raw_size) == 0; }),
            virtual_sections.end());
        std::sort(virtual_sections.begin(), virtual_sections.end(),
                  [](const auto& lhs, const auto& rhs) {
                      return lhs.virtual_address < rhs.virtual_address;
                  });
        for (std::size_t index = 1; index < virtual_sections.size(); ++index) {
            const std::uint64_t previous_end =
                static_cast<std::uint64_t>(virtual_sections[index - 1].virtual_address) +
                std::max(virtual_sections[index - 1].virtual_size,
                         virtual_sections[index - 1].raw_size);
            if (previous_end > virtual_sections[index].virtual_address)
                return workspace_result_t<void>::failure(pe_error("section virtual ranges overlap"));
        }
        std::sort(image_->sections_.begin(), image_->sections_.end(),
                  [](const auto& lhs, const auto& rhs) {
                      return std::tie(lhs.virtual_address, lhs.index) <
                             std::tie(rhs.virtual_address, rhs.index);
                  });
        if ((file_header.Characteristics & IMAGE_FILE_DLL) != 0)
            image_->artifact_kind_ = pe_artifact_kind_t::dynamic_library;
        else if (image_->subsystem_ == IMAGE_SUBSYSTEM_NATIVE &&
                 ends_with(provider_.identity().normalized_source, ".sys"))
            image_->artifact_kind_ = pe_artifact_kind_t::driver;
        else
            image_->artifact_kind_ = pe_artifact_kind_t::executable;
        if (image_->entry_rva_ != 0) {
            const auto* section = image_->section_for_rva(image_->entry_rva_, 1);
            auto mapped_entry = image_->rva_to_file_offset(image_->entry_rva_, 1);
            if (!section || !section->executable || !mapped_entry)
                return workspace_result_t<void>::failure(pe_error("entry point is not mapped executable code",
                                                                  image_->entry_rva_, 1));
            auto entry_result = add_entry_point(image_->entry_rva_, "image_entry");
            if (!entry_result)
                return entry_result;
        }
        for (const auto& item : image_->directories_) {
            if (item.index == IMAGE_DIRECTORY_ENTRY_SECURITY)
                continue;
            auto mapped = image_->rva_to_file_offset(item.rva, item.size);
            if (!mapped)
                return workspace_result_t<void>::failure(pe_error("data directory is not fully file-backed",
                                                                  item.rva, item.size));
        }
        return workspace_result_t<void>::success();
    }

    workspace_result_t<void> parse_thunks(std::uint32_t lookup_rva, std::uint32_t iat_rva,
                                          const std::string& library, bool delayed,
                                          std::uint32_t& total_imports) {
        const std::uint64_t stride = image_->format_ == format_id_t::pe32_plus ? 8 : 4;
        const std::uint64_t ordinal_mask = image_->format_ == format_id_t::pe32_plus
                                               ? IMAGE_ORDINAL_FLAG64
                                               : IMAGE_ORDINAL_FLAG32;
        for (std::uint32_t index = 0; index < limits_.max_imports; ++index) {
            if ((index % 4096) == 0 && cancel_.stop_requested())
                return workspace_result_t<void>::failure(stop_error(cancel_));
            if (total_imports >= limits_.max_imports)
                return workspace_result_t<void>::failure(
                    limit_error("import count exceeds its limit", total_imports,
                                limits_.max_imports));
            std::uint64_t entry_rva_u64 = 0;
            if (!checked_add_u64(lookup_rva, static_cast<std::uint64_t>(index) * stride,
                                 entry_rva_u64) ||
                entry_rva_u64 > std::numeric_limits<std::uint32_t>::max())
                return workspace_result_t<void>::failure(pe_error("import thunk RVA overflowed"));
            std::uint64_t thunk = 0;
            if (stride == 8) {
                auto result = read_rva<std::uint64_t>(entry_rva_u64);
                if (!result)
                    return workspace_result_t<void>::failure(result.error());
                thunk = result.value();
            } else {
                auto result = read_rva<std::uint32_t>(entry_rva_u64);
                if (!result)
                    return workspace_result_t<void>::failure(result.error());
                thunk = result.value();
            }
            if (thunk == 0)
                return workspace_result_t<void>::success();
            auto import_budget = consume_metadata_bytes(sizeof(pe_import_t) + library.size());
            if (!import_budget)
                return import_budget;
            pe_import_t item;
            item.library = library;
            item.lookup_rva = static_cast<std::uint32_t>(entry_rva_u64);
            const std::uint64_t iat = static_cast<std::uint64_t>(iat_rva) +
                                      static_cast<std::uint64_t>(index) * stride;
            if (iat > std::numeric_limits<std::uint32_t>::max())
                return workspace_result_t<void>::failure(pe_error("import IAT RVA overflowed"));
            item.iat_rva = static_cast<std::uint32_t>(iat);
            item.delayed = delayed;
            if ((thunk & ordinal_mask) != 0) {
                item.ordinal = static_cast<std::uint16_t>(thunk & 0xffffU);
            } else {
                if (thunk > std::numeric_limits<std::uint32_t>::max())
                    return workspace_result_t<void>::failure(pe_error("import name RVA is invalid"));
                auto hint_result = read_rva<std::uint16_t>(thunk);
                if (!hint_result)
                    return workspace_result_t<void>::failure(hint_result.error());
                std::uint64_t name_rva = 0;
                if (!checked_add_u64(thunk, sizeof(std::uint16_t), name_rva) ||
                    name_rva > std::numeric_limits<std::uint32_t>::max())
                    return workspace_result_t<void>::failure(pe_error("import name RVA overflowed"));
                auto name_result = read_cstring_rva(static_cast<std::uint32_t>(name_rva));
                if (!name_result)
                    return workspace_result_t<void>::failure(name_result.error());
                if (name_result.value().empty())
                    return workspace_result_t<void>::failure(
                        pe_error("import symbol name is empty"));
                item.hint = hint_result.value();
                item.name = name_result.take_value();
            }
            image_->imports_.push_back(std::move(item));
            ++total_imports;
        }
        return workspace_result_t<void>::failure(
            limit_error("import thunk table is not terminated", limits_.max_imports,
                        limits_.max_imports));
    }

    workspace_result_t<void> parse_import_directory(bool delayed) {
        const auto* data = directory(delayed ? IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT
                                             : IMAGE_DIRECTORY_ENTRY_IMPORT);
        if (!data)
            return workspace_result_t<void>::success();
        std::uint32_t total_imports = static_cast<std::uint32_t>(image_->imports_.size());
        const std::uint64_t descriptor_size = delayed ? sizeof(delay_descriptor_t)
                                                      : sizeof(IMAGE_IMPORT_DESCRIPTOR);
        const std::uint64_t capacity = data->size / descriptor_size;
        const std::uint64_t descriptors = std::min<std::uint64_t>(
            capacity, limits_.max_import_descriptors);
        bool terminated = false;
        for (std::uint64_t index = 0; index < descriptors; ++index) {
            if (cancel_.stop_requested())
                return workspace_result_t<void>::failure(stop_error(cancel_));
            const std::uint64_t descriptor_rva = data->rva + index * descriptor_size;
            if (!delayed) {
                auto descriptor_result = read_rva<IMAGE_IMPORT_DESCRIPTOR>(descriptor_rva);
                if (!descriptor_result)
                    return workspace_result_t<void>::failure(descriptor_result.error());
                const auto descriptor = descriptor_result.value();
                if (descriptor.OriginalFirstThunk == 0 && descriptor.FirstThunk == 0 &&
                    descriptor.Name == 0 && descriptor.TimeDateStamp == 0 &&
                    descriptor.ForwarderChain == 0) {
                    terminated = true;
                    break;
                }
                if (descriptor.Name == 0 || descriptor.FirstThunk == 0)
                    return workspace_result_t<void>::failure(pe_error("import descriptor is incomplete"));
                auto library_result = read_cstring_rva(descriptor.Name);
                if (!library_result)
                    return workspace_result_t<void>::failure(library_result.error());
                if (library_result.value().empty())
                    return workspace_result_t<void>::failure(pe_error("import library name is empty"));
                const std::uint32_t lookup = descriptor.OriginalFirstThunk != 0
                                                 ? descriptor.OriginalFirstThunk
                                                 : descriptor.FirstThunk;
                auto thunk_result = parse_thunks(lookup, descriptor.FirstThunk,
                                                 library_result.value(), false, total_imports);
                if (!thunk_result)
                    return thunk_result;
            } else {
                auto descriptor_result = read_rva<delay_descriptor_t>(descriptor_rva);
                if (!descriptor_result)
                    return workspace_result_t<void>::failure(descriptor_result.error());
                const auto descriptor = descriptor_result.value();
                if (descriptor.attributes == 0 && descriptor.name == 0 &&
                    descriptor.module_handle == 0 && descriptor.iat == 0 &&
                    descriptor.int_table == 0 && descriptor.bound_iat == 0 &&
                    descriptor.unload_iat == 0 && descriptor.timestamp == 0) {
                    terminated = true;
                    break;
                }
                const bool rva_fields = (descriptor.attributes & 1U) != 0;
                if ((descriptor.attributes & ~1U) != 0)
                    return workspace_result_t<void>::failure(
                        pe_error("delay import attributes contain unsupported bits"));
                auto normalize_field = [&](std::uint32_t value, const char* name)
                    -> workspace_result_t<std::uint32_t> {
                    if (rva_fields)
                        return workspace_result_t<std::uint32_t>::success(value);
                    return va_field_to_rva(value, name);
                };
                auto name_rva = normalize_field(descriptor.name, "delay import name");
                auto iat_rva = normalize_field(descriptor.iat, "delay import IAT");
                auto int_rva = normalize_field(descriptor.int_table, "delay import INT");
                if (!name_rva || !iat_rva || !int_rva)
                    return workspace_result_t<void>::failure(
                        !name_rva ? name_rva.error() : (!iat_rva ? iat_rva.error() : int_rva.error()));
                if (name_rva.value() == 0 || iat_rva.value() == 0 || int_rva.value() == 0)
                    return workspace_result_t<void>::failure(pe_error("delay import descriptor is incomplete"));
                auto library_result = read_cstring_rva(name_rva.value());
                if (!library_result)
                    return workspace_result_t<void>::failure(library_result.error());
                if (library_result.value().empty())
                    return workspace_result_t<void>::failure(
                        pe_error("delay import library name is empty"));
                auto thunk_result = parse_thunks(int_rva.value(), iat_rva.value(),
                                                 library_result.value(), true, total_imports);
                if (!thunk_result)
                    return thunk_result;
            }
        }
        if (!terminated)
            return workspace_result_t<void>::failure(pe_error("import descriptor table is not terminated"));
        return workspace_result_t<void>::success();
    }

    workspace_result_t<void> parse_exports() {
        const auto* data = directory(IMAGE_DIRECTORY_ENTRY_EXPORT);
        if (!data)
            return workspace_result_t<void>::success();
        if (data->size < sizeof(IMAGE_EXPORT_DIRECTORY))
            return workspace_result_t<void>::failure(pe_error("export directory is truncated"));
        auto header_result = read_rva<IMAGE_EXPORT_DIRECTORY>(data->rva);
        if (!header_result)
            return workspace_result_t<void>::failure(header_result.error());
        const auto header = header_result.value();
        if (header.NumberOfFunctions > limits_.max_exports || header.NumberOfNames > limits_.max_exports)
            return workspace_result_t<void>::failure(
                limit_error("export count exceeds its limit",
                            std::max(header.NumberOfFunctions, header.NumberOfNames), limits_.max_exports));
        if (header.NumberOfNames > header.NumberOfFunctions)
            return workspace_result_t<void>::failure(pe_error("export name count exceeds function count"));
        if ((header.NumberOfFunctions != 0 && header.AddressOfFunctions == 0) ||
            (header.NumberOfNames != 0 &&
             (header.AddressOfNames == 0 || header.AddressOfNameOrdinals == 0)))
            return workspace_result_t<void>::failure(
                pe_error("export address tables are incomplete"));
        std::multimap<std::uint32_t, std::string> names;
        for (std::uint32_t index = 0; index < header.NumberOfNames; ++index) {
            if ((index % 4096) == 0 && cancel_.stop_requested())
                return workspace_result_t<void>::failure(stop_error(cancel_));
            auto name_rva_result = read_rva<std::uint32_t>(
                static_cast<std::uint64_t>(header.AddressOfNames) + index * sizeof(std::uint32_t));
            auto ordinal_result = read_rva<std::uint16_t>(
                static_cast<std::uint64_t>(header.AddressOfNameOrdinals) + index * sizeof(std::uint16_t));
            if (!name_rva_result || !ordinal_result)
                return workspace_result_t<void>::failure(
                    !name_rva_result ? name_rva_result.error() : ordinal_result.error());
            if (ordinal_result.value() >= header.NumberOfFunctions)
                return workspace_result_t<void>::failure(pe_error("export name ordinal is out of range"));
            auto name_result = read_cstring_rva(name_rva_result.value());
            if (!name_result)
                return workspace_result_t<void>::failure(name_result.error());
            if (name_result.value().empty())
                return workspace_result_t<void>::failure(pe_error("export name is empty"));
            auto name_budget = consume_metadata_bytes(
                sizeof(std::pair<const std::uint32_t, std::string>));
            if (!name_budget)
                return name_budget;
            names.emplace(ordinal_result.value(), name_result.take_value());
        }
        const std::uint64_t forwarder_end = static_cast<std::uint64_t>(data->rva) + data->size;
        for (std::uint32_t index = 0; index < header.NumberOfFunctions; ++index) {
            if ((index % 4096) == 0 && cancel_.stop_requested())
                return workspace_result_t<void>::failure(stop_error(cancel_));
            auto function_result = read_rva<std::uint32_t>(
                static_cast<std::uint64_t>(header.AddressOfFunctions) + index * sizeof(std::uint32_t));
            if (!function_result)
                return workspace_result_t<void>::failure(function_result.error());
            if (function_result.value() == 0)
                continue;
            const std::uint32_t function_rva = function_result.value();
            std::optional<std::string> forwarder;
            if (function_rva >= data->rva && function_rva < forwarder_end) {
                auto forwarder_result = read_cstring_rva(function_rva,
                    static_cast<std::uint32_t>(forwarder_end - function_rva));
                if (!forwarder_result)
                    return workspace_result_t<void>::failure(forwarder_result.error());
                if (forwarder_result.value().empty())
                    return workspace_result_t<void>::failure(
                        pe_error("export forwarder is empty"));
                forwarder = forwarder_result.take_value();
            } else if (!image_->section_for_rva(function_rva, 1)) {
                return workspace_result_t<void>::failure(pe_error("export RVA is not mapped", function_rva));
            } else {
                const auto* section = image_->section_for_rva(function_rva, 1);
                if (section && section->executable) {
                    auto entry_result = add_entry_point(function_rva, "export");
                    if (!entry_result)
                        return entry_result;
                }
            }
            const auto aliases = names.equal_range(index);
            const std::uint64_t ordinal = static_cast<std::uint64_t>(header.Base) + index;
            if (ordinal > std::numeric_limits<std::uint32_t>::max())
                return workspace_result_t<void>::failure(
                    pe_error("export ordinal overflowed"));
            if (aliases.first == aliases.second) {
                auto export_budget = consume_metadata_bytes(sizeof(pe_export_t) +
                    (forwarder ? forwarder->size() : 0));
                if (!export_budget)
                    return export_budget;
                image_->exports_.push_back({std::nullopt, static_cast<std::uint32_t>(ordinal), function_rva,
                                            std::move(forwarder)});
            } else {
                for (auto alias = aliases.first; alias != aliases.second; ++alias) {
                    auto export_budget = consume_metadata_bytes(sizeof(pe_export_t) +
                        alias->second.size() + (forwarder ? forwarder->size() : 0));
                    if (!export_budget)
                        return export_budget;
                    image_->exports_.push_back({alias->second, static_cast<std::uint32_t>(ordinal), function_rva,
                                                forwarder});
                }
            }
        }
        return workspace_result_t<void>::success();
    }

    workspace_result_t<void> parse_relocations() {
        const auto* data = directory(IMAGE_DIRECTORY_ENTRY_BASERELOC);
        if (!data)
            return workspace_result_t<void>::success();
        std::uint64_t cursor = 0;
        while (cursor < data->size) {
            if (cancel_.stop_requested())
                return workspace_result_t<void>::failure(stop_error(cancel_));
            if (data->size - cursor < sizeof(IMAGE_BASE_RELOCATION))
                return workspace_result_t<void>::failure(pe_error("relocation block is truncated"));
            auto block_result = read_rva<IMAGE_BASE_RELOCATION>(data->rva + cursor);
            if (!block_result)
                return workspace_result_t<void>::failure(block_result.error());
            const auto block = block_result.value();
            if (block.SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION) ||
                block.SizeOfBlock > data->size - cursor || (block.SizeOfBlock & 1U) != 0)
                return workspace_result_t<void>::failure(pe_error("relocation block size is invalid"));
            const std::uint32_t count =
                (block.SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(std::uint16_t);
            for (std::uint32_t index = 0; index < count; ++index) {
                if (image_->relocations_.size() >= limits_.max_relocations)
                    return workspace_result_t<void>::failure(
                        limit_error("relocation count exceeds its limit",
                                    image_->relocations_.size(), limits_.max_relocations));
                auto entry_result = read_rva<std::uint16_t>(
                    data->rva + cursor + sizeof(IMAGE_BASE_RELOCATION) +
                    index * sizeof(std::uint16_t));
                if (!entry_result)
                    return workspace_result_t<void>::failure(entry_result.error());
                const std::uint16_t type = entry_result.value() >> 12;
                if (type == IMAGE_REL_BASED_ABSOLUTE)
                    continue;
                const std::uint64_t rva_value = static_cast<std::uint64_t>(block.VirtualAddress) +
                                                (entry_result.value() & 0x0fffU);
                if (rva_value >= image_->image_size_)
                    return workspace_result_t<void>::failure(pe_error("relocation RVA is outside the image"));
                auto relocation_budget = consume_metadata_bytes(sizeof(pe_relocation_t));
                if (!relocation_budget)
                    return relocation_budget;
                image_->relocations_.push_back({static_cast<std::uint32_t>(rva_value), type});
            }
            cursor += block.SizeOfBlock;
        }
        return workspace_result_t<void>::success();
    }

    workspace_result_t<void> parse_tls() {
        const auto* data = directory(IMAGE_DIRECTORY_ENTRY_TLS);
        if (!data)
            return workspace_result_t<void>::success();
        std::uint64_t callbacks_va = 0;
        if (image_->format_ == format_id_t::pe32_plus) {
            if (data->size < sizeof(IMAGE_TLS_DIRECTORY64))
                return workspace_result_t<void>::failure(pe_error("TLS directory is truncated"));
            auto result = read_rva<IMAGE_TLS_DIRECTORY64>(data->rva);
            if (!result)
                return workspace_result_t<void>::failure(result.error());
            callbacks_va = result.value().AddressOfCallBacks;
        } else {
            if (data->size < sizeof(IMAGE_TLS_DIRECTORY32))
                return workspace_result_t<void>::failure(pe_error("TLS directory is truncated"));
            auto result = read_rva<IMAGE_TLS_DIRECTORY32>(data->rva);
            if (!result)
                return workspace_result_t<void>::failure(result.error());
            callbacks_va = result.value().AddressOfCallBacks;
        }
        if (callbacks_va == 0)
            return workspace_result_t<void>::success();
        auto callbacks_rva = va_field_to_rva(callbacks_va, "TLS callbacks");
        if (!callbacks_rva)
            return workspace_result_t<void>::failure(callbacks_rva.error());
        const std::uint64_t stride = image_->format_ == format_id_t::pe32_plus ? 8 : 4;
        for (std::uint32_t index = 0; index < limits_.max_tls_callbacks; ++index) {
            if ((index % 4096) == 0 && cancel_.stop_requested())
                return workspace_result_t<void>::failure(stop_error(cancel_));
            std::uint64_t callback_va = 0;
            const std::uint64_t item_rva = callbacks_rva.value() + index * stride;
            if (stride == 8) {
                auto result = read_rva<std::uint64_t>(item_rva);
                if (!result)
                    return workspace_result_t<void>::failure(result.error());
                callback_va = result.value();
            } else {
                auto result = read_rva<std::uint32_t>(item_rva);
                if (!result)
                    return workspace_result_t<void>::failure(result.error());
                callback_va = result.value();
            }
            if (callback_va == 0)
                return workspace_result_t<void>::success();
            auto callback_rva = va_field_to_rva(callback_va, "TLS callback");
            if (!callback_rva)
                return workspace_result_t<void>::failure(callback_rva.error());
            const auto* section = image_->section_for_rva(callback_rva.value(), 1);
            auto mapped_callback = image_->rva_to_file_offset(callback_rva.value(), 1);
            if (!section || !section->executable || !mapped_callback)
                return workspace_result_t<void>::failure(pe_error("TLS callback is not executable"));
            auto callback_budget = consume_metadata_bytes(sizeof(std::uint32_t));
            if (!callback_budget)
                return callback_budget;
            image_->tls_callbacks_.push_back(callback_rva.value());
            auto entry_result = add_entry_point(callback_rva.value(), "tls_callback");
            if (!entry_result)
                return entry_result;
        }
        return workspace_result_t<void>::failure(
            limit_error("TLS callback table is not terminated", limits_.max_tls_callbacks,
                        limits_.max_tls_callbacks));
    }

    workspace_result_t<void> try_parse_language_scopes(pe_unwind_record_t& record) {
        if (!record.language_data_rva)
            return workspace_result_t<void>::success();
        if (cancel_.stop_requested())
            return workspace_result_t<void>::failure(stop_error(cancel_));
        auto count_result = read_rva<std::uint32_t>(*record.language_data_rva);
        if (!count_result)
            return workspace_result_t<void>::success();
        const std::uint64_t count = count_result.value();
        if (count > limits_.max_language_scopes)
            return workspace_result_t<void>::success();
        std::uint64_t record_bytes = 0;
        std::uint64_t table_bytes = 0;
        if (!checked_mul_u64(count, sizeof(pe_unwind_scope_t), record_bytes) ||
            !checked_add_u64(sizeof(std::uint32_t), record_bytes, table_bytes) ||
            table_bytes > std::numeric_limits<std::uint32_t>::max() ||
            table_bytes > limits_.max_total_metadata_bytes - metadata_bytes_ ||
            !image_->rva_to_file_offset(*record.language_data_rva, table_bytes))
            return workspace_result_t<void>::success();
        std::vector<pe_unwind_scope_t> scopes;
        scopes.reserve(static_cast<std::size_t>(count));
        for (std::uint64_t index = 0; index < count; ++index) {
            if (cancel_.stop_requested())
                return workspace_result_t<void>::failure(stop_error(cancel_));
            std::uint64_t delta = 0;
            std::uint64_t item_rva = 0;
            if (!checked_mul_u64(index, sizeof(pe_unwind_scope_t), delta) ||
                !checked_add_u64(*record.language_data_rva + sizeof(std::uint32_t),
                                 delta, item_rva))
                return workspace_result_t<void>::success();
            auto item = read_rva<pe_unwind_scope_t>(item_rva);
            if (!item)
                return workspace_result_t<void>::success();
            const auto& scope = item.value();
            const std::uint64_t scope_size = scope.end_rva > scope.begin_rva
                ? static_cast<std::uint64_t>(scope.end_rva) - scope.begin_rva : 0;
            const auto* scope_section = image_->section_for_rva(scope.begin_rva, scope_size);
            if (scope_size == 0 || scope.end_rva > image_->image_size_ ||
                !scope_section || !scope_section->executable)
                return workspace_result_t<void>::success();
            if (scope.handler_rva > 1) {
                const auto* handler_section = image_->section_for_rva(scope.handler_rva, 1);
                if (!handler_section || !handler_section->executable)
                    return workspace_result_t<void>::success();
            }
            if (scope.jump_target_rva != 0) {
                const auto* jump_section = image_->section_for_rva(scope.jump_target_rva, 1);
                if (!jump_section || !jump_section->executable)
                    return workspace_result_t<void>::success();
            }
            scopes.push_back(scope);
        }
        auto budget = consume_metadata_bytes(record_bytes);
        if (!budget)
            return budget;
        record.language_data_kind = pe_unwind_language_data_kind_t::c_specific_scope_table;
        record.language_data_size = static_cast<std::uint32_t>(table_bytes);
        record.language_scopes = std::move(scopes);
        return workspace_result_t<void>::success();
    }

    workspace_result_t<std::uint32_t> parse_unwind_record(std::uint32_t unwind_rva,
                                                           std::uint32_t depth) {
        const auto existing = unwind_index_by_rva_.find(unwind_rva);
        if (existing != unwind_index_by_rva_.end())
            return workspace_result_t<std::uint32_t>::success(existing->second);
        if (depth >= limits_.max_unwind_chain_depth)
            return workspace_result_t<std::uint32_t>::failure(
                limit_error("chained unwind depth exceeds its limit", depth + 1,
                            limits_.max_unwind_chain_depth));
        if (!active_unwind_rvas_.insert(unwind_rva).second)
            return workspace_result_t<std::uint32_t>::failure(
                pe_error("chained unwind records contain a cycle"));
        struct active_unwind_guard_t {
            std::unordered_set<std::uint32_t>& active;
            std::uint32_t rva;
            ~active_unwind_guard_t() { active.erase(rva); }
        } active_guard{active_unwind_rvas_, unwind_rva};
        if (image_->unwind_records_.size() >= limits_.max_runtime_functions)
            return workspace_result_t<std::uint32_t>::failure(
                limit_error("unwind record count exceeds its limit",
                            image_->unwind_records_.size(), limits_.max_runtime_functions));
        auto header_offset = image_->rva_to_file_offset(unwind_rva, 4);
        if (!header_offset)
            return workspace_result_t<std::uint32_t>::failure(header_offset.error());
        auto header = cached_data(header_offset.value(), 4);
        if (!header)
            return workspace_result_t<std::uint32_t>::failure(header.error());
        pe_unwind_record_t record;
        record.unwind_rva = unwind_rva;
        record.version = header.value()[0] & 0x07U;
        record.flags = header.value()[0] >> 3U;
        record.prolog_size = header.value()[1];
        const std::uint8_t code_slots = header.value()[2];
        record.frame_register = header.value()[3] & 0x0FU;
        record.frame_offset = header.value()[3] >> 4U;
        if ((record.version != 1 && record.version != 2) ||
            (record.flags & ~0x07U) != 0 ||
            ((record.flags & 0x04U) != 0 && (record.flags & 0x03U) != 0) ||
            (record.frame_register == 0 && record.frame_offset != 0) ||
            (record.frame_register != 0 &&
             record.frame_register != 3 && record.frame_register != 5 &&
             record.frame_register != 6 && record.frame_register != 7 &&
             record.frame_register < 12))
            return workspace_result_t<std::uint32_t>::failure(
                pe_error("unwind header flags or version are invalid"));
        if (code_slots > limits_.max_unwind_codes - unwind_code_count_)
            return workspace_result_t<std::uint32_t>::failure(
                limit_error("unwind code count exceeds its limit",
                            unwind_code_count_ + code_slots,
                            limits_.max_unwind_codes));
        unwind_code_count_ += code_slots;
        std::uint64_t code_bytes = 0;
        if (!checked_mul_u64(code_slots, 2, code_bytes))
            return workspace_result_t<std::uint32_t>::failure(
                pe_error("unwind code size overflowed"));
        const std::uint8_t* code_data = nullptr;
        if (code_bytes != 0) {
            auto codes_offset = image_->rva_to_file_offset(unwind_rva + 4ULL, code_bytes);
            if (!codes_offset)
                return workspace_result_t<std::uint32_t>::failure(codes_offset.error());
            auto codes = cached_data(codes_offset.value(), code_bytes);
            if (!codes)
                return workspace_result_t<std::uint32_t>::failure(codes.error());
            code_data = codes.value();
        }
        record.codes.reserve(code_slots);
        std::uint8_t slot = 0;
        std::uint8_t previous_offset = 0xFFU;
        bool seen_epilogue = false;
        bool seen_non_epilogue = false;
        while (slot < code_slots) {
            if (cancel_.stop_requested())
                return workspace_result_t<std::uint32_t>::failure(stop_error(cancel_));
            const auto* raw = code_data + static_cast<std::size_t>(slot) * 2;
            pe_unwind_code_t decoded;
            decoded.code_offset = raw[0];
            decoded.operation = static_cast<pe_unwind_operation_t>(raw[1] & 0x0FU);
            decoded.operation_info = raw[1] >> 4U;
            if (static_cast<std::uint8_t>(decoded.operation) > 10 ||
                decoded.operation == pe_unwind_operation_t::spare)
                return workspace_result_t<std::uint32_t>::failure(
                    pe_error("unwind code stream is invalid"));
            if (decoded.operation == pe_unwind_operation_t::epilogue) {
                if (record.version != 2 || seen_non_epilogue)
                    return workspace_result_t<std::uint32_t>::failure(
                        pe_error("unwind epilogue encoding is invalid"));
                decoded.slot_count = 1;
                if (!seen_epilogue) {
                    if ((decoded.operation_info & ~1U) != 0)
                        return workspace_result_t<std::uint32_t>::failure(
                            pe_error("first unwind epilogue encoding is invalid"));
                    decoded.epilogue_size = decoded.code_offset;
                    decoded.epilogue_at_end = (decoded.operation_info & 1U) != 0;
                    seen_epilogue = true;
                } else {
                    decoded.epilogue_offset =
                        (static_cast<std::uint32_t>(decoded.operation_info) << 8U) |
                        decoded.code_offset;
                    decoded.epilogue_padding = decoded.epilogue_offset == 0;
                }
                record.codes.push_back(decoded);
                ++slot;
                continue;
            }
            seen_non_epilogue = true;
            if (decoded.code_offset > record.prolog_size ||
                decoded.code_offset > previous_offset)
                return workspace_result_t<std::uint32_t>::failure(
                    pe_error("unwind code offsets are not in descending order"));
            previous_offset = decoded.code_offset;
            switch (decoded.operation) {
            case pe_unwind_operation_t::allocate_large:
                decoded.slot_count = decoded.operation_info == 0 ? 2 : 3;
                break;
            case pe_unwind_operation_t::save_nonvolatile:
            case pe_unwind_operation_t::save_xmm128:
                decoded.slot_count = 2;
                break;
            case pe_unwind_operation_t::save_nonvolatile_far:
            case pe_unwind_operation_t::save_xmm128_far:
                decoded.slot_count = 3;
                break;
            default:
                decoded.slot_count = 1;
                break;
            }
            if (decoded.operation == pe_unwind_operation_t::allocate_large &&
                decoded.operation_info > 1)
                return workspace_result_t<std::uint32_t>::failure(
                    pe_error("large unwind allocation encoding is invalid"));
            if (decoded.slot_count > code_slots - slot)
                return workspace_result_t<std::uint32_t>::failure(
                    pe_error("unwind operation operands are truncated"));
            const auto nonvolatile_integer = [](std::uint8_t reg) {
                return reg == 3 || reg == 5 || reg == 6 || reg == 7 || reg >= 12;
            };
            if (((decoded.operation == pe_unwind_operation_t::push_nonvolatile ||
                  decoded.operation == pe_unwind_operation_t::save_nonvolatile ||
                  decoded.operation == pe_unwind_operation_t::save_nonvolatile_far) &&
                 !nonvolatile_integer(decoded.operation_info)) ||
                ((decoded.operation == pe_unwind_operation_t::save_xmm128 ||
                  decoded.operation == pe_unwind_operation_t::save_xmm128_far) &&
                 decoded.operation_info < 6) ||
                (decoded.operation == pe_unwind_operation_t::set_frame_pointer &&
                 (decoded.operation_info != 0 || record.frame_register == 0)) ||
                (decoded.operation == pe_unwind_operation_t::push_machine_frame &&
                 decoded.operation_info > 1))
                return workspace_result_t<std::uint32_t>::failure(
                    pe_error("unwind operation information is invalid"));
            if (decoded.slot_count == 2) {
                std::uint16_t value = 0;
                std::memcpy(&value, raw + 2, sizeof(value));
                const std::uint32_t scale =
                    decoded.operation == pe_unwind_operation_t::save_xmm128 ? 16U : 8U;
                decoded.stack_offset = static_cast<std::uint32_t>(value) * scale;
            } else if (decoded.slot_count == 3) {
                std::uint32_t value = 0;
                std::memcpy(&value, raw + 2, sizeof(value));
                decoded.stack_offset = value;
                if (decoded.operation == pe_unwind_operation_t::allocate_large &&
                    (value == 0 || (value & 7U) != 0))
                    return workspace_result_t<std::uint32_t>::failure(
                        pe_error("large unwind allocation is not aligned"));
            } else if (decoded.operation == pe_unwind_operation_t::allocate_small) {
                decoded.stack_offset = static_cast<std::uint32_t>(decoded.operation_info) * 8U + 8U;
            }
            if (decoded.operation == pe_unwind_operation_t::allocate_large &&
                decoded.operation_info == 0 && decoded.stack_offset == 0)
                return workspace_result_t<std::uint32_t>::failure(
                    pe_error("large unwind allocation is zero"));
            record.codes.push_back(decoded);
            slot = static_cast<std::uint8_t>(slot + decoded.slot_count);
        }
        const std::uint64_t aligned_slots = (static_cast<std::uint64_t>(code_slots) + 1ULL) & ~1ULL;
        std::uint64_t tail_rva = 0;
        if (!checked_add_u64(unwind_rva, 4ULL + aligned_slots * 2ULL, tail_rva))
            return workspace_result_t<std::uint32_t>::failure(
                pe_error("unwind tail RVA overflowed"));
        if ((record.flags & 0x04U) != 0) {
            auto chained = read_rva<RUNTIME_FUNCTION>(tail_rva);
            if (!chained || chained.value().BeginAddress >= chained.value().EndAddress ||
                chained.value().EndAddress > image_->image_size_ ||
                (chained.value().UnwindData & 3U) != 0 ||
                !image_->section_for_rva(chained.value().BeginAddress,
                    static_cast<std::uint64_t>(chained.value().EndAddress) -
                        chained.value().BeginAddress) ||
                !image_->rva_to_file_offset(chained.value().UnwindData, 1))
                return workspace_result_t<std::uint32_t>::failure(
                    chained ? pe_error("chained unwind function is invalid") : chained.error());
            pe_runtime_function_t function{chained.value().BeginAddress,
                chained.value().EndAddress, chained.value().UnwindData, 0};
            auto chained_index = parse_unwind_record(function.unwind_rva, depth + 1);
            if (!chained_index)
                return workspace_result_t<std::uint32_t>::failure(chained_index.error());
            function.unwind_record_index = chained_index.value();
            const auto& primary = image_->unwind_records_[function.unwind_record_index];
            if (primary.frame_register != record.frame_register ||
                primary.frame_offset != record.frame_offset)
                return workspace_result_t<std::uint32_t>::failure(
                    pe_error("chained unwind frame state does not match its primary record"));
            record.chained_function = function;
        } else if ((record.flags & 0x03U) != 0) {
            auto handler = read_rva<std::uint32_t>(tail_rva);
            if (!handler)
                return workspace_result_t<std::uint32_t>::failure(handler.error());
            const auto* section = image_->section_for_rva(handler.value(), 1);
            if (!section || !section->executable ||
                !image_->rva_to_file_offset(handler.value(), 1))
                return workspace_result_t<std::uint32_t>::failure(
                    pe_error("unwind language handler is not executable"));
            record.exception_handler_rva = handler.value();
            auto entry_result = add_entry_point(handler.value(), "unwind_handler");
            if (!entry_result)
                return workspace_result_t<std::uint32_t>::failure(entry_result.error());
            std::uint64_t language_rva = 0;
            if (!checked_add_u64(tail_rva, sizeof(std::uint32_t), language_rva) ||
                language_rva >= image_->image_size_)
                return workspace_result_t<std::uint32_t>::failure(
                    pe_error("unwind language data RVA is invalid"));
            record.language_data_rva = static_cast<std::uint32_t>(language_rva);
            auto language = try_parse_language_scopes(record);
            if (!language)
                return workspace_result_t<std::uint32_t>::failure(language.error());
        }
        auto budget = consume_metadata_bytes(sizeof(pe_unwind_record_t) +
            record.codes.size() * sizeof(pe_unwind_code_t));
        if (!budget)
            return workspace_result_t<std::uint32_t>::failure(budget.error());
        const auto index = static_cast<std::uint32_t>(image_->unwind_records_.size());
        image_->unwind_records_.push_back(std::move(record));
        unwind_index_by_rva_.emplace(unwind_rva, index);
        return workspace_result_t<std::uint32_t>::success(index);
    }

    workspace_result_t<void> parse_exception_directory() {
        const auto* data = directory(IMAGE_DIRECTORY_ENTRY_EXCEPTION);
        if (!data || image_->architecture_ != architecture_id_t::x86_64)
            return workspace_result_t<void>::success();
        if (data->size % sizeof(RUNTIME_FUNCTION) != 0)
            return workspace_result_t<void>::failure(pe_error("exception directory size is invalid"));
        const std::uint64_t count = data->size / sizeof(RUNTIME_FUNCTION);
        if (count > limits_.max_runtime_functions)
            return workspace_result_t<void>::failure(
                limit_error("runtime-function count exceeds its limit", count,
                            limits_.max_runtime_functions));
        image_->runtime_functions_.reserve(static_cast<std::size_t>(count));
        for (std::uint64_t index = 0; index < count; ++index) {
            if ((index % 4096) == 0 && cancel_.stop_requested())
                return workspace_result_t<void>::failure(stop_error(cancel_));
            auto result = read_rva<RUNTIME_FUNCTION>(data->rva + index * sizeof(RUNTIME_FUNCTION));
            if (!result)
                return workspace_result_t<void>::failure(result.error());
            const auto record = result.value();
            const auto* code_section = image_->section_for_rva(
                record.BeginAddress,
                record.EndAddress > record.BeginAddress
                    ? record.EndAddress - record.BeginAddress : 0);
            if (record.BeginAddress >= record.EndAddress || record.EndAddress > image_->image_size_ ||
                !code_section || !code_section->executable ||
                !image_->section_for_rva(record.UnwindData, 1) ||
                !image_->rva_to_file_offset(record.BeginAddress,
                                            record.EndAddress - record.BeginAddress) ||
                !image_->rva_to_file_offset(record.UnwindData, 1))
                return workspace_result_t<void>::failure(pe_error("runtime-function record is invalid"));
            auto runtime_budget = consume_metadata_bytes(sizeof(pe_runtime_function_t));
            if (!runtime_budget)
                return runtime_budget;
            auto unwind = parse_unwind_record(record.UnwindData, 0);
            if (!unwind)
                return workspace_result_t<void>::failure(unwind.error());
            image_->runtime_functions_.push_back(
                {record.BeginAddress, record.EndAddress, record.UnwindData, unwind.value()});
            auto entry_result = add_entry_point(record.BeginAddress, "unwind");
            if (!entry_result)
                return entry_result;
        }
        std::sort(image_->runtime_functions_.begin(), image_->runtime_functions_.end(),
                  [](const auto& lhs, const auto& rhs) {
                      return std::tie(lhs.begin_rva, lhs.end_rva, lhs.unwind_rva) <
                             std::tie(rhs.begin_rva, rhs.end_rva, rhs.unwind_rva);
                  });
        for (std::size_t index = 1; index < image_->runtime_functions_.size(); ++index) {
            if (image_->runtime_functions_[index - 1].end_rva >
                image_->runtime_functions_[index].begin_rva)
                return workspace_result_t<void>::failure(
                    pe_error("runtime-function ranges overlap"));
        }
        return workspace_result_t<void>::success();
    }

    template <typename T>
    static std::optional<T> read_field(const std::vector<std::uint8_t>& bytes,
                                       std::size_t offset) {
        if (offset > bytes.size() || sizeof(T) > bytes.size() - offset)
            return std::nullopt;
        T value{};
        std::memcpy(&value, bytes.data() + offset, sizeof(value));
        return value;
    }

    workspace_result_t<void> parse_guard_table(
        std::uint64_t table_va, std::uint64_t count, std::uint32_t metadata_size,
        std::uint64_t target_size, bool require_executable,
        bool require_zero_metadata, bool promote_entries, const char* label,
        std::optional<std::uint32_t>& table_rva_out,
        std::vector<pe_guard_function_entry_t>& entries) {
        if ((table_va == 0) != (count == 0))
            return workspace_result_t<void>::failure(
                pe_error(std::string(label) + " pointer and count are inconsistent"));
        if (count == 0)
            return workspace_result_t<void>::success();
        if (count > limits_.max_load_config_entries)
            return workspace_result_t<void>::failure(
                limit_error(std::string(label) + " entry count exceeds its limit",
                            count, limits_.max_load_config_entries));
        if (metadata_size > pe_guard_function_entry_t{}.metadata.size())
            return workspace_result_t<void>::failure(
                pe_error(std::string(label) + " metadata size is invalid"));
        auto table_rva = va_field_to_rva(table_va, label);
        if (!table_rva)
            return workspace_result_t<void>::failure(table_rva.error());
        const std::uint64_t stride = sizeof(std::uint32_t) + metadata_size;
        std::uint64_t table_bytes = 0;
        std::uint64_t stored_bytes = 0;
        if (!checked_mul_u64(count, stride, table_bytes) ||
            !checked_mul_u64(count, sizeof(pe_guard_function_entry_t), stored_bytes))
            return workspace_result_t<void>::failure(
                pe_error(std::string(label) + " size overflowed"));
        auto table_offset = image_->rva_to_file_offset(table_rva.value(), table_bytes);
        if (!table_offset)
            return workspace_result_t<void>::failure(
                pe_error(std::string(label) + " is not fully file-backed"));
        auto budget = consume_metadata_bytes(stored_bytes);
        if (!budget)
            return budget;
        table_rva_out = table_rva.value();
        entries.reserve(static_cast<std::size_t>(count));
        for (std::uint64_t index = 0; index < count; ++index) {
            if (cancel_.stop_requested())
                return workspace_result_t<void>::failure(stop_error(cancel_));
            std::uint64_t delta = 0;
            std::uint64_t entry_offset = 0;
            if (!checked_mul_u64(index, stride, delta) ||
                !checked_add_u64(table_offset.value(), delta, entry_offset))
                return workspace_result_t<void>::failure(
                    pe_error(std::string(label) + " entry offset overflowed"));
            auto bytes = cached_data(entry_offset, stride);
            if (!bytes)
                return workspace_result_t<void>::failure(bytes.error());
            pe_guard_function_entry_t entry;
            std::memcpy(&entry.rva, bytes.value(), sizeof(entry.rva));
            entry.metadata_size = static_cast<std::uint8_t>(metadata_size);
            if (metadata_size != 0) {
                std::memcpy(entry.metadata.data(), bytes.value() + sizeof(entry.rva),
                            metadata_size);
                if (require_zero_metadata &&
                    std::any_of(entry.metadata.begin(),
                                entry.metadata.begin() + metadata_size,
                                [](std::uint8_t value) { return value != 0; }))
                    return workspace_result_t<void>::failure(
                        pe_error(std::string(label) + " contains nonzero reserved metadata"));
            }
            const auto* section = image_->section_for_rva(entry.rva, target_size);
            auto mapped = image_->rva_to_file_offset(entry.rva, target_size);
            if (!section || !mapped || (require_executable && !section->executable))
                return workspace_result_t<void>::failure(
                    pe_error(std::string(label) + " contains an invalid target"));
            entries.push_back(entry);
            if (promote_entries &&
                !entry.has_flag(pe_guard_function_flag_t::fid_suppressed)) {
                auto promoted = add_entry_point(entry.rva, "cfg_guard");
                if (!promoted)
                    return promoted;
            }
        }
        if (!std::is_sorted(entries.begin(), entries.end(),
                            [](const auto& lhs, const auto& rhs) {
                                return lhs.rva < rhs.rva;
                            }) ||
            std::adjacent_find(entries.begin(), entries.end(),
                               [](const auto& lhs, const auto& rhs) {
                                   return lhs.rva == rhs.rva;
                               }) != entries.end())
            return workspace_result_t<void>::failure(
                pe_error(std::string(label) + " is not strictly ordered"));
        return workspace_result_t<void>::success();
    }

    workspace_result_t<void> parse_dynamic_relocations(
        std::uint64_t table_va, pe_load_config_t& config) {
        std::optional<std::uint32_t> pointer_rva;
        if (table_va != 0) {
            auto converted = va_field_to_rva(table_va, "dynamic relocation table");
            if (!converted)
                return workspace_result_t<void>::failure(converted.error());
            pointer_rva = converted.value();
        }
        std::optional<std::uint32_t> section_rva;
        if (config.dynamic_value_reloc_table_section == 0) {
            if (config.dynamic_value_reloc_table_offset != 0)
                return workspace_result_t<void>::failure(
                    pe_error("dynamic relocation section offset has no section"));
        } else {
            if (config.dynamic_value_reloc_table_section > image_->sections_.size())
                return workspace_result_t<void>::failure(
                    pe_error("dynamic relocation section index is invalid"));
            const auto& section =
                image_->sections_[config.dynamic_value_reloc_table_section - 1];
            if (config.dynamic_value_reloc_table_offset > section.raw_size ||
                sizeof(IMAGE_DYNAMIC_RELOCATION_TABLE) >
                    section.raw_size - config.dynamic_value_reloc_table_offset)
                return workspace_result_t<void>::failure(
                    pe_error("dynamic relocation section offset is out of range"));
            std::uint64_t value = 0;
            if (!checked_add_u64(section.virtual_address,
                                 config.dynamic_value_reloc_table_offset, value) ||
                value > std::numeric_limits<std::uint32_t>::max())
                return workspace_result_t<void>::failure(
                    pe_error("dynamic relocation table RVA overflowed"));
            section_rva = static_cast<std::uint32_t>(value);
        }
        if (pointer_rva && section_rva && *pointer_rva != *section_rva)
            return workspace_result_t<void>::failure(
                pe_error("dynamic relocation table locations disagree"));
        const auto table_rva = pointer_rva ? pointer_rva : section_rva;
        if (!table_rva)
            return workspace_result_t<void>::success();
        auto header = read_rva<IMAGE_DYNAMIC_RELOCATION_TABLE>(*table_rva);
        if (!header)
            return workspace_result_t<void>::failure(header.error());
        if (header.value().Version != 1 && header.value().Version != 2)
            return workspace_result_t<void>::failure(
                pe_error("dynamic relocation table version is unsupported"));
        if (header.value().Size > limits_.max_dynamic_relocation_bytes)
            return workspace_result_t<void>::failure(
                limit_error("dynamic relocation table exceeds its byte limit",
                            header.value().Size,
                            limits_.max_dynamic_relocation_bytes));
        std::uint64_t table_size = 0;
        if (!checked_add_u64(sizeof(IMAGE_DYNAMIC_RELOCATION_TABLE),
                             header.value().Size, table_size) ||
            !image_->rva_to_file_offset(*table_rva, table_size))
            return workspace_result_t<void>::failure(
                pe_error("dynamic relocation table is not fully file-backed"));
        pe_dynamic_relocation_table_t table;
        table.table_rva = *table_rva;
        table.version = header.value().Version;
        table.payload_size = header.value().Size;
        std::uint64_t cursor = 0;
        std::uint64_t end = 0;
        if (!checked_add_u64(*table_rva, sizeof(IMAGE_DYNAMIC_RELOCATION_TABLE), cursor) ||
            !checked_add_u64(cursor, header.value().Size, end))
            return workspace_result_t<void>::failure(
                pe_error("dynamic relocation table range overflowed"));
        const bool image64 = image_->format_ == format_id_t::pe32_plus;
        while (cursor < end) {
            if (cancel_.stop_requested())
                return workspace_result_t<void>::failure(stop_error(cancel_));
            if (table.records.size() >= limits_.max_dynamic_relocation_records)
                return workspace_result_t<void>::failure(
                    limit_error("dynamic relocation record count exceeds its limit",
                                table.records.size() + 1,
                                limits_.max_dynamic_relocation_records));
            const std::uint64_t remaining = end - cursor;
            pe_dynamic_relocation_record_t record;
            record.record_rva = static_cast<std::uint32_t>(cursor);
            if (table.version == 1) {
                const std::uint32_t header_size = image64 ? 12U : 8U;
                if (remaining < header_size)
                    return workspace_result_t<void>::failure(
                        pe_error("dynamic relocation record header is truncated"));
                auto offset = image_->rva_to_file_offset(cursor, header_size);
                if (!offset)
                    return workspace_result_t<void>::failure(offset.error());
                auto bytes = cached_data(offset.value(), header_size);
                if (!bytes)
                    return workspace_result_t<void>::failure(bytes.error());
                if (image64) {
                    std::memcpy(&record.symbol, bytes.value(), sizeof(std::uint64_t));
                    std::memcpy(&record.fixup_info_size,
                                bytes.value() + sizeof(std::uint64_t),
                                sizeof(std::uint32_t));
                } else {
                    std::uint32_t symbol = 0;
                    std::memcpy(&symbol, bytes.value(), sizeof(symbol));
                    record.symbol = symbol;
                    std::memcpy(&record.fixup_info_size,
                                bytes.value() + sizeof(std::uint32_t),
                                sizeof(std::uint32_t));
                }
                record.header_size = header_size;
            } else {
                const std::uint32_t minimum_header = image64 ? 24U : 20U;
                if (remaining < minimum_header)
                    return workspace_result_t<void>::failure(
                        pe_error("dynamic relocation v2 header is truncated"));
                auto offset = image_->rva_to_file_offset(cursor, minimum_header);
                if (!offset)
                    return workspace_result_t<void>::failure(offset.error());
                auto bytes = cached_data(offset.value(), minimum_header);
                if (!bytes)
                    return workspace_result_t<void>::failure(bytes.error());
                std::memcpy(&record.header_size, bytes.value(), sizeof(std::uint32_t));
                std::memcpy(&record.fixup_info_size,
                            bytes.value() + sizeof(std::uint32_t),
                            sizeof(std::uint32_t));
                if (record.header_size < minimum_header ||
                    record.header_size > remaining)
                    return workspace_result_t<void>::failure(
                        pe_error("dynamic relocation v2 header size is invalid"));
                std::size_t field_offset = 2 * sizeof(std::uint32_t);
                if (image64) {
                    std::memcpy(&record.symbol, bytes.value() + field_offset,
                                sizeof(std::uint64_t));
                    field_offset += sizeof(std::uint64_t);
                } else {
                    std::uint32_t symbol = 0;
                    std::memcpy(&symbol, bytes.value() + field_offset,
                                sizeof(std::uint32_t));
                    record.symbol = symbol;
                    field_offset += sizeof(std::uint32_t);
                }
                std::memcpy(&record.symbol_group, bytes.value() + field_offset,
                            sizeof(std::uint32_t));
                std::memcpy(&record.flags,
                            bytes.value() + field_offset + sizeof(std::uint32_t),
                            sizeof(std::uint32_t));
            }
            std::uint64_t record_size = 0;
            if (!checked_add_u64(record.header_size, record.fixup_info_size,
                                 record_size) || record_size > remaining)
                return workspace_result_t<void>::failure(
                    pe_error("dynamic relocation fixup range is invalid"));
            std::uint64_t fixup_rva = 0;
            if (!checked_add_u64(cursor, record.header_size, fixup_rva) ||
                fixup_rva > std::numeric_limits<std::uint32_t>::max())
                return workspace_result_t<void>::failure(
                    pe_error("dynamic relocation fixup RVA overflowed"));
            record.fixup_info_rva = static_cast<std::uint32_t>(fixup_rva);
            if (record.symbol <=
                static_cast<std::uint64_t>(pe_dynamic_relocation_kind_t::arm64_kernel_import_call_transfer))
                record.kind = static_cast<pe_dynamic_relocation_kind_t>(record.symbol);
            auto budget = consume_metadata_bytes(sizeof(record));
            if (!budget)
                return budget;
            table.records.push_back(record);
            cursor += record_size;
        }
        if (cursor != end)
            return workspace_result_t<void>::failure(
                pe_error("dynamic relocation records do not consume their table"));
        config.dynamic_value_reloc_table_rva = *table_rva;
        config.dynamic_relocations = std::move(table);
        return workspace_result_t<void>::success();
    }

    workspace_result_t<void> parse_load_config() {
        const auto* data = directory(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG);
        if (!data)
            return workspace_result_t<void>::success();
        if (data->size < sizeof(std::uint32_t) || data->size > 65536)
            return workspace_result_t<void>::failure(pe_error("load-config directory size is invalid"));
        auto offset_result = image_->rva_to_file_offset(data->rva, data->size);
        if (!offset_result)
            return workspace_result_t<void>::failure(offset_result.error());
        auto bytes_result = provider_.read_vector(offset_result.value(), data->size, 65536, cancel_);
        if (!bytes_result)
            return workspace_result_t<void>::failure(bytes_result.error());
        const auto& bytes = bytes_result.value();
        const auto declared_size = read_field<std::uint32_t>(bytes, 0);
        if (!declared_size || *declared_size < sizeof(std::uint32_t) || *declared_size > data->size)
            return workspace_result_t<void>::failure(pe_error("load-config declared size is invalid"));
        const std::vector<std::uint8_t> declared_bytes(bytes.begin(),
                                                       bytes.begin() + *declared_size);
        pe_load_config_t config;
        config.declared_size = *declared_size;
        auto normalize_optional_va = [&](std::uint64_t value, const char* field,
                                         std::optional<std::uint32_t>& destination)
            -> workspace_result_t<void> {
            if (value == 0)
                return workspace_result_t<void>::success();
            auto result = va_field_to_rva(value, field);
            if (!result)
                return workspace_result_t<void>::failure(result.error());
            destination = result.value();
            return workspace_result_t<void>::success();
        };
        std::uint64_t seh_table_va = 0;
        std::uint64_t guard_table_va = 0;
        std::uint64_t address_taken_iat_table_va = 0;
        std::uint64_t address_taken_iat_count = 0;
        std::uint64_t long_jump_table_va = 0;
        std::uint64_t long_jump_count = 0;
        std::uint64_t eh_continuation_table_va = 0;
        std::uint64_t eh_continuation_count = 0;
        std::uint64_t dynamic_reloc_table_va = 0;
        if (image_->format_ == format_id_t::pe32_plus) {
            const auto cookie = read_field<std::uint64_t>(declared_bytes, offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64, SecurityCookie));
            const auto seh_table = read_field<std::uint64_t>(declared_bytes, offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64, SEHandlerTable));
            const auto seh_count = read_field<std::uint64_t>(declared_bytes, offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64, SEHandlerCount));
            const auto guard_check = read_field<std::uint64_t>(declared_bytes, offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64, GuardCFCheckFunctionPointer));
            const auto guard_dispatch = read_field<std::uint64_t>(declared_bytes, offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64, GuardCFDispatchFunctionPointer));
            const auto guard_table = read_field<std::uint64_t>(declared_bytes, offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64, GuardCFFunctionTable));
            const auto guard_count = read_field<std::uint64_t>(declared_bytes, offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64, GuardCFFunctionCount));
            const auto guard_flags = read_field<std::uint32_t>(declared_bytes, offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64, GuardFlags));
            const auto address_iat_table = read_field<std::uint64_t>(declared_bytes, offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64, GuardAddressTakenIatEntryTable));
            const auto address_iat_count = read_field<std::uint64_t>(declared_bytes, offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64, GuardAddressTakenIatEntryCount));
            const auto long_jump_table = read_field<std::uint64_t>(declared_bytes, offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64, GuardLongJumpTargetTable));
            const auto long_jump_entries = read_field<std::uint64_t>(declared_bytes, offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64, GuardLongJumpTargetCount));
            const auto dynamic_reloc_table = read_field<std::uint64_t>(declared_bytes, offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64, DynamicValueRelocTable));
            const auto dynamic_reloc_offset = read_field<std::uint32_t>(declared_bytes, offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64, DynamicValueRelocTableOffset));
            const auto dynamic_reloc_section = read_field<std::uint16_t>(declared_bytes, offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64, DynamicValueRelocTableSection));
            const auto eh_table = read_field<std::uint64_t>(declared_bytes, offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64, GuardEHContinuationTable));
            const auto eh_count = read_field<std::uint64_t>(declared_bytes, offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64, GuardEHContinuationCount));
            if (cookie) {
                auto result = normalize_optional_va(*cookie, "security cookie", config.security_cookie_rva);
                if (!result) return result;
            }
            if (seh_table) seh_table_va = *seh_table;
            if (seh_count) config.seh_handler_count = *seh_count;
            if (guard_check) {
                auto result = normalize_optional_va(*guard_check, "CFG check", config.guard_check_rva);
                if (!result) return result;
            }
            if (guard_dispatch) {
                auto result = normalize_optional_va(*guard_dispatch, "CFG dispatch", config.guard_dispatch_rva);
                if (!result) return result;
            }
            if (guard_table) guard_table_va = *guard_table;
            if (guard_count) config.guard_function_count = *guard_count;
            if (guard_flags) config.guard_flags = *guard_flags;
            if (address_iat_table) address_taken_iat_table_va = *address_iat_table;
            if (address_iat_count) address_taken_iat_count = *address_iat_count;
            if (long_jump_table) long_jump_table_va = *long_jump_table;
            if (long_jump_entries) long_jump_count = *long_jump_entries;
            if (dynamic_reloc_table) dynamic_reloc_table_va = *dynamic_reloc_table;
            if (dynamic_reloc_offset) config.dynamic_value_reloc_table_offset = *dynamic_reloc_offset;
            if (dynamic_reloc_section) config.dynamic_value_reloc_table_section = *dynamic_reloc_section;
            if (eh_table) eh_continuation_table_va = *eh_table;
            if (eh_count) eh_continuation_count = *eh_count;
        } else {
            const auto cookie = read_field<std::uint32_t>(declared_bytes, offsetof(IMAGE_LOAD_CONFIG_DIRECTORY32, SecurityCookie));
            const auto seh_table = read_field<std::uint32_t>(declared_bytes, offsetof(IMAGE_LOAD_CONFIG_DIRECTORY32, SEHandlerTable));
            const auto seh_count = read_field<std::uint32_t>(declared_bytes, offsetof(IMAGE_LOAD_CONFIG_DIRECTORY32, SEHandlerCount));
            const auto guard_check = read_field<std::uint32_t>(declared_bytes, offsetof(IMAGE_LOAD_CONFIG_DIRECTORY32, GuardCFCheckFunctionPointer));
            const auto guard_dispatch = read_field<std::uint32_t>(declared_bytes, offsetof(IMAGE_LOAD_CONFIG_DIRECTORY32, GuardCFDispatchFunctionPointer));
            const auto guard_table = read_field<std::uint32_t>(declared_bytes, offsetof(IMAGE_LOAD_CONFIG_DIRECTORY32, GuardCFFunctionTable));
            const auto guard_count = read_field<std::uint32_t>(declared_bytes, offsetof(IMAGE_LOAD_CONFIG_DIRECTORY32, GuardCFFunctionCount));
            const auto guard_flags = read_field<std::uint32_t>(declared_bytes, offsetof(IMAGE_LOAD_CONFIG_DIRECTORY32, GuardFlags));
            const auto address_iat_table = read_field<std::uint32_t>(declared_bytes, offsetof(IMAGE_LOAD_CONFIG_DIRECTORY32, GuardAddressTakenIatEntryTable));
            const auto address_iat_count = read_field<std::uint32_t>(declared_bytes, offsetof(IMAGE_LOAD_CONFIG_DIRECTORY32, GuardAddressTakenIatEntryCount));
            const auto long_jump_table = read_field<std::uint32_t>(declared_bytes, offsetof(IMAGE_LOAD_CONFIG_DIRECTORY32, GuardLongJumpTargetTable));
            const auto long_jump_entries = read_field<std::uint32_t>(declared_bytes, offsetof(IMAGE_LOAD_CONFIG_DIRECTORY32, GuardLongJumpTargetCount));
            const auto dynamic_reloc_table = read_field<std::uint32_t>(declared_bytes, offsetof(IMAGE_LOAD_CONFIG_DIRECTORY32, DynamicValueRelocTable));
            const auto dynamic_reloc_offset = read_field<std::uint32_t>(declared_bytes, offsetof(IMAGE_LOAD_CONFIG_DIRECTORY32, DynamicValueRelocTableOffset));
            const auto dynamic_reloc_section = read_field<std::uint16_t>(declared_bytes, offsetof(IMAGE_LOAD_CONFIG_DIRECTORY32, DynamicValueRelocTableSection));
            const auto eh_table = read_field<std::uint32_t>(declared_bytes, offsetof(IMAGE_LOAD_CONFIG_DIRECTORY32, GuardEHContinuationTable));
            const auto eh_count = read_field<std::uint32_t>(declared_bytes, offsetof(IMAGE_LOAD_CONFIG_DIRECTORY32, GuardEHContinuationCount));
            if (cookie) {
                auto result = normalize_optional_va(*cookie, "security cookie", config.security_cookie_rva);
                if (!result) return result;
            }
            if (seh_table) seh_table_va = *seh_table;
            if (seh_count) config.seh_handler_count = *seh_count;
            if (guard_check) {
                auto result = normalize_optional_va(*guard_check, "CFG check", config.guard_check_rva);
                if (!result) return result;
            }
            if (guard_dispatch) {
                auto result = normalize_optional_va(*guard_dispatch, "CFG dispatch", config.guard_dispatch_rva);
                if (!result) return result;
            }
            if (guard_table) guard_table_va = *guard_table;
            if (guard_count) config.guard_function_count = *guard_count;
            if (guard_flags) config.guard_flags = *guard_flags;
            if (address_iat_table) address_taken_iat_table_va = *address_iat_table;
            if (address_iat_count) address_taken_iat_count = *address_iat_count;
            if (long_jump_table) long_jump_table_va = *long_jump_table;
            if (long_jump_entries) long_jump_count = *long_jump_entries;
            if (dynamic_reloc_table) dynamic_reloc_table_va = *dynamic_reloc_table;
            if (dynamic_reloc_offset) config.dynamic_value_reloc_table_offset = *dynamic_reloc_offset;
            if (dynamic_reloc_section) config.dynamic_value_reloc_table_section = *dynamic_reloc_section;
            if (eh_table) eh_continuation_table_va = *eh_table;
            if (eh_count) eh_continuation_count = *eh_count;
        }
        config.guard_address_taken_iat_count = address_taken_iat_count;
        config.guard_long_jump_target_count = long_jump_count;
        config.guard_eh_continuation_count = eh_continuation_count;
        if (config.seh_handler_count > limits_.max_load_config_entries ||
            config.guard_function_count > limits_.max_load_config_entries ||
            address_taken_iat_count > limits_.max_load_config_entries ||
            long_jump_count > limits_.max_load_config_entries ||
            eh_continuation_count > limits_.max_load_config_entries)
            return workspace_result_t<void>::failure(
                limit_error("load-config function table exceeds its limit",
                            std::max({config.seh_handler_count, config.guard_function_count,
                                      address_taken_iat_count, long_jump_count,
                                      eh_continuation_count}),
                            limits_.max_load_config_entries));
        if ((seh_table_va == 0) != (config.seh_handler_count == 0) ||
            (guard_table_va == 0) != (config.guard_function_count == 0))
            return workspace_result_t<void>::failure(
                pe_error("load-config table pointer and count are inconsistent"));
        if (seh_table_va != 0 && config.seh_handler_count != 0) {
            auto table_rva = va_field_to_rva(seh_table_va, "SafeSEH table");
            if (!table_rva)
                return workspace_result_t<void>::failure(table_rva.error());
            config.seh_table_rva = table_rva.value();
            std::uint64_t table_size = 0;
            if (!checked_mul_u64(config.seh_handler_count, sizeof(std::uint32_t), table_size) ||
                !image_->rva_to_file_offset(table_rva.value(), table_size))
                return workspace_result_t<void>::failure(
                    pe_error("SafeSEH table is not fully file-backed"));
            config.seh_handler_rvas.reserve(static_cast<std::size_t>(config.seh_handler_count));
            for (std::uint64_t index = 0; index < config.seh_handler_count; ++index) {
                if ((index % 4096) == 0 && cancel_.stop_requested())
                    return workspace_result_t<void>::failure(stop_error(cancel_));
                auto entry = read_rva<std::uint32_t>(table_rva.value() + index * sizeof(std::uint32_t));
                if (!entry)
                    return workspace_result_t<void>::failure(entry.error());
                const auto* handler_section = image_->section_for_rva(entry.value(), 1);
                if (!handler_section || !handler_section->executable)
                    return workspace_result_t<void>::failure(pe_error("SafeSEH handler RVA is not mapped"));
                auto mapped_handler = image_->rva_to_file_offset(entry.value(), 1);
                if (!mapped_handler)
                    return workspace_result_t<void>::failure(mapped_handler.error());
                auto handler_budget = consume_metadata_bytes(sizeof(std::uint32_t));
                if (!handler_budget)
                    return handler_budget;
                config.seh_handler_rvas.push_back(entry.value());
                auto entry_result = add_entry_point(entry.value(), "safe_seh");
                if (!entry_result)
                    return entry_result;
            }
            if (!std::is_sorted(config.seh_handler_rvas.begin(),
                                config.seh_handler_rvas.end()) ||
                std::adjacent_find(config.seh_handler_rvas.begin(),
                                   config.seh_handler_rvas.end()) !=
                    config.seh_handler_rvas.end())
                return workspace_result_t<void>::failure(
                    pe_error("SafeSEH table is not strictly ordered"));
        }
        const std::uint32_t metadata_size =
            (config.guard_flags & IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK) >>
            IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT;
        auto modern = parse_guard_table(guard_table_va,
            config.guard_function_count, metadata_size, 1, true, false, true,
            "CFG function table", config.guard_function_table_rva,
            config.guard_function_entries);
        const std::uint64_t pointer_size =
            image_->format_ == format_id_t::pe32_plus ? 8ULL : 4ULL;
        if (modern)
            modern = parse_guard_table(address_taken_iat_table_va,
                address_taken_iat_count, metadata_size, pointer_size, false,
                false, false, "address-taken IAT table",
                config.guard_address_taken_iat_table_rva,
                config.guard_address_taken_iat_entries);
        if (modern)
            modern = parse_guard_table(long_jump_table_va, long_jump_count,
                metadata_size, 1, true, true, false, "long-jump target table",
                config.guard_long_jump_table_rva,
                config.guard_long_jump_targets);
        if (modern)
            modern = parse_guard_table(eh_continuation_table_va,
                eh_continuation_count, metadata_size, 1, true, false, false,
                "EH continuation table",
                config.guard_eh_continuation_table_rva,
                config.guard_eh_continuation_targets);
        if (!modern)
            return modern;
        auto dynamic = parse_dynamic_relocations(dynamic_reloc_table_va, config);
        if (!dynamic)
            return dynamic;
        image_->load_config_ = std::move(config);
        return workspace_result_t<void>::success();
    }

    workspace_result_t<void> parse_debug_directory() {
        const auto* data = directory(IMAGE_DIRECTORY_ENTRY_DEBUG);
        if (!data)
            return workspace_result_t<void>::success();
        if (data->size % sizeof(IMAGE_DEBUG_DIRECTORY) != 0)
            return workspace_result_t<void>::failure(pe_error("debug directory size is invalid"));
        const std::uint64_t count = data->size / sizeof(IMAGE_DEBUG_DIRECTORY);
        if (count > 65536)
            return workspace_result_t<void>::failure(limit_error("debug record count exceeds its limit", count, 65536));
        for (std::uint64_t index = 0; index < count; ++index) {
            auto entry_result = read_rva<IMAGE_DEBUG_DIRECTORY>(
                data->rva + index * sizeof(IMAGE_DEBUG_DIRECTORY));
            if (!entry_result)
                return workspace_result_t<void>::failure(entry_result.error());
            const auto entry = entry_result.value();
            if (entry.Type != IMAGE_DEBUG_TYPE_CODEVIEW)
                continue;
            if (entry.SizeOfData < 4)
                return workspace_result_t<void>::failure(pe_error("CodeView record is truncated"));
            if (entry.SizeOfData > limits_.max_string_bytes + 32U)
                return workspace_result_t<void>::failure(
                    limit_error("CodeView record exceeds its limit", entry.SizeOfData,
                                limits_.max_string_bytes + 32U));
            std::uint64_t codeview_offset = entry.PointerToRawData;
            if (codeview_offset == 0 && entry.AddressOfRawData == 0)
                return workspace_result_t<void>::failure(
                    pe_error("CodeView record has no data location"));
            if (entry.AddressOfRawData != 0) {
                auto mapped = image_->rva_to_file_offset(entry.AddressOfRawData, entry.SizeOfData);
                if (!mapped)
                    return workspace_result_t<void>::failure(mapped.error());
                if (codeview_offset != 0 && codeview_offset != mapped.value())
                    return workspace_result_t<void>::failure(
                        pe_error("CodeView file and RVA locations disagree"));
                codeview_offset = mapped.value();
            }
            auto span = validate_span(codeview_offset, entry.SizeOfData, provider_.size(), "pe_parse");
            if (!span)
                return workspace_result_t<void>::failure(pe_error("CodeView data is outside the file"));
            auto bytes_result = provider_.read_vector(codeview_offset, entry.SizeOfData,
                                                      limits_.max_string_bytes + 32ULL, cancel_);
            if (!bytes_result)
                return workspace_result_t<void>::failure(bytes_result.error());
            const auto& bytes = bytes_result.value();
            pe_codeview_t codeview;
            codeview.timestamp = entry.TimeDateStamp;
            std::size_t path_offset = 0;
            if (bytes.size() >= 24 && std::memcmp(bytes.data(), "RSDS", 4) == 0) {
                std::memcpy(codeview.guid.data(), bytes.data() + 4, codeview.guid.size());
                std::memcpy(&codeview.age, bytes.data() + 20, sizeof(codeview.age));
                path_offset = 24;
            } else if (bytes.size() >= 16 && std::memcmp(bytes.data(), "NB10", 4) == 0) {
                std::memcpy(&codeview.timestamp, bytes.data() + 8, sizeof(codeview.timestamp));
                std::memcpy(&codeview.age, bytes.data() + 12, sizeof(codeview.age));
                path_offset = 16;
            } else {
                continue;
            }
            const auto terminator = std::find(bytes.begin() + static_cast<std::ptrdiff_t>(path_offset),
                                              bytes.end(), static_cast<std::uint8_t>(0));
            if (terminator == bytes.end())
                return workspace_result_t<void>::failure(pe_error("CodeView path is not terminated"));
            codeview.pdb_path.assign(
                reinterpret_cast<const char*>(bytes.data() + path_offset),
                static_cast<std::size_t>(terminator - bytes.begin()) - path_offset);
            if (!valid_utf8_text(codeview.pdb_path))
                return workspace_result_t<void>::failure(
                    pe_error("CodeView path is not valid printable UTF-8"));
            auto codeview_budget = consume_metadata_bytes(sizeof(pe_codeview_t) +
                                                          codeview.pdb_path.size());
            if (!codeview_budget)
                return codeview_budget;
            image_->codeview_records_.push_back(std::move(codeview));
        }
        return workspace_result_t<void>::success();
    }

    workspace_result_t<std::string> resource_name(std::uint32_t base_rva,
                                                  std::uint32_t value) {
        if ((value & 0x80000000U) == 0) {
            auto text = std::to_string(value & 0xffffU);
            auto budget = consume_metadata_bytes(text.size());
            if (!budget)
                return workspace_result_t<std::string>::failure(budget.error());
            return workspace_result_t<std::string>::success(std::move(text));
        }
        const std::uint32_t relative = value & 0x7fffffffU;
        auto name_header_span = validate_span(relative, sizeof(std::uint16_t),
                                              resource_directory_size_, "pe_parse");
        if (!name_header_span)
            return workspace_result_t<std::string>::failure(
                pe_error("resource name offset exceeds the resource directory"));
        const std::uint64_t string_rva = static_cast<std::uint64_t>(base_rva) + relative;
        auto length_result = read_rva<std::uint16_t>(string_rva);
        if (!length_result)
            return workspace_result_t<std::string>::failure(length_result.error());
        const std::uint64_t byte_count = static_cast<std::uint64_t>(length_result.value()) * 2;
        if (byte_count > limits_.max_string_bytes)
            return workspace_result_t<std::string>::failure(
                limit_error("resource name exceeds its limit", byte_count, limits_.max_string_bytes));
        auto name_span = validate_span(static_cast<std::uint64_t>(relative) + sizeof(std::uint16_t),
                                       byte_count, resource_directory_size_, "pe_parse");
        if (!name_span)
            return workspace_result_t<std::string>::failure(
                pe_error("resource name exceeds the resource directory"));
        auto offset_result = image_->rva_to_file_offset(string_rva + 2, byte_count);
        if (!offset_result)
            return workspace_result_t<std::string>::failure(offset_result.error());
        auto bytes_result = provider_.read_vector(offset_result.value(), byte_count,
                                                  limits_.max_string_bytes, cancel_);
        if (!bytes_result)
            return workspace_result_t<std::string>::failure(bytes_result.error());
        std::wstring wide(length_result.value(), L'\0');
        for (std::size_t index = 0; index < wide.size(); ++index) {
            wide[index] = static_cast<wchar_t>(
                bytes_result.value()[index * 2] |
                (static_cast<std::uint16_t>(bytes_result.value()[index * 2 + 1]) << 8));
        }
        if (wide.empty())
            return workspace_result_t<std::string>::failure(
                pe_error("resource name is empty"));
        const int needed = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
                                               wide.data(), static_cast<int>(wide.size()),
                                               nullptr, 0, nullptr, nullptr);
        if (needed <= 0)
            return workspace_result_t<std::string>::failure(pe_error("resource name is invalid UTF-16"));
        std::string utf8(static_cast<std::size_t>(needed), '\0');
        if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
                                wide.data(), static_cast<int>(wide.size()),
                                utf8.data(), needed, nullptr, nullptr) != needed)
            return workspace_result_t<std::string>::failure(pe_error("resource name conversion failed"));
        auto budget = consume_metadata_bytes(utf8.size());
        if (!budget)
            return workspace_result_t<std::string>::failure(budget.error());
        return workspace_result_t<std::string>::success(std::move(utf8));
    }

    workspace_result_t<void> walk_resources(std::uint32_t base_rva, std::uint32_t relative,
                                            std::uint32_t depth, std::string type,
                                            std::string name, std::uint16_t language,
                                            std::unordered_set<std::uint32_t>& visited) {
        if (depth > limits_.max_resource_depth)
            return workspace_result_t<void>::failure(
                limit_error("resource tree depth exceeds its limit", depth,
                            limits_.max_resource_depth));
        if (depth > 2)
            return workspace_result_t<void>::failure(
                pe_error("resource tree exceeds the representable type/name/language shape"));
        if (++resource_nodes_ > limits_.max_resources)
            return workspace_result_t<void>::failure(
                limit_error("resource node count exceeds its limit", resource_nodes_,
                            limits_.max_resources));
        auto directory_span = validate_span(relative, sizeof(IMAGE_RESOURCE_DIRECTORY),
                                            resource_directory_size_, "pe_parse");
        if (!directory_span)
            return workspace_result_t<void>::failure(
                pe_error("resource directory offset exceeds its root bounds"));
        if (!visited.insert(relative).second)
            return workspace_result_t<void>::failure(pe_error("resource directory contains a cycle"));
        const std::uint64_t directory_rva = static_cast<std::uint64_t>(base_rva) + relative;
        auto directory_result = read_rva<IMAGE_RESOURCE_DIRECTORY>(directory_rva);
        if (!directory_result)
            return workspace_result_t<void>::failure(directory_result.error());
        const std::uint32_t count = static_cast<std::uint32_t>(directory_result.value().NumberOfNamedEntries) +
                                    directory_result.value().NumberOfIdEntries;
        if (count > limits_.max_resources)
            return workspace_result_t<void>::failure(
                limit_error("resource count exceeds its limit",
                            count, limits_.max_resources));
        std::uint64_t next_entry_count = 0;
        if (!checked_add_u64(resource_entries_, count, next_entry_count) ||
            next_entry_count > limits_.max_resources)
            return workspace_result_t<void>::failure(
                limit_error("resource entry count exceeds its aggregate limit",
                            next_entry_count, limits_.max_resources));
        resource_entries_ = next_entry_count;
        std::uint64_t entries_size = 0;
        if (!checked_mul_u64(count, sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY), entries_size))
            return workspace_result_t<void>::failure(pe_error("resource entry table size overflowed"));
        auto entries_span = validate_span(
            static_cast<std::uint64_t>(relative) + sizeof(IMAGE_RESOURCE_DIRECTORY),
            entries_size, resource_directory_size_, "pe_parse");
        if (!entries_span)
            return workspace_result_t<void>::failure(
                pe_error("resource entry table exceeds its root bounds"));
        for (std::uint32_t index = 0; index < count; ++index) {
            if (cancel_.stop_requested())
                return workspace_result_t<void>::failure(stop_error(cancel_));
            auto entry_result = read_rva<IMAGE_RESOURCE_DIRECTORY_ENTRY>(
                directory_rva + sizeof(IMAGE_RESOURCE_DIRECTORY) +
                index * sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY));
            if (!entry_result)
                return workspace_result_t<void>::failure(entry_result.error());
            const auto entry = entry_result.value();
            if (depth == 2 && (entry.Name & 0x80000000U) != 0)
                return workspace_result_t<void>::failure(
                    pe_error("resource language entry must use a numeric identifier"));
            std::string label;
            if (depth != 2) {
                auto label_result = resource_name(base_rva, entry.Name);
                if (!label_result)
                    return workspace_result_t<void>::failure(label_result.error());
                label = label_result.take_value();
            }
            std::string next_type = type;
            std::string next_name = name;
            std::uint16_t next_language = language;
            if (depth == 0)
                next_type = std::move(label);
            else if (depth == 1)
                next_name = std::move(label);
            else if (depth == 2) {
                next_language = static_cast<std::uint16_t>(entry.Id);
            }
            if (entry.DataIsDirectory) {
                if (depth >= 2)
                    return workspace_result_t<void>::failure(
                        pe_error("resource language entry cannot contain another directory"));
                auto child_span = validate_span(entry.OffsetToDirectory,
                                                sizeof(IMAGE_RESOURCE_DIRECTORY),
                                                resource_directory_size_, "pe_parse");
                if (!child_span)
                    return workspace_result_t<void>::failure(
                        pe_error("resource child directory exceeds its root bounds"));
                auto result = walk_resources(base_rva, entry.OffsetToDirectory,
                                             depth + 1, std::move(next_type),
                                             std::move(next_name), next_language, visited);
                if (!result)
                    return result;
            } else {
                if (depth != 2)
                    return workspace_result_t<void>::failure(
                        pe_error("resource data must appear below type, name, and language"));
                auto data_entry_span = validate_span(entry.OffsetToData,
                                                     sizeof(IMAGE_RESOURCE_DATA_ENTRY),
                                                     resource_directory_size_, "pe_parse");
                if (!data_entry_span)
                    return workspace_result_t<void>::failure(
                        pe_error("resource data entry exceeds its root bounds"));
                auto data_result = read_rva<IMAGE_RESOURCE_DATA_ENTRY>(
                    static_cast<std::uint64_t>(base_rva) + entry.OffsetToData);
                if (!data_result)
                    return workspace_result_t<void>::failure(data_result.error());
                if (data_result.value().Size == 0) {
                    if (data_result.value().OffsetToData > image_->image_size_)
                        return workspace_result_t<void>::failure(
                            pe_error("empty resource data RVA exceeds the image"));
                } else {
                    auto mapped = image_->rva_to_file_offset(data_result.value().OffsetToData,
                                                             data_result.value().Size);
                    if (!mapped)
                        return workspace_result_t<void>::failure(mapped.error());
                }
                auto resource_budget = consume_metadata_bytes(sizeof(pe_resource_t) +
                                                              next_type.size() + next_name.size());
                if (!resource_budget)
                    return resource_budget;
                image_->resources_.push_back({std::move(next_type), std::move(next_name),
                    next_language, data_result.value().OffsetToData, data_result.value().Size,
                    data_result.value().CodePage});
            }
        }
        visited.erase(relative);
        return workspace_result_t<void>::success();
    }

    workspace_result_t<void> parse_resources() {
        const auto* data = directory(IMAGE_DIRECTORY_ENTRY_RESOURCE);
        if (!data)
            return workspace_result_t<void>::success();
        if (data->size < sizeof(IMAGE_RESOURCE_DIRECTORY))
            return workspace_result_t<void>::failure(pe_error("resource directory is truncated"));
        resource_directory_size_ = data->size;
        resource_nodes_ = 0;
        resource_entries_ = 0;
        std::unordered_set<std::uint32_t> visited;
        return walk_resources(data->rva, 0, 0, {}, {}, 0, visited);
    }

    void sort_results() {
        auto entry_less = [](const pe_entry_point_t& lhs, const pe_entry_point_t& rhs) {
            return std::tie(lhs.rva, lhs.provenance) < std::tie(rhs.rva, rhs.provenance);
        };
        std::sort(image_->entry_points_.begin(), image_->entry_points_.end(), entry_less);
        image_->entry_points_.erase(std::unique(image_->entry_points_.begin(), image_->entry_points_.end(),
            [](const auto& lhs, const auto& rhs) {
                return lhs.rva == rhs.rva && lhs.provenance == rhs.provenance;
            }), image_->entry_points_.end());
        std::sort(image_->imports_.begin(), image_->imports_.end(), [](const auto& lhs, const auto& rhs) {
            return std::tie(lhs.delayed, lhs.library, lhs.iat_rva, lhs.lookup_rva,
                            lhs.name, lhs.ordinal, lhs.hint) <
                   std::tie(rhs.delayed, rhs.library, rhs.iat_rva, rhs.lookup_rva,
                            rhs.name, rhs.ordinal, rhs.hint);
        });
        std::sort(image_->exports_.begin(), image_->exports_.end(), [](const auto& lhs, const auto& rhs) {
            return std::tie(lhs.ordinal, lhs.rva, lhs.name, lhs.forwarder) <
                   std::tie(rhs.ordinal, rhs.rva, rhs.name, rhs.forwarder);
        });
        std::sort(image_->relocations_.begin(), image_->relocations_.end(), [](const auto& lhs, const auto& rhs) {
            return std::tie(lhs.rva, lhs.type) < std::tie(rhs.rva, rhs.type);
        });
        std::sort(image_->codeview_records_.begin(), image_->codeview_records_.end(),
                  [](const auto& lhs, const auto& rhs) {
                      return std::tie(lhs.guid, lhs.age, lhs.pdb_path, lhs.timestamp) <
                             std::tie(rhs.guid, rhs.age, rhs.pdb_path, rhs.timestamp);
                  });
        std::sort(image_->resources_.begin(), image_->resources_.end(),
                  [](const auto& lhs, const auto& rhs) {
                      return std::tie(lhs.type, lhs.name, lhs.language, lhs.data_rva,
                                      lhs.size, lhs.code_page) <
                             std::tie(rhs.type, rhs.name, rhs.language, rhs.data_rva,
                                      rhs.size, rhs.code_page);
                  });
    }

    const byte_provider_t& provider_;
    const pe_parse_limits_t& limits_;
    const cancellation_token_t& cancel_;
    std::shared_ptr<pe_image_t> image_;
    mutable byte_view_t read_cache_;
    mutable std::uint64_t read_cache_offset_ = 0;
    std::uint64_t metadata_bytes_ = 0;
    std::uint32_t resource_directory_size_ = 0;
    std::uint64_t resource_nodes_ = 0;
    std::uint64_t resource_entries_ = 0;
    std::uint64_t unwind_code_count_ = 0;
    std::unordered_map<std::uint32_t, std::uint32_t> unwind_index_by_rva_;
    std::unordered_set<std::uint32_t> active_unwind_rvas_;
};

workspace_result_t<std::uint64_t> pe_image_t::rva_to_file_offset(std::uint64_t rva,
                                                                std::uint64_t size_value) const {
    if (rva < headers_size_) {
        auto range = validate_span(rva, size_value, headers_size_, "pe_map");
        if (!range)
            return workspace_result_t<std::uint64_t>::failure(range.error());
        return workspace_result_t<std::uint64_t>::success(rva);
    }
    const auto* section = section_for_rva(rva, size_value);
    if (!section) {
        auto error = make_workspace_error(workspace_error_code_t::out_of_range,
                                          "RVA is not file-backed", "pe_map");
        error.address = address_t{address_space_id_t::relative_virtual, rva,
                                  architecture_, mode_};
        error.size = size_value;
        return workspace_result_t<std::uint64_t>::failure(std::move(error));
    }
    const std::uint64_t delta = rva - section->virtual_address;
    if (delta > section->raw_size || size_value > section->raw_size - delta) {
        auto error = make_workspace_error(workspace_error_code_t::out_of_range,
                                          "RVA lies in zero-filled virtual section data", "pe_map");
        error.address = address_t{address_space_id_t::relative_virtual, rva,
                                  architecture_, mode_};
        error.size = size_value;
        return workspace_result_t<std::uint64_t>::failure(std::move(error));
    }
    return workspace_result_t<std::uint64_t>::success(section->raw_offset + delta);
}

workspace_result_t<std::uint64_t> pe_image_t::file_offset_to_rva(std::uint64_t offset,
                                                                std::uint64_t size_value) const {
    if (offset < headers_size_) {
        auto range = validate_span(offset, size_value, headers_size_, "pe_map");
        if (!range)
            return workspace_result_t<std::uint64_t>::failure(range.error());
        return workspace_result_t<std::uint64_t>::success(offset);
    }
    const auto* section = section_for_file_offset(offset, size_value);
    if (!section) {
        auto error = make_workspace_error(workspace_error_code_t::out_of_range,
                                          "file offset is not mapped into the image", "pe_map");
        error.offset = offset;
        error.size = size_value;
        return workspace_result_t<std::uint64_t>::failure(std::move(error));
    }
    return workspace_result_t<std::uint64_t>::success(
        section->virtual_address + (offset - section->raw_offset));
}

workspace_result_t<std::uint64_t> pe_image_t::rva_to_va(std::uint64_t rva) const {
    if (rva >= image_size_)
        return workspace_result_t<std::uint64_t>::failure(
            make_workspace_error(workspace_error_code_t::out_of_range,
                                 "RVA exceeds image size", "pe_map"));
    std::uint64_t va = 0;
    if (!checked_add_u64(image_base_, rva, va))
        return workspace_result_t<std::uint64_t>::failure(
            make_workspace_error(workspace_error_code_t::range_overflow,
                                 "VA calculation overflowed", "pe_map"));
    return workspace_result_t<std::uint64_t>::success(va);
}

workspace_result_t<std::uint64_t> pe_image_t::va_to_rva(std::uint64_t va) const {
    std::uint64_t rva = 0;
    if (!checked_sub_u64(va, image_base_, rva) || rva >= image_size_)
        return workspace_result_t<std::uint64_t>::failure(
            make_workspace_error(workspace_error_code_t::out_of_range,
                                 "VA is outside image bounds", "pe_map"));
    return workspace_result_t<std::uint64_t>::success(rva);
}

const pe_section_t* pe_image_t::section_for_rva(std::uint64_t rva,
                                                std::uint64_t size_value) const noexcept {
    const auto upper = std::upper_bound(
        sections_.begin(), sections_.end(), rva,
        [](std::uint64_t value, const pe_section_t& section) {
            return value < section.virtual_address;
        });
    if (upper == sections_.begin())
        return nullptr;
    const checked_span_t requested{rva, size_value};
    auto iterator = upper;
    while (iterator != sections_.begin()) {
        --iterator;
        const std::uint64_t extent = std::max<std::uint64_t>(
            iterator->virtual_size, iterator->raw_size);
        const checked_span_t section_span{iterator->virtual_address, extent};
        if (section_span.contains(requested))
            return &*iterator;
        std::uint64_t end = 0;
        if (extent != 0 && checked_add_u64(iterator->virtual_address, extent, end) &&
            end < rva)
            break;
    }
    return nullptr;
}

const pe_section_t* pe_image_t::section_for_file_offset(std::uint64_t offset,
                                                        std::uint64_t size_value) const noexcept {
    for (const auto& section : sections_) {
        const checked_span_t section_span{section.raw_offset, section.raw_size};
        const checked_span_t requested{offset, size_value};
        if (section_span.contains(requested))
            return &section;
    }
    return nullptr;
}

workspace_result_t<std::shared_ptr<const pe_image_t>>
parse_pe_image(const byte_provider_t& provider, const pe_parse_limits_t& limits,
               const cancellation_token_t& cancel) {
    auto profile = validate_pe_parser_profile(make_pe_parser_profile(limits));
    if (!profile)
        return workspace_result_t<std::shared_ptr<const pe_image_t>>::failure(
            profile.error());
    return pe_parser_t(provider, limits, cancel).parse();
}

workspace_result_t<std::shared_ptr<const workspace_image_t>>
normalize_pe_image(const pe_image_t& image, const byte_provider_t& provider,
                   const cancellation_token_t& cancel) {
    if (cancel.stop_requested())
        return workspace_result_t<std::shared_ptr<const workspace_image_t>>::failure(
            stop_error(cancel));
    try {
        auto normalized = std::make_shared<workspace_image_t>();
        normalized->format = image.format();
        normalized->architecture = image.architecture();
        normalized->architecture_mode = image.architecture_mode();
        normalized->abi = image.abi();
        normalized->endian = image.endian();
        normalized->address_width_bits = image.format() == format_id_t::pe32_plus ? 64 : 32;
        normalized->image_base = image.image_base();
        normalized->image_size = image.image_size();
        normalized->header_size = image.headers_size();
        normalized->format_name = image.format() == format_id_t::pe32_plus ? "pe32_plus" : "pe32";
        normalized->provider_size = provider.size();
        normalized->member = provider.member_metadata();

        const auto make_address = [&image](std::uint64_t rva) {
            return address_t{address_space_id_t::relative_virtual, rva,
                             image.architecture(), image.architecture_mode()};
        };
        const auto section_permissions = [](const pe_section_t& section) {
            std::uint32_t permissions = image_permission_none;
            if (section.readable)
                permissions |= image_permission_read;
            if (section.writable)
                permissions |= image_permission_write;
            if (section.executable)
                permissions |= image_permission_execute;
            if (section.discardable)
                permissions |= image_permission_discardable;
            return permissions;
        };

        if (image.headers_size() != 0) {
            image_address_mapping_t mapping;
            mapping.source_start = 0;
            mapping.target_start = 0;
            mapping.size = image.headers_size();
            mapping.permissions = image_permission_read;
            normalized->address_mappings.push_back(mapping);
        }
        for (const auto& section : image.sections()) {
            if (cancel.stop_requested())
                return workspace_result_t<std::shared_ptr<const workspace_image_t>>::failure(
                    stop_error(cancel));
            const std::uint64_t virtual_size = section.virtual_size;
            const std::uint64_t file_size = section.raw_size;
            if (virtual_size == 0 && file_size == 0)
                continue;
            image_section_t normalized_section;
            normalized_section.index = section.index;
            normalized_section.name = section.name;
            normalized_section.virtual_address = section.virtual_address;
            normalized_section.virtual_size = virtual_size;
            normalized_section.file_offset = file_size == 0 ? 0 : section.raw_offset;
            normalized_section.file_size = file_size;
            normalized_section.flags = section.characteristics;
            normalized_section.permissions = section_permissions(section);
            normalized->sections.push_back(normalized_section);

            image_segment_t normalized_segment;
            normalized_segment.index = section.index;
            normalized_segment.name = section.name;
            normalized_segment.virtual_address = section.virtual_address;
            normalized_segment.virtual_size = virtual_size;
            normalized_segment.file_offset = file_size == 0 ? 0 : section.raw_offset;
            normalized_segment.file_size = file_size;
            normalized_segment.flags = section.characteristics;
            normalized_segment.permissions = normalized_section.permissions;
            normalized->segments.push_back(std::move(normalized_segment));

            if (file_size != 0) {
                image_address_mapping_t mapping;
                mapping.source_start = section.raw_offset;
                mapping.target_start = section.virtual_address;
                mapping.size = file_size;
                mapping.permissions = normalized_section.permissions;
                normalized->address_mappings.push_back(mapping);
            }
        }
        for (const auto& entry : image.entry_points()) {
            if (cancel.stop_requested())
                return workspace_result_t<std::shared_ptr<const workspace_image_t>>::failure(
                    stop_error(cancel));
            normalized->entry_points.push_back(image_entry_point_t{make_address(entry.rva), entry.provenance});
        }
        for (const auto& imported : image.imports()) {
            if (cancel.stop_requested())
                return workspace_result_t<std::shared_ptr<const workspace_image_t>>::failure(
                    stop_error(cancel));
            image_import_t normalized_import;
            normalized_import.library = imported.library;
            normalized_import.name = imported.name;
            if (imported.ordinal)
                normalized_import.ordinal = *imported.ordinal;
            normalized_import.lookup_address = make_address(imported.lookup_rva);
            normalized_import.address = make_address(imported.iat_rva);
            normalized_import.delayed = imported.delayed;
            normalized->imports.push_back(normalized_import);

            image_symbol_t symbol;
            symbol.name = imported.library;
            symbol.name.push_back('!');
            if (imported.name)
                symbol.name.append(*imported.name);
            else if (imported.ordinal)
                symbol.name.append("#").append(std::to_string(*imported.ordinal));
            symbol.address = normalized_import.address;
            symbol.kind = image_symbol_kind_t::import_symbol;
            symbol.binding = image_symbol_binding_t::external;
            normalized->symbols.push_back(std::move(symbol));
        }
        for (const auto& exported : image.exports()) {
            if (cancel.stop_requested())
                return workspace_result_t<std::shared_ptr<const workspace_image_t>>::failure(
                    stop_error(cancel));
            image_export_t normalized_export;
            normalized_export.name = exported.name;
            normalized_export.ordinal = exported.ordinal;
            normalized_export.address = make_address(exported.rva);
            normalized_export.forwarder = exported.forwarder;
            normalized->exports.push_back(normalized_export);

            image_symbol_t symbol;
            symbol.ordinal = exported.ordinal;
            if (exported.name)
                symbol.name = *exported.name;
            symbol.address = normalized_export.address;
            symbol.kind = image_symbol_kind_t::export_symbol;
            symbol.binding = image_symbol_binding_t::global;
            symbol.defined = !exported.forwarder.has_value();
            symbol.forwarded = exported.forwarder.has_value();
            normalized->symbols.push_back(std::move(symbol));
        }
        for (const auto& relocation : image.relocations()) {
            if (cancel.stop_requested())
                return workspace_result_t<std::shared_ptr<const workspace_image_t>>::failure(
                    stop_error(cancel));
            normalized->relocations.push_back(image_relocation_t{
                make_address(relocation.rva), relocation.type, std::nullopt});
        }
        auto validation = validate_workspace_image(*normalized);
        if (!validation)
            return workspace_result_t<std::shared_ptr<const workspace_image_t>>::failure(
                validation.error());
        return workspace_result_t<std::shared_ptr<const workspace_image_t>>::success(
            std::static_pointer_cast<const workspace_image_t>(std::move(normalized)));
    } catch (const std::bad_alloc&) {
        return workspace_result_t<std::shared_ptr<const workspace_image_t>>::failure(
            make_workspace_error(workspace_error_code_t::limit_exceeded,
                                 "PE normalization allocation failed", "pe_normalize"));
    }
}

std::vector<unwind_record_t> parse_x64_unwind_records(const byte_provider_t& provider,
                                                      const pe_image_t& image,
                                                      const cancellation_token_t& cancel) {
    std::vector<unwind_record_t> result;
    const auto& runtime_functions = image.runtime_functions();
    if (runtime_functions.empty())
        return result;

    constexpr std::size_t max_records = 65536;
    constexpr std::uint32_t max_chain_depth = 16;

    auto read_u32 = [&](std::uint32_t rva) -> std::optional<std::uint32_t> {
        auto offset = image.rva_to_file_offset(rva, 4);
        if (!offset) return std::nullopt;
        auto lease = provider.lease(offset.value(), 4, cancel);
        if (!lease || lease.value().size() < 4) return std::nullopt;
        std::uint32_t value = 0;
        std::memcpy(&value, lease.value().data(), 4);
        return value;
    };

    auto read_bytes = [&](std::uint32_t rva,
                          std::uint64_t size) -> std::optional<std::vector<std::uint8_t>> {
        auto offset = image.rva_to_file_offset(rva, size);
        if (!offset) return std::nullopt;
        auto lease = provider.lease(offset.value(), size, cancel);
        if (!lease || lease.value().size() < size) return std::nullopt;
        return std::vector<std::uint8_t>(lease.value().data(),
                                         lease.value().data() + lease.value().size());
    };

    for (std::size_t i = 0; i < runtime_functions.size(); ++i) {
        if ((i % 4096) == 0 && cancel.stop_requested())
            return result;
        if (result.size() >= max_records)
            break;

        const auto& rf = runtime_functions[i];
        if (rf.unwind_rva == 0)
            continue;

        std::uint32_t cur_func_rva = rf.begin_rva;
        std::uint32_t cur_end_rva = rf.end_rva;
        std::uint32_t cur_unwind_rva = rf.unwind_rva;
        std::uint32_t depth = 0;

        while (cur_unwind_rva != 0 && depth < max_chain_depth) {
            if (result.size() >= max_records)
                break;

            auto header = read_bytes(cur_unwind_rva, 4);
            if (!header || header->size() < 4)
                break;

            const auto* hdr = header->data();
            std::uint8_t version = hdr[0] & 0x07U;
            std::uint8_t flags = hdr[0] >> 3U;
            std::uint8_t code_slots = hdr[2];
            std::uint8_t frame_reg = hdr[3] & 0x0FU;

            unwind_record_t rec;
            rec.function_rva = cur_func_rva;
            rec.end_rva = cur_end_rva;
            rec.unwind_info_rva = cur_unwind_rva;
            rec.version = version;
            rec.flags = flags;
            rec.frame_reg = frame_reg;

            if (code_slots > 0) {
                std::uint64_t code_bytes = static_cast<std::uint64_t>(code_slots) * 2;
                auto codes = read_bytes(cur_unwind_rva + 4, code_bytes);
                if (codes) {
                    for (std::uint8_t s = 0; s < code_slots; ++s) {
                        const auto* raw = codes->data() + static_cast<std::size_t>(s) * 2;
                        unwind_code_t uc;
                        uc.code_offset = raw[0];
                        uc.unwind_op = raw[1] & 0x0FU;
                        uc.op_info = raw[1] >> 4U;
                        rec.unwind_codes.push_back(uc);
                    }
                }
            }

            std::uint64_t aligned_slots =
                (static_cast<std::uint64_t>(code_slots) + 1ULL) & ~1ULL;
            std::uint64_t tail_rva =
                static_cast<std::uint64_t>(cur_unwind_rva) + 4ULL + aligned_slots * 2ULL;

            std::uint32_t next_func_rva = 0;
            std::uint32_t next_end_rva = 0;
            std::uint32_t next_unwind_rva = 0;
            bool has_chain = false;

            if ((flags & 0x04U) != 0) {
                auto chained = read_bytes(static_cast<std::uint32_t>(tail_rva), 12);
                if (chained && chained->size() >= 12) {
                    std::memcpy(&next_func_rva, chained->data(), 4);
                    std::memcpy(&next_end_rva, chained->data() + 4, 4);
                    std::memcpy(&next_unwind_rva, chained->data() + 8, 4);
                    rec.chained_function_rva = next_func_rva;
                    rec.chained_end_rva = next_end_rva;
                    has_chain = true;
                }
            } else if ((flags & 0x03U) != 0) {
                auto handler = read_u32(static_cast<std::uint32_t>(tail_rva));
                if (handler) {
                    rec.handler_rva = *handler;
                    std::uint64_t data_rva = tail_rva + 4;
                    if (data_rva < image.image_size()) {
                        std::uint64_t avail = image.image_size() - data_rva;
                        std::uint64_t read_size = avail < 256 ? avail : 256;
                        auto handler_data = read_bytes(
                            static_cast<std::uint32_t>(data_rva), read_size);
                        if (handler_data)
                            rec.handler_data = std::move(*handler_data);
                    }
                }
            }

            result.push_back(std::move(rec));

            if (!has_chain)
                break;

            cur_func_rva = next_func_rva;
            cur_end_rva = next_end_rva;
            cur_unwind_rva = next_unwind_rva;
            ++depth;
        }
    }

    return result;
}

std::vector<exception_edge_t> build_exception_edges(
    const std::vector<unwind_record_t>& unwinds) {
    std::vector<exception_edge_t> edges;
    edges.reserve(unwinds.size());
    for (const auto& rec : unwinds) {
        if (rec.handler_rva != 0) {
            exception_edge_t edge;
            edge.from_rva = rec.function_rva;
            edge.to_rva = rec.handler_rva;
            edge.edge_kind = 0;
            edge.handler_rva = rec.handler_rva;
            edge.provenance = static_cast<std::uint8_t>(fact_provenance_t::unwind_metadata);
            edges.push_back(edge);
        }
        if (rec.chained_function_rva != 0) {
            exception_edge_t edge;
            edge.from_rva = rec.function_rva;
            edge.to_rva = rec.chained_function_rva;
            edge.edge_kind = 1;
            edge.handler_rva = 0;
            edge.provenance = static_cast<std::uint8_t>(fact_provenance_t::unwind_metadata);
            edges.push_back(edge);
        }
    }
    return edges;
}

}
