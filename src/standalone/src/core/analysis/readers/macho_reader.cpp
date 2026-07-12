#include "macho_reader.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <exception>
#include <functional>
#include <limits>
#include <new>
#include <stdexcept>
#include <utility>

namespace aida::analysis::readers {

std::string macho_slice_identity_t::stable_key() const {
    std::string value;
    if (archive_member_ordinal)
        value = "ar:" + std::to_string(*archive_member_ordinal) + ":";
    value += std::to_string(container_offset) + ":" + std::to_string(size) + ":" +
             std::to_string(cpu_type) + ":" + std::to_string(cpu_subtype) + ":" +
             std::to_string(static_cast<unsigned int>(endian)) + ":" +
             std::to_string(is_64_bit ? 64U : 32U);
    return value;
}

std::vector<std::string> macho_metadata_document_t::differential_records() const {
    const auto hex = [](const std::string& value) {
        static constexpr char digits[] = "0123456789abcdef";
        std::string encoded;
        encoded.reserve(value.size() * 2U);
        for (const auto byte : value) {
            const auto value_byte = static_cast<std::uint8_t>(byte);
            encoded.push_back(digits[value_byte >> 4U]);
            encoded.push_back(digits[value_byte & 0x0fU]);
        }
        return encoded;
    };
    std::vector<std::string> records;
    records.emplace_back("container|" + std::to_string(static_cast<unsigned int>(container_kind)) + "|" +
                         std::to_string(thin_archive ? 1U : 0U));
    for (const auto& member : archive_members) {
        records.emplace_back("archive|" + std::to_string(member.ordinal) + "|" + hex(member.name) + "|" +
                             std::to_string(member.header_offset) + "|" + std::to_string(member.data_offset) + "|" +
                             std::to_string(member.data_size) + "|" +
                             std::to_string(member.embedded ? 1U : 0U) + "|" +
                             std::to_string(member.mach_metadata_available ? 1U : 0U));
    }
    for (const auto& image : slices) {
        const auto key = image.identity.stable_key();
        records.emplace_back("slice|" + key + "|" + std::to_string(image.file_type) + "|" +
                             std::to_string(image.flags));
        for (const auto& command : image.load_commands) {
            records.emplace_back("command|" + key + "|" + std::to_string(command.ordinal) + "|" +
                                 std::to_string(command.command) + "|" + std::to_string(command.offset) + "|" +
                                 std::to_string(command.size) + "|" + hex(command.kind));
        }
        for (const auto& segment : image.segments) {
            records.emplace_back("segment|" + key + "|" + std::to_string(segment.index) + "|" +
                                 hex(segment.name) + "|" + std::to_string(segment.virtual_address) + "|" +
                                 std::to_string(segment.virtual_size) + "|" + std::to_string(segment.file_offset) + "|" +
                                 std::to_string(segment.file_size));
            for (const auto& section : segment.sections) {
                records.emplace_back("section|" + key + "|" + std::to_string(section.index) + "|" +
                                     hex(section.segment_name) + "|" + hex(section.section_name) + "|" +
                                     std::to_string(section.address) + "|" + std::to_string(section.size) + "|" +
                                     std::to_string(section.file_offset) + "|" +
                                     std::to_string(section.relocation_count));
            }
        }
        for (const auto& dylib : image.dylibs) {
            records.emplace_back("dylib|" + key + "|" + std::to_string(dylib.command) + "|" + hex(dylib.path) +
                                 "|" + std::to_string(dylib.timestamp) + "|" +
                                 std::to_string(dylib.current_version) + "|" +
                                 std::to_string(dylib.compatibility_version));
        }
        for (const auto& symbol : image.symbols) {
            records.emplace_back("symbol|" + key + "|" + std::to_string(symbol.index) + "|" + hex(symbol.name) +
                                 "|" + std::to_string(symbol.value) + "|" + std::to_string(symbol.type) + "|" +
                                 std::to_string(symbol.section) + "|" + std::to_string(symbol.descriptor));
        }
        for (const auto& bind : image.bindings) {
            records.emplace_back("bind|" + key + "|" + std::to_string(static_cast<unsigned int>(bind.stream)) +
                                 "|" + std::to_string(bind.segment_index) + "|" + std::to_string(bind.address) +
                                 "|" + std::to_string(bind.type) + "|" + std::to_string(bind.library_ordinal) + "|" +
                                 hex(bind.symbol) + "|" + std::to_string(bind.addend) + "|" +
                                 std::to_string(bind.flags));
        }
        for (const auto& rebase : image.rebases) {
            records.emplace_back("rebase|" + key + "|" + std::to_string(rebase.segment_index) + "|" +
                                 std::to_string(rebase.address) + "|" + std::to_string(rebase.type));
        }
        for (const auto& entry : image.exports) {
            records.emplace_back("export|" + key + "|" + hex(entry.name) + "|" +
                                 std::to_string(entry.flags) + "|" + std::to_string(entry.address) + "|" +
                                 (entry.other ? std::to_string(*entry.other) : "-") + "|" +
                                 (entry.import_name ? hex(*entry.import_name) : "-"));
        }
        for (const auto& relocation : image.relocations) {
            records.emplace_back("relocation|" + key + "|" +
                                 (relocation.section_index ? std::to_string(*relocation.section_index) : "-") + "|" +
                                 std::to_string(relocation.address) + "|" +
                                 std::to_string(relocation.symbol_number) + "|" +
                                 std::to_string(relocation.type) + "|" + std::to_string(relocation.length) + "|" +
                                 std::to_string(relocation.pc_relative ? 1U : 0U) + "|" +
                                 std::to_string(relocation.external ? 1U : 0U) + "|" +
                                 std::to_string(relocation.scattered ? 1U : 0U) + "|" +
                                 (relocation.target_value ? std::to_string(*relocation.target_value) : "-"));
        }
        for (const auto& unwind : image.unwind) {
            records.emplace_back("unwind|" + key + "|" + hex(unwind.kind) + "|" +
                                 std::to_string(unwind.file_offset) + "|" + std::to_string(unwind.size) + "|" +
                                 (unwind.function_address ? std::to_string(*unwind.function_address) : "-"));
        }
        for (const auto& exception : image.exceptions) {
            records.emplace_back("exception|" + key + "|" + hex(exception.kind) + "|" +
                                 std::to_string(exception.file_offset) + "|" + std::to_string(exception.size));
        }
        for (const auto& seed : image.metadata_seeds) {
            records.emplace_back("seed|" + key + "|" + hex(seed.kind) + "|" + hex(seed.segment_name) + "|" +
                                 hex(seed.section_name) + "|" + std::to_string(seed.address) + "|" +
                                 std::to_string(seed.file_offset) + "|" + std::to_string(seed.size));
        }
        const auto& signature = image.code_signature;
        records.emplace_back("codesign|" + key + "|" + std::to_string(signature.present ? 1U : 0U) + "|" +
                             std::to_string(signature.parsed ? 1U : 0U) + "|" +
                             std::to_string(signature.verified ? 1U : 0U) + "|" +
                             std::to_string(signature.trusted ? 1U : 0U) + "|" +
                             std::to_string(signature.command_offset) + "|" +
                             std::to_string(signature.data_offset) + "|" +
                             std::to_string(signature.data_size) + "|" +
                             std::to_string(signature.superblob_magic) + "|" +
                             std::to_string(signature.superblob_length));
        for (const auto& slot : signature.slots) {
            records.emplace_back("codesign_slot|" + key + "|" + std::to_string(slot.type) + "|" +
                                 std::to_string(slot.offset) + "|" + std::to_string(slot.magic) + "|" +
                                 std::to_string(slot.length));
        }
    }
    return records;
}

namespace {

constexpr std::uint32_t k_lc_req_dyld = 0x80000000U;
constexpr std::uint32_t k_lc_segment = 0x1U;
constexpr std::uint32_t k_lc_symtab = 0x2U;
constexpr std::uint32_t k_lc_dysymtab = 0xbU;
constexpr std::uint32_t k_lc_load_dylib = 0xcU;
constexpr std::uint32_t k_lc_id_dylib = 0xdU;
constexpr std::uint32_t k_lc_load_weak_dylib = 0x18U;
constexpr std::uint32_t k_lc_segment_64 = 0x19U;
constexpr std::uint32_t k_lc_reexport_dylib = 0x1fU;
constexpr std::uint32_t k_lc_lazy_load_dylib = 0x20U;
constexpr std::uint32_t k_lc_dyld_info = 0x22U;
constexpr std::uint32_t k_lc_load_upward_dylib = 0x23U;
constexpr std::uint32_t k_lc_function_starts = 0x26U;
constexpr std::uint32_t k_lc_data_in_code = 0x29U;
constexpr std::uint32_t k_lc_code_signature = 0x1dU;
constexpr std::uint32_t k_lc_dyld_exports_trie = 0x33U;
constexpr std::uint32_t k_lc_dyld_chained_fixups = 0x34U;
constexpr std::uint32_t k_mh_object = 0x1U;
constexpr std::uint32_t k_mh_execute = 0x2U;
constexpr std::uint32_t k_mh_fvmlib = 0x3U;
constexpr std::uint32_t k_mh_core = 0x4U;
constexpr std::uint32_t k_mh_preload = 0x5U;
constexpr std::uint32_t k_mh_dylib = 0x6U;
constexpr std::uint32_t k_mh_dylinker = 0x7U;
constexpr std::uint32_t k_mh_bundle = 0x8U;
constexpr std::uint32_t k_mh_dylib_stub = 0x9U;
constexpr std::uint32_t k_mh_dsym = 0xaU;
constexpr std::uint32_t k_mh_kext_bundle = 0xbU;
constexpr std::uint32_t k_mh_fileset = 0xcU;
constexpr std::uint32_t k_export_reexport = 0x08U;
constexpr std::uint32_t k_export_stub_and_resolver = 0x10U;
constexpr std::uint32_t k_cs_superblob = 0xfade0cc0U;

class parse_exception_t final : public std::exception {
public:
    explicit parse_exception_t(workspace_error_t error) : error_(std::move(error)) {}

    const char* what() const noexcept override {
        return error_.message.c_str();
    }

    const workspace_error_t& error() const noexcept {
        return error_;
    }

private:
    workspace_error_t error_;
};

struct byte_slice_t {
    const std::uint8_t* bytes = nullptr;
    std::uint64_t size = 0;
    std::uint64_t origin = 0;
};

struct symtab_ref_t {
    std::uint64_t symbol_offset = 0;
    std::uint32_t symbol_count = 0;
    std::uint64_t string_offset = 0;
    std::uint32_t string_size = 0;
};

struct dysymtab_ref_t {
    std::uint64_t external_relocation_offset = 0;
    std::uint32_t external_relocation_count = 0;
    std::uint64_t local_relocation_offset = 0;
    std::uint32_t local_relocation_count = 0;
};

struct dyld_info_ref_t {
    std::uint64_t rebase_offset = 0;
    std::uint32_t rebase_size = 0;
    std::uint64_t bind_offset = 0;
    std::uint32_t bind_size = 0;
    std::uint64_t weak_bind_offset = 0;
    std::uint32_t weak_bind_size = 0;
    std::uint64_t lazy_bind_offset = 0;
    std::uint32_t lazy_bind_size = 0;
    std::uint64_t export_offset = 0;
    std::uint32_t export_size = 0;
};

struct blob_ref_t {
    std::uint64_t offset = 0;
    std::uint32_t size = 0;
    std::uint64_t command_offset = 0;
};

bool has_prefix(const byte_slice_t& slice, const std::array<std::uint8_t, 4>& value) noexcept {
    return slice.size >= value.size() &&
           std::equal(value.begin(), value.end(), slice.bytes);
}

bool has_prefix(const byte_slice_t& slice, const char* value, std::size_t length) noexcept {
    return slice.size >= length && std::memcmp(slice.bytes, value, length) == 0;
}

bool is_fat(const byte_slice_t& slice) noexcept {
    return has_prefix(slice, {0xcaU, 0xfeU, 0xbaU, 0xbeU}) ||
           has_prefix(slice, {0xbeU, 0xbaU, 0xfeU, 0xcaU}) ||
           has_prefix(slice, {0xcaU, 0xfeU, 0xbaU, 0xbfU}) ||
           has_prefix(slice, {0xbfU, 0xbaU, 0xfeU, 0xcaU});
}

bool is_thin_macho(const byte_slice_t& slice) noexcept {
    return has_prefix(slice, {0xceU, 0xfaU, 0xedU, 0xfeU}) ||
           has_prefix(slice, {0xcfU, 0xfaU, 0xedU, 0xfeU}) ||
           has_prefix(slice, {0xfeU, 0xedU, 0xfaU, 0xceU}) ||
           has_prefix(slice, {0xfeU, 0xedU, 0xfaU, 0xcfU});
}

bool is_archive(const byte_slice_t& slice) noexcept {
    return has_prefix(slice, "!<arch>\n", 8U) || has_prefix(slice, "!<thin>\n", 8U);
}

architecture_id_t architecture_for_cpu(std::int32_t cpu_type) noexcept {
    switch (static_cast<std::uint32_t>(cpu_type)) {
        case 7U:
            return architecture_id_t::x86;
        case 0x01000007U:
            return architecture_id_t::x86_64;
        case 12U:
            return architecture_id_t::arm;
        case 0x0100000cU:
            return architecture_id_t::aarch64;
        case 8U:
            return architecture_id_t::mips;
        case 0x01000008U:
            return architecture_id_t::mips64;
        case 18U:
            return architecture_id_t::ppc;
        case 0x01000012U:
            return architecture_id_t::ppc64;
        case 0x01000017U:
            return architecture_id_t::riscv64;
        default:
            return architecture_id_t::unknown;
    }
}

macho_file_kind_t file_kind_for_type(std::uint32_t type) noexcept {
    switch (type) {
        case k_mh_object:
            return macho_file_kind_t::object;
        case k_mh_execute:
            return macho_file_kind_t::executable;
        case k_mh_fvmlib:
            return macho_file_kind_t::fixed_vm_library;
        case k_mh_core:
            return macho_file_kind_t::core;
        case k_mh_preload:
            return macho_file_kind_t::preload;
        case k_mh_dylib:
            return macho_file_kind_t::dylib;
        case k_mh_dylinker:
            return macho_file_kind_t::dylinker;
        case k_mh_bundle:
            return macho_file_kind_t::bundle;
        case k_mh_dylib_stub:
            return macho_file_kind_t::dylib_stub;
        case k_mh_dsym:
            return macho_file_kind_t::dsym;
        case k_mh_kext_bundle:
            return macho_file_kind_t::kext_bundle;
        case k_mh_fileset:
            return macho_file_kind_t::fileset;
        default:
            return macho_file_kind_t::unknown;
    }
}

const char* command_kind(std::uint32_t command) noexcept {
    switch (command & ~k_lc_req_dyld) {
        case k_lc_segment:
            return "segment";
        case k_lc_symtab:
            return "symtab";
        case k_lc_dysymtab:
            return "dysymtab";
        case k_lc_load_dylib:
            return "load_dylib";
        case k_lc_id_dylib:
            return "id_dylib";
        case k_lc_load_weak_dylib:
            return "load_weak_dylib";
        case k_lc_segment_64:
            return "segment_64";
        case k_lc_code_signature:
            return "code_signature";
        case k_lc_reexport_dylib:
            return "reexport_dylib";
        case k_lc_lazy_load_dylib:
            return "lazy_load_dylib";
        case k_lc_dyld_info:
            return "dyld_info";
        case k_lc_load_upward_dylib:
            return "load_upward_dylib";
        case k_lc_function_starts:
            return "function_starts";
        case k_lc_data_in_code:
            return "data_in_code";
        case k_lc_dyld_exports_trie:
            return "dyld_exports_trie";
        case k_lc_dyld_chained_fixups:
            return "dyld_chained_fixups";
        default:
            return "unknown";
    }
}

class macho_reader_t final {
public:
    macho_reader_t(byte_slice_t input, const macho_reader_limits_t& limits,
                   const cancellation_token_t& cancel)
        : input_(input), limits_(limits), cancel_(cancel) {}

    macho_metadata_document_t read() {
        validate_limits();
        if (input_.size == 0)
            fail(workspace_error_code_t::malformed_image, "Mach-O input is empty", "macho.detect", 0, 0);
        if (input_.size > limits_.max_input_bytes)
            fail(workspace_error_code_t::limit_exceeded, "Mach-O input exceeds its configured bound",
                 "macho.detect", 0, input_.size);
        if (is_archive(input_)) {
            document_.container_kind = macho_container_kind_t::archive;
            parse_archive(input_);
        } else if (is_fat(input_)) {
            document_.container_kind = macho_container_kind_t::fat;
            parse_fat(input_, std::nullopt);
        } else if (is_thin_macho(input_)) {
            document_.container_kind = macho_container_kind_t::thin;
            parse_thin(input_, {}, std::nullopt);
        } else {
            fail(workspace_error_code_t::unsupported_format,
                 "Input is not a Mach-O, fat Mach-O, or UNIX archive", "macho.detect", 0, 4);
        }
        if (document_.slices.empty() && document_.archive_members.empty())
            fail(workspace_error_code_t::malformed_image, "Mach-O container contains no metadata-bearing member",
                 "macho.detect", 0, input_.size);
        return std::move(document_);
    }

private:
    byte_slice_t input_;
    const macho_reader_limits_t& limits_;
    const cancellation_token_t& cancel_;
    macho_metadata_document_t document_;
    std::uint64_t metadata_bytes_ = 0;
    std::uint64_t string_bytes_ = 0;
    std::uint32_t section_count_ = 0;

    [[noreturn]] void fail(workspace_error_code_t code, std::string message, std::string phase,
                           std::uint64_t offset, std::uint64_t size) const {
        workspace_error_t error = make_workspace_error(code, std::move(message), std::move(phase));
        std::uint64_t absolute = 0;
        if (offset <= (std::numeric_limits<std::uint64_t>::max)() - input_.origin)
            absolute = input_.origin + offset;
        else
            absolute = offset;
        error.offset = absolute;
        error.size = size;
        throw parse_exception_t(std::move(error));
    }

    [[noreturn]] void fail_stop(std::string phase) const {
        workspace_error_t error = make_workspace_error(
            cancel_.deadline_exceeded() ? workspace_error_code_t::deadline_exceeded
                                        : workspace_error_code_t::cancelled,
            "Mach-O metadata read was cancelled", std::move(phase));
        error.deadline = cancel_.deadline_exceeded();
        error.cancellation = !error.deadline;
        throw parse_exception_t(std::move(error));
    }

    void poll(std::uint64_t iteration, const char* phase) const {
        if ((iteration & 0xffU) == 0U && cancel_.stop_requested())
            fail_stop(phase);
    }

    void validate_limits() const {
        if (limits_.max_input_bytes == 0 || limits_.max_metadata_bytes == 0 ||
            limits_.max_string_bytes == 0 || limits_.max_linkedit_bytes == 0 ||
            limits_.max_archive_members == 0 || limits_.max_fat_slices == 0 ||
            limits_.max_load_commands == 0 || limits_.max_segments == 0 ||
            limits_.max_sections == 0 || limits_.max_symbols == 0 || limits_.max_dylibs == 0 ||
            limits_.max_binds == 0 || limits_.max_rebases == 0 || limits_.max_exports == 0 ||
            limits_.max_relocations == 0 || limits_.max_unwind_records == 0 ||
            limits_.max_metadata_seeds == 0 || limits_.max_code_signature_slots == 0 ||
            limits_.max_export_depth == 0 || limits_.max_export_depth > 1024U) {
            fail(workspace_error_code_t::invalid_argument, "Mach-O reader limits are invalid",
                 "macho.profile", 0, 0);
        }
    }

    void consume_metadata(std::uint64_t amount, const char* phase) {
        if (amount > limits_.max_metadata_bytes - (std::min)(metadata_bytes_, limits_.max_metadata_bytes))
            fail(workspace_error_code_t::limit_exceeded, "Mach-O metadata exceeds its configured bound",
                 phase, 0, amount);
        if (metadata_bytes_ > (std::numeric_limits<std::uint64_t>::max)() - amount)
            fail(workspace_error_code_t::range_overflow, "Mach-O metadata accounting overflowed",
                 phase, 0, amount);
        metadata_bytes_ += amount;
        if (metadata_bytes_ > limits_.max_metadata_bytes)
            fail(workspace_error_code_t::limit_exceeded, "Mach-O metadata exceeds its configured bound",
                 phase, 0, metadata_bytes_);
    }

    std::string owned_string(const std::uint8_t* value, std::size_t length, const char* phase) {
        if (length > limits_.max_string_bytes - (std::min)(string_bytes_, limits_.max_string_bytes))
            fail(workspace_error_code_t::limit_exceeded, "Mach-O string metadata exceeds its configured bound",
                 phase, 0, length);
        if (string_bytes_ > (std::numeric_limits<std::uint64_t>::max)() - length)
            fail(workspace_error_code_t::range_overflow, "Mach-O string accounting overflowed", phase, 0, length);
        string_bytes_ += length;
        consume_metadata(length, phase);
        return std::string(reinterpret_cast<const char*>(value), length);
    }

    std::string owned_string(const char* value, const char* phase) {
        return owned_string(reinterpret_cast<const std::uint8_t*>(value), std::strlen(value), phase);
    }

    template <typename T>
    void append(std::vector<T>& values, T value, std::uint64_t maximum, const char* phase) {
        if (values.size() >= maximum)
            fail(workspace_error_code_t::limit_exceeded, "Mach-O metadata record count exceeds its configured bound",
                 phase, 0, values.size() + 1U);
        consume_metadata(sizeof(T), phase);
        values.emplace_back(std::move(value));
    }

    void require_range(const byte_slice_t& slice, std::uint64_t offset, std::uint64_t size,
                       const char* phase) const {
        if (offset > slice.size || size > slice.size - offset)
            fail(workspace_error_code_t::out_of_range, "Mach-O range exceeds its container member",
                 phase, offset, size);
    }

    byte_slice_t subrange(const byte_slice_t& slice, std::uint64_t offset, std::uint64_t size,
                          const char* phase) const {
        require_range(slice, offset, size, phase);
        if (offset > (std::numeric_limits<std::uint64_t>::max)() - slice.origin)
            fail(workspace_error_code_t::range_overflow, "Mach-O member offset overflowed", phase, offset, size);
        return {slice.bytes + static_cast<std::size_t>(offset), size, slice.origin + offset};
    }

    std::uint8_t u8(const byte_slice_t& slice, std::uint64_t offset, const char* phase) const {
        require_range(slice, offset, 1, phase);
        return slice.bytes[static_cast<std::size_t>(offset)];
    }

    std::uint16_t u16(const byte_slice_t& slice, std::uint64_t offset, bool little, const char* phase) const {
        require_range(slice, offset, 2, phase);
        const auto* value = slice.bytes + static_cast<std::size_t>(offset);
        if (little)
            return static_cast<std::uint16_t>(value[0]) | (static_cast<std::uint16_t>(value[1]) << 8U);
        return (static_cast<std::uint16_t>(value[0]) << 8U) | static_cast<std::uint16_t>(value[1]);
    }

    std::uint32_t u32(const byte_slice_t& slice, std::uint64_t offset, bool little, const char* phase) const {
        require_range(slice, offset, 4, phase);
        const auto* value = slice.bytes + static_cast<std::size_t>(offset);
        if (little) {
            return static_cast<std::uint32_t>(value[0]) |
                   (static_cast<std::uint32_t>(value[1]) << 8U) |
                   (static_cast<std::uint32_t>(value[2]) << 16U) |
                   (static_cast<std::uint32_t>(value[3]) << 24U);
        }
        return (static_cast<std::uint32_t>(value[0]) << 24U) |
               (static_cast<std::uint32_t>(value[1]) << 16U) |
               (static_cast<std::uint32_t>(value[2]) << 8U) |
               static_cast<std::uint32_t>(value[3]);
    }

    std::uint64_t u64(const byte_slice_t& slice, std::uint64_t offset, bool little, const char* phase) const {
        require_range(slice, offset, 8, phase);
        std::uint64_t value = 0;
        if (little) {
            for (std::uint32_t index = 0; index < 8; ++index)
                value |= static_cast<std::uint64_t>(slice.bytes[static_cast<std::size_t>(offset + index)]) <<
                         (index * 8U);
        } else {
            for (std::uint32_t index = 0; index < 8; ++index)
                value = (value << 8U) | slice.bytes[static_cast<std::size_t>(offset + index)];
        }
        return value;
    }

    std::int32_t i32(const byte_slice_t& slice, std::uint64_t offset, bool little, const char* phase) const {
        return static_cast<std::int32_t>(u32(slice, offset, little, phase));
    }

    std::string fixed_string(const byte_slice_t& slice, std::uint64_t offset, std::uint64_t size,
                             const char* phase) {
        require_range(slice, offset, size, phase);
        const auto* begin = slice.bytes + static_cast<std::size_t>(offset);
        const auto* end = begin + static_cast<std::size_t>(size);
        const auto* terminator = std::find(begin, end, static_cast<std::uint8_t>(0));
        return owned_string(begin, static_cast<std::size_t>(terminator - begin), phase);
    }

    std::string c_string(const byte_slice_t& slice, std::uint64_t offset, std::uint64_t limit,
                         const char* phase) {
        require_range(slice, offset, 0, phase);
        const auto available = slice.size - offset;
        const auto count = (std::min)(available, limit);
        const auto* begin = slice.bytes + static_cast<std::size_t>(offset);
        const auto* end = begin + static_cast<std::size_t>(count);
        const auto* terminator = std::find(begin, end, static_cast<std::uint8_t>(0));
        if (terminator == end)
            fail(workspace_error_code_t::malformed_image,
                 "Mach-O string is not terminated inside its declared range", phase, offset, count);
        return owned_string(begin, static_cast<std::size_t>(terminator - begin), phase);
    }

    std::uint64_t checked_add(std::uint64_t left, std::uint64_t right, const byte_slice_t& slice,
                              const char* phase) const {
        if (left > (std::numeric_limits<std::uint64_t>::max)() - right)
            fail(workspace_error_code_t::range_overflow, "Mach-O offset arithmetic overflowed", phase, left, right);
        const auto result = left + right;
        if (result > slice.size)
            fail(workspace_error_code_t::out_of_range, "Mach-O range exceeds its container member", phase,
                 left, right);
        return result;
    }

    std::uint64_t read_uleb(const byte_slice_t& slice, std::uint64_t& cursor,
                            std::uint64_t end, const char* phase) const {
        std::uint64_t value = 0;
        for (std::uint32_t index = 0; index < 10; ++index) {
            if (cursor >= end)
                fail(workspace_error_code_t::malformed_image, "Mach-O ULEB128 is truncated", phase, cursor, 1);
            const auto byte = u8(slice, cursor++, phase);
            const auto payload = static_cast<std::uint64_t>(byte & 0x7fU);
            if (index == 9U && (byte & 0x7eU) != 0U)
                fail(workspace_error_code_t::range_overflow, "Mach-O ULEB128 overflows 64 bits", phase,
                     cursor - 1U, 1);
            value |= payload << (index * 7U);
            if ((byte & 0x80U) == 0U)
                return value;
        }
        fail(workspace_error_code_t::malformed_image, "Mach-O ULEB128 is overlong", phase, cursor - 10U, 10);
    }

    std::int64_t read_sleb(const byte_slice_t& slice, std::uint64_t& cursor,
                           std::uint64_t end, const char* phase) const {
        std::uint64_t value = 0;
        std::uint8_t byte = 0;
        std::uint32_t shift = 0;
        for (std::uint32_t index = 0; index < 10; ++index) {
            if (cursor >= end)
                fail(workspace_error_code_t::malformed_image, "Mach-O SLEB128 is truncated", phase, cursor, 1);
            byte = u8(slice, cursor++, phase);
            if (index == 9U && (byte & 0x7eU) != 0U)
                fail(workspace_error_code_t::range_overflow, "Mach-O SLEB128 overflows 64 bits", phase,
                     cursor - 1U, 1);
            value |= static_cast<std::uint64_t>(byte & 0x7fU) << shift;
            shift += 7U;
            if ((byte & 0x80U) == 0U)
                break;
            if (index == 9U)
                fail(workspace_error_code_t::malformed_image, "Mach-O SLEB128 is overlong", phase,
                     cursor - 10U, 10);
        }
        if (shift < 64U && (byte & 0x40U) != 0U)
            value |= (~0ULL) << shift;
        return static_cast<std::int64_t>(value);
    }

    void parse_archive(const byte_slice_t& archive) {
        document_.thin_archive = has_prefix(archive, "!<thin>\n", 8U);
        std::uint64_t cursor = 8;
        byte_slice_t gnu_names{};
        while (cursor < archive.size) {
            poll(cursor, "macho.archive");
            require_range(archive, cursor, 60, "macho.archive");
            if (std::memcmp(archive.bytes + static_cast<std::size_t>(cursor + 58U), "`\n", 2) != 0)
                fail(workspace_error_code_t::malformed_image, "UNIX archive member trailer is invalid",
                     "macho.archive", cursor + 58U, 2);
            const auto raw_name = archive_name_field(archive, cursor);
            const auto raw_size = parse_decimal(archive, cursor + 48U, 10U, "macho.archive");
            const auto payload_offset = checked_add(cursor, 60U, archive, "macho.archive");
            const bool special_name_table = raw_name == "//";
            const bool special_symbol_table = raw_name == "/" || raw_name == "/SYM64/";
            const bool bsd_extended = raw_name.size() > 3U && raw_name[0] == '#' && raw_name[1] == '1' &&
                                      raw_name[2] == '/';
            std::uint64_t embedded_size = raw_size;
            bool embedded = !document_.thin_archive || special_name_table || special_symbol_table || bsd_extended;
            if (embedded)
                require_range(archive, payload_offset, raw_size, "macho.archive");
            else
                embedded_size = 0;
            std::string name;
            std::uint64_t content_offset = payload_offset;
            std::uint64_t content_size = embedded_size;
            if (bsd_extended) {
                const auto name_size = parse_decimal_text(raw_name.substr(3U), "macho.archive");
                if (name_size > raw_size)
                    fail(workspace_error_code_t::malformed_image, "BSD archive member name exceeds member data",
                         "macho.archive", cursor, raw_size);
                name = fixed_string(archive, payload_offset, name_size, "macho.archive");
                content_offset = checked_add(payload_offset, name_size, archive, "macho.archive");
                content_size = raw_size - name_size;
            } else if (raw_name.size() > 1U && raw_name[0] == '/' && raw_name[1] >= '0' && raw_name[1] <= '9') {
                name = gnu_archive_name(gnu_names, parse_decimal_text(raw_name.substr(1U), "macho.archive"));
            } else {
                name = raw_name;
                if (name.size() > 1U && name.back() == '/')
                    name.pop_back();
            }
            macho_archive_member_metadata_t member;
            member.ordinal = static_cast<std::uint32_t>(document_.archive_members.size());
            member.name = std::move(name);
            member.header_offset = cursor;
            member.data_offset = content_offset;
            member.data_size = content_size;
            member.embedded = embedded;
            const auto member_index = member.ordinal;
            append(document_.archive_members, std::move(member), limits_.max_archive_members, "macho.archive");
            if (special_name_table && embedded) {
                gnu_names = subrange(archive, payload_offset, raw_size, "macho.archive");
            } else if (!special_symbol_table && embedded && content_size >= 4U) {
                const auto content = subrange(archive, content_offset, content_size, "macho.archive");
                if (is_fat(content))
                    parse_fat(content, member_index);
                else if (is_thin_macho(content))
                    parse_thin(content, {}, member_index);
            }
            if (embedded) {
                const auto next = checked_add(payload_offset, raw_size, archive, "macho.archive");
                cursor = next + (raw_size & 1U);
                if (cursor > archive.size)
                    fail(workspace_error_code_t::out_of_range, "UNIX archive padding exceeds input", "macho.archive",
                         next, raw_size & 1U);
            } else {
                cursor = payload_offset;
            }
        }
    }

    std::uint64_t parse_decimal(const byte_slice_t& slice, std::uint64_t offset, std::uint64_t width,
                                const char* phase) const {
        require_range(slice, offset, width, phase);
        std::uint64_t value = 0;
        bool any = false;
        for (std::uint64_t index = 0; index < width; ++index) {
            const char ch = static_cast<char>(slice.bytes[static_cast<std::size_t>(offset + index)]);
            if (ch == ' ')
                continue;
            if (ch < '0' || ch > '9')
                fail(workspace_error_code_t::malformed_image, "UNIX archive decimal field is invalid", phase,
                     offset + index, 1);
            const auto digit = static_cast<std::uint64_t>(ch - '0');
            if (value > ((std::numeric_limits<std::uint64_t>::max)() - digit) / 10U)
                fail(workspace_error_code_t::range_overflow, "UNIX archive decimal field overflowed", phase,
                     offset, width);
            value = value * 10U + digit;
            any = true;
        }
        if (!any)
            fail(workspace_error_code_t::malformed_image, "UNIX archive decimal field is empty", phase, offset, width);
        return value;
    }

    std::string archive_name_field(const byte_slice_t& slice, std::uint64_t offset) {
        require_range(slice, offset, 16U, "macho.archive");
        const auto* begin = slice.bytes + static_cast<std::size_t>(offset);
        std::size_t length = 16U;
        while (length > 0U && begin[length - 1U] == static_cast<std::uint8_t>(' '))
            --length;
        return owned_string(begin, length, "macho.archive");
    }

    std::uint64_t parse_decimal_text(const std::string& text, const char* phase) const {
        if (text.empty())
            fail(workspace_error_code_t::malformed_image, "UNIX archive decimal field is empty", phase, 0, 0);
        std::uint64_t value = 0;
        for (const char ch : text) {
            if (ch < '0' || ch > '9')
                fail(workspace_error_code_t::malformed_image, "UNIX archive decimal field is invalid", phase, 0, 0);
            const auto digit = static_cast<std::uint64_t>(ch - '0');
            if (value > ((std::numeric_limits<std::uint64_t>::max)() - digit) / 10U)
                fail(workspace_error_code_t::range_overflow, "UNIX archive decimal field overflowed", phase, 0, 0);
            value = value * 10U + digit;
        }
        return value;
    }

    std::string gnu_archive_name(const byte_slice_t& table, std::uint64_t offset) {
        if (table.bytes == nullptr || offset >= table.size)
            fail(workspace_error_code_t::malformed_image, "GNU archive member name offset is invalid",
                 "macho.archive", offset, 1);
        const auto* begin = table.bytes + static_cast<std::size_t>(offset);
        const auto* end = table.bytes + static_cast<std::size_t>(table.size);
        const auto* terminator = std::find(begin, end, static_cast<std::uint8_t>('\n'));
        if (terminator == end)
            fail(workspace_error_code_t::malformed_image, "GNU archive member name is unterminated",
                 "macho.archive", offset, table.size - offset);
        std::size_t length = static_cast<std::size_t>(terminator - begin);
        if (length > 0U && begin[length - 1U] == '/')
            --length;
        return owned_string(begin, length, "macho.archive");
    }

    void parse_fat(const byte_slice_t& fat, std::optional<std::uint32_t> archive_member) {
        if (fat.size < 8U)
            fail(workspace_error_code_t::malformed_image, "Fat Mach-O header is truncated", "macho.fat", 0, fat.size);
        const bool little = has_prefix(fat, {0xbeU, 0xbaU, 0xfeU, 0xcaU}) ||
                            has_prefix(fat, {0xbfU, 0xbaU, 0xfeU, 0xcaU});
        const bool is_64 = has_prefix(fat, {0xcaU, 0xfeU, 0xbaU, 0xbfU}) ||
                           has_prefix(fat, {0xbfU, 0xbaU, 0xfeU, 0xcaU});
        const auto count = u32(fat, 4, little, "macho.fat");
        if (count == 0U || count > limits_.max_fat_slices)
            fail(workspace_error_code_t::limit_exceeded, "Fat Mach-O slice count exceeds its configured bound",
                 "macho.fat", 4, count);
        const std::uint64_t record_size = is_64 ? 32U : 20U;
        if (count > (fat.size - 8U) / record_size)
            fail(workspace_error_code_t::out_of_range, "Fat Mach-O architecture table is truncated",
                 "macho.fat", 8, static_cast<std::uint64_t>(count) * record_size);
        std::vector<std::pair<std::uint64_t, std::uint64_t>> ranges;
        ranges.reserve(count);
        for (std::uint32_t index = 0; index < count; ++index) {
            poll(index, "macho.fat");
            const auto offset = 8ULL + static_cast<std::uint64_t>(index) * record_size;
            const auto cpu_type = i32(fat, offset, little, "macho.fat");
            const auto cpu_subtype = i32(fat, offset + 4U, little, "macho.fat");
            const auto member_offset = is_64 ? u64(fat, offset + 8U, little, "macho.fat")
                                             : u32(fat, offset + 8U, little, "macho.fat");
            const auto member_size = is_64 ? u64(fat, offset + 16U, little, "macho.fat")
                                           : u32(fat, offset + 12U, little, "macho.fat");
            const auto alignment = u32(fat, offset + (is_64 ? 24U : 16U), little, "macho.fat");
            if (member_size == 0U || alignment >= 64U ||
                (member_offset & ((1ULL << alignment) - 1ULL)) != 0U)
                fail(workspace_error_code_t::malformed_image, "Fat Mach-O slice alignment or size is invalid",
                     "macho.fat", offset, record_size);
            require_range(fat, member_offset, member_size, "macho.fat");
            const auto member_end = member_offset + member_size;
            for (const auto& range : ranges) {
                if (member_offset < range.second && range.first < member_end)
                    fail(workspace_error_code_t::malformed_image, "Fat Mach-O slices overlap", "macho.fat",
                         member_offset, member_size);
            }
            ranges.emplace_back(member_offset, member_end);
            macho_slice_identity_t identity;
            identity.container_offset = fat.origin + member_offset;
            identity.size = member_size;
            identity.cpu_type = cpu_type;
            identity.cpu_subtype = cpu_subtype;
            identity.architecture = architecture_for_cpu(cpu_type);
            identity.endian = little ? endian_t::little : endian_t::big;
            identity.is_64_bit = (static_cast<std::uint32_t>(cpu_type) & 0x01000000U) != 0U;
            identity.archive_member_ordinal = archive_member;
            const auto member = subrange(fat, member_offset, member_size, "macho.fat");
            if (!is_thin_macho(member))
                fail(workspace_error_code_t::malformed_image, "Fat Mach-O slice is not a thin Mach-O image",
                     "macho.fat", member_offset, member_size);
            parse_thin(member, std::move(identity), archive_member);
        }
    }

    void parse_thin(const byte_slice_t& slice, macho_slice_identity_t identity,
                    std::optional<std::uint32_t> archive_member) {
        if (slice.size < 28U)
            fail(workspace_error_code_t::malformed_image, "Mach-O header is truncated", "macho.header", 0, slice.size);
        const bool little = has_prefix(slice, {0xceU, 0xfaU, 0xedU, 0xfeU}) ||
                            has_prefix(slice, {0xcfU, 0xfaU, 0xedU, 0xfeU});
        const bool is_64 = has_prefix(slice, {0xcfU, 0xfaU, 0xedU, 0xfeU}) ||
                           has_prefix(slice, {0xfeU, 0xedU, 0xfaU, 0xcfU});
        const auto header_size = is_64 ? 32ULL : 28ULL;
        require_range(slice, 0, header_size, "macho.header");
        const auto cpu_type = i32(slice, 4U, little, "macho.header");
        const auto cpu_subtype = i32(slice, 8U, little, "macho.header");
        if (identity.cpu_type != 0 && (identity.cpu_type != cpu_type || identity.cpu_subtype != cpu_subtype))
            fail(workspace_error_code_t::malformed_image,
                 "Fat Mach-O architecture record does not match the thin slice header", "macho.header", 4, 8);
        identity.container_offset = slice.origin;
        identity.size = slice.size;
        identity.cpu_type = cpu_type;
        identity.cpu_subtype = cpu_subtype;
        identity.architecture = architecture_for_cpu(cpu_type);
        identity.endian = little ? endian_t::little : endian_t::big;
        identity.is_64_bit = is_64;
        identity.archive_member_ordinal = archive_member;
        const auto file_type = u32(slice, 12U, little, "macho.header");
        const auto command_count = u32(slice, 16U, little, "macho.header");
        const auto command_bytes = u32(slice, 20U, little, "macho.header");
        if (command_count > limits_.max_load_commands)
            fail(workspace_error_code_t::limit_exceeded, "Mach-O load command count exceeds its configured bound",
                 "macho.header", 16, command_count);
        const auto commands_end = checked_add(header_size, command_bytes, slice, "macho.header");
        macho_slice_metadata_t image;
        image.identity = std::move(identity);
        image.file_type = file_type;
        image.file_kind = file_kind_for_type(file_type);
        image.flags = u32(slice, 24U, little, "macho.header");
        image.header_size = header_size;
        std::optional<symtab_ref_t> symtab;
        std::optional<dysymtab_ref_t> dysymtab;
        std::optional<dyld_info_ref_t> dyld_info;
        std::optional<blob_ref_t> exports;
        std::optional<blob_ref_t> code_signature;
        std::uint64_t cursor = header_size;
        for (std::uint32_t ordinal = 0; ordinal < command_count; ++ordinal) {
            poll(ordinal, "macho.load_commands");
            require_range(slice, cursor, 8U, "macho.load_commands");
            const auto command = u32(slice, cursor, little, "macho.load_commands");
            const auto size = u32(slice, cursor + 4U, little, "macho.load_commands");
            if (size < 8U || size > commands_end - cursor)
                fail(workspace_error_code_t::malformed_image, "Mach-O load command size is invalid",
                     "macho.load_commands", cursor, size);
            macho_load_command_metadata_t command_metadata;
            command_metadata.ordinal = ordinal;
            command_metadata.command = command;
            command_metadata.offset = cursor;
            command_metadata.size = size;
            command_metadata.kind = owned_string(command_kind(command), "macho.load_commands");
            append(image.load_commands, std::move(command_metadata), limits_.max_load_commands,
                   "macho.load_commands");
            const auto base_command = command & ~k_lc_req_dyld;
            if (base_command == k_lc_segment || base_command == k_lc_segment_64)
                parse_segment(slice, cursor, size, little, is_64, image);
            else if (base_command == k_lc_symtab)
                symtab = parse_symtab_command(slice, cursor, size, little);
            else if (base_command == k_lc_dysymtab)
                dysymtab = parse_dysymtab_command(slice, cursor, size, little);
            else if (is_dylib_command(base_command))
                parse_dylib_command(slice, cursor, size, little, image);
            else if (base_command == k_lc_dyld_info)
                dyld_info = parse_dyld_info_command(slice, cursor, size, little);
            else if (base_command == k_lc_dyld_exports_trie)
                exports = parse_linkedit_command(slice, cursor, size, little, "macho.exports");
            else if (base_command == k_lc_code_signature)
                code_signature = parse_linkedit_command(slice, cursor, size, little, "macho.codesign");
            cursor += size;
        }
        if (cursor != commands_end)
            fail(workspace_error_code_t::malformed_image, "Mach-O load command table size is inconsistent",
                 "macho.load_commands", cursor, commands_end - cursor);
        if (symtab)
            parse_symbols(slice, little, is_64, *symtab, image);
        parse_section_relocations(slice, little, image);
        if (dysymtab) {
            parse_relocation_table(slice, little, dysymtab->external_relocation_offset,
                                   dysymtab->external_relocation_count, std::nullopt, image, "macho.extrel");
            parse_relocation_table(slice, little, dysymtab->local_relocation_offset,
                                   dysymtab->local_relocation_count, std::nullopt, image, "macho.locrel");
        }
        if (dyld_info) {
            parse_rebase_stream(slice, *dyld_info, image);
            parse_bind_stream(slice, dyld_info->bind_offset, dyld_info->bind_size,
                              macho_bind_stream_kind_t::regular, image);
            parse_bind_stream(slice, dyld_info->weak_bind_offset, dyld_info->weak_bind_size,
                              macho_bind_stream_kind_t::weak, image);
            parse_bind_stream(slice, dyld_info->lazy_bind_offset, dyld_info->lazy_bind_size,
                              macho_bind_stream_kind_t::lazy, image);
            if (dyld_info->export_size != 0U)
                parse_export_trie(slice, {dyld_info->export_offset, dyld_info->export_size}, image);
        }
        if (exports && exports->size != 0U &&
            (!dyld_info || exports->offset != dyld_info->export_offset || exports->size != dyld_info->export_size))
            parse_export_trie(slice, *exports, image);
        if (code_signature)
            parse_code_signature(slice, *code_signature, image);
        parse_section_auxiliary_metadata(slice, little, image);
        if (archive_member && *archive_member < document_.archive_members.size())
            document_.archive_members[*archive_member].mach_metadata_available = true;
        append(document_.slices, std::move(image), static_cast<std::uint64_t>(limits_.max_fat_slices) *
                                                   limits_.max_archive_members,
               "macho.slice");
    }

    bool is_dylib_command(std::uint32_t command) const noexcept {
        return command == k_lc_load_dylib || command == k_lc_id_dylib ||
               command == k_lc_load_weak_dylib || command == k_lc_reexport_dylib ||
               command == k_lc_lazy_load_dylib || command == k_lc_load_upward_dylib;
    }

    void parse_segment(const byte_slice_t& slice, std::uint64_t offset, std::uint32_t command_size,
                       bool little, bool image_is_64, macho_slice_metadata_t& image) {
        const auto is_64 = (u32(slice, offset, little, "macho.segment") & ~k_lc_req_dyld) == k_lc_segment_64;
        if (is_64 != image_is_64)
            fail(workspace_error_code_t::malformed_image, "Mach-O segment command width mismatches image header",
                 "macho.segment", offset, command_size);
        const std::uint64_t header_size = is_64 ? 72U : 56U;
        const std::uint64_t section_size = is_64 ? 80U : 68U;
        if (command_size < header_size)
            fail(workspace_error_code_t::malformed_image, "Mach-O segment command is truncated",
                 "macho.segment", offset, command_size);
        const auto section_count = u32(slice, offset + (is_64 ? 64U : 48U), little, "macho.segment");
        if (section_count > limits_.max_sections || section_count > limits_.max_sections - section_count_ ||
            section_count > (command_size - header_size) / section_size)
            fail(workspace_error_code_t::limit_exceeded, "Mach-O section count exceeds its configured bound",
                 "macho.segment", offset, section_count);
        if (command_size != header_size + static_cast<std::uint64_t>(section_count) * section_size)
            fail(workspace_error_code_t::malformed_image, "Mach-O segment command has trailing or missing bytes",
                 "macho.segment", offset, command_size);
        if (image.segments.size() >= limits_.max_segments)
            fail(workspace_error_code_t::limit_exceeded, "Mach-O segment count exceeds its configured bound",
                 "macho.segment", offset, image.segments.size() + 1U);
        macho_segment_metadata_t segment;
        segment.index = static_cast<std::uint32_t>(image.segments.size());
        segment.name = fixed_string(slice, offset + 8U, 16U, "macho.segment");
        segment.virtual_address = is_64 ? u64(slice, offset + 24U, little, "macho.segment")
                                        : u32(slice, offset + 24U, little, "macho.segment");
        segment.virtual_size = is_64 ? u64(slice, offset + 32U, little, "macho.segment")
                                     : u32(slice, offset + 28U, little, "macho.segment");
        segment.file_offset = is_64 ? u64(slice, offset + 40U, little, "macho.segment")
                                    : u32(slice, offset + 32U, little, "macho.segment");
        segment.file_size = is_64 ? u64(slice, offset + 48U, little, "macho.segment")
                                  : u32(slice, offset + 36U, little, "macho.segment");
        segment.maximum_protection = i32(slice, offset + (is_64 ? 56U : 40U), little, "macho.segment");
        segment.initial_protection = i32(slice, offset + (is_64 ? 60U : 44U), little, "macho.segment");
        segment.flags = u32(slice, offset + (is_64 ? 68U : 52U), little, "macho.segment");
        if (segment.file_size != 0U)
            require_range(slice, segment.file_offset, segment.file_size, "macho.segment");
        for (std::uint32_t index = 0; index < section_count; ++index) {
            poll(index, "macho.sections");
            const auto section_offset = offset + header_size + static_cast<std::uint64_t>(index) * section_size;
            macho_section_metadata_t section;
            section.index = section_count_++;
            section.section_name = fixed_string(slice, section_offset, 16U, "macho.sections");
            section.segment_name = fixed_string(slice, section_offset + 16U, 16U, "macho.sections");
            section.address = is_64 ? u64(slice, section_offset + 32U, little, "macho.sections")
                                    : u32(slice, section_offset + 32U, little, "macho.sections");
            section.size = is_64 ? u64(slice, section_offset + 40U, little, "macho.sections")
                                 : u32(slice, section_offset + 36U, little, "macho.sections");
            section.file_offset = u32(slice, section_offset + (is_64 ? 48U : 40U), little, "macho.sections");
            section.alignment = u32(slice, section_offset + (is_64 ? 52U : 44U), little, "macho.sections");
            section.relocation_offset = u32(slice, section_offset + (is_64 ? 56U : 48U), little, "macho.sections");
            section.relocation_count = u32(slice, section_offset + (is_64 ? 60U : 52U), little, "macho.sections");
            section.flags = u32(slice, section_offset + (is_64 ? 64U : 56U), little, "macho.sections");
            section.reserved1 = u32(slice, section_offset + (is_64 ? 68U : 60U), little, "macho.sections");
            section.reserved2 = u32(slice, section_offset + (is_64 ? 72U : 64U), little, "macho.sections");
            section.reserved3 = is_64 ? u32(slice, section_offset + 76U, little, "macho.sections") : 0U;
            const auto section_type = section.flags & 0xffU;
            if (section.size != 0U && section_type != 0x1U && section_type != 0xcU && section_type != 0x12U)
                require_range(slice, section.file_offset, section.size, "macho.sections");
            if (section.relocation_count != 0U) {
                require_range(slice, section.relocation_offset, 0, "macho.sections");
                if (section.relocation_count > limits_.max_relocations ||
                    section.relocation_count > (slice.size - section.relocation_offset) / 8U)
                    fail(workspace_error_code_t::limit_exceeded,
                         "Mach-O section relocation count exceeds its configured bound", "macho.sections",
                         section.relocation_offset, section.relocation_count);
            }
            append(segment.sections, std::move(section), limits_.max_sections, "macho.sections");
        }
        append(image.segments, std::move(segment), limits_.max_segments, "macho.segment");
    }

    symtab_ref_t parse_symtab_command(const byte_slice_t& slice, std::uint64_t offset,
                                      std::uint32_t size, bool little) const {
        if (size != 24U)
            fail(workspace_error_code_t::malformed_image, "Mach-O symtab command size is invalid",
                 "macho.symtab", offset, size);
        return {u32(slice, offset + 8U, little, "macho.symtab"),
                u32(slice, offset + 12U, little, "macho.symtab"),
                u32(slice, offset + 16U, little, "macho.symtab"),
                u32(slice, offset + 20U, little, "macho.symtab")};
    }

    dysymtab_ref_t parse_dysymtab_command(const byte_slice_t& slice, std::uint64_t offset,
                                          std::uint32_t size, bool little) const {
        if (size != 80U)
            fail(workspace_error_code_t::malformed_image, "Mach-O dysymtab command size is invalid",
                 "macho.dysymtab", offset, size);
        return {u32(slice, offset + 64U, little, "macho.dysymtab"),
                u32(slice, offset + 68U, little, "macho.dysymtab"),
                u32(slice, offset + 72U, little, "macho.dysymtab"),
                u32(slice, offset + 76U, little, "macho.dysymtab")};
    }

    dyld_info_ref_t parse_dyld_info_command(const byte_slice_t& slice, std::uint64_t offset,
                                            std::uint32_t size, bool little) const {
        if (size != 48U)
            fail(workspace_error_code_t::malformed_image, "Mach-O dyld info command size is invalid",
                 "macho.dyld", offset, size);
        return {u32(slice, offset + 8U, little, "macho.dyld"),
                u32(slice, offset + 12U, little, "macho.dyld"),
                u32(slice, offset + 16U, little, "macho.dyld"),
                u32(slice, offset + 20U, little, "macho.dyld"),
                u32(slice, offset + 24U, little, "macho.dyld"),
                u32(slice, offset + 28U, little, "macho.dyld"),
                u32(slice, offset + 32U, little, "macho.dyld"),
                u32(slice, offset + 36U, little, "macho.dyld"),
                u32(slice, offset + 40U, little, "macho.dyld"),
                u32(slice, offset + 44U, little, "macho.dyld")};
    }

    blob_ref_t parse_linkedit_command(const byte_slice_t& slice, std::uint64_t offset,
                                      std::uint32_t size, bool little, const char* phase) const {
        if (size != 16U)
            fail(workspace_error_code_t::malformed_image, "Mach-O linkedit command size is invalid", phase,
                 offset, size);
        const auto data_offset = static_cast<std::uint64_t>(u32(slice, offset + 8U, little, phase));
        const auto data_size = u32(slice, offset + 12U, little, phase);
        if (data_size > limits_.max_linkedit_bytes)
            fail(workspace_error_code_t::limit_exceeded, "Mach-O linkedit blob exceeds its configured bound",
                 phase, data_offset, data_size);
        require_range(slice, data_offset, data_size, phase);
        return {data_offset, data_size, offset};
    }

    void parse_dylib_command(const byte_slice_t& slice, std::uint64_t offset, std::uint32_t size,
                             bool little, macho_slice_metadata_t& image) {
        if (size < 24U)
            fail(workspace_error_code_t::malformed_image, "Mach-O dylib command is truncated",
                 "macho.dylib", offset, size);
        const auto name_offset = u32(slice, offset + 8U, little, "macho.dylib");
        if (name_offset < 24U || name_offset >= size)
            fail(workspace_error_code_t::malformed_image, "Mach-O dylib path offset is invalid",
                 "macho.dylib", offset + 8U, name_offset);
        macho_dylib_metadata_t dylib;
        dylib.command = u32(slice, offset, little, "macho.dylib");
        dylib.path = c_string(slice, offset + name_offset, size - name_offset, "macho.dylib");
        dylib.timestamp = u32(slice, offset + 12U, little, "macho.dylib");
        dylib.current_version = u32(slice, offset + 16U, little, "macho.dylib");
        dylib.compatibility_version = u32(slice, offset + 20U, little, "macho.dylib");
        append(image.dylibs, std::move(dylib), limits_.max_dylibs, "macho.dylib");
    }

    void parse_symbols(const byte_slice_t& slice, bool little, bool is_64, const symtab_ref_t& symtab,
                       macho_slice_metadata_t& image) {
        const auto entry_size = is_64 ? 16ULL : 12ULL;
        require_range(slice, symtab.symbol_offset, 0, "macho.symbols");
        if (symtab.symbol_count > limits_.max_symbols ||
            symtab.symbol_count > (slice.size - symtab.symbol_offset) / entry_size)
            fail(workspace_error_code_t::limit_exceeded, "Mach-O symbol count exceeds its configured bound",
                 "macho.symbols", symtab.symbol_offset, symtab.symbol_count);
        require_range(slice, symtab.string_offset, symtab.string_size, "macho.symbols");
        for (std::uint32_t index = 0; index < symtab.symbol_count; ++index) {
            poll(index, "macho.symbols");
            const auto offset = symtab.symbol_offset + static_cast<std::uint64_t>(index) * entry_size;
            const auto string_index = u32(slice, offset, little, "macho.symbols");
            if (string_index >= symtab.string_size && string_index != 0U)
                fail(workspace_error_code_t::malformed_image, "Mach-O symbol string index is invalid",
                     "macho.symbols", offset, 4);
            macho_symbol_metadata_t symbol;
            symbol.index = index;
            symbol.name = string_index == 0U ? owned_string("", "macho.symbols") :
                c_string(slice, symtab.string_offset + string_index, symtab.string_size - string_index,
                         "macho.symbols");
            symbol.type = u8(slice, offset + 4U, "macho.symbols");
            symbol.section = u8(slice, offset + 5U, "macho.symbols");
            symbol.descriptor = u16(slice, offset + 6U, little, "macho.symbols");
            symbol.value = is_64 ? u64(slice, offset + 8U, little, "macho.symbols")
                                 : u32(slice, offset + 8U, little, "macho.symbols");
            append(image.symbols, std::move(symbol), limits_.max_symbols, "macho.symbols");
        }
    }

    void parse_section_relocations(const byte_slice_t& slice, bool little, macho_slice_metadata_t& image) {
        for (const auto& segment : image.segments) {
            for (const auto& section : segment.sections) {
                if (section.relocation_count != 0U)
                    parse_relocation_table(slice, little, section.relocation_offset, section.relocation_count,
                                           section.index, image, "macho.section_reloc");
            }
        }
    }

    void parse_relocation_table(const byte_slice_t& slice, bool little, std::uint64_t offset,
                                std::uint32_t count, std::optional<std::uint32_t> section,
                                macho_slice_metadata_t& image, const char* phase) {
        if (count == 0U)
            return;
        require_range(slice, offset, 0, phase);
        if (count > limits_.max_relocations || count > limits_.max_relocations - image.relocations.size() ||
            count > (slice.size - offset) / 8U)
            fail(workspace_error_code_t::limit_exceeded, "Mach-O relocation count exceeds its configured bound",
                 phase, offset, count);
        for (std::uint32_t index = 0; index < count; ++index) {
            poll(index, phase);
            const auto entry = offset + static_cast<std::uint64_t>(index) * 8U;
            const auto word0 = u32(slice, entry, little, phase);
            const auto word1 = u32(slice, entry + 4U, little, phase);
            macho_relocation_metadata_t relocation;
            relocation.section_index = section;
            relocation.scattered = (word0 & 0x80000000U) != 0U;
            if (relocation.scattered) {
                relocation.address = word0 & 0x00ffffffU;
                relocation.type = static_cast<std::uint8_t>((word0 >> 24U) & 0x0fU);
                relocation.length = static_cast<std::uint8_t>((word0 >> 28U) & 0x03U);
                relocation.pc_relative = (word0 & 0x40000000U) != 0U;
                relocation.target_value = word1;
            } else {
                relocation.address = static_cast<std::uint64_t>(static_cast<std::int64_t>(
                    static_cast<std::int32_t>(word0)));
                relocation.symbol_number = word1 & 0x00ffffffU;
                relocation.pc_relative = (word1 & 0x01000000U) != 0U;
                relocation.length = static_cast<std::uint8_t>((word1 >> 25U) & 0x03U);
                relocation.external = (word1 & 0x08000000U) != 0U;
                relocation.type = static_cast<std::uint8_t>((word1 >> 28U) & 0x0fU);
            }
            append(image.relocations, std::move(relocation), limits_.max_relocations, phase);
        }
    }

    void parse_rebase_stream(const byte_slice_t& slice, const dyld_info_ref_t& info,
                             macho_slice_metadata_t& image) {
        if (info.rebase_size == 0U)
            return;
        if (info.rebase_size > limits_.max_linkedit_bytes)
            fail(workspace_error_code_t::limit_exceeded, "Mach-O rebase stream exceeds its configured bound",
                 "macho.rebase", info.rebase_offset, info.rebase_size);
        require_range(slice, info.rebase_offset, info.rebase_size, "macho.rebase");
        const auto end = info.rebase_offset + info.rebase_size;
        std::uint64_t cursor = info.rebase_offset;
        std::uint32_t segment_index = 0;
        std::uint64_t segment_offset = 0;
        std::uint8_t type = 0;
        const auto pointer_size = image.identity.is_64_bit ? 8ULL : 4ULL;
        while (cursor < end) {
            poll(cursor - info.rebase_offset, "macho.rebase");
            const auto opcode = u8(slice, cursor++, "macho.rebase");
            const auto immediate = opcode & 0x0fU;
            switch (opcode & 0xf0U) {
                case 0x00U:
                    if (immediate != 0U)
                        fail(workspace_error_code_t::malformed_image, "Mach-O rebase done opcode is invalid",
                             "macho.rebase", cursor - 1U, 1);
                    return;
                case 0x10U:
                    type = immediate;
                    break;
                case 0x20U:
                    segment_index = immediate;
                    segment_offset = read_uleb(slice, cursor, end, "macho.rebase");
                    break;
                case 0x30U:
                    segment_offset = checked_stream_add(segment_offset,
                        read_uleb(slice, cursor, end, "macho.rebase"), "macho.rebase", cursor);
                    break;
                case 0x40U:
                    segment_offset = checked_stream_add(segment_offset,
                        static_cast<std::uint64_t>(immediate) * pointer_size, "macho.rebase", cursor);
                    break;
                case 0x50U:
                    for (std::uint8_t index = 0; index < immediate; ++index) {
                        append_rebase(segment_index, segment_offset, type, image, "macho.rebase");
                        segment_offset = checked_stream_add(segment_offset, pointer_size, "macho.rebase", cursor);
                    }
                    break;
                case 0x60U: {
                    const auto count = read_uleb(slice, cursor, end, "macho.rebase");
                    for (std::uint64_t index = 0; index < count; ++index) {
                        append_rebase(segment_index, segment_offset, type, image, "macho.rebase");
                        segment_offset = checked_stream_add(segment_offset, pointer_size, "macho.rebase", cursor);
                    }
                    break;
                }
                case 0x70U:
                    append_rebase(segment_index, segment_offset, type, image, "macho.rebase");
                    segment_offset = checked_stream_add(segment_offset,
                        pointer_size + read_uleb(slice, cursor, end, "macho.rebase"), "macho.rebase", cursor);
                    break;
                case 0x80U: {
                    const auto count = read_uleb(slice, cursor, end, "macho.rebase");
                    const auto skip = read_uleb(slice, cursor, end, "macho.rebase");
                    for (std::uint64_t index = 0; index < count; ++index) {
                        append_rebase(segment_index, segment_offset, type, image, "macho.rebase");
                        segment_offset = checked_stream_add(segment_offset, pointer_size + skip,
                                                            "macho.rebase", cursor);
                    }
                    break;
                }
                default:
                    fail(workspace_error_code_t::malformed_image, "Mach-O rebase opcode is unsupported",
                         "macho.rebase", cursor - 1U, 1);
            }
        }
        fail(workspace_error_code_t::malformed_image, "Mach-O rebase stream has no terminator",
             "macho.rebase", info.rebase_offset, info.rebase_size);
    }

    std::uint64_t checked_stream_add(std::uint64_t left, std::uint64_t right, const char* phase,
                                     std::uint64_t offset) const {
        if (left > (std::numeric_limits<std::uint64_t>::max)() - right)
            fail(workspace_error_code_t::range_overflow, "Mach-O stream address arithmetic overflowed",
                 phase, offset, right);
        return left + right;
    }

    void append_rebase(std::uint32_t segment_index, std::uint64_t segment_offset, std::uint8_t type,
                       macho_slice_metadata_t& image, const char* phase) {
        if (segment_index >= image.segments.size())
            fail(workspace_error_code_t::malformed_image, "Mach-O rebase segment index is invalid",
                 phase, segment_index, 1);
        const auto& segment = image.segments[segment_index];
        if (segment_offset >= segment.virtual_size ||
            segment.virtual_address > (std::numeric_limits<std::uint64_t>::max)() - segment_offset)
            fail(workspace_error_code_t::out_of_range, "Mach-O rebase address is outside its segment",
                 phase, segment_offset, 1);
        macho_rebase_metadata_t rebase;
        rebase.segment_index = segment_index;
        rebase.address = segment.virtual_address + segment_offset;
        rebase.type = type;
        append(image.rebases, std::move(rebase), limits_.max_rebases, phase);
    }

    void parse_bind_stream(const byte_slice_t& slice, std::uint64_t offset, std::uint32_t size,
                           macho_bind_stream_kind_t stream, macho_slice_metadata_t& image) {
        if (size == 0U)
            return;
        if (size > limits_.max_linkedit_bytes)
            fail(workspace_error_code_t::limit_exceeded, "Mach-O bind stream exceeds its configured bound",
                 "macho.bind", offset, size);
        require_range(slice, offset, size, "macho.bind");
        const auto end = offset + size;
        std::uint64_t cursor = offset;
        std::uint32_t segment_index = 0;
        std::uint64_t segment_offset = 0;
        std::int64_t library_ordinal = 0;
        std::string symbol = owned_string("", "macho.bind");
        std::int64_t addend = 0;
        std::uint8_t type = 0;
        std::uint8_t flags = 0;
        const auto pointer_size = image.identity.is_64_bit ? 8ULL : 4ULL;
        while (cursor < end) {
            poll(cursor - offset, "macho.bind");
            const auto opcode = u8(slice, cursor++, "macho.bind");
            const auto immediate = opcode & 0x0fU;
            switch (opcode & 0xf0U) {
                case 0x00U:
                    if (immediate != 0U)
                        fail(workspace_error_code_t::malformed_image, "Mach-O bind done opcode is invalid",
                             "macho.bind", cursor - 1U, 1);
                    if (stream != macho_bind_stream_kind_t::lazy)
                        return;
                    break;
                case 0x10U:
                    library_ordinal = immediate;
                    break;
                case 0x20U:
                    library_ordinal = static_cast<std::int64_t>(read_uleb(slice, cursor, end, "macho.bind"));
                    break;
                case 0x30U:
                    library_ordinal = immediate == 0U ? 0 : static_cast<std::int8_t>(immediate | 0xf0U);
                    break;
                case 0x40U:
                    flags = immediate;
                    symbol = c_string(slice, cursor, end - cursor, "macho.bind");
                    cursor += symbol.size() + 1U;
                    break;
                case 0x50U:
                    type = immediate;
                    break;
                case 0x60U:
                    addend = read_sleb(slice, cursor, end, "macho.bind");
                    break;
                case 0x70U:
                    segment_index = immediate;
                    segment_offset = read_uleb(slice, cursor, end, "macho.bind");
                    break;
                case 0x80U:
                    segment_offset = checked_stream_add(segment_offset,
                        read_uleb(slice, cursor, end, "macho.bind"), "macho.bind", cursor);
                    break;
                case 0x90U:
                    append_bind(stream, segment_index, segment_offset, type, library_ordinal, symbol, addend,
                                flags, image, "macho.bind");
                    segment_offset = checked_stream_add(segment_offset, pointer_size, "macho.bind", cursor);
                    break;
                case 0xa0U:
                    append_bind(stream, segment_index, segment_offset, type, library_ordinal, symbol, addend,
                                flags, image, "macho.bind");
                    segment_offset = checked_stream_add(segment_offset,
                        pointer_size + read_uleb(slice, cursor, end, "macho.bind"), "macho.bind", cursor);
                    break;
                case 0xb0U:
                    append_bind(stream, segment_index, segment_offset, type, library_ordinal, symbol, addend,
                                flags, image, "macho.bind");
                    segment_offset = checked_stream_add(segment_offset,
                        pointer_size + static_cast<std::uint64_t>(immediate) * pointer_size,
                        "macho.bind", cursor);
                    break;
                case 0xc0U: {
                    const auto count = read_uleb(slice, cursor, end, "macho.bind");
                    const auto skip = read_uleb(slice, cursor, end, "macho.bind");
                    for (std::uint64_t index = 0; index < count; ++index) {
                        append_bind(stream, segment_index, segment_offset, type, library_ordinal, symbol, addend,
                                    flags, image, "macho.bind");
                        segment_offset = checked_stream_add(segment_offset, pointer_size + skip,
                                                            "macho.bind", cursor);
                    }
                    break;
                }
                case 0xd0U:
                    if (immediate == 0U) {
                        const auto count = read_uleb(slice, cursor, end, "macho.bind");
                        if (count > limits_.max_binds)
                            fail(workspace_error_code_t::limit_exceeded,
                                 "Mach-O threaded bind ordinal table exceeds its configured bound",
                                 "macho.bind", cursor, count);
                    } else if (immediate != 1U) {
                        fail(workspace_error_code_t::malformed_image, "Mach-O threaded bind opcode is invalid",
                             "macho.bind", cursor - 1U, 1);
                    }
                    break;
                default:
                    fail(workspace_error_code_t::malformed_image, "Mach-O bind opcode is unsupported",
                         "macho.bind", cursor - 1U, 1);
            }
        }
    }

    void append_bind(macho_bind_stream_kind_t stream, std::uint32_t segment_index,
                     std::uint64_t segment_offset, std::uint8_t type, std::int64_t library_ordinal,
                     const std::string& symbol, std::int64_t addend, std::uint8_t flags,
                     macho_slice_metadata_t& image, const char* phase) {
        if (segment_index >= image.segments.size())
            fail(workspace_error_code_t::malformed_image, "Mach-O bind segment index is invalid",
                 phase, segment_index, 1);
        const auto& segment = image.segments[segment_index];
        if (segment_offset >= segment.virtual_size ||
            segment.virtual_address > (std::numeric_limits<std::uint64_t>::max)() - segment_offset)
            fail(workspace_error_code_t::out_of_range, "Mach-O bind address is outside its segment",
                 phase, segment_offset, 1);
        macho_binding_metadata_t binding;
        binding.stream = stream;
        binding.segment_index = segment_index;
        binding.address = segment.virtual_address + segment_offset;
        binding.type = type;
        binding.library_ordinal = library_ordinal;
        binding.symbol = owned_string(reinterpret_cast<const std::uint8_t*>(symbol.data()), symbol.size(), phase);
        binding.addend = addend;
        binding.flags = flags;
        append(image.bindings, std::move(binding), limits_.max_binds, phase);
    }

    void parse_export_trie(const byte_slice_t& slice, const blob_ref_t& blob, macho_slice_metadata_t& image) {
        if (blob.size > limits_.max_linkedit_bytes)
            fail(workspace_error_code_t::limit_exceeded, "Mach-O export trie exceeds its configured bound",
                 "macho.exports", blob.offset, blob.size);
        require_range(slice, blob.offset, blob.size, "macho.exports");
        if (blob.size == 0U)
            return;
        std::vector<std::uint64_t> path;
        std::uint64_t nodes = 0;
        std::function<void(std::uint64_t, const std::string&, std::uint32_t)> visit;
        visit = [&](std::uint64_t node_offset, const std::string& prefix, std::uint32_t depth) {
            poll(nodes, "macho.exports");
            if (depth > limits_.max_export_depth || node_offset >= blob.size)
                fail(workspace_error_code_t::malformed_image, "Mach-O export trie node is invalid",
                     "macho.exports", blob.offset + node_offset, 1);
            if (nodes++ >= limits_.max_exports)
                fail(workspace_error_code_t::limit_exceeded, "Mach-O export trie node count exceeds its configured bound",
                     "macho.exports", blob.offset + node_offset, 1);
            if (std::find(path.begin(), path.end(), node_offset) != path.end())
                fail(workspace_error_code_t::malformed_image, "Mach-O export trie contains a cycle",
                     "macho.exports", blob.offset + node_offset, 1);
            path.push_back(node_offset);
            std::uint64_t cursor = blob.offset + node_offset;
            const auto end = blob.offset + blob.size;
            const auto terminal_size = read_uleb(slice, cursor, end, "macho.exports");
            if (terminal_size > end - cursor)
                fail(workspace_error_code_t::malformed_image, "Mach-O export trie terminal is truncated",
                     "macho.exports", cursor, terminal_size);
            const auto terminal_end = cursor + terminal_size;
            if (terminal_size != 0U) {
                const auto flags = read_uleb(slice, cursor, terminal_end, "macho.exports");
                macho_export_metadata_t entry;
                entry.name = owned_string(reinterpret_cast<const std::uint8_t*>(prefix.data()), prefix.size(),
                                          "macho.exports");
                entry.flags = flags;
                if ((flags & k_export_reexport) != 0U) {
                    entry.other = read_uleb(slice, cursor, terminal_end, "macho.exports");
                    entry.import_name = c_string(slice, cursor, terminal_end - cursor, "macho.exports");
                    cursor += entry.import_name->size() + 1U;
                } else {
                    entry.address = read_uleb(slice, cursor, terminal_end, "macho.exports");
                    if ((flags & k_export_stub_and_resolver) != 0U)
                        entry.other = read_uleb(slice, cursor, terminal_end, "macho.exports");
                }
                if (cursor != terminal_end)
                    fail(workspace_error_code_t::malformed_image, "Mach-O export trie terminal has trailing bytes",
                         "macho.exports", cursor, terminal_end - cursor);
                append(image.exports, std::move(entry), limits_.max_exports, "macho.exports");
            }
            cursor = terminal_end;
            if (cursor >= end)
                fail(workspace_error_code_t::malformed_image, "Mach-O export trie child count is truncated",
                     "macho.exports", cursor, 1);
            const auto child_count = u8(slice, cursor++, "macho.exports");
            for (std::uint8_t index = 0; index < child_count; ++index) {
                const auto* edge_begin = slice.bytes + static_cast<std::size_t>(cursor);
                const auto* edge_end = slice.bytes + static_cast<std::size_t>(end);
                const auto* edge_terminator = std::find(edge_begin, edge_end, static_cast<std::uint8_t>(0));
                if (edge_terminator == edge_end)
                    fail(workspace_error_code_t::malformed_image, "Mach-O export trie edge is unterminated",
                         "macho.exports", cursor, end - cursor);
                const auto edge_size = static_cast<std::size_t>(edge_terminator - edge_begin);
                if (prefix.size() > limits_.max_string_bytes - edge_size)
                    fail(workspace_error_code_t::limit_exceeded, "Mach-O export name exceeds its configured bound",
                         "macho.exports", cursor, edge_size);
                std::string child_prefix = prefix;
                child_prefix.append(reinterpret_cast<const char*>(edge_begin), edge_size);
                cursor += edge_size + 1U;
                const auto child_offset = read_uleb(slice, cursor, end, "macho.exports");
                visit(child_offset, child_prefix, depth + 1U);
            }
            path.pop_back();
        };
        visit(0U, {}, 0U);
    }

    void parse_code_signature(const byte_slice_t& slice, const blob_ref_t& blob,
                              macho_slice_metadata_t& image) {
        auto& signature = image.code_signature;
        signature.present = true;
        signature.command_offset = blob.command_offset;
        signature.data_offset = blob.offset;
        signature.data_size = blob.size;
        if (blob.size < 8U)
            fail(workspace_error_code_t::malformed_image, "Mach-O code signature blob is truncated",
                 "macho.codesign", blob.offset, blob.size);
        signature.superblob_magic = u32(slice, blob.offset, false, "macho.codesign");
        signature.superblob_length = u32(slice, blob.offset + 4U, false, "macho.codesign");
        if (signature.superblob_length < 8U || signature.superblob_length > blob.size)
            fail(workspace_error_code_t::malformed_image, "Mach-O code signature length is invalid",
                 "macho.codesign", blob.offset + 4U, 4);
        signature.parsed = true;
        if (signature.superblob_magic != k_cs_superblob)
            return;
        if (signature.superblob_length < 12U)
            fail(workspace_error_code_t::malformed_image, "Mach-O code signature superblob is truncated",
                 "macho.codesign", blob.offset, signature.superblob_length);
        const auto count = u32(slice, blob.offset + 8U, false, "macho.codesign");
        if (count > limits_.max_code_signature_slots ||
            count > (signature.superblob_length - 12U) / 8U)
            fail(workspace_error_code_t::limit_exceeded,
                 "Mach-O code signature slot count exceeds its configured bound", "macho.codesign",
                 blob.offset + 8U, count);
        for (std::uint32_t index = 0; index < count; ++index) {
            poll(index, "macho.codesign");
            const auto entry = blob.offset + 12U + static_cast<std::uint64_t>(index) * 8U;
            const auto type = u32(slice, entry, false, "macho.codesign");
            const auto member_offset = u32(slice, entry + 4U, false, "macho.codesign");
            if (member_offset > signature.superblob_length - 8U)
                fail(workspace_error_code_t::malformed_image, "Mach-O code signature slot offset is invalid",
                     "macho.codesign", entry + 4U, 4);
            const auto member = blob.offset + member_offset;
            const auto magic = u32(slice, member, false, "macho.codesign");
            const auto length = u32(slice, member + 4U, false, "macho.codesign");
            if (length < 8U || length > signature.superblob_length - member_offset)
                fail(workspace_error_code_t::malformed_image, "Mach-O code signature slot length is invalid",
                     "macho.codesign", member + 4U, 4);
            macho_code_signature_slot_t slot;
            slot.type = type;
            slot.offset = member_offset;
            slot.magic = magic;
            slot.length = length;
            append(signature.slots, std::move(slot), limits_.max_code_signature_slots, "macho.codesign");
        }
    }

    void parse_section_auxiliary_metadata(const byte_slice_t& slice, bool little,
                                          macho_slice_metadata_t& image) {
        for (const auto& segment : image.segments) {
            for (const auto& section : segment.sections) {
                if (section.section_name == "__compact_unwind")
                    append_compact_unwind(slice, little, section, image);
                if (section.section_name == "__eh_frame" || section.section_name == "__gcc_except_tab" ||
                    section.section_name == "__objc_ehtypes")
                    append_exception(section.section_name, section.file_offset, section.size, image);
                if (section.section_name.rfind("__objc_", 0U) == 0U)
                    append_seed("objc", section, image);
                if (section.section_name.rfind("__swift", 0U) == 0U)
                    append_seed("swift", section, image);
            }
        }
    }

    void append_compact_unwind(const byte_slice_t& slice, bool little,
                               const macho_section_metadata_t& section, macho_slice_metadata_t& image) {
        const auto entry_size = image.identity.is_64_bit ? 32ULL : 20ULL;
        if (section.size % entry_size != 0U)
            fail(workspace_error_code_t::malformed_image, "Mach-O compact unwind section has an invalid size",
                 "macho.unwind", section.file_offset, section.size);
        const auto count = section.size / entry_size;
        if (count > limits_.max_unwind_records || count > limits_.max_unwind_records - image.unwind.size())
            fail(workspace_error_code_t::limit_exceeded, "Mach-O unwind record count exceeds its configured bound",
                 "macho.unwind", section.file_offset, count);
        for (std::uint64_t index = 0; index < count; ++index) {
            macho_unwind_metadata_t record;
            record.kind = owned_string("compact_unwind", "macho.unwind");
            record.file_offset = section.file_offset + index * entry_size;
            record.size = entry_size;
            record.function_address = image.identity.is_64_bit
                ? u64(slice, record.file_offset, little, "macho.unwind")
                : u32(slice, record.file_offset, little, "macho.unwind");
            append(image.unwind, std::move(record), limits_.max_unwind_records, "macho.unwind");
        }
    }

    void append_exception(const std::string& kind, std::uint64_t offset, std::uint64_t size,
                          macho_slice_metadata_t& image) {
        macho_exception_metadata_t exception;
        exception.kind = owned_string(reinterpret_cast<const std::uint8_t*>(kind.data()), kind.size(),
                                      "macho.exception");
        exception.file_offset = offset;
        exception.size = size;
        append(image.exceptions, std::move(exception), limits_.max_unwind_records, "macho.exception");
    }

    void append_seed(const char* kind, const macho_section_metadata_t& section,
                     macho_slice_metadata_t& image) {
        macho_metadata_seed_t seed;
        seed.kind = owned_string(kind, "macho.metadata");
        seed.segment_name = owned_string(reinterpret_cast<const std::uint8_t*>(section.segment_name.data()),
                                         section.segment_name.size(), "macho.metadata");
        seed.section_name = owned_string(reinterpret_cast<const std::uint8_t*>(section.section_name.data()),
                                         section.section_name.size(), "macho.metadata");
        seed.address = section.address;
        seed.file_offset = section.file_offset;
        seed.size = section.size;
        append(image.metadata_seeds, std::move(seed), limits_.max_metadata_seeds, "macho.metadata");
    }
};

workspace_result_t<macho_metadata_document_t> read_bytes(const std::vector<std::uint8_t>& bytes,
                                                          const macho_reader_limits_t& limits,
                                                          const cancellation_token_t& cancel) {
    try {
        macho_reader_t reader({bytes.data(), static_cast<std::uint64_t>(bytes.size()), 0}, limits, cancel);
        return workspace_result_t<macho_metadata_document_t>::success(reader.read());
    } catch (const parse_exception_t& error) {
        return workspace_result_t<macho_metadata_document_t>::failure(error.error());
    } catch (const std::bad_alloc&) {
        return workspace_result_t<macho_metadata_document_t>::failure(make_workspace_error(
            workspace_error_code_t::limit_exceeded, "Mach-O metadata allocation failed", "macho.profile"));
    } catch (const std::length_error&) {
        return workspace_result_t<macho_metadata_document_t>::failure(make_workspace_error(
            workspace_error_code_t::limit_exceeded, "Mach-O metadata allocation length is unsupported",
            "macho.profile"));
    }
}

}

workspace_result_t<macho_metadata_document_t> read_macho_metadata(
    const std::vector<std::uint8_t>& bytes, const macho_reader_limits_t& limits,
    const cancellation_token_t& cancel) {
    return read_bytes(bytes, limits, cancel);
}

workspace_result_t<macho_metadata_document_t> read_macho_metadata(
    const byte_provider_t& provider, const macho_reader_limits_t& limits,
    const cancellation_token_t& cancel) {
    if (provider.size() > limits.max_input_bytes) {
        workspace_error_t error = make_workspace_error(
            workspace_error_code_t::limit_exceeded, "Mach-O provider exceeds its configured input bound",
            "macho.profile");
        error.size = provider.size();
        return workspace_result_t<macho_metadata_document_t>::failure(std::move(error));
    }
    auto bytes = provider.read_vector(0, provider.size(), limits.max_input_bytes, cancel);
    if (!bytes)
        return workspace_result_t<macho_metadata_document_t>::failure(bytes.error());
    return read_bytes(bytes.value(), limits, cancel);
}

}
