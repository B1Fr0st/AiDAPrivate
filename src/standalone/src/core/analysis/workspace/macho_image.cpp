#include "macho_image.hpp"

#include "checked_range.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iterator>
#include <limits>
#include <map>
#include <memory>
#include <new>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <tuple>
#include <unordered_set>
#include <utility>
#include <vector>

#include <zlib.h>

namespace aida::analysis {
namespace {

constexpr std::uint32_t macho_magic_32 = 0xFEEDFACEU;
constexpr std::uint32_t macho_cigam_32 = 0xCEFAEDFEU;
constexpr std::uint32_t macho_magic_64 = 0xFEEDFACFU;
constexpr std::uint32_t macho_cigam_64 = 0xCFFAEDFEU;
constexpr std::uint32_t fat_magic = 0xCAFEBABEU;
constexpr std::uint32_t fat_cigam = 0xBEBAFECAU;
constexpr std::uint32_t fat_magic_64 = 0xCAFEBABFU;
constexpr std::uint32_t fat_cigam_64 = 0xBFBAFECAU;

constexpr std::uint32_t lc_segment = 0x01U;
constexpr std::uint32_t lc_symtab = 0x02U;
constexpr std::uint32_t lc_symseg = 0x03U;
constexpr std::uint32_t lc_thread = 0x04U;
constexpr std::uint32_t lc_unixthread = 0x05U;
constexpr std::uint32_t lc_load_fvmlib = 0x06U;
constexpr std::uint32_t lc_id_fvmlib = 0x07U;
constexpr std::uint32_t lc_ident = 0x08U;
constexpr std::uint32_t lc_fvmfile = 0x09U;
constexpr std::uint32_t lc_prepage = 0x0aU;
constexpr std::uint32_t lc_load_dylib = 0x0cU;
constexpr std::uint32_t lc_id_dylib = 0x0dU;
constexpr std::uint32_t lc_load_dylinker = 0x0eU;
constexpr std::uint32_t lc_id_dylinker = 0x0fU;
constexpr std::uint32_t lc_prebound_dylib = 0x10U;
constexpr std::uint32_t lc_routines = 0x11U;
constexpr std::uint32_t lc_sub_framework = 0x12U;
constexpr std::uint32_t lc_sub_umbrella = 0x13U;
constexpr std::uint32_t lc_sub_client = 0x14U;
constexpr std::uint32_t lc_sub_library = 0x15U;
constexpr std::uint32_t lc_twolevel_hints = 0x16U;
constexpr std::uint32_t lc_prebind_checksum = 0x17U;
constexpr std::uint32_t lc_dysymtab = 0x0bU;
constexpr std::uint32_t lc_load_weak_dylib = 0x80000018U;
constexpr std::uint32_t lc_segment_64 = 0x19U;
constexpr std::uint32_t lc_routines_64 = 0x1aU;
constexpr std::uint32_t lc_uuid = 0x1bU;
constexpr std::uint32_t lc_rpath = 0x8000001cU;
constexpr std::uint32_t lc_code_signature = 0x1dU;
constexpr std::uint32_t lc_segment_split_info = 0x1eU;
constexpr std::uint32_t lc_reexport_dylib = 0x8000001fU;
constexpr std::uint32_t lc_lazy_load_dylib = 0x20U;
constexpr std::uint32_t lc_encryption_info = 0x21U;
constexpr std::uint32_t lc_dyld_info = 0x22U;
constexpr std::uint32_t lc_dyld_info_only = 0x80000022U;
constexpr std::uint32_t lc_load_upward_dylib = 0x80000023U;
constexpr std::uint32_t lc_version_min_macosx = 0x24U;
constexpr std::uint32_t lc_version_min_iphoneos = 0x25U;
constexpr std::uint32_t lc_function_starts = 0x26U;
constexpr std::uint32_t lc_dyld_environment = 0x27U;
constexpr std::uint32_t lc_main = 0x80000028U;
constexpr std::uint32_t lc_data_in_code = 0x29U;
constexpr std::uint32_t lc_source_version = 0x2aU;
constexpr std::uint32_t lc_dylib_code_sign_drs = 0x2bU;
constexpr std::uint32_t lc_encryption_info_64 = 0x2cU;
constexpr std::uint32_t lc_linker_option = 0x2dU;
constexpr std::uint32_t lc_linker_optimization_hint = 0x2eU;
constexpr std::uint32_t lc_version_min_tvos = 0x2fU;
constexpr std::uint32_t lc_version_min_watchos = 0x30U;
constexpr std::uint32_t lc_note = 0x31U;
constexpr std::uint32_t lc_build_version = 0x32U;
constexpr std::uint32_t lc_dyld_exports_trie = 0x80000033U;
constexpr std::uint32_t lc_dyld_chained_fixups = 0x80000034U;
constexpr std::uint32_t lc_fileset_entry = 0x80000035U;

constexpr std::int32_t cpu_type_x86 = 7;
constexpr std::int32_t cpu_type_x86_64 = 0x01000007;
constexpr std::int32_t cpu_type_arm = 12;
constexpr std::int32_t cpu_type_arm64 = 0x0100000c;
constexpr std::int32_t cpu_type_arm64_32 = 0x0200000c;
constexpr std::int32_t cpu_type_powerpc = 18;
constexpr std::int32_t cpu_type_powerpc64 = 0x01000012;

constexpr std::uint32_t mh_object = 1U;
constexpr std::uint32_t mh_execute = 2U;
constexpr std::uint32_t mh_fvmlib = 3U;
constexpr std::uint32_t mh_core = 4U;
constexpr std::uint32_t mh_dylib = 6U;
constexpr std::uint32_t mh_dylinker = 7U;
constexpr std::uint32_t mh_dylib_stub = 9U;
constexpr std::uint32_t mh_dsym = 10U;
constexpr std::uint32_t mh_fileset = 12U;
constexpr std::uint32_t mh_split_segs = 0x20U;

constexpr std::uint32_t s_zerofill = 0x01U;
constexpr std::uint32_t s_gb_zerofill = 0x0cU;
constexpr std::uint32_t s_thread_local_zerofill = 0x12U;
constexpr std::uint32_t section_type_mask = 0xffU;
constexpr std::uint32_t section_attr_pure_instructions = 0x80000000U;
constexpr std::uint32_t section_attr_some_instructions = 0x00000400U;
constexpr std::uint32_t sg_highvm = 0x01U;

constexpr std::uint8_t n_stab = 0xe0U;
constexpr std::uint8_t n_pext = 0x10U;
constexpr std::uint8_t n_type = 0x0eU;
constexpr std::uint8_t n_ext = 0x01U;
constexpr std::uint8_t n_undf = 0x00U;
constexpr std::uint8_t n_abs = 0x02U;
constexpr std::uint8_t n_sect = 0x0eU;
constexpr std::uint16_t n_weak_ref = 0x0040U;
constexpr std::uint16_t n_weak_def = 0x0080U;

constexpr std::uint8_t rebase_opcode_mask = 0xf0U;
constexpr std::uint8_t rebase_immediate_mask = 0x0fU;
constexpr std::uint8_t rebase_done = 0x00U;
constexpr std::uint8_t rebase_set_type = 0x10U;
constexpr std::uint8_t rebase_set_segment = 0x20U;
constexpr std::uint8_t rebase_add_address = 0x30U;
constexpr std::uint8_t rebase_add_address_scaled = 0x40U;
constexpr std::uint8_t rebase_do_immediate = 0x50U;
constexpr std::uint8_t rebase_do_uleb = 0x60U;
constexpr std::uint8_t rebase_do_add_address = 0x70U;
constexpr std::uint8_t rebase_do_times_skip = 0x80U;

constexpr std::uint8_t bind_opcode_mask = 0xf0U;
constexpr std::uint8_t bind_immediate_mask = 0x0fU;
constexpr std::uint8_t bind_done = 0x00U;
constexpr std::uint8_t bind_set_dylib_ordinal = 0x10U;
constexpr std::uint8_t bind_set_dylib_ordinal_uleb = 0x20U;
constexpr std::uint8_t bind_set_dylib_special = 0x30U;
constexpr std::uint8_t bind_set_symbol = 0x40U;
constexpr std::uint8_t bind_set_type = 0x50U;
constexpr std::uint8_t bind_set_addend = 0x60U;
constexpr std::uint8_t bind_set_segment = 0x70U;
constexpr std::uint8_t bind_add_address = 0x80U;
constexpr std::uint8_t bind_do = 0x90U;
constexpr std::uint8_t bind_do_add_address = 0xa0U;
constexpr std::uint8_t bind_do_add_address_scaled = 0xb0U;
constexpr std::uint8_t bind_do_times_skip = 0xc0U;
constexpr std::uint8_t bind_threaded = 0xd0U;

constexpr std::uint64_t export_kind_mask = 0x03U;
constexpr std::uint64_t export_kind_absolute = 0x02U;
constexpr std::uint64_t export_reexport = 0x08U;
constexpr std::uint64_t export_stub_and_resolver = 0x10U;

constexpr std::uint16_t chained_start_none = 0xffffU;
constexpr std::uint16_t chained_start_multi = 0x8000U;
constexpr std::uint16_t chained_start_last = 0x8000U;
constexpr std::uint16_t chained_start_value_mask = 0x7fffU;

constexpr std::uint16_t chained_ptr_arm64e = 1U;
constexpr std::uint16_t chained_ptr_64 = 2U;
constexpr std::uint16_t chained_ptr_32 = 3U;
constexpr std::uint16_t chained_ptr_32_cache = 4U;
constexpr std::uint16_t chained_ptr_32_firmware = 5U;
constexpr std::uint16_t chained_ptr_64_offset = 6U;
constexpr std::uint16_t chained_ptr_arm64e_kernel = 7U;
constexpr std::uint16_t chained_ptr_64_kernel_cache = 8U;
constexpr std::uint16_t chained_ptr_arm64e_userland = 9U;
constexpr std::uint16_t chained_ptr_arm64e_firmware = 10U;
constexpr std::uint16_t chained_ptr_x86_64_kernel_cache = 11U;
constexpr std::uint16_t chained_ptr_arm64e_userland24 = 12U;
constexpr std::uint16_t chained_ptr_arm64e_shared_cache = 13U;
constexpr std::uint16_t chained_ptr_arm64e_segmented = 14U;

constexpr std::uint32_t chained_import = 1U;
constexpr std::uint32_t chained_import_addend = 2U;
constexpr std::uint32_t chained_import_addend64 = 3U;
constexpr std::uint32_t chained_symbols_uncompressed = 0U;
constexpr std::uint32_t chained_symbols_zlib = 1U;

constexpr std::uint64_t cancellation_interval = 1024U;

struct endian_reader_t {
    endian_t endian = endian_t::little;

    bool big() const noexcept {
        return endian == endian_t::big;
    }

    std::uint16_t u16(const void* pointer) const noexcept {
        const auto* bytes = static_cast<const std::uint8_t*>(pointer);
        if (big())
            return static_cast<std::uint16_t>((static_cast<std::uint16_t>(bytes[0]) << 8U) |
                                              static_cast<std::uint16_t>(bytes[1]));
        return static_cast<std::uint16_t>((static_cast<std::uint16_t>(bytes[1]) << 8U) |
                                          static_cast<std::uint16_t>(bytes[0]));
    }

    std::uint32_t u32(const void* pointer) const noexcept {
        const auto* bytes = static_cast<const std::uint8_t*>(pointer);
        if (big()) {
            return (static_cast<std::uint32_t>(bytes[0]) << 24U) |
                   (static_cast<std::uint32_t>(bytes[1]) << 16U) |
                   (static_cast<std::uint32_t>(bytes[2]) << 8U) |
                   static_cast<std::uint32_t>(bytes[3]);
        }
        return (static_cast<std::uint32_t>(bytes[3]) << 24U) |
               (static_cast<std::uint32_t>(bytes[2]) << 16U) |
               (static_cast<std::uint32_t>(bytes[1]) << 8U) |
               static_cast<std::uint32_t>(bytes[0]);
    }

    std::uint64_t u64(const void* pointer) const noexcept {
        const auto* bytes = static_cast<const std::uint8_t*>(pointer);
        std::uint64_t value = 0;
        if (big()) {
            for (std::uint32_t index = 0; index < 8; ++index)
                value = (value << 8U) | bytes[index];
        } else {
            for (std::uint32_t index = 8; index != 0; --index)
                value = (value << 8U) | bytes[index - 1U];
        }
        return value;
    }

    std::int16_t i16(const void* pointer) const noexcept {
        return static_cast<std::int16_t>(u16(pointer));
    }

    std::int32_t i32(const void* pointer) const noexcept {
        return static_cast<std::int32_t>(u32(pointer));
    }
};

struct segment_record_t {
    std::uint32_t index = 0;
    std::string name;
    std::uint64_t vm_address = 0;
    std::uint64_t vm_size = 0;
    std::uint64_t file_offset = 0;
    std::uint64_t file_size = 0;
    std::int32_t max_protection = 0;
    std::int32_t initial_protection = 0;
    std::uint32_t flags = 0;
};

struct section_record_t {
    std::uint32_t index = 0;
    std::uint32_t segment_index = 0;
    std::string section_name;
    std::string segment_name;
    std::uint64_t vm_address = 0;
    std::uint64_t size = 0;
    std::uint64_t file_offset = 0;
    std::uint64_t file_size = 0;
    std::uint32_t relocation_offset = 0;
    std::uint32_t relocation_count = 0;
    std::uint32_t flags = 0;
    std::uint32_t permissions = image_permission_none;
};

struct symbol_record_t {
    std::uint64_t ordinal = 0;
    std::string name;
    std::uint64_t value = 0;
    std::uint8_t type = 0;
    std::uint8_t section = 0;
    std::uint16_t description = 0;
};

struct dependency_record_t {
    std::string name;
};

struct bind_record_t {
    std::string name;
    std::int64_t library_ordinal = 0;
    std::uint64_t vm_address = 0;
    std::int64_t addend = 0;
    std::uint8_t type = 0;
    bool weak = false;
    bool lazy = false;
};

struct export_record_t {
    std::string name;
    std::uint64_t address = 0;
    std::optional<std::string> forwarder;
    bool absolute = false;
};

struct relocation_record_t {
    std::uint64_t vm_address = 0;
    std::uint64_t type = 0;
    std::optional<std::uint64_t> target_vm_address;
};

struct metadata_symbol_record_t {
    std::string name;
    std::uint64_t vm_address = 0;
    std::uint64_t size = 0;
    image_symbol_kind_t kind = image_symbol_kind_t::metadata;
};

struct symtab_descriptor_t {
    std::uint32_t symbol_offset = 0;
    std::uint32_t symbol_count = 0;
    std::uint32_t string_offset = 0;
    std::uint32_t string_size = 0;
};

struct dysymtab_descriptor_t {
    std::uint32_t local_index = 0;
    std::uint32_t local_count = 0;
    std::uint32_t external_index = 0;
    std::uint32_t external_count = 0;
    std::uint32_t undefined_index = 0;
    std::uint32_t undefined_count = 0;
    std::uint32_t toc_offset = 0;
    std::uint32_t toc_count = 0;
    std::uint32_t module_offset = 0;
    std::uint32_t module_count = 0;
    std::uint32_t external_reference_offset = 0;
    std::uint32_t external_reference_count = 0;
    std::uint32_t indirect_offset = 0;
    std::uint32_t indirect_count = 0;
    std::uint32_t external_relocation_offset = 0;
    std::uint32_t external_relocation_count = 0;
    std::uint32_t local_relocation_offset = 0;
    std::uint32_t local_relocation_count = 0;
};

struct dyld_info_descriptor_t {
    std::uint32_t rebase_offset = 0;
    std::uint32_t rebase_size = 0;
    std::uint32_t bind_offset = 0;
    std::uint32_t bind_size = 0;
    std::uint32_t weak_bind_offset = 0;
    std::uint32_t weak_bind_size = 0;
    std::uint32_t lazy_bind_offset = 0;
    std::uint32_t lazy_bind_size = 0;
    std::uint32_t export_offset = 0;
    std::uint32_t export_size = 0;
};

struct linkedit_descriptor_t {
    std::uint32_t offset = 0;
    std::uint32_t size = 0;
};

struct command_descriptor_t {
    std::uint32_t command = 0;
    std::uint64_t offset = 0;
    std::uint32_t size = 0;
};

struct chained_import_record_t {
    std::string name;
    std::int64_t library_ordinal = 0;
    std::int64_t addend = 0;
    bool weak = false;
};

struct chain_pointer_t {
    std::uint64_t next = 0;
    std::uint64_t stride = 0;
    std::uint64_t ordinal = 0;
    std::int64_t addend = 0;
    std::optional<std::uint64_t> target;
    bool bind = false;
    bool target_is_offset = false;
};

struct inflate_guard_t {
    z_stream stream{};
    bool initialized = false;

    ~inflate_guard_t() {
        if (initialized)
            inflateEnd(&stream);
    }
};

struct parse_product_t {
    std::shared_ptr<const workspace_image_t> image;
    std::int32_t cpu_type = 0;
    std::int32_t cpu_subtype = 0;
    std::uint64_t metadata_bytes = 0;
    std::uint64_t string_bytes = 0;
};

workspace_error_t make_macho_error(workspace_error_code_t code, std::string message,
                                   std::string phase,
                                   std::optional<std::uint64_t> offset = {},
                                   std::optional<std::uint64_t> size = {}) {
    auto error = make_workspace_error(code, std::move(message), std::move(phase));
    error.offset = offset;
    error.size = size;
    return error;
}

workspace_error_t make_limit_error(std::string message, std::string phase,
                                   std::uint64_t value, std::uint64_t limit) {
    auto error = make_macho_error(workspace_error_code_t::limit_exceeded,
                                  std::move(message), std::move(phase));
    error.details.emplace_back("value", std::to_string(value));
    error.details.emplace_back("limit", std::to_string(limit));
    return error;
}

workspace_error_t make_stop_error(const cancellation_token_t& cancel, std::string phase) {
    const bool deadline = cancel.deadline_exceeded();
    auto error = make_macho_error(deadline ? workspace_error_code_t::deadline_exceeded
                                           : workspace_error_code_t::cancelled,
                                  deadline ? "Mach-O parsing deadline exceeded"
                                           : "Mach-O parsing cancelled",
                                  std::move(phase));
    error.deadline = deadline;
    error.cancellation = !deadline;
    return error;
}

bool decode_uleb128(const std::vector<std::uint8_t>& data, std::uint64_t& cursor,
                    std::uint64_t limit, std::uint64_t& value) noexcept {
    value = 0;
    std::uint32_t shift = 0;
    for (std::uint32_t index = 0; index < 10; ++index) {
        if (cursor >= limit || cursor >= data.size())
            return false;
        const std::uint8_t byte = data[static_cast<std::size_t>(cursor++)];
        const std::uint64_t payload = byte & 0x7fU;
        if (shift == 63U && payload > 1U)
            return false;
        value |= payload << shift;
        if ((byte & 0x80U) == 0)
            return true;
        shift += 7U;
    }
    return false;
}

bool decode_sleb128(const std::vector<std::uint8_t>& data, std::uint64_t& cursor,
                    std::uint64_t limit, std::int64_t& value) noexcept {
    std::uint64_t bits = 0;
    std::uint32_t shift = 0;
    std::uint8_t byte = 0;
    for (std::uint32_t index = 0; index < 10; ++index) {
        if (cursor >= limit || cursor >= data.size())
            return false;
        byte = data[static_cast<std::size_t>(cursor++)];
        const std::uint64_t payload = byte & 0x7fU;
        if (shift == 63U && payload != 0U && payload != 0x7fU)
            return false;
        bits |= payload << shift;
        shift += 7U;
        if ((byte & 0x80U) == 0) {
            if (shift < 64U && (byte & 0x40U) != 0)
                bits |= (~0ULL) << shift;
            value = static_cast<std::int64_t>(bits);
            return true;
        }
    }
    return false;
}

std::int64_t sign_extend(std::uint64_t value, std::uint32_t width) noexcept {
    if (width == 0 || width >= 64)
        return static_cast<std::int64_t>(value);
    const std::uint64_t sign = 1ULL << (width - 1U);
    const std::uint64_t mask = (1ULL << width) - 1ULL;
    value &= mask;
    return static_cast<std::int64_t>((value ^ sign) - sign);
}

bool zero_fill_section(std::uint32_t flags) noexcept {
    const std::uint32_t type = flags & section_type_mask;
    return type == s_zerofill || type == s_gb_zerofill ||
           type == s_thread_local_zerofill;
}

bool objc_section(std::string_view name) noexcept {
    return name == "__objc_classlist" || name == "__objc_protolist" ||
           name == "__objc_imageinfo" || name == "__objc_methname" ||
           name == "__objc_classname" || name == "__objc_methtype" ||
           name == "__objc_selrefs" || name == "__objc_classrefs" ||
           name == "__objc_superrefs" || name == "__objc_catlist" ||
           name == "__objc_nlcatlist" || name == "__objc_nlclslist" ||
           name == "__objc_protorefs" || name == "__objc_ivar" ||
           name == "__objc_const" || name == "__objc_data" ||
           name == "__objc_methref";
}

bool swift_section(std::string_view name) noexcept {
    return name == "__swift5_types" || name == "__swift5_protos" ||
           name == "__swift5_proto" || name == "__swift5_field" ||
           name == "__swift5_fieldmd" || name == "__swift5_mpenum" ||
           name == "__swift5_builtin" || name == "__swift5_capture" ||
           name == "__swift5_reflstr" || name == "__swift5_assocty" ||
           name == "__swift5_replace" || name == "__swift5_replac2" ||
           name == "__swift5_typeref" || name == "__swift5_entry";
}

bool dwarf_section(std::string_view name) noexcept {
    return name == "__debug_info" || name == "__debug_line" ||
           name == "__debug_str" || name == "__debug_abbrev" ||
           name == "__debug_ranges" || name == "__debug_aranges" ||
           name == "__debug_macinfo" || name == "__debug_loc" ||
           name == "__debug_frame" || name == "__debug_pubnames" ||
           name == "__debug_pubtypes" || name == "__debug_line_str" ||
           name == "__debug_loclists" || name == "__debug_rnglists" ||
           name == "__debug_str_offs" || name == "__debug_addr" ||
           name == "__debug_names" || name == "__debug_types" ||
           name == "__debug_cu_index" || name == "__debug_tu_index" ||
           name == "__apple_names" || name == "__apple_types" ||
           name == "__apple_namespac" || name == "__apple_objc";
}

class macho_parser_t {
public:
    macho_parser_t(const byte_provider_t& provider, const macho_parse_limits_t& limits,
                   const cancellation_token_t& cancel, std::uint64_t provider_base,
                   std::uint64_t provider_size, std::string provider_source,
                   std::optional<provider_member_metadata_t> member);

    workspace_result_t<parse_product_t> parse();

private:
    const byte_provider_t& provider_;
    const macho_parse_limits_t& limits_;
    const cancellation_token_t& cancel_;
    std::uint64_t provider_base_ = 0;
    std::uint64_t provider_size_ = 0;
    std::uint64_t provider_end_ = 0;
    std::string provider_source_;
    std::optional<provider_member_metadata_t> member_;
    mutable byte_view_t cache_;
    mutable std::uint64_t cache_relative_offset_ = 0;
    endian_reader_t reader_;
    bool is_64_bit_ = false;
    std::uint8_t pointer_size_ = 0;
    std::uint64_t header_size_ = 0;
    std::uint64_t commands_end_ = 0;
    std::int32_t cpu_type_ = 0;
    std::int32_t cpu_subtype_ = 0;
    std::uint32_t file_type_ = 0;
    std::uint32_t header_flags_ = 0;
    std::uint32_t command_count_ = 0;
    std::uint32_t command_bytes_ = 0;
    std::uint64_t image_base_ = 0;
    std::uint64_t image_size_ = 0;
    architecture_id_t architecture_ = architecture_id_t::unknown;
    architecture_mode_t architecture_mode_ = architecture_mode_t::unknown;
    abi_id_t abi_ = abi_id_t::unknown;
    std::uint64_t metadata_bytes_ = 0;
    std::uint64_t string_bytes_ = 0;
    std::uint64_t chained_steps_ = 0;
    std::uint64_t export_nodes_ = 0;
    std::uint64_t rebase_entries_ = 0;
    std::vector<segment_record_t> segments_;
    std::vector<section_record_t> sections_;
    std::vector<symbol_record_t> symbols_;
    std::vector<dependency_record_t> dependencies_;
    std::vector<bind_record_t> binds_;
    std::vector<export_record_t> exports_;
    std::vector<relocation_record_t> relocations_;
    std::vector<metadata_symbol_record_t> metadata_symbols_;
    std::vector<std::pair<std::uint64_t, std::string>> vm_entry_points_;
    std::vector<std::pair<std::uint64_t, std::string>> file_entry_points_;
    std::vector<std::pair<checked_span_t, std::string>> metadata_ranges_;
    std::map<std::uint64_t, std::uint64_t> chained_locations_;
    std::set<std::uint32_t> singleton_commands_;
    std::optional<symtab_descriptor_t> symtab_;
    std::optional<dysymtab_descriptor_t> dysymtab_;
    std::optional<dyld_info_descriptor_t> dyld_info_;
    std::optional<linkedit_descriptor_t> exports_trie_;
    std::optional<linkedit_descriptor_t> chained_fixups_;
    std::optional<linkedit_descriptor_t> function_starts_;
    std::optional<linkedit_descriptor_t> data_in_code_;
    std::optional<std::uint64_t> main_entry_offset_;
    std::optional<std::string> uuid_;
    std::vector<command_descriptor_t> thread_commands_;

    workspace_error_t error(workspace_error_code_t code, std::string message,
                            std::string phase, std::optional<std::uint64_t> relative_offset = {},
                            std::optional<std::uint64_t> size = {}) const;
    workspace_result_t<void> poll(std::uint64_t iteration, std::string phase) const;
    workspace_result_t<void> consume_metadata(std::uint64_t amount, std::string phase);
    workspace_result_t<void> consume_string(std::uint64_t amount, std::string phase);
    workspace_result_t<std::uint64_t> absolute_range(std::uint64_t relative_offset,
                                                     std::uint64_t size,
                                                     std::string phase) const;
    workspace_result_t<const std::uint8_t*> bytes(std::uint64_t relative_offset,
                                                  std::uint64_t size,
                                                  std::string phase) const;
    workspace_result_t<std::uint8_t> read_u8(std::uint64_t relative_offset,
                                             std::string phase) const;
    workspace_result_t<std::uint16_t> read_u16(std::uint64_t relative_offset,
                                               std::string phase) const;
    workspace_result_t<std::uint32_t> read_u32(std::uint64_t relative_offset,
                                               std::string phase) const;
    workspace_result_t<std::uint64_t> read_u64(std::uint64_t relative_offset,
                                               std::string phase) const;
    workspace_result_t<std::int32_t> read_i32(std::uint64_t relative_offset,
                                              std::string phase) const;
    workspace_result_t<std::string> read_fixed_string(std::uint64_t relative_offset,
                                                      std::uint64_t size,
                                                      std::string phase);
    workspace_result_t<std::string> read_cstring(std::uint64_t relative_offset,
                                                std::uint64_t available,
                                                std::string phase);
    workspace_result_t<void> validate_zero_padding(std::uint64_t relative_offset,
                                                   std::uint64_t size,
                                                   std::string phase) const;
    workspace_result_t<std::vector<std::uint8_t>> read_blob(std::uint64_t relative_offset,
                                                            std::uint64_t size,
                                                            std::string phase);
    workspace_result_t<void> register_metadata_range(std::uint64_t offset, std::uint64_t size,
                                                     std::string label);
    workspace_result_t<void> parse_header();
    workspace_result_t<void> select_architecture();
    workspace_result_t<void> parse_load_commands();
    workspace_result_t<void> parse_load_command(std::uint32_t command,
                                                std::uint64_t offset,
                                                std::uint32_t size);
    workspace_result_t<void> parse_segment(std::uint64_t offset, std::uint32_t size,
                                           bool is_64_bit);
    workspace_result_t<void> parse_symtab_command(std::uint64_t offset, std::uint32_t size);
    workspace_result_t<void> parse_dysymtab_command(std::uint64_t offset, std::uint32_t size);
    workspace_result_t<void> parse_dylib_command(std::uint32_t command,
                                                 std::uint64_t offset,
                                                 std::uint32_t size);
    workspace_result_t<void> parse_dyld_info_command(std::uint64_t offset, std::uint32_t size);
    workspace_result_t<void> parse_linkedit_command(std::uint32_t command,
                                                    std::uint64_t offset,
                                                    std::uint32_t size);
    workspace_result_t<void> parse_string_command(std::uint32_t command,
                                                  std::uint64_t offset,
                                                  std::uint32_t size);
    workspace_result_t<void> parse_misc_command(std::uint32_t command,
                                                std::uint64_t offset,
                                                std::uint32_t size);
    workspace_result_t<void> validate_layout();
    workspace_result_t<void> process_payloads();
    workspace_result_t<void> parse_symbols();
    workspace_result_t<void> validate_dynamic_symbol_table();
    workspace_result_t<void> parse_relocation_table(std::uint64_t offset,
                                                    std::uint64_t count,
                                                    const section_record_t* section,
                                                    bool dynamic_table,
                                                    std::string label);
    workspace_result_t<void> parse_relocations();
    workspace_result_t<void> parse_dyld_payloads();
    workspace_result_t<void> parse_rebase_stream(const std::vector<std::uint8_t>& data);
    workspace_result_t<void> parse_bind_stream(const std::vector<std::uint8_t>& data,
                                               bool weak, bool lazy);
    workspace_result_t<void> append_rebase(std::uint64_t segment_index,
                                           std::uint64_t segment_offset,
                                           std::uint64_t type);
    workspace_result_t<void> append_bind(std::uint64_t segment_index,
                                         std::uint64_t segment_offset,
                                         const std::string& name,
                                         std::int64_t library_ordinal,
                                         std::int64_t addend,
                                         std::uint8_t type,
                                         bool weak, bool lazy);
    workspace_result_t<void> parse_threaded_apply(
        std::uint64_t segment_index, std::uint64_t segment_offset,
        const std::vector<bind_record_t>& ordinal_table, bool weak, bool lazy);
    workspace_result_t<void> parse_export_trie(const std::vector<std::uint8_t>& data);
    workspace_result_t<void> parse_export_node(const std::vector<std::uint8_t>& data,
                                               std::uint64_t node_offset,
                                               const std::string& prefix,
                                               std::uint32_t depth,
                                               std::unordered_set<std::uint64_t>& active);
    workspace_result_t<void> parse_chained_fixups();
    workspace_result_t<std::vector<std::uint8_t>> decompress_chained_symbols(
        const std::vector<std::uint8_t>& data, std::uint32_t symbols_offset);
    workspace_result_t<std::vector<chained_import_record_t>> parse_chained_imports(
        const std::vector<std::uint8_t>& data, std::uint32_t imports_offset,
        std::uint32_t imports_count, std::uint32_t imports_format,
        std::uint32_t symbols_offset, std::uint32_t symbols_format);
    workspace_result_t<chain_pointer_t> decode_chain_pointer(std::uint16_t format,
                                                             std::uint64_t value) const;
    workspace_result_t<void> walk_chained_page(
        std::uint32_t segment_index, std::uint16_t pointer_format,
        std::uint32_t page_index, std::uint16_t page_size,
        std::uint16_t start, std::uint32_t max_valid_pointer,
        const std::vector<chained_import_record_t>& imports);
    workspace_result_t<void> parse_function_starts();
    workspace_result_t<void> parse_data_in_code();
    workspace_result_t<void> parse_thread_commands();
    workspace_result_t<void> parse_language_metadata();
    workspace_result_t<void> parse_cstring_metadata(const section_record_t& section,
                                                     std::string prefix);
    workspace_result_t<void> parse_pointer_metadata(const section_record_t& section,
                                                    std::string name);
    workspace_result_t<void> parse_swift_relative_metadata(const section_record_t& section,
                                                           std::string name);
    workspace_result_t<void> add_metadata_symbol(std::string name,
                                                 std::uint64_t vm_address,
                                                 std::uint64_t size,
                                                 image_symbol_kind_t kind =
                                                     image_symbol_kind_t::metadata);
    std::optional<std::uint64_t> vm_to_rva(std::uint64_t vm_address,
                                          std::uint64_t size = 1) const noexcept;
    std::optional<std::uint64_t> file_to_vm(std::uint64_t file_offset,
                                           std::uint64_t size = 1) const noexcept;
    std::optional<std::uint64_t> vm_to_file(std::uint64_t vm_address,
                                           std::uint64_t size = 1) const noexcept;
    std::string library_name(std::int64_t ordinal) const;
    workspace_result_t<parse_product_t> normalize();
};

macho_parser_t::macho_parser_t(const byte_provider_t& provider,
                               const macho_parse_limits_t& limits,
                               const cancellation_token_t& cancel,
                               std::uint64_t provider_base,
                               std::uint64_t provider_size,
                               std::string provider_source,
                               std::optional<provider_member_metadata_t> member)
    : provider_(provider), limits_(limits), cancel_(cancel),
      provider_base_(provider_base), provider_size_(provider_size),
      provider_source_(std::move(provider_source)), member_(std::move(member)) {}

workspace_error_t macho_parser_t::error(
    workspace_error_code_t code, std::string message, std::string phase,
    std::optional<std::uint64_t> relative_offset,
    std::optional<std::uint64_t> size) const {
    std::optional<std::uint64_t> absolute_offset;
    if (relative_offset) {
        std::uint64_t value = 0;
        if (checked_add_u64(provider_base_, *relative_offset, value))
            absolute_offset = value;
        else
            absolute_offset = *relative_offset;
    }
    return make_macho_error(code, std::move(message), std::move(phase),
                            absolute_offset, size);
}

workspace_result_t<void> macho_parser_t::poll(std::uint64_t iteration,
                                              std::string phase) const {
    if ((iteration % cancellation_interval) == 0 && cancel_.stop_requested())
        return workspace_result_t<void>::failure(make_stop_error(cancel_, std::move(phase)));
    return workspace_result_t<void>::success();
}

workspace_result_t<void> macho_parser_t::consume_metadata(std::uint64_t amount,
                                                          std::string phase) {
    std::uint64_t next = 0;
    if (!checked_add_u64(metadata_bytes_, amount, next))
        return workspace_result_t<void>::failure(error(
            workspace_error_code_t::range_overflow,
            "Mach-O metadata budget accounting overflowed", std::move(phase)));
    if (next > limits_.max_total_metadata_bytes)
        return workspace_result_t<void>::failure(make_limit_error(
            "Mach-O aggregate metadata budget exceeded", std::move(phase), next,
            limits_.max_total_metadata_bytes));
    metadata_bytes_ = next;
    return workspace_result_t<void>::success();
}

workspace_result_t<void> macho_parser_t::consume_string(std::uint64_t amount,
                                                        std::string phase) {
    std::uint64_t next = 0;
    if (!checked_add_u64(string_bytes_, amount, next))
        return workspace_result_t<void>::failure(error(
            workspace_error_code_t::range_overflow,
            "Mach-O string budget accounting overflowed", phase));
    if (next > limits_.max_string_bytes)
        return workspace_result_t<void>::failure(make_limit_error(
            "Mach-O aggregate string budget exceeded", phase, next,
            limits_.max_string_bytes));
    auto consumed = consume_metadata(amount, std::move(phase));
    if (!consumed)
        return consumed;
    string_bytes_ = next;
    return workspace_result_t<void>::success();
}

workspace_result_t<std::uint64_t> macho_parser_t::absolute_range(
    std::uint64_t relative_offset, std::uint64_t size, std::string phase) const {
    if (relative_offset > provider_size_ || size > provider_size_ - relative_offset)
        return workspace_result_t<std::uint64_t>::failure(error(
            workspace_error_code_t::out_of_range,
            "Mach-O range exceeds its bounded provider member", std::move(phase),
            relative_offset, size));
    std::uint64_t absolute = 0;
    std::uint64_t absolute_end = 0;
    if (!checked_add_u64(provider_base_, relative_offset, absolute) ||
        !checked_add_u64(absolute, size, absolute_end))
        return workspace_result_t<std::uint64_t>::failure(error(
            workspace_error_code_t::range_overflow,
            "Mach-O provider range overflowed", std::move(phase), relative_offset,
            size));
    if (absolute_end > provider_.size())
        return workspace_result_t<std::uint64_t>::failure(error(
            workspace_error_code_t::out_of_range,
            "Mach-O range exceeds the backing provider", std::move(phase),
            relative_offset, size));
    return workspace_result_t<std::uint64_t>::success(absolute);
}

workspace_result_t<const std::uint8_t*> macho_parser_t::bytes(
    std::uint64_t relative_offset, std::uint64_t size, std::string phase) const {
    if (cancel_.stop_requested())
        return workspace_result_t<const std::uint8_t*>::failure(
            make_stop_error(cancel_, phase));
    auto absolute = absolute_range(relative_offset, size, phase);
    if (!absolute)
        return workspace_result_t<const std::uint8_t*>::failure(absolute.error());
    std::uint64_t requested_end = 0;
    std::uint64_t cached_end = 0;
    if (checked_add_u64(relative_offset, size, requested_end) && cache_.data() &&
        checked_add_u64(cache_relative_offset_, cache_.size(), cached_end) &&
        relative_offset >= cache_relative_offset_ && requested_end <= cached_end) {
        return workspace_result_t<const std::uint8_t*>::success(
            cache_.data() + static_cast<std::size_t>(relative_offset -
                                                     cache_relative_offset_));
    }
    constexpr std::uint64_t window = 64ULL * 1024ULL;
    const std::uint64_t window_offset = relative_offset - (relative_offset % window);
    const std::uint64_t available = provider_size_ - window_offset;
    const std::uint64_t desired = std::max(size, std::min(window, available));
    auto window_absolute = absolute_range(window_offset, desired, phase);
    if (!window_absolute)
        return workspace_result_t<const std::uint8_t*>::failure(window_absolute.error());
    auto lease = provider_.lease(window_absolute.value(), desired, cancel_);
    std::uint64_t leased_relative = window_offset;
    if (!lease && (window_offset != relative_offset || desired != size)) {
        lease = provider_.lease(absolute.value(), size, cancel_);
        leased_relative = relative_offset;
    }
    if (!lease)
        return workspace_result_t<const std::uint8_t*>::failure(lease.error());
    cache_ = lease.take_value();
    cache_relative_offset_ = leased_relative;
    if (!cache_.data() || relative_offset < cache_relative_offset_ ||
        relative_offset - cache_relative_offset_ > cache_.size() ||
        size > cache_.size() - (relative_offset - cache_relative_offset_)) {
        return workspace_result_t<const std::uint8_t*>::failure(error(
            workspace_error_code_t::integrity_failure,
            "Mach-O provider lease did not contain the requested range", std::move(phase),
            relative_offset, size));
    }
    return workspace_result_t<const std::uint8_t*>::success(
        cache_.data() + static_cast<std::size_t>(relative_offset -
                                                 cache_relative_offset_));
}

workspace_result_t<std::uint8_t> macho_parser_t::read_u8(
    std::uint64_t relative_offset, std::string phase) const {
    auto value = bytes(relative_offset, 1, std::move(phase));
    if (!value)
        return workspace_result_t<std::uint8_t>::failure(value.error());
    return workspace_result_t<std::uint8_t>::success(*value.value());
}

workspace_result_t<std::uint16_t> macho_parser_t::read_u16(
    std::uint64_t relative_offset, std::string phase) const {
    auto value = bytes(relative_offset, 2, std::move(phase));
    if (!value)
        return workspace_result_t<std::uint16_t>::failure(value.error());
    return workspace_result_t<std::uint16_t>::success(reader_.u16(value.value()));
}

workspace_result_t<std::uint32_t> macho_parser_t::read_u32(
    std::uint64_t relative_offset, std::string phase) const {
    auto value = bytes(relative_offset, 4, std::move(phase));
    if (!value)
        return workspace_result_t<std::uint32_t>::failure(value.error());
    return workspace_result_t<std::uint32_t>::success(reader_.u32(value.value()));
}

workspace_result_t<std::uint64_t> macho_parser_t::read_u64(
    std::uint64_t relative_offset, std::string phase) const {
    auto value = bytes(relative_offset, 8, std::move(phase));
    if (!value)
        return workspace_result_t<std::uint64_t>::failure(value.error());
    return workspace_result_t<std::uint64_t>::success(reader_.u64(value.value()));
}

workspace_result_t<std::int32_t> macho_parser_t::read_i32(
    std::uint64_t relative_offset, std::string phase) const {
    auto value = read_u32(relative_offset, std::move(phase));
    if (!value)
        return workspace_result_t<std::int32_t>::failure(value.error());
    return workspace_result_t<std::int32_t>::success(
        static_cast<std::int32_t>(value.value()));
}

workspace_result_t<std::string> macho_parser_t::read_fixed_string(
    std::uint64_t relative_offset, std::uint64_t size, std::string phase) {
    auto value = bytes(relative_offset, size, phase);
    if (!value)
        return workspace_result_t<std::string>::failure(value.error());
    std::uint64_t length = 0;
    while (length < size && value.value()[length] != 0)
        ++length;
    auto budget = consume_string(length, phase);
    if (!budget)
        return workspace_result_t<std::string>::failure(budget.error());
    return workspace_result_t<std::string>::success(std::string(
        reinterpret_cast<const char*>(value.value()), static_cast<std::size_t>(length)));
}

workspace_result_t<std::string> macho_parser_t::read_cstring(
    std::uint64_t relative_offset, std::uint64_t available, std::string phase) {
    auto span = absolute_range(relative_offset, available, phase);
    if (!span)
        return workspace_result_t<std::string>::failure(span.error());
    const std::uint64_t scan_limit = std::min(available, limits_.max_string_bytes);
    std::string result;
    std::uint64_t scanned = 0;
    while (scanned < scan_limit) {
        auto stopped = poll(scanned, phase);
        if (!stopped)
            return workspace_result_t<std::string>::failure(stopped.error());
        const std::uint64_t amount = std::min<std::uint64_t>(4096, scan_limit - scanned);
        auto chunk = bytes(relative_offset + scanned, amount, phase);
        if (!chunk)
            return workspace_result_t<std::string>::failure(chunk.error());
        const auto* begin = chunk.value();
        const auto* end = begin + static_cast<std::size_t>(amount);
        const auto* terminator = std::find(begin, end, static_cast<std::uint8_t>(0));
        result.append(reinterpret_cast<const char*>(begin),
                      static_cast<std::size_t>(terminator - begin));
        scanned += static_cast<std::uint64_t>(terminator - begin);
        if (terminator != end) {
            auto budget = consume_string(result.size(), phase);
            if (!budget)
                return workspace_result_t<std::string>::failure(budget.error());
            return workspace_result_t<std::string>::success(std::move(result));
        }
    }
    return workspace_result_t<std::string>::failure(error(
        workspace_error_code_t::malformed_image,
        "Mach-O string is not terminated inside its declared range", std::move(phase),
        relative_offset, available));
}

workspace_result_t<void> macho_parser_t::validate_zero_padding(
    std::uint64_t relative_offset, std::uint64_t size, std::string phase) const {
    std::uint64_t consumed = 0;
    while (consumed < size) {
        auto stopped = poll(consumed, phase);
        if (!stopped)
            return stopped;
        const std::uint64_t amount = std::min<std::uint64_t>(4096, size - consumed);
        auto data = bytes(relative_offset + consumed, amount, phase);
        if (!data)
            return workspace_result_t<void>::failure(data.error());
        const auto* begin = data.value();
        const auto* end = begin + static_cast<std::size_t>(amount);
        const auto* nonzero = std::find_if(begin, end, [](std::uint8_t value) {
            return value != 0;
        });
        if (nonzero != end)
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::malformed_image,
                "Mach-O load-command padding is not zero", std::move(phase),
                relative_offset + consumed +
                    static_cast<std::uint64_t>(nonzero - begin),
                1));
        consumed += amount;
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<std::vector<std::uint8_t>> macho_parser_t::read_blob(
    std::uint64_t relative_offset, std::uint64_t size, std::string phase) {
    if (size == 0)
        return workspace_result_t<std::vector<std::uint8_t>>::success({});
    if (size > limits_.max_linkedit_blob_bytes)
        return workspace_result_t<std::vector<std::uint8_t>>::failure(make_limit_error(
            "Mach-O metadata blob exceeds its per-blob budget", phase, size,
            limits_.max_linkedit_blob_bytes));
    auto absolute = absolute_range(relative_offset, size, phase);
    if (!absolute)
        return workspace_result_t<std::vector<std::uint8_t>>::failure(absolute.error());
    auto result = provider_.read_vector(absolute.value(), size,
                                        limits_.max_linkedit_blob_bytes, cancel_);
    if (!result)
        return workspace_result_t<std::vector<std::uint8_t>>::failure(result.error());
    auto budget = consume_metadata(size, phase);
    if (!budget)
        return workspace_result_t<std::vector<std::uint8_t>>::failure(budget.error());
    return workspace_result_t<std::vector<std::uint8_t>>::success(result.take_value());
}

workspace_result_t<void> macho_parser_t::register_metadata_range(
    std::uint64_t offset, std::uint64_t size, std::string label) {
    if (size == 0)
        return workspace_result_t<void>::success();
    auto span_result = absolute_range(offset, size, "macho.linkedit.range");
    if (!span_result)
        return workspace_result_t<void>::failure(span_result.error());
    checked_span_t candidate{offset, size};
    checked_span_t commands{0, commands_end_};
    if (candidate.overlaps(commands))
        return workspace_result_t<void>::failure(error(
            workspace_error_code_t::malformed_image,
            "Mach-O metadata overlaps the header or load-command table",
            "macho.linkedit.range", offset, size));
    for (const auto& existing : metadata_ranges_) {
        if (!candidate.overlaps(existing.first))
            continue;
        auto overlap_error = error(
            workspace_error_code_t::malformed_image,
            "Mach-O metadata ranges overlap", "macho.linkedit.range", offset, size);
        overlap_error.details.emplace_back("range", label);
        overlap_error.details.emplace_back("overlaps", existing.second);
        return workspace_result_t<void>::failure(std::move(overlap_error));
    }
    auto budget = consume_metadata(sizeof(checked_span_t) + sizeof(std::string) +
                                       label.size(),
                                   "macho.linkedit.range");
    if (!budget)
        return budget;
    metadata_ranges_.emplace_back(candidate, std::move(label));
    return workspace_result_t<void>::success();
}

workspace_result_t<parse_product_t> macho_parser_t::parse() {
    if (provider_size_ == 0 || limits_.max_load_commands == 0 ||
        limits_.max_segments == 0 || limits_.max_sections == 0 ||
        limits_.max_symbols == 0 || limits_.max_total_metadata_bytes == 0 ||
        limits_.max_export_trie_depth == 0 ||
        limits_.max_export_trie_depth > 512) {
        return workspace_result_t<parse_product_t>::failure(error(
            workspace_error_code_t::invalid_argument,
            "Mach-O parser limits or provider extent are invalid", "macho.profile"));
    }
    auto source_budget = consume_string(provider_source_.size(), "macho.profile");
    if (!source_budget)
        return workspace_result_t<parse_product_t>::failure(source_budget.error());
    if (member_) {
        auto member_string_budget = consume_string(
            member_->normalized_member_path.size(), "macho.profile");
        if (!member_string_budget)
            return workspace_result_t<parse_product_t>::failure(
                member_string_budget.error());
        auto member_budget = consume_metadata(sizeof(provider_member_metadata_t),
                                              "macho.profile");
        if (!member_budget)
            return workspace_result_t<parse_product_t>::failure(member_budget.error());
    }
    if (!checked_add_u64(provider_base_, provider_size_, provider_end_) ||
        provider_end_ > provider_.size()) {
        return workspace_result_t<parse_product_t>::failure(error(
            workspace_error_code_t::out_of_range,
            "Mach-O bounded provider member exceeds the backing provider",
            "macho.profile", 0, provider_size_));
    }
    auto header = parse_header();
    if (!header)
        return workspace_result_t<parse_product_t>::failure(header.error());
    auto command_budget = consume_metadata(commands_end_, "macho.load_commands");
    if (!command_budget)
        return workspace_result_t<parse_product_t>::failure(command_budget.error());
    auto commands = parse_load_commands();
    if (!commands)
        return workspace_result_t<parse_product_t>::failure(commands.error());
    auto layout = validate_layout();
    if (!layout)
        return workspace_result_t<parse_product_t>::failure(layout.error());
    auto payloads = process_payloads();
    if (!payloads)
        return workspace_result_t<parse_product_t>::failure(payloads.error());
    if (cancel_.stop_requested())
        return workspace_result_t<parse_product_t>::failure(
            make_stop_error(cancel_, "macho.normalize"));
    return normalize();
}

workspace_result_t<void> macho_parser_t::parse_header() {
    if (provider_size_ < 28)
        return workspace_result_t<void>::failure(error(
            workspace_error_code_t::malformed_image,
            "Provider member is smaller than a Mach-O header", "macho.header", 0,
            provider_size_));
    auto magic_value = read_u32(0, "macho.header");
    if (!magic_value)
        return workspace_result_t<void>::failure(magic_value.error());
    switch (magic_value.value()) {
        case macho_magic_32:
            reader_.endian = endian_t::little;
            is_64_bit_ = false;
            break;
        case macho_cigam_32:
            reader_.endian = endian_t::big;
            is_64_bit_ = false;
            break;
        case macho_magic_64:
            reader_.endian = endian_t::little;
            is_64_bit_ = true;
            break;
        case macho_cigam_64:
            reader_.endian = endian_t::big;
            is_64_bit_ = true;
            break;
        default:
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::unsupported_format,
                "Provider member does not contain a thin Mach-O image", "macho.header",
                0, 4));
    }
    header_size_ = is_64_bit_ ? 32U : 28U;
    if (provider_size_ < header_size_)
        return workspace_result_t<void>::failure(error(
            workspace_error_code_t::malformed_image,
            "Mach-O header is truncated", "macho.header", 0, header_size_));
    auto cpu = read_i32(4, "macho.header");
    auto subtype = read_i32(8, "macho.header");
    auto type = read_u32(12, "macho.header");
    auto count = read_u32(16, "macho.header");
    auto command_bytes = read_u32(20, "macho.header");
    auto flags = read_u32(24, "macho.header");
    if (!cpu || !subtype || !type || !count || !command_bytes || !flags)
        return workspace_result_t<void>::failure(error(
            workspace_error_code_t::malformed_image,
            "Mach-O header fields are truncated", "macho.header", 0, header_size_));
    if (is_64_bit_) {
        auto reserved = read_u32(28, "macho.header");
        if (!reserved || reserved.value() != 0)
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::malformed_image,
                "Mach-O 64-bit header reserved field is nonzero",
                "macho.header", 28, 4));
    }
    cpu_type_ = cpu.value();
    cpu_subtype_ = subtype.value();
    file_type_ = type.value();
    header_flags_ = flags.value();
    command_count_ = count.value();
    command_bytes_ = command_bytes.value();
    if (file_type_ == 0 || file_type_ > 12)
        return workspace_result_t<void>::failure(error(
            workspace_error_code_t::malformed_image,
            "Mach-O file type is outside the defined range", "macho.header", 12, 4));
    if (command_count_ > limits_.max_load_commands)
        return workspace_result_t<void>::failure(make_limit_error(
            "Mach-O load-command count exceeds its budget", "macho.header",
            command_count_, limits_.max_load_commands));
    if (command_bytes_ > limits_.max_total_metadata_bytes)
        return workspace_result_t<void>::failure(make_limit_error(
            "Mach-O load-command bytes exceed the metadata budget", "macho.header",
            command_bytes_, limits_.max_total_metadata_bytes));
    if (!checked_add_u64(header_size_, command_bytes_, commands_end_) ||
        commands_end_ > provider_size_)
        return workspace_result_t<void>::failure(error(
            workspace_error_code_t::malformed_image,
            "Mach-O load-command table is truncated or overflowed", "macho.header",
            header_size_, command_bytes_));
    if (command_count_ != 0 && command_bytes_ < 8)
        return workspace_result_t<void>::failure(error(
            workspace_error_code_t::malformed_image,
            "Mach-O load-command table cannot contain its declared commands",
            "macho.header", header_size_, command_bytes_));
    return select_architecture();
}

workspace_result_t<void> macho_parser_t::select_architecture() {
    switch (cpu_type_) {
        case cpu_type_x86:
            architecture_ = architecture_id_t::x86;
            architecture_mode_ = architecture_mode_t::x86_32;
            abi_ = abi_id_t::darwin;
            pointer_size_ = 4;
            break;
        case cpu_type_x86_64:
            architecture_ = architecture_id_t::x86_64;
            architecture_mode_ = architecture_mode_t::x86_64;
            abi_ = abi_id_t::darwin_x86_64;
            pointer_size_ = 8;
            break;
        case cpu_type_arm:
            architecture_ = architecture_id_t::arm;
            architecture_mode_ = architecture_mode_t::arm_a32;
            abi_ = abi_id_t::darwin;
            pointer_size_ = 4;
            break;
        case cpu_type_arm64:
            architecture_ = architecture_id_t::aarch64;
            architecture_mode_ = architecture_mode_t::aarch64;
            abi_ = abi_id_t::darwin_aarch64;
            pointer_size_ = 8;
            break;
        case cpu_type_arm64_32:
            architecture_ = architecture_id_t::aarch64;
            architecture_mode_ = architecture_mode_t::aarch64;
            abi_ = abi_id_t::darwin_aarch64;
            pointer_size_ = 4;
            break;
        case cpu_type_powerpc:
            architecture_ = architecture_id_t::ppc;
            architecture_mode_ = architecture_mode_t::ppc32;
            abi_ = abi_id_t::darwin;
            pointer_size_ = 4;
            break;
        case cpu_type_powerpc64:
            architecture_ = architecture_id_t::ppc64;
            architecture_mode_ = architecture_mode_t::ppc64;
            abi_ = abi_id_t::darwin;
            pointer_size_ = 8;
            break;
        default: {
            auto unsupported = error(
                workspace_error_code_t::unsupported_format,
                "Mach-O CPU type is not representable by the workspace model",
                "macho.header", 4, 4);
            unsupported.details.emplace_back("cputype", std::to_string(cpu_type_));
            return workspace_result_t<void>::failure(std::move(unsupported));
        }
    }
    if ((is_64_bit_ && cpu_type_ != cpu_type_arm64_32 && pointer_size_ != 8) ||
        (!is_64_bit_ && pointer_size_ != 4))
        return workspace_result_t<void>::failure(error(
            workspace_error_code_t::malformed_image,
            "Mach-O magic and CPU address width disagree", "macho.header", 0,
            header_size_));
    return workspace_result_t<void>::success();
}

workspace_result_t<void> macho_parser_t::parse_load_commands() {
    std::uint64_t cursor = header_size_;
    for (std::uint32_t index = 0; index < command_count_; ++index) {
        auto stopped = poll(index, "macho.load_commands");
        if (!stopped)
            return stopped;
        if (cursor > commands_end_ || commands_end_ - cursor < 8)
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::malformed_image,
                "Mach-O load-command header is truncated", "macho.load_commands",
                cursor, commands_end_ - cursor));
        auto command = read_u32(cursor, "macho.load_commands");
        auto size = read_u32(cursor + 4, "macho.load_commands");
        if (!command || !size)
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::malformed_image,
                "Mach-O load-command header is truncated", "macho.load_commands",
                cursor, 8));
        const std::uint32_t alignment = is_64_bit_ ? 8U : 4U;
        const bool kernel_core_thread_alignment =
            is_64_bit_ && file_type_ == mh_core && command.value() == lc_thread &&
            (size.value() % 4U) == 0;
        if (size.value() < 8 ||
            ((size.value() % alignment) != 0 && !kernel_core_thread_alignment) ||
            size.value() > commands_end_ - cursor)
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::malformed_image,
                "Mach-O load command has an invalid bounded size",
                "macho.load_commands", cursor, size.value()));
        auto parsed = parse_load_command(command.value(), cursor, size.value());
        if (!parsed)
            return parsed;
        cursor += size.value();
    }
    if (cursor != commands_end_)
        return workspace_result_t<void>::failure(error(
            workspace_error_code_t::malformed_image,
            "Mach-O load-command sizes do not consume sizeofcmds exactly",
            "macho.load_commands", cursor, commands_end_ - cursor));
    return workspace_result_t<void>::success();
}

workspace_result_t<void> macho_parser_t::parse_load_command(
    std::uint32_t command, std::uint64_t offset, std::uint32_t size) {
    std::optional<std::uint32_t> singleton_key;
    switch (command) {
        case lc_symseg:
        case lc_id_fvmlib:
        case lc_ident:
        case lc_prepage:
        case lc_unixthread:
        case lc_twolevel_hints:
        case lc_prebind_checksum:
        case lc_uuid:
        case lc_id_dylib:
        case lc_id_dylinker:
        case lc_load_dylinker:
        case lc_code_signature:
        case lc_segment_split_info:
        case lc_dylib_code_sign_drs:
        case lc_linker_optimization_hint:
        case lc_source_version:
        case lc_build_version:
            singleton_key = command;
            break;
        case lc_version_min_macosx:
        case lc_version_min_iphoneos:
        case lc_version_min_tvos:
        case lc_version_min_watchos:
            singleton_key = lc_version_min_macosx;
            break;
        case lc_encryption_info:
        case lc_encryption_info_64:
            singleton_key = lc_encryption_info;
            break;
        case lc_routines:
        case lc_routines_64:
            singleton_key = lc_routines;
            break;
        default:
            break;
    }
    if (singleton_key && !singleton_commands_.insert(*singleton_key).second)
        return workspace_result_t<void>::failure(error(
            workspace_error_code_t::malformed_image,
            "Mach-O contains a duplicate singleton load command",
            "macho.load_commands", offset, size));
    switch (command) {
        case lc_segment:
            if (is_64_bit_)
                return workspace_result_t<void>::failure(error(
                    workspace_error_code_t::malformed_image,
                    "LC_SEGMENT is invalid in a 64-bit Mach-O image",
                    "macho.segment", offset, size));
            return parse_segment(offset, size, false);
        case lc_segment_64:
            if (!is_64_bit_)
                return workspace_result_t<void>::failure(error(
                    workspace_error_code_t::malformed_image,
                    "LC_SEGMENT_64 is invalid in a 32-bit Mach-O image",
                    "macho.segment", offset, size));
            return parse_segment(offset, size, true);
        case lc_symtab:
            return parse_symtab_command(offset, size);
        case lc_dysymtab:
            return parse_dysymtab_command(offset, size);
        case lc_load_dylib:
        case lc_id_dylib:
        case lc_reexport_dylib:
        case lc_lazy_load_dylib:
        case lc_load_upward_dylib:
        case lc_load_weak_dylib:
            return parse_dylib_command(command, offset, size);
        case lc_dyld_info:
        case lc_dyld_info_only:
            return parse_dyld_info_command(offset, size);
        case lc_code_signature:
        case lc_segment_split_info:
        case lc_dylib_code_sign_drs:
        case lc_linker_optimization_hint:
        case lc_dyld_exports_trie:
        case lc_dyld_chained_fixups:
        case lc_function_starts:
        case lc_data_in_code:
            return parse_linkedit_command(command, offset, size);
        case lc_load_dylinker:
        case lc_id_dylinker:
        case lc_rpath:
        case lc_dyld_environment:
        case lc_sub_framework:
        case lc_sub_umbrella:
        case lc_sub_client:
        case lc_sub_library:
            return parse_string_command(command, offset, size);
        default:
            return parse_misc_command(command, offset, size);
    }
}

workspace_result_t<void> macho_parser_t::parse_segment(
    std::uint64_t offset, std::uint32_t size, bool is_64_bit) {
    const std::uint64_t fixed_size = is_64_bit ? 72U : 56U;
    const std::uint64_t section_size = is_64_bit ? 80U : 68U;
    if (size < fixed_size)
        return workspace_result_t<void>::failure(error(
            workspace_error_code_t::malformed_image,
            "Mach-O segment command is truncated", "macho.segment", offset, size));
    if (segments_.size() >= limits_.max_segments)
        return workspace_result_t<void>::failure(make_limit_error(
            "Mach-O segment count exceeds its budget", "macho.segment",
            segments_.size() + 1U, limits_.max_segments));
    auto name = read_fixed_string(offset + 8, 16, "macho.segment");
    if (!name)
        return workspace_result_t<void>::failure(name.error());
    segment_record_t segment;
    segment.index = static_cast<std::uint32_t>(segments_.size());
    segment.name = name.take_value();
    workspace_result_t<std::uint32_t> section_count =
        workspace_result_t<std::uint32_t>::success(0);
    if (is_64_bit) {
        auto vm_address = read_u64(offset + 24, "macho.segment");
        auto vm_size = read_u64(offset + 32, "macho.segment");
        auto file_offset = read_u64(offset + 40, "macho.segment");
        auto file_size = read_u64(offset + 48, "macho.segment");
        auto max_protection = read_i32(offset + 56, "macho.segment");
        auto initial_protection = read_i32(offset + 60, "macho.segment");
        section_count = read_u32(offset + 64, "macho.segment");
        auto flags = read_u32(offset + 68, "macho.segment");
        if (!vm_address || !vm_size || !file_offset || !file_size ||
            !max_protection || !initial_protection || !section_count || !flags)
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::malformed_image,
                "Mach-O 64-bit segment fields are truncated", "macho.segment",
                offset, size));
        segment.vm_address = vm_address.value();
        segment.vm_size = vm_size.value();
        segment.file_offset = file_offset.value();
        segment.file_size = file_size.value();
        segment.max_protection = max_protection.value();
        segment.initial_protection = initial_protection.value();
        segment.flags = flags.value();
    } else {
        auto vm_address = read_u32(offset + 24, "macho.segment");
        auto vm_size = read_u32(offset + 28, "macho.segment");
        auto file_offset = read_u32(offset + 32, "macho.segment");
        auto file_size = read_u32(offset + 36, "macho.segment");
        auto max_protection = read_i32(offset + 40, "macho.segment");
        auto initial_protection = read_i32(offset + 44, "macho.segment");
        section_count = read_u32(offset + 48, "macho.segment");
        auto flags = read_u32(offset + 52, "macho.segment");
        if (!vm_address || !vm_size || !file_offset || !file_size ||
            !max_protection || !initial_protection || !section_count || !flags)
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::malformed_image,
                "Mach-O 32-bit segment fields are truncated", "macho.segment",
                offset, size));
        segment.vm_address = vm_address.value();
        segment.vm_size = vm_size.value();
        segment.file_offset = file_offset.value();
        segment.file_size = file_size.value();
        segment.max_protection = max_protection.value();
        segment.initial_protection = initial_protection.value();
        segment.flags = flags.value();
    }
    if (section_count.value() > limits_.max_sections_per_segment)
        return workspace_result_t<void>::failure(make_limit_error(
            "Mach-O per-segment section count exceeds its budget", "macho.segment",
            section_count.value(), limits_.max_sections_per_segment));
    if (section_count.value() > limits_.max_sections - sections_.size())
        return workspace_result_t<void>::failure(make_limit_error(
            "Mach-O aggregate section count exceeds its budget", "macho.segment",
            sections_.size() + section_count.value(), limits_.max_sections));
    std::uint64_t section_bytes = 0;
    std::uint64_t required_size = 0;
    if (!checked_mul_u64(section_count.value(), section_size, section_bytes) ||
        !checked_add_u64(fixed_size, section_bytes, required_size) ||
        required_size != size)
        return workspace_result_t<void>::failure(error(
            workspace_error_code_t::malformed_image,
            "Mach-O segment command size does not match its section table",
            "macho.segment", offset, size));
    if (segment.file_size > segment.vm_size)
        return workspace_result_t<void>::failure(error(
            workspace_error_code_t::malformed_image,
            "Mach-O segment file extent exceeds its virtual extent",
            "macho.segment", offset, size));
    if ((segment.initial_protection & ~segment.max_protection) != 0)
        return workspace_result_t<void>::failure(error(
            workspace_error_code_t::malformed_image,
            "Mach-O segment initial protection exceeds its maximum protection",
            "macho.segment", offset, size));
    if (segment.file_size != 0) {
        auto file_span = absolute_range(segment.file_offset, segment.file_size,
                                        "macho.segment.file_range");
        if (!file_span)
            return workspace_result_t<void>::failure(file_span.error());
    }
    std::uint64_t segment_vm_end = 0;
    if (!checked_add_u64(segment.vm_address, segment.vm_size, segment_vm_end))
        return workspace_result_t<void>::failure(error(
            workspace_error_code_t::range_overflow,
            "Mach-O segment virtual range overflowed", "macho.segment",
            offset, size));
    const std::uint32_t permissions =
        ((segment.initial_protection & 1) != 0 ? image_permission_read : 0U) |
        ((segment.initial_protection & 2) != 0 ? image_permission_write : 0U) |
        ((segment.initial_protection & 4) != 0 ? image_permission_execute : 0U);
    const std::size_t first_section = sections_.size();
    bool saw_zero_fill = false;
    bool saw_gigabyte_zero_fill = false;
    for (std::uint32_t index = 0; index < section_count.value(); ++index) {
        auto stopped = poll(index, "macho.sections");
        if (!stopped)
            return stopped;
        const std::uint64_t section_offset = offset + fixed_size +
                                             static_cast<std::uint64_t>(index) * section_size;
        auto section_name = read_fixed_string(section_offset, 16, "macho.sections");
        auto segment_name = read_fixed_string(section_offset + 16, 16, "macho.sections");
        if (!section_name || !segment_name)
            return workspace_result_t<void>::failure(
                !section_name ? section_name.error() : segment_name.error());
        section_record_t section;
        section.index = static_cast<std::uint32_t>(sections_.size());
        section.segment_index = segment.index;
        section.section_name = section_name.take_value();
        section.segment_name = segment_name.take_value();
        section.permissions = permissions;
        std::uint32_t alignment_power = 0;
        if (is_64_bit) {
            auto vm_address = read_u64(section_offset + 32, "macho.sections");
            auto section_extent = read_u64(section_offset + 40, "macho.sections");
            auto file_offset = read_u32(section_offset + 48, "macho.sections");
            auto alignment = read_u32(section_offset + 52, "macho.sections");
            auto relocation_offset = read_u32(section_offset + 56, "macho.sections");
            auto relocation_count = read_u32(section_offset + 60, "macho.sections");
            auto flags = read_u32(section_offset + 64, "macho.sections");
            auto reserved1 = read_u32(section_offset + 68, "macho.sections");
            auto reserved2 = read_u32(section_offset + 72, "macho.sections");
            auto reserved3 = read_u32(section_offset + 76, "macho.sections");
            if (!vm_address || !section_extent || !file_offset || !alignment ||
                !relocation_offset || !relocation_count || !flags || !reserved1 ||
                !reserved2 || !reserved3)
                return workspace_result_t<void>::failure(error(
                    workspace_error_code_t::malformed_image,
                    "Mach-O 64-bit section record is truncated", "macho.sections",
                    section_offset, section_size));
            section.vm_address = vm_address.value();
            section.size = section_extent.value();
            section.file_offset = file_offset.value();
            alignment_power = alignment.value();
            section.relocation_offset = relocation_offset.value();
            section.relocation_count = relocation_count.value();
            section.flags = flags.value();
            if (reserved3.value() != 0)
                return workspace_result_t<void>::failure(error(
                    workspace_error_code_t::malformed_image,
                    "Mach-O 64-bit section reserved field is nonzero",
                    "macho.sections", section_offset, section_size));
        } else {
            auto vm_address = read_u32(section_offset + 32, "macho.sections");
            auto section_extent = read_u32(section_offset + 36, "macho.sections");
            auto file_offset = read_u32(section_offset + 40, "macho.sections");
            auto alignment = read_u32(section_offset + 44, "macho.sections");
            auto relocation_offset = read_u32(section_offset + 48, "macho.sections");
            auto relocation_count = read_u32(section_offset + 52, "macho.sections");
            auto flags = read_u32(section_offset + 56, "macho.sections");
            auto reserved1 = read_u32(section_offset + 60, "macho.sections");
            auto reserved2 = read_u32(section_offset + 64, "macho.sections");
            if (!vm_address || !section_extent || !file_offset || !alignment ||
                !relocation_offset || !relocation_count || !flags || !reserved1 ||
                !reserved2)
                return workspace_result_t<void>::failure(error(
                    workspace_error_code_t::malformed_image,
                    "Mach-O 32-bit section record is truncated", "macho.sections",
                    section_offset, section_size));
            section.vm_address = vm_address.value();
            section.size = section_extent.value();
            section.file_offset = file_offset.value();
            alignment_power = alignment.value();
            section.relocation_offset = relocation_offset.value();
            section.relocation_count = relocation_count.value();
            section.flags = flags.value();
        }
        if (section.segment_name != segment.name)
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::malformed_image,
                "Mach-O section segment name disagrees with its command",
                "macho.sections", section_offset, section_size));
        const bool zero_fill = zero_fill_section(section.flags);
        const bool gigabyte_zero_fill =
            (section.flags & section_type_mask) == s_gb_zerofill;
        if (!zero_fill && saw_zero_fill)
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::malformed_image,
                "Mach-O file-backed section follows a zero-fill section",
                "macho.sections", section_offset, section_size));
        saw_zero_fill = saw_zero_fill || zero_fill;
        saw_gigabyte_zero_fill = saw_gigabyte_zero_fill || gigabyte_zero_fill;
        if (alignment_power >= (is_64_bit ? 64U : 32U))
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::malformed_image,
                "Mach-O section alignment exponent is invalid", "macho.sections",
                section_offset, section_size));
        const std::uint64_t section_alignment = 1ULL << alignment_power;
        if ((section.vm_address % section_alignment) != 0 ||
             (!zero_fill &&
              (section.file_offset % section_alignment) != 0))
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::malformed_image,
                "Mach-O section violates its declared alignment",
                "macho.sections", section_offset, section_size));
        std::uint64_t section_vm_end = 0;
        if (!checked_add_u64(section.vm_address, section.size, section_vm_end) ||
            section.vm_address < segment.vm_address || section_vm_end > segment_vm_end)
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::malformed_image,
                "Mach-O section virtual range escapes its segment", "macho.sections",
                section_offset, section_size));
        section.file_size = zero_fill ? 0 : section.size;
        if (section.file_size != 0) {
            auto section_file = absolute_range(section.file_offset, section.file_size,
                                               "macho.sections.file_range");
            if (!section_file)
                return workspace_result_t<void>::failure(section_file.error());
            checked_span_t segment_file{segment.file_offset, segment.file_size};
            checked_span_t data_file{section.file_offset, section.file_size};
            if (!segment_file.contains(data_file))
                return workspace_result_t<void>::failure(error(
                    workspace_error_code_t::malformed_image,
                    "Mach-O section file range escapes its segment", "macho.sections",
                    section.file_offset, section.file_size));
            const std::uint64_t mapped_delta =
                (segment.flags & sg_highvm) != 0
                ? segment.vm_size - segment.file_size +
                      (section.file_offset - segment.file_offset)
                : section.file_offset - segment.file_offset;
            std::uint64_t expected_vm_address = 0;
            if (!checked_add_u64(segment.vm_address, mapped_delta,
                                 expected_vm_address) ||
                expected_vm_address != section.vm_address)
                return workspace_result_t<void>::failure(error(
                    workspace_error_code_t::malformed_image,
                    "Mach-O section file and virtual offsets disagree",
                    "macho.sections", section.file_offset, section.file_size));
        }
        if ((section.flags & (section_attr_pure_instructions |
                              section_attr_some_instructions)) != 0)
            section.permissions |= image_permission_execute;
        for (std::size_t previous_index = first_section;
             previous_index < sections_.size(); ++previous_index) {
            const auto& previous = sections_[previous_index];
            checked_span_t previous_vm{previous.vm_address, previous.size};
            checked_span_t current_vm{section.vm_address, section.size};
            if (previous.size != 0 && section.size != 0 &&
                previous_vm.overlaps(current_vm))
                return workspace_result_t<void>::failure(error(
                    workspace_error_code_t::malformed_image,
                    "Mach-O sections overlap in virtual address space",
                    "macho.sections", section_offset, section_size));
            checked_span_t previous_file{previous.file_offset, previous.file_size};
            checked_span_t current_file{section.file_offset, section.file_size};
            if (previous.file_size != 0 && section.file_size != 0 &&
                previous_file.overlaps(current_file))
                return workspace_result_t<void>::failure(error(
                    workspace_error_code_t::malformed_image,
                    "Mach-O sections overlap in file address space",
                    "macho.sections", section_offset, section_size));
        }
        sections_.push_back(std::move(section));
    }
    if (saw_gigabyte_zero_fill) {
        for (std::size_t index = first_section; index < sections_.size(); ++index) {
            if ((sections_[index].flags & section_type_mask) != s_gb_zerofill)
                return workspace_result_t<void>::failure(error(
                    workspace_error_code_t::malformed_image,
                    "Mach-O gigabyte zero-fill segment mixes section types",
                    "macho.sections", offset, size));
        }
    }
    std::uint64_t section_record_bytes = 0;
    if (!checked_mul_u64(section_count.value(), sizeof(section_record_t),
                         section_record_bytes))
        return workspace_result_t<void>::failure(error(
            workspace_error_code_t::range_overflow,
            "Mach-O section metadata allocation accounting overflowed",
            "macho.segment"));
    auto budget = consume_metadata(sizeof(segment_record_t) + section_record_bytes,
                                    "macho.segment");
    if (!budget)
        return budget;
    segments_.push_back(std::move(segment));
    return workspace_result_t<void>::success();
}

workspace_result_t<void> macho_parser_t::parse_symtab_command(
    std::uint64_t offset, std::uint32_t size) {
    if (size != 24 || symtab_)
        return workspace_result_t<void>::failure(error(
            workspace_error_code_t::malformed_image,
            symtab_ ? "Mach-O contains duplicate LC_SYMTAB commands"
                    : "LC_SYMTAB has an invalid size",
            "macho.symtab", offset, size));
    auto symbol_offset = read_u32(offset + 8, "macho.symtab");
    auto symbol_count = read_u32(offset + 12, "macho.symtab");
    auto string_offset = read_u32(offset + 16, "macho.symtab");
    auto string_size = read_u32(offset + 20, "macho.symtab");
    if (!symbol_offset || !symbol_count || !string_offset || !string_size)
        return workspace_result_t<void>::failure(error(
            workspace_error_code_t::malformed_image,
            "LC_SYMTAB fields are truncated", "macho.symtab", offset, size));
    if (symbol_count.value() > limits_.max_symbols)
        return workspace_result_t<void>::failure(make_limit_error(
            "Mach-O symbol count exceeds its budget", "macho.symtab",
            symbol_count.value(), limits_.max_symbols));
    symtab_ = symtab_descriptor_t{symbol_offset.value(), symbol_count.value(),
                                 string_offset.value(), string_size.value()};
    return workspace_result_t<void>::success();
}

workspace_result_t<void> macho_parser_t::parse_dysymtab_command(
    std::uint64_t offset, std::uint32_t size) {
    if (size != 80 || dysymtab_)
        return workspace_result_t<void>::failure(error(
            workspace_error_code_t::malformed_image,
            dysymtab_ ? "Mach-O contains duplicate LC_DYSYMTAB commands"
                      : "LC_DYSYMTAB has an invalid size",
            "macho.dysymtab", offset, size));
    dysymtab_descriptor_t descriptor;
    auto local_index = read_u32(offset + 8, "macho.dysymtab");
    auto local_count = read_u32(offset + 12, "macho.dysymtab");
    auto external_index = read_u32(offset + 16, "macho.dysymtab");
    auto external_count = read_u32(offset + 20, "macho.dysymtab");
    auto undefined_index = read_u32(offset + 24, "macho.dysymtab");
    auto undefined_count = read_u32(offset + 28, "macho.dysymtab");
    auto toc_offset = read_u32(offset + 32, "macho.dysymtab");
    auto toc_count = read_u32(offset + 36, "macho.dysymtab");
    auto module_offset = read_u32(offset + 40, "macho.dysymtab");
    auto module_count = read_u32(offset + 44, "macho.dysymtab");
    auto reference_offset = read_u32(offset + 48, "macho.dysymtab");
    auto reference_count = read_u32(offset + 52, "macho.dysymtab");
    auto indirect_offset = read_u32(offset + 56, "macho.dysymtab");
    auto indirect_count = read_u32(offset + 60, "macho.dysymtab");
    auto external_relocation_offset = read_u32(offset + 64, "macho.dysymtab");
    auto external_relocation_count = read_u32(offset + 68, "macho.dysymtab");
    auto local_relocation_offset = read_u32(offset + 72, "macho.dysymtab");
    auto local_relocation_count = read_u32(offset + 76, "macho.dysymtab");
    if (!local_index || !local_count || !external_index || !external_count ||
        !undefined_index || !undefined_count || !toc_offset || !toc_count ||
        !module_offset || !module_count || !reference_offset || !reference_count ||
        !indirect_offset || !indirect_count ||
        !external_relocation_offset || !external_relocation_count ||
        !local_relocation_offset || !local_relocation_count)
        return workspace_result_t<void>::failure(error(
            workspace_error_code_t::malformed_image,
            "LC_DYSYMTAB fields are truncated", "macho.dysymtab", offset, size));
    descriptor.local_index = local_index.value();
    descriptor.local_count = local_count.value();
    descriptor.external_index = external_index.value();
    descriptor.external_count = external_count.value();
    descriptor.undefined_index = undefined_index.value();
    descriptor.undefined_count = undefined_count.value();
    descriptor.toc_offset = toc_offset.value();
    descriptor.toc_count = toc_count.value();
    descriptor.module_offset = module_offset.value();
    descriptor.module_count = module_count.value();
    descriptor.external_reference_offset = reference_offset.value();
    descriptor.external_reference_count = reference_count.value();
    descriptor.indirect_offset = indirect_offset.value();
    descriptor.indirect_count = indirect_count.value();
    descriptor.external_relocation_offset = external_relocation_offset.value();
    descriptor.external_relocation_count = external_relocation_count.value();
    descriptor.local_relocation_offset = local_relocation_offset.value();
    descriptor.local_relocation_count = local_relocation_count.value();
    dysymtab_ = descriptor;
    return workspace_result_t<void>::success();
}

workspace_result_t<void> macho_parser_t::parse_dylib_command(
    std::uint32_t command, std::uint64_t offset, std::uint32_t size) {
    if (size < 24)
        return workspace_result_t<void>::failure(error(
            workspace_error_code_t::malformed_image,
            "Mach-O dylib command is truncated", "macho.dylib", offset, size));
    if (command == lc_id_dylib && file_type_ != mh_dylib &&
        file_type_ != mh_dylib_stub)
        return workspace_result_t<void>::failure(error(
            workspace_error_code_t::malformed_image,
            "LC_ID_DYLIB is present in a non-dylib image", "macho.dylib",
            offset, size));
    auto name_offset = read_u32(offset + 8, "macho.dylib");
    if (!name_offset || name_offset.value() < 24 || name_offset.value() >= size)
        return workspace_result_t<void>::failure(error(
            workspace_error_code_t::malformed_image,
            "Mach-O dylib name offset escapes its load command", "macho.dylib",
            offset, size));
    auto name = read_cstring(offset + name_offset.value(), size - name_offset.value(),
                             "macho.dylib");
    if (!name)
        return workspace_result_t<void>::failure(name.error());
    if (name.value().empty())
        return workspace_result_t<void>::failure(error(
            workspace_error_code_t::malformed_image,
            "Mach-O dylib name is empty", "macho.dylib",
            offset + name_offset.value(), 1));
    auto prefix_padding = validate_zero_padding(offset + 24,
                                                name_offset.value() - 24,
                                                "macho.dylib");
    if (!prefix_padding)
        return prefix_padding;
    const std::uint64_t suffix_start = name_offset.value() + name.value().size() + 1U;
    auto suffix_padding = validate_zero_padding(offset + suffix_start,
                                                size - suffix_start,
                                                "macho.dylib");
    if (!suffix_padding)
        return suffix_padding;
    if (command != lc_id_dylib) {
        if (dependencies_.size() >= limits_.max_dylib_dependencies)
            return workspace_result_t<void>::failure(make_limit_error(
                "Mach-O dependency count exceeds its budget", "macho.dylib",
                dependencies_.size() + 1U, limits_.max_dylib_dependencies));
        dependencies_.push_back({name.take_value()});
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<void> macho_parser_t::parse_dyld_info_command(
    std::uint64_t offset, std::uint32_t size) {
    if (size != 48 || dyld_info_)
        return workspace_result_t<void>::failure(error(
            workspace_error_code_t::malformed_image,
            dyld_info_ ? "Mach-O contains duplicate dyld-info commands"
                       : "Mach-O dyld-info command has an invalid size",
            "macho.dyld_info", offset, size));
    std::array<std::uint32_t, 10> fields{};
    for (std::uint32_t index = 0; index < fields.size(); ++index) {
        auto field = read_u32(offset + 8U + index * 4U, "macho.dyld_info");
        if (!field)
            return workspace_result_t<void>::failure(field.error());
        fields[index] = field.value();
    }
    dyld_info_ = dyld_info_descriptor_t{
        fields[0], fields[1], fields[2], fields[3], fields[4],
        fields[5], fields[6], fields[7], fields[8], fields[9]};
    return workspace_result_t<void>::success();
}

workspace_result_t<void> macho_parser_t::parse_linkedit_command(
    std::uint32_t command, std::uint64_t offset, std::uint32_t size) {
    if (size != 16)
        return workspace_result_t<void>::failure(error(
            workspace_error_code_t::malformed_image,
            "Mach-O link-edit command has an invalid size", "macho.linkedit",
            offset, size));
    if (command == lc_linker_optimization_hint && file_type_ != mh_object)
        return workspace_result_t<void>::failure(error(
            workspace_error_code_t::malformed_image,
            "LC_LINKER_OPTIMIZATION_HINT is present outside an object file",
            "macho.linkedit", offset, size));
    auto data_offset = read_u32(offset + 8, "macho.linkedit");
    auto data_size = read_u32(offset + 12, "macho.linkedit");
    if (!data_offset || !data_size)
        return workspace_result_t<void>::failure(error(
            workspace_error_code_t::malformed_image,
            "Mach-O link-edit command is truncated", "macho.linkedit", offset,
            size));
    if ((data_offset.value() == 0) != (data_size.value() == 0))
        return workspace_result_t<void>::failure(error(
            workspace_error_code_t::malformed_image,
            "Mach-O link-edit command has a partial null range", "macho.linkedit",
            offset, size));
    linkedit_descriptor_t descriptor{data_offset.value(), data_size.value()};
    std::optional<linkedit_descriptor_t>* destination = nullptr;
    std::string label;
    switch (command) {
        case lc_dyld_exports_trie:
            destination = &exports_trie_;
            label = "exports_trie";
            break;
        case lc_dyld_chained_fixups:
            destination = &chained_fixups_;
            label = "chained_fixups";
            break;
        case lc_function_starts:
            destination = &function_starts_;
            label = "function_starts";
            break;
        case lc_data_in_code:
            destination = &data_in_code_;
            label = "data_in_code";
            break;
        default:
            if (command == lc_code_signature)
                label = "code_signature";
            else if (command == lc_dylib_code_sign_drs)
                label = "code_sign_drs";
            else if (command == lc_segment_split_info)
                label = "segment_split_info";
            else
                label = "linker_optimization_hint";
            return register_metadata_range(descriptor.offset, descriptor.size,
                                           std::move(label));
    }
    if (*destination)
        return workspace_result_t<void>::failure(error(
            workspace_error_code_t::malformed_image,
            "Mach-O contains a duplicate singleton link-edit command",
            "macho.linkedit", offset, size));
    *destination = descriptor;
    return workspace_result_t<void>::success();
}

workspace_result_t<void> macho_parser_t::parse_string_command(
    std::uint32_t command, std::uint64_t offset, std::uint32_t size) {
    if (size < 12)
        return workspace_result_t<void>::failure(error(
            workspace_error_code_t::malformed_image,
            "Mach-O string load command is truncated", "macho.load_string",
            offset, size));
    if (command == lc_id_dylinker && file_type_ != mh_dylinker)
        return workspace_result_t<void>::failure(error(
            workspace_error_code_t::malformed_image,
            "LC_ID_DYLINKER is present outside a dynamic linker image",
            "macho.load_string", offset, size));
    if (command == lc_load_dylinker && file_type_ != mh_execute)
        return workspace_result_t<void>::failure(error(
            workspace_error_code_t::malformed_image,
            "LC_LOAD_DYLINKER is present outside an executable image",
            "macho.load_string", offset, size));
    auto string_offset = read_u32(offset + 8, "macho.load_string");
    if (!string_offset || string_offset.value() < 12 || string_offset.value() >= size)
        return workspace_result_t<void>::failure(error(
            workspace_error_code_t::malformed_image,
            "Mach-O load-command string offset escapes its command",
            "macho.load_string", offset, size));
    auto value = read_cstring(offset + string_offset.value(), size - string_offset.value(),
                              "macho.load_string");
    if (!value)
        return workspace_result_t<void>::failure(value.error());
    auto prefix_padding = validate_zero_padding(offset + 12,
                                                string_offset.value() - 12,
                                                "macho.load_string");
    if (!prefix_padding)
        return prefix_padding;
    const std::uint64_t suffix_start = string_offset.value() + value.value().size() + 1U;
    return validate_zero_padding(offset + suffix_start, size - suffix_start,
                                 "macho.load_string");
}

workspace_result_t<void> macho_parser_t::parse_misc_command(
    std::uint32_t command, std::uint64_t offset, std::uint32_t size) {
    if (command == lc_symseg || command == lc_twolevel_hints) {
        if (size != 16)
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::malformed_image,
                "Mach-O auxiliary table command has an invalid size",
                "macho.auxiliary", offset, size));
        auto table_offset = read_u32(offset + 8, "macho.auxiliary");
        auto size_or_count = read_u32(offset + 12, "macho.auxiliary");
        if (!table_offset || !size_or_count)
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::malformed_image,
                "Mach-O auxiliary table command is truncated",
                "macho.auxiliary", offset, size));
        std::uint64_t table_size = size_or_count.value();
        if (command == lc_twolevel_hints &&
            !checked_mul_u64(size_or_count.value(), 4, table_size))
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::range_overflow,
                "Mach-O two-level hint table size overflowed",
                "macho.auxiliary"));
        if (table_size != 0 && (table_offset.value() & 3U) != 0)
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::malformed_image,
                "Mach-O auxiliary table is not naturally aligned",
                "macho.auxiliary", table_offset.value(), table_size));
        return register_metadata_range(
            table_offset.value(), table_size,
            command == lc_symseg ? "symbol_segment" : "twolevel_hints");
    }
    if (command == lc_load_fvmlib || command == lc_id_fvmlib ||
        command == lc_fvmfile) {
        const std::uint32_t fixed_size = command == lc_fvmfile ? 16U : 20U;
        if (size < fixed_size)
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::malformed_image,
                "Mach-O fixed-VM command is truncated", "macho.fixed_vm",
                offset, size));
        if (command == lc_id_fvmlib && file_type_ != mh_fvmlib)
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::malformed_image,
                "LC_IDFVMLIB is present outside a fixed-VM library",
                "macho.fixed_vm", offset, size));
        auto name_offset = read_u32(offset + 8, "macho.fixed_vm");
        if (!name_offset || name_offset.value() < fixed_size ||
            name_offset.value() >= size)
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::malformed_image,
                "Mach-O fixed-VM name escapes its command", "macho.fixed_vm",
                offset, size));
        auto name = read_cstring(offset + name_offset.value(),
                                 size - name_offset.value(), "macho.fixed_vm");
        if (!name)
            return workspace_result_t<void>::failure(name.error());
        auto prefix = validate_zero_padding(offset + fixed_size,
                                            name_offset.value() - fixed_size,
                                            "macho.fixed_vm");
        if (!prefix)
            return prefix;
        const std::uint64_t suffix = name_offset.value() + name.value().size() + 1U;
        return validate_zero_padding(offset + suffix, size - suffix,
                                     "macho.fixed_vm");
    }
    if (command == lc_ident) {
        std::uint64_t cursor = offset + 8U;
        const std::uint64_t end = offset + size;
        while (cursor < end) {
            auto value = read_u8(cursor, "macho.ident");
            if (!value)
                return workspace_result_t<void>::failure(value.error());
            if (value.value() == 0) {
                ++cursor;
                continue;
            }
            auto text = read_cstring(cursor, end - cursor, "macho.ident");
            if (!text)
                return workspace_result_t<void>::failure(text.error());
            cursor += text.value().size() + 1U;
        }
        return workspace_result_t<void>::success();
    }
    if (command == lc_prepage) {
        if (size != 8)
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::malformed_image,
                "LC_PREPAGE has an invalid size", "macho.prepage", offset,
                size));
        return workspace_result_t<void>::success();
    }
    if (command == lc_prebind_checksum) {
        if (size != 12)
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::malformed_image,
                "LC_PREBIND_CKSUM has an invalid size", "macho.prebind_checksum",
                offset, size));
        return workspace_result_t<void>::success();
    }
    if (command == lc_main) {
        if (size != 24 || main_entry_offset_)
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::malformed_image,
                main_entry_offset_ ? "Mach-O contains duplicate LC_MAIN commands"
                                   : "LC_MAIN has an invalid size",
                "macho.entry", offset, size));
        if (file_type_ != mh_execute)
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::malformed_image,
                "LC_MAIN is present in a non-executable image", "macho.entry",
                offset, size));
        auto entry = read_u64(offset + 8, "macho.entry");
        if (!entry)
            return workspace_result_t<void>::failure(entry.error());
        main_entry_offset_ = entry.value();
        return workspace_result_t<void>::success();
    }
    if (command == lc_thread || command == lc_unixthread) {
        if (size < 16)
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::malformed_image,
                "Mach-O thread-state command is truncated", "macho.thread",
                offset, size));
        if (thread_commands_.size() >= limits_.max_thread_states)
            return workspace_result_t<void>::failure(make_limit_error(
                "Mach-O thread-state command count exceeds its budget", "macho.thread",
                thread_commands_.size() + 1U, limits_.max_thread_states));
        thread_commands_.push_back({command, offset, size});
        return workspace_result_t<void>::success();
    }
    if (command == lc_encryption_info || command == lc_encryption_info_64) {
        const std::uint32_t minimum = command == lc_encryption_info_64 ? 24U : 20U;
        if (size != minimum)
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::malformed_image,
                "Mach-O encryption-info command has an invalid size",
                "macho.encryption", offset, size));
        if ((command == lc_encryption_info_64) != is_64_bit_)
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::malformed_image,
                "Mach-O encryption-info command disagrees with the image width",
                "macho.encryption", offset, size));
        auto crypt_offset = read_u32(offset + 8, "macho.encryption");
        auto crypt_size = read_u32(offset + 12, "macho.encryption");
        if (!crypt_offset || !crypt_size)
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::malformed_image,
                "Mach-O encryption-info command is truncated", "macho.encryption",
                offset, size));
        if (crypt_size.value() != 0) {
            auto crypt = absolute_range(crypt_offset.value(), crypt_size.value(),
                                        "macho.encryption");
            if (!crypt)
                return workspace_result_t<void>::failure(crypt.error());
        }
        if (command == lc_encryption_info_64) {
            auto padding = read_u32(offset + 20, "macho.encryption");
            if (!padding || padding.value() != 0)
                return workspace_result_t<void>::failure(error(
                    workspace_error_code_t::malformed_image,
                    "LC_ENCRYPTION_INFO_64 padding is nonzero",
                    "macho.encryption", offset + 20, 4));
        }
        return workspace_result_t<void>::success();
    }
    if (command == lc_uuid) {
        if (size != 24)
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::malformed_image,
                "LC_UUID has an invalid size", "macho.uuid", offset, size));
        auto uuid_bytes = bytes(offset + 8, 16, "macho.uuid");
        if (!uuid_bytes)
            return workspace_result_t<void>::failure(uuid_bytes.error());
        constexpr char digits[] = "0123456789abcdef";
        std::string uuid;
        uuid.reserve(32);
        for (std::uint32_t index = 0; index < 16; ++index) {
            const std::uint8_t value = uuid_bytes.value()[index];
            uuid.push_back(digits[value >> 4U]);
            uuid.push_back(digits[value & 0x0fU]);
        }
        uuid_ = std::move(uuid);
        return workspace_result_t<void>::success();
    }
    if (command == lc_source_version) {
        if (size != 16)
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::malformed_image,
                "LC_SOURCE_VERSION has an invalid size", "macho.version", offset,
                size));
        return workspace_result_t<void>::success();
    }
    if (command == lc_version_min_macosx || command == lc_version_min_iphoneos ||
        command == lc_version_min_tvos || command == lc_version_min_watchos) {
        if (size != 16)
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::malformed_image,
                "Mach-O minimum-version command has an invalid size",
                "macho.version", offset, size));
        return workspace_result_t<void>::success();
    }
    if (command == lc_build_version) {
        if (size < 24)
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::malformed_image,
                "LC_BUILD_VERSION is truncated", "macho.version", offset, size));
        auto tool_count = read_u32(offset + 20, "macho.version");
        std::uint64_t tool_bytes = 0;
        std::uint64_t required = 0;
        if (!tool_count || !checked_mul_u64(tool_count.value(), 8, tool_bytes) ||
            !checked_add_u64(24, tool_bytes, required) || required != size)
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::malformed_image,
                "LC_BUILD_VERSION tool table has an invalid size", "macho.version",
                offset, size));
        return workspace_result_t<void>::success();
    }
    if (command == lc_linker_option) {
        if (size < 12)
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::malformed_image,
                "LC_LINKER_OPTION is truncated", "macho.linker_option", offset,
                size));
        if (file_type_ != mh_object)
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::malformed_image,
                "LC_LINKER_OPTION is present outside an object file",
                "macho.linker_option", offset, size));
        auto count = read_u32(offset + 8, "macho.linker_option");
        if (!count || count.value() > limits_.max_load_commands)
            return workspace_result_t<void>::failure(make_limit_error(
                "Mach-O linker-option count exceeds its budget", "macho.linker_option",
                count ? count.value() : 0, limits_.max_load_commands));
        std::uint64_t cursor = offset + 12;
        const std::uint64_t end = offset + size;
        for (std::uint32_t index = 0; index < count.value(); ++index) {
            if (cursor >= end)
                return workspace_result_t<void>::failure(error(
                    workspace_error_code_t::malformed_image,
                    "LC_LINKER_OPTION string table is truncated",
                    "macho.linker_option", offset, size));
            auto option = read_cstring(cursor, end - cursor, "macho.linker_option");
            if (!option)
                return workspace_result_t<void>::failure(option.error());
            cursor += option.value().size() + 1U;
        }
        return validate_zero_padding(cursor, end - cursor,
                                     "macho.linker_option");
    }
    if (command == lc_note) {
        if (size != 40)
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::malformed_image,
                "LC_NOTE has an invalid size", "macho.note", offset, size));
        auto data_offset = read_u64(offset + 24, "macho.note");
        auto data_size = read_u64(offset + 32, "macho.note");
        if (!data_offset || !data_size)
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::malformed_image,
                "LC_NOTE is truncated", "macho.note", offset, size));
        if (data_size.value() != 0) {
            auto note = absolute_range(data_offset.value(), data_size.value(), "macho.note");
            if (!note)
                return workspace_result_t<void>::failure(note.error());
            return register_metadata_range(data_offset.value(), data_size.value(),
                                           "note");
        }
        return workspace_result_t<void>::success();
    }
    if (command == lc_routines || command == lc_routines_64) {
        const std::uint32_t required = command == lc_routines_64 ? 72U : 40U;
        if (size != required)
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::malformed_image,
                "Mach-O routines command has an invalid size", "macho.routines",
                offset, size));
        if ((command == lc_routines_64) != is_64_bit_)
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::malformed_image,
                "Mach-O routines command disagrees with the image width",
                "macho.routines", offset, size));
        std::uint64_t address = 0;
        if (command == lc_routines_64) {
            auto value = read_u64(offset + 8, "macho.routines");
            if (!value)
                return workspace_result_t<void>::failure(value.error());
            address = value.value();
        } else {
            auto value = read_u32(offset + 8, "macho.routines");
            if (!value)
                return workspace_result_t<void>::failure(value.error());
            address = value.value();
        }
        if (address != 0)
            vm_entry_points_.emplace_back(address, "load-command:routines");
        const std::uint64_t reserved_start = command == lc_routines_64 ? 24U : 16U;
        auto reserved = validate_zero_padding(offset + reserved_start,
                                              size - reserved_start,
                                              "macho.routines");
        if (!reserved)
            return reserved;
        return workspace_result_t<void>::success();
    }
    if (command == lc_fileset_entry) {
        if (size < 32)
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::malformed_image,
                "LC_FILESET_ENTRY is truncated", "macho.fileset", offset, size));
        if (file_type_ != mh_fileset)
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::malformed_image,
                "LC_FILESET_ENTRY is present outside a fileset",
                "macho.fileset", offset, size));
        auto file_offset = read_u64(offset + 16, "macho.fileset");
        auto name_offset = read_u32(offset + 24, "macho.fileset");
        auto reserved = read_u32(offset + 28, "macho.fileset");
        if (!file_offset || !name_offset || !reserved || reserved.value() != 0 ||
            file_offset.value() >= provider_size_ ||
            name_offset.value() < 32 || name_offset.value() >= size)
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::malformed_image,
                "LC_FILESET_ENTRY fields escape the image or command",
                "macho.fileset", offset, size));
        auto identifier = read_cstring(offset + name_offset.value(),
                                       size - name_offset.value(), "macho.fileset");
        if (!identifier)
            return workspace_result_t<void>::failure(identifier.error());
        auto prefix_padding = validate_zero_padding(offset + 32,
                                                    name_offset.value() - 32,
                                                    "macho.fileset");
        if (!prefix_padding)
            return prefix_padding;
        const std::uint64_t suffix_start = name_offset.value() +
                                           identifier.value().size() + 1U;
        return validate_zero_padding(offset + suffix_start, size - suffix_start,
                                     "macho.fileset");
    }
    if (command == lc_prebound_dylib) {
        if (size < 20)
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::malformed_image,
                "LC_PREBOUND_DYLIB is truncated", "macho.prebound", offset, size));
        auto name_offset = read_u32(offset + 8, "macho.prebound");
        auto module_count = read_u32(offset + 12, "macho.prebound");
        auto linked_offset = read_u32(offset + 16, "macho.prebound");
        if (!name_offset || !module_count || !linked_offset ||
            name_offset.value() < 20 || name_offset.value() >= size ||
            module_count.value() > limits_.max_symbols)
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::malformed_image,
                "LC_PREBOUND_DYLIB name escapes its command", "macho.prebound",
                offset, size));
        auto name = read_cstring(offset + name_offset.value(), size - name_offset.value(),
                                 "macho.prebound");
        if (!name)
            return workspace_result_t<void>::failure(name.error());
        const std::uint64_t name_end = name_offset.value() + name.value().size() + 1U;
        const std::uint64_t linked_size =
            (static_cast<std::uint64_t>(module_count.value()) + 7U) / 8U;
        if ((linked_size == 0 && linked_offset.value() != 0) ||
            (linked_size != 0 &&
             (linked_offset.value() < 20 || linked_offset.value() > size ||
              linked_size > size - linked_offset.value())))
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::malformed_image,
                "LC_PREBOUND_DYLIB module vector escapes its command",
                "macho.prebound", offset, size));
        checked_span_t name_span{name_offset.value(), name_end - name_offset.value()};
        checked_span_t linked_span{linked_offset.value(), linked_size};
        if (linked_size != 0 && name_span.overlaps(linked_span))
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::malformed_image,
                "LC_PREBOUND_DYLIB name and module vector overlap",
                "macho.prebound", offset, size));
        std::vector<checked_span_t> payloads{name_span};
        if (linked_size != 0)
            payloads.push_back(linked_span);
        std::sort(payloads.begin(), payloads.end(),
                  [](const checked_span_t& left, const checked_span_t& right) {
                      return left.offset < right.offset;
                  });
        std::uint64_t padding_cursor = 20;
        for (const auto& payload : payloads) {
            if (payload.offset > padding_cursor) {
                auto padding = validate_zero_padding(
                    offset + padding_cursor, payload.offset - padding_cursor,
                    "macho.prebound");
                if (!padding)
                    return padding;
            }
            padding_cursor = payload.offset + payload.size;
        }
        if (padding_cursor < size)
            return validate_zero_padding(offset + padding_cursor,
                                         size - padding_cursor,
                                         "macho.prebound");
    }
    if ((command & 0x80000000U) != 0)
        return workspace_result_t<void>::failure(error(
            workspace_error_code_t::unsupported_format,
            "Mach-O contains an unknown required-dyld load command",
            "macho.load_commands", offset, size));
    return workspace_result_t<void>::success();
}

workspace_result_t<void> macho_parser_t::validate_layout() {
    if (segments_.empty() && file_type_ == mh_dylib_stub) {
        image_base_ = 0;
        image_size_ = commands_end_;
        return workspace_result_t<void>::success();
    }
    if (segments_.empty())
        return workspace_result_t<void>::failure(error(
            workspace_error_code_t::malformed_image,
            "Mach-O image contains no segment commands", "macho.layout"));
    bool have_base = false;
    std::uint64_t maximum_end = 0;
    for (std::size_t index = 0; index < segments_.size(); ++index) {
        const auto& segment = segments_[index];
        const bool guard = segment.file_size == 0 && segment.initial_protection == 0 &&
                           segment.name == "__PAGEZERO";
        if (!guard && segment.vm_size != 0) {
            if (!have_base || segment.vm_address < image_base_)
                image_base_ = segment.vm_address;
            have_base = true;
        }
        std::uint64_t end = 0;
        if (!checked_add_u64(segment.vm_address, segment.vm_size, end))
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::range_overflow,
                "Mach-O segment virtual extent overflowed", "macho.layout"));
        maximum_end = std::max(maximum_end, end);
        for (std::size_t previous_index = 0; previous_index < index; ++previous_index) {
            const auto& previous = segments_[previous_index];
            const bool linkedit_alias =
                (previous.name == "__LINKEDIT" && segment.name == "__LINKINFO") ||
                (previous.name == "__LINKINFO" && segment.name == "__LINKEDIT");
            checked_span_t previous_file{previous.file_offset, previous.file_size};
            checked_span_t current_file{segment.file_offset, segment.file_size};
            if (previous.file_size != 0 && segment.file_size != 0 &&
                previous_file.overlaps(current_file) && !linkedit_alias)
                return workspace_result_t<void>::failure(error(
                    workspace_error_code_t::malformed_image,
                    "Mach-O segments overlap in file address space", "macho.layout",
                    segment.file_offset, segment.file_size));
            checked_span_t previous_vm{previous.vm_address, previous.vm_size};
            checked_span_t current_vm{segment.vm_address, segment.vm_size};
            if (previous.vm_size != 0 && segment.vm_size != 0 &&
                previous_vm.overlaps(current_vm) && !linkedit_alias)
                return workspace_result_t<void>::failure(error(
                    workspace_error_code_t::malformed_image,
                    "Mach-O segments overlap in virtual address space", "macho.layout"));
        }
    }
    if (!have_base || maximum_end < image_base_)
        return workspace_result_t<void>::failure(error(
            workspace_error_code_t::malformed_image,
            "Mach-O image has no representable virtual layout", "macho.layout"));
    if (pointer_size_ == 4 &&
        (image_base_ > 0xffffffffULL || maximum_end > 0x100000000ULL))
        return workspace_result_t<void>::failure(error(
            workspace_error_code_t::malformed_image,
            "Mach-O virtual layout exceeds its 32-bit address width",
            "macho.layout"));
    image_size_ = maximum_end - image_base_;
    image_size_ = std::max(image_size_, commands_end_);
    if (image_size_ == 0)
        return workspace_result_t<void>::failure(error(
            workspace_error_code_t::malformed_image,
            "Mach-O virtual image size is zero", "macho.layout"));
    for (std::size_t index = 0; index < sections_.size(); ++index) {
        const auto& section = sections_[index];
        if (section.size != 0 && !vm_to_rva(section.vm_address, section.size))
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::malformed_image,
                "Mach-O section cannot be normalized into the image",
                "macho.layout", section.file_offset, section.file_size));
        for (std::size_t previous_index = 0; previous_index < index; ++previous_index) {
            const auto& previous = sections_[previous_index];
            checked_span_t previous_vm{previous.vm_address, previous.size};
            checked_span_t current_vm{section.vm_address, section.size};
            if (previous.segment_index != section.segment_index && previous.size != 0 &&
                section.size != 0 && previous_vm.overlaps(current_vm))
                return workspace_result_t<void>::failure(error(
                    workspace_error_code_t::malformed_image,
                    "Mach-O sections from different segments overlap",
                    "macho.layout"));
        }
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<void> macho_parser_t::process_payloads() {
    auto symbols = parse_symbols();
    if (!symbols)
        return symbols;
    auto dynamic_symbols = validate_dynamic_symbol_table();
    if (!dynamic_symbols)
        return dynamic_symbols;
    auto relocation_result = parse_relocations();
    if (!relocation_result)
        return relocation_result;
    if (chained_fixups_ && chained_fixups_->size != 0 && dyld_info_ &&
        (dyld_info_->rebase_size != 0 || dyld_info_->bind_size != 0 ||
         dyld_info_->weak_bind_size != 0 || dyld_info_->lazy_bind_size != 0))
        return workspace_result_t<void>::failure(error(
            workspace_error_code_t::malformed_image,
            "Mach-O mixes classic dyld fixups with chained fixups",
            "macho.fixups"));
    auto dyld = parse_dyld_payloads();
    if (!dyld)
        return dyld;
    auto chained = parse_chained_fixups();
    if (!chained)
        return chained;
    auto starts = parse_function_starts();
    if (!starts)
        return starts;
    auto data = parse_data_in_code();
    if (!data)
        return data;
    auto threads = parse_thread_commands();
    if (!threads)
        return threads;
    auto languages = parse_language_metadata();
    if (!languages)
        return languages;
    if (main_entry_offset_)
        file_entry_points_.emplace_back(*main_entry_offset_, "load-command:main");
    return workspace_result_t<void>::success();
}

workspace_result_t<void> macho_parser_t::parse_symbols() {
    if (!symtab_)
        return workspace_result_t<void>::success();
    const std::uint64_t record_size = is_64_bit_ ? 16U : 12U;
    std::uint64_t symbol_bytes = 0;
    if (!checked_mul_u64(symtab_->symbol_count, record_size, symbol_bytes))
        return workspace_result_t<void>::failure(error(
            workspace_error_code_t::range_overflow,
            "Mach-O symbol table size overflowed", "macho.symtab"));
    if (symtab_->string_size > limits_.max_string_bytes)
        return workspace_result_t<void>::failure(make_limit_error(
            "Mach-O string table exceeds its budget", "macho.symtab",
            symtab_->string_size, limits_.max_string_bytes));
    const std::uint64_t symbol_alignment = is_64_bit_ ? 8U : 4U;
    if (symbol_bytes != 0 &&
        (symtab_->symbol_offset % symbol_alignment) != 0)
        return workspace_result_t<void>::failure(error(
            workspace_error_code_t::malformed_image,
            "Mach-O symbol table is not naturally aligned",
            "macho.symtab", symtab_->symbol_offset, symbol_bytes));
    auto symbol_range = register_metadata_range(symtab_->symbol_offset, symbol_bytes,
                                                "symbol_table");
    if (!symbol_range)
        return symbol_range;
    auto string_range = register_metadata_range(symtab_->string_offset,
                                                symtab_->string_size,
                                                "symbol_strings");
    if (!string_range)
        return string_range;
    auto symbol_data = read_blob(symtab_->symbol_offset, symbol_bytes, "macho.symtab");
    if (!symbol_data)
        return workspace_result_t<void>::failure(symbol_data.error());
    auto strings = read_blob(symtab_->string_offset, symtab_->string_size,
                             "macho.symtab.strings");
    if (!strings)
        return workspace_result_t<void>::failure(strings.error());
    if (!strings.value().empty() && strings.value().front() != 0)
        return workspace_result_t<void>::failure(error(
            workspace_error_code_t::malformed_image,
            "Mach-O string table does not begin with an empty string",
            "macho.symtab.strings", symtab_->string_offset, symtab_->string_size));
    std::uint64_t symbol_record_bytes = 0;
    if (!checked_mul_u64(symtab_->symbol_count, sizeof(symbol_record_t),
                         symbol_record_bytes))
        return workspace_result_t<void>::failure(error(
            workspace_error_code_t::range_overflow,
            "Mach-O symbol metadata allocation accounting overflowed",
            "macho.symtab"));
    auto record_budget = consume_metadata(symbol_record_bytes, "macho.symtab");
    if (!record_budget)
        return record_budget;
    symbols_.reserve(symtab_->symbol_count);
    for (std::uint32_t index = 0; index < symtab_->symbol_count; ++index) {
        auto stopped = poll(index, "macho.symtab");
        if (!stopped)
            return stopped;
        const auto* record = symbol_data.value().data() +
                             static_cast<std::size_t>(index * record_size);
        const std::uint32_t string_index = reader_.u32(record);
        symbol_record_t symbol;
        symbol.ordinal = index;
        symbol.type = record[4];
        symbol.section = record[5];
        symbol.description = reader_.u16(record + 6);
        symbol.value = is_64_bit_ ? reader_.u64(record + 8) : reader_.u32(record + 8);
        if (string_index != 0) {
            if (string_index >= strings.value().size())
                return workspace_result_t<void>::failure(error(
                    workspace_error_code_t::malformed_image,
                    "Mach-O symbol string index escapes the string table",
                    "macho.symtab", symtab_->symbol_offset + index * record_size,
                    record_size));
            const auto* begin = strings.value().data() + string_index;
            const auto* end = strings.value().data() + strings.value().size();
            const auto* terminator = std::find(begin, end, static_cast<std::uint8_t>(0));
            if (terminator == end)
                return workspace_result_t<void>::failure(error(
                    workspace_error_code_t::malformed_image,
                    "Mach-O symbol name is not terminated in the string table",
                    "macho.symtab.strings", symtab_->string_offset + string_index,
                    strings.value().size() - string_index));
            symbol.name.assign(reinterpret_cast<const char*>(begin),
                               static_cast<std::size_t>(terminator - begin));
            auto budget = consume_string(symbol.name.size(), "macho.symtab.names");
            if (!budget)
                return budget;
        }
        const std::uint8_t basic_type = symbol.type & n_type;
        if ((symbol.type & n_stab) == 0 && basic_type == n_sect &&
            (symbol.section == 0 || symbol.section > sections_.size()))
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::malformed_image,
                "Mach-O symbol references an invalid section ordinal",
                "macho.symtab", symtab_->symbol_offset + index * record_size,
                record_size));
        if ((symbol.type & n_stab) == 0 && basic_type == n_sect) {
            const auto& section = sections_[symbol.section - 1U];
            std::uint64_t section_end = 0;
            if (!checked_add_u64(section.vm_address, section.size, section_end) ||
                symbol.value < section.vm_address || symbol.value > section_end)
                return workspace_result_t<void>::failure(error(
                    workspace_error_code_t::malformed_image,
                    "Mach-O symbol value escapes its referenced section",
                    "macho.symtab", symtab_->symbol_offset + index * record_size,
                    record_size));
        }
        symbols_.push_back(std::move(symbol));
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<void> macho_parser_t::validate_dynamic_symbol_table() {
    if (!dysymtab_)
        return workspace_result_t<void>::success();
    if (!symtab_)
        return workspace_result_t<void>::failure(error(
            workspace_error_code_t::malformed_image,
            "LC_DYSYMTAB is present without LC_SYMTAB", "macho.dysymtab"));
    const auto validate_partition = [&](std::uint32_t index, std::uint32_t count,
                                        std::string name) -> workspace_result_t<void> {
        if (index > symbols_.size() || count > symbols_.size() - index) {
            auto partition_error = error(
                workspace_error_code_t::malformed_image,
                "Mach-O dynamic symbol partition escapes LC_SYMTAB",
                "macho.dysymtab");
            partition_error.details.emplace_back("partition", std::move(name));
            return workspace_result_t<void>::failure(std::move(partition_error));
        }
        return workspace_result_t<void>::success();
    };
    auto locals = validate_partition(dysymtab_->local_index, dysymtab_->local_count,
                                     "locals");
    auto external = validate_partition(dysymtab_->external_index,
                                       dysymtab_->external_count, "external");
    auto undefined = validate_partition(dysymtab_->undefined_index,
                                        dysymtab_->undefined_count, "undefined");
    if (!locals || !external || !undefined)
        return !locals ? locals : (!external ? external : undefined);
    std::array<checked_span_t, 3> partitions{{
        {dysymtab_->local_index, dysymtab_->local_count},
        {dysymtab_->external_index, dysymtab_->external_count},
        {dysymtab_->undefined_index, dysymtab_->undefined_count}}};
    for (std::size_t left = 0; left < partitions.size(); ++left) {
        for (std::size_t right = left + 1; right < partitions.size(); ++right) {
            if (partitions[left].size != 0 && partitions[right].size != 0 &&
                partitions[left].overlaps(partitions[right]))
                return workspace_result_t<void>::failure(error(
                    workspace_error_code_t::malformed_image,
                    "Mach-O dynamic symbol partitions overlap", "macho.dysymtab"));
        }
    }
    struct table_t {
        std::uint32_t offset;
        std::uint32_t count;
        std::uint64_t record_size;
        std::uint64_t alignment;
        const char* label;
    };
    const std::array<table_t, 4> tables{{
        {dysymtab_->toc_offset, dysymtab_->toc_count, 8, 4, "dysymtab_toc"},
        {dysymtab_->module_offset, dysymtab_->module_count,
         is_64_bit_ ? 56U : 52U, is_64_bit_ ? 8U : 4U, "dysymtab_modules"},
        {dysymtab_->external_reference_offset,
         dysymtab_->external_reference_count, 4, 4, "dysymtab_extrefs"},
        {dysymtab_->indirect_offset, dysymtab_->indirect_count, 4, 4,
         "dysymtab_indirect"}}};
    for (const auto& table : tables) {
        std::uint64_t bytes_value = 0;
        if (!checked_mul_u64(table.count, table.record_size, bytes_value))
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::range_overflow,
                "Mach-O dynamic symbol table size overflowed", "macho.dysymtab"));
        if (bytes_value != 0 && (table.offset % table.alignment) != 0)
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::malformed_image,
                "Mach-O dynamic symbol table is not naturally aligned",
                "macho.dysymtab", table.offset, bytes_value));
        auto range = register_metadata_range(table.offset, bytes_value, table.label);
        if (!range)
            return range;
    }
    if (dysymtab_->indirect_count > limits_.max_symbols)
        return workspace_result_t<void>::failure(make_limit_error(
            "Mach-O indirect symbol count exceeds its budget", "macho.dysymtab",
            dysymtab_->indirect_count, limits_.max_symbols));
    if (dysymtab_->indirect_count != 0) {
        std::uint64_t indirect_bytes = 0;
        if (!checked_mul_u64(dysymtab_->indirect_count, 4, indirect_bytes))
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::range_overflow,
                "Mach-O indirect symbol table size overflowed",
                "macho.dysymtab.indirect"));
        auto data = read_blob(dysymtab_->indirect_offset, indirect_bytes,
                              "macho.dysymtab.indirect");
        if (!data)
            return workspace_result_t<void>::failure(data.error());
        for (std::uint32_t index = 0; index < dysymtab_->indirect_count; ++index) {
            const std::uint32_t value = reader_.u32(data.value().data() + index * 4U);
            if ((value & 0xc0000000U) == 0 && value >= symbols_.size())
                return workspace_result_t<void>::failure(error(
                    workspace_error_code_t::malformed_image,
                    "Mach-O indirect symbol index escapes LC_SYMTAB",
                    "macho.dysymtab.indirect",
                    dysymtab_->indirect_offset + index * 4U, 4));
        }
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<void> macho_parser_t::parse_relocation_table(
    std::uint64_t offset, std::uint64_t count, const section_record_t* section,
    bool dynamic_table, std::string label) {
    if (count == 0)
        return workspace_result_t<void>::success();
    if (count > limits_.max_relocations - relocations_.size())
        return workspace_result_t<void>::failure(make_limit_error(
            "Mach-O relocation count exceeds its budget", "macho.relocations",
            relocations_.size() + count, limits_.max_relocations));
    std::uint64_t table_size = 0;
    if (!checked_mul_u64(count, 8, table_size))
        return workspace_result_t<void>::failure(error(
            workspace_error_code_t::range_overflow,
            "Mach-O relocation table size overflowed", "macho.relocations"));
    if ((offset & 3U) != 0)
        return workspace_result_t<void>::failure(error(
            workspace_error_code_t::malformed_image,
            "Mach-O relocation table is not naturally aligned",
            "macho.relocations", offset, table_size));
    auto range = register_metadata_range(offset, table_size, label);
    if (!range)
        return range;
    auto data = read_blob(offset, table_size, "macho.relocations");
    if (!data)
        return workspace_result_t<void>::failure(data.error());
    std::uint64_t record_bytes = 0;
    if (!checked_mul_u64(count, sizeof(relocation_record_t), record_bytes))
        return workspace_result_t<void>::failure(error(
            workspace_error_code_t::range_overflow,
            "Mach-O relocation metadata allocation accounting overflowed",
            "macho.relocations"));
    auto record_budget = consume_metadata(record_bytes, "macho.relocations");
    if (!record_budget)
        return record_budget;
    std::uint64_t dynamic_base = 0;
    if (dynamic_table) {
        if (segments_.empty())
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::malformed_image,
                "Mach-O dynamic relocations have no segment base",
                "macho.relocations"));
        const segment_record_t* base_segment = &segments_.front();
        if ((header_flags_ & mh_split_segs) != 0) {
            base_segment = nullptr;
            for (const auto& candidate : segments_) {
                if ((candidate.initial_protection & 2) != 0) {
                    base_segment = &candidate;
                    break;
                }
            }
            if (!base_segment)
                return workspace_result_t<void>::failure(error(
                    workspace_error_code_t::malformed_image,
                    "Mach-O split-segment relocations have no writable segment base",
                    "macho.relocations"));
        }
        dynamic_base = base_segment->vm_address;
    }
    const auto paired_architecture = architecture_ == architecture_id_t::x86 ||
                                     architecture_ == architecture_id_t::arm ||
                                     architecture_ == architecture_id_t::ppc ||
                                     architecture_ == architecture_id_t::ppc64;
    const auto requires_pair = [&](std::uint32_t type) {
        if (architecture_ == architecture_id_t::x86)
            return type == 2U || type == 4U;
        if (architecture_ == architecture_id_t::arm)
            return type == 2U || type == 3U || type == 8U || type == 9U;
        if (architecture_ == architecture_id_t::ppc ||
            architecture_ == architecture_id_t::ppc64)
            return type != 0U && type != 1U && type != 2U && type != 3U &&
                   type != 9U;
        return false;
    };
    bool pair_expected = false;
    for (std::uint64_t index = 0; index < count; ++index) {
        auto stopped = poll(index, "macho.relocations");
        if (!stopped)
            return stopped;
        const auto* record = data.value().data() + static_cast<std::size_t>(index * 8U);
        const std::uint32_t first = reader_.u32(record);
        const std::uint32_t second = reader_.u32(record + 4);
        relocation_record_t relocation;
        std::uint64_t location = 0;
        std::uint32_t relocation_type = 0;
        std::uint32_t length_power = 0;
        std::uint32_t symbol_number = 0;
        bool external = false;
        bool pc_relative = false;
        bool scattered = (first & 0x80000000U) != 0;
        if (scattered && (architecture_ == architecture_id_t::x86_64 ||
                          architecture_ == architecture_id_t::aarch64))
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::malformed_image,
                "Mach-O 64-bit relocation uses a scattered encoding",
                "macho.relocations", offset + index * 8U, 8));
        if (scattered) {
            const std::uint64_t address_offset = first & 0x00ffffffU;
            pc_relative = (first & 0x40000000U) != 0;
            length_power = (first >> 28U) & 0x3U;
            relocation_type = (first >> 24U) & 0xfU;
            if (paired_architecture && relocation_type == 1U) {
                if (!pair_expected)
                    return workspace_result_t<void>::failure(error(
                        workspace_error_code_t::malformed_image,
                        "Mach-O relocation table contains an orphan pair record",
                        "macho.relocations", offset + index * 8U, 8));
                pair_expected = false;
                continue;
            }
            if (pair_expected)
                return workspace_result_t<void>::failure(error(
                    workspace_error_code_t::malformed_image,
                    "Mach-O relocation table is missing a required pair record",
                    "macho.relocations", offset + index * 8U, 8));
            if (section) {
                if (address_offset > section->size)
                    return workspace_result_t<void>::failure(error(
                        workspace_error_code_t::malformed_image,
                        "Mach-O scattered relocation escapes its section",
                        "macho.relocations", offset + index * 8U, 8));
                if (!checked_add_u64(section->vm_address, address_offset, location))
                    return workspace_result_t<void>::failure(error(
                        workspace_error_code_t::range_overflow,
                        "Mach-O scattered relocation address overflowed",
                        "macho.relocations"));
            } else if (dynamic_table) {
                if (!checked_add_u64(dynamic_base, address_offset, location))
                    return workspace_result_t<void>::failure(error(
                        workspace_error_code_t::range_overflow,
                        "Mach-O dynamic scattered relocation address overflowed",
                        "macho.relocations"));
            } else {
                location = address_offset;
            }
            relocation.target_vm_address = second;
        } else {
            if (reader_.big()) {
                symbol_number = second >> 8U;
                pc_relative = (second & 0x80U) != 0;
                length_power = (second >> 5U) & 0x3U;
                external = (second & 0x10U) != 0;
                relocation_type = second & 0xfU;
            } else {
                symbol_number = second & 0x00ffffffU;
                pc_relative = (second & 0x01000000U) != 0;
                length_power = (second >> 25U) & 0x3U;
                external = (second & 0x08000000U) != 0;
                relocation_type = second >> 28U;
            }
            if (paired_architecture && relocation_type == 1U) {
                if (!pair_expected)
                    return workspace_result_t<void>::failure(error(
                        workspace_error_code_t::malformed_image,
                        "Mach-O relocation table contains an orphan pair record",
                        "macho.relocations", offset + index * 8U, 8));
                pair_expected = false;
                continue;
            }
            if (pair_expected)
                return workspace_result_t<void>::failure(error(
                    workspace_error_code_t::malformed_image,
                    "Mach-O relocation table is missing a required pair record",
                    "macho.relocations", offset + index * 8U, 8));
            const std::int32_t signed_address = static_cast<std::int32_t>(first);
            if (signed_address < 0)
                return workspace_result_t<void>::failure(error(
                    workspace_error_code_t::malformed_image,
                    "Mach-O relocation has a negative non-scattered address",
                    "macho.relocations", offset + index * 8U, 8));
            const std::uint64_t address_offset = static_cast<std::uint32_t>(signed_address);
            if (section) {
                if (address_offset > section->size)
                    return workspace_result_t<void>::failure(error(
                        workspace_error_code_t::malformed_image,
                        "Mach-O relocation escapes its section", "macho.relocations",
                        offset + index * 8U, 8));
                if (!checked_add_u64(section->vm_address, address_offset, location))
                    return workspace_result_t<void>::failure(error(
                        workspace_error_code_t::range_overflow,
                        "Mach-O relocation address overflowed", "macho.relocations"));
            } else if (dynamic_table) {
                if (!checked_add_u64(dynamic_base, address_offset, location))
                    return workspace_result_t<void>::failure(error(
                        workspace_error_code_t::range_overflow,
                        "Mach-O dynamic relocation address overflowed",
                        "macho.relocations"));
            } else {
                location = address_offset;
            }
            if (external) {
                if (symbol_number >= symbols_.size())
                    return workspace_result_t<void>::failure(error(
                        workspace_error_code_t::malformed_image,
                        "Mach-O relocation symbol index escapes LC_SYMTAB",
                        "macho.relocations", offset + index * 8U, 8));
                const auto& target_symbol = symbols_[symbol_number];
                if ((target_symbol.type & n_stab) == 0 &&
                    (target_symbol.type & n_type) != n_undf)
                    relocation.target_vm_address = target_symbol.value;
            } else {
                if (symbol_number > sections_.size())
                    return workspace_result_t<void>::failure(error(
                        workspace_error_code_t::malformed_image,
                        "Mach-O local relocation references an invalid section ordinal",
                        "macho.relocations", offset + index * 8U, 8));
                if (symbol_number != 0)
                    relocation.target_vm_address =
                        sections_[symbol_number - 1U].vm_address;
            }
        }
        const std::uint64_t width = 1ULL << length_power;
        if (section) {
            const std::uint64_t delta = location - section->vm_address;
            if (delta > section->size || width > section->size - delta)
                return workspace_result_t<void>::failure(error(
                    workspace_error_code_t::malformed_image,
                    "Mach-O relocation width escapes its section",
                    "macho.relocations", offset + index * 8U, 8));
        }
        if (!vm_to_rva(location, width))
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::malformed_image,
                "Mach-O relocation location is outside the normalized image",
                "macho.relocations", offset + index * 8U, 8));
        relocation.vm_address = location;
        relocation.type = relocation_type |
                          (static_cast<std::uint64_t>(pc_relative) << 8U) |
                          (static_cast<std::uint64_t>(length_power) << 9U) |
                          (static_cast<std::uint64_t>(external) << 11U) |
                          (static_cast<std::uint64_t>(scattered) << 12U);
        if (relocation.target_vm_address && !vm_to_rva(*relocation.target_vm_address))
            relocation.target_vm_address.reset();
        relocations_.push_back(std::move(relocation));
        pair_expected = requires_pair(relocation_type);
    }
    if (pair_expected)
        return workspace_result_t<void>::failure(error(
            workspace_error_code_t::malformed_image,
            "Mach-O relocation table ends before a required pair record",
            "macho.relocations", offset, table_size));
    return workspace_result_t<void>::success();
}

workspace_result_t<void> macho_parser_t::parse_relocations() {
    for (const auto& section : sections_) {
        auto parsed = parse_relocation_table(
            section.relocation_offset, section.relocation_count, &section, false,
            "section_relocations_" + std::to_string(section.index));
        if (!parsed)
            return parsed;
    }
    if (!dysymtab_)
        return workspace_result_t<void>::success();
    auto external = parse_relocation_table(
        dysymtab_->external_relocation_offset,
        dysymtab_->external_relocation_count, nullptr, true,
        "dysymtab_external_relocations");
    if (!external)
        return external;
    return parse_relocation_table(dysymtab_->local_relocation_offset,
                                  dysymtab_->local_relocation_count, nullptr, true,
                                  "dysymtab_local_relocations");
}

std::optional<std::uint64_t> macho_parser_t::vm_to_rva(
    std::uint64_t vm_address, std::uint64_t size) const noexcept {
    if (vm_address < image_base_)
        return std::nullopt;
    const std::uint64_t rva = vm_address - image_base_;
    if (rva > image_size_ || size > image_size_ - rva)
        return std::nullopt;
    if (!segments_.empty()) {
        bool mapped = false;
        for (const auto& segment : segments_) {
            if (vm_address < segment.vm_address)
                continue;
            const std::uint64_t delta = vm_address - segment.vm_address;
            if (delta <= segment.vm_size && size <= segment.vm_size - delta) {
                mapped = true;
                break;
            }
        }
        if (!mapped)
            return std::nullopt;
    }
    return rva;
}

std::optional<std::uint64_t> macho_parser_t::file_to_vm(
    std::uint64_t file_offset, std::uint64_t size) const noexcept {
    for (const auto& segment : segments_) {
        if (file_offset < segment.file_offset)
            continue;
        const std::uint64_t delta = file_offset - segment.file_offset;
        if (delta > segment.file_size || size > segment.file_size - delta)
            continue;
        const std::uint64_t high_delta = (segment.flags & sg_highvm) != 0
            ? segment.vm_size - segment.file_size
            : 0;
        std::uint64_t result = 0;
        if (checked_add_u64(high_delta, delta, result) &&
            checked_add_u64(segment.vm_address, result, result))
            return result;
    }
    return std::nullopt;
}

std::optional<std::uint64_t> macho_parser_t::vm_to_file(
    std::uint64_t vm_address, std::uint64_t size) const noexcept {
    for (const auto& segment : segments_) {
        std::uint64_t mapped_vm = segment.vm_address;
        if ((segment.flags & sg_highvm) != 0 &&
            !checked_add_u64(mapped_vm, segment.vm_size - segment.file_size,
                             mapped_vm))
            continue;
        if (vm_address < mapped_vm)
            continue;
        const std::uint64_t delta = vm_address - mapped_vm;
        if (delta > segment.file_size || size > segment.file_size - delta)
            continue;
        std::uint64_t result = 0;
        if (checked_add_u64(segment.file_offset, delta, result))
            return result;
    }
    return std::nullopt;
}

std::string macho_parser_t::library_name(std::int64_t ordinal) const {
    if (ordinal > 0 && static_cast<std::uint64_t>(ordinal) <= dependencies_.size())
        return dependencies_[static_cast<std::size_t>(ordinal - 1)].name;
    switch (ordinal) {
        case 0:
            return "self";
        case -1:
            return "main-executable";
        case -2:
            return "flat-lookup";
        case -3:
            return "weak-lookup";
        default:
            return "dylib-ordinal:" + std::to_string(ordinal);
    }
}

workspace_result_t<void> macho_parser_t::parse_dyld_payloads() {
    const auto parse_range = [&](std::uint32_t offset, std::uint32_t size,
                                 const char* label,
                                 auto&& parser) -> workspace_result_t<void> {
        if ((offset == 0) != (size == 0))
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::malformed_image,
                "Mach-O dyld stream has a partial null range", "macho.dyld_info",
                offset, size));
        if (size == 0)
            return workspace_result_t<void>::success();
        auto range = register_metadata_range(offset, size, label);
        if (!range)
            return range;
        auto data = read_blob(offset, size, std::string("macho.dyld.") + label);
        if (!data)
            return workspace_result_t<void>::failure(data.error());
        return parser(data.value());
    };
    if (dyld_info_) {
        auto rebase = parse_range(
            dyld_info_->rebase_offset, dyld_info_->rebase_size, "rebase",
            [&](const std::vector<std::uint8_t>& data) {
                return parse_rebase_stream(data);
            });
        if (!rebase)
            return rebase;
        auto bind = parse_range(
            dyld_info_->bind_offset, dyld_info_->bind_size, "bind",
            [&](const std::vector<std::uint8_t>& data) {
                return parse_bind_stream(data, false, false);
            });
        if (!bind)
            return bind;
        auto weak = parse_range(
            dyld_info_->weak_bind_offset, dyld_info_->weak_bind_size, "weak_bind",
            [&](const std::vector<std::uint8_t>& data) {
                return parse_bind_stream(data, true, false);
            });
        if (!weak)
            return weak;
        auto lazy = parse_range(
            dyld_info_->lazy_bind_offset, dyld_info_->lazy_bind_size, "lazy_bind",
            [&](const std::vector<std::uint8_t>& data) {
                return parse_bind_stream(data, false, true);
            });
        if (!lazy)
            return lazy;
        auto export_result = parse_range(
            dyld_info_->export_offset, dyld_info_->export_size, "exports",
            [&](const std::vector<std::uint8_t>& data) {
                return parse_export_trie(data);
            });
        if (!export_result)
            return export_result;
    }
    if (exports_trie_ && exports_trie_->size != 0) {
        const bool duplicate = dyld_info_ &&
            dyld_info_->export_offset == exports_trie_->offset &&
            dyld_info_->export_size == exports_trie_->size;
        if (!duplicate) {
            auto exports = parse_range(
                exports_trie_->offset, exports_trie_->size, "exports_trie",
                [&](const std::vector<std::uint8_t>& data) {
                    return parse_export_trie(data);
                });
            if (!exports)
                return exports;
        }
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<void> macho_parser_t::append_rebase(
    std::uint64_t segment_index, std::uint64_t segment_offset,
    std::uint64_t type) {
    if (segment_index >= segments_.size())
        return workspace_result_t<void>::failure(error(
            workspace_error_code_t::malformed_image,
            "Mach-O rebase references an invalid segment", "macho.rebase"));
    const auto& segment = segments_[static_cast<std::size_t>(segment_index)];
    const std::uint64_t width = type == 2U || type == 3U ? 4U : pointer_size_;
    if (segment_offset > segment.vm_size ||
        width > segment.vm_size - segment_offset)
        return workspace_result_t<void>::failure(error(
            workspace_error_code_t::malformed_image,
            "Mach-O rebase escapes its segment", "macho.rebase"));
    if (rebase_entries_ >= limits_.max_rebase_entries)
        return workspace_result_t<void>::failure(make_limit_error(
            "Mach-O rebase count exceeds its budget", "macho.rebase",
            rebase_entries_ + 1U, limits_.max_rebase_entries));
    if (relocations_.size() >= limits_.max_relocations)
        return workspace_result_t<void>::failure(make_limit_error(
            "Mach-O relocation count exceeds its budget", "macho.rebase",
            relocations_.size() + 1U, limits_.max_relocations));
    std::uint64_t vm_address = 0;
    if (!checked_add_u64(segment.vm_address, segment_offset, vm_address))
        return workspace_result_t<void>::failure(error(
            workspace_error_code_t::range_overflow,
            "Mach-O rebase address overflowed", "macho.rebase"));
    auto budget = consume_metadata(sizeof(relocation_record_t), "macho.rebase");
    if (!budget)
        return budget;
    relocations_.push_back({vm_address, type, std::nullopt});
    ++rebase_entries_;
    return workspace_result_t<void>::success();
}

workspace_result_t<void> macho_parser_t::append_bind(
    std::uint64_t segment_index, std::uint64_t segment_offset,
    const std::string& name, std::int64_t library_ordinal,
    std::int64_t addend, std::uint8_t type, bool weak, bool lazy) {
    if (name.empty())
        return workspace_result_t<void>::failure(error(
            workspace_error_code_t::malformed_image,
            "Mach-O bind operation has no symbol name", "macho.bind"));
    if (type == 0)
        return workspace_result_t<void>::failure(error(
            workspace_error_code_t::malformed_image,
            "Mach-O bind operation has no bind type", "macho.bind"));
    if (type > 3)
        return workspace_result_t<void>::failure(error(
            workspace_error_code_t::malformed_image,
            "Mach-O bind operation uses an unknown bind type", "macho.bind"));
    if (library_ordinal > 0 &&
        static_cast<std::uint64_t>(library_ordinal) > dependencies_.size())
        return workspace_result_t<void>::failure(error(
            workspace_error_code_t::malformed_image,
            "Mach-O bind operation references an invalid dylib ordinal",
            "macho.bind"));
    if (library_ordinal < -3)
        return workspace_result_t<void>::failure(error(
            workspace_error_code_t::malformed_image,
            "Mach-O bind operation uses a reserved special dylib ordinal",
            "macho.bind"));
    if (segment_index >= segments_.size())
        return workspace_result_t<void>::failure(error(
            workspace_error_code_t::malformed_image,
            "Mach-O bind operation references an invalid segment", "macho.bind"));
    const auto& segment = segments_[static_cast<std::size_t>(segment_index)];
    const std::uint64_t width = type == 2U || type == 3U ? 4U : pointer_size_;
    if (segment_offset > segment.vm_size ||
        width > segment.vm_size - segment_offset)
        return workspace_result_t<void>::failure(error(
            workspace_error_code_t::malformed_image,
            "Mach-O bind operation escapes its segment", "macho.bind"));
    if (binds_.size() >= limits_.max_bind_entries ||
        binds_.size() >= limits_.max_imports)
        return workspace_result_t<void>::failure(make_limit_error(
            "Mach-O bind/import count exceeds its budget", "macho.bind",
            binds_.size() + 1U,
            std::min(limits_.max_bind_entries, limits_.max_imports)));
    if (relocations_.size() >= limits_.max_relocations)
        return workspace_result_t<void>::failure(make_limit_error(
            "Mach-O relocation count exceeds its budget", "macho.bind",
            relocations_.size() + 1U, limits_.max_relocations));
    std::uint64_t vm_address = 0;
    if (!checked_add_u64(segment.vm_address, segment_offset, vm_address))
        return workspace_result_t<void>::failure(error(
            workspace_error_code_t::range_overflow,
            "Mach-O bind address overflowed", "macho.bind"));
    auto string_budget = consume_string(name.size(), "macho.bind");
    if (!string_budget)
        return string_budget;
    auto record_budget = consume_metadata(sizeof(bind_record_t) +
                                              sizeof(relocation_record_t),
                                          "macho.bind");
    if (!record_budget)
        return record_budget;
    binds_.push_back({name, library_ordinal, vm_address, addend, type, weak, lazy});
    relocations_.push_back({vm_address, 0x10000ULL | type, std::nullopt});
    return workspace_result_t<void>::success();
}

workspace_result_t<void> macho_parser_t::parse_rebase_stream(
    const std::vector<std::uint8_t>& data) {
    std::uint64_t cursor = 0;
    std::uint64_t segment_index = 0;
    std::uint64_t segment_offset = 0;
    std::uint8_t type = 0;
    bool have_segment = false;
    const auto advance = [&](std::uint64_t amount) -> bool {
        std::uint64_t next = 0;
        if (!checked_add_u64(segment_offset, amount, next))
            return false;
        segment_offset = next;
        return true;
    };
    while (cursor < data.size()) {
        auto stopped = poll(cursor, "macho.rebase");
        if (!stopped)
            return stopped;
        const std::uint8_t byte = data[static_cast<std::size_t>(cursor++)];
        const std::uint8_t opcode = byte & rebase_opcode_mask;
        const std::uint8_t immediate = byte & rebase_immediate_mask;
        if (opcode == rebase_done) {
            while (cursor < data.size()) {
                if (data[static_cast<std::size_t>(cursor++)] != 0)
                    return workspace_result_t<void>::failure(error(
                        workspace_error_code_t::malformed_image,
                        "Mach-O rebase stream contains data after DONE",
                        "macho.rebase"));
            }
            return workspace_result_t<void>::success();
        }
        if (opcode == rebase_set_type) {
            if (immediate == 0 || immediate > 3)
                return workspace_result_t<void>::failure(error(
                    workspace_error_code_t::malformed_image,
                    "Mach-O rebase type is outside the defined range",
                    "macho.rebase"));
            type = immediate;
            continue;
        }
        if (opcode == rebase_set_segment) {
            std::uint64_t value = 0;
            if (!decode_uleb128(data, cursor, data.size(), value) ||
                immediate >= segments_.size() || value > segments_[immediate].vm_size)
                return workspace_result_t<void>::failure(error(
                    workspace_error_code_t::malformed_image,
                    "Mach-O rebase segment state is invalid", "macho.rebase"));
            segment_index = immediate;
            segment_offset = value;
            have_segment = true;
            continue;
        }
        if (!have_segment)
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::malformed_image,
                "Mach-O rebase operation precedes segment selection",
                "macho.rebase"));
        if (opcode == rebase_add_address) {
            std::uint64_t value = 0;
            if (!decode_uleb128(data, cursor, data.size(), value) || !advance(value))
                return workspace_result_t<void>::failure(error(
                    workspace_error_code_t::malformed_image,
                    "Mach-O rebase address increment is invalid", "macho.rebase"));
            continue;
        }
        if (opcode == rebase_add_address_scaled) {
            if (!advance(static_cast<std::uint64_t>(immediate) * pointer_size_))
                return workspace_result_t<void>::failure(error(
                    workspace_error_code_t::range_overflow,
                    "Mach-O scaled rebase increment overflowed", "macho.rebase"));
            continue;
        }
        std::uint64_t count = 0;
        std::uint64_t skip = 0;
        if (opcode == rebase_do_immediate) {
            count = immediate;
        } else if (opcode == rebase_do_uleb) {
            if (!decode_uleb128(data, cursor, data.size(), count))
                return workspace_result_t<void>::failure(error(
                    workspace_error_code_t::malformed_image,
                    "Mach-O rebase count ULEB128 is invalid", "macho.rebase"));
        } else if (opcode == rebase_do_add_address) {
            count = 1;
            if (!decode_uleb128(data, cursor, data.size(), skip))
                return workspace_result_t<void>::failure(error(
                    workspace_error_code_t::malformed_image,
                    "Mach-O rebase skip ULEB128 is invalid", "macho.rebase"));
        } else if (opcode == rebase_do_times_skip) {
            if (!decode_uleb128(data, cursor, data.size(), count) ||
                !decode_uleb128(data, cursor, data.size(), skip))
                return workspace_result_t<void>::failure(error(
                    workspace_error_code_t::malformed_image,
                    "Mach-O repeated rebase operands are invalid", "macho.rebase"));
        } else {
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::malformed_image,
                "Mach-O rebase stream contains an unknown opcode", "macho.rebase"));
        }
        if (count > limits_.max_rebase_entries - rebase_entries_)
            return workspace_result_t<void>::failure(make_limit_error(
                "Mach-O rebase operation exceeds its remaining budget", "macho.rebase",
                rebase_entries_ + count, limits_.max_rebase_entries));
        std::uint64_t stride = 0;
        if (!checked_add_u64(pointer_size_, skip, stride))
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::range_overflow,
                "Mach-O rebase stride overflowed", "macho.rebase"));
        for (std::uint64_t index = 0; index < count; ++index) {
            if (type == 0)
                return workspace_result_t<void>::failure(error(
                    workspace_error_code_t::malformed_image,
                    "Mach-O rebase operation precedes type selection",
                    "macho.rebase"));
            auto appended = append_rebase(segment_index, segment_offset, type);
            if (!appended)
                return appended;
            if (!advance(stride))
                return workspace_result_t<void>::failure(error(
                    workspace_error_code_t::range_overflow,
                    "Mach-O rebase cursor overflowed", "macho.rebase"));
        }
    }
    return workspace_result_t<void>::failure(error(
        workspace_error_code_t::malformed_image,
        "Mach-O rebase stream is missing DONE", "macho.rebase"));
}

workspace_result_t<void> macho_parser_t::parse_threaded_apply(
    std::uint64_t segment_index, std::uint64_t segment_offset,
    const std::vector<bind_record_t>& ordinal_table, bool weak, bool lazy) {
    if (pointer_size_ != 8 || segment_index >= segments_.size() ||
        ordinal_table.empty())
        return workspace_result_t<void>::failure(error(
            workspace_error_code_t::malformed_image,
            "Mach-O threaded bind state is incomplete", "macho.bind.threaded"));
    const auto& segment = segments_[static_cast<std::size_t>(segment_index)];
    std::uint64_t offset = segment_offset;
    for (;;) {
        if (++chained_steps_ > limits_.max_chained_fixup_steps)
            return workspace_result_t<void>::failure(make_limit_error(
                "Mach-O threaded bind traversal exceeds its step budget",
                "macho.bind.threaded", chained_steps_,
                limits_.max_chained_fixup_steps));
        if (offset > segment.vm_size || 8U > segment.vm_size - offset)
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::malformed_image,
                "Mach-O threaded bind chain escapes its segment",
                "macho.bind.threaded"));
        std::uint64_t vm_address = 0;
        if (!checked_add_u64(segment.vm_address, offset, vm_address))
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::range_overflow,
                "Mach-O threaded bind address overflowed", "macho.bind.threaded"));
        auto file_offset = vm_to_file(vm_address, 8);
        if (!file_offset)
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::malformed_image,
                "Mach-O threaded bind pointer is not file-backed",
                "macho.bind.threaded"));
        auto value = read_u64(*file_offset, "macho.bind.threaded");
        if (!value)
            return workspace_result_t<void>::failure(value.error());
        const bool is_bind = ((value.value() >> 62U) & 1U) != 0;
        if (is_bind) {
            const std::uint64_t ordinal = value.value() & 0xffffU;
            if (ordinal >= ordinal_table.size())
                return workspace_result_t<void>::failure(error(
                    workspace_error_code_t::malformed_image,
                    "Mach-O threaded bind ordinal escapes its table",
                    "macho.bind.threaded"));
            const auto& entry = ordinal_table[static_cast<std::size_t>(ordinal)];
            auto appended = append_bind(segment_index, offset, entry.name,
                                        entry.library_ordinal, entry.addend,
                                        entry.type, entry.weak || weak,
                                        entry.lazy || lazy);
            if (!appended)
                return appended;
        } else {
            auto appended = append_rebase(segment_index, offset, 0x20000U);
            if (!appended)
                return appended;
        }
        const std::uint64_t delta = (value.value() >> 51U) & 0x7ffU;
        if (delta == 0)
            break;
        std::uint64_t increment = 0;
        if (!checked_mul_u64(delta, 8, increment) ||
            !checked_add_u64(offset, increment, offset))
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::range_overflow,
                "Mach-O threaded bind chain increment overflowed",
                "macho.bind.threaded"));
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<void> macho_parser_t::parse_bind_stream(
    const std::vector<std::uint8_t>& data, bool weak, bool lazy) {
    std::uint64_t cursor = 0;
    std::int64_t library_ordinal = 0;
    std::int64_t addend = 0;
    std::uint8_t type = 0;
    std::uint64_t segment_index = 0;
    std::uint64_t segment_offset = 0;
    std::string symbol;
    bool symbol_weak = false;
    bool have_segment = false;
    bool saw_done = false;
    std::uint64_t threaded_table_size = 0;
    std::vector<bind_record_t> threaded_table;
    const auto reset_lazy_state = [&]() {
        library_ordinal = 0;
        addend = 0;
        type = 0;
        symbol.clear();
        symbol_weak = false;
        have_segment = false;
        segment_index = 0;
        segment_offset = 0;
    };
    const auto advance = [&](std::uint64_t amount) -> bool {
        std::uint64_t next = 0;
        if (!checked_add_u64(segment_offset, amount, next))
            return false;
        segment_offset = next;
        return true;
    };
    const auto emit = [&]() -> workspace_result_t<void> {
        if (threaded_table_size != 0 && threaded_table.size() < threaded_table_size) {
            if (symbol.empty() || type == 0 || type > 3 || library_ordinal < -3 ||
                (library_ordinal > 0 &&
                 static_cast<std::uint64_t>(library_ordinal) > dependencies_.size()))
                return workspace_result_t<void>::failure(error(
                    workspace_error_code_t::malformed_image,
                    "Mach-O threaded ordinal entry has invalid binding state",
                    "macho.bind"));
            auto budget = consume_string(symbol.size(), "macho.bind.threaded");
            if (!budget)
                return budget;
            threaded_table.push_back({symbol, library_ordinal, 0, addend, type,
                                      symbol_weak || weak, lazy});
            return workspace_result_t<void>::success();
        }
        if (!have_segment)
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::malformed_image,
                "Mach-O bind operation precedes segment selection", "macho.bind"));
        return append_bind(segment_index, segment_offset, symbol, library_ordinal,
                           addend, type, symbol_weak || weak, lazy);
    };
    while (cursor < data.size()) {
        auto stopped = poll(cursor, "macho.bind");
        if (!stopped)
            return stopped;
        const std::uint8_t byte = data[static_cast<std::size_t>(cursor++)];
        const std::uint8_t opcode = byte & bind_opcode_mask;
        const std::uint8_t immediate = byte & bind_immediate_mask;
        if (opcode == bind_done) {
            if (threaded_table_size != 0 &&
                threaded_table.size() != threaded_table_size)
                return workspace_result_t<void>::failure(error(
                    workspace_error_code_t::malformed_image,
                    "Mach-O threaded ordinal table is incomplete",
                    "macho.bind.threaded"));
            saw_done = true;
            if (lazy) {
                reset_lazy_state();
                continue;
            }
            while (cursor < data.size()) {
                if (data[static_cast<std::size_t>(cursor++)] != 0)
                    return workspace_result_t<void>::failure(error(
                        workspace_error_code_t::malformed_image,
                        "Mach-O bind stream contains data after DONE", "macho.bind"));
            }
            return workspace_result_t<void>::success();
        }
        if (opcode == bind_set_dylib_ordinal) {
            library_ordinal = immediate;
            continue;
        }
        if (opcode == bind_set_dylib_ordinal_uleb) {
            std::uint64_t ordinal = 0;
            if (!decode_uleb128(data, cursor, data.size(), ordinal) ||
                ordinal > static_cast<std::uint64_t>((std::numeric_limits<std::int64_t>::max)()))
                return workspace_result_t<void>::failure(error(
                    workspace_error_code_t::malformed_image,
                    "Mach-O bind dylib ordinal ULEB128 is invalid", "macho.bind"));
            library_ordinal = static_cast<std::int64_t>(ordinal);
            continue;
        }
        if (opcode == bind_set_dylib_special) {
            library_ordinal = immediate == 0
                ? 0
                : static_cast<std::int8_t>(immediate | 0xf0U);
            if (library_ordinal < -3)
                return workspace_result_t<void>::failure(error(
                    workspace_error_code_t::malformed_image,
                    "Mach-O bind stream uses a reserved special dylib ordinal",
                    "macho.bind"));
            continue;
        }
        if (opcode == bind_set_symbol) {
            const std::uint64_t start = cursor;
            while (cursor < data.size() && data[static_cast<std::size_t>(cursor)] != 0)
                ++cursor;
            if (cursor >= data.size())
                return workspace_result_t<void>::failure(error(
                    workspace_error_code_t::malformed_image,
                    "Mach-O bind symbol is not terminated", "macho.bind"));
            symbol.assign(reinterpret_cast<const char*>(data.data() + start),
                          static_cast<std::size_t>(cursor - start));
            ++cursor;
            if (symbol.empty())
                return workspace_result_t<void>::failure(error(
                    workspace_error_code_t::malformed_image,
                    "Mach-O bind symbol is empty", "macho.bind"));
            auto budget = consume_string(symbol.size(), "macho.bind.symbols");
            if (!budget)
                return budget;
            symbol_weak = (immediate & 1U) != 0;
            continue;
        }
        if (opcode == bind_set_type) {
            if (immediate == 0 || immediate > 3)
                return workspace_result_t<void>::failure(error(
                    workspace_error_code_t::malformed_image,
                    "Mach-O bind type is outside the defined range",
                    "macho.bind"));
            type = immediate;
            continue;
        }
        if (opcode == bind_set_addend) {
            if (!decode_sleb128(data, cursor, data.size(), addend))
                return workspace_result_t<void>::failure(error(
                    workspace_error_code_t::malformed_image,
                    "Mach-O bind addend SLEB128 is invalid", "macho.bind"));
            continue;
        }
        if (opcode == bind_set_segment) {
            std::uint64_t value = 0;
            if (!decode_uleb128(data, cursor, data.size(), value) ||
                immediate >= segments_.size() || value > segments_[immediate].vm_size)
                return workspace_result_t<void>::failure(error(
                    workspace_error_code_t::malformed_image,
                    "Mach-O bind segment state is invalid", "macho.bind"));
            segment_index = immediate;
            segment_offset = value;
            have_segment = true;
            continue;
        }
        if (opcode == bind_add_address) {
            std::uint64_t value = 0;
            if (!decode_uleb128(data, cursor, data.size(), value) || !advance(value))
                return workspace_result_t<void>::failure(error(
                    workspace_error_code_t::malformed_image,
                    "Mach-O bind address increment is invalid", "macho.bind"));
            continue;
        }
        if (opcode == bind_threaded) {
            if (weak || lazy)
                return workspace_result_t<void>::failure(error(
                    workspace_error_code_t::malformed_image,
                    "Mach-O threaded bind opcode is invalid in this stream",
                    "macho.bind.threaded"));
            if (immediate == 0) {
                if (threaded_table_size != 0)
                    return workspace_result_t<void>::failure(error(
                        workspace_error_code_t::malformed_image,
                        "Mach-O threaded ordinal table is defined more than once",
                        "macho.bind.threaded"));
                const std::uint64_t table_limit =
                    std::min<std::uint64_t>(limits_.max_bind_entries,
                                            limits_.max_imports);
                std::uint64_t requested_size = 0;
                if (!decode_uleb128(data, cursor, data.size(), requested_size) ||
                    requested_size == 0 || requested_size > table_limit)
                    return workspace_result_t<void>::failure(error(
                        workspace_error_code_t::malformed_image,
                        "Mach-O threaded bind ordinal-table size is invalid",
                        "macho.bind.threaded"));
                threaded_table_size = requested_size;
                std::uint64_t table_bytes = 0;
                if (!checked_mul_u64(threaded_table_size, sizeof(bind_record_t),
                                     table_bytes))
                    return workspace_result_t<void>::failure(error(
                        workspace_error_code_t::range_overflow,
                        "Mach-O threaded ordinal-table allocation overflowed",
                        "macho.bind.threaded"));
                auto table_budget = consume_metadata(table_bytes,
                                                     "macho.bind.threaded");
                if (!table_budget)
                    return table_budget;
                threaded_table.reserve(static_cast<std::size_t>(threaded_table_size));
            } else if (immediate == 1) {
                if (!have_segment || threaded_table.size() != threaded_table_size)
                    return workspace_result_t<void>::failure(error(
                        workspace_error_code_t::malformed_image,
                        "Mach-O threaded bind apply state is incomplete",
                        "macho.bind.threaded"));
                auto applied = parse_threaded_apply(segment_index, segment_offset,
                                                    threaded_table, weak, lazy);
                if (!applied)
                    return applied;
            } else {
                return workspace_result_t<void>::failure(error(
                    workspace_error_code_t::malformed_image,
                    "Mach-O threaded bind subopcode is unknown",
                    "macho.bind.threaded"));
            }
            continue;
        }
        if (opcode == bind_do) {
            const bool building_table = threaded_table_size != 0 &&
                                        threaded_table.size() < threaded_table_size;
            auto emitted = emit();
            if (!emitted)
                return emitted;
            if (!building_table) {
                if (!advance(pointer_size_))
                    return workspace_result_t<void>::failure(error(
                        workspace_error_code_t::range_overflow,
                        "Mach-O bind cursor overflowed", "macho.bind"));
            }
            continue;
        }
        if (opcode == bind_do_add_address || opcode == bind_do_add_address_scaled) {
            if (threaded_table_size != 0 &&
                threaded_table.size() < threaded_table_size)
                return workspace_result_t<void>::failure(error(
                    workspace_error_code_t::malformed_image,
                    "Mach-O threaded ordinal table requires plain DO_BIND entries",
                    "macho.bind.threaded"));
            auto emitted = emit();
            if (!emitted)
                return emitted;
            std::uint64_t increment = pointer_size_;
            if (opcode == bind_do_add_address) {
                std::uint64_t value = 0;
                if (!decode_uleb128(data, cursor, data.size(), value) ||
                    !checked_add_u64(increment, value, increment))
                    return workspace_result_t<void>::failure(error(
                        workspace_error_code_t::malformed_image,
                        "Mach-O bind skip ULEB128 is invalid", "macho.bind"));
            } else {
                std::uint64_t scaled = 0;
                if (!checked_mul_u64(immediate, pointer_size_, scaled) ||
                    !checked_add_u64(increment, scaled, increment))
                    return workspace_result_t<void>::failure(error(
                        workspace_error_code_t::range_overflow,
                        "Mach-O scaled bind increment overflowed", "macho.bind"));
            }
            if (!advance(increment))
                return workspace_result_t<void>::failure(error(
                    workspace_error_code_t::range_overflow,
                    "Mach-O bind cursor overflowed", "macho.bind"));
            continue;
        }
        if (opcode == bind_do_times_skip) {
            if (threaded_table_size != 0 &&
                threaded_table.size() < threaded_table_size)
                return workspace_result_t<void>::failure(error(
                    workspace_error_code_t::malformed_image,
                    "Mach-O threaded ordinal table requires plain DO_BIND entries",
                    "macho.bind.threaded"));
            std::uint64_t count = 0;
            std::uint64_t skip = 0;
            if (!decode_uleb128(data, cursor, data.size(), count) ||
                !decode_uleb128(data, cursor, data.size(), skip) ||
                count > limits_.max_bind_entries - binds_.size())
                return workspace_result_t<void>::failure(error(
                    workspace_error_code_t::malformed_image,
                    "Mach-O repeated bind operands exceed bounds or budget",
                    "macho.bind"));
            std::uint64_t stride = 0;
            if (!checked_add_u64(pointer_size_, skip, stride))
                return workspace_result_t<void>::failure(error(
                    workspace_error_code_t::range_overflow,
                    "Mach-O bind stride overflowed", "macho.bind"));
            for (std::uint64_t index = 0; index < count; ++index) {
                auto emitted = emit();
                if (!emitted)
                    return emitted;
                if (!advance(stride))
                    return workspace_result_t<void>::failure(error(
                        workspace_error_code_t::range_overflow,
                        "Mach-O bind cursor overflowed", "macho.bind"));
            }
            continue;
        }
        return workspace_result_t<void>::failure(error(
            workspace_error_code_t::malformed_image,
            "Mach-O bind stream contains an unknown opcode", "macho.bind"));
    }
    if (!saw_done)
        return workspace_result_t<void>::failure(error(
            workspace_error_code_t::malformed_image,
            "Mach-O bind stream is missing DONE", "macho.bind"));
    return workspace_result_t<void>::success();
}

workspace_result_t<void> macho_parser_t::parse_export_trie(
    const std::vector<std::uint8_t>& data) {
    if (data.empty())
        return workspace_result_t<void>::failure(error(
            workspace_error_code_t::malformed_image,
            "Mach-O export trie is empty", "macho.exports"));
    std::unordered_set<std::uint64_t> active;
    return parse_export_node(data, 0, std::string{}, 0, active);
}

workspace_result_t<void> macho_parser_t::parse_export_node(
    const std::vector<std::uint8_t>& data, std::uint64_t node_offset,
    const std::string& prefix, std::uint32_t depth,
    std::unordered_set<std::uint64_t>& active) {
    if (depth > limits_.max_export_trie_depth)
        return workspace_result_t<void>::failure(make_limit_error(
            "Mach-O export trie depth exceeds its budget", "macho.exports",
            depth, limits_.max_export_trie_depth));
    if (node_offset >= data.size())
        return workspace_result_t<void>::failure(error(
            workspace_error_code_t::malformed_image,
            "Mach-O export trie node offset escapes the trie", "macho.exports"));
    if (!active.insert(node_offset).second)
        return workspace_result_t<void>::failure(error(
            workspace_error_code_t::malformed_image,
            "Mach-O export trie contains a cycle", "macho.exports"));
    if (++export_nodes_ > limits_.max_export_trie_nodes) {
        active.erase(node_offset);
        return workspace_result_t<void>::failure(make_limit_error(
            "Mach-O export trie node count exceeds its budget", "macho.exports",
            export_nodes_, limits_.max_export_trie_nodes));
    }
    auto stopped = poll(export_nodes_, "macho.exports");
    if (!stopped) {
        active.erase(node_offset);
        return stopped;
    }
    std::uint64_t cursor = node_offset;
    std::uint64_t terminal_size = 0;
    if (!decode_uleb128(data, cursor, data.size(), terminal_size) ||
        terminal_size > data.size() - cursor) {
        active.erase(node_offset);
        return workspace_result_t<void>::failure(error(
            workspace_error_code_t::malformed_image,
            "Mach-O export trie terminal size is invalid", "macho.exports"));
    }
    const std::uint64_t terminal_end = cursor + terminal_size;
    if (terminal_size != 0) {
        if (exports_.size() >= limits_.max_exports) {
            active.erase(node_offset);
            return workspace_result_t<void>::failure(make_limit_error(
                "Mach-O export count exceeds its budget", "macho.exports",
                exports_.size() + 1U, limits_.max_exports));
        }
        std::uint64_t flags = 0;
        if (!decode_uleb128(data, cursor, terminal_end, flags)) {
            active.erase(node_offset);
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::malformed_image,
                "Mach-O export flags are invalid", "macho.exports"));
        }
        const std::uint64_t export_kind = flags & export_kind_mask;
        if (prefix.empty() || export_kind == export_kind_mask ||
            ((flags & export_stub_and_resolver) != 0 && export_kind != 0) ||
            ((flags & export_reexport) != 0 &&
             ((flags & export_stub_and_resolver) != 0 ||
              export_kind != 0))) {
            active.erase(node_offset);
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::malformed_image,
                "Mach-O export flag combination is invalid",
                "macho.exports"));
        }
        export_record_t exported;
        std::optional<std::uint64_t> resolver_address;
        exported.name = prefix;
        exported.absolute = export_kind == export_kind_absolute;
        if ((flags & export_reexport) != 0) {
            std::uint64_t ordinal = 0;
            if (!decode_uleb128(data, cursor, terminal_end, ordinal) ||
                ordinal == 0 || ordinal > dependencies_.size()) {
                active.erase(node_offset);
                return workspace_result_t<void>::failure(error(
                    workspace_error_code_t::malformed_image,
                    "Mach-O re-export references an invalid dylib ordinal",
                    "macho.exports"));
            }
            const std::uint64_t name_start = cursor;
            while (cursor < terminal_end && data[static_cast<std::size_t>(cursor)] != 0)
                ++cursor;
            if (cursor >= terminal_end) {
                active.erase(node_offset);
                return workspace_result_t<void>::failure(error(
                    workspace_error_code_t::malformed_image,
                    "Mach-O re-export name is not terminated", "macho.exports"));
            }
            std::string imported(
                reinterpret_cast<const char*>(data.data() + name_start),
                static_cast<std::size_t>(cursor - name_start));
            ++cursor;
            if (imported.empty())
                imported = prefix;
            const auto& library =
                dependencies_[static_cast<std::size_t>(ordinal - 1U)].name;
            if (library.size() >= limits_.max_string_bytes ||
                imported.size() > limits_.max_string_bytes - library.size() - 1U) {
                active.erase(node_offset);
                return workspace_result_t<void>::failure(make_limit_error(
                    "Mach-O re-export forwarder exceeds its string budget",
                    "macho.exports", library.size() + imported.size() + 1U,
                    limits_.max_string_bytes));
            }
            exported.forwarder = library + "!" + imported;
        } else {
            if (!decode_uleb128(data, cursor, terminal_end, exported.address)) {
                active.erase(node_offset);
                return workspace_result_t<void>::failure(error(
                    workspace_error_code_t::malformed_image,
                    "Mach-O export address is invalid", "macho.exports"));
            }
            if ((flags & export_stub_and_resolver) != 0) {
                std::uint64_t resolver = 0;
                if (!decode_uleb128(data, cursor, terminal_end, resolver)) {
                    active.erase(node_offset);
                    return workspace_result_t<void>::failure(error(
                        workspace_error_code_t::malformed_image,
                        "Mach-O export resolver address is invalid", "macho.exports"));
                }
                resolver_address = resolver;
            }
        }
        if (cursor != terminal_end) {
            active.erase(node_offset);
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::malformed_image,
                "Mach-O export terminal contains trailing bytes", "macho.exports"));
        }
        auto name_budget = consume_string(exported.name.size(), "macho.exports");
        if (!name_budget) {
            active.erase(node_offset);
            return name_budget;
        }
        if (exported.forwarder) {
            auto forwarder_budget = consume_string(exported.forwarder->size(),
                                                   "macho.exports");
            if (!forwarder_budget) {
                active.erase(node_offset);
                return forwarder_budget;
            }
        }
        if (resolver_address) {
            std::uint64_t resolver_vm = 0;
            if (!checked_add_u64(image_base_, *resolver_address, resolver_vm)) {
                active.erase(node_offset);
                return workspace_result_t<void>::failure(error(
                    workspace_error_code_t::range_overflow,
                    "Mach-O export resolver address overflowed",
                    "macho.exports"));
            }
            auto resolver = add_metadata_symbol(
                "export-resolver:" + exported.name, resolver_vm, 0,
                image_symbol_kind_t::function);
            if (!resolver) {
                active.erase(node_offset);
                return resolver;
            }
        }
        auto record_budget = consume_metadata(sizeof(export_record_t),
                                              "macho.exports");
        if (!record_budget) {
            active.erase(node_offset);
            return record_budget;
        }
        exports_.push_back(std::move(exported));
    }
    cursor = terminal_end;
    if (cursor >= data.size()) {
        active.erase(node_offset);
        return workspace_result_t<void>::failure(error(
            workspace_error_code_t::malformed_image,
            "Mach-O export trie node lacks a child count", "macho.exports"));
    }
    const std::uint8_t child_count = data[static_cast<std::size_t>(cursor++)];
    struct child_t {
        std::string prefix;
        std::uint64_t offset;
    };
    std::vector<child_t> children;
    children.reserve(child_count);
    std::set<std::string> edges;
    for (std::uint32_t child_index = 0; child_index < child_count; ++child_index) {
        const std::uint64_t edge_start = cursor;
        while (cursor < data.size() && data[static_cast<std::size_t>(cursor)] != 0)
            ++cursor;
        if (cursor >= data.size() || cursor == edge_start) {
            active.erase(node_offset);
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::malformed_image,
                "Mach-O export trie child edge is empty or unterminated",
                "macho.exports"));
        }
        std::string edge(reinterpret_cast<const char*>(data.data() + edge_start),
                         static_cast<std::size_t>(cursor - edge_start));
        ++cursor;
        if (!edges.insert(edge).second) {
            active.erase(node_offset);
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::malformed_image,
                "Mach-O export trie node has duplicate child edges",
                "macho.exports"));
        }
        std::uint64_t child_offset = 0;
        if (!decode_uleb128(data, cursor, data.size(), child_offset) ||
            child_offset >= data.size()) {
            active.erase(node_offset);
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::malformed_image,
                "Mach-O export trie child offset is invalid", "macho.exports"));
        }
        if (edge.size() > limits_.max_string_bytes ||
            prefix.size() > limits_.max_string_bytes - edge.size()) {
            active.erase(node_offset);
            return workspace_result_t<void>::failure(make_limit_error(
                "Mach-O export name exceeds its string budget", "macho.exports",
                prefix.size() + edge.size(), limits_.max_string_bytes));
        }
        auto child_budget = consume_metadata(sizeof(child_t) + prefix.size() +
                                                 edge.size(),
                                             "macho.exports");
        if (!child_budget) {
            active.erase(node_offset);
            return child_budget;
        }
        children.push_back({prefix + edge, child_offset});
    }
    for (const auto& child : children) {
        auto parsed = parse_export_node(data, child.offset, child.prefix, depth + 1U, active);
        if (!parsed) {
            active.erase(node_offset);
            return parsed;
        }
    }
    active.erase(node_offset);
    return workspace_result_t<void>::success();
}

workspace_result_t<std::vector<std::uint8_t>>
macho_parser_t::decompress_chained_symbols(
    const std::vector<std::uint8_t>& data, std::uint32_t symbols_offset) {
    if (symbols_offset >= data.size())
        return workspace_result_t<std::vector<std::uint8_t>>::failure(error(
            workspace_error_code_t::malformed_image,
            "Mach-O compressed chained symbol pool is empty",
            "macho.chained.symbols"));
    inflate_guard_t guard;
    guard.stream.zalloc = Z_NULL;
    guard.stream.zfree = Z_NULL;
    guard.stream.opaque = Z_NULL;
    const int initialized = inflateInit(&guard.stream);
    if (initialized != Z_OK)
        return workspace_result_t<std::vector<std::uint8_t>>::failure(error(
            initialized == Z_MEM_ERROR ? workspace_error_code_t::limit_exceeded
                                       : workspace_error_code_t::unsupported_format,
            "Mach-O chained symbol decompressor initialization failed",
            "macho.chained.symbols"));
    guard.initialized = true;
    const std::uint64_t output_limit =
        std::min(limits_.max_string_bytes, limits_.max_linkedit_blob_bytes);
    std::vector<std::uint8_t> output;
    std::array<std::uint8_t, 64U * 1024U> chunk{};
    std::uint64_t input_position = symbols_offset;
    for (std::uint64_t iteration = 0;; ++iteration) {
        auto stopped = poll(iteration, "macho.chained.symbols");
        if (!stopped)
            return workspace_result_t<std::vector<std::uint8_t>>::failure(
                stopped.error());
        if (guard.stream.avail_in == 0 && input_position < data.size()) {
            const std::uint64_t remaining = data.size() - input_position;
            const std::uint64_t amount = std::min<std::uint64_t>(
                remaining, (std::numeric_limits<uInt>::max)());
            guard.stream.next_in = const_cast<Bytef*>(
                reinterpret_cast<const Bytef*>(data.data() + input_position));
            guard.stream.avail_in = static_cast<uInt>(amount);
            input_position += amount;
        }
        guard.stream.next_out = reinterpret_cast<Bytef*>(chunk.data());
        guard.stream.avail_out = static_cast<uInt>(chunk.size());
        const uInt before_in = guard.stream.avail_in;
        const uInt before_out = guard.stream.avail_out;
        const int status = inflate(&guard.stream, Z_NO_FLUSH);
        const std::uint64_t produced = chunk.size() - guard.stream.avail_out;
        std::uint64_t next_output_size = 0;
        if (!checked_add_u64(output.size(), produced, next_output_size))
            return workspace_result_t<std::vector<std::uint8_t>>::failure(error(
                workspace_error_code_t::range_overflow,
                "Mach-O chained symbol output size overflowed",
                "macho.chained.symbols"));
        if (next_output_size > output_limit)
            return workspace_result_t<std::vector<std::uint8_t>>::failure(
                make_limit_error("Mach-O chained symbol pool exceeds its budget",
                                 "macho.chained.symbols",
                                 next_output_size,
                                 output_limit));
        output.insert(output.end(), chunk.begin(),
                      chunk.begin() + static_cast<std::ptrdiff_t>(produced));
        if (status == Z_STREAM_END) {
            const std::uint64_t consumed_position =
                input_position - guard.stream.avail_in;
            for (std::uint64_t index = consumed_position; index < data.size(); ++index) {
                auto tail_stopped = poll(index - consumed_position,
                                         "macho.chained.symbols");
                if (!tail_stopped)
                    return workspace_result_t<std::vector<std::uint8_t>>::failure(
                        tail_stopped.error());
                if (data[static_cast<std::size_t>(index)] != 0)
                    return workspace_result_t<std::vector<std::uint8_t>>::failure(error(
                        workspace_error_code_t::malformed_image,
                        "Mach-O compressed chained symbol pool has trailing data",
                        "macho.chained.symbols"));
            }
            auto budget = consume_metadata(output.size(), "macho.chained.symbols");
            if (!budget)
                return workspace_result_t<std::vector<std::uint8_t>>::failure(
                    budget.error());
            return workspace_result_t<std::vector<std::uint8_t>>::success(
                std::move(output));
        }
        if (status != Z_OK) {
            const auto code = status == Z_MEM_ERROR
                ? workspace_error_code_t::limit_exceeded
                : workspace_error_code_t::malformed_image;
            return workspace_result_t<std::vector<std::uint8_t>>::failure(error(
                code, "Mach-O compressed chained symbol pool is invalid",
                "macho.chained.symbols"));
        }
        if (before_in == guard.stream.avail_in &&
            before_out == guard.stream.avail_out)
            return workspace_result_t<std::vector<std::uint8_t>>::failure(error(
                workspace_error_code_t::malformed_image,
                "Mach-O compressed chained symbol pool made no progress",
                "macho.chained.symbols"));
    }
}

workspace_result_t<std::vector<chained_import_record_t>>
macho_parser_t::parse_chained_imports(
    const std::vector<std::uint8_t>& data, std::uint32_t imports_offset,
    std::uint32_t imports_count, std::uint32_t imports_format,
    std::uint32_t symbols_offset, std::uint32_t symbols_format) {
    if (imports_count > limits_.max_chained_fixup_imports)
        return workspace_result_t<std::vector<chained_import_record_t>>::failure(
            make_limit_error("Mach-O chained import count exceeds its budget",
                             "macho.chained.imports", imports_count,
                             limits_.max_chained_fixup_imports));
    if (symbols_format != chained_symbols_uncompressed &&
        symbols_format != chained_symbols_zlib)
        return workspace_result_t<std::vector<chained_import_record_t>>::failure(error(
            workspace_error_code_t::unsupported_format,
            "Mach-O chained-fixup symbol format is unsupported",
            "macho.chained.imports"));
    if (imports_count == 0) {
        if (imports_offset > data.size() || symbols_offset > data.size())
            return workspace_result_t<std::vector<chained_import_record_t>>::failure(error(
                workspace_error_code_t::malformed_image,
                "Mach-O empty chained import table has invalid offsets or symbols",
                "macho.chained.imports"));
        if (symbols_format == chained_symbols_zlib) {
            auto symbols = decompress_chained_symbols(data, symbols_offset);
            if (!symbols)
                return workspace_result_t<std::vector<chained_import_record_t>>::failure(
                    symbols.error());
        }
        return workspace_result_t<std::vector<chained_import_record_t>>::success({});
    }
    std::uint64_t record_size = 0;
    if (imports_format == chained_import)
        record_size = 4;
    else if (imports_format == chained_import_addend)
        record_size = 8;
    else if (imports_format == chained_import_addend64)
        record_size = 16;
    else
        return workspace_result_t<std::vector<chained_import_record_t>>::failure(error(
            workspace_error_code_t::unsupported_format,
            "Mach-O chained-fixup import format is unsupported",
            "macho.chained.imports"));
    std::uint64_t table_size = 0;
    if (!checked_mul_u64(imports_count, record_size, table_size) ||
        imports_offset > data.size() || table_size > data.size() - imports_offset ||
        symbols_offset > data.size())
        return workspace_result_t<std::vector<chained_import_record_t>>::failure(error(
            workspace_error_code_t::malformed_image,
            "Mach-O chained import or symbol table is truncated",
            "macho.chained.imports"));
    const std::uint64_t table_end = imports_offset + table_size;
    if (imports_offset < 28U || symbols_offset < table_end)
        return workspace_result_t<std::vector<chained_import_record_t>>::failure(error(
            workspace_error_code_t::malformed_image,
            "Mach-O chained import and symbol regions overlap fixed metadata",
            "macho.chained.imports"));
    std::vector<std::uint8_t> decompressed_symbols;
    const std::uint8_t* symbol_data = data.data() + symbols_offset;
    std::uint64_t symbol_size = data.size() - symbols_offset;
    if (symbols_format == chained_symbols_zlib) {
        auto symbols = decompress_chained_symbols(data, symbols_offset);
        if (!symbols)
            return workspace_result_t<std::vector<chained_import_record_t>>::failure(
                symbols.error());
        decompressed_symbols = symbols.take_value();
        symbol_data = decompressed_symbols.data();
        symbol_size = decompressed_symbols.size();
    }
    std::vector<chained_import_record_t> imports;
    imports.reserve(imports_count);
    std::uint64_t import_record_bytes = 0;
    if (!checked_mul_u64(imports_count, sizeof(chained_import_record_t),
                         import_record_bytes))
        return workspace_result_t<std::vector<chained_import_record_t>>::failure(error(
            workspace_error_code_t::range_overflow,
            "Mach-O chained import allocation accounting overflowed",
            "macho.chained.imports"));
    auto import_budget = consume_metadata(import_record_bytes,
                                          "macho.chained.imports");
    if (!import_budget)
        return workspace_result_t<std::vector<chained_import_record_t>>::failure(
            import_budget.error());
    for (std::uint32_t index = 0; index < imports_count; ++index) {
        auto stopped = poll(index, "macho.chained.imports");
        if (!stopped)
            return workspace_result_t<std::vector<chained_import_record_t>>::failure(
                stopped.error());
        const auto* record = data.data() + imports_offset +
                             static_cast<std::size_t>(index * record_size);
        chained_import_record_t imported;
        std::uint64_t name_offset = 0;
        if (imports_format == chained_import ||
            imports_format == chained_import_addend) {
            const std::uint32_t raw = reader_.u32(record);
            const std::uint32_t encoded_ordinal = raw & 0xffU;
            imported.library_ordinal = encoded_ordinal >= 0xf1U
                ? static_cast<std::int8_t>(encoded_ordinal)
                : static_cast<std::int64_t>(encoded_ordinal);
            imported.weak = ((raw >> 8U) & 1U) != 0;
            name_offset = raw >> 9U;
            if (imports_format == chained_import_addend)
                imported.addend = static_cast<std::int32_t>(reader_.u32(record + 4));
        } else {
            const std::uint64_t raw = reader_.u64(record);
            if (((raw >> 17U) & 0x7fffU) != 0)
                return workspace_result_t<std::vector<chained_import_record_t>>::failure(
                    error(workspace_error_code_t::malformed_image,
                          "Mach-O chained 64-bit import has nonzero reserved bits",
                          "macho.chained.imports"));
            const std::uint32_t encoded_ordinal = raw & 0xffffU;
            imported.library_ordinal = encoded_ordinal >= 0xfff1U
                ? static_cast<std::int16_t>(encoded_ordinal)
                : static_cast<std::int64_t>(encoded_ordinal);
            imported.weak = ((raw >> 16U) & 1U) != 0;
            name_offset = raw >> 32U;
            imported.addend = static_cast<std::int64_t>(reader_.u64(record + 8));
        }
        if (imported.library_ordinal > 0 &&
            static_cast<std::uint64_t>(imported.library_ordinal) > dependencies_.size())
            return workspace_result_t<std::vector<chained_import_record_t>>::failure(error(
                workspace_error_code_t::malformed_image,
                "Mach-O chained import references an invalid dylib ordinal",
                "macho.chained.imports"));
        if (imported.library_ordinal < -3)
            return workspace_result_t<std::vector<chained_import_record_t>>::failure(error(
                workspace_error_code_t::malformed_image,
                "Mach-O chained import uses a reserved special dylib ordinal",
                "macho.chained.imports"));
        if (name_offset >= symbol_size)
            return workspace_result_t<std::vector<chained_import_record_t>>::failure(error(
                workspace_error_code_t::malformed_image,
                "Mach-O chained import name escapes the symbol pool",
                "macho.chained.imports"));
        std::uint64_t end = name_offset;
        while (end < symbol_size && symbol_data[static_cast<std::size_t>(end)] != 0)
            ++end;
        if (end >= symbol_size || end == name_offset)
            return workspace_result_t<std::vector<chained_import_record_t>>::failure(error(
                workspace_error_code_t::malformed_image,
                "Mach-O chained import name is empty or unterminated",
                "macho.chained.imports"));
        imported.name.assign(
            reinterpret_cast<const char*>(symbol_data + name_offset),
            static_cast<std::size_t>(end - name_offset));
        auto budget = consume_string(imported.name.size(), "macho.chained.imports");
        if (!budget)
            return workspace_result_t<std::vector<chained_import_record_t>>::failure(
                budget.error());
        imports.push_back(std::move(imported));
    }
    return workspace_result_t<std::vector<chained_import_record_t>>::success(
        std::move(imports));
}

workspace_result_t<chain_pointer_t> macho_parser_t::decode_chain_pointer(
    std::uint16_t format, std::uint64_t value) const {
    chain_pointer_t pointer;
    switch (format) {
        case chained_ptr_64:
        case chained_ptr_64_offset:
            pointer.stride = 4;
            pointer.next = (value >> 51U) & 0xfffU;
            pointer.bind = ((value >> 63U) & 1U) != 0;
            if (pointer.bind) {
                if (((value >> 32U) & 0x7ffffU) != 0)
                    return workspace_result_t<chain_pointer_t>::failure(error(
                        workspace_error_code_t::malformed_image,
                        "Mach-O chained 64-bit bind has nonzero reserved bits",
                        "macho.chained.pointer"));
                pointer.ordinal = value & 0x00ffffffU;
                pointer.addend = static_cast<std::int64_t>((value >> 24U) & 0xffU);
            } else {
                if (((value >> 44U) & 0x7fU) != 0)
                    return workspace_result_t<chain_pointer_t>::failure(error(
                        workspace_error_code_t::malformed_image,
                        "Mach-O chained 64-bit rebase has nonzero reserved bits",
                        "macho.chained.pointer"));
                const std::uint64_t low = value & 0x0000000fffffffffULL;
                const std::uint64_t high = (value >> 36U) & 0xffU;
                pointer.target = low | (high << 56U);
                pointer.target_is_offset = format == chained_ptr_64_offset;
            }
            break;
        case chained_ptr_32:
            pointer.stride = 4;
            pointer.next = (value >> 26U) & 0x1fU;
            pointer.bind = ((value >> 31U) & 1U) != 0;
            if (pointer.bind) {
                pointer.ordinal = value & 0x000fffffU;
                pointer.addend = static_cast<std::int64_t>((value >> 20U) & 0x3fU);
            } else {
                pointer.target = value & 0x03ffffffU;
            }
            break;
        case chained_ptr_32_cache:
            pointer.stride = 4;
            pointer.next = (value >> 30U) & 0x3U;
            pointer.target = value & 0x3fffffffU;
            break;
        case chained_ptr_32_firmware:
            pointer.stride = 4;
            pointer.next = (value >> 26U) & 0x3fU;
            pointer.target = value & 0x03ffffffU;
            break;
        case chained_ptr_arm64e:
        case chained_ptr_arm64e_kernel:
        case chained_ptr_arm64e_userland:
        case chained_ptr_arm64e_firmware:
        case chained_ptr_arm64e_userland24: {
            pointer.stride =
                (format == chained_ptr_arm64e_kernel ||
                 format == chained_ptr_arm64e_firmware)
                ? 4U
                : 8U;
            pointer.next = (value >> 51U) & 0x7ffU;
            pointer.bind = ((value >> 62U) & 1U) != 0;
            const bool authenticated = ((value >> 63U) & 1U) != 0;
            if (pointer.bind) {
                const std::uint64_t zero = format == chained_ptr_arm64e_userland24
                    ? (value >> 24U) & 0xffU
                    : (value >> 16U) & 0xffffU;
                if (zero != 0)
                    return workspace_result_t<chain_pointer_t>::failure(error(
                        workspace_error_code_t::malformed_image,
                        "Mach-O arm64e chained bind has nonzero reserved bits",
                        "macho.chained.pointer"));
                pointer.ordinal = format == chained_ptr_arm64e_userland24
                    ? value & 0x00ffffffU
                    : value & 0x0000ffffU;
                if (!authenticated)
                    pointer.addend = sign_extend((value >> 32U) & 0x7ffffU, 19);
            } else if (authenticated) {
                pointer.target = value & 0xffffffffU;
                pointer.target_is_offset = true;
            } else {
                const std::uint64_t low = value & 0x000007ffffffffffULL;
                const std::uint64_t high = (value >> 43U) & 0xffU;
                pointer.target = low | (high << 56U);
                pointer.target_is_offset =
                    format == chained_ptr_arm64e_kernel ||
                    format == chained_ptr_arm64e_userland ||
                    format == chained_ptr_arm64e_userland24;
            }
            break;
        }
        case chained_ptr_64_kernel_cache:
        case chained_ptr_x86_64_kernel_cache:
            pointer.stride = format == chained_ptr_x86_64_kernel_cache ? 1U : 4U;
            pointer.next = (value >> 51U) & 0xfffU;
            break;
        case chained_ptr_arm64e_shared_cache:
            pointer.stride = 8;
            pointer.next = (value >> 52U) & 0x7ffU;
            pointer.target = value & 0x00000003ffffffffULL;
            pointer.target_is_offset = true;
            if (((value >> 63U) & 1U) == 0) {
                if (((value >> 42U) & 0x3ffU) != 0)
                    return workspace_result_t<chain_pointer_t>::failure(error(
                        workspace_error_code_t::malformed_image,
                        "Mach-O shared-cache chained rebase has nonzero reserved bits",
                        "macho.chained.pointer"));
                pointer.target = *pointer.target | (((value >> 34U) & 0xffU) << 56U);
            }
            break;
        case chained_ptr_arm64e_segmented: {
            pointer.stride = 4;
            pointer.next = (value >> 51U) & 0xfffU;
            const std::uint32_t target_segment =
                static_cast<std::uint32_t>((value >> 28U) & 0xfU);
            const std::uint64_t target_offset = value & 0x0fffffffU;
            if (target_segment >= segments_.size() ||
                target_offset >= segments_[target_segment].vm_size)
                return workspace_result_t<chain_pointer_t>::failure(error(
                    workspace_error_code_t::malformed_image,
                    "Mach-O segmented chained pointer references an invalid segment",
                    "macho.chained.pointer"));
            std::uint64_t target = 0;
            if (!checked_add_u64(segments_[target_segment].vm_address,
                                 target_offset, target))
                return workspace_result_t<chain_pointer_t>::failure(error(
                    workspace_error_code_t::range_overflow,
                    "Mach-O segmented chained target overflowed",
                    "macho.chained.pointer"));
            pointer.target = target;
            break;
        }
        default: {
            auto unsupported = error(
                workspace_error_code_t::unsupported_format,
                "Mach-O chained pointer format is unsupported",
                "macho.chained.pointer");
            unsupported.details.emplace_back("pointer_format", std::to_string(format));
            return workspace_result_t<chain_pointer_t>::failure(std::move(unsupported));
        }
    }
    return workspace_result_t<chain_pointer_t>::success(pointer);
}

workspace_result_t<void> macho_parser_t::walk_chained_page(
    std::uint32_t segment_index, std::uint16_t pointer_format,
    std::uint32_t page_index, std::uint16_t page_size,
    std::uint16_t start, std::uint32_t max_valid_pointer,
    const std::vector<chained_import_record_t>& imports) {
    if (segment_index >= segments_.size() || start >= page_size)
        return workspace_result_t<void>::failure(error(
            workspace_error_code_t::malformed_image,
            "Mach-O chained page start is invalid", "macho.chained.page"));
    const auto& segment = segments_[segment_index];
    const bool pointer32 = pointer_format == chained_ptr_32 ||
                           pointer_format == chained_ptr_32_cache ||
                           pointer_format == chained_ptr_32_firmware;
    const std::uint64_t width = pointer32 ? 4U : 8U;
    std::uint64_t page_offset = 0;
    if (!checked_mul_u64(page_index, page_size, page_offset) ||
        !checked_add_u64(page_offset, start, page_offset))
        return workspace_result_t<void>::failure(error(
            workspace_error_code_t::range_overflow,
            "Mach-O chained page offset overflowed", "macho.chained.page"));
    std::uint64_t offset_in_page = start;
    for (;;) {
        if (++chained_steps_ > limits_.max_chained_fixup_steps)
            return workspace_result_t<void>::failure(make_limit_error(
                "Mach-O chained-fixup traversal exceeds its step budget",
                "macho.chained.page", chained_steps_,
                limits_.max_chained_fixup_steps));
        if (page_offset > segment.vm_size || width > segment.vm_size - page_offset ||
            offset_in_page > page_size || width > page_size - offset_in_page)
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::malformed_image,
                "Mach-O chained pointer escapes its page or segment",
                "macho.chained.page"));
        std::uint64_t vm_address = 0;
        if (!checked_add_u64(segment.vm_address, page_offset, vm_address))
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::range_overflow,
                "Mach-O chained pointer address overflowed",
                "macho.chained.page"));
        auto file_offset = vm_to_file(vm_address, width);
        if (!file_offset)
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::malformed_image,
                "Mach-O chained pointer is not file-backed",
                "macho.chained.page"));
        std::uint64_t raw = 0;
        if (pointer32) {
            auto value = read_u32(*file_offset, "macho.chained.page");
            if (!value)
                return workspace_result_t<void>::failure(value.error());
            raw = value.value();
        } else {
            auto value = read_u64(*file_offset, "macho.chained.page");
            if (!value)
                return workspace_result_t<void>::failure(value.error());
            raw = value.value();
        }
        auto decoded = decode_chain_pointer(pointer_format, raw);
        if (!decoded)
            return workspace_result_t<void>::failure(decoded.error());
        if (decoded.value().stride == 0 ||
            (offset_in_page % decoded.value().stride) != 0)
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::malformed_image,
                "Mach-O chained pointer violates its format alignment",
                "macho.chained.page"));
        std::uint64_t pointer_end = 0;
        if (!checked_add_u64(vm_address, width, pointer_end))
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::range_overflow,
                "Mach-O chained pointer extent overflowed",
                "macho.chained.page"));
        auto next_location = chained_locations_.lower_bound(vm_address);
        bool overlaps = next_location != chained_locations_.end() &&
                        pointer_end > next_location->first;
        if (!overlaps && next_location != chained_locations_.begin()) {
            const auto previous = std::prev(next_location);
            std::uint64_t previous_end = 0;
            if (!checked_add_u64(previous->first, previous->second, previous_end))
                return workspace_result_t<void>::failure(error(
                    workspace_error_code_t::range_overflow,
                    "Mach-O chained pointer history overflowed",
                    "macho.chained.page"));
            overlaps = previous_end > vm_address;
        }
        if (overlaps)
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::malformed_image,
                "Mach-O chained pointer ranges overlap",
                "macho.chained.page"));
        auto location_budget = consume_metadata(
            sizeof(std::pair<const std::uint64_t, std::uint64_t>),
            "macho.chained.page");
        if (!location_budget)
            return location_budget;
        chained_locations_.emplace_hint(next_location, vm_address, width);
        if (decoded.value().bind) {
            if (decoded.value().ordinal >= imports.size())
                return workspace_result_t<void>::failure(error(
                    workspace_error_code_t::malformed_image,
                    "Mach-O chained bind ordinal escapes its import table",
                    "macho.chained.page"));
            const auto& imported = imports[static_cast<std::size_t>(decoded.value().ordinal)];
            std::int64_t total_addend = 0;
            if ((decoded.value().addend > 0 &&
                 imported.addend > (std::numeric_limits<std::int64_t>::max)() -
                                       decoded.value().addend) ||
                (decoded.value().addend < 0 &&
                 imported.addend < (std::numeric_limits<std::int64_t>::min)() -
                                       decoded.value().addend))
                return workspace_result_t<void>::failure(error(
                    workspace_error_code_t::range_overflow,
                    "Mach-O chained bind addend overflowed",
                    "macho.chained.page"));
            total_addend = imported.addend + decoded.value().addend;
            auto bound = append_bind(segment_index, page_offset, imported.name,
                                     imported.library_ordinal, total_addend, 1,
                                     imported.weak, false);
            if (!bound)
                return bound;
        } else if (!(pointer_format == chained_ptr_32 && decoded.value().target &&
                     *decoded.value().target > max_valid_pointer)) {
            auto rebased = append_rebase(segment_index, page_offset, 0x30000U |
                                                               pointer_format);
            if (!rebased)
                return rebased;
            if (decoded.value().target) {
                std::uint64_t target = *decoded.value().target;
                if (decoded.value().target_is_offset) {
                    if (pointer_format == chained_ptr_64_offset)
                        target &= 0x0000000fffffffffULL;
                    else
                        target &= 0x000007ffffffffffULL;
                    if (!checked_add_u64(image_base_, target, target))
                        return workspace_result_t<void>::failure(error(
                            workspace_error_code_t::range_overflow,
                            "Mach-O chained rebase target overflowed",
                            "macho.chained.page"));
                }
                if (vm_to_rva(target))
                    relocations_.back().target_vm_address = target;
            }
        }
        if (decoded.value().next == 0)
            break;
        std::uint64_t increment = 0;
        if (!checked_mul_u64(decoded.value().next, decoded.value().stride, increment) ||
            increment == 0 || !checked_add_u64(page_offset, increment, page_offset) ||
            !checked_add_u64(offset_in_page, increment, offset_in_page))
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::range_overflow,
                "Mach-O chained pointer increment overflowed",
                "macho.chained.page"));
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<void> macho_parser_t::parse_chained_fixups() {
    if (!chained_fixups_ || chained_fixups_->size == 0)
        return workspace_result_t<void>::success();
    if ((chained_fixups_->offset & 3U) != 0)
        return workspace_result_t<void>::failure(error(
            workspace_error_code_t::malformed_image,
            "Mach-O chained-fixup payload is not naturally aligned",
            "macho.chained", chained_fixups_->offset, chained_fixups_->size));
    auto range = register_metadata_range(chained_fixups_->offset, chained_fixups_->size,
                                         "chained_fixups");
    if (!range)
        return range;
    auto blob = read_blob(chained_fixups_->offset, chained_fixups_->size,
                          "macho.chained");
    if (!blob)
        return workspace_result_t<void>::failure(blob.error());
    const auto& data = blob.value();
    if (data.size() < 28)
        return workspace_result_t<void>::failure(error(
            workspace_error_code_t::malformed_image,
            "Mach-O chained-fixup header is truncated", "macho.chained",
            chained_fixups_->offset, chained_fixups_->size));
    const std::uint32_t version = reader_.u32(data.data());
    const std::uint32_t starts_offset = reader_.u32(data.data() + 4);
    const std::uint32_t imports_offset = reader_.u32(data.data() + 8);
    const std::uint32_t symbols_offset = reader_.u32(data.data() + 12);
    const std::uint32_t imports_count = reader_.u32(data.data() + 16);
    const std::uint32_t imports_format = reader_.u32(data.data() + 20);
    const std::uint32_t symbols_format = reader_.u32(data.data() + 24);
    if (version != 0 || starts_offset < 28 || starts_offset >= data.size() ||
        imports_offset > data.size() || symbols_offset > data.size())
        return workspace_result_t<void>::failure(error(
            workspace_error_code_t::malformed_image,
            "Mach-O chained-fixup header fields are invalid", "macho.chained"));
    auto imports = parse_chained_imports(data, imports_offset, imports_count,
                                         imports_format, symbols_offset,
                                         symbols_format);
    if (!imports)
        return workspace_result_t<void>::failure(imports.error());
    if (data.size() - starts_offset < 4)
        return workspace_result_t<void>::failure(error(
            workspace_error_code_t::malformed_image,
            "Mach-O chained starts-in-image record is truncated",
            "macho.chained.starts"));
    const std::uint32_t segment_count = reader_.u32(data.data() + starts_offset);
    std::uint64_t offsets_size = 0;
    if (segment_count != segments_.size() ||
        !checked_mul_u64(segment_count, 4, offsets_size) ||
        offsets_size > data.size() - starts_offset - 4U)
        return workspace_result_t<void>::failure(error(
            workspace_error_code_t::malformed_image,
            "Mach-O chained segment-offset table is invalid",
            "macho.chained.starts"));
    checked_span_t starts_header{starts_offset, 4U + offsets_size};
    std::optional<checked_span_t> imports_span;
    std::optional<checked_span_t> symbols_span;
    if (imports_count != 0) {
        const std::uint64_t import_record_size = imports_format == chained_import
            ? 4U
            : (imports_format == chained_import_addend ? 8U : 16U);
        std::uint64_t import_bytes = 0;
        if (!checked_mul_u64(imports_count, import_record_size, import_bytes))
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::range_overflow,
                "Mach-O chained import span overflowed",
                "macho.chained.starts"));
        imports_span = checked_span_t{imports_offset, import_bytes};
        symbols_span = checked_span_t{symbols_offset, data.size() - symbols_offset};
        if (starts_header.overlaps(*imports_span) ||
            starts_header.overlaps(*symbols_span))
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::malformed_image,
                "Mach-O chained starts table overlaps import or symbol metadata",
                "macho.chained.starts"));
    }
    std::vector<checked_span_t> segment_info_ranges;
    segment_info_ranges.reserve(segment_count);
    std::uint64_t total_pages = 0;
    for (std::uint32_t segment_index = 0; segment_index < segment_count;
         ++segment_index) {
        auto stopped = poll(segment_index, "macho.chained.starts");
        if (!stopped)
            return stopped;
        const std::uint32_t relative = reader_.u32(
            data.data() + starts_offset + 4U + segment_index * 4U);
        if (relative == 0)
            continue;
        std::uint64_t segment_info = 0;
        if (!checked_add_u64(starts_offset, relative, segment_info) ||
            segment_info > data.size() || data.size() - segment_info < 22)
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::malformed_image,
                "Mach-O chained starts-in-segment offset is invalid",
                "macho.chained.starts"));
        const auto* info = data.data() + segment_info;
        const std::uint32_t info_size = reader_.u32(info);
        const std::uint16_t page_size = reader_.u16(info + 4);
        const std::uint16_t pointer_format = reader_.u16(info + 6);
        const std::uint64_t segment_offset = reader_.u64(info + 8);
        const std::uint16_t page_count = reader_.u16(info + 20);
        std::uint64_t page_bytes = 0;
        std::uint64_t minimum_size = 0;
        if ((page_size != 0x1000U && page_size != 0x4000U) ||
            !checked_mul_u64(page_count, 2, page_bytes) ||
            !checked_add_u64(22, page_bytes, minimum_size) ||
            info_size < minimum_size || info_size > data.size() - segment_info)
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::malformed_image,
                "Mach-O chained starts-in-segment record is invalid",
                "macho.chained.starts"));
        checked_span_t info_span{segment_info, info_size};
        if (info_span.overlaps(starts_header) ||
            (imports_span && info_span.overlaps(*imports_span)) ||
            (symbols_span && info_span.overlaps(*symbols_span)))
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::malformed_image,
                "Mach-O chained segment record overlaps its offset table",
                "macho.chained.starts"));
        for (const auto& existing : segment_info_ranges) {
            if (info_span.overlaps(existing))
                return workspace_result_t<void>::failure(error(
                    workspace_error_code_t::malformed_image,
                    "Mach-O chained segment records overlap",
                    "macho.chained.starts"));
        }
        segment_info_ranges.push_back(info_span);
        if (!checked_add_u64(total_pages, page_count, total_pages) ||
            total_pages > limits_.max_chained_fixup_pages)
            return workspace_result_t<void>::failure(make_limit_error(
                "Mach-O chained page count exceeds its budget",
                "macho.chained.starts", total_pages,
                limits_.max_chained_fixup_pages));
        const auto& segment = segments_[segment_index];
        bool pointer_format_32 = false;
        bool pointer_format_arm64e = false;
        switch (pointer_format) {
            case chained_ptr_32:
            case chained_ptr_32_cache:
            case chained_ptr_32_firmware:
                pointer_format_32 = true;
                break;
            case chained_ptr_arm64e:
            case chained_ptr_arm64e_kernel:
            case chained_ptr_arm64e_userland:
            case chained_ptr_arm64e_firmware:
            case chained_ptr_arm64e_userland24:
            case chained_ptr_arm64e_shared_cache:
            case chained_ptr_arm64e_segmented:
                pointer_format_arm64e = true;
                break;
            case chained_ptr_64:
            case chained_ptr_64_offset:
            case chained_ptr_64_kernel_cache:
            case chained_ptr_x86_64_kernel_cache:
                break;
            default:
                return workspace_result_t<void>::failure(error(
                    workspace_error_code_t::unsupported_format,
                    "Mach-O chained pointer format is unsupported",
                    "macho.chained.starts"));
        }
        if ((pointer_format_32 && pointer_size_ != 4) ||
            (!pointer_format_32 && pointer_size_ != 8) ||
            (pointer_format_arm64e && architecture_ != architecture_id_t::aarch64) ||
            (pointer_format == chained_ptr_x86_64_kernel_cache &&
             architecture_ != architecture_id_t::x86_64))
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::malformed_image,
                "Mach-O chained pointer format disagrees with the image architecture",
                "macho.chained.starts"));
        auto segment_rva = vm_to_rva(segment.vm_address, segment.vm_size == 0 ? 1 :
                                                             segment.vm_size);
        if (!segment_rva || segment_offset != *segment_rva)
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::malformed_image,
                "Mach-O chained segment offset disagrees with the segment layout",
                "macho.chained.starts"));
        std::uint64_t rounded_size = 0;
        if (!checked_add_u64(segment.vm_size, page_size - 1U, rounded_size))
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::range_overflow,
                "Mach-O chained segment page count overflowed",
                "macho.chained.starts"));
        const std::uint64_t expected_pages = rounded_size / page_size;
        if (page_count != expected_pages)
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::malformed_image,
                "Mach-O chained page count disagrees with its segment extent",
                "macho.chained.starts"));
        for (std::uint32_t page_index = 0; page_index < page_count; ++page_index) {
            const std::uint16_t start = reader_.u16(info + 22U + page_index * 2U);
            if (start == chained_start_none)
                continue;
            if ((start & chained_start_multi) == 0) {
                auto walked = walk_chained_page(segment_index, pointer_format,
                                                page_index, page_size, start,
                                                reader_.u32(info + 16),
                                                imports.value());
                if (!walked)
                    return walked;
                continue;
            }
            std::uint64_t overflow_index = start & chained_start_value_mask;
            if (overflow_index >= (info_size - 22U - page_bytes) / 2U)
                return workspace_result_t<void>::failure(error(
                    workspace_error_code_t::malformed_image,
                    "Mach-O chained multi-start index escapes its overflow pool",
                    "macho.chained.starts"));
            for (;;) {
                std::uint64_t entry_offset = 22U + page_bytes + overflow_index * 2U;
                if (entry_offset > info_size || 2U > info_size - entry_offset)
                    return workspace_result_t<void>::failure(error(
                        workspace_error_code_t::malformed_image,
                        "Mach-O chained multi-start list escapes its record",
                        "macho.chained.starts"));
                const std::uint16_t entry = reader_.u16(info + entry_offset);
                auto walked = walk_chained_page(
                    segment_index, pointer_format, page_index, page_size,
                    entry & chained_start_value_mask, reader_.u32(info + 16),
                    imports.value());
                if (!walked)
                    return walked;
                ++overflow_index;
                if ((entry & chained_start_last) != 0)
                    break;
            }
        }
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<void> macho_parser_t::parse_function_starts() {
    if (!function_starts_ || function_starts_->size == 0)
        return workspace_result_t<void>::success();
    auto range = register_metadata_range(function_starts_->offset,
                                         function_starts_->size,
                                         "function_starts");
    if (!range)
        return range;
    auto blob = read_blob(function_starts_->offset, function_starts_->size,
                          "macho.function_starts");
    if (!blob)
        return workspace_result_t<void>::failure(blob.error());
    std::uint64_t cursor = 0;
    std::uint64_t current_rva = 0;
    std::uint64_t count = 0;
    bool terminated = false;
    while (cursor < blob.value().size()) {
        auto stopped = poll(count, "macho.function_starts");
        if (!stopped)
            return stopped;
        std::uint64_t delta = 0;
        if (!decode_uleb128(blob.value(), cursor, blob.value().size(), delta))
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::malformed_image,
                "Mach-O function-start delta is invalid",
                "macho.function_starts"));
        if (delta == 0) {
            terminated = true;
            break;
        }
        if (++count > limits_.max_function_starts)
            return workspace_result_t<void>::failure(make_limit_error(
                "Mach-O function-start count exceeds its budget",
                "macho.function_starts", count, limits_.max_function_starts));
        if (!checked_add_u64(current_rva, delta, current_rva))
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::range_overflow,
                "Mach-O function-start address overflowed",
                "macho.function_starts"));
        if (current_rva >= image_size_)
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::malformed_image,
                "Mach-O function start is outside the image",
                "macho.function_starts"));
        std::uint64_t vm_address = 0;
        if (!checked_add_u64(image_base_, current_rva, vm_address))
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::range_overflow,
                "Mach-O function-start address overflowed",
                "macho.function_starts"));
        auto added = add_metadata_symbol(std::string{}, vm_address, 0,
                                         image_symbol_kind_t::function);
        if (!added)
            return added;
    }
    if (!terminated)
        return workspace_result_t<void>::failure(error(
            workspace_error_code_t::malformed_image,
            "Mach-O function-start table is not terminated",
            "macho.function_starts"));
    while (cursor < blob.value().size()) {
        if (blob.value()[static_cast<std::size_t>(cursor++)] != 0)
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::malformed_image,
                "Mach-O function-start table has nonzero trailing bytes",
                "macho.function_starts"));
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<void> macho_parser_t::parse_data_in_code() {
    if (!data_in_code_ || data_in_code_->size == 0)
        return workspace_result_t<void>::success();
    if ((data_in_code_->offset & 3U) != 0)
        return workspace_result_t<void>::failure(error(
            workspace_error_code_t::malformed_image,
            "Mach-O data-in-code table is not naturally aligned",
            "macho.data_in_code", data_in_code_->offset, data_in_code_->size));
    if ((data_in_code_->size % 8U) != 0)
        return workspace_result_t<void>::failure(error(
            workspace_error_code_t::malformed_image,
            "Mach-O data-in-code table has a partial record",
            "macho.data_in_code", data_in_code_->offset, data_in_code_->size));
    const std::uint64_t count = data_in_code_->size / 8U;
    if (count > limits_.max_data_in_code_entries)
        return workspace_result_t<void>::failure(make_limit_error(
            "Mach-O data-in-code count exceeds its budget", "macho.data_in_code",
            count, limits_.max_data_in_code_entries));
    auto range = register_metadata_range(data_in_code_->offset, data_in_code_->size,
                                         "data_in_code");
    if (!range)
        return range;
    auto blob = read_blob(data_in_code_->offset, data_in_code_->size,
                          "macho.data_in_code");
    if (!blob)
        return workspace_result_t<void>::failure(blob.error());
    std::uint64_t previous_end = 0;
    bool have_previous = false;
    for (std::uint64_t index = 0; index < count; ++index) {
        auto stopped = poll(index, "macho.data_in_code");
        if (!stopped)
            return stopped;
        const auto* record = blob.value().data() + static_cast<std::size_t>(index * 8U);
        const std::uint32_t file_offset = reader_.u32(record);
        const std::uint16_t length = reader_.u16(record + 4);
        const std::uint16_t kind = reader_.u16(record + 6);
        if (length == 0 || kind == 0 || kind > 5 ||
            (kind == 3U && (length & 1U) != 0) ||
            (kind >= 4U && (length & 3U) != 0))
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::malformed_image,
                "Mach-O data-in-code entry has an invalid length or kind",
                "macho.data_in_code",
                data_in_code_->offset + index * 8U, 8));
        std::uint64_t entry_end = 0;
        if (!checked_add_u64(file_offset, length, entry_end))
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::range_overflow,
                "Mach-O data-in-code range overflowed",
                "macho.data_in_code",
                data_in_code_->offset + index * 8U, 8));
        if (have_previous && file_offset < previous_end)
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::malformed_image,
                "Mach-O data-in-code ranges overlap or are out of order",
                "macho.data_in_code",
                data_in_code_->offset + index * 8U, 8));
        previous_end = entry_end;
        have_previous = true;
        auto vm_address = file_to_vm(file_offset, length);
        if (!vm_address)
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::malformed_image,
                "Mach-O data-in-code entry is not mapped by a segment",
                "macho.data_in_code", data_in_code_->offset + index * 8U, 8));
        bool executable = false;
        for (const auto& segment : segments_) {
            if ((segment.initial_protection & 4) == 0 ||
                *vm_address < segment.vm_address)
                continue;
            const std::uint64_t delta = *vm_address - segment.vm_address;
            if (delta <= segment.vm_size && length <= segment.vm_size - delta) {
                executable = true;
                break;
            }
        }
        if (!executable)
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::malformed_image,
                "Mach-O data-in-code entry is outside executable memory",
                "macho.data_in_code", data_in_code_->offset + index * 8U, 8));
        auto added = add_metadata_symbol("data-in-code:" + std::to_string(kind),
                                         *vm_address, length);
        if (!added)
            return added;
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<void> macho_parser_t::parse_thread_commands() {
    std::uint64_t state_count = 0;
    for (const auto& command : thread_commands_) {
        std::uint64_t cursor = command.offset + 8U;
        const std::uint64_t end = command.offset + command.size;
        while (cursor < end) {
            if (end - cursor < 8)
                return workspace_result_t<void>::failure(error(
                    workspace_error_code_t::malformed_image,
                    "Mach-O thread-state header is truncated", "macho.thread",
                    cursor, end - cursor));
            auto flavor = read_u32(cursor, "macho.thread");
            auto count = read_u32(cursor + 4U, "macho.thread");
            if (!flavor || !count || count.value() == 0 || count.value() > 4096)
                return workspace_result_t<void>::failure(error(
                    workspace_error_code_t::malformed_image,
                    "Mach-O thread-state flavor or count is invalid", "macho.thread",
                    cursor, 8));
            std::uint64_t state_size = 0;
            if (!checked_mul_u64(count.value(), 4, state_size) ||
                state_size > end - cursor - 8U)
                return workspace_result_t<void>::failure(error(
                    workspace_error_code_t::malformed_image,
                    "Mach-O thread-state payload is truncated", "macho.thread",
                    cursor, end - cursor));
            if (++state_count > limits_.max_thread_states)
                return workspace_result_t<void>::failure(make_limit_error(
                    "Mach-O thread-state count exceeds its budget", "macho.thread",
                    state_count, limits_.max_thread_states));
            const std::uint64_t state = cursor + 8U;
            std::optional<std::uint64_t> program_counter;
            std::uint64_t expected_state_size = 0;
            std::uint64_t program_counter_offset = 0;
            bool program_counter_is_64_bit = false;
            if (architecture_ == architecture_id_t::x86 && flavor.value() == 1U) {
                expected_state_size = 64U;
                program_counter_offset = 40U;
            } else if (architecture_ == architecture_id_t::x86_64 &&
                       flavor.value() == 4U) {
                expected_state_size = 168U;
                program_counter_offset = 128U;
                program_counter_is_64_bit = true;
            } else if (architecture_ == architecture_id_t::arm &&
                       flavor.value() == 1U) {
                expected_state_size = 68U;
                program_counter_offset = 60U;
            } else if (architecture_ == architecture_id_t::aarch64 &&
                       flavor.value() == 6U) {
                expected_state_size = 272U;
                program_counter_offset = 256U;
                program_counter_is_64_bit = true;
            } else if (architecture_ == architecture_id_t::ppc &&
                       flavor.value() == 1U) {
                expected_state_size = 160U;
            } else if (architecture_ == architecture_id_t::ppc64 &&
                       flavor.value() == 5U) {
                expected_state_size = 312U;
                program_counter_is_64_bit = true;
            }
            if (expected_state_size != 0) {
                if (state_size != expected_state_size)
                    return workspace_result_t<void>::failure(error(
                        workspace_error_code_t::malformed_image,
                        "Mach-O recognized thread state has an invalid size",
                        "macho.thread", cursor, 8U + state_size));
                if (program_counter_is_64_bit) {
                    auto value = read_u64(state + program_counter_offset,
                                          "macho.thread");
                    if (!value)
                        return workspace_result_t<void>::failure(value.error());
                    program_counter = value.value();
                } else {
                    auto value = read_u32(state + program_counter_offset,
                                          "macho.thread");
                    if (!value)
                        return workspace_result_t<void>::failure(value.error());
                    program_counter = value.value();
                }
            }
            if (program_counter && *program_counter != 0)
                vm_entry_points_.emplace_back(
                    *program_counter,
                    command.command == lc_unixthread
                        ? "load-command:unixthread"
                        : "load-command:thread");
            cursor += 8U + state_size;
        }
        if (cursor != end)
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::malformed_image,
                "Mach-O thread-state records do not consume their command",
                "macho.thread", command.offset, command.size));
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<void> macho_parser_t::add_metadata_symbol(
    std::string name, std::uint64_t vm_address, std::uint64_t size,
    image_symbol_kind_t kind) {
    if (metadata_symbols_.size() >= limits_.max_metadata_symbols)
        return workspace_result_t<void>::failure(make_limit_error(
            "Mach-O metadata-symbol count exceeds its budget", "macho.metadata",
            metadata_symbols_.size() + 1U, limits_.max_metadata_symbols));
    if (!vm_to_rva(vm_address, size == 0 ? 1 : size))
        return workspace_result_t<void>::failure(error(
            workspace_error_code_t::malformed_image,
            "Mach-O metadata symbol is outside the image", "macho.metadata"));
    auto string_budget = consume_string(name.size(), "macho.metadata");
    if (!string_budget)
        return string_budget;
    auto metadata_budget = consume_metadata(sizeof(metadata_symbol_record_t),
                                            "macho.metadata");
    if (!metadata_budget)
        return metadata_budget;
    metadata_symbols_.push_back({std::move(name), vm_address, size, kind});
    return workspace_result_t<void>::success();
}

workspace_result_t<void> macho_parser_t::parse_cstring_metadata(
    const section_record_t& section, std::string prefix) {
    if (section.file_size == 0)
        return workspace_result_t<void>::success();
    auto blob = read_blob(section.file_offset, section.file_size,
                          "macho.metadata.strings");
    if (!blob)
        return workspace_result_t<void>::failure(blob.error());
    std::uint64_t cursor = 0;
    while (cursor < blob.value().size()) {
        while (cursor < blob.value().size() &&
               blob.value()[static_cast<std::size_t>(cursor)] == 0)
            ++cursor;
        if (cursor == blob.value().size())
            break;
        const std::uint64_t start = cursor;
        while (cursor < blob.value().size() &&
               blob.value()[static_cast<std::size_t>(cursor)] != 0)
            ++cursor;
        if (cursor == blob.value().size())
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::malformed_image,
                "Mach-O metadata string is not terminated in its section",
                "macho.metadata.strings", section.file_offset + start,
                section.file_size - start));
        std::string value(
            reinterpret_cast<const char*>(blob.value().data() + start),
            static_cast<std::size_t>(cursor - start));
        if (prefix.size() > limits_.max_string_bytes ||
            value.size() > limits_.max_string_bytes - prefix.size())
            return workspace_result_t<void>::failure(make_limit_error(
                "Mach-O recovered metadata string exceeds its budget",
                "macho.metadata.strings", prefix.size() + value.size(),
                limits_.max_string_bytes));
        std::uint64_t vm_address = 0;
        if (!checked_add_u64(section.vm_address, start, vm_address))
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::range_overflow,
                "Mach-O metadata string address overflowed",
                "macho.metadata.strings"));
        auto added = add_metadata_symbol(prefix + value, vm_address,
                                         value.size() + 1U);
        if (!added)
            return added;
        ++cursor;
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<void> macho_parser_t::parse_pointer_metadata(
    const section_record_t& section, std::string name) {
    if (section.file_size == 0)
        return workspace_result_t<void>::success();
    if ((section.file_size % pointer_size_) != 0)
        return workspace_result_t<void>::failure(error(
            workspace_error_code_t::malformed_image,
            "Mach-O pointer metadata section has a partial pointer",
            "macho.metadata.pointers", section.file_offset, section.file_size));
    const std::uint64_t count = section.file_size / pointer_size_;
    if (count > limits_.max_metadata_symbols - metadata_symbols_.size())
        return workspace_result_t<void>::failure(make_limit_error(
            "Mach-O pointer metadata exceeds its symbol budget",
            "macho.metadata.pointers", metadata_symbols_.size() + count,
            limits_.max_metadata_symbols));
    for (std::uint64_t index = 0; index < count; ++index) {
        auto stopped = poll(index, "macho.metadata.pointers");
        if (!stopped)
            return stopped;
        const std::uint64_t file_offset = section.file_offset + index * pointer_size_;
        std::uint64_t target = 0;
        if (pointer_size_ == 8) {
            auto value = read_u64(file_offset, "macho.metadata.pointers");
            if (!value)
                return workspace_result_t<void>::failure(value.error());
            target = value.value();
        } else {
            auto value = read_u32(file_offset, "macho.metadata.pointers");
            if (!value)
                return workspace_result_t<void>::failure(value.error());
            target = value.value();
        }
        if (target == 0 || !vm_to_rva(target))
            continue;
        auto added = add_metadata_symbol(name, target, 0);
        if (!added)
            return added;
        if (relocations_.size() >= limits_.max_relocations)
            return workspace_result_t<void>::failure(make_limit_error(
                "Mach-O relocation count exceeds its budget",
                "macho.metadata.pointers", relocations_.size() + 1U,
                limits_.max_relocations));
        std::uint64_t location = 0;
        if (!checked_add_u64(section.vm_address, index * pointer_size_, location))
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::range_overflow,
                "Mach-O metadata pointer address overflowed",
                "macho.metadata.pointers"));
        auto relocation_budget = consume_metadata(sizeof(relocation_record_t),
                                                  "macho.metadata.pointers");
        if (!relocation_budget)
            return relocation_budget;
        relocations_.push_back({location, 0x40000U, target});
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<void> macho_parser_t::parse_swift_relative_metadata(
    const section_record_t& section, std::string name) {
    if (section.file_size == 0)
        return workspace_result_t<void>::success();
    if ((section.file_size % 4U) != 0)
        return workspace_result_t<void>::failure(error(
            workspace_error_code_t::malformed_image,
            "Mach-O Swift metadata section has a partial relative pointer",
            "macho.metadata.swift", section.file_offset, section.file_size));
    const std::uint64_t count = section.file_size / 4U;
    if (count > limits_.max_metadata_symbols - metadata_symbols_.size())
        return workspace_result_t<void>::failure(make_limit_error(
            "Mach-O Swift metadata exceeds its symbol budget",
            "macho.metadata.swift", metadata_symbols_.size() + count,
            limits_.max_metadata_symbols));
    for (std::uint64_t index = 0; index < count; ++index) {
        auto stopped = poll(index, "macho.metadata.swift");
        if (!stopped)
            return stopped;
        auto relative = read_i32(section.file_offset + index * 4U,
                                 "macho.metadata.swift");
        if (!relative)
            return workspace_result_t<void>::failure(relative.error());
        if (relative.value() == 0)
            continue;
        if ((static_cast<std::uint32_t>(relative.value()) & 3U) != 0)
            continue;
        std::uint64_t location = 0;
        if (!checked_add_u64(section.vm_address, index * 4U, location))
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::range_overflow,
                "Mach-O Swift relative-pointer location overflowed",
                "macho.metadata.swift"));
        std::uint64_t target = 0;
        if (relative.value() > 0) {
            if (!checked_add_u64(location, static_cast<std::uint32_t>(relative.value()),
                                 target))
                return workspace_result_t<void>::failure(error(
                    workspace_error_code_t::range_overflow,
                    "Mach-O Swift relative-pointer target overflowed",
                    "macho.metadata.swift"));
        } else {
            const std::uint64_t magnitude =
                static_cast<std::uint64_t>(-
                    static_cast<std::int64_t>(relative.value()));
            if (!checked_sub_u64(location, magnitude, target))
                return workspace_result_t<void>::failure(error(
                    workspace_error_code_t::malformed_image,
                    "Mach-O Swift relative-pointer target underflowed",
                    "macho.metadata.swift"));
        }
        if (!vm_to_rva(target))
            continue;
        auto added = add_metadata_symbol(name, target, 0);
        if (!added)
            return added;
        if (relocations_.size() >= limits_.max_relocations)
            return workspace_result_t<void>::failure(make_limit_error(
                "Mach-O relocation count exceeds its budget",
                "macho.metadata.swift", relocations_.size() + 1U,
                limits_.max_relocations));
        auto relocation_budget = consume_metadata(sizeof(relocation_record_t),
                                                  "macho.metadata.swift");
        if (!relocation_budget)
            return relocation_budget;
        relocations_.push_back({location, 0x50000U, target});
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<void> macho_parser_t::parse_language_metadata() {
    if (uuid_) {
        auto marker = add_metadata_symbol("macho-uuid:" + *uuid_, image_base_, 0);
        if (!marker)
            return marker;
    }
    if (file_type_ == mh_dsym) {
        auto marker = add_metadata_symbol("macho:dsym", image_base_, 0);
        if (!marker)
            return marker;
    }
    for (const auto& section : sections_) {
        if (section.size == 0)
            continue;
        if (dwarf_section(section.section_name)) {
            auto marker = add_metadata_symbol("dwarf:" + section.section_name,
                                              section.vm_address, section.size);
            if (!marker)
                return marker;
        }
        if (objc_section(section.section_name)) {
            auto marker = add_metadata_symbol("objc-section:" + section.section_name,
                                              section.vm_address, section.size);
            if (!marker)
                return marker;
            if (section.section_name == "__objc_methname") {
                auto parsed = parse_cstring_metadata(section, "objc-method:");
                if (!parsed)
                    return parsed;
            } else if (section.section_name == "__objc_classname") {
                auto parsed = parse_cstring_metadata(section, "objc-class:");
                if (!parsed)
                    return parsed;
            } else if (section.section_name == "__objc_methtype") {
                auto parsed = parse_cstring_metadata(section, "objc-method-type:");
                if (!parsed)
                    return parsed;
            } else if (section.section_name == "__objc_classlist" ||
                       section.section_name == "__objc_nlclslist") {
                auto parsed = parse_pointer_metadata(section, "objc-class-descriptor");
                if (!parsed)
                    return parsed;
            } else if (section.section_name == "__objc_protolist") {
                auto parsed = parse_pointer_metadata(section, "objc-protocol-descriptor");
                if (!parsed)
                    return parsed;
            } else if (section.section_name == "__objc_catlist" ||
                       section.section_name == "__objc_nlcatlist") {
                auto parsed = parse_pointer_metadata(section, "objc-category-descriptor");
                if (!parsed)
                    return parsed;
            }
        }
        if (swift_section(section.section_name)) {
            auto marker = add_metadata_symbol("swift-section:" + section.section_name,
                                              section.vm_address, section.size);
            if (!marker)
                return marker;
            if (section.section_name == "__swift5_reflstr") {
                auto parsed = parse_cstring_metadata(section, "swift-reflection:");
                if (!parsed)
                    return parsed;
            } else if (section.section_name == "__swift5_types") {
                auto parsed = parse_swift_relative_metadata(section,
                                                            "swift-type-descriptor");
                if (!parsed)
                    return parsed;
            } else if (section.section_name == "__swift5_protos" ||
                       section.section_name == "__swift5_proto") {
                auto parsed = parse_swift_relative_metadata(
                    section, "swift-protocol-descriptor");
                if (!parsed)
                    return parsed;
            } else if (section.section_name == "__swift5_entry") {
                auto parsed = parse_swift_relative_metadata(section,
                                                            "swift-entry-point");
                if (!parsed)
                    return parsed;
            }
        }
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<parse_product_t> macho_parser_t::normalize() {
    auto image_budget = consume_metadata(sizeof(workspace_image_t), "macho.normalize");
    if (!image_budget)
        return workspace_result_t<parse_product_t>::failure(image_budget.error());
    auto normalized = std::make_shared<workspace_image_t>();
    normalized->format = format_id_t::macho;
    normalized->architecture = architecture_;
    normalized->architecture_mode = architecture_mode_;
    normalized->abi = abi_;
    normalized->endian = reader_.endian;
    normalized->address_width_bits = static_cast<std::uint8_t>(pointer_size_ * 8U);
    normalized->image_base = image_base_;
    normalized->image_size = image_size_;
    auto header_vm = file_to_vm(0, commands_end_);
    normalized->header_size = segments_.empty()
        ? std::min(commands_end_, image_size_)
        : (header_vm && *header_vm == image_base_
               ? std::min(commands_end_, image_size_)
               : 0);
    normalized->format_name = is_64_bit_ ? "macho64" : "macho32";
    if (file_type_ == mh_dsym)
        normalized->format_name += "-dsym";
    normalized->provider_source = provider_source_;
    normalized->provider_size = provider_size_;
    normalized->member = member_;

    const auto make_address = [&](std::uint64_t rva) {
        return address_t{address_space_id_t::relative_virtual, rva,
                         architecture_, architecture_mode_};
    };
    const auto segment_permissions = [](const segment_record_t& segment) {
        return ((segment.initial_protection & 1) != 0 ? image_permission_read : 0U) |
               ((segment.initial_protection & 2) != 0 ? image_permission_write : 0U) |
               ((segment.initial_protection & 4) != 0 ? image_permission_execute : 0U);
    };

    if (normalized->header_size != 0 && segments_.empty()) {
        normalized->address_mappings.push_back({
            address_space_id_t::file_offset,
            address_space_id_t::relative_virtual,
            0,
            0,
            normalized->header_size,
            image_permission_read});
    }
    for (const auto& segment : segments_) {
        const bool guard = segment.file_size == 0 && segment.initial_protection == 0 &&
                           segment.name == "__PAGEZERO";
        if (guard || segment.vm_size == 0 || segment.vm_address < image_base_)
            continue;
        auto rva = vm_to_rva(segment.vm_address, segment.vm_size);
        if (!rva)
            return workspace_result_t<parse_product_t>::failure(error(
                workspace_error_code_t::malformed_image,
                "Mach-O segment cannot be normalized", "macho.normalize"));
        image_segment_t output;
        output.index = segment.index;
        output.name = segment.name;
        output.virtual_address = *rva;
        output.virtual_size = segment.vm_size;
        output.file_offset = segment.file_offset;
        output.file_size = segment.file_size;
        output.flags = segment.flags;
        output.permissions = segment_permissions(segment);
        normalized->segments.push_back(output);
        if (segment.file_size != 0) {
            std::uint64_t mapping_vm = segment.vm_address;
            if ((segment.flags & sg_highvm) != 0 &&
                !checked_add_u64(mapping_vm,
                                 segment.vm_size - segment.file_size,
                                 mapping_vm))
                return workspace_result_t<parse_product_t>::failure(error(
                    workspace_error_code_t::range_overflow,
                    "Mach-O high-VM segment mapping overflowed",
                    "macho.normalize"));
            auto mapping_rva = vm_to_rva(mapping_vm, segment.file_size);
            if (!mapping_rva)
                return workspace_result_t<parse_product_t>::failure(error(
                    workspace_error_code_t::malformed_image,
                    "Mach-O segment file mapping cannot be normalized",
                    "macho.normalize"));
            normalized->address_mappings.push_back({
                address_space_id_t::file_offset,
                address_space_id_t::relative_virtual,
                segment.file_offset,
                *mapping_rva,
                segment.file_size,
                output.permissions});
        }
    }
    for (const auto& section : sections_) {
        if (section.size == 0)
            continue;
        auto rva = vm_to_rva(section.vm_address, section.size);
        if (!rva)
            return workspace_result_t<parse_product_t>::failure(error(
                workspace_error_code_t::malformed_image,
                "Mach-O section cannot be normalized", "macho.normalize"));
        image_section_t output;
        output.index = section.index;
        output.name = section.segment_name + "," + section.section_name;
        output.virtual_address = *rva;
        output.virtual_size = section.size;
        output.file_offset = section.file_size == 0 ? 0 : section.file_offset;
        output.file_size = section.file_size;
        output.flags = section.flags;
        output.permissions = section.permissions;
        normalized->sections.push_back(std::move(output));
    }

    const auto executable_rva = [&](std::uint64_t rva) {
        for (const auto& segment : normalized->segments) {
            if ((segment.permissions & image_permission_execute) == 0 ||
                rva < segment.virtual_address)
                continue;
            const std::uint64_t delta = rva - segment.virtual_address;
            if (delta < segment.virtual_size)
                return true;
        }
        return false;
    };
    std::set<std::pair<std::uint64_t, std::string>> entry_dedupe;
    for (const auto& entry : file_entry_points_) {
        auto vm_address = file_to_vm(entry.first);
        auto rva = vm_address ? vm_to_rva(*vm_address) : std::nullopt;
        if (!rva || !executable_rva(*rva))
            return workspace_result_t<parse_product_t>::failure(error(
                workspace_error_code_t::malformed_image,
                "Mach-O file-offset entry point is not executable",
                "macho.normalize.entry", entry.first, 1));
        if (entry_dedupe.emplace(*rva, entry.second).second)
            normalized->entry_points.push_back({make_address(*rva), entry.second});
    }
    for (const auto& entry : vm_entry_points_) {
        auto rva = vm_to_rva(entry.first);
        if (!rva || !executable_rva(*rva))
            return workspace_result_t<parse_product_t>::failure(error(
                workspace_error_code_t::malformed_image,
                "Mach-O thread or routines entry point is not executable",
                "macho.normalize.entry"));
        if (entry_dedupe.emplace(*rva, entry.second).second)
            normalized->entry_points.push_back({make_address(*rva), entry.second});
    }

    for (const auto& raw : symbols_) {
        image_symbol_t symbol;
        symbol.ordinal = raw.ordinal;
        symbol.name = raw.name;
        symbol.address = make_address(0);
        const std::uint8_t basic_type = raw.type & n_type;
        const bool debug = (raw.type & n_stab) != 0;
        const bool external = (raw.type & n_ext) != 0;
        symbol.binding = (raw.description & (n_weak_ref | n_weak_def)) != 0
            ? image_symbol_binding_t::weak
            : (external ? image_symbol_binding_t::global
                        : image_symbol_binding_t::local);
        if ((raw.type & n_pext) != 0)
            symbol.binding = image_symbol_binding_t::local;
        symbol.kind = debug ? image_symbol_kind_t::debug_symbol
                            : image_symbol_kind_t::unknown;
        if (!debug && basic_type == n_sect) {
            const auto& section = sections_[raw.section - 1U];
            const bool inside_section = raw.value >= section.vm_address &&
                                        raw.value - section.vm_address < section.size;
            auto rva = inside_section ? vm_to_rva(raw.value) : std::nullopt;
            if (rva) {
                symbol.address = make_address(*rva);
                symbol.defined = true;
                symbol.kind = (section.permissions & image_permission_execute) != 0
                    ? image_symbol_kind_t::function
                    : image_symbol_kind_t::object;
            }
        } else if (!debug && basic_type == n_abs) {
            auto rva = vm_to_rva(raw.value);
            if (rva) {
                symbol.address = make_address(*rva);
                symbol.defined = true;
                symbol.kind = image_symbol_kind_t::object;
            }
        } else if (debug) {
            auto rva = vm_to_rva(raw.value);
            if (rva) {
                symbol.address = make_address(*rva);
                symbol.defined = true;
            }
        } else if (basic_type == n_undf) {
            symbol.binding = image_symbol_binding_t::external;
        }
        normalized->symbols.push_back(std::move(symbol));
    }
    for (const auto& raw : metadata_symbols_) {
        auto rva = vm_to_rva(raw.vm_address, raw.size == 0 ? 1 : raw.size);
        if (!rva)
            return workspace_result_t<parse_product_t>::failure(error(
                workspace_error_code_t::malformed_image,
                "Mach-O metadata symbol cannot be normalized",
                "macho.normalize.symbol"));
        if (raw.kind == image_symbol_kind_t::function && !executable_rva(*rva))
            return workspace_result_t<parse_product_t>::failure(error(
                workspace_error_code_t::malformed_image,
                "Mach-O recovered function is outside executable memory",
                "macho.normalize.symbol"));
        image_symbol_t symbol;
        symbol.ordinal = normalized->symbols.size();
        symbol.name = raw.name;
        symbol.address = make_address(*rva);
        symbol.size = raw.size;
        symbol.kind = raw.kind;
        symbol.binding = image_symbol_binding_t::local;
        symbol.defined = true;
        normalized->symbols.push_back(std::move(symbol));
    }

    std::set<std::tuple<std::uint64_t, std::string, std::string, bool>> import_dedupe;
    for (const auto& raw : binds_) {
        const std::uint64_t width = raw.type == 2U || raw.type == 3U
            ? 4U
            : pointer_size_;
        auto rva = vm_to_rva(raw.vm_address, width);
        if (!rva)
            return workspace_result_t<parse_product_t>::failure(error(
                workspace_error_code_t::malformed_image,
                "Mach-O bind cannot be normalized", "macho.normalize.import"));
        const std::string library = library_name(raw.library_ordinal);
        const auto key = std::make_tuple(*rva, library, raw.name, raw.lazy);
        if (!import_dedupe.insert(key).second)
            continue;
        image_import_t imported;
        imported.library = library;
        imported.name = raw.name;
        imported.lookup_address = make_address(*rva);
        imported.address = make_address(*rva);
        imported.delayed = raw.lazy;
        normalized->imports.push_back(imported);
        image_symbol_t symbol;
        symbol.ordinal = normalized->symbols.size();
        symbol.name = library + "!" + raw.name;
        symbol.address = imported.address;
        symbol.kind = image_symbol_kind_t::import_symbol;
        symbol.binding = raw.weak ? image_symbol_binding_t::weak
                                  : image_symbol_binding_t::external;
        normalized->symbols.push_back(std::move(symbol));
    }

    std::uint64_t fallback_rva = 0;
    if (normalized->header_size == 0 && !normalized->segments.empty())
        fallback_rva = normalized->segments.front().virtual_address;
    std::set<std::tuple<std::string, std::uint64_t, std::string>> export_dedupe;
    const auto add_export = [&](std::string name, std::uint64_t rva,
                                std::optional<std::string> forwarder,
                                std::uint64_t ordinal)
        -> workspace_result_t<void> {
        const std::string forwarder_key = forwarder.value_or(std::string{});
        if (!export_dedupe.emplace(name, rva, forwarder_key).second)
            return workspace_result_t<void>::success();
        if (normalized->exports.size() >= limits_.max_exports)
            return workspace_result_t<void>::failure(make_limit_error(
                "Mach-O normalized export count exceeds its budget",
                "macho.normalize.export", normalized->exports.size() + 1U,
                limits_.max_exports));
        image_export_t exported;
        exported.name = name;
        exported.ordinal = ordinal;
        exported.address = make_address(rva);
        exported.forwarder = forwarder;
        normalized->exports.push_back(exported);
        image_symbol_t symbol;
        symbol.ordinal = ordinal;
        symbol.name = std::move(name);
        symbol.address = exported.address;
        symbol.kind = image_symbol_kind_t::export_symbol;
        symbol.binding = image_symbol_binding_t::global;
        symbol.defined = !forwarder.has_value();
        symbol.forwarded = forwarder.has_value();
        normalized->symbols.push_back(std::move(symbol));
        return workspace_result_t<void>::success();
    };
    for (const auto& raw : exports_) {
        std::uint64_t rva = raw.address;
        std::optional<std::string> forwarder = raw.forwarder;
        if (raw.absolute) {
            forwarder = "absolute:" + std::to_string(raw.address);
            rva = fallback_rva;
        } else if (forwarder) {
            rva = fallback_rva;
        } else if (rva >= image_size_) {
            return workspace_result_t<parse_product_t>::failure(error(
                workspace_error_code_t::malformed_image,
                "Mach-O export address is outside the image",
                "macho.normalize.export"));
        }
        auto added = add_export(raw.name, rva, forwarder,
                                normalized->exports.size());
        if (!added)
            return workspace_result_t<parse_product_t>::failure(added.error());
    }
    for (const auto& raw : symbols_) {
        if ((raw.type & n_stab) != 0 || (raw.type & n_ext) == 0 ||
            (raw.type & n_type) != n_sect || raw.name.empty())
            continue;
        const auto& section = sections_[raw.section - 1U];
        if (raw.value < section.vm_address ||
            raw.value - section.vm_address >= section.size)
            continue;
        auto rva = vm_to_rva(raw.value);
        if (!rva)
            continue;
        auto added = add_export(raw.name, *rva, std::nullopt,
                                normalized->exports.size());
        if (!added)
            return workspace_result_t<parse_product_t>::failure(added.error());
    }

    std::set<std::tuple<std::uint64_t, std::uint64_t, std::uint64_t>> relocation_dedupe;
    for (const auto& raw : relocations_) {
        auto rva = vm_to_rva(raw.vm_address);
        if (!rva)
            return workspace_result_t<parse_product_t>::failure(error(
                workspace_error_code_t::malformed_image,
                "Mach-O relocation cannot be normalized",
                "macho.normalize.relocation"));
        std::optional<address_t> target;
        std::uint64_t target_key = (std::numeric_limits<std::uint64_t>::max)();
        if (raw.target_vm_address) {
            auto target_rva = vm_to_rva(*raw.target_vm_address);
            if (target_rva) {
                target = make_address(*target_rva);
                target_key = *target_rva;
            }
        }
        if (!relocation_dedupe.emplace(*rva, raw.type, target_key).second)
            continue;
        normalized->relocations.push_back({make_address(*rva), raw.type, target});
    }

    workspace_image_limits_t validation_limits;
    validation_limits.max_string_bytes = limits_.max_string_bytes;
    auto validation = validate_workspace_image(*normalized, validation_limits,
                                               false, cancel_);
    if (!validation)
        return workspace_result_t<parse_product_t>::failure(validation.error());
    parse_product_t product;
    product.cpu_type = cpu_type_;
    product.cpu_subtype = cpu_subtype_;
    product.metadata_bytes = metadata_bytes_;
    product.string_bytes = string_bytes_;
    product.image = std::static_pointer_cast<const workspace_image_t>(normalized);
    return workspace_result_t<parse_product_t>::success(std::move(product));
}

workspace_result_t<std::vector<std::uint8_t>> read_provider_blob(
    const byte_provider_t& provider, std::uint64_t offset, std::uint64_t size,
    std::uint64_t limit, const cancellation_token_t& cancel, std::string phase) {
    auto span = validate_span(offset, size, provider.size(), phase.c_str());
    if (!span)
        return workspace_result_t<std::vector<std::uint8_t>>::failure(span.error());
    return provider.read_vector(offset, size, limit, cancel);
}

workspace_result_t<fat_image_t> parse_fat_macho_impl(
    const byte_provider_t& provider, const macho_parse_limits_t& limits,
    const cancellation_token_t& cancel) {
    if (provider.size() < 8)
        return workspace_result_t<fat_image_t>::failure(make_macho_error(
            workspace_error_code_t::malformed_image,
            "Provider is smaller than a fat Mach-O header", "macho.fat", 0,
            provider.size()));
    auto header = read_provider_blob(provider, 0, 8, 8, cancel, "macho.fat");
    if (!header)
        return workspace_result_t<fat_image_t>::failure(header.error());
    std::uint32_t magic = 0;
    std::memcpy(&magic, header.value().data(), sizeof(magic));
    bool is_64_bit = false;
    endian_reader_t reader;
    if (magic == fat_magic) {
        reader.endian = endian_t::little;
    } else if (magic == fat_cigam) {
        reader.endian = endian_t::big;
    } else if (magic == fat_magic_64) {
        reader.endian = endian_t::little;
        is_64_bit = true;
    } else if (magic == fat_cigam_64) {
        reader.endian = endian_t::big;
        is_64_bit = true;
    } else {
        return workspace_result_t<fat_image_t>::failure(make_macho_error(
            workspace_error_code_t::unsupported_format,
            "Provider does not contain a fat Mach-O image", "macho.fat", 0, 4));
    }
    const std::uint32_t count = reader.u32(header.value().data() + 4);
    if (count == 0)
        return workspace_result_t<fat_image_t>::failure(make_macho_error(
            workspace_error_code_t::malformed_image,
            "Fat Mach-O contains no architecture records", "macho.fat", 4, 4));
    if (count > limits.max_fat_slices)
        return workspace_result_t<fat_image_t>::failure(make_limit_error(
            "Fat Mach-O slice count exceeds its budget", "macho.fat",
            count, limits.max_fat_slices));
    const std::uint64_t record_size = is_64_bit ? 32U : 20U;
    std::uint64_t table_size = 0;
    std::uint64_t table_end = 0;
    if (!checked_mul_u64(count, record_size, table_size) ||
        !checked_add_u64(8, table_size, table_end) || table_end > provider.size())
        return workspace_result_t<fat_image_t>::failure(make_macho_error(
            workspace_error_code_t::malformed_image,
            "Fat Mach-O architecture table is truncated or overflowed",
            "macho.fat", 8, table_size));
    if (table_size > limits.max_total_metadata_bytes)
        return workspace_result_t<fat_image_t>::failure(make_limit_error(
            "Fat Mach-O architecture table exceeds its metadata budget",
            "macho.fat", table_size, limits.max_total_metadata_bytes));
    auto table = read_provider_blob(provider, 8, table_size, table_size, cancel,
                                    "macho.fat.table");
    if (!table)
        return workspace_result_t<fat_image_t>::failure(table.error());
    struct slice_header_t {
        std::int32_t cpu_type;
        std::int32_t cpu_subtype;
        std::uint64_t offset;
        std::uint64_t size;
        std::uint32_t alignment;
    };
    std::vector<slice_header_t> headers;
    std::uint64_t header_records_bytes = 0;
    std::uint64_t slice_records_bytes = 0;
    std::uint64_t fat_overhead = 0;
    if (!checked_mul_u64(count, sizeof(slice_header_t), header_records_bytes) ||
        !checked_mul_u64(count, sizeof(fat_slice_t), slice_records_bytes) ||
        !checked_add_u64(table_size, header_records_bytes, fat_overhead) ||
        !checked_add_u64(fat_overhead, slice_records_bytes, fat_overhead) ||
        !checked_add_u64(fat_overhead, sizeof(fat_image_t), fat_overhead))
        return workspace_result_t<fat_image_t>::failure(make_macho_error(
            workspace_error_code_t::range_overflow,
            "Fat Mach-O metadata accounting overflowed", "macho.fat"));
    if (fat_overhead > limits.max_total_metadata_bytes)
        return workspace_result_t<fat_image_t>::failure(make_limit_error(
            "Fat Mach-O metadata exceeds its aggregate budget", "macho.fat",
            fat_overhead, limits.max_total_metadata_bytes));
    std::uint64_t remaining_metadata = limits.max_total_metadata_bytes - fat_overhead;
    std::uint64_t remaining_strings = limits.max_string_bytes;
    headers.reserve(count);
    for (std::uint32_t index = 0; index < count; ++index) {
        if (cancel.stop_requested())
            return workspace_result_t<fat_image_t>::failure(
                make_stop_error(cancel, "macho.fat.table"));
        const auto* record = table.value().data() +
                             static_cast<std::size_t>(index * record_size);
        slice_header_t slice{};
        slice.cpu_type = reader.i32(record);
        slice.cpu_subtype = reader.i32(record + 4);
        if (is_64_bit) {
            slice.offset = reader.u64(record + 8);
            slice.size = reader.u64(record + 16);
            slice.alignment = reader.u32(record + 24);
            if (reader.u32(record + 28) != 0)
                return workspace_result_t<fat_image_t>::failure(make_macho_error(
                    workspace_error_code_t::malformed_image,
                    "Fat Mach-O 64-bit architecture record has a nonzero reserved field",
                    "macho.fat.table", 8 + index * record_size, record_size));
        } else {
            slice.offset = reader.u32(record + 8);
            slice.size = reader.u32(record + 12);
            slice.alignment = reader.u32(record + 16);
        }
        if (slice.size == 0 || slice.offset < table_end ||
            slice.alignment >= 64 ||
            slice.offset > provider.size() ||
            slice.size > provider.size() - slice.offset)
            return workspace_result_t<fat_image_t>::failure(make_macho_error(
                workspace_error_code_t::malformed_image,
                "Fat Mach-O slice range or alignment exponent is invalid",
                "macho.fat.table", 8 + index * record_size, record_size));
        const std::uint64_t alignment = 1ULL << slice.alignment;
        if ((slice.offset % alignment) != 0)
            return workspace_result_t<fat_image_t>::failure(make_macho_error(
                workspace_error_code_t::malformed_image,
                "Fat Mach-O slice offset violates its declared alignment",
                "macho.fat.table", 8 + index * record_size, record_size));
        checked_span_t current{slice.offset, slice.size};
        for (const auto& previous : headers) {
            if (current.overlaps({previous.offset, previous.size}))
                return workspace_result_t<fat_image_t>::failure(make_macho_error(
                    workspace_error_code_t::malformed_image,
                    "Fat Mach-O slices overlap", "macho.fat.table",
                    slice.offset, slice.size));
            if (slice.cpu_type == previous.cpu_type &&
                slice.cpu_subtype == previous.cpu_subtype)
                return workspace_result_t<fat_image_t>::failure(make_macho_error(
                    workspace_error_code_t::malformed_image,
                    "Fat Mach-O contains a duplicate CPU/subtype member",
                    "macho.fat.table", 8 + index * record_size, record_size));
        }
        headers.push_back(slice);
    }

    fat_image_t fat;
    fat.is_64bit = is_64_bit;
    fat.endian = reader.endian;
    fat.magic = magic;
    fat.slices.reserve(headers.size());
    const auto& identity = provider.identity();
    for (std::uint32_t index = 0; index < headers.size(); ++index) {
        if (remaining_metadata == 0)
            return workspace_result_t<fat_image_t>::failure(make_limit_error(
                "Fat Mach-O members exhausted their aggregate metadata budget",
                "macho.fat", limits.max_total_metadata_bytes,
                limits.max_total_metadata_bytes));
        if (remaining_strings == 0)
            return workspace_result_t<fat_image_t>::failure(make_limit_error(
                "Fat Mach-O members exhausted their aggregate string budget",
                "macho.fat", limits.max_string_bytes, limits.max_string_bytes));
        const auto& header_value = headers[index];
        provider_member_metadata_t member;
        if (identity.member) {
            if (identity.member->depth >= 64)
                return workspace_result_t<fat_image_t>::failure(make_macho_error(
                    workspace_error_code_t::limit_exceeded,
                    "Fat Mach-O member nesting exceeds the workspace depth limit",
                    "macho.fat.provenance"));
            member.normalized_member_path = identity.member->normalized_member_path + "/";
            member.depth = identity.member->depth + 1U;
        } else {
            member.depth = 1;
        }
        member.normalized_member_path += "fat/" + std::to_string(index) + "-" +
                                         std::to_string(header_value.cpu_type);
        member.container_offset = header_value.offset;
        member.compressed_size = header_value.size;
        member.uncompressed_size = header_value.size;
        member.ordinal = index;
        member.compressed = false;
        std::string source = identity.normalized_source.empty()
            ? "provider"
            : identity.normalized_source;
        source += "!/" + member.normalized_member_path;
        macho_parse_limits_t member_limits = limits;
        member_limits.max_total_metadata_bytes = remaining_metadata;
        member_limits.max_string_bytes = remaining_strings;
        macho_parser_t parser(provider, member_limits, cancel, header_value.offset,
                              header_value.size, std::move(source), member);
        auto parsed = parser.parse();
        if (!parsed) {
            auto member_error = parsed.error();
            member_error.details.emplace_back("fat_slice", std::to_string(index));
            member_error.details.emplace_back("cputype",
                                              std::to_string(header_value.cpu_type));
            member_error.details.emplace_back("cpusubtype",
                                              std::to_string(header_value.cpu_subtype));
            return workspace_result_t<fat_image_t>::failure(std::move(member_error));
        }
        if (parsed.value().cpu_type != header_value.cpu_type ||
            parsed.value().cpu_subtype != header_value.cpu_subtype) {
            auto mismatch = make_macho_error(
                workspace_error_code_t::malformed_image,
                "Fat Mach-O member header disagrees with its architecture record",
                "macho.fat.member", header_value.offset, header_value.size);
            mismatch.details.emplace_back("slice", std::to_string(index));
            return workspace_result_t<fat_image_t>::failure(std::move(mismatch));
        }
        if (parsed.value().metadata_bytes > remaining_metadata ||
            parsed.value().string_bytes > remaining_strings)
            return workspace_result_t<fat_image_t>::failure(make_macho_error(
                workspace_error_code_t::integrity_failure,
                "Fat Mach-O member exceeded its assigned parser budget",
                "macho.fat.member", header_value.offset, header_value.size));
        remaining_metadata -= parsed.value().metadata_bytes;
        remaining_strings -= parsed.value().string_bytes;
        fat_slice_t slice;
        slice.cpu_type = header_value.cpu_type;
        slice.cpu_subtype = header_value.cpu_subtype;
        slice.offset = header_value.offset;
        slice.size = header_value.size;
        slice.align = header_value.alignment;
        slice.architecture = parsed.value().image->architecture;
        slice.image = parsed.value().image;
        fat.slices.push_back(std::move(slice));
    }
    return workspace_result_t<fat_image_t>::success(std::move(fat));
}

}

workspace_result_t<std::shared_ptr<const workspace_image_t>>
parse_macho(const byte_provider_t& provider, const macho_parse_limits_t& limits,
            const cancellation_token_t& cancel) {
    try {
        std::string source = provider.identity().normalized_source.empty()
            ? "provider"
            : provider.identity().normalized_source;
        macho_parser_t parser(provider, limits, cancel, 0, provider.size(),
                              std::move(source), provider.member_metadata());
        auto parsed = parser.parse();
        if (!parsed)
            return workspace_result_t<std::shared_ptr<const workspace_image_t>>::failure(
                parsed.error());
        return workspace_result_t<std::shared_ptr<const workspace_image_t>>::success(
            parsed.value().image);
    } catch (const std::bad_alloc&) {
        return workspace_result_t<std::shared_ptr<const workspace_image_t>>::failure(
            make_macho_error(workspace_error_code_t::limit_exceeded,
                             "Mach-O parsing allocation failed", "macho.parse"));
    } catch (const std::length_error&) {
        return workspace_result_t<std::shared_ptr<const workspace_image_t>>::failure(
            make_macho_error(workspace_error_code_t::limit_exceeded,
                             "Mach-O parsing allocation length is unsupported",
                             "macho.parse"));
    }
}

workspace_result_t<std::shared_ptr<const workspace_image_t>>
parse_macho(const byte_provider_t& provider, const cancellation_token_t& cancel) {
    return parse_macho(provider, macho_parse_limits_t{}, cancel);
}

workspace_result_t<fat_image_t>
parse_fat_macho(const byte_provider_t& provider,
                const macho_parse_limits_t& limits,
                const cancellation_token_t& cancel) {
    try {
        return parse_fat_macho_impl(provider, limits, cancel);
    } catch (const std::bad_alloc&) {
        return workspace_result_t<fat_image_t>::failure(make_macho_error(
            workspace_error_code_t::limit_exceeded,
            "Fat Mach-O parsing allocation failed", "macho.fat"));
    } catch (const std::length_error&) {
        return workspace_result_t<fat_image_t>::failure(make_macho_error(
            workspace_error_code_t::limit_exceeded,
            "Fat Mach-O parsing allocation length is unsupported", "macho.fat"));
    }
}

workspace_result_t<fat_image_t>
parse_fat_macho(const byte_provider_t& provider,
                const cancellation_token_t& cancel) {
    return parse_fat_macho(provider, macho_parse_limits_t{}, cancel);
}

}
