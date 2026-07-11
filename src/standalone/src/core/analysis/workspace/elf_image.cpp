#include "elf_image.hpp"

#include "checked_range.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <new>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <tuple>
#include <unordered_map>
#include <utility>
#include <vector>

namespace aida::analysis {
namespace {

constexpr std::uint32_t pn_xnum = 0xffff;
constexpr std::uint32_t invalid_section_index =
    (std::numeric_limits<std::uint32_t>::max)();
constexpr std::uint64_t invalid_rva =
    (std::numeric_limits<std::uint64_t>::max)();
constexpr std::size_t invalid_symbol_table_index =
    (std::numeric_limits<std::size_t>::max)();
constexpr std::uint64_t cancel_check_interval = 256;

workspace_error_t elf_error(std::string message, const char* phase,
                            std::optional<std::uint64_t> offset = {},
                            std::optional<std::uint64_t> size = {}) {
    auto error = make_workspace_error(workspace_error_code_t::malformed_image,
                                      std::move(message), phase);
    error.offset = offset;
    error.size = size;
    return error;
}

workspace_error_t unsupported_error(std::string message) {
    return make_workspace_error(workspace_error_code_t::unsupported_format,
                                std::move(message), "elf_header");
}

workspace_error_t limit_error(std::string message, const char* phase,
                              std::uint64_t value, std::uint64_t limit) {
    auto error = make_workspace_error(workspace_error_code_t::limit_exceeded,
                                      std::move(message), phase);
    error.details.emplace_back("value", std::to_string(value));
    error.details.emplace_back("limit", std::to_string(limit));
    return error;
}

workspace_error_t stop_error(const cancellation_token_t& cancel) {
    if (cancel.deadline_exceeded()) {
        auto error = make_workspace_error(workspace_error_code_t::deadline_exceeded,
                                          "ELF parsing deadline exceeded", "elf_parse");
        error.deadline = true;
        return error;
    }
    auto error = make_workspace_error(workspace_error_code_t::cancelled,
                                      "ELF parsing cancelled", "elf_parse");
    error.cancellation = true;
    return error;
}

workspace_error_t allocation_error() {
    return make_workspace_error(workspace_error_code_t::limit_exceeded,
                                "ELF parsing allocation failed", "elf_parse");
}

bool is_power_of_two(std::uint64_t value) noexcept {
    return value != 0 && (value & (value - 1)) == 0;
}

bool align_up(std::uint64_t value, std::uint64_t alignment,
              std::uint64_t& result) noexcept {
    if (alignment <= 1) {
        result = value;
        return true;
    }
    const auto mask = alignment - 1;
    std::uint64_t adjusted = 0;
    if (!checked_add_u64(value, mask, adjusted))
        return false;
    result = adjusted & ~mask;
    return true;
}

std::uint16_t read_u16_le(const std::uint8_t* value) noexcept {
    return static_cast<std::uint16_t>(value[0]) |
           static_cast<std::uint16_t>(static_cast<std::uint16_t>(value[1]) << 8);
}

std::uint16_t read_u16_be(const std::uint8_t* value) noexcept {
    return static_cast<std::uint16_t>(static_cast<std::uint16_t>(value[0]) << 8) |
           static_cast<std::uint16_t>(value[1]);
}

std::uint32_t read_u32_le(const std::uint8_t* value) noexcept {
    return static_cast<std::uint32_t>(value[0]) |
           (static_cast<std::uint32_t>(value[1]) << 8) |
           (static_cast<std::uint32_t>(value[2]) << 16) |
           (static_cast<std::uint32_t>(value[3]) << 24);
}

std::uint32_t read_u32_be(const std::uint8_t* value) noexcept {
    return (static_cast<std::uint32_t>(value[0]) << 24) |
           (static_cast<std::uint32_t>(value[1]) << 16) |
           (static_cast<std::uint32_t>(value[2]) << 8) |
           static_cast<std::uint32_t>(value[3]);
}

std::uint64_t read_u64_le(const std::uint8_t* value) noexcept {
    return static_cast<std::uint64_t>(value[0]) |
           (static_cast<std::uint64_t>(value[1]) << 8) |
           (static_cast<std::uint64_t>(value[2]) << 16) |
           (static_cast<std::uint64_t>(value[3]) << 24) |
           (static_cast<std::uint64_t>(value[4]) << 32) |
           (static_cast<std::uint64_t>(value[5]) << 40) |
           (static_cast<std::uint64_t>(value[6]) << 48) |
           (static_cast<std::uint64_t>(value[7]) << 56);
}

std::uint64_t read_u64_be(const std::uint8_t* value) noexcept {
    return (static_cast<std::uint64_t>(value[0]) << 56) |
           (static_cast<std::uint64_t>(value[1]) << 48) |
           (static_cast<std::uint64_t>(value[2]) << 40) |
           (static_cast<std::uint64_t>(value[3]) << 32) |
           (static_cast<std::uint64_t>(value[4]) << 24) |
           (static_cast<std::uint64_t>(value[5]) << 16) |
           (static_cast<std::uint64_t>(value[6]) << 8) |
           static_cast<std::uint64_t>(value[7]);
}

std::int32_t signed_u32(std::uint32_t value) noexcept {
    if (value <= static_cast<std::uint32_t>((std::numeric_limits<std::int32_t>::max)()))
        return static_cast<std::int32_t>(value);
    return -1 - static_cast<std::int32_t>((std::numeric_limits<std::uint32_t>::max)() - value);
}

std::int64_t signed_u64(std::uint64_t value) noexcept {
    if (value <= static_cast<std::uint64_t>((std::numeric_limits<std::int64_t>::max)()))
        return static_cast<std::int64_t>(value);
    return -1 - static_cast<std::int64_t>((std::numeric_limits<std::uint64_t>::max)() - value);
}

struct endian_reader_t {
    bool big = false;

    std::uint16_t u16(const std::uint8_t* value) const noexcept {
        return big ? read_u16_be(value) : read_u16_le(value);
    }

    std::uint32_t u32(const std::uint8_t* value) const noexcept {
        return big ? read_u32_be(value) : read_u32_le(value);
    }

    std::uint64_t u64(const std::uint8_t* value) const noexcept {
        return big ? read_u64_be(value) : read_u64_le(value);
    }

    std::int32_t i32(const std::uint8_t* value) const noexcept {
        return signed_u32(u32(value));
    }

    std::int64_t i64(const std::uint8_t* value) const noexcept {
        return signed_u64(u64(value));
    }
};

architecture_mode_t architecture_mode(std::uint16_t machine, bool is_64) noexcept {
    switch (machine) {
        case em_386:
            return architecture_mode_t::x86_32;
        case em_x86_64:
            return architecture_mode_t::x86_64;
        case em_arm:
            return architecture_mode_t::arm_a32;
        case em_aarch64:
            return architecture_mode_t::aarch64;
        case em_mips:
            return is_64 ? architecture_mode_t::mips64 : architecture_mode_t::mips32;
        case em_ppc:
            return architecture_mode_t::ppc32;
        case em_ppc64:
            return architecture_mode_t::ppc64;
        case em_riscv:
            return is_64 ? architecture_mode_t::riscv64 : architecture_mode_t::riscv32;
        default:
            return architecture_mode_t::unknown;
    }
}

abi_id_t linux_abi(architecture_id_t architecture) noexcept {
    switch (architecture) {
        case architecture_id_t::x86:
            return abi_id_t::linux_x86;
        case architecture_id_t::x86_64:
            return abi_id_t::linux_x64;
        case architecture_id_t::arm:
            return abi_id_t::linux_arm;
        case architecture_id_t::aarch64:
            return abi_id_t::linux_aarch64;
        case architecture_id_t::mips:
        case architecture_id_t::mips64:
            return abi_id_t::linux_mips;
        case architecture_id_t::ppc:
            return abi_id_t::linux_ppc;
        case architecture_id_t::ppc64:
            return abi_id_t::linux_ppc64;
        case architecture_id_t::riscv:
        case architecture_id_t::riscv32:
        case architecture_id_t::riscv64:
            return abi_id_t::linux_riscv;
        default:
            return abi_id_t::sysv;
    }
}

abi_id_t android_abi(architecture_id_t architecture) noexcept {
    switch (architecture) {
        case architecture_id_t::x86:
            return abi_id_t::android_x86;
        case architecture_id_t::x86_64:
            return abi_id_t::android_x86_64;
        case architecture_id_t::arm:
            return abi_id_t::android_arm;
        case architecture_id_t::aarch64:
            return abi_id_t::android_aarch64;
        default:
            return abi_id_t::sysv;
    }
}

std::uint32_t segment_permissions(std::uint32_t flags) noexcept {
    std::uint32_t permissions = image_permission_none;
    if ((flags & pf_r) != 0)
        permissions |= image_permission_read;
    if ((flags & pf_w) != 0)
        permissions |= image_permission_write;
    if ((flags & pf_x) != 0)
        permissions |= image_permission_execute;
    return permissions;
}

std::uint32_t section_permissions(std::uint64_t flags) noexcept {
    std::uint32_t permissions = image_permission_none;
    if ((flags & shf_alloc) != 0)
        permissions |= image_permission_read;
    if ((flags & shf_write) != 0)
        permissions |= image_permission_write;
    if ((flags & shf_execinstr) != 0)
        permissions |= image_permission_execute;
    return permissions;
}

const char* segment_type_name(std::uint32_t type) noexcept {
    switch (type) {
        case pt_null: return "NULL";
        case pt_load: return "LOAD";
        case pt_dynamic: return "DYNAMIC";
        case pt_interp: return "INTERP";
        case pt_note: return "NOTE";
        case pt_shlib: return "SHLIB";
        case pt_phdr: return "PHDR";
        case pt_tls: return "TLS";
        case pt_gnu_eh_frame: return "GNU_EH_FRAME";
        case pt_gnu_stack: return "GNU_STACK";
        case pt_gnu_relro: return "GNU_RELRO";
        case pt_gnu_property: return "GNU_PROPERTY";
        default: return "OTHER";
    }
}

const char* dynamic_tag_name(std::int64_t tag) noexcept {
    switch (tag) {
        case dt_null: return "NULL";
        case dt_needed: return "NEEDED";
        case dt_pltrelsz: return "PLTRELSZ";
        case dt_pltgot: return "PLTGOT";
        case dt_hash: return "HASH";
        case dt_strtab: return "STRTAB";
        case dt_symtab: return "SYMTAB";
        case dt_rela: return "RELA";
        case dt_relasz: return "RELASZ";
        case dt_relaent: return "RELAENT";
        case dt_strsz: return "STRSZ";
        case dt_syment: return "SYMENT";
        case dt_init: return "INIT";
        case dt_fini: return "FINI";
        case dt_soname: return "SONAME";
        case dt_rpath: return "RPATH";
        case dt_symbolic: return "SYMBOLIC";
        case dt_rel: return "REL";
        case dt_relsz: return "RELSZ";
        case dt_relent: return "RELENT";
        case dt_pltrel: return "PLTREL";
        case dt_debug: return "DEBUG";
        case dt_textrel: return "TEXTREL";
        case dt_jmprel: return "JMPREL";
        case dt_bind_now: return "BIND_NOW";
        case dt_init_array: return "INIT_ARRAY";
        case dt_fini_array: return "FINI_ARRAY";
        case dt_init_arraysz: return "INIT_ARRAYSZ";
        case dt_fini_arraysz: return "FINI_ARRAYSZ";
        case dt_runpath: return "RUNPATH";
        case dt_flags: return "FLAGS";
        case dt_preinit_array: return "PREINIT_ARRAY";
        case dt_preinit_arraysz: return "PREINIT_ARRAYSZ";
        case dt_gnu_hash: return "GNU_HASH";
        case dt_versym: return "VERSYM";
        case dt_verdef: return "VERDEF";
        case dt_verdefnum: return "VERDEFNUM";
        case dt_verneed: return "VERNEED";
        case dt_verneednum: return "VERNEEDNUM";
        default: return "OTHER";
    }
}

elf_filetype_t file_type(std::uint16_t type) noexcept {
    switch (type) {
        case et_rel: return elf_filetype_t::relocatable;
        case et_exec: return elf_filetype_t::executable;
        case et_dyn: return elf_filetype_t::shared;
        case et_core: return elf_filetype_t::core;
        default: return elf_filetype_t::unknown;
    }
}

image_symbol_kind_t normalized_symbol_kind(const elf_symbol_t& symbol) noexcept {
    if (symbol.is_import)
        return image_symbol_kind_t::import_symbol;
    if (symbol.is_export)
        return image_symbol_kind_t::export_symbol;
    switch (symbol.kind) {
        case elf_symbol_kind_t::function:
        case elf_symbol_kind_t::ifunc:
            return image_symbol_kind_t::function;
        case elf_symbol_kind_t::data:
        case elf_symbol_kind_t::common:
        case elf_symbol_kind_t::tls:
            return image_symbol_kind_t::object;
        case elf_symbol_kind_t::section:
            return image_symbol_kind_t::section;
        case elf_symbol_kind_t::file:
            return image_symbol_kind_t::metadata;
        case elf_symbol_kind_t::unknown:
        case elf_symbol_kind_t::notype:
            return image_symbol_kind_t::unknown;
    }
    return image_symbol_kind_t::unknown;
}

image_symbol_binding_t normalized_symbol_binding(const elf_symbol_t& symbol) noexcept {
    if (symbol.is_import)
        return image_symbol_binding_t::external;
    if (symbol.is_local)
        return image_symbol_binding_t::local;
    if (symbol.is_weak)
        return image_symbol_binding_t::weak;
    if (symbol.is_global || symbol.is_unique)
        return image_symbol_binding_t::global;
    return image_symbol_binding_t::unknown;
}

struct raw_header_t {
    bool is_64 = false;
    bool big_endian = false;
    bool section_count_extended = false;
    bool segment_count_extended = false;
    bool section_names_extended = false;
    std::uint8_t osabi = 0;
    std::uint8_t abi_version = 0;
    std::uint16_t type = 0;
    std::uint16_t machine = 0;
    std::uint32_t version = 0;
    std::uint32_t flags = 0;
    std::uint64_t entry = 0;
    std::uint64_t phoff = 0;
    std::uint64_t shoff = 0;
    std::uint16_t ehsize = 0;
    std::uint16_t phentsize = 0;
    std::uint16_t shentsize = 0;
    std::uint32_t phnum = 0;
    std::uint32_t shnum = 0;
    std::uint32_t shstrndx = 0;
    checked_span_t header_span;
    std::optional<checked_span_t> program_table_span;
    std::optional<checked_span_t> section_table_span;
};

struct raw_section_t {
    std::uint32_t index = 0;
    std::uint32_t name = 0;
    std::uint32_t type = 0;
    std::uint32_t link = 0;
    std::uint32_t info = 0;
    std::uint64_t flags = 0;
    std::uint64_t address = 0;
    std::uint64_t offset = 0;
    std::uint64_t size = 0;
    std::uint64_t alignment = 0;
    std::uint64_t entry_size = 0;
    std::optional<checked_span_t> file_span;
};

struct raw_segment_t {
    std::uint32_t index = 0;
    std::uint32_t type = 0;
    std::uint32_t flags = 0;
    std::uint64_t offset = 0;
    std::uint64_t virtual_address = 0;
    std::uint64_t physical_address = 0;
    std::uint64_t file_size = 0;
    std::uint64_t memory_size = 0;
    std::uint64_t alignment = 0;
    std::optional<checked_span_t> file_span;
};

struct raw_dynamic_t {
    std::int64_t tag = 0;
    std::uint64_t value = 0;
};

struct string_table_t {
    std::uint64_t file_offset = 0;
    std::vector<std::uint8_t> bytes;
};

struct parsed_symbol_table_t {
    std::uint32_t section_index = invalid_section_index;
    bool dynamic = false;
    std::vector<elf_symbol_t> symbols;
};

struct relocation_span_t {
    checked_span_t span;
    bool has_addend = false;
    std::size_t symbol_table_index = invalid_symbol_table_index;
    std::optional<std::uint32_t> target_section_index;
    std::size_t first_relocation = 0;
    std::size_t relocation_count = 0;
};

class elf_parser_t {
public:
    elf_parser_t(const byte_provider_t& provider, const elf_parse_limits_t& limits,
                 const cancellation_token_t& cancel)
        : provider_(provider), limits_(limits), cancel_(cancel) {}

    workspace_result_t<elf_image_t> parse();

private:
    workspace_result_t<void> poll(std::uint64_t iteration = 0) const;
    workspace_result_t<checked_span_t> file_span(std::uint64_t offset,
                                                 std::uint64_t size,
                                                 const char* phase) const;
    workspace_result_t<void> read_exact(std::uint64_t offset, void* destination,
                                        std::uint64_t size, const char* phase) const;
    workspace_result_t<void> charge_metadata(std::uint64_t size, const char* phase);
    workspace_result_t<void> charge_string_bytes(std::uint64_t size,
                                                 const char* phase);
    workspace_result_t<void> charge_materialized_string(std::uint64_t size,
                                                        const char* phase);
    workspace_result_t<void> parse_header();
    workspace_result_t<raw_section_t> read_section_header(std::uint64_t offset,
                                                          std::uint32_t index) const;
    workspace_result_t<void> parse_section_headers();
    workspace_result_t<void> classify_sections();
    workspace_result_t<void> inspect_compressed_section(elf_section_t& section,
                                                        const raw_section_t& raw);
    workspace_result_t<void> parse_program_headers();
    workspace_result_t<void> validate_load_overlaps() const;
    workspace_result_t<void> parse_interpreter();
    workspace_result_t<const string_table_t*> load_string_table(std::uint32_t index);
    workspace_result_t<std::string> string_at(const string_table_t& table,
                                              std::uint64_t offset,
                                              const char* phase) const;
    workspace_result_t<void> build_image_layout();
    workspace_result_t<void> parse_symbol_sections();
    workspace_result_t<std::size_t> parse_symbol_table(
        std::uint32_t section_index, std::uint64_t file_offset,
        std::uint64_t entry_size, std::uint64_t count,
        const string_table_t& strings, bool dynamic);
    workspace_result_t<void> parse_dynamic_table();
    workspace_result_t<std::optional<std::uint64_t>> dynamic_value(std::int64_t tag) const;
    workspace_result_t<void> resolve_dynamic_strings(
        std::optional<std::uint32_t> dynamic_section_index);
    workspace_result_t<void> resolve_dynamic_names();
    workspace_result_t<void> parse_dynamic_symbols();
    workspace_result_t<std::optional<std::uint64_t>> sysv_hash_symbol_count(
        std::uint64_t address);
    workspace_result_t<std::optional<std::uint64_t>> gnu_hash_symbol_count(
        std::uint64_t address);
    workspace_result_t<void> parse_relocation_sections();
    workspace_result_t<void> parse_dynamic_relocations();
    workspace_result_t<void> parse_relocation_range(
        std::uint64_t file_offset, std::uint64_t size, std::uint64_t entry_size,
        bool has_addend, bool is_plt, std::string section_name,
        std::optional<std::uint32_t> relocation_section_index,
        std::size_t symbol_table_index,
        std::optional<std::uint32_t> target_section_index);
    workspace_result_t<void> parse_notes();
    workspace_result_t<void> parse_note_span(const checked_span_t& span,
                                             std::string section_name);
    workspace_result_t<void> parse_init_fini();
    workspace_result_t<void> parse_pointer_array(
        std::uint64_t file_offset, std::uint64_t size, bool is_init,
        bool is_fini, bool is_preinit);
    workspace_result_t<void> build_plt_got_facts();
    workspace_result_t<void> build_normalized_image();
    workspace_result_t<std::uint64_t> virtual_to_file(std::uint64_t address,
                                                      std::uint64_t size,
                                                      const char* phase) const;
    workspace_result_t<std::pair<std::uint64_t, std::uint64_t>> virtual_file_window(
        std::uint64_t address, const char* phase) const;
    std::optional<std::uint64_t> virtual_to_rva(std::uint64_t address) const noexcept;
    std::optional<std::uint64_t> section_runtime_address(
        std::uint32_t section_index, std::uint64_t section_offset = 0) const noexcept;
    std::optional<std::uint64_t> symbol_rva(const elf_symbol_t& symbol) const noexcept;
    const parsed_symbol_table_t* symbol_table(std::size_t index) const noexcept;
    const elf_symbol_t* relocation_symbol(const elf_relocation_t& relocation) const noexcept;
    bool dynamic_range_matches_section(std::uint32_t type, std::uint64_t address,
                                       std::uint64_t size) const noexcept;
    std::uint64_t pointer_size() const noexcept;
    std::uint64_t native_symbol_size() const noexcept;
    std::uint64_t native_rel_size(bool has_addend) const noexcept;
    std::uint64_t native_dynamic_size() const noexcept;

    const byte_provider_t& provider_;
    const elf_parse_limits_t& limits_;
    const cancellation_token_t& cancel_;
    raw_header_t header_;
    endian_reader_t reader_;
    std::vector<raw_section_t> raw_sections_;
    std::vector<raw_segment_t> raw_segments_;
    std::vector<std::optional<string_table_t>> string_tables_;
    std::vector<parsed_symbol_table_t> symbol_tables_;
    std::vector<std::int64_t> symbol_table_lookup_;
    std::vector<std::int64_t> extended_index_lookup_;
    std::vector<std::uint64_t> section_rvas_;
    std::vector<raw_dynamic_t> raw_dynamic_;
    std::optional<string_table_t> external_dynamic_strings_;
    const string_table_t* dynamic_strings_ = nullptr;
    std::optional<std::size_t> dynamic_symbol_table_index_;
    std::vector<relocation_span_t> relocation_spans_;
    std::vector<std::uint64_t> note_offsets_;
    elf_image_t image_;
    std::uint64_t metadata_bytes_ = 0;
    std::uint64_t string_bytes_ = 0;
    std::uint64_t materialized_string_bytes_ = 0;
    std::uint64_t symbol_count_ = 0;
    std::uint64_t relocation_count_ = 0;
    std::uint64_t note_count_ = 0;
    std::uint64_t init_fini_count_ = 0;
    std::uint64_t plt_got_count_ = 0;
    std::uint64_t image_end_ = 0;
    bool has_load_segments_ = false;
};

workspace_result_t<void> elf_parser_t::poll(std::uint64_t iteration) const {
    if ((iteration % cancel_check_interval) == 0 && cancel_.stop_requested())
        return workspace_result_t<void>::failure(stop_error(cancel_));
    return workspace_result_t<void>::success();
}

workspace_result_t<checked_span_t> elf_parser_t::file_span(
    std::uint64_t offset, std::uint64_t size, const char* phase) const {
    auto result = validate_span(offset, size, provider_.size(), phase);
    if (result)
        return result;
    auto error = std::move(result.error());
    if (error.code == workspace_error_code_t::out_of_range) {
        error.code = workspace_error_code_t::malformed_image;
        error.message = "ELF data is truncated";
    }
    return workspace_result_t<checked_span_t>::failure(std::move(error));
}

workspace_result_t<void> elf_parser_t::read_exact(
    std::uint64_t offset, void* destination, std::uint64_t size,
    const char* phase) const {
    auto span = file_span(offset, size, phase);
    if (!span)
        return workspace_result_t<void>::failure(std::move(span.error()));
    auto result = provider_.read_exact(offset, destination, size, cancel_);
    if (!result)
        return workspace_result_t<void>::failure(std::move(result.error()));
    return workspace_result_t<void>::success();
}

workspace_result_t<void> elf_parser_t::charge_metadata(std::uint64_t size,
                                                        const char* phase) {
    if (metadata_bytes_ > limits_.max_total_metadata_bytes ||
        size > limits_.max_total_metadata_bytes - metadata_bytes_) {
        std::uint64_t requested = 0;
        if (!checked_add_u64(metadata_bytes_, size, requested))
            requested = (std::numeric_limits<std::uint64_t>::max)();
        return workspace_result_t<void>::failure(limit_error(
            "ELF metadata budget exceeded", phase, requested,
            limits_.max_total_metadata_bytes));
    }
    metadata_bytes_ += size;
    return workspace_result_t<void>::success();
}

workspace_result_t<void> elf_parser_t::charge_string_bytes(std::uint64_t size,
                                                            const char* phase) {
    if (string_bytes_ > limits_.max_string_table_bytes ||
        size > limits_.max_string_table_bytes - string_bytes_) {
        std::uint64_t requested = 0;
        if (!checked_add_u64(string_bytes_, size, requested))
            requested = (std::numeric_limits<std::uint64_t>::max)();
        return workspace_result_t<void>::failure(limit_error(
            "ELF string-table budget exceeded", phase, requested,
            limits_.max_string_table_bytes));
    }
    string_bytes_ += size;
    return workspace_result_t<void>::success();
}

workspace_result_t<void> elf_parser_t::charge_materialized_string(
    std::uint64_t size, const char* phase) {
    if (materialized_string_bytes_ > limits_.max_materialized_string_bytes ||
        size > limits_.max_materialized_string_bytes - materialized_string_bytes_) {
        std::uint64_t requested = 0;
        if (!checked_add_u64(materialized_string_bytes_, size, requested))
            requested = (std::numeric_limits<std::uint64_t>::max)();
        return workspace_result_t<void>::failure(limit_error(
            "ELF materialized string budget exceeded", phase, requested,
            limits_.max_materialized_string_bytes));
    }
    materialized_string_bytes_ += size;
    return workspace_result_t<void>::success();
}

workspace_result_t<raw_section_t> elf_parser_t::read_section_header(
    std::uint64_t offset, std::uint32_t index) const {
    std::array<std::uint8_t, sizeof(elf64_shdr_t)> bytes{};
    const auto required = header_.is_64 ? sizeof(elf64_shdr_t) : sizeof(elf32_shdr_t);
    auto read = read_exact(offset, bytes.data(), required, "elf_sections");
    if (!read)
        return workspace_result_t<raw_section_t>::failure(std::move(read.error()));
    raw_section_t section;
    section.index = index;
    section.name = reader_.u32(bytes.data());
    section.type = reader_.u32(bytes.data() + 4);
    if (header_.is_64) {
        section.flags = reader_.u64(bytes.data() + 8);
        section.address = reader_.u64(bytes.data() + 16);
        section.offset = reader_.u64(bytes.data() + 24);
        section.size = reader_.u64(bytes.data() + 32);
        section.link = reader_.u32(bytes.data() + 40);
        section.info = reader_.u32(bytes.data() + 44);
        section.alignment = reader_.u64(bytes.data() + 48);
        section.entry_size = reader_.u64(bytes.data() + 56);
    } else {
        section.flags = reader_.u32(bytes.data() + 8);
        section.address = reader_.u32(bytes.data() + 12);
        section.offset = reader_.u32(bytes.data() + 16);
        section.size = reader_.u32(bytes.data() + 20);
        section.link = reader_.u32(bytes.data() + 24);
        section.info = reader_.u32(bytes.data() + 28);
        section.alignment = reader_.u32(bytes.data() + 32);
        section.entry_size = reader_.u32(bytes.data() + 36);
    }
    return workspace_result_t<raw_section_t>::success(std::move(section));
}

workspace_result_t<void> elf_parser_t::parse_header() {
    auto stopped = poll();
    if (!stopped)
        return stopped;
    std::array<std::uint8_t, ei_nident> ident{};
    auto ident_read = read_exact(0, ident.data(), ident.size(), "elf_header");
    if (!ident_read)
        return ident_read;
    if (ident[ei_mag0] != elfmag0 || ident[ei_mag1] != elfmag1 ||
        ident[ei_mag2] != elfmag2 || ident[ei_mag3] != elfmag3)
        return workspace_result_t<void>::failure(
            elf_error("invalid ELF magic", "elf_header", 0, 4));
    if (ident[ei_class] != elfclass32 && ident[ei_class] != elfclass64)
        return workspace_result_t<void>::failure(
            unsupported_error("unsupported ELF class"));
    if (ident[ei_data] != elfdata2lsb && ident[ei_data] != elfdata2msb)
        return workspace_result_t<void>::failure(
            unsupported_error("unsupported ELF byte order"));
    if (ident[ei_version] != ev_current)
        return workspace_result_t<void>::failure(
            elf_error("invalid ELF identification version", "elf_header", ei_version, 1));
    for (std::size_t index = ei_pad; index < ident.size(); ++index) {
        if (ident[index] != 0)
            return workspace_result_t<void>::failure(
                elf_error("nonzero ELF identification padding", "elf_header", index, 1));
    }
    header_.is_64 = ident[ei_class] == elfclass64;
    header_.big_endian = ident[ei_data] == elfdata2msb;
    header_.osabi = ident[ei_osabi];
    header_.abi_version = ident[ei_abiversion];
    reader_.big = header_.big_endian;
    std::array<std::uint8_t, sizeof(elf64_ehdr_t)> bytes{};
    const auto required = header_.is_64 ? sizeof(elf64_ehdr_t) : sizeof(elf32_ehdr_t);
    auto header_read = read_exact(0, bytes.data(), required, "elf_header");
    if (!header_read)
        return header_read;
    header_.type = reader_.u16(bytes.data() + 16);
    header_.machine = reader_.u16(bytes.data() + 18);
    header_.version = reader_.u32(bytes.data() + 20);
    if (header_.is_64) {
        header_.entry = reader_.u64(bytes.data() + 24);
        header_.phoff = reader_.u64(bytes.data() + 32);
        header_.shoff = reader_.u64(bytes.data() + 40);
        header_.flags = reader_.u32(bytes.data() + 48);
        header_.ehsize = reader_.u16(bytes.data() + 52);
        header_.phentsize = reader_.u16(bytes.data() + 54);
        header_.phnum = reader_.u16(bytes.data() + 56);
        header_.shentsize = reader_.u16(bytes.data() + 58);
        header_.shnum = reader_.u16(bytes.data() + 60);
        header_.shstrndx = reader_.u16(bytes.data() + 62);
    } else {
        header_.entry = reader_.u32(bytes.data() + 24);
        header_.phoff = reader_.u32(bytes.data() + 28);
        header_.shoff = reader_.u32(bytes.data() + 32);
        header_.flags = reader_.u32(bytes.data() + 36);
        header_.ehsize = reader_.u16(bytes.data() + 40);
        header_.phentsize = reader_.u16(bytes.data() + 42);
        header_.phnum = reader_.u16(bytes.data() + 44);
        header_.shentsize = reader_.u16(bytes.data() + 46);
        header_.shnum = reader_.u16(bytes.data() + 48);
        header_.shstrndx = reader_.u16(bytes.data() + 50);
    }
    if (header_.version != ev_current)
        return workspace_result_t<void>::failure(
            elf_error("invalid ELF header version", "elf_header", 20, 4));
    if (file_type(header_.type) == elf_filetype_t::unknown)
        return workspace_result_t<void>::failure(
            unsupported_error("unsupported ELF file type"));
    const auto architecture = elf_machine_to_arch(header_.machine);
    const auto mode = architecture_mode(header_.machine, header_.is_64);
    if (architecture == architecture_id_t::unknown || mode == architecture_mode_t::unknown)
        return workspace_result_t<void>::failure(
            unsupported_error("unsupported ELF machine architecture"));
    const bool class_mismatch =
        (header_.machine == em_386 && header_.is_64) ||
        (header_.machine == em_x86_64 && !header_.is_64) ||
        (header_.machine == em_arm && header_.is_64) ||
        (header_.machine == em_aarch64 && !header_.is_64) ||
        (header_.machine == em_ppc && header_.is_64) ||
        (header_.machine == em_ppc64 && !header_.is_64);
    if (class_mismatch)
        return workspace_result_t<void>::failure(
            elf_error("ELF class conflicts with machine architecture", "elf_header"));
    if ((header_.machine == em_386 || header_.machine == em_x86_64 ||
         header_.machine == em_riscv) && header_.big_endian)
        return workspace_result_t<void>::failure(
            elf_error("ELF byte order conflicts with machine architecture", "elf_header"));
    if (header_.ehsize < required)
        return workspace_result_t<void>::failure(
            elf_error("ELF header size is too small", "elf_header", 0, header_.ehsize));
    auto declared_header = file_span(0, header_.ehsize, "elf_header");
    if (!declared_header)
        return workspace_result_t<void>::failure(std::move(declared_header.error()));
    header_.header_span = declared_header.take_value();
    const auto section_required = header_.is_64 ? sizeof(elf64_shdr_t) : sizeof(elf32_shdr_t);
    header_.section_count_extended = header_.shnum == 0 && header_.shoff != 0;
    header_.segment_count_extended = header_.phnum == pn_xnum;
    header_.section_names_extended = header_.shstrndx == shn_xindex;
    const bool needs_section_zero =
        header_.section_count_extended || header_.segment_count_extended ||
        header_.section_names_extended;
    if (needs_section_zero) {
        if (header_.shoff == 0 || header_.shentsize < section_required)
            return workspace_result_t<void>::failure(
                elf_error("extended ELF counts require section header zero", "elf_header"));
        auto section_zero = read_section_header(header_.shoff, 0);
        if (!section_zero)
            return workspace_result_t<void>::failure(std::move(section_zero.error()));
        if (section_zero.value().type != sht_null)
            return workspace_result_t<void>::failure(
                elf_error("ELF section header zero is not SHT_NULL", "elf_sections",
                          header_.shoff, section_required));
        if (header_.shnum == 0) {
            if (section_zero.value().size == 0 ||
                section_zero.value().size > (std::numeric_limits<std::uint32_t>::max)())
                return workspace_result_t<void>::failure(
                    elf_error("invalid extended ELF section count", "elf_header"));
            header_.shnum = static_cast<std::uint32_t>(section_zero.value().size);
        }
        if (header_.phnum == pn_xnum)
            header_.phnum = section_zero.value().info;
        if (header_.shstrndx == shn_xindex)
            header_.shstrndx = section_zero.value().link;
    }
    if (header_.shnum > limits_.max_sections)
        return workspace_result_t<void>::failure(limit_error(
            "ELF section count exceeds its budget", "elf_header", header_.shnum,
            limits_.max_sections));
    if (header_.phnum > limits_.max_segments)
        return workspace_result_t<void>::failure(limit_error(
            "ELF segment count exceeds its budget", "elf_header", header_.phnum,
            limits_.max_segments));
    if (header_.shnum == 0) {
        if (header_.shoff != 0 || header_.shstrndx != shn_undef)
            return workspace_result_t<void>::failure(
                elf_error("ELF section-table fields are inconsistent", "elf_header"));
    } else {
        if (header_.shoff == 0 || header_.shentsize < section_required)
            return workspace_result_t<void>::failure(
                elf_error("ELF section header table is invalid", "elf_header"));
        std::uint64_t table_size = 0;
        if (!checked_mul_u64(header_.shentsize, header_.shnum, table_size))
            return workspace_result_t<void>::failure(
                elf_error("ELF section header table size overflows", "elf_header"));
        auto span = file_span(header_.shoff, table_size, "elf_sections");
        if (!span)
            return workspace_result_t<void>::failure(std::move(span.error()));
        header_.section_table_span = span.take_value();
        if (header_.shstrndx >= header_.shnum && header_.shstrndx != shn_undef)
            return workspace_result_t<void>::failure(
                elf_error("ELF section-name table index is out of range", "elf_header"));
    }
    const auto program_required = header_.is_64 ? sizeof(elf64_phdr_t) : sizeof(elf32_phdr_t);
    if (header_.phnum == 0) {
        if (header_.phoff != 0)
            return workspace_result_t<void>::failure(
                elf_error("ELF program-table fields are inconsistent", "elf_header"));
    } else {
        if (header_.phoff == 0 || header_.phentsize < program_required)
            return workspace_result_t<void>::failure(
                elf_error("ELF program header table is invalid", "elf_header"));
        std::uint64_t table_size = 0;
        if (!checked_mul_u64(header_.phentsize, header_.phnum, table_size))
            return workspace_result_t<void>::failure(
                elf_error("ELF program header table size overflows", "elf_header"));
        auto span = file_span(header_.phoff, table_size, "elf_segments");
        if (!span)
            return workspace_result_t<void>::failure(std::move(span.error()));
        header_.program_table_span = span.take_value();
    }
    if (header_.program_table_span &&
        header_.header_span.overlaps(*header_.program_table_span))
        return workspace_result_t<void>::failure(
            elf_error("ELF header overlaps the program header table", "elf_header"));
    if (header_.section_table_span &&
        header_.header_span.overlaps(*header_.section_table_span))
        return workspace_result_t<void>::failure(
            elf_error("ELF header overlaps the section header table", "elf_header"));
    if (header_.program_table_span && header_.section_table_span &&
        header_.program_table_span->overlaps(*header_.section_table_span))
        return workspace_result_t<void>::failure(
            elf_error("ELF program and section header tables overlap", "elf_header"));
    auto charged = charge_metadata(header_.ehsize, "elf_header");
    if (!charged)
        return charged;
    image_.filetype = file_type(header_.type);
    image_.is_64bit = header_.is_64;
    image_.endian = header_.big_endian ? endian_t::big : endian_t::little;
    image_.machine = header_.machine;
    image_.version = header_.version;
    image_.flags = header_.flags;
    image_.osabi = header_.osabi;
    image_.abi_version = header_.abi_version;
    image_.entry_point = header_.entry;
    image_.phoff = header_.phoff;
    image_.shoff = header_.shoff;
    image_.ehsize = header_.ehsize;
    image_.phentsize = header_.phentsize;
    image_.phnum = header_.phnum;
    image_.shentsize = header_.shentsize;
    image_.shnum = header_.shnum;
    image_.shstrndx = header_.shstrndx;
    return workspace_result_t<void>::success();
}

workspace_result_t<const string_table_t*> elf_parser_t::load_string_table(
    std::uint32_t index) {
    if (index >= raw_sections_.size() || raw_sections_[index].type != sht_strtab)
        return workspace_result_t<const string_table_t*>::failure(
            elf_error("ELF string-table index is invalid", "elf_strings"));
    if (string_tables_[index])
        return workspace_result_t<const string_table_t*>::success(&*string_tables_[index]);
    const auto& section = raw_sections_[index];
    auto string_charge = charge_string_bytes(section.size, "elf_strings");
    if (!string_charge)
        return workspace_result_t<const string_table_t*>::failure(
            std::move(string_charge.error()));
    auto metadata_charge = charge_metadata(section.size, "elf_strings");
    if (!metadata_charge)
        return workspace_result_t<const string_table_t*>::failure(
            std::move(metadata_charge.error()));
    string_table_t table;
    table.file_offset = section.offset;
    if (section.size != 0) {
        auto bytes = provider_.read_vector(section.offset, section.size,
                                           limits_.max_string_table_bytes, cancel_);
        if (!bytes)
            return workspace_result_t<const string_table_t*>::failure(
                std::move(bytes.error()));
        table.bytes = bytes.take_value();
        if (table.bytes.front() != 0 || table.bytes.back() != 0)
            return workspace_result_t<const string_table_t*>::failure(
                elf_error("ELF string table is not NUL bounded", "elf_strings",
                          section.offset, section.size));
    }
    string_tables_[index] = std::move(table);
    return workspace_result_t<const string_table_t*>::success(&*string_tables_[index]);
}

workspace_result_t<std::string> elf_parser_t::string_at(
    const string_table_t& table, std::uint64_t offset, const char* phase) const {
    if (table.bytes.empty()) {
        if (offset == 0)
            return workspace_result_t<std::string>::success({});
        return workspace_result_t<std::string>::failure(
            elf_error("ELF string offset exceeds an empty table", phase,
                      table.file_offset, 0));
    }
    if (offset >= table.bytes.size())
        return workspace_result_t<std::string>::failure(
            elf_error("ELF string offset is out of range", phase,
                      table.file_offset + offset, 1));
    const auto begin = table.bytes.begin() + static_cast<std::ptrdiff_t>(offset);
    const auto end = std::find(begin, table.bytes.end(), static_cast<std::uint8_t>(0));
    if (end == table.bytes.end())
        return workspace_result_t<std::string>::failure(
            elf_error("ELF string is not NUL terminated", phase,
                      table.file_offset + offset,
                      table.bytes.size() - static_cast<std::size_t>(offset)));
    return workspace_result_t<std::string>::success(
        std::string(reinterpret_cast<const char*>(&*begin),
                    static_cast<std::size_t>(end - begin)));
}

workspace_result_t<void> elf_parser_t::parse_section_headers() {
    if (header_.shnum == 0) {
        string_tables_.clear();
        symbol_table_lookup_.clear();
        return workspace_result_t<void>::success();
    }
    auto charged = charge_metadata(header_.section_table_span->size, "elf_sections");
    if (!charged)
        return charged;
    raw_sections_.reserve(header_.shnum);
    for (std::uint32_t index = 0; index < header_.shnum; ++index) {
        auto stopped = poll(index);
        if (!stopped)
            return stopped;
        std::uint64_t stride = 0;
        std::uint64_t offset = 0;
        if (!checked_mul_u64(index, header_.shentsize, stride) ||
            !checked_add_u64(header_.shoff, stride, offset))
            return workspace_result_t<void>::failure(
                elf_error("ELF section header offset overflows", "elf_sections"));
        auto parsed = read_section_header(offset, index);
        if (!parsed)
            return workspace_result_t<void>::failure(std::move(parsed.error()));
        auto section = parsed.take_value();
        if (index != 0 && section.type == sht_null &&
            (section.name != 0 || section.flags != 0 || section.address != 0 ||
             section.offset != 0 || section.size != 0 || section.link != 0 ||
             section.info != 0 || section.alignment != 0 ||
             section.entry_size != 0))
            return workspace_result_t<void>::failure(
                elf_error("inactive ELF section header has nonzero fields",
                          "elf_sections", offset, header_.shentsize));
        if (section.alignment != 0 && !is_power_of_two(section.alignment))
            return workspace_result_t<void>::failure(
                elf_error("ELF section alignment is not a power of two", "elf_sections",
                          offset, header_.shentsize));
        if (section.entry_size != 0 && section.size != 0 &&
            section.entry_size > section.size)
            return workspace_result_t<void>::failure(
                elf_error("ELF section entry size exceeds the section", "elf_sections",
                          section.offset, section.size));
        if (section.type == sht_nobits) {
            if (section.offset > provider_.size())
                return workspace_result_t<void>::failure(
                    elf_error("ELF NOBITS section offset exceeds the provider",
                              "elf_sections", section.offset, 0));
        } else if (section.type != sht_null && section.size != 0) {
            auto span = file_span(section.offset, section.size, "elf_sections");
            if (!span)
                return workspace_result_t<void>::failure(std::move(span.error()));
            section.file_span = span.take_value();
        }
        raw_sections_.push_back(std::move(section));
    }
    const auto& zero = raw_sections_.front();
    if (zero.type != sht_null || zero.name != 0 || zero.flags != 0 || zero.address != 0 ||
        zero.offset != 0 || zero.alignment != 0 || zero.entry_size != 0)
        return workspace_result_t<void>::failure(
            elf_error("ELF section header zero has invalid fields", "elf_sections",
                      header_.shoff, header_.shentsize));
    if ((!header_.section_count_extended && zero.size != 0) ||
        (!header_.segment_count_extended && zero.info != 0) ||
        (!header_.section_names_extended && zero.link != 0))
        return workspace_result_t<void>::failure(
            elf_error("ELF section header zero has unexpected extended-count fields",
                      "elf_sections", header_.shoff, header_.shentsize));
    std::vector<std::pair<checked_span_t, std::uint32_t>> spans;
    spans.reserve(raw_sections_.size());
    for (const auto& section : raw_sections_) {
        if (!section.file_span)
            continue;
        if (section.file_span->overlaps(header_.header_span) ||
            (header_.program_table_span &&
             section.file_span->overlaps(*header_.program_table_span)) ||
            (header_.section_table_span &&
             section.file_span->overlaps(*header_.section_table_span)))
            return workspace_result_t<void>::failure(
                elf_error("ELF section data overlaps structural metadata", "elf_sections",
                          section.offset, section.size));
        spans.emplace_back(*section.file_span, section.index);
    }
    std::sort(spans.begin(), spans.end(), [](const auto& left, const auto& right) {
        return std::tie(left.first.offset, left.first.size, left.second) <
               std::tie(right.first.offset, right.first.size, right.second);
    });
    for (std::size_t index = 1; index < spans.size(); ++index) {
        if (spans[index - 1].first.overlaps(spans[index].first)) {
            auto error = elf_error("ELF section file ranges overlap", "elf_sections",
                                   spans[index].first.offset, spans[index].first.size);
            error.details.emplace_back("first_section",
                                       std::to_string(spans[index - 1].second));
            error.details.emplace_back("second_section",
                                       std::to_string(spans[index].second));
            return workspace_result_t<void>::failure(std::move(error));
        }
    }
    string_tables_.resize(raw_sections_.size());
    symbol_table_lookup_.assign(raw_sections_.size(), -1);
    extended_index_lookup_.assign(raw_sections_.size(), -1);
    const string_table_t* section_names = nullptr;
    if (header_.shstrndx != shn_undef) {
        if (raw_sections_[header_.shstrndx].type != sht_strtab)
            return workspace_result_t<void>::failure(
                elf_error("ELF section-name table is not SHT_STRTAB", "elf_sections"));
        auto names = load_string_table(header_.shstrndx);
        if (!names)
            return workspace_result_t<void>::failure(std::move(names.error()));
        section_names = names.value();
    }
    image_.sections.reserve(raw_sections_.size());
    std::unordered_map<std::uint64_t, std::string> section_name_cache;
    section_name_cache.reserve(raw_sections_.size());
    for (const auto& raw : raw_sections_) {
        auto stopped = poll(raw.index);
        if (!stopped)
            return stopped;
        if (!section_names && raw.name != 0)
            return workspace_result_t<void>::failure(
                elf_error("ELF section name exists without a name table", "elf_sections"));
        std::string name;
        if (section_names) {
            const auto cached = section_name_cache.find(raw.name);
            if (cached != section_name_cache.end()) {
                name = cached->second;
            } else {
                auto parsed_name = string_at(*section_names, raw.name, "elf_sections");
                if (!parsed_name)
                    return workspace_result_t<void>::failure(
                        std::move(parsed_name.error()));
                name = parsed_name.take_value();
                section_name_cache.emplace(raw.name, name);
            }
        }
        auto name_budget = charge_materialized_string(name.size(), "elf_sections");
        if (!name_budget)
            return name_budget;
        elf_section_t section;
        section.index = raw.index;
        section.name = std::move(name);
        section.type = raw.type;
        section.flags = raw.flags;
        section.addr = raw.address;
        section.offset = raw.offset;
        section.size = raw.size;
        section.link = raw.link;
        section.info = raw.info;
        section.addralign = raw.alignment;
        section.entsize = raw.entry_size;
        section.readable = (raw.flags & shf_alloc) != 0;
        section.writable = (raw.flags & shf_write) != 0;
        section.executable = (raw.flags & shf_execinstr) != 0;
        section.allocated = (raw.flags & shf_alloc) != 0;
        section.is_init_array = raw.type == sht_init_array;
        section.is_fini_array = raw.type == sht_fini_array;
        section.is_preinit_array = raw.type == sht_preinit_array;
        section.is_symtab = raw.type == sht_symtab;
        section.is_dynsym = raw.type == sht_dynsym;
        section.is_strtab = raw.type == sht_strtab;
        section.is_dynamic = raw.type == sht_dynamic;
        section.is_note = raw.type == sht_note;
        section.is_rela = raw.type == sht_rela;
        section.is_rel = raw.type == sht_rel;
        section.is_nobits = raw.type == sht_nobits;
        section.is_hash = raw.type == sht_hash;
        section.is_gnu_hash = raw.type == sht_gnu_hash;
        section.is_plt = section.name == ".plt" || section.name == ".plt.sec" ||
                         section.name == ".plt.got" || section.name == ".iplt";
        section.is_got = section.name == ".got";
        section.is_got_plt = section.name == ".got.plt";
        image_.sections.push_back(std::move(section));
    }
    return classify_sections();
}

workspace_result_t<void> elf_parser_t::inspect_compressed_section(
    elf_section_t& section, const raw_section_t& raw) {
    const bool flag_compressed = (raw.flags & shf_compressed) != 0;
    const bool gnu_compressed = section.name.rfind(".zdebug_", 0) == 0;
    if (!flag_compressed && !gnu_compressed)
        return workspace_result_t<void>::success();
    if (flag_compressed && gnu_compressed)
        return workspace_result_t<void>::failure(
            elf_error("ELF debug section uses two compression encodings",
                      "elf_debug", raw.offset, raw.size));
    if (raw.type == sht_nobits)
        return workspace_result_t<void>::failure(
            elf_error("ELF NOBITS section cannot be compressed", "elf_debug",
                      raw.offset, raw.size));
    section.is_compressed = true;
    section.uses_gnu_zdebug = gnu_compressed;
    if (flag_compressed) {
        const std::uint64_t header_size = header_.is_64 ? 24 : 12;
        if (raw.size < header_size)
            return workspace_result_t<void>::failure(
                elf_error("ELF compressed section header is truncated", "elf_debug",
                          raw.offset, raw.size));
        std::array<std::uint8_t, 24> bytes{};
        auto read = read_exact(raw.offset, bytes.data(), header_size, "elf_debug");
        if (!read)
            return read;
        auto charged = charge_metadata(header_size, "elf_debug");
        if (!charged)
            return charged;
        section.compression_type = reader_.u32(bytes.data());
        const auto uncompressed = header_.is_64 ? reader_.u64(bytes.data() + 8)
                                                : reader_.u32(bytes.data() + 4);
        const auto alignment = header_.is_64 ? reader_.u64(bytes.data() + 16)
                                             : reader_.u32(bytes.data() + 8);
        if (section.compression_type == 0 || uncompressed == 0 ||
            (alignment != 0 && !is_power_of_two(alignment)))
            return workspace_result_t<void>::failure(
                elf_error("ELF compressed section metadata is invalid", "elf_debug",
                          raw.offset, header_size));
        section.uncompressed_size = uncompressed;
    } else {
        if (raw.size < 12)
            return workspace_result_t<void>::failure(
                elf_error("GNU compressed debug header is truncated", "elf_debug",
                          raw.offset, raw.size));
        std::array<std::uint8_t, 12> bytes{};
        auto read = read_exact(raw.offset, bytes.data(), bytes.size(), "elf_debug");
        if (!read)
            return read;
        auto charged = charge_metadata(bytes.size(), "elf_debug");
        if (!charged)
            return charged;
        if (std::memcmp(bytes.data(), "ZLIB", 4) != 0)
            return workspace_result_t<void>::failure(
                elf_error("GNU compressed debug magic is invalid", "elf_debug",
                          raw.offset, 4));
        const auto uncompressed = read_u64_be(bytes.data() + 4);
        if (uncompressed == 0)
            return workspace_result_t<void>::failure(
                elf_error("GNU compressed debug size is zero", "elf_debug",
                          raw.offset + 4, 8));
        section.compression_type = elfcompress_zlib;
        section.uncompressed_size = uncompressed;
    }
    image_.dwarf_sections.has_compressed_debug = true;
    image_.dwarf_sections.uses_gnu_zdebug |= gnu_compressed;
    auto name_budget = charge_materialized_string(section.name.size(), "elf_debug");
    if (!name_budget)
        return name_budget;
    image_.dwarf_sections.compressed_section_names.push_back(section.name);
    return workspace_result_t<void>::success();
}

workspace_result_t<void> elf_parser_t::classify_sections() {
    const auto debug_name = [](std::string_view name, std::string_view suffix) {
        const std::string_view debug_prefix = ".debug_";
        const std::string_view zdebug_prefix = ".zdebug_";
        if (name.size() == debug_prefix.size() + suffix.size() &&
            name.substr(0, debug_prefix.size()) == debug_prefix &&
            name.substr(debug_prefix.size()) == suffix)
            return true;
        return name.size() == zdebug_prefix.size() + suffix.size() &&
               name.substr(0, zdebug_prefix.size()) == zdebug_prefix &&
               name.substr(zdebug_prefix.size()) == suffix;
    };
    for (std::size_t index = 0; index < image_.sections.size(); ++index) {
        auto stopped = poll(index);
        if (!stopped)
            return stopped;
        auto& section = image_.sections[index];
        const auto name = std::string_view(section.name);
        section.is_dwarf = name.rfind(".debug_", 0) == 0 ||
                           name.rfind(".zdebug_", 0) == 0 ||
                           name == ".eh_frame" || name == ".eh_frame_hdr" ||
                           name == ".gdb_index" || name == ".gnu_debugdata";
        image_.dwarf_sections.has_debug_info |= debug_name(name, "info");
        image_.dwarf_sections.has_debug_line |= debug_name(name, "line");
        image_.dwarf_sections.has_debug_str |= debug_name(name, "str");
        image_.dwarf_sections.has_debug_abbrev |= debug_name(name, "abbrev");
        image_.dwarf_sections.has_debug_ranges |= debug_name(name, "ranges");
        image_.dwarf_sections.has_debug_aranges |= debug_name(name, "aranges");
        image_.dwarf_sections.has_debug_macinfo |= debug_name(name, "macinfo");
        image_.dwarf_sections.has_debug_loc |= debug_name(name, "loc");
        image_.dwarf_sections.has_debug_frame |= debug_name(name, "frame");
        image_.dwarf_sections.has_debug_pubnames |= debug_name(name, "pubnames");
        image_.dwarf_sections.has_debug_pubtypes |= debug_name(name, "pubtypes");
        image_.dwarf_sections.has_debug_line_str |= debug_name(name, "line_str");
        image_.dwarf_sections.has_debug_loclists |= debug_name(name, "loclists");
        image_.dwarf_sections.has_debug_rnglists |= debug_name(name, "rnglists");
        image_.dwarf_sections.has_debug_str_offsets |= debug_name(name, "str_offsets");
        image_.dwarf_sections.has_debug_addr |= debug_name(name, "addr");
        image_.dwarf_sections.has_debug_types |= debug_name(name, "types");
        image_.dwarf_sections.has_debug_names |= debug_name(name, "names");
        image_.dwarf_sections.has_debug_sup |= debug_name(name, "sup");
        image_.dwarf_sections.has_eh_frame |= name == ".eh_frame";
        image_.dwarf_sections.has_eh_frame_hdr |= name == ".eh_frame_hdr";
        image_.dwarf_sections.has_gnu_debuglink |= name == ".gnu_debuglink";
        image_.dwarf_sections.has_gnu_debugaltlink |= name == ".gnu_debugaltlink";
        image_.dwarf_sections.has_gnu_debugdata |= name == ".gnu_debugdata";
        if (name == ".gnu_debugdata") {
            if (section.size < 6)
                return workspace_result_t<void>::failure(
                    elf_error("GNU debugdata payload is truncated", "elf_debug",
                              section.offset, section.size));
            std::array<std::uint8_t, 6> magic{};
            auto read = read_exact(section.offset, magic.data(), magic.size(), "elf_debug");
            if (!read)
                return read;
            static constexpr std::array<std::uint8_t, 6> xz_magic{
                0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00};
            if (magic != xz_magic)
                return workspace_result_t<void>::failure(
                    elf_error("GNU debugdata payload is not XZ encoded", "elf_debug",
                              section.offset, magic.size()));
            auto charged = charge_metadata(magic.size(), "elf_debug");
            if (!charged)
                return charged;
            auto name_budget = charge_materialized_string(section.name.size(),
                                                           "elf_debug");
            if (!name_budget)
                return name_budget;
            section.is_compressed = true;
            image_.dwarf_sections.has_compressed_debug = true;
            image_.dwarf_sections.compressed_section_names.push_back(section.name);
        }
        auto compressed = inspect_compressed_section(section, raw_sections_[index]);
        if (!compressed)
            return compressed;
        const auto& raw = raw_sections_[index];
        if (raw.type == sht_symtab || raw.type == sht_dynsym) {
            if (raw.link >= raw_sections_.size() || raw_sections_[raw.link].type != sht_strtab)
                return workspace_result_t<void>::failure(
                    elf_error("ELF symbol table does not link to a string table",
                              "elf_sections", raw.offset, raw.size));
            if (raw.entry_size < native_symbol_size() || raw.entry_size == 0 ||
                raw.size % raw.entry_size != 0)
                return workspace_result_t<void>::failure(
                    elf_error("ELF symbol table entry layout is invalid", "elf_sections",
                              raw.offset, raw.size));
        } else if (raw.type == sht_rel || raw.type == sht_rela) {
            if (raw.link >= raw_sections_.size() ||
                (raw_sections_[raw.link].type != sht_symtab &&
                 raw_sections_[raw.link].type != sht_dynsym))
                return workspace_result_t<void>::failure(
                    elf_error("ELF relocation section has an invalid symbol-table link",
                              "elf_sections", raw.offset, raw.size));
            const auto required = native_rel_size(raw.type == sht_rela);
            if (raw.entry_size != 0 && raw.entry_size < required)
                return workspace_result_t<void>::failure(
                    elf_error("ELF relocation entry size is too small", "elf_sections",
                              raw.offset, raw.size));
            const auto stride = raw.entry_size == 0 ? required : raw.entry_size;
            if (raw.size % stride != 0)
                return workspace_result_t<void>::failure(
                    elf_error("ELF relocation section has a partial entry", "elf_sections",
                              raw.offset, raw.size));
            if (header_.type == et_rel &&
                (raw.info == shn_undef || raw.info >= raw_sections_.size()))
                return workspace_result_t<void>::failure(
                    elf_error("relocatable ELF relocation target is invalid",
                              "elf_sections", raw.offset, raw.size));
        } else if (raw.type == sht_dynamic) {
            if (raw.link != shn_undef &&
                (raw.link >= raw_sections_.size() ||
                 raw_sections_[raw.link].type != sht_strtab))
                return workspace_result_t<void>::failure(
                    elf_error("ELF dynamic section has an invalid string-table link",
                              "elf_sections", raw.offset, raw.size));
            const auto stride = raw.entry_size == 0 ? native_dynamic_size() : raw.entry_size;
            if (stride < native_dynamic_size() || raw.size % stride != 0)
                return workspace_result_t<void>::failure(
                    elf_error("ELF dynamic section entry layout is invalid",
                              "elf_sections", raw.offset, raw.size));
        } else if (raw.type == sht_symtab_shndx) {
            if (raw.link >= raw_sections_.size() ||
                (raw_sections_[raw.link].type != sht_symtab &&
                 raw_sections_[raw.link].type != sht_dynsym))
                return workspace_result_t<void>::failure(
                    elf_error("ELF extended symbol-index section link is invalid",
                              "elf_sections", raw.offset, raw.size));
            const auto stride = raw.entry_size == 0 ? 4 : raw.entry_size;
            if (stride < 4 || raw.size % stride != 0)
                return workspace_result_t<void>::failure(
                    elf_error("ELF extended symbol-index layout is invalid",
                              "elf_sections", raw.offset, raw.size));
            if (extended_index_lookup_[raw.link] >= 0)
                return workspace_result_t<void>::failure(
                    elf_error("ELF symbol table has multiple extended-index sections",
                              "elf_sections", raw.offset, raw.size));
            extended_index_lookup_[raw.link] = raw.index;
        }
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<void> elf_parser_t::parse_program_headers() {
    if (header_.phnum == 0)
        return workspace_result_t<void>::success();
    auto charged = charge_metadata(header_.program_table_span->size, "elf_segments");
    if (!charged)
        return charged;
    raw_segments_.reserve(header_.phnum);
    image_.segments.reserve(header_.phnum);
    std::uint32_t interpreter_count = 0;
    std::uint32_t dynamic_count = 0;
    for (std::uint32_t index = 0; index < header_.phnum; ++index) {
        auto stopped = poll(index);
        if (!stopped)
            return stopped;
        std::uint64_t stride = 0;
        std::uint64_t offset = 0;
        if (!checked_mul_u64(index, header_.phentsize, stride) ||
            !checked_add_u64(header_.phoff, stride, offset))
            return workspace_result_t<void>::failure(
                elf_error("ELF program header offset overflows", "elf_segments"));
        std::array<std::uint8_t, sizeof(elf64_phdr_t)> bytes{};
        const auto required = header_.is_64 ? sizeof(elf64_phdr_t) : sizeof(elf32_phdr_t);
        auto read = read_exact(offset, bytes.data(), required, "elf_segments");
        if (!read)
            return read;
        raw_segment_t raw;
        raw.index = index;
        raw.type = reader_.u32(bytes.data());
        if (header_.is_64) {
            raw.flags = reader_.u32(bytes.data() + 4);
            raw.offset = reader_.u64(bytes.data() + 8);
            raw.virtual_address = reader_.u64(bytes.data() + 16);
            raw.physical_address = reader_.u64(bytes.data() + 24);
            raw.file_size = reader_.u64(bytes.data() + 32);
            raw.memory_size = reader_.u64(bytes.data() + 40);
            raw.alignment = reader_.u64(bytes.data() + 48);
        } else {
            raw.offset = reader_.u32(bytes.data() + 4);
            raw.virtual_address = reader_.u32(bytes.data() + 8);
            raw.physical_address = reader_.u32(bytes.data() + 12);
            raw.file_size = reader_.u32(bytes.data() + 16);
            raw.memory_size = reader_.u32(bytes.data() + 20);
            raw.flags = reader_.u32(bytes.data() + 24);
            raw.alignment = reader_.u32(bytes.data() + 28);
        }
        if (raw.alignment > 1 && !is_power_of_two(raw.alignment))
            return workspace_result_t<void>::failure(
                elf_error("ELF segment alignment is not a power of two", "elf_segments",
                          offset, header_.phentsize));
        if ((raw.type == pt_load || raw.type == pt_tls) &&
            raw.file_size > raw.memory_size)
            return workspace_result_t<void>::failure(
                elf_error("ELF segment file size exceeds memory size", "elf_segments",
                          raw.offset, raw.file_size));
        if (raw.type == pt_load && raw.alignment > 1 &&
            raw.offset % raw.alignment != raw.virtual_address % raw.alignment)
            return workspace_result_t<void>::failure(
                elf_error("ELF load segment alignment is inconsistent", "elf_segments",
                          raw.offset, raw.file_size));
        std::uint64_t virtual_end = 0;
        if (!checked_add_u64(raw.virtual_address, raw.memory_size, virtual_end))
            return workspace_result_t<void>::failure(
                elf_error("ELF segment virtual range overflows", "elf_segments"));
        if (raw.file_size != 0) {
            auto span = file_span(raw.offset, raw.file_size, "elf_segments");
            if (!span)
                return workspace_result_t<void>::failure(std::move(span.error()));
            raw.file_span = span.take_value();
        } else if (raw.offset > provider_.size()) {
            return workspace_result_t<void>::failure(
                elf_error("zero-length ELF segment offset exceeds the provider",
                          "elf_segments", raw.offset, 0));
        }
        if (raw.type == pt_interp && ++interpreter_count > 1)
            return workspace_result_t<void>::failure(
                elf_error("ELF contains multiple interpreter segments", "elf_segments"));
        if (raw.type == pt_dynamic && ++dynamic_count > 1)
            return workspace_result_t<void>::failure(
                elf_error("ELF contains multiple dynamic segments", "elf_segments"));
        if (raw.type == pt_phdr && header_.program_table_span) {
            if (!raw.file_span || !raw.file_span->contains(*header_.program_table_span))
                return workspace_result_t<void>::failure(
                    elf_error("ELF PHDR segment does not contain the program header table",
                              "elf_segments", raw.offset, raw.file_size));
        }
        elf_segment_t segment;
        segment.index = raw.index;
        segment.type = raw.type;
        segment.flags = raw.flags;
        segment.offset = raw.offset;
        segment.vaddr = raw.virtual_address;
        segment.paddr = raw.physical_address;
        segment.filesz = raw.file_size;
        segment.memsz = raw.memory_size;
        segment.align = raw.alignment;
        segment.readable = (raw.flags & pf_r) != 0;
        segment.writable = (raw.flags & pf_w) != 0;
        segment.executable = (raw.flags & pf_x) != 0;
        segment.is_load = raw.type == pt_load;
        segment.is_dynamic = raw.type == pt_dynamic;
        segment.is_interp = raw.type == pt_interp;
        segment.is_note = raw.type == pt_note;
        segment.is_tls = raw.type == pt_tls;
        segment.is_gnu_eh_frame = raw.type == pt_gnu_eh_frame;
        segment.is_gnu_stack = raw.type == pt_gnu_stack;
        segment.is_gnu_relro = raw.type == pt_gnu_relro;
        segment.is_gnu_property = raw.type == pt_gnu_property;
        segment.type_name = segment_type_name(raw.type);
        raw_segments_.push_back(raw);
        image_.segments.push_back(std::move(segment));
    }
    return validate_load_overlaps();
}

workspace_result_t<void> elf_parser_t::validate_load_overlaps() const {
    std::uint64_t overlap_checks = 0;
    for (std::size_t left_index = 0; left_index < raw_segments_.size(); ++left_index) {
        const auto& left = raw_segments_[left_index];
        if (left.type != pt_load || left.memory_size == 0)
            continue;
        for (std::size_t right_index = left_index + 1;
             right_index < raw_segments_.size(); ++right_index) {
            const auto& right = raw_segments_[right_index];
            if (right.type != pt_load || right.memory_size == 0)
                continue;
            if (overlap_checks >= limits_.max_overlap_checks)
                return workspace_result_t<void>::failure(limit_error(
                    "ELF segment overlap-check budget exceeded", "elf_segments",
                    overlap_checks + 1, limits_.max_overlap_checks));
            ++overlap_checks;
            const checked_span_t left_memory{left.virtual_address, left.memory_size};
            const checked_span_t right_memory{right.virtual_address, right.memory_size};
            if (left_memory.overlaps(right_memory)) {
                const auto overlap_start = (std::max)(left.virtual_address,
                                                      right.virtual_address);
                const auto overlap_end = (std::min)(left.virtual_address + left.memory_size,
                                                    right.virtual_address + right.memory_size);
                const auto left_file_end = left.virtual_address + left.file_size;
                const auto right_file_end = right.virtual_address + right.file_size;
                const auto left_backed_end = (std::max)(
                    overlap_start, (std::min)(overlap_end, left_file_end));
                const auto right_backed_end = (std::max)(
                    overlap_start, (std::min)(overlap_end, right_file_end));
                if (left_backed_end != right_backed_end ||
                    (left_backed_end > overlap_start &&
                     left.offset + (overlap_start - left.virtual_address) !=
                         right.offset + (overlap_start - right.virtual_address))) {
                    auto error = elf_error("overlapping ELF load segments map conflicting data",
                                           "elf_segments", overlap_start,
                                           overlap_end - overlap_start);
                    error.details.emplace_back("first_segment", std::to_string(left.index));
                    error.details.emplace_back("second_segment", std::to_string(right.index));
                    return workspace_result_t<void>::failure(std::move(error));
                }
            }
            if (left.file_span && right.file_span &&
                left.file_span->overlaps(*right.file_span)) {
                const auto overlap = (std::max)(left.offset, right.offset);
                const auto left_address = left.virtual_address + (overlap - left.offset);
                const auto right_address = right.virtual_address + (overlap - right.offset);
                if (left_address != right_address) {
                    auto error = elf_error("overlapping ELF load file ranges map to different addresses",
                                           "elf_segments", overlap, 1);
                    error.details.emplace_back("first_segment", std::to_string(left.index));
                    error.details.emplace_back("second_segment", std::to_string(right.index));
                    return workspace_result_t<void>::failure(std::move(error));
                }
            }
        }
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<void> elf_parser_t::parse_interpreter() {
    const raw_segment_t* interpreter = nullptr;
    for (const auto& segment : raw_segments_) {
        if (segment.type == pt_interp) {
            interpreter = &segment;
            break;
        }
    }
    if (!interpreter)
        return workspace_result_t<void>::success();
    if (interpreter->file_size < 2)
        return workspace_result_t<void>::failure(
            elf_error("ELF interpreter path is truncated", "elf_interp",
                      interpreter->offset, interpreter->file_size));
    auto string_charge = charge_string_bytes(interpreter->file_size, "elf_interp");
    if (!string_charge)
        return string_charge;
    auto metadata_charge = charge_metadata(interpreter->file_size, "elf_interp");
    if (!metadata_charge)
        return metadata_charge;
    auto bytes = provider_.read_vector(interpreter->offset, interpreter->file_size,
                                       limits_.max_string_table_bytes, cancel_);
    if (!bytes)
        return workspace_result_t<void>::failure(std::move(bytes.error()));
    auto data = bytes.take_value();
    const auto terminator = std::find(data.begin(), data.end(), static_cast<std::uint8_t>(0));
    if (terminator == data.end() || terminator == data.begin())
        return workspace_result_t<void>::failure(
            elf_error("ELF interpreter path is not a terminated nonempty string",
                      "elf_interp", interpreter->offset, interpreter->file_size));
    if (std::any_of(terminator, data.end(), [](std::uint8_t value) { return value != 0; }))
        return workspace_result_t<void>::failure(
            elf_error("ELF interpreter segment contains data after its path",
                      "elf_interp", interpreter->offset, interpreter->file_size));
    const auto length = static_cast<std::size_t>(terminator - data.begin());
    auto materialized = charge_materialized_string(length, "elf_interp");
    if (!materialized)
        return materialized;
    image_.interpreter = std::string(
        reinterpret_cast<const char*>(data.data()),
        length);
    return workspace_result_t<void>::success();
}

workspace_result_t<std::uint64_t> elf_parser_t::virtual_to_file(
    std::uint64_t address, std::uint64_t size, const char* phase) const {
    std::optional<std::uint64_t> resolved;
    for (const auto& segment : raw_segments_) {
        if (segment.file_size == 0 || address < segment.virtual_address)
            continue;
        const auto delta = address - segment.virtual_address;
        if (delta > segment.file_size || size > segment.file_size - delta)
            continue;
        std::uint64_t offset = 0;
        if (!checked_add_u64(segment.offset, delta, offset))
            return workspace_result_t<std::uint64_t>::failure(
                elf_error("ELF virtual-to-file mapping overflows", phase));
        if (resolved && *resolved != offset)
            return workspace_result_t<std::uint64_t>::failure(
                elf_error("ELF virtual address has conflicting file mappings", phase,
                          address, size));
        resolved = offset;
    }
    for (const auto& section : raw_sections_) {
        if (!section.file_span || address < section.address)
            continue;
        const auto delta = address - section.address;
        if (delta > section.size || size > section.size - delta)
            continue;
        std::uint64_t offset = 0;
        if (!checked_add_u64(section.offset, delta, offset))
            return workspace_result_t<std::uint64_t>::failure(
                elf_error("ELF section virtual-to-file mapping overflows", phase));
        if (resolved && *resolved != offset)
            return workspace_result_t<std::uint64_t>::failure(
                elf_error("ELF virtual address has conflicting section mappings", phase,
                          address, size));
        resolved = offset;
    }
    if (!resolved)
        return workspace_result_t<std::uint64_t>::failure(
            elf_error("ELF virtual range is not file backed", phase, address, size));
    auto span = file_span(*resolved, size, phase);
    if (!span)
        return workspace_result_t<std::uint64_t>::failure(std::move(span.error()));
    return workspace_result_t<std::uint64_t>::success(*resolved);
}

workspace_result_t<std::pair<std::uint64_t, std::uint64_t>>
elf_parser_t::virtual_file_window(std::uint64_t address, const char* phase) const {
    std::optional<std::pair<std::uint64_t, std::uint64_t>> resolved;
    for (const auto& segment : raw_segments_) {
        if (segment.file_size == 0 || address < segment.virtual_address)
            continue;
        const auto delta = address - segment.virtual_address;
        if (delta >= segment.file_size)
            continue;
        const auto candidate = std::make_pair(segment.offset + delta,
                                              segment.file_size - delta);
        if (resolved && resolved->first != candidate.first)
            return workspace_result_t<std::pair<std::uint64_t, std::uint64_t>>::failure(
                elf_error("ELF virtual address has conflicting file windows", phase,
                          address, 1));
        if (!resolved || candidate.second < resolved->second)
            resolved = candidate;
    }
    for (const auto& section : raw_sections_) {
        if (!section.file_span || address < section.address)
            continue;
        const auto delta = address - section.address;
        if (delta >= section.size)
            continue;
        const auto candidate = std::make_pair(section.offset + delta,
                                              section.size - delta);
        if (resolved && resolved->first != candidate.first)
            return workspace_result_t<std::pair<std::uint64_t, std::uint64_t>>::failure(
                elf_error("ELF virtual address has conflicting section windows", phase,
                          address, 1));
        if (!resolved || candidate.second < resolved->second)
            resolved = candidate;
    }
    if (!resolved)
        return workspace_result_t<std::pair<std::uint64_t, std::uint64_t>>::failure(
            elf_error("ELF virtual address is not file backed", phase, address, 1));
    return workspace_result_t<std::pair<std::uint64_t, std::uint64_t>>::success(*resolved);
}

std::optional<std::uint64_t> elf_parser_t::virtual_to_rva(
    std::uint64_t address) const noexcept {
    if (address < image_.normalized.image_base || address >= image_end_)
        return std::nullopt;
    const auto rva = address - image_.normalized.image_base;
    if (has_load_segments_) {
        for (const auto& segment : raw_segments_) {
            if (segment.type != pt_load || address < segment.virtual_address)
                continue;
            const auto delta = address - segment.virtual_address;
            if (delta < segment.memory_size)
                return rva;
        }
        return std::nullopt;
    }
    if (rva < header_.ehsize)
        return rva;
    for (std::size_t index = 0; index < section_rvas_.size(); ++index) {
        if (section_rvas_[index] == invalid_rva || rva < section_rvas_[index])
            continue;
        if (rva - section_rvas_[index] < raw_sections_[index].size)
            return rva;
    }
    return std::nullopt;
}

std::optional<std::uint64_t> elf_parser_t::section_runtime_address(
    std::uint32_t section_index, std::uint64_t section_offset) const noexcept {
    if (section_index >= section_rvas_.size() ||
        section_rvas_[section_index] == invalid_rva ||
        section_offset > raw_sections_[section_index].size)
        return std::nullopt;
    std::uint64_t rva = 0;
    std::uint64_t address = 0;
    if (!checked_add_u64(section_rvas_[section_index], section_offset, rva) ||
        !checked_add_u64(image_.normalized.image_base, rva, address) ||
        address >= image_end_)
        return std::nullopt;
    return address;
}

std::uint64_t elf_parser_t::pointer_size() const noexcept {
    return header_.is_64 ? 8 : 4;
}

std::uint64_t elf_parser_t::native_symbol_size() const noexcept {
    return header_.is_64 ? sizeof(elf64_sym_t) : sizeof(elf32_sym_t);
}

std::uint64_t elf_parser_t::native_rel_size(bool has_addend) const noexcept {
    if (header_.is_64)
        return has_addend ? sizeof(elf64_rela_t) : sizeof(elf64_rel_t);
    return has_addend ? sizeof(elf32_rela_t) : sizeof(elf32_rel_t);
}

std::uint64_t elf_parser_t::native_dynamic_size() const noexcept {
    return header_.is_64 ? sizeof(elf64_dyn_t) : sizeof(elf32_dyn_t);
}

workspace_result_t<void> elf_parser_t::build_image_layout() {
    section_rvas_.assign(raw_sections_.size(), invalid_rva);
    std::uint64_t image_base = 0;
    std::uint64_t image_end = 0;
    bool found_load = false;
    for (const auto& segment : raw_segments_) {
        if (segment.type != pt_load || segment.memory_size == 0)
            continue;
        const auto end = segment.virtual_address + segment.memory_size;
        if (!found_load || segment.virtual_address < image_base)
            image_base = segment.virtual_address;
        if (!found_load || end > image_end)
            image_end = end;
        found_load = true;
    }
    has_load_segments_ = found_load;
    if (found_load) {
        if (image_end <= image_base)
            return workspace_result_t<void>::failure(
                elf_error("ELF load image has an empty virtual range", "elf_layout"));
        for (const auto& section : raw_sections_) {
            if ((section.flags & shf_alloc) == 0 || section.size == 0)
                continue;
            std::uint64_t section_end = 0;
            if (!checked_add_u64(section.address, section.size, section_end) ||
                section.address < image_base || section_end > image_end)
                return workspace_result_t<void>::failure(
                    elf_error("allocated ELF section lies outside the load image",
                              "elf_layout", section.offset, section.size));
            bool contained = false;
            for (const auto& segment : raw_segments_) {
                if (segment.type != pt_load || section.address < segment.virtual_address)
                    continue;
                const auto delta = section.address - segment.virtual_address;
                if (delta > segment.memory_size ||
                    section.size > segment.memory_size - delta)
                    continue;
                if (section.type != sht_nobits) {
                    if (delta > segment.file_size ||
                        section.size > segment.file_size - delta ||
                        segment.offset + delta != section.offset)
                        continue;
                }
                contained = true;
                break;
            }
            bool tls_contained = false;
            if (!contained && (section.flags & shf_tls) != 0) {
                for (const auto& segment : raw_segments_) {
                    if (segment.type != pt_tls || section.address < segment.virtual_address)
                        continue;
                    const auto delta = section.address - segment.virtual_address;
                    if (delta > segment.memory_size ||
                        section.size > segment.memory_size - delta)
                        continue;
                    if (section.type != sht_nobits &&
                        (delta > segment.file_size ||
                         section.size > segment.file_size - delta ||
                         segment.offset + delta != section.offset))
                        continue;
                    tls_contained = true;
                    break;
                }
            }
            if (!contained && !tls_contained)
                return workspace_result_t<void>::failure(
                    elf_error("allocated ELF section is not consistently mapped by a load segment",
                              "elf_layout", section.offset, section.size));
            if (contained)
                section_rvas_[section.index] = section.address - image_base;
        }
    } else {
        std::uint64_t cursor = 0;
        if (!align_up(header_.ehsize, 16, cursor))
            return workspace_result_t<void>::failure(
                elf_error("ELF synthetic layout header overflows", "elf_layout"));
        bool assigned = false;
        for (const auto& section : raw_sections_) {
            if (section.index == 0 || section.size == 0 ||
                (section.flags & shf_alloc) == 0)
                continue;
            const auto alignment = section.alignment == 0 ? 1 : section.alignment;
            std::uint64_t start = 0;
            std::uint64_t end = 0;
            if (!align_up(cursor, alignment, start) ||
                !checked_add_u64(start, section.size, end))
                return workspace_result_t<void>::failure(
                    elf_error("ELF synthetic section layout overflows", "elf_layout",
                              section.offset, section.size));
            section_rvas_[section.index] = start;
            cursor = end;
            assigned = true;
        }
        if (!assigned) {
            for (const auto& section : raw_sections_) {
                if (section.index == 0 || section.size == 0 ||
                    (section.type != sht_progbits && section.type != sht_nobits &&
                     section.type != sht_init_array && section.type != sht_fini_array &&
                     section.type != sht_preinit_array))
                    continue;
                const auto alignment = section.alignment == 0 ? 1 : section.alignment;
                std::uint64_t start = 0;
                std::uint64_t end = 0;
                if (!align_up(cursor, alignment, start) ||
                    !checked_add_u64(start, section.size, end))
                    return workspace_result_t<void>::failure(
                        elf_error("ELF synthetic section layout overflows", "elf_layout",
                                  section.offset, section.size));
                section_rvas_[section.index] = start;
                cursor = end;
                assigned = true;
            }
        }
        if (!assigned || cursor == 0)
            return workspace_result_t<void>::failure(
                elf_error("ELF has no loadable analysis image", "elf_layout"));
        image_base = 0;
        image_end = cursor;
    }
    if (!header_.is_64 && image_end > (std::uint64_t{1} << 32))
        return workspace_result_t<void>::failure(
            elf_error("ELF32 virtual image exceeds its address width", "elf_layout"));
    image_end_ = image_end;
    image_.normalized.image_base = image_base;
    image_.normalized.image_size = image_end - image_base;
    return workspace_result_t<void>::success();
}

workspace_result_t<void> elf_parser_t::parse_symbol_sections() {
    for (const auto& section : raw_sections_) {
        if (section.type != sht_symtab && section.type != sht_dynsym)
            continue;
        auto stopped = poll(section.index);
        if (!stopped)
            return stopped;
        const auto count = section.size / section.entry_size;
        if (section.info > count)
            return workspace_result_t<void>::failure(
                elf_error("ELF symbol-table local boundary is out of range",
                          "elf_symbols", section.offset, section.size));
        auto strings = load_string_table(section.link);
        if (!strings)
            return workspace_result_t<void>::failure(std::move(strings.error()));
        auto parsed = parse_symbol_table(section.index, section.offset,
                                         section.entry_size, count,
                                         *strings.value(), section.type == sht_dynsym);
        if (!parsed)
            return workspace_result_t<void>::failure(std::move(parsed.error()));
        if (section.type == sht_dynsym)
            dynamic_symbol_table_index_ = parsed.value();
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<std::size_t> elf_parser_t::parse_symbol_table(
    std::uint32_t section_index, std::uint64_t file_offset,
    std::uint64_t entry_size, std::uint64_t count,
    const string_table_t& strings, bool dynamic) {
    if (count > limits_.max_symbols - symbol_count_)
        return workspace_result_t<std::size_t>::failure(limit_error(
            "ELF symbol count exceeds its budget", "elf_symbols",
            symbol_count_ + count, limits_.max_symbols));
    std::uint64_t table_size = 0;
    if (!checked_mul_u64(entry_size, count, table_size))
        return workspace_result_t<std::size_t>::failure(
            elf_error("ELF symbol table size overflows", "elf_symbols"));
    auto table_span = file_span(file_offset, table_size, "elf_symbols");
    if (!table_span)
        return workspace_result_t<std::size_t>::failure(std::move(table_span.error()));
    auto charged = charge_metadata(table_size, "elf_symbols");
    if (!charged)
        return workspace_result_t<std::size_t>::failure(std::move(charged.error()));
    const raw_section_t* extended = nullptr;
    if (section_index != invalid_section_index &&
        section_index < extended_index_lookup_.size() &&
        extended_index_lookup_[section_index] >= 0)
        extended = &raw_sections_[static_cast<std::size_t>(
            extended_index_lookup_[section_index])];
    std::uint64_t extended_stride = 0;
    if (extended) {
        extended_stride = extended->entry_size == 0 ? 4 : extended->entry_size;
        if (extended->size / extended_stride < count)
            return workspace_result_t<std::size_t>::failure(
                elf_error("ELF extended symbol-index table is truncated",
                          "elf_symbols", extended->offset, extended->size));
        auto extended_charge = charge_metadata(extended->size, "elf_symbols");
        if (!extended_charge)
            return workspace_result_t<std::size_t>::failure(
                std::move(extended_charge.error()));
    }
    parsed_symbol_table_t table;
    table.section_index = section_index;
    table.dynamic = dynamic;
    table.symbols.reserve(static_cast<std::size_t>(count));
    std::unordered_map<std::uint64_t, std::string> name_cache;
    name_cache.reserve(static_cast<std::size_t>((std::min)(count, std::uint64_t{65536})));
    std::array<std::uint8_t, sizeof(elf64_sym_t)> bytes{};
    for (std::uint64_t index = 0; index < count; ++index) {
        auto stopped = poll(index);
        if (!stopped)
            return workspace_result_t<std::size_t>::failure(std::move(stopped.error()));
        std::uint64_t stride = 0;
        std::uint64_t offset = 0;
        if (!checked_mul_u64(index, entry_size, stride) ||
            !checked_add_u64(file_offset, stride, offset))
            return workspace_result_t<std::size_t>::failure(
                elf_error("ELF symbol offset overflows", "elf_symbols"));
        auto read = read_exact(offset, bytes.data(), native_symbol_size(), "elf_symbols");
        if (!read)
            return workspace_result_t<std::size_t>::failure(std::move(read.error()));
        std::uint32_t name_offset = 0;
        std::uint8_t info = 0;
        std::uint8_t other = 0;
        std::uint16_t raw_section_index = 0;
        std::uint64_t value = 0;
        std::uint64_t size = 0;
        if (header_.is_64) {
            name_offset = reader_.u32(bytes.data());
            info = bytes[4];
            other = bytes[5];
            raw_section_index = reader_.u16(bytes.data() + 6);
            value = reader_.u64(bytes.data() + 8);
            size = reader_.u64(bytes.data() + 16);
        } else {
            name_offset = reader_.u32(bytes.data());
            value = reader_.u32(bytes.data() + 4);
            size = reader_.u32(bytes.data() + 8);
            info = bytes[12];
            other = bytes[13];
            raw_section_index = reader_.u16(bytes.data() + 14);
        }
        std::uint32_t resolved_section_index = raw_section_index;
        if (raw_section_index == shn_xindex) {
            if (!extended)
                return workspace_result_t<std::size_t>::failure(
                    elf_error("ELF symbol requires a missing extended section index",
                              "elf_symbols", offset, native_symbol_size()));
            std::uint64_t extended_offset = 0;
            std::uint64_t extended_delta = 0;
            if (!checked_mul_u64(index, extended_stride, extended_delta) ||
                !checked_add_u64(extended->offset, extended_delta, extended_offset))
                return workspace_result_t<std::size_t>::failure(
                    elf_error("ELF extended symbol index offset overflows", "elf_symbols"));
            std::array<std::uint8_t, 4> extended_bytes{};
            auto extended_read = read_exact(extended_offset, extended_bytes.data(),
                                            extended_bytes.size(), "elf_symbols");
            if (!extended_read)
                return workspace_result_t<std::size_t>::failure(
                    std::move(extended_read.error()));
            resolved_section_index = reader_.u32(extended_bytes.data());
        }
        if (resolved_section_index < 0xff00 &&
            resolved_section_index >= raw_sections_.size())
            return workspace_result_t<std::size_t>::failure(
                elf_error("ELF symbol section index is out of range", "elf_symbols",
                          offset, native_symbol_size()));
        std::string parsed_symbol_name;
        const auto cached_name = name_cache.find(name_offset);
        if (cached_name != name_cache.end()) {
            parsed_symbol_name = cached_name->second;
        } else {
            auto parsed_name = string_at(strings, name_offset, "elf_symbols");
            if (!parsed_name)
                return workspace_result_t<std::size_t>::failure(
                    std::move(parsed_name.error()));
            parsed_symbol_name = parsed_name.take_value();
            name_cache.emplace(name_offset, parsed_symbol_name);
        }
        if (index == 0 && (name_offset != 0 || value != 0 || size != 0 || info != 0 ||
                           other != 0 || raw_section_index != shn_undef))
            return workspace_result_t<std::size_t>::failure(
                elf_error("ELF symbol-table zero entry is not null", "elf_symbols",
                          offset, native_symbol_size()));
        auto name_budget = charge_materialized_string(parsed_symbol_name.size(),
                                                       "elf_symbols");
        if (!name_budget)
            return workspace_result_t<std::size_t>::failure(
                std::move(name_budget.error()));
        if (resolved_section_index < raw_sections_.size() &&
            resolved_section_index != shn_undef) {
            const auto& target = raw_sections_[resolved_section_index];
            if (header_.type == et_rel) {
                if (value > target.size || size > target.size - value)
                    return workspace_result_t<std::size_t>::failure(
                        elf_error("relocatable ELF symbol exceeds its section",
                                  "elf_symbols", offset, native_symbol_size()));
            } else if (target.size != 0) {
                const bool tls_offset = (info & 0x0f) == stt_tls &&
                                        value <= target.size &&
                                        size <= target.size - value;
                if (!tls_offset) {
                    std::uint64_t target_end = 0;
                    if (!checked_add_u64(target.address, target.size, target_end) ||
                        value < target.address || value > target_end ||
                        size > target_end - value)
                        return workspace_result_t<std::size_t>::failure(
                            elf_error("ELF symbol value conflicts with its section",
                                      "elf_symbols", offset, native_symbol_size()));
                }
            }
        }
        elf_symbol_t symbol;
        symbol.name = std::move(parsed_symbol_name);
        symbol.value = value;
        symbol.size = size;
        symbol.binding = info >> 4;
        symbol.type = info & 0x0f;
        symbol.visibility = other & 0x03;
        symbol.shndx = raw_section_index;
        symbol.section_index = resolved_section_index;
        symbol.table_section_index = section_index;
        symbol.table_symbol_index = static_cast<std::uint32_t>(index);
        symbol.is_local = symbol.binding == stb_local;
        symbol.is_global = symbol.binding == stb_global;
        symbol.is_weak = symbol.binding == stb_weak;
        symbol.is_unique = symbol.binding == stb_gnu_unique;
        symbol.is_undefined = resolved_section_index == shn_undef;
        symbol.is_absolute = resolved_section_index == shn_abs;
        symbol.is_common = resolved_section_index == shn_common;
        symbol.is_from_symtab = !dynamic;
        symbol.is_from_dynsym = dynamic;
        symbol.is_import = dynamic && symbol.is_undefined &&
                           (symbol.is_global || symbol.is_weak || symbol.is_unique) &&
                           !symbol.name.empty();
        symbol.is_export = dynamic && !symbol.is_undefined && !symbol.is_absolute &&
                           !symbol.is_common &&
                           (symbol.is_global || symbol.is_weak || symbol.is_unique) &&
                           (symbol.visibility == stv_default ||
                            symbol.visibility == stv_protected) &&
                           !symbol.name.empty();
        switch (symbol.type) {
            case stt_func: symbol.kind = elf_symbol_kind_t::function; break;
            case stt_object: symbol.kind = elf_symbol_kind_t::data; break;
            case stt_section: symbol.kind = elf_symbol_kind_t::section; break;
            case stt_file: symbol.kind = elf_symbol_kind_t::file; break;
            case stt_common: symbol.kind = elf_symbol_kind_t::common; break;
            case stt_tls: symbol.kind = elf_symbol_kind_t::tls; break;
            case stt_gnu_ifunc: symbol.kind = elf_symbol_kind_t::ifunc; break;
            case stt_notype: symbol.kind = elf_symbol_kind_t::notype; break;
            default: symbol.kind = elf_symbol_kind_t::unknown; break;
        }
        table.symbols.push_back(symbol);
        if (dynamic)
            image_.dynsym_symbols.push_back(std::move(symbol));
        else
            image_.symtab_symbols.push_back(std::move(symbol));
    }
    symbol_count_ += count;
    const auto table_index = symbol_tables_.size();
    symbol_tables_.push_back(std::move(table));
    if (section_index != invalid_section_index)
        symbol_table_lookup_[section_index] = static_cast<std::int64_t>(table_index);
    return workspace_result_t<std::size_t>::success(table_index);
}

workspace_result_t<std::optional<std::uint64_t>> elf_parser_t::dynamic_value(
    std::int64_t tag) const {
    std::optional<std::uint64_t> value;
    for (const auto& entry : raw_dynamic_) {
        if (entry.tag != tag)
            continue;
        if (value && *value != entry.value)
            return workspace_result_t<std::optional<std::uint64_t>>::failure(
                elf_error("ELF dynamic tag has conflicting values", "elf_dynamic"));
        value = entry.value;
    }
    return workspace_result_t<std::optional<std::uint64_t>>::success(value);
}

workspace_result_t<void> elf_parser_t::parse_dynamic_table() {
    std::optional<std::uint32_t> section_index;
    for (const auto& section : raw_sections_) {
        if (section.type != sht_dynamic)
            continue;
        if (section_index)
            return workspace_result_t<void>::failure(
                elf_error("ELF contains multiple dynamic sections", "elf_dynamic"));
        section_index = section.index;
    }
    const raw_segment_t* segment = nullptr;
    for (const auto& candidate : raw_segments_) {
        if (candidate.type == pt_dynamic) {
            segment = &candidate;
            break;
        }
    }
    if (!section_index && !segment)
        return workspace_result_t<void>::success();
    std::uint64_t offset = 0;
    std::uint64_t size = 0;
    std::uint64_t entry_size = native_dynamic_size();
    if (section_index) {
        const auto& section = raw_sections_[*section_index];
        offset = section.offset;
        size = section.size;
        entry_size = section.entry_size == 0 ? native_dynamic_size()
                                             : section.entry_size;
        if (segment) {
            if (!segment->file_span || !section.file_span ||
                !segment->file_span->contains(*section.file_span))
                return workspace_result_t<void>::failure(
                    elf_error("ELF dynamic section conflicts with its segment",
                              "elf_dynamic", section.offset, section.size));
            if (section.address != 0) {
                std::uint64_t section_end = 0;
                std::uint64_t segment_end = 0;
                if (!checked_add_u64(section.address, section.size, section_end) ||
                    !checked_add_u64(segment->virtual_address, segment->memory_size,
                                     segment_end) ||
                    section.address < segment->virtual_address ||
                    section_end > segment_end ||
                    segment->offset + (section.address - segment->virtual_address) !=
                        section.offset)
                    return workspace_result_t<void>::failure(
                        elf_error("ELF dynamic section address conflicts with its segment",
                                  "elf_dynamic", section.offset, section.size));
            }
        }
    } else {
        offset = segment->offset;
        size = segment->file_size;
    }
    if (size == 0)
        return workspace_result_t<void>::failure(
            elf_error("ELF dynamic table is empty", "elf_dynamic", offset, size));
    if (entry_size < native_dynamic_size() || size % entry_size != 0)
        return workspace_result_t<void>::failure(
            elf_error("ELF dynamic table has a partial or undersized entry",
                      "elf_dynamic", offset, size));
    const auto count = size / entry_size;
    if (count > limits_.max_dynamic_entries)
        return workspace_result_t<void>::failure(limit_error(
            "ELF dynamic entry count exceeds its budget", "elf_dynamic", count,
            limits_.max_dynamic_entries));
    auto span = file_span(offset, size, "elf_dynamic");
    if (!span)
        return workspace_result_t<void>::failure(std::move(span.error()));
    auto charged = charge_metadata(size, "elf_dynamic");
    if (!charged)
        return charged;
    raw_dynamic_.reserve(static_cast<std::size_t>(count));
    std::array<std::uint8_t, sizeof(elf64_dyn_t)> bytes{};
    bool terminated = false;
    for (std::uint64_t index = 0; index < count; ++index) {
        auto stopped = poll(index);
        if (!stopped)
            return stopped;
        std::uint64_t delta = 0;
        std::uint64_t entry_offset = 0;
        if (!checked_mul_u64(index, entry_size, delta) ||
            !checked_add_u64(offset, delta, entry_offset))
            return workspace_result_t<void>::failure(
                elf_error("ELF dynamic entry offset overflows", "elf_dynamic"));
        auto read = read_exact(entry_offset, bytes.data(), native_dynamic_size(),
                               "elf_dynamic");
        if (!read)
            return read;
        raw_dynamic_t entry;
        if (header_.is_64) {
            entry.tag = reader_.i64(bytes.data());
            entry.value = reader_.u64(bytes.data() + 8);
        } else {
            entry.tag = reader_.i32(bytes.data());
            entry.value = reader_.u32(bytes.data() + 4);
        }
        raw_dynamic_.push_back(entry);
        if (entry.tag == dt_null) {
            terminated = true;
            break;
        }
    }
    if (!terminated)
        return workspace_result_t<void>::failure(
            elf_error("ELF dynamic table has no DT_NULL terminator", "elf_dynamic",
                      offset, size));
    auto strings = resolve_dynamic_strings(section_index);
    if (!strings)
        return strings;
    return resolve_dynamic_names();
}

workspace_result_t<void> elf_parser_t::resolve_dynamic_strings(
    std::optional<std::uint32_t> dynamic_section_index) {
    if (raw_dynamic_.empty())
        return workspace_result_t<void>::success();
    auto strtab_value = dynamic_value(dt_strtab);
    if (!strtab_value)
        return workspace_result_t<void>::failure(std::move(strtab_value.error()));
    auto strsz_value = dynamic_value(dt_strsz);
    if (!strsz_value)
        return workspace_result_t<void>::failure(std::move(strsz_value.error()));
    if (dynamic_section_index) {
        const auto& section = raw_sections_[*dynamic_section_index];
        if (section.link != shn_undef) {
            auto strings = load_string_table(section.link);
            if (!strings)
                return workspace_result_t<void>::failure(std::move(strings.error()));
            dynamic_strings_ = strings.value();
            if (strsz_value.value() && *strsz_value.value() > dynamic_strings_->bytes.size())
                return workspace_result_t<void>::failure(
                    elf_error("DT_STRSZ exceeds the linked dynamic string table",
                              "elf_dynamic"));
            if (strtab_value.value() && raw_sections_[section.link].address != 0 &&
                *strtab_value.value() != raw_sections_[section.link].address)
                return workspace_result_t<void>::failure(
                    elf_error("DT_STRTAB conflicts with the linked string table",
                              "elf_dynamic"));
        }
    }
    bool needs_strings = false;
    for (const auto& entry : raw_dynamic_) {
        if (entry.tag == dt_needed || entry.tag == dt_soname ||
            entry.tag == dt_runpath || entry.tag == dt_rpath ||
            entry.tag == dt_symtab) {
            needs_strings = true;
            break;
        }
    }
    if (dynamic_strings_ || !needs_strings)
        return workspace_result_t<void>::success();
    if (!strtab_value.value() || !strsz_value.value() || *strsz_value.value() == 0)
        return workspace_result_t<void>::failure(
            elf_error("ELF dynamic strings are not safely described", "elf_dynamic"));
    auto offset = virtual_to_file(*strtab_value.value(), *strsz_value.value(),
                                  "elf_dynamic");
    if (!offset)
        return workspace_result_t<void>::failure(std::move(offset.error()));
    auto string_charge = charge_string_bytes(*strsz_value.value(), "elf_dynamic");
    if (!string_charge)
        return string_charge;
    auto metadata_charge = charge_metadata(*strsz_value.value(), "elf_dynamic");
    if (!metadata_charge)
        return metadata_charge;
    auto bytes = provider_.read_vector(offset.value(), *strsz_value.value(),
                                       limits_.max_string_table_bytes, cancel_);
    if (!bytes)
        return workspace_result_t<void>::failure(std::move(bytes.error()));
    string_table_t table;
    table.file_offset = offset.value();
    table.bytes = bytes.take_value();
    if (table.bytes.empty() || table.bytes.front() != 0 || table.bytes.back() != 0)
        return workspace_result_t<void>::failure(
            elf_error("ELF dynamic string table is not NUL bounded", "elf_dynamic",
                      table.file_offset, table.bytes.size()));
    external_dynamic_strings_ = std::move(table);
    dynamic_strings_ = &*external_dynamic_strings_;
    return workspace_result_t<void>::success();
}

workspace_result_t<void> elf_parser_t::resolve_dynamic_names() {
    image_.dynamic_entries.reserve(raw_dynamic_.size());
    std::unordered_map<std::uint64_t, std::string> name_cache;
    name_cache.reserve(raw_dynamic_.size());
    for (std::size_t index = 0; index < raw_dynamic_.size(); ++index) {
        auto stopped = poll(index);
        if (!stopped)
            return stopped;
        const auto& raw = raw_dynamic_[index];
        elf_dynamic_entry_t entry;
        entry.tag = raw.tag;
        entry.val = raw.value;
        entry.tag_name = dynamic_tag_name(raw.tag);
        if (raw.tag == dt_needed || raw.tag == dt_soname ||
            raw.tag == dt_runpath || raw.tag == dt_rpath) {
            if (!dynamic_strings_)
                return workspace_result_t<void>::failure(
                    elf_error("ELF dynamic string tag has no string table",
                              "elf_dynamic"));
            std::string resolved_name;
            const auto cached = name_cache.find(raw.value);
            if (cached != name_cache.end()) {
                resolved_name = cached->second;
            } else {
                auto name = string_at(*dynamic_strings_, raw.value, "elf_dynamic");
                if (!name)
                    return workspace_result_t<void>::failure(std::move(name.error()));
                resolved_name = name.take_value();
                name_cache.emplace(raw.value, resolved_name);
            }
            if (resolved_name.empty())
                return workspace_result_t<void>::failure(
                    elf_error("ELF dynamic string tag resolves to an empty string",
                              "elf_dynamic"));
            constexpr std::uint64_t copies = 3;
            std::uint64_t materialized_size = 0;
            if (!checked_mul_u64(resolved_name.size(), copies, materialized_size))
                return workspace_result_t<void>::failure(limit_error(
                    "ELF materialized dynamic strings overflow", "elf_dynamic",
                    (std::numeric_limits<std::uint64_t>::max)(),
                    limits_.max_materialized_string_bytes));
            auto name_budget = charge_materialized_string(materialized_size,
                                                           "elf_dynamic");
            if (!name_budget)
                return name_budget;
            if (raw.tag == dt_needed) {
                entry.needed_name = resolved_name;
                image_.needed_libraries.push_back(resolved_name);
            } else if (raw.tag == dt_soname) {
                if (image_.soname && *image_.soname != resolved_name)
                    return workspace_result_t<void>::failure(
                        elf_error("ELF has conflicting SONAME values", "elf_dynamic"));
                entry.soname = resolved_name;
                image_.soname = resolved_name;
            } else if (raw.tag == dt_runpath) {
                if (image_.runpath && *image_.runpath != resolved_name)
                    return workspace_result_t<void>::failure(
                        elf_error("ELF has conflicting RUNPATH values", "elf_dynamic"));
                entry.runpath = resolved_name;
                image_.runpath = resolved_name;
            } else {
                if (image_.rpath && *image_.rpath != resolved_name)
                    return workspace_result_t<void>::failure(
                        elf_error("ELF has conflicting RPATH values", "elf_dynamic"));
                entry.rpath = resolved_name;
                image_.rpath = resolved_name;
            }
        }
        image_.dynamic_entries.push_back(std::move(entry));
    }
    std::sort(image_.needed_libraries.begin(), image_.needed_libraries.end());
    image_.needed_libraries.erase(
        std::unique(image_.needed_libraries.begin(), image_.needed_libraries.end()),
        image_.needed_libraries.end());
    return workspace_result_t<void>::success();
}

workspace_result_t<std::optional<std::uint64_t>>
elf_parser_t::sysv_hash_symbol_count(std::uint64_t address) {
    auto window = virtual_file_window(address, "elf_hash");
    if (!window)
        return workspace_result_t<std::optional<std::uint64_t>>::failure(
            std::move(window.error()));
    if (window.value().second < 8)
        return workspace_result_t<std::optional<std::uint64_t>>::failure(
            elf_error("ELF SysV hash header is truncated", "elf_hash",
                      window.value().first, window.value().second));
    std::array<std::uint8_t, 8> header{};
    auto read = read_exact(window.value().first, header.data(), header.size(), "elf_hash");
    if (!read)
        return workspace_result_t<std::optional<std::uint64_t>>::failure(
            std::move(read.error()));
    const auto buckets = reader_.u32(header.data());
    const auto chains = reader_.u32(header.data() + 4);
    if (buckets == 0 || chains == 0)
        return workspace_result_t<std::optional<std::uint64_t>>::failure(
            elf_error("ELF SysV hash dimensions are invalid", "elf_hash",
                      window.value().first, header.size()));
    std::uint64_t words = 0;
    std::uint64_t bytes = 0;
    if (!checked_add_u64(2, buckets, words) ||
        !checked_add_u64(words, chains, words) ||
        !checked_mul_u64(words, 4, bytes) || bytes > window.value().second)
        return workspace_result_t<std::optional<std::uint64_t>>::failure(
            elf_error("ELF SysV hash table is truncated or overflows", "elf_hash",
                      window.value().first, window.value().second));
    auto charged = charge_metadata(bytes, "elf_hash");
    if (!charged)
        return workspace_result_t<std::optional<std::uint64_t>>::failure(
            std::move(charged.error()));
    return workspace_result_t<std::optional<std::uint64_t>>::success(chains);
}

workspace_result_t<std::optional<std::uint64_t>>
elf_parser_t::gnu_hash_symbol_count(std::uint64_t address) {
    auto window = virtual_file_window(address, "elf_gnu_hash");
    if (!window)
        return workspace_result_t<std::optional<std::uint64_t>>::failure(
            std::move(window.error()));
    if (window.value().second < 16)
        return workspace_result_t<std::optional<std::uint64_t>>::failure(
            elf_error("ELF GNU hash header is truncated", "elf_gnu_hash",
                      window.value().first, window.value().second));
    std::array<std::uint8_t, 16> header{};
    auto read = read_exact(window.value().first, header.data(), header.size(),
                           "elf_gnu_hash");
    if (!read)
        return workspace_result_t<std::optional<std::uint64_t>>::failure(
            std::move(read.error()));
    const auto bucket_count = reader_.u32(header.data());
    const auto symbol_offset = reader_.u32(header.data() + 4);
    const auto bloom_count = reader_.u32(header.data() + 8);
    if (bucket_count == 0 || bloom_count == 0)
        return workspace_result_t<std::optional<std::uint64_t>>::failure(
            elf_error("ELF GNU hash dimensions are invalid", "elf_gnu_hash",
                      window.value().first, header.size()));
    std::uint64_t bloom_bytes = 0;
    std::uint64_t bucket_bytes = 0;
    std::uint64_t prefix_bytes = 0;
    if (!checked_mul_u64(bloom_count, pointer_size(), bloom_bytes) ||
        !checked_mul_u64(bucket_count, 4, bucket_bytes) ||
        !checked_add_u64(16, bloom_bytes, prefix_bytes) ||
        !checked_add_u64(prefix_bytes, bucket_bytes, prefix_bytes) ||
        prefix_bytes > window.value().second)
        return workspace_result_t<std::optional<std::uint64_t>>::failure(
            elf_error("ELF GNU hash prefix is truncated or overflows", "elf_gnu_hash",
                      window.value().first, window.value().second));
    auto charged = charge_metadata(prefix_bytes, "elf_gnu_hash");
    if (!charged)
        return workspace_result_t<std::optional<std::uint64_t>>::failure(
            std::move(charged.error()));
    const auto buckets_offset = window.value().first + 16 + bloom_bytes;
    std::uint32_t maximum_bucket = 0;
    std::array<std::uint8_t, 4> word{};
    for (std::uint32_t index = 0; index < bucket_count; ++index) {
        auto stopped = poll(index);
        if (!stopped)
            return workspace_result_t<std::optional<std::uint64_t>>::failure(
                std::move(stopped.error()));
        auto bucket_read = read_exact(buckets_offset + static_cast<std::uint64_t>(index) * 4,
                                      word.data(), word.size(), "elf_gnu_hash");
        if (!bucket_read)
            return workspace_result_t<std::optional<std::uint64_t>>::failure(
                std::move(bucket_read.error()));
        const auto bucket = reader_.u32(word.data());
        if (bucket != 0 && bucket < symbol_offset)
            return workspace_result_t<std::optional<std::uint64_t>>::failure(
                elf_error("ELF GNU hash bucket precedes its symbol offset",
                          "elf_gnu_hash"));
        maximum_bucket = (std::max)(maximum_bucket, bucket);
    }
    if (maximum_bucket == 0)
        return workspace_result_t<std::optional<std::uint64_t>>::success(symbol_offset);
    const auto chains_offset = buckets_offset + bucket_bytes;
    std::uint64_t symbol_index = maximum_bucket;
    for (;;) {
        if (symbol_index >= limits_.max_symbols)
            return workspace_result_t<std::optional<std::uint64_t>>::failure(limit_error(
                "ELF GNU hash symbol count exceeds its budget", "elf_gnu_hash",
                symbol_index + 1, limits_.max_symbols));
        std::uint64_t chain_delta = 0;
        if (!checked_mul_u64(symbol_index - symbol_offset, 4, chain_delta) ||
            chain_delta > window.value().second - prefix_bytes ||
            window.value().second - prefix_bytes - chain_delta < 4)
            return workspace_result_t<std::optional<std::uint64_t>>::failure(
                elf_error("ELF GNU hash chain is truncated or overflows",
                          "elf_gnu_hash"));
        auto chain_charge = charge_metadata(4, "elf_gnu_hash");
        if (!chain_charge)
            return workspace_result_t<std::optional<std::uint64_t>>::failure(
                std::move(chain_charge.error()));
        auto chain_read = read_exact(chains_offset + chain_delta, word.data(), word.size(),
                                     "elf_gnu_hash");
        if (!chain_read)
            return workspace_result_t<std::optional<std::uint64_t>>::failure(
                std::move(chain_read.error()));
        const auto chain = reader_.u32(word.data());
        ++symbol_index;
        if ((chain & 1U) != 0)
            break;
    }
    return workspace_result_t<std::optional<std::uint64_t>>::success(symbol_index);
}

workspace_result_t<void> elf_parser_t::parse_dynamic_symbols() {
    if (dynamic_symbol_table_index_) {
        const auto* parsed_table = symbol_table(*dynamic_symbol_table_index_);
        if (!parsed_table)
            return workspace_result_t<void>::failure(
                elf_error("ELF dynamic symbol table state is inconsistent",
                          "elf_symbols"));
        auto symtab = dynamic_value(dt_symtab);
        if (!symtab)
            return workspace_result_t<void>::failure(std::move(symtab.error()));
        auto syment = dynamic_value(dt_syment);
        if (!syment)
            return workspace_result_t<void>::failure(std::move(syment.error()));
        if (parsed_table->section_index != invalid_section_index) {
            const auto& section = raw_sections_[parsed_table->section_index];
            if (syment.value() && *syment.value() != section.entry_size)
                return workspace_result_t<void>::failure(
                    elf_error("DT_SYMENT conflicts with SHT_DYNSYM", "elf_symbols"));
            if (symtab.value()) {
                if (section.address != 0 && *symtab.value() != section.address)
                    return workspace_result_t<void>::failure(
                        elf_error("DT_SYMTAB conflicts with SHT_DYNSYM", "elf_symbols"));
                if (section.address == 0) {
                    auto offset = virtual_to_file(*symtab.value(), section.size,
                                                  "elf_symbols");
                    if (!offset || offset.value() != section.offset)
                        return workspace_result_t<void>::failure(
                            elf_error("DT_SYMTAB file mapping conflicts with SHT_DYNSYM",
                                      "elf_symbols"));
                }
            }
        }
        std::optional<std::uint64_t> hash_count;
        auto hash = dynamic_value(dt_hash);
        if (!hash)
            return workspace_result_t<void>::failure(std::move(hash.error()));
        if (hash.value()) {
            auto count = sysv_hash_symbol_count(*hash.value());
            if (!count)
                return workspace_result_t<void>::failure(std::move(count.error()));
            hash_count = count.value();
        }
        auto gnu_hash = dynamic_value(dt_gnu_hash);
        if (!gnu_hash)
            return workspace_result_t<void>::failure(std::move(gnu_hash.error()));
        if (gnu_hash.value()) {
            auto count = gnu_hash_symbol_count(*gnu_hash.value());
            if (!count)
                return workspace_result_t<void>::failure(std::move(count.error()));
            if (hash_count && count.value() && *hash_count != *count.value())
                return workspace_result_t<void>::failure(
                    elf_error("ELF SysV and GNU hash symbol counts disagree",
                              "elf_symbols"));
            if (!hash_count)
                hash_count = count.value();
        }
        if (hash_count && *hash_count != parsed_table->symbols.size())
            return workspace_result_t<void>::failure(
                elf_error("ELF hash symbol count conflicts with SHT_DYNSYM",
                          "elf_symbols"));
        return workspace_result_t<void>::success();
    }
    auto symtab = dynamic_value(dt_symtab);
    if (!symtab)
        return workspace_result_t<void>::failure(std::move(symtab.error()));
    if (!symtab.value())
        return workspace_result_t<void>::success();
    if (!dynamic_strings_)
        return workspace_result_t<void>::failure(
            elf_error("DT_SYMTAB has no dynamic string table", "elf_symbols"));
    auto syment = dynamic_value(dt_syment);
    if (!syment)
        return workspace_result_t<void>::failure(std::move(syment.error()));
    const auto entry_size = syment.value().value_or(native_symbol_size());
    if (entry_size < native_symbol_size())
        return workspace_result_t<void>::failure(
            elf_error("DT_SYMENT is smaller than the ELF symbol record",
                      "elf_symbols"));
    std::optional<std::uint64_t> count;
    auto hash = dynamic_value(dt_hash);
    if (!hash)
        return workspace_result_t<void>::failure(std::move(hash.error()));
    if (hash.value()) {
        auto parsed = sysv_hash_symbol_count(*hash.value());
        if (!parsed)
            return workspace_result_t<void>::failure(std::move(parsed.error()));
        count = parsed.value();
    }
    auto gnu_hash = dynamic_value(dt_gnu_hash);
    if (!gnu_hash)
        return workspace_result_t<void>::failure(std::move(gnu_hash.error()));
    if (gnu_hash.value()) {
        auto parsed = gnu_hash_symbol_count(*gnu_hash.value());
        if (!parsed)
            return workspace_result_t<void>::failure(std::move(parsed.error()));
        if (count && parsed.value() && *count != *parsed.value())
            return workspace_result_t<void>::failure(
                elf_error("ELF SysV and GNU hash symbol counts disagree",
                          "elf_symbols"));
        if (!count)
            count = parsed.value();
    }
    auto strtab = dynamic_value(dt_strtab);
    if (!strtab)
        return workspace_result_t<void>::failure(std::move(strtab.error()));
    if (!count && strtab.value() && *strtab.value() > *symtab.value()) {
        const auto distance = *strtab.value() - *symtab.value();
        if (distance % entry_size == 0)
            count = distance / entry_size;
    }
    if (!count || *count == 0)
        return workspace_result_t<void>::failure(
            elf_error("ELF dynamic symbol table cannot be safely bounded",
                      "elf_symbols"));
    if (*count > limits_.max_symbols - symbol_count_)
        return workspace_result_t<void>::failure(limit_error(
            "ELF dynamic symbol count exceeds its budget", "elf_symbols",
            symbol_count_ + *count, limits_.max_symbols));
    std::uint64_t table_size = 0;
    if (!checked_mul_u64(*count, entry_size, table_size))
        return workspace_result_t<void>::failure(
            elf_error("ELF dynamic symbol table size overflows", "elf_symbols"));
    auto offset = virtual_to_file(*symtab.value(), table_size, "elf_symbols");
    if (!offset)
        return workspace_result_t<void>::failure(std::move(offset.error()));
    auto parsed = parse_symbol_table(invalid_section_index, offset.value(), entry_size,
                                     *count, *dynamic_strings_, true);
    if (!parsed)
        return workspace_result_t<void>::failure(std::move(parsed.error()));
    dynamic_symbol_table_index_ = parsed.value();
    return workspace_result_t<void>::success();
}

const parsed_symbol_table_t* elf_parser_t::symbol_table(std::size_t index) const noexcept {
    if (index >= symbol_tables_.size())
        return nullptr;
    return &symbol_tables_[index];
}

const elf_symbol_t* elf_parser_t::relocation_symbol(
    const elf_relocation_t& relocation) const noexcept {
    if (!relocation.symbol_table_section_index)
        return nullptr;
    const auto section_index = *relocation.symbol_table_section_index;
    std::size_t table_index = invalid_symbol_table_index;
    if (section_index == invalid_section_index) {
        table_index = dynamic_symbol_table_index_.value_or(invalid_symbol_table_index);
    } else if (section_index < symbol_table_lookup_.size() &&
               symbol_table_lookup_[section_index] >= 0) {
        table_index = static_cast<std::size_t>(symbol_table_lookup_[section_index]);
    }
    const auto* table = symbol_table(table_index);
    if (!table || relocation.sym >= table->symbols.size())
        return nullptr;
    return &table->symbols[relocation.sym];
}

workspace_result_t<void> elf_parser_t::parse_relocation_range(
    std::uint64_t file_offset, std::uint64_t size, std::uint64_t entry_size,
    bool has_addend, bool is_plt, std::string section_name,
    std::optional<std::uint32_t> relocation_section_index,
    std::size_t symbol_table_index,
    std::optional<std::uint32_t> target_section_index) {
    const auto required = native_rel_size(has_addend);
    if (entry_size < required || size % entry_size != 0)
        return workspace_result_t<void>::failure(
            elf_error("ELF relocation table entry layout is invalid",
                      "elf_relocations", file_offset, size));
    auto span_result = file_span(file_offset, size, "elf_relocations");
    if (!span_result)
        return workspace_result_t<void>::failure(std::move(span_result.error()));
    const auto span = span_result.value();
    if (!relocation_section_index) {
        for (auto& existing : relocation_spans_) {
            if (!existing.span.overlaps(span))
                continue;
            if (existing.span.offset == span.offset && existing.span.size == span.size &&
                existing.has_addend == has_addend &&
                existing.symbol_table_index == symbol_table_index &&
                existing.target_section_index == target_section_index) {
                if (is_plt) {
                    const auto end = existing.first_relocation + existing.relocation_count;
                    for (std::size_t index = existing.first_relocation; index < end; ++index)
                        image_.relocations[index].is_plt = true;
                }
                return workspace_result_t<void>::success();
            }
            return workspace_result_t<void>::failure(
                elf_error("ELF relocation tables overlap inconsistently",
                          "elf_relocations", file_offset, size));
        }
    }
    const auto count = size / entry_size;
    if (count > limits_.max_relocations - relocation_count_)
        return workspace_result_t<void>::failure(limit_error(
            "ELF relocation count exceeds its budget", "elf_relocations",
            relocation_count_ + count, limits_.max_relocations));
    const auto* symbols = symbol_table(symbol_table_index);
    if (!symbols && symbol_table_index != invalid_symbol_table_index)
        return workspace_result_t<void>::failure(
            elf_error("ELF relocation symbol table is unavailable", "elf_relocations"));
    if (target_section_index && *target_section_index >= raw_sections_.size())
        return workspace_result_t<void>::failure(
            elf_error("ELF relocation target section is out of range",
                      "elf_relocations"));
    auto charged = charge_metadata(size, "elf_relocations");
    if (!charged)
        return charged;
    relocation_span_t parsed_span;
    parsed_span.span = span;
    parsed_span.has_addend = has_addend;
    parsed_span.symbol_table_index = symbol_table_index;
    parsed_span.target_section_index = target_section_index;
    parsed_span.first_relocation = image_.relocations.size();
    parsed_span.relocation_count = static_cast<std::size_t>(count);
    std::array<std::uint8_t, sizeof(elf64_rela_t)> bytes{};
    for (std::uint64_t index = 0; index < count; ++index) {
        auto stopped = poll(index);
        if (!stopped)
            return stopped;
        std::uint64_t delta = 0;
        std::uint64_t offset = 0;
        if (!checked_mul_u64(index, entry_size, delta) ||
            !checked_add_u64(file_offset, delta, offset))
            return workspace_result_t<void>::failure(
                elf_error("ELF relocation entry offset overflows", "elf_relocations"));
        auto read = read_exact(offset, bytes.data(), required, "elf_relocations");
        if (!read)
            return read;
        elf_relocation_t relocation;
        if (header_.is_64) {
            relocation.offset = reader_.u64(bytes.data());
            relocation.info = reader_.u64(bytes.data() + 8);
            if (has_addend)
                relocation.addend = reader_.i64(bytes.data() + 16);
            relocation.sym = static_cast<std::uint32_t>(relocation.info >> 32);
            relocation.type = static_cast<std::uint32_t>(relocation.info);
        } else {
            relocation.offset = reader_.u32(bytes.data());
            relocation.info = reader_.u32(bytes.data() + 4);
            if (has_addend)
                relocation.addend = reader_.i32(bytes.data() + 8);
            relocation.sym = static_cast<std::uint32_t>(relocation.info >> 8);
            relocation.type = static_cast<std::uint32_t>(relocation.info & 0xff);
        }
        if (relocation.sym != 0 &&
            (!symbols || relocation.sym >= symbols->symbols.size()))
            return workspace_result_t<void>::failure(
                elf_error("ELF relocation symbol index is out of range",
                          "elf_relocations", offset, required));
        if (header_.type == et_rel && target_section_index && relocation.type != 0) {
            const auto& target = raw_sections_[*target_section_index];
            if (target.size == 0 || relocation.offset >= target.size)
                return workspace_result_t<void>::failure(
                    elf_error("relocatable ELF relocation offset exceeds its target section",
                              "elf_relocations", offset, required));
        } else if (header_.type != et_rel && relocation.type != 0 &&
                   !virtual_to_rva(relocation.offset)) {
            return workspace_result_t<void>::failure(
                elf_error("ELF relocation address lies outside the load image",
                          "elf_relocations", offset, required));
        }
        std::uint64_t materialized_size = section_name.size();
        if (symbols && relocation.sym < symbols->symbols.size()) {
            if (!checked_add_u64(materialized_size,
                                 symbols->symbols[relocation.sym].name.size(),
                                 materialized_size))
                return workspace_result_t<void>::failure(limit_error(
                    "ELF relocation string materialization overflows",
                    "elf_relocations",
                    (std::numeric_limits<std::uint64_t>::max)(),
                    limits_.max_materialized_string_bytes));
        }
        auto string_budget = charge_materialized_string(materialized_size,
                                                        "elf_relocations");
        if (!string_budget)
            return string_budget;
        relocation.has_addend = has_addend;
        relocation.is_plt = is_plt;
        relocation.section_name = section_name;
        relocation.relocation_section_index = relocation_section_index;
        relocation.target_section_index = target_section_index;
        if (symbols) {
            relocation.symbol_table_section_index = symbols->section_index;
            if (relocation.sym < symbols->symbols.size() &&
                !symbols->symbols[relocation.sym].name.empty())
                relocation.symbol_name = symbols->symbols[relocation.sym].name;
        }
        image_.relocations.push_back(std::move(relocation));
    }
    relocation_count_ += count;
    relocation_spans_.push_back(parsed_span);
    return workspace_result_t<void>::success();
}

workspace_result_t<void> elf_parser_t::parse_relocation_sections() {
    for (const auto& section : raw_sections_) {
        if (section.type != sht_rel && section.type != sht_rela)
            continue;
        auto stopped = poll(section.index);
        if (!stopped)
            return stopped;
        if (section.link >= symbol_table_lookup_.size() ||
            symbol_table_lookup_[section.link] < 0)
            return workspace_result_t<void>::failure(
                elf_error("ELF relocation section references an unparsed symbol table",
                          "elf_relocations", section.offset, section.size));
        const auto has_addend = section.type == sht_rela;
        const auto entry_size = section.entry_size == 0
                                    ? native_rel_size(has_addend)
                                    : section.entry_size;
        const auto name = image_.sections[section.index].name;
        const bool is_plt = name.find(".plt") != std::string::npos ||
                            name.find(".iplt") != std::string::npos;
        std::optional<std::uint32_t> target;
        if (section.info != shn_undef)
            target = section.info;
        auto parsed = parse_relocation_range(
            section.offset, section.size, entry_size, has_addend, is_plt, name,
            section.index, static_cast<std::size_t>(symbol_table_lookup_[section.link]),
            target);
        if (!parsed)
            return parsed;
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<void> elf_parser_t::parse_dynamic_relocations() {
    const auto table_index = dynamic_symbol_table_index_.value_or(
        invalid_symbol_table_index);
    const auto parse_family = [this, table_index](
        std::int64_t address_tag, std::int64_t size_tag, std::int64_t entry_tag,
        bool has_addend, bool is_plt, const char* name) -> workspace_result_t<void> {
        auto address = dynamic_value(address_tag);
        if (!address)
            return workspace_result_t<void>::failure(std::move(address.error()));
        auto size = dynamic_value(size_tag);
        if (!size)
            return workspace_result_t<void>::failure(std::move(size.error()));
        if (!address.value() && !size.value())
            return workspace_result_t<void>::success();
        if (!address.value() || !size.value())
            return workspace_result_t<void>::failure(
                elf_error("ELF dynamic relocation tags are incomplete",
                          "elf_relocations"));
        if (*size.value() == 0)
            return workspace_result_t<void>::success();
        auto entry = dynamic_value(entry_tag);
        if (!entry)
            return workspace_result_t<void>::failure(std::move(entry.error()));
        const auto stride = entry.value().value_or(native_rel_size(has_addend));
        if (stride < native_rel_size(has_addend))
            return workspace_result_t<void>::failure(
                elf_error("ELF dynamic relocation entry size is too small",
                          "elf_relocations"));
        auto offset = virtual_to_file(*address.value(), *size.value(),
                                      "elf_relocations");
        if (!offset)
            return workspace_result_t<void>::failure(std::move(offset.error()));
        return parse_relocation_range(offset.value(), *size.value(), stride,
                                      has_addend, is_plt, name, std::nullopt,
                                      table_index, std::nullopt);
    };
    auto rela = parse_family(dt_rela, dt_relasz, dt_relaent, true, false, "DT_RELA");
    if (!rela)
        return rela;
    auto rel = parse_family(dt_rel, dt_relsz, dt_relent, false, false, "DT_REL");
    if (!rel)
        return rel;
    auto jmprel = dynamic_value(dt_jmprel);
    if (!jmprel)
        return workspace_result_t<void>::failure(std::move(jmprel.error()));
    auto pltrelsz = dynamic_value(dt_pltrelsz);
    if (!pltrelsz)
        return workspace_result_t<void>::failure(std::move(pltrelsz.error()));
    if (!jmprel.value() && !pltrelsz.value())
        return workspace_result_t<void>::success();
    if (!jmprel.value() || !pltrelsz.value())
        return workspace_result_t<void>::failure(
            elf_error("ELF PLT relocation tags are incomplete", "elf_relocations"));
    if (*pltrelsz.value() == 0)
        return workspace_result_t<void>::success();
    auto pltrel = dynamic_value(dt_pltrel);
    if (!pltrel)
        return workspace_result_t<void>::failure(std::move(pltrel.error()));
    if (!pltrel.value() ||
        (*pltrel.value() != static_cast<std::uint64_t>(dt_rel) &&
         *pltrel.value() != static_cast<std::uint64_t>(dt_rela)))
        return workspace_result_t<void>::failure(
            elf_error("ELF DT_PLTREL has an invalid relocation encoding",
                      "elf_relocations"));
    const bool has_addend = *pltrel.value() == static_cast<std::uint64_t>(dt_rela);
    auto entry = dynamic_value(has_addend ? dt_relaent : dt_relent);
    if (!entry)
        return workspace_result_t<void>::failure(std::move(entry.error()));
    const auto stride = entry.value().value_or(native_rel_size(has_addend));
    auto offset = virtual_to_file(*jmprel.value(), *pltrelsz.value(),
                                  "elf_relocations");
    if (!offset)
        return workspace_result_t<void>::failure(std::move(offset.error()));
    return parse_relocation_range(offset.value(), *pltrelsz.value(), stride,
                                  has_addend, true, "DT_JMPREL", std::nullopt,
                                  table_index, std::nullopt);
}

workspace_result_t<void> elf_parser_t::parse_note_span(
    const checked_span_t& span, std::string section_name) {
    auto charged = charge_metadata(span.size, "elf_notes");
    if (!charged)
        return charged;
    std::uint64_t cursor = span.offset;
    const auto span_end = span.offset + span.size;
    while (cursor < span_end) {
        auto stopped = poll(note_count_);
        if (!stopped)
            return stopped;
        const auto remaining = span_end - cursor;
        if (remaining < sizeof(elf_nhdr_t)) {
            std::array<std::uint8_t, sizeof(elf_nhdr_t)> tail{};
            auto read = read_exact(cursor, tail.data(), remaining, "elf_notes");
            if (!read)
                return read;
            if (std::any_of(tail.begin(), tail.begin() + static_cast<std::ptrdiff_t>(remaining),
                            [](std::uint8_t value) { return value != 0; }))
                return workspace_result_t<void>::failure(
                    elf_error("ELF note table has a nonzero truncated tail", "elf_notes",
                              cursor, remaining));
            break;
        }
        std::array<std::uint8_t, sizeof(elf_nhdr_t)> header{};
        auto read = read_exact(cursor, header.data(), header.size(), "elf_notes");
        if (!read)
            return read;
        const auto name_size = reader_.u32(header.data());
        const auto descriptor_size = reader_.u32(header.data() + 4);
        const auto type = reader_.u32(header.data() + 8);
        std::uint64_t aligned_name = 0;
        std::uint64_t aligned_descriptor = 0;
        std::uint64_t record_size = 0;
        if (!align_up(name_size, 4, aligned_name) ||
            !align_up(descriptor_size, 4, aligned_descriptor) ||
            !checked_add_u64(sizeof(elf_nhdr_t), aligned_name, record_size) ||
            !checked_add_u64(record_size, aligned_descriptor, record_size) ||
            record_size > remaining)
            return workspace_result_t<void>::failure(
                elf_error("ELF note record is truncated or overflows", "elf_notes",
                          cursor, remaining));
        const auto note_position = std::lower_bound(note_offsets_.begin(),
                                                    note_offsets_.end(), cursor);
        const bool duplicate = note_position != note_offsets_.end() &&
                               *note_position == cursor;
        if (!duplicate) {
            if (note_count_ >= limits_.max_notes)
                return workspace_result_t<void>::failure(limit_error(
                    "ELF note count exceeds its budget", "elf_notes", note_count_ + 1,
                    limits_.max_notes));
            auto name_charge = charge_string_bytes(name_size, "elf_notes");
            if (!name_charge)
                return name_charge;
            auto name_materialized = charge_materialized_string(name_size, "elf_notes");
            if (!name_materialized)
                return name_materialized;
            std::vector<std::uint8_t> name_bytes;
            if (name_size != 0) {
                auto name = provider_.read_vector(cursor + sizeof(elf_nhdr_t), name_size,
                                                  limits_.max_string_table_bytes, cancel_);
                if (!name)
                    return workspace_result_t<void>::failure(std::move(name.error()));
                name_bytes = name.take_value();
            }
            std::string name;
            if (!name_bytes.empty()) {
                const auto terminator = std::find(name_bytes.begin(), name_bytes.end(),
                                                  static_cast<std::uint8_t>(0));
                if (terminator != name_bytes.end() &&
                    std::any_of(terminator, name_bytes.end(),
                                [](std::uint8_t value) { return value != 0; }))
                    return workspace_result_t<void>::failure(
                        elf_error("ELF note name contains data after its terminator",
                                  "elf_notes", cursor + sizeof(elf_nhdr_t), name_size));
                const auto length = terminator == name_bytes.end()
                                        ? name_bytes.size()
                                        : static_cast<std::size_t>(terminator - name_bytes.begin());
                name.assign(reinterpret_cast<const char*>(name_bytes.data()), length);
            }
            std::vector<std::uint8_t> descriptor;
            if (descriptor_size != 0) {
                const auto descriptor_offset = cursor + sizeof(elf_nhdr_t) + aligned_name;
                auto bytes = provider_.read_vector(descriptor_offset, descriptor_size,
                                                   limits_.max_total_metadata_bytes, cancel_);
                if (!bytes)
                    return workspace_result_t<void>::failure(std::move(bytes.error()));
                descriptor = bytes.take_value();
            }
            elf_note_t note;
            note.type = type;
            note.name = std::move(name);
            note.descriptor = std::move(descriptor);
            note.section_name = section_name;
            note.file_offset = cursor;
            note.is_build_id = note.name == "GNU" && type == nt_gnu_build_id;
            note.is_abi_tag = note.name == "GNU" && type == nt_gnu_abi_tag;
            note.is_version = note.name != "GNU" && type == nt_version;
            note.is_gnu_property = note.name == "GNU" &&
                                   type == nt_gnu_property_type_0;
            if (note.is_build_id) {
                if (note.descriptor.empty() || note.descriptor.size() > 4096)
                    return workspace_result_t<void>::failure(
                        elf_error("ELF GNU build ID has an invalid size", "elf_notes",
                                  cursor, record_size));
                static constexpr char hex[] = "0123456789abcdef";
                std::string encoded;
                encoded.resize(note.descriptor.size() * 2);
                for (std::size_t index = 0; index < note.descriptor.size(); ++index) {
                    encoded[index * 2] = hex[note.descriptor[index] >> 4];
                    encoded[index * 2 + 1] = hex[note.descriptor[index] & 0x0f];
                }
                note.build_id_hex = std::move(encoded);
                auto build_id_budget = charge_materialized_string(
                    note.build_id_hex->size(), "elf_notes");
                if (!build_id_budget)
                    return build_id_budget;
            }
            note_offsets_.insert(note_position, cursor);
            image_.notes.push_back(std::move(note));
            ++note_count_;
        }
        cursor += record_size;
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<void> elf_parser_t::parse_notes() {
    std::vector<std::pair<checked_span_t, std::string>> spans;
    for (const auto& section : raw_sections_) {
        if (section.type == sht_note && section.file_span)
            spans.emplace_back(*section.file_span, image_.sections[section.index].name);
    }
    for (const auto& segment : raw_segments_) {
        if (segment.type == pt_note && segment.file_span)
            spans.emplace_back(*segment.file_span, "PT_NOTE");
    }
    std::sort(spans.begin(), spans.end(), [](const auto& left, const auto& right) {
        return std::tie(left.first.offset, left.first.size, left.second) <
               std::tie(right.first.offset, right.first.size, right.second);
    });
    spans.erase(std::unique(spans.begin(), spans.end(), [](const auto& left, const auto& right) {
                    return left.first.offset == right.first.offset &&
                           left.first.size == right.first.size;
                }),
                spans.end());
    for (auto& span : spans) {
        auto parsed = parse_note_span(span.first, std::move(span.second));
        if (!parsed)
            return parsed;
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<void> elf_parser_t::parse_pointer_array(
    std::uint64_t file_offset, std::uint64_t size, bool is_init,
    bool is_fini, bool is_preinit) {
    if (size % pointer_size() != 0)
        return workspace_result_t<void>::failure(
            elf_error("ELF initializer array has a partial pointer", "elf_init_fini",
                      file_offset, size));
    const auto count = size / pointer_size();
    if (count > limits_.max_init_fini_entries - init_fini_count_)
        return workspace_result_t<void>::failure(limit_error(
            "ELF initializer/finalizer count exceeds its budget", "elf_init_fini",
            init_fini_count_ + count, limits_.max_init_fini_entries));
    auto span = file_span(file_offset, size, "elf_init_fini");
    if (!span)
        return workspace_result_t<void>::failure(std::move(span.error()));
    auto charged = charge_metadata(size, "elf_init_fini");
    if (!charged)
        return charged;
    std::array<std::uint8_t, 8> bytes{};
    const auto sentinel = header_.is_64
                              ? (std::numeric_limits<std::uint64_t>::max)()
                              : static_cast<std::uint64_t>(
                                    (std::numeric_limits<std::uint32_t>::max)());
    for (std::uint64_t index = 0; index < count; ++index) {
        auto stopped = poll(index);
        if (!stopped)
            return stopped;
        const auto offset = file_offset + index * pointer_size();
        auto read = read_exact(offset, bytes.data(), pointer_size(), "elf_init_fini");
        if (!read)
            return read;
        const auto address = header_.is_64 ? reader_.u64(bytes.data())
                                           : reader_.u32(bytes.data());
        if (address == 0 || address == sentinel)
            continue;
        elf_init_fini_entry_t entry;
        entry.address = address;
        entry.index = static_cast<std::uint32_t>(index);
        entry.is_init = is_init;
        entry.is_fini = is_fini;
        entry.is_preinit = is_preinit;
        image_.init_fini_entries.push_back(entry);
    }
    init_fini_count_ += count;
    return workspace_result_t<void>::success();
}

bool elf_parser_t::dynamic_range_matches_section(
    std::uint32_t type, std::uint64_t address, std::uint64_t size) const noexcept {
    for (const auto& section : raw_sections_) {
        if (section.type != type || section.address != address || section.size != size)
            continue;
        return true;
    }
    return false;
}

workspace_result_t<void> elf_parser_t::parse_init_fini() {
    for (const auto& section : raw_sections_) {
        const bool is_init = section.type == sht_init_array;
        const bool is_fini = section.type == sht_fini_array;
        const bool is_preinit = section.type == sht_preinit_array;
        if (!is_init && !is_fini && !is_preinit)
            continue;
        if (section.type == sht_nobits || !section.file_span)
            return workspace_result_t<void>::failure(
                elf_error("ELF initializer array is not file backed", "elf_init_fini",
                          section.offset, section.size));
        auto parsed = parse_pointer_array(section.offset, section.size,
                                          is_init, is_fini, is_preinit);
        if (!parsed)
            return parsed;
    }
    const auto parse_dynamic_array = [this](
        std::int64_t address_tag, std::int64_t size_tag, std::uint32_t section_type,
        bool is_init, bool is_fini, bool is_preinit) -> workspace_result_t<void> {
        auto address = dynamic_value(address_tag);
        if (!address)
            return workspace_result_t<void>::failure(std::move(address.error()));
        auto size = dynamic_value(size_tag);
        if (!size)
            return workspace_result_t<void>::failure(std::move(size.error()));
        if (!address.value() && !size.value())
            return workspace_result_t<void>::success();
        if (!address.value() || !size.value())
            return workspace_result_t<void>::failure(
                elf_error("ELF dynamic initializer-array tags are incomplete",
                          "elf_init_fini"));
        if (*size.value() == 0)
            return workspace_result_t<void>::success();
        if (dynamic_range_matches_section(section_type, *address.value(), *size.value()))
            return workspace_result_t<void>::success();
        auto offset = virtual_to_file(*address.value(), *size.value(), "elf_init_fini");
        if (!offset)
            return workspace_result_t<void>::failure(std::move(offset.error()));
        return parse_pointer_array(offset.value(), *size.value(),
                                   is_init, is_fini, is_preinit);
    };
    auto preinit = parse_dynamic_array(dt_preinit_array, dt_preinit_arraysz,
                                       sht_preinit_array, false, false, true);
    if (!preinit)
        return preinit;
    auto init_array = parse_dynamic_array(dt_init_array, dt_init_arraysz,
                                          sht_init_array, true, false, false);
    if (!init_array)
        return init_array;
    auto fini_array = parse_dynamic_array(dt_fini_array, dt_fini_arraysz,
                                          sht_fini_array, false, true, false);
    if (!fini_array)
        return fini_array;
    const auto add_single = [this](std::int64_t tag, bool is_init,
                                   bool is_fini) -> workspace_result_t<void> {
        auto address = dynamic_value(tag);
        if (!address)
            return workspace_result_t<void>::failure(std::move(address.error()));
        if (!address.value() || *address.value() == 0)
            return workspace_result_t<void>::success();
        if (init_fini_count_ >= limits_.max_init_fini_entries)
            return workspace_result_t<void>::failure(limit_error(
                "ELF initializer/finalizer count exceeds its budget", "elf_init_fini",
                init_fini_count_ + 1, limits_.max_init_fini_entries));
        elf_init_fini_entry_t entry;
        entry.address = *address.value();
        entry.is_init = is_init;
        entry.is_fini = is_fini;
        image_.init_fini_entries.push_back(entry);
        ++init_fini_count_;
        return workspace_result_t<void>::success();
    };
    auto init = add_single(dt_init, true, false);
    if (!init)
        return init;
    auto fini = add_single(dt_fini, false, true);
    if (!fini)
        return fini;
    return workspace_result_t<void>::success();
}

workspace_result_t<void> elf_parser_t::build_plt_got_facts() {
    std::vector<std::size_t> plt_sec_candidates;
    std::vector<std::size_t> plt_candidates;
    const auto add_fact = [this](elf_plt_got_entry_t fact) -> workspace_result_t<void> {
        if (plt_got_count_ >= limits_.max_plt_got_entries)
            return workspace_result_t<void>::failure(limit_error(
                "ELF PLT/GOT fact count exceeds its budget", "elf_plt_got",
                plt_got_count_ + 1, limits_.max_plt_got_entries));
        image_.plt_got_entries.push_back(std::move(fact));
        ++plt_got_count_;
        return workspace_result_t<void>::success();
    };
    for (const auto& section : image_.sections) {
        if (!section.is_got && !section.is_got_plt && !section.is_plt)
            continue;
        const auto runtime = section_runtime_address(section.index);
        if (!runtime)
            return workspace_result_t<void>::failure(
                elf_error("ELF PLT/GOT section is not part of the analysis image",
                          "elf_plt_got", section.offset, section.size));
        if (section.is_got || section.is_got_plt) {
            if (section.size % pointer_size() != 0)
                return workspace_result_t<void>::failure(
                    elf_error("ELF GOT section has a partial pointer", "elf_plt_got",
                              section.offset, section.size));
            const auto slots = section.size / pointer_size();
            for (std::uint64_t slot = 0; slot < slots; ++slot) {
                elf_plt_got_entry_t fact;
                fact.address = *runtime + slot * pointer_size();
                fact.got_address = fact.address;
                fact.slot_index = static_cast<std::uint32_t>(slot);
                fact.is_got = section.is_got;
                fact.is_got_plt = section.is_got_plt;
                auto added = add_fact(std::move(fact));
                if (!added)
                    return added;
            }
        } else {
            std::uint64_t stride = section.entsize;
            std::uint64_t plt_header_size = 0;
            if (section.name == ".plt") {
                switch (header_.machine) {
                    case em_arm:
                        plt_header_size = 20;
                        if (stride == 0)
                            stride = 12;
                        break;
                    case em_aarch64:
                    case em_mips:
                    case em_riscv:
                        plt_header_size = 32;
                        if (stride == 0)
                            stride = 16;
                        break;
                    case em_386:
                    case em_x86_64:
                        plt_header_size = 16;
                        if (stride == 0)
                            stride = 16;
                        break;
                    default:
                        break;
                }
            }
            if (stride == 0)
                stride = section.name == ".plt.got" ? pointer_size() : 16;
            if (plt_header_size > section.size ||
                (section.size - plt_header_size) % stride != 0) {
                plt_header_size = section.name == ".plt" ? stride : 0;
                if (plt_header_size > section.size ||
                    (section.size - plt_header_size) % stride != 0) {
                    if (section.size % pointer_size() == 0) {
                        stride = pointer_size();
                        plt_header_size = section.name == ".plt" ? stride : 0;
                    } else {
                        stride = section.size;
                        plt_header_size = 0;
                    }
                }
            }
            if (stride == 0 || plt_header_size > section.size ||
                (section.size - plt_header_size) % stride != 0)
                return workspace_result_t<void>::failure(
                    elf_error("ELF PLT section has an invalid entry layout",
                              "elf_plt_got", section.offset, section.size));
            if (plt_header_size != 0) {
                elf_plt_got_entry_t resolver;
                resolver.address = *runtime;
                resolver.is_plt = true;
                auto added = add_fact(std::move(resolver));
                if (!added)
                    return added;
            }
            const auto slots = (section.size - plt_header_size) / stride;
            for (std::uint64_t slot = 0; slot < slots; ++slot) {
                elf_plt_got_entry_t fact;
                fact.address = *runtime + plt_header_size + slot * stride;
                fact.slot_index = static_cast<std::uint32_t>(
                    slot + (plt_header_size == 0 ? 0 : 1));
                fact.is_plt = true;
                auto added = add_fact(std::move(fact));
                if (!added)
                    return added;
                const auto fact_index = image_.plt_got_entries.size() - 1;
                if (section.name == ".plt.sec" || section.name == ".iplt")
                    plt_sec_candidates.push_back(fact_index);
                else
                    plt_candidates.push_back(fact_index);
            }
        }
    }
    std::vector<bool> remove(image_.plt_got_entries.size(), false);
    std::unordered_map<std::uint64_t, std::size_t> got_lookup;
    got_lookup.reserve(image_.plt_got_entries.size());
    for (std::size_t index = 0; index < image_.plt_got_entries.size(); ++index) {
        const auto& fact = image_.plt_got_entries[index];
        if (fact.is_got || fact.is_got_plt)
            got_lookup.emplace(fact.got_address, index);
    }
    std::size_t plt_ordinal = 0;
    for (const auto& relocation : image_.relocations) {
        if (!relocation.is_plt)
            continue;
        if (relocation.symbol_name) {
            auto name_budget = charge_materialized_string(
                relocation.symbol_name->size(), "elf_plt_got");
            if (!name_budget)
                return name_budget;
        }
        std::uint64_t relocation_got = relocation.offset;
        if (header_.type == et_rel && relocation.target_section_index) {
            const auto address = section_runtime_address(*relocation.target_section_index,
                                                         relocation.offset);
            if (!address)
                return workspace_result_t<void>::failure(
                    elf_error("relocatable ELF PLT relocation has no mapped GOT address",
                              "elf_plt_got"));
            relocation_got = *address;
        }
        const auto& candidates = plt_ordinal < plt_sec_candidates.size()
                                     ? plt_sec_candidates
                                     : plt_candidates;
        std::optional<std::size_t> plt_index;
        if (plt_ordinal < candidates.size())
            plt_index = candidates[plt_ordinal];
        std::optional<std::size_t> got_index;
        const auto got = got_lookup.find(relocation_got);
        if (got != got_lookup.end())
            got_index = got->second;
        if (got_index) {
            auto& fact = image_.plt_got_entries[*got_index];
            fact.is_plt = true;
            if (plt_index) {
                fact.address = image_.plt_got_entries[*plt_index].address;
                remove[*plt_index] = true;
            }
            fact.symbol_name = relocation.symbol_name;
        } else if (plt_index) {
            auto& fact = image_.plt_got_entries[*plt_index];
            fact.got_address = relocation_got;
            fact.symbol_name = relocation.symbol_name;
        } else {
            elf_plt_got_entry_t fact;
            fact.address = relocation_got;
            fact.got_address = relocation_got;
            fact.slot_index = static_cast<std::uint32_t>(plt_ordinal);
            fact.symbol_name = relocation.symbol_name;
            fact.is_plt = true;
            auto added = add_fact(std::move(fact));
            if (!added)
                return added;
            remove.push_back(false);
        }
        ++plt_ordinal;
    }
    auto pltgot = dynamic_value(dt_pltgot);
    if (!pltgot)
        return workspace_result_t<void>::failure(std::move(pltgot.error()));
    if (pltgot.value()) {
        const bool represented = std::any_of(
            image_.plt_got_entries.begin(), image_.plt_got_entries.end(),
            [&](const auto& fact) { return fact.got_address == *pltgot.value(); });
        if (!represented) {
            elf_plt_got_entry_t fact;
            fact.address = *pltgot.value();
            fact.got_address = *pltgot.value();
            fact.is_got_plt = true;
            auto added = add_fact(std::move(fact));
            if (!added)
                return added;
            remove.push_back(false);
        }
    }
    std::vector<elf_plt_got_entry_t> compacted;
    compacted.reserve(image_.plt_got_entries.size());
    for (std::size_t index = 0; index < image_.plt_got_entries.size(); ++index) {
        if (index >= remove.size() || !remove[index])
            compacted.push_back(std::move(image_.plt_got_entries[index]));
    }
    image_.plt_got_entries = std::move(compacted);
    std::sort(image_.plt_got_entries.begin(), image_.plt_got_entries.end(),
              [](const auto& left, const auto& right) {
                  return std::tie(left.address, left.got_address, left.slot_index,
                                  left.is_plt, left.is_got, left.is_got_plt) <
                         std::tie(right.address, right.got_address, right.slot_index,
                                  right.is_plt, right.is_got, right.is_got_plt);
              });
    return workspace_result_t<void>::success();
}

std::optional<std::uint64_t> elf_parser_t::symbol_rva(
    const elf_symbol_t& symbol) const noexcept {
    if (symbol.is_undefined || symbol.is_absolute || symbol.is_common)
        return std::nullopt;
    if (symbol.section_index >= raw_sections_.size())
        return std::nullopt;
    const auto& section = raw_sections_[symbol.section_index];
    const bool section_relative = header_.type == et_rel ||
                                  (symbol.kind == elf_symbol_kind_t::tls &&
                                   symbol.value <= section.size &&
                                   symbol.size <= section.size - symbol.value);
    if (section_relative) {
        if (section_rvas_[symbol.section_index] == invalid_rva)
            return std::nullopt;
        std::uint64_t rva = 0;
        if (!checked_add_u64(section_rvas_[symbol.section_index], symbol.value, rva) ||
            rva >= image_.normalized.image_size)
            return std::nullopt;
        return rva;
    }
    return virtual_to_rva(symbol.value);
}

workspace_result_t<void> elf_parser_t::build_normalized_image() {
    workspace_image_t normalized;
    normalized.format = format_id_t::elf;
    normalized.architecture = elf_machine_to_arch(header_.machine);
    normalized.architecture_mode = architecture_mode(header_.machine, header_.is_64);
    normalized.endian = header_.big_endian ? endian_t::big : endian_t::little;
    normalized.address_width_bits = header_.is_64 ? 64 : 32;
    normalized.image_base = image_.normalized.image_base;
    normalized.image_size = image_.normalized.image_size;
    normalized.format_name = header_.is_64 ? "elf64" : "elf32";
    normalized.provider_size = provider_.size();
    normalized.member = provider_.member_metadata();
    bool android = false;
    bool linux = header_.osabi == elfosabi_linux || header_.osabi == elfosabi_gnu;
    if (image_.interpreter) {
        const auto& interpreter = *image_.interpreter;
        android = interpreter.find("/system/bin/linker") != std::string::npos ||
                  interpreter.find("/apex/") != std::string::npos;
        linux |= interpreter.find("ld-linux") != std::string::npos ||
                 interpreter.find("ld-musl") != std::string::npos;
    }
    linux |= std::any_of(image_.notes.begin(), image_.notes.end(),
                         [](const auto& note) { return note.is_abi_tag; });
    normalized.abi = android ? android_abi(normalized.architecture)
                     : linux ? linux_abi(normalized.architecture)
                             : abi_id_t::sysv;
    if (has_load_segments_) {
        for (const auto& segment : raw_segments_) {
            if (segment.type == pt_load && segment.offset == 0 &&
                segment.virtual_address == normalized.image_base &&
                segment.file_size >= header_.ehsize) {
                normalized.header_size = header_.ehsize;
                break;
            }
        }
    } else {
        normalized.header_size = (std::min)(static_cast<std::uint64_t>(header_.ehsize),
                                            normalized.image_size);
    }
    for (const auto& segment : raw_segments_) {
        if (segment.type != pt_load || segment.memory_size == 0)
            continue;
        image_segment_t output;
        output.index = segment.index;
        output.name = segment_type_name(segment.type);
        auto segment_name_budget = charge_materialized_string(output.name.size(),
                                                               "elf_normalize");
        if (!segment_name_budget)
            return segment_name_budget;
        output.virtual_address = segment.virtual_address - normalized.image_base;
        output.virtual_size = segment.memory_size;
        output.file_offset = segment.file_size == 0 ? 0 : segment.offset;
        output.file_size = segment.file_size;
        output.alignment = segment.alignment;
        output.flags = segment.flags;
        output.permissions = segment_permissions(segment.flags);
        normalized.segments.push_back(output);
        if (segment.file_size != 0) {
            image_address_mapping_t mapping;
            mapping.source_space = address_space_id_t::file_offset;
            mapping.target_space = address_space_id_t::relative_virtual;
            mapping.source_start = segment.offset;
            mapping.target_start = output.virtual_address;
            mapping.size = segment.file_size;
            mapping.permissions = output.permissions;
            normalized.address_mappings.push_back(mapping);
        }
    }
    if (!has_load_segments_ && normalized.header_size != 0) {
        image_address_mapping_t mapping;
        mapping.source_start = 0;
        mapping.target_start = 0;
        mapping.size = normalized.header_size;
        mapping.permissions = image_permission_read;
        normalized.address_mappings.push_back(mapping);
    }
    for (const auto& section : raw_sections_) {
        if (section.index >= section_rvas_.size() ||
            section_rvas_[section.index] == invalid_rva || section.size == 0)
            continue;
        image_section_t output;
        output.index = section.index;
        output.name = image_.sections[section.index].name;
        auto section_name_budget = charge_materialized_string(output.name.size(),
                                                               "elf_normalize");
        if (!section_name_budget)
            return section_name_budget;
        output.virtual_address = section_rvas_[section.index];
        output.virtual_size = section.size;
        output.file_offset = section.type == sht_nobits ? 0 : section.offset;
        output.file_size = section.type == sht_nobits ? 0 : section.size;
        output.flags = section.flags;
        output.permissions = section_permissions(section.flags);
        if (output.permissions == image_permission_none)
            output.permissions = image_permission_read;
        normalized.sections.push_back(output);
        if (!has_load_segments_ && output.file_size != 0) {
            image_address_mapping_t mapping;
            mapping.source_start = output.file_offset;
            mapping.target_start = output.virtual_address;
            mapping.size = output.file_size;
            mapping.permissions = output.permissions;
            normalized.address_mappings.push_back(mapping);
        }
    }
    const auto make_address = [&](std::uint64_t rva) {
        return address_t{address_space_id_t::relative_virtual, rva,
                         normalized.architecture, normalized.architecture_mode};
    };
    const auto add_entry = [&](std::uint64_t address,
                               std::string provenance) -> workspace_result_t<void> {
        const auto rva = virtual_to_rva(address);
        if (!rva)
            return workspace_result_t<void>::success();
        const auto normalized_address = make_address(*rva);
        if (!workspace_image_contains(normalized, normalized_address))
            return workspace_result_t<void>::failure(
                elf_error("ELF entry point is outside normalized mapped regions",
                          "elf_normalize", address, 1));
        const bool duplicate = std::any_of(
            normalized.entry_points.begin(), normalized.entry_points.end(),
            [&](const auto& entry) {
                return entry.address.value == *rva && entry.provenance == provenance;
            });
        if (!duplicate) {
            auto provenance_budget = charge_materialized_string(provenance.size(),
                                                                 "elf_normalize");
            if (!provenance_budget)
                return provenance_budget;
            normalized.entry_points.push_back(
                image_entry_point_t{normalized_address, std::move(provenance)});
        }
        return workspace_result_t<void>::success();
    };
    if (header_.entry != 0) {
        if (header_.type == et_rel || !virtual_to_rva(header_.entry))
            return workspace_result_t<void>::failure(
                elf_error("ELF header entry point is outside the analysis image",
                          "elf_normalize", header_.entry, 1));
        auto added = add_entry(header_.entry, "elf_header");
        if (!added)
            return added;
    }
    for (const auto& entry : image_.init_fini_entries) {
        const char* provenance = entry.is_preinit ? "preinit_array"
                                 : entry.is_init ? "init"
                                                 : "fini";
        auto added = add_entry(entry.address, provenance);
        if (!added)
            return added;
    }
    std::uint64_t ordinal = 0;
    const auto add_symbol = [&](const elf_symbol_t& source) -> workspace_result_t<void> {
        if (source.table_symbol_index == 0 && source.name.empty())
            return workspace_result_t<void>::success();
        image_symbol_t symbol;
        symbol.ordinal = ordinal++;
        symbol.name = source.name;
        if (symbol.name.empty() && source.kind == elf_symbol_kind_t::section &&
            source.section_index < image_.sections.size())
            symbol.name = image_.sections[source.section_index].name;
        auto symbol_name_budget = charge_materialized_string(symbol.name.size(),
                                                              "elf_normalize");
        if (!symbol_name_budget)
            return symbol_name_budget;
        symbol.address = make_address(0);
        symbol.size = source.size;
        symbol.kind = normalized_symbol_kind(source);
        symbol.binding = normalized_symbol_binding(source);
        const auto rva = symbol_rva(source);
        if (rva) {
            const auto address = make_address(*rva);
            if (workspace_image_contains(normalized, address)) {
                symbol.address = address;
                symbol.defined = true;
            }
        }
        normalized.symbols.push_back(symbol);
        if (source.is_export && symbol.defined) {
            auto export_name_budget = charge_materialized_string(source.name.size(),
                                                                  "elf_normalize");
            if (!export_name_budget)
                return export_name_budget;
            image_export_t exported;
            exported.name = source.name;
            exported.ordinal = source.table_symbol_index;
            exported.address = symbol.address;
            normalized.exports.push_back(std::move(exported));
        }
        return workspace_result_t<void>::success();
    };
    for (const auto& symbol : image_.symtab_symbols) {
        auto added = add_symbol(symbol);
        if (!added)
            return added;
    }
    for (const auto& symbol : image_.dynsym_symbols) {
        auto added = add_symbol(symbol);
        if (!added)
            return added;
    }
    const std::string import_library = image_.needed_libraries.size() == 1
                                           ? image_.needed_libraries.front()
                                           : "<dynamic>";
    for (const auto& fact : image_.plt_got_entries) {
        if (!fact.symbol_name || fact.symbol_name->empty())
            continue;
        const auto got_rva = virtual_to_rva(fact.got_address);
        const auto target_rva = virtual_to_rva(fact.address);
        if (!got_rva || !target_rva)
            continue;
        std::uint64_t import_string_size = import_library.size();
        if (!checked_add_u64(import_string_size, fact.symbol_name->size(),
                             import_string_size))
            return workspace_result_t<void>::failure(limit_error(
                "ELF normalized import strings overflow", "elf_normalize",
                (std::numeric_limits<std::uint64_t>::max)(),
                limits_.max_materialized_string_bytes));
        auto import_name_budget = charge_materialized_string(import_string_size,
                                                              "elf_normalize");
        if (!import_name_budget)
            return import_name_budget;
        image_import_t imported;
        imported.library = import_library;
        imported.name = fact.symbol_name;
        imported.lookup_address = make_address(*got_rva);
        imported.address = make_address(*target_rva);
        if (!workspace_image_contains(normalized, imported.lookup_address) ||
            !workspace_image_contains(normalized, imported.address))
            continue;
        normalized.imports.push_back(std::move(imported));
    }
    for (const auto& relocation : image_.relocations) {
        if (relocation.type == 0)
            continue;
        std::optional<std::uint64_t> rva;
        if (header_.type == et_rel && relocation.target_section_index) {
            const auto address = section_runtime_address(*relocation.target_section_index,
                                                         relocation.offset);
            if (address)
                rva = virtual_to_rva(*address);
        } else {
            rva = virtual_to_rva(relocation.offset);
        }
        if (!rva)
            continue;
        image_relocation_t output;
        output.address = make_address(*rva);
        output.type = relocation.type;
        if (const auto* target_symbol = relocation_symbol(relocation)) {
            const auto target_rva = symbol_rva(*target_symbol);
            if (target_rva)
                output.target = make_address(*target_rva);
        }
        normalized.relocations.push_back(std::move(output));
    }
    std::sort(normalized.exports.begin(), normalized.exports.end(),
              [](const auto& left, const auto& right) {
                  return std::tie(left.address.value, left.ordinal, left.name) <
                         std::tie(right.address.value, right.ordinal, right.name);
              });
    normalized.exports.erase(
        std::unique(normalized.exports.begin(), normalized.exports.end(),
                    [](const auto& left, const auto& right) {
                        return left.address.value == right.address.value &&
                               left.name == right.name;
                    }),
        normalized.exports.end());
    std::sort(normalized.imports.begin(), normalized.imports.end(),
              [](const auto& left, const auto& right) {
                  return std::tie(left.address.value, left.lookup_address.value,
                                  left.library, left.name) <
                         std::tie(right.address.value, right.lookup_address.value,
                                  right.library, right.name);
              });
    normalized.imports.erase(
        std::unique(normalized.imports.begin(), normalized.imports.end(),
                    [](const auto& left, const auto& right) {
                        return left.address.value == right.address.value &&
                               left.lookup_address.value == right.lookup_address.value &&
                               left.library == right.library && left.name == right.name;
                    }),
        normalized.imports.end());
    auto validation = validate_workspace_image(normalized, {}, false, cancel_);
    if (!validation)
        return validation;
    image_.normalized = std::move(normalized);
    return workspace_result_t<void>::success();
}

workspace_result_t<elf_image_t> elf_parser_t::parse() {
    auto header = parse_header();
    if (!header)
        return workspace_result_t<elf_image_t>::failure(std::move(header.error()));
    auto sections = parse_section_headers();
    if (!sections)
        return workspace_result_t<elf_image_t>::failure(std::move(sections.error()));
    auto segments = parse_program_headers();
    if (!segments)
        return workspace_result_t<elf_image_t>::failure(std::move(segments.error()));
    auto interpreter = parse_interpreter();
    if (!interpreter)
        return workspace_result_t<elf_image_t>::failure(std::move(interpreter.error()));
    auto layout = build_image_layout();
    if (!layout)
        return workspace_result_t<elf_image_t>::failure(std::move(layout.error()));
    auto symbols = parse_symbol_sections();
    if (!symbols)
        return workspace_result_t<elf_image_t>::failure(std::move(symbols.error()));
    auto dynamic = parse_dynamic_table();
    if (!dynamic)
        return workspace_result_t<elf_image_t>::failure(std::move(dynamic.error()));
    auto dynamic_symbols = parse_dynamic_symbols();
    if (!dynamic_symbols)
        return workspace_result_t<elf_image_t>::failure(std::move(dynamic_symbols.error()));
    auto relocations = parse_relocation_sections();
    if (!relocations)
        return workspace_result_t<elf_image_t>::failure(std::move(relocations.error()));
    auto dynamic_relocations = parse_dynamic_relocations();
    if (!dynamic_relocations)
        return workspace_result_t<elf_image_t>::failure(
            std::move(dynamic_relocations.error()));
    auto notes = parse_notes();
    if (!notes)
        return workspace_result_t<elf_image_t>::failure(std::move(notes.error()));
    auto init_fini = parse_init_fini();
    if (!init_fini)
        return workspace_result_t<elf_image_t>::failure(std::move(init_fini.error()));
    auto plt_got = build_plt_got_facts();
    if (!plt_got)
        return workspace_result_t<elf_image_t>::failure(std::move(plt_got.error()));
    auto normalized = build_normalized_image();
    if (!normalized)
        return workspace_result_t<elf_image_t>::failure(std::move(normalized.error()));
    return workspace_result_t<elf_image_t>::success(std::move(image_));
}

}

architecture_id_t elf_machine_to_arch(std::uint16_t machine) noexcept {
    switch (machine) {
        case em_386: return architecture_id_t::x86;
        case em_x86_64: return architecture_id_t::x86_64;
        case em_arm: return architecture_id_t::arm;
        case em_aarch64: return architecture_id_t::aarch64;
        case em_mips: return architecture_id_t::mips;
        case em_ppc: return architecture_id_t::ppc;
        case em_ppc64: return architecture_id_t::ppc64;
        case em_riscv: return architecture_id_t::riscv;
        default: return architecture_id_t::unknown;
    }
}

endian_t elf_data_to_endian(std::uint8_t data) noexcept {
    return data == elfdata2msb ? endian_t::big : endian_t::little;
}

workspace_result_t<elf_image_t> parse_elf_image(
    const byte_provider_t& provider, const elf_parse_limits_t& limits,
    const cancellation_token_t& cancel) {
    try {
        elf_parser_t parser(provider, limits, cancel);
        return parser.parse();
    } catch (const std::bad_alloc&) {
        return workspace_result_t<elf_image_t>::failure(allocation_error());
    } catch (const std::length_error&) {
        return workspace_result_t<elf_image_t>::failure(allocation_error());
    }
}

workspace_result_t<elf_image_t> parse_elf_image(
    const byte_provider_t& provider, const cancellation_token_t& cancel) {
    return parse_elf_image(provider, elf_parse_limits_t{}, cancel);
}

workspace_result_t<workspace_image_t> parse_elf(
    const byte_provider_t& provider, const elf_parse_limits_t& limits,
    const cancellation_token_t& cancel) {
    auto parsed = parse_elf_image(provider, limits, cancel);
    if (!parsed)
        return workspace_result_t<workspace_image_t>::failure(std::move(parsed.error()));
    return workspace_result_t<workspace_image_t>::success(
        std::move(parsed.value().normalized));
}

workspace_result_t<workspace_image_t> parse_elf(
    const byte_provider_t& provider, const cancellation_token_t& cancel) {
    return parse_elf(provider, elf_parse_limits_t{}, cancel);
}

workspace_result_t<bool> is_elf_file(
    const byte_provider_t& provider, const cancellation_token_t& cancel) {
    if (cancel.stop_requested())
        return workspace_result_t<bool>::failure(stop_error(cancel));
    if (provider.size() < 4)
        return workspace_result_t<bool>::success(false);
    auto span = validate_span(0, 4, provider.size(), "elf_probe");
    if (!span)
        return workspace_result_t<bool>::failure(std::move(span.error()));
    std::array<std::uint8_t, 4> magic{};
    auto read = provider.read_exact(0, magic.data(), magic.size(), cancel);
    if (!read)
        return workspace_result_t<bool>::failure(std::move(read.error()));
    return workspace_result_t<bool>::success(
        magic[0] == elfmag0 && magic[1] == elfmag1 &&
        magic[2] == elfmag2 && magic[3] == elfmag3);
}

}
