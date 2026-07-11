#pragma once

#include "byte_provider.hpp"
#include "workspace_types.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace aida::analysis {

inline constexpr std::uint8_t elfmag0 = 0x7f;
inline constexpr std::uint8_t elfmag1 = 'E';
inline constexpr std::uint8_t elfmag2 = 'L';
inline constexpr std::uint8_t elfmag3 = 'F';

inline constexpr std::uint8_t ei_mag0 = 0;
inline constexpr std::uint8_t ei_mag1 = 1;
inline constexpr std::uint8_t ei_mag2 = 2;
inline constexpr std::uint8_t ei_mag3 = 3;
inline constexpr std::uint8_t ei_class = 4;
inline constexpr std::uint8_t ei_data = 5;
inline constexpr std::uint8_t ei_version = 6;
inline constexpr std::uint8_t ei_osabi = 7;
inline constexpr std::uint8_t ei_abiversion = 8;
inline constexpr std::uint8_t ei_pad = 9;
inline constexpr std::uint8_t ei_nident = 16;

inline constexpr std::uint8_t elfclassnone = 0;
inline constexpr std::uint8_t elfclass32 = 1;
inline constexpr std::uint8_t elfclass64 = 2;

inline constexpr std::uint8_t elfdatanone = 0;
inline constexpr std::uint8_t elfdata2lsb = 1;
inline constexpr std::uint8_t elfdata2msb = 2;

inline constexpr std::uint8_t ev_none = 0;
inline constexpr std::uint8_t ev_current = 1;

inline constexpr std::uint16_t et_none = 0;
inline constexpr std::uint16_t et_rel = 1;
inline constexpr std::uint16_t et_exec = 2;
inline constexpr std::uint16_t et_dyn = 3;
inline constexpr std::uint16_t et_core = 4;

inline constexpr std::uint16_t em_none = 0;
inline constexpr std::uint16_t em_386 = 3;
inline constexpr std::uint16_t em_arm = 40;
inline constexpr std::uint16_t em_x86_64 = 62;
inline constexpr std::uint16_t em_aarch64 = 183;
inline constexpr std::uint16_t em_mips = 8;
inline constexpr std::uint16_t em_ppc = 20;
inline constexpr std::uint16_t em_ppc64 = 21;
inline constexpr std::uint16_t em_riscv = 243;
inline constexpr std::uint16_t em_sparc = 2;
inline constexpr std::uint16_t em_s390 = 22;

inline constexpr std::uint32_t sht_null = 0;
inline constexpr std::uint32_t sht_progbits = 1;
inline constexpr std::uint32_t sht_symtab = 2;
inline constexpr std::uint32_t sht_strtab = 3;
inline constexpr std::uint32_t sht_rela = 4;
inline constexpr std::uint32_t sht_hash = 5;
inline constexpr std::uint32_t sht_dynamic = 6;
inline constexpr std::uint32_t sht_note = 7;
inline constexpr std::uint32_t sht_nobits = 8;
inline constexpr std::uint32_t sht_rel = 9;
inline constexpr std::uint32_t sht_shlib = 10;
inline constexpr std::uint32_t sht_dynsym = 11;
inline constexpr std::uint32_t sht_init_array = 14;
inline constexpr std::uint32_t sht_fini_array = 15;
inline constexpr std::uint32_t sht_preinit_array = 16;
inline constexpr std::uint32_t sht_group = 17;
inline constexpr std::uint32_t sht_symtab_shndx = 18;
inline constexpr std::uint32_t sht_gnu_hash = 0x6ffffff6;
inline constexpr std::uint32_t sht_gnu_verdef = 0x6ffffffd;
inline constexpr std::uint32_t sht_gnu_verneed = 0x6ffffffe;
inline constexpr std::uint32_t sht_gnu_versym = 0x6fffffff;

inline constexpr std::uint64_t shf_write = 0x1;
inline constexpr std::uint64_t shf_alloc = 0x2;
inline constexpr std::uint64_t shf_execinstr = 0x4;
inline constexpr std::uint64_t shf_merge = 0x10;
inline constexpr std::uint64_t shf_strings = 0x20;
inline constexpr std::uint64_t shf_info_link = 0x40;
inline constexpr std::uint64_t shf_link_order = 0x80;
inline constexpr std::uint64_t shf_os_nonconforming = 0x100;
inline constexpr std::uint64_t shf_group = 0x200;
inline constexpr std::uint64_t shf_tls = 0x400;
inline constexpr std::uint64_t shf_compressed = 0x800;

inline constexpr std::uint32_t pt_null = 0;
inline constexpr std::uint32_t pt_load = 1;
inline constexpr std::uint32_t pt_dynamic = 2;
inline constexpr std::uint32_t pt_interp = 3;
inline constexpr std::uint32_t pt_note = 4;
inline constexpr std::uint32_t pt_shlib = 5;
inline constexpr std::uint32_t pt_phdr = 6;
inline constexpr std::uint32_t pt_tls = 7;
inline constexpr std::uint32_t pt_gnu_eh_frame = 0x6474e550;
inline constexpr std::uint32_t pt_gnu_stack = 0x6474e551;
inline constexpr std::uint32_t pt_gnu_relro = 0x6474e552;
inline constexpr std::uint32_t pt_gnu_property = 0x6474e553;

inline constexpr std::uint32_t pf_x = 0x1;
inline constexpr std::uint32_t pf_w = 0x2;
inline constexpr std::uint32_t pf_r = 0x4;

inline constexpr std::uint8_t stb_local = 0;
inline constexpr std::uint8_t stb_global = 1;
inline constexpr std::uint8_t stb_weak = 2;
inline constexpr std::uint8_t stb_gnu_unique = 10;

inline constexpr std::uint8_t stt_notype = 0;
inline constexpr std::uint8_t stt_object = 1;
inline constexpr std::uint8_t stt_func = 2;
inline constexpr std::uint8_t stt_section = 3;
inline constexpr std::uint8_t stt_file = 4;
inline constexpr std::uint8_t stt_common = 5;
inline constexpr std::uint8_t stt_tls = 6;
inline constexpr std::uint8_t stt_gnu_ifunc = 10;

inline constexpr std::uint8_t stv_default = 0;
inline constexpr std::uint8_t stv_internal = 1;
inline constexpr std::uint8_t stv_hidden = 2;
inline constexpr std::uint8_t stv_protected = 3;

inline constexpr std::int64_t dt_null = 0;
inline constexpr std::int64_t dt_needed = 1;
inline constexpr std::int64_t dt_pltrelsz = 2;
inline constexpr std::int64_t dt_pltgot = 3;
inline constexpr std::int64_t dt_hash = 4;
inline constexpr std::int64_t dt_strtab = 5;
inline constexpr std::int64_t dt_symtab = 6;
inline constexpr std::int64_t dt_rela = 7;
inline constexpr std::int64_t dt_relasz = 8;
inline constexpr std::int64_t dt_relaent = 9;
inline constexpr std::int64_t dt_strsz = 10;
inline constexpr std::int64_t dt_syment = 11;
inline constexpr std::int64_t dt_init = 12;
inline constexpr std::int64_t dt_fini = 13;
inline constexpr std::int64_t dt_soname = 14;
inline constexpr std::int64_t dt_rpath = 15;
inline constexpr std::int64_t dt_symbolic = 16;
inline constexpr std::int64_t dt_rel = 17;
inline constexpr std::int64_t dt_relsz = 18;
inline constexpr std::int64_t dt_relent = 19;
inline constexpr std::int64_t dt_pltrel = 20;
inline constexpr std::int64_t dt_debug = 21;
inline constexpr std::int64_t dt_textrel = 22;
inline constexpr std::int64_t dt_jmprel = 23;
inline constexpr std::int64_t dt_bind_now = 24;
inline constexpr std::int64_t dt_init_array = 25;
inline constexpr std::int64_t dt_fini_array = 26;
inline constexpr std::int64_t dt_init_arraysz = 27;
inline constexpr std::int64_t dt_fini_arraysz = 28;
inline constexpr std::int64_t dt_runpath = 29;
inline constexpr std::int64_t dt_flags = 30;
inline constexpr std::int64_t dt_preinit_array = 32;
inline constexpr std::int64_t dt_preinit_arraysz = 33;
inline constexpr std::int64_t dt_gnu_hash = 0x6ffffef5;
inline constexpr std::int64_t dt_versym = 0x6ffffff0;
inline constexpr std::int64_t dt_verdef = 0x6ffffffc;
inline constexpr std::int64_t dt_verdefnum = 0x6ffffffd;
inline constexpr std::int64_t dt_verneed = 0x6ffffffe;
inline constexpr std::int64_t dt_verneednum = 0x6fffffff;

inline constexpr std::uint32_t nt_version = 1;
inline constexpr std::uint32_t nt_gnu_build_id = 3;
inline constexpr std::uint32_t nt_gnu_abi_tag = 1;
inline constexpr std::uint32_t nt_gnu_hwcap = 2;
inline constexpr std::uint32_t nt_gnu_property_type_0 = 5;

inline constexpr std::uint32_t elfcompress_zlib = 1;
inline constexpr std::uint32_t elfcompress_zstd = 2;

inline constexpr std::uint16_t shn_undef = 0;
inline constexpr std::uint16_t shn_abs = 0xfff1;
inline constexpr std::uint16_t shn_common = 0xfff2;
inline constexpr std::uint16_t shn_xindex = 0xffff;

inline constexpr std::uint8_t elfosabi_none = 0;
inline constexpr std::uint8_t elfosabi_linux = 3;
inline constexpr std::uint8_t elfosabi_gnu = 3;

#pragma pack(push, 1)

struct elf32_ehdr_t {
    std::uint8_t  e_ident[16];
    std::uint16_t e_type;
    std::uint16_t e_machine;
    std::uint32_t e_version;
    std::uint32_t e_entry;
    std::uint32_t e_phoff;
    std::uint32_t e_shoff;
    std::uint32_t e_flags;
    std::uint16_t e_ehsize;
    std::uint16_t e_phentsize;
    std::uint16_t e_phnum;
    std::uint16_t e_shentsize;
    std::uint16_t e_shnum;
    std::uint16_t e_shstrndx;
};
static_assert(sizeof(elf32_ehdr_t) == 52);

struct elf64_ehdr_t {
    std::uint8_t  e_ident[16];
    std::uint16_t e_type;
    std::uint16_t e_machine;
    std::uint32_t e_version;
    std::uint64_t e_entry;
    std::uint64_t e_phoff;
    std::uint64_t e_shoff;
    std::uint32_t e_flags;
    std::uint16_t e_ehsize;
    std::uint16_t e_phentsize;
    std::uint16_t e_phnum;
    std::uint16_t e_shentsize;
    std::uint16_t e_shnum;
    std::uint16_t e_shstrndx;
};
static_assert(sizeof(elf64_ehdr_t) == 64);

struct elf32_phdr_t {
    std::uint32_t p_type;
    std::uint32_t p_offset;
    std::uint32_t p_vaddr;
    std::uint32_t p_paddr;
    std::uint32_t p_filesz;
    std::uint32_t p_memsz;
    std::uint32_t p_flags;
    std::uint32_t p_align;
};
static_assert(sizeof(elf32_phdr_t) == 32);

struct elf64_phdr_t {
    std::uint32_t p_type;
    std::uint32_t p_flags;
    std::uint64_t p_offset;
    std::uint64_t p_vaddr;
    std::uint64_t p_paddr;
    std::uint64_t p_filesz;
    std::uint64_t p_memsz;
    std::uint64_t p_align;
};
static_assert(sizeof(elf64_phdr_t) == 56);

struct elf32_shdr_t {
    std::uint32_t sh_name;
    std::uint32_t sh_type;
    std::uint32_t sh_flags;
    std::uint32_t sh_addr;
    std::uint32_t sh_offset;
    std::uint32_t sh_size;
    std::uint32_t sh_link;
    std::uint32_t sh_info;
    std::uint32_t sh_addralign;
    std::uint32_t sh_entsize;
};
static_assert(sizeof(elf32_shdr_t) == 40);

struct elf64_shdr_t {
    std::uint32_t sh_name;
    std::uint32_t sh_type;
    std::uint64_t sh_flags;
    std::uint64_t sh_addr;
    std::uint64_t sh_offset;
    std::uint64_t sh_size;
    std::uint32_t sh_link;
    std::uint32_t sh_info;
    std::uint64_t sh_addralign;
    std::uint64_t sh_entsize;
};
static_assert(sizeof(elf64_shdr_t) == 64);

struct elf32_sym_t {
    std::uint32_t st_name;
    std::uint32_t st_value;
    std::uint32_t st_size;
    std::uint8_t  st_info;
    std::uint8_t  st_other;
    std::uint16_t st_shndx;
};
static_assert(sizeof(elf32_sym_t) == 16);

struct elf64_sym_t {
    std::uint32_t st_name;
    std::uint8_t  st_info;
    std::uint8_t  st_other;
    std::uint16_t st_shndx;
    std::uint64_t st_value;
    std::uint64_t st_size;
};
static_assert(sizeof(elf64_sym_t) == 24);

struct elf32_rel_t {
    std::uint32_t r_offset;
    std::uint32_t r_info;
};
static_assert(sizeof(elf32_rel_t) == 8);

struct elf64_rel_t {
    std::uint64_t r_offset;
    std::uint64_t r_info;
};
static_assert(sizeof(elf64_rel_t) == 16);

struct elf32_rela_t {
    std::uint32_t r_offset;
    std::uint32_t r_info;
    std::int32_t  r_addend;
};
static_assert(sizeof(elf32_rela_t) == 12);

struct elf64_rela_t {
    std::uint64_t r_offset;
    std::uint64_t r_info;
    std::int64_t  r_addend;
};
static_assert(sizeof(elf64_rela_t) == 24);

struct elf32_dyn_t {
    std::int32_t  d_tag;
    std::uint32_t d_val;
};
static_assert(sizeof(elf32_dyn_t) == 8);

struct elf64_dyn_t {
    std::int64_t  d_tag;
    std::uint64_t d_val;
};
static_assert(sizeof(elf64_dyn_t) == 16);

struct elf_nhdr_t {
    std::uint32_t n_namesz;
    std::uint32_t n_descsz;
    std::uint32_t n_type;
};
static_assert(sizeof(elf_nhdr_t) == 12);

#pragma pack(pop)

struct elf_parse_limits_t {
    std::uint32_t max_sections = 65536;
    std::uint32_t max_segments = 65536;
    std::uint32_t max_symbols = 1u << 20;
    std::uint32_t max_relocations = 1u << 20;
    std::uint32_t max_dynamic_entries = 65536;
    std::uint32_t max_notes = 65536;
    std::uint32_t max_plt_got_entries = 65536;
    std::uint32_t max_init_fini_entries = 65536;
    std::uint64_t max_overlap_checks = 1ULL << 20;
    std::uint64_t max_string_table_bytes = 64ULL * 1024ULL * 1024ULL;
    std::uint64_t max_materialized_string_bytes = 128ULL * 1024ULL * 1024ULL;
    std::uint64_t max_total_metadata_bytes = 256ULL * 1024ULL * 1024ULL;
};

enum class elf_filetype_t : std::uint8_t {
    unknown = 0,
    relocatable = 1,
    executable = 2,
    shared = 3,
    core = 4
};

struct elf_section_t {
    std::uint32_t index = 0;
    std::string name;
    std::uint32_t type = 0;
    std::uint64_t flags = 0;
    std::uint64_t addr = 0;
    std::uint64_t offset = 0;
    std::uint64_t size = 0;
    std::uint32_t link = 0;
    std::uint32_t info = 0;
    std::uint64_t addralign = 0;
    std::uint64_t entsize = 0;
    bool readable = false;
    bool writable = false;
    bool executable = false;
    bool allocated = false;
    bool is_dwarf = false;
    bool is_init_array = false;
    bool is_fini_array = false;
    bool is_preinit_array = false;
    bool is_symtab = false;
    bool is_dynsym = false;
    bool is_strtab = false;
    bool is_dynamic = false;
    bool is_note = false;
    bool is_rela = false;
    bool is_rel = false;
    bool is_nobits = false;
    bool is_plt = false;
    bool is_got = false;
    bool is_got_plt = false;
    bool is_hash = false;
    bool is_gnu_hash = false;
    bool is_compressed = false;
    bool uses_gnu_zdebug = false;
    std::uint32_t compression_type = 0;
    std::optional<std::uint64_t> uncompressed_size;
};

struct elf_segment_t {
    std::uint32_t index = 0;
    std::uint32_t type = 0;
    std::uint32_t flags = 0;
    std::uint64_t offset = 0;
    std::uint64_t vaddr = 0;
    std::uint64_t paddr = 0;
    std::uint64_t filesz = 0;
    std::uint64_t memsz = 0;
    std::uint64_t align = 0;
    bool readable = false;
    bool writable = false;
    bool executable = false;
    bool is_load = false;
    bool is_dynamic = false;
    bool is_interp = false;
    bool is_note = false;
    bool is_tls = false;
    bool is_gnu_eh_frame = false;
    bool is_gnu_stack = false;
    bool is_gnu_relro = false;
    bool is_gnu_property = false;
    std::string type_name;
};

enum class elf_symbol_kind_t : std::uint8_t {
    unknown = 0,
    function = 1,
    data = 2,
    section = 3,
    file = 4,
    common = 5,
    tls = 6,
    ifunc = 7,
    notype = 8
};

struct elf_symbol_t {
    std::string name;
    std::uint64_t value = 0;
    std::uint64_t size = 0;
    std::uint8_t binding = 0;
    std::uint8_t type = 0;
    std::uint8_t visibility = 0;
    std::uint16_t shndx = 0;
    std::uint32_t section_index = 0;
    std::uint32_t table_section_index = 0;
    std::uint32_t table_symbol_index = 0;
    elf_symbol_kind_t kind = elf_symbol_kind_t::unknown;
    bool is_local = false;
    bool is_global = false;
    bool is_weak = false;
    bool is_undefined = false;
    bool is_export = false;
    bool is_import = false;
    bool is_absolute = false;
    bool is_common = false;
    bool is_unique = false;
    bool is_from_symtab = false;
    bool is_from_dynsym = false;
};

struct elf_relocation_t {
    std::uint64_t offset = 0;
    std::uint64_t info = 0;
    std::int64_t addend = 0;
    std::uint32_t sym = 0;
    std::uint32_t type = 0;
    bool has_addend = false;
    bool is_plt = false;
    std::string section_name;
    std::optional<std::string> symbol_name;
    std::optional<std::uint32_t> symbol_table_section_index;
    std::optional<std::uint32_t> target_section_index;
    std::optional<std::uint32_t> relocation_section_index;
};

struct elf_dynamic_entry_t {
    std::int64_t tag = 0;
    std::uint64_t val = 0;
    std::string tag_name;
    std::optional<std::string> needed_name;
    std::optional<std::string> soname;
    std::optional<std::string> runpath;
    std::optional<std::string> rpath;
};

struct elf_note_t {
    std::uint32_t type = 0;
    std::string name;
    std::vector<std::uint8_t> descriptor;
    std::string section_name;
    std::uint64_t file_offset = 0;
    bool is_build_id = false;
    bool is_version = false;
    bool is_abi_tag = false;
    bool is_gnu_property = false;
    std::optional<std::string> build_id_hex;
};

struct elf_plt_got_entry_t {
    std::uint64_t address = 0;
    std::uint64_t got_address = 0;
    std::uint32_t slot_index = 0;
    std::optional<std::string> symbol_name;
    bool is_plt = false;
    bool is_got = false;
    bool is_got_plt = false;
};

struct elf_init_fini_entry_t {
    std::uint64_t address = 0;
    std::uint32_t index = 0;
    bool is_init = false;
    bool is_fini = false;
    bool is_preinit = false;
};

struct elf_dwarf_sections_t {
    bool has_debug_info = false;
    bool has_debug_line = false;
    bool has_debug_str = false;
    bool has_debug_abbrev = false;
    bool has_debug_ranges = false;
    bool has_debug_aranges = false;
    bool has_debug_macinfo = false;
    bool has_debug_loc = false;
    bool has_debug_frame = false;
    bool has_debug_pubnames = false;
    bool has_debug_pubtypes = false;
    bool has_debug_line_str = false;
    bool has_debug_loclists = false;
    bool has_debug_rnglists = false;
    bool has_debug_str_offsets = false;
    bool has_debug_addr = false;
    bool has_debug_types = false;
    bool has_debug_names = false;
    bool has_debug_sup = false;
    bool has_eh_frame = false;
    bool has_eh_frame_hdr = false;
    bool has_gnu_debuglink = false;
    bool has_gnu_debugaltlink = false;
    bool has_gnu_debugdata = false;
    bool has_compressed_debug = false;
    bool uses_gnu_zdebug = false;
    std::vector<std::string> compressed_section_names;
};

struct elf_image_t {
    workspace_image_t normalized;
    elf_filetype_t filetype = elf_filetype_t::unknown;
    bool is_64bit = false;
    endian_t endian = endian_t::little;
    std::uint16_t machine = 0;
    std::uint32_t version = 0;
    std::uint32_t flags = 0;
    std::uint8_t osabi = 0;
    std::uint8_t abi_version = 0;
    std::uint64_t entry_point = 0;
    std::uint64_t phoff = 0;
    std::uint64_t shoff = 0;
    std::uint16_t ehsize = 0;
    std::uint16_t phentsize = 0;
    std::uint32_t phnum = 0;
    std::uint16_t shentsize = 0;
    std::uint32_t shnum = 0;
    std::uint32_t shstrndx = 0;
    std::vector<elf_section_t> sections;
    std::vector<elf_segment_t> segments;
    std::vector<elf_symbol_t> symtab_symbols;
    std::vector<elf_symbol_t> dynsym_symbols;
    std::vector<elf_relocation_t> relocations;
    std::vector<elf_dynamic_entry_t> dynamic_entries;
    std::vector<elf_note_t> notes;
    std::vector<elf_plt_got_entry_t> plt_got_entries;
    std::vector<elf_init_fini_entry_t> init_fini_entries;
    elf_dwarf_sections_t dwarf_sections;
    std::optional<std::string> interpreter;
    std::optional<std::string> soname;
    std::optional<std::string> runpath;
    std::optional<std::string> rpath;
    std::vector<std::string> needed_libraries;
    elf_image_t() = default;
    elf_image_t(const elf_image_t&) = default;
    elf_image_t(elf_image_t&&) noexcept = default;
    elf_image_t& operator=(const elf_image_t&) = default;
    elf_image_t& operator=(elf_image_t&&) noexcept = default;
};

architecture_id_t elf_machine_to_arch(std::uint16_t machine) noexcept;
endian_t elf_data_to_endian(std::uint8_t data) noexcept;

workspace_result_t<workspace_image_t>
parse_elf(const byte_provider_t& provider,
          const cancellation_token_t& cancel = {});

workspace_result_t<workspace_image_t>
parse_elf(const byte_provider_t& provider,
          const elf_parse_limits_t& limits,
          const cancellation_token_t& cancel = {});

workspace_result_t<elf_image_t>
parse_elf_image(const byte_provider_t& provider,
                const cancellation_token_t& cancel = {});

workspace_result_t<elf_image_t>
parse_elf_image(const byte_provider_t& provider,
                const elf_parse_limits_t& limits,
                const cancellation_token_t& cancel = {});

workspace_result_t<bool>
is_elf_file(const byte_provider_t& provider,
            const cancellation_token_t& cancel = {});

}
