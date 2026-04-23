#pragma once
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string>
#include <vector>
#include <cstring>
#include <cstdint>
#include <fstream>
#include <algorithm>
#include <stdexcept>

namespace pe_file {

inline uint32_t align_up(uint32_t value, uint32_t alignment) {
    return (value + alignment - 1) & ~(alignment - 1);
}

struct data_directory_t {
    uint32_t rva;
    uint32_t size;
};

struct section_t {
    char name[8];
    uint32_t virtual_size;
    uint32_t virtual_address;
    uint32_t raw_size;
    uint32_t raw_offset;
    uint32_t characteristics;
    std::vector<uint8_t> data;
    uint32_t reloc_count;
    uint32_t reloc_offset;
    uint16_t line_count;
    uint16_t line_offset;
};

struct import_entry_t {
    std::string dll_name;
    std::string func_name;
    uint16_t ordinal;
    bool by_ordinal;
    uint64_t iat_rva;
    uint64_t ilt_rva;
};

struct import_descriptor_t {
    std::string dll_name;
    std::vector<import_entry_t> entries;
    uint32_t original_first_thunk_rva;
    uint32_t first_thunk_rva;
};

struct tls_directory_t {
    uint64_t raw_data_start;
    uint64_t raw_data_end;
    uint64_t address_of_index;
    uint64_t address_of_callbacks;
    uint32_t size_of_zero_fill;
    uint32_t characteristics;
    std::vector<uint64_t> callback_rvas;
};

struct relocation_block_t {
    uint32_t page_rva;
    std::vector<uint16_t> entries;
};

struct exception_entry_t {
    uint32_t begin_address;
    uint32_t end_address;
    uint32_t unwind_info;
};

struct delay_import_t {
    std::string dll_name;
    uint32_t attributes;
    uint32_t module_handle_rva;
    uint32_t iat_rva;
    uint32_t int_rva;
    uint32_t bound_iat_rva;
    uint32_t unload_iat_rva;
    uint32_t timestamp;
};

struct export_entry_t {
    uint32_t ordinal;
    uint32_t func_rva;
    std::string name;
    bool has_name;
    bool is_forwarder;
    std::string forwarder_string;
};

struct resource_entry_t {
    uint32_t type_id;
    uint32_t name_id;
    uint32_t lang_id;
    uint32_t data_rva;
    uint32_t size;
    uint32_t codepage;
    bool type_is_string;
    std::wstring type_string;
    bool name_is_string;
    std::wstring name_string;
};

struct import_record_t {
    std::string dll;
    std::string api;
    uint16_t ordinal;
    uint32_t iat_rva;
    bool by_ordinal;
    bool delay_loaded;
};

struct pe_image_t {
    std::vector<uint8_t> raw_file;
    IMAGE_DOS_HEADER dos_header;
    std::vector<uint8_t> dos_stub;
    bool has_rich_header;
    uint32_t rich_offset;
    uint32_t rich_size;
    uint32_t pe_signature;
    IMAGE_FILE_HEADER file_header;
    IMAGE_OPTIONAL_HEADER64 optional_header;
    data_directory_t data_directories[16];
    std::vector<section_t> sections;
    std::vector<import_descriptor_t> imports;
    std::vector<delay_import_t> delay_imports;
    std::vector<relocation_block_t> relocations;
    std::vector<exception_entry_t> exceptions;
    tls_directory_t tls;
    bool has_tls;
    bool is_dll;
    std::vector<resource_entry_t> resources;
    std::vector<export_entry_t> exports;

    uint32_t rva_to_offset(uint32_t rva) const {
        for (const auto& sec : sections) {
            if (rva >= sec.virtual_address && rva < sec.virtual_address + sec.virtual_size) {
                return sec.raw_offset + (rva - sec.virtual_address);
            }
        }
        return 0;
    }

    section_t* section_from_rva(uint32_t rva) {
        for (auto& sec : sections) {
            uint32_t sec_end = sec.virtual_address + (std::max)(sec.virtual_size, sec.raw_size);
            if (rva >= sec.virtual_address && rva < sec_end) {
                return &sec;
            }
        }
        return nullptr;
    }

    const section_t* section_from_rva(uint32_t rva) const {
        for (const auto& sec : sections) {
            uint32_t sec_end = sec.virtual_address + (std::max)(sec.virtual_size, sec.raw_size);
            if (rva >= sec.virtual_address && rva < sec_end) {
                return &sec;
            }
        }
        return nullptr;
    }

    uint32_t next_section_rva() const {
        uint32_t sa = section_alignment();
        if (sections.empty()) {
            return align_up(optional_header.SizeOfHeaders, sa);
        }
        uint32_t highest = 0;
        for (const auto& sec : sections) {
            uint32_t end = sec.virtual_address + align_up((std::max)(sec.virtual_size, sec.raw_size), sa);
            if (end > highest) {
                highest = end;
            }
        }
        return highest;
    }

    uint32_t file_alignment() const {
        return optional_header.FileAlignment;
    }

    uint32_t section_alignment() const {
        return optional_header.SectionAlignment;
    }

    uint8_t* rva_ptr(uint32_t rva) {
        for (auto& sec : sections) {
            uint32_t sec_end = sec.virtual_address + static_cast<uint32_t>(sec.data.size());
            if (rva >= sec.virtual_address && rva < sec_end) {
                return sec.data.data() + (rva - sec.virtual_address);
            }
        }
        return nullptr;
    }

    const uint8_t* rva_ptr(uint32_t rva) const {
        for (const auto& sec : sections) {
            uint32_t sec_end = sec.virtual_address + static_cast<uint32_t>(sec.data.size());
            if (rva >= sec.virtual_address && rva < sec_end) {
                return sec.data.data() + (rva - sec.virtual_address);
            }
        }
        return nullptr;
    }

    const IMAGE_SECTION_HEADER* section_for_rva(uint32_t rva) const {
        const section_t* s = section_from_rva(rva);
        if (!s) {
            return nullptr;
        }
        thread_local IMAGE_SECTION_HEADER hdr;
        std::memset(&hdr, 0, sizeof(hdr));
        std::memcpy(hdr.Name, s->name, 8);
        hdr.Misc.VirtualSize = s->virtual_size;
        hdr.VirtualAddress = s->virtual_address;
        hdr.SizeOfRawData = s->raw_size;
        hdr.PointerToRawData = s->raw_offset;
        hdr.PointerToRelocations = s->reloc_offset;
        hdr.NumberOfRelocations = static_cast<uint16_t>(s->reloc_count);
        hdr.PointerToLinenumbers = static_cast<uint32_t>(s->line_offset);
        hdr.NumberOfLinenumbers = s->line_count;
        hdr.Characteristics = s->characteristics;
        return &hdr;
    }

    std::vector<import_record_t> parse_imports_full() const {
        std::vector<import_record_t> out;

        if (data_directories[1].rva != 0 && data_directories[1].size != 0) {
            uint32_t desc_rva = data_directories[1].rva;
            for (;;) {
                const uint8_t* dp = rva_ptr(desc_rva);
                if (!dp) {
                    break;
                }
                IMAGE_IMPORT_DESCRIPTOR desc{};
                std::memcpy(&desc, dp, sizeof(desc));
                if (desc.Name == 0 && desc.FirstThunk == 0) {
                    break;
                }
                std::string dllname;
                const uint8_t* np = rva_ptr(desc.Name);
                if (np) {
                    dllname = reinterpret_cast<const char*>(np);
                }
                uint32_t thunk_rva = (desc.OriginalFirstThunk != 0) ? desc.OriginalFirstThunk : desc.FirstThunk;
                uint32_t iat_rva = desc.FirstThunk;
                for (uint32_t idx = 0; ; ++idx) {
                    const uint8_t* tp = rva_ptr(thunk_rva + idx * 8);
                    if (!tp) {
                        break;
                    }
                    uint64_t tv = 0;
                    std::memcpy(&tv, tp, 8);
                    if (tv == 0) {
                        break;
                    }
                    import_record_t r{};
                    r.dll = dllname;
                    r.ordinal = 0;
                    r.iat_rva = iat_rva + idx * 8;
                    r.delay_loaded = false;
                    if (tv & (1ULL << 63)) {
                        r.by_ordinal = true;
                        r.ordinal = static_cast<uint16_t>(tv & 0xFFFFu);
                    } else {
                        r.by_ordinal = false;
                        uint32_t hint_rva = static_cast<uint32_t>(tv & 0x7FFFFFFFu);
                        const uint8_t* hp = rva_ptr(hint_rva);
                        if (hp) {
                            uint16_t hint = 0;
                            std::memcpy(&hint, hp, 2);
                            r.ordinal = hint;
                            r.api = reinterpret_cast<const char*>(hp + 2);
                        }
                    }
                    out.push_back(std::move(r));
                }
                desc_rva += sizeof(IMAGE_IMPORT_DESCRIPTOR);
            }
        }

        if (data_directories[13].rva != 0 && data_directories[13].size != 0) {
            uint32_t desc_rva = data_directories[13].rva;
            for (;;) {
                const uint8_t* dp = rva_ptr(desc_rva);
                if (!dp) {
                    break;
                }
                uint32_t attrs = 0, name_rva = 0, hmod = 0, iat = 0, int_rva = 0;
                std::memcpy(&attrs, dp, 4);
                std::memcpy(&name_rva, dp + 4, 4);
                std::memcpy(&hmod, dp + 8, 4);
                std::memcpy(&iat, dp + 12, 4);
                std::memcpy(&int_rva, dp + 16, 4);
                if (name_rva == 0 && iat == 0) {
                    break;
                }
                std::string dllname;
                const uint8_t* np = rva_ptr(name_rva);
                if (np) {
                    dllname = reinterpret_cast<const char*>(np);
                }
                uint32_t walk_rva = (int_rva != 0) ? int_rva : iat;
                for (uint32_t idx = 0; ; ++idx) {
                    const uint8_t* tp = rva_ptr(walk_rva + idx * 8);
                    if (!tp) {
                        break;
                    }
                    uint64_t tv = 0;
                    std::memcpy(&tv, tp, 8);
                    if (tv == 0) {
                        break;
                    }
                    import_record_t r{};
                    r.dll = dllname;
                    r.ordinal = 0;
                    r.iat_rva = iat + idx * 8;
                    r.delay_loaded = true;
                    if (tv & (1ULL << 63)) {
                        r.by_ordinal = true;
                        r.ordinal = static_cast<uint16_t>(tv & 0xFFFFu);
                    } else {
                        r.by_ordinal = false;
                        uint32_t hint_rva = static_cast<uint32_t>(tv & 0x7FFFFFFFu);
                        const uint8_t* hp = rva_ptr(hint_rva);
                        if (hp) {
                            uint16_t hint = 0;
                            std::memcpy(&hint, hp, 2);
                            r.ordinal = hint;
                            r.api = reinterpret_cast<const char*>(hp + 2);
                        }
                    }
                    out.push_back(std::move(r));
                }
                desc_rva += 32;
            }
        }

        return out;
    }

    bool erase_import_directories() {
        if (data_directories[1].rva != 0 && data_directories[1].size != 0) {
            uint32_t desc_rva = data_directories[1].rva;
            for (;;) {
                uint8_t* dp = rva_ptr(desc_rva);
                if (!dp) {
                    break;
                }
                IMAGE_IMPORT_DESCRIPTOR desc{};
                std::memcpy(&desc, dp, sizeof(desc));
                if (desc.Name == 0 && desc.FirstThunk == 0) {
                    std::memset(dp, 0, sizeof(IMAGE_IMPORT_DESCRIPTOR));
                    break;
                }
                if (desc.Name != 0) {
                    uint8_t* q = rva_ptr(desc.Name);
                    if (q) {
                        while (*q != 0) {
                            *q = 0;
                            ++q;
                        }
                    }
                }
                uint32_t thunk_rva = (desc.OriginalFirstThunk != 0) ? desc.OriginalFirstThunk : desc.FirstThunk;
                for (uint32_t idx = 0; ; ++idx) {
                    uint8_t* tp = rva_ptr(thunk_rva + idx * 8);
                    if (!tp) {
                        break;
                    }
                    uint64_t tv = 0;
                    std::memcpy(&tv, tp, 8);
                    if (tv == 0) {
                        break;
                    }
                    if (!(tv & (1ULL << 63))) {
                        uint32_t hint_rva = static_cast<uint32_t>(tv & 0x7FFFFFFFu);
                        uint8_t* hp = rva_ptr(hint_rva);
                        if (hp) {
                            hp[0] = 0;
                            hp[1] = 0;
                            uint8_t* q = hp + 2;
                            while (*q != 0) {
                                *q = 0;
                                ++q;
                            }
                        }
                    }
                    std::memset(tp, 0, 8);
                }
                if (desc.FirstThunk != 0 && desc.FirstThunk != thunk_rva) {
                    for (uint32_t idx = 0; ; ++idx) {
                        uint8_t* tp = rva_ptr(desc.FirstThunk + idx * 8);
                        if (!tp) {
                            break;
                        }
                        uint64_t tv = 0;
                        std::memcpy(&tv, tp, 8);
                        if (tv == 0) {
                            break;
                        }
                        std::memset(tp, 0, 8);
                    }
                } else if (desc.FirstThunk != 0) {
                    for (uint32_t idx = 0; ; ++idx) {
                        uint8_t* tp = rva_ptr(desc.FirstThunk + idx * 8);
                        if (!tp) {
                            break;
                        }
                        uint64_t tv = 0;
                        std::memcpy(&tv, tp, 8);
                        if (tv == 0) {
                            break;
                        }
                        std::memset(tp, 0, 8);
                    }
                }
                std::memset(dp, 0, sizeof(IMAGE_IMPORT_DESCRIPTOR));
                desc_rva += sizeof(IMAGE_IMPORT_DESCRIPTOR);
            }
            data_directories[1].rva = 0;
            data_directories[1].size = 0;
            optional_header.DataDirectory[1].VirtualAddress = 0;
            optional_header.DataDirectory[1].Size = 0;
        }

        if (data_directories[13].rva != 0 && data_directories[13].size != 0) {
            uint32_t desc_rva = data_directories[13].rva;
            for (;;) {
                uint8_t* dp = rva_ptr(desc_rva);
                if (!dp) {
                    break;
                }
                uint32_t attrs = 0, name_rva = 0, hmod = 0, iat = 0, int_rva = 0;
                std::memcpy(&attrs, dp, 4);
                std::memcpy(&name_rva, dp + 4, 4);
                std::memcpy(&hmod, dp + 8, 4);
                std::memcpy(&iat, dp + 12, 4);
                std::memcpy(&int_rva, dp + 16, 4);
                if (name_rva == 0 && iat == 0) {
                    std::memset(dp, 0, 32);
                    break;
                }
                if (name_rva != 0) {
                    uint8_t* q = rva_ptr(name_rva);
                    if (q) {
                        while (*q != 0) {
                            *q = 0;
                            ++q;
                        }
                    }
                }
                if (int_rva != 0) {
                    for (uint32_t idx = 0; ; ++idx) {
                        uint8_t* tp = rva_ptr(int_rva + idx * 8);
                        if (!tp) {
                            break;
                        }
                        uint64_t tv = 0;
                        std::memcpy(&tv, tp, 8);
                        if (tv == 0) {
                            break;
                        }
                        if (!(tv & (1ULL << 63))) {
                            uint32_t hint_rva = static_cast<uint32_t>(tv & 0x7FFFFFFFu);
                            uint8_t* hp = rva_ptr(hint_rva);
                            if (hp) {
                                hp[0] = 0;
                                hp[1] = 0;
                                uint8_t* q = hp + 2;
                                while (*q != 0) {
                                    *q = 0;
                                    ++q;
                                }
                            }
                        }
                        std::memset(tp, 0, 8);
                    }
                }
                if (iat != 0) {
                    for (uint32_t idx = 0; ; ++idx) {
                        uint8_t* tp = rva_ptr(iat + idx * 8);
                        if (!tp) {
                            break;
                        }
                        uint64_t tv = 0;
                        std::memcpy(&tv, tp, 8);
                        if (tv == 0) {
                            break;
                        }
                        std::memset(tp, 0, 8);
                    }
                }
                std::memset(dp, 0, 32);
                desc_rva += 32;
            }
            data_directories[13].rva = 0;
            data_directories[13].size = 0;
            optional_header.DataDirectory[13].VirtualAddress = 0;
            optional_header.DataDirectory[13].Size = 0;
        }

        imports.clear();
        delay_imports.clear();
        return true;
    }
};

inline void parse_imports(pe_image_t& pe);
inline void parse_relocations(pe_image_t& pe);
inline void parse_exceptions(pe_image_t& pe);
inline void parse_tls(pe_image_t& pe);
inline void parse_delay_imports(pe_image_t& pe);
inline void parse_resources(pe_image_t& pe);
inline void parse_exports(pe_image_t& pe);
inline void recalculate_headers(pe_image_t& pe);

inline pe_image_t load(const std::vector<uint8_t>& buffer) {
    pe_image_t pe{};
    std::memset(&pe.dos_header, 0, sizeof(pe.dos_header));
    std::memset(&pe.file_header, 0, sizeof(pe.file_header));
    std::memset(&pe.optional_header, 0, sizeof(pe.optional_header));
    std::memset(&pe.tls, 0, sizeof(tls_directory_t));
    std::memset(pe.data_directories, 0, sizeof(pe.data_directories));
    pe.has_rich_header = false;
    pe.rich_offset = 0;
    pe.rich_size = 0;
    pe.pe_signature = 0;
    pe.has_tls = false;
    pe.is_dll = false;

    size_t file_size = buffer.size();
    if (file_size < sizeof(IMAGE_DOS_HEADER)) {
        throw std::runtime_error("Buffer too small for DOS header");
    }

    pe.raw_file = buffer;

    std::memcpy(&pe.dos_header, pe.raw_file.data(), sizeof(IMAGE_DOS_HEADER));
    if (pe.dos_header.e_magic != IMAGE_DOS_SIGNATURE) {
        throw std::runtime_error("Invalid DOS signature");
    }

    uint32_t e_lfanew = static_cast<uint32_t>(pe.dos_header.e_lfanew);
    if (e_lfanew < 64 || e_lfanew >= file_size) {
        throw std::runtime_error("Invalid e_lfanew value");
    }

    if (e_lfanew > 64) {
        pe.dos_stub.resize(e_lfanew - 64);
        std::memcpy(pe.dos_stub.data(), pe.raw_file.data() + 64, e_lfanew - 64);
    }

    pe.has_rich_header = false;
    pe.rich_offset = 0;
    pe.rich_size = 0;

    if (pe.dos_stub.size() >= 8) {
        uint32_t rich_pos = 0;
        bool found_rich = false;
        for (int32_t i = static_cast<int32_t>(pe.dos_stub.size()) - 4; i >= 0; i--) {
            uint32_t val = 0;
            std::memcpy(&val, pe.dos_stub.data() + i, 4);
            if (val == 0x68636952) {
                rich_pos = static_cast<uint32_t>(i);
                found_rich = true;
                break;
            }
        }

        if (found_rich && rich_pos + 8 <= pe.dos_stub.size()) {
            uint32_t xor_key = 0;
            std::memcpy(&xor_key, pe.dos_stub.data() + rich_pos + 4, 4);

            uint32_t dans_sig = 0x536E6144 ^ xor_key;
            bool found_dans = false;
            uint32_t dans_pos = 0;

            for (int32_t i = static_cast<int32_t>(rich_pos) - 4; i >= 0; i--) {
                uint32_t val = 0;
                std::memcpy(&val, pe.dos_stub.data() + i, 4);
                if (val == dans_sig) {
                    dans_pos = static_cast<uint32_t>(i);
                    found_dans = true;
                    break;
                }
            }

            if (found_dans) {
                pe.has_rich_header = true;
                pe.rich_offset = dans_pos;
                pe.rich_size = (rich_pos + 8) - dans_pos;
            }
        }
    }

    if (e_lfanew + 4 > file_size) {
        throw std::runtime_error("File too small for PE signature");
    }

    std::memcpy(&pe.pe_signature, pe.raw_file.data() + e_lfanew, 4);
    if (pe.pe_signature != IMAGE_NT_SIGNATURE) {
        throw std::runtime_error("Invalid PE signature");
    }

    uint32_t fh_offset = e_lfanew + 4;
    if (fh_offset + sizeof(IMAGE_FILE_HEADER) > file_size) {
        throw std::runtime_error("File too small for file header");
    }
    std::memcpy(&pe.file_header, pe.raw_file.data() + fh_offset, sizeof(IMAGE_FILE_HEADER));

    uint32_t oh_offset = fh_offset + sizeof(IMAGE_FILE_HEADER);
    if (oh_offset + sizeof(IMAGE_OPTIONAL_HEADER64) > file_size) {
        throw std::runtime_error("File too small for optional header");
    }
    std::memcpy(&pe.optional_header, pe.raw_file.data() + oh_offset, sizeof(IMAGE_OPTIONAL_HEADER64));

    if (pe.optional_header.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        throw std::runtime_error("Not a PE32+ (x64) image");
    }

    uint32_t num_dirs = pe.optional_header.NumberOfRvaAndSizes;
    if (num_dirs > 16) {
        num_dirs = 16;
    }
    for (uint32_t i = 0; i < num_dirs; i++) {
        pe.data_directories[i].rva = pe.optional_header.DataDirectory[i].VirtualAddress;
        pe.data_directories[i].size = pe.optional_header.DataDirectory[i].Size;
    }

    uint32_t sh_offset = oh_offset + pe.file_header.SizeOfOptionalHeader;
    uint32_t num_sections = pe.file_header.NumberOfSections;

    for (uint32_t i = 0; i < num_sections; i++) {
        uint32_t hdr_off = sh_offset + i * sizeof(IMAGE_SECTION_HEADER);
        if (hdr_off + sizeof(IMAGE_SECTION_HEADER) > file_size) {
            throw std::runtime_error("File too small for section header");
        }

        IMAGE_SECTION_HEADER sh{};
        std::memcpy(&sh, pe.raw_file.data() + hdr_off, sizeof(IMAGE_SECTION_HEADER));

        section_t sec{};
        std::memcpy(sec.name, sh.Name, 8);
        sec.virtual_size = sh.Misc.VirtualSize;
        sec.virtual_address = sh.VirtualAddress;
        sec.raw_size = sh.SizeOfRawData;
        sec.raw_offset = sh.PointerToRawData;
        sec.characteristics = sh.Characteristics;
        sec.reloc_offset = sh.PointerToRelocations;
        sec.reloc_count = sh.NumberOfRelocations;
        sec.line_offset = static_cast<uint16_t>(sh.PointerToLinenumbers & 0xFFFF);
        sec.line_count = sh.NumberOfLinenumbers;

        if (sec.raw_size > 0 && sec.raw_offset > 0) {
            uint32_t read_size = sec.raw_size;
            if (sec.raw_offset + read_size > file_size) {
                if (sec.raw_offset < file_size) {
                    read_size = static_cast<uint32_t>(file_size - sec.raw_offset);
                } else {
                    read_size = 0;
                }
            }
            if (read_size > 0) {
                sec.data.resize(sec.raw_size, 0);
                std::memcpy(sec.data.data(), pe.raw_file.data() + sec.raw_offset, read_size);
            }
        }

        pe.sections.push_back(std::move(sec));
    }

    pe.is_dll = (pe.file_header.Characteristics & IMAGE_FILE_DLL) != 0;

    parse_imports(pe);
    parse_relocations(pe);
    parse_exceptions(pe);
    parse_tls(pe);
    parse_delay_imports(pe);
    parse_resources(pe);
    parse_exports(pe);

    return pe;
}

inline pe_image_t load(const std::string& path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open file: " + path);
    }

    auto file_size = static_cast<size_t>(file.tellg());
    if (file_size < sizeof(IMAGE_DOS_HEADER)) {
        throw std::runtime_error("File too small for DOS header");
    }

    std::vector<uint8_t> buffer(file_size);
    file.seekg(0, std::ios::beg);
    file.read(reinterpret_cast<char*>(buffer.data()), file_size);
    file.close();

    return load(buffer);
}

inline void parse_imports(pe_image_t& pe) {
    pe.imports.clear();

    if (pe.data_directories[1].rva == 0 || pe.data_directories[1].size == 0) {
        return;
    }

    const uint8_t* base = pe.rva_ptr(pe.data_directories[1].rva);
    if (!base) {
        return;
    }

    uint32_t desc_rva = pe.data_directories[1].rva;
    for (;;) {
        const uint8_t* desc_ptr = pe.rva_ptr(desc_rva);
        if (!desc_ptr) {
            break;
        }

        IMAGE_IMPORT_DESCRIPTOR desc{};
        std::memcpy(&desc, desc_ptr, sizeof(IMAGE_IMPORT_DESCRIPTOR));

        if (desc.Name == 0 && desc.FirstThunk == 0) {
            break;
        }

        import_descriptor_t imp_desc{};
        imp_desc.original_first_thunk_rva = desc.OriginalFirstThunk;
        imp_desc.first_thunk_rva = desc.FirstThunk;

        const uint8_t* name_ptr = pe.rva_ptr(desc.Name);
        if (name_ptr) {
            imp_desc.dll_name = reinterpret_cast<const char*>(name_ptr);
        }

        uint32_t thunk_rva = (desc.OriginalFirstThunk != 0) ? desc.OriginalFirstThunk : desc.FirstThunk;
        uint32_t iat_rva = desc.FirstThunk;

        for (uint32_t idx = 0; ; idx++) {
            const uint8_t* thunk_ptr = pe.rva_ptr(thunk_rva + idx * 8);
            if (!thunk_ptr) {
                break;
            }

            uint64_t thunk_val = 0;
            std::memcpy(&thunk_val, thunk_ptr, 8);
            if (thunk_val == 0) {
                break;
            }

            import_entry_t entry{};
            entry.dll_name = imp_desc.dll_name;
            entry.iat_rva = iat_rva + idx * 8;
            entry.ilt_rva = thunk_rva + idx * 8;

            if (thunk_val & (1ULL << 63)) {
                entry.by_ordinal = true;
                entry.ordinal = static_cast<uint16_t>(thunk_val & 0xFFFF);
            } else {
                entry.by_ordinal = false;
                entry.ordinal = 0;
                uint32_t hint_rva = static_cast<uint32_t>(thunk_val & 0x7FFFFFFF);
                const uint8_t* hint_name = pe.rva_ptr(hint_rva);
                if (hint_name) {
                    uint16_t hint = 0;
                    std::memcpy(&hint, hint_name, 2);
                    entry.ordinal = hint;
                    entry.func_name = reinterpret_cast<const char*>(hint_name + 2);
                }
            }

            imp_desc.entries.push_back(std::move(entry));
        }

        pe.imports.push_back(std::move(imp_desc));
        desc_rva += sizeof(IMAGE_IMPORT_DESCRIPTOR);
    }
}

inline void parse_relocations(pe_image_t& pe) {
    pe.relocations.clear();

    if (pe.data_directories[5].rva == 0 || pe.data_directories[5].size == 0) {
        return;
    }

    uint32_t reloc_rva = pe.data_directories[5].rva;
    uint32_t reloc_end = reloc_rva + pe.data_directories[5].size;

    while (reloc_rva < reloc_end) {
        const uint8_t* block_ptr = pe.rva_ptr(reloc_rva);
        if (!block_ptr) {
            break;
        }

        uint32_t page_rva = 0;
        uint32_t block_size = 0;
        std::memcpy(&page_rva, block_ptr, 4);
        std::memcpy(&block_size, block_ptr + 4, 4);

        if (block_size == 0 || block_size < 8) {
            break;
        }

        relocation_block_t block{};
        block.page_rva = page_rva;

        uint32_t num_entries = (block_size - 8) / 2;
        const uint8_t* entries_ptr = block_ptr + 8;

        for (uint32_t i = 0; i < num_entries; i++) {
            uint16_t entry = 0;
            std::memcpy(&entry, entries_ptr + i * 2, 2);
            block.entries.push_back(entry);
        }

        pe.relocations.push_back(std::move(block));
        reloc_rva += block_size;
    }
}

inline void parse_exceptions(pe_image_t& pe) {
    pe.exceptions.clear();

    if (pe.data_directories[3].rva == 0 || pe.data_directories[3].size == 0) {
        return;
    }

    uint32_t count = pe.data_directories[3].size / 12;
    uint32_t exc_rva = pe.data_directories[3].rva;

    for (uint32_t i = 0; i < count; i++) {
        const uint8_t* ptr = pe.rva_ptr(exc_rva + i * 12);
        if (!ptr) {
            break;
        }

        exception_entry_t entry{};
        std::memcpy(&entry.begin_address, ptr, 4);
        std::memcpy(&entry.end_address, ptr + 4, 4);
        std::memcpy(&entry.unwind_info, ptr + 8, 4);
        pe.exceptions.push_back(entry);
    }
}

inline void parse_tls(pe_image_t& pe) {
    pe.has_tls = false;
    pe.tls = tls_directory_t{};

    if (pe.data_directories[9].rva == 0 || pe.data_directories[9].size == 0) {
        return;
    }

    const uint8_t* tls_ptr = pe.rva_ptr(pe.data_directories[9].rva);
    if (!tls_ptr) {
        return;
    }

    IMAGE_TLS_DIRECTORY64 tls_dir{};
    std::memcpy(&tls_dir, tls_ptr, sizeof(IMAGE_TLS_DIRECTORY64));

    pe.tls.raw_data_start = tls_dir.StartAddressOfRawData;
    pe.tls.raw_data_end = tls_dir.EndAddressOfRawData;
    pe.tls.address_of_index = tls_dir.AddressOfIndex;
    pe.tls.address_of_callbacks = tls_dir.AddressOfCallBacks;
    pe.tls.size_of_zero_fill = tls_dir.SizeOfZeroFill;
    pe.tls.characteristics = tls_dir.Characteristics;
    pe.has_tls = true;

    if (tls_dir.AddressOfCallBacks != 0) {
        uint64_t image_base = pe.optional_header.ImageBase;
        if (tls_dir.AddressOfCallBacks >= image_base) {
            uint32_t cb_rva = static_cast<uint32_t>(tls_dir.AddressOfCallBacks - image_base);
            for (uint32_t idx = 0; ; idx++) {
                const uint8_t* cb_ptr = pe.rva_ptr(cb_rva + idx * 8);
                if (!cb_ptr) {
                    break;
                }
                uint64_t cb_va = 0;
                std::memcpy(&cb_va, cb_ptr, 8);
                if (cb_va == 0) {
                    break;
                }
                pe.tls.callback_rvas.push_back(cb_va);
            }
        }
    }
}

inline void parse_delay_imports(pe_image_t& pe) {
    pe.delay_imports.clear();

    if (pe.data_directories[13].rva == 0 || pe.data_directories[13].size == 0) {
        return;
    }

    uint32_t desc_rva = pe.data_directories[13].rva;
    for (;;) {
        const uint8_t* ptr = pe.rva_ptr(desc_rva);
        if (!ptr) {
            break;
        }

        uint32_t attrs = 0, dll_name_rva = 0, hmod_rva = 0, iat = 0, int_rva = 0;
        uint32_t bound_iat = 0, unload_iat = 0, ts = 0;
        std::memcpy(&attrs, ptr, 4);
        std::memcpy(&dll_name_rva, ptr + 4, 4);
        std::memcpy(&hmod_rva, ptr + 8, 4);
        std::memcpy(&iat, ptr + 12, 4);
        std::memcpy(&int_rva, ptr + 16, 4);
        std::memcpy(&bound_iat, ptr + 20, 4);
        std::memcpy(&unload_iat, ptr + 24, 4);
        std::memcpy(&ts, ptr + 28, 4);

        if (dll_name_rva == 0) {
            break;
        }

        delay_import_t di{};
        di.attributes = attrs;
        di.module_handle_rva = hmod_rva;
        di.iat_rva = iat;
        di.int_rva = int_rva;
        di.bound_iat_rva = bound_iat;
        di.unload_iat_rva = unload_iat;
        di.timestamp = ts;

        const uint8_t* name_ptr = pe.rva_ptr(dll_name_rva);
        if (name_ptr) {
            di.dll_name = reinterpret_cast<const char*>(name_ptr);
        }

        pe.delay_imports.push_back(std::move(di));
        desc_rva += 32;
    }
}

inline void parse_resources(pe_image_t& pe) {
    pe.resources.clear();
    uint32_t rsrc_rva = pe.data_directories[2].rva;
    uint32_t rsrc_size = pe.data_directories[2].size;
    if (rsrc_rva == 0 || rsrc_size == 0) {
        return;
    }
    const uint8_t* base = pe.rva_ptr(rsrc_rva);
    if (!base) {
        return;
    }
    const uint32_t base_size = rsrc_size;

    auto read_u32 = [](const uint8_t* p) {
        uint32_t v = 0;
        std::memcpy(&v, p, 4);
        return v;
    };
    auto read_u16 = [](const uint8_t* p) {
        uint16_t v = 0;
        std::memcpy(&v, p, 2);
        return v;
    };
    auto read_str = [&](uint32_t offset) -> std::wstring {
        if (offset + 2 > base_size) {
            return {};
        }
        uint16_t len = read_u16(base + offset);
        std::wstring s;
        for (uint32_t i = 0; i < len; ++i) {
            if (offset + 2 + i * 2 + 2 > base_size) {
                break;
            }
            uint16_t ch = read_u16(base + offset + 2 + i * 2);
            s.push_back(static_cast<wchar_t>(ch));
        }
        return s;
    };

    struct frame_t {
        uint32_t type_id;
        uint32_t name_id;
        bool type_is_str;
        std::wstring type_str;
        bool name_is_str;
        std::wstring name_str;
    };

    auto walk = [&](auto& self, uint32_t dir_offset, int level, const frame_t& ctx) -> void {
        if (dir_offset + 16 > base_size) {
            return;
        }
        const uint8_t* dir = base + dir_offset;
        uint16_t num_named = read_u16(dir + 12);
        uint16_t num_id = read_u16(dir + 14);
        uint32_t total = static_cast<uint32_t>(num_named) + num_id;
        for (uint32_t i = 0; i < total; ++i) {
            uint32_t entry_off = dir_offset + 16u + i * 8u;
            if (entry_off + 8 > base_size) {
                break;
            }
            uint32_t name_field = read_u32(base + entry_off);
            uint32_t data_field = read_u32(base + entry_off + 4);
            bool is_dir = (data_field & 0x80000000u) != 0u;
            uint32_t off = data_field & 0x7FFFFFFFu;
            bool cur_is_str = (name_field & 0x80000000u) != 0u;
            uint32_t cur_id = name_field & 0x7FFFFFFFu;
            std::wstring cur_str;
            if (cur_is_str) {
                cur_str = read_str(cur_id);
            }
            if (level == 0) {
                if (is_dir) {
                    frame_t next = ctx;
                    next.type_id = cur_is_str ? 0u : cur_id;
                    next.type_is_str = cur_is_str;
                    next.type_str = cur_str;
                    self(self, off, 1, next);
                }
            } else if (level == 1) {
                if (is_dir) {
                    frame_t next = ctx;
                    next.name_id = cur_is_str ? 0u : cur_id;
                    next.name_is_str = cur_is_str;
                    next.name_str = cur_str;
                    self(self, off, 2, next);
                }
            } else {
                if (!is_dir && off + 16u <= base_size) {
                    resource_entry_t re{};
                    re.type_id = ctx.type_id;
                    re.name_id = ctx.name_id;
                    re.lang_id = cur_is_str ? 0u : cur_id;
                    re.data_rva = read_u32(base + off + 0);
                    re.size = read_u32(base + off + 4);
                    re.codepage = read_u32(base + off + 8);
                    re.type_is_string = ctx.type_is_str;
                    re.type_string = ctx.type_str;
                    re.name_is_string = ctx.name_is_str;
                    re.name_string = ctx.name_str;
                    pe.resources.push_back(std::move(re));
                }
            }
        }
    };

    frame_t root{};
    walk(walk, 0u, 0, root);
}

inline void parse_exports(pe_image_t& pe) {
    pe.exports.clear();
    uint32_t exp_rva = pe.data_directories[0].rva;
    uint32_t exp_size = pe.data_directories[0].size;
    if (exp_rva == 0 || exp_size == 0) {
        return;
    }
    const uint8_t* dir_ptr = pe.rva_ptr(exp_rva);
    if (!dir_ptr) {
        return;
    }
    IMAGE_EXPORT_DIRECTORY ed{};
    std::memcpy(&ed, dir_ptr, sizeof(ed));
    if (ed.AddressOfFunctions == 0 || ed.NumberOfFunctions == 0) {
        return;
    }
    uint32_t exp_end = exp_rva + exp_size;

    const uint8_t* funcs_ptr = pe.rva_ptr(ed.AddressOfFunctions);
    if (!funcs_ptr) {
        return;
    }
    const uint8_t* names_ptr = (ed.AddressOfNames != 0) ? pe.rva_ptr(ed.AddressOfNames) : nullptr;
    const uint8_t* ords_ptr = (ed.AddressOfNameOrdinals != 0) ? pe.rva_ptr(ed.AddressOfNameOrdinals) : nullptr;

    std::vector<std::string> ordinal_names(ed.NumberOfFunctions);
    std::vector<uint8_t> has_name_flags(ed.NumberOfFunctions, 0);
    if (names_ptr && ords_ptr) {
        for (uint32_t i = 0; i < ed.NumberOfNames; ++i) {
            uint32_t name_rva = 0;
            std::memcpy(&name_rva, names_ptr + i * 4, 4);
            uint16_t ord = 0;
            std::memcpy(&ord, ords_ptr + i * 2, 2);
            const uint8_t* n = pe.rva_ptr(name_rva);
            if (n && ord < ordinal_names.size()) {
                ordinal_names[ord] = reinterpret_cast<const char*>(n);
                has_name_flags[ord] = 1;
            }
        }
    }

    for (uint32_t i = 0; i < ed.NumberOfFunctions; ++i) {
        uint32_t func_rva = 0;
        std::memcpy(&func_rva, funcs_ptr + i * 4, 4);
        if (func_rva == 0) {
            continue;
        }
        export_entry_t e{};
        e.ordinal = i + ed.Base;
        e.func_rva = func_rva;
        if (i < ordinal_names.size() && has_name_flags[i]) {
            e.name = ordinal_names[i];
            e.has_name = true;
        } else {
            e.has_name = false;
        }
        e.is_forwarder = (func_rva >= exp_rva && func_rva < exp_end);
        if (e.is_forwarder) {
            const uint8_t* fp = pe.rva_ptr(func_rva);
            if (fp) {
                e.forwarder_string = reinterpret_cast<const char*>(fp);
            }
        }
        pe.exports.push_back(std::move(e));
    }
}

inline section_t& add_section(pe_image_t& pe, const char name[8], uint32_t characteristics, const std::vector<uint8_t>& data) {
    section_t sec{};
    std::memcpy(sec.name, name, 8);
    sec.characteristics = characteristics;
    sec.virtual_address = pe.next_section_rva();
    sec.virtual_size = static_cast<uint32_t>(data.size());
    sec.raw_size = align_up(static_cast<uint32_t>(data.size()), pe.file_alignment());
    if (sec.raw_size == 0 && !data.empty()) {
        sec.raw_size = pe.file_alignment();
    }
    sec.raw_offset = 0;
    sec.reloc_offset = 0;
    sec.reloc_count = 0;
    sec.line_offset = 0;
    sec.line_count = 0;
    sec.data = data;
    if (sec.data.size() < sec.raw_size) {
        sec.data.resize(sec.raw_size, 0);
    }

    pe.sections.push_back(std::move(sec));
    pe.file_header.NumberOfSections = static_cast<uint16_t>(pe.sections.size());

    recalculate_headers(pe);

    return pe.sections.back();
}

inline void recalculate_headers(pe_image_t& pe) {
    pe.file_header.NumberOfSections = static_cast<uint16_t>(pe.sections.size());

    uint32_t size_of_code = 0;
    uint32_t size_of_init = 0;
    uint32_t size_of_uninit = 0;

    for (const auto& sec : pe.sections) {
        if (sec.characteristics & IMAGE_SCN_CNT_CODE) {
            size_of_code += sec.raw_size;
        }
        if (sec.characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) {
            size_of_init += sec.raw_size;
        }
        if (sec.characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) {
            if (sec.virtual_size > sec.raw_size) {
                size_of_uninit += sec.virtual_size - sec.raw_size;
            } else {
                size_of_uninit += sec.virtual_size;
            }
        }
    }

    pe.optional_header.SizeOfCode = size_of_code;
    pe.optional_header.SizeOfInitializedData = size_of_init;
    pe.optional_header.SizeOfUninitializedData = size_of_uninit;

    uint32_t fa = pe.file_alignment();
    uint32_t sa = pe.section_alignment();

    uint32_t headers_raw = 64
        + static_cast<uint32_t>(pe.dos_stub.size())
        + 4
        + static_cast<uint32_t>(sizeof(IMAGE_FILE_HEADER))
        + static_cast<uint32_t>(sizeof(IMAGE_OPTIONAL_HEADER64))
        + static_cast<uint32_t>(pe.sections.size()) * static_cast<uint32_t>(sizeof(IMAGE_SECTION_HEADER));
    pe.optional_header.SizeOfHeaders = align_up(headers_raw, fa);

    uint32_t current_offset = pe.optional_header.SizeOfHeaders;
    for (auto& sec : pe.sections) {
        if (sec.raw_size == 0 || sec.data.empty()) {
            sec.raw_offset = 0;
        } else {
            sec.raw_offset = current_offset;
            current_offset += align_up(sec.raw_size, fa);
        }
    }

    if (!pe.sections.empty()) {
        uint32_t highest = 0;
        for (const auto& sec : pe.sections) {
            uint32_t end = sec.virtual_address + align_up((std::max)(sec.virtual_size, sec.raw_size), sa);
            if (end > highest) {
                highest = end;
            }
        }
        pe.optional_header.SizeOfImage = highest;
    } else {
        pe.optional_header.SizeOfImage = align_up(pe.optional_header.SizeOfHeaders, sa);
    }

    pe.optional_header.CheckSum = 0;
}

inline void write(const pe_image_t& pe, const std::string& path) {
    uint32_t fa = pe.file_alignment();

    uint32_t headers_raw = 64
        + static_cast<uint32_t>(pe.dos_stub.size())
        + 4
        + static_cast<uint32_t>(sizeof(IMAGE_FILE_HEADER))
        + static_cast<uint32_t>(sizeof(IMAGE_OPTIONAL_HEADER64))
        + static_cast<uint32_t>(pe.sections.size()) * static_cast<uint32_t>(sizeof(IMAGE_SECTION_HEADER));
    uint32_t aligned_headers = align_up(headers_raw, fa);

    struct section_layout_t {
        uint32_t raw_offset;
        uint32_t aligned_raw_size;
    };

    std::vector<section_layout_t> layouts(pe.sections.size());
    uint32_t current_offset = aligned_headers;
    for (size_t i = 0; i < pe.sections.size(); i++) {
        const auto& sec = pe.sections[i];
        if (sec.data.empty()) {
            layouts[i].raw_offset = 0;
            layouts[i].aligned_raw_size = 0;
        } else {
            layouts[i].raw_offset = current_offset;
            layouts[i].aligned_raw_size = align_up(static_cast<uint32_t>(sec.data.size()), fa);
            current_offset += layouts[i].aligned_raw_size;
        }
    }

    uint32_t total_size = current_offset;
    std::vector<uint8_t> output(total_size, 0);

    uint32_t pos = 0;

    IMAGE_DOS_HEADER dos = pe.dos_header;
    std::memcpy(output.data() + pos, &dos, sizeof(IMAGE_DOS_HEADER));
    pos += sizeof(IMAGE_DOS_HEADER);

    if (!pe.dos_stub.empty()) {
        std::memcpy(output.data() + pos, pe.dos_stub.data(), pe.dos_stub.size());
        pos += static_cast<uint32_t>(pe.dos_stub.size());
    }

    uint32_t pe_sig = IMAGE_NT_SIGNATURE;
    std::memcpy(output.data() + pos, &pe_sig, 4);
    pos += 4;

    IMAGE_FILE_HEADER fh = pe.file_header;
    fh.NumberOfSections = static_cast<uint16_t>(pe.sections.size());
    std::memcpy(output.data() + pos, &fh, sizeof(IMAGE_FILE_HEADER));
    pos += sizeof(IMAGE_FILE_HEADER);

    IMAGE_OPTIONAL_HEADER64 oh = pe.optional_header;

    uint32_t sa = oh.SectionAlignment;

    uint32_t sc = 0, si = 0, su = 0;
    for (size_t idx = 0; idx < pe.sections.size(); idx++) {
        const auto& sec = pe.sections[idx];
        if (sec.characteristics & IMAGE_SCN_CNT_CODE) {
            sc += layouts[idx].aligned_raw_size;
        }
        if (sec.characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) {
            si += layouts[idx].aligned_raw_size;
        }
        if (sec.characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) {
            if (sec.virtual_size > sec.raw_size) {
                su += sec.virtual_size - sec.raw_size;
            } else {
                su += sec.virtual_size;
            }
        }
    }

    oh.SizeOfCode = sc;
    oh.SizeOfInitializedData = si;
    oh.SizeOfUninitializedData = su;
    oh.SizeOfHeaders = aligned_headers;

    if (!pe.sections.empty()) {
        uint32_t highest = 0;
        for (const auto& sec : pe.sections) {
            uint32_t end = sec.virtual_address + align_up((std::max)(sec.virtual_size, sec.raw_size), sa);
            if (end > highest) {
                highest = end;
            }
        }
        oh.SizeOfImage = highest;
    } else {
        oh.SizeOfImage = align_up(aligned_headers, sa);
    }

    oh.CheckSum = 0;

    for (uint32_t i = 0; i < 16; i++) {
        oh.DataDirectory[i].VirtualAddress = pe.data_directories[i].rva;
        oh.DataDirectory[i].Size = pe.data_directories[i].size;
    }
    oh.NumberOfRvaAndSizes = 16;

    std::memcpy(output.data() + pos, &oh, sizeof(IMAGE_OPTIONAL_HEADER64));
    pos += sizeof(IMAGE_OPTIONAL_HEADER64);

    for (size_t i = 0; i < pe.sections.size(); i++) {
        const auto& sec = pe.sections[i];
        IMAGE_SECTION_HEADER sh{};
        std::memcpy(sh.Name, sec.name, 8);
        sh.Misc.VirtualSize = sec.virtual_size;
        sh.VirtualAddress = sec.virtual_address;
        sh.SizeOfRawData = layouts[i].aligned_raw_size;
        sh.PointerToRawData = layouts[i].raw_offset;
        sh.PointerToRelocations = sec.reloc_offset;
        sh.PointerToLinenumbers = static_cast<uint32_t>(sec.line_offset);
        sh.NumberOfRelocations = static_cast<uint16_t>(sec.reloc_count);
        sh.NumberOfLinenumbers = sec.line_count;
        sh.Characteristics = sec.characteristics;
        std::memcpy(output.data() + pos, &sh, sizeof(IMAGE_SECTION_HEADER));
        pos += sizeof(IMAGE_SECTION_HEADER);
    }

    for (size_t i = 0; i < pe.sections.size(); i++) {
        const auto& sec = pe.sections[i];
        if (sec.data.empty() || layouts[i].raw_offset == 0) {
            continue;
        }
        std::memcpy(output.data() + layouts[i].raw_offset, sec.data.data(), sec.data.size());
    }

    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out.is_open()) {
        throw std::runtime_error("Failed to open output file: " + path);
    }
    out.write(reinterpret_cast<const char*>(output.data()), output.size());
    out.close();
}

}
