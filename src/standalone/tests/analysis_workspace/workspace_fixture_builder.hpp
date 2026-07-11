#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include "../../src/core/analysis/workspace/baseline_pipeline.hpp"
#include "../../src/core/analysis/workspace/decompiler_service.hpp"
#include "../../src/core/analysis/workspace/overlay_journal.hpp"
#include "../../src/core/analysis/workspace/pe_baseline_analyzer.hpp"
#include "../../src/core/analysis/workspace/workspace_database.hpp"
#include "../../src/core/analysis/workspace/workspace_registry.hpp"

#include <algorithm>
#include <atomic>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace aida::analysis::test_fixture {

struct fixture_error_t final : std::runtime_error {
    using std::runtime_error::runtime_error;
};

inline std::filesystem::path unique_root(const std::string& label)
{
    static std::atomic<std::uint64_t> sequence{0};
    const auto value = sequence.fetch_add(1, std::memory_order_relaxed) + 1;
    return std::filesystem::temp_directory_path() /
        ("aida_workspace_" + label + "_" + std::to_string(GetCurrentProcessId()) + "_" +
         std::to_string(value));
}

inline std::vector<std::uint8_t> minimal_pe64(std::uint8_t discriminator)
{
    std::vector<std::uint8_t> bytes(0x400, 0);
    IMAGE_DOS_HEADER dos{};
    dos.e_magic = IMAGE_DOS_SIGNATURE;
    dos.e_lfanew = 0x80;
    std::memcpy(bytes.data(), &dos, sizeof(dos));

    IMAGE_NT_HEADERS64 nt{};
    nt.Signature = IMAGE_NT_SIGNATURE;
    nt.FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
    nt.FileHeader.NumberOfSections = 1;
    nt.FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
    nt.FileHeader.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE;
    nt.OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    nt.OptionalHeader.AddressOfEntryPoint = 0x1000;
    nt.OptionalHeader.BaseOfCode = 0x1000;
    nt.OptionalHeader.ImageBase = 0x140000000ULL;
    nt.OptionalHeader.SectionAlignment = 0x1000;
    nt.OptionalHeader.FileAlignment = 0x200;
    nt.OptionalHeader.MajorOperatingSystemVersion = 10;
    nt.OptionalHeader.MajorSubsystemVersion = 10;
    nt.OptionalHeader.SizeOfImage = 0x2000;
    nt.OptionalHeader.SizeOfHeaders = 0x200;
    nt.OptionalHeader.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_CUI;
    nt.OptionalHeader.DllCharacteristics = IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE |
        IMAGE_DLLCHARACTERISTICS_NX_COMPAT | IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA;
    nt.OptionalHeader.SizeOfStackReserve = 1ULL << 20;
    nt.OptionalHeader.SizeOfStackCommit = 4096;
    nt.OptionalHeader.SizeOfHeapReserve = 1ULL << 20;
    nt.OptionalHeader.SizeOfHeapCommit = 4096;
    nt.OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
    std::memcpy(bytes.data() + dos.e_lfanew, &nt, sizeof(nt));

    IMAGE_SECTION_HEADER section{};
    const char section_name[] = ".text";
    std::memcpy(section.Name, section_name, sizeof(section_name) - 1);
    section.Misc.VirtualSize = 0x200;
    section.VirtualAddress = 0x1000;
    section.SizeOfRawData = 0x200;
    section.PointerToRawData = 0x200;
    section.Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
    const std::size_t section_offset = static_cast<std::size_t>(dos.e_lfanew) +
        sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER64);
    std::memcpy(bytes.data() + section_offset, &section, sizeof(section));

    const std::uint8_t code[] = {0xB8, discriminator, 0x00, 0x00, 0x00, 0xC3};
    std::memcpy(bytes.data() + section.PointerToRawData, code, sizeof(code));
    const std::string marker = "AiDA workspace fixture " + std::to_string(discriminator);
    std::memcpy(bytes.data() + section.PointerToRawData + 0x40, marker.data(), marker.size());
    return bytes;
}

inline void fixture_store(std::vector<std::uint8_t>& bytes, std::size_t offset,
                          const void* source, std::size_t size)
{
    if ((size != 0 && source == nullptr) || offset > bytes.size() || size > bytes.size() - offset)
        throw fixture_error_t("fixture write exceeds its bounded image");
    if (size != 0)
        std::memcpy(bytes.data() + offset, source, size);
}

template <typename T>
inline void fixture_store(std::vector<std::uint8_t>& bytes, std::size_t offset,
                          const T& value)
{
    fixture_store(bytes, offset, &value, sizeof(value));
}

inline std::vector<std::uint8_t> analysis_contract_pe64(std::uint8_t discriminator)
{
    constexpr std::uint32_t headers_size = 0x400;
    constexpr std::uint32_t text_rva = 0x1000;
    constexpr std::uint32_t pdata_rva = 0x2000;
    constexpr std::uint32_t xdata_rva = 0x3000;
    constexpr std::uint32_t idata_rva = 0x4000;
    constexpr std::uint32_t reloc_rva = 0x5000;
    constexpr std::uint32_t text_raw = 0x400;
    constexpr std::uint32_t pdata_raw = 0x800;
    constexpr std::uint32_t xdata_raw = 0xA00;
    constexpr std::uint32_t idata_raw = 0xC00;
    constexpr std::uint32_t reloc_raw = 0xE00;

    std::vector<std::uint8_t> bytes(0x1000, 0);
    IMAGE_DOS_HEADER dos{};
    dos.e_magic = IMAGE_DOS_SIGNATURE;
    dos.e_lfanew = 0x80;
    fixture_store(bytes, 0, dos);

    IMAGE_NT_HEADERS64 nt{};
    nt.Signature = IMAGE_NT_SIGNATURE;
    nt.FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
    nt.FileHeader.NumberOfSections = 5;
    nt.FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
    nt.FileHeader.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE;
    nt.OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    nt.OptionalHeader.AddressOfEntryPoint = text_rva;
    nt.OptionalHeader.BaseOfCode = text_rva;
    nt.OptionalHeader.ImageBase = 0x140000000ULL;
    nt.OptionalHeader.SectionAlignment = 0x1000;
    nt.OptionalHeader.FileAlignment = 0x200;
    nt.OptionalHeader.MajorOperatingSystemVersion = 10;
    nt.OptionalHeader.MajorSubsystemVersion = 10;
    nt.OptionalHeader.SizeOfImage = 0x6000;
    nt.OptionalHeader.SizeOfHeaders = headers_size;
    nt.OptionalHeader.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_CUI;
    nt.OptionalHeader.DllCharacteristics = IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE |
        IMAGE_DLLCHARACTERISTICS_NX_COMPAT | IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA;
    nt.OptionalHeader.SizeOfStackReserve = 1ULL << 20;
    nt.OptionalHeader.SizeOfStackCommit = 4096;
    nt.OptionalHeader.SizeOfHeapReserve = 1ULL << 20;
    nt.OptionalHeader.SizeOfHeapCommit = 4096;
    nt.OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
    nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION] = {pdata_rva,
        2U * static_cast<DWORD>(sizeof(RUNTIME_FUNCTION))};
    nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT] = {idata_rva,
        2U * static_cast<DWORD>(sizeof(IMAGE_IMPORT_DESCRIPTOR))};
    nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT] = {idata_rva + 0x60, 16};
    nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC] = {reloc_rva, 12};
    fixture_store(bytes, static_cast<std::size_t>(dos.e_lfanew), nt);

    std::array<IMAGE_SECTION_HEADER, 5> sections{};
    const auto initialize_section = [](IMAGE_SECTION_HEADER& section, const char* name,
                                       std::uint32_t rva, std::uint32_t raw,
                                       std::uint32_t size, std::uint32_t characteristics) {
        const std::size_t name_size = (std::min<std::size_t>)(std::strlen(name), sizeof(section.Name));
        std::memcpy(section.Name, name, name_size);
        section.Misc.VirtualSize = size;
        section.VirtualAddress = rva;
        section.SizeOfRawData = size;
        section.PointerToRawData = raw;
        section.Characteristics = characteristics;
    };
    initialize_section(sections[0], ".text", text_rva, text_raw, 0x400,
        IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ);
    initialize_section(sections[1], ".pdata", pdata_rva, pdata_raw, 0x200,
        IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ);
    initialize_section(sections[2], ".xdata", xdata_rva, xdata_raw, 0x200,
        IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ);
    initialize_section(sections[3], ".idata", idata_rva, idata_raw, 0x200,
        IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE);
    initialize_section(sections[4], ".reloc", reloc_rva, reloc_raw, 0x200,
        IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_DISCARDABLE);
    const std::size_t section_offset = static_cast<std::size_t>(dos.e_lfanew) +
        sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER64);
    fixture_store(bytes, section_offset, sections.data(), sections.size() * sizeof(sections[0]));

    const std::array<std::uint8_t, 14> entry_code{{
        0xFF, 0x15, 0x5A, 0x30, 0x00, 0x00,
        0xB8, discriminator, 0x00, 0x00, 0x00, 0xC3, 0x90, 0xC3
    }};
    fixture_store(bytes, text_raw, entry_code.data(), entry_code.size());
    const std::array<std::uint8_t, 2> cold_code{{0x90, 0xC3}};
    fixture_store(bytes, text_raw + 0x20, cold_code.data(), cold_code.size());
    const std::array<std::uint8_t, 8> fs_code{{0x64, 0x8B, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00}};
    const std::array<std::uint8_t, 9> gs_code{{0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00}};
    fixture_store(bytes, text_raw + 0x60, fs_code.data(), fs_code.size());
    fixture_store(bytes, text_raw + 0x68, gs_code.data(), gs_code.size());
    bytes[text_raw + 0x80] = 0xC3;
    const std::uint64_t relocation_target = nt.OptionalHeader.ImageBase + 0x1006;
    fixture_store(bytes, text_raw + 0x100, relocation_target);
    const std::string marker = "AiDA analysis contract fixture " + std::to_string(discriminator);
    fixture_store(bytes, text_raw + 0x120, marker.data(), marker.size());

    RUNTIME_FUNCTION primary{};
    primary.BeginAddress = 0x1000;
    primary.EndAddress = 0x100C;
    primary.UnwindData = 0x3000;
    RUNTIME_FUNCTION chained_owner{};
    chained_owner.BeginAddress = 0x1020;
    chained_owner.EndAddress = 0x1022;
    chained_owner.UnwindData = 0x3020;
    fixture_store(bytes, pdata_raw, primary);
    fixture_store(bytes, pdata_raw + sizeof(primary), chained_owner);

    const std::array<std::uint8_t, 4> handler_unwind{{0x09, 0x00, 0x00, 0x00}};
    fixture_store(bytes, xdata_raw, handler_unwind.data(), handler_unwind.size());
    const std::uint32_t handler_rva = 0x1080;
    fixture_store(bytes, xdata_raw + 4, handler_rva);
    const std::array<std::uint8_t, 4> language_data{{0x41, 0x69, 0x44, 0x41}};
    fixture_store(bytes, xdata_raw + 8, language_data.data(), language_data.size());
    const std::array<std::uint8_t, 4> chained_unwind{{0x21, 0x00, 0x00, 0x00}};
    fixture_store(bytes, xdata_raw + 0x20, chained_unwind.data(), chained_unwind.size());
    fixture_store(bytes, xdata_raw + 0x24, primary);

    IMAGE_IMPORT_DESCRIPTOR import_descriptor{};
    import_descriptor.OriginalFirstThunk = idata_rva + 0x40;
    import_descriptor.Name = idata_rva + 0x80;
    import_descriptor.FirstThunk = idata_rva + 0x60;
    fixture_store(bytes, idata_raw, import_descriptor);
    const std::uint64_t import_name_rva = idata_rva + 0xA0;
    fixture_store(bytes, idata_raw + 0x40, import_name_rva);
    fixture_store(bytes, idata_raw + 0x60, import_name_rva);
    const char import_library[] = "KERNEL32.dll";
    fixture_store(bytes, idata_raw + 0x80, import_library, sizeof(import_library));
    const std::uint16_t import_hint = 0;
    fixture_store(bytes, idata_raw + 0xA0, import_hint);
    const char import_name[] = "ExitProcess";
    fixture_store(bytes, idata_raw + 0xA2, import_name, sizeof(import_name));

    IMAGE_BASE_RELOCATION relocation{};
    relocation.VirtualAddress = text_rva;
    relocation.SizeOfBlock = 12;
    fixture_store(bytes, reloc_raw, relocation);
    const std::uint16_t relocation_entry = static_cast<std::uint16_t>(
        (IMAGE_REL_BASED_DIR64 << 12) | 0x100);
    const std::uint16_t relocation_padding = 0;
    fixture_store(bytes, reloc_raw + sizeof(relocation), relocation_entry);
    fixture_store(bytes, reloc_raw + sizeof(relocation) + sizeof(relocation_entry),
                  relocation_padding);
    return bytes;
}

inline std::vector<std::uint8_t> minimal_pe32(std::uint8_t discriminator)
{
    std::vector<std::uint8_t> bytes(0x400, 0);
    IMAGE_DOS_HEADER dos{};
    dos.e_magic = IMAGE_DOS_SIGNATURE;
    dos.e_lfanew = 0x80;
    std::memcpy(bytes.data(), &dos, sizeof(dos));

    IMAGE_NT_HEADERS32 nt{};
    nt.Signature = IMAGE_NT_SIGNATURE;
    nt.FileHeader.Machine = IMAGE_FILE_MACHINE_I386;
    nt.FileHeader.NumberOfSections = 1;
    nt.FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER32);
    nt.FileHeader.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_32BIT_MACHINE;
    nt.OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
    nt.OptionalHeader.AddressOfEntryPoint = 0x1000;
    nt.OptionalHeader.BaseOfCode = 0x1000;
    nt.OptionalHeader.BaseOfData = 0x1000;
    nt.OptionalHeader.ImageBase = 0x00400000;
    nt.OptionalHeader.SectionAlignment = 0x1000;
    nt.OptionalHeader.FileAlignment = 0x200;
    nt.OptionalHeader.MajorOperatingSystemVersion = 6;
    nt.OptionalHeader.MajorSubsystemVersion = 6;
    nt.OptionalHeader.SizeOfImage = 0x2000;
    nt.OptionalHeader.SizeOfHeaders = 0x200;
    nt.OptionalHeader.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_CUI;
    nt.OptionalHeader.DllCharacteristics = IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE |
        IMAGE_DLLCHARACTERISTICS_NX_COMPAT;
    nt.OptionalHeader.SizeOfStackReserve = 1u << 20;
    nt.OptionalHeader.SizeOfStackCommit = 4096;
    nt.OptionalHeader.SizeOfHeapReserve = 1u << 20;
    nt.OptionalHeader.SizeOfHeapCommit = 4096;
    nt.OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
    std::memcpy(bytes.data() + dos.e_lfanew, &nt, sizeof(nt));

    IMAGE_SECTION_HEADER section{};
    const char section_name[] = ".text";
    std::memcpy(section.Name, section_name, sizeof(section_name) - 1);
    section.Misc.VirtualSize = 0x200;
    section.VirtualAddress = 0x1000;
    section.SizeOfRawData = 0x200;
    section.PointerToRawData = 0x200;
    section.Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
    const std::size_t section_offset = static_cast<std::size_t>(dos.e_lfanew) +
        sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER32);
    std::memcpy(bytes.data() + section_offset, &section, sizeof(section));

    const std::uint8_t code[] = {
        0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x04, 0xB8, discriminator,
        0x00, 0x00, 0x00, 0xC9, 0xC3
    };
    std::memcpy(bytes.data() + section.PointerToRawData, code, sizeof(code));
    const std::string marker = "AiDA x86 workspace fixture " + std::to_string(discriminator);
    std::memcpy(bytes.data() + section.PointerToRawData + 0x40, marker.data(), marker.size());
    return bytes;
}

enum class hostile_pe_variant_t : std::uint8_t {
    truncated_headers,
    raw_span_overflow,
    raw_section_overlap,
    virtual_section_overlap,
    raw_virtual_directory_gap,
    out_of_file_directory,
    impossible_section_count,
    invalid_dos_magic,
    invalid_pe_signature,
    zero_section_alignment,
    import_self_reference,
    overlay_beyond_last_section,
    zero_size_of_image,
    corrupt_optional_header_magic
};

inline std::vector<std::uint8_t> hostile_pe64(hostile_pe_variant_t variant)
{
    auto bytes = minimal_pe64(0x7F);
    IMAGE_DOS_HEADER dos{};
    std::memcpy(&dos, bytes.data(), sizeof(dos));
    IMAGE_NT_HEADERS64 nt{};
    std::memcpy(&nt, bytes.data() + dos.e_lfanew, sizeof(nt));
    const std::size_t section_offset = static_cast<std::size_t>(dos.e_lfanew) +
        sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER64);
    IMAGE_SECTION_HEADER first{};
    std::memcpy(&first, bytes.data() + section_offset, sizeof(first));
    IMAGE_SECTION_HEADER second = first;
    const char second_name[] = ".evil";
    std::memset(second.Name, 0, sizeof(second.Name));
    std::memcpy(second.Name, second_name, sizeof(second_name) - 1);

    switch (variant) {
    case hostile_pe_variant_t::truncated_headers:
        bytes.resize(64);
        return bytes;
    case hostile_pe_variant_t::raw_span_overflow:
        first.PointerToRawData = 0xFFFFFFF0u;
        first.SizeOfRawData = 0x200;
        break;
    case hostile_pe_variant_t::raw_section_overlap:
        nt.FileHeader.NumberOfSections = 2;
        second.PointerToRawData = 0x300;
        second.SizeOfRawData = 0x100;
        second.VirtualAddress = 0x1800;
        second.Misc.VirtualSize = 0x100;
        std::memcpy(bytes.data() + section_offset + sizeof(first), &second, sizeof(second));
        break;
    case hostile_pe_variant_t::virtual_section_overlap:
        nt.FileHeader.NumberOfSections = 2;
        second.PointerToRawData = 0;
        second.SizeOfRawData = 0;
        second.VirtualAddress = 0x1100;
        second.Misc.VirtualSize = 0x200;
        std::memcpy(bytes.data() + section_offset + sizeof(first), &second, sizeof(second));
        break;
    case hostile_pe_variant_t::raw_virtual_directory_gap:
        first.Misc.VirtualSize = 0x400;
        nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress = 0x1250;
        nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size = 0x20;
        break;
    case hostile_pe_variant_t::out_of_file_directory:
        nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress = 0x1000;
        nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size = 0x300;
        break;
    case hostile_pe_variant_t::impossible_section_count:
        nt.FileHeader.NumberOfSections = 0xFFFF;
        break;
    case hostile_pe_variant_t::invalid_dos_magic:
        dos.e_magic = 0x1234;
        std::memcpy(bytes.data(), &dos, sizeof(dos));
        return bytes;
    case hostile_pe_variant_t::invalid_pe_signature:
        nt.Signature = 0xDEADBEEF;
        break;
    case hostile_pe_variant_t::zero_section_alignment:
        nt.OptionalHeader.SectionAlignment = 0;
        break;
    case hostile_pe_variant_t::import_self_reference:
        nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = 0;
        nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = sizeof(IMAGE_IMPORT_DESCRIPTOR);
        break;
    case hostile_pe_variant_t::overlay_beyond_last_section:
        bytes.resize(bytes.size() + 256, 0xCC);
        break;
    case hostile_pe_variant_t::zero_size_of_image:
        nt.OptionalHeader.SizeOfImage = 0;
        break;
    case hostile_pe_variant_t::corrupt_optional_header_magic:
        nt.OptionalHeader.Magic = 0x0123;
        break;
    }
    std::memcpy(bytes.data() + dos.e_lfanew, &nt, sizeof(nt));
    std::memcpy(bytes.data() + section_offset, &first, sizeof(first));
    return bytes;
}

inline void fixture_store_u16(std::vector<std::uint8_t>& bytes, std::size_t offset,
                              std::uint16_t value, endian_t endian)
{
    std::array<std::uint8_t, 2> encoded{};
    for (std::size_t index = 0; index < encoded.size(); ++index) {
        const auto shift = static_cast<unsigned>((endian == endian_t::little ? index :
            encoded.size() - index - 1) * 8);
        encoded[index] = static_cast<std::uint8_t>(value >> shift);
    }
    fixture_store(bytes, offset, encoded.data(), encoded.size());
}

inline void fixture_store_u32(std::vector<std::uint8_t>& bytes, std::size_t offset,
                              std::uint32_t value, endian_t endian)
{
    std::array<std::uint8_t, 4> encoded{};
    for (std::size_t index = 0; index < encoded.size(); ++index) {
        const auto shift = static_cast<unsigned>((endian == endian_t::little ? index :
            encoded.size() - index - 1) * 8);
        encoded[index] = static_cast<std::uint8_t>(value >> shift);
    }
    fixture_store(bytes, offset, encoded.data(), encoded.size());
}

inline void fixture_store_u64(std::vector<std::uint8_t>& bytes, std::size_t offset,
                              std::uint64_t value, endian_t endian)
{
    std::array<std::uint8_t, 8> encoded{};
    for (std::size_t index = 0; index < encoded.size(); ++index) {
        const auto shift = static_cast<unsigned>((endian == endian_t::little ? index :
            encoded.size() - index - 1) * 8);
        encoded[index] = static_cast<std::uint8_t>(value >> shift);
    }
    fixture_store(bytes, offset, encoded.data(), encoded.size());
}

inline std::vector<std::uint8_t> minimal_elf(
    architecture_id_t architecture, architecture_mode_t mode, endian_t endian,
    const std::vector<std::uint8_t>& instruction, std::uint8_t discriminator)
{
    if (instruction.empty() || instruction.size() > 0x40)
        throw fixture_error_t("ELF fixture instruction extent is invalid");
    std::uint16_t machine = 0;
    bool is_64 = false;
    switch (architecture) {
    case architecture_id_t::x86:
        machine = 3;
        is_64 = false;
        if (mode != architecture_mode_t::x86_32 || endian != endian_t::little)
            throw fixture_error_t("ELF x86 fixture mode is invalid");
        break;
    case architecture_id_t::x86_64:
        machine = 62;
        is_64 = true;
        if (mode != architecture_mode_t::x86_64 || endian != endian_t::little)
            throw fixture_error_t("ELF x86-64 fixture mode is invalid");
        break;
    case architecture_id_t::arm:
        machine = 40;
        is_64 = false;
        if (mode != architecture_mode_t::arm_a32)
            throw fixture_error_t("ELF ARM fixture mode is invalid");
        break;
    case architecture_id_t::aarch64:
        machine = 183;
        is_64 = true;
        if (mode != architecture_mode_t::aarch64)
            throw fixture_error_t("ELF AArch64 fixture mode is invalid");
        break;
    case architecture_id_t::mips:
    case architecture_id_t::mips64:
        machine = 8;
        is_64 = mode == architecture_mode_t::mips64;
        if (mode != architecture_mode_t::mips32 && mode != architecture_mode_t::mips64)
            throw fixture_error_t("ELF MIPS fixture mode is invalid");
        break;
    case architecture_id_t::ppc:
        machine = 20;
        is_64 = false;
        if (mode != architecture_mode_t::ppc32)
            throw fixture_error_t("ELF PowerPC fixture mode is invalid");
        break;
    case architecture_id_t::ppc64:
        machine = 21;
        is_64 = true;
        if (mode != architecture_mode_t::ppc64)
            throw fixture_error_t("ELF PowerPC64 fixture mode is invalid");
        break;
    case architecture_id_t::riscv:
    case architecture_id_t::riscv32:
    case architecture_id_t::riscv64:
        machine = 243;
        is_64 = mode == architecture_mode_t::riscv64;
        if ((mode != architecture_mode_t::riscv32 && mode != architecture_mode_t::riscv64) ||
            endian != endian_t::little)
            throw fixture_error_t("ELF RISC-V fixture mode is invalid");
        break;
    default:
        throw fixture_error_t("ELF fixture architecture is unsupported");
    }

    constexpr std::size_t code_offset = 0x100;
    constexpr std::size_t file_size = 0x200;
    const std::uint64_t image_base = is_64 ? 0x400000ULL : 0x10000ULL;
    const std::size_t header_size = is_64 ? 64 : 52;
    const std::size_t program_header_size = is_64 ? 56 : 32;
    std::vector<std::uint8_t> bytes(file_size, 0);
    bytes[0] = 0x7f;
    bytes[1] = 'E';
    bytes[2] = 'L';
    bytes[3] = 'F';
    bytes[4] = is_64 ? 2 : 1;
    bytes[5] = endian == endian_t::little ? 1 : 2;
    bytes[6] = 1;
    bytes[7] = 3;
    fixture_store_u16(bytes, 16, 2, endian);
    fixture_store_u16(bytes, 18, machine, endian);
    fixture_store_u32(bytes, 20, 1, endian);
    if (is_64) {
        fixture_store_u64(bytes, 24, image_base, endian);
        fixture_store_u64(bytes, 32, header_size, endian);
        fixture_store_u64(bytes, 40, 0, endian);
        fixture_store_u32(bytes, 48, architecture == architecture_id_t::arm ? 0x05000000U : 0, endian);
        fixture_store_u16(bytes, 52, static_cast<std::uint16_t>(header_size), endian);
        fixture_store_u16(bytes, 54, static_cast<std::uint16_t>(program_header_size), endian);
        fixture_store_u16(bytes, 56, 1, endian);
        fixture_store_u16(bytes, 58, 0, endian);
        fixture_store_u16(bytes, 60, 0, endian);
        fixture_store_u16(bytes, 62, 0, endian);
        fixture_store_u32(bytes, header_size, 1, endian);
        fixture_store_u32(bytes, header_size + 4, 5, endian);
        fixture_store_u64(bytes, header_size + 8, code_offset, endian);
        fixture_store_u64(bytes, header_size + 16, image_base, endian);
        fixture_store_u64(bytes, header_size + 24, image_base, endian);
        fixture_store_u64(bytes, header_size + 32, file_size - code_offset, endian);
        fixture_store_u64(bytes, header_size + 40, file_size - code_offset, endian);
        fixture_store_u64(bytes, header_size + 48, 0x100, endian);
    } else {
        fixture_store_u32(bytes, 24, static_cast<std::uint32_t>(image_base), endian);
        fixture_store_u32(bytes, 28, static_cast<std::uint32_t>(header_size), endian);
        fixture_store_u32(bytes, 32, 0, endian);
        fixture_store_u32(bytes, 36, architecture == architecture_id_t::arm ? 0x05000000U : 0, endian);
        fixture_store_u16(bytes, 40, static_cast<std::uint16_t>(header_size), endian);
        fixture_store_u16(bytes, 42, static_cast<std::uint16_t>(program_header_size), endian);
        fixture_store_u16(bytes, 44, 1, endian);
        fixture_store_u16(bytes, 46, 0, endian);
        fixture_store_u16(bytes, 48, 0, endian);
        fixture_store_u16(bytes, 50, 0, endian);
        fixture_store_u32(bytes, header_size, 1, endian);
        fixture_store_u32(bytes, header_size + 4, code_offset, endian);
        fixture_store_u32(bytes, header_size + 8, static_cast<std::uint32_t>(image_base), endian);
        fixture_store_u32(bytes, header_size + 12, static_cast<std::uint32_t>(image_base), endian);
        fixture_store_u32(bytes, header_size + 16,
            static_cast<std::uint32_t>(file_size - code_offset), endian);
        fixture_store_u32(bytes, header_size + 20,
            static_cast<std::uint32_t>(file_size - code_offset), endian);
        fixture_store_u32(bytes, header_size + 24, 5, endian);
        fixture_store_u32(bytes, header_size + 28, 0x100, endian);
    }
    fixture_store(bytes, code_offset, instruction.data(), instruction.size());
    const std::string marker = "AiDA ELF fixture " + std::to_string(discriminator);
    fixture_store(bytes, code_offset + 0x80, marker.data(), marker.size());
    return bytes;
}

inline std::vector<std::uint8_t> minimal_macho64(
    architecture_id_t architecture, std::uint8_t discriminator)
{
    constexpr std::uint32_t cpu_arch_abi64 = 0x01000000U;
    std::uint32_t cpu_type = 0;
    std::uint32_t cpu_subtype = 0;
    std::array<std::uint8_t, 8> code{};
    if (architecture == architecture_id_t::x86_64) {
        cpu_type = cpu_arch_abi64 | 7U;
        cpu_subtype = 3;
        code = {0xB8, discriminator, 0x00, 0x00, 0x00, 0xC3, 0x90, 0xC3};
    } else if (architecture == architecture_id_t::aarch64) {
        cpu_type = cpu_arch_abi64 | 12U;
        code = {0x1F, 0x20, 0x03, 0xD5, 0xC0, 0x03, 0x5F, 0xD6};
    } else {
        throw fixture_error_t("Mach-O fixture architecture is unsupported");
    }
    constexpr std::size_t segment_offset = 32;
    constexpr std::size_t main_offset = segment_offset + 72;
    constexpr std::size_t code_offset = main_offset + 24;
    std::vector<std::uint8_t> bytes(0x200, 0);
    fixture_store_u32(bytes, 0, 0xfeedfacfU, endian_t::little);
    fixture_store_u32(bytes, 4, cpu_type, endian_t::little);
    fixture_store_u32(bytes, 8, cpu_subtype, endian_t::little);
    fixture_store_u32(bytes, 12, 2, endian_t::little);
    fixture_store_u32(bytes, 16, 2, endian_t::little);
    fixture_store_u32(bytes, 20, 96, endian_t::little);
    fixture_store_u32(bytes, 24, 0, endian_t::little);
    fixture_store_u32(bytes, 28, 0, endian_t::little);
    fixture_store_u32(bytes, segment_offset, 0x19, endian_t::little);
    fixture_store_u32(bytes, segment_offset + 4, 72, endian_t::little);
    const char segment_name[] = "__TEXT";
    fixture_store(bytes, segment_offset + 8, segment_name, sizeof(segment_name) - 1);
    fixture_store_u64(bytes, segment_offset + 24, 0x100000000ULL, endian_t::little);
    fixture_store_u64(bytes, segment_offset + 32, 0x1000, endian_t::little);
    fixture_store_u64(bytes, segment_offset + 40, 0, endian_t::little);
    fixture_store_u64(bytes, segment_offset + 48,
        static_cast<std::uint64_t>(bytes.size()), endian_t::little);
    fixture_store_u32(bytes, segment_offset + 56, 5, endian_t::little);
    fixture_store_u32(bytes, segment_offset + 60, 5, endian_t::little);
    fixture_store_u32(bytes, segment_offset + 64, 0, endian_t::little);
    fixture_store_u32(bytes, segment_offset + 68, 0, endian_t::little);
    fixture_store_u32(bytes, main_offset, 0x80000028U, endian_t::little);
    fixture_store_u32(bytes, main_offset + 4, 24, endian_t::little);
    fixture_store_u64(bytes, main_offset + 8, code_offset, endian_t::little);
    fixture_store_u64(bytes, main_offset + 16, 0, endian_t::little);
    fixture_store(bytes, code_offset, code.data(), code.size());
    const std::string marker = "AiDA Mach-O fixture " + std::to_string(discriminator);
    fixture_store(bytes, 0x100, marker.data(), marker.size());
    return bytes;
}

inline std::vector<std::uint8_t> minimal_fat_macho64(
    architecture_id_t architecture, std::uint8_t discriminator)
{
    const auto thin = minimal_macho64(architecture, discriminator);
    const std::uint32_t cpu_type = architecture == architecture_id_t::x86_64
        ? 0x01000007U : 0x0100000cU;
    const std::uint32_t cpu_subtype = architecture == architecture_id_t::x86_64 ? 3U : 0U;
    constexpr std::size_t slice_offset = 0x1000;
    std::vector<std::uint8_t> bytes(slice_offset + thin.size(), 0);
    fixture_store_u32(bytes, 0, 0xcafebabeU, endian_t::big);
    fixture_store_u32(bytes, 4, 1, endian_t::big);
    fixture_store_u32(bytes, 8, cpu_type, endian_t::big);
    fixture_store_u32(bytes, 12, cpu_subtype, endian_t::big);
    fixture_store_u32(bytes, 16, static_cast<std::uint32_t>(slice_offset), endian_t::big);
    fixture_store_u32(bytes, 20, static_cast<std::uint32_t>(thin.size()), endian_t::big);
    fixture_store_u32(bytes, 24, 12, endian_t::big);
    fixture_store(bytes, slice_offset, thin.data(), thin.size());
    return bytes;
}

inline std::vector<std::uint8_t> minimal_coff_object(
    std::uint16_t machine, const std::vector<std::uint8_t>& instruction)
{
    if (instruction.empty() || instruction.size() > 0x20)
        throw fixture_error_t("COFF fixture instruction extent is invalid");
    constexpr std::size_t section_offset = 20;
    constexpr std::size_t raw_offset = 0x40;
    constexpr std::size_t raw_size = 0x20;
    constexpr std::size_t symbol_offset = raw_offset + raw_size;
    constexpr std::size_t symbol_size = 18;
    std::vector<std::uint8_t> bytes(symbol_offset + symbol_size + 4, 0);
    fixture_store_u16(bytes, 0, machine, endian_t::little);
    fixture_store_u16(bytes, 2, 1, endian_t::little);
    fixture_store_u32(bytes, 8, static_cast<std::uint32_t>(symbol_offset), endian_t::little);
    fixture_store_u32(bytes, 12, 1, endian_t::little);
    fixture_store_u16(bytes, 16, 0, endian_t::little);
    fixture_store_u16(bytes, 18, 0, endian_t::little);
    const char section_name[] = ".text";
    fixture_store(bytes, section_offset, section_name, sizeof(section_name) - 1);
    fixture_store_u32(bytes, section_offset + 16, static_cast<std::uint32_t>(raw_size),
        endian_t::little);
    fixture_store_u32(bytes, section_offset + 20, static_cast<std::uint32_t>(raw_offset),
        endian_t::little);
    fixture_store_u32(bytes, section_offset + 36, 0x60000020U, endian_t::little);
    fixture_store(bytes, raw_offset, instruction.data(), instruction.size());
    const char symbol_name[] = "entry";
    fixture_store(bytes, symbol_offset, symbol_name, sizeof(symbol_name) - 1);
    fixture_store_u32(bytes, symbol_offset + 8, 0, endian_t::little);
    fixture_store_u16(bytes, symbol_offset + 12, 1, endian_t::little);
    fixture_store_u16(bytes, symbol_offset + 14, 0x20, endian_t::little);
    bytes[symbol_offset + 16] = 2;
    bytes[symbol_offset + 17] = 0;
    fixture_store_u32(bytes, symbol_offset + symbol_size, 4, endian_t::little);
    return bytes;
}

inline void fixture_store_decimal(std::vector<std::uint8_t>& bytes, std::size_t offset,
                                  std::size_t width, std::uint64_t value)
{
    const auto text = std::to_string(value);
    if (text.size() > width || offset > bytes.size() || width > bytes.size() - offset)
        throw fixture_error_t("fixture decimal field exceeds its width");
    std::fill(bytes.begin() + static_cast<std::ptrdiff_t>(offset),
        bytes.begin() + static_cast<std::ptrdiff_t>(offset + width), static_cast<std::uint8_t>(' '));
    fixture_store(bytes, offset, text.data(), text.size());
}

inline std::vector<std::uint8_t> minimal_coff_archive(
    const std::vector<std::uint8_t>& object)
{
    if (object.empty())
        throw fixture_error_t("COFF archive fixture requires an object member");
    constexpr std::size_t archive_header_size = 8;
    constexpr std::size_t member_header_size = 60;
    const std::size_t padding = object.size() & 1U;
    std::vector<std::uint8_t> bytes(
        archive_header_size + member_header_size + object.size() + padding,
        static_cast<std::uint8_t>(' '));
    const char magic[] = "!<arch>\n";
    fixture_store(bytes, 0, magic, archive_header_size);
    const char name[] = "fixture.obj/";
    fixture_store(bytes, archive_header_size, name, sizeof(name) - 1);
    fixture_store_decimal(bytes, archive_header_size + 48, 10, object.size());
    bytes[archive_header_size + 58] = '`';
    bytes[archive_header_size + 59] = '\n';
    fixture_store(bytes, archive_header_size + member_header_size,
        object.data(), object.size());
    if (padding != 0)
        bytes.back() = '\n';
    return bytes;
}

inline void fixture_append_u16(std::vector<std::uint8_t>& bytes, std::uint16_t value,
                               endian_t endian)
{
    const auto offset = bytes.size();
    bytes.resize(offset + 2);
    fixture_store_u16(bytes, offset, value, endian);
}

inline void fixture_append_u32(std::vector<std::uint8_t>& bytes, std::uint32_t value,
                               endian_t endian)
{
    const auto offset = bytes.size();
    bytes.resize(offset + 4);
    fixture_store_u32(bytes, offset, value, endian);
}

inline void fixture_append_bytes(std::vector<std::uint8_t>& bytes, const void* data,
                                 std::size_t size)
{
    const auto offset = bytes.size();
    bytes.resize(offset + size);
    fixture_store(bytes, offset, data, size);
}

inline std::vector<std::uint8_t> minimal_classfile()
{
    std::vector<std::uint8_t> bytes;
    fixture_append_u32(bytes, 0xcafebabeU, endian_t::big);
    fixture_append_u16(bytes, 0, endian_t::big);
    fixture_append_u16(bytes, 52, endian_t::big);
    fixture_append_u16(bytes, 5, endian_t::big);
    const char fixture_name[] = "Fixture";
    bytes.push_back(1);
    fixture_append_u16(bytes, static_cast<std::uint16_t>(sizeof(fixture_name) - 1),
        endian_t::big);
    fixture_append_bytes(bytes, fixture_name, sizeof(fixture_name) - 1);
    bytes.push_back(7);
    fixture_append_u16(bytes, 1, endian_t::big);
    const char object_name[] = "java/lang/Object";
    bytes.push_back(1);
    fixture_append_u16(bytes, static_cast<std::uint16_t>(sizeof(object_name) - 1),
        endian_t::big);
    fixture_append_bytes(bytes, object_name, sizeof(object_name) - 1);
    bytes.push_back(7);
    fixture_append_u16(bytes, 3, endian_t::big);
    fixture_append_u16(bytes, 0x21, endian_t::big);
    fixture_append_u16(bytes, 2, endian_t::big);
    fixture_append_u16(bytes, 4, endian_t::big);
    fixture_append_u16(bytes, 0, endian_t::big);
    fixture_append_u16(bytes, 0, endian_t::big);
    fixture_append_u16(bytes, 0, endian_t::big);
    fixture_append_u16(bytes, 0, endian_t::big);
    return bytes;
}

inline std::vector<std::uint8_t> minimal_dex()
{
    constexpr std::size_t header_size = 0x70;
    constexpr std::size_t map_size = 28;
    std::vector<std::uint8_t> bytes(header_size + map_size, 0);
    const std::array<std::uint8_t, 8> magic{{'d', 'e', 'x', '\n', '0', '3', '5', 0}};
    fixture_store(bytes, 0, magic.data(), magic.size());
    fixture_store_u32(bytes, 32, static_cast<std::uint32_t>(bytes.size()), endian_t::little);
    fixture_store_u32(bytes, 36, static_cast<std::uint32_t>(header_size), endian_t::little);
    fixture_store_u32(bytes, 40, 0x12345678U, endian_t::little);
    fixture_store_u32(bytes, 52, static_cast<std::uint32_t>(header_size), endian_t::little);
    fixture_store_u32(bytes, 104, static_cast<std::uint32_t>(map_size), endian_t::little);
    fixture_store_u32(bytes, 108, static_cast<std::uint32_t>(header_size), endian_t::little);
    fixture_store_u32(bytes, header_size, 2, endian_t::little);
    fixture_store_u16(bytes, header_size + 4, 0x0000, endian_t::little);
    fixture_store_u16(bytes, header_size + 6, 0, endian_t::little);
    fixture_store_u32(bytes, header_size + 8, 1, endian_t::little);
    fixture_store_u32(bytes, header_size + 12, 0, endian_t::little);
    fixture_store_u16(bytes, header_size + 16, 0x1000, endian_t::little);
    fixture_store_u16(bytes, header_size + 18, 0, endian_t::little);
    fixture_store_u32(bytes, header_size + 20, 1, endian_t::little);
    fixture_store_u32(bytes, header_size + 24, static_cast<std::uint32_t>(header_size),
        endian_t::little);
    return bytes;
}

inline std::vector<std::uint8_t> minimal_android_runtime_container(bool oat)
{
    std::vector<std::uint8_t> bytes(8, 0);
    const char* magic = oat ? "oat\n" : "vdex";
    fixture_store(bytes, 0, magic, 4);
    bytes[4] = '1';
    bytes[5] = '2';
    bytes[6] = '3';
    return bytes;
}

inline std::uint32_t fixture_crc32(const std::vector<std::uint8_t>& bytes) noexcept
{
    std::uint32_t value = 0xffffffffU;
    for (const auto byte : bytes) {
        value ^= byte;
        for (unsigned bit = 0; bit < 8; ++bit)
            value = (value >> 1) ^ (0xedb88320U & (0U - (value & 1U)));
    }
    return ~value;
}

struct stored_zip_member_t {
    std::string path;
    std::vector<std::uint8_t> bytes;
};

inline std::vector<std::uint8_t> minimal_stored_zip(
    const std::vector<stored_zip_member_t>& members)
{
    if (members.empty() || members.size() > 0xffffU)
        throw fixture_error_t("stored ZIP fixture member count is invalid");
    std::vector<std::uint8_t> bytes;
    std::vector<std::uint8_t> central;
    for (const auto& member : members) {
        if (member.path.empty() || member.path.size() > 0xffffU || member.bytes.empty() ||
            member.bytes.size() > 0xffffffffULL || member.path.front() == '/' ||
            member.path.find('\\') != std::string::npos ||
            member.path.find("//") != std::string::npos || member.path == "." ||
            member.path == ".." || member.path.rfind("./", 0) == 0 ||
            member.path.rfind("../", 0) == 0 || member.path.find("/./") != std::string::npos ||
            member.path.find("/../") != std::string::npos ||
            (member.path.size() >= 2 && member.path.compare(member.path.size() - 2, 2, "/.") == 0) ||
            (member.path.size() >= 3 && member.path.compare(member.path.size() - 3, 3, "/..") == 0))
            throw fixture_error_t("stored ZIP fixture member is invalid");
        if (bytes.size() > 0xffffffffULL)
            throw fixture_error_t("stored ZIP fixture local offset exceeds ZIP32");
        const auto local_offset = static_cast<std::uint32_t>(bytes.size());
        const auto crc = fixture_crc32(member.bytes);
        fixture_append_u32(bytes, 0x04034b50U, endian_t::little);
        fixture_append_u16(bytes, 20, endian_t::little);
        fixture_append_u16(bytes, 0x0800, endian_t::little);
        fixture_append_u16(bytes, 0, endian_t::little);
        fixture_append_u16(bytes, 0, endian_t::little);
        fixture_append_u16(bytes, 0, endian_t::little);
        fixture_append_u32(bytes, crc, endian_t::little);
        fixture_append_u32(bytes, static_cast<std::uint32_t>(member.bytes.size()), endian_t::little);
        fixture_append_u32(bytes, static_cast<std::uint32_t>(member.bytes.size()), endian_t::little);
        fixture_append_u16(bytes, static_cast<std::uint16_t>(member.path.size()), endian_t::little);
        fixture_append_u16(bytes, 0, endian_t::little);
        fixture_append_bytes(bytes, member.path.data(), member.path.size());
        fixture_append_bytes(bytes, member.bytes.data(), member.bytes.size());

        fixture_append_u32(central, 0x02014b50U, endian_t::little);
        fixture_append_u16(central, 20, endian_t::little);
        fixture_append_u16(central, 20, endian_t::little);
        fixture_append_u16(central, 0x0800, endian_t::little);
        fixture_append_u16(central, 0, endian_t::little);
        fixture_append_u16(central, 0, endian_t::little);
        fixture_append_u16(central, 0, endian_t::little);
        fixture_append_u32(central, crc, endian_t::little);
        fixture_append_u32(central, static_cast<std::uint32_t>(member.bytes.size()), endian_t::little);
        fixture_append_u32(central, static_cast<std::uint32_t>(member.bytes.size()), endian_t::little);
        fixture_append_u16(central, static_cast<std::uint16_t>(member.path.size()), endian_t::little);
        fixture_append_u16(central, 0, endian_t::little);
        fixture_append_u16(central, 0, endian_t::little);
        fixture_append_u16(central, 0, endian_t::little);
        fixture_append_u16(central, 0, endian_t::little);
        fixture_append_u32(central, 0, endian_t::little);
        fixture_append_u32(central, local_offset, endian_t::little);
        fixture_append_bytes(central, member.path.data(), member.path.size());
    }
    if (bytes.size() > 0xffffffffULL || central.size() > 0xffffffffULL ||
        central.size() > 0xffffffffULL - bytes.size())
        throw fixture_error_t("stored ZIP fixture exceeds ZIP32");
    const auto central_offset = static_cast<std::uint32_t>(bytes.size());
    fixture_append_bytes(bytes, central.data(), central.size());
    fixture_append_u32(bytes, 0x06054b50U, endian_t::little);
    fixture_append_u16(bytes, 0, endian_t::little);
    fixture_append_u16(bytes, 0, endian_t::little);
    fixture_append_u16(bytes, static_cast<std::uint16_t>(members.size()), endian_t::little);
    fixture_append_u16(bytes, static_cast<std::uint16_t>(members.size()), endian_t::little);
    fixture_append_u32(bytes, static_cast<std::uint32_t>(central.size()), endian_t::little);
    fixture_append_u32(bytes, central_offset, endian_t::little);
    fixture_append_u16(bytes, 0, endian_t::little);
    return bytes;
}

inline std::filesystem::path write_bytes_fixture(const std::filesystem::path& path,
                                                 const std::vector<std::uint8_t>& bytes)
{
    std::filesystem::create_directories(path.parent_path());
    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    stream.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    stream.flush();
    if (!stream)
        throw fixture_error_t("unable to write binary fixture");
    return path;
}

inline std::filesystem::path write_fixture(const std::filesystem::path& root,
                                           const std::string& directory,
                                           const std::string& basename,
                                           std::uint8_t discriminator)
{
    const auto parent = root / directory;
    std::filesystem::create_directories(parent);
    const auto path = parent / basename;
    const auto bytes = minimal_pe64(discriminator);
    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    stream.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    stream.flush();
    if (!stream)
        throw fixture_error_t("unable to write PE fixture");
    return path;
}

inline std::filesystem::path write_fixture32(const std::filesystem::path& root,
                                             const std::string& directory,
                                             const std::string& basename,
                                             std::uint8_t discriminator)
{
    return write_bytes_fixture(root / directory / basename, minimal_pe32(discriminator));
}

inline std::shared_ptr<analysis_workspace_t> open_workspace(const std::filesystem::path& path,
                                                             const std::string& bin_name)
{
    open_static_workspace_request_t request;
    request.source_path = path.u8string();
    request.bin_name = bin_name;
    request.load_profile = {1, 0, 0, 0};
    const auto path_identity = std::filesystem::absolute(path).lexically_normal().u8string();
    request.load_profile.insert(request.load_profile.end(), path_identity.begin(), path_identity.end());
    auto opened = workspace_registry().open_static(request);
    if (!opened)
        throw fixture_error_t(opened.error().stable_code() + ":" + opened.error().message);
    return opened.take_value();
}

inline std::shared_ptr<std::mutex> service_install_mutex(const binary_id_t& binary_id)
{
    static std::mutex registry_mutex;
    static std::unordered_map<std::string, std::weak_ptr<std::mutex>> registry;
    std::lock_guard<std::mutex> lock(registry_mutex);
    for (auto it = registry.begin(); it != registry.end();) {
        if (it->second.expired())
            it = registry.erase(it);
        else
            ++it;
    }
    const auto key = binary_id.to_hex();
    auto service_mutex = registry[key].lock();
    if (!service_mutex) {
        service_mutex = std::make_shared<std::mutex>();
        registry[key] = service_mutex;
    }
    return service_mutex;
}

inline void install_services(const std::shared_ptr<analysis_workspace_t>& workspace)
{
    if (!workspace)
        throw fixture_error_t("workspace is required for service installation");
    const auto install_mutex = service_install_mutex(workspace->identity().binary_id());
    std::lock_guard<std::mutex> lock(*install_mutex);
    if (workspace->database() && workspace->persistence_queue() && workspace->overlay() &&
        workspace->decompiler())
        return;
    if (workspace->database() || workspace->persistence_queue() || workspace->overlay() ||
        workspace->decompiler())
        throw fixture_error_t("workspace contains a partial service installation");
    workspace_database_options_t options;
    options.identity = workspace->identity_handle();
    options.versions.engine_version = "analysis-workspace-harness-2";
    options.versions.specification_version = "normalized-static-engine-1";
    options.versions.analysis_settings_hash = "fixture-default";
    auto database = workspace_database_t::open(options);
    if (!database)
        throw fixture_error_t(database.error().stable_code() + ":" + database.error().message);
    auto database_service = database.take_value();
    auto queue_service = database_service->queue();
    auto stop_services = [&] {
        const auto decompiler_service = workspace->decompiler();
        const auto overlay_service = workspace->overlay();
        if (decompiler_service)
            decompiler_service->request_cancel();
        if (overlay_service)
            overlay_service->request_cancel();
        if (queue_service)
            queue_service->request_cancel();
        database_service->request_cancel();
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        if (decompiler_service)
            (void)decompiler_service->drain(deadline);
        if (overlay_service)
            (void)overlay_service->drain(deadline);
        if (queue_service)
            (void)queue_service->drain(deadline);
        (void)database_service->drain(deadline);
    };
    auto registered = workspace->register_lifecycle_participant(database_service);
    if (!registered) {
        stop_services();
        throw fixture_error_t(registered.error().stable_code() + ":" + registered.error().message);
    }
    auto installed = workspace->install_database(database_service);
    if (!installed) {
        stop_services();
        throw fixture_error_t(installed.error().stable_code() + ":" + installed.error().message);
    }
    if (!queue_service) {
        stop_services();
        throw fixture_error_t("workspace database did not create its persistence queue");
    }
    registered = workspace->register_lifecycle_participant(queue_service);
    if (!registered) {
        stop_services();
        throw fixture_error_t(registered.error().stable_code() + ":" + registered.error().message);
    }
    installed = workspace->install_persistence_queue(queue_service);
    if (!installed) {
        stop_services();
        throw fixture_error_t(installed.error().stable_code() + ":" + installed.error().message);
    }
    auto overlay = overlay_journal_t::open(workspace, database_service);
    if (!overlay)
    {
        stop_services();
        throw fixture_error_t(overlay.error().stable_code() + ":" + overlay.error().message);
    }
    if (workspace->overlay() != overlay.value())
    {
        stop_services();
        throw fixture_error_t("overlay factory did not publish its returned service");
    }
    auto decompiler = decompiler_service_t::create(workspace, database_service, options.versions);
    if (!decompiler)
    {
        stop_services();
        throw fixture_error_t(decompiler.error().stable_code() + ":" + decompiler.error().message);
    }
    if (workspace->decompiler() != decompiler.value())
    {
        stop_services();
        throw fixture_error_t("decompiler factory did not publish its returned service");
    }
}

inline void analyze_workspace(
    const std::shared_ptr<analysis_workspace_t>& workspace,
    std::uint32_t worker_lanes = 1)
{
    baseline_analysis_settings_t settings;
    settings.decode_worker_lanes = worker_lanes;
    auto started = baseline_analysis_service_t::start(workspace, settings);
    if (!started)
        throw fixture_error_t(started.error().stable_code() + ":" + started.error().message);
    auto waited = aida::infra::taskflow_runtime::wait_for(started.value(), 60u * 60u * 1000u);
    if (!waited.completed) {
        baseline_analysis_service_t::cancel(started.value());
        (void)aida::infra::taskflow_runtime::wait_for(started.value(), 10000);
        const auto progress = workspace->progress();
        if (progress.error)
            throw fixture_error_t(progress.error->stable_code() + ":" + progress.error->message);
        throw fixture_error_t(waited.cancelled ? "CANCELLED:baseline graph cancelled" :
            (waited.failed ? "INTERNAL_ERROR:baseline graph failed" :
             "DEADLINE_EXCEEDED:baseline harness safety deadline exceeded"));
    }
    const auto progress = workspace->progress();
    if (progress.readiness != workspace_readiness_t::baseline_ready || !workspace->snapshot())
        throw fixture_error_t("baseline graph completed without a ready publication");
}

inline std::shared_ptr<analysis_metrics_t> analyze_workspace_instrumented(
    const std::shared_ptr<analysis_workspace_t>& workspace,
    std::uint32_t worker_lanes = 1)
{
    baseline_analysis_settings_t settings;
    settings.decode_worker_lanes = worker_lanes;
    auto analyzer = pe_baseline_analyzer_t::create(
        workspace, settings, workspace->generation(), workspace->analysis_revision(),
        std::nullopt);
    if (!analyzer)
        throw fixture_error_t(analyzer.error().stable_code() + ":" + analyzer.error().message);
    std::atomic<bool> runtime_cancelled{false};
    auto run = [&](auto callable) {
        auto result = callable();
        if (!result)
            throw fixture_error_t(result.error().stable_code() + ":" + result.error().message);
    };
    run([&] { return analyzer.value()->parse_phase(runtime_cancelled); });
    run([&] { return analyzer.value()->seed_phase(runtime_cancelled); });
    for (std::uint32_t lane = 0; lane < analyzer.value()->decode_lane_count(); ++lane)
        run([&] { return analyzer.value()->decode_lane_phase(lane, runtime_cancelled); });
    run([&] { return analyzer.value()->decode_merge_phase(runtime_cancelled); });
    run([&] { return analyzer.value()->blocks_phase(runtime_cancelled); });
    run([&] { return analyzer.value()->functions_phase(runtime_cancelled); });
    run([&] { return analyzer.value()->cfg_calls_phase(runtime_cancelled); });
    run([&] { return analyzer.value()->xrefs_phase(runtime_cancelled); });
    run([&] { return analyzer.value()->strings_data_phase(runtime_cancelled); });
    run([&] { return analyzer.value()->metadata_symbols_types_phase(runtime_cancelled); });
    run([&] { return analyzer.value()->search_index_phase(runtime_cancelled); });
    run([&] { return analyzer.value()->persistence_phase(runtime_cancelled); });
    run([&] { return analyzer.value()->publish_ready_phase(runtime_cancelled); });
    std::uint64_t decoded_bytes = 0;
    const auto snapshot = workspace->snapshot();
    if (snapshot) {
        for (const auto& span : snapshot->coverage) {
            if (span.reason == coverage_reason_t::decoded)
                decoded_bytes += span.size;
        }
    }
    analyzer.value()->metrics()->set(analysis_metric_t::decoded_bytes, decoded_bytes);
    return analyzer.value()->metrics();
}

inline void remove_database_artifacts(const std::string& database_path)
{
    if (database_path.empty())
        return;
    std::error_code error;
    for (const auto& candidate : {database_path, database_path + "-wal", database_path + "-shm"}) {
        std::filesystem::remove(std::filesystem::u8path(candidate), error);
        if (error)
            throw fixture_error_t("unable to remove harness database artifact: " + error.message());
    }
}

inline void close_workspace(const std::shared_ptr<analysis_workspace_t>& workspace,
                            bool remove_database = false)
{
    if (!workspace)
        return;
    const std::string database_path = workspace->database() ? workspace->database()->path() : std::string();
    auto closed = workspace_registry().close(
        workspace->identity().binary_id(), std::chrono::steady_clock::now() + std::chrono::seconds(10));
    if (!closed)
        throw fixture_error_t(closed.error().stable_code() + ":" + closed.error().message);
    if (remove_database)
        remove_database_artifacts(database_path);
}

class fixture_root_t final {
public:
    explicit fixture_root_t(std::string label) : path_(unique_root(label)) {
        std::filesystem::create_directories(path_);
    }
    ~fixture_root_t() {
        std::error_code error;
        std::filesystem::remove_all(path_, error);
    }
    const std::filesystem::path& path() const noexcept { return path_; }
private:
    std::filesystem::path path_;
};

}
