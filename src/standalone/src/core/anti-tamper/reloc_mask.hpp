#pragma once

#include <windows.h>
#include <cstdint>
#include <cstring>
#include <vector>

#include "state.hpp"
#include "webhook.hpp"
#include "../../helpers/diag_log.hpp"

namespace anti_tamper {
namespace reloc_mask {

using ::anti_tamper::state::reloc_mask_entry_t;

constexpr uint32_t kImageRelBasedDir64   = 10;
constexpr uint32_t kImageRelBasedHighlow = 3;

inline uint64_t get_preferred_image_base()
{
    HMODULE h = GetModuleHandleW(nullptr);
    if (!h) return 0;

    auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(h);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;

    auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
        reinterpret_cast<const uint8_t*>(h) + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

    return static_cast<uint64_t>(nt->OptionalHeader.ImageBase);
}

inline uint64_t get_runtime_image_base()
{
    return reinterpret_cast<uint64_t>(GetModuleHandleW(nullptr));
}

inline uint64_t get_text_section_range(uint64_t& text_base_out, uint32_t& text_size_out)
{
    HMODULE h = GetModuleHandleW(nullptr);
    if (!h) return 0;

    auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(h);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;

    auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
        reinterpret_cast<const uint8_t*>(h) + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

    auto* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i)
    {
        if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
        {
            text_base_out = reinterpret_cast<uint64_t>(h) + sec[i].VirtualAddress;
            text_size_out = sec[i].Misc.VirtualSize;
            return reinterpret_cast<uint64_t>(h) + sec[i].VirtualAddress;
        }
    }
    return 0;
}

inline void populate_reloc_mask_table(std::vector<reloc_mask_entry_t>& table)
{
    table.clear();

    HMODULE h = GetModuleHandleW(nullptr);
    if (!h)
    {
        webhook::write_log("reloc_mask", "populate_failed_no_module");
        return;
    }

    auto* base = reinterpret_cast<const uint8_t*>(h);
    auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
    {
        webhook::write_log("reloc_mask", "populate_failed_bad_dos");
        return;
    }

    auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
    {
        webhook::write_log("reloc_mask", "populate_failed_bad_nt");
        return;
    }

    uint32_t text_rva = 0;
    uint32_t text_size = 0;
    auto* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i)
    {
        if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
        {
            text_rva = sec[i].VirtualAddress;
            text_size = sec[i].Misc.VirtualSize;
            break;
        }
    }

    if (text_rva == 0 || text_size == 0)
    {
        webhook::write_log("reloc_mask", "populate_no_text_section");
        return;
    }

    uint32_t text_end_rva = text_rva + text_size;

    DWORD reloc_dir_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    DWORD reloc_dir_size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

    if (reloc_dir_rva == 0 || reloc_dir_size == 0)
    {
        webhook::write_log("reloc_mask", "populate_no_reloc_section");
        return;
    }

    auto* reloc_start = base + reloc_dir_rva;
    auto* reloc_end = reloc_start + reloc_dir_size;
    auto* p = reloc_start;

    uint32_t entry_count = 0;

    while (p + sizeof(IMAGE_BASE_RELOCATION) <= reloc_end)
    {
        auto* hdr = reinterpret_cast<const IMAGE_BASE_RELOCATION*>(p);
        if (hdr->VirtualAddress == 0 || hdr->SizeOfBlock == 0)
            break;

        uint32_t block_rva = hdr->VirtualAddress;
        DWORD block_size = hdr->SizeOfBlock;
        DWORD entry_count_in_block = (block_size - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

        auto* entries = reinterpret_cast<const WORD*>(
            p + sizeof(IMAGE_BASE_RELOCATION));

        for (DWORD e = 0; e < entry_count_in_block; ++e)
        {
            WORD entry = entries[e];
            uint16_t type = (entry >> 12) & 0xF;
            uint16_t offset_in_page = entry & 0xFFF;
            uint32_t target_rva = block_rva + offset_in_page;

            if (target_rva >= text_rva && target_rva < text_end_rva)
            {
                if (type == kImageRelBasedDir64 || type == kImageRelBasedHighlow)
                {
                    reloc_mask_entry_t mask_entry{};
                    mask_entry.offset = target_rva - text_rva;
                    mask_entry.size = (type == kImageRelBasedDir64) ? 8 : 4;
                    mask_entry.reloc_type = type;
                    mask_entry._pad = 0;

                    uint64_t runtime_va = reinterpret_cast<uint64_t>(h) + target_rva;
                    memset(mask_entry.original_value, 0, 8);

                    const uint8_t* runtime_ptr = reinterpret_cast<const uint8_t*>(runtime_va);
                    uint64_t runtime_base = get_runtime_image_base();
                    uint64_t preferred_base = get_preferred_image_base();
                    int64_t delta = static_cast<int64_t>(runtime_base) - static_cast<int64_t>(preferred_base);

                    uint64_t current_val = 0;
                    memcpy(&current_val, runtime_ptr, mask_entry.size);

                    uint64_t original_val = 0;
                    if (type == kImageRelBasedDir64)
                        original_val = current_val - static_cast<uint64_t>(delta);
                    else
                    {
                        uint32_t current_32 = static_cast<uint32_t>(current_val & 0xFFFFFFFF);
                        uint32_t delta_32 = static_cast<uint32_t>(delta & 0xFFFFFFFF);
                        uint32_t original_32 = (current_32 - delta_32) & 0xFFFFFFFF;
                        original_val = static_cast<uint64_t>(original_32);
                    }

                    memcpy(mask_entry.original_value, &original_val, mask_entry.size);

                    table.push_back(mask_entry);
                    ++entry_count;
                }
            }
        }

        p += block_size;
    }

    {
        char dbg[160];
        _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
            "reloc_mask_populated entries=%u text_rva=0x%X text_size=0x%X",
            entry_count, text_rva, text_size);
        webhook::write_log("reloc_mask", dbg);
        diag::log_tagged_critical("reloc_mask", dbg);
    }
}

inline bool verify_then_mask_buffer(uint8_t* buffer, uint32_t text_size,
                                     const std::vector<reloc_mask_entry_t>& table)
{
    uint64_t preferred_base = get_preferred_image_base();
    uint64_t runtime_base = get_runtime_image_base();
    int64_t delta = static_cast<int64_t>(runtime_base) - static_cast<int64_t>(preferred_base);

    for (const auto& entry : table)
    {
        if (entry.offset + entry.size > text_size)
            continue;

        uint64_t actual_value = 0;
        memcpy(&actual_value, buffer + entry.offset, entry.size);

        uint64_t original_value = 0;
        memcpy(&original_value, entry.original_value, entry.size);

        uint64_t expected_value;
        if (entry.reloc_type == kImageRelBasedDir64)
        {
            expected_value = original_value + static_cast<uint64_t>(delta);
        }
        else if (entry.reloc_type == kImageRelBasedHighlow)
        {
            uint32_t orig_32 = static_cast<uint32_t>(original_value & 0xFFFFFFFF);
            uint32_t delta_32 = static_cast<uint32_t>(static_cast<uint64_t>(delta) & 0xFFFFFFFF);
            uint32_t expected_32 = (orig_32 + delta_32) & 0xFFFFFFFF;
            expected_value = static_cast<uint64_t>(expected_32);
        }
        else
        {
            return false;
        }

        if (actual_value != expected_value)
        {
            char dbg[256];
            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                "reloc_mask_tamper_detected offset=%u type=%u actual=0x%llX expected=0x%llX",
                entry.offset, entry.reloc_type,
                static_cast<unsigned long long>(actual_value),
                static_cast<unsigned long long>(expected_value));
            diag::log_tagged_critical("reloc_mask", dbg);
            webhook::write_log_critical("reloc_mask", dbg);
            return false;
        }

        memset(buffer + entry.offset, 0, entry.size);
    }

    return true;
}

}
}
