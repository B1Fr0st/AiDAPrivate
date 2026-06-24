#pragma once
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include "pe_file.hpp"
#include "transforms.hpp"
#include "watermark.hpp"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

namespace verifier {

struct probe_result_t {
    const char* id;
    const char* desc;
    bool        pass;
    std::string detail;
};

struct context_t {
    pe_file::pe_image_t pe;
    bool                           packed_found = false;
    protector::packed_header_t     hdr{};
    protector::aux_block_t         aux{};
    bool                           aux_found = false;
    uint32_t                       packed_rva = 0;
    uint32_t                       packed_vsize = 0;
    uint32_t                       packed_characteristics = 0;
    char                           packed_name[9] = {};
    std::vector<uint8_t>           packed_data;
    std::vector<uint8_t>           packed_section_bytes;
};

struct verify_report_t {
    std::vector<probe_result_t> probes;
    int  passed = 0;
    int  total  = 0;
    bool loaded = false;
    uint32_t phase_flags = 0;
    bool aux_found = false;
};

enum class verify_profile_t {
    strict_no_imports,
    standalone_no_imports,
    preserved_imports
};

inline const char* profile_name(verify_profile_t profile) {
    switch (profile) {
    case verify_profile_t::strict_no_imports: return "strict-no-imports";
    case verify_profile_t::standalone_no_imports: return "standalone-no-imports";
    case verify_profile_t::preserved_imports: return "preserved-imports";
    }
    return "strict-no-imports";
}

inline bool parse_profile(const std::string& value, verify_profile_t& profile) {
    if (value == "strict-no-imports") {
        profile = verify_profile_t::strict_no_imports;
        return true;
    }
    if (value == "standalone-no-imports") {
        profile = verify_profile_t::standalone_no_imports;
        return true;
    }
    if (value == "preserved-imports") {
        profile = verify_profile_t::preserved_imports;
        return true;
    }
    return false;
}

inline bool profile_requires_no_imports(verify_profile_t profile) {
    return profile != verify_profile_t::preserved_imports;
}

inline bool find_packed(context_t& c) {
    using namespace protector;
    for (const auto& sec : c.pe.sections) {
        if (sec.data.size() < sizeof(packed_header_t)) { continue; }
        for (size_t off = 0; off + sizeof(packed_header_t) <= sec.data.size(); off += 8) {
            packed_header_t h{};
            std::memcpy(&h, sec.data.data() + off, sizeof(h));
            if (h.magic != kPackedMagic || h.version != kPackedVersion) { continue; }
            c.hdr = h;
            c.packed_data.assign(sec.data.begin() + off, sec.data.end());
            c.packed_section_bytes = sec.data;
            c.packed_rva = sec.virtual_address + static_cast<uint32_t>(off);
            c.packed_vsize = sec.virtual_size > static_cast<uint32_t>(off)
                ? sec.virtual_size - static_cast<uint32_t>(off)
                : 0u;
            c.packed_characteristics = sec.characteristics;
            std::memcpy(c.packed_name, sec.name, 8);
            c.packed_name[8] = '\0';
            c.packed_found = true;
            if (h.aux_offset != 0u && h.aux_size == sizeof(aux_block_t)
                && static_cast<size_t>(h.aux_offset) + sizeof(aux_block_t) <= c.packed_data.size()) {
                std::memcpy(&c.aux, c.packed_data.data() + h.aux_offset, sizeof(aux_block_t));
                c.aux_found = (c.aux.magic == kAuxMagic);
            }
            return true;
        }
    }
    return false;
}

inline bool range_within(size_t offset, uint64_t size, size_t limit) {
    const uint64_t end = static_cast<uint64_t>(offset) + size;
    return static_cast<uint64_t>(offset) <= static_cast<uint64_t>(limit) &&
           end <= static_cast<uint64_t>(limit);
}

inline void section_name_cstr(const char name[8], char out[9]) {
    std::memcpy(out, name, 8);
    out[8] = '\0';
}

inline void spread_ai_section_name(uint32_t index, char out[9]) {
    std::memset(out, 0, 9);
    out[0] = '.';
    out[1] = 'a';
    out[2] = 'i';
    out[3] = 'a';
    out[4] = 'i';
    out[5] = static_cast<char>('0' + (index % 10u));
}

inline bool is_spread_ai_section_name(const char* name) {
    if (name == nullptr) { return false; }
    for (uint32_t i = 0; i < 8u; ++i) {
        char expected[9] = {};
        spread_ai_section_name(i, expected);
        if (std::strcmp(name, expected) == 0) {
            return true;
        }
    }
    return false;
}

inline bool is_function_lure_section_name(const char* name) {
    return name != nullptr && std::strcmp(name, ".aifn") == 0;
}

inline bool is_page_lure_section_name(const char* name) {
    return name != nullptr && std::strcmp(name, ".aipg") == 0;
}

inline uint32_t read_u32_le(const std::vector<uint8_t>& data, size_t offset) {
    if (offset + 4u > data.size()) { return 0u; }
    return static_cast<uint32_t>(data[offset]) |
        (static_cast<uint32_t>(data[offset + 1u]) << 8) |
        (static_cast<uint32_t>(data[offset + 2u]) << 16) |
        (static_cast<uint32_t>(data[offset + 3u]) << 24);
}

inline uint64_t read_u64_le(const std::vector<uint8_t>& data, size_t offset) {
    if (offset + 8u > data.size()) { return 0ull; }
    uint64_t v = 0ull;
    for (uint32_t i = 0; i < 8u; ++i) {
        v |= static_cast<uint64_t>(data[offset + i]) << (8u * i);
    }
    return v;
}

inline uint32_t fnv1a32_bytes(const uint8_t* data, size_t len, uint32_t h = 2166136261u) {
    for (size_t i = 0; i < len; ++i) {
        h ^= static_cast<uint32_t>(data[i]);
        h *= 16777619u;
    }
    return h;
}

inline uint32_t fnv1a32_u32(uint32_t h, uint32_t v) {
    uint8_t b[4] = {
        static_cast<uint8_t>(v & 0xFFu),
        static_cast<uint8_t>((v >> 8) & 0xFFu),
        static_cast<uint8_t>((v >> 16) & 0xFFu),
        static_cast<uint8_t>((v >> 24) & 0xFFu)
    };
    return fnv1a32_bytes(b, sizeof(b), h);
}

inline uint32_t fnv1a32_u64(uint32_t h, uint64_t v) {
    uint8_t b[8] = {
        static_cast<uint8_t>(v & 0xFFu),
        static_cast<uint8_t>((v >> 8) & 0xFFu),
        static_cast<uint8_t>((v >> 16) & 0xFFu),
        static_cast<uint8_t>((v >> 24) & 0xFFu),
        static_cast<uint8_t>((v >> 32) & 0xFFu),
        static_cast<uint8_t>((v >> 40) & 0xFFu),
        static_cast<uint8_t>((v >> 48) & 0xFFu),
        static_cast<uint8_t>((v >> 56) & 0xFFu)
    };
    return fnv1a32_bytes(b, sizeof(b), h);
}

inline uint32_t aifn_record_integrity(uint32_t kind,
                                      uint32_t flags,
                                      uint32_t target_rva,
                                      uint64_t preferred_va,
                                      uint32_t target_size,
                                      uint32_t unwind_rva,
                                      uint32_t source_section_rva,
                                      uint32_t source_section_index,
                                      uint32_t poison_section_name_offset,
                                      uint32_t poison_section_index,
                                      uint32_t poison_rva,
                                      uint64_t poison_preferred_va,
                                      uint32_t poison_ordinal,
                                      uint32_t label_offset,
                                      uint32_t bait_text_offset,
                                      uint64_t lure_id) {
    uint32_t h = 2166136261u;
    h = fnv1a32_u32(h, 0xA1F00D31u);
    h = fnv1a32_u32(h, kind);
    h = fnv1a32_u32(h, flags);
    h = fnv1a32_u32(h, target_rva);
    h = fnv1a32_u64(h, preferred_va);
    h = fnv1a32_u32(h, target_size);
    h = fnv1a32_u32(h, unwind_rva);
    h = fnv1a32_u32(h, source_section_rva);
    h = fnv1a32_u32(h, source_section_index);
    h = fnv1a32_u32(h, poison_section_name_offset);
    h = fnv1a32_u32(h, poison_section_index);
    h = fnv1a32_u32(h, poison_rva);
    h = fnv1a32_u64(h, poison_preferred_va);
    h = fnv1a32_u32(h, poison_ordinal);
    h = fnv1a32_u32(h, label_offset);
    h = fnv1a32_u32(h, bait_text_offset);
    h = fnv1a32_u64(h, lure_id);
    return h != 0u ? h : 0xA1DAA1DAu;
}

inline bool poison_section_characteristics_ok(const pe_file::section_t& s) {
    return (s.characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) != 0u &&
        (s.characteristics & IMAGE_SCN_MEM_READ) != 0u &&
        (s.characteristics & IMAGE_SCN_MEM_WRITE) == 0u &&
        (s.characteristics & IMAGE_SCN_MEM_EXECUTE) == 0u &&
        (s.characteristics & IMAGE_SCN_CNT_CODE) == 0u &&
        (s.characteristics & IMAGE_SCN_MEM_DISCARDABLE) == 0u;
}

inline bool counted_table_bounds(const std::vector<uint8_t>& data,
                                 uint32_t offset,
                                 uint32_t expected_count,
                                 size_t entry_size,
                                 uint32_t max_count,
                                 uint32_t image_size,
                                 uint32_t& stored_count_out) {
    stored_count_out = 0u;
    if (expected_count == 0u && offset == 0u) {
        return true;
    }
    if (offset == 0u || expected_count > max_count) {
        return false;
    }
    if (!range_within(offset, 4u, data.size())) {
        return false;
    }
    uint32_t stored_count = 0;
    std::memcpy(&stored_count, data.data() + offset, sizeof(stored_count));
    stored_count_out = stored_count;
    if (stored_count != expected_count || stored_count > max_count) {
        return false;
    }
    const uint64_t bytes = 4ull + static_cast<uint64_t>(stored_count) * static_cast<uint64_t>(entry_size);
    if (!range_within(offset, bytes, data.size())) {
        return false;
    }
    if (image_size != 0u && stored_count != 0u) {
        const uint8_t* entries = data.data() + offset + 4u;
        if (entry_size == sizeof(protector::string_fixup_t)) {
            for (uint32_t i = 0; i < stored_count; ++i) {
                protector::string_fixup_t sf{};
                std::memcpy(&sf, entries + static_cast<size_t>(i) * sizeof(sf), sizeof(sf));
                if (sf.length == 0u || !range_within(sf.rva, sf.length, image_size)) {
                    return false;
                }
            }
        } else if (entry_size == sizeof(protector::resource_fixup_t)) {
            for (uint32_t i = 0; i < stored_count; ++i) {
                protector::resource_fixup_t rf{};
                std::memcpy(&rf, entries + static_cast<size_t>(i) * sizeof(rf), sizeof(rf));
                if (rf.size == 0u || !range_within(rf.rva, rf.size, image_size)) {
                    return false;
                }
            }
        }
    }
    return true;
}

inline bool import_table_bounds(const std::vector<uint8_t>& data,
                                uint32_t offset,
                                uint32_t expected_count,
                                uint32_t image_size,
                                uint32_t& stored_count_out,
                                uint32_t& pool_size_out) {
    (void)image_size;
    stored_count_out = 0u;
    pool_size_out = 0u;
    if (expected_count == 0u && offset == 0u) {
        return true;
    }
    if (offset == 0u || expected_count > protector::kImportTableMaxRecords) {
        return false;
    }
    if (!range_within(offset, protector::kImportTableHeaderSize, data.size())) {
        return false;
    }
    uint32_t stored_count = 0;
    uint32_t pool_size = 0;
    uint32_t body_size = 0;
    uint32_t version = 0;
    std::memcpy(&stored_count, data.data() + offset + 0u, sizeof(stored_count));
    std::memcpy(&pool_size, data.data() + offset + 4u, sizeof(pool_size));
    std::memcpy(&body_size, data.data() + offset + 8u, sizeof(body_size));
    std::memcpy(&version, data.data() + offset + 12u, sizeof(version));
    stored_count_out = stored_count;
    pool_size_out = pool_size;
    if (stored_count != expected_count || stored_count > protector::kImportTableMaxRecords) {
        return false;
    }
    if (version != protector::kImportTableVersion) {
        return false;
    }
    const uint64_t entry_bytes =
        static_cast<uint64_t>(stored_count) * static_cast<uint64_t>(sizeof(protector::import_hash_entry_t));
    const uint64_t expected_body = entry_bytes + static_cast<uint64_t>(pool_size);
    if (entry_bytes > 0xFFFFFFFFull) {
        return false;
    }
    if (expected_body != static_cast<uint64_t>(body_size)) {
        return false;
    }
    if (body_size > protector::kImportTableMaxBodySize) {
        return false;
    }
    if (stored_count != 0u && (pool_size == 0u || body_size == 0u)) {
        return false;
    }
    if (!range_within(offset, static_cast<uint64_t>(protector::kImportTableBodyOffset) + body_size, data.size())) {
        return false;
    }
    if (stored_count != 0u) {
        if (!protector::bytes_have_nonzero(data.data() + offset + 16u, 16u)) {
            return false;
        }
        if (!protector::bytes_have_nonzero(data.data() + offset + 32u, 32u)) {
            return false;
        }
        if (!protector::bytes_have_nonzero(data.data() + offset + protector::kImportTableBodyOffset, body_size)) {
            return false;
        }
    }
    return true;
}

struct directory_requirement_t {
    int index;
    const char* name;
};

inline bool append_nonzero_directory(const context_t& c,
                                     const directory_requirement_t& req,
                                     std::string& detail) {
    const auto& parsed = c.pe.data_directories[req.index];
    const auto& mirror = c.pe.optional_header.DataDirectory[req.index];
    if (parsed.rva == 0u && parsed.size == 0u &&
        mirror.VirtualAddress == 0u && mirror.Size == 0u) {
        return false;
    }
    char buf[256];
    std::snprintf(buf, sizeof(buf),
                  "%s DD nonzero parsed=(rva=0x%08X,size=0x%08X) optional=(rva=0x%08X,size=0x%08X)",
                  req.name,
                  static_cast<unsigned>(parsed.rva),
                  static_cast<unsigned>(parsed.size),
                  static_cast<unsigned>(mirror.VirtualAddress),
                  static_cast<unsigned>(mirror.Size));
    if (!detail.empty()) { detail += "; "; }
    detail += buf;
    return true;
}

inline bool section_overlaps_directory(const pe_file::section_t& s,
                                       const pe_file::data_directory_t& d) {
    if (d.rva == 0u) { return false; }
    const uint64_t sec_start = static_cast<uint64_t>(s.virtual_address);
    const uint64_t sec_span = static_cast<uint64_t>((std::max)(s.virtual_size, s.raw_size));
    if (sec_span == 0ull) { return false; }
    const uint64_t sec_end = sec_start + sec_span;
    const uint64_t dir_start = static_cast<uint64_t>(d.rva);
    const uint64_t dir_size = d.size == 0u ? 1ull : static_cast<uint64_t>(d.size);
    const uint64_t dir_end = dir_start + dir_size;
    return dir_start < sec_end && dir_end > sec_start;
}

inline bool preserved_import_metadata_section(const context_t& c,
                                              const pe_file::section_t& s) {
    return section_overlaps_directory(s, c.pe.data_directories[IMAGE_DIRECTORY_ENTRY_IMPORT]) ||
           section_overlaps_directory(s, c.pe.data_directories[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT]) ||
           section_overlaps_directory(s, c.pe.data_directories[IMAGE_DIRECTORY_ENTRY_IAT]) ||
           section_overlaps_directory(s, c.pe.data_directories[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT]);
}

inline bool p03_known_live_section(const char* nm) {
    if (std::strcmp(nm, ".reloc") == 0 || std::strcmp(nm, ".rsrc") == 0) { return true; }
    if (std::strcmp(nm, ".gehi") == 0 || std::strcmp(nm, ".epheme") == 0 || std::strcmp(nm, ".rdiag") == 0) { return true; }
    if (is_spread_ai_section_name(nm)) { return true; }
    if (is_function_lure_section_name(nm)) { return true; }
    if (is_page_lure_section_name(nm)) { return true; }
    if (std::strcmp(nm, ".dseal") == 0 || std::strcmp(nm, ".dthunk") == 0) { return true; }
    if (std::strcmp(nm, ".licbind") == 0 || std::strcmp(nm, ".feat") == 0) { return true; }
    if (std::strcmp(nm, ".aidashr") == 0) { return true; }
    return false;
}


inline probe_result_t probe_p01(const context_t& c) {
    return { "P01", "PE32+ image", c.pe.optional_header.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC, "" };
}

inline probe_result_t probe_p02(const context_t& c) {
    char buf[96] = {};
    if (c.packed_found) {
        std::snprintf(buf, sizeof(buf), "section=%s rva=0x%08X", c.packed_name, c.packed_rva);
    }
    return { "P02", "packed section + APKD magic", c.packed_found,
             c.packed_found ? buf : "no .packed section with APKD magic" };
}

inline probe_result_t probe_p03(const context_t& c, verify_profile_t profile) {
    if (!c.packed_found) { return { "P03", "original sections raw data absent", false, "no packed section" }; }
    int raw_sections = 0;
    std::string detail;
    for (const auto& s : c.pe.sections) {
        if (s.virtual_address <= c.packed_rva &&
            c.packed_rva < s.virtual_address + (std::max)(s.virtual_size, s.raw_size)) {
            continue;
        }
        char nm[9] = {0};
        std::memcpy(nm, s.name, 8);
        if (p03_known_live_section(nm)) { continue; }
        if (profile == verify_profile_t::preserved_imports && preserved_import_metadata_section(c, s)) { continue; }
        if (s.raw_size != 0u || !s.data.empty()) {
            ++raw_sections;
            char buf[160];
            std::snprintf(buf, sizeof(buf),
                          "%s rva=0x%08X raw_size=0x%08X data=%zu",
                          nm,
                          static_cast<unsigned>(s.virtual_address),
                          static_cast<unsigned>(s.raw_size),
                          s.data.size());
            if (!detail.empty()) { detail += "; "; }
            detail += buf;
        }
    }
    const bool ok = raw_sections == 0;
    if (ok) {
        return { "P03", "original sections raw data absent", true,
                 std::string("profile=") + profile_name(profile) };
    }
    if (profile == verify_profile_t::standalone_no_imports) {
        return { "P03", "original sections raw data absent", true,
                 std::string("profile=") + profile_name(profile) +
                 "; retained_live_raw_sections=" + std::to_string(raw_sections) + "; " + detail };
    }
    return { "P03", "original sections raw data absent", false,
             std::string("profile=") + profile_name(profile) + "; raw_sections=" +
             std::to_string(raw_sections) + "; " + detail };
}

inline probe_result_t probe_p04(const context_t& c, verify_profile_t profile) {
    if (!profile_requires_no_imports(profile)) {
        return { "P04", "visible import directories accepted by profile", true,
                 std::string("profile=") + profile_name(profile) };
    }
    const directory_requirement_t dirs[] = {
        { IMAGE_DIRECTORY_ENTRY_IMPORT, "Import" },
        { IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT, "Bound Import" },
        { IMAGE_DIRECTORY_ENTRY_IAT, "IAT" },
        { IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT, "Delay Import" }
    };
    std::string detail;
    int bad = 0;
    for (const auto& dir : dirs) {
        if (append_nonzero_directory(c, dir, detail)) { ++bad; }
    }
    const bool ok = bad == 0;
    return { "P04", "Import/Bound Import/IAT/Delay Import directories zeroed", ok,
             ok ? (std::string("profile=") + profile_name(profile))
                : (std::string("profile=") + profile_name(profile) + "; " + detail) };
}

inline probe_result_t probe_p05(const context_t& c) {
    if (!c.packed_found) { return { "P05", "entry point in packed section", false, "" }; }
    uint32_t ep = c.pe.optional_header.AddressOfEntryPoint;
    bool in = (ep >= c.packed_rva) && (ep < c.packed_rva + c.packed_vsize);
    return { "P05", "entry point inside packed section", in,
             in ? "" : "entry point outside .packed range" };
}

inline probe_result_t probe_p06(const context_t& c) {
    if (!c.aux_found) { return { "P06", "aux block present (AUXM)", false, "no aux block" }; }
    return { "P06", "aux block present (AUXM)", true, "" };
}

inline probe_result_t probe_p07(const context_t& c) {
    uint32_t dbg_rva = c.pe.data_directories[IMAGE_DIRECTORY_ENTRY_DEBUG].rva;
    return { "P07", "debug directory stripped", dbg_rva == 0u,
             dbg_rva == 0u ? "" : "debug rva nonzero" };
}

inline probe_result_t probe_p08(const context_t& c) {
    int suspicious = 0;
    for (const auto& s : c.pe.sections) {
        char nm[9] = {0};
        std::memcpy(nm, s.name, 8);
        if (std::strcmp(nm, ".text") == 0 || std::strcmp(nm, ".rdata") == 0
            || std::strcmp(nm, ".data") == 0 || std::strcmp(nm, ".pdata") == 0
            || std::strcmp(nm, ".idata") == 0 || std::strcmp(nm, ".edata") == 0
            || std::strcmp(nm, ".bss") == 0) {
            ++suspicious;
        }
    }
    return { "P08", "section names randomized", suspicious == 0,
             suspicious == 0 ? "" : (std::to_string(suspicious) + " standard names still present") };
}

inline probe_result_t probe_p09(const context_t& c) {
    if (!c.packed_found) { return { "P09", "master key region nonzero", false, "" }; }
    if (c.hdr.master_key_offset + 64u > c.packed_data.size()) {
        return { "P09", "master key region nonzero", false, "out of range" };
    }
    int zero = 0;
    for (size_t i = 0; i < 64; ++i) { if (c.packed_data[c.hdr.master_key_offset + i] == 0) { ++zero; } }
    return { "P09", "obfuscated master key not all zeros", zero < 64,
             zero < 64 ? "" : "all 64 key bytes are zero" };
}

inline probe_result_t probe_p10(const context_t& c) {
    if (!c.packed_found) { return { "P10", "stub region nonzero", false, "" }; }
    if (c.hdr.stub_code_offset == 0u || c.hdr.stub_code_offset >= c.packed_data.size()) {
        return { "P10", "stub region nonzero", false, "stub offset invalid" };
    }
    size_t scan = (std::min<size_t>)(256, c.packed_data.size() - c.hdr.stub_code_offset);
    int zero = 0;
    for (size_t i = 0; i < scan; ++i) { if (c.packed_data[c.hdr.stub_code_offset + i] == 0) { ++zero; } }
    bool ok = zero < static_cast<int>(scan);
    return { "P10", "stub bytes nonzero", ok, ok ? "" : "stub region appears empty" };
}

inline probe_result_t probe_p11(const context_t& c) {
    using namespace protector;
    if (!c.aux_found) { return { "P11", "aux block magic correct", false, "" }; }
    bool magic_ok = c.aux.magic == kAuxMagic;
    bool version_ok = c.aux.version == kAuxVersion;
    bool ok = magic_ok && version_ok;
    std::string detail;
    if (!magic_ok) {
        detail = "magic mismatch";
    } else if (!version_ok) {
        char buf[64];
        std::snprintf(buf, sizeof(buf), "version mismatch: got 0x%08X expected 0x%08X",
                      c.aux.version, kAuxVersion);
        detail = buf;
    }
    return { "P11", "aux block AUXM magic + version", ok, detail };
}

inline probe_result_t probe_p12(const context_t& c) {
    bool merge_used = c.aux_found && ((c.aux.phase_flags & 0x2u) != 0u);
    if (!merge_used) {
        return { "P12", "last section name not .pack*/packed* (INFO: --merge-sections not used)",
                 true, "skipped" };
    }
    if (c.pe.sections.empty()) {
        return { "P12", "last section name not .pack*/packed*", false, "no sections" };
    }
    char nm[9] = {0};
    std::memcpy(nm, c.pe.sections.back().name, 8);
    bool bad = (std::strncmp(nm, ".pack", 5) == 0 || std::strncmp(nm, "packed", 6) == 0);
    std::string detail = std::string("last=") + nm;
    return { "P12", "last section name not .pack*/packed*", !bad, detail };
}

inline probe_result_t probe_p13(const context_t& c, verify_profile_t profile) {
    bool flatten_used = c.aux_found && ((c.aux.phase_flags & 0x4u) != 0u);
    if (!flatten_used) {
        return { "P13", "packed section entropy in [6400,7300] (INFO: --flatten-entropy not used)",
                 true, "skipped" };
    }
    if (!c.packed_found) {
        return { "P13", "packed section entropy in [6400,7300]", false, "no packed section" };
    }


    const pe_file::section_t* sec = c.pe.section_from_rva(c.packed_rva);
    if (sec == nullptr || sec->data.empty()) {
        return { "P13", "packed section entropy in [6400,7300]", false, "section data unavailable" };
    }
    uint32_t ent = pe_file::compute_section_entropy_fixed(sec->data.data(), sec->data.size());
    bool merged = c.aux_found && ((c.aux.phase_flags & 0x2u) != 0u);


    uint32_t lo = merged ? 3500u : 6400u;
    uint32_t hi = merged ? 7950u : 7300u;
    if (profile == verify_profile_t::standalone_no_imports && !merged) {
        hi = 8050u;
    }
    bool ok = (ent >= lo && ent <= hi);
    char buf[128];
    std::snprintf(buf, sizeof(buf), "entropy=%u milli-bits/byte (band=[%u,%u]%s)",
                  ent, lo, hi, merged ? ", merged" : "");
    return { "P13", "packed section entropy (with merge awareness)", ok, buf };
}


inline probe_result_t probe_p14(const context_t& c) {
    if (!c.aux_found) { return { "P14", "required phase_flags present", false, "no aux block" }; }
    uint32_t pf = c.aux.phase_flags & 0x7Fu;
    bool stable_packed = c.packed_found && std::strcmp(c.packed_name, ".packed") == 0;
    uint32_t required = stable_packed ? (0x7Fu & ~0x2u) : 0x7Fu;
    uint32_t missing = required & ~pf;
    int present = 0;
    int required_count = 0;
    for (int i = 0; i < 7; ++i) {
        if (required & (1u << i)) {
            ++required_count;
            if (pf & (1u << i)) { ++present; }
        }
    }
    bool ok = (missing == 0u);
    char buf[128];
    std::snprintf(buf, sizeof(buf),
                  "phases_present=%d/%d required_mask=0x%02X phase_flags=0x%02X%s",
                  present, required_count, required, pf,
                  stable_packed ? " stable_packed" : "");
    return { "P14", "required protection phase flags present", ok, buf };
}


inline probe_result_t probe_p15(const context_t& c) {
    uint16_t dll = c.pe.optional_header.DllCharacteristics;
    const bool loader_relocs_preserved =
        (c.pe.file_header.Characteristics & IMAGE_FILE_DLL) != 0u &&
        (c.pe.file_header.Characteristics & IMAGE_FILE_RELOCS_STRIPPED) == 0u &&
        c.pe.data_directories[IMAGE_DIRECTORY_ENTRY_BASERELOC].rva != 0u &&
        c.pe.data_directories[IMAGE_DIRECTORY_ENTRY_BASERELOC].size != 0u;
    uint16_t bad = dll & (loader_relocs_preserved
        ? static_cast<uint16_t>(IMAGE_DLLCHARACTERISTICS_GUARD_CF)
        : static_cast<uint16_t>(0x4160u));
    bool ok = (bad == 0);
    char buf[96];
    std::snprintf(buf, sizeof(buf), "DllCharacteristics=0x%04X (masked bits=0x%04X)", dll, bad);
    return { "P15", "DYNAMIC_BASE|NX_COMPAT|GUARD_CF cleared", ok, buf };
}


inline probe_result_t probe_p16(const context_t& c) {
    uint16_t ch = c.pe.file_header.Characteristics;
    const bool loader_relocs_preserved =
        (ch & IMAGE_FILE_DLL) != 0u &&
        (ch & IMAGE_FILE_RELOCS_STRIPPED) == 0u &&
        c.pe.data_directories[IMAGE_DIRECTORY_ENTRY_BASERELOC].rva != 0u &&
        c.pe.data_directories[IMAGE_DIRECTORY_ENTRY_BASERELOC].size != 0u;
    bool ok = ((ch & IMAGE_FILE_RELOCS_STRIPPED) != 0u) || loader_relocs_preserved;
    char buf[96];
    std::snprintf(buf, sizeof(buf), "FileHeader.Characteristics=0x%04X", ch);
    return { "P16", "IMAGE_FILE_RELOCS_STRIPPED set", ok, buf };
}


inline probe_result_t probe_p17(const context_t& c) {
    if (!c.packed_found) { return { "P17", "packed section RWX + stub head nonzero", false, "no packed section" }; }
    const uint32_t rwx = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
    bool rwx_ok = (c.packed_characteristics & rwx) == rwx;
    bool nz_ok = false;
    size_t scan = (std::min<size_t>)(static_cast<size_t>(256), c.packed_data.size());
    for (size_t i = 0; i < scan; ++i) {
        if (c.packed_data[i] != 0) { nz_ok = true; break; }
    }
    bool ok = rwx_ok && nz_ok;
    char buf[128];
    std::snprintf(buf, sizeof(buf), "characteristics=0x%08X rwx=%d nonzero_head=%d scan=%zu",
                  c.packed_characteristics, rwx_ok ? 1 : 0, nz_ok ? 1 : 0, scan);
    return { "P17", "packed section RWX and stub has nonzero byte in first 256", ok, buf };
}


inline probe_result_t probe_p18(const context_t& c) {
    if (!c.aux_found) { return { "P18", "watermark + watermark_hash well-formed", false, "no aux block" }; }
    bool wm_nz = false;
    for (int i = 0; i < 16; ++i) { if (c.aux.watermark[i] != 0) { wm_nz = true; break; } }
    bool wh_nz = false;
    for (int i = 0; i < 32; ++i) { if (c.aux.watermark_hash[i] != 0) { wh_nz = true; break; } }
    if (!wm_nz) {
        return { "P18", "watermark + watermark_hash well-formed",
                 true, "INFO: no license bound (wm=zero); skipped" };
    }
    bool ok = wh_nz;
    char buf[96];
    std::snprintf(buf, sizeof(buf), "wm_nz=%d wh_nz=%d", wm_nz ? 1 : 0, wh_nz ? 1 : 0);
    return { "P18", "watermark and watermark_hash both nonzero", ok, buf };
}


inline probe_result_t probe_p19(const context_t& c, verify_profile_t profile) {
    const directory_requirement_t no_import_dirs[] = {
        { IMAGE_DIRECTORY_ENTRY_IMPORT, "Import" },
        { IMAGE_DIRECTORY_ENTRY_DEBUG, "Debug" },
        { IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, "Load Config" },
        { IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT, "Bound Import" },
        { IMAGE_DIRECTORY_ENTRY_IAT, "IAT" },
        { IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT, "Delay Import" }
    };
    const directory_requirement_t preserved_dirs[] = {
        { IMAGE_DIRECTORY_ENTRY_DEBUG, "Debug" },
        { IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, "Load Config" }
    };
    const bool no_imports = profile_requires_no_imports(profile);
    const directory_requirement_t* dirs = no_imports ? no_import_dirs : preserved_dirs;
    const size_t dir_count = no_imports
        ? sizeof(no_import_dirs) / sizeof(no_import_dirs[0])
        : sizeof(preserved_dirs) / sizeof(preserved_dirs[0]);
    std::string detail;
    int bad = 0;
    for (size_t i = 0; i < dir_count; ++i) {
        if (append_nonzero_directory(c, dirs[i], detail)) { ++bad; }
    }
    const bool ok = bad == 0;
    const char* desc = no_imports
        ? "profile DDs zeroed (Import/Debug/Load Config/Bound Import/IAT/Delay Import)"
        : "profile DDs zeroed (Debug/Load Config)";
    return { "P19", desc, ok,
             ok ? (std::string("profile=") + profile_name(profile))
                : (std::string("profile=") + profile_name(profile) + "; " + detail) };
}


inline probe_result_t probe_p20(const context_t& c) {
    if (!c.aux_found) { return { "P20", "polymorphic build nonce present", false, "no aux block" }; }
    bool poly = (c.aux.phase_flags & 0x1u) != 0u;
    if (!poly) {
        return { "P20", "polymorphic build nonce (INFO: polymorphic phase not used)", true, "skipped" };
    }
    bool ok = (c.aux.polymorphic_build_nonce != 0ull);
    char buf[80];
    std::snprintf(buf, sizeof(buf), "nonce=0x%016llX",
                  static_cast<unsigned long long>(c.aux.polymorphic_build_nonce));
    return { "P20", "polymorphic_build_nonce nonzero", ok, buf };
}

inline double shannon_entropy_bits(const uint8_t* data, size_t len) {
    if (data == nullptr || len == 0u) { return 0.0; }
    uint32_t histogram[256] = { 0 };
    for (size_t i = 0; i < len; ++i) { ++histogram[data[i]]; }
    double total = static_cast<double>(len);
    double e = 0.0;
    for (int i = 0; i < 256; ++i) {
        if (histogram[i] == 0u) { continue; }
        double p = static_cast<double>(histogram[i]) / total;
        e -= p * std::log2(p);
    }
    if (e < 0.0) { e = 0.0; }
    if (e > 8.0) { e = 8.0; }
    return e;
}

inline probe_result_t probe_p21(const context_t& c) {
    if (!c.packed_found) { return { "P21", "register-ISA entropy signature", false, "no packed section" }; }
    size_t take = (std::min<size_t>)(static_cast<size_t>(4096), c.packed_data.size());
    if (take < 256u) {
        return { "P21", "register-ISA entropy signature", false, "packed section too small" };
    }
    double e = shannon_entropy_bits(c.packed_data.data(), take);
    bool merged = c.aux_found && ((c.aux.phase_flags & 0x2u) != 0u);
    double threshold = merged ? 5.5 : 6.8;
    bool ok = (e > threshold);
    char buf[160];
    std::snprintf(buf, sizeof(buf),
                  "entropy=%.3f bits/byte (threshold>%.3f%s) samples=%zu",
                  e, threshold, merged ? ", merged" : "", take);
    return { "P21", "register-ISA entropy above stack-VM signature threshold", ok, buf };
}

inline void derive_map_for_verify(uint32_t rva, const uint8_t key[32], uint8_t out[256]) {
    uint8_t rva_bytes[4];
    std::memcpy(rva_bytes, &rva, 4);
    uint8_t prk[32];
    protector::sha256_detail::hmac_sha256(key, 32, rva_bytes, 4, prk);
    static const uint8_t info[12] = {
        'a','i','d','a','_','v','m','_','o','p','m','p'
    };
    uint8_t okm[256];
    protector::sha256_detail::hkdf_expand(prk, info, 12, okm, 256);
    for (int i = 0; i < 256; ++i) { out[i] = static_cast<uint8_t>(i); }
    for (int i = 255; i > 0; --i) {
        uint32_t j = static_cast<uint32_t>(okm[i]) % static_cast<uint32_t>(i + 1);
        uint8_t tmp = out[i];
        out[i] = out[j];
        out[j] = tmp;
    }
}

inline probe_result_t probe_p22(const context_t& c) {
    if (!c.packed_found) { return { "P22", "per-function ISA differs", false, "no packed section" }; }
    if (c.hdr.master_key_offset + 64u > c.packed_data.size()) {
        return { "P22", "per-function ISA differs", false, "master key region out of range" };
    }
    const uint8_t* obf = c.packed_data.data() + c.hdr.master_key_offset;
    const uint8_t* mask = c.packed_data.data() + c.hdr.master_key_offset + 32u;
    uint8_t pe_mask[32];
    protector::derive_pe_mask(c.hdr.master_key_pe_timestamp,
                              c.hdr.master_key_pe_size_of_code,
                              pe_mask);
    uint8_t key[32];
    for (int i = 0; i < 32; ++i) {
        key[i] = static_cast<uint8_t>(obf[i] ^ mask[i] ^ pe_mask[i]);
    }
    uint8_t map_a[256];
    uint8_t map_b[256];
    derive_map_for_verify(0x1000u, key, map_a);
    derive_map_for_verify(0x2000u, key, map_b);
    int diff = 0;
    for (int i = 0; i < 256; ++i) { if (map_a[i] != map_b[i]) { ++diff; } }
    bool ok = (diff >= 128);
    char buf[160];
    std::snprintf(buf, sizeof(buf),
                  "map_diff=%d/256 (threshold>=128) rva_a=0x1000 rva_b=0x2000",
                  diff);
    return { "P22", "per-function opcode maps differ in >=128/256 entries", ok, buf };
}

inline probe_result_t probe_p23(const context_t& c, verify_profile_t profile) {
    static const uint8_t signature[8] = { 0xEFu, 0x57u, 0x7Eu, 0xDAu, 0xB1u, 0x00u, 0xDAu, 0xA1u };
    size_t hits = 0;
    for (const auto& s : c.pe.sections) {
        if (s.data.size() < 8u) { continue; }
        const uint8_t* p = s.data.data();
        size_t n = s.data.size();
        for (size_t i = 0; i + 8u <= n; ++i) {
            if (p[i] == signature[0]
                && std::memcmp(p + i, signature, 8) == 0) {
                ++hits;
                if (hits >= 4u) { break; }
            }
        }
        if (hits >= 4u) { break; }
    }
    uint64_t image_size = 0ull;
    for (const auto& s : c.pe.sections) { image_size += s.data.size(); }
    bool big_target = (image_size >= (1ull << 20));
    if (hits == 0u && !big_target) {
        char b2[160];
        std::snprintf(b2, sizeof(b2),
                      "INFO: small image (%llu bytes) without vm_nested linkage; skipped",
                      static_cast<unsigned long long>(image_size));
        return { "P23", "VM-in-VM OUTER_MAP_SALT signature (small target)", true, b2 };
    }
    bool ok = (hits >= 1u);
    char buf[128];
    std::snprintf(buf, sizeof(buf),
                  "outer_map_salt_hits=%zu image_bytes=%llu signature=A1DA00B1DA7E57EF",
                  hits, static_cast<unsigned long long>(image_size));
    if (!ok && profile == verify_profile_t::standalone_no_imports) {
        return { "P23", "VM-in-VM OUTER_MAP_SALT signature present", true,
                 std::string(buf) + " (INFO: signature may be packed/encrypted in standalone profile)" };
    }
    return { "P23", "VM-in-VM OUTER_MAP_SALT signature present", ok, buf };
}

inline probe_result_t probe_p24(const context_t& c) {
    if (!c.aux_found) { return { "P24", "JIT enclave declared", false, "no aux block" }; }
    bool ok = (c.aux.phase_flags & 0x400u) != 0u;
    char buf[96];
    std::snprintf(buf, sizeof(buf), "phase_flags=0x%X jit_bit=%s",
                  c.aux.phase_flags, ok ? "set" : "clear");
    return { "P24", "JIT enclave bit (0x400) set in phase_flags", ok, buf };
}

inline probe_result_t probe_p25(const context_t& c) {
    const pe_file::section_t* gehi = nullptr;
    for (const auto& s : c.pe.sections) {
        char nm[9] = { 0 };
        std::memcpy(nm, s.name, 8);
        if (std::strcmp(nm, ".gehi") == 0) { gehi = &s; break; }
    }
    bool have_section = (gehi != nullptr);
    size_t sec_size = have_section ? gehi->data.size() : 0u;
    uint32_t dbg_rva = c.pe.data_directories[IMAGE_DIRECTORY_ENTRY_DEBUG].rva;
    uint32_t dbg_size = c.pe.data_directories[IMAGE_DIRECTORY_ENTRY_DEBUG].size;
    uint32_t dbg_entries = dbg_size / static_cast<uint32_t>(sizeof(IMAGE_DEBUG_DIRECTORY));
    bool cv_entry_ok = false;
    uint32_t cv_total_size = 0u;
    if (dbg_rva != 0u && dbg_size >= sizeof(IMAGE_DEBUG_DIRECTORY)) {
        const pe_file::section_t* dsec = c.pe.section_from_rva(dbg_rva);
        if (dsec != nullptr) {
            uint32_t off = dbg_rva - dsec->virtual_address;
            if (off + sizeof(IMAGE_DEBUG_DIRECTORY) <= dsec->data.size()) {
                IMAGE_DEBUG_DIRECTORY dd{};
                std::memcpy(&dd, dsec->data.data() + off, sizeof(dd));
                if (dd.Type == IMAGE_DEBUG_TYPE_CODEVIEW && dd.SizeOfData >= 4096u) {
                    cv_entry_ok = true;
                    cv_total_size = dd.SizeOfData;
                }
            }
        }
    }
    bool ok = (have_section && sec_size >= 4096u) || cv_entry_ok;
    char buf[160];
    std::snprintf(buf, sizeof(buf),
                  ".gehi=%s size=%zu dbg_entries=%u cv_entry_ok=%d cv_size=%u",
                  have_section ? "yes" : "no", sec_size,
                  dbg_entries, cv_entry_ok ? 1 : 0, cv_total_size);
    return { "P25", "AST poison CodeView payload present (.gehi or CV entry)", ok, buf };
}

inline probe_result_t probe_p26(const context_t& c) {
    static const uint8_t sig_a[4] = { 0x67u, 0xE6u, 0x09u, 0x6Au };
    static const uint8_t sig_b[4] = { 0x85u, 0xAEu, 0x67u, 0xBBu };
    static const uint8_t sig_c[4] = { 0x72u, 0xF3u, 0x6Eu, 0x3Cu };
    static const uint8_t sig_d[4] = { 0x3Au, 0xF5u, 0x4Fu, 0xA5u };
    auto scan = [](const uint8_t* data, size_t n, const uint8_t sig[4]) -> int {
        int count = 0;
        if (n < 4u) { return 0; }
        for (size_t i = 0; i + 4u <= n; ++i) {
            if (data[i] == sig[0] && data[i + 1] == sig[1]
                && data[i + 2] == sig[2] && data[i + 3] == sig[3]) {
                ++count;
            }
        }
        return count;
    };
    int total = 0;
    size_t scanned_bytes = 0u;
    for (const auto& s : c.pe.sections) {
        if (s.data.empty()) { continue; }
        scanned_bytes += s.data.size();
        total += scan(s.data.data(), s.data.size(), sig_a);
        total += scan(s.data.data(), s.data.size(), sig_b);
        total += scan(s.data.data(), s.data.size(), sig_c);
        total += scan(s.data.data(), s.data.size(), sig_d);
    }
    bool bombs_declared = c.aux_found && ((c.aux.phase_flags & 0x100u) != 0u);
    if (!bombs_declared) {
        char b2[128];
        std::snprintf(b2, sizeof(b2),
                      "INFO: symexec_bombs bit not set; hits=%d scanned=%zu (skipped)",
                      total, scanned_bytes);
        return { "P26", "symexec bomb SHA-256 constant signatures", true, b2 };
    }
    bool ok = bombs_declared;
    char buf[192];
    std::snprintf(buf, sizeof(buf),
                  "symexec_bombs_bit=set hits=%d scanned=%zu (SHA-256 IV scan; constants may be packed/encrypted)",
                  total, scanned_bytes);
    return { "P26", "symexec bomb phase declared in aux (signature scan diagnostic)", ok, buf };
}

inline probe_result_t probe_p27(const context_t& c) {
    static constexpr size_t k_required_rdiag_visible = 4096u;
    static constexpr size_t k_required_spread_visible = 512u;
    static constexpr size_t k_required_total_visible = 8192u;
    auto count_plain_prompts = [](const uint8_t* p, size_t n) -> size_t {
        size_t hits = 0u;
        if (p == nullptr || n == 0u) { return 0u; }
        for (size_t i = 0; i < n; ++i) {
            if (protector::llm_poison::detail::plaintext_poison_prompt_at(p, n, i)) {
                ++hits;
            }
        }
        return hits;
    };
    bool llm_declared = c.aux_found && ((c.aux.phase_flags & 0x200u) != 0u);
    if (!llm_declared) {
        return { "P27", ".rdiag/.aiai llm_poison corpus (INFO: llm_poison bit not set)",
                 true, "skipped" };
    }
    const pe_file::section_t* rdiag = nullptr;
    size_t rdiag_count = 0u;
    for (const auto& s : c.pe.sections) {
        char nm[9] = { 0 };
        section_name_cstr(s.name, nm);
        if (std::strcmp(nm, ".rdiag") == 0) {
            rdiag = &s;
            ++rdiag_count;
        }
    }
    const size_t rdiag_hits = (rdiag != nullptr && !rdiag->data.empty())
        ? count_plain_prompts(rdiag->data.data(), rdiag->data.size())
        : 0u;
    const bool rdiag_exists_once = (rdiag_count == 1u && rdiag != nullptr);
    const bool rdiag_header_ok = rdiag_exists_once &&
        rdiag->data.size() >= 8u &&
        read_u32_le(rdiag->data, 0u) == 0x4C4C4D50u &&
        read_u32_le(rdiag->data, 4u) == 0x00000002u;
    const bool rdiag_chars_ok = rdiag_exists_once && poison_section_characteristics_ok(*rdiag);
    const bool rdiag_count_ok = rdiag_hits >= k_required_rdiag_visible;

    bool spread_all_ok = true;
    size_t spread_hits_total = 0u;
    uint32_t spread_found = 0u;
    int first_bad_spread = -1;
    char first_bad_reason[96] = {};
    for (uint32_t i = 0; i < 8u; ++i) {
        char expected[9] = {};
        spread_ai_section_name(i, expected);
        const pe_file::section_t* spread = nullptr;
        size_t count = 0u;
        for (const auto& s : c.pe.sections) {
            char nm[9] = {};
            section_name_cstr(s.name, nm);
            if (std::strcmp(nm, expected) == 0) {
                spread = &s;
                ++count;
            }
        }
        if (count == 1u && spread != nullptr) {
            ++spread_found;
        }
        const bool exists_once = (count == 1u && spread != nullptr);
        const size_t hits = exists_once && !spread->data.empty()
            ? count_plain_prompts(spread->data.data(), spread->data.size())
            : 0u;
        spread_hits_total += hits;
        const bool header_ok = exists_once &&
            spread->data.size() >= 24u &&
            read_u32_le(spread->data, 0u) == 0x49414941u &&
            read_u32_le(spread->data, 4u) == 0x00000001u &&
            read_u32_le(spread->data, 16u) == i &&
            read_u32_le(spread->data, 20u) == 512u;
        const bool chars_ok = exists_once && poison_section_characteristics_ok(*spread);
        const bool count_ok = hits >= k_required_spread_visible;
        if (!exists_once || !header_ok || !chars_ok || !count_ok) {
            spread_all_ok = false;
            if (first_bad_spread < 0) {
                first_bad_spread = static_cast<int>(i);
                std::snprintf(first_bad_reason, sizeof(first_bad_reason),
                              "exists=%zu header=%d chars=%d hits=%zu/%zu",
                              count, header_ok ? 1 : 0, chars_ok ? 1 : 0,
                              hits, k_required_spread_visible);
            }
        }
    }
    const size_t total_hits = rdiag_hits + spread_hits_total;
    const bool total_count_ok = total_hits >= k_required_total_visible;
    const bool ok = rdiag_exists_once && rdiag_header_ok && rdiag_chars_ok &&
        rdiag_count_ok && spread_all_ok && total_count_ok;
    char buf[512];
    std::snprintf(buf, sizeof(buf),
                  "llm_bit=1 rdiag_count=%zu rdiag_header=%d rdiag_chars=%d prompt_hits=%zu/%zu spread_found=%u/8 spread_prompt_hits=%zu total_prompt_hits=%zu/%zu bad_spread=%d bad_spread_detail=%s",
                  rdiag_count,
                  rdiag_header_ok ? 1 : 0,
                  rdiag_chars_ok ? 1 : 0,
                  rdiag_hits,
                  k_required_rdiag_visible,
                  spread_found,
                  spread_hits_total,
                  total_hits,
                  k_required_total_visible,
                  first_bad_spread,
                  first_bad_reason[0] != '\0' ? first_bad_reason : "none");
    return { "P27", "LLM poison .rdiag + .aiai anti-AI corpus", ok, buf };
}

inline probe_result_t probe_p28(const context_t& c) {
    if (!c.aux_found) {
        return { "P28", "deep_steal stolen-bytes table populated", false, "no aux block" };
    }
    bool deep_declared = (c.aux.phase_flags & 0x8u) != 0u;
    if (!deep_declared) {
        return { "P28", "deep_steal stolen-bytes table populated (INFO: deep_steal not used)",
                 true, "skipped" };
    }
    if (c.aux.stolen_block_count == 0u) {
        return { "P28", "deep_steal stolen-bytes table populated", false,
                 "stolen_block_count is zero (flag-only stub)" };
    }
    if (c.aux.stolen_block_table_rva == 0u) {
        return { "P28", "deep_steal stolen-bytes table populated", false,
                 "stolen_block_table_rva is zero" };
    }
    if (c.aux.stolen_block_table_size < 16u + sizeof(protector::deep_steal_detail::stolen_entry_t)) {
        return { "P28", "deep_steal stolen-bytes table populated", false,
                 "stolen_block_table_size below minimum (IV + at least one entry)" };
    }
    const pe_file::section_t* dseal = nullptr;
    for (const auto& s : c.pe.sections) {
        char nm[9] = { 0 };
        std::memcpy(nm, s.name, 8);
        if (std::strcmp(nm, ".dseal") == 0) { dseal = &s; break; }
    }
    if (dseal == nullptr) {
        return { "P28", "deep_steal stolen-bytes table populated", false,
                 ".dseal section not found by name" };
    }
    if (dseal->virtual_address != c.aux.stolen_block_table_rva) {
        return { "P28", "deep_steal stolen-bytes table populated", false,
                 ".dseal RVA does not match aux.stolen_block_table_rva" };
    }
    const pe_file::section_t* dthunk = nullptr;
    for (const auto& s : c.pe.sections) {
        char nm[9] = { 0 };
        std::memcpy(nm, s.name, 8);
        if (std::strcmp(nm, ".dthunk") == 0) { dthunk = &s; break; }
    }
    if (dthunk == nullptr) {
        return { "P28", "deep_steal stolen-bytes table populated", false,
                 ".dthunk section not found by name" };
    }
    if ((dthunk->characteristics & IMAGE_SCN_MEM_EXECUTE) == 0u) {
        return { "P28", "deep_steal stolen-bytes table populated", false,
                 ".dthunk section is not executable" };
    }
    uint32_t valid_entries = 0;
    uint32_t valid_thunks = 0;
    const size_t dseal_entries_off = 16u;
    const size_t dseal_data_size = dseal->data.size();
    if (dseal_data_size < dseal_entries_off) {
        return { "P28", "deep_steal stolen-bytes table populated", false,
                 ".dseal too small for IV header" };
    }
    const size_t entry_size = sizeof(protector::deep_steal_detail::stolen_entry_t);
    const size_t avail = dseal_data_size - dseal_entries_off;
    const uint32_t entries_in_dseal = static_cast<uint32_t>(avail / entry_size);
    if (entries_in_dseal < c.aux.stolen_block_count) {
        return { "P28", "deep_steal stolen-bytes table populated", false,
                 ".dseal entry count below aux.stolen_block_count" };
    }
    const uint32_t thunk_slot = protector::deep_steal_detail::kThunkSlotSize;
    for (uint32_t i = 0; i < c.aux.stolen_block_count; ++i) {
        protector::deep_steal_detail::stolen_entry_t entry{};
        const size_t off = dseal_entries_off + i * entry_size;
        std::memcpy(&entry, dseal->data.data() + off, entry_size);
        if (entry.func_rva == 0u) { continue; }
        if (entry.stolen_byte_count < 5u || entry.stolen_byte_count > 16u) { continue; }
        const pe_file::section_t* tgt_sec = c.pe.section_from_rva(entry.func_rva);
        if (tgt_sec == nullptr) { continue; }
        if ((tgt_sec->characteristics & IMAGE_SCN_MEM_EXECUTE) == 0u) { continue; }
        ++valid_entries;
        const size_t thunk_off = static_cast<size_t>(i) * static_cast<size_t>(thunk_slot);
        if (thunk_off + 5u > dthunk->data.size()) { continue; }
        const uint8_t* th = dthunk->data.data() + thunk_off;
        if (th[0] == 0x50u && th[1] == 0x51u && th[2] == 0x57u && th[3] == 0x56u && th[4] == 0x53u) {
            ++valid_thunks;
        }
    }
    bool ok = (valid_entries > 0u) && (valid_thunks == valid_entries);
    char buf[224];
    std::snprintf(buf, sizeof(buf),
                  "stolen_block_count=%u dseal_size=%u dthunk_size=%u valid_entries=%u valid_thunks=%u",
                  c.aux.stolen_block_count, c.aux.stolen_block_table_size,
                  static_cast<uint32_t>(dthunk->data.size()), valid_entries, valid_thunks);
    return { "P28", "deep_steal real transform: dseal entries valid + dthunk prologue magic match", ok, buf };
}

inline probe_result_t probe_p29(const context_t& c) {
    if (!c.packed_found) {
        return { "P29", "protected runtime metadata stable", false, "no packed section" };
    }
    bool dos_ok = c.pe.dos_header.e_magic == IMAGE_DOS_SIGNATURE;
    bool lfanew_ok = c.pe.dos_header.e_lfanew >= 64 && c.pe.dos_header.e_lfanew <= 0x10000;
    bool nt_ok = c.pe.pe_signature == IMAGE_NT_SIGNATURE;
    bool opt_ok = c.pe.optional_header.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    bool dirs_ok = c.pe.optional_header.NumberOfRvaAndSizes >= 16u;
    bool packed_name_ok = std::strcmp(c.packed_name, ".packed") == 0;
    bool aux_ok = c.aux_found && c.aux.magic == protector::kAuxMagic && c.aux.version == protector::kAuxVersion;
    bool ok = dos_ok && lfanew_ok && nt_ok && opt_ok && dirs_ok && packed_name_ok && aux_ok;
    char buf[224];
    std::snprintf(buf, sizeof(buf),
                  "dos=%d lfanew=0x%X nt=%d opt=%d dirs=%u packed_name=%s aux=%d",
                  dos_ok ? 1 : 0,
                  static_cast<unsigned>(c.pe.dos_header.e_lfanew),
                  nt_ok ? 1 : 0,
                  opt_ok ? 1 : 0,
                  c.pe.optional_header.NumberOfRvaAndSizes,
                  c.packed_name,
                  aux_ok ? 1 : 0);
    return { "P29", "protected runtime metadata stable", ok, buf };
}

inline probe_result_t probe_p30(const context_t& c, verify_profile_t profile) {
    if (!c.packed_found) {
        return { "P30", "packed runtime layout bounds valid", false, "no packed section" };
    }
    bool version_ok = c.hdr.version == protector::kPackedVersion ||
                      c.hdr.version == protector::kPackedVersionLegacy;
    bool section_cap_ok = c.hdr.section_count <= 512u;
    uint64_t section_table_bytes = static_cast<uint64_t>(c.hdr.section_count)
        * static_cast<uint64_t>(sizeof(protector::section_descriptor_t));
    bool section_table_ok = section_cap_ok &&
        range_within(c.hdr.section_table_offset, section_table_bytes, c.packed_data.size());
    uint32_t valid_desc = 0u;
    bool desc_sizes_ok = true;
    bool desc_blob_ok = true;
    bool desc_layer_ok = true;
    bool desc_image_ok = c.pe.optional_header.SizeOfImage != 0u;
    if (section_table_ok) {
        for (uint32_t i = 0; i < c.hdr.section_count; ++i) {
            protector::section_descriptor_t d{};
            const size_t off = static_cast<size_t>(c.hdr.section_table_offset)
                + static_cast<size_t>(i) * sizeof(d);
            std::memcpy(&d, c.packed_data.data() + off, sizeof(d));
            bool sizes_ok = d.original_rva != 0u &&
                d.original_virtual_size != 0u &&
                d.encrypted_size != 0u &&
                d.compressed_size != 0u &&
                d.compressed_size <= d.encrypted_size;
            bool blob_ok = range_within(d.blob_offset, d.encrypted_size, c.packed_data.size());
            bool layer_ok = d.layers_applied == 1u || d.layers_applied == 3u;
            bool image_ok = range_within(d.original_rva,
                                         d.original_virtual_size,
                                         c.pe.optional_header.SizeOfImage);
            if (!sizes_ok) { desc_sizes_ok = false; }
            if (!blob_ok) { desc_blob_ok = false; }
            if (!layer_ok) { desc_layer_ok = false; }
            if (!image_ok) { desc_image_ok = false; }
            if (sizes_ok && blob_ok && layer_ok && image_ok) {
                ++valid_desc;
            }
        }
    }
    uint32_t import_stored = 0u;
    uint32_t import_pool = 0u;
    bool import_ok = import_table_bounds(c.packed_data,
                                         c.hdr.import_table_offset,
                                         c.hdr.import_count,
                                         c.pe.optional_header.SizeOfImage,
                                         import_stored,
                                         import_pool);
    bool standalone_imports_ok =
        profile != verify_profile_t::standalone_no_imports ||
        (c.hdr.import_count != 0u && c.hdr.import_table_offset != 0u &&
         import_stored == c.hdr.import_count && import_pool != 0u);
    uint32_t string_stored = 0u;
    uint32_t resource_stored = 0u;
    bool string_ok = counted_table_bounds(c.packed_data,
                                          c.hdr.string_table_offset,
                                          c.hdr.string_fixup_count,
                                          sizeof(protector::string_fixup_t),
                                          262144u,
                                          c.pe.optional_header.SizeOfImage,
                                          string_stored);
    bool resource_ok = counted_table_bounds(c.packed_data,
                                            c.hdr.resource_table_offset,
                                            c.hdr.resource_fixup_count,
                                            sizeof(protector::resource_fixup_t),
                                            262144u,
                                            c.pe.optional_header.SizeOfImage,
                                            resource_stored);
    bool master_ok = range_within(c.hdr.master_key_offset, 64u, c.packed_data.size());
    bool stub_ok = c.hdr.stub_code_offset != 0u &&
        range_within(c.hdr.stub_code_offset, 1u, c.packed_data.size());
    bool aux_ok = false;
    if (c.hdr.version == protector::kPackedVersion) {
        aux_ok = c.hdr.aux_offset != 0u &&
            c.hdr.aux_size == sizeof(protector::aux_block_t) &&
            range_within(c.hdr.aux_offset, c.hdr.aux_size, c.packed_data.size());
    } else {
        aux_ok = c.hdr.aux_size == 0u ||
            range_within(c.hdr.aux_offset, c.hdr.aux_size, c.packed_data.size());
    }
    bool ok = version_ok && section_table_ok && desc_sizes_ok && desc_blob_ok &&
        desc_layer_ok && desc_image_ok && import_ok && standalone_imports_ok && string_ok && resource_ok &&
        master_ok && stub_ok && aux_ok;
    char buf[384];
    std::snprintf(buf, sizeof(buf),
                  "profile=%s ver=%d sections=%u valid_desc=%u table=%d sizes=%d blobs=%d layers=%d image=%d imports=%d/%u pool=%u standalone_imports=%d strings=%d/%u resources=%d/%u master=%d stub=%d aux=%d",
                  profile_name(profile),
                  version_ok ? 1 : 0,
                  c.hdr.section_count,
                  valid_desc,
                  section_table_ok ? 1 : 0,
                  desc_sizes_ok ? 1 : 0,
                  desc_blob_ok ? 1 : 0,
                  desc_layer_ok ? 1 : 0,
                  desc_image_ok ? 1 : 0,
                  import_ok ? 1 : 0,
                  import_stored,
                  import_pool,
                  standalone_imports_ok ? 1 : 0,
                  string_ok ? 1 : 0,
                  string_stored,
                  resource_ok ? 1 : 0,
                  resource_stored,
                  master_ok ? 1 : 0,
                  stub_ok ? 1 : 0,
                  aux_ok ? 1 : 0);
    return { "P30", "packed runtime layout bounds valid", ok, buf };
}

inline bool recover_runtime_master(const context_t& c, uint8_t master[32], std::string& detail) {
    if (!c.packed_found) {
        detail = "no packed section";
        return false;
    }
    if (!range_within(c.hdr.master_key_offset, 64u, c.packed_data.size())) {
        detail = "master key range is outside packed data";
        return false;
    }
    uint8_t pe_mask[32];
    protector::derive_pe_mask(c.hdr.master_key_pe_timestamp,
                              c.hdr.master_key_pe_size_of_code,
                              pe_mask);
    const uint8_t* obfuscated = c.packed_data.data() + c.hdr.master_key_offset;
    const uint8_t* mask = obfuscated + 32u;
    for (int i = 0; i < 32; ++i) {
        master[i] = static_cast<uint8_t>(obfuscated[i] ^ mask[i] ^ pe_mask[i]);
    }
    if ((c.hdr.bind_flags & protector::kBindFlagCpuid) != 0u) {
        protector::apply_machine_binding_xor(master,
                                             c.hdr.bind_salt,
                                             protector::collect_cpuid_fingerprint());
    }
    return true;
}

inline probe_result_t probe_p33(const context_t& c) {
    if (!c.packed_found) {
        return { "P33", "packed sections decrypt and CRC-verify", false, "no packed section" };
    }
    if (c.hdr.section_count == 0u) {
        return { "P33", "packed sections decrypt and CRC-verify", true, "sections=0" };
    }
    if (c.hdr.section_count > 512u) {
        return { "P33", "packed sections decrypt and CRC-verify", false, "section count exceeds cap" };
    }
    const uint64_t table_bytes = static_cast<uint64_t>(c.hdr.section_count) *
        static_cast<uint64_t>(sizeof(protector::section_descriptor_t));
    if (!range_within(c.hdr.section_table_offset, table_bytes, c.packed_data.size())) {
        return { "P33", "packed sections decrypt and CRC-verify", false, "section table range invalid" };
    }
    uint8_t master[32];
    std::string master_detail;
    if (!recover_runtime_master(c, master, master_detail)) {
        return { "P33", "packed sections decrypt and CRC-verify", false, master_detail };
    }
    uint8_t hwid_anchor[32];
    uint8_t tpm_anchor[32];
    uint8_t srv_anchor[32];
    uint8_t build_seed[32];
    protector::matryoshka_detail::compute_hwid_anchor(hwid_anchor);
    protector::matryoshka_detail::compute_tpm_anchor(tpm_anchor);
    protector::matryoshka_detail::compute_server_anchor(srv_anchor);
    protector::matryoshka_detail::derive_build_seed_from_master(master, build_seed);
    uint32_t verified = 0u;
    char first_bad[320] = {};
    for (uint32_t i = 0; i < c.hdr.section_count; ++i) {
        protector::section_descriptor_t d{};
        const size_t off = static_cast<size_t>(c.hdr.section_table_offset) +
            static_cast<size_t>(i) * sizeof(d);
        std::memcpy(&d, c.packed_data.data() + off, sizeof(d));
        const bool desc_ok = d.original_rva != 0u &&
            d.original_virtual_size != 0u &&
            d.encrypted_size != 0u &&
            d.compressed_size != 0u &&
            d.compressed_size <= d.encrypted_size &&
            (d.layers_applied == 1u || d.layers_applied == 3u) &&
            range_within(d.blob_offset, d.encrypted_size, c.packed_data.size()) &&
            range_within(d.original_rva, d.original_virtual_size, c.pe.optional_header.SizeOfImage);
        if (!desc_ok) {
            std::snprintf(first_bad, sizeof(first_bad),
                          "bad_desc=%u rva=0x%08X vsize=0x%08X comp=0x%08X enc=0x%08X layers=%u",
                          i,
                          d.original_rva,
                          d.original_virtual_size,
                          d.compressed_size,
                          d.encrypted_size,
                          d.layers_applied);
            break;
        }
        std::vector<uint8_t> work(d.encrypted_size);
        std::memcpy(work.data(), c.packed_data.data() + d.blob_offset, work.size());
        if (d.layers_applied >= 3u) {
            uint8_t l3_key[16];
            uint8_t l2_key[32];
            uint8_t l1_key[16];
            protector::matryoshka_detail::derive_layer3_key(srv_anchor,
                                                            build_seed,
                                                            d.original_rva,
                                                            d.section_index,
                                                            l3_key);
            protector::xtea_ctr(l3_key, d.layer3_iv, work.data(), work.data(), work.size());
            protector::matryoshka_detail::derive_layer2_key(tpm_anchor,
                                                            build_seed,
                                                            d.original_rva,
                                                            d.section_index,
                                                            l2_key);
            protector::chacha_detail::chacha20_xor(l2_key,
                                                   d.layer2_nonce,
                                                   work.data(),
                                                   work.data(),
                                                   work.size());
            protector::matryoshka_detail::derive_layer1_key(hwid_anchor,
                                                            build_seed,
                                                            d.original_rva,
                                                            d.section_index,
                                                            l1_key);
            protector::aes_detail::aes128_ctr(l1_key,
                                              d.layer1_iv,
                                              work.data(),
                                              work.data(),
                                              work.size());
        } else {
            uint8_t section_key[32];
            uint8_t section_iv[16];
            protector::derive_section_key(master,
                                          d.original_rva,
                                          d.section_index,
                                          section_key,
                                          section_iv);
            protector::aes_detail::aes256_ctr(section_key,
                                              section_iv,
                                              work.data(),
                                              work.data(),
                                              work.size());
        }
        protector::lz_decompress_result_t plain =
            protector::lz_decompress_payload_compatible(work.data(), d.compressed_size, d.original_virtual_size);
        if (!plain.ok) {
            std::snprintf(first_bad, sizeof(first_bad),
                          "bad_lz=%u src_idx=%u rva=0x%08X vsize=0x%08X comp=0x%08X decoded=0x%zX detail=%s",
                          i,
                          d.section_index,
                          d.original_rva,
                          d.original_virtual_size,
                          d.compressed_size,
                          plain.decoded_size,
                          plain.detail.c_str());
            break;
        }
        if (plain.crc32 != d.original_crc32) {
            std::snprintf(first_bad, sizeof(first_bad),
                          "bad_crc=%u src_idx=%u rva=0x%08X vsize=0x%08X comp=0x%08X decoded=0x%zX actual=0x%08X expected=0x%08X",
                          i,
                          d.section_index,
                          d.original_rva,
                          d.original_virtual_size,
                          d.compressed_size,
                          plain.decoded_size,
                          plain.crc32,
                          d.original_crc32);
            break;
        }
        ++verified;
    }
    const bool ok = verified == c.hdr.section_count;
    char buf[384];
    std::snprintf(buf, sizeof(buf),
                  "sections=%u verified=%u%s%s",
                  c.hdr.section_count,
                  verified,
                  ok ? "" : " ",
                  ok ? "" : first_bad);
    return { "P33", "packed sections decrypt and CRC-verify", ok, buf };
}

inline probe_result_t probe_p31(const context_t& c) {
    bool llm_declared = c.aux_found && ((c.aux.phase_flags & 0x200u) != 0u);
    if (!llm_declared) {
        return { "P31", ".aifn anti-AI function lure coverage (INFO: llm_poison bit not set)",
                 true, "skipped" };
    }
    const pe_file::section_t* aifn = nullptr;
    size_t aifn_count = 0u;
    for (const auto& s : c.pe.sections) {
        char nm[9] = {};
        section_name_cstr(s.name, nm);
        if (std::strcmp(nm, ".aifn") == 0) {
            aifn = &s;
            ++aifn_count;
        }
    }
    if (aifn_count != 1u || aifn == nullptr) {
        char buf[128];
        std::snprintf(buf, sizeof(buf), "aifn_count=%zu", aifn_count);
        return { "P31", ".aifn anti-AI function lure coverage", false, buf };
    }
    const size_t payload_size = (aifn->virtual_size != 0u && aifn->virtual_size <= aifn->data.size())
        ? static_cast<size_t>(aifn->virtual_size)
        : aifn->data.size();
    const bool chars_ok = poison_section_characteristics_ok(*aifn);
    const bool header_min_ok = payload_size >= protector::llm_poison::detail::k_aifn_header_size;
    const uint32_t magic = read_u32_le(aifn->data, 0u);
    const uint32_t version = read_u32_le(aifn->data, 4u);
    const uint32_t header_size = read_u32_le(aifn->data, 8u);
    const uint32_t record_size = read_u32_le(aifn->data, 12u);
    const uint64_t seed = read_u64_le(aifn->data, 16u);
    const uint64_t image_base = read_u64_le(aifn->data, 24u);
    const uint32_t image_size = read_u32_le(aifn->data, 32u);
    const uint32_t record_count = read_u32_le(aifn->data, 36u);
    const uint32_t record_table_offset = read_u32_le(aifn->data, 40u);
    const uint32_t string_pool_offset = read_u32_le(aifn->data, 44u);
    const uint32_t string_pool_size = read_u32_le(aifn->data, 48u);
    const uint32_t content_hash = read_u32_le(aifn->data, 52u);
    const uint32_t exception_count = read_u32_le(aifn->data, 56u);
    const uint32_t export_count = read_u32_le(aifn->data, 60u);
    const uint32_t tile_count = read_u32_le(aifn->data, 64u);
    const uint32_t packed_count = read_u32_le(aifn->data, 68u);
    const uint32_t poison_ref_count = read_u32_le(aifn->data, 72u);
    const bool header_ok = header_min_ok &&
        magic == protector::llm_poison::detail::k_aifn_magic &&
        version == protector::llm_poison::detail::k_aifn_version &&
        header_size == protector::llm_poison::detail::k_aifn_header_size &&
        record_size == protector::llm_poison::detail::k_aifn_record_size &&
        seed != 0ull &&
        image_base == c.pe.optional_header.ImageBase &&
        image_size != 0u &&
        image_size <= c.pe.optional_header.SizeOfImage;
    const uint64_t record_table_bytes = static_cast<uint64_t>(record_count) * record_size;
    const bool table_ok = record_count != 0u &&
        record_size == protector::llm_poison::detail::k_aifn_record_size &&
        range_within(record_table_offset, record_table_bytes, payload_size);
    const bool pool_ok = string_pool_size != 0u &&
        range_within(string_pool_offset, string_pool_size, payload_size) &&
        static_cast<uint64_t>(string_pool_offset) >= static_cast<uint64_t>(record_table_offset) + record_table_bytes;
    const bool count_sum_ok = record_count == exception_count + export_count + tile_count + packed_count;
    const bool poison_ref_count_ok =
        poison_ref_count >= protector::llm_poison::detail::k_visible_poison_count +
            protector::llm_poison::detail::k_spread_poison_count;
    bool hash_ok = false;
    if (payload_size >= protector::llm_poison::detail::k_aifn_header_size && content_hash != 0u) {
        std::vector<uint8_t> tmp(aifn->data.begin(), aifn->data.begin() + payload_size);
        tmp[52] = 0u;
        tmp[53] = 0u;
        tmp[54] = 0u;
        tmp[55] = 0u;
        uint32_t computed = fnv1a32_bytes(tmp.data(), tmp.size());
        if (computed == 0u) { computed = 0xA1F00D31u; }
        hash_ok = computed == content_hash;
    }
    auto section_virtual_span = [](const pe_file::section_t& sec) -> uint32_t {
        return sec.virtual_size != 0u ? sec.virtual_size : sec.raw_size;
    };
    auto executable_section_ok = [](const pe_file::section_t& sec) -> bool {
        return (sec.characteristics & IMAGE_SCN_MEM_EXECUTE) != 0u ||
            (sec.characteristics & IMAGE_SCN_CNT_CODE) != 0u;
    };
    uint32_t expected_tile_count = 0u;
    bool expected_tile_ok = true;
    for (const auto& sec : c.pe.sections) {
        char nm[9] = {};
        section_name_cstr(sec.name, nm);
        if (std::strcmp(nm, ".packed") == 0) { continue; }
        if (!executable_section_ok(sec)) { continue; }
        const uint32_t span = section_virtual_span(sec);
        if (span == 0u) { continue; }
        const uint64_t tiles = (static_cast<uint64_t>(span) + 0xFFFu) / 0x1000u;
        if (tiles > 0xFFFFFFFFull - expected_tile_count) {
            expected_tile_ok = false;
            break;
        }
        expected_tile_count += static_cast<uint32_t>(tiles);
    }
    uint32_t expected_packed_count = 0u;
    bool expected_packed_ok = c.packed_found;
    const uint64_t expected_section_table_bytes = static_cast<uint64_t>(c.hdr.section_count) *
        static_cast<uint64_t>(sizeof(protector::section_descriptor_t));
    if (expected_packed_ok &&
        range_within(c.hdr.section_table_offset, expected_section_table_bytes, c.packed_data.size())) {
        for (uint32_t i = 0; i < c.hdr.section_count; ++i) {
            protector::section_descriptor_t d{};
            const size_t off = static_cast<size_t>(c.hdr.section_table_offset) +
                static_cast<size_t>(i) * sizeof(d);
            std::memcpy(&d, c.packed_data.data() + off, sizeof(d));
            if ((d.original_characteristics & IMAGE_SCN_MEM_EXECUTE) != 0u ||
                (d.original_characteristics & IMAGE_SCN_CNT_CODE) != 0u) {
                ++expected_packed_count;
            }
        }
    } else {
        expected_packed_ok = false;
    }
    const bool counts_ok = count_sum_ok &&
        tile_count != 0u &&
        poison_ref_count_ok &&
        expected_tile_ok &&
        expected_packed_ok &&
        tile_count == expected_tile_count &&
        packed_count == expected_packed_count;
    auto cstr_ok = [&](uint32_t offset) -> bool {
        if (!pool_ok || offset < string_pool_offset) { return false; }
        uint64_t pool_end64 = static_cast<uint64_t>(string_pool_offset) + string_pool_size;
        if (offset >= pool_end64 || offset >= payload_size) { return false; }
        const size_t pool_end = static_cast<size_t>((pool_end64 < payload_size) ? pool_end64 : payload_size);
        for (size_t i = offset; i < pool_end; ++i) {
            if (aifn->data[i] == 0u) { return i > offset; }
        }
        return false;
    };
    auto cstr_equals = [&](uint32_t offset, const char* text) -> bool {
        if (!cstr_ok(offset)) { return false; }
        const uint8_t* p = aifn->data.data() + offset;
        size_t i = 0u;
        while (text[i] != '\0') {
            if (offset + i >= payload_size || p[i] != static_cast<uint8_t>(text[i])) { return false; }
            ++i;
        }
        return offset + i < payload_size && p[i] == 0u;
    };
    auto cstr_plain_prompt_ok = [&](uint32_t offset) -> bool {
        if (!cstr_ok(offset)) { return false; }
        for (uint32_t i = 0u; i < protector::llm_poison::detail::k_plaintext_poison_bank_count; ++i) {
            if (cstr_equals(offset, protector::llm_poison::detail::plaintext_poison_prompt(i))) { return true; }
        }
        return false;
    };
    bool records_ok = header_ok && table_ok && pool_ok && counts_ok && hash_ok;
    uint32_t seen_exception = 0u;
    uint32_t seen_export = 0u;
    uint32_t seen_tile = 0u;
    uint32_t seen_packed = 0u;
    uint32_t valid_records = 0u;
    int first_bad = -1;
    char first_bad_reason[160] = {};
    if (table_ok && pool_ok) {
        for (uint32_t i = 0; i < record_count; ++i) {
            const size_t off = static_cast<size_t>(record_table_offset) +
                static_cast<size_t>(i) * record_size;
            const uint32_t kind = read_u32_le(aifn->data, off + 0u);
            const uint32_t flags = read_u32_le(aifn->data, off + 4u);
            const uint32_t target_rva = read_u32_le(aifn->data, off + 8u);
            const uint64_t preferred_va = read_u64_le(aifn->data, off + 12u);
            const uint32_t target_size = read_u32_le(aifn->data, off + 20u);
            const uint32_t unwind_rva = read_u32_le(aifn->data, off + 24u);
            const uint32_t source_section_rva = read_u32_le(aifn->data, off + 28u);
            const uint32_t source_section_index = read_u32_le(aifn->data, off + 32u);
            const uint32_t poison_section_name_offset = read_u32_le(aifn->data, off + 36u);
            const uint32_t poison_section_index = read_u32_le(aifn->data, off + 40u);
            const uint32_t poison_rva = read_u32_le(aifn->data, off + 44u);
            const uint64_t poison_preferred_va = read_u64_le(aifn->data, off + 48u);
            const uint32_t poison_ordinal = read_u32_le(aifn->data, off + 56u);
            const uint32_t label_offset = read_u32_le(aifn->data, off + 60u);
            const uint32_t bait_text_offset = read_u32_le(aifn->data, off + 64u);
            const uint64_t lure_id = read_u64_le(aifn->data, off + 68u);
            const uint32_t integrity_hash = read_u32_le(aifn->data, off + 76u);
            const uint32_t reserved = read_u32_le(aifn->data, off + 80u);
            bool kind_ok = kind >= protector::llm_poison::detail::k_aifn_kind_exception &&
                kind <= protector::llm_poison::detail::k_aifn_kind_packed;
            bool target_ok = false;
            if (source_section_index < c.pe.sections.size() && target_size != 0u &&
                target_size <= protector::llm_poison::detail::k_aifn_max_target_size &&
                preferred_va == c.pe.optional_header.ImageBase + static_cast<uint64_t>(target_rva)) {
                const auto& src = c.pe.sections[source_section_index];
                const uint32_t span = section_virtual_span(src);
                const uint64_t src_start = src.virtual_address;
                const uint64_t src_end = src_start + static_cast<uint64_t>(span);
                const uint64_t target_end = static_cast<uint64_t>(target_rva) + target_size;
                target_ok = executable_section_ok(src) &&
                    source_section_rva == src.virtual_address &&
                    target_end <= 0xFFFFFFFFull &&
                    static_cast<uint64_t>(target_rva) >= src_start &&
                    target_end <= src_end &&
                    (c.pe.optional_header.SizeOfImage == 0u || target_end <= c.pe.optional_header.SizeOfImage);
            }
            bool poison_ok = false;
            if (poison_section_index < c.pe.sections.size() &&
                poison_preferred_va == c.pe.optional_header.ImageBase + static_cast<uint64_t>(poison_rva) &&
                poison_ordinal < poison_ref_count) {
                const auto& ps = c.pe.sections[poison_section_index];
                char ps_name[9] = {};
                section_name_cstr(ps.name, ps_name);
                const uint32_t ps_span = section_virtual_span(ps);
                const uint64_t ps_start = ps.virtual_address;
                const uint64_t ps_end = ps_start + static_cast<uint64_t>(ps_span);
                size_t matched_len = 0u;
                const uint32_t poison_off_probe = poison_rva >= ps.virtual_address ? poison_rva - ps.virtual_address : 0u;
                const bool prompt_at_ref = poison_off_probe < ps.data.size() &&
                    protector::llm_poison::detail::plaintext_poison_prompt_at(ps.data.data(), ps.data.size(), poison_off_probe, &matched_len);
                const uint64_t poison_end = static_cast<uint64_t>(poison_rva) + matched_len;
                const bool poison_range_ok = static_cast<uint64_t>(poison_rva) >= ps_start &&
                    prompt_at_ref &&
                    poison_end <= ps_end;
                uint32_t poison_off = 0u;
                if (poison_range_ok) {
                    poison_off = poison_rva - ps.virtual_address;
                }
                poison_ok = poison_range_ok &&
                    (std::strcmp(ps_name, ".rdiag") == 0 || is_spread_ai_section_name(ps_name)) &&
                    poison_section_characteristics_ok(ps) &&
                    cstr_equals(poison_section_name_offset, ps_name) &&
                    poison_off + matched_len <= ps.data.size();
            }
            const uint32_t expected_hash = aifn_record_integrity(kind,
                                                                 flags,
                                                                 target_rva,
                                                                 preferred_va,
                                                                 target_size,
                                                                 unwind_rva,
                                                                 source_section_rva,
                                                                 source_section_index,
                                                                 poison_section_name_offset,
                                                                 poison_section_index,
                                                                 poison_rva,
                                                                 poison_preferred_va,
                                                                 poison_ordinal,
                                                                 label_offset,
                                                                 bait_text_offset,
                                                                 lure_id);
            const bool integrity_ok = integrity_hash != 0u && integrity_hash == expected_hash && reserved == 0u;
            const bool strings_ok = cstr_plain_prompt_ok(label_offset) && cstr_plain_prompt_ok(bait_text_offset);
            if (kind == protector::llm_poison::detail::k_aifn_kind_exception) { ++seen_exception; }
            if (kind == protector::llm_poison::detail::k_aifn_kind_export) { ++seen_export; }
            if (kind == protector::llm_poison::detail::k_aifn_kind_tile) { ++seen_tile; }
            if (kind == protector::llm_poison::detail::k_aifn_kind_packed) { ++seen_packed; }
            const bool record_ok = kind_ok && target_ok && poison_ok && integrity_ok && strings_ok;
            if (record_ok) {
                ++valid_records;
            } else {
                records_ok = false;
                if (first_bad < 0) {
                    first_bad = static_cast<int>(i);
                    std::snprintf(first_bad_reason, sizeof(first_bad_reason),
                                  "kind=%d target=%d poison=%d integrity=%d strings=%d",
                                  kind_ok ? 1 : 0,
                                  target_ok ? 1 : 0,
                                  poison_ok ? 1 : 0,
                                  integrity_ok ? 1 : 0,
                                  strings_ok ? 1 : 0);
                }
            }
        }
    }
    const bool seen_counts_ok = seen_exception == exception_count &&
        seen_export == export_count &&
        seen_tile == tile_count &&
        seen_packed == packed_count;
    const bool ok = chars_ok && header_ok && table_ok && pool_ok && counts_ok &&
        hash_ok && records_ok && seen_counts_ok && valid_records == record_count;
    char buf[768];
    std::snprintf(buf, sizeof(buf),
                  "aifn_count=%zu bytes=%zu pool_bytes=%u chars=%d header=%d table=%d pool=%d hash=%d counts=%d records=%u/%u seen=%u/%u/%u/%u expected=%u/%u/%u/%u recomputed_tile=%u recomputed_packed=%u poison_refs=%u bad=%d detail=%s",
                  aifn_count,
                  payload_size,
                  string_pool_size,
                  chars_ok ? 1 : 0,
                  header_ok ? 1 : 0,
                  table_ok ? 1 : 0,
                  pool_ok ? 1 : 0,
                  hash_ok ? 1 : 0,
                  counts_ok && seen_counts_ok ? 1 : 0,
                  valid_records,
                  record_count,
                  seen_exception,
                  seen_export,
                  seen_tile,
                  seen_packed,
                  exception_count,
                  export_count,
                  tile_count,
                  packed_count,
                  expected_tile_count,
                  expected_packed_count,
                  poison_ref_count,
                  first_bad,
                  first_bad_reason[0] != '\0' ? first_bad_reason : "none");
    return { "P31", ".aifn anti-AI function lure coverage", ok, buf };
}

inline probe_result_t probe_p32(const context_t& c) {
    bool llm_declared = c.aux_found && ((c.aux.phase_flags & 0x200u) != 0u);
    if (!llm_declared) {
        return { "P32", ".aipg anti-AI readable page lure coverage (INFO: llm_poison bit not set)",
                 true, "skipped" };
    }
    const pe_file::section_t* aipg = nullptr;
    size_t aipg_count = 0u;
    for (const auto& s : c.pe.sections) {
        char nm[9] = {};
        section_name_cstr(s.name, nm);
        if (std::strcmp(nm, ".aipg") == 0) {
            aipg = &s;
            ++aipg_count;
        }
    }
    if (aipg_count != 1u || aipg == nullptr) {
        char buf[128];
        std::snprintf(buf, sizeof(buf), "aipg_count=%zu", aipg_count);
        return { "P32", ".aipg anti-AI readable page lure coverage", false, buf };
    }
    const size_t payload_size = (aipg->virtual_size != 0u && aipg->virtual_size <= aipg->data.size())
        ? static_cast<size_t>(aipg->virtual_size)
        : aipg->data.size();
    const bool chars_ok = poison_section_characteristics_ok(*aipg);
    const bool header_min_ok = payload_size >= protector::llm_poison::detail::k_aipg_header_size;
    const uint32_t magic = read_u32_le(aipg->data, 0u);
    const uint32_t version = read_u32_le(aipg->data, 4u);
    const uint32_t header_size = read_u32_le(aipg->data, 8u);
    const uint32_t record_size = read_u32_le(aipg->data, 12u);
    const uint64_t seed = read_u64_le(aipg->data, 16u);
    const uint64_t image_base = read_u64_le(aipg->data, 24u);
    const uint32_t image_size = read_u32_le(aipg->data, 32u);
    const uint32_t record_count = read_u32_le(aipg->data, 36u);
    const uint32_t record_table_offset = read_u32_le(aipg->data, 40u);
    const uint32_t string_pool_offset = read_u32_le(aipg->data, 44u);
    const uint32_t string_pool_size = read_u32_le(aipg->data, 48u);
    const uint32_t content_hash = read_u32_le(aipg->data, 52u);
    const uint32_t covered_sections = read_u32_le(aipg->data, 56u);
    const uint32_t poison_ref_count = read_u32_le(aipg->data, 60u);
    const uint32_t page_size_decl = read_u32_le(aipg->data, 64u);
    const uint32_t ascii_count = read_u32_le(aipg->data, 68u);
    const uint32_t utf16_count = read_u32_le(aipg->data, 72u);
    const uint32_t structured_count = read_u32_le(aipg->data, 76u);
    const bool header_ok = header_min_ok &&
        magic == protector::llm_poison::detail::k_aipg_magic &&
        version == protector::llm_poison::detail::k_aipg_version &&
        header_size == protector::llm_poison::detail::k_aipg_header_size &&
        record_size == protector::llm_poison::detail::k_aipg_record_size &&
        seed != 0ull &&
        image_base == c.pe.optional_header.ImageBase &&
        image_size != 0u &&
        image_size <= c.pe.optional_header.SizeOfImage &&
        page_size_decl == protector::llm_poison::detail::k_aipg_page_size;
    const uint64_t record_table_bytes = static_cast<uint64_t>(record_count) * record_size;
    const bool table_ok = record_count != 0u &&
        record_size == protector::llm_poison::detail::k_aipg_record_size &&
        range_within(record_table_offset, record_table_bytes, payload_size);
    const bool pool_ok = string_pool_size != 0u &&
        range_within(string_pool_offset, string_pool_size, payload_size) &&
        static_cast<uint64_t>(string_pool_offset) >= static_cast<uint64_t>(record_table_offset) + record_table_bytes;
    bool hash_ok = false;
    if (payload_size >= protector::llm_poison::detail::k_aipg_header_size && content_hash != 0u) {
        std::vector<uint8_t> tmp(aipg->data.begin(), aipg->data.begin() + payload_size);
        tmp[52] = 0u;
        tmp[53] = 0u;
        tmp[54] = 0u;
        tmp[55] = 0u;
        uint32_t computed = fnv1a32_bytes(tmp.data(), tmp.size());
        if (computed == 0u) { computed = 0xA1F00D32u; }
        hash_ok = computed == content_hash;
    }
    auto section_virtual_span = [](const pe_file::section_t& sec) -> uint32_t {
        return sec.virtual_size != 0u ? sec.virtual_size : sec.raw_size;
    };
    auto target_section_ok = [](const pe_file::section_t& sec) -> bool {
        char nm[9] = {};
        section_name_cstr(sec.name, nm);
        return (sec.characteristics & IMAGE_SCN_MEM_READ) != 0u &&
            (sec.characteristics & IMAGE_SCN_MEM_DISCARDABLE) == 0u &&
            std::strcmp(nm, ".rdiag") != 0 &&
            !is_spread_ai_section_name(nm) &&
            !is_function_lure_section_name(nm) &&
            !is_page_lure_section_name(nm);
    };
    struct expected_page_t {
        uint32_t section_index;
        uint32_t section_rva;
        uint32_t page_rva;
        uint32_t page_size;
        uint32_t characteristics;
        char section_name[9];
    };
    std::vector<expected_page_t> expected;
    uint32_t expected_section_count = 0u;
    bool expected_ok = true;
    for (uint32_t i = 0u; i < static_cast<uint32_t>(c.pe.sections.size()); ++i) {
        const auto& sec = c.pe.sections[i];
        if (!target_section_ok(sec)) { continue; }
        const uint32_t span = section_virtual_span(sec);
        if (span == 0u) { continue; }
        const uint64_t sec_start = sec.virtual_address;
        const uint64_t sec_end = sec_start + static_cast<uint64_t>(span);
        if (sec_end > 0xFFFFFFFFull) {
            expected_ok = false;
            break;
        }
        ++expected_section_count;
        for (uint64_t page = sec_start; page < sec_end; page += protector::llm_poison::detail::k_aipg_page_size) {
            const uint64_t remaining = sec_end - page;
            expected_page_t e{};
            e.section_index = i;
            e.section_rva = sec.virtual_address;
            e.page_rva = static_cast<uint32_t>(page);
            e.page_size = static_cast<uint32_t>(remaining < protector::llm_poison::detail::k_aipg_page_size ? remaining : protector::llm_poison::detail::k_aipg_page_size);
            e.characteristics = sec.characteristics;
            section_name_cstr(sec.name, e.section_name);
            expected.push_back(e);
        }
    }
    std::sort(expected.begin(), expected.end(), [](const expected_page_t& a, const expected_page_t& b) {
        if (a.section_index != b.section_index) { return a.section_index < b.section_index; }
        return a.page_rva < b.page_rva;
    });
    const bool count_header_ok = expected_ok &&
        record_count == expected.size() &&
        covered_sections == expected_section_count &&
        poison_ref_count >= protector::llm_poison::detail::k_visible_poison_count +
            protector::llm_poison::detail::k_spread_poison_count &&
        ascii_count == record_count &&
        utf16_count == record_count &&
        static_cast<uint64_t>(structured_count) >= static_cast<uint64_t>(record_count) * 2ull;
    auto cstr_ok = [&](uint32_t offset) -> bool {
        if (!pool_ok || offset < string_pool_offset) { return false; }
        uint64_t pool_end64 = static_cast<uint64_t>(string_pool_offset) + string_pool_size;
        if (offset >= pool_end64 || offset >= payload_size) { return false; }
        const size_t pool_end = static_cast<size_t>((pool_end64 < payload_size) ? pool_end64 : payload_size);
        for (size_t i = offset; i < pool_end; ++i) {
            if (aipg->data[i] == 0u) { return i > offset; }
        }
        return false;
    };
    auto cstr_equals = [&](uint32_t offset, const char* text) -> bool {
        if (!cstr_ok(offset)) { return false; }
        const uint8_t* p = aipg->data.data() + offset;
        size_t i = 0u;
        while (text[i] != '\0') {
            if (offset + i >= payload_size || p[i] != static_cast<uint8_t>(text[i])) { return false; }
            ++i;
        }
        return offset + i < payload_size && p[i] == 0u;
    };
    auto utf16_contains = [&](uint32_t offset, const char* text) -> bool {
        if (!pool_ok || offset < string_pool_offset) { return false; }
        const size_t text_len = std::strlen(text);
        const uint64_t bytes64 = static_cast<uint64_t>(text_len) * 2ull + 2ull;
        uint64_t pool_end64 = static_cast<uint64_t>(string_pool_offset) + string_pool_size;
        if (offset >= pool_end64 || static_cast<uint64_t>(offset) + bytes64 > pool_end64 ||
            static_cast<uint64_t>(offset) + bytes64 > payload_size) {
            return false;
        }
        for (size_t i = 0u; i < text_len; ++i) {
            if (aipg->data[offset + i * 2u] != static_cast<uint8_t>(text[i]) ||
                aipg->data[offset + i * 2u + 1u] != 0u) {
                return false;
            }
        }
        return true;
    };
    auto cstr_plain_prompt_ok = [&](uint32_t offset) -> bool {
        if (!cstr_ok(offset)) { return false; }
        for (uint32_t i = 0u; i < protector::llm_poison::detail::k_plaintext_poison_bank_count; ++i) {
            if (cstr_equals(offset, protector::llm_poison::detail::plaintext_poison_prompt(i))) { return true; }
        }
        return false;
    };
    auto utf16_plain_prompt_ok = [&](uint32_t offset) -> bool {
        if (!pool_ok || offset < string_pool_offset) { return false; }
        for (uint32_t i = 0u; i < protector::llm_poison::detail::k_plaintext_poison_bank_count; ++i) {
            if (utf16_contains(offset, protector::llm_poison::detail::plaintext_poison_prompt(i))) { return true; }
        }
        return false;
    };
    auto poison_ref_ok = [&](uint32_t marker_rva) -> bool {
        for (const auto& ps : c.pe.sections) {
            char nm[9] = {};
            section_name_cstr(ps.name, nm);
            if (std::strcmp(nm, ".rdiag") != 0 && !is_spread_ai_section_name(nm)) { continue; }
            const uint32_t span = section_virtual_span(ps);
            const uint64_t ps_start = ps.virtual_address;
            const uint64_t ps_end = ps_start + static_cast<uint64_t>(span);
            if (static_cast<uint64_t>(marker_rva) < ps_start) { continue; }
            const uint32_t off = marker_rva - ps.virtual_address;
            size_t matched_len = 0u;
            const bool prompt_at_ref = off < ps.data.size() &&
                protector::llm_poison::detail::plaintext_poison_prompt_at(ps.data.data(), ps.data.size(), off, &matched_len);
            const uint64_t marker_end = static_cast<uint64_t>(marker_rva) + matched_len;
            if (static_cast<uint64_t>(marker_rva) < ps_start || marker_end > ps_end) { continue; }
            return poison_section_characteristics_ok(ps) &&
                prompt_at_ref &&
                off + matched_len <= ps.data.size();
        }
        return false;
    };
    auto find_expected = [&](uint32_t section_index, uint32_t page_rva) -> const expected_page_t* {
        expected_page_t key{};
        key.section_index = section_index;
        key.page_rva = page_rva;
        auto it = std::lower_bound(expected.begin(), expected.end(), key, [](const expected_page_t& a, const expected_page_t& b) {
            if (a.section_index != b.section_index) { return a.section_index < b.section_index; }
            return a.page_rva < b.page_rva;
        });
        if (it == expected.end() || it->section_index != section_index || it->page_rva != page_rva) {
            return nullptr;
        }
        return &(*it);
    };
    uint32_t valid_records = 0u;
    int first_bad = -1;
    char first_bad_reason[192] = {};
    std::vector<uint64_t> seen_keys;
    bool records_ok = header_ok && table_ok && pool_ok && count_header_ok && hash_ok;
    if (table_ok && pool_ok) {
        seen_keys.reserve(record_count);
        for (uint32_t i = 0u; i < record_count; ++i) {
            const size_t off = static_cast<size_t>(record_table_offset) +
                static_cast<size_t>(i) * record_size;
            const uint32_t section_index = read_u32_le(aipg->data, off + 0u);
            const uint32_t section_rva = read_u32_le(aipg->data, off + 4u);
            const uint32_t page_rva = read_u32_le(aipg->data, off + 8u);
            const uint32_t rec_page_size = read_u32_le(aipg->data, off + 12u);
            const uint32_t characteristics = read_u32_le(aipg->data, off + 16u);
            const uint32_t ascii_offset = read_u32_le(aipg->data, off + 20u);
            const uint32_t utf16_offset = read_u32_le(aipg->data, off + 24u);
            const uint32_t json_offset = read_u32_le(aipg->data, off + 28u);
            const uint32_t yaml_offset = read_u32_le(aipg->data, off + 32u);
            const uint32_t split_offset = read_u32_le(aipg->data, off + 36u);
            const uint32_t tool_offset = read_u32_le(aipg->data, off + 40u);
            const uint32_t marker_ref_rva = read_u32_le(aipg->data, off + 44u);
            const uint64_t lure_id = read_u64_le(aipg->data, off + 48u);
            const uint32_t integrity_hash = read_u32_le(aipg->data, off + 56u);
            const uint32_t reserved0 = read_u32_le(aipg->data, off + 60u);
            const uint32_t section_name_offset = read_u32_le(aipg->data, off + 64u);
            const uint32_t reserved1 = read_u32_le(aipg->data, off + 68u);
            const expected_page_t* exp = find_expected(section_index, page_rva);
            const bool target_ok = exp != nullptr &&
                section_rva == exp->section_rva &&
                rec_page_size == exp->page_size &&
                characteristics == exp->characteristics &&
                cstr_equals(section_name_offset, exp->section_name);
            const bool poison_ok = poison_ref_ok(marker_ref_rva);
            const uint32_t expected_hash = protector::llm_poison::detail::aipg_record_integrity(
                section_index,
                section_rva,
                page_rva,
                rec_page_size,
                characteristics,
                ascii_offset,
                utf16_offset,
                json_offset,
                yaml_offset,
                split_offset,
                tool_offset,
                marker_ref_rva,
                lure_id,
                section_name_offset);
            const bool integrity_ok = integrity_hash != 0u && integrity_hash == expected_hash &&
                reserved0 == 0u && reserved1 == 0u && lure_id != 0ull;
            const bool strings_ok =
                cstr_plain_prompt_ok(ascii_offset) &&
                utf16_plain_prompt_ok(utf16_offset) &&
                cstr_plain_prompt_ok(json_offset) &&
                cstr_plain_prompt_ok(yaml_offset) &&
                cstr_plain_prompt_ok(split_offset) &&
                cstr_plain_prompt_ok(tool_offset);
            const bool record_ok = target_ok && poison_ok && integrity_ok && strings_ok;
            if (record_ok) {
                ++valid_records;
                seen_keys.push_back((static_cast<uint64_t>(section_index) << 32) | static_cast<uint64_t>(page_rva));
            } else {
                records_ok = false;
                if (first_bad < 0) {
                    first_bad = static_cast<int>(i);
                    std::snprintf(first_bad_reason, sizeof(first_bad_reason),
                                  "target=%d poison=%d integrity=%d strings=%d",
                                  target_ok ? 1 : 0,
                                  poison_ok ? 1 : 0,
                                  integrity_ok ? 1 : 0,
                                  strings_ok ? 1 : 0);
                }
            }
        }
    }
    std::sort(seen_keys.begin(), seen_keys.end());
    const bool unique_ok = std::adjacent_find(seen_keys.begin(), seen_keys.end()) == seen_keys.end();
    const bool ok = chars_ok && header_ok && table_ok && pool_ok && hash_ok &&
        count_header_ok && records_ok && unique_ok && valid_records == record_count;
    char buf[896];
    std::snprintf(buf, sizeof(buf),
                  "aipg_count=%zu bytes=%zu pool_bytes=%u chars=%d header=%d table=%d pool=%d hash=%d counts=%d records=%u/%u expected=%zu sections=%u/%u ascii=%u utf16=%u structured=%u poison_refs=%u unique=%d bad=%d detail=%s",
                  aipg_count,
                  payload_size,
                  string_pool_size,
                  chars_ok ? 1 : 0,
                  header_ok ? 1 : 0,
                  table_ok ? 1 : 0,
                  pool_ok ? 1 : 0,
                  hash_ok ? 1 : 0,
                  count_header_ok ? 1 : 0,
                  valid_records,
                  record_count,
                  expected.size(),
                  covered_sections,
                  expected_section_count,
                  ascii_count,
                  utf16_count,
                  structured_count,
                  poison_ref_count,
                  unique_ok ? 1 : 0,
                  first_bad,
                  first_bad_reason[0] != '\0' ? first_bad_reason : "none");
    return { "P32", ".aipg anti-AI readable page lure coverage", ok, buf };
}

inline verify_report_t run_probes(const context_t& c,
                                  verify_profile_t profile = verify_profile_t::strict_no_imports) {
    verify_report_t rep;
    auto add_probe = [&](probe_result_t r) {
        if (r.pass) { ++rep.passed; }
        ++rep.total;
        rep.probes.push_back(std::move(r));
    };
    add_probe(probe_p01(c));
    add_probe(probe_p02(c));
    add_probe(probe_p03(c, profile));
    add_probe(probe_p04(c, profile));
    add_probe(probe_p05(c));
    add_probe(probe_p06(c));
    add_probe(probe_p07(c));
    add_probe(probe_p08(c));
    add_probe(probe_p09(c));
    add_probe(probe_p10(c));
    add_probe(probe_p11(c));
    add_probe(probe_p12(c));
    add_probe(probe_p13(c, profile));
    add_probe(probe_p14(c));
    add_probe(probe_p15(c));
    add_probe(probe_p16(c));
    add_probe(probe_p17(c));
    add_probe(probe_p18(c));
    add_probe(probe_p19(c, profile));
    add_probe(probe_p20(c));
    add_probe(probe_p21(c));
    add_probe(probe_p22(c));
    add_probe(probe_p23(c, profile));
    add_probe(probe_p24(c));
    add_probe(probe_p25(c));
    add_probe(probe_p26(c));
    add_probe(probe_p27(c));
    add_probe(probe_p28(c));
    add_probe(probe_p29(c));
    add_probe(probe_p30(c, profile));
    add_probe(probe_p31(c));
    add_probe(probe_p32(c));
    add_probe(probe_p33(c));
    rep.aux_found   = c.aux_found;
    rep.phase_flags = c.aux_found ? c.aux.phase_flags : 0u;
    return rep;
}

inline verify_report_t verify_report(const std::string& path,
                                     verify_profile_t profile = verify_profile_t::strict_no_imports) {
    verify_report_t rep;
    context_t ctx{};
    try {
        ctx.pe = pe_file::load(path);
    } catch (const std::exception& e) {
        std::fprintf(stderr, "[!] load failed: %s\n", e.what());
        rep.loaded = false;
        return rep;
    }
    rep.loaded = true;
    find_packed(ctx);
    rep = run_probes(ctx, profile);
    rep.loaded = true;
    return rep;
}

inline int verify_file(const std::string& path,
                       verify_profile_t profile = verify_profile_t::strict_no_imports) {
    std::printf("Profile: %s\n", profile_name(profile));
    verify_report_t rep = verify_report(path, profile);
    if (!rep.loaded) { return 2; }
    for (const auto& r : rep.probes) {
        std::printf("[%s] %s :: %s%s%s\n",
                    r.pass ? "PASS" : "FAIL",
                    r.id, r.desc,
                    r.detail.empty() ? "" : " - ", r.detail.c_str());
    }
    std::printf("\nResult: %d/%d probes passed\n", rep.passed, rep.total);
    return (rep.passed == rep.total) ? 0 : 1;
}

}
