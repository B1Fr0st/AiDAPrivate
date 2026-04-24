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
#include <cstdio>
#include <cstring>
#include <string>
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


inline probe_result_t probe_p01(const context_t& c) {
    return { "P01", "PE32+ image", c.pe.optional_header.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC, "" };
}

inline probe_result_t probe_p02(const context_t& c) {
    return { "P02", "packed section + APKD magic", c.packed_found,
             c.packed_found ? "" : "no .packed section with APKD magic" };
}

inline probe_result_t probe_p03(const context_t& c) {
    if (!c.packed_found) { return { "P03", "original sections zeroed", false, "no packed section" }; }
    int nonzero = 0;
    for (const auto& s : c.pe.sections) {
        if (s.virtual_address <= c.packed_rva &&
            c.packed_rva < s.virtual_address + (std::max)(s.virtual_size, s.raw_size)) {
            continue;
        }
        char nm[9] = {0};
        std::memcpy(nm, s.name, 8);
        if (std::strcmp(nm, ".reloc") == 0 || std::strcmp(nm, ".rsrc") == 0) { continue; }
        if (s.raw_size != 0u) { ++nonzero; }
    }
    return { "P03", "original sections zeroed (raw_size==0)", nonzero == 0,
             nonzero == 0 ? "" : (std::to_string(nonzero) + " sections still have raw data") };
}

inline probe_result_t probe_p04(const context_t& c) {
    uint32_t imp_rva = c.pe.data_directories[IMAGE_DIRECTORY_ENTRY_IMPORT].rva;
    return { "P04", "import directory empty", imp_rva == 0u,
             imp_rva == 0u ? "" : "import directory rva nonzero" };
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

inline probe_result_t probe_p13(const context_t& c) {
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
    bool ok = (ent >= lo && ent <= hi);
    char buf[128];
    std::snprintf(buf, sizeof(buf), "entropy=%u milli-bits/byte (band=[%u,%u]%s)",
                  ent, lo, hi, merged ? ", merged" : "");
    return { "P13", "packed section entropy (with merge awareness)", ok, buf };
}


inline probe_result_t probe_p14(const context_t& c) {
    if (!c.aux_found) { return { "P14", "phase_flags = 7/7 phases fired", false, "no aux block" }; }
    uint32_t pf = c.aux.phase_flags & 0x7Fu;
    int n = 0;
    for (int i = 0; i < 7; ++i) { if (pf & (1u << i)) { ++n; } }
    bool ok = (n == 7);
    char buf[64];
    std::snprintf(buf, sizeof(buf), "phases_fired=%d/7 (phase_flags=0x%02X)", n, pf);
    return { "P14", "all 7 protection phases fired (--all)", ok, buf };
}


inline probe_result_t probe_p15(const context_t& c) {
    uint16_t dll = c.pe.optional_header.DllCharacteristics;
    uint16_t bad = dll & 0x4160u;
    bool ok = (bad == 0);
    char buf[96];
    std::snprintf(buf, sizeof(buf), "DllCharacteristics=0x%04X (masked bits=0x%04X)", dll, bad);
    return { "P15", "DYNAMIC_BASE|NX_COMPAT|GUARD_CF cleared", ok, buf };
}


inline probe_result_t probe_p16(const context_t& c) {
    uint16_t ch = c.pe.file_header.Characteristics;
    bool ok = (ch & 0x0001u) != 0u;
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


inline probe_result_t probe_p19(const context_t& c) {
    const int idx[4] = { 1, 6, 10, 12 };
    int bad = 0;
    char buf[192];
    int len = 0;
    for (int k = 0; k < 4; ++k) {
        const auto& d = c.pe.data_directories[idx[k]];
        if (d.rva != 0u || d.size != 0u) { ++bad; }
        len += std::snprintf(buf + len, sizeof(buf) - len, "DD[%d]=(%u,%u) ",
                             idx[k], d.rva, d.size);
        if (len >= static_cast<int>(sizeof(buf))) { break; }
    }
    bool ok = (bad == 0);
    return { "P19", "DD[1/6/10/12] zeroed (Import/Debug/LoadCfg/IAT)", ok, buf };
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

inline verify_report_t run_probes(const context_t& c) {
    probe_result_t (*probes[])(const context_t&) = {
        probe_p01, probe_p02, probe_p03, probe_p04, probe_p05,
        probe_p06, probe_p07, probe_p08, probe_p09, probe_p10,
        probe_p11, probe_p12, probe_p13,
        probe_p14, probe_p15, probe_p16, probe_p17, probe_p18, probe_p19, probe_p20
    };
    verify_report_t rep;
    for (auto fn : probes) {
        probe_result_t r = fn(c);
        if (r.pass) { ++rep.passed; }
        ++rep.total;
        rep.probes.push_back(std::move(r));
    }
    rep.aux_found   = c.aux_found;
    rep.phase_flags = c.aux_found ? c.aux.phase_flags : 0u;
    return rep;
}

inline verify_report_t verify_report(const std::string& path) {
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
    rep = run_probes(ctx);
    rep.loaded = true;
    return rep;
}

inline int verify_file(const std::string& path) {
    verify_report_t rep = verify_report(path);
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
