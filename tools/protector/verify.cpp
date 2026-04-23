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

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using namespace protector;

namespace verifier {

struct probe_result_t {
    const char* id;
    const char* desc;
    bool        pass;
    std::string detail;
};

struct context_t {
    pe_file::pe_image_t pe;
    bool                packed_found = false;
    packed_header_t     hdr{};
    aux_block_t         aux{};
    bool                aux_found = false;
    uint32_t            packed_rva = 0;
    uint32_t            packed_vsize = 0;
    std::vector<uint8_t> packed_data;
};

static bool find_packed(context_t& c) {
    for (const auto& sec : c.pe.sections) {
        if (sec.data.size() < sizeof(packed_header_t)) { continue; }
        packed_header_t h{};
        std::memcpy(&h, sec.data.data(), sizeof(h));
        if (h.magic == kPackedMagic) {
            c.hdr = h;
            c.packed_data = sec.data;
            c.packed_rva = sec.virtual_address;
            c.packed_vsize = sec.virtual_size;
            c.packed_found = true;
            if (h.aux_offset != 0u && h.aux_size == sizeof(aux_block_t)
                && static_cast<size_t>(h.aux_offset) + sizeof(aux_block_t) <= sec.data.size()) {
                std::memcpy(&c.aux, sec.data.data() + h.aux_offset, sizeof(aux_block_t));
                c.aux_found = (c.aux.magic == kAuxMagic);
            }
            return true;
        }
    }
    return false;
}

static probe_result_t probe_p01(const context_t& c) {
    return { "P01", "PE32+ image", c.pe.optional_header.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC, "" };
}

static probe_result_t probe_p02(const context_t& c) {
    return { "P02", "packed section + APKD magic", c.packed_found,
             c.packed_found ? "" : "no .packed section with APKD magic" };
}

static probe_result_t probe_p03(const context_t& c) {
    if (!c.packed_found) { return { "P03", "original sections zeroed", false, "no packed section" }; }
    int nonzero = 0;
    for (const auto& s : c.pe.sections) {
        if (s.virtual_address == c.packed_rva) { continue; }
        char nm[9] = {0};
        std::memcpy(nm, s.name, 8);
        if (std::strcmp(nm, ".reloc") == 0 || std::strcmp(nm, ".rsrc") == 0) { continue; }
        if (s.raw_size != 0u) { ++nonzero; }
    }
    return { "P03", "original sections zeroed (raw_size==0)", nonzero == 0,
             nonzero == 0 ? "" : (std::to_string(nonzero) + " sections still have raw data") };
}

static probe_result_t probe_p04(const context_t& c) {
    uint32_t imp_rva = c.pe.data_directories[IMAGE_DIRECTORY_ENTRY_IMPORT].rva;
    return { "P04", "import directory empty", imp_rva == 0u,
             imp_rva == 0u ? "" : "import directory rva nonzero" };
}

static probe_result_t probe_p05(const context_t& c) {
    if (!c.packed_found) { return { "P05", "entry point in packed section", false, "" }; }
    uint32_t ep = c.pe.optional_header.AddressOfEntryPoint;
    bool in = (ep >= c.packed_rva) && (ep < c.packed_rva + c.packed_vsize);
    return { "P05", "entry point inside packed section", in,
             in ? "" : "entry point outside .packed range" };
}

static probe_result_t probe_p06(const context_t& c) {
    if (!c.aux_found) { return { "P06", "aux block present (AUXM)", false, "no aux block" }; }
    return { "P06", "aux block present (AUXM)", true, "" };
}

static probe_result_t probe_p07(const context_t& c) {
    uint32_t dbg_rva = c.pe.data_directories[IMAGE_DIRECTORY_ENTRY_DEBUG].rva;
    return { "P07", "debug directory stripped", dbg_rva == 0u,
             dbg_rva == 0u ? "" : "debug rva nonzero" };
}

static probe_result_t probe_p08(const context_t& c) {
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

static probe_result_t probe_p09(const context_t& c) {
    if (!c.packed_found) { return { "P09", "master key region nonzero", false, "" }; }
    if (c.hdr.master_key_offset + 64u > c.packed_data.size()) {
        return { "P09", "master key region nonzero", false, "out of range" };
    }
    int zero = 0;
    for (size_t i = 0; i < 64; ++i) { if (c.packed_data[c.hdr.master_key_offset + i] == 0) { ++zero; } }
    return { "P09", "obfuscated master key not all zeros", zero < 64,
             zero < 64 ? "" : "all 64 key bytes are zero" };
}

static probe_result_t probe_p10(const context_t& c) {
    if (!c.packed_found) { return { "P10", "stub region nonzero", false, "" }; }
    if (c.hdr.stub_code_offset == 0u || c.hdr.stub_code_offset >= c.packed_data.size()) {
        return { "P10", "stub region nonzero", false, "stub offset invalid" };
    }
    size_t scan = std::min<size_t>(256, c.packed_data.size() - c.hdr.stub_code_offset);
    int zero = 0;
    for (size_t i = 0; i < scan; ++i) { if (c.packed_data[c.hdr.stub_code_offset + i] == 0) { ++zero; } }
    bool ok = zero < static_cast<int>(scan);
    return { "P10", "stub bytes nonzero", ok, ok ? "" : "stub region appears empty" };
}

static probe_result_t probe_p11(const context_t& c) {
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

static probe_result_t probe_p12(const context_t& c) {
    bool wm_id_present = (c.pe.optional_header.Win32VersionValue != 0u)
                      || (c.pe.optional_header.LoaderFlags != 0u);
    return { "P12", "watermark id (informational; only set with --embed-watermark)",
             true,
             wm_id_present ? "watermark id present in PE header" : "watermark id not embedded" };
}

static probe_result_t probe_p13(const context_t& c) {
    if (!c.aux_found) { return { "P13", "bind/tamper fields visible", false, "no aux" }; }
    char buf[128];
    std::snprintf(buf, sizeof(buf), "bind_flags=0x%X tamper_level=%u",
                  c.aux.bind_flags, c.aux.tamper_response_level);
    return { "P13", "bind/tamper metadata", true, buf };
}

inline int verify_file(const std::string& path) {
    context_t ctx{};
    try {
        ctx.pe = pe_file::load(path);
    } catch (const std::exception& e) {
        std::fprintf(stderr, "[!] load failed: %s\n", e.what());
        return 2;
    }
    find_packed(ctx);

    probe_result_t (*probes[])(const context_t&) = {
        probe_p01, probe_p02, probe_p03, probe_p04, probe_p05,
        probe_p06, probe_p07, probe_p08, probe_p09, probe_p10,
        probe_p11, probe_p12, probe_p13
    };

    int passed = 0, total = 0;
    for (auto fn : probes) {
        probe_result_t r = fn(ctx);
        ++total;
        if (r.pass) { ++passed; }
        std::printf("[%s] %s :: %s%s%s\n",
                    r.pass ? "PASS" : "FAIL",
                    r.id, r.desc,
                    r.detail.empty() ? "" : " - ", r.detail.c_str());
    }
    std::printf("\nResult: %d/%d probes passed\n", passed, total);
    return (passed == total) ? 0 : 1;
}

}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "Usage: aida_protector_verify <protected.exe>\n");
        return 1;
    }
    return verifier::verify_file(argv[1]);
}
