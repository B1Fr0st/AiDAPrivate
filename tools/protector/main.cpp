#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include "pe_file.hpp"
#include "transforms.hpp"
#include "stub.hpp"

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <filesystem>
#include <new>
#include <string>
#include <vector>

namespace protector {

struct config_t {
    std::string input_path;
    std::string output_path;
    bool strip_rich = false;
    bool strip_debug = false;
    bool encrypt_imports = false;
    bool encrypt_strings = false;
    bool encrypt_resources = false;
    bool pack_sections = false;
    bool mangle_headers = false;
    bool randomize_section_names = false;
    bool embed_watermark = false;
    bool bind_machine = false;
    bool polymorphic_stub = false;
    bool merge_sections = false;
    bool flatten_entropy = false;
    bool deep_steal = false;
    bool ghost_veh = false;
    bool rdtsc_entangle = false;
    bool opaque_predicates = false;
    bool ast_poison = false;
    bool symexec_bombs = false;
    bool llm_poison = false;
    bool no_llm_poison_explicit = false;
    bool jit = false;
    bool no_jit_explicit = false;
    bool verbose = false;
    bool seed_provided = false;
    bool watermark_provided = false;
    bool target_arc = false;
    uint64_t seed = 0;
    uint32_t tamper_response_level = 0;
    uint8_t  license_hash[16] = {0};
    uint32_t matryoshka_layers = 3u;
    uint8_t  spki_pin_primary[32]   = {0};
    uint8_t  spki_pin_secondary[32] = {0};
    bool     spki_pin_primary_provided   = false;
    bool     spki_pin_secondary_provided = false;
    char     primary_host[64]   = {0};
    char     secondary_host[64] = {0};
    bool     primary_host_provided   = false;
    bool     secondary_host_provided = false;
};

static void print_usage(std::FILE* out) {
    std::fprintf(out,
        "Usage: aida_protector [options]\n"
        "\n"
        "Required:\n"
        "  -i, --input <path>          Input PE file path (.exe or .dll)\n"
        "  -o, --output <path>         Output protected PE file path\n"
        "\n"
        "Protection flags:\n"
        "  --strip-rich                Strip Rich header\n"
        "  --strip-debug               Strip debug directory\n"
        "  --encrypt-imports           Replace IAT with hash table\n"
        "  --encrypt-strings           XOR-encrypt strings in .rdata\n"
        "  --encrypt-resources         XOR-encrypt RT_RCDATA resources\n"
        "  --pack-sections             Compress + AES-256-CTR encrypt sections\n"
        "  --mangle-headers            Mangle PE headers\n"
        "  --randomize-section-names   Randomize section names\n"
        "  --polymorphic               Emit polymorphic stub variant (Phase 1)\n"
        "  --merge-sections            Merge sections to reduce surface (Phase 2)\n"
        "  --flatten-entropy           Flatten per-section entropy (Phase 2)\n"
        "  --deep-steal                Deep-steal code blocks (Phase 3)\n"
        "  --ghost-veh                 Install ghost VEH guards (Phase 4)\n"
        "  --rdtsc-entangle            Entangle timing via rdtsc (Phase 5)\n"
        "  --opaque-predicates         Insert opaque predicates (Phase 6)\n"
        "  --ast-poison                Inject AST-poisoning debug section (Phase B.1)\n"
        "  --symexec-bombs             Inject symbolic-execution state-explosion bombs (Phase B.2)\n"
        "  --llm-poison                Embed LLM-prompt-injection trap strings in .rdata (Phase B.3)\n"
        "  --jit                       Declare JIT enclave presence in aux block (runtime must also be JIT-enabled)\n"
        "  --no-jit                    Declare JIT disabled (e.g. for AiDA.dll inside IDA Pro's ACG)\n"
        "\n"
        "Aggregate:\n"
        "  -a, --all                   Enable all protections\n"
        "\n"
        "Watermark / Binding:\n"
        "  --watermark <hex32>         128-bit license watermark (32 hex chars)\n"
        "  --embed-watermark           Embed watermark identifier in PE header\n"
        "  --bind-machine              Bind decryption key to current CPUID\n"
        "  --tamper-level <0..3>       Tamper response level for orchestrator\n"
        "\n"
        "Targets:\n"
        "  --target-arc                ARC mode (aida_core.dll): forces the hardened ARC profile,\n"
        "                              tighter flatten band, tamper-level 4. Validates input is aida_core.dll.\n"
        "\n"
        "Pack-section encryption depth:\n"
        "  --matryoshka-layers <1|3>   1 = legacy single AES-256-CTR layer.\n"
        "                              3 (default) = Matryoshka triple-stack: AES-128-CTR (HWID-anchored)\n"
        "                              -> ChaCha20 (TPM-anchored) -> XTEA-CTR (server-heartbeat-anchored).\n"
        "\n"
        "Auth transport pinning:\n"
        "  --pin-primary <hex64>       SHA-256(SPKI) of the primary auth server cert, hex (64 chars)\n"
        "  --pin-secondary <hex64>     SHA-256(SPKI) of the backup auth server cert, hex (64 chars)\n"
        "  --primary-host <utf8>       Override default primary auth hostname (<= 63 chars, alnum/./-/_)\n"
        "  --secondary-host <utf8>     Override default secondary auth hostname (<= 63 chars, alnum/./-/_)\n"
        "\n"
        "Control:\n"
        "  --seed <u64>                Deterministic seed for RNG\n"
        "  -v, --verbose               Print transform log to stdout\n"
        "  -h, --help                  Print this help and exit\n");
}

static bool parse_uint64(const char* s, uint64_t& out) {
    if (s == nullptr || *s == '\0') {
        return false;
    }
    int base = 10;
    const char* p = s;
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        base = 16;
        p = s + 2;
        if (*p == '\0') {
            return false;
        }
    }
    char* end = nullptr;
    errno = 0;
    unsigned long long v = std::strtoull(p, &end, base);
    if (end == p || *end != '\0') {
        return false;
    }
    out = static_cast<uint64_t>(v);
    return true;
}

static bool parse_hex16(const char* s, uint8_t out[16]) {
    if (s == nullptr) { return false; }
    size_t len = std::strlen(s);
    if (len != 32) { return false; }
    auto hexv = [](char c, int& v) {
        if (c >= '0' && c <= '9') { v = c - '0'; return true; }
        if (c >= 'a' && c <= 'f') { v = c - 'a' + 10; return true; }
        if (c >= 'A' && c <= 'F') { v = c - 'A' + 10; return true; }
        return false;
    };
    for (int i = 0; i < 16; ++i) {
        int hi = 0, lo = 0;
        if (!hexv(s[i * 2], hi)) { return false; }
        if (!hexv(s[i * 2 + 1], lo)) { return false; }
        out[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return true;
}

static bool parse_hex32(const char* s, uint8_t out[32]) {
    if (s == nullptr) { return false; }
    size_t len = std::strlen(s);
    if (len != 64) { return false; }
    auto hexv = [](char c, int& v) {
        if (c >= '0' && c <= '9') { v = c - '0'; return true; }
        if (c >= 'a' && c <= 'f') { v = c - 'a' + 10; return true; }
        if (c >= 'A' && c <= 'F') { v = c - 'A' + 10; return true; }
        return false;
    };
    for (int i = 0; i < 32; ++i) {
        int hi = 0, lo = 0;
        if (!hexv(s[i * 2], hi)) { return false; }
        if (!hexv(s[i * 2 + 1], lo)) { return false; }
        out[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return true;
}

static bool copy_host_arg(const char* s, char out[64]) {
    if (s == nullptr) { return false; }
    size_t len = std::strlen(s);
    if (len == 0u || len >= 64u) { return false; }
    for (size_t i = 0; i < len; ++i) {
        unsigned char c = static_cast<unsigned char>(s[i]);
        bool alpha = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
        bool digit = (c >= '0' && c <= '9');
        bool punct = (c == '.' || c == '-' || c == '_');
        if (!alpha && !digit && !punct) { return false; }
    }
    std::memset(out, 0, 64);
    std::memcpy(out, s, len);
    return true;
}

inline config_t parse_args(int argc, char** argv) {
    config_t cfg{};
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-h" || arg == "--help") {
            print_usage(stdout);
            std::exit(0);
        } else if (arg == "-i" || arg == "--input") {
            if (i + 1 >= argc) {
                std::fprintf(stderr, "Error: %s requires a value\n", arg.c_str());
                print_usage(stderr);
                std::exit(1);
            }
            cfg.input_path = argv[++i];
        } else if (arg == "-o" || arg == "--output") {
            if (i + 1 >= argc) {
                std::fprintf(stderr, "Error: %s requires a value\n", arg.c_str());
                print_usage(stderr);
                std::exit(1);
            }
            cfg.output_path = argv[++i];
        } else if (arg == "--strip-rich") {
            cfg.strip_rich = true;
        } else if (arg == "--strip-debug") {
            cfg.strip_debug = true;
        } else if (arg == "--ast-poison") {
            cfg.ast_poison = true;
        } else if (arg == "--symexec-bombs") {
            cfg.symexec_bombs = true;
        } else if (arg == "--llm-poison") {
            cfg.llm_poison = true;
            cfg.no_llm_poison_explicit = false;
        } else if (arg == "--no-llm-poison") {
            cfg.llm_poison = false;
            cfg.no_llm_poison_explicit = true;
        } else if (arg == "--jit") {
            cfg.jit = true;
            cfg.no_jit_explicit = false;
        } else if (arg == "--no-jit") {
            cfg.jit = false;
            cfg.no_jit_explicit = true;
        } else if (arg == "--encrypt-imports") {
            cfg.encrypt_imports = true;
        } else if (arg == "--no-encrypt-imports") {
            cfg.encrypt_imports = false;
        } else if (arg == "--encrypt-strings") {
            cfg.encrypt_strings = true;
        } else if (arg == "--encrypt-resources") {
            cfg.encrypt_resources = true;
        } else if (arg == "--pack-sections") {
            cfg.pack_sections = true;
        } else if (arg == "--mangle-headers") {
            cfg.mangle_headers = true;
        } else if (arg == "--randomize-section-names") {
            cfg.randomize_section_names = true;
        } else if (arg == "--polymorphic") {
            cfg.polymorphic_stub = true;
        } else if (arg == "--merge-sections") {
            cfg.merge_sections = true;
        } else if (arg == "--flatten-entropy") {
            cfg.flatten_entropy = true;
        } else if (arg == "--deep-steal") {
            cfg.deep_steal = true;
        } else if (arg == "--ghost-veh") {
            cfg.ghost_veh = true;
        } else if (arg == "--rdtsc-entangle") {
            cfg.rdtsc_entangle = true;
        } else if (arg == "--opaque-predicates") {
            cfg.opaque_predicates = true;
        } else if (arg == "-a" || arg == "--all") {
            cfg.strip_rich = true;
            cfg.strip_debug = true;
            cfg.encrypt_imports = true;
            cfg.encrypt_strings = true;
            cfg.encrypt_resources = true;
            cfg.pack_sections = true;
            cfg.mangle_headers = true;
            cfg.randomize_section_names = true;
            cfg.polymorphic_stub = true;
            cfg.merge_sections = true;
            cfg.flatten_entropy = true;
            cfg.deep_steal = true;
            cfg.ghost_veh = true;
            cfg.rdtsc_entangle = true;
            cfg.opaque_predicates = true;
            cfg.ast_poison = true;
            cfg.symexec_bombs = true;
            cfg.llm_poison = true;
            cfg.jit = true;
        } else if (arg == "-v" || arg == "--verbose") {
            cfg.verbose = true;
        } else if (arg == "--seed") {
            if (i + 1 >= argc) {
                std::fprintf(stderr, "Error: --seed requires a value\n");
                print_usage(stderr);
                std::exit(1);
            }
            uint64_t v = 0;
            if (!parse_uint64(argv[++i], v)) {
                std::fprintf(stderr, "Error: invalid --seed value\n");
                std::exit(1);
            }
            cfg.seed = v;
            cfg.seed_provided = true;
        } else if (arg == "--watermark") {
            if (i + 1 >= argc) {
                std::fprintf(stderr, "Error: --watermark requires a value\n");
                std::exit(1);
            }
            if (!parse_hex16(argv[++i], cfg.license_hash)) {
                std::fprintf(stderr, "Error: --watermark must be 32 hex chars\n");
                std::exit(1);
            }
            cfg.watermark_provided = true;
        } else if (arg == "--embed-watermark") {
            cfg.embed_watermark = true;
        } else if (arg == "--bind-machine") {
            cfg.bind_machine = true;
        } else if (arg == "--target-arc") {
            cfg.target_arc = true;
        } else if (arg == "--tamper-level") {
            if (i + 1 >= argc) {
                std::fprintf(stderr, "Error: --tamper-level requires a value\n");
                std::exit(1);
            }
            uint64_t v = 0;
            if (!parse_uint64(argv[++i], v) || v > 3u) {
                std::fprintf(stderr, "Error: --tamper-level must be 0..3\n");
                std::exit(1);
            }
            cfg.tamper_response_level = static_cast<uint32_t>(v);
        } else if (arg == "--pin-primary") {
            if (i + 1 >= argc) {
                std::fprintf(stderr, "Error: --pin-primary requires a value\n");
                std::exit(1);
            }
            if (!parse_hex32(argv[++i], cfg.spki_pin_primary)) {
                std::fprintf(stderr, "Error: --pin-primary must be 64 hex chars (SHA-256 of SPKI)\n");
                std::exit(1);
            }
            cfg.spki_pin_primary_provided = true;
        } else if (arg == "--pin-secondary") {
            if (i + 1 >= argc) {
                std::fprintf(stderr, "Error: --pin-secondary requires a value\n");
                std::exit(1);
            }
            if (!parse_hex32(argv[++i], cfg.spki_pin_secondary)) {
                std::fprintf(stderr, "Error: --pin-secondary must be 64 hex chars (SHA-256 of SPKI)\n");
                std::exit(1);
            }
            cfg.spki_pin_secondary_provided = true;
        } else if (arg == "--primary-host") {
            if (i + 1 >= argc) {
                std::fprintf(stderr, "Error: --primary-host requires a value\n");
                std::exit(1);
            }
            if (!copy_host_arg(argv[++i], cfg.primary_host)) {
                std::fprintf(stderr, "Error: --primary-host must be a DNS hostname (<= 63 chars, alnum/./-/_)\n");
                std::exit(1);
            }
            cfg.primary_host_provided = true;
        } else if (arg == "--secondary-host") {
            if (i + 1 >= argc) {
                std::fprintf(stderr, "Error: --secondary-host requires a value\n");
                std::exit(1);
            }
            if (!copy_host_arg(argv[++i], cfg.secondary_host)) {
                std::fprintf(stderr, "Error: --secondary-host must be a DNS hostname (<= 63 chars, alnum/./-/_)\n");
                std::exit(1);
            }
            cfg.secondary_host_provided = true;
        } else if (arg == "--matryoshka-layers") {
            if (i + 1 >= argc) {
                std::fprintf(stderr, "Error: --matryoshka-layers requires a value (1 or 3)\n");
                std::exit(1);
            }
            uint64_t v = 0;
            if (!parse_uint64(argv[++i], v) || (v != 1u && v != 3u)) {
                std::fprintf(stderr, "Error: --matryoshka-layers must be 1 (legacy) or 3 (full Matryoshka)\n");
                std::exit(1);
            }
            cfg.matryoshka_layers = static_cast<uint32_t>(v);
        } else {
            std::fprintf(stderr, "Unknown option: %s\n", arg.c_str());
            print_usage(stderr);
            std::exit(1);
        }
    }
    if (cfg.no_jit_explicit) { cfg.jit = false; }
    if (cfg.no_llm_poison_explicit) { cfg.llm_poison = false; }
    if (cfg.target_arc) {
        cfg.strip_rich = true;
        cfg.strip_debug = true;
        cfg.encrypt_strings = true;
        cfg.encrypt_resources = true;
        cfg.pack_sections = true;
        cfg.mangle_headers = true;
        cfg.randomize_section_names = true;
        cfg.polymorphic_stub = true;
        cfg.merge_sections = true;
        cfg.deep_steal = true;
        cfg.ghost_veh = true;
        cfg.rdtsc_entangle = true;
        cfg.opaque_predicates = true;
        cfg.flatten_entropy = true;
        cfg.ast_poison = true;
        cfg.symexec_bombs = true;
        if (!cfg.no_llm_poison_explicit) { cfg.llm_poison = true; }
        if (!cfg.no_jit_explicit) { cfg.jit = true; }
        cfg.tamper_response_level = 4u;
    }
    if (cfg.input_path.empty() || cfg.output_path.empty()) {
        std::fprintf(stderr, "Error: --input and --output are required\n");
        print_usage(stderr);
        std::exit(1);
    }
    return cfg;
}

static uint64_t bytes_fingerprint64(const uint8_t* bytes, size_t len) {
    uint64_t h = 14695981039346656037ULL;
    if (bytes == nullptr) {
        return 0;
    }
    for (size_t i = 0; i < len; ++i) {
        h ^= static_cast<uint64_t>(bytes[i]);
        h *= 1099511628211ULL;
    }
    return h;
}

static unsigned count_zero_bytes(const uint8_t* bytes, size_t len) {
    if (bytes == nullptr) {
        return 0;
    }
    unsigned n = 0;
    for (size_t i = 0; i < len; ++i) {
        if (bytes[i] == 0) {
            ++n;
        }
    }
    return n;
}

static bool packed_range_within(uint32_t offset, uint64_t size, size_t limit) {
    const uint64_t end = static_cast<uint64_t>(offset) + size;
    return static_cast<uint64_t>(offset) <= static_cast<uint64_t>(limit) &&
           end <= static_cast<uint64_t>(limit);
}

static bool validate_counted_table_range(const uint8_t* base,
                                         size_t limit,
                                         uint32_t offset,
                                         uint32_t expected_count,
                                         size_t entry_size,
                                         uint32_t max_count,
                                         uint32_t image_size,
                                         const char* name,
                                         std::string& detail_out) {
    if (expected_count == 0u && offset == 0u) {
        return true;
    }
    if (offset == 0u) {
        detail_out = std::string(name) + " table missing for nonzero count";
        return false;
    }
    if (expected_count > max_count) {
        detail_out = std::string(name) + " table count exceeds verifier cap";
        return false;
    }
    if (!packed_range_within(offset, 4u, limit)) {
        detail_out = std::string(name) + " table count is outside packed data";
        return false;
    }
    uint32_t stored_count = 0;
    std::memcpy(&stored_count, base + offset, sizeof(stored_count));
    if (stored_count != expected_count) {
        detail_out = std::string(name) + " table stored count does not match header";
        return false;
    }
    if (stored_count > max_count) {
        detail_out = std::string(name) + " table stored count exceeds verifier cap";
        return false;
    }
    const uint64_t bytes = 4ull + static_cast<uint64_t>(stored_count) * static_cast<uint64_t>(entry_size);
    if (!packed_range_within(offset, bytes, limit)) {
        detail_out = std::string(name) + " table entries exceed packed data";
        return false;
    }
    if (image_size != 0u && stored_count != 0u) {
        const uint8_t* entries = base + offset + 4u;
        if (entry_size == sizeof(protector::string_fixup_t)) {
            for (uint32_t i = 0; i < stored_count; ++i) {
                protector::string_fixup_t sf{};
                std::memcpy(&sf, entries + static_cast<size_t>(i) * sizeof(sf), sizeof(sf));
                if (sf.length == 0u || !packed_range_within(sf.rva, sf.length, image_size)) {
                    detail_out = std::string(name) + " table target range exceeds image size";
                    return false;
                }
            }
        } else if (entry_size == sizeof(protector::resource_fixup_t)) {
            for (uint32_t i = 0; i < stored_count; ++i) {
                protector::resource_fixup_t rf{};
                std::memcpy(&rf, entries + static_cast<size_t>(i) * sizeof(rf), sizeof(rf));
                if (rf.size == 0u || !packed_range_within(rf.rva, rf.size, image_size)) {
                    detail_out = std::string(name) + " table target range exceeds image size";
                    return false;
                }
            }
        }
    }
    return true;
}

static bool validate_import_table_range(const uint8_t* base,
                                        size_t limit,
                                        uint32_t offset,
                                        uint32_t expected_count,
                                        uint32_t image_size,
                                        std::string& detail_out) {
    constexpr uint32_t kMaxImports = 65536u;
    if (expected_count == 0u && offset == 0u) {
        return true;
    }
    if (offset == 0u) {
        detail_out = "import table missing for nonzero count";
        return false;
    }
    if (expected_count > kMaxImports) {
        detail_out = "import table count exceeds verifier cap";
        return false;
    }
    if (!packed_range_within(offset, 8u, limit)) {
        detail_out = "import table header is outside packed data";
        return false;
    }
    uint32_t stored_count = 0;
    std::memcpy(&stored_count, base + offset, sizeof(stored_count));
    if (stored_count != expected_count) {
        detail_out = "import table stored count does not match header";
        return false;
    }
    if (stored_count > kMaxImports) {
        detail_out = "import table stored count exceeds verifier cap";
        return false;
    }
    const uint64_t pool_field = static_cast<uint64_t>(offset) + 4ull
        + static_cast<uint64_t>(stored_count) * static_cast<uint64_t>(sizeof(protector::import_hash_entry_t));
    if (pool_field + 4ull > static_cast<uint64_t>(limit)) {
        detail_out = "import name-pool size field exceeds packed data";
        return false;
    }
    uint32_t pool_size = 0;
    std::memcpy(&pool_size, base + static_cast<size_t>(pool_field), sizeof(pool_size));
    const uint64_t bytes = 4ull
        + static_cast<uint64_t>(stored_count) * static_cast<uint64_t>(sizeof(protector::import_hash_entry_t))
        + 4ull
        + static_cast<uint64_t>(pool_size);
    if (!packed_range_within(offset, bytes, limit)) {
        detail_out = "import table/name-pool exceeds packed data";
        return false;
    }
    if (image_size != 0u && stored_count != 0u) {
        const uint8_t* entries = base + offset + 4u;
        for (uint32_t i = 0; i < stored_count; ++i) {
            protector::import_hash_entry_t entry{};
            std::memcpy(&entry, entries + static_cast<size_t>(i) * sizeof(entry), sizeof(entry));
            if (!packed_range_within(entry.iat_rva, 8u, image_size)) {
                detail_out = "import table IAT target range exceeds image size";
                return false;
            }
        }
    }
    return true;
}

inline bool validate_existing_packed_candidate(const pe_file::pe_image_t& pe,
                                               const pe_file::section_t& sec,
                                               size_t packed_off,
                                               std::string& detail_out) {
    if (pe.dos_header.e_magic != IMAGE_DOS_SIGNATURE ||
        pe.pe_signature != IMAGE_NT_SIGNATURE ||
        pe.optional_header.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
        pe.optional_header.SizeOfImage == 0u) {
        detail_out = "PE headers are not a valid protected PE32+ image";
        return false;
    }
    if (packed_off + sizeof(protector::packed_header_t) > sec.data.size()) {
        detail_out = "packed candidate header exceeds section data";
        return false;
    }
    if (sec.virtual_address == 0u ||
        sec.virtual_size < sizeof(protector::packed_header_t) ||
        !packed_range_within(sec.virtual_address, sec.virtual_size, pe.optional_header.SizeOfImage)) {
        detail_out = "packed candidate section range exceeds image";
        return false;
    }
    if (sec.virtual_size <= packed_off) {
        detail_out = "packed candidate header is outside virtual section range";
        return false;
    }
    const size_t packed_virtual_size = static_cast<size_t>(sec.virtual_size) - packed_off;
    const size_t packed_payload_size = (std::min<size_t>)(sec.data.size() - packed_off, packed_virtual_size);
    if (packed_payload_size < sizeof(protector::packed_header_t)) {
        detail_out = "packed candidate virtual payload is too small";
        return false;
    }
    const uint8_t* packed_base = sec.data.data() + packed_off;
    protector::packed_header_t hdr{};
    std::memcpy(&hdr, packed_base, sizeof(hdr));
    if (hdr.magic != protector::kPackedMagic ||
        (hdr.version != protector::kPackedVersion &&
         hdr.version != protector::kPackedVersionLegacy)) {
        detail_out = "packed candidate magic/version mismatch";
        return false;
    }
    if (hdr.section_count > 512u) {
        detail_out = "packed candidate section count exceeds runtime cap";
        return false;
    }
    const uint64_t section_table_bytes = static_cast<uint64_t>(hdr.section_count)
        * static_cast<uint64_t>(sizeof(protector::section_descriptor_t));
    if (!packed_range_within(hdr.section_table_offset, section_table_bytes, packed_payload_size)) {
        detail_out = "packed candidate section table exceeds packed data";
        return false;
    }
    for (uint32_t i = 0; i < hdr.section_count; ++i) {
        protector::section_descriptor_t desc{};
        const size_t desc_off = static_cast<size_t>(hdr.section_table_offset)
            + static_cast<size_t>(i) * sizeof(desc);
        std::memcpy(&desc, packed_base + desc_off, sizeof(desc));
        if (desc.original_rva == 0u || desc.original_virtual_size == 0u) {
            detail_out = "packed candidate section descriptor has empty target range";
            return false;
        }
        if (desc.encrypted_size == 0u || desc.compressed_size == 0u ||
            desc.compressed_size > desc.encrypted_size) {
            detail_out = "packed candidate section descriptor has invalid sizes";
            return false;
        }
        if (!packed_range_within(desc.blob_offset, desc.encrypted_size, packed_payload_size)) {
            detail_out = "packed candidate encrypted blob exceeds packed data";
            return false;
        }
        if (desc.layers_applied != 1u && desc.layers_applied != 3u) {
            detail_out = "packed candidate section descriptor has unsupported layer count";
            return false;
        }
        if (!packed_range_within(desc.original_rva,
                                 desc.original_virtual_size,
                                 pe.optional_header.SizeOfImage)) {
            detail_out = "packed candidate section descriptor target exceeds image";
            return false;
        }
    }
    if (!validate_import_table_range(packed_base,
                                     packed_payload_size,
                                     hdr.import_table_offset,
                                     hdr.import_count,
                                     pe.optional_header.SizeOfImage,
                                     detail_out)) {
        return false;
    }
    constexpr uint32_t kMaxExistingFixups = 262144u;
    if (!validate_counted_table_range(packed_base,
                                      packed_payload_size,
                                      hdr.string_table_offset,
                                      hdr.string_fixup_count,
                                      sizeof(protector::string_fixup_t),
                                      kMaxExistingFixups,
                                      pe.optional_header.SizeOfImage,
                                      "string fixup",
                                      detail_out)) {
        return false;
    }
    if (!validate_counted_table_range(packed_base,
                                      packed_payload_size,
                                      hdr.resource_table_offset,
                                      hdr.resource_fixup_count,
                                      sizeof(protector::resource_fixup_t),
                                      kMaxExistingFixups,
                                      pe.optional_header.SizeOfImage,
                                      "resource fixup",
                                      detail_out)) {
        return false;
    }
    if (!packed_range_within(hdr.master_key_offset, 64u, packed_payload_size)) {
        detail_out = "packed candidate master key exceeds packed data";
        return false;
    }
    if (count_zero_bytes(packed_base + hdr.master_key_offset, 64u) == 64u) {
        detail_out = "packed candidate master key material is all zero";
        return false;
    }
    if (hdr.stub_code_offset == 0u ||
        !packed_range_within(hdr.stub_code_offset, 1u, packed_payload_size)) {
        detail_out = "packed candidate stub offset is invalid";
        return false;
    }
    const size_t stub_scan = (std::min<size_t>)(256u, packed_payload_size - hdr.stub_code_offset);
    if (stub_scan == 0u ||
        count_zero_bytes(packed_base + hdr.stub_code_offset, stub_scan) == stub_scan) {
        detail_out = "packed candidate stub bytes are empty";
        return false;
    }
    if (hdr.version == protector::kPackedVersion) {
        if (hdr.aux_offset == 0u || hdr.aux_size != sizeof(protector::aux_block_t) ||
            !packed_range_within(hdr.aux_offset, hdr.aux_size, packed_payload_size)) {
            detail_out = "packed candidate aux block offset/size mismatch";
            return false;
        }
        protector::aux_block_t aux{};
        std::memcpy(&aux, packed_base + hdr.aux_offset, sizeof(aux));
        if (aux.magic != protector::kAuxMagic || aux.version != protector::kAuxVersion) {
            detail_out = "packed candidate aux block magic/version mismatch";
            return false;
        }
    } else if (hdr.aux_size != 0u &&
               !packed_range_within(hdr.aux_offset, hdr.aux_size, packed_payload_size)) {
        detail_out = "legacy packed candidate aux block exceeds packed data";
        return false;
    }
    const uint32_t packed_rva = sec.virtual_address + static_cast<uint32_t>(packed_off);
    const uint32_t ep = pe.optional_header.AddressOfEntryPoint;
    if (ep < packed_rva || ep >= packed_rva + static_cast<uint32_t>(packed_virtual_size)) {
        detail_out = "entry point is outside packed candidate section";
        return false;
    }
    const uint32_t ep_rel = ep - packed_rva;
    if (ep_rel < hdr.stub_code_offset || ep_rel >= packed_payload_size) {
        detail_out = "entry point is outside packed candidate stub region";
        return false;
    }
    char name_buf[16] = {};
    std::memcpy(name_buf, sec.name, sizeof(sec.name));
    name_buf[8] = '\0';
    char buf[224];
    std::snprintf(buf, sizeof(buf),
        "validated packed layout in section '%s' rva=0x%X offset=0x%zX version=0x%08X size=%zu sections=%u ep_rel=0x%X",
        name_buf,
        static_cast<unsigned>(packed_rva),
        packed_off,
        hdr.version,
        packed_payload_size,
        hdr.section_count,
        ep_rel);
    detail_out = buf;
    return true;
}

inline bool detect_already_protected(const pe_file::pe_image_t& pe, std::string& detail_out) {
    std::string rejected_detail;
    for (const auto& sec : pe.sections) {
        const size_t scan_limit = (std::min<size_t>)(sec.data.size(), sec.virtual_size);
        if (scan_limit < sizeof(protector::packed_header_t)) continue;
        for (size_t off = 0; off + sizeof(protector::packed_header_t) <= scan_limit; off += 8) {
            protector::packed_header_t hdr{};
            std::memcpy(&hdr, sec.data.data() + off, sizeof(hdr));
            if (hdr.magic != protector::kPackedMagic ||
                (hdr.version != protector::kPackedVersion &&
                 hdr.version != protector::kPackedVersionLegacy)) {
                continue;
            }
            std::string candidate_detail;
            if (validate_existing_packed_candidate(pe, sec, off, candidate_detail)) {
                detail_out = candidate_detail;
                return true;
            }
            if (rejected_detail.empty())
                rejected_detail = candidate_detail;
        }
    }
    if (!rejected_detail.empty())
        detail_out = rejected_detail;
    return false;
}

inline bool validate_protected_metadata(const pe_file::pe_image_t& pe,
                                        const protector::transform_result_t& result,
                                        const stub::generated_stub_t& gen,
                                        std::string& detail_out) {
    if (pe.dos_header.e_magic != IMAGE_DOS_SIGNATURE) {
        detail_out = "DOS header magic is not MZ";
        return false;
    }
    if (pe.dos_header.e_lfanew < 64 || pe.dos_header.e_lfanew > 0x10000) {
        detail_out = "DOS e_lfanew is outside the supported loader range";
        return false;
    }
    if (pe.pe_signature != IMAGE_NT_SIGNATURE) {
        detail_out = "NT signature is not PE";
        return false;
    }
    if (pe.optional_header.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        detail_out = "optional header magic is not PE32+";
        return false;
    }
    if (pe.optional_header.NumberOfRvaAndSizes < 16u) {
        detail_out = "NumberOfRvaAndSizes is below 16";
        return false;
    }
    const pe_file::section_t* packed_sec = pe.section_from_rva(result.packed_section_rva);
    if (packed_sec == nullptr) {
        detail_out = "packed section RVA does not resolve to a section";
        return false;
    }
    if (!protector::section_skip_list::name_equals(packed_sec->name, ".packed")) {
        char name_buf[16] = {};
        std::memcpy(name_buf, packed_sec->name, sizeof(packed_sec->name));
        name_buf[8] = '\0';
        detail_out = std::string("packed section name is unstable: ") + name_buf;
        return false;
    }
    const uint32_t packed_off = result.packed_section_rva - packed_sec->virtual_address;
    if (static_cast<size_t>(packed_off) + sizeof(protector::packed_header_t) > packed_sec->data.size()) {
        detail_out = "packed header is outside the packed section data";
        return false;
    }
    const size_t packed_payload_size = packed_sec->data.size() - static_cast<size_t>(packed_off);
    protector::packed_header_t hdr{};
    std::memcpy(&hdr, packed_sec->data.data() + packed_off, sizeof(hdr));
    if (hdr.magic != protector::kPackedMagic || hdr.version != protector::kPackedVersion) {
        detail_out = "packed header magic/version mismatch";
        return false;
    }
    if (hdr.section_count > 512u) {
        detail_out = "packed section count exceeds runtime cap";
        return false;
    }
    if (hdr.import_count != result.imports.entry_count ||
        hdr.string_fixup_count != result.strings.entry_count ||
        hdr.resource_fixup_count != result.resources.entry_count) {
        detail_out = "packed header counts do not match transform result";
        return false;
    }
    if (hdr.section_table_offset != result.layout.section_table_offset ||
        hdr.import_table_offset != result.layout.import_table_offset ||
        hdr.string_table_offset != result.layout.string_table_offset ||
        hdr.resource_table_offset != result.layout.resource_table_offset ||
        hdr.master_key_offset != result.layout.master_key_offset ||
        hdr.stub_code_offset != result.layout.stub_offset ||
        hdr.aux_offset != result.layout.aux_offset) {
        detail_out = "packed header offsets do not match transform layout";
        return false;
    }
    const uint64_t section_table_bytes = static_cast<uint64_t>(hdr.section_count)
        * static_cast<uint64_t>(sizeof(protector::section_descriptor_t));
    if (!packed_range_within(hdr.section_table_offset, section_table_bytes, packed_payload_size)) {
        detail_out = "section descriptor table exceeds packed section data";
        return false;
    }
    for (uint32_t i = 0; i < hdr.section_count; ++i) {
        protector::section_descriptor_t desc{};
        const size_t desc_off = static_cast<size_t>(packed_off)
            + hdr.section_table_offset
            + static_cast<size_t>(i) * sizeof(desc);
        if (desc_off + sizeof(desc) > packed_sec->data.size()) {
            detail_out = "section descriptor is outside packed section data";
            return false;
        }
        std::memcpy(&desc, packed_sec->data.data() + desc_off, sizeof(desc));
        if (desc.original_rva == 0u || desc.original_virtual_size == 0u) {
            detail_out = "section descriptor has empty target range";
            return false;
        }
        if (desc.encrypted_size == 0u || desc.compressed_size == 0u || desc.compressed_size > desc.encrypted_size) {
            detail_out = "section descriptor has invalid compressed/encrypted sizes";
            return false;
        }
        if (!packed_range_within(desc.blob_offset, desc.encrypted_size, packed_payload_size)) {
            detail_out = "packed section blob exceeds packed section data";
            return false;
        }
        if (desc.layers_applied != 1u && desc.layers_applied != 3u) {
            detail_out = "section descriptor has unsupported matryoshka layer count";
            return false;
        }
        if (!packed_range_within(desc.original_rva,
                                 desc.original_virtual_size,
                                 pe.optional_header.SizeOfImage)) {
            detail_out = "section descriptor target range exceeds image size";
            return false;
        }
    }
    if (!validate_import_table_range(packed_sec->data.data() + packed_off,
                                     packed_payload_size,
                                     hdr.import_table_offset,
                                     hdr.import_count,
                                     pe.optional_header.SizeOfImage,
                                     detail_out)) {
        return false;
    }
    constexpr uint32_t kMaxFixups = 262144u;
    if (!validate_counted_table_range(packed_sec->data.data() + packed_off,
                                      packed_payload_size,
                                      hdr.string_table_offset,
                                      hdr.string_fixup_count,
                                      sizeof(protector::string_fixup_t),
                                      kMaxFixups,
                                      pe.optional_header.SizeOfImage,
                                      "string fixup",
                                      detail_out)) {
        return false;
    }
    if (!validate_counted_table_range(packed_sec->data.data() + packed_off,
                                      packed_payload_size,
                                      hdr.resource_table_offset,
                                      hdr.resource_fixup_count,
                                      sizeof(protector::resource_fixup_t),
                                      kMaxFixups,
                                      pe.optional_header.SizeOfImage,
                                      "resource fixup",
                                      detail_out)) {
        return false;
    }
    if (!packed_range_within(hdr.master_key_offset, 64u, packed_payload_size)) {
        detail_out = "master key material exceeds packed section data";
        return false;
    }
    if (hdr.aux_offset == 0u || hdr.aux_size != sizeof(protector::aux_block_t)) {
        detail_out = "aux block offset/size mismatch";
        return false;
    }
    if (static_cast<size_t>(packed_off) + hdr.aux_offset + sizeof(protector::aux_block_t) > packed_sec->data.size()) {
        detail_out = "aux block is outside the packed section data";
        return false;
    }
    protector::aux_block_t aux{};
    std::memcpy(&aux, packed_sec->data.data() + packed_off + hdr.aux_offset, sizeof(aux));
    if (aux.magic != protector::kAuxMagic || aux.version != protector::kAuxVersion) {
        detail_out = "aux block magic/version mismatch";
        return false;
    }
    if (gen.main_stub.empty() || gen.main_stub_entry_offset >= gen.main_stub.size()) {
        detail_out = "generated main stub entry offset is invalid";
        return false;
    }
    if (hdr.stub_code_offset == 0u ||
        !packed_range_within(hdr.stub_code_offset,
                             static_cast<uint64_t>(gen.main_stub.size()),
                             packed_payload_size)) {
        detail_out = "main stub body is outside the packed section data";
        return false;
    }
    if (!packed_range_within(hdr.stub_code_offset,
                             static_cast<uint64_t>(gen.main_stub_entry_offset) + 1ull,
                             packed_payload_size)) {
        detail_out = "main stub entry is outside the packed section data";
        return false;
    }
    const uint32_t expected_entry = result.packed_section_rva
        + result.layout.stub_offset
        + gen.main_stub_entry_offset;
    if (pe.optional_header.AddressOfEntryPoint != expected_entry) {
        detail_out = "entry point does not match generated main stub";
        return false;
    }
    for (uint32_t i = 0; i < 16u; ++i) {
        if (pe.optional_header.DataDirectory[i].VirtualAddress != pe.data_directories[i].rva ||
            pe.optional_header.DataDirectory[i].Size != pe.data_directories[i].size) {
            detail_out = "optional-header data directory mirror is stale";
            return false;
        }
    }
    return true;
}

inline int run(const config_t& cfg) {
    pe_file::pe_image_t pe;
    uint64_t input_size = 0;
    try {
        pe = pe_file::load(cfg.input_path);
        std::error_code ec;
        auto sz = std::filesystem::file_size(cfg.input_path, ec);
        if (!ec) {
            input_size = static_cast<uint64_t>(sz);
        }
    } catch (const std::bad_alloc&) {
        std::fprintf(stderr, "[!] out of memory loading PE\n");
        return 2;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "[!] parse error: %s\n", e.what());
        return 2;
    }

    if (pe.optional_header.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        std::fprintf(stderr, "[!] not a PE32+ image\n");
        return 2;
    }

    if (cfg.target_arc) {
        std::string input_basename;
        try {
            std::filesystem::path p(cfg.input_path);
            input_basename = p.filename().string();
        } catch (const std::exception&) {
            input_basename.clear();
        }
        std::string lower = input_basename;
        for (auto& ch : lower) {
            if (ch >= 'A' && ch <= 'Z') { ch = static_cast<char>(ch - 'A' + 'a'); }
        }
        bool name_ok = (lower == "aida_core.dll");
        bool is_dll_flag = (pe.file_header.Characteristics & IMAGE_FILE_DLL) != 0;
        if (!name_ok || !is_dll_flag) {
            std::fprintf(stderr,
                "[!] --target-arc rejected: input must be aida_core.dll (got '%s', is_dll=%d).\n"
                "    The ARC protection profile is exclusive to the runtime core DLL.\n",
                input_basename.c_str(), is_dll_flag ? 1 : 0);
            return 2;
        }
    }

    {
        std::string protect_detail;
        if (detect_already_protected(pe, protect_detail)) {
            std::fprintf(stdout,
                "[!] %s is already protected (%s) — skipping to preserve binary integrity.\n"
                "    Re-protection on top of a protected PE would corrupt section blobs, double-encrypt strings,\n"
                "    and chain stubs incorrectly. Run a Clean build (deletes the binary so the linker emits a\n"
                "    fresh unprotected PE) if you want a brand-new protected build.\n",
                cfg.input_path.c_str(), protect_detail.c_str());
            if (cfg.input_path != cfg.output_path) {
                std::error_code copy_ec;
                std::filesystem::copy_file(cfg.input_path, cfg.output_path,
                    std::filesystem::copy_options::overwrite_existing, copy_ec);
                if (copy_ec) {
                    std::fprintf(stderr, "[!] copy_file failed: %s\n", copy_ec.message().c_str());
                    return 2;
                }
            }
            return 0;
        }
    }

    const bool is_dll = (pe.file_header.Characteristics & IMAGE_FILE_DLL) != 0;

    protector::protect_options_t opt{};
    opt.strip_rich = cfg.strip_rich;
    opt.strip_debug = cfg.strip_debug;
    opt.encrypt_imports = cfg.encrypt_imports;
    opt.encrypt_strings = cfg.encrypt_strings;
    opt.encrypt_resources = cfg.encrypt_resources;
    opt.pack_sections = cfg.pack_sections;
    opt.mangle_headers = cfg.mangle_headers;
    opt.randomize_section_names = cfg.randomize_section_names;
    opt.verbose = cfg.verbose;
    opt.seed_provided = cfg.seed_provided;
    opt.seed = cfg.seed;
    opt.embed_watermark = cfg.embed_watermark;
    opt.bind_machine = cfg.bind_machine;
    opt.polymorphic_stub = cfg.polymorphic_stub;
    opt.merge_sections = cfg.merge_sections;
    opt.flatten_entropy = cfg.flatten_entropy;
    opt.deep_steal = cfg.deep_steal;
    opt.ghost_veh = cfg.ghost_veh;
    opt.rdtsc_entangle = cfg.rdtsc_entangle;
    opt.opaque_predicates = cfg.opaque_predicates;
    opt.ast_poison = cfg.ast_poison;
    opt.symexec_bombs = cfg.symexec_bombs;
    opt.llm_poison = cfg.llm_poison;
    opt.jit = cfg.jit;
    opt.tamper_response_level = cfg.tamper_response_level;
    opt.matryoshka_layers = cfg.matryoshka_layers;
    std::memcpy(opt.license_hash, cfg.license_hash, 16);
    std::memcpy(opt.spki_pin_primary,   cfg.spki_pin_primary,   32);
    std::memcpy(opt.spki_pin_secondary, cfg.spki_pin_secondary, 32);
    opt.spki_pin_primary_provided   = cfg.spki_pin_primary_provided;
    opt.spki_pin_secondary_provided = cfg.spki_pin_secondary_provided;
    std::memcpy(opt.primary_host,   cfg.primary_host,   sizeof(opt.primary_host));
    std::memcpy(opt.secondary_host, cfg.secondary_host, sizeof(opt.secondary_host));
    opt.primary_host_provided   = cfg.primary_host_provided;
    opt.secondary_host_provided = cfg.secondary_host_provided;

    if (cfg.target_arc) {
        opt.strip_rich = true;
        opt.strip_debug = true;
        opt.encrypt_strings = true;
        opt.encrypt_resources = true;
        opt.pack_sections = true;
        opt.mangle_headers = true;
        opt.randomize_section_names = true;
        opt.polymorphic_stub = true;
        opt.merge_sections = true;
        opt.flatten_entropy = true;
        opt.deep_steal = true;
        opt.ghost_veh = true;
        opt.rdtsc_entangle = true;
        opt.opaque_predicates = true;
        opt.ast_poison = true;
        opt.symexec_bombs = true;
        if (!cfg.no_llm_poison_explicit) {
            opt.llm_poison = true;
        }
        if (!cfg.no_jit_explicit) {
            opt.jit = true;
        }
        opt.tamper_response_level = 4u;
    }

    if (cfg.verbose) {
        std::fprintf(stdout, "[+] Loaded PE: %s (%llu bytes, %s)\n",
                     cfg.input_path.c_str(),
                     static_cast<unsigned long long>(input_size),
                     is_dll ? "DLL" : "EXE");
        if (cfg.target_arc) {
            std::fprintf(stdout, "[+] Target profile: ARC (packed strings/resources, header hardening, section randomization, deep_steal, anti-analysis phases forced; tamper_level=%u; flatten band 7000..7100)\n",
                         cfg.tamper_response_level);
        }
        std::fprintf(stdout, "[+] Sections: %zu\n", pe.sections.size());
        std::fprintf(stdout, "[+] Transforms enabled:%s%s%s%s%s%s%s%s\n",
                     cfg.strip_rich ? " strip_rich" : "",
                     cfg.strip_debug ? " strip_debug" : "",
                     cfg.encrypt_imports ? " encrypt_imports" : "",
                     cfg.encrypt_strings ? " encrypt_strings" : "",
                     cfg.encrypt_resources ? " encrypt_resources" : "",
                     cfg.pack_sections ? " pack_sections" : "",
                     cfg.mangle_headers ? " mangle_headers" : "",
                     cfg.randomize_section_names ? " randomize_section_names" : "");
        std::fprintf(stdout, "[+] Phase flags:%s%s%s%s%s%s%s\n",
                     cfg.polymorphic_stub ? " polymorphic" : "",
                     cfg.merge_sections ? " merge_sections" : "",
                     cfg.flatten_entropy ? " flatten_entropy" : "",
                     cfg.deep_steal ? " deep_steal" : "",
                     cfg.ghost_veh ? " ghost_veh" : "",
                     cfg.rdtsc_entangle ? " rdtsc_entangle" : "",
                     cfg.opaque_predicates ? " opaque_predicates" : "");
        std::fprintf(stdout, "[+] Phase B flags:%s%s%s%s\n",
                     cfg.ast_poison ? " ast_poison" : "",
                     cfg.symexec_bombs ? " symexec_bombs" : "",
                     cfg.llm_poison ? " llm_poison" : "",
                     cfg.jit ? " jit" : "");
        std::fprintf(stdout, "[+] Matryoshka pack layers: %u (%s)\n",
                     cfg.matryoshka_layers,
                     cfg.matryoshka_layers >= 3u ? "full triple stack" : "legacy single AES");
    }

    const uint32_t reloc_rva = pe.data_directories[IMAGE_DIRECTORY_ENTRY_BASERELOC].rva;
    const uint32_t reloc_size = pe.data_directories[IMAGE_DIRECTORY_ENTRY_BASERELOC].size;
    const uint32_t exc_rva = pe.data_directories[IMAGE_DIRECTORY_ENTRY_EXCEPTION].rva;
    const uint32_t exc_size = pe.data_directories[IMAGE_DIRECTORY_ENTRY_EXCEPTION].size;
    const bool has_existing_tls = pe.has_tls;
    const uint64_t preferred_base = pe.optional_header.ImageBase;

    protector::transform_result_t result;
    try {
        result = protector::protect_pe(pe, opt);
    } catch (const std::bad_alloc&) {
        std::fprintf(stderr, "[!] out of memory during protection\n");
        return 3;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "[!] transform error: %s\n", e.what());
        return 3;
    }

    if (!result.success) {
        std::fprintf(stderr, "[!] transform error: %s\n", result.error.c_str());
        return 3;
    }

    stub::stub_config_t stub_cfg{};
    stub_cfg.packed_section_rva = result.packed_section_rva;
    stub_cfg.original_entry_rva = result.original_entry_point;
    stub_cfg.section_count = static_cast<uint32_t>(pe.sections.size());
    stub_cfg.import_count = result.imports.entry_count;
    stub_cfg.string_fixup_count = result.strings.entry_count;
    stub_cfg.resource_fixup_count = result.resources.entry_count;
    stub_cfg.is_dll = is_dll;
    stub_cfg.has_existing_tls = has_existing_tls;
    stub_cfg.exception_dir_rva = exc_rva;
    stub_cfg.exception_dir_size = exc_size;
    stub_cfg.reloc_dir_rva = reloc_rva;
    stub_cfg.reloc_dir_size = reloc_size;
    stub_cfg.preferred_image_base = preferred_base;
    std::memcpy(stub_cfg.obfuscated_master_key, result.obfuscated_master_key, 32);
    std::memcpy(stub_cfg.key_obfuscation_mask, result.key_obfuscation_mask, 32);
    stub_cfg.original_timestamp = result.master_key_pe_timestamp;
    stub_cfg.original_size_of_code = result.master_key_pe_size_of_code;
    stub_cfg.section_table_offset = result.layout.section_table_offset;
    stub_cfg.import_table_offset = result.layout.import_table_offset;
    stub_cfg.string_table_offset = result.layout.string_table_offset;
    stub_cfg.resource_table_offset = result.layout.resource_table_offset;
    stub_cfg.master_key_offset = result.layout.master_key_offset;
    stub_cfg.stub_code_offset = result.layout.stub_offset;
    stub_cfg.seed = result.seed_used;
    stub_cfg.polymorphic = cfg.polymorphic_stub;

    stub::generated_stub_t gen;
    try {
        gen = stub::generate(stub_cfg);
    } catch (const std::bad_alloc&) {
        std::fprintf(stderr, "[!] out of memory generating stub\n");
        return 3;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "[!] stub generation error: %s\n", e.what());
        return 3;
    }

    if (gen.main_stub.size() > result.reserved_main_stub_size) {
        std::fprintf(stderr,
                     "[!] main stub too large: %zu bytes, reserved %u\n",
                     gen.main_stub.size(),
                     result.reserved_main_stub_size);
        return 3;
    }
    if (gen.tls_stub.size() > result.reserved_tls_stub_size) {
        std::fprintf(stderr,
                     "[!] tls stub too large: %zu bytes, reserved %u\n",
                     gen.tls_stub.size(),
                     result.reserved_tls_stub_size);
        return 3;
    }

    if (!protector::write_stub_into_packed(pe,
                                            result.packed_section_rva,
                                            result.layout,
                                            gen.main_stub,
                                            gen.tls_stub)) {
        std::fprintf(stderr, "[!] failed to write stub into .packed section\n");
        return 3;
    }

    if (!protector::patch_aux_signature(pe,
                                         result.packed_section_rva,
                                         result.layout,
                                         gen.build_nonce,
                                         gen.stub_signature_tag)) {
        std::fprintf(stderr, "[!] failed to patch aux signature fields\n");
        return 3;
    }

    const uint32_t new_entry = result.packed_section_rva
                                + result.layout.stub_offset
                                + gen.main_stub_entry_offset;
    protector::redirect_entry_point(pe, new_entry);

    bool tls_installed = false;
    if (!gen.tls_stub.empty() && result.layout.tls_stub_offset != 0u) {
        const uint32_t tls_rva = result.packed_section_rva
                                 + result.layout.tls_stub_offset
                                 + gen.tls_stub_entry_offset;
        const uint32_t tls_callback_list_rva = result.layout.tls_callback_array_offset != 0u
            ? result.packed_section_rva + result.layout.tls_callback_array_offset
            : 0u;
        const uint32_t tls_callback_list_capacity = result.layout.tls_callback_array_offset != 0u
            ? static_cast<uint32_t>(pe.tls.callback_rvas.size() + 2u)
            : 0u;
        tls_installed = protector::install_tls_callback(pe,
                                                        tls_rva,
                                                        tls_callback_list_rva,
                                                        tls_callback_list_capacity);
    }

    bool flatten_applied = false;
    bool merge_applied = false;
    if (cfg.flatten_entropy) {
        if (cfg.target_arc) {
            flatten_applied = protector::apply_flatten_entropy_band(
                pe, result.packed_section_rva, cfg.seed ^ 0xF1A7ULL, cfg.verbose,
                7100u, 7000u, 6900u);
        } else {
            flatten_applied = protector::apply_flatten_entropy(
                pe, result.packed_section_rva, cfg.seed ^ 0xF1A7ULL, cfg.verbose);
        }
    }
    if (cfg.merge_sections) {
        merge_applied = protector::apply_merge_sections(pe, cfg.seed);
    }
    uint32_t clear_phase_flags = 0u;
    if (cfg.merge_sections && !merge_applied) {
        clear_phase_flags |= 0x2u;
    }
    if (cfg.flatten_entropy && !flatten_applied) {
        clear_phase_flags |= 0x4u;
    }
    if (clear_phase_flags != 0u &&
        !protector::patch_aux_phase_flags(pe,
                                          result.packed_section_rva,
                                          result.layout,
                                          clear_phase_flags,
                                          0u)) {
        std::fprintf(stderr, "[!] failed to patch aux phase flags\n");
        return 3;
    }

    try {
        pe_file::recalculate_headers(pe);
    } catch (const std::bad_alloc&) {
        std::fprintf(stderr, "[!] out of memory recalculating headers\n");
        return 3;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "[!] header recalculation error: %s\n", e.what());
        return 3;
    }

    {
        uint32_t ep = pe.optional_header.AddressOfEntryPoint;
        const pe_file::section_t* ep_sec = pe.section_from_rva(ep);
        if (ep_sec == nullptr) {
            std::fprintf(stderr, "[!] entry point not inside any section\n");
            return 3;
        }
    }

    {
        std::string metadata_detail;
        if (!validate_protected_metadata(pe, result, gen, metadata_detail)) {
            std::fprintf(stderr, "[!] protected metadata validation failed: %s\n",
                         metadata_detail.c_str());
            return 3;
        }
    }

    try {
        pe_file::write(pe, cfg.output_path);
    } catch (const std::bad_alloc&) {
        std::fprintf(stderr, "[!] out of memory writing output\n");
        return 4;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "[!] write error: %s\n", e.what());
        return 4;
    }

    if (cfg.verbose) {
        uint64_t output_size = 0;
        std::error_code ec;
        auto sz = std::filesystem::file_size(cfg.output_path, ec);
        if (!ec) {
            output_size = static_cast<uint64_t>(sz);
        }

        const uint64_t key_fingerprint = bytes_fingerprint64(result.obfuscated_master_key, 32);
        const unsigned key_zeroes = count_zero_bytes(result.obfuscated_master_key, 32);

        std::fprintf(stdout, "[+] Master key material: obfuscated_len=32 zero_bytes=%u fingerprint=0x%016llX\n",
                     key_zeroes,
                     static_cast<unsigned long long>(key_fingerprint));
        std::fprintf(stdout, "[+] destroy_imports: %u entries\n",
                     result.imports.entry_count);
        std::fprintf(stdout, "[+] encrypt_strings: %u strings\n",
                     result.strings.entry_count);
        std::fprintf(stdout, "[+] encrypt_resources: %u RT_RCDATA entries\n",
                     result.resources.entry_count);

        uint32_t packed_count = 0;
        for (const auto& s : pe.sections) {
            if (s.data.empty() && s.raw_size == 0u && s.virtual_size != 0u) {
                ++packed_count;
            }
        }
        std::fprintf(stdout, "[+] pack_sections: %u sections\n", packed_count);
        std::fprintf(stdout, "[+] stub: main=%zu bytes (reserved %u), tls=%zu bytes (reserved %u)\n",
                     gen.main_stub.size(), result.reserved_main_stub_size,
                     gen.tls_stub.size(), result.reserved_tls_stub_size);
        std::fprintf(stdout, "[+] packed section: rva=0x%08X size=%u\n",
                     result.packed_section_rva, result.layout.total_size);
        if (const pe_file::section_t* psec = pe.section_from_rva(result.packed_section_rva)) {
            char packed_name[16] = {};
            std::memcpy(packed_name, psec->name, sizeof(psec->name));
            packed_name[8] = '\0';
            uint32_t packed_header_sections = packed_count;
            uint32_t runtime_phase_flags = 0u;
            const uint32_t packed_off = result.packed_section_rva - psec->virtual_address;
            if (static_cast<size_t>(packed_off) + sizeof(protector::packed_header_t) <= psec->data.size()) {
                protector::packed_header_t verbose_hdr{};
                std::memcpy(&verbose_hdr, psec->data.data() + packed_off, sizeof(verbose_hdr));
                if (verbose_hdr.magic == protector::kPackedMagic) {
                    packed_header_sections = verbose_hdr.section_count;
                    if (verbose_hdr.aux_size == sizeof(protector::aux_block_t) &&
                        static_cast<size_t>(packed_off) + verbose_hdr.aux_offset + sizeof(protector::aux_block_t) <= psec->data.size()) {
                        protector::aux_block_t verbose_aux{};
                        std::memcpy(&verbose_aux, psec->data.data() + packed_off + verbose_hdr.aux_offset, sizeof(verbose_aux));
                        if (verbose_aux.magic == protector::kAuxMagic) {
                            runtime_phase_flags = verbose_aux.phase_flags;
                        }
                    }
                }
            }
            std::fprintf(stdout,
                         "[+] runtime metadata: dos_magic=0x%04X e_lfanew=0x%08X nt_sig=0x%08X packed_name=%s packed_ch=0x%08X phase_flags=0x%08X\n",
                         pe.dos_header.e_magic,
                         static_cast<unsigned>(pe.dos_header.e_lfanew),
                         pe.pe_signature,
                         packed_name,
                         psec->characteristics,
                         runtime_phase_flags);
            std::fprintf(stdout,
                         "[+] packed layout: sections=%u imports=%u strings=%u resources=%u section_table=0x%08X import_table=0x%08X string_table=0x%08X resource_table=0x%08X master=0x%08X aux=0x%08X stub=0x%08X\n",
                         packed_header_sections,
                         result.imports.entry_count,
                         result.strings.entry_count,
                         result.resources.entry_count,
                         result.layout.section_table_offset,
                         result.layout.import_table_offset,
                         result.layout.string_table_offset,
                         result.layout.resource_table_offset,
                         result.layout.master_key_offset,
                         result.layout.aux_offset,
                         result.layout.stub_offset);
        }
        std::fprintf(stdout, "[+] entry: 0x%08X -> 0x%08X\n",
                     result.original_entry_point, new_entry);
        std::fprintf(stdout, "[+] tls callback: %s\n",
                     tls_installed ? "installed"
                                   : (has_existing_tls ? "skipped" : "no existing tls directory"));
        std::fprintf(stdout, "[+] flatten_entropy: %s\n",
                     flatten_applied ? "applied" : (cfg.flatten_entropy ? "skipped" : "disabled"));
        std::fprintf(stdout, "[+] merge_sections: %s\n",
                     merge_applied ? "applied" : (cfg.merge_sections ? "skipped" : "disabled"));
        std::fprintf(stdout, "[+] write: %s (%llu bytes)\n",
                     cfg.output_path.c_str(),
                     static_cast<unsigned long long>(output_size));
    }

    return 0;
}

}

int main(int argc, char** argv) {
    try {
        return protector::run(protector::parse_args(argc, argv));
    } catch (const std::bad_alloc&) {
        std::fprintf(stderr, "[!] out of memory\n");
        return 3;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "[!] fatal: %s\n", e.what());
        return 3;
    }
}
