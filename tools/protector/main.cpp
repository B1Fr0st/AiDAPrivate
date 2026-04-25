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
    uint64_t seed = 0;
    uint32_t tamper_response_level = 0;
    uint8_t  license_hash[16] = {0};
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
        } else {
            std::fprintf(stderr, "Unknown option: %s\n", arg.c_str());
            print_usage(stderr);
            std::exit(1);
        }
    }
    if (cfg.no_jit_explicit) { cfg.jit = false; }
    if (cfg.no_llm_poison_explicit) { cfg.llm_poison = false; }
    if (cfg.input_path.empty() || cfg.output_path.empty()) {
        std::fprintf(stderr, "Error: --input and --output are required\n");
        print_usage(stderr);
        std::exit(1);
    }
    return cfg;
}

static void hex32(char* out, const uint8_t* bytes) {
    static const char kHex[] = "0123456789abcdef";
    for (int i = 0; i < 32; ++i) {
        out[i * 2] = kHex[(bytes[i] >> 4) & 0xF];
        out[i * 2 + 1] = kHex[bytes[i] & 0xF];
    }
    out[64] = '\0';
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
    std::memcpy(opt.license_hash, cfg.license_hash, 16);

    if (cfg.verbose) {
        std::fprintf(stdout, "[+] Loaded PE: %s (%llu bytes, %s)\n",
                     cfg.input_path.c_str(),
                     static_cast<unsigned long long>(input_size),
                     is_dll ? "DLL" : "EXE");
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
        tls_installed = protector::install_tls_callback(pe, tls_rva);
    }

    bool flatten_applied = false;
    bool merge_applied = false;
    if (cfg.flatten_entropy) {
        flatten_applied = protector::apply_flatten_entropy(
            pe, result.packed_section_rva, cfg.seed ^ 0xF1A7ULL, cfg.verbose);
    }
    if (cfg.merge_sections) {
        merge_applied = protector::apply_merge_sections(pe, cfg.seed);
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

        char keyhex[65];
        hex32(keyhex, result.obfuscated_master_key);

        std::fprintf(stdout, "[+] Master key (obfuscated): %s\n", keyhex);
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
