#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include "personalize.hpp"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

namespace {

static constexpr uint8_t kXorMask[8] = {
    0xA5, 0x5A, 0x3C, 0xC3, 0x96, 0x69, 0x4B, 0xB4
};

static constexpr uint8_t kMasterKeyChunk0[8] = {
    0xA5, 0x5A, 0x3C, 0xC3, 0x96, 0x69, 0x4B, 0xB4
};
static constexpr uint8_t kMasterKeyChunk1[8] = {
    0xA5, 0x5A, 0x3C, 0xC3, 0x96, 0x69, 0x4B, 0xB4
};
static constexpr uint8_t kMasterKeyChunk2[8] = {
    0xA5, 0x5A, 0x3C, 0xC3, 0x96, 0x69, 0x4B, 0xB4
};
static constexpr uint8_t kMasterKeyChunk3[8] = {
    0xA5, 0x5A, 0x3C, 0xC3, 0x96, 0x69, 0x4B, 0xB4
};

inline void reconstruct_master_key(uint8_t out[32]) {
    for (int i = 0; i < 8; ++i) {
        out[i]      = kMasterKeyChunk0[i] ^ kXorMask[i];
        out[8 + i]  = kMasterKeyChunk1[i] ^ kXorMask[i];
        out[16 + i] = kMasterKeyChunk2[i] ^ kXorMask[i];
        out[24 + i] = kMasterKeyChunk3[i] ^ kXorMask[i];
    }
}

static void print_usage_personalize(std::FILE* out) {
    std::fprintf(out,
        "Usage: aida_protector_personalize [options]\n"
        "\n"
        "Required:\n"
        "  -i, --input <path>              Template PE file path\n"
        "  -o, --output <path>             Output personalized PE file path\n"
        "  --template-metadata <path>      Path to template_metadata.json\n"
        "  --customer-uuid <hex32>         32 hex chars (128-bit customer UUID)\n"
        "\n"
        "Options:\n"
        "  -v, --verbose                   Verbose output\n"
        "  -h, --help                      Print this help and exit\n");
}

struct personalize_config_t {
    std::string input_path;
    std::string output_path;
    std::string template_metadata_path;
    std::string customer_uuid;
    bool verbose = false;
};

inline personalize_config_t parse_personalize_args(int argc, char** argv) {
    personalize_config_t cfg{};
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-h" || arg == "--help") {
            print_usage_personalize(stdout);
            std::exit(0);
        } else if (arg == "-i" || arg == "--input") {
            if (i + 1 >= argc) {
                std::fprintf(stderr, "Error: %s requires a value\n", arg.c_str());
                std::exit(1);
            }
            cfg.input_path = argv[++i];
        } else if (arg == "-o" || arg == "--output") {
            if (i + 1 >= argc) {
                std::fprintf(stderr, "Error: %s requires a value\n", arg.c_str());
                std::exit(1);
            }
            cfg.output_path = argv[++i];
        } else if (arg == "--template-metadata") {
            if (i + 1 >= argc) {
                std::fprintf(stderr, "Error: --template-metadata requires a value\n");
                std::exit(1);
            }
            cfg.template_metadata_path = argv[++i];
        } else if (arg == "--customer-uuid") {
            if (i + 1 >= argc) {
                std::fprintf(stderr, "Error: --customer-uuid requires a value\n");
                std::exit(1);
            }
            cfg.customer_uuid = argv[++i];
            if (cfg.customer_uuid.size() != 32) {
                std::fprintf(stderr, "Error: --customer-uuid must be 32 hex chars\n");
                std::exit(1);
            }
        } else if (arg == "-v" || arg == "--verbose") {
            cfg.verbose = true;
        } else {
            std::fprintf(stderr, "Unknown option: %s\n", arg.c_str());
            print_usage_personalize(stderr);
            std::exit(1);
        }
    }
    if (cfg.input_path.empty() || cfg.output_path.empty()) {
        std::fprintf(stderr, "Error: --input and --output are required\n");
        std::exit(1);
    }
    if (cfg.template_metadata_path.empty()) {
        std::fprintf(stderr, "Error: --template-metadata is required\n");
        std::exit(1);
    }
    if (cfg.customer_uuid.empty()) {
        std::fprintf(stderr, "Error: --customer-uuid is required\n");
        std::exit(1);
    }
    return cfg;
}

}

int main(int argc, char** argv) {
    try {
        personalize_config_t cfg = parse_personalize_args(argc, argv);

        uint8_t master_key[32];
        reconstruct_master_key(master_key);

        protector::personalize::personalize_progress_t progress;
        if (cfg.verbose) {
            progress.report = [](int pct, const char* msg) {
                std::fprintf(stdout, "[personalize] %3d%%  %s\n", pct, msg);
                std::fflush(stdout);
            };
        }

        int ret = protector::personalize::run_personalize_pipeline(
            cfg.input_path,
            cfg.output_path,
            cfg.template_metadata_path,
            cfg.customer_uuid,
            master_key,
            cfg.verbose ? &progress : nullptr);

        SecureZeroMemory(master_key, sizeof(master_key));
        return ret;
    } catch (const std::bad_alloc&) {
        std::fprintf(stderr, "[!] out of memory\n");
        return 3;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "[!] fatal: %s\n", e.what());
        return 3;
    }
}
