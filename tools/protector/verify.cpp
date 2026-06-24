#include "verify_api.hpp"

#include <cstdio>
#include <string>

int main(int argc, char** argv) {
    verifier::verify_profile_t profile = verifier::verify_profile_t::strict_no_imports;
    std::string path;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i] != nullptr ? argv[i] : "";
        if (arg == "--profile") {
            if (i + 1 >= argc) {
                std::fprintf(stderr, "Usage: aida_protector_verify [--profile strict-no-imports|standalone-no-imports|preserved-imports] <protected.exe>\n");
                return 1;
            }
            std::string value = argv[++i] != nullptr ? argv[i] : "";
            if (!verifier::parse_profile(value, profile)) {
                std::fprintf(stderr, "Unknown verifier profile: %s\n", value.c_str());
                std::fprintf(stderr, "Usage: aida_protector_verify [--profile strict-no-imports|standalone-no-imports|preserved-imports] <protected.exe>\n");
                return 1;
            }
        } else if (path.empty()) {
            path = arg;
        } else {
            std::fprintf(stderr, "Unexpected argument: %s\n", arg.c_str());
            std::fprintf(stderr, "Usage: aida_protector_verify [--profile strict-no-imports|standalone-no-imports|preserved-imports] <protected.exe>\n");
            return 1;
        }
    }
    if (path.empty()) {
        std::fprintf(stderr, "Usage: aida_protector_verify [--profile strict-no-imports|standalone-no-imports|preserved-imports] <protected.exe>\n");
        return 1;
    }
    return verifier::verify_file(path, profile);
}
