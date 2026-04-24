#include "verify_api.hpp"

#include <cstdio>

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "Usage: aida_protector_verify <protected.exe>\n");
        return 1;
    }
    return verifier::verify_file(argv[1]);
}
