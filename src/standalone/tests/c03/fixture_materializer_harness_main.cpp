#include "fixture_materializer_harness.hpp"

#include <filesystem>
#include <iostream>
#include <string>

int main(int argc, char** argv)
{
    if (argc != 3) {
        std::cerr << "usage: c03_fixture_materializer_harness <repository-root> <output-root>\n";
        return 2;
    }
    std::string failure;
    if (!aida::analysis::c03::run_fixture_materializer_harness(
            std::filesystem::absolute(argv[1]), std::filesystem::absolute(argv[2]), failure)) {
        std::cerr << failure << '\n';
        return 1;
    }
    return 0;
}
