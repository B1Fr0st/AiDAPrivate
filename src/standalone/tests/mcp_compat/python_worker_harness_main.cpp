#include "python_worker_harness.hpp"

#include <iostream>

int main(int argc, char** argv) {
    std::string failure;
    const std::filesystem::path fake_worker = argc == 2 ? std::filesystem::path(argv[1]) : std::filesystem::path{};
    if (!aida::standalone::tests::mcp_compat::run_python_worker_harness(failure, fake_worker)) {
        std::cerr << failure << '\n';
        return 1;
    }
    return 0;
}
