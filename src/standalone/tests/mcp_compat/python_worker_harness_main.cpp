#include "python_worker_harness.hpp"

#include <iostream>

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "python worker harness requires exactly one fake-worker path\n";
        return 2;
    }
    std::string failure;
    const std::filesystem::path fake_worker(argv[1]);
    if (!aida::standalone::tests::mcp_compat::run_python_worker_harness(failure, fake_worker)) {
        std::cerr << failure << '\n';
        return 1;
    }
    return 0;
}
