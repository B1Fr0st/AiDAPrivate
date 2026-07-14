#include "benchmark_sla_receipt_harness.hpp"

#include <iostream>
#include <string_view>

int main(int argc, char** argv)
{
    if (argc != 4 || (std::string_view(argv[1]) != "measure" && std::string_view(argv[1]) != "not-run")) {
        std::cerr << "usage: benchmark_sla_receipt_harness <measure|not-run> <evidence-root> <input-json>\n";
        return 2;
    }
    std::string receipt;
    std::string failure;
    if (!aida::analysis::c03::run_benchmark_sla_receipt_harness(argv[2], argv[3],
        std::string_view(argv[1]) == "not-run", receipt, failure)) {
        std::cerr << failure << '\n';
        return 1;
    }
    std::cout << receipt << '\n';
    return 0;
}
