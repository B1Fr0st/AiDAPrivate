#pragma once

#include <string>

namespace aida::tests::c03 {

struct authority_surface_ledger_result_t {
    bool passed = false;
    std::string failure;
};

authority_surface_ledger_result_t run_authority_surface_ledger_harness();

}
