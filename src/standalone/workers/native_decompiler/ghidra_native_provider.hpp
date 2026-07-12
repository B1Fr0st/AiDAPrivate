#pragma once

#include "native_worker_runtime.hpp"

#include <optional>
#include <vector>

namespace aida::analysis::native_worker::ghidra_native_provider {

struct result_t {
    std::optional<decompiler_document_t> document;
    std::vector<decompiler_diagnostic_t> diagnostics;
};

result_t produce(const runtime::startup_t& startup, const decompiler_worker_job_request_t& job);

}
