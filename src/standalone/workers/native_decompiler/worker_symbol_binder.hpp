#pragma once

#include "../../src/core/disasm/ghidra_adapters/aida_ghidra_preamble.hpp"
#include "../../src/core/disasm/ghidra_adapters/aida_architecture.hpp"
#include "../../src/core/disasm/ghidra_adapters/aida_function_db.hpp"

#include "snapshot_sidecar.hpp"

#include "helpers/diag_log.hpp"

#include <chrono>
#include <cstdint>
#include <unordered_set>
#include <utility>

namespace aida::analysis::native_worker::worker_symbol_binder {

struct bind_result_t {
    std::unordered_set<ghidra::FunctionSymbol*> pinned;
    std::size_t names = 0;
    std::size_t imports = 0;
    std::size_t noreturn = 0;
    std::size_t prototypes = 0;
    double bind_ms = 0.0;
};

inline bind_result_t bind(aida_ghidra::architecture_t& arch,
                          const snapshot_sidecar::sidecar_t& sidecar,
                          std::uint64_t image_base,
                          std::uint64_t image_size)
{
    const auto started = std::chrono::steady_clock::now();
    bind_result_t result;
    result.names = sidecar.names.size();
    result.imports = sidecar.imports.size();
    result.noreturn = sidecar.noreturn.size();
    result.prototypes = sidecar.prototypes.size();
    aida_ghidra::populate_from_sidecar(arch.symbol_database(), sidecar, image_base, image_size);
    try {
        arch.apply_pdb_function_prototypes();
    } catch (...) {
        diag::log_tagged_fmt("dec", "sidecar_prototypes_apply_exception");
    }
    if (!sidecar.prototypes.empty() && arch.symboltab && arch.getDefaultCodeSpace()) {
        ghidra::Scope* global_scope = arch.symboltab->getGlobalScope();
        ghidra::AddrSpace* space = arch.getDefaultCodeSpace();
        if (global_scope && space) {
            try {
                result.pinned.reserve(sidecar.prototypes.size());
            } catch (...) {
            }
            for (const auto& record : sidecar.prototypes) {
                if (record.rva == 0 || record.rva > (std::numeric_limits<std::uint64_t>::max)() - image_base)
                    continue;
                ghidra::Funcdata* fd = nullptr;
                try {
                    fd = global_scope->queryFunction(
                        ghidra::Address(space, image_base + record.rva));
                } catch (...) {
                    fd = nullptr;
                }
                if (!fd)
                    continue;
                if (auto* symbol = fd->getSymbol())
                    result.pinned.insert(symbol);
            }
        }
    }
    result.bind_ms = std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now() - started).count();
    diag::log_tagged_fmt("dec",
        "sidecar_bound names=%zu imports=%zu noreturn=%zu prototypes=%zu pinned=%zu bind_ms=%.2f",
        result.names, result.imports, result.noreturn, result.prototypes,
        result.pinned.size(), result.bind_ms);
    return result;
}

}
