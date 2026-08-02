#include "assertion_telemetry/assertion_telemetry.hpp"

#include "../../src/core/analysis/decompiler/api_prototype_table.hpp"

#include <cstdint>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

namespace aida::analysis::c03_test {
namespace {

void require(bool condition, const char* message)
{
    assertion_telemetry::record_assertion(condition, message, __FILE__, __LINE__);
    if (!condition)
        throw std::runtime_error(message);
}

std::optional<api_prototypes::api_prototype_t> legacy_find(std::string_view module,
                                                           std::string_view name) noexcept
{
    using namespace api_prototypes;
    if (name.empty() || name.size() > 256 || module.empty() || module.size() > 260)
        return std::nullopt;
    const std::string_view base = normalized_module(module);
    for (const auto& entry : k_entries) {
        if (entry.is_crt || !entry.signature || entry.signature[0] == '\0')
            continue;
        if (name != entry.name)
            continue;
        std::string_view entry_module = normalized_module(entry.module);
        if (iequals(base, entry_module))
            return api_prototype_t{entry.signature, entry.is_noreturn};
    }
    if (!module_is_crt(module))
        return std::nullopt;
    for (const auto& entry : k_entries) {
        if (!entry.is_crt || !entry.signature || entry.signature[0] == '\0')
            continue;
        if (name == entry.name)
            return api_prototype_t{entry.signature, entry.is_noreturn};
    }
    return std::nullopt;
}

bool same_result(const std::optional<api_prototypes::api_prototype_t>& lhs,
                 const std::optional<api_prototypes::api_prototype_t>& rhs)
{
    if (lhs.has_value() != rhs.has_value())
        return false;
    if (!lhs)
        return true;
    return lhs->signature.data() == rhs->signature.data() &&
           lhs->signature.size() == rhs->signature.size() &&
           lhs->is_noreturn == rhs->is_noreturn;
}

void verify_table_invariants()
{
    using namespace api_prototypes;
    constexpr std::size_t count = sizeof(k_entries) / sizeof(k_entries[0]);
    require(count >= 900, "api prototype table must hold at least 900 entries");
    std::unordered_set<std::string> module_name_keys;
    std::unordered_set<std::string> crt_names;
    std::size_t crt_count = 0;
    for (const auto& entry : k_entries) {
        std::string module = entry.module ? entry.module : "";
        for (auto& ch : module)
            if (ch >= 'A' && ch <= 'Z')
                ch = static_cast<char>(ch - 'A' + 'a');
        std::string normalized = module.size() > 4 && module.compare(module.size() - 4, 4, ".dll") == 0
            ? module.substr(0, module.size() - 4) : module;
        std::string key = normalized + '\x1f' + (entry.name ? entry.name : "");
        require(module_name_keys.insert(std::move(key)).second,
            "api prototype table holds a duplicate (module,name) row");
        require(entry.signature && entry.signature[0] != '\0',
            "api prototype table row has an empty signature");
        require(std::string_view(entry.signature).size() <= 4096,
            "api prototype signature exceeds 4096 bytes");
        if (entry.is_crt) {
            ++crt_count;
            require(crt_names.insert(entry.name).second,
                "api prototype table holds a duplicate CRT name");
        }
    }
    require(crt_count >= 400, "api prototype table must hold at least 400 CRT entries");
}

void verify_differential_lookup()
{
    using namespace api_prototypes;
    constexpr std::size_t count = sizeof(k_entries) / sizeof(k_entries[0]);
    for (std::size_t index = 0; index < count; ++index) {
        const auto& entry = k_entries[index];
        const auto legacy = legacy_find(entry.module, entry.name);
        const auto indexed = find(entry.module, entry.name);
        require(same_result(legacy, indexed), "differential lookup diverged on a table row");
        require(indexed.has_value(), "indexed lookup missed a table row");
    }
    static const char* crt_modules[] = {
        "msvcrt", "ucrtbase", "msvcp140", "vcruntime140",
        "api-ms-win-crt-runtime-l1-1-0", "MSVCRT.DLL", "UCRTBASE.dll", "msvcp140.dll"
    };
    for (const auto& entry : k_entries) {
        if (!entry.is_crt)
            continue;
        for (const char* module : crt_modules) {
            const auto legacy = legacy_find(module, entry.name);
            const auto indexed = find(module, entry.name);
            require(same_result(legacy, indexed), "differential CRT lookup diverged");
            require(indexed.has_value(), "indexed CRT lookup missed a CRT name");
        }
    }
    for (const auto& entry : k_entries) {
        if (entry.is_crt)
            continue;
        const auto legacy = legacy_find("ucrtbase", entry.name);
        const auto indexed = find("ucrtbase", entry.name);
        require(same_result(legacy, indexed), "differential non-CRT lookup diverged");
    }
}

void verify_negative_probes()
{
    using namespace api_prototypes;
    static const char* missing_names[] = {
        "definitely_missing_api_0", "GetLastError2", "mallo", "printfx",
        "not_a_symbol", "_not_crt_", "zzz_missing", "NtQuerySystemInformationEx2"
    };
    static const char* wrong_modules[] = {
        "user32.dll", "comctl32.dll", "ws2_32.dll", "CRYPT32.dll", "missing.dll"
    };
    std::size_t probes = 0;
    for (const char* name : missing_names) {
        for (const char* module : wrong_modules) {
            for (int round = 0; round < 4; ++round) {
                ++probes;
                const auto legacy = legacy_find(module, name);
                const auto indexed = find(module, name);
                require(same_result(legacy, indexed), "negative probe diverged");
                require(!indexed.has_value(), "negative probe produced a false hit");
            }
        }
    }
    for (const auto& entry : k_entries) {
        if (entry.is_crt)
            continue;
        for (const char* module : wrong_modules) {
            const auto legacy = legacy_find(module, entry.name);
            const auto indexed = find(module, entry.name);
            require(same_result(legacy, indexed), "wrong-module probe diverged");
            ++probes;
        }
    }
    std::string long_name(300, 'x');
    const auto long_probe = find("kernel32.dll", long_name);
    require(!long_probe.has_value(), "oversized name probe produced a false hit");
    const auto empty_probe = find("kernel32.dll", "");
    require(!empty_probe.has_value(), "empty name probe produced a false hit");
    const auto empty_module = find("", "malloc");
    require(!empty_module.has_value(), "empty module probe produced a false hit");
    const auto legacy_long = legacy_find("kernel32.dll", long_name);
    const auto indexed_long = find("kernel32.dll", long_name);
    require(same_result(legacy_long, indexed_long), "oversized probe diverged");
    require(probes >= 1000, "negative probe battery must cover at least 1000 probes");
}

}

void run_api_prototype_lookup_harness()
{
    verify_table_invariants();
    verify_differential_lookup();
    verify_negative_probes();
}

}

int main()
{
    try {
        aida::analysis::c03_test::run_api_prototype_lookup_harness();
        std::cout << "api_prototype_lookup_harness source contract satisfied\n";
        return 0;
    } catch (const std::exception& error) {
        aida::analysis::c03_test::assertion_telemetry::record_exception(error.what());
        std::cerr << error.what() << '\n';
        return 1;
    }
}
