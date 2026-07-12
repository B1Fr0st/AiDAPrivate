#include "triton_z3_adapter.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <limits>
#include <mutex>
#include <new>
#include <sstream>
#include <thread>
#include <unordered_set>
#include <utility>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#endif

#if defined(__has_include)
#if __has_include(<triton/context.hpp>) && __has_include(<triton/version.hpp>)
#define AIDA_SEMANTIC_REFINER_HAS_TRITON 1
#endif
#if __has_include(<z3++.h>) && __has_include(<z3.h>)
#define AIDA_SEMANTIC_REFINER_HAS_Z3 1
#endif
#endif

#ifndef AIDA_SEMANTIC_REFINER_HAS_TRITON
#define AIDA_SEMANTIC_REFINER_HAS_TRITON 0
#endif

#ifndef AIDA_SEMANTIC_REFINER_HAS_Z3
#define AIDA_SEMANTIC_REFINER_HAS_Z3 0
#endif

#if AIDA_SEMANTIC_REFINER_HAS_TRITON && AIDA_SEMANTIC_REFINER_HAS_Z3
#include <triton/ast.hpp>
#include <triton/astContext.hpp>
#include <triton/context.hpp>
#include <triton/version.hpp>
#include <triton/x86Specifications.hpp>
#include <z3++.h>
#include <z3.h>
#endif

namespace aida::analysis {
namespace {

constexpr std::size_t k_max_ir_nodes = 4096;
constexpr std::size_t k_max_stable_text = 128;
constexpr std::size_t k_max_diagnostic_key = 192;
constexpr std::size_t k_max_symbol_length = 64;
constexpr std::uint64_t k_megabyte = 1024ULL * 1024ULL;

bool valid_availability(triton_z3_adapter_availability_t value) noexcept
{
    switch (value) {
    case triton_z3_adapter_availability_t::ready:
    case triton_z3_adapter_availability_t::local_triton_unavailable:
    case triton_z3_adapter_availability_t::local_z3_unavailable:
    case triton_z3_adapter_availability_t::local_z3_not_linked:
        return true;
    }
    return false;
}

bool valid_domain(triton_z3_semantic_domain_t value) noexcept
{
    switch (value) {
    case triton_z3_semantic_domain_t::constant:
    case triton_z3_semantic_domain_t::condition:
    case triton_z3_semantic_domain_t::stack_effect:
        return true;
    }
    return false;
}

bool ascii_alpha(char value) noexcept
{
    return (value >= 'A' && value <= 'Z') || (value >= 'a' && value <= 'z');
}

bool ascii_digit(char value) noexcept
{
    return value >= '0' && value <= '9';
}

bool valid_stable_text(const std::string& value, std::size_t maximum) noexcept
{
    if (value.empty() || value.size() > maximum)
        return false;
    return std::all_of(value.begin(), value.end(), [](char character) {
        return character >= 0x21 && character <= 0x7E;
    });
}

bool valid_diagnostic_key(const std::string& value) noexcept
{
    if (value.empty())
        return true;
    if (value.size() > k_max_diagnostic_key)
        return false;
    return std::all_of(value.begin(), value.end(), [](char character) {
        return ascii_alpha(character) || ascii_digit(character) || character == '.' ||
               character == '_' || character == '-';
    });
}

bool valid_symbol(const std::string& value) noexcept
{
    if (value.empty() || value.size() > k_max_symbol_length)
        return false;
    if (!ascii_alpha(value.front()))
        return false;
    for (const char character : value) {
        if (!ascii_alpha(character) && !ascii_digit(character) && character != '_')
            return false;
    }
    return value != "true" && value != "false" && value != "let" && value != "forall" &&
           value != "exists" && value != "assert";
}

bool valid_bit_width(std::uint32_t value) noexcept
{
    return value != 0 && value <= 64;
}

bool literal_fits(std::uint64_t value, std::uint32_t bit_width) noexcept
{
    return bit_width == 64 || value < (1ULL << bit_width);
}

bool binary_bitvector_opcode(triton_z3_ir_opcode_t value) noexcept
{
    switch (value) {
    case triton_z3_ir_opcode_t::add:
    case triton_z3_ir_opcode_t::subtract:
    case triton_z3_ir_opcode_t::bitwise_and:
    case triton_z3_ir_opcode_t::bitwise_or:
    case triton_z3_ir_opcode_t::bitwise_xor:
    case triton_z3_ir_opcode_t::shift_left:
    case triton_z3_ir_opcode_t::logical_shift_right:
    case triton_z3_ir_opcode_t::arithmetic_shift_right:
        return true;
    default:
        return false;
    }
}

bool comparison_opcode(triton_z3_ir_opcode_t value) noexcept
{
    switch (value) {
    case triton_z3_ir_opcode_t::equal:
    case triton_z3_ir_opcode_t::distinct:
    case triton_z3_ir_opcode_t::unsigned_less_than:
    case triton_z3_ir_opcode_t::signed_less_than:
        return true;
    default:
        return false;
    }
}

bool logical_opcode(triton_z3_ir_opcode_t value) noexcept
{
    return value == triton_z3_ir_opcode_t::logical_not ||
           value == triton_z3_ir_opcode_t::logical_and;
}

bool node_references_valid(const triton_z3_ir_node_t& node,
                           const std::vector<triton_z3_ir_node_t>& nodes) noexcept
{
    const auto prior = [&](std::uint32_t id) {
        return id != 0 && id < node.id && id <= nodes.size();
    };
    if (binary_bitvector_opcode(node.opcode)) {
        return prior(node.lhs_id) && prior(node.rhs_id) &&
               nodes[node.lhs_id - 1].bit_width == node.bit_width &&
               nodes[node.rhs_id - 1].bit_width == node.bit_width;
    }
    if (comparison_opcode(node.opcode)) {
        return node.bit_width == 1 && prior(node.lhs_id) && prior(node.rhs_id) &&
               nodes[node.lhs_id - 1].bit_width == nodes[node.rhs_id - 1].bit_width;
    }
    if (node.opcode == triton_z3_ir_opcode_t::logical_not) {
        return node.bit_width == 1 && prior(node.lhs_id) && node.rhs_id == 0 &&
               nodes[node.lhs_id - 1].bit_width == 1;
    }
    if (node.opcode == triton_z3_ir_opcode_t::logical_and) {
        return node.bit_width == 1 && prior(node.lhs_id) && prior(node.rhs_id) &&
               nodes[node.lhs_id - 1].bit_width == 1 && nodes[node.rhs_id - 1].bit_width == 1;
    }
    return false;
}

bool all_nodes_reachable(const triton_z3_static_ir_t& value)
{
    std::vector<bool> reached(value.nodes.size(), false);
    std::vector<std::uint32_t> pending{value.root_node_id};
    while (!pending.empty()) {
        const auto id = pending.back();
        pending.pop_back();
        if (id == 0 || id > value.nodes.size())
            return false;
        if (reached[id - 1])
            continue;
        reached[id - 1] = true;
        const auto& node = value.nodes[id - 1];
        if (node.lhs_id != 0)
            pending.push_back(node.lhs_id);
        if (node.rhs_id != 0)
            pending.push_back(node.rhs_id);
    }
    return std::all_of(reached.begin(), reached.end(), [](bool item) { return item; });
}

class denied_triton_z3_adapter_t final : public triton_z3_adapter_t {
public:
    explicit denied_triton_z3_adapter_t(triton_z3_adapter_availability_t availability)
        : availability_(availability == triton_z3_adapter_availability_t::ready || !valid_availability(availability)
              ? triton_z3_adapter_availability_t::local_z3_not_linked
              : availability) {}

    triton_z3_adapter_capabilities_t capabilities() const override
    {
        triton_z3_adapter_capabilities_t result;
        result.availability = availability_;
        return result;
    }

    triton_z3_proof_response_t prove(
        const triton_z3_proof_request_t&,
        const cancellation_token_t& cancel) override
    {
        triton_z3_proof_response_t result;
        if (cancel.stop_requested()) {
            result.status = triton_z3_proof_status_t::cancelled;
            result.unknown_reason = triton_z3_unknown_reason_t::none;
            result.diagnostic_key = "semantic_refiner.adapter.cancelled";
            return result;
        }
        result.status = triton_z3_proof_status_t::denied;
        result.unknown_reason = triton_z3_unknown_reason_t::dependency_unavailable;
        result.diagnostic_key = "semantic_refiner.adapter." + triton_z3_adapter_availability_key(availability_);
        return result;
    }

private:
    triton_z3_adapter_availability_t availability_;
};

#if AIDA_SEMANTIC_REFINER_HAS_TRITON && AIDA_SEMANTIC_REFINER_HAS_Z3

std::uint64_t elapsed_milliseconds(
    std::chrono::steady_clock::time_point begin,
    std::chrono::steady_clock::time_point end) noexcept
{
    const auto nanoseconds = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin).count();
    if (nanoseconds <= 0)
        return 0;
    constexpr std::int64_t per_millisecond = 1000000;
    return static_cast<std::uint64_t>((nanoseconds + per_millisecond - 1) / per_millisecond);
}

bool current_thread_cpu_milliseconds(std::uint64_t& result) noexcept
{
#if defined(_WIN32)
    FILETIME created{};
    FILETIME exited{};
    FILETIME kernel{};
    FILETIME user{};
    if (GetThreadTimes(GetCurrentThread(), &created, &exited, &kernel, &user) == 0)
        return false;
    ULARGE_INTEGER kernel_ticks{};
    kernel_ticks.LowPart = kernel.dwLowDateTime;
    kernel_ticks.HighPart = kernel.dwHighDateTime;
    ULARGE_INTEGER user_ticks{};
    user_ticks.LowPart = user.dwLowDateTime;
    user_ticks.HighPart = user.dwHighDateTime;
    const auto ticks = kernel_ticks.QuadPart + user_ticks.QuadPart;
    result = ticks == 0 ? 0 : (ticks + 9999ULL) / 10000ULL;
    return true;
#else
    result = 0;
    return false;
#endif
}

struct adapter_measurement_t {
    std::chrono::steady_clock::time_point wall_begin;
    std::uint64_t cpu_begin_ms = 0;
    bool cpu_valid = false;
};

adapter_measurement_t begin_adapter_measurement() noexcept
{
    adapter_measurement_t result;
    result.wall_begin = std::chrono::steady_clock::now();
    result.cpu_valid = current_thread_cpu_milliseconds(result.cpu_begin_ms);
    return result;
}

unsigned bounded_unsigned(std::uint64_t value) noexcept
{
    return value > std::numeric_limits<unsigned>::max()
        ? std::numeric_limits<unsigned>::max()
        : static_cast<unsigned>(value);
}

std::uint64_t peak_solver_memory_bytes(const z3::solver& solver)
{
    const auto statistics = solver.statistics();
    double megabytes = 0.0;
    for (unsigned index = 0; index < statistics.size(); ++index) {
        const auto key = statistics.key(index);
        if (key != "max memory" && key != "memory")
            continue;
        const auto value = statistics.is_uint(index)
            ? static_cast<double>(statistics.uint_value(index))
            : statistics.is_double(index) ? statistics.double_value(index) : 0.0;
        megabytes = std::max(megabytes, value);
    }
    if (megabytes <= 0.0)
        return 0;
    const auto bytes = megabytes * static_cast<double>(k_megabyte);
    if (bytes >= static_cast<double>(std::numeric_limits<std::uint64_t>::max()))
        return std::numeric_limits<std::uint64_t>::max();
    return static_cast<std::uint64_t>(bytes + 0.999999);
}

triton_z3_proof_response_t terminal_response(
    triton_z3_proof_status_t status,
    triton_z3_unknown_reason_t reason,
    std::string diagnostic_key,
    const adapter_measurement_t& measurement,
    std::uint64_t peak_memory_bytes = 0)
{
    triton_z3_proof_response_t result;
    result.status = status;
    result.unknown_reason = reason;
    result.diagnostic_key = std::move(diagnostic_key);
    result.elapsed_wall_clock_ms = elapsed_milliseconds(
        measurement.wall_begin, std::chrono::steady_clock::now());
    std::uint64_t cpu_end_ms = 0;
    result.elapsed_cpu_ms = measurement.cpu_valid && current_thread_cpu_milliseconds(cpu_end_ms) &&
                                    cpu_end_ms >= measurement.cpu_begin_ms
        ? cpu_end_ms - measurement.cpu_begin_ms
        : std::numeric_limits<std::uint64_t>::max();
    result.peak_memory_bytes = peak_memory_bytes;
    return result;
}

class production_triton_z3_adapter_t final : public triton_z3_adapter_t {
public:
    triton_z3_adapter_capabilities_t capabilities() const override
    {
        triton_z3_adapter_capabilities_t result;
        result.availability = triton_z3_adapter_availability_t::ready;
        result.triton_version = std::to_string(triton::MAJOR) + "." +
                                std::to_string(triton::MINOR) + "." +
                                std::to_string(triton::BUILD);
        unsigned major = 0;
        unsigned minor = 0;
        unsigned build = 0;
        unsigned revision = 0;
        Z3_get_version(&major, &minor, &build, &revision);
        result.z3_version = std::to_string(major) + "." + std::to_string(minor) + "." +
                            std::to_string(build) + "." + std::to_string(revision);
        return result;
    }

    triton_z3_proof_response_t prove(
        const triton_z3_proof_request_t& request,
        const cancellation_token_t& cancel) override
    {
        const auto measurement = begin_adapter_measurement();
        if (!valid_triton_z3_proof_request(request))
            return terminal_response(triton_z3_proof_status_t::denied,
                triton_z3_unknown_reason_t::unsupported_semantics,
                "semantic_refiner.adapter.invalid_request", measurement);
        if (cancel.stop_requested())
            return terminal_response(triton_z3_proof_status_t::cancelled,
                triton_z3_unknown_reason_t::none,
                "semantic_refiner.adapter.cancelled", measurement);

        try {
            triton::Context triton_context(triton::arch::ARCH_X86_64);
            const auto ast = triton_context.getAstContext();
            std::vector<triton::ast::SharedAbstractNode> expressions(request.static_ir.nodes.size() + 1);
            std::vector<triton::ast::SharedAbstractNode> variables;
            variables.reserve(request.static_ir.nodes.size());

            for (const auto& node : request.static_ir.nodes) {
                triton::ast::SharedAbstractNode expression;
                switch (node.opcode) {
                case triton_z3_ir_opcode_t::bitvector_constant:
                    expression = ast->bv(node.literal, node.bit_width);
                    break;
                case triton_z3_ir_opcode_t::symbolic_variable: {
                    const auto variable = triton_context.newSymbolicVariable(
                        node.bit_width, "aida_semantic_" + node.symbol);
                    expression = ast->variable(variable);
                    variables.push_back(expression);
                    break;
                }
                case triton_z3_ir_opcode_t::add:
                    expression = ast->bvadd(expressions[node.lhs_id], expressions[node.rhs_id]);
                    break;
                case triton_z3_ir_opcode_t::subtract:
                    expression = ast->bvsub(expressions[node.lhs_id], expressions[node.rhs_id]);
                    break;
                case triton_z3_ir_opcode_t::bitwise_and:
                    expression = ast->bvand(expressions[node.lhs_id], expressions[node.rhs_id]);
                    break;
                case triton_z3_ir_opcode_t::bitwise_or:
                    expression = ast->bvor(expressions[node.lhs_id], expressions[node.rhs_id]);
                    break;
                case triton_z3_ir_opcode_t::bitwise_xor:
                    expression = ast->bvxor(expressions[node.lhs_id], expressions[node.rhs_id]);
                    break;
                case triton_z3_ir_opcode_t::shift_left:
                    expression = ast->bvshl(expressions[node.lhs_id], expressions[node.rhs_id]);
                    break;
                case triton_z3_ir_opcode_t::logical_shift_right:
                    expression = ast->bvlshr(expressions[node.lhs_id], expressions[node.rhs_id]);
                    break;
                case triton_z3_ir_opcode_t::arithmetic_shift_right:
                    expression = ast->bvashr(expressions[node.lhs_id], expressions[node.rhs_id]);
                    break;
                case triton_z3_ir_opcode_t::equal:
                    expression = ast->equal(expressions[node.lhs_id], expressions[node.rhs_id]);
                    break;
                case triton_z3_ir_opcode_t::distinct:
                    expression = ast->distinct(expressions[node.lhs_id], expressions[node.rhs_id]);
                    break;
                case triton_z3_ir_opcode_t::unsigned_less_than:
                    expression = ast->bvult(expressions[node.lhs_id], expressions[node.rhs_id]);
                    break;
                case triton_z3_ir_opcode_t::signed_less_than:
                    expression = ast->bvslt(expressions[node.lhs_id], expressions[node.rhs_id]);
                    break;
                case triton_z3_ir_opcode_t::logical_not:
                    expression = ast->lnot(expressions[node.lhs_id]);
                    break;
                case triton_z3_ir_opcode_t::logical_and:
                    expression = ast->land(expressions[node.lhs_id], expressions[node.rhs_id]);
                    break;
                }
                if (!expression || expression->getBitvectorSize() != node.bit_width)
                    return terminal_response(triton_z3_proof_status_t::unknown,
                        triton_z3_unknown_reason_t::unsupported_semantics,
                        "semantic_refiner.adapter.triton_ir_rejected", measurement);
                expressions[node.id] = std::move(expression);
            }

            std::ostringstream script;
            for (const auto& variable : variables)
                script << ast->declare(variable) << '\n';
            script << ast->assert_(ast->lnot(expressions[request.static_ir.root_node_id])) << '\n';
            const auto smt = script.str();
            if (smt.size() > request.limits.max_memory_bytes)
                return terminal_response(triton_z3_proof_status_t::unknown,
                    triton_z3_unknown_reason_t::resource_limit,
                    "semantic_refiner.adapter.memory_limit", measurement, smt.size());

            z3::context z3_context;
            z3::solver solver(z3_context);
            z3::params parameters(z3_context);
            parameters.set("timeout", bounded_unsigned(request.limits.max_wall_clock_ms));
            const auto memory_megabytes = request.limits.max_memory_bytes / k_megabyte +
                (request.limits.max_memory_bytes % k_megabyte == 0 ? 0 : 1);
            parameters.set("max_memory", bounded_unsigned(memory_megabytes));
            parameters.set("random_seed", 0U);
            solver.set(parameters);
            const auto assertions = z3_context.parse_string(smt.c_str());
            if (assertions.empty())
                return terminal_response(triton_z3_proof_status_t::unknown,
                    triton_z3_unknown_reason_t::unsupported_semantics,
                    "semantic_refiner.adapter.empty_formula", measurement);
            for (unsigned index = 0; index < assertions.size(); ++index)
                solver.add(assertions[index]);

            std::atomic<bool> solver_finished{false};
            std::mutex interrupt_mutex;
            std::condition_variable interrupt_condition;
            std::thread interrupter([&] {
                std::unique_lock<std::mutex> lock(interrupt_mutex);
                while (!solver_finished.load(std::memory_order_acquire)) {
                    if (cancel.stop_requested()) {
                        z3_context.interrupt();
                        return;
                    }
                    auto wake = std::chrono::steady_clock::now() + std::chrono::milliseconds(1);
                    const auto deadline = cancel.deadline();
                    if (deadline && *deadline < wake)
                        wake = *deadline;
                    interrupt_condition.wait_until(lock, wake, [&] {
                        return solver_finished.load(std::memory_order_acquire);
                    });
                }
            });

            z3::check_result checked = z3::unknown;
            try {
                checked = solver.check();
            } catch (...) {
                solver_finished.store(true, std::memory_order_release);
                interrupt_condition.notify_all();
                interrupter.join();
                throw;
            }
            solver_finished.store(true, std::memory_order_release);
            interrupt_condition.notify_all();
            interrupter.join();

            const auto peak_memory = peak_solver_memory_bytes(solver);
            if (cancel.stop_requested())
                return terminal_response(triton_z3_proof_status_t::cancelled,
                    triton_z3_unknown_reason_t::none,
                    "semantic_refiner.adapter.cancelled", measurement, peak_memory);
            if (peak_memory > request.limits.max_memory_bytes)
                return terminal_response(triton_z3_proof_status_t::unknown,
                    triton_z3_unknown_reason_t::resource_limit,
                    "semantic_refiner.adapter.memory_limit", measurement, peak_memory);
            if (checked == z3::unsat) {
                auto result = terminal_response(triton_z3_proof_status_t::proved,
                    triton_z3_unknown_reason_t::none, {}, measurement, peak_memory);
                result.refinement_key = request.refinement_key;
                return result;
            }
            if (checked == z3::sat)
                return terminal_response(triton_z3_proof_status_t::disproved,
                    triton_z3_unknown_reason_t::none, {}, measurement, peak_memory);

            const auto reason = solver.reason_unknown();
            if (reason.find("timeout") != std::string::npos || reason.find("max. memory") != std::string::npos)
                return terminal_response(triton_z3_proof_status_t::timeout,
                    triton_z3_unknown_reason_t::resource_limit,
                    "semantic_refiner.adapter.resource_limit", measurement, peak_memory);
            return terminal_response(triton_z3_proof_status_t::unknown,
                triton_z3_unknown_reason_t::solver_unknown,
                "semantic_refiner.adapter.solver_unknown", measurement, peak_memory);
        } catch (const z3::exception& error) {
            if (cancel.stop_requested())
                return terminal_response(triton_z3_proof_status_t::cancelled,
                    triton_z3_unknown_reason_t::none,
                    "semantic_refiner.adapter.cancelled", measurement);
            const std::string reason = error.msg();
            if (reason.find("max. memory") != std::string::npos ||
                reason.find("timeout") != std::string::npos)
                return terminal_response(triton_z3_proof_status_t::timeout,
                    triton_z3_unknown_reason_t::resource_limit,
                    "semantic_refiner.adapter.resource_limit", measurement,
                    request.limits.max_memory_bytes);
            return terminal_response(triton_z3_proof_status_t::unknown,
                triton_z3_unknown_reason_t::unsupported_semantics,
                "semantic_refiner.adapter.backend_failure", measurement);
        } catch (const std::bad_alloc&) {
            return terminal_response(triton_z3_proof_status_t::unknown,
                triton_z3_unknown_reason_t::resource_limit,
                "semantic_refiner.adapter.memory_limit", measurement,
                request.limits.max_memory_bytes);
        } catch (...) {
            return terminal_response(triton_z3_proof_status_t::unknown,
                triton_z3_unknown_reason_t::unsupported_semantics,
                "semantic_refiner.adapter.backend_failure", measurement);
        }
    }
};

#endif

}

bool triton_z3_adapter_capabilities_t::valid() const noexcept
{
    if (!valid_availability(availability) || !local_dependencies_only || !static_hir_only ||
        target_execution_supported)
        return false;
    if (availability == triton_z3_adapter_availability_t::ready)
        return valid_stable_text(triton_version, k_max_stable_text) &&
               valid_stable_text(z3_version, k_max_stable_text);
    return (triton_version.empty() || valid_stable_text(triton_version, k_max_stable_text)) &&
           (z3_version.empty() || valid_stable_text(z3_version, k_max_stable_text));
}

bool triton_z3_adapter_capabilities_t::available() const noexcept
{
    return valid() && availability == triton_z3_adapter_availability_t::ready;
}

bool valid_triton_z3_static_ir(const triton_z3_static_ir_t& value)
{
    try {
        if (!valid_domain(value.domain) || value.nodes.empty() || value.nodes.size() > k_max_ir_nodes ||
            value.root_node_id != value.nodes.size())
            return false;

        std::unordered_set<std::string> symbols;
        bool has_symbol = false;
        bool has_stack_symbol = false;
        bool has_stack_arithmetic = false;
        for (std::size_t index = 0; index < value.nodes.size(); ++index) {
            const auto& node = value.nodes[index];
            if (node.id != index + 1 || !valid_bit_width(node.bit_width))
                return false;
            if (node.opcode == triton_z3_ir_opcode_t::bitvector_constant) {
                if (!node.symbol.empty() || node.lhs_id != 0 || node.rhs_id != 0 ||
                    !literal_fits(node.literal, node.bit_width))
                    return false;
                continue;
            }
            if (node.opcode == triton_z3_ir_opcode_t::symbolic_variable) {
                if (!valid_symbol(node.symbol) || node.literal != 0 || node.lhs_id != 0 || node.rhs_id != 0 ||
                    !symbols.insert(node.symbol).second)
                    return false;
                has_symbol = true;
                has_stack_symbol = has_stack_symbol || (node.symbol == "sp_entry" && node.bit_width == 64);
                continue;
            }
            if (!node.symbol.empty() || node.literal != 0 ||
                !node_references_valid(node, value.nodes))
                return false;
            has_stack_arithmetic = has_stack_arithmetic || node.opcode == triton_z3_ir_opcode_t::add ||
                                   node.opcode == triton_z3_ir_opcode_t::subtract;
        }

        const auto& root = value.nodes.back();
        if (root.bit_width != 1 || (!comparison_opcode(root.opcode) && !logical_opcode(root.opcode)))
            return false;
        if (value.domain == triton_z3_semantic_domain_t::constant && has_symbol)
            return false;
        if (value.domain == triton_z3_semantic_domain_t::stack_effect &&
            (!has_stack_symbol || !has_stack_arithmetic))
            return false;
        return all_nodes_reachable(value);
    } catch (...) {
        return false;
    }
}

bool valid_triton_z3_proof_limits(const triton_z3_proof_limits_t& value) noexcept
{
    return value.max_wall_clock_ms != 0 && value.max_cpu_ms != 0 &&
           value.max_memory_bytes != 0 && value.max_ir_nodes != 0 &&
           value.max_ir_nodes <= k_max_ir_nodes;
}

bool valid_triton_z3_proof_request(const triton_z3_proof_request_t& value)
{
    return value.ordinal != 0 && valid_stable_text(value.stable_id, k_max_stable_text) &&
           valid_stable_text(value.refinement_key, k_max_stable_text) &&
           valid_triton_z3_static_ir(value.static_ir) &&
           value.static_ir.nodes.size() <= value.limits.max_ir_nodes &&
           valid_triton_z3_proof_limits(value.limits) && validate_decompiler_entity_key(value.entity).valid() &&
           validate_source_coordinate(value.coordinate).valid() &&
           value.coordinate.layer == decompiler_coordinate_layer_t::hir && value.coordinate.entity == value.entity;
}

bool valid_triton_z3_proof_response(const triton_z3_proof_response_t& value) noexcept
{
    if ((!value.refinement_key.empty() && !valid_stable_text(value.refinement_key, k_max_stable_text)) ||
        !valid_diagnostic_key(value.diagnostic_key))
        return false;
    switch (value.status) {
    case triton_z3_proof_status_t::proved:
        return value.unknown_reason == triton_z3_unknown_reason_t::none &&
               !value.refinement_key.empty() && value.diagnostic_key.empty();
    case triton_z3_proof_status_t::disproved:
        return value.unknown_reason == triton_z3_unknown_reason_t::none &&
               value.refinement_key.empty() && value.diagnostic_key.empty();
    case triton_z3_proof_status_t::unknown:
        return value.unknown_reason != triton_z3_unknown_reason_t::none && value.refinement_key.empty();
    case triton_z3_proof_status_t::timeout:
        return value.unknown_reason == triton_z3_unknown_reason_t::resource_limit && value.refinement_key.empty();
    case triton_z3_proof_status_t::cancelled:
        return value.unknown_reason == triton_z3_unknown_reason_t::none && value.refinement_key.empty();
    case triton_z3_proof_status_t::denied:
        return value.unknown_reason != triton_z3_unknown_reason_t::none && value.refinement_key.empty();
    }
    return false;
}

std::string triton_z3_adapter_availability_key(triton_z3_adapter_availability_t value)
{
    switch (value) {
    case triton_z3_adapter_availability_t::ready:
        return "ready";
    case triton_z3_adapter_availability_t::local_triton_unavailable:
        return "local_triton_unavailable";
    case triton_z3_adapter_availability_t::local_z3_unavailable:
        return "local_z3_unavailable";
    case triton_z3_adapter_availability_t::local_z3_not_linked:
        return "local_z3_not_linked";
    }
    return "invalid";
}

std::shared_ptr<triton_z3_adapter_t> make_triton_z3_adapter()
{
#if !AIDA_SEMANTIC_REFINER_HAS_TRITON
    return make_triton_z3_adapter_denied(triton_z3_adapter_availability_t::local_triton_unavailable);
#elif !AIDA_SEMANTIC_REFINER_HAS_Z3
    return make_triton_z3_adapter_denied(triton_z3_adapter_availability_t::local_z3_unavailable);
#else
    return std::make_shared<production_triton_z3_adapter_t>();
#endif
}

std::shared_ptr<triton_z3_adapter_t> make_triton_z3_adapter_denied(
    triton_z3_adapter_availability_t availability)
{
    return std::make_shared<denied_triton_z3_adapter_t>(availability);
}

}
