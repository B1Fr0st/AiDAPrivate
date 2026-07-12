#include "semantic_refiner_harness.hpp"

#include "../../src/core/analysis/decompiler/semantic_refiner.hpp"

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <memory>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace aida::analysis::c03_test {
namespace {

void require(bool condition, const char* message)
{
    if (!condition)
        throw std::runtime_error(message);
}

sha256_digest_t digest(const std::string& value)
{
    return stable_serialization_hash(value);
}

address_t address(std::uint64_t value)
{
    address_t result;
    result.space = address_space_id_t::relative_virtual;
    result.value = value;
    result.architecture = architecture_id_t::x86_64;
    result.mode = architecture_mode_t::x86_64;
    return result;
}

decompiler_entity_key_t entity()
{
    native_decompiler_entity_identity_t identity;
    identity.function_id = 77;
    identity.entry = address(0x1400);
    identity.end = address(0x1420);
    identity.function_bytes_hash = digest("semantic-refiner-function");
    identity.canonical_symbol = "fixture::semantic_refiner";
    decompiler_entity_key_t result;
    result.kind = decompiler_entity_kind_t::native_function;
    result.format = format_id_t::pe32_plus;
    result.architecture = architecture_id_t::x86_64;
    result.mode = architecture_mode_t::x86_64;
    result.identity = std::move(identity);
    return result;
}

source_coordinate_t coordinate(const decompiler_entity_key_t& value)
{
    source_coordinate_t result;
    result.layer = decompiler_coordinate_layer_t::hir;
    result.workspace_generation = 9;
    result.entity = value;
    result.address_range = decompiler_address_range_t{address(0x1400), address(0x1404)};
    result.instruction_range = decompiler_instruction_range_t{401, 402};
    return result;
}

hir_function_t function(const decompiler_entity_key_t& value)
{
    hir_value_t return_value;
    return_value.id = 1;
    return_value.kind = hir_node_kind_t::return_value;
    return_value.type_id = 1;
    return_value.stable_value = "0";
    return_value.coordinate = coordinate(value);
    return_value.confidence = 100;
    return_value.provenance = decompiler_fact_provenance_t::provider_semantics;

    hir_block_t block;
    block.id = 1;
    block.coordinate = coordinate(value);
    block.values.push_back(std::move(return_value));

    decompiler_unknown_t preserved_unknown;
    preserved_unknown.reason = decompiler_unknown_reason_t::unresolved_reference;
    preserved_unknown.stable_token = "preserved_hir_unknown";
    preserved_unknown.coordinate = coordinate(value);
    preserved_unknown.confidence = 25;
    preserved_unknown.provenance = decompiler_fact_provenance_t::provider_semantics;

    hir_function_t result;
    result.entity = value;
    result.provider_ir_hash = digest("semantic-refiner-provider-ir");
    result.type_graph_revision = 3;
    result.return_type_id = 1;
    result.blocks.push_back(std::move(block));
    result.unknowns.push_back(std::move(preserved_unknown));
    return result;
}

decompiler_profile_budget_t profile(decompiler_profile_id_t id)
{
    decompiler_profile_budget_t result;
    result.profile = id;
    result.max_wall_clock_ms = 500;
    result.max_cpu_ms = 250;
    result.max_memory_bytes = 512ULL << 20;
    result.max_provider_ir_nodes = 128;
    result.max_hir_nodes = 128;
    result.max_ast_nodes = 128;
    if (id == decompiler_profile_id_t::thorough) {
        result.max_semantic_queries = 2;
        result.semantic_proofs_enabled = true;
    }
    return result;
}

triton_z3_ir_node_t ir_node(
    std::uint32_t id,
    triton_z3_ir_opcode_t opcode,
    std::uint32_t bit_width,
    std::uint64_t literal = 0,
    std::string symbol = {},
    std::uint32_t lhs_id = 0,
    std::uint32_t rhs_id = 0)
{
    triton_z3_ir_node_t result;
    result.id = id;
    result.opcode = opcode;
    result.bit_width = bit_width;
    result.literal = literal;
    result.symbol = std::move(symbol);
    result.lhs_id = lhs_id;
    result.rhs_id = rhs_id;
    return result;
}

triton_z3_static_ir_t constant_ir(std::uint64_t base)
{
    triton_z3_static_ir_t result;
    result.domain = triton_z3_semantic_domain_t::constant;
    result.nodes.push_back(ir_node(1, triton_z3_ir_opcode_t::bitvector_constant, 64, base));
    result.nodes.push_back(ir_node(2, triton_z3_ir_opcode_t::bitvector_constant, 64, 1));
    result.nodes.push_back(ir_node(3, triton_z3_ir_opcode_t::add, 64, 0, {}, 1, 2));
    result.nodes.push_back(ir_node(4, triton_z3_ir_opcode_t::bitvector_constant, 64, base + 1));
    result.nodes.push_back(ir_node(5, triton_z3_ir_opcode_t::equal, 1, 0, {}, 3, 4));
    result.root_node_id = 5;
    return result;
}

triton_z3_static_ir_t condition_ir()
{
    triton_z3_static_ir_t result;
    result.domain = triton_z3_semantic_domain_t::condition;
    result.nodes.push_back(ir_node(1, triton_z3_ir_opcode_t::symbolic_variable, 32, 0, "condition_value"));
    result.nodes.push_back(ir_node(2, triton_z3_ir_opcode_t::unsigned_less_than, 1, 0, {}, 1, 1));
    result.nodes.push_back(ir_node(3, triton_z3_ir_opcode_t::logical_not, 1, 0, {}, 2));
    result.root_node_id = 3;
    return result;
}

triton_z3_static_ir_t stack_effect_ir()
{
    triton_z3_static_ir_t result;
    result.domain = triton_z3_semantic_domain_t::stack_effect;
    result.nodes.push_back(ir_node(1, triton_z3_ir_opcode_t::symbolic_variable, 64, 0, "sp_entry"));
    result.nodes.push_back(ir_node(2, triton_z3_ir_opcode_t::bitvector_constant, 64, 0x28));
    result.nodes.push_back(ir_node(3, triton_z3_ir_opcode_t::subtract, 64, 0, {}, 1, 2));
    result.nodes.push_back(ir_node(4, triton_z3_ir_opcode_t::bitvector_constant, 64, 0xFFFFFFFFFFFFFFD8ULL));
    result.nodes.push_back(ir_node(5, triton_z3_ir_opcode_t::add, 64, 0, {}, 1, 4));
    result.nodes.push_back(ir_node(6, triton_z3_ir_opcode_t::equal, 1, 0, {}, 3, 5));
    result.root_node_id = 6;
    return result;
}

semantic_refinement_query_t query(
    const decompiler_entity_key_t& value,
    std::uint64_t ordinal,
    triton_z3_static_ir_t static_ir)
{
    semantic_refinement_query_t result;
    result.ordinal = ordinal;
    result.stable_id = "proof." + std::to_string(ordinal);
    result.coordinate = coordinate(value);
    result.static_ir = std::move(static_ir);
    result.refinement_key = "refinement." + std::to_string(ordinal);
    return result;
}

semantic_refinement_request_t request(
    std::size_t query_count,
    decompiler_profile_id_t id = decompiler_profile_id_t::thorough)
{
    semantic_refinement_request_t result;
    result.profile = profile(id);
    result.function = function(entity());
    for (std::size_t index = 0; index < query_count; ++index)
        result.queries.push_back(query(result.function.entity, index + 1, constant_ir(index + 1)));
    return result;
}

triton_z3_proof_response_t response(
    triton_z3_proof_status_t status,
    const semantic_refinement_query_t& query_value,
    triton_z3_unknown_reason_t unknown_reason = triton_z3_unknown_reason_t::none)
{
    triton_z3_proof_response_t result;
    result.status = status;
    switch (status) {
    case triton_z3_proof_status_t::proved:
    case triton_z3_proof_status_t::disproved:
    case triton_z3_proof_status_t::cancelled:
        result.unknown_reason = triton_z3_unknown_reason_t::none;
        break;
    case triton_z3_proof_status_t::unknown:
        result.unknown_reason = unknown_reason == triton_z3_unknown_reason_t::none
            ? triton_z3_unknown_reason_t::solver_unknown
            : unknown_reason;
        break;
    case triton_z3_proof_status_t::timeout:
        result.unknown_reason = triton_z3_unknown_reason_t::resource_limit;
        break;
    case triton_z3_proof_status_t::denied:
        result.unknown_reason = triton_z3_unknown_reason_t::dependency_unavailable;
        break;
    }
    result.refinement_key = status == triton_z3_proof_status_t::proved ? query_value.refinement_key : "";
    result.peak_memory_bytes = 1024;
    return result;
}

triton_z3_adapter_capabilities_t ready_capabilities(bool target_execution_supported = false)
{
    triton_z3_adapter_capabilities_t result;
    result.availability = triton_z3_adapter_availability_t::ready;
    result.triton_version = "local-fixture";
    result.z3_version = "local-fixture";
    result.target_execution_supported = target_execution_supported;
    return result;
}

class fake_budget_adapter_t final : public triton_z3_adapter_t {
public:
    explicit fake_budget_adapter_t(
        std::vector<triton_z3_proof_response_t> script,
        bool target_execution_supported = false)
        : script_(std::move(script)), target_execution_supported_(target_execution_supported) {}

    triton_z3_adapter_capabilities_t capabilities() const override
    {
        return ready_capabilities(target_execution_supported_);
    }

    triton_z3_proof_response_t prove(
        const triton_z3_proof_request_t& proof_request,
        const cancellation_token_t& cancel) override
    {
        invocations.fetch_add(1, std::memory_order_relaxed);
        {
            std::lock_guard<std::mutex> lock(requests_mutex_);
            requests_.push_back(proof_request);
        }
        if (cancel.stop_requested()) {
            triton_z3_proof_response_t cancelled;
            cancelled.status = triton_z3_proof_status_t::cancelled;
            cancelled.unknown_reason = triton_z3_unknown_reason_t::none;
            return cancelled;
        }
        if (next_ >= script_.size())
            throw std::runtime_error("fake proof budget exceeded");
        return script_[next_++];
    }

    triton_z3_proof_request_t request_at(std::size_t index) const
    {
        std::lock_guard<std::mutex> lock(requests_mutex_);
        if (index >= requests_.size())
            throw std::runtime_error("missing fake adapter request");
        return requests_[index];
    }

    std::atomic<std::uint32_t> invocations{0};

private:
    std::vector<triton_z3_proof_response_t> script_;
    bool target_execution_supported_ = false;
    std::size_t next_ = 0;
    mutable std::mutex requests_mutex_;
    std::vector<triton_z3_proof_request_t> requests_;
};

class cooperative_wait_adapter_t final : public triton_z3_adapter_t {
public:
    triton_z3_adapter_capabilities_t capabilities() const override
    {
        return ready_capabilities();
    }

    triton_z3_proof_response_t prove(
        const triton_z3_proof_request_t&,
        const cancellation_token_t& cancel) override
    {
        entered.store(true, std::memory_order_release);
        while (!cancel.stop_requested())
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        observed_stop.store(true, std::memory_order_release);
        triton_z3_proof_response_t result;
        result.status = triton_z3_proof_status_t::cancelled;
        result.unknown_reason = triton_z3_unknown_reason_t::none;
        return result;
    }

    std::atomic<bool> entered{false};
    std::atomic<bool> observed_stop{false};
};

class sleeping_timing_liar_adapter_t final : public triton_z3_adapter_t {
public:
    triton_z3_adapter_capabilities_t capabilities() const override
    {
        return ready_capabilities();
    }

    triton_z3_proof_response_t prove(
        const triton_z3_proof_request_t& request_value,
        const cancellation_token_t&) override
    {
        entered.store(true, std::memory_order_release);
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        finished.store(true, std::memory_order_release);
        triton_z3_proof_response_t result;
        result.status = triton_z3_proof_status_t::proved;
        result.unknown_reason = triton_z3_unknown_reason_t::none;
        result.refinement_key = request_value.refinement_key;
        result.elapsed_wall_clock_ms = 0;
        result.elapsed_cpu_ms = 0;
        return result;
    }

    std::atomic<bool> entered{false};
    std::atomic<bool> finished{false};
};

class cpu_timing_liar_adapter_t final : public triton_z3_adapter_t {
public:
    triton_z3_adapter_capabilities_t capabilities() const override
    {
        return ready_capabilities();
    }

    triton_z3_proof_response_t prove(
        const triton_z3_proof_request_t&,
        const cancellation_token_t& cancel) override
    {
        while (!cancel.stop_requested())
            accumulator_.fetch_add(1, std::memory_order_relaxed);
        triton_z3_proof_response_t result;
        result.status = triton_z3_proof_status_t::cancelled;
        result.unknown_reason = triton_z3_unknown_reason_t::none;
        result.elapsed_cpu_ms = 0;
        return result;
    }

private:
    std::atomic<std::uint64_t> accumulator_{0};
};

bool contains_unknown(const std::vector<decompiler_unknown_t>& unknowns, const std::string& token)
{
    for (const auto& unknown : unknowns)
        if (unknown.stable_token == token)
            return true;
    return false;
}

bool contains_diagnostic(const std::vector<decompiler_diagnostic_t>& diagnostics, const std::string& key)
{
    for (const auto& diagnostic : diagnostics)
        if (diagnostic.localization_key == key)
            return true;
    return false;
}

bool wait_until_true(const std::atomic<bool>& value, std::chrono::milliseconds timeout)
{
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (!value.load(std::memory_order_acquire) && std::chrono::steady_clock::now() < deadline)
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    return value.load(std::memory_order_acquire);
}

std::string stable_result_signature(const semantic_refinement_result_t& result)
{
    std::ostringstream stream;
    stream << static_cast<unsigned>(result.status) << '|' << result.adapter_invocations;
    for (const auto& fact : result.facts)
        stream << "|f:" << fact.ordinal << ':' << fact.stable_id << ':' << fact.refinement_key << ':'
               << static_cast<unsigned>(fact.confidence) << ':' << static_cast<unsigned>(fact.provenance);
    for (const auto& unknown : result.unknowns)
        stream << "|u:" << static_cast<unsigned>(unknown.reason) << ':' << unknown.stable_token << ':'
               << static_cast<unsigned>(unknown.provenance);
    for (const auto& diagnostic : result.diagnostics)
        stream << "|d:" << diagnostic.ordinal << ':' << static_cast<unsigned>(diagnostic.code) << ':'
               << diagnostic.localization_key;
    return stream.str();
}

void verify_thorough_only_no_baseline_invocation()
{
    const auto fast_request = request(1, decompiler_profile_id_t::fast);
    const auto balanced_request = request(1, decompiler_profile_id_t::balanced);
    auto adapter = std::make_shared<fake_budget_adapter_t>(std::vector<triton_z3_proof_response_t>{
        response(triton_z3_proof_status_t::proved, fast_request.queries.front())});
    semantic_refiner_t refiner(adapter);

    const auto fast = refiner.refine(fast_request);
    const auto balanced = refiner.refine(balanced_request);
    require(fast.status == semantic_refinement_status_t::profile_rejected, "fast profile invoked semantic refinement");
    require(balanced.status == semantic_refinement_status_t::profile_rejected, "balanced profile invoked semantic refinement");
    require(adapter->invocations.load(std::memory_order_relaxed) == 0, "baseline profile reached Triton/Z3 adapter");
    require(fast.facts.empty() && balanced.facts.empty(), "baseline profile produced semantic facts");
    require(contains_unknown(fast.unknowns, "preserved_hir_unknown"), "fast profile lost existing unknown");
    require(contains_unknown(balanced.unknowns, "preserved_hir_unknown"), "balanced profile lost existing unknown");
}

void verify_proved_static_refinement()
{
    const auto value = request(1);
    auto adapter = std::make_shared<fake_budget_adapter_t>(std::vector<triton_z3_proof_response_t>{
        response(triton_z3_proof_status_t::proved, value.queries.front())});
    semantic_refiner_t refiner(adapter);
    const auto result = refiner.refine(value);

    require(result.status == semantic_refinement_status_t::completed, "thorough proof did not complete");
    require(result.adapter_invocations == 1 && adapter->invocations.load(std::memory_order_relaxed) == 1,
        "thorough proof did not use exactly one adapter query");
    require(result.facts.size() == 1, "proved static query did not create one semantic fact");
    require(result.facts.front().provenance == decompiler_fact_provenance_t::semantic_proof,
        "proved static query lost semantic-proof provenance");
    const auto proof_request = adapter->request_at(0);
    require(proof_request.entity == value.function.entity, "adapter request escaped the function boundary");
    require(proof_request.static_ir.domain == triton_z3_semantic_domain_t::constant,
        "adapter request did not preserve structured static Triton IR");
    require(contains_unknown(result.unknowns, "preserved_hir_unknown"), "semantic refinement lost HIR unknown");
}

void verify_query_budget()
{
    const auto value = request(3);
    std::vector<triton_z3_proof_response_t> script;
    script.push_back(response(triton_z3_proof_status_t::proved, value.queries[0]));
    script.push_back(response(triton_z3_proof_status_t::proved, value.queries[1]));
    auto adapter = std::make_shared<fake_budget_adapter_t>(script);
    semantic_refiner_t refiner(adapter);
    const auto result = refiner.refine(value);

    require(result.status == semantic_refinement_status_t::completed_with_unknowns,
        "query budget exhaustion was not preserved as unknown");
    require(result.adapter_invocations == 2 && adapter->invocations.load(std::memory_order_relaxed) == 2,
        "semantic query count limit was not enforced");
    require(result.facts.size() == 2, "query budget changed proved-query count");
    require(contains_unknown(result.unknowns, "semantic_budget_exhausted:proof.3"),
        "query budget did not retain exhausted query as unknown");
}

void verify_timeout_and_unknown_preservation()
{
    const auto value = request(2);
    std::vector<triton_z3_proof_response_t> script;
    script.push_back(response(triton_z3_proof_status_t::timeout, value.queries[0]));
    script.push_back(response(triton_z3_proof_status_t::unknown, value.queries[1],
        triton_z3_unknown_reason_t::unsupported_semantics));
    auto adapter = std::make_shared<fake_budget_adapter_t>(script);
    semantic_refiner_t refiner(adapter);
    const auto result = refiner.refine(value);

    require(result.status == semantic_refinement_status_t::completed_with_unknowns,
        "timeout or unknown was promoted to a proof");
    require(result.facts.empty(), "timeout or unknown produced semantic facts");
    require(contains_unknown(result.unknowns, "preserved_hir_unknown"), "timeout path lost original unknown");
    require(contains_unknown(result.unknowns, "semantic_timeout:proof.1"), "timeout was not preserved");
    require(contains_unknown(result.unknowns, "semantic_unknown:proof.2"), "solver unknown was not preserved");
    require(contains_diagnostic(result.diagnostics, "semantic_refiner.adapter.timeout"), "timeout diagnostic missing");
}

void verify_pre_cancellation()
{
    const auto value = request(2);
    auto adapter = std::make_shared<fake_budget_adapter_t>(std::vector<triton_z3_proof_response_t>{
        response(triton_z3_proof_status_t::proved, value.queries[0])});
    semantic_refiner_t refiner(adapter);
    cancellation_source_t source;
    source.request_cancel();
    const auto result = refiner.refine(value, source.token());

    require(result.status == semantic_refinement_status_t::cancelled, "pre-cancelled semantic work completed");
    require(adapter->invocations.load(std::memory_order_relaxed) == 0 && result.adapter_invocations == 0,
        "pre-cancelled semantic work invoked the adapter");
    require(contains_unknown(result.unknowns, "semantic_cancelled:proof.1"), "cancelled first query was lost");
    require(contains_unknown(result.unknowns, "semantic_cancelled:proof.2"), "cancelled pending query was lost");
}

void verify_mid_call_cancellation_and_deadline()
{
    const auto value = request(1);
    auto cancellation_adapter = std::make_shared<cooperative_wait_adapter_t>();
    semantic_refiner_t cancellation_refiner(cancellation_adapter);
    cancellation_source_t cancellation;
    std::thread canceller([&] {
        wait_until_true(cancellation_adapter->entered, std::chrono::milliseconds(200));
        cancellation.request_cancel();
    });
    const auto cancelled = cancellation_refiner.refine(value, cancellation.token());
    canceller.join();
    require(cancelled.status == semantic_refinement_status_t::cancelled,
        "mid-call cancellation completed semantic work");
    require(cancellation_adapter->observed_stop.load(std::memory_order_acquire),
        "mid-call cancellation did not reach the adapter token");
    require(contains_diagnostic(cancelled.diagnostics, "semantic_refiner.cancelled"),
        "mid-call cancellation diagnostic missing");

    auto deadline_adapter = std::make_shared<cooperative_wait_adapter_t>();
    semantic_refiner_t deadline_refiner(deadline_adapter);
    cancellation_source_t deadline_source(
        std::chrono::steady_clock::now() + std::chrono::milliseconds(15));
    const auto deadline = deadline_refiner.refine(value, deadline_source.token());
    require(deadline.status == semantic_refinement_status_t::cancelled,
        "caller deadline completed semantic work");
    require(deadline_adapter->observed_stop.load(std::memory_order_acquire),
        "caller deadline did not reach the adapter token");
    require(contains_diagnostic(deadline.diagnostics, "semantic_refiner.cancelled.deadline"),
        "caller deadline diagnostic missing");
}

void verify_adapter_denial()
{
    const auto value = request(1);
    semantic_refiner_t refiner(make_triton_z3_adapter_denied(
        triton_z3_adapter_availability_t::local_z3_not_linked));
    const auto result = refiner.refine(value);

    require(result.status == semantic_refinement_status_t::adapter_denied,
        "unlinked local Z3 did not deny semantic refinement");
    require(result.adapter_invocations == 0, "denied adapter was invoked");
    require(result.facts.empty(), "denied adapter produced semantic facts");
    require(contains_unknown(result.unknowns, "semantic_adapter_denied:proof.1"),
        "denied adapter did not preserve query as unknown");
    require(contains_diagnostic(result.diagnostics, "semantic_refiner.adapter.local_z3_not_linked"),
        "denied adapter did not emit explicit diagnostic");
}

void verify_target_execution_denial()
{
    const auto value = request(1);
    auto adapter = std::make_shared<fake_budget_adapter_t>(
        std::vector<triton_z3_proof_response_t>{response(triton_z3_proof_status_t::proved, value.queries[0])},
        true);
    semantic_refiner_t refiner(adapter);
    const auto result = refiner.refine(value);

    require(result.status == semantic_refinement_status_t::adapter_denied,
        "target-executing adapter was accepted");
    require(result.adapter_invocations == 0 && adapter->invocations.load(std::memory_order_relaxed) == 0,
        "target-executing adapter reached prove");
    require(contains_diagnostic(result.diagnostics, "semantic_refiner.adapter.target_execution_forbidden"),
        "target-execution denial diagnostic missing");
}

void verify_claimed_response_limits()
{
    auto timing_request = request(2);
    auto timing_response = response(triton_z3_proof_status_t::proved, timing_request.queries[0]);
    timing_response.elapsed_wall_clock_ms = timing_request.profile.max_wall_clock_ms + 1;
    auto timing_adapter = std::make_shared<fake_budget_adapter_t>(
        std::vector<triton_z3_proof_response_t>{timing_response});
    semantic_refiner_t timing_refiner(timing_adapter);
    const auto timing_result = timing_refiner.refine(timing_request);
    require(timing_result.adapter_invocations == 1, "claimed timing overrun invoked a pending query");
    require(contains_diagnostic(timing_result.diagnostics, "semantic_refiner.adapter.reported_limit_exceeded"),
        "claimed timing overrun was accepted");
    require(contains_unknown(timing_result.unknowns, "semantic_budget_exhausted:proof.2"),
        "claimed timing overrun lost pending work");

    auto memory_request = request(1);
    auto memory_response = response(triton_z3_proof_status_t::proved, memory_request.queries[0]);
    memory_response.peak_memory_bytes = memory_request.profile.max_memory_bytes + 1;
    auto memory_adapter = std::make_shared<fake_budget_adapter_t>(
        std::vector<triton_z3_proof_response_t>{memory_response});
    semantic_refiner_t memory_refiner(memory_adapter);
    const auto memory_result = memory_refiner.refine(memory_request);
    require(memory_result.facts.empty(), "claimed memory overrun produced a proof");
    require(contains_unknown(memory_result.unknowns, "semantic_memory_limit:proof.1"),
        "claimed memory overrun was not preserved");
    require(contains_diagnostic(memory_result.diagnostics, "semantic_refiner.adapter.reported_limit_exceeded"),
        "claimed memory overrun diagnostic missing");
}

void verify_host_timing_authority()
{
    auto wall_request = request(1);
    wall_request.profile.max_wall_clock_ms = 10;
    wall_request.profile.max_cpu_ms = 200;
    auto wall_adapter = std::make_shared<sleeping_timing_liar_adapter_t>();
    semantic_refiner_t wall_refiner(wall_adapter);
    const auto begin = std::chrono::steady_clock::now();
    const auto wall_result = wall_refiner.refine(wall_request);
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - begin);
    require(wall_result.status == semantic_refinement_status_t::completed_with_unknowns,
        "host wall deadline accepted a timing lie");
    require(wall_result.facts.empty(), "host wall deadline accepted a late proof");
    require(contains_diagnostic(wall_result.diagnostics, "semantic_refiner.worker.deadline"),
        "host wall deadline diagnostic missing");
    require(elapsed < std::chrono::milliseconds(200), "uncooperative proof blocked the bounded worker");
    require(wait_until_true(wall_adapter->finished, std::chrono::milliseconds(500)),
        "detached timing fixture did not terminate");

    auto cpu_request = request(1);
    cpu_request.profile.max_wall_clock_ms = 500;
    cpu_request.profile.max_cpu_ms = 3;
    auto cpu_adapter = std::make_shared<cpu_timing_liar_adapter_t>();
    semantic_refiner_t cpu_refiner(cpu_adapter);
    const auto cpu_result = cpu_refiner.refine(cpu_request);
    require(cpu_result.status == semantic_refinement_status_t::completed_with_unknowns,
        "host CPU limit accepted a timing lie");
    require(cpu_result.facts.empty(), "host CPU limit accepted a proof");
    require(contains_diagnostic(cpu_result.diagnostics, "semantic_refiner.worker.cpu_limit"),
        "host CPU limit diagnostic missing");
}

void verify_repeated_run_determinism()
{
    const auto value = request(2);
    std::string expected;
    for (std::uint32_t run = 0; run < 5; ++run) {
        std::vector<triton_z3_proof_response_t> script;
        script.push_back(response(triton_z3_proof_status_t::proved, value.queries[0]));
        script.push_back(response(triton_z3_proof_status_t::unknown, value.queries[1],
            triton_z3_unknown_reason_t::unsupported_semantics));
        auto adapter = std::make_shared<fake_budget_adapter_t>(std::move(script));
        semantic_refiner_t refiner(adapter);
        const auto signature = stable_result_signature(refiner.refine(value));
        if (run == 0)
            expected = signature;
        else
            require(signature == expected, "semantic refinement output changed across repeated runs");
    }
}

void verify_production_semantic_fixtures()
{
    const auto adapter = make_triton_z3_adapter();
    const auto capabilities = adapter->capabilities();
    require(capabilities.valid() && capabilities.available(),
        "local Triton/Z3 production adapter is unavailable");
    require(!capabilities.target_execution_supported && capabilities.local_dependencies_only &&
            capabilities.static_hir_only,
        "production adapter capability contract permits target execution");

    std::vector<triton_z3_static_ir_t> fixtures;
    fixtures.push_back(constant_ir(41));
    fixtures.push_back(condition_ir());
    fixtures.push_back(stack_effect_ir());
    semantic_refiner_t refiner(adapter);
    for (std::size_t index = 0; index < fixtures.size(); ++index) {
        auto value = request(1);
        value.profile.max_wall_clock_ms = 2000;
        value.profile.max_cpu_ms = 1000;
        value.profile.max_semantic_queries = 1;
        value.queries[0].static_ir = std::move(fixtures[index]);
        value.queries[0].refinement_key = "production." + std::to_string(index + 1);
        const auto result = refiner.refine(value);
        require(result.status == semantic_refinement_status_t::completed,
            "production semantic fixture did not complete");
        require(result.adapter_invocations == 1 && result.facts.size() == 1,
            "production semantic fixture did not produce exactly one proof");
        require(result.facts.front().refinement_key == value.queries[0].refinement_key,
            "production semantic fixture returned the wrong refinement key");
    }
}

}

void run_semantic_refiner_harness()
{
    verify_thorough_only_no_baseline_invocation();
    verify_proved_static_refinement();
    verify_query_budget();
    verify_timeout_and_unknown_preservation();
    verify_pre_cancellation();
    verify_mid_call_cancellation_and_deadline();
    verify_adapter_denial();
    verify_target_execution_denial();
    verify_claimed_response_limits();
    verify_host_timing_authority();
    verify_repeated_run_determinism();
    verify_production_semantic_fixtures();
}

}

int main()
{
    try {
        aida::analysis::c03_test::run_semantic_refiner_harness();
        std::cout << "semantic_refiner_harness source contract satisfied\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
