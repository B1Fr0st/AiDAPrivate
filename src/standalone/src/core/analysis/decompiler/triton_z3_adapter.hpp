#pragma once

#include "decompiler_contracts.hpp"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace aida::analysis {

enum class triton_z3_adapter_availability_t : std::uint8_t {
    ready = 1,
    local_triton_unavailable = 2,
    local_z3_unavailable = 3,
    local_z3_not_linked = 4
};

enum class triton_z3_semantic_domain_t : std::uint8_t {
    constant = 1,
    condition = 2,
    stack_effect = 3
};

enum class triton_z3_ir_opcode_t : std::uint8_t {
    bitvector_constant = 1,
    symbolic_variable = 2,
    add = 3,
    subtract = 4,
    bitwise_and = 5,
    bitwise_or = 6,
    bitwise_xor = 7,
    shift_left = 8,
    logical_shift_right = 9,
    arithmetic_shift_right = 10,
    equal = 11,
    distinct = 12,
    unsigned_less_than = 13,
    signed_less_than = 14,
    logical_not = 15,
    logical_and = 16,
    multiply = 17
};

enum class triton_z3_proof_status_t : std::uint8_t {
    proved = 1,
    disproved = 2,
    unknown = 3,
    timeout = 4,
    cancelled = 5,
    denied = 6
};

enum class triton_z3_unknown_reason_t : std::uint8_t {
    none = 0,
    solver_unknown = 1,
    unsupported_semantics = 2,
    resource_limit = 3,
    dependency_unavailable = 4
};

struct triton_z3_ir_node_t {
    std::uint32_t id = 0;
    triton_z3_ir_opcode_t opcode = triton_z3_ir_opcode_t::bitvector_constant;
    std::uint32_t bit_width = 0;
    std::uint64_t literal = 0;
    std::string symbol;
    std::uint32_t lhs_id = 0;
    std::uint32_t rhs_id = 0;
};

struct triton_z3_static_ir_t {
    triton_z3_semantic_domain_t domain = triton_z3_semantic_domain_t::constant;
    std::vector<triton_z3_ir_node_t> nodes;
    std::uint32_t root_node_id = 0;
};

struct triton_z3_adapter_capabilities_t {
    triton_z3_adapter_availability_t availability = triton_z3_adapter_availability_t::local_z3_not_linked;
    std::string triton_version;
    std::string z3_version;
    bool local_dependencies_only = true;
    bool static_hir_only = true;
    bool target_execution_supported = false;

    bool valid() const noexcept;
    bool available() const noexcept;
};

struct triton_z3_proof_limits_t {
    std::uint64_t max_wall_clock_ms = 0;
    std::uint64_t max_cpu_ms = 0;
    std::uint64_t max_memory_bytes = 0;
    std::uint32_t max_ir_nodes = 0;
};

struct triton_z3_proof_request_t {
    decompiler_entity_key_t entity;
    source_coordinate_t coordinate;
    std::uint64_t ordinal = 0;
    std::string stable_id;
    triton_z3_static_ir_t static_ir;
    std::string refinement_key;
    triton_z3_proof_limits_t limits;
};

struct triton_z3_proof_response_t {
    triton_z3_proof_status_t status = triton_z3_proof_status_t::denied;
    triton_z3_unknown_reason_t unknown_reason = triton_z3_unknown_reason_t::dependency_unavailable;
    std::string refinement_key;
    std::string diagnostic_key;
    std::uint64_t elapsed_wall_clock_ms = 0;
    std::uint64_t elapsed_cpu_ms = 0;
    std::uint64_t peak_memory_bytes = 0;
};

class triton_z3_adapter_t {
public:
    virtual ~triton_z3_adapter_t() = default;

    virtual triton_z3_adapter_capabilities_t capabilities() const = 0;
    virtual triton_z3_proof_response_t prove(
        const triton_z3_proof_request_t& request,
        const cancellation_token_t& cancel) = 0;
};

bool valid_triton_z3_static_ir(const triton_z3_static_ir_t& value);
bool valid_triton_z3_proof_limits(const triton_z3_proof_limits_t& value) noexcept;
bool valid_triton_z3_proof_request(const triton_z3_proof_request_t& value);
bool valid_triton_z3_proof_response(const triton_z3_proof_response_t& value) noexcept;
std::string triton_z3_adapter_availability_key(triton_z3_adapter_availability_t value);
std::shared_ptr<triton_z3_adapter_t> make_triton_z3_adapter();
std::shared_ptr<triton_z3_adapter_t> make_triton_z3_adapter_denied(
    triton_z3_adapter_availability_t availability = triton_z3_adapter_availability_t::local_z3_not_linked);

}
