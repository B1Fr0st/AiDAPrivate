#pragma once

#include "packed_string_pool.hpp"
#include "workspace/compact_ir.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string_view>
#include <vector>

namespace aida::analysis {

enum class packed_entity_domain_t : std::uint16_t {
    invalid = 0,
    instruction = 1,
    operand = 2,
    edge = 3,
    string = 4,
    symbol = 5,
    address_expression = 6,
    basic_block = 7,
    function = 8,
    function_chunk = 9,
    target_fact = 10,
    xref = 11,
    coverage = 12
};

struct packed_entity_id_parts_t final {
    packed_entity_domain_t domain = packed_entity_domain_t::invalid;
    std::uint16_t shard = 0;
    std::uint32_t ordinal = 0;

    constexpr bool operator==(const packed_entity_id_parts_t& other) const noexcept {
        return domain == other.domain && shard == other.shard && ordinal == other.ordinal;
    }

    constexpr bool operator!=(const packed_entity_id_parts_t& other) const noexcept {
        return !(*this == other);
    }
};

class packed_entity_id_t final {
public:
    constexpr packed_entity_id_t() noexcept = default;

    static packed_store_result_t<packed_entity_id_t>
        make(packed_entity_domain_t domain, std::uint16_t shard, std::uint64_t ordinal) noexcept;

    constexpr std::uint64_t value() const noexcept { return value_; }
    constexpr bool valid() const noexcept { return value_ != 0; }
    constexpr packed_entity_id_parts_t parts() const noexcept {
        return packed_entity_id_parts_t{
            static_cast<packed_entity_domain_t>(value_ >> 48U),
            static_cast<std::uint16_t>((value_ >> 32U) & 0xffffULL),
            static_cast<std::uint32_t>(value_ & 0xffffffffULL)};
    }

    constexpr bool operator==(const packed_entity_id_t& other) const noexcept {
        return value_ == other.value_;
    }

    constexpr bool operator!=(const packed_entity_id_t& other) const noexcept {
        return !(*this == other);
    }

    constexpr bool operator<(const packed_entity_id_t& other) const noexcept {
        return value_ < other.value_;
    }

private:
    explicit constexpr packed_entity_id_t(std::uint64_t value) noexcept : value_(value) {}

    std::uint64_t value_ = 0;
};

struct packed_entity_reference_t final {
    packed_entity_domain_t domain = packed_entity_domain_t::invalid;
    std::uint16_t shard = 0;
    entity_id_t source_id = 0;
    bool use_local_shard = true;

    static constexpr packed_entity_reference_t local(packed_entity_domain_t domain,
                                                     entity_id_t source_id) noexcept {
        return packed_entity_reference_t{domain, 0, source_id, true};
    }

    static constexpr packed_entity_reference_t in_shard(packed_entity_domain_t domain,
                                                        std::uint16_t shard,
                                                        entity_id_t source_id) noexcept {
        return packed_entity_reference_t{domain, shard, source_id, false};
    }

    constexpr bool empty() const noexcept {
        return domain == packed_entity_domain_t::invalid && source_id == 0;
    }
};

struct packed_address_t final {
    std::uint64_t value = 0;
    std::uint32_t metadata = 0;

    static packed_address_t pack(const address_t& address) noexcept;
    address_t unpack() const noexcept;

    constexpr bool operator==(const packed_address_t& other) const noexcept {
        return value == other.value && metadata == other.metadata;
    }

    constexpr bool operator!=(const packed_address_t& other) const noexcept {
        return !(*this == other);
    }
};

struct packed_instruction_input_t final {
    entity_id_t source_id = 0;
    address_t address;
    std::uint8_t length = 0;
    std::uint16_t mnemonic_id = 0;
    std::string_view mnemonic;
    std::uint32_t opcode_id = 0;
    std::uint32_t flow_flags = flow_none;
    fact_provenance_t provenance = fact_provenance_t::unknown;
    std::uint8_t confidence = 0;
    coverage_reason_t coverage = coverage_reason_t::decoded;
    std::uint64_t stable_source_id = 0;
};

struct packed_operand_input_t final {
    entity_id_t source_id = 0;
    packed_entity_reference_t instruction;
    packed_entity_reference_t address_expression;
    std::uint8_t operand_index = 0;
    std::uint8_t decoder_operand_id = 0;
    operand_kind_t kind = operand_kind_t::none;
    std::uint8_t access = 0;
    std::uint8_t visibility = 0;
    std::uint8_t encoding = 0;
    std::uint8_t memory_type = 0;
    std::uint8_t access_width = 0;
    std::uint16_t bit_width = 0;
    std::uint16_t access_width_bits = 0;
    std::uint16_t access_count = 0;
    std::uint16_t element_width_bits = 0;
    std::uint16_t element_count = 0;
    std::uint16_t address_width_bits = 0;
    std::uint16_t reg = 0;
    std::uint16_t segment_reg = 0;
    std::uint16_t base_reg = 0;
    std::uint16_t index_reg = 0;
    std::uint8_t scale = 0;
    bool relative = false;
    bool signed_value = false;
    bool has_displacement = false;
    bool has_resolved_expression_value = false;
    std::int64_t displacement = 0;
    std::uint64_t immediate = 0;
    std::uint64_t resolved_expression_value = 0;
    std::uint16_t address_components = address_component_none;
    address_expression_kind_t address_expression_kind = address_expression_kind_t::none;
    target_resolution_t address_resolution = target_resolution_t::unresolved_indirect;
};

struct packed_edge_input_t final {
    entity_id_t source_id = 0;
    packed_entity_reference_t source_entity;
    std::optional<packed_entity_reference_t> target_entity;
    address_t source;
    address_t target;
    edge_kind_t kind = edge_kind_t::fallthrough;
    fact_provenance_t provenance = fact_provenance_t::unknown;
    std::uint8_t confidence = 0;
};

struct packed_string_input_t final {
    entity_id_t source_id = 0;
    address_t address;
    std::uint64_t byte_length = 0;
    string_encoding_t encoding = string_encoding_t::ascii;
    std::string_view value;
    fact_provenance_t provenance = fact_provenance_t::unknown;
    std::uint8_t confidence = 0;
};

struct packed_symbol_input_t final {
    entity_id_t source_id = 0;
    address_t address;
    std::string_view name;
    symbol_kind_t kind = symbol_kind_t::data;
    fact_provenance_t provenance = fact_provenance_t::unknown;
    std::uint8_t confidence = 0;
};

struct packed_address_expression_input_t final {
    entity_id_t source_id = 0;
    packed_entity_reference_t instruction;
    std::uint16_t base_reg = 0;
    std::uint16_t index_reg = 0;
    std::uint8_t scale = 0;
    std::int64_t displacement = 0;
    std::uint16_t segment_reg = 0;
    std::uint16_t address_components = address_component_none;
    address_expression_kind_t kind = address_expression_kind_t::none;
    target_resolution_t resolution = target_resolution_t::unresolved_indirect;
    fact_provenance_t provenance = fact_provenance_t::unknown;
    std::uint8_t confidence = 0;
};

struct packed_basic_block_input_t final {
    entity_id_t source_id = 0;
    address_t start_address;
    address_t end_address;
    std::uint32_t instruction_begin = 0;
    std::uint16_t instruction_count = 0;
    std::uint16_t predecessor_count = 0;
    std::uint16_t successor_count = 0;
    std::uint32_t flags = 0;
    fact_provenance_t provenance = fact_provenance_t::unknown;
    std::uint8_t confidence = 0;
};

struct packed_function_input_t final {
    entity_id_t source_id = 0;
    address_t start_address;
    address_t end_address;
    packed_entity_reference_t entry_block;
    packed_entity_reference_t symbol;
    std::string_view name;
    std::uint16_t chunk_count = 0;
    std::uint32_t flags = 0;
    std::uint64_t return_type_id = 0;
    fact_provenance_t provenance = fact_provenance_t::unknown;
    std::uint8_t confidence = 0;
};

struct packed_function_chunk_input_t final {
    entity_id_t source_id = 0;
    packed_entity_reference_t function;
    address_t start_address;
    address_t end_address;
    std::uint32_t block_begin = 0;
    std::uint16_t block_count = 0;
    std::uint8_t flags = 0;
    fact_provenance_t provenance = fact_provenance_t::unknown;
    std::uint8_t confidence = 0;
};

struct packed_target_fact_input_t final {
    entity_id_t source_id = 0;
    packed_entity_reference_t instruction;
    packed_entity_reference_t operand;
    packed_entity_reference_t address_expression;
    address_t target;
    target_kind_record_t kind = target_kind_record_t::branch;
    target_resolution_t resolution = target_resolution_t::image_relative;
    std::uint8_t operand_index = 0xFFU;
    std::uint16_t access_width_bits = 0;
    std::uint16_t access_count = 0;
    bool direct = false;
    bool is_external = false;
    fact_provenance_t provenance = fact_provenance_t::unknown;
    std::uint8_t confidence = 0;
};

struct packed_xref_input_t final {
    entity_id_t source_id = 0;
    packed_entity_reference_t source_entity;
    packed_entity_reference_t target_entity;
    address_t source_address;
    address_t target_address;
    xref_kind_t kind = xref_kind_t::code;
    bool is_direct = false;
    fact_provenance_t provenance = fact_provenance_t::unknown;
    std::uint8_t confidence = 0;
};

struct packed_coverage_input_t final {
    entity_id_t source_id = 0;
    address_t span_begin;
    address_t span_end;
    coverage_reason_t reason = coverage_reason_t::pending;
    std::uint32_t undecodable_count = 0;
    fact_provenance_t provenance = fact_provenance_t::unknown;
    std::uint8_t confidence = 0;
};

struct packed_instruction_view_t final {
    packed_entity_id_t id;
    address_t address;
    std::uint8_t length = 0;
    std::uint16_t mnemonic_id = 0;
    std::string_view mnemonic;
    std::uint32_t opcode_id = 0;
    std::uint32_t flow_flags = flow_none;
    std::uint32_t first_operand = 0;
    std::uint16_t operand_count = 0;
    fact_provenance_t provenance = fact_provenance_t::unknown;
    std::uint8_t confidence = 0;
    coverage_reason_t coverage = coverage_reason_t::decoded;
    std::uint64_t stable_source_id = 0;
};

struct packed_operand_view_t final {
    packed_entity_id_t id;
    packed_entity_id_t instruction_id;
    packed_entity_id_t address_expression_id;
    std::uint8_t operand_index = 0;
    std::uint8_t decoder_operand_id = 0;
    operand_kind_t kind = operand_kind_t::none;
    std::uint8_t access = 0;
    std::uint8_t visibility = 0;
    std::uint8_t encoding = 0;
    std::uint8_t memory_type = 0;
    std::uint8_t access_width = 0;
    std::uint16_t bit_width = 0;
    std::uint16_t access_width_bits = 0;
    std::uint16_t access_count = 0;
    std::uint16_t element_width_bits = 0;
    std::uint16_t element_count = 0;
    std::uint16_t address_width_bits = 0;
    std::uint16_t reg = 0;
    std::uint16_t segment_reg = 0;
    std::uint16_t base_reg = 0;
    std::uint16_t index_reg = 0;
    std::uint8_t scale = 0;
    bool relative = false;
    bool signed_value = false;
    bool has_displacement = false;
    bool has_resolved_expression_value = false;
    std::int64_t displacement = 0;
    std::uint64_t immediate = 0;
    std::uint64_t resolved_expression_value = 0;
    std::uint16_t address_components = address_component_none;
    address_expression_kind_t address_expression_kind = address_expression_kind_t::none;
    target_resolution_t address_resolution = target_resolution_t::unresolved_indirect;
};

struct packed_edge_view_t final {
    packed_entity_id_t id;
    packed_entity_id_t source_entity;
    std::optional<packed_entity_id_t> target_entity;
    address_t source;
    address_t target;
    edge_kind_t kind = edge_kind_t::fallthrough;
    fact_provenance_t provenance = fact_provenance_t::unknown;
    std::uint8_t confidence = 0;
};

struct packed_string_view_t final {
    packed_entity_id_t id;
    address_t address;
    std::uint64_t byte_length = 0;
    string_encoding_t encoding = string_encoding_t::ascii;
    std::string_view value;
    fact_provenance_t provenance = fact_provenance_t::unknown;
    std::uint8_t confidence = 0;
};

struct packed_symbol_view_t final {
    packed_entity_id_t id;
    address_t address;
    std::string_view name;
    symbol_kind_t kind = symbol_kind_t::data;
    fact_provenance_t provenance = fact_provenance_t::unknown;
    std::uint8_t confidence = 0;
};

struct packed_address_expression_view_t final {
    packed_entity_id_t id;
    packed_entity_id_t instruction_id;
    std::uint16_t base_reg = 0;
    std::uint16_t index_reg = 0;
    std::uint8_t scale = 0;
    std::int64_t displacement = 0;
    std::uint16_t segment_reg = 0;
    std::uint16_t address_components = address_component_none;
    address_expression_kind_t kind = address_expression_kind_t::none;
    target_resolution_t resolution = target_resolution_t::unresolved_indirect;
    fact_provenance_t provenance = fact_provenance_t::unknown;
    std::uint8_t confidence = 0;
};

struct packed_basic_block_view_t final {
    packed_entity_id_t id;
    address_t start_address;
    address_t end_address;
    std::uint32_t instruction_begin = 0;
    std::uint16_t instruction_count = 0;
    std::uint16_t predecessor_count = 0;
    std::uint16_t successor_count = 0;
    std::uint32_t flags = 0;
    fact_provenance_t provenance = fact_provenance_t::unknown;
    std::uint8_t confidence = 0;
};

struct packed_function_view_t final {
    packed_entity_id_t id;
    address_t start_address;
    address_t end_address;
    packed_entity_id_t entry_block_id;
    packed_entity_id_t symbol_id;
    std::string_view name;
    std::uint16_t chunk_count = 0;
    std::uint32_t flags = 0;
    std::uint64_t return_type_id = 0;
    fact_provenance_t provenance = fact_provenance_t::unknown;
    std::uint8_t confidence = 0;
};

struct packed_function_chunk_view_t final {
    packed_entity_id_t id;
    packed_entity_id_t function_id;
    address_t start_address;
    address_t end_address;
    std::uint32_t block_begin = 0;
    std::uint16_t block_count = 0;
    std::uint8_t flags = 0;
    fact_provenance_t provenance = fact_provenance_t::unknown;
    std::uint8_t confidence = 0;
};

struct packed_target_fact_view_t final {
    packed_entity_id_t id;
    packed_entity_id_t instruction_id;
    packed_entity_id_t operand_id;
    packed_entity_id_t address_expression_id;
    address_t target;
    target_kind_record_t kind = target_kind_record_t::branch;
    target_resolution_t resolution = target_resolution_t::image_relative;
    std::uint8_t operand_index = 0xFFU;
    std::uint16_t access_width_bits = 0;
    std::uint16_t access_count = 0;
    bool direct = false;
    bool is_external = false;
    fact_provenance_t provenance = fact_provenance_t::unknown;
    std::uint8_t confidence = 0;
};

struct packed_xref_view_t final {
    packed_entity_id_t id;
    packed_entity_id_t source_entity;
    packed_entity_id_t target_entity;
    address_t source_address;
    address_t target_address;
    xref_kind_t kind = xref_kind_t::code;
    bool is_direct = false;
    fact_provenance_t provenance = fact_provenance_t::unknown;
    std::uint8_t confidence = 0;
};

struct packed_coverage_view_t final {
    packed_entity_id_t id;
    address_t span_begin;
    address_t span_end;
    coverage_reason_t reason = coverage_reason_t::pending;
    std::uint32_t undecodable_count = 0;
    fact_provenance_t provenance = fact_provenance_t::unknown;
    std::uint8_t confidence = 0;
};

struct packed_size_accounting_t final {
    std::uint64_t string_pool_bytes = 0;
    std::uint64_t instruction_bytes = 0;
    std::uint64_t operand_bytes = 0;
    std::uint64_t edge_bytes = 0;
    std::uint64_t string_record_bytes = 0;
    std::uint64_t symbol_bytes = 0;
    std::uint64_t address_expression_bytes = 0;
    std::uint64_t basic_block_bytes = 0;
    std::uint64_t function_bytes = 0;
    std::uint64_t function_chunk_bytes = 0;
    std::uint64_t target_fact_bytes = 0;
    std::uint64_t xref_bytes = 0;
    std::uint64_t coverage_bytes = 0;
    std::uint64_t payload_bytes = 0;
    std::uint64_t reserved_bytes = 0;
};

class packed_analysis_shard_compatibility_view_t;

class packed_analysis_shard_t final {
public:
    packed_analysis_shard_t(packed_analysis_shard_t&&) noexcept;
    packed_analysis_shard_t& operator=(packed_analysis_shard_t&&) noexcept;
    ~packed_analysis_shard_t();

    packed_analysis_shard_t(const packed_analysis_shard_t&) = delete;
    packed_analysis_shard_t& operator=(const packed_analysis_shard_t&) = delete;

    bool valid() const noexcept;
    std::uint16_t shard_id() const noexcept;
    std::uint32_t local_string_count() const noexcept;

    std::uint32_t instruction_count() const noexcept;
    std::uint32_t operand_count() const noexcept;
    std::uint32_t edge_count() const noexcept;
    std::uint32_t string_record_count() const noexcept;
    std::uint32_t symbol_count() const noexcept;
    std::uint32_t address_expression_count() const noexcept;
    std::uint32_t basic_block_count() const noexcept;
    std::uint32_t function_count() const noexcept;
    std::uint32_t function_chunk_count() const noexcept;
    std::uint32_t target_fact_count() const noexcept;
    std::uint32_t xref_count() const noexcept;
    std::uint32_t coverage_count() const noexcept;
    const packed_string_pool_t& string_pool() const noexcept;
    packed_size_accounting_t size_accounting() const noexcept;
    packed_store_result_t<void> validate() const;

    std::optional<packed_instruction_view_t> instruction(std::size_t index) const;
    std::optional<packed_operand_view_t> operand(std::size_t index) const;
    std::optional<packed_edge_view_t> edge(std::size_t index) const;
    std::optional<packed_string_view_t> string(std::size_t index) const;
    std::optional<packed_symbol_view_t> symbol(std::size_t index) const;
    std::optional<packed_address_expression_view_t> address_expression(std::size_t index) const;
    std::optional<packed_basic_block_view_t> basic_block(std::size_t index) const;
    std::optional<packed_function_view_t> function(std::size_t index) const;
    std::optional<packed_function_chunk_view_t> function_chunk(std::size_t index) const;
    std::optional<packed_target_fact_view_t> target_fact(std::size_t index) const;
    std::optional<packed_xref_view_t> xref(std::size_t index) const;
    std::optional<packed_coverage_view_t> coverage(std::size_t index) const;
    packed_analysis_shard_compatibility_view_t compatibility_view() const noexcept;

    void release() noexcept;

private:
    struct impl_t;
    explicit packed_analysis_shard_t(std::unique_ptr<impl_t> impl) noexcept;

    std::unique_ptr<impl_t> impl_;

    friend class packed_analysis_shard_builder_t;
    friend class packed_analysis_store_t;
};

class packed_analysis_shard_compatibility_view_t final {
public:
    std::optional<instruction_record_t> instruction(std::size_t index) const;
    std::optional<operand_fact_t> operand(std::size_t index) const;
    std::optional<edge_record_t> edge(std::size_t index) const;
    std::optional<string_record_t> string(std::size_t index) const;
    std::optional<symbol_record_t> symbol(std::size_t index) const;
    std::optional<basic_block_record_t> basic_block(std::size_t index) const;
    std::optional<function_record_t> function(std::size_t index) const;
    std::optional<function_chunk_record_t> function_chunk(std::size_t index) const;
    std::optional<target_fact_t> target_fact(std::size_t index) const;
    std::optional<xref_record_t> xref(std::size_t index) const;
    std::optional<coverage_span_t> coverage(std::size_t index) const;

private:
    explicit packed_analysis_shard_compatibility_view_t(
        const packed_analysis_shard_t* shard) noexcept;

    const packed_analysis_shard_t* shard_ = nullptr;

    friend class packed_analysis_shard_t;
};

class packed_analysis_shard_builder_t final {
public:
    explicit packed_analysis_shard_builder_t(std::uint16_t shard);
    packed_analysis_shard_builder_t(packed_analysis_shard_builder_t&&) noexcept;
    packed_analysis_shard_builder_t& operator=(packed_analysis_shard_builder_t&&) noexcept;
    ~packed_analysis_shard_builder_t();

    packed_analysis_shard_builder_t(const packed_analysis_shard_builder_t&) = delete;
    packed_analysis_shard_builder_t& operator=(const packed_analysis_shard_builder_t&) = delete;

    packed_store_result_t<void> add_instruction(const packed_instruction_input_t& input);
    packed_store_result_t<void> add_operand(const packed_operand_input_t& input);
    packed_store_result_t<void> add_edge(const packed_edge_input_t& input);
    packed_store_result_t<void> add_string(const packed_string_input_t& input);
    packed_store_result_t<void> add_symbol(const packed_symbol_input_t& input);
    packed_store_result_t<void> add_address_expression(const packed_address_expression_input_t& input);
    packed_store_result_t<void> add_basic_block(const packed_basic_block_input_t& input);
    packed_store_result_t<void> add_function(const packed_function_input_t& input);
    packed_store_result_t<void> add_function_chunk(const packed_function_chunk_input_t& input);
    packed_store_result_t<void> add_target_fact(const packed_target_fact_input_t& input);
    packed_store_result_t<void> add_xref(const packed_xref_input_t& input);
    packed_store_result_t<void> add_coverage(const packed_coverage_input_t& input);
    packed_store_result_t<packed_analysis_shard_t> finalize() &&;

    void reserve_strings(std::size_t string_estimate);
    std::uint16_t shard_id() const noexcept;
    bool finalized() const noexcept;

private:
    struct impl_t;
    std::unique_ptr<impl_t> impl_;
};

class packed_analysis_store_t;

class packed_analysis_compatibility_view_t final {
public:
    std::optional<instruction_record_t> instruction(std::size_t index) const;
    std::optional<operand_fact_t> operand(std::size_t index) const;
    std::optional<edge_record_t> edge(std::size_t index) const;
    std::optional<string_record_t> string(std::size_t index) const;
    std::optional<symbol_record_t> symbol(std::size_t index) const;
    std::optional<basic_block_record_t> basic_block(std::size_t index) const;
    std::optional<function_record_t> function(std::size_t index) const;
    std::optional<function_chunk_record_t> function_chunk(std::size_t index) const;
    std::optional<target_fact_t> target_fact(std::size_t index) const;
    std::optional<xref_record_t> xref(std::size_t index) const;
    std::optional<coverage_span_t> coverage(std::size_t index) const;

private:
    explicit packed_analysis_compatibility_view_t(const packed_analysis_store_t* store) noexcept;

    const packed_analysis_store_t* store_ = nullptr;

    friend class packed_analysis_store_t;
};

class packed_analysis_store_t final {
public:
    packed_analysis_store_t(packed_analysis_store_t&&) noexcept;
    packed_analysis_store_t& operator=(packed_analysis_store_t&&) noexcept;
    ~packed_analysis_store_t();

    packed_analysis_store_t(const packed_analysis_store_t&) = delete;
    packed_analysis_store_t& operator=(const packed_analysis_store_t&) = delete;

    static packed_store_result_t<packed_analysis_store_t>
        merge(std::vector<packed_analysis_shard_t> shards);

    bool valid() const;
    std::uint32_t instruction_count() const noexcept;
    std::uint32_t operand_count() const noexcept;
    std::uint32_t edge_count() const noexcept;
    std::uint32_t string_record_count() const noexcept;
    std::uint32_t symbol_count() const noexcept;
    std::uint32_t address_expression_count() const noexcept;
    std::uint32_t basic_block_count() const noexcept;
    std::uint32_t function_count() const noexcept;
    std::uint32_t function_chunk_count() const noexcept;
    std::uint32_t target_fact_count() const noexcept;
    std::uint32_t xref_count() const noexcept;
    std::uint32_t coverage_count() const noexcept;
    const packed_string_pool_t& string_pool() const noexcept;
    packed_size_accounting_t size_accounting() const noexcept;
    packed_store_result_t<void> validate() const;

    std::optional<packed_instruction_view_t> instruction(std::size_t index) const;
    std::optional<packed_operand_view_t> operand(std::size_t index) const;
    std::optional<packed_edge_view_t> edge(std::size_t index) const;
    std::optional<packed_string_view_t> string(std::size_t index) const;
    std::optional<packed_symbol_view_t> symbol(std::size_t index) const;
    std::optional<packed_address_expression_view_t> address_expression(std::size_t index) const;
    std::optional<packed_basic_block_view_t> basic_block(std::size_t index) const;
    std::optional<packed_function_view_t> function(std::size_t index) const;
    std::optional<packed_function_chunk_view_t> function_chunk(std::size_t index) const;
    std::optional<packed_target_fact_view_t> target_fact(std::size_t index) const;
    std::optional<packed_xref_view_t> xref(std::size_t index) const;
    std::optional<packed_coverage_view_t> coverage(std::size_t index) const;
    packed_analysis_compatibility_view_t compatibility_view() const noexcept;

private:
    struct impl_t;
    explicit packed_analysis_store_t(std::unique_ptr<impl_t> impl) noexcept;

    std::unique_ptr<impl_t> impl_;

    friend class packed_analysis_compatibility_view_t;
};

static_assert(sizeof(packed_entity_id_t) == sizeof(std::uint64_t),
              "packed entity identifiers must remain 64-bit");

}
