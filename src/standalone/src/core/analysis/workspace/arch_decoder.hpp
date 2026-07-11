#pragma once

#include "byte_provider.hpp"
#include "compact_ir.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <thread>

namespace aida::analysis {

struct arch_decoder_key_t {
    architecture_id_t architecture = architecture_id_t::unknown;
    architecture_mode_t mode = architecture_mode_t::unknown;
    endian_t endian = endian_t::little;
    abi_id_t abi = abi_id_t::unknown;
    std::uint8_t address_width_bits = 0;

    friend bool operator==(const arch_decoder_key_t& lhs,
                           const arch_decoder_key_t& rhs) noexcept;
    friend bool operator!=(const arch_decoder_key_t& lhs,
                           const arch_decoder_key_t& rhs) noexcept;
    friend bool operator<(const arch_decoder_key_t& lhs,
                          const arch_decoder_key_t& rhs) noexcept;
};

arch_decoder_key_t make_arch_decoder_key(const workspace_image_t& image) noexcept;
workspace_result_t<void> validate_arch_decoder_key(const arch_decoder_key_t& key);

struct arch_decode_request_t {
    address_t address;
    std::uint64_t provider_offset = 0;
    std::uint64_t runtime_address = 0;
    std::uint64_t image_base = 0;
    std::uint64_t image_size = 0;
    std::uint16_t available_bytes = 0;
    fact_provenance_t provenance = fact_provenance_t::recursive_decode;
    std::uint8_t confidence = 100;
    std::uint64_t stable_source_id = 0;
};

struct arch_decode_result_t {
    static constexpr std::size_t operand_capacity = 16;
    static constexpr std::size_t target_capacity = 64;
    static constexpr std::uint16_t instruction_byte_capacity = 255;

    instruction_record_t instruction;
    std::array<operand_fact_t, operand_capacity> operands{};
    std::array<target_fact_t, target_capacity> targets{};
    std::uint8_t operand_count = 0;
    std::uint16_t target_count = 0;
    std::uint8_t delay_slot_count = 0;
};

struct arch_format_options_t {
    static constexpr std::size_t hard_maximum_text_bytes = 64ULL * 1024ULL;

    bool uppercase = false;
    std::size_t maximum_text_bytes = 1024;
};

workspace_result_t<void> validate_arch_format_options(
    const arch_format_options_t& options);

struct arch_decoder_limits_t {
    std::uint16_t minimum_instruction_bytes = 1;
    std::uint16_t maximum_instruction_bytes = 1;
    std::uint16_t instruction_alignment = 1;
    std::uint8_t maximum_operand_facts = 0;
    std::uint16_t maximum_target_facts = 0;
    std::uint8_t maximum_delay_slots = 0;
};

workspace_result_t<void> validate_arch_decoder_limits(const arch_decoder_limits_t& limits);

struct arch_decode_budget_t {
    static constexpr std::uint64_t hard_max_decode_attempts = 64'000'000;
    static constexpr std::uint64_t hard_max_input_bytes = 1ULL << 30;
    static constexpr std::uint64_t hard_max_instructions = 32'000'000;
    static constexpr std::uint64_t hard_max_operand_facts = 256'000'000;
    static constexpr std::uint64_t hard_max_target_facts = 128'000'000;
    static constexpr std::uint64_t hard_max_format_attempts = 64'000'000;
    static constexpr std::uint64_t hard_max_format_input_bytes = 1ULL << 30;
    static constexpr std::uint64_t hard_max_formatted_instructions = 32'000'000;
    static constexpr std::uint64_t hard_max_formatted_text_bytes = 1ULL << 30;

    std::uint64_t max_decode_attempts = 4'000'000;
    std::uint64_t max_input_bytes = 64ULL << 20;
    std::uint64_t max_instructions = 2'000'000;
    std::uint64_t max_operand_facts = 16'000'000;
    std::uint64_t max_target_facts = 8'000'000;
    std::uint64_t max_format_attempts = 4'000'000;
    std::uint64_t max_format_input_bytes = 64ULL << 20;
    std::uint64_t max_formatted_instructions = 2'000'000;
    std::uint64_t max_formatted_text_bytes = 64ULL << 20;
};

workspace_result_t<void> validate_arch_decode_budget(const arch_decode_budget_t& budget);

struct arch_decode_usage_t {
    std::uint64_t decode_attempts = 0;
    std::uint64_t input_bytes = 0;
    std::uint64_t instructions = 0;
    std::uint64_t decoded_bytes = 0;
    std::uint64_t operand_facts = 0;
    std::uint64_t target_facts = 0;
    std::uint64_t format_attempts = 0;
    std::uint64_t format_input_bytes = 0;
    std::uint64_t formatted_instructions = 0;
    std::uint64_t formatted_text_bytes = 0;
    std::uint64_t cancellation_polls = 0;
};

class arch_decode_control_t final {
public:
    arch_decode_control_t(const arch_decode_control_t&) = delete;
    arch_decode_control_t& operator=(const arch_decode_control_t&) = delete;
    arch_decode_control_t(arch_decode_control_t&&) = delete;
    arch_decode_control_t& operator=(arch_decode_control_t&&) = delete;

    const cancellation_token_t& cancellation() const noexcept;
    const arch_decode_budget_t& budget() const noexcept;
    const arch_decode_usage_t& usage() const noexcept;
    workspace_result_t<void> poll() const;

private:
    arch_decode_control_t(const cancellation_token_t& cancellation,
                          const arch_decode_budget_t& budget,
                          arch_decode_usage_t& usage,
                          const char* phase) noexcept;

    const cancellation_token_t* cancellation_ = nullptr;
    const arch_decode_budget_t* budget_ = nullptr;
    arch_decode_usage_t* usage_ = nullptr;
    const char* phase_ = nullptr;

    friend class worker_owned_arch_decoder_t;
};

class arch_decoder_backend_t {
public:
    virtual ~arch_decoder_backend_t() = default;
    arch_decoder_backend_t(const arch_decoder_backend_t&) = delete;
    arch_decoder_backend_t& operator=(const arch_decoder_backend_t&) = delete;

    virtual workspace_result_t<void> decode_one(
        const byte_view_t& view,
        std::uint64_t view_provider_offset,
        const arch_decode_request_t& request,
        arch_decode_result_t& output,
        const arch_decode_control_t& control) = 0;

protected:
    arch_decoder_backend_t() = default;

    virtual workspace_result_t<std::string> format_decoded(
        const arch_decode_result_t& decoded,
        const arch_decode_control_t& control) = 0;

    static workspace_result_t<std::string> combine_format_text(
        const char* mnemonic,
        std::size_t mnemonic_capacity,
        const char* operands,
        std::size_t operands_capacity);

    friend class worker_owned_arch_decoder_t;
};

using arch_decoder_factory_fn_t =
    workspace_result_t<std::unique_ptr<arch_decoder_backend_t>> (*)(
        const arch_decoder_key_t& key,
        const cancellation_token_t& cancellation);

struct arch_decoder_registration_t {
    arch_decoder_key_t key;
    arch_decoder_limits_t limits;
    std::string implementation_id;
    std::uint64_t implementation_version = 0;
    arch_decoder_factory_fn_t factory = nullptr;
};

class worker_owned_arch_decoder_t final {
public:
    ~worker_owned_arch_decoder_t();
    worker_owned_arch_decoder_t(const worker_owned_arch_decoder_t&) = delete;
    worker_owned_arch_decoder_t& operator=(const worker_owned_arch_decoder_t&) = delete;
    worker_owned_arch_decoder_t(worker_owned_arch_decoder_t&&) = delete;
    worker_owned_arch_decoder_t& operator=(worker_owned_arch_decoder_t&&) = delete;

    const arch_decoder_key_t& key() const noexcept;
    const arch_decoder_registration_t& registration() const noexcept;
    const arch_decode_budget_t& budget() const noexcept;
    const arch_decode_usage_t& usage() const noexcept;
    std::thread::id owner_thread() const noexcept;

    workspace_result_t<void> poll();
    workspace_result_t<void> decode_one(
        const byte_view_t& view,
        std::uint64_t view_provider_offset,
        const arch_decode_request_t& request,
        arch_decode_result_t& output);
    workspace_result_t<arch_decode_result_t> decode_one(
        const byte_view_t& view,
        std::uint64_t view_provider_offset,
        const arch_decode_request_t& request);
    workspace_result_t<arch_decode_result_t> decode_one(
        const byte_provider_t& provider,
        const arch_decode_request_t& request);
    workspace_result_t<std::string> format_one(
        const byte_view_t& view,
        std::uint64_t view_provider_offset,
        const arch_decode_request_t& request,
        const arch_decode_result_t& decoded,
        const arch_format_options_t& options = {});
    workspace_result_t<std::string> format_one(
        const byte_provider_t& provider,
        const arch_decode_request_t& request,
        const arch_decode_result_t& decoded,
        const arch_format_options_t& options = {});

private:
    worker_owned_arch_decoder_t(
        arch_decoder_key_t key,
        arch_decoder_registration_t registration,
        arch_decode_budget_t budget,
        cancellation_token_t cancellation,
        std::unique_ptr<arch_decoder_backend_t> backend);

    workspace_result_t<void> verify_owner() const;

    arch_decoder_key_t key_;
    arch_decoder_registration_t registration_;
    arch_decode_budget_t budget_;
    arch_decode_usage_t usage_;
    cancellation_token_t cancellation_;
    std::unique_ptr<arch_decoder_backend_t> backend_;
    std::thread::id owner_thread_;

    friend class arch_decoder_registry_t;
};

class arch_decoder_registry_t final {
public:
    static constexpr std::size_t registration_capacity = 128;

    arch_decoder_registry_t();
    ~arch_decoder_registry_t();
    arch_decoder_registry_t(const arch_decoder_registry_t&) = delete;
    arch_decoder_registry_t& operator=(const arch_decoder_registry_t&) = delete;
    arch_decoder_registry_t(arch_decoder_registry_t&&) = delete;
    arch_decoder_registry_t& operator=(arch_decoder_registry_t&&) = delete;

    workspace_result_t<void> register_decoder(
        const arch_decoder_registration_t& registration);
    workspace_result_t<arch_decoder_registration_t> resolve(
        const arch_decoder_key_t& key) const;
    workspace_result_t<std::unique_ptr<worker_owned_arch_decoder_t>> create_worker(
        const arch_decoder_key_t& key,
        const arch_decode_budget_t& budget = {},
        const cancellation_token_t& cancellation = {}) const;
    std::size_t registered_count() const;

private:
    struct impl_t;
    std::unique_ptr<impl_t> impl_;
};

arch_decoder_registry_t& default_arch_decoder_registry();

}
