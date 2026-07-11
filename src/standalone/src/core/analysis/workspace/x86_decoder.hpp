#pragma once

#include "arch_decoder.hpp"
#include "byte_provider.hpp"
#include "compact_ir.hpp"
#include "pe_image.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

namespace aida::analysis {

struct x86_decoder_profile_t {
    static constexpr std::uint64_t schema_version = 2;
    static constexpr std::uint64_t zydis_version = 0x0004000100000000ULL;
    static constexpr std::uint64_t zycore_version = 0x0001000500020000ULL;
    static constexpr std::size_t canonical_byte_count = 80;

    architecture_mode_t mode = architecture_mode_t::unknown;
    std::uint64_t feature_mask = 0;

    std::array<std::uint8_t, canonical_byte_count> canonical_bytes() const noexcept;

    friend bool operator==(const x86_decoder_profile_t& lhs,
                           const x86_decoder_profile_t& rhs) noexcept {
        return lhs.mode == rhs.mode && lhs.feature_mask == rhs.feature_mask;
    }

    friend bool operator!=(const x86_decoder_profile_t& lhs,
                           const x86_decoder_profile_t& rhs) noexcept {
        return !(lhs == rhs);
    }
};

workspace_result_t<x86_decoder_profile_t>
make_x86_decoder_profile(architecture_mode_t mode);
entity_id_t canonical_x86_decode_claim_id(const address_t& address) noexcept;

struct x86_decode_request_t {
    address_t address;
    std::uint64_t provider_offset = 0;
    std::uint64_t runtime_address = 0;
    std::uint64_t image_base = 0;
    std::uint64_t image_size = 0;
    std::uint8_t available_bytes = 15;
    fact_provenance_t provenance = fact_provenance_t::recursive_decode;
    std::uint8_t confidence = 100;
    std::uint64_t stable_source_id = 0;
};

struct x86_decode_result_t {
    static constexpr std::size_t operand_capacity = 10;
    static constexpr std::size_t target_capacity = 11;

    instruction_record_t instruction;
    std::array<operand_fact_t, operand_capacity> operands{};
    std::array<target_fact_t, target_capacity> targets{};
    std::uint8_t operand_count = 0;
    std::uint8_t target_count = 0;
};

struct instruction_format_options_t {
    bool uppercase = false;
    bool force_segment = false;
    bool show_relative_addresses = false;
    std::size_t maximum_text_bytes = 1024;
};

class worker_owned_x86_decoder_t final {
public:
    static workspace_result_t<std::unique_ptr<worker_owned_x86_decoder_t>>
        create(architecture_mode_t mode);

    ~worker_owned_x86_decoder_t();
    worker_owned_x86_decoder_t(worker_owned_x86_decoder_t&&) noexcept;
    worker_owned_x86_decoder_t& operator=(worker_owned_x86_decoder_t&&) noexcept;
    worker_owned_x86_decoder_t(const worker_owned_x86_decoder_t&) = delete;
    worker_owned_x86_decoder_t& operator=(const worker_owned_x86_decoder_t&) = delete;

    architecture_mode_t mode() const noexcept;
    const x86_decoder_profile_t& profile() const noexcept;
    workspace_result_t<void>
        decode_one(const byte_view_t& view, std::uint64_t view_provider_offset,
                   const x86_decode_request_t& request, x86_decode_result_t& output,
                   const cancellation_token_t& cancel = {});
    workspace_result_t<x86_decode_result_t>
        decode_one(const byte_view_t& view, std::uint64_t view_provider_offset,
                   const x86_decode_request_t& request,
                   const cancellation_token_t& cancel = {});
    workspace_result_t<x86_decode_result_t>
        decode_one(const byte_provider_t& provider, const x86_decode_request_t& request,
                   const cancellation_token_t& cancel = {});
    workspace_result_t<std::string>
        format_one(const std::uint8_t* bytes, std::size_t byte_count,
                   std::uint64_t runtime_address,
                   const instruction_record_t& instruction,
                   const instruction_format_options_t& options = {},
                   const cancellation_token_t& cancel = {});
    workspace_result_t<std::string>
        format_one(const byte_view_t& view, std::uint64_t view_provider_offset,
                   const byte_provider_t& provider, const pe_image_t& image,
                   const instruction_record_t& instruction,
                   const instruction_format_options_t& options = {},
                   const cancellation_token_t& cancel = {});
    workspace_result_t<std::string>
        format_one(const byte_provider_t& provider, const pe_image_t& image,
                   const instruction_record_t& instruction,
                   const instruction_format_options_t& options = {},
                   const cancellation_token_t& cancel = {});

private:
    struct impl_t;
    explicit worker_owned_x86_decoder_t(std::unique_ptr<impl_t> impl);
    std::unique_ptr<impl_t> impl_;
};

workspace_result_t<void> register_x86_decoder_backends(
    arch_decoder_registry_t& registry);

}
