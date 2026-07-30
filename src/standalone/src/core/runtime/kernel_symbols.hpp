#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace kernel_symbols
{
    enum class state_t : std::uint32_t
    {
        not_started = 0,
        loading     = 1,
        ready       = 2,
        failed      = 3,
    };

    struct lookup_result_t
    {
        bool          resolved       = false;
        std::string   module;
        std::string   symbol;
        std::uint64_t symbol_base_va = 0;
        std::uint64_t offset         = 0;
        bool          exact          = false;
    };

    struct struct_field_desc_t
    {
        std::string   name;
        std::string   type;
        std::uint32_t offset = 0;
        std::uint32_t size   = 0;
    };

    struct struct_desc_t
    {
        std::string                      name;
        std::uint32_t                    size = 0;
        std::vector<struct_field_desc_t> fields;
    };

    struct decoded_field_t
    {
        std::string   name;
        std::string   type;
        std::uint32_t offset    = 0;
        std::uint32_t size      = 0;
        std::string   value;
        std::string   annotation;
        bool          truncated = false;
    };

    struct status_t
    {
        state_t       state            = state_t::not_started;
        std::string   detail;
        std::string   last_error;
        std::string   pdb_name;
        std::string   cache_path;
        std::uint64_t ntoskrnl_base    = 0;
        std::uint64_t ntoskrnl_size    = 0;
        std::uint64_t function_count   = 0;
        std::uint64_t global_count     = 0;
        std::uint64_t struct_count     = 0;
        std::uint64_t load_duration_ms = 0;
        bool          from_cache       = false;
    };

    void ensure_started();
    void request_reload();
    bool ready();
    status_t status();
    const char* state_name(state_t state) noexcept;

    std::optional<lookup_result_t> lookup(std::uint64_t va);
    std::string format(std::uint64_t va);
    std::optional<std::uint64_t> resolve(const std::string& expression);
    std::optional<struct_desc_t> describe_struct(const std::string& name);
    std::vector<decoded_field_t> decode_struct_buffer(const struct_desc_t& desc,
                                                      const std::vector<std::uint8_t>& bytes,
                                                      std::uint64_t base_va);
}
