#pragma once

#include <nlohmann/json.hpp>

#include <cstddef>
#include <memory>
#include <string>
#include <vector>

namespace aida::standalone::mcp::protocol {

using json = nlohmann::json;

struct schema_error_t {
    std::string path;
    std::string keyword;
    std::string message;
    std::string instance_fragment;
};

struct schema_validation_t {
    bool valid = true;
    bool truncated = false;
    std::vector<schema_error_t> errors;

    json diagnostics() const;
    std::string summary() const;
};

struct schema_cache_stats_t {
    std::size_t entries = 0;
    std::size_t hits = 0;
    std::size_t misses = 0;
    std::size_t evictions = 0;
};

class schema_runtime_t {
public:
    explicit schema_runtime_t(std::size_t cache_capacity = 128);
    ~schema_runtime_t();

    schema_runtime_t(const schema_runtime_t&) = delete;
    schema_runtime_t& operator=(const schema_runtime_t&) = delete;
    schema_runtime_t(schema_runtime_t&&) noexcept;
    schema_runtime_t& operator=(schema_runtime_t&&) noexcept;

    schema_validation_t compile(const json& schema);
    schema_validation_t validate(const json& schema, const json& instance);
    schema_cache_stats_t cache_stats() const;
    void clear();

private:
    struct impl_t;
    std::unique_ptr<impl_t> impl_;
};

}
