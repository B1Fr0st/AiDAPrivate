#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include <ida.hpp>
#include <kernwin.hpp>
#include <nlohmann/json.hpp>

namespace aida
{
namespace vuln
{

enum class ida_gateway_domain_t : std::uint32_t
{
    idb,
    hexrays,
    ui,
    netnode,
    xref,
    function,
    segment,
    type,
    mixed
};

enum class ida_gateway_modal_policy_t : std::uint32_t
{
    defer_if_modal,
    allow_modal
};

struct ida_gateway_request_t
{
    ida_gateway_domain_t domain = ida_gateway_domain_t::mixed;
    ida_gateway_modal_policy_t modal_policy = ida_gateway_modal_policy_t::defer_if_modal;
    std::string phase;
    std::string operation;
    int mff_flags = MFF_READ;
    std::uint32_t deadline_ms = 10000;
    std::uint64_t expected_idb_generation = 0;
    std::uint64_t expected_hexrays_generation = 0;
    std::shared_ptr<std::atomic_bool> cancellation;
};

struct ida_gateway_context_t
{
    std::uint64_t request_id = 0;
    std::uint64_t idb_generation = 0;
    std::uint64_t hexrays_generation = 0;
    bool cancellation_requested = false;
};

struct ida_gateway_result_t
{
    bool ok = false;
    bool cancelled = false;
    bool deferred = false;
    bool timed_out = false;
    bool exception = false;
    bool stale_generation = false;
    std::uint64_t request_id = 0;
    std::uint64_t idb_generation = 0;
    std::uint64_t hexrays_generation = 0;
    std::uint64_t queue_wait_ms = 0;
    std::uint64_t elapsed_ms = 0;
    std::string phase;
    std::string operation;
    std::string error;
    nlohmann::json data = nlohmann::json::object();
};

struct ida_gateway_snapshot_t
{
    std::string snapshot_id;
    std::string root_filename;
    std::string input_path;
    std::string sha256;
    std::uint64_t image_base = 0;
    std::uint64_t min_ea = 0;
    std::uint64_t max_ea = 0;
    std::uint32_t pointer_width_bits = 0;
    std::string processor;
    std::string endianness;
    bool dll = false;
    bool kernel_mode = false;
    bool valid = false;
    std::string error;
};

class ida_gateway_t
{
public:
    ida_gateway_t();
    ~ida_gateway_t();

    ida_gateway_t(const ida_gateway_t&) = delete;
    ida_gateway_t& operator=(const ida_gateway_t&) = delete;

    void start();
    void stop();
    void cancel_all();
    bool cancel_request(std::uint64_t request_id);

    ida_gateway_result_t execute(const ida_gateway_request_t& request,
                                 const std::function<nlohmann::json(const ida_gateway_context_t&)>& body);

    ida_gateway_result_t capture_idb_snapshot(const std::shared_ptr<std::atomic_bool>& cancellation,
                                              std::uint32_t deadline_ms);

    std::uint64_t bump_idb_generation(const char* reason);
    std::uint64_t bump_hexrays_generation(const char* reason);
    std::uint64_t idb_generation() const;
    std::uint64_t hexrays_generation() const;
    std::vector<std::uint64_t> pending_request_ids() const;
    nlohmann::json metrics_json() const;

private:
    struct impl_t;
    std::unique_ptr<impl_t> m_impl;
};

nlohmann::json to_json(const ida_gateway_snapshot_t& snapshot);
const char* gateway_domain_name(ida_gateway_domain_t domain);

}
}
