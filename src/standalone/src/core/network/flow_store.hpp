#pragma once

#include "flow_serializer.hpp"

#include <atomic>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace flow_store {

struct operation_result {
    bool success = false;
    size_t flow_count = 0;
    std::string error;
};

struct replay_item_result {
    uint64_t source_flow_id = 0;
    bool success = false;
    mitm_proxy::http_exchange exchange;
    std::string error;
};

struct client_replay_options {
    std::vector<uint64_t> flow_ids;
    std::vector<mitm_proxy::http_exchange> flows;
    std::string target_host;
    uint16_t target_port = 0;
    bool override_tls = false;
    bool use_tls = false;
    uint32_t concurrency = 1;
    uint32_t delay_ms = 0;
    bool stop_on_error = false;
    std::shared_ptr<std::atomic_bool> cancel;
};

struct client_replay_result {
    bool completed = false;
    bool cancelled = false;
    size_t attempted = 0;
    size_t succeeded = 0;
    size_t failed = 0;
    std::vector<replay_item_result> items;
    std::string error;
};

operation_result save_history(const std::string& file_path,
                              flow_serializer::flow_format format,
                              const std::vector<uint64_t>& flow_ids = {});

operation_result load_history(const std::string& file_path,
                              flow_serializer::flow_format format,
                              bool append);

operation_result import_flows(const std::vector<mitm_proxy::http_exchange>& flows, bool append);
std::vector<mitm_proxy::http_exchange> select_history(const std::vector<uint64_t>& flow_ids);

bool set_tags(uint64_t flow_id, const std::vector<std::string>& tags);
bool add_tag(uint64_t flow_id, const std::string& tag);
bool remove_tag(uint64_t flow_id, const std::string& tag);

client_replay_result client_replay(const client_replay_options& options);

}
