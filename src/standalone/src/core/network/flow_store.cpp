#include "flow_store.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <mutex>
#include <thread>

namespace flow_store {
namespace {

std::vector<mitm_proxy::http_exchange> source_flows(const client_replay_options& options)
{
    if (!options.flows.empty())
        return options.flows;
    return select_history(options.flow_ids);
}

bool cancelled(const std::shared_ptr<std::atomic_bool>& token)
{
    return token && token->load(std::memory_order_acquire);
}

void delay_or_cancel(uint32_t delay_ms, const std::shared_ptr<std::atomic_bool>& token)
{
    uint32_t waited = 0;
    while (waited < delay_ms && !cancelled(token)) {
        const uint32_t slice = std::min<uint32_t>(delay_ms - waited, 25);
        std::this_thread::sleep_for(std::chrono::milliseconds(slice));
        waited += slice;
    }
}

}

operation_result save_history(const std::string& file_path,
                              flow_serializer::flow_format format,
                              const std::vector<uint64_t>& flow_ids)
{
    operation_result result;
    std::vector<mitm_proxy::http_exchange> flows = select_history(flow_ids);
    std::string error;
    if (!flow_serializer::save_file(file_path, format, flows, error)) {
        result.error = error;
        return result;
    }
    result.success = true;
    result.flow_count = flows.size();
    return result;
}

operation_result load_history(const std::string& file_path,
                              flow_serializer::flow_format format,
                              bool append)
{
    operation_result result;
    auto loaded = flow_serializer::load_file(file_path, format);
    if (!loaded.success) {
        result.error = loaded.error;
        return result;
    }
    return import_flows(loaded.flows, append);
}

operation_result import_flows(const std::vector<mitm_proxy::http_exchange>& flows, bool append)
{
    operation_result result;
    if (!append)
        mitm_proxy::clear_history();
    if (!mitm_proxy::append_history(flows, false)) {
        result.error = "failed to import flows into proxy history";
        return result;
    }
    result.success = true;
    result.flow_count = flows.size();
    return result;
}

std::vector<mitm_proxy::http_exchange> select_history(const std::vector<uint64_t>& flow_ids)
{
    if (flow_ids.empty())
        return mitm_proxy::get_history();
    return mitm_proxy::get_history_by_ids(flow_ids);
}

bool set_tags(uint64_t flow_id, const std::vector<std::string>& tags)
{
    return mitm_proxy::set_exchange_tags(flow_id, tags);
}

bool add_tag(uint64_t flow_id, const std::string& tag)
{
    return mitm_proxy::add_exchange_tag(flow_id, tag);
}

bool remove_tag(uint64_t flow_id, const std::string& tag)
{
    return mitm_proxy::remove_exchange_tag(flow_id, tag);
}

client_replay_result client_replay(const client_replay_options& options)
{
    client_replay_result result;
    std::vector<mitm_proxy::http_exchange> flows = source_flows(options);
    result.items.resize(flows.size());
    if (flows.empty()) {
        result.completed = true;
        return result;
    }

    std::atomic_size_t next{0};
    std::atomic_bool stop{false};
    std::atomic_size_t attempted{0};
    std::atomic_size_t succeeded{0};
    std::atomic_size_t failed{0};
    std::mutex result_mutex;
    const uint32_t worker_count = std::max<uint32_t>(1, std::min<uint32_t>(options.concurrency == 0 ? 1 : options.concurrency, static_cast<uint32_t>(flows.size())));
    std::vector<std::thread> workers;
    workers.reserve(worker_count);

    for (uint32_t i = 0; i < worker_count; ++i) {
        workers.emplace_back([&, i]() {
            for (;;) {
                if (stop.load(std::memory_order_acquire) || cancelled(options.cancel))
                    break;
                const size_t index = next.fetch_add(1);
                if (index >= flows.size())
                    break;
                if (options.delay_ms > 0 && (index > 0 || i > 0))
                    delay_or_cancel(options.delay_ms, options.cancel);
                if (stop.load(std::memory_order_acquire) || cancelled(options.cancel))
                    break;
                const auto& flow = flows[index];
                std::vector<uint8_t> raw_request = flow_serializer::build_raw_request(flow);
                const std::string host = options.target_host.empty() ? flow.target_host : options.target_host;
                const uint16_t port = options.target_port == 0 ? flow.target_port : options.target_port;
                const bool use_tls = options.override_tls ? options.use_tls : flow.is_tls;
                replay_item_result item;
                item.source_flow_id = flow.id;
                if (host.empty() || port == 0 || raw_request.empty()) {
                    item.error = "flow cannot be replayed without host, port, and request bytes";
                    item.success = false;
                } else {
                    attempted.fetch_add(1, std::memory_order_relaxed);
                    auto replay = mitm_proxy::repeat_request(host, port, use_tls, raw_request);
                    item.success = replay.success;
                    item.exchange = std::move(replay.exchange);
                    item.error = std::move(replay.error);
                }
                const bool item_success = item.success;
                {
                    std::lock_guard<std::mutex> lock(result_mutex);
                    result.items[index] = std::move(item);
                }
                if (item_success) {
                    succeeded.fetch_add(1, std::memory_order_relaxed);
                } else {
                    failed.fetch_add(1, std::memory_order_relaxed);
                    if (options.stop_on_error)
                        stop.store(true, std::memory_order_release);
                }
            }
        });
    }

    for (auto& worker : workers)
        if (worker.joinable())
            worker.join();

    result.attempted = attempted.load(std::memory_order_relaxed);
    result.succeeded = succeeded.load(std::memory_order_relaxed);
    result.failed = failed.load(std::memory_order_relaxed);
    result.cancelled = cancelled(options.cancel);
    result.completed = !result.cancelled && !stop.load(std::memory_order_acquire);
    if (!result.completed && options.stop_on_error && result.failed > 0)
        result.error = "stopped after replay error";
    if (result.cancelled)
        result.error = "cancelled";
    return result;
}

}
