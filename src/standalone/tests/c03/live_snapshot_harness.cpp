#include "live_snapshot_harness.hpp"

#include "../../src/core/analysis/live_snapshot_provider.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <exception>
#include <future>
#include <iostream>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

namespace aida::analysis::c03_test {
namespace {

using namespace aida::analysis::c03;

template <typename value_t, typename = void>
struct has_write_member_t : std::false_type {};

template <typename value_t>
struct has_write_member_t<value_t, std::void_t<decltype(&value_t::write)>> : std::true_type {};

template <typename value_t, typename = void>
struct has_write_page_member_t : std::false_type {};

template <typename value_t>
struct has_write_page_member_t<value_t, std::void_t<decltype(&value_t::write_page)>>
    : std::true_type {};

static_assert(!has_write_member_t<live_snapshot_provider_t>::value,
              "live snapshot provider exposes a write operation");
static_assert(!has_write_member_t<live_snapshot_adapter_t>::value,
              "live snapshot adapter exposes a write operation");
static_assert(!has_write_page_member_t<live_snapshot_adapter_t>::value,
              "live snapshot adapter exposes a page write operation");

void require(bool condition, std::string_view message)
{
    if (!condition)
        throw std::runtime_error(std::string(message));
}

class manual_clock_t final : public live_snapshot_clock_t {
public:
    live_request_budget_t::time_point_t now() const noexcept override
    {
        return live_request_budget_t::time_point_t(
            live_request_budget_t::clock_t::duration(ticks_.load(std::memory_order_acquire)));
    }

    void advance(std::chrono::milliseconds elapsed) noexcept
    {
        const auto duration =
            std::chrono::duration_cast<live_request_budget_t::clock_t::duration>(elapsed);
        ticks_.fetch_add(duration.count(), std::memory_order_acq_rel);
    }

private:
    std::atomic<live_request_budget_t::clock_t::duration::rep> ticks_{0};
};

class blocking_gate_t final {
public:
    void arm()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        armed_ = true;
        entered_ = false;
        released_ = false;
        departed_ = false;
    }

    void pass() const
    {
        std::unique_lock<std::mutex> lock(mutex_);
        if (!armed_)
            return;
        entered_ = true;
        wake_.notify_all();
        wake_.wait(lock, [this] { return released_; });
        armed_ = false;
        departed_ = true;
        wake_.notify_all();
    }

    bool wait_for_entry(std::chrono::milliseconds timeout) const
    {
        std::unique_lock<std::mutex> lock(mutex_);
        return wake_.wait_for(lock, timeout, [this] { return entered_; });
    }

    void release()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        released_ = true;
        wake_.notify_all();
    }

    bool wait_for_departure(std::chrono::milliseconds timeout) const
    {
        std::unique_lock<std::mutex> lock(mutex_);
        return wake_.wait_for(lock, timeout, [this] { return departed_; });
    }

private:
    mutable std::mutex mutex_;
    mutable std::condition_variable wake_;
    mutable bool armed_ = false;
    mutable bool entered_ = false;
    mutable bool released_ = false;
    mutable bool departed_ = false;
};

live_snapshot_fingerprint_t make_fingerprint(std::uint8_t seed)
{
    live_snapshot_fingerprint_t fingerprint{};
    for (std::size_t index = 0; index < fingerprint.size(); ++index)
        fingerprint[index] = static_cast<std::uint8_t>(seed + index * 7U);
    return fingerprint;
}

class fake_live_snapshot_adapter_t final : public live_snapshot_adapter_t {
public:
    explicit fake_live_snapshot_adapter_t(std::shared_ptr<manual_clock_t> clock)
        : clock_(std::move(clock))
    {
        process_ = {0xB30U, 0x123456789ULL};
        module_ = {0x0000000180000000ULL, 0x100U, 0xB30B30ULL, make_fingerprint(17U)};
        memory_.resize(static_cast<std::size_t>(module_.size));
        for (std::size_t index = 0; index < memory_.size(); ++index)
            memory_[index] = static_cast<std::uint8_t>(index);
    }

    live_process_identity_t process() const noexcept { return process_; }
    live_module_identity_t module() const noexcept { return module_; }
    std::uint64_t page_reads() const noexcept { return page_reads_; }
    std::uint64_t process_queries() const noexcept { return process_queries_; }
    std::uint64_t module_queries() const noexcept { return module_queries_; }
    blocking_gate_t& process_gate() noexcept { return process_gate_; }
    blocking_gate_t& module_gate() noexcept { return module_gate_; }
    blocking_gate_t& read_gate() noexcept { return read_gate_; }

    void set_partial_read(bool enabled) noexcept { partial_read_ = enabled; }
    void set_pid_reuse_after_read(bool enabled) noexcept { pid_reuse_after_read_ = enabled; }
    void set_module_unload_after_read(bool enabled) noexcept { module_unload_after_read_ = enabled; }
    void set_module_remap_after_read(bool enabled) noexcept { module_remap_after_read_ = enabled; }
    void set_read_elapsed(std::chrono::milliseconds elapsed) noexcept { read_elapsed_ = elapsed; }

    void remap_now() noexcept
    {
        ++module_.mapping_identity;
        module_.fingerprint[0] ^= 0xA5U;
    }

    live_snapshot_result_t<live_process_identity_t>
    query_process(std::uint32_t pid, const live_snapshot_operation_context_t& context) const override
    {
        ++process_queries_;
        if (context.cancellation.stop_requested()) {
            return live_snapshot_result_t<live_process_identity_t>::failure(
                make_live_snapshot_error(live_snapshot_error_code_t::cancelled, "fake_process"));
        }
        process_gate_.pass();
        if (pid != process_.pid) {
            return live_snapshot_result_t<live_process_identity_t>::failure(
                make_live_snapshot_error(live_snapshot_error_code_t::process_identity_changed,
                                         "fake_process", process_.pid, pid));
        }
        return live_snapshot_result_t<live_process_identity_t>::success(process_);
    }

    live_snapshot_result_t<live_module_identity_t>
    query_module(const live_process_identity_t& process, std::uint64_t module_base,
                 const live_snapshot_operation_context_t& context) const override
    {
        ++module_queries_;
        if (context.cancellation.stop_requested()) {
            return live_snapshot_result_t<live_module_identity_t>::failure(
                make_live_snapshot_error(live_snapshot_error_code_t::cancelled, "fake_module"));
        }
        module_gate_.pass();
        if (process != process_) {
            return live_snapshot_result_t<live_module_identity_t>::failure(
                make_live_snapshot_error(live_snapshot_error_code_t::pid_reused, "fake_module",
                                         process.creation_identity, process_.creation_identity));
        }
        if (!module_present_ || module_base != module_.base) {
            return live_snapshot_result_t<live_module_identity_t>::failure(
                make_live_snapshot_error(live_snapshot_error_code_t::module_unloaded, "fake_module"));
        }
        return live_snapshot_result_t<live_module_identity_t>::success(module_);
    }

    live_snapshot_result_t<live_snapshot_adapter_page_t>
    read_page(const live_process_identity_t& process, const live_module_identity_t& module,
              std::uint64_t address, std::uint64_t size,
              const live_snapshot_operation_context_t& context) const override
    {
        if (context.cancellation.stop_requested()) {
            return live_snapshot_result_t<live_snapshot_adapter_page_t>::failure(
                make_live_snapshot_error(live_snapshot_error_code_t::cancelled, "fake_read"));
        }
        read_gate_.pass();
        if (process != process_) {
            return live_snapshot_result_t<live_snapshot_adapter_page_t>::failure(
                make_live_snapshot_error(live_snapshot_error_code_t::pid_reused, "fake_read",
                                         process.creation_identity, process_.creation_identity));
        }
        if (!module_present_) {
            return live_snapshot_result_t<live_snapshot_adapter_page_t>::failure(
                make_live_snapshot_error(live_snapshot_error_code_t::module_unloaded, "fake_read"));
        }
        if (module != module_) {
            return live_snapshot_result_t<live_snapshot_adapter_page_t>::failure(
                make_live_snapshot_error(live_snapshot_error_code_t::module_remapped, "fake_read",
                                         module.mapping_identity, module_.mapping_identity));
        }
        if (address < module_.base || size == 0 || size > module_.size ||
            address - module_.base > module_.size - size) {
            return live_snapshot_result_t<live_snapshot_adapter_page_t>::failure(
                make_live_snapshot_error(live_snapshot_error_code_t::range_invalid, "fake_read"));
        }
        const auto offset = static_cast<std::size_t>(address - module_.base);
        const auto count = static_cast<std::size_t>(size);
        live_snapshot_adapter_page_t page;
        page.address = address;
        page.bytes.assign(memory_.begin() + offset, memory_.begin() + offset + count);
        if (partial_read_ && !page.bytes.empty())
            page.bytes.pop_back();
        ++page_reads_;
        if (pid_reuse_after_read_)
            ++process_.creation_identity;
        if (module_unload_after_read_)
            module_present_ = false;
        if (module_remap_after_read_)
            remap_now();
        clock_->advance(read_elapsed_);
        return live_snapshot_result_t<live_snapshot_adapter_page_t>::success(std::move(page));
    }

private:
    std::shared_ptr<manual_clock_t> clock_;
    mutable live_process_identity_t process_{};
    mutable live_module_identity_t module_{};
    std::vector<std::uint8_t> memory_;
    mutable bool module_present_ = true;
    mutable bool partial_read_ = false;
    mutable bool pid_reuse_after_read_ = false;
    mutable bool module_unload_after_read_ = false;
    mutable bool module_remap_after_read_ = false;
    mutable std::chrono::milliseconds read_elapsed_{0};
    mutable std::uint64_t page_reads_ = 0;
    mutable std::uint64_t process_queries_ = 0;
    mutable std::uint64_t module_queries_ = 0;
    blocking_gate_t process_gate_;
    blocking_gate_t module_gate_;
    blocking_gate_t read_gate_;
};

live_request_budget_limits_t make_limits()
{
    live_request_budget_limits_t limits;
    limits.maximum_result_bytes = 64U;
    limits.maximum_adapter_bytes = 64U;
    limits.maximum_pages_per_request = 4U;
    limits.maximum_page_bytes = 16U;
    limits.maximum_cached_pages = 2U;
    limits.maximum_cached_bytes = 32U;
    limits.maximum_elapsed = std::chrono::milliseconds(1000);
    return limits;
}

live_snapshot_request_t make_request(const fake_live_snapshot_adapter_t& adapter,
                                     live_request_budget_limits_t limits)
{
    live_snapshot_request_t request;
    request.process = adapter.process();
    request.module = adapter.module();
    request.window_base = request.module.base;
    request.window_size = 0x60U;
    request.limits = limits;
    return request;
}

std::shared_ptr<live_snapshot_provider_t> open_provider(
    const std::shared_ptr<fake_live_snapshot_adapter_t>& adapter,
    const std::shared_ptr<manual_clock_t>& clock, live_request_budget_limits_t limits = make_limits())
{
    auto result = live_snapshot_provider_t::open(adapter, make_request(*adapter, limits), clock);
    require(result.has_value(), "fake live snapshot provider failed to open");
    return std::move(result).take_value();
}

template <typename value_t>
void require_gate_entry(blocking_gate_t& gate, std::future<value_t>& pending,
                        std::string_view message)
{
    if (gate.wait_for_entry(std::chrono::seconds(2)))
        return;
    gate.release();
    pending.wait();
    throw std::runtime_error(std::string(message));
}

template <typename value_t>
value_t finish_while_gate_blocked(blocking_gate_t& gate, std::future<value_t>& pending,
                                  std::string_view timeout_message,
                                  std::string_view departure_message)
{
    const bool completed = pending.wait_for(std::chrono::seconds(2)) == std::future_status::ready;
    gate.release();
    if (!completed) {
        pending.wait();
        gate.wait_for_departure(std::chrono::seconds(2));
        throw std::runtime_error(std::string(timeout_message));
    }
    auto result = pending.get();
    require(gate.wait_for_departure(std::chrono::seconds(2)), departure_message);
    return result;
}

void verify_no_bulk_baseline_and_bounded_cache()
{
    const auto clock = std::make_shared<manual_clock_t>();
    const auto adapter = std::make_shared<fake_live_snapshot_adapter_t>(clock);
    const auto provider = open_provider(adapter, clock);
    require(adapter->page_reads() == 0, "opening a snapshot performed a bulk memory read");

    const auto first = provider->read(adapter->module().base + 4U, 4U);
    require(first && first.value().bytes == std::vector<std::uint8_t>({4U, 5U, 6U, 7U}),
            "first page read returned incorrect bytes");
    require(adapter->page_reads() == 1, "first snapshot read did not issue exactly one page read");

    const auto cached = provider->read(adapter->module().base + 4U, 4U);
    require(cached && adapter->page_reads() == 1,
            "cached snapshot read re-read a live page");

    require(provider->read(adapter->module().base + 0x20U, 1U),
            "second page read failed");
    require(provider->read(adapter->module().base + 0x40U, 1U),
            "third page read failed");
    const auto stats = provider->cache_stats();
    require(stats.cached_pages == 2U && stats.cached_bytes == 32U && stats.cache_hits == 1U &&
                stats.cache_misses == 3U && stats.cache_evictions == 1U,
            "bounded page cache counters or capacity drifted");
}

void verify_pid_reuse_and_stale_snapshot_rejection()
{
    const auto reuse_clock = std::make_shared<manual_clock_t>();
    const auto reuse_adapter = std::make_shared<fake_live_snapshot_adapter_t>(reuse_clock);
    reuse_adapter->set_pid_reuse_after_read(true);
    const auto reuse_provider = open_provider(reuse_adapter, reuse_clock);
    const auto reuse = reuse_provider->read(reuse_adapter->module().base, 1U);
    require(!reuse && reuse.error().code == live_snapshot_error_code_t::pid_reused,
            "PID reuse after a page read was accepted");
    require(reuse_provider->cache_stats().cached_pages == 0U,
            "PID reuse retained cache data from the stale identity");

    const auto stale_clock = std::make_shared<manual_clock_t>();
    const auto stale_adapter = std::make_shared<fake_live_snapshot_adapter_t>(stale_clock);
    const auto stale_provider = open_provider(stale_adapter, stale_clock);
    stale_adapter->remap_now();
    const auto stale = stale_provider->read(stale_adapter->module().base, 1U);
    require(!stale && stale.error().code == live_snapshot_error_code_t::module_remapped,
            "stale module snapshot was accepted before a live page read");
    require(stale_adapter->page_reads() == 0U,
            "stale module snapshot issued a live page read");
}

void verify_partial_unload_and_remap_rejection()
{
    const auto partial_clock = std::make_shared<manual_clock_t>();
    const auto partial_adapter = std::make_shared<fake_live_snapshot_adapter_t>(partial_clock);
    partial_adapter->set_partial_read(true);
    const auto partial_provider = open_provider(partial_adapter, partial_clock);
    const auto partial = partial_provider->read(partial_adapter->module().base, 1U);
    require(!partial && partial.error().code == live_snapshot_error_code_t::partial_read &&
                partial.error().expected == 16U && partial.error().actual == 15U,
            "partial page read was accepted");

    const auto unload_clock = std::make_shared<manual_clock_t>();
    const auto unload_adapter = std::make_shared<fake_live_snapshot_adapter_t>(unload_clock);
    unload_adapter->set_module_unload_after_read(true);
    const auto unload_provider = open_provider(unload_adapter, unload_clock);
    const auto unload = unload_provider->read(unload_adapter->module().base, 1U);
    require(!unload && unload.error().code == live_snapshot_error_code_t::module_unloaded,
            "module unload after a page read was accepted");
    require(unload_provider->cache_stats().cached_pages == 0U,
            "module unload retained cache data from the stale identity");

    const auto remap_clock = std::make_shared<manual_clock_t>();
    const auto remap_adapter = std::make_shared<fake_live_snapshot_adapter_t>(remap_clock);
    remap_adapter->set_module_remap_after_read(true);
    const auto remap_provider = open_provider(remap_adapter, remap_clock);
    const auto remap = remap_provider->read(remap_adapter->module().base, 1U);
    require(!remap && remap.error().code == live_snapshot_error_code_t::module_remapped,
            "module remap after a page read was accepted");
    require(remap_provider->cache_stats().cached_pages == 0U,
            "module remap retained cache data from the stale identity");
}

void verify_request_page_adapter_and_time_caps()
{
    auto page_limits = make_limits();
    page_limits.maximum_pages_per_request = 1U;
    const auto page_clock = std::make_shared<manual_clock_t>();
    const auto page_adapter = std::make_shared<fake_live_snapshot_adapter_t>(page_clock);
    const auto page_provider = open_provider(page_adapter, page_clock, page_limits);
    const auto page = page_provider->read(page_adapter->module().base + 15U, 2U);
    require(!page && page.error().code == live_snapshot_error_code_t::page_limit_exceeded &&
                page_adapter->page_reads() == 0U,
            "multi-page request exceeded its cap after a live read");

    auto result_limits = make_limits();
    result_limits.maximum_result_bytes = 8U;
    const auto result_clock = std::make_shared<manual_clock_t>();
    const auto result_adapter = std::make_shared<fake_live_snapshot_adapter_t>(result_clock);
    const auto result_provider = open_provider(result_adapter, result_clock, result_limits);
    const auto oversized = result_provider->read(result_adapter->module().base, 9U);
    require(!oversized && oversized.error().code == live_snapshot_error_code_t::result_byte_limit_exceeded &&
                result_adapter->page_reads() == 0U,
            "result byte cap was not enforced before a live read");

    auto adapter_limits = make_limits();
    adapter_limits.maximum_adapter_bytes = 16U;
    const auto adapter_clock = std::make_shared<manual_clock_t>();
    const auto adapter = std::make_shared<fake_live_snapshot_adapter_t>(adapter_clock);
    const auto adapter_provider = open_provider(adapter, adapter_clock, adapter_limits);
    const auto adapter_cap = adapter_provider->read(adapter->module().base, 17U);
    require(!adapter_cap && adapter_cap.error().code == live_snapshot_error_code_t::adapter_byte_limit_exceeded &&
                adapter->page_reads() == 1U,
            "adapter byte cap was not enforced between bounded pages");

    auto time_limits = make_limits();
    time_limits.maximum_elapsed = std::chrono::milliseconds(250);
    const auto time_clock = std::make_shared<manual_clock_t>();
    const auto time_adapter = std::make_shared<fake_live_snapshot_adapter_t>(time_clock);
    time_adapter->set_read_elapsed(std::chrono::milliseconds(300));
    const auto time_provider = open_provider(time_adapter, time_clock, time_limits);
    const auto timed = time_provider->read(time_adapter->module().base, 1U);
    require(!timed && timed.error().code == live_snapshot_error_code_t::deadline_exceeded,
             "request time cap was not enforced after a live page read");
}

void verify_hard_bounded_adapter_calls_and_cache_scope()
{
    auto open_limits = make_limits();
    open_limits.maximum_elapsed = std::chrono::milliseconds(250);

    const auto process_clock = std::make_shared<manual_clock_t>();
    const auto process_adapter = std::make_shared<fake_live_snapshot_adapter_t>(process_clock);
    const auto process_request = make_request(*process_adapter, open_limits);
    process_adapter->process_gate().arm();
    auto process_pending = std::async(
        std::launch::async, [process_adapter, process_clock, process_request] {
            return live_snapshot_provider_t::open(process_adapter, process_request, process_clock);
        });
    require_gate_entry(process_adapter->process_gate(), process_pending,
                       "process adapter call did not enter its blocking gate");
    const auto process_result = finish_while_gate_blocked(
        process_adapter->process_gate(), process_pending,
        "process adapter call exceeded its hard deadline",
        "process adapter call did not leave its blocking gate");
    require(!process_result &&
                process_result.error().code == live_snapshot_error_code_t::deadline_exceeded,
            "blocked process adapter call did not return deadline_exceeded");

    const auto module_clock = std::make_shared<manual_clock_t>();
    const auto module_adapter = std::make_shared<fake_live_snapshot_adapter_t>(module_clock);
    const auto module_request = make_request(*module_adapter, open_limits);
    module_adapter->module_gate().arm();
    auto module_pending = std::async(
        std::launch::async, [module_adapter, module_clock, module_request] {
            return live_snapshot_provider_t::open(module_adapter, module_request, module_clock);
        });
    require_gate_entry(module_adapter->module_gate(), module_pending,
                       "module adapter call did not enter its blocking gate");
    const auto module_result = finish_while_gate_blocked(
        module_adapter->module_gate(), module_pending,
        "module adapter call exceeded its hard deadline",
        "module adapter call did not leave its blocking gate");
    require(!module_result &&
                module_result.error().code == live_snapshot_error_code_t::deadline_exceeded,
            "blocked module adapter call did not return deadline_exceeded");

    auto read_limits = make_limits();
    read_limits.maximum_elapsed = std::chrono::milliseconds(500);
    const auto read_clock = std::make_shared<manual_clock_t>();
    const auto read_adapter = std::make_shared<fake_live_snapshot_adapter_t>(read_clock);
    const auto read_provider = open_provider(read_adapter, read_clock, read_limits);
    const auto read_address = read_adapter->module().base;
    read_adapter->read_gate().arm();
    auto read_pending = std::async(std::launch::async, [read_provider, read_address] {
        return read_provider->read(read_address, 1U);
    });
    require_gate_entry(read_adapter->read_gate(), read_pending,
                       "page adapter call did not enter its blocking gate");

    auto stats_pending = std::async(std::launch::async, [read_provider] {
        return read_provider->cache_stats();
    });
    const bool stats_ready =
        stats_pending.wait_for(std::chrono::milliseconds(100)) == std::future_status::ready;
    if (!stats_ready) {
        read_adapter->read_gate().release();
        read_pending.wait();
        stats_pending.wait();
        read_adapter->read_gate().wait_for_departure(std::chrono::seconds(2));
        throw std::runtime_error("cache mutex remained held across a blocking adapter read");
    }
    const auto blocked_stats = stats_pending.get();
    require(blocked_stats.cached_pages == 0U && blocked_stats.cached_bytes == 0U,
            "blocking adapter read published cache data before completion");

    const auto read_result = finish_while_gate_blocked(
        read_adapter->read_gate(), read_pending,
        "page adapter call exceeded its hard deadline",
        "page adapter call did not leave its blocking gate");
    require(!read_result &&
                read_result.error().code == live_snapshot_error_code_t::deadline_exceeded,
            "blocked page adapter call did not return deadline_exceeded");

    const auto cancel_clock = std::make_shared<manual_clock_t>();
    const auto cancel_adapter = std::make_shared<fake_live_snapshot_adapter_t>(cancel_clock);
    const auto cancel_provider = open_provider(cancel_adapter, cancel_clock);
    const auto cancel_address = cancel_adapter->module().base;
    live_snapshot_cancellation_source_t source;
    const auto token = source.token();
    cancel_adapter->read_gate().arm();
    auto cancel_pending = std::async(
        std::launch::async, [cancel_provider, cancel_address, token] {
            return cancel_provider->read(cancel_address, 1U, token);
        });
    require_gate_entry(cancel_adapter->read_gate(), cancel_pending,
                       "cancelled page adapter call did not enter its blocking gate");
    source.request_stop();
    const auto cancel_result = finish_while_gate_blocked(
        cancel_adapter->read_gate(), cancel_pending,
        "page adapter call ignored hard cancellation",
        "cancelled page adapter call did not leave its blocking gate");
    require(!cancel_result &&
                cancel_result.error().code == live_snapshot_error_code_t::cancelled,
            "blocked page adapter call did not return cancelled");
}

void verify_cancellation()
{
    const auto clock = std::make_shared<manual_clock_t>();
    const auto adapter = std::make_shared<fake_live_snapshot_adapter_t>(clock);
    const auto provider = open_provider(adapter, clock);
    live_snapshot_cancellation_source_t source;
    source.request_stop();
    const auto cancelled = provider->read(adapter->module().base, 1U, source.token());
    require(!cancelled && cancelled.error().code == live_snapshot_error_code_t::cancelled &&
                adapter->page_reads() == 0U,
            "cancelled request issued a live page read");
}

}

void run_live_snapshot_harness()
{
    verify_no_bulk_baseline_and_bounded_cache();
    verify_pid_reuse_and_stale_snapshot_rejection();
    verify_partial_unload_and_remap_rejection();
    verify_request_page_adapter_and_time_caps();
    verify_hard_bounded_adapter_calls_and_cache_scope();
    verify_cancellation();
}

}

int main()
{
    try {
        aida::analysis::c03_test::run_live_snapshot_harness();
        std::cout << "live_snapshot_harness source contract satisfied\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
