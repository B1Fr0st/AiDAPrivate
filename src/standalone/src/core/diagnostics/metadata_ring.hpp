#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>

#include "../../helpers/diag_log.hpp"

namespace aida::diagnostics {

inline constexpr std::size_t kMetadataRingCapacity = 512;
inline constexpr std::size_t kMetadataRingMaxLabelLen = 96;
inline constexpr std::size_t kMetadataRingMaxReasonLen = 128;
inline constexpr std::size_t kMetadataRingRateLimitMs = 200;

enum class breadcrumb_category_t : std::uint8_t {
    startup_shutdown = 0,
    message_pump = 1,
    wndproc = 2,
    render = 3,
    ui_dispatcher = 4,
    mcp_ingress = 5,
    mcp_tool_call = 6,
    mcp_lease = 7,
    capacity_governor = 8,
    downstream_producer = 9,
    work_queue = 10,
    critical_queue = 11,
    service_queue = 12,
    thread_runtime = 13,
    testlab = 14,
    driver_debugger = 15,
    license_arc_watchdog = 16,
    camoufox = 17,
    background_command = 18,
    crash_exception = 19,
    observer = 20,
    count
};

inline const char* category_name(breadcrumb_category_t c) {
    switch (c) {
    case breadcrumb_category_t::startup_shutdown: return "startup_shutdown";
    case breadcrumb_category_t::message_pump: return "message_pump";
    case breadcrumb_category_t::wndproc: return "wndproc";
    case breadcrumb_category_t::render: return "render";
    case breadcrumb_category_t::ui_dispatcher: return "ui_dispatcher";
    case breadcrumb_category_t::mcp_ingress: return "mcp_ingress";
    case breadcrumb_category_t::mcp_tool_call: return "mcp_tool_call";
    case breadcrumb_category_t::mcp_lease: return "mcp_lease";
    case breadcrumb_category_t::capacity_governor: return "capacity_governor";
    case breadcrumb_category_t::downstream_producer: return "downstream_producer";
    case breadcrumb_category_t::work_queue: return "work_queue";
    case breadcrumb_category_t::critical_queue: return "critical_queue";
    case breadcrumb_category_t::service_queue: return "service_queue";
    case breadcrumb_category_t::thread_runtime: return "thread_runtime";
    case breadcrumb_category_t::testlab: return "testlab";
    case breadcrumb_category_t::driver_debugger: return "driver_debugger";
    case breadcrumb_category_t::license_arc_watchdog: return "license_arc_watchdog";
    case breadcrumb_category_t::camoufox: return "camoufox";
    case breadcrumb_category_t::background_command: return "background_command";
    case breadcrumb_category_t::crash_exception: return "crash_exception";
    case breadcrumb_category_t::observer: return "observer";
    default: return "unknown";
    }
}

struct breadcrumb_t {
    std::uint64_t event_id;
    std::uint64_t timestamp_ms;
    std::uint64_t elapsed_ms;
    std::uint64_t monotonic_start_ms;
    breadcrumb_category_t category;
    std::uint8_t pid_high;
    std::uint8_t priority;
    DWORD pid;
    DWORD tid;
    char label[kMetadataRingMaxLabelLen];
    char reason[kMetadataRingMaxReasonLen];
    char owner_subsystem[48];
    char tool_or_request_id[64];
    char session_or_target[64];
    std::uint64_t lease_token;
    std::uint64_t generation;
    std::uint16_t status_code;
};

struct ring_t {
    breadcrumb_t entries[kMetadataRingCapacity];
    std::atomic<std::uint64_t> write_index{0};
    std::atomic<std::uint64_t> total_events{0};
    std::atomic<std::uint64_t> dropped_events{0};
    std::atomic<std::uint64_t> rate_limited_events{0};
    std::atomic<bool> shutdown_requested{false};
    std::atomic<std::uint64_t> monotonic_start{0};
    std::mutex rate_mutex;
    std::uint64_t last_emit_per_category[static_cast<std::size_t>(breadcrumb_category_t::count)] = {};
    std::uint64_t category_counts[static_cast<std::size_t>(breadcrumb_category_t::count)] = {};

    ring_t() {
        monotonic_start.store(static_cast<std::uint64_t>(GetTickCount64()), std::memory_order_release);
        std::memset(entries, 0, sizeof(entries));
        std::memset(last_emit_per_category, 0, sizeof(last_emit_per_category));
        std::memset(category_counts, 0, sizeof(category_counts));
    }
};

inline ring_t& global_ring() {
    static ring_t ring;
    return ring;
}

inline std::uint64_t now_ms() {
    return static_cast<std::uint64_t>(GetTickCount64());
}

inline std::uint64_t elapsed_ms() {
    const std::uint64_t start = global_ring().monotonic_start.load(std::memory_order_acquire);
    const std::uint64_t now = now_ms();
    return now >= start ? now - start : 0;
}

inline void copy_truncated(char* dst, std::size_t dst_size, const char* src) {
    if (!dst || dst_size == 0) return;
    if (!src || src[0] == '\0') { dst[0] = '\0'; return; }
    const std::size_t src_len = std::strlen(src);
    const std::size_t copy_len = src_len < dst_size - 1 ? src_len : dst_size - 1;
    std::memcpy(dst, src, copy_len);
    dst[copy_len] = '\0';
}

inline bool should_rate_limit(breadcrumb_category_t category) {
    const auto cat_idx = static_cast<std::size_t>(category);
    if (cat_idx >= static_cast<std::size_t>(breadcrumb_category_t::count))
        return false;
    auto& ring = global_ring();
    const std::uint64_t now = now_ms();
    std::lock_guard<std::mutex> lk(ring.rate_mutex);
    const std::uint64_t last = ring.last_emit_per_category[cat_idx];
    if (last != 0 && now > last && now - last < kMetadataRingRateLimitMs) {
        ring.rate_limited_events.fetch_add(1, std::memory_order_relaxed);
        return true;
    }
    ring.last_emit_per_category[cat_idx] = now;
    return false;
}

struct breadcrumb_options_t {
    breadcrumb_category_t category = breadcrumb_category_t::startup_shutdown;
    const char* label = nullptr;
    const char* reason = nullptr;
    const char* owner_subsystem = nullptr;
    const char* tool_or_request_id = nullptr;
    const char* session_or_target = nullptr;
    std::uint64_t lease_token = 0;
    std::uint64_t generation = 0;
    std::uint16_t status_code = 0;
    std::uint8_t priority = 0;
    bool force = false;
};

inline void emit(breadcrumb_options_t&& opts) {
    if (!opts.force && should_rate_limit(opts.category))
        return;

    auto& ring = global_ring();
    if (ring.shutdown_requested.load(std::memory_order_acquire))
        return;

    const std::uint64_t idx = ring.write_index.fetch_add(1, std::memory_order_acq_rel);
    const std::size_t slot = idx % kMetadataRingCapacity;
    const std::uint64_t eid = ring.total_events.fetch_add(1, std::memory_order_acq_rel) + 1;
    const std::uint64_t ts = now_ms();
    const std::uint64_t el = elapsed_ms();

    breadcrumb_t& entry = ring.entries[slot];
    entry.event_id = eid;
    entry.timestamp_ms = ts;
    entry.elapsed_ms = el;
    entry.monotonic_start_ms = ring.monotonic_start.load(std::memory_order_acquire);
    entry.category = opts.category;
    entry.priority = opts.priority;
    entry.pid = GetCurrentProcessId();
    entry.tid = GetCurrentThreadId();
    entry.lease_token = opts.lease_token;
    entry.generation = opts.generation;
    entry.status_code = opts.status_code;
    copy_truncated(entry.label, kMetadataRingMaxLabelLen, opts.label ? opts.label : "");
    copy_truncated(entry.reason, kMetadataRingMaxReasonLen, opts.reason ? opts.reason : "");
    copy_truncated(entry.owner_subsystem, sizeof(entry.owner_subsystem), opts.owner_subsystem ? opts.owner_subsystem : "");
    copy_truncated(entry.tool_or_request_id, sizeof(entry.tool_or_request_id), opts.tool_or_request_id ? opts.tool_or_request_id : "");
    copy_truncated(entry.session_or_target, sizeof(entry.session_or_target), opts.session_or_target ? opts.session_or_target : "");

    const auto cat_idx = static_cast<std::size_t>(opts.category);
    if (cat_idx < static_cast<std::size_t>(breadcrumb_category_t::count)) {
        std::lock_guard<std::mutex> lk(ring.rate_mutex);
        ring.category_counts[cat_idx]++;
    }

    diag::log_tagged_fmt("diag",
        "METADATA-RING-EVENT id=%llu cat=%s label=%s reason=%s owner=%s tool_req=%s sess_tgt=%s pid=%lu tid=%lu ts=%llu elapsed=%llu lease=%llu gen=%llu status=%u pri=%u",
        static_cast<unsigned long long>(eid),
        category_name(opts.category),
        opts.label ? opts.label : "<none>",
        opts.reason ? opts.reason : "<none>",
        opts.owner_subsystem ? opts.owner_subsystem : "<none>",
        opts.tool_or_request_id ? opts.tool_or_request_id : "<none>",
        opts.session_or_target ? opts.session_or_target : "<none>",
        static_cast<unsigned long>(entry.pid),
        static_cast<unsigned long>(entry.tid),
        static_cast<unsigned long long>(ts),
        static_cast<unsigned long long>(el),
        static_cast<unsigned long long>(opts.lease_token),
        static_cast<unsigned long long>(opts.generation),
        static_cast<unsigned>(opts.status_code),
        static_cast<unsigned>(opts.priority));
}

inline void emit(breadcrumb_category_t category, const char* label, const char* reason = nullptr, bool force = false) {
    breadcrumb_options_t opts;
    opts.category = category;
    opts.label = label;
    opts.reason = reason;
    opts.force = force;
    emit(std::move(opts));
}

inline void request_shutdown() {
    global_ring().shutdown_requested.store(true, std::memory_order_release);
}

struct ring_snapshot_t {
    std::uint64_t total_events;
    std::uint64_t dropped_events;
    std::uint64_t rate_limited_events;
    std::uint64_t write_index;
    std::uint64_t monotonic_start_ms;
    std::size_t capacity;
    std::size_t valid_entries;
    std::uint64_t category_counts[static_cast<std::size_t>(breadcrumb_category_t::count)];
    breadcrumb_t entries[kMetadataRingCapacity];
};

inline ring_snapshot_t snapshot(std::size_t max_entries = kMetadataRingCapacity) {
    ring_snapshot_t snap{};
    auto& ring = global_ring();
    snap.total_events = ring.total_events.load(std::memory_order_acquire);
    snap.dropped_events = ring.dropped_events.load(std::memory_order_acquire);
    snap.rate_limited_events = ring.rate_limited_events.load(std::memory_order_acquire);
    snap.write_index = ring.write_index.load(std::memory_order_acquire);
    snap.monotonic_start_ms = ring.monotonic_start.load(std::memory_order_acquire);
    snap.capacity = kMetadataRingCapacity;

    {
        std::lock_guard<std::mutex> lk(ring.rate_mutex);
        std::memcpy(snap.category_counts, ring.category_counts, sizeof(snap.category_counts));
    }

    const std::uint64_t current_write = snap.write_index;
    const std::size_t total_valid = static_cast<std::size_t>(
        current_write < kMetadataRingCapacity ? current_write : kMetadataRingCapacity);
    const std::size_t to_copy = total_valid < max_entries ? total_valid : max_entries;

    if (to_copy > 0 && current_write > 0) {
        const std::size_t start_idx = current_write >= to_copy
            ? static_cast<std::size_t>((current_write - to_copy) % kMetadataRingCapacity)
            : 0;
        for (std::size_t i = 0; i < to_copy; ++i) {
            const std::size_t src = (start_idx + i) % kMetadataRingCapacity;
            snap.entries[i] = ring.entries[src];
        }
        snap.valid_entries = to_copy;
    }

    return snap;
}

inline void dump_to_log(std::size_t max_entries = 64) {
    auto snap = snapshot(max_entries);
    diag::log_tagged_critical_fmt("diag",
        "METADATA-RING-DUMP total=%llu dropped=%llu rate_limited=%llu write_index=%llu capacity=%zu valid=%zu monotonic_start=%llu pid=%lu",
        static_cast<unsigned long long>(snap.total_events),
        static_cast<unsigned long long>(snap.dropped_events),
        static_cast<unsigned long long>(snap.rate_limited_events),
        static_cast<unsigned long long>(snap.write_index),
        snap.capacity,
        snap.valid_entries,
        static_cast<unsigned long long>(snap.monotonic_start_ms),
        static_cast<unsigned long>(GetCurrentProcessId()));

    for (std::size_t i = 0; i < snap.valid_entries; ++i) {
        const auto& e = snap.entries[i];
        diag::log_tagged_fmt("diag",
            "METADATA-RING-DUMP-ENTRY idx=%zu id=%llu cat=%s label=%s reason=%s owner=%s pid=%lu tid=%lu ts=%llu elapsed=%llu lease=%llu gen=%llu status=%u",
            i,
            static_cast<unsigned long long>(e.event_id),
            category_name(e.category),
            e.label[0] ? e.label : "<none>",
            e.reason[0] ? e.reason : "<none>",
            e.owner_subsystem[0] ? e.owner_subsystem : "<none>",
            static_cast<unsigned long>(e.pid),
            static_cast<unsigned long>(e.tid),
            static_cast<unsigned long long>(e.timestamp_ms),
            static_cast<unsigned long long>(e.elapsed_ms),
            static_cast<unsigned long long>(e.lease_token),
            static_cast<unsigned long long>(e.generation),
            static_cast<unsigned>(e.status_code));
    }
}

inline std::string snapshot_json_string(std::size_t max_entries = 32) {
    auto snap = snapshot(max_entries);
    std::string out;
    out.reserve(4096 + snap.valid_entries * 256);
    char buf[512];
    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
        "{\"total_events\":%llu,\"dropped_events\":%llu,\"rate_limited_events\":%llu,\"write_index\":%llu,\"capacity\":%zu,\"valid_entries\":%zu,\"monotonic_start_ms\":%llu,\"entries\":[",
        static_cast<unsigned long long>(snap.total_events),
        static_cast<unsigned long long>(snap.dropped_events),
        static_cast<unsigned long long>(snap.rate_limited_events),
        static_cast<unsigned long long>(snap.write_index),
        snap.capacity,
        snap.valid_entries,
        static_cast<unsigned long long>(snap.monotonic_start_ms));
    out += buf;
    for (std::size_t i = 0; i < snap.valid_entries; ++i) {
        const auto& e = snap.entries[i];
        if (i > 0) out += ",";
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
            "{\"id\":%llu,\"cat\":\"%s\",\"label\":\"%s\",\"reason\":\"%s\",\"owner\":\"%s\",\"pid\":%lu,\"tid\":%lu,\"ts\":%llu,\"elapsed\":%llu,\"lease\":%llu,\"gen\":%llu,\"status\":%u}",
            static_cast<unsigned long long>(e.event_id),
            category_name(e.category),
            e.label[0] ? e.label : "",
            e.reason[0] ? e.reason : "",
            e.owner_subsystem[0] ? e.owner_subsystem : "",
            static_cast<unsigned long>(e.pid),
            static_cast<unsigned long>(e.tid),
            static_cast<unsigned long long>(e.timestamp_ms),
            static_cast<unsigned long long>(e.elapsed_ms),
            static_cast<unsigned long long>(e.lease_token),
            static_cast<unsigned long long>(e.generation),
            static_cast<unsigned>(e.status_code));
        out += buf;
    }
    out += "]}";
    return out;
}

inline std::string category_summary_string() {
    auto snap = snapshot(0);
    char buf[1024];
    std::string out;
    out.reserve(512);
    bool first = true;
    for (std::size_t i = 0; i < static_cast<std::size_t>(breadcrumb_category_t::count); ++i) {
        if (snap.category_counts[i] == 0) continue;
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
            "%s%s=%llu",
            first ? "" : ";",
            category_name(static_cast<breadcrumb_category_t>(i)),
            static_cast<unsigned long long>(snap.category_counts[i]));
        out += buf;
        first = false;
    }
    return out.empty() ? std::string("none") : out;
}

}
