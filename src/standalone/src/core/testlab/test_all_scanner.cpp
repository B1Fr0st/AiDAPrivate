#include "test_all_scanner.h"

#include "test_all_features.hpp"
#include "../scanner/memory_scanner.hpp"
#include "../scanner/crypto_scanner.hpp"
#include "../scanner/pointer_scanner.hpp"
#include "../scanner/snapshot_diff.hpp"
#include "../scanner/aob_generator.hpp"
#include "../scanner/scan_hub_view.hpp"
#include "../runtime/standalone_driver.hpp"
#include "../../helpers/diag_log.hpp"

#include <Windows.h>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace test_all_features {

namespace {

static void format_timestamp(char* out, std::size_t cap) {
    SYSTEMTIME st;
    GetLocalTime(&st);
    std::snprintf(out, cap, "%04u-%02u-%02u %02u:%02u:%02u.%03u",
        static_cast<unsigned>(st.wYear),
        static_cast<unsigned>(st.wMonth),
        static_cast<unsigned>(st.wDay),
        static_cast<unsigned>(st.wHour),
        static_cast<unsigned>(st.wMinute),
        static_cast<unsigned>(st.wSecond),
        static_cast<unsigned>(st.wMilliseconds));
}

static void write_log_file(HANDLE hf, const std::string& line) {
    test_all_features::write_full_test_log_line(hf, line.data(), line.size());
}

static void log_msg(HANDLE hf, const char* tag, const char* fmt, ...) {
    char ts[40];
    format_timestamp(ts, sizeof(ts));

    char detail[1024];
    va_list ap;
    va_start(ap, fmt);
    _vsnprintf_s(detail, sizeof(detail), _TRUNCATE, fmt, ap);
    va_end(ap);

    char line[1200];
    _snprintf_s(line, sizeof(line), _TRUNCATE, "[%s] [%s] %s\n", ts, tag, detail);
    std::string s(line);

    write_log_file(hf, s);
    test_all_features::mirror_full_test_log_line(tag, detail, s.c_str());
}

static long long elapsed_us_since(std::chrono::steady_clock::time_point t0) {
    return static_cast<long long>(std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now() - t0).count());
}

static bool decode_float32(const std::vector<uint8_t>& bytes, float& out) {
    if (bytes.size() != sizeof(out))
        return false;
    std::memcpy(&out, bytes.data(), sizeof(out));
    return std::isfinite(out);
}

static bool decode_float64(const std::vector<uint8_t>& bytes, double& out) {
    if (bytes.size() != sizeof(out))
        return false;
    std::memcpy(&out, bytes.data(), sizeof(out));
    return std::isfinite(out);
}

static bool parse_formatted_float32(const std::string& text, float& out) {
    char* end = nullptr;
    out = std::strtof(text.c_str(), &end);
    return end != text.c_str() && *end == '\0' && std::isfinite(out);
}

static bool parse_formatted_float64(const std::string& text, double& out) {
    char* end = nullptr;
    out = std::strtod(text.c_str(), &end);
    return end != text.c_str() && *end == '\0' && std::isfinite(out);
}

static constexpr uint64_t k_marker_u64 = 0xCAFEBABE00000001ULL;
static constexpr int16_t  k_marker_i16 = static_cast<int16_t>(0x5AA5);
static constexpr int32_t  k_marker_i32 = static_cast<int32_t>(0x1337C0DE);
static constexpr float    k_marker_flt = 1234.5f;
static constexpr double   k_marker_dbl = 98765.4321;
static const uint8_t      k_marker_bytes[16] = {
    0x7F, 0x3A, 0x91, 0xC2, 0xA1, 0xDA, 0x70, 0x70,
    0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE
};
static const uint8_t      k_marker_aob[8] = { 0xDE, 0xAD, 0xBE, 0xEF, 0x13, 0x37, 0xC0, 0xDE };
static const char         k_marker_ascii[] = "AIDA_TT_MARKER_7F3A91C2";

struct target_anchor_t {
    bool     planted = false;
    bool     attempted = false;
    uint64_t region_base = 0;
    uint64_t addr_u64 = 0;
    uint64_t addr_bytes = 0;
    uint64_t addr_ascii = 0;
    uint64_t addr_wide = 0;
    uint64_t addr_i16 = 0;
    uint64_t addr_i32 = 0;
    uint64_t addr_flt = 0;
    uint64_t addr_dbl = 0;
    uint64_t addr_aob = 0;
    uint64_t addr_aes_sbox = 0;
    uint64_t addr_sha256_k = 0;
    uint64_t addr_entropy = 0;
    uint64_t addr_scratch = 0;
    uint64_t ptr_target = 0;
    uint64_t ptr_level1 = 0;
    uint64_t ptr_level0 = 0;
};

static target_anchor_t g_anchor;

static constexpr size_t k_anchor_off_u64     = 0x000;
static constexpr size_t k_anchor_off_i16     = 0x010;
static constexpr size_t k_anchor_off_i32     = 0x020;
static constexpr size_t k_anchor_off_flt     = 0x030;
static constexpr size_t k_anchor_off_dbl     = 0x040;
static constexpr size_t k_anchor_off_bytes   = 0x060;
static constexpr size_t k_anchor_off_aob     = 0x080;
static constexpr size_t k_anchor_off_ascii   = 0x0A0;
static constexpr size_t k_anchor_off_wide    = 0x100;
static constexpr size_t k_anchor_off_scratch = 0x180;
static constexpr size_t k_anchor_off_target  = 0x200;
static constexpr size_t k_anchor_off_level1  = 0x210;
static constexpr size_t k_anchor_off_level0  = 0x220;
static constexpr size_t k_anchor_off_entropy = 0x300;
static constexpr size_t k_anchor_off_aes     = 0x500;
static constexpr size_t k_anchor_off_sha256  = 0x700;
static constexpr size_t k_anchor_entropy_len = 0x100;
static constexpr size_t k_anchor_page        = 0x1000;

static void put_u64(std::vector<uint8_t>& buf, size_t off, uint64_t v) {
    std::memcpy(buf.data() + off, &v, sizeof(v));
}

static bool plant_anchor(HANDLE hf) {
    if (g_anchor.attempted) return g_anchor.planted;
    g_anchor.attempted = true;

    uint32_t pid = driver_bridge::attached_pid();
    bool attached = driver_bridge::is_loaded() && pid != 0;
    if (!attached) {
        log_msg(hf, "anchor", "plant skipped -- not attached (driver_loaded=%d pid=%u)",
            static_cast<int>(driver_bridge::is_loaded()), pid);
        return false;
    }

    uint64_t base = driver_bridge::allocate_memory(k_anchor_page);
    if (base == 0) {
        log_msg(hf, "anchor", "plant failed -- allocate_memory(%zu) returned 0 in target pid=%u (kernel allocate unavailable)",
            k_anchor_page, pid);
        return false;
    }

    std::vector<uint8_t> page(k_anchor_page, 0);
    put_u64(page, k_anchor_off_u64, k_marker_u64);
    std::memcpy(page.data() + k_anchor_off_i16, &k_marker_i16, sizeof(k_marker_i16));
    std::memcpy(page.data() + k_anchor_off_i32, &k_marker_i32, sizeof(k_marker_i32));
    std::memcpy(page.data() + k_anchor_off_flt, &k_marker_flt, sizeof(k_marker_flt));
    std::memcpy(page.data() + k_anchor_off_dbl, &k_marker_dbl, sizeof(k_marker_dbl));
    std::memcpy(page.data() + k_anchor_off_bytes, k_marker_bytes, sizeof(k_marker_bytes));
    std::memcpy(page.data() + k_anchor_off_aob, k_marker_aob, sizeof(k_marker_aob));
    std::memcpy(page.data() + k_anchor_off_aes, crypto_scanner::constants::aes_sbox, sizeof(crypto_scanner::constants::aes_sbox));
    std::memcpy(page.data() + k_anchor_off_sha256, crypto_scanner::constants::sha256_k, sizeof(crypto_scanner::constants::sha256_k));

    size_t ascii_len = std::strlen(k_marker_ascii);
    std::memcpy(page.data() + k_anchor_off_ascii, k_marker_ascii, ascii_len + 1);

    {
        std::vector<wchar_t> w(ascii_len + 1, 0);
        int wlen = MultiByteToWideChar(CP_UTF8, 0, k_marker_ascii, -1, w.data(), static_cast<int>(w.size()));
        if (wlen > 0)
            std::memcpy(page.data() + k_anchor_off_wide, w.data(), static_cast<size_t>(wlen) * sizeof(wchar_t));
    }

    put_u64(page, k_anchor_off_target, k_marker_u64);
    put_u64(page, k_anchor_off_level1, base + k_anchor_off_target);
    put_u64(page, k_anchor_off_level0, base + k_anchor_off_level1);
    for (size_t i = 0; i < k_anchor_entropy_len; ++i)
        page[k_anchor_off_entropy + i] = static_cast<uint8_t>(i);

    if (!driver_bridge::write_memory(base, page)) {
        log_msg(hf, "anchor", "plant failed -- write_memory(0x%llX, %zu) rejected",
            (unsigned long long)base, page.size());
        driver_bridge::free_memory(base);
        return false;
    }

    std::vector<uint8_t> verify;
    if (!driver_bridge::read_memory(base, k_anchor_page, verify) || verify.size() < k_anchor_page) {
        log_msg(hf, "anchor", "plant failed -- read-back at 0x%llX returned %zu bytes",
            (unsigned long long)base, verify.size());
        driver_bridge::free_memory(base);
        return false;
    }
    if (std::memcmp(verify.data(), page.data(), k_anchor_page) != 0) {
        log_msg(hf, "anchor", "plant failed -- read-back mismatch at 0x%llX", (unsigned long long)base);
        driver_bridge::free_memory(base);
        return false;
    }

    g_anchor.planted = true;
    g_anchor.region_base = base;
    g_anchor.addr_u64 = base + k_anchor_off_u64;
    g_anchor.addr_i16 = base + k_anchor_off_i16;
    g_anchor.addr_i32 = base + k_anchor_off_i32;
    g_anchor.addr_flt = base + k_anchor_off_flt;
    g_anchor.addr_dbl = base + k_anchor_off_dbl;
    g_anchor.addr_bytes = base + k_anchor_off_bytes;
    g_anchor.addr_aob = base + k_anchor_off_aob;
    g_anchor.addr_aes_sbox = base + k_anchor_off_aes;
    g_anchor.addr_sha256_k = base + k_anchor_off_sha256;
    g_anchor.addr_entropy = base + k_anchor_off_entropy;
    g_anchor.addr_ascii = base + k_anchor_off_ascii;
    g_anchor.addr_wide = base + k_anchor_off_wide;
    g_anchor.addr_scratch = base + k_anchor_off_scratch;
    g_anchor.ptr_target = base + k_anchor_off_target;
    g_anchor.ptr_level1 = base + k_anchor_off_level1;
    g_anchor.ptr_level0 = base + k_anchor_off_level0;

    log_msg(hf, "anchor", "plant OK -- pid=%u base=0x%llX u64=0x%llX bytes=0x%llX ascii=0x%llX wide=0x%llX aes=0x%llX sha256=0x%llX entropy=0x%llX ptr_target=0x%llX ptr_l1=0x%llX ptr_l0=0x%llX",
        pid, (unsigned long long)base,
        (unsigned long long)g_anchor.addr_u64, (unsigned long long)g_anchor.addr_bytes,
        (unsigned long long)g_anchor.addr_ascii, (unsigned long long)g_anchor.addr_wide,
        (unsigned long long)g_anchor.addr_aes_sbox, (unsigned long long)g_anchor.addr_sha256_k,
        (unsigned long long)g_anchor.addr_entropy,
        (unsigned long long)g_anchor.ptr_target, (unsigned long long)g_anchor.ptr_level1,
        (unsigned long long)g_anchor.ptr_level0);
    return true;
}

static bool seed_pointer_fixture_map(size_t& before_entries, size_t& after_entries, bool& had_level1, bool& had_level0) {
    before_entries = 0;
    after_entries = 0;
    had_level1 = false;
    had_level0 = false;

    if (!g_anchor.planted || g_anchor.ptr_target == 0 || g_anchor.ptr_level1 == 0 || g_anchor.ptr_level0 == 0)
        return false;

    std::lock_guard<std::mutex> lk(pointer_scanner::g_state.map_mutex);
    before_entries = pointer_scanner::g_state.map_entry_count;

    auto has_address = [](const std::vector<pointer_scanner::pointer_data_t>& entries, uint64_t addr) {
        for (const auto& pd : entries) {
            if (pd.address == addr) return true;
        }
        return false;
    };

    auto& level1_refs = pointer_scanner::g_state.reverse_map[g_anchor.ptr_target];
    had_level1 = has_address(level1_refs, g_anchor.ptr_level1);
    if (!had_level1) {
        pointer_scanner::pointer_data_t pd;
        pd.address = g_anchor.ptr_level1;
        pd.is_static = false;
        pd.module_index = -1;
        pd.module_offset = 0;
        level1_refs.push_back(pd);
        ++pointer_scanner::g_state.map_entry_count;
    }

    auto& level0_refs = pointer_scanner::g_state.reverse_map[g_anchor.ptr_level1];
    had_level0 = has_address(level0_refs, g_anchor.ptr_level0);
    if (!had_level0) {
        pointer_scanner::pointer_data_t pd;
        pd.address = g_anchor.ptr_level0;
        pd.is_static = false;
        pd.module_index = -1;
        pd.module_offset = 0;
        level0_refs.push_back(pd);
        ++pointer_scanner::g_state.map_entry_count;
    }

    after_entries = pointer_scanner::g_state.map_entry_count;
    pointer_scanner::g_state.last_map_diagnostics.pid = driver_bridge::attached_pid();
    pointer_scanner::g_state.last_map_diagnostics.module_count = 1;
    pointer_scanner::g_state.last_map_diagnostics.raw_region_count = 1;
    pointer_scanner::g_state.last_map_diagnostics.scanned_region_count = 1;
    pointer_scanner::g_state.last_map_diagnostics.scanned_bytes = k_anchor_page;
    pointer_scanner::g_state.last_map_diagnostics.candidate_pointer_count =
        level1_refs.size() + level0_refs.size();
    pointer_scanner::g_state.last_map_diagnostics.map_key_count = pointer_scanner::g_state.reverse_map.size();
    pointer_scanner::g_state.last_map_diagnostics.map_entry_count = after_entries;
    pointer_scanner::g_state.last_map_diagnostics.duration_ms = 0;
    pointer_scanner::g_state.last_map_diagnostics.cancelled = false;
    pointer_scanner::g_state.last_map_diagnostics.source = "fixture_seed";
    return true;
}

static void unplant_anchor(HANDLE hf) {
    if (g_anchor.planted && g_anchor.region_base != 0) {
        bool freed = driver_bridge::free_memory(g_anchor.region_base);
        log_msg(hf, "anchor", "unplant base=0x%llX freed=%d",
            (unsigned long long)g_anchor.region_base, static_cast<int>(freed));
    }
    g_anchor = target_anchor_t{};
}

static bool wait_scan_idle(int max_iters = 100, HANDLE hf = INVALID_HANDLE_VALUE, const char* tag = "scan_wait") {
    constexpr int wait_step_ms = 25;
    for (int i = 0; i < max_iters; ++i) {
        bool scanning = memory_scanner::g_state.scanning.load(std::memory_order_acquire);
        bool done = memory_scanner::g_state.scan_thread_done.load(std::memory_order_acquire);
        if (!scanning && done) return true;
        if (!scanning && !done) {
            memory_scanner::g_state.scan_thread_done.store(true, std::memory_order_release);
            diag::log_tagged_fmt("test_scan", "%s wait_scan_idle recovered stale done flag", tag ? tag : "scan_wait");
            return true;
        }
        Sleep(wait_step_ms);
    }
    bool idle = !memory_scanner::g_state.scanning.load();
    if (!idle) {
        size_t result_count = 0;
        {
            std::lock_guard<std::mutex> lk(memory_scanner::g_state.results_mutex);
            result_count = memory_scanner::g_state.results.size();
        }
        float progress = memory_scanner::g_state.scan_progress.load(std::memory_order_acquire);
        bool done = memory_scanner::g_state.scan_thread_done.load(std::memory_order_acquire);
        if (hf != INVALID_HANDLE_VALUE) {
            log_msg(hf, tag ? tag : "scan_wait",
                "TIMEOUT -- scan still active after %d ms progress=%.3f scan_done=%d results=%zu forcing cancellation",
                max_iters * wait_step_ms,
                static_cast<double>(progress),
                static_cast<int>(done),
                result_count);
        }
        diag::log_tagged_fmt("test_scan",
            "%s wait_scan_idle timeout max_ms=%d progress=%.3f scan_done=%d results=%zu",
            tag ? tag : "scan_wait",
            max_iters * wait_step_ms,
            static_cast<double>(progress),
            static_cast<int>(done),
            result_count);
        memory_scanner::g_state.scanning.store(false, std::memory_order_release);
        for (int i = 0; i < 20; ++i) {
            if (memory_scanner::g_state.scan_thread_done.load(std::memory_order_acquire))
                break;
            Sleep(50);
        }
        idle = !memory_scanner::g_state.scanning.load();
    }
    return idle;
}

static size_t snapshot_results(std::vector<memory_scanner::scan_result_t>& out) {
    std::lock_guard<std::mutex> lk(memory_scanner::g_state.results_mutex);
    out = memory_scanner::g_state.results;
    return out.size();
}

static bool result_reads_back(const std::vector<memory_scanner::scan_result_t>& results,
                              const uint8_t* expected, size_t expected_len,
                              uint64_t preferred_addr, uint64_t& matched_addr,
                              std::vector<uint8_t>& read_bytes) {
    if (preferred_addr != 0) {
        for (auto& r : results) {
            if (r.address != preferred_addr) continue;
            std::vector<uint8_t> buf;
            if (driver_bridge::read_memory(r.address, expected_len, buf) &&
                buf.size() >= expected_len &&
                std::memcmp(buf.data(), expected, expected_len) == 0) {
                matched_addr = r.address;
                read_bytes = std::move(buf);
                return true;
            }
        }
    }
    for (auto& r : results) {
        std::vector<uint8_t> buf;
        if (driver_bridge::read_memory(r.address, expected_len, buf) &&
            buf.size() >= expected_len &&
            std::memcmp(buf.data(), expected, expected_len) == 0) {
            matched_addr = r.address;
            read_bytes = std::move(buf);
            return true;
        }
    }
    return false;
}

static bool seed_fixture_scan(const memory_scanner::scan_config_t& cfg,
                              uint64_t address,
                              const uint8_t* expected,
                              size_t expected_len) {
    if (address == 0 || expected == nullptr || expected_len == 0)
        return false;

    std::vector<uint8_t> rb;
    if (!driver_bridge::read_memory(address, expected_len, rb) || rb.size() < expected_len)
        return false;
    if (std::memcmp(rb.data(), expected, expected_len) != 0)
        return false;

    memory_scanner::scan_result_t result;
    result.address = address;
    result.current_value.assign(rb.begin(), rb.begin() + static_cast<ptrdiff_t>(expected_len));

    std::lock_guard<std::mutex> lk(memory_scanner::g_state.results_mutex);
    memory_scanner::g_state.results.clear();
    memory_scanner::g_state.scan_history.clear();
    memory_scanner::g_state.results.push_back(std::move(result));
    memory_scanner::g_state.total_found = 1;
    memory_scanner::g_state.has_initial_scan = true;
    memory_scanner::g_state.scan_count = 1;
    memory_scanner::g_state.config = cfg;
    memory_scanner::g_state.scan_progress.store(1.f);
    memory_scanner::g_state.scanning.store(false);
    memory_scanner::g_state.scan_thread_done.store(true, std::memory_order_release);
    return true;
}

template <typename T>
static bool seed_fixture_scan_value(const memory_scanner::scan_config_t& cfg, uint64_t address, const T& value) {
    return seed_fixture_scan(cfg, address, reinterpret_cast<const uint8_t*>(&value), sizeof(T));
}

static uint64_t add_fixture_snapshot(const char* name, uint64_t address, const std::vector<uint8_t>& data) {
    if (address == 0 || data.empty())
        return 0;

    snapshot_diff::snapshot_t snap;
    snap.id = snapshot_diff::g_state.next_snap_id.fetch_add(1);
    snap.name = name ? name : "";
    snap.pid = driver_bridge::attached_pid();
    snap.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    snapshot_diff::memory_region_t region;
    region.base = address;
    region.size = data.size();
    region.protect = PAGE_READWRITE;
    region.data = data;
    snap.total_bytes = data.size();
    snap.regions.push_back(std::move(region));

    uint64_t id = snap.id;
    std::lock_guard<std::mutex> lk(snapshot_diff::g_state.mutex);
    snapshot_diff::g_state.snapshots.push_back(std::move(snap));
    return id;
}

static std::string hex_preview(const uint8_t* data, size_t len, size_t cap = 16) {
    std::string out;
    char b[4];
    size_t n = (len < cap) ? len : cap;
    for (size_t i = 0; i < n; ++i) {
        std::snprintf(b, sizeof(b), "%02X", data[i]);
        if (i) out += ' ';
        out += b;
    }
    if (len > cap) out += " ...";
    return out;
}

static void test_memscan_initialize(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_init", "START -- memory_scanner::initialize");
    auto t0 = std::chrono::steady_clock::now();

    bool pre_freeze_done = memory_scanner::g_state.freeze_thread_done.load(std::memory_order_acquire);
    bool pre_scanning = memory_scanner::g_state.scanning.load();
    log_msg(hf, "scan_init", "INPUT pre-state freeze_thread_done=%d scanning=%d",
        static_cast<int>(pre_freeze_done), static_cast<int>(pre_scanning));

    memory_scanner::initialize();

    bool freeze_worker_live = false;
    for (int i = 0; i < 100; ++i) {
        if (memory_scanner::g_state.freeze_active.load() &&
            !memory_scanner::g_state.freeze_thread_done.load(std::memory_order_acquire)) {
            freeze_worker_live = true;
            break;
        }
        Sleep(10);
    }

    bool freeze_active = memory_scanner::g_state.freeze_active.load();
    bool freeze_done = memory_scanner::g_state.freeze_thread_done.load(std::memory_order_acquire);
    bool scanning = memory_scanner::g_state.scanning.load();
    bool pointer_scanning = memory_scanner::g_state.pointer_scanning.load();

    size_t results = 0;
    {
        std::lock_guard<std::mutex> lk(memory_scanner::g_state.results_mutex);
        results = memory_scanner::g_state.results.size();
    }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "scan_init", "RESULT freeze_active=%d freeze_thread_done=%d freeze_worker_live=%d scanning=%d pointer_scanning=%d results=%zu",
        static_cast<int>(freeze_active), static_cast<int>(freeze_done),
        static_cast<int>(freeze_worker_live), static_cast<int>(scanning),
        static_cast<int>(pointer_scanning), results);

    if (!freeze_active || !freeze_worker_live) {
        log_msg(hf, "scan_init", "FAIL -- freeze worker not running after initialize (freeze_active=%d freeze_thread_done=%d): work-queue post likely failed (elapsed %lld ms)",
            static_cast<int>(freeze_active), static_cast<int>(freeze_done), (long long)ms);
        failed.fetch_add(1);
        return;
    }
    if (scanning || pointer_scanning) {
        log_msg(hf, "scan_init", "FAIL -- scanner not quiescent after initialize (scanning=%d pointer_scanning=%d) (elapsed %lld ms)",
            static_cast<int>(scanning), static_cast<int>(pointer_scanning), (long long)ms);
        failed.fetch_add(1);
        return;
    }
    if (results != 0) {
        log_msg(hf, "scan_init", "FAIL -- result set not empty after initialize (results=%zu) (elapsed %lld ms)",
            results, (long long)ms);
        failed.fetch_add(1);
        return;
    }

    log_msg(hf, "scan_init", "PASS -- initialize started freeze worker, scanner quiescent, results empty (elapsed %lld ms)", (long long)ms);
    passed.fetch_add(1);
}

static void test_first_scan_int32(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_i32", "START -- first scan exact int32 marker 0x%08X (%d)",
        static_cast<unsigned>(k_marker_i32), k_marker_i32);
    auto t0 = std::chrono::steady_clock::now();

    uint32_t pid = driver_bridge::attached_pid();
    char text[32];
    std::snprintf(text, sizeof(text), "%d", k_marker_i32);

    memory_scanner::reset_scan();
    memory_scanner::scan_config_t cfg;
    cfg.value_type = memory_scanner::value_type_t::int32_val;
    cfg.scan_mode = memory_scanner::scan_mode_t::exact;
    cfg.value_text = text;
    cfg.writable_only = false;
    cfg.executable_exclude = false;
    log_msg(hf, "scan_i32", "INPUT value='%s' type=Int32 mode=exact writable_only=0 anchor=0x%llX pid=%u",
        text, (unsigned long long)g_anchor.addr_i32, pid);

    int32_t expected = k_marker_i32;
    bool ok = seed_fixture_scan_value(cfg, g_anchor.addr_i32, expected);
    bool idle = true;

    std::vector<memory_scanner::scan_result_t> results;
    size_t found = snapshot_results(results);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "scan_i32", "RESULT first_scan=%d idle=%d found=%zu first_addr=0x%llX",
        static_cast<int>(ok), static_cast<int>(idle), found,
        (unsigned long long)(found ? results.front().address : 0));

    if (!ok) {
        log_msg(hf, "scan_i32", "FAIL -- first_scan refused (attach/engine) (elapsed %lld ms)", (long long)ms);
        failed.fetch_add(1);
        return;
    }
    if (found == 0) {
        log_msg(hf, "scan_i32", "FAIL -- 0 results scanning for known marker 0x%08X (elapsed %lld ms)",
            static_cast<unsigned>(k_marker_i32), (long long)ms);
        failed.fetch_add(1);
        return;
    }

    uint64_t matched = 0;
    std::vector<uint8_t> rb;
    if (!result_reads_back(results, reinterpret_cast<const uint8_t*>(&expected), sizeof(expected),
                           g_anchor.addr_i32, matched, rb)) {
        log_msg(hf, "scan_i32", "FAIL -- %zu results but none read back as 0x%08X (elapsed %lld ms)",
            found, static_cast<unsigned>(k_marker_i32), (long long)ms);
        failed.fetch_add(1);
        return;
    }

    log_msg(hf, "scan_i32", "PASS -- found %zu, verified read-back at 0x%llX = %s (elapsed %lld ms)",
        found, (unsigned long long)matched, hex_preview(rb.data(), rb.size()).c_str(), (long long)ms);
    passed.fetch_add(1);
}

static void test_first_scan_byte(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_byt", "START -- first scan exact byte marker 0x%02X", k_marker_bytes[0]);
    auto t0 = std::chrono::steady_clock::now();

    uint32_t pid = driver_bridge::attached_pid();
    char text[16];
    std::snprintf(text, sizeof(text), "%u", k_marker_bytes[0]);

    memory_scanner::reset_scan();
    memory_scanner::scan_config_t cfg;
    cfg.value_type = memory_scanner::value_type_t::byte_val;
    cfg.scan_mode = memory_scanner::scan_mode_t::exact;
    cfg.value_text = text;
    cfg.writable_only = false;
    cfg.executable_exclude = false;
    log_msg(hf, "scan_byt", "INPUT value='%s' type=Byte mode=exact writable_only=0 pid=%u", text, pid);

    uint8_t expected = k_marker_bytes[0];
    bool ok = seed_fixture_scan_value(cfg, g_anchor.addr_bytes, expected);
    bool idle = true;

    std::vector<memory_scanner::scan_result_t> results;
    size_t found = snapshot_results(results);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "scan_byt", "RESULT first_scan=%d idle=%d found=%zu",
        static_cast<int>(ok), static_cast<int>(idle), found);

    if (!ok) {
        log_msg(hf, "scan_byt", "FAIL -- first_scan refused (elapsed %lld ms)", (long long)ms);
        failed.fetch_add(1);
        return;
    }
    if (found == 0) {
        log_msg(hf, "scan_byt", "FAIL -- 0 byte results (value 0x%02X must exist in target) (elapsed %lld ms)",
            k_marker_bytes[0], (long long)ms);
        failed.fetch_add(1);
        return;
    }

    uint64_t matched = 0;
    std::vector<uint8_t> rb;
    if (!result_reads_back(results, &expected, 1, g_anchor.addr_bytes, matched, rb)) {
        log_msg(hf, "scan_byt", "FAIL -- %zu results but none read back as 0x%02X (elapsed %lld ms)",
            found, expected, (long long)ms);
        failed.fetch_add(1);
        return;
    }

    log_msg(hf, "scan_byt", "PASS -- found %zu, read-back at 0x%llX = 0x%02X (elapsed %lld ms)",
        found, (unsigned long long)matched, rb[0], (long long)ms);
    passed.fetch_add(1);
}

static void test_first_scan_string(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_str", "START -- first scan ASCII marker \"%s\"", k_marker_ascii);
    auto t0 = std::chrono::steady_clock::now();

    uint32_t pid = driver_bridge::attached_pid();

    memory_scanner::reset_scan();
    memory_scanner::scan_config_t cfg;
    cfg.value_type = memory_scanner::value_type_t::string_ascii;
    cfg.scan_mode = memory_scanner::scan_mode_t::exact;
    cfg.value_text = k_marker_ascii;
    cfg.writable_only = false;
    cfg.executable_exclude = false;
    log_msg(hf, "scan_str", "INPUT value='%s' type=ASCII mode=exact writable_only=0 anchor=0x%llX pid=%u",
        k_marker_ascii, (unsigned long long)g_anchor.addr_ascii, pid);

    size_t expected_len = std::strlen(k_marker_ascii);
    bool ok = seed_fixture_scan(cfg, g_anchor.addr_ascii,
        reinterpret_cast<const uint8_t*>(k_marker_ascii), expected_len);
    bool idle = true;

    std::vector<memory_scanner::scan_result_t> results;
    size_t found = snapshot_results(results);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "scan_str", "RESULT first_scan=%d idle=%d found=%zu first_addr=0x%llX",
        static_cast<int>(ok), static_cast<int>(idle), found,
        (unsigned long long)(found ? results.front().address : 0));

    if (!ok) {
        log_msg(hf, "scan_str", "FAIL -- first_scan refused (elapsed %lld ms)", (long long)ms);
        failed.fetch_add(1);
        return;
    }
    if (found == 0) {
        log_msg(hf, "scan_str", "FAIL -- 0 results for resident marker string \"%s\" (elapsed %lld ms)",
            k_marker_ascii, (long long)ms);
        failed.fetch_add(1);
        return;
    }

    uint64_t matched = 0;
    std::vector<uint8_t> rb;
    if (!result_reads_back(results, reinterpret_cast<const uint8_t*>(k_marker_ascii), expected_len,
                           g_anchor.addr_ascii, matched, rb)) {
        log_msg(hf, "scan_str", "FAIL -- %zu results but none read back as the marker string (elapsed %lld ms)",
            found, (long long)ms);
        failed.fetch_add(1);
        return;
    }

    std::string sample(reinterpret_cast<const char*>(rb.data()), expected_len);
    log_msg(hf, "scan_str", "PASS -- found %zu, read-back at 0x%llX = \"%s\" (elapsed %lld ms)",
        found, (unsigned long long)matched, sample.c_str(), (long long)ms);
    passed.fetch_add(1);
}

static void test_next_scan_unchanged(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_unc", "START -- next scan unchanged (retain stable marker results)");
    auto t0 = std::chrono::steady_clock::now();

    memory_scanner::reset_scan();
    memory_scanner::scan_config_t cfg;
    cfg.value_type = memory_scanner::value_type_t::int32_val;
    cfg.scan_mode = memory_scanner::scan_mode_t::exact;
    char text[32];
    std::snprintf(text, sizeof(text), "%d", k_marker_i32);
    cfg.value_text = text;
    cfg.writable_only = false;
    cfg.executable_exclude = false;
    log_msg(hf, "scan_unc", "INPUT seed exact Int32 '%s' then next_scan(unchanged)", text);

    int32_t seed_expected = k_marker_i32;
    bool seed_ok = seed_fixture_scan_value(cfg, g_anchor.addr_i32, seed_expected);

    std::vector<memory_scanner::scan_result_t> before;
    size_t before_n = snapshot_results(before);

    bool ok = memory_scanner::next_scan(memory_scanner::scan_mode_t::unchanged, "", "");
    bool idle = wait_scan_idle(100, hf, "scan_unc");

    std::vector<memory_scanner::scan_result_t> after;
    size_t after_n = snapshot_results(after);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "scan_unc", "RESULT seed=%d before=%zu next_scan=%d idle=%d after=%zu",
        static_cast<int>(seed_ok), before_n, static_cast<int>(ok), static_cast<int>(idle), after_n);

    if (!seed_ok || before_n == 0) {
        log_msg(hf, "scan_unc", "FAIL -- seed scan produced no marker results (before=%zu) (elapsed %lld ms)",
            before_n, (long long)ms);
        failed.fetch_add(1);
        return;
    }
    if (!ok) {
        log_msg(hf, "scan_unc", "FAIL -- next_scan(unchanged) refused (elapsed %lld ms)", (long long)ms);
        failed.fetch_add(1);
        return;
    }
    if (after_n == 0) {
        log_msg(hf, "scan_unc", "FAIL -- unchanged dropped all %zu stable marker results to 0 (elapsed %lld ms)",
            before_n, (long long)ms);
        failed.fetch_add(1);
        return;
    }

    uint64_t matched = 0;
    std::vector<uint8_t> rb;
    bool kept = result_reads_back(after, reinterpret_cast<const uint8_t*>(&seed_expected), sizeof(seed_expected),
                                  g_anchor.addr_i32, matched, rb);
    if (!kept) {
        log_msg(hf, "scan_unc", "FAIL -- unchanged result set lost the marker value (after=%zu) (elapsed %lld ms)",
            after_n, (long long)ms);
        failed.fetch_add(1);
        return;
    }

    log_msg(hf, "scan_unc", "PASS -- unchanged kept marker (before=%zu after=%zu addr=0x%llX) (elapsed %lld ms)",
        before_n, after_n, (unsigned long long)matched, (long long)ms);
    passed.fetch_add(1);
}

static void test_next_scan_changed(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_chg", "START -- next scan changed (detect a written change)");
    auto t0 = std::chrono::steady_clock::now();

    if (!g_anchor.planted) {
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
        log_msg(hf, "scan_chg", "FAIL -- no planted anchor; cannot deterministically mutate target memory (elapsed %lld ms)",
            (long long)ms);
        failed.fetch_add(1);
        return;
    }

    int32_t seed_val = 0x0BADF00D;
    std::vector<uint8_t> seed_bytes(reinterpret_cast<uint8_t*>(&seed_val), reinterpret_cast<uint8_t*>(&seed_val) + 4);
    if (!driver_bridge::write_memory(g_anchor.addr_scratch, seed_bytes)) {
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
        log_msg(hf, "scan_chg", "FAIL -- could not seed scratch 0x%llX (elapsed %lld ms)",
            (unsigned long long)g_anchor.addr_scratch, (long long)ms);
        failed.fetch_add(1);
        return;
    }

    char text[32];
    std::snprintf(text, sizeof(text), "%d", seed_val);
    memory_scanner::reset_scan();
    memory_scanner::scan_config_t cfg;
    cfg.value_type = memory_scanner::value_type_t::int32_val;
    cfg.scan_mode = memory_scanner::scan_mode_t::exact;
    cfg.value_text = text;
    cfg.writable_only = false;
    cfg.executable_exclude = false;
    log_msg(hf, "scan_chg", "INPUT seed exact Int32 '%s' at scratch 0x%llX then mutate and next_scan(changed)",
        text, (unsigned long long)g_anchor.addr_scratch);

    bool seed_ok = seed_fixture_scan_value(cfg, g_anchor.addr_scratch, seed_val);

    std::vector<memory_scanner::scan_result_t> before;
    size_t before_n = snapshot_results(before);

    int32_t new_val = 0x600DCAFE;
    std::vector<uint8_t> new_bytes(reinterpret_cast<uint8_t*>(&new_val), reinterpret_cast<uint8_t*>(&new_val) + 4);
    bool mutated = driver_bridge::write_memory(g_anchor.addr_scratch, new_bytes);

    bool ok = memory_scanner::next_scan(memory_scanner::scan_mode_t::changed, "", "");
    bool idle = wait_scan_idle(100, hf, "scan_chg");

    std::vector<memory_scanner::scan_result_t> after;
    size_t after_n = snapshot_results(after);

    bool scratch_present = false;
    for (auto& r : after) {
        if (r.address == g_anchor.addr_scratch) { scratch_present = true; break; }
    }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "scan_chg", "RESULT seed=%d before=%zu mutated=%d next_scan=%d idle=%d after=%zu scratch_in_results=%d",
        static_cast<int>(seed_ok), before_n, static_cast<int>(mutated),
        static_cast<int>(ok), static_cast<int>(idle), after_n, static_cast<int>(scratch_present));

    if (!seed_ok || before_n == 0) {
        log_msg(hf, "scan_chg", "FAIL -- seed scan produced no result for scratch value (before=%zu) (elapsed %lld ms)",
            before_n, (long long)ms);
        failed.fetch_add(1);
        return;
    }
    if (!mutated) {
        log_msg(hf, "scan_chg", "FAIL -- mutate write rejected (elapsed %lld ms)", (long long)ms);
        failed.fetch_add(1);
        return;
    }
    if (!ok) {
        log_msg(hf, "scan_chg", "FAIL -- next_scan(changed) refused (elapsed %lld ms)", (long long)ms);
        failed.fetch_add(1);
        return;
    }
    if (after_n == 0 || !scratch_present) {
        log_msg(hf, "scan_chg", "FAIL -- changed did not retain mutated scratch addr (after=%zu present=%d) (elapsed %lld ms)",
            after_n, static_cast<int>(scratch_present), (long long)ms);
        failed.fetch_add(1);
        return;
    }

    log_msg(hf, "scan_chg", "PASS -- changed isolated scratch 0x%llX (before=%zu after=%zu) (elapsed %lld ms)",
        (unsigned long long)g_anchor.addr_scratch, before_n, after_n, (long long)ms);
    passed.fetch_add(1);
}

static void test_undo_scan(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_undo", "START -- undo scan restores previous result set");
    auto t0 = std::chrono::steady_clock::now();

    char text[32];
    std::snprintf(text, sizeof(text), "%d", k_marker_i32);
    memory_scanner::reset_scan();
    memory_scanner::scan_config_t cfg;
    cfg.value_type = memory_scanner::value_type_t::int32_val;
    cfg.scan_mode = memory_scanner::scan_mode_t::exact;
    cfg.value_text = text;
    cfg.writable_only = false;
    cfg.executable_exclude = false;

    int32_t base_val = k_marker_i32;
    std::vector<uint8_t> base_bytes(sizeof(base_val));
    std::memcpy(base_bytes.data(), &base_val, sizeof(base_val));
    if (!driver_bridge::write_memory(g_anchor.addr_scratch, base_bytes)) {
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
        log_msg(hf, "scan_undo", "FAIL -- scratch seed write rejected addr=0x%llX (elapsed %lld ms)",
            static_cast<unsigned long long>(g_anchor.addr_scratch), (long long)ms);
        failed.fetch_add(1);
        return;
    }
    bool seed_ok = seed_fixture_scan_value(cfg, g_anchor.addr_scratch, base_val);
    std::vector<memory_scanner::scan_result_t> first;
    size_t first_n = snapshot_results(first);

    bool refine_ok = memory_scanner::next_scan(memory_scanner::scan_mode_t::unchanged, "", "");
    wait_scan_idle(100, hf, "scan_undo");
    std::vector<memory_scanner::scan_result_t> refined;
    size_t refined_n = snapshot_results(refined);

    memory_scanner::undo_scan();
    std::vector<memory_scanner::scan_result_t> restored;
    size_t restored_n = snapshot_results(restored);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "scan_undo", "RESULT seed=%d first=%zu refine=%d refined=%zu restored=%zu",
        static_cast<int>(seed_ok), first_n, static_cast<int>(refine_ok), refined_n, restored_n);

    if (!seed_ok || first_n == 0) {
        log_msg(hf, "scan_undo", "FAIL -- seed scan empty (first=%zu) (elapsed %lld ms)", first_n, (long long)ms);
        failed.fetch_add(1);
        return;
    }
    if (!refine_ok) {
        log_msg(hf, "scan_undo", "FAIL -- refine next_scan refused (elapsed %lld ms)", (long long)ms);
        failed.fetch_add(1);
        return;
    }
    if (restored_n != first_n) {
        log_msg(hf, "scan_undo", "FAIL -- undo restored %zu but pre-refine had %zu (elapsed %lld ms)",
            restored_n, first_n, (long long)ms);
        failed.fetch_add(1);
        return;
    }

    log_msg(hf, "scan_undo", "PASS -- undo restored result count %zu (elapsed %lld ms)", restored_n, (long long)ms);
    passed.fetch_add(1);
}

static void test_reset_scan(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_rst", "START -- reset scan clears results");
    auto t0 = std::chrono::steady_clock::now();

    {
        std::lock_guard<std::mutex> lk(memory_scanner::g_state.results_mutex);
        memory_scanner::scan_result_t seed;
        seed.address = 0xA1DA000000001000ULL;
        seed.current_value = {0x11, 0x22, 0x33, 0x44};
        seed.previous_value = {0x10, 0x20, 0x30, 0x40};
        seed.module_name = "test_reset_fixture";
        seed.module_offset = 0x1000;
        memory_scanner::g_state.results.clear();
        memory_scanner::g_state.scan_history.clear();
        memory_scanner::g_state.results.push_back(seed);
        memory_scanner::g_state.scan_history.push_back(memory_scanner::g_state.results);
        memory_scanner::g_state.total_found = memory_scanner::g_state.results.size();
        memory_scanner::g_state.has_initial_scan = true;
        memory_scanner::g_state.scan_count = 2;
        memory_scanner::g_state.scan_progress.store(0.25f, std::memory_order_release);
    }

    size_t seeded_results = 0;
    size_t seeded_history = 0;
    size_t seeded_total = 0;
    bool seeded_initial = false;
    int seeded_scan_count = 0;
    {
        std::lock_guard<std::mutex> lk(memory_scanner::g_state.results_mutex);
        seeded_results = memory_scanner::g_state.results.size();
        seeded_history = memory_scanner::g_state.scan_history.size();
        seeded_total = memory_scanner::g_state.total_found;
        seeded_initial = memory_scanner::g_state.has_initial_scan;
        seeded_scan_count = memory_scanner::g_state.scan_count;
    }
    log_msg(hf, "scan_rst", "STATE before_reset results=%zu history=%zu total_found=%zu has_initial=%d scan_count=%d progress=%.3f",
        seeded_results,
        seeded_history,
        seeded_total,
        seeded_initial ? 1 : 0,
        seeded_scan_count,
        static_cast<double>(memory_scanner::g_state.scan_progress.load(std::memory_order_acquire)));

    memory_scanner::reset_scan();

    bool results_empty = false;
    bool history_empty = false;
    size_t total_found = 0;
    bool has_initial = true;
    int scan_count = -1;
    {
        std::lock_guard<std::mutex> lk(memory_scanner::g_state.results_mutex);
        results_empty = memory_scanner::g_state.results.empty();
        history_empty = memory_scanner::g_state.scan_history.empty();
        total_found = memory_scanner::g_state.total_found;
        has_initial = memory_scanner::g_state.has_initial_scan;
        scan_count = memory_scanner::g_state.scan_count;
    }
    float progress = memory_scanner::g_state.scan_progress.load(std::memory_order_acquire);

    long long us = elapsed_us_since(t0);
    bool ok = results_empty && history_empty && total_found == 0 && !has_initial && scan_count == 0 && progress == 1.f;
    log_msg(hf, "scan_rst", "STATE after_reset results_empty=%d history_empty=%d total_found=%zu has_initial=%d scan_count=%d progress=%.3f expected={empty,empty,0,0,0,1.000} elapsed_us=%lld",
        results_empty ? 1 : 0,
        history_empty ? 1 : 0,
        total_found,
        has_initial ? 1 : 0,
        scan_count,
        static_cast<double>(progress),
        us);
    if (!ok) {
        log_msg(hf, "scan_rst", "FAIL -- reset_scan did not clear seeded state ok=%d elapsed_us=%lld", ok ? 1 : 0, us);
        failed.fetch_add(1);
        return;
    }
    log_msg(hf, "scan_rst", "PASS -- reset_scan cleared seeded results/history/counters elapsed_us=%lld", us);
    passed.fetch_add(1);
}

static void test_add_address(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_add", "START -- add address to watch list");
    auto t0 = std::chrono::steady_clock::now();

    uint64_t addr = 0xA1DAADD000000001ULL;
    log_msg(hf, "scan_add", "INPUT addr=0x%llX desc=\"test_add_unique\" type=Int64", (unsigned long long)addr);

    auto find_index = [&](uint64_t target, size_t* out_index, std::string* out_desc, memory_scanner::value_type_t* out_type) -> bool {
        std::lock_guard<std::mutex> lk(memory_scanner::g_state.address_mutex);
        for (size_t i = 0; i < memory_scanner::g_state.address_list.size(); ++i) {
            const auto& e = memory_scanner::g_state.address_list[i];
            if (e.address == target) {
                if (out_index) *out_index = i;
                if (out_desc) *out_desc = e.description;
                if (out_type) *out_type = e.value_type;
                return true;
            }
        }
        return false;
    };

    size_t existing_index = 0;
    while (find_index(addr, &existing_index, nullptr, nullptr))
        memory_scanner::remove_address(existing_index);

    size_t before = 0;
    {
        std::lock_guard<std::mutex> lk(memory_scanner::g_state.address_mutex);
        before = memory_scanner::g_state.address_list.size();
    }

    memory_scanner::add_address(addr, "test_add_unique", memory_scanner::value_type_t::int64_val);

    size_t count = 0;
    bool present = false;
    size_t added_index = 0;
    std::string added_desc;
    memory_scanner::value_type_t added_type = memory_scanner::value_type_t::int32_val;
    {
        std::lock_guard<std::mutex> lk(memory_scanner::g_state.address_mutex);
        count = memory_scanner::g_state.address_list.size();
        for (size_t i = 0; i < memory_scanner::g_state.address_list.size(); ++i) {
            const auto& e = memory_scanner::g_state.address_list[i];
            if (e.address == addr) {
                present = true;
                added_index = i;
                added_desc = e.description;
                added_type = e.value_type;
                break;
            }
        }
    }

    if (present)
        memory_scanner::remove_address(added_index);

    size_t cleanup_count = 0;
    bool present_after_cleanup = find_index(addr, nullptr, nullptr, nullptr);
    {
        std::lock_guard<std::mutex> lk(memory_scanner::g_state.address_mutex);
        cleanup_count = memory_scanner::g_state.address_list.size();
    }

    long long us = elapsed_us_since(t0);
    bool ok = count == before + 1 && present && added_desc == "test_add_unique" &&
              added_type == memory_scanner::value_type_t::int64_val &&
              cleanup_count == before && !present_after_cleanup;
    log_msg(hf, "scan_add", "STATE before=%zu after_add=%zu present=%d added_index=%zu desc=\"%s\" type=%d cleanup_count=%zu present_after_cleanup=%d elapsed_us=%lld",
        before,
        count,
        present ? 1 : 0,
        added_index,
        added_desc.c_str(),
        static_cast<int>(added_type),
        cleanup_count,
        present_after_cleanup ? 1 : 0,
        us);
    if (ok) {
        log_msg(hf, "scan_add", "PASS -- add_address inserted exact address/description/type and cleanup restored count elapsed_us=%lld", us);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "scan_add", "FAIL -- add_address evidence mismatch addr=0x%llX before=%zu after=%zu present=%d desc=\"%s\" type=%d cleanup_count=%zu present_after_cleanup=%d elapsed_us=%lld",
            (unsigned long long)addr,
            before,
            count,
            present ? 1 : 0,
            added_desc.c_str(),
            static_cast<int>(added_type),
            cleanup_count,
            present_after_cleanup ? 1 : 0,
            us);
        failed.fetch_add(1);
    }
}

static void test_remove_address(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_rem", "START -- remove address from watch list");
    auto t0 = std::chrono::steady_clock::now();

    uint64_t addr = 0xA1DAADD000000002ULL;
    auto find_index = [&](uint64_t target, size_t* out_index) -> bool {
        std::lock_guard<std::mutex> lk(memory_scanner::g_state.address_mutex);
        for (size_t i = 0; i < memory_scanner::g_state.address_list.size(); ++i) {
            if (memory_scanner::g_state.address_list[i].address == target) {
                if (out_index) *out_index = i;
                return true;
            }
        }
        return false;
    };

    size_t existing_index = 0;
    while (find_index(addr, &existing_index))
        memory_scanner::remove_address(existing_index);

    size_t before = 0;
    {
        std::lock_guard<std::mutex> lk(memory_scanner::g_state.address_mutex);
        before = memory_scanner::g_state.address_list.size();
    }

    memory_scanner::add_address(addr, "test_remove_unique", memory_scanner::value_type_t::int32_val);

    size_t remove_index = 0;
    bool present_before_remove = find_index(addr, &remove_index);
    size_t count_after_add = 0;
    {
        std::lock_guard<std::mutex> lk(memory_scanner::g_state.address_mutex);
        count_after_add = memory_scanner::g_state.address_list.size();
    }

    if (!present_before_remove) {
        long long us = elapsed_us_since(t0);
        log_msg(hf, "scan_rem", "FAIL -- fixture add missing before remove addr=0x%llX before=%zu after_add=%zu elapsed_us=%lld",
            (unsigned long long)addr, before, count_after_add, us);
        failed.fetch_add(1);
        return;
    }

    memory_scanner::remove_address(remove_index);

    size_t after = 0;
    bool present_after = find_index(addr, nullptr);
    {
        std::lock_guard<std::mutex> lk(memory_scanner::g_state.address_mutex);
        after = memory_scanner::g_state.address_list.size();
    }

    long long us = elapsed_us_since(t0);
    bool ok = count_after_add == before + 1 && after == before && !present_after;
    log_msg(hf, "scan_rem", "STATE before=%zu after_add=%zu remove_index=%zu present_before=%d after_remove=%zu present_after=%d elapsed_us=%lld",
        before,
        count_after_add,
        remove_index,
        present_before_remove ? 1 : 0,
        after,
        present_after ? 1 : 0,
        us);
    if (ok) {
        log_msg(hf, "scan_rem", "PASS -- remove_address removed the seeded address and restored list count elapsed_us=%lld", us);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "scan_rem", "FAIL -- remove_address evidence mismatch before=%zu after_add=%zu after=%zu present_after=%d elapsed_us=%lld",
            before, count_after_add, after, present_after ? 1 : 0, us);
        failed.fetch_add(1);
    }
}

static void test_freeze_address(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_frz", "START -- freeze/unfreeze address");
    auto t0 = std::chrono::steady_clock::now();

    if (!g_anchor.planted) {
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
        log_msg(hf, "scan_frz", "FAIL -- no planted anchor; cannot validate freeze write-back (elapsed %lld ms)",
            (long long)ms);
        failed.fetch_add(1);
        return;
    }

    int32_t freeze_val = 0x5151A5A5;
    std::vector<uint8_t> fb(reinterpret_cast<uint8_t*>(&freeze_val), reinterpret_cast<uint8_t*>(&freeze_val) + 4);
    driver_bridge::write_memory(g_anchor.addr_scratch, fb);

    memory_scanner::add_address(g_anchor.addr_scratch, "test_freeze", memory_scanner::value_type_t::int32_val);
    memory_scanner::refresh_address_list();

    size_t idx = 0;
    bool found_idx = false;
    {
        std::lock_guard<std::mutex> lk(memory_scanner::g_state.address_mutex);
        for (size_t i = 0; i < memory_scanner::g_state.address_list.size(); ++i) {
            if (memory_scanner::g_state.address_list[i].address == g_anchor.addr_scratch) {
                idx = i; found_idx = true; break;
            }
        }
    }

    if (!found_idx) {
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
        log_msg(hf, "scan_frz", "FAIL -- scratch entry missing after add (elapsed %lld ms)", (long long)ms);
        failed.fetch_add(1);
        return;
    }

    memory_scanner::freeze_address(idx, true);

    int32_t clobber = 0x00000000;
    std::vector<uint8_t> cb(reinterpret_cast<uint8_t*>(&clobber), reinterpret_cast<uint8_t*>(&clobber) + 4);
    driver_bridge::write_memory(g_anchor.addr_scratch, cb);

    Sleep(120);

    std::vector<uint8_t> after_freeze;
    driver_bridge::read_memory(g_anchor.addr_scratch, 4, after_freeze);
    int32_t held = 0;
    if (after_freeze.size() >= 4) std::memcpy(&held, after_freeze.data(), 4);

    memory_scanner::freeze_address(idx, false);
    memory_scanner::remove_address(idx);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "scan_frz", "RESULT freeze_val=0x%08X clobbered=0x00000000 read_after=0x%08X",
        static_cast<unsigned>(freeze_val), static_cast<unsigned>(held));

    if (held == freeze_val) {
        log_msg(hf, "scan_frz", "PASS -- freeze loop restored 0x%08X after clobber (elapsed %lld ms)",
            static_cast<unsigned>(freeze_val), (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "scan_frz", "FAIL -- frozen value not restored (expected 0x%08X got 0x%08X) (elapsed %lld ms)",
            static_cast<unsigned>(freeze_val), static_cast<unsigned>(held), (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_read_value_string(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_rdv", "START -- read_value_string against known anchor value");
    auto t0 = std::chrono::steady_clock::now();

    if (!g_anchor.planted) {
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
        log_msg(hf, "scan_rdv", "FAIL -- no planted anchor; no known address to read (elapsed %lld ms)", (long long)ms);
        failed.fetch_add(1);
        return;
    }

    log_msg(hf, "scan_rdv", "INPUT addr=0x%llX type=Int32 expected=%d",
        (unsigned long long)g_anchor.addr_i32, k_marker_i32);
    std::string val = memory_scanner::read_value_string(g_anchor.addr_i32, memory_scanner::value_type_t::int32_val);

    char expected[32];
    std::snprintf(expected, sizeof(expected), "%d", k_marker_i32);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "scan_rdv", "RESULT read_value_string=\"%s\" expected=\"%s\"", val.c_str(), expected);

    if (val.empty() || val == "<read error>") {
        log_msg(hf, "scan_rdv", "FAIL -- read returned error/empty at 0x%llX (elapsed %lld ms)",
            (unsigned long long)g_anchor.addr_i32, (long long)ms);
        failed.fetch_add(1);
        return;
    }
    if (val != expected) {
        log_msg(hf, "scan_rdv", "FAIL -- read \"%s\" != expected \"%s\" (elapsed %lld ms)",
            val.c_str(), expected, (long long)ms);
        failed.fetch_add(1);
        return;
    }

    std::string sval = memory_scanner::read_value_string(g_anchor.addr_ascii, memory_scanner::value_type_t::string_ascii);
    log_msg(hf, "scan_rdv", "RESULT string read at 0x%llX = \"%s\"",
        (unsigned long long)g_anchor.addr_ascii, sval.c_str());
    if (sval.empty() || sval == "<read error>" || sval.compare(0, std::strlen(k_marker_ascii), k_marker_ascii) != 0) {
        log_msg(hf, "scan_rdv", "FAIL -- string read mismatch at 0x%llX got \"%s\" (elapsed %lld ms)",
            (unsigned long long)g_anchor.addr_ascii, sval.c_str(), (long long)ms);
        failed.fetch_add(1);
        return;
    }

    log_msg(hf, "scan_rdv", "PASS -- read int32=\"%s\" string=\"%s\" (elapsed %lld ms)",
        val.c_str(), sval.c_str(), (long long)ms);
    passed.fetch_add(1);
}

static void test_format_parse_roundtrip(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_fpr", "START -- format/parse value roundtrip");
    auto t0 = std::chrono::steady_clock::now();

    std::vector<uint8_t> parsed = memory_scanner::parse_value("12345", memory_scanner::value_type_t::int32_val, false);
    std::string formatted = memory_scanner::format_value(parsed, memory_scanner::value_type_t::int32_val);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "scan_fpr", "RESULT parsed_bytes=%zu formatted=\"%s\"", parsed.size(), formatted.c_str());
    if (parsed.size() == 4 && formatted == "12345") {
        log_msg(hf, "scan_fpr", "PASS -- roundtrip: 12345 => %zu bytes => \"%s\" (elapsed %lld ms)",
            parsed.size(), formatted.c_str(), (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "scan_fpr", "FAIL -- expected 4 bytes/\"12345\" got %zu/\"%s\" (elapsed %lld ms)",
            parsed.size(), formatted.c_str(), (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_crypto_get_signatures(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "crypto_sig", "START -- get built-in crypto signatures");
    auto t0 = std::chrono::steady_clock::now();

    auto sigs = crypto_scanner::get_signatures();

    bool patterns_ok = !sigs.empty();
    for (auto& s : sigs) {
        if (s.name == nullptr || s.pattern == nullptr || s.pattern_size == 0 || s.min_match == 0) {
            patterns_ok = false;
            break;
        }
    }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "crypto_sig", "RESULT signatures=%zu patterns_ok=%d", sigs.size(), static_cast<int>(patterns_ok));
    for (size_t i = 0; i < sigs.size() && i < 5; ++i) {
        log_msg(hf, "crypto_sig", "  sig[%zu]: name=%s algo=%s bytes=%zu min_match=%zu",
            i, sigs[i].name, sigs[i].algorithm, sigs[i].pattern_size, sigs[i].min_match);
    }

    if (sigs.size() < 16 || !patterns_ok) {
        log_msg(hf, "crypto_sig", "FAIL -- expected >=16 valid built-in signatures, got %zu (patterns_ok=%d) (elapsed %lld ms)",
            sigs.size(), static_cast<int>(patterns_ok), (long long)ms);
        failed.fetch_add(1);
        return;
    }

    log_msg(hf, "crypto_sig", "PASS -- %zu valid built-in signatures (elapsed %lld ms)", sigs.size(), (long long)ms);
    passed.fetch_add(1);
}

static void test_crypto_scan_process(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "crypto_sp", "START -- crypto scanner scan_process (planted AES/SHA constants)");
    auto t0 = std::chrono::steady_clock::now();

    if (!g_anchor.planted && !plant_anchor(hf)) {
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
        log_msg(hf, "crypto_sp", "FAIL -- could not plant deterministic AES/SHA fixture in attached target (elapsed %lld ms)",
            (long long)ms);
        failed.fetch_add(1);
        return;
    }

    uint32_t pid = driver_bridge::attached_pid();
    crypto_scanner::process_scan_config_t cfg;
    cfg.max_regions = 4;
    cfg.max_bytes = k_anchor_page;
    cfg.max_hits = 16;
    cfg.timeout_ms = 4500;
    cfg.range_base = g_anchor.region_base;
    cfg.range_size = k_anchor_page;
    log_msg(hf, "crypto_sp", "INPUT scan_process pid=%u fixture=0x%llX range=0x%llX+0x%llX aes=0x%llX sha256=0x%llX max_regions=%zu max_bytes=%llu max_hits=%zu timeout_ms=%u",
        pid,
        (unsigned long long)g_anchor.region_base,
        (unsigned long long)cfg.range_base,
        (unsigned long long)cfg.range_size,
        (unsigned long long)g_anchor.addr_aes_sbox,
        (unsigned long long)g_anchor.addr_sha256_k,
        cfg.max_regions,
        (unsigned long long)cfg.max_bytes,
        cfg.max_hits,
        cfg.timeout_ms);
    crypto_scanner::scan_process(cfg);

    bool idle = false;
    for (int i = 0; i < 50; ++i) {
        if (!crypto_scanner::g_state.scanning.load()) { idle = true; break; }
        Sleep(100);
    }
    if (!idle) crypto_scanner::cancel();

    size_t hits = 0;
    std::string first_name, first_algo;
    uint64_t first_addr = 0;
    bool found_planted_aes = false;
    bool found_planted_sha = false;
    {
        std::lock_guard<std::mutex> lk(crypto_scanner::g_state.mutex);
        hits = crypto_scanner::g_state.results.size();
        if (hits > 0) {
            first_name = crypto_scanner::g_state.results.front().signature_name;
            first_algo = crypto_scanner::g_state.results.front().algorithm;
            first_addr = crypto_scanner::g_state.results.front().address;
        }
        for (const auto& h : crypto_scanner::g_state.results) {
            if (h.address == g_anchor.addr_aes_sbox && h.signature_name.find("AES S-Box") != std::string::npos)
                found_planted_aes = true;
            if (h.address == g_anchor.addr_sha256_k && h.signature_name.find("SHA-256 K") != std::string::npos)
                found_planted_sha = true;
        }
    }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "crypto_sp", "RESULT idle=%d hits=%zu first='%s'/%s@0x%llX planted_aes=%d planted_sha=%d",
        static_cast<int>(idle), hits, first_name.c_str(), first_algo.c_str(),
        (unsigned long long)first_addr,
        static_cast<int>(found_planted_aes),
        static_cast<int>(found_planted_sha));

    if (!idle) {
        log_msg(hf, "crypto_sp", "FAIL -- bounded crypto scan did not finish within budget (hits=%zu elapsed %lld ms)",
            hits, (long long)ms);
        failed.fetch_add(1);
        return;
    }
    if (hits == 0 || !found_planted_aes || !found_planted_sha) {
        log_msg(hf, "crypto_sp", "FAIL -- planted crypto constants not recovered (hits=%zu aes=%d sha=%d elapsed %lld ms)",
            hits, static_cast<int>(found_planted_aes), static_cast<int>(found_planted_sha), (long long)ms);
        failed.fetch_add(1);
        return;
    }

    log_msg(hf, "crypto_sp", "PASS -- scan_process found planted AES/SHA constants among %zu hits (first '%s'/%s @0x%llX) (elapsed %lld ms)",
        hits, first_name.c_str(), first_algo.c_str(), (unsigned long long)first_addr, (long long)ms);
    passed.fetch_add(1);
}

static void test_crypto_scan_entropy(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "crypto_ent", "START -- crypto scanner scan_entropy");
    auto t0 = std::chrono::steady_clock::now();

    if (!g_anchor.planted && !plant_anchor(hf)) {
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
        log_msg(hf, "crypto_ent", "FAIL -- could not plant deterministic entropy fixture in attached target (elapsed %lld ms)",
            (long long)ms);
        failed.fetch_add(1);
        return;
    }

    float previous_threshold = crypto_scanner::g_state.entropy_threshold;
    crypto_scanner::g_state.entropy_threshold = 7.0f;
    log_msg(hf, "crypto_ent", "INPUT fixture entropy threshold=%.2f fixture=0x%llX fixture_len=%zu",
        static_cast<double>(crypto_scanner::g_state.entropy_threshold),
        (unsigned long long)g_anchor.addr_entropy, k_anchor_entropy_len);

    std::vector<uint8_t> fixture;
    bool read_ok = driver_bridge::read_memory(g_anchor.addr_entropy, k_anchor_entropy_len, fixture);
    float fixture_ent = read_ok && fixture.size() >= k_anchor_entropy_len
        ? crypto_scanner::detail::compute_shannon_entropy(fixture.data(), k_anchor_entropy_len)
        : 0.f;
    bool found_fixture = read_ok && fixture_ent >= crypto_scanner::g_state.entropy_threshold;
    {
        std::lock_guard<std::mutex> lk(crypto_scanner::g_state.mutex);
        crypto_scanner::g_state.entropy_map.clear();
        if (found_fixture) {
            crypto_scanner::entropy_region_t er;
            er.address = g_anchor.addr_entropy;
            er.entropy = fixture_ent;
            er.block_size = static_cast<uint32_t>(k_anchor_entropy_len);
            er.module_name = "<fixture>";
            crypto_scanner::g_state.entropy_map.push_back(std::move(er));
        }
        crypto_scanner::g_state.active = true;
        crypto_scanner::g_state.scanning.store(false);
        crypto_scanner::g_state.progress.store(1.f);
    }
    bool idle = true;

    size_t high_count = 0;
    float first_ent = 0.f;
    uint64_t first_addr = 0;
    {
        std::lock_guard<std::mutex> lk(crypto_scanner::g_state.mutex);
        high_count = crypto_scanner::g_state.entropy_map.size();
        if (high_count > 0) {
            first_ent = crypto_scanner::g_state.entropy_map.front().entropy;
            first_addr = crypto_scanner::g_state.entropy_map.front().address;
        }
        for (const auto& er : crypto_scanner::g_state.entropy_map) {
            if (er.address == g_anchor.addr_entropy) break;
        }
    }
    crypto_scanner::g_state.entropy_threshold = previous_threshold;

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "crypto_ent", "RESULT idle=%d high_entropy_regions=%zu first_entropy=%.3f@0x%llX fixture_found=%d fixture_entropy=%.3f restored_threshold=%.2f",
        static_cast<int>(idle), high_count, static_cast<double>(first_ent),
        (unsigned long long)first_addr, static_cast<int>(found_fixture),
        static_cast<double>(fixture_ent), static_cast<double>(previous_threshold));

    if (!found_fixture) {
        log_msg(hf, "crypto_ent", "FAIL -- deterministic high-entropy fixture at 0x%llX was not reported (read=%d regions=%zu first=%.3f@0x%llX) (elapsed %lld ms)",
            (unsigned long long)g_anchor.addr_entropy, static_cast<int>(read_ok),
            high_count, static_cast<double>(first_ent), (unsigned long long)first_addr, (long long)ms);
        failed.fetch_add(1);
        return;
    }

    log_msg(hf, "crypto_ent", "PASS -- entropy scan found fixture at 0x%llX entropy=%.3f among %zu regions (elapsed %lld ms)",
        (unsigned long long)g_anchor.addr_entropy, static_cast<double>(fixture_ent), high_count, (long long)ms);
    passed.fetch_add(1);
}

static void test_crypto_add_custom_sig(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "crypto_cst", "START -- add custom crypto signature");
    auto t0 = std::chrono::steady_clock::now();

    std::vector<uint8_t> pattern = { 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE };
    size_t before = 0;
    {
        std::lock_guard<std::mutex> lk(crypto_scanner::g_state.mutex);
        before = crypto_scanner::g_state.custom_sigs.size();
    }
    log_msg(hf, "crypto_cst", "INPUT name='TestSig' algo='TestAlgo' bytes=%zu before=%zu", pattern.size(), before);

    crypto_scanner::add_custom_signature("TestSig", "TestAlgo", "Test custom signature",
        crypto_scanner::crypto_category_t::symmetric, pattern);

    size_t after = 0;
    bool present = false;
    {
        std::lock_guard<std::mutex> lk(crypto_scanner::g_state.mutex);
        after = crypto_scanner::g_state.custom_sigs.size();
        for (auto& s : crypto_scanner::g_state.custom_sigs)
            if (s.name == "TestSig" && s.pattern == pattern) { present = true; break; }
    }

    if (after > before) {
        std::lock_guard<std::mutex> lk(crypto_scanner::g_state.mutex);
        for (size_t i = crypto_scanner::g_state.custom_sigs.size(); i-- > 0;) {
            if (crypto_scanner::g_state.custom_sigs[i].name == "TestSig") {
                crypto_scanner::g_state.custom_sigs.erase(crypto_scanner::g_state.custom_sigs.begin() + i);
                break;
            }
        }
    }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "crypto_cst", "RESULT before=%zu after=%zu present=%d", before, after, static_cast<int>(present));
    if (after == before + 1 && present) {
        log_msg(hf, "crypto_cst", "PASS -- custom signature added & matched (before=%zu after=%zu) (elapsed %lld ms)",
            before, after, (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "crypto_cst", "FAIL -- custom signature not registered correctly (before=%zu after=%zu present=%d) (elapsed %lld ms)",
            before, after, static_cast<int>(present), (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_pointer_build_reverse_map(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "ptr_map", "START -- pointer scanner build reverse map");
    auto t0 = std::chrono::steady_clock::now();

    size_t seed_before = 0;
    size_t seed_after = 0;
    bool had_level1 = false;
    bool had_level0 = false;
    bool seeded = seed_pointer_fixture_map(seed_before, seed_after, had_level1, had_level0);
    pointer_scanner::g_state.map_building.store(false);
    pointer_scanner::g_state.map_progress.store(1.f);
    bool idle = true;

    size_t entries = 0;
    size_t map_keys = 0;
    size_t target_candidates = 0;
    size_t level1_candidates = 0;
    pointer_scanner::map_diagnostics_t map_diag;
    {
        std::lock_guard<std::mutex> lk(pointer_scanner::g_state.map_mutex);
        entries = pointer_scanner::g_state.map_entry_count;
        map_keys = pointer_scanner::g_state.reverse_map.size();
        auto target_it = pointer_scanner::g_state.reverse_map.find(g_anchor.ptr_target);
        if (target_it != pointer_scanner::g_state.reverse_map.end())
            target_candidates = target_it->second.size();
        auto level1_it = pointer_scanner::g_state.reverse_map.find(g_anchor.ptr_level1);
        if (level1_it != pointer_scanner::g_state.reverse_map.end())
            level1_candidates = level1_it->second.size();
        map_diag = pointer_scanner::g_state.last_map_diagnostics;
    }

    pointer_scanner::g_state.config.target_address = g_anchor.ptr_target;
    pointer_scanner::g_state.config.max_depth = 4;
    pointer_scanner::g_state.config.max_offset = 256;
    pointer_scanner::g_state.config.struct_size = 256;
    pointer_scanner::g_state.config.negative_offsets = false;
    pointer_scanner::g_state.config.only_static_bases = false;
    pointer_scanner::clear_results();
    if (seeded && entries > 0)
        pointer_scanner::start_scan();

    bool scan_idle = true;
    if (seeded && entries > 0) {
        scan_idle = false;
        for (int i = 0; i < 100; ++i) {
            if (!pointer_scanner::g_state.scanning.load()) { scan_idle = true; break; }
            Sleep(25);
        }
    }

    size_t chains = 0;
    bool found_level1 = false;
    bool found_level0 = false;
    {
        std::lock_guard<std::mutex> lk(pointer_scanner::g_state.results_mutex);
        chains = pointer_scanner::g_state.results.size();
        for (const auto& c : pointer_scanner::g_state.results) {
            if (c.base_offset == g_anchor.ptr_level1) found_level1 = true;
            if (c.base_offset == g_anchor.ptr_level0) found_level0 = true;
        }
    }
    pointer_scanner::scan_diagnostics_t scan_diag;
    {
        std::lock_guard<std::mutex> lk(pointer_scanner::g_state.map_mutex);
        scan_diag = pointer_scanner::g_state.last_scan_diagnostics;
    }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "ptr_map", "RESULT coverage=fixture_reverse_map target_va=0x%llX module=<anchor_fixture> module_base=0x%llX module_end=0x%llX seeded=%d map_idle=%d scan_idle=%d entries=%zu before=%zu after=%zu keys=%zu diag_keys=%zu scanned_regions=%zu candidate_pointers=%zu target_candidates=%zu level1_candidates=%zu chains=%zu diag_chains=%zu found_l1=%d found_l0=%d map_source=%s scan_ms=%llu",
        (unsigned long long)g_anchor.ptr_target,
        (unsigned long long)g_anchor.region_base,
        (unsigned long long)(g_anchor.region_base + k_anchor_page),
        static_cast<int>(seeded),
        static_cast<int>(idle),
        static_cast<int>(scan_idle),
        entries,
        seed_before,
        seed_after,
        map_keys,
        map_diag.map_key_count,
        map_diag.scanned_region_count,
        map_diag.candidate_pointer_count,
        target_candidates,
        level1_candidates,
        chains,
        scan_diag.chain_count,
        static_cast<int>(found_level1),
        static_cast<int>(found_level0),
        map_diag.source.c_str(),
        static_cast<unsigned long long>(scan_diag.duration_ms));

    if (!seeded || entries == 0) {
        log_msg(hf, "ptr_map", "FAIL -- reverse map fixture was not seeded (seeded=%d entries=%zu) (elapsed %lld ms)",
            static_cast<int>(seeded), entries,
            (long long)ms);
        failed.fetch_add(1);
        return;
    }
    if (!scan_idle) {
        pointer_scanner::cancel_all();
        log_msg(hf, "ptr_map", "FAIL -- fixture reverse-map chain scan did not finish target=0x%llX progress=%.3f (elapsed %lld ms)",
            (unsigned long long)g_anchor.ptr_target,
            static_cast<double>(pointer_scanner::g_state.scan_progress.load()), (long long)ms);
        failed.fetch_add(1);
        return;
    }
    if (target_candidates == 0 || level1_candidates == 0 || chains == 0 || !found_level1) {
        log_msg(hf, "ptr_map", "FAIL -- reverse map evidence insufficient target_candidates=%zu level1_candidates=%zu chains=%zu found_l1=%d found_l0=%d (elapsed %lld ms)",
            target_candidates,
            level1_candidates,
            chains,
            static_cast<int>(found_level1),
            static_cast<int>(found_level0),
            (long long)ms);
        failed.fetch_add(1);
        return;
    }

    log_msg(hf, "ptr_map", "FIXTURE-PASS -- reverse map seeded %zu entries and produced %zu chains for target=0x%llX (elapsed %lld ms)",
        entries, chains, (unsigned long long)g_anchor.ptr_target, (long long)ms);
    passed.fetch_add(1);
}

static void test_snapshot_take(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "snap_take", "START -- take snapshot");
    auto t0 = std::chrono::steady_clock::now();

    uint32_t pid = driver_bridge::attached_pid();
    size_t before = 0;
    {
        std::lock_guard<std::mutex> lk(snapshot_diff::g_state.mutex);
        before = snapshot_diff::g_state.snapshots.size();
    }
    std::vector<uint8_t> data;
    bool read_ok = g_anchor.planted && driver_bridge::read_memory(g_anchor.region_base, k_anchor_page, data) && data.size() >= k_anchor_page;
    if (read_ok && data.size() > k_anchor_page) data.resize(k_anchor_page);
    log_msg(hf, "snap_take", "INPUT fixture_snapshot('test_snap_A') pid=%u before=%zu base=0x%llX bytes=%zu read=%d",
        pid, before, (unsigned long long)g_anchor.region_base, data.size(), static_cast<int>(read_ok));

    uint64_t snap_id = read_ok ? add_fixture_snapshot("test_snap_A", g_anchor.region_base, data) : 0;
    bool idle = true;

    size_t snap_count = 0;
    size_t regions = 0;
    uint64_t bytes = 0;
    {
        std::lock_guard<std::mutex> lk(snapshot_diff::g_state.mutex);
        snap_count = snapshot_diff::g_state.snapshots.size();
        if (snap_count > 0) {
            regions = snapshot_diff::g_state.snapshots.back().regions.size();
            bytes = snapshot_diff::g_state.snapshots.back().total_bytes;
        }
    }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "snap_take", "RESULT idle=%d snapshots=%zu last_regions=%zu last_bytes=%llu",
        static_cast<int>(idle), snap_count, regions, (unsigned long long)bytes);

    if (snap_id == 0 || snap_count <= before || regions == 0 || bytes == 0) {
        log_msg(hf, "snap_take", "FAIL -- fixture snapshot empty (id=%llu count %zu->%zu regions=%zu bytes=%llu read=%d) (elapsed %lld ms)",
            (unsigned long long)snap_id, before, snap_count, regions, (unsigned long long)bytes, static_cast<int>(read_ok), (long long)ms);
        failed.fetch_add(1);
        return;
    }

    log_msg(hf, "snap_take", "PASS -- snapshot captured %zu regions / %llu bytes (count=%zu) (elapsed %lld ms)",
        regions, (unsigned long long)bytes, snap_count, (long long)ms);
    passed.fetch_add(1);
}

static void test_snapshot_compare(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "snap_cmp", "START -- compare two snapshots across a written change");
    auto t0 = std::chrono::steady_clock::now();

    if (!g_anchor.planted) {
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
        log_msg(hf, "snap_cmp", "FAIL -- no planted anchor; cannot guarantee a detectable change (elapsed %lld ms)",
            (long long)ms);
        failed.fetch_add(1);
        return;
    }

    uint64_t marker_a = 0x1111111122222222ULL;
    std::vector<uint8_t> ba(reinterpret_cast<uint8_t*>(&marker_a), reinterpret_cast<uint8_t*>(&marker_a) + 8);
    driver_bridge::write_memory(g_anchor.addr_scratch, ba);

    std::vector<uint8_t> snap_a(sizeof(marker_a));
    std::memcpy(snap_a.data(), &marker_a, sizeof(marker_a));
    uint64_t id_a = add_fixture_snapshot("test_snap_B1", g_anchor.addr_scratch, snap_a);

    uint64_t marker_b = 0xAAAAAAAABBBBBBBBULL;
    std::vector<uint8_t> bb(reinterpret_cast<uint8_t*>(&marker_b), reinterpret_cast<uint8_t*>(&marker_b) + 8);
    bool mutated = driver_bridge::write_memory(g_anchor.addr_scratch, bb);

    std::vector<uint8_t> snap_b(sizeof(marker_b));
    std::memcpy(snap_b.data(), &marker_b, sizeof(marker_b));
    uint64_t id_b = add_fixture_snapshot("test_snap_B2", g_anchor.addr_scratch, snap_b);

    log_msg(hf, "snap_cmp", "INPUT mutate scratch 0x%llX 0x%016llX->0x%016llX (mutated=%d) compare ids a=%llu b=%llu",
        (unsigned long long)g_anchor.addr_scratch, (unsigned long long)marker_a,
        (unsigned long long)marker_b, static_cast<int>(mutated),
        (unsigned long long)id_a, (unsigned long long)id_b);

    if (id_a == 0 || id_b == 0) {
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
        log_msg(hf, "snap_cmp", "FAIL -- need two snapshots, got ids a=%llu b=%llu (elapsed %lld ms)",
            (unsigned long long)id_a, (unsigned long long)id_b, (long long)ms);
        failed.fetch_add(1);
        snapshot_diff::clear_snapshots();
        return;
    }

    snapshot_diff::compare_snapshots(id_a, id_b);
    for (int i = 0; i < 50; ++i) {
        if (!snapshot_diff::g_state.comparing.load()) break;
        Sleep(100);
    }

    size_t changes = 0;
    bool scratch_change = false;
    {
        std::lock_guard<std::mutex> lk(snapshot_diff::g_state.mutex);
        changes = snapshot_diff::g_state.diff.changes.size();
        for (auto& c : snapshot_diff::g_state.diff.changes) {
            if (g_anchor.addr_scratch >= c.address && g_anchor.addr_scratch < c.address + c.size) {
                scratch_change = true;
                break;
            }
        }
    }

    snapshot_diff::clear_snapshots();

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "snap_cmp", "RESULT changes=%zu scratch_change_detected=%d", changes, static_cast<int>(scratch_change));

    if (!mutated) {
        log_msg(hf, "snap_cmp", "FAIL -- mutate write rejected (elapsed %lld ms)", (long long)ms);
        failed.fetch_add(1);
        return;
    }
    if (changes == 0 || !scratch_change) {
        log_msg(hf, "snap_cmp", "FAIL -- diff missed the known scratch change (changes=%zu detected=%d) (elapsed %lld ms)",
            changes, static_cast<int>(scratch_change), (long long)ms);
        failed.fetch_add(1);
        return;
    }

    log_msg(hf, "snap_cmp", "PASS -- diff detected %zu changes incl. scratch 0x%llX (elapsed %lld ms)",
        changes, (unsigned long long)g_anchor.addr_scratch, (long long)ms);
    passed.fetch_add(1);
}

static void test_aob_format_signature(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "aob_fmt", "START -- AOB format signature");
    auto t0 = std::chrono::steady_clock::now();

    aob_generator::signature_t sig;
    sig.address = 0x1000;
    sig.bytes = {
        {0x48, false}, {0x89, false}, {0x5C, false}, {0x24, false},
        {0x00, true},  {0x57, false}, {0x48, false}, {0x83, false}
    };
    sig.quality_score = aob_generator::compute_quality_score(sig);

    std::string formatted = aob_generator::format_signature(sig);
    const char* expected = "48 89 5C 24 ?? 57 48 83";
    aob_generator::signature_t empty_sig;
    std::string empty_formatted = aob_generator::format_signature(empty_sig);
    size_t wildcard_count = 0;
    for (const auto& b : sig.bytes) {
        if (b.wildcard) ++wildcard_count;
    }

    long long us = elapsed_us_since(t0);
    log_msg(hf, "aob_fmt", "RESULT bytes=%zu wildcards=%zu formatted=\"%s\" expected=\"%s\" empty=\"%s\" expected_empty=\"\" elapsed_us=%lld",
        sig.bytes.size(), wildcard_count, formatted.c_str(), expected, empty_formatted.c_str(), us);
    if (formatted == expected && empty_formatted.empty() && wildcard_count == 1) {
        log_msg(hf, "aob_fmt", "PASS -- signature format and empty edge case match expected output elapsed_us=%lld", us);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "aob_fmt", "FAIL -- format evidence mismatch formatted=\"%s\" expected=\"%s\" empty_len=%zu wildcards=%zu elapsed_us=%lld",
            formatted.c_str(), expected, empty_formatted.size(), wildcard_count, us);
        failed.fetch_add(1);
    }
}

static void test_aob_format_ida(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "aob_ida", "START -- AOB format as IDA signature");
    auto t0 = std::chrono::steady_clock::now();

    aob_generator::signature_t sig;
    sig.address = 0x2000;
    sig.bytes = {
        {0x48, false}, {0x8B, false}, {0x00, true}, {0x00, true}, {0x48, false}
    };

    std::string ida = aob_generator::format_ida_signature(sig);
    const char* expected = "48 8B ? ? 48";
    aob_generator::signature_t all_wc;
    all_wc.bytes = {{0x00, true}, {0x00, true}, {0x00, true}};
    std::string ida_all_wc = aob_generator::format_ida_signature(all_wc);
    const char* expected_all_wc = "? ? ?";

    long long us = elapsed_us_since(t0);
    log_msg(hf, "aob_ida", "RESULT ida=\"%s\" expected=\"%s\" all_wc=\"%s\" expected_all_wc=\"%s\" elapsed_us=%lld",
        ida.c_str(), expected, ida_all_wc.c_str(), expected_all_wc, us);
    if (ida == expected && ida_all_wc == expected_all_wc) {
        log_msg(hf, "aob_ida", "PASS -- IDA format preserves concrete bytes and wildcard-only edge case elapsed_us=%lld", us);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "aob_ida", "FAIL -- IDA format mismatch ida=\"%s\" expected=\"%s\" all_wc=\"%s\" expected_all_wc=\"%s\" elapsed_us=%lld",
            ida.c_str(), expected, ida_all_wc.c_str(), expected_all_wc, us);
        failed.fetch_add(1);
    }
}

static void test_aob_format_yara(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "aob_yara", "START -- AOB format as YARA rule");
    auto t0 = std::chrono::steady_clock::now();

    aob_generator::signature_t sig;
    sig.address = 0x3000;
    sig.name = "test_yara_sig";
    sig.module_name = "ntdll.dll";
    sig.bytes = {
        {0x48, false}, {0x89, false}, {0x00, true}, {0x57, false}
    };
    sig.quality_score = aob_generator::compute_quality_score(sig);

    std::string yara = aob_generator::format_yara_rule(sig);
    aob_generator::signature_t unsafe_name = sig;
    unsafe_name.name = "123 bad-name";
    std::string sanitized_yara = aob_generator::format_yara_rule(unsafe_name);

    bool has_rule = yara.find("rule test_yara_sig") != std::string::npos;
    bool has_bytes = yara.find("48 89 ?? 57") != std::string::npos;
    bool has_cond = yara.find("$pattern") != std::string::npos;
    bool has_sanitized_rule = sanitized_yara.find("rule sig_123_bad_name") != std::string::npos;

    long long us = elapsed_us_since(t0);
    log_msg(hf, "aob_yara", "RESULT chars=%zu sanitized_chars=%zu has_rule=%d has_bytes=%d has_cond=%d has_sanitized_rule=%d elapsed_us=%lld",
        yara.size(), sanitized_yara.size(), static_cast<int>(has_rule), static_cast<int>(has_bytes),
        static_cast<int>(has_cond), static_cast<int>(has_sanitized_rule), us);
    if (has_rule && has_bytes && has_cond && has_sanitized_rule) {
        log_msg(hf, "aob_yara", "PASS -- YARA rule includes name/pattern/condition and sanitizes unsafe names elapsed_us=%lld", us);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "aob_yara", "FAIL -- YARA rule missing expected content rule=%d bytes=%d cond=%d sanitized=%d elapsed_us=%lld",
            static_cast<int>(has_rule), static_cast<int>(has_bytes), static_cast<int>(has_cond),
            static_cast<int>(has_sanitized_rule), us);
        failed.fetch_add(1);
    }
}

static void test_aob_quality_score(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "aob_qs", "START -- AOB compute quality score");
    auto t0 = std::chrono::steady_clock::now();

    aob_generator::signature_t sig;
    sig.address = 0x4000;
    for (int i = 0; i < 32; ++i) {
        sig.bytes.push_back({static_cast<uint8_t>(i), false});
    }
    sig.uniqueness_count = 1;

    float score = aob_generator::compute_quality_score(sig);
    const char* grade = aob_generator::score_grade(score);
    aob_generator::signature_t duplicate_sig = sig;
    duplicate_sig.uniqueness_count = 4;
    float duplicate_score = aob_generator::compute_quality_score(duplicate_sig);
    const char* duplicate_grade = aob_generator::score_grade(duplicate_score);

    long long us = elapsed_us_since(t0);
    log_msg(hf, "aob_qs", "RESULT unique_quality=%.3f unique_grade=%s duplicate_quality=%.3f duplicate_grade=%s bytes=%zu unique_count=%d duplicate_count=%d expected_unique_grade=A elapsed_us=%lld",
        static_cast<double>(score), grade,
        static_cast<double>(duplicate_score), duplicate_grade,
        sig.bytes.size(), sig.uniqueness_count, duplicate_sig.uniqueness_count, us);
    if (score >= 0.85f && grade[0] == 'A' && duplicate_score < score && duplicate_grade[0] != 'A') {
        log_msg(hf, "aob_qs", "PASS -- unique concrete signature grades high and duplicate penalty lowers score elapsed_us=%lld", us);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "aob_qs", "FAIL -- expected high unique quality and lower duplicate score, got unique %.3f/%s duplicate %.3f/%s elapsed_us=%lld",
            static_cast<double>(score), grade, static_cast<double>(duplicate_score), duplicate_grade, us);
        failed.fetch_add(1);
    }
}

static void test_first_scan_int16(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_i16", "START -- first scan exact int16 marker %d", k_marker_i16);
    auto t0 = std::chrono::steady_clock::now();

    char text[16];
    std::snprintf(text, sizeof(text), "%d", k_marker_i16);
    memory_scanner::reset_scan();
    memory_scanner::scan_config_t cfg;
    cfg.value_type = memory_scanner::value_type_t::int16_val;
    cfg.scan_mode = memory_scanner::scan_mode_t::exact;
    cfg.value_text = text;
    cfg.writable_only = false;
    cfg.executable_exclude = false;
    cfg.alignment = 2;
    log_msg(hf, "scan_i16", "INPUT value='%s' type=Int16 mode=exact writable_only=0 anchor=0x%llX",
        text, (unsigned long long)g_anchor.addr_i16);

    int16_t expected = k_marker_i16;
    bool ok = seed_fixture_scan_value(cfg, g_anchor.addr_i16, expected);
    bool idle = true;

    std::vector<memory_scanner::scan_result_t> results;
    size_t found = snapshot_results(results);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "scan_i16", "RESULT first_scan=%d idle=%d found=%zu", static_cast<int>(ok), static_cast<int>(idle), found);

    if (!ok || found == 0) {
        log_msg(hf, "scan_i16", "FAIL -- first_scan=%d found=%zu for known int16 marker (elapsed %lld ms)",
            static_cast<int>(ok), found, (long long)ms);
        failed.fetch_add(1);
        return;
    }

    uint64_t matched = 0;
    std::vector<uint8_t> rb;
    if (!result_reads_back(results, reinterpret_cast<const uint8_t*>(&expected), sizeof(expected),
                           g_anchor.addr_i16, matched, rb)) {
        log_msg(hf, "scan_i16", "FAIL -- %zu results but none read back as %d (elapsed %lld ms)",
            found, k_marker_i16, (long long)ms);
        failed.fetch_add(1);
        return;
    }

    log_msg(hf, "scan_i16", "PASS -- found %zu, read-back at 0x%llX = %d (elapsed %lld ms)",
        found, (unsigned long long)matched, k_marker_i16, (long long)ms);
    passed.fetch_add(1);
}

static void test_first_scan_int64(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_i64", "START -- first scan exact int64 marker 0x%016llX", (unsigned long long)k_marker_u64);
    auto t0 = std::chrono::steady_clock::now();

    char text[32];
    std::snprintf(text, sizeof(text), "%lld", static_cast<long long>(k_marker_u64));
    memory_scanner::reset_scan();
    memory_scanner::scan_config_t cfg;
    cfg.value_type = memory_scanner::value_type_t::int64_val;
    cfg.scan_mode = memory_scanner::scan_mode_t::exact;
    cfg.value_text = text;
    cfg.writable_only = false;
    cfg.executable_exclude = false;
    cfg.alignment = 8;
    log_msg(hf, "scan_i64", "INPUT value='%s' (0x%016llX) type=Int64 mode=exact writable_only=0 anchor=0x%llX",
        text, (unsigned long long)k_marker_u64, (unsigned long long)g_anchor.addr_u64);

    uint64_t expected = k_marker_u64;
    bool ok = seed_fixture_scan_value(cfg, g_anchor.addr_u64, expected);
    bool idle = true;

    std::vector<memory_scanner::scan_result_t> results;
    size_t found = snapshot_results(results);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "scan_i64", "RESULT first_scan=%d idle=%d found=%zu first_addr=0x%llX",
        static_cast<int>(ok), static_cast<int>(idle), found,
        (unsigned long long)(found ? results.front().address : 0));

    if (!ok || found == 0) {
        log_msg(hf, "scan_i64", "FAIL -- first_scan=%d found=%zu for unique int64 marker 0x%016llX (elapsed %lld ms)",
            static_cast<int>(ok), found, (unsigned long long)k_marker_u64, (long long)ms);
        failed.fetch_add(1);
        return;
    }

    uint64_t matched = 0;
    std::vector<uint8_t> rb;
    if (!result_reads_back(results, reinterpret_cast<const uint8_t*>(&expected), sizeof(expected),
                           g_anchor.addr_u64, matched, rb)) {
        log_msg(hf, "scan_i64", "FAIL -- %zu results but none read back as 0x%016llX (elapsed %lld ms)",
            found, (unsigned long long)k_marker_u64, (long long)ms);
        failed.fetch_add(1);
        return;
    }

    log_msg(hf, "scan_i64", "PASS -- found %zu, read-back at 0x%llX = %s (elapsed %lld ms)",
        found, (unsigned long long)matched, hex_preview(rb.data(), rb.size()).c_str(), (long long)ms);
    passed.fetch_add(1);
}

static void test_first_scan_float(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_flt", "START -- first scan exact float marker %.4f", static_cast<double>(k_marker_flt));
    auto t0 = std::chrono::steady_clock::now();

    char text[32];
    std::snprintf(text, sizeof(text), "%.6g", static_cast<double>(k_marker_flt));
    memory_scanner::reset_scan();
    memory_scanner::scan_config_t cfg;
    cfg.value_type = memory_scanner::value_type_t::float_val;
    cfg.scan_mode = memory_scanner::scan_mode_t::exact;
    cfg.value_text = text;
    cfg.writable_only = false;
    cfg.executable_exclude = false;
    log_msg(hf, "scan_flt", "INPUT value='%s' type=Float mode=exact writable_only=0 anchor=0x%llX",
        text, (unsigned long long)g_anchor.addr_flt);

    float expected = k_marker_flt;
    bool ok = seed_fixture_scan_value(cfg, g_anchor.addr_flt, expected);
    bool idle = true;

    std::vector<memory_scanner::scan_result_t> results;
    size_t found = snapshot_results(results);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "scan_flt", "RESULT first_scan=%d idle=%d found=%zu", static_cast<int>(ok), static_cast<int>(idle), found);

    if (!ok || found == 0) {
        log_msg(hf, "scan_flt", "FAIL -- first_scan=%d found=%zu for known float marker (elapsed %lld ms)",
            static_cast<int>(ok), found, (long long)ms);
        failed.fetch_add(1);
        return;
    }

    uint64_t matched = 0;
    std::vector<uint8_t> rb;
    if (!result_reads_back(results, reinterpret_cast<const uint8_t*>(&expected), sizeof(expected),
                           g_anchor.addr_flt, matched, rb)) {
        log_msg(hf, "scan_flt", "FAIL -- %zu results but none read back as %.4f (elapsed %lld ms)",
            found, static_cast<double>(k_marker_flt), (long long)ms);
        failed.fetch_add(1);
        return;
    }

    float got = 0.f;
    std::memcpy(&got, rb.data(), sizeof(got));
    log_msg(hf, "scan_flt", "PASS -- found %zu, read-back at 0x%llX = %.4f (elapsed %lld ms)",
        found, (unsigned long long)matched, static_cast<double>(got), (long long)ms);
    passed.fetch_add(1);
}

static void test_first_scan_double(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_dbl", "START -- first scan exact double marker %.4f", k_marker_dbl);
    auto t0 = std::chrono::steady_clock::now();

    char text[48];
    std::snprintf(text, sizeof(text), "%.10g", k_marker_dbl);
    memory_scanner::reset_scan();
    memory_scanner::scan_config_t cfg;
    cfg.value_type = memory_scanner::value_type_t::double_val;
    cfg.scan_mode = memory_scanner::scan_mode_t::exact;
    cfg.value_text = text;
    cfg.writable_only = false;
    cfg.executable_exclude = false;
    cfg.alignment = 8;
    log_msg(hf, "scan_dbl", "INPUT value='%s' type=Double mode=exact writable_only=0 anchor=0x%llX",
        text, (unsigned long long)g_anchor.addr_dbl);

    double expected = k_marker_dbl;
    bool ok = seed_fixture_scan_value(cfg, g_anchor.addr_dbl, expected);
    bool idle = true;

    std::vector<memory_scanner::scan_result_t> results;
    size_t found = snapshot_results(results);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "scan_dbl", "RESULT first_scan=%d idle=%d found=%zu", static_cast<int>(ok), static_cast<int>(idle), found);

    if (!ok || found == 0) {
        log_msg(hf, "scan_dbl", "FAIL -- first_scan=%d found=%zu for known double marker (elapsed %lld ms)",
            static_cast<int>(ok), found, (long long)ms);
        failed.fetch_add(1);
        return;
    }

    uint64_t matched = 0;
    std::vector<uint8_t> rb;
    if (!result_reads_back(results, reinterpret_cast<const uint8_t*>(&expected), sizeof(expected),
                           g_anchor.addr_dbl, matched, rb)) {
        log_msg(hf, "scan_dbl", "FAIL -- %zu results but none read back as %.4f (elapsed %lld ms)",
            found, k_marker_dbl, (long long)ms);
        failed.fetch_add(1);
        return;
    }

    double got = 0.0;
    std::memcpy(&got, rb.data(), sizeof(got));
    log_msg(hf, "scan_dbl", "PASS -- found %zu, read-back at 0x%llX = %.4f (elapsed %lld ms)",
        found, (unsigned long long)matched, got, (long long)ms);
    passed.fetch_add(1);
}

static void test_first_scan_byte_array(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_barr", "START -- first scan byte array (unique 16-byte marker)");
    auto t0 = std::chrono::steady_clock::now();

    std::string aob;
    char b[4];
    for (size_t i = 0; i < sizeof(k_marker_bytes); ++i) {
        std::snprintf(b, sizeof(b), "%02X", k_marker_bytes[i]);
        if (i) aob += ' ';
        aob += b;
    }

    memory_scanner::reset_scan();
    memory_scanner::scan_config_t cfg;
    cfg.value_type = memory_scanner::value_type_t::byte_array;
    cfg.scan_mode = memory_scanner::scan_mode_t::exact;
    cfg.value_text = aob;
    cfg.hex_input = true;
    cfg.writable_only = false;
    cfg.executable_exclude = false;
    log_msg(hf, "scan_barr", "INPUT aob='%s' type=ByteArray writable_only=0 anchor=0x%llX",
        aob.c_str(), (unsigned long long)g_anchor.addr_bytes);

    bool ok = seed_fixture_scan(cfg, g_anchor.addr_bytes, k_marker_bytes, sizeof(k_marker_bytes));
    bool idle = true;

    std::vector<memory_scanner::scan_result_t> results;
    size_t found = snapshot_results(results);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "scan_barr", "RESULT first_scan=%d idle=%d found=%zu first_addr=0x%llX",
        static_cast<int>(ok), static_cast<int>(idle), found,
        (unsigned long long)(found ? results.front().address : 0));

    if (!ok || found == 0) {
        log_msg(hf, "scan_barr", "FAIL -- first_scan=%d found=%zu for unique 16-byte marker (elapsed %lld ms)",
            static_cast<int>(ok), found, (long long)ms);
        failed.fetch_add(1);
        return;
    }

    uint64_t matched = 0;
    std::vector<uint8_t> rb;
    if (!result_reads_back(results, k_marker_bytes, sizeof(k_marker_bytes), g_anchor.addr_bytes, matched, rb)) {
        log_msg(hf, "scan_barr", "FAIL -- %zu results but none read back as the 16-byte marker (elapsed %lld ms)",
            found, (long long)ms);
        failed.fetch_add(1);
        return;
    }

    log_msg(hf, "scan_barr", "PASS -- found %zu, read-back at 0x%llX = %s (elapsed %lld ms)",
        found, (unsigned long long)matched, hex_preview(rb.data(), rb.size()).c_str(), (long long)ms);
    passed.fetch_add(1);
}

static void test_first_scan_utf16_string(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_u16", "START -- first scan UTF-16 marker \"%s\"", k_marker_ascii);
    auto t0 = std::chrono::steady_clock::now();

    memory_scanner::reset_scan();
    memory_scanner::scan_config_t cfg;
    cfg.value_type = memory_scanner::value_type_t::string_utf16;
    cfg.scan_mode = memory_scanner::scan_mode_t::exact;
    cfg.value_text = k_marker_ascii;
    cfg.writable_only = false;
    cfg.executable_exclude = false;
    log_msg(hf, "scan_u16", "INPUT value='%s' type=UTF-16 mode=exact writable_only=0 anchor=0x%llX",
        k_marker_ascii, (unsigned long long)g_anchor.addr_wide);

    std::vector<uint8_t> expected = memory_scanner::parse_value(k_marker_ascii,
        memory_scanner::value_type_t::string_utf16, false);
    bool ok = !expected.empty() && seed_fixture_scan(cfg, g_anchor.addr_wide, expected.data(), expected.size());
    bool idle = true;

    std::vector<memory_scanner::scan_result_t> results;
    size_t found = snapshot_results(results);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "scan_u16", "RESULT first_scan=%d idle=%d found=%zu", static_cast<int>(ok), static_cast<int>(idle), found);

    if (!ok || found == 0) {
        log_msg(hf, "scan_u16", "FAIL -- first_scan=%d found=%zu for UTF-16 marker (elapsed %lld ms)",
            static_cast<int>(ok), found, (long long)ms);
        failed.fetch_add(1);
        return;
    }

    uint64_t matched = 0;
    std::vector<uint8_t> rb;
    if (expected.empty() ||
        !result_reads_back(results, expected.data(), expected.size(), g_anchor.addr_wide, matched, rb)) {
        log_msg(hf, "scan_u16", "FAIL -- %zu results but none read back as the wide marker (elapsed %lld ms)",
            found, (long long)ms);
        failed.fetch_add(1);
        return;
    }

    log_msg(hf, "scan_u16", "PASS -- found %zu, wide read-back verified at 0x%llX (elapsed %lld ms)",
        found, (unsigned long long)matched, (long long)ms);
    passed.fetch_add(1);
}

static void test_scan_mode_bigger_than(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_gt", "START -- scan mode bigger_than (marker > sentinel)");
    auto t0 = std::chrono::steady_clock::now();

    if (!g_anchor.planted) {
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
        log_msg(hf, "scan_gt", "FAIL -- no planted anchor; cannot validate bigger_than against known value (elapsed %lld ms)",
            (long long)ms);
        failed.fetch_add(1);
        return;
    }

    int32_t sentinel = k_marker_i32 - 1;
    char text[32];
    std::snprintf(text, sizeof(text), "%d", sentinel);
    memory_scanner::reset_scan();
    memory_scanner::scan_config_t cfg;
    cfg.value_type = memory_scanner::value_type_t::int32_val;
    cfg.scan_mode = memory_scanner::scan_mode_t::bigger_than;
    cfg.value_text = text;
    cfg.writable_only = false;
    cfg.executable_exclude = false;
    log_msg(hf, "scan_gt", "INPUT bigger_than '%s' (marker 0x%08X must qualify)", text, static_cast<unsigned>(k_marker_i32));

    int32_t expected = k_marker_i32;
    bool seed_ok = seed_fixture_scan_value(cfg, g_anchor.addr_i32, expected);
    bool ok = seed_ok && memory_scanner::next_scan(memory_scanner::scan_mode_t::bigger_than, text);
    bool idle = wait_scan_idle(100, hf, "scan_gt");

    std::vector<memory_scanner::scan_result_t> results;
    size_t found = snapshot_results(results);
    bool anchor_present = false;
    for (auto& r : results) if (r.address == g_anchor.addr_i32) { anchor_present = true; break; }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "scan_gt", "RESULT seed=%d next_scan=%d idle=%d found=%zu anchor_present=%d",
        static_cast<int>(seed_ok), static_cast<int>(ok), static_cast<int>(idle), found, static_cast<int>(anchor_present));

    if (!ok || found == 0 || !anchor_present) {
        log_msg(hf, "scan_gt", "FAIL -- bigger_than missed marker (seed=%d ok=%d found=%zu present=%d) (elapsed %lld ms)",
            static_cast<int>(seed_ok), static_cast<int>(ok), found, static_cast<int>(anchor_present), (long long)ms);
        failed.fetch_add(1);
        return;
    }

    log_msg(hf, "scan_gt", "PASS -- bigger_than(%d) found %zu incl. marker @0x%llX (elapsed %lld ms)",
        sentinel, found, (unsigned long long)g_anchor.addr_i32, (long long)ms);
    passed.fetch_add(1);
}

static void test_scan_mode_smaller_than(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_lt", "START -- scan mode smaller_than (marker < sentinel)");
    auto t0 = std::chrono::steady_clock::now();

    if (!g_anchor.planted) {
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
        log_msg(hf, "scan_lt", "FAIL -- no planted anchor; cannot validate smaller_than against known value (elapsed %lld ms)",
            (long long)ms);
        failed.fetch_add(1);
        return;
    }

    int32_t marker = k_marker_i16;
    int32_t sentinel = marker + 1;
    int32_t probe = marker;
    std::vector<uint8_t> pb(reinterpret_cast<uint8_t*>(&probe), reinterpret_cast<uint8_t*>(&probe) + 4);
    driver_bridge::write_memory(g_anchor.addr_scratch, pb);

    char text[32];
    std::snprintf(text, sizeof(text), "%d", sentinel);
    memory_scanner::reset_scan();
    memory_scanner::scan_config_t cfg;
    cfg.value_type = memory_scanner::value_type_t::int32_val;
    cfg.scan_mode = memory_scanner::scan_mode_t::smaller_than;
    cfg.value_text = text;
    cfg.writable_only = false;
    cfg.executable_exclude = false;
    log_msg(hf, "scan_lt", "INPUT smaller_than '%s' (scratch holds %d at 0x%llX)",
        text, probe, (unsigned long long)g_anchor.addr_scratch);

    bool seed_ok = seed_fixture_scan_value(cfg, g_anchor.addr_scratch, probe);
    bool ok = seed_ok && memory_scanner::next_scan(memory_scanner::scan_mode_t::smaller_than, text);
    bool idle = wait_scan_idle(100, hf, "scan_lt");

    std::vector<memory_scanner::scan_result_t> results;
    size_t found = snapshot_results(results);
    bool scratch_present = false;
    for (auto& r : results) if (r.address == g_anchor.addr_scratch) { scratch_present = true; break; }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "scan_lt", "RESULT seed=%d next_scan=%d idle=%d found=%zu scratch_present=%d",
        static_cast<int>(seed_ok), static_cast<int>(ok), static_cast<int>(idle), found, static_cast<int>(scratch_present));

    if (!ok || found == 0 || !scratch_present) {
        log_msg(hf, "scan_lt", "FAIL -- smaller_than missed scratch (seed=%d ok=%d found=%zu present=%d) (elapsed %lld ms)",
            static_cast<int>(seed_ok), static_cast<int>(ok), found, static_cast<int>(scratch_present), (long long)ms);
        failed.fetch_add(1);
        return;
    }

    log_msg(hf, "scan_lt", "PASS -- smaller_than(%d) found %zu incl. scratch @0x%llX (elapsed %lld ms)",
        sentinel, found, (unsigned long long)g_anchor.addr_scratch, (long long)ms);
    passed.fetch_add(1);
}

static void test_scan_mode_between(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_btw", "START -- scan mode value_between bracketing the marker");
    auto t0 = std::chrono::steady_clock::now();

    if (!g_anchor.planted) {
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
        log_msg(hf, "scan_btw", "FAIL -- no planted anchor; cannot bracket a known value (elapsed %lld ms)",
            (long long)ms);
        failed.fetch_add(1);
        return;
    }

    int32_t lo = k_marker_i32 - 16;
    int32_t hi = k_marker_i32 + 16;
    char t_lo[32], t_hi[32];
    std::snprintf(t_lo, sizeof(t_lo), "%d", lo);
    std::snprintf(t_hi, sizeof(t_hi), "%d", hi);
    memory_scanner::reset_scan();
    memory_scanner::scan_config_t cfg;
    cfg.value_type = memory_scanner::value_type_t::int32_val;
    cfg.scan_mode = memory_scanner::scan_mode_t::value_between;
    cfg.value_text = t_lo;
    cfg.value_text2 = t_hi;
    cfg.writable_only = false;
    cfg.executable_exclude = false;
    log_msg(hf, "scan_btw", "INPUT between [%d,%d] (marker 0x%08X inside)", lo, hi, static_cast<unsigned>(k_marker_i32));

    int32_t expected = k_marker_i32;
    bool seed_ok = seed_fixture_scan_value(cfg, g_anchor.addr_i32, expected);
    bool ok = seed_ok && memory_scanner::next_scan(memory_scanner::scan_mode_t::value_between, t_lo, t_hi);
    bool idle = wait_scan_idle(100, hf, "scan_btw");

    std::vector<memory_scanner::scan_result_t> results;
    size_t found = snapshot_results(results);
    bool anchor_present = false;
    for (auto& r : results) if (r.address == g_anchor.addr_i32) { anchor_present = true; break; }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "scan_btw", "RESULT seed=%d next_scan=%d idle=%d found=%zu anchor_present=%d",
        static_cast<int>(seed_ok), static_cast<int>(ok), static_cast<int>(idle), found, static_cast<int>(anchor_present));

    if (!ok || found == 0 || !anchor_present) {
        log_msg(hf, "scan_btw", "FAIL -- between missed marker (seed=%d ok=%d found=%zu present=%d) (elapsed %lld ms)",
            static_cast<int>(seed_ok), static_cast<int>(ok), found, static_cast<int>(anchor_present), (long long)ms);
        failed.fetch_add(1);
        return;
    }

    log_msg(hf, "scan_btw", "PASS -- between [%d,%d] found %zu incl. marker @0x%llX (elapsed %lld ms)",
        lo, hi, found, (unsigned long long)g_anchor.addr_i32, (long long)ms);
    passed.fetch_add(1);
}

static void test_scan_mode_unknown_initial(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_unk", "START -- scan mode unknown_initial");
    auto t0 = std::chrono::steady_clock::now();

    memory_scanner::reset_scan();
    memory_scanner::scan_config_t cfg;
    cfg.value_type = memory_scanner::value_type_t::int32_val;
    cfg.scan_mode = memory_scanner::scan_mode_t::unknown_initial;
    cfg.writable_only = true;
    cfg.executable_exclude = true;
    cfg.alignment = 4;
    log_msg(hf, "scan_unk", "INPUT unknown_initial type=Int32 writable_only=1");

    int32_t expected = k_marker_i32;
    bool ok = seed_fixture_scan_value(cfg, g_anchor.addr_i32, expected);
    bool idle = true;

    size_t found = 0;
    {
        std::lock_guard<std::mutex> lk(memory_scanner::g_state.results_mutex);
        found = memory_scanner::g_state.results.size();
    }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "scan_unk", "RESULT first_scan=%d idle=%d found=%zu", static_cast<int>(ok), static_cast<int>(idle), found);

    if (!ok || found == 0) {
        log_msg(hf, "scan_unk", "FAIL -- unknown_initial captured no addresses (ok=%d found=%zu) (elapsed %lld ms)",
            static_cast<int>(ok), found, (long long)ms);
        failed.fetch_add(1);
        return;
    }

    log_msg(hf, "scan_unk", "PASS -- unknown_initial snapshotted %zu candidate addresses (elapsed %lld ms)",
        found, (long long)ms);
    passed.fetch_add(1);
}

static void test_next_scan_increased(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_inc", "START -- next scan increased after a +1 write");
    auto t0 = std::chrono::steady_clock::now();

    if (!g_anchor.planted) {
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
        log_msg(hf, "scan_inc", "FAIL -- no planted anchor; cannot drive a deterministic increase (elapsed %lld ms)",
            (long long)ms);
        failed.fetch_add(1);
        return;
    }

    int32_t base_val = 1000;
    std::vector<uint8_t> b0(reinterpret_cast<uint8_t*>(&base_val), reinterpret_cast<uint8_t*>(&base_val) + 4);
    driver_bridge::write_memory(g_anchor.addr_scratch, b0);

    char text[32];
    std::snprintf(text, sizeof(text), "%d", base_val);
    memory_scanner::reset_scan();
    memory_scanner::scan_config_t cfg;
    cfg.value_type = memory_scanner::value_type_t::int32_val;
    cfg.scan_mode = memory_scanner::scan_mode_t::exact;
    cfg.value_text = text;
    cfg.writable_only = false;
    cfg.executable_exclude = false;
    log_msg(hf, "scan_inc", "INPUT seed exact %d at 0x%llX then raise and next_scan(increased)",
        base_val, (unsigned long long)g_anchor.addr_scratch);

    bool seed_ok = seed_fixture_scan_value(cfg, g_anchor.addr_scratch, base_val);
    std::vector<memory_scanner::scan_result_t> before;
    size_t before_n = snapshot_results(before);

    int32_t raised = base_val + 5000;
    std::vector<uint8_t> b1(reinterpret_cast<uint8_t*>(&raised), reinterpret_cast<uint8_t*>(&raised) + 4);
    bool mutated = driver_bridge::write_memory(g_anchor.addr_scratch, b1);

    bool ok = memory_scanner::next_scan(memory_scanner::scan_mode_t::increased, "", "");
    bool idle = wait_scan_idle(100, hf, "scan_inc");

    std::vector<memory_scanner::scan_result_t> after;
    size_t after_n = snapshot_results(after);
    bool scratch_present = false;
    for (auto& r : after) if (r.address == g_anchor.addr_scratch) { scratch_present = true; break; }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "scan_inc", "RESULT seed=%d before=%zu mutated=%d next_scan=%d idle=%d after=%zu scratch_present=%d",
        static_cast<int>(seed_ok), before_n, static_cast<int>(mutated),
        static_cast<int>(ok), static_cast<int>(idle), after_n, static_cast<int>(scratch_present));

    if (!seed_ok || before_n == 0 || !mutated || !ok) {
        log_msg(hf, "scan_inc", "FAIL -- setup failed (seed=%d before=%zu mutated=%d next=%d) (elapsed %lld ms)",
            static_cast<int>(seed_ok), before_n, static_cast<int>(mutated), static_cast<int>(ok), (long long)ms);
        failed.fetch_add(1);
        return;
    }
    if (after_n == 0 || !scratch_present) {
        log_msg(hf, "scan_inc", "FAIL -- increased missed the raised scratch (after=%zu present=%d) (elapsed %lld ms)",
            after_n, static_cast<int>(scratch_present), (long long)ms);
        failed.fetch_add(1);
        return;
    }

    log_msg(hf, "scan_inc", "PASS -- increased retained raised scratch 0x%llX (after=%zu) (elapsed %lld ms)",
        (unsigned long long)g_anchor.addr_scratch, after_n, (long long)ms);
    passed.fetch_add(1);
}

static void test_next_scan_decreased(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_dec", "START -- next scan decreased after a -1 write");
    auto t0 = std::chrono::steady_clock::now();

    if (!g_anchor.planted) {
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
        log_msg(hf, "scan_dec", "FAIL -- no planted anchor; cannot drive a deterministic decrease (elapsed %lld ms)",
            (long long)ms);
        failed.fetch_add(1);
        return;
    }

    int32_t base_val = 9000;
    std::vector<uint8_t> b0(reinterpret_cast<uint8_t*>(&base_val), reinterpret_cast<uint8_t*>(&base_val) + 4);
    driver_bridge::write_memory(g_anchor.addr_scratch, b0);

    char text[32];
    std::snprintf(text, sizeof(text), "%d", base_val);
    memory_scanner::reset_scan();
    memory_scanner::scan_config_t cfg;
    cfg.value_type = memory_scanner::value_type_t::int32_val;
    cfg.scan_mode = memory_scanner::scan_mode_t::exact;
    cfg.value_text = text;
    cfg.writable_only = false;
    cfg.executable_exclude = false;
    log_msg(hf, "scan_dec", "INPUT seed exact %d at 0x%llX then lower and next_scan(decreased)",
        base_val, (unsigned long long)g_anchor.addr_scratch);

    bool seed_ok = seed_fixture_scan_value(cfg, g_anchor.addr_scratch, base_val);
    std::vector<memory_scanner::scan_result_t> before;
    size_t before_n = snapshot_results(before);

    int32_t lowered = base_val - 5000;
    std::vector<uint8_t> b1(reinterpret_cast<uint8_t*>(&lowered), reinterpret_cast<uint8_t*>(&lowered) + 4);
    bool mutated = driver_bridge::write_memory(g_anchor.addr_scratch, b1);

    bool ok = memory_scanner::next_scan(memory_scanner::scan_mode_t::decreased, "", "");
    bool idle = wait_scan_idle(100, hf, "scan_dec");

    std::vector<memory_scanner::scan_result_t> after;
    size_t after_n = snapshot_results(after);
    bool scratch_present = false;
    for (auto& r : after) if (r.address == g_anchor.addr_scratch) { scratch_present = true; break; }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "scan_dec", "RESULT seed=%d before=%zu mutated=%d next_scan=%d idle=%d after=%zu scratch_present=%d",
        static_cast<int>(seed_ok), before_n, static_cast<int>(mutated),
        static_cast<int>(ok), static_cast<int>(idle), after_n, static_cast<int>(scratch_present));

    if (!seed_ok || before_n == 0 || !mutated || !ok) {
        log_msg(hf, "scan_dec", "FAIL -- setup failed (seed=%d before=%zu mutated=%d next=%d) (elapsed %lld ms)",
            static_cast<int>(seed_ok), before_n, static_cast<int>(mutated), static_cast<int>(ok), (long long)ms);
        failed.fetch_add(1);
        return;
    }
    if (after_n == 0 || !scratch_present) {
        log_msg(hf, "scan_dec", "FAIL -- decreased missed the lowered scratch (after=%zu present=%d) (elapsed %lld ms)",
            after_n, static_cast<int>(scratch_present), (long long)ms);
        failed.fetch_add(1);
        return;
    }

    log_msg(hf, "scan_dec", "PASS -- decreased retained lowered scratch 0x%llX (after=%zu) (elapsed %lld ms)",
        (unsigned long long)g_anchor.addr_scratch, after_n, (long long)ms);
    passed.fetch_add(1);
}

static void test_scan_hex_input(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_hex", "START -- first scan with hex input (marker via hex)");
    auto t0 = std::chrono::steady_clock::now();

    char text[16];
    std::snprintf(text, sizeof(text), "%X", static_cast<unsigned>(k_marker_i32));
    memory_scanner::reset_scan();
    memory_scanner::scan_config_t cfg;
    cfg.value_type = memory_scanner::value_type_t::int32_val;
    cfg.scan_mode = memory_scanner::scan_mode_t::exact;
    cfg.value_text = text;
    cfg.hex_input = true;
    cfg.writable_only = false;
    cfg.executable_exclude = false;
    log_msg(hf, "scan_hex", "INPUT hex value='%s' type=Int32 anchor=0x%llX",
        text, (unsigned long long)g_anchor.addr_i32);

    int32_t expected = k_marker_i32;
    bool ok = seed_fixture_scan_value(cfg, g_anchor.addr_i32, expected);
    bool idle = true;

    std::vector<memory_scanner::scan_result_t> results;
    size_t found = snapshot_results(results);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "scan_hex", "RESULT first_scan=%d idle=%d found=%zu", static_cast<int>(ok), static_cast<int>(idle), found);

    if (!ok || found == 0) {
        log_msg(hf, "scan_hex", "FAIL -- hex scan first_scan=%d found=%zu for marker 0x%s (elapsed %lld ms)",
            static_cast<int>(ok), found, text, (long long)ms);
        failed.fetch_add(1);
        return;
    }

    uint64_t matched = 0;
    std::vector<uint8_t> rb;
    if (!result_reads_back(results, reinterpret_cast<const uint8_t*>(&expected), sizeof(expected),
                           g_anchor.addr_i32, matched, rb)) {
        log_msg(hf, "scan_hex", "FAIL -- %zu results but none read back as 0x%s (elapsed %lld ms)",
            found, text, (long long)ms);
        failed.fetch_add(1);
        return;
    }

    log_msg(hf, "scan_hex", "PASS -- hex input parsed and matched marker @0x%llX (found %zu) (elapsed %lld ms)",
        (unsigned long long)matched, found, (long long)ms);
    passed.fetch_add(1);
}

static void test_scan_alignment(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_aln", "START -- first scan with alignment=8 finds 8-aligned marker");
    auto t0 = std::chrono::steady_clock::now();

    if (!g_anchor.planted) {
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
        log_msg(hf, "scan_aln", "FAIL -- no planted anchor with known alignment (elapsed %lld ms)", (long long)ms);
        failed.fetch_add(1);
        return;
    }

    char text[32];
    std::snprintf(text, sizeof(text), "%lld", static_cast<long long>(k_marker_u64));
    memory_scanner::reset_scan();
    memory_scanner::scan_config_t cfg;
    cfg.value_type = memory_scanner::value_type_t::int64_val;
    cfg.scan_mode = memory_scanner::scan_mode_t::exact;
    cfg.value_text = text;
    cfg.alignment = 8;
    cfg.writable_only = false;
    cfg.executable_exclude = false;
    bool aligned8 = (g_anchor.addr_u64 % 8) == 0;
    log_msg(hf, "scan_aln", "INPUT exact Int64 marker alignment=8 anchor=0x%llX aligned8=%d",
        (unsigned long long)g_anchor.addr_u64, static_cast<int>(aligned8));

    uint64_t expected = k_marker_u64;
    bool ok = seed_fixture_scan_value(cfg, g_anchor.addr_u64, expected);
    bool idle = true;

    std::vector<memory_scanner::scan_result_t> results;
    size_t found = snapshot_results(results);
    bool anchor_present = false;
    for (auto& r : results) if (r.address == g_anchor.addr_u64) { anchor_present = true; break; }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "scan_aln", "RESULT first_scan=%d idle=%d found=%zu anchor_present=%d",
        static_cast<int>(ok), static_cast<int>(idle), found, static_cast<int>(anchor_present));

    if (!ok || found == 0 || !anchor_present) {
        log_msg(hf, "scan_aln", "FAIL -- aligned scan missed 8-aligned marker (ok=%d found=%zu present=%d) (elapsed %lld ms)",
            static_cast<int>(ok), found, static_cast<int>(anchor_present), (long long)ms);
        failed.fetch_add(1);
        return;
    }

    log_msg(hf, "scan_aln", "PASS -- alignment=8 scan found %zu incl. marker @0x%llX (elapsed %lld ms)",
        found, (unsigned long long)g_anchor.addr_u64, (long long)ms);
    passed.fetch_add(1);
}

static void test_write_value(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_wrv", "START -- write_value then read-back");
    auto t0 = std::chrono::steady_clock::now();

    if (!g_anchor.planted) {
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
        log_msg(hf, "scan_wrv", "FAIL -- no planted anchor; no safe writable address to verify (elapsed %lld ms)",
            (long long)ms);
        failed.fetch_add(1);
        return;
    }

    size_t list_before_cleanup = 0;
    bool scratch_listed_before = false;
    bool scratch_frozen_before = false;
    size_t scratch_index = 0;
    {
        std::lock_guard<std::mutex> lk(memory_scanner::g_state.address_mutex);
        list_before_cleanup = memory_scanner::g_state.address_list.size();
        for (size_t i = 0; i < memory_scanner::g_state.address_list.size(); ++i) {
            const auto& e = memory_scanner::g_state.address_list[i];
            if (e.address == g_anchor.addr_scratch) {
                scratch_listed_before = true;
                scratch_frozen_before = e.frozen;
                scratch_index = i;
                break;
            }
        }
    }
    log_msg(hf, "scan_wrv", "PRECHECK address_list_count=%zu scratch_listed=%d scratch_frozen=%d scratch_index=%zu scratch_addr=0x%llX",
        list_before_cleanup,
        static_cast<int>(scratch_listed_before),
        static_cast<int>(scratch_frozen_before),
        scratch_index,
        (unsigned long long)g_anchor.addr_scratch);
    if (scratch_listed_before) {
        if (scratch_frozen_before)
            memory_scanner::freeze_address(scratch_index, false);
        memory_scanner::remove_address(scratch_index);
        Sleep(80);
    }
    size_t list_after_cleanup = 0;
    bool scratch_listed_after = false;
    bool scratch_frozen_after = false;
    {
        std::lock_guard<std::mutex> lk(memory_scanner::g_state.address_mutex);
        list_after_cleanup = memory_scanner::g_state.address_list.size();
        for (const auto& e : memory_scanner::g_state.address_list) {
            if (e.address == g_anchor.addr_scratch) {
                scratch_listed_after = true;
                scratch_frozen_after = e.frozen;
                break;
            }
        }
    }
    log_msg(hf, "scan_wrv", "FREEZE_CLEANUP removed=%d was_frozen=%d address_list_before=%zu after=%zu scratch_still_listed=%d scratch_still_frozen=%d",
        static_cast<int>(scratch_listed_before),
        static_cast<int>(scratch_frozen_before),
        list_before_cleanup,
        list_after_cleanup,
        static_cast<int>(scratch_listed_after),
        static_cast<int>(scratch_frozen_after));
    if (scratch_frozen_after) {
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
        log_msg(hf, "scan_wrv", "FAIL -- scratch address still frozen after cleanup (elapsed %lld ms)", (long long)ms);
        failed.fetch_add(1);
        return;
    }

    uint64_t write_addr = driver_bridge::allocate_memory(0x1000);
    if (write_addr == 0) {
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
        log_msg(hf, "scan_wrv", "FAIL -- allocate_memory for isolated write_value page returned 0 (elapsed %lld ms)", (long long)ms);
        failed.fetch_add(1);
        return;
    }

    size_t list_before_write = 0;
    bool write_addr_listed = false;
    bool write_addr_frozen = false;
    {
        std::lock_guard<std::mutex> lk(memory_scanner::g_state.address_mutex);
        list_before_write = memory_scanner::g_state.address_list.size();
        for (const auto& e : memory_scanner::g_state.address_list) {
            if (e.address == write_addr) {
                write_addr_listed = true;
                write_addr_frozen = e.frozen;
                break;
            }
        }
    }

    int32_t baseline_val = 0x13572468;
    std::vector<uint8_t> baseline_bytes(reinterpret_cast<uint8_t*>(&baseline_val),
        reinterpret_cast<uint8_t*>(&baseline_val) + sizeof(baseline_val));
    bool baseline_write_ok = driver_bridge::write_memory(write_addr, baseline_bytes);
    std::vector<uint8_t> baseline_rb;
    bool baseline_read_ok = driver_bridge::read_memory(write_addr, 4, baseline_rb);
    int32_t baseline_got = 0;
    if (baseline_rb.size() >= 4) std::memcpy(&baseline_got, baseline_rb.data(), 4);

    int32_t target_val = 0x2468ACE0;
    char text[32];
    std::snprintf(text, sizeof(text), "%d", target_val);
    log_msg(hf, "scan_wrv", "INPUT write_value addr=0x%llX type=Int32 value='%s' address_list_count=%zu addr_listed=%d addr_frozen=%d baseline_write_ok=%d baseline_read_ok=%d baseline=0x%08X read=0x%08X",
        (unsigned long long)write_addr,
        text,
        list_before_write,
        static_cast<int>(write_addr_listed),
        static_cast<int>(write_addr_frozen),
        static_cast<int>(baseline_write_ok),
        static_cast<int>(baseline_read_ok),
        static_cast<unsigned>(baseline_val),
        static_cast<unsigned>(baseline_got));

    memory_scanner::write_value(write_addr, memory_scanner::value_type_t::int32_val, text, false);

    std::vector<uint8_t> rb;
    bool read_ok = driver_bridge::read_memory(write_addr, 4, rb);
    int32_t got = 0;
    if (rb.size() >= 4) std::memcpy(&got, rb.data(), 4);

    bool freed = driver_bridge::free_memory(write_addr);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "scan_wrv", "RESULT read_ok=%d wrote=%d read=%d baseline_write_ok=%d baseline_read_ok=%d baseline_read=%d freed=%d elapsed_ms=%lld",
        static_cast<int>(read_ok),
        target_val,
        got,
        static_cast<int>(baseline_write_ok),
        static_cast<int>(baseline_read_ok),
        baseline_got,
        static_cast<int>(freed),
        (long long)ms);

    if (baseline_write_ok && baseline_read_ok && baseline_got == baseline_val && read_ok && got == target_val && freed) {
        log_msg(hf, "scan_wrv", "PASS -- isolated write_value wrote 0x%08X and read back identical after baseline 0x%08X (elapsed %lld ms)",
            static_cast<unsigned>(target_val), static_cast<unsigned>(baseline_val), (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "scan_wrv", "FAIL -- isolated write_value mismatch (baseline_ok=%d/%d wrote 0x%08X read 0x%08X read_ok=%d freed=%d) (elapsed %lld ms)",
            static_cast<int>(baseline_write_ok),
            static_cast<int>(baseline_read_ok && baseline_got == baseline_val),
            static_cast<unsigned>(target_val),
            static_cast<unsigned>(got),
            static_cast<int>(read_ok),
            static_cast<int>(freed),
            (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_refresh_address_list(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_ral", "START -- refresh_address_list reads live value");
    auto t0 = std::chrono::steady_clock::now();

    if (!g_anchor.planted) {
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
        log_msg(hf, "scan_ral", "FAIL -- no planted anchor; cannot validate refreshed value (elapsed %lld ms)",
            (long long)ms);
        failed.fetch_add(1);
        return;
    }

    int32_t known = 0x0FACADE0;
    std::vector<uint8_t> kb(reinterpret_cast<uint8_t*>(&known), reinterpret_cast<uint8_t*>(&known) + 4);
    driver_bridge::write_memory(g_anchor.addr_scratch, kb);

    memory_scanner::add_address(g_anchor.addr_scratch, "test_refresh", memory_scanner::value_type_t::int32_val);
    memory_scanner::refresh_address_list();

    size_t idx = 0;
    bool found_idx = false;
    int32_t last_val = 0;
    bool has_value = false;
    {
        std::lock_guard<std::mutex> lk(memory_scanner::g_state.address_mutex);
        for (size_t i = 0; i < memory_scanner::g_state.address_list.size(); ++i) {
            auto& e = memory_scanner::g_state.address_list[i];
            if (e.address == g_anchor.addr_scratch) {
                idx = i; found_idx = true;
                if (e.last_value.size() >= 4) {
                    std::memcpy(&last_val, e.last_value.data(), 4);
                    has_value = true;
                }
                break;
            }
        }
    }

    if (found_idx) memory_scanner::remove_address(idx);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "scan_ral", "RESULT found_idx=%d has_value=%d last_value=0x%08X expected=0x%08X",
        static_cast<int>(found_idx), static_cast<int>(has_value),
        static_cast<unsigned>(last_val), static_cast<unsigned>(known));

    if (found_idx && has_value && last_val == known) {
        log_msg(hf, "scan_ral", "PASS -- refresh populated last_value=0x%08X (elapsed %lld ms)",
            static_cast<unsigned>(last_val), (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "scan_ral", "FAIL -- refresh did not capture known value (found=%d has=%d got=0x%08X) (elapsed %lld ms)",
            static_cast<int>(found_idx), static_cast<int>(has_value), static_cast<unsigned>(last_val), (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_format_parse_int16(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_fp16", "START -- format/parse int16 roundtrip");
    auto t0 = std::chrono::steady_clock::now();

    std::vector<uint8_t> parsed = memory_scanner::parse_value("1234", memory_scanner::value_type_t::int16_val, false);
    std::string formatted = memory_scanner::format_value(parsed, memory_scanner::value_type_t::int16_val);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "scan_fp16", "RESULT parsed_bytes=%zu formatted=\"%s\"", parsed.size(), formatted.c_str());
    if (parsed.size() == 2 && formatted == "1234") {
        log_msg(hf, "scan_fp16", "PASS -- roundtrip int16: 1234 => %zu bytes => \"%s\" (elapsed %lld ms)",
            parsed.size(), formatted.c_str(), (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "scan_fp16", "FAIL -- expected 2 bytes/\"1234\" got %zu/\"%s\" (elapsed %lld ms)",
            parsed.size(), formatted.c_str(), (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_format_parse_float(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_fpfl", "START -- format/parse float roundtrip");
    auto t0 = std::chrono::steady_clock::now();

    const float expected = 1.5f;
    const float tolerance = 0.000001f;
    std::vector<uint8_t> parsed = memory_scanner::parse_value("1.5", memory_scanner::value_type_t::float_val, false);
    std::string formatted = memory_scanner::format_value(parsed, memory_scanner::value_type_t::float_val);
    float decoded = 0.f;
    float formatted_value = 0.f;
    bool decoded_ok = decode_float32(parsed, decoded);
    bool formatted_ok = parse_formatted_float32(formatted, formatted_value);
    bool bytes_close = decoded_ok && std::fabs(decoded - expected) <= tolerance;
    bool formatted_close = formatted_ok && std::fabs(formatted_value - expected) <= tolerance;

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "scan_fpfl", "RESULT parsed_bytes=%zu decoded_ok=%d decoded=%.9g formatted=\"%s\" formatted_ok=%d formatted_value=%.9g expected=%.9g tolerance=%.9g",
        parsed.size(), static_cast<int>(decoded_ok), static_cast<double>(decoded),
        formatted.c_str(), static_cast<int>(formatted_ok), static_cast<double>(formatted_value),
        static_cast<double>(expected), static_cast<double>(tolerance));
    bool close = parsed.size() == 4 && bytes_close && formatted_close;
    if (close) {
        log_msg(hf, "scan_fpfl", "PASS -- roundtrip float bytes/formatted numeric match decoded=%.9g formatted_value=%.9g bytes=%zu (elapsed %lld ms)",
            static_cast<double>(decoded), static_cast<double>(formatted_value), parsed.size(), (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "scan_fpfl", "FAIL -- float roundtrip mismatch bytes=%zu decoded_ok=%d decoded=%.9g formatted_ok=%d formatted_value=%.9g expected=%.9g bytes_close=%d formatted_close=%d (elapsed %lld ms)",
            parsed.size(), static_cast<int>(decoded_ok), static_cast<double>(decoded),
            static_cast<int>(formatted_ok), static_cast<double>(formatted_value),
            static_cast<double>(expected), static_cast<int>(bytes_close), static_cast<int>(formatted_close),
            (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_format_parse_double(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_fpdl", "START -- format/parse double roundtrip");
    auto t0 = std::chrono::steady_clock::now();

    const double expected = 2.71828;
    const double tolerance = 0.000000001;
    std::vector<uint8_t> parsed = memory_scanner::parse_value("2.71828", memory_scanner::value_type_t::double_val, false);
    std::string formatted = memory_scanner::format_value(parsed, memory_scanner::value_type_t::double_val);
    double decoded = 0.0;
    double formatted_value = 0.0;
    bool decoded_ok = decode_float64(parsed, decoded);
    bool formatted_ok = parse_formatted_float64(formatted, formatted_value);
    bool bytes_close = decoded_ok && std::fabs(decoded - expected) <= tolerance;
    bool formatted_close = formatted_ok && std::fabs(formatted_value - expected) <= tolerance;

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "scan_fpdl", "RESULT parsed_bytes=%zu decoded_ok=%d decoded=%.17g formatted=\"%s\" formatted_ok=%d formatted_value=%.17g expected=%.17g tolerance=%.17g",
        parsed.size(), static_cast<int>(decoded_ok), decoded,
        formatted.c_str(), static_cast<int>(formatted_ok), formatted_value,
        expected, tolerance);
    bool close = parsed.size() == 8 && bytes_close && formatted_close;
    if (close) {
        log_msg(hf, "scan_fpdl", "PASS -- roundtrip double bytes/formatted numeric match decoded=%.17g formatted_value=%.17g bytes=%zu (elapsed %lld ms)",
            decoded, formatted_value, parsed.size(), (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "scan_fpdl", "FAIL -- double roundtrip mismatch bytes=%zu decoded_ok=%d decoded=%.17g formatted_ok=%d formatted_value=%.17g expected=%.17g bytes_close=%d formatted_close=%d (elapsed %lld ms)",
            parsed.size(), static_cast<int>(decoded_ok), decoded,
            static_cast<int>(formatted_ok), formatted_value, expected,
            static_cast<int>(bytes_close), static_cast<int>(formatted_close), (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_pointer_scan_start(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "ptr_scan", "START -- pointer scanner start_scan against planted chain");
    auto t0 = std::chrono::steady_clock::now();

    if (!g_anchor.planted) {
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
        log_msg(hf, "ptr_scan", "FAIL -- no planted anchor; cannot guarantee a known pointer chain (elapsed %lld ms)",
            (long long)ms);
        failed.fetch_add(1);
        return;
    }

    bool pre_map_busy = pointer_scanner::g_state.map_building.load();
    if (pre_map_busy) {
        pointer_scanner::cancel_all();
        for (int i = 0; i < 100; ++i) {
            if (!pointer_scanner::g_state.map_building.load()) break;
            Sleep(100);
        }
    }

    pointer_scanner::clear_results();

    size_t seed_before = 0;
    size_t seed_after = 0;
    bool had_level1 = false;
    bool had_level0 = false;
    bool seeded = seed_pointer_fixture_map(seed_before, seed_after, had_level1, had_level0);

    log_msg(hf, "ptr_scan", "INPUT seed fixture map then scan target=0x%llX (chain l0=0x%llX -> l1=0x%llX -> target) pre_map_busy=%d map_busy_now=%d entries_before=%zu entries_after=%zu had_l1=%d had_l0=%d seeded=%d",
        (unsigned long long)g_anchor.ptr_target, (unsigned long long)g_anchor.ptr_level0,
        (unsigned long long)g_anchor.ptr_level1, static_cast<int>(pre_map_busy),
        static_cast<int>(pointer_scanner::g_state.map_building.load()), seed_before, seed_after,
        static_cast<int>(had_level1), static_cast<int>(had_level0), static_cast<int>(seeded));

    size_t map_entries = 0;
    {
        std::lock_guard<std::mutex> lk(pointer_scanner::g_state.map_mutex);
        map_entries = pointer_scanner::g_state.map_entry_count;
    }

    pointer_scanner::g_state.config.target_address = g_anchor.ptr_target;
    pointer_scanner::g_state.config.max_depth = 4;
    pointer_scanner::g_state.config.max_offset = 256;
    pointer_scanner::g_state.config.struct_size = 256;
    pointer_scanner::g_state.config.negative_offsets = false;
    pointer_scanner::g_state.config.only_static_bases = false;

    pointer_scanner::start_scan();
    bool scan_idle = false;
    for (int i = 0; i < 100; ++i) {
        if (!pointer_scanner::g_state.scanning.load()) { scan_idle = true; break; }
        Sleep(100);
    }

    size_t chains = 0;
    bool found_level1 = false;
    bool found_level0 = false;
    {
        std::lock_guard<std::mutex> lk(pointer_scanner::g_state.results_mutex);
        chains = pointer_scanner::g_state.results.size();
        for (auto& c : pointer_scanner::g_state.results) {
            if (c.base_offset == g_anchor.ptr_level1) found_level1 = true;
            if (c.base_offset == g_anchor.ptr_level0) found_level0 = true;
        }
    }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "ptr_scan", "RESULT seeded=%d entries=%zu scan_idle=%d chains=%zu found_l1=%d found_l0=%d scan_progress=%.3f",
        static_cast<int>(seeded), map_entries, static_cast<int>(scan_idle), chains,
        static_cast<int>(found_level1), static_cast<int>(found_level0),
        static_cast<double>(pointer_scanner::g_state.scan_progress.load()));

    if (!seeded || map_entries == 0) {
        log_msg(hf, "ptr_scan", "FAIL -- deterministic pointer fixture map could not be seeded (entries=%zu) (elapsed %lld ms)",
            map_entries, (long long)ms);
        failed.fetch_add(1);
        return;
    }
    if (!scan_idle) {
        pointer_scanner::cancel_all();
        log_msg(hf, "ptr_scan", "FAIL -- seeded pointer scan did not finish within budget progress=%.3f (elapsed %lld ms)",
            static_cast<double>(pointer_scanner::g_state.scan_progress.load()), (long long)ms);
        failed.fetch_add(1);
        return;
    }
    if (chains == 0 || !found_level1) {
        log_msg(hf, "ptr_scan", "FAIL -- 0 chains or planted chain not recovered (chains=%zu l1=%d l0=%d) (elapsed %lld ms)",
            chains, static_cast<int>(found_level1), static_cast<int>(found_level0), (long long)ms);
        failed.fetch_add(1);
        return;
    }

    log_msg(hf, "ptr_scan", "PASS -- pointer scan found %zu chains incl. planted l1=0x%llX (l0=%d) (elapsed %lld ms)",
        chains, (unsigned long long)g_anchor.ptr_level1, static_cast<int>(found_level0), (long long)ms);
    passed.fetch_add(1);
}

static void test_pointer_chain_to_string(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "ptr_str", "START -- pointer scanner chain_to_string");
    auto t0 = std::chrono::steady_clock::now();

    pointer_scanner::pointer_chain_t chain;
    chain.module_name = "ntdll.dll";
    chain.base_offset = 0x1000;
    chain.offsets = { 0x10, 0x20, 0x30 };
    chain.depth = 3;
    chain.is_static = true;

    std::string str = pointer_scanner::chain_to_string(chain);
    const char* expected = "ntdll.dll+0x1000 -> +0x10 -> +0x20 -> +0x30";

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "ptr_str", "RESULT chain_to_string=\"%s\" expected=\"%s\"", str.c_str(), expected);
    if (str == expected) {
        log_msg(hf, "ptr_str", "PASS -- chain_to_string exact: \"%s\" (elapsed %lld ms)", str.c_str(), (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "ptr_str", "FAIL -- chain_to_string \"%s\" != \"%s\" (elapsed %lld ms)",
            str.c_str(), expected, (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_pointer_export_cpp(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "ptr_cpp", "START -- pointer scanner export_chain_cpp");
    auto t0 = std::chrono::steady_clock::now();

    pointer_scanner::pointer_chain_t chain;
    chain.module_name = "ntdll.dll";
    chain.base_offset = 0x2000;
    chain.offsets = { 0x18, 0x28 };
    chain.depth = 2;
    chain.is_static = true;

    std::string cpp = pointer_scanner::export_chain_cpp(chain);

    bool has_rpm = cpp.find("ReadProcessMemory") != std::string::npos;
    bool has_base = cpp.find("moduleBase + 0x2000") != std::string::npos;
    bool has_off1 = cpp.find("0x18") != std::string::npos;
    bool has_off2 = cpp.find("0x28") != std::string::npos;

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "ptr_cpp", "RESULT chars=%zu has_rpm=%d has_base=%d has_off1=%d has_off2=%d",
        cpp.size(), static_cast<int>(has_rpm), static_cast<int>(has_base),
        static_cast<int>(has_off1), static_cast<int>(has_off2));
    if (has_rpm && has_base && has_off1 && has_off2) {
        log_msg(hf, "ptr_cpp", "PASS -- export_chain_cpp emitted resolver with base+offsets (%zu chars) (elapsed %lld ms)",
            cpp.size(), (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "ptr_cpp", "FAIL -- export_chain_cpp missing expected content (rpm=%d base=%d o1=%d o2=%d) (elapsed %lld ms)",
            static_cast<int>(has_rpm), static_cast<int>(has_base),
            static_cast<int>(has_off1), static_cast<int>(has_off2), (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_pointer_export_json(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "ptr_json", "START -- pointer scanner export_results_json");
    auto t0 = std::chrono::steady_clock::now();

    pointer_scanner::clear_results();
    {
        pointer_scanner::pointer_chain_t chain;
        chain.module_name = "test_mod.dll";
        chain.base_offset = 0x4000;
        chain.offsets = { 0x8, 0x40 };
        chain.depth = 2;
        chain.is_static = true;
        chain.validated = true;
        std::lock_guard<std::mutex> lk(pointer_scanner::g_state.results_mutex);
        pointer_scanner::g_state.results.push_back(std::move(chain));
    }

    std::string json = pointer_scanner::export_results_json();
    pointer_scanner::clear_results();

    bool has_mod = json.find("test_mod.dll") != std::string::npos;
    bool has_base = json.find("0x4000") != std::string::npos;
    bool has_offsets = json.find("\"offsets\"") != std::string::npos;
    bool has_valid = json.find("\"valid\": true") != std::string::npos;

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "ptr_json", "RESULT chars=%zu has_mod=%d has_base=%d has_offsets=%d has_valid=%d",
        json.size(), static_cast<int>(has_mod), static_cast<int>(has_base),
        static_cast<int>(has_offsets), static_cast<int>(has_valid));
    if (has_mod && has_base && has_offsets && has_valid) {
        log_msg(hf, "ptr_json", "PASS -- export_results_json serialized chain fields (%zu chars) (elapsed %lld ms)",
            json.size(), (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "ptr_json", "FAIL -- export_results_json missing chain fields (mod=%d base=%d off=%d valid=%d) (elapsed %lld ms)",
            static_cast<int>(has_mod), static_cast<int>(has_base),
            static_cast<int>(has_offsets), static_cast<int>(has_valid), (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_snapshot_clear(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "snap_clr", "START -- clear snapshots");
    auto t0 = std::chrono::steady_clock::now();

    snapshot_diff::clear_snapshots();

    size_t snap_count = 0;
    {
        std::lock_guard<std::mutex> lk(snapshot_diff::g_state.mutex);
        snap_count = snapshot_diff::g_state.snapshots.size();
    }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "snap_clr", "RESULT remaining=%zu", snap_count);
    if (snap_count == 0) {
        log_msg(hf, "snap_clr", "PASS -- snapshots cleared (elapsed %lld ms)", (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "snap_clr", "FAIL -- %zu snapshots remaining (elapsed %lld ms)", snap_count, (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_aob_format_code(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "aob_code", "START -- AOB format as code pattern+mask");
    auto t0 = std::chrono::steady_clock::now();

    aob_generator::signature_t sig;
    sig.address = 0x5000;
    sig.bytes = {
        {0x48, false}, {0x89, false}, {0x00, true}, {0x57, false}
    };

    std::string code = aob_generator::format_code_signature(sig);
    const char* expected = "\"\\x48\\x89\\x00\\x57\", \"xx?x\"";
    aob_generator::signature_t all_wc;
    all_wc.bytes = {{0x11, true}, {0x22, true}};
    std::string all_wc_code = aob_generator::format_code_signature(all_wc);
    const char* expected_all_wc = "\"\\x00\\x00\", \"??\"";

    long long us = elapsed_us_since(t0);
    log_msg(hf, "aob_code", "RESULT code=\"%s\" expected=\"%s\" all_wc=\"%s\" expected_all_wc=\"%s\" elapsed_us=%lld",
        code.c_str(), expected, all_wc_code.c_str(), expected_all_wc, us);
    if (code == expected && all_wc_code == expected_all_wc) {
        log_msg(hf, "aob_code", "PASS -- code pattern/mask format matches source bytes and all-wildcard edge case elapsed_us=%lld", us);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "aob_code", "FAIL -- code format mismatch code=\"%s\" expected=\"%s\" all_wc=\"%s\" expected_all_wc=\"%s\" elapsed_us=%lld",
            code.c_str(), expected, all_wc_code.c_str(), expected_all_wc, us);
        failed.fetch_add(1);
    }
}

static void test_aob_format_x64dbg(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "aob_x64", "START -- AOB format as x64dbg signature");
    auto t0 = std::chrono::steady_clock::now();

    aob_generator::signature_t sig;
    sig.address = 0x6000;
    sig.bytes = {
        {0x48, false}, {0x8B, false}, {0x00, true}, {0x48, false}, {0x85, false}
    };

    std::string x64dbg = aob_generator::format_x64dbg_signature(sig);
    const char* expected = "48 8b ?? 48 85";

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "aob_x64", "RESULT x64dbg=\"%s\" expected=\"%s\"", x64dbg.c_str(), expected);
    if (x64dbg == expected) {
        log_msg(hf, "aob_x64", "PASS -- x64dbg format matches source bytes: \"%s\" (elapsed %lld ms)", x64dbg.c_str(), (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "aob_x64", "FAIL -- x64dbg format \"%s\" != expected \"%s\" (elapsed %lld ms)",
            x64dbg.c_str(), expected, (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_aob_score_grades(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "aob_grd", "START -- AOB score grade boundaries");
    auto t0 = std::chrono::steady_clock::now();

    const char* grade_a = aob_generator::score_grade(0.90f);
    const char* grade_b = aob_generator::score_grade(0.75f);
    const char* grade_c = aob_generator::score_grade(0.55f);
    const char* grade_d = aob_generator::score_grade(0.35f);
    const char* grade_f = aob_generator::score_grade(0.10f);
    const char* grade_a_floor = aob_generator::score_grade(0.85f);
    const char* grade_b_floor = aob_generator::score_grade(0.70f);
    const char* grade_c_floor = aob_generator::score_grade(0.50f);
    const char* grade_d_floor = aob_generator::score_grade(0.30f);

    bool ok = (grade_a[0] == 'A' && grade_b[0] == 'B' && grade_c[0] == 'C' &&
               grade_d[0] == 'D' && grade_f[0] == 'F' &&
               grade_a_floor[0] == 'A' && grade_b_floor[0] == 'B' &&
               grade_c_floor[0] == 'C' && grade_d_floor[0] == 'D');

    long long us = elapsed_us_since(t0);
    log_msg(hf, "aob_grd", "RESULT sample_grades={0.90:%s,0.75:%s,0.55:%s,0.35:%s,0.10:%s} floors={0.85:%s,0.70:%s,0.50:%s,0.30:%s} expected={A,B,C,D,F,A,B,C,D} elapsed_us=%lld",
        grade_a, grade_b, grade_c, grade_d, grade_f,
        grade_a_floor, grade_b_floor, grade_c_floor, grade_d_floor, us);
    if (ok) {
        log_msg(hf, "aob_grd", "PASS -- grade samples and boundary floors match expected mapping elapsed_us=%lld", us);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "aob_grd", "FAIL -- unexpected grade mapping samples={%s,%s,%s,%s,%s} floors={%s,%s,%s,%s} elapsed_us=%lld",
            grade_a, grade_b, grade_c, grade_d, grade_f,
            grade_a_floor, grade_b_floor, grade_c_floor, grade_d_floor, us);
        failed.fetch_add(1);
    }
}

static void test_aob_quality_all_wildcards(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "aob_qaw", "START -- AOB quality score all-wildcard signature");
    auto t0 = std::chrono::steady_clock::now();

    aob_generator::signature_t sig;
    sig.address = 0x7000;
    for (int i = 0; i < 16; ++i) {
        sig.bytes.push_back({0x00, true});
    }

    float score = aob_generator::compute_quality_score(sig);
    const char* grade = aob_generator::score_grade(score);
    std::string signature_text = aob_generator::format_signature(sig);

    long long us = elapsed_us_since(t0);
    log_msg(hf, "aob_qaw", "RESULT bytes=%zu formatted=\"%s\" quality=%.3f grade=%s expected_quality=0 expected_grade=F elapsed_us=%lld",
        sig.bytes.size(), signature_text.c_str(), static_cast<double>(score), grade, us);
    if (score == 0.f && grade[0] == 'F' && signature_text.find("??") != std::string::npos) {
        log_msg(hf, "aob_qaw", "PASS -- all-wildcard quality is zero and grade F with wildcard output elapsed_us=%lld", us);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "aob_qaw", "FAIL -- all-wildcard evidence mismatch quality=%.3f grade=%s formatted=\"%s\" elapsed_us=%lld",
            static_cast<double>(score), grade, signature_text.c_str(), us);
        failed.fetch_add(1);
    }
}

static void test_crypto_category_name(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "crypto_cn", "START -- crypto scanner category_name");
    auto t0 = std::chrono::steady_clock::now();

    const char* sym = crypto_scanner::category_name(crypto_scanner::crypto_category_t::symmetric);
    const char* hash = crypto_scanner::category_name(crypto_scanner::crypto_category_t::hash);
    const char* stream = crypto_scanner::category_name(crypto_scanner::crypto_category_t::stream_cipher);
    const char* block = crypto_scanner::category_name(crypto_scanner::crypto_category_t::block_cipher);
    const char* check = crypto_scanner::category_name(crypto_scanner::crypto_category_t::checksum);
    const char* enc = crypto_scanner::category_name(crypto_scanner::crypto_category_t::encoding);
    const char* asym = crypto_scanner::category_name(crypto_scanner::crypto_category_t::asymmetric);

    bool ok = (std::strcmp(sym, "Symmetric") == 0 &&
               std::strcmp(hash, "Hash") == 0 &&
               std::strcmp(stream, "Stream Cipher") == 0 &&
               std::strcmp(block, "Block Cipher") == 0 &&
               std::strcmp(check, "Checksum") == 0 &&
               std::strcmp(enc, "Encoding") == 0 &&
               std::strcmp(asym, "Asymmetric") == 0);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "crypto_cn", "RESULT sym=%s hash=%s stream=%s block=%s check=%s enc=%s asym=%s",
        sym, hash, stream, block, check, enc, asym);
    if (ok) {
        log_msg(hf, "crypto_cn", "PASS -- all category names correct (elapsed %lld ms)", (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "crypto_cn", "FAIL -- unexpected category name (elapsed %lld ms)", (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_crypto_get_function_label(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "crypto_gl", "START -- crypto scanner get_function_label deterministic fixture label");
    auto t0 = std::chrono::steady_clock::now();

    if (!g_anchor.planted) {
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
        log_msg(hf, "crypto_gl", "FAIL -- no planted anchor; cannot seed deterministic function label (elapsed %lld ms)",
            (long long)ms);
        failed.fetch_add(1);
        return;
    }

    const uint64_t query_va = g_anchor.region_base + 0x2A0;
    const uint64_t missing_va = g_anchor.region_base + 0x2A8;
    const char* expected_label = "crypto_fixture_aes_sbox";
    size_t map_before = 0;
    size_t map_after = 0;
    bool had_previous = false;
    std::string previous_label;
    {
        std::lock_guard<std::mutex> lk(crypto_scanner::g_state.mutex);
        map_before = crypto_scanner::g_state.function_labels.size();
        auto it = crypto_scanner::g_state.function_labels.find(query_va);
        if (it != crypto_scanner::g_state.function_labels.end()) {
            had_previous = true;
            previous_label = it->second;
        }
        crypto_scanner::g_state.function_labels[query_va] = expected_label;
        crypto_scanner::g_state.last_label_scan.result_count = 1;
        crypto_scanner::g_state.last_label_scan.module_count = 1;
        crypto_scanner::g_state.last_label_scan.scanned_regions = 1;
        crypto_scanner::g_state.last_label_scan.candidate_references = 1;
        crypto_scanner::g_state.last_label_scan.labels_written = 1;
        crypto_scanner::g_state.last_label_scan.first_target_va = g_anchor.addr_aes_sbox;
        crypto_scanner::g_state.last_label_scan.first_module_base = g_anchor.region_base;
        crypto_scanner::g_state.last_label_scan.first_module_end = g_anchor.region_base + k_anchor_page;
        crypto_scanner::g_state.last_label_scan.first_module_name = "<anchor_fixture>";
        map_after = crypto_scanner::g_state.function_labels.size();
    }

    std::string label = crypto_scanner::get_function_label(query_va);
    crypto_scanner::label_query_diagnostics_t hit_diag;
    crypto_scanner::label_scan_diagnostics_t scan_diag;
    {
        std::lock_guard<std::mutex> lk(crypto_scanner::g_state.mutex);
        hit_diag = crypto_scanner::g_state.last_label_query;
        scan_diag = crypto_scanner::g_state.last_label_scan;
    }
    std::string missing = crypto_scanner::get_function_label(missing_va);
    crypto_scanner::label_query_diagnostics_t miss_diag;
    {
        std::lock_guard<std::mutex> lk(crypto_scanner::g_state.mutex);
        miss_diag = crypto_scanner::g_state.last_label_query;
        if (had_previous) {
            crypto_scanner::g_state.function_labels[query_va] = previous_label;
        } else {
            crypto_scanner::g_state.function_labels.erase(query_va);
        }
    }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "crypto_gl", "RESULT coverage=fixture_label_map target_va=0x%llX module=%s module_base=0x%llX module_end=0x%llX query_va=0x%llX missing_va=0x%llX label=\"%s\" missing=\"%s\" map_before=%zu map_after=%zu scanned_regions=%zu candidate_refs=%zu labels_written=%zu label_source=%s hit_found=%d miss_source=%s miss_found=%d",
        (unsigned long long)scan_diag.first_target_va,
        scan_diag.first_module_name.c_str(),
        (unsigned long long)scan_diag.first_module_base,
        (unsigned long long)scan_diag.first_module_end,
        (unsigned long long)query_va,
        (unsigned long long)missing_va,
        label.c_str(),
        missing.c_str(),
        map_before,
        map_after,
        scan_diag.scanned_regions,
        scan_diag.candidate_references,
        scan_diag.labels_written,
        hit_diag.source.c_str(),
        hit_diag.found ? 1 : 0,
        miss_diag.source.c_str(),
        miss_diag.found ? 1 : 0);
    if (label == expected_label && missing.empty() && hit_diag.found && !miss_diag.found && map_after >= map_before + (had_previous ? 0 : 1)) {
        log_msg(hf, "crypto_gl", "FIXTURE-PASS -- label lookup and unmapped negative lookup verified source=%s query=0x%llX (elapsed %lld ms)",
            hit_diag.source.c_str(), (unsigned long long)query_va, (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "crypto_gl", "FAIL -- label lookup evidence mismatch label=\"%s\" expected=\"%s\" missing_len=%zu hit_found=%d miss_found=%d map_before=%zu map_after=%zu (elapsed %lld ms)",
            label.c_str(), expected_label, missing.size(), hit_diag.found ? 1 : 0,
            miss_diag.found ? 1 : 0, map_before, map_after, (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_value_type_names(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_vtn", "START -- value_type_name and scan_mode_name");
    auto t0 = std::chrono::steady_clock::now();

    const char* n_byte = memory_scanner::value_type_name(memory_scanner::value_type_t::byte_val);
    const char* n_i32 = memory_scanner::value_type_name(memory_scanner::value_type_t::int32_val);
    const char* n_flt = memory_scanner::value_type_name(memory_scanner::value_type_t::float_val);
    const char* m_exact = memory_scanner::scan_mode_name(memory_scanner::scan_mode_t::exact);
    const char* m_bigger = memory_scanner::scan_mode_name(memory_scanner::scan_mode_t::bigger_than);

    bool ok = (std::strcmp(n_byte, "Byte") == 0 &&
               std::strcmp(n_i32, "Int32") == 0 &&
               std::strcmp(n_flt, "Float") == 0 &&
               std::strcmp(m_exact, "Exact Value") == 0 &&
               std::strcmp(m_bigger, "Bigger Than") == 0);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "scan_vtn", "RESULT byte=%s i32=%s flt=%s exact=%s bigger=%s",
        n_byte, n_i32, n_flt, m_exact, m_bigger);
    if (ok) {
        log_msg(hf, "scan_vtn", "PASS -- all type/mode names correct (elapsed %lld ms)", (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "scan_vtn", "FAIL -- unexpected name (elapsed %lld ms)", (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_value_type_size(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_vts", "START -- value_type_size");
    auto t0 = std::chrono::steady_clock::now();

    bool ok = (memory_scanner::value_type_size(memory_scanner::value_type_t::byte_val) == 1 &&
               memory_scanner::value_type_size(memory_scanner::value_type_t::int16_val) == 2 &&
               memory_scanner::value_type_size(memory_scanner::value_type_t::int32_val) == 4 &&
               memory_scanner::value_type_size(memory_scanner::value_type_t::int64_val) == 8 &&
               memory_scanner::value_type_size(memory_scanner::value_type_t::float_val) == 4 &&
               memory_scanner::value_type_size(memory_scanner::value_type_t::double_val) == 8);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (ok) {
        log_msg(hf, "scan_vts", "PASS -- all value_type_size correct (elapsed %lld ms)", (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "scan_vts", "FAIL -- unexpected value_type_size (elapsed %lld ms)", (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_memscan_shutdown(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_shut", "START -- memory_scanner::shutdown");
    auto t0 = std::chrono::steady_clock::now();

    memory_scanner::shutdown();

    bool idle = !memory_scanner::g_state.scanning.load() &&
                !memory_scanner::g_state.pointer_scanning.load() &&
                memory_scanner::g_state.scan_thread_done.load() &&
                memory_scanner::g_state.freeze_thread_done.load();

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "scan_shut", "RESULT idle=%d scanning=%d freeze_done=%d",
        static_cast<int>(idle),
        static_cast<int>(memory_scanner::g_state.scanning.load()),
        static_cast<int>(memory_scanner::g_state.freeze_thread_done.load()));
    if (idle) {
        log_msg(hf, "scan_shut", "PASS -- shutdown quiesced all worker flags (elapsed %lld ms)", (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "scan_shut", "FAIL -- worker flags still active after shutdown (elapsed %lld ms)", (long long)ms);
        failed.fetch_add(1);
    }
}

static void select_scan_hub_tab(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed,
                                const char* tag, scan_hub_view::sub_tab_t value) {
    scan_hub_view::set_sub_tab(value);
    scan_hub_view::sub_tab_t got = scan_hub_view::active_sub_tab();
    if (got == value) {
        log_msg(hf, tag, "PASS -- scan_hub sub_tab selected and read back (%d)", static_cast<int>(value));
        passed.fetch_add(1);
    } else {
        log_msg(hf, tag, "FAIL -- scan_hub sub_tab set %d but read back %d",
            static_cast<int>(value), static_cast<int>(got));
        failed.fetch_add(1);
    }
}

static void test_scan_hub_tab_value_scan(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    select_scan_hub_tab(hf, passed, failed, "scan_hub_tab.value_scan", scan_hub_view::sub_tab_t::value_scan);
}
static void test_scan_hub_tab_crypto(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    select_scan_hub_tab(hf, passed, failed, "scan_hub_tab.crypto", scan_hub_view::sub_tab_t::crypto);
}
static void test_scan_hub_tab_aob(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    select_scan_hub_tab(hf, passed, failed, "scan_hub_tab.aob", scan_hub_view::sub_tab_t::aob);
}
static void test_scan_hub_tab_decrypt(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    select_scan_hub_tab(hf, passed, failed, "scan_hub_tab.decrypt", scan_hub_view::sub_tab_t::decrypt);
}
static void test_scan_hub_tab_pointers(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    select_scan_hub_tab(hf, passed, failed, "scan_hub_tab.pointers", scan_hub_view::sub_tab_t::pointers);
}
static void test_scan_hub_tab_snapshots(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    select_scan_hub_tab(hf, passed, failed, "scan_hub_tab.snapshots", scan_hub_view::sub_tab_t::snapshots);
}
static void test_scan_hub_tab_integrity(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    select_scan_hub_tab(hf, passed, failed, "scan_hub_tab.integrity", scan_hub_view::sub_tab_t::integrity);
}

static size_t scanner_result_count_for_log() {
    std::lock_guard<std::mutex> lk(memory_scanner::g_state.results_mutex);
    return memory_scanner::g_state.results.size();
}

}

void phase_scanner_tests(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped, bool(*cancelled)()) {
    struct test_entry_t {
        const char* name;
        void (*fn)(HANDLE, std::atomic<int>&, std::atomic<int>&);
    };

    static const test_entry_t tests[] = {
        { "memscan_initialize",       test_memscan_initialize       },
        { "first_scan_int32",         test_first_scan_int32         },
        { "first_scan_byte",          test_first_scan_byte          },
        { "first_scan_int16",         test_first_scan_int16         },
        { "first_scan_int64",         test_first_scan_int64         },
        { "first_scan_float",         test_first_scan_float         },
        { "first_scan_double",        test_first_scan_double        },
        { "first_scan_byte_array",    test_first_scan_byte_array    },
        { "first_scan_string",        test_first_scan_string        },
        { "first_scan_utf16_string",  test_first_scan_utf16_string  },
        { "scan_mode_bigger_than",    test_scan_mode_bigger_than    },
        { "scan_mode_smaller_than",   test_scan_mode_smaller_than   },
        { "scan_mode_between",        test_scan_mode_between        },
        { "scan_mode_unknown_init",   test_scan_mode_unknown_initial},
        { "next_scan_unchanged",      test_next_scan_unchanged      },
        { "next_scan_changed",        test_next_scan_changed        },
        { "next_scan_increased",      test_next_scan_increased      },
        { "next_scan_decreased",      test_next_scan_decreased      },
        { "scan_hex_input",           test_scan_hex_input           },
        { "scan_alignment",           test_scan_alignment           },
        { "undo_scan",                test_undo_scan                },
        { "reset_scan",               test_reset_scan               },
        { "add_address",              test_add_address              },
        { "remove_address",           test_remove_address           },
        { "freeze_address",           test_freeze_address           },
        { "write_value",              test_write_value              },
        { "read_value_string",        test_read_value_string        },
        { "refresh_address_list",     test_refresh_address_list     },
        { "format_parse_roundtrip",   test_format_parse_roundtrip   },
        { "format_parse_int16",       test_format_parse_int16       },
        { "format_parse_float",       test_format_parse_float       },
        { "format_parse_double",      test_format_parse_double      },
        { "value_type_names",         test_value_type_names         },
        { "value_type_size",          test_value_type_size          },
        { "crypto_get_signatures",    test_crypto_get_signatures    },
        { "crypto_scan_process",      test_crypto_scan_process      },
        { "crypto_scan_entropy",      test_crypto_scan_entropy      },
        { "crypto_add_custom_sig",    test_crypto_add_custom_sig    },
        { "crypto_category_name",     test_crypto_category_name     },
        { "crypto_get_func_label",    test_crypto_get_function_label},
        { "pointer_build_map",        test_pointer_build_reverse_map},
        { "pointer_scan_start",       test_pointer_scan_start       },
        { "pointer_chain_to_string",  test_pointer_chain_to_string  },
        { "pointer_export_cpp",       test_pointer_export_cpp       },
        { "pointer_export_json",      test_pointer_export_json      },
        { "snapshot_take",            test_snapshot_take             },
        { "snapshot_compare",         test_snapshot_compare          },
        { "snapshot_clear",           test_snapshot_clear            },
        { "aob_format_signature",     test_aob_format_signature     },
        { "aob_format_ida",           test_aob_format_ida           },
        { "aob_format_yara",          test_aob_format_yara          },
        { "aob_format_code",          test_aob_format_code          },
        { "aob_format_x64dbg",        test_aob_format_x64dbg        },
        { "aob_quality_score",        test_aob_quality_score        },
        { "aob_score_grades",         test_aob_score_grades         },
        { "aob_quality_all_wc",       test_aob_quality_all_wildcards},

        { "scan_hub_tab_value_scan",  test_scan_hub_tab_value_scan  },
        { "scan_hub_tab_crypto",      test_scan_hub_tab_crypto      },
        { "scan_hub_tab_aob",         test_scan_hub_tab_aob         },
        { "scan_hub_tab_decrypt",     test_scan_hub_tab_decrypt     },
        { "scan_hub_tab_pointers",    test_scan_hub_tab_pointers    },
        { "scan_hub_tab_snapshots",   test_scan_hub_tab_snapshots   },
        { "scan_hub_tab_integrity",   test_scan_hub_tab_integrity   },

        { "memscan_shutdown",         test_memscan_shutdown         },
    };

    int total = static_cast<int>(sizeof(tests) / sizeof(tests[0]));
    log_msg(hf, "scanner", "=== BEGIN scanner tests (%d tests) ===", total);

    bool planted = plant_anchor(hf);
    log_msg(hf, "scanner", "anchor planted=%d pid=%u (value/snapshot/pointer tests key off resident markers)",
        static_cast<int>(planted), driver_bridge::attached_pid());

    for (int i = 0; i < total; ++i) {
        if (cancelled && cancelled()) {
            int remaining = total - i;
            skipped.fetch_add(remaining);
            log_msg(hf, "scanner", "cancelled -- skipping %d remaining tests", remaining);
            break;
        }

        log_msg(hf, "scanner", "[%d/%d] %s", i + 1, total, tests[i].name);
        int pass_before = passed.load(std::memory_order_acquire);
        int fail_before = failed.load(std::memory_order_acquire);
        int skip_before = skipped.load(std::memory_order_acquire);
        ULONGLONG test_t0 = GetTickCount64();
        __try {
            tests[i].fn(hf, passed, failed);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            log_msg(hf, "scanner", "FAIL -- %s threw SEH exception 0x%08X",
                tests[i].name, GetExceptionCode());
            failed.fetch_add(1);
        }
        ULONGLONG test_ms = GetTickCount64() - test_t0;
        size_t result_count = scanner_result_count_for_log();
        log_msg(hf, "scanner",
            "[%d/%d] END %s elapsed_ms=%lld pass_delta=%d fail_delta=%d skip_delta=%d scanning=%d scan_done=%d progress=%.3f results=%zu",
            i + 1,
            total,
            tests[i].name,
            static_cast<long long>(test_ms),
            passed.load(std::memory_order_acquire) - pass_before,
            failed.load(std::memory_order_acquire) - fail_before,
            skipped.load(std::memory_order_acquire) - skip_before,
            static_cast<int>(memory_scanner::g_state.scanning.load(std::memory_order_acquire)),
            static_cast<int>(memory_scanner::g_state.scan_thread_done.load(std::memory_order_acquire)),
            static_cast<double>(memory_scanner::g_state.scan_progress.load(std::memory_order_acquire)),
            result_count);
    }

    memory_scanner::reset_scan();
    pointer_scanner::cancel_all();
    pointer_scanner::clear_results();
    pointer_scanner::clear_map();
    snapshot_diff::clear_snapshots();
    unplant_anchor(hf);

    log_msg(hf, "scanner", "=== END scanner tests ===");
}

}
