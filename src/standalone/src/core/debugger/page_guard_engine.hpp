#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include "work_queue.hpp"
#include <tlhelp32.h>

#include "standalone_driver.hpp"

#include <atomic>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace page_guard_engine {


struct pg_capture_t {
    uint64_t timestamp;
    uint64_t fault_addr;
    uint64_t rip;
    uint64_t ctx_rax;
    uint64_t ctx_rcx;
    uint64_t ctx_rdx;
    uint32_t exception_code;
    uint32_t access_type;
    uint8_t  pad[8];
};

static_assert(sizeof(pg_capture_t) == 64, "pg_capture_t must be 64 bytes");


struct pg_ring_header_t {
    volatile uint32_t write_idx;
    volatile uint32_t read_idx;
    uint32_t          reserved0;
    uint32_t          reserved1;
};

static_assert(sizeof(pg_ring_header_t) == 16, "pg_ring_header_t must be 16 bytes");

static constexpr uint32_t RING_ENTRIES    = 256;
static constexpr uint32_t RING_TOTAL_SIZE = sizeof(pg_ring_header_t) +
                                             RING_ENTRIES * sizeof(pg_capture_t);


static constexpr size_t SHELLCODE_SIZE          = 265;
static constexpr size_t PATCH_RING_BASE         = 50;
static constexpr size_t PATCH_PAGE_BASE         = 183;
static constexpr size_t PATCH_PAGE_SIZE         = 196;
static constexpr size_t PATCH_ORIG_PROTECT      = 208;
static constexpr size_t PATCH_VIRT_PROTECT      = 227;


static inline std::vector<uint8_t> generate_veh_shellcode(
        uint64_t ring_base,
        uint64_t page_base,
        uint64_t page_size,
        uint32_t orig_protect,
        uint64_t virt_protect_fn)
{


    static const uint8_t kTemplate[SHELLCODE_SIZE] = {

        0x53,
        0x56,
        0x57,
        0x41, 0x55,
        0x41, 0x56,
        0x48, 0x83, 0xEC, 0x28,
        0x49, 0x89, 0xCD,
        0x48, 0x8B, 0x19,
        0x8B, 0x03,
        0x3D, 0x01, 0x00, 0x00, 0x80,
        0x0F, 0x84, 0x12, 0x00, 0x00, 0x00,
        0x3D, 0x04, 0x00, 0x00, 0x80,
        0x0F, 0x84, 0x8C, 0x00, 0x00, 0x00,
        0x33, 0xC0,
        0xE9, 0xCD, 0x00, 0x00, 0x00,

        0x48, 0xB8,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x44, 0x8B, 0x00,
        0x45, 0x0F, 0xB6, 0xC0,
        0x41, 0xC1, 0xE0, 0x06,
        0x48, 0x8D, 0x48, 0x10,
        0x49, 0x03, 0xC8,
        0x48, 0x89, 0xC6,
        0x0F, 0x31,
        0x48, 0xC1, 0xE2, 0x20,
        0x48, 0x0B, 0xC2,
        0x48, 0x89, 0x01,
        0x48, 0x8B, 0x43, 0x10,
        0x48, 0x89, 0x41, 0x08,
        0x49, 0x8B, 0x55, 0x08,
        0x48, 0x8B, 0x82, 0xF8, 0x00, 0x00, 0x00,
        0x48, 0x89, 0x41, 0x10,
        0x48, 0x8B, 0x42, 0x78,
        0x48, 0x89, 0x41, 0x18,
        0x48, 0x8B, 0x82, 0x80, 0x00, 0x00, 0x00,
        0x48, 0x89, 0x41, 0x20,
        0x48, 0x8B, 0x82, 0x88, 0x00, 0x00, 0x00,
        0x48, 0x89, 0x41, 0x28,
        0x8B, 0x03,
        0x89, 0x41, 0x30,
        0x8B, 0x43, 0x20,
        0x89, 0x41, 0x34,
        0x8B, 0x06,
        0xFF, 0xC0,
        0x0F, 0xB6, 0xC0,
        0x89, 0x06,
        0x81, 0x4A, 0x44, 0x00, 0x01, 0x00, 0x00,
        0xB8, 0xFF, 0xFF, 0xFF, 0xFF,
        0xE9, 0x48, 0x00, 0x00, 0x00,

        0x48, 0xB8,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x48, 0x89, 0xC1,
        0x48, 0xB8,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x48, 0x89, 0xC2,
        0xB8,
        0x00, 0x00, 0x00, 0x00,
        0x0D, 0x00, 0x01, 0x00, 0x00,
        0x41, 0x89, 0xC0,
        0x4C, 0x8D, 0x4C, 0x24, 0x20,
        0x48, 0xB8,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xFF, 0xD0,
        0x49, 0x8B, 0x4D, 0x08,
        0x81, 0x61, 0x44, 0xFF, 0xFE, 0xFF, 0xFF,
        0xB8, 0xFF, 0xFF, 0xFF, 0xFF,

        0x48, 0x83, 0xC4, 0x28,
        0x41, 0x5E,
        0x41, 0x5D,
        0x5F,
        0x5E,
        0x5B,
        0xC3,
    };

    static_assert(sizeof(kTemplate) == SHELLCODE_SIZE,
                  "shellcode template size mismatch");

    std::vector<uint8_t> sc(kTemplate, kTemplate + SHELLCODE_SIZE);


    auto patch64 = [&](size_t off, uint64_t v) {
        memcpy(sc.data() + off, &v, 8);
    };
    auto patch32 = [&](size_t off, uint32_t v) {
        memcpy(sc.data() + off, &v, 4);
    };

    patch64(PATCH_RING_BASE,    ring_base);
    patch64(PATCH_PAGE_BASE,    page_base);
    patch64(PATCH_PAGE_SIZE,    page_size);
    patch32(PATCH_ORIG_PROTECT, orig_protect);
    patch64(PATCH_VIRT_PROTECT, virt_protect_fn);

    return sc;
}


struct pg_session_t {
    uint32_t session_id    = 0;
    uint32_t pid           = 0;
    uint64_t target_addr   = 0;
    uint64_t region_size   = 0;
    uint64_t ring_addr     = 0;
    uint64_t sc_addr       = 0;
    uint32_t orig_protect  = 0;
    uint64_t veh_handle    = 0;

    std::mutex                 captures_mutex;
    std::queue<pg_capture_t>   captures;

    std::atomic<bool>          polling{false};


    uint32_t prev_write_idx   = 0;
    uint64_t total_captured   = 0;
    uint64_t estimated_drops  = 0;

    pg_session_t() = default;
    ~pg_session_t() {
        polling.store(false);
    }

    pg_session_t(const pg_session_t&)            = delete;
    pg_session_t& operator=(const pg_session_t&) = delete;
};


class pg_engine_t {
public:
    pg_engine_t() = default;
    ~pg_engine_t() {
        std::lock_guard<std::mutex> lk(sessions_mutex_);
        sessions_.clear();
    }

    pg_engine_t(const pg_engine_t&)            = delete;
    pg_engine_t& operator=(const pg_engine_t&) = delete;


    uint32_t install(uint32_t pid, uint64_t target_addr, uint64_t region_size) {
        if (!driver_bridge::using_kernel_driver()) return 0;


        driver_bridge::memory_region_t mri{};
        if (!driver_bridge::query_memory(target_addr, mri))     return 0;
        uint32_t orig_protect = mri.protect;


        uint64_t k32_base = find_module_base(pid, "kernel32.dll");
        if (k32_base == 0) return 0;
        uint64_t virt_protect_fn = driver_bridge::resolve_export(k32_base, "VirtualProtect");
        if (virt_protect_fn == 0) return 0;


        uint64_t ring_addr = driver_bridge::allocate_memory(RING_TOTAL_SIZE + 16);
        if (ring_addr == 0) return 0;

        uint64_t sc_addr = driver_bridge::allocate_memory(SHELLCODE_SIZE + 16);
        if (sc_addr == 0) return 0;


        std::vector<uint8_t> zeroes(RING_TOTAL_SIZE, 0);
        driver_bridge::write_memory(ring_addr, zeroes);


        auto sc = generate_veh_shellcode(ring_addr, target_addr,
                                         region_size, orig_protect,
                                         virt_protect_fn);
        driver_bridge::write_memory(sc_addr, sc);


        uint32_t old_prot = 0;
        if (!driver_bridge::protect_memory(target_addr, region_size,
                                    orig_protect | 0x100 , &old_prot))
            return 0;


        uint64_t ntdll_base_install = find_module_base(pid, "ntdll.dll");
        if (ntdll_base_install == 0) return 0;
        uint64_t rtl_add_fn = driver_bridge::resolve_export(ntdll_base_install,
                                                      "RtlAddVectoredExceptionHandler");
        if (rtl_add_fn == 0) return 0;

        uint64_t veh_handle = driver_bridge::call_function(rtl_add_fn, 1, sc_addr);


        auto session         = std::make_unique<pg_session_t>();
        session->pid         = pid;
        session->target_addr = target_addr;
        session->region_size = region_size;
        session->ring_addr   = ring_addr;
        session->sc_addr     = sc_addr;
        session->orig_protect= orig_protect;
        session->veh_handle  = veh_handle;
        session->polling.store(true);

        uint32_t sid = next_id_++;
        session->session_id = sid;

        auto* sess_ptr = session.get();
        work_queue::post([this, sess_ptr]() {
            poll_ring(sess_ptr);
        });

        std::lock_guard<std::mutex> lk(sessions_mutex_);
        sessions_[sid] = std::move(session);
        return sid;
    }


    std::vector<pg_capture_t> get_captures(uint32_t session_id) {
        std::lock_guard<std::mutex> lk(sessions_mutex_);
        auto it = sessions_.find(session_id);
        if (it == sessions_.end()) return {};

        auto& sess = *it->second;
        std::lock_guard<std::mutex> slk(sess.captures_mutex);
        std::vector<pg_capture_t> out;
        while (!sess.captures.empty()) {
            out.push_back(sess.captures.front());
            sess.captures.pop();
        }
        return out;
    }


    bool uninstall(uint32_t session_id) {
        std::unique_ptr<pg_session_t> sess;
        {
            std::lock_guard<std::mutex> lk(sessions_mutex_);
            auto it = sessions_.find(session_id);
            if (it == sessions_.end()) return false;
            sess = std::move(it->second);
            sessions_.erase(it);
        }


        sess->polling.store(false);

        if (driver_bridge::using_kernel_driver()) {

            if (sess->veh_handle) {
                uint64_t ntdll_base = find_module_base(sess->pid, "ntdll.dll");
                if (ntdll_base) {
                    uint64_t rtl_rm = driver_bridge::resolve_export(ntdll_base,
                                                              "RtlRemoveVectoredExceptionHandler");
                    if (rtl_rm) driver_bridge::call_function(rtl_rm, sess->veh_handle);
                }
            }

            driver_bridge::protect_memory(sess->target_addr, sess->region_size,
                                   sess->orig_protect, nullptr);
        }
        return true;
    }


    struct session_info_t {
        uint32_t session_id;
        uint32_t pid;
        uint64_t target_addr;
        uint64_t region_size;
        size_t   pending_captures;
    };

    std::vector<session_info_t> list_sessions() {
        std::lock_guard<std::mutex> lk(sessions_mutex_);
        std::vector<session_info_t> out;
        for (auto& [sid, sess] : sessions_) {
            session_info_t si;
            si.session_id  = sid;
            si.pid         = sess->pid;
            si.target_addr = sess->target_addr;
            si.region_size = sess->region_size;
            {
                std::lock_guard<std::mutex> slk(sess->captures_mutex);
                si.pending_captures = sess->captures.size();
            }
            out.push_back(si);
        }
        return out;
    }


    static uint64_t find_module_base(uint32_t pid, const char* name_lower) noexcept {
        auto modules = driver_bridge::enumerate_modules();
        for (const auto& m : modules) {
            std::string lower_name = m.name;
            for (char& c : lower_name)
                c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
            if (lower_name == name_lower)
                return m.base;
        }
        return 0;
    }

private:
    void poll_ring(pg_session_t* sess) {
        while (sess->polling.load()) {
            if (driver_bridge::using_kernel_driver()) {
                drain_ring(sess);
            }

            if (sess->polling.load())
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    }

    void drain_ring(pg_session_t* sess) {

        pg_ring_header_t hdr{};
        std::vector<uint8_t> hdr_buf;
        if (!driver_bridge::read_memory(sess->ring_addr, sizeof(hdr), hdr_buf) || hdr_buf.size() < sizeof(hdr))
            return;
        std::memcpy(&hdr, hdr_buf.data(), sizeof(hdr));

        uint32_t w = hdr.write_idx & (RING_ENTRIES - 1);
        uint32_t r = hdr.read_idx  & (RING_ENTRIES - 1);


        if (w == r && w != sess->prev_write_idx) {
            sess->estimated_drops += RING_ENTRIES;
        }
        sess->prev_write_idx = w;

        uint64_t drained = 0;
        while (r != w) {
            pg_capture_t entry{};
            uint64_t entry_addr = sess->ring_addr + sizeof(pg_ring_header_t)
                                  + r * sizeof(pg_capture_t);
            std::vector<uint8_t> entry_buf;
            if (driver_bridge::read_memory(entry_addr, sizeof(entry), entry_buf) && entry_buf.size() >= sizeof(entry)) {
                std::memcpy(&entry, entry_buf.data(), sizeof(entry));
                std::lock_guard<std::mutex> lk(sess->captures_mutex);
                sess->captures.push(entry);
            }
            r = (r + 1) & (RING_ENTRIES - 1);
            drained++;
        }
        sess->total_captured += drained;

        if (r != (hdr.read_idx & (RING_ENTRIES - 1))) {

            uint32_t new_r = r;
            std::vector<uint8_t> r_buf(sizeof(new_r));
            std::memcpy(r_buf.data(), &new_r, sizeof(new_r));
            driver_bridge::write_memory(sess->ring_addr + offsetof(pg_ring_header_t, read_idx), r_buf);
        }
    }

    std::mutex sessions_mutex_;
    std::unordered_map<uint32_t, std::unique_ptr<pg_session_t>> sessions_;
    uint32_t next_id_ = 1;
};

inline pg_engine_t g_pg_engine;

}
