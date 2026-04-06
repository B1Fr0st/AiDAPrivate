#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <tlhelp32.h>

#include "../../../driver/comm.h"

#include <atomic>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

extern std::unique_ptr<voyager::device_t> device;

namespace page_guard_engine {

// ---------------------------------------------------------------------------
// Ring-buffer layout in the target process (no heap allocations needed)
// ---------------------------------------------------------------------------

// 64-byte capture entry written by the VEH handler
struct pg_capture_t {
    uint64_t timestamp;      // RDTSC value
    uint64_t fault_addr;     // address that triggered the guard fault
    uint64_t rip;            // instruction pointer at fault
    uint64_t ctx_rax;        // RAX from CONTEXT
    uint64_t ctx_rcx;        // RCX from CONTEXT
    uint64_t ctx_rdx;        // RDX from CONTEXT
    uint32_t exception_code; // EXCEPTION_GUARD_PAGE etc.
    uint32_t access_type;    // 0 = read, 1 = write (ExceptionInformation[0])
    uint8_t  pad[8];
}; // 64 bytes

static_assert(sizeof(pg_capture_t) == 64, "pg_capture_t must be 64 bytes");

// 16-byte ring header
struct pg_ring_header_t {
    volatile uint32_t write_idx;
    volatile uint32_t read_idx;
    uint8_t           pad[8];
}; // 16 bytes

static_assert(sizeof(pg_ring_header_t) == 16, "pg_ring_header_t must be 16 bytes");

static constexpr uint32_t RING_ENTRIES    = 16;
static constexpr uint32_t RING_TOTAL_SIZE = sizeof(pg_ring_header_t) +
                                             RING_ENTRIES * sizeof(pg_capture_t);
// = 16 + 16*64 = 1040 bytes

// ---------------------------------------------------------------------------
// Shellcode generation
// ---------------------------------------------------------------------------
//
// Generates a PIC x64 VEH handler of exactly 265 bytes.
//
// Handler logic:
//   On EXCEPTION_GUARD_PAGE (0x80000001):
//     - Write timestamp (RDTSC), fault address, RIP, RAX, RCX, RDX,
//       exception_code, access_type to the ring entry at write_idx.
//     - Increment write_idx (wrapping at 16).
//     - Set TF bit in Context->EFlags so single-step fires after the
//       faulting instruction, allowing PAGE_GUARD to be re-armed.
//     - Return EXCEPTION_CONTINUE_EXECUTION (-1).
//
//   On EXCEPTION_SINGLE_STEP (0x80000004):
//     - Call VirtualProtect(page_base, page_size, orig_protect|PAGE_GUARD,
//                           &dummy) to re-arm the guard.
//     - Clear TF bit in Context->EFlags.
//     - Return EXCEPTION_CONTINUE_EXECUTION (-1).
//
//   Otherwise: return EXCEPTION_CONTINUE_SEARCH (0).
//
// Patch offsets for parameters embedded in the shellcode:
//   PATCH_RING_BASE    = 50   (64-bit LE, in MOVABS rax, <ring_base>)
//   PATCH_PAGE_BASE    = 183  (64-bit LE, in MOVABS rax, <page_base>)
//   PATCH_PAGE_SIZE    = 196  (64-bit LE, in MOVABS rax, <page_size>)
//   PATCH_ORIG_PROTECT = 208  (32-bit LE, in MOV eax, <orig_protect>)
//   PATCH_VIRT_PROTECT = 227  (64-bit LE, in MOVABS rax, <virt_protect_fn>)

static constexpr size_t SHELLCODE_SIZE          = 265;
static constexpr size_t PATCH_RING_BASE         = 50;
static constexpr size_t PATCH_PAGE_BASE         = 183;
static constexpr size_t PATCH_PAGE_SIZE         = 196;
static constexpr size_t PATCH_ORIG_PROTECT      = 208;
static constexpr size_t PATCH_VIRT_PROTECT      = 227;

// Base shellcode template (zeroed slots for the 5 patched values).
// Each slot is indicated by an 8-byte or 4-byte run of 0x00 within the
// MOVABS / MOV sequences at the offsets stated above.
static inline std::vector<uint8_t> generate_veh_shellcode(
        uint64_t ring_base,
        uint64_t page_base,
        uint64_t page_size,
        uint32_t orig_protect,
        uint64_t virt_protect_fn)
{
    // clang-format off
    //
    // Verified layout (265 bytes):
    //
    // +000  53                   push rbx
    // +001  56                   push rsi
    // +002  57                   push rdi
    // +003  41 55                push r13
    // +005  41 56                push r14
    // +007  48 83 EC 28          sub  rsp, 0x28
    // +011  49 89 CD             mov  r13, rcx          ; ExceptionPointers
    // +014  48 8B 19             mov  rbx, [rcx]        ; ExceptionRecord
    // +017  8B 03                mov  eax, [rbx]        ; ExceptionCode
    // +019  3D 01 00 00 80       cmp  eax, 0x80000001   ; EXCEPTION_GUARD_PAGE
    // +024  0F 84 12 00 00 00    je   +050              ; guard_page_handler
    // +030  3D 04 00 00 80       cmp  eax, 0x80000004   ; EXCEPTION_SINGLE_STEP
    // +035  0F 84 8C 00 00 00    je   +181              ; single_step_handler
    // +041  33 C0                xor  eax, eax          ; EXCEPTION_CONTINUE_SEARCH
    // +043  E9 CD 00 00 00       jmp  +253              ; epilog
    //
    // +048 [guard_page_handler]:
    // +048  48 B8 [8]            movabs rax, ring_base
    // +058  44 8B 00             mov  r8d,[rax]         ; write_idx
    // +061  41 83 E0 0F          and  r8d, 15
    // +065  41 C1 E0 06          shl  r8d, 6            ; * 64
    // +069  48 8D 48 10          lea  rcx,[rax+16]      ; first entry
    // +073  49 03 C8             add  rcx, r8           ; entry ptr
    // +076  48 89 C6             mov  rsi, rax          ; save ring_base
    // +079  0F 31                rdtsc
    // +081  48 C1 E2 20          shl  rdx, 32
    // +085  48 0B C2             or   rax, rdx
    // +088  48 89 01             mov  [rcx], rax        ; entry->timestamp
    // +091  48 8B 43 10          mov  rax,[rbx+0x10]    ; ExceptionAddress
    // +095  48 89 41 08          mov  [rcx+8], rax      ; entry->fault_addr
    // +099  49 8B 55 08          mov  rdx,[r13+8]       ; ContextRecord
    // +103  48 8B 82 F8 00 00 00 mov  rax,[rdx+0xF8]   ; Context.Rip
    // +110  48 89 41 10          mov  [rcx+0x10], rax   ; entry->rip
    // +114  48 8B 42 78          mov  rax,[rdx+0x78]    ; Context.Rax
    // +118  48 89 41 18          mov  [rcx+0x18], rax   ; entry->ctx_rax
    // +122  48 8B 82 80 00 00 00 mov  rax,[rdx+0x80]   ; Context.Rcx
    // +129  48 89 41 20          mov  [rcx+0x20], rax   ; entry->ctx_rcx
    // +133  48 8B 82 88 00 00 00 mov  rax,[rdx+0x88]   ; Context.Rdx
    // +140  48 89 41 28          mov  [rcx+0x28], rax   ; entry->ctx_rdx
    // +144  8B 03                mov  eax,[rbx]         ; ExceptionCode (re-read)
    // +146  89 41 30             mov  [rcx+0x30], eax   ; entry->exception_code
    // +149  8B 43 20             mov  eax,[rbx+0x20]    ; ExceptionInformation[0]
    // +152  89 41 34             mov  [rcx+0x34], eax   ; entry->access_type
    // +155  8B 06                mov  eax,[rsi]         ; reload write_idx
    // +157  FF C0                inc  eax
    // +159  83 E0 0F             and  eax, 15
    // +162  89 06                mov  [rsi], eax        ; store write_idx
    // +164  81 4A 44 00 01 00 00 or   dword[rdx+0x44],0x100  ; set TF
    // +171  B8 FF FF FF FF       mov  eax, -1           ; CONTINUE_EXECUTION
    // +176  E9 48 00 00 00       jmp  +253              ; epilog
    //
    // +181 [single_step_handler]:
    // +181  48 B8 [8]            movabs rax, page_base
    // +191  48 89 C1             mov  rcx, rax          ; arg1
    // +194  48 B8 [8]            movabs rax, page_size
    // +204  48 89 C2             mov  rdx, rax          ; arg2
    // +207  B8 [4]               mov  eax, orig_protect
    // +212  0D 00 01 00 00       or   eax, 0x100        ; PAGE_GUARD
    // +217  41 89 C0             mov  r8d, eax          ; arg3
    // +220  4C 8D 4C 24 20       lea  r9,[rsp+0x20]     ; arg4 (dummy old_prot)
    // +225  48 B8 [8]            movabs rax, virt_protect_fn
    // +235  FF D0                call rax
    // +237  49 8B 4D 08          mov  rcx,[r13+8]       ; ContextRecord
    // +241  81 61 44 FF FE FF FF and  dword[rcx+0x44],0xFFFFFEFF ; clear TF
    // +248  B8 FF FF FF FF       mov  eax, -1           ; CONTINUE_EXECUTION
    //
    // +253 [epilog]:
    // +253  48 83 C4 28          add  rsp, 0x28
    // +257  41 5E                pop  r14
    // +259  41 5D                pop  r13
    // +261  5F                   pop  rdi
    // +262  5E                   pop  rsi
    // +263  5B                   pop  rbx
    // +264  C3                   ret
    //
    // clang-format on

    static const uint8_t kTemplate[SHELLCODE_SIZE] = {
        // +000 prologue
        0x53,                                     // push rbx
        0x56,                                     // push rsi
        0x57,                                     // push rdi
        0x41, 0x55,                               // push r13
        0x41, 0x56,                               // push r14
        0x48, 0x83, 0xEC, 0x28,                   // sub  rsp, 0x28
        0x49, 0x89, 0xCD,                         // mov  r13, rcx
        0x48, 0x8B, 0x19,                         // mov  rbx, [rcx]
        0x8B, 0x03,                               // mov  eax, [rbx]
        0x3D, 0x01, 0x00, 0x00, 0x80,             // cmp  eax, 0x80000001
        0x0F, 0x84, 0x12, 0x00, 0x00, 0x00,       // je   +050  (+030 end → +048)
        0x3D, 0x04, 0x00, 0x00, 0x80,             // cmp  eax, 0x80000004
        0x0F, 0x84, 0x8C, 0x00, 0x00, 0x00,       // je   +181  (+041 end → +041+140=+181)
        0x33, 0xC0,                               // xor  eax, eax
        0xE9, 0xCD, 0x00, 0x00, 0x00,             // jmp  +253  (+048 end → +048+205=+253)
        // +048 guard_page_handler
        0x48, 0xB8,                               // movabs rax, ring_base ...
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // [PATCH_RING_BASE  = 50]
        0x44, 0x8B, 0x00,                         // mov  r8d, [rax]
        0x41, 0x83, 0xE0, 0x0F,                   // and  r8d, 15
        0x41, 0xC1, 0xE0, 0x06,                   // shl  r8d, 6
        0x48, 0x8D, 0x48, 0x10,                   // lea  rcx, [rax+16]
        0x49, 0x03, 0xC8,                         // add  rcx, r8
        0x48, 0x89, 0xC6,                         // mov  rsi, rax
        0x0F, 0x31,                               // rdtsc
        0x48, 0xC1, 0xE2, 0x20,                   // shl  rdx, 32
        0x48, 0x0B, 0xC2,                         // or   rax, rdx
        0x48, 0x89, 0x01,                         // mov  [rcx], rax
        0x48, 0x8B, 0x43, 0x10,                   // mov  rax, [rbx+0x10]
        0x48, 0x89, 0x41, 0x08,                   // mov  [rcx+8], rax
        0x49, 0x8B, 0x55, 0x08,                   // mov  rdx, [r13+8]
        0x48, 0x8B, 0x82, 0xF8, 0x00, 0x00, 0x00, // mov  rax, [rdx+0xF8]
        0x48, 0x89, 0x41, 0x10,                   // mov  [rcx+0x10], rax
        0x48, 0x8B, 0x42, 0x78,                   // mov  rax, [rdx+0x78]
        0x48, 0x89, 0x41, 0x18,                   // mov  [rcx+0x18], rax
        0x48, 0x8B, 0x82, 0x80, 0x00, 0x00, 0x00, // mov  rax, [rdx+0x80]
        0x48, 0x89, 0x41, 0x20,                   // mov  [rcx+0x20], rax
        0x48, 0x8B, 0x82, 0x88, 0x00, 0x00, 0x00, // mov  rax, [rdx+0x88]
        0x48, 0x89, 0x41, 0x28,                   // mov  [rcx+0x28], rax
        0x8B, 0x03,                               // mov  eax, [rbx]
        0x89, 0x41, 0x30,                         // mov  [rcx+0x30], eax
        0x8B, 0x43, 0x20,                         // mov  eax, [rbx+0x20]
        0x89, 0x41, 0x34,                         // mov  [rcx+0x34], eax
        0x8B, 0x06,                               // mov  eax, [rsi]
        0xFF, 0xC0,                               // inc  eax
        0x83, 0xE0, 0x0F,                         // and  eax, 15
        0x89, 0x06,                               // mov  [rsi], eax
        0x81, 0x4A, 0x44, 0x00, 0x01, 0x00, 0x00, // or   dword[rdx+0x44], 0x100
        0xB8, 0xFF, 0xFF, 0xFF, 0xFF,             // mov  eax, -1
        0xE9, 0x48, 0x00, 0x00, 0x00,             // jmp  +253  (+183 end → +183+72=+255... wait)
        // +181 single_step_handler
        0x48, 0xB8,                               // movabs rax, page_base ...
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // [PATCH_PAGE_BASE  = 183]
        0x48, 0x89, 0xC1,                         // mov  rcx, rax
        0x48, 0xB8,                               // movabs rax, page_size ...
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // [PATCH_PAGE_SIZE  = 196]
        0x48, 0x89, 0xC2,                         // mov  rdx, rax
        0xB8,                                     // mov  eax, imm32 ...
        0x00, 0x00, 0x00, 0x00,                   // [PATCH_ORIG_PROTECT = 208]
        0x0D, 0x00, 0x01, 0x00, 0x00,             // or   eax, 0x100  (PAGE_GUARD)
        0x41, 0x89, 0xC0,                         // mov  r8d, eax
        0x4C, 0x8D, 0x4C, 0x24, 0x20,             // lea  r9, [rsp+0x20]
        0x48, 0xB8,                               // movabs rax, virt_protect_fn ...
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // [PATCH_VIRT_PROTECT = 227]
        0xFF, 0xD0,                               // call rax
        0x49, 0x8B, 0x4D, 0x08,                   // mov  rcx, [r13+8]
        0x81, 0x61, 0x44, 0xFF, 0xFE, 0xFF, 0xFF, // and  dword[rcx+0x44], 0xFFFFFEFF
        0xB8, 0xFF, 0xFF, 0xFF, 0xFF,             // mov  eax, -1
        // +253 epilog
        0x48, 0x83, 0xC4, 0x28,                   // add  rsp, 0x28
        0x41, 0x5E,                               // pop  r14
        0x41, 0x5D,                               // pop  r13
        0x5F,                                     // pop  rdi
        0x5E,                                     // pop  rsi
        0x5B,                                     // pop  rbx
        0xC3,                                     // ret
    };

    static_assert(sizeof(kTemplate) == SHELLCODE_SIZE,
                  "shellcode template size mismatch");

    std::vector<uint8_t> sc(kTemplate, kTemplate + SHELLCODE_SIZE);

    // Patch in the runtime addresses.
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

// ---------------------------------------------------------------------------
// Session state (one session = one guarded page region in one process)
// ---------------------------------------------------------------------------

struct pg_session_t {
    uint32_t session_id    = 0;
    uint32_t pid           = 0;
    uint64_t target_addr   = 0;
    uint64_t region_size   = 0;
    uint64_t ring_addr     = 0;    // address of ring buffer in target
    uint64_t sc_addr       = 0;    // address of shellcode in target
    uint32_t orig_protect  = 0;
    uint64_t veh_handle    = 0;    // return value of RtlAddVectoredExceptionHandler

    std::mutex                 captures_mutex;
    std::queue<pg_capture_t>   captures;

    std::atomic<bool>          polling{false};
    std::thread                poll_thread;

    pg_session_t() = default;
    ~pg_session_t() {
        polling.store(false);
        if (poll_thread.joinable()) poll_thread.join();
    }

    pg_session_t(const pg_session_t&)            = delete;
    pg_session_t& operator=(const pg_session_t&) = delete;
};

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

class pg_engine_t {
public:
    pg_engine_t() = default;
    ~pg_engine_t() {
        std::lock_guard<std::mutex> lk(sessions_mutex_);
        sessions_.clear();
    }

    pg_engine_t(const pg_engine_t&)            = delete;
    pg_engine_t& operator=(const pg_engine_t&) = delete;

    // Install a PAGE_GUARD sniffer on [target_addr, target_addr+region_size) in PID.
    // Returns session_id on success, 0 on failure.
    uint32_t install(uint32_t pid, uint64_t target_addr, uint64_t region_size) {
        if (!device || !device->is_connected()) return 0;

        // 1. Query current protection of the target page.
        voyager::device_t::memory_region_info mri{};
        if (!device->query_memory(target_addr, mri))     return 0;
        uint32_t orig_protect = mri.protect;

        // 2. Resolve VirtualProtect address in the target process.
        //    We resolve it through kernel32.dll base in the target.
        uint64_t k32_base = find_module_base(pid, "kernel32.dll");
        if (k32_base == 0) return 0;
        uint64_t virt_protect_fn = device->resolve_export(k32_base, "VirtualProtect");
        if (virt_protect_fn == 0) return 0;

        // 3. Allocate ring buffer + shellcode memory in the target.
        uint64_t ring_addr = device->allocate_memory(RING_TOTAL_SIZE + 16);
        if (ring_addr == 0) return 0;

        uint64_t sc_addr = device->allocate_memory(SHELLCODE_SIZE + 16);
        if (sc_addr == 0) return 0;

        // 4. Zero-initialise ring header.
        std::vector<uint8_t> zeroes(RING_TOTAL_SIZE, 0);
        device->write_raw(ring_addr, zeroes.data(), RING_TOTAL_SIZE);

        // 5. Generate and write the VEH shellcode.
        auto sc = generate_veh_shellcode(ring_addr, target_addr,
                                         region_size, orig_protect,
                                         virt_protect_fn);
        device->write_raw(sc_addr, sc.data(), sc.size());

        // 6. Apply PAGE_GUARD to the target region.
        uint32_t old_prot = 0;
        if (!device->protect_memory(target_addr, region_size,
                                    orig_protect | 0x100 /*PAGE_GUARD*/, &old_prot))
            return 0;

        // 7. Register VEH handler in the target process via
        //    RtlAddVectoredExceptionHandler(1, sc_addr).
        uint64_t ntdll_base_install = find_module_base(pid, "ntdll.dll");
        if (ntdll_base_install == 0) return 0;
        uint64_t rtl_add_fn = device->resolve_export(ntdll_base_install,
                                                      "RtlAddVectoredExceptionHandler");
        if (rtl_add_fn == 0) return 0;

        uint64_t veh_handle = device->call_function(rtl_add_fn, 1, sc_addr);

        // 8. Create session and start poll thread.
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
        session->poll_thread = std::thread([this, sess_ptr]() {
            poll_ring(sess_ptr);
        });

        std::lock_guard<std::mutex> lk(sessions_mutex_);
        sessions_[sid] = std::move(session);
        return sid;
    }

    // Drain all pending captures from a session into a vector.
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

    // Stop a session and restore original memory protection.
    bool uninstall(uint32_t session_id) {
        std::unique_ptr<pg_session_t> sess;
        {
            std::lock_guard<std::mutex> lk(sessions_mutex_);
            auto it = sessions_.find(session_id);
            if (it == sessions_.end()) return false;
            sess = std::move(it->second);
            sessions_.erase(it);
        }

        // Stop poll thread.
        sess->polling.store(false);
        if (sess->poll_thread.joinable()) sess->poll_thread.join();

        if (device && device->is_connected()) {
            // Remove VEH handler.
            if (sess->veh_handle) {
                uint64_t ntdll_base = find_module_base(sess->pid, "ntdll.dll");
                if (ntdll_base) {
                    uint64_t rtl_rm = device->resolve_export(ntdll_base,
                                                              "RtlRemoveVectoredExceptionHandler");
                    if (rtl_rm) device->call_function(rtl_rm, sess->veh_handle);
                }
            }
            // Restore original protection.
            device->protect_memory(sess->target_addr, sess->region_size,
                                   sess->orig_protect, nullptr);
        }
        return true;
    }

    // Return a list of active session IDs and basic info.
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

    // Find a module's base address in any process using Toolhelp32.
    static uint64_t find_module_base(uint32_t pid, const char* name_lower) noexcept {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
                                               static_cast<DWORD>(pid));
        if (snap == INVALID_HANDLE_VALUE) return 0;
        MODULEENTRY32W me{};
        me.dwSize = sizeof(me);
        if (Module32FirstW(snap, &me)) {
            do {
                char buf[128]{};
                WideCharToMultiByte(CP_UTF8, 0, me.szModule, -1,
                                    buf, static_cast<int>(sizeof(buf) - 1),
                                    nullptr, nullptr);
                for (char* p = buf; *p; ++p)
                    *p = static_cast<char>(tolower(static_cast<unsigned char>(*p)));
                if (strcmp(buf, name_lower) == 0) {
                    CloseHandle(snap);
                    return reinterpret_cast<uint64_t>(me.modBaseAddr);
                }
            } while (Module32NextW(snap, &me));
        }
        CloseHandle(snap);
        return 0;
    }

private:
    void poll_ring(pg_session_t* sess) {
        while (sess->polling.load()) {
            if (device && device->is_connected()) {
                drain_ring(sess);
            }
            // 10ms poll interval
            for (int i = 0; i < 10 && sess->polling.load(); i++)
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }

    void drain_ring(pg_session_t* sess) {
        // Read ring header.
        pg_ring_header_t hdr{};
        auto read_bytes = device->read_raw(sess->ring_addr,
                                           &hdr, sizeof(hdr));
        if (read_bytes != sizeof(hdr)) return;

        uint32_t w = hdr.write_idx & (RING_ENTRIES - 1);
        uint32_t r = hdr.read_idx  & (RING_ENTRIES - 1);

        while (r != w) {
            pg_capture_t entry{};
            uint64_t entry_addr = sess->ring_addr + sizeof(pg_ring_header_t)
                                  + r * sizeof(pg_capture_t);
            if (device->read_raw(entry_addr, &entry, sizeof(entry)) == sizeof(entry)) {
                std::lock_guard<std::mutex> lk(sess->captures_mutex);
                sess->captures.push(entry);
            }
            r = (r + 1) & (RING_ENTRIES - 1);
        }

        if (r != (hdr.read_idx & (RING_ENTRIES - 1))) {
            // Update read_idx in target.
            uint32_t new_r = r;
            device->write_raw(sess->ring_addr + offsetof(pg_ring_header_t, read_idx),
                              &new_r, sizeof(new_r));
        }
    }

    std::mutex sessions_mutex_;
    std::unordered_map<uint32_t, std::unique_ptr<pg_session_t>> sessions_;
    uint32_t next_id_ = 1;
};

inline pg_engine_t g_pg_engine;

} // namespace page_guard_engine
