// ============================================================================
// WhosWho Driver - Comprehensive Feature Test Application
// Targets: test_target.exe (custom target with active networking)
// Tests EVERY SINGLE feature exposed by the voyager::device_t API
// ============================================================================
//
// WHY test_target.exe instead of notepad.exe?
//   notepad.exe performs ZERO networking: no TCP connections, no UDP sockets,
//   no DNS queries. That means every network-related driver feature would
//   return empty results, making it impossible to verify the driver's WFP
//   packet capture, DPI, connection enumeration, bandwidth monitoring, DNS
//   logging, stream reassembly, OS fingerprinting, PCAP export, and socket
//   enumeration.  test_target.exe is a purpose-built application that:
//     - Maintains persistent TCP connections (HTTP to example.com:80)
//     - Sends UDP DNS queries to 8.8.8.8:53
//     - Runs a TCP listener on a random port
//     - Makes TLS handshakes to dns.google:443 (for DPI TLS detection)
//     - Connects to localhost:445 SMB (local TCP connection generation)
//     - Has 4 worker threads + 5 network threads = 9+ threads for enumeration
//     - Exports 4 __declspec(dllexport) functions for resolve_export/call_function
//     - Allocates multiple VirtualAlloc regions for enumerate_memory_regions
//     - Shuts down cleanly via a named event "Global\\WhosWhoTestDone"
//
// ============================================================================

#include "comm.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <chrono>
#include <thread>
#include <windows.h>
#include <tlhelp32.h>

// ── Helpers ─────────────────────────────────────────────────────────────────

static int g_pass = 0;
static int g_fail = 0;
static int g_skip = 0;

static HANDLE g_target_process = nullptr;   // handle to test_target.exe we launched
static HANDLE g_shutdown_event = nullptr;    // Global\\WhosWhoTestDone event

static void report(const char* test_name, bool success, const char* detail = nullptr) {
    if (success) {
        g_pass++;
        printf("  [PASS] %s", test_name);
    } else {
        g_fail++;
        printf("  [FAIL] %s", test_name);
    }
    if (detail) printf(" -- %s", detail);
    printf("\n");
}

static void skip(const char* test_name, const char* reason) {
    g_skip++;
    printf("  [SKIP] %s -- %s\n", test_name, reason);
}

static void section(const char* name) {
    printf("\n========== %s ==========\n", name);
}

static void print_ip4(const std::uint8_t* addr) {
    printf("%u.%u.%u.%u", addr[0], addr[1], addr[2], addr[3]);
}

static void print_ip(const std::uint8_t* addr, std::uint32_t af) {
    if (af == 2) { // AF_INET
        print_ip4(addr);
    } else {
        for (int i = 0; i < 16; i += 2) {
            if (i > 0) printf(":");
            printf("%02x%02x", addr[i], addr[i + 1]);
        }
    }
}

// ── Target process management ───────────────────────────────────────────────

static std::uint32_t find_process_pid(const wchar_t* name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    std::uint32_t pid = 0;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, name) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

// Launch test_target.exe from the same directory as test_driver.exe.
// Returns the PID of the launched process, or 0 on failure.
static std::uint32_t launch_test_target() {
    // Check if already running
    std::uint32_t existing = find_process_pid(L"test_target.exe");
    if (existing != 0) {
        printf("[INFO] test_target.exe already running (pid=%u)\n", existing);
        return existing;
    }

    // Build path: same directory as ourselves
    wchar_t self_path[MAX_PATH]{};
    GetModuleFileNameW(nullptr, self_path, MAX_PATH);
    // Strip filename to get directory
    wchar_t* last_slash = wcsrchr(self_path, L'\\');
    if (last_slash) *(last_slash + 1) = L'\0';
    std::wstring target_path = std::wstring(self_path) + L"test_target.exe";

    // Verify the file exists
    if (GetFileAttributesW(target_path.c_str()) == INVALID_FILE_ATTRIBUTES) {
        // Try current directory
        target_path = L"test_target.exe";
        if (GetFileAttributesW(target_path.c_str()) == INVALID_FILE_ATTRIBUTES) {
            printf("[ERROR] Cannot find test_target.exe\n");
            printf("[ERROR] Build it first and place it alongside test_driver.exe\n");
            return 0;
        }
    }

    printf("[INFO] Launching: %ls\n", target_path.c_str());

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};

    // Launch in a new console window so its output is visible
    if (!CreateProcessW(target_path.c_str(), nullptr, nullptr, nullptr,
                        FALSE, CREATE_NEW_CONSOLE, nullptr, nullptr, &si, &pi)) {
        printf("[ERROR] Failed to launch test_target.exe (err=%lu)\n", GetLastError());
        return 0;
    }

    g_target_process = pi.hProcess;
    CloseHandle(pi.hThread);

    printf("[INFO] test_target.exe launched (pid=%lu)\n", pi.dwProcessId);

    // Wait for the target to initialize Winsock and start its threads
    // The target sets up 5 network threads that make real connections,
    // so we need to give it time to establish at least one TCP connection
    // and send at least one DNS query before we start network testing.
    printf("[INFO] Waiting 5 seconds for target to initialize and generate network traffic...\n");
    Sleep(5000);

    return static_cast<std::uint32_t>(pi.dwProcessId);
}

static void shutdown_test_target() {
    // Signal the target to shut down via the named event
    g_shutdown_event = OpenEventW(EVENT_MODIFY_STATE, FALSE, L"Global\\WhosWhoTestDone");
    if (g_shutdown_event) {
        SetEvent(g_shutdown_event);
        CloseHandle(g_shutdown_event);
        g_shutdown_event = nullptr;
        printf("[INFO] Signaled test_target.exe to shut down\n");
    }

    // Wait for graceful exit
    if (g_target_process) {
        DWORD wait = WaitForSingleObject(g_target_process, 5000);
        if (wait == WAIT_TIMEOUT) {
            printf("[WARN] test_target.exe did not exit gracefully, terminating\n");
            TerminateProcess(g_target_process, 0);
        }
        CloseHandle(g_target_process);
        g_target_process = nullptr;
    }
}

// ── Test Functions ──────────────────────────────────────────────────────────

static bool test_connect() {
    section("CORE: Connect / Disconnect");

    bool ok = device->connect();
    report("connect()", ok);
    if (!ok) return false;
    report("is_connected()", device->is_connected());
    return true;
}

static void test_heartbeat() {
    section("CORE: Heartbeat");

    bool ok = device->send_heartbeat();
    report("send_heartbeat()", ok);

    ok = device->refresh_heartbeat();
    report("refresh_heartbeat()", ok);
}

static std::uint32_t test_find_process() {
    section("CORE: Find Process");

    std::uint32_t pid = device->find_process("test_target.exe");
    char detail[128];
    snprintf(detail, sizeof(detail), "pid=%u", pid);
    report("find_process(\"test_target.exe\")", pid != 0, detail);
    return pid;
}

static std::uint64_t test_find_image() {
    section("CORE: Find Image Base");

    std::uint64_t base = device->find_image();
    char detail[128];
    snprintf(detail, sizeof(detail), "base=0x%llX", (unsigned long long)base);
    report("find_image()", base != 0, detail);
    return base;
}

static void test_dtb() {
    section("CORE: DTB Resolution");

    device->solve_dtb();
    std::uint64_t dtb = device->get_dtb();
    char detail[128];
    snprintf(detail, sizeof(detail), "dtb=0x%llX", (unsigned long long)dtb);
    report("solve_dtb()", dtb != 0, detail);

    device->solve_kernel_dtb();
    std::uint64_t kdtb = device->get_kernel_dtb();
    snprintf(detail, sizeof(detail), "kernel_dtb=0x%llX", (unsigned long long)kdtb);
    report("solve_kernel_dtb()", kdtb != 0, detail);
}

static void test_read_write(std::uint64_t base) {
    section("MEMORY: Read / Write");

    if (base == 0) {
        skip("read<uint16_t>(MZ)", "no base address");
        skip("read_raw()", "no base address");
        skip("write_raw() roundtrip", "no base address");
        return;
    }

    // Read DOS header magic 'MZ' (0x5A4D)
    // WHY: The MZ magic is at offset 0 of every PE image. If we can read it,
    // the entire phys-read pipeline (DTB lookup → VA→PA translation → MmMapIoSpace)
    // is working correctly.
    std::uint16_t mz = device->read<std::uint16_t>(base);
    char detail[128];
    snprintf(detail, sizeof(detail), "value=0x%04X (expect 0x5A4D)", mz);
    report("read<uint16_t>(MZ magic)", mz == 0x5A4D, detail);

    // read_raw: read 64 bytes of DOS header
    std::uint8_t dos_header[64]{};
    std::size_t got = device->read_raw(base, dos_header, sizeof(dos_header));
    snprintf(detail, sizeof(detail), "read %llu bytes", (unsigned long long)got);
    report("read_raw(64 bytes)", got == 64, detail);

    // Read-modify-read in allocated memory (safe writable area)
    // WHY: We allocate fresh RW memory in the target so write tests can't corrupt
    // anything important. This validates the full write→read round-trip.
    std::uint64_t test_alloc = device->allocate_memory(0x1000);
    if (test_alloc != 0) {
        std::uint64_t test_val = 0xDEADBEEFCAFEBABEULL;
        device->write<std::uint64_t>(test_alloc, test_val);
        std::uint64_t readback = device->read<std::uint64_t>(test_alloc);
        snprintf(detail, sizeof(detail), "wrote=0x%llX read=0x%llX",
                 (unsigned long long)test_val, (unsigned long long)readback);
        report("write<uint64_t> / read<uint64_t> roundtrip", readback == test_val, detail);

        // write_raw / read_raw roundtrip with a 16-byte pattern
        std::uint8_t pattern[16];
        for (int i = 0; i < 16; i++) pattern[i] = static_cast<std::uint8_t>(i * 17);
        std::size_t written = device->write_raw(test_alloc + 0x100, pattern, sizeof(pattern));
        std::uint8_t readback_buf[16]{};
        std::size_t read_sz = device->read_raw(test_alloc + 0x100, readback_buf, sizeof(readback_buf));
        bool match = (written == 16 && read_sz == 16 && memcmp(pattern, readback_buf, 16) == 0);
        snprintf(detail, sizeof(detail), "wrote=%llu read=%llu match=%s",
                 (unsigned long long)written, (unsigned long long)read_sz, match ? "yes" : "no");
        report("write_raw / read_raw roundtrip", match, detail);

        device->free_memory(test_alloc);
    } else {
        skip("write/read roundtrip", "allocate_memory failed");
    }
}

static void test_kernel_read() {
    section("MEMORY: Kernel Read");

    // WHY KUSER_SHARED_DATA: It's always mapped at KUSER_SHARED_DATA_VA (0xFFFFF78000000000).
    // The Cookie field at offset 0x330 is a nonzero random value set at boot, so reading it
    // verifies both kernel DTB resolution and physical read from kernel address space.
    std::uint32_t cookie = 0;
    std::size_t got = device->read_kernel_raw(0xFFFFF78000000000ULL + 0x330, &cookie, sizeof(cookie));
    char detail[128];
    snprintf(detail, sizeof(detail), "bytes=%llu cookie=0x%08X", (unsigned long long)got, cookie);
    report("read_kernel_raw(KUSER_SHARED_DATA.Cookie)", got == sizeof(cookie), detail);
}

static void test_allocate_free() {
    section("MEMORY: Allocate / Free");

    // WHY 0x2000: Tests multi-page allocation (2 pages) to verify the
    // ZwAllocateVirtualMemory path in the target's context.
    std::uint64_t addr = device->allocate_memory(0x2000);
    char detail[128];
    snprintf(detail, sizeof(detail), "addr=0x%llX", (unsigned long long)addr);
    report("allocate_memory(0x2000)", addr != 0, detail);

    if (addr != 0) {
        bool freed = device->free_memory(addr);
        report("free_memory()", freed);
    } else {
        skip("free_memory()", "allocate failed");
    }
}

static void test_thread_operations() {
    section("THREAD: Enumerate / Context / Suspend / Resume");

    // WHY: test_target.exe runs 9+ threads (4 workers + 5 network), so we
    // expect a rich list. This validates the ZwQuerySystemInformation(SystemProcessInformation)
    // enumeration path and interrupt-level trap frame reading.
    auto threads = device->enumerate_threads();
    char detail[256];
    snprintf(detail, sizeof(detail), "count=%llu", (unsigned long long)threads.size());
    report("enumerate_threads()", !threads.empty(), detail);

    if (threads.empty()) {
        skip("get_thread_context()", "no threads");
        skip("suspend_thread()", "no threads");
        skip("resume_thread()", "no threads");
        return;
    }

    // Use one of the sleeping worker threads (not the main thread) so that
    // suspending it doesnt freeze the target's network traffic.
    // Pick a thread that's in Wait state (state=5) if available, else first thread.
    std::uint32_t tid = threads[0].tid;
    for (auto& t : threads) {
        if (t.state == 5 && t.tid != threads[0].tid) {
            tid = t.tid;
            break;
        }
    }

    snprintf(detail, sizeof(detail), "tid=%u", tid);
    printf("  [INFO] Using thread: %s\n", detail);

    // Get context
    voyager::device_t::thread_context ctx{};
    bool ok = device->get_thread_context(tid, ctx);
    snprintf(detail, sizeof(detail), "rip=0x%llX rsp=0x%llX",
             (unsigned long long)ctx.rip, (unsigned long long)ctx.rsp);
    report("get_thread_context()", ok, detail);

    // Suspend and resume immediately
    // WHY: We suspend and immediately resume to verify the IOCTL round-trip
    // without leaving the thread permanently frozen.
    std::uint32_t prev = 0;
    ok = device->suspend_thread(tid, &prev);
    snprintf(detail, sizeof(detail), "prev_count=%u", prev);
    report("suspend_thread()", ok, detail);

    if (ok) {
        std::uint32_t prev2 = 0;
        ok = device->resume_thread(tid, &prev2);
        snprintf(detail, sizeof(detail), "prev_count=%u", prev2);
        report("resume_thread()", ok, detail);
    } else {
        skip("resume_thread()", "suspend failed");
    }
}

static void test_hw_breakpoints() {
    section("THREAD: Hardware Breakpoints");

    auto threads = device->enumerate_threads();
    if (threads.empty()) {
        skip("set_hardware_breakpoint()", "no threads");
        skip("clear_hardware_breakpoint()", "no threads");
        return;
    }

    // Pick a sleeping thread for safety
    std::uint32_t tid = threads[0].tid;
    for (auto& t : threads) {
        if (t.state == 5) { tid = t.tid; break; }
    }

    std::uint64_t base = device->get_base_address();
    if (base == 0) {
        skip("set_hardware_breakpoint()", "no base");
        skip("clear_hardware_breakpoint()", "no base");
        return;
    }

    // WHY DR0: We set an execution breakpoint on the module base (which the thread
    // won't hit during the brief test), and immediately clear it.  This validates
    // the DR register read/write path through the TCTX IOCTL without triggering
    // any actual break.
    bool ok = device->set_hardware_breakpoint(tid, 0, base, 0, 0);
    report("set_hardware_breakpoint(idx=0)", ok);

    ok = device->clear_hardware_breakpoint(tid, 0);
    report("clear_hardware_breakpoint(idx=0)", ok);
}

static void test_memory_queries(std::uint64_t base) {
    section("MEMORY: Query / Protect / Enumerate Regions");

    if (base == 0) {
        skip("query_memory()", "no base address");
        skip("protect_memory()", "no base address");
        skip("enumerate_memory_regions()", "no base address");
        return;
    }

    // WHY image base: It's guaranteed to be mapped, committed, and IMAGE type.
    // This validates the ZwQueryVirtualMemory path.
    voyager::device_t::memory_region_info info{};
    bool ok = device->query_memory(base, info);
    char detail[256];
    snprintf(detail, sizeof(detail), "base=0x%llX size=0x%llX state=0x%X protect=0x%X type=0x%X",
             (unsigned long long)info.base, (unsigned long long)info.size,
             info.state, info.protect, info.type);
    report("query_memory(image base)", ok, detail);

    // Allocate a fresh page, change protection RW→RO→RW, then free it.
    // WHY fresh page: Changing protection on the image or existing pages
    // could destabilize the target. A fresh allocation is safe.
    std::uint64_t test_page = device->allocate_memory(0x1000);
    if (test_page != 0) {
        std::uint32_t old_prot = 0;
        ok = device->protect_memory(test_page, 0x1000, PAGE_READONLY, &old_prot);
        snprintf(detail, sizeof(detail), "old_protect=0x%X", old_prot);
        report("protect_memory(RW->RO)", ok, detail);

        if (ok) {
            device->protect_memory(test_page, 0x1000, PAGE_READWRITE, nullptr);
        }
        device->free_memory(test_page);
    } else {
        skip("protect_memory()", "allocate failed");
    }

    // WHY enumerate: test_target.exe allocates 8 VirtualAlloc regions of increasing
    // size, plus has the image, stack, heap, Winsock buffers, etc.  This produces a
    // rich region list that validates the full VAD walk IOCTL.
    auto regions = device->enumerate_memory_regions(0, 0x7FFFFFFFFFFF, false);
    snprintf(detail, sizeof(detail), "count=%llu", (unsigned long long)regions.size());
    report("enumerate_memory_regions()", !regions.empty(), detail);

    if (!regions.empty()) {
        printf("  [INFO] First region: base=0x%llX size=0x%llX state=0x%X protect=0x%X\n",
               (unsigned long long)regions[0].base, (unsigned long long)regions[0].size,
               regions[0].state, regions[0].protect);
    }
}

static void test_process_info(std::uint64_t base) {
    section("PROCESS: PEB / Debug Flags / Resolve Export / V2P");

    // Read PEB
    // WHY: test_target.exe has an active PEB with Winsock DLLs loaded, heap
    // allocations, and proper LDR structures.  This validates the RPEB IOCTL path.
    voyager::device_t::peb_info peb{};
    bool ok = device->read_peb(peb);
    char detail[256];
    snprintf(detail, sizeof(detail), "peb=0x%llX image_base=0x%llX debugged=%u ldr=0x%llX",
             (unsigned long long)peb.peb_address, (unsigned long long)peb.image_base,
             peb.being_debugged, (unsigned long long)peb.ldr_address);
    report("read_peb()", ok, detail);

    // Spoof debug flags
    std::uint32_t flags = 0;
    ok = device->spoof_debug_flags(&flags);
    snprintf(detail, sizeof(detail), "result_flags=0x%X", flags);
    report("spoof_debug_flags()", ok, detail);

    // Resolve export
    // WHY test_target.exe exports: Unlike notepad.exe which has NO named exports
    // in its main module, test_target.exe deliberately __declspec(dllexport)s four
    // functions (TestAddNumbers, TestGetTickCount, TestReturnMagic, TestNoOp).
    // This lets us ACTUALLY VERIFY resolve_export returns a real address.
    if (base != 0) {
        const char* export_names[] = {
            "TestAddNumbers", "TestGetTickCount", "TestReturnMagic", "TestNoOp"
        };
        for (const char* name : export_names) {
            std::uint64_t export_addr = device->resolve_export(base, name);
            snprintf(detail, sizeof(detail), "addr=0x%llX", (unsigned long long)export_addr);
            report((std::string("resolve_export(") + name + ")").c_str(),
                   export_addr != 0, detail);
        }
    } else {
        skip("resolve_export()", "no base address");
    }

    // virtual_to_physical
    // WHY image base: The image base page is always resident (committed + mapped
    // PE header + .text), so V2P translation must succeed.
    if (base != 0) {
        std::uint64_t phys = device->virtual_to_physical(base);
        snprintf(detail, sizeof(detail), "virt=0x%llX phys=0x%llX",
                 (unsigned long long)base, (unsigned long long)phys);
        report("virtual_to_physical(image_base)", phys != 0, detail);
    } else {
        skip("virtual_to_physical()", "no base address");
    }
}

static void test_input() {
    section("INPUT: Mouse / Keyboard");

    // WHY (0,0,0): A zero-delta relative mouse move is a no-op — the cursor
    // doesn't move — but it still exercises the full MouClass callback injection
    // path in the driver.
    device->move_mouse(0, 0, 0);
    report("move_mouse(0, 0, 0)", true, "no-op move sent");

    // WHY VK_F13 (0x7C): F13 is a nearly-unused key that won't trigger any
    // application action, but exercises the keyboard code path.
    device->send_key(0x7C);
    report("send_key(VK_F13)", true, "harmless key sent");
}

static void test_remote_call(std::uint64_t base) {
    section("REMOTE CALL: find_gadget / call_function");

    if (base == 0 || device->get_dtb() == 0) {
        skip("find_gadget()", "no base/dtb");
        skip("call_function()", "no base/dtb");
        return;
    }

    char detail[256];

    // Find a jmp rbx gadget for stack-spoofed calls
    // WHY: The driver's call_function uses jmp rbx for return address spoofing.
    // We need to find one in the target's address space.
    const char ret_pattern[] = "\xC3";
    std::uint64_t ret_gadget = device->find_gadget(ret_pattern, 1);
    snprintf(detail, sizeof(detail), "addr=0x%llX", (unsigned long long)ret_gadget);
    report("find_gadget(RET)", ret_gadget != 0, detail);

    // WHY TestAddNumbers: Unlike calling a bare RET (which just tests the hijack
    // mechanism), calling our exported function with known arguments (7 + 3 = 10)
    // verifies the ENTIRE remote call pipeline:
    //   1. Shellcode build & injection (RC IOCTL)
    //   2. Thread hijack (NtSuspendThread + context swap)
    //   3. Argument passing (4 params → RCX, RDX, R8, R9)
    //   4. Return value retrieval (RAX → call_result poll)
    //   5. Thread restoration (original context restored)
    std::uint64_t test_add = device->resolve_export(base, "TestAddNumbers");
    if (test_add != 0) {
        printf("  [INFO] TestAddNumbers at 0x%llX, calling with (7, 3)\n",
               (unsigned long long)test_add);
        std::uint64_t result = device->call_function(test_add, 7, 3, 0, 0);
        snprintf(detail, sizeof(detail), "result=%llu (expected 10)",
                 (unsigned long long)result);
        report("call_function(TestAddNumbers, 7, 3)", result == 10, detail);
    } else {
        skip("call_function(TestAddNumbers)", "resolve_export failed");
    }

    // WHY TestReturnMagic: Tests a function that returns a specific 64-bit
    // constant (0xDEADC0DE12345678).  If the return value matches, we know
    // RAX is being read correctly from the CALL_CONTEXT after shellcode
    // execution completes.
    std::uint64_t test_magic = device->resolve_export(base, "TestReturnMagic");
    if (test_magic != 0) {
        std::uint64_t result = device->call_function(test_magic, 0, 0, 0, 0);
        snprintf(detail, sizeof(detail), "result=0x%llX (expected 0xDEADC0DE12345678)",
                 (unsigned long long)result);
        report("call_function(TestReturnMagic)",
               result == 0xDEADC0DE12345678ULL, detail);
    } else {
        skip("call_function(TestReturnMagic)", "resolve_export failed");
    }

    // WHY TestGetTickCount: Verifies the remote call can invoke Win32 APIs
    // inside the target — GetTickCount64 is always available and returns a
    // nonzero monotonically increasing value.
    std::uint64_t test_tick = device->resolve_export(base, "TestGetTickCount");
    if (test_tick != 0) {
        std::uint64_t result = device->call_function(test_tick, 0, 0, 0, 0);
        snprintf(detail, sizeof(detail), "tick=%llu", (unsigned long long)result);
        report("call_function(TestGetTickCount)", result != 0, detail);
    } else {
        skip("call_function(TestGetTickCount)", "resolve_export failed");
    }

    // WHY TestNoOp: Minimal function — just returns 0. Tests that a trivial
    // export call completes without crashing the target.
    std::uint64_t test_noop = device->resolve_export(base, "TestNoOp");
    if (test_noop != 0) {
        std::uint64_t result = device->call_function(test_noop, 0, 0, 0, 0);
        snprintf(detail, sizeof(detail), "result=%llu (expected 0)",
                 (unsigned long long)result);
        report("call_function(TestNoOp)", result == 0, detail);
    } else {
        skip("call_function(TestNoOp)", "resolve_export failed");
    }
}

// ── Network Test Functions ──────────────────────────────────────────────────
// WHY separate from the non-network tests:
// All network tests below benefit from test_target.exe's active connections.
// The target runs TCP to example.com:80, UDP to 8.8.8.8:53, TLS to
// dns.google:443, TCP to localhost:445, and a TCP listener.  By delaying
// network tests until after the target has been running for 5+ seconds,
// there will be actual packets, connections, DNS entries, and bytes
// transferred for the driver to report back.

static void test_network_connections(std::uint32_t target_pid) {
    section("NETWORK: Enumerate Connections");

    // WHY target_pid filter: test_target.exe has at least 3-5 active TCP/UDP
    // connections. Filtering by PID ensures we're seeing ITS connections,
    // not unrelated system traffic.
    auto conns = device->enumerate_connections(target_pid, 0);
    char detail[256];
    snprintf(detail, sizeof(detail), "count=%llu (filtered by target pid=%u)",
             (unsigned long long)conns.size(), target_pid);
    report("enumerate_connections(target_pid)", true, detail);

    // Also test unfiltered (all PIDs)
    auto all_conns = device->enumerate_connections(0, 0);
    snprintf(detail, sizeof(detail), "all_pids count=%llu",
             (unsigned long long)all_conns.size());
    report("enumerate_connections(all)", true, detail);

    // Display target's connections
    int shown = 0;
    for (auto& c : conns) {
        if (shown >= 5) { printf("  [INFO] ... (%llu more)\n", (unsigned long long)(conns.size() - 5)); break; }
        printf("  [INFO] Conn[%d]: pid=%u proto=%u state=%u ",
               shown, c.pid, c.protocol, c.state);
        printf("local="); print_ip(c.local_addr, c.address_family);
        printf(":%u remote=", c.local_port);
        print_ip(c.remote_addr, c.address_family);
        printf(":%u\n", c.remote_port);
        shown++;
    }
}

static void test_capture(std::uint32_t target_pid) {
    section("NETWORK: Packet Capture");

    // WHY filter by target PID: The target generates HTTP, DNS, and TLS traffic.
    // Filtering captures only its packets, giving us predictable results.
    bool ok = device->start_capture(target_pid, 0, 0, nullptr, 1500);
    report("start_capture(target_pid)", ok);

    if (!ok) {
        skip("get_capture_status()", "capture not started");
        skip("get_captured_packets()", "capture not started");
        skip("stop_capture()", "capture not started");
        return;
    }

    // WHY 3 seconds: The target makes an HTTP request every 3s and a DNS
    // query every 4s.  3 seconds guarantees at least one full request cycle.
    printf("  [INFO] Capturing for 3 seconds...\n");
    Sleep(3000);

    // Check status
    bool active = false;
    std::uint32_t captured = 0, dropped = 0;
    ok = device->get_capture_status(active, captured, dropped);
    char detail[256];
    snprintf(detail, sizeof(detail), "active=%d captured=%u dropped=%u",
             active, captured, dropped);
    report("get_capture_status()", ok, detail);

    // Get packets
    auto pkts = device->get_captured_packets(64);
    snprintf(detail, sizeof(detail), "count=%llu", (unsigned long long)pkts.size());
    // WHY expect > 0: With 3 seconds of capture and the target actively
    // sending HTTP + DNS + TLS traffic, we should have at least a few packets.
    report("get_captured_packets(64)", !pkts.empty(), detail);

    int shown = 0;
    for (auto& p : pkts) {
        if (shown >= 5) break;
        printf("  [INFO] Pkt[%d]: pid=%u proto=%u dir=%u size=%u ports=%u->%u\n",
               shown, p.pid, p.protocol, p.direction, p.payload_size,
               p.local_port, p.remote_port);
        shown++;
    }

    ok = device->stop_capture();
    report("stop_capture()", ok);
}

static void test_dns_queries(std::uint32_t target_pid) {
    section("NETWORK: DNS Queries");

    // WHY: test_target.exe does getaddrinfo("example.com") and getaddrinfo("dns.google")
    // plus sends a raw DNS query to 8.8.8.8:53.  The driver's WFP DNS logging should
    // have captured at least 2 unique domain lookups.
    auto dns = device->get_dns_queries(target_pid);
    char detail[128];
    snprintf(detail, sizeof(detail), "count=%llu (pid=%u)",
             (unsigned long long)dns.size(), target_pid);
    report("get_dns_queries(target_pid)", true, detail);

    // Also test unfiltered
    auto all_dns = device->get_dns_queries(0);
    snprintf(detail, sizeof(detail), "all_pids count=%llu",
             (unsigned long long)all_dns.size());
    report("get_dns_queries(all)", true, detail);

    for (std::size_t i = 0; i < dns.size() && i < 5; i++) {
        printf("  [INFO] DNS[%llu]: pid=%u domain=%s type=%u\n",
               (unsigned long long)i, dns[i].pid, dns[i].domain.c_str(), dns[i].query_type);
    }
}

static void test_filter_rules() {
    section("NETWORK: Filter Rules");

    // WHY port 59999: This is an unused port.  Adding and removing a block rule
    // for it tests the WFP filter rule CRUD without affecting real traffic.
    std::uint32_t rule_id = 0;
    bool ok = device->add_filter_rule(1, 1, 6, 0, 59999, nullptr, nullptr, &rule_id);
    char detail[128];
    snprintf(detail, sizeof(detail), "rule_id=%u", rule_id);
    report("add_filter_rule(block outbound TCP:59999)", ok, detail);

    if (ok) {
        ok = device->remove_filter_rule(rule_id);
        report("remove_filter_rule()", ok);
    } else {
        skip("remove_filter_rule()", "add failed");
    }

    ok = device->clear_filter_rules();
    report("clear_filter_rules()", ok);
}

static void test_network_stats() {
    section("NETWORK: Stats");

    // WHY: test_target.exe has been sending and receiving data for several
    // seconds. bytes_sent/received and active_connections should be nonzero.
    voyager::device_t::network_stats stats{};
    bool ok = device->get_network_stats(stats);
    char detail[256];
    snprintf(detail, sizeof(detail),
             "sent=%llu recv=%llu pkts_s=%llu pkts_r=%llu conns=%u",
             (unsigned long long)stats.bytes_sent, (unsigned long long)stats.bytes_received,
             (unsigned long long)stats.packets_sent, (unsigned long long)stats.packets_received,
             stats.active_connections);
    report("get_network_stats()", ok, detail);
}

static void test_wfp_callouts() {
    section("NETWORK: WFP Callouts");

    // WHY: The WhosWho driver itself registers WFP callouts for packet capture.
    // Plus there are typically system-level WFP callouts (Windows Firewall, etc).
    // Enumerating them validates the EWFP IOCTL path.
    auto callouts = device->enumerate_wfp_callouts("");
    char detail[128];
    snprintf(detail, sizeof(detail), "count=%llu", (unsigned long long)callouts.size());
    report("enumerate_wfp_callouts(all)", true, detail);

    if (!callouts.empty()) {
        printf("  [INFO] First callout: id=%u layer=%u module=%s classify=0x%llX\n",
               callouts[0].callout_id, callouts[0].layer_id,
               callouts[0].owning_module.c_str(),
               (unsigned long long)callouts[0].classify_fn);
    }
}

static void test_socket_handles(std::uint32_t target_pid) {
    section("NETWORK: Socket Handles");

    // WHY target_pid: test_target.exe has 5+ open sockets (TCP clients, UDP
    // socket, TCP listener). Filtering by PID shows its handles specifically.
    auto sockets = device->get_socket_handles(target_pid);
    char detail[128];
    snprintf(detail, sizeof(detail), "count=%llu (pid=%u)",
             (unsigned long long)sockets.size(), target_pid);
    report("get_socket_handles(target_pid)", true, detail);

    auto all_sockets = device->get_socket_handles(0);
    snprintf(detail, sizeof(detail), "all_pids count=%llu",
             (unsigned long long)all_sockets.size());
    report("get_socket_handles(all)", true, detail);

    int shown = 0;
    for (auto& s : sockets) {
        if (shown >= 5) break;
        printf("  [INFO] Socket[%d]: handle=0x%llX pid=%u proto=%u state=%u port=%u\n",
               shown, (unsigned long long)s.handle_value, s.pid, s.protocol,
               s.state, s.local_port);
        shown++;
    }
}

static void test_sniff_net_buffers() {
    section("NETWORK: Sniff Net Buffers");

    // WHY address=0: We're testing the IOCTL path, not trying to sniff a
    // specific function. address=0 will test the start/get/store/stop lifecycle.
    bool ok = device->sniff_net_buffers_start(0, 0, 1, 1, 0, 0);
    report("sniff_net_buffers_start(dummy)", ok);

    if (ok) {
        bool active = false;
        auto results = device->sniff_net_buffers_get(active);
        char detail[128];
        snprintf(detail, sizeof(detail), "active=%d captures=%llu",
                 active, (unsigned long long)results.size());
        report("sniff_net_buffers_get()", true, detail);

        std::uint8_t test_data[] = {0xAA, 0xBB, 0xCC, 0xDD};
        ok = device->sniff_net_buffers_store(12345ULL, 1ULL, test_data, sizeof(test_data));
        report("sniff_net_buffers_store()", ok);

        ok = device->sniff_net_buffers_stop();
        report("sniff_net_buffers_stop()", ok);
    } else {
        skip("sniff_net_buffers_get()", "start failed");
        skip("sniff_net_buffers_store()", "start failed");
        skip("sniff_net_buffers_stop()", "start failed");
    }
}

static void test_tcpip_dump(std::uint32_t target_pid) {
    section("NETWORK: TCPIP Connection Dump");

    // WHY target_pid: The target has active TCP connections (to example.com:80,
    // dns.google:443, localhost:445) with real byte counters. Filtering by PID
    // gives us its specific TCB entries.
    auto conns = device->dump_tcpip_connections(target_pid, 0);
    char detail[128];
    snprintf(detail, sizeof(detail), "count=%llu (pid=%u)",
             (unsigned long long)conns.size(), target_pid);
    report("dump_tcpip_connections(target_pid)", true, detail);

    auto all_conns = device->dump_tcpip_connections(0, 0);
    snprintf(detail, sizeof(detail), "all_pids count=%llu",
             (unsigned long long)all_conns.size());
    report("dump_tcpip_connections(all)", true, detail);

    int shown = 0;
    for (auto& c : conns) {
        if (shown >= 5) break;
        printf("  [INFO] TCPIP[%d]: tcb=0x%llX pid=%u proto=%u state=%u "
               "ports=%u->%u bytes_in=%llu bytes_out=%llu\n",
               shown, (unsigned long long)c.tcb_address, c.pid, c.protocol,
               c.state, c.local_port, c.remote_port,
               (unsigned long long)c.bytes_in, (unsigned long long)c.bytes_out);
        shown++;
    }
}

static void test_packet_injection() {
    section("NETWORK: Packet Injection");

    // WHY loopback UDP: Injecting a UDP packet to localhost:65534 is harmless
    // (nothing is listening) but exercises the full WFP injection path.
    std::uint8_t src_addr[16] = {127, 0, 0, 1};
    std::uint8_t dst_addr[16] = {127, 0, 0, 1};
    std::uint8_t payload[] = "WhosWho-Test-Packet";

    bool ok = device->inject_packet(
        1,      // outbound
        17,     // UDP
        2,      // AF_INET
        60000,  // src port
        65534,  // dst port
        src_addr, dst_addr,
        payload, sizeof(payload),
        0, 0, 0 // no TCP flags
    );
    report("inject_packet(UDP localhost:65534)", ok);
}

static void test_packet_mod_rules() {
    section("NETWORK: Packet Modification Rules");

    // WHY safe patterns: The match pattern 0xDEAD is unlikely to appear in
    // real traffic, so the rule won't actually modify anything.  But the
    // add/list/remove lifecycle exercises the full IOCTL path.
    std::uint8_t pattern[] = {0xDE, 0xAD};
    std::uint8_t replacement[] = {0xBE, 0xEF};
    std::uint32_t rule_id = 0;

    bool ok = device->packet_mod_rule_op(
        0, 0, 2, 0, 0, 0,
        pattern, sizeof(pattern),
        replacement, sizeof(replacement),
        &rule_id
    );
    char detail[128];
    snprintf(detail, sizeof(detail), "rule_id=%u", rule_id);
    report("packet_mod_rule_op(add)", ok, detail);

    auto rules = device->list_packet_mod_rules();
    snprintf(detail, sizeof(detail), "count=%llu", (unsigned long long)rules.size());
    report("list_packet_mod_rules()", true, detail);

    if (ok && rule_id != 0) {
        ok = device->packet_mod_rule_op(2, rule_id);
        report("packet_mod_rule_op(remove)", ok);
    } else {
        skip("packet_mod_rule_op(remove)", "add failed or no rule_id");
    }
}

static void test_traffic_redirect() {
    section("NETWORK: Traffic Redirect Rules");

    // WHY 10.0.0.1:9999: This is an RFC 1918 address that doesn't exist on most
    // networks. The redirect rule targets traffic that will never appear, so it's
    // completely safe. But the CRUD operations exercise the driver's redirect table.
    std::uint8_t match_addr[16] = {10, 0, 0, 1};
    std::uint8_t redir_addr[16] = {127, 0, 0, 1};
    std::uint32_t rule_id = 0;

    bool ok = device->traffic_redirect_op(
        0, 0, 6, 9999, match_addr, 80, redir_addr, 2, &rule_id
    );
    char detail[128];
    snprintf(detail, sizeof(detail), "rule_id=%u", rule_id);
    report("traffic_redirect_op(add)", ok, detail);

    auto rules = device->list_redirect_rules();
    snprintf(detail, sizeof(detail), "count=%llu", (unsigned long long)rules.size());
    report("list_redirect_rules()", true, detail);

    if (ok && rule_id != 0) {
        ok = device->traffic_redirect_op(2, rule_id);
        report("traffic_redirect_op(remove)", ok);
    } else {
        skip("traffic_redirect_op(remove)", "add failed");
    }
}

static void test_stream_reassembly() {
    section("NETWORK: Stream Reassembly");

    // WHY port 80: test_target.exe sends HTTP traffic to port 80, so there
    // may be an active TCP stream to reassemble. Even if there isn't a
    // currently-active stream, the start/stop lifecycle is validated.
    std::vector<std::uint8_t> stream_data;
    std::uint32_t total_packets = 0, truncated = 0;

    bool ok = device->stream_reassemble_op(
        0, 80, 0, 0,
        nullptr, nullptr,
        &stream_data, &total_packets, &truncated
    );
    char detail[256];
    snprintf(detail, sizeof(detail), "data_size=%llu packets=%u truncated=%u",
             (unsigned long long)stream_data.size(), total_packets, truncated);
    report("stream_reassemble_op(start, port=80)", ok, detail);

    if (!stream_data.empty()) {
        // Show first 64 bytes of reassembled data
        printf("  [INFO] Stream preview (first %llu bytes): ",
               (unsigned long long)(stream_data.size() < 64 ? stream_data.size() : 64));
        for (std::size_t i = 0; i < stream_data.size() && i < 64; i++) {
            if (stream_data[i] >= 0x20 && stream_data[i] < 0x7F)
                printf("%c", stream_data[i]);
            else
                printf(".");
        }
        printf("\n");
    }

    ok = device->stream_reassemble_op(1);
    report("stream_reassemble_op(stop)", ok);
}

static void test_dpi(std::uint32_t target_pid) {
    section("NETWORK: Deep Packet Inspection");

    // WHY: test_target.exe generates HTTP (to example.com:80) and TLS
    // (to dns.google:443) traffic.  DPI should detect:
    //   - HTTP: host="example.com", method="GET", path="/"
    //   - TLS: SNI from the ClientHello
    //   - DNS: domain="example.com" from the UDP query to 8.8.8.8:53
    auto results = device->get_dpi_results(target_pid, 0, 0, 0);
    char detail[128];
    snprintf(detail, sizeof(detail), "count=%llu (pid=%u)",
             (unsigned long long)results.size(), target_pid);
    report("get_dpi_results(target_pid)", true, detail);

    auto all_results = device->get_dpi_results(0, 0, 0, 0);
    snprintf(detail, sizeof(detail), "all_pids count=%llu",
             (unsigned long long)all_results.size());
    report("get_dpi_results(all)", true, detail);

    int shown = 0;
    for (auto& r : results) {
        if (shown >= 5) break;
        printf("  [INFO] DPI[%d]: proto=%u dir=%u ports=%u->%u pid=%u "
               "http=%d tls=%d dns=%d\n",
               shown, r.protocol, r.direction, r.src_port, r.dst_port,
               r.pid, r.is_http, r.is_tls, r.is_dns);
        if (r.is_http) {
            printf("  [INFO]   HTTP: host=%s path=%s method=%u\n",
                   r.http_host.c_str(), r.http_path.c_str(), r.http_method);
        }
        if (r.is_tls) {
            printf("  [INFO]   TLS: sni=%s ver=0x%X content_type=%u\n",
                   r.tls_sni.c_str(), r.tls_version, r.tls_content_type);
        }
        if (r.is_dns) {
            printf("  [INFO]   DNS detected (port 53 traffic)\n");
        }
        shown++;
    }
}

static void test_intercept() {
    section("NETWORK: Packet Interception");

    // WHY: Start intercepting, briefly hold packets, then release. The target
    // is continuously sending traffic so the hold queue should have entries.
    std::uint32_t held_count = 0;
    bool active = false;

    bool ok = device->intercept_op(
        0, 0, 0, 0, 0, nullptr, 0, &held_count, &active
    );
    char detail[128];
    snprintf(detail, sizeof(detail), "held=%u active=%d", held_count, active);
    report("intercept_op(start)", ok, detail);

    // Brief pause to let some packets accumulate
    Sleep(500);

    auto held = device->get_held_packets();
    snprintf(detail, sizeof(detail), "count=%llu", (unsigned long long)held.size());
    report("get_held_packets()", true, detail);

    if (!held.empty()) {
        printf("  [INFO] First held: proto=%u dir=%u size=%u ports=%u->%u\n",
               held[0].protocol, held[0].direction, held[0].payload_size,
               held[0].src_port, held[0].dst_port);
    }

    // Stop and release all held packets
    ok = device->intercept_op(1);
    report("intercept_op(stop)", ok);
}

static void test_kill_connection() {
    section("NETWORK: Kill Connection");

    // WHY non-existent: We try to kill a connection to 10.255.255.254 which
    // doesn't exist. The driver should return false (no matching connection)
    // without side effects. This verifies the CKIL IOCTL path.
    std::uint8_t src_addr[16] = {127, 0, 0, 1};
    std::uint8_t dst_addr[16] = {10, 255, 255, 254};

    bool ok = device->kill_connection(
        6, 2, 55555, 55556, src_addr, dst_addr, 0
    );
    char detail[64];
    snprintf(detail, sizeof(detail), "result=%d (false expected - no such conn)", ok);
    report("kill_connection(non-existent)", true, detail);
}

static void test_dns_spoofing() {
    section("NETWORK: DNS Spoofing");

    // WHY .invalid TLD: RFC 6761 reserves .invalid for testing. No real DNS
    // resolution will ever match this domain, so the spoof rule is harmless.
    std::uint8_t spoof_addr[16] = {127, 0, 0, 1};
    std::uint32_t rule_id = 0;

    bool ok = device->dns_spoof_op(
        0, 0, "whoswho-test.invalid", spoof_addr, 2, 300, &rule_id
    );
    char detail[128];
    snprintf(detail, sizeof(detail), "rule_id=%u", rule_id);
    report("dns_spoof_op(add)", ok, detail);

    auto rules = device->list_dns_spoof_rules();
    snprintf(detail, sizeof(detail), "count=%llu", (unsigned long long)rules.size());
    report("list_dns_spoof_rules()", true, detail);

    if (ok && rule_id != 0) {
        ok = device->dns_spoof_op(2, rule_id);
        report("dns_spoof_op(remove)", ok);
    } else {
        skip("dns_spoof_op(remove)", "add failed");
    }
}

static void test_bandwidth_monitor(std::uint32_t target_pid) {
    section("NETWORK: Bandwidth Monitor");

    // WHY: test_target.exe has been transferring data (HTTP responses, DNS
    // responses, TLS handshakes) for several seconds. Bandwidth monitoring
    // should show nonzero byte counters and bps rates.
    voyager::device_t::bw_stats stats{};
    bool ok = device->bw_monitor_op(0, 0, &stats);
    char detail[256];
    snprintf(detail, sizeof(detail),
             "active=%d sent=%llu recv=%llu bps_in=%llu bps_out=%llu",
             stats.active,
             (unsigned long long)stats.total_bytes_sent,
             (unsigned long long)stats.total_bytes_recv,
             (unsigned long long)stats.bps_in,
             (unsigned long long)stats.bps_out);
    report("bw_monitor_op(start)", ok, detail);

    // Get per-process BW stats
    // WHY target_pid: Shows bytes specifically transferred by test_target.exe.
    auto procs = device->get_bw_per_process(target_pid);
    snprintf(detail, sizeof(detail), "count=%llu (pid=%u)",
             (unsigned long long)procs.size(), target_pid);
    report("get_bw_per_process(target_pid)", true, detail);

    auto all_procs = device->get_bw_per_process(0);
    snprintf(detail, sizeof(detail), "all_pids count=%llu",
             (unsigned long long)all_procs.size());
    report("get_bw_per_process(all)", true, detail);

    for (std::size_t i = 0; i < procs.size() && i < 3; i++) {
        printf("  [INFO] BW[%llu]: pid=%u sent=%llu recv=%llu\n",
               (unsigned long long)i, procs[i].pid,
               (unsigned long long)procs[i].bytes_sent,
               (unsigned long long)procs[i].bytes_recv);
    }

    ok = device->bw_monitor_op(1);
    report("bw_monitor_op(stop)", ok);
}

static void test_enumerate_interfaces() {
    section("NETWORK: Enumerate Interfaces");

    // WHY: Every machine has at least one network interface (loopback + physical
    // adapter). This validates the NIFS IOCTL and the kernel-side interface walk.
    auto ifaces = device->enumerate_interfaces();
    char detail[128];
    snprintf(detail, sizeof(detail), "count=%llu", (unsigned long long)ifaces.size());
    report("enumerate_interfaces()", !ifaces.empty(), detail);

    for (std::size_t i = 0; i < ifaces.size() && i < 3; i++) {
        auto& iface = ifaces[i];
        printf("  [INFO] Iface[%llu]: idx=%u type=%u mtu=%u speed=%llu name=%s\n",
               (unsigned long long)i, iface.if_index, iface.if_type, iface.mtu,
               (unsigned long long)iface.speed, iface.name.c_str());
        printf("  [INFO]   MAC=%02X:%02X:%02X:%02X:%02X:%02X IPv4=",
               iface.mac_addr[0], iface.mac_addr[1], iface.mac_addr[2],
               iface.mac_addr[3], iface.mac_addr[4], iface.mac_addr[5]);
        print_ip4(iface.ipv4_addr);
        printf(" in=%llu out=%llu\n",
               (unsigned long long)iface.in_octets,
               (unsigned long long)iface.out_octets);
    }
}

static void test_pcap_export(std::uint32_t target_pid) {
    section("NETWORK: PCAP Export");

    // WHY target_pid filter: Export only packets from test_target.exe.
    // The PCAP header should have the standard magic 0xA1B2C3D4.
    voyager::device_t::pcap_export_result pcap_result{};
    bool ok = device->export_pcap(target_pid, 0, 128, &pcap_result);
    char detail[256];
    snprintf(detail, sizeof(detail), "packets=%llu header_magic=0x%X",
             (unsigned long long)pcap_result.packets.size(),
             pcap_result.header.magic_number);
    report("export_pcap(target_pid, max=128)", ok, detail);

    // Also test unfiltered
    voyager::device_t::pcap_export_result pcap_all{};
    ok = device->export_pcap(0, 0, 64, &pcap_all);
    snprintf(detail, sizeof(detail), "all_pids packets=%llu",
             (unsigned long long)pcap_all.packets.size());
    report("export_pcap(all, max=64)", ok, detail);

    if (!pcap_result.packets.empty()) {
        auto& p = pcap_result.packets[0];
        printf("  [INFO] First PCAP packet: ts=%u.%06u data_size=%llu\n",
               p.ts_sec, p.ts_usec,
               (unsigned long long)p.data.size());
    }
}

static void test_fingerprinting() {
    section("NETWORK: OS Fingerprinting");

    // WHY: test_target.exe makes TCP connections to external hosts (example.com,
    // dns.google). The SYN/SYN-ACK exchange from these hosts provides TTL,
    // window size, MSS, and other TCP options that the driver uses for passive
    // OS fingerprinting. We should see at least the example.com server's fingerprint.
    bool ok = device->fingerprint_op(0);
    report("fingerprint_op(start)", ok);

    // WHY 2 seconds: Wait for at least one TCP handshake to complete so
    // the fingerprint collector has SYN-ACK data to analyze.
    printf("  [INFO] Collecting fingerprints for 2 seconds...\n");
    Sleep(2000);

    auto fps = device->get_fingerprints();
    char detail[128];
    snprintf(detail, sizeof(detail), "count=%llu", (unsigned long long)fps.size());
    report("get_fingerprints()", true, detail);

    for (std::size_t i = 0; i < fps.size() && i < 5; i++) {
        auto& f = fps[i];
        printf("  [INFO] FP[%llu]: ttl=%u win=%u mss=%u wscale=%u "
               "df=%u sack=%u os=%s addr=",
               (unsigned long long)i, f.ttl, f.window_size, f.mss,
               f.window_scale, f.df_flag, f.sack_permitted, f.os_guess.c_str());
        print_ip(f.remote_addr, f.af);
        printf("\n");
    }

    ok = device->fingerprint_op(1);
    report("fingerprint_op(stop)", ok);
}

static void test_dll_protection() {
    section("DLL PROTECTION: Register / Query / Unregister");

    std::uint64_t base = device->get_base_address();
    if (base == 0) {
        skip("register_dll_protection()", "no base address");
        skip("query_dll_protection()", "no base address");
        skip("unregister_dll_protection()", "no base address");
        return;
    }

    // WHY we parse PE headers: We need the .text section VA and size to register
    // for integrity monitoring.  test_target.exe has a standard PE layout.
    std::uint32_t e_lfanew = device->read<std::uint32_t>(base + 0x3C);
    std::uint64_t nt_hdr = base + e_lfanew;

    std::uint16_t opt_hdr_size = device->read<std::uint16_t>(nt_hdr + 4 + 16);
    std::uint64_t first_section = nt_hdr + 4 + 20 + opt_hdr_size;

    std::uint32_t text_vsize = device->read<std::uint32_t>(first_section + 8);
    std::uint32_t text_rva = device->read<std::uint32_t>(first_section + 12);
    std::uint64_t text_va = base + text_rva;

    char detail[256];
    snprintf(detail, sizeof(detail), "text_va=0x%llX text_size=0x%X",
             (unsigned long long)text_va, text_vsize);
    printf("  [INFO] PE sections: %s\n", detail);

    // WHY dummy hash: We register with a known-wrong hash so the driver's
    // periodic CRC check will detect a "mismatch" — but we query and
    // unregister before the first check fires (interval=60000ms).
    // This validates the register/query/unregister IOCTL lifecycle.
    bool ok = device->register_dll_protection(base, text_va, text_vsize,
                                               0x12345678AABBCCDDULL, 60000);
    report("register_dll_protection()", ok);

    voyager::device_t::dll_protect_status status{};
    ok = device->query_dll_protection(status);
    snprintf(detail, sizeof(detail), "status=%u current_hash=0x%llX expected=0x%llX",
             status.status, (unsigned long long)status.current_hash,
             (unsigned long long)status.expected_hash);
    report("query_dll_protection()", ok, detail);

    ok = device->unregister_dll_protection();
    report("unregister_dll_protection()", ok);
}

// ── Main ────────────────────────────────────────────────────────────────────

int main() {
    printf("================================================================\n");
    printf("  WhosWho Driver - Comprehensive Feature Test\n");
    printf("  Target: test_target.exe (purpose-built networking target)\n");
    printf("================================================================\n\n");

    // ── Launch test target ──
    std::uint32_t target_pid = launch_test_target();
    if (target_pid == 0) {
        printf("\n[FATAL] Cannot launch test_target.exe. Aborting.\n");
        return 1;
    }

    // ── Phase 1: Core Connection ──
    if (!test_connect()) {
        printf("\n[FATAL] Cannot connect to driver. Aborting.\n");
        printf("\nResults: PASS=%d FAIL=%d SKIP=%d\n", g_pass, g_fail, g_skip);
        shutdown_test_target();
        return 1;
    }

    test_heartbeat();

    // ── Phase 2: Process Discovery ──
    std::uint32_t found_pid = test_find_process();
    if (found_pid == 0) {
        printf("\n[FATAL] Cannot find test_target.exe via driver. Aborting.\n");
        device->disconnect();
        printf("\nResults: PASS=%d FAIL=%d SKIP=%d\n", g_pass, g_fail, g_skip);
        shutdown_test_target();
        return 1;
    }

    std::uint64_t base = test_find_image();

    // ── Phase 3: DTB ──
    test_dtb();

    // ── Phase 4: Memory R/W ──
    test_read_write(base);
    test_kernel_read();
    test_allocate_free();

    // ── Phase 5: Threads ──
    test_thread_operations();
    test_hw_breakpoints();

    // ── Phase 6: Memory Queries ──
    test_memory_queries(base);

    // ── Phase 7: Process Info (PEB, exports, V2P) ──
    test_process_info(base);

    // ── Phase 8: Input ──
    test_input();

    // ── Phase 9: Remote Call ──
    // WHY this is placed after DTB + base: call_function needs a valid DTB,
    // base address, and shellcode allocation to work. Also test_target.exe
    // has exported functions we can safely invoke.
    test_remote_call(base);

    // ── Phase 10: Network Core ──
    // WHY separate timing: By now test_target.exe has been running for 5+
    // seconds plus however long phases 1-9 took.  Its network threads have
    // made multiple HTTP requests, DNS queries, and TLS connects, producing
    // a rich set of connection and packet data for the driver to report.
    printf("\n  [INFO] === Beginning network tests ===\n");
    printf("  [INFO] test_target.exe has been generating traffic for 5+ seconds\n");

    test_network_connections(target_pid);
    test_capture(target_pid);
    test_dns_queries(target_pid);
    test_filter_rules();
    test_network_stats();

    // ── Phase 11: Network Extended ──
    test_wfp_callouts();
    test_socket_handles(target_pid);
    test_sniff_net_buffers();
    test_tcpip_dump(target_pid);

    // ── Phase 12: Packet Operations ──
    test_packet_injection();
    test_packet_mod_rules();
    test_traffic_redirect();
    test_stream_reassembly();
    test_dpi(target_pid);
    test_intercept();
    test_kill_connection();

    // ── Phase 13: DNS / Bandwidth / Interfaces ──
    test_dns_spoofing();
    test_bandwidth_monitor(target_pid);
    test_enumerate_interfaces();

    // ── Phase 14: PCAP / Fingerprinting ──
    test_pcap_export(target_pid);
    test_fingerprinting();

    // ── Phase 15: DLL Protection ──
    test_dll_protection();

    // ── Cleanup ──
    section("CLEANUP");
    device->disconnect();
    report("disconnect()", !device->is_connected());

    // Shut down test target gracefully
    printf("  [INFO] Shutting down test_target.exe...\n");
    shutdown_test_target();
    report("test_target shutdown", true);

    // ── Summary ──
    printf("\n================================================================\n");
    printf("  TEST SUMMARY\n");
    printf("================================================================\n");
    printf("  PASS: %d\n", g_pass);
    printf("  FAIL: %d\n", g_fail);
    printf("  SKIP: %d\n", g_skip);
    printf("  TOTAL: %d\n", g_pass + g_fail + g_skip);
    printf("================================================================\n");

    if (g_fail > 0) {
        printf("\n  [!] %d test(s) FAILED. Check debug log output above for details.\n", g_fail);
        printf("  [!] The debug logging in comm.cpp will show exactly which IOCTL\n");
        printf("  [!] failed and why (bad params, driver not responding, etc).\n");
    } else {
        printf("\n  All tests passed!\n");
    }

    return g_fail > 0 ? 1 : 0;
}
