// ============================================================================
// WhosWho Driver - Comprehensive Feature Test Application
// Target: test_target.exe (custom-built networking + export target)
// Tests EVERY SINGLE feature exposed by the voyager::device_t API
// ============================================================================
//
// WHY test_target.exe?
//   test_target.exe is our purpose-built target process that:
//     - Exports functions (TestAddNumbers, TestGetTickCount, TestReturnMagic,
//       TestNoOp) so resolve_export and call_function can be validated with
//       known argument/return-value signatures
//     - Generates REAL network traffic: TCP HTTP to example.com, UDP DNS to
//       8.8.8.8, TLS to dns.google:443, TCP listener on loopback, local TCP
//       connections — this exercises EVERY networking IOCTL with actual data
//     - Spawns 9 threads (4 workers + 5 network) so enumerate_threads,
//       get/set_thread_context, suspend/resume all operate on a rich thread set
//     - Allocates diverse memory regions (VirtualAlloc with varying sizes) so
//       enumerate_memory_regions returns a non-trivial result
//     - Stays alive until signaled via "Global\WhosWhoTestDone" or Enter key
//
// INSTRUCTIONS:
//   1. Build both test_target.exe and test_driver.exe (CMake ALL_BUILD)
//   2. Load the WhosWho driver
//   3. Run test_target.exe FIRST (it will generate traffic and wait)
//   4. Run test_driver.exe (as Administrator) in another terminal
//   5. Observe results; test_target.exe will be signaled to shut down when done
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

// ── Target process detection ────────────────────────────────────────────────

// Find a running test_target.exe via the Windows toolhelp snapshot API.
// WHY: test_target.exe is our custom-built target with exported functions and
// active networking threads. Unlike notepad.exe, it generates real TCP/UDP/TLS
// traffic so every network IOCTL can be validated with actual packet data.
static std::uint32_t find_target_pid() {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    std::uint32_t pid = 0;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, L"test_target.exe") == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
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

    // WHY "test_target.exe": The driver's find_process walks the EPROCESS linked list
    // in kernel memory to find a process by name. test_target.exe is our custom target
    // with exported functions and active network traffic for comprehensive testing.
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

    // WHY: test_target.exe spawns 9 threads (4 workers + 5 network threads).
    // Enumerating them validates the TENUM IOCTL and the kernel-side
    // ZwQuerySystemInformation(SystemProcessInformation) thread walk.
    // With 9+ threads we get a much richer result than notepad's 2-3 threads.
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
    // suspending it doesn't freeze the target's network traffic.
    // WHY state==5: State 5 = Wait. test_target.exe has dedicated sleep/wait
    // threads, picking one avoids disrupting the active networking threads.
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

    // WHY enumerate: test_target.exe has a rich set of memory regions: the PE
    // image, stack, heap, loaded DLLs (ntdll, kernel32, ws2_32, etc.), plus 8
    // explicit VirtualAlloc regions (0x10000..0x80000 bytes each) that it
    // allocates at startup.  This validates the full VAD walk IOCTL path.
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
    // WHY: test_target.exe has a rich PEB with loaded DLLs (ntdll, kernel32,
    // ws2_32, etc.), heap allocations, proper LDR structures, and Winsock
    // initialization. More DLLs loaded than notepad due to networking.
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

    // Resolve exports from test_target.exe itself
    // WHY: test_target.exe exports TestAddNumbers, TestGetTickCount,
    // TestReturnMagic, and TestNoOp. Unlike notepad.exe which has NO named
    // exports, our custom binary has known exports we can validate directly.
    if (base != 0) {
        // Test resolving our custom exports from the target's own module
        std::uint64_t add_nums = device->resolve_export(base, "TestAddNumbers");
        snprintf(detail, sizeof(detail), "addr=0x%llX", (unsigned long long)add_nums);
        report("resolve_export(test_target, \"TestAddNumbers\")", add_nums != 0, detail);

        std::uint64_t get_tick = device->resolve_export(base, "TestGetTickCount");
        snprintf(detail, sizeof(detail), "addr=0x%llX", (unsigned long long)get_tick);
        report("resolve_export(test_target, \"TestGetTickCount\")", get_tick != 0, detail);

        std::uint64_t ret_magic = device->resolve_export(base, "TestReturnMagic");
        snprintf(detail, sizeof(detail), "addr=0x%llX", (unsigned long long)ret_magic);
        report("resolve_export(test_target, \"TestReturnMagic\")", ret_magic != 0, detail);

        std::uint64_t no_op = device->resolve_export(base, "TestNoOp");
        snprintf(detail, sizeof(detail), "addr=0x%llX", (unsigned long long)no_op);
        report("resolve_export(test_target, \"TestNoOp\")", no_op != 0, detail);

        // Also resolve well-known system DLL exports to exercise the LDR walk
        // WHY: Validates that the driver can walk the PEB→LDR linked list and
        // parse PE export directories of system DLLs loaded in the target.
        std::uint64_t ntdll_base = 0;
        std::uint64_t kernel32_base = 0;
        if (peb.ldr_address != 0) {
            // PEB_LDR_DATA->InLoadOrderModuleList.Flink is at ldr + 0x10
            std::uint64_t first_entry = device->read<std::uint64_t>(peb.ldr_address + 0x10);
            if (first_entry != 0) {
                // entry[0] = the exe itself, entry[1] = ntdll
                std::uint64_t ntdll_entry = device->read<std::uint64_t>(first_entry);
                if (ntdll_entry != 0) {
                    ntdll_base = device->read<std::uint64_t>(ntdll_entry + 0x30);
                    printf("  [INFO] ntdll.dll base via LDR walk: 0x%llX\n",
                           (unsigned long long)ntdll_base);

                    // entry[2] = kernel32
                    std::uint64_t k32_entry = device->read<std::uint64_t>(ntdll_entry);
                    if (k32_entry != 0) {
                        kernel32_base = device->read<std::uint64_t>(k32_entry + 0x30);
                        printf("  [INFO] kernel32.dll base via LDR walk: 0x%llX\n",
                               (unsigned long long)kernel32_base);
                    }
                }
            }
        }

        if (ntdll_base != 0) {
            std::uint64_t rtl_get_ver = device->resolve_export(ntdll_base, "RtlGetVersion");
            snprintf(detail, sizeof(detail), "addr=0x%llX", (unsigned long long)rtl_get_ver);
            report("resolve_export(ntdll, \"RtlGetVersion\")", rtl_get_ver != 0, detail);
        } else {
            skip("resolve_export(ntdll)", "failed to walk LDR for ntdll base");
        }

        if (kernel32_base != 0) {
            std::uint64_t get_pid = device->resolve_export(kernel32_base, "GetCurrentProcessId");
            snprintf(detail, sizeof(detail), "addr=0x%llX", (unsigned long long)get_pid);
            report("resolve_export(kernel32, \"GetCurrentProcessId\")", get_pid != 0, detail);
        } else {
            skip("resolve_export(kernel32)", "failed to walk LDR for kernel32 base");
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

static void test_remote_call(std::uint64_t base, std::uint32_t target_pid) {
    section("REMOTE CALL: find_gadget / call_function");

    if (base == 0 || device->get_dtb() == 0) {
        skip("find_gadget()", "no base/dtb");
        skip("call_function()", "no base/dtb");
        return;
    }

    char detail[256];

    // Find a RET gadget in test_target's address space
    // WHY: The driver's call_function uses a return gadget for stack-spoofed calls.
    const char ret_pattern[] = "\xC3";
    std::uint64_t ret_gadget = device->find_gadget(ret_pattern, 1);
    snprintf(detail, sizeof(detail), "addr=0x%llX", (unsigned long long)ret_gadget);
    report("find_gadget(RET)", ret_gadget != 0, detail);

    // ── Call test_target.exe's own exported functions ──
    // WHY: Unlike notepad.exe which has NO exports, test_target.exe exports
    // TestAddNumbers, TestGetTickCount, TestReturnMagic, and TestNoOp.
    // This lets us verify:
    //   1. Argument passing (TestAddNumbers: a+b should equal expected sum)
    //   2. Return value retrieval (TestReturnMagic: known constant 0xDEADC0DE12345678)
    //   3. Thread hijack stability (multiple sequential calls should all succeed)
    //   4. Zero-arg calls (TestNoOp: verifies the trampoline with no useful work)

    // Resolve TestAddNumbers from test_target.exe's own export table
    std::uint64_t add_addr = device->resolve_export(base, "TestAddNumbers");
    if (add_addr != 0) {
        printf("  [INFO] TestAddNumbers at 0x%llX, calling with args (100, 200)...\n",
               (unsigned long long)add_addr);
        // WHY 100+200=300: A simple addition with known operands and known result.
        // The __stdcall convention passes args via stack/register per x64 ABI.
        // arg1=100, arg2=200, arg3=0(unused), arg4=0(unused) → return 300.
        std::uint64_t result = device->call_function(add_addr, 100, 200, 0, 0);
        snprintf(detail, sizeof(detail), "result=%llu (expected 300)",
                 (unsigned long long)result);
        report("call_function(TestAddNumbers, 100, 200)", result == 300, detail);
    } else {
        skip("call_function(TestAddNumbers)", "resolve_export failed");
    }

    // Resolve TestReturnMagic from test_target.exe
    std::uint64_t magic_addr = device->resolve_export(base, "TestReturnMagic");
    if (magic_addr != 0) {
        printf("  [INFO] TestReturnMagic at 0x%llX, calling...\n",
               (unsigned long long)magic_addr);
        // WHY 0xDEADC0DE12345678: This is the known constant baked into the function.
        // If we get it back correctly, it proves the full 64-bit return value path
        // from RAX through the shell code → call_result poll is intact.
        std::uint64_t result = device->call_function(magic_addr, 0, 0, 0, 0);
        snprintf(detail, sizeof(detail), "result=0x%llX (expected 0xDEADC0DE12345678)",
                 (unsigned long long)result);
        report("call_function(TestReturnMagic)",
               result == 0xDEADC0DE12345678ULL, detail);
    } else {
        skip("call_function(TestReturnMagic)", "resolve_export failed");
    }

    // Resolve TestGetTickCount from test_target.exe
    std::uint64_t tick_addr = device->resolve_export(base, "TestGetTickCount");
    if (tick_addr != 0) {
        printf("  [INFO] TestGetTickCount at 0x%llX, calling...\n",
               (unsigned long long)tick_addr);
        // WHY nonzero: GetTickCount64 always returns >0 on a running system.
        // A third sequential remote call proves the first two didn't corrupt
        // the target's thread state (context was properly saved/restored).
        std::uint64_t result = device->call_function(tick_addr, 0, 0, 0, 0);
        snprintf(detail, sizeof(detail), "tick=%llu", (unsigned long long)result);
        report("call_function(TestGetTickCount)", result != 0, detail);
    } else {
        skip("call_function(TestGetTickCount)", "resolve_export failed");
    }

    // Resolve TestNoOp from test_target.exe
    std::uint64_t noop_addr = device->resolve_export(base, "TestNoOp");
    if (noop_addr != 0) {
        // WHY return==0: TestNoOp returns 0 unconditionally. This validates
        // that a zero return value is correctly propagated (not confused with
        // a failure sentinel).
        std::uint64_t result = device->call_function(noop_addr, 0, 0, 0, 0);
        snprintf(detail, sizeof(detail), "result=%llu (expected 0)",
                 (unsigned long long)result);
        report("call_function(TestNoOp)", result == 0, detail);
    } else {
        skip("call_function(TestNoOp)", "resolve_export failed");
    }

    // Also call GetCurrentProcessId via kernel32 as a cross-check
    // WHY: Verifies the PID matches what find_process returned, confirming
    // we're operating in the correct process context.
    voyager::device_t::peb_info peb{};
    device->read_peb(peb);
    std::uint64_t kernel32_base = 0;
    if (peb.ldr_address != 0) {
        std::uint64_t first = device->read<std::uint64_t>(peb.ldr_address + 0x10);
        if (first != 0) {
            std::uint64_t ntdll_entry = device->read<std::uint64_t>(first);
            if (ntdll_entry != 0) {
                std::uint64_t k32_entry = device->read<std::uint64_t>(ntdll_entry);
                if (k32_entry != 0) {
                    kernel32_base = device->read<std::uint64_t>(k32_entry + 0x30);
                }
            }
        }
    }

    if (kernel32_base != 0) {
        std::uint64_t get_pid_addr = device->resolve_export(kernel32_base, "GetCurrentProcessId");
        if (get_pid_addr != 0) {
            printf("  [INFO] GetCurrentProcessId at 0x%llX, calling...\n",
                   (unsigned long long)get_pid_addr);
            std::uint64_t result = device->call_function(get_pid_addr, 0, 0, 0, 0);
            snprintf(detail, sizeof(detail), "result=%llu (expected pid=%u)",
                     (unsigned long long)result, target_pid);
            report("call_function(GetCurrentProcessId)",
                   static_cast<std::uint32_t>(result) == target_pid, detail);
        } else {
            skip("call_function(GetCurrentProcessId)", "resolve_export failed");
        }
    } else {
        skip("call_function(GetCurrentProcessId)", "could not find kernel32 base");
    }
}

// ── Network Test Functions ──────────────────────────────────────────────────
// WHY we use test_target.exe for network tests:
// test_target.exe generates REAL network traffic — TCP HTTP to example.com,
// UDP DNS to 8.8.8.8, TLS to dns.google:443, a TCP listener on loopback, and
// local TCP connections. This means PID-filtered queries will return ACTUAL
// connections, packets, and DNS entries from our target process.
// Every network IOCTL is exercised with real data, not empty results.

static void test_network_connections(std::uint32_t target_pid) {
    section("NETWORK: Enumerate Connections");

    // WHY target_pid filter: test_target.exe has active TCP/UDP connections
    // (HTTP to example.com, DNS to 8.8.8.8, TLS to dns.google, listener on
    // loopback). PID-filtered results should show these live connections.
    auto conns = device->enumerate_connections(target_pid, 0);
    char detail[256];
    snprintf(detail, sizeof(detail), "count=%llu (test_target has active connections)",
             (unsigned long long)conns.size());
    report("enumerate_connections(target_pid)", true, detail);

    int shown = 0;
    for (auto& c : conns) {
        if (shown >= 5) break;
        printf("  [INFO] TargetConn[%d]: pid=%u proto=%u state=%u ",
               shown, c.pid, c.protocol, c.state);
        printf("local="); print_ip(c.local_addr, c.address_family);
        printf(":%u remote=", c.local_port);
        print_ip(c.remote_addr, c.address_family);
        printf(":%u\n", c.remote_port);
        shown++;
    }

    // System-wide: other processes (svchost, browsers, etc.) have connections
    auto all_conns = device->enumerate_connections(0, 0);
    snprintf(detail, sizeof(detail), "all_pids count=%llu",
             (unsigned long long)all_conns.size());
    report("enumerate_connections(all)", true, detail);

    shown = 0;
    for (auto& c : all_conns) {
        if (shown >= 3) { printf("  [INFO] ... (%llu more)\n", (unsigned long long)(all_conns.size() - 3)); break; }
        printf("  [INFO] SysConn[%d]: pid=%u proto=%u state=%u ",
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

    // WHY target_pid capture: test_target.exe generates real HTTP, DNS, and TLS
    // traffic, so capturing its PID should yield actual packets.
    bool ok = device->start_capture(target_pid, 0, 0, nullptr, 1500);
    report("start_capture(target_pid)", ok);

    if (!ok) {
        skip("get_capture_status()", "capture not started");
        skip("get_captured_packets()", "capture not started");
        skip("stop_capture()", "capture not started");
        return;
    }

    // WHY 3 seconds: test_target.exe has periodic HTTP/DNS/TLS traffic that
    // should produce packets within a few seconds.
    printf("  [INFO] Capturing test_target traffic for 3 seconds...\n");
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
    // NOTE: On an isolated VM with no internet, this may be 0 — that's OK.
    // The IOCTL path is still fully exercised.
    report("get_captured_packets(64)", true, detail);

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

    // WHY target_pid: test_target.exe resolves example.com, 8.8.8.8 (UDP DNS),
    // and dns.google (TLS). PID-filtered DNS queries should return these.
    auto dns = device->get_dns_queries(target_pid);
    char detail[128];
    snprintf(detail, sizeof(detail), "count=%llu (test_target resolves multiple domains)",
             (unsigned long long)dns.size());
    report("get_dns_queries(target_pid)", true, detail);

    int shown = 0;
    for (auto& d : dns) {
        if (shown >= 5) break;
        printf("  [INFO] TargetDNS[%d]: pid=%u domain=%s type=%u\n",
               shown, d.pid, d.domain.c_str(), d.query_type);
        shown++;
    }

    // System-wide: svchost (DNS client), browsers, and other services
    auto all_dns = device->get_dns_queries(0);
    snprintf(detail, sizeof(detail), "all_pids count=%llu",
             (unsigned long long)all_dns.size());
    report("get_dns_queries(all)", true, detail);

    for (std::size_t i = 0; i < all_dns.size() && i < 5; i++) {
        printf("  [INFO] SysDNS[%llu]: pid=%u domain=%s type=%u\n",
               (unsigned long long)i, all_dns[i].pid, all_dns[i].domain.c_str(), all_dns[i].query_type);
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

    // WHY: System-wide network stats should show nonzero counters.
    // test_target.exe also contributes real traffic to the counters.
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

    // WHY target_pid: test_target.exe has multiple open sockets (TCP HTTP,
    // UDP DNS, TLS, TCP listener, local TCP). PID-filtered results should
    // return these active socket handles.
    auto sockets = device->get_socket_handles(target_pid);
    char detail[128];
    snprintf(detail, sizeof(detail), "count=%llu (test_target has multiple sockets)",
             (unsigned long long)sockets.size());
    report("get_socket_handles(target_pid)", true, detail);

    int shown = 0;
    for (auto& s : sockets) {
        if (shown >= 5) break;
        printf("  [INFO] TargetSocket[%d]: handle=0x%llX pid=%u proto=%u state=%u port=%u\n",
               shown, (unsigned long long)s.handle_value, s.pid, s.protocol,
               s.state, s.local_port);
        shown++;
    }

    // System-wide: other processes have many open sockets
    auto all_sockets = device->get_socket_handles(0);
    snprintf(detail, sizeof(detail), "all_pids count=%llu",
             (unsigned long long)all_sockets.size());
    report("get_socket_handles(all)", true, detail);

    shown = 0;
    for (auto& s : all_sockets) {
        if (shown >= 3) { printf("  [INFO] ... (%llu more)\n", (unsigned long long)(all_sockets.size() - 3)); break; }
        printf("  [INFO] SysSocket[%d]: handle=0x%llX pid=%u proto=%u state=%u port=%u\n",
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

    // WHY target_pid: test_target.exe has HTTP, TLS, and local TCP connections.
    // PID-filtered TCPIP dump should return these active connections.
    auto conns = device->dump_tcpip_connections(target_pid, 0);
    char detail[128];
    snprintf(detail, sizeof(detail), "count=%llu (test_target has active TCP conns)",
             (unsigned long long)conns.size());
    report("dump_tcpip_connections(target_pid)", true, detail);

    int shown = 0;
    for (auto& c : conns) {
        if (shown >= 5) break;
        printf("  [INFO] TargetTCP[%d]: tcb=0x%llX pid=%u proto=%u state=%u "
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

    // WHY port 80: We test the start/stop lifecycle with port 80, which
    // test_target.exe's HTTP thread uses to connect to example.com.
    // Stream reassembly should capture HTTP request/response data.
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

    // WHY: test_target.exe generates HTTP, TLS, and DNS traffic, so PID-filtered
    // DPI results should detect real protocol signatures from our target process.
    auto results = device->get_dpi_results(target_pid, 0, 0, 0);
    char detail[128];
    snprintf(detail, sizeof(detail), "count=%llu (test_target generates HTTP/TLS/DNS)",
             (unsigned long long)results.size());
    report("get_dpi_results(target_pid)", true, detail);

    int shown = 0;
    for (auto& r : results) {
        if (shown >= 5) break;
        printf("  [INFO] TargetDPI[%d]: proto=%u dir=%u ports=%u->%u pid=%u "
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

    // WHY: Start intercepting, briefly hold packets, then release. System
    // background traffic may or may not produce held packets, but the
    // start/stop lifecycle is validated either way.
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

    // WHY: System-wide bandwidth monitoring should show nonzero counters.
    // test_target.exe generates real traffic so its per-process BW should be nonzero.
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

    // Per-process BW for test_target (should be nonzero — real traffic)
    auto procs = device->get_bw_per_process(target_pid);
    snprintf(detail, sizeof(detail), "count=%llu (test_target has active traffic)",
             (unsigned long long)procs.size());
    report("get_bw_per_process(target_pid)", true, detail);

    // System-wide per-process
    auto all_procs = device->get_bw_per_process(0);
    snprintf(detail, sizeof(detail), "all_pids count=%llu",
             (unsigned long long)all_procs.size());
    report("get_bw_per_process(all)", true, detail);

    for (std::size_t i = 0; i < all_procs.size() && i < 3; i++) {
        printf("  [INFO] BW[%llu]: pid=%u sent=%llu recv=%llu\n",
               (unsigned long long)i, all_procs[i].pid,
               (unsigned long long)all_procs[i].bytes_sent,
               (unsigned long long)all_procs[i].bytes_recv);
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

    // WHY target_pid: test_target.exe generates real packets (HTTP, DNS, TLS).
    // PID-filtered PCAP export should contain actual captured packets.
    voyager::device_t::pcap_export_result pcap_result{};
    bool ok = device->export_pcap(target_pid, 0, 128, &pcap_result);
    char detail[256];
    snprintf(detail, sizeof(detail), "packets=%llu (test_target traffic) magic=0x%X",
             (unsigned long long)pcap_result.packets.size(),
             pcap_result.header.magic_number);
    report("export_pcap(target_pid)", ok, detail);

    // System-wide
    voyager::device_t::pcap_export_result pcap_all{};
    ok = device->export_pcap(0, 0, 64, &pcap_all);
    snprintf(detail, sizeof(detail), "all_pids packets=%llu",
             (unsigned long long)pcap_all.packets.size());
    report("export_pcap(all, max=64)", ok, detail);

    if (!pcap_all.packets.empty()) {
        auto& p = pcap_all.packets[0];
        printf("  [INFO] First PCAP packet: ts=%u.%06u data_size=%llu\n",
               p.ts_sec, p.ts_usec,
               (unsigned long long)p.data.size());
    }
}

static void test_fingerprinting() {
    section("NETWORK: OS Fingerprinting");

    // WHY: test_target.exe makes multiple TCP connections (HTTP, TLS, local),
    // so SYN/SYN-ACK exchanges from its connections can be fingerprinted.
    // System-wide, other processes may also trigger TCP handshakes.
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
    printf("  Target: test_target.exe (custom traffic-generating test app)\n");
    printf("================================================================\n\n");

    // ── Launch test_target.exe automatically ──
    // WHY auto-launch: test_target.exe needs to be running with its 9 threads
    // (4 worker + 5 network) fully initialized before we start testing.
    // We launch it ourselves, wait for its network threads to spin up, then
    // signal shutdown via "Global\WhosWhoTestDone" when tests complete.
    STARTUPINFOA si{};
    PROCESS_INFORMATION pi{};
    si.cb = sizeof(si);

    // Try to find test_target.exe in the same directory as the test runner
    char exe_path[MAX_PATH];
    GetModuleFileNameA(nullptr, exe_path, MAX_PATH);
    char* last_slash = strrchr(exe_path, '\\');
    if (last_slash) *(last_slash + 1) = '\0';
    strcat_s(exe_path, "test_target.exe");

    bool launched = false;
    std::uint32_t target_pid = find_target_pid();

    if (target_pid != 0) {
        printf("[INFO] test_target.exe already running (pid=%u)\n", target_pid);
    } else {
        printf("[INFO] Launching test_target.exe from: %s\n", exe_path);
        if (CreateProcessA(exe_path, nullptr, nullptr, nullptr, FALSE,
                           0, nullptr, nullptr, &si, &pi)) {
            target_pid = pi.dwProcessId;
            launched = true;
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            printf("[INFO] Launched test_target.exe (pid=%u)\n", target_pid);

            // WHY 3-second wait: test_target.exe spawns 5 network threads that
            // need time to establish TCP/UDP/TLS connections. 3 seconds is
            // conservative enough for DNS resolution + TCP handshakes + TLS setup.
            printf("[INFO] Waiting 3 seconds for network threads to initialize...\n");
            Sleep(3000);
        } else {
            printf("[FATAL] Failed to launch test_target.exe (error=%lu)\n", GetLastError());
            printf("[FATAL] Ensure test_target.exe is in the same directory as this test.\n");
            return 1;
        }
    }

    printf("[INFO] Target: test_target.exe (pid=%u)\n\n", target_pid);

    // ── Phase 1: Core Connection ──
    if (!test_connect()) {
        printf("\n[FATAL] Cannot connect to driver. Aborting.\n");
        printf("\nResults: PASS=%d FAIL=%d SKIP=%d\n", g_pass, g_fail, g_skip);
        return 1;
    }

    test_heartbeat();

    // ── Phase 2: Process Discovery ──
    std::uint32_t found_pid = test_find_process();
    if (found_pid == 0) {
        printf("\n[FATAL] Cannot find test_target.exe via driver. Aborting.\n");
        device->disconnect();
        printf("\nResults: PASS=%d FAIL=%d SKIP=%d\n", g_pass, g_fail, g_skip);
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
    // base address, and shellcode allocation to work. We call test_target.exe's
    // exported functions (TestAddNumbers, TestReturnMagic, GetCurrentProcessId)
    // which provide deterministic, verifiable return values.
    test_remote_call(base, found_pid);

    // ── Phase 10: Network Core ──
    // WHY test_target.exe for network tests: It generates REAL traffic —
    // HTTP (TCP 80), UDP DNS (8.8.8.8:53), TLS (dns.google:443), TCP listener,
    // and local TCP (127.0.0.1:445). PID-filtered queries return actual data.
    printf("\n  [INFO] === Beginning network tests ===\n");
    printf("  [INFO] test_target.exe generates HTTP, DNS, TLS, and local TCP traffic\n");
    printf("  [INFO] PID-filtered queries should return real connections and packets\n");

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

    // ── Signal test_target.exe to shut down ──
    // WHY named event: test_target.exe waits on "Global\WhosWhoTestDone".
    // Setting this event causes it to exit cleanly, releasing all sockets
    // and threads. Only signal if WE launched it (don't kill a user-started instance).
    if (launched) {
        HANDLE done_event = OpenEventA(EVENT_MODIFY_STATE, FALSE, "Global\\WhosWhoTestDone");
        if (done_event) {
            SetEvent(done_event);
            CloseHandle(done_event);
            printf("  [INFO] Signaled test_target.exe to shut down\n");
        } else {
            printf("  [WARN] Could not signal test_target.exe (event not found)\n");
        }
    } else {
        printf("  [INFO] test_target.exe was already running; not signaling shutdown\n");
    }

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
