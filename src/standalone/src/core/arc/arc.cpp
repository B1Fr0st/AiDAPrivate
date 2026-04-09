

#define ARC_EXPORTS
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include "arc.h"
#include "../../comm.h"

#include <windows.h>
#include <intrin.h>
#include <iphlpapi.h>
#include <bcrypt.h>

#include <atomic>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <mutex>
#include <string>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "bcrypt.lib")


namespace
{

    struct arc_session_t
    {
        bool     initialized;
        uint64_t session_hash;
        uint64_t hwid_hash;
        uint64_t init_timestamp;
        uint64_t xor_key;
        uint64_t code_hash;
        uint64_t heartbeat_counter;
        uint64_t last_heartbeat_tsc;
    };

    std::mutex      g_session_mtx;
    arc_session_t   g_session = {};


    arc_comm_vtable_t g_vtable = {};
    bool              g_vtable_ready = false;


    uint64_t fnv1a(const void* data, size_t len)
    {
        uint64_t h = 14695981039346656037ULL;
        const auto* p = static_cast<const uint8_t*>(data);
        for (size_t i = 0; i < len; ++i) {
            h ^= p[i];
            h *= 1099511628211ULL;
        }
        return h;
    }

    uint64_t fnv1a_str(const char* s)
    {
        if (!s) return 0;
        return fnv1a(s, strlen(s));
    }


    std::string recompute_hwid()
    {
        uint64_t hash = 14695981039346656037ULL;
        auto mix = [&](uint64_t value) {
            hash ^= value;
            hash *= 1099511628211ULL;
        };

        wchar_t computer_name[MAX_COMPUTERNAME_LENGTH + 1] = {};
        DWORD name_size = MAX_COMPUTERNAME_LENGTH + 1;
        if (GetComputerNameW(computer_name, &name_size)) {
            for (DWORD i = 0; i < name_size; ++i)
                mix(static_cast<uint64_t>(computer_name[i]));
        } else {
            mix(0xDEADBEEF00000001ULL);
        }

        int cpu_info[4] = {};
        __cpuid(cpu_info, 1);
        mix((static_cast<uint64_t>(cpu_info[0]) << 32) | static_cast<unsigned>(cpu_info[1]));
        mix((static_cast<uint64_t>(cpu_info[2]) << 32) | static_cast<unsigned>(cpu_info[3]));

        DWORD volume_serial = 0;
        if (GetVolumeInformationW(L"C:\\", nullptr, 0, &volume_serial, nullptr, nullptr, nullptr, 0)
            && volume_serial != 0) {
            mix(volume_serial);
        } else {
            mix(0xDEADBEEF00000002ULL);
        }

        bool got_guid = false;
        HKEY hKey = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                L"SOFTWARE\\Microsoft\\Cryptography",
                0, KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) {
            wchar_t guid[128] = {};
            DWORD size = sizeof(guid);
            DWORD type = 0;
            if (RegQueryValueExW(hKey, L"MachineGuid", nullptr, &type,
                    reinterpret_cast<BYTE*>(guid), &size) == ERROR_SUCCESS
                && type == REG_SZ && guid[0] != L'\0') {
                for (size_t i = 0; guid[i] != L'\0'; ++i)
                    mix(static_cast<uint64_t>(guid[i]));
                got_guid = true;
            }
            RegCloseKey(hKey);
        }
        if (!got_guid) {
            mix(0xDEADBEEF00000003ULL);
        }

        char out[17];
        snprintf(out, sizeof(out), "%016llX", static_cast<unsigned long long>(hash));
        return out;
    }


    bool check_debugger_present()
    {

        if (IsDebuggerPresent())
            return true;


        using NtQIP_t = LONG(WINAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
        auto NtQIP = reinterpret_cast<NtQIP_t>(
            GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess"));
        if (NtQIP) {
            ULONG_PTR debug_port = 0;
            LONG status = NtQIP(
                GetCurrentProcess(),
                7,
                &debug_port,
                sizeof(debug_port),
                nullptr);
            if (status == 0 && debug_port != 0)
                return true;
        }


        auto* peb = reinterpret_cast<const uint8_t*>(
            __readgsqword(0x60));
        if (peb) {

            uint32_t flags = *reinterpret_cast<const uint32_t*>(peb + 0xBC);

            if (flags & 0x70)
                return true;
        }

        return false;
    }


    uint64_t compute_own_code_hash()
    {
        HMODULE hMod = nullptr;


        MEMORY_BASIC_INFORMATION mbi = {};
        if (VirtualQuery(reinterpret_cast<const void*>(&compute_own_code_hash), &mbi, sizeof(mbi)) == 0)
            return 0;
        hMod = static_cast<HMODULE>(mbi.AllocationBase);
        if (!hMod) return 0;

        auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(hMod);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;

        auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(
            reinterpret_cast<const uint8_t*>(hMod) + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

        const auto* sec = IMAGE_FIRST_SECTION(nt);
        uint64_t combined = 0;
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
            if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
                auto base = reinterpret_cast<uintptr_t>(hMod) + sec[i].VirtualAddress;
                size_t size = sec[i].Misc.VirtualSize;
                if (size > 0 && size < 64 * 1024 * 1024) {
                    combined ^= fnv1a(reinterpret_cast<const void*>(base), size);
                }
            }
        }
        return combined;
    }


    bool is_session_valid()
    {
        std::lock_guard<std::mutex> lk(g_session_mtx);
        if (!g_session.initialized)
            return false;


        uint64_t check = g_session.session_hash ^ g_session.hwid_hash ^ g_session.xor_key;
        if (check == 0)
            return false;


        int64_t now = static_cast<int64_t>(time(nullptr));
        int64_t delta = now - static_cast<int64_t>(g_session.init_timestamp);
        if (delta < -300 || delta > 86400)
            return false;

        return true;
    }


    bool vtable_connect(uint64_t )
    {
        if (!is_session_valid()) return false;
        if (check_debugger_present()) return false;
        if (!device) return false;
        return device->connect();
    }

    void vtable_disconnect()
    {
        if (device) device->disconnect();
    }

    bool vtable_is_connected()
    {
        if (!device) return false;
        return device->is_connected();
    }

    void vtable_set_process_id(uint32_t pid)
    {
        if (!is_session_valid()) return;
        if (device) device->set_process_id(pid);
    }

    uint64_t vtable_solve_dtb()
    {
        if (!is_session_valid()) return 0;
        if (!device) return 0;
        device->solve_dtb();
        return device->get_dtb();
    }

    uint64_t vtable_get_dtb()
    {
        if (!device) return 0;
        return device->get_dtb();
    }

    uint64_t vtable_find_image()
    {
        if (!is_session_valid()) return 0;
        if (!device) return 0;
        return device->find_image();
    }

    void vtable_set_base_address(uint64_t base)
    {
        if (device) device->set_base_address(base);
    }

    uint32_t vtable_find_process(const char* name)
    {
        if (!is_session_valid()) return 0;
        if (!device || !name) return 0;
        return device->find_process(name);
    }

    void vtable_clear_process_context()
    {
        if (device) device->clear_process_context();
    }

    size_t vtable_read_raw(uint64_t address, void* buffer, size_t size)
    {
        if (!is_session_valid()) return 0;
        if (check_debugger_present()) return 0;
        if (!device || !buffer || size == 0) return 0;
        return device->read_raw(address, buffer, size);
    }

    size_t vtable_write_raw(uint64_t address, const void* buffer, size_t size)
    {
        if (!is_session_valid()) return 0;
        if (check_debugger_present()) return 0;
        if (!device || !buffer || size == 0) return 0;
        return device->write_raw(address, buffer, size);
    }

    uint32_t vtable_enumerate_memory_regions(
        void (*callback)(const arc_comm_vtable_t::memory_region_info_t*, void*),
        void* ctx)
    {
        if (!is_session_valid() || !device || !callback) return 0;

        auto regions = device->enumerate_memory_regions(0, 0, false);
        uint32_t count = 0;
        for (const auto& r : regions) {
            arc_comm_vtable_t::memory_region_info_t info{};
            info.base    = r.base;
            info.size    = r.size;
            info.state   = r.state;
            info.protect = r.protect;
            info.type    = r.type;
            callback(&info, ctx);
            ++count;
        }
        return count;
    }

    bool vtable_query_memory(uint64_t address, arc_comm_vtable_t::memory_region_info_t* out)
    {
        if (!is_session_valid() || !device || !out) return false;

        voyager::device_t::memory_region_info info{};
        if (!device->query_memory(address, info))
            return false;

        out->base    = info.base;
        out->size    = info.size;
        out->state   = info.state;
        out->protect = info.protect;
        out->type    = info.type;
        return true;
    }

    uint32_t vtable_enumerate_threads(
        void (*callback)(const arc_comm_vtable_t::thread_info_t*, void*),
        void* ctx)
    {
        if (!is_session_valid() || !device || !callback) return 0;

        auto threads = device->enumerate_threads();
        uint32_t count = 0;
        for (const auto& t : threads) {
            arc_comm_vtable_t::thread_info_t info{};
            info.tid   = t.tid;
            info.state = t.state;
            info.rip   = t.rip;
            callback(&info, ctx);
            ++count;
        }
        return count;
    }

    uint64_t vtable_remote_call(
        uint64_t function_address,
        uint64_t arg1, uint64_t arg2,
        uint64_t arg3, uint64_t arg4)
    {
        if (!is_session_valid() || check_debugger_present()) return 0;
        if (!device) return 0;

        return device->call_function(function_address, arg1, arg2, arg3, arg4);
    }

    void init_vtable()
    {
        g_vtable.connect                  = vtable_connect;
        g_vtable.disconnect               = vtable_disconnect;
        g_vtable.is_connected             = vtable_is_connected;
        g_vtable.set_process_id           = vtable_set_process_id;
        g_vtable.solve_dtb                = vtable_solve_dtb;
        g_vtable.get_dtb                  = vtable_get_dtb;
        g_vtable.find_image               = vtable_find_image;
        g_vtable.set_base_address         = vtable_set_base_address;
        g_vtable.find_process             = vtable_find_process;
        g_vtable.clear_process_context    = vtable_clear_process_context;
        g_vtable.read_raw                 = vtable_read_raw;
        g_vtable.write_raw                = vtable_write_raw;
        g_vtable.enumerate_memory_regions = vtable_enumerate_memory_regions;
        g_vtable.query_memory             = vtable_query_memory;
        g_vtable.enumerate_threads        = vtable_enumerate_threads;
        g_vtable.remote_call              = vtable_remote_call;
        memset(g_vtable._reserved, 0, sizeof(g_vtable._reserved));
        g_vtable_ready = true;
    }
}


extern "C"
{

ARC_API bool arc_init(
    const char*  session_token,
    const char*  hwid,
    int64_t      timestamp,
    uint32_t     interface_version)
{

    if (interface_version != ARC_INTERFACE_VERSION)
        return false;

    if (!session_token || !hwid)
        return false;


    size_t token_len = strlen(session_token);
    if (token_len < 32 || token_len > 128)
        return false;


    size_t hwid_len = strlen(hwid);
    if (hwid_len < 8 || hwid_len > 64)
        return false;


    if (check_debugger_present())
        return false;


    std::string local_hwid = recompute_hwid();
    if (local_hwid != hwid)
        return false;


    int64_t now = static_cast<int64_t>(time(nullptr));
    int64_t drift = now - timestamp;
    if (drift < -300 || drift > 300)
        return false;


    {
        std::lock_guard<std::mutex> lk(g_session_mtx);


        uint64_t tsc = __rdtsc();
        g_session.xor_key = tsc ^ 0xA1DA'CAFE'BABE'C0DEull;

        g_session.session_hash   = fnv1a_str(session_token);
        g_session.hwid_hash      = fnv1a_str(hwid);
        g_session.init_timestamp = static_cast<uint64_t>(timestamp);
        g_session.heartbeat_counter = 0;
        g_session.last_heartbeat_tsc = __rdtsc();

        // Compute code integrity hash of our own .text section
        g_session.code_hash = compute_own_code_hash();

        g_session.initialized = true;
    }

    // Initialize the driver comm vtable
    init_vtable();

    return true;
}

ARC_API const arc_comm_vtable_t* arc_get_comm_bridge()
{
    if (!is_session_valid())
        return nullptr;

    if (!g_vtable_ready)
        return nullptr;

    return &g_vtable;
}

ARC_API uint64_t arc_validate_tool_exec(
    uint64_t tool_name_hash,
    uint64_t gate_token)
{
    // Both must be non-zero
    if (tool_name_hash == 0 || gate_token == 0)
        return 0;

    // Session must be valid
    if (!is_session_valid())
        return 0;

    // Anti-debug check on every tool execution
    if (check_debugger_present())
        return 0;

    // Compute verification token
    std::lock_guard<std::mutex> lk(g_session_mtx);
    uint64_t buf[4] = {
        tool_name_hash,
        gate_token,
        g_session.session_hash,
        static_cast<uint64_t>(GetTickCount64()),
    };
    return fnv1a(buf, sizeof(buf));
}

ARC_API arc_heartbeat_result_t arc_heartbeat()
{
    arc_heartbeat_result_t result{};
    result.valid = false;
    result.proof_token = 0;
    result.timestamp = 0;

    if (!is_session_valid())
        return result;

    // Code integrity check: verify our .text section hasn't been patched
    uint64_t current_hash = compute_own_code_hash();
    {
        std::lock_guard<std::mutex> lk(g_session_mtx);
        if (g_session.code_hash != 0 && current_hash != g_session.code_hash) {

            g_session.initialized = false;
            SecureZeroMemory(&g_session, sizeof(g_session));
            return result;
        }


        if (check_debugger_present()) {
            g_session.initialized = false;
            SecureZeroMemory(&g_session, sizeof(g_session));
            return result;
        }


        uint64_t current_tsc = __rdtsc();
        if (current_tsc < g_session.last_heartbeat_tsc) {

            g_session.initialized = false;
            SecureZeroMemory(&g_session, sizeof(g_session));
            return result;
        }
        g_session.last_heartbeat_tsc = current_tsc;
        g_session.heartbeat_counter++;


        uint64_t proof_data[5] = {
            g_session.session_hash,
            g_session.hwid_hash,
            g_session.heartbeat_counter,
            g_session.code_hash,
            current_tsc,
        };
        result.proof_token = fnv1a(proof_data, sizeof(proof_data));
        result.timestamp = static_cast<uint64_t>(time(nullptr));
        result.valid = true;
    }

    return result;
}

ARC_API void arc_cleanup()
{
    std::lock_guard<std::mutex> lk(g_session_mtx);


    SecureZeroMemory(&g_session, sizeof(g_session));


    SecureZeroMemory(&g_vtable, sizeof(g_vtable));
    g_vtable_ready = false;
}

}


BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID)
{
    switch (reason) {
    case DLL_PROCESS_ATTACH:

        break;
    case DLL_PROCESS_DETACH:
        arc_cleanup();
        break;
    }
    return TRUE;
}
