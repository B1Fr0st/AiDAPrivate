#include "aida_pro.hpp"

#include "anti_re.hpp"
#include "game_stealth.hpp"
#include "ida_utils.hpp"
#include "graphrag.hpp"
#include "analysis_db.hpp"
#include "vuln/embedded_libz3.hpp"
#include "vuln/chain_verify_service.hpp"

#include <delayimp.h>

extern "C" {

static FARPROC WINAPI aida_plugin_delay_load_hook(unsigned dliNotify, PDelayLoadInfo pdli)
{
    if (dliNotify == dliNotePreLoadLibrary && pdli != nullptr && pdli->szDll != nullptr)
    {
        if (_stricmp(pdli->szDll, "libz3.dll") == 0)
        {
            aida::vuln::embedded_libz3::ensure_loaded();
            HMODULE m = aida::vuln::embedded_libz3::g_z3_module.load(std::memory_order_acquire);
            if (m != nullptr)
                return reinterpret_cast<FARPROC>(m);
        }
    }
    return nullptr;
}

const PfnDliHook __pfnDliNotifyHook2 = aida_plugin_delay_load_hook;

}

#ifdef __NT__
#include "driver_loader.hpp"
#include "aida_ipc.hpp"
#include <atomic>
#include <exception>
#include <thread>
#include <bcrypt.h>
#include <vector>

#pragma comment(lib, "bcrypt.lib")
#endif

#ifdef __NT__

namespace {

constexpr DWORD kDllMainBadHostFastFailCode  = 0xA1DAB10Fu;
constexpr DWORD kDllMainBadNameFastFailCode  = 0xA1DAB110u;

std::atomic<bool> g_plugin_module_pinned{false};

bool env_flag_enabled(const char* name)
{
    if (!name || !*name)
        return false;
    char value[16] = {};
    DWORD n = GetEnvironmentVariableA(name, value, static_cast<DWORD>(sizeof(value)));
    if (n == 0)
        return false;
    if (n >= sizeof(value))
        return true;
    return value[0] != '\0' && !(value[0] == '0' && value[1] == '\0');
}

bool destructive_plugin_action_suppressed()
{
    return env_flag_enabled("AIDA_FULL_TEST_RUNNING") ||
           env_flag_enabled("AIDA_DISABLE_DESTRUCTIVE_ENFORCEMENT");
}

bool pin_plugin_module()
{
    if (g_plugin_module_pinned.load(std::memory_order_acquire))
        return true;
    HMODULE module = nullptr;
    BOOL ok = GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
                                 reinterpret_cast<LPCWSTR>(&pin_plugin_module),
                                 &module);
    DWORD gle = ok ? 0 : GetLastError();
    const bool pinned = ok && module != nullptr;
    if (pinned)
        g_plugin_module_pinned.store(true, std::memory_order_release);
    aida_ipc::trace_breadcrumb("plugin_module_pin ok=%d module=%p gle=%lu", pinned ? 1 : 0, module, gle);
    return pinned;
}

void join_plugin_thread(std::thread& worker, const char* name)
{
    if (!worker.joinable())
        return;
    const ULONGLONG started = GetTickCount64();
    aida_ipc::trace_breadcrumb("plugin_worker_join_begin name=%s", name ? name : "<unknown>");
    try
    {
        worker.join();
        aida_ipc::trace_breadcrumb("plugin_worker_join_done name=%s elapsed_ms=%llu",
                                   name ? name : "<unknown>",
                                   static_cast<unsigned long long>(GetTickCount64() - started));
    }
    catch (const std::exception& ex)
    {
        aida_ipc::trace_breadcrumb("plugin_worker_join_exception name=%s what=%s",
                                   name ? name : "<unknown>",
                                   ex.what());
    }
    catch (...)
    {
        aida_ipc::trace_breadcrumb("plugin_worker_join_unknown_exception name=%s", name ? name : "<unknown>");
    }
}

bool ascii_iequal_w(const wchar_t* a, const wchar_t* b)
{
    while (*a && *b)
    {
        wchar_t la = static_cast<wchar_t>(towlower(*a));
        wchar_t lb = static_cast<wchar_t>(towlower(*b));
        if (la != lb)
            return false;
        ++a;
        ++b;
    }
    return *a == L'\0' && *b == L'\0';
}

bool plugin_get_basename(HMODULE module, wchar_t* out, size_t cap)
{
    wchar_t full_path[MAX_PATH] = {};
    DWORD got = GetModuleFileNameW(module, full_path, MAX_PATH);
    if (got == 0 || got >= MAX_PATH)
        return false;
    const wchar_t* base = full_path;
    for (const wchar_t* p = full_path; *p != L'\0'; ++p)
    {
        if (*p == L'\\' || *p == L'/')
            base = p + 1;
    }
    size_t len = wcslen(base);
    if (len + 1 > cap)
        return false;
    for (size_t i = 0; i < len; ++i)
        out[i] = base[i];
    out[len] = L'\0';
    return true;
}

bool plugin_host_is_ida_exe()
{
    wchar_t host_name[MAX_PATH] = {};
    if (!plugin_get_basename(nullptr, host_name, MAX_PATH))
        return false;
    static const wchar_t* allowed_hosts[] = {
        L"ida.exe",      L"ida64.exe",
        L"idat.exe",     L"idat64.exe",
        L"idaq.exe",     L"idaq64.exe",
        L"idaw.exe",     L"idaw64.exe",
        L"idal.exe",     L"idal64.exe",
        L"ida-pro.exe",  L"idapro.exe"
    };
    for (const wchar_t* allowed : allowed_hosts)
    {
        if (ascii_iequal_w(host_name, allowed))
            return true;
    }
    return false;
}

bool plugin_own_filename_is_canonical(HINSTANCE self_module)
{
    wchar_t own_name[MAX_PATH] = {};
    if (!plugin_get_basename(reinterpret_cast<HMODULE>(self_module), own_name, MAX_PATH))
        return false;
    return ascii_iequal_w(own_name, L"aida.dll");
}

DWORD WINAPI plugin_kill_thread(LPVOID param)
{
    DWORD reason = static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(param));
    if (destructive_plugin_action_suppressed())
    {
        msg("AiDA: plugin kill suppressed in full-test/destructive-disabled mode reason=0x%08X\n", reason);
        return 0;
    }
    Sleep(50);
    bool driver_ok = false;
    __try {
        driver_ok = driver_loader::is_driver_loaded();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        driver_ok = false;
    }
    if (driver_ok)
    {
        __try {
            if (device && (device->is_connected() || device->connect()))
            {
                device->trigger_kernel_bsod(
                    reason,
                    static_cast<std::uint64_t>(__rdtsc()) ^ 0xA1DAB10C0FF1CEDDull);
                Sleep(3000);
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
        }
    }
    __fastfail(reason);
    return 0;
}

void plugin_dispatch_kill(DWORD reason)
{
    HANDLE t = CreateThread(
        nullptr, 0,
        plugin_kill_thread,
        reinterpret_cast<LPVOID>(static_cast<ULONG_PTR>(reason)),
        0, nullptr);
    if (t)
        CloseHandle(t);
}

void plugin_validate_load_context(HINSTANCE self_module)
{
    bool host_ok = plugin_host_is_ida_exe();
    if (!host_ok)
    {
        plugin_dispatch_kill(kDllMainBadHostFastFailCode);
        return;
    }
    if (!plugin_own_filename_is_canonical(self_module))
    {
        plugin_dispatch_kill(kDllMainBadNameFastFailCode);
    }
}

}
extern "C" BOOL WINAPI DllMain(HINSTANCE hinstDLL,
                                DWORD     fdwReason,
                                LPVOID    )
{
#ifdef __NT__
    aida_ipc::trace_breadcrumb("DllMain_enter fdwReason=%lu hinstDLL=%p", static_cast<unsigned long>(fdwReason), static_cast<void*>(hinstDLL));
#endif
    if (fdwReason == DLL_PROCESS_ATTACH)
    {
#ifdef __NT__
        aida_ipc::trace_breadcrumb("DllMain_before_DisableThreadLibraryCalls");
#endif
        DisableThreadLibraryCalls(hinstDLL);
#ifdef __NT__
        aida_ipc::trace_breadcrumb("DllMain_after_DisableThreadLibraryCalls");
        /* plugin_validate_load_context(hinstDLL); */
        aida_ipc::trace_breadcrumb("DllMain_plugin_validate_load_context_commented_out");
#endif
    }
#ifdef __NT__
    aida_ipc::trace_breadcrumb("DllMain_exit_returning_TRUE");
#endif
    return TRUE;
}

namespace {

constexpr DWORD  kSelfReverseEngineerBsodCode     = 0xA1DA0DEAu;

uint8_t g_self_re_forbidden_hash_standalone[32] = {};
uint8_t g_self_re_forbidden_hash_plugin[32]     = {};
uint8_t g_self_re_forbidden_hash_arc[32]        = {};
std::atomic<bool> g_self_re_hashes_ready{false};

bool hash_is_zero(const uint8_t h[32])
{
    for (int i = 0; i < 32; ++i)
        if (h[i] != 0) return false;
    return true;
}

bool sha256_file_path_w(const wchar_t* path, uint8_t out_hash[32])
{
    std::memset(out_hash, 0, 32);
    HANDLE hf = CreateFileW(path, GENERIC_READ,
                            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            nullptr, OPEN_EXISTING,
                            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
                            nullptr);
    if (hf == INVALID_HANDLE_VALUE) return false;

    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE hh = nullptr;
    DWORD obj_len = 0, got = 0;
    std::vector<unsigned char> obj_buf;
    bool ok = false;
    do {
        if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM,
                                                          nullptr, 0)))
            break;
        if (!BCRYPT_SUCCESS(BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH,
                                                reinterpret_cast<PUCHAR>(&obj_len),
                                                sizeof(obj_len), &got, 0))
            || obj_len == 0)
            break;
        obj_buf.assign(obj_len, 0);
        if (!BCRYPT_SUCCESS(BCryptCreateHash(alg, &hh, obj_buf.data(), obj_len,
                                               nullptr, 0, 0)))
            break;
        uint8_t buf[65536];
        DWORD bytes_read = 0;
        ok = true;
        while (ReadFile(hf, buf, sizeof(buf), &bytes_read, nullptr) && bytes_read > 0)
        {
            if (!BCRYPT_SUCCESS(BCryptHashData(hh, buf, bytes_read, 0)))
            {
                ok = false;
                break;
            }
        }
        if (!ok) break;
        if (!BCRYPT_SUCCESS(BCryptFinishHash(hh, out_hash, 32, 0)))
            ok = false;
    } while (false);
    if (hh) BCryptDestroyHash(hh);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    CloseHandle(hf);
    return ok;
}

bool hashes_equal(const uint8_t a[32], const uint8_t b[32])
{
    uint8_t diff = 0;
    for (int i = 0; i < 32; ++i)
        diff |= static_cast<uint8_t>(a[i] ^ b[i]);
    return diff == 0;
}

__declspec(noinline) static DWORD seh_self_re_bsod_call(uint32_t reason_code, uint64_t evidence)
{
    DWORD seh = 0;
    __try {
        if (device.get() != nullptr
            && (device->is_connected() || device->connect()))
        {
            (void)device->trigger_kernel_bsod(reason_code, evidence);
        }
    } __except ((seh = GetExceptionCode()), EXCEPTION_EXECUTE_HANDLER) {}
    return seh;
}

void trigger_self_re_bsod(const char* full_path, const uint8_t matched_hash[32])
{
    msg(OBFSTR_C("AiDA: self-reverse-engineering attempt detected. target=%s\n"),
        full_path ? full_path : "(null)");
    if (destructive_plugin_action_suppressed())
    {
        msg(OBFSTR_C("AiDA: self-reverse-engineering destructive response suppressed by test-safe environment.\n"));
        return;
    }
    std::uint64_t evidence = 0;
    if (matched_hash)
        std::memcpy(&evidence, matched_hash, sizeof(evidence));
    (void)seh_self_re_bsod_call(kSelfReverseEngineerBsodCode, evidence);
    Sleep(2000);
    __fastfail(kSelfReverseEngineerBsodCode);
}

void check_input_for_self_target()
{
    if (!g_self_re_hashes_ready.load(std::memory_order_acquire))
        return;
    char path_a[MAX_PATH * 2] = {};
    ssize_t n = get_input_file_path(path_a, sizeof(path_a));
    if (n <= 0 || path_a[0] == '\0')
        return;
    int wlen = MultiByteToWideChar(CP_UTF8, 0, path_a, -1, nullptr, 0);
    if (wlen <= 0) return;
    std::vector<wchar_t> wpath(static_cast<size_t>(wlen), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, path_a, -1, wpath.data(), wlen);

    uint8_t actual[32] = {};
    if (!sha256_file_path_w(wpath.data(), actual))
        return;

    const uint8_t* matched = nullptr;
    if (!hash_is_zero(g_self_re_forbidden_hash_standalone)
        && hashes_equal(actual, g_self_re_forbidden_hash_standalone))
        matched = g_self_re_forbidden_hash_standalone;
    else if (!hash_is_zero(g_self_re_forbidden_hash_plugin)
        && hashes_equal(actual, g_self_re_forbidden_hash_plugin))
        matched = g_self_re_forbidden_hash_plugin;
    else if (!hash_is_zero(g_self_re_forbidden_hash_arc)
        && hashes_equal(actual, g_self_re_forbidden_hash_arc))
        matched = g_self_re_forbidden_hash_arc;

    if (!matched)
        return;
    trigger_self_re_bsod(path_a, matched);
}

bool plugin_cpuid_vm_vendor_match();
bool plugin_hyperv_guest_partition();
bool plugin_smbios_vm_string();
void plugin_vm_guard();
void plugin_kd_test_signing_guard();

constexpr DWORD kVirtualMachineFastFailCode = 0xA1DAB10Cu;
constexpr DWORD kKernelDebugFastFailCode    = 0xA1DAB10Du;
constexpr DWORD kTestSigningFastFailCode    = 0xA1DAB10Eu;

bool plugin_cpuid_vm_vendor_match()
{
    int regs[4] = {};
    __cpuid(regs, 1);
    if ((regs[2] & (1 << 31)) == 0)
        return false;

    __cpuid(regs, 0x40000000);
    char vendor[12];
    memcpy(vendor + 0, &regs[1], 4);
    memcpy(vendor + 4, &regs[2], 4);
    memcpy(vendor + 8, &regs[3], 4);

    static const char* known[] = {
        "VMwareVMware",
        "KVMKVMKVM\0\0\0",
        "VBoxVBoxVBox",
        "XenVMMXenVMM",
        "prl hyperv \0",
        " lrpepyh vr",
        "bhyve bhyve ",
        "TCGTCGTCGTCG",
        "ACRNACRNACRN",
    };
    for (const auto* k : known)
    {
        if (memcmp(vendor, k, 12) == 0)
            return true;
    }
    return false;
}

bool plugin_hyperv_guest_partition()
{
    int regs[4] = {};
    __cpuid(regs, 1);
    if ((regs[2] & (1 << 31)) == 0)
        return false;

    __cpuid(regs, 0x40000000);
    char vendor[12];
    memcpy(vendor + 0, &regs[1], 4);
    memcpy(vendor + 4, &regs[2], 4);
    memcpy(vendor + 8, &regs[3], 4);

    const char hv[12] = { 'M','i','c','r','o','s','o','f','t',' ','H','v' };
    if (memcmp(vendor, hv, 12) != 0)
        return false;

    __cpuid(regs, 0x40000001);
    if (static_cast<uint32_t>(regs[0]) != 0x31237648u)
        return true;

    __cpuid(regs, 0x40000003);
    uint32_t partition_caps = static_cast<uint32_t>(regs[0]);
    const uint32_t root_bits = (1u << 0) | (1u << 1) | (1u << 5);
    return (partition_caps & root_bits) == 0;
}

bool plugin_smbios_vm_string()
{
    UINT size = GetSystemFirmwareTable('RSMB', 0, nullptr, 0);
    if (size == 0 || size > 1024 * 1024)
        return false;

    auto* buf = static_cast<uint8_t*>(malloc(size));
    if (!buf)
        return false;

    bool found = false;
    if (GetSystemFirmwareTable('RSMB', 0, buf, size) == size)
    {
        static const char* const short_needles[] = {
            "QEMU",
            "VBOX",
            "VirtualBox",
            "innotek",
            "BOCHS",
            "Bochs",
            "Parallels",
            "SeaBIOS",
            "BXPC",
            "OVMF",
            "EDK II",
            "Tianocore",
            "Standard PC (Q35"
        };
        for (UINT i = 0; i + 4 <= size && !found; ++i)
        {
            const char* p = reinterpret_cast<const char*>(buf + i);
            for (const char* needle : short_needles)
            {
                size_t nlen = strlen(needle);
                if (i + nlen > size)
                    continue;
                if (memcmp(p, needle, nlen) == 0)
                {
                    found = true;
                    break;
                }
            }
            if (found)
                break;
            if (i + 12 <= size &&
                (memcmp(p, "VMware, Inc.", 12) == 0
                 || memcmp(p, "VMware Virt", 11) == 0))
            {
                found = true;
            }
        }
    }
    free(buf);
    return found;
}

void plugin_vm_guard()
{
    if (plugin_cpuid_vm_vendor_match())
        __fastfail(kVirtualMachineFastFailCode);

    if (plugin_hyperv_guest_partition())
        __fastfail(kVirtualMachineFastFailCode);

    if (plugin_smbios_vm_string())
        __fastfail(kVirtualMachineFastFailCode);
}

using nt_query_system_information_t = LONG (WINAPI*)(ULONG, PVOID, ULONG, PULONG);

constexpr ULONG kPluginSystemKernelDebuggerInformation = 35;
constexpr ULONG kPluginSystemCodeIntegrityInformation  = 103;
constexpr ULONG kPluginCodeIntegrityTestSign           = 0x02;

struct plugin_system_kernel_debugger_information_t
{
    BOOLEAN kernel_debugger_enabled;
    BOOLEAN kernel_debugger_not_present;
};

struct plugin_system_code_integrity_information_t
{
    ULONG length;
    ULONG code_integrity_options;
};

nt_query_system_information_t plugin_resolve_nt_query_system_information()
{
    HMODULE nt = GetModuleHandleW(L"ntdll.dll");
    if (!nt)
        return nullptr;
    return reinterpret_cast<nt_query_system_information_t>(
        GetProcAddress(nt, "NtQuerySystemInformation"));
}

void plugin_kd_test_signing_guard()
{
    auto fn = plugin_resolve_nt_query_system_information();
    if (!fn)
        return;

    plugin_system_kernel_debugger_information_t kdi{};
    ULONG ret = 0;
    LONG status = fn(kPluginSystemKernelDebuggerInformation, &kdi, sizeof(kdi), &ret);
    if (status >= 0 && kdi.kernel_debugger_enabled != 0 && kdi.kernel_debugger_not_present == 0)
        __fastfail(kKernelDebugFastFailCode);

    plugin_system_code_integrity_information_t sci{};
    sci.length = sizeof(sci);
    ret = 0;
    status = fn(kPluginSystemCodeIntegrityInformation, &sci, sizeof(sci), &ret);
    if (status >= 0 && (sci.code_integrity_options & kPluginCodeIntegrityTestSign) != 0)
        __fastfail(kTestSigningFastFailCode);
}

}
#endif

#ifdef __NT__
static bool has_expected_plugin_filename()
{
    HMODULE module = nullptr;
    if (!GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS
                | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCWSTR>(&has_expected_plugin_filename),
            &module) || module == nullptr)
    {
        return false;
    }

    wchar_t module_path[MAX_PATH] = {};
    if (GetModuleFileNameW(module, module_path, MAX_PATH) == 0)
        return false;

    const wchar_t* base_name = module_path;
    for (const wchar_t* p = module_path; *p != L'\0'; ++p)
    {
        if (*p == L'\\' || *p == L'/')
            base_name = p + 1;
    }

    return wcscmp(base_name, L"AiDA.dll") == 0;
}
#endif

extern "C" int __stdcall simpleline_place_t__compare2(
    const simpleline_place_t *a,
    const place_t *b,
    void *)
{
    return simpleline_place_t__compare(a, b);
}

extern "C" bool __stdcall simpleline_place_t__equals(
    const simpleline_place_t *a,
    const place_t *b,
    void *ud)
{
    return simpleline_place_t__compare2(a, b, ud) == 0;
}


static bool show_eula_dialog()
{
    int choice = ask_yn(ASKBTN_NO,
        "AiDA - End User License Agreement\n"
        "\n"
        "By clicking YES you acknowledge that you have read, understood,\n"
        "and agreed to the AiDA End User License Agreement.\n"
        "\n"
        "Key points:\n"
        "  - You may only use AiDA on targets you are legally authorized to analyze.\n"
        "  - The software contains anti-reverse-engineering self-defense mechanisms.\n"
        "  - Telemetry data (HWID, IP, Discord ID) is collected for license enforcement.\n"
        "  - AI provider endpoints are volatile and may change without notice.\n"
        "  - The kernel driver operates at Ring 0; system instability may occur.\n"
        "  - The software is provided AS-IS with no warranty.\n"
        "\n"
        "Do you accept the EULA?");
    return choice == ASKBTN_YES;
}


static int idaapi finish_populating_widget_popup(
    TWidget* widget, TPopupMenu* popup_handle,
    const action_activation_ctx_t* ctx)
{
#ifdef __NT__
    aida_ipc::trace_breadcrumb("finish_populating_widget_popup_enter ctx=%p", static_cast<void*>(const_cast<action_activation_ctx_t*>(ctx)));
#endif
    if (ctx == nullptr
        || (ctx->widget_type != BWN_PSEUDOCODE && ctx->widget_type != BWN_DISASM))
    {
#ifdef __NT__
        aida_ipc::trace_breadcrumb("finish_populating_widget_popup_return_0 ctx_null=%d widget_type=%d", ctx == nullptr ? 1 : 0, ctx ? ctx->widget_type : -1);
#endif
        return 0;
    }

    static const char* const kept_actions[] = {
        "ai_assistant:copy_context",
        "ai_assistant:save_database_context",
        "ai_assistant:fix_analysis",
        "aida:chain_verify_open_panel",
        "aida:chain_verify_current_function_as_link",
        "aida:chain_verify_start",
        "aida:chain_verify_cancel",
        "aida:chain_verify_copy_result_json",
    };

    const std::string menu_root = OBFSTR("AiDA/");
#ifdef __NT__
    aida_ipc::trace_breadcrumb("finish_populating_widget_popup_before_attach_loop count=%d", static_cast<int>(sizeof(kept_actions)/sizeof(kept_actions[0])));
#endif
    for (const char* action_name : kept_actions)
    {
        attach_action_to_popup(widget, popup_handle, action_name,
                               menu_root.c_str(), 0);
    }
#ifdef __NT__
    aida_ipc::trace_breadcrumb("finish_populating_widget_popup_return_0_after_attach");
#endif
    return 0;
}


ssize_t idaapi ui_event_listener_t::on_event(ssize_t code, va_list va)
{
#ifdef __NT__
    aida_ipc::trace_breadcrumb("ui_event_on_event_enter code=%zd", static_cast<ssize_t>(code));
#endif
#ifdef __NT__
    /*
    if (code == ui_ready_to_run)
    {
        anti_re::initialize();
        check_input_for_self_target();
    }
    if (code == ui_database_inited)
    {
        check_input_for_self_target();
    }
    */
    aida_ipc::trace_breadcrumb("ui_event_on_event_commented_block_end");
#endif

    if (code == ui_finish_populating_widget_popup)
    {
#ifdef __NT__
        aida_ipc::trace_breadcrumb("ui_event_on_event_finish_populating_widget_popup");
#endif
        TWidget* widget = va_arg(va, TWidget*);
        TPopupMenu* popup_handle = va_arg(va, TPopupMenu*);
        const action_activation_ctx_t* ctx = va_arg(va, const action_activation_ctx_t*);
#ifdef __NT__
        aida_ipc::trace_breadcrumb("ui_event_on_event_calling_finish_populating_widget_popup");
#endif
        return finish_populating_widget_popup(widget, popup_handle, ctx);
    }
#ifdef __NT__
    aida_ipc::trace_breadcrumb("ui_event_on_event_return_0");
#endif
    return 0;
}

static int idaapi self_analysis_watchdog(void *)
{
#ifdef __NT__
    aida_ipc::trace_breadcrumb("self_analysis_watchdog_enter");
    aida_ipc::trace_breadcrumb("self_analysis_watchdog_commented_block_begin");
#endif
    /*
    static bool s_self_target_checked = false;
    static bool s_is_self_target      = false;

    aida_ipc::trace_breadcrumb("self_analysis_watchdog_enter checked=%d self_target=%d", s_self_target_checked ? 1 : 0, s_is_self_target ? 1 : 0);
    if (!s_self_target_checked)
    {
        s_is_self_target      = ida_utils::is_self_target_database();
        s_self_target_checked = true;
        aida_ipc::trace_breadcrumb("self_analysis_watchdog_self_target_checked self_target=%d", s_is_self_target ? 1 : 0);
    }

    if (s_is_self_target)
    {
        aida_ipc::trace_breadcrumb("self_analysis_watchdog_stop_self_target");
        return -1;
    }

#ifdef __NT__
    aida_ipc::trace_breadcrumb("self_analysis_watchdog_guard_begin");
    const bool guard_ok = anti_re::guard();
    const DWORD internal_exception = anti_re::last_internal_verify_exception();
    aida_ipc::trace_breadcrumb("self_analysis_watchdog_guard_result ok=%d internal_exception=0x%08lX", guard_ok ? 1 : 0, internal_exception);
    if (!guard_ok)
    {
        if (internal_exception != 0)
        {
            anti_re::latch_self_analysis_violation("self_analysis_watchdog_internal_verify_exception", false);
            anti_re::sync_latched_violation_with_server();
            aida_ipc::trace_breadcrumb("self_analysis_watchdog_stop_internal_exception code=0x%08lX", internal_exception);
            return -1;
        }
        anti_re::latch_self_analysis_violation("self_analysis_watchdog");
        anti_re::sync_latched_violation_with_server();
        anti_re::arm_destructive_enforcement();
        anti_re::enforce_self_analysis_violation();
        aida_ipc::trace_breadcrumb("self_analysis_watchdog_enforced_violation");
        return -1;
    }
#endif

    aida_ipc::trace_breadcrumb("self_analysis_watchdog_reschedule");
    return 30000;
    */
#ifdef __NT__
    aida_ipc::trace_breadcrumb("self_analysis_watchdog_commented_block_end returning_minus1");
#endif
    return -1;
}

class chain_verify_action_handler_t final : public action_handler_t
{
public:
    chain_verify_action_handler_t(aida::vuln::chain_verify_action_kind_t action_kind, aida_plugin_t* owner)
        : kind(action_kind), plugin(owner)
    {
    }

    int idaapi activate(action_activation_ctx_t* ctx) override
    {
        if (plugin != nullptr)
            plugin->activate_chain_verify_action(kind, ctx);
        return 1;
    }

    action_state_t idaapi update(action_update_ctx_t* ctx) override
    {
        if (plugin == nullptr)
            return AST_DISABLE;
        return plugin->update_chain_verify_action(kind, ctx);
    }

private:
    aida::vuln::chain_verify_action_kind_t kind;
    aida_plugin_t* plugin = nullptr;
};

aida_plugin_t::aida_plugin_t(bool standalone_verified, const std::string& standalone_failure)
{
#ifdef __NT__
    aida_ipc::trace_breadcrumb("constructor_enter standalone_verified=%d", standalone_verified ? 1 : 0);
    aida_ipc::trace_breadcrumb("constructor_standalone_failure=%s", standalone_failure.empty() ? "(empty)" : standalone_failure.c_str());
#endif
    msg(OBFSTR_C("--- Plugin Loading (v%s) ---\n"), AIDA_VERSION);
#ifdef __NT__
    aida_ipc::trace_breadcrumb("constructor_after_version_msg");
    aida_ipc::trace_breadcrumb("constructor_before_chain_verifier_service_create");
#endif
    chain_verifier_service = std::make_unique<aida::vuln::chain_verifier_service_t>();
#ifdef __NT__
    aida_ipc::trace_breadcrumb("constructor_after_chain_verifier_service_create");
    aida_ipc::trace_breadcrumb("constructor_before_register_actions");
#endif
    register_actions();
#ifdef __NT__
    aida_ipc::trace_breadcrumb("constructor_after_register_actions");
    aida_ipc::trace_breadcrumb("constructor_commented_block_standalone_verified_check_begin");
#endif

    /*
    if (!standalone_verified)
    {
        set_disabled(std::string("AiDAStandalone.exe is not reachable or not authenticated: ")
            + (standalone_failure.empty() ? "verification failed" : standalone_failure));
        msg(OBFSTR_C("AiDA: plugin loaded in disabled mode. %s\n"), disabled_detail.c_str());
        return;
    }
    */

#ifdef __NT__
    aida_ipc::trace_breadcrumb("constructor_commented_block_standalone_verified_check_end");
    aida_ipc::trace_breadcrumb("constructor_before_initialize_operational");
#endif
    if (!initialize_operational(true))
    {
#ifdef __NT__
        aida_ipc::trace_breadcrumb("constructor_initialize_operational_failed disabled_detail=%s", disabled_detail.c_str());
#endif
        msg(OBFSTR_C("AiDA: plugin loaded in disabled mode. %s\n"), disabled_detail.c_str());
    }
#ifdef __NT__
    else
    {
        aida_ipc::trace_breadcrumb("constructor_initialize_operational_succeeded");
    }
    aida_ipc::trace_breadcrumb("constructor_exit");
#endif
}

void aida_plugin_t::set_disabled(const std::string& reason)
{
#ifdef __NT__
    aida_ipc::trace_breadcrumb("set_disabled_enter reason=%s", reason.empty() ? "(empty)" : reason.c_str());
#endif
    disabled_detail = reason.empty() ? std::string("standalone verification failed") : reason;
    features_initialized = false;
#ifdef __NT__
    aida_ipc::trace_breadcrumb("set_disabled_exit disabled_detail=%s features_initialized=0", disabled_detail.c_str());
#endif
}

bool aida_plugin_t::is_operational() const
{
#ifdef __NT__
    aida_ipc::trace_breadcrumb("is_operational features_initialized=%d", features_initialized ? 1 : 0);
#endif
    return features_initialized;
}

const std::string& aida_plugin_t::disabled_reason() const
{
    return disabled_detail;
}

bool aida_plugin_t::ensure_operational(bool interactive)
{
#ifdef __NT__
    aida_ipc::trace_breadcrumb("ensure_operational_enter interactive=%d features_initialized=%d", interactive ? 1 : 0, features_initialized ? 1 : 0);
#endif
    if (features_initialized)
    {
#ifdef __NT__
        aida_ipc::trace_breadcrumb("ensure_operational_already_initialized_returning_true");
#endif
        return true;
    }
#ifdef __NT__
    aida_ipc::trace_breadcrumb("ensure_operational_calling_initialize_operational");
#endif
    return initialize_operational(interactive);
}

bool aida_plugin_t::initialize_operational(bool interactive)
{
#ifdef __NT__
    aida_ipc::trace_breadcrumb("initialize_operational_enter interactive=%d", interactive ? 1 : 0);
    aida_ipc::trace_breadcrumb("initialize_operational_commented_block_1_begin (verify_standalone, watchdog)");
#endif
    /*
#ifdef __NT__
    aida_ipc::trace_breadcrumb("initialize_operational_enter interactive=%d", interactive ? 1 : 0);
    std::string standalone_failure;
    aida_ipc::trace_breadcrumb("initialize_operational_verify_standalone_begin");
    if (!aida_ipc::verify_standalone_runtime(&standalone_failure))
    {
        set_disabled(std::string("AiDAStandalone.exe must be running, authenticated, and ARC-verified. detail=")
            + (standalone_failure.empty() ? "verification failed" : standalone_failure));
        aida_ipc::trace_breadcrumb("initialize_operational_verify_standalone_fail reason=%s", disabled_detail.c_str());
        if (interactive)
            warning(OBFSTR_C("AiDA is disabled: %s"), disabled_detail.c_str());
        else
            msg(OBFSTR_C("AiDA: %s\n"), disabled_detail.c_str());
        return false;
    }
    aida_ipc::trace_breadcrumb("initialize_operational_verify_standalone_ok");
    driver_loader::mark_already_loaded();
    if (!aida_ipc::start_standalone_watchdog())
        msg(OBFSTR_C("AiDA standalone watchdog worker unavailable.\n"));
    aida_ipc::trace_breadcrumb("initialize_operational_watchdog_started");
#endif
    */

#ifdef __NT__
    aida_ipc::trace_breadcrumb("initialize_operational_commented_block_1_end");
    aida_ipc::trace_breadcrumb("initialize_operational_before_settings_load_from_file");
#endif
    g_settings.load_from_file();
#ifdef __NT__
    aida_ipc::trace_breadcrumb("initialize_operational_after_settings_load_from_file");
    aida_ipc::trace_breadcrumb("initialize_operational_commented_block_2_begin (eula)");
#endif

    /*
    if (!g_settings.eula_accepted)
    {
        aida_ipc::trace_breadcrumb("initialize_operational_eula_prompt_begin");
        if (!show_eula_dialog())
        {
            set_disabled("End User License Agreement was declined");
            msg(OBFSTR_C("AiDA: End User License Agreement was declined. Plugin remains disabled.\n"));
            aida_ipc::trace_breadcrumb("initialize_operational_eula_declined");
            return false;
        }
        g_settings.eula_accepted = true;
        aida_ipc::trace_breadcrumb("initialize_operational_eula_save_begin");
        g_settings.save();
        aida_ipc::trace_breadcrumb("initialize_operational_eula_save_done");
    }
    */

#ifdef __NT__
    aida_ipc::trace_breadcrumb("initialize_operational_commented_block_2_end (eula)");
    aida_ipc::trace_breadcrumb("initialize_operational_commented_block_3_begin (anti_re)");
#endif

    /*
    #ifdef __NT__
    aida_ipc::trace_breadcrumb("initialize_operational_anti_re_initialize_begin");
    if (!anti_re::initialize())
        msg(OBFSTR_C("AiDA: kernel-backed runtime attestation warm-up failed; runtime checks will retry on demand.\n"));
    aida_ipc::trace_breadcrumb("initialize_operational_anti_re_initialize_done");
    #endif
    */

#ifdef __NT__
    aida_ipc::trace_breadcrumb("initialize_operational_commented_block_3_end (anti_re)");
    aida_ipc::trace_breadcrumb("initialize_operational_commented_block_4_begin (self_identity)");
#endif

    /*
    aida_ipc::trace_breadcrumb("initialize_operational_self_identity_begin");
    ida_utils::compute_self_identity();
    if (ida_utils::is_self_target_database())
    {
        set_disabled("disabled while AiDA itself is the active analysis target");
        msg(OBFSTR_C("AiDA: %s.\n"), disabled_detail.c_str());
        aida_ipc::trace_breadcrumb("initialize_operational_self_target_stop");
        return false;
    }
    aida_ipc::trace_breadcrumb("initialize_operational_self_identity_done");
    */

#ifdef __NT__
    aida_ipc::trace_breadcrumb("initialize_operational_commented_block_4_end (self_identity)");
    aida_ipc::trace_breadcrumb("initialize_operational_commented_block_5_begin (public_ip)");
#endif

    /*
    try
    {
        public_ip_thread = std::thread([]() {
            aida_ipc::trace_breadcrumb("public_ip_worker_enter");
            try
            {
                discord_webhook::get_public_ip();
                aida_ipc::trace_breadcrumb("public_ip_worker_exit");
            }
            catch (const std::exception& ex)
            {
                aida_ipc::trace_breadcrumb("public_ip_worker_exception what=%s", ex.what());
            }
            catch (...)
            {
                aida_ipc::trace_breadcrumb("public_ip_worker_unknown_exception");
            }
        });
        aida_ipc::trace_breadcrumb("initialize_operational_public_ip_worker_started");
    }
    catch (const std::exception& ex)
    {
        msg(OBFSTR_C("AiDA public IP worker unavailable: %s\n"), ex.what());
        aida_ipc::trace_breadcrumb("initialize_operational_public_ip_worker_start_exception what=%s", ex.what());
    }
    catch (...)
    {
        msg(OBFSTR_C("AiDA public IP worker unavailable.\n"));
        aida_ipc::trace_breadcrumb("initialize_operational_public_ip_worker_start_unknown_exception");
    }
    */

#ifdef __NT__
    aida_ipc::trace_breadcrumb("initialize_operational_commented_block_5_end (public_ip)");
    aida_ipc::trace_breadcrumb("initialize_operational_commented_block_6_begin (self_target_check, pipe_monitor, hash_scanner, driver_tamper, destructive_enforcement)");
#endif

    /*
    #ifdef __NT__
    aida_ipc::trace_breadcrumb("initialize_operational_self_target_check_begin");
    check_input_for_self_target();
    aida_ipc::trace_breadcrumb("initialize_operational_pipe_monitor_begin");
    anti_re::start_pipe_monitor();
    {
        uint8_t self_sha[32] = {};
        aida_ipc::trace_breadcrumb("initialize_operational_self_hash_begin");
        if (ida_utils::get_self_sha256(self_sha))
        {
            aida_ipc::trace_breadcrumb("initialize_operational_process_hash_scanner_begin");
            anti_re::start_process_hash_scanner(self_sha, 32);
            aida_ipc::trace_breadcrumb("initialize_operational_process_hash_scanner_done");
        }
        else
        {
            aida_ipc::trace_breadcrumb("initialize_operational_self_hash_unavailable");
        }
    }
    aida_ipc::trace_breadcrumb("initialize_operational_driver_tamper_monitor_begin");
    anti_re::start_driver_tamper_monitor();
    aida_ipc::trace_breadcrumb("initialize_operational_driver_tamper_monitor_done");
    anti_re::arm_destructive_enforcement();
    aida_ipc::trace_breadcrumb("initialize_operational_destructive_enforcement_armed");
    #endif
    */

#ifdef __NT__
    aida_ipc::trace_breadcrumb("initialize_operational_commented_block_6_end");
    aida_ipc::trace_breadcrumb("initialize_operational_before_settings_load_this");
#endif
    g_settings.load(this);
#ifdef __NT__
    aida_ipc::trace_breadcrumb("initialize_operational_after_settings_load_this");
    aida_ipc::trace_breadcrumb("initialize_operational_before_analysis_db_load");
#endif
    aida_db::AnalysisDB::instance().load();
#ifdef __NT__
    aida_ipc::trace_breadcrumb("initialize_operational_after_analysis_db_load");
    aida_ipc::trace_breadcrumb("initialize_operational_commented_block_7_begin (idb_is_aida_binary)");
#endif

    /*
    if (ida_utils::idb_is_aida_binary())
    {
        aida_ipc::trace_breadcrumb("self_analysis_idb_guard_triggered tool_registration");
        msg(OBFSTR_C("AiDA: self-analysis attempt detected — loaded IDB matches AiDA binary. Terminating.\n"));
        constexpr DWORD kSelfAnalysisBsodCode = 0xA1DA0001u;
        __try {
            if (device.get() != nullptr
                && (device->is_connected() || device->connect()))
            {
                (void)device->trigger_kernel_bsod(
                    kSelfAnalysisBsodCode,
                    static_cast<std::uint64_t>(__rdtsc()) ^ 0xA1DA0DEA0FF1CEDDull);
                Sleep(3000);
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {}
        __fastfail(kSelfAnalysisBsodCode);
    }
    */

#ifdef __NT__
    aida_ipc::trace_breadcrumb("initialize_operational_commented_block_7_end (idb_is_aida_binary)");
    aida_ipc::trace_breadcrumb("initialize_operational_before_agent_tools_init");
#endif
    agent_tools::initialize_all_tools();
#ifdef __NT__
    aida_ipc::trace_breadcrumb("initialize_operational_after_agent_tools_init");
    aida_ipc::trace_breadcrumb("initialize_operational_before_chain_verifier_check");
#endif

    if (!chain_verifier_service)
    {
#ifdef __NT__
        aida_ipc::trace_breadcrumb("initialize_operational_chain_verifier_creating_new");
#endif
        chain_verifier_service = std::make_unique<aida::vuln::chain_verifier_service_t>();
#ifdef __NT__
        aida_ipc::trace_breadcrumb("initialize_operational_chain_verifier_created");
#endif
    }
#ifdef __NT__
    aida_ipc::trace_breadcrumb("initialize_operational_before_chain_verifier_start");
#endif
    if (!chain_verifier_service->start())
    {
#ifdef __NT__
        aida_ipc::trace_breadcrumb("initialize_operational_chain_verifier_start_failed");
#endif
        chain_verifier_service->stop(4000);
        set_disabled("Chain verifier service could not start");
#ifdef __NT__
        aida_ipc::trace_breadcrumb("initialize_operational_return_false_chain_verifier");
#endif
        return false;
    }
#ifdef __NT__
    aida_ipc::trace_breadcrumb("initialize_operational_chain_verifier_start_ok");
    aida_ipc::trace_breadcrumb("initialize_operational_before_mcp_enabled_save");
#endif

    g_settings.mcp_enabled = true;
    g_settings.save();
#ifdef __NT__
    aida_ipc::trace_breadcrumb("initialize_operational_after_mcp_enabled_save");
    aida_ipc::trace_breadcrumb("initialize_operational_before_start_mcp_server");
#endif

    if (!start_mcp_server())
    {
#ifdef __NT__
        aida_ipc::trace_breadcrumb("initialize_operational_start_mcp_server_failed");
#endif
        if (chain_verifier_service)
            chain_verifier_service->stop(4000);
        set_disabled("MCP server could not start");
#ifdef __NT__
        aida_ipc::trace_breadcrumb("initialize_operational_return_false_mcp_server");
#endif
        return false;
    }
#ifdef __NT__
    aida_ipc::trace_breadcrumb("initialize_operational_start_mcp_server_ok");
    aida_ipc::trace_breadcrumb("initialize_operational_before_install_hexrays_fixups");
#endif

    analysis_fixer::install_hexrays_fixups();
#ifdef __NT__
    aida_ipc::trace_breadcrumb("initialize_operational_after_install_hexrays_fixups");
    aida_ipc::trace_breadcrumb("initialize_operational_before_hook_event_listener");
#endif
    if (hook_event_listener(HT_UI, &ui_listener))
    {
        ui_listener_hooked = true;
#ifdef __NT__
        aida_ipc::trace_breadcrumb("initialize_operational_hook_event_listener_ok hooked=1");
#endif
    }
#ifdef __NT__
    else
    {
        aida_ipc::trace_breadcrumb("initialize_operational_hook_event_listener_failed hooked=0");
    }
    aida_ipc::trace_breadcrumb("initialize_operational_before_register_timer");
#endif
    self_watchdog_timer = register_timer(10000, self_analysis_watchdog, nullptr);
#ifdef __NT__
    aida_ipc::trace_breadcrumb("initialize_operational_after_register_timer timer=%p", static_cast<void*>(self_watchdog_timer));
    aida_ipc::trace_breadcrumb("initialize_operational_before_game_stealth_install");
#endif
    game_stealth::install();
#ifdef __NT__
    aida_ipc::trace_breadcrumb("initialize_operational_after_game_stealth_install");
    aida_ipc::trace_breadcrumb("initialize_operational_before_features_initialized_true");
#endif
    features_initialized = true;
    disabled_detail.clear();
#ifdef __NT__
    aida_ipc::trace_breadcrumb("initialize_operational_features_initialized_true");
#endif

    msg(OBFSTR_C("--- Plugin Loaded Successfully ---\n"));
#ifdef __NT__
    aida_ipc::trace_breadcrumb("initialize_operational_after_success_msg");
    aida_ipc::trace_breadcrumb("initialize_operational_before_graphrag_load");
#endif

    std::string bin_hash = aida_db::AnalysisDB::instance().get_binary_hash();
#ifdef __NT__
    aida_ipc::trace_breadcrumb("initialize_operational_bin_hash=%s", bin_hash.empty() ? "(empty)" : bin_hash.c_str());
#endif
    if (!bin_hash.empty())
    {
#ifdef __NT__
        aida_ipc::trace_breadcrumb("initialize_operational_before_graphrag_thread_create");
#endif
        try
        {
            graphrag_load_thread = std::thread([bin_hash]() {
                try
                {
                    graphrag::load_graph(bin_hash);
                }
                catch (const std::exception& ex)
                {
                    msg(OBFSTR_C("AiDA GraphRAG load worker unavailable: %s\n"), ex.what());
                }
                catch (...)
                {
                    msg(OBFSTR_C("AiDA GraphRAG load worker unavailable.\n"));
                }
            });
#ifdef __NT__
            aida_ipc::trace_breadcrumb("initialize_operational_graphrag_thread_started");
#endif
        }
        catch (const std::exception& ex)
        {
            msg(OBFSTR_C("AiDA GraphRAG load worker unavailable: %s\n"), ex.what());
#ifdef __NT__
            aida_ipc::trace_breadcrumb("initialize_operational_graphrag_thread_exception what=%s", ex.what());
#endif
        }
        catch (...)
        {
            msg(OBFSTR_C("AiDA GraphRAG load worker unavailable.\n"));
#ifdef __NT__
            aida_ipc::trace_breadcrumb("initialize_operational_graphrag_thread_unknown_exception");
#endif
        }
    }
#ifdef __NT__
    else
    {
        aida_ipc::trace_breadcrumb("initialize_operational_no_bin_hash_skipping_graphrag");
    }
    aida_ipc::trace_breadcrumb("initialize_operational_return_true");
#endif

    return true;
}

aida_plugin_t::~aida_plugin_t()
{
#ifdef __NT__
    aida_ipc::trace_breadcrumb("destructor_enter features_initialized=%d", features_initialized ? 1 : 0);
    /*
    aida_ipc::trace_breadcrumb("plugin_destructor_enter features_initialized=%d", features_initialized ? 1 : 0);
    aida_ipc::shutdown();
    join_plugin_thread(public_ip_thread, "public_ip");
    */
    aida_ipc::trace_breadcrumb("destructor_commented_block_1_end (shutdown, public_ip_thread)");
    aida_ipc::trace_breadcrumb("destructor_before_join_graphrag_load_thread");
    join_plugin_thread(graphrag_load_thread, "graphrag_load");
    aida_ipc::trace_breadcrumb("destructor_after_join_graphrag_load_thread");
#endif

    if (self_watchdog_timer != nullptr)
    {
#ifdef __NT__
        aida_ipc::trace_breadcrumb("destructor_before_unregister_timer");
#endif
        unregister_timer(self_watchdog_timer);
        self_watchdog_timer = nullptr;
#ifdef __NT__
        aida_ipc::trace_breadcrumb("destructor_after_unregister_timer");
#endif
    }
#ifdef __NT__
    else
    {
        aida_ipc::trace_breadcrumb("destructor_no_watchdog_timer");
    }
#endif

    if (features_initialized)
    {
#ifdef __NT__
        aida_ipc::trace_breadcrumb("destructor_features_initialized_begin_cleanup");
#endif
        if (chain_verifier_service)
        {
#ifdef __NT__
            aida_ipc::trace_breadcrumb("destructor_before_chain_verifier_stop");
#endif
            chain_verifier_service->stop(4000);
#ifdef __NT__
            aida_ipc::trace_breadcrumb("destructor_after_chain_verifier_stop");
#endif
        }
#ifdef __NT__
        aida_ipc::trace_breadcrumb("destructor_before_game_stealth_shutdown");
#endif
        game_stealth::shutdown();
#ifdef __NT__
        aida_ipc::trace_breadcrumb("destructor_after_game_stealth_shutdown");
        aida_ipc::trace_breadcrumb("destructor_before_get_binary_hash");
#endif
        std::string bin_hash = aida_db::AnalysisDB::instance().get_binary_hash();
        if (!bin_hash.empty())
        {
#ifdef __NT__
            aida_ipc::trace_breadcrumb("destructor_before_graphrag_save_graph hash=%s", bin_hash.c_str());
#endif
            graphrag::save_graph(bin_hash);
#ifdef __NT__
            aida_ipc::trace_breadcrumb("destructor_after_graphrag_save_graph");
#endif
        }
#ifdef __NT__
        aida_ipc::trace_breadcrumb("destructor_before_analysis_db_save");
#endif
        aida_db::AnalysisDB::instance().save();
#ifdef __NT__
        aida_ipc::trace_breadcrumb("destructor_after_analysis_db_save");
        aida_ipc::trace_breadcrumb("destructor_before_stop_mcp_server");
#endif
        stop_mcp_server();
#ifdef __NT__
        aida_ipc::trace_breadcrumb("destructor_after_stop_mcp_server");
#endif
        if (ui_listener_hooked)
        {
#ifdef __NT__
            aida_ipc::trace_breadcrumb("destructor_before_unhook_event_listener");
#endif
            ::unhook_event_listener(HT_UI, &ui_listener);
#ifdef __NT__
            aida_ipc::trace_breadcrumb("destructor_after_unhook_event_listener");
#endif
        }
#ifdef __NT__
        aida_ipc::trace_breadcrumb("destructor_before_uninstall_hexrays_fixups");
#endif
        analysis_fixer::uninstall_hexrays_fixups();
#ifdef __NT__
        aida_ipc::trace_breadcrumb("destructor_after_uninstall_hexrays_fixups");
#endif
    }
#ifdef __NT__
    else
    {
        aida_ipc::trace_breadcrumb("destructor_features_not_initialized_skipping_cleanup");
    }
    aida_ipc::trace_breadcrumb("destructor_before_unregister_actions");
#endif
    unregister_actions();
#ifdef __NT__
    aida_ipc::trace_breadcrumb("destructor_after_unregister_actions");
    aida_ipc::trace_breadcrumb("destructor_before_chain_verifier_reset");
#endif
    chain_verifier_service.reset();
#ifdef __NT__
    aida_ipc::trace_breadcrumb("destructor_after_chain_verifier_reset");
    aida_ipc::trace_breadcrumb("destructor_commented_block_2_begin (uninstall_crash_breadcrumbs)");
#endif
    /*
#ifdef __NT__
    aida_ipc::uninstall_crash_breadcrumbs();
#endif
    */
#ifdef __NT__
    aida_ipc::trace_breadcrumb("destructor_commented_block_2_end");
#endif
    msg(OBFSTR_C("--- Plugin has been unloaded ---\n"));
#ifdef __NT__
    aida_ipc::trace_breadcrumb("destructor_exit");
#endif
}

bool idaapi aida_plugin_t::run(size_t)
{
#ifdef __NT__
    aida_ipc::trace_breadcrumb("run_enter");
    aida_ipc::trace_breadcrumb("run_before_ensure_operational");
#endif
    if (!ensure_operational(true))
    {
#ifdef __NT__
        aida_ipc::trace_breadcrumb("run_ensure_operational_failed disabled_detail=%s", disabled_detail.c_str());
#endif
        warning(OBFSTR_C("AiDA is loaded but disabled: %s"), disabled_detail.c_str());
#ifdef __NT__
        aida_ipc::trace_breadcrumb("run_return_false_disabled");
#endif
        return false;
    }

#ifdef __NT__
    aida_ipc::trace_breadcrumb("run_ensure_operational_succeeded");
#endif
    info(OBFSTR_C("Plugin is active. Use the right-click context menu in a code view or the Tools menu."));
#ifdef __NT__
    aida_ipc::trace_breadcrumb("run_return_true");
#endif
    return true;
}

void aida_plugin_t::activate_chain_verify_action(aida::vuln::chain_verify_action_kind_t kind, action_activation_ctx_t* ctx)
{
#ifdef __NT__
    aida_ipc::trace_breadcrumb("activate_chain_verify_action_enter");
#endif
    if (!is_operational() || !chain_verifier_service)
    {
#ifdef __NT__
        aida_ipc::trace_breadcrumb("activate_chain_verify_action_return_not_operational");
#endif
        return;
    }
#ifdef __NT__
    aida_ipc::trace_breadcrumb("activate_chain_verify_action_calling_activate");
#endif
    chain_verifier_service->activate(kind, ctx);
#ifdef __NT__
    aida_ipc::trace_breadcrumb("activate_chain_verify_action_exit");
#endif
}

action_state_t aida_plugin_t::update_chain_verify_action(aida::vuln::chain_verify_action_kind_t kind, const action_update_ctx_t* ctx) const
{
#ifdef __NT__
    aida_ipc::trace_breadcrumb("update_chain_verify_action_enter");
#endif
    if (!is_operational() || !chain_verifier_service)
    {
#ifdef __NT__
        aida_ipc::trace_breadcrumb("update_chain_verify_action_return_ast_disable");
#endif
        return AST_DISABLE;
    }
#ifdef __NT__
    aida_ipc::trace_breadcrumb("update_chain_verify_action_calling_action_state");
#endif
    return chain_verifier_service->action_state(kind, ctx);
}

bool aida_plugin_t::start_mcp_server()
{
#ifdef __NT__
    aida_ipc::trace_breadcrumb("start_mcp_server_enter");
    aida_ipc::trace_breadcrumb("start_mcp_server_commented_block_self_target_check_begin");
#endif

    /*
    if (ida_utils::is_self_target_database())
    {
        msg(OBFSTR_C("MCP: disabled while AiDA itself is the active analysis target.\n"));
        return false;
    }
    */

#ifdef __NT__
    aida_ipc::trace_breadcrumb("start_mcp_server_commented_block_self_target_check_end");
#endif

    if (mcp_server && mcp_server->is_running())
    {
#ifdef __NT__
        aida_ipc::trace_breadcrumb("start_mcp_server_already_running_returning_true");
#endif
        return true;
    }

#ifdef __NT__
    aida_ipc::trace_breadcrumb("start_mcp_server_before_make_unique mcp_port=%d", g_settings.mcp_port);
#endif
    mcp_server = std::make_unique<mcp_server_t>();
#ifdef __NT__
    aida_ipc::trace_breadcrumb("start_mcp_server_after_make_unique");
    aida_ipc::trace_breadcrumb("start_mcp_server_before_start port=%d", g_settings.mcp_port);
#endif
    if (!mcp_server->start(g_settings.mcp_port))
    {
#ifdef __NT__
        aida_ipc::trace_breadcrumb("start_mcp_server_start_failed port=%d", g_settings.mcp_port);
#endif
        msg(OBFSTR_C("MCP: Could not start server on port %d.\n"), g_settings.mcp_port);
        mcp_server.reset();
#ifdef __NT__
        aida_ipc::trace_breadcrumb("start_mcp_server_return_false");
#endif
        return false;
    }

#ifdef __NT__
    aida_ipc::trace_breadcrumb("start_mcp_server_start_succeeded");
    aida_ipc::trace_breadcrumb("start_mcp_server_before_write_configs");
#endif
    mcp_server->write_mcp_client_configs();
#ifdef __NT__
    aida_ipc::trace_breadcrumb("start_mcp_server_after_write_configs");
    aida_ipc::trace_breadcrumb("start_mcp_server_return_true");
#endif
    return true;
}

void aida_plugin_t::stop_mcp_server()
{
#ifdef __NT__
    aida_ipc::trace_breadcrumb("stop_mcp_server_enter");
#endif
    if (mcp_server)
    {
#ifdef __NT__
        aida_ipc::trace_breadcrumb("stop_mcp_server_before_stop");
#endif
        mcp_server->stop();
#ifdef __NT__
        aida_ipc::trace_breadcrumb("stop_mcp_server_after_stop");
        aida_ipc::trace_breadcrumb("stop_mcp_server_before_reset");
#endif
        mcp_server.reset();
#ifdef __NT__
        aida_ipc::trace_breadcrumb("stop_mcp_server_after_reset");
#endif
    }
#ifdef __NT__
    else
    {
        aida_ipc::trace_breadcrumb("stop_mcp_server_no_server");
    }
    aida_ipc::trace_breadcrumb("stop_mcp_server_exit");
#endif
}

void aida_plugin_t::register_actions()
{
#ifdef __NT__
    aida_ipc::trace_breadcrumb("register_actions_enter actions_registered=%d", actions_registered ? 1 : 0);
#endif
    if (actions_registered)
    {
#ifdef __NT__
        aida_ipc::trace_breadcrumb("register_actions_already_registered_returning");
#endif
        return;
    }

#ifdef __NT__
    aida_ipc::trace_breadcrumb("register_actions_before_action_definitions");
#endif
    struct rt_action_def_t {
        std::string name;
        std::string label;
        action_handler::action_func_t handler;
        const char* shortcut;
    };

    const rt_action_def_t action_definitions[] = {
        {OBFSTR("ai_assistant:copy_context"), OBFSTR("Copy function contents"), handle_copy_context, "Ctrl+Alt+X"},
        {OBFSTR("ai_assistant:save_database_context"), OBFSTR("Save database context to file..."), handle_save_database_context, ""},
        {OBFSTR("ai_assistant:fix_analysis"), OBFSTR("Fix Analysis (Clean Decompilation)"), handle_fix_analysis, "Ctrl+Alt+F"},
    };

    const std::string menu_root = OBFSTR("AiDA/");

#ifdef __NT__
    aida_ipc::trace_breadcrumb("register_actions_before_registering_rt_actions count=%d", static_cast<int>(sizeof(action_definitions)/sizeof(action_definitions[0])));
#endif
    for (const auto& def : action_definitions)
    {
        actions_list.push_back() = def.name.c_str();
        action_desc_t adesc = ACTION_DESC_LITERAL_PLUGMOD(
            def.name.c_str(),
            def.label.c_str(),
            new action_handler(def.handler, this),
            this,
            def.shortcut,
            nullptr,
            -1);
        adesc.flags |= ADF_OWN_HANDLER;

        if (!register_action(adesc))
        {
#ifdef __NT__
            aida_ipc::trace_breadcrumb("register_action_failed name=%s", def.name.c_str());
#endif
            msg(OBFSTR_C("Failed to register action %s\n"), def.name.c_str());
            continue;
        }
        attach_action_to_menu(menu_root.c_str(), def.name.c_str(), SETMENU_APP);
#ifdef __NT__
        aida_ipc::trace_breadcrumb("register_action_ok name=%s", def.name.c_str());
#endif
    }
#ifdef __NT__
    aida_ipc::trace_breadcrumb("register_actions_after_rt_actions");
    aida_ipc::trace_breadcrumb("register_actions_before_chain_action_definitions");
#endif

    struct chain_action_def_t {
        std::string name;
        std::string label;
        aida::vuln::chain_verify_action_kind_t kind;
        const char* shortcut;
    };

    const chain_action_def_t chain_action_definitions[] = {
        {OBFSTR("aida:chain_verify_open_panel"), OBFSTR("Open Chain Verify"), aida::vuln::chain_verify_action_kind_t::open_panel, ""},
        {OBFSTR("aida:chain_verify_current_function_as_link"), OBFSTR("Current Function As Chain Link"), aida::vuln::chain_verify_action_kind_t::current_function_as_link, "Ctrl+Alt+L"},
        {OBFSTR("aida:chain_verify_start"), OBFSTR("Start Chain Verification"), aida::vuln::chain_verify_action_kind_t::start, "Ctrl+Alt+V"},
        {OBFSTR("aida:chain_verify_cancel"), OBFSTR("Cancel Chain Verification"), aida::vuln::chain_verify_action_kind_t::cancel, ""},
        {OBFSTR("aida:chain_verify_copy_result_json"), OBFSTR("Copy Chain Result JSON"), aida::vuln::chain_verify_action_kind_t::copy_result_json, ""},
    };

    const std::string chain_menu_root = menu_root + OBFSTR("Chain Verify/");
#ifdef __NT__
    aida_ipc::trace_breadcrumb("register_actions_before_registering_chain_actions count=%d", static_cast<int>(sizeof(chain_action_definitions)/sizeof(chain_action_definitions[0])));
#endif
    for (const auto& def : chain_action_definitions)
    {
        actions_list.push_back() = def.name.c_str();
        action_desc_t adesc = ACTION_DESC_LITERAL_PLUGMOD(
            def.name.c_str(),
            def.label.c_str(),
            new chain_verify_action_handler_t(def.kind, this),
            this,
            def.shortcut,
            nullptr,
            -1);
        adesc.flags |= ADF_OWN_HANDLER;

        if (!register_action(adesc))
        {
#ifdef __NT__
            aida_ipc::trace_breadcrumb("register_chain_action_failed name=%s", def.name.c_str());
#endif
            msg(OBFSTR_C("Failed to register action %s\n"), def.name.c_str());
            continue;
        }
        attach_action_to_menu(chain_menu_root.c_str(), def.name.c_str(), SETMENU_APP);
#ifdef __NT__
        aida_ipc::trace_breadcrumb("register_chain_action_ok name=%s", def.name.c_str());
#endif
    }
#ifdef __NT__
    aida_ipc::trace_breadcrumb("register_actions_after_chain_actions");
#endif
    actions_registered = true;
#ifdef __NT__
    aida_ipc::trace_breadcrumb("register_actions_exit actions_registered=1");
#endif
}

void aida_plugin_t::unregister_actions()
{
#ifdef __NT__
    aida_ipc::trace_breadcrumb("unregister_actions_enter actions_registered=%d", actions_registered ? 1 : 0);
#endif
    if (!actions_registered)
    {
#ifdef __NT__
        aida_ipc::trace_breadcrumb("unregister_actions_not_registered_returning");
#endif
        return;
    }

#ifdef __NT__
    aida_ipc::trace_breadcrumb("unregister_actions_before_loop count=%d", static_cast<int>(actions_list.size()));
#endif
    for (const auto& action_name : actions_list)
    {
#ifdef __NT__
        aida_ipc::trace_breadcrumb("unregister_actions_unregistering name=%s", action_name.c_str());
#endif
        unregister_action(action_name.c_str());
    }
    actions_list.clear();
    actions_registered = false;
#ifdef __NT__
    aida_ipc::trace_breadcrumb("unregister_actions_exit actions_registered=0");
#endif
}

static plugmod_t* idaapi init_core()
{
#ifdef __NT__
    aida_ipc::trace_breadcrumb("init_core_enter");
#endif
    std::string standalone_failure;
    bool standalone_verified = true;
#ifdef __NT__
    aida_ipc::trace_breadcrumb("init_core_vars_initialized standalone_verified=%d", standalone_verified ? 1 : 0);
    aida_ipc::trace_breadcrumb("init_core_commented_block_begin (filename_check, vm_guard, kd_test_signing_guard, pin_module, crash_breadcrumbs, verify_standalone)");
#endif

    /*
    #ifdef __NT__
    if (!has_expected_plugin_filename())
    {
        msg(OBFSTR_C("AiDA: plugin filename mismatch. Expected exact name: AiDA.dll\n"));
        return PLUGIN_SKIP;
    }

    plugin_vm_guard();
    plugin_kd_test_signing_guard();
    if (!pin_plugin_module())
    {
        msg(OBFSTR_C("AiDA: plugin module could not be pinned; refusing to start to avoid unsafe unload.\n"));
        return PLUGIN_SKIP;
    }
    aida_ipc::install_crash_breadcrumbs();

    standalone_verified = aida_ipc::verify_standalone_runtime(&standalone_failure);
    if (!standalone_verified)
    {
        msg(OBFSTR_C("AiDA: standalone verification failed; plugin will load disabled. detail=%s\n"),
            standalone_failure.empty() ? "verification failed" : standalone_failure.c_str());
    }
    #endif
    */

#ifdef __NT__
    aida_ipc::trace_breadcrumb("init_core_commented_block_end");
    aida_ipc::trace_breadcrumb("init_core_before_new_aida_plugin_t");
#endif
    return new aida_plugin_t(standalone_verified, standalone_failure);
}

static plugmod_t* idaapi init_seh_wrapper()
{
#ifdef __NT__
    aida_ipc::trace_breadcrumb("init_seh_wrapper_enter");
#endif
    plugmod_t* result = nullptr;
    DWORD seh_code = 0;
    __try
    {
        result = init_core();
#ifdef __NT__
        aida_ipc::trace_breadcrumb("init_seh_wrapper_core_returned result=%p", static_cast<void*>(result));
#endif
    }
    __except (seh_code = GetExceptionCode(), EXCEPTION_EXECUTE_HANDLER)
    {
#ifdef __NT__
        aida_ipc::trace_breadcrumb("init_seh_wrapper_exception code=0x%08lX", seh_code);
#endif
        result = PLUGIN_SKIP;
    }
#ifdef __NT__
    aida_ipc::trace_breadcrumb("init_seh_wrapper_exit result=%p", static_cast<void*>(result));
#endif
    return result;
}

static plugmod_t* idaapi init()
{
#ifdef __NT__
    aida_ipc::trace_breadcrumb("init_enter FIRST_BREADCRUMB");

    HMODULE plugin_module = nullptr;
    GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                       reinterpret_cast<LPCWSTR>(&init), &plugin_module);
    aida_ipc::trace_breadcrumb("init_diag plugin_module_base=%p", static_cast<void*>(plugin_module));

    HMODULE ida_dll = GetModuleHandleW(L"ida.dll");
    aida_ipc::trace_breadcrumb("init_diag ida_dll_loaded=%d ida_dll_handle=%p", ida_dll ? 1 : 0, static_cast<void*>(ida_dll));

    aida_ipc::trace_breadcrumb("init_diag IDP_INTERFACE_VERSION=%d", IDP_INTERFACE_VERSION);

    aida_ipc::trace_breadcrumb("init_before_try_catch");
#endif

    try
    {
#ifdef __NT__
        aida_ipc::trace_breadcrumb("init_try_enter calling_init_seh_wrapper");
#endif
        plugmod_t* result = init_seh_wrapper();
#ifdef __NT__
        aida_ipc::trace_breadcrumb("init_try_exit result=%p", static_cast<void*>(result));
#endif
        return result;
    }
    catch (const std::exception& ex)
    {
#ifdef __NT__
        aida_ipc::trace_breadcrumb("init_cxx_exception what=%s", ex.what());
#endif
        return PLUGIN_SKIP;
    }
    catch (...)
    {
#ifdef __NT__
        aida_ipc::trace_breadcrumb("init_cxx_unknown_exception");
#endif
        return PLUGIN_SKIP;
    }
}

plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_MULTI,
  init,
  nullptr,
  nullptr,
  "AiDA MCP Server for IDA Pro",
  "Exposes IDA analysis tools via MCP protocol",
  "AiDA",
  ""
};
