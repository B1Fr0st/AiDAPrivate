#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <userenv.h>
#include <sddl.h>
#include <psapi.h>
#include <cstdint>
#include <string>
#include <vector>
#include <functional>
#include <memory>
#include <thread>
#include <atomic>
#include <mutex>
#pragma comment(lib, "userenv.lib")
#pragma comment(lib, "advapi32.lib")

namespace sandbox
{
    struct config
    {
        std::wstring exe_path;
        std::wstring arguments;
        std::wstring working_dir;
        uint32_t     timeout_ms = 30000;
        uint64_t     max_memory = 512ULL * 1024 * 1024;
        bool         capture_stdout = true;
        bool         capture_stderr = true;
        bool         use_appcontainer = true;
        bool         allow_network = false;
    };

    struct result
    {
        bool        success = false;
        uint32_t    exit_code = 0;
        uint32_t    pid = 0;
        std::string stdout_data;
        std::string stderr_data;
        std::string error;
        bool        timed_out = false;
        bool        killed = false;
        uint64_t    peak_memory_bytes = 0;
        uint32_t    elapsed_ms = 0;
    };

    struct handle_closer {
        void operator()(HANDLE h) {
            if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h);
        }
    };
    using safe_handle = std::unique_ptr<std::remove_pointer_t<HANDLE>, handle_closer>;

    inline safe_handle make_safe(HANDLE h) {
        return safe_handle((h == INVALID_HANDLE_VALUE) ? nullptr : h);
    }

    inline safe_handle create_sandbox_job(const config& cfg)
    {
        auto job = make_safe(CreateJobObjectW(nullptr, nullptr));
        if (!job) return {};

        JOBOBJECT_EXTENDED_LIMIT_INFORMATION ext = {};
        ext.BasicLimitInformation.LimitFlags =
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE |
            JOB_OBJECT_LIMIT_ACTIVE_PROCESS |
            JOB_OBJECT_LIMIT_PROCESS_MEMORY |
            JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;

        ext.BasicLimitInformation.ActiveProcessLimit = 1;
        ext.ProcessMemoryLimit = cfg.max_memory;

        if (cfg.timeout_ms > 0) {
            ext.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_JOB_TIME;

            ext.BasicLimitInformation.PerJobUserTimeLimit.QuadPart =
                static_cast<LONGLONG>(cfg.timeout_ms) * 10000LL;
        }

        SetInformationJobObject(job.get(), JobObjectExtendedLimitInformation,
                                &ext, sizeof(ext));


        JOBOBJECT_BASIC_UI_RESTRICTIONS ui = {};
        ui.UIRestrictionsClass =
            JOB_OBJECT_UILIMIT_DESKTOP |
            JOB_OBJECT_UILIMIT_DISPLAYSETTINGS |
            JOB_OBJECT_UILIMIT_EXITWINDOWS |
            JOB_OBJECT_UILIMIT_GLOBALATOMS |
            JOB_OBJECT_UILIMIT_HANDLES |
            JOB_OBJECT_UILIMIT_READCLIPBOARD |
            JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS |
            JOB_OBJECT_UILIMIT_WRITECLIPBOARD;

        SetInformationJobObject(job.get(), JobObjectBasicUIRestrictions,
                                &ui, sizeof(ui));

        return job;
    }


    inline safe_handle create_restricted_token()
    {
        safe_handle process_token;
        {
            HANDLE raw = nullptr;
            if (!OpenProcessToken(GetCurrentProcess(),
                                  TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY |
                                  TOKEN_QUERY | TOKEN_ADJUST_DEFAULT,
                                  &raw))
                return {};
            process_token = make_safe(raw);
        }


        SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
        PSID admin_sid = nullptr;
        AllocateAndInitializeSid(&nt, 2,
            SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
            0, 0, 0, 0, 0, 0, &admin_sid);

        SID_AND_ATTRIBUTES deny_sids[1] = {};
        DWORD deny_count = 0;
        if (admin_sid) {
            deny_sids[0].Sid = admin_sid;
            deny_sids[0].Attributes = 0;
            deny_count = 1;
        }


        static const wchar_t* priv_names[] = {
            SE_DEBUG_NAME, SE_TAKE_OWNERSHIP_NAME, SE_TCB_NAME,
            SE_LOAD_DRIVER_NAME, SE_BACKUP_NAME, SE_RESTORE_NAME,
            SE_SHUTDOWN_NAME, SE_SYSTEMTIME_NAME, SE_MANAGE_VOLUME_NAME,
            SE_IMPERSONATE_NAME, SE_CREATE_GLOBAL_NAME,
            SE_ASSIGNPRIMARYTOKEN_NAME, SE_INCREASE_QUOTA_NAME,
            SE_CREATE_TOKEN_NAME, SE_AUDIT_NAME, SE_SECURITY_NAME
        };

        std::vector<LUID_AND_ATTRIBUTES> privs_to_delete;
        for (auto name : priv_names) {
            LUID luid;
            if (LookupPrivilegeValueW(nullptr, name, &luid)) {
                privs_to_delete.push_back({luid, 0});
            }
        }

        HANDLE restricted_raw = nullptr;
        BOOL ok = CreateRestrictedToken(
            process_token.get(),
            DISABLE_MAX_PRIVILEGE,
            deny_count, deny_sids,
            static_cast<DWORD>(privs_to_delete.size()),
            privs_to_delete.data(),
            0, nullptr,
            &restricted_raw);

        if (admin_sid) FreeSid(admin_sid);
        if (!ok) return {};
        return make_safe(restricted_raw);
    }


    struct appcontainer_ctx
    {
        PSID  sid = nullptr;
        ~appcontainer_ctx() { if (sid) FreeSid(sid); }
    };

    inline bool setup_appcontainer(
        const config& cfg,
        appcontainer_ctx& ctx,
        SECURITY_CAPABILITIES& caps,
        std::vector<SID_AND_ATTRIBUTES>& cap_sids)
    {

        wchar_t name[128];
        swprintf_s(name, L"AiDA.Sandbox.%u.%llu",
                   GetCurrentProcessId(), GetTickCount64());


        DeleteAppContainerProfile(name);

        HRESULT hr = CreateAppContainerProfile(
            name, name, name, nullptr, 0, &ctx.sid);
        if (FAILED(hr)) return false;


        if (cfg.allow_network) {

            SID_IDENTIFIER_AUTHORITY app_auth = SECURITY_APP_PACKAGE_AUTHORITY;
            PSID net_sid = nullptr;
            AllocateAndInitializeSid(&app_auth, 2,
                SECURITY_CAPABILITY_BASE_RID,
                SECURITY_CAPABILITY_INTERNET_CLIENT,
                0, 0, 0, 0, 0, 0, &net_sid);
            if (net_sid) {
                cap_sids.push_back({net_sid, SE_GROUP_ENABLED});
            }
        }

        caps.AppContainerSid = ctx.sid;
        caps.Capabilities = cap_sids.empty() ? nullptr : cap_sids.data();
        caps.CapabilityCount = static_cast<DWORD>(cap_sids.size());

        return true;
    }


    inline std::string drain_pipe(HANDLE pipe)
    {
        std::string data;
        char buf[4096];
        DWORD read = 0;
        while (ReadFile(pipe, buf, sizeof(buf), &read, nullptr) && read > 0) {
            data.append(buf, read);
            if (data.size() > 16 * 1024 * 1024) break;
        }
        return data;
    }


    inline result execute(const config& cfg)
    {
        result res;

        if (cfg.exe_path.empty()) {
            res.error = "No executable path specified.";
            return res;
        }

        DWORD start_tick = GetTickCount();


        auto job = create_sandbox_job(cfg);
        if (!job) {
            res.error = "Failed to create sandbox job object.";
            return res;
        }


        auto token = create_restricted_token();
        if (!token) {
            res.error = "Failed to create restricted token.";
            return res;
        }


        SECURITY_ATTRIBUTES sa = {};
        sa.nLength = sizeof(sa);
        sa.bInheritHandle = TRUE;

        HANDLE stdout_rd = nullptr, stdout_wr = nullptr;
        HANDLE stderr_rd = nullptr, stderr_wr = nullptr;

        if (cfg.capture_stdout) CreatePipe(&stdout_rd, &stdout_wr, &sa, 0);
        if (cfg.capture_stderr) CreatePipe(&stderr_rd, &stderr_wr, &sa, 0);


        if (stdout_rd) SetHandleInformation(stdout_rd, HANDLE_FLAG_INHERIT, 0);
        if (stderr_rd) SetHandleInformation(stderr_rd, HANDLE_FLAG_INHERIT, 0);


        appcontainer_ctx ac_ctx;
        SECURITY_CAPABILITIES sec_caps = {};
        std::vector<SID_AND_ATTRIBUTES> cap_sids;
        bool using_appcontainer = false;

        SIZE_T attr_size = 0;
        LPPROC_THREAD_ATTRIBUTE_LIST attr_list = nullptr;

        if (cfg.use_appcontainer) {
            using_appcontainer = setup_appcontainer(cfg, ac_ctx, sec_caps, cap_sids);
        }

        if (using_appcontainer) {
            InitializeProcThreadAttributeList(nullptr, 1, 0, &attr_size);
            attr_list = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(
                GetProcessHeap(), 0, attr_size);
            if (attr_list) {
                InitializeProcThreadAttributeList(attr_list, 1, 0, &attr_size);
                UpdateProcThreadAttribute(attr_list, 0,
                    PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
                    &sec_caps, sizeof(sec_caps), nullptr, nullptr);
            }
        }


        STARTUPINFOEXW si = {};
        si.StartupInfo.cb = sizeof(si);
        si.lpAttributeList = attr_list;

        if (stdout_wr) si.StartupInfo.hStdOutput = stdout_wr;
        if (stderr_wr) si.StartupInfo.hStdError  = stderr_wr;
        if (stdout_wr || stderr_wr)
            si.StartupInfo.dwFlags |= STARTF_USESTDHANDLES;

        PROCESS_INFORMATION pi = {};

        std::wstring cmdline = L"\"" + cfg.exe_path + L"\"";
        if (!cfg.arguments.empty())
            cmdline += L" " + cfg.arguments;

        std::wstring workdir = cfg.working_dir;
        if (workdir.empty()) {
            wchar_t temp[MAX_PATH];
            GetTempPathW(MAX_PATH, temp);
            workdir = temp;
        }

        DWORD flags = CREATE_SUSPENDED | CREATE_NO_WINDOW |
                       EXTENDED_STARTUPINFO_PRESENT;

        BOOL created = CreateProcessAsUserW(
            token.get(),
            cfg.exe_path.c_str(),
            const_cast<LPWSTR>(cmdline.c_str()),
            nullptr, nullptr,
            TRUE,
            flags,
            nullptr,
            workdir.c_str(),
            &si.StartupInfo,
            &pi);


        if (stdout_wr) CloseHandle(stdout_wr);
        if (stderr_wr) CloseHandle(stderr_wr);

        if (attr_list) {
            DeleteProcThreadAttributeList(attr_list);
            HeapFree(GetProcessHeap(), 0, attr_list);
        }


        for (auto& cs : cap_sids)
            if (cs.Sid) FreeSid(cs.Sid);

        if (!created) {
            DWORD err = GetLastError();
            char buf[256];
            snprintf(buf, sizeof(buf),
                     "Failed to create sandboxed process (error %u).", err);
            res.error = buf;
            if (stdout_rd) CloseHandle(stdout_rd);
            if (stderr_rd) CloseHandle(stderr_rd);
            return res;
        }

        res.pid = pi.dwProcessId;


        AssignProcessToJobObject(job.get(), pi.hProcess);


        ResumeThread(pi.hThread);
        CloseHandle(pi.hThread);


        std::thread stdout_thread;
        std::thread stderr_thread;
        std::string captured_stdout, captured_stderr;

        if (stdout_rd) {
            stdout_thread = std::thread([&]() {
                captured_stdout = drain_pipe(stdout_rd);
            });
        }
        if (stderr_rd) {
            stderr_thread = std::thread([&]() {
                captured_stderr = drain_pipe(stderr_rd);
            });
        }


        DWORD wait_ms = (cfg.timeout_ms > 0) ? cfg.timeout_ms : INFINITE;
        DWORD wait_result = WaitForSingleObject(pi.hProcess, wait_ms);

        if (wait_result == WAIT_TIMEOUT) {
            res.timed_out = true;
            TerminateProcess(pi.hProcess, 0xDEAD);
            WaitForSingleObject(pi.hProcess, 5000);
            res.killed = true;
        }


        DWORD exit_code = 0;
        GetExitCodeProcess(pi.hProcess, &exit_code);
        res.exit_code = exit_code;


        PROCESS_MEMORY_COUNTERS_EX pmc = {};
        pmc.cb = sizeof(pmc);
        if (GetProcessMemoryInfo(pi.hProcess,
                (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc))) {
            res.peak_memory_bytes = pmc.PeakWorkingSetSize;
        }

        CloseHandle(pi.hProcess);


        if (stdout_thread.joinable()) stdout_thread.join();
        if (stderr_thread.joinable()) stderr_thread.join();

        if (stdout_rd) CloseHandle(stdout_rd);
        if (stderr_rd) CloseHandle(stderr_rd);

        res.stdout_data = std::move(captured_stdout);
        res.stderr_data = std::move(captured_stderr);
        res.elapsed_ms  = GetTickCount() - start_tick;
        res.success      = true;

        return res;
    }

}
