#pragma once

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <thread>

#include <nlohmann/json.hpp>

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
        std::string session_dir;
        std::string wsb_path;
    };

    namespace detail
    {
        inline std::wstring windows_sandbox_exe()
        {
            wchar_t system_root[MAX_PATH] = {};
            GetEnvironmentVariableW(L"SystemRoot", system_root, MAX_PATH);
            if (system_root[0] == 0)
                return {};
            std::filesystem::path path = std::filesystem::path(system_root) / L"System32" / L"WindowsSandbox.exe";
            if (!std::filesystem::exists(path))
                return {};
            return path.wstring();
        }

        inline std::wstring ps_quote(const std::wstring& text)
        {
            std::wstring result = L"'";
            for (wchar_t ch : text) {
                if (ch == L'\'')
                    result += L"''";
                else
                    result.push_back(ch);
            }
            result += L"'";
            return result;
        }

        inline std::string narrow(const std::wstring& text)
        {
            if (text.empty())
                return {};
            char buffer[4096] = {};
            WideCharToMultiByte(CP_UTF8, 0, text.c_str(), -1, buffer, sizeof(buffer), nullptr, nullptr);
            return buffer;
        }

        inline std::wstring read_text_file(const std::filesystem::path& path)
        {
            std::wifstream ifs(path);
            if (!ifs.is_open())
                return {};
            return std::wstring((std::istreambuf_iterator<wchar_t>(ifs)), std::istreambuf_iterator<wchar_t>());
        }

        inline std::string read_utf8_file(const std::filesystem::path& path)
        {
            std::ifstream ifs(path, std::ios::binary);
            if (!ifs.is_open())
                return {};
            return std::string((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
        }

        inline void copy_workspace(const std::filesystem::path& source_dir,
                                   const std::filesystem::path& target_dir)
        {
            std::error_code ec;
            std::filesystem::create_directories(target_dir, ec);
            if (!std::filesystem::exists(source_dir))
                return;

            for (const auto& entry : std::filesystem::recursive_directory_iterator(source_dir, ec)) {
                if (ec)
                    break;
                const auto relative = std::filesystem::relative(entry.path(), source_dir, ec);
                if (ec)
                    continue;
                const auto destination = target_dir / relative;
                if (entry.is_directory(ec)) {
                    std::filesystem::create_directories(destination, ec);
                    continue;
                }
                if (!entry.is_regular_file(ec))
                    continue;
                std::filesystem::create_directories(destination.parent_path(), ec);
                std::filesystem::copy_file(entry.path(), destination,
                                           std::filesystem::copy_options::overwrite_existing, ec);
            }
        }

        inline std::filesystem::path create_session_dir()
        {
            wchar_t temp_path[MAX_PATH] = {};
            GetTempPathW(MAX_PATH, temp_path);
            const auto tick = std::chrono::steady_clock::now().time_since_epoch().count();
            std::filesystem::path dir = std::filesystem::path(temp_path) / L"AiDAStandalone" / L"Sandbox"
                                      / std::to_wstring(GetCurrentProcessId())
                                      / std::to_wstring(static_cast<unsigned long long>(tick));
            std::filesystem::create_directories(dir);
            return dir;
        }

        inline void write_runner_script(const std::filesystem::path& script_path,
                                        const std::wstring& guest_root,
                                        const std::wstring& guest_exe,
                                        const std::wstring& guest_arguments,
                                        uint32_t timeout_ms,
                                        bool capture_stdout,
                                        bool capture_stderr)
        {
            std::wofstream ofs(script_path, std::ios::trunc);
            ofs << L"$ErrorActionPreference = 'Stop'\n";
            ofs << L"$guestRoot = " << ps_quote(guest_root) << L"\n";
            ofs << L"$exePath = " << ps_quote(guest_exe) << L"\n";
            ofs << L"$argLine = " << ps_quote(guest_arguments) << L"\n";
            ofs << L"$stdoutFile = Join-Path $guestRoot 'stdout.txt'\n";
            ofs << L"$stderrFile = Join-Path $guestRoot 'stderr.txt'\n";
            ofs << L"$metaFile = Join-Path $guestRoot 'metadata.json'\n";
            ofs << L"$workDir = Split-Path -Path $exePath -Parent\n";
            ofs << L"$sw = [System.Diagnostics.Stopwatch]::StartNew()\n";
            ofs << L"$timedOut = $false\n";
            ofs << L"$killed = $false\n";
            ofs << L"$exitCode = 0\n";
            ofs << L"$pidValue = 0\n";
            ofs << L"if (" << (capture_stdout ? L"$true" : L"$false") << L") { if (Test-Path $stdoutFile) { Remove-Item $stdoutFile -Force } }\n";
            ofs << L"if (" << (capture_stderr ? L"$true" : L"$false") << L") { if (Test-Path $stderrFile) { Remove-Item $stderrFile -Force } }\n";
            ofs << L"$proc = Start-Process -FilePath $exePath -ArgumentList $argLine -WorkingDirectory $workDir "
                   L"-PassThru -WindowStyle Hidden"
                << (capture_stdout ? L" -RedirectStandardOutput $stdoutFile" : L"")
                << (capture_stderr ? L" -RedirectStandardError $stderrFile" : L"")
                << L"\n";
            ofs << L"$pidValue = $proc.Id\n";
            ofs << L"if (-not $proc.WaitForExit(" << timeout_ms << L")) {\n";
            ofs << L"  $timedOut = $true\n";
            ofs << L"  Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue\n";
            ofs << L"  $killed = $true\n";
            ofs << L"  $proc.WaitForExit()\n";
            ofs << L"}\n";
            ofs << L"$sw.Stop()\n";
            ofs << L"if ($proc.HasExited) { $exitCode = $proc.ExitCode }\n";
            ofs << L"$meta = [ordered]@{\n";
            ofs << L"  success = $true\n";
            ofs << L"  exit_code = $exitCode\n";
            ofs << L"  pid = $pidValue\n";
            ofs << L"  timed_out = $timedOut\n";
            ofs << L"  killed = $killed\n";
            ofs << L"  elapsed_ms = [int]$sw.ElapsedMilliseconds\n";
            ofs << L"}\n";
            ofs << L"$meta | ConvertTo-Json -Depth 4 | Out-File -FilePath $metaFile -Encoding utf8\n";
        }

        inline void write_wsb(const std::filesystem::path& wsb_path,
                              const std::filesystem::path& session_dir,
                              bool allow_network)
        {
            std::wofstream ofs(wsb_path, std::ios::trunc);
            const std::wstring host = session_dir.wstring();
            const std::wstring guest_root = L"C:\\Users\\WDAGUtilityAccount\\Desktop\\AiDAWorkspace";
            ofs << L"<Configuration>\n";
            ofs << L"  <Networking>" << (allow_network ? L"Default" : L"Disable") << L"</Networking>\n";
            ofs << L"  <MappedFolders>\n";
            ofs << L"    <MappedFolder>\n";
            ofs << L"      <HostFolder>" << host << L"</HostFolder>\n";
            ofs << L"      <SandboxFolder>" << guest_root << L"</SandboxFolder>\n";
            ofs << L"      <ReadOnly>false</ReadOnly>\n";
            ofs << L"    </MappedFolder>\n";
            ofs << L"  </MappedFolders>\n";
            ofs << L"  <LogonCommand>\n";
            ofs << L"    <Command>powershell.exe -ExecutionPolicy Bypass -File "
                << guest_root << L"\\run.ps1</Command>\n";
            ofs << L"  </LogonCommand>\n";
            ofs << L"</Configuration>\n";
        }
    }

    inline result execute(const config& cfg)
    {
        result res;
        const auto sandbox_exe = detail::windows_sandbox_exe();
        if (sandbox_exe.empty()) {
            res.error = "Windows Sandbox is unavailable. Enable the Windows Sandbox feature first.";
            return res;
        }

        if (cfg.exe_path.empty()) {
            res.error = "No executable path specified.";
            return res;
        }

        const std::filesystem::path exe_path(cfg.exe_path);
        if (!std::filesystem::exists(exe_path)) {
            res.error = "Target executable does not exist.";
            return res;
        }

        const auto session_dir = detail::create_session_dir();
        const auto host_input_dir = session_dir / L"input";
        const auto host_wsb = session_dir / L"session.wsb";
        const auto host_script = session_dir / L"run.ps1";
        const auto host_meta = session_dir / L"metadata.json";
        const auto host_stdout = session_dir / L"stdout.txt";
        const auto host_stderr = session_dir / L"stderr.txt";

        const std::filesystem::path source_dir =
            (!cfg.working_dir.empty() && std::filesystem::exists(cfg.working_dir))
            ? std::filesystem::path(cfg.working_dir)
            : exe_path.parent_path();

        detail::copy_workspace(source_dir, host_input_dir);
        if (!std::filesystem::exists(host_input_dir / exe_path.filename())) {
            std::error_code ec;
            std::filesystem::copy_file(exe_path, host_input_dir / exe_path.filename(),
                                       std::filesystem::copy_options::overwrite_existing, ec);
        }

        const std::wstring guest_root = L"C:\\Users\\WDAGUtilityAccount\\Desktop\\AiDAWorkspace";
        const std::wstring guest_exe = guest_root + L"\\input\\" + exe_path.filename().wstring();
        detail::write_runner_script(host_script, guest_root, guest_exe, cfg.arguments,
                                    cfg.timeout_ms, cfg.capture_stdout, cfg.capture_stderr);
        detail::write_wsb(host_wsb, session_dir, cfg.allow_network);

        STARTUPINFOW si{};
        si.cb = sizeof(si);
        PROCESS_INFORMATION pi{};
        std::wstring cmd = L"\"" + sandbox_exe + L"\" \"" + host_wsb.wstring() + L"\"";
        const auto start_tick = GetTickCount();

        if (!CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
                            nullptr, session_dir.c_str(), &si, &pi)) {
            res.error = "Failed to launch Windows Sandbox.";
            return res;
        }

        CloseHandle(pi.hThread);
        res.pid = pi.dwProcessId;

        const uint32_t host_timeout = (std::max)(cfg.timeout_ms + 120000u, 180000u);
        while ((GetTickCount() - start_tick) < host_timeout) {
            if (std::filesystem::exists(host_meta))
                break;
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }

        if (!std::filesystem::exists(host_meta)) {
            res.timed_out = true;
            res.killed = true;
            TerminateProcess(pi.hProcess, 0xDEAD);
            CloseHandle(pi.hProcess);
            res.error = "Timed out waiting for Windows Sandbox to return execution metadata.";
            res.session_dir = detail::narrow(session_dir.wstring());
            res.wsb_path = detail::narrow(host_wsb.wstring());
            return res;
        }

        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);

        auto meta = nlohmann::json::parse(detail::read_utf8_file(host_meta), nullptr, false);
        if (meta.is_discarded() || !meta.is_object()) {
            res.error = "Sandbox metadata was unreadable.";
            res.session_dir = detail::narrow(session_dir.wstring());
            res.wsb_path = detail::narrow(host_wsb.wstring());
            return res;
        }

        res.success = meta.value("success", true);
        res.exit_code = meta.value("exit_code", 0u);
        res.timed_out = meta.value("timed_out", false);
        res.killed = meta.value("killed", false);
        res.elapsed_ms = meta.value("elapsed_ms", static_cast<uint32_t>(GetTickCount() - start_tick));
        res.stdout_data = cfg.capture_stdout ? detail::read_utf8_file(host_stdout) : std::string();
        res.stderr_data = cfg.capture_stderr ? detail::read_utf8_file(host_stderr) : std::string();
        res.session_dir = detail::narrow(session_dir.wstring());
        res.wsb_path = detail::narrow(host_wsb.wstring());
        return res;
    }
}
