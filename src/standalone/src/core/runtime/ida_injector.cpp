#include "ida_injector.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>
#include <ntstatus.h>
#include <psapi.h>
#include <shlobj.h>
#include <commdlg.h>
#include <objbase.h>
#include <tlhelp32.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "../settings/standalone_settings.hpp"
#include "../helpers/diag_log.hpp"
#include "../helpers/win32_dialog.hpp"
#include "../infra/work_queue.hpp"
#include "standalone_driver.hpp"
#include "../../../../aida_manual_map_proof.hpp"
#include "../../../../aida_plugin_encrypted.h"

#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "Comdlg32.lib")
#pragma comment(lib, "Advapi32.lib")

#ifndef STATUS_AUTH_TAG_MISMATCH
#define STATUS_AUTH_TAG_MISMATCH ((NTSTATUS)0xC000A002L)
#endif

extern settings_sa_t g_sa_settings;

namespace
{
    using namespace aida_manual_map;

    constexpr DWORD kIdaUiReadyTimeoutMs       = 60000;
    constexpr DWORD kPipeServerAcceptTimeoutMs = 30000;
    constexpr DWORD kBootstrapTimeoutMs        = 30000;
    constexpr DWORD kKillFastFailCode          = 0xA1DAB1FFu;

    struct injector_session_t
    {
        DWORD ida_pid = 0;
        HANDLE ida_process = nullptr;
        HANDLE ida_thread = nullptr;
        std::vector<uint8_t> pipe_secret;
        std::vector<uint8_t> ai_session_key;
        std::string plan;
        uint64_t parent_pid = 0;
        uint64_t timestamp_unix = 0;
        uint64_t feature_epoch = 0;
        uint64_t runtime_nonce_seed = 0;
        uint64_t plan_id_hash = 0;
        std::atomic<bool> active{false};
        std::atomic<bool> handshake_completed{false};
        std::atomic<bool> shutdown_requested{false};
    };

    std::mutex g_session_mutex;
    std::unique_ptr<injector_session_t> g_session;

    void inject_log(const char* fmt, ...)
    {
        char buf[1024];
        va_list ap;
        va_start(ap, fmt);
        std::vsnprintf(buf, sizeof(buf), fmt, ap);
        va_end(ap);
        ::diag::log_tagged("ida_inject", buf);
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
        if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, nullptr, 0)))
            return false;
        if (!BCRYPT_SUCCESS(BCryptSetProperty(alg, BCRYPT_CHAINING_MODE,
                                               reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)),
                                               sizeof(BCRYPT_CHAIN_MODE_GCM), 0)))
        {
            BCryptCloseAlgorithmProvider(alg, 0);
            return false;
        }

        DWORD object_length = 0;
        DWORD got = 0;
        if (!BCRYPT_SUCCESS(BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH,
                                               reinterpret_cast<PUCHAR>(&object_length),
                                               sizeof(object_length), &got, 0))
            || got != sizeof(object_length) || object_length == 0)
        {
            BCryptCloseAlgorithmProvider(alg, 0);
            return false;
        }

        std::vector<unsigned char> key_object(object_length, 0);
        BCRYPT_KEY_HANDLE hkey = nullptr;
        NTSTATUS status = BCryptGenerateSymmetricKey(alg, &hkey,
                                                       key_object.data(), object_length,
                                                       const_cast<PUCHAR>(key), key_len, 0);
        if (!BCRYPT_SUCCESS(status))
        {
            BCryptCloseAlgorithmProvider(alg, 0);
            return false;
        }

        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info = {};
        BCRYPT_INIT_AUTH_MODE_INFO(info);
        info.pbNonce = const_cast<PUCHAR>(nonce);
        info.cbNonce = nonce_len;
        info.pbTag = const_cast<PUCHAR>(tag);
        info.cbTag = tag_len;

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

        if (!BCRYPT_SUCCESS(status) || out_len != plaintext_len)
        {
            SecureZeroMemory(plaintext, plaintext_len);
            return false;
        }
        return true;
    }

    bool decrypt_plugin_bytes(std::vector<uint8_t>& out)
    {
        out.assign(g_aida_plugin_plaintext_size, 0);
        if (g_aida_plugin_plaintext_size != g_aida_plugin_ciphertext_len)
            return false;
        return aes_gcm_decrypt(g_aida_plugin_ciphertext, g_aida_plugin_ciphertext_len,
                                g_aida_plugin_key, sizeof(g_aida_plugin_key),
                                g_aida_plugin_nonce, sizeof(g_aida_plugin_nonce),
                                g_aida_plugin_tag, sizeof(g_aida_plugin_tag),
                                out.data(), static_cast<unsigned long>(out.size()));
    }

    std::wstring widen(const std::string& s)
    {
        if (s.empty())
            return {};
        int sz = MultiByteToWideChar(CP_UTF8, 0, s.data(),
                                      static_cast<int>(s.size()),
                                      nullptr, 0);
        if (sz <= 0)
            return {};
        std::wstring out(static_cast<size_t>(sz), L'\0');
        MultiByteToWideChar(CP_UTF8, 0, s.data(),
                             static_cast<int>(s.size()),
                             out.data(), sz);
        return out;
    }

    std::string narrow(const std::wstring& s)
    {
        if (s.empty())
            return {};
        int sz = WideCharToMultiByte(CP_UTF8, 0, s.data(),
                                       static_cast<int>(s.size()),
                                       nullptr, 0, nullptr, nullptr);
        if (sz <= 0)
            return {};
        std::string out(static_cast<size_t>(sz), '\0');
        WideCharToMultiByte(CP_UTF8, 0, s.data(),
                             static_cast<int>(s.size()),
                             out.data(), sz, nullptr, nullptr);
        return out;
    }

    std::string read_registry_string(HKEY root, const wchar_t* subkey, const wchar_t* value)
    {
        HKEY key = nullptr;
        if (RegOpenKeyExW(root, subkey, 0, KEY_READ | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS)
            return {};
        wchar_t buf[1024] = {};
        DWORD type = 0;
        DWORD bytes = sizeof(buf) - sizeof(wchar_t);
        std::string out;
        if (RegQueryValueExW(key, value, nullptr, &type,
                              reinterpret_cast<LPBYTE>(buf), &bytes) == ERROR_SUCCESS
            && (type == REG_SZ || type == REG_EXPAND_SZ))
        {
            buf[bytes / sizeof(wchar_t)] = L'\0';
            out = narrow(buf);
        }
        RegCloseKey(key);
        return out;
    }

    bool path_exists_file(const std::string& p)
    {
        if (p.empty())
            return false;
        std::error_code ec;
        return std::filesystem::is_regular_file(std::filesystem::path(widen(p)), ec);
    }

    std::string find_ida_in_dir(const std::filesystem::path& dir)
    {
        std::error_code ec;
        if (!std::filesystem::is_directory(dir, ec))
            return {};
        static const wchar_t* const exe_names[] = {
            L"ida64.exe",
            L"ida.exe",
            L"idat64.exe",
            L"idat.exe",
        };
        for (const wchar_t* name : exe_names)
        {
            auto candidate = dir / name;
            if (std::filesystem::is_regular_file(candidate, ec))
                return narrow(candidate.wstring());
        }
        return {};
    }

    std::string scan_program_files()
    {
        wchar_t* pf = nullptr;
        std::vector<std::filesystem::path> roots;
        if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_ProgramFiles, 0, nullptr, &pf)) && pf)
        {
            roots.emplace_back(pf);
            CoTaskMemFree(pf);
        }
        pf = nullptr;
        if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_ProgramFilesX86, 0, nullptr, &pf)) && pf)
        {
            roots.emplace_back(pf);
            CoTaskMemFree(pf);
        }

        const wchar_t* version_dirs[] = {
            L"IDA Professional 9.3", L"IDA Professional 9.2",
            L"IDA Professional 9.1", L"IDA Professional 9.0",
            L"IDA Pro 9.3", L"IDA Pro 9.2", L"IDA Pro 9.1", L"IDA Pro 9.0",
            L"IDA Pro 8.4", L"IDA Pro 8.3",
            L"IDA 9.3", L"IDA 9.2", L"IDA 9.1", L"IDA 9.0",
            L"IDA 8.4", L"IDA 8.3", L"IDA",
        };

        for (const auto& root : roots)
        {
            for (const wchar_t* sub : version_dirs)
            {
                auto candidate = find_ida_in_dir(root / sub);
                if (!candidate.empty())
                    return candidate;
            }
            std::error_code ec;
            for (auto& entry : std::filesystem::directory_iterator(root, ec))
            {
                if (!entry.is_directory(ec))
                    continue;
                auto name = entry.path().filename().wstring();
                if (_wcsnicmp(name.c_str(), L"IDA", 3) != 0)
                    continue;
                auto candidate = find_ida_in_dir(entry.path());
                if (!candidate.empty())
                    return candidate;
            }
        }
        return {};
    }

    std::string discover_via_registry()
    {
        const wchar_t* roots[] = {
            L"SOFTWARE\\Hex-Rays\\IDA",
            L"SOFTWARE\\Hex-Rays\\IDA Pro",
            L"SOFTWARE\\Hex-Rays\\IDA Professional",
        };
        for (HKEY hive : { HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE })
        {
            for (const wchar_t* sub : roots)
            {
                std::string p = read_registry_string(hive, sub, L"InstallDir");
                if (p.empty())
                    continue;
                std::filesystem::path root_dir(widen(p));
                std::string candidate = find_ida_in_dir(root_dir);
                if (!candidate.empty())
                    return candidate;
            }
        }
        return {};
    }

    std::string prompt_for_ida_exe(HWND owner)
    {
        char buf[MAX_PATH] = {};
        static const char k_ida_filter[] =
            "IDA executable\0ida.exe;ida64.exe;idat.exe;idat64.exe\0"
            "All files (*.*)\0*.*\0\0";
        if (!win32_dialog::show_open_file_dialog(owner,
                "Select ida.exe / ida64.exe",
                k_ida_filter,
                buf, sizeof(buf),
                "ida_injector::prompt_for_ida_exe")) {
            return {};
        }
        return std::string(buf);
    }

    void persist_ida_path(const std::string& path)
    {
        g_sa_settings.ida_pro_path = path;
        g_sa_settings.save();
    }
}

namespace ida_injector
{
    bool validate_ida_path(const std::string& path)
    {
        if (path.empty() || !path_exists_file(path))
            return false;
        auto wide = widen(path);
        const wchar_t* base = wide.c_str();
        for (const wchar_t* p = wide.c_str(); *p; ++p)
            if (*p == L'\\' || *p == L'/')
                base = p + 1;
        return _wcsicmp(base, L"ida64.exe") == 0
            || _wcsicmp(base, L"ida.exe")   == 0
            || _wcsicmp(base, L"idat64.exe") == 0
            || _wcsicmp(base, L"idat.exe")   == 0;
    }

    std::string discover_ida_path()
    {
        if (validate_ida_path(g_sa_settings.ida_pro_path))
            return g_sa_settings.ida_pro_path;
        std::string p = discover_via_registry();
        if (validate_ida_path(p))
            return p;
        p = scan_program_files();
        if (validate_ida_path(p))
            return p;
        return {};
    }
}

namespace
{
    struct prepared_image_t
    {
        std::vector<uint8_t> bytes;
        uint64_t local_base = 0;
        uint64_t remote_base = 0;
        uint32_t image_size = 0;
        uint32_t headers_size = 0;
        uint32_t exception_rva = 0;
        uint32_t exception_size = 0;
        uint32_t tls_callbacks_va = 0;
        struct section_t {
            uint32_t va;
            uint32_t size;
            DWORD    protect;
        };
        std::vector<section_t> sections;
    };

    bool parse_pe_headers(const uint8_t* buf, size_t size,
                          IMAGE_DOS_HEADER& dos_out,
                          IMAGE_NT_HEADERS64& nt_out)
    {
        if (size < sizeof(IMAGE_DOS_HEADER))
            return false;
        std::memcpy(&dos_out, buf, sizeof(dos_out));
        if (dos_out.e_magic != IMAGE_DOS_SIGNATURE)
            return false;
        if (static_cast<size_t>(dos_out.e_lfanew) + sizeof(IMAGE_NT_HEADERS64) > size)
            return false;
        std::memcpy(&nt_out, buf + dos_out.e_lfanew, sizeof(nt_out));
        if (nt_out.Signature != IMAGE_NT_SIGNATURE)
            return false;
        if (nt_out.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
            return false;
        if (nt_out.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
            return false;
        return true;
    }

    DWORD section_protect_from_chars(DWORD ch)
    {
        bool exec = (ch & IMAGE_SCN_MEM_EXECUTE) != 0;
        bool read = (ch & IMAGE_SCN_MEM_READ) != 0;
        bool write = (ch & IMAGE_SCN_MEM_WRITE) != 0;
        if (exec && read && write)  return PAGE_EXECUTE_READWRITE;
        if (exec && read)            return PAGE_EXECUTE_READ;
        if (exec && write)           return PAGE_EXECUTE_WRITECOPY;
        if (exec)                    return PAGE_EXECUTE;
        if (read && write)           return PAGE_READWRITE;
        if (read)                    return PAGE_READONLY;
        if (write)                   return PAGE_WRITECOPY;
        return PAGE_NOACCESS;
    }

    bool layout_image(const std::vector<uint8_t>& pe,
                      uint64_t remote_base,
                      prepared_image_t& out)
    {
        IMAGE_DOS_HEADER dos = {};
        IMAGE_NT_HEADERS64 nt = {};
        if (!parse_pe_headers(pe.data(), pe.size(), dos, nt))
            return false;

        out.image_size = nt.OptionalHeader.SizeOfImage;
        out.headers_size = nt.OptionalHeader.SizeOfHeaders;
        if (out.image_size == 0 || out.image_size > 256 * 1024 * 1024)
            return false;

        out.bytes.assign(out.image_size, 0);
        out.remote_base = remote_base;
        out.local_base = reinterpret_cast<uint64_t>(out.bytes.data());

        std::memcpy(out.bytes.data(), pe.data(), out.headers_size);

        const auto* file_header = &nt.FileHeader;
        const size_t section_table_off = dos.e_lfanew
            + sizeof(uint32_t)
            + sizeof(IMAGE_FILE_HEADER)
            + file_header->SizeOfOptionalHeader;

        if (section_table_off + file_header->NumberOfSections * sizeof(IMAGE_SECTION_HEADER) > pe.size())
            return false;

        const auto* sec = reinterpret_cast<const IMAGE_SECTION_HEADER*>(
            pe.data() + section_table_off);

        for (WORD i = 0; i < file_header->NumberOfSections; ++i)
        {
            uint32_t va = sec[i].VirtualAddress;
            uint32_t vs = sec[i].Misc.VirtualSize;
            uint32_t rs = sec[i].SizeOfRawData;
            uint32_t ro = sec[i].PointerToRawData;
            if (va + std::max(vs, rs) > out.image_size)
                return false;
            if (rs > 0)
            {
                if (static_cast<size_t>(ro) + rs > pe.size())
                    return false;
                std::memcpy(out.bytes.data() + va, pe.data() + ro, rs);
            }
            uint32_t section_size = vs ? vs : rs;
            prepared_image_t::section_t s{};
            s.va = va;
            s.size = section_size;
            s.protect = section_protect_from_chars(sec[i].Characteristics);
            out.sections.push_back(s);
        }
        out.exception_rva = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
        out.exception_size = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size;

        const auto& tls_dir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
        if (tls_dir.VirtualAddress && tls_dir.Size >= sizeof(IMAGE_TLS_DIRECTORY64))
        {
            IMAGE_TLS_DIRECTORY64 tls = {};
            std::memcpy(&tls, out.bytes.data() + tls_dir.VirtualAddress, sizeof(tls));
            out.tls_callbacks_va = static_cast<uint32_t>(tls.AddressOfCallBacks
                                                          ? tls.AddressOfCallBacks - nt.OptionalHeader.ImageBase
                                                          : 0);
        }
        return true;
    }

    bool apply_relocations_local(prepared_image_t& img)
    {
        IMAGE_DOS_HEADER dos = {};
        IMAGE_NT_HEADERS64 nt = {};
        if (!parse_pe_headers(img.bytes.data(), img.bytes.size(), dos, nt))
            return false;
        int64_t delta = static_cast<int64_t>(img.remote_base)
                       - static_cast<int64_t>(nt.OptionalHeader.ImageBase);
        if (delta == 0)
            return true;
        const auto& rd = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        uint32_t reloc_rva = rd.VirtualAddress;
        uint32_t reloc_size = rd.Size;
        if (reloc_rva == 0 || reloc_size == 0)
        {
            const auto* file_header = &nt.FileHeader;
            const size_t section_table_off = dos.e_lfanew + sizeof(uint32_t)
                + sizeof(IMAGE_FILE_HEADER) + file_header->SizeOfOptionalHeader;
            const auto* sect = reinterpret_cast<const IMAGE_SECTION_HEADER*>(
                img.bytes.data() + section_table_off);
            for (WORD i = 0; i < file_header->NumberOfSections; ++i)
            {
                char nm[9] = {};
                std::memcpy(nm, sect[i].Name, 8);
                if (std::strcmp(nm, ".reloc") == 0)
                {
                    reloc_rva = sect[i].VirtualAddress;
                    reloc_size = sect[i].Misc.VirtualSize
                                ? sect[i].Misc.VirtualSize : sect[i].SizeOfRawData;
                    break;
                }
            }
        }
        if (reloc_rva == 0 || reloc_size == 0)
            return false;

        uint8_t* base = img.bytes.data();
        auto* reloc = reinterpret_cast<IMAGE_BASE_RELOCATION*>(base + reloc_rva);
        auto* reloc_end = reinterpret_cast<IMAGE_BASE_RELOCATION*>(base + reloc_rva + reloc_size);
        while (reloc < reloc_end && reloc->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION))
        {
            uint32_t count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION))
                            / sizeof(uint16_t);
            auto* entries = reinterpret_cast<uint16_t*>(
                reinterpret_cast<uint8_t*>(reloc) + sizeof(IMAGE_BASE_RELOCATION));
            for (uint32_t i = 0; i < count; ++i)
            {
                uint16_t type = entries[i] >> 12;
                uint16_t off = entries[i] & 0xFFF;
                if (type == IMAGE_REL_BASED_ABSOLUTE)
                    continue;
                if (type == IMAGE_REL_BASED_DIR64)
                {
                    auto* p = reinterpret_cast<uint64_t*>(base + reloc->VirtualAddress + off);
                    *p = static_cast<uint64_t>(static_cast<int64_t>(*p) + delta);
                }
                else if (type == IMAGE_REL_BASED_HIGHLOW)
                {
                    auto* p = reinterpret_cast<uint32_t*>(base + reloc->VirtualAddress + off);
                    *p = static_cast<uint32_t>(static_cast<int64_t>(*p) + delta);
                }
                else
                {
                    return false;
                }
            }
            reloc = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
                reinterpret_cast<uint8_t*>(reloc) + reloc->SizeOfBlock);
        }
        return true;
    }

    struct on_disk_module_t
    {
        std::vector<uint8_t> bytes;
        IMAGE_DOS_HEADER dos = {};
        IMAGE_NT_HEADERS64 nt = {};
    };

    bool load_module_for_export_lookup(const std::wstring& path, on_disk_module_t& out)
    {
        std::ifstream f(path, std::ios::binary);
        if (!f.is_open())
            return false;
        f.seekg(0, std::ios::end);
        std::streamoff sz = f.tellg();
        if (sz <= 0 || sz > 256 * 1024 * 1024)
            return false;
        f.seekg(0, std::ios::beg);
        out.bytes.assign(static_cast<size_t>(sz), 0);
        f.read(reinterpret_cast<char*>(out.bytes.data()), sz);
        if (!f)
            return false;
        return parse_pe_headers(out.bytes.data(), out.bytes.size(), out.dos, out.nt);
    }

    uint32_t rva_to_file_off(const on_disk_module_t& m, uint32_t rva)
    {
        const auto* file_header = &m.nt.FileHeader;
        const size_t section_table_off = m.dos.e_lfanew
            + sizeof(uint32_t)
            + sizeof(IMAGE_FILE_HEADER)
            + file_header->SizeOfOptionalHeader;
        if (section_table_off + file_header->NumberOfSections * sizeof(IMAGE_SECTION_HEADER) > m.bytes.size())
            return 0;
        const auto* sec = reinterpret_cast<const IMAGE_SECTION_HEADER*>(
            m.bytes.data() + section_table_off);
        for (WORD i = 0; i < file_header->NumberOfSections; ++i)
        {
            uint32_t v_addr = sec[i].VirtualAddress;
            uint32_t v_size = sec[i].Misc.VirtualSize ? sec[i].Misc.VirtualSize : sec[i].SizeOfRawData;
            if (rva >= v_addr && rva < v_addr + v_size)
                return sec[i].PointerToRawData + (rva - v_addr);
        }
        return 0;
    }

    bool resolve_export_rva(const on_disk_module_t& m, const char* name, uint32_t ordinal,
                             uint32_t& out_rva)
    {
        const auto& ed = m.nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (ed.VirtualAddress == 0 || ed.Size == 0)
            return false;
        uint32_t exp_off = rva_to_file_off(m, ed.VirtualAddress);
        if (exp_off == 0 || exp_off + sizeof(IMAGE_EXPORT_DIRECTORY) > m.bytes.size())
            return false;
        IMAGE_EXPORT_DIRECTORY exp = {};
        std::memcpy(&exp, m.bytes.data() + exp_off, sizeof(exp));
        uint32_t funcs_off = rva_to_file_off(m, exp.AddressOfFunctions);
        if (funcs_off == 0)
            return false;

        if (!name)
        {
            uint32_t idx = ordinal - exp.Base;
            if (idx >= exp.NumberOfFunctions)
                return false;
            uint32_t rva = 0;
            std::memcpy(&rva, m.bytes.data() + funcs_off + idx * 4, 4);
            if (rva == 0)
                return false;
            out_rva = rva;
            return true;
        }

        uint32_t names_off = rva_to_file_off(m, exp.AddressOfNames);
        uint32_t ordinals_off = rva_to_file_off(m, exp.AddressOfNameOrdinals);
        if (names_off == 0 || ordinals_off == 0)
            return false;
        for (uint32_t i = 0; i < exp.NumberOfNames; ++i)
        {
            uint32_t name_rva = 0;
            std::memcpy(&name_rva, m.bytes.data() + names_off + i * 4, 4);
            uint32_t name_off = rva_to_file_off(m, name_rva);
            if (name_off == 0 || name_off >= m.bytes.size())
                continue;
            const char* exp_name = reinterpret_cast<const char*>(m.bytes.data() + name_off);
            size_t maxlen = m.bytes.size() - name_off;
            size_t cmp = 0;
            while (cmp < maxlen && exp_name[cmp] != '\0')
                ++cmp;
            if (cmp == maxlen)
                continue;
            if (std::strcmp(exp_name, name) != 0)
                continue;
            uint16_t ord_idx = 0;
            std::memcpy(&ord_idx, m.bytes.data() + ordinals_off + i * 2, 2);
            if (ord_idx >= exp.NumberOfFunctions)
                return false;
            uint32_t rva = 0;
            std::memcpy(&rva, m.bytes.data() + funcs_off + ord_idx * 4, 4);
            if (rva == 0)
                return false;
            if (rva >= ed.VirtualAddress && rva < ed.VirtualAddress + ed.Size)
                return false;
            out_rva = rva;
            return true;
        }
        return false;
    }

    struct remote_module_info_t
    {
        std::wstring path;
        uint64_t base = 0;
        on_disk_module_t parsed;
    };

    bool enumerate_remote_modules(HANDLE process,
                                   std::map<std::wstring, remote_module_info_t>& out)
    {
        std::vector<HMODULE> mods(1024);
        DWORD needed = 0;
        for (;;)
        {
            if (!EnumProcessModulesEx(process, mods.data(),
                                       static_cast<DWORD>(mods.size() * sizeof(HMODULE)),
                                       &needed, LIST_MODULES_64BIT))
                return false;
            if (needed <= mods.size() * sizeof(HMODULE))
                break;
            mods.resize(needed / sizeof(HMODULE) + 32);
        }
        size_t count = needed / sizeof(HMODULE);
        for (size_t i = 0; i < count; ++i)
        {
            wchar_t path[MAX_PATH] = {};
            if (GetModuleFileNameExW(process, mods[i], path, MAX_PATH) == 0)
                continue;
            const wchar_t* base = path;
            for (const wchar_t* p = path; *p; ++p)
                if (*p == L'\\' || *p == L'/')
                    base = p + 1;
            std::wstring lower(base);
            for (auto& ch : lower) ch = static_cast<wchar_t>(towlower(ch));
            remote_module_info_t info;
            info.path = path;
            info.base = reinterpret_cast<uint64_t>(mods[i]);
            out[lower] = std::move(info);
        }
        return true;
    }

    std::wstring underlying_basename_lower(HMODULE local)
    {
        wchar_t buf[MAX_PATH] = {};
        if (GetModuleFileNameW(local, buf, MAX_PATH) == 0)
            return {};
        const wchar_t* base = buf;
        for (const wchar_t* p = buf; *p; ++p)
            if (*p == L'\\' || *p == L'/')
                base = p + 1;
        std::wstring out(base);
        for (auto& c : out)
            c = static_cast<wchar_t>(towlower(c));
        return out;
    }

    bool find_remote_export_va(HANDLE process,
                                 const std::map<std::wstring, remote_module_info_t>& mods,
                                 const std::wstring& dll_lower,
                                 const char* func_name,
                                 uint64_t& out_va)
    {
        auto it = mods.find(dll_lower);
        if (it == mods.end())
            return false;
        on_disk_module_t parsed{};
        if (!load_module_for_export_lookup(it->second.path, parsed))
            return false;
        uint32_t rva = 0;
        if (!resolve_export_rva(parsed, func_name, 0, rva))
            return false;
        (void)process;
        out_va = it->second.base + rva;
        return true;
    }

    bool remote_load_library(HANDLE process,
                              uint64_t load_library_a_va,
                              const std::string& dll_name,
                              std::string& err)
    {
        size_t name_size = dll_name.size() + 1;
        LPVOID remote_name = VirtualAllocEx(process, nullptr, name_size,
                                              MEM_COMMIT | MEM_RESERVE,
                                              PAGE_READWRITE);
        if (!remote_name)
        {
            err = "VirtualAllocEx for module name failed";
            return false;
        }
        SIZE_T wrote = 0;
        if (!WriteProcessMemory(process, remote_name,
                                  dll_name.c_str(), name_size, &wrote)
            || wrote != name_size)
        {
            VirtualFreeEx(process, remote_name, 0, MEM_RELEASE);
            err = "WriteProcessMemory for module name failed";
            return false;
        }
        DWORD tid = 0;
        HANDLE th = CreateRemoteThread(process, nullptr, 0,
            reinterpret_cast<LPTHREAD_START_ROUTINE>(load_library_a_va),
            remote_name, 0, &tid);
        if (!th)
        {
            VirtualFreeEx(process, remote_name, 0, MEM_RELEASE);
            err = "CreateRemoteThread(LoadLibraryA) failed";
            return false;
        }
        DWORD wait = WaitForSingleObject(th, 15000);
        DWORD result = 0;
        GetExitCodeThread(th, &result);
        CloseHandle(th);
        VirtualFreeEx(process, remote_name, 0, MEM_RELEASE);
        if (wait != WAIT_OBJECT_0)
        {
            err = "remote LoadLibraryA timed out for " + dll_name;
            return false;
        }
        if (result == 0)
        {
            err = "remote LoadLibraryA returned 0 for " + dll_name;
            return false;
        }
        return true;
    }

    bool ensure_modules_loaded(HANDLE process,
                                const std::vector<std::wstring>& required,
                                DWORD initial_wait_ms,
                                std::map<std::wstring, remote_module_info_t>& out,
                                std::string& err)
    {
        ULONGLONG deadline = GetTickCount64() + initial_wait_ms;
        for (;;)
        {
            out.clear();
            if (!enumerate_remote_modules(process, out))
            {
                err = "EnumProcessModulesEx failed (process may have exited)";
                return false;
            }
            bool all_present = true;
            for (const auto& r : required)
                if (out.find(r) == out.end())
                {
                    all_present = false;
                    break;
                }
            if (all_present)
                return true;
            if (GetTickCount64() >= deadline)
                break;
            Sleep(100);
        }

        if (out.find(L"kernel32.dll") == out.end())
        {
            err = "kernel32.dll is not loaded in target process";
            return false;
        }
        uint64_t load_library_va = 0;
        if (!find_remote_export_va(process, out, L"kernel32.dll", "LoadLibraryA", load_library_va))
        {
            err = "Failed to resolve kernel32!LoadLibraryA in target";
            return false;
        }

        for (const auto& r : required)
        {
            if (out.find(r) != out.end())
                continue;
            std::string narrow_name = narrow(r);
            std::string sub_err;
            if (!remote_load_library(process, load_library_va, narrow_name, sub_err))
            {
                err = std::string("force-load failed for ") + narrow_name + ": " + sub_err;
                return false;
            }
        }

        out.clear();
        if (!enumerate_remote_modules(process, out))
        {
            err = "EnumProcessModulesEx failed after force-load";
            return false;
        }
        for (const auto& r : required)
        {
            if (out.find(r) != out.end())
                continue;
            HMODULE local = LoadLibraryExA(narrow(r).c_str(), nullptr, 0);
            if (!local)
            {
                err = std::string("module still missing after force-load: ") + narrow(r);
                return false;
            }
            std::wstring underlying = underlying_basename_lower(local);
            FreeLibrary(local);
            if (underlying.empty() || out.find(underlying) == out.end())
            {
                err = std::string("module still missing after force-load: ") + narrow(r)
                    + " (underlying=" + (underlying.empty() ? std::string("<unknown>") : narrow(underlying)) + ")";
                return false;
            }
        }
        return true;
    }

    bool function_underlying(FARPROC local_proc, std::wstring& out_basename, HMODULE& out_module)
    {
        out_module = nullptr;
        if (!GetModuleHandleExW(
                GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS
                    | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                reinterpret_cast<LPCWSTR>(local_proc),
                &out_module)
            || out_module == nullptr)
            return false;
        out_basename = underlying_basename_lower(out_module);
        return !out_basename.empty();
    }

    bool resolve_function_to_remote(FARPROC local_proc,
                                      const std::map<std::wstring, remote_module_info_t>& mods,
                                      uint64_t& out_remote_addr,
                                      std::wstring& out_underlying)
    {
        HMODULE actual = nullptr;
        if (!function_underlying(local_proc, out_underlying, actual))
            return false;
        auto it = mods.find(out_underlying);
        if (it == mods.end())
            return false;
        uint64_t local_proc_addr = reinterpret_cast<uint64_t>(local_proc);
        uint64_t local_base = reinterpret_cast<uint64_t>(actual);
        if (local_proc_addr < local_base)
            return false;
        out_remote_addr = it->second.base + (local_proc_addr - local_base);
        return true;
    }

    HMODULE try_load_local_with_fallback(const char* dll_name,
                                            const std::string& ida_install_dir,
                                            const std::map<std::wstring, remote_module_info_t>& mods)
    {
        HMODULE h = LoadLibraryExA(dll_name, nullptr, 0);
        if (h)
            return h;
        if (!ida_install_dir.empty())
        {
            std::string full = ida_install_dir;
            if (!full.empty() && full.back() != '\\' && full.back() != '/')
                full.push_back('\\');
            full.append(dll_name);
            h = LoadLibraryExA(full.c_str(), nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
            if (h)
                return h;
        }
        std::string lower_name(dll_name);
        for (auto& c : lower_name)
            c = static_cast<char>(::tolower(static_cast<unsigned char>(c)));
        std::wstring lower_w = widen(lower_name);
        auto it = mods.find(lower_w);
        if (it != mods.end() && !it->second.path.empty())
        {
            h = LoadLibraryExW(it->second.path.c_str(), nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
            if (h)
                return h;
        }
        return nullptr;
    }

    bool resolve_imports_remote(prepared_image_t& img,
                                  HANDLE process,
                                  uint64_t load_library_va,
                                  const std::string& ida_install_dir,
                                  std::map<std::wstring, remote_module_info_t>& mods,
                                  std::string& err)
    {
        IMAGE_DOS_HEADER dos = {};
        IMAGE_NT_HEADERS64 nt = {};
        if (!parse_pe_headers(img.bytes.data(), img.bytes.size(), dos, nt))
        {
            err = "parse_pe_headers failed during IAT resolution";
            return false;
        }
        const auto& imp = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (imp.VirtualAddress == 0 || imp.Size == 0)
            return true;

        auto* desc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(
            img.bytes.data() + imp.VirtualAddress);
        for (; desc->Name != 0; ++desc)
        {
            const char* dll_name = reinterpret_cast<const char*>(img.bytes.data() + desc->Name);
            HMODULE local = try_load_local_with_fallback(dll_name, ida_install_dir, mods);
            if (!local)
            {
                err = std::string("LoadLibraryExA(") + dll_name
                    + ") failed locally (also tried IDA install dir and remote module path)";
                return false;
            }

            auto* lookup = reinterpret_cast<IMAGE_THUNK_DATA64*>(
                img.bytes.data()
                + (desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk));
            auto* iat = reinterpret_cast<IMAGE_THUNK_DATA64*>(
                img.bytes.data() + desc->FirstThunk);

            bool dll_ok = true;
            std::string dll_err;
            for (; lookup->u1.AddressOfData; ++lookup, ++iat)
            {
                FARPROC local_proc = nullptr;
                std::string func_label;
                if (IMAGE_SNAP_BY_ORDINAL64(lookup->u1.Ordinal))
                {
                    uint32_t ordinal = static_cast<uint32_t>(IMAGE_ORDINAL64(lookup->u1.Ordinal));
                    local_proc = GetProcAddress(local, MAKEINTRESOURCEA(ordinal));
                    func_label = std::string("ordinal #") + std::to_string(ordinal);
                }
                else
                {
                    auto* import_by_name = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(
                        img.bytes.data() + lookup->u1.AddressOfData);
                    local_proc = GetProcAddress(local, import_by_name->Name);
                    func_label = import_by_name->Name;
                }
                if (!local_proc)
                {
                    dll_err = std::string("export ") + func_label + " not found in " + dll_name;
                    dll_ok = false;
                    break;
                }
                uint64_t remote_addr = 0;
                std::wstring underlying_lower;
                if (!resolve_function_to_remote(local_proc, mods, remote_addr, underlying_lower))
                {
                    if (!underlying_lower.empty())
                    {
                        std::string load_err;
                        if (!remote_load_library(process, load_library_va,
                                                   narrow(underlying_lower), load_err))
                        {
                            dll_err = std::string("forwarder load failed for ")
                                + narrow(underlying_lower) + ": " + load_err;
                            dll_ok = false;
                            break;
                        }
                        mods.clear();
                        if (!enumerate_remote_modules(process, mods))
                        {
                            dll_err = "EnumProcessModulesEx failed after forwarder load";
                            dll_ok = false;
                            break;
                        }
                        if (!resolve_function_to_remote(local_proc, mods, remote_addr, underlying_lower))
                        {
                            dll_err = std::string("still could not map ") + dll_name + "!"
                                + func_label + " (underlying="
                                + narrow(underlying_lower) + ")";
                            dll_ok = false;
                            break;
                        }
                    }
                    else
                    {
                        dll_err = std::string("could not map ") + dll_name + "!" + func_label
                            + " to a remote module";
                        dll_ok = false;
                        break;
                    }
                }
                iat->u1.Function = remote_addr;
            }
            FreeLibrary(local);
            if (!dll_ok)
            {
                err = dll_err;
                return false;
            }
        }
        return true;
    }

    bool is_apiset_dll_name(const std::string& lower)
    {
        if (lower.size() < 7) return false;
        if (lower.compare(0, 7, "api-ms-") == 0) return true;
        if (lower.compare(0, 7, "ext-ms-") == 0) return true;
        return false;
    }

    std::vector<std::wstring> collect_required_imports(const std::vector<uint8_t>& pe)
    {
        std::vector<std::wstring> out;
        IMAGE_DOS_HEADER dos = {};
        IMAGE_NT_HEADERS64 nt = {};
        if (!parse_pe_headers(pe.data(), pe.size(), dos, nt))
            return out;
        const auto& imp = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (imp.VirtualAddress == 0 || imp.Size == 0)
            return out;

        const auto* file_header = &nt.FileHeader;
        const size_t section_table_off = dos.e_lfanew + sizeof(uint32_t)
            + sizeof(IMAGE_FILE_HEADER) + file_header->SizeOfOptionalHeader;
        const auto* sec = reinterpret_cast<const IMAGE_SECTION_HEADER*>(
            pe.data() + section_table_off);
        auto rva_to_off = [&](uint32_t rva) -> uint32_t {
            for (WORD i = 0; i < file_header->NumberOfSections; ++i)
            {
                uint32_t v = sec[i].VirtualAddress;
                uint32_t s = sec[i].Misc.VirtualSize ? sec[i].Misc.VirtualSize : sec[i].SizeOfRawData;
                if (rva >= v && rva < v + s)
                    return sec[i].PointerToRawData + (rva - v);
            }
            return 0;
        };
        uint32_t imp_off = rva_to_off(imp.VirtualAddress);
        if (imp_off == 0)
            return out;
        const auto* desc = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(pe.data() + imp_off);
        for (; desc->Name != 0; ++desc)
        {
            uint32_t name_off = rva_to_off(desc->Name);
            if (name_off == 0)
                continue;
            const char* dll_name = reinterpret_cast<const char*>(pe.data() + name_off);
            std::string lower(dll_name);
            for (auto& ch : lower)
                ch = static_cast<char>(::tolower(static_cast<unsigned char>(ch)));
            if (is_apiset_dll_name(lower))
                continue;
            out.push_back(widen(lower));
        }
        return out;
    }

#pragma pack(push, 1)
    struct bootstrap_payload_t
    {
        uint64_t image_base;
        uint64_t marker_va;
        uint64_t proof_buffer_va;
        uint64_t proof_data_va;
        uint64_t proof_data_len;
        uint64_t marker_value;
        uint64_t dllmain_va;
        uint64_t plugin_struct_va;
        uint64_t rtl_add_function_table_va;
        uint64_t exception_table_va;
        uint64_t exception_count;
        uint64_t tls_callback_array_va;
        uint64_t completion_event_va;
        uint64_t set_event_va;
    };
#pragma pack(pop)

    static_assert(offsetof(bootstrap_payload_t, image_base)                == 0x00, "bp 00");
    static_assert(offsetof(bootstrap_payload_t, marker_va)                  == 0x08, "bp 08");
    static_assert(offsetof(bootstrap_payload_t, proof_buffer_va)            == 0x10, "bp 10");
    static_assert(offsetof(bootstrap_payload_t, proof_data_va)              == 0x18, "bp 18");
    static_assert(offsetof(bootstrap_payload_t, proof_data_len)             == 0x20, "bp 20");
    static_assert(offsetof(bootstrap_payload_t, marker_value)               == 0x28, "bp 28");
    static_assert(offsetof(bootstrap_payload_t, dllmain_va)                 == 0x30, "bp 30");
    static_assert(offsetof(bootstrap_payload_t, plugin_struct_va)           == 0x38, "bp 38");
    static_assert(offsetof(bootstrap_payload_t, rtl_add_function_table_va)  == 0x40, "bp 40");
    static_assert(offsetof(bootstrap_payload_t, exception_table_va)         == 0x48, "bp 48");
    static_assert(offsetof(bootstrap_payload_t, exception_count)            == 0x50, "bp 50");
    static_assert(offsetof(bootstrap_payload_t, tls_callback_array_va)      == 0x58, "bp 58");
    static_assert(offsetof(bootstrap_payload_t, completion_event_va)        == 0x60, "bp 60");
    static_assert(offsetof(bootstrap_payload_t, set_event_va)               == 0x68, "bp 68");

    alignas(16) static const uint8_t kBootstrapShellcode[] = {
        0x53,
        0x56,
        0x57,
        0x48, 0x83, 0xEC, 0x20,
        0x48, 0x89, 0xCB,
        0x48, 0x8B, 0x7B, 0x10,
        0x48, 0x8B, 0x73, 0x18,
        0x48, 0x8B, 0x4B, 0x20,
        0x48, 0x85, 0xC9,
        0x74, 0x0F,
        0x8A, 0x06,
        0x88, 0x07,
        0x48, 0xFF, 0xC6,
        0x48, 0xFF, 0xC7,
        0x48, 0xFF, 0xC9,
        0x75, 0xF1,
        0x0F, 0xAE, 0xF0,
        0x48, 0x8B, 0x43, 0x28,
        0x48, 0x8B, 0x4B, 0x08,
        0x48, 0x89, 0x01,
        0x0F, 0xAE, 0xF0,
        0x48, 0x8B, 0x4B, 0x48,
        0x48, 0x85, 0xC9,
        0x74, 0x0D,
        0x48, 0x8B, 0x53, 0x50,
        0x4C, 0x8B, 0x03,
        0x48, 0x8B, 0x43, 0x40,
        0xFF, 0xD0,
        0x48, 0x8B, 0x73, 0x58,
        0x48, 0x85, 0xF6,
        0x74, 0x1B,
        0x48, 0x8B, 0x06,
        0x48, 0x85, 0xC0,
        0x74, 0x13,
        0x48, 0x8B, 0x0B,
        0xBA, 0x01, 0x00, 0x00, 0x00,
        0x45, 0x31, 0xC0,
        0xFF, 0xD0,
        0x48, 0x83, 0xC6, 0x08,
        0xEB, 0xE5,
        0x48, 0x8B, 0x0B,
        0xBA, 0x01, 0x00, 0x00, 0x00,
        0x45, 0x31, 0xC0,
        0x48, 0x8B, 0x43, 0x30,
        0xFF, 0xD0,
        0x48, 0x8B, 0x43, 0x38,
        0x48, 0x85, 0xC0,
        0x74, 0x0B,
        0x48, 0x8B, 0x40, 0x08,
        0x48, 0x85, 0xC0,
        0x74, 0x02,
        0xFF, 0xD0,
        0x48, 0x8B, 0x4B, 0x60,
        0x48, 0x85, 0xC9,
        0x74, 0x0B,
        0x48, 0x8B, 0x43, 0x68,
        0x48, 0x85, 0xC0,
        0x74, 0x02,
        0xFF, 0xD0,
        0x31, 0xC0,
        0x48, 0x83, 0xC4, 0x20,
        0x5F,
        0x5E,
        0x5B,
        0xC3,
    };
    static constexpr size_t kBootstrapShellcodeSize = sizeof(kBootstrapShellcode);
    static_assert(kBootstrapShellcodeSize == 0xB8,
                  "bootstrap shellcode must be exactly 184 bytes after hand-encoding");

    bool transfer_image_to_remote(HANDLE process,
                                   const prepared_image_t& img,
                                   std::string& err)
    {
        SIZE_T wrote = 0;
        if (!WriteProcessMemory(process,
                                  reinterpret_cast<LPVOID>(img.remote_base),
                                  img.bytes.data(),
                                  img.bytes.size(),
                                  &wrote)
            || wrote != img.bytes.size())
        {
            err = std::string("WriteProcessMemory image failed err=")
                + std::to_string(static_cast<unsigned long>(GetLastError()));
            return false;
        }
        for (const auto& s : img.sections)
        {
            DWORD old = 0;
            if (!VirtualProtectEx(process,
                                    reinterpret_cast<LPVOID>(img.remote_base + s.va),
                                    s.size,
                                    s.protect,
                                    &old))
            {
                err = std::string("VirtualProtectEx failed for section va=0x")
                    + std::to_string(s.va);
                return false;
            }
        }
        DWORD old = 0;
        VirtualProtectEx(process,
                         reinterpret_cast<LPVOID>(img.remote_base),
                         img.headers_size,
                         PAGE_READONLY,
                         &old);
        return true;
    }

    bool wait_for_ida_ui_ready(HANDLE process, DWORD timeout_ms)
    {
        DWORD waitres = WaitForInputIdle(process, timeout_ms);
        if (waitres != 0)
            return false;
        ULONGLONG deadline = GetTickCount64() + 5000;
        while (GetTickCount64() < deadline)
        {
            std::map<std::wstring, remote_module_info_t> mods;
            if (enumerate_remote_modules(process, mods))
            {
                bool seen_ida = false;
                for (const auto& kv : mods)
                {
                    if (kv.first.find(L"ida") == 0 && kv.first.find(L".dll") != std::wstring::npos)
                    {
                        seen_ida = true;
                        break;
                    }
                }
                if (seen_ida)
                    return true;
            }
            Sleep(100);
        }
        return true;
    }

    bool inject_bootstrap_and_run(HANDLE process,
                                   const prepared_image_t& img,
                                   const proof_buffer_t& proof,
                                   const std::wstring& ntdll_path,
                                   uint64_t ntdll_remote_base,
                                   std::string& err)
    {
        on_disk_module_t ntdll{};
        if (!load_module_for_export_lookup(ntdll_path, ntdll))
        {
            err = "failed to parse on-disk ntdll for RtlAddFunctionTable export";
            return false;
        }
        uint32_t rtl_rva = 0;
        if (!resolve_export_rva(ntdll, "RtlAddFunctionTable", 0, rtl_rva))
        {
            err = "RtlAddFunctionTable not found in ntdll exports";
            return false;
        }

        size_t shellcode_size = kBootstrapShellcodeSize;
        size_t payload_size = sizeof(bootstrap_payload_t);
        size_t proof_size = sizeof(proof_buffer_t);
        size_t total_alloc = (shellcode_size + 0xF) & ~size_t{0xF};
        size_t payload_off = total_alloc;
        total_alloc += (payload_size + 0xF) & ~size_t{0xF};
        size_t proof_off = total_alloc;
        total_alloc += (proof_size + 0xF) & ~size_t{0xF};

        LPVOID region = VirtualAllocEx(process, nullptr, total_alloc,
                                        MEM_COMMIT | MEM_RESERVE,
                                        PAGE_EXECUTE_READWRITE);
        if (!region)
        {
            err = "VirtualAllocEx for bootstrap region failed err="
                + std::to_string(static_cast<unsigned long>(GetLastError()));
            return false;
        }
        uint8_t* remote_shellcode = reinterpret_cast<uint8_t*>(region);
        uint8_t* remote_payload = remote_shellcode + payload_off;
        uint8_t* remote_proof = remote_shellcode + proof_off;

        SIZE_T wrote = 0;
        if (!WriteProcessMemory(process, remote_shellcode,
                                  kBootstrapShellcode, shellcode_size, &wrote)
            || wrote != shellcode_size)
        {
            VirtualFreeEx(process, region, 0, MEM_RELEASE);
            err = "WriteProcessMemory(shellcode) failed";
            return false;
        }

        if (!WriteProcessMemory(process, remote_proof,
                                  &proof, proof_size, &wrote)
            || wrote != proof_size)
        {
            VirtualFreeEx(process, region, 0, MEM_RELEASE);
            err = "WriteProcessMemory(proof) failed";
            return false;
        }

        bootstrap_payload_t payload{};
        payload.image_base = img.remote_base;
        payload.marker_va = img.remote_base + g_aida_plugin_marker_rva;
        payload.proof_buffer_va = img.remote_base + g_aida_plugin_proof_rva;
        payload.proof_data_va = reinterpret_cast<uint64_t>(remote_proof);
        payload.proof_data_len = proof_size;
        payload.marker_value = aida_manual_map::kMarkerValue;
        payload.dllmain_va = img.remote_base + g_aida_plugin_dllmain_rva;
        payload.plugin_struct_va = img.remote_base + g_aida_plugin_struct_rva;
        payload.rtl_add_function_table_va = ntdll_remote_base + rtl_rva;
        payload.exception_table_va = img.exception_size
            ? img.remote_base + img.exception_rva
            : 0;
        payload.exception_count = img.exception_size
            ? img.exception_size / sizeof(RUNTIME_FUNCTION)
            : 0;
        payload.tls_callback_array_va = img.tls_callbacks_va
            ? img.remote_base + img.tls_callbacks_va
            : 0;
        payload.completion_event_va = 0;
        payload.set_event_va = 0;

        if (!WriteProcessMemory(process, remote_payload,
                                  &payload, payload_size, &wrote)
            || wrote != payload_size)
        {
            VirtualFreeEx(process, region, 0, MEM_RELEASE);
            err = "WriteProcessMemory(payload) failed";
            return false;
        }

        DWORD tid = 0;
        HANDLE th = CreateRemoteThread(process, nullptr, 0,
                                         reinterpret_cast<LPTHREAD_START_ROUTINE>(remote_shellcode),
                                         remote_payload, 0, &tid);
        if (!th)
        {
            VirtualFreeEx(process, region, 0, MEM_RELEASE);
            err = "CreateRemoteThread(bootstrap) failed err="
                + std::to_string(static_cast<unsigned long>(GetLastError()));
            return false;
        }

        DWORD wait = WaitForSingleObject(th, kBootstrapTimeoutMs);
        DWORD exit_code = 0;
        GetExitCodeThread(th, &exit_code);
        CloseHandle(th);
        VirtualFreeEx(process, region, 0, MEM_RELEASE);

        if (wait != WAIT_OBJECT_0)
        {
            err = "bootstrap thread did not complete within budget";
            return false;
        }
        return true;
    }

    bool compute_hmac_sha256(const uint8_t* key, size_t key_len,
                              const uint8_t* data, size_t data_len,
                              uint8_t out_mac[32])
    {
        unsigned int mac_len = 0;
        unsigned char buf[EVP_MAX_MD_SIZE] = {};
        if (HMAC(EVP_sha256(), key, static_cast<int>(key_len),
                  data, data_len, buf, &mac_len) == nullptr)
            return false;
        if (mac_len != 32)
            return false;
        std::memcpy(out_mac, buf, 32);
        return true;
    }

    bool constant_time_eq(const uint8_t* a, const uint8_t* b, size_t n)
    {
        uint8_t diff = 0;
        for (size_t i = 0; i < n; ++i)
            diff |= static_cast<uint8_t>(a[i] ^ b[i]);
        return diff == 0;
    }

    struct overlapped_ctx_t
    {
        OVERLAPPED ov;
        HANDLE     event;
    };

    bool ovl_init(overlapped_ctx_t& c)
    {
        c.event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!c.event)
            return false;
        std::memset(&c.ov, 0, sizeof(c.ov));
        c.ov.hEvent = c.event;
        return true;
    }

    void ovl_destroy(overlapped_ctx_t& c)
    {
        if (c.event)
        {
            CloseHandle(c.event);
            c.event = nullptr;
        }
    }

    bool pipe_write_all(HANDLE pipe, const void* data, size_t n)
    {
        if (n == 0)
            return true;
        overlapped_ctx_t c{};
        if (!ovl_init(c))
            return false;
        BOOL ok = WriteFile(pipe, data, static_cast<DWORD>(n), nullptr, &c.ov);
        if (!ok && GetLastError() != ERROR_IO_PENDING)
        {
            ovl_destroy(c);
            return false;
        }
        DWORD got = 0;
        BOOL res = GetOverlappedResult(pipe, &c.ov, &got, TRUE);
        ovl_destroy(c);
        return res && got == static_cast<DWORD>(n);
    }

    bool pipe_read_all_with_timeout(HANDLE pipe, void* data, size_t n, DWORD timeout_ms)
    {
        if (n == 0)
            return true;
        overlapped_ctx_t c{};
        if (!ovl_init(c))
            return false;
        BOOL ok = ReadFile(pipe, data, static_cast<DWORD>(n), nullptr, &c.ov);
        if (!ok && GetLastError() != ERROR_IO_PENDING)
        {
            ovl_destroy(c);
            return false;
        }
        DWORD wait = WaitForSingleObject(c.event, timeout_ms);
        if (wait != WAIT_OBJECT_0)
        {
            CancelIoEx(pipe, &c.ov);
            WaitForSingleObject(c.event, 250);
            ovl_destroy(c);
            return false;
        }
        DWORD got = 0;
        BOOL res = GetOverlappedResult(pipe, &c.ov, &got, FALSE);
        ovl_destroy(c);
        return res && got == static_cast<DWORD>(n);
    }

    void pipe_server_thread()
    {
        injector_session_t* session = nullptr;
        {
            std::lock_guard<std::mutex> lk(g_session_mutex);
            session = g_session.get();
        }
        if (!session)
            return;

        wchar_t pipe_name[64] = {};
        std::swprintf(pipe_name, 64, L"%s%lu",
                       aida_manual_map::kPipePrefix,
                       static_cast<unsigned long>(session->ida_pid));

        HANDLE pipe = CreateNamedPipeW(pipe_name,
                                         PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                                         PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT
                                         | PIPE_REJECT_REMOTE_CLIENTS,
                                         1,
                                         8192, 8192,
                                         5000, nullptr);
        if (pipe == INVALID_HANDLE_VALUE)
        {
            inject_log("pipe_create_failed err=%lu", GetLastError());
            return;
        }

        overlapped_ctx_t connect_ctx{};
        if (!ovl_init(connect_ctx))
        {
            CloseHandle(pipe);
            return;
        }
        BOOL connected = ConnectNamedPipe(pipe, &connect_ctx.ov);
        DWORD err = GetLastError();
        bool got_client = false;
        if (connected || err == ERROR_PIPE_CONNECTED)
        {
            got_client = true;
        }
        else if (err == ERROR_IO_PENDING)
        {
            ULONGLONG deadline = GetTickCount64() + kPipeServerAcceptTimeoutMs;
            while (!session->shutdown_requested.load(std::memory_order_acquire))
            {
                ULONGLONG now = GetTickCount64();
                if (now >= deadline)
                    break;
                DWORD remaining = static_cast<DWORD>(deadline - now);
                if (remaining > 250)
                    remaining = 250;
                DWORD wait = WaitForSingleObject(connect_ctx.event, remaining);
                if (wait == WAIT_OBJECT_0)
                {
                    DWORD bytes = 0;
                    got_client = GetOverlappedResult(pipe, &connect_ctx.ov, &bytes, FALSE) != 0;
                    break;
                }
                if (wait != WAIT_TIMEOUT)
                {
                    err = GetLastError();
                    break;
                }
            }
            if (!got_client)
            {
                CancelIoEx(pipe, &connect_ctx.ov);
                WaitForSingleObject(connect_ctx.event, 250);
            }
        }
        ovl_destroy(connect_ctx);

        if (!got_client)
        {
            inject_log("pipe_no_client err=%lu", err);
            CloseHandle(pipe);
            return;
        }

        frame_header_t header{};
        if (!pipe_read_all_with_timeout(pipe, &header, sizeof(header), 8000)
            || header.verb != verb_hello
            || header.payload_len != 16 + 32)
        {
            inject_log("pipe_hello_bad");
            DisconnectNamedPipe(pipe);
            CloseHandle(pipe);
            return;
        }
        std::vector<uint8_t> hello_payload(header.payload_len);
        if (!pipe_read_all_with_timeout(pipe, hello_payload.data(),
                                         hello_payload.size(), 8000))
        {
            inject_log("pipe_hello_payload_read_failed");
            CloseHandle(pipe);
            return;
        }

        uint8_t auth_input[5 + 16] = { 'H','E','L','L','O' };
        std::memcpy(auth_input + 5, hello_payload.data(), 16);
        uint8_t expected_mac[32] = {};
        if (!compute_hmac_sha256(session->pipe_secret.data(),
                                  session->pipe_secret.size(),
                                  auth_input, sizeof(auth_input), expected_mac))
        {
            inject_log("pipe_hello_hmac_compute_failed");
            CloseHandle(pipe);
            return;
        }
        if (!constant_time_eq(hello_payload.data() + 16, expected_mac, 32))
        {
            inject_log("pipe_hello_hmac_mismatch");
            CloseHandle(pipe);
            return;
        }

        uint8_t ack_input[9 + 16] = { 'H','E','L','L','O','_','A','C','K' };
        std::memcpy(ack_input + 9, hello_payload.data(), 16);
        uint8_t ack_mac[32] = {};
        if (!compute_hmac_sha256(session->pipe_secret.data(),
                                  session->pipe_secret.size(),
                                  ack_input, sizeof(ack_input), ack_mac))
        {
            inject_log("pipe_ack_hmac_compute_failed");
            CloseHandle(pipe);
            return;
        }
        frame_header_t ack_hdr{};
        ack_hdr.verb = verb_hello_ack;
        ack_hdr.payload_len = 32;
        if (!pipe_write_all(pipe, &ack_hdr, sizeof(ack_hdr))
            || !pipe_write_all(pipe, ack_mac, 32))
        {
            inject_log("pipe_ack_write_failed");
            CloseHandle(pipe);
            return;
        }

        session->handshake_completed.store(true, std::memory_order_release);
        inject_log("pipe_handshake_complete pid=%lu",
              static_cast<unsigned long>(session->ida_pid));

        ULONGLONG last_heartbeat = GetTickCount64();
        while (!session->shutdown_requested.load(std::memory_order_acquire))
        {
            DWORD avail = 0;
            if (!PeekNamedPipe(pipe, nullptr, 0, nullptr, &avail, nullptr))
                break;
            if (avail >= sizeof(frame_header_t))
            {
                frame_header_t in{};
                if (!pipe_read_all_with_timeout(pipe, &in, sizeof(in), 6000))
                    break;
                if (in.payload_len > kFrameMaxPayload)
                    break;
                std::vector<uint8_t> body(in.payload_len);
                if (in.payload_len > 0
                    && !pipe_read_all_with_timeout(pipe, body.data(), body.size(), 6000))
                    break;
                switch (in.verb)
                {
                    case verb_status:
                        if (body.size() >= 4 + 32)
                        {
                            uint32_t code = 0;
                            std::memcpy(&code, body.data(), 4);
                            std::string msg(body.begin() + 4, body.end() - 32);
                            inject_log("pipe_status code=%u msg=%s", code, msg.c_str());
                        }
                        last_heartbeat = GetTickCount64();
                        break;
                    case verb_heartbeat:
                        last_heartbeat = GetTickCount64();
                        if (body.size() == 8 + 32)
                        {
                            frame_header_t hb_hdr{};
                            hb_hdr.verb = verb_heartbeat;
                            hb_hdr.payload_len = 0;
                            pipe_write_all(pipe, &hb_hdr, sizeof(hb_hdr));
                        }
                        break;
                    case verb_bye:
                        inject_log("pipe_bye");
                        session->shutdown_requested.store(true, std::memory_order_release);
                        break;
                    default:
                        break;
                }
            }
            ULONGLONG now = GetTickCount64();
            if (now - last_heartbeat > 30000)
            {
                inject_log("pipe_heartbeat_timeout");
                break;
            }
            Sleep(50);
        }

        if (session->shutdown_requested.load(std::memory_order_acquire))
        {
            uint8_t kill_mac[32] = {};
            if (compute_hmac_sha256(session->pipe_secret.data(),
                                      session->pipe_secret.size(),
                                      reinterpret_cast<const uint8_t*>("KILL"), 4,
                                      kill_mac))
            {
                frame_header_t kh{};
                kh.verb = verb_kill;
                kh.payload_len = 32;
                pipe_write_all(pipe, &kh, sizeof(kh));
                pipe_write_all(pipe, kill_mac, 32);
            }
        }

        DisconnectNamedPipe(pipe);
        CloseHandle(pipe);
        session->active.store(false, std::memory_order_release);
    }

    bool spawn_ida_process(const std::string& ida_path,
                            const std::string& target_file,
                            HANDLE& out_job,
                            HANDLE& out_process,
                            HANDLE& out_thread,
                            DWORD& out_pid,
                            std::string& err)
    {
        ::diag::log_tagged_critical_fmt("ida_inject", "spawn enter ida='%s' target='%s'",
            ida_path.c_str(), target_file.c_str());
        std::wstring exe = widen(ida_path);
        std::wstring tgt = widen(target_file);
        std::wstring cmd;
        cmd.reserve(exe.size() + tgt.size() + 8);
        cmd.push_back(L'"');
        cmd.append(exe);
        cmd.push_back(L'"');
        if (!tgt.empty())
        {
            cmd.append(L" \"");
            cmd.append(tgt);
            cmd.push_back(L'"');
        }
        std::vector<wchar_t> cmd_buf(cmd.begin(), cmd.end());
        cmd_buf.push_back(L'\0');

        ::diag::log_tagged("ida_inject", "spawn CreateJobObjectW_pre");
        HANDLE job = CreateJobObjectW(nullptr, nullptr);
        if (!job)
        {
            DWORD ec = GetLastError();
            ::diag::log_tagged_critical_fmt("ida_inject", "spawn CreateJobObjectW_FAIL err=%lu",
                static_cast<unsigned long>(ec));
            err = "CreateJobObjectW failed err="
                + std::to_string(static_cast<unsigned long>(ec));
            return false;
        }
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli = {};
        jeli.BasicLimitInformation.LimitFlags =
            JOB_OBJECT_LIMIT_BREAKAWAY_OK
            | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
        SetInformationJobObject(job, JobObjectExtendedLimitInformation,
                                  &jeli, sizeof(jeli));

        STARTUPINFOW si = {};
        si.cb = sizeof(si);
        PROCESS_INFORMATION pi = {};
        DWORD flags = CREATE_DEFAULT_ERROR_MODE | CREATE_SUSPENDED | CREATE_BREAKAWAY_FROM_JOB;
        ::diag::log_tagged_fmt("ida_inject", "spawn CreateProcessW_pre flags=0x%lX",
            static_cast<unsigned long>(flags));
        if (!CreateProcessW(exe.c_str(), cmd_buf.data(),
                              nullptr, nullptr, FALSE,
                              flags,
                              nullptr, nullptr, &si, &pi))
        {
            DWORD ec = GetLastError();
            CloseHandle(job);
            ::diag::log_tagged_critical_fmt("ida_inject", "spawn CreateProcessW_FAIL err=%lu",
                static_cast<unsigned long>(ec));
            err = std::string("CreateProcessW failed err=")
                + std::to_string(static_cast<unsigned long>(ec));
            return false;
        }
        ::diag::log_tagged_fmt("ida_inject", "spawn CreateProcessW_ok pid=%lu",
            static_cast<unsigned long>(pi.dwProcessId));
        if (!AssignProcessToJobObject(job, pi.hProcess))
        {
            DWORD ec = GetLastError();
            TerminateProcess(pi.hProcess, 1);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            CloseHandle(job);
            ::diag::log_tagged_critical_fmt("ida_inject", "spawn AssignProcessToJobObject_FAIL err=%lu",
                static_cast<unsigned long>(ec));
            err = std::string("AssignProcessToJobObject failed err=")
                + std::to_string(static_cast<unsigned long>(ec));
            return false;
        }
        ::diag::log_tagged("ida_inject", "spawn ResumeThread_pre");
        ResumeThread(pi.hThread);
        out_job = job;
        out_process = pi.hProcess;
        out_thread = pi.hThread;
        out_pid = pi.dwProcessId;
        ::diag::log_tagged_critical_fmt("ida_inject", "spawn done pid=%lu",
            static_cast<unsigned long>(pi.dwProcessId));
        return true;
    }

    bool query_job_pids(HANDLE job, std::vector<DWORD>& out_pids)
    {
        out_pids.clear();
        DWORD assumed = 64;
        for (int attempt = 0; attempt < 4; ++attempt)
        {
            DWORD bufsize = static_cast<DWORD>(sizeof(JOBOBJECT_BASIC_PROCESS_ID_LIST))
                + (assumed - 1) * static_cast<DWORD>(sizeof(ULONG_PTR));
            std::vector<uint8_t> buf(bufsize, 0);
            DWORD ret = 0;
            BOOL ok = QueryInformationJobObject(job, JobObjectBasicProcessIdList,
                                                  buf.data(), bufsize, &ret);
            DWORD err = ok ? 0 : GetLastError();
            auto* list = reinterpret_cast<JOBOBJECT_BASIC_PROCESS_ID_LIST*>(buf.data());
            if (ok)
            {
                out_pids.reserve(list->NumberOfProcessIdsInList);
                for (DWORD i = 0; i < list->NumberOfProcessIdsInList; ++i)
                    out_pids.push_back(static_cast<DWORD>(list->ProcessIdList[i]));
                return true;
            }
            if (err == ERROR_MORE_DATA && list->NumberOfAssignedProcesses > assumed)
            {
                assumed = list->NumberOfAssignedProcesses + 8;
                continue;
            }
            return false;
        }
        return false;
    }

    bool process_basename_lower(DWORD pid, std::wstring& out_basename)
    {
        HANDLE p = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!p)
            return false;
        wchar_t path[MAX_PATH] = {};
        DWORD len = MAX_PATH;
        BOOL ok = QueryFullProcessImageNameW(p, 0, path, &len);
        CloseHandle(p);
        if (!ok)
            return false;
        const wchar_t* base = path;
        for (const wchar_t* x = path; *x; ++x)
            if (*x == L'\\' || *x == L'/')
                base = x + 1;
        out_basename.assign(base);
        for (auto& c : out_basename)
            c = static_cast<wchar_t>(towlower(c));
        return true;
    }

    bool is_ida_basename(const std::wstring& base)
    {
        return base == L"ida.exe" || base == L"ida64.exe"
            || base == L"idat.exe" || base == L"idat64.exe"
            || base == L"idaq.exe" || base == L"idaq64.exe";
    }

    bool wait_for_settled_target(HANDLE job,
                                   HANDLE initial_process,
                                   DWORD initial_pid,
                                   DWORD timeout_ms,
                                   HANDLE& out_process,
                                   DWORD& out_pid)
    {
        ULONGLONG deadline = GetTickCount64() + timeout_ms;
        DWORD last_candidate = 0;
        ULONGLONG stable_since = 0;
        constexpr DWORD kStableMs = 2500;
        ULONGLONG started_at = GetTickCount64();
        DWORD iter_count = 0;
        bool initial_dead_logged = false;

        while (GetTickCount64() < deadline)
        {
            ++iter_count;
            std::vector<DWORD> pids;
            if (!query_job_pids(job, pids))
            {
                if (iter_count <= 3 || (iter_count % 8) == 0) {
                    ::diag::log_tagged_critical_fmt("ida_inject",
                        "wait_settled iter=%lu query_job_pids_FAIL elapsed_ms=%llu",
                        static_cast<unsigned long>(iter_count),
                        static_cast<unsigned long long>(GetTickCount64() - started_at));
                }
                Sleep(250);
                continue;
            }
            if (iter_count <= 3 || (iter_count % 8) == 0) {
                ::diag::log_tagged_fmt("ida_inject",
                    "wait_settled iter=%lu pids_in_job=%zu elapsed_ms=%llu",
                    static_cast<unsigned long>(iter_count),
                    pids.size(),
                    static_cast<unsigned long long>(GetTickCount64() - started_at));
            }

            DWORD candidate = 0;
            FILETIME latest_ct = {};
            for (DWORD pid : pids)
            {
                std::wstring base;
                if (!process_basename_lower(pid, base) || !is_ida_basename(base))
                    continue;
                HANDLE p = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
                if (!p)
                    continue;
                FILETIME ct = {}, et = {}, kt = {}, ut = {};
                bool ok = (GetProcessTimes(p, &ct, &et, &kt, &ut) != 0);
                CloseHandle(p);
                if (!ok)
                    continue;
                if (CompareFileTime(&ct, &latest_ct) > 0)
                {
                    latest_ct = ct;
                    candidate = pid;
                }
            }

            if (candidate == 0)
            {
                if (initial_process)
                {
                    DWORD wres = WaitForSingleObject(initial_process, 0);
                    if (wres == WAIT_TIMEOUT)
                    {
                        candidate = initial_pid;
                    }
                    else if (!initial_dead_logged)
                    {
                        DWORD exit_code = 0;
                        GetExitCodeProcess(initial_process, &exit_code);
                        ::diag::log_tagged_critical_fmt("ida_inject",
                            "wait_settled INITIAL_PROCESS_DEAD pid=%lu wres=0x%lX exit_code=0x%08lX elapsed_ms=%llu — IDA crashed/exited shortly after spawn",
                            static_cast<unsigned long>(initial_pid),
                            static_cast<unsigned long>(wres),
                            static_cast<unsigned long>(exit_code),
                            static_cast<unsigned long long>(GetTickCount64() - started_at));
                        initial_dead_logged = true;
                    }
                }
            }

            if (candidate == 0)
            {
                if (iter_count <= 3 || (iter_count % 8) == 0) {
                    ::diag::log_tagged_fmt("ida_inject",
                        "wait_settled iter=%lu no_candidate elapsed_ms=%llu",
                        static_cast<unsigned long>(iter_count),
                        static_cast<unsigned long long>(GetTickCount64() - started_at));
                }
                if (initial_dead_logged
                    && pids.empty()
                    && (GetTickCount64() - started_at) >= 5000)
                {
                    ::diag::log_tagged_critical_fmt("ida_inject",
                        "wait_settled EARLY_BAIL initial_dead_and_no_job_processes elapsed_ms=%llu — IDA exited, nothing to manual-map into",
                        static_cast<unsigned long long>(GetTickCount64() - started_at));
                    return false;
                }
                Sleep(250);
                continue;
            }

            if (candidate != last_candidate)
            {
                last_candidate = candidate;
                stable_since = GetTickCount64();
            }
            else if (GetTickCount64() - stable_since >= kStableMs)
            {
                HANDLE p = OpenProcess(
                    PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION
                    | PROCESS_VM_READ | PROCESS_VM_WRITE
                    | PROCESS_CREATE_THREAD | PROCESS_DUP_HANDLE
                    | SYNCHRONIZE | PROCESS_TERMINATE,
                    FALSE, candidate);
                if (!p)
                {
                    DWORD ec = GetLastError();
                    ::diag::log_tagged_critical_fmt("ida_inject",
                        "wait_settled OpenProcess_full_access_FAIL pid=%lu err=%lu (post-seal_handles?)",
                        static_cast<unsigned long>(candidate),
                        static_cast<unsigned long>(ec));
                    last_candidate = 0;
                    stable_since = 0;
                    Sleep(250);
                    continue;
                }
                if (WaitForSingleObject(p, 0) != WAIT_TIMEOUT)
                {
                    DWORD exit_code = 0;
                    GetExitCodeProcess(p, &exit_code);
                    ::diag::log_tagged_critical_fmt("ida_inject",
                        "wait_settled candidate_dead_at_settle pid=%lu exit_code=0x%08lX",
                        static_cast<unsigned long>(candidate),
                        static_cast<unsigned long>(exit_code));
                    CloseHandle(p);
                    last_candidate = 0;
                    stable_since = 0;
                    Sleep(250);
                    continue;
                }
                ::diag::log_tagged_critical_fmt("ida_inject",
                    "wait_settled SUCCESS pid=%lu after_iter=%lu elapsed_ms=%llu",
                    static_cast<unsigned long>(candidate),
                    static_cast<unsigned long>(iter_count),
                    static_cast<unsigned long long>(GetTickCount64() - started_at));
                out_process = p;
                out_pid = candidate;
                return true;
            }

            Sleep(250);
        }
        ::diag::log_tagged_critical_fmt("ida_inject",
            "wait_settled GIVING_UP elapsed_ms=%llu iter=%lu",
            static_cast<unsigned long long>(GetTickCount64() - started_at),
            static_cast<unsigned long>(iter_count));
        return false;
    }

    uint64_t fnv1a64(const std::string& s)
    {
        uint64_t h = 14695981039346656037ULL;
        for (char c : s)
        {
            h ^= static_cast<uint8_t>(c);
            h *= 1099511628211ULL;
        }
        return h;
    }

    bool sha256_file_path(const std::wstring& path, uint8_t out_hash[32])
    {
        std::memset(out_hash, 0, 32);
        HANDLE hf = CreateFileW(path.c_str(), GENERIC_READ,
                                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                nullptr, OPEN_EXISTING,
                                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
                                nullptr);
        if (hf == INVALID_HANDLE_VALUE)
            return false;
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

    void compute_self_executable_hash(uint8_t out_hash[32])
    {
        std::memset(out_hash, 0, 32);
        wchar_t self_path[MAX_PATH * 2] = {};
        DWORD got = GetModuleFileNameW(nullptr, self_path,
                                         static_cast<DWORD>(sizeof(self_path) / sizeof(self_path[0])));
        if (got == 0 || got >= sizeof(self_path) / sizeof(self_path[0]))
            return;
        sha256_file_path(self_path, out_hash);
    }

    bool build_proof_buffer(DWORD ida_pid,
                              const std::vector<uint8_t>& pipe_secret,
                              const std::string& plan,
                              proof_buffer_t& out)
    {
        out = {};
        out.magic = aida_manual_map::kProofMagic;
        out.version = aida_manual_map::kProofVersion;
        out.flags = 0;
        out.parent_pid = GetCurrentProcessId();
        out.ida_pid = ida_pid;
        out.timestamp_unix = static_cast<uint64_t>(std::time(nullptr));

        uint64_t epoch = static_cast<uint64_t>(g_sa_settings.license_issued_at);
        if (epoch == 0)
            epoch = out.timestamp_unix;
        out.feature_epoch = epoch;

        uint8_t nonce[32] = {};
        if (RAND_bytes(nonce, sizeof(nonce)) != 1)
            return false;
        std::memcpy(&out.runtime_nonce_seed, nonce, 8);
        if (out.runtime_nonce_seed == 0)
            out.runtime_nonce_seed = 0xA1DAA1DAA1DAA1DAULL;

        out.plan_id_hash = fnv1a64(plan);

        if (pipe_secret.size() != aida_manual_map::kPipeSecretLen)
            return false;
        std::memcpy(out.pipe_secret, pipe_secret.data(), pipe_secret.size());

        std::string ai_key = g_sa_settings.license_auth_hmac_key_b64;
        size_t copy_n = std::min<size_t>(ai_key.size(), aida_manual_map::kAiSessionKeyLen);
        std::memcpy(out.ai_session_key, ai_key.data(), copy_n);

        std::string p = plan.empty() ? std::string("standalone") : plan;
        size_t plan_n = std::min<size_t>(p.size(), aida_manual_map::kProofPlanLen - 1);
        std::memcpy(out.plan, p.data(), plan_n);

        compute_self_executable_hash(out.forbidden_hash_standalone);
        std::memcpy(out.forbidden_hash_plugin, g_aida_plugin_input_sha256,
                    sizeof(g_aida_plugin_input_sha256) < aida_manual_map::kForbiddenHashLen
                        ? sizeof(g_aida_plugin_input_sha256)
                        : aida_manual_map::kForbiddenHashLen);
        std::memset(out.forbidden_hash_arc, 0, aida_manual_map::kForbiddenHashLen);
        return true;
    }

    void close_session_handles_locked()
    {
        if (!g_session)
            return;
        if (g_session->ida_thread)
        {
            CloseHandle(g_session->ida_thread);
            g_session->ida_thread = nullptr;
        }
        if (g_session->ida_process)
        {
            CloseHandle(g_session->ida_process);
            g_session->ida_process = nullptr;
        }
    }
}

namespace ida_injector
{
    void shutdown_pipe_server()
    {
        std::lock_guard<std::mutex> lk(g_session_mutex);
        if (!g_session)
            return;
        g_session->shutdown_requested.store(true, std::memory_order_release);
    }

    bool launch_ida_with_aida(const std::string& target_file_or_empty,
                                std::string& err_out)
    {
        ::diag::log_tagged_critical("ida_inject", "launch_ida_with_aida_enter");
        std::string ida_path = discover_ida_path();
        ::diag::log_tagged_fmt("ida_inject", "discover_ida_path returned='%s'", ida_path.c_str());
        if (ida_path.empty() || !validate_ida_path(ida_path))
        {
            err_out = "IDA executable path is not configured (looking for ida.exe, ida64.exe, idat.exe, or idat64.exe). Set it in AiDA settings or pick the file when prompted.";
            ::diag::log_tagged_critical("ida_inject", "discover_ida_path_failed");
            return false;
        }

        if (g_sa_settings.ida_pro_path != ida_path)
        {
            persist_ida_path(ida_path);
        }

        ::diag::log_tagged("ida_inject", "decrypt_plugin_bytes_pre");
        std::vector<uint8_t> dll_bytes;
        if (!decrypt_plugin_bytes(dll_bytes))
        {
            err_out = "Embedded AiDA.dll could not be decrypted (build watermark mismatch?)";
            ::diag::log_tagged_critical("ida_inject", "decrypt_plugin_bytes_FAIL");
            return false;
        }
        ::diag::log_tagged_fmt("ida_inject", "decrypt_plugin_bytes_ok size=%zu", dll_bytes.size());

        ::diag::log_tagged_fmt("ida_inject", "spawn_ida_process_pre target='%s'",
            target_file_or_empty.c_str());
        HANDLE job = nullptr;
        HANDLE initial_process = nullptr;
        HANDLE initial_thread = nullptr;
        DWORD initial_pid = 0;
        if (!spawn_ida_process(ida_path, target_file_or_empty,
                                  job, initial_process, initial_thread,
                                  initial_pid, err_out))
        {
            ::diag::log_tagged_critical_fmt("ida_inject", "spawn_ida_process_FAIL err='%s'",
                err_out.c_str());
            return false;
        }
        ::diag::log_tagged_fmt("ida_inject", "spawn_ida_process_ok pid=%lu",
            static_cast<unsigned long>(initial_pid));

        bool permitted = driver_bridge::kernel_anti_dump_permit_pid(initial_pid);
        ::diag::log_tagged_critical_fmt("ida_inject",
            "kernel_anti_dump_permit_pid pid=%lu result=%d (whitelisted from WhosWho continuous_anti_dump kill list)",
            static_cast<unsigned long>(initial_pid),
            permitted ? 1 : 0);
        if (!permitted)
        {
            bool stopped = driver_bridge::kernel_anti_dump_stop_continuous();
            ::diag::log_tagged_critical_fmt("ida_inject",
                "kernel_anti_dump_stop_continuous fallback result=%d (driver does not support PID whitelist; disabling kill timer for the rest of this session)",
                stopped ? 1 : 0);
        }

        for (int i = 0; i < 20; ++i)
        {
            DWORD wres = WaitForSingleObject(initial_process, 50);
            if (wres == WAIT_OBJECT_0)
            {
                DWORD exit_code = 0;
                GetExitCodeProcess(initial_process, &exit_code);
                ::diag::log_tagged_critical_fmt("ida_inject",
                    "EARLY_DEATH ida.exe died %d ms after ResumeThread, exit_code=0x%08lX (STATUS_*) — driver/AV killed it, or IDA crashed at startup",
                    (i + 1) * 50,
                    static_cast<unsigned long>(exit_code));
                char ec_buf[32] = {};
                std::snprintf(ec_buf, sizeof(ec_buf), "0x%08lX", static_cast<unsigned long>(exit_code));
                err_out = std::string("IDA exited immediately after spawn (exit_code=")
                    + ec_buf + ") — likely killed by AV/driver/anti-tamper";
                TerminateJobObject(job, 1);
                CloseHandle(initial_thread);
                CloseHandle(initial_process);
                CloseHandle(job);
                return false;
            }
            else if (wres == WAIT_FAILED)
            {
                DWORD ec = GetLastError();
                ::diag::log_tagged_critical_fmt("ida_inject",
                    "EARLY_WAIT_FAILED iter=%d err=%lu", i, static_cast<unsigned long>(ec));
                break;
            }
        }
        ::diag::log_tagged("ida_inject", "early_death_check_passed (ida.exe alive after 1s)");

        ::diag::log_tagged("ida_inject", "wait_for_ida_ui_ready_pre");
        wait_for_ida_ui_ready(initial_process, 5000);
        ::diag::log_tagged("ida_inject", "wait_for_ida_ui_ready_post");

        ::diag::log_tagged("ida_inject", "wait_for_settled_target_pre budget_ms=120000");
        HANDLE process = nullptr;
        DWORD pid = 0;
        if (!wait_for_settled_target(job, initial_process, initial_pid,
                                       120000, process, pid))
        {
            err_out = "Could not lock onto a settled IDA process within the timeout window";
            ::diag::log_tagged_critical("ida_inject", "wait_for_settled_target_TIMEOUT");
            TerminateJobObject(job, 1);
            CloseHandle(initial_thread);
            CloseHandle(initial_process);
            CloseHandle(job);
            return false;
        }
        ::diag::log_tagged_fmt("ida_inject", "wait_for_settled_target_ok pid=%lu",
            static_cast<unsigned long>(pid));

        if (process != initial_process)
        {
            inject_log("ida_inject_target_handoff initial=%lu settled=%lu",
                        static_cast<unsigned long>(initial_pid),
                        static_cast<unsigned long>(pid));
        }
        CloseHandle(initial_thread);
        CloseHandle(initial_process);

        std::filesystem::path ida_path_p(widen(ida_path));
        std::string ida_install_dir = narrow(ida_path_p.parent_path().wstring());
        std::string ida_basename = narrow(ida_path_p.filename().wstring());

        std::vector<std::wstring> required = collect_required_imports(dll_bytes);
        required.push_back(L"ntdll.dll");
        required.push_back(L"kernel32.dll");
        std::map<std::wstring, remote_module_info_t> mods;
        std::string load_err;
        if (!ensure_modules_loaded(process, required, 5000, mods, load_err))
        {
            err_out = "Required modules not present in " + ida_basename + ": " + load_err;
            TerminateJobObject(job, 1);
            CloseHandle(process);
            CloseHandle(job);
            return false;
        }

        uint64_t remote_base = 0;
        LPVOID alloc = VirtualAllocEx(process,
                                        reinterpret_cast<LPVOID>(g_aida_plugin_preferred_base),
                                        g_aida_plugin_image_size,
                                        MEM_COMMIT | MEM_RESERVE,
                                        PAGE_READWRITE);
        if (!alloc)
        {
            alloc = VirtualAllocEx(process, nullptr,
                                     g_aida_plugin_image_size,
                                     MEM_COMMIT | MEM_RESERVE,
                                     PAGE_READWRITE);
        }
        auto fail = [&](const std::string& msg) -> bool {
            err_out = msg;
            if (alloc) VirtualFreeEx(process, alloc, 0, MEM_RELEASE);
            shutdown_pipe_server();
            TerminateJobObject(job, 1);
            CloseHandle(process);
            CloseHandle(job);
            return false;
        };

        if (!alloc)
            return fail("VirtualAllocEx for image failed err="
                + std::to_string(static_cast<unsigned long>(GetLastError())));
        remote_base = reinterpret_cast<uint64_t>(alloc);

        prepared_image_t img{};
        if (!layout_image(dll_bytes, remote_base, img))
            return fail("layout_image failed (PE structure invalid)");

        if (!apply_relocations_local(img))
            return fail("apply_relocations failed (delta="
                + std::to_string(static_cast<int64_t>(remote_base - g_aida_plugin_preferred_base))
                + ")");

        uint64_t load_library_va = 0;
        if (!find_remote_export_va(process, mods, L"kernel32.dll", "LoadLibraryA", load_library_va))
            return fail("Could not resolve kernel32!LoadLibraryA in remote process");

        std::string ires;
        if (!resolve_imports_remote(img, process, load_library_va, ida_install_dir, mods, ires))
            return fail("import resolution failed: " + ires);

        if (!transfer_image_to_remote(process, img, err_out))
        {
            VirtualFreeEx(process, alloc, 0, MEM_RELEASE);
            shutdown_pipe_server();
            TerminateJobObject(job, 1);
            CloseHandle(process);
            CloseHandle(job);
            return false;
        }

        std::vector<uint8_t> pipe_secret(aida_manual_map::kPipeSecretLen, 0);
        if (RAND_bytes(pipe_secret.data(),
                        static_cast<int>(pipe_secret.size())) != 1)
            return fail("RAND_bytes failed for pipe secret");
        std::string plan = g_sa_settings.license_plan;
        proof_buffer_t proof{};
        if (!build_proof_buffer(pid, pipe_secret, plan, proof))
            return fail("failed to build proof buffer");

        {
            std::lock_guard<std::mutex> lk(g_session_mutex);
            g_session = std::make_unique<injector_session_t>();
            g_session->ida_pid = pid;
            g_session->ida_process = process;
            g_session->ida_thread = nullptr;
            g_session->pipe_secret = pipe_secret;
            g_session->ai_session_key.assign(
                proof.ai_session_key,
                proof.ai_session_key + aida_manual_map::kAiSessionKeyLen);
            g_session->plan = plan;
            g_session->parent_pid = proof.parent_pid;
            g_session->timestamp_unix = proof.timestamp_unix;
            g_session->feature_epoch = proof.feature_epoch;
            g_session->runtime_nonce_seed = proof.runtime_nonce_seed;
            g_session->plan_id_hash = proof.plan_id_hash;
            g_session->active.store(true, std::memory_order_release);
        }

        ::diag::log_tagged("ida_inject", "pipe_server_thread_spawn_pre");
        HANDLE pipe_thread = CreateThread(nullptr, 0,
            [](LPVOID) -> DWORD {
                pipe_server_thread();
                return 0;
            },
            nullptr, 0, nullptr);
        if (!pipe_thread)
        {
            DWORD ec = GetLastError();
            ::diag::log_tagged_critical_fmt("ida_inject",
                "pipe_server_thread_CreateThread_FAIL err=%lu (post-seal_handles, expected after activation hardening)",
                static_cast<unsigned long>(ec));
            work_queue::post([]() { pipe_server_thread(); });
            ::diag::log_tagged("ida_inject", "pipe_server_thread_dispatched_via_work_queue");
        }
        else
        {
            CloseHandle(pipe_thread);
            ::diag::log_tagged("ida_inject", "pipe_server_thread_spawn_ok");
        }
        Sleep(200);

        auto ntdll_it = mods.find(L"ntdll.dll");
        if (ntdll_it == mods.end())
            return fail("ntdll.dll not present in remote enumeration");
        std::wstring ntdll_path = ntdll_it->second.path;
        uint64_t ntdll_base = ntdll_it->second.base;

        std::string boot_err;
        if (!inject_bootstrap_and_run(process, img, proof, ntdll_path, ntdll_base, boot_err))
            return fail("bootstrap injection failed: " + boot_err);

        std::memset(&proof, 0, sizeof(proof));
        SecureZeroMemory(pipe_secret.data(), pipe_secret.size());
        SecureZeroMemory(dll_bytes.data(), dll_bytes.size());

        inject_log("ida_inject_complete pid=%lu base=0x%llx size=0x%x",
              static_cast<unsigned long>(pid),
              static_cast<unsigned long long>(remote_base),
              static_cast<unsigned>(g_aida_plugin_image_size));
        CloseHandle(job);
        return true;
    }
}

namespace ida_injector
{
    bool prompt_and_persist_ida_path(HWND owner, std::string& path_out)
    {
        std::string picked = prompt_for_ida_exe(owner);
        if (picked.empty() || !validate_ida_path(picked))
            return false;
        persist_ida_path(picked);
        path_out = picked;
        return true;
    }
}
