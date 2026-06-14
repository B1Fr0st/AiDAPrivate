#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shlobj.h>

#include "cert_profile_manager.hpp"
#include "helpers/diag_log.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <system_error>
#include <vector>

namespace cert_intercept {
namespace profiles {
namespace {

uint64_t tick_ms()
{
    return static_cast<uint64_t>(GetTickCount64());
}

uint64_t elapsed_since(uint64_t start_ms)
{
    const uint64_t now = tick_ms();
    return now >= start_ms ? now - start_ms : 0;
}

std::filesystem::path local_appdata()
{
    wchar_t path[MAX_PATH] = {};
    HRESULT hr = SHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA, nullptr, SHGFP_TYPE_CURRENT, path);
    if (SUCCEEDED(hr) && path[0] != L'\0')
        return std::filesystem::path(path);

    wchar_t temp[MAX_PATH] = {};
    DWORD len = GetTempPathW(MAX_PATH, temp);
    if (len > 0 && len < MAX_PATH)
        return std::filesystem::path(temp);

    return std::filesystem::path(L"C:\\Users\\Public");
}

bool read_binary(const std::filesystem::path& path, std::vector<uint8_t>& out)
{
    std::ifstream in(path, std::ios::binary);
    if (!in)
        return false;
    out.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    return true;
}

bool write_text_if_changed(const std::filesystem::path& path, const std::string& data, std::string& error)
{
    std::error_code ec;
    std::filesystem::create_directories(path.parent_path(), ec);
    if (ec) {
        error = "mkdir_failed:" + std::to_string(ec.value());
        return false;
    }

    std::vector<uint8_t> existing;
    if (read_binary(path, existing) &&
        existing.size() == data.size() &&
        std::equal(existing.begin(), existing.end(), data.begin())) {
        return true;
    }

    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) {
        error = "open_failed";
        return false;
    }
    out.write(data.data(), static_cast<std::streamsize>(data.size()));
    if (!out) {
        error = "write_failed";
        return false;
    }
    return true;
}

bool write_bytes_if_changed(const std::filesystem::path& path, const std::vector<uint8_t>& data, std::string& error)
{
    std::error_code ec;
    std::filesystem::create_directories(path.parent_path(), ec);
    if (ec) {
        error = "mkdir_failed:" + std::to_string(ec.value());
        return false;
    }

    std::vector<uint8_t> existing;
    if (read_binary(path, existing) && existing == data)
        return true;

    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) {
        error = "open_failed";
        return false;
    }
    if (!data.empty())
        out.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
    if (!out) {
        error = "write_failed";
        return false;
    }
    return true;
}

}

std::filesystem::path intercept_root()
{
    return local_appdata() / L"AiDA" / L"Standalone" / L"intercept";
}

std::filesystem::path ca_export_root()
{
    return intercept_root() / L"ca";
}

public_ca_export_t export_public_ca_files(const cert_generator::root_ca_t& ca)
{
    const uint64_t start_ms = tick_ms();
    public_ca_export_t result;
    result.directory = ca_export_root();
    result.pem_path = result.directory / L"aida_root_ca.pem";
    result.der_path = result.directory / L"aida_root_ca.der";

    diag::log_tagged_fmt("cert_profile", "export_public_ca_files begin dir=%s pem=%s der=%s ca_valid=%d",
        result.directory.u8string().c_str(),
        result.pem_path.u8string().c_str(),
        result.der_path.u8string().c_str(),
        ca.valid ? 1 : 0);

    std::string pem;
    if (!cert_generator::export_ca_certificate_pem(ca, pem) || pem.empty()) {
        result.error = "pem_export_failed";
        diag::log_tagged_fmt("cert_profile", "export_public_ca_files pem_export_failed elapsed_ms=%llu",
            static_cast<unsigned long long>(elapsed_since(start_ms)));
        return result;
    }

    std::vector<uint8_t> der;
    if (!cert_generator::export_ca_certificate_der(ca, der) || der.empty()) {
        result.error = "der_export_failed";
        diag::log_tagged_fmt("cert_profile", "export_public_ca_files der_export_failed elapsed_ms=%llu",
            static_cast<unsigned long long>(elapsed_since(start_ms)));
        return result;
    }

    if (!write_text_if_changed(result.pem_path, pem, result.error)) {
        diag::log_tagged_fmt("cert_profile", "export_public_ca_files pem_write_failed err=%s elapsed_ms=%llu",
            result.error.c_str(),
            static_cast<unsigned long long>(elapsed_since(start_ms)));
        return result;
    }

    if (!write_bytes_if_changed(result.der_path, der, result.error)) {
        diag::log_tagged_fmt("cert_profile", "export_public_ca_files der_write_failed err=%s elapsed_ms=%llu",
            result.error.c_str(),
            static_cast<unsigned long long>(elapsed_since(start_ms)));
        return result;
    }

    result.ok = true;
    diag::log_tagged_fmt("cert_profile", "export_public_ca_files done pem_len=%zu der_len=%zu elapsed_ms=%llu",
        pem.size(),
        der.size(),
        static_cast<unsigned long long>(elapsed_since(start_ms)));
    return result;
}

}
}
