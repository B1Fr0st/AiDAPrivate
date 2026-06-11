#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include "standalone_license_transport.hpp"

#include <windows.h>
#include <winhttp.h>
#include <wincrypt.h>
#include <bcrypt.h>

#include <atomic>
#include <chrono>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <openssl/evp.h>
#include <openssl/err.h>

#include "../crypto/keys.hpp"
#include "../crypto/wb_ed25519.hpp"
#include "../../helpers/diag_log.hpp"

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")

namespace aida {
namespace license {
namespace transport {

namespace {

constexpr uint32_t kDefaultTimeoutMs = 15000u;
constexpr uint32_t kWatchdogGraceMs = 5000u;
constexpr DWORD kWinhttpRfc5705ExporterId = 173u;
constexpr DWORD kWinhttpServerCbtId = 108u;
constexpr size_t kExporterSize = 32u;
constexpr size_t kSpkiHashSize = 32u;
constexpr size_t kSigSize = 64u;
constexpr char kExporterLabel[] = "EXPORTER-aida-auth-v1";

constexpr wchar_t kDefaultPrimaryHost[]   = L"api.aidapro.net";
constexpr wchar_t kDefaultSecondaryHost[] = L"fallback.aidapro.net";

constexpr uint32_t kAuxMagic    = 0x4D585541u;
constexpr uint32_t kAuxVersion  = 0x00030000u;
constexpr size_t   kAuxBlockSize = 368u;
constexpr size_t   kAuxOffsetVersion       = 4u;
constexpr size_t   kAuxOffsetSpkiPrimary   = 160u;
constexpr size_t   kAuxOffsetSpkiSecondary = 192u;
constexpr size_t   kAuxOffsetPrimaryHost   = 224u;
constexpr size_t   kAuxOffsetSecondaryHost = 288u;
constexpr size_t   kAuxHostNameCap         = 64u;

struct winhttp_api_t {
    HMODULE module = nullptr;

    using fn_open_t           = HINTERNET (WINAPI*)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
    using fn_connect_t        = HINTERNET (WINAPI*)(HINTERNET, LPCWSTR, INTERNET_PORT, DWORD);
    using fn_open_request_t   = HINTERNET (WINAPI*)(HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR*, DWORD);
    using fn_send_request_t   = BOOL (WINAPI*)(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD, DWORD, DWORD_PTR);
    using fn_recv_response_t  = BOOL (WINAPI*)(HINTERNET, LPVOID);
    using fn_query_headers_t  = BOOL (WINAPI*)(HINTERNET, DWORD, LPCWSTR, LPVOID, LPDWORD, LPDWORD);
    using fn_query_avail_t    = BOOL (WINAPI*)(HINTERNET, LPDWORD);
    using fn_read_data_t      = BOOL (WINAPI*)(HINTERNET, LPVOID, DWORD, LPDWORD);
    using fn_close_handle_t   = BOOL (WINAPI*)(HINTERNET);
    using fn_set_timeouts_t   = BOOL (WINAPI*)(HINTERNET, int, int, int, int);
    using fn_set_option_t     = BOOL (WINAPI*)(HINTERNET, DWORD, LPVOID, DWORD);
    using fn_query_option_t   = BOOL (WINAPI*)(HINTERNET, DWORD, LPVOID, LPDWORD);

    fn_open_t          p_open          = nullptr;
    fn_connect_t       p_connect       = nullptr;
    fn_open_request_t  p_open_request  = nullptr;
    fn_send_request_t  p_send_request  = nullptr;
    fn_recv_response_t p_recv_response = nullptr;
    fn_query_headers_t p_query_headers = nullptr;
    fn_query_avail_t   p_query_avail   = nullptr;
    fn_read_data_t     p_read_data     = nullptr;
    fn_close_handle_t  p_close_handle  = nullptr;
    fn_set_timeouts_t  p_set_timeouts  = nullptr;
    fn_set_option_t    p_set_option    = nullptr;
    fn_query_option_t  p_query_option  = nullptr;
};

struct pin_state_t {
    uint8_t pins[2][32];
    std::wstring primary_host;
    std::wstring secondary_host;
    bool primary_valid = false;
    bool secondary_valid = false;
};

std::mutex g_state_mtx;
std::mutex g_openssl_mtx;
bool g_initialized = false;
winhttp_api_t g_api;
pin_state_t g_pins;
pubkey_provider_fn g_pubkey_provider = nullptr;

const char* winhttp_error_name(DWORD gle) noexcept
{
    switch (gle) {
    case ERROR_WINHTTP_TIMEOUT:
        return "ERROR_WINHTTP_TIMEOUT";
    case ERROR_WINHTTP_NAME_NOT_RESOLVED:
        return "ERROR_WINHTTP_NAME_NOT_RESOLVED";
    case ERROR_WINHTTP_CANNOT_CONNECT:
        return "ERROR_WINHTTP_CANNOT_CONNECT";
    case ERROR_WINHTTP_CONNECTION_ERROR:
        return "ERROR_WINHTTP_CONNECTION_ERROR";
    case ERROR_WINHTTP_SECURE_FAILURE:
        return "ERROR_WINHTTP_SECURE_FAILURE";
    default:
        return "WINHTTP_ERROR";
    }
}

std::string format_winhttp_error(const char* stage, DWORD gle)
{
    char buf[160];
    _snprintf_s(buf, sizeof(buf), _TRUNCATE, "%s gle=%lu name=%s",
        stage ? stage : "winhttp_failed",
        static_cast<unsigned long>(gle),
        winhttp_error_name(gle));
    return std::string(buf);
}

void trans_log(const char* step)
{
    static char s_log_path[MAX_PATH] = {};
    static INIT_ONCE s_once = INIT_ONCE_STATIC_INIT;
    BOOL pending = FALSE;
    InitOnceBeginInitialize(&s_once, INIT_ONCE_ASYNC, &pending, nullptr);
    if (pending || s_log_path[0] == '\0') {
        if (!diag::build_log_path("aida_debug.log", s_log_path, sizeof(s_log_path))) {
            strcpy_s(s_log_path, "aida_debug.log");
        }
        InitOnceComplete(&s_once, INIT_ONCE_ASYNC, nullptr);
    }
    HANDLE hf = CreateFileA(s_log_path, FILE_APPEND_DATA | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hf == INVALID_HANDLE_VALUE) { return; }
    SYSTEMTIME st{};
    GetLocalTime(&st);
    char line[1024];
    int len = _snprintf_s(line, sizeof(line), _TRUNCATE,
        "[%02d:%02d:%02d.%03d] [transport] %s\r\n",
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, step);
    if (len > 0) {
        DWORD w = 0;
        WriteFile(hf, line, static_cast<DWORD>(len), &w, nullptr);
    }
    CloseHandle(hf);
}

void trans_log_fmt(const char* fmt, ...)
{
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    _vsnprintf_s(buf, sizeof(buf), _TRUNCATE, fmt, ap);
    va_end(ap);
    trans_log(buf);
}

bool openssl_ed25519_verify(const std::vector<uint8_t>& payload_bytes,
                            const std::vector<uint8_t>& sig_bytes,
                            const uint8_t pubkey[32],
                            const char* phase,
                            std::string& last_error)
{
    bool ok = false;
    std::lock_guard<std::mutex> openssl_lk(g_openssl_mtx);
    EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, pubkey, 32);
    if (!pkey) {
        last_error = "sig_invalid_pkey";
        trans_log_fmt("sig_verify_%s pkey_failed", phase ? phase : "openssl");
        return false;
    }
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        EVP_PKEY_free(pkey);
        last_error = "sig_invalid_ctx";
        trans_log_fmt("sig_verify_%s ctx_failed", phase ? phase : "openssl");
        return false;
    }
    if (EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, pkey) == 1) {
        int rc = EVP_DigestVerify(
            ctx,
            sig_bytes.data(), sig_bytes.size(),
            payload_bytes.data(), payload_bytes.size());
        ok = (rc == 1);
        if (!ok) {
            trans_log_fmt("sig_verify_%s verify_rc=%d", phase ? phase : "openssl", rc);
        }
    } else {
        last_error = "sig_invalid_init";
        trans_log_fmt("sig_verify_%s init_failed", phase ? phase : "openssl");
    }
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return ok;
}

bool resolve_winhttp(winhttp_api_t& api)
{
    api.module = LoadLibraryW(L"winhttp.dll");
    if (!api.module) { return false; }

    api.p_open           = reinterpret_cast<winhttp_api_t::fn_open_t>          (GetProcAddress(api.module, "WinHttpOpen"));
    api.p_connect        = reinterpret_cast<winhttp_api_t::fn_connect_t>       (GetProcAddress(api.module, "WinHttpConnect"));
    api.p_open_request   = reinterpret_cast<winhttp_api_t::fn_open_request_t>  (GetProcAddress(api.module, "WinHttpOpenRequest"));
    api.p_send_request   = reinterpret_cast<winhttp_api_t::fn_send_request_t>  (GetProcAddress(api.module, "WinHttpSendRequest"));
    api.p_recv_response  = reinterpret_cast<winhttp_api_t::fn_recv_response_t> (GetProcAddress(api.module, "WinHttpReceiveResponse"));
    api.p_query_headers  = reinterpret_cast<winhttp_api_t::fn_query_headers_t> (GetProcAddress(api.module, "WinHttpQueryHeaders"));
    api.p_query_avail    = reinterpret_cast<winhttp_api_t::fn_query_avail_t>   (GetProcAddress(api.module, "WinHttpQueryDataAvailable"));
    api.p_read_data      = reinterpret_cast<winhttp_api_t::fn_read_data_t>     (GetProcAddress(api.module, "WinHttpReadData"));
    api.p_close_handle   = reinterpret_cast<winhttp_api_t::fn_close_handle_t>  (GetProcAddress(api.module, "WinHttpCloseHandle"));
    api.p_set_timeouts   = reinterpret_cast<winhttp_api_t::fn_set_timeouts_t>  (GetProcAddress(api.module, "WinHttpSetTimeouts"));
    api.p_set_option     = reinterpret_cast<winhttp_api_t::fn_set_option_t>    (GetProcAddress(api.module, "WinHttpSetOption"));
    api.p_query_option   = reinterpret_cast<winhttp_api_t::fn_query_option_t>  (GetProcAddress(api.module, "WinHttpQueryOption"));

    if (!api.p_open || !api.p_connect || !api.p_open_request || !api.p_send_request ||
        !api.p_recv_response || !api.p_query_headers || !api.p_query_avail ||
        !api.p_read_data || !api.p_close_handle || !api.p_set_timeouts ||
        !api.p_set_option || !api.p_query_option) {
        FreeLibrary(api.module);
        api.module = nullptr;
        return false;
    }
    return true;
}

bool all_zero(const uint8_t* p, size_t n)
{
    for (size_t i = 0; i < n; ++i) {
        if (p[i] != 0u) { return false; }
    }
    return true;
}

std::wstring utf8_to_utf16(const std::string& in)
{
    if (in.empty()) { return std::wstring(); }
    int sz = MultiByteToWideChar(CP_UTF8, 0, in.data(), static_cast<int>(in.size()), nullptr, 0);
    if (sz <= 0) { return std::wstring(); }
    std::wstring out(static_cast<size_t>(sz), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, in.data(), static_cast<int>(in.size()), &out[0], sz);
    return out;
}

std::wstring cstr_to_utf16(const char* in, size_t cap)
{
    size_t n = 0;
    while (n < cap && in[n] != '\0') { ++n; }
    return utf8_to_utf16(std::string(in, n));
}

bool sha256_compute(const uint8_t* data, size_t len, uint8_t out[32])
{
    BCRYPT_ALG_HANDLE h_alg = nullptr;
    BCRYPT_HASH_HANDLE h_hash = nullptr;
    NTSTATUS st = BCryptOpenAlgorithmProvider(&h_alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (st != 0) { return false; }
    st = BCryptCreateHash(h_alg, &h_hash, nullptr, 0, nullptr, 0, 0);
    if (st != 0) {
        BCryptCloseAlgorithmProvider(h_alg, 0);
        return false;
    }
    st = BCryptHashData(h_hash, const_cast<PUCHAR>(data), static_cast<ULONG>(len), 0);
    if (st != 0) {
        BCryptDestroyHash(h_hash);
        BCryptCloseAlgorithmProvider(h_alg, 0);
        return false;
    }
    st = BCryptFinishHash(h_hash, out, 32, 0);
    BCryptDestroyHash(h_hash);
    BCryptCloseAlgorithmProvider(h_alg, 0);
    return st == 0;
}

bool hmac_sha256_compute(const uint8_t* key, size_t key_len,
                         const uint8_t* data, size_t data_len,
                         uint8_t out[32])
{
    BCRYPT_ALG_HANDLE h_alg = nullptr;
    BCRYPT_HASH_HANDLE h_hash = nullptr;
    NTSTATUS st = BCryptOpenAlgorithmProvider(
        &h_alg, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (st != 0) { return false; }
    st = BCryptCreateHash(h_alg, &h_hash, nullptr, 0,
        const_cast<PUCHAR>(key), static_cast<ULONG>(key_len), 0);
    if (st != 0) {
        BCryptCloseAlgorithmProvider(h_alg, 0);
        return false;
    }
    st = BCryptHashData(h_hash, const_cast<PUCHAR>(data), static_cast<ULONG>(data_len), 0);
    if (st != 0) {
        BCryptDestroyHash(h_hash);
        BCryptCloseAlgorithmProvider(h_alg, 0);
        return false;
    }
    st = BCryptFinishHash(h_hash, out, 32, 0);
    BCryptDestroyHash(h_hash);
    BCryptCloseAlgorithmProvider(h_alg, 0);
    return st == 0;
}

bool derive_exporter_from_cbt(const std::vector<uint8_t>& cbt_blob,
                              std::vector<uint8_t>& out_exporter)
{
    out_exporter.clear();
    if (cbt_blob.empty()) { return false; }
    uint8_t prk[32];
    std::vector<uint8_t> salt(kExporterLabel,
        kExporterLabel + sizeof(kExporterLabel) - 1u);
    if (!hmac_sha256_compute(salt.data(), salt.size(),
                             cbt_blob.data(), cbt_blob.size(),
                             prk)) {
        return false;
    }
    std::vector<uint8_t> info;
    info.assign(kExporterLabel, kExporterLabel + sizeof(kExporterLabel) - 1u);
    info.push_back(0x01u);
    uint8_t okm[32];
    if (!hmac_sha256_compute(prk, sizeof(prk),
                             info.data(), info.size(),
                             okm)) {
        std::memset(prk, 0, sizeof(prk));
        return false;
    }
    out_exporter.assign(okm, okm + kExporterSize);
    std::memset(prk, 0, sizeof(prk));
    std::memset(okm, 0, sizeof(okm));
    return true;
}

bool encode_spki_der(PCCERT_CONTEXT cert, std::vector<uint8_t>& out_der)
{
    if (!cert || !cert->pCertInfo) { return false; }
    DWORD encoded_size = 0;
    if (!CryptEncodeObjectEx(
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            X509_PUBLIC_KEY_INFO,
            &cert->pCertInfo->SubjectPublicKeyInfo,
            0,
            nullptr,
            nullptr,
            &encoded_size)) {
        DWORD gle = GetLastError();
        if (gle != ERROR_MORE_DATA) { return false; }
    }
    if (encoded_size == 0u) { return false; }
    out_der.assign(static_cast<size_t>(encoded_size), 0u);
    if (!CryptEncodeObjectEx(
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            X509_PUBLIC_KEY_INFO,
            &cert->pCertInfo->SubjectPublicKeyInfo,
            0,
            nullptr,
            out_der.data(),
            &encoded_size)) {
        out_der.clear();
        return false;
    }
    out_der.resize(static_cast<size_t>(encoded_size));
    return true;
}

bool match_pin_against_chain(PCCERT_CONTEXT leaf,
                             const pin_state_t& pins,
                             std::array<uint8_t, 32>& out_matched_hash,
                             std::string& detail)
{
    if (!pins.primary_valid && !pins.secondary_valid) {
        std::vector<uint8_t> der;
        if (encode_spki_der(leaf, der)) {
            uint8_t hash[32];
            if (sha256_compute(der.data(), der.size(), hash)) {
                std::memcpy(out_matched_hash.data(), hash, 32);
            }
        }
        detail = "no_pins_baked_system_ca_only";
        return true;
    }

    HCERTCHAINENGINE engine = HCCE_CURRENT_USER;
    CERT_CHAIN_PARA chain_para{};
    chain_para.cbSize = sizeof(chain_para);

    PCCERT_CHAIN_CONTEXT chain_ctx = nullptr;
    if (!CertGetCertificateChain(
            engine,
            leaf,
            nullptr,
            leaf->hCertStore,
            &chain_para,
            0,
            nullptr,
            &chain_ctx)) {
        detail = "chain_build_failed";
        return false;
    }
    if (!chain_ctx || chain_ctx->cChain == 0u) {
        if (chain_ctx) { CertFreeCertificateChain(chain_ctx); }
        detail = "chain_empty";
        return false;
    }

    bool matched = false;
    for (DWORD ci = 0; ci < chain_ctx->cChain && !matched; ++ci) {
        const CERT_SIMPLE_CHAIN* simple = chain_ctx->rgpChain[ci];
        if (!simple) { continue; }
        for (DWORD ei = 0; ei < simple->cElement && !matched; ++ei) {
            const CERT_CHAIN_ELEMENT* el = simple->rgpElement[ei];
            if (!el || !el->pCertContext) { continue; }
            std::vector<uint8_t> der;
            if (!encode_spki_der(el->pCertContext, der)) { continue; }
            uint8_t hash[32];
            if (!sha256_compute(der.data(), der.size(), hash)) { continue; }
            if (pins.primary_valid && std::memcmp(hash, pins.pins[0], 32) == 0) {
                std::memcpy(out_matched_hash.data(), hash, 32);
                matched = true;
                break;
            }
            if (pins.secondary_valid && std::memcmp(hash, pins.pins[1], 32) == 0) {
                std::memcpy(out_matched_hash.data(), hash, 32);
                matched = true;
                break;
            }
        }
    }

    CertFreeCertificateChain(chain_ctx);

    if (!matched) {
        detail = "pin_mismatch";
        return false;
    }
    return true;
}

bool load_pin_state_from_aux(pin_state_t& out)
{
    out = pin_state_t{};
    out.primary_host = kDefaultPrimaryHost;
    out.secondary_host = kDefaultSecondaryHost;

    HMODULE h = GetModuleHandleW(nullptr);
    if (!h) { return false; }
    uint8_t* base = reinterpret_cast<uint8_t*>(h);
    IMAGE_DOS_HEADER dos{};
    std::memcpy(&dos, base, sizeof(dos));
    if (dos.e_magic != IMAGE_DOS_SIGNATURE) { return false; }
    IMAGE_NT_HEADERS nt{};
    std::memcpy(&nt, base + dos.e_lfanew, sizeof(nt));
    if (nt.Signature != IMAGE_NT_SIGNATURE) { return false; }

    IMAGE_SECTION_HEADER* sec = reinterpret_cast<IMAGE_SECTION_HEADER*>(
        base + dos.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER)
             + nt.FileHeader.SizeOfOptionalHeader);

    for (unsigned i = 0; i < nt.FileHeader.NumberOfSections; ++i, ++sec) {
        uint8_t* p = base + sec->VirtualAddress;
        size_t sz = sec->Misc.VirtualSize;
        if (sz < kAuxBlockSize || sz > 0x02000000u) { continue; }
        for (size_t j = 0; j + kAuxBlockSize <= sz; j += 4) {
            uint32_t mg = 0;
            std::memcpy(&mg, p + j, 4);
            if (mg != kAuxMagic) { continue; }
            uint32_t ver = 0;
            std::memcpy(&ver, p + j + kAuxOffsetVersion, 4);
            if (ver != kAuxVersion) { continue; }

            std::memcpy(out.pins[0], p + j + kAuxOffsetSpkiPrimary,   32);
            std::memcpy(out.pins[1], p + j + kAuxOffsetSpkiSecondary, 32);
            out.primary_valid = !all_zero(out.pins[0], 32);
            out.secondary_valid = !all_zero(out.pins[1], 32);

            char primary_buf[kAuxHostNameCap + 1u];
            char secondary_buf[kAuxHostNameCap + 1u];
            std::memcpy(primary_buf,   p + j + kAuxOffsetPrimaryHost,   kAuxHostNameCap);
            std::memcpy(secondary_buf, p + j + kAuxOffsetSecondaryHost, kAuxHostNameCap);
            primary_buf[kAuxHostNameCap]   = '\0';
            secondary_buf[kAuxHostNameCap] = '\0';

            if (primary_buf[0] != '\0') {
                std::wstring w = cstr_to_utf16(primary_buf, kAuxHostNameCap);
                if (!w.empty()) { out.primary_host = std::move(w); }
            }
            if (secondary_buf[0] != '\0') {
                std::wstring w = cstr_to_utf16(secondary_buf, kAuxHostNameCap);
                if (!w.empty()) { out.secondary_host = std::move(w); }
            }
            return out.primary_valid;
        }
    }
    return false;
}

struct watchdog_t {
    HINTERNET handle = nullptr;
    winhttp_api_t::fn_close_handle_t p_close = nullptr;
    DWORD deadline_ms = 0;
    volatile LONG finished = 0;
    HANDLE cancel_ev = nullptr;
};

HANDLE start_watchdog(watchdog_t& wd, HINTERNET h, winhttp_api_t::fn_close_handle_t p_close, DWORD deadline_ms)
{
    wd.handle = h;
    wd.p_close = p_close;
    wd.deadline_ms = deadline_ms;
    wd.finished = 0;
    wd.cancel_ev = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    return CreateThread(nullptr, 0, [](LPVOID arg) -> DWORD {
        auto* w = reinterpret_cast<watchdog_t*>(arg);
        DWORD wait = WaitForSingleObject(w->cancel_ev, w->deadline_ms);
        if (wait == WAIT_TIMEOUT &&
            InterlockedCompareExchange(&w->finished, 0, 0) == 0 &&
            w->handle && w->p_close) {
            w->p_close(w->handle);
        }
        return 0;
    }, &wd, 0, nullptr);
}

void stop_watchdog(watchdog_t& wd, HANDLE thread)
{
    InterlockedExchange(&wd.finished, 1);
    if (wd.cancel_ev) { SetEvent(wd.cancel_ev); }
    if (thread) {
        WaitForSingleObject(thread, 1000);
        CloseHandle(thread);
    }
    if (wd.cancel_ev) { CloseHandle(wd.cancel_ev); wd.cancel_ev = nullptr; }
}

bool query_cbt_or_exporter(const winhttp_api_t& api, HINTERNET h_req,
                           std::vector<uint8_t>& out_exporter,
                           std::string& detail)
{
    DWORD size_rfc = 0;
    BOOL rc_size = api.p_query_option(h_req, kWinhttpRfc5705ExporterId, nullptr, &size_rfc);
    DWORD gle_size = GetLastError();
    if (rc_size || (gle_size == ERROR_INSUFFICIENT_BUFFER && size_rfc > 0u)) {
        std::vector<uint8_t> buf(size_rfc > 0u ? size_rfc : kExporterSize, 0u);
        DWORD sz = static_cast<DWORD>(buf.size());
        if (api.p_query_option(h_req, kWinhttpRfc5705ExporterId, buf.data(), &sz) && sz > 0u) {
            buf.resize(sz);
            if (buf.size() >= kExporterSize) {
                out_exporter.assign(buf.begin(), buf.begin() + kExporterSize);
                return true;
            }
            out_exporter = std::move(buf);
            if (out_exporter.size() < kExporterSize) {
                out_exporter.resize(kExporterSize, 0u);
            }
            return true;
        }
    }

    DWORD size_cbt = 0;
    api.p_query_option(h_req, kWinhttpServerCbtId, nullptr, &size_cbt);
    DWORD gle_cbt = GetLastError();
    if (size_cbt == 0u && gle_cbt != ERROR_INSUFFICIENT_BUFFER) {
        detail = "cbt_query_failed";
        return false;
    }
    std::vector<uint8_t> cbt_buf(size_cbt, 0u);
    DWORD sz_cbt = size_cbt;
    if (!api.p_query_option(h_req, kWinhttpServerCbtId, cbt_buf.data(), &sz_cbt) || sz_cbt == 0u) {
        detail = "cbt_query_failed_2";
        return false;
    }
    cbt_buf.resize(sz_cbt);
    if (!derive_exporter_from_cbt(cbt_buf, out_exporter)) {
        detail = "cbt_derive_failed";
        return false;
    }
    return true;
}

bool send_once(const winhttp_api_t& api,
               const pin_state_t& pins,
               const request_t& req,
               const std::wstring& host_override,
               response_t& resp,
               std::string& last_error)
{
    const ULONGLONG t0 = GetTickCount64();
    trans_log_fmt("send_once_begin method_len=%zu path_len=%zu body=%zu headers=%zu timeout_ms=%lu override=%d",
        req.method.size(), req.path.size(), req.body.size(), req.headers.size(),
        static_cast<unsigned long>(req.timeout_ms), host_override.empty() ? 0 : 1);
    trans_log("send_once_phase=open_session");
    HINTERNET h_session = api.p_open(L"AiDAStandalone-Auth/1.0",
                                     WINHTTP_ACCESS_TYPE_NO_PROXY,
                                     WINHTTP_NO_PROXY_NAME,
                                     WINHTTP_NO_PROXY_BYPASS,
                                     0);
    if (!h_session) {
        const DWORD gle = GetLastError();
        last_error = format_winhttp_error("winhttp_open_failed", gle);
        trans_log_fmt("send_once_open_session_failed gle=%lu elapsed_ms=%llu",
            static_cast<unsigned long>(gle),
            static_cast<unsigned long long>(GetTickCount64() - t0));
        return false;
    }
    trans_log_fmt("send_once_phase=session_opened elapsed_ms=%llu",
        static_cast<unsigned long long>(GetTickCount64() - t0));

    DWORD timeout_ms = req.timeout_ms > 0u ? req.timeout_ms : kDefaultTimeoutMs;
    int tmo = static_cast<int>(timeout_ms);
    api.p_set_timeouts(h_session, tmo, tmo, tmo, tmo);

    DWORD proto_flags = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3;
    api.p_set_option(h_session, WINHTTP_OPTION_SECURE_PROTOCOLS, &proto_flags, sizeof(proto_flags));

    DWORD connect_tmo = timeout_ms;
    api.p_set_option(h_session, WINHTTP_OPTION_CONNECT_TIMEOUT, &connect_tmo, sizeof(connect_tmo));

    WINHTTP_RESOLVER_CACHE_CONFIG cache_cfg{};
    cache_cfg.ulMaxResolverCacheEntries = 0u;
    cache_cfg.ulMaxCacheEntryAge = 0u;
    cache_cfg.ulMinCacheEntryTtl = 0u;
    cache_cfg.ullFlags = WINHTTP_RESOLVER_CACHE_CONFIG_FLAG_BYPASS_CACHE;
    api.p_set_option(h_session, WINHTTP_OPTION_RESOLVER_CACHE_CONFIG, &cache_cfg, sizeof(cache_cfg));

    const std::wstring& wired_host = host_override.empty() ? req.host : host_override;
    trans_log_fmt("send_once_phase=connect host_len=%zu elapsed_ms=%llu",
        wired_host.size(), static_cast<unsigned long long>(GetTickCount64() - t0));
    HINTERNET h_connect = api.p_connect(h_session, wired_host.c_str(),
                                        INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!h_connect) {
        const DWORD gle = GetLastError();
        last_error = format_winhttp_error("winhttp_connect_failed", gle);
        trans_log_fmt("send_once_connect_failed gle=%lu elapsed_ms=%llu",
            static_cast<unsigned long>(gle),
            static_cast<unsigned long long>(GetTickCount64() - t0));
        api.p_close_handle(h_session);
        return false;
    }
    trans_log_fmt("send_once_phase=connected elapsed_ms=%llu",
        static_cast<unsigned long long>(GetTickCount64() - t0));

    std::wstring wverb = utf8_to_utf16(req.method.empty() ? std::string("GET") : req.method);
    trans_log_fmt("send_once_phase=open_request method_len=%zu path_len=%zu elapsed_ms=%llu",
        wverb.size(), req.path.size(), static_cast<unsigned long long>(GetTickCount64() - t0));
    HINTERNET h_req = api.p_open_request(h_connect, wverb.c_str(),
                                         req.path.empty() ? L"/" : req.path.c_str(),
                                         nullptr,
                                         WINHTTP_NO_REFERER,
                                         WINHTTP_DEFAULT_ACCEPT_TYPES,
                                         WINHTTP_FLAG_SECURE);
    if (!h_req) {
        const DWORD gle = GetLastError();
        last_error = format_winhttp_error("winhttp_open_request_failed", gle);
        trans_log_fmt("send_once_open_request_failed gle=%lu elapsed_ms=%llu",
            static_cast<unsigned long>(gle),
            static_cast<unsigned long long>(GetTickCount64() - t0));
        api.p_close_handle(h_connect);
        api.p_close_handle(h_session);
        return false;
    }
    trans_log_fmt("send_once_phase=request_opened elapsed_ms=%llu",
        static_cast<unsigned long long>(GetTickCount64() - t0));

    api.p_set_timeouts(h_req, tmo, tmo, tmo, tmo);

    DWORD sec_flags = 0u;
    api.p_set_option(h_req, WINHTTP_OPTION_SECURITY_FLAGS, &sec_flags, sizeof(sec_flags));

    DWORD disable_features = WINHTTP_DISABLE_REDIRECTS | WINHTTP_DISABLE_KEEP_ALIVE | WINHTTP_DISABLE_AUTHENTICATION;
    api.p_set_option(h_req, WINHTTP_OPTION_DISABLE_FEATURE, &disable_features, sizeof(disable_features));

    std::wstring hdr_str;
    hdr_str.reserve(256u + req.headers.size() * 64u);
    for (const auto& kv : req.headers) {
        hdr_str += kv.first;
        hdr_str += L": ";
        hdr_str += kv.second;
        hdr_str += L"\r\n";
    }

    LPCWSTR hdr_ptr = hdr_str.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS : hdr_str.c_str();
    DWORD   hdr_len = hdr_str.empty() ? 0u : static_cast<DWORD>(hdr_str.size());

    LPVOID body_ptr = req.body.empty()
                        ? WINHTTP_NO_REQUEST_DATA
                        : const_cast<uint8_t*>(req.body.data());
    DWORD body_len = static_cast<DWORD>(req.body.size());

    DWORD watchdog_deadline = timeout_ms + kWatchdogGraceMs;

    watchdog_t wd_send;
    trans_log_fmt("send_once_phase=send_request hdr_len=%lu body_len=%lu elapsed_ms=%llu",
        static_cast<unsigned long>(hdr_len), static_cast<unsigned long>(body_len),
        static_cast<unsigned long long>(GetTickCount64() - t0));
    HANDLE wd_send_thread = start_watchdog(wd_send, h_req, api.p_close_handle, watchdog_deadline);
    BOOL send_ok = api.p_send_request(h_req, hdr_ptr, hdr_len, body_ptr, body_len, body_len, 0);
    DWORD send_gle = GetLastError();
    stop_watchdog(wd_send, wd_send_thread);
    trans_log_fmt("send_once_phase=send_request_done ok=%d gle=%lu elapsed_ms=%llu",
        send_ok ? 1 : 0, static_cast<unsigned long>(send_gle),
        static_cast<unsigned long long>(GetTickCount64() - t0));

    if (!send_ok) {
        trans_log_fmt("send_failed gle=%lu", static_cast<unsigned long>(send_gle));
        last_error = format_winhttp_error("winhttp_send_failed", send_gle);
        api.p_close_handle(h_req);
        api.p_close_handle(h_connect);
        api.p_close_handle(h_session);
        return false;
    }

    watchdog_t wd_recv;
    trans_log_fmt("send_once_phase=receive_response elapsed_ms=%llu",
        static_cast<unsigned long long>(GetTickCount64() - t0));
    HANDLE wd_recv_thread = start_watchdog(wd_recv, h_req, api.p_close_handle, watchdog_deadline);
    BOOL recv_ok = api.p_recv_response(h_req, nullptr);
    DWORD recv_gle = GetLastError();
    stop_watchdog(wd_recv, wd_recv_thread);
    trans_log_fmt("send_once_phase=receive_response_done ok=%d gle=%lu elapsed_ms=%llu",
        recv_ok ? 1 : 0, static_cast<unsigned long>(recv_gle),
        static_cast<unsigned long long>(GetTickCount64() - t0));

    if (!recv_ok) {
        trans_log_fmt("recv_failed gle=%lu", static_cast<unsigned long>(recv_gle));
        last_error = format_winhttp_error("winhttp_recv_failed", recv_gle);
        api.p_close_handle(h_req);
        api.p_close_handle(h_connect);
        api.p_close_handle(h_session);
        return false;
    }

    PCCERT_CONTEXT leaf_cert = nullptr;
    DWORD cert_size = sizeof(leaf_cert);
    trans_log_fmt("send_once_phase=query_cert elapsed_ms=%llu",
        static_cast<unsigned long long>(GetTickCount64() - t0));
    if (!api.p_query_option(h_req, WINHTTP_OPTION_SERVER_CERT_CONTEXT, &leaf_cert, &cert_size) || !leaf_cert) {
        const DWORD gle = GetLastError();
        last_error = format_winhttp_error("winhttp_cert_query_failed", gle);
        trans_log_fmt("send_once_cert_query_failed gle=%lu cert_size=%lu elapsed_ms=%llu",
            static_cast<unsigned long>(gle), static_cast<unsigned long>(cert_size),
            static_cast<unsigned long long>(GetTickCount64() - t0));
        api.p_close_handle(h_req);
        api.p_close_handle(h_connect);
        api.p_close_handle(h_session);
        return false;
    }

    std::string pin_detail;
    trans_log_fmt("send_once_phase=pin_check elapsed_ms=%llu",
        static_cast<unsigned long long>(GetTickCount64() - t0));
    bool pinned_ok = match_pin_against_chain(leaf_cert, pins, resp.server_spki_hash, pin_detail);
    CertFreeCertificateContext(leaf_cert);
    if (!pinned_ok) {
        last_error = "pin_invalid";
        trans_log_fmt("pin_check_failed detail=%s", pin_detail.c_str());
        api.p_close_handle(h_req);
        api.p_close_handle(h_connect);
        api.p_close_handle(h_session);
        return false;
    }

    std::string exporter_detail;
    trans_log_fmt("send_once_phase=exporter_query elapsed_ms=%llu",
        static_cast<unsigned long long>(GetTickCount64() - t0));
    if (!query_cbt_or_exporter(api, h_req, resp.tls_exporter, exporter_detail)) {
        last_error = "exporter_unavailable";
        trans_log_fmt("exporter_unavailable detail=%s", exporter_detail.c_str());
        api.p_close_handle(h_req);
        api.p_close_handle(h_connect);
        api.p_close_handle(h_session);
        return false;
    }

    DWORD status_code = 0;
    DWORD scode_size = sizeof(status_code);
    trans_log_fmt("send_once_phase=query_status elapsed_ms=%llu",
        static_cast<unsigned long long>(GetTickCount64() - t0));
    if (!api.p_query_headers(h_req,
                             WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                             WINHTTP_HEADER_NAME_BY_INDEX,
                             &status_code, &scode_size, WINHTTP_NO_HEADER_INDEX)) {
        last_error = format_winhttp_error("winhttp_status_query_failed", GetLastError());
        api.p_close_handle(h_req);
        api.p_close_handle(h_connect);
        api.p_close_handle(h_session);
        return false;
    }
    resp.http_status = status_code;
    trans_log_fmt("send_once_phase=status_ok status=%lu elapsed_ms=%llu",
        static_cast<unsigned long>(status_code),
        static_cast<unsigned long long>(GetTickCount64() - t0));

    {
        wchar_t hdr_name[] = L"X-Debug-Reason";
        wchar_t hdr_buf[192] = {};
        DWORD hdr_size = sizeof(hdr_buf);
        DWORD idx_dbg = 0u;
        if (api.p_query_headers(h_req,
                                WINHTTP_QUERY_CUSTOM,
                                hdr_name,
                                hdr_buf,
                                &hdr_size,
                                &idx_dbg)) {
            resp.debug_reason.clear();
            for (size_t i = 0; hdr_buf[i] != L'\0' && i < (sizeof(hdr_buf)/sizeof(hdr_buf[0])) - 1; ++i) {
                wchar_t c = hdr_buf[i];
                if (c >= 0x20 && c < 0x7F) {
                    resp.debug_reason.push_back(static_cast<char>(c));
                }
            }
        }
    }

    resp.body.clear();
    resp.body.reserve(4096u);
    uint8_t chunk[8192];
    trans_log_fmt("send_once_phase=read_body_begin elapsed_ms=%llu",
        static_cast<unsigned long long>(GetTickCount64() - t0));
    for (;;) {
        DWORD avail = 0u;
        if (!api.p_query_avail(h_req, &avail)) { break; }
        if (avail == 0u) { break; }
        DWORD to_read = avail > sizeof(chunk) ? static_cast<DWORD>(sizeof(chunk)) : avail;
        DWORD got = 0u;
        if (!api.p_read_data(h_req, chunk, to_read, &got)) { break; }
        if (got == 0u) { break; }
        resp.body.insert(resp.body.end(), chunk, chunk + got);
        if (resp.body.size() > 16u * 1024u * 1024u) {
            last_error = "winhttp_body_oversized";
            api.p_close_handle(h_req);
            api.p_close_handle(h_connect);
            api.p_close_handle(h_session);
            return false;
        }
    }

    api.p_close_handle(h_req);
    api.p_close_handle(h_connect);
    api.p_close_handle(h_session);
    trans_log_fmt("send_once_success status=%lu body=%zu elapsed_ms=%llu",
        static_cast<unsigned long>(resp.http_status), resp.body.size(),
        static_cast<unsigned long long>(GetTickCount64() - t0));
    return true;
}

}

bool initialize()
{
    std::lock_guard<std::mutex> lk(g_state_mtx);
    if (g_initialized) { return true; }

    if (!resolve_winhttp(g_api)) {
        trans_log("init_winhttp_resolve_failed");
        return false;
    }

    if (!load_pin_state_from_aux(g_pins)) {
        trans_log("init_no_aux_block_using_system_ca_only");
        g_pins = pin_state_t{};
        g_pins.primary_host = kDefaultPrimaryHost;
        g_pins.secondary_host = kDefaultSecondaryHost;
    }

    if (!g_pins.primary_valid && !g_pins.secondary_valid) {
        trans_log("init_no_pins_baked_relying_on_system_ca");
    }

    g_initialized = true;
    trans_log_fmt("init_ok primary_valid=%d secondary_valid=%d primary_host=%ls",
                  g_pins.primary_valid ? 1 : 0,
                  g_pins.secondary_valid ? 1 : 0,
                  g_pins.primary_host.c_str());
    return true;
}

bool is_initialized()
{
    std::lock_guard<std::mutex> lk(g_state_mtx);
    return g_initialized;
}

void set_pubkey_provider(pubkey_provider_fn fn)
{
    std::lock_guard<std::mutex> lk(g_state_mtx);
    g_pubkey_provider = fn;
}

bool send(const request_t& req, response_t& resp, std::string& last_error)
{
    {
        std::lock_guard<std::mutex> lk(g_state_mtx);
        if (!g_initialized) {
            last_error = "transport_not_initialized";
            return false;
        }
    }

    winhttp_api_t api_local;
    pin_state_t pins_local;
    {
        std::lock_guard<std::mutex> lk(g_state_mtx);
        api_local = g_api;
        pins_local = g_pins;
    }

    resp.http_status = 0u;
    resp.body.clear();
    resp.tls_exporter.clear();
    resp.server_spki_hash.fill(0u);

    const uint32_t backoff_ms[3] = { 200u, 800u, 3000u };

    for (int attempt = 0; attempt < 3; ++attempt) {
        if (attempt > 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(backoff_ms[attempt - 1]));
        }
        std::string err;
        response_t local_resp;
        trans_log_fmt("transport_send_attempt_begin attempt=%d host_len=%zu path_len=%zu",
            attempt + 1, req.host.size(), req.path.size());
        if (send_once(api_local, pins_local, req, std::wstring(), local_resp, err)) {
            resp = std::move(local_resp);
            trans_log_fmt("transport_send_attempt_ok attempt=%d status=%lu body=%zu",
                attempt + 1, static_cast<unsigned long>(resp.http_status), resp.body.size());
            return true;
        }
        last_error = err;
        trans_log_fmt("primary_attempt=%d err=%s", attempt + 1, err.c_str());
        if (err == "pin_invalid") {
            break;
        }
    }

    if (pins_local.secondary_valid && !pins_local.secondary_host.empty()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(backoff_ms[2]));
        std::string err;
        response_t local_resp;
        if (send_once(api_local, pins_local, req, pins_local.secondary_host, local_resp, err)) {
            resp = std::move(local_resp);
            trans_log("secondary_attempt_ok");
            return true;
        }
        last_error = err;
        trans_log_fmt("secondary_attempt_err=%s", err.c_str());
    }

    return false;
}

bool verify_response_signature(
    const std::vector<uint8_t>& payload_bytes,
    const std::vector<uint8_t>& sig_bytes,
    uint8_t kid,
    std::string& last_error)
{
    if (payload_bytes.empty() || sig_bytes.size() != kSigSize) {
        last_error = "sig_invalid";
        return false;
    }

    pubkey_provider_fn provider = nullptr;
    {
        std::lock_guard<std::mutex> lk(g_state_mtx);
        provider = g_pubkey_provider;
    }
    if (!provider) {
        last_error = "sig_invalid";
        return false;
    }

    alignas(32) uint8_t pubkey_a[32];
    alignas(32) uint8_t pubkey_b[32];
    bool got_a = provider(kid, pubkey_a);

    bool got_b = false;
    if (kid >= static_cast<uint8_t>(aida::pubkeys::kid_license_1) &&
        kid <= static_cast<uint8_t>(aida::pubkeys::kid_arc_2)) {
        std::string err_b;
        got_b = aida::pubkeys::load_pubkey(
            static_cast<aida::pubkeys::kid_e>(kid), pubkey_b, err_b);
    }

    bool a_ok = false;
    bool b_ok = false;

    if (got_a) {
        a_ok = openssl_ed25519_verify(payload_bytes, sig_bytes, pubkey_a, "primary", last_error);
    }

    bool wb_self_test_ok = aida::wb_ed25519::self_test_ok();
    if (got_b) {
        if (wb_self_test_ok) {
            b_ok = aida::wb_ed25519::verify(
                payload_bytes.data(), payload_bytes.size(),
                sig_bytes.data(), pubkey_b);
        } else {
            trans_log_fmt("sig_dualverify_wb_unavailable wb_err=%s",
                aida::wb_ed25519::last_error());
            b_ok = false;
        }
    }

    uint8_t pk_diff = 0;
    if (got_a && got_b) {
        for (int i = 0; i < 32; ++i) {
            pk_diff |= static_cast<uint8_t>(pubkey_a[i] ^ pubkey_b[i]);
        }
    }

    SecureZeroMemory(pubkey_a, sizeof(pubkey_a));
    SecureZeroMemory(pubkey_b, sizeof(pubkey_b));

    bool both_loaded = got_a && got_b;
    bool both_passed = a_ok && b_ok;
    bool pks_match = (pk_diff == 0);
    bool accept = both_loaded && both_passed && pks_match;

    if (!accept) {
        if (!got_a || !got_b) {
            trans_log_fmt("sig_dualverify_pubkey_load got_a=%d got_b=%d kid=%u",
                got_a ? 1 : 0, got_b ? 1 : 0, static_cast<unsigned>(kid));
        } else if (!pks_match) {
            trans_log("sig_dualverify_pubkey_share_mismatch");
        } else if (a_ok && !b_ok) {
            if (wb_self_test_ok) {
                trans_log_fmt("sig_dualverify_wb_failed wb_err=%s",
                    aida::wb_ed25519::last_error());
            } else {
                trans_log("sig_dualverify_wb_unavailable_rejected");
            }
        } else if (!a_ok && b_ok) {
            trans_log("sig_dualverify_openssl_failed");
        } else {
            trans_log("sig_dualverify_both_failed");
        }
        last_error = "sig_invalid";
        return false;
    }
    return true;
}

}
}
}
