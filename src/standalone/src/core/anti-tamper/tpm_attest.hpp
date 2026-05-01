#pragma once

#include <windows.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <intrin.h>

#include <atomic>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <string>
#include <vector>

#pragma comment(lib, "bcrypt.lib")

#ifdef TBS_SUCCESS
#undef TBS_SUCCESS
#endif
#ifdef TBS_E_TPM_NOT_FOUND
#undef TBS_E_TPM_NOT_FOUND
#endif
#ifdef TBS_E_SERVICE_NOT_RUNNING
#undef TBS_E_SERVICE_NOT_RUNNING
#endif

namespace anti_tamper {
namespace tpm_attest {

constexpr uint32_t TBS_SUCCESS                = 0x00000000u;
constexpr uint32_t TBS_E_TPM_NOT_FOUND        = 0x8028400Fu;
constexpr uint32_t TBS_E_SERVICE_NOT_RUNNING  = 0x80284010u;

constexpr uint32_t TPM_VERSION_20             = 2u;

constexpr uint32_t TPM_ST_ATTEST_QUOTE        = 0x8018u;
constexpr uint32_t TPM_CC_GET_RANDOM          = 0x0000017Bu;
constexpr uint32_t TPM_CC_NV_INCREMENT        = 0x00000134u;
constexpr uint32_t TPM_CC_NV_READ             = 0x0000014Eu;
constexpr uint32_t TPM_CC_NV_DEFINE_SPACE     = 0x0000012Au;
constexpr uint32_t TPM_CC_PCR_EXTEND          = 0x00000182u;
constexpr uint32_t TPM_CC_PCR_READ            = 0x0000017Eu;
constexpr uint32_t TPM_CC_QUOTE               = 0x00000158u;
constexpr uint32_t TPM_CC_STARTUP             = 0x00000144u;
constexpr uint32_t TPM_CC_GET_CAPABILITY      = 0x0000017Au;

constexpr uint32_t TPM_RH_OWNER               = 0x40000001u;
constexpr uint32_t TPM_RH_PLATFORM            = 0x4000000Cu;
constexpr uint32_t TPM_RH_NULL                = 0x40000007u;
constexpr uint32_t TPM_RS_PW                  = 0x40000009u;

constexpr uint16_t TPM_ALG_SHA256             = 0x000Bu;
constexpr uint16_t TPM_ALG_NULL               = 0x0010u;
constexpr uint16_t TPM_ALG_RSASSA             = 0x0014u;

constexpr uint32_t TPM_ATTR_NV_PLATFORMCREATE = 0x40000000u;
constexpr uint32_t TPM_ATTR_NV_OWNERWRITE     = 0x00000002u;
constexpr uint32_t TPM_ATTR_NV_AUTHWRITE      = 0x00000004u;
constexpr uint32_t TPM_ATTR_NV_AUTHREAD       = 0x40000000u;
constexpr uint32_t TPM_ATTR_NV_COUNTER        = 0x00000010u;
constexpr uint32_t TPM_ATTR_NV_NO_DA          = 0x02000000u;
constexpr uint32_t TPM_ATTR_NV_PPREAD         = 0x00000001u;

constexpr uint32_t TPM_NV_INDEX_AIDA_COUNTER  = 0x01C40190u;
constexpr uint32_t TPM_PCR_AIDA_VERSION       = 16u;

struct tbs_context_params2_t
{
    uint32_t version;
    uint32_t flags;
};

struct tbs_device_info_t
{
    uint32_t structVersion;
    uint32_t tpmVersion;
    uint32_t tpmInterfaceType;
    uint32_t tpmImpRevision;
};

using tbsi_context_create_fn       = uint32_t (WINAPI*)(const tbs_context_params2_t*, void**);
using tbsi_context_close_fn        = uint32_t (WINAPI*)(void*);
using tbsi_get_device_info_fn      = uint32_t (WINAPI*)(uint32_t, void*);
using tbsip_submit_command_fn      = uint32_t (WINAPI*)(void*, uint32_t, uint32_t, const uint8_t*, uint32_t, uint8_t*, uint32_t*);
using tbsi_physical_presence_fn    = uint32_t (WINAPI*)(void*, const uint8_t*, uint32_t, uint8_t*, uint32_t*);

struct tbs_apis_t
{
    HMODULE                       module;
    tbsi_context_create_fn        Tbsi_Context_Create;
    tbsi_context_close_fn         Tbsip_Context_Close;
    tbsi_get_device_info_fn       Tbsi_GetDeviceInfo;
    tbsip_submit_command_fn       Tbsip_Submit_Command;
};

inline tbs_apis_t& tbs_apis()
{
    static tbs_apis_t inst{};
    return inst;
}

inline std::string& last_error_storage()
{
    static std::string s;
    return s;
}

inline void set_last_error(const char* msg)
{
    last_error_storage() = msg ? msg : "";
}

inline const char* last_error()
{
    return last_error_storage().c_str();
}

inline std::atomic<bool>& tpm_disabled_flag()
{
    static std::atomic<bool> v{false};
    return v;
}

inline std::atomic<bool>& tpm_initialized_flag()
{
    static std::atomic<bool> v{false};
    return v;
}

inline std::mutex& tpm_mutex()
{
    static std::mutex m;
    return m;
}

inline bool load_tbs_apis()
{
    auto& apis = tbs_apis();
    if (apis.module && apis.Tbsi_Context_Create) return true;
    apis.module = LoadLibraryW(L"tbs.dll");
    if (!apis.module)
    {
        set_last_error("tpm_unavailable");
        return false;
    }
    apis.Tbsi_Context_Create  = reinterpret_cast<tbsi_context_create_fn>(GetProcAddress(apis.module, "Tbsi_Context_Create"));
    apis.Tbsip_Context_Close  = reinterpret_cast<tbsi_context_close_fn>(GetProcAddress(apis.module, "Tbsip_Context_Close"));
    apis.Tbsi_GetDeviceInfo   = reinterpret_cast<tbsi_get_device_info_fn>(GetProcAddress(apis.module, "Tbsi_GetDeviceInfo"));
    apis.Tbsip_Submit_Command = reinterpret_cast<tbsip_submit_command_fn>(GetProcAddress(apis.module, "Tbsip_Submit_Command"));
    if (!apis.Tbsi_Context_Create || !apis.Tbsip_Context_Close
        || !apis.Tbsi_GetDeviceInfo || !apis.Tbsip_Submit_Command)
    {
        FreeLibrary(apis.module);
        apis.module = nullptr;
        set_last_error("tpm_unavailable");
        return false;
    }
    return true;
}

inline void* open_tbs_context()
{
    auto& apis = tbs_apis();
    if (!load_tbs_apis()) return nullptr;
    tbs_context_params2_t params{};
    params.version = 2;
    params.flags = 1u << 1;
    void* ctx = nullptr;
    uint32_t st = apis.Tbsi_Context_Create(&params, &ctx);
    if (st != TBS_SUCCESS || !ctx)
    {
        params.flags = 0;
        st = apis.Tbsi_Context_Create(&params, &ctx);
        if (st != TBS_SUCCESS || !ctx)
        {
            tpm_disabled_flag().store(true, std::memory_order_release);
            set_last_error("tpm_unavailable");
            return nullptr;
        }
    }
    return ctx;
}

inline void close_tbs_context(void* ctx)
{
    if (!ctx) return;
    auto& apis = tbs_apis();
    if (apis.Tbsip_Context_Close) apis.Tbsip_Context_Close(ctx);
}

inline uint32_t query_tpm_version()
{
    auto& apis = tbs_apis();
    if (!load_tbs_apis()) return 0;
    tbs_device_info_t info{};
    uint32_t st = apis.Tbsi_GetDeviceInfo(static_cast<uint32_t>(sizeof(info)), &info);
    if (st != TBS_SUCCESS) return 0;
    return info.tpmVersion;
}

inline void put_u16(std::vector<uint8_t>& v, uint16_t x)
{
    v.push_back(static_cast<uint8_t>((x >> 8) & 0xFF));
    v.push_back(static_cast<uint8_t>(x & 0xFF));
}

inline void put_u32(std::vector<uint8_t>& v, uint32_t x)
{
    v.push_back(static_cast<uint8_t>((x >> 24) & 0xFF));
    v.push_back(static_cast<uint8_t>((x >> 16) & 0xFF));
    v.push_back(static_cast<uint8_t>((x >> 8) & 0xFF));
    v.push_back(static_cast<uint8_t>(x & 0xFF));
}

inline void put_u64(std::vector<uint8_t>& v, uint64_t x)
{
    for (int i = 7; i >= 0; --i)
        v.push_back(static_cast<uint8_t>((x >> (i * 8)) & 0xFF));
}

inline uint16_t read_u16(const uint8_t* p)
{
    return static_cast<uint16_t>((p[0] << 8) | p[1]);
}

inline uint32_t read_u32(const uint8_t* p)
{
    return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16)
         | (static_cast<uint32_t>(p[2]) << 8)  |  static_cast<uint32_t>(p[3]);
}

inline uint64_t read_u64(const uint8_t* p)
{
    uint64_t r = 0;
    for (int i = 0; i < 8; ++i)
        r = (r << 8) | static_cast<uint64_t>(p[i]);
    return r;
}

inline void finalize_command_header(std::vector<uint8_t>& cmd, uint16_t tag, uint32_t cc)
{
    cmd[0] = static_cast<uint8_t>((tag >> 8) & 0xFF);
    cmd[1] = static_cast<uint8_t>(tag & 0xFF);
    uint32_t size = static_cast<uint32_t>(cmd.size());
    cmd[2] = static_cast<uint8_t>((size >> 24) & 0xFF);
    cmd[3] = static_cast<uint8_t>((size >> 16) & 0xFF);
    cmd[4] = static_cast<uint8_t>((size >> 8) & 0xFF);
    cmd[5] = static_cast<uint8_t>(size & 0xFF);
    cmd[6] = static_cast<uint8_t>((cc >> 24) & 0xFF);
    cmd[7] = static_cast<uint8_t>((cc >> 16) & 0xFF);
    cmd[8] = static_cast<uint8_t>((cc >> 8) & 0xFF);
    cmd[9] = static_cast<uint8_t>(cc & 0xFF);
}

inline std::vector<uint8_t> begin_command(uint16_t tag, uint32_t cc)
{
    std::vector<uint8_t> v;
    v.reserve(64);
    v.resize(10, 0);
    static_cast<void>(tag);
    static_cast<void>(cc);
    return v;
}

inline bool submit_raw(void* ctx, const uint8_t* in, uint32_t in_len,
                       std::vector<uint8_t>& out)
{
    auto& apis = tbs_apis();
    if (!apis.Tbsip_Submit_Command) return false;
    out.assign(4096, 0);
    uint32_t out_len = static_cast<uint32_t>(out.size());
    uint32_t st = apis.Tbsip_Submit_Command(ctx, 0, 0, in, in_len, out.data(), &out_len);
    if (st != TBS_SUCCESS) { out.clear(); return false; }
    if (out_len < 10) { out.clear(); return false; }
    out.resize(out_len);
    uint32_t resp_code = read_u32(out.data() + 6);
    if (resp_code != 0)
    {
        out.clear();
        return false;
    }
    return true;
}

inline bool initialize()
{
    auto& mtx = tpm_mutex();
    std::lock_guard<std::mutex> lk(mtx);
    if (tpm_initialized_flag().load(std::memory_order_acquire)) return true;
    if (tpm_disabled_flag().load(std::memory_order_acquire))
    {
        set_last_error("tpm_unavailable");
        return false;
    }
    if (!load_tbs_apis())
    {
        tpm_disabled_flag().store(true, std::memory_order_release);
        return false;
    }
    uint32_t ver = query_tpm_version();
    if (ver != TPM_VERSION_20)
    {
        tpm_disabled_flag().store(true, std::memory_order_release);
        set_last_error("tpm_unavailable");
        return false;
    }
    void* ctx = open_tbs_context();
    if (!ctx)
    {
        tpm_disabled_flag().store(true, std::memory_order_release);
        return false;
    }
    close_tbs_context(ctx);
    tpm_initialized_flag().store(true, std::memory_order_release);
    set_last_error("");
    return true;
}

inline bool is_available()
{
    if (tpm_disabled_flag().load(std::memory_order_acquire)) return false;
    if (tpm_initialized_flag().load(std::memory_order_acquire)) return true;
    return initialize();
}

inline bool extend_pcr(uint32_t pcr_index, const uint8_t digest[32])
{
    if (!is_available()) return false;
    auto* ctx = open_tbs_context();
    if (!ctx) return false;

    std::vector<uint8_t> cmd;
    cmd.reserve(64);
    cmd.resize(10, 0);
    put_u32(cmd, pcr_index);
    put_u32(cmd, 9);
    put_u16(cmd, TPM_RS_PW);
    put_u16(cmd, 0);
    cmd.push_back(0);
    put_u16(cmd, 0);
    put_u32(cmd, 1);
    put_u16(cmd, TPM_ALG_SHA256);
    cmd.insert(cmd.end(), digest, digest + 32);

    finalize_command_header(cmd, 0x8002, TPM_CC_PCR_EXTEND);

    std::vector<uint8_t> resp;
    bool ok = submit_raw(ctx, cmd.data(), static_cast<uint32_t>(cmd.size()), resp);
    close_tbs_context(ctx);
    if (!ok) { set_last_error("tpm_pcr_extend_failed"); return false; }
    return true;
}

inline bool read_pcr(uint32_t pcr_index, uint8_t out[32])
{
    if (!is_available()) return false;
    auto* ctx = open_tbs_context();
    if (!ctx) return false;

    std::vector<uint8_t> cmd;
    cmd.reserve(64);
    cmd.resize(10, 0);
    put_u32(cmd, 1);
    put_u16(cmd, TPM_ALG_SHA256);
    cmd.push_back(3);
    cmd.push_back(0);
    cmd.push_back(0);
    cmd.push_back(0);
    if (pcr_index < 24)
    {
        size_t byte_off = pcr_index / 8;
        cmd[cmd.size() - 3 + byte_off] = static_cast<uint8_t>(1u << (pcr_index % 8));
    }

    finalize_command_header(cmd, 0x8001, TPM_CC_PCR_READ);

    std::vector<uint8_t> resp;
    bool ok = submit_raw(ctx, cmd.data(), static_cast<uint32_t>(cmd.size()), resp);
    close_tbs_context(ctx);
    if (!ok || resp.size() < 10 + 8 + 32)
    {
        set_last_error("tpm_pcr_read_failed");
        return false;
    }

    size_t pos = 10 + 4;
    pos += 4;
    pos += 2;
    pos += 1;
    pos += 3;
    pos += 4;
    pos += 2;
    if (resp.size() >= pos + 32)
    {
        memcpy(out, resp.data() + resp.size() - 32, 32);
        return true;
    }
    set_last_error("tpm_pcr_read_short");
    return false;
}

struct quote_result_t
{
    std::vector<uint8_t> attest;
    std::vector<uint8_t> signature;
    bool                 valid;
};

inline bool sign_with_aik(const uint8_t* nonce, uint32_t nonce_len,
                          const uint32_t* pcr_indices, uint32_t pcr_count,
                          quote_result_t& out)
{
    out.attest.clear();
    out.signature.clear();
    out.valid = false;
    if (!is_available()) return false;
    if (!nonce || nonce_len == 0 || nonce_len > 64) { set_last_error("tpm_invalid_nonce"); return false; }
    if (!pcr_indices || pcr_count == 0 || pcr_count > 24) { set_last_error("tpm_invalid_pcr_list"); return false; }

    auto* ctx = open_tbs_context();
    if (!ctx) return false;

    std::vector<uint8_t> cmd;
    cmd.reserve(96);
    cmd.resize(10, 0);
    put_u32(cmd, 0x81000001u);
    put_u32(cmd, 9);
    put_u16(cmd, TPM_RS_PW);
    put_u16(cmd, 0);
    cmd.push_back(0);
    put_u16(cmd, 0);
    put_u16(cmd, static_cast<uint16_t>(nonce_len));
    cmd.insert(cmd.end(), nonce, nonce + nonce_len);
    put_u16(cmd, TPM_ALG_NULL);
    put_u32(cmd, 1);
    put_u16(cmd, TPM_ALG_SHA256);
    cmd.push_back(3);
    cmd.push_back(0);
    cmd.push_back(0);
    cmd.push_back(0);
    for (uint32_t i = 0; i < pcr_count; ++i)
    {
        uint32_t idx = pcr_indices[i];
        if (idx < 24)
        {
            size_t byte_off = idx / 8;
            cmd[cmd.size() - 3 + byte_off] |= static_cast<uint8_t>(1u << (idx % 8));
        }
    }

    finalize_command_header(cmd, 0x8002, TPM_CC_QUOTE);

    std::vector<uint8_t> resp;
    bool ok = submit_raw(ctx, cmd.data(), static_cast<uint32_t>(cmd.size()), resp);
    close_tbs_context(ctx);
    if (!ok)
    {
        set_last_error("tpm_quote_failed");
        return false;
    }

    if (resp.size() < 12)
    {
        set_last_error("tpm_quote_short");
        return false;
    }
    size_t pos = 10;
    pos += 4;
    if (pos + 2 > resp.size()) { set_last_error("tpm_quote_short"); return false; }
    uint16_t attest_len = read_u16(resp.data() + pos);
    pos += 2;
    if (pos + attest_len > resp.size()) { set_last_error("tpm_quote_short"); return false; }
    out.attest.assign(resp.data() + pos, resp.data() + pos + attest_len);
    pos += attest_len;
    if (pos < resp.size())
        out.signature.assign(resp.data() + pos, resp.data() + resp.size());
    out.valid = true;
    return true;
}

inline bool gen_random(uint8_t* buf, uint32_t len)
{
    if (!buf || len == 0 || len > 256) return false;
    if (!is_available()) return false;
    auto* ctx = open_tbs_context();
    if (!ctx) return false;

    std::vector<uint8_t> cmd;
    cmd.reserve(20);
    cmd.resize(10, 0);
    put_u16(cmd, static_cast<uint16_t>(len));
    finalize_command_header(cmd, 0x8001, TPM_CC_GET_RANDOM);

    std::vector<uint8_t> resp;
    bool ok = submit_raw(ctx, cmd.data(), static_cast<uint32_t>(cmd.size()), resp);
    close_tbs_context(ctx);
    if (!ok || resp.size() < 12)
    {
        set_last_error("tpm_random_failed");
        return false;
    }
    size_t pos = 10;
    if (pos + 2 > resp.size()) return false;
    uint16_t got = read_u16(resp.data() + pos);
    pos += 2;
    if (pos + got > resp.size() || got != len) return false;
    memcpy(buf, resp.data() + pos, len);
    return true;
}

inline bool nv_define_counter(uint32_t nv_index)
{
    if (!is_available()) return false;
    auto* ctx = open_tbs_context();
    if (!ctx) return false;

    std::vector<uint8_t> cmd;
    cmd.reserve(96);
    cmd.resize(10, 0);
    put_u32(cmd, TPM_RH_OWNER);
    put_u32(cmd, 9);
    put_u16(cmd, TPM_RS_PW);
    put_u16(cmd, 0);
    cmd.push_back(0);
    put_u16(cmd, 0);
    put_u16(cmd, 0);

    std::vector<uint8_t> public_area;
    public_area.reserve(32);
    put_u32(public_area, nv_index);
    put_u16(public_area, TPM_ALG_SHA256);
    put_u32(public_area, TPM_ATTR_NV_OWNERWRITE | TPM_ATTR_NV_AUTHWRITE
                       | TPM_ATTR_NV_AUTHREAD  | TPM_ATTR_NV_COUNTER
                       | TPM_ATTR_NV_NO_DA);
    put_u16(public_area, 0);
    put_u16(public_area, 8);

    put_u16(cmd, static_cast<uint16_t>(public_area.size()));
    cmd.insert(cmd.end(), public_area.begin(), public_area.end());

    finalize_command_header(cmd, 0x8002, TPM_CC_NV_DEFINE_SPACE);

    std::vector<uint8_t> resp;
    bool ok = submit_raw(ctx, cmd.data(), static_cast<uint32_t>(cmd.size()), resp);
    close_tbs_context(ctx);
    if (!ok)
    {
        set_last_error("tpm_nv_define_failed");
        return false;
    }
    return true;
}

inline bool nv_increment(uint32_t nv_index)
{
    if (!is_available()) return false;
    auto* ctx = open_tbs_context();
    if (!ctx) return false;

    std::vector<uint8_t> cmd;
    cmd.reserve(48);
    cmd.resize(10, 0);
    put_u32(cmd, nv_index);
    put_u32(cmd, nv_index);
    put_u32(cmd, 9);
    put_u16(cmd, TPM_RS_PW);
    put_u16(cmd, 0);
    cmd.push_back(0);
    put_u16(cmd, 0);

    finalize_command_header(cmd, 0x8002, TPM_CC_NV_INCREMENT);

    std::vector<uint8_t> resp;
    bool ok = submit_raw(ctx, cmd.data(), static_cast<uint32_t>(cmd.size()), resp);
    close_tbs_context(ctx);
    if (!ok)
    {
        set_last_error("tpm_nv_increment_failed");
        return false;
    }
    return true;
}

inline bool nv_read_counter(uint32_t nv_index, uint64_t& out_value)
{
    out_value = 0;
    if (!is_available()) return false;
    auto* ctx = open_tbs_context();
    if (!ctx) return false;

    std::vector<uint8_t> cmd;
    cmd.reserve(48);
    cmd.resize(10, 0);
    put_u32(cmd, nv_index);
    put_u32(cmd, nv_index);
    put_u32(cmd, 9);
    put_u16(cmd, TPM_RS_PW);
    put_u16(cmd, 0);
    cmd.push_back(0);
    put_u16(cmd, 0);
    put_u16(cmd, 8);
    put_u16(cmd, 0);

    finalize_command_header(cmd, 0x8002, TPM_CC_NV_READ);

    std::vector<uint8_t> resp;
    bool ok = submit_raw(ctx, cmd.data(), static_cast<uint32_t>(cmd.size()), resp);
    close_tbs_context(ctx);
    if (!ok || resp.size() < 12)
    {
        set_last_error("tpm_nv_read_failed");
        return false;
    }

    size_t pos = 10;
    pos += 4;
    if (pos + 2 > resp.size()) return false;
    uint16_t data_len = read_u16(resp.data() + pos);
    pos += 2;
    if (data_len != 8 || pos + 8 > resp.size()) return false;
    out_value = read_u64(resp.data() + pos);
    return true;
}

inline bool ensure_counter_defined(uint32_t nv_index)
{
    uint64_t v = 0;
    if (nv_read_counter(nv_index, v)) return true;
    return nv_define_counter(nv_index);
}

inline bool extend_version_pcr(const uint8_t binary_sha256[32])
{
    return extend_pcr(TPM_PCR_AIDA_VERSION, binary_sha256);
}

struct cpu_attest_caps_t
{
    bool sgx_supported;
    bool tdx_supported;
    bool sev_snp_supported;
    bool txt_supported;
    bool pluton_supported;
};

inline cpu_attest_caps_t detect_cpu_attest_caps()
{
    cpu_attest_caps_t c{};
    int regs[4] = {};
    __cpuid(regs, 0);
    int max_basic = regs[0];

    char vendor[13] = {};
    memcpy(vendor + 0, &regs[1], 4);
    memcpy(vendor + 4, &regs[3], 4);
    memcpy(vendor + 8, &regs[2], 4);
    vendor[12] = 0;

    if (max_basic >= 7)
    {
        __cpuidex(regs, 7, 0);
        c.sgx_supported = (regs[1] & (1 << 2)) != 0;
        c.tdx_supported = (regs[2] & (1 << 26)) != 0;
    }

    if (memcmp(vendor, "AuthenticAMD", 12) == 0)
    {
        __cpuid(regs, 0x80000000);
        if (static_cast<unsigned int>(regs[0]) >= 0x8000001Fu)
        {
            __cpuid(regs, 0x8000001F);
            c.sev_snp_supported = (regs[0] & (1 << 4)) != 0;
        }
    }

    if (max_basic >= 1)
    {
        __cpuid(regs, 1);
        c.txt_supported = (regs[2] & (1 << 6)) != 0;
    }

    HMODULE pluton = LoadLibraryW(L"WdaPluton.dll");
    if (!pluton) pluton = LoadLibraryW(L"plutonAttestation.dll");
    if (pluton)
    {
        c.pluton_supported = true;
        FreeLibrary(pluton);
    }

    return c;
}

inline bool query_pluton_quote(const uint8_t* nonce, uint32_t nonce_len,
                               std::vector<uint8_t>& out)
{
    out.clear();
    HMODULE pluton = LoadLibraryW(L"WdaPluton.dll");
    if (!pluton) pluton = LoadLibraryW(L"plutonAttestation.dll");
    if (!pluton)
    {
        set_last_error("pluton_unavailable");
        return false;
    }
    using pluton_quote_fn = uint32_t (WINAPI*)(const uint8_t*, uint32_t, uint8_t*, uint32_t*);
    auto fn = reinterpret_cast<pluton_quote_fn>(GetProcAddress(pluton, "PlutonGetAttestationQuote"));
    if (!fn) fn = reinterpret_cast<pluton_quote_fn>(GetProcAddress(pluton, "PlutonAttestQuote"));
    if (!fn)
    {
        FreeLibrary(pluton);
        set_last_error("pluton_unavailable");
        return false;
    }
    out.assign(2048, 0);
    uint32_t out_len = static_cast<uint32_t>(out.size());
    uint32_t st = fn(nonce, nonce_len, out.data(), &out_len);
    FreeLibrary(pluton);
    if (st != 0 || out_len == 0)
    {
        out.clear();
        set_last_error("pluton_quote_failed");
        return false;
    }
    out.resize(out_len);
    return true;
}

inline bool read_intel_me_status(uint32_t& out_status)
{
    out_status = 0;
    HKEY hk = nullptr;
    LSTATUS rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\MEIx64",
        0, KEY_READ, &hk);
    if (rc != ERROR_SUCCESS) return false;
    DWORD val = 0, sz = sizeof(val), tp = 0;
    rc = RegQueryValueExW(hk, L"Start", nullptr, &tp, reinterpret_cast<LPBYTE>(&val), &sz);
    RegCloseKey(hk);
    if (rc != ERROR_SUCCESS) return false;
    out_status = val;
    return true;
}

}
}
