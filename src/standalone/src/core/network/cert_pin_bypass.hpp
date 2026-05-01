#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "standalone_driver.hpp"
#include "zydis_disasm.hpp"

#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

namespace cert_pin_bypass {


struct bypass_signature {
    std::string name;
    std::string module_name;
    std::string description;


    std::vector<uint8_t> pattern;
    std::vector<uint8_t> mask;


    std::vector<uint8_t> patch;


    bool return_success = true;


    std::vector<std::string> string_hints;


    std::string export_name;
};

struct applied_bypass {
    std::string     signature_name;
    std::string     module_name;
    uint64_t        address = 0;
    std::vector<uint8_t> original_bytes;
    std::vector<uint8_t> patch_bytes;
    bool            active = false;
};

struct state_t {
    uint32_t    target_pid = 0;
    std::string target_process;
    bool        attached = false;

    std::mutex  mutex;
    std::vector<applied_bypass> active_bypasses;


    std::vector<bypass_signature> signatures;
};

inline state_t g_state;


inline void init_signature_database() {
    auto& sigs = g_state.signatures;
    sigs.clear();

    {
        bypass_signature sig;
        sig.name = "OpenSSL ssl_verify_cert_chain";
        sig.module_name = "libssl";
        sig.description = "OpenSSL certificate chain verification";

        sig.pattern = { 0x48, 0x83, 0xEC, 0x48, 0x48, 0x89, 0x5C, 0x24 };
        sig.mask    = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
        sig.patch = { 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3 };
        sig.return_success = true;
        sig.string_hints = { "ssl_verify_cert_chain", "X509_V_ERR_" };
        sig.export_name = "ssl_verify_cert_chain";
        sigs.push_back(std::move(sig));
    }


    {
        bypass_signature sig;
        sig.name = "OpenSSL X509_verify_cert";
        sig.module_name = "libcrypto";
        sig.description = "OpenSSL X509 certificate verification";
        sig.pattern = { 0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x6C, 0x24, 0x10 };
        sig.mask    = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
        sig.patch = { 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3 };
        sig.return_success = true;
        sig.string_hints = { "X509_verify_cert", "unable to get local issuer certificate" };
        sig.export_name = "X509_verify_cert";
        sigs.push_back(std::move(sig));
    }


    {
        bypass_signature sig;
        sig.name = "BoringSSL verify_cert_chain";
        sig.module_name = "";
        sig.description = "BoringSSL (Chrome/Edge) certificate chain verification";
        sig.pattern = { 0x48, 0x89, 0x5C, 0x24, 0x08, 0x57, 0x48, 0x83, 0xEC, 0x20 };
        sig.mask    = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
        sig.patch = { 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3 };
        sig.return_success = true;
        sig.string_hints = { "CERTIFICATE_VERIFY_FAILED", "ssl_crypto_x509_session_verify_cert_chain" };
        sigs.push_back(std::move(sig));
    }


    {
        bypass_signature sig;
        sig.name = "Schannel CertVerifyCertificateChainPolicy";
        sig.module_name = "crypt32.dll";
        sig.description = "Windows Schannel certificate chain policy verification";
        sig.pattern = { 0x48, 0x89, 0x5C, 0x24, 0x10, 0x48, 0x89, 0x74, 0x24, 0x18 };
        sig.mask    = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
        sig.patch = { 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3 };
        sig.return_success = true;
        sig.string_hints = { "CertVerifyCertificateChainPolicy" };
        sig.export_name = "CertVerifyCertificateChainPolicy";
        sigs.push_back(std::move(sig));
    }


    {
        bypass_signature sig;
        sig.name = "WinHTTP SSL validation";
        sig.module_name = "winhttp.dll";
        sig.description = "WinHTTP internal TLS certificate callback";
        sig.pattern = { 0x48, 0x8B, 0xC4, 0x48, 0x89, 0x58, 0x08, 0x48, 0x89, 0x68, 0x10 };
        sig.mask    = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
        sig.patch = { 0x31, 0xC0, 0xC3 };
        sig.return_success = false;
        sig.string_hints = { "WinHttpSendRequest", "WINHTTP_CALLBACK_STATUS_FLAG_SECURITY" };
        sigs.push_back(std::move(sig));
    }


    {
        bypass_signature sig;
        sig.name = "WinINet SSL error handler";
        sig.module_name = "wininet.dll";
        sig.description = "WinINet SSL error dialog/callback handler";
        sig.pattern = { 0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x74, 0x24, 0x10, 0x57 };
        sig.mask    = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
        sig.patch = { 0x31, 0xC0, 0xC3 };
        sig.return_success = false;
        sig.string_hints = { "InternetErrorDlg", "ERROR_INTERNET_SEC_CERT" };
        sigs.push_back(std::move(sig));
    }


    {
        bypass_signature sig;
        sig.name = ".NET SslStream verification";
        sig.module_name = "System.Net.Security";
        sig.description = ".NET managed SSL certificate verification callback";
        sig.pattern = { 0x48, 0x89, 0x5C, 0x24, 0x10, 0x55, 0x56, 0x57, 0x41, 0x54 };
        sig.mask    = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
        sig.patch = { 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3 };
        sig.return_success = true;
        sig.string_hints = { "System.Net.Security.SslStream", "RemoteCertificateValidationCallback" };
        sigs.push_back(std::move(sig));
    }


    {
        bypass_signature sig;
        sig.name = "NSS ssl3_HandleCertificate";
        sig.module_name = "nss3.dll";
        sig.description = "Mozilla NSS SSL certificate handler";
        sig.pattern = { 0x55, 0x48, 0x89, 0xE5, 0x41, 0x57, 0x41, 0x56, 0x41, 0x55 };
        sig.mask    = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
        sig.patch = { 0x31, 0xC0, 0xC3 };
        sig.return_success = false;
        sig.string_hints = { "ssl3_HandleCertificate", "SEC_ERROR_" };
        sigs.push_back(std::move(sig));
    }
}


inline bool pattern_match(const uint8_t* data, size_t data_size,
                          const uint8_t* pattern, const uint8_t* mask, size_t pattern_size) {
    if (data_size < pattern_size) return false;
    for (size_t i = 0; i < pattern_size; i++) {
        if ((data[i] & mask[i]) != (pattern[i] & mask[i])) return false;
    }
    return true;
}


inline bool verify_function_prologue(uint64_t addr) {
    std::vector<uint8_t> buf;
    if (!driver_bridge::read_memory(addr, 32, buf) || buf.size() < 4) return false;

    AsmInstr ins = zydis_decode_one(buf.data(), static_cast<int>(buf.size()), addr);
    if (ins.len == 0) return false;


    const char* m = ins.mnem;
    if (strcmp(m, "push") == 0) return true;
    if (strcmp(m, "sub") == 0) return true;
    if (strcmp(m, "mov") == 0) return true;
    if (strcmp(m, "int3") == 0) return false;
    if (strcmp(m, "nop") == 0) return false;
    return false;
}


inline uint64_t find_string_in_module(uint64_t mod_base, uint32_t mod_size,
                                       const std::string& needle) {
    constexpr size_t CHUNK_SIZE = 0x10000;
    for (uint64_t offset = 0; offset < mod_size; offset += CHUNK_SIZE) {
        size_t read_size = static_cast<size_t>(
            std::min(static_cast<uint64_t>(CHUNK_SIZE + needle.size()),
                     static_cast<uint64_t>(mod_size) - offset));
        std::vector<uint8_t> chunk;
        if (!driver_bridge::read_memory(mod_base + offset, read_size, chunk) || chunk.size() < needle.size()) continue;

        for (size_t i = 0; i + needle.size() <= chunk.size(); i++) {
            if (memcmp(chunk.data() + i, needle.data(), needle.size()) == 0) {
                return mod_base + offset + i;
            }
        }
    }
    return 0;
}


inline uint64_t find_function_by_string_ref(uint64_t mod_base, uint32_t mod_size,
                                             uint64_t string_addr) {
    constexpr size_t CHUNK_SIZE = 0x10000;
    constexpr size_t MAX_BACKWARD = 256;

    for (uint64_t offset = 0; offset < mod_size; offset += CHUNK_SIZE) {
        size_t read_size = static_cast<size_t>(
            std::min(static_cast<uint64_t>(CHUNK_SIZE),
                     static_cast<uint64_t>(mod_size) - offset));
        std::vector<uint8_t> chunk;
        if (!driver_bridge::read_memory(mod_base + offset, read_size, chunk) || chunk.size() < 7) continue;


        for (size_t i = 0; i + 7 <= chunk.size(); i++) {
            uint64_t ip = mod_base + offset + i;
            AsmInstr ins = zydis_decode_one(chunk.data() + i,
                                            static_cast<int>(chunk.size() - i), ip);
            if (ins.len == 0) continue;


            if (strcmp(ins.mnem, "lea") == 0) {

                if (ins.len >= 7 && (chunk[i] == 0x48 || chunk[i] == 0x4C)) {
                    int32_t disp = 0;
                    memcpy(&disp, chunk.data() + i + 3, 4);
                    uint64_t target = ip + ins.len + disp;
                    if (target == string_addr) {

                        uint64_t search_start = (ip > MAX_BACKWARD) ? ip - MAX_BACKWARD : mod_base;
                        std::vector<uint8_t> backward_buf;
                        if (!driver_bridge::read_memory(search_start,
                            static_cast<size_t>(ip - search_start), backward_buf) || backward_buf.empty()) continue;
                        size_t brd = backward_buf.size();


                        for (size_t b = brd; b > 0; b--) {
                            if (backward_buf[b - 1] == 0xCC || backward_buf[b - 1] == 0x90) {
                                uint64_t candidate = search_start + b;
                                if (verify_function_prologue(candidate)) {
                                    return candidate;
                                }
                            }
                        }
                    }
                }
            }
            i += (ins.len > 1) ? ins.len - 1 : 0;
        }
    }
    return 0;
}


inline uint64_t resolve_bypass_target(const bypass_signature& sig,
                                       uint64_t mod_base, uint32_t mod_size) {

    if (!sig.export_name.empty()) {
        uint64_t addr = driver_bridge::resolve_export(mod_base, sig.export_name.c_str());
        if (addr != 0) return addr;
    }


    for (const auto& hint : sig.string_hints) {
        uint64_t str_addr = find_string_in_module(mod_base, mod_size, hint);
        if (str_addr == 0) continue;
        uint64_t func_addr = find_function_by_string_ref(mod_base, mod_size, str_addr);
        if (func_addr != 0 && verify_function_prologue(func_addr)) {
            return func_addr;
        }
    }


    constexpr size_t CHUNK_SIZE = 0x10000;
    for (uint64_t offset = 0; offset < mod_size; offset += CHUNK_SIZE) {
        size_t read_size = static_cast<size_t>(
            std::min(static_cast<uint64_t>(CHUNK_SIZE),
                     static_cast<uint64_t>(mod_size) - offset));
        std::vector<uint8_t> chunk;
        if (!driver_bridge::read_memory(mod_base + offset, read_size, chunk) || chunk.empty()) continue;

        for (size_t j = 0; j + sig.pattern.size() <= chunk.size(); j++) {
            if (pattern_match(chunk.data() + j, chunk.size() - j,
                              sig.pattern.data(), sig.mask.data(), sig.pattern.size())) {
                return mod_base + offset + j;
            }
        }
    }

    return 0;
}


inline int scan_and_bypass(uint32_t target_pid) {
    if (!driver_bridge::using_kernel_driver()) return -1;


    if (g_state.signatures.empty()) init_signature_database();


    uint32_t original_pid = driver_bridge::attached_pid();


    if (!driver_bridge::attach(target_pid)) {
        if (original_pid) driver_bridge::attach(original_pid);
        return -1;
    }

    driver_bridge::peb_info_t peb_out;
    uint64_t target_image = 0;
    if (driver_bridge::read_peb(peb_out)) {
        target_image = peb_out.image_base;
    }
    if (!target_image) {
        driver_bridge::detach();
        if (original_pid) driver_bridge::attach(original_pid);
        return -1;
    }

    g_state.target_pid = target_pid;
    g_state.attached = true;


    auto modules = driver_bridge::enumerate_modules();
    int bypasses_applied = 0;

    std::lock_guard<std::mutex> lock(g_state.mutex);
    g_state.active_bypasses.clear();

    for (auto& sig : g_state.signatures) {

        uint64_t mod_base = 0;
        uint32_t mod_size = 0;

        if (sig.module_name.empty()) {

            mod_base = target_image;

            std::vector<uint8_t> pe_buf;
            if (driver_bridge::read_memory(mod_base, 0x200, pe_buf) && pe_buf.size() >= 0x200) {
                auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(pe_buf.data());
                if (dos->e_magic == IMAGE_DOS_SIGNATURE && dos->e_lfanew < 0x180) {
                    auto nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(pe_buf.data() + dos->e_lfanew);
                    mod_size = nt->OptionalHeader.SizeOfImage;
                }
            }
            if (mod_size == 0) mod_size = 0x1000000;
        } else {
            for (auto& m : modules) {

                std::string lower_name = m.name;
                std::string lower_sig = sig.module_name;
                for (auto& c : lower_name) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
                for (auto& c : lower_sig) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));

                if (lower_name.find(lower_sig) != std::string::npos) {
                    mod_base = m.base;
                    mod_size = m.size;
                    break;
                }
            }
        }

        if (mod_base == 0 || mod_size == 0) continue;


        uint64_t addr = resolve_bypass_target(sig, mod_base, mod_size);
        if (addr != 0) {
            applied_bypass bypass;
            bypass.signature_name = sig.name;
            bypass.module_name = sig.module_name;
            bypass.address = addr;
            bypass.patch_bytes = sig.patch;
            if (!driver_bridge::read_memory(addr, sig.patch.size(), bypass.original_bytes)) continue;

            if (driver_bridge::write_memory(addr, sig.patch)) {
                bypass.active = true;
                g_state.active_bypasses.push_back(std::move(bypass));
                bypasses_applied++;
            }
        }
    }


    driver_bridge::detach();
    if (original_pid) driver_bridge::attach(original_pid);

    return bypasses_applied;
}


inline int revert_all_bypasses() {
    if (!driver_bridge::using_kernel_driver()) return -1;
    if (g_state.target_pid == 0) return 0;

    uint32_t original_pid = driver_bridge::attached_pid();

    if (!driver_bridge::attach(g_state.target_pid)) {
        if (original_pid) driver_bridge::attach(original_pid);
        return -1;
    }

    std::lock_guard<std::mutex> lock(g_state.mutex);
    int reverted = 0;
    for (auto& bypass : g_state.active_bypasses) {
        if (!bypass.active) continue;
        if (driver_bridge::write_memory(bypass.address, bypass.original_bytes)) {
            bypass.active = false;
            reverted++;
        }
    }

    driver_bridge::detach();
    if (original_pid) driver_bridge::attach(original_pid);

    return reverted;
}


inline std::vector<applied_bypass> get_active_bypasses() {
    std::lock_guard<std::mutex> lock(g_state.mutex);
    return g_state.active_bypasses;
}


inline bool is_bypass_active() {
    std::lock_guard<std::mutex> lock(g_state.mutex);
    for (auto& b : g_state.active_bypasses) {
        if (b.active) return true;
    }
    return false;
}


inline void add_custom_signature(bypass_signature sig) {
    g_state.signatures.push_back(std::move(sig));
}

}
