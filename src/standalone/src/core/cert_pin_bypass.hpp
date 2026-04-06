#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "comm.h"
#include "standalone_driver.hpp"

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

    auto make_pattern = [](const std::vector<uint8_t>& bytes, const std::vector<uint8_t>& m) -> bypass_signature {
        bypass_signature sig;
        sig.pattern = bytes;
        sig.mask = m;
        return sig;
    };


    {
        bypass_signature sig;
        sig.name = "OpenSSL ssl_verify_cert_chain";
        sig.module_name = "libssl";
        sig.description = "OpenSSL certificate chain verification";

        sig.pattern = { 0x48, 0x83, 0xEC, 0x48, 0x48, 0x89, 0x5C, 0x24 };
        sig.mask    = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
        sig.patch = { 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3 };
        sig.return_success = true;
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


inline int scan_and_bypass(uint32_t target_pid) {
    if (!device || !device->is_connected()) return -1;


    if (g_state.signatures.empty()) init_signature_database();


    uint32_t original_pid = device->get_process_id();


    device->clear_process_context();
    device->set_process_id(target_pid);
    auto target_image = device->find_image();
    if (!target_image) {
        device->clear_process_context();
        if (original_pid) device->set_process_id(original_pid);
        return -1;
    }
    device->solve_dtb();

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

            uint8_t pe_buf[0x200] = {};
            device->read_raw(mod_base, pe_buf, sizeof(pe_buf));
            auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(pe_buf);
            if (dos->e_magic == IMAGE_DOS_SIGNATURE && dos->e_lfanew < 0x180) {
                auto nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(pe_buf + dos->e_lfanew);
                mod_size = nt->OptionalHeader.SizeOfImage;
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


        constexpr size_t CHUNK_SIZE = 0x10000;
        bool found = false;

        for (uint64_t offset = 0; offset < mod_size && !found; offset += CHUNK_SIZE) {
            size_t read_size = static_cast<size_t>(std::min(static_cast<uint64_t>(CHUNK_SIZE),
                static_cast<uint64_t>(mod_size) - offset));
            std::vector<uint8_t> chunk(read_size);
            size_t actually_read = device->read_raw(mod_base + offset, chunk.data(), read_size);
            if (actually_read == 0) continue;
            chunk.resize(actually_read);


            for (size_t i = 0; i + sig.pattern.size() <= chunk.size(); i++) {
                if (pattern_match(chunk.data() + i, chunk.size() - i,
                                  sig.pattern.data(), sig.mask.data(), sig.pattern.size())) {
                    uint64_t addr = mod_base + offset + i;


                    applied_bypass bypass;
                    bypass.signature_name = sig.name;
                    bypass.module_name = sig.module_name;
                    bypass.address = addr;
                    bypass.patch_bytes = sig.patch;
                    bypass.original_bytes.resize(sig.patch.size());
                    device->read_raw(addr, bypass.original_bytes.data(), bypass.original_bytes.size());


                    size_t written = device->write_raw(addr, sig.patch.data(), sig.patch.size());
                    if (written == sig.patch.size()) {
                        bypass.active = true;
                        g_state.active_bypasses.push_back(std::move(bypass));
                        bypasses_applied++;
                        found = true;
                    }
                    break;
                }
            }
        }
    }


    device->clear_process_context();
    if (original_pid) {
        device->set_process_id(original_pid);
        device->find_image();
        device->solve_dtb();
    }

    return bypasses_applied;
}


inline int revert_all_bypasses() {
    if (!device || !device->is_connected()) return -1;
    if (g_state.target_pid == 0) return 0;

    uint32_t original_pid = device->get_process_id();

    device->clear_process_context();
    device->set_process_id(g_state.target_pid);
    device->find_image();
    device->solve_dtb();

    std::lock_guard<std::mutex> lock(g_state.mutex);
    int reverted = 0;
    for (auto& bypass : g_state.active_bypasses) {
        if (!bypass.active) continue;
        size_t written = device->write_raw(bypass.address, bypass.original_bytes.data(), bypass.original_bytes.size());
        if (written == bypass.original_bytes.size()) {
            bypass.active = false;
            reverted++;
        }
    }

    device->clear_process_context();
    if (original_pid) {
        device->set_process_id(original_pid);
        device->find_image();
        device->solve_dtb();
    }

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
