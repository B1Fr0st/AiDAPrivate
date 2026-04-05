#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

namespace cert_pin_bypass {

// ─── Signature Database ───────────────────────────────────────────
// Known certificate verification functions across common SSL/TLS libraries
// Each signature has a name, module, pattern bytes, and the NOP/bypass patch

struct bypass_signature {
    std::string name;          // Human-readable name
    std::string module_name;   // DLL or module to scan within
    std::string description;

    // Pattern to search for (IDA-style: "48 89 5C 24 ?? 48 89 6C 24 ??")
    std::vector<uint8_t> pattern;
    std::vector<uint8_t> mask;  // 0xFF = exact match, 0x00 = wildcard

    // Bypass patch: typically "mov eax, 1; ret" (B8 01 00 00 00 C3) or "xor eax, eax; ret" (31 C0 C3)
    std::vector<uint8_t> patch;

    // If true, the patch should make the function return success (1/TRUE)
    // If false, the patch should make the function return 0 (no error)
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

    // Built-in signature database
    std::vector<bypass_signature> signatures;
};

inline state_t g_state;

// ─── Signature Database ───────────────────────────────────────────

inline void init_signature_database() {
    auto& sigs = g_state.signatures;
    sigs.clear();

    auto make_pattern = [](const std::vector<uint8_t>& bytes, const std::vector<uint8_t>& m) -> bypass_signature {
        bypass_signature sig;
        sig.pattern = bytes;
        sig.mask = m;
        return sig;
    };

    // ── OpenSSL: ssl_verify_cert_chain ───────────────────────
    // Patch to always return 1 (verified)
    {
        bypass_signature sig;
        sig.name = "OpenSSL ssl_verify_cert_chain";
        sig.module_name = "libssl";
        sig.description = "OpenSSL certificate chain verification";
        // Prologue: sub rsp, 48h; mov [rsp+...], rbx
        sig.pattern = { 0x48, 0x83, 0xEC, 0x48, 0x48, 0x89, 0x5C, 0x24 };
        sig.mask    = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
        sig.patch = { 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3 }; // mov eax, 1; ret
        sig.return_success = true;
        sigs.push_back(std::move(sig));
    }

    // ── OpenSSL: X509_verify_cert ────────────────────────────
    {
        bypass_signature sig;
        sig.name = "OpenSSL X509_verify_cert";
        sig.module_name = "libcrypto";
        sig.description = "OpenSSL X509 certificate verification";
        sig.pattern = { 0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x6C, 0x24, 0x10 };
        sig.mask    = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
        sig.patch = { 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3 }; // mov eax, 1; ret
        sig.return_success = true;
        sigs.push_back(std::move(sig));
    }

    // ── BoringSSL: ssl_crypto_x509_session_verify_cert_chain ─
    {
        bypass_signature sig;
        sig.name = "BoringSSL verify_cert_chain";
        sig.module_name = "";  // embedded in exe
        sig.description = "BoringSSL (Chrome/Edge) certificate chain verification";
        sig.pattern = { 0x48, 0x89, 0x5C, 0x24, 0x08, 0x57, 0x48, 0x83, 0xEC, 0x20 };
        sig.mask    = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
        sig.patch = { 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3 }; // mov eax, 1; ret
        sig.return_success = true;
        sigs.push_back(std::move(sig));
    }

    // ── Schannel: CertVerifyCertificateChainPolicy (Windows) ─
    {
        bypass_signature sig;
        sig.name = "Schannel CertVerifyCertificateChainPolicy";
        sig.module_name = "crypt32.dll";
        sig.description = "Windows Schannel certificate chain policy verification";
        sig.pattern = { 0x48, 0x89, 0x5C, 0x24, 0x10, 0x48, 0x89, 0x74, 0x24, 0x18 };
        sig.mask    = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
        sig.patch = { 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3 }; // mov eax, 1; ret (TRUE = verified)
        sig.return_success = true;
        sigs.push_back(std::move(sig));
    }

    // ── WinHTTP: Internal SSL validation stub ────────────────
    {
        bypass_signature sig;
        sig.name = "WinHTTP SSL validation";
        sig.module_name = "winhttp.dll";
        sig.description = "WinHTTP internal TLS certificate callback";
        sig.pattern = { 0x48, 0x8B, 0xC4, 0x48, 0x89, 0x58, 0x08, 0x48, 0x89, 0x68, 0x10 };
        sig.mask    = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
        sig.patch = { 0x31, 0xC0, 0xC3 }; // xor eax, eax; ret (0 = SEC_E_OK)
        sig.return_success = false;
        sigs.push_back(std::move(sig));
    }

    // ── WinINet: InternetErrorDlg cert override ──────────────
    {
        bypass_signature sig;
        sig.name = "WinINet SSL error handler";
        sig.module_name = "wininet.dll";
        sig.description = "WinINet SSL error dialog/callback handler";
        sig.pattern = { 0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x74, 0x24, 0x10, 0x57 };
        sig.mask    = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
        sig.patch = { 0x31, 0xC0, 0xC3 }; // xor eax, eax; ret (ERROR_SUCCESS)
        sig.return_success = false;
        sigs.push_back(std::move(sig));
    }

    // ── .NET: System.Net.Security SslStream verify ───────────
    {
        bypass_signature sig;
        sig.name = ".NET SslStream verification";
        sig.module_name = "System.Net.Security";
        sig.description = ".NET managed SSL certificate verification callback";
        sig.pattern = { 0x48, 0x89, 0x5C, 0x24, 0x10, 0x55, 0x56, 0x57, 0x41, 0x54 };
        sig.mask    = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
        sig.patch = { 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3 }; // mov eax, 1; ret
        sig.return_success = true;
        sigs.push_back(std::move(sig));
    }

    // ── NSS: ssl3_HandleCertificate (Firefox) ────────────────
    {
        bypass_signature sig;
        sig.name = "NSS ssl3_HandleCertificate";
        sig.module_name = "nss3.dll";
        sig.description = "Mozilla NSS SSL certificate handler";
        sig.pattern = { 0x55, 0x48, 0x89, 0xE5, 0x41, 0x57, 0x41, 0x56, 0x41, 0x55 };
        sig.mask    = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
        sig.patch = { 0x31, 0xC0, 0xC3 }; // xor eax, eax; ret (SECSuccess = 0)
        sig.return_success = false;
        sigs.push_back(std::move(sig));
    }
}

// ─── Pattern Matching ─────────────────────────────────────────────

inline bool pattern_match(const uint8_t* data, size_t data_size,
                          const uint8_t* pattern, const uint8_t* mask, size_t pattern_size) {
    if (data_size < pattern_size) return false;
    for (size_t i = 0; i < pattern_size; i++) {
        if ((data[i] & mask[i]) != (pattern[i] & mask[i])) return false;
    }
    return true;
}

// ─── Scan & Apply ─────────────────────────────────────────────────

// Scan a target process for known cert verification signatures and apply bypasses
// Requires the kernel driver to be connected and attached to the target process
// Returns the number of bypasses applied
inline int scan_and_bypass(uint32_t target_pid) {
    if (!device || !device->is_connected()) return -1;

    // Initialize signature database if needed
    if (g_state.signatures.empty()) init_signature_database();

    // Save current device state
    uint32_t original_pid = device->get_process_id();

    // Attach to target
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

    // Get module list
    auto modules = device->enumerate_modules();
    int bypasses_applied = 0;

    std::lock_guard<std::mutex> lock(g_state.mutex);
    g_state.active_bypasses.clear();

    for (auto& sig : g_state.signatures) {
        // Find the target module
        uint64_t mod_base = 0;
        uint32_t mod_size = 0;

        if (sig.module_name.empty()) {
            // Scan the main executable
            mod_base = target_image;
            // Read PE header to get size
            uint8_t pe_buf[0x200] = {};
            device->read_raw(mod_base, pe_buf, sizeof(pe_buf));
            auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(pe_buf);
            if (dos->e_magic == IMAGE_DOS_SIGNATURE && dos->e_lfanew < 0x180) {
                auto nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(pe_buf + dos->e_lfanew);
                mod_size = nt->OptionalHeader.SizeOfImage;
            }
            if (mod_size == 0) mod_size = 0x1000000; // fallback 16MB
        } else {
            for (auto& m : modules) {
                // Case-insensitive partial match
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

        // Read .text section (scan module in chunks)
        constexpr size_t CHUNK_SIZE = 0x10000; // 64KB chunks
        bool found = false;

        for (uint64_t offset = 0; offset < mod_size && !found; offset += CHUNK_SIZE) {
            size_t read_size = static_cast<size_t>(std::min(static_cast<uint64_t>(CHUNK_SIZE),
                static_cast<uint64_t>(mod_size) - offset));
            std::vector<uint8_t> chunk(read_size);
            size_t actually_read = device->read_raw(mod_base + offset, chunk.data(), read_size);
            if (actually_read == 0) continue;
            chunk.resize(actually_read);

            // Scan chunk for pattern
            for (size_t i = 0; i + sig.pattern.size() <= chunk.size(); i++) {
                if (pattern_match(chunk.data() + i, chunk.size() - i,
                                  sig.pattern.data(), sig.mask.data(), sig.pattern.size())) {
                    uint64_t addr = mod_base + offset + i;

                    // Read original bytes
                    applied_bypass bypass;
                    bypass.signature_name = sig.name;
                    bypass.module_name = sig.module_name;
                    bypass.address = addr;
                    bypass.patch_bytes = sig.patch;
                    bypass.original_bytes.resize(sig.patch.size());
                    device->read_raw(addr, bypass.original_bytes.data(), bypass.original_bytes.size());

                    // Write the bypass patch
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

    // Restore original device context
    device->clear_process_context();
    if (original_pid) {
        device->set_process_id(original_pid);
        device->find_image();
        device->solve_dtb();
    }

    return bypasses_applied;
}

// Revert all applied bypasses (restore original bytes)
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

// Get list of currently applied bypasses
inline std::vector<applied_bypass> get_active_bypasses() {
    std::lock_guard<std::mutex> lock(g_state.mutex);
    return g_state.active_bypasses;
}

// Check if bypass is active for a given target
inline bool is_bypass_active() {
    std::lock_guard<std::mutex> lock(g_state.mutex);
    for (auto& b : g_state.active_bypasses) {
        if (b.active) return true;
    }
    return false;
}

// Add custom signature
inline void add_custom_signature(bypass_signature sig) {
    g_state.signatures.push_back(std::move(sig));
}

} // namespace cert_pin_bypass
