#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <bcrypt.h>
#include <imagehlp.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

namespace {

constexpr size_t kFingerprintBytes = 32;
constexpr size_t kShareCount = 4;

struct share_descriptor_t {
    const char* anchor_export;
    const char* sentinel_export;
    uint32_t offset;
    uint32_t length;
};

const std::array<share_descriptor_t, kShareCount> kShareDescriptors = {{
    { "aida_share_anchor_a", "k_expected_fingerprint_a", 0u,  256u },
    { "aida_share_anchor_b", "k_expected_fingerprint_b", 16u, 288u },
    { "aida_share_anchor_c", "k_expected_fingerprint_c", 8u,  320u },
    { "aida_share_anchor_d", "k_expected_fingerprint_d", 24u, 272u }
}};

struct section_record_t {
    uint32_t virtual_address;
    uint32_t virtual_size;
    uint32_t raw_offset;
    uint32_t raw_size;
    char name[9];
};

struct pe_layout_t {
    uint64_t image_base;
    uint32_t entry_point_rva;
    uint32_t export_dir_rva;
    uint32_t export_dir_size;
    std::vector<section_record_t> sections;
};

bool is_transient_share_error(DWORD err) {
    return err == ERROR_SHARING_VIOLATION
        || err == ERROR_LOCK_VIOLATION
        || err == ERROR_USER_MAPPED_FILE
        || err == ERROR_ACCESS_DENIED;
}

HANDLE create_with_retry(const std::string& path, DWORD access, DWORD share, DWORD disposition) {
    constexpr int kMaxAttempts = 60;
    constexpr DWORD kBackoffMs = 500;
    HANDLE handle = INVALID_HANDLE_VALUE;
    for (int attempt = 0; attempt < kMaxAttempts; ++attempt) {
        handle = ::CreateFileA(path.c_str(), access, share, nullptr, disposition,
                               FILE_ATTRIBUTE_NORMAL, nullptr);
        if (handle != INVALID_HANDLE_VALUE) {
            return handle;
        }
        DWORD err = ::GetLastError();
        if (!is_transient_share_error(err)) {
            return INVALID_HANDLE_VALUE;
        }
        ::Sleep(kBackoffMs);
    }
    return INVALID_HANDLE_VALUE;
}

bool read_entire_file(const std::string& path, std::vector<uint8_t>& out) {
    HANDLE h = create_with_retry(path, GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING);
    if (h == INVALID_HANDLE_VALUE) {
        std::cerr << "share_fingerprint_baker: failed to open '" << path << "' err=" << ::GetLastError() << std::endl;
        return false;
    }
    LARGE_INTEGER size{};
    if (!::GetFileSizeEx(h, &size) || size.QuadPart <= 0 || size.QuadPart > (1024LL * 1024LL * 1024LL)) {
        ::CloseHandle(h);
        std::cerr << "share_fingerprint_baker: bad size for '" << path << "'" << std::endl;
        return false;
    }
    out.resize(static_cast<size_t>(size.QuadPart));
    DWORD read_total = 0;
    BOOL ok = ::ReadFile(h, out.data(), static_cast<DWORD>(out.size()), &read_total, nullptr);
    ::CloseHandle(h);
    if (!ok || read_total != out.size()) {
        std::cerr << "share_fingerprint_baker: short read on '" << path << "'" << std::endl;
        return false;
    }
    return true;
}

bool write_entire_file(const std::string& path, const std::vector<uint8_t>& buffer) {
    HANDLE h = create_with_retry(path, GENERIC_WRITE, 0, CREATE_ALWAYS);
    if (h == INVALID_HANDLE_VALUE) {
        std::cerr << "share_fingerprint_baker: failed to create '" << path << "' err=" << ::GetLastError() << std::endl;
        return false;
    }
    DWORD written = 0;
    BOOL ok = ::WriteFile(h, buffer.data(), static_cast<DWORD>(buffer.size()), &written, nullptr);
    ::CloseHandle(h);
    if (!ok || written != buffer.size()) {
        std::cerr << "share_fingerprint_baker: short write on '" << path << "'" << std::endl;
        return false;
    }
    return true;
}

bool parse_pe_layout(const std::vector<uint8_t>& file, pe_layout_t& out) {
    if (file.size() < sizeof(IMAGE_DOS_HEADER)) {
        std::cerr << "share_fingerprint_baker: file too small for DOS header" << std::endl;
        return false;
    }
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(file.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        std::cerr << "share_fingerprint_baker: not a DOS image" << std::endl;
        return false;
    }
    if (dos->e_lfanew <= 0 || static_cast<size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS64) > file.size()) {
        std::cerr << "share_fingerprint_baker: bad e_lfanew" << std::endl;
        return false;
    }
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(file.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        std::cerr << "share_fingerprint_baker: bad NT signature" << std::endl;
        return false;
    }
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
        std::cerr << "share_fingerprint_baker: only PE32+ AMD64 supported" << std::endl;
        return false;
    }
    if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        std::cerr << "share_fingerprint_baker: optional header not PE32+" << std::endl;
        return false;
    }
    out.image_base = nt->OptionalHeader.ImageBase;
    out.entry_point_rva = nt->OptionalHeader.AddressOfEntryPoint;
    if (nt->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXPORT) {
        std::cerr << "share_fingerprint_baker: data directory missing export entry" << std::endl;
        return false;
    }
    out.export_dir_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    out.export_dir_size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    if (out.export_dir_rva == 0 || out.export_dir_size == 0) {
        std::cerr << "share_fingerprint_baker: PE has no export directory" << std::endl;
        return false;
    }

    const auto* first_section = IMAGE_FIRST_SECTION(nt);
    const size_t sec_table_offset = reinterpret_cast<const uint8_t*>(first_section) - file.data();
    const size_t sec_table_end = sec_table_offset + static_cast<size_t>(nt->FileHeader.NumberOfSections) * sizeof(IMAGE_SECTION_HEADER);
    if (sec_table_end > file.size()) {
        std::cerr << "share_fingerprint_baker: section table overruns file" << std::endl;
        return false;
    }
    out.sections.clear();
    out.sections.reserve(nt->FileHeader.NumberOfSections);
    for (uint16_t i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        const IMAGE_SECTION_HEADER& sh = first_section[i];
        section_record_t rec{};
        rec.virtual_address = sh.VirtualAddress;
        rec.virtual_size = sh.Misc.VirtualSize;
        rec.raw_offset = sh.PointerToRawData;
        rec.raw_size = sh.SizeOfRawData;
        std::memcpy(rec.name, sh.Name, 8);
        rec.name[8] = '\0';
        out.sections.push_back(rec);
    }
    return true;
}

bool rva_to_file_offset(const pe_layout_t& pe, uint32_t rva, uint32_t length, uint32_t& out_offset) {
    for (const auto& sec : pe.sections) {
        if (sec.virtual_size == 0) {
            continue;
        }
        uint32_t sec_end_va = sec.virtual_address + sec.virtual_size;
        if (rva >= sec.virtual_address && rva < sec_end_va) {
            uint32_t off_in_sec = rva - sec.virtual_address;
            if (off_in_sec + length > sec.raw_size) {
                return false;
            }
            out_offset = sec.raw_offset + off_in_sec;
            return true;
        }
    }
    return false;
}

bool sha256_bytes(const uint8_t* data, size_t len, uint8_t out[kFingerprintBytes]) {
    BCRYPT_ALG_HANDLE alg = nullptr;
    NTSTATUS st = ::BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (st != 0) {
        return false;
    }
    BCRYPT_HASH_HANDLE h = nullptr;
    st = ::BCryptCreateHash(alg, &h, nullptr, 0, nullptr, 0, 0);
    if (st != 0) {
        ::BCryptCloseAlgorithmProvider(alg, 0);
        return false;
    }
    bool ok = false;
    st = ::BCryptHashData(h, const_cast<PUCHAR>(data), static_cast<ULONG>(len), 0);
    if (st == 0) {
        st = ::BCryptFinishHash(h, out, static_cast<ULONG>(kFingerprintBytes), 0);
        ok = (st == 0);
    }
    ::BCryptDestroyHash(h);
    ::BCryptCloseAlgorithmProvider(alg, 0);
    return ok;
}

bool fingerprint_region_is_zero(const std::vector<uint8_t>& file, uint32_t offset) {
    if (offset + kFingerprintBytes > file.size()) {
        return false;
    }
    uint8_t acc = 0;
    for (size_t i = 0; i < kFingerprintBytes; ++i) {
        acc |= file[offset + i];
    }
    return acc == 0;
}

bool find_export_rva(const std::vector<uint8_t>& file, const pe_layout_t& pe, const char* name, uint32_t& out_rva) {
    uint32_t edir_offset = 0;
    if (!rva_to_file_offset(pe, pe.export_dir_rva, static_cast<uint32_t>(sizeof(IMAGE_EXPORT_DIRECTORY)), edir_offset)) {
        std::cerr << "share_fingerprint_baker: export directory RVA does not map to file" << std::endl;
        return false;
    }
    const auto* edir = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(file.data() + edir_offset);
    if (edir->NumberOfNames == 0 || edir->AddressOfNames == 0 || edir->AddressOfNameOrdinals == 0 || edir->AddressOfFunctions == 0) {
        std::cerr << "share_fingerprint_baker: export directory missing tables" << std::endl;
        return false;
    }
    uint32_t names_off = 0;
    uint32_t ords_off = 0;
    uint32_t funcs_off = 0;
    if (!rva_to_file_offset(pe, edir->AddressOfNames, edir->NumberOfNames * 4u, names_off)) return false;
    if (!rva_to_file_offset(pe, edir->AddressOfNameOrdinals, edir->NumberOfNames * 2u, ords_off)) return false;
    if (!rva_to_file_offset(pe, edir->AddressOfFunctions, edir->NumberOfFunctions * 4u, funcs_off)) return false;
    const uint32_t* name_rvas = reinterpret_cast<const uint32_t*>(file.data() + names_off);
    const uint16_t* ords = reinterpret_cast<const uint16_t*>(file.data() + ords_off);
    const uint32_t* func_rvas = reinterpret_cast<const uint32_t*>(file.data() + funcs_off);
    for (uint32_t i = 0; i < edir->NumberOfNames; ++i) {
        uint32_t name_rva = name_rvas[i];
        uint32_t name_off = 0;
        if (!rva_to_file_offset(pe, name_rva, 1u, name_off)) continue;
        const char* sym = reinterpret_cast<const char*>(file.data() + name_off);
        size_t max_len = file.size() - name_off;
        size_t cmp_len = std::strlen(name);
        if (max_len < cmp_len + 1) continue;
        if (std::memcmp(sym, name, cmp_len) == 0 && sym[cmp_len] == '\0') {
            uint16_t ord = ords[i];
            if (ord >= edir->NumberOfFunctions) return false;
            uint32_t fn_rva = func_rvas[ord];
            if (fn_rva == 0) return false;
            if (fn_rva >= pe.export_dir_rva && fn_rva < pe.export_dir_rva + pe.export_dir_size) {
                return false;
            }
            out_rva = fn_rva;
            return true;
        }
    }
    std::cerr << "share_fingerprint_baker: export '" << name << "' not found in PE export table" << std::endl;
    return false;
}

bool fix_checksum(const std::string& path) {
    DWORD header_sum = 0;
    DWORD check_sum = 0;
    DWORD st = ::MapFileAndCheckSumA(const_cast<LPSTR>(path.c_str()), &header_sum, &check_sum);
    if (st != CHECKSUM_SUCCESS) {
        std::cerr << "share_fingerprint_baker: MapFileAndCheckSumA failed status=" << st << std::endl;
        return false;
    }
    HANDLE h = create_with_retry(path, GENERIC_READ | GENERIC_WRITE, 0, OPEN_EXISTING);
    if (h == INVALID_HANDLE_VALUE) {
        std::cerr << "share_fingerprint_baker: cannot open for checksum write err=" << ::GetLastError() << std::endl;
        return false;
    }
    HANDLE mapping = ::CreateFileMappingA(h, nullptr, PAGE_READWRITE, 0, 0, nullptr);
    if (mapping == nullptr) {
        ::CloseHandle(h);
        std::cerr << "share_fingerprint_baker: CreateFileMappingA failed err=" << ::GetLastError() << std::endl;
        return false;
    }
    void* base = ::MapViewOfFile(mapping, FILE_MAP_WRITE, 0, 0, 0);
    if (base == nullptr) {
        ::CloseHandle(mapping);
        ::CloseHandle(h);
        std::cerr << "share_fingerprint_baker: MapViewOfFile failed err=" << ::GetLastError() << std::endl;
        return false;
    }
    PIMAGE_NT_HEADERS nt = ::ImageNtHeader(base);
    if (nt == nullptr) {
        ::UnmapViewOfFile(base);
        ::CloseHandle(mapping);
        ::CloseHandle(h);
        std::cerr << "share_fingerprint_baker: ImageNtHeader failed" << std::endl;
        return false;
    }
    nt->OptionalHeader.CheckSum = check_sum;
    ::FlushViewOfFile(base, 0);
    ::UnmapViewOfFile(base);
    ::CloseHandle(mapping);
    ::CloseHandle(h);
    return true;
}

bool run_bake(const std::string& input_path, const std::string& output_path) {
    std::vector<uint8_t> file;
    if (!read_entire_file(input_path, file)) {
        return false;
    }
    pe_layout_t layout{};
    if (!parse_pe_layout(file, layout)) {
        return false;
    }

    std::array<uint32_t, kShareCount> sentinel_offsets{};
    std::array<uint32_t, kShareCount> anchor_offsets{};
    bool any_zero = false;
    bool any_nonzero = false;
    for (size_t i = 0; i < kShareCount; ++i) {
        const auto& desc = kShareDescriptors[i];
        uint32_t anchor_rva = 0;
        if (!find_export_rva(file, layout, desc.anchor_export, anchor_rva)) return false;
        uint32_t sentinel_rva = 0;
        if (!find_export_rva(file, layout, desc.sentinel_export, sentinel_rva)) return false;
        uint32_t anchor_off = 0;
        if (!rva_to_file_offset(layout, anchor_rva + desc.offset, desc.length, anchor_off)) {
            std::cerr << "share_fingerprint_baker: cannot map anchor '" << desc.anchor_export
                      << "' rva=0x" << std::hex << anchor_rva << "+0x" << desc.offset
                      << " len=" << std::dec << desc.length << std::endl;
            return false;
        }
        uint32_t sentinel_off = 0;
        if (!rva_to_file_offset(layout, sentinel_rva, static_cast<uint32_t>(kFingerprintBytes), sentinel_off)) {
            std::cerr << "share_fingerprint_baker: cannot map sentinel '" << desc.sentinel_export
                      << "' rva=0x" << std::hex << sentinel_rva << std::dec << std::endl;
            return false;
        }
        sentinel_offsets[i] = sentinel_off;
        anchor_offsets[i] = anchor_off;
        bool z = fingerprint_region_is_zero(file, sentinel_off);
        if (z) any_zero = true; else any_nonzero = true;
        std::cout << "share_fingerprint_baker: '" << desc.anchor_export
                  << "' anchor_rva=0x" << std::hex << anchor_rva
                  << " hash_off=0x" << anchor_off
                  << " len=" << std::dec << desc.length
                  << " sentinel_rva=0x" << std::hex << sentinel_rva
                  << " sentinel_off=0x" << sentinel_off
                  << std::dec << " zero=" << (z ? "1" : "0") << std::endl;
    }

    if (!any_zero && any_nonzero) {
        std::cout << "share_fingerprint_baker: all fingerprints already non-zero; idempotent re-run (exit 0)" << std::endl;
        if (output_path != input_path) {
            if (!write_entire_file(output_path, file)) {
                return false;
            }
        }
        return true;
    }
    if (any_zero && any_nonzero) {
        std::cerr << "share_fingerprint_baker: mixed zero/non-zero fingerprint state; refusing to bake (binary appears partially patched)" << std::endl;
        return false;
    }

    for (size_t i = 0; i < kShareCount; ++i) {
        const auto& desc = kShareDescriptors[i];
        uint8_t digest[kFingerprintBytes] = {0};
        if (!sha256_bytes(file.data() + anchor_offsets[i], desc.length, digest)) {
            std::cerr << "share_fingerprint_baker: sha256 failed for '" << desc.anchor_export << "'" << std::endl;
            return false;
        }
        std::memcpy(file.data() + sentinel_offsets[i], digest, kFingerprintBytes);
    }

    if (!write_entire_file(output_path, file)) {
        return false;
    }
    bool sum_ok = fix_checksum(output_path);
    if (sum_ok) {
        std::cout << "share_fingerprint_baker: baked " << kShareCount << " fingerprints into '" << output_path << "' and refreshed PE checksum" << std::endl;
    } else {
        std::cout << "share_fingerprint_baker: baked " << kShareCount << " fingerprints into '" << output_path << "' (checksum refresh skipped)" << std::endl;
    }
    return true;
}

void print_usage() {
    std::cerr << "usage:\n"
              << "  share_fingerprint_baker --input <pe> [--output <pe>]\n";
}

bool arg_value(int argc, char** argv, int& i, std::string& out) {
    if (i + 1 >= argc) {
        return false;
    }
    out = argv[++i];
    return true;
}

}

int main(int argc, char** argv) {
    std::string input_path;
    std::string output_path;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--input") {
            if (!arg_value(argc, argv, i, input_path)) { print_usage(); return 2; }
        } else if (a == "--output") {
            if (!arg_value(argc, argv, i, output_path)) { print_usage(); return 2; }
        } else if (a == "--help" || a == "-h" || a == "/?") {
            print_usage();
            return 0;
        } else {
            std::cerr << "share_fingerprint_baker: unknown argument '" << a << "'" << std::endl;
            print_usage();
            return 2;
        }
    }

    if (input_path.empty()) {
        print_usage();
        return 2;
    }
    if (output_path.empty()) {
        output_path = input_path;
    }
    return run_bake(input_path, output_path) ? 0 : 1;
}
