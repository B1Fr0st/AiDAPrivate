#include "large_pe_fixture_builder.hpp"

#include <algorithm>
#include <cstdint>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <vector>

#include <windows.h>
#include <bcrypt.h>

namespace {

using namespace aida::analysis::test_fixture;

void require(bool condition, const std::string& message) {
    if (!condition)
        throw std::runtime_error("large_pe_fixture_harness: " + message);
}

std::string file_sha256(const std::filesystem::path& path) {
    std::ifstream stream(path, std::ios::binary);
    require(stream.good(), "failed to open written fixture " + path.u8string());
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    require(BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) == 0,
            "BCryptOpenAlgorithmProvider failed");
    BCRYPT_HASH_HANDLE hash = nullptr;
    require(BCryptCreateHash(algorithm, &hash, nullptr, 0, nullptr, 0, 0) == 0,
            "BCryptCreateHash failed");
    std::vector<char> chunk(1U << 20U, 0);
    while (stream) {
        stream.read(chunk.data(), static_cast<std::streamsize>(chunk.size()));
        const auto count = stream.gcount();
        if (count > 0) {
            require(BCryptHashData(hash, reinterpret_cast<PUCHAR>(chunk.data()),
                                   static_cast<ULONG>(count), 0) == 0,
                    "BCryptHashData failed");
        }
    }
    std::vector<std::uint8_t> digest(32, 0);
    require(BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0) == 0,
            "BCryptFinishHash failed");
    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(algorithm, 0);
    static const char hex[] = "0123456789abcdef";
    std::string text;
    text.reserve(64);
    for (const auto byte : digest) {
        text.push_back(hex[(byte >> 4U) & 0xFU]);
        text.push_back(hex[byte & 0xFU]);
    }
    return text;
}

void verify_determinism(const large_pe_params_t& raw, const std::string& label) {
    const auto params = validated_large_pe_params(raw);
    const auto first = build_large_pe64(params);
    const auto second = build_large_pe64(params);
    require(!first.empty(), label + ": build produced an empty image");
    require(first == second, label + ": two in-memory builds diverged");
    const auto hash_a = large_pe_sha256(params);
    const auto hash_b = large_pe_sha256(params);
    require(hash_a == hash_b, label + ": streaming hash diverged across runs");
    require(hash_a.size() == 64, label + ": hash text is not a SHA-256 hex digest");
}

void verify_manifest(const large_pe_params_t& raw, const std::string& label) {
    const auto params = validated_large_pe_params(raw);
    const auto manifest = describe_large_pe(params);
    const auto image = build_large_pe64(params);
    require(manifest.file_size == image.size(), label + ": manifest file_size != build size");
    require(manifest.function_count > 0, label + ": zero functions generated");
    require(manifest.instruction_count_estimate > 0,
            label + ": zero instructions estimated");
    require(manifest.code_bytes == params.code_bytes,
            label + ": manifest code_bytes mismatch");
    require(manifest.function_rva_begin < manifest.function_rva_end,
            label + ": invalid function rva window");
    require(!manifest.sections.empty(), label + ": no sections described");
    bool saw_pdata = false;
    std::uint32_t previous_rva = 0;
    std::uint32_t previous_raw = 0;
    bool first = true;
    for (const auto& section : manifest.sections) {
        require(section.virtual_size > 0 || section.raw_size > 0,
                label + ": empty section " + section.name);
        require(section.raw_offset + section.raw_size <= image.size(),
                label + ": section " + section.name + " escapes the image");
        if (!first) {
            require(section.rva >= previous_rva, label + ": section rva order violated");
            require(section.raw_offset >= previous_raw,
                    label + ": section raw offset order violated");
        }
        previous_rva = section.rva;
        previous_raw = section.raw_offset;
        first = false;
        if (section.name == ".pdata")
            saw_pdata = true;
    }
    require(saw_pdata == params.seed_pdata,
            label + ": .pdata presence does not match seed_pdata");
    if (params.seed_pdata)
        require(manifest.pdata_bytes == manifest.function_count * 12ULL,
                label + ": .pdata size is not function_count * 12");
}

void verify_sink_equivalence(const large_pe_params_t& raw, const std::string& label) {
    const auto params = validated_large_pe_params(raw);
    const auto image = build_large_pe64(params);
    const auto temp_root = std::filesystem::temp_directory_path() /
        ("aida_large_pe_fixture_harness_" + std::to_string(GetCurrentProcessId()));
    std::filesystem::create_directories(temp_root);
    const auto path = temp_root / "fixture.bin";
    write_large_pe64(path, params);
    require(std::filesystem::file_size(path) == image.size(),
            label + ": written file size != build size");
    std::ifstream stream(path, std::ios::binary);
    std::vector<std::uint8_t> written((std::istreambuf_iterator<char>(stream)),
                                      std::istreambuf_iterator<char>());
    require(written == image, label + ": written bytes != build bytes");
    require(file_sha256(path) == large_pe_sha256(params),
            label + ": file digest != streaming digest");
    std::error_code remove_error;
    std::filesystem::remove_all(temp_root, remove_error);
}

void verify_seed_divergence() {
    large_pe_params_t base;
    base.code_bytes = 1024ULL * 1024ULL;
    base.seed = 0xA1DA0001ULL;
    large_pe_params_t other = base;
    other.seed = 0xA1DA0002ULL;
    require(large_pe_sha256(validated_large_pe_params(base)) !=
            large_pe_sha256(validated_large_pe_params(other)),
            "distinct seeds produced identical digests");
}

void verify_sizes() {
    for (const std::uint64_t code_bytes :
         {512ULL * 1024ULL, 4ULL * 1024ULL * 1024ULL, 32ULL * 1024ULL * 1024ULL}) {
        large_pe_params_t params;
        params.code_bytes = code_bytes;
        params.code_sections = code_bytes >= 4ULL * 1024ULL * 1024ULL ? 4U : 1U;
        const std::string label = "size " + std::to_string(code_bytes);
        verify_determinism(params, label);
        verify_manifest(params, label);
    }
}

void verify_validation() {
    large_pe_params_t invalid;
    invalid.code_bytes = 0;
    bool rejected = false;
    try {
        (void)validated_large_pe_params(invalid);
    } catch (const std::exception&) {
        rejected = true;
    }
    require(rejected, "zero code_bytes was not rejected");
}

} // namespace

int main() {
    try {
        verify_sizes();
        large_pe_params_t multi;
        multi.code_bytes = 8ULL * 1024ULL * 1024ULL;
        multi.code_sections = 3;
        multi.string_count = 2048;
        multi.data_pointer_count = 2048;
        verify_sink_equivalence(multi, "sink equivalence");
        verify_seed_divergence();
        verify_validation();
        std::cout << "large_pe_fixture_harness: pass\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << "\n";
        return 1;
    }
}
