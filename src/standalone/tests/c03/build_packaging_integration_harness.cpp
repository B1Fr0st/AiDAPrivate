#include "build_packaging_integration_harness.hpp"

#include "assertion_telemetry/assertion_telemetry.hpp"
#include "evidence_hash.hpp"
#include "../../src/core/analysis/build_worker_packaging_integration.hpp"

#include <Windows.h>
#include <wincrypt.h>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <tuple>
#include <utility>
#include <vector>

#pragma comment(lib, "crypt32.lib")

namespace aida::analysis::c03_test {
namespace {

using namespace aida::analysis::c03;
using json = nlohmann::json;

constexpr std::string_view k_native_protocol_hash =
    "a0026d656b22dac563f5118b2d18f132c2bc2a64efaa28e5d170da0b725edccc";
constexpr std::string_view k_python_protocol_hash =
    "0a8dd2e97f78ef594ea2b7b5399eb1a049972e0b2d9a9541378aca0c76879004";
constexpr std::string_view k_managed_contract_hash =
    "4fe173593d2e044466706c58b3573ec528930a1762a3177ac53e7b84c166cfa6";

void require(bool condition, std::string_view message) {
    assertion_telemetry::record_assertion(condition, message, __FILE__, __LINE__);
    if (!condition)
        throw std::runtime_error(std::string(message));
}

std::array<std::uint8_t, 32> decode_hash(std::string_view value) {
    require(value.size() == 64, "SHA-256 value has invalid length");
    const auto nibble = [](char character) -> std::uint8_t {
        if (character >= '0' && character <= '9')
            return static_cast<std::uint8_t>(character - '0');
        if (character >= 'a' && character <= 'f')
            return static_cast<std::uint8_t>(character - 'a' + 10);
        throw std::runtime_error("SHA-256 value is not lowercase hexadecimal");
    };
    std::array<std::uint8_t, 32> result{};
    for (std::size_t index = 0; index < result.size(); ++index)
        result[index] = static_cast<std::uint8_t>((nibble(value[index * 2]) << 4U) |
                                                  nibble(value[index * 2 + 1]));
    return result;
}

void append_u32(std::vector<std::uint8_t>& output, std::uint32_t value) {
    output.push_back(static_cast<std::uint8_t>(value));
    output.push_back(static_cast<std::uint8_t>(value >> 8U));
    output.push_back(static_cast<std::uint8_t>(value >> 16U));
    output.push_back(static_cast<std::uint8_t>(value >> 24U));
}

void append_string(std::vector<std::uint8_t>& output, std::string_view value) {
    require(!value.empty() && value.size() <= 4096, "manifest string violates fixture policy");
    append_u32(output, static_cast<std::uint32_t>(value.size()));
    output.insert(output.end(), value.begin(), value.end());
}

void append_hash(std::vector<std::uint8_t>& output, std::string_view value) {
    const auto bytes = decode_hash(value);
    output.insert(output.end(), bytes.begin(), bytes.end());
}

void write_bytes(const std::filesystem::path& path, const std::vector<std::uint8_t>& bytes) {
    std::filesystem::create_directories(path.parent_path());
    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    require(static_cast<bool>(stream), "cannot create fixture binary");
    stream.write(reinterpret_cast<const char*>(bytes.data()),
                 static_cast<std::streamsize>(bytes.size()));
    require(static_cast<bool>(stream), "cannot write fixture binary");
}

void write_text(const std::filesystem::path& path, std::string_view text) {
    std::filesystem::create_directories(path.parent_path());
    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    require(static_cast<bool>(stream), "cannot create fixture text");
    stream.write(text.data(), static_cast<std::streamsize>(text.size()));
    require(static_cast<bool>(stream), "cannot write fixture text");
}

std::string file_hash(const std::filesystem::path& path) {
    const auto result = sha256_evidence_file(path, 2ULL * 1024ULL * 1024ULL * 1024ULL);
    require(result.ok, result.error);
    return result.sha256;
}

std::uint64_t file_size(const std::filesystem::path& path) {
    std::error_code error;
    const auto size = std::filesystem::file_size(path, error);
    require(!error && size != 0, "fixture file size is invalid");
    return size;
}

std::filesystem::path locate_repository_root() {
    std::array<std::filesystem::path, 2> candidates{
        std::filesystem::current_path(), std::filesystem::absolute(std::filesystem::path(__FILE__))
    };
    for (auto candidate : candidates) {
        if (std::filesystem::is_regular_file(candidate))
            candidate = candidate.parent_path();
        for (std::size_t depth = 0; depth < 24 && !candidate.empty(); ++depth) {
            if (std::filesystem::is_regular_file(
                    candidate / "packaging/c03_worker_runtime/managed_runtime_source_spec.json") &&
                std::filesystem::is_directory(
                    candidate / ".deps/dotnet-sdk-10.0.301-win-x64/shared/Microsoft.NETCore.App/10.0.9"))
                return candidate;
            const auto parent = candidate.parent_path();
            if (parent == candidate)
                break;
            candidate = parent;
        }
    }
    throw std::runtime_error("repository-local managed runtime fixture is unavailable");
}

std::string canonical_inventory_hash(const json& entries) {
    std::vector<std::tuple<std::string, std::uint64_t, std::string>> rows;
    rows.reserve(entries.size());
    for (const auto& entry : entries)
        rows.emplace_back(entry.at("relative_path").get<std::string>(),
                          entry.at("size_bytes").get<std::uint64_t>(),
                          entry.at("sha256").get<std::string>());
    std::sort(rows.begin(), rows.end(), [](const auto& left, const auto& right) {
        return std::get<0>(left) < std::get<0>(right);
    });
    std::string material;
    for (std::size_t index = 0; index < rows.size(); ++index) {
        if (index != 0)
            material.push_back('\n');
        material += std::get<0>(rows[index]) + "|" +
                    std::to_string(std::get<1>(rows[index])) + "|" +
                    std::get<2>(rows[index]);
    }
    const auto digest = sha256_evidence_text(material);
    require(digest.ok, digest.error);
    return digest.sha256;
}

std::filesystem::path signed_system_binary() {
    std::array<wchar_t, 32768> windows{};
    const UINT length = GetWindowsDirectoryW(windows.data(), static_cast<UINT>(windows.size()));
    require(length != 0 && length < static_cast<UINT>(windows.size()),
            "Windows directory is unavailable");
    const auto path = std::filesystem::path(windows.data()) / "System32" / "where.exe";
    require(std::filesystem::is_regular_file(path), "signed system fixture is unavailable");
    return path;
}

std::string signer_sha256(const std::filesystem::path& path) {
    HCERTSTORE store = nullptr;
    HCRYPTMSG message = nullptr;
    DWORD encoding = 0;
    DWORD content_type = 0;
    DWORD format_type = 0;
    require(CryptQueryObject(CERT_QUERY_OBJECT_FILE, path.c_str(),
                             CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                             CERT_QUERY_FORMAT_FLAG_BINARY, 0, &encoding, &content_type,
                             &format_type, &store, &message, nullptr) != FALSE,
            "signed system fixture has no embedded signer");
    struct closer_t final {
        HCERTSTORE store;
        HCRYPTMSG message;
        ~closer_t() {
            if (message)
                CryptMsgClose(message);
            if (store)
                CertCloseStore(store, 0);
        }
    } closer{store, message};
    DWORD signer_size = 0;
    require(CryptMsgGetParam(message, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &signer_size) != FALSE &&
                signer_size >= static_cast<DWORD>(sizeof(CMSG_SIGNER_INFO)),
            "signed system fixture signer metadata is unavailable");
    std::vector<std::uint8_t> buffer(signer_size);
    require(CryptMsgGetParam(message, CMSG_SIGNER_INFO_PARAM, 0, buffer.data(),
                             &signer_size) != FALSE,
            "signed system fixture signer metadata is unreadable");
    const auto* signer = reinterpret_cast<const CMSG_SIGNER_INFO*>(buffer.data());
    CERT_INFO certificate_info{};
    certificate_info.Issuer = signer->Issuer;
    certificate_info.SerialNumber = signer->SerialNumber;
    PCCERT_CONTEXT certificate = CertFindCertificateInStore(
        store, encoding, 0, CERT_FIND_SUBJECT_CERT, &certificate_info, nullptr);
    require(certificate != nullptr, "signed system fixture certificate is unavailable");
    struct certificate_closer_t final {
        PCCERT_CONTEXT value;
        ~certificate_closer_t() {
            if (value)
                CertFreeCertificateContext(value);
        }
    } certificate_closer{certificate};
    std::array<std::uint8_t, 32> digest{};
    DWORD digest_size = static_cast<DWORD>(digest.size());
    require(CertGetCertificateContextProperty(certificate, CERT_SHA256_HASH_PROP_ID,
                                               digest.data(), &digest_size) != FALSE &&
                digest_size == static_cast<DWORD>(digest.size()),
            "signed system fixture certificate digest is unavailable");
    constexpr char digits[] = "0123456789abcdef";
    std::string result(digest.size() * 2, '0');
    for (std::size_t index = 0; index < digest.size(); ++index) {
        result[index * 2] = digits[digest[index] >> 4U];
        result[index * 2 + 1] = digits[digest[index] & 0x0fU];
    }
    return result;
}

std::vector<std::uint8_t> native_manifest(std::string_view path,
                                          std::string_view worker_hash,
                                          std::uint8_t provider,
                                          std::string_view managed_runtime_manifest_hash = {}) {
    std::vector<std::uint8_t> bytes;
    append_u32(bytes, 0x464d574eU);
    append_u32(bytes, provider == 2 ? 3 : 2);
    append_string(bytes, path);
    append_hash(bytes, worker_hash);
    bytes.push_back(provider);
    append_string(bytes, provider == 1 ? "aida-native-decompiler" : "ICSharpCode.Decompiler");
    append_string(bytes, provider == 1 ? "2" : "10.1.0.8386");
    append_hash(bytes, provider == 1 ? worker_hash :
        "bebc24d573164da41b6f43f521d96362516d0f4b5b2715a9e7d877f4b2730345");
    append_string(bytes, provider == 1 ? "aida-native-decompiler-worker-v3" :
                                         "aida-managed-decompiler-worker-v3");
    append_hash(bytes, provider == 1 ?
        "50c79d3e14004aecfea4b2dd358d236d160a7c1b468b96806df00ede6e765a47" :
        "4dd8c0d095629437387a4b631fd9ac3c3cb8e840f6b7af277ccc2ad49d4bc3b7");
    append_u32(bytes, 3);
    append_hash(bytes, k_native_protocol_hash);
    append_u32(bytes, 1);
    append_u32(bytes, 0);
    if (provider == 2) {
        require(!managed_runtime_manifest_hash.empty(),
                "managed runtime manifest hash is absent");
        append_hash(bytes, managed_runtime_manifest_hash);
    }
    return bytes;
}

std::vector<std::uint8_t> python_manifest(std::string_view worker_hash) {
    std::vector<std::uint8_t> bytes;
    append_u32(bytes, 0x4d575041U);
    append_u32(bytes, 1);
    append_string(bytes, "deps/AiDA_AnalysisPythonWorker.exe");
    append_hash(bytes, worker_hash);
    append_hash(bytes, k_python_protocol_hash);
    append_u32(bytes, 1);
    return bytes;
}

class fixture_t final {
public:
    fixture_t() {
        std::array<wchar_t, MAX_PATH> temporary{};
        require(GetTempPathW(static_cast<DWORD>(temporary.size()), temporary.data()) != 0,
                "temporary directory is unavailable");
        root_ = std::filesystem::path(temporary.data()) /
                ("aida-c03-package-harness-" + std::to_string(GetCurrentProcessId()) + "-" +
                 std::to_string(GetTickCount64()));
        package_ = root_ / "package";
        evidence_ = root_ / "evidence";
        std::filesystem::create_directories(package_);
        std::filesystem::create_directories(evidence_);
        try {
            create();
        } catch (...) {
            std::error_code error;
            std::filesystem::remove_all(root_, error);
            throw;
        }
    }

    ~fixture_t() {
        std::error_code error;
        std::filesystem::remove_all(root_, error);
    }

    fixture_t(const fixture_t&) = delete;
    fixture_t& operator=(const fixture_t&) = delete;

    const std::filesystem::path& package() const noexcept { return package_; }
    const std::filesystem::path& manifest_path() const noexcept { return manifest_path_; }
    const json& manifest() const noexcept { return manifest_; }
    const std::string& authority_hash() const noexcept { return authority_hash_; }

    std::string publish_manifest(const json& value, std::string_view name = "manifest.json") {
        manifest_path_ = evidence_ / std::string(name);
        write_text(manifest_path_, value.dump() + "\n");
        return file_hash(manifest_path_);
    }

    void refresh_artifact(json& value, std::string_view id) const {
        auto found = std::find_if(value["artifacts"].begin(), value["artifacts"].end(),
            [&](const json& artifact) { return artifact.at("id").get<std::string>() == id; });
        require(found != value["artifacts"].end(), "fixture artifact id is absent");
        const auto path = package_ / std::filesystem::u8path(
            found->at("relative_path").get<std::string>());
        (*found)["size_bytes"] = file_size(path);
        (*found)["sha256"] = file_hash(path);
    }

private:
    json artifact(std::string id, std::string kind, std::string path,
                  std::string owner, std::vector<std::string> licenses = {}) const {
        const auto absolute = package_ / std::filesystem::u8path(path);
        return {{"id", std::move(id)}, {"kind", std::move(kind)},
                {"relative_path", std::move(path)}, {"size_bytes", file_size(absolute)},
                {"sha256", file_hash(absolute)}, {"owner", std::move(owner)},
                {"license_ids", std::move(licenses)}};
    }

    json containment(std::size_t worker_index) const {
        const bool python = worker_index == 2;
        return {{"job_object", true}, {"kill_on_parent_close", true},
                {"restricted_token", true}, {"network_denied", true},
                {"child_process_denied", true}, {"unrelated_handles_denied", true},
                {"process_mitigations", true}, {"acl_restricted_ipc", true},
                {"authenticated_ipc", true}, {"monotonic_sequence", true},
                {"cpu_quota_ms", python ? 15000 : 30000},
                {"memory_quota_bytes", python ? 536870912ULL : 2147483648ULL},
                {"deadline_ms", python ? 30000 : 60000},
                {"cancellation_replaces_worker", true}};
    }

    json inventory_entry(const std::filesystem::path& path,
                         std::string relative) const {
        return {{"relative_path", std::move(relative)},
                {"size_bytes", file_size(path)}, {"sha256", file_hash(path)}};
    }

    std::string create_managed_runtime() {
        const auto managed_executable = package_ / "deps/AiDA_ManagedDecompilerWorker.exe";
        std::filesystem::create_directories(managed_executable.parent_path());
        std::filesystem::copy_file(signed_system_binary(), managed_executable,
                                   std::filesystem::copy_options::overwrite_existing);
        const std::array<std::pair<std::string_view, std::string_view>, 6> application_files{{
            {"assembly", "deps/AiDA_ManagedDecompilerWorker.dll"},
            {"deps", "deps/AiDA_ManagedDecompilerWorker.deps.json"},
            {"runtimeconfig", "deps/AiDA_ManagedDecompilerWorker.runtimeconfig.json"},
            {"provider", "deps/ICSharpCode.Decompiler.dll"},
            {"direct_dependency", "deps/System.Collections.Immutable.dll"},
            {"direct_dependency", "deps/System.Reflection.Metadata.dll"},
        }};
        for (const auto& entry : application_files)
            write_text(package_ / std::filesystem::u8path(std::string(entry.second)),
                       std::string(entry.second) + "\n");
        const auto runtime_source = locate_repository_root() /
            ".deps/dotnet-sdk-10.0.301-win-x64";
        std::vector<std::filesystem::path> runtime_relatives{
            "dotnet.exe", "LICENSE.txt", "ThirdPartyNotices.txt",
            "host/fxr/10.0.9/hostfxr.dll"
        };
        const auto framework_root = runtime_source / "shared/Microsoft.NETCore.App/10.0.9";
        std::vector<std::filesystem::path> framework_relatives;
        for (const auto& entry : std::filesystem::recursive_directory_iterator(framework_root)) {
            if (entry.is_regular_file())
                framework_relatives.push_back(std::filesystem::relative(entry.path(), runtime_source));
        }
        std::sort(framework_relatives.begin(), framework_relatives.end(),
                  [](const auto& left, const auto& right) {
                      return left.generic_u8string() < right.generic_u8string();
                  });
        require(framework_relatives.size() == 189,
                "repository-local managed runtime file count is invalid");
        runtime_relatives.insert(runtime_relatives.end(), framework_relatives.begin(),
                                 framework_relatives.end());
        require(runtime_relatives.size() == 193,
                "managed runtime fixture inventory is incomplete");
        json runtime_files = json::array();
        for (const auto& relative : runtime_relatives) {
            const auto source = runtime_source / relative;
            const auto packaged_relative = std::filesystem::path("deps/dotnet") / relative;
            const auto destination = package_ / packaged_relative;
            std::filesystem::create_directories(destination.parent_path());
            std::filesystem::copy_file(source, destination,
                                       std::filesystem::copy_options::overwrite_existing);
            runtime_files.push_back(inventory_entry(destination,
                packaged_relative.generic_u8string()));
        }
        json application = json::array();
        auto apphost = inventory_entry(managed_executable,
                                       "deps/AiDA_ManagedDecompilerWorker.exe");
        apphost["role"] = "apphost";
        application.push_back(std::move(apphost));
        for (const auto& entry : application_files) {
            const auto relative = std::string(entry.second);
            auto identity = inventory_entry(package_ / std::filesystem::u8path(relative), relative);
            identity["role"] = entry.first;
            application.push_back(std::move(identity));
        }
        std::uint64_t runtime_bytes = 0;
        for (const auto& entry : runtime_files)
            runtime_bytes += entry.at("size_bytes").get<std::uint64_t>();
        require(runtime_bytes == 80344570ULL &&
                    canonical_inventory_hash(runtime_files) ==
                        "8582bda52b66ad61651a2c9bc2c705cf10b038e374f87662045397c7966b02c9",
                "managed runtime fixture identity differs from the locked package contract");
        std::uint64_t total_bytes = runtime_bytes;
        for (const auto& entry : application)
            total_bytes += entry.at("size_bytes").get<std::uint64_t>();
        json combined = runtime_files;
        for (const auto& entry : application)
            combined.push_back(entry);
        const json runtime_manifest{
            {"schema", "aida.c03.managed-runtime-manifest"}, {"schema_version", 1},
            {"source_contract_sha256",
             "2ee04cc5ed3c0fdbe1dac2f59ff2ac0e0fd5b4595c042aadb9abfbbd8153c4de"},
            {"target_framework", "net10.0"},
            {"runtime", {{"framework", "Microsoft.NETCore.App"}, {"version", "10.0.9"},
                         {"runtime_identifier", "win-x64"}, {"relative_root", "deps/dotnet"},
                         {"exact_inventory", true}, {"file_count", 193},
                         {"total_size_bytes", runtime_bytes},
                         {"canonical_inventory_sha256", canonical_inventory_hash(runtime_files)},
                         {"files", runtime_files}}},
            {"application", {{"exact_inventory", true}, {"files", application}}},
            {"launch", {{"executable_relative_path", "deps/AiDA_ManagedDecompilerWorker.exe"},
                        {"hostfxr_relative_path", "deps/dotnet/host/fxr/10.0.9/hostfxr.dll"},
                        {"dotnet_root_relative_path", "deps/dotnet"},
                        {"multilevel_lookup", false}, {"roll_forward", "Disable"},
                        {"roll_forward_to_prerelease", false},
                        {"machine_runtime_fallback", false}}},
            {"inventory", {{"file_count", 200}, {"total_size_bytes", total_bytes},
                           {"canonical_inventory_sha256", canonical_inventory_hash(combined)}}}
        };
        const auto manifest_path = package_ / "deps/AiDA_ManagedRuntime.manifest.json";
        write_text(manifest_path, runtime_manifest.dump() + "\n");
        const auto digest = file_hash(manifest_path);
        write_text(package_ / "deps/AiDA_ManagedRuntime.manifest.sha256", digest + "\n");
        return digest;
    }

    void create_ghidra_specs() {
        const std::array<std::pair<std::string_view, std::string_view>, 51> specifications{{
            {"x86-64.sla","sla"},{"x86.sla","sla"},{"ARM7_le.sla","sla"},
            {"ARM7_be.sla","sla"},{"AARCH64.sla","sla"},{"AARCH64BE.sla","sla"},
            {"mips32le.sla","sla"},{"mips32be.sla","sla"},{"mips64le.sla","sla"},
            {"mips64be.sla","sla"},{"ppc_32_le.sla","sla"},{"ppc_32_be.sla","sla"},
            {"ppc_64_le.sla","sla"},{"ppc_64_be.sla","sla"},{"riscv.ilp32d.sla","sla"},
            {"riscv.lp64d.sla","sla"},{"x86-64.pspec","pspec"},
            {"x86-64-win.cspec","cspec"},{"x86-64-gcc.cspec","cspec"},
            {"x86.pspec","pspec"},{"x86win.cspec","cspec"},{"x86gcc.cspec","cspec"},
            {"x86-16-real.pspec","pspec"},{"x86-16.cspec","cspec"},{"x86.ldefs","ldefs"},
            {"ARMt.pspec","pspec"},{"ARM.cspec","cspec"},{"ARM_win.cspec","cspec"},
            {"ARM.ldefs","ldefs"},{"AARCH64.pspec","pspec"},{"AARCH64.cspec","cspec"},
            {"AARCH64_win.cspec","cspec"},{"AARCH64.ldefs","ldefs"},
            {"mips32.pspec","pspec"},{"mips64.pspec","pspec"},
            {"mips32le.cspec","cspec"},{"mips32be.cspec","cspec"},
            {"mips64le.cspec","cspec"},{"mips64be.cspec","cspec"},{"mips.ldefs","ldefs"},
            {"ppc_32.pspec","pspec"},{"ppc_64.pspec","pspec"},{"ppc_32.cspec","cspec"},
            {"ppc_64_le.cspec","cspec"},{"ppc_64_be.cspec","cspec"},{"ppc.ldefs","ldefs"},
            {"RV32.pspec","pspec"},{"RV64.pspec","pspec"},{"riscv32-fp.cspec","cspec"},
            {"riscv64-fp.cspec","cspec"},{"riscv.ldefs","ldefs"},
        }};
        json files = json::array();
        std::string rows;
        for (const auto& specification : specifications) {
            const auto name = std::string(specification.first);
            const auto contents = name + "\n";
            for (const auto mirror : {"ghidra_specs", "deps/ghidra_specs"})
                write_text(package_ / mirror / name, contents);
            const auto path = package_ / "ghidra_specs" / name;
            const auto size = file_size(path);
            const auto hash = file_hash(path);
            files.push_back({{"name", name}, {"kind", specification.second},
                             {"size_bytes", size}, {"sha256", hash}});
            rows += name + "\t" + std::string(specification.second) + "\t" +
                    std::to_string(size) + "\t" + hash + "\n";
        }
        const auto inventory_hash = sha256_evidence_text(rows);
        require(inventory_hash.ok, inventory_hash.error);
        const std::string generator_hash(64, '6');
        const auto generation = sha256_evidence_text(
            "aida.c03.ghidra-spec-generation.v1\n880c588da681d62451d3dd5f901abc7cb86491a128a7793c8738f9bd7917f0b7\n" +
            generator_hash + "\n" + inventory_hash.sha256 + "\n");
        require(generation.ok, generation.error);
        const json manifest{
            {"schema", "aida.c03.ghidra-spec-manifest"}, {"schema_version", 1},
            {"source_contract_sha256", "880c588da681d62451d3dd5f901abc7cb86491a128a7793c8738f9bd7917f0b7"},
            {"producer", {{"id", "ghidra_sleigh_compiler"},
                          {"executable_sha256", generator_hash},
                          {"approved_input_root", true}, {"approved_generator_root", true}}},
            {"specifications", {{"file_count", 51},
                                {"mirrors", {"ghidra_specs", "deps/ghidra_specs"}},
                                {"exact_inventory", true}, {"generation_id", generation.sha256},
                                {"canonical_inventory_sha256", inventory_hash.sha256},
                                {"files", files}}}
        };
        const auto path = package_ / "deps/AiDA_GhidraSpecs.manifest.json";
        write_text(path, manifest.dump() + "\n");
        write_text(package_ / "deps/AiDA_GhidraSpecs.manifest.sha256",
                   file_hash(path) + "\n");
    }

    void create_acl_receipt(std::string_view path, std::string_view policy,
                            std::string_view worker_manifest_path,
                            std::uint64_t path_count) {
        const auto manifest_hash = file_hash(
            package_ / std::filesystem::u8path(std::string(worker_manifest_path)));
        const json receipt{
            {"schema", "aida.c03.worker-runtime-acl-receipt"}, {"schema_version", 1},
            {"policy", policy},
            {"app_container_profile", "AiDA.NativeWorker." + manifest_hash.substr(0, 32)},
            {"app_container_sid", "S-1-15-2-1"},
            {"worker_manifest_sha256", manifest_hash}, {"protected_parent_required", true},
            {"access", {{"read_execute", true}, {"write", false}, {"delete", false},
                        {"change_permissions", false}, {"take_ownership", false}}},
            {"path_count", path_count}, {"verified", true}
        };
        write_text(package_ / std::filesystem::u8path(std::string(path)),
                   receipt.dump() + "\n");
    }

    void create_worker(std::string_view executable_path, std::string_view manifest_path,
                       std::string_view digest_path,
                       std::string_view acl_path, std::string_view protector_path,
                       std::string_view signature_path, std::uint8_t provider,
                       std::string_view managed_runtime_manifest_hash = {}) {
        const auto source = signed_system_binary();
        const auto executable = package_ / std::filesystem::u8path(std::string(executable_path));
        std::filesystem::create_directories(executable.parent_path());
        std::filesystem::copy_file(source, executable,
                                   std::filesystem::copy_options::overwrite_existing);
        const auto executable_hash = file_hash(executable);
        const auto manifest = provider == 0 ? python_manifest(executable_hash) :
                                             native_manifest(executable_path, executable_hash, provider,
                                                             managed_runtime_manifest_hash);
        write_bytes(package_ / std::filesystem::u8path(std::string(manifest_path)), manifest);
        const auto manifest_hash = file_hash(
            package_ / std::filesystem::u8path(std::string(manifest_path)));
        write_text(package_ / std::filesystem::u8path(std::string(digest_path)),
                   manifest_hash + "\n");
        create_acl_receipt(acl_path, provider == 1 ? "native" :
            (provider == 2 ? "managed" : "analysis_python"), manifest_path,
            provider == 1 ? 105 : (provider == 2 ? 207 : 1));
        const json protector{
            {"schema", "aida.protector.receipt"}, {"schema_version", 2},
            {"status", "passed"}, {"artifact_relative_path", std::string(executable_path)},
            {"artifact_sha256", executable_hash}, {"artifact_size_bytes", file_size(executable)},
            {"tool_sha256", std::string(64, '1')},
            {"verifier_sha256", std::string(64, '2')}, {"profile", "production"},
            {"post_process", {{"protection_verified", true}, {"symbols_scrubbed", true},
                              {"debug_paths_scrubbed", true}, {"rich_header_scrubbed", true}}},
            {"production_flags", {"/Qspectre", "/sdl", "/guard:cf", "/guard:ehcont", "/guard:xfg"}}
        };
        write_text(package_ / std::filesystem::u8path(std::string(protector_path)),
                   protector.dump() + "\n");
        const json signature{
            {"schema", "aida.signature.receipt"}, {"schema_version", 2},
            {"status", "verified"}, {"artifact_relative_path", std::string(executable_path)},
            {"artifact_sha256", executable_hash}, {"artifact_size_bytes", file_size(executable)},
            {"verification_mode", "wintrust_offline"},
            {"signer_thumbprint_sha256", signer_sha256(executable)},
            {"verifier_sha256", std::string(64, '3')}, {"chain_status", "trusted"},
            {"timestamp_status", "trusted"}
        };
        write_text(package_ / std::filesystem::u8path(std::string(signature_path)),
                   signature.dump() + "\n");
    }

    void create() {
        const auto managed_runtime_hash = create_managed_runtime();
        create_ghidra_specs();
        create_worker("deps/AiDA_NativeDecompilerWorker.exe",
                      "deps/AiDA_NativeDecompilerWorker.manifest.bin",
                      "deps/AiDA_NativeDecompilerWorker.manifest.sha256",
                      "deps/evidence/native.acl.json",
                      "deps/evidence/native.protector.json", "deps/evidence/native.signature.json", 1);
        create_worker("deps/AiDA_ManagedDecompilerWorker.exe",
                      "deps/AiDA_ManagedDecompilerWorker.manifest.bin",
                      "deps/AiDA_ManagedDecompilerWorker.manifest.sha256",
                      "deps/evidence/managed.acl.json",
                      "deps/evidence/managed.protector.json", "deps/evidence/managed.signature.json",
                      2, managed_runtime_hash);
        create_worker("deps/AiDA_AnalysisPythonWorker.exe",
                      "deps/AiDA_AnalysisPythonWorker.manifest.bin",
                      "deps/AiDA_AnalysisPythonWorker.manifest.sha256",
                      "deps/evidence/analysis-python/AiDA_AnalysisPythonWorker.acl.json",
                      "deps/evidence/analysis-python/AiDA_AnalysisPythonWorker.protector_receipt.json",
                       "deps/evidence/analysis-python/AiDA_AnalysisPythonWorker.signature_receipt.json", 0);
        const auto standalone = package_ / "AiDAStandalone.exe";
        std::filesystem::copy_file(signed_system_binary(), standalone,
                                   std::filesystem::copy_options::overwrite_existing);
        const auto standalone_hash = file_hash(standalone);
        const json standalone_protector{
            {"schema", "aida.protector.receipt"}, {"schema_version", 2},
            {"status", "passed"}, {"artifact_relative_path", "AiDAStandalone.exe"},
            {"artifact_sha256", standalone_hash},
            {"artifact_size_bytes", file_size(standalone)},
            {"tool_sha256", std::string(64, '1')},
            {"verifier_sha256", std::string(64, '2')}, {"profile", "production"},
            {"post_process", {{"protection_verified", true}, {"symbols_scrubbed", true},
                              {"debug_paths_scrubbed", true}, {"rich_header_scrubbed", true}}},
            {"production_flags", {"/Qspectre", "/sdl", "/guard:cf", "/guard:ehcont", "/guard:xfg"}}
        };
        write_text(package_ / "deps/evidence/standalone.protector.json",
                   standalone_protector.dump() + "\n");
        const json standalone_signature{
            {"schema", "aida.signature.receipt"}, {"schema_version", 2},
            {"status", "verified"}, {"artifact_relative_path", "AiDAStandalone.exe"},
            {"artifact_sha256", standalone_hash},
            {"artifact_size_bytes", file_size(standalone)},
            {"verification_mode", "wintrust_offline"},
            {"signer_thumbprint_sha256", signer_sha256(standalone)},
            {"verifier_sha256", std::string(64, '3')}, {"chain_status", "trusted"},
            {"timestamp_status", "trusted"}
        };
        write_text(package_ / "deps/evidence/standalone.signature.json",
                   standalone_signature.dump() + "\n");
        std::filesystem::create_directories(package_ / "deps/camoufox-135.0.1-beta.24-win.x86_64");
        std::filesystem::create_directories(package_ / "deps/AiDA_CamoufoxReverseMcp");
        std::filesystem::copy_file(signed_system_binary(),
            package_ / "deps/camoufox-135.0.1-beta.24-win.x86_64/camoufox.exe",
            std::filesystem::copy_options::overwrite_existing);
        std::filesystem::copy_file(signed_system_binary(),
            package_ / "deps/AiDA_CamoufoxReverseMcp/AiDA_CamoufoxReverseMcp.exe",
            std::filesystem::copy_options::overwrite_existing);
        write_text(package_ / "notices/THIRD_PARTY_NOTICES.md", "AiDA C03 fixture notices\n");
        for (std::size_t index = 1; index < 502; ++index)
            write_text(package_ / "deps/camoufox-135.0.1-beta.24-win.x86_64" /
                           ("fixture-" + std::to_string(index) + ".bin"),
                       "camoufox-fixture-" + std::to_string(index) + "\n");
        for (std::size_t index = 1; index < 26; ++index)
            write_text(package_ / "notices" / ("NOTICE-" + std::to_string(index) + ".txt"),
                       "notice-fixture-" + std::to_string(index) + "\n");

        const auto authority = sha256_evidence_text("aida-c03-source-authority");
        require(authority.ok, authority.error);
        authority_hash_ = authority.sha256;
        manifest_ = {
            {"schema", "aida.c03.distribution-manifest"}, {"schema_version", 2},
            {"generator", {{"preset", "ninja-msvc-release"}, {"no_network_fetch", true},
                           {"offline_only", true}, {"manifest_digest_algorithm", "sha256"}}},
            {"source_authority_sha256", authority_hash_},
            {"distribution", {{"disk_backed", true}, {"protected", true},
                              {"arc_license_gates_required", true}, {"acl_restricted_ipc", true},
                              {"raw_standalone_download_forbidden", true},
                              {"fileless_launch_forbidden", true}, {"exact_inventory", true},
                              {"package_layout", "self-contained"}}},
            {"artifacts", json::array()}, {"workers", json::array()},
            {"dependencies", json::array()},
            {"customer_sidecars", {{"only_supported_browser", "camoufox"},
                                   {"browser_artifact", "camoufox-browser"},
                                   {"reverse_mcp_artifact", "camoufox-reverse-mcp"},
                                   {"developer_source_shipped", false},
                                   {"loose_python_shipped", false},
                                   {"stock_browser_fallback", false},
                                   {"environment", {{"AIDA_CAMOUFOX_EXECUTABLE", "verified-browser"},
                                                    {"AIDA_CAMOUFOX_MCP_EXECUTABLE", "verified-frozen-sidecar"},
                                                    {"AIDA_CAMOUFOX_PYTHON", "unset-unless-verified-sidecar-runtime"}}}}}
        };
        const std::array<std::array<std::string_view, 7>, 3> paths{{
            {"native_decompiler", "deps/AiDA_NativeDecompilerWorker.exe",
             "deps/AiDA_NativeDecompilerWorker.manifest.bin",
             "deps/AiDA_NativeDecompilerWorker.manifest.sha256",
             "deps/evidence/native.acl.json", "deps/evidence/native.protector.json",
             "deps/evidence/native.signature.json"},
            {"managed_cli_decompiler", "deps/AiDA_ManagedDecompilerWorker.exe",
             "deps/AiDA_ManagedDecompilerWorker.manifest.bin",
             "deps/AiDA_ManagedDecompilerWorker.manifest.sha256",
             "deps/evidence/managed.acl.json", "deps/evidence/managed.protector.json",
             "deps/evidence/managed.signature.json"},
            {"analysis_python", "deps/AiDA_AnalysisPythonWorker.exe",
             "deps/AiDA_AnalysisPythonWorker.manifest.bin",
             "deps/AiDA_AnalysisPythonWorker.manifest.sha256",
             "deps/evidence/analysis-python/AiDA_AnalysisPythonWorker.acl.json",
             "deps/evidence/analysis-python/AiDA_AnalysisPythonWorker.protector_receipt.json",
             "deps/evidence/analysis-python/AiDA_AnalysisPythonWorker.signature_receipt.json"}
        }};
        for (std::size_t index = 0; index < paths.size(); ++index) {
            const auto& row = paths[index];
            const std::string prefix(row[0]);
            manifest_["artifacts"].push_back(artifact(prefix + "-exe", "worker_executable",
                std::string(row[1]), prefix));
            manifest_["artifacts"].push_back(artifact(prefix + "-manifest", "worker_manifest",
                std::string(row[2]), prefix));
            manifest_["artifacts"].push_back(artifact(prefix + "-digest", "manifest_digest",
                std::string(row[3]), prefix));
            manifest_["artifacts"].push_back(artifact(prefix + "-acl", "acl_receipt",
                std::string(row[4]), prefix));
            manifest_["artifacts"].push_back(artifact(prefix + "-protector", "protector_receipt",
                std::string(row[5]), prefix));
            manifest_["artifacts"].push_back(artifact(prefix + "-signature", "signature_receipt",
                std::string(row[6]), prefix));
            const bool python = index == 2;
            const json dependency_ids = index == 0 ? json::array({"ghidra-worker"}) :
                (index == 1 ? json::array({"dotnet-runtime", "icsharpcode-decompiler",
                                           "system-collections-immutable",
                                           "system-reflection-metadata"}) :
                              json::array({"analysis-python-worker"}));
            manifest_["workers"].push_back({{"id", prefix},
                {"executable_artifact", prefix + "-exe"},
                {"worker_manifest_artifact", prefix + "-manifest"},
                {"worker_manifest_digest_artifact", prefix + "-digest"},
                {"acl_receipt_artifact", prefix + "-acl"},
                {"protector_receipt_artifact", prefix + "-protector"},
                {"signature_receipt_artifact", prefix + "-signature"},
                {"protocol", {{"name", python ? "aida-analysis-python" :
                    (index == 0 ? "aida-native-decompiler" : "aida-managed-cli-decompiler")},
                    {"version", python ? 1 : 3},
                    {"hash_material_sha256", std::string(python ? k_python_protocol_hash :
                        (index == 1 ? k_managed_contract_hash : k_native_protocol_hash))},
                    {"worker_manifest_schema_version", python ? 1 : (index == 1 ? 3 : 2)}}},
                {"containment", containment(index)}, {"target_execution_forbidden", true},
                {"dependency_ids", dependency_ids}});
        }
        manifest_["artifacts"].push_back(artifact(
            "standalone-executable", "application", "AiDAStandalone.exe", "standalone"));
        manifest_["artifacts"].push_back(artifact(
            "standalone-protector", "protector_receipt",
            "deps/evidence/standalone.protector.json", "standalone"));
        manifest_["artifacts"].push_back(artifact(
            "standalone-signature", "signature_receipt",
            "deps/evidence/standalone.signature.json", "standalone"));
        manifest_["artifacts"].push_back(artifact(
            "managed-runtime-manifest", "resource_manifest",
            "deps/AiDA_ManagedRuntime.manifest.json", "managed_cli_decompiler"));
        manifest_["artifacts"].push_back(artifact(
            "managed-runtime-manifest-digest", "manifest_digest",
            "deps/AiDA_ManagedRuntime.manifest.sha256", "managed_cli_decompiler"));
        manifest_["artifacts"].push_back(artifact(
            "ghidra-spec-manifest", "resource_manifest",
            "deps/AiDA_GhidraSpecs.manifest.json", "native_decompiler"));
        manifest_["artifacts"].push_back(artifact(
            "ghidra-spec-manifest-digest", "manifest_digest",
            "deps/AiDA_GhidraSpecs.manifest.sha256", "native_decompiler"));
        std::size_t generated_id = 0;
        for (const auto& entry : std::filesystem::recursive_directory_iterator(
                 package_ / "deps/dotnet")) {
            if (!entry.is_regular_file())
                continue;
            const auto relative = std::filesystem::relative(entry.path(), package_).generic_u8string();
            manifest_["artifacts"].push_back(artifact(
                "managed-dotnet-" + std::to_string(generated_id++), "worker_runtime",
                relative, "managed_cli_decompiler"));
        }
        const std::array<std::pair<std::string_view, std::string_view>, 6> managed_artifacts{{
            {"managed-worker-assembly", "deps/AiDA_ManagedDecompilerWorker.dll"},
            {"managed-worker-deps", "deps/AiDA_ManagedDecompilerWorker.deps.json"},
            {"managed-worker-runtimeconfig", "deps/AiDA_ManagedDecompilerWorker.runtimeconfig.json"},
            {"managed-worker-provider", "deps/ICSharpCode.Decompiler.dll"},
            {"managed-worker-immutable", "deps/System.Collections.Immutable.dll"},
            {"managed-worker-metadata", "deps/System.Reflection.Metadata.dll"},
        }};
        for (const auto& managed_artifact : managed_artifacts)
            manifest_["artifacts"].push_back(artifact(
                std::string(managed_artifact.first), "worker_runtime",
                std::string(managed_artifact.second), "managed_cli_decompiler"));
        for (const auto mirror : {"ghidra_specs", "deps/ghidra_specs"}) {
            for (const auto& entry : std::filesystem::directory_iterator(package_ / mirror)) {
                const auto relative = std::filesystem::relative(entry.path(), package_).generic_u8string();
                manifest_["artifacts"].push_back(artifact(
                    "ghidra-resource-" + std::to_string(generated_id++), "resource",
                    relative, "native_decompiler"));
            }
        }
        manifest_["artifacts"].push_back(artifact("camoufox-browser", "browser",
            "deps/camoufox-135.0.1-beta.24-win.x86_64/camoufox.exe", "camoufox"));
        for (std::size_t index = 1; index < 502; ++index) {
            const auto relative = "deps/camoufox-135.0.1-beta.24-win.x86_64/fixture-" +
                                  std::to_string(index) + ".bin";
            manifest_["artifacts"].push_back(artifact(
                "camoufox-fixture-" + std::to_string(index), "browser", relative, "camoufox"));
        }
        manifest_["artifacts"].push_back(artifact("camoufox-reverse-mcp", "reverse_mcp",
            "deps/AiDA_CamoufoxReverseMcp/AiDA_CamoufoxReverseMcp.exe", "camoufox-reverse-mcp"));
        manifest_["artifacts"].push_back(artifact("notice-common", "notice",
            "notices/THIRD_PARTY_NOTICES.md", "notices", {"fixture-license"}));
        for (std::size_t index = 1; index < 26; ++index) {
            const auto relative = "notices/NOTICE-" + std::to_string(index) + ".txt";
            manifest_["artifacts"].push_back(artifact(
                "notice-fixture-" + std::to_string(index), "notice", relative,
                "notices", {"fixture-license"}));
        }
        const auto add_dependency = [&](std::string_view id, std::string_view version,
                                        std::string_view usage, std::string_view license,
                                        json artifact_ids, json dependency_ids = json::array()) {
            manifest_["dependencies"].push_back({
                {"id", std::string(id)}, {"version", std::string(version)},
                {"usage", std::string(usage)}, {"license", std::string(license)},
                {"artifact_ids", std::move(artifact_ids)},
                {"notice_artifact_ids", usage == "production" ?
                    json::array({"notice-common"}) : json::array()},
                {"dependencies", std::move(dependency_ids)}});
        };
        add_dependency("zydis", "4.1.1", "production", "MIT",
                       json::array({"standalone-executable"}), json::array({"zycore"}));
        add_dependency("zycore", "bundled-4.1.1", "production", "MIT",
                       json::array({"standalone-executable"}));
        add_dependency("capstone", "5.0.9", "production", "BSD-style",
                       json::array({"standalone-executable"}));
        add_dependency("taskflow", "local-pinned", "production", "MIT",
                       json::array({"standalone-executable"}));
        add_dependency("ghidra-worker", "local-pinned", "production", "Apache-2.0",
                       json::array({"ghidra-spec-manifest"}));
        add_dependency("triton", "local-pinned", "production", "Apache-2.0",
                       json::array({"standalone-executable"}), json::array({"z3"}));
        add_dependency("z3", "4.13.4", "production", "MIT",
                       json::array({"standalone-executable"}));
        add_dependency("sqlite", "3.53.3", "production", "Public-Domain",
                       json::array({"standalone-executable"}));
        add_dependency("imgui", "local-pinned", "production", "MIT",
                       json::array({"standalone-executable"}));
        add_dependency("zlib", "1.3.2", "production", "zlib",
                       json::array({"standalone-executable"}));
        add_dependency("zstd", "1.5.7", "production", "BSD-3-Clause",
                       json::array({"standalone-executable"}));
        add_dependency("liblzma", "5.8.3", "production", "0BSD",
                       json::array({"standalone-executable"}));
        add_dependency("minizip-ng", "4.2.2", "production", "zlib",
                       json::array({"standalone-executable"}), json::array({"zlib"}));
        add_dependency("pcre2", "10.47", "production",
                       "BSD-3-Clause-WITH-PCRE2-exception",
                       json::array({"standalone-executable"}));
        add_dependency("nlohmann-json", "3.12.0", "production", "MIT",
                       json::array({"standalone-executable"}));
        add_dependency("json-schema-validator", "2.4.0", "production", "MIT",
                       json::array({"standalone-executable"}),
                       json::array({"nlohmann-json"}));
        add_dependency("llvm-demangle", "22.1.8", "production",
                       "Apache-2.0-WITH-LLVM-exception",
                       json::array({"standalone-executable"}));
        add_dependency("dotnet-runtime", "10.0.9", "production",
                       "Microsoft-.NET-Library-and-third-party",
                       json::array({"managed-runtime-manifest"}));
        add_dependency("dotnet-sdk", "10.0.301", "build_only",
                       "Microsoft-.NET-Library", json::array());
        add_dependency("icsharpcode-decompiler", "10.1.0.8386", "production", "MIT",
                       json::array({"managed-worker-provider"}),
                       json::array({"dotnet-runtime"}));
        add_dependency("system-collections-immutable", "9.0.0", "production", "MIT",
                       json::array({"managed-worker-immutable"}),
                       json::array({"dotnet-runtime"}));
        add_dependency("system-reflection-metadata", "9.0.0", "production", "MIT",
                       json::array({"managed-worker-metadata"}),
                       json::array({"dotnet-runtime"}));
        add_dependency("analysis-python-worker", "protocol-v1", "production",
                       "AiDA-Proprietary", json::array({"analysis_python-exe"}));
        add_dependency("camoufox", "135.0.1-beta.24", "production",
                       "MPL-2.0-and-third-party", json::array({"camoufox-browser"}));
        add_dependency("camoufox-reverse-mcp", "local-pinned", "production",
                       "MIT-and-runtime-graph", json::array({"camoufox-reverse-mcp"}));
        add_dependency("pyinstaller", "6.21.0", "build_only",
                       "GPL-2.0-or-later-with-bootloader-exception", json::array());
        add_dependency("lief", "0.17.6", "evidence_only", "Apache-2.0", json::array());
        add_dependency("remill", "6.0.1", "evidence_only", "Apache-2.0", json::array());
        add_dependency("lmdb", "not-selected", "non_use", "not-shipped", json::array());
        add_dependency("unicorn", "not-selected", "non_use", "not-shipped", json::array());
        publish_manifest(manifest_);
    }

    std::filesystem::path root_;
    std::filesystem::path package_;
    std::filesystem::path evidence_;
    std::filesystem::path manifest_path_;
    json manifest_;
    std::string authority_hash_;
};

package_verification_request_t request_for(const fixture_t& fixture,
                                           std::string expected_manifest_hash) {
    package_verification_request_t request;
    request.package_root = fixture.package();
    request.manifest_path = fixture.manifest_path();
    request.expected_manifest_sha256 = std::move(expected_manifest_hash);
    request.expected_source_authority_sha256 = fixture.authority_hash();
    request.expected_protector_tool_sha256 = std::string(64, '1');
    request.expected_protector_verifier_sha256 = std::string(64, '2');
    request.expected_signature_verifier_sha256 = std::string(64, '3');
    return request;
}

void verify_allowed_customer_path_neighbors(fixture_t& fixture,
                                            build_worker_packaging_integration_t& integration) {
    constexpr std::string_view allowed_paths[]{
        "resources/runtime-policy.json",
        "resources/runtime-policy.sha256",
        "resources/LICENSE.txt",
        "resources/NOTICE.md",
        "resources/binary-layout.dat",
        "resources/runtime.manifest"
    };
    auto candidate = fixture.manifest();
    std::size_t index = 0;
    for (const auto path : allowed_paths) {
        const auto absolute = fixture.package() / std::filesystem::u8path(path);
        write_text(absolute, std::string(path) + "\n");
        candidate["artifacts"].push_back({
            {"id", "allowed-neighbor-" + std::to_string(index++)}, {"kind", "resource"},
            {"relative_path", std::string(path)}, {"size_bytes", file_size(absolute)},
            {"sha256", file_hash(absolute)}, {"owner", "fixture"},
            {"license_ids", json::array()}});
    }
    const auto digest = fixture.publish_manifest(candidate, "allowed-neighbors.json");
    const auto verified = integration.verify_distribution_package(request_for(fixture, digest));
    require(static_cast<bool>(verified),
            verified ? "" : "legitimate customer resource neighbor was rejected");
    for (const auto path : allowed_paths)
        std::filesystem::remove(fixture.package() / std::filesystem::u8path(path));
    fixture.publish_manifest(fixture.manifest());
}

void verify_forbidden_customer_path_policy(fixture_t& fixture,
                                           build_worker_packaging_integration_t& integration) {
    constexpr std::string_view forbidden_extensions[]{
        ".a", ".asm", ".bash", ".bat", ".c", ".c++", ".cc", ".cmake", ".cmd", ".cpp",
        ".cppm", ".cs", ".csproj", ".cxx", ".def", ".exp", ".fs", ".fsproj", ".go",
        ".gradle", ".h", ".hh", ".hpp", ".hxx", ".ilk", ".in", ".inc", ".inl", ".ipp",
        ".ixx", ".java", ".kt", ".kts", ".lib", ".m", ".make", ".map", ".mk", ".mm",
        ".natvis", ".nupkg", ".nuspec", ".obj", ".pdb", ".props", ".ps1", ".psd1",
        ".psm1", ".pth", ".py", ".pyc", ".pyo", ".pyz", ".rc", ".rc2", ".rs", ".s",
        ".sh", ".sln", ".snupkg", ".spec", ".swift", ".targets", ".tpp", ".vb",
        ".vbproj", ".vcxproj", ".vcxproj.filters", ".whl", ".zig", ".zsh"
    };
    constexpr std::string_view forbidden_paths[]{
        "nested/BUILD",
        "nested/BUILD.BAZEL",
        "nested/CMakeLists.TXT",
        "nested/GNUMakefile",
        "nested/Makefile",
        "nested/MESON.BUILD",
        "nested/WORKSPACE",
        "nested/WORKSPACE.BAZEL",
        "nested/C03-SAFE-HEADLESS/bin/harness.exe",
        "nested/camoufox-reverse-mcp/source.txt",
        "nested/CAMOUFOX_REVERSE_MCP/source.txt",
        "nested/LIBRARY-PACKS/runtime.dll",
        "nested/METADATA/runtime.dll",
        "nested/PACKS/runtime.dll",
        "nested/SDK/runtime.dll",
        "nested/TEMPLATES/runtime.dll",
        "nested/provider.DIST-INFO/runtime.dll",
        "nested/provider.EGG-INFO/runtime.dll",
        "nested/payload.CpP",
        "nested/payload.PS1.backup",
        "nested/payload.HPP_copy",
        "nested/payload.CMAKE-old",
        "nested/chrome.EXE",
        "nested/MSEDGE.exe",
        "nested/STOCK-FIREFOX.EXE"
    };
    std::size_t case_index = 0;
    const auto reject = [&](std::string relative_path) {
        auto candidate = fixture.manifest();
        json artifact{
            {"id", "forbidden-path-" + std::to_string(case_index)}, {"kind", "resource"},
            {"relative_path", std::move(relative_path)}, {"size_bytes", 1},
            {"sha256", std::string(64, 'a')}, {"owner", "fixture"},
            {"license_ids", json::array()}};
        candidate["artifacts"].insert(candidate["artifacts"].begin(), std::move(artifact));
        const auto digest = fixture.publish_manifest(
            candidate, "forbidden-path-" + std::to_string(case_index++) + ".json");
        const auto rejected = integration.verify_distribution_package(request_for(fixture, digest));
        require(!rejected && rejected.error().code ==
                    build_worker_error_code_t::package_policy_violation,
                "forbidden customer source, script, build, or developer payload was accepted");
    };
    for (const auto extension : forbidden_extensions)
        reject("nested/source/payload" + std::string(extension));
    for (const auto path : forbidden_paths)
        reject(std::string(path));
    reject(std::string(32769, 'x'));
}

void verify_deny_link_policy() {
    build_worker_packaging_integration_t integration;
    deny_link_check_request_t clean{"AiDAStandalone", {"imgui", "z3"},
                                    {"nlohmann_json"}, {"capstone", "zydis"}};
    const auto accepted = integration.check_deny_links(clean);
    require(accepted && accepted.value().inspected == 6,
            "clean direct/interface/transitive link graph was rejected");
    for (const auto& request : std::array<deny_link_check_request_t, 3>{
             deny_link_check_request_t{"direct", {"lmdb"}, {}, {}},
             deny_link_check_request_t{"interface", {}, {"unicorn::unicorn"}, {}},
             deny_link_check_request_t{"transitive", {}, {}, {"Remill-library"}}}) {
        const auto rejected = integration.check_deny_links(request);
        require(!rejected && rejected.error().code ==
                    build_worker_error_code_t::forbidden_link_detected,
                "forbidden dependency escaped a link-graph lane");
    }
    require(integration.deny_link_checks_completed() == 1,
            "deny-link success counter is not success-only");
}

void verify_real_distribution() {
    fixture_t fixture;
    build_worker_packaging_integration_t integration;
    const auto manifest_hash = file_hash(fixture.manifest_path());
    const auto verified = integration.verify_distribution_package(
        request_for(fixture, manifest_hash));
    require(static_cast<bool>(verified), verified ? "" : verified.error().stable_code);
    require(verified.value().artifacts_verified == 855 &&
                verified.value().workers_verified == 3 &&
                verified.value().dependencies_verified == 30 &&
                verified.value().resource_manifests_verified == 2 &&
                verified.value().acl_receipts_verified == 3 &&
                verified.value().notices_verified == 26 &&
                verified.value().protector_receipts_verified == 4 &&
                verified.value().signature_receipts_verified == 4 &&
                verified.value().exact_package_inventory && verified.value().no_network_fetch &&
                verified.value().disk_backed && verified.value().arc_license_gates_required &&
                verified.value().camoufox_only,
            "verified package evidence counters or policy results are incomplete");
    require(integration.package_verifications_completed() == 1,
            "package success counter did not advance exactly once");
    verify_allowed_customer_path_neighbors(fixture, integration);
    require(integration.package_verifications_completed() == 2,
            "allowed customer resource neighbors did not reach the production verifier");

    auto widened_budget = request_for(fixture, manifest_hash);
    widened_budget.maximum_total_artifact_bytes = k_default_package_total_limit + 1;
    const auto widened_rejected = integration.verify_distribution_package(widened_budget);
    require(!widened_rejected && widened_rejected.error().code ==
                build_worker_error_code_t::invalid_argument,
            "caller-widened package resource budget was accepted");

    auto wrong_authority = request_for(fixture, manifest_hash);
    wrong_authority.expected_source_authority_sha256 = std::string(64, 'a');
    const auto authority_rejected = integration.verify_distribution_package(wrong_authority);
    require(!authority_rejected && authority_rejected.error().code ==
                build_worker_error_code_t::schema_mismatch,
            "unbound source authority was accepted");

    json traversal = fixture.manifest();
    traversal["artifacts"][0]["relative_path"] = "../escape.exe";
    const auto traversal_hash = fixture.publish_manifest(traversal, "traversal.json");
    const auto traversal_rejected = integration.verify_distribution_package(
        request_for(fixture, traversal_hash));
    require(!traversal_rejected && traversal_rejected.error().code ==
                build_worker_error_code_t::unsafe_path,
            "artifact path traversal was accepted");

    json v1 = fixture.manifest();
    v1["schema_version"] = 1;
    const auto v1_hash = fixture.publish_manifest(v1, "v1.json");
    const auto v1_rejected = integration.verify_distribution_package(request_for(fixture, v1_hash));
    require(!v1_rejected && v1_rejected.error().code ==
                build_worker_error_code_t::schema_mismatch,
            "distribution schema v1 was accepted");

    const auto attached_manifest_path = fixture.package() / "attached-manifest.json";
    write_text(attached_manifest_path, fixture.manifest().dump() + "\n");
    auto attached_request = request_for(fixture, file_hash(attached_manifest_path));
    attached_request.manifest_path = attached_manifest_path;
    const auto attached_rejected = integration.verify_distribution_package(attached_request);
    require(!attached_rejected && attached_rejected.error().code ==
                build_worker_error_code_t::package_policy_violation,
            "package-internal distribution manifest was accepted");
    std::filesystem::remove(attached_manifest_path);

    json wrong_hash = fixture.manifest();
    wrong_hash["artifacts"][0]["sha256"] = std::string(64, 'a');
    const auto wrong_hash_digest = fixture.publish_manifest(wrong_hash, "wrong-hash.json");
    const auto hash_rejected = integration.verify_distribution_package(
        request_for(fixture, wrong_hash_digest));
    require(!hash_rejected && hash_rejected.error().code ==
                build_worker_error_code_t::hash_mismatch,
            "artifact hash mismatch was accepted");

    json bad_boolean = fixture.manifest();
    bad_boolean["customer_sidecars"]["developer_source_shipped"] = "false";
    const auto bad_boolean_hash = fixture.publish_manifest(bad_boolean, "bad-boolean.json");
    const auto boolean_rejected = integration.verify_distribution_package(
        request_for(fixture, bad_boolean_hash));
    require(!boolean_rejected && boolean_rejected.error().code ==
                build_worker_error_code_t::package_policy_violation,
            "non-boolean customer source policy was accepted");

    json stale_dependency = fixture.manifest();
    auto zydis = std::find_if(stale_dependency["dependencies"].begin(),
                              stale_dependency["dependencies"].end(), [](const json& value) {
                                  return value.at("id") == "zydis";
                              });
    require(zydis != stale_dependency["dependencies"].end(),
            "locked dependency fixture is absent");
    (*zydis)["version"] = "4.1.0";
    const auto stale_dependency_hash = fixture.publish_manifest(
        stale_dependency, "stale-dependency.json");
    const auto stale_dependency_rejected = integration.verify_distribution_package(
        request_for(fixture, stale_dependency_hash));
    require(!stale_dependency_rejected && stale_dependency_rejected.error().code ==
                build_worker_error_code_t::dependency_graph_invalid,
            "stale production dependency identity was accepted");

    json widened_worker_dependencies = fixture.manifest();
    widened_worker_dependencies["workers"][0]["dependency_ids"].push_back("zlib");
    const auto widened_worker_dependencies_hash = fixture.publish_manifest(
        widened_worker_dependencies, "widened-worker-dependencies.json");
    const auto widened_worker_dependencies_rejected =
        integration.verify_distribution_package(
            request_for(fixture, widened_worker_dependencies_hash));
    require(!widened_worker_dependencies_rejected &&
                widened_worker_dependencies_rejected.error().code ==
                    build_worker_error_code_t::dependency_graph_invalid,
            "widened worker dependency authority was accepted");

    json missing_standalone = fixture.manifest();
    auto standalone = std::find_if(missing_standalone["artifacts"].begin(),
                                   missing_standalone["artifacts"].end(), [](const json& value) {
                                       return value.at("id") == "standalone-executable";
                                   });
    require(standalone != missing_standalone["artifacts"].end(),
            "standalone fixture artifact is absent");
    (*standalone)["id"] = "unbound-standalone";
    const auto missing_standalone_hash = fixture.publish_manifest(
        missing_standalone, "missing-standalone.json");
    const auto missing_standalone_rejected = integration.verify_distribution_package(
        request_for(fixture, missing_standalone_hash));
    require(!missing_standalone_rejected && missing_standalone_rejected.error().code ==
                build_worker_error_code_t::artifact_inventory_mismatch,
            "unbound protected standalone was accepted");

    const auto leaked_safe_headless_source = fixture.package() /
        "c03-safe-headless/nested/HARNESS.CPP";
    write_text(leaked_safe_headless_source, "source leak\n");
    fixture.publish_manifest(fixture.manifest(), "safe-headless-source-leak.json");
    const auto safe_headless_source_rejected = integration.verify_distribution_package(
        request_for(fixture, file_hash(fixture.manifest_path())));
    require(!safe_headless_source_rejected && safe_headless_source_rejected.error().code ==
                build_worker_error_code_t::package_policy_violation,
            "unlisted developer safe-headless source payload was accepted");
    std::filesystem::remove_all(fixture.package() / "c03-safe-headless");

    write_text(fixture.package() / "unlisted.bin", "unlisted\n");
    fixture.publish_manifest(fixture.manifest(), "unlisted.json");
    const auto unlisted_rejected = integration.verify_distribution_package(
        request_for(fixture, file_hash(fixture.manifest_path())));
    require(!unlisted_rejected && unlisted_rejected.error().code ==
                build_worker_error_code_t::artifact_inventory_mismatch,
            "unlisted customer artifact was accepted");
    std::filesystem::remove(fixture.package() / "unlisted.bin");

    const auto protector_path = fixture.package() / "deps/evidence/native.protector.json";
    std::ifstream protector_stream(protector_path, std::ios::binary);
    require(static_cast<bool>(protector_stream), "protector receipt fixture is unreadable");
    const auto original_protector = json::parse(protector_stream);
    json invalid_protector = original_protector;
    invalid_protector["post_process"]["protection_verified"] = false;
    write_text(protector_path, invalid_protector.dump() + "\n");
    json invalid_protector_manifest = fixture.manifest();
    fixture.refresh_artifact(invalid_protector_manifest, "native_decompiler-protector");
    const auto invalid_protector_hash = fixture.publish_manifest(
        invalid_protector_manifest, "invalid-protector.json");
    const auto protector_rejected = integration.verify_distribution_package(
        request_for(fixture, invalid_protector_hash));
    require(!protector_rejected && protector_rejected.error().code ==
                build_worker_error_code_t::protector_receipt_invalid,
            "fake protector receipt was accepted");
    write_text(protector_path, original_protector.dump() + "\n");

    const auto signature_path = fixture.package() / "deps/evidence/native.signature.json";
    std::ifstream signature_stream(signature_path, std::ios::binary);
    require(static_cast<bool>(signature_stream), "signature receipt fixture is unreadable");
    const auto original_signature = json::parse(signature_stream);
    json invalid_signature = original_signature;
    invalid_signature["signer_thumbprint_sha256"] = std::string(64, '4');
    write_text(signature_path, invalid_signature.dump() + "\n");
    json invalid_signature_manifest = fixture.manifest();
    fixture.refresh_artifact(invalid_signature_manifest, "native_decompiler-signature");
    const auto invalid_signature_hash = fixture.publish_manifest(
        invalid_signature_manifest, "invalid-signature.json");
    const auto signature_rejected = integration.verify_distribution_package(
        request_for(fixture, invalid_signature_hash));
    require(!signature_rejected && signature_rejected.error().code ==
                build_worker_error_code_t::signature_receipt_invalid,
            "fake signer receipt was accepted");
    write_text(signature_path, original_signature.dump() + "\n");

    const auto acl_path = fixture.package() / "deps/evidence/native.acl.json";
    std::ifstream acl_stream(acl_path, std::ios::binary);
    require(static_cast<bool>(acl_stream), "ACL receipt fixture is unreadable");
    const auto original_acl = json::parse(acl_stream);
    json weakened_acl = original_acl;
    weakened_acl["access"]["write"] = true;
    write_text(acl_path, weakened_acl.dump() + "\n");
    json weakened_acl_manifest = fixture.manifest();
    fixture.refresh_artifact(weakened_acl_manifest, "native_decompiler-acl");
    const auto weakened_acl_hash = fixture.publish_manifest(
        weakened_acl_manifest, "weakened-acl.json");
    const auto acl_rejected = integration.verify_distribution_package(
        request_for(fixture, weakened_acl_hash));
    require(!acl_rejected && acl_rejected.error().code ==
                build_worker_error_code_t::containment_policy_mismatch,
            "write-capable worker ACL receipt was accepted");
    write_text(acl_path, original_acl.dump() + "\n");

    const auto runtime_manifest_path = fixture.package() / "deps/AiDA_ManagedRuntime.manifest.json";
    const auto runtime_digest_path = fixture.package() / "deps/AiDA_ManagedRuntime.manifest.sha256";
    std::ifstream runtime_stream(runtime_manifest_path, std::ios::binary);
    require(static_cast<bool>(runtime_stream), "managed runtime fixture is unreadable");
    const auto original_runtime = json::parse(runtime_stream);
    json truncated_runtime = original_runtime;
    truncated_runtime["runtime"]["file_count"] = 192;
    write_text(runtime_manifest_path, truncated_runtime.dump() + "\n");
    write_text(runtime_digest_path, file_hash(runtime_manifest_path) + "\n");
    json truncated_runtime_outer = fixture.manifest();
    fixture.refresh_artifact(truncated_runtime_outer, "managed-runtime-manifest");
    fixture.refresh_artifact(truncated_runtime_outer, "managed-runtime-manifest-digest");
    const auto truncated_runtime_hash = fixture.publish_manifest(
        truncated_runtime_outer, "truncated-managed-runtime.json");
    const auto runtime_rejected = integration.verify_distribution_package(
        request_for(fixture, truncated_runtime_hash));
    require(!runtime_rejected && runtime_rejected.error().code ==
                build_worker_error_code_t::schema_mismatch,
            "truncated managed runtime manifest was accepted");
    write_text(runtime_manifest_path, original_runtime.dump() + "\n");
    write_text(runtime_digest_path, file_hash(runtime_manifest_path) + "\n");

    const auto ghidra_manifest_path = fixture.package() / "deps/AiDA_GhidraSpecs.manifest.json";
    const auto ghidra_digest_path = fixture.package() / "deps/AiDA_GhidraSpecs.manifest.sha256";
    std::ifstream ghidra_stream(ghidra_manifest_path, std::ios::binary);
    require(static_cast<bool>(ghidra_stream), "Ghidra specification fixture is unreadable");
    const auto original_ghidra = json::parse(ghidra_stream);
    json omitted_ghidra = original_ghidra;
    omitted_ghidra["specifications"]["files"].erase(
        omitted_ghidra["specifications"]["files"].end() - 1);
    write_text(ghidra_manifest_path, omitted_ghidra.dump() + "\n");
    write_text(ghidra_digest_path, file_hash(ghidra_manifest_path) + "\n");
    json omitted_ghidra_outer = fixture.manifest();
    fixture.refresh_artifact(omitted_ghidra_outer, "ghidra-spec-manifest");
    fixture.refresh_artifact(omitted_ghidra_outer, "ghidra-spec-manifest-digest");
    const auto omitted_ghidra_hash = fixture.publish_manifest(
        omitted_ghidra_outer, "omitted-ghidra-spec.json");
    const auto ghidra_rejected = integration.verify_distribution_package(
        request_for(fixture, omitted_ghidra_hash));
    require(!ghidra_rejected && ghidra_rejected.error().code ==
                build_worker_error_code_t::schema_mismatch,
            "incomplete Ghidra specification manifest was accepted");
    write_text(ghidra_manifest_path, original_ghidra.dump() + "\n");
    write_text(ghidra_digest_path, file_hash(ghidra_manifest_path) + "\n");

    const auto leaked_sdk_path = fixture.package() / "deps/dotnet/sdk/leak.dll";
    write_text(leaked_sdk_path, "sdk leak\n");
    json sdk_leak = fixture.manifest();
    sdk_leak["artifacts"].push_back({
        {"id", "managed-sdk-leak"}, {"kind", "worker_runtime"},
        {"relative_path", "deps/dotnet/sdk/leak.dll"},
        {"size_bytes", file_size(leaked_sdk_path)}, {"sha256", file_hash(leaked_sdk_path)},
        {"owner", "managed_cli_decompiler"}, {"license_ids", json::array()}});
    const auto sdk_leak_hash = fixture.publish_manifest(sdk_leak, "sdk-leak.json");
    const auto sdk_rejected = integration.verify_distribution_package(
        request_for(fixture, sdk_leak_hash));
    require(!sdk_rejected && sdk_rejected.error().code ==
                build_worker_error_code_t::package_policy_violation,
            "customer SDK payload leak was accepted");
    std::filesystem::remove_all(leaked_sdk_path.parent_path());

    const auto omitted_camoufox_path = fixture.package() /
        "deps/camoufox-135.0.1-beta.24-win.x86_64/fixture-501.bin";
    std::filesystem::remove(omitted_camoufox_path);
    json omitted_camoufox = fixture.manifest();
    omitted_camoufox["artifacts"].erase(
        std::remove_if(omitted_camoufox["artifacts"].begin(),
                       omitted_camoufox["artifacts"].end(), [](const json& value) {
                           return value.at("id") == "camoufox-fixture-501";
                       }),
        omitted_camoufox["artifacts"].end());
    const auto omitted_camoufox_hash = fixture.publish_manifest(
        omitted_camoufox, "omitted-camoufox.json");
    const auto camoufox_rejected = integration.verify_distribution_package(
        request_for(fixture, omitted_camoufox_hash));
    require(!camoufox_rejected && camoufox_rejected.error().code ==
                build_worker_error_code_t::artifact_inventory_mismatch,
            "incomplete Camoufox bundle was accepted");
    verify_forbidden_customer_path_policy(fixture, integration);
}

}

void run_build_packaging_integration_harness() {
    verify_deny_link_policy();
    verify_real_distribution();
}

}

int main() {
    try {
        aida::analysis::c03_test::run_build_packaging_integration_harness();
        std::cout << "build_packaging_integration_harness verified real package bytes\n";
        return 0;
    } catch (const std::exception& error) {
        aida::analysis::c03_test::assertion_telemetry::record_exception(error.what());
        std::cerr << error.what() << '\n';
        return 1;
    }
}
