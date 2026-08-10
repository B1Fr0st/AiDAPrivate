#include "workspace_fixture_builder.hpp"
#include "large_pe_fixture_builder.hpp"
#include "snapshot_hash.hpp"

#include "../c03/benchmark_sla_schema.hpp"
#include "../c03/assertion_telemetry/assertion_telemetry.hpp"
#include "../c03/evidence_hash.hpp"

#include <winioctl.h>
#include <psapi.h>

#include "../../src/core/mcp/compat/c03_compatibility_registration.hpp"
#include "../../src/core/mcp/registry/tool_registry.hpp"
#include "../../src/core/analysis/tile_decode_orchestrator.hpp"
#include "../../src/core/analysis/benchmark/benchmark_runner.hpp"
#include "../../src/core/analysis/benchmark/benchmark_scorecard.hpp"
#include "../../src/core/analysis/benchmark/benchmark_sla.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <intrin.h>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace {

using namespace aida::analysis;
using namespace aida::analysis::test_fixture;
using json = nlohmann::json;
using steady_clock_t = std::chrono::steady_clock;

std::uint64_t nanoseconds_since(steady_clock_t::time_point begin)
{
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
        steady_clock_t::now() - begin).count());
}

std::string cpu_vendor()
{
    int registers[4]{};
    __cpuid(registers, 0);
    std::array<char, 13> value{};
    std::memcpy(value.data(), &registers[1], 4);
    std::memcpy(value.data() + 4, &registers[3], 4);
    std::memcpy(value.data() + 8, &registers[2], 4);
    return value.data();
}

std::string cpu_model()
{
    int registers[4]{};
    __cpuid(registers, static_cast<int>(0x80000000u));
    if (static_cast<std::uint32_t>(registers[0]) < 0x80000004u)
        return {};
    std::array<char, 49> value{};
    for (std::uint32_t leaf = 0x80000002u; leaf <= 0x80000004u; ++leaf) {
        __cpuid(registers, static_cast<int>(leaf));
        std::memcpy(value.data() + (leaf - 0x80000002u) * 16, registers, 16);
    }
    std::string result(value.data());
    const auto first = result.find_first_not_of(' ');
    const auto last = result.find_last_not_of(' ');
    return first == std::string::npos ? std::string() : result.substr(first, last - first + 1);
}

std::string descriptor_text(const std::vector<std::uint8_t>& buffer, DWORD offset)
{
    if (offset == 0 || offset >= buffer.size()) return {};
    const char* begin = reinterpret_cast<const char*>(buffer.data() + offset);
    const std::size_t available = buffer.size() - offset;
    const void* terminator = std::memchr(begin, 0, available);
    if (!terminator) return {};
    return std::string(begin, static_cast<const char*>(terminator));
}

json storage_identity(const wchar_t* volume_path)
{
    json result{{"available", false}, {"device_path", nullptr}, {"vendor", nullptr},
        {"product", nullptr}, {"revision", nullptr}, {"serial", nullptr},
        {"bus_type", nullptr}, {"error", nullptr}};
    if (!volume_path || !volume_path[0] || volume_path[1] != L':') {
        result["error"] = "volume_device_path_unavailable";
        return result;
    }
    const std::wstring device = std::wstring(L"\\\\.\\") + volume_path[0] + L":";
    result["device_path"] = std::filesystem::path(device).u8string();
    HANDLE handle = CreateFileW(device.c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        result["error"] = std::string("open_failed:") + std::to_string(GetLastError());
        return result;
    }
    STORAGE_PROPERTY_QUERY query{};
    query.PropertyId = StorageDeviceProperty;
    query.QueryType = PropertyStandardQuery;
    std::vector<std::uint8_t> buffer(4096);
    DWORD returned = 0;
    const BOOL queried = DeviceIoControl(handle, IOCTL_STORAGE_QUERY_PROPERTY,
        &query, sizeof(query), buffer.data(), static_cast<DWORD>(buffer.size()), &returned, nullptr);
    const DWORD status = queried ? ERROR_SUCCESS : GetLastError();
    CloseHandle(handle);
    if (!queried || returned < sizeof(STORAGE_DEVICE_DESCRIPTOR)) {
        result["error"] = std::string("query_failed:") + std::to_string(status);
        return result;
    }
    buffer.resize((std::min<std::size_t>)(buffer.size(), returned));
    const auto* descriptor = reinterpret_cast<const STORAGE_DEVICE_DESCRIPTOR*>(buffer.data());
    result["available"] = true;
    result["vendor"] = descriptor_text(buffer, descriptor->VendorIdOffset);
    result["product"] = descriptor_text(buffer, descriptor->ProductIdOffset);
    result["revision"] = descriptor_text(buffer, descriptor->ProductRevisionOffset);
    result["serial"] = descriptor_text(buffer, descriptor->SerialNumberOffset);
    result["bus_type"] = static_cast<unsigned>(descriptor->BusType);
    return result;
}

json file_version_identity(const std::filesystem::path& path)
{
    json result{{"available", false}, {"value", nullptr}, {"error", nullptr}};
    DWORD ignored = 0;
    const DWORD bytes = GetFileVersionInfoSizeW(path.c_str(), &ignored);
    if (bytes == 0) {
        result["error"] = std::string("version_unavailable:") + std::to_string(GetLastError());
        return result;
    }
    std::vector<std::uint8_t> buffer(bytes);
    if (!GetFileVersionInfoW(path.c_str(), 0, bytes, buffer.data())) {
        result["error"] = std::string("version_read_failed:") + std::to_string(GetLastError());
        return result;
    }
    VS_FIXEDFILEINFO* fixed = nullptr;
    UINT fixed_size = 0;
    if (!VerQueryValueW(buffer.data(), L"\\", reinterpret_cast<void**>(&fixed), &fixed_size) ||
        !fixed || fixed_size < sizeof(VS_FIXEDFILEINFO) || fixed->dwSignature != 0xFEEF04BDu) {
        result["error"] = "version_record_invalid";
        return result;
    }
    result["available"] = true;
    result["value"] = std::to_string(HIWORD(fixed->dwFileVersionMS)) + "." +
        std::to_string(LOWORD(fixed->dwFileVersionMS)) + "." +
        std::to_string(HIWORD(fixed->dwFileVersionLS)) + "." +
        std::to_string(LOWORD(fixed->dwFileVersionLS));
    return result;
}

const char* format_name(format_id_t format)
{
    switch (format) {
    case format_id_t::pe32: return "PE32";
    case format_id_t::pe32_plus: return "PE32+";
    case format_id_t::elf: return "ELF";
    case format_id_t::jar: return "JAR";
    case format_id_t::macho: return "Mach-O";
    case format_id_t::macho_fat: return "fat Mach-O";
    case format_id_t::coff: return "COFF";
    case format_id_t::archive: return "archive";
    case format_id_t::zip: return "ZIP";
    case format_id_t::apk: return "APK";
    case format_id_t::ipa: return "IPA";
    case format_id_t::dex: return "DEX";
    case format_id_t::oat: return "OAT";
    case format_id_t::vdex: return "VDEX";
    case format_id_t::classfile: return "classfile";
    default: return "unknown";
    }
}

const char* architecture_name(architecture_id_t architecture)
{
    switch (architecture) {
    case architecture_id_t::x86: return "x86";
    case architecture_id_t::x86_64: return "x86-64";
    case architecture_id_t::arm: return "ARM";
    case architecture_id_t::aarch64: return "AArch64";
    case architecture_id_t::mips: return "MIPS";
    case architecture_id_t::ppc: return "PowerPC";
    case architecture_id_t::ppc64: return "PowerPC64";
    case architecture_id_t::riscv: return "RISC-V";
    case architecture_id_t::jvm_bytecode: return "JVM bytecode";
    case architecture_id_t::arm64ec: return "ARM64EC";
    case architecture_id_t::mips64: return "MIPS64";
    case architecture_id_t::riscv32: return "RISC-V32";
    case architecture_id_t::riscv64: return "RISC-V64";
    case architecture_id_t::dalvik_bytecode: return "Dalvik bytecode";
    default: return "unknown";
    }
}

const char* architecture_mode_name(architecture_mode_t mode)
{
    switch (mode) {
    case architecture_mode_t::x86_16: return "x86-16";
    case architecture_mode_t::x86_32: return "x86-32";
    case architecture_mode_t::x86_64: return "x86-64";
    case architecture_mode_t::arm_a32: return "ARM A32";
    case architecture_mode_t::arm_thumb: return "ARM Thumb";
    case architecture_mode_t::aarch64: return "AArch64";
    case architecture_mode_t::mips32: return "MIPS32";
    case architecture_mode_t::mips64: return "MIPS64";
    case architecture_mode_t::ppc32: return "PowerPC32";
    case architecture_mode_t::ppc64: return "PowerPC64";
    case architecture_mode_t::riscv32: return "RISC-V32";
    case architecture_mode_t::riscv64: return "RISC-V64";
    case architecture_mode_t::jvm: return "JVM";
    case architecture_mode_t::dalvik: return "Dalvik";
    default: return "unknown";
    }
}

std::uint64_t executable_bytes(const std::shared_ptr<const workspace_image_t>& image)
{
    std::uint64_t total = 0;
    if (!image) return total;
    for (const auto& section : image->sections) {
        if ((section.permissions & image_permission_execute) != 0)
            total += (std::max)(section.virtual_size, section.file_size);
    }
    if (total == 0) {
        for (const auto& segment : image->segments) {
            if ((segment.permissions & image_permission_execute) != 0)
                total += (std::max)(segment.virtual_size, segment.file_size);
        }
    }
    return total;
}

std::uint64_t zero_bytes(const std::filesystem::path& path, std::uint64_t expected_size)
{
    std::ifstream stream(path, std::ios::binary);
    if (!stream)
        throw fixture_error_t("benchmark fixture cannot be opened for zero-padding qualification");
    std::vector<char> buffer(1024 * 1024);
    std::uint64_t consumed = 0;
    std::uint64_t zeros = 0;
    while (stream) {
        stream.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
        const auto count = stream.gcount();
        if (count <= 0)
            break;
        consumed += static_cast<std::uint64_t>(count);
        zeros += static_cast<std::uint64_t>(std::count(buffer.begin(), buffer.begin() + count, '\0'));
    }
    if (stream.bad() || consumed != expected_size)
        throw fixture_error_t("benchmark fixture changed or failed during zero-padding qualification");
    return zeros;
}

json process_memory_snapshot()
{
    json result{{"available", false}, {"working_set_bytes", nullptr},
        {"peak_working_set_bytes", nullptr}, {"private_bytes", nullptr},
        {"pagefile_bytes", nullptr}, {"peak_pagefile_bytes", nullptr}, {"error", nullptr}};
    using get_process_memory_info_t = BOOL(WINAPI*)(HANDLE, PPROCESS_MEMORY_COUNTERS, DWORD);
    const auto function = reinterpret_cast<get_process_memory_info_t>(
        GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "K32GetProcessMemoryInfo"));
    if (!function) {
        result["error"] = std::string("K32GetProcessMemoryInfo unavailable:") +
            std::to_string(GetLastError());
        return result;
    }
    PROCESS_MEMORY_COUNTERS_EX counters{};
    counters.cb = static_cast<DWORD>(sizeof(counters));
    if (!function(GetCurrentProcess(), reinterpret_cast<PPROCESS_MEMORY_COUNTERS>(&counters),
        static_cast<DWORD>(sizeof(counters)))) {
        result["error"] = std::string("K32GetProcessMemoryInfo failed:") +
            std::to_string(GetLastError());
        return result;
    }
    result["available"] = true;
    result["working_set_bytes"] = counters.WorkingSetSize;
    result["peak_working_set_bytes"] = counters.PeakWorkingSetSize;
    result["private_bytes"] = counters.PrivateUsage;
    result["pagefile_bytes"] = counters.PagefileUsage;
    result["peak_pagefile_bytes"] = counters.PeakPagefileUsage;
    return result;
}

json database_measurement(const workspace_database_snapshot_t& snapshot)
{
    return json{{"path", snapshot.path}, {"schema_version", snapshot.schema_version},
        {"persisted_generation", snapshot.persisted_generation},
        {"persisted_analysis_revision", snapshot.persisted_analysis_revision},
        {"persisted_overlay_revision", snapshot.persisted_overlay_revision},
        {"database_bytes", snapshot.database_bytes}, {"wal_bytes", snapshot.wal_bytes},
        {"last_commit_logical_bytes", snapshot.last_commit_logical_bytes},
        {"logical_bytes", snapshot.cumulative_logical_bytes},
        {"last_commit_rows", snapshot.last_commit_rows}, {"rows", snapshot.cumulative_rows},
        {"last_commit_page_write_bytes", snapshot.last_commit_page_write_bytes},
        {"page_write_bytes", snapshot.cumulative_page_write_bytes},
        {"last_commit_elapsed_us", snapshot.last_commit_elapsed_us},
        {"write_amplification", snapshot.cumulative_logical_bytes == 0
            ? json(nullptr) : json(static_cast<double>(snapshot.cumulative_page_write_bytes) /
                static_cast<double>(snapshot.cumulative_logical_bytes))}};
}

std::shared_ptr<analysis_workspace_t> open_benchmark_workspace(
    const std::filesystem::path& path, std::uint8_t profile,
    json* acquisition_metrics = nullptr,
    bool pin_profile = false)
{
    static const std::uint64_t run_nonce =
        (static_cast<std::uint64_t>(GetCurrentProcessId()) << 32) ^
        static_cast<std::uint64_t>(steady_clock_t::now().time_since_epoch().count());
    open_static_workspace_request_t request;
    request.source_path = path.u8string();
    request.bin_name = path.filename().u8string();
    request.load_profile = {1, 0, profile, 0};
    if (!pin_profile) {
        for (unsigned shift = 0; shift < 64; shift += 8)
            request.load_profile.push_back(static_cast<std::uint8_t>(run_nonce >> shift));
    }
    const auto acquisition_begin = steady_clock_t::now();
    auto opened = workspace_registry().open_static(request);
    const auto acquisition_ns = nanoseconds_since(acquisition_begin);
    if (!opened)
        throw fixture_error_t(opened.error().stable_code() + ":" + opened.error().message);
    const auto service_begin = steady_clock_t::now();
    install_services(opened.value());
    const auto service_ns = nanoseconds_since(service_begin);
    if (acquisition_metrics) {
        *acquisition_metrics = json{{"identity_provider_format_open_ns", acquisition_ns},
            {"service_install_ns", service_ns},
            {"workspace_setup_ns", acquisition_ns + service_ns}};
    }
    return opened.take_value();
}

json host_identity(const std::filesystem::path& path)
{
    SYSTEM_INFO system{};
    GetNativeSystemInfo(&system);
    MEMORYSTATUSEX memory{};
    memory.dwLength = sizeof(memory);
    if (!GlobalMemoryStatusEx(&memory))
        throw fixture_error_t("GlobalMemoryStatusEx failed");
    wchar_t computer[MAX_COMPUTERNAME_LENGTH + 1]{};
    DWORD computer_size = static_cast<DWORD>(std::size(computer));
    GetComputerNameW(computer, &computer_size);
    wchar_t volume_path[MAX_PATH]{};
    const auto absolute = std::filesystem::absolute(path).wstring();
    GetVolumePathNameW(absolute.c_str(), volume_path, static_cast<DWORD>(std::size(volume_path)));
    wchar_t filesystem_name[MAX_PATH]{};
    DWORD serial = 0, maximum_component = 0, flags = 0;
    GetVolumeInformationW(volume_path, nullptr, 0, &serial, &maximum_component, &flags,
                          filesystem_name, static_cast<DWORD>(std::size(filesystem_name)));
    ULARGE_INTEGER free_available{}, total_bytes{}, total_free{};
    if (!GetDiskFreeSpaceExW(volume_path, &free_available, &total_bytes, &total_free))
        throw fixture_error_t("GetDiskFreeSpaceExW failed");
    OSVERSIONINFOW version{};
    version.dwOSVersionInfoSize = sizeof(version);
    using rtl_get_version_t = LONG(WINAPI*)(OSVERSIONINFOW*);
    auto rtl_get_version = reinterpret_cast<rtl_get_version_t>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion"));
    if (!rtl_get_version || rtl_get_version(&version) != 0)
        throw fixture_error_t("RtlGetVersion failed");
    return json{{"computer", std::filesystem::path(computer).u8string()},
        {"cpu_vendor", cpu_vendor()}, {"cpu_model", cpu_model()},
        {"logical_processors", system.dwNumberOfProcessors},
        {"processor_architecture", system.wProcessorArchitecture},
        {"page_size", system.dwPageSize}, {"installed_memory_bytes", memory.ullTotalPhys},
        {"available_memory_bytes", memory.ullAvailPhys},
        {"os", json{{"platform", "Windows"}, {"major", version.dwMajorVersion},
            {"minor", version.dwMinorVersion}, {"build", version.dwBuildNumber}}},
        {"volume", std::filesystem::path(volume_path).u8string()},
        {"filesystem", std::filesystem::path(filesystem_name).u8string()},
        {"drive_type", GetDriveTypeW(volume_path)}, {"volume_serial", serial},
        {"volume_total_bytes", total_bytes.QuadPart}, {"volume_free_bytes", total_free.QuadPart},
        {"volume_available_bytes", free_available.QuadPart},
        {"storage_device", storage_identity(volume_path)}};
}

json snapshot_counts(const analysis_snapshot_t& snapshot,
                     const std::shared_ptr<search_index_t>& search = {})
{
    std::uint64_t decoded = 0, data = 0, padding = 0, conflict = 0, undecodable = 0;
    std::uint64_t call_edges = 0;
    for (const auto& edge : snapshot.edges)
        if (edge.kind == edge_kind_t::call || edge.kind == edge_kind_t::tail_call)
            ++call_edges;
    for (const auto& coverage : snapshot.coverage) {
        switch (coverage.reason) {
        case coverage_reason_t::decoded: decoded += coverage.size; break;
        case coverage_reason_t::proven_data: data += coverage.size; break;
        case coverage_reason_t::padding: padding += coverage.size; break;
        case coverage_reason_t::conflict: conflict += coverage.size; break;
        case coverage_reason_t::undecodable: undecodable += coverage.size; break;
        default: break;
        }
    }
    return json{{"instructions", snapshot.instructions.size()}, {"blocks", snapshot.blocks.size()},
        {"functions", snapshot.functions.size()}, {"cfg_edges", snapshot.edges.size()},
        {"call_edges", call_edges},
        {"xrefs", snapshot.xrefs.size()}, {"strings", snapshot.strings.size()},
        {"symbols", snapshot.symbols.size()},
        {"types", search ? search->types().size() : 0},
        {"globals", search ? search->data_candidates().size() : 0},
        {"coverage_decoded_bytes", decoded},
        {"coverage_data_bytes", data}, {"coverage_padding_bytes", padding},
        {"coverage_conflict_bytes", conflict}, {"coverage_undecodable_bytes", undecodable}};
}

std::shared_ptr<analysis_workspace_t> reopen_persisted_benchmark_workspace(
    const std::filesystem::path& path,
    std::uint8_t profile,
    const workspace_identity_t& expected_identity,
    std::uint64_t expected_analysis_revision,
    std::uint64_t expected_overlay_revision,
    const json& expected_counts,
    json& measurement,
    bool pin_profile = false)
{
    const auto wall_begin = steady_clock_t::now();
    const auto memory_before = process_memory_snapshot();
    const auto acquisition_begin = steady_clock_t::now();
    auto workspace = open_benchmark_workspace(path, profile, nullptr, pin_profile);
    const auto acquisition_ns = nanoseconds_since(acquisition_begin);
    try {
        if (workspace->identity().binary_id() != expected_identity.binary_id() ||
            workspace->identity().content_hash() != expected_identity.content_hash() ||
            workspace->identity().load_profile_hash() != expected_identity.load_profile_hash())
            throw fixture_error_t("warm reopen acquisition did not preserve the exact cold workspace identity");
        const auto admission_snapshot = workspace->snapshot();
        if (!admission_snapshot || admission_snapshot->baseline_complete ||
            admission_snapshot->binary_id != expected_identity.binary_id() ||
            admission_snapshot->load_profile_hash != expected_identity.load_profile_hash() ||
            admission_snapshot->generation != workspace->generation() ||
            admission_snapshot->analysis_revision != 0 ||
            admission_snapshot->overlay_revision != 0 ||
            admission_snapshot->normalized_image != workspace->normalized_image() ||
            admission_snapshot->image != workspace->image() || workspace->analysis_revision() != 0 ||
            workspace->overlay_revision() != 0 || workspace->search_index())
            throw fixture_error_t("warm reopen acquisition did not begin from a parsed revision-zero publication");

        const auto snapshot_begin = steady_clock_t::now();
        auto loaded = workspace->database()->load_snapshot(
            workspace->normalized_image(), workspace->image(), workspace->cancellation_token());
        const auto snapshot_load_ns = nanoseconds_since(snapshot_begin);
        if (!loaded || !loaded.value())
            throw fixture_error_t(loaded ? "warm reopen found no committed baseline" :
                loaded.error().stable_code() + ":" + loaded.error().message);
        auto snapshot = loaded.take_value();
        if (snapshot->generation != workspace->generation() ||
            snapshot->binary_id != expected_identity.binary_id() ||
            snapshot->load_profile_hash != expected_identity.load_profile_hash() ||
            snapshot->analysis_revision != expected_analysis_revision ||
            snapshot->overlay_revision != expected_overlay_revision ||
            snapshot->normalized_image != workspace->normalized_image() ||
            snapshot->image != workspace->image() ||
            !snapshot->baseline_complete)
            throw fixture_error_t("warm reopen persisted revisions did not match the cold publication");

        const auto products_begin = steady_clock_t::now();
        auto products = workspace->database()->load_search_products(
            snapshot->generation, snapshot->analysis_revision,
            snapshot->overlay_revision, workspace->cancellation_token());
        const auto products_load_ns = nanoseconds_since(products_begin);
        if (!products)
            throw fixture_error_t(products.error().stable_code() + ":" + products.error().message);

        const auto index_begin = steady_clock_t::now();
        auto metrics = std::make_shared<analysis_metrics_t>(snapshot->generation);
        auto index = search_index_t::build(snapshot,
            std::move(products.value().data_candidates),
            std::move(products.value().switches),
            std::move(products.value().types), metrics, {},
            workspace->cancellation_token());
        const auto index_build_ns = nanoseconds_since(index_begin);
        if (!index)
            throw fixture_error_t(index.error().stable_code() + ":" + index.error().message);

        const auto publish_begin = steady_clock_t::now();
        auto published = workspace->publish_analysis_bundle(
            workspace->generation(), workspace->analysis_revision(), snapshot,
            index.take_value(), true);
        const auto publish_ns = nanoseconds_since(publish_begin);
        if (!published || workspace->analysis_revision() != expected_analysis_revision ||
            workspace->overlay_revision() != expected_overlay_revision ||
            workspace->progress().readiness != workspace_readiness_t::baseline_ready ||
            !workspace->snapshot() || !workspace->search_index())
            throw fixture_error_t(published ? "warm reopen publication state mismatch" :
                published.error().stable_code() + ":" + published.error().message);
        const auto counts = snapshot_counts(*workspace->snapshot(), workspace->search_index());
        if (counts != expected_counts)
            throw fixture_error_t("warm reopen counts diverged from the cold committed publication");
        const auto database = workspace->database()->snapshot();

        measurement = json{{"wall_ns", nanoseconds_since(wall_begin)},
            {"cache_state", "warm_persisted_reopen"},
            {"acquisition_ns", acquisition_ns}, {"snapshot_load_ns", snapshot_load_ns},
            {"search_products_load_ns", products_load_ns},
            {"search_index_rebuild_ns", index_build_ns}, {"publication_ns", publish_ns},
            {"success", true}, {"reanalysis_started", false},
            {"identity_match", true}, {"revision_match", true},
            {"binary_id", workspace->identity().binary_id().to_hex()},
            {"source_path", workspace->identity().normalized_source_path()},
            {"member_path", workspace->identity().normalized_member_path()
                ? json(*workspace->identity().normalized_member_path()) : json(nullptr)},
            {"analysis_revision", workspace->analysis_revision()},
            {"overlay_revision", workspace->overlay_revision()},
            {"memory_before", memory_before}, {"memory_after", process_memory_snapshot()},
            {"database", database_measurement(database)},
            {"counts", std::move(counts)}};
        return workspace;
    } catch (...) {
        try { close_workspace(workspace, true); } catch (...) {}
        throw;
    }
}

json runtime_snapshot_json(const aida::infra::taskflow_runtime::runtime_snapshot_t& snapshot)
{
    json active_per_domain = json::array();
    for (std::size_t index = 0; index < aida::infra::taskflow_runtime::executor_domain_count; ++index)
        active_per_domain.push_back(snapshot.active_per_domain[index]);
    return json{{"total_submitted", snapshot.total_submitted},
        {"total_rejected", snapshot.total_rejected}, {"total_cancelled", snapshot.total_cancelled},
        {"total_failed", snapshot.total_failed}, {"total_timed_out", snapshot.total_timed_out},
        {"total_active", snapshot.total_active}, {"active_per_domain", std::move(active_per_domain)},
        {"oldest_active_ms", snapshot.oldest_active_ms},
        {"work_queue_pending", snapshot.work_queue_pending},
        {"service_queue_pending", snapshot.service_queue_pending},
        {"critical_queue_pending", snapshot.critical_queue_pending},
        {"work_queue_active", snapshot.work_queue_active},
        {"service_queue_active", snapshot.service_queue_active},
        {"critical_queue_active", snapshot.critical_queue_active},
        {"accepting", snapshot.accepting}, {"shutting_down", snapshot.shutting_down},
        {"labels_under_pressure", snapshot.labels_under_pressure}};
}

json instrumentation_summary(const analysis_metrics_snapshot_t& snapshot)
{
    const auto value = [&](analysis_metric_t metric) { return snapshot.value(metric); };
    json phases = json::array();
    for (std::size_t index = 0; index < baseline_phase_count; ++index) {
        const auto phase = static_cast<baseline_phase_t>(index);
        const auto& metric = snapshot.phases[index];
        phases.push_back(json{{"name", analysis_metrics_t::phase_name(phase)},
            {"invocations", metric.invocations}, {"wall_ns", metric.wall_ns},
            {"cpu_ns", metric.cpu_ns}, {"bytes_in", metric.bytes_in},
            {"bytes_out", metric.bytes_out}, {"work_items", metric.work_items},
            {"cancellation_checks", metric.cancellation_checks},
            {"failures", metric.failures}, {"queue_depth_peak", metric.queue_depth_peak},
            {"active_workers_peak", metric.active_workers_peak}});
    }
    return json{{"wall_ns", snapshot.wall_ns}, {"process_cpu_ns", snapshot.process_cpu_ns},
        {"generation", snapshot.generation}, {"phases", std::move(phases)},
        {"bytes", json{{"file", value(analysis_metric_t::file_bytes)},
            {"executable", value(analysis_metric_t::executable_bytes)},
            {"mapped", value(analysis_metric_t::mapped_bytes)},
            {"read", value(analysis_metric_t::read_bytes)},
            {"copied", value(analysis_metric_t::copied_bytes)},
            {"decoded", value(analysis_metric_t::decoded_bytes)},
            {"indexed", value(analysis_metric_t::indexed_bytes)}}},
        {"provider_io", json{{"leases", value(analysis_metric_t::provider_leases)},
            {"mapped_windows", value(analysis_metric_t::mapped_windows)},
            {"revalidations", value(analysis_metric_t::provider_revalidations)}}},
        {"facts", json{{"instructions", value(analysis_metric_t::instructions)},
            {"blocks", value(analysis_metric_t::blocks)},
            {"functions", value(analysis_metric_t::functions)},
            {"cfg_edges", value(analysis_metric_t::cfg_edges)},
            {"call_edges", value(analysis_metric_t::call_edges)},
            {"xrefs", value(analysis_metric_t::xrefs)},
            {"strings", value(analysis_metric_t::strings)},
            {"data_candidates", value(analysis_metric_t::data_candidates)},
            {"symbols", value(analysis_metric_t::symbols)},
            {"types", value(analysis_metric_t::types)},
            {"switches", value(analysis_metric_t::switches)},
            {"thunks", value(analysis_metric_t::thunks)},
            {"noreturn_functions", value(analysis_metric_t::noreturn_functions)}}},
        {"coverage", json{{"decoded_bytes",
                value(analysis_metric_t::coverage_decoded_bytes)},
            {"data_bytes", value(analysis_metric_t::coverage_data_bytes)},
            {"padding_bytes", value(analysis_metric_t::coverage_padding_bytes)},
            {"conflict_bytes", value(analysis_metric_t::coverage_conflict_bytes)},
            {"undecodable_bytes", value(analysis_metric_t::coverage_undecodable_bytes)}}},
        {"workers", json{{"tasks_scheduled", value(analysis_metric_t::tasks_scheduled)},
            {"tasks_completed", value(analysis_metric_t::tasks_completed)},
            {"tasks_rejected", value(analysis_metric_t::tasks_rejected)},
            {"work_items", value(analysis_metric_t::work_items)},
            {"peak_workers", value(analysis_metric_t::peak_workers)},
            {"peak_queue_depth", value(analysis_metric_t::peak_queue_depth)},
            {"cancellation_checks", value(analysis_metric_t::cancellation_checks)}}},
        {"memory", json{{"peak_private_bytes", value(analysis_metric_t::peak_private_bytes)},
            {"peak_committed_bytes", value(analysis_metric_t::peak_committed_bytes)}}},
        {"database", json{{"database_bytes", value(analysis_metric_t::database_bytes)},
            {"bytes_written", value(analysis_metric_t::database_bytes_written)},
            {"logical_bytes", value(analysis_metric_t::database_logical_bytes)},
            {"rows", value(analysis_metric_t::database_rows)},
            {"commit_elapsed_ns", value(analysis_metric_t::database_commit_elapsed_ns)},
            {"persistence_batches", value(analysis_metric_t::persistence_batches)},
            {"write_amplification", value(analysis_metric_t::database_logical_bytes) == 0
                ? json(nullptr) : json(static_cast<double>(
                    value(analysis_metric_t::database_bytes_written)) /
                    static_cast<double>(value(analysis_metric_t::database_logical_bytes)))}}},
        {"cache", json{{"hits", value(analysis_metric_t::cache_hits)},
            {"misses", value(analysis_metric_t::cache_misses)},
            {"invalidations", value(analysis_metric_t::cache_invalidations)}}},
        {"cancellation", json{{"requests", value(analysis_metric_t::cancellation_requests)},
            {"completions", value(analysis_metric_t::cancellation_completions)},
            {"latency_ns", value(analysis_metric_t::cancellation_latency_ns)}}},
        {"fairness", json{{"concurrent_workspace_peak",
                value(analysis_metric_t::concurrent_workspace_peak)},
            {"wait_ns", value(analysis_metric_t::fairness_wait_ns)},
            {"service_units", value(analysis_metric_t::fairness_service_units)}}},
        {"mcp", json{{"calls", value(analysis_metric_t::mcp_calls)},
            {"latency_ns", value(analysis_metric_t::mcp_latency_ns)},
            {"latency_max_ns", value(analysis_metric_t::mcp_latency_max_ns)}}},
        {"decompiler", json{{"cold_calls", value(analysis_metric_t::decompile_cold_calls)},
            {"cold_latency_ns", value(analysis_metric_t::decompile_cold_latency_ns)},
            {"cold_latency_max_ns", value(analysis_metric_t::decompile_cold_latency_max_ns)},
            {"warm_calls", value(analysis_metric_t::decompile_warm_calls)},
            {"warm_latency_ns", value(analysis_metric_t::decompile_warm_latency_ns)},
            {"warm_latency_max_ns", value(analysis_metric_t::decompile_warm_latency_max_ns)}}},
        {"worker_pool", json{
            {"slots_busy_ns", value(analysis_metric_t::worker_slots_busy_ns)},
            {"slots_scheduled_ns", value(analysis_metric_t::worker_slots_scheduled_ns)},
            {"utilization", value(analysis_metric_t::worker_slots_scheduled_ns) == 0
                ? json(nullptr) : json(static_cast<double>(
                    value(analysis_metric_t::worker_slots_busy_ns)) /
                    static_cast<double>(value(analysis_metric_t::worker_slots_scheduled_ns)))},
            {"queue_wait_ns_total", value(analysis_metric_t::queue_wait_ns_total)},
            {"queue_wait_max_ns", value(analysis_metric_t::queue_wait_max_ns)},
            {"queue_depth_mean", value(analysis_metric_t::queue_depth_samples) == 0
                ? json(nullptr) : json(static_cast<double>(
                    value(analysis_metric_t::queue_depth_sum)) /
                    static_cast<double>(value(analysis_metric_t::queue_depth_samples)))}}},
        {"decode_detail", json{
            {"tiles", value(analysis_metric_t::decode_tiles)},
            {"requests", value(analysis_metric_t::decode_requests)},
            {"frontier_seeds", value(analysis_metric_t::decode_frontier_seeds)},
            {"waves", value(analysis_metric_t::decode_waves)},
            {"cross_tile_edges", value(analysis_metric_t::decode_cross_tile_edges)},
            {"invalid_bytes", value(analysis_metric_t::decode_invalid_bytes)},
            {"invalid_runs", value(analysis_metric_t::decode_invalid_runs)},
            {"duplicate_instructions", value(analysis_metric_t::decode_duplicate_instructions)},
            {"merge_ns", value(analysis_metric_t::decode_merge_ns)},
            {"lane_wall_ns_max", value(analysis_metric_t::decode_lane_wall_ns_max)},
            {"bytes_attempted", value(analysis_metric_t::decode_bytes_attempted)}}},
        {"post_decode", json{
            {"blocks_split", value(analysis_metric_t::blocks_split)},
            {"function_seeds_processed", value(analysis_metric_t::function_seeds_processed)},
            {"cfg_indirect_sites", value(analysis_metric_t::cfg_indirect_sites)},
            {"xref_candidates", value(analysis_metric_t::xref_candidates)},
            {"strings_scanned_bytes", value(analysis_metric_t::strings_scanned_bytes)},
            {"pass_merge_ns", value(analysis_metric_t::pass_merge_ns)}}},
        {"index", json{
            {"entries", value(analysis_metric_t::index_entries)},
            {"trigram_postings", value(analysis_metric_t::index_trigram_postings)},
            {"text_bytes", value(analysis_metric_t::index_text_bytes)},
            {"serialized_bytes", value(analysis_metric_t::index_serialized_bytes)},
            {"type_candidates_evaluated", value(analysis_metric_t::type_candidates_evaluated)}}},
        {"persistence_queue", json{
            {"wait_ns", value(analysis_metric_t::persist_queue_wait_ns)},
            {"depth_peak", value(analysis_metric_t::persist_queue_depth_peak)},
            {"pages_written", value(analysis_metric_t::persist_pages_written)},
            {"wal_bytes_peak", value(analysis_metric_t::persist_wal_bytes_peak)}}},
        {"memory_pressure", json{
            {"resident_bytes_peak", value(analysis_metric_t::resident_bytes_peak)},
            {"mapped_workspace_peak", value(analysis_metric_t::mapped_window_bytes_peak)},
            {"mapped_global_peak", value(analysis_metric_t::mapped_window_bytes_global_peak)},
            {"spill_bytes_peak", value(analysis_metric_t::spill_bytes_peak)},
            {"spill_written", value(analysis_metric_t::spill_bytes_written)},
            {"spill_read", value(analysis_metric_t::spill_bytes_read)},
            {"budget_rejections", value(analysis_metric_t::budget_rejections)},
            {"pressure_events", value(analysis_metric_t::memory_pressure_events)}}},
        {"decompiler_batch", json{
            {"calls", value(analysis_metric_t::decompile_batch_calls)},
            {"completed", value(analysis_metric_t::decompile_batch_completed)},
            {"failed", value(analysis_metric_t::decompile_batch_failed)},
            {"cancelled", value(analysis_metric_t::decompile_batch_cancelled)},
            {"wall_ns", value(analysis_metric_t::decompile_batch_wall_ns)},
            {"queue_depth_peak", value(analysis_metric_t::decompile_batch_queue_depth_peak)},
            {"memory_cache_hits", value(analysis_metric_t::decompile_memory_cache_hits)},
            {"persistent_cache_hits", value(analysis_metric_t::decompile_persistent_cache_hits)},
            {"funcs_per_s", value(analysis_metric_t::decompile_batch_wall_ns) == 0
                ? json(nullptr) : json(static_cast<double>(
                    value(analysis_metric_t::decompile_batch_completed)) * 1000000000.0 /
                    static_cast<double>(value(analysis_metric_t::decompile_batch_wall_ns)))}}}};
}

json background_batch_block(const analysis_metrics_snapshot_t& before,
                            const analysis_metrics_snapshot_t& after,
                            bool metrics_available)
{
    if (!metrics_available)
        return json{{"engine", "parallel_batch"}, {"status", "not_applicable"},
            {"reason", "workspace_background_metrics_unavailable"},
            {"funcs_per_s", nullptr}};
    const auto delta = [&](analysis_metric_t metric) {
        const auto after_value = after.value(metric);
        const auto before_value = before.value(metric);
        return after_value >= before_value ? after_value - before_value : 0ULL;
    };
    const auto calls = delta(analysis_metric_t::decompile_batch_calls);
    const auto completed = delta(analysis_metric_t::decompile_batch_completed);
    const auto wall_ns = delta(analysis_metric_t::decompile_batch_wall_ns);
    const auto memory_hits = delta(analysis_metric_t::decompile_memory_cache_hits);
    const auto persistent_hits = delta(analysis_metric_t::decompile_persistent_cache_hits);
    return json{{"engine", "parallel_batch"}, {"wiring", "registry_orchestrator"},
        {"calls", calls}, {"completed", completed},
        {"failed", delta(analysis_metric_t::decompile_batch_failed)},
        {"cancelled", delta(analysis_metric_t::decompile_batch_cancelled)},
        {"wall_ns", wall_ns},
        {"queue_depth_peak", after.value(analysis_metric_t::decompile_batch_queue_depth_peak) >=
                before.value(analysis_metric_t::decompile_batch_queue_depth_peak)
            ? after.value(analysis_metric_t::decompile_batch_queue_depth_peak)
            : before.value(analysis_metric_t::decompile_batch_queue_depth_peak)},
        {"memory_cache_hits", memory_hits},
        {"persistent_cache_hits", persistent_hits},
        {"cache_hit_rate", calls == 0 ? json(nullptr) : json(
            static_cast<double>(memory_hits + persistent_hits) / static_cast<double>(calls))},
        {"funcs_per_s", wall_ns == 0 ? json(nullptr) : json(
            static_cast<double>(completed) * 1000000000.0 / static_cast<double>(wall_ns))}};
}

json measured_percentile(std::vector<std::uint64_t> values, double rank)
{
    if (values.size() < 2) return nullptr;
    std::sort(values.begin(), values.end());
    const auto index = static_cast<std::size_t>((values.size() - 1) * rank);
    return values[index];
}

bool valid_decompile_sample(const decompiler_result_t& value,
                            const std::shared_ptr<analysis_workspace_t>& workspace)
{
    return value.binary_id == workspace->identity().binary_id() && value.function_id != 0 &&
        value.pseudocode.find_first_not_of(" \t\r\n") != std::string::npos &&
        !value.line_to_address.empty();
}

std::vector<std::size_t> stratified_function_indices(
    const std::vector<function_record_t>& functions)
{
    const std::size_t target = (std::min<std::size_t>)(32, functions.size());
    if (target == 0)
        return {};
    if (functions.size() <= target) {
        std::vector<std::size_t> all(functions.size());
        for (std::size_t index = 0; index < all.size(); ++index)
            all[index] = index;
        return all;
    }
    std::set<std::size_t> selected;
    const std::size_t address_samples = (std::min<std::size_t>)(20, target);
    for (std::size_t sample = 0; sample < address_samples; ++sample) {
        selected.insert(sample * (functions.size() - 1) /
            (address_samples == 1 ? 1 : address_samples - 1));
    }
    std::vector<std::size_t> by_size(functions.size());
    for (std::size_t index = 0; index < by_size.size(); ++index)
        by_size[index] = index;
    std::sort(by_size.begin(), by_size.end(), [&](std::size_t left, std::size_t right) {
        const auto left_size = functions[left].end.value - functions[left].start.value;
        const auto right_size = functions[right].end.value - functions[right].start.value;
        if (left_size != right_size) return left_size > right_size;
        return functions[left].start < functions[right].start;
    });
    const std::size_t size_target = (std::min)(target, address_samples + 6);
    for (std::size_t index : by_size) {
        if (selected.size() >= size_target) break;
        selected.insert(index);
    }
    std::vector<std::size_t> by_evidence(functions.size());
    for (std::size_t index = 0; index < by_evidence.size(); ++index)
        by_evidence[index] = index;
    std::sort(by_evidence.begin(), by_evidence.end(), [&](std::size_t left, std::size_t right) {
        if (functions[left].provenance != functions[right].provenance)
            return functions[left].provenance < functions[right].provenance;
        if (functions[left].confidence != functions[right].confidence)
            return functions[left].confidence < functions[right].confidence;
        return functions[left].start < functions[right].start;
    });
    for (std::size_t offset = 0; offset < by_evidence.size() && selected.size() < target; ++offset) {
        selected.insert(by_evidence[offset]);
        if (selected.size() < target)
            selected.insert(by_evidence[by_evidence.size() - 1 - offset]);
    }
    std::vector<std::size_t> result(selected.begin(), selected.end());
    std::sort(result.begin(), result.end(), [&](std::size_t left, std::size_t right) {
        return functions[left].start < functions[right].start;
    });
    return result;
}

json decompiler_measurements(const std::shared_ptr<analysis_workspace_t>& workspace,
                             analysis_metrics_t& interaction_metrics)
{
    auto snapshot = workspace->snapshot();
    auto service = workspace->decompiler();
    auto image = workspace->normalized_image();
    std::vector<std::uint64_t> cold_values;
    std::vector<std::uint64_t> warm_values;
    json errors = json::array();
    std::size_t attempts = 0;
    std::size_t cold_successes = 0;
    std::size_t warm_successes = 0;
    json selected_functions = json::array();
    if (!snapshot || !service || !image)
        throw fixture_error_t("decompiler benchmark requires a published normalized workspace");
    if (snapshot->functions.empty())
        throw fixture_error_t("decompiler benchmark requires recovered functions");
    const auto selected = stratified_function_indices(snapshot->functions);
    if (selected.empty())
        throw fixture_error_t("decompiler benchmark stratification selected no functions");
    for (std::size_t index : selected) {
        const auto& function = snapshot->functions[index];
        selected_functions.push_back(json{{"population_index", index},
            {"function_id", function.id}, {"address", std::to_string(function.start.value)},
            {"size", function.end.value - function.start.value},
            {"provenance", static_cast<unsigned>(function.provenance)},
            {"confidence", function.confidence}, {"thunk", function.thunk},
            {"noreturn", function.noreturn}});
        ++attempts;
        auto address = function.start;
        if (address.space == address_space_id_t::relative_virtual) {
            address.space = address_space_id_t::virtual_address;
            if (!checked_add_u64(address.value, image->image_base, address.value))
                throw fixture_error_t("decompiler benchmark address overflowed normalized image base");
        }
        auto begin = steady_clock_t::now();
        auto cold = service->decompile(address, {false, false});
        const auto cold_ns = nanoseconds_since(begin);
        interaction_metrics.record_decompile_latency(false, cold_ns);
        if (!cold || !valid_decompile_sample(cold.value(), workspace)) {
            errors.push_back(json{{"function", index}, {"phase", "cold"},
                {"code", cold ? "INVALID_RESULT" : cold.error().stable_code()},
                {"message", cold ? "decompiler result was empty or unmapped" : cold.error().message}});
            continue;
        }
        cold_values.push_back(cold_ns);
        ++cold_successes;
        begin = steady_clock_t::now();
        auto warm = service->decompile(address, {true, true});
        const auto warm_ns = nanoseconds_since(begin);
        interaction_metrics.record_decompile_latency(true, warm_ns);
        if (!warm || !valid_decompile_sample(warm.value(), workspace)) {
            errors.push_back(json{{"function", index}, {"phase", "warm"},
                {"code", warm ? "INVALID_RESULT" : warm.error().stable_code()},
                {"message", warm ? "decompiler result was empty or unmapped" : warm.error().message}});
            continue;
        }
        warm_values.push_back(warm_ns);
        ++warm_successes;
    }
    std::uint64_t cold_total = 0;
    std::uint64_t warm_total = 0;
    for (const auto value : cold_values) cold_total += value;
    for (const auto value : warm_values) warm_total += value;
    if (cold_successes == 0 || warm_successes == 0)
        throw fixture_error_t("decompiler benchmark produced no valid cold/warm sample pair");
    return json{{"function_population", snapshot ? snapshot->functions.size() : 0},
        {"requested_sample_cap", 32}, {"minimum_sample_when_available", 20},
        {"smaller_population", snapshot ? snapshot->functions.size() < 20 : true},
        {"selected_functions", std::move(selected_functions)},
        {"attempts", attempts}, {"cold_successes", cold_successes},
        {"cold_failures", attempts - cold_successes}, {"warm_successes", warm_successes},
        {"warm_failures", cold_successes - warm_successes}, {"cold_ns", cold_values},
        {"warm_ns", warm_values}, {"cold_total_ns", cold_total}, {"warm_total_ns", warm_total},
        {"cold_average_ns", cold_values.empty() ? json(nullptr) :
            json(cold_total / cold_values.size())},
        {"warm_average_ns", warm_values.empty() ? json(nullptr) :
            json(warm_total / warm_values.size())},
        {"cold_max_ns", cold_values.empty() ? json(nullptr) :
            json(*std::max_element(cold_values.begin(), cold_values.end()))},
        {"warm_max_ns", warm_values.empty() ? json(nullptr) :
            json(*std::max_element(warm_values.begin(), warm_values.end()))},
        {"cold_p50_ns", measured_percentile(cold_values, 0.50)},
        {"cold_p95_ns", measured_percentile(cold_values, 0.95)},
        {"warm_p50_ns", measured_percentile(warm_values, 0.50)},
        {"warm_p95_ns", measured_percentile(warm_values, 0.95)},
        {"errors", std::move(errors)}};
}

json mcp_measurement(const std::shared_ptr<analysis_workspace_t>& workspace,
                     analysis_metrics_t& interaction_metrics)
{
    mcp_standalone::tool_registry_t registry;
    mcp_standalone::register_c03_compatibility_tools(registry);
    std::vector<std::uint64_t> latencies;
    json failures = json::array();
    std::size_t last_returned = 0;
    std::size_t attempts = 0;
    for (std::size_t sample = 0; sample < 16; ++sample) {
        ++attempts;
        const auto begin = steady_clock_t::now();
        const auto response = registry.call_registered_tool("list_funcs",
            json{{"bin_name", workspace->identity().bin_name()},
                {"queries", json{{"offset", sample * 16}, {"count", 200}}}});
        const auto latency = nanoseconds_since(begin);
        interaction_metrics.record_mcp_latency(latency);
        const bool valid = response.success && response.data.is_object() &&
            response.data.contains("result") && response.data["result"].is_array() &&
            response.data["result"].size() == 1 &&
            response.data["result"][0].contains("data") &&
            response.data["result"][0]["data"].is_array() &&
            response.meta.is_object() && response.meta.contains("aida") &&
            response.meta["aida"].is_object() &&
            response.meta["aida"].value("contract_name", std::string()) ==
                "list_funcs";
        aida::analysis::c03_test::assertion_telemetry::record_assertion(
            valid, "benchmark MCP registry response satisfies the exact generated contract",
            __FILE__, __LINE__);
        if (!valid)
            failures.push_back(json{{"sample", sample}, {"error_code", response.error_code},
                {"message", response.text}});
        else {
            latencies.push_back(latency);
            last_returned = response.data["result"][0]["data"].size();
        }
    }
    std::uint64_t total_latency = 0;
    for (const auto latency : latencies) total_latency += latency;
    if (latencies.empty())
        throw fixture_error_t("MCP benchmark handler produced no identity-bound responses");
    return json{{"handler_calls_wired", true},
        {"handler", "mcp_standalone::tool_registry_t::call_registered_tool"},
        {"tool", "list_funcs"}, {"latency_ns", latencies},
        {"attempts", attempts}, {"successes", latencies.size()},
        {"failures_count", attempts - latencies.size()},
        {"total_success_latency_ns", total_latency},
        {"average_success_latency_ns", latencies.empty() ? json(nullptr) :
            json(total_latency / latencies.size())},
        {"max_success_latency_ns", latencies.empty() ? json(nullptr) :
            json(*std::max_element(latencies.begin(), latencies.end()))},
        {"p50_ns", measured_percentile(latencies, 0.50)},
        {"p95_ns", measured_percentile(latencies, 0.95)},
        {"failures", std::move(failures)}, {"last_returned", last_returned}};
}

json cancellation_measurement(const std::filesystem::path& path, bool pin_profile = false)
{
    const auto runtime_before = aida::infra::taskflow_runtime::active_snapshot();
    const auto memory_before = process_memory_snapshot();
    auto workspace = open_benchmark_workspace(path, 7, nullptr, pin_profile);
    try {
        baseline_analysis_settings_t settings;
        settings.decode_worker_lanes = 1;
        auto started = baseline_analysis_service_t::start(workspace, settings);
        if (!started)
            throw fixture_error_t(started.error().stable_code() + ":" + started.error().message);
        const auto observation_deadline = steady_clock_t::now() + std::chrono::milliseconds(250);
        aida::infra::taskflow_runtime::wait_result_t state;
        while (steady_clock_t::now() < observation_deadline) {
            state = aida::infra::taskflow_runtime::wait_for(started.value(), 0);
            if (!state.timed_out || workspace->progress().completed_bytes != 0)
                break;
            std::this_thread::yield();
        }
        const bool completed_before_request = state.completed || state.failed || state.cancelled;
        const auto requested = steady_clock_t::now();
        const bool cancellation_signalled = completed_before_request
            ? false : baseline_analysis_service_t::cancel(started.value());
        const auto completed = aida::infra::taskflow_runtime::wait_for(started.value(), 60000);
        const auto latency = nanoseconds_since(requested);
        const auto progress = workspace->progress();
        json result{{"completed_before_request", completed_before_request},
            {"measured", !completed_before_request},
            {"unavailable_reason", completed_before_request
                ? json("analysis_completed_before_cancellation") : json(nullptr)},
            {"cancellation_signalled", cancellation_signalled},
            {"request_to_completion_ns", completed_before_request ? json(nullptr) : json(latency)},
            {"runtime_before", runtime_snapshot_json(runtime_before)},
            {"runtime_after", runtime_snapshot_json(
                aida::infra::taskflow_runtime::active_snapshot())},
            {"memory_before", memory_before}, {"memory_after", process_memory_snapshot()},
            {"job", json{{"completed", completed.completed}, {"cancelled", completed.cancelled},
                {"failed", completed.failed}, {"timed_out", completed.timed_out}}},
            {"final_progress", json{{"readiness", static_cast<unsigned>(progress.readiness)},
                {"completed_bytes", progress.completed_bytes}, {"total_bytes", progress.total_bytes},
                {"cancellation_requested", progress.cancellation_requested}}}};
        if (progress.error)
            result["error"] = json{{"code", progress.error->stable_code()},
                {"message", progress.error->message}, {"phase", progress.error->phase}};
        close_workspace(workspace, true);
        return result;
    } catch (...) {
        try { close_workspace(workspace, true); } catch (...) {}
        throw;
    }
}

json concurrent_measurement(const std::filesystem::path& path, bool pin_profile = false)
{
    using job_handle_t = aida::infra::taskflow_runtime::job_handle_t;
    std::vector<std::shared_ptr<analysis_workspace_t>> workspaces;
    std::vector<job_handle_t> jobs;
    const auto runtime_before = aida::infra::taskflow_runtime::active_snapshot();
    const auto memory_before = process_memory_snapshot();
    const auto begin = steady_clock_t::now();
    try {
        for (std::uint8_t profile = 11; profile < 15; ++profile) {
            auto workspace = open_benchmark_workspace(path, profile, nullptr, pin_profile);
            baseline_analysis_settings_t settings;
            settings.decode_worker_lanes = static_cast<std::uint32_t>((profile % 4) + 1);
            auto started = baseline_analysis_service_t::start(workspace, settings);
            if (!started)
                throw fixture_error_t(started.error().stable_code() + ":" + started.error().message);
            workspaces.push_back(std::move(workspace));
            jobs.push_back(started.value());
        }
        std::vector<bool> finished(jobs.size(), false);
        std::vector<std::uint64_t> completion_ns(jobs.size(), 0);
        std::size_t remaining = jobs.size();
        std::uint32_t peak_active = 0;
        std::uint64_t peak_pending = 0;
        const auto safety_deadline = steady_clock_t::now() + std::chrono::hours(1);
        while (remaining != 0) {
            const auto runtime = aida::infra::taskflow_runtime::active_snapshot();
            peak_active = (std::max)(peak_active, runtime.total_active);
            peak_pending = (std::max)(peak_pending, runtime.work_queue_pending +
                runtime.service_queue_pending + runtime.critical_queue_pending);
            for (std::size_t index = 0; index < jobs.size(); ++index) {
                if (finished[index])
                    continue;
                const auto state = aida::infra::taskflow_runtime::wait_for(jobs[index], 0);
                if (state.timed_out)
                    continue;
                if (!state.completed)
                    throw fixture_error_t(state.cancelled ? "CANCELLED:concurrent workspace job cancelled" :
                        "INTERNAL_ERROR:concurrent workspace job failed");
                finished[index] = true;
                completion_ns[index] = nanoseconds_since(begin);
                --remaining;
            }
            if (steady_clock_t::now() >= safety_deadline)
                throw fixture_error_t("DEADLINE_EXCEEDED:concurrent benchmark safety deadline exceeded");
            if (remaining != 0)
                std::this_thread::yield();
        }
        const auto elapsed = nanoseconds_since(begin);
        json per_workspace = json::array();
        std::uint64_t total_file_bytes = 0;
        std::uint64_t total_executable_bytes = 0;
        for (std::size_t index = 0; index < workspaces.size(); ++index) {
            total_file_bytes += workspaces[index]->provider().size();
            const auto image = workspaces[index]->normalized_image();
            if (!image)
                throw fixture_error_t("concurrent benchmark workspace lost normalized image metadata");
            total_executable_bytes += executable_bytes(image);
            per_workspace.push_back(json{{"binary_id", workspaces[index]->identity().binary_id().to_hex()},
                {"completion_ns", completion_ns[index]},
                {"format", format_name(image->format)},
                {"architecture", architecture_name(image->architecture)},
                {"architecture_mode", architecture_mode_name(image->architecture_mode)},
                {"counts", snapshot_counts(*workspaces[index]->snapshot(),
                    workspaces[index]->search_index())}});
        }
        const auto minimum_completion = *std::min_element(completion_ns.begin(), completion_ns.end());
        const auto maximum_completion = *std::max_element(completion_ns.begin(), completion_ns.end());
        const auto runtime_after = aida::infra::taskflow_runtime::active_snapshot();
        json result{{"workspace_count", workspaces.size()}, {"wall_ns", elapsed},
            {"total_file_bytes", total_file_bytes}, {"total_executable_bytes", total_executable_bytes},
            {"file_bytes_per_second", elapsed == 0 ? json(nullptr) : json(
                static_cast<double>(total_file_bytes) * 1000000000.0 / static_cast<double>(elapsed))},
            {"completion_spread_ns", maximum_completion - minimum_completion},
            {"peak_active_jobs", peak_active}, {"peak_pending_jobs", peak_pending},
            {"runtime_before", runtime_snapshot_json(runtime_before)},
            {"runtime_after", runtime_snapshot_json(runtime_after)},
            {"memory_before", memory_before}, {"memory_after", process_memory_snapshot()},
            {"per_workspace", std::move(per_workspace)}};
        for (auto& workspace : workspaces)
            close_workspace(workspace, true);
        return result;
    } catch (...) {
        for (const auto& job : jobs)
            baseline_analysis_service_t::cancel(job);
        for (auto& workspace : workspaces) {
            try { close_workspace(workspace, true); } catch (...) {}
        }
        throw;
    }
}

int validate_receipt_command(const std::filesystem::path& root, const std::filesystem::path& relative)
{
    std::error_code error;
    const auto canonical_root = std::filesystem::weakly_canonical(root, error);
    if (error || !std::filesystem::is_directory(canonical_root))
        throw fixture_error_t("benchmark receipt evidence root is invalid");
    if (relative.is_absolute() || relative.has_root_name())
        throw fixture_error_t("benchmark receipt path must be evidence-root relative");
    for (const auto& part : relative) {
        if (part == "..")
            throw fixture_error_t("benchmark receipt path traversal is forbidden");
    }
    const auto receipt_path = std::filesystem::weakly_canonical(canonical_root / relative, error);
    const auto within = std::filesystem::relative(receipt_path, canonical_root, error);
    if (error || within.empty() || within.is_absolute() ||
        (within.begin() != within.end() && *within.begin() == ".."))
        throw fixture_error_t("benchmark receipt path escapes the evidence root");
    std::ifstream stream(receipt_path, std::ios::binary);
    if (!stream)
        throw fixture_error_t("benchmark receipt is unavailable");
    json receipt;
    try {
        stream >> receipt;
    } catch (const json::exception& exception) {
        throw fixture_error_t(std::string("benchmark receipt JSON is invalid: ") + exception.what());
    }
    const auto validation = aida::analysis::c03::validate_benchmark_sla_receipt_files(
        receipt, aida::analysis::c03::approved_external_sla_slot(), canonical_root);
    if (!validation.valid) {
        std::string failure = "benchmark receipt failed the C03 SLA contract";
        for (const auto& violation : validation.violations)
            failure += "\n" + violation.path + ":" + violation.code + ":" + violation.message;
        throw fixture_error_t(std::move(failure));
    }
    std::cout << receipt.dump(2) << '\n';
    return 0;
}

struct measurement_options_t {
    std::string benchmark_mode = "deterministic_component";
    std::string claim_status = "development_only";
    bool release_qualification = false;
    bool pin_profile = false;
    bool skip_concurrent = false;
    std::uint32_t worker_lanes = 0;
    std::function<void(const std::shared_ptr<analysis_workspace_t>&)> publication_callback;
};

json run_measurement(const std::filesystem::path& path, const measurement_options_t& options)
{
    std::shared_ptr<aida::analysis::analysis_workspace_t> workspace;
    try {
        if (!std::filesystem::is_regular_file(path))
            throw aida::analysis::test_fixture::fixture_error_t("benchmark fixture does not exist");
        const auto fixture_size = std::filesystem::file_size(path);
        const auto fixture_zero_bytes = zero_bytes(path, fixture_size);
        const auto host = host_identity(path);
        const auto runtime_before = aida::infra::taskflow_runtime::active_snapshot();
        const auto cold_memory_before = process_memory_snapshot();
        json acquisition_metrics;
        const auto cold_begin = steady_clock_t::now();
        workspace = open_benchmark_workspace(path, 1, &acquisition_metrics, options.pin_profile);
        const auto image = workspace->normalized_image();
        if (!image)
            throw aida::analysis::test_fixture::fixture_error_t("benchmark fixture image metadata is unavailable");
        const auto code_bytes = executable_bytes(image);
        if (code_bytes == 0)
            throw aida::analysis::test_fixture::fixture_error_t(
                "benchmark fixture has no normalized executable bytes");
        if (options.release_qualification) {
            const auto& thresholds = aida::analysis::c03::benchmark_sla_thresholds();
            const auto minimum = thresholds.at("release_min_artifact_bytes").get<std::uint64_t>();
            const auto maximum = thresholds.at("release_max_artifact_bytes").get<std::uint64_t>();
            const auto code_density = static_cast<double>(code_bytes) / static_cast<double>(fixture_size);
            const auto zero_ratio = static_cast<double>(fixture_zero_bytes) / static_cast<double>(fixture_size);
            if (fixture_size < minimum || fixture_size > maximum || code_bytes < 64ULL * 1024ULL * 1024ULL ||
                code_density < 0.10 || zero_ratio > 0.80)
                throw aida::analysis::test_fixture::fixture_error_t(
                    "release SLA fixture fails size, executable-volume, density, or zero-padding qualification");
        }
        const auto analysis_begin = steady_clock_t::now();
        analyze_workspace(workspace, options.worker_lanes);
        const auto analysis_ns = nanoseconds_since(analysis_begin);
        const auto cold_wall_ns = nanoseconds_since(cold_begin);
        if (options.publication_callback)
            options.publication_callback(workspace);
        const auto published_metrics = benchmark::harvest_workspace_baseline_metrics(workspace);
        const auto runtime_after = aida::infra::taskflow_runtime::active_snapshot();
        const workspace_identity_t cold_identity = workspace->identity();
        const auto cold_analysis_revision = workspace->analysis_revision();
        const auto cold_overlay_revision = workspace->overlay_revision();
        const auto cold_counts = snapshot_counts(*workspace->snapshot(), workspace->search_index());
        const auto cold_database = workspace->database()->snapshot();
        const auto setup_ns = acquisition_metrics.value("workspace_setup_ns", 0ULL);
        json report;
        report["fixture"] = json{{"path", path.u8string()},
            {"normalized_path", workspace->identity().normalized_source_path()},
            {"member_path", workspace->identity().normalized_member_path()
                ? json(*workspace->identity().normalized_member_path()) : json(nullptr)},
            {"size", fixture_size}, {"sha256", workspace->identity().content_hash().to_hex()},
            {"format", format_name(image->format)}, {"format_id", static_cast<unsigned>(image->format)},
            {"format_name", image->format_name},
            {"architecture", architecture_name(image->architecture)},
            {"architecture_id", static_cast<unsigned>(image->architecture)},
            {"architecture_mode", architecture_mode_name(image->architecture_mode)},
            {"architecture_mode_id", static_cast<unsigned>(image->architecture_mode)},
            {"abi_id", static_cast<unsigned>(image->abi)},
            {"endian", image->endian == endian_t::little ? "little" : "big"},
            {"address_width_bits", image->address_width_bits},
            {"image_base", std::to_string(image->image_base)},
            {"image_size", image->image_size}, {"header_size", image->header_size},
            {"executable_code_bytes", code_bytes},
            {"zero_bytes", fixture_zero_bytes},
            {"code_density", static_cast<double>(code_bytes) / static_cast<double>(fixture_size)},
            {"zero_ratio", static_cast<double>(fixture_zero_bytes) / static_cast<double>(fixture_size)},
            {"entry_points", image->entry_points.size()}, {"segments", image->segments.size()},
            {"sections", image->sections.size()}, {"image_symbols", image->symbols.size()},
            {"imports", image->imports.size()}, {"exports", image->exports.size()},
            {"relocations", image->relocations.size()}};
        report["host"] = host;
        report["cold"] = json{{"wall_ns", cold_wall_ns},
            {"cache_state", "cold_graph"},
            {"file_bytes", workspace->provider().size()},
            {"executable_code_bytes", code_bytes},
            {"phases", json{{"workspace_acquisition", acquisition_metrics},
                {"baseline_analysis_ns", analysis_ns},
                {"accounted_ns", setup_ns + analysis_ns},
                {"timer_overhead_ns", cold_wall_ns >= setup_ns + analysis_ns
                    ? cold_wall_ns - setup_ns - analysis_ns : 0}}},
            {"runtime_before", runtime_snapshot_json(runtime_before)},
            {"runtime_after", runtime_snapshot_json(runtime_after)},
            {"memory_before", cold_memory_before}, {"memory_after", process_memory_snapshot()},
            {"counts", cold_counts},
            {"database", database_measurement(cold_database)}};
        close_workspace(workspace);
        workspace.reset();
        json warm_reopen;
        workspace = reopen_persisted_benchmark_workspace(path, 1, cold_identity,
            cold_analysis_revision, cold_overlay_revision, cold_counts, warm_reopen,
            options.pin_profile);
        report["warm_reopen"] = std::move(warm_reopen);
        analysis_metrics_t interaction_metrics(workspace->generation());
        interaction_metrics.sample_process_memory();
        const auto background_metrics = workspace->background_metrics();
        analysis_metrics_snapshot_t background_before;
        if (background_metrics)
            background_before = background_metrics->snapshot();
        report["mcp"] = mcp_measurement(workspace, interaction_metrics);
        report["decompiler"] = decompiler_measurements(workspace, interaction_metrics);
        analysis_metrics_snapshot_t background_after;
        if (background_metrics)
            background_after = background_metrics->snapshot();
        report["background_decompile_batch"] = background_batch_block(
            background_before, background_after, background_metrics != nullptr);
        interaction_metrics.sample_process_memory();
        interaction_metrics.mark_finished();
        report["interaction_instrumentation"] =
            instrumentation_summary(interaction_metrics.snapshot());
        report["interaction_database_after"] =
            database_measurement(workspace->database()->snapshot());
        close_workspace(workspace, true);
        workspace.reset();
        if (published_metrics) {
            const auto& metrics_snapshot = *published_metrics;
            const auto counter = [&](analysis_metric_t metric) {
                return metrics_snapshot.value(metric);
            };
            if (counter(analysis_metric_t::file_bytes) != report["cold"].value("file_bytes", 0ULL) ||
                counter(analysis_metric_t::executable_bytes) != code_bytes ||
                counter(analysis_metric_t::mapped_bytes) == 0 ||
                counter(analysis_metric_t::read_bytes) == 0 ||
                counter(analysis_metric_t::decoded_bytes) == 0 ||
                counter(analysis_metric_t::indexed_bytes) == 0 ||
                counter(analysis_metric_t::instructions) !=
                    cold_counts.value("instructions", 0ULL) ||
                counter(analysis_metric_t::blocks) != cold_counts.value("blocks", 0ULL) ||
                counter(analysis_metric_t::functions) != cold_counts.value("functions", 0ULL) ||
                counter(analysis_metric_t::xrefs) != cold_counts.value("xrefs", 0ULL) ||
                counter(analysis_metric_t::strings) != cold_counts.value("strings", 0ULL) ||
                counter(analysis_metric_t::types) != cold_counts.value("types", 0ULL) ||
                counter(analysis_metric_t::database_bytes) == 0 ||
                counter(analysis_metric_t::peak_private_bytes) == 0)
                throw aida::analysis::test_fixture::fixture_error_t(
                    "published baseline metrics did not bind the cold published normalized baseline");
            report["instrumented_engine"] = json{
                {"wall_ns", metrics_snapshot.wall_ns},
                {"cache_state", "cold_graph_published_metrics"},
                {"source", "workspace_last_baseline_metrics"},
                {"metrics", json::parse(metrics_snapshot.to_json())},
                {"summary", instrumentation_summary(metrics_snapshot)},
                {"memory_before", cold_memory_before},
                {"memory_after", report["cold"]["memory_after"]},
                {"database", report["cold"]["database"]},
                {"counts", cold_counts}};
        } else {
            workspace = open_benchmark_workspace(path, 2, nullptr, options.pin_profile);
            const auto instrumented_memory_before = process_memory_snapshot();
            const auto instrumented_begin = steady_clock_t::now();
            auto instrumented = analyze_workspace_instrumented(workspace, options.worker_lanes);
            const auto instrumented_snapshot = instrumented->snapshot();
            const auto published_snapshot = workspace->snapshot();
            const auto published_search = workspace->search_index();
            if (!published_snapshot || !published_search ||
                instrumented_snapshot.value(analysis_metric_t::file_bytes) !=
                    workspace->provider().size() ||
                instrumented_snapshot.value(analysis_metric_t::executable_bytes) != code_bytes ||
                instrumented_snapshot.value(analysis_metric_t::mapped_bytes) == 0 ||
                instrumented_snapshot.value(analysis_metric_t::read_bytes) == 0 ||
                instrumented_snapshot.value(analysis_metric_t::decoded_bytes) == 0 ||
                instrumented_snapshot.value(analysis_metric_t::indexed_bytes) == 0 ||
                instrumented_snapshot.value(analysis_metric_t::instructions) !=
                    published_snapshot->instructions.size() ||
                instrumented_snapshot.value(analysis_metric_t::blocks) !=
                    published_snapshot->blocks.size() ||
                instrumented_snapshot.value(analysis_metric_t::functions) !=
                    published_snapshot->functions.size() ||
                instrumented_snapshot.value(analysis_metric_t::xrefs) !=
                    published_snapshot->xrefs.size() ||
                instrumented_snapshot.value(analysis_metric_t::strings) !=
                    published_snapshot->strings.size() ||
                instrumented_snapshot.value(analysis_metric_t::types) !=
                    published_search->types().size() ||
                instrumented_snapshot.value(analysis_metric_t::database_bytes) == 0 ||
                instrumented_snapshot.value(analysis_metric_t::peak_private_bytes) == 0)
                throw aida::analysis::test_fixture::fixture_error_t(
                    "instrumented engine counters did not bind the published normalized baseline");
            report["instrumented_engine"] = json{{"wall_ns", nanoseconds_since(instrumented_begin)},
                {"cache_state", "cold_instrumented_phases"},
                {"source", "direct_instrumented_analyzer"},
                {"metrics", json::parse(instrumented_snapshot.to_json())},
                {"summary", instrumentation_summary(instrumented_snapshot)},
                {"memory_before", instrumented_memory_before},
                {"memory_after", process_memory_snapshot()},
                {"database", database_measurement(workspace->database()->snapshot())},
                {"counts", snapshot_counts(*published_snapshot, published_search)}};
            close_workspace(workspace, true);
            workspace.reset();
        }
        if (options.skip_concurrent) {
            report["concurrent_fairness"] = json{{"skipped", true},
                {"reason", "pinned_measurement_mode"}};
        } else {
            report["concurrent_fairness"] = concurrent_measurement(path, options.pin_profile);
        }
        report["cancellation"] = cancellation_measurement(path, options.pin_profile);
        report["fixture"]["file_version"] = file_version_identity(path);
        report["benchmark_contract"] = json{{"mode", options.benchmark_mode},
            {"claim_status", options.claim_status},
            {"thresholds", aida::analysis::c03::benchmark_sla_thresholds()},
            {"receipt_validation_required", true}, {"target_execution_forbidden", true}};
        report["runtime_claim"] = "measurement_only";
        return report;
    } catch (...) {
        if (workspace) {
            try { close_workspace(workspace, true); } catch (...) {}
        }
        throw;
    }
}

std::uint64_t metrics_counter(const json& metrics, const char* name)
{
    if (!metrics.is_object())
        return 0;
    const auto it = metrics.find("counters");
    if (it == metrics.end() || !it->is_object())
        return 0;
    const auto counter = it->find(name);
    if (counter == it->end() || !counter->is_number())
        return 0;
    return counter->get<std::uint64_t>();
}

std::uint64_t metrics_phase_wall_ns(const json& metrics, const char* name)
{
    if (!metrics.is_object())
        return 0;
    const auto it = metrics.find("phases");
    if (it == metrics.end() || !it->is_array())
        return 0;
    for (const auto& phase : *it) {
        if (phase.value("name", std::string()) == name)
            return phase.value("wall_ns", 0ULL);
    }
    return 0;
}

bool metrics_phase_present(const json& metrics, const char* name)
{
    if (!metrics.is_object())
        return false;
    const auto it = metrics.find("phases");
    if (it == metrics.end() || !it->is_array())
        return false;
    for (const auto& phase : *it) {
        if (phase.value("name", std::string()) == name)
            return true;
    }
    return false;
}

json nullable_rate(std::uint64_t units, std::uint64_t wall_ns)
{
    if (wall_ns == 0)
        return nullptr;
    return static_cast<double>(units) * 1000000000.0 / static_cast<double>(wall_ns);
}

json throughput_block(const json& report, const json& metrics)
{
    const std::uint64_t cold_wall_ns = report["cold"].value("wall_ns", 0ULL);
    const std::uint64_t file_bytes = report["cold"].value("file_bytes", 0ULL);
    const std::uint64_t decode_wall_ns = metrics_phase_wall_ns(metrics, "decode") +
        metrics_phase_wall_ns(metrics, "decode_merge");
    const std::uint64_t decoded_bytes = metrics_counter(metrics, "decoded_bytes");
    const std::uint64_t instructions = metrics_counter(metrics, "instructions");
    const std::uint64_t functions = metrics_counter(metrics, "functions");
    const std::uint64_t analysis_ns = report["cold"]["phases"].value("baseline_analysis_ns", 0ULL);
    const std::uint64_t index_wall_ns = metrics_phase_wall_ns(metrics, "search_index");
    const std::uint64_t persist_wall_ns = metrics_phase_wall_ns(metrics, "persistence");
    return json{
        {"file_bytes_per_s", nullable_rate(file_bytes, cold_wall_ns)},
        {"decode_bytes_per_s", nullable_rate(decoded_bytes, decode_wall_ns)},
        {"instructions_per_s", nullable_rate(instructions, decode_wall_ns)},
        {"functions_per_s", nullable_rate(functions, analysis_ns)},
        {"index_bytes_per_s", nullable_rate(
            metrics_counter(metrics, "index_text_bytes"), index_wall_ns)},
        {"persist_bytes_per_s", nullable_rate(
            metrics_counter(metrics, "database_bytes_written"), persist_wall_ns)},
        {"decompile_all_funcs_per_s", nullptr}};
}

json memory_block(const json& report, const json& metrics)
{
    return json{
        {"peak_private_bytes", metrics_counter(metrics, "peak_private_bytes")},
        {"peak_committed_bytes", metrics_counter(metrics, "peak_committed_bytes")},
        {"resident_bytes_peak", metrics_counter(metrics, "resident_bytes_peak")},
        {"mapped_workspace_peak", metrics_counter(metrics, "mapped_window_bytes_peak")},
        {"mapped_global_peak", metrics_counter(metrics, "mapped_window_bytes_global_peak")},
        {"spill_bytes_peak", metrics_counter(metrics, "spill_bytes_peak")},
        {"spill_bytes_written", metrics_counter(metrics, "spill_bytes_written")},
        {"spill_bytes_read", metrics_counter(metrics, "spill_bytes_read")},
        {"budget_rejections", metrics_counter(metrics, "budget_rejections")},
        {"memory_pressure_events", metrics_counter(metrics, "memory_pressure_events")},
        {"process_before", report["cold"]["memory_before"]},
        {"process_after", report["cold"]["memory_after"]}};
}

struct sla_measurement_context_t {
    const json* report = nullptr;
    const json* metrics = nullptr;
    const json* throughput = nullptr;
    double wall_scale = 1.0;
    const bool* determinism_match = nullptr;
    double scaling_wall16_over_wall1 = -1.0;
    double scaling_efficiency_16 = -1.0;
    bool scaling_gate_applicable = false;
    const json* decompile_funcs_per_s = nullptr;
};

json sla_verdict(const char* key, const json& target, const json& actual,
                 const char* verdict)
{
    return json{{"key", key}, {"target", target}, {"actual", actual},
        {"verdict", verdict}};
}

json evaluate_program_sla(const sla_measurement_context_t& context)
{
    const auto& thresholds = benchmark::program_sla_thresholds();
    const auto& report = *context.report;
    const auto& metrics = *context.metrics;
    const auto& throughput = *context.throughput;
    json verdicts = json::array();
    const auto push_max_ms = [&](const char* key, double target, const json& actual_ms) {
        if (actual_ms.is_null()) {
            verdicts.push_back(sla_verdict(key, target, nullptr, "NOT_MEASURED"));
            return;
        }
        verdicts.push_back(sla_verdict(key, target, actual_ms,
            actual_ms.get<double>() <= target ? "PASS" : "FAIL"));
    };
    const auto push_min = [&](const char* key, double target, const json& actual) {
        if (actual.is_null()) {
            verdicts.push_back(sla_verdict(key, target, nullptr, "NOT_MEASURED"));
            return;
        }
        verdicts.push_back(sla_verdict(key, target, actual,
            actual.get<double>() >= target ? "PASS" : "FAIL"));
    };
    const auto push_max_bytes = [&](const char* key, std::uint64_t target,
                                    std::optional<std::uint64_t> actual) {
        if (!actual) {
            verdicts.push_back(sla_verdict(key, target, nullptr, "NOT_MEASURED"));
            return;
        }
        verdicts.push_back(sla_verdict(key, target, *actual,
            *actual <= target ? "PASS" : "FAIL"));
    };

    const double wall_ms = static_cast<double>(report["cold"].value("wall_ns", 0ULL)) / 1000000.0;
    push_max_ms("total_wall_ms_max_300mb",
        thresholds["total_wall_ms_max_300mb"].get<double>() * context.wall_scale, wall_ms);
    {
        const double stretch = thresholds["total_wall_ms_stretch_300mb"].get<double>() *
            context.wall_scale;
        verdicts.push_back(sla_verdict("total_wall_ms_stretch_300mb", stretch, wall_ms,
            wall_ms <= stretch ? "PASS" : "WARN"));
    }
    push_min("decode_throughput_bytes_per_s_min",
        thresholds["decode_throughput_bytes_per_s_min"].get<double>(),
        throughput["decode_bytes_per_s"]);
    push_min("file_throughput_bytes_per_s_min",
        thresholds["file_throughput_bytes_per_s_min"].get<double>(),
        throughput["file_bytes_per_s"]);
    push_min("instructions_per_s_min",
        thresholds["instructions_per_s_min"].get<double>(),
        throughput["instructions_per_s"]);
    push_max_ms("publish_ready_ms_max", thresholds["publish_ready_ms_max"].get<double>(),
        metrics_phase_present(metrics, "publish_ready")
            ? json(static_cast<double>(metrics_phase_wall_ns(metrics, "publish_ready")) / 1000000.0)
            : json(nullptr));
    push_max_ms("indexed_query_p95_ms_max", thresholds["indexed_query_p95_ms_max"].get<double>(),
        report["mcp"]["p95_ns"].is_number()
            ? json(static_cast<double>(report["mcp"]["p95_ns"].get<std::uint64_t>()) / 1000000.0)
            : json(nullptr));
    push_max_ms("metadata_ready_ms_max", thresholds["metadata_ready_ms_max"].get<double>(),
        metrics_phase_present(metrics, "metadata_symbols_types")
            ? json(static_cast<double>(
                metrics_phase_wall_ns(metrics, "metadata_symbols_types")) / 1000000.0)
            : json(nullptr));
    push_max_ms("warm_reopen_ms_max", thresholds["warm_reopen_ms_max"].get<double>(),
        report["warm_reopen"]["wall_ns"].is_number()
            ? json(static_cast<double>(
                report["warm_reopen"]["wall_ns"].get<std::uint64_t>()) / 1000000.0)
            : json(nullptr));
    push_max_ms("cancellation_p95_ms_max", thresholds["cancellation_p95_ms_max"].get<double>(),
        report["cancellation"]["request_to_completion_ns"].is_number()
            ? json(static_cast<double>(
                report["cancellation"]["request_to_completion_ns"].get<std::uint64_t>()) / 1000000.0)
            : json(nullptr));
    push_max_bytes("incremental_private_bytes_max",
        thresholds["incremental_private_bytes_max"].get<std::uint64_t>(),
        metrics_counter(metrics, "peak_private_bytes"));
    {
        const std::uint64_t mapped = metrics_counter(metrics, "mapped_window_bytes_peak");
        push_max_bytes("workspace_mapped_bytes_max",
            thresholds["workspace_mapped_bytes_max"].get<std::uint64_t>(),
            mapped == 0 ? std::optional<std::uint64_t>{} : std::optional<std::uint64_t>(mapped));
    }
    {
        const std::uint64_t mapped = metrics_counter(metrics, "mapped_window_bytes_global_peak");
        push_max_bytes("global_mapped_bytes_max",
            thresholds["global_mapped_bytes_max"].get<std::uint64_t>(),
            mapped == 0 ? std::optional<std::uint64_t>{} : std::optional<std::uint64_t>(mapped));
    }
    if (context.decompile_funcs_per_s && context.decompile_funcs_per_s->is_number()) {
        const double funcs_per_s = context.decompile_funcs_per_s->get<double>();
        verdicts.push_back(sla_verdict("decompile_all_funcs_per_s_min",
            thresholds["decompile_all_funcs_per_s_min"], funcs_per_s,
            funcs_per_s >= thresholds["decompile_all_funcs_per_s_min"].get<double>()
                ? "PASS" : "FAIL"));
        verdicts.push_back(sla_verdict("decompile_all_funcs_per_s_stretch",
            thresholds["decompile_all_funcs_per_s_stretch"], funcs_per_s,
            funcs_per_s >= thresholds["decompile_all_funcs_per_s_stretch"].get<double>()
                ? "PASS" : "WARN"));
    } else {
        verdicts.push_back(sla_verdict("decompile_all_funcs_per_s_min",
            thresholds["decompile_all_funcs_per_s_min"], nullptr, "NOT_MEASURED"));
        verdicts.push_back(sla_verdict("decompile_all_funcs_per_s_stretch",
            thresholds["decompile_all_funcs_per_s_stretch"], nullptr, "NOT_MEASURED"));
    }
    verdicts.push_back(sla_verdict("decompile_all_funcs_wall_per_s_min",
        thresholds["decompile_all_funcs_wall_per_s_min"], nullptr, "NOT_MEASURED"));
    verdicts.push_back(sla_verdict("decompile_all_funcs_wall_per_s_stretch",
        thresholds["decompile_all_funcs_wall_per_s_stretch"], nullptr, "NOT_MEASURED"));
    if (context.scaling_gate_applicable) {
        verdicts.push_back(sla_verdict("scaling_wall16_over_wall1_max",
            thresholds["scaling_wall16_over_wall1_max"], context.scaling_wall16_over_wall1,
            context.scaling_wall16_over_wall1 <=
                thresholds["scaling_wall16_over_wall1_max"].get<double>() ? "PASS" : "FAIL"));
        verdicts.push_back(sla_verdict("scaling_efficiency_16_min",
            thresholds["scaling_efficiency_16_min"], context.scaling_efficiency_16,
            context.scaling_efficiency_16 >=
                thresholds["scaling_efficiency_16_min"].get<double>() ? "PASS" : "WARN"));
    } else {
        verdicts.push_back(sla_verdict("scaling_wall16_over_wall1_max",
            thresholds["scaling_wall16_over_wall1_max"], nullptr, "NOT_MEASURED"));
        verdicts.push_back(sla_verdict("scaling_efficiency_16_min",
            thresholds["scaling_efficiency_16_min"], nullptr, "NOT_MEASURED"));
    }
    if (context.determinism_match) {
        verdicts.push_back(sla_verdict("determinism_hash_match",
            thresholds["determinism_hash_match"], *context.determinism_match,
            *context.determinism_match ? "PASS" : "FAIL"));
    } else {
        verdicts.push_back(sla_verdict("determinism_hash_match",
            thresholds["determinism_hash_match"], nullptr, "NOT_MEASURED"));
    }

    bool any_fail = false;
    bool all_pass_or_warn = true;
    for (const auto& verdict : verdicts) {
        const auto value = verdict.value("verdict", std::string());
        if (value == "FAIL")
            any_fail = true;
        if (value != "PASS" && value != "WARN")
            all_pass_or_warn = false;
    }
    return json{{"thresholds", thresholds},
        {"verdicts", std::move(verdicts)},
        {"overall", any_fail ? "FAIL" : (all_pass_or_warn ? "PASS" : "NOT_MEASURED")},
        {"wall_scale", context.wall_scale},
        {"reference_bytes", benchmark::program_sla_reference_bytes}};
}

std::string benchmark_run_id()
{
    SYSTEMTIME utc{};
    GetSystemTime(&utc);
    char stamp[32]{};
    _snprintf_s(stamp, sizeof(stamp), _TRUNCATE, "%04u%02u%02uT%02u%02u%02uZ",
        static_cast<unsigned>(utc.wYear), static_cast<unsigned>(utc.wMonth),
        static_cast<unsigned>(utc.wDay), static_cast<unsigned>(utc.wHour),
        static_cast<unsigned>(utc.wMinute), static_cast<unsigned>(utc.wSecond));
    return std::string(stamp) + "-" + std::to_string(GetCurrentProcessId());
}

json large_pe_params_json(const large_pe_params_t& params)
{
    return json{{"code_bytes", params.code_bytes},
        {"function_count", params.function_count},
        {"seed", params.seed},
        {"code_sections", params.code_sections},
        {"string_count", params.string_count},
        {"data_pointer_count", params.data_pointer_count},
        {"seed_pdata", params.seed_pdata},
        {"call_density_pct", params.call_density_pct},
        {"jump_density_pct", params.jump_density_pct},
        {"padding_pct", params.padding_pct}};
}

json large_pe_manifest_json(const large_pe_manifest_t& manifest)
{
    json sections = json::array();
    for (const auto& section : manifest.sections) {
        sections.push_back(json{{"name", section.name}, {"rva", section.rva},
            {"raw_offset", section.raw_offset}, {"virtual_size", section.virtual_size},
            {"raw_size", section.raw_size}});
    }
    return json{{"sections", std::move(sections)},
        {"function_rva_begin", manifest.function_rva_begin},
        {"function_rva_end", manifest.function_rva_end},
        {"function_count", manifest.function_count},
        {"instruction_count_estimate", manifest.instruction_count_estimate},
        {"code_bytes", manifest.code_bytes},
        {"pdata_bytes", manifest.pdata_bytes},
        {"xdata_bytes", manifest.xdata_bytes},
        {"rdata_bytes", manifest.rdata_bytes},
        {"data_bytes", manifest.data_bytes},
        {"reloc_bytes", manifest.reloc_bytes},
        {"file_size", manifest.file_size}};
}

json scorecard_phases(const json& metrics)
{
    json phases = json::array();
    if (metrics.is_object() && metrics.contains("phases") && metrics["phases"].is_array()) {
        for (const auto& phase : metrics["phases"]) {
            const std::uint64_t wall_ns = phase.value("wall_ns", 0ULL);
            phases.push_back(json{{"name", phase.value("name", std::string())},
                {"invocations", phase.value("invocations", 0ULL)},
                {"wall_ns", wall_ns}, {"cpu_ns", phase.value("cpu_ns", 0ULL)},
                {"bytes_in", phase.value("bytes_in", 0ULL)},
                {"bytes_out", phase.value("bytes_out", 0ULL)},
                {"work_items", phase.value("work_items", 0ULL)},
                {"queue_depth_peak", phase.value("queue_depth_peak", 0ULL)},
                {"active_workers_peak", phase.value("active_workers_peak", 0ULL)},
                {"throughput_bytes_per_s", nullable_rate(
                    phase.value("bytes_out", 0ULL), wall_ns)}});
        }
    }
    return phases;
}

struct scorecard_input_t {
    std::string mode;
    const json* report = nullptr;
    const json* metrics = nullptr;
    const json* throughput = nullptr;
    const json* memory = nullptr;
    const json* program_sla = nullptr;
    std::uint32_t lanes = 0;
    bool load_profile_pinned = true;
    const json* scaling = nullptr;
    const json* determinism = nullptr;
    const json* decompile_batch = nullptr;
};

json build_scorecard(const scorecard_input_t& input)
{
    const auto& report = *input.report;
    const auto& metrics = *input.metrics;
    const auto& sla = *input.program_sla;
    const std::uint64_t tasks_completed = metrics_counter(metrics, "tasks_completed");
    const std::uint64_t slots_busy = metrics_counter(metrics, "worker_slots_busy_ns");
    const std::uint64_t slots_scheduled = metrics_counter(metrics, "worker_slots_scheduled_ns");
    const std::uint64_t depth_samples = metrics_counter(metrics, "queue_depth_samples");
    const std::uint64_t logical_bytes = metrics_counter(metrics, "database_logical_bytes");
    const std::uint64_t cold_wall_ns = report["cold"].value("wall_ns", 0ULL);
    const std::uint64_t host_logical =
        (std::max<std::uint64_t>)(1, report["host"].value("logical_processors", 0U));
    json parallelism_efficiency = nullptr;
    if (cold_wall_ns != 0 && slots_busy != 0) {
        parallelism_efficiency = (std::min)(1.0, static_cast<double>(slots_busy) /
            (static_cast<double>(cold_wall_ns) * static_cast<double>(host_logical)));
    }
    json scorecard{
        {"scorecard_schema", benchmark::scorecard_schema_v2},
        {"scorecard_schema_version", benchmark::scorecard_schema_v2_version},
        {"run_id", benchmark_run_id()},
        {"mode", input.mode},
        {"claim_status", "measurement_only"},
        {"claim", json{
            {"tracks", json::array({
                json{{"id", "auto_analysis_wall"},
                    {"definition", "cold wall_ns open-to-baseline_ready at or below the size-scaled total_wall_ms_max_300mb gate (reference 300 MiB)"}},
                json{{"id", "batch_decompile_throughput"},
                    {"definition", "decompile_all_funcs_per_s on the parallel production batch engine; a throughput claim, never a minutes claim"}}})},
            {"real_mode_invocation",
                "analysis_benchmark_harness real <path>, or Test Lab analysis_benchmark_real_300mb with AIDA_BENCHMARK_REAL_PE=<path>"}}},
        {"run", json{{"lanes", input.lanes},
            {"load_profile_pinned", input.load_profile_pinned},
            {"wall_ns", cold_wall_ns},
            {"process_cpu_ns", metrics.value("process_cpu_ns", 0ULL)},
            {"analysis_revision", report["warm_reopen"].value("analysis_revision", 0ULL)},
            {"overlay_revision", report["warm_reopen"].value("overlay_revision", 0ULL)},
            {"generation", metrics.value("generation", 0ULL)}}},
        {"phases", scorecard_phases(metrics)},
        {"throughput", *input.throughput},
        {"worker_pool", json{
            {"status", "measured"},
            {"slots_busy_ns", slots_busy},
            {"slots_scheduled_ns", slots_scheduled},
            {"utilization", slots_scheduled == 0 ? json(nullptr) : json(static_cast<double>(
                slots_busy) / static_cast<double>(slots_scheduled))},
            {"parallelism_efficiency", parallelism_efficiency},
            {"logical_cores", host_logical},
            {"queue_wait_mean_ns", tasks_completed == 0 ? json(nullptr) : json(
                metrics_counter(metrics, "queue_wait_ns_total") / tasks_completed)},
            {"queue_wait_ns_total", metrics_counter(metrics, "queue_wait_ns_total")},
            {"queue_wait_max_ns", metrics_counter(metrics, "queue_wait_max_ns")},
            {"queue_depth_mean", depth_samples == 0 ? json(nullptr) : json(static_cast<double>(
                metrics_counter(metrics, "queue_depth_sum")) /
                static_cast<double>(depth_samples))},
            {"queue_depth_peak", metrics_counter(metrics, "peak_queue_depth")},
            {"tasks_scheduled", metrics_counter(metrics, "tasks_scheduled")},
            {"tasks_completed", tasks_completed},
            {"tasks_rejected", metrics_counter(metrics, "tasks_rejected")}}},
        {"decode_detail", json{
            {"tiles", metrics_counter(metrics, "decode_tiles")},
            {"requests", metrics_counter(metrics, "decode_requests")},
            {"waves", metrics_counter(metrics, "decode_waves")},
            {"frontier_seeds", metrics_counter(metrics, "decode_frontier_seeds")},
            {"cross_tile_edges", metrics_counter(metrics, "decode_cross_tile_edges")},
            {"invalid_bytes", metrics_counter(metrics, "decode_invalid_bytes")},
            {"duplicate_instructions", metrics_counter(metrics, "decode_duplicate_instructions")},
            {"merge_ns", metrics_counter(metrics, "decode_merge_ns")},
            {"lane_wall_ns_max", metrics_counter(metrics, "decode_lane_wall_ns_max")},
            {"bytes_attempted", metrics_counter(metrics, "decode_bytes_attempted")}}},
        {"memory", *input.memory},
        {"persistence", json{
            {"database_bytes", report["cold"]["database"].value("database_bytes", 0ULL)},
            {"bytes_written", metrics_counter(metrics, "database_bytes_written")},
            {"logical_bytes", logical_bytes},
            {"rows", metrics_counter(metrics, "database_rows")},
            {"commit_elapsed_ns", metrics_counter(metrics, "database_commit_elapsed_ns")},
            {"write_amplification", logical_bytes == 0 ? json(nullptr) : json(static_cast<double>(
                metrics_counter(metrics, "database_bytes_written")) /
                static_cast<double>(logical_bytes))},
            {"queue_wait_ns", metrics_counter(metrics, "persist_queue_wait_ns")},
            {"queue_depth_peak", metrics_counter(metrics, "persist_queue_depth_peak")},
            {"pages_written", metrics_counter(metrics, "persist_pages_written")},
            {"wal_bytes_peak", metrics_counter(metrics, "persist_wal_bytes_peak")}}},
        {"decompile", input.decompile_batch ? *input.decompile_batch
            : json{{"engine", "parallel_batch"}, {"status", "not_applicable"},
                {"reason", "background_batch_window_not_measured"},
                {"funcs_per_s", nullptr}}},
        {"interaction", json{
            {"warm_reopen_ms", report["warm_reopen"]["wall_ns"].is_number()
                ? json(static_cast<double>(
                    report["warm_reopen"]["wall_ns"].get<std::uint64_t>()) / 1000000.0)
                : json(nullptr)},
            {"metadata_ready_ms", metrics_phase_present(metrics, "metadata_symbols_types")
                ? json(static_cast<double>(
                    metrics_phase_wall_ns(metrics, "metadata_symbols_types")) / 1000000.0)
                : json(nullptr)},
            {"indexed_query_p95_ms", report["mcp"]["p95_ns"].is_number()
                ? json(static_cast<double>(report["mcp"]["p95_ns"].get<std::uint64_t>()) / 1000000.0)
                : json(nullptr)},
            {"mcp_call_p95_ms", report["mcp"]["p95_ns"].is_number()
                ? json(static_cast<double>(report["mcp"]["p95_ns"].get<std::uint64_t>()) / 1000000.0)
                : json(nullptr)},
            {"decompile_cold_p95_ms", report["decompiler"]["cold_p95_ns"].is_number()
                ? json(static_cast<double>(
                    report["decompiler"]["cold_p95_ns"].get<std::uint64_t>()) / 1000000.0)
                : json(nullptr)},
            {"decompile_warm_p95_ms", report["decompiler"]["warm_p95_ns"].is_number()
                ? json(static_cast<double>(
                    report["decompiler"]["warm_p95_ns"].get<std::uint64_t>()) / 1000000.0)
                : json(nullptr)},
            {"cancellation_request_to_completion_ms",
                report["cancellation"]["request_to_completion_ns"].is_number()
                    ? json(static_cast<double>(
                        report["cancellation"]["request_to_completion_ns"].get<std::uint64_t>()) /
                        1000000.0)
                    : json(nullptr)}}},
        {"counts", json{
            {"instructions", metrics_counter(metrics, "instructions")},
            {"blocks", metrics_counter(metrics, "blocks")},
            {"functions", metrics_counter(metrics, "functions")},
            {"xrefs", metrics_counter(metrics, "xrefs")},
            {"strings", metrics_counter(metrics, "strings")},
            {"symbols", metrics_counter(metrics, "symbols")},
            {"types", metrics_counter(metrics, "types")},
            {"decoded_bytes", metrics_counter(metrics, "decoded_bytes")}}},
        {"sla", sla},
        {"artifacts", json{{"report_json", nullptr},
            {"baseline_json", nullptr},
            {"compare_verdict_json", nullptr}, {"receipt_json", nullptr}}},
        {"verdict", sla.value("overall", std::string("NOT_MEASURED")) == "FAIL" ? "FAIL" : "PASS"}};
    if (input.scaling)
        scorecard["scaling"] = *input.scaling;
    else
        scorecard["scaling"] = nullptr;
    if (input.determinism)
        scorecard["determinism"] = *input.determinism;
    else
        scorecard["determinism"] = nullptr;
    return scorecard;
}

std::uint32_t parse_code_mb(const std::string& text)
{
    std::size_t consumed = 0;
    const unsigned long value = std::stoul(text, &consumed, 10);
    constexpr unsigned long min_mb = static_cast<unsigned long>(
        benchmark::synthetic_code_bytes_min / (1024ULL * 1024ULL));
    constexpr unsigned long max_mb = static_cast<unsigned long>(
        benchmark::synthetic_code_bytes_max / (1024ULL * 1024ULL));
    if (consumed != text.size() || value < min_mb || value > max_mb)
        throw fixture_error_t("synthetic code size must be within 8..320 MiB");
    return static_cast<std::uint32_t>(value);
}

std::uint64_t parse_seed_hex(const std::string& text)
{
    std::string_view view(text);
    if (view.size() > 2 && view[0] == '0' && (view[1] == 'x' || view[1] == 'X'))
        view.remove_prefix(2);
    if (view.empty())
        throw fixture_error_t("seed_hex must be a hexadecimal integer");
    std::size_t consumed = 0;
    const std::string narrowed(view);
    const unsigned long long value = std::stoull(narrowed, &consumed, 16);
    if (consumed != narrowed.size())
        throw fixture_error_t("seed_hex must be a hexadecimal integer");
    return static_cast<std::uint64_t>(value);
}

std::vector<std::uint32_t> parse_lanes_csv(const std::string& text)
{
    std::vector<std::uint32_t> lanes;
    std::size_t offset = 0;
    while (offset <= text.size()) {
        const auto comma = text.find(',', offset);
        const std::string token = text.substr(offset,
            comma == std::string::npos ? std::string::npos : comma - offset);
        if (token.empty())
            throw fixture_error_t("lanes_csv contains an empty element");
        std::size_t consumed = 0;
        const unsigned long value = std::stoul(token, &consumed, 10);
        if (consumed != token.size())
            throw fixture_error_t("lanes_csv elements must be decimal integers");
        const std::uint32_t lane = static_cast<std::uint32_t>(value);
        if (lane != 1 && lane != 2 && lane != 4 && lane != 8 && lane != 16 && lane != 32)
            throw fixture_error_t("lanes_csv elements must be within {1,2,4,8,16,32}");
        if (std::find(lanes.begin(), lanes.end(), lane) != lanes.end())
            throw fixture_error_t("lanes_csv elements must be unique");
        if (!lanes.empty() && lane < lanes.back())
            throw fixture_error_t("lanes_csv elements must be ascending");
        lanes.push_back(lane);
        if (comma == std::string::npos)
            break;
        offset = comma + 1;
    }
    if (lanes.empty())
        throw fixture_error_t("lanes_csv must contain at least one lane count");
    return lanes;
}

void assert_synthetic_within_limits(const large_pe_manifest_t& manifest)
{
    const tile_decode_orchestrator_limits_t tile_limits;
    const baseline_analysis_settings_t settings;
    const std::uint64_t instruction_limit =
        (std::min<std::uint64_t>)(tile_limits.maximum_instructions,
                                  settings.max_decoded_instructions);
    if (manifest.instruction_count_estimate >= instruction_limit)
        throw fixture_error_t(
            "synthetic fixture instruction estimate " +
            std::to_string(manifest.instruction_count_estimate) +
            " meets or exceeds the active decode limit " +
            std::to_string(instruction_limit) +
            "; the generator never truncates, so this configuration is rejected");
}

void assert_fixture_digest(const std::filesystem::path& path,
                           const large_pe_params_t& params)
{
    const auto file_digest = c03::sha256_evidence_file(path);
    if (!file_digest.ok)
        throw fixture_error_t("synthetic fixture digest failed: " + file_digest.error);
    if (file_digest.sha256 != large_pe_sha256(params))
        throw fixture_error_t("synthetic fixture digest diverged from the deterministic generator");
}

snapshot_hash_result_t capture_publication_hash(
    const std::shared_ptr<analysis_workspace_t>& workspace)
{
    const auto snapshot = workspace->snapshot();
    const auto search = workspace->search_index();
    if (!snapshot || !search)
        throw fixture_error_t("determinism capture requires a published workspace");
    auto validated = validate_analysis_snapshot(*snapshot, true, workspace->cancellation_token());
    if (!validated)
        throw fixture_error_t(validated.error().stable_code() + ":" + validated.error().message);
    snapshot_hash_input_t input;
    input.snapshot = snapshot.get();
    input.data_candidates = &search->data_candidates();
    input.switches = &search->switches();
    input.types = &search->types();
    input.content_hash = workspace->identity().content_hash();
    return compute_snapshot_hash(input);
}

json scaling_row_from_report(std::uint32_t lanes, const json& report)
{
    const auto& metrics = report["instrumented_engine"]["metrics"];
    const std::uint64_t tasks_completed = metrics_counter(metrics, "tasks_completed");
    const std::uint64_t slots_scheduled = metrics_counter(metrics, "worker_slots_scheduled_ns");
    return json{{"lanes", lanes},
        {"wall_ns", report["cold"].value("wall_ns", 0ULL)},
        {"decode_wall_ns", metrics_phase_wall_ns(metrics, "decode")},
        {"decode_merge_wall_ns", metrics_phase_wall_ns(metrics, "decode_merge")},
        {"instructions", metrics_counter(metrics, "instructions")},
        {"decoded_bytes", metrics_counter(metrics, "decoded_bytes")},
        {"file_bytes", report["cold"].value("file_bytes", 0ULL)},
        {"peak_private_bytes", metrics_counter(metrics, "peak_private_bytes")},
        {"resident_bytes_peak", metrics_counter(metrics, "resident_bytes_peak")},
        {"worker_utilization", slots_scheduled == 0 ? json(nullptr) : json(static_cast<double>(
            metrics_counter(metrics, "worker_slots_busy_ns")) /
            static_cast<double>(slots_scheduled))},
        {"queue_wait_mean_ns", tasks_completed == 0 ? json(nullptr) : json(
            metrics_counter(metrics, "queue_wait_ns_total") / tasks_completed)},
        {"tasks_scheduled", metrics_counter(metrics, "tasks_scheduled")},
        {"tasks_completed", tasks_completed},
        {"tasks_rejected", metrics_counter(metrics, "tasks_rejected")}};
}

void remove_report_database_artifacts(const json& report)
{
    const std::string cold_path = report["cold"]["database"].value("path", std::string());
    remove_database_artifacts(cold_path);
    const std::string instrumented_path =
        report["instrumented_engine"]["database"].value("path", std::string());
    remove_database_artifacts(instrumented_path);
}

}

void emit_benchmark_report(const json& report, const std::optional<std::filesystem::path>& out)
{
    const std::string text = report.dump(2);
    std::cout << text << '\n';
    if (out) {
        std::ofstream stream(*out, std::ios::binary | std::ios::trunc);
        stream << text << '\n';
        stream.flush();
        if (!stream)
            throw aida::analysis::test_fixture::fixture_error_t(
                "unable to write the --out benchmark report");
    }
}

int run_legacy_mode(const std::string& benchmark_mode, const std::filesystem::path& path,
                    const std::optional<std::filesystem::path>& out)
{
    const bool release_sla = benchmark_mode == "release_sla";
    measurement_options_t options;
    options.benchmark_mode = benchmark_mode;
    options.claim_status = release_sla ? "measurement_candidate" : "development_only";
    options.release_qualification = release_sla;
    options.pin_profile = false;
    options.skip_concurrent = false;
    options.worker_lanes = 0;
    const auto report = run_measurement(std::filesystem::absolute(path), options);
    emit_benchmark_report(report, out);
    return 0;
}

int run_synthetic_mode(std::uint32_t code_mb, std::uint64_t seed, std::uint32_t lanes,
                       const std::optional<std::filesystem::path>& out)
{
    large_pe_params_t params;
    params.code_bytes = static_cast<std::uint64_t>(code_mb) * 1024ULL * 1024ULL;
    params.seed = seed;
    params = validated_large_pe_params(params);
    const auto manifest = describe_large_pe(params);
    assert_synthetic_within_limits(manifest);
    fixture_root_t root("synthetic_benchmark");
    const auto fixture_path = root.path() / "synthetic.exe";
    write_large_pe64(fixture_path, params);
    assert_fixture_digest(fixture_path, params);
    measurement_options_t options;
    options.benchmark_mode = "synthetic";
    options.claim_status = "measurement_only";
    options.pin_profile = true;
    options.skip_concurrent = true;
    options.worker_lanes = lanes;
    auto report = run_measurement(fixture_path, options);
    const auto metrics = report["instrumented_engine"]["metrics"];
    const search_index_limits_t search_limits;
    if (metrics_counter(metrics, "index_entries") >= search_limits.max_entries)
        throw aida::analysis::test_fixture::fixture_error_t(
            "synthetic run exceeded the search index entry bound");
    report["fixture"]["generator"] = json{{"kind", "synthetic_large_pe64"},
        {"params", large_pe_params_json(params)},
        {"manifest", large_pe_manifest_json(manifest)}};
    report["fixture"]["kind"] = "synthetic";
    report["fixture"]["size_bytes"] = report["fixture"]["size"];
    const auto throughput = throughput_block(report, metrics);
    report["throughput"] = throughput;
    const auto memory = memory_block(report, metrics);
    report["memory"] = memory;
    const auto background_batch = report["background_decompile_batch"];
    sla_measurement_context_t sla_context;
    sla_context.report = &report;
    sla_context.metrics = &metrics;
    sla_context.throughput = &throughput;
    sla_context.wall_scale = static_cast<double>(code_mb) / 300.0;
    sla_context.decompile_funcs_per_s = &background_batch["funcs_per_s"];
    auto program_sla = evaluate_program_sla(sla_context);
    report["program_sla"] = program_sla;
    scorecard_input_t scorecard_input;
    scorecard_input.mode = "synthetic";
    scorecard_input.report = &report;
    scorecard_input.metrics = &metrics;
    scorecard_input.throughput = &throughput;
    scorecard_input.memory = &memory;
    scorecard_input.program_sla = &program_sla;
    scorecard_input.lanes = lanes;
    scorecard_input.load_profile_pinned = true;
    scorecard_input.decompile_batch = &background_batch;
    report["scorecard"] = build_scorecard(scorecard_input);
    report["scorecard"]["fixture"] = report["fixture"];
    report["scorecard"]["host"] = report["host"];
    emit_benchmark_report(report, out);
    return program_sla.value("overall", std::string()) == "FAIL" ? 1 : 0;
}

int run_scaling_mode(std::uint32_t code_mb, std::uint64_t seed,
                     const std::vector<std::uint32_t>& lanes,
                     const std::optional<std::filesystem::path>& out)
{
    large_pe_params_t params;
    params.code_bytes = static_cast<std::uint64_t>(code_mb) * 1024ULL * 1024ULL;
    params.seed = seed;
    params = validated_large_pe_params(params);
    const auto manifest = describe_large_pe(params);
    assert_synthetic_within_limits(manifest);
    fixture_root_t root("scaling_benchmark");
    const auto fixture_path = root.path() / "synthetic.exe";
    write_large_pe64(fixture_path, params);
    assert_fixture_digest(fixture_path, params);

    json rows = json::array();
    std::vector<std::pair<std::string,
        std::pair<std::uint32_t, snapshot_hash_result_t>>> hash_runs;
    json last_report;
    for (const auto lane : lanes) {
        snapshot_hash_result_t captured;
        measurement_options_t options;
        options.benchmark_mode = "scaling";
        options.claim_status = "measurement_only";
        options.pin_profile = true;
        options.skip_concurrent = true;
        options.worker_lanes = lane;
        options.publication_callback = [&](const std::shared_ptr<analysis_workspace_t>& workspace) {
            captured = capture_publication_hash(workspace);
        };
        last_report = run_measurement(fixture_path, options);
        remove_report_database_artifacts(last_report);
        rows.push_back(scaling_row_from_report(lane, last_report));
        hash_runs.push_back({"lanes=" + std::to_string(lane), {lane, captured}});
    }
    bool hash_match = false;
    const auto hash_manifest = build_hash_manifest(hash_runs, hash_match);

    std::optional<std::uint64_t> wall_lane1;
    for (const auto& row : rows) {
        if (row.value("lanes", 0U) == 1U) {
            wall_lane1 = row.value("wall_ns", 0ULL);
            break;
        }
    }
    json lane_values = json::array();
    json wall_values = json::array();
    json speedup_values = json::array();
    json efficiency_values = json::array();
    for (auto& row : rows) {
        const auto lane = row.value("lanes", 0U);
        const std::uint64_t wall_ns = row.value("wall_ns", 0ULL);
        json speedup = nullptr;
        json efficiency = nullptr;
        if (wall_lane1 && *wall_lane1 != 0 && wall_ns != 0) {
            speedup = static_cast<double>(*wall_lane1) / static_cast<double>(wall_ns);
            efficiency = static_cast<double>(*wall_lane1) /
                (static_cast<double>(wall_ns) * static_cast<double>(lane));
        }
        row["speedup"] = speedup;
        row["efficiency"] = efficiency;
        row["decode_throughput_bytes_per_s"] = nullable_rate(
            row.value("decoded_bytes", 0ULL),
            row.value("decode_wall_ns", 0ULL) + row.value("decode_merge_wall_ns", 0ULL));
        lane_values.push_back(lane);
        wall_values.push_back(wall_ns);
        speedup_values.push_back(speedup);
        efficiency_values.push_back(efficiency);
    }

    double wall16_over_wall1 = -1.0;
    double efficiency_16 = -1.0;
    bool has_lane16 = false;
    std::optional<std::uint64_t> wall_lane16;
    for (const auto& row : rows) {
        if (row.value("lanes", 0U) == 16U) {
            has_lane16 = true;
            wall_lane16 = row.value("wall_ns", 0ULL);
            if (row["efficiency"].is_number())
                efficiency_16 = row["efficiency"].get<double>();
        }
    }
    const auto host_logical = last_report["host"].value("logical_processors", 0U);
    const bool scaling_gate_applicable = wall_lane1.has_value() && has_lane16 &&
        host_logical >= 16;
    if (scaling_gate_applicable && *wall_lane1 != 0 && wall_lane16 && *wall_lane16 != 0)
        wall16_over_wall1 = static_cast<double>(*wall_lane16) / static_cast<double>(*wall_lane1);

    const auto metrics = last_report["instrumented_engine"]["metrics"];
    const auto throughput = throughput_block(last_report, metrics);
    const auto memory = memory_block(last_report, metrics);
    const auto background_batch = last_report["background_decompile_batch"];
    sla_measurement_context_t sla_context;
    sla_context.report = &last_report;
    sla_context.metrics = &metrics;
    sla_context.throughput = &throughput;
    sla_context.wall_scale = static_cast<double>(code_mb) / 300.0;
    sla_context.determinism_match = lanes.size() >= 2 ? &hash_match : nullptr;
    sla_context.scaling_wall16_over_wall1 = wall16_over_wall1;
    sla_context.scaling_efficiency_16 = efficiency_16;
    sla_context.scaling_gate_applicable = scaling_gate_applicable;
    sla_context.decompile_funcs_per_s = &background_batch["funcs_per_s"];
    auto program_sla = evaluate_program_sla(sla_context);

    json scaling_block = json{{"lanes", std::move(lane_values)},
        {"wall_ns", std::move(wall_values)},
        {"speedup", std::move(speedup_values)},
        {"efficiency", std::move(efficiency_values)},
        {"rows", std::move(rows)},
        {"hash_match_across_lanes", lanes.size() >= 2 ? json(hash_match) : json(nullptr)},
        {"wall16_over_wall1", wall16_over_wall1 < 0 ? json(nullptr) : json(wall16_over_wall1)},
        {"efficiency_16", efficiency_16 < 0 ? json(nullptr) : json(efficiency_16)},
        {"gate_applicable", scaling_gate_applicable},
        {"host_logical_processors", host_logical}};

    last_report["fixture"]["generator"] = json{{"kind", "synthetic_large_pe64"},
        {"params", large_pe_params_json(params)},
        {"manifest", large_pe_manifest_json(manifest)}};
    last_report["fixture"]["kind"] = "synthetic";
    last_report["fixture"]["size_bytes"] = last_report["fixture"]["size"];
    last_report["throughput"] = throughput;
    last_report["memory"] = memory;
    last_report["scaling"] = scaling_block;
    last_report["determinism"] = hash_manifest;
    last_report["program_sla"] = program_sla;
    scorecard_input_t scorecard_input;
    scorecard_input.mode = "scaling";
    scorecard_input.report = &last_report;
    scorecard_input.metrics = &metrics;
    scorecard_input.throughput = &throughput;
    scorecard_input.memory = &memory;
    scorecard_input.program_sla = &program_sla;
    scorecard_input.lanes = lanes.back();
    scorecard_input.load_profile_pinned = true;
    scorecard_input.scaling = &scaling_block;
    scorecard_input.determinism = &hash_manifest;
    scorecard_input.decompile_batch = &background_batch;
    last_report["scorecard"] = build_scorecard(scorecard_input);
    last_report["scorecard"]["fixture"] = last_report["fixture"];
    last_report["scorecard"]["host"] = last_report["host"];
    emit_benchmark_report(last_report, out);
    return program_sla.value("overall", std::string()) == "FAIL" ? 1 : 0;
}

int run_determinism_mode(std::uint32_t code_mb, std::uint64_t seed,
                         const std::optional<std::filesystem::path>& out)
{
    large_pe_params_t params;
    params.code_bytes = static_cast<std::uint64_t>(code_mb) * 1024ULL * 1024ULL;
    params.seed = seed;
    params = validated_large_pe_params(params);
    const auto manifest = describe_large_pe(params);
    assert_synthetic_within_limits(manifest);
    fixture_root_t root("determinism_benchmark");
    const auto fixture_path = root.path() / "synthetic.exe";
    write_large_pe64(fixture_path, params);
    assert_fixture_digest(fixture_path, params);

    const std::array<std::pair<const char*, std::uint32_t>, 3> run_plan{{
        {"A_lanes_1", 1}, {"B_lanes_16", 16}, {"C_lanes_16", 16}}};
    std::vector<std::pair<std::string,
        std::pair<std::uint32_t, snapshot_hash_result_t>>> hash_runs;
    json report;
    for (const auto& [label, lanes] : run_plan) {
        snapshot_hash_result_t captured;
        measurement_options_t options;
        options.benchmark_mode = "determinism";
        options.claim_status = "measurement_only";
        options.pin_profile = true;
        options.skip_concurrent = true;
        options.worker_lanes = lanes;
        options.publication_callback = [&](const std::shared_ptr<analysis_workspace_t>& workspace) {
            captured = capture_publication_hash(workspace);
        };
        report = run_measurement(fixture_path, options);
        remove_report_database_artifacts(report);
        hash_runs.push_back({label, {lanes, captured}});
    }
    bool hash_match = false;
    const auto hash_manifest = build_hash_manifest(hash_runs, hash_match);

    const auto metrics = report["instrumented_engine"]["metrics"];
    const auto throughput = throughput_block(report, metrics);
    const auto memory = memory_block(report, metrics);
    const auto background_batch = report["background_decompile_batch"];
    sla_measurement_context_t sla_context;
    sla_context.report = &report;
    sla_context.metrics = &metrics;
    sla_context.throughput = &throughput;
    sla_context.wall_scale = static_cast<double>(code_mb) / 300.0;
    sla_context.determinism_match = &hash_match;
    sla_context.decompile_funcs_per_s = &background_batch["funcs_per_s"];
    auto program_sla = evaluate_program_sla(sla_context);

    report["fixture"]["generator"] = json{{"kind", "synthetic_large_pe64"},
        {"params", large_pe_params_json(params)},
        {"manifest", large_pe_manifest_json(manifest)}};
    report["fixture"]["kind"] = "synthetic";
    report["fixture"]["size_bytes"] = report["fixture"]["size"];
    report["throughput"] = throughput;
    report["memory"] = memory;
    report["determinism"] = hash_manifest;
    report["program_sla"] = program_sla;
    scorecard_input_t scorecard_input;
    scorecard_input.mode = "determinism";
    scorecard_input.report = &report;
    scorecard_input.metrics = &metrics;
    scorecard_input.throughput = &throughput;
    scorecard_input.memory = &memory;
    scorecard_input.program_sla = &program_sla;
    scorecard_input.lanes = 16;
    scorecard_input.load_profile_pinned = true;
    scorecard_input.determinism = &hash_manifest;
    scorecard_input.decompile_batch = &background_batch;
    report["scorecard"] = build_scorecard(scorecard_input);
    report["scorecard"]["fixture"] = report["fixture"];
    report["scorecard"]["host"] = report["host"];
    emit_benchmark_report(report, out);
    if (!hash_match)
        return 1;
    return program_sla.value("overall", std::string()) == "FAIL" ? 1 : 0;
}

int run_determinism_hw_mode(std::uint32_t code_mb, std::uint64_t seed,
                            const std::optional<std::filesystem::path>& out)
{
    benchmark::benchmark_run_request_t request;
    request.mode = benchmark::benchmark_mode_t::synthetic;
    request.synthetic_code_bytes = static_cast<std::uint64_t>(code_mb) * 1024ULL * 1024ULL;
    request.synthetic_seed = seed;
    request.run_determinism_stage = true;
    request.determinism_runs = 2;
    const auto result = benchmark::run_benchmark(request);
    if (!result.ok)
        throw fixture_error_t("production determinism-hw benchmark failed: " + result.error);
    json scorecard;
    try {
        scorecard = json::parse(result.scorecard_json);
    } catch (const json::exception& exception) {
        throw fixture_error_t(std::string("production determinism-hw scorecard is invalid: ") +
            exception.what());
    }
    const auto hardware = (std::max)(1U, std::thread::hardware_concurrency());
    const std::uint32_t expected_budget = (std::min)(64U, (std::max)(2U, hardware));
    if (!scorecard["determinism"].is_object() ||
        !scorecard["determinism"]["runs"].is_array() ||
        scorecard["determinism"]["runs"].size() != 3)
        throw fixture_error_t("production determinism-hw stage did not execute the default budget plan");
    const std::array<std::uint32_t, 3> expected_budgets{1U, expected_budget, expected_budget};
    std::string first_hash;
    for (std::size_t index = 0; index < expected_budgets.size(); ++index) {
        const auto& run = scorecard["determinism"]["runs"][index];
        if (run.value("budget", 0U) != expected_budgets[index])
            throw fixture_error_t("production determinism-hw stage used a non-default worker budget");
        const auto hash = run.value("snapshot_sha256", std::string());
        if (hash.empty())
            throw fixture_error_t("production determinism-hw stage omitted a snapshot digest");
        if (index == 0)
            first_hash = hash;
        else if (hash != first_hash)
            throw fixture_error_t("production determinism-hw snapshot digests diverged across budgets");
    }
    if (!scorecard["determinism"].value("match", false))
        throw fixture_error_t("production determinism-hw stage reported a digest mismatch");
    if (!scorecard["sla"].is_object() || !scorecard["sla"]["verdicts"].is_array())
        throw fixture_error_t("production determinism-hw scorecard omitted its SLA verdicts");
    bool determinism_pass = false;
    for (const auto& verdict : scorecard["sla"]["verdicts"]) {
        if (verdict.value("key", std::string()) == "determinism_hash_match") {
            determinism_pass = verdict.value("verdict", std::string()) == "PASS" &&
                verdict.value("actual", false);
            break;
        }
    }
    if (!determinism_pass)
        throw fixture_error_t("production determinism-hw SLA key determinism_hash_match did not PASS");
    emit_benchmark_report(scorecard, out);
    return 0;
}

int run_real_mode(const std::filesystem::path& path,
                  const std::optional<std::filesystem::path>& out)
{
    std::error_code fixture_path_error;
    if (!std::filesystem::is_regular_file(path, fixture_path_error))
        throw fixture_error_t("real fixture does not exist: " + path.u8string());
    std::error_code fixture_size_error;
    const auto fixture_file_size = std::filesystem::file_size(path, fixture_size_error);
    if (fixture_size_error)
        throw fixture_error_t("real fixture size query failed: " + path.u8string());
    if (fixture_file_size < benchmark::real_fixture_min_bytes ||
        fixture_file_size > benchmark::real_fixture_max_bytes)
        throw fixture_error_t("real fixture size " + std::to_string(fixture_file_size) +
            " is outside the program-gate 300000000..500000000 byte window");
    measurement_options_t options;
    options.benchmark_mode = "real";
    options.claim_status = "measurement_candidate";
    options.release_qualification = true;
    options.pin_profile = false;
    options.skip_concurrent = true;
    options.worker_lanes = 0;
    auto report = run_measurement(std::filesystem::absolute(path), options);
    const auto metrics = report["instrumented_engine"]["metrics"];
    const auto throughput = throughput_block(report, metrics);
    const auto memory = memory_block(report, metrics);
    const auto background_batch = report["background_decompile_batch"];
    report["throughput"] = throughput;
    report["memory"] = memory;
    report["fixture"]["kind"] = "real";
    report["fixture"]["size_bytes"] = report["fixture"]["size"];
    sla_measurement_context_t sla_context;
    sla_context.report = &report;
    sla_context.metrics = &metrics;
    sla_context.throughput = &throughput;
    sla_context.wall_scale = benchmark::program_sla_wall_scale(
        report["fixture"]["size_bytes"].get<std::uint64_t>());
    sla_context.decompile_funcs_per_s = &background_batch["funcs_per_s"];
    auto program_sla = evaluate_program_sla(sla_context);
    report["program_sla"] = program_sla;
    scorecard_input_t scorecard_input;
    scorecard_input.mode = "real";
    scorecard_input.report = &report;
    scorecard_input.metrics = &metrics;
    scorecard_input.throughput = &throughput;
    scorecard_input.memory = &memory;
    scorecard_input.program_sla = &program_sla;
    scorecard_input.lanes = 0;
    scorecard_input.load_profile_pinned = false;
    scorecard_input.decompile_batch = &background_batch;
    report["scorecard"] = build_scorecard(scorecard_input);
    report["scorecard"]["fixture"] = report["fixture"];
    report["scorecard"]["host"] = report["host"];
    emit_benchmark_report(report, out);
    return program_sla.value("overall", std::string()) == "FAIL" ? 1 : 0;
}

std::string seed_hex_text(std::uint64_t seed)
{
    char buffer[24]{};
    _snprintf_s(buffer, sizeof(buffer), _TRUNCATE, "0x%llX",
        static_cast<unsigned long long>(seed));
    return buffer;
}

int run_synthetic_compare_mode(std::uint32_t code_mb, std::uint64_t seed,
                               const std::filesystem::path& baseline_path,
                               bool update_baseline,
                               const std::optional<std::filesystem::path>& out)
{
    json baseline;
    {
        std::ifstream stream(baseline_path, std::ios::binary);
        if (!stream)
            throw fixture_error_t("structural baseline is unavailable: " +
                baseline_path.u8string());
        try {
            stream >> baseline;
        } catch (const json::exception& exception) {
            throw fixture_error_t(std::string("structural baseline JSON is invalid: ") +
                exception.what());
        }
    }
    if (baseline.value("schema", std::string()) != benchmark::structural_baseline_schema_v1 ||
        baseline.value("schema_version", 0U) != benchmark::structural_baseline_schema_v1_version)
        throw fixture_error_t("structural baseline schema marker is missing or unsupported");
    if (baseline.value("code_mb", 0U) != code_mb)
        throw fixture_error_t("structural baseline code_mb does not match the requested fixture");
    if (baseline.value("seed_hex", std::string()) != seed_hex_text(seed))
        throw fixture_error_t("structural baseline seed_hex does not match the requested fixture");

    large_pe_params_t params;
    params.code_bytes = static_cast<std::uint64_t>(code_mb) * 1024ULL * 1024ULL;
    params.seed = seed;
    params = validated_large_pe_params(params);
    const auto manifest = describe_large_pe(params);
    assert_synthetic_within_limits(manifest);
    fixture_root_t root("synthetic_compare_benchmark");
    const auto fixture_path = root.path() / "synthetic.exe";
    write_large_pe64(fixture_path, params);
    assert_fixture_digest(fixture_path, params);

    snapshot_hash_result_t captured;
    measurement_options_t options;
    options.benchmark_mode = "synthetic_compare";
    options.claim_status = "measurement_only";
    options.pin_profile = true;
    options.skip_concurrent = true;
    options.worker_lanes = 0;
    options.publication_callback = [&](const std::shared_ptr<analysis_workspace_t>& workspace) {
        captured = capture_publication_hash(workspace);
    };
    auto report = run_measurement(fixture_path, options);
    const auto metrics = report["instrumented_engine"]["metrics"];
    const auto throughput = throughput_block(report, metrics);
    const auto memory = memory_block(report, metrics);
    const auto background_batch = report["background_decompile_batch"];
    report["throughput"] = throughput;
    report["memory"] = memory;
    report["fixture"]["generator"] = json{{"kind", "synthetic_large_pe64"},
        {"params", large_pe_params_json(params)},
        {"manifest", large_pe_manifest_json(manifest)}};
    report["fixture"]["kind"] = "synthetic";
    report["fixture"]["size_bytes"] = report["fixture"]["size"];
    sla_measurement_context_t sla_context;
    sla_context.report = &report;
    sla_context.metrics = &metrics;
    sla_context.throughput = &throughput;
    sla_context.wall_scale = static_cast<double>(code_mb) / 300.0;
    sla_context.determinism_match = nullptr;
    sla_context.decompile_funcs_per_s = &background_batch["funcs_per_s"];
    auto program_sla = evaluate_program_sla(sla_context);
    report["program_sla"] = program_sla;
    scorecard_input_t scorecard_input;
    scorecard_input.mode = "synthetic_compare";
    scorecard_input.report = &report;
    scorecard_input.metrics = &metrics;
    scorecard_input.throughput = &throughput;
    scorecard_input.memory = &memory;
    scorecard_input.program_sla = &program_sla;
    scorecard_input.lanes = 0;
    scorecard_input.load_profile_pinned = true;
    scorecard_input.decompile_batch = &background_batch;
    report["scorecard"] = build_scorecard(scorecard_input);
    report["scorecard"]["fixture"] = report["fixture"];
    report["scorecard"]["host"] = report["host"];

    const std::uint64_t logical_bytes = metrics_counter(metrics, "database_logical_bytes");
    const std::uint64_t written_bytes = metrics_counter(metrics, "database_bytes_written");
    const json write_amplification = logical_bytes == 0 ? json(nullptr)
        : json(static_cast<double>(written_bytes) / static_cast<double>(logical_bytes));
    json scorecard_blocks = json::object();
    if (baseline.contains("contract") && baseline["contract"].is_object() &&
        baseline["contract"].contains("required_scorecard_blocks") &&
        baseline["contract"]["required_scorecard_blocks"].is_array()) {
        for (const auto& block : baseline["contract"]["required_scorecard_blocks"]) {
            const auto name = block.get<std::string>();
            scorecard_blocks[name] = report["scorecard"].contains(name) &&
                !report["scorecard"][name].is_null();
        }
    }
    json candidate = json{
        {"schema", benchmark::structural_baseline_schema_v1},
        {"schema_version", benchmark::structural_baseline_schema_v1_version},
        {"code_mb", code_mb},
        {"seed_hex", seed_hex_text(seed)},
        {"capture", json{
            {"status", "captured"},
            {"snapshot_sha256", captured.manifest_sha256},
            {"counts", json{
                {"instructions", metrics_counter(metrics, "instructions")},
                {"blocks", metrics_counter(metrics, "blocks")},
                {"functions", metrics_counter(metrics, "functions")},
                {"xrefs", metrics_counter(metrics, "xrefs")},
                {"strings", metrics_counter(metrics, "strings")},
                {"types", metrics_counter(metrics, "types")},
                {"decoded_bytes", metrics_counter(metrics, "decoded_bytes")}}},
            {"write_amplification", write_amplification},
            {"phases_present", benchmark::metrics_phase_names_from_json(metrics)},
            {"scorecard_schema_version",
                report["scorecard"].value("scorecard_schema_version", 0U)},
            {"scorecard_blocks", std::move(scorecard_blocks)}}}};

    auto verdict = benchmark::compare_structural_baseline(baseline, candidate);
    verdict["baseline"] = baseline_path.u8string();
    if (update_baseline) {
        if (!benchmark::structural_compare_update_allowed(verdict)) {
            verdict["baseline_updated"] = false;
            verdict["baseline_update_refused"] =
                "contract checks failed; the baseline is only rewritten after a structural PASS";
        } else {
            candidate["contract"] = baseline.contains("contract") &&
                    baseline["contract"].is_object()
                ? baseline["contract"] : json::object();
            std::ofstream stream(baseline_path, std::ios::binary | std::ios::trunc);
            if (!stream)
                throw fixture_error_t("unable to rewrite the structural baseline: " +
                    baseline_path.u8string());
            stream << candidate.dump(2) << '\n';
            stream.flush();
            if (!stream)
                throw fixture_error_t("structural baseline rewrite failed: " +
                    baseline_path.u8string());
            verdict["baseline_updated"] = true;
        }
    } else {
        verdict["baseline_updated"] = false;
    }
    emit_benchmark_report(verdict, out);
    return verdict.value("overall", std::string()) == "FAIL" ? 1 : 0;
}

int run_compare_mode(const std::filesystem::path& baseline_path,
                     const std::filesystem::path& candidate_path,
                     const std::optional<std::filesystem::path>& out)
{
    const auto load_report = [](const std::filesystem::path& path) {
        std::ifstream stream(path, std::ios::binary);
        if (!stream)
            throw fixture_error_t("compare report is unavailable: " + path.u8string());
        json value;
        try {
            stream >> value;
        } catch (const json::exception& exception) {
            throw fixture_error_t(std::string("compare report JSON is invalid: ") +
                exception.what());
        }
        return value;
    };
    const json baseline = load_report(baseline_path);
    const json candidate = load_report(candidate_path);

    const auto verdict_actual = [](const json& report, const std::string& key) -> json {
        const json* container = nullptr;
        if (report.contains("program_sla") && report["program_sla"].is_object())
            container = &report["program_sla"];
        else if (report.contains("sla") && report["sla"].is_object())
            container = &report["sla"];
        if (!container || !container->contains("verdicts") ||
            !(*container)["verdicts"].is_array())
            return nullptr;
        for (const auto& verdict : (*container)["verdicts"]) {
            if (verdict.value("key", std::string()) == key)
                return verdict["actual"];
        }
        return nullptr;
    };

    json verdicts = json::array();
    json warnings = json::array();
    bool any_fail = false;
    const auto& thresholds = benchmark::program_sla_thresholds();
    for (const auto& item : thresholds.items()) {
        const auto& key = item.key();
        if (key == "threshold_schema" || key == "threshold_schema_version")
            continue;
        const json candidate_actual = verdict_actual(candidate, key);
        const json baseline_actual = verdict_actual(baseline, key);
        if (baseline_actual.is_null() || candidate_actual.is_null()) {
            verdicts.push_back(json{{"key", key}, {"target", item.value()},
                {"baseline", baseline_actual}, {"candidate", candidate_actual},
                {"delta_pct", nullptr}, {"verdict", "NOT_COMPARABLE"}});
            continue;
        }
        if (item.value().is_boolean()) {
            const bool worse = baseline_actual.get<bool>() && !candidate_actual.get<bool>();
            if (worse)
                any_fail = true;
            verdicts.push_back(json{{"key", key}, {"target", item.value()},
                {"baseline", baseline_actual}, {"candidate", candidate_actual},
                {"delta_pct", nullptr}, {"verdict", worse ? "FAIL" : "PASS"}});
            continue;
        }
        if (!baseline_actual.is_number() || !candidate_actual.is_number()) {
            verdicts.push_back(json{{"key", key}, {"target", item.value()},
                {"baseline", baseline_actual}, {"candidate", candidate_actual},
                {"delta_pct", nullptr}, {"verdict", "NOT_COMPARABLE"}});
            continue;
        }
        const double baseline_value = baseline_actual.get<double>();
        const double candidate_value = candidate_actual.get<double>();
        if (baseline_value == 0.0) {
            verdicts.push_back(json{{"key", key}, {"target", item.value()},
                {"baseline", baseline_actual}, {"candidate", candidate_actual},
                {"delta_pct", nullptr}, {"verdict", "NOT_COMPARABLE"}});
            continue;
        }
        const double delta_pct =
            (candidate_value - baseline_value) / baseline_value * 100.0;
        const bool lower_is_better = key.find("_max") != std::string::npos;
        const bool worse = lower_is_better ? delta_pct > 5.0 : delta_pct < -5.0;
        if (worse)
            any_fail = true;
        verdicts.push_back(json{{"key", key}, {"target", item.value()},
            {"baseline", baseline_actual}, {"candidate", candidate_actual},
            {"delta_pct", delta_pct}, {"verdict", worse ? "FAIL" : "PASS"}});
    }

    static const char* const informational_keys[] = {
        "file_bytes_per_s", "decode_bytes_per_s", "instructions_per_s",
        "functions_per_s", "index_bytes_per_s", "persist_bytes_per_s",
        "decompile_all_funcs_per_s"};
    json informational = json::array();
    for (const char* key : informational_keys) {
        const json baseline_value = baseline.contains("throughput")
            ? baseline["throughput"].value(key, json(nullptr)) : json(nullptr);
        const json candidate_value = candidate.contains("throughput")
            ? candidate["throughput"].value(key, json(nullptr)) : json(nullptr);
        if (!baseline_value.is_number() || !candidate_value.is_number()) {
            informational.push_back(json{{"key", key}, {"baseline", baseline_value},
                {"candidate", candidate_value}, {"delta_pct", nullptr},
                {"verdict", "NOT_COMPARABLE"}});
            continue;
        }
        const double before = baseline_value.get<double>();
        const double after = candidate_value.get<double>();
        if (before == 0.0) {
            informational.push_back(json{{"key", key}, {"baseline", baseline_value},
                {"candidate", candidate_value}, {"delta_pct", nullptr},
                {"verdict", "NOT_COMPARABLE"}});
            continue;
        }
        const double delta_pct = (after - before) / before * 100.0;
        const bool warn = delta_pct < -10.0;
        if (warn)
            warnings.push_back(std::string(key) + " regressed " +
                std::to_string(delta_pct) + "%");
        informational.push_back(json{{"key", key}, {"baseline", baseline_value},
            {"candidate", candidate_value}, {"delta_pct", delta_pct},
            {"verdict", warn ? "WARN" : "PASS"}});
    }

    json verdict_report = json{
        {"schema", "aida.hyperperf.compare-verdict"},
        {"schema_version", 1},
        {"baseline", baseline_path.u8string()},
        {"candidate", candidate_path.u8string()},
        {"verdicts", std::move(verdicts)},
        {"informational", std::move(informational)},
        {"warnings", std::move(warnings)},
        {"overall", any_fail ? "FAIL" : "PASS"}};
    emit_benchmark_report(verdict_report, out);
    return any_fail ? 1 : 0;
}

int main(int argc, char** argv)
{
    try {
        if (argc == 4 && std::string_view(argv[1]) == "--validate-receipt")
            return validate_receipt_command(argv[2], std::filesystem::u8path(argv[3]));
        std::vector<std::string> args;
        for (int index = 1; index < argc; ++index)
            args.emplace_back(argv[index]);
        std::optional<std::filesystem::path> out_path;
        for (std::size_t index = 0; index + 1 < args.size(); ++index) {
            if (args[index] == "--out") {
                out_path = std::filesystem::u8path(args[index + 1]);
                args.erase(args.begin() + static_cast<std::ptrdiff_t>(index),
                           args.begin() + static_cast<std::ptrdiff_t>(index + 2));
                break;
            }
        }
        if (args.empty())
            throw aida::analysis::test_fixture::fixture_error_t(
                "usage: analysis_benchmark_harness <deterministic_component|release_sla|synthetic|scaling|determinism|determinism_hw|real|synthetic_compare|compare> ...");
        const std::string& mode = args[0];
        if ((mode == "deterministic_component" || mode == "release_sla") && args.size() == 2)
            return run_legacy_mode(mode, std::filesystem::u8path(args[1]), out_path);
        if (mode == "synthetic" && (args.size() == 3 || args.size() == 5)) {
            std::uint32_t lanes = 0;
            if (args.size() == 5) {
                if (args[3] != "--lanes")
                    throw aida::analysis::test_fixture::fixture_error_t(
                        "synthetic mode accepts only --lanes <N> after <seed_hex>");
                const auto parsed = parse_lanes_csv(args[4]);
                if (parsed.size() != 1)
                    throw aida::analysis::test_fixture::fixture_error_t(
                        "synthetic --lanes accepts exactly one lane count");
                lanes = parsed.at(0);
            }
            return run_synthetic_mode(parse_code_mb(args[1]), parse_seed_hex(args[2]),
                lanes, out_path);
        }
        if (mode == "scaling" && args.size() == 4) {
            return run_scaling_mode(parse_code_mb(args[1]), parse_seed_hex(args[2]),
                parse_lanes_csv(args[3]), out_path);
        }
        if (mode == "determinism" && args.size() == 3)
            return run_determinism_mode(parse_code_mb(args[1]), parse_seed_hex(args[2]), out_path);
        if (mode == "determinism_hw" && args.size() == 3)
            return run_determinism_hw_mode(parse_code_mb(args[1]), parse_seed_hex(args[2]), out_path);
        if (mode == "real" && args.size() == 2)
            return run_real_mode(std::filesystem::u8path(args[1]), out_path);
        if (mode == "synthetic_compare" && (args.size() == 4 || args.size() == 5)) {
            bool update_baseline = false;
            if (args.size() == 5) {
                if (args[4] != "--update-baseline")
                    throw aida::analysis::test_fixture::fixture_error_t(
                        "synthetic_compare accepts only --update-baseline after <baseline.json>");
                update_baseline = true;
            }
            return run_synthetic_compare_mode(parse_code_mb(args[1]), parse_seed_hex(args[2]),
                std::filesystem::u8path(args[3]), update_baseline, out_path);
        }
        if (mode == "compare" && args.size() == 3)
            return run_compare_mode(std::filesystem::u8path(args[1]),
                std::filesystem::u8path(args[2]), out_path);
        throw aida::analysis::test_fixture::fixture_error_t(
            "usage: analysis_benchmark_harness <deterministic_component|release_sla> <fixture> [--out <report.json>] | synthetic <code_mb> <seed_hex> [--lanes N] [--out <report.json>] | scaling <code_mb> <seed_hex> <lanes_csv> [--out <report.json>] | determinism <code_mb> <seed_hex> [--out <report.json>] | determinism_hw <code_mb> <seed_hex> [--out <report.json>] | real <fixture> [--out <report.json>] | synthetic_compare <code_mb> <seed_hex> <baseline.json> [--update-baseline] [--out <verdict.json>] | compare <baseline.json> <candidate.json> [--out <verdict.json>]");
    } catch (const std::exception& error) {
        aida::analysis::c03_test::assertion_telemetry::record_exception(
            error.what());
        std::cerr << error.what() << '\n';
        return 1;
    }
}
