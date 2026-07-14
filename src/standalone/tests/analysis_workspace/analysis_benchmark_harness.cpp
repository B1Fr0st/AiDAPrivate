#include "workspace_fixture_builder.hpp"

#include "../c03/benchmark_sla_schema.hpp"
#include "../c03/assertion_telemetry/assertion_telemetry.hpp"

#include <winioctl.h>
#include <psapi.h>

#include "../../src/core/mcp/compat/c03_compatibility_registration.hpp"
#include "../../src/core/mcp/registry/tool_registry.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <intrin.h>
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
    std::array<char, 1024 * 1024> buffer{};
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
    json* acquisition_metrics = nullptr)
{
    static const std::uint64_t run_nonce =
        (static_cast<std::uint64_t>(GetCurrentProcessId()) << 32) ^
        static_cast<std::uint64_t>(steady_clock_t::now().time_since_epoch().count());
    open_static_workspace_request_t request;
    request.source_path = path.u8string();
    request.bin_name = path.filename().u8string();
    request.load_profile = {1, 0, profile, 0};
    for (unsigned shift = 0; shift < 64; shift += 8)
        request.load_profile.push_back(static_cast<std::uint8_t>(run_nonce >> shift));
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
    json& measurement)
{
    const auto wall_begin = steady_clock_t::now();
    const auto memory_before = process_memory_snapshot();
    const auto acquisition_begin = steady_clock_t::now();
    auto workspace = open_benchmark_workspace(path, profile);
    const auto acquisition_ns = nanoseconds_since(acquisition_begin);
    try {
        if (workspace->identity().binary_id() != expected_identity.binary_id() ||
            workspace->identity().content_hash() != expected_identity.content_hash() ||
            workspace->identity().load_profile_hash() != expected_identity.load_profile_hash() ||
            workspace->snapshot() || workspace->analysis_revision() != 0)
            throw fixture_error_t("warm reopen acquisition did not preserve the exact cold workspace identity");

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
            {"warm_latency_max_ns", value(analysis_metric_t::decompile_warm_latency_max_ns)}}}};
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

json cancellation_measurement(const std::filesystem::path& path)
{
    const auto runtime_before = aida::infra::taskflow_runtime::active_snapshot();
    const auto memory_before = process_memory_snapshot();
    auto workspace = open_benchmark_workspace(path, 7);
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

json concurrent_measurement(const std::filesystem::path& path)
{
    using job_handle_t = aida::infra::taskflow_runtime::job_handle_t;
    std::vector<std::shared_ptr<analysis_workspace_t>> workspaces;
    std::vector<job_handle_t> jobs;
    const auto runtime_before = aida::infra::taskflow_runtime::active_snapshot();
    const auto memory_before = process_memory_snapshot();
    const auto begin = steady_clock_t::now();
    try {
        for (std::uint8_t profile = 11; profile < 15; ++profile) {
            auto workspace = open_benchmark_workspace(path, profile);
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

}

int main(int argc, char** argv)
{
    std::shared_ptr<aida::analysis::analysis_workspace_t> workspace;
    try {
        if (argc == 4 && std::string_view(argv[1]) == "--validate-receipt")
            return validate_receipt_command(argv[2], std::filesystem::u8path(argv[3]));
        if (argc != 3)
            throw aida::analysis::test_fixture::fixture_error_t(
                "usage: analysis_benchmark_harness <deterministic_component|release_sla> <code-bearing supported static fixture>");
        const std::string benchmark_mode = argv[1];
        if (benchmark_mode != "deterministic_component" && benchmark_mode != "release_sla")
            throw aida::analysis::test_fixture::fixture_error_t("benchmark mode is unsupported");
        const bool release_sla = benchmark_mode == "release_sla";
        const std::filesystem::path path = std::filesystem::absolute(argv[2]);
        if (!std::filesystem::is_regular_file(path))
            throw aida::analysis::test_fixture::fixture_error_t("benchmark fixture does not exist");
        const auto fixture_size = std::filesystem::file_size(path);
        const auto fixture_zero_bytes = zero_bytes(path, fixture_size);
        const auto host = host_identity(path);
        const auto runtime_before = aida::infra::taskflow_runtime::active_snapshot();
        const auto cold_memory_before = process_memory_snapshot();
        json acquisition_metrics;
        const auto cold_begin = steady_clock_t::now();
        workspace = open_benchmark_workspace(path, 1, &acquisition_metrics);
        const auto image = workspace->normalized_image();
        if (!image)
            throw aida::analysis::test_fixture::fixture_error_t("benchmark fixture image metadata is unavailable");
        const auto code_bytes = executable_bytes(image);
        if (code_bytes == 0)
            throw aida::analysis::test_fixture::fixture_error_t(
                "benchmark fixture has no normalized executable bytes");
        if (release_sla) {
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
        analyze_workspace(workspace, 0);
        const auto analysis_ns = nanoseconds_since(analysis_begin);
        const auto cold_wall_ns = nanoseconds_since(cold_begin);
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
            cold_analysis_revision, cold_overlay_revision, cold_counts, warm_reopen);
        report["warm_reopen"] = std::move(warm_reopen);
        analysis_metrics_t interaction_metrics(workspace->generation());
        interaction_metrics.sample_process_memory();
        report["mcp"] = mcp_measurement(workspace, interaction_metrics);
        report["decompiler"] = decompiler_measurements(workspace, interaction_metrics);
        interaction_metrics.sample_process_memory();
        interaction_metrics.mark_finished();
        report["interaction_instrumentation"] =
            instrumentation_summary(interaction_metrics.snapshot());
        report["interaction_database_after"] =
            database_measurement(workspace->database()->snapshot());
        close_workspace(workspace, true);
        workspace.reset();
        workspace = open_benchmark_workspace(path, 2);
        const auto instrumented_memory_before = process_memory_snapshot();
        const auto instrumented_begin = steady_clock_t::now();
        auto instrumented = analyze_workspace_instrumented(workspace, 0);
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
            {"metrics", json::parse(instrumented_snapshot.to_json())},
            {"summary", instrumentation_summary(instrumented_snapshot)},
            {"memory_before", instrumented_memory_before},
            {"memory_after", process_memory_snapshot()},
            {"database", database_measurement(workspace->database()->snapshot())},
            {"counts", snapshot_counts(*published_snapshot, published_search)}};
        close_workspace(workspace, true);
        workspace.reset();
        report["concurrent_fairness"] = concurrent_measurement(path);
        report["cancellation"] = cancellation_measurement(path);
        report["fixture"]["file_version"] = file_version_identity(path);
        report["benchmark_contract"] = json{{"mode", benchmark_mode},
            {"claim_status", release_sla ? "measurement_candidate" : "development_only"},
            {"thresholds", aida::analysis::c03::benchmark_sla_thresholds()},
            {"receipt_validation_required", true}, {"target_execution_forbidden", true}};
        report["runtime_claim"] = "measurement_only";
        std::cout << report.dump(2) << '\n';
        return 0;
    } catch (const std::exception& error) {
        aida::analysis::c03_test::assertion_telemetry::record_exception(
            error.what());
        if (workspace) {
            try { close_workspace(workspace, true); } catch (...) {}
        }
        std::cerr << error.what() << '\n';
        return 1;
    }
}
