#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include "../analysis_workspace/workspace_fixture_builder.hpp"

#include "../../src/core/analysis/analysis_budget.hpp"
#include "../../src/core/analysis/mapped_window_cache.hpp"
#include "../../src/core/analysis/provider_snapshot.hpp"
#include "../../src/core/analysis/spill_provider.hpp"
#include "../../src/core/analysis/subrange_provider.hpp"
#include "../../src/core/analysis/workspace/analysis_metrics.hpp"
#include "../../src/core/analysis/workspace/compact_ir.hpp"
#include "../../src/core/analysis/workspace/workspace_identity.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <future>
#include <iostream>
#include <limits>
#include <memory>
#include <optional>
#include <process.h>
#include <set>
#include <string>
#include <thread>
#include <vector>

struct harness_log_t {
    using clock_t = std::chrono::steady_clock;
    static unsigned long pid() { return static_cast<unsigned long>(_getpid()); }
    static unsigned long tid() { return static_cast<unsigned long>(std::hash<std::thread::id>{}(std::this_thread::get_id())); }
    static std::uint64_t epoch_ms() { return std::chrono::duration_cast<std::chrono::milliseconds>(clock_t::now().time_since_epoch()).count(); }
    static void emit(const char* test, const char* phase, const char* status, std::uint64_t elapsed_ms, const std::string& detail = {}) {
        std::fprintf(stderr, "[C03-HARNESS] test=%s phase=%s status=%s elapsed=%llums pid=%lu tid=%lu errno=%d detail=%s\n",
            test, phase, status, static_cast<unsigned long long>(elapsed_ms), pid(), tid(), static_cast<int>(errno),
            detail.empty() ? "-" : detail.c_str());
        std::fflush(stderr);
    }
};

namespace {

using namespace aida::analysis;
using namespace aida::analysis::test_fixture;

void require(bool condition, const std::string& message) {
    if (!condition)
        throw fixture_error_t(message);
}

template <typename value_t>
value_t require_value(workspace_result_t<value_t> result, const std::string& message) {
    if (!result)
        throw fixture_error_t(message + ":" + result.error().stable_code() + ":" + result.error().message);
    return result.take_value();
}

void require_success(workspace_result_t<void> result, const std::string& message) {
    if (!result)
        throw fixture_error_t(message + ":" + result.error().stable_code() + ":" + result.error().message);
}

constexpr std::uint64_t kMiB = 1024ULL * 1024ULL;
constexpr std::uint64_t kGiB = 1024ULL * 1024ULL * 1024ULL;

std::string wide_to_utf8_test(const std::wstring& value) {
    if (value.empty())
        return {};
    const int required = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
        static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    if (required <= 0)
        return {};
    std::string result(static_cast<std::size_t>(required), '\0');
    WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
        static_cast<int>(value.size()), result.data(), required, nullptr, nullptr);
    return result;
}

std::set<std::string> temp_spill_files() {
    std::set<std::string> names;
    std::vector<wchar_t> directory(32768, L'\0');
    const DWORD length = GetTempPathW(static_cast<DWORD>(directory.size()), directory.data());
    if (length == 0 || length >= directory.size())
        throw fixture_error_t("unable to enumerate the temporary directory");
    const std::wstring pattern = std::wstring(directory.data()) + L"aid*";
    WIN32_FIND_DATAW data{};
    HANDLE search = FindFirstFileW(pattern.c_str(), &data);
    if (search == INVALID_HANDLE_VALUE)
        return names;
    do {
        if ((data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
            names.insert(wide_to_utf8_test(data.cFileName));
    } while (FindNextFileW(search, &data));
    FindClose(search);
    return names;
}

std::vector<std::uint8_t> dense_pe64(std::uint32_t instruction_count) {
    constexpr std::uint8_t pattern[] = {0x48, 0x89, 0xC8};
    const std::uint64_t code_bytes64 = static_cast<std::uint64_t>(instruction_count) * sizeof(pattern);
    require(code_bytes64 <= 64ULL * 1024ULL * 1024ULL, "dense fixture code span exceeds its bound");
    const std::uint32_t code_bytes = static_cast<std::uint32_t>(code_bytes64);
    const std::uint32_t code_raw = (code_bytes + 0x1FFU) & ~0x1FFU;
    std::vector<std::uint8_t> bytes(0x400 + code_raw, 0);
    IMAGE_DOS_HEADER dos{};
    dos.e_magic = IMAGE_DOS_SIGNATURE;
    dos.e_lfanew = 0x80;
    std::memcpy(bytes.data(), &dos, sizeof(dos));
    IMAGE_NT_HEADERS64 nt{};
    nt.Signature = IMAGE_NT_SIGNATURE;
    nt.FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
    nt.FileHeader.NumberOfSections = 1;
    nt.FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
    nt.FileHeader.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE;
    nt.OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    nt.OptionalHeader.AddressOfEntryPoint = 0x1000;
    nt.OptionalHeader.BaseOfCode = 0x1000;
    nt.OptionalHeader.ImageBase = 0x140000000ULL;
    nt.OptionalHeader.SectionAlignment = 0x1000;
    nt.OptionalHeader.FileAlignment = 0x200;
    nt.OptionalHeader.MajorOperatingSystemVersion = 10;
    nt.OptionalHeader.MajorSubsystemVersion = 10;
    nt.OptionalHeader.SizeOfImage = (0x1000U + code_bytes + 0xFFFU) & ~0xFFFU;
    nt.OptionalHeader.SizeOfHeaders = 0x200;
    nt.OptionalHeader.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_CUI;
    nt.OptionalHeader.DllCharacteristics = IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE |
        IMAGE_DLLCHARACTERISTICS_NX_COMPAT | IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA;
    nt.OptionalHeader.SizeOfStackReserve = 1ULL << 20;
    nt.OptionalHeader.SizeOfStackCommit = 4096;
    nt.OptionalHeader.SizeOfHeapReserve = 1ULL << 20;
    nt.OptionalHeader.SizeOfHeapCommit = 4096;
    nt.OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
    std::memcpy(bytes.data() + dos.e_lfanew, &nt, sizeof(nt));
    IMAGE_SECTION_HEADER section{};
    const char section_name[] = ".text";
    std::memcpy(section.Name, section_name, sizeof(section_name) - 1);
    section.Misc.VirtualSize = code_bytes;
    section.VirtualAddress = 0x1000;
    section.SizeOfRawData = code_raw;
    section.PointerToRawData = 0x400;
    section.Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
    const std::size_t section_offset = static_cast<std::size_t>(dos.e_lfanew) +
        sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER64);
    std::memcpy(bytes.data() + section_offset, &section, sizeof(section));
    for (std::uint32_t offset = 0; offset < code_bytes; offset += sizeof(pattern))
        std::memcpy(bytes.data() + 0x400 + offset, pattern, sizeof(pattern));
    return bytes;
}

void write_sparse_fixture(const std::filesystem::path& path,
                          const std::vector<std::uint8_t>& headers,
                          std::uint64_t total_size) {
    std::filesystem::create_directories(path.parent_path());
    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    stream.write(reinterpret_cast<const char*>(headers.data()),
                 static_cast<std::streamsize>(headers.size()));
    stream.seekp(static_cast<std::streamoff>(total_size - 1));
    stream.put('\0');
    stream.flush();
    if (!stream)
        throw fixture_error_t("unable to write sparse fixture");
    require(static_cast<std::uint64_t>(std::filesystem::file_size(path)) == total_size,
            "sparse fixture size diverged");
}

std::vector<std::uint8_t> large_pe64_headers(std::uint64_t total_size) {
    const std::uint64_t bulk = total_size - 0x400;
    std::vector<std::uint8_t> bytes(0x400, 0);
    IMAGE_DOS_HEADER dos{};
    dos.e_magic = IMAGE_DOS_SIGNATURE;
    dos.e_lfanew = 0x80;
    std::memcpy(bytes.data(), &dos, sizeof(dos));
    IMAGE_NT_HEADERS64 nt{};
    nt.Signature = IMAGE_NT_SIGNATURE;
    nt.FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
    nt.FileHeader.NumberOfSections = 2;
    nt.FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
    nt.FileHeader.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE;
    nt.OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    nt.OptionalHeader.AddressOfEntryPoint = 0x1000;
    nt.OptionalHeader.BaseOfCode = 0x1000;
    nt.OptionalHeader.ImageBase = 0x140000000ULL;
    nt.OptionalHeader.SectionAlignment = 0x1000;
    nt.OptionalHeader.FileAlignment = 0x200;
    nt.OptionalHeader.MajorOperatingSystemVersion = 10;
    nt.OptionalHeader.MajorSubsystemVersion = 10;
    nt.OptionalHeader.SizeOfImage = static_cast<std::uint32_t>(
        (0x2000ULL + bulk + 0xFFFULL) & ~0xFFFULL);
    nt.OptionalHeader.SizeOfHeaders = 0x200;
    nt.OptionalHeader.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_CUI;
    nt.OptionalHeader.DllCharacteristics = IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE |
        IMAGE_DLLCHARACTERISTICS_NX_COMPAT | IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA;
    nt.OptionalHeader.SizeOfStackReserve = 1ULL << 20;
    nt.OptionalHeader.SizeOfStackCommit = 4096;
    nt.OptionalHeader.SizeOfHeapReserve = 1ULL << 20;
    nt.OptionalHeader.SizeOfHeapCommit = 4096;
    nt.OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
    std::memcpy(bytes.data() + dos.e_lfanew, &nt, sizeof(nt));
    const std::size_t section_offset = static_cast<std::size_t>(dos.e_lfanew) +
        sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER64);
    IMAGE_SECTION_HEADER text{};
    const char text_name[] = ".text";
    std::memcpy(text.Name, text_name, sizeof(text_name) - 1);
    text.Misc.VirtualSize = 0x200;
    text.VirtualAddress = 0x1000;
    text.SizeOfRawData = 0x200;
    text.PointerToRawData = 0x200;
    text.Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
    std::memcpy(bytes.data() + section_offset, &text, sizeof(text));
    IMAGE_SECTION_HEADER rdata{};
    const char rdata_name[] = ".rdata";
    std::memcpy(rdata.Name, rdata_name, sizeof(rdata_name) - 1);
    rdata.Misc.VirtualSize = static_cast<std::uint32_t>(bulk);
    rdata.VirtualAddress = 0x2000;
    rdata.SizeOfRawData = static_cast<std::uint32_t>(bulk);
    rdata.PointerToRawData = 0x400;
    rdata.Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;
    std::memcpy(bytes.data() + section_offset + sizeof(IMAGE_SECTION_HEADER), &rdata, sizeof(rdata));
    const std::uint8_t code[] = {0x31, 0xC0, 0xC3, 0x90};
    std::memcpy(bytes.data() + text.PointerToRawData, code, sizeof(code));
    return bytes;
}

struct analysis_run_outcome_t {
    bool completed = false;
    std::string failing_call;
    workspace_error_t error{};
    std::shared_ptr<analysis_metrics_t> metrics;
};

struct relay_attach_guard_t {
    const analysis_metrics_t* metrics;
    explicit relay_attach_guard_t(analysis_metrics_t* attached) : metrics(attached) {
        provider_metrics_relay::attach_analysis_metrics(attached);
    }
    ~relay_attach_guard_t() { provider_metrics_relay::detach_analysis_metrics(metrics); }
};

analysis_run_outcome_t run_instrumented(const std::shared_ptr<analysis_workspace_t>& workspace,
                                        baseline_analysis_settings_t settings,
                                        bool attach_relay) {
    analysis_run_outcome_t outcome;
    auto created = pe_baseline_analyzer_t::create(workspace, settings, workspace->generation(),
        workspace->analysis_revision(), std::nullopt);
    if (!created) {
        outcome.failing_call = "create";
        outcome.error = created.error();
        return outcome;
    }
    auto analyzer = created.take_value();
    outcome.metrics = analyzer->metrics();
    std::optional<relay_attach_guard_t> relay_guard;
    if (attach_relay)
        relay_guard.emplace(analyzer->metrics().get());
    std::atomic<bool> runtime_cancelled{false};
    const auto run_phase = [&](const char* name, auto callable) -> bool {
        auto result = callable();
        if (!result) {
            outcome.failing_call = name;
            outcome.error = result.error();
            return false;
        }
        return true;
    };
    bool ok = run_phase("parse", [&] { return analyzer->parse_phase(runtime_cancelled); });
    ok = ok && run_phase("seed", [&] { return analyzer->seed_phase(runtime_cancelled); });
    ok = ok && run_phase("decode", [&] { return analyzer->decode_phase(runtime_cancelled); });
    ok = ok && run_phase("decode_merge", [&] { return analyzer->decode_merge_phase(runtime_cancelled); });
    ok = ok && run_phase("data_discovery", [&] { return analyzer->data_discovery_phase(runtime_cancelled); });
    ok = ok && run_phase("function_recovery", [&] { return analyzer->function_recovery_phase(runtime_cancelled); });
    ok = ok && run_phase("functions", [&] { return analyzer->functions_phase(runtime_cancelled); });
    ok = ok && run_phase("cfg_calls", [&] { return analyzer->cfg_calls_phase(runtime_cancelled); });
    ok = ok && run_phase("xrefs", [&] { return analyzer->xrefs_phase(runtime_cancelled); });
    ok = ok && run_phase("strings_data", [&] { return analyzer->strings_data_phase(runtime_cancelled); });
    ok = ok && run_phase("metadata_symbols_types", [&] { return analyzer->metadata_symbols_types_phase(runtime_cancelled); });
    ok = ok && run_phase("search_index", [&] { return analyzer->search_index_phase(runtime_cancelled); });
    ok = ok && run_phase("persistence_submit", [&] { return analyzer->persistence_submit_phase(runtime_cancelled); });
    ok = ok && run_phase("persistence_commit", [&] { return analyzer->persistence_commit_phase(runtime_cancelled); });
    ok = ok && run_phase("publish_ready", [&] { return analyzer->publish_ready_phase(runtime_cancelled); });
    outcome.completed = ok;
    return outcome;
}

struct snapshot_counts_t {
    std::uint64_t instructions = 0;
    std::uint64_t operand_facts = 0;
    std::uint64_t target_facts = 0;
    std::uint64_t edges = 0;
    std::uint64_t coverage = 0;
    std::uint64_t xrefs = 0;
    std::uint64_t strings = 0;
};

baseline_analysis_settings_t scaled_settings(const snapshot_counts_t& counts,
                                             std::uint64_t budget_bytes) {
    const auto scaled = [](std::uint64_t count) {
        return count + count / 8 + 4096;
    };
    baseline_analysis_settings_t settings;
    settings.max_analysis_memory_bytes = budget_bytes;
    settings.max_decoded_instructions = scaled(counts.instructions);
    settings.tile_decode_limits.maximum_instructions = scaled(counts.instructions);
    settings.tile_decode_limits.maximum_operand_facts = scaled(counts.operand_facts);
    settings.tile_decode_limits.maximum_target_facts = scaled(counts.target_facts);
    settings.tile_decode_limits.maximum_edges = scaled(counts.edges);
    settings.tile_decode_limits.maximum_coverage_spans = scaled(counts.coverage);
    settings.max_coverage_spans = scaled(counts.coverage);
    settings.xref_limits.max_xrefs = scaled(counts.xrefs);
    settings.max_strings = scaled(counts.strings);
    settings.function_limits.max_result_bytes = budget_bytes;
    settings.call_graph_limits.max_result_bytes = budget_bytes;
    settings.data_limits.max_result_bytes = budget_bytes;
    settings.xref_limits.max_result_bytes = budget_bytes;
    settings.string_limits.max_result_bytes = budget_bytes;
    settings.symbol_type_limits.max_result_bytes = budget_bytes;
    settings.search_limits.max_index_bytes = budget_bytes;
    return settings;
}

std::uint64_t budget_floor_bytes(const baseline_analysis_settings_t& settings) {
    const std::pair<std::uint64_t, std::uint64_t> products[] = {
        {settings.max_decoded_instructions, sizeof(instruction_record_t)},
        {settings.tile_decode_limits.maximum_instructions, sizeof(instruction_record_t)},
        {settings.tile_decode_limits.maximum_operand_facts, sizeof(operand_fact_t)},
        {settings.tile_decode_limits.maximum_target_facts, sizeof(target_fact_t)},
        {settings.tile_decode_limits.maximum_edges, sizeof(edge_record_t)},
        {settings.tile_decode_limits.maximum_coverage_spans, sizeof(coverage_span_t)},
        {settings.max_coverage_spans, sizeof(coverage_span_t)},
        {settings.xref_limits.max_xrefs, sizeof(xref_record_t)},
        {settings.max_strings, sizeof(string_record_t)}};
    std::uint64_t floor = 1;
    for (const auto& product : products) {
        std::uint64_t bytes = 0;
        if (!checked_mul_u64(product.first, product.second, bytes))
            throw fixture_error_t("budget floor computation overflowed");
        floor = (std::max)(floor, bytes);
    }
    return floor;
}

std::uint64_t full_walk_bytes(const analysis_snapshot_t& snapshot) {
    std::uint64_t total = sizeof(snapshot);
    const auto add = [&total](std::uint64_t count, std::uint64_t size) {
        std::uint64_t bytes = 0;
        if (!checked_mul_u64(count, size, bytes) || !checked_add_u64(total, bytes, total))
            throw fixture_error_t("independent memory walk overflowed");
    };
    const std::pair<std::uint64_t, std::uint64_t> allocations[] = {
        {snapshot.instructions.capacity(), sizeof(instruction_record_t)},
        {snapshot.delay_slot_counts.capacity(), sizeof(std::uint8_t)},
        {snapshot.operand_facts.hot.capacity(), sizeof(operand_fact_hot_t)},
        {snapshot.operand_facts.cold.capacity(), sizeof(operand_fact_cold_t)},
        {snapshot.target_facts.capacity(), sizeof(target_fact_t)},
        {snapshot.blocks.capacity(), sizeof(basic_block_record_t)},
        {snapshot.function_chunks.capacity(), sizeof(function_chunk_record_t)},
        {snapshot.function_block_memberships.capacity(), sizeof(function_block_membership_record_t)},
        {snapshot.functions.capacity(), sizeof(function_record_t)},
        {snapshot.edges.capacity(), sizeof(edge_record_t)},
        {snapshot.call_graph.nodes.capacity(), sizeof(call_graph_node_record_t)},
        {snapshot.call_graph.call_sites.capacity(), sizeof(recovered_call_site_t)},
        {snapshot.call_graph.candidates.capacity(), sizeof(recovered_call_candidate_t)},
        {snapshot.call_graph.edges.capacity(), sizeof(call_graph_edge_record_t)},
        {snapshot.call_graph.conflicts.capacity(), sizeof(call_graph_conflict_t)},
        {snapshot.xrefs.capacity(), sizeof(xref_record_t)},
        {snapshot.strings.capacity(), sizeof(string_record_t)},
        {snapshot.symbols.capacity(), sizeof(symbol_record_t)},
        {snapshot.rich_facts.data_candidates.capacity(), sizeof(data_candidate_record_t)},
        {snapshot.rich_facts.data_pointer_facts.capacity(), sizeof(data_pointer_fact_t)},
        {snapshot.rich_facts.data_conflicts.capacity(), sizeof(data_candidate_conflict_t)},
        {snapshot.rich_facts.type_candidates.capacity(), sizeof(symbol_type_candidate_record_t)},
        {snapshot.rich_facts.type_references.capacity(), sizeof(type_reference_fact_t)},
        {snapshot.rich_facts.metadata_conflicts.capacity(), sizeof(metadata_conflict_record_t)},
        {snapshot.coverage.capacity(), sizeof(coverage_span_t)}};
    for (const auto& allocation : allocations)
        add(allocation.first, allocation.second);
    for (const auto& string : snapshot.strings)
        add(string.value.capacity(), 1);
    for (const auto& symbol : snapshot.symbols)
        add(symbol.name.capacity(), 1);
    for (const auto& function : snapshot.functions)
        add(function.chunks.capacity(), sizeof(address_range_t));
    for (const auto& type : snapshot.rich_facts.type_candidates) {
        add(type.display_name.capacity(), 1);
        add(type.canonical_type.capacity(), 1);
        add(type.source_key.capacity(), 1);
    }
    for (const auto& reference : snapshot.rich_facts.type_references)
        add(reference.source_key.capacity(), 1);
    for (const auto& conflict : snapshot.rich_facts.metadata_conflicts) {
        add(conflict.identity.capacity(), 1);
        add(conflict.selected_value.capacity(), 1);
        add(conflict.rejected_value.capacity(), 1);
    }
    return total;
}

int gate_order_index(const std::string& phase) {
    static const char* order[] = {"decode_merge", "data_discovery", "function_recovery",
        "functions", "cfg_calls", "xrefs", "strings_data", "metadata_symbols_types", "search_index"};
    for (int index = 0; index < 9; ++index) {
        if (phase == order[index])
            return index;
    }
    return -1;
}

class mutable_identity_double_t final : public byte_provider_t {
public:
    explicit mutable_identity_double_t(std::shared_ptr<const byte_provider_t> parent)
        : parent_(std::move(parent)), identity_(parent_->identity()) {}

    const byte_provider_identity_t& identity() const noexcept override { return identity_; }
    std::uint64_t size() const noexcept override { return parent_->size(); }
    std::uint64_t maximum_contiguous_lease(std::uint64_t offset) const noexcept override {
        return parent_->maximum_contiguous_lease(offset);
    }
    workspace_result_t<byte_view_t> lease(
        std::uint64_t offset, std::uint64_t size,
        const cancellation_token_t& cancel = {}) const override {
        auto result = parent_->lease(offset, size, cancel);
        if (result && !changed_) {
            identity_.last_write_time_100ns ^= 1ULL;
            changed_ = true;
        }
        return result;
    }

private:
    std::shared_ptr<const byte_provider_t> parent_;
    mutable byte_provider_identity_t identity_;
    mutable bool changed_ = false;
};

class cancel_after_read_provider_t final : public byte_provider_t {
public:
    cancel_after_read_provider_t(std::shared_ptr<const byte_provider_t> parent,
                                 cancellation_source_t& cancellation)
        : parent_(std::move(parent)), cancellation_(cancellation),
          identity_(parent_->identity()) {}

    const byte_provider_identity_t& identity() const noexcept override { return identity_; }
    std::uint64_t size() const noexcept override { return parent_->size(); }
    std::uint64_t maximum_contiguous_lease(std::uint64_t offset) const noexcept override {
        return parent_->maximum_contiguous_lease(offset);
    }
    workspace_result_t<byte_view_t> lease(
        std::uint64_t offset, std::uint64_t size,
        const cancellation_token_t& cancel = {}) const override {
        auto result = parent_->lease(offset, size, cancel);
        if (result && !cancelled_) {
            cancelled_ = true;
            cancellation_.request_cancel();
        }
        return result;
    }

private:
    std::shared_ptr<const byte_provider_t> parent_;
    cancellation_source_t& cancellation_;
    byte_provider_identity_t identity_;
    mutable bool cancelled_ = false;
};

void verify_pin_identity_single_pass(const std::filesystem::path& root) {
    const auto path = root / "pin" / "fixture.exe";
    write_bytes_fixture(path, minimal_pe64(0x41));
    auto provider = require_value(mapped_file_provider_t::open(path.u8string()),
                                  "pinned provider open failed");
    require(provider->identity().immutable_snapshot,
            "pinned provider did not advertise an immutable snapshot identity");
    require(provider->identity().content_sha256.has_value(),
            "pinned provider lost its content identity");
    require(provider->content_pin_active(), "pinned provider did not report an active content pin");
    const auto independent = require_value(sha256_provider(*provider),
                                           "independent provider hash failed");
    require(independent == *provider->identity().content_sha256,
            "pinned open-time digest diverged from an independent full-file hash");
    const auto statistics = provider->window_cache_statistics();
    require(statistics.has_value(), "mapped provider did not forward window cache statistics");
    require(statistics->capacity_bytes >= 256ULL * kMiB &&
                statistics->capacity_bytes <= 1ULL * kGiB,
            "resolved cache capacity is outside its fail-closed envelope");
    auto captured = require_value(provider_snapshot_t::capture(provider),
                                  "pinned snapshot capture failed");
    require(captured->identity().content_sha256 &&
                *captured->identity().content_sha256 == independent,
            "captured pinned snapshot content identity diverged");
    require(!captured->metrics().materialized,
            "pinned capture was misclassified as a materialization");
    require(!captured->metrics().hash_recomputed,
            "pinned capture recomputed a hash it should have reused");
    require(captured->metrics().bytes == provider->size() &&
                captured->metrics().elapsed_ns > 0,
            "pinned capture metrics are incomplete");
    mapped_file_provider_options_t legacy_options;
    legacy_options.pin_local_file_snapshot = false;
    auto legacy = require_value(mapped_file_provider_t::open(path.u8string(), legacy_options),
                                "legacy provider open failed");
    require(!legacy->identity().immutable_snapshot,
            "pin escape hatch did not restore the legacy mutable identity");
    require(!legacy->content_pin_active(),
            "pin escape hatch still reported an active content pin");
    auto materialized = require_value(provider_snapshot_t::materialize(legacy),
                                      "legacy materialization failed");
    require(materialized->metrics().materialized &&
                materialized->metrics().bytes == legacy->size() &&
                materialized->metrics().hash_bytes == legacy->size(),
            "legacy materialization metrics are incomplete");
    require(materialized->identity().content_sha256 &&
                *materialized->identity().content_sha256 == independent,
            "legacy materialized snapshot digest diverged from the pinned digest");
    require(materialized->source() &&
                std::dynamic_pointer_cast<const spill_provider_t>(materialized->source()),
            "legacy materialization did not route through the spill provider");
}

void verify_pin_hold_sharing_violation(const std::filesystem::path& root) {
    const auto first_path = root / "pinhold" / "first.exe";
    const auto second_path = root / "pinhold" / "second.exe";
    write_bytes_fixture(first_path, minimal_pe64(0x51));
    write_bytes_fixture(second_path, minimal_pe64(0x52));
    const auto first_bytes = minimal_pe64(0x51);
    std::optional<sha256_digest_t> first_digest;
    {
        auto provider = require_value(mapped_file_provider_t::open(first_path.u8string()),
                                      "pin-hold provider open failed");
        first_digest = *provider->identity().content_sha256;
        const auto wide_first = std::wstring(first_path.wstring());
        const auto wide_second = std::wstring(second_path.wstring());
        const BOOL replaced = MoveFileExW(wide_second.c_str(), wide_first.c_str(),
                                          MOVEFILE_REPLACE_EXISTING);
        require(!replaced, "OS pin did not deny a replace while the provider was open");
        const DWORD status = GetLastError();
        require(status == ERROR_SHARING_VIOLATION || status == ERROR_ACCESS_DENIED ||
                    status == ERROR_LOCK_VIOLATION,
                "replace rejection was not a sharing violation: " + std::to_string(status));
        std::vector<std::uint8_t> readback(16);
        require_success(provider->read_exact(0, readback.data(), readback.size()),
                        "pinned provider readback failed after the rejected replace");
        require(std::equal(readback.begin(), readback.end(), first_bytes.begin()),
                "pinned provider content changed after the rejected replace");
    }
    const BOOL replaced = MoveFileExW(second_path.wstring().c_str(), first_path.wstring().c_str(),
                                      MOVEFILE_REPLACE_EXISTING);
    require(replaced, "replace failed after the provider released its pin");
    auto reopened = require_value(mapped_file_provider_t::open(first_path.u8string()),
                                  "reopened provider open failed");
    require(reopened->identity().content_sha256 &&
            *reopened->identity().content_sha256 != *first_digest,
            "reopened provider did not observe the replaced content identity");
}

void verify_mutable_identity_double(const std::filesystem::path& root) {
    const auto path = root / "double" / "fixture.exe";
    write_bytes_fixture(path, minimal_pe64(0x61));
    auto provider = require_value(mapped_file_provider_t::open(path.u8string()),
                                  "double parent provider open failed");
    auto pinned_double = std::make_shared<mutable_identity_double_t>(provider);
    auto capture_result = provider_snapshot_t::capture(pinned_double);
    require(!capture_result &&
                capture_result.error().code == workspace_error_code_t::file_changed,
            "mutable identity double was not fail-closed at snapshot capture");
    auto workspace = open_workspace(path, "double-fixture.exe");
    try {
        auto binding_double = std::make_shared<mutable_identity_double_t>(
            workspace->provider_handle());
        auto created = analysis_workspace_t::create(workspace->identity_handle(),
            binding_double, workspace->image());
        require(!created && created.error().code == workspace_error_code_t::file_changed,
                "mutable identity double was not fail-closed at provider binding");
        close_workspace(workspace, true);
    } catch (...) {
        try { close_workspace(workspace, true); } catch (...) {}
        throw;
    }
    mapped_file_provider_options_t legacy_options;
    legacy_options.pin_local_file_snapshot = false;
    auto legacy = require_value(mapped_file_provider_t::open(path.u8string(), legacy_options),
                                "legacy double parent open failed");
    auto legacy_double = std::make_shared<mutable_identity_double_t>(legacy);
    auto materialized = provider_snapshot_t::materialize(legacy_double);
    require(!materialized && materialized.error().code == workspace_error_code_t::file_changed,
            "legacy materialization did not detect the mutable identity mid-stream");
}

void verify_capture_recompute_and_spill(const std::filesystem::path& root) {
    const auto path = root / "recompute" / "fixture.bin";
    std::vector<std::uint8_t> bytes(2ULL * kMiB + 977ULL);
    for (std::size_t index = 0; index < bytes.size(); ++index)
        bytes[index] = static_cast<std::uint8_t>((index * 53U + 7U) & 0xFFU);
    write_bytes_fixture(path, bytes);
    const auto expected = require_value(sha256_bytes(bytes.data(), bytes.size()),
                                        "recompute fixture hashing failed");
    mapped_file_provider_options_t legacy_options;
    legacy_options.pin_local_file_snapshot = false;
    auto legacy = require_value(mapped_file_provider_t::open(path.u8string(), legacy_options),
                                "recompute legacy provider open failed");
    class stamped_wrapper_t final : public byte_provider_t {
    public:
        stamped_wrapper_t(std::shared_ptr<const byte_provider_t> parent, sha256_digest_t digest)
            : parent_(std::move(parent)) {
            identity_ = parent_->identity();
            identity_.immutable_snapshot = true;
            identity_.content_sha256 = digest;
        }
        const byte_provider_identity_t& identity() const noexcept override { return identity_; }
        std::uint64_t size() const noexcept override { return parent_->size(); }
        std::uint64_t maximum_contiguous_lease(std::uint64_t offset) const noexcept override {
            return parent_->maximum_contiguous_lease(offset);
        }
        workspace_result_t<byte_view_t> lease(
            std::uint64_t offset, std::uint64_t size,
            const cancellation_token_t& cancel = {}) const override {
            return parent_->lease(offset, size, cancel);
        }
    private:
        std::shared_ptr<const byte_provider_t> parent_;
        byte_provider_identity_t identity_;
    };
    auto stamped = std::make_shared<stamped_wrapper_t>(legacy, expected);
    auto captured = require_value(provider_snapshot_t::capture(stamped),
                                  "non-pinned stamped capture failed");
    require(captured->metrics().hash_recomputed,
            "non-pinned capture skipped its legacy hash recomputation");
    require(captured->identity().content_sha256 &&
                *captured->identity().content_sha256 == expected,
            "non-pinned capture digest diverged");
    provider_snapshot_options_t materialize_options;
    materialize_options.max_materialized_bytes = 8ULL * kMiB;
    materialize_options.copy_chunk_bytes = 512ULL * 1024ULL;
    auto materialized = require_value(provider_snapshot_t::materialize(legacy, materialize_options),
                                      "pipelined materialization failed");
    require(materialized->metrics().materialized &&
                materialized->metrics().bytes == bytes.size() &&
                materialized->metrics().hash_bytes == bytes.size() &&
                materialized->metrics().hash_ns > 0,
            "pipelined materialization metrics are incomplete");
    require(materialized->identity().content_sha256 &&
                *materialized->identity().content_sha256 == expected,
            "pipelined materialization digest diverged from the sequential digest construction");
    require_success(materialized->verify_content(), "pipelined materialization verification failed");
    cancellation_source_t cancellation;
    auto cancelling = std::make_shared<cancel_after_read_provider_t>(legacy, cancellation);
    auto cancelled = provider_snapshot_t::materialize(cancelling, materialize_options,
                                                      cancellation.token());
    require(!cancelled &&
                (cancelled.error().code == workspace_error_code_t::cancelled ||
                 cancelled.error().code == workspace_error_code_t::deadline_exceeded),
            "in-flight materialization cancellation did not propagate its stop code");
}

void verify_spill_relay_counters(const std::filesystem::path& root) {
    static_cast<void>(root);
    analysis_metrics_t metrics(1);
    relay_attach_guard_t relay_guard(&metrics);
    std::vector<std::uint8_t> bytes(3ULL * kMiB);
    for (std::size_t index = 0; index < bytes.size(); ++index)
        bytes[index] = static_cast<std::uint8_t>((index * 29U + 11U) & 0xFFU);
    spill_provider_options_t options;
    options.max_spill_bytes = 8ULL * kMiB;
    options.write_chunk_bytes = 256ULL * 1024ULL;
    auto sink = require_value(spill_sink_t::create("relay-spill", options),
                              "relay spill sink creation failed");
    require_success(sink->append(bytes.data(), bytes.size()), "relay spill append failed");
    auto provider = require_value(sink->finalize(), "relay spill finalization failed");
    auto view = require_value(provider->lease(0, 4096), "relay spill lease failed");
    static_cast<void>(view);
    auto snapshot = metrics.snapshot();
    require(snapshot.value(analysis_metric_t::spill_bytes_written) == bytes.size(),
            "spill write counter diverged");
    require(snapshot.value(analysis_metric_t::spill_bytes_peak) == bytes.size(),
            "spill high-water counter diverged");
    require(snapshot.value(analysis_metric_t::spill_bytes_read) == 4096,
            "spill read counter diverged");
    require(snapshot.value(analysis_metric_t::memory_pressure_events) == 1,
            "spill activation did not record a pressure event");
    provider.reset();
    sink.reset();
    spill_provider_options_t quota_options;
    quota_options.max_spill_bytes = 1024;
    quota_options.write_chunk_bytes = 512;
    auto quota_sink = require_value(spill_sink_t::create("relay-quota", quota_options),
                                    "relay quota sink creation failed");
    const std::array<std::uint8_t, 2048> oversized{};
    auto quota = quota_sink->append(oversized.data(), oversized.size());
    require(!quota && quota.error().code == workspace_error_code_t::limit_exceeded,
            "spill quota overrun was not fail-closed");
    snapshot = metrics.snapshot();
    require(snapshot.value(analysis_metric_t::budget_rejections) == 1,
            "spill quota rejection did not record a budget rejection");
    mapped_file_provider_options_t provider_options;
    provider_options.pin_local_file_snapshot = false;
    const auto fixture_path = std::filesystem::temp_directory_path() /
        ("aida_provider_budget_reject_" + std::to_string(GetCurrentProcessId()) + ".bin");
    write_bytes_fixture(fixture_path, bytes);
    auto mapped = require_value(mapped_file_provider_t::open(fixture_path.u8string(),
                                                             provider_options),
                                "rejection fixture provider open failed");
    provider_snapshot_options_t materialize_options;
    materialize_options.max_materialized_bytes = 1ULL * kMiB;
    materialize_options.copy_chunk_bytes = 256ULL * 1024ULL;
    auto rejected = provider_snapshot_t::materialize(mapped, materialize_options);
    require(!rejected && rejected.error().code == workspace_error_code_t::limit_exceeded,
            "materialization capacity overrun was not fail-closed");
    snapshot = metrics.snapshot();
    require(snapshot.value(analysis_metric_t::budget_rejections) == 2,
            "materialization rejection did not record a budget rejection");
    mapped.reset();
    std::error_code ignored;
    std::filesystem::remove(fixture_path, ignored);
}

void verify_auto_resolution_boundaries(const std::filesystem::path& root) {
    const auto headers = large_pe64_headers(320ULL * kMiB);
    const auto check = [&](std::uint64_t size, std::uint64_t expected_window,
                           std::uint64_t expected_capacity, const char* label) {
        const auto path = root / "resolution" / (std::string(label) + ".bin");
        write_sparse_fixture(path, headers, size);
        mapped_window_cache_options_t options;
        options.window_bytes = 0;
        options.max_cached_window_bytes = 0;
        options.max_lease_bytes = 64ULL * kMiB;
        options.immutable_source = true;
        {
            auto cache = require_value(mapped_window_cache_t::open(path.u8string(), options),
                                       std::string("auto-resolution cache open failed: ") + label);
            const auto statistics = cache->statistics();
            require(statistics.capacity_bytes == expected_capacity,
                    std::string("auto cache capacity diverged: ") + label);
            require(cache->maximum_contiguous_lease(0) == expected_window,
                    std::string("auto window size diverged: ") + label);
            require_success(cache->trim(), std::string("auto-resolution trim failed: ") + label);
        }
        std::error_code ignored;
        std::filesystem::remove(path, ignored);
    };
    check(63ULL * kMiB, 4ULL * kMiB, 256ULL * kMiB, "below-medium");
    check(64ULL * kMiB, 8ULL * kMiB, 256ULL * kMiB, "at-medium");
    check(255ULL * kMiB, 8ULL * kMiB, 256ULL * kMiB, "below-large");
    check(256ULL * kMiB, 16ULL * kMiB, 256ULL * kMiB, "at-large");
    check(300ULL * kMiB, 16ULL * kMiB, 304ULL * kMiB, "typical");
    check(2ULL * kGiB, 16ULL * kMiB, 1ULL * kGiB, "at-ceiling");
    const auto explicit_path = root / "resolution" / "explicit.bin";
    write_sparse_fixture(explicit_path, headers, 300ULL * kMiB);
    mapped_window_cache_options_t explicit_options;
    explicit_options.window_bytes = 4ULL * kMiB;
    explicit_options.max_lease_bytes = 4ULL * kMiB;
    explicit_options.max_cached_window_bytes = 256ULL * kMiB;
    explicit_options.shard_count = 16;
    {
        auto explicit_cache = require_value(
            mapped_window_cache_t::open(explicit_path.u8string(), explicit_options),
            "explicit cache open failed");
        require(explicit_cache->statistics().capacity_bytes == 256ULL * kMiB &&
                    explicit_cache->maximum_contiguous_lease(0) == 4ULL * kMiB,
                "explicit cache options were not preserved verbatim");
        require_success(explicit_cache->trim(), "explicit cache trim failed");
    }
    std::error_code ignored;
    std::filesystem::remove(explicit_path, ignored);
}

void verify_concurrency_stress(const std::filesystem::path& root) {
    const auto path = root / "stress" / "large.exe";
    const std::uint64_t file_size = 300ULL * kMiB;
    write_sparse_fixture(path, large_pe64_headers(file_size), file_size);
    mapped_window_cache_options_t options;
    options.window_bytes = 0;
    options.max_cached_window_bytes = 512ULL * kMiB;
    options.max_lease_bytes = 64ULL * kMiB;
    options.immutable_source = true;
    auto cache = require_value(mapped_window_cache_t::open(path.u8string(), options),
                               "stress cache open failed");
    require(cache->maximum_contiguous_lease(0) == 16ULL * kMiB,
            "stress cache did not resolve to 16 MiB windows");
    const std::uint64_t window = cache->maximum_contiguous_lease(0);
    for (std::uint64_t offset = 0; offset < file_size; offset += window)
        require_value(cache->lease(offset, 1), "warmup lease failed");
    constexpr std::uint32_t kWorkers = 32;
    constexpr std::uint32_t kIterations = 512;
    std::atomic<bool> start{false};
    std::atomic<std::uint32_t> ready{0};
    std::atomic<std::uint32_t> failures{0};
    std::atomic<std::uint32_t> limit_rejections{0};
    std::array<std::vector<std::uint64_t>, kWorkers> latencies;
    std::array<std::thread, kWorkers> workers;
    for (std::uint32_t index = 0; index < kWorkers; ++index) {
        workers[index] = std::thread([&, index]() {
            latencies[index].reserve(kIterations);
            std::uint64_t state = 0x9E3779B97F4A7C15ULL ^ (index + 1);
            ready.fetch_add(1, std::memory_order_release);
            while (!start.load(std::memory_order_acquire))
                std::this_thread::yield();
            for (std::uint32_t iteration = 0; iteration < kIterations; ++iteration) {
                state ^= state << 13U;
                state ^= state >> 7U;
                state ^= state << 17U;
                const std::uint64_t window_start = (state % (file_size / window)) * window;
                const std::uint64_t delta = (state / window) % (window - kMiB);
                const auto began = std::chrono::steady_clock::now();
                auto view = cache->lease(window_start + delta, kMiB);
                const auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(
                    std::chrono::steady_clock::now() - began).count();
                if (!view) {
                    failures.fetch_add(1, std::memory_order_relaxed);
                    if (view.error().code == workspace_error_code_t::limit_exceeded)
                        limit_rejections.fetch_add(1, std::memory_order_relaxed);
                    continue;
                }
                if (!view.value().data() || view.value().size() != kMiB)
                    failures.fetch_add(1, std::memory_order_relaxed);
                latencies[index].push_back(static_cast<std::uint64_t>(elapsed));
            }
        });
    }
    while (ready.load(std::memory_order_acquire) != kWorkers)
        std::this_thread::yield();
    start.store(true, std::memory_order_release);
    for (auto& worker : workers)
        worker.join();
    require(failures.load() == 0, "stress lease sweep recorded a lease failure");
    require(limit_rejections.load() == 0,
            "stress lease sweep recorded a spurious capacity rejection");
    std::vector<std::uint64_t> merged;
    for (const auto& samples : latencies)
        merged.insert(merged.end(), samples.begin(), samples.end());
    require(!merged.empty(), "stress lease sweep recorded no samples");
    std::sort(merged.begin(), merged.end());
    const std::uint64_t p50 = merged[merged.size() / 2];
    const std::uint64_t p99 = merged[(std::min)(merged.size() - 1,
        (merged.size() * 99ULL) / 100ULL)];
    const std::uint64_t latency_floor = (std::max)(p50, 1000ULL);
    require(p99 < 2 * latency_floor,
            "stress lease p99 exceeded twice the median: p50=" + std::to_string(p50) +
                " p99=" + std::to_string(p99));
    const auto statistics = cache->statistics();
    require(statistics.lease_count >= kWorkers * kIterations,
            "stress lease counter diverged");
    require(statistics.map_calls != 0, "stress map counter diverged");
    require(statistics.cached_window_bytes <= statistics.capacity_bytes,
            "stress cache exceeded its resolved capacity");
    require(statistics.capacity_bytes == 512ULL * kMiB,
            "stress cache capacity diverged from its explicit bound");
    require_success(cache->trim(), "stress cache trim failed");
}

void verify_eviction_smoke(const std::filesystem::path& root) {
    const auto path = root / "eviction" / "large.exe";
    const std::uint64_t file_size = 300ULL * kMiB;
    write_sparse_fixture(path, large_pe64_headers(file_size), file_size);
    auto future = std::async(std::launch::async, [&]() -> std::string {
        mapped_window_cache_options_t options;
        options.window_bytes = 16ULL * kMiB;
        options.max_lease_bytes = 16ULL * kMiB;
        options.max_cached_window_bytes = 64ULL * kMiB;
        options.immutable_source = true;
        auto cache = mapped_window_cache_t::open(path.u8string(), options);
        if (!cache)
            return "eviction cache open failed";
        const std::uint64_t window = 16ULL * kMiB;
        for (std::uint64_t offset = 0; offset < file_size; offset += window) {
            auto view = cache.value()->lease(offset, 1);
            if (!view)
                return "eviction sweep lease failed: " + view.error().message;
        }
        const auto statistics = cache.value()->statistics();
        if (statistics.evictions == 0)
            return "eviction sweep recorded no evictions";
        if (statistics.admission_steals == 0)
            return "eviction sweep recorded no cross-shard steals";
        if (statistics.cached_window_bytes > statistics.capacity_bytes)
            return "eviction sweep exceeded its cache capacity";
        auto trimmed = cache.value()->trim();
        if (!trimmed)
            return "eviction cache trim failed";
        return {};
    });
    require(future.wait_for(std::chrono::seconds(120)) == std::future_status::ready,
            "eviction smoke watchdog fired: possible deadlock");
    const auto failure = future.get();
    require(failure.empty(), failure);
}

void verify_global_cap_exhaustion(const std::filesystem::path& root) {
    const auto first_path = root / "globalcap" / "first.bin";
    const auto second_path = root / "globalcap" / "second.bin";
    const auto third_path = root / "globalcap" / "third.bin";
    const std::uint64_t file_size = 1ULL * kGiB + 64ULL * kMiB;
    const auto headers = large_pe64_headers(file_size);
    write_sparse_fixture(first_path, headers, file_size);
    write_sparse_fixture(second_path, headers, file_size);
    write_sparse_fixture(third_path, headers, file_size);
    analysis_metrics_t metrics(1);
    relay_attach_guard_t relay_guard(&metrics);
    mapped_window_cache_options_t options;
    options.window_bytes = 16ULL * kMiB;
    options.max_lease_bytes = 16ULL * kMiB;
    options.max_cached_window_bytes = 1ULL * kGiB;
    options.immutable_source = true;
    std::vector<byte_view_t> pinned;
    std::optional<workspace_error_t> exhaustion;
    {
        auto first = require_value(mapped_window_cache_t::open(first_path.u8string(), options),
                                   "first global-cap cache open failed");
        auto second = require_value(mapped_window_cache_t::open(second_path.u8string(), options),
                                    "second global-cap cache open failed");
        for (std::uint64_t offset = 0; offset < 1ULL * kGiB; offset += options.window_bytes) {
            pinned.emplace_back(require_value(first->lease(offset, 1),
                                              "first global-cap pin failed"));
        }
        for (std::uint64_t offset = 0; offset < 1ULL * kGiB; offset += options.window_bytes) {
            pinned.emplace_back(require_value(second->lease(offset, 1),
                                              "second global-cap pin failed"));
        }
        auto third = require_value(mapped_window_cache_t::open(third_path.u8string(), options),
                                   "third global-cap cache open failed");
        auto blocked = third->lease(0, 1);
        require(!blocked && blocked.error().code == workspace_error_code_t::limit_exceeded,
                "third global-cap cache admission was not fail-closed");
        require(blocked.error().message == "global mapped-window capacity is exhausted",
                "global exhaustion message diverged: " + blocked.error().message);
        exhaustion.emplace(blocked.error());
        const auto snapshot = metrics.snapshot();
        require(snapshot.value(analysis_metric_t::budget_rejections) >= 1,
                "global exhaustion did not record a budget rejection");
        require(snapshot.value(analysis_metric_t::mapped_window_bytes_global_peak) >= 2ULL * kGiB,
                "global mapped-window peak did not reach the fail-closed ceiling");
    }
    pinned.clear();
    const auto required_detail = exhaustion->details;
    require(!required_detail.empty(), "global exhaustion lost its counter details");
}

void verify_budget_validation_matrix() {
    require_success(baseline_analysis_settings_t{}.validate(),
                    "default analysis settings did not pass validation");
    const auto base_settings = [] {
        baseline_analysis_settings_t settings;
        settings.max_analysis_memory_bytes = 64ULL * kMiB;
        settings.max_decoded_instructions = 65536;
        settings.tile_decode_limits.maximum_instructions = 65536;
        settings.tile_decode_limits.maximum_operand_facts = 65536;
        settings.tile_decode_limits.maximum_target_facts = 65536;
        settings.tile_decode_limits.maximum_edges = 65536;
        settings.tile_decode_limits.maximum_coverage_spans = 65536;
        settings.max_coverage_spans = 65536;
        settings.xref_limits.max_xrefs = 65536;
        settings.max_strings = 65536;
        settings.function_limits.max_result_bytes = 32ULL * kMiB;
        settings.call_graph_limits.max_result_bytes = 32ULL * kMiB;
        settings.data_limits.max_result_bytes = 32ULL * kMiB;
        settings.xref_limits.max_result_bytes = 32ULL * kMiB;
        settings.string_limits.max_result_bytes = 32ULL * kMiB;
        settings.symbol_type_limits.max_result_bytes = 32ULL * kMiB;
        settings.search_limits.max_index_bytes = 32ULL * kMiB;
        return settings;
    };
    require_success(base_settings().validate(),
                    "scaled validation-matrix base settings did not pass validation");
    const auto expect_rejection = [&](const char* field, auto mutator) {
        baseline_analysis_settings_t settings = base_settings();
        mutator(settings);
        auto result = settings.validate();
        if (result)
            throw fixture_error_t(std::string("validation accepted a violated cap: ") + field);
        if (result.error().code != workspace_error_code_t::invalid_argument)
            throw fixture_error_t(std::string("validation returned the wrong code for: ") + field);
        bool named = false;
        for (const auto& detail : result.error().details)
            named = named || (detail.first == "field" && detail.second == field);
        if (!named)
            throw fixture_error_t(std::string("validation did not name the failing field: ") + field);
    };
    expect_rejection("max_decoded_instructions", [](baseline_analysis_settings_t& settings) {
        settings.max_decoded_instructions = (64ULL * kMiB / sizeof(instruction_record_t)) + 1024;
    });
    expect_rejection("tile_decode_limits.maximum_instructions",
                     [](baseline_analysis_settings_t& settings) {
        settings.tile_decode_limits.maximum_instructions =
            (64ULL * kMiB / sizeof(instruction_record_t)) + 1024;
    });
    expect_rejection("tile_decode_limits.maximum_operand_facts",
                     [](baseline_analysis_settings_t& settings) {
        settings.tile_decode_limits.maximum_operand_facts =
            (64ULL * kMiB / sizeof(operand_fact_t)) + 1024;
    });
    expect_rejection("tile_decode_limits.maximum_target_facts",
                     [](baseline_analysis_settings_t& settings) {
        settings.tile_decode_limits.maximum_target_facts =
            (64ULL * kMiB / sizeof(target_fact_t)) + 1024;
    });
    expect_rejection("tile_decode_limits.maximum_edges",
                     [](baseline_analysis_settings_t& settings) {
        settings.tile_decode_limits.maximum_edges = (64ULL * kMiB / sizeof(edge_record_t)) + 1024;
    });
    expect_rejection("tile_decode_limits.maximum_coverage_spans",
                     [](baseline_analysis_settings_t& settings) {
        settings.tile_decode_limits.maximum_coverage_spans =
            (64ULL * kMiB / sizeof(coverage_span_t)) + 1024;
    });
    expect_rejection("max_coverage_spans", [](baseline_analysis_settings_t& settings) {
        settings.max_coverage_spans = (64ULL * kMiB / sizeof(coverage_span_t)) + 1024;
    });
    expect_rejection("xref_limits.max_xrefs", [](baseline_analysis_settings_t& settings) {
        settings.xref_limits.max_xrefs = (64ULL * kMiB / sizeof(xref_record_t)) + 1024;
    });
    expect_rejection("max_strings", [](baseline_analysis_settings_t& settings) {
        settings.max_strings = (64ULL * kMiB / sizeof(string_record_t)) + 1024;
    });
}

void verify_budget_gates_sweep(const std::filesystem::path& root) {
    const auto path = root / "budget" / "dense.exe";
    write_bytes_fixture(path, dense_pe64(200000));
    snapshot_counts_t counts;
    std::uint64_t final_accounted = 0;
    {
        auto workspace = open_workspace(path, "dense-fixture.exe");
        try {
            install_services(workspace);
            auto outcome = run_instrumented(workspace, baseline_analysis_settings_t{}, false);
            require(outcome.completed,
                    "reference dense analysis failed: " + outcome.error.message);
            const auto snapshot = workspace->snapshot();
            require(snapshot && snapshot->baseline_complete,
                    "reference dense analysis did not publish a complete snapshot");
            counts.instructions = snapshot->instructions.size();
            counts.operand_facts = snapshot->operand_facts.size();
            counts.target_facts = snapshot->target_facts.size();
            counts.edges = snapshot->edges.size();
            counts.coverage = snapshot->coverage.size();
            counts.xrefs = snapshot->xrefs.size();
            counts.strings = snapshot->strings.size();
            final_accounted = require_value(snapshot_memory_accounted_bytes(*snapshot),
                                            "reference accounted-bytes computation failed");
            close_workspace(workspace, true);
        } catch (...) {
            try { close_workspace(workspace, true); } catch (...) {}
            throw;
        }
    }
    require(counts.instructions != 0 && counts.operand_facts != 0,
            "dense reference fixture produced no decode facts");
    const std::uint64_t floor = budget_floor_bytes(scaled_settings(counts, 0));
    const std::uint64_t success_budget = final_accounted + 16ULL * kMiB;
    struct observation_t {
        std::uint64_t budget;
        int gate_index;
    };
    std::vector<observation_t> observations;
    std::uint64_t budget = floor;
    bool completed = false;
    for (std::uint32_t run = 0; run < 16 && !completed; ++run) {
        auto settings = scaled_settings(counts, budget);
        require_success(settings.validate(),
                        "scaled settings did not pass validation at budget " +
                            std::to_string(budget));
        auto workspace = open_workspace(path, "dense-fixture.exe");
        try {
            install_services(workspace);
            auto outcome = run_instrumented(workspace, settings, false);
            close_workspace(workspace, true);
            if (outcome.completed) {
                completed = true;
                continue;
            }
            require(outcome.error.code == workspace_error_code_t::limit_exceeded,
                    "budget gate failure was not fail-closed limit_exceeded: " +
                        outcome.error.message);
            const int gate_index = gate_order_index(outcome.error.phase);
            require(gate_index >= 0,
                    "budget failure carried a non-gate phase string: " + outcome.error.phase);
            observations.push_back({budget, gate_index});
        } catch (...) {
            try { close_workspace(workspace, true); } catch (...) {}
            throw;
        }
        budget = (std::max)(budget + budget / 2, budget + 1);
        if (budget > success_budget)
            budget = success_budget;
    }
    require(completed, "budget sweep never reached a passing analysis");
    require(!observations.empty(), "budget sweep recorded no gate failures");
    require(observations.front().gate_index == 0,
            "the tightest budget did not trip the decode_merge gate first: tripped gate " +
                std::to_string(observations.front().gate_index));
    for (std::size_t index = 1; index < observations.size(); ++index)
        require(observations[index].gate_index >= observations[index - 1].gate_index,
                "budget gate failures were not monotone in canonical gate order");
}

void verify_ledger_parity(const std::filesystem::path& root) {
    const auto path = write_bytes_fixture(root / "ledger" / "fixture.exe",
                                          analysis_contract_pe64(0x67));
    auto workspace = open_workspace(path, "ledger-fixture.exe");
    try {
        install_services(workspace);
        analyze_workspace(workspace, 2);
        const auto snapshot = workspace->snapshot();
        require(snapshot && snapshot->baseline_complete,
                "ledger parity baseline did not publish a complete snapshot");
        const std::uint64_t accounted = require_value(
            snapshot_memory_accounted_bytes(*snapshot),
            "ledger parity accounted-bytes computation failed");
        const std::uint64_t walked = full_walk_bytes(*snapshot);
        require(accounted == walked,
                "budget ledger diverged from the independent full walk: accounted=" +
                    std::to_string(accounted) + " walked=" + std::to_string(walked));
        close_workspace(workspace, true);
    } catch (...) {
        try { close_workspace(workspace, true); } catch (...) {}
        throw;
    }
}

void verify_regression_surfaces(const std::filesystem::path& root) {
    const auto path = write_bytes_fixture(root / "regression" / "fixture.exe",
                                          analysis_contract_pe64(0x68));
    const auto measure = [&](std::uint32_t lanes) {
        auto workspace = open_workspace(path, "regression-fixture.exe");
        struct counts_t {
            std::size_t instructions = 0;
            std::size_t xrefs = 0;
            std::size_t strings = 0;
            sha256_digest_t provider_hash{};
            binary_id_t binary_id{};
        } counts;
        try {
            install_services(workspace);
            analyze_workspace(workspace, lanes);
            const auto snapshot = workspace->snapshot();
            require(snapshot, "regression baseline did not publish a snapshot");
            counts.instructions = snapshot->instructions.size();
            counts.xrefs = snapshot->xrefs.size();
            counts.strings = snapshot->strings.size();
            counts.provider_hash = workspace->identity().content_hash();
            counts.binary_id = workspace->identity().binary_id();
            const auto publication = workspace->analysis_publication();
            require(publication && publication->provider,
                    "regression publication provider is unavailable");
            const auto mapped = std::dynamic_pointer_cast<const mapped_file_provider_t>(
                publication->provider);
            require(mapped && mapped->content_pin_active(),
                    "baseline publication provider is not the pinned mapped provider");
            const auto independent = require_value(
                sha256_provider(*publication->provider), "regression provider rehash failed");
            require(independent == counts.provider_hash,
                    "bound provider hash diverged from an independent recompute");
            close_workspace(workspace, true);
        } catch (...) {
            try { close_workspace(workspace, true); } catch (...) {}
            throw;
        }
        return counts;
    };
    const auto serial = measure(1);
    const auto parallel = measure(2);
    require(serial.instructions == parallel.instructions && serial.instructions != 0 &&
                serial.xrefs == parallel.xrefs && serial.strings == parallel.strings,
            "baseline analysis signatures changed with worker lanes");
    require(serial.provider_hash == parallel.provider_hash,
            "persisted provider hash changed across runs");
    require(serial.binary_id == parallel.binary_id,
            "load-profile identity changed across identical reopens");
    auto reopened = open_workspace(path, "regression-fixture.exe");
    try {
        require(reopened->identity().content_hash() == serial.provider_hash,
                "reopened workspace provider hash diverged");
        require(reopened->identity().binary_id() == serial.binary_id,
                "reopened workspace binary identity diverged");
        close_workspace(reopened, true);
    } catch (...) {
        try { close_workspace(reopened, true); } catch (...) {}
        throw;
    }
}

void verify_memory_ceiling_300mb(const std::filesystem::path& root) {
    const auto path = root / "ceiling" / "large.exe";
    const std::uint64_t file_size = 300ULL * kMiB;
    write_sparse_fixture(path, large_pe64_headers(file_size), file_size);
    const auto temp_before = temp_spill_files();
    auto workspace = open_workspace(path, "ceiling-large.exe");
    struct sampler_guard_t {
        std::atomic<bool>& stop;
        std::thread worker;
        ~sampler_guard_t() {
            stop.store(true, std::memory_order_release);
            if (worker.joinable())
                worker.join();
        }
    };
    std::atomic<bool> sampler_stop{false};
    std::atomic<std::uint32_t> sampler_violations{0};
    try {
        install_services(workspace);
        const auto provider = workspace->provider_handle();
        require(provider, "ceiling provider handle is unavailable");
        const auto mapped = std::dynamic_pointer_cast<const mapped_file_provider_t>(provider);
        require(mapped && mapped->content_pin_active() &&
                    mapped->identity().immutable_snapshot &&
                    mapped->identity().content_sha256.has_value(),
                "ceiling provider is not the pinned zero-copy snapshot");
        sampler_guard_t sampler{sampler_stop};
        sampler.worker = std::thread([&]() {
            while (!sampler_stop.load(std::memory_order_acquire)) {
                const auto statistics = provider->window_cache_statistics();
                if (statistics &&
                    (statistics->cached_window_bytes > statistics->capacity_bytes ||
                     statistics->capacity_bytes > 1ULL * kGiB ||
                     statistics->global_admitted_window_bytes > 2ULL * kGiB))
                    sampler_violations.fetch_add(1, std::memory_order_relaxed);
                std::this_thread::sleep_for(std::chrono::milliseconds(2));
            }
        });
        baseline_analysis_settings_t settings;
        settings.decode_worker_lanes = 32;
        auto outcome = run_instrumented(workspace, settings, true);
        sampler_stop.store(true, std::memory_order_release);
        sampler.worker.join();
        require(outcome.completed,
                "300 MiB baseline did not complete: " + outcome.error.message);
        require(sampler_violations.load() == 0,
                "concurrent statistics sampler observed a capacity violation");
        const auto statistics = provider->window_cache_statistics();
        require(statistics.has_value(), "ceiling provider lost its window statistics");
        require(statistics->capacity_bytes == 304ULL * kMiB,
                "ceiling cache capacity diverged from round_up(300 MiB, 16 MiB): " +
                    std::to_string(statistics->capacity_bytes));
        require(statistics->cached_window_bytes <= statistics->capacity_bytes,
                "ceiling cache exceeded its resolved capacity");
        require(statistics->lease_count != 0, "ceiling lease counter diverged");
        const auto metrics = outcome.metrics->snapshot();
        require(metrics.value(analysis_metric_t::peak_private_bytes) <= 16ULL * kGiB,
                "peak private bytes exceeded the analysis budget");
        require(metrics.value(analysis_metric_t::mapped_window_bytes_peak) <= 1ULL * kGiB,
                "workspace mapped-window peak exceeded its fail-closed ceiling");
        require(metrics.value(analysis_metric_t::mapped_window_bytes_global_peak) <= 2ULL * kGiB,
                "global mapped-window peak exceeded its fail-closed ceiling");
        require(metrics.value(analysis_metric_t::spill_bytes_peak) == 0 &&
                    metrics.value(analysis_metric_t::spill_bytes_written) == 0,
                "local-file analysis recorded spill traffic");
        const auto json = metrics.to_json();
        require(json.find("\"mapped_window_bytes_peak\"") != std::string::npos &&
                    json.find("\"mapped_window_bytes_global_peak\"") != std::string::npos &&
                    json.find("\"spill_bytes_peak\"") != std::string::npos &&
                    json.find("\"budget_rejections\"") != std::string::npos &&
                    json.find("\"memory_pressure_events\"") != std::string::npos &&
                    json.find("\"resident_bytes_peak\"") != std::string::npos,
                "metrics JSON is missing memory-pressure counters");
        close_workspace(workspace, true);
    } catch (...) {
        sampler_stop.store(true, std::memory_order_release);
        try { close_workspace(workspace, true); } catch (...) {}
        throw;
    }
    const auto temp_after = temp_spill_files();
    require(temp_before == temp_after,
            "local-file 300 MiB analysis leaked a temporary spill artifact");
}

struct adaptive_budget_case_t {
    std::uint64_t total_phys;
    std::uint64_t usable_bytes;
    std::uint64_t max_analysis_memory_bytes;
    std::uint64_t packed_staging_memory_budget_bytes;
    std::uint64_t packed_generation_quota_bytes;
    std::uint64_t window_cache_per_file_bytes;
    std::uint64_t window_cache_global_bytes;
    std::uint64_t pdb_persistence_total_bytes;
    std::uint64_t reopen_range_budget_bytes;
    bool low_memory;
};

host_memory_envelope_t synthetic_memory_envelope(std::uint64_t total_phys) {
    host_memory_envelope_t envelope;
    envelope.total_phys = total_phys;
    envelope.avail_phys = total_phys;
    envelope.reserve_os_bytes = (std::min)(
        (std::max)(total_phys / 4ULL, 4ULL * kGiB), 16ULL * kGiB);
    envelope.usable_bytes = total_phys > envelope.reserve_os_bytes
        ? total_phys - envelope.reserve_os_bytes : 0;
    return envelope;
}

bool same_budget_fields(const adaptive_analysis_budget_fields_t& left,
                        const adaptive_analysis_budget_fields_t& right) {
    return left.max_analysis_memory_bytes == right.max_analysis_memory_bytes &&
        left.packed_staging_memory_budget_bytes == right.packed_staging_memory_budget_bytes &&
        left.packed_generation_quota_bytes == right.packed_generation_quota_bytes &&
        left.window_cache_per_file_bytes == right.window_cache_per_file_bytes &&
        left.window_cache_global_bytes == right.window_cache_global_bytes &&
        left.pdb_persistence_total_bytes == right.pdb_persistence_total_bytes &&
        left.reopen_range_budget_bytes == right.reopen_range_budget_bytes &&
        left.low_memory == right.low_memory;
}

void verify_adaptive_budget_formula() {
    static const adaptive_budget_case_t cases[] = {
        {4294967296ULL, 0ULL, 8589934592ULL, 536870912ULL, 8589934592ULL, 268435456ULL, 1073741824ULL, 268435456ULL, 1073741824ULL, true},
        {8589934592ULL, 4294967296ULL, 8589934592ULL, 536870912ULL, 8589934592ULL, 268435456ULL, 1073741824ULL, 268435456ULL, 1073741824ULL, true},
        {17179869184ULL, 12884901888ULL, 8589934592ULL, 805306368ULL, 8589934592ULL, 402653184ULL, 1073741824ULL, 402653184ULL, 1610612736ULL, true},
        {21474836480ULL, 16106127360ULL, 8589934592ULL, 1006632960ULL, 8589934592ULL, 503316480ULL, 1073741824ULL, 503316480ULL, 2013265920ULL, true},
        {25769803775ULL, 19327352832ULL, 9663676416ULL, 1207959552ULL, 9663676416ULL, 603979776ULL, 1207959552ULL, 603979776ULL, 2415919104ULL, true},
        {25769803776ULL, 19327352832ULL, 9663676416ULL, 1207959552ULL, 9663676416ULL, 603979776ULL, 1207959552ULL, 603979776ULL, 2415919104ULL, false},
        {34359738368ULL, 25769803776ULL, 12884901888ULL, 1610612736ULL, 12884901888ULL, 805306368ULL, 1610612736ULL, 805306368ULL, 3221225472ULL, false},
        {51539607552ULL, 38654705664ULL, 19327352832ULL, 2415919104ULL, 17179869184ULL, 1207959552ULL, 2415919104ULL, 1073741824ULL, 4831838208ULL, false},
        {68719476736ULL, 51539607552ULL, 25769803776ULL, 3221225472ULL, 17179869184ULL, 1610612736ULL, 3221225472ULL, 1073741824ULL, 6442450944ULL, false},
        {137438953472ULL, 120259084288ULL, 51539607552ULL, 4294967296ULL, 17179869184ULL, 2147483648ULL, 4294967296ULL, 1073741824ULL, 8589934592ULL, false}};
    for (const auto& test : cases) {
        const auto envelope = synthetic_memory_envelope(test.total_phys);
        require(envelope.usable_bytes == test.usable_bytes,
                "synthetic envelope usable bytes diverged from the reserve formula at total " +
                    std::to_string(test.total_phys));
        const auto first = adaptive_analysis_budget_fields(envelope);
        const auto second = adaptive_analysis_budget_fields(envelope);
        require(same_budget_fields(first, second),
                "adaptive budget fields are not deterministic at total " +
                    std::to_string(test.total_phys));
        require(first.max_analysis_memory_bytes == test.max_analysis_memory_bytes &&
                first.packed_staging_memory_budget_bytes == test.packed_staging_memory_budget_bytes &&
                first.packed_generation_quota_bytes == test.packed_generation_quota_bytes &&
                first.window_cache_per_file_bytes == test.window_cache_per_file_bytes &&
                first.window_cache_global_bytes == test.window_cache_global_bytes &&
                first.pdb_persistence_total_bytes == test.pdb_persistence_total_bytes &&
                first.reopen_range_budget_bytes == test.reopen_range_budget_bytes &&
                first.low_memory == test.low_memory,
                "adaptive budget row diverged at total " + std::to_string(test.total_phys) +
                    ": mam=" + std::to_string(first.max_analysis_memory_bytes) +
                    " staging=" + std::to_string(first.packed_staging_memory_budget_bytes) +
                    " quota=" + std::to_string(first.packed_generation_quota_bytes) +
                    " wpf=" + std::to_string(first.window_cache_per_file_bytes) +
                    " wg=" + std::to_string(first.window_cache_global_bytes) +
                    " pdb=" + std::to_string(first.pdb_persistence_total_bytes) +
                    " reopen=" + std::to_string(first.reopen_range_budget_bytes) +
                    " low=" + (first.low_memory ? std::string("true") : std::string("false")));
        require(first.max_analysis_memory_bytes >= 8ULL * kGiB &&
                first.max_analysis_memory_bytes <= 48ULL * kGiB &&
                first.packed_staging_memory_budget_bytes >= 512ULL * kMiB &&
                first.packed_staging_memory_budget_bytes <= 4ULL * kGiB &&
                first.packed_generation_quota_bytes >= 8ULL * kGiB &&
                first.packed_generation_quota_bytes <= 16ULL * kGiB &&
                first.window_cache_per_file_bytes >= 256ULL * kMiB &&
                first.window_cache_per_file_bytes <= 2ULL * kGiB &&
                first.window_cache_global_bytes >= 1ULL * kGiB &&
                first.window_cache_global_bytes <= 4ULL * kGiB &&
                first.pdb_persistence_total_bytes >= 256ULL * kMiB &&
                first.pdb_persistence_total_bytes <= 1ULL * kGiB &&
                first.reopen_range_budget_bytes >= 1ULL * kGiB &&
                first.reopen_range_budget_bytes <= 8ULL * kGiB,
                "adaptive budget fields escaped their clamp envelope at total " +
                    std::to_string(test.total_phys));
        require(first.window_cache_per_file_bytes <= first.window_cache_global_bytes,
                "per-file window cache exceeds the global window cache at total " +
                    std::to_string(test.total_phys));
    }
}

}

int main()
{
    const auto harness_start = harness_log_t::epoch_ms();
    harness_log_t::emit("workspace_provider_budget", "main", "enter", 0);
    const auto phase = [&](const char* name, auto callable) {
        harness_log_t::emit("workspace_provider_budget", name, "enter", 0);
        const auto began = harness_log_t::epoch_ms();
        callable();
        harness_log_t::emit("workspace_provider_budget", name, "pass",
                            harness_log_t::epoch_ms() - began);
    };
    try {
        fixture_root_t root("provider_budget");
        phase("pin_identity_single_pass", [&] { verify_pin_identity_single_pass(root.path()); });
        phase("pin_hold_sharing_violation", [&] { verify_pin_hold_sharing_violation(root.path()); });
        phase("mutable_identity_double", [&] { verify_mutable_identity_double(root.path()); });
        phase("capture_recompute_and_spill", [&] { verify_capture_recompute_and_spill(root.path()); });
        phase("spill_relay_counters", [&] { verify_spill_relay_counters(root.path()); });
        phase("auto_resolution_boundaries", [&] { verify_auto_resolution_boundaries(root.path()); });
        phase("concurrency_stress", [&] { verify_concurrency_stress(root.path()); });
        phase("eviction_smoke", [&] { verify_eviction_smoke(root.path()); });
        phase("global_cap_exhaustion", [&] { verify_global_cap_exhaustion(root.path()); });
        phase("budget_validation_matrix", [&] { verify_budget_validation_matrix(); });
        phase("adaptive_budget_formula", [&] { verify_adaptive_budget_formula(); });
        phase("budget_gates_sweep", [&] { verify_budget_gates_sweep(root.path()); });
        phase("ledger_parity", [&] { verify_ledger_parity(root.path()); });
        phase("regression_surfaces", [&] { verify_regression_surfaces(root.path()); });
        phase("memory_ceiling_300mb", [&] { verify_memory_ceiling_300mb(root.path()); });
        harness_log_t::emit("workspace_provider_budget", "main", "pass",
                            harness_log_t::epoch_ms() - harness_start);
        std::cout << "workspace_provider_budget_harness source contract satisfied\n";
        return 0;
    } catch (const std::exception& error) {
        const auto elapsed = harness_log_t::epoch_ms() - harness_start;
        harness_log_t::emit("workspace_provider_budget", "main", "fail", elapsed, error.what());
        std::cerr << error.what() << '\n';
        return 1;
    }
}
