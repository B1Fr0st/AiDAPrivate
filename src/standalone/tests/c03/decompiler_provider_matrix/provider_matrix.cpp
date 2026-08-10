#include "provider_matrix.hpp"

#include "../decompiler_quality_schema.hpp"
#include "../evidence_hash.hpp"
#include "../fixture_materializer.hpp"
#include "../../analysis_workspace/workspace_fixture_builder.hpp"

#include "core/analysis/decompiler/decompiler_ui_integration.hpp"
#include "core/analysis/decompiler/native_worker_host.hpp"
#include "core/analysis/decompiler/providers/ghidra_ir_adapter.hpp"
#include "core/analysis/decompiler/pseudocode_readability.hpp"
#include "core/analysis/collection/artifact_collection.hpp"
#include "core/analysis/subrange_provider.hpp"
#include "core/analysis/workspace/coff_image.hpp"
#include "core/analysis/workspace/ipa_container.hpp"
#include "core/disasm/ghidra_adapters/aida_arch_map.hpp"
#include "core/disasm/ghidra_adapters/aida_load_image.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <functional>
#include <future>
#include <iomanip>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

namespace aida::analysis::c03::provider_matrix {
namespace {

using clock_t = std::chrono::steady_clock;

constexpr std::size_t k_max_entities_per_fixture = 4096;
constexpr std::uint64_t k_max_json_bytes = 64ULL * 1024ULL * 1024ULL;
constexpr std::uint64_t k_max_artifact_bytes = 128ULL * 1024ULL * 1024ULL;
constexpr std::uint64_t k_max_result_bytes = 128ULL * 1024ULL * 1024ULL;
constexpr std::uint64_t k_max_provider_artifact_raw_bytes = 24ULL * 1024ULL * 1024ULL;
constexpr std::uint64_t k_max_provider_artifact_encoded_bytes = 48ULL * 1024ULL * 1024ULL;
constexpr std::uint64_t k_max_provider_structured_encoded_bytes = 24ULL * 1024ULL * 1024ULL;
constexpr std::uint64_t k_max_contract_text_bytes = 65536;
constexpr std::uint64_t k_max_run_diagnostic_items = 65536;
constexpr std::uint64_t k_max_run_diagnostic_encoded_bytes = 16ULL * 1024ULL * 1024ULL;
constexpr std::uint64_t k_max_cancellation_diagnostic_items = 1024;
constexpr std::uint64_t k_max_cancellation_diagnostic_encoded_bytes = 1024ULL * 1024ULL;
constexpr std::uint64_t k_max_fact_and_unknown_items = 65536;
constexpr std::uint64_t k_max_fact_and_unknown_encoded_bytes = 16ULL * 1024ULL * 1024ULL;
constexpr std::uint64_t k_max_confidence_properties = 65536;
constexpr std::uint64_t k_max_confidence_encoded_bytes = 16ULL * 1024ULL * 1024ULL;
constexpr std::uint64_t k_max_readability_nodes = 1ULL << 20;
constexpr std::uint64_t k_max_identity_file_bytes = 1024ULL * 1024ULL * 1024ULL;
constexpr std::uint64_t k_max_snapshot_bytes = 192ULL * 1024ULL * 1024ULL;
constexpr std::uint64_t k_cancellation_budget_ms = 250;
constexpr std::array<std::string_view, 10> k_fact_fields{
    "entities", "calls", "fields", "locals", "parameters", "cfg_edges",
    "control_structures", "exception_regions", "types", "source_coordinates"};
constexpr std::array<std::string_view, 10> k_metric_names{
    "typed_entities", "calls", "fields", "locals", "parameters", "cfg",
    "control_structures", "exception_regions", "type_correctness", "source_coordinates"};
constexpr std::string_view k_owned_fact_prefix = "aida-owned-v1:";

struct matrix_error_t final : std::runtime_error {
    using std::runtime_error::runtime_error;
};

struct matrix_not_applicable_t final : std::runtime_error {
    using std::runtime_error::runtime_error;
};

std::string bounded_contract_text(const std::string_view value, const char* field)
{
    if (value.empty() || value.size() > k_max_contract_text_bytes)
        throw matrix_error_t(std::string(field) + " violates the provider text bound");
    return std::string(value);
}

std::uint64_t checked_sum(const std::uint64_t left, const std::uint64_t right,
                          const char* message)
{
    if (right > (std::numeric_limits<std::uint64_t>::max)() - left)
        throw matrix_error_t(message);
    return left + right;
}

std::uint64_t encoded_string_upper(const std::string_view value)
{
    if (value.size() > ((std::numeric_limits<std::uint64_t>::max)() - 2ULL) / 6ULL)
        throw matrix_error_t("provider JSON string size overflowed");
    return static_cast<std::uint64_t>(value.size()) * 6ULL + 2ULL;
}

std::uint64_t tick_ns() noexcept
{
    const auto value = std::chrono::duration_cast<std::chrono::nanoseconds>(
        clock_t::now().time_since_epoch()).count();
    return value <= 0 ? 1ULL : static_cast<std::uint64_t>(value);
}

std::filesystem::path canonical_path(const std::filesystem::path& input)
{
    std::error_code error;
    auto absolute = std::filesystem::absolute(input, error);
    if (error)
        throw matrix_error_t("unable to resolve absolute path: " + error.message());
    auto normalized = std::filesystem::weakly_canonical(absolute, error);
    if (error)
        normalized = absolute.lexically_normal();
    return normalized;
}

json read_json(const std::filesystem::path& path)
{
    std::error_code error;
    const auto size = std::filesystem::file_size(path, error);
    if (error || size == 0 || size > k_max_json_bytes)
        throw matrix_error_t("JSON evidence is absent, empty, or oversized: " + path.u8string());
    std::ifstream stream(path, std::ios::binary);
    if (!stream)
        throw matrix_error_t("unable to open JSON evidence: " + path.u8string());
    std::string bytes(static_cast<std::size_t>(size), '\0');
    stream.read(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    if (!stream || stream.gcount() != static_cast<std::streamsize>(bytes.size()))
        throw matrix_error_t("unable to read complete JSON evidence: " + path.u8string());
    try {
        return json::parse(bytes, nullptr, true, false);
    } catch (const std::exception& error_value) {
        throw matrix_error_t("malformed JSON evidence " + path.u8string() + ": " + error_value.what());
    }
}

void write_json_atomic(const std::filesystem::path& path, const json& value)
{
    std::error_code error;
    std::filesystem::create_directories(path.parent_path(), error);
    if (error || !std::filesystem::is_directory(path.parent_path()))
        throw matrix_error_t("provider result output directory is unavailable");
    const auto temporary = path.parent_path() / (path.filename().u8string() + ".tmp");
    const auto bytes = value.dump() + "\n";
    if (bytes.size() > k_max_result_bytes)
        throw matrix_error_t("serialized provider evidence exceeds the 128 MiB result bound");
    {
        std::ofstream stream(temporary, std::ios::binary | std::ios::trunc);
        if (!stream)
            throw matrix_error_t("unable to create provider result temporary file");
        stream.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
        stream.flush();
        if (!stream)
            throw matrix_error_t("unable to write provider result temporary file");
    }
    if (!MoveFileExW(temporary.c_str(), path.c_str(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        const auto win32_error = GetLastError();
        std::filesystem::remove(temporary, error);
        throw matrix_error_t("unable to publish provider result: " + std::to_string(win32_error));
    }
}

std::filesystem::path executable_path()
{
    std::vector<wchar_t> buffer(32768);
    const auto length = GetModuleFileNameW(nullptr, buffer.data(),
        static_cast<DWORD>(buffer.size()));
    if (length == 0 || length >= buffer.size())
        throw matrix_error_t("unable to resolve provider-matrix executable identity");
    return canonical_path(std::filesystem::path(buffer.data(), buffer.data() + length));
}

std::string hash_file_or_empty(const std::filesystem::path& path, std::string& error)
{
    const auto hash = sha256_evidence_file(path, k_max_identity_file_bytes);
    if (!hash.ok) {
        if (!error.empty())
            error += "; ";
        error += path.u8string() + ": " + hash.error;
        return {};
    }
    return hash.sha256;
}

std::string hex_encode(const std::string& bytes)
{
    static constexpr std::array<char, 16> digits{
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    if (bytes.size() > (std::numeric_limits<std::size_t>::max)() / 2)
        throw matrix_error_t("artifact payload is too large to encode");
    std::string output(bytes.size() * 2, '\0');
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        const auto value = static_cast<unsigned char>(bytes[index]);
        output[index * 2] = digits[value >> 4];
        output[index * 2 + 1] = digits[value & 0x0f];
    }
    return output;
}

json artifact_json(const std::string& bytes)
{
    if (bytes.empty())
        throw matrix_error_t("measured artifact payload is empty");
    if (bytes.size() > k_max_artifact_bytes)
        throw matrix_error_t("measured artifact exceeds the 128 MiB evidence bound");
    const auto hash = sha256_evidence_bytes(bytes.data(), bytes.size());
    if (!hash.ok)
        throw matrix_error_t(hash.error);
    return json{{"encoding", "hex"}, {"sha256", hash.sha256},
        {"byte_size", static_cast<std::uint64_t>(bytes.size())},
        {"payload", hex_encode(bytes)}};
}

json null_artifacts()
{
    return json{{"provider_ir", nullptr}, {"hir", nullptr}, {"type_graph", nullptr},
        {"ast", nullptr}, {"document", nullptr}, {"printc", nullptr}};
}

class provider_evidence_budget_t final {
public:
    struct checkpoint_t final {
        std::uint64_t raw_bytes = 0;
        std::uint64_t encoded_bytes = 0;
        std::uint64_t structured_encoded_bytes = 0;
    };

    checkpoint_t checkpoint() const noexcept
    {
        return {raw_bytes_, encoded_bytes_, structured_encoded_bytes_};
    }

    void restore(const checkpoint_t& checkpoint) noexcept
    {
        raw_bytes_ = checkpoint.raw_bytes;
        encoded_bytes_ = checkpoint.encoded_bytes;
        structured_encoded_bytes_ = checkpoint.structured_encoded_bytes;
    }

    void charge_record(const std::size_t byte_size)
    {
        const auto framed = checked_add(static_cast<std::uint64_t>(byte_size), 8ULL,
            "framed provider evidence budget overflowed");
        const auto raw = checked_add(raw_bytes_, framed,
            "raw provider evidence budget overflowed");
        if (framed > (std::numeric_limits<std::uint64_t>::max)() / 2ULL)
            throw matrix_error_t("encoded provider evidence budget overflowed");
        const auto encoded = checked_add(encoded_bytes_, framed * 2ULL,
            "encoded provider evidence budget overflowed");
        if (raw > k_max_provider_artifact_raw_bytes ||
            encoded > k_max_provider_artifact_encoded_bytes)
            throw matrix_error_t("provider evidence exceeds its cumulative pre-encoding budget");
        raw_bytes_ = raw;
        encoded_bytes_ = encoded;
    }

    void charge_bundle()
    {
        const auto raw = checked_add(raw_bytes_, 36ULL,
            "raw provider evidence budget overflowed");
        const auto encoded = checked_add(encoded_bytes_, 72ULL,
            "encoded provider evidence budget overflowed");
        if (raw > k_max_provider_artifact_raw_bytes ||
            encoded > k_max_provider_artifact_encoded_bytes)
            throw matrix_error_t("provider evidence exceeds its cumulative pre-encoding budget");
        raw_bytes_ = raw;
        encoded_bytes_ = encoded;
    }

    void charge_structured(const std::uint64_t encoded_bytes)
    {
        const auto total = checked_add(structured_encoded_bytes_, encoded_bytes,
            "structured provider evidence budget overflowed");
        if (total > k_max_provider_structured_encoded_bytes)
            throw matrix_error_t(
                "provider structured evidence exceeds its cumulative pre-construction budget");
        structured_encoded_bytes_ = total;
    }

private:
    static std::uint64_t checked_add(const std::uint64_t left,
                                     const std::uint64_t right,
                                     const char* message)
    {
        if (right > (std::numeric_limits<std::uint64_t>::max)() - left)
            throw matrix_error_t(message);
        return left + right;
    }

    std::uint64_t raw_bytes_ = 0;
    std::uint64_t encoded_bytes_ = 0;
    std::uint64_t structured_encoded_bytes_ = 0;
};

class payload_bundle_t final {
public:
    explicit payload_bundle_t(provider_evidence_budget_t& budget)
        : budget_(&budget)
    {
        budget_->charge_bundle();
    }

    void append(std::string bytes)
    {
        if (bytes.empty())
            throw matrix_error_t("canonical stage serialization is empty");
        budget_->charge_record(bytes.size());
        records_.push_back(std::move(bytes));
    }

    bool empty() const noexcept { return records_.empty(); }

    std::string finish() const
    {
        if (records_.empty())
            return {};
        std::string output("AIDA-C03-CANONICAL-BUNDLE-V2", 28);
        append_u64(output, static_cast<std::uint64_t>(records_.size()));
        for (const auto& record : records_) {
            append_u64(output, static_cast<std::uint64_t>(record.size()));
            output.append(record);
        }
        return output;
    }

private:
    static void append_u64(std::string& output, const std::uint64_t value)
    {
        for (std::uint32_t shift = 0; shift < 64; shift += 8)
            output.push_back(static_cast<char>((value >> shift) & 0xffU));
    }

    std::vector<std::string> records_;
    provider_evidence_budget_t* budget_ = nullptr;
};

std::string severity_text(const decompiler_diagnostic_severity_t severity)
{
    switch (severity) {
    case decompiler_diagnostic_severity_t::note: return "info";
    case decompiler_diagnostic_severity_t::warning: return "warning";
    case decompiler_diagnostic_severity_t::error: return "error";
    }
    return "error";
}

void append_diagnostic_component(std::string& message,
                                 const std::string_view component)
{
    if (component.size() > k_max_contract_text_bytes ||
        message.size() >= k_max_contract_text_bytes ||
        component.size() > k_max_contract_text_bytes - message.size() - 1ULL)
        throw matrix_error_t("provider diagnostic source text exceeds its bound");
    message.push_back(' ');
    message.append(component.data(), component.size());
}

json diagnostic_json(const decompiler_diagnostic_t& diagnostic)
{
    std::string message = bounded_contract_text(diagnostic.localization_key.empty()
        ? std::string("decompiler.diagnostic") : diagnostic.localization_key,
        "decompiler diagnostic message");
    for (const auto& argument : diagnostic.localization_arguments)
        append_diagnostic_component(message, argument);
    return json{{"code", "decompiler:" +
            std::to_string(static_cast<std::uint16_t>(diagnostic.code))},
        {"message", std::move(message)}, {"severity", severity_text(diagnostic.severity)}};
}

json diagnostic_json(const decompiler_ui_diagnostic_t& diagnostic)
{
    auto message = diagnostic.message.empty()
        ? (diagnostic.localization_key.empty() ? std::string("decompiler.ui") : diagnostic.localization_key)
        : diagnostic.message;
    message = bounded_contract_text(std::move(message), "decompiler UI diagnostic message");
    return json{{"code", "decompiler:" +
            std::to_string(static_cast<std::uint16_t>(diagnostic.code))},
        {"message", std::move(message)}, {"severity", severity_text(diagnostic.severity)}};
}

json diagnostic_json(const native_worker::native_worker_diagnostic_t& diagnostic)
{
    auto message = bounded_contract_text(diagnostic.phase.empty()
        ? std::string("native_worker") : diagnostic.phase,
        "native worker diagnostic message");
    if (!diagnostic.detail.empty())
        append_diagnostic_component(message, diagnostic.detail);
    return json{{"code", "native_worker:" +
            std::to_string(static_cast<std::uint16_t>(diagnostic.code))},
        {"message", std::move(message)}, {"severity", "error"}};
}

enum class diagnostic_scope_t : std::uint8_t {
    run,
    cancellation
};

class diagnostic_accumulator_t final {
public:
    diagnostic_accumulator_t(provider_evidence_budget_t& provider_budget,
                             const diagnostic_scope_t scope)
        : provider_budget_(&provider_budget),
          max_items_(scope == diagnostic_scope_t::run
              ? k_max_run_diagnostic_items : k_max_cancellation_diagnostic_items),
          max_encoded_bytes_(scope == diagnostic_scope_t::run
              ? k_max_run_diagnostic_encoded_bytes
              : k_max_cancellation_diagnostic_encoded_bytes)
    {
        provider_budget_->charge_structured(2);
    }

    void append(json value)
    {
        if (!value.is_object() || value.size() != 3 ||
            !value.contains("code") || !value.at("code").is_string() ||
            !value.contains("message") || !value.at("message").is_string() ||
            !value.contains("severity") || !value.at("severity").is_string())
            throw matrix_error_t("provider diagnostic shape is invalid");
        const auto& code = value.at("code").get_ref<const std::string&>();
        const auto& message = value.at("message").get_ref<const std::string&>();
        const auto& severity = value.at("severity").get_ref<const std::string&>();
        if (code.empty() || code.size() > k_max_contract_text_bytes ||
            message.empty() || message.size() > k_max_contract_text_bytes ||
            (severity != "info" && severity != "warning" && severity != "error"))
            throw matrix_error_t("provider diagnostic text violates its contract");
        auto encoded = checked_sum(encoded_string_upper(code),
            encoded_string_upper(message), "provider diagnostic size overflowed");
        encoded = checked_sum(encoded, encoded_string_upper(severity),
            "provider diagnostic size overflowed");
        encoded = checked_sum(encoded, 40ULL,
            "provider diagnostic size overflowed");
        if (items_.size() >= max_items_ ||
            encoded > max_encoded_bytes_ - (std::min)(encoded_bytes_, max_encoded_bytes_))
            throw matrix_error_t("provider diagnostic evidence exceeds its cumulative bound");
        provider_budget_->charge_structured(encoded);
        encoded_bytes_ += encoded;
        items_.push_back(std::move(value));
    }

    json finish()
    {
        return std::move(items_);
    }

private:
    provider_evidence_budget_t* provider_budget_ = nullptr;
    std::uint64_t max_items_ = 0;
    std::uint64_t max_encoded_bytes_ = 0;
    std::uint64_t encoded_bytes_ = 0;
    json items_ = json::array();
};

std::string bounded_fact_text(const std::string_view value)
{
    if (value.size() > k_max_contract_text_bytes)
        throw matrix_error_t("provider fact source text exceeds its bound");
    return std::string(value);
}

std::string qualified_fact_text(const std::string_view owner,
                                const std::string_view name)
{
    if (owner.empty())
        return bounded_fact_text(name);
    const auto combined = checked_sum(static_cast<std::uint64_t>(owner.size()),
        static_cast<std::uint64_t>(name.size()),
        "provider qualified fact size overflowed");
    if (combined > k_max_contract_text_bytes - 2ULL)
        throw matrix_error_t("provider qualified fact exceeds its text bound");
    std::string output;
    output.reserve(static_cast<std::size_t>(combined + 2ULL));
    output.append(owner.data(), owner.size());
    output.append("::");
    output.append(name.data(), name.size());
    return output;
}

std::string owned_fact_text(const std::string_view owner,
                            const std::string_view value)
{
    if (owner.empty())
        return bounded_fact_text(value);
    const auto owner_length = std::to_string(owner.size());
    auto size = checked_sum(static_cast<std::uint64_t>(k_owned_fact_prefix.size()),
        static_cast<std::uint64_t>(owner_length.size()),
        "provider owned fact size overflowed");
    size = checked_sum(size, 1ULL, "provider owned fact size overflowed");
    size = checked_sum(size, static_cast<std::uint64_t>(owner.size()),
        "provider owned fact size overflowed");
    size = checked_sum(size, static_cast<std::uint64_t>(value.size()),
        "provider owned fact size overflowed");
    if (size > k_max_contract_text_bytes)
        throw matrix_error_t("provider owned fact exceeds its text bound");
    std::string output;
    output.reserve(static_cast<std::size_t>(size));
    output.append(k_owned_fact_prefix);
    output.append(owner_length);
    output.push_back(':');
    output.append(owner);
    output.append(value);
    return output;
}

std::string coordinate_fact(const source_coordinate_t& coordinate)
{
    std::ostringstream stream;
    if (coordinate.source_origin) {
        const auto& source = *coordinate.source_origin;
        if (source.source_path.size() > k_max_contract_text_bytes - 128ULL)
            throw matrix_error_t("provider source-coordinate path exceeds its text bound");
        stream << source.source_path << ':' << source.first_line << ':' << source.first_column
               << ':' << source.last_line << ':' << source.last_column;
        return bounded_fact_text(stream.str());
    }
    if (coordinate.address_range) {
        stream << "address:" << static_cast<unsigned>(coordinate.address_range->begin.space)
               << ":0x" << std::hex << coordinate.address_range->begin.value
               << "-0x" << coordinate.address_range->end.value;
        return bounded_fact_text(stream.str());
    }
    if (coordinate.instruction_range) {
        stream << "instruction:" << coordinate.instruction_range->first_instruction_id
               << '-' << coordinate.instruction_range->last_instruction_id;
        return bounded_fact_text(stream.str());
    }
    if (coordinate.document_range) {
        stream << "document:" << coordinate.document_range->begin
               << '-' << coordinate.document_range->end;
        return bounded_fact_text(stream.str());
    }
    return {};
}

std::string entity_fact(const decompiler_entity_key_t& entity)
{
    return std::visit([](const auto& identity) -> std::string {
        using identity_t = std::decay_t<decltype(identity)>;
        if constexpr (std::is_same_v<identity_t, native_decompiler_entity_identity_t>)
            return bounded_fact_text(identity.canonical_symbol);
        else if constexpr (std::is_same_v<identity_t, cli_decompiler_entity_identity_t>)
            return qualified_fact_text(identity.declaring_type, identity.method_name);
        else if constexpr (std::is_same_v<identity_t, jvm_decompiler_entity_identity_t>)
            return qualified_fact_text(identity.class_internal_name, identity.method_name);
        else
            return qualified_fact_text(identity.class_descriptor, identity.method_name);
    }, entity.identity);
}

class fact_accumulator_t final {
public:
    explicit fact_accumulator_t(provider_evidence_budget_t& provider_budget)
        : provider_budget_(&provider_budget)
    {
        provider_budget_->charge_structured(1024);
        for (const auto field : k_fact_fields)
            facts_.emplace(std::string(field),
                std::set<std::string, std::less<>>{});
        for (const auto metric : k_metric_names)
            unknowns_.emplace(std::string(metric),
                std::set<std::string, std::less<>>{});
    }

    void add(const std::string_view field, const std::string_view value,
             const double confidence)
    {
        if (value.empty())
            return;
        if (value.size() > k_max_contract_text_bytes || !std::isfinite(confidence))
            throw matrix_error_t("provider fact violates its text or confidence bound");
        const auto found = facts_.find(field);
        if (found == facts_.end())
            throw matrix_error_t("unknown provider fact field");
        if (found->second.find(value) == found->second.end()) {
            charge_fact_like(value);
            found->second.insert(std::string(value));
        }
        const auto bounded = (std::max)(0.0, (std::min)(1.0, confidence));
        const auto existing = confidence_.find(value);
        if (existing == confidence_.end()) {
            charge_confidence(value);
            confidence_.emplace(std::string(value), bounded);
        } else if (existing->second > bounded) {
            existing->second = bounded;
        }
    }

    void add_owned(const std::string_view field, const std::string_view owner,
                   const std::string_view value, const double confidence)
    {
        if (value.empty())
            return;
        add(field, owned_fact_text(owner, value), confidence);
    }

    void unavailable(const std::string_view stage, const std::string_view value)
    {
        append_unknown(value, decompiler_unknown_reason_t::provider_abstained,
            stage);
    }

    void coordinate(const std::string_view owner, const source_coordinate_t& value,
                    const double confidence = 1.0)
    {
        add_owned("source_coordinates", owner, coordinate_fact(value), confidence);
    }

    void provider_ir(const provider_ir_t& value)
    {
        const auto owner = entity_fact(value.entity);
        add("entities", owner, 1.0);
        for (const auto& coordinate_value : value.source_coordinates)
            coordinate(owner, coordinate_value);
        for (const auto& block : value.blocks) {
            coordinate(owner, block.coordinate);
            for (const auto successor : block.successor_ids)
                add_owned("cfg_edges", owner,
                    "block:" + std::to_string(block.id) + "->block:" +
                    std::to_string(successor), 1.0);
            for (const auto successor : block.exception_successor_ids) {
                add_owned("cfg_edges", owner,
                    "block:" + std::to_string(block.id) + "=>exception:" +
                    std::to_string(successor), 1.0);
                add_owned("exception_regions", owner,
                    "block:" + std::to_string(block.id) + "=>" +
                    std::to_string(successor), 1.0);
            }
            for (const auto& node : block.values) {
                const auto confidence = static_cast<double>(node.confidence) / 100.0;
                coordinate(owner, node.coordinate, confidence);
                if (node.opcode == provider_ir_opcode_t::call ||
                    node.opcode == provider_ir_opcode_t::indirect_call)
                    add_owned("calls", owner,
                        node.stable_symbol.empty() ? node.stable_immediate : node.stable_symbol,
                        confidence);
                if (node.opcode == provider_ir_opcode_t::field_load ||
                    node.opcode == provider_ir_opcode_t::field_store)
                    add_owned("fields", owner,
                        node.stable_symbol.empty() ? node.stable_immediate : node.stable_symbol,
                        confidence);
            }
        }
        append_unknowns(value.unknowns, "provider_ir");
    }

    void hir(const hir_function_t& value)
    {
        const auto owner = entity_fact(value.entity);
        for (const auto field : std::array<std::string_view, 4>{
                 "calls", "fields", "cfg_edges", "exception_regions"})
            erase_owned(field, owner);
        auto& signature_types = signature_type_ids_[owner];
        if (value.return_type_id != 0)
            signature_types.insert(value.return_type_id);
        add("entities", owner, 1.0);
        add_owned("types", owner, "arity:" + std::to_string(value.parameters.size()), 1.0);
        for (const auto& variable : value.parameters) {
            if (variable.type_id != 0)
                signature_types.insert(variable.type_id);
            add_owned("parameters", owner, variable.stable_name,
                static_cast<double>(variable.confidence) / 100.0);
            coordinate(owner, variable.coordinate,
                static_cast<double>(variable.confidence) / 100.0);
        }
        for (const auto& variable : value.locals) {
            add_owned("locals", owner, variable.stable_name,
                static_cast<double>(variable.confidence) / 100.0);
            coordinate(owner, variable.coordinate,
                static_cast<double>(variable.confidence) / 100.0);
        }
        for (const auto& coordinate_value : value.source_coordinates)
            coordinate(owner, coordinate_value);
        for (const auto& block : value.blocks) {
            const bool returns = std::any_of(block.values.begin(), block.values.end(),
                [](const hir_value_t& node) { return node.kind == hir_node_kind_t::return_value; });
            const bool throws = std::any_of(block.values.begin(), block.values.end(),
                [](const hir_value_t& node) { return node.kind == hir_node_kind_t::throw_value; });
            for (const auto successor : block.successor_ids)
                add_owned("cfg_edges", owner,
                    "block:" + std::to_string(block.id) + "->block:" +
                    std::to_string(successor), 1.0);
            for (const auto successor : block.exception_successor_ids) {
                add_owned("cfg_edges", owner,
                    "block:" + std::to_string(block.id) + "=>exception:" +
                    std::to_string(successor), 1.0);
                add_owned("exception_regions", owner,
                    "try:block:" + std::to_string(block.id) + "=>handler:block:" +
                    std::to_string(successor), 1.0);
            }
            if (block.successor_ids.empty() && returns)
                add_owned("cfg_edges", owner,
                    "block:" + std::to_string(block.id) + "->return", 1.0);
            else if (block.successor_ids.empty() && throws)
                add_owned("cfg_edges", owner,
                    "block:" + std::to_string(block.id) + "->exit", 1.0);
            for (const auto& node : block.values) {
                const auto confidence = static_cast<double>(node.confidence) / 100.0;
                coordinate(owner, node.coordinate, confidence);
                if (node.kind == hir_node_kind_t::call)
                    add_owned("calls", owner, node.stable_value, confidence);
                if (node.kind == hir_node_kind_t::field)
                    add_owned("fields", owner, node.stable_value, confidence);
            }
        }
        append_unknowns(value.unknowns, "hir");
    }

    void type_graph(const type_graph_t& value)
    {
        const auto owner = entity_fact(value.entity);
        auto reachable = signature_type_ids_[owner];
        bool changed = true;
        while (changed) {
            changed = false;
            for (const auto& edge : value.edges) {
                if (reachable.find(edge.source_type_id) != reachable.end() &&
                    reachable.insert(edge.target_type_id).second)
                    changed = true;
            }
        }
        for (const auto& node : value.nodes) {
            if (reachable.find(node.id) != reachable.end() &&
                node.kind != decompiler_type_kind_t::unknown)
                add_owned("types", owner,
                    node.canonical_name.empty() ? node.display_name : node.canonical_name,
                    static_cast<double>(node.confidence) / 100.0);
            for (const auto& coordinate_value : node.coordinates)
                coordinate(owner, coordinate_value,
                    static_cast<double>(node.confidence) / 100.0);
        }
        for (const auto& edge : value.edges) {
            if (edge.kind == decompiler_type_edge_kind_t::member)
                add_owned("fields", owner, edge.stable_name,
                    static_cast<double>(edge.confidence) / 100.0);
        }
        append_unknowns(value.unknowns, "type_graph");
    }

    void ast(const typed_pseudocode_ast_v2_t& value)
    {
        ast_seen_ = true;
        const auto owner = entity_fact(value.entity);
        std::map<std::uint64_t, const typed_pseudocode_ast_node_t*> nodes;
        for (const auto& node : value.nodes)
            nodes.emplace(node.id, &node);
        add("entities", owner, 1.0);
        for (const auto& coordinate_value : value.source_coordinates)
            coordinate(owner, coordinate_value);
        for (const auto& node : value.nodes) {
            const auto confidence = static_cast<double>(node.confidence) / 100.0;
            coordinate(owner, node.coordinate, confidence);
            switch (node.kind) {
            case typed_pseudocode_ast_node_kind_t::if_statement:
                add_owned("control_structures", owner, "if", confidence); break;
            case typed_pseudocode_ast_node_kind_t::else_clause:
                add_owned("control_structures", owner, "else", confidence); break;
            case typed_pseudocode_ast_node_kind_t::while_statement:
                add_owned("control_structures", owner, "while", confidence); break;
            case typed_pseudocode_ast_node_kind_t::do_while_statement:
                add_owned("control_structures", owner, "do_while", confidence); break;
            case typed_pseudocode_ast_node_kind_t::for_statement:
                add_owned("control_structures", owner, "for", confidence); break;
            case typed_pseudocode_ast_node_kind_t::switch_statement:
                add_owned("control_structures", owner, "switch", confidence); break;
            case typed_pseudocode_ast_node_kind_t::switch_case:
                add_owned("control_structures", owner, "case", confidence); break;
            case typed_pseudocode_ast_node_kind_t::break_statement:
                add_owned("control_structures", owner, "break", confidence); break;
            case typed_pseudocode_ast_node_kind_t::continue_statement:
                add_owned("control_structures", owner, "continue", confidence); break;
            case typed_pseudocode_ast_node_kind_t::return_statement:
                add_owned("control_structures", owner, "return", confidence); break;
            case typed_pseudocode_ast_node_kind_t::throw_statement:
                add_owned("control_structures", owner, "throw", confidence);
                add_owned("exception_regions", owner,
                    "throw:" + std::to_string(node.id), confidence); break;
            case typed_pseudocode_ast_node_kind_t::try_statement:
                add_owned("control_structures", owner, "try", confidence);
                add_owned("exception_regions", owner,
                    "try:" + std::to_string(node.id), confidence); break;
            case typed_pseudocode_ast_node_kind_t::catch_clause:
                add_owned("control_structures", owner, "catch", confidence);
                add_owned("exception_regions", owner,
                    "catch:" + std::to_string(node.id), confidence); break;
            case typed_pseudocode_ast_node_kind_t::finally_clause:
                add_owned("control_structures", owner, "finally", confidence);
                add_owned("exception_regions", owner,
                    "finally:" + std::to_string(node.id), confidence); break;
            case typed_pseudocode_ast_node_kind_t::call_expression:
                if (!node.child_ids.empty()) {
                    const auto callee = nodes.find(node.child_ids.front());
                    if (callee != nodes.end() &&
                        (callee->second->kind == typed_pseudocode_ast_node_kind_t::identifier ||
                         callee->second->kind == typed_pseudocode_ast_node_kind_t::member_expression))
                        add_owned("calls", owner, callee->second->stable_text, confidence);
                }
                break;
            case typed_pseudocode_ast_node_kind_t::member_expression:
                add_owned("fields", owner, node.stable_text, confidence); break;
            default:
                break;
            }
        }
        append_unknowns(value.unknowns, "ast");
    }

    void document(const decompiler_document_t& value)
    {
        if (!ast_seen_)
            ast(value.ast);
        const auto owner = entity_fact(value.entity);
        for (const auto& mapping : value.source_maps)
            for (const auto& coordinate_value : mapping.coordinates)
                coordinate(owner, coordinate_value);
        append_unknowns(value.unknowns, "document");
    }

    json facts_json() const
    {
        json output = json::object();
        for (const auto field : k_fact_fields) {
            output[std::string(field)] = json::array();
            const auto& values = facts_.at(std::string(field));
            for (const auto& value : values)
                output[std::string(field)].push_back(value);
        }
        return output;
    }

    json confidence_json() const
    {
        json output = json::object();
        for (const auto& [fact, confidence] : confidence_)
            output[fact] = confidence;
        return output;
    }

    json unknowns_json() const
    {
        json output = json::object();
        for (const auto metric : k_metric_names) {
            output[std::string(metric)] = json::array();
            for (const auto& unknown_value : unknowns_.at(std::string(metric)))
                output[std::string(metric)].push_back(unknown_value);
        }
        return output;
    }

private:
    void erase_owned(const std::string_view field, const std::string_view owner)
    {
        if (owner.empty())
            return;
        const auto prefix = owned_fact_text(owner, {});
        auto& values = facts_.at(std::string(field));
        for (auto iterator = values.begin(); iterator != values.end();) {
            if (iterator->size() >= prefix.size() &&
                iterator->compare(0, prefix.size(), prefix) == 0) {
                confidence_.erase(*iterator);
                iterator = values.erase(iterator);
            } else {
                ++iterator;
            }
        }
    }

    void charge_fact_like(const std::string_view value)
    {
        const auto encoded = checked_sum(encoded_string_upper(value), 1ULL,
            "provider fact size overflowed");
        if (fact_and_unknown_items_ >= k_max_fact_and_unknown_items ||
            encoded > k_max_fact_and_unknown_encoded_bytes -
                (std::min)(fact_and_unknown_encoded_bytes_,
                    k_max_fact_and_unknown_encoded_bytes))
            throw matrix_error_t("provider facts and explicit unknowns exceed their cumulative bound");
        provider_budget_->charge_structured(encoded);
        ++fact_and_unknown_items_;
        fact_and_unknown_encoded_bytes_ += encoded;
    }

    void charge_confidence(const std::string_view value)
    {
        const auto encoded = checked_sum(encoded_string_upper(value), 34ULL,
            "provider confidence size overflowed");
        if (confidence_.size() >= k_max_confidence_properties ||
            encoded > k_max_confidence_encoded_bytes -
                (std::min)(confidence_encoded_bytes_, k_max_confidence_encoded_bytes))
            throw matrix_error_t("provider confidence evidence exceeds its cumulative bound");
        provider_budget_->charge_structured(encoded);
        confidence_encoded_bytes_ += encoded;
    }

    static bool stage_affects(const std::string_view stage,
                              const std::string_view metric) noexcept
    {
        if (stage == "provider_ir")
            return metric == "typed_entities" || metric == "calls" ||
                metric == "fields" || metric == "cfg" ||
                metric == "control_structures" || metric == "exception_regions" ||
                metric == "type_correctness" || metric == "source_coordinates";
        if (stage == "hir")
            return true;
        if (stage == "type_graph")
            return metric == "fields" || metric == "locals" ||
                metric == "parameters" || metric == "type_correctness" ||
                metric == "source_coordinates";
        if (stage == "ast" || stage == "document")
            return metric == "typed_entities" || metric == "calls" ||
                metric == "fields" || metric == "control_structures" ||
                metric == "exception_regions" || metric == "type_correctness" ||
                metric == "source_coordinates";
        return false;
    }

    static bool reason_affects(const decompiler_unknown_reason_t reason,
                               const std::string_view metric) noexcept
    {
        switch (reason) {
        case decompiler_unknown_reason_t::unsupported_instruction:
            return metric == "calls" || metric == "fields" || metric == "locals" ||
                metric == "parameters" || metric == "cfg" ||
                metric == "control_structures" || metric == "exception_regions" ||
                metric == "type_correctness" || metric == "source_coordinates";
        case decompiler_unknown_reason_t::unsupported_metadata:
            return metric == "typed_entities" || metric == "fields" ||
                metric == "locals" || metric == "parameters" ||
                metric == "exception_regions" || metric == "type_correctness" ||
                metric == "source_coordinates";
        case decompiler_unknown_reason_t::unresolved_reference:
            return metric == "typed_entities" || metric == "calls" ||
                metric == "fields" || metric == "type_correctness";
        case decompiler_unknown_reason_t::opaque_control_flow:
            return metric == "cfg" || metric == "control_structures" ||
                metric == "exception_regions" || metric == "source_coordinates";
        case decompiler_unknown_reason_t::incomplete_debug_information:
            return metric == "type_correctness";
        case decompiler_unknown_reason_t::conflicting_type_evidence:
            return metric == "fields" || metric == "locals" ||
                metric == "parameters" || metric == "type_correctness";
        case decompiler_unknown_reason_t::bounded_analysis_limit:
        case decompiler_unknown_reason_t::semantic_timeout:
        case decompiler_unknown_reason_t::malformed_input:
        case decompiler_unknown_reason_t::provider_abstained:
            return true;
        }
        return true;
    }

    void append_unknown(const std::string_view value,
                        const decompiler_unknown_reason_t reason,
                        const std::string_view stage)
    {
        if (value.empty())
            return;
        if (value.size() > k_max_contract_text_bytes)
            throw matrix_error_t("provider explicit unknown exceeds its text bound");
        if (!unknown_origins_.emplace(std::string(value), reason).second)
            return;
        bool assigned = false;
        for (const auto metric : k_metric_names) {
            if (!stage_affects(stage, metric) || !reason_affects(reason, metric))
                continue;
            auto& values = unknowns_.at(std::string(metric));
            if (values.find(value) == values.end()) {
                charge_fact_like(value);
                values.insert(std::string(value));
            }
            assigned = true;
        }
        if (assigned)
            return;
        for (const auto metric : k_metric_names) {
            if (!stage_affects(stage, metric))
                continue;
            auto& values = unknowns_.at(std::string(metric));
            if (values.find(value) == values.end()) {
                charge_fact_like(value);
                values.insert(std::string(value));
            }
            assigned = true;
        }
        if (!assigned)
            throw matrix_error_t("provider explicit unknown has no metric domain");
    }

    void append_unknowns(const std::vector<decompiler_unknown_t>& values,
                         const std::string_view stage)
    {
        for (const auto& value : values) {
            if (!value.stable_token.empty())
                append_unknown(value.stable_token, value.reason, stage);
            else
                append_unknown("reason:" +
                    std::to_string(static_cast<std::uint8_t>(value.reason)),
                    value.reason, stage);
        }
    }

    provider_evidence_budget_t* provider_budget_ = nullptr;
    std::map<std::string, std::set<std::string, std::less<>>, std::less<>> facts_;
    std::map<std::string, double, std::less<>> confidence_;
    std::map<std::string, std::set<std::string, std::less<>>, std::less<>> unknowns_;
    std::map<std::string, decompiler_unknown_reason_t, std::less<>> unknown_origins_;
    std::map<std::string, std::set<std::uint64_t>, std::less<>> signature_type_ids_;
    std::uint64_t fact_and_unknown_items_ = 0;
    std::uint64_t fact_and_unknown_encoded_bytes_ = 0;
    std::uint64_t confidence_encoded_bytes_ = 0;
    bool ast_seen_ = false;
};

class readability_accumulator_t final {
public:
    explicit readability_accumulator_t(provider_evidence_budget_t& provider_budget)
    {
        provider_budget.charge_structured(512);
    }

    void append(const decompiler_document_t& document,
                const std::optional<pseudocode_readability_report_t>& supplied = {})
    {
        if (document.ast.nodes.size() > k_max_readability_nodes -
                (std::min)(processed_nodes_, k_max_readability_nodes))
            throw matrix_error_t("provider readability node count exceeds its cumulative bound");
        processed_nodes_ += static_cast<std::uint64_t>(document.ast.nodes.size());
        std::optional<pseudocode_readability_report_t> report = supplied;
        if (!report) {
            const auto analyzed = analyze_pseudocode_readability(document.ast, document);
            if (analyzed.succeeded())
                report = analyzed.report;
        }
        if (!report)
            throw matrix_error_t("production readability analysis did not produce a report");
        checked_accumulate(declaration_count_, report->metrics.declaration_count);
        max_expression_depth_ = (std::max)(max_expression_depth_,
            report->metrics.max_expression_depth);
        max_control_nesting_ = (std::max)(max_control_nesting_,
            report->metrics.max_control_nesting);
        checked_accumulate(dead_placeholder_count_, report->metrics.dead_placeholder_count);
        checked_accumulate(cast_count_, report->metrics.cast_count);
        checked_accumulate(fabricated_body_count_, report->metrics.fabricated_body_count);
        for (const auto& node : document.ast.nodes) {
            if (node.kind != typed_pseudocode_ast_node_kind_t::identifier)
                continue;
            checked_accumulate(symbol_count_, 1);
            if (!node.stable_text.empty())
                checked_accumulate(named_symbol_count_, 1);
        }
    }

    json to_json() const
    {
        return json{{"declaration_count", declaration_count_},
            {"max_expression_depth", max_expression_depth_},
            {"max_control_nesting", max_control_nesting_},
            {"dead_placeholder_count", dead_placeholder_count_},
            {"cast_count", cast_count_},
            {"fabricated_body_count", fabricated_body_count_},
            {"symbol_count", symbol_count_},
            {"named_symbol_count", named_symbol_count_}};
    }

private:
    static void checked_accumulate(std::uint64_t& target, const std::uint64_t value)
    {
        target = checked_sum(target, value, "provider readability metric overflowed");
    }

    std::uint64_t declaration_count_ = 0;
    std::uint64_t max_expression_depth_ = 0;
    std::uint64_t max_control_nesting_ = 0;
    std::uint64_t dead_placeholder_count_ = 0;
    std::uint64_t cast_count_ = 0;
    std::uint64_t fabricated_body_count_ = 0;
    std::uint64_t symbol_count_ = 0;
    std::uint64_t named_symbol_count_ = 0;
    std::uint64_t processed_nodes_ = 0;
};

std::string witness(json value)
{
    value.erase("execution_witness_sha256");
    const auto hash = canonical_json_sha256(std::move(value));
    if (!hash.ok)
        throw matrix_error_t(hash.error);
    return hash.sha256;
}

}
}

namespace aida::analysis::c03::provider_matrix {
namespace {

std::uint64_t native_runtime_address(
    const native_decompiler_entity_identity_t& identity,
    const workspace_image_t& image);

struct stage_bundles_t final {
    explicit stage_bundles_t(provider_evidence_budget_t& budget)
        : provider_ir(budget), hir(budget), type_graph(budget), ast(budget),
          document(budget), printc(budget)
    {
    }

    payload_bundle_t provider_ir;
    payload_bundle_t hir;
    payload_bundle_t type_graph;
    payload_bundle_t ast;
    payload_bundle_t document;
    payload_bundle_t printc;

    json artifacts(bool require_provider, bool require_hir,
                   bool require_types, bool require_ast,
                   bool require_document, bool require_printc) const
    {
        auto output = null_artifacts();
        const auto bind = [&output](std::string_view name, const payload_bundle_t& bundle,
                                    const bool required) {
            if (required) {
                const auto bytes = bundle.finish();
                if (bytes.empty())
                    throw matrix_error_t("required provider artifact bundle is empty");
                output[std::string(name)] = artifact_json(bytes);
            } else if (!bundle.empty()) {
                throw matrix_error_t("provider emitted an artifact outside its result contract");
            }
        };
        bind("provider_ir", provider_ir, require_provider);
        bind("hir", hir, require_hir);
        bind("type_graph", type_graph, require_types);
        bind("ast", ast, require_ast);
        bind("document", document, require_document);
        bind("printc", printc, require_printc);
        return output;
    }
};

void append_diagnostics(diagnostic_accumulator_t& output,
                        const std::vector<decompiler_diagnostic_t>& values)
{
    for (const auto& value : values)
        output.append(diagnostic_json(value));
}

void append_diagnostics(diagnostic_accumulator_t& output,
                        const std::vector<decompiler_ui_diagnostic_t>& values)
{
    for (const auto& value : values)
        output.append(diagnostic_json(value));
}

void append_diagnostics(diagnostic_accumulator_t& output,
                        const std::vector<native_worker::native_worker_diagnostic_t>& values)
{
    for (const auto& value : values)
        output.append(diagnostic_json(value));
}

std::uint64_t ended_after(const std::uint64_t started) noexcept
{
    const auto observed = tick_ns();
    return observed > started ? observed : started + 1;
}

decompiler_language_identity_t native_language_identity(
    const ghidra_adapter::ghidra_language_spec_t& language,
    const workspace_image_t& image)
{
    decompiler_language_identity_t result;
    result.language_id = language.language_id;
    result.language_version = "ghidra-staged-v1";
    result.compiler_spec_id = language.compiler_spec_id;
    result.language_spec_hash = stable_serialization_hash(
        language.language_id + "|" + language.compiler_spec_id);
    result.architecture = image.architecture;
    result.mode = image.architecture_mode;
    result.endian = image.endian;
    return result;
}

decompiler_ui_request_t make_native_ui_request(
    const generation_bound_decompiler_entity_t& binding,
    const analysis_workspace_t& workspace,
    const native_worker::packaged_native_worker_runtime_t& runtime,
    const std::chrono::steady_clock::time_point deadline)
{
    const auto publication = workspace.analysis_publication();
    if (!publication || !publication->snapshot ||
        !publication->snapshot->normalized_image)
        throw matrix_error_t("native UI request lacks a normalized publication");
    const auto image = publication->snapshot->normalized_image;
    const auto* native = std::get_if<native_decompiler_entity_identity_t>(
        &binding.entity.identity);
    if (!native)
        throw matrix_error_t("native UI request received a managed entity");
    auto language = ghidra_adapter::resolve_ghidra_language(*image);
    if (!language)
        throw matrix_error_t(language.error().stable_code() + ":" + language.error().message);
    decompiler_ui_request_t request;
    request.source = decompiler_ui_invocation_source_t::api_call;
    request.function_address = native_runtime_address(*native, *image);
    request.function_end_address = native->end.value;
    if (native->end.space == address_space_id_t::relative_virtual) {
        if (native->end.value > (std::numeric_limits<std::uint64_t>::max)() -
                image->image_base)
            throw matrix_error_t("native entity end address overflows the image base");
        request.function_end_address += image->image_base;
    }
    request.function_symbol = native->canonical_symbol;
    request.language = native_language_identity(language.value(), *image);
    request.worker_protocol_hash = runtime.worker_protocol_hash;
    request.metadata_revision = publication->analysis_revision;
    request.type_graph_revision = publication->analysis_revision;
    request.profile = decompiler_profile_id_t::balanced;
    request.cache_mode = decompiler_pipeline_cache_mode_t::bypass;
    request.provider_registration_id = "aida.decompiler.native.ghidra";
    request.renderer = pseudocode_renderer_style_settings(
        pseudocode_renderer_style_profile_t::balanced);
    request.dependencies = {
        {"aida.native.provider",
            runtime.provider.provider_version + "|" + runtime.provider.worker_build_id,
            runtime.provider.provider_binary_hash},
        {"aida.native.worker.manifest",
            std::to_string(native_worker::k_native_worker_manifest_schema_version),
            runtime.manifest_hash},
        {"aida.native.worker.protocol",
            std::to_string(runtime.worker_protocol_version),
            runtime.worker_protocol_hash},
        {"ghidra.language",
            request.language.language_version + "|" + request.language.compiler_spec_id,
            request.language.language_spec_hash}};
    request.deadline = deadline;
    return request;
}

decompiler_pipeline_cache_key_t make_provider_cache_key(
    const decompiler_pipeline_request_t& request,
    const native_worker::packaged_native_worker_runtime_t& runtime)
{
    decompiler_pipeline_cache_key_t key;
    key.stage = decompiler_cache_stage_t::provider_ir;
    key.workspace_id = request.workspace_id;
    key.workspace_generation = request.workspace_generation;
    key.analysis_revision = request.analysis_revision;
    key.entity = request.entity;
    key.provider = runtime.provider;
    key.worker_protocol_version = runtime.worker_protocol_version;
    key.worker_protocol_hash = request.cache_identity.worker_protocol_hash;
    key.language = request.language;
    key.loader_layout_hash = request.cache_identity.loader_layout_hash;
    key.function_bytes_hash = request.cache_identity.function_bytes_hash;
    key.chunk_fingerprints = request.cache_identity.chunk_fingerprints;
    key.metadata_revision = request.cache_identity.metadata_revision;
    key.type_graph_revision = request.cache_identity.type_graph_revision;
    key.overlay_revision = request.cache_identity.overlay_revision;
    key.profile = request.budget.value_or(default_decompiler_profile_policy().balanced);
    key.renderer = request.renderer.value_or(pseudocode_renderer_style_settings(
        pseudocode_renderer_style_profile_t::balanced));
    key.dependencies = request.cache_identity.dependencies;
    const auto validation = validate_decompiler_pipeline_cache_key(key);
    if (!validation.valid())
        throw matrix_error_t("direct native provider cache identity is invalid");
    return key;
}

std::uint64_t relative_range_value(const address_t& value,
                                   const workspace_image_t& image)
{
    if (value.space == address_space_id_t::relative_virtual)
        return value.value;
    if (value.value < image.image_base)
        throw matrix_error_t("native snapshot range precedes the image base");
    return value.value - image.image_base;
}

native_worker::native_worker_snapshot_t capture_native_snapshot(
    const analysis_workspace_t& workspace,
    const decompiler_pipeline_cache_key_t& key,
    const std::chrono::steady_clock::time_point deadline)
{
    const auto publication = workspace.analysis_publication();
    if (!publication || !publication->snapshot ||
        !publication->snapshot->normalized_image)
        throw matrix_error_t("native snapshot lacks a normalized publication");
    const auto image = publication->snapshot->normalized_image;
    auto language = ghidra_adapter::resolve_ghidra_language(*image);
    if (!language)
        throw matrix_error_t(language.error().stable_code() + ":" + language.error().message);
    auto revision = ghidra_adapter::make_ghidra_adapter_revision(
        workspace.identity(), *publication->snapshot);
    if (!revision)
        throw matrix_error_t(revision.error().stable_code() + ":" + revision.error().message);
    auto load_image = ghidra_adapter::ghidra_load_image_t::create(
        workspace.provider_handle(), image, language.value(), revision.value());
    if (!load_image)
        throw matrix_error_t(load_image.error().stable_code() + ":" + load_image.error().message);
    std::vector<std::pair<std::uint64_t, std::uint64_t>> ranges;
    ranges.emplace_back(0, (std::min<std::uint64_t>)(image->image_size, 1ULL << 20));
    for (const auto& fingerprint : key.chunk_fingerprints) {
        const auto begin = relative_range_value(fingerprint.begin, *image);
        const auto end = relative_range_value(fingerprint.end, *image);
        if (begin >= end || end > image->image_size)
            throw matrix_error_t("native snapshot fingerprint range is invalid");
        ranges.emplace_back(begin, end);
    }
    std::sort(ranges.begin(), ranges.end());
    std::vector<std::pair<std::uint64_t, std::uint64_t>> merged;
    for (const auto& range : ranges) {
        if (range.first >= range.second)
            continue;
        if (!merged.empty() && range.first <= merged.back().second)
            merged.back().second = (std::max)(merged.back().second, range.second);
        else
            merged.push_back(range);
    }
    const auto limit = (std::min<std::uint64_t>)(k_max_snapshot_bytes,
        key.profile.max_memory_bytes / 2);
    std::uint64_t total = 0;
    native_worker::native_provider_snapshot_t snapshot;
    snapshot.image_base = image->image_base;
    snapshot.image_size = image->image_size;
    for (const auto& range : merged) {
        const auto size = range.second - range.first;
        if (size > limit - total)
            throw matrix_error_t("native snapshot exceeds the balanced profile memory bound");
        total += size;
        native_worker::native_provider_snapshot_range_t captured;
        captured.relative_virtual_address = range.first;
        captured.bytes.reserve(static_cast<std::size_t>(size));
        for (auto cursor = range.first; cursor < range.second;) {
            if (clock_t::now() >= deadline)
                throw matrix_error_t("native snapshot deadline expired");
            const auto amount = (std::min<std::uint64_t>)(4ULL << 20,
                range.second - cursor);
            const address_t address{address_space_id_t::relative_virtual, cursor,
                image->architecture, image->architecture_mode};
            auto read = load_image.value()->read(address, amount);
            if (!read || read.value().bytes.size() != amount)
                throw matrix_error_t(read ? "native snapshot read was truncated" :
                    read.error().stable_code() + ":" + read.error().message);
            captured.bytes.insert(captured.bytes.end(),
                read.value().bytes.begin(), read.value().bytes.end());
            cursor += amount;
        }
        snapshot.ranges.push_back(std::move(captured));
    }
    const auto serialized = native_worker::serialize_native_provider_snapshot(snapshot);
    if (serialized.empty())
        throw matrix_error_t("native snapshot serialization failed");
    auto wrapped = native_worker::make_native_worker_snapshot(
        std::vector<std::uint8_t>(serialized.begin(), serialized.end()));
    if (!wrapped)
        throw matrix_error_t("native snapshot binding failed");
    return std::move(*wrapped);
}

struct native_job_t final {
    decompiler_pipeline_cache_key_t cache_key;
    decompiler_profile_budget_t profile;
    native_worker::native_worker_snapshot_t snapshot;
};

native_job_t make_native_job(
    const generation_bound_decompiler_entity_t& binding,
    const analysis_workspace_t& workspace,
    const native_worker::packaged_native_worker_runtime_t& runtime,
    const std::chrono::steady_clock::time_point deadline)
{
    auto request = make_native_ui_request(binding, workspace, runtime, deadline);
    auto pipeline = decompiler_ui_integration_t::build_pipeline_request(
        request, workspace);
    if (!pipeline)
        throw matrix_error_t(pipeline.error().stable_code() + ":" + pipeline.error().message);
    auto key = make_provider_cache_key(pipeline.value(), runtime);
    auto snapshot = capture_native_snapshot(workspace, key, deadline);
    return native_job_t{key, key.profile, std::move(snapshot)};
}

}
}

namespace aida::analysis::c03::provider_matrix {
namespace {

struct runtime_identity_t final {
    std::filesystem::path executable;
    std::filesystem::path native_binary;
    std::filesystem::path native_manifest;
    std::filesystem::path managed_binary;
    std::filesystem::path managed_manifest;
    std::filesystem::path managed_runtime_manifest;
    std::filesystem::path spec_manifest;
    std::string provider_build_sha256;
    std::string native_binary_sha256;
    std::string native_manifest_sha256;
    std::string managed_binary_sha256;
    std::string managed_manifest_sha256;
    std::string managed_runtime_manifest_sha256;
    std::string spec_manifest_sha256;
    std::string error;

    bool complete() const noexcept
    {
        return error.empty() && !provider_build_sha256.empty() &&
            !native_binary_sha256.empty() && !native_manifest_sha256.empty() &&
            !managed_binary_sha256.empty() && !managed_manifest_sha256.empty() &&
            !managed_runtime_manifest_sha256.empty() && !spec_manifest_sha256.empty();
    }
};

runtime_identity_t load_runtime_identity(const std::filesystem::path& runtime_root)
{
    runtime_identity_t result;
    result.executable = executable_path();
    result.native_binary = runtime_root /
        std::filesystem::u8path(native_worker::k_native_worker_binary_artifact_relative_path);
    result.native_manifest = runtime_root /
        std::filesystem::u8path(native_worker::k_native_worker_manifest_artifact_relative_path);
    result.managed_binary = runtime_root /
        std::filesystem::u8path(native_worker::k_managed_worker_binary_artifact_relative_path);
    result.managed_manifest = runtime_root /
        std::filesystem::u8path(native_worker::k_managed_worker_manifest_artifact_relative_path);
    result.managed_runtime_manifest = runtime_root /
        std::filesystem::u8path(native_worker::k_managed_runtime_manifest_artifact_relative_path);
    result.spec_manifest = runtime_root / "deps/AiDA_GhidraSpecs.manifest.json";
    result.provider_build_sha256 = hash_file_or_empty(result.executable, result.error);
    result.native_binary_sha256 = hash_file_or_empty(result.native_binary, result.error);
    result.native_manifest_sha256 = hash_file_or_empty(result.native_manifest, result.error);
    result.managed_binary_sha256 = hash_file_or_empty(result.managed_binary, result.error);
    result.managed_manifest_sha256 = hash_file_or_empty(result.managed_manifest, result.error);
    result.managed_runtime_manifest_sha256 = hash_file_or_empty(
        result.managed_runtime_manifest, result.error);
    result.spec_manifest_sha256 = hash_file_or_empty(result.spec_manifest, result.error);
    return result;
}

json identity_json(const runtime_identity_t& identity,
                   const native_worker::packaged_native_worker_runtime_t* runtime,
                   const std::set<std::string, std::less<>>& worker_roles)
{
    json workers = json::array();
    if (worker_roles.find("native") != worker_roles.end()) {
        workers.push_back({{"role", "native"},
            {"binary_sha256", identity.native_binary_sha256},
            {"manifest_sha256", identity.native_manifest_sha256}});
    }
    if (worker_roles.find("managed") != worker_roles.end()) {
        workers.push_back({{"role", "managed"},
            {"binary_sha256", identity.managed_binary_sha256},
            {"manifest_sha256", identity.managed_manifest_sha256}});
    }
    return json{{"provider_build_sha256", identity.provider_build_sha256},
        {"workers", std::move(workers)},
        {"runtime_manifest_sha256", identity.managed_runtime_manifest_sha256},
        {"spec_manifest_sha256", identity.spec_manifest_sha256},
        {"protocol_sha256", runtime ? runtime->worker_protocol_hash.to_hex() : std::string{}}};
}

struct corpus_context_t final {
    corpus_materialization_result_t materialization;
    struct provider_fixture_t final : materialized_fixture_t {
        std::string architecture_identity;
        std::optional<raw_code_profile_t> raw_code_profile;
        bool managed_only = false;
    };
    std::vector<provider_fixture_t> fixtures;
    json identity;
};

using provider_fixture_t = corpus_context_t::provider_fixture_t;

std::optional<raw_code_profile_t> raw_code_profile_from_fixture(
    std::string_view format, std::string_view architecture,
    std::string_view architecture_identity, std::string_view mode,
    std::string_view endian, const std::uint64_t size)
{
    if (format != "raw_code")
        return std::nullopt;
    if (size == 0)
        throw matrix_error_t("raw-code fixture is empty");
    raw_code_profile_t profile;
    profile.abi = abi_id_t::sysv;
    if (endian == "little")
        profile.endian = endian_t::little;
    else if (endian == "big")
        profile.endian = endian_t::big;
    else
        throw matrix_error_t("raw-code fixture endian identity is unsupported");
    if (architecture == "x86" && architecture_identity == "x86" && mode == "32") {
        profile.architecture = architecture_id_t::x86;
        profile.architecture_mode = architecture_mode_t::x86_32;
        profile.address_width_bits = 32;
    } else if (architecture == "x64" && architecture_identity == "x64" && mode == "64") {
        profile.architecture = architecture_id_t::x86_64;
        profile.architecture_mode = architecture_mode_t::x86_64;
        profile.address_width_bits = 64;
    } else if (architecture == "arm" && architecture_identity == "arm" && mode == "arm") {
        profile.architecture = architecture_id_t::arm;
        profile.architecture_mode = architecture_mode_t::arm_a32;
        profile.address_width_bits = 32;
    } else if (architecture == "arm" && architecture_identity == "thumb" && mode == "thumb") {
        profile.architecture = architecture_id_t::arm;
        profile.architecture_mode = architecture_mode_t::arm_thumb;
        profile.address_width_bits = 32;
    } else if (architecture == "aarch64" && architecture_identity == "aarch64" && mode == "64") {
        profile.architecture = architecture_id_t::aarch64;
        profile.architecture_mode = architecture_mode_t::aarch64;
        profile.address_width_bits = 64;
    } else if (architecture == "mips" && architecture_identity == "mips32" && mode == "32") {
        profile.architecture = architecture_id_t::mips;
        profile.architecture_mode = architecture_mode_t::mips32;
        profile.address_width_bits = 32;
    } else if (architecture == "mips" && architecture_identity == "mips64" && mode == "64") {
        profile.architecture = architecture_id_t::mips64;
        profile.architecture_mode = architecture_mode_t::mips64;
        profile.address_width_bits = 64;
    } else if (architecture == "ppc" && architecture_identity == "ppc32" && mode == "32") {
        profile.architecture = architecture_id_t::ppc;
        profile.architecture_mode = architecture_mode_t::ppc32;
        profile.address_width_bits = 32;
    } else if (architecture == "ppc" && architecture_identity == "ppc64" && mode == "64") {
        profile.architecture = architecture_id_t::ppc64;
        profile.architecture_mode = architecture_mode_t::ppc64;
        profile.address_width_bits = 64;
    } else if (architecture == "riscv" && architecture_identity == "riscv32" && mode == "32") {
        profile.architecture = architecture_id_t::riscv32;
        profile.architecture_mode = architecture_mode_t::riscv32;
        profile.address_width_bits = 32;
    } else if (architecture == "riscv" && architecture_identity == "riscv64" && mode == "64") {
        profile.architecture = architecture_id_t::riscv64;
        profile.architecture_mode = architecture_mode_t::riscv64;
        profile.address_width_bits = 64;
    } else {
        throw matrix_error_t("raw-code fixture architecture identity is inconsistent");
    }
    profile.image_base = 0x00100000ULL;
    profile.code_file_offset = 0;
    profile.code_rva = 0;
    profile.code_size = size;
    profile.entry_rva = 0;
    profile.symbol_name = "fragment";
    return profile;
}

corpus_context_t prepare_corpus(const matrix_config_t& config)
{
    const auto fixture_root = config.repository_root /
        "src/standalone/tests/c03/fixtures";
    const auto manifest_path = fixture_root / "corpus_manifest.json";
    const auto recipes_path = fixture_root / "corpus_generator_recipes.json";
    const auto ground_truth_path = fixture_root / "corpus_ground_truth.json";
    corpus_context_t context;
    const auto manifest = read_json(manifest_path);
    const auto recipes = read_json(recipes_path);
    const auto ground_truth = read_json(ground_truth_path);
    const auto manifest_validation = validate_corpus_manifest(manifest);
    if (!manifest_validation.valid)
        throw matrix_error_t(manifest_validation.summary());
    if (!ground_truth.is_object() ||
        ground_truth.value("schema", std::string{}) !=
            "aida.c03.corpus-ground-truth" ||
        !ground_truth.value("target_execution_forbidden", false))
        throw matrix_error_t("ground-truth corpus identity or nonexecution contract is invalid");
    std::atomic_bool cancelled{false};
    context.materialization = materialize_c03_corpus(manifest, recipes,
        ground_truth, config.materialized_root, &cancelled);
    if (!context.materialization.ok)
        throw matrix_error_t(context.materialization.error);
    const auto receipt_validation = validate_materialization_receipt(
        context.materialization.receipt, manifest, recipes,
        ground_truth, config.materialized_root);
    if (!receipt_validation.valid)
        throw matrix_error_t(receipt_validation.summary());
    struct fixture_identity_t final {
        std::string format;
        std::string architecture;
        std::string architecture_identity;
        std::string mode;
        std::string endian;
    };
    std::map<std::string, fixture_identity_t, std::less<>> identities;
    for (const auto& item : manifest.at("fixtures")) {
        fixture_identity_t value{item.at("format").get<std::string>(),
            item.at("architecture").get<std::string>(),
            item.at("architecture_identity").get<std::string>(),
            item.at("mode").get<std::string>(), item.at("endian").get<std::string>()};
        const auto id = item.at("id").get<std::string>();
        if (id.empty() || value.format.empty() || value.architecture.empty() ||
            value.architecture_identity.empty() || value.mode.empty() || value.endian.empty() ||
            !identities.emplace(id, std::move(value)).second)
            throw matrix_error_t("corpus manifest fixture identity is invalid or duplicated");
    }
    std::map<std::string, std::string, std::less<>> recipe_identities;
    for (const auto& item : recipes.at("recipes")) {
        const auto id = item.at("id").get<std::string>();
        const auto architecture_identity =
            item.at("architecture_identity").get<std::string>();
        if (id.empty() || architecture_identity.empty() ||
            !recipe_identities.emplace(id, architecture_identity).second)
            throw matrix_error_t("corpus recipe fixture identity is invalid or duplicated");
    }
    if (identities.size() != context.materialization.fixtures.size() ||
        recipe_identities.size() != identities.size())
        throw matrix_error_t("corpus fixture identity cardinality is inconsistent");
    context.fixtures.reserve(context.materialization.fixtures.size());
    for (const auto& fixture : context.materialization.fixtures) {
        const auto identity_entry = identities.find(fixture.id);
        const auto recipe_entry = recipe_identities.find(fixture.id);
        if (identity_entry == identities.end() || recipe_entry == recipe_identities.end() ||
            recipe_entry->second != identity_entry->second.architecture_identity ||
            fixture.format != identity_entry->second.format ||
            fixture.architecture != identity_entry->second.architecture ||
            fixture.mode != identity_entry->second.mode ||
            fixture.endian != identity_entry->second.endian)
            throw matrix_error_t("materialized fixture identity differs from its non-truth contract");
        provider_fixture_t provider_fixture;
        static_cast<materialized_fixture_t&>(provider_fixture) = fixture;
        provider_fixture.architecture_identity =
            identity_entry->second.architecture_identity;
        provider_fixture.raw_code_profile = raw_code_profile_from_fixture(
            provider_fixture.format, provider_fixture.architecture,
            provider_fixture.architecture_identity, provider_fixture.mode,
            provider_fixture.endian, provider_fixture.size_bytes);
        provider_fixture.managed_only = provider_fixture.format == "cli" ||
            provider_fixture.architecture_identity == "jvm" ||
            provider_fixture.architecture_identity == "dalvik";
        context.fixtures.push_back(std::move(provider_fixture));
    }
    const auto manifest_hash = sha256_evidence_file(manifest_path, k_max_json_bytes);
    const auto recipes_hash = sha256_evidence_file(recipes_path, k_max_json_bytes);
    const auto truth_hash = sha256_evidence_file(ground_truth_path, k_max_json_bytes);
    const auto fixture_set_hash = canonical_json_sha256(
        context.materialization.receipt.at("fixtures"));
    if (!manifest_hash.ok || !recipes_hash.ok || !truth_hash.ok ||
        !fixture_set_hash.ok ||
        !context.materialization.receipt.contains("receipt_sha256") ||
        !context.materialization.receipt.at("receipt_sha256").is_string() ||
        !is_canonical_sha256(context.materialization.receipt.at("receipt_sha256").get_ref<const std::string&>()))
        throw matrix_error_t("corpus identity hashing failed");
    context.identity = {{"manifest_sha256", manifest_hash.sha256},
        {"recipes_sha256", recipes_hash.sha256},
        {"ground_truth_sha256", truth_hash.sha256},
        {"materialization_receipt_sha256",
            context.materialization.receipt.at("receipt_sha256")},
        {"fixture_set_sha256", fixture_set_hash.sha256}};
    return context;
}

bool is_collection_fixture(const std::string& format) noexcept
{
    return format == "zip" || format == "zip64" || format == "apk" ||
        format == "aab" || format == "ipa" || format == "jar" ||
        format == "archive" || format == "static_library" ||
        format == "import_library" || format == "macho_fat";
}

bool code_bearing_member(const collection_member_descriptor_t& member) noexcept
{
    switch (member.member_kind) {
    case collection_member_kind_t::binary:
    case collection_member_kind_t::dex:
    case collection_member_kind_t::classfile:
    case collection_member_kind_t::native_library:
    case collection_member_kind_t::fat_slice:
        return true;
    case collection_member_kind_t::unknown:
    case collection_member_kind_t::nested_archive:
    case collection_member_kind_t::debug_companion:
    case collection_member_kind_t::resource:
    case collection_member_kind_t::manifest:
        return false;
    }
    return false;
}

struct analysis_unit_source_t final {
    std::shared_ptr<const byte_provider_t> provider;
    std::string logical_path;
};

class metadata_bound_provider_t final : public byte_provider_t {
public:
    static std::shared_ptr<const byte_provider_t> create(
        std::shared_ptr<const byte_provider_t> provider,
        provider_member_metadata_t metadata,
        std::string normalized_source)
    {
        bool normalized = true;
        std::size_t component_start = 0;
        while (component_start < metadata.normalized_member_path.size()) {
            const auto separator = metadata.normalized_member_path.find('/', component_start);
            const auto component_end = separator == std::string::npos
                ? metadata.normalized_member_path.size() : separator;
            const auto length = component_end - component_start;
            if (length == 0 ||
                (length == 1 && metadata.normalized_member_path[component_start] == '.') ||
                (length == 2 && metadata.normalized_member_path[component_start] == '.' &&
                    metadata.normalized_member_path[component_start + 1] == '.')) {
                normalized = false;
                break;
            }
            if (separator == std::string::npos)
                break;
            component_start = separator + 1;
        }
        if (!provider || provider->size() == 0 || normalized_source.empty() ||
            normalized_source.find('\0') != std::string::npos ||
            metadata.normalized_member_path.empty() ||
            !normalized ||
            metadata.normalized_member_path.front() == '/' ||
            metadata.normalized_member_path.find('\\') != std::string::npos ||
            metadata.normalized_member_path.find('\0') != std::string::npos ||
            metadata.depth == 0 || metadata.depth > 64 ||
            metadata.uncompressed_size != provider->size())
            throw matrix_error_t("collection member metadata cannot be bound to opened bytes");
        auto identity = provider->identity();
        identity.normalized_source = std::move(normalized_source);
        identity.size = provider->size();
        identity.member = std::move(metadata);
        return std::shared_ptr<const byte_provider_t>(new metadata_bound_provider_t(
            std::move(provider), std::move(identity)));
    }

    const byte_provider_identity_t& identity() const noexcept override { return identity_; }
    std::uint64_t size() const noexcept override { return provider_->size(); }
    std::uint64_t maximum_contiguous_lease(const std::uint64_t offset) const noexcept override
    {
        return provider_->maximum_contiguous_lease(offset);
    }
    workspace_result_t<byte_view_t> lease(
        const std::uint64_t offset, const std::uint64_t size_value,
        const cancellation_token_t& cancel = {}) const override
    {
        return provider_->lease(offset, size_value, cancel);
    }

private:
    metadata_bound_provider_t(std::shared_ptr<const byte_provider_t> provider,
                              byte_provider_identity_t identity)
        : provider_(std::move(provider)), identity_(std::move(identity))
    {
    }

    std::shared_ptr<const byte_provider_t> provider_;
    byte_provider_identity_t identity_;
};

std::string archive_member_path(const coff_archive_member_t& member)
{
    std::string name;
    name.reserve(member.name.size());
    for (const auto character : member.name) {
        const auto value = static_cast<unsigned char>(character);
        name.push_back((value >= 'a' && value <= 'z') ||
            (value >= 'A' && value <= 'Z') ||
            (value >= '0' && value <= '9') || value == '.' || value == '_' || value == '-'
            ? static_cast<char>(value) : '_');
    }
    if (name.empty() || name == "." || name == "..")
        name = "binary";
    return "member_" + std::to_string(member.index) + "/" + name;
}

std::vector<analysis_unit_source_t> archive_analysis_sources(
    const std::shared_ptr<const byte_provider_t>& provider,
    const std::string& normalized_source)
{
    auto parsed = parse_coff_image(*provider);
    if (!parsed)
        throw matrix_error_t(parsed.error().stable_code() + ":" +
            parsed.error().message);
    if (parsed.value().artifact_kind != coff_artifact_kind_t::archive)
        throw matrix_error_t("archive fixture did not parse as a COFF archive");
    std::vector<analysis_unit_source_t> output;
    std::size_t import_object_count = 0;
    for (const auto& member : parsed.value().archive_members) {
        if (member.kind == coff_archive_member_kind_t::import_object) {
            ++import_object_count;
            continue;
        }
        if (member.kind != coff_archive_member_kind_t::object)
            continue;
        if (output.size() >= k_max_entities_per_fixture)
            throw matrix_error_t("archive code-member count exceeds the provider bound");
        provider_member_metadata_t metadata;
        metadata.normalized_member_path = archive_member_path(member);
        metadata.container_offset = member.payload_offset;
        metadata.compressed_size = member.payload_size;
        metadata.uncompressed_size = member.payload_size;
        metadata.ordinal = member.index;
        metadata.depth = 1;
        auto opened = subrange_provider_t::create_member(provider,
            member.payload_offset, member.payload_size, metadata);
        if (!opened)
            throw matrix_error_t(opened.error().stable_code() + ":" +
                opened.error().message);
        auto member_provider = metadata_bound_provider_t::create(
            std::static_pointer_cast<const byte_provider_t>(opened.take_value()),
            metadata, normalized_source);
        output.push_back({std::move(member_provider), metadata.normalized_member_path});
    }
    if (output.empty() && import_object_count != 0)
        throw matrix_not_applicable_t(
            "archive contains import metadata but no executable object entity");
    if (output.empty())
        throw matrix_error_t("archive contains no code-bearing object member");
    return output;
}

std::vector<analysis_unit_source_t> collection_analysis_sources(
    const std::shared_ptr<const byte_provider_t>& provider,
    const std::string& normalized_source)
{
    auto collection = artifact_collection_t::open(
        provider);
    if (!collection)
        throw matrix_error_t(collection.error().stable_code() + ":" +
            collection.error().message);
    auto verified = collection.value()->verify_integrity();
    if (!verified)
        throw matrix_error_t(verified.error().stable_code() + ":" +
            verified.error().message);
    std::vector<analysis_unit_source_t> output;
    std::function<void(const std::shared_ptr<artifact_collection_t>&,
                       const std::string&, std::uint32_t)> visit;
    visit = [&](const std::shared_ptr<artifact_collection_t>& current,
                const std::string& prefix, const std::uint32_t depth) {
        if (!current || depth > 32)
            throw matrix_error_t("collection member traversal exceeded its depth bound");
        for (std::size_t index = 0; index < current->members().size(); ++index) {
            if (output.size() >= k_max_entities_per_fixture)
                throw matrix_error_t("collection code-member count exceeds the provider bound");
            const auto& member = current->members()[index];
            const auto path = prefix.empty() ? member.normalized_path :
                prefix + "!/" + member.normalized_path;
            const bool typed_member = member.format == format_id_t::pe32 ||
                member.format == format_id_t::pe32_plus ||
                member.format == format_id_t::elf ||
                member.format == format_id_t::macho ||
                member.format == format_id_t::macho_fat ||
                member.format == format_id_t::coff ||
                member.format == format_id_t::dex ||
                member.format == format_id_t::oat ||
                member.format == format_id_t::vdex ||
                member.format == format_id_t::classfile;
            if (code_bearing_member(member) || typed_member) {
                auto opened = current->open_member(index);
                if (!opened)
                    throw matrix_error_t(opened.error().stable_code() + ":" +
                        opened.error().message);
                auto metadata = member.provider_metadata;
                metadata.normalized_member_path = path;
                metadata.ordinal = member.ordinal;
                auto member_provider = metadata_bound_provider_t::create(
                    opened.take_value(), std::move(metadata), normalized_source);
                output.push_back({std::move(member_provider), path});
            }
            if (member.is_nested_collection ||
                member.member_kind == collection_member_kind_t::nested_archive) {
                auto child = current->open_child_collection(index);
                if (!child)
                    throw matrix_error_t(child.error().stable_code() + ":" +
                        child.error().message);
                auto child_verified = child.value()->verify_integrity();
                if (!child_verified)
                    throw matrix_error_t(child_verified.error().stable_code() + ":" +
                        child_verified.error().message);
                visit(child.value(), path, depth + 1);
            }
        }
    };
    visit(collection.value(), {}, 0);
    std::sort(output.begin(), output.end(), [](const auto& left, const auto& right) {
        return left.logical_path < right.logical_path;
    });
    if (std::adjacent_find(output.begin(), output.end(), [](const auto& left, const auto& right) {
            return left.logical_path == right.logical_path;
        }) != output.end())
        throw matrix_error_t("collection contains duplicate code-bearing logical paths");
    if (output.empty())
        throw matrix_error_t("collection contains no code-bearing member");
    return output;
}

std::vector<analysis_unit_source_t> ipa_analysis_sources(
    const std::shared_ptr<const byte_provider_t>& provider,
    const std::string& normalized_source)
{
    auto container = ipa_container_t::open(provider);
    if (!container)
        throw matrix_error_t(container.error().stable_code() + ":" +
            container.error().message);
    std::vector<analysis_unit_source_t> output;
    output.reserve(container.value()->members().size());
    for (std::size_t index = 0; index < container.value()->members().size(); ++index) {
        if (output.size() >= k_max_entities_per_fixture)
            throw matrix_error_t("IPA code-member count exceeds the provider bound");
        const auto& member = container.value()->members()[index];
        if (member.role == ipa_member_role_t::debug_companion)
            continue;
        auto opened = container.value()->open_member_provider(index);
        if (!opened)
            throw matrix_error_t(opened.error().stable_code() + ":" +
                opened.error().message);
        auto metadata = member.provider_metadata;
        metadata.normalized_member_path = member.normalized_path;
        auto member_provider = metadata_bound_provider_t::create(
            opened.take_value(), std::move(metadata), normalized_source);
        output.push_back({std::move(member_provider), member.normalized_path});
    }
    if (output.empty())
        throw matrix_error_t("IPA contains no code-bearing Mach-O member");
    return output;
}

std::vector<analysis_unit_source_t> analysis_unit_sources(
    const materialized_fixture_t& fixture)
{
    if (!is_collection_fixture(fixture.format))
        return {};
    auto mapped = mapped_file_provider_t::open(fixture.path.u8string());
    if (!mapped)
        throw matrix_error_t(mapped.error().stable_code() + ":" +
            mapped.error().message);
    auto provider = std::static_pointer_cast<const byte_provider_t>(mapped.take_value());
    const auto normalized_source = canonical_path(fixture.path).u8string();
    if (fixture.format == "ipa")
        return ipa_analysis_sources(provider, normalized_source);
    if (fixture.format == "archive" || fixture.format == "static_library" ||
        fixture.format == "import_library")
        return archive_analysis_sources(provider, normalized_source);
    return collection_analysis_sources(provider, normalized_source);
}

class workspace_scope_t final {
public:
    workspace_scope_t() = default;
    workspace_scope_t(const workspace_scope_t&) = delete;
    workspace_scope_t& operator=(const workspace_scope_t&) = delete;

    ~workspace_scope_t()
    {
        if (!workspace_)
            return;
        const auto database_path = workspace_->database()
            ? workspace_->database()->path() : std::string{};
        auto closed = workspace_registry().close(workspace_->identity().binary_id(),
            clock_t::now() + std::chrono::seconds(10));
        if (!closed) {
            auto& failure = deferred_close_failure();
            if (!failure)
                failure = std::move(closed.error());
            return;
        }
        if (!database_path.empty()) {
            std::error_code error;
            for (const auto& candidate : {
                    database_path, database_path + "-wal", database_path + "-shm"}) {
                std::filesystem::remove(std::filesystem::u8path(candidate), error);
                error.clear();
            }
        }
    }

    static std::unique_ptr<workspace_scope_t> create(
        const provider_fixture_t& fixture, std::string bin_name,
        const analysis_unit_source_t* source = nullptr)
    {
        auto& close_failure = deferred_close_failure();
        if (close_failure) {
            auto detail = close_failure->stable_code() + ":" +
                close_failure->message;
            close_failure.reset();
            throw matrix_error_t("previous scorer workspace close failed:" + detail);
        }
        auto result = std::make_unique<workspace_scope_t>();
        const auto scorer_profile_identity = bin_name;
        const auto bind_scorer_profile = [&scorer_profile_identity](
                std::vector<std::uint8_t>& profile) {
            constexpr std::string_view domain = "aida.c03.provider-matrix";
            profile.push_back(0);
            profile.insert(profile.end(), domain.begin(), domain.end());
            profile.push_back(0);
            profile.insert(profile.end(), scorer_profile_identity.begin(),
                scorer_profile_identity.end());
            profile.push_back(0);
            const auto execution = scorer_execution_identity();
            for (std::size_t index = 0; index < sizeof(execution); ++index)
                profile.push_back(static_cast<std::uint8_t>(execution >> (index * 8U)));
        };
        if (source) {
            if (!source->provider || !source->provider->member_metadata())
                throw matrix_error_t("analysis unit provider lacks immutable member metadata");
            open_provider_workspace_request_t request;
            request.provider = source->provider;
            request.bin_name = std::move(bin_name);
            request.member_metadata = source->provider->member_metadata();
            request.load_profile = {1, 0, 0, 0};
            const auto source_identity = std::filesystem::absolute(fixture.path)
                .lexically_normal().u8string() + "!/" + source->logical_path;
            request.load_profile.insert(request.load_profile.end(),
                source_identity.begin(), source_identity.end());
            bind_scorer_profile(request.load_profile);
            auto opened = workspace_registry().admit_verified_provider(request);
            if (!opened)
                throw matrix_error_t(opened.error().stable_code() + ":" +
                    opened.error().message);
            result->workspace_ = opened.take_value();
        } else if (fixture.raw_code_profile) {
            open_static_workspace_request_t request;
            request.source_path = fixture.path.u8string();
            request.bin_name = std::move(bin_name);
            request.raw_code_profile = fixture.raw_code_profile;
            request.load_profile = {1, 0, 0, 0};
            const auto path_identity = std::filesystem::absolute(fixture.path)
                .lexically_normal().u8string();
            request.load_profile.insert(request.load_profile.end(),
                path_identity.begin(), path_identity.end());
            bind_scorer_profile(request.load_profile);
            auto opened = workspace_registry().open_static(request);
            if (!opened)
                throw matrix_error_t(opened.error().stable_code() + ":" +
                    opened.error().message);
            result->workspace_ = opened.take_value();
        } else {
            open_static_workspace_request_t request;
            request.source_path = fixture.path.u8string();
            request.bin_name = std::move(bin_name);
            request.load_profile = {1, 0, 0, 0};
            const auto path_identity = std::filesystem::absolute(fixture.path)
                .lexically_normal().u8string();
            request.load_profile.insert(request.load_profile.end(),
                path_identity.begin(), path_identity.end());
            bind_scorer_profile(request.load_profile);
            auto opened = workspace_registry().open_static(request);
            if (!opened)
                throw matrix_error_t(opened.error().stable_code() + ":" +
                    opened.error().message);
            result->workspace_ = opened.take_value();
        }
        test_fixture::install_services(result->workspace_);
        test_fixture::analyze_workspace(result->workspace_, 1);
        const auto publication = result->workspace_->analysis_publication();
        if (!publication || !publication->coherent_with(result->workspace_->identity()) ||
            publication->readiness != workspace_readiness_t::baseline_ready ||
            !publication->snapshot)
            throw matrix_error_t("baseline publication is not coherent and ready");
        return result;
    }

    const std::shared_ptr<analysis_workspace_t>& workspace() const noexcept
    {
        return workspace_;
    }

private:
    static std::uint64_t scorer_execution_identity() noexcept
    {
        static const std::uint64_t identity = []() noexcept {
            const auto process = static_cast<std::uint64_t>(::GetCurrentProcessId());
            FILETIME created{};
            FILETIME exited{};
            FILETIME kernel{};
            FILETIME user{};
            std::uint64_t epoch = static_cast<std::uint64_t>(::GetTickCount64());
            if (::GetProcessTimes(::GetCurrentProcess(), &created, &exited, &kernel, &user))
                epoch = (static_cast<std::uint64_t>(created.dwHighDateTime) << 32U) |
                    static_cast<std::uint64_t>(created.dwLowDateTime);
            return epoch ^ (process * 0x9E3779B97F4A7C15ULL);
        }();
        return identity;
    }

    static std::optional<workspace_error_t>& deferred_close_failure()
    {
        static std::optional<workspace_error_t> failure;
        return failure;
    }

    std::shared_ptr<analysis_workspace_t> workspace_;
};

std::uint64_t native_runtime_address(const native_decompiler_entity_identity_t& identity,
                                     const workspace_image_t& image)
{
    if (identity.entry.space != address_space_id_t::relative_virtual)
        return identity.entry.value;
    if (identity.entry.value > (std::numeric_limits<std::uint64_t>::max)() - image.image_base)
        throw matrix_error_t("native entity address overflows the image base");
    return image.image_base + identity.entry.value;
}

std::vector<generation_bound_decompiler_entity_t> enumerate_entities(
    const std::shared_ptr<decompiler_ui_integration_t>& integration)
{
    if (!integration || !integration->workspace())
        throw matrix_error_t("production decompiler integration is unavailable");
    const auto workspace = integration->workspace();
    auto publication = workspace->analysis_publication();
    if (!publication || !publication->snapshot || !publication->provider)
        throw matrix_error_t("decompiler entity publication is unavailable");
    const auto format = workspace->identity().format();
    const bool managed_candidate =
        format == format_id_t::pe32 || format == format_id_t::pe32_plus ||
        format == format_id_t::classfile || format == format_id_t::dex ||
        format == format_id_t::oat || format == format_id_t::vdex;
    if (!publication->managed_artifacts && managed_candidate &&
        workspace->target_kind() == target_kind_t::static_file) {
        const auto target_revision = publication->analysis_revision == 0
            ? 1ULL : publication->analysis_revision;
        auto admitted = build_managed_artifact_publication(
            workspace->identity(), *publication->provider,
            publication->snapshot->image, publication->generation,
            target_revision, publication->overlay_revision);
        if (!admitted)
            throw matrix_error_t(admitted.error().stable_code() + ":" +
                admitted.error().message);
        if (admitted.value()) {
            auto published = workspace->publish_managed_artifacts(
                publication->generation, publication->analysis_revision,
                admitted.take_value(), true);
            if (!published)
                throw matrix_error_t(published.error().stable_code() + ":" +
                    published.error().message);
            publication = workspace->analysis_publication();
            if (!publication || !publication->snapshot || !publication->provider)
                throw matrix_error_t("managed artifact publication is unavailable");
        }
    }
    std::vector<generation_bound_decompiler_entity_t> output;
    if (publication->snapshot->functions.size() > k_max_entities_per_fixture)
        throw matrix_error_t("native entity count exceeds the provider-matrix source bound");
    output.reserve(publication->snapshot->functions.size() +
        (publication->managed_artifacts ? publication->managed_artifacts->methods().size() : 0));
    const auto image = publication->snapshot->normalized_image;
    if (image) {
        for (const auto& function : publication->snapshot->functions) {
            if (function.id == 0 || !(function.start < function.end))
                continue;
            if (function.provenance == fact_provenance_t::gap_recovery)
                continue;
            decompiler_entity_locator_t locator;
            locator.address = function.start.value;
            locator.expected_kind = decompiler_entity_kind_t::native_function;
            auto resolved = integration->resolve_entity_at(locator);
            if (!resolved)
                throw matrix_error_t(resolved.error().stable_code() + ":" + resolved.error().message);
            output.push_back(resolved.take_value());
        }
    }
    if (publication->managed_artifacts) {
        const auto& methods = publication->managed_artifacts->methods();
        if (methods.size() > k_max_entities_per_fixture ||
            output.size() > k_max_entities_per_fixture - methods.size())
            throw matrix_error_t("managed entity count exceeds the provider-matrix source bound");
        for (const auto& method : methods) {
            if (!method.has_body || method.artifact_index >=
                    publication->managed_artifacts->artifacts().size())
                continue;
            const auto& artifact = publication->managed_artifacts->artifacts()[method.artifact_index];
            decompiler_entity_locator_t locator;
            locator.token = method.entity_token;
            locator.artifact_ordinal = artifact.artifact_ordinal;
            locator.expected_kind = method.entity.kind;
            auto resolved = integration->resolve_entity_at(locator);
            if (!resolved)
                throw matrix_error_t(resolved.error().stable_code() + ":" + resolved.error().message);
            output.push_back(resolved.take_value());
        }
    }
    std::sort(output.begin(), output.end(), [](const auto& left, const auto& right) {
        return left.entity < right.entity;
    });
    output.erase(std::unique(output.begin(), output.end(), [](const auto& left, const auto& right) {
        return left.entity == right.entity;
    }), output.end());
    return output;
}

struct workspace_unit_t final {
    std::unique_ptr<workspace_scope_t> scope;
    std::shared_ptr<decompiler_ui_integration_t> integration;
    std::vector<generation_bound_decompiler_entity_t> entities;
};

struct scheduled_entity_t final {
    const workspace_unit_t* unit = nullptr;
    const generation_bound_decompiler_entity_t* entity = nullptr;
};

std::vector<scheduled_entity_t> scheduled_entities(
    const std::vector<workspace_unit_t>& units, const bool native_only,
    const bool reverse)
{
    std::vector<scheduled_entity_t> output;
    for (const auto& unit : units) {
        for (const auto& entity : unit.entities) {
            if (native_only && entity.entity.kind !=
                    decompiler_entity_kind_t::native_function)
                continue;
            output.push_back({&unit, &entity});
        }
    }
    if (reverse)
        std::reverse(output.begin(), output.end());
    return output;
}

std::vector<workspace_unit_t> make_workspace_units(
    const provider_fixture_t& fixture,
    const std::string& label,
    const std::filesystem::path& runtime_root)
{
    const auto sources = analysis_unit_sources(fixture);
    const auto unit_count = sources.empty() ? 1ULL :
        static_cast<std::uint64_t>(sources.size());
    std::vector<workspace_unit_t> output;
    output.reserve(static_cast<std::size_t>(unit_count));
    std::size_t entity_count = 0;
    for (std::size_t index = 0; index < unit_count; ++index) {
        const auto* source = sources.empty() ? nullptr : &sources[index];
        auto scope = workspace_scope_t::create(fixture,
            label + "-" + std::to_string(index), source);
        auto integration = decompiler_ui_integration_t::create_production(
            scope->workspace(), runtime_root);
        if (!integration)
            throw matrix_error_t(integration.error().stable_code() + ":" +
                integration.error().message);
        auto entities = enumerate_entities(integration.value());
        if (entities.empty())
            throw matrix_error_t("code-bearing analysis unit contains no decompiler entity");
        if (entities.size() > k_max_entities_per_fixture - entity_count)
            throw matrix_error_t("aggregate fixture entity count exceeds the provider bound");
        entity_count += entities.size();
        output.push_back(workspace_unit_t{std::move(scope), integration.take_value(),
            std::move(entities)});
    }
    return output;
}

json base_fixture_json(const provider_fixture_t& fixture,
                       std::string status, std::string reason)
{
    return json{{"id", bounded_contract_text(fixture.id, "fixture id")},
        {"status", std::move(status)},
        {"status_reason", bounded_contract_text(std::move(reason), "fixture status_reason")},
        {"artifact_sha256", fixture.artifact_sha256},
        {"artifact_size", fixture.size_bytes},
        {"format", bounded_contract_text(fixture.format, "fixture format")},
        {"architecture", bounded_contract_text(fixture.architecture_identity,
            "fixture architecture")},
        {"mode", bounded_contract_text(fixture.mode, "fixture mode")},
        {"endian", bounded_contract_text(fixture.endian, "fixture endian")},
        {"runs", json::array()}};
}

json make_run_json(std::string run_id, const std::uint64_t started,
                   const std::uint64_t ended, std::string schedule,
                   std::string cache_state,
                   json artifacts, const fact_accumulator_t& facts,
                   const readability_accumulator_t& readability,
                   json diagnostics)
{
    json output{{"run_id", bounded_contract_text(std::move(run_id), "provider run id")},
        {"execution_witness_sha256", ""},
        {"started_tick_ns", started}, {"ended_tick_ns", ended},
        {"duration_ns", ended >= started ? ended - started : 0},
        {"schedule", std::move(schedule)},
        {"cache_state", std::move(cache_state)}, {"outcome", "success"},
        {"artifacts", std::move(artifacts)}, {"facts", facts.facts_json()},
        {"confidence", facts.confidence_json()},
        {"explicit_unknowns", facts.unknowns_json()},
        {"readability", readability.to_json()}, {"diagnostics", std::move(diagnostics)}};
    output["execution_witness_sha256"] = witness(output);
    return output;
}

json make_cancellation_json(bool requested, std::string status, std::string reason,
                            std::uint64_t started, std::uint64_t requested_tick,
                            std::uint64_t ended, std::string outcome, json diagnostics)
{
    json output{{"requested", requested}, {"status", std::move(status)},
        {"status_reason", bounded_contract_text(std::move(reason),
            "cancellation status_reason")}, {"started_tick_ns", started},
        {"cancel_requested_tick_ns", requested_tick}, {"ended_tick_ns", ended},
        {"latency_ns", ended >= requested_tick ? ended - requested_tick : 0},
        {"outcome", std::move(outcome)}, {"diagnostics", std::move(diagnostics)},
        {"execution_witness_sha256", ""}};
    output["execution_witness_sha256"] = witness(output);
    return output;
}

std::string provider_name(const provider_selection_t provider)
{
    switch (provider) {
    case provider_selection_t::candidate: return "aida_typed_pipeline";
    case provider_selection_t::ghidra_printc: return "ghidra_printc";
    case provider_selection_t::aida_current: return "aida_current";
    case provider_selection_t::all: break;
    }
    throw matrix_error_t("all is not an individual provider result");
}

json workspace_error_json(const workspace_error_t& error)
{
    return json{{"code", bounded_contract_text(error.stable_code(),
            "workspace diagnostic code")},
        {"message", bounded_contract_text(error.message.empty()
            ? std::string("workspace failure") : error.message,
            "workspace diagnostic message")},
        {"severity", "error"}};
}

std::optional<std::string> worker_role(
    const decompiler_provider_descriptor_t& provider)
{
    switch (provider.identity.provider) {
    case decompiler_provider_id_t::ghidra_native: return "native";
    case decompiler_provider_id_t::ilspy_cli: return "managed";
    case decompiler_provider_id_t::jvm_ssa:
    case decompiler_provider_id_t::dalvik_ssa:
        return std::nullopt;
    }
    return std::nullopt;
}

std::vector<generation_bound_decompiler_entity_t> native_entities(
    const std::vector<generation_bound_decompiler_entity_t>& entities)
{
    std::vector<generation_bound_decompiler_entity_t> output;
    for (const auto& entity : entities) {
        if (entity.entity.kind == decompiler_entity_kind_t::native_function)
            output.push_back(entity);
    }
    return output;
}

std::uint64_t cancellation_entity_weight(
    const generation_bound_decompiler_entity_t& entity) noexcept
{
    if (const auto* native = std::get_if<native_decompiler_entity_identity_t>(
            &entity.entity.identity)) {
        if (native->entry.space == native->end.space && native->end.value > native->entry.value)
            return native->end.value - native->entry.value;
    }
    return entity.provider_size;
}

std::vector<generation_bound_decompiler_entity_t> cancellation_order(
    std::vector<generation_bound_decompiler_entity_t> entities)
{
    std::stable_sort(entities.begin(), entities.end(), [](const auto& left, const auto& right) {
        const auto left_weight = cancellation_entity_weight(left);
        const auto right_weight = cancellation_entity_weight(right);
        if (left_weight != right_weight)
            return left_weight > right_weight;
        return left.entity < right.entity;
    });
    return entities;
}

struct cancellation_observation_t final {
    explicit cancellation_observation_t(provider_evidence_budget_t& provider_budget)
        : diagnostics(provider_budget, diagnostic_scope_t::cancellation)
    {
    }

    bool cancelled = false;
    diagnostic_accumulator_t diagnostics;
};

struct cancellation_unit_t final {
    const workspace_unit_t* unit = nullptr;
    std::vector<generation_bound_decompiler_entity_t> entities;
};

cancellation_unit_t select_cancellation_unit(
    const std::vector<workspace_unit_t>& units, const bool native_only)
{
    const workspace_unit_t* selected = nullptr;
    std::uint64_t selected_weight = 0;
    for (const auto& unit : units) {
        for (const auto& entity : unit.entities) {
            if (native_only && entity.entity.kind !=
                    decompiler_entity_kind_t::native_function)
                continue;
            const auto weight = cancellation_entity_weight(entity);
            if (!selected || weight > selected_weight) {
                selected = &unit;
                selected_weight = weight;
            }
        }
    }
    cancellation_unit_t output;
    output.unit = selected;
    if (!selected)
        return output;
    output.entities = native_only ? native_entities(selected->entities) :
        selected->entities;
    output.entities = cancellation_order(std::move(output.entities));
    return output;
}

bool fixture_is_managed_only(const provider_fixture_t& fixture) noexcept
{
    return fixture.managed_only;
}

json candidate_cancellation(
    const std::shared_ptr<decompiler_ui_integration_t>& integration,
    std::vector<generation_bound_decompiler_entity_t> entities,
    const std::uint64_t deadline_ms,
    provider_evidence_budget_t& evidence_budget)
{
    if (!integration || entities.empty())
        return make_cancellation_json(true, "not_measured",
            "no production entity was available for cancellation", 0, 0, 0,
            "provider_failure", json::array());
    const auto budget_ms = (std::min)(deadline_ms, k_cancellation_budget_ms);
    const auto execution_deadline = clock_t::now() +
        std::chrono::milliseconds(deadline_ms);
    const auto entry_deadline = clock_t::now() +
        std::chrono::milliseconds(budget_ms);
    cancellation_source_t source(execution_deadline);
    entities = cancellation_order(std::move(entities));
    const auto requests_before = integration->metrics().total_requests;
    const auto started = tick_ns();
    auto operation = std::async(std::launch::async,
        [&integration, entities = std::move(entities), &source,
         execution_deadline,
         &evidence_budget] {
            cancellation_observation_t observation(evidence_budget);
            constexpr std::size_t max_attempts = 64;
            for (std::size_t attempt = 0;
                 attempt < max_attempts &&
                 clock_t::now() < execution_deadline; ++attempt) {
                auto result = integration->decompile_entity(
                    entities[attempt % entities.size()],
                    decompiler_ui_invocation_source_t::api_call,
                    decompiler_profile_id_t::balanced,
                    decompiler_pipeline_cache_mode_t::bypass, source.token());
                if (!result) {
                    observation.diagnostics.append(workspace_error_json(result.error()));
                    if (result.error().code == workspace_error_code_t::cancelled) {
                        observation.cancelled = true;
                        break;
                    }
                } else {
                    append_diagnostics(observation.diagnostics, result.value().diagnostics);
                    if (result.value().status == decompiler_pipeline_status_t::cancelled) {
                        observation.cancelled = true;
                        break;
                    }
                }
                std::this_thread::yield();
            }
            return observation;
    });
    bool entered = false;
    while (clock_t::now() < entry_deadline) {
        if (integration->metrics().total_requests > requests_before) {
            entered = true;
            break;
        }
        if (operation.wait_for(std::chrono::milliseconds(0)) ==
                std::future_status::ready)
            break;
        std::this_thread::yield();
    }
    source.request_cancel();
    const auto requested = (std::max)(started, tick_ns());
    const auto response_deadline = clock_t::now() +
        std::chrono::milliseconds(budget_ms);
    const bool ready_by_deadline = operation.wait_until(response_deadline) ==
        std::future_status::ready;
    auto observation = operation.get();
    const auto ended = ended_after(requested);
    const auto budget_ns = budget_ms >
        (std::numeric_limits<std::uint64_t>::max)() / 1000000ULL
        ? (std::numeric_limits<std::uint64_t>::max)()
        : budget_ms * 1000000ULL;
    const bool cancelled = observation.cancelled && entered && ready_by_deadline &&
        ended - requested <= budget_ns;
    return make_cancellation_json(true, cancelled ? "measured" : "failed",
        cancelled ? "production typed pipeline observed cancellation" :
            "production typed pipeline did not report cancellation",
        started, requested, ended,
        cancelled ? "cancelled" : "provider_failure",
        observation.diagnostics.finish());
}

json run_candidate_fixture(
    const provider_fixture_t& fixture,
    const std::filesystem::path& runtime_root,
    const std::uint64_t deadline_ms,
    std::set<std::string, std::less<>>& observed_roles,
    std::optional<json>& cancellation,
    provider_evidence_budget_t& evidence_budget)
{
    try {
        auto units = make_workspace_units(fixture,
            "c03-provider-candidate-" + fixture.id, runtime_root);
        auto fixture_json = base_fixture_json(fixture, "measured",
            "two cache-bypassed production typed-pipeline runs completed");
        for (std::uint32_t ordinal = 1; ordinal <= 2; ++ordinal) {
            const bool reverse = ordinal == 2;
            const auto started = tick_ns();
            stage_bundles_t bundles(evidence_budget);
            fact_accumulator_t facts(evidence_budget);
            readability_accumulator_t readability(evidence_budget);
            diagnostic_accumulator_t diagnostics(evidence_budget,
                diagnostic_scope_t::run);
            for (const auto scheduled : scheduled_entities(units, false, reverse)) {
                    auto result = scheduled.unit->integration->decompile_entity(
                        *scheduled.entity,
                        decompiler_ui_invocation_source_t::api_call,
                        decompiler_profile_id_t::balanced,
                        decompiler_pipeline_cache_mode_t::bypass);
                    if (!result)
                        throw matrix_error_t(result.error().stable_code() + ":" +
                            result.error().message);
                    const auto& value = result.value();
                    const auto candidate_detail = [&]() {
                        if (!value.diagnostics.empty()) {
                            const auto& diagnostic = value.diagnostics.front();
                            if (!diagnostic.message.empty())
                                return diagnostic.localization_key + ":" + diagnostic.message;
                            return diagnostic.localization_key;
                        }
                        return std::string{"no diagnostic"};
                    }();
                    if (!value.succeeded())
                        throw matrix_error_t("production typed pipeline did not complete: status=" +
                            std::to_string(static_cast<unsigned>(value.status)) + ":" +
                            candidate_detail);
                    if (!value.provider)
                        throw matrix_error_t("production typed pipeline omitted provider: " +
                            candidate_detail);
                    if (!value.provider_stage)
                        throw matrix_error_t("production typed pipeline omitted provider stage: " +
                            candidate_detail);
                    if (!value.normalized_stage)
                        throw matrix_error_t("production typed pipeline omitted normalized stage: " +
                            candidate_detail);
                    if (!value.document)
                        throw matrix_error_t("production typed pipeline omitted document: " +
                            candidate_detail);
                    if (const auto role = worker_role(*value.provider))
                        observed_roles.insert(*role);
                    bundles.provider_ir.append(serialize_provider_ir(
                        value.provider_stage->provider_ir));
                    bundles.hir.append(serialize_hir_function(
                        value.normalized_stage->hir));
                    bundles.type_graph.append(serialize_type_graph(
                        value.normalized_stage->type_graph));
                    bundles.ast.append(serialize_typed_pseudocode_ast(
                        value.normalized_stage->ast));
                    bundles.document.append(serialize_decompiler_document(*value.document));
                    facts.provider_ir(value.provider_stage->provider_ir);
                    facts.hir(value.normalized_stage->hir);
                    facts.type_graph(value.normalized_stage->type_graph);
                    facts.ast(value.normalized_stage->ast);
                    facts.document(*value.document);
                    readability.append(*value.document, value.readability);
                    append_diagnostics(diagnostics, value.diagnostics);
            }
            const auto ended = ended_after(started);
            const auto run_id = "aida_typed_pipeline:" + fixture.id + ":" +
                std::to_string(ordinal) + ":" + std::to_string(started);
            fixture_json["runs"].push_back(make_run_json(run_id, started, ended,
                reverse ? "reverse_entity_order" : "forward_entity_order",
                "cache_bypass", bundles.artifacts(true, true, true, true, true, false),
                facts, readability, diagnostics.finish()));
        }
        if (!cancellation) {
            auto selected = select_cancellation_unit(units, false);
            if (selected.unit)
                cancellation = candidate_cancellation(selected.unit->integration,
                    std::move(selected.entities), deadline_ms, evidence_budget);
        }
        return fixture_json;
    } catch (const matrix_not_applicable_t& error) {
        return base_fixture_json(fixture, "not_applicable", error.what());
    } catch (const std::exception& error) {
        return base_fixture_json(fixture, "failed", error.what());
    }
}

std::uint64_t next_native_job_id() noexcept
{
    static std::atomic<std::uint64_t> next{1};
    const auto value = next.fetch_add(1, std::memory_order_relaxed);
    return value == 0 ? next.fetch_add(1, std::memory_order_relaxed) : value;
}

native_worker::native_worker_execution_result_t execute_native_job(
    const native_job_t& job,
    const native_worker::packaged_native_worker_runtime_t& runtime,
    const std::chrono::steady_clock::time_point deadline,
    std::function<bool()> cancellation_requested)
{
    if (!runtime.native_host)
        throw matrix_error_t("packaged native worker host is unavailable");
    native_worker::native_worker_execution_request_t request;
    request.job_id = next_native_job_id();
    request.cache_key = job.cache_key;
    request.profile = job.profile;
    request.snapshot = job.snapshot;
    request.deadline = deadline;
    request.cancellation_requested = std::move(cancellation_requested);
    request.request_printc_evidence = true;
    return runtime.native_host->execute(request);
}

json ghidra_cancellation(
    const generation_bound_decompiler_entity_t& entity,
    const analysis_workspace_t& workspace,
    const native_worker::packaged_native_worker_runtime_t& runtime,
    const std::uint64_t deadline_ms,
    provider_evidence_budget_t& evidence_budget)
{
    const auto preparation_deadline = clock_t::now() +
        std::chrono::milliseconds(deadline_ms);
    const auto job = make_native_job(entity, workspace, runtime,
        preparation_deadline);
    const auto budget_ms = (std::min)(deadline_ms, k_cancellation_budget_ms);
    const auto execution_deadline = clock_t::now() +
        std::chrono::milliseconds(deadline_ms);
    const auto entry_deadline = clock_t::now() +
        std::chrono::milliseconds(budget_ms);
    std::atomic_bool cancel_requested{false};
    std::atomic_bool callback_observed{false};
    const auto started = tick_ns();
    auto operation = std::async(std::launch::async,
        [&job, &runtime, execution_deadline, &cancel_requested,
         &callback_observed,
         &evidence_budget] {
            cancellation_observation_t observation(evidence_budget);
            constexpr std::size_t max_attempts = 8;
            for (std::size_t attempt = 0;
                 attempt < max_attempts &&
                 clock_t::now() < execution_deadline; ++attempt) {
                auto result = execute_native_job(job, runtime,
                    execution_deadline,
                    [&cancel_requested, &callback_observed] {
                        callback_observed.store(true, std::memory_order_release);
                        return cancel_requested.load(std::memory_order_acquire);
                    });
                append_diagnostics(observation.diagnostics, result.worker_diagnostics);
                append_diagnostics(observation.diagnostics, result.diagnostics);
                if (result.status ==
                        native_worker::native_worker_execution_status_t::cancelled) {
                    observation.cancelled = true;
                    break;
                }
                std::this_thread::yield();
            }
            return observation;
    });
    bool entered = false;
    while (clock_t::now() < entry_deadline) {
        if (callback_observed.load(std::memory_order_acquire)) {
            entered = true;
            break;
        }
        if (operation.wait_for(std::chrono::milliseconds(0)) ==
                std::future_status::ready)
            break;
        std::this_thread::yield();
    }
    cancel_requested.store(true, std::memory_order_release);
    const auto requested = (std::max)(started, tick_ns());
    const auto response_deadline = clock_t::now() +
        std::chrono::milliseconds(budget_ms);
    const bool ready_by_deadline = operation.wait_until(response_deadline) ==
        std::future_status::ready;
    auto observation = operation.get();
    const auto ended = ended_after(requested);
    const auto budget_ns = budget_ms >
        (std::numeric_limits<std::uint64_t>::max)() / 1000000ULL
        ? (std::numeric_limits<std::uint64_t>::max)()
        : budget_ms * 1000000ULL;
    const bool cancelled = entered && ready_by_deadline &&
        ended - requested <= budget_ns && observation.cancelled;
    return make_cancellation_json(true, cancelled ? "measured" : "failed",
        cancelled ? "verified native worker observed cancellation" :
            "verified native worker did not report cancellation",
        started, requested, ended,
        cancelled ? "cancelled" : "provider_failure",
        observation.diagnostics.finish());
}

json run_ghidra_fixture(
    const provider_fixture_t& fixture,
    const std::filesystem::path& runtime_root,
    const native_worker::packaged_native_worker_runtime_t& runtime,
    const std::uint64_t deadline_ms,
    std::set<std::string, std::less<>>& observed_roles,
    std::optional<json>& cancellation,
    provider_evidence_budget_t& evidence_budget)
{
    try {
        if (fixture_is_managed_only(fixture))
            return base_fixture_json(fixture, "not_applicable",
                "fixture contract is managed-only");
        auto units = make_workspace_units(fixture,
            "c03-provider-ghidra-" + fixture.id, runtime_root);
        std::size_t native_count = 0;
        for (const auto& unit : units)
            native_count += native_entities(unit.entities).size();
        if (native_count == 0)
            return base_fixture_json(fixture, "not_applicable",
                "fixture contains only managed decompiler entities");
        auto fixture_json = base_fixture_json(fixture, "measured",
            "two direct verified native-worker PrintC runs completed");
        for (std::uint32_t ordinal = 1; ordinal <= 2; ++ordinal) {
            const bool reverse = ordinal == 2;
            const auto started = tick_ns();
            stage_bundles_t bundles(evidence_budget);
            fact_accumulator_t facts(evidence_budget);
            readability_accumulator_t readability(evidence_budget);
            diagnostic_accumulator_t diagnostics(evidence_budget,
                diagnostic_scope_t::run);
            for (const auto scheduled : scheduled_entities(units, true, reverse)) {
                    const auto deadline = clock_t::now() +
                        std::chrono::milliseconds(deadline_ms);
                    const auto job = make_native_job(*scheduled.entity,
                        *scheduled.unit->scope->workspace(), runtime, deadline);
                    auto result = execute_native_job(job, runtime, deadline,
                        [] { return false; });
                    append_diagnostics(diagnostics, result.worker_diagnostics);
                    append_diagnostics(diagnostics, result.diagnostics);
                    const auto worker_detail = [&]() {
                        if (!result.diagnostics.empty()) {
                            const auto& diagnostic = result.diagnostics.front();
                            return diagnostic.phase + ":" + diagnostic.detail;
                        }
                        if (!result.worker_diagnostics.empty()) {
                            const auto& diagnostic = result.worker_diagnostics.front();
                            std::string detail = diagnostic.localization_key;
                            for (const auto& argument : diagnostic.localization_arguments)
                                detail.append(":").append(argument);
                            return detail;
                        }
                        return std::string{"no diagnostic"};
                    }();
                    if (result.status != native_worker::native_worker_execution_status_t::completed)
                        throw matrix_error_t("verified native worker did not complete: status=" +
                            std::to_string(static_cast<unsigned>(result.status)) + ":" +
                            worker_detail);
                    if (!result.document)
                        throw matrix_error_t("verified native worker omitted document: " + worker_detail);
                    if (result.provider_artifacts.empty())
                        throw matrix_error_t("verified native worker omitted provider artifacts: " + worker_detail);
                    if (!result.printc_evidence || result.printc_evidence->empty())
                        throw matrix_error_t("verified native worker omitted PrintC evidence: " + worker_detail);
                    if (result.document->ast.root_node_id == 0 || result.document->ast.nodes.empty())
                        throw matrix_error_t("verified native worker returned an invalid AST: " + worker_detail);
                    if (result.document->rendered_text.empty())
                        throw matrix_error_t("verified native worker returned empty rendered text: " + worker_detail);
                    if (result.worker_process_id == 0)
                        throw matrix_error_t("verified native worker omitted process identity: " + worker_detail);
                    if (result.manifest_hash != runtime.manifest_hash)
                        throw matrix_error_t("verified native worker manifest binding mismatch: " + worker_detail);
                    if (result.snapshot_hash != job.snapshot.hash)
                        throw matrix_error_t("verified native worker snapshot binding mismatch: " + worker_detail);
                    if (stable_serialization_hash(result.provider_artifacts) !=
                        result.provider_artifacts_hash)
                        throw matrix_error_t("verified native worker provider-artifact hash mismatch: " + worker_detail);
                    if (stable_serialization_hash(*result.printc_evidence) !=
                        result.printc_evidence_hash)
                        throw matrix_error_t("verified native worker PrintC hash mismatch: " + worker_detail);
                    std::vector<decompiler_diagnostic_t> decode_diagnostics;
                    auto decoded = ghidra_ir_adapter::deserialize_artifacts(
                        result.provider_artifacts, decode_diagnostics);
                    append_diagnostics(diagnostics, decode_diagnostics);
                    if (!decoded)
                        throw matrix_error_t("Ghidra typed provider artifacts failed decoding");
                    bundles.provider_ir.append(serialize_provider_ir(decoded->provider_ir));
                    bundles.hir.append(serialize_hir_function(decoded->hir));
                    bundles.type_graph.append(serialize_type_graph(decoded->type_graph));
                    bundles.ast.append(serialize_typed_pseudocode_ast(result.document->ast));
                    bundles.document.append(serialize_decompiler_document(*result.document));
                    bundles.printc.append(*result.printc_evidence);
                    facts.provider_ir(decoded->provider_ir);
                    facts.hir(decoded->hir);
                    facts.type_graph(decoded->type_graph);
                    facts.document(*result.document);
                    readability.append(*result.document);
                    observed_roles.insert("native");
            }
            const auto ended = ended_after(started);
            const auto run_id = "ghidra_printc:" + fixture.id + ":" +
                std::to_string(ordinal) + ":" + std::to_string(started);
            fixture_json["runs"].push_back(make_run_json(run_id, started, ended,
                reverse ? "reverse_entity_order" : "forward_entity_order",
                "cache_bypass", bundles.artifacts(true, true, true, true, true, true),
                facts, readability, diagnostics.finish()));
        }
        if (!cancellation) {
            auto selected = select_cancellation_unit(units, true);
            if (selected.unit && !selected.entities.empty())
                cancellation = ghidra_cancellation(selected.entities.front(),
                    *selected.unit->scope->workspace(), runtime, deadline_ms,
                    evidence_budget);
        }
        return fixture_json;
    } catch (const matrix_not_applicable_t& error) {
        return base_fixture_json(fixture, "not_applicable", error.what());
    } catch (const std::exception& error) {
        return base_fixture_json(fixture, "failed", error.what());
    }
}

json current_cancellation(
    std::vector<generation_bound_decompiler_entity_t> entities,
    const std::shared_ptr<analysis_workspace_t>& workspace,
    const std::uint64_t deadline_ms,
    provider_evidence_budget_t& evidence_budget)
{
    if (!workspace || !workspace->decompiler())
        return make_cancellation_json(true, "not_measured",
            "current AiDA decompiler service is unavailable", 0, 0, 0,
            "provider_failure", json::array());
    entities = cancellation_order(std::move(entities));
    if (entities.empty())
        return make_cancellation_json(true, "not_measured",
            "current AiDA cancellation entity set is empty", 0, 0, 0,
            "provider_failure", json::array());
    const auto budget_ms = (std::min)(deadline_ms, k_cancellation_budget_ms);
    const auto execution_deadline = clock_t::now() +
        std::chrono::milliseconds(deadline_ms);
    const auto entry_deadline = clock_t::now() +
        std::chrono::milliseconds(budget_ms);
    cancellation_source_t source(execution_deadline);
    const auto requests_before = workspace->decompiler()->snapshot().requests;
    const auto started = tick_ns();
    auto operation = std::async(std::launch::async,
        [&workspace, entities = std::move(entities), &source,
         execution_deadline,
         &evidence_budget] {
            cancellation_observation_t observation(evidence_budget);
            constexpr std::size_t max_attempts = 64;
            for (std::size_t attempt = 0;
                 attempt < max_attempts &&
                 clock_t::now() < execution_deadline; ++attempt) {
                const auto* native = std::get_if<native_decompiler_entity_identity_t>(
                    &entities[attempt % entities.size()].entity.identity);
                if (!native)
                    throw matrix_error_t("current AiDA cancellation set contains a non-native entity");
                decompiler_request_t request;
                request.use_memory_cache = false;
                request.use_persistent_cache = false;
                request.deadline = execution_deadline;
                request.publish_feedback = false;
                auto result = workspace->decompiler()->decompile(native->entry,
                    std::move(request), source.token());
                if (!result) {
                    observation.diagnostics.append(workspace_error_json(result.error()));
                    if (result.error().code == workspace_error_code_t::cancelled) {
                        observation.cancelled = true;
                        break;
                    }
                } else {
                    append_diagnostics(observation.diagnostics,
                        result.value().document.diagnostics);
                }
                std::this_thread::yield();
            }
            return observation;
    });
    bool entered = false;
    while (clock_t::now() < entry_deadline) {
        if (workspace->decompiler()->snapshot().requests > requests_before) {
            entered = true;
            break;
        }
        if (operation.wait_for(std::chrono::milliseconds(0)) ==
                std::future_status::ready)
            break;
        std::this_thread::yield();
    }
    source.request_cancel();
    const auto requested = (std::max)(started, tick_ns());
    const auto response_deadline = clock_t::now() +
        std::chrono::milliseconds(budget_ms);
    const bool ready_by_deadline = operation.wait_until(response_deadline) ==
        std::future_status::ready;
    auto observation = operation.get();
    const auto ended = ended_after(requested);
    const auto budget_ns = budget_ms >
        (std::numeric_limits<std::uint64_t>::max)() / 1000000ULL
        ? (std::numeric_limits<std::uint64_t>::max)()
        : budget_ms * 1000000ULL;
    const bool cancelled = entered && ready_by_deadline &&
        ended - requested <= budget_ns && observation.cancelled;
    return make_cancellation_json(true, cancelled ? "measured" : "failed",
        cancelled ? "current AiDA service observed cancellation" :
            "current AiDA service did not report cancellation",
        started, requested, ended,
        cancelled ? "cancelled" : "provider_failure",
        observation.diagnostics.finish());
}

json run_current_fixture(
    const provider_fixture_t& fixture,
    const std::filesystem::path& runtime_root,
    const std::uint64_t deadline_ms,
    std::optional<json>& cancellation,
    provider_evidence_budget_t& evidence_budget)
{
    try {
        if (fixture_is_managed_only(fixture))
            return base_fixture_json(fixture, "not_applicable",
                "fixture contract is managed-only");
        auto units = make_workspace_units(fixture,
            "c03-provider-current-" + fixture.id, runtime_root);
        std::size_t native_count = 0;
        for (const auto& unit : units)
            native_count += native_entities(unit.entities).size();
        if (native_count == 0)
            return base_fixture_json(fixture, "not_applicable",
                "fixture contains only managed decompiler entities");
        auto fixture_json = base_fixture_json(fixture, "measured",
            "two cache-disabled current AiDA in-process runs completed");
        for (std::uint32_t ordinal = 1; ordinal <= 2; ++ordinal) {
            const bool reverse = ordinal == 2;
            const auto started = tick_ns();
            stage_bundles_t bundles(evidence_budget);
            fact_accumulator_t facts(evidence_budget);
            readability_accumulator_t readability(evidence_budget);
            diagnostic_accumulator_t diagnostics(evidence_budget,
                diagnostic_scope_t::run);
            for (const auto scheduled : scheduled_entities(units, true, reverse)) {
                const auto service = scheduled.unit->scope->workspace()->decompiler();
                if (!service)
                    throw matrix_error_t("current AiDA decompiler service is unavailable");
                    const auto* native = std::get_if<native_decompiler_entity_identity_t>(
                        &scheduled.entity->entity.identity);
                    if (!native)
                        throw matrix_error_t("current AiDA received an invalid native entity");
                    decompiler_request_t request;
                    request.use_memory_cache = false;
                    request.use_persistent_cache = false;
                    request.deadline = clock_t::now() +
                        std::chrono::milliseconds(deadline_ms);
                    request.publish_feedback = false;
                    auto result = service->decompile(native->entry, request);
                    if (!result)
                        throw matrix_error_t(result.error().stable_code() + ":" +
                            result.error().message);
                    const auto& document = result.value().document;
                    if (document.ast.root_node_id == 0 || document.ast.nodes.empty() ||
                        document.rendered_text.empty())
                        throw matrix_error_t("current AiDA returned an empty document or AST");
                    bundles.ast.append(serialize_typed_pseudocode_ast(document.ast));
                    bundles.document.append(serialize_decompiler_document(document));
                    facts.document(document);
                    facts.unavailable("provider_ir",
                        "provider_ir:not_exposed_by_aida_current_public_api");
                    facts.unavailable("hir",
                        "hir:not_exposed_by_aida_current_public_api");
                    facts.unavailable("type_graph",
                        "type_graph:not_exposed_by_aida_current_public_api");
                    readability.append(document);
                    append_diagnostics(diagnostics, document.diagnostics);
            }
            const auto ended = ended_after(started);
            const auto run_id = "aida_current:" + fixture.id + ":" +
                std::to_string(ordinal) + ":" + std::to_string(started);
            fixture_json["runs"].push_back(make_run_json(run_id, started, ended,
                reverse ? "reverse_entity_order" : "forward_entity_order",
                "cache_bypass", bundles.artifacts(false, false, false, true, true, false),
                facts, readability, diagnostics.finish()));
        }
        if (!cancellation) {
            auto selected = select_cancellation_unit(units, true);
            if (selected.unit)
                cancellation = current_cancellation(std::move(selected.entities),
                    selected.unit->scope->workspace(), deadline_ms,
                    evidence_budget);
        }
        return fixture_json;
    } catch (const matrix_not_applicable_t& error) {
        return base_fixture_json(fixture, "not_applicable", error.what());
    } catch (const std::exception& error) {
        return base_fixture_json(fixture, "failed", error.what());
    }
}

json launch_audit_json(const runtime_identity_t& identity,
                       const std::set<std::string, std::less<>>& roles)
{
    json output = json::array();
    if (roles.find("native") != roles.end())
        output.push_back({{"image_sha256", identity.native_binary_sha256},
            {"image_role", "verified_worker"}, {"permitted", true}});
    if (roles.find("managed") != roles.end())
        output.push_back({{"image_sha256", identity.managed_binary_sha256},
            {"image_role", "verified_worker"}, {"permitted", true}});
    return output;
}

std::set<std::string, std::less<>> expected_worker_roles(
    const provider_selection_t provider)
{
    if (provider == provider_selection_t::candidate)
        return {"managed", "native"};
    if (provider == provider_selection_t::ghidra_printc)
        return {"native"};
    if (provider == provider_selection_t::aida_current)
        return {};
    throw matrix_error_t("all has no direct worker-role contract");
}

std::filesystem::path provider_output_path(
    const std::filesystem::path& output_root,
    const provider_selection_t provider)
{
    switch (provider) {
    case provider_selection_t::candidate:
        return output_root / "candidate.results.json";
    case provider_selection_t::ghidra_printc:
        return output_root / "ghidra-printc.results.json";
    case provider_selection_t::aida_current:
        return output_root / "aida-current.results.json";
    case provider_selection_t::all:
        break;
    }
    throw matrix_error_t("all has no single provider output path");
}

std::uint64_t bounded_json_size(const json& value,
                                const std::uint64_t limit)
{
    const auto serialized = value.dump();
    return serialized.size() > limit ? limit + 1 :
        static_cast<std::uint64_t>(serialized.size());
}

json execute_provider(
    const provider_selection_t provider,
    const std::filesystem::path& runtime_root,
    const std::uint64_t deadline_ms,
    const std::vector<provider_fixture_t>& fixtures_input,
    const json& corpus_identity,
    const runtime_identity_t& identity,
    const native_worker::packaged_native_worker_runtime_t& runtime)
{
    json fixtures = json::array();
    provider_evidence_budget_t evidence_budget;
    std::set<std::string, std::less<>> observed_roles;
    std::optional<json> cancellation;
    std::size_t measured = 0;
    std::size_t failed = 0;
    std::size_t not_applicable = 0;
    for (const auto& fixture : fixtures_input) {
        const auto budget_checkpoint = evidence_budget.checkpoint();
        json value;
        switch (provider) {
        case provider_selection_t::candidate:
            value = run_candidate_fixture(fixture, runtime_root,
                deadline_ms, observed_roles, cancellation, evidence_budget);
            break;
        case provider_selection_t::ghidra_printc:
            value = run_ghidra_fixture(fixture, runtime_root, runtime,
                deadline_ms, observed_roles, cancellation, evidence_budget);
            break;
        case provider_selection_t::aida_current:
            value = run_current_fixture(fixture, runtime_root,
                deadline_ms, cancellation, evidence_budget);
            break;
        case provider_selection_t::all:
            throw matrix_error_t("all cannot execute as an individual provider");
        }
        const auto status = value.at("status").get<std::string>();
        if (status == "measured")
            ++measured;
        else if (status == "failed") {
            ++failed;
            evidence_budget.restore(budget_checkpoint);
        } else if (status == "not_applicable") {
            ++not_applicable;
            evidence_budget.restore(budget_checkpoint);
        }
        fixtures.push_back(std::move(value));
    }
    if (!cancellation)
        cancellation = make_cancellation_json(true, "not_measured",
            "no applicable provider entity was available for cancellation",
            0, 0, 0, "provider_failure", json::array());
    const auto expected_roles = expected_worker_roles(provider);
    const auto expected_not_applicable = provider == provider_selection_t::candidate
        ? 0ULL : static_cast<std::uint64_t>(std::count_if(
            fixtures_input.begin(), fixtures_input.end(), [](const auto& fixture) {
                return fixture_is_managed_only(fixture);
            }));
    const auto expected_measured = static_cast<std::uint64_t>(fixtures_input.size()) -
        expected_not_applicable;
    const bool cancellation_measured = cancellation->at("status") == "measured" &&
        cancellation->at("outcome") == "cancelled";
    const bool complete = failed == 0 && measured == expected_measured &&
        not_applicable == expected_not_applicable && measured != 0 &&
        cancellation_measured && observed_roles == expected_roles;
    std::string status_reason;
    if (complete) {
        status_reason = "all required fixtures, identities, worker launches, and cancellation evidence were measured";
    } else if (measured == 0 && failed == 0) {
        status_reason = "the provider was not applicable to any materialized fixture";
    } else if (failed != 0) {
        status_reason = std::to_string(failed) + " required fixture measurements failed";
    } else if (!cancellation_measured) {
        status_reason = "provider cancellation was not measured";
    } else if (measured != expected_measured ||
               not_applicable != expected_not_applicable) {
        status_reason = "provider applicability does not match the corpus contract";
    } else {
        status_reason = "observed worker roles do not match the provider contract";
    }
    const auto status = complete ? "measured" :
        (measured == 0 && failed == 0 ? "not_measured" : "failed");
    json provider_run{{"provider", provider_name(provider)}, {"status", status},
        {"status_reason", bounded_contract_text(std::move(status_reason),
            "provider status_reason")},
        {"identity", identity_json(identity, &runtime, observed_roles)},
        {"corpus", corpus_identity}, {"fixtures", std::move(fixtures)},
        {"cancellation", std::move(*cancellation)},
        {"launch_audit", launch_audit_json(identity, observed_roles)}};
    json output{{"schema", "aida.c03.decompiler-provider-results"},
        {"schema_version", 3}, {"evidence_class", "measured_provider_output"},
        {"measurement_eligible", complete}, {"analysis_mode", "static_only"},
        {"target_execution_forbidden", true},
        {"target_execution_observed", false},
        {"provider_run", std::move(provider_run)}};
    if (bounded_json_size(output, k_max_result_bytes - 1) >
            k_max_result_bytes - 1) {
        auto& run = output["provider_run"];
        for (auto& fixture : run["fixtures"]) {
            if (fixture["status"] == "measured") {
                fixture["status"] = "failed";
                fixture["status_reason"] =
                    "raw provider evidence exceeded the 128 MiB result-file bound";
                fixture["runs"] = json::array();
            }
        }
        run["status"] = "failed";
        run["status_reason"] =
            "raw provider evidence exceeded the 128 MiB result-file bound";
        output["measurement_eligible"] = false;
        if (bounded_json_size(output, k_max_result_bytes - 1) >
                k_max_result_bytes - 1)
            throw matrix_error_t("bounded provider failure evidence exceeds the result-file limit");
    }
    const auto validation = validate_decompiler_provider_results(output);
    if (!validation.valid)
        throw matrix_error_t(validation.summary());
    return output;
}

}

matrix_result_t run(const matrix_config_t& input)
{
    matrix_result_t result;
    try {
        matrix_config_t config = input;
        config.repository_root = canonical_path(config.repository_root);
        config.runtime_root = canonical_path(config.runtime_root);
        config.materialized_root = canonical_path(config.materialized_root);
        config.output_root = canonical_path(config.output_root);
        if (!std::filesystem::is_directory(config.repository_root) ||
            !std::filesystem::is_directory(config.runtime_root) ||
            config.deadline_ms < 1000 || config.deadline_ms > 3600000)
            throw matrix_error_t("provider-matrix configuration is invalid");
        auto corpus = prepare_corpus(config);
        if (corpus.fixtures.size() != 48)
            throw matrix_error_t("provider matrix requires the complete 48-fixture corpus");
        auto identity = load_runtime_identity(config.runtime_root);
        if (!identity.complete())
            throw matrix_error_t("provider runtime identity is incomplete: " + identity.error);
        auto runtime_result = native_worker::create_packaged_native_worker_runtime(
            config.runtime_root);
        if (!runtime_result)
            throw matrix_error_t(runtime_result.error().stable_code() + ":" +
                runtime_result.error().message);
        auto runtime = runtime_result.take_value();
        if (!runtime.native_host || !runtime.provider_host ||
            runtime.worker_protocol_version != k_decompiler_worker_protocol_version ||
            runtime.worker_protocol_hash != native_worker::native_worker_protocol_hash() ||
            runtime.manifest_hash.to_hex() != identity.native_manifest_sha256 ||
            runtime.managed_manifest_hash.to_hex() != identity.managed_manifest_sha256 ||
            runtime.managed_runtime_manifest_hash.to_hex() !=
                identity.managed_runtime_manifest_sha256)
            throw matrix_error_t("packaged worker runtime identity differs from hashed disk evidence");
        const auto receipt_path = config.output_root / "materialization.receipt.json";
        write_json_atomic(receipt_path, corpus.materialization.receipt);
        result.output_files.push_back(receipt_path);
        std::vector<provider_selection_t> providers;
        if (config.provider == provider_selection_t::all) {
            providers = {provider_selection_t::candidate,
                provider_selection_t::ghidra_printc,
                provider_selection_t::aida_current};
        } else {
            providers.push_back(config.provider);
        }
        bool all_measured = true;
        for (const auto provider : providers) {
            const auto evidence = execute_provider(provider, config.runtime_root,
                config.deadline_ms, corpus.fixtures,
                corpus.identity, identity, runtime);
            const auto output_path = provider_output_path(config.output_root, provider);
            write_json_atomic(output_path, evidence);
            result.output_files.push_back(output_path);
            all_measured = all_measured && evidence.at("measurement_eligible").get<bool>();
        }
        result.exit_code = all_measured ? 0 : 4;
        if (!all_measured)
            result.error = "one or more required provider measurements did not complete";
    } catch (const std::exception& error) {
        result.exit_code = 3;
        result.error = error.what();
    }
    return result;
}

}
