#include "benchmark_sla_receipt.hpp"

#include "evidence_hash.hpp"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <fstream>
#include <limits>
#include <set>
#include <string_view>
#include <vector>

namespace aida::analysis::c03
{
namespace
{
struct image_qualification_t
{
    bool ok = false;
    bool pdb = false;
    bool static_library = false;
    bool code_image = false;
    std::string format;
    std::string architecture;
    std::string mode;
    std::string endian;
    std::uint64_t size_bytes = 0;
    std::uint64_t executable_bytes = 0;
    std::uint64_t zero_bytes = 0;
    std::string error;
};

benchmark_receipt_build_result_t failure(std::string error)
{
    return {false, {}, std::move(error)};
}

bool safe_relative_path(std::string_view value)
{
    if (value.empty())
        return false;
    const auto path = std::filesystem::u8path(std::string(value));
    if (path.is_absolute() || path.has_root_name())
        return false;
    for (const auto& part : path) {
        if (part == "..")
            return false;
    }
    return true;
}

std::filesystem::path evidence_path(const std::filesystem::path& root, std::string_view relative)
{
    if (!safe_relative_path(relative))
        return {};
    std::error_code error;
    const auto canonical_root = std::filesystem::weakly_canonical(root, error);
    if (error || !std::filesystem::is_directory(canonical_root))
        return {};
    const auto candidate = std::filesystem::weakly_canonical(
        canonical_root / std::filesystem::u8path(std::string(relative)), error);
    if (error)
        return {};
    const auto inside = std::filesystem::relative(candidate, canonical_root, error);
    if (error || inside.empty() || inside.is_absolute() ||
        (inside.begin() != inside.end() && *inside.begin() == ".."))
        return {};
    return candidate;
}

bool load_json_file(const std::filesystem::path& root, std::string_view relative,
    std::uint64_t maximum_bytes, json& value, std::string& error)
{
    const auto path = evidence_path(root, relative);
    if (path.empty()) {
        error = "JSON evidence path is outside the evidence root";
        return false;
    }
    std::error_code filesystem_error;
    const auto size = std::filesystem::file_size(path, filesystem_error);
    if (filesystem_error || size == 0 || size > maximum_bytes) {
        error = "JSON evidence size is invalid";
        return false;
    }
    std::ifstream stream(path, std::ios::binary);
    if (!stream) {
        error = "cannot open JSON evidence";
        return false;
    }
    try {
        stream >> value;
    } catch (const json::exception& exception) {
        error = std::string("invalid JSON evidence: ") + exception.what();
        return false;
    }
    if (!stream || !value.is_object()) {
        error = "JSON evidence root must be an object";
        return false;
    }
    return true;
}

std::uint16_t read_u16(const std::vector<std::uint8_t>& bytes, std::size_t offset, bool little, bool& ok)
{
    if (offset > bytes.size() || bytes.size() - offset < 2U) {
        ok = false;
        return 0;
    }
    if (little)
        return static_cast<std::uint16_t>(bytes[offset]) |
            static_cast<std::uint16_t>(bytes[offset + 1U] << 8U);
    return static_cast<std::uint16_t>(bytes[offset] << 8U) |
        static_cast<std::uint16_t>(bytes[offset + 1U]);
}

std::uint32_t read_u32(const std::vector<std::uint8_t>& bytes, std::size_t offset, bool little, bool& ok)
{
    if (offset > bytes.size() || bytes.size() - offset < 4U) {
        ok = false;
        return 0;
    }
    std::uint32_t value = 0;
    for (std::size_t index = 0; index < 4U; ++index) {
        const std::size_t source = little ? offset + index : offset + 3U - index;
        value |= static_cast<std::uint32_t>(bytes[source]) << (index * 8U);
    }
    return value;
}

std::uint64_t read_u64(const std::vector<std::uint8_t>& bytes, std::size_t offset, bool little, bool& ok)
{
    if (offset > bytes.size() || bytes.size() - offset < 8U) {
        ok = false;
        return 0;
    }
    std::uint64_t value = 0;
    for (std::size_t index = 0; index < 8U; ++index) {
        const std::size_t source = little ? offset + index : offset + 7U - index;
        value |= static_cast<std::uint64_t>(bytes[source]) << (index * 8U);
    }
    return value;
}

std::uint64_t interval_bytes(std::vector<std::pair<std::uint64_t, std::uint64_t>> intervals,
    std::uint64_t file_size)
{
    for (auto& interval : intervals) {
        interval.first = std::min(interval.first, file_size);
        interval.second = std::min(interval.second, file_size);
        if (interval.second < interval.first)
            interval.second = interval.first;
    }
    std::sort(intervals.begin(), intervals.end());
    std::uint64_t total = 0;
    std::uint64_t begin = 0;
    std::uint64_t end = 0;
    bool active = false;
    for (const auto& interval : intervals) {
        if (interval.first == interval.second)
            continue;
        if (!active) {
            begin = interval.first;
            end = interval.second;
            active = true;
            continue;
        }
        if (interval.first <= end) {
            end = std::max(end, interval.second);
            continue;
        }
        total += end - begin;
        begin = interval.first;
        end = interval.second;
    }
    if (active)
        total += end - begin;
    return total;
}

std::string pe_architecture(std::uint16_t machine)
{
    switch (machine) {
    case 0x014c: return "x86";
    case 0x8664: return "x64";
    case 0x01c0:
    case 0x01c4: return "arm";
    case 0xaa64: return "aarch64";
    case 0xa641: return "arm64ec";
    default: return "machine-" + std::to_string(machine);
    }
}

bool qualify_pe(const std::vector<std::uint8_t>& bytes, std::uint64_t file_size,
    image_qualification_t& result)
{
    if (bytes.size() < 0x40U || bytes[0] != 'M' || bytes[1] != 'Z')
        return false;
    bool ok = true;
    const auto pe_offset = static_cast<std::size_t>(read_u32(bytes, 0x3cU, true, ok));
    if (!ok || pe_offset > bytes.size() || bytes.size() - pe_offset < 24U ||
        bytes[pe_offset] != 'P' || bytes[pe_offset + 1U] != 'E' ||
        bytes[pe_offset + 2U] != 0 || bytes[pe_offset + 3U] != 0) {
        result.error = "invalid PE header";
        return true;
    }
    const auto machine = read_u16(bytes, pe_offset + 4U, true, ok);
    const auto section_count = read_u16(bytes, pe_offset + 6U, true, ok);
    const auto optional_size = read_u16(bytes, pe_offset + 20U, true, ok);
    const auto optional_offset = pe_offset + 24U;
    const auto magic = read_u16(bytes, optional_offset, true, ok);
    if (!ok || section_count == 0 || section_count > 4096U ||
        (magic != 0x10bU && magic != 0x20bU)) {
        result.error = "invalid PE image metadata";
        return true;
    }
    const auto table = optional_offset + optional_size;
    if (table > bytes.size() || static_cast<std::size_t>(section_count) > (bytes.size() - table) / 40U) {
        result.error = "PE section table exceeds bounded header capture";
        return true;
    }
    std::vector<std::pair<std::uint64_t, std::uint64_t>> executable;
    for (std::size_t index = 0; index < section_count; ++index) {
        const auto offset = table + index * 40U;
        const auto raw_size = read_u32(bytes, offset + 16U, true, ok);
        const auto raw_offset = read_u32(bytes, offset + 20U, true, ok);
        const auto characteristics = read_u32(bytes, offset + 36U, true, ok);
        if (!ok) {
            result.error = "invalid PE section record";
            return true;
        }
        if ((characteristics & 0x20000000U) != 0 && raw_size != 0)
            executable.emplace_back(raw_offset, static_cast<std::uint64_t>(raw_offset) + raw_size);
    }
    result.code_image = true;
    result.format = magic == 0x20bU ? "pe32plus" : "pe32";
    result.architecture = pe_architecture(machine);
    result.mode = magic == 0x20bU ? "64" : "32";
    result.endian = "little";
    result.executable_bytes = interval_bytes(std::move(executable), file_size);
    result.ok = result.executable_bytes != 0;
    if (!result.ok)
        result.error = "PE image has no file-backed executable range";
    return true;
}

std::string elf_architecture(std::uint16_t machine)
{
    switch (machine) {
    case 3: return "x86";
    case 8: return "mips";
    case 20: return "powerpc";
    case 21: return "powerpc64";
    case 40: return "arm";
    case 62: return "x64";
    case 183: return "aarch64";
    case 243: return "riscv";
    default: return "machine-" + std::to_string(machine);
    }
}

bool qualify_elf(const std::vector<std::uint8_t>& bytes, std::uint64_t file_size,
    image_qualification_t& result)
{
    if (bytes.size() < 16U || bytes[0] != 0x7fU || bytes[1] != 'E' || bytes[2] != 'L' || bytes[3] != 'F')
        return false;
    const bool is64 = bytes[4] == 2U;
    const bool is32 = bytes[4] == 1U;
    const bool little = bytes[5] == 1U;
    if ((!is32 && !is64) || (!little && bytes[5] != 2U)) {
        result.error = "unsupported ELF identity";
        return true;
    }
    bool ok = true;
    const auto machine = read_u16(bytes, 18U, little, ok);
    const auto program_offset = is64 ? read_u64(bytes, 32U, little, ok) : read_u32(bytes, 28U, little, ok);
    const auto program_entry_size = read_u16(bytes, is64 ? 54U : 42U, little, ok);
    const auto program_count = read_u16(bytes, is64 ? 56U : 44U, little, ok);
    if (!ok || program_count == 0 || program_count > 4096U || program_entry_size < (is64 ? 56U : 32U) ||
        program_offset > bytes.size() || static_cast<std::uint64_t>(program_count) >
            (bytes.size() - static_cast<std::size_t>(program_offset)) / program_entry_size) {
        result.error = "ELF program table exceeds bounded header capture";
        return true;
    }
    std::vector<std::pair<std::uint64_t, std::uint64_t>> executable;
    for (std::size_t index = 0; index < program_count; ++index) {
        const auto offset = static_cast<std::size_t>(program_offset) + index * program_entry_size;
        const auto type = read_u32(bytes, offset, little, ok);
        const auto flags = read_u32(bytes, offset + (is64 ? 4U : 24U), little, ok);
        const auto file_offset = is64 ? read_u64(bytes, offset + 8U, little, ok) : read_u32(bytes, offset + 4U, little, ok);
        const auto file_bytes = is64 ? read_u64(bytes, offset + 32U, little, ok) : read_u32(bytes, offset + 16U, little, ok);
        if (!ok) {
            result.error = "invalid ELF program record";
            return true;
        }
        if (type == 1U && (flags & 1U) != 0 && file_bytes != 0 && file_offset <=
            (std::numeric_limits<std::uint64_t>::max)() - file_bytes)
            executable.emplace_back(file_offset, file_offset + file_bytes);
    }
    result.code_image = true;
    result.format = is64 ? "elf64" : "elf32";
    result.architecture = elf_architecture(machine);
    result.mode = is64 ? "64" : "32";
    result.endian = little ? "little" : "big";
    result.executable_bytes = interval_bytes(std::move(executable), file_size);
    result.ok = result.executable_bytes != 0;
    if (!result.ok)
        result.error = "ELF image has no file-backed executable load range";
    return true;
}

std::string macho_architecture(std::uint32_t cpu)
{
    const auto base = cpu & 0x00ffffffU;
    if (base == 7U)
        return (cpu & 0x01000000U) != 0 ? "x64" : "x86";
    if (base == 12U)
        return (cpu & 0x01000000U) != 0 ? "aarch64" : "arm";
    if (base == 18U)
        return (cpu & 0x01000000U) != 0 ? "powerpc64" : "powerpc";
    return "cpu-" + std::to_string(cpu);
}

bool qualify_macho(const std::vector<std::uint8_t>& bytes, std::uint64_t file_size,
    image_qualification_t& result)
{
    if (bytes.size() < 32U)
        return false;
    bool ignored = true;
    const auto magic_little = read_u32(bytes, 0, true, ignored);
    bool little = true;
    bool is64 = false;
    if (magic_little == 0xfeedfaceU)
        is64 = false;
    else if (magic_little == 0xfeedfacfU)
        is64 = true;
    else if (magic_little == 0xcefaedfeU) {
        little = false;
        is64 = false;
    } else if (magic_little == 0xcffaedfeU) {
        little = false;
        is64 = true;
    } else {
        return false;
    }
    bool ok = true;
    const auto cpu = read_u32(bytes, 4U, little, ok);
    const auto command_count = read_u32(bytes, 16U, little, ok);
    const auto command_bytes = read_u32(bytes, 20U, little, ok);
    std::size_t offset = is64 ? 32U : 28U;
    if (!ok || command_count > 65536U || command_bytes > bytes.size() - offset) {
        result.error = "Mach-O load commands exceed bounded header capture";
        return true;
    }
    std::vector<std::pair<std::uint64_t, std::uint64_t>> executable;
    for (std::uint32_t index = 0; index < command_count; ++index) {
        const auto command = read_u32(bytes, offset, little, ok);
        const auto size = read_u32(bytes, offset + 4U, little, ok);
        if (!ok || size < 8U || offset > bytes.size() || size > bytes.size() - offset) {
            result.error = "invalid Mach-O load command";
            return true;
        }
        if ((command == 1U && !is64 && size >= 56U) || (command == 0x19U && is64 && size >= 72U)) {
            const auto file_offset = is64 ? read_u64(bytes, offset + 40U, little, ok) : read_u32(bytes, offset + 32U, little, ok);
            const auto file_bytes = is64 ? read_u64(bytes, offset + 48U, little, ok) : read_u32(bytes, offset + 36U, little, ok);
            const auto initial_protection = read_u32(bytes, offset + (is64 ? 60U : 44U), little, ok);
            if (!ok) {
                result.error = "invalid Mach-O segment command";
                return true;
            }
            if ((initial_protection & 4U) != 0 && file_bytes != 0 && file_offset <=
                (std::numeric_limits<std::uint64_t>::max)() - file_bytes)
                executable.emplace_back(file_offset, file_offset + file_bytes);
        }
        offset += size;
    }
    result.code_image = true;
    result.format = is64 ? "macho64" : "macho32";
    result.architecture = macho_architecture(cpu);
    result.mode = is64 ? "64" : "32";
    result.endian = little ? "little" : "big";
    result.executable_bytes = interval_bytes(std::move(executable), file_size);
    result.ok = result.executable_bytes != 0;
    if (!result.ok)
        result.error = "Mach-O image has no file-backed executable segment";
    return true;
}

image_qualification_t qualify_image(const std::filesystem::path& path)
{
    image_qualification_t result;
    std::error_code error;
    result.size_bytes = std::filesystem::file_size(path, error);
    if (error || result.size_bytes == 0) {
        result.error = "benchmark artifact size is unavailable";
        return result;
    }
    constexpr std::uint64_t header_limit = 16ULL * 1024ULL * 1024ULL;
    const auto prefix_size = static_cast<std::size_t>(std::min(result.size_bytes, header_limit));
    std::vector<std::uint8_t> prefix(prefix_size);
    std::ifstream stream(path, std::ios::binary);
    if (!stream) {
        result.error = "cannot open benchmark artifact";
        return result;
    }
    stream.read(reinterpret_cast<char*>(prefix.data()), static_cast<std::streamsize>(prefix.size()));
    if (stream.gcount() != static_cast<std::streamsize>(prefix.size())) {
        result.error = "benchmark artifact header read was incomplete";
        return result;
    }
    if (prefix.size() >= 24U && std::equal(prefix.begin(), prefix.begin() + 24U,
        reinterpret_cast<const std::uint8_t*>("Microsoft C/C++ MSF 7.00"))) {
        result.pdb = true;
        result.error = "PDB files cannot satisfy benchmark code-image evidence";
        return result;
    }
    if (prefix.size() >= 8U && std::equal(prefix.begin(), prefix.begin() + 8U,
        reinterpret_cast<const std::uint8_t*>("!<arch>\n"))) {
        result.static_library = true;
        result.error = "static libraries cannot satisfy benchmark code-image evidence";
        return result;
    }
    bool recognized = qualify_pe(prefix, result.size_bytes, result);
    if (!recognized)
        recognized = qualify_elf(prefix, result.size_bytes, result);
    if (!recognized)
        recognized = qualify_macho(prefix, result.size_bytes, result);
    if (!recognized) {
        result.error = "benchmark artifact is not a supported regular production code image";
        return result;
    }
    stream.clear();
    stream.seekg(0, std::ios::beg);
    std::array<char, 1024 * 1024> buffer{};
    std::uint64_t consumed = 0;
    while (stream) {
        stream.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
        const auto count = stream.gcount();
        if (count <= 0)
            break;
        consumed += static_cast<std::uint64_t>(count);
        result.zero_bytes += static_cast<std::uint64_t>(std::count(buffer.begin(), buffer.begin() + count, '\0'));
    }
    if (stream.bad() || consumed != result.size_bytes) {
        result.ok = false;
        result.error = "benchmark artifact changed or failed while scanning";
    }
    return result;
}

bool required_string(const json& object, std::string_view name, std::string& value)
{
    const auto iterator = object.find(std::string(name));
    if (iterator == object.end() || !iterator->is_string() || iterator->get_ref<const std::string&>().empty())
        return false;
    value = iterator->get<std::string>();
    return true;
}

bool required_u64(const json& object, std::string_view name, std::uint64_t& value)
{
    const auto iterator = object.find(std::string(name));
    if (iterator == object.end() || (!iterator->is_number_unsigned() &&
        (!iterator->is_number_integer() || iterator->get<std::int64_t>() < 0)))
        return false;
    value = iterator->get<std::uint64_t>();
    return true;
}

bool make_binding(const std::filesystem::path& root, const json& record,
    std::string_view id, std::string_view kind, json& binding, std::string& error)
{
    std::string path;
    std::uint64_t maximum = 0;
    if (!record.is_object() || !required_string(record, "path", path) ||
        !required_u64(record, "max_bytes", maximum) || maximum == 0 ||
        maximum > 4ULL * 1024ULL * 1024ULL * 1024ULL) {
        error = "evidence binding record is incomplete or unbounded";
        return false;
    }
    const auto hash = sha256_repository_evidence_file(root, path, maximum);
    if (!hash.ok) {
        error = hash.error;
        return false;
    }
    binding = {{"id", id}, {"kind", kind}, {"path", path},
        {"sha256", hash.sha256}, {"max_bytes", maximum}};
    return true;
}

double median(std::vector<double> values)
{
    if (values.empty())
        return 0.0;
    std::sort(values.begin(), values.end());
    const auto middle = values.size() / 2U;
    return values.size() % 2U == 0 ? (values[middle - 1U] + values[middle]) / 2.0 : values[middle];
}

double p95(std::vector<double> values)
{
    if (values.empty())
        return 0.0;
    std::sort(values.begin(), values.end());
    const auto rank = std::max<std::size_t>(1U,
        static_cast<std::size_t>(std::ceil(static_cast<double>(values.size()) * 0.95)));
    return values[rank - 1U];
}

bool numeric(const json& value)
{
    return value.is_number() && std::isfinite(value.get<double>()) && value.get<double>() >= 0.0;
}

bool unsigned_value(const json& value)
{
    return value.is_number_unsigned() || (value.is_number_integer() && value.get<std::int64_t>() >= 0);
}

json aggregate_samples(const json& samples, std::string& error)
{
    std::vector<double> warm_analysis;
    std::vector<double> metadata;
    std::vector<double> reopen;
    std::vector<double> query;
    std::vector<double> cancellation;
    std::array<std::uint64_t, 8> totals{};
    for (const auto& sample : samples) {
        if (!sample.is_object()) {
            error = "raw benchmark sample is not an object";
            return {};
        }
        for (const auto field : {"analysis_ms", "metadata_ready_ms", "warm_reopen_ms", "query_ms", "cancellation_response_ms"}) {
            if (!sample.contains(field) || !numeric(sample.at(field))) {
                error = std::string("raw benchmark sample lacks numeric field ") + field;
                return {};
            }
        }
        if (sample.value("cache_state", std::string{}) == "warm")
            warm_analysis.push_back(sample.at("analysis_ms").get<double>());
        metadata.push_back(sample.at("metadata_ready_ms").get<double>());
        reopen.push_back(sample.at("warm_reopen_ms").get<double>());
        query.push_back(sample.at("query_ms").get<double>());
        cancellation.push_back(sample.at("cancellation_response_ms").get<double>());
        if (!sample.contains("memory") || !sample.at("memory").is_object()) {
            error = "raw benchmark sample lacks memory evidence";
            return {};
        }
        const auto& memory = sample.at("memory");
        const std::array<const char*, 8> fields{"private_bytes", "resident_bytes", "workspace_mapped_bytes",
            "global_mapped_bytes", "cache_bytes", "spill_bytes", "spill_written_bytes", "spill_read_bytes"};
        for (std::size_t index = 0; index < fields.size(); ++index) {
            if (!memory.contains(fields[index]) || !unsigned_value(memory.at(fields[index]))) {
                error = std::string("raw benchmark sample lacks memory field ") + fields[index];
                return {};
            }
            const auto value = memory.at(fields[index]).get<std::uint64_t>();
            if (index < 6U)
                totals[index] = std::max(totals[index], value);
            else if (value > (std::numeric_limits<std::uint64_t>::max)() - totals[index]) {
                error = "raw benchmark spill aggregate overflowed";
                return {};
            } else {
                totals[index] += value;
            }
        }
    }
    return {{"warm_analysis_p50_ms", median(warm_analysis)},
        {"warm_analysis_max_ms", warm_analysis.empty() ? 0.0 : *std::max_element(warm_analysis.begin(), warm_analysis.end())},
        {"metadata_ready_max_ms", metadata.empty() ? 0.0 : *std::max_element(metadata.begin(), metadata.end())},
        {"warm_reopen_max_ms", reopen.empty() ? 0.0 : *std::max_element(reopen.begin(), reopen.end())},
        {"indexed_query_p95_ms", p95(query)}, {"cancellation_p95_ms", p95(cancellation)},
        {"private_peak_bytes", totals[0]}, {"resident_peak_bytes", totals[1]},
        {"workspace_mapped_peak_bytes", totals[2]}, {"global_mapped_peak_bytes", totals[3]},
        {"cache_peak_bytes", totals[4]}, {"spill_peak_bytes", totals[5]},
        {"spill_written_total_bytes", totals[6]}, {"spill_read_total_bytes", totals[7]}};
}

std::string validation_failure(const contract_validation_result_t& validation)
{
    std::string error = "benchmark receipt validation failed";
    for (const auto& violation : validation.violations)
        error += "\n" + violation.path + ":" + violation.code + ":" + violation.message;
    return error;
}

bool finalize_receipt(json& receipt, const std::filesystem::path& evidence_root,
    benchmark_receipt_build_result_t& output)
{
    const auto hash = canonical_json_sha256(receipt, "receipt_sha256");
    if (!hash.ok) {
        output = failure(hash.error);
        return false;
    }
    receipt["receipt_sha256"] = hash.sha256;
    const auto validation = validate_benchmark_sla_receipt_files(receipt, approved_external_sla_slot(), evidence_root);
    if (!validation.valid) {
        output = failure(validation_failure(validation));
        return false;
    }
    output = {true, receipt, {}};
    return true;
}
}

benchmark_receipt_build_result_t build_benchmark_sla_receipt(
    const std::filesystem::path& evidence_root, std::string_view measurement_manifest_path)
{
    json input;
    std::string error;
    if (!load_json_file(evidence_root, measurement_manifest_path, 16ULL * 1024ULL * 1024ULL, input, error))
        return failure(std::move(error));
    if (input.value("schema", std::string{}) != "aida.c03.benchmark-measurement-input" ||
        input.value("schema_version", 0) != 1 || !input.value("target_execution_forbidden", false))
        return failure("benchmark measurement input schema or target non-execution contract is invalid");
    const auto mode = input.value("mode", std::string{});
    if (mode != "deterministic_component" && mode != "release_sla")
        return failure("benchmark measurement mode is invalid");
    const bool release = mode == "release_sla";
    if (!input.contains("evidence") || !input.at("evidence").is_object() ||
        !input.contains("artifact") || !input.at("artifact").is_object())
        return failure("benchmark measurement evidence or artifact record is absent");
    const auto& evidence = input.at("evidence");
    const auto& artifact_input = input.at("artifact");
    for (const auto field : {"harness", "runtime", "source_provenance"}) {
        if (!evidence.contains(field))
            return failure(std::string("benchmark evidence is missing ") + field);
    }
    json bindings = json::array();
    json binding;
    if (!make_binding(evidence_root, evidence.at("harness"), "benchmark-harness", "executable", binding, error))
        return failure(std::move(error));
    bindings.push_back(binding);
    const auto harness_hash = binding.at("sha256");
    if (!make_binding(evidence_root, evidence.at("runtime"), "analysis-runtime", "executable", binding, error))
        return failure(std::move(error));
    bindings.push_back(binding);
    const auto runtime_hash = binding.at("sha256");
    if (!make_binding(evidence_root, evidence.at("source_provenance"), "corpus-source", "provenance", binding, error))
        return failure(std::move(error));
    bindings.push_back(binding);
    const auto source_hash = binding.at("sha256");
    json manifest_record{{"path", measurement_manifest_path}, {"max_bytes", 16ULL * 1024ULL * 1024ULL}};
    if (!make_binding(evidence_root, manifest_record, "measurement-manifest", "manifest", binding, error))
        return failure(std::move(error));
    bindings.push_back(binding);
    const auto manifest_hash = binding.at("sha256");
    json artifact_binding_record{{"path", artifact_input.value("path", std::string{})},
        {"max_bytes", artifact_input.value("max_bytes", 0ULL)}};
    if (!make_binding(evidence_root, artifact_binding_record, "benchmark-artifact", "target-static-bytes", binding, error))
        return failure(std::move(error));
    bindings.push_back(binding);
    const auto artifact_hash = binding.at("sha256");
    const auto artifact_path = evidence_path(evidence_root, artifact_input.value("path", std::string{}));
    if (artifact_path.empty())
        return failure("benchmark artifact path escapes the evidence root");
    auto qualified = qualify_image(artifact_path);
    if (!qualified.ok)
        return failure(qualified.error);
    const auto expected_format = artifact_input.value("format", std::string{});
    const auto expected_architecture = artifact_input.value("architecture", std::string{});
    const auto expected_mode = artifact_input.value("architecture_mode", std::string{});
    const auto expected_endian = artifact_input.value("endian", std::string{});
    if (expected_format != qualified.format || expected_architecture != qualified.architecture ||
        expected_mode != qualified.mode || expected_endian != qualified.endian)
        return failure("benchmark artifact identity disagrees with parsed code-image metadata");
    if (!artifact_input.value("redistribution", false) || artifact_input.value("installer_only", true) ||
        artifact_input.value("fabricated", true))
        return failure("benchmark artifact license or production attestation is invalid");
    const auto code_density = static_cast<double>(qualified.executable_bytes) /
        static_cast<double>(qualified.size_bytes);
    const auto zero_ratio = static_cast<double>(qualified.zero_bytes) /
        static_cast<double>(qualified.size_bytes);
    if (release) {
        const auto minimum = benchmark_sla_thresholds().at("release_min_artifact_bytes").get<std::uint64_t>();
        const auto maximum = benchmark_sla_thresholds().at("release_max_artifact_bytes").get<std::uint64_t>();
        if (qualified.size_bytes < minimum || qualified.size_bytes > maximum)
            return failure("release SLA requires a real 300-500 MB code image");
        if (qualified.executable_bytes < 64ULL * 1024ULL * 1024ULL || code_density < 0.10 || zero_ratio > 0.80)
            return failure("release SLA artifact fails executable-volume, density, or zero-padding qualification");
        if (source_hash != approved_external_sla_slot().at("generator_source").at("sha256"))
            return failure("release SLA source provenance does not bind the approved external slot policy");
    }
    if (!input.contains("samples") || !input.at("samples").is_array())
        return failure("benchmark measurement input has no raw samples");
    auto aggregate = aggregate_samples(input.at("samples"), error);
    if (!error.empty())
        return failure(std::move(error));
    const auto receipt_id = input.value("receipt_id", std::string{});
    const auto authorization = input.value("authorization_id", std::string{});
    const auto production_identity = artifact_input.value("production_identity", std::string{});
    const auto version = artifact_input.value("version", std::string{});
    const auto spdx = artifact_input.value("license_spdx", std::string{});
    if (receipt_id.empty() || authorization.empty() || production_identity.empty() || version.empty() || spdx.empty())
        return failure("benchmark identity, authorization, version, or license evidence is incomplete");
    json receipt{{"schema", "aida.c03.benchmark-sla-receipt"}, {"schema_version", 2},
        {"receipt_id", receipt_id}, {"mode", mode},
        {"claim_status", release ? "measured" : "development_only"},
        {"provenance", {{"authorization_id", authorization},
            {"harness_build_sha256", harness_hash}, {"runtime_build_sha256", runtime_hash},
            {"manifest_sha256", manifest_hash}, {"harness_binding_id", "benchmark-harness"},
            {"runtime_binding_id", "analysis-runtime"}, {"manifest_binding_id", "measurement-manifest"},
            {"evidence_bindings", bindings}}},
        {"corpus", {{"external_slot_id", release ? approved_external_sla_slot().at("slot_id") : json("component-local")},
            {"slot_approval_id", release ? approved_external_sla_slot().at("approval").at("approval_id") : json("component-only")},
            {"license_policy_id", release ? approved_external_sla_slot().at("license").at("policy_id") : json("component-license")},
            {"license_policy_version", release ? approved_external_sla_slot().at("license").at("policy_version") : json(1)},
            {"source_provenance_sha256", source_hash}, {"source_binding_id", "corpus-source"},
            {"license", {{"spdx", spdx}, {"redistribution", true}}},
            {"artifact", {{"sha256", artifact_hash}, {"size_bytes", qualified.size_bytes},
                {"format", qualified.format}, {"architecture", qualified.architecture}, {"mode", qualified.mode},
                {"endian", qualified.endian}, {"external", release}, {"binding_id", "benchmark-artifact"},
                {"qualification", {{"classification", release ? "production_code_image" : "deterministic_component_code_image"},
                    {"production_identity", production_identity}, {"version", version},
                    {"executable_bytes", qualified.executable_bytes}, {"zero_bytes", qualified.zero_bytes},
                    {"code_density", code_density}, {"zero_ratio", zero_ratio}, {"pdb", qualified.pdb},
                    {"static_library", qualified.static_library}, {"installer_only", false}, {"fabricated", false},
                    {"code_image", qualified.code_image}, {"target_execution_forbidden", true}}}}}}},
        {"matrix", input.value("matrix", json::object())}, {"hardware", input.value("hardware", json::object())},
        {"cache", input.value("cache", json::object())},
        {"resource_quotas", input.value("resource_quotas", json::object())},
        {"sample_policy", input.value("sample_policy", json::object())}, {"samples", input.at("samples")},
        {"aggregate", std::move(aggregate)}, {"thresholds", benchmark_sla_thresholds()}, {"receipt_sha256", ""}};
    benchmark_receipt_build_result_t output;
    finalize_receipt(receipt, evidence_root, output);
    return output;
}

benchmark_receipt_build_result_t build_benchmark_not_run_receipt(
    const std::filesystem::path& evidence_root, std::string_view search_receipt_path)
{
    json input;
    std::string error;
    if (!load_json_file(evidence_root, search_receipt_path, 16ULL * 1024ULL * 1024ULL, input, error))
        return failure(std::move(error));
    if (input.value("schema", std::string{}) != "aida.c03.benchmark-search-receipt" ||
        input.value("schema_version", 0) != 1 || !input.value("target_execution_forbidden", false) ||
        !input.contains("evidence") || !input.at("evidence").is_object())
        return failure("benchmark search receipt schema or target non-execution contract is invalid");
    const auto& evidence = input.at("evidence");
    if (!evidence.contains("harness") || !evidence.contains("runtime") ||
        !evidence.contains("source_provenance"))
        return failure("benchmark search receipt lacks harness, runtime, or qualification-policy evidence");
    json bindings = json::array();
    json binding;
    if (!make_binding(evidence_root, evidence.at("harness"), "benchmark-harness", "executable", binding, error))
        return failure(std::move(error));
    bindings.push_back(binding);
    const auto harness_hash = binding.at("sha256");
    if (!make_binding(evidence_root, evidence.at("runtime"), "analysis-runtime", "executable", binding, error))
        return failure(std::move(error));
    bindings.push_back(binding);
    const auto runtime_hash = binding.at("sha256");
    if (!make_binding(evidence_root, evidence.at("source_provenance"), "qualification-policy", "provenance", binding, error))
        return failure(std::move(error));
    bindings.push_back(binding);
    const auto policy_hash = binding.at("sha256");
    if (policy_hash != approved_external_sla_slot().at("generator_source").at("sha256"))
        return failure("benchmark search evidence does not bind the approved qualification policy");
    json manifest_record{{"path", search_receipt_path}, {"max_bytes", 16ULL * 1024ULL * 1024ULL}};
    if (!make_binding(evidence_root, manifest_record, "search-manifest", "manifest", binding, error))
        return failure(std::move(error));
    bindings.push_back(binding);
    const auto manifest_hash = binding.at("sha256");
    if (!input.contains("searched_roots") || !input.at("searched_roots").is_array() ||
        input.at("searched_roots").empty() || !input.contains("candidates") || !input.at("candidates").is_array())
        return failure("benchmark search receipt lacks searched roots or candidate rejections");
    json rejection_evidence = json::array();
    for (const auto& candidate : input.at("candidates")) {
        if (!candidate.is_object() || candidate.value("path", std::string{}).empty() ||
            !candidate.contains("rejection_codes") || !candidate.at("rejection_codes").is_array() ||
            candidate.at("rejection_codes").empty())
            return failure("benchmark candidate rejection evidence is incomplete");
        rejection_evidence.push_back(candidate);
    }
    const auto receipt_id = input.value("receipt_id", std::string{});
    const auto authorization = input.value("authorization_id", std::string{});
    if (receipt_id.empty() || authorization.empty())
        return failure("benchmark not-run receipt identity or authorization is absent");
    json receipt{{"schema", "aida.c03.benchmark-sla-receipt"}, {"schema_version", 2},
        {"receipt_id", receipt_id}, {"mode", "release_sla"},
        {"claim_status", "NOT RUN - NO QUALIFYING LOCAL FIXTURE"},
        {"provenance", {{"authorization_id", authorization},
            {"harness_build_sha256", harness_hash}, {"runtime_build_sha256", runtime_hash},
            {"manifest_sha256", manifest_hash}, {"policy_sha256", policy_hash},
            {"harness_binding_id", "benchmark-harness"},
            {"runtime_binding_id", "analysis-runtime"}, {"manifest_binding_id", "search-manifest"},
            {"policy_binding_id", "qualification-policy"},
            {"evidence_bindings", bindings}}},
        {"external_slot", approved_external_sla_slot()},
        {"not_run", {{"reason", "NO QUALIFYING LOCAL FIXTURE"},
            {"searched_roots", input.at("searched_roots")}, {"candidate_count", input.at("candidates").size()},
            {"rejection_evidence", std::move(rejection_evidence)}, {"target_execution_forbidden", true}}},
        {"thresholds", benchmark_sla_thresholds()}, {"receipt_sha256", ""}};
    benchmark_receipt_build_result_t output;
    finalize_receipt(receipt, evidence_root, output);
    return output;
}
}
