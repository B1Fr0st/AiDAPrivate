#include "analysis_memory_provider.hpp"
#include "assertion_telemetry/assertion_telemetry.hpp"

#include "../../src/core/analysis/flirt/flirt_db_builder.hpp"
#include "../../src/core/analysis/flirt/flirt_engine.hpp"
#include "../../src/core/analysis/workspace/coff_image.hpp"
#include "../../src/core/analysis/workspace/workspace_identity.hpp"

#include <cstdint>
#include <cstring>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace aida::analysis::c03_test {
namespace {

void require(bool condition, const char* message)
{
    assertion_telemetry::record_assertion(condition, message, __FILE__, __LINE__);
    if (!condition)
        throw std::runtime_error(message);
}

void verify_builder_performance(const std::shared_ptr<const flirt::flirt_signature_db_t>& db);

address_t rva(std::uint64_t value)
{
    return address_t{address_space_id_t::relative_virtual, value,
                     architecture_id_t::x86_64, architecture_mode_t::x86_64};
}

std::string hex_digest(const sha256_digest_t& digest)
{
    static const char* digits = "0123456789abcdef";
    std::string out;
    out.reserve(64);
    for (const auto byte : digest.bytes) {
        out.push_back(digits[byte >> 4]);
        out.push_back(digits[byte & 0xF]);
    }
    return out;
}

struct lib_byte_source_t {
    std::string name;
    std::vector<std::uint8_t> bytes;
};

std::vector<lib_byte_source_t> harvest_symbol_bytes(const std::vector<std::string>& libraries,
                                                    const std::vector<std::string>& wanted_names)
{
    std::vector<lib_byte_source_t> out;
    for (const auto& name : wanted_names) {
        for (const auto& library : libraries) {
            auto opened = mapped_file_provider_t::open(library);
            if (!opened)
                continue;
            auto provider = opened.take_value();
            auto archive = parse_coff_image(*provider);
            if (!archive)
                continue;
            bool harvested = false;
            for (const auto& member : archive.value().archive_members) {
                if (member.kind != coff_archive_member_kind_t::object ||
                    member.machine != coff_machine_amd64 || member.payload_size < 4)
                    continue;
                auto sub = subrange_provider_t::create(
                    std::static_pointer_cast<const byte_provider_t>(provider),
                    member.payload_offset, member.payload_size, "member");
                if (!sub)
                    continue;
                auto object = parse_coff_image(*sub.value());
                if (!object)
                    continue;
                for (const auto& symbol : object.value().symbols) {
                    if (symbol.name != name || !symbol.is_defined)
                        continue;
                    for (const auto& section : object.value().sections) {
                        if (static_cast<std::int32_t>(section.index) != symbol.section_number ||
                            !section.has_raw_data || symbol.value >= section.raw_size)
                            continue;
                        auto bytes = sub.value()->read_vector(
                            section.raw_offset + symbol.value,
                            (std::min<std::uint64_t>)(section.raw_size - symbol.value, 32), 4096);
                        if (!bytes || bytes.value().size() < 16)
                            continue;
                        lib_byte_source_t source;
                        source.name = name;
                        source.bytes = bytes.take_value();
                        out.push_back(std::move(source));
                        harvested = true;
                        break;
                    }
                }
                if (harvested)
                    break;
            }
            if (harvested)
                break;
        }
    }
    return out;
}

void verify_builder_smoke()
{
    auto discovered = flirt::discover_msvc_static_libs();
    assertion_telemetry::record_assertion(true, "MSVC static library discovery evaluated",
                                          __FILE__, __LINE__);
    if (!discovered) {
        std::cout << "flirt_db_builder smoke skipping: no MSVC static libraries on this host\n";
        return;
    }
    std::vector<std::string> crt_libs;
    for (const auto& path : discovered.value()) {
        const auto leaf = std::filesystem::path(path).filename().string();
        if (leaf == "libcmt.lib" || leaf == "libvcruntime.lib")
            crt_libs.push_back(path);
    }
    require(crt_libs.size() == 2, "discovery must locate libcmt.lib and libvcruntime.lib");
    flirt::flirt_db_builder_options_t options;
    options.library_paths = crt_libs;
    std::vector<flirt::flirt_db_build_entry_t> entries;
    auto built = flirt::build_flirt_db_entries(options, entries, {});
    require(built.has_value(), "FLIRT builder failed on the host CRT libraries");
    require(entries.size() >= 1000, "builder must emit at least 1000 CRT signatures");

    auto blob = flirt::serialize_afdb(entries, "smoke-toolset");
    require(blob.has_value(), "builder output failed serialization");
    auto db = flirt::flirt_signature_db_t::load_from_blob(blob.value().data(), blob.value().size(), "smoke");
    require(db.has_value(), "builder output failed database validation");
    require(db.value()->entry_count() == entries.size(), "database entry count mismatch");

    std::vector<flirt::flirt_db_build_entry_t> second_entries;
    auto rebuilt = flirt::build_flirt_db_entries(options, second_entries, {});
    require(rebuilt.has_value(), "FLIRT builder rerun failed");
    auto second_blob = flirt::serialize_afdb(second_entries, "smoke-toolset");
    require(second_blob.has_value(), "builder rerun failed serialization");
    const auto first_hash = sha256_bytes(blob.value().data(), blob.value().size());
    const auto second_hash = sha256_bytes(second_blob.value().data(), second_blob.value().size());
    require(first_hash.has_value() && second_hash.has_value(), "blob hashing failed");
    require(hex_digest(first_hash.value()) == hex_digest(second_hash.value()),
            "builder output is not deterministic across reruns");

    std::vector<const flirt::flirt_db_build_entry_t*> selected;
    for (const auto& entry : entries) {
        if (selected.size() >= 25)
            break;
        if (entry.func_size == 0 || entry.func_size > 0x200)
            continue;
        const auto bucket = db.value()->bucket(entry.prefix8);
        if (bucket.second != 1)
            continue;
        bool unique = true;
        for (const auto& other : selected)
            if (other->name == entry.name)
                unique = false;
        if (unique)
            selected.push_back(&entry);
    }
    require(selected.size() == 25, "could not select 25 unique-bucket signatures for the engine test");
    std::vector<std::string> names;
    for (const auto* entry : selected)
        names.push_back(entry->name);
    const auto harvested = harvest_symbol_bytes(crt_libs, names);
    require(harvested.size() == 25, "could not re-harvest the 25 function bodies from COFF members");

    workspace_image_t image;
    image.format = format_id_t::pe32_plus;
    image.architecture = architecture_id_t::x86_64;
    image.address_width_bits = 64;
    image.image_base = 0x140000000;
    image.image_size = 0x4000;
    image_section_t code;
    code.index = 1;
    code.name = ".text";
    code.virtual_address = 0x1000;
    code.virtual_size = 0x2000;
    code.file_offset = 0;
    code.file_size = 0x2000;
    code.permissions = image_permission_read | image_permission_execute;
    image.sections.push_back(code);

    std::vector<std::uint8_t> region(0x2000, 0x90);
    analysis_snapshot_t snapshot;
    snapshot.baseline_complete = true;
    for (std::size_t index = 0; index < 25; ++index) {
        const std::uint64_t start = 0x1000 + index * 0x80;
        std::memcpy(region.data() + index * 0x80, harvested[index].bytes.data(),
                    harvested[index].bytes.size());
        function_record_t function;
        function.start = rva(start);
        function.end = rva(start + selected[index]->func_size);
        snapshot.functions.push_back(function);
    }
    auto provider = std::make_shared<memory_provider_t>(std::move(region), "builder-engine-test");
    flirt::flirt_scan_request_t request;
    request.snapshot = &snapshot;
    request.image = &image;
    request.provider = provider;
    request.db = db.value().get();
    auto scanned = flirt::flirt_scan(request, {});
    require(scanned.has_value(), "engine scan over lib-replanted bodies failed");
    const auto& result = scanned.value();
    require(result.status == flirt::k_flirt_status_completed, "engine scan did not complete");
    require(result.matches.size() == 25, "engine must name 25/25 replanted CRT bodies");
    for (std::size_t index = 0; index < 25; ++index) {
        const std::uint64_t start = 0x1000 + index * 0x80;
        const flirt::flirt_match_t* match = nullptr;
        for (const auto& candidate : result.matches)
            if (candidate.rva == start)
                match = &candidate;
        require(match && match->name == names[index],
                "engine named a replanted CRT body incorrectly");
        require(match->tier == flirt::k_flirt_tier_exact_size,
                "exact-byte replant must reach the size-confirmed tier");
    }
    verify_builder_performance(db.value());
}

void verify_builder_performance(const std::shared_ptr<const flirt::flirt_signature_db_t>& db)
{
    constexpr std::size_t k_function_count = 1000000;
    constexpr std::size_t k_image_bytes = 300ull << 20;
    workspace_image_t image;
    image.format = format_id_t::pe32_plus;
    image.architecture = architecture_id_t::x86_64;
    image.address_width_bits = 64;
    image.image_base = 0x140000000;
    image.image_size = k_image_bytes + 0x1000;
    image_section_t code;
    code.index = 1;
    code.name = ".text";
    code.virtual_address = 0x1000;
    code.virtual_size = k_image_bytes;
    code.file_offset = 0;
    code.file_size = k_image_bytes;
    code.permissions = image_permission_read | image_permission_execute;
    image.sections.push_back(code);

    std::vector<std::uint8_t> region(k_image_bytes, 0);
    analysis_snapshot_t snapshot;
    snapshot.baseline_complete = true;
    snapshot.functions.reserve(k_function_count);
    for (std::size_t index = 0; index < k_function_count; ++index) {
        function_record_t function;
        const std::uint64_t start = 0x1000 + index * 300;
        function.start = rva(start);
        function.end = rva(start + 0x20);
        snapshot.functions.push_back(function);
    }
    auto provider = std::make_shared<memory_provider_t>(std::move(region), "builder-perf");
    flirt::flirt_scan_request_t request;
    request.snapshot = &snapshot;
    request.image = &image;
    request.provider = provider;
    request.db = db.get();
    const auto started = std::chrono::steady_clock::now();
    auto scanned = flirt::flirt_scan(request, {});
    const double wall_ms = std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now() - started).count();
    require(scanned.has_value(), "performance FLIRT scan failed");
    const auto& result = scanned.value();
    require(result.status == flirt::k_flirt_status_completed,
            "performance FLIRT scan did not complete");
    require(result.functions_considered == k_function_count,
            "performance scan must consider all 1M functions");
    require(result.elapsed_ms < 5000.0 && wall_ms < 5000.0,
            "1M-function anchored scan must complete under 5 seconds");
    require(result.matches.empty(), "zero-filled bodies must not produce matches");
    std::cout << "flirt_db_builder perf: functions=" << result.functions_considered
              << " elapsed_ms=" << result.elapsed_ms << '\n';
}

int run_smoke()
{
    verify_builder_smoke();
    std::cout << "flirt_db_builder smoke satisfied\n";
    return 0;
}

int run_cli(const std::vector<std::string>& args)
{
    flirt::flirt_db_builder_options_t options;
    std::string seed_header;
    std::string raw_db;
    for (std::size_t index = 1; index < args.size(); ++index) {
        const std::string& arg = args[index];
        const auto next = [&]() -> std::string {
            if (index + 1 >= args.size())
                throw std::runtime_error("missing value for " + arg);
            return args[++index];
        };
        if (arg == "--lib")
            options.library_paths.push_back(next());
        else if (arg == "--seed-header")
            seed_header = next();
        else if (arg == "--raw-db")
            raw_db = next();
        else if (arg == "--toolset")
            options.toolset = next();
        else
            return 2;
    }
    std::vector<flirt::flirt_db_build_entry_t> entries;
    auto built = flirt::build_flirt_db_entries(options, entries, {});
    if (!built) {
        std::cerr << "flirt_db_builder: build failed: " << built.error().message << '\n';
        return 1;
    }
    const auto& stats = built.value();
    auto blob = flirt::serialize_afdb(entries, options.toolset);
    if (!blob) {
        std::cerr << "flirt_db_builder: serialization failed\n";
        return 1;
    }
    if (!raw_db.empty()) {
        std::ofstream out(raw_db, std::ios::binary | std::ios::trunc);
        out.write(reinterpret_cast<const char*>(blob.value().data()),
                  static_cast<std::streamsize>(blob.value().size()));
        out.flush();
        if (!out) {
            std::cerr << "flirt_db_builder: failed writing " << raw_db << '\n';
            return 1;
        }
    }
    std::string digest;
    if (!seed_header.empty()) {
        auto written = flirt::write_flirt_seed_header(blob.value(), options.toolset,
                                                      static_cast<std::uint32_t>(entries.size()),
                                                      seed_header);
        if (!written) {
            std::cerr << "flirt_db_builder: seed header write failed: "
                      << written.error().message << '\n';
            return 1;
        }
        digest = written.value();
    } else {
        const auto hash = sha256_bytes(blob.value().data(), blob.value().size());
        if (hash.has_value())
            digest = hex_digest(hash.value());
    }
    std::cout << "flirt_db_builder libraries=" << stats.libraries_loaded
              << " members=" << stats.members_parsed
              << " sections=" << stats.code_sections
              << " symbols=" << stats.symbols_seen
              << " emitted=" << stats.signatures_emitted
              << " deduped=" << stats.deduped
              << " collisions=" << stats.collisions_kept
              << " dropped_short=" << stats.dropped_short
              << " dropped_prefix=" << stats.dropped_prefix
              << " dropped_mask=" << stats.dropped_mask
              << " sha256=" << digest << '\n';
    return 0;
}

}

}

int main(int argc, char** argv)
{
    try {
        std::vector<std::string> args;
        for (int index = 0; index < argc; ++index)
            args.emplace_back(argv[index] ? argv[index] : "");
        if (args.size() <= 1)
            return aida::analysis::c03_test::run_smoke();
        return aida::analysis::c03_test::run_cli(args);
    } catch (const std::exception& error) {
        aida::analysis::c03_test::assertion_telemetry::record_exception(error.what());
        std::cerr << error.what() << '\n';
        return 1;
    }
}
