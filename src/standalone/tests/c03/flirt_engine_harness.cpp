#include "analysis_memory_provider.hpp"
#include "assertion_telemetry/assertion_telemetry.hpp"

#include "../../src/core/analysis/flirt/flirt_engine.hpp"
#include "../../src/core/analysis/flirt/flirt_signature_db.hpp"
#include "../../src/core/analysis/flirt/static_recognition_service.hpp"

#include <cstdint>
#include <cstring>
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

address_t rva(std::uint64_t value)
{
    return address_t{address_space_id_t::relative_virtual, value,
                     architecture_id_t::x86_64, architecture_mode_t::x86_64};
}

flirt::flirt_db_build_entry_t make_sig(const char* name,
                                       std::initializer_list<std::uint8_t> prefix,
                                       std::initializer_list<std::uint8_t> tail,
                                       std::uint32_t mask,
                                       std::uint32_t func_size,
                                       std::uint16_t flags)
{
    flirt::flirt_db_build_entry_t entry;
    std::size_t cursor = 0;
    for (const auto byte : prefix)
        entry.bytes[cursor++] = byte;
    for (const auto byte : tail)
        entry.bytes[cursor++] = byte;
    entry.pattern_len = static_cast<std::uint8_t>(cursor);
    entry.mask = mask;
    entry.func_size = func_size;
    entry.name = name;
    entry.sig_flags = flags;
    std::memcpy(&entry.prefix8, entry.bytes, sizeof(entry.prefix8));
    return entry;
}

std::shared_ptr<const flirt::flirt_signature_db_t> build_fixture_db()
{
    std::vector<flirt::flirt_db_build_entry_t> entries;
    entries.push_back(make_sig("malloc",
        {0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x74},
        {0x24, 0x10, 0x57, 0x48, 0x83, 0xEC, 0x20, 0xE8},
        0xFFFFu, 0x40u, flirt::k_afdb_sig_flag_crt_runtime));
    entries.push_back(make_sig("free",
        {0x48, 0x83, 0xEC, 0x28, 0x55, 0x48, 0x8B, 0xEC},
        {0xE8, 0x00, 0x00, 0x00, 0x00, 0x90, 0x5D, 0xC3},
        0xE1FFu, 0x30u, flirt::k_afdb_sig_flag_crt_runtime));
    entries.push_back(make_sig("memcpy",
        {0x48, 0x8B, 0xC4, 0x48, 0x89, 0x58, 0x08, 0x4C},
        {0x8B, 0x40, 0x10, 0x48, 0x8D, 0x50, 0x18, 0xEB},
        0xFFFFu, 0x50u, flirt::k_afdb_sig_flag_crt_runtime));
    entries.push_back(make_sig("memmove",
        {0x48, 0x8B, 0xC4, 0x48, 0x89, 0x58, 0x08, 0x4C},
        {0x8B, 0x40, 0x10, 0x48, 0x8D, 0x50, 0x18, 0xEB},
        0xFFFFu, 0x50u, flirt::k_afdb_sig_flag_crt_runtime));
    entries.push_back(make_sig("abort",
        {0x48, 0x83, 0xEC, 0x28, 0xB9, 0x16, 0x00, 0x00},
        {0x00, 0xE8, 0x11, 0x22, 0x33, 0x44, 0xCC, 0xC3},
        0xFFFFu, 0x20u, static_cast<std::uint16_t>(flirt::k_afdb_sig_flag_crt_runtime |
                                                   flirt::k_afdb_sig_flag_noreturn)));
    entries.push_back(make_sig("calloc",
        {0x40, 0x53, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x8B},
        {0xD9, 0x48, 0x85, 0xDB, 0x74, 0x10, 0xE8, 0x99},
        0xFFFFu, 0u, flirt::k_afdb_sig_flag_crt_runtime));
    entries.push_back(make_sig("realloc",
        {0x48, 0x89, 0x4C, 0x24, 0x08, 0x55, 0x48, 0x8B},
        {0xEC, 0x48, 0x83, 0xEC, 0x30, 0x48, 0x8B, 0x45},
        0xFFFFu, 0u, flirt::k_afdb_sig_flag_crt_runtime));
    entries.push_back(make_sig("memset",
        {0x48, 0x8D, 0x05, 0x11, 0x22, 0x33, 0x44, 0x48},
        {0x89, 0x58, 0x10, 0x48, 0x89, 0x68, 0x18, 0x56},
        0xFFFFu, 0u, flirt::k_afdb_sig_flag_crt_runtime));
    auto blob = flirt::serialize_afdb(entries, "fixture-toolset");
    require(blob.has_value(), "fixture FLIRT database serialization failed");
    auto db = flirt::flirt_signature_db_t::load_from_blob(
        blob.value().data(), blob.value().size(), "fixture");
    require(db.has_value(), "fixture FLIRT database failed validation");
    require(db.value()->entry_count() == 8, "fixture FLIRT database must hold 8 entries");
    return db.take_value();
}

void verify_library_exclusion()
{
    analysis_snapshot_t snapshot;
    snapshot.baseline_complete = true;
    symbol_record_t named;
    named.address = rva(0x1300);
    named.name = "user_supplied_name";
    named.kind = symbol_kind_t::function;
    snapshot.symbols.push_back(named);

    static_recognition::recognition_records_t records;
    const auto plant = [&records](std::uint64_t at, std::uint8_t tier) {
        flirt::flirt_match_t match;
        match.rva = at;
        match.name = "crt_fn_" + std::to_string(at);
        match.tier = tier;
        match.confidence = tier == flirt::k_flirt_tier_exact_size ? 230 :
            tier == flirt::k_flirt_tier_exact_crc ? 200 : 170;
        records.flirt.push_back(std::move(match));
    };
    plant(0x1000, flirt::k_flirt_tier_exact_size);
    plant(0x1100, flirt::k_flirt_tier_exact_crc);
    plant(0x1200, flirt::k_flirt_tier_pattern_only);
    plant(0x1300, flirt::k_flirt_tier_exact_size);

    const auto exclusion = static_recognition::build_library_exclusion(records, snapshot);
    require(exclusion.tier_candidates == 3,
            "exclusion must consider exact_size and exact_crc tiers only");
    require(exclusion.suppressed_named == 1,
            "snapshot-named function must suppress exclusion");
    require(static_recognition::is_library_function(exclusion, 0x1000),
            "exact_size match must be excluded");
    require(static_recognition::is_library_function(exclusion, 0x1100),
            "exact_crc match must be excluded");
    require(!static_recognition::is_library_function(exclusion, 0x1200),
            "pattern_only match must never be excluded");
    require(!static_recognition::is_library_function(exclusion, 0x1300),
            "named override must never be excluded");

    static_recognition::recognition_records_t empty_records;
    const auto empty_exclusion = static_recognition::build_library_exclusion(empty_records, snapshot);
    require(empty_exclusion.rvas.empty() && empty_exclusion.tier_candidates == 0,
            "empty recognition must produce an empty exclusion set");
}

}

void run_flirt_engine_harness()
{
    const auto db = build_fixture_db();

    std::vector<std::uint8_t> bytes(0x2000, 0x90);
    const auto plant = [&bytes](std::uint64_t file_offset, std::initializer_list<std::uint8_t> prefix,
                                std::initializer_list<std::uint8_t> tail) {
        std::size_t cursor = static_cast<std::size_t>(file_offset);
        for (const auto byte : prefix)
            bytes[cursor++] = byte;
        for (const auto byte : tail)
            bytes[cursor++] = byte;
    };
    plant(0x0000,
          {0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x74},
          {0x24, 0x10, 0x57, 0x48, 0x83, 0xEC, 0x20, 0xE8});
    plant(0x0100,
          {0x48, 0x83, 0xEC, 0x28, 0x55, 0x48, 0x8B, 0xEC},
          {0xE8, 0xDE, 0xAD, 0xBE, 0xEF, 0x90, 0x5D, 0xC3});
    plant(0x0200,
          {0x48, 0x8B, 0xC4, 0x48, 0x89, 0x58, 0x08, 0x4C},
          {0x8B, 0x40, 0x10, 0x48, 0x8D, 0x50, 0x18, 0xEB});
    plant(0x0300,
          {0x48, 0x83, 0xEC, 0x28, 0xB9, 0x16, 0x00, 0x00},
          {0x00, 0xE8, 0x11, 0x22, 0x33, 0x44, 0xCC, 0xC3});
    plant(0x0400,
          {0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x74},
          {0x24, 0xFF, 0x57, 0x48, 0x83, 0xEC, 0x20, 0xE8});
    plant(0x0500,
          {0x40, 0x53, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x8B},
          {0xD9, 0x48, 0x85, 0xDB, 0x74, 0x10, 0xE8, 0x99});

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
    code.virtual_size = 0x1000;
    code.file_offset = 0;
    code.file_size = 0x1000;
    code.permissions = image_permission_read | image_permission_execute;
    image.sections.push_back(code);
    image_section_t data;
    data.index = 2;
    data.name = ".rdata";
    data.virtual_address = 0x3000;
    data.virtual_size = 0x1000;
    data.file_offset = 0x1000;
    data.file_size = 0x1000;
    data.permissions = image_permission_read;
    image.sections.push_back(data);

    analysis_snapshot_t snapshot;
    snapshot.baseline_complete = true;
    const auto add_function = [&snapshot](std::uint64_t start, std::uint64_t size, bool thunk) {
        function_record_t function;
        function.start = rva(0x1000 + start);
        function.end = rva(0x1000 + start + size);
        function.thunk = thunk;
        snapshot.functions.push_back(function);
    };
    add_function(0x0000, 0x40, false);
    add_function(0x0100, 0x30, false);
    add_function(0x0200, 0x50, false);
    add_function(0x0300, 0x20, true);
    add_function(0x0FF8, 0x8, false);
    add_function(0x0400, 0x40, false);
    add_function(0x0500, 0x18, false);

    auto provider = std::make_shared<memory_provider_t>(std::move(bytes), "flirt-fixture");

    flirt::flirt_scan_request_t request;
    request.snapshot = &snapshot;
    request.image = &image;
    request.provider = provider;
    request.db = db.get();
    auto scanned = flirt::flirt_scan(request, {});
    require(scanned.has_value(), "flirt_scan failed on the fixture");
    const auto& result = scanned.value();
    require(result.status == flirt::k_flirt_status_completed, "flirt_scan did not complete");
    require(result.matches.size() == 3, "flirt_scan must name exactly 3 functions");
    require(result.functions_skipped_thunk == 1, "thunk function was not skipped");
    require(result.functions_skipped_short == 1, "short function was not skipped");
    require(result.ambiguous == 1, "collision pair must be ambiguous");
    require(result.rejected_reloc == 0, "no relocations exist in the fixture");
    require(result.candidates_tested >= 5, "candidate counter is inconsistent");
    require(result.functions_considered == 5, "considered counter is inconsistent");

    const auto find_match = [&result](std::uint64_t rva_value) -> const flirt::flirt_match_t* {
        for (const auto& match : result.matches)
            if (match.rva == rva_value)
                return &match;
        return nullptr;
    };
    const auto* malloc_match = find_match(0x1000);
    require(malloc_match && malloc_match->name == "malloc", "exact replant was not named malloc");
    require(malloc_match->tier == flirt::k_flirt_tier_exact_size,
            "exact replant must reach the size-confirmed tier");
    require(malloc_match->confidence == 230, "size-confirmed tier confidence must be 230");
    const auto* free_match = find_match(0x1100);
    require(free_match && free_match->name == "free",
            "relocation-masked replant was not named free");
    require(free_match->tier == flirt::k_flirt_tier_exact_size,
            "relocation-masked replant must reach the size-confirmed tier");
    const auto* calloc_match = find_match(0x1500);
    require(calloc_match && calloc_match->name == "calloc", "second exact replant was not named calloc");
    require(calloc_match->tier == flirt::k_flirt_tier_exact_crc,
            "sizeless signature must land on the crc tier");
    require(calloc_match->confidence == 200, "crc tier confidence must be 200");
    require(!find_match(0x1200), "collision pair must not emit a name");
    require(!find_match(0x1300), "thunk function must not emit a name");
    require(!find_match(0x1400), "corrupted prefix must not emit a name");
    require(!find_match(0x1FF8), "short function must not emit a name");

    flirt::flirt_scan_request_t absent_request;
    absent_request.snapshot = &snapshot;
    absent_request.image = &image;
    absent_request.provider = provider;
    absent_request.db = nullptr;
    auto absent = flirt::flirt_scan(absent_request, {});
    require(absent.has_value() && absent.value().status == flirt::k_flirt_status_db_absent,
            "missing database must degrade to db_absent");
    require(absent.value().matches.empty(), "missing database must emit no matches");

    verify_library_exclusion();
}

}

int main()
{
    try {
        aida::analysis::c03_test::run_flirt_engine_harness();
        std::cout << "flirt_engine_harness source contract satisfied\n";
        return 0;
    } catch (const std::exception& error) {
        aida::analysis::c03_test::assertion_telemetry::record_exception(error.what());
        std::cerr << error.what() << '\n';
        return 1;
    }
}
