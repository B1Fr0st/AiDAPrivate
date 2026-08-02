#include "analysis_memory_provider.hpp"
#include "assertion_telemetry/assertion_telemetry.hpp"
#include "../analysis_workspace/workspace_fixture_builder.hpp"

#include "../../src/core/analysis/flirt/static_recognition_service.hpp"
#include "../../src/core/analysis/flirt/type_seed_exporter.hpp"
#include "../../src/core/analysis/workspace/type_recovery.hpp"
#include "../../src/core/re/rtti.hpp"
#include "../../src/core/re/vmt.hpp"

#include <cstdint>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace aida::analysis::c03_test {
namespace {

using test_fixture::analyze_workspace;
using test_fixture::open_workspace;
using test_fixture::write_bytes_fixture;

void require(bool condition, const char* message)
{
    assertion_telemetry::record_assertion(condition, message, __FILE__, __LINE__);
    if (!condition)
        throw std::runtime_error(message);
}

constexpr std::uint64_t k_image_base = 0x140000000ull;
constexpr std::uint32_t k_text_rva = 0x1000;
constexpr std::uint32_t k_rdata_rva = 0x2000;
constexpr std::uint32_t k_text_raw = 0x400;
constexpr std::uint32_t k_rdata_raw = 0x600;

void store(std::vector<std::uint8_t>& bytes, std::size_t offset, const void* source, std::size_t size)
{
    std::memcpy(bytes.data() + offset, source, size);
}

template <typename T>
void store(std::vector<std::uint8_t>& bytes, std::size_t offset, const T& value)
{
    store(bytes, offset, &value, sizeof(value));
}

void store_u64(std::vector<std::uint8_t>& bytes, std::size_t offset, std::uint64_t value)
{
    store(bytes, offset, value);
}

void store_i32(std::vector<std::uint8_t>& bytes, std::size_t offset, std::int32_t value)
{
    store(bytes, offset, value);
}

void store_u32(std::vector<std::uint8_t>& bytes, std::size_t offset, std::uint32_t value)
{
    store(bytes, offset, value);
}

void store_name(std::vector<std::uint8_t>& bytes, std::size_t offset, const char* name)
{
    store(bytes, offset, name, std::strlen(name) + 1);
}

std::vector<std::uint8_t> build_rtti_pe()
{
    std::vector<std::uint8_t> bytes(0xC00, 0);
    IMAGE_DOS_HEADER dos{};
    dos.e_magic = IMAGE_DOS_SIGNATURE;
    dos.e_lfanew = 0x80;
    store(bytes, 0, dos);

    IMAGE_NT_HEADERS64 nt{};
    nt.Signature = IMAGE_NT_SIGNATURE;
    nt.FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
    nt.FileHeader.NumberOfSections = 2;
    nt.FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
    nt.FileHeader.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE;
    nt.OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    nt.OptionalHeader.AddressOfEntryPoint = k_text_rva;
    nt.OptionalHeader.BaseOfCode = k_text_rva;
    nt.OptionalHeader.ImageBase = k_image_base;
    nt.OptionalHeader.SectionAlignment = 0x1000;
    nt.OptionalHeader.FileAlignment = 0x200;
    nt.OptionalHeader.MajorOperatingSystemVersion = 10;
    nt.OptionalHeader.MajorSubsystemVersion = 10;
    nt.OptionalHeader.SizeOfImage = 0x3000;
    nt.OptionalHeader.SizeOfHeaders = 0x400;
    nt.OptionalHeader.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_CUI;
    nt.OptionalHeader.DllCharacteristics = IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE |
        IMAGE_DLLCHARACTERISTICS_NX_COMPAT | IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA;
    nt.OptionalHeader.SizeOfStackReserve = 1ull << 20;
    nt.OptionalHeader.SizeOfStackCommit = 4096;
    nt.OptionalHeader.SizeOfHeapReserve = 1ull << 20;
    nt.OptionalHeader.SizeOfHeapCommit = 4096;
    nt.OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
    store(bytes, static_cast<std::size_t>(dos.e_lfanew), nt);

    IMAGE_SECTION_HEADER text{};
    const char text_name[] = ".text";
    std::memcpy(text.Name, text_name, sizeof(text_name) - 1);
    text.Misc.VirtualSize = 0x200;
    text.VirtualAddress = k_text_rva;
    text.SizeOfRawData = 0x200;
    text.PointerToRawData = k_text_raw;
    text.Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
    IMAGE_SECTION_HEADER rdata{};
    const char rdata_name[] = ".rdata";
    std::memcpy(rdata.Name, rdata_name, sizeof(rdata_name) - 1);
    rdata.Misc.VirtualSize = 0x600;
    rdata.VirtualAddress = k_rdata_rva;
    rdata.SizeOfRawData = 0x600;
    rdata.PointerToRawData = k_rdata_raw;
    rdata.Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;
    const std::size_t section_table = static_cast<std::size_t>(dos.e_lfanew) +
        sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER64);
    store(bytes, section_table, text);
    store(bytes, section_table + sizeof(IMAGE_SECTION_HEADER), rdata);

    for (std::size_t index = 0; index < 9; ++index) {
        const std::size_t fn = k_text_raw + index * 0x10;
        bytes[fn + 0] = 0x48;
        bytes[fn + 1] = 0x83;
        bytes[fn + 2] = 0xEC;
        bytes[fn + 3] = 0x28;
        bytes[fn + 4] = 0x48;
        bytes[fn + 5] = 0x83;
        bytes[fn + 6] = 0xC4;
        bytes[fn + 7] = 0x28;
        bytes[fn + 8] = 0xC3;
    }

    const std::size_t rd = k_rdata_raw;
    store(bytes, rd + 0x100, "\x00\x00\x00\x00\x00\x00\x00\x00", 8);
    store(bytes, rd + 0x108, "\x00\x00\x00\x00\x00\x00\x00\x00", 8);
    store_name(bytes, rd + 0x110, ".?AVBase@@");
    store_name(bytes, rd + 0x150, ".?AVMid@@");
    store_name(bytes, rd + 0x190, ".?AVLeaf@@");

    store_u32(bytes, rd + 0x200, 1);
    store_u32(bytes, rd + 0x204, 0);
    store_u32(bytes, rd + 0x208, 0);
    store_i32(bytes, rd + 0x20C, 0x2100);
    store_i32(bytes, rd + 0x210, 0x2260);
    store_i32(bytes, rd + 0x214, 0x2200);
    store_u32(bytes, rd + 0x220, 1);
    store_u32(bytes, rd + 0x224, 0);
    store_u32(bytes, rd + 0x228, 0);
    store_i32(bytes, rd + 0x22C, 0x2140);
    store_i32(bytes, rd + 0x230, 0x2270);
    store_i32(bytes, rd + 0x234, 0x2220);
    store_u32(bytes, rd + 0x240, 1);
    store_u32(bytes, rd + 0x244, 0);
    store_u32(bytes, rd + 0x248, 0);
    store_i32(bytes, rd + 0x24C, 0x2180);
    store_i32(bytes, rd + 0x250, 0x2280);
    store_i32(bytes, rd + 0x254, 0x2240);

    store_u32(bytes, rd + 0x260, 0);
    store_u32(bytes, rd + 0x264, 0);
    store_u32(bytes, rd + 0x268, 1);
    store_i32(bytes, rd + 0x26C, 0x22A0);
    store_u32(bytes, rd + 0x270, 0);
    store_u32(bytes, rd + 0x274, 0);
    store_u32(bytes, rd + 0x278, 2);
    store_i32(bytes, rd + 0x27C, 0x22B0);
    store_u32(bytes, rd + 0x280, 0);
    store_u32(bytes, rd + 0x284, 0);
    store_u32(bytes, rd + 0x288, 2);
    store_i32(bytes, rd + 0x28C, 0x22C0);

    store_i32(bytes, rd + 0x2A0, 0x22D0);
    store_i32(bytes, rd + 0x2B0, 0x22E8);
    store_i32(bytes, rd + 0x2B4, 0x22D0);
    store_i32(bytes, rd + 0x2C0, 0x22E8);
    store_i32(bytes, rd + 0x2C4, 0x22D0);

    store_i32(bytes, rd + 0x2D0, 0x2100);
    store_u32(bytes, rd + 0x2D4, 0);
    store_i32(bytes, rd + 0x2D8, 0);
    store_i32(bytes, rd + 0x2DC, -1);
    store_i32(bytes, rd + 0x2E0, 0);
    store_u32(bytes, rd + 0x2E4, 0);
    store_i32(bytes, rd + 0x2E8, 0x2140);
    store_u32(bytes, rd + 0x2EC, 1);
    store_i32(bytes, rd + 0x2F0, 8);
    store_i32(bytes, rd + 0x2F4, 0);
    store_i32(bytes, rd + 0x2F8, 4);
    store_u32(bytes, rd + 0x2FC, 0);

    store_u64(bytes, rd + 0x300, k_image_base + 0x2200);
    for (std::size_t slot = 0; slot < 4; ++slot)
        store_u64(bytes, rd + 0x308 + slot * 8, k_image_base + k_text_rva + slot * 0x10);
    store_u64(bytes, rd + 0x340, k_image_base + 0x2240);
    for (std::size_t slot = 0; slot < 5; ++slot)
        store_u64(bytes, rd + 0x348 + slot * 8, k_image_base + k_text_rva + 0x40 + slot * 0x10);
    return bytes;
}

workspace_image_t fixture_image()
{
    workspace_image_t image;
    image.format = format_id_t::pe32_plus;
    image.architecture = architecture_id_t::x86_64;
    image.architecture_mode = architecture_mode_t::x86_64;
    image.address_width_bits = 64;
    image.image_base = k_image_base;
    image.image_size = 0x3000;
    image_section_t text;
    text.index = 1;
    text.name = ".text";
    text.virtual_address = k_text_rva;
    text.virtual_size = 0x200;
    text.file_offset = k_text_raw;
    text.file_size = 0x200;
    text.permissions = image_permission_read | image_permission_execute;
    image.sections.push_back(text);
    image_section_t rdata;
    rdata.index = 2;
    rdata.name = ".rdata";
    rdata.virtual_address = k_rdata_rva;
    rdata.virtual_size = 0x600;
    rdata.file_offset = k_rdata_raw;
    rdata.file_size = 0x600;
    rdata.permissions = image_permission_read;
    image.sections.push_back(rdata);
    return image;
}

const re::rtti::static_rtti_type_t* find_type(const re::rtti::static_rtti_result_t& result,
                                              const std::string& name)
{
    for (const auto& type : result.types)
        if (type.name == name)
            return &type;
    return nullptr;
}

std::vector<std::uint64_t> fixture_function_starts()
{
    std::vector<std::uint64_t> starts;
    for (std::size_t index = 0; index < 9; ++index)
        starts.push_back(k_text_rva + index * 0x10);
    return starts;
}

void verify_direct_static_scan()
{
    const auto image = fixture_image();
    auto provider_bytes = build_rtti_pe();
    auto provider = std::make_shared<memory_provider_t>(std::move(provider_bytes), "rtti-fixture");
    auto scanned = re::rtti::scan_static_image(image, *provider, {}, {});
    require(scanned.has_value(), "static RTTI scan failed on the fixture");
    const auto& result = scanned.value();
    require(result.status == re::rtti::k_static_rtti_completed,
            "static RTTI scan did not complete on the fixture");
    require(result.types.size() == 3, "static RTTI scan must recover exactly 3 classes");
    const auto* base = find_type(result, "Base");
    const auto* mid = find_type(result, "Mid");
    const auto* leaf = find_type(result, "Leaf");
    require(base && mid && leaf, "static RTTI scan missed a fixture class");
    require(base->decorated_name == ".?AVBase@@" && mid->decorated_name == ".?AVMid@@" &&
            leaf->decorated_name == ".?AVLeaf@@", "decorated names were not preserved");
    require(base->type_descriptor_rva == 0x2100 && mid->type_descriptor_rva == 0x2140 &&
            leaf->type_descriptor_rva == 0x2180, "type descriptor RVAs are wrong");
    require(leaf->bases.size() == 2, "Leaf must have exactly two base records");
    require(leaf->bases[0].name == "Mid" && leaf->bases[1].name == "Base",
            "Leaf base list must be {Mid, Base} in descriptor order");
    require(leaf->bases[0].mdisp == 8 && leaf->bases[0].vdisp == 4,
            "base record mdisp/vdisp were not parsed");
    require(base->vtable_rvas.size() == 1 && base->vtable_rvas[0] == 0x2308,
            "Base vtable was not attributed");
    require(leaf->vtable_rvas.size() == 1 && leaf->vtable_rvas[0] == 0x2348,
            "Leaf vtable was not attributed");
    require(mid->col_rva == 0x2220 && mid->col_rva != 0, "Mid COL was not recovered");

    const auto starts = fixture_function_starts();
    auto slots = re::vmt::extract_slots_static(image, *provider, result, &starts, {});
    require(slots.has_value(), "static vfunc slot extraction failed on the fixture");
    const auto& slot_result = slots.value();
    require(slot_result.status == re::vmt::k_static_vtables_completed,
            "static vfunc slot extraction did not complete");
    require(slot_result.slots.size() == 9, "exactly 9 vfunc slots must be extracted");
    require(slot_result.vtables_validated == 2, "exactly 2 vtables must validate");
    std::size_t base_slots = 0;
    std::size_t leaf_slots = 0;
    for (const auto& slot : slot_result.slots) {
        require(slot.confidence == 200, "on-start slot must carry confidence 200");
        if (slot.vtable_rva == 0x2308) {
            require(slot.function_rva == k_text_rva + slot.slot_index * 0x10,
                    "Base slot target is wrong");
            ++base_slots;
        } else if (slot.vtable_rva == 0x2348) {
            require(slot.function_rva == k_text_rva + 0x40 + slot.slot_index * 0x10,
                    "Leaf slot target is wrong");
            ++leaf_slots;
        } else {
            require(false, "slot attributed to an unknown vtable");
        }
    }
    require(base_slots == 4 && leaf_slots == 5, "slot attribution must be 4 Base + 5 Leaf");

    auto empty = re::rtti::scan_static_image(
        image, *std::make_shared<memory_provider_t>(std::vector<std::uint8_t>(0xC00, 0), "rtti-empty"),
        {}, {});
    require(empty.has_value() && empty.value().status == re::rtti::k_static_rtti_no_rtti &&
            empty.value().types.empty(), "absent RTTI must degrade to no_rtti");
}

void verify_workspace_ladder()
{
    const auto root = std::filesystem::temp_directory_path() /
        ("aida_srec_rtti_" + std::to_string(GetCurrentProcessId()));
    std::filesystem::create_directories(root);
    const auto pe_path = write_bytes_fixture(root / "rtti_fixture.exe", build_rtti_pe());
    auto workspace = open_workspace(pe_path, "rtti_fixture.exe");
    analyze_workspace(workspace);
    require(workspace->snapshot() && workspace->snapshot()->baseline_complete,
            "RTTI fixture baseline did not complete");

    auto records = static_recognition::run_for_workspace(
        workspace, static_recognition::static_recognition_settings_t{}, {});
    require(records.has_value(), "static recognition run failed on the RTTI fixture");
    const auto& value = *records.value();
    require(value.status == static_recognition::k_status_complete ||
            value.status == static_recognition::k_status_partial,
            "static recognition must complete on the RTTI fixture");
    require(value.rtti.types.size() == 3, "service RTTI scan must recover 3 classes");
    require(value.flirt_status == flirt::k_flirt_status_db_absent,
            "empty seed DB must degrade FLIRT to db_absent");
    require(value.vtable_slots.size() == 9, "service must publish 9 vtable slots");
    std::size_t leaf_named = 0;
    std::size_t base_named = 0;
    for (const auto& slot : value.vtable_slots) {
        if (slot.vtable_rva == 0x2348) {
            require(slot.class_name == "Leaf", "Leaf slot carries the wrong class name");
            require(slot.method_name == "Leaf::method_" + std::to_string(slot.slot_index),
                    "Leaf slot carries the wrong ladder method name");
            ++leaf_named;
        } else if (slot.vtable_rva == 0x2308) {
            require(slot.class_name == "Base", "Base slot carries the wrong class name");
            require(slot.method_name == "Base::method_" + std::to_string(slot.slot_index),
                    "Base slot carries the wrong ladder method name");
            ++base_named;
        }
    }
    require(leaf_named == 5 && base_named == 4, "ladder slot names must cover all 9 slots");
    std::size_t symbol_covered_slots = 0;
    for (const auto& slot : value.vtable_slots) {
        for (const auto& symbol : workspace->snapshot()->symbols) {
            if (!symbol.name.empty() && symbol.address.value == slot.function_rva) {
                ++symbol_covered_slots;
                break;
            }
        }
    }
    require(value.names.size() + symbol_covered_slots == 9,
            "ladder must emit one name per non-symbol-covered slot");
    require(value.names.size() >= 8, "ladder must emit at least 8 new names");
    for (const auto& name : value.names)
        require(name.source == "rtti_vfunc" && name.kind == "function",
                "ladder names must carry rtti_vfunc provenance");

    const auto evidence = static_recognition::make_static_rtti_evidence(value, k_image_base);
    require(!evidence.empty(), "static RTTI evidence export is empty");
    type_recovery_request_t recovery_request;
    recovery_request.function_rva = 0;
    recovery_request.injected_evidence = evidence;
    auto recovered = recover_types(*workspace, recovery_request, {});
    require(recovered.has_value(), "recover_types rejected injected static RTTI evidence");
    require(recovered.value().rtti_classes.size() >= 3,
            "injected static RTTI evidence must surface at least 3 rtti_classes");
    require(recovered.value().vtables.size() >= 2,
            "injected static RTTI evidence must surface at least 2 vtables");
    require(recovered.value().injected_evidence_count == evidence.size(),
            "injected evidence counter is inconsistent");
    bool found_leaf = false;
    for (const auto& info : recovered.value().rtti_classes)
        if (info.class_name == "Leaf")
            found_leaf = true;
    require(found_leaf, "recover_types must surface the Leaf class");
    std::error_code ec;
    std::filesystem::remove_all(root, ec);
}

void verify_test_target_if_present()
{
    const auto source_path = std::filesystem::path(__FILE__).lexically_normal();
    const auto repo_root = source_path.parent_path().parent_path().parent_path().parent_path();
    const auto candidates = {
        repo_root / "build-ninja" / "Release" / "AiDA_TestTarget.exe",
        repo_root / "build-ninja" / "AiDA_TestTarget.exe"
    };
    std::filesystem::path target;
    for (const auto& candidate : candidates) {
        std::error_code ec;
        if (std::filesystem::is_regular_file(candidate, ec)) {
            target = candidate;
            break;
        }
    }
    assertion_telemetry::record_assertion(true, "AiDA_TestTarget.exe discovery evaluated",
                                          __FILE__, __LINE__);
    if (target.empty()) {
        std::cout << "rtti_static_harness skipping live fixture: AiDA_TestTarget.exe absent\n";
        return;
    }
    auto workspace = open_workspace(target, "AiDA_TestTarget.exe");
    analyze_workspace(workspace);
    auto records = static_recognition::run_for_workspace(
        workspace, static_recognition::static_recognition_settings_t{}, {});
    require(records.has_value(), "static recognition run failed on AiDA_TestTarget.exe");
    const auto& value = *records.value();
    require(value.rtti.types.size() >= 5,
            "AiDA_TestTarget.exe must yield at least 5 RTTI classes");
    bool found_fixture_base = false;
    std::size_t handler_family = 0;
    for (const auto& type : value.rtti.types) {
        if (type.name.find("fixture_rtti_base") != std::string::npos)
            found_fixture_base = true;
        if (type.name.find("handler_t") != std::string::npos)
            ++handler_family;
    }
    require(found_fixture_base, "AiDA_TestTarget.exe must yield fixture_rtti_base");
    require(handler_family >= 1, "AiDA_TestTarget.exe must yield at least one *handler_t family class");
}

void verify_static_scan_performance()
{
    constexpr std::uint64_t k_rdata_bytes = 40ull << 20;
    workspace_image_t image;
    image.format = format_id_t::pe32_plus;
    image.architecture = architecture_id_t::x86_64;
    image.address_width_bits = 64;
    image.image_base = k_image_base;
    image.image_size = k_rdata_bytes + 0x2000;
    image_section_t rdata;
    rdata.index = 1;
    rdata.name = ".rdata";
    rdata.virtual_address = 0x1000;
    rdata.virtual_size = k_rdata_bytes;
    rdata.file_offset = 0;
    rdata.file_size = k_rdata_bytes;
    rdata.permissions = image_permission_read;
    image.sections.push_back(rdata);
    auto provider = std::make_shared<memory_provider_t>(
        std::vector<std::uint8_t>(k_rdata_bytes, 0), "rtti-perf");
    auto scanned = re::rtti::scan_static_image(image, *provider, {}, {});
    require(scanned.has_value(), "performance RTTI scan failed");
    require(scanned.value().status == re::rtti::k_static_rtti_no_rtti,
            "zero-filled rdata must report no_rtti");
    require(scanned.value().elapsed_ms < 2000.0,
            "40MB static RTTI scan must complete under 2 seconds");
    std::cout << "rtti_static_harness perf: bytes=" << scanned.value().bytes_scanned
              << " elapsed_ms=" << scanned.value().elapsed_ms << '\n';
}

}

void run_rtti_static_harness()
{
    verify_direct_static_scan();
    verify_workspace_ladder();
    verify_static_scan_performance();
    verify_test_target_if_present();
}

}

int main()
{
    try {
        aida::analysis::c03_test::run_rtti_static_harness();
        std::cout << "rtti_static_harness source contract satisfied\n";
        return 0;
    } catch (const std::exception& error) {
        aida::analysis::c03_test::assertion_telemetry::record_exception(error.what());
        std::cerr << error.what() << '\n';
        return 1;
    }
}
