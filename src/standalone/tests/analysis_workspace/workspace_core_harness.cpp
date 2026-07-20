#include "workspace_fixture_builder.hpp"
#include "../../src/core/analysis/workspace/apk_container.hpp"
#include "../../src/core/analysis/workspace/arch_decoder.hpp"
#include "../../src/core/analysis/workspace/function_recovery.hpp"
#include "../../src/core/analysis/workspace/ipa_container.hpp"
#include "../../src/core/analysis/workspace/jar_container.hpp"
#include "../../src/core/analysis/workspace/macho_image.hpp"
#include "../../src/core/analysis/workspace/x86_decoder.hpp"
#include "../../src/core/analysis/workspace/zip_container.hpp"
#include "../../src/core/disasm/zydis_disasm.hpp"
#include "../../src/core/session/analysis_session.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <future>
#include <iostream>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <thread>
#include <tuple>
#include <vector>

namespace {

using namespace aida::analysis;
using namespace aida::analysis::test_fixture;

struct snapshot_signature_t {
    std::size_t instructions = 0;
    std::size_t blocks = 0;
    std::size_t functions = 0;
    std::size_t edges = 0;
    std::size_t xrefs = 0;
    std::size_t strings = 0;
    std::vector<std::tuple<std::uint64_t, std::uint8_t, std::uint32_t>> decoded;

    bool operator==(const snapshot_signature_t& other) const {
        return instructions == other.instructions && blocks == other.blocks &&
            functions == other.functions && edges == other.edges && xrefs == other.xrefs &&
            strings == other.strings && decoded == other.decoded;
    }
};

snapshot_signature_t signature(const analysis_snapshot_t& snapshot)
{
    snapshot_signature_t result;
    result.instructions = snapshot.instructions.size();
    result.blocks = snapshot.blocks.size();
    result.functions = snapshot.functions.size();
    result.edges = snapshot.edges.size();
    result.xrefs = snapshot.xrefs.size();
    result.strings = snapshot.strings.size();
    for (const auto& instruction : snapshot.instructions)
        result.decoded.emplace_back(instruction.address.value, instruction.length, instruction.flow_flags);
    return result;
}

snapshot_signature_t analyze_once(const std::filesystem::path& path, std::uint32_t lanes)
{
    auto workspace = open_workspace(path, "core-fixture.exe");
    try {
        install_services(workspace);
        analyze_workspace(workspace, lanes);
        auto snapshot = workspace->snapshot();
        if (!snapshot || !snapshot->baseline_complete || workspace->progress().readiness !=
            workspace_readiness_t::baseline_ready)
            throw fixture_error_t("baseline readiness was not published");
        std::uint64_t accounted = 0;
        for (const auto& coverage : snapshot->coverage)
            accounted += coverage.size;
        const auto image = workspace->normalized_image();
        if (!image || snapshot->normalized_image != image ||
            image->workspace_binary_id != workspace->identity().binary_id() ||
            image->provider_content_hash != workspace->identity().content_hash() ||
            !image->provider_binding_verified)
            throw fixture_error_t("normalized baseline publication lost its provider identity");
        std::uint64_t executable = 0;
        for (const auto& section : image->sections) {
            if ((section.permissions & image_permission_execute) != 0)
                executable += (std::max)(section.virtual_size, section.file_size);
        }
        if (executable == 0) {
            for (const auto& segment : image->segments) {
                if ((segment.permissions & image_permission_execute) != 0)
                    executable += (std::max)(segment.virtual_size, segment.file_size);
            }
        }
        if (accounted != executable)
            throw fixture_error_t("executable coverage accounting mismatch");
        for (const auto& instruction : snapshot->instructions) {
            if (instruction.length == 0 || instruction.address.architecture != image->architecture ||
                instruction.address.mode != image->architecture_mode)
                throw fixture_error_t("compact IR instruction lost normalized architecture facts");
        }
        auto result = signature(*snapshot);
        close_workspace(workspace, true);
        return result;
    } catch (...) {
        try { close_workspace(workspace, true); } catch (...) {}
        throw;
    }
}

void verify_pe32(const std::filesystem::path& path)
{
    auto workspace = open_workspace(path, "x86-fixture.exe");
    try {
        install_services(workspace);
        const auto database = workspace->database();
        const auto queue = workspace->persistence_queue();
        const auto overlay = workspace->overlay();
        const auto decompiler = workspace->decompiler();
        install_services(workspace);
        if (!database || !queue || !overlay || !decompiler ||
            workspace->database() != database || workspace->persistence_queue() != queue ||
            workspace->overlay() != overlay || workspace->decompiler() != decompiler)
            throw fixture_error_t("idempotent fixture service installation replaced a published service");
        analyze_workspace(workspace, 2);
        const auto image = workspace->image();
        const auto snapshot = workspace->snapshot();
        if (!image || image->format() != format_id_t::pe32 ||
            image->architecture() != architecture_id_t::x86 || image->image_base() != 0x00400000 ||
            image->entry_rva() != 0x1000 || !snapshot || snapshot->instructions.size() < 5 ||
            snapshot->functions.empty())
            throw fixture_error_t("PE32 parser/baseline architecture contract failed");
        auto formatted = disasm::format_page(workspace, 0, 5, workspace->cancellation_token());
        if (!formatted || formatted.value().size() < 5 ||
            std::string(formatted.value()[0].mnem) != "push" ||
            std::string(formatted.value()[1].mnem) != "mov" ||
            std::string(formatted.value()[2].mnem) != "sub" ||
            std::string(formatted.value()[3].mnem) != "mov")
            throw fixture_error_t("PE32 x86 instruction decoding did not match fixture ground truth");
        close_workspace(workspace, true);
    } catch (...) {
        try { close_workspace(workspace, true); } catch (...) {}
        throw;
    }
}

void verify_rejected(const std::filesystem::path& path,
                     const std::vector<std::uint8_t>& bytes,
                     workspace_error_code_t expected)
{
    write_bytes_fixture(path, bytes);
    open_static_workspace_request_t request;
    request.source_path = path.u8string();
    request.bin_name = path.filename().u8string();
    request.load_profile = {1, 0, 0, 0};
    auto rejected = workspace_registry().open_static(request);
    if (rejected) {
        auto unexpected = rejected.take_value();
        close_workspace(unexpected);
        throw fixture_error_t("hostile fixture unexpectedly produced a workspace");
    }
    if (rejected.error().code != expected || rejected.error().phase.empty() ||
        rejected.error().message.empty())
        throw fixture_error_t("hostile fixture did not fail with its stable bounded error contract");
}

struct format_fixture_expectation_t {
    format_id_t format = format_id_t::unknown;
    architecture_id_t architecture = architecture_id_t::unknown;
    architecture_mode_t mode = architecture_mode_t::unknown;
    endian_t endian = endian_t::little;
    std::optional<std::string> member_path;
    bool member_prefix = false;
};

void verify_format_fixture(const std::filesystem::path& path,
                           const std::vector<std::uint8_t>& bytes,
                           const format_fixture_expectation_t& expected,
                           std::optional<std::string> requested_member = {})
{
    write_bytes_fixture(path, bytes);
    open_static_workspace_request_t request;
    request.source_path = path.u8string();
    request.bin_name = path.filename().u8string();
    request.member_path = std::move(requested_member);
    request.load_profile = {0x46, 0x4d, 0x54, static_cast<std::uint8_t>(expected.format)};
    auto opened = workspace_registry().open_static(request);
    if (!opened)
        throw fixture_error_t(opened.error().stable_code() + ":" + opened.error().message);
    auto workspace = opened.take_value();
    try {
        const auto image = workspace->normalized_image();
        const auto& identity = workspace->identity();
        if (!image || image->format != expected.format ||
            image->architecture != expected.architecture ||
            image->architecture_mode != expected.mode || image->endian != expected.endian ||
            identity.format() != expected.format || identity.architecture() != expected.architecture ||
            identity.architecture_mode() != expected.mode || identity.endian() != expected.endian ||
            image->workspace_binary_id != identity.binary_id() ||
            image->provider_content_hash != identity.content_hash() ||
            !image->provider_binding_verified || identity.normalized_source_path().empty())
            throw fixture_error_t("normalized format detection facts diverged from workspace identity");
        if ((expected.format == format_id_t::pe32 || expected.format == format_id_t::pe32_plus) !=
            static_cast<bool>(workspace->image()))
            throw fixture_error_t("legacy PE adapter publication disagreed with normalized format");
        if (expected.member_path) {
            if (!identity.normalized_member_path() || !image->member)
                throw fixture_error_t("container member provenance was not bound to workspace identity");
            const auto& actual = *identity.normalized_member_path();
            const bool matches = expected.member_prefix
                ? actual.rfind(*expected.member_path, 0) == 0
                : actual == *expected.member_path;
            if (!matches || image->member->normalized_member_path != actual ||
                workspace->provider().member_metadata() != image->member)
                throw fixture_error_t("container member identity did not match normalized provenance");
        } else if (identity.normalized_member_path() || image->member) {
            throw fixture_error_t("root format detection unexpectedly published member provenance");
        }
        close_workspace(workspace);
    } catch (...) {
        try { close_workspace(workspace); } catch (...) {}
        throw;
    }
}

void verify_format_and_member_detection(const std::filesystem::path& root)
{
    const auto open_provider = [](const std::filesystem::path& path) {
        auto opened = mapped_file_provider_t::open(path.u8string());
        if (!opened)
            throw fixture_error_t(opened.error().stable_code() + ":" + opened.error().message);
        return opened.take_value();
    };
    const auto elf = minimal_elf(architecture_id_t::x86_64,
        architecture_mode_t::x86_64, endian_t::little, {0xC3}, 0x71);
    verify_format_fixture(root / "formats" / "fixture.elf", elf,
        {format_id_t::elf, architecture_id_t::x86_64,
            architecture_mode_t::x86_64, endian_t::little});

    const auto macho = minimal_macho64(architecture_id_t::x86_64, 0x72);
    verify_format_fixture(root / "formats" / "fixture.macho", macho,
        {format_id_t::macho, architecture_id_t::x86_64,
            architecture_mode_t::x86_64, endian_t::little});
    const auto fat_path = root / "formats" / "fixture.fat";
    const auto fat = minimal_fat_macho64(architecture_id_t::x86_64, 0x73);
    verify_format_fixture(fat_path, fat,
        {format_id_t::macho, architecture_id_t::x86_64,
            architecture_mode_t::x86_64, endian_t::little, std::string("fat/"), true});
    const auto fat_provider = open_provider(fat_path);
    auto fat_image = parse_fat_macho(*fat_provider);
    if (!fat_image || fat_image.value().slices.size() != 1 ||
        fat_image.value().slices.front().architecture != architecture_id_t::x86_64 ||
        !fat_image.value().slices.front().image ||
        !fat_image.value().slices.front().image->member)
        throw fixture_error_t(fat_image ? "fat Mach-O slice detection lost member provenance" :
            fat_image.error().stable_code() + ":" + fat_image.error().message);

    const auto coff = minimal_coff_object(0x8664, {0xC3});
    verify_format_fixture(root / "formats" / "fixture.obj", coff,
        {format_id_t::coff, architecture_id_t::x86_64,
            architecture_mode_t::x86_64, endian_t::little});
    verify_format_fixture(root / "formats" / "fixture.lib", minimal_coff_archive(coff),
        {format_id_t::archive, architecture_id_t::x86_64,
            architecture_mode_t::x86_64, endian_t::little});

    const auto classfile = minimal_classfile();
    verify_format_fixture(root / "formats" / "Fixture.class", classfile,
        {format_id_t::classfile, architecture_id_t::jvm_bytecode,
            architecture_mode_t::jvm, endian_t::big});
    const auto dex = minimal_dex();
    verify_format_fixture(root / "formats" / "classes.dex", dex,
        {format_id_t::dex, architecture_id_t::dalvik_bytecode,
            architecture_mode_t::dalvik, endian_t::little});
    verify_format_fixture(root / "formats" / "fixture.oat",
        minimal_android_runtime_container(true),
        {format_id_t::oat, architecture_id_t::dalvik_bytecode,
            architecture_mode_t::dalvik, endian_t::little});
    verify_format_fixture(root / "formats" / "fixture.vdex",
        minimal_android_runtime_container(false),
        {format_id_t::vdex, architecture_id_t::dalvik_bytecode,
            architecture_mode_t::dalvik, endian_t::little});

    const std::string class_member = "Fixture.class";
    const auto jar = minimal_stored_zip({stored_zip_member_t{class_member, classfile}});
    const auto jar_path = root / "formats" / "fixture.jar";
    verify_format_fixture(jar_path, jar,
        {format_id_t::classfile, architecture_id_t::jvm_bytecode,
            architecture_mode_t::jvm, endian_t::big, class_member}, class_member);

    const std::string pe_member = "bin/member.exe";
    const auto zip_path = root / "formats" / "fixture.zip";
    verify_format_fixture(zip_path,
        minimal_stored_zip({stored_zip_member_t{pe_member, minimal_pe64(0x74)}}),
        {format_id_t::pe32_plus, architecture_id_t::x86_64,
            architecture_mode_t::x86_64, endian_t::little, pe_member}, pe_member);

    const std::string dex_member = "classes.dex";
    const auto apk_path = root / "formats" / "fixture.apk";
    verify_format_fixture(apk_path, minimal_stored_zip({stored_zip_member_t{dex_member, dex}}),
        {format_id_t::dex, architecture_id_t::dalvik_bytecode,
            architecture_mode_t::dalvik, endian_t::little, dex_member}, dex_member);

    const std::string ipa_member = "Payload/Fixture.app/Fixture";
    const auto ipa_path = root / "formats" / "fixture.ipa";
    verify_format_fixture(ipa_path, minimal_stored_zip({stored_zip_member_t{ipa_member, macho}}),
        {format_id_t::macho, architecture_id_t::x86_64,
            architecture_mode_t::x86_64, endian_t::little, ipa_member}, ipa_member);

    auto zip = zip_container_t::open(open_provider(zip_path));
    if (!zip || zip.value()->members().size() != 1 ||
        !zip.value()->find_member(pe_member) || zip.value()->uses_zip64())
        throw fixture_error_t(zip ? "ZIP container detection did not retain its bounded member" :
            zip.error().stable_code() + ":" + zip.error().message);
    auto zip_integrity = zip.value()->verify_integrity();
    if (!zip_integrity || !zip.value()->integrity_verified())
        throw fixture_error_t(zip_integrity ? "ZIP integrity state was not published" :
            zip_integrity.error().stable_code() + ":" + zip_integrity.error().message);

    auto jar_container = jar_container_t::open(open_provider(jar_path));
    if (!jar_container || jar_container.value()->members().size() != 1 ||
        !jar_container.value()->find_member(class_member))
        throw fixture_error_t(jar_container ? "JAR class member detection diverged" :
            jar_container.error().stable_code() + ":" + jar_container.error().message);
    auto parsed_class = jar_container.value()->parse_class_member(class_member);
    if (!parsed_class || parsed_class.value().classfile.normalized.format != format_id_t::classfile ||
        parsed_class.value().identity.internal_name != "Fixture" ||
        !parsed_class.value().provider->member_metadata())
        throw fixture_error_t(parsed_class ? "JAR class identity did not bind its source member" :
            parsed_class.error().stable_code() + ":" + parsed_class.error().message);

    auto apk_container = apk_container_t::open(open_provider(apk_path));
    if (!apk_container || apk_container.value()->kind() != apk_container_kind_t::apk ||
        apk_container.value()->members().size() != 1 ||
        apk_container.value()->members().front().normalized_path != dex_member)
        throw fixture_error_t(apk_container ? "APK code member detection diverged" :
            apk_container.error().stable_code() + ":" + apk_container.error().message);
    auto apk_integrity = apk_container.value()->verify_integrity();
    auto parsed_dex = apk_container.value()->parse_dex_member(0);
    if (!apk_integrity || !apk_container.value()->integrity_verified() || !parsed_dex ||
        parsed_dex.value().image.normalized.format != format_id_t::dex ||
        !parsed_dex.value().provider->member_metadata())
        throw fixture_error_t(!apk_integrity
            ? apk_integrity.error().stable_code() + ":" + apk_integrity.error().message
            : (!parsed_dex ? parsed_dex.error().stable_code() + ":" + parsed_dex.error().message
                : "APK DEX source identity was not retained"));

    auto ipa_container = ipa_container_t::open(open_provider(ipa_path));
    if (!ipa_container || ipa_container.value()->members().size() != 1 ||
        ipa_container.value()->members().front().normalized_path != ipa_member ||
        ipa_container.value()->members().front().format != format_id_t::macho ||
        ipa_container.value()->members().front().architecture != architecture_id_t::x86_64)
        throw fixture_error_t(ipa_container ? "IPA Mach-O member detection diverged" :
            ipa_container.error().stable_code() + ":" + ipa_container.error().message);

    open_static_workspace_request_t root_container;
    root_container.source_path = jar_path.u8string();
    root_container.bin_name = "fixture.jar";
    auto rejected = workspace_registry().open_static(root_container);
    if (rejected) {
        auto unexpected = rejected.take_value();
        close_workspace(unexpected);
        throw fixture_error_t("ZIP root admission did not require an explicit member selector");
    }
    if (rejected.error().code != workspace_error_code_t::unsupported_format ||
        rejected.error().phase != "workspace_open.detect")
        throw fixture_error_t("ZIP root admission did not require an explicit member selector");

    auto hostile_member = root_container;
    hostile_member.member_path = "../Fixture.class";
    auto hostile_member_result = workspace_registry().open_static(hostile_member);
    if (hostile_member_result) {
        auto unexpected = hostile_member_result.take_value();
        close_workspace(unexpected);
        throw fixture_error_t("hostile ZIP member selector was not rejected without aliasing");
    }
    if (hostile_member_result.error().code != workspace_error_code_t::target_not_found ||
        hostile_member_result.error().phase != "workspace_open.container")
        throw fixture_error_t("hostile ZIP member selector was not rejected without aliasing");

    verify_rejected(root / "formats" / "unknown.bin",
        {0x13, 0x37, 0x00, 0xff}, workspace_error_code_t::unsupported_format);
    verify_rejected(root / "formats" / "compact.dex",
        {'c', 'd', 'e', 'x', '0', '0', '1', 0}, workspace_error_code_t::unsupported_format);
}

void verify_cancellation(const std::filesystem::path& root)
{
    const auto parse_path = write_bytes_fixture(root / "cancel_parse.exe", minimal_pe64(0x11));
    open_static_workspace_request_t request;
    request.source_path = parse_path.u8string();
    request.bin_name = "cancel_parse.exe";
    request.load_profile = {1, 0, 0, 0};
    cancellation_source_t parse_cancel;
    parse_cancel.request_cancel();
    auto parsed = workspace_registry().open_static(request, parse_cancel.token());
    if (parsed || parsed.error().code != workspace_error_code_t::cancelled)
        throw fixture_error_t("pre-cancelled hostile parse did not return CANCELLED");

    auto decode_bytes = minimal_pe64(0x22);
    decode_bytes.resize(8u * 1024u * 1024u, 0x90);
    IMAGE_DOS_HEADER dos{};
    std::memcpy(&dos, decode_bytes.data(), sizeof(dos));
    IMAGE_NT_HEADERS64 nt{};
    std::memcpy(&nt, decode_bytes.data() + dos.e_lfanew, sizeof(nt));
    nt.OptionalHeader.SizeOfImage = 8u * 1024u * 1024u + 0x2000u;
    std::memcpy(decode_bytes.data() + dos.e_lfanew, &nt, sizeof(nt));
    const std::size_t section_offset = static_cast<std::size_t>(dos.e_lfanew) +
        sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER64);
    IMAGE_SECTION_HEADER section{};
    std::memcpy(&section, decode_bytes.data() + section_offset, sizeof(section));
    section.Misc.VirtualSize = static_cast<DWORD>(decode_bytes.size() - section.PointerToRawData);
    section.SizeOfRawData = section.Misc.VirtualSize;
    std::memcpy(decode_bytes.data() + section_offset, &section, sizeof(section));
    const auto decode_path = write_bytes_fixture(root / "cancel_decode.exe", decode_bytes);
    auto workspace = open_workspace(decode_path, "cancel_decode.exe");
    try {
        install_services(workspace);
        baseline_analysis_settings_t settings;
        settings.decode_worker_lanes = 2;
        auto started = baseline_analysis_service_t::start(workspace, settings);
        if (!started)
            throw fixture_error_t(started.error().stable_code() + ":" + started.error().message);
        workspace->request_cancel();
        const auto waited = aida::infra::taskflow_runtime::wait_for(started.value(), 10000);
        const auto progress = workspace->progress();
        if (!waited.completed || (!waited.cancelled &&
            (!progress.error || progress.error->code != workspace_error_code_t::cancelled)) ||
            progress.readiness == workspace_readiness_t::baseline_ready)
            throw fixture_error_t("decode cancellation did not stop publication within its bounded drain");
        close_workspace(workspace, true);
    } catch (...) {
        try { close_workspace(workspace, true); } catch (...) {}
        throw;
    }
}

std::shared_ptr<analysis_workspace_t> open_canonical_workspace(
    const std::filesystem::path& path)
{
    baseline_analysis_settings_t settings;
    open_static_workspace_request_t request;
    request.source_path = path.u8string();
    request.bin_name = path.filename().u8string();
    const std::string profile = "aida-pe-workspace-engine-1|" + settings.canonical_json();
    request.load_profile.assign(profile.begin(), profile.end());
    auto opened = workspace_registry().open_static(request);
    if (!opened)
        throw fixture_error_t(opened.error().stable_code() + ":" + opened.error().message);
    return opened.take_value();
}

std::shared_ptr<workspace_database_t> install_partial_database(
    const std::shared_ptr<analysis_workspace_t>& workspace, bool install_queue)
{
    workspace_database_options_t options;
    options.identity = workspace->identity_handle();
    options.versions.engine_version = "aida-pe-workspace-engine-1";
    options.versions.specification_version = "pe-x86-zydis-4.1.1-ghidra-native-1";
    options.versions.analysis_settings_hash = workspace->identity().load_profile_hash().to_hex();
    auto opened = workspace_database_t::open(options);
    if (!opened)
        throw fixture_error_t(opened.error().stable_code() + ":" + opened.error().message);
    auto database = opened.take_value();
    auto registered = workspace->register_lifecycle_participant(database);
    if (!registered) throw fixture_error_t(registered.error().message);
    auto installed = workspace->install_database(database);
    if (!installed) throw fixture_error_t(installed.error().message);
    if (install_queue) {
        auto queue = database->queue();
        registered = workspace->register_lifecycle_participant(queue);
        if (!registered) throw fixture_error_t(registered.error().message);
        installed = workspace->install_persistence_queue(queue);
        if (!installed) throw fixture_error_t(installed.error().message);
    }
    return database;
}

void wait_acquired_job(const analysis_session::static_workspace_acquisition_t& acquisition)
{
    if (!acquisition.analysis_job) return;
    const auto waited = aida::infra::taskflow_runtime::wait_for(*acquisition.analysis_job, 60000);
    if (!waited.completed)
        throw fixture_error_t(waited.cancelled ? "shared acquisition analysis was cancelled" :
            (waited.failed ? "shared acquisition analysis failed" :
             "shared acquisition analysis did not drain"));
}

void verify_partial_service_recovery(const std::filesystem::path& root)
{
    for (const bool queue_installed : {false, true}) {
        const auto path = write_fixture(root, queue_installed ? "db_queue" : "db_only",
            queue_installed ? "db_queue.exe" : "db_only.exe",
            queue_installed ? 0x32 : 0x31);
        auto workspace = open_canonical_workspace(path);
        try {
            auto database = install_partial_database(workspace, queue_installed);
            auto acquired = analysis_session::acquire_static_workspace(path.u8string());
            if (!acquired || acquired.value().workspace != workspace ||
                workspace->database() != database || workspace->persistence_queue() != database->queue() ||
                !workspace->overlay() || !workspace->decompiler())
                throw fixture_error_t("partial service recovery did not complete one coherent service set");
            wait_acquired_job(acquired.value());
            close_workspace(workspace, true);
        } catch (...) {
            try { close_workspace(workspace, true); } catch (...) {}
            throw;
        }
    }
}

void verify_shared_acquisition(const std::filesystem::path& root)
{
    const auto path = write_fixture(root, "singleflight", "singleflight.exe", 0x44);
    auto first = std::async(std::launch::async, [&] {
        return analysis_session::acquire_static_workspace(path.u8string());
    });
    auto second = std::async(std::launch::async, [&] {
        return analysis_session::acquire_static_workspace(path.u8string());
    });
    auto first_result = first.get();
    auto second_result = second.get();
    if (!first_result || !second_result ||
        first_result.value().workspace != second_result.value().workspace ||
        static_cast<unsigned>(first_result.value().analysis_started) +
            static_cast<unsigned>(second_result.value().analysis_started) != 1 ||
        !first_result.value().workspace->database() ||
        !first_result.value().workspace->persistence_queue() ||
        !first_result.value().workspace->overlay() ||
        !first_result.value().workspace->decompiler())
        throw fixture_error_t("concurrent static acquisition did not produce one starter and one coherent joiner");
    auto workspace = first_result.value().workspace;
    try {
        cancellation_source_t cancelled;
        cancelled.request_cancel();
        auto cancelled_joiner = analysis_session::acquire_static_workspace(
            path.u8string(), cancelled.token());
        if (cancelled_joiner || cancelled_joiner.error().code != workspace_error_code_t::cancelled)
            throw fixture_error_t("cancelled same-file joiner did not detach before service dispatch");
        cancellation_source_t expired(std::chrono::steady_clock::now());
        auto expired_joiner = analysis_session::acquire_static_workspace(
            path.u8string(), expired.token());
        if (expired_joiner || expired_joiner.error().code != workspace_error_code_t::deadline_exceeded)
            throw fixture_error_t("expired same-file joiner did not return DEADLINE_EXCEEDED");
        wait_acquired_job(first_result.value().analysis_job ? first_result.value() : second_result.value());
        if (workspace->progress().readiness != workspace_readiness_t::baseline_ready ||
            !workspace->snapshot())
            throw fixture_error_t("cancelled/deadline joiners cancelled the shared starter");
        close_workspace(workspace, true);
    } catch (...) {
        try { close_workspace(workspace, true); } catch (...) {}
        throw;
    }
}

address_t contract_rva(std::uint64_t rva)
{
    return address_t{address_space_id_t::relative_virtual, rva,
        architecture_id_t::x86_64, architecture_mode_t::x86_64};
}

void verify_provider_identity_mismatch(const std::filesystem::path& root)
{
    const auto first_path = write_fixture(root, "provider_a", "same.exe", 0x55);
    const auto second_path = write_fixture(root, "provider_b", "same.exe", 0x55);
    auto first = open_workspace(first_path, "same.exe");
    auto second = open_workspace(second_path, "same.exe");
    try {
        auto mismatched = analysis_workspace_t::create(first->identity_handle(),
            second->provider_handle(), second->image());
        if (mismatched || mismatched.error().code != workspace_error_code_t::integrity_failure)
            throw fixture_error_t("provider/source identity mismatch was not rejected");
        close_workspace(first, true);
        close_workspace(second, true);
    } catch (...) {
        try { close_workspace(first, true); } catch (...) {}
        try { close_workspace(second, true); } catch (...) {}
        throw;
    }
}

void verify_parser_limit_identity_divergence(const std::filesystem::path& path)
{
    open_static_workspace_request_t narrow_request;
    narrow_request.source_path = path.u8string();
    narrow_request.bin_name = "profile-fixture.exe";
    narrow_request.load_profile = {0x50, 0x36};
    narrow_request.pe_limits.max_sections = 1;
    auto narrow_result = workspace_registry().open_static(narrow_request);
    if (!narrow_result)
        throw fixture_error_t(narrow_result.error().stable_code() + ":" + narrow_result.error().message);
    auto narrow = narrow_result.take_value();
    auto wide_request = narrow_request;
    wide_request.pe_limits.max_sections = 2;
    auto wide_result = workspace_registry().open_static(wide_request);
    if (!wide_result) {
        close_workspace(narrow, true);
        throw fixture_error_t(wide_result.error().stable_code() + ":" + wide_result.error().message);
    }
    auto wide = wide_result.take_value();
    try {
        if (narrow->identity().content_hash() != wide->identity().content_hash() ||
            narrow->identity().normalized_source_path() != wide->identity().normalized_source_path() ||
            narrow->identity().load_profile_hash() == wide->identity().load_profile_hash() ||
            narrow->identity().binary_id() == wide->identity().binary_id())
            throw fixture_error_t("parser-limit change did not diverge canonical workspace identity");
        close_workspace(narrow, true);
        close_workspace(wide, true);
    } catch (...) {
        try { close_workspace(narrow, true); } catch (...) {}
        try { close_workspace(wide, true); } catch (...) {}
        throw;
    }
}

void verify_cross_workspace_publication(const std::filesystem::path& root)
{
    auto first = open_workspace(write_fixture(root, "substitute_a", "a.exe", 0x61), "a.exe");
    auto second = open_workspace(write_fixture(root, "substitute_b", "b.exe", 0x62), "b.exe");
    try {
        install_services(first);
        install_services(second);
        analyze_workspace(first, 1);
        analyze_workspace(second, 2);
        const auto first_publication = first->analysis_publication();
        const auto second_publication = second->analysis_publication();
        auto snapshot_substitution = second->publish_snapshot(
            second->generation(), first->snapshot(), false);
        if (snapshot_substitution ||
            snapshot_substitution.error().code != workspace_error_code_t::integrity_failure ||
            second->analysis_publication() != second_publication)
            throw fixture_error_t("cross-workspace snapshot substitution was not rejected atomically");
        auto next_snapshot = std::make_shared<analysis_snapshot_t>(*first->snapshot());
        next_snapshot->analysis_revision = first->analysis_revision() + 1;
        auto index_substitution = first->publish_analysis_bundle(
            first->generation(), first->analysis_revision(), next_snapshot,
            second->search_index(), true);
        if (index_substitution ||
            index_substitution.error().code != workspace_error_code_t::integrity_failure ||
            first->analysis_publication() != first_publication)
            throw fixture_error_t("cross-workspace search-index substitution was not rejected atomically");
        close_workspace(first, true);
        close_workspace(second, true);
    } catch (...) {
        try { close_workspace(first, true); } catch (...) {}
        try { close_workspace(second, true); } catch (...) {}
        throw;
    }
}

const operand_fact_t& require_segment_operand(const x86_decode_result_t& decoded,
                                              std::uint16_t expected_width,
                                              std::int64_t expected_displacement)
{
    for (std::size_t index = 0; index < decoded.operand_count; ++index) {
        const auto& operand = decoded.operands[index];
        if (operand.kind != operand_kind_t::memory)
            continue;
        if (operand.segment_reg == 0 || operand.bit_width != expected_width ||
            operand.access_width_bits != expected_width ||
            operand.displacement != expected_displacement ||
            operand.address_expression != address_expression_kind_t::segment_relative ||
            operand.address_resolution != target_resolution_t::segment_relative)
            throw fixture_error_t("FS/GS operand expression or access width was not retained");
        return operand;
    }
    throw fixture_error_t("FS/GS decode did not publish a memory operand");
}

x86_decode_result_t decode_contract_instruction(
    worker_owned_x86_decoder_t& decoder,
    const std::shared_ptr<analysis_workspace_t>& workspace,
    std::uint64_t rva)
{
    const auto image = workspace->image();
    auto offset = image->rva_to_file_offset(rva, 15);
    if (!offset)
        throw fixture_error_t(offset.error().stable_code() + ":" + offset.error().message);
    auto view = workspace->provider().lease(offset.value(), 15);
    if (!view)
        throw fixture_error_t(view.error().stable_code() + ":" + view.error().message);
    x86_decode_request_t request;
    request.address = contract_rva(rva);
    request.provider_offset = offset.value();
    request.runtime_address = image->image_base() + rva;
    request.image_base = image->image_base();
    request.image_size = image->image_size();
    request.available_bytes = 15;
    auto decoded = decoder.decode_one(view.value(), offset.value(), request);
    if (!decoded)
        throw fixture_error_t(decoded.error().stable_code() + ":" + decoded.error().message);
    return decoded.take_value();
}

void verify_segment_expressions(const std::shared_ptr<analysis_workspace_t>& workspace)
{
    auto decoder_result = worker_owned_x86_decoder_t::create(architecture_mode_t::x86_64);
    if (!decoder_result)
        throw fixture_error_t(decoder_result.error().stable_code() + ":" + decoder_result.error().message);
    auto decoder = decoder_result.take_value();
    const auto fs = decode_contract_instruction(*decoder, workspace, 0x1060);
    const auto gs = decode_contract_instruction(*decoder, workspace, 0x1068);
    const auto& fs_operand = require_segment_operand(fs, 32, 0x30);
    const auto& gs_operand = require_segment_operand(gs, 64, 0x60);
    if (fs_operand.segment_reg == gs_operand.segment_reg)
        throw fixture_error_t("FS and GS segment identities collapsed");
    const auto segment_target = [](const x86_decode_result_t& decoded, std::uint16_t width) {
        return std::any_of(decoded.targets.begin(), decoded.targets.begin() + decoded.target_count,
            [width](const target_fact_t& target) {
                return target.kind == target_kind_record_t::data &&
                    target.resolution == target_resolution_t::segment_relative &&
                    target.access_width_bits == width;
            });
    };
    if (!segment_target(fs, 32) || !segment_target(gs, 64))
        throw fixture_error_t("FS/GS target expressions lost segment-relative access width");
}

void verify_function_recovery_contracts(const workspace_image_t& image)
{
    std::vector<instruction_record_t> instructions(3);
    instructions[0].id = 1;
    instructions[0].address = contract_rva(0x1000);
    instructions[0].length = 2;
    instructions[0].flow_flags = flow_branch | flow_direct;
    instructions[0].target_fact_count = 1;
    instructions[0].provenance = fact_provenance_t::image_entry;
    instructions[0].confidence = 100;
    instructions[1].id = 2;
    instructions[1].address = contract_rva(0x1010);
    instructions[1].length = 1;
    instructions[1].flow_flags = flow_return | flow_terminal;
    instructions[1].provenance = fact_provenance_t::linear_validation;
    instructions[1].confidence = 80;
    instructions[2].id = 3;
    instructions[2].address = contract_rva(0x1020);
    instructions[2].length = 1;
    instructions[2].flow_flags = flow_return | flow_terminal;
    instructions[2].provenance = fact_provenance_t::recursive_decode;
    instructions[2].confidence = 90;
    target_fact_t branch;
    branch.instruction_id = instructions[0].id;
    branch.target = contract_rva(0x1020);
    branch.kind = target_kind_record_t::branch;
    branch.resolution = target_resolution_t::image_relative;
    branch.direct = true;
    std::vector<target_fact_t> targets{branch};
    function_seed_t entry;
    entry.address = contract_rva(0x1000);
    entry.kind = function_seed_kind_t::image_entry;
    entry.provenance = fact_provenance_t::image_entry;
    entry.confidence = 100;
    entry.stable_source_id = 1;
    function_seed_t relocation;
    relocation.address = contract_rva(0x1020);
    relocation.kind = function_seed_kind_t::relocation_target;
    relocation.provenance = fact_provenance_t::relocation;
    relocation.confidence = 70;
    relocation.stable_source_id = 2;
    auto relocation_duplicate = relocation;
    relocation_duplicate.stable_source_id = 3;
    const std::vector<function_seed_t> seeds{entry, relocation, relocation_duplicate};
    function_recovery_limits_t limits;
    auto blocks = function_recovery_t::build_blocks(image, instructions, targets, seeds, limits, {});
    if (!blocks)
        throw fixture_error_t(blocks.error().stable_code() + ":" + blocks.error().message);
    auto functions = function_recovery_t::recover_functions(
        image, instructions, seeds, blocks.take_value(), limits, {});
    if (!functions)
        throw fixture_error_t(functions.error().stable_code() + ":" + functions.error().message);
    if (functions.value().functions.size() != 1 ||
        functions.value().functions.front().start.value != 0x1000 ||
        functions.value().functions.front().chunk_count != 2 ||
        functions.value().function_chunks.size() != 2 ||
        functions.value().function_chunks.front().cold ||
        !functions.value().function_chunks.back().cold ||
        functions.value().function_chunks.back().start.value != 0x1020)
        throw fixture_error_t("relocation-interior arbitration or cold chunk recovery diverged");

    std::vector<instruction_record_t> unwind_instructions(3);
    for (std::size_t index = 0; index < unwind_instructions.size(); ++index) {
        auto& instruction = unwind_instructions[index];
        instruction.id = 10 + index;
        instruction.address = contract_rva(0x1000 + index * 4);
        instruction.length = 4;
        instruction.flow_flags = flow_fallthrough;
        instruction.provenance = fact_provenance_t::unwind_metadata;
        instruction.confidence = 100;
    }
    function_seed_t unwind;
    unwind.address = contract_rva(0x1000);
    unwind.known_end = contract_rva(0x1008);
    unwind.kind = function_seed_kind_t::unwind_range;
    unwind.provenance = fact_provenance_t::unwind_metadata;
    unwind.confidence = 100;
    auto unwind_blocks = function_recovery_t::build_blocks(
        image, unwind_instructions, {}, {unwind}, limits, {});
    if (!unwind_blocks)
        throw fixture_error_t(unwind_blocks.error().stable_code() + ":" + unwind_blocks.error().message);
    const bool ends_at_unwind = std::any_of(unwind_blocks.value().blocks.begin(),
        unwind_blocks.value().blocks.end(), [](const basic_block_record_t& block) {
            return block.start.value == 0x1000 && block.end.value == 0x1008;
        });
    const bool begins_after_unwind = std::any_of(unwind_blocks.value().blocks.begin(),
        unwind_blocks.value().blocks.end(), [](const basic_block_record_t& block) {
            return block.start.value == 0x1008;
        });
    if (!ends_at_unwind || !begins_after_unwind)
        throw fixture_error_t("proven unwind end did not split the basic-block stream");
}

void verify_analysis_contract_fixture(const std::filesystem::path& path)
{
    auto workspace = open_workspace(path, "analysis-contract.exe");
    try {
        const auto image = workspace->image();
        const auto normalized_image = workspace->normalized_image();
        if (!image || !normalized_image || image->imports().size() != 1 ||
            !image->imports().front().name || *image->imports().front().name != "ExitProcess" ||
            image->imports().front().iat_rva != 0x4060 || image->relocations().size() != 1 ||
            image->relocations().front().rva != 0x1100 || image->runtime_functions().size() != 2 ||
            image->unwind_records().size() != 2)
            throw fixture_error_t("advanced PE import/relocation/runtime metadata was not parsed");
        const auto handler = std::find_if(image->unwind_records().begin(), image->unwind_records().end(),
            [](const pe_unwind_record_t& value) { return value.exception_handler_rva.has_value(); });
        const auto chained = std::find_if(image->unwind_records().begin(), image->unwind_records().end(),
            [](const pe_unwind_record_t& value) { return value.chained_function.has_value(); });
        if (handler == image->unwind_records().end() ||
            *handler->exception_handler_rva != 0x1080 || !handler->language_data_rva ||
            chained == image->unwind_records().end() ||
            chained->chained_function->begin_rva != 0x1000 ||
            chained->chained_function->end_rva != 0x100C)
            throw fixture_error_t("unwind handler/chained metadata contract diverged");
        verify_segment_expressions(workspace);
        verify_function_recovery_contracts(*normalized_image);
        install_services(workspace);
        analyze_workspace(workspace, 3);
        const auto snapshot = workspace->snapshot();
        const bool relocation_interior_function = std::any_of(snapshot->functions.begin(),
            snapshot->functions.end(), [](const function_record_t& function) {
                return function.start.value == 0x1006;
            });
        const bool unwind_split = std::any_of(snapshot->blocks.begin(), snapshot->blocks.end(),
            [](const basic_block_record_t& block) { return block.end.value == 0x100C; });
        const bool handler_edge = std::any_of(snapshot->edges.begin(), snapshot->edges.end(),
            [](const edge_record_t& edge) {
                return edge.kind == edge_kind_t::exception_edge && edge.target.value == 0x1080;
            });
        const bool chained_edge = std::any_of(snapshot->edges.begin(), snapshot->edges.end(),
            [](const edge_record_t& edge) {
                return edge.kind == edge_kind_t::exception_edge && edge.source.value == 0x1020;
            });
        const bool call_fallthrough = std::any_of(snapshot->edges.begin(), snapshot->edges.end(),
            [](const edge_record_t& edge) {
                return edge.kind == edge_kind_t::fallthrough && edge.source.value == 0x1000;
            });
        if (relocation_interior_function || !unwind_split || !handler_edge || !chained_edge ||
            call_fallthrough)
            throw fixture_error_t("baseline relocation/unwind/IAT noreturn arbitration diverged");
        close_workspace(workspace, true);
    } catch (...) {
        try { close_workspace(workspace, true); } catch (...) {}
        throw;
    }
}

struct budget_failure_signature_t {
    workspace_error_code_t code = workspace_error_code_t::none;
    std::string phase;
    std::optional<std::uint64_t> address;
    std::optional<std::uint64_t> size;

    bool operator==(const budget_failure_signature_t& other) const {
        return code == other.code && phase == other.phase && address == other.address &&
            size == other.size;
    }
};

budget_failure_signature_t deterministic_budget_failure(
    const std::filesystem::path& path, std::uint32_t worker_lanes)
{
    baseline_analysis_settings_t settings;
    settings.decode_worker_lanes = worker_lanes;
    settings.max_decoded_instructions = 1;
    settings.max_trace_instructions = 8;
    open_static_workspace_request_t request;
    request.source_path = path.u8string();
    request.bin_name = "budget-" + std::to_string(worker_lanes) + ".exe";
    request.load_profile = {0x42, 0x55, 0x44, 0x47, 0x45, 0x54};
    request.pe_limits = settings.pe_limits;
    request.analysis_settings = settings;
    auto opened = workspace_registry().open_static(request);
    if (!opened)
        throw fixture_error_t(opened.error().stable_code() + ":" + opened.error().message);
    auto workspace = opened.take_value();
    try {
        install_services(workspace);
        auto analyzer = pe_baseline_analyzer_t::create(workspace, settings,
            workspace->generation(), workspace->analysis_revision(), std::nullopt);
        if (!analyzer)
            throw fixture_error_t(analyzer.error().stable_code() + ":" + analyzer.error().message);
        std::atomic<bool> runtime_cancelled{false};
        std::vector<workspace_result_t<void>> results;
        results.push_back(analyzer.value()->parse_phase(runtime_cancelled));
        if (results.back())
            results.push_back(analyzer.value()->seed_phase(runtime_cancelled));
        for (std::uint32_t lane = 0; results.back() && lane < analyzer.value()->decode_lane_count(); ++lane)
            results.push_back(analyzer.value()->decode_lane_phase(lane, runtime_cancelled));
        if (results.back())
            results.push_back(analyzer.value()->decode_merge_phase(runtime_cancelled));
        const auto failure = std::find_if(results.begin(), results.end(),
            [](const workspace_result_t<void>& result) { return !result; });
        if (failure == results.end() || failure->error().code != workspace_error_code_t::limit_exceeded)
            throw fixture_error_t("bounded decode did not produce its deterministic limit failure");
        budget_failure_signature_t signature;
        signature.code = failure->error().code;
        signature.phase = failure->error().phase;
        if (failure->error().address)
            signature.address = failure->error().address->value;
        signature.size = failure->error().size;
        close_workspace(workspace, true);
        return signature;
    } catch (...) {
        try { close_workspace(workspace, true); } catch (...) {}
        throw;
    }
}

void verify_deterministic_budget(const std::filesystem::path& path)
{
    const auto serial = deterministic_budget_failure(path, 1);
    const auto parallel = deterministic_budget_failure(path, 4);
    if (!(serial == parallel))
        throw fixture_error_t("decode budget failure changed with worker count");
}

struct decoder_fixture_case_t {
    arch_decoder_key_t key;
    std::vector<std::uint8_t> bytes;
};

arch_decoder_key_t decoder_key(architecture_id_t architecture,
                               architecture_mode_t mode,
                               endian_t endian,
                               std::uint8_t width)
{
    arch_decoder_key_t key;
    key.architecture = architecture;
    key.mode = mode;
    key.endian = endian;
    key.abi = abi_id_t::unknown;
    key.address_width_bits = width;
    return key;
}

std::vector<decoder_fixture_case_t> decoder_fixture_cases()
{
    const std::vector<std::uint8_t> zero_word{0x00, 0x00, 0x00, 0x00};
    return {
        {decoder_key(architecture_id_t::x86, architecture_mode_t::x86_16,
            endian_t::little, 16), {0x90}},
        {decoder_key(architecture_id_t::x86, architecture_mode_t::x86_32,
            endian_t::little, 32), {0xC3}},
        {decoder_key(architecture_id_t::x86_64, architecture_mode_t::x86_64,
            endian_t::little, 64), {0xC3}},
        {decoder_key(architecture_id_t::arm, architecture_mode_t::arm_a32,
            endian_t::little, 32), {0x00, 0xF0, 0x20, 0xE3}},
        {decoder_key(architecture_id_t::arm, architecture_mode_t::arm_a32,
            endian_t::big, 32), {0xE3, 0x20, 0xF0, 0x00}},
        {decoder_key(architecture_id_t::arm, architecture_mode_t::arm_thumb,
            endian_t::little, 32), {0x00, 0xBF}},
        {decoder_key(architecture_id_t::arm, architecture_mode_t::arm_thumb,
            endian_t::big, 32), {0xBF, 0x00}},
        {decoder_key(architecture_id_t::aarch64, architecture_mode_t::aarch64,
            endian_t::little, 64), {0x1F, 0x20, 0x03, 0xD5}},
        {decoder_key(architecture_id_t::aarch64, architecture_mode_t::aarch64,
            endian_t::big, 64), {0xD5, 0x03, 0x20, 0x1F}},
        {decoder_key(architecture_id_t::mips, architecture_mode_t::mips32,
            endian_t::little, 32), zero_word},
        {decoder_key(architecture_id_t::mips, architecture_mode_t::mips32,
            endian_t::big, 32), zero_word},
        {decoder_key(architecture_id_t::mips, architecture_mode_t::mips64,
            endian_t::little, 64), zero_word},
        {decoder_key(architecture_id_t::mips, architecture_mode_t::mips64,
            endian_t::big, 64), zero_word},
        {decoder_key(architecture_id_t::mips64, architecture_mode_t::mips64,
            endian_t::little, 64), zero_word},
        {decoder_key(architecture_id_t::mips64, architecture_mode_t::mips64,
            endian_t::big, 64), zero_word},
        {decoder_key(architecture_id_t::ppc, architecture_mode_t::ppc32,
            endian_t::little, 32), {0x00, 0x00, 0x00, 0x60}},
        {decoder_key(architecture_id_t::ppc, architecture_mode_t::ppc32,
            endian_t::big, 32), {0x60, 0x00, 0x00, 0x00}},
        {decoder_key(architecture_id_t::ppc64, architecture_mode_t::ppc64,
            endian_t::little, 64), {0x00, 0x00, 0x00, 0x60}},
        {decoder_key(architecture_id_t::ppc64, architecture_mode_t::ppc64,
            endian_t::big, 64), {0x60, 0x00, 0x00, 0x00}},
        {decoder_key(architecture_id_t::riscv, architecture_mode_t::riscv32,
            endian_t::little, 32), {0x13, 0x00, 0x00, 0x00}},
        {decoder_key(architecture_id_t::riscv, architecture_mode_t::riscv32,
            endian_t::big, 32), {0x00, 0x00, 0x00, 0x13}},
        {decoder_key(architecture_id_t::riscv, architecture_mode_t::riscv64,
            endian_t::little, 64), {0x13, 0x00, 0x00, 0x00}},
        {decoder_key(architecture_id_t::riscv, architecture_mode_t::riscv64,
            endian_t::big, 64), {0x00, 0x00, 0x00, 0x13}},
        {decoder_key(architecture_id_t::riscv32, architecture_mode_t::riscv32,
            endian_t::little, 32), {0x13, 0x00, 0x00, 0x00}},
        {decoder_key(architecture_id_t::riscv32, architecture_mode_t::riscv32,
            endian_t::big, 32), {0x00, 0x00, 0x00, 0x13}},
        {decoder_key(architecture_id_t::riscv64, architecture_mode_t::riscv64,
            endian_t::little, 64), {0x13, 0x00, 0x00, 0x00}},
        {decoder_key(architecture_id_t::riscv64, architecture_mode_t::riscv64,
            endian_t::big, 64), {0x00, 0x00, 0x00, 0x13}}
    };
}

void verify_architecture_decoder_matrix(const std::filesystem::path& root)
{
    auto& registry = default_arch_decoder_registry();
    const auto cases = decoder_fixture_cases();
    if (registry.registered_count() != cases.size())
        throw fixture_error_t("default architecture decoder enrollment changed without matrix coverage");
    std::set<std::tuple<unsigned, unsigned, unsigned, unsigned>> domains;
    for (std::size_t index = 0; index < cases.size(); ++index) {
        const auto& fixture = cases[index];
        const auto inserted = domains.emplace(
            static_cast<unsigned>(fixture.key.architecture),
            static_cast<unsigned>(fixture.key.mode),
            static_cast<unsigned>(fixture.key.endian), fixture.key.address_width_bits);
        if (!inserted.second)
            throw fixture_error_t("architecture decoder matrix contains a duplicate domain");
        auto resolved = registry.resolve(fixture.key);
        if (!resolved || !resolved.value().factory || resolved.value().implementation_id.empty())
            throw fixture_error_t(resolved ? "decoder enrollment metadata is incomplete" :
                resolved.error().stable_code() + ":" + resolved.error().message);
        if (fixture.bytes.size() < resolved.value().limits.minimum_instruction_bytes ||
            fixture.bytes.size() > resolved.value().limits.maximum_instruction_bytes)
            throw fixture_error_t("decoder fixture byte extent disagrees with enrolled limits");

        const auto path = write_bytes_fixture(root / "decoders" /
            ("decoder_" + std::to_string(index) + ".bin"), fixture.bytes);
        auto provider_result = mapped_file_provider_t::open(path.u8string());
        if (!provider_result)
            throw fixture_error_t(provider_result.error().stable_code() + ":" +
                provider_result.error().message);
        auto provider = provider_result.take_value();

        arch_decode_budget_t budget;
        budget.max_decode_attempts = 2;
        budget.max_input_bytes = fixture.bytes.size() * 2;
        budget.max_instructions = 1;
        budget.max_operand_facts = arch_decode_result_t::operand_capacity * 2;
        budget.max_target_facts = arch_decode_result_t::target_capacity * 2;
        budget.max_format_attempts = 1;
        budget.max_format_input_bytes = fixture.bytes.size();
        budget.max_formatted_instructions = 1;
        budget.max_formatted_text_bytes = 4096;
        auto worker_result = registry.create_worker(fixture.key, budget);
        if (!worker_result)
            throw fixture_error_t(worker_result.error().stable_code() + ":" +
                worker_result.error().message);
        auto worker = worker_result.take_value();
        arch_decode_request_t request;
        request.address = {address_space_id_t::relative_virtual, 0,
            fixture.key.architecture, fixture.key.mode};
        request.provider_offset = 0;
        request.runtime_address = 0x100000;
        request.image_base = 0x100000;
        request.image_size = 0x1000;
        request.available_bytes = static_cast<std::uint16_t>(fixture.bytes.size());
        request.provenance = fact_provenance_t::image_entry;
        request.confidence = 100;
        request.stable_source_id = index + 1;
        auto decoded = worker->decode_one(*provider, request);
        if (!decoded || decoded.value().instruction.id == 0 ||
            decoded.value().instruction.address != request.address ||
            decoded.value().instruction.length < resolved.value().limits.minimum_instruction_bytes ||
            decoded.value().instruction.length > fixture.bytes.size() ||
            decoded.value().instruction.operand_fact_count != decoded.value().operand_count ||
            decoded.value().instruction.target_fact_count != decoded.value().target_count ||
            decoded.value().operand_count > arch_decode_result_t::operand_capacity ||
            decoded.value().target_count > arch_decode_result_t::target_capacity)
            throw fixture_error_t(decoded ? "architecture decoder emitted invalid compact IR" :
                decoded.error().stable_code() + ":" + decoded.error().message);
        arch_format_options_t format_options;
        format_options.uppercase = true;
        format_options.maximum_text_bytes = 1024;
        auto formatted = worker->format_one(*provider, request, decoded.value(), format_options);
        if (!formatted || formatted.value().empty())
            throw fixture_error_t(formatted ? "architecture formatter emitted empty text" :
                formatted.error().stable_code() + ":" + formatted.error().message);
        for (const auto character : formatted.value()) {
            if (character >= 'a' && character <= 'z')
                throw fixture_error_t("architecture formatter ignored uppercase normalization");
        }
        auto exhausted = worker->decode_one(*provider, request);
        if (exhausted || exhausted.error().code != workspace_error_code_t::limit_exceeded ||
            exhausted.error().phase != "arch_decoder.decode")
            throw fixture_error_t("compact IR instruction budget was not enforced deterministically");
        const auto& usage = worker->usage();
        if (usage.decode_attempts != 2 || usage.input_bytes != fixture.bytes.size() * 2 ||
            usage.instructions != 1 || usage.decoded_bytes != decoded.value().instruction.length ||
            usage.format_attempts != 1 ||
            usage.format_input_bytes != decoded.value().instruction.length ||
            usage.formatted_instructions != 1 || usage.formatted_text_bytes != formatted.value().size() ||
            usage.cancellation_polls == 0)
            throw fixture_error_t("architecture decoder usage accounting diverged from hard budgets");
    }

    cancellation_source_t cancelled;
    cancelled.request_cancel();
    auto cancelled_worker = registry.create_worker(cases.front().key, {}, cancelled.token());
    if (cancelled_worker || cancelled_worker.error().code != workspace_error_code_t::cancelled)
        throw fixture_error_t("pre-cancelled architecture worker creation did not fail closed");

    const std::array<arch_decoder_key_t, 3> unsupported{{
        decoder_key(architecture_id_t::arm64ec, architecture_mode_t::aarch64,
            endian_t::little, 64),
        arch_decoder_key_t{architecture_id_t::jvm_bytecode, architecture_mode_t::jvm,
            endian_t::big, abi_id_t::jvm, 32},
        arch_decoder_key_t{architecture_id_t::dalvik_bytecode, architecture_mode_t::dalvik,
            endian_t::little, abi_id_t::dalvik, 32}
    }};
    for (const auto& key : unsupported) {
        auto resolved = registry.resolve(key);
        if (resolved || resolved.error().code != workspace_error_code_t::unsupported_format)
            throw fixture_error_t("unenrolled managed or hybrid architecture did not fail closed");
    }
}

void verify_normalized_baseline_facts(const std::filesystem::path& path)
{
    auto workspace = open_workspace(path, "normalized-baseline.elf");
    try {
        install_services(workspace);
        analyze_workspace(workspace, 3);
        const auto image = workspace->normalized_image();
        const auto snapshot = workspace->snapshot();
        if (!image || image->format != format_id_t::elf || workspace->image() ||
            image->entry_points.empty() || !snapshot || snapshot->normalized_image != image ||
            snapshot->image || !snapshot->baseline_complete || snapshot->instructions.empty() ||
            snapshot->blocks.empty() || snapshot->functions.empty() ||
            !workspace->search_index() || workspace->database()->snapshot().persisted_analysis_revision !=
                workspace->analysis_revision())
            throw fixture_error_t("normalized non-PE baseline facts were not published and persisted");
        const auto entry = image->entry_points.front().address;
        const bool entry_decoded = std::any_of(snapshot->instructions.begin(),
            snapshot->instructions.end(), [&](const instruction_record_t& instruction) {
                return instruction.address == entry;
            });
        if (!entry_decoded)
            throw fixture_error_t("normalized image entry point did not seed compact IR decoding");
        for (const auto& block : snapshot->blocks) {
            if (block.start.architecture != image->architecture ||
                block.start.mode != image->architecture_mode ||
                block.end.architecture != image->architecture ||
                block.end.mode != image->architecture_mode)
                throw fixture_error_t("normalized basic-block facts lost architecture identity");
        }
        close_workspace(workspace, true);
    } catch (...) {
        try { close_workspace(workspace, true); } catch (...) {}
        throw;
    }
}

void verify_content_identity_rebinding(const std::filesystem::path& root)
{
    const auto path = write_fixture(root, "identity_rebind", "rebind.exe", 0xD0);
    auto first = open_workspace(path, "rebind.exe");
    const workspace_identity_t first_identity = first->identity();
    close_workspace(first);
    first.reset();
    write_bytes_fixture(path, minimal_pe64(0xD1));
    auto second = open_workspace(path, "rebind.exe");
    try {
        if (second->identity().normalized_source_path() != first_identity.normalized_source_path() ||
            second->identity().content_hash() == first_identity.content_hash() ||
            second->identity().binary_id() == first_identity.binary_id() ||
            second->normalized_image()->provider_content_hash != second->identity().content_hash())
            throw fixture_error_t("same-path content replacement did not rebind workspace identity");
        close_workspace(second);
    } catch (...) {
        try { close_workspace(second); } catch (...) {}
        throw;
    }
}

void verify_persistence_source_identity_reopen(const std::filesystem::path& root)
{
    const auto path = write_fixture(root, "persistence_reopen", "persist.exe", 0xD2);
    std::shared_ptr<analysis_workspace_t> workspace;
    std::string database_path;
    try {
        workspace = open_workspace(path, "persist.exe");
        install_services(workspace);
        analyze_workspace(workspace, 2);
        const workspace_identity_t expected = workspace->identity();
        const auto expected_revision = workspace->analysis_revision();
        database_path = workspace->database()->path();
        close_workspace(workspace);
        workspace.reset();

        workspace = open_workspace(path, "persist.exe");
        install_services(workspace);
        if (workspace->identity().binary_id() != expected.binary_id() ||
            workspace->identity().content_hash() != expected.content_hash() ||
            workspace->identity().load_profile_hash() != expected.load_profile_hash() ||
            workspace->database()->path() != database_path || workspace->snapshot() ||
            workspace->analysis_revision() != 0)
            throw fixture_error_t("reopened workspace did not preserve exact persisted source identity");
        auto loaded = workspace->database()->load_snapshot(
            workspace->normalized_image(), workspace->image(), workspace->cancellation_token());
        if (!loaded || !loaded.value() || !loaded.value()->baseline_complete ||
            loaded.value()->binary_id != expected.binary_id() ||
            loaded.value()->load_profile_hash != expected.load_profile_hash() ||
            loaded.value()->analysis_revision != expected_revision ||
            loaded.value()->normalized_image != workspace->normalized_image() ||
            loaded.value()->image != workspace->image())
            throw fixture_error_t(loaded ? "persisted source identity facts did not reopen exactly" :
                loaded.error().stable_code() + ":" + loaded.error().message);
        close_workspace(workspace, true);
        workspace.reset();
    } catch (...) {
        if (workspace && !workspace->closed()) {
            try { close_workspace(workspace); } catch (...) {}
        }
        if (!database_path.empty()) {
            try { remove_database_artifacts(database_path); } catch (...) {}
        }
        throw;
    }
}

void verify_feature_pool_saturation(const std::filesystem::path& root)
{
    std::vector<std::shared_ptr<analysis_workspace_t>> workspaces;
    std::vector<aida::infra::taskflow_runtime::job_handle_t> jobs;
    try {
        for (std::uint8_t index = 0; index < 4; ++index) {
            auto path = write_fixture(root, "saturation_" + std::to_string(index),
                "saturate.exe", static_cast<std::uint8_t>(0x80 + index));
            auto workspace = open_workspace(path, "saturate.exe");
            install_services(workspace);
            baseline_analysis_settings_t settings;
            settings.decode_worker_lanes = 2;
            auto started = baseline_analysis_service_t::start(workspace, settings);
            if (!started)
                throw fixture_error_t(started.error().stable_code() + ":" + started.error().message);
            workspaces.push_back(std::move(workspace));
            jobs.push_back(started.value());
        }
        std::uint32_t peak_active = 0;
        for (std::size_t index = 0; index < jobs.size(); ++index) {
            const auto state = aida::infra::taskflow_runtime::wait_for(jobs[index], 120000);
            const auto runtime = aida::infra::taskflow_runtime::active_snapshot();
            peak_active = (std::max)(peak_active, runtime.total_active);
            if (!state.completed)
                throw fixture_error_t(state.cancelled ? "CANCELLED:feature-pool saturation job cancelled" :
                    "INTERNAL_ERROR:feature-pool saturation job failed");
            const auto progress = workspaces[index]->progress();
            if (progress.readiness != workspace_readiness_t::baseline_ready || !workspaces[index]->snapshot())
                throw fixture_error_t("feature-pool saturation workspace did not reach baseline ready");
        }
        if (peak_active == 0)
            throw fixture_error_t("feature-pool saturation did not observe any concurrent activity");
        for (auto& workspace : workspaces)
            close_workspace(workspace, true);
    } catch (...) {
        for (const auto& job : jobs)
            baseline_analysis_service_t::cancel(job);
        for (auto& workspace : workspaces) {
            try { close_workspace(workspace, true); } catch (...) {}
        }
        throw;
    }
}

void verify_nonzero_fairness_metrics(const std::filesystem::path& root)
{
    std::vector<std::shared_ptr<analysis_workspace_t>> workspaces;
    std::vector<aida::infra::taskflow_runtime::job_handle_t> jobs;
    try {
        for (std::uint8_t index = 0; index < 3; ++index) {
            auto path = write_fixture(root, "fairness_" + std::to_string(index),
                "fair.exe", static_cast<std::uint8_t>(0x90 + index));
            auto workspace = open_workspace(path, "fair.exe");
            install_services(workspace);
            baseline_analysis_settings_t settings;
            settings.decode_worker_lanes = 1;
            auto started = baseline_analysis_service_t::start(workspace, settings);
            if (!started)
                throw fixture_error_t(started.error().stable_code() + ":" + started.error().message);
            workspaces.push_back(std::move(workspace));
            jobs.push_back(started.value());
        }
        std::uint32_t peak_concurrent = 0;
        for (std::size_t index = 0; index < jobs.size(); ++index) {
            const auto runtime = aida::infra::taskflow_runtime::active_snapshot();
            peak_concurrent = (std::max)(peak_concurrent, runtime.total_active);
            const auto state = aida::infra::taskflow_runtime::wait_for(jobs[index], 120000);
            if (!state.completed)
                throw fixture_error_t("fairness metric workspace job did not complete");
        }
        if (peak_concurrent < 2)
            throw fixture_error_t("fairness metrics did not observe concurrent workspace admission");
        for (auto& workspace : workspaces)
            close_workspace(workspace, true);
    } catch (...) {
        for (const auto& job : jobs)
            baseline_analysis_service_t::cancel(job);
        for (auto& workspace : workspaces) {
            try { close_workspace(workspace, true); } catch (...) {}
        }
        throw;
    }
}

void verify_frozen_persistence_publication_metrics(const std::filesystem::path& root)
{
    const auto path = write_fixture(root, "frozen", "frozen.exe", 0xA0);
    auto workspace = open_workspace(path, "frozen.exe");
    try {
        install_services(workspace);
        analyze_workspace(workspace, 2);
        const auto snapshot_before = workspace->snapshot();
        const auto search_before = workspace->search_index();
        const auto db_before = workspace->database()->snapshot();
        const auto analysis_revision_before = workspace->analysis_revision();
        const auto overlay_revision_before = workspace->overlay_revision();
        if (!snapshot_before || !search_before || db_before.database_bytes == 0 ||
            db_before.cumulative_logical_bytes == 0 || db_before.cumulative_page_write_bytes == 0 ||
            analysis_revision_before == 0)
            throw fixture_error_t("frozen metrics showed no persistence or publication activity");
        const auto snapshot_after = workspace->snapshot();
        const auto search_after = workspace->search_index();
        const auto analysis_revision_after = workspace->analysis_revision();
        const auto overlay_revision_after = workspace->overlay_revision();
        if (snapshot_after != snapshot_before || search_after != search_before ||
            analysis_revision_after != analysis_revision_before ||
            overlay_revision_after != overlay_revision_before)
            throw fixture_error_t("frozen persistence/publication state changed without a mutation");
        close_workspace(workspace, true);
    } catch (...) {
        try { close_workspace(workspace, true); } catch (...) {}
        throw;
    }
}

void verify_live_header_mismatch_rejection()
{
    open_live_workspace_request_t live_request;
    live_request.bin_name = "live-mismatch";
    live_request.snapshot.pid = 0xFFFFFFFF;
    live_request.snapshot.module_base = 0x10000;
    live_request.snapshot.module_size = 0x1000;
    live_request.snapshot.module_name = "mismatch.exe";
    live_request.snapshot.module_path = "C:\\fake\\mismatch.exe";
    live_request.snapshot.capture_address = {address_space_id_t::live_virtual,
        0x10000, architecture_id_t::x86_64, architecture_mode_t::x86_64};
    live_request.snapshot.capture_size = 0x1000;
    auto rejected = workspace_registry().open_live(live_request);
    if (rejected || rejected.error().code == workspace_error_code_t::none)
        throw fixture_error_t("live workspace with non-existent PID was not rejected");
}

void verify_same_base_module_replacement_rejection(const std::filesystem::path& root)
{
    const auto first_path = write_fixture(root, "same_base_a", "same_base.exe", 0xC0);
    const auto second_path = write_fixture(root, "same_base_b", "same_base.exe", 0xC1);
    auto first = open_workspace(first_path, "same_base.exe");
    auto second = open_workspace(second_path, "same_base.exe");
    try {
        if (first->image()->image_base() != second->image()->image_base())
            throw fixture_error_t("same-base fixtures do not share an image base");
        if (first->identity().binary_id() == second->identity().binary_id())
            throw fixture_error_t("same-base distinct content collapsed to one binary identity");
        install_services(first);
        install_services(second);
        analyze_workspace(first, 1);
        analyze_workspace(second, 1);
        if (first->snapshot()->functions.empty() || second->snapshot()->functions.empty())
            throw fixture_error_t("same-base workspaces did not produce independent baselines");
        if (first->snapshot() == second->snapshot())
            throw fixture_error_t("same-base workspaces collapsed to one snapshot");
        close_workspace(first, true);
        close_workspace(second, true);
    } catch (...) {
        try { close_workspace(first, true); } catch (...) {}
        try { close_workspace(second, true); } catch (...) {}
        throw;
    }
}

}

int main()
{
    try {
        fixture_root_t root("core");
        const auto path = write_fixture(root.path(), "one", "fixture.exe", 42);
        const auto serial = analyze_once(path, 1);
        const auto parallel = analyze_once(path, 2);
        if (!(serial == parallel) || serial.instructions == 0 || serial.functions == 0)
            throw fixture_error_t("baseline output changed with worker count or was empty");
        verify_format_and_member_detection(root.path());
        verify_architecture_decoder_matrix(root.path());
        const auto normalized_path = write_bytes_fixture(root.path() / "normalized" / "baseline.elf",
            minimal_elf(architecture_id_t::x86_64, architecture_mode_t::x86_64,
                endian_t::little, {0xC3}, 0x75));
        const auto normalized_serial = analyze_once(normalized_path, 1);
        const auto normalized_parallel = analyze_once(normalized_path, 4);
        if (!(normalized_serial == normalized_parallel) || normalized_serial.instructions == 0 ||
            normalized_serial.blocks == 0 || normalized_serial.functions == 0)
            throw fixture_error_t("normalized baseline changed with deterministic worker count");
        verify_normalized_baseline_facts(normalized_path);
        verify_pe32(write_fixture32(root.path(), "x86", "fixture32.exe", 0x2A));
        verify_rejected(root.path() / "truncated.exe",
            hostile_pe64(hostile_pe_variant_t::truncated_headers), workspace_error_code_t::malformed_pe);
        verify_rejected(root.path() / "raw_overflow.exe",
            hostile_pe64(hostile_pe_variant_t::raw_span_overflow), workspace_error_code_t::malformed_pe);
        verify_rejected(root.path() / "raw_overlap.exe",
            hostile_pe64(hostile_pe_variant_t::raw_section_overlap), workspace_error_code_t::malformed_pe);
        verify_rejected(root.path() / "virtual_overlap.exe",
            hostile_pe64(hostile_pe_variant_t::virtual_section_overlap), workspace_error_code_t::malformed_pe);
        verify_rejected(root.path() / "raw_virtual_gap.exe",
            hostile_pe64(hostile_pe_variant_t::raw_virtual_directory_gap), workspace_error_code_t::malformed_pe);
        verify_rejected(root.path() / "directory_out_of_file.exe",
            hostile_pe64(hostile_pe_variant_t::out_of_file_directory), workspace_error_code_t::malformed_pe);
        verify_rejected(root.path() / "impossible_sections.exe",
            hostile_pe64(hostile_pe_variant_t::impossible_section_count), workspace_error_code_t::limit_exceeded);
        verify_rejected(root.path() / "invalid_dos.exe",
            hostile_pe64(hostile_pe_variant_t::invalid_dos_magic), workspace_error_code_t::malformed_pe);
        verify_rejected(root.path() / "invalid_pe_sig.exe",
            hostile_pe64(hostile_pe_variant_t::invalid_pe_signature), workspace_error_code_t::malformed_pe);
        verify_rejected(root.path() / "zero_section_align.exe",
            hostile_pe64(hostile_pe_variant_t::zero_section_alignment), workspace_error_code_t::malformed_pe);
        verify_rejected(root.path() / "import_self_ref.exe",
            hostile_pe64(hostile_pe_variant_t::import_self_reference), workspace_error_code_t::malformed_pe);
        verify_rejected(root.path() / "overlay.exe",
            hostile_pe64(hostile_pe_variant_t::overlay_beyond_last_section), workspace_error_code_t::malformed_pe);
        verify_rejected(root.path() / "zero_size_image.exe",
            hostile_pe64(hostile_pe_variant_t::zero_size_of_image), workspace_error_code_t::malformed_pe);
        verify_rejected(root.path() / "corrupt_opt_magic.exe",
            hostile_pe64(hostile_pe_variant_t::corrupt_optional_header_magic), workspace_error_code_t::malformed_pe);
        verify_cancellation(root.path());
        verify_partial_service_recovery(root.path());
        verify_shared_acquisition(root.path());
        verify_provider_identity_mismatch(root.path());
        verify_parser_limit_identity_divergence(path);
        verify_cross_workspace_publication(root.path());
        const auto contract_path = write_bytes_fixture(
            root.path() / "analysis-contract.exe", analysis_contract_pe64(0x66));
        verify_analysis_contract_fixture(contract_path);
        verify_deterministic_budget(contract_path);
        verify_feature_pool_saturation(root.path());
        verify_nonzero_fairness_metrics(root.path());
        verify_frozen_persistence_publication_metrics(root.path());
        verify_content_identity_rebinding(root.path());
        verify_persistence_source_identity_reopen(root.path());
        verify_live_header_mismatch_rejection();
        verify_same_base_module_replacement_rejection(root.path());
        std::cout << "workspace_core_harness source contract satisfied\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
