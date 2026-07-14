#include "collection_graph_harness.hpp"
#include "assertion_telemetry/assertion_telemetry.hpp"

#include "../../src/core/analysis/collection/artifact_collection.hpp"
#include "../../src/core/analysis/collection/member_graph.hpp"
#include "../../src/core/analysis/mapped_window_cache.hpp"
#include "../../src/core/analysis/workspace/zip_container.hpp"

#include <zlib.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <memory>
#include <stdexcept>
#include <string>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

namespace aida::analysis::c03 {

namespace {

struct zip_fixture_member_t final {
    std::string path;
    std::vector<std::uint8_t> bytes;
    bool deflate = false;
};

struct deflate_ender_t final {
    void operator()(z_stream* value) const noexcept {
        if (value)
            deflateEnd(value);
    }
};

template <typename value_t>
value_t require_value(workspace_result_t<value_t> result, const char* message) {
	const bool accepted = static_cast<bool>(result);
	aida::analysis::c03_test::assertion_telemetry::record_assertion(
		accepted, message, __FILE__, __LINE__);
    if (!accepted)
        throw std::runtime_error(std::string(message) + ": " + result.error().stable_code());
    return result.take_value();
}

void require(bool condition, const char* message) {
	aida::analysis::c03_test::assertion_telemetry::record_assertion(
		condition, message, __FILE__, __LINE__);
    if (!condition)
        throw std::runtime_error(message);
}

template <typename value_t>
void require_error(workspace_result_t<value_t> result, workspace_error_code_t code,
                   const char* message) {
	const bool accepted = !result && result.error().code == code;
	aida::analysis::c03_test::assertion_telemetry::record_assertion(
		accepted, message, __FILE__, __LINE__);
    if (!accepted)
        throw std::runtime_error(message);
}

void append_u16(std::vector<std::uint8_t>& output, std::uint16_t value) {
    output.push_back(static_cast<std::uint8_t>(value));
    output.push_back(static_cast<std::uint8_t>(value >> 8U));
}

void append_u32(std::vector<std::uint8_t>& output, std::uint32_t value) {
    for (std::uint32_t shift = 0; shift != 32; shift += 8)
        output.push_back(static_cast<std::uint8_t>(value >> shift));
}

void append_u64(std::vector<std::uint8_t>& output, std::uint64_t value) {
    for (std::uint32_t shift = 0; shift != 64; shift += 8)
        output.push_back(static_cast<std::uint8_t>(value >> shift));
}

std::uint32_t crc_of(const std::vector<std::uint8_t>& bytes) {
    uLong crc = crc32(0L, Z_NULL, 0);
    std::size_t offset = 0;
    while (offset < bytes.size()) {
        const auto amount = static_cast<uInt>((std::min)(
            bytes.size() - offset, static_cast<std::size_t>((std::numeric_limits<uInt>::max)())));
        crc = crc32(crc, reinterpret_cast<const Bytef*>(bytes.data() + offset), amount);
        offset += amount;
    }
    return static_cast<std::uint32_t>(crc);
}

std::vector<std::uint8_t> raw_deflate(const std::vector<std::uint8_t>& bytes) {
    z_stream stream{};
    if (deflateInit2(&stream, Z_BEST_COMPRESSION, Z_DEFLATED, -MAX_WBITS, 8,
                     Z_DEFAULT_STRATEGY) != Z_OK)
        throw std::runtime_error("raw deflate initialization failed");
    const std::unique_ptr<z_stream, deflate_ender_t> cleanup(&stream);
    stream.next_in = bytes.empty() ? nullptr : const_cast<Bytef*>(
        reinterpret_cast<const Bytef*>(bytes.data()));
    stream.avail_in = static_cast<uInt>(bytes.size());
    std::vector<std::uint8_t> output;
    std::array<std::uint8_t, 16384> chunk{};
    for (;;) {
        stream.next_out = reinterpret_cast<Bytef*>(chunk.data());
        stream.avail_out = static_cast<uInt>(chunk.size());
        const int status = deflate(&stream, Z_FINISH);
        if (status != Z_OK && status != Z_STREAM_END)
            throw std::runtime_error("raw deflate failed");
        output.insert(output.end(), chunk.begin(), chunk.begin() + (chunk.size() - stream.avail_out));
        if (status == Z_STREAM_END)
            break;
    }
    return output;
}

std::vector<std::uint8_t> build_zip(const std::vector<zip_fixture_member_t>& members) {
    struct record_t final {
        std::string path;
        std::vector<std::uint8_t> compressed;
        std::uint32_t crc = 0;
        std::uint64_t local_offset = 0;
        std::uint64_t uncompressed_size = 0;
        std::uint16_t method = 0;
    };
    std::vector<std::uint8_t> output;
    std::vector<record_t> records;
    records.reserve(members.size());
    for (const auto& member : members) {
        record_t record;
        record.path = member.path;
        record.compressed = member.deflate ? raw_deflate(member.bytes) : member.bytes;
        record.crc = crc_of(member.bytes);
        record.local_offset = output.size();
        record.uncompressed_size = member.bytes.size();
        record.method = member.deflate ? 8U : 0U;
        append_u32(output, 0x04034b50U);
        append_u16(output, 20U);
        append_u16(output, 0);
        append_u16(output, record.method);
        append_u16(output, 0);
        append_u16(output, 0);
        append_u32(output, record.crc);
        append_u32(output, static_cast<std::uint32_t>(record.compressed.size()));
        append_u32(output, static_cast<std::uint32_t>(record.uncompressed_size));
        append_u16(output, static_cast<std::uint16_t>(record.path.size()));
        append_u16(output, 0);
        output.insert(output.end(), record.path.begin(), record.path.end());
        output.insert(output.end(), record.compressed.begin(), record.compressed.end());
        records.push_back(std::move(record));
    }
    const std::uint64_t central_offset = output.size();
    for (const auto& record : records) {
        append_u32(output, 0x02014b50U);
        append_u16(output, 20U);
        append_u16(output, 20U);
        append_u16(output, 0);
        append_u16(output, record.method);
        append_u16(output, 0);
        append_u16(output, 0);
        append_u32(output, record.crc);
        append_u32(output, static_cast<std::uint32_t>(record.compressed.size()));
        append_u32(output, static_cast<std::uint32_t>(record.uncompressed_size));
        append_u16(output, static_cast<std::uint16_t>(record.path.size()));
        append_u16(output, 0);
        append_u16(output, 0);
        append_u16(output, 0);
        append_u32(output, 0);
        append_u32(output, static_cast<std::uint32_t>(record.local_offset));
        output.insert(output.end(), record.path.begin(), record.path.end());
    }
    const std::uint64_t central_size = output.size() - central_offset;
    append_u32(output, 0x06054b50U);
    append_u16(output, 0);
    append_u16(output, 0);
    append_u16(output, static_cast<std::uint16_t>(records.size()));
    append_u16(output, static_cast<std::uint16_t>(records.size()));
    append_u32(output, static_cast<std::uint32_t>(central_size));
    append_u32(output, static_cast<std::uint32_t>(central_offset));
    append_u16(output, 0);
    return output;
}

void write_fixture(const std::filesystem::path& path,
                   const std::vector<std::uint8_t>& bytes) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    if (!output)
        throw std::runtime_error("fixture file open failed");
    output.write(reinterpret_cast<const char*>(bytes.data()),
                 static_cast<std::streamsize>(bytes.size()));
    if (!output)
        throw std::runtime_error("fixture file write failed");
}

std::shared_ptr<mapped_window_cache_t> open_fixture(const std::filesystem::path& path) {
    mapped_window_cache_options_t options;
    options.immutable_source = true;
    return require_value(mapped_window_cache_t::open(path.u8string(), options),
                         "fixture provider open failed");
}

std::shared_ptr<artifact_collection_t> open_collection(const std::filesystem::path& path,
                                                       collection_open_limits_t limits = {},
                                                       std::shared_ptr<member_graph_t> graph = {}) {
    auto provider = open_fixture(path);
    return require_value(artifact_collection_t::open(provider, limits, {}, std::move(graph)),
                         "collection open failed");
}

void verify_zip_archive_kind_detection(const std::filesystem::path& root) {
    const auto archive_bytes = build_zip({
        {"classes.dex", {0x64, 0x65, 0x78, 0x0a, 0x03, 0x00, 0x00, 0x00}, false},
        {"lib/arm64-v8a/libnative.so", {0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00}, false},
        {"AndroidManifest.xml", {0x03, 0x00, 0x08, 0x00}, false},
        {"resources.arsc", {0x02, 0x00, 0x0c, 0x00}, false},
        {"META-INF/MANIFEST.MF", {'M', 'a', 'n', 'i'}, false},
    });
    const auto path = root / "test.zip";
    write_fixture(path, archive_bytes);
    auto collection = open_collection(path);
    require(collection->kind() == collection_kind_t::apk,
            "ZIP with AndroidManifest.xml was not classified as APK");
    require(collection->member_count() >= 4,
            "APK collection should have at least 4 members");

    const auto* dex_member = collection->find_member("classes.dex");
    require(dex_member != nullptr, "classes.dex member not found");
    require(dex_member->member_kind == collection_member_kind_t::dex,
            "classes.dex was not classified as dex");

    const auto* so_member = collection->find_member("lib/arm64-v8a/libnative.so");
    require(so_member != nullptr, "libnative.so member not found");
    require(so_member->member_kind == collection_member_kind_t::native_library,
            "libnative.so was not classified as native_library");

    const auto* manifest_member = collection->find_member("AndroidManifest.xml");
    require(manifest_member != nullptr, "AndroidManifest.xml member not found");
    require(manifest_member->member_kind == collection_member_kind_t::manifest,
            "AndroidManifest.xml was not classified as manifest");

    auto dex_provider = require_value(collection->open_member("classes.dex"),
                                      "lazy open classes.dex failed");
    require(dex_provider->size() == 8, "classes.dex provider size mismatch");

    auto integrity = require_value(collection->verify_integrity(),
                                    "integrity verification failed");
    require(collection->integrity_verified(), "integrity flag not set");
}

void verify_ipa_classification(const std::filesystem::path& root) {
    const auto archive_bytes = build_zip({
        {"Payload/MyApp.app/MyApp", {0xcf, 0xfa, 0xed, 0xfe}, false},
        {"Payload/MyApp.app/Info.plist", {0x62, 0x70, 0x6c, 0x69}, false},
        {"Payload/MyApp.app/Frameworks/libswift.dylib", {0xcf, 0xfa, 0xed, 0xfe}, false},
    });
    const auto path = root / "test.ipa";
    write_fixture(path, archive_bytes);
    auto collection = open_collection(path);
    require(collection->kind() == collection_kind_t::ipa,
            "ZIP with Payload/ was not classified as IPA");
    require(collection->member_count() == 3, "IPA collection should have 3 members");

    const auto* app_binary = collection->find_member("Payload/MyApp.app/MyApp");
    require(app_binary != nullptr, "MyApp member not found");
}

void verify_jar_classification(const std::filesystem::path& root) {
    const auto archive_bytes = build_zip({
        {"META-INF/MANIFEST.MF", {'M', 'a', 'n', 'i', 'f', 'e', 's', 't'}, false},
        {"com/example/Main.class", {0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00, 0x00, 0x34}, false},
        {"com/example/Util.class", {0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00, 0x00, 0x34}, true},
    });
    const auto path = root / "test.jar";
    write_fixture(path, archive_bytes);
    auto collection = open_collection(path);
    require(collection->kind() == collection_kind_t::jar,
            "ZIP with MANIFEST.MF and .class was not classified as JAR");
    require(collection->member_count() == 3, "JAR collection should have 3 members");

    const auto* class_member = collection->find_member("com/example/Main.class");
    require(class_member != nullptr, "Main.class member not found");
    require(class_member->member_kind == collection_member_kind_t::classfile,
            "Main.class was not classified as classfile");
    require(class_member->compressed == false,
            "Main.class should not be compressed (stored)");

    const auto* util_member = collection->find_member("com/example/Util.class");
    require(util_member != nullptr, "Util.class member not found");
    require(util_member->compressed == true,
            "Util.class should be compressed (deflated)");
}

void verify_standalone_binary(const std::filesystem::path& root) {
    std::vector<std::uint8_t> pe_bytes(512, 0);
    pe_bytes[0] = 0x4D;
    pe_bytes[1] = 0x5A;
    pe_bytes[60] = 0x80;
    pe_bytes[61] = 0x00;
    pe_bytes[0x80] = 0x50;
    pe_bytes[0x81] = 0x45;
    pe_bytes[0x82] = 0x00;
    pe_bytes[0x83] = 0x00;
    const auto path = root / "test.exe";
    write_fixture(path, pe_bytes);
    auto collection = open_collection(path);
    require(collection->kind() == collection_kind_t::standalone_binary,
            "PE binary was not classified as standalone_binary");
    require(collection->member_count() == 1, "standalone binary should have 1 member");

    const auto& member = collection->members()[0];
    require(member.member_kind == collection_member_kind_t::binary,
            "standalone member should be classified as binary");
    require(member.format == format_id_t::pe32_plus,
            "standalone member format should be PE32+");

    auto provider = require_value(collection->open_member(0),
                                  "lazy open standalone member failed");
    require(provider->size() == pe_bytes.size(), "standalone provider size mismatch");
}

void verify_deep_nesting(const std::filesystem::path& root) {
    auto inner_zip = build_zip({
        {"inner_class.class", {0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00, 0x00, 0x34}, false},
    });
    auto middle_zip = build_zip({
        {"middle.jar", inner_zip, false},
        {"middle_class.class", {0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00, 0x00, 0x35}, false},
    });
    auto outer_zip = build_zip({
        {"outer.jar", middle_zip, false},
        {"outer_class.class", {0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00, 0x00, 0x36}, false},
    });
    const auto path = root / "nested.zip";
    write_fixture(path, outer_zip);

    auto graph = std::make_shared<member_graph_t>();
    auto collection = open_collection(path, {}, graph);
    require(collection->kind() == collection_kind_t::jar,
            "outer nested ZIP was not classified as JAR");
    require(collection->member_count() == 2, "outer collection should have 2 members");

    const auto* outer_jar_member = collection->find_member("outer.jar");
    require(outer_jar_member != nullptr, "outer.jar member not found");
    require(outer_jar_member->is_nested_collection,
            "outer.jar should be flagged as nested collection");

    auto child_collection = require_value(
        collection->open_child_collection("outer.jar"),
        "open_child_collection for outer.jar failed");
    require(child_collection->kind() == collection_kind_t::jar,
            "middle nested ZIP was not classified as JAR");
    require(child_collection->depth() == 1, "child collection depth should be 1");
    require(child_collection->member_count() == 2,
            "middle collection should have 2 members");

    const auto& child_provenance = child_collection->provenance();
    require(!child_provenance.empty(), "child collection should have provenance");

    auto grandchild_collection = require_value(
        child_collection->open_child_collection("middle.jar"),
        "open_child_collection for middle.jar failed");
    require(grandchild_collection->depth() == 2, "grandchild depth should be 2");
    require(grandchild_collection->member_count() == 1,
            "grandchild collection should have 1 member");

    const auto* inner_member = grandchild_collection->find_member("inner_class.class");
    require(inner_member != nullptr, "inner_class.class not found in grandchild");

    require(graph->node_count() >= 7,
            "graph should have at least 7 nodes (3 collections + 4 leaf members)");
    require(graph->max_depth() >= 2, "graph max depth should be at least 2");
}

void verify_duplicate_names_across_nesting(const std::filesystem::path& root) {
    auto inner_zip = build_zip({
        {"classes.dex", {0x64, 0x65, 0x78, 0x0a, 0x03, 0x00, 0x00, 0x00}, false},
    });
    auto outer_zip = build_zip({
        {"classes.dex", {0x64, 0x65, 0x78, 0x0a, 0x03, 0x00, 0x00, 0x01}, false},
        {"nested.apk", inner_zip, false},
    });
    const auto path = root / "dup_names.zip";
    write_fixture(path, outer_zip);

    auto graph = std::make_shared<member_graph_t>();
    auto collection = open_collection(path, {}, graph);
    require(collection->kind() == collection_kind_t::apk,
            "outer duplicate-name ZIP was not classified as APK");

    const auto* outer_dex = collection->find_member("classes.dex");
    require(outer_dex != nullptr, "outer classes.dex not found");

    auto child = require_value(collection->open_child_collection("nested.apk"),
                               "open nested.apk failed");
    const auto* inner_dex = child->find_member("classes.dex");
    require(inner_dex != nullptr, "inner classes.dex not found");

    auto outer_hash = require_value(collection->compute_member_hash(0),
                                    "outer member hash computation failed");
    auto inner_hash = require_value(child->compute_member_hash(0),
                                    "inner member hash computation failed");
    require(outer_hash != inner_hash,
            "duplicate-named members at different depths should have different hashes");

    auto graph_dupes = graph->duplicate_names();
    require(!graph_dupes.empty(), "graph should report duplicate names");
    bool found_classes_dex_dupe = false;
    for (const auto& name : graph_dupes) {
        if (name == "classes.dex")
            found_classes_dex_dupe = true;
    }
    require(found_classes_dex_dupe,
            "graph duplicate names should include classes.dex");

    auto nodes = graph->nodes_with_name("classes.dex");
    require(nodes.size() >= 2,
            "graph should have at least 2 nodes named classes.dex");
}

void verify_member_hash_identity(const std::filesystem::path& root) {
    std::vector<std::uint8_t> content_a(256, 0xAA);
    std::vector<std::uint8_t> content_b(256, 0xBB);

    auto archive = build_zip({
        {"file_a.bin", content_a, false},
        {"file_b.bin", content_b, false},
        {"file_a_copy.bin", content_a, false},
    });
    const auto path = root / "hash_test.zip";
    write_fixture(path, archive);

    auto graph = std::make_shared<member_graph_t>();
    auto collection = open_collection(path, {}, graph);
    auto hash_a = require_value(collection->compute_member_hash(0),
                                "hash for file_a.bin failed");
    auto hash_b = require_value(collection->compute_member_hash(1),
                                "hash for file_b.bin failed");
    auto hash_a_copy = require_value(collection->compute_member_hash(2),
                                     "hash for file_a_copy.bin failed");

    require(hash_a != hash_b, "different content should produce different hashes");
    require(hash_a == hash_a_copy,
            "identical content should produce identical hashes");

    auto matching = graph->find_by_hash(hash_a);
    require(matching.size() >= 2,
            "graph hash index should find at least 2 nodes for hash_a");

    const auto& members = collection->members();
    require(members[0].content_hash.has_value(),
            "member 0 should have cached content hash");
    require(members[2].content_hash.has_value(),
            "member 2 should have cached content hash");
    require(*members[0].content_hash == *members[2].content_hash,
            "cached hashes for identical content should match");
}

void verify_cancellation(const std::filesystem::path& root) {
    auto archive = build_zip({
        {"classes.dex", {0x64, 0x65, 0x78, 0x0a, 0x03, 0x00, 0x00, 0x00}, false},
        {"classes2.dex", {0x64, 0x65, 0x78, 0x0a, 0x03, 0x00, 0x00, 0x01}, false},
    });
    const auto path = root / "cancel_test.zip";
    write_fixture(path, archive);

    auto provider = open_fixture(path);
    cancellation_source_t cancel_source;
    cancel_source.request_cancel();

    auto result = artifact_collection_t::open(provider, {}, cancel_source.token());
    require_error(result, workspace_error_code_t::cancelled,
                  "cancelled collection open was accepted");

    cancellation_source_t cancel_member;
    auto collection = open_collection(path);
    cancel_member.request_cancel();
    auto member_result = collection->open_member(0, cancel_member.token());
    if (member_result) {
    } else {
        require(member_result.error().code == workspace_error_code_t::cancelled ||
                member_result.error().code == workspace_error_code_t::deadline_exceeded,
                "cancelled member open should report cancellation");
    }
}

void verify_concurrent_child_isolation(const std::filesystem::path& root) {
    auto inner_a = build_zip({
        {"class_a.class", {0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00, 0x00, 0x34}, false},
    });
    auto inner_b = build_zip({
        {"class_b.class", {0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00, 0x00, 0x35}, false},
    });
    auto outer = build_zip({
        {"nested_a.jar", inner_a, false},
        {"nested_b.jar", inner_b, false},
    });
    const auto path = root / "concurrent.zip";
    write_fixture(path, outer);

    auto collection = open_collection(path);
    require(collection->member_count() == 2,
            "concurrent test collection should have 2 members");

    std::atomic<bool> success_a{false};
    std::atomic<bool> success_b{false};
    std::atomic<bool> started{false};

    auto worker_a = [&]() {
        started.store(true, std::memory_order_release);
        auto child = collection->open_child_collection(0);
        if (child) {
            auto inner_collection = child.take_value();
            require(inner_collection->member_count() == 1,
                    "child A should have 1 member");
            auto provider = inner_collection->open_member(0);
            if (provider)
                success_a.store(true, std::memory_order_release);
        }
    };

    auto worker_b = [&]() {
        while (!started.load(std::memory_order_acquire))
            std::this_thread::yield();
        auto child = collection->open_child_collection(1);
        if (child) {
            auto inner_collection = child.take_value();
            require(inner_collection->member_count() == 1,
                    "child B should have 1 member");
            auto provider = inner_collection->open_member(0);
            if (provider)
                success_b.store(true, std::memory_order_release);
        }
    };

    std::thread thread_a(worker_a);
    std::thread thread_b(worker_b);
    thread_a.join();
    thread_b.join();

    require(success_a.load(), "concurrent child A open failed");
    require(success_b.load(), "concurrent child B open failed");
}

void verify_companion_debug_detection(const std::filesystem::path& root) {
    auto archive = build_zip({
        {"app.exe", {0x4D, 0x5A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, false},
        {"app.pdb", {0x4D, 0x44, 0x42, 0x46, 0x00, 0x00, 0x00, 0x00}, false},
        {"libfoo.so", {0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00}, false},
        {"libfoo.so.debug", {0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00}, false},
        {"unrelated.txt", {'h', 'e', 'l', 'l', 'o'}, false},
    });
    const auto path = root / "companion.zip";
    write_fixture(path, archive);

    collection_open_limits_t limits;
    limits.enable_companion_detection = true;
    auto collection = open_collection(path, limits);

    const auto* exe_member = collection->find_member("app.exe");
    require(exe_member != nullptr, "app.exe not found");
    require(exe_member->companion_debug_path.has_value(),
            "app.exe should have companion debug path");
    require(*exe_member->companion_debug_path == "app.pdb",
            "app.exe companion should be app.pdb");

    const auto* pdb_member = collection->find_member("app.pdb");
    require(pdb_member != nullptr, "app.pdb not found");
    require(pdb_member->member_kind == collection_member_kind_t::debug_companion,
            "app.pdb should be classified as debug_companion");
    require(pdb_member->companion_binary_path.has_value(),
            "app.pdb should have companion binary path");

    const auto* so_member = collection->find_member("libfoo.so");
    require(so_member != nullptr, "libfoo.so not found");
    require(so_member->companion_debug_path.has_value(),
            "libfoo.so should have companion debug path");
    require(*so_member->companion_debug_path == "libfoo.so.debug",
            "libfoo.so companion should be libfoo.so.debug");

    auto debug_provider = require_value(
        collection->open_companion_debug(0),
        "open_companion_debug for app.exe failed");
    require(debug_provider->size() == 8, "companion debug provider size mismatch");

    auto binary_provider = require_value(
        collection->open_companion_binary(1),
        "open_companion_binary for app.pdb failed");
    require(binary_provider->size() == 8, "companion binary provider size mismatch");
}

void verify_member_graph_operations(const std::filesystem::path& root) {
    auto inner_zip = build_zip({
        {"data.bin", {0x01, 0x02, 0x03, 0x04}, false},
    });
    auto outer_zip = build_zip({
        {"manifest.xml", {0x03, 0x00, 0x08, 0x00}, false},
        {"nested.zip", inner_zip, false},
        {"lib/x86/libnative.so", {0x7f, 0x45, 0x4c, 0x46}, false},
    });
    const auto path = root / "graph_test.zip";
    write_fixture(path, outer_zip);

    auto graph = std::make_shared<member_graph_t>();
    auto collection = open_collection(path, {}, graph);

    const auto root_node_value = collection->graph_node();
    require(root_node_value != 0, "collection should have a graph root node");

    member_node_id_t root_id;
    root_id.value = root_node_value;
    const auto* root_node = graph->node(root_id);
    require(root_node != nullptr, "root node should be retrievable");
    require(root_node->kind == member_node_kind_t::root_collection,
            "root node should be root_collection kind");

    auto children = graph->children(root_id);
    require(children.size() == 3, "root should have 3 child nodes");

    auto path_to_root_result = graph->path_to_root(children[0]);
    require(path_to_root_result.size() == 2,
            "path_to_root from first child should have 2 nodes");

    auto descendants_result = graph->descendants(root_id);
    require(descendants_result.size() >= 3,
            "root should have at least 3 descendants");

    auto all_nodes = graph->all_nodes();
    require(all_nodes.size() >= 4, "graph should have at least 4 nodes total");

    auto child_collection = require_value(
        collection->open_child_collection("nested.zip"),
        "open_child_collection for graph test failed");

    auto all_nodes_after = graph->all_nodes();
    require(all_nodes_after.size() > all_nodes.size(),
            "graph should grow after opening child collection");

    auto traverse_count = std::atomic<std::size_t>{0};
    auto traverse_result = graph->traverse(root_id,
        [&](const member_node_t& node) -> workspace_result_t<void> {
            traverse_count.fetch_add(1, std::memory_order_acq_rel);
            return workspace_result_t<void>::success();
        });
    require(static_cast<bool>(traverse_result), "traversal should succeed");
    require(traverse_count.load() > 0, "traversal should visit at least 1 node");

    auto lock_acquired = graph->acquire_child_lock(children[0]);
    require(lock_acquired, "first child lock should be acquired");
    auto lock_again = graph->acquire_child_lock(children[0]);
    require(!lock_again, "double-locking same child should fail");
    graph->release_child_lock(children[0]);
    auto lock_after_release = graph->acquire_child_lock(children[0]);
    require(lock_after_release, "child lock should be re-acquirable after release");
    graph->release_child_lock(children[0]);

    auto lock_a = graph->acquire_child_lock(children[0]);
    auto lock_b = graph->acquire_child_lock(children[1]);
    require(lock_a && lock_b, "different children should be independently lockable");
    require(graph->active_locks() == 2, "graph should report 2 active locks");
    graph->release_child_lock(children[0]);
    graph->release_child_lock(children[1]);
    require(graph->active_locks() == 0, "graph should report 0 active locks after release");

    auto provenance = graph->provenance_chain(children[0]);
    require(!provenance.empty(), "child node should have provenance chain");
}

void verify_provenance_chain_tracking(const std::filesystem::path& root) {
    auto inner_zip = build_zip({
        {"leaf.class", {0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00, 0x00, 0x34}, false},
    });
    auto middle_zip = build_zip({
        {"inner.jar", inner_zip, false},
    });
    auto outer_zip = build_zip({
        {"middle.jar", middle_zip, false},
    });
    const auto path = root / "provenance.zip";
    write_fixture(path, outer_zip);

    auto collection = open_collection(path);
    require(collection->provenance().empty(),
            "root collection should have empty provenance");

    auto child = require_value(collection->open_child_collection("middle.jar"),
                               "open middle.jar failed");
    require(child->provenance().size() == 1,
            "child collection should have 1 provenance link");

    auto grandchild = require_value(child->open_child_collection("inner.jar"),
                                    "open inner.jar failed");
    require(grandchild->provenance().size() == 2,
            "grandchild collection should have 2 provenance links");

    const auto& member = grandchild->members()[0];
    require(member.provenance_chain.size() >= 3,
            "leaf member should have at least 3 provenance chain entries");
}

void verify_duplicate_name_tracking_within_collection(const std::filesystem::path& root) {
    auto archive = build_zip({
        {"lib/x86/libnative.so", {0x7f, 0x45, 0x4c, 0x46, 0x01}, false},
        {"lib/arm64/libnative.so", {0x7f, 0x45, 0x4c, 0x46, 0x02}, false},
        {"lib/x86_64/libnative.so", {0x7f, 0x45, 0x4c, 0x46, 0x03}, false},
    });
    const auto path = root / "dup_within.zip";
    write_fixture(path, archive);

    auto collection = open_collection(path);
    auto dupes = collection->duplicate_member_names();
    require(!dupes.empty(), "collection should report duplicate member names");

    bool found_libnative = false;
    for (const auto& name : dupes) {
        if (name == "libnative.so")
            found_libnative = true;
    }
    require(found_libnative, "duplicate names should include libnative.so");

    auto members = collection->members_with_name("libnative.so");
    require(members.size() == 3, "should find 3 members named libnative.so");

    for (const auto* member : members) {
        require(!member->duplicate_path_siblings.empty(),
                "each duplicate member should have sibling paths");
    }
}

void verify_graph_traversal_cancellation(const std::filesystem::path& root) {
    auto archive = build_zip({
        {"file1.bin", {0x01, 0x02}, false},
        {"file2.bin", {0x03, 0x04}, false},
        {"file3.bin", {0x05, 0x06}, false},
    });
    const auto path = root / "traversal_cancel.zip";
    write_fixture(path, archive);

    auto graph = std::make_shared<member_graph_t>();
    auto collection = open_collection(path, {}, graph);

    member_node_id_t root_id;
    root_id.value = collection->graph_node();

    cancellation_source_t cancel_source;
    cancel_source.request_cancel();

    std::atomic<std::size_t> visit_count{0};
    auto result = graph->traverse(root_id,
        [&](const member_node_t& node) -> workspace_result_t<void> {
            visit_count.fetch_add(1, std::memory_order_acq_rel);
            return workspace_result_t<void>::success();
        }, cancel_source.token());

    require(!result, "cancelled traversal should fail");
    require(result.error().code == workspace_error_code_t::cancelled ||
            result.error().code == workspace_error_code_t::deadline_exceeded,
            "cancelled traversal should report cancellation");
}

void append_u32_be(std::vector<std::uint8_t>& output, std::uint32_t value) {
    output.push_back(static_cast<std::uint8_t>(value >> 24));
    output.push_back(static_cast<std::uint8_t>(value >> 16));
    output.push_back(static_cast<std::uint8_t>(value >> 8));
    output.push_back(static_cast<std::uint8_t>(value));
}

std::vector<std::uint8_t> build_minimal_macho64(std::int32_t cputype,
                                                std::int32_t cpusubtype) {
    std::vector<std::uint8_t> macho;
    append_u32(macho, 0xFEEDFACFu);
    append_u32(macho, static_cast<std::uint32_t>(cputype));
    append_u32(macho, static_cast<std::uint32_t>(cpusubtype));
    append_u32(macho, 2u);
    append_u32(macho, 0u);
    append_u32(macho, 0u);
    append_u32(macho, 0u);
    append_u32(macho, 0u);
    return macho;
}

std::vector<std::uint8_t> build_fat_macho_two_slices() {
    constexpr std::int32_t CPU_TYPE_X86_64 = 0x01000007;
    constexpr std::int32_t CPU_TYPE_ARM64 = 0x0100000C;
    constexpr std::int32_t CPU_SUBTYPE_X86_64_ALL = 3;
    constexpr std::int32_t CPU_SUBTYPE_ARM64_ALL = 0;

    auto slice0 = build_minimal_macho64(CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL);
    auto slice1 = build_minimal_macho64(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL);

    const std::uint32_t header_size = 8 + 2 * 20;
    const std::uint32_t slice0_offset = header_size;
    const std::uint32_t slice0_size = static_cast<std::uint32_t>(slice0.size());
    const std::uint32_t slice1_offset = slice0_offset + slice0_size;
    const std::uint32_t slice1_size = static_cast<std::uint32_t>(slice1.size());

    std::vector<std::uint8_t> fat;
    append_u32_be(fat, 0xCAFEBABEu);
    append_u32_be(fat, 2u);

    append_u32_be(fat, static_cast<std::uint32_t>(CPU_TYPE_X86_64));
    append_u32_be(fat, static_cast<std::uint32_t>(CPU_SUBTYPE_X86_64_ALL));
    append_u32_be(fat, slice0_offset);
    append_u32_be(fat, slice0_size);
    append_u32_be(fat, 12u);

    append_u32_be(fat, static_cast<std::uint32_t>(CPU_TYPE_ARM64));
    append_u32_be(fat, static_cast<std::uint32_t>(CPU_SUBTYPE_ARM64_ALL));
    append_u32_be(fat, slice1_offset);
    append_u32_be(fat, slice1_size);
    append_u32_be(fat, 14u);

    fat.insert(fat.end(), slice0.begin(), slice0.end());
    fat.insert(fat.end(), slice1.begin(), slice1.end());
    return fat;
}

void verify_fat_macho_slices(const std::filesystem::path& root) {
    const auto fat_bytes = build_fat_macho_two_slices();
    const auto path = root / "test_fat.macho";
    write_fixture(path, fat_bytes);
    auto collection = open_collection(path);
    require(collection->kind() == collection_kind_t::fat_macho,
            "fat Mach-O was not classified as fat_macho");
    require(collection->member_count() == 2,
            "fat Mach-O collection should have 2 slice members");

    const auto& slice0 = collection->members()[0];
    const auto& slice1 = collection->members()[1];
    require(slice0.member_kind == collection_member_kind_t::fat_slice,
            "slice 0 should be classified as fat_slice");
    require(slice1.member_kind == collection_member_kind_t::fat_slice,
            "slice 1 should be classified as fat_slice");
    require(slice0.normalized_path == "slice_0",
            "slice 0 should have stable identity slice_0");
    require(slice1.normalized_path == "slice_1",
            "slice 1 should have stable identity slice_1");
    require(slice0.architecture != slice1.architecture,
            "slices should have distinct architectures");
    require(slice0.architecture == architecture_id_t::x86_64,
            "slice 0 should be x86_64");
    require(slice1.architecture == architecture_id_t::aarch64,
            "slice 1 should be aarch64");
    require(slice0.container_offset != slice1.container_offset,
            "slices should have distinct container offsets");
    require(slice0.ordinal == 0, "slice 0 ordinal should be 0");
    require(slice1.ordinal == 1, "slice 1 ordinal should be 1");
}

void verify_aab_classification(const std::filesystem::path& root) {
    const auto archive_bytes = build_zip({
        {"AndroidManifest.xml", {0x03, 0x00, 0x08, 0x00}, false},
        {"base/dex/classes.dex", {0x64, 0x65, 0x78, 0x0a, 0x03, 0x00, 0x00, 0x00}, false},
        {"base/assets/config.json", {0x7b, 0x7d, 0x00, 0x00}, false},
        {"base/lib/arm64-v8a/libnative.so", {0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00}, false},
    });
    const auto path = root / "test.aab";
    write_fixture(path, archive_bytes);
    auto collection = open_collection(path);
    require(collection->kind() == collection_kind_t::aab,
            "ZIP with base/dex/ and AndroidManifest.xml was not classified as AAB");
    require(collection->member_count() >= 3,
            "AAB collection should have at least 3 members");

    const auto* manifest_member = collection->find_member("AndroidManifest.xml");
    require(manifest_member != nullptr, "AndroidManifest.xml member not found in AAB");
    require(manifest_member->member_kind == collection_member_kind_t::manifest,
            "AndroidManifest.xml was not classified as manifest in AAB");

    const auto* dex_member = collection->find_member("base/dex/classes.dex");
    require(dex_member != nullptr, "base/dex/classes.dex member not found in AAB");
    require(dex_member->member_kind == collection_member_kind_t::dex,
            "base/dex/classes.dex was not classified as dex in AAB");

    const auto* so_member = collection->find_member("base/lib/arm64-v8a/libnative.so");
    require(so_member != nullptr, "base/lib/arm64-v8a/libnative.so member not found in AAB");
    require(so_member->member_kind == collection_member_kind_t::native_library,
            "libnative.so in AAB was not classified as native_library");
}

}

void run_collection_graph_harness(const std::filesystem::path& root) {
    std::filesystem::create_directories(root);
    try {
        verify_zip_archive_kind_detection(root);
        verify_ipa_classification(root);
        verify_jar_classification(root);
        verify_standalone_binary(root);
        verify_deep_nesting(root);
        verify_duplicate_names_across_nesting(root);
        verify_member_hash_identity(root);
        verify_cancellation(root);
        verify_concurrent_child_isolation(root);
        verify_companion_debug_detection(root);
        verify_member_graph_operations(root);
        verify_provenance_chain_tracking(root);
        verify_duplicate_name_tracking_within_collection(root);
        verify_graph_traversal_cancellation(root);
        verify_fat_macho_slices(root);
        verify_aab_classification(root);
    } catch (...) {
        std::error_code ignored;
        std::filesystem::remove_all(root, ignored);
        throw;
    }
    std::error_code ignored;
    std::filesystem::remove_all(root, ignored);
}

}

int main() {
    std::filesystem::path root;
    std::error_code ignored;
    try {
        root = std::filesystem::temp_directory_path() / "aida-c03-collection-graph";
        std::filesystem::remove_all(root, ignored);
        aida::analysis::c03::run_collection_graph_harness(root);
        std::cout << "collection_graph_harness source contract satisfied\n";
        return 0;
    } catch (const std::exception& error) {
		aida::analysis::c03_test::assertion_telemetry::record_exception(error.what());
        std::filesystem::remove_all(root, ignored);
        std::cerr << error.what() << '\n';
        return 1;
    }
}
