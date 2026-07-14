#include "fixture_materializer_harness.hpp"
#include "assertion_telemetry/assertion_telemetry.hpp"

#include "decompiler_quality_schema.hpp"
#include "evidence_hash.hpp"
#include "fixture_materializer.hpp"
#include "managed_fixture_fidelity/managed_fixture_fidelity.hpp"

#include "../../src/core/analysis/readers/managed/classfile_reader.hpp"
#include "../../src/core/analysis/readers/managed/dex_reader.hpp"
#include "../../src/core/analysis/readers/managed/managed_reader_contracts.hpp"
#include "../../src/core/analysis/workspace/byte_provider.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <fstream>
#include <memory>
#include <set>
#include <stdexcept>
#include <string_view>
#include <utility>
#include <vector>

namespace aida::analysis::c03
{
namespace
{
    namespace managed = ::aida::analysis::readers::managed;

    json load_json(const std::filesystem::path& path, std::uint64_t limit)
    {
        std::error_code error;
        if (!std::filesystem::is_regular_file(path, error) || error)
            throw std::runtime_error("fixture contract file is absent");
        const auto size = std::filesystem::file_size(path, error);
        if (error || size == 0 || size > limit)
            throw std::runtime_error("fixture contract file size is invalid");
        std::ifstream stream(path, std::ios::binary);
        if (!stream)
            throw std::runtime_error("fixture contract file cannot be opened");
        json value;
        stream >> value;
        if (!stream || !stream.eof())
            throw std::runtime_error("fixture contract JSON is malformed or has trailing data");
        return value;
    }

void require(bool condition, std::string message)
{
	aida::analysis::c03_test::assertion_telemetry::record_assertion(condition, message, __FILE__, __LINE__);
    if (!condition)
            throw std::runtime_error(std::move(message));
    }

    std::set<std::string, std::less<>> values(const json& records, std::string_view field)
    {
        std::set<std::string, std::less<>> output;
        for (const auto& record : records) {
            require(record.is_object() && record.contains(std::string(field)) &&
                record.at(std::string(field)).is_string(), "fixture record identity field is invalid");
            output.insert(record.at(std::string(field)).get<std::string>());
        }
        return output;
    }

    const materialized_fixture_t& fixture_by_id(
        const std::vector<materialized_fixture_t>& fixtures, std::string_view id)
    {
        const auto found = std::find_if(fixtures.begin(), fixtures.end(),
            [id](const auto& fixture) { return fixture.id == id; });
        require(found != fixtures.end(), "required materialized fixture is absent");
        return *found;
    }

    std::vector<std::uint8_t> load_binary(const std::filesystem::path& path,
        std::uint64_t limit)
    {
        std::error_code error;
        const auto size = std::filesystem::file_size(path, error);
        require(!error && size != 0U && size <= limit,
            "managed fixture size is absent or exceeds its bound");
        std::ifstream stream(path, std::ios::binary);
        require(static_cast<bool>(stream), "managed fixture cannot be opened");
        std::vector<std::uint8_t> bytes(static_cast<std::size_t>(size));
        stream.read(reinterpret_cast<char*>(bytes.data()),
            static_cast<std::streamsize>(bytes.size()));
        require(stream.good() || stream.eof(), "managed fixture cannot be read");
        require(static_cast<std::size_t>(stream.gcount()) == bytes.size(),
            "managed fixture read was truncated");
        return bytes;
    }

    std::shared_ptr<mapped_file_provider_t> open_provider(
        const std::filesystem::path& path)
    {
        auto provider = mapped_file_provider_t::open(path.u8string());
        require(provider.has_value(), "managed fixture provider could not be opened");
        return provider.take_value();
    }

    std::shared_ptr<mapped_file_provider_t> write_mutant(
        const std::filesystem::path& root, std::string_view name,
        const std::vector<std::uint8_t>& bytes)
    {
        std::error_code error;
        std::filesystem::create_directories(root, error);
        require(!error, "managed mutant directory could not be created");
        const auto path = root / std::filesystem::u8path(std::string(name));
        std::ofstream stream(path, std::ios::binary | std::ios::trunc);
        require(static_cast<bool>(stream), "managed mutant file could not be created");
        stream.write(reinterpret_cast<const char*>(bytes.data()),
            static_cast<std::streamsize>(bytes.size()));
        stream.flush();
        require(static_cast<bool>(stream), "managed mutant file could not be written");
        return open_provider(path);
    }

    void put_le16(std::vector<std::uint8_t>& bytes, std::size_t offset,
        std::uint16_t value)
    {
        require(offset <= bytes.size() && 2U <= bytes.size() - offset,
            "managed mutant 16-bit write exceeds input");
        bytes[offset] = static_cast<std::uint8_t>(value);
        bytes[offset + 1U] = static_cast<std::uint8_t>(value >> 8U);
    }

    void put_le32(std::vector<std::uint8_t>& bytes, std::size_t offset,
        std::uint32_t value)
    {
        require(offset <= bytes.size() && 4U <= bytes.size() - offset,
            "managed mutant 32-bit write exceeds input");
        bytes[offset] = static_cast<std::uint8_t>(value);
        bytes[offset + 1U] = static_cast<std::uint8_t>(value >> 8U);
        bytes[offset + 2U] = static_cast<std::uint8_t>(value >> 16U);
        bytes[offset + 3U] = static_cast<std::uint8_t>(value >> 24U);
    }

    std::uint32_t read_uleb(const std::vector<std::uint8_t>& bytes,
        std::size_t& cursor)
    {
        std::uint32_t value = 0U;
        unsigned shift = 0U;
        for (unsigned count = 0U; count < 5U; ++count) {
            require(cursor < bytes.size(), "managed mutant ULEB128 is truncated");
            const auto byte = bytes[cursor++];
            require(count != 4U || (byte & 0xf0U) == 0U,
                "managed mutant ULEB128 exceeds 32 bits");
            value |= static_cast<std::uint32_t>(byte & 0x7fU) << shift;
            if ((byte & 0x80U) == 0U)
                return value;
            shift += 7U;
        }
        throw std::runtime_error("managed mutant ULEB128 exceeds 32 bits");
    }

    void reseal(std::vector<std::uint8_t>& bytes)
    {
        std::string error;
        require(seal_c03_dex(bytes, error), error);
    }

    void require_dex_reader_rejection(const std::filesystem::path& root,
        std::string_view name, const std::vector<std::uint8_t>& bytes)
    {
        const auto provider = write_mutant(root, name, bytes);
        const auto result = managed::read_dex(*provider);
        require(!result.has_value(), "malformed DEX fixture was accepted by the production reader");
    }

    void verify_classfile_fixture(const materialized_fixture_t& fixture,
        const std::filesystem::path& mutant_root)
    {
        const auto bytes = load_binary(fixture.path, 4ULL * 1024ULL * 1024ULL);
        const auto provider = open_provider(fixture.path);
        const auto metadata = managed::parse_classfile_metadata(*provider);
        require(metadata.has_value(), "production classfile metadata reader rejected the fixture");
        const auto artifact = managed::read_classfile(*provider);
        require(artifact.has_value() && artifact.value().valid(),
            "production classfile artifact reader rejected the fixture");
        const auto& image = metadata.value().image;
        const auto& value = artifact.value();
        std::set<decompiler_entity_key_t> identities;
        std::size_t body_count = 0U;
        std::size_t named_body_count = 0U;
        for (std::size_t index = 0; index < value.methods.size(); ++index) {
            const auto& method = value.methods[index];
            if (!method.has_body)
                continue;
            ++body_count;
            if (method.method_name == "add" || method.method_name == "guardedDivide")
                ++named_body_count;
            require(method.code_size != 0U && method.code_offset <= provider->size() &&
                method.code_size <= provider->size() - method.code_offset,
                "classfile method code range exceeds the provider");
            identities.insert(managed::build_jvm_entity_key(value,
                static_cast<std::uint32_t>(index)));
        }
        require(body_count >= 3U && named_body_count == 2U &&
            identities.size() == body_count,
            "classfile fixture does not expose distinct stable method identities");
        bool branch = false;
        bool invoke = false;
        bool debug_locals = false;
        for (const auto& method : image.methods) {
            if (!method.code)
                continue;
            debug_locals = debug_locals || !method.code->local_variables.empty();
            for (const auto& instruction : method.code->instructions) {
                branch = branch || instruction.branch_target.has_value();
                invoke = invoke || (instruction.opcode >= 0xb6U &&
                    instruction.opcode <= 0xbaU);
            }
        }
        require(branch && invoke && debug_locals &&
            !metadata.value().all_exception_regions.empty(),
            "classfile fixture omits branch, invoke, locals, or exception metadata");

        auto truncated = bytes;
        truncated.resize(truncated.size() - 7U);
        const auto truncated_provider = write_mutant(
            mutant_root, "classfile-truncated.class", truncated);
        require(!managed::read_classfile(*truncated_provider).has_value(),
            "truncated classfile fixture was accepted");
        auto count_overflow = bytes;
        count_overflow[8U] = 0xffU;
        count_overflow[9U] = 0xffU;
        const auto count_provider = write_mutant(
            mutant_root, "classfile-count-overflow.class", count_overflow);
        require(!managed::read_classfile(*count_provider).has_value(),
            "classfile constant-pool count overflow was accepted");
        managed::managed_reader_limits_t limits;
        limits.max_methods = 2U;
        require(!managed::read_classfile(*provider, limits).has_value(),
            "classfile method allocation limit was not enforced");
        managed::managed_reader_limits_t file_limits;
        file_limits.max_metadata_bytes = bytes.size() - 1U;
        require(!managed::read_classfile(*provider, file_limits).has_value(),
            "classfile file-size allocation limit was not enforced");
        cancellation_source_t cancelled;
        cancelled.request_cancel();
        const auto cancelled_result = managed::read_classfile(
            *provider, {}, cancelled.token());
        require(!cancelled_result.has_value() &&
            cancelled_result.error().code == workspace_error_code_t::cancelled,
            "classfile cancellation was not propagated");
        cancellation_source_t expired(
            std::chrono::steady_clock::now() - std::chrono::milliseconds(1));
        const auto expired_result = managed::read_classfile(
            *provider, {}, expired.token());
        require(!expired_result.has_value() &&
            expired_result.error().code == workspace_error_code_t::deadline_exceeded,
            "classfile deadline was not propagated");
    }

    void verify_dex_fixture(const materialized_fixture_t& fixture,
        const std::filesystem::path& mutant_root)
    {
        const auto bytes = load_binary(fixture.path, 4ULL * 1024ULL * 1024ULL);
        const auto fidelity = validate_c03_dex_fidelity(bytes);
        require(fidelity.valid, fidelity.error);
        const auto provider = open_provider(fixture.path);
        const auto metadata = managed::parse_dex_metadata(*provider);
        require(metadata.has_value(), "production DEX metadata reader rejected the fixture");
        const auto artifact = managed::read_dex(*provider);
        require(artifact.has_value() && artifact.value().valid(),
            "production DEX artifact reader rejected the fixture");
        const auto& value = artifact.value();
        std::set<decompiler_entity_key_t> identities;
        std::size_t body_count = 0U;
        std::size_t named_body_count = 0U;
        for (std::size_t index = 0; index < value.methods.size(); ++index) {
            const auto& method = value.methods[index];
            if (!method.has_body)
                continue;
            ++body_count;
            if (method.method_name == "add" || method.method_name == "guardedDivide")
                ++named_body_count;
            require(method.code_size != 0U && method.code_offset <= provider->size() &&
                method.code_size <= provider->size() - method.code_offset,
                "DEX method code range exceeds the provider");
            identities.insert(managed::build_dalvik_entity_key(value,
                static_cast<std::uint32_t>(index)));
        }
        require(body_count >= 3U && named_body_count == 2U &&
            identities.size() == body_count,
            "DEX fixture does not expose distinct stable method identities");
        bool debug = false;
        bool tries = false;
        bool instructions = false;
        for (const auto& definition : metadata.value().image.classes) {
            for (const auto& method : definition.direct_methods) {
                if (!method.code)
                    continue;
                debug = debug || method.code->debug_info.has_value();
                tries = tries || !method.code->tries.empty();
                instructions = instructions || !method.code->instructions.empty();
            }
        }
        require(debug && tries && instructions && fidelity.dex.code_item_count == 3U &&
            fidelity.dex.debug_info_count == 3U,
            "DEX fixture omits instructions, tries, or debug metadata");

        auto checksum = bytes;
        checksum[8U] ^= 1U;
        require(!validate_c03_dex_fidelity(checksum).valid,
            "DEX checksum mismatch was accepted");
        auto signature = bytes;
        signature[12U] ^= 1U;
        require(!validate_c03_dex_fidelity(signature).valid,
            "DEX signature mismatch was accepted");
        auto truncated = bytes;
        truncated.pop_back();
        require(!validate_c03_dex_fidelity(truncated).valid,
            "truncated DEX fixture was accepted");
        auto duplicate_map = bytes;
        const auto first_map_item = static_cast<std::size_t>(fidelity.dex.map_offset) + 4U;
        put_le16(duplicate_map, first_map_item + 12U,
            static_cast<std::uint16_t>(duplicate_map[first_map_item] |
                (static_cast<std::uint16_t>(duplicate_map[first_map_item + 1U]) << 8U)));
        reseal(duplicate_map);
        require(!validate_c03_dex_fidelity(duplicate_map).valid,
            "duplicate DEX map type was accepted");
        require_dex_reader_rejection(
            mutant_root, "dex-duplicate-map.dex", duplicate_map);
        auto bad_offset = bytes;
        put_le32(bad_offset, 112U,
            static_cast<std::uint32_t>(bad_offset.size() + 16U));
        reseal(bad_offset);
        require_dex_reader_rejection(mutant_root, "dex-bad-offset.dex", bad_offset);
        auto bad_count = bytes;
        put_le32(bad_count, 88U, 0xffffffffU);
        reseal(bad_count);
        require(!validate_c03_dex_fidelity(bad_count).valid,
            "DEX identifier count overflow was accepted");
        require_dex_reader_rejection(mutant_root, "dex-count-overflow.dex", bad_count);
        auto duplicate_method = bytes;
        std::size_t cursor = fidelity.dex.class_data_offset;
        for (unsigned index = 0U; index < 4U; ++index)
            static_cast<void>(read_uleb(duplicate_method, cursor));
        static_cast<void>(read_uleb(duplicate_method, cursor));
        static_cast<void>(read_uleb(duplicate_method, cursor));
        static_cast<void>(read_uleb(duplicate_method, cursor));
        require(cursor < duplicate_method.size(),
            "DEX duplicate-method mutation cursor exceeds input");
        duplicate_method[cursor] = 0U;
        reseal(duplicate_method);
        require_dex_reader_rejection(
            mutant_root, "dex-duplicate-method.dex", duplicate_method);

        managed::managed_reader_limits_t limits;
        limits.max_methods = 2U;
        require(!managed::read_dex(*provider, limits).has_value(),
            "DEX method allocation limit was not enforced");
        managed::dex_parse_limits_t file_limits;
        file_limits.parser_limits.max_file_size = bytes.size() - 1U;
        require(!managed::parse_dex_metadata(*provider, file_limits).has_value(),
            "DEX file-size allocation limit was not enforced");
        cancellation_source_t cancelled;
        cancelled.request_cancel();
        const auto cancelled_result = managed::read_dex(
            *provider, {}, cancelled.token());
        require(!cancelled_result.has_value() &&
            cancelled_result.error().code == workspace_error_code_t::cancelled,
            "DEX cancellation was not propagated");
        cancellation_source_t expired(
            std::chrono::steady_clock::now() - std::chrono::milliseconds(1));
        const auto expired_result = managed::read_dex(
            *provider, {}, expired.token());
        require(!expired_result.has_value() &&
            expired_result.error().code == workspace_error_code_t::deadline_exceeded,
            "DEX deadline was not propagated");
    }

    void verify_collection_member_reuse(
        const std::vector<materialized_fixture_t>& fixtures)
    {
        const auto dex = load_binary(fixture_by_id(fixtures, "dex-dalvik").path,
            4ULL * 1024ULL * 1024ULL);
        const auto classfile = load_binary(
            fixture_by_id(fixtures, "classfile-jvm").path,
            4ULL * 1024ULL * 1024ULL);
        for (const auto id : {"apk-multidex", "aab-multidex"}) {
            const auto archive = load_binary(fixture_by_id(fixtures, id).path,
                8ULL * 1024ULL * 1024ULL);
            std::vector<std::uint8_t> member;
            std::string error;
            require(extract_c03_stored_zip_member(
                archive, "classes.dex", member, error), error);
            require(member == dex,
                "APK/AAB fixture does not reuse the canonical DEX member bytes");
        }
        const auto jar = load_binary(fixture_by_id(fixtures, "jar-jvm").path,
            8ULL * 1024ULL * 1024ULL);
        std::vector<std::uint8_t> member;
        std::string error;
        require(extract_c03_stored_zip_member(jar,
            "aida/c03/corpus/Fixture.class", member, error), error);
        require(member == classfile,
            "JAR fixture does not reuse the canonical classfile member bytes");
    }

    void verify_managed_fixture_fidelity(
        const std::vector<materialized_fixture_t>& fixtures,
        const std::filesystem::path& output_root)
    {
        const auto mutant_root = output_root / "managed-fixture-fidelity";
        verify_classfile_fixture(
            fixture_by_id(fixtures, "classfile-jvm"), mutant_root);
        verify_dex_fixture(fixture_by_id(fixtures, "dex-dalvik"), mutant_root);
        verify_collection_member_reuse(fixtures);
    }
}

bool run_fixture_materializer_harness(const std::filesystem::path& repository_root,
    const std::filesystem::path& output_root, std::string& failure)
{
    try {
        const auto fixture_root = repository_root / "src/standalone/tests/c03/fixtures";
        const auto manifest = load_json(fixture_root / "corpus_manifest.json", 4ULL * 1024ULL * 1024ULL);
        const auto recipes = load_json(fixture_root / "corpus_generator_recipes.json", 4ULL * 1024ULL * 1024ULL);
        const auto ground_truth = load_json(fixture_root / "corpus_ground_truth.json", 8ULL * 1024ULL * 1024ULL);
        const auto malformed = load_json(fixture_root / "malformed_cases.json", 4ULL * 1024ULL * 1024ULL);
        const auto manifest_result = validate_corpus_manifest(manifest);
        require(manifest_result.valid, manifest_result.summary());
        for (const auto source_name : {"generator_source", "materializer_source", "ground_truth_source"}) {
            const auto& source = manifest.at(source_name);
            const auto observed = sha256_repository_evidence_file(repository_root,
                source.at("path").get<std::string>(), 16ULL * 1024ULL * 1024ULL);
            require(observed.ok && observed.sha256 == source.at("sha256").get<std::string>(),
                observed.ok ? std::string(source_name) + " hash binding mismatch" : observed.error);
        }
        const auto malformed_result = validate_malformed_case_manifest(manifest, malformed);
        require(malformed_result.valid, malformed_result.summary());
        require(recipes.at("target_execution_forbidden") == true &&
            ground_truth.at("target_execution_forbidden") == true,
            "target execution prohibition is absent");
        const auto manifest_ids = values(manifest.at("fixtures"), "id");
        require(manifest_ids == values(recipes.at("recipes"), "id") &&
            manifest_ids == values(ground_truth.at("fixtures"), "id"),
            "manifest, recipes, and ground truth do not have identical fixture inventories");
        const std::set<std::string, std::less<>> mandatory_formats{"pe32", "pe32plus", "coff", "static_library",
            "import_library", "cli", "readytorun", "elf32", "elf64", "macho_thin", "macho_fat", "zip", "zip64",
            "apk", "aab", "dex", "oat", "vdex", "ipa", "jar", "classfile", "raw_code"};
        const std::set<std::string, std::less<>> mandatory_architectures{"x86", "x64", "arm", "thumb", "aarch64",
            "arm64ec", "arm64x", "mips32", "mips64", "ppc32", "ppc64", "riscv32", "riscv64", "jvm",
            "dalvik", "cil"};
        const auto formats = values(manifest.at("fixtures"), "format");
        const auto architectures = values(manifest.at("fixtures"), "architecture_identity");
        require(std::includes(formats.begin(), formats.end(), mandatory_formats.begin(), mandatory_formats.end()),
            "fixture format matrix is incomplete");
        require(std::includes(architectures.begin(), architectures.end(), mandatory_architectures.begin(), mandatory_architectures.end()),
            "fixture architecture matrix is incomplete");
        const auto first_root = output_root / "first";
        const auto second_root = output_root / "second";
        const auto first = materialize_c03_corpus(manifest, recipes, ground_truth, first_root);
        const auto second = materialize_c03_corpus(manifest, recipes, ground_truth, second_root);
        require(first.ok, first.error);
        require(second.ok, second.error);
        require(first.fixtures.size() == second.fixtures.size() && first.fixtures.size() == manifest_ids.size(),
            "materialized fixture cardinality is nondeterministic");
        for (std::size_t index = 0; index < first.fixtures.size(); ++index) {
            require(first.fixtures[index].id == second.fixtures[index].id &&
                first.fixtures[index].artifact_sha256 == second.fixtures[index].artifact_sha256 &&
                first.fixtures[index].recipe_sha256 == second.fixtures[index].recipe_sha256 &&
                first.fixtures[index].ground_truth_sha256 == second.fixtures[index].ground_truth_sha256 &&
                first.fixtures[index].size_bytes == second.fixtures[index].size_bytes,
                "fixture materialization is not byte deterministic");
        }
        verify_managed_fixture_fidelity(first.fixtures, output_root);
        const auto first_validation = validate_materialization_receipt(first.receipt, manifest, recipes, ground_truth, first_root);
        const auto second_validation = validate_materialization_receipt(second.receipt, manifest, recipes, ground_truth, second_root);
        require(first_validation.valid, first_validation.summary());
        require(second_validation.valid, second_validation.summary());
        const auto malformed_first_root = output_root / "malformed-first";
        const auto malformed_second_root = output_root / "malformed-second";
        const auto malformed_first = materialize_c03_malformed_corpus(malformed, first.fixtures, malformed_first_root);
        const auto malformed_second = materialize_c03_malformed_corpus(malformed, second.fixtures, malformed_second_root);
        require(malformed_first.ok, malformed_first.error);
        require(malformed_second.ok, malformed_second.error);
        require(malformed_first.fixtures.size() == malformed.at("cases").size() &&
            malformed_first.fixtures.size() == malformed_second.fixtures.size(),
            "malformed fixture materialization coverage is incomplete");
        for (std::size_t index = 0; index < malformed_first.fixtures.size(); ++index) {
            require(malformed_first.fixtures[index].id == malformed_second.fixtures[index].id &&
                malformed_first.fixtures[index].artifact_sha256 == malformed_second.fixtures[index].artifact_sha256 &&
                malformed_first.fixtures[index].recipe_sha256 == malformed_second.fixtures[index].recipe_sha256 &&
                malformed_first.fixtures[index].size_bytes == malformed_second.fixtures[index].size_bytes,
                "malformed fixture materialization is not byte deterministic");
        }
        const auto malformed_first_validation = validate_malformed_materialization_receipt(
            malformed_first.receipt, malformed, malformed_first_root);
        const auto malformed_second_validation = validate_malformed_materialization_receipt(
            malformed_second.receipt, malformed, malformed_second_root);
        require(malformed_first_validation.valid, malformed_first_validation.summary());
        require(malformed_second_validation.valid, malformed_second_validation.summary());
        auto mutated_receipt = first.receipt;
        mutated_receipt.at("fixtures").front()["artifact_sha256"] = std::string(64, '0');
        require(!validate_materialization_receipt(mutated_receipt, manifest, recipes, ground_truth, first_root).valid,
            "tampered artifact hash was accepted");
        mutated_receipt = first.receipt;
        mutated_receipt["target_execution_forbidden"] = false;
        require(!validate_materialization_receipt(mutated_receipt, manifest, recipes, ground_truth, first_root).valid,
            "target execution permission was accepted");
        auto malformed_mutation = malformed_first.receipt;
        malformed_mutation.at("fixtures").front()["artifact_sha256"] = std::string(64, '0');
        require(!validate_malformed_materialization_receipt(
            malformed_mutation, malformed, malformed_first_root).valid,
            "tampered malformed fixture hash was accepted");
        failure.clear();
        return true;
    } catch (const std::exception& error) {
		aida::analysis::c03_test::assertion_telemetry::record_exception(error.what());
        failure = error.what();
        return false;
    }
}
}
