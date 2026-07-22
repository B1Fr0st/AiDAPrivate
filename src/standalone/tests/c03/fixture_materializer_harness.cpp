#include "fixture_materializer_harness.hpp"
#include "assertion_telemetry/assertion_telemetry.hpp"

#include "decompiler_quality_schema.hpp"
#include "evidence_hash.hpp"
#include "fixture_materializer.hpp"
#include "managed_fixture_fidelity/managed_fixture_fidelity.hpp"

#include "../../src/core/analysis/readers/managed/classfile_reader.hpp"
#include "../../src/core/analysis/readers/managed/cli_metadata_reader.hpp"
#include "../../src/core/analysis/readers/managed/dex_reader.hpp"
#include "../../src/core/analysis/readers/managed/managed_reader_contracts.hpp"
#include "../../src/core/analysis/workspace/byte_provider.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <fstream>
#include <memory>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
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
        if (!stream)
            throw std::runtime_error("fixture contract JSON is malformed or has trailing data");
        stream >> std::ws;
        if (stream.bad() || !stream.eof())
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
        if (!provider)
            throw std::runtime_error("managed fixture provider could not be opened: " +
                path.u8string() + ": " + provider.error().message);
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
        stream.close();
        require(static_cast<bool>(stream), "managed mutant file could not be committed");
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

    void verify_cli_fixture(const materialized_fixture_t& fixture,
        bool ready_to_run)
    {
        const auto bytes = load_binary(fixture.path, 8ULL * 1024ULL * 1024ULL);
        const auto provider = open_provider(fixture.path);
        const auto metadata = managed::parse_cli_metadata(*provider);
        require(metadata.has_value(), "production CLI metadata reader rejected the fixture");
        const auto artifact = managed::read_cli_metadata(*provider);
        require(artifact.has_value() && artifact.value().valid(),
            "production CLI artifact reader rejected the fixture");
        const auto& parsed = metadata.value();
        const auto& value = artifact.value();
        require(parsed.method_defs.size() == 2U && parsed.method_bodies.size() == 2U &&
            parsed.params.size() == 4U && value.methods.size() == 2U &&
            value.code_ranges.size() == 2U,
            "CLI fixture does not expose both source methods and parameter rows");
        require(std::any_of(value.types.begin(), value.types.end(), [](const auto& type) {
            return type.fully_qualified_name == "AiDA.C03.Corpus.ManagedFixture";
        }), "CLI fixture namespace disagrees with its source corpus");
        const std::array<std::pair<std::string, std::vector<std::uint8_t>>, 2>
            expected_methods{{
                {"Add", {0x02U, 0x16U, 0x2fU, 0x04U, 0x03U, 0x02U,
                    0x59U, 0x2aU, 0x02U, 0x03U, 0x58U, 0x2aU}},
                {"GuardedDivide", {0x03U, 0x2dU, 0x06U, 0x73U, 0x01U,
                    0x00U, 0x00U, 0x0aU, 0x7aU, 0x02U, 0x03U, 0x5bU, 0x2aU}}}};
        const std::array<std::array<std::string, 2>, 2> expected_parameters{{
            {{"left", "right"}}, {{"value", "divisor"}}}};
        std::set<std::string, std::less<>> identities;
        for (std::size_t index = 0; index < expected_methods.size(); ++index) {
            const auto& expected = expected_methods[index];
            const auto method = std::find_if(value.methods.begin(), value.methods.end(),
                [&](const auto& candidate) {
                    return candidate.method_name == expected.first;
                });
            require(method != value.methods.end() && method->has_body &&
                method->declaring_type_name == "AiDA.C03.Corpus.ManagedFixture" &&
                method->parameter_names.size() == expected_parameters[index].size() &&
                std::equal(method->parameter_names.begin(), method->parameter_names.end(),
                    expected_parameters[index].begin()),
                "CLI fixture method identity or parameters disagree with its source corpus");
            const auto range = std::find_if(value.code_ranges.begin(), value.code_ranges.end(),
                [&](const auto& candidate) {
                    return candidate.method_token == method->metadata_token;
                });
            require(range != value.code_ranges.end() &&
                range->code_bytes == expected.second &&
                range->offset == method->code_offset &&
                range->size == method->code_size,
                "CLI fixture method body disagrees with its source corpus");
            identities.insert(method->declaring_type_name + "." + method->method_name);
        }
        require(identities == std::set<std::string, std::less<>>{
                "AiDA.C03.Corpus.ManagedFixture.Add",
                "AiDA.C03.Corpus.ManagedFixture.GuardedDivide"},
            "CLI fixture stable entity inventory is incomplete");
        require(std::any_of(value.member_references.begin(),
            value.member_references.end(), [](const auto& reference) {
                return reference.kind == managed::managed_reference_kind_t::method_reference &&
                    reference.declaring_type_name == "System.DivideByZeroException" &&
                    reference.member_name == ".ctor";
            }), "CLI fixture guarded divide exception constructor is absent");
        const std::array<std::uint8_t, 4> ready_to_run_magic{'R', 'T', 'R', 0U};
        require(bytes.size() > 0x1803U &&
            (ready_to_run ?
                std::equal(bytes.begin() + 0x1800U, bytes.begin() + 0x1804U,
                    ready_to_run_magic.begin()) :
                std::all_of(bytes.begin() + 0x1800U, bytes.begin() + 0x1804U,
                    [](std::uint8_t byte) { return byte == 0U; })),
            "CLI fixture ReadyToRun identity disagrees with its recipe");
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
        require(image.this_class_name == "aida/c03/corpus/Fixture" &&
            image.source_file == std::optional<std::string>{"Fixture.java"},
            "classfile type or source-file identity disagrees with its source corpus");
        std::set<decompiler_entity_key_t> identities;
        std::set<std::string, std::less<>> semantic_methods;
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
            require(method.declaring_type_name == "aida/c03/corpus/Fixture",
                "classfile method declaring type disagrees with its source corpus");
            semantic_methods.insert(method.method_name + method.method_signature);
            identities.insert(managed::build_jvm_entity_key(value,
                static_cast<std::uint32_t>(index)));
        }
        require(body_count == 3U && named_body_count == 2U &&
            identities.size() == body_count &&
            semantic_methods == std::set<std::string, std::less<>>{
                "<init>()V", "add(II)I", "guardedDivide(II)I"} &&
            value.fields.size() == 1U &&
            value.fields.front().declaring_type_name == "aida/c03/corpus/Fixture" &&
            value.fields.front().field_name == "bias" &&
            value.fields.front().field_signature == "I",
            "classfile fixture does not expose distinct stable method identities");
        bool constructor_semantics = false;
        bool add_semantics = false;
        bool divide_semantics = false;
        for (const auto& method : image.methods) {
            if (!method.code)
                continue;
            const auto has_opcode = [&](std::uint8_t opcode) {
                return std::any_of(method.code->instructions.begin(),
                    method.code->instructions.end(), [&](const auto& instruction) {
                        return instruction.opcode == opcode;
                    });
            };
            std::set<std::uint16_t> lines;
            for (const auto& line : method.code->line_numbers)
                lines.insert(line.line_number);
            std::set<std::string, std::less<>> locals;
            for (const auto& local : method.code->local_variables)
                locals.insert(local.name + ":" + local.descriptor);
            if (method.name == "<init>")
                constructor_semantics = method.descriptor == "()V" &&
                    has_opcode(0xb7U) && has_opcode(0xb1U) &&
                    lines == std::set<std::uint16_t>{3U} &&
                    locals == std::set<std::string, std::less<>>{
                        "this:Laida/c03/corpus/Fixture;"};
            else if (method.name == "add")
                add_semantics = method.descriptor == "(II)I" &&
                    has_opcode(0x60U) && has_opcode(0xb2U) &&
                    has_opcode(0xacU) && method.code->exceptions.size() == 1U &&
                    method.code->exceptions.front().catch_class_name ==
                        std::optional<std::string>{"java/lang/ArithmeticException"} &&
                    lines == std::set<std::uint16_t>{6U, 9U} &&
                    locals == std::set<std::string, std::less<>>{
                        "left:I", "result:I", "right:I"};
            else if (method.name == "guardedDivide")
                divide_semantics = method.descriptor == "(II)I" &&
                    has_opcode(0x9aU) && has_opcode(0xbbU) &&
                    has_opcode(0xb7U) && has_opcode(0xbfU) &&
                    has_opcode(0x6cU) && has_opcode(0xacU) &&
                    method.code->exceptions.empty() &&
                    lines == std::set<std::uint16_t>{15U, 17U} &&
                    locals == std::set<std::string, std::less<>>{
                        "divisor:I", "value:I"};
        }
        require(constructor_semantics && add_semantics && divide_semantics &&
            metadata.value().all_exception_regions.size() == 1U,
            "classfile bytecode or debug semantics disagree with its source corpus");

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
        require(metadata.value().image.classes.size() == 1U &&
            metadata.value().image.classes.front().class_descriptor ==
                "Laida/c03/corpus/Fixture;" &&
            metadata.value().image.classes.front().source_file ==
                std::optional<std::string>{"Fixture.smali"},
            "DEX class or source-file identity disagrees with its source corpus");
        std::set<decompiler_entity_key_t> identities;
        std::set<std::string, std::less<>> semantic_methods;
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
            require(method.declaring_type_name == "Laida/c03/corpus/Fixture;",
                "DEX method declaring type disagrees with its source corpus");
            semantic_methods.insert(method.method_name + method.method_signature);
            identities.insert(managed::build_dalvik_entity_key(value,
                static_cast<std::uint32_t>(index)));
        }
        require(body_count == 3U && named_body_count == 2U &&
            identities.size() == body_count &&
            semantic_methods == std::set<std::string, std::less<>>{
                "<init>()V", "add(II)I", "guardedDivide(II)I"},
            "DEX fixture does not expose distinct stable method identities");
        bool constructor_semantics = false;
        bool add_semantics = false;
        bool divide_semantics = false;
        const auto& dex_image = metadata.value().image;
        for (const auto& definition : metadata.value().image.classes) {
            for (const auto& encoded : definition.direct_methods) {
                if (!encoded.code || encoded.method_index >= dex_image.methods.size())
                    continue;
                const auto& method = dex_image.methods[encoded.method_index];
                const auto& code = *encoded.code;
                std::set<std::uint8_t> opcodes;
                for (const auto& instruction : code.instructions)
                    opcodes.insert(instruction.opcode);
                std::vector<std::string> parameter_names;
                if (code.debug_info) {
                    for (const auto& name_index :
                        code.debug_info->parameter_name_string_indices) {
                        require(name_index && *name_index < dex_image.strings.size(),
                            "DEX debug parameter name exceeds the string table");
                        parameter_names.push_back(dex_image.strings[*name_index].value);
                    }
                }
                if (method.name == "<init>")
                    constructor_semantics = method.descriptor == "()V" &&
                        code.debug_info && code.debug_info->line_start == 4U &&
                        parameter_names.empty() &&
                        opcodes == std::set<std::uint8_t>{0x0eU, 0x70U};
                else if (method.name == "add")
                    add_semantics = method.descriptor == "(II)I" &&
                        code.debug_info && code.debug_info->line_start == 10U &&
                        parameter_names == std::vector<std::string>{"left", "right"} &&
                        opcodes == std::set<std::uint8_t>{0x0fU, 0x12U, 0x90U} &&
                        code.tries.size() == 1U &&
                        code.catch_handlers.size() == 1U &&
                        code.catch_handlers.front().typed_handlers.size() == 1U &&
                        code.catch_handlers.front().typed_handlers.front().first == 2U;
                else if (method.name == "guardedDivide")
                    divide_semantics = method.descriptor == "(II)I" &&
                        code.debug_info && code.debug_info->line_start == 23U &&
                        parameter_names == std::vector<std::string>{"value", "divisor"} &&
                        opcodes == std::set<std::uint8_t>{
                            0x0fU, 0x22U, 0x27U, 0x39U, 0x70U, 0x93U} &&
                        code.tries.empty() && code.catch_handlers.empty();
            }
        }
        require(constructor_semantics && add_semantics && divide_semantics &&
            fidelity.dex.code_item_count == 3U &&
            fidelity.dex.debug_info_count == 3U,
            "DEX bytecode or debug semantics disagree with its source corpus");

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
        verify_cli_fixture(fixture_by_id(fixtures, "cli-x64"), false);
        verify_cli_fixture(fixture_by_id(fixtures, "readytorun-x64"), true);
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
        const std::set<std::string, std::less<>> expected_source_files{
            "source_corpus/native_fixture.c", "source_corpus/managed_fixture.cs",
            "source_corpus/Fixture.java", "source_corpus/Fixture.smali"};
        require(ground_truth.contains("source_files") &&
            ground_truth.at("source_files").is_object() &&
            ground_truth.at("source_files").size() == expected_source_files.size(),
            "ground-truth source hash inventory is incomplete");
        for (const auto& source_path : expected_source_files) {
            require(ground_truth.at("source_files").contains(source_path) &&
                ground_truth.at("source_files").at(source_path).is_string(),
                "ground-truth source hash binding is absent");
            const auto observed = sha256_evidence_file(
                fixture_root / std::filesystem::u8path(source_path),
                4ULL * 1024ULL * 1024ULL);
            require(observed.ok && observed.sha256 ==
                    ground_truth.at("source_files").at(source_path).get<std::string>(),
                observed.ok ? "ground-truth source hash binding mismatch" : observed.error);
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
