#include "workspace_fixture_builder.hpp"

#include "../c03/analysis_memory_provider.hpp"

#include "../../src/core/analysis/workspace/parallel_pass.hpp"
#include "../../src/core/analysis/workspace/byte_provider.hpp"
#include "../../src/core/analysis/workspace/query_index.hpp"
#include "../../src/core/analysis/workspace/search_index.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <functional>
#include <limits>
#include <memory>
#include <numeric>
#include <optional>
#include <process.h>
#include <regex>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

struct harness_log_t {
    using clock_t = std::chrono::steady_clock;
    static unsigned long pid() { return static_cast<unsigned long>(_getpid()); }
    static unsigned long tid() { return static_cast<unsigned long>(std::hash<std::thread::id>{}(std::this_thread::get_id())); }
    static std::uint64_t epoch_ms() { return std::chrono::duration_cast<std::chrono::milliseconds>(clock_t::now().time_since_epoch()).count(); }
    static void emit(const char* test, const char* phase, const char* status, std::uint64_t elapsed_ms, const std::string& detail = {}) {
        std::fprintf(stderr, "[C03-HARNESS] test=%s phase=%s status=%s elapsed=%llums pid=%lu tid=%lu detail=%s\n",
            test, phase, status, static_cast<unsigned long long>(elapsed_ms), pid(), tid(),
            detail.empty() ? "-" : detail.c_str());
        std::fflush(stderr);
    }
};

namespace {

using namespace aida::analysis;

constexpr std::uint64_t kGeneration = 77;
constexpr std::uint64_t kAnalysisRevision = 9;
constexpr std::uint64_t kOverlayRevision = 4;
constexpr std::size_t kCursorOffset = 4 + 4 + 32 + 32 + 1 + 32 + 8 * 4 + 1 + 1;

void require(bool condition, const std::string& message) {
    if (!condition)
        throw std::runtime_error(message);
}

template <typename T>
T require_value(workspace_result_t<T> result, const std::string& message) {
    if (!result)
        throw std::runtime_error(message + ": " + result.error().stable_code() + " " +
            result.error().message);
    return result.take_value();
}

struct splitmix64_t {
    std::uint64_t state = 0;
    std::uint64_t next() {
        state += 0x9E3779B97F4A7C15ULL;
        std::uint64_t value = state;
        value = (value ^ (value >> 30)) * 0xBF58476D1CE4E5B9ULL;
        value = (value ^ (value >> 27)) * 0x94D049BB133111EBULL;
        return value ^ (value >> 31);
    }
    std::uint64_t below(std::uint64_t bound) {
        return bound == 0 ? 0 : next() % bound;
    }
};

std::string harness_normalize(std::string_view text) {
    std::string result;
    result.reserve(text.size());
    bool previous_space = false;
    for (const auto raw : text) {
        const auto value = static_cast<unsigned char>(raw);
        if (value < 0x80U && std::isspace(value) != 0) {
            if (!result.empty() && !previous_space)
                result.push_back(' ');
            previous_space = true;
            continue;
        }
        previous_space = false;
        result.push_back(value < 0x80U
            ? static_cast<char>(std::tolower(value)) : static_cast<char>(value));
    }
    while (!result.empty() && result.back() == ' ')
        result.pop_back();
    return result;
}

std::uint32_t harness_trigram_key(const char* value) {
    return static_cast<std::uint32_t>(static_cast<unsigned char>(value[0])) |
        (static_cast<std::uint32_t>(static_cast<unsigned char>(value[1])) << 8U) |
        (static_cast<std::uint32_t>(static_cast<unsigned char>(value[2])) << 16U);
}

std::string ascii_lower(std::string_view text) {
    std::string result(text);
    for (auto& value : result) {
        const auto byte = static_cast<unsigned char>(value);
        if (byte < 0x80U)
            value = static_cast<char>(std::tolower(byte));
    }
    return result;
}

bool ascii_contains_case_insensitive(std::string_view subject, std::string_view pattern) {
    return ascii_lower(subject).find(ascii_lower(pattern)) != std::string::npos;
}

address_t relative_address(std::uint64_t value) {
    return address_t{address_space_id_t::relative_virtual, value,
        architecture_id_t::x86_64, architecture_mode_t::x86_64};
}

binary_id_t identity_bytes(std::uint8_t seed) {
    binary_id_t result;
    for (std::size_t index = 0; index < result.bytes.size(); ++index)
        result.bytes[index] = static_cast<std::uint8_t>(seed + index);
    return result;
}

struct fixture_scale_t {
    std::size_t symbols = 0;
    std::size_t strings = 0;
    std::size_t types = 0;
    std::size_t instructions = 0;
    std::size_t operands = 0;
    std::size_t data = 0;
    std::size_t switches = 0;
};

struct fixture_model_t {
    std::shared_ptr<analysis_snapshot_t> snapshot;
    std::vector<data_candidate_record_t> data_candidates;
    std::vector<switch_record_t> switches;
    std::vector<type_candidate_record_t> types;
};

const std::array<const char*, 24> kWordPool{
    "alpha", "beta", "gamma", "delta", "needle", "parser", "worker", "token",
    "shared", "omega", "sigma", "payload", "anchor", "vector", "matrix", "cipher",
    "harvest", "lantern", "quartz", "nebula", "sonar", "tundra", "falcon", "ember"};

std::string pool_word(splitmix64_t& rng) {
    return kWordPool[rng.below(kWordPool.size())];
}

std::string pool_phrase(splitmix64_t& rng, std::size_t max_words) {
    const auto words = 1U + rng.below(max_words);
    std::string result = pool_word(rng);
    for (std::size_t index = 1; index < words; ++index) {
        result.push_back(' ');
        result += pool_word(rng);
    }
    return result;
}

std::string case_variant(splitmix64_t& rng, const std::string& value) {
    std::string result = value;
    const auto mode = rng.below(3);
    if (mode == 1)
        return ascii_lower(result);
    if (mode == 2) {
        for (auto& character : result) {
            const auto byte = static_cast<unsigned char>(character);
            if (byte < 0x80U)
                character = static_cast<char>(std::toupper(byte));
        }
    }
    return result;
}

fixture_model_t make_model(std::uint64_t seed, const fixture_scale_t& scale,
    const sha256_digest_t& provider_hash, std::uint64_t provider_size) {
    splitmix64_t rng{seed};
    fixture_model_t model;
    auto snapshot = std::make_shared<analysis_snapshot_t>();
    snapshot->binary_id = identity_bytes(0x21U);
    snapshot->load_profile_hash = identity_bytes(0x67U);
    snapshot->generation = kGeneration;
    snapshot->analysis_revision = kAnalysisRevision;
    snapshot->overlay_revision = kOverlayRevision;
    snapshot->baseline_complete = true;
    auto image = std::make_shared<workspace_image_t>();
    image->format = format_id_t::pe32_plus;
    image->architecture = architecture_id_t::x86_64;
    image->architecture_mode = architecture_mode_t::x86_64;
    image->abi = abi_id_t::windows_x64;
    image->address_width_bits = 64;
    image->image_base = 0x140000000ULL;
    image->image_size = 0x100000;
    image->provider_size = provider_size;
    image->provider_content_hash = provider_hash;
    image->workspace_binary_id = snapshot->binary_id;
    image->provider_binding_verified = true;
    snapshot->normalized_image = std::move(image);

    const auto symbol_address = [](std::size_t index) {
        return relative_address(0x1000 + index * 0x20ULL);
    };
    const auto string_address = [](std::size_t index) {
        return relative_address(0x1004 + index * 0x20ULL);
    };
    const auto type_address = [](std::size_t index) {
        return relative_address(0x1008 + index * 0x20ULL);
    };
    const auto instruction_address = [](std::size_t index) {
        return relative_address(0x100C + index * 0x20ULL);
    };
    const auto data_address = [](std::size_t index) {
        return relative_address(0x1010 + index * 0x20ULL);
    };
    const auto switch_address = [](std::size_t index) {
        return relative_address(0x1014 + index * 0x20ULL);
    };

    const auto push_symbol = [&](entity_id_t id, std::uint64_t address_value,
                                 std::string name, symbol_kind_t kind) {
        symbol_record_t record;
        record.id = id;
        record.address = relative_address(address_value);
        record.name = std::move(name);
        record.kind = kind;
        record.provenance = fact_provenance_t::debug_symbol;
        record.confidence = 90;
        snapshot->symbols.push_back(std::move(record));
    };
    push_symbol(1, 0x2000, "AlphaParser", symbol_kind_t::function);
    push_symbol(2, 0x2020, "needle_worker", symbol_kind_t::data);
    push_symbol(3, 0x2040, "AlphaParser", symbol_kind_t::function);
    push_symbol(4, 0x2060, "alphaPARSER", symbol_kind_t::debug_symbol);
    push_symbol(5, 0x2080, "", symbol_kind_t::data);
    push_symbol(6, 0x20A0, "   ", symbol_kind_t::data);
    push_symbol(7, 0x20C0, "  Shared  Token  Alpha ", symbol_kind_t::function);
    for (std::size_t index = snapshot->symbols.size(); index < scale.symbols; ++index) {
        std::string name;
        const auto roll = rng.below(50);
        if (roll == 0 && index > 8) {
            name.clear();
        } else if (roll == 1 && index > 8) {
            name = snapshot->symbols[1 + rng.below(index - 1)].name;
        } else if (roll == 2 && index > 8) {
            name = "  " + pool_phrase(rng, 2) + "   ";
        } else {
            name = pool_phrase(rng, 3);
            name = case_variant(rng, name);
        }
        if (rng.below(97) == 0)
            name += "\xC3\x89";
        const auto kind_roll = rng.below(10);
        const auto kind = kind_roll < 6
            ? symbol_kind_t::function
            : (kind_roll < 8 ? symbol_kind_t::data : symbol_kind_t::import_symbol);
        push_symbol(index + 1, symbol_address(index).value, std::move(name), kind);
    }

    const auto push_string = [&](entity_id_t id, std::uint64_t address_value,
                                 std::string value) {
        string_record_t record;
        record.id = id;
        record.address = relative_address(address_value);
        record.byte_length = value.size();
        record.encoding = rng.below(3) == 0
            ? string_encoding_t::ascii : string_encoding_t::utf8;
        record.value = std::move(value);
        record.provenance = fact_provenance_t::recursive_decode;
        record.confidence = 88;
        snapshot->strings.push_back(std::move(record));
    };
    push_string(1, 0x3000, "needle payload anchor alpha");
    push_string(2, 0x3020, "Shared Token Alpha");
    push_string(3, 0x3040, "needle_1234");
    push_string(4, 0x3060, "ab");
    push_string(5, 0x3080, "x");
    push_string(6, 0x30A0, "  Shared  Token  Alpha ");
    push_string(7, 0x30C0, "CAF\xC3\x89_\xCE\x94 data");
    for (std::size_t index = snapshot->strings.size(); index < scale.strings; ++index) {
        std::string value;
        const auto roll = rng.below(40);
        if (roll == 0 && index > 8) {
            value.clear();
        } else if (roll == 1 && index > 8) {
            value = snapshot->strings[1 + rng.below(index - 1)].value;
        } else if (roll == 2 && index > 8) {
            value = ascii_lower(snapshot->strings[1 + rng.below(index - 1)].value);
        } else if (roll == 3 && index > 8) {
            value = "   " + pool_phrase(rng, 2) + "  ";
        } else {
            value = pool_phrase(rng, 6);
            if (rng.below(23) == 0)
                value = case_variant(rng, value);
        }
        push_string(index + 1, string_address(index).value, std::move(value));
    }

    const auto push_type = [&](entity_id_t id, std::uint64_t address_value,
                               std::string display, std::string canonical,
                               type_candidate_kind_t kind) {
        type_candidate_record_t record;
        record.id = id;
        record.address = relative_address(address_value);
        record.kind = kind;
        record.display_name = std::move(display);
        record.canonical_type = std::move(canonical);
        record.provenance = fact_provenance_t::debug_symbol;
        record.confidence = 86;
        record.explicitly_unknown = false;
        model.types.push_back(std::move(record));
    };
    push_type(1, 0x4000, "NeedleType", "struct NeedleType *",
        type_candidate_kind_t::global_object);
    push_type(2, 0x4020, "", "int (__fastcall *)(void *)",
        type_candidate_kind_t::function_prototype);
    push_type(3, 0x4040, "needle_type", "struct needle_type",
        type_candidate_kind_t::pointer_object);
    for (std::size_t index = model.types.size(); index < scale.types; ++index) {
        const auto kind = static_cast<type_candidate_kind_t>(index % 4U);
        std::string display;
        if (rng.below(3) != 0)
            display = case_variant(rng, pool_phrase(rng, 2));
        std::string canonical = display.empty()
            ? "struct canonical_" + pool_word(rng) + " *"
            : "struct " + ascii_lower(display);
        push_type(index + 1, type_address(index).value, std::move(display),
            std::move(canonical), kind);
    }

    const std::array<std::uint32_t, 12> opcodes{0x90U, 0xE8U, 0xE9U, 0xC3U, 0x55U,
        0x48U, 0xEBU, 0x74U, 0x75U, 0xB8U, 0x8BU, 0x89U};
    const std::array<std::uint32_t, 6> flows{
        flow_fallthrough,
        flow_call | flow_direct | flow_fallthrough,
        flow_return | flow_terminal,
        flow_branch | flow_conditional | flow_fallthrough,
        flow_none,
        flow_call | flow_indirect};
    const auto push_instruction = [&](entity_id_t id, std::uint64_t address_value,
                                      std::uint32_t opcode, std::uint32_t flow) {
        instruction_record_t record;
        record.id = id;
        record.address = relative_address(address_value);
        record.length = static_cast<std::uint8_t>(1 + (id % 7U));
        record.opcode_id = opcode;
        record.flow_flags = flow;
        record.provenance = fact_provenance_t::recursive_decode;
        record.confidence = 95;
        record.stable_source_id = address_value;
        snapshot->instructions.push_back(record);
    };
    push_instruction(1, 0x2000, 0xE8U, flow_call | flow_direct | flow_fallthrough);
    push_instruction(2, 0x2020, 0xC3U, flow_return | flow_terminal);
    push_instruction(3, 0x2040, 0x90U, flow_fallthrough);
    push_instruction(4, 0x2060, 0xEBU, flow_branch | flow_direct);
    for (std::size_t index = snapshot->instructions.size(); index < scale.instructions;
         ++index) {
        push_instruction(index + 1, instruction_address(index).value,
            opcodes[rng.below(opcodes.size())], flows[rng.below(flows.size())]);
    }

    const auto push_operand = [&](entity_id_t id, entity_id_t instruction_id,
                                  operand_kind_t kind, std::uint64_t value) {
        operand_fact_t fact;
        fact.id = id;
        fact.instruction_id = instruction_id;
        fact.kind = kind;
        fact.immediate = value;
        fact.bit_width = 64;
        snapshot->operand_facts.append(fact,
            static_cast<std::uint32_t>(instruction_id - 1U));
    };
    entity_id_t operand_id = 900001;
    push_operand(operand_id++, 1, operand_kind_t::immediate, 0x1234U);
    push_operand(operand_id++, 1, operand_kind_t::immediate, 0x1234U);
    push_operand(operand_id++, 2, operand_kind_t::immediate, 0x1234U);
    push_operand(operand_id++, 1, operand_kind_t::immediate, 0x5678U);
    push_operand(operand_id++, 3, operand_kind_t::immediate, 0xDEADBEEFU);
    const std::array<std::uint64_t, 7> immediate_pool{0x1234ULL, 0x5678ULL, 0x1000ULL,
        0x2000ULL, 0xDEADBEEFULL, 0x140000000ULL, 0x42ULL};
    for (std::size_t index = snapshot->operand_facts.size(); index < scale.operands;
         ++index) {
        const auto instruction_id = 1 + rng.below(scale.instructions);
        const auto roll = rng.below(10);
        if (roll < 7) {
            push_operand(operand_id++, instruction_id, operand_kind_t::immediate,
                immediate_pool[rng.below(immediate_pool.size())]);
        } else if (roll < 9) {
            push_operand(operand_id++, instruction_id, operand_kind_t::reg, 0);
        } else {
            push_operand(operand_id++, instruction_id, operand_kind_t::memory, 0);
        }
    }

    for (std::size_t index = 0; index < scale.data; ++index) {
        data_candidate_record_t record;
        record.id = index + 1;
        record.address = data_address(index);
        record.size = 1 + rng.below(64);
        record.kind = static_cast<data_candidate_kind_t>(index % 6U);
        if (rng.below(2) == 0)
            record.target = relative_address(0x1000 + rng.below(0x4000));
        record.provenance = fact_provenance_t::relocation;
        record.confidence = 84;
        model.data_candidates.push_back(record);
    }

    for (std::size_t index = 0; index < scale.switches; ++index) {
        switch_record_t record;
        record.id = index + 1;
        record.function_id = 1;
        record.dispatch = switch_address(index);
        record.table = relative_address(switch_address(index).value + 0x8);
        const auto targets = rng.below(9);
        for (std::size_t target = 0; target < targets; ++target) {
            record.case_targets.push_back(
                relative_address(0x1000 + rng.below(0x8000)));
        }
        record.entry_size = static_cast<std::uint8_t>(rng.below(2) == 0 ? 4U : 8U);
        record.provenance = fact_provenance_t::recursive_decode;
        record.confidence = 82;
        model.switches.push_back(std::move(record));
    }

    model.snapshot = std::move(snapshot);
    return model;
}

struct oracle_record_t {
    search_entity_kind_t kind = search_entity_kind_t::symbol;
    entity_id_t entity_id = 0;
    address_t address;
    std::uint64_t numeric_value = 0;
    std::uint32_t auxiliary_flags = 0;
    std::string text;
    std::uint32_t text_id = 0;
    std::uint32_t normalized_id = 0;
};

struct oracle_trigram_span_t {
    std::uint32_t key = 0;
    std::uint32_t begin = 0;
    std::uint32_t count = 0;
};

struct oracle_t {
    std::vector<oracle_record_t> records;
    std::vector<std::string> pool;
    std::vector<std::uint32_t> address_references;
    std::vector<std::uint32_t> entity_kind_references;
    std::vector<std::uint32_t> entity_id_references;
    std::vector<std::uint32_t> instruction_references;
    std::vector<std::pair<std::uint32_t, std::uint32_t>> opcode_references;
    std::vector<std::pair<std::uint64_t, std::uint32_t>> immediate_references;
    std::vector<std::pair<std::uint32_t, std::uint32_t>> text_references;
    std::vector<oracle_trigram_span_t> trigram_spans;
    std::vector<std::uint32_t> trigram_postings;
    std::uint64_t source_text_bytes = 0;
    std::uint64_t referenced_text_bytes = 0;

    bool record_less(std::uint32_t lhs, std::uint32_t rhs) const {
        const auto& left = records[lhs];
        const auto& right = records[rhs];
        if (left.address != right.address)
            return left.address < right.address;
        if (left.kind != right.kind)
            return left.kind < right.kind;
        if (left.entity_id != right.entity_id)
            return left.entity_id < right.entity_id;
        if (left.text_id != right.text_id)
            return left.text_id < right.text_id;
        if (left.normalized_id != right.normalized_id)
            return left.normalized_id < right.normalized_id;
        if (left.numeric_value != right.numeric_value)
            return left.numeric_value < right.numeric_value;
        return left.auxiliary_flags < right.auxiliary_flags;
    }
};

oracle_t build_oracle(const fixture_model_t& model) {
    oracle_t oracle;
    std::unordered_map<std::string, std::uint32_t> intern;
    const auto intern_string = [&](const std::string& value) {
        const auto found = intern.find(value);
        if (found != intern.end())
            return found->second;
        const auto id = static_cast<std::uint32_t>(oracle.pool.size() + 1U);
        oracle.pool.push_back(value);
        intern.emplace(oracle.pool.back(), id);
        return id;
    };
    const auto add_record = [&](search_entity_kind_t kind, entity_id_t entity_id,
                                const address_t& address, std::uint64_t numeric_value,
                                std::uint32_t auxiliary_flags,
                                const std::string& text) {
        oracle_record_t record;
        record.kind = kind;
        record.entity_id = entity_id;
        record.address = address;
        record.numeric_value = numeric_value;
        record.auxiliary_flags = auxiliary_flags;
        if (!text.empty()) {
            const auto normalized = harness_normalize(text);
            std::uint64_t referenced = text.size();
            if (!normalized.empty())
                referenced += normalized.size();
            oracle.referenced_text_bytes += referenced;
            oracle.source_text_bytes += text.size();
            record.text = text;
            record.text_id = intern_string(text);
            if (!normalized.empty())
                record.normalized_id = intern_string(normalized);
        }
        oracle.records.push_back(std::move(record));
    };
    for (const auto& symbol : model.snapshot->symbols) {
        add_record(symbol.kind == symbol_kind_t::function
                ? search_entity_kind_t::function : search_entity_kind_t::symbol,
            symbol.id, symbol.address, 0, 0, symbol.name);
    }
    for (const auto& string : model.snapshot->strings) {
        add_record(search_entity_kind_t::string, string.id, string.address,
            string.byte_length, static_cast<std::uint32_t>(string.encoding), string.value);
    }
    for (const auto& type : model.types) {
        add_record(search_entity_kind_t::type_candidate, type.id, type.address, 0,
            static_cast<std::uint32_t>(type.kind),
            type.display_name.empty() ? type.canonical_type : type.display_name);
    }
    for (const auto& instruction : model.snapshot->instructions) {
        add_record(search_entity_kind_t::instruction, instruction.id, instruction.address,
            instruction.opcode_id, instruction.flow_flags, {});
    }
    for (const auto& data : model.data_candidates) {
        add_record(search_entity_kind_t::data_candidate, data.id, data.address, data.size,
            static_cast<std::uint32_t>(data.kind), {});
    }
    for (const auto& dispatch : model.switches) {
        add_record(search_entity_kind_t::switch_dispatch, dispatch.id, dispatch.dispatch,
            dispatch.case_targets.size(), dispatch.entry_size, {});
    }

    const auto less = [&oracle](const oracle_record_t& lhs, const oracle_record_t& rhs) {
        if (lhs.address != rhs.address)
            return lhs.address < rhs.address;
        if (lhs.kind != rhs.kind)
            return lhs.kind < rhs.kind;
        if (lhs.entity_id != rhs.entity_id)
            return lhs.entity_id < rhs.entity_id;
        if (lhs.text_id != rhs.text_id)
            return lhs.text_id < rhs.text_id;
        if (lhs.normalized_id != rhs.normalized_id)
            return lhs.normalized_id < rhs.normalized_id;
        if (lhs.numeric_value != rhs.numeric_value)
            return lhs.numeric_value < rhs.numeric_value;
        return lhs.auxiliary_flags < rhs.auxiliary_flags;
    };
    std::sort(oracle.records.begin(), oracle.records.end(), less);

    const auto count = oracle.records.size();
    oracle.address_references.reserve(count);
    oracle.entity_kind_references.reserve(count);
    oracle.entity_id_references.reserve(count);
    for (std::size_t index = 0; index < count; ++index) {
        const auto reference = static_cast<std::uint32_t>(index);
        const auto& record = oracle.records[index];
        oracle.address_references.push_back(reference);
        oracle.entity_kind_references.push_back(reference);
        oracle.entity_id_references.push_back(reference);
        if (record.normalized_id != 0) {
            oracle.text_references.emplace_back(reference, record.normalized_id);
        }
        if (record.kind == search_entity_kind_t::instruction) {
            oracle.instruction_references.push_back(reference);
            oracle.opcode_references.emplace_back(
                static_cast<std::uint32_t>(record.numeric_value), reference);
        }
    }
    std::sort(oracle.address_references.begin(), oracle.address_references.end(),
        [&oracle](std::uint32_t lhs, std::uint32_t rhs) {
            return oracle.record_less(lhs, rhs);
        });
    std::sort(oracle.entity_kind_references.begin(), oracle.entity_kind_references.end(),
        [&oracle](std::uint32_t lhs, std::uint32_t rhs) {
            const auto& left = oracle.records[lhs];
            const auto& right = oracle.records[rhs];
            if (left.kind != right.kind)
                return left.kind < right.kind;
            if (left.entity_id != right.entity_id)
                return left.entity_id < right.entity_id;
            return lhs < rhs;
        });
    for (std::size_t index = 1; index < oracle.entity_kind_references.size(); ++index) {
        const auto& previous = oracle.records[oracle.entity_kind_references[index - 1U]];
        const auto& current = oracle.records[oracle.entity_kind_references[index]];
        require(!(previous.kind == current.kind && previous.entity_id == current.entity_id),
            "fixture produced a duplicate final entity");
    }
    std::sort(oracle.entity_id_references.begin(), oracle.entity_id_references.end(),
        [&oracle](std::uint32_t lhs, std::uint32_t rhs) {
            const auto& left = oracle.records[lhs];
            const auto& right = oracle.records[rhs];
            if (left.entity_id != right.entity_id)
                return left.entity_id < right.entity_id;
            if (left.kind != right.kind)
                return left.kind < right.kind;
            return lhs < rhs;
        });
    std::sort(oracle.opcode_references.begin(), oracle.opcode_references.end());

    const auto instruction_reference = [&oracle](entity_id_t id)
        -> std::optional<std::uint32_t> {
        const auto first = std::lower_bound(oracle.entity_id_references.begin(),
            oracle.entity_id_references.end(), id,
            [&oracle](std::uint32_t reference, entity_id_t value) {
                return oracle.records[reference].entity_id < value;
            });
        for (auto current = first; current != oracle.entity_id_references.end();
             ++current) {
            const auto& record = oracle.records[*current];
            if (record.entity_id != id)
                break;
            if (record.kind == search_entity_kind_t::instruction)
                return *current;
        }
        return std::nullopt;
    };
    const auto& operand_fact_store = model.snapshot->operand_facts;
    for (std::size_t index = 0; index < operand_fact_store.size(); ++index) {
        const auto operand = operand_fact_materialize(operand_fact_store, index,
            model.snapshot->instructions);
        if (operand.kind != operand_kind_t::immediate)
            continue;
        const auto reference = instruction_reference(operand.instruction_id);
        require(reference.has_value(), "fixture immediate references unknown instruction");
        oracle.immediate_references.emplace_back(operand.immediate, *reference);
    }
    std::sort(oracle.immediate_references.begin(), oracle.immediate_references.end());
    oracle.immediate_references.erase(
        std::unique(oracle.immediate_references.begin(),
            oracle.immediate_references.end()),
        oracle.immediate_references.end());

    std::sort(oracle.text_references.begin(), oracle.text_references.end(),
        [&oracle](const std::pair<std::uint32_t, std::uint32_t>& lhs,
                  const std::pair<std::uint32_t, std::uint32_t>& rhs) {
            const auto& left = oracle.pool[lhs.second - 1U];
            const auto& right = oracle.pool[rhs.second - 1U];
            if (left != right)
                return left < right;
            return oracle.record_less(lhs.first, rhs.first);
        });

    std::vector<std::pair<std::uint32_t, std::uint32_t>> pairs;
    for (std::size_t text_index = 0; text_index < oracle.text_references.size();
         ++text_index) {
        const auto& text = oracle.pool[oracle.text_references[text_index].second - 1U];
        std::vector<std::uint32_t> keys;
        if (text.size() >= 3)
            keys.reserve(text.size() - 2U);
        for (std::size_t offset = 0; offset + 3U <= text.size(); ++offset)
            keys.push_back(harness_trigram_key(text.data() + offset));
        std::sort(keys.begin(), keys.end());
        keys.erase(std::unique(keys.begin(), keys.end()), keys.end());
        for (const auto key : keys)
            pairs.emplace_back(key, static_cast<std::uint32_t>(text_index));
    }
    std::sort(pairs.begin(), pairs.end());
    std::size_t pair_index = 0;
    while (pair_index < pairs.size()) {
        const auto key = pairs[pair_index].first;
        const auto begin = static_cast<std::uint32_t>(oracle.trigram_postings.size());
        do {
            oracle.trigram_postings.push_back(pairs[pair_index].second);
            ++pair_index;
        } while (pair_index < pairs.size() && pairs[pair_index].first == key);
        oracle.trigram_spans.push_back(oracle_trigram_span_t{key, begin,
            static_cast<std::uint32_t>(oracle.trigram_postings.size() - begin)});
    }
    return oracle;
}

struct oracle_writer_t {
    std::vector<std::uint8_t> blob;
    void append(const void* data, std::size_t size) {
        const auto* first = static_cast<const std::uint8_t*>(data);
        blob.insert(blob.end(), first, first + size);
    }
    void u8(std::uint8_t value) { append(&value, sizeof(value)); }
    void u32(std::uint32_t value) {
        std::array<std::uint8_t, 4> bytes{};
        for (unsigned shift = 0; shift < 32; shift += 8)
            bytes[shift / 8] = static_cast<std::uint8_t>(value >> shift);
        append(bytes.data(), bytes.size());
    }
    void u64(std::uint64_t value) {
        std::array<std::uint8_t, 8> bytes{};
        for (unsigned shift = 0; shift < 64; shift += 8)
            bytes[shift / 8] = static_cast<std::uint8_t>(value >> shift);
        append(bytes.data(), bytes.size());
    }
    void fixed32(const std::array<std::uint8_t, 32>& value) {
        append(value.data(), value.size());
    }
    void counted_u32s(const std::vector<std::uint32_t>& values) {
        u64(values.size());
        for (const auto value : values)
            u32(value);
    }
};

std::vector<std::uint8_t> oracle_serialize(const oracle_t& oracle,
    const analysis_snapshot_t& snapshot, const search_index_limits_t& limits) {
    oracle_writer_t writer;
    writer.u32(0x58444953U);
    writer.u32(1U);
    writer.fixed32(snapshot.binary_id.bytes);
    writer.fixed32(snapshot.load_profile_hash.bytes);
    writer.u8(snapshot.normalized_image->provider_content_hash.empty() ? 0U : 1U);
    writer.fixed32(snapshot.normalized_image->provider_content_hash.bytes);
    writer.u64(snapshot.generation);
    writer.u64(snapshot.analysis_revision);
    writer.u64(snapshot.overlay_revision);
    writer.u64(snapshot.normalized_image->provider_size);
    writer.u8(static_cast<std::uint8_t>(architecture_id_t::x86_64));
    writer.u8(static_cast<std::uint8_t>(architecture_mode_t::x86_64));
    writer.u64(0);
    writer.u64(0);
    writer.u64(limits.max_entries);
    writer.u64(limits.max_trigram_postings);
    writer.u64(limits.max_indexed_text_bytes);
    writer.u64(limits.max_index_bytes);
    writer.u32(limits.max_query_bytes);
    writer.u32(limits.max_results_per_query);
    writer.u32(limits.cancellation_check_interval);

    std::vector<std::uint32_t> offsets(oracle.pool.size(), 0);
    std::vector<std::uint32_t> lengths(oracle.pool.size(), 0);
    std::vector<char> pool_bytes;
    for (std::size_t index = 0; index < oracle.pool.size(); ++index) {
        offsets[index] = static_cast<std::uint32_t>(pool_bytes.size());
        lengths[index] = static_cast<std::uint32_t>(oracle.pool[index].size());
        pool_bytes.insert(pool_bytes.end(), oracle.pool[index].begin(),
            oracle.pool[index].end());
    }
    writer.counted_u32s(offsets);
    writer.counted_u32s(lengths);
    writer.u64(pool_bytes.size());
    if (!pool_bytes.empty())
        writer.append(pool_bytes.data(), pool_bytes.size());

    writer.u64(oracle.records.size());
    for (const auto& record : oracle.records) {
        writer.u64(record.entity_id);
        writer.u64(record.numeric_value);
        writer.u64(record.address.value);
        const auto metadata = static_cast<std::uint32_t>(record.address.space) |
            (static_cast<std::uint32_t>(record.address.architecture) << 8U) |
            (static_cast<std::uint32_t>(record.address.mode) << 16U);
        writer.u32(metadata);
        writer.u32(record.text_id);
        writer.u32(record.normalized_id);
        writer.u32(record.auxiliary_flags);
        writer.u8(static_cast<std::uint8_t>(record.kind));
    }
    writer.u64(oracle.text_references.size());
    for (const auto& reference : oracle.text_references) {
        writer.u32(reference.first);
        writer.u32(reference.second);
    }
    writer.counted_u32s(oracle.address_references);
    writer.counted_u32s(oracle.entity_kind_references);
    writer.counted_u32s(oracle.entity_id_references);
    writer.counted_u32s(oracle.instruction_references);
    writer.u64(oracle.opcode_references.size());
    for (const auto& reference : oracle.opcode_references) {
        writer.u32(reference.first);
        writer.u32(reference.second);
    }
    writer.u64(oracle.immediate_references.size());
    for (const auto& reference : oracle.immediate_references) {
        writer.u64(reference.first);
        writer.u32(reference.second);
    }
    writer.u64(oracle.trigram_spans.size());
    for (const auto& span : oracle.trigram_spans) {
        writer.u32(span.key);
        writer.u32(span.begin);
        writer.u32(span.count);
    }
    writer.counted_u32s(oracle.trigram_postings);
    writer.u64(0);
    writer.u64(oracle.source_text_bytes);
    writer.u64(oracle.referenced_text_bytes);
    std::uint64_t unique_text_bytes = 0;
    for (const auto& value : oracle.pool)
        unique_text_bytes += value.size();
    writer.u64(unique_text_bytes);
    writer.u64(oracle.records.size());
    writer.u64(oracle.text_references.size());
    writer.u64(oracle.address_references.size());
    writer.u64(oracle.entity_kind_references.size());
    writer.u64(oracle.trigram_spans.size());
    writer.u64(oracle.trigram_postings.size());
    writer.u64(oracle.pool.size());
    return std::move(writer.blob);
}

class sealed_memory_provider_t final : public byte_provider_t {
public:
    static workspace_result_t<std::shared_ptr<sealed_memory_provider_t>> create(
        std::vector<std::uint8_t> bytes) {
        auto source = std::make_shared<memory_provider_t>(std::move(bytes),
            "c03://search-index-parity-fixture");
        auto digest = source->compute_content_sha256();
        if (!digest)
            return workspace_result_t<std::shared_ptr<sealed_memory_provider_t>>::failure(
                digest.error());
        auto identity = source->identity();
        identity.content_sha256 = digest.take_value();
        identity.file_id[0] = 0xC0;
        identity.file_id[1] = 0x04;
        return workspace_result_t<std::shared_ptr<sealed_memory_provider_t>>::success(
            std::shared_ptr<sealed_memory_provider_t>(new sealed_memory_provider_t(
                std::move(source), std::move(identity))));
    }

    const byte_provider_identity_t& identity() const noexcept override {
        return identity_;
    }
    std::uint64_t size() const noexcept override {
        return source_->size();
    }
    std::uint64_t maximum_contiguous_lease(std::uint64_t offset) const noexcept override {
        return source_->maximum_contiguous_lease(offset);
    }
    workspace_result_t<byte_view_t> lease(std::uint64_t offset, std::uint64_t size,
        const cancellation_token_t& cancel = {}) const override {
        return source_->lease(offset, size, cancel);
    }

private:
    sealed_memory_provider_t(std::shared_ptr<const memory_provider_t> source,
        byte_provider_identity_t identity)
        : source_(std::move(source)), identity_(std::move(identity)) {}

    std::shared_ptr<const memory_provider_t> source_;
    byte_provider_identity_t identity_;
};

search_index_limits_t parity_limits() {
    search_index_limits_t limits;
    limits.max_entries = 1ULL << 24;
    limits.max_trigram_postings = 1ULL << 26;
    limits.max_indexed_text_bytes = 1ULL << 30;
    limits.max_index_bytes = 2ULL * 1024ULL * 1024ULL * 1024ULL;
    limits.max_query_bytes = 1U << 16;
    limits.max_results_per_query = 100000;
    limits.cancellation_check_interval = 256;
    return limits;
}

std::vector<std::uint8_t> serialize_index(const search_index_t& index) {
    std::vector<std::uint8_t> blob;
    auto result = index.serialize_to(
        [&blob](const std::uint8_t* data, std::size_t size) {
            blob.insert(blob.end(), data, data + size);
            return workspace_result_t<void>::success();
        });
    require(static_cast<bool>(result), "index serialization failed");
    return blob;
}

void compare_masked_blobs(const std::vector<std::uint8_t>& actual,
    const std::vector<std::uint8_t>& expected, bool mask_memory,
    const std::string& message) {
    require(actual.size() == expected.size(),
        message + ": serialized sizes diverged " + std::to_string(actual.size()) +
            " vs " + std::to_string(expected.size()));
    require(actual.size() >= kCursorOffset + 16 + 88,
        message + ": serialized blob is shorter than the fixed header");
    const auto memory_offset = actual.size() - 88;
    for (std::size_t index = 0; index < actual.size(); ++index) {
        if (index >= kCursorOffset && index < kCursorOffset + 16)
            continue;
        if (mask_memory && index >= memory_offset && index < memory_offset + 8)
            continue;
        require(actual[index] == expected[index],
            message + ": serialized byte diverged at offset " + std::to_string(index));
    }
}

void compare_record_view(const search_record_view_t& actual,
    const oracle_record_t& expected, const std::string& message) {
    require(actual.kind == expected.kind, message + ": kind diverged");
    require(actual.entity_id == expected.entity_id, message + ": entity id diverged");
    require(actual.address == expected.address, message + ": address diverged");
    require(actual.numeric_value == expected.numeric_value,
        message + ": numeric value diverged");
    require(actual.auxiliary_flags == expected.auxiliary_flags,
        message + ": auxiliary flags diverged");
    require(actual.text == expected.text, message + ": text diverged");
}

void verify_index_against_oracle(const search_index_t& index, const oracle_t& oracle,
    const std::string& message) {
    require(index.record_count() == oracle.records.size(),
        message + ": record count diverged");
    for (std::size_t record = 0; record < oracle.records.size(); ++record) {
        const auto view = index.record(record);
        require(view.has_value(), message + ": record view missing at " +
            std::to_string(record));
        compare_record_view(*view, oracle.records[record],
            message + ": record " + std::to_string(record));
    }
    require(index.text_record_count() == oracle.text_references.size(),
        message + ": text record count diverged");
    for (std::size_t entry = 0; entry < oracle.text_references.size(); ++entry) {
        const auto view = index.text_record(entry);
        require(view.has_value(), message + ": text record view missing at " +
            std::to_string(entry));
        compare_record_view(*view, oracle.records[oracle.text_references[entry].first],
            message + ": text record " + std::to_string(entry));
    }
    const auto accounting = index.size_accounting();
    std::uint64_t unique_text_bytes = 0;
    for (const auto& value : oracle.pool)
        unique_text_bytes += value.size();
    require(accounting.record_count == oracle.records.size(),
        message + ": accounting record count diverged");
    require(accounting.text_reference_count == oracle.text_references.size(),
        message + ": accounting text reference count diverged");
    require(accounting.address_reference_count == oracle.address_references.size(),
        message + ": accounting address reference count diverged");
    require(accounting.entity_reference_count == oracle.entity_kind_references.size(),
        message + ": accounting entity reference count diverged");
    require(accounting.trigram_count == oracle.trigram_spans.size(),
        message + ": accounting trigram count diverged");
    require(accounting.trigram_posting_count == oracle.trigram_postings.size(),
        message + ": accounting trigram posting count diverged");
    require(accounting.string_count == oracle.pool.size(),
        message + ": accounting string count diverged");
    require(accounting.unique_text_bytes == unique_text_bytes,
        message + ": accounting unique text bytes diverged");
    require(accounting.source_text_bytes == oracle.source_text_bytes,
        message + ": accounting source text bytes diverged");
    require(accounting.referenced_text_bytes == oracle.referenced_text_bytes,
        message + ": accounting referenced text bytes diverged");
    require(accounting.memory_bytes != 0,
        message + ": accounting memory bytes is zero");
}

struct expected_page_t {
    std::vector<const oracle_record_t*> hits;
    std::uint64_t total = 0;
    std::uint64_t next_offset = 0;
    bool truncated = false;
};

expected_page_t paginate(const std::vector<const oracle_record_t*>& matches,
    std::uint64_t offset, std::uint32_t limit) {
    expected_page_t page;
    page.total = matches.size();
    std::uint64_t ordinal = 0;
    for (const auto* record : matches) {
        if (ordinal++ < offset || page.hits.size() >= limit)
            continue;
        page.hits.push_back(record);
    }
    page.next_offset = offset >= page.total ? page.total : offset + page.hits.size();
    page.truncated = page.next_offset < page.total;
    return page;
}

void compare_page(const search_page_t& actual, const expected_page_t& expected,
    bool immediate_numeric, std::uint64_t immediate_value, const std::string& message) {
    require(actual.total == expected.total,
        message + ": page total diverged " + std::to_string(actual.total) + " vs " +
            std::to_string(expected.total));
    require(actual.next_offset == expected.next_offset,
        message + ": page next offset diverged");
    require(actual.truncated == expected.truncated,
        message + ": page truncation diverged");
    require(actual.hits.size() == expected.hits.size(),
        message + ": page hit count diverged");
    for (std::size_t index = 0; index < expected.hits.size(); ++index) {
        const auto& hit = actual.hits[index];
        const auto& expected_record = *expected.hits[index];
        const auto prefix = message + ": hit " + std::to_string(index);
        require(hit.kind == expected_record.kind, prefix + " kind diverged");
        require(hit.entity_id == expected_record.entity_id,
            prefix + " entity id diverged");
        require(hit.address == expected_record.address, prefix + " address diverged");
        require(hit.text == expected_record.text, prefix + " text diverged");
        const auto expected_numeric = immediate_numeric
            ? immediate_value : expected_record.numeric_value;
        require(hit.numeric_value == expected_numeric,
            prefix + " numeric value diverged");
    }
}

void compare_pages_exact(const search_page_t& lhs, const search_page_t& rhs,
    const std::string& message) {
    require(lhs.total == rhs.total && lhs.next_offset == rhs.next_offset &&
        lhs.truncated == rhs.truncated &&
        lhs.candidates_examined == rhs.candidates_examined &&
        lhs.cancellation_checks == rhs.cancellation_checks &&
        lhs.hits.size() == rhs.hits.size(), message + ": page fields diverged");
    for (std::size_t index = 0; index < lhs.hits.size(); ++index) {
        const auto& left = lhs.hits[index];
        const auto& right = rhs.hits[index];
        require(left.kind == right.kind && left.entity_id == right.entity_id &&
            left.address == right.address && left.text == right.text &&
            left.numeric_value == right.numeric_value,
            message + ": hit " + std::to_string(index) + " diverged");
    }
}

expected_page_t expected_find_text(const oracle_t& oracle, const std::string& query,
    std::uint64_t offset, std::uint32_t limit) {
    const auto normalized = harness_normalize(query);
    std::vector<std::uint32_t> candidate_texts;
    if (normalized.size() >= 3) {
        std::vector<std::uint32_t> keys;
        for (std::size_t index = 0; index + 3U <= normalized.size(); ++index)
            keys.push_back(harness_trigram_key(normalized.data() + index));
        std::sort(keys.begin(), keys.end());
        keys.erase(std::unique(keys.begin(), keys.end()), keys.end());
        const oracle_trigram_span_t* candidates = nullptr;
        for (const auto key : keys) {
            const auto found = std::lower_bound(oracle.trigram_spans.begin(),
                oracle.trigram_spans.end(), key,
                [](const oracle_trigram_span_t& span, std::uint32_t value) {
                    return span.key < value;
                });
            if (found == oracle.trigram_spans.end() || found->key != key)
                return paginate({}, offset, limit);
            if (!candidates || found->count < candidates->count)
                candidates = &*found;
        }
        for (std::size_t index = 0; index < candidates->count; ++index) {
            candidate_texts.push_back(
                oracle.trigram_postings[candidates->begin + index]);
        }
    } else {
        for (std::size_t index = 0; index < oracle.text_references.size(); ++index)
            candidate_texts.push_back(static_cast<std::uint32_t>(index));
    }
    std::vector<const oracle_record_t*> matches;
    for (const auto text_index : candidate_texts) {
        const auto& content =
            oracle.pool[oracle.text_references[text_index].second - 1U];
        if (content.find(normalized) != std::string::npos)
            matches.push_back(&oracle.records[oracle.text_references[text_index].first]);
    }
    return paginate(matches, offset, limit);
}

expected_page_t expected_find_opcode(const oracle_t& oracle, std::uint32_t opcode,
    std::uint64_t offset, std::uint32_t limit) {
    std::vector<const oracle_record_t*> matches;
    for (const auto& reference : oracle.opcode_references) {
        if (reference.first == opcode)
            matches.push_back(&oracle.records[reference.second]);
    }
    return paginate(matches, offset, limit);
}

expected_page_t expected_find_immediate(const oracle_t& oracle, std::uint64_t value,
    std::uint64_t offset, std::uint32_t limit) {
    std::vector<const oracle_record_t*> matches;
    for (const auto& reference : oracle.immediate_references) {
        if (reference.first == value)
            matches.push_back(&oracle.records[reference.second]);
    }
    return paginate(matches, offset, limit);
}

expected_page_t expected_find_instruction(const oracle_t& oracle,
    const search_instruction_filter_t& filter, std::uint64_t offset,
    std::uint32_t limit) {
    std::vector<const oracle_record_t*> candidates;
    if (!filter.opcode_id && !filter.immediate) {
        for (const auto reference : oracle.instruction_references)
            candidates.push_back(&oracle.records[reference]);
    } else if (filter.opcode_id) {
        for (const auto& reference : oracle.opcode_references) {
            if (reference.first == *filter.opcode_id)
                candidates.push_back(&oracle.records[reference.second]);
        }
    } else {
        for (const auto& reference : oracle.immediate_references) {
            if (reference.first == *filter.immediate)
                candidates.push_back(&oracle.records[reference.second]);
        }
    }
    std::vector<const oracle_record_t*> matches;
    for (const auto* record : candidates) {
        if (record->kind != search_entity_kind_t::instruction)
            continue;
        if (filter.opcode_id && record->numeric_value != *filter.opcode_id)
            continue;
        if ((record->auxiliary_flags & filter.required_flow_flags) !=
            filter.required_flow_flags)
            continue;
        if ((record->auxiliary_flags & filter.forbidden_flow_flags) != 0)
            continue;
        if (filter.begin &&
            (record->address < *filter.begin || !(record->address < *filter.end)))
            continue;
        matches.push_back(record);
    }
    return paginate(matches, offset, limit);
}

expected_page_t expected_find_entity(const oracle_t& oracle,
    const search_entity_filter_t& filter, std::uint64_t offset, std::uint32_t limit) {
    std::vector<const oracle_record_t*> matches;
    if (filter.kind) {
        for (const auto reference : oracle.entity_kind_references) {
            const auto& record = oracle.records[reference];
            if (record.kind == *filter.kind &&
                (!filter.entity_id || record.entity_id == *filter.entity_id))
                matches.push_back(&record);
        }
    } else if (filter.entity_id) {
        for (const auto reference : oracle.entity_id_references) {
            const auto& record = oracle.records[reference];
            if (record.entity_id == *filter.entity_id)
                matches.push_back(&record);
        }
    } else {
        for (const auto reference : oracle.address_references)
            matches.push_back(&oracle.records[reference]);
    }
    return paginate(matches, offset, limit);
}

expected_page_t expected_find_address_range(const oracle_t& oracle,
    const address_t& begin, const address_t& end, std::uint64_t offset,
    std::uint32_t limit) {
    std::vector<const oracle_record_t*> matches;
    for (const auto reference : oracle.address_references) {
        const auto& record = oracle.records[reference];
        if (!(record.address < begin) && record.address < end)
            matches.push_back(&record);
    }
    return paginate(matches, offset, limit);
}

void verify_query_battery(const search_index_t& index, const oracle_t& oracle,
    const std::string& message) {
    const auto run_text = [&](const std::string& query, std::uint64_t offset,
                              std::uint32_t limit) {
        auto page = require_value(index.find_text(query, offset, limit, {}),
            message + ": find_text failed");
        compare_page(page, expected_find_text(oracle, query, offset, limit), false, 0,
            message + ": find_text('" + query + "', " + std::to_string(offset) + ", " +
                std::to_string(limit) + ")");
    };
    run_text("alpha", 0, 4096);
    run_text("ALPHA parser", 0, 4096);
    run_text("needle payload anchor", 0, 4096);
    run_text("shared token alpha", 0, 4096);
    run_text("ab", 0, 4096);
    run_text("x", 0, 4096);
    run_text("token", 0, 4096);
    run_text("absent trigram phrase", 0, 4096);
    for (const auto limit : {1U, 7U, 4096U}) {
        for (const auto offset : {0ULL, 1ULL, 3ULL, 17ULL, 4096ULL, 100000ULL})
            run_text("alpha", offset, limit);
    }
    auto opcode_page = require_value(index.find_opcode(0xE8U, 0, 4096, {}),
        message + ": find_opcode failed");
    compare_page(opcode_page, expected_find_opcode(oracle, 0xE8U, 0, 4096), false, 0,
        message + ": find_opcode");
    auto immediate_page = require_value(index.find_immediate(0x1234ULL, 0, 4096, {}),
        message + ": find_immediate failed");
    compare_page(immediate_page, expected_find_immediate(oracle, 0x1234ULL, 0, 4096),
        true, 0x1234ULL, message + ": find_immediate");
    search_instruction_filter_t flow_filter;
    flow_filter.required_flow_flags = flow_call;
    auto flow_page = require_value(index.find_instruction(flow_filter, 0, 4096, {}),
        message + ": find_instruction flow failed");
    compare_page(flow_page, expected_find_instruction(oracle, flow_filter, 0, 4096),
        false, 0, message + ": find_instruction flow");
    search_instruction_filter_t range_filter;
    range_filter.begin = relative_address(0x1000);
    range_filter.end = relative_address(0x5000);
    range_filter.required_flow_flags = flow_fallthrough;
    range_filter.forbidden_flow_flags = flow_call;
    auto range_page = require_value(index.find_instruction(range_filter, 0, 4096, {}),
        message + ": find_instruction range failed");
    compare_page(range_page, expected_find_instruction(oracle, range_filter, 0, 4096),
        false, 0, message + ": find_instruction range");
    search_entity_filter_t kind_filter;
    kind_filter.kind = search_entity_kind_t::string;
    auto kind_page = require_value(index.find_entity(kind_filter, 0, 4096, {}),
        message + ": find_entity kind failed");
    compare_page(kind_page, expected_find_entity(oracle, kind_filter, 0, 4096), false, 0,
        message + ": find_entity kind");
    search_entity_filter_t id_filter;
    id_filter.entity_id = 1;
    auto id_page = require_value(index.find_entity(id_filter, 0, 4096, {}),
        message + ": find_entity id failed");
    compare_page(id_page, expected_find_entity(oracle, id_filter, 0, 4096), false, 0,
        message + ": find_entity id");
    search_entity_filter_t both_filter;
    both_filter.kind = search_entity_kind_t::string;
    both_filter.entity_id = 3;
    auto both_page = require_value(index.find_entity(both_filter, 0, 4096, {}),
        message + ": find_entity both failed");
    compare_page(both_page, expected_find_entity(oracle, both_filter, 0, 4096), false, 0,
        message + ": find_entity both");
    for (const auto limit : {1U, 7U, 4096U}) {
        for (const auto offset : {0ULL, 1ULL, 5ULL, 4096ULL}) {
            search_entity_filter_t paged_filter;
            paged_filter.kind = search_entity_kind_t::string;
            auto paged = require_value(
                index.find_entity(paged_filter, offset, limit, {}),
                message + ": find_entity paged failed");
            compare_page(paged,
                expected_find_entity(oracle, paged_filter, offset, limit), false, 0,
                message + ": find_entity paged");
        }
    }
    auto address_page = require_value(index.find_address_range(
        relative_address(0x1000), relative_address(0x1000 + 0x800ULL), 0, 4096, {}),
        message + ": find_address_range failed");
    compare_page(address_page, expected_find_address_range(oracle,
        relative_address(0x1000), relative_address(0x1000 + 0x800ULL), 0, 4096), false,
        0, message + ": find_address_range");
    for (const auto limit : {1U, 7U, 4096U}) {
        for (const auto offset : {0ULL, 2ULL, 4096ULL}) {
            auto paged = require_value(index.find_address_range(
                relative_address(0x2000), relative_address(0x100000), offset, limit, {}),
                message + ": find_address_range paged failed");
            compare_page(paged, expected_find_address_range(oracle,
                relative_address(0x2000), relative_address(0x100000), offset, limit),
                false, 0, message + ": find_address_range paged");
        }
    }
}

void run_query_battery_on(const search_index_t& index, std::vector<search_page_t>& pages,
    const std::string& message) {
    pages.push_back(require_value(index.find_text("alpha", 0, 4096, {}),
        message + ": find_text battery failed"));
    pages.push_back(require_value(index.find_text("needle payload anchor", 0, 4096, {}),
        message + ": find_text battery failed"));
    pages.push_back(require_value(index.find_text("ab", 0, 4096, {}),
        message + ": find_text battery failed"));
    pages.push_back(require_value(index.find_text("alpha", 3, 7, {}),
        message + ": find_text battery failed"));
    pages.push_back(require_value(index.find_opcode(0xE8U, 0, 4096, {}),
        message + ": find_opcode battery failed"));
    pages.push_back(require_value(index.find_immediate(0x1234ULL, 0, 4096, {}),
        message + ": find_immediate battery failed"));
    search_instruction_filter_t flow_filter;
    flow_filter.required_flow_flags = flow_call;
    pages.push_back(require_value(index.find_instruction(flow_filter, 0, 4096, {}),
        message + ": find_instruction battery failed"));
    search_entity_filter_t id_filter;
    id_filter.entity_id = 1;
    pages.push_back(require_value(index.find_entity(id_filter, 0, 4096, {}),
        message + ": find_entity battery failed"));
    pages.push_back(require_value(index.find_address_range(relative_address(0x1000),
        relative_address(0x1800), 0, 4096, {}),
        message + ": find_address_range battery failed"));
}

fixture_scale_t base_scale() {
    fixture_scale_t scale;
    scale.symbols = 3000;
    scale.strings = 4000;
    scale.types = 2000;
    scale.instructions = 6000;
    scale.operands = 3000;
    scale.data = 1000;
    scale.switches = 200;
    return scale;
}

fixture_scale_t large_scale() {
    auto scale = base_scale();
    scale.symbols *= 24;
    scale.strings *= 24;
    scale.types *= 24;
    scale.instructions *= 24;
    scale.operands *= 24;
    scale.data *= 24;
    scale.switches *= 24;
    return scale;
}

void verify_parity(const sha256_digest_t& provider_hash, std::uint64_t provider_size) {
    const auto limits = parity_limits();
    auto model_a = make_model(0xA17A1234ULL, base_scale(), provider_hash, provider_size);
    auto model_b = make_model(0xA17A1234ULL, base_scale(), provider_hash, provider_size);
    const auto oracle = build_oracle(model_a);
    auto metrics_a = std::make_shared<analysis_metrics_t>(kGeneration);
    auto metrics_b = std::make_shared<analysis_metrics_t>(kGeneration);
    auto index_a = require_value(search_index_t::build(model_a.snapshot,
        model_a.data_candidates, model_a.switches, model_a.types, metrics_a, limits, {}),
        "parallel search index build A failed");
    auto index_b = require_value(search_index_t::build(model_b.snapshot,
        model_b.data_candidates, model_b.switches, model_b.types, metrics_b, limits, {}),
        "parallel search index build B failed");

    verify_index_against_oracle(*index_a, oracle, "index A vs sequential oracle");
    verify_index_against_oracle(*index_b, oracle, "index B vs sequential oracle");
    require(index_a->size_accounting().memory_bytes ==
        index_b->size_accounting().memory_bytes,
        "build A and build B memory accounting diverged");

    const auto blob_a = serialize_index(*index_a);
    const auto blob_b = serialize_index(*index_b);
    const auto blob_oracle = oracle_serialize(oracle, *model_a.snapshot, limits);
    compare_masked_blobs(blob_a, blob_oracle, true,
        "index A serialization vs sequential oracle");
    compare_masked_blobs(blob_a, blob_b, false,
        "index A serialization vs index B serialization");

    const auto snapshot_metrics = metrics_a->snapshot();
    require(snapshot_metrics.value(analysis_metric_t::index_entries) ==
        oracle.records.size(), "index_entries metric diverged");
    require(snapshot_metrics.value(analysis_metric_t::index_trigram_postings) ==
        oracle.trigram_postings.size(), "index_trigram_postings metric diverged");
    require(snapshot_metrics.value(analysis_metric_t::index_text_bytes) ==
        oracle.source_text_bytes, "index_text_bytes metric diverged");
    require(snapshot_metrics.value(analysis_metric_t::index_serialized_bytes) >=
        blob_a.size(), "index_serialized_bytes metric diverged");
    require(snapshot_metrics.value(analysis_metric_t::indexed_bytes) ==
        index_a->size_accounting().memory_bytes, "indexed_bytes metric diverged");

    verify_query_battery(*index_a, oracle, "index A query battery");

    std::vector<search_page_t> pages_a;
    std::vector<search_page_t> pages_b;
    run_query_battery_on(*index_a, pages_a, "index A cross-build battery");
    run_query_battery_on(*index_b, pages_b, "index B cross-build battery");
    require(pages_a.size() == pages_b.size(), "cross-build battery size diverged");
    for (std::size_t page = 0; page < pages_a.size(); ++page) {
        compare_pages_exact(pages_a[page], pages_b[page],
            "cross-build query page " + std::to_string(page));
    }

    auto restored_model = make_model(0xA17A1234ULL, base_scale(), provider_hash,
        provider_size);
    auto restored = require_value(search_index_t::restore(restored_model.snapshot,
        restored_model.data_candidates, restored_model.switches, restored_model.types,
        std::make_shared<analysis_metrics_t>(kGeneration), limits, blob_a, {}),
        "parallel-built index restore failed");
    verify_index_against_oracle(*restored, oracle, "restored index vs sequential oracle");
    const auto blob_restored = serialize_index(*restored);
    compare_masked_blobs(blob_restored, blob_a, true,
        "restored serialization vs source serialization");
    std::vector<search_page_t> pages_restored;
    run_query_battery_on(*restored, pages_restored, "restored battery");
    require(pages_restored.size() == pages_a.size(), "restored battery size diverged");
    for (std::size_t page = 0; page < pages_restored.size(); ++page) {
        compare_pages_exact(pages_restored[page], pages_a[page],
            "restored query page " + std::to_string(page));
    }
}

void verify_forced_limits(const sha256_digest_t& provider_hash,
    std::uint64_t provider_size) {
    const auto expect_failure = [&](search_index_limits_t limits,
        workspace_error_code_t code, const char* message, const char* phase) {
        auto model = make_model(0xB77E5511ULL, base_scale(), provider_hash,
            provider_size);
        auto result = search_index_t::build(model.snapshot, model.data_candidates,
            model.switches, model.types,
            std::make_shared<analysis_metrics_t>(kGeneration), limits, {});
        require(!result, "forced-limit build unexpectedly succeeded");
        require(result.error().code == code,
            std::string("forced-limit code diverged: ") + result.error().stable_code());
        require(result.error().message == message,
            std::string("forced-limit message diverged: ") + result.error().message);
        require(result.error().phase == phase,
            std::string("forced-limit phase diverged: ") + result.error().phase);
    };
    auto baseline_limits = parity_limits();
    const auto prospective = make_model(0xB77E5511ULL, base_scale(), provider_hash,
        provider_size);
    const auto prospective_entries = prospective.snapshot->symbols.size() +
        prospective.snapshot->strings.size() + prospective.snapshot->instructions.size() +
        prospective.data_candidates.size() + prospective.switches.size() +
        prospective.types.size();

    auto entries_limits = baseline_limits;
    entries_limits.max_entries = prospective_entries - 1;
    expect_failure(entries_limits, workspace_error_code_t::limit_exceeded,
        "search-index entry count exceeds analysis budget", "search_index");

    auto text_limits = baseline_limits;
    text_limits.max_indexed_text_bytes = 1;
    expect_failure(text_limits, workspace_error_code_t::limit_exceeded,
        "search-index text budget exceeded", "search_index");

    auto postings_limits = baseline_limits;
    postings_limits.max_trigram_postings = 1;
    expect_failure(postings_limits, workspace_error_code_t::limit_exceeded,
        "search-index posting budget exceeded", "search_index");

    auto base_limits = baseline_limits;
    base_limits.max_index_bytes = 1;
    expect_failure(base_limits, workspace_error_code_t::limit_exceeded,
        "search-index base storage exceeds memory budget", "search_index");

    auto model = make_model(0xB77E5511ULL, base_scale(), provider_hash, provider_size);
    auto built = require_value(search_index_t::build(model.snapshot,
        model.data_candidates, model.switches, model.types,
        std::make_shared<analysis_metrics_t>(kGeneration), baseline_limits, {}),
        "baseline build for memory cap measurement failed");
    auto memory_limits = baseline_limits;
    memory_limits.max_index_bytes = built->size_accounting().memory_bytes - 1;
    expect_failure(memory_limits, workspace_error_code_t::limit_exceeded,
        "search-index memory budget exceeded", "search_index");
}

void verify_cancellation(const sha256_digest_t& provider_hash,
    std::uint64_t provider_size) {
    const auto limits = parity_limits();
    {
        auto model = make_model(0xCA5CE11ULL, base_scale(), provider_hash,
            provider_size);
        cancellation_source_t cancelled;
        cancelled.request_cancel();
        auto result = search_index_t::build(model.snapshot, model.data_candidates,
            model.switches, model.types,
            std::make_shared<analysis_metrics_t>(kGeneration), limits,
            cancelled.token());
        require(!result, "pre-cancelled build unexpectedly succeeded");
        require(result.error().code == workspace_error_code_t::cancelled,
            "pre-cancelled build error code diverged");
        require(result.error().message == "search operation cancelled",
            "pre-cancelled build error message diverged");
        require(result.error().phase == "search_index",
            "pre-cancelled build error phase diverged");
    }
    {
        auto model = make_model(0xCA5CE11ULL, base_scale(), provider_hash,
            provider_size);
        cancellation_source_t deadline(
            std::chrono::steady_clock::now() - std::chrono::seconds(1));
        auto result = search_index_t::build(model.snapshot, model.data_candidates,
            model.switches, model.types,
            std::make_shared<analysis_metrics_t>(kGeneration), limits,
            deadline.token());
        require(!result, "expired-deadline build unexpectedly succeeded");
        require(result.error().code == workspace_error_code_t::deadline_exceeded,
            "expired-deadline build error code diverged");
        require(result.error().message == "search operation exceeded its deadline",
            "expired-deadline build error message diverged");
    }
    {
        auto model = make_model(0xCA5CE11ULL, large_scale(), provider_hash,
            provider_size);
        auto large_limits = limits;
        large_limits.cancellation_check_interval = 64;
        cancellation_source_t source;
        std::atomic<bool> done{false};
        std::thread watcher([&] {
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
            if (!done.load(std::memory_order_acquire))
                source.request_cancel();
        });
        const auto started = harness_log_t::epoch_ms();
        auto result = search_index_t::build(model.snapshot, model.data_candidates,
            model.switches, model.types,
            std::make_shared<analysis_metrics_t>(kGeneration), large_limits,
            source.token());
        const auto elapsed = harness_log_t::epoch_ms() - started;
        done.store(true, std::memory_order_release);
        watcher.join();
        require(!result, "live-cancelled build unexpectedly succeeded");
        require(result.error().code == workspace_error_code_t::cancelled ||
            result.error().code == workspace_error_code_t::deadline_exceeded,
            "live-cancelled build error code diverged");
        require(elapsed < 60000,
            "live-cancelled build did not quiesce inside the bounded window");
    }
}

void verify_parallel_primitives() {
    require(parallel_worker_count() >= 1 && parallel_worker_count() <= 16,
        "parallel_worker_count is outside its contracted range");

    for (const auto count : {0ULL, 1ULL, 2ULL, 7ULL, 1000ULL, 65536ULL}) {
        for (const std::uint32_t workers : {0U, 1U, 2U, 16U}) {
            const auto shards = parallel_shards(count, workers);
            const auto resolved = workers == 0 ? parallel_worker_count() : workers;
            const auto expected_count = count == 0
                ? 0ULL
                : static_cast<unsigned long long>((std::min<std::uint64_t>)(count,
                      (std::max<std::uint32_t>)(1U, resolved)));
            require(shards.size() == expected_count, "shard count diverged");
            std::size_t cursor = 0;
            std::size_t min_extent = std::numeric_limits<std::size_t>::max();
            std::size_t max_extent = 0;
            for (const auto& shard : shards) {
                require(shard.begin == cursor, "shard coverage is not contiguous");
                cursor = shard.end;
                min_extent = (std::min)(min_extent, shard.end - shard.begin);
                max_extent = (std::max)(max_extent, shard.end - shard.begin);
            }
            require(cursor == count, "shard coverage does not cover the input range");
            if (!shards.empty())
                require(max_extent - min_extent <= 1, "shard extents are not near-equal");
            const auto repeated = parallel_shards(count, workers);
            require(repeated.size() == shards.size(),
                "shard partition is not deterministic");
            for (std::size_t shard = 0; shard < shards.size(); ++shard) {
                require(repeated[shard].begin == shards[shard].begin &&
                    repeated[shard].end == shards[shard].end,
                    "shard partition is not deterministic");
            }
        }
    }

    splitmix64_t rng{0x5EED5EEDULL};
    const auto check_sort = [&](std::vector<std::uint64_t> values,
        std::uint32_t workers, const std::string& label) {
        auto expected = values;
        std::sort(expected.begin(), expected.end());
        parallel_sort(values.begin(), values.end(),
            [](std::uint64_t lhs, std::uint64_t rhs) { return lhs < rhs; }, workers);
        require(values == expected, label + ": parallel_sort output diverged");
    };
    check_sort(std::vector<std::uint64_t>(100000, 0xABCDEFULL), 1, "all-equal@1");
    check_sort(std::vector<std::uint64_t>(100000, 0xABCDEFULL), 16, "all-equal@16");
    std::vector<std::uint64_t> distinct(200000);
    for (std::size_t index = 0; index < distinct.size(); ++index)
        distinct[index] = distinct.size() - index;
    check_sort(distinct, 4, "distinct-descending@4");
    std::vector<std::uint64_t> randoms(1000000);
    for (auto& value : randoms)
        value = rng.next();
    check_sort(randoms, 16, "random@16");
    check_sort(randoms, 1, "random@1");
    for (const auto boundary : {65535ULL, 65536ULL, 65537ULL}) {
        std::vector<std::uint64_t> edge(boundary);
        for (auto& value : edge)
            value = rng.next();
        check_sort(edge, 4, "boundary@" + std::to_string(boundary));
    }
    {
        struct keyed_t {
            std::uint32_t key = 0;
            std::uint32_t payload = 0;
            bool operator==(const keyed_t& other) const {
                return key == other.key && payload == other.payload;
            }
        };
        std::vector<keyed_t> keyed(300000);
        for (auto& value : keyed) {
            value.key = static_cast<std::uint32_t>(rng.below(100));
            value.payload = static_cast<std::uint32_t>(rng.next());
        }
        auto expected = keyed;
        const auto less = [](const keyed_t& lhs, const keyed_t& rhs) {
            return lhs.key != rhs.key ? lhs.key < rhs.key : lhs.payload < rhs.payload;
        };
        std::sort(expected.begin(), expected.end(), less);
        for (const std::uint32_t workers : {1U, 4U, 16U}) {
            auto actual = keyed;
            parallel_sort(actual.begin(), actual.end(), less, workers);
            require(actual == expected,
                "duplicated-keys parallel_sort diverged at workers=" +
                    std::to_string(workers));
        }
    }

    {
        const auto shards = parallel_shards(8, 8);
        std::vector<std::size_t> visits(shards.size(), 0);
        auto result = parallel_run_shards(shards,
            [&](std::size_t shard_index, const parallel_shard_t& shard) {
                visits[shard_index] = shard.end - shard.begin;
                return workspace_result_t<void>::success();
            }, {});
        require(static_cast<bool>(result), "all-success shard run failed");
        require(std::accumulate(visits.begin(), visits.end(), std::size_t{0}) == 8,
            "all-success shard run did not visit every shard");
    }
    {
        const auto shards = parallel_shards(8, 8);
        auto result = parallel_run_shards(shards,
            [&](std::size_t shard_index, const parallel_shard_t&) {
                if (shard_index == 3) {
                    return workspace_result_t<void>::failure(make_workspace_error(
                        workspace_error_code_t::integrity_failure, "alpha failure",
                        "harness"));
                }
                if (shard_index == 5) {
                    return workspace_result_t<void>::failure(make_workspace_error(
                        workspace_error_code_t::limit_exceeded, "beta failure",
                        "harness"));
                }
                return workspace_result_t<void>::success();
            }, {});
        require(!result && result.error().message == "alpha failure",
            "shard runner did not return the lowest-shard failure");
    }
    {
        const auto shards = parallel_shards(4, 4);
        auto result = parallel_run_shards(shards,
            [&](std::size_t shard_index, const parallel_shard_t&)
                -> workspace_result_t<void> {
                if (shard_index == 1) {
                    return workspace_result_t<void>::failure(make_workspace_error(
                        workspace_error_code_t::integrity_failure, "first failure",
                        "harness"));
                }
                if (shard_index == 2)
                    throw std::runtime_error("slot two exception");
                return workspace_result_t<void>::success();
            }, {});
        require(!result && result.error().message == "first failure",
            "shard runner prioritized a later exception over an earlier failure");
    }
    {
        const auto shards = parallel_shards(4, 4);
        bool observed = false;
        try {
            auto result = parallel_run_shards(shards,
                [&](std::size_t shard_index, const parallel_shard_t&)
                    -> workspace_result_t<void> {
                    if (shard_index == 2)
                        throw std::runtime_error("slot two exception");
                    return workspace_result_t<void>::success();
                }, {});
            require(!result, "exception-only shard run reported a workspace failure");
        } catch (const std::runtime_error& error) {
            observed = std::string(error.what()) == "slot two exception";
        }
        require(observed, "shard runner did not rethrow the shard exception");
    }
    {
        const auto shards = parallel_shards(4, 4);
        cancellation_source_t source;
        std::atomic<bool> release{false};
        std::thread canceller([&] {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
            source.request_cancel();
            release.store(true, std::memory_order_release);
        });
        const auto started = harness_log_t::epoch_ms();
        auto result = parallel_run_shards(shards,
            [&](std::size_t, const parallel_shard_t&) {
                while (!release.load(std::memory_order_acquire))
                    std::this_thread::yield();
                auto error = make_workspace_error(workspace_error_code_t::cancelled,
                    "shard observed cancellation", "harness");
                error.cancellation = true;
                return workspace_result_t<void>::failure(std::move(error));
            }, source.token());
        canceller.join();
        const auto elapsed = harness_log_t::epoch_ms() - started;
        require(!result && result.error().code == workspace_error_code_t::cancelled,
            "cancellation shard run did not surface the shard error");
        require(elapsed < 5000, "cancellation shard run did not join promptly");
    }

    {
        const auto shards = parallel_shards(1000, 4);
        auto result = parallel_validate_shards(shards, 1,
            [&](std::size_t, const parallel_shard_t& shard) {
                ordered_error_t outcome;
                for (std::size_t item = shard.begin; item < shard.end; ++item) {
                    if (item == 120 || item == 500) {
                        outcome.ordinal = item;
                        outcome.error = make_workspace_error(
                            workspace_error_code_t::integrity_failure,
                            item == 120 ? "lower ordinal" : "higher ordinal", "harness");
                        return outcome;
                    }
                }
                return outcome;
            }, {});
        require(!result && result.error().message == "lower ordinal",
            "validate shards did not reduce to the minimum ordinal failure");
        auto success = parallel_validate_shards(shards, 1,
            [&](std::size_t, const parallel_shard_t&) {
                return ordered_error_t{};
            }, {});
        require(static_cast<bool>(success), "validate shards rejected a clean run");
    }

    {
        const auto sums = parallel_prefix_sums(
            std::vector<std::uint64_t>{5, 7, 11, 13},
            [](std::uint64_t lhs, std::uint64_t rhs) { return lhs + rhs; });
        require((sums == std::vector<std::uint64_t>{0, 5, 12, 23}),
            "parallel_prefix_sums output diverged");
        require(parallel_prefix_sums(std::vector<std::uint64_t>{},
            [](std::uint64_t lhs, std::uint64_t rhs) { return lhs + rhs; }).empty(),
            "parallel_prefix_sums mishandled an empty input");
    }
}

void verify_wrapper_queries(const search_index_t& index,
    const std::shared_ptr<provider_snapshot_t>& provider,
    const std::vector<std::uint8_t>& provider_bytes, const oracle_t& oracle,
    const std::string& message) {
    query_index_limits_t limits;
    limits.max_page_size = 4096;
    auto query_a = require_value(query_index_t::build(
        index.shared_from_this(), provider, limits),
        message + ": query index construction failed");

    auto literal = require_value(query_a->query_literal(
        literal_search_query_t{"needle", true}, query_page_request_t{4096, {}}),
        message + ": literal wrapper query failed");
    std::vector<const oracle_record_t*> literal_expected;
    for (const auto& reference : oracle.text_references) {
        const auto& record = oracle.records[reference.first];
        if (record.text.find("needle") != std::string::npos)
            literal_expected.push_back(&record);
    }
    require(literal.total == literal_expected.size() &&
        literal.hits.size() == literal_expected.size(),
        message + ": literal wrapper total diverged " +
            std::to_string(literal.total) + " vs " +
            std::to_string(literal_expected.size()));
    for (std::size_t entry = 0; entry < literal_expected.size(); ++entry)
        require(literal.hits[entry].entity_id == literal_expected[entry]->entity_id,
            message + ": literal wrapper hit order diverged");

    auto insensitive = require_value(query_a->query_literal(
        literal_search_query_t{"ALPHA", false}, query_page_request_t{4096, {}}),
        message + ": case-insensitive wrapper query failed");
    std::size_t insensitive_expected = 0;
    for (const auto& reference : oracle.text_references) {
        const auto& record = oracle.records[reference.first];
        if (ascii_contains_case_insensitive(record.text, "ALPHA"))
            ++insensitive_expected;
    }
    require(insensitive.total == insensitive_expected &&
        insensitive.hits.size() == insensitive_expected,
        message + ": case-insensitive wrapper total diverged " +
            std::to_string(insensitive.total) + " vs " +
            std::to_string(insensitive_expected));

    regex_compile_options_t options;
    options.case_sensitive = false;
    auto regex = require_value(query_a->query_regex(
        regex_search_query_t{"needle_[0-9]+", options}, query_page_request_t{4096, {}}),
        message + ": regex wrapper query failed");
    const std::regex expected_pattern("needle_[0-9]+", std::regex_constants::icase);
    std::size_t regex_expected = 0;
    for (const auto& reference : oracle.text_references) {
        const auto& record = oracle.records[reference.first];
        if (std::regex_search(record.text, expected_pattern))
            ++regex_expected;
    }
    require(regex.total == regex_expected && regex.hits.size() == regex_expected,
        message + ": regex wrapper total diverged " + std::to_string(regex.total) +
            " vs " + std::to_string(regex_expected));

    const std::string marker = "AiDA workspace fixture 41";
    const std::vector<std::uint8_t> pattern(marker.begin(), marker.end());
    std::size_t byte_expected = 0;
    for (std::size_t position = 0; position + pattern.size() <= provider_bytes.size();
         ++position) {
        if (std::memcmp(provider_bytes.data() + position, pattern.data(),
                pattern.size()) == 0)
            ++byte_expected;
    }
    byte_search_query_t bytes_query;
    bytes_query.pattern = pattern;
    auto bytes = require_value(query_a->query_bytes(bytes_query,
        query_page_request_t{4096, {}}),
        message + ": bytes wrapper query failed");
    require(byte_expected != 0,
        message + ": byte fixture marker is absent from the provider bytes");
    require(bytes.total == byte_expected && bytes.hits.size() == byte_expected,
        message + ": bytes wrapper total diverged " + std::to_string(bytes.total) +
            " vs " + std::to_string(byte_expected));
}

}

int main() {
    const auto harness_start = harness_log_t::epoch_ms();
    harness_log_t::emit("search_index_parity", "main", "enter", 0);
    try {
        auto provider = require_value(sealed_memory_provider_t::create(
            aida::analysis::test_fixture::analysis_contract_pe64(0x29U)),
            "parity provider creation failed");
        require(provider->identity().content_sha256.has_value(),
            "parity provider hash is absent");
        const auto provider_hash = *provider->identity().content_sha256;
        const auto provider_size = provider->size();
        const auto provider_bytes = aida::analysis::test_fixture::analysis_contract_pe64(
            0x29U);
        auto provider_snapshot = require_value(provider_snapshot_t::capture(
            provider, kGeneration), "parity provider snapshot capture failed");

        {
            const auto phase_start = harness_log_t::epoch_ms();
            harness_log_t::emit("search_index_parity", "parallel_primitives", "enter", 0);
            verify_parallel_primitives();
            harness_log_t::emit("search_index_parity", "parallel_primitives", "pass",
                harness_log_t::epoch_ms() - phase_start);
        }

        {
            const auto phase_start = harness_log_t::epoch_ms();
            harness_log_t::emit("search_index_parity", "build_parity", "enter", 0);
            verify_parity(provider_hash, provider_size);
            harness_log_t::emit("search_index_parity", "build_parity", "pass",
                harness_log_t::epoch_ms() - phase_start);
        }

        {
            const auto phase_start = harness_log_t::epoch_ms();
            harness_log_t::emit("search_index_parity", "wrapper_queries", "enter", 0);
            auto model = make_model(0xA17A1234ULL, base_scale(), provider_hash,
                provider_size);
            const auto oracle = build_oracle(model);
            auto index = require_value(search_index_t::build(model.snapshot,
                model.data_candidates, model.switches, model.types,
                std::make_shared<analysis_metrics_t>(kGeneration), parity_limits(), {}),
                "wrapper fixture build failed");
            verify_wrapper_queries(*index, provider_snapshot, provider_bytes, oracle,
                "wrapper queries");
            harness_log_t::emit("search_index_parity", "wrapper_queries", "pass",
                harness_log_t::epoch_ms() - phase_start);
        }

        {
            const auto phase_start = harness_log_t::epoch_ms();
            harness_log_t::emit("search_index_parity", "forced_limits", "enter", 0);
            verify_forced_limits(provider_hash, provider_size);
            harness_log_t::emit("search_index_parity", "forced_limits", "pass",
                harness_log_t::epoch_ms() - phase_start);
        }

        {
            const auto phase_start = harness_log_t::epoch_ms();
            harness_log_t::emit("search_index_parity", "cancellation", "enter", 0);
            verify_cancellation(provider_hash, provider_size);
            harness_log_t::emit("search_index_parity", "cancellation", "pass",
                harness_log_t::epoch_ms() - phase_start);
        }

        harness_log_t::emit("search_index_parity", "main", "pass",
            harness_log_t::epoch_ms() - harness_start);
        std::printf("search_index_parity_harness source contract satisfied\n");
        return 0;
    } catch (const std::exception& error) {
        const auto elapsed = harness_log_t::epoch_ms() - harness_start;
        harness_log_t::emit("search_index_parity", "main", "fail", elapsed, error.what());
        std::fprintf(stderr, "%s\n", error.what());
        return 1;
    } catch (...) {
        const auto elapsed = harness_log_t::epoch_ms() - harness_start;
        harness_log_t::emit("search_index_parity", "main", "fail", elapsed,
            "search index parity harness failed with a non-standard exception");
        return 1;
    }
}
