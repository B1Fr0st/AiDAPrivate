#include "decompiler_quality_scorer.hpp"

#include "assertion_telemetry/assertion_telemetry.hpp"

#include "evidence_hash.hpp"
#include "fixture_materializer.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <cctype>
#include <cmath>
#include <fstream>
#include <limits>
#include <map>
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
    constexpr std::array<std::string_view, 10> k_metrics{"typed_entities", "calls", "fields", "locals",
        "parameters", "cfg", "control_structures", "exception_regions", "type_correctness", "source_coordinates"};
    constexpr std::string_view k_owned_fact_prefix = "aida-owned-v1:";

    struct scorer_error_t : std::runtime_error
    {
        using std::runtime_error::runtime_error;
    };

    struct binding_t
    {
        quality_file_binding_request_t request;
        std::string sha256;
    };

    using binding_map_t = std::map<std::string, binding_t, std::less<>>;

    void require(bool condition, std::string message)
    {
		aida::analysis::c03_test::assertion_telemetry::record_assertion(
			condition, message, __FILE__, __LINE__);
        if (!condition)
            throw scorer_error_t(std::move(message));
    }

    void add_count(std::uint64_t& value, std::uint64_t increment, std::string_view label)
    {
        require(value <= std::numeric_limits<std::uint64_t>::max() - increment,
            std::string(label) + " counter overflow");
        value += increment;
    }

    void require_closed(const json& value, std::initializer_list<std::string_view> allowed,
        std::string_view label)
    {
        require(value.is_object(), std::string(label) + " must be an object");
        std::set<std::string, std::less<>> names;
        for (const auto name : allowed)
            names.emplace(name);
        for (auto iterator = value.begin(); iterator != value.end(); ++iterator)
            require(names.find(iterator.key()) != names.end(), std::string(label) + " has unknown field " + iterator.key());
    }

    std::string require_text(const json& value, std::string_view field, std::string_view label)
    {
        require(value.contains(std::string(field)) && value.at(std::string(field)).is_string() &&
            !value.at(std::string(field)).get_ref<const std::string&>().empty(),
            std::string(label) + " requires nonempty " + std::string(field));
        return value.at(std::string(field)).get<std::string>();
    }

    std::set<std::string, std::less<>> strings(const json& value, std::string_view label)
    {
        require(value.is_array(), std::string(label) + " must be an array");
        std::set<std::string, std::less<>> output;
        for (const auto& item : value) {
            require(item.is_string() && !item.get_ref<const std::string&>().empty(),
                std::string(label) + " contains an invalid fact");
            require(output.insert(item.get<std::string>()).second,
                std::string(label) + " contains a duplicate fact");
        }
        return output;
    }

    binding_map_t bind_files(const decompiler_quality_score_request_t& request)
    {
        require(!request.file_bindings.empty() && request.file_bindings.size() <= 512,
            "quality scorer requires a bounded nonempty file-binding set");
        binding_map_t bindings;
        for (const auto& binding : request.file_bindings) {
            require(!binding.id.empty() && !binding.kind.empty() && !binding.relative_path.empty() &&
                is_canonical_sha256(binding.expected_sha256) &&
                binding.maximum_bytes != 0 && binding.maximum_bytes <= 4ULL * 1024ULL * 1024ULL * 1024ULL,
                "quality file binding is incomplete or unbounded");
            const auto hash = sha256_repository_evidence_file(request.evidence_root,
                binding.relative_path, binding.maximum_bytes);
            require(hash.ok, hash.error);
            require(hash.sha256 == binding.expected_sha256,
                "quality file binding hash differs from the expected immutable identity");
            require(bindings.emplace(binding.id, binding_t{binding, hash.sha256}).second,
                "quality file binding identifier is duplicated");
        }
        return bindings;
    }

    const binding_t& binding(const binding_map_t& bindings, std::string_view id)
    {
        const auto found = bindings.find(std::string(id));
        require(found != bindings.end(), "quality evidence references an unknown file binding");
        return found->second;
    }

    json load_bound_json(const std::filesystem::path& root, const binding_t& source)
    {
        const auto path = root / std::filesystem::u8path(source.request.relative_path);
        std::error_code size_error;
        const auto size = std::filesystem::file_size(path, size_error);
        require(!size_error && size != 0 && size <= source.request.maximum_bytes &&
                size <= static_cast<std::uint64_t>((std::numeric_limits<std::size_t>::max)()),
            "bound JSON evidence is absent, empty, or oversized");
        std::ifstream stream(path, std::ios::binary);
        require(stream.good(), "bound JSON evidence cannot be opened");
        std::string bytes(static_cast<std::size_t>(size), '\0');
        stream.read(bytes.data(), static_cast<std::streamsize>(bytes.size()));
        require(stream && stream.gcount() == static_cast<std::streamsize>(bytes.size()),
            "bound JSON evidence could not be read completely");
        const auto observed = sha256_evidence_bytes(bytes.data(), bytes.size());
        require(observed.ok && observed.sha256 == source.sha256,
            observed.ok ? "bound JSON bytes changed after evidence binding" : observed.error);
        try {
            return json::parse(bytes, nullptr, true, false);
        } catch (const std::exception& parse_error) {
            throw scorer_error_t(std::string("bound JSON evidence is malformed: ") +
                parse_error.what());
        }
    }

    std::map<std::string, json, std::less<>> index_by_id(const json& records, std::string_view label)
    {
        require(records.is_array() && !records.empty(), std::string(label) + " must be a nonempty array");
        std::map<std::string, json, std::less<>> output;
        for (const auto& record : records) {
            require_closed(record, {"id", "format", "architecture", "architecture_identity", "mode", "endian", "source", "facts"}, label);
            const auto id = require_text(record, "id", label);
            require(output.emplace(id, record).second, std::string(label) + " contains a duplicate identifier");
        }
        return output;
    }

    std::string fact_field(std::string_view metric)
    {
        if (metric == "typed_entities") return "entities";
        if (metric == "cfg") return "cfg_edges";
        if (metric == "type_correctness") return "types";
        return std::string(metric);
    }

    bool supplemental_metric(const std::string_view metric) noexcept
    {
        return metric == "fields" || metric == "locals" ||
            metric == "parameters" || metric == "exception_regions";
    }

    std::set<std::string, std::less<>> metric_facts(const json& facts, std::string_view metric)
    {
        require(facts.is_object(), "provider or ground-truth facts must be an object");
        const auto field = fact_field(metric);
        const auto found = facts.find(field);
        require(found != facts.end(), "provider or ground-truth facts omit required metric field: " + field);
        return strings(*found, field);
    }

    std::set<std::string, std::less<>> metric_unknowns(const json& unknowns,
        std::string_view metric)
    {
        require_closed(unknowns, {"typed_entities", "calls", "fields", "locals", "parameters",
            "cfg", "control_structures", "exception_regions", "type_correctness", "source_coordinates"},
            "metric-domain explicit unknowns");
        const auto found = unknowns.find(std::string(metric));
        require(found != unknowns.end(), "metric-domain explicit unknowns omit required metric");
        return strings(*found, "metric-domain explicit unknowns");
    }

    std::string ascii_lower(std::string value)
    {
        std::transform(value.begin(), value.end(), value.begin(), [](const unsigned char character) {
            return static_cast<char>(std::tolower(character));
        });
        return value;
    }

    std::string trim_ascii(std::string value)
    {
        const auto nonspace = [](const unsigned char character) { return !std::isspace(character); };
        const auto begin = std::find_if(value.begin(), value.end(), nonspace);
        const auto end = std::find_if(value.rbegin(), value.rend(), nonspace).base();
        return begin < end ? std::string(begin, end) : std::string{};
    }

    struct owned_fact_t
    {
        std::string owner;
        std::string value;
    };

    owned_fact_t decode_owned_fact(const std::string_view raw)
    {
        if (raw.substr(0, k_owned_fact_prefix.size()) != k_owned_fact_prefix)
            return {{}, std::string(raw)};
        const auto length_begin = raw.data() + k_owned_fact_prefix.size();
        const auto colon = raw.find(':', k_owned_fact_prefix.size());
        require(colon != std::string_view::npos && colon != k_owned_fact_prefix.size(),
            "owned semantic fact has an invalid owner length");
        std::size_t owner_size = 0;
        const auto parsed = std::from_chars(length_begin, raw.data() + colon, owner_size);
        require(parsed.ec == std::errc{} && parsed.ptr == raw.data() + colon &&
            owner_size <= raw.size() - colon - 1U,
            "owned semantic fact has an invalid owner extent");
        const auto owner_begin = colon + 1U;
        return {std::string(raw.substr(owner_begin, owner_size)),
            std::string(raw.substr(owner_begin + owner_size))};
    }

    std::string identifier_leaf(std::string value)
    {
        value = trim_ascii(std::move(value));
        const auto encoded_jvm_name = ascii_lower(value);
        if (encoded_jvm_name.size() >= 17U &&
            encoded_jvm_name.compare(encoded_jvm_name.size() - 17U, 17U,
                "$jvm$3c696e69743e") == 0)
            return "constructor";
        const auto arrow = value.rfind("->");
        if (arrow != std::string::npos)
            value.erase(0, arrow + 2U);
        const auto scope = value.rfind("::");
        if (scope != std::string::npos)
            value.erase(0, scope + 2U);
        const auto open = value.find('(');
        if (open != std::string::npos)
            value.erase(open);
        const auto type_suffix = value.find(':');
        if (type_suffix != std::string::npos)
            value.erase(type_suffix);
        while (!value.empty() && (value.front() == '_' || value.front() == 'L')) {
            if (value.front() == 'L' && value.find('/') == std::string::npos &&
                value.find('.') == std::string::npos)
                break;
            value.erase(value.begin());
        }
        while (!value.empty() && value.back() == ';')
            value.pop_back();
        const auto separator = value.find_last_of("./$");
        if (separator != std::string::npos)
            value.erase(0, separator + 1U);
        value = ascii_lower(std::move(value));
        if (value == "<init>" || value == "$jvm$3c696e69743e")
            return "constructor";
        return value;
    }

    std::string variable_leaf(std::string value)
    {
        value = trim_ascii(std::move(value));
        const auto type_suffix = value.rfind(':');
        if (type_suffix != std::string::npos &&
            (type_suffix == 0 || value[type_suffix - 1U] != ':'))
            value.erase(type_suffix);
        const auto descriptor_close = value.rfind(')');
        const auto separator = value.rfind('.');
        if (separator != std::string::npos &&
            (descriptor_close == std::string::npos || separator > descriptor_close))
            value.erase(0, separator + 1U);
        return identifier_leaf(std::move(value));
    }

    std::set<std::string, std::less<>> target_symbols(const json& truth)
    {
        const auto& facts = truth.at("facts");
        const auto symbols = facts.find("symbols");
        const auto entities = facts.find("entities");
        require(symbols != facts.end() && entities != facts.end(),
            "ground-truth facts omit callable symbols or entities");
        std::set<std::string, std::less<>> symbol_names;
        for (const auto& value : strings(*symbols, "ground-truth symbols")) {
            const auto normalized = identifier_leaf(value);
            require(!normalized.empty(), "ground-truth symbol cannot be normalized");
            symbol_names.insert(normalized);
        }
        std::set<std::string, std::less<>> output;
        for (const auto& value : strings(*entities, "ground-truth entities")) {
            const auto normalized = identifier_leaf(value);
            if (symbol_names.find(normalized) != symbol_names.end())
                output.insert(normalized);
        }
        if (output.empty())
            output = std::move(symbol_names);
        return output;
    }

    std::string inferred_owner(const std::string_view raw,
        const std::set<std::string, std::less<>>& targets)
    {
        std::string value(raw);
        const auto type_suffix = value.rfind(':');
        if (type_suffix != std::string::npos)
            value.erase(type_suffix);
        std::vector<std::string> parts;
        std::string current;
        for (std::size_t index = 0; index < value.size(); ++index) {
            if (value[index] == '.' || (value[index] == ':' && index + 1U < value.size() &&
                    value[index + 1U] == ':')) {
                if (!current.empty()) {
                    parts.push_back(current);
                    current.clear();
                }
                if (value[index] == ':')
                    ++index;
            } else {
                current.push_back(value[index]);
            }
        }
        if (!current.empty())
            parts.push_back(std::move(current));
        if (parts.size() >= 2U) {
            const auto candidate = identifier_leaf(parts[parts.size() - 2U]);
            if (targets.find(candidate) != targets.end())
                return candidate;
        }
        if (targets.size() == 1U)
            return *targets.begin();
        return {};
    }

    std::string semantic_owner(const owned_fact_t& fact,
        const std::set<std::string, std::less<>>& targets)
    {
        if (!fact.owner.empty())
            return identifier_leaf(fact.owner);
        const auto separator = fact.value.find(':');
        if (separator != std::string::npos) {
            const auto candidate = identifier_leaf(fact.value.substr(0, separator));
            if (targets.find(candidate) != targets.end())
                return candidate;
        }
        return inferred_owner(fact.value, targets);
    }

    std::string owned_semantic_token(const std::string& owner,
        const std::string_view token)
    {
        return (owner.empty() ? std::string("global") : owner) + "|" +
            std::string(token);
    }

    struct semantic_projection_t
    {
        std::set<std::string, std::less<>> facts;
        std::map<std::string, double, std::less<>> confidence;
    };

    void add_semantic(semantic_projection_t& output, std::string fact,
        const double confidence)
    {
        if (fact.empty())
            return;
        output.facts.insert(fact);
        const auto found = output.confidence.find(fact);
        if (found == output.confidence.end())
            output.confidence.emplace(std::move(fact), confidence);
        else
            found->second = std::min(found->second, confidence);
    }

    double raw_confidence(const json& output, const std::string& fact)
    {
        const auto found = output.at("confidence").find(fact);
        require(found != output.at("confidence").end() && found->is_number(),
            "provider confidence lacks semantic source fact: " + fact);
        const auto value = found->get<double>();
        require(std::isfinite(value) && value >= 0.0 && value <= 1.0,
            "provider semantic source confidence is invalid");
        return value;
    }

    std::string variable_token(const owned_fact_t& fact,
        const std::set<std::string, std::less<>>& targets, const bool expected)
    {
        const auto name = variable_leaf(fact.value);
        auto owner = fact.owner.empty() ? inferred_owner(fact.value, targets) :
            identifier_leaf(fact.owner);
        if (expected && owner.empty() && targets.size() == 1U)
            owner = *targets.begin();
        return owner.empty() ? name : owner + "|" + name;
    }

    std::string call_token(const owned_fact_t& fact,
        const std::set<std::string, std::less<>>& targets)
    {
        auto edge = fact.value.find("->");
        while (edge != std::string::npos) {
            const auto caller = identifier_leaf(fact.value.substr(0, edge));
            const auto callee = identifier_leaf(fact.value.substr(edge + 2U));
            if (!caller.empty() && !callee.empty() && targets.find(caller) != targets.end())
                return caller + "->" + callee;
            edge = fact.value.find("->", edge + 2U);
        }
        const auto caller = fact.owner.empty() ?
            (targets.size() == 1U ? *targets.begin() : std::string{}) :
            identifier_leaf(fact.owner);
        const auto callee = identifier_leaf(fact.value);
        if (caller.empty() || callee.empty())
            return "unresolved-call:" + ascii_lower(fact.value);
        return caller + "->" + callee;
    }

    struct semantic_edge_t
    {
        std::string owner;
        std::string source;
        std::string target;
        bool exception = false;
    };

    std::optional<semantic_edge_t> semantic_edge(const std::string& raw,
        const std::set<std::string, std::less<>>& targets)
    {
        auto fact = decode_owned_fact(raw);
        auto delimiter = fact.value.find("=>");
        const bool explicit_exception = delimiter != std::string::npos;
        if (!explicit_exception)
            delimiter = fact.value.find("->");
        if (delimiter == std::string::npos)
            return std::nullopt;
        const auto delimiter_size = 2U;
        auto left = fact.value.substr(0, delimiter);
        auto right = fact.value.substr(delimiter + delimiter_size);
        auto owner = identifier_leaf(fact.owner);
        if (owner.empty()) {
            const auto owner_separator = left.find(':');
            if (owner_separator != std::string::npos) {
                const auto candidate = identifier_leaf(left.substr(0, owner_separator));
                if (targets.find(candidate) != targets.end()) {
                    owner = candidate;
                    left.erase(0, owner_separator + 1U);
                }
            }
            if (owner.empty() && targets.size() == 1U)
                owner = *targets.begin();
        }
        const auto source = ascii_lower(left);
        const auto target = ascii_lower(right);
        const bool named_exception = target.find("exception") != std::string::npos ||
            target.find("handler") != std::string::npos || target.find("catch") != std::string::npos;
        return semantic_edge_t{std::move(owner), source, target,
            explicit_exception || named_exception};
    }

    semantic_projection_t graph_projection(const std::set<std::string, std::less<>>& values,
        const std::set<std::string, std::less<>>& targets, const json* output)
    {
        struct graph_t
        {
            std::vector<semantic_edge_t> edges;
            double confidence = 1.0;
        };
        std::map<std::string, graph_t, std::less<>> graphs;
        for (const auto& raw : values) {
            const auto edge = semantic_edge(raw, targets);
            if (!edge)
                continue;
            if (output && !edge->owner.empty() &&
                targets.find(edge->owner) == targets.end())
                continue;
            auto& graph = graphs[edge->owner];
            graph.edges.push_back(*edge);
            if (output)
                graph.confidence = std::min(graph.confidence, raw_confidence(*output, raw));
        }
        semantic_projection_t result;
        for (const auto& [owner, graph] : graphs) {
            std::map<std::string, std::uint64_t, std::less<>> indegree;
            std::map<std::string, std::uint64_t, std::less<>> outdegree;
            std::uint64_t exception_edges = 0;
            for (const auto& edge : graph.edges) {
                ++outdegree[edge.source];
                ++indegree[edge.target];
                indegree.try_emplace(edge.source, 0);
                outdegree.try_emplace(edge.target, 0);
                if (edge.exception)
                    ++exception_edges;
            }
            const auto prefix = owner.empty() ? std::string("global|") : owner + "|";
            const auto branches = std::count_if(outdegree.begin(), outdegree.end(),
                [](const auto& value) { return value.second > 1U; });
            const auto joins = std::count_if(indegree.begin(), indegree.end(),
                [](const auto& value) { return value.second > 1U; });
            const auto exits = std::count_if(outdegree.begin(), outdegree.end(),
                [](const auto& value) { return value.second == 0U; });
            for (const auto& token : std::array<std::string, 7>{
                     prefix + "edges:" + std::to_string(graph.edges.size()),
                     prefix + "normal_edges:" + std::to_string(graph.edges.size() - exception_edges),
                     prefix + "exception_edges:" + std::to_string(exception_edges),
                     prefix + "nodes:" + std::to_string(outdegree.size()),
                     prefix + "branches:" + std::to_string(branches),
                     prefix + "joins:" + std::to_string(joins),
                     prefix + "exits:" + std::to_string(exits)})
                add_semantic(result, token, graph.confidence);
        }
        return result;
    }

    std::set<std::string, std::less<>> type_atoms(const owned_fact_t& fact)
    {
        auto value = ascii_lower(fact.value);
        std::set<std::string, std::less<>> output;
        if (value.rfind("arity:", 0) == 0) {
            output.insert(value);
            return output;
        }
        const auto open = value.find('(');
        const auto close = open == std::string::npos ? std::string::npos : value.find(')', open + 1U);
        if (open != std::string::npos && close != std::string::npos) {
            const auto parameters = value.substr(open + 1U, close - open - 1U);
            const auto arity = parameters.empty() ? 0U :
                static_cast<unsigned>(std::count(parameters.begin(), parameters.end(), ',')) + 1U;
            output.insert("arity:" + std::to_string(arity));
        }
        const auto add_type = [&output](const std::string_view token) {
            output.insert("type:" + std::string(token));
        };
        const auto contains = [&value](const std::string_view token) {
            return value.find(token) != std::string::npos;
        };
        if (contains("system.int64") || contains("int64_t") || value == "j") add_type("int64");
        else if (contains("system.int32") || contains("int32_t") || value == "i" || value == "int" || contains("int(int")) add_type("int32");
        if (contains("system.boolean") || value == "bool" || value == "z") add_type("bool");
        if (contains("system.void") || value == "void" || value == "v") add_type("void");
        if (value == "b" || contains("system.byte")) add_type("int8");
        if (value == "s" || contains("system.int16")) add_type("int16");
        if (value == "c" || contains("system.char")) add_type("char16");
        if (value == "f" || contains("system.single") || value == "float") add_type("float32");
        if (value == "d" || contains("system.double") || value == "double") add_type("float64");
        if (output.empty()) {
            const auto normalized = identifier_leaf(value);
            if (!normalized.empty())
                add_type(normalized);
        }
        return output;
    }

    std::string basename_lower(std::string value)
    {
        std::replace(value.begin(), value.end(), '\\', '/');
        const auto separator = value.find_last_of('/');
        if (separator != std::string::npos)
            value.erase(0, separator + 1U);
        return ascii_lower(std::move(value));
    }

    void add_expected_coordinate(semantic_projection_t& output, const std::string& raw,
        const std::set<std::string, std::less<>>& targets,
        const bool include_source_file)
    {
        const auto first = raw.find(':');
        const auto second = first == std::string::npos ? std::string::npos : raw.find(':', first + 1U);
        const auto third = second == std::string::npos ? std::string::npos : raw.find(':', second + 1U);
        if (first == std::string::npos || second == std::string::npos || third == std::string::npos)
            return;
        auto owner = identifier_leaf(raw.substr(0, first));
        if (targets.find(owner) == targets.end() && targets.size() == 1U)
            owner = *targets.begin();
        if (owner.empty())
            owner = "global";
        add_semantic(output, owner + "|coordinate", 1.0);
        if (include_source_file)
            add_semantic(output, owner + "|source_file:" +
                basename_lower(raw.substr(second + 1U, third - second - 1U)), 1.0);
    }

    void add_observed_coordinate(semantic_projection_t& output, const std::string& raw,
        const json& provider_output, const bool include_source_file)
    {
        const auto decoded = decode_owned_fact(raw);
        auto owner = identifier_leaf(decoded.owner);
        if (owner.empty())
            owner = "global";
        const auto confidence = raw_confidence(provider_output, raw);
        add_semantic(output, owner + "|coordinate", confidence);
        if (decoded.value.rfind("address:", 0) == 0 ||
            decoded.value.rfind("instruction:", 0) == 0 ||
            decoded.value.rfind("document:", 0) == 0)
            return;
        if (!include_source_file)
            return;
        const auto last = decoded.value.rfind(':');
        if (last == std::string::npos)
            return;
        const auto fourth = decoded.value.rfind(':', last - 1U);
        const auto third = fourth == std::string::npos ? std::string::npos :
            decoded.value.rfind(':', fourth - 1U);
        const auto second = third == std::string::npos ? std::string::npos :
            decoded.value.rfind(':', third - 1U);
        if (second == std::string::npos)
            return;
        add_semantic(output, owner + "|source_file:" +
            basename_lower(decoded.value.substr(0, second)), confidence);
    }

    semantic_projection_t project_expected(const json& truth, const std::string_view metric)
    {
        semantic_projection_t output;
        const auto targets = target_symbols(truth);
        if (metric == "typed_entities") {
            for (const auto& target : targets)
                add_semantic(output, target, 1.0);
            return output;
        }
        const auto raw = metric_facts(truth.at("facts"), metric);
        if (metric == "cfg")
            return graph_projection(raw, targets, nullptr);
        if (metric == "source_coordinates") {
            const auto architecture = truth.at("architecture_identity").get<std::string>();
            const bool include_source_file = architecture == "jvm" || architecture == "dalvik";
            for (const auto& value : raw)
                add_expected_coordinate(output, value, targets, include_source_file);
            return output;
        }
        for (const auto& value : raw) {
            const owned_fact_t fact{{}, value};
            if (metric == "calls")
                add_semantic(output, call_token(fact, targets), 1.0);
            else if (metric == "fields")
                add_semantic(output, identifier_leaf(value), 1.0);
            else if (metric == "locals" || metric == "parameters")
                add_semantic(output, variable_token(fact, targets, true), 1.0);
            else if (metric == "control_structures")
                add_semantic(output, ascii_lower(value), 1.0);
            else if (metric == "exception_regions") {
                const auto lower = ascii_lower(value);
                const auto owner = semantic_owner(fact, targets);
                if (lower.find("throw") != std::string::npos)
                    add_semantic(output, owned_semantic_token(owner, "throw"), 1.0);
                if (lower.find("catch") != std::string::npos || lower.find("exception") != std::string::npos ||
                    lower.find("->") != std::string::npos || lower.find("=>") != std::string::npos)
                    add_semantic(output, owned_semantic_token(owner, "exception_edge"), 1.0);
                if (lower.find("try") != std::string::npos)
                    add_semantic(output, owned_semantic_token(owner, "try"), 1.0);
                if (lower.find("finally") != std::string::npos)
                    add_semantic(output, owned_semantic_token(owner, "finally"), 1.0);
            } else if (metric == "type_correctness") {
                const auto owner = semantic_owner(fact, targets);
                for (const auto& atom : type_atoms(fact))
                    add_semantic(output, owned_semantic_token(owner, atom), 1.0);
            }
        }
        return output;
    }

    semantic_projection_t project_observed(const json& provider_output, const json& truth,
        const std::string_view metric)
    {
        semantic_projection_t output;
        const auto targets = target_symbols(truth);
        const auto raw = metric_facts(provider_output.at("facts"), metric);
        if (metric == "cfg")
            return graph_projection(raw, targets, &provider_output);
        if (metric == "source_coordinates") {
            const auto architecture = truth.at("architecture_identity").get<std::string>();
            const bool include_source_file = architecture == "jvm" || architecture == "dalvik";
            for (const auto& value : raw) {
                const auto decoded = decode_owned_fact(value);
                const auto owner = identifier_leaf(decoded.owner);
                if (!owner.empty() && targets.find(owner) == targets.end())
                    continue;
                add_observed_coordinate(output, value, provider_output,
                    include_source_file);
            }
            return output;
        }
        for (const auto& value : raw) {
            const auto fact = decode_owned_fact(value);
            const auto confidence = raw_confidence(provider_output, value);
            const auto owner = identifier_leaf(fact.owner);
            if (!owner.empty() && targets.find(owner) == targets.end())
                continue;
            if (metric == "typed_entities") {
                const auto entity = identifier_leaf(fact.value);
                if (targets.find(entity) != targets.end())
                    add_semantic(output, entity, confidence);
            }
            else if (metric == "calls")
                add_semantic(output, call_token(fact, targets), confidence);
            else if (metric == "fields")
                add_semantic(output, identifier_leaf(fact.value), confidence);
            else if (metric == "locals" || metric == "parameters")
                add_semantic(output, variable_token(fact, targets, false), confidence);
            else if (metric == "control_structures")
                add_semantic(output, ascii_lower(fact.value), confidence);
            else if (metric == "exception_regions") {
                const auto lower = ascii_lower(fact.value);
                const auto owner = semantic_owner(fact, targets);
                if (lower.find("throw") != std::string::npos)
                    add_semantic(output, owned_semantic_token(owner, "throw"), confidence);
                if (lower.find("catch") != std::string::npos || lower.find("exception") != std::string::npos ||
                    lower.find("->") != std::string::npos || lower.find("=>") != std::string::npos)
                    add_semantic(output, owned_semantic_token(owner, "exception_edge"), confidence);
                if (lower.find("try") != std::string::npos)
                    add_semantic(output, owned_semantic_token(owner, "try"), confidence);
                if (lower.find("finally") != std::string::npos)
                    add_semantic(output, owned_semantic_token(owner, "finally"), confidence);
            } else if (metric == "type_correctness") {
                const auto owner = semantic_owner(fact, targets);
                for (const auto& atom : type_atoms(fact))
                    add_semantic(output, owned_semantic_token(owner, atom), confidence);
            }
        }
        return output;
    }

    json normalized_ground_truth_records(const json& ground_truth)
    {
        require_closed(ground_truth, {"schema", "schema_version", "license", "target_execution_forbidden",
            "coordinate_contract", "source_files", "metric_fact_defaults", "metric_fact_overrides", "fixtures"},
            "ground truth");
        require(ground_truth.value("schema", std::string{}) == "aida.c03.corpus-ground-truth" &&
            ground_truth.value("schema_version", 0) == 1 && ground_truth.value("target_execution_forbidden", false),
            "quality ground truth identity or nonexecution contract is invalid");
        require(ground_truth.contains("metric_fact_defaults") && ground_truth.at("metric_fact_defaults").is_object() &&
            ground_truth.contains("metric_fact_overrides") && ground_truth.at("metric_fact_overrides").is_object(),
            "quality ground truth metric fact policy is absent");
        require(ground_truth.contains("source_files") && ground_truth.at("source_files").is_object() &&
            !ground_truth.at("source_files").empty(), "quality ground truth source hash inventory is absent");
        for (auto iterator = ground_truth.at("source_files").begin();
             iterator != ground_truth.at("source_files").end(); ++iterator)
            require(!iterator.key().empty() && iterator->is_string() &&
                is_canonical_sha256(iterator->get_ref<const std::string&>()),
                "quality ground truth source hash inventory is invalid");
        constexpr std::array<std::string_view, 4> supplemental_fields{
            "fields", "locals", "parameters", "exception_regions"};
        const auto& defaults = ground_truth.at("metric_fact_defaults");
        require_closed(defaults, {"fields", "locals", "parameters", "exception_regions"},
            "ground-truth metric defaults");
        for (const auto field : supplemental_fields) {
            require(defaults.contains(std::string(field)),
                "ground-truth metric defaults omit " + std::string(field));
            strings(defaults.at(std::string(field)), field);
        }
        const auto& source_records = ground_truth.at("fixtures");
        require(source_records.is_array() && !source_records.empty(), "ground truth fixtures must be a nonempty array");
        std::set<std::string, std::less<>> fixture_ids;
        for (const auto& record : source_records)
            require(fixture_ids.insert(require_text(record, "id", "ground truth")).second,
                "ground truth contains a duplicate identifier");
        for (auto iterator = ground_truth.at("metric_fact_overrides").begin();
             iterator != ground_truth.at("metric_fact_overrides").end(); ++iterator) {
            require(fixture_ids.find(iterator.key()) != fixture_ids.end(),
                "ground-truth metric override references an unknown fixture: " + iterator.key());
            require_closed(*iterator, {"fields", "locals", "parameters", "exception_regions"},
                "ground-truth metric override");
            for (const auto field : supplemental_fields) {
                require(iterator->contains(std::string(field)),
                    "ground-truth metric override omits " + std::string(field));
                strings(iterator->at(std::string(field)), field);
            }
        }
        json normalized = json::array();
        std::map<std::string, std::set<std::string, std::less<>>, std::less<>> aggregate;
        std::set<std::string, std::less<>> referenced_sources;
        for (const auto metric : k_metrics)
            aggregate.emplace(std::string(metric), std::set<std::string, std::less<>>{});
        for (const auto& record : source_records) {
            json normalized_record = record;
            const auto source = require_text(normalized_record, "source", "ground truth");
            require(ground_truth.at("source_files").contains(source),
                "ground-truth fixture references an unbound source file");
            referenced_sources.insert(source);
            auto& facts = normalized_record.at("facts");
            require_closed(facts, {"entities", "cfg_edges", "calls", "fields", "locals", "parameters", "types",
                "symbols", "control_structures", "exception_regions", "source_coordinates", "explicit_unknowns"},
                "ground-truth facts");
            const auto id = record.at("id").get<std::string>();
            const auto override = ground_truth.at("metric_fact_overrides").find(id);
            for (const auto field : supplemental_fields) {
                if (!facts.contains(std::string(field)))
                    facts[std::string(field)] = override == ground_truth.at("metric_fact_overrides").end() ?
                        defaults.at(std::string(field)) : override->at(std::string(field));
            }
            require(facts.contains("explicit_unknowns"), "ground-truth facts omit explicit_unknowns");
            strings(facts.at("explicit_unknowns"), "explicit_unknowns");
            for (const auto metric : k_metrics) {
                const auto values = metric_facts(facts, metric);
                aggregate.at(std::string(metric)).insert(values.begin(), values.end());
            }
            normalized.push_back(std::move(normalized_record));
        }
        for (const auto metric : k_metrics)
            require(!aggregate.at(std::string(metric)).empty(),
                "ground-truth corpus has no positive facts for metric: " + std::string(metric));
        require(referenced_sources.size() == ground_truth.at("source_files").size(),
            "ground-truth source hash inventory contains an unreferenced source file");
        return normalized;
    }

    json score_metric(const std::set<std::string, std::less<>>& expected,
        const std::set<std::string, std::less<>>& observed, std::string_view provenance_id,
        const json& confidence, const std::set<std::string, std::less<>>& explicit_unknowns)
    {
        std::uint64_t tp = 0;
        for (const auto& value : observed) {
            if (expected.find(value) != expected.end())
                ++tp;
        }
        const auto fp = static_cast<std::uint64_t>(observed.size()) - tp;
        const auto fn = static_cast<std::uint64_t>(expected.size()) - tp;
        const bool verified_empty = tp == 0 && fp == 0 && fn == 0;
        const double precision = verified_empty ? 1.0 :
            (tp + fp == 0 ? 0.0 : static_cast<double>(tp) / static_cast<double>(tp + fp));
        const double recall = verified_empty ? 1.0 :
            (tp + fn == 0 ? 0.0 : static_cast<double>(tp) / static_cast<double>(tp + fn));
        const double f1 = precision + recall == 0.0 ? 0.0 : 2.0 * precision * recall / (precision + recall);
        std::vector<double> known_confidence;
        for (const auto& fact : observed) {
            const auto found = confidence.find(fact);
            require(found != confidence.end() && found->is_number(), "observed fact lacks confidence evidence: " + fact);
            const double value = found->get<double>();
            require(std::isfinite(value) && value >= 0.0 && value <= 1.0,
                "observed fact confidence is not a finite ratio");
            known_confidence.push_back(value);
        }
        const auto known_observation_count = known_confidence.size();
        double confidence_sum = 0.0;
        double minimum_confidence = 1.0;
        for (const auto value : known_confidence) {
            confidence_sum += value;
            minimum_confidence = std::min(minimum_confidence, value);
        }
        json unknown_ids = json::array();
        for (const auto& unknown : explicit_unknowns)
            unknown_ids.push_back(unknown);
        const auto observations = static_cast<std::uint64_t>(known_observation_count + explicit_unknowns.size());
        return {{"tp", tp}, {"fp", fp}, {"fn", fn}, {"precision", precision}, {"recall", recall}, {"f1", f1},
            {"provenance_ids", json::array({std::string(provenance_id)})},
            {"confidence", {{"observation_count", observations},
                {"known_observations", known_observation_count},
                {"explicit_unknown_observations", explicit_unknowns.size()}, {"implicit_unknown_observations", 0},
                {"confidence_sum", confidence_sum}, {"mean_confidence", known_observation_count == 0 ? 1.0 :
                    confidence_sum / static_cast<double>(known_observation_count)},
                {"minimum_confidence", minimum_confidence},
                {"explicit_unknown_ratio", observations == 0 ? 0.0 :
                    static_cast<double>(explicit_unknowns.size()) / static_cast<double>(observations)},
                {"explicit_unknown_ids", std::move(unknown_ids)},
                {"provenance_ids", json::array({std::string(provenance_id)})}}}};
    }

    struct provider_score_t
    {
        std::string provider;
        std::string build_hash;
        std::string build_binding_id;
        std::string result_binding_id;
        std::string result_hash;
        std::string runtime_manifest_binding_id;
        std::string spec_manifest_binding_id;
        json worker_bindings;
        json metrics;
        json readability;
        json diagnostics;
        json determinism_runs;
        json cancellation;
        json identity;
    };

    std::vector<std::uint8_t> decode_hex_payload(std::string_view payload)
    {
        require(!payload.empty() && payload.size() % 2 == 0,
            "raw provider artifact hex payload is empty or odd-sized");
        const auto nibble = [](const char value) -> std::uint8_t {
            if (value >= '0' && value <= '9')
                return static_cast<std::uint8_t>(value - '0');
            if (value >= 'a' && value <= 'f')
                return static_cast<std::uint8_t>(value - 'a' + 10);
            throw scorer_error_t("raw provider artifact contains non-canonical hex");
        };
        std::vector<std::uint8_t> bytes(payload.size() / 2U);
        for (std::size_t index = 0; index < bytes.size(); ++index)
            bytes[index] = static_cast<std::uint8_t>(
                (nibble(payload[index * 2U]) << 4U) | nibble(payload[index * 2U + 1U]));
        return bytes;
    }

    std::string validate_raw_artifact(const json& artifact, std::string_view label)
    {
        require(artifact.is_object(), std::string(label) + " raw artifact is absent");
        require_closed(artifact, {"encoding", "sha256", "byte_size", "payload"}, label);
        require(artifact.value("encoding", std::string{}) == "hex" &&
            artifact.contains("sha256") && artifact.at("sha256").is_string() &&
            is_canonical_sha256(artifact.at("sha256").get_ref<const std::string&>()) &&
            artifact.contains("byte_size") && artifact.at("byte_size").is_number_unsigned() &&
            artifact.at("byte_size").get<std::uint64_t>() != 0 &&
            artifact.at("byte_size").get<std::uint64_t>() <= 128ULL * 1024ULL * 1024ULL &&
            artifact.contains("payload") && artifact.at("payload").is_string(),
            std::string(label) + " raw artifact contract is invalid");
        const auto& payload = artifact.at("payload").get_ref<const std::string&>();
        const auto expected_size = artifact.at("byte_size").get<std::uint64_t>();
        require(expected_size <= std::numeric_limits<std::size_t>::max() / 2U &&
            payload.size() == static_cast<std::size_t>(expected_size) * 2U,
            std::string(label) + " raw artifact byte count differs from its hex payload");
        const auto bytes = decode_hex_payload(payload);
        const auto hash = sha256_evidence_bytes(bytes.data(), bytes.size());
        require(hash.ok, hash.error);
        require(hash.sha256 == artifact.at("sha256").get<std::string>(),
            std::string(label) + " raw artifact hash differs from its payload");
        return hash.sha256;
    }

    std::uint64_t read_bundle_u64(const std::vector<std::uint8_t>& bytes,
        std::size_t& offset, std::string_view label)
    {
        require(offset <= bytes.size() && bytes.size() - offset >= 8U,
            std::string(label) + " canonical bundle is truncated");
        std::uint64_t value = 0;
        for (std::uint32_t shift = 0; shift < 64U; shift += 8U)
            value |= static_cast<std::uint64_t>(bytes[offset++]) << shift;
        return value;
    }

    std::string canonical_bundle_hash(const json& artifact, std::string_view label)
    {
        const auto payload = decode_hex_payload(artifact.at("payload").get_ref<const std::string&>());
        constexpr std::string_view magic = "AIDA-C03-CANONICAL-BUNDLE-V2";
        require(payload.size() >= magic.size() + 8U &&
            std::equal(magic.begin(), magic.end(), payload.begin()),
            std::string(label) + " raw artifact is not a canonical provider bundle");
        std::size_t offset = magic.size();
        const auto count = read_bundle_u64(payload, offset, label);
        require(count != 0 && count <= 4096U,
            std::string(label) + " canonical bundle record count is invalid");
        std::vector<std::string> record_hashes;
        record_hashes.reserve(static_cast<std::size_t>(count));
        for (std::uint64_t index = 0; index < count; ++index) {
            const auto size = read_bundle_u64(payload, offset, label);
            require(size != 0 && size <= payload.size() - offset,
                std::string(label) + " canonical bundle record extent is invalid");
            const auto hash = sha256_evidence_bytes(payload.data() + offset,
                static_cast<std::size_t>(size));
            require(hash.ok, hash.error);
            record_hashes.push_back(hash.sha256);
            offset += static_cast<std::size_t>(size);
        }
        require(offset == payload.size(),
            std::string(label) + " canonical bundle contains trailing data");
        std::sort(record_hashes.begin(), record_hashes.end());
        const auto hash = canonical_json_sha256(json(record_hashes));
        require(hash.ok, hash.error);
        return hash.sha256;
    }

    json canonical_diagnostics(const json& diagnostics)
    {
        require(diagnostics.is_array(), "provider diagnostics must be an array");
        std::vector<std::pair<std::string, json>> rows;
        rows.reserve(diagnostics.size());
        for (const auto& diagnostic : diagnostics)
            rows.emplace_back(diagnostic.dump(), diagnostic);
        std::sort(rows.begin(), rows.end(), [](const auto& left, const auto& right) {
            return left.first < right.first;
        });
        json output = json::array();
        for (auto& row : rows)
            output.push_back(std::move(row.second));
        return output;
    }

    void validate_execution_witness(const json& value, std::string_view label)
    {
        require(value.is_object() && value.contains("execution_witness_sha256") &&
            value.at("execution_witness_sha256").is_string() &&
            is_canonical_sha256(value.at("execution_witness_sha256").get_ref<const std::string&>()),
            std::string(label) + " execution witness is absent");
        const auto expected = canonical_json_sha256(value, "execution_witness_sha256");
        require(expected.ok, expected.error);
        require(expected.sha256 == value.at("execution_witness_sha256").get<std::string>(),
            std::string(label) + " execution witness hash is invalid");
    }

    bool managed_only_fixture(const json& truth)
    {
        const auto architecture = truth.at("architecture_identity").get<std::string>();
        const auto format = truth.at("format").get<std::string>();
        return architecture == "jvm" || architecture == "dalvik" || format == "cli";
    }

    bool artifact_required(std::string_view provider, std::string_view artifact)
    {
        if (provider == "aida_typed_pipeline")
            return artifact != "printc";
        if (provider == "ghidra_printc")
            return true;
        return artifact == "ast" || artifact == "document";
    }

    provider_score_t score_provider(const json& provider, const binding_map_t& bindings,
        const std::filesystem::path& evidence_root,
        const std::map<std::string, json, std::less<>>& truth,
        const std::map<std::string, json, std::less<>>& materialized,
        const std::set<std::string, std::less<>>& selected_ids,
        std::string_view manifest_hash, std::string_view recipes_hash,
        std::string_view ground_truth_hash, std::string_view materialization_receipt_hash,
        std::string_view fixture_set_hash)
    {
        require_closed(provider, {"provider", "status", "status_reason", "identity", "corpus",
            "fixtures", "cancellation", "launch_audit", "build_binding_id", "result_binding_id",
            "worker_bindings", "runtime_manifest_binding_id", "spec_manifest_binding_id"},
            "provider run");
        provider_score_t score;
        score.provider = require_text(provider, "provider", "provider run");
        score.build_binding_id = require_text(provider, "build_binding_id", "provider run");
        score.result_binding_id = require_text(provider, "result_binding_id", "provider run");
        const auto& build = binding(bindings, score.build_binding_id);
        const auto& results = binding(bindings, score.result_binding_id);
        require(build.request.kind == "provider_build" &&
            results.request.kind == "provider_results", "provider build, manifest, or result binding kind mismatch");
        require(score.build_binding_id != score.result_binding_id,
            "provider build and result binding identifiers overlap");
        score.build_hash = build.sha256;
        score.result_hash = results.sha256;
        std::set<std::string, std::less<>> forbidden_artifact_hashes;
        for (const auto& pair : bindings) {
            if (pair.second.request.kind == "corpus_ground_truth" ||
                pair.second.request.kind == "materialization_receipt" ||
                pair.second.request.kind == "source_ground_truth" ||
                pair.second.request.kind == "materialized_artifact") {
                forbidden_artifact_hashes.insert(pair.second.sha256);
                require(pair.second.sha256 != score.result_hash,
                    "provider result file collides with source, ground-truth, or artifact evidence");
            }
        }
        const auto result_evidence = load_bound_json(evidence_root, results);
        const auto provider_validation = validate_decompiler_provider_results(result_evidence);
        require(provider_validation.valid, provider_validation.summary());
        require(result_evidence.at("measurement_eligible").get<bool>() &&
            result_evidence.at("provider_run").at("status") == "measured",
            "nonmeasurement provider evidence cannot produce a quality receipt");
        json bound_run = provider;
        bound_run.erase("build_binding_id");
        bound_run.erase("result_binding_id");
        bound_run.erase("worker_bindings");
        bound_run.erase("runtime_manifest_binding_id");
        bound_run.erase("spec_manifest_binding_id");
        if (result_evidence.at("provider_run").contains("build_binding_id") ||
            result_evidence.at("provider_run").contains("result_binding_id") ||
            result_evidence.at("provider_run").contains("worker_bindings") ||
            result_evidence.at("provider_run").contains("runtime_manifest_binding_id") ||
            result_evidence.at("provider_run").contains("spec_manifest_binding_id"))
            require(false, "provider result file must not inject receipt binding identifiers");
        require(result_evidence.at("provider_run") == bound_run,
            "provider run differs from its hash-bound result evidence");
        score.identity = provider.at("identity");
        require(score.identity.at("provider_build_sha256") == score.build_hash,
            "provider build identity differs from its executable binding");
        const auto runtime_binding_id = require_text(provider, "runtime_manifest_binding_id", "provider run");
        const auto spec_binding_id = require_text(provider, "spec_manifest_binding_id", "provider run");
        score.runtime_manifest_binding_id = runtime_binding_id;
        score.spec_manifest_binding_id = spec_binding_id;
        score.worker_bindings = provider.at("worker_bindings");
        const auto& runtime_binding = binding(bindings, runtime_binding_id);
        const auto& spec_binding = binding(bindings, spec_binding_id);
        require(runtime_binding.request.kind == "runtime_manifest" &&
            spec_binding.request.kind == "spec_manifest" &&
            score.identity.at("runtime_manifest_sha256") == runtime_binding.sha256 &&
            score.identity.at("spec_manifest_sha256") == spec_binding.sha256,
            "provider runtime or specification identity differs from its file binding");
        require(provider.contains("worker_bindings") && provider.at("worker_bindings").is_array(),
            "provider worker bindings are absent");
        std::map<std::string, std::pair<std::string, std::string>, std::less<>> identity_workers;
        for (const auto& worker : score.identity.at("workers")) {
            const auto role = worker.at("role").get<std::string>();
            require(identity_workers.emplace(role, std::pair{
                worker.at("binary_sha256").get<std::string>(),
                worker.at("manifest_sha256").get<std::string>()}).second,
                "provider identity repeats a worker role");
        }
        if (score.provider == "aida_typed_pipeline")
            require(identity_workers.size() == 2 &&
                identity_workers.find("native") != identity_workers.end() &&
                identity_workers.find("managed") != identity_workers.end(),
                "typed pipeline identity must bind both production workers");
        else if (score.provider == "ghidra_printc")
            require(identity_workers.size() == 1 &&
                identity_workers.find("native") != identity_workers.end(),
                "Ghidra PrintC identity must bind only the native worker");
        else
            require(identity_workers.empty(),
                "current AiDA in-process baseline must not claim a worker identity");
        std::set<std::string, std::less<>> worker_binding_roles;
        for (const auto& worker : provider.at("worker_bindings")) {
            require_closed(worker, {"role", "binary_binding_id", "manifest_binding_id"},
                "provider worker binding");
            const auto role = require_text(worker, "role", "provider worker binding");
            const auto binary_id = require_text(worker, "binary_binding_id", "provider worker binding");
            const auto worker_manifest_id = require_text(worker, "manifest_binding_id", "provider worker binding");
            require(worker_binding_roles.insert(role).second,
                "provider worker binding role is duplicated");
            const auto found = identity_workers.find(role);
            require(found != identity_workers.end(), "provider worker binding has no identity row");
            const auto& binary = binding(bindings, binary_id);
            const auto& worker_manifest = binding(bindings, worker_manifest_id);
            require(binary.request.kind == "worker_binary" &&
                worker_manifest.request.kind == "worker_manifest" &&
                found->second.first == binary.sha256 &&
                found->second.second == worker_manifest.sha256,
                "provider worker identity differs from its executable or manifest binding");
        }
        require(worker_binding_roles.size() == identity_workers.size(),
            "provider worker binding set is incomplete");
        const auto& corpus = provider.at("corpus");
        require(require_text(corpus, "manifest_sha256", "provider corpus") ==
                std::string(manifest_hash) &&
            require_text(corpus, "recipes_sha256", "provider corpus") ==
                std::string(recipes_hash) &&
            require_text(corpus, "ground_truth_sha256", "provider corpus") ==
                std::string(ground_truth_hash) &&
            require_text(corpus, "materialization_receipt_sha256", "provider corpus") ==
                std::string(materialization_receipt_hash) &&
            require_text(corpus, "fixture_set_sha256", "provider corpus") ==
                std::string(fixture_set_hash),
            "provider corpus identity differs from the scored immutable corpus");
        const auto& fixtures = provider.at("fixtures");
        require(fixtures.is_array() && fixtures.size() == selected_ids.size(),
            "provider fixture result cardinality differs from corpus selection");
        std::map<std::string, json, std::less<>> outputs;
        std::array<json, 2> deterministic_outputs{json::array(), json::array()};
        std::array<json, 2> deterministic_source_maps{json::array(), json::array()};
        std::array<std::set<std::string, std::less<>>, 2> deterministic_schedules;
        std::array<std::set<std::string, std::less<>>, 2> deterministic_cache_states;
        std::set<std::string, std::less<>> run_ids;
        std::uint64_t unsupported = 0;
        for (const auto& fixture : fixtures) {
            const auto id = require_text(fixture, "id", "provider fixture result");
            require(selected_ids.find(id) != selected_ids.end(), "provider returned an unselected fixture");
            const auto& expected = truth.at(id);
            const auto& artifact = materialized.at(id);
            require(fixture.at("artifact_sha256") == artifact.at("artifact_sha256") &&
                fixture.at("artifact_size") == artifact.at("size_bytes") &&
                fixture.at("format") == expected.at("format") &&
                fixture.at("architecture") == expected.at("architecture_identity") &&
                fixture.at("mode") == expected.at("mode") && fixture.at("endian") == expected.at("endian"),
                "provider fixture identity differs from the materialized corpus");
            const bool required = score.provider == "aida_typed_pipeline" ||
                !managed_only_fixture(expected);
            const auto fixture_status = fixture.at("status").get<std::string>();
            if (!required) {
                require(fixture_status == "not_applicable" && fixture.at("runs").empty(),
                    "native baseline must explicitly mark managed-only fixtures not applicable");
                ++unsupported;
                require(outputs.emplace(id, json()).second,
                    "provider fixture result identifier is duplicated");
                for (std::size_t run_index = 0; run_index < 2; ++run_index) {
                    deterministic_outputs[run_index].push_back(
                        {{"id", id}, {"status", "not_applicable"}});
                    deterministic_source_maps[run_index].push_back(
                        {{"id", id}, {"source_coordinates", json::array()}});
                }
                continue;
            }
            require(fixture_status == "measured" && fixture.at("runs").size() == 2,
                "required provider fixture lacks two measured production runs");
            std::array<std::string, 2> output_hashes;
            std::array<std::string, 2> source_hashes;
            for (std::size_t run_index = 0; run_index < 2; ++run_index) {
                const auto& measured_run = fixture.at("runs")[run_index];
                const auto run_id = require_text(measured_run, "run_id", "provider measured run");
                require(run_ids.insert(run_id).second, "provider run identifier is duplicated");
                const auto started = measured_run.at("started_tick_ns").get<std::uint64_t>();
                const auto ended = measured_run.at("ended_tick_ns").get<std::uint64_t>();
                const auto duration = measured_run.at("duration_ns").get<std::uint64_t>();
                require(ended > started && ended - started == duration,
                    "provider run timing is non-monotonic or self-inconsistent");
                const auto schedule = require_text(measured_run, "schedule", "provider measured run");
                const auto cache_state = require_text(measured_run, "cache_state", "provider measured run");
                deterministic_schedules[run_index].insert(schedule);
                deterministic_cache_states[run_index].insert(cache_state);
                validate_execution_witness(measured_run, "provider measured run");
                const auto& artifacts = measured_run.at("artifacts");
                json canonical_artifacts = json::object();
                for (const std::string_view artifact_name : {"provider_ir", "hir", "type_graph",
                         "ast", "document", "printc"}) {
                    const auto& raw = artifacts.at(std::string(artifact_name));
                    if (artifact_required(score.provider, artifact_name)) {
                        const auto artifact_hash = validate_raw_artifact(raw, artifact_name);
                        require(forbidden_artifact_hashes.find(artifact_hash) ==
                                forbidden_artifact_hashes.end(),
                            "raw provider stage copies source, ground-truth, receipt, or target-artifact evidence");
                        canonical_artifacts[std::string(artifact_name)] =
                            canonical_bundle_hash(raw, artifact_name);
                    } else {
                        require(raw.is_null(), "provider emitted a raw artifact outside its measured contract");
                        canonical_artifacts[std::string(artifact_name)] = nullptr;
                    }
                }
                json deterministic = {{"outcome", measured_run.at("outcome")},
                    {"canonical_artifacts", std::move(canonical_artifacts)},
                    {"facts", measured_run.at("facts")},
                    {"confidence", measured_run.at("confidence")},
                    {"explicit_unknowns", measured_run.at("explicit_unknowns")},
                    {"readability", measured_run.at("readability")},
                    {"diagnostics", canonical_diagnostics(measured_run.at("diagnostics"))}};
                const auto output_hash = canonical_json_sha256(deterministic);
                require(output_hash.ok, output_hash.error);
                output_hashes[run_index] = output_hash.sha256;
                const auto source_hash = canonical_json_sha256(
                    measured_run.at("facts").at("source_coordinates"));
                require(source_hash.ok, source_hash.error);
                source_hashes[run_index] = source_hash.sha256;
                deterministic_outputs[run_index].push_back(
                    {{"id", id}, {"output_sha256", output_hash.sha256}});
                deterministic_source_maps[run_index].push_back(
                    {{"id", id}, {"source_coordinates_sha256", source_hash.sha256}});
            }
            require(fixture.at("runs")[0].at("run_id") != fixture.at("runs")[1].at("run_id") &&
                fixture.at("runs")[0].at("execution_witness_sha256") !=
                    fixture.at("runs")[1].at("execution_witness_sha256") &&
                fixture.at("runs")[0].at("started_tick_ns") != fixture.at("runs")[1].at("started_tick_ns"),
                "determinism runs do not contain distinct execution witnesses");
            require(output_hashes[0] == output_hashes[1] && source_hashes[0] == source_hashes[1],
                "provider output is nondeterministic across cache-bypassed runs");
            require(outputs.emplace(id, fixture.at("runs")[0]).second,
                "provider fixture result identifier is duplicated");
        }
        for (const auto& id : selected_ids)
            require(outputs.find(id) != outputs.end(), "provider omitted selected fixture: " + id);
        for (std::size_t run_index = 0; run_index < 2; ++run_index) {
            require(deterministic_schedules[run_index].size() == 1U &&
                deterministic_cache_states[run_index].size() == 1U,
                "provider determinism run does not use one corpus-wide schedule and cache state");
        }
        require(*deterministic_schedules[0].begin() != *deterministic_schedules[1].begin() ||
            *deterministic_cache_states[0].begin() != *deterministic_cache_states[1].begin(),
            "provider determinism runs do not vary schedule or cache state");
        json metrics = json::object();
        for (const auto metric : k_metrics) {
            std::set<std::string, std::less<>> expected;
            std::set<std::string, std::less<>> observed;
            std::set<std::string, std::less<>> unknowns;
            json confidence = json::object();
            for (const auto& id : selected_ids) {
                const auto& expected_record = truth.at(id);
                const auto& output = outputs.at(id);
                const auto expected_semantics = project_expected(expected_record, metric);
                if (supplemental_metric(metric) && expected_semantics.facts.empty())
                    continue;
                for (const auto& fact : expected_semantics.facts)
                    expected.insert(id + "\n" + fact);
                if (output.is_null())
                    continue;
                const auto observed_semantics = project_observed(output, expected_record, metric);
                for (const auto& fact : observed_semantics.facts) {
                    const auto scoped = id + "\n" + fact;
                    observed.insert(scoped);
                    const auto found = observed_semantics.confidence.find(fact);
                    require(found != observed_semantics.confidence.end(),
                        "semantic provider fact lacks confidence: " + fact);
                    confidence[scoped] = found->second;
                }
                for (const auto& unknown : metric_unknowns(output.at("explicit_unknowns"), metric))
                    unknowns.insert(id + "\n" + unknown);
            }
            metrics[std::string(metric)] = score_metric(expected, observed,
                score.provider + ":" + std::string(metric), confidence, unknowns);
        }
        std::uint64_t declarations = 0;
        std::uint64_t maximum_expression_depth = 0;
        std::uint64_t maximum_control_nesting = 0;
        std::uint64_t placeholders = 0;
        std::uint64_t casts = 0;
        std::uint64_t fabricated = 0;
        std::uint64_t symbol_count = 0;
        std::uint64_t named_symbols = 0;
        std::uint64_t success = 0;
        json diagnostics = json::array();
        for (const auto& pair : outputs) {
            if (pair.second.is_null())
                continue;
            const auto& readability = pair.second.at("readability");
            require_closed(readability, {"declaration_count", "max_expression_depth", "max_control_nesting",
                "dead_placeholder_count", "cast_count", "fabricated_body_count", "symbol_count", "named_symbol_count"},
                "provider readability");
            for (const auto field : {"declaration_count", "max_expression_depth", "max_control_nesting",
                     "dead_placeholder_count", "cast_count", "fabricated_body_count", "symbol_count", "named_symbol_count"})
                require(readability.contains(field) && readability.at(field).is_number_unsigned(),
                    std::string("provider readability requires unsigned ") + field);
            add_count(declarations, readability.at("declaration_count").get<std::uint64_t>(), "declaration");
            maximum_expression_depth = std::max(maximum_expression_depth,
                readability.at("max_expression_depth").get<std::uint64_t>());
            maximum_control_nesting = std::max(maximum_control_nesting,
                readability.at("max_control_nesting").get<std::uint64_t>());
            add_count(placeholders, readability.at("dead_placeholder_count").get<std::uint64_t>(), "placeholder");
            add_count(casts, readability.at("cast_count").get<std::uint64_t>(), "cast");
            const auto fabricated_bodies = readability.at("fabricated_body_count").get<std::uint64_t>();
            require(fabricated_bodies == 0, "provider returned a fabricated pseudocode body");
            add_count(fabricated, fabricated_bodies, "fabricated body");
            const auto fixture_symbols = readability.at("symbol_count").get<std::uint64_t>();
            const auto fixture_named_symbols = readability.at("named_symbol_count").get<std::uint64_t>();
            require(fixture_named_symbols <= fixture_symbols, "named symbol count exceeds fixture symbol count");
            add_count(symbol_count, fixture_symbols, "symbol");
            add_count(named_symbols, fixture_named_symbols, "named symbol");
            for (const auto& diagnostic : pair.second.at("diagnostics"))
                diagnostics.push_back(diagnostic);
            ++success;
        }
        score.metrics = std::move(metrics);
        score.readability = {{"declaration_count", declarations},
            {"naming_consistency_ratio", symbol_count == 0 ? 1.0 : static_cast<double>(named_symbols) / symbol_count},
            {"max_expression_depth", maximum_expression_depth}, {"max_control_nesting", maximum_control_nesting},
            {"dead_placeholder_count", placeholders}, {"cast_count", casts}, {"fabricated_body_count", fabricated}};
        score.diagnostics = {{"summary", {{"provider_crash", 0}, {"timeout", 0}, {"unsupported", unsupported},
                {"cancelled", 0}, {"success", success}}}, {"events", std::move(diagnostics)}};
        require(provider.contains("cancellation") && provider.at("cancellation").is_object(),
            "provider cancellation evidence is absent");
        const auto& cancellation = provider.at("cancellation");
        require(cancellation.at("status") == "measured" &&
            cancellation.at("outcome") == "cancelled",
            "provider cancellation was not actually observed");
        const auto cancellation_started = cancellation.at("started_tick_ns").get<std::uint64_t>();
        const auto cancellation_requested = cancellation.at("cancel_requested_tick_ns").get<std::uint64_t>();
        const auto cancellation_ended = cancellation.at("ended_tick_ns").get<std::uint64_t>();
        const auto cancellation_latency = cancellation.at("latency_ns").get<std::uint64_t>();
        require(cancellation_started <= cancellation_requested &&
            cancellation_requested <= cancellation_ended &&
            cancellation_ended - cancellation_requested == cancellation_latency &&
            cancellation_latency <= 250ULL * 1000ULL * 1000ULL,
            "provider cancellation timing is non-monotonic, self-inconsistent, or above 250 ms");
        validate_execution_witness(cancellation, "provider cancellation");
        score.cancellation = {{"requested", true}, {"completed_jobs", 0},
            {"cancelled_jobs", 1},
            {"p95_ms", static_cast<double>(cancellation_latency) / 1'000'000.0}};
        score.diagnostics["cancellation"] = score.cancellation;
        score.determinism_runs = json::array();
        for (std::size_t run_index = 0; run_index < 2; ++run_index) {
            const auto output_hash = canonical_json_sha256(deterministic_outputs[run_index]);
            const auto source_hash = canonical_json_sha256(deterministic_source_maps[run_index]);
            require(output_hash.ok && source_hash.ok,
                output_hash.ok ? source_hash.error : output_hash.error);
            score.determinism_runs.push_back({{"run_id", score.provider + "-run-" +
                    std::to_string(run_index + 1U)},
                {"schedule", *deterministic_schedules[run_index].begin()},
                {"cache_state", *deterministic_cache_states[run_index].begin()},
                {"normalized_ast_sha256", output_hash.sha256},
                {"source_map_sha256", source_hash.sha256}, {"outcome", "success"}});
        }
        std::set<std::string, std::less<>> launch_hashes;
        std::set<std::string, std::less<>> artifact_hashes;
        for (const auto& pair : materialized)
            artifact_hashes.insert(pair.second.at("artifact_sha256").get<std::string>());
        for (const auto& launch : provider.at("launch_audit")) {
            const auto hash = launch.at("image_sha256").get<std::string>();
            require(artifact_hashes.find(hash) == artifact_hashes.end(),
                "provider launch audit contains an analyzed artifact");
            require(std::any_of(identity_workers.begin(), identity_workers.end(),
                [&hash](const auto& worker) { return worker.second.first == hash; }),
                "provider launch audit contains an identity-unbound executable");
            require(launch_hashes.insert(hash).second,
                "provider launch audit contains a duplicate executable");
        }
        for (const auto& worker : identity_workers)
            require(launch_hashes.find(worker.second.first) != launch_hashes.end(),
                "provider worker identity lacks an observed launch audit row");
        return score;
    }

    double f1(const provider_score_t& score, std::string_view metric)
    {
        return score.metrics.at(std::string(metric)).at("f1").get<double>();
    }
}

decompiler_quality_score_result_t score_decompiler_quality(
    const decompiler_quality_score_request_t& request)
{
    try {
        require(!request.authorization_id.empty() && !request.receipt_id.empty() && !request.run_id.empty() &&
            !request.started_utc.empty() && !request.ended_utc.empty() && !request.candidate_provider.empty() &&
            !request.harness_binding_id.empty() && !request.scorer_binding_id.empty() &&
            !request.corpus_manifest_binding_id.empty() && !request.recipes_binding_id.empty() &&
            !request.ground_truth_binding_id.empty() && !request.materialization_receipt_binding_id.empty(),
            "quality scoring request identity is incomplete");
        const auto corpus_validation = validate_corpus_manifest(request.corpus_manifest);
        require(corpus_validation.valid, corpus_validation.summary());
        require(request.ground_truth.is_object() && request.ground_truth.value("schema", std::string{}) ==
            "aida.c03.corpus-ground-truth" && request.ground_truth.value("target_execution_forbidden", false),
            "quality ground truth is invalid or permits target execution");
        require(request.materialization_receipt.is_object() &&
            request.materialization_receipt.value("target_execution_forbidden", false),
            "quality materialization evidence is absent or permits target execution");
        const auto bindings = bind_files(request);
        const auto& harness_binding = binding(bindings, request.harness_binding_id);
        const auto& scorer_binding = binding(bindings, request.scorer_binding_id);
        const auto& manifest_binding = binding(bindings, request.corpus_manifest_binding_id);
        const auto& recipes_binding = binding(bindings, request.recipes_binding_id);
        const auto& ground_truth_binding = binding(bindings, request.ground_truth_binding_id);
        const auto& materialization_binding = binding(bindings, request.materialization_receipt_binding_id);
        require(harness_binding.request.kind == "harness_build" && scorer_binding.request.kind == "scorer_build" &&
            manifest_binding.request.kind == "corpus_manifest" && recipes_binding.request.kind == "corpus_recipes" &&
            ground_truth_binding.request.kind == "corpus_ground_truth" &&
            materialization_binding.request.kind == "materialization_receipt",
            "quality core evidence binding kind mismatch");
        require(load_bound_json(request.evidence_root, manifest_binding) == request.corpus_manifest,
            "loaded corpus manifest differs from its evidence binding");
        require(load_bound_json(request.evidence_root, recipes_binding) == request.recipes,
            "loaded corpus recipes differ from their evidence binding");
        require(load_bound_json(request.evidence_root, ground_truth_binding) == request.ground_truth,
            "loaded ground truth differs from its evidence binding");
        require(load_bound_json(request.evidence_root, materialization_binding) == request.materialization_receipt,
            "loaded materialization receipt differs from its evidence binding");
        const auto materialization_validation = validate_materialization_receipt(request.materialization_receipt,
            request.corpus_manifest, request.recipes, request.ground_truth, request.evidence_root / "artifacts");
        require(materialization_validation.valid, materialization_validation.summary());
        const auto truth = index_by_id(normalized_ground_truth_records(request.ground_truth), "ground truth");
        std::map<std::string, json, std::less<>> materialized;
        std::set<std::string, std::less<>> selected_ids;
        json corpus_rows = json::array();
        for (const auto& fixture : request.materialization_receipt.at("fixtures")) {
            const auto id = require_text(fixture, "id", "materialization fixture");
            require(truth.find(id) != truth.end(), "materialized fixture lacks ground truth");
            require(materialized.emplace(id, fixture).second, "materialization fixture is duplicated");
            selected_ids.insert(id);
            const auto artifact_binding_id = "artifact:" + id;
            const auto& artifact_binding = binding(bindings, artifact_binding_id);
            require(artifact_binding.request.kind == "materialized_artifact", "artifact evidence binding kind mismatch");
            require(artifact_binding.sha256 == fixture.at("artifact_sha256").get<std::string>(),
                "materialized artifact hash differs from evidence binding");
            const auto source_binding_id = "source:" + id;
            const auto& source_binding = binding(bindings, source_binding_id);
            require(source_binding.request.kind == "source_ground_truth", "source evidence binding kind mismatch");
            const auto source_path = truth.at(id).at("source").get<std::string>();
            require(request.ground_truth.at("source_files").at(source_path) == source_binding.sha256,
                "source evidence binding differs from the ground-truth source hash inventory");
            const auto truth_hash = canonical_json_sha256(truth.at(id).at("facts"));
            require(truth_hash.ok, truth_hash.error);
            corpus_rows.push_back({{"id", id}, {"artifact_sha256", artifact_binding.sha256},
                {"source_provenance_sha256", source_binding.sha256}, {"semantic_facts_sha256", truth_hash.sha256},
                {"artifact_binding_id", artifact_binding_id}, {"source_binding_id", source_binding_id},
                {"format", truth.at(id).at("format")}, {"architecture", truth.at(id).at("architecture_identity")},
                {"mode", truth.at(id).at("mode")}, {"endian", truth.at(id).at("endian")}});
        }
        require(selected_ids.size() == truth.size(), "quality corpus selection does not cover every ground-truth fixture");
        const auto provider_fixture_set_hash = canonical_json_sha256(
            request.materialization_receipt.at("fixtures"));
        require(provider_fixture_set_hash.ok, provider_fixture_set_hash.error);
        require(request.provider_runs.is_array() && request.provider_runs.size() == 3,
            "quality scoring requires candidate, Ghidra PrintC, and current AiDA provider runs");
        std::map<std::string, provider_score_t, std::less<>> provider_scores;
        for (const auto& provider : request.provider_runs) {
            auto score = score_provider(provider, bindings, request.evidence_root, truth,
                materialized, selected_ids, manifest_binding.sha256, recipes_binding.sha256,
                ground_truth_binding.sha256,
                request.materialization_receipt.at("receipt_sha256").get<std::string>(),
                provider_fixture_set_hash.sha256);
            require(provider_scores.emplace(score.provider, std::move(score)).second,
                "provider quality run is duplicated");
        }
        const auto candidate = provider_scores.find(request.candidate_provider);
        const auto printc = provider_scores.find("ghidra_printc");
        const auto current = provider_scores.find("aida_current");
        require(candidate != provider_scores.end() && printc != provider_scores.end() && current != provider_scores.end(),
            "required quality provider run is absent");
        require(candidate->second.identity.at("protocol_sha256") ==
                printc->second.identity.at("protocol_sha256") &&
            candidate->second.identity.at("protocol_sha256") ==
                current->second.identity.at("protocol_sha256"),
            "quality providers do not bind the same production protocol identity");
        json file_bindings = json::array();
        for (const auto& pair : bindings)
            file_bindings.push_back({{"id", pair.first}, {"kind", pair.second.request.kind},
                {"path", pair.second.request.relative_path}, {"sha256", pair.second.sha256},
                {"max_bytes", pair.second.request.maximum_bytes}});
        json provider_builds = json::array();
        for (const auto& pair : provider_scores) {
            json workers = json::array();
            for (const auto& worker_binding : pair.second.worker_bindings) {
                const auto role = worker_binding.at("role").get<std::string>();
                const auto identity = std::find_if(pair.second.identity.at("workers").begin(),
                    pair.second.identity.at("workers").end(), [&role](const json& worker) {
                        return worker.at("role").get<std::string>() == role;
                    });
                require(identity != pair.second.identity.at("workers").end(),
                    "provider receipt worker binding lacks an identity");
                workers.push_back({{"role", role},
                    {"binary_sha256", identity->at("binary_sha256")},
                    {"manifest_sha256", identity->at("manifest_sha256")},
                    {"binary_binding_id", worker_binding.at("binary_binding_id")},
                    {"manifest_binding_id", worker_binding.at("manifest_binding_id")}});
            }
            provider_builds.push_back({{"provider", pair.first},
                {"build_sha256", pair.second.build_hash},
                {"build_binding_id", pair.second.build_binding_id},
                {"workers", std::move(workers)},
                {"runtime_manifest_sha256", pair.second.identity.at("runtime_manifest_sha256")},
                {"runtime_manifest_binding_id", pair.second.runtime_manifest_binding_id},
                {"spec_manifest_sha256", pair.second.identity.at("spec_manifest_sha256")},
                {"spec_manifest_binding_id", pair.second.spec_manifest_binding_id},
                {"protocol_sha256", pair.second.identity.at("protocol_sha256")},
                {"result_sha256", pair.second.result_hash},
                {"result_binding_id", pair.second.result_binding_id}});
        }
        const auto fixture_set_hash = canonical_json_sha256(corpus_rows);
        require(fixture_set_hash.ok, fixture_set_hash.error);
        json required_formats = request.corpus_manifest.at("required_coverage").at("formats");
        json required_architectures = request.corpus_manifest.at("required_coverage").at("architectures");
        json matrix_rows = json::array();
        for (const auto& row : corpus_rows)
            matrix_rows.push_back({{"fixture_id", row.at("id")}, {"format", row.at("format")},
                {"architecture", row.at("architecture")}, {"mode", row.at("mode")}, {"endian", row.at("endian")}});
        json baseline = json::object();
        for (const auto& pair : std::array<std::pair<std::string_view, const provider_score_t*>, 2>{
                 std::pair<std::string_view, const provider_score_t*>{"ghidra_printc", &printc->second},
                 {"aida_current", &current->second}}) {
            json deltas = json::object();
            for (const auto metric : k_metrics) {
                const double baseline_value = f1(*pair.second, metric);
                const double current_value = f1(candidate->second, metric);
                deltas[std::string(metric)] = {{"baseline_f1", baseline_value}, {"current_f1", current_value},
                    {"delta", current_value - baseline_value}};
            }
            baseline[std::string(pair.first)] = {{"provider", std::string(pair.first)},
                {"provider_build_sha256", pair.second->build_hash}, {"same_fixture_set", true},
                {"fixture_set_sha256", fixture_set_hash.sha256}, {"metric_deltas", std::move(deltas)}};
        }
        json claims = json::array();
        for (const auto metric : k_metrics) {
            claims.push_back({{"id", "objective-" + std::string(metric)}, {"metric_id", std::string(metric)},
                {"actual", f1(candidate->second, metric)},
                {"threshold", decompiler_quality_thresholds().at("metric_f1_min").at(std::string(metric))},
                {"comparator", "gte"},
                {"evidence_ids", json::array({request.candidate_provider + ":" + std::string(metric)})}});
        }
        json receipt = {{"schema", "aida.c03.decompiler-quality-receipt"}, {"schema_version", 2},
            {"receipt_id", request.receipt_id},
            {"provenance", {{"authorization_id", request.authorization_id},
                {"harness_build_sha256", harness_binding.sha256}, {"scorer_build_sha256", scorer_binding.sha256},
                {"corpus_manifest_sha256", manifest_binding.sha256}, {"recipes_sha256", recipes_binding.sha256},
                {"ground_truth_sha256", ground_truth_binding.sha256},
                {"materialization_receipt_sha256", materialization_binding.sha256},
                {"harness_binding_id", request.harness_binding_id}, {"scorer_binding_id", request.scorer_binding_id},
                {"corpus_manifest_binding_id", request.corpus_manifest_binding_id},
                {"recipes_binding_id", request.recipes_binding_id},
                {"ground_truth_binding_id", request.ground_truth_binding_id},
                {"materialization_receipt_binding_id", request.materialization_receipt_binding_id},
                {"evidence_bindings", std::move(file_bindings)}, {"provider_builds", std::move(provider_builds)}}},
            {"corpus", {{"manifest_sha256", manifest_binding.sha256}, {"fixture_set_sha256", fixture_set_hash.sha256},
                {"fixtures", std::move(corpus_rows)}}},
            {"matrix", {{"required_formats", required_formats}, {"observed_formats", required_formats},
                {"required_architectures", required_architectures}, {"observed_architectures", required_architectures},
                {"fixture_matrix", std::move(matrix_rows)}}},
            {"execution", {{"run_id", request.run_id}, {"started_utc", request.started_utc},
                {"ended_utc", request.ended_utc}, {"schedule", "bounded_provider_matrix"},
                {"cache_state", "explicit_disclosed"}, {"target_execution_forbidden", true}}},
            {"metrics", candidate->second.metrics}, {"readability", candidate->second.readability},
            {"determinism", {{"canonicalization_version", "typed-pseudocode-ast-v2"},
                {"runs", candidate->second.determinism_runs}}}, {"baseline", std::move(baseline)},
            {"thresholds", decompiler_quality_thresholds()}, {"diagnostics", candidate->second.diagnostics},
            {"failures", json::array()}, {"claims", std::move(claims)}, {"receipt_sha256", ""}};
        const auto receipt_hash = canonical_json_sha256(receipt, "receipt_sha256");
        require(receipt_hash.ok, receipt_hash.error);
        receipt["receipt_sha256"] = receipt_hash.sha256;
        auto validation = validate_decompiler_quality_receipt_files(receipt, request.evidence_root);
        decompiler_quality_score_result_t output;
        output.ok = validation.valid;
        output.error = validation.valid ? std::string{} : validation.summary();
        output.receipt = std::move(receipt);
        output.validation = std::move(validation);
        return output;
    } catch (const std::exception& error) {
        decompiler_quality_score_result_t output;
        output.error = error.what();
        output.validation.reject("", "scorer_failure", error.what());
        return output;
    }
}
}
