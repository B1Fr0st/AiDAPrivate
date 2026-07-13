#include "stack_handlers_harness.hpp"

#include "../../src/core/analysis/workspace/calling_convention.hpp"
#include "../../src/core/mcp/compat/effect_policy.hpp"
#include "../../src/core/mcp/compat/handlers/stack.hpp"
#include "../../src/core/mcp/compat/ida_contracts_generated.hpp"
#include "../../src/core/mcp/compat/target_resolver.hpp"
#include "../../src/core/mcp/compat/workspace_adapter.hpp"
#include "../../src/core/mcp/protocol/mcp_tool_contract.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <limits>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace aida::standalone::tests::mcp_compat {

namespace {

using namespace aida::standalone::mcp::compat;
using namespace aida::standalone::mcp::compat::handlers;
using protocol::cancellation_token_t;
using protocol::json;

void require(bool condition, std::string_view message) {
    if (!condition) {
        throw std::runtime_error(std::string(message));
    }
}

void require_fixture(bool condition, std::string_view tool, std::string_view category,
                     std::string_view detail) {
    if (!condition) {
        throw std::runtime_error(
            std::string(tool) + " " + std::string(category) + " fixture: " +
            std::string(detail));
    }
}

std::string_view provenance_name(analysis::fact_provenance_t value) noexcept {
    using analysis::fact_provenance_t;
    switch (value) {
    case fact_provenance_t::unknown: return "unknown";
    case fact_provenance_t::gap_recovery: return "gap_recovery";
    case fact_provenance_t::linear_validation: return "linear_validation";
    case fact_provenance_t::recursive_decode: return "recursive_decode";
    case fact_provenance_t::relocation: return "relocation";
    case fact_provenance_t::call_target: return "call_target";
    case fact_provenance_t::export_entry: return "export_entry";
    case fact_provenance_t::tls_entry: return "tls_entry";
    case fact_provenance_t::image_entry: return "image_entry";
    case fact_provenance_t::unwind_metadata: return "unwind_metadata";
    case fact_provenance_t::debug_symbol: return "debug_symbol";
    case fact_provenance_t::user_definition: return "user_definition";
    case fact_provenance_t::decompiler_feedback: return "decompiler_feedback";
    }
    return "unknown";
}

std::string_view slot_kind_name(analysis::stack_slot_kind_t value) noexcept {
    using analysis::stack_slot_kind_t;
    switch (value) {
    case stack_slot_kind_t::unknown: return "unknown";
    case stack_slot_kind_t::argument: return "argument";
    case stack_slot_kind_t::local: return "local";
    case stack_slot_kind_t::spill: return "spill";
    case stack_slot_kind_t::saved_register: return "saved_register";
    case stack_slot_kind_t::outgoing_argument: return "outgoing_argument";
    }
    return "unknown";
}

std::uint64_t fixture_type_size(std::string_view type) noexcept {
    if (type == "char" || type == "bool" || type == "uint8_t") return 1U;
    if (type == "short" || type == "uint16_t") return 2U;
    if (type == "int" || type == "unsigned int" || type == "uint32_t") return 4U;
    if (type == "long long" || type == "uint64_t" || type == "void*" ||
        type == "char*") return 8U;
    if (type == "char[16]") return 16U;
    if (type == "char[32]") return 32U;
    if (type == "char[256]") return 256U;
    return 1U;
}

std::string fixture_hex(std::uint64_t value) {
    std::array<char, 32> buffer{};
    const auto formatted = std::to_chars(
        buffer.data(), buffer.data() + buffer.size(), value, 16);
    if (formatted.ec != std::errc{}) {
        throw std::runtime_error("stack fixture address formatting failed");
    }
    std::string result = "0x";
    result.append(buffer.data(), formatted.ptr);
    return result;
}

struct typed_slot_fixture_t final {
    analysis::stack_slot_t slot;
    std::optional<std::string> name;
    std::optional<std::string> type;
    std::string source = "inferred";
};

typed_slot_fixture_t make_slot(
    std::int64_t offset, std::uint64_t size,
    std::optional<std::string> name = std::nullopt,
    std::optional<std::string> type = std::nullopt,
    std::string source = "inferred",
    analysis::fact_provenance_t provenance =
        analysis::fact_provenance_t::recursive_decode,
    std::uint8_t confidence = 80U,
    analysis::stack_slot_kind_t kind = analysis::stack_slot_kind_t::local) {
    typed_slot_fixture_t result;
    result.slot.offset = offset;
    result.slot.size = size;
    result.slot.base_reg = 5U;
    const std::uint64_t maximum_width =
        (std::numeric_limits<std::uint16_t>::max)();
    result.slot.access_width_bits = static_cast<std::uint16_t>(
        size > maximum_width / 8U ? maximum_width : size * 8U);
    result.slot.kind = kind;
    result.slot.provenance = provenance;
    result.slot.confidence = confidence;
    result.slot.is_argument = kind == analysis::stack_slot_kind_t::argument;
    result.slot.is_spill = kind == analysis::stack_slot_kind_t::spill;
    result.slot.is_local = kind == analysis::stack_slot_kind_t::local;
    result.slot.is_saved_register = kind == analysis::stack_slot_kind_t::saved_register;
    result.slot.read = true;
    result.slot.written = kind != analysis::stack_slot_kind_t::argument;
    result.name = std::move(name);
    result.type = std::move(type);
    result.source = std::move(source);
    return result;
}

struct frame_fixture_t final {
    analysis::stack_frame_info_t frame;
    std::vector<typed_slot_fixture_t> slots;
    std::uint8_t confidence = 88U;
};

struct overlay_snapshot_t final {
    std::unordered_map<std::string, frame_fixture_t> frames;
};

class typed_stack_store_t final {
public:
    void clear() {
        frames_.clear();
        missing_.clear();
        history_.clear();
        analysis_revision_ = 3U;
        overlay_revision_ = 7U;
        transaction_id_ = 40U;
    }

    void seed_frame(std::string address, std::vector<typed_slot_fixture_t> slots,
                    std::uint8_t confidence = 88U) {
        frame_fixture_t frame;
        frame.confidence = confidence;
        frame.frame.frame_size = 0x100U;
        frame.frame.observed_stack_extent = 0x100U;
        frame.frame.frame_size_known = true;
        frame.frame.stack_pointer_reg = 4U;
        frame.frame.frame_pointer_reg = 5U;
        frame.frame.uses_frame_pointer = true;
        frame.frame.prologue_end_rva = 0x10U;
        frame.frame.epilogue_start_rva = 0x80U;
        frame.slots = std::move(slots);
        sync_slots(frame);
        frames_[std::move(address)] = std::move(frame);
    }

    void mark_missing(std::string address) {
        missing_.insert(std::move(address));
    }

    bool is_missing(std::string_view address) const {
        return missing_.find(std::string(address)) != missing_.end();
    }

    std::uint64_t overlay_revision() const noexcept {
        return overlay_revision_;
    }

    std::size_t history_size() const noexcept {
        return history_.size();
    }

    std::size_t named_slot_count(std::string_view address) const {
        const auto found = frames_.find(std::string(address));
        if (found == frames_.end()) return 0U;
        return static_cast<std::size_t>(std::count_if(
            found->second.slots.begin(), found->second.slots.end(),
            [](const typed_slot_fixture_t& slot) { return slot.name.has_value(); }));
    }

    bool has_named_slot(std::string_view address, std::string_view name) const {
        const auto found = frames_.find(std::string(address));
        if (found == frames_.end()) return false;
        return std::any_of(
            found->second.slots.begin(), found->second.slots.end(),
            [name](const typed_slot_fixture_t& slot) {
                return slot.name && *slot.name == name;
            });
    }

    json query_frame(std::string_view address) const {
        const auto found = frames_.find(std::string(address));
        const frame_fixture_t* frame = found == frames_.end() ? &empty_frame_ : &found->second;
        json slots = json::array();
        for (const auto& record : frame->slots) {
            json slot{
                {"offset", record.slot.offset},
                {"size", record.slot.size},
                {"base_reg", record.slot.base_reg},
                {"access_width_bits", record.slot.access_width_bits},
                {"kind", record.source == "declared"
                    ? std::string("declared")
                    : std::string(slot_kind_name(record.slot.kind))},
                {"provenance", std::string(provenance_name(record.slot.provenance))},
                {"confidence", record.slot.confidence},
                {"is_argument", record.slot.is_argument},
                {"is_spill", record.slot.is_spill},
                {"is_local", record.slot.is_local},
                {"is_saved_register", record.slot.is_saved_register},
                {"read", record.slot.read},
                {"written", record.slot.written},
                {"source", record.source},
            };
            if (record.name) slot["name"] = *record.name;
            if (record.type) slot["type"] = *record.type;
            slots.push_back(std::move(slot));
        }
        json saved_registers = json::array();
        for (const auto& record : frame->frame.preserved_registers) {
            saved_registers.push_back({
                {"reg", record.reg},
                {"saved", record.saved},
                {"restored", record.restored},
                {"save_address", fixture_hex(record.save_rva)},
                {"restore_address", fixture_hex(record.restore_rva)},
                {"provenance", std::string(provenance_name(record.provenance))},
                {"confidence", record.confidence},
            });
        }
        json output{
            {"function", std::string(address)},
            {"state", "inferred"},
            {"abi", static_cast<std::uint64_t>(analysis::cc_abi_t::windows_x64)},
            {"confidence", frame->confidence},
            {"frame_size", frame->frame.frame_size},
            {"frame_size_known", frame->frame.frame_size_known},
            {"observed_stack_extent", frame->frame.observed_stack_extent},
            {"stack_pointer_reg", frame->frame.stack_pointer_reg},
            {"frame_pointer_reg", frame->frame.frame_pointer_reg},
            {"uses_frame_pointer", frame->frame.uses_frame_pointer},
            {"has_shadow_space", frame->frame.has_shadow_space},
            {"shadow_space_size", frame->frame.shadow_space_size},
            {"prologue_end", "0x10"},
            {"epilogue_start", "0x80"},
            {"slots", std::move(slots)},
            {"slot_count", frame->slots.size()},
            {"saved_registers", std::move(saved_registers)},
            {"saved_register_count", frame->frame.preserved_registers.size()},
            {"bounded", true},
            {"instructions_analyzed", 64U},
        };
        output["_meta"]["aida"] = {
            {"adapter", "ida_compat_read"},
            {"analysis_revision", analysis_revision_},
            {"overlay_revision", overlay_revision_},
            {"target_kind", "static"},
            {"pid", nullptr},
        };
        return output;
    }

    json transact(std::string_view tool, const json& arguments,
                  bool live_write, bool target_file_write,
                  bool non_overlapping) {
        const std::uint64_t revision_before = overlay_revision_;
        history_.push_back({frames_});
        const auto& items = arguments.at("items");
        for (const auto& item : items) {
            const std::string address = item.at("address").get<std::string>();
            const std::int64_t offset = item.at("offset").get<std::int64_t>();
            auto& frame = frames_[address];
            if (tool == "declare_stack") {
                const std::string name = item.at("name").get<std::string>();
                const std::string type = item.at("type").get<std::string>();
                auto existing = std::find_if(
                    frame.slots.begin(), frame.slots.end(),
                    [offset](const typed_slot_fixture_t& slot) {
                        return slot.slot.offset == offset;
                    });
                if (existing != frame.slots.end()) {
                    existing->name = name;
                    existing->type = type;
                    existing->source = existing->source == "inferred"
                        ? "inferred_and_declared"
                        : "declared";
                } else {
                    frame.slots.push_back(make_slot(
                        offset, fixture_type_size(type), name, type, "declared",
                        analysis::fact_provenance_t::user_definition, 100U,
                        analysis::stack_slot_kind_t::unknown));
                }
            } else {
                auto existing = std::find_if(
                    frame.slots.begin(), frame.slots.end(),
                    [offset](const typed_slot_fixture_t& slot) {
                        return slot.slot.offset == offset && slot.name.has_value();
                    });
                if (existing != frame.slots.end()) {
                    if (existing->source == "inferred_and_declared") {
                        existing->name.reset();
                        existing->type.reset();
                        existing->source = "inferred";
                    } else {
                        frame.slots.erase(existing);
                    }
                }
            }
            sync_slots(frame);
        }
        ++overlay_revision_;
        ++transaction_id_;
        json item_receipts = json::array();
        for (std::size_t index = 0; index < items.size(); ++index) {
            item_receipts.push_back({
                {"index", index},
                {"success", true},
                {"operation_index", index},
                {"entity_key", "stack:" + std::to_string(index)},
                {"removes_value", tool == "delete_stack"},
            });
        }
        json provenance{
            {"adapter", "ida_compat_mut"},
            {"tool", std::string(tool)},
            {"read_only", false},
            {"mutation_mode", "reversible_overlay"},
            {"target_binding", "workspace_request_context"},
            {"target_selector_supplied", false},
            {"ui_switched", false},
            {"target_kind", "static_file"},
            {"live_write", live_write},
            {"analysis_revision", analysis_revision_},
            {"overlay_revision", revision_before},
        };
        if (target_file_write) provenance["target_file_write"] = true;
        if (!non_overlapping) provenance["non_overlapping"] = false;
        return {
            {"committed", true},
            {"dry_run", false},
            {"item_count", items.size()},
            {"items", std::move(item_receipts)},
            {"revision", overlay_revision_},
            {"transaction_id", transaction_id_},
            {"idempotent_replay", false},
            {"operations", items.size()},
            {"_meta", {{"aida", std::move(provenance)}}},
        };
    }

    bool undo_last() {
        if (history_.empty()) return false;
        frames_ = std::move(history_.back().frames);
        history_.pop_back();
        ++overlay_revision_;
        return true;
    }

private:
    static void sync_slots(frame_fixture_t& frame) {
        frame.frame.slots.clear();
        frame.frame.slots.reserve(frame.slots.size());
        for (const auto& slot : frame.slots) frame.frame.slots.push_back(slot.slot);
    }

    frame_fixture_t empty_frame_{};
    std::unordered_map<std::string, frame_fixture_t> frames_;
    std::unordered_set<std::string> missing_;
    std::vector<overlay_snapshot_t> history_;
    std::uint64_t analysis_revision_ = 3U;
    std::uint64_t overlay_revision_ = 7U;
    std::uint64_t transaction_id_ = 40U;
};

const adapters::stack_adapter_t k_stack_adapters[k_stack_tool_count] = {
    &adapters::stack_frame,
    &adapters::declare_stack,
    &adapters::delete_stack,
};

struct backend_state_t final {
    std::size_t query_calls = 0;
    std::size_t overlay_calls = 0;
    std::string last_contract;
    std::string last_lane;
    json last_arguments = json::object();
    std::vector<json> query_arguments;
    std::vector<json> overlay_arguments;
    std::uint32_t last_pid = 0;
    std::optional<std::uint64_t> last_expected_generation;
    bool saw_deadline = false;
    bool invalid_output = false;
    bool invalid_confidence = false;
    bool receipt_live_write = false;
    bool receipt_target_file_write = false;
    bool receipt_non_overlapping = true;
    std::size_t live_writes = 0;
    std::size_t target_file_writes = 0;
    std::shared_ptr<std::atomic_bool> cancel_during_dispatch;
    typed_stack_store_t store;

    void clear_observations() {
        query_arguments.clear();
        overlay_arguments.clear();
        last_arguments = json::object();
    }

    void prepare_standard(std::string_view tool) {
        store.clear();
        clear_observations();
        invalid_output = false;
        invalid_confidence = false;
        receipt_live_write = false;
        receipt_target_file_write = false;
        receipt_non_overlapping = true;
        if (tool == "delete_stack") {
            store.seed_frame("0x140001200", {
                make_slot(-0x20, 4U, std::string("var_20"), std::string("int"),
                          "declared", analysis::fact_provenance_t::user_definition, 100U,
                          analysis::stack_slot_kind_t::unknown),
            });
        }
    }

    adapter_result_t<adapter_response_t> respond(
        std::string_view lane, const adapter_call_context_t& context,
        const adapter_request_t& request) {
        if (lane == "query") ++query_calls;
        else ++overlay_calls;
        last_lane = std::string(lane);
        last_contract = context.contract == nullptr
            ? std::string()
            : std::string(context.contract->name);
        last_pid = context.target ? context.target->target().pid : 0U;
        last_expected_generation = request.expected_generation;
        saw_deadline = request.deadline &&
            *request.deadline > std::chrono::steady_clock::now();
        last_arguments = json::parse(request.payload, nullptr, false);
        if (lane == "query") query_arguments.push_back(last_arguments);
        else overlay_arguments.push_back(last_arguments);
        if (cancel_during_dispatch) {
            cancel_during_dispatch->store(true, std::memory_order_release);
        }
        if (invalid_output) {
            return adapter_result_t<adapter_response_t>::success({json::array().dump(), false});
        }
        if (context.contract == nullptr || last_arguments.is_discarded() ||
            !last_arguments.is_object()) {
            return adapter_result_t<adapter_response_t>::failure(
                {adapter_error_code_t::backend_rejected,
                 "fixture_request_invalid", 0U, 0U});
        }
        if (lane == "query") {
            if (context.contract->name != "stack_frame" ||
                !last_arguments.contains("address") ||
                !last_arguments.at("address").is_string() ||
                last_arguments.value("include_saved_regs", false) != true) {
                return adapter_result_t<adapter_response_t>::failure(
                    {adapter_error_code_t::backend_rejected,
                     "fixture_typed_query_required", 0U, 0U});
            }
            const std::string address = last_arguments.at("address").get<std::string>();
            if (store.is_missing(address)) {
                return adapter_result_t<adapter_response_t>::failure(
                    {adapter_error_code_t::backend_rejected,
                     "stack_frame_not_found", 0U, 0U});
            }
            json output = store.query_frame(address);
            if (invalid_confidence) output["confidence"] = 101U;
            return adapter_result_t<adapter_response_t>::success({output.dump(), false});
        }
        if (context.contract->name != "declare_stack" &&
            context.contract->name != "delete_stack") {
            return adapter_result_t<adapter_response_t>::failure(
                {adapter_error_code_t::backend_rejected,
                 "fixture_overlay_contract_invalid", 0U, 0U});
        }
        if (!last_arguments.contains("items") ||
            !last_arguments.at("items").is_array() ||
            !last_arguments.contains("aida_tx") ||
            !last_arguments.at("aida_tx").is_object() ||
            last_arguments.at("aida_tx").value(
                "expected_revision", (std::numeric_limits<std::uint64_t>::max)()) !=
                store.overlay_revision()) {
            return adapter_result_t<adapter_response_t>::failure(
                {adapter_error_code_t::backend_rejected,
                 "fixture_overlay_revision_stale", store.overlay_revision(), 0U});
        }
        json output = store.transact(
            context.contract->name, last_arguments,
            receipt_live_write, receipt_target_file_write,
            receipt_non_overlapping);
        return adapter_result_t<adapter_response_t>::success({output.dump(), false});
    }
};

target_record_t make_target(std::uint64_t target_id, std::uint32_t pid,
                            std::uint64_t creation_identity, std::string name,
                            std::uint64_t generation = 9U) {
    target_record_t target;
    target.target_id = target_id;
    target.pid = pid;
    target.process_creation_identity = creation_identity;
    target.bin_name = std::move(name);
    target.generation = generation;
    target.attach_generation = 0x109U;
    target.revision = 1U;
    return target;
}

json routed(json arguments) {
    arguments["pid"] = 4101;
    return arguments;
}

stack_invocation_options_t matching_options() {
    stack_invocation_options_t options;
    options.expected_generation = 9U;
    return options;
}

json make_valid_args(std::string_view tool) {
    if (tool == "stack_frame") {
        return routed({{"addrs", "0x140001000"}});
    }
    if (tool == "declare_stack") {
        return routed({{"items", json{{"addr", "0x140001100"},
                                        {"offset", "-0x20"},
                                        {"name", "var_20"},
                                        {"ty", "int"}}}});
    }
    return routed({{"items", json{{"addr", "0x140001200"},
                                    {"name", "var_20"}}}});
}

json make_boundary_args(std::string_view tool, const stack_handler_limits_t& limits) {
    if (tool == "stack_frame") {
        json addrs = json::array();
        for (std::size_t index = 0; index < limits.max_addrs; ++index) {
            addrs.push_back("0x140010000");
        }
        return routed({{"addrs", std::move(addrs)}});
    }
    json items = json::array();
    if (tool == "declare_stack") {
        for (std::size_t index = 0; index < limits.max_batch_items; ++index) {
            items.push_back({
                {"addr", "0x140020000"},
                {"offset", std::to_string(-4096LL - static_cast<std::int64_t>(index * 8U))},
                {"name", "v" + std::to_string(index)},
                {"ty", "int"},
            });
        }
    } else {
        for (std::size_t index = 0; index < limits.max_batch_items; ++index) {
            items.push_back({
                {"addr", "0x140030000"},
                {"name", "v" + std::to_string(index)},
            });
        }
    }
    return routed({{"items", std::move(items)}});
}

json make_invalid_args(std::string_view tool, const stack_handler_limits_t& limits) {
    json values = json::array();
    const std::size_t maximum = tool == "stack_frame"
        ? limits.max_addrs
        : limits.max_batch_items;
    for (std::size_t index = 0; index <= maximum; ++index) {
        if (tool == "stack_frame") values.push_back("0x140001000");
        else if (tool == "declare_stack") {
            values.push_back({
                {"addr", "0x140001000"}, {"offset", "-0x10"},
                {"name", "v"}, {"ty", "int"},
            });
        } else {
            values.push_back({{"addr", "0x140001000"}, {"name", "v"}});
        }
    }
    return tool == "stack_frame"
        ? routed({{"addrs", std::move(values)}})
        : routed({{"items", std::move(values)}});
}

void verify_contracts(const stack_handlers_t& handlers,
                      protocol::schema_runtime_t& schemas) {
    require(handlers.size() == k_stack_tool_count,
            "stack handler contract count is not exactly three");
    require(stack_tool_names().size() == k_stack_tool_count,
            "stack name ledger count is not exactly three");
    std::unordered_set<std::string> unique_names;
    for (std::size_t index = 0; index < k_stack_tool_count; ++index) {
        const auto name = stack_tool_names()[index];
        const auto* descriptor = find_contract(name);
        const auto& contract = handlers.contract_at(index);
        require(descriptor != nullptr, "stack generated descriptor is missing");
        require(contract.name == name && handlers.find(name) == &contract,
                "stack handler lookup differs from the exact name ledger");
        require(unique_names.emplace(contract.name).second,
                "stack handler name ledger contains a duplicate");
        require(descriptor->adapter_symbol ==
                    "aida::standalone::mcp::compat::adapters::" + std::string(name),
                "stack generated adapter symbol differs from the linked function name");
        require(contract.description == descriptor->description &&
                    contract.input_schema == json::parse(
                        descriptor->input_schema_json.begin(),
                        descriptor->input_schema_json.end()) &&
                    contract.output_schema == json::parse(
                        descriptor->output_schema_json.begin(),
                        descriptor->output_schema_json.end()) &&
                    contract.annotations == json::parse(
                        descriptor->annotations_json.begin(),
                        descriptor->annotations_json.end()),
                "stack generated descriptor data was not preserved exactly");
        require(contract.target_policy.requirement ==
                    protocol::target_requirement_t::optional &&
                    contract.target_policy.accepts_pid &&
                    contract.target_policy.accepts_bin_name,
                "stack target policy differs from the generated contract");
        if (name == "stack_frame") {
            require(contract.effect_policy.effect ==
                        protocol::tool_effect_t::workspace_read &&
                        contract.effect_policy.lock ==
                        protocol::effect_lock_t::workspace_shared &&
                        contract.effect_policy.read_only && !contract.effect_policy.unsafe,
                    "stack_frame effect policy is not a shared workspace read");
        } else {
            require(contract.effect_policy.effect ==
                        protocol::tool_effect_t::workspace_overlay_mutation &&
                        contract.effect_policy.lock ==
                        protocol::effect_lock_t::workspace_overlay_transaction &&
                        !contract.effect_policy.read_only && !contract.effect_policy.unsafe,
                    "stack mutation effect policy is not a reversible overlay transaction");
        }
        require(protocol::validate_tool_contract(contract, schemas).valid,
                "stack generated contract fails schema runtime validation");
        const json list_entry = contract.tool_list_entry();
        require(list_entry.at("inputSchema") == contract.input_schema &&
                    list_entry.at("outputSchema") == contract.output_schema &&
                    !list_entry.contains("_meta"),
                "stack tool-list schema or metadata separation changed");
    }
}

std::size_t total_backend_calls(const backend_state_t& backend) {
    return backend.query_calls + backend.overlay_calls;
}

void verify_standard_fixture(std::string_view tool,
                             adapters::stack_adapter_t adapter,
                             const stack_handlers_t& handlers,
                             backend_state_t& backend,
                             std::size_t& completed) {
    backend.prepare_standard(tool);
    const json metadata{{"fixture_tool", std::string(tool)}};
    const auto options = matching_options();
    const json valid = make_valid_args(tool);

    std::size_t before = total_backend_calls(backend);
    auto result = adapter(
        handlers, valid, cancellation_token_t::create(), options, metadata);
    require_fixture(!result.is_error(), tool, "valid", result.text());
    require_fixture(total_backend_calls(backend) > before,
                    tool, "valid", "typed backend was not invoked");
    require_fixture(backend.last_contract == tool, tool, "valid",
                    "request reached the wrong production stack contract");
    require_fixture(backend.last_pid == 4101 && backend.saw_deadline &&
                        backend.last_expected_generation == options.expected_generation,
                    tool, "valid",
                    "target, deadline, or expected generation was not forwarded");
    require_fixture(result.structured_content().is_object() &&
                        !result.structured_content().contains("_meta") &&
                        result.aida_metadata().value("tool", std::string()) == tool,
                    tool, "valid", "generated output and trusted metadata were not separated");
    if (tool == "stack_frame") {
        require_fixture(backend.last_lane == "query" &&
                            backend.last_arguments == json{{"address", "0x140001000"},
                                                           {"include_saved_regs", true}},
                        tool, "valid", "generated query was not normalized to production shape");
    } else {
        require_fixture(backend.last_lane == "overlay" &&
                            backend.last_arguments.at("items").is_array() &&
                            backend.last_arguments.at("aida_tx").contains("expected_revision"),
                        tool, "valid", "mutation was not normalized to a revision-bound overlay");
    }
    ++completed;

    const json boundary = make_boundary_args(tool, handlers.limits());
    before = total_backend_calls(backend);
    result = adapter(
        handlers, boundary, cancellation_token_t::create(), options, metadata);
    require_fixture(!result.is_error(), tool, "boundary", result.text());
    require_fixture(total_backend_calls(backend) > before,
                    tool, "boundary", "pinned maximum did not reach typed preflight");
    ++completed;

    const json invalid = make_invalid_args(tool, handlers.limits());
    before = total_backend_calls(backend);
    result = adapter(
        handlers, invalid, cancellation_token_t::create(), options, metadata);
    require_fixture(result.is_error() &&
                        result.error_code() == "MCP_TOOL_INPUT_INVALID",
                    tool, "invalid", "over-limit input was not rejected canonically");
    require_fixture(total_backend_calls(backend) == before,
                    tool, "invalid", "invalid input reached the backend");
    require_fixture(
        result.structured_content().at("error").at("details").value(
            "policy", std::string()) == "bounded_stack_adapter",
        tool, "invalid", "bounded stack diagnostics are absent");
    ++completed;

    json ambiguous = valid;
    ambiguous.erase("pid");
    ambiguous["bin_name"] = "fixture";
    before = total_backend_calls(backend);
    result = adapter(
        handlers, ambiguous, cancellation_token_t::create(), options, metadata);
    require_fixture(result.is_error() &&
                        result.error_code() == "MCP_TOOL_TARGET_POLICY_REJECTED",
                    tool, "ambiguous_target",
                    "ambiguous binary selector was not rejected canonically");
    require_fixture(total_backend_calls(backend) == before,
                    tool, "ambiguous_target", "ambiguous target reached the backend");
    ++completed;

    auto cancellation = cancellation_token_t::create();
    backend.cancel_during_dispatch = cancellation.state();
    before = total_backend_calls(backend);
    result = adapter(handlers, valid, cancellation, options, metadata);
    backend.cancel_during_dispatch.reset();
    require_fixture(result.is_error() &&
                        result.error_code() == "MCP_TOOL_CANCELLED",
                    tool, "cancellation", "in-flight cancellation was not observed");
    require_fixture(total_backend_calls(backend) > before,
                    tool, "cancellation", "cancellation did not exercise the backend window");
    ++completed;

    backend.invalid_output = true;
    before = total_backend_calls(backend);
    result = adapter(
        handlers, valid, cancellation_token_t::create(), options, metadata);
    backend.invalid_output = false;
    require_fixture(result.is_error() &&
                        result.error_code() == "MCP_TOOL_OUTPUT_INVALID",
                    tool, "output_validation",
                    "untyped backend output was not rejected canonically");
    require_fixture(total_backend_calls(backend) > before,
                    tool, "output_validation", "invalid-output fixture missed the backend");
    ++completed;
}

void verify_generated_compatibility(stack_handlers_t& handlers,
                                    backend_state_t& backend,
                                    std::size_t& completed) {
    backend.store.clear();
    backend.clear_observations();
    backend.store.seed_frame("0x140040000", {
        make_slot(-8, 8U, std::string("saved_rbp"), std::string("void*"),
                  "inferred_and_declared", analysis::fact_provenance_t::debug_symbol,
                  84U, analysis::stack_slot_kind_t::saved_register),
    });
    const auto options = matching_options();
    const json metadata{{"fixture_tool", "generated_compatibility"}};
    auto result = adapters::stack_frame(
        handlers,
        routed({{"addrs", json::array({"0x140040000", "0x140040100"})}}),
        cancellation_token_t::create(), options, metadata);
    require_fixture(!result.is_error(), "stack_frame", "generated_compatibility",
                    result.text());
    const json expected{
        {"result", json::array({
            json{{"addr", "0x140040000"},
                 {"vars", json::array({
                     json{{"name", "saved_rbp"}, {"offset", "-0x8"},
                          {"size", "8"}, {"type", "void*"}},
                 })}},
            json{{"addr", "0x140040100"}, {"vars", json::array()}},
        })},
    };
    require_fixture(result.structured_content() == expected,
                    "stack_frame", "generated_compatibility",
                    "typed frames did not translate to the exact generated output schema");
    require_fixture(backend.query_arguments.size() == 2U &&
                        backend.query_arguments[0] ==
                            json{{"address", "0x140040000"}, {"include_saved_regs", true}} &&
                        backend.query_arguments[1] ==
                            json{{"address", "0x140040100"}, {"include_saved_regs", true}},
                    "stack_frame", "generated_compatibility",
                    "generated address batch was not fanned out to production typed queries");
    ++completed;

    backend.store.clear();
    backend.clear_observations();
    result = adapters::declare_stack(
        handlers,
        routed({{"items", json{{"addr", "0x140041000"},
                                 {"offset", "-0x10"},
                                 {"name", "counter"},
                                 {"ty", "int"}}}}),
        cancellation_token_t::create(), options, metadata);
    require_fixture(!result.is_error(), "declare_stack", "generated_singleton",
                    result.text());
    require_fixture(result.structured_content() == json{{"result", json::array({
                        json{{"addr", "0x140041000"}, {"name", "counter"}},
                    })}},
                    "declare_stack", "generated_singleton",
                    "singleton declaration output differs from the generated schema");
    const auto& declare_payload = backend.overlay_arguments.back();
    require_fixture(declare_payload.at("items").size() == 1U &&
                        declare_payload.at("items")[0] == json{
                            {"address", "0x140041000"}, {"offset", -16},
                            {"name", "counter"}, {"type", "int"}} &&
                        !declare_payload.at("items")[0].contains("addr") &&
                        !declare_payload.at("items")[0].contains("ty"),
                    "declare_stack", "generated_singleton",
                    "generated declaration was not normalized to the production overlay schema");
    ++completed;

    backend.clear_observations();
    result = adapters::delete_stack(
        handlers,
        routed({{"items", json{{"addr", "0x140041000"}, {"name", "counter"}}}}),
        cancellation_token_t::create(), options, metadata);
    require_fixture(!result.is_error(), "delete_stack", "generated_singleton",
                    result.text());
    require_fixture(result.structured_content() == json{{"result", json::array({
                        json{{"addr", "0x140041000"}, {"name", "counter"}},
                    })}},
                    "delete_stack", "generated_singleton",
                    "delete-by-name output differs from the generated schema");
    const auto& delete_payload = backend.overlay_arguments.back().at("items")[0];
    require_fixture(delete_payload ==
                        json{{"address", "0x140041000"}, {"offset", -16}} &&
                        !delete_payload.contains("name"),
                    "delete_stack", "generated_singleton",
                    "delete-by-name did not resolve to the typed production offset payload");
    ++completed;
}

void verify_provenance_confidence(stack_handlers_t& handlers,
                                  backend_state_t& backend,
                                  std::size_t& completed) {
    backend.store.clear();
    backend.store.seed_frame("0x140050000", {
        make_slot(-0x40, 32U, std::nullopt, std::nullopt, "inferred",
                  analysis::fact_provenance_t::recursive_decode, 61U),
        make_slot(-0x8, 8U, std::string("saved_rbp"), std::string("void*"),
                  "inferred_and_declared", analysis::fact_provenance_t::debug_symbol,
                  73U, analysis::stack_slot_kind_t::saved_register),
        make_slot(-0x80, 16U, std::string("buffer"), std::string("char[16]"),
                  "declared", analysis::fact_provenance_t::user_definition,
                  100U, analysis::stack_slot_kind_t::unknown),
    }, 79U);
    const auto result = adapters::stack_frame(
        handlers, routed({{"addrs", "0x140050000"}}),
        cancellation_token_t::create(), matching_options(),
        json{{"fixture_tool", "typed_provenance"}});
    require_fixture(!result.is_error(), "stack_frame", "typed_provenance",
                    result.text());
    const auto& variables = result.structured_content().at("result")[0].at("vars");
    require_fixture(variables.size() == 2U &&
                        variables[0].at("name") == "saved_rbp" &&
                        variables[1].at("name") == "buffer",
                    "stack_frame", "typed_provenance",
                    "generated output did not exclude unnamed inferred slots");
    const auto& typed = result.aida_metadata().at("typed_frames")[0];
    require_fixture(typed.at("confidence") == 79U &&
                        typed.at("slots").size() == 3U &&
                        typed.at("slots")[0].at("provenance") == "recursive_decode" &&
                        typed.at("slots")[0].at("confidence") == 61U &&
                        typed.at("slots")[1].at("provenance") == "debug_symbol" &&
                        typed.at("slots")[1].at("confidence") == 73U &&
                        typed.at("slots")[2].at("provenance") == "user_definition" &&
                        typed.at("slots")[2].at("confidence") == 100U,
                    "stack_frame", "typed_provenance",
                    "typed provenance or confidence was lost during generated translation");
    ++completed;
}

void verify_expected_generation(stack_handlers_t& handlers,
                                backend_state_t& backend,
                                std::size_t& completed) {
    backend.store.clear();
    stack_invocation_options_t matching;
    matching.expected_generation = 9U;
    std::size_t before = backend.query_calls;
    auto result = adapters::stack_frame(
        handlers, routed({{"addrs", "0x140060000"}}),
        cancellation_token_t::create(), matching,
        json{{"fixture_tool", "expected_generation"}});
    require_fixture(!result.is_error() && backend.query_calls == before + 1U &&
                        backend.last_expected_generation == matching.expected_generation,
                    "stack_frame", "matching_generation",
                    "matching expected_generation was not forwarded to the typed query");
    ++completed;

    stack_invocation_options_t stale;
    stale.expected_generation = 8U;
    before = backend.query_calls;
    result = adapters::stack_frame(
        handlers, routed({{"addrs", "0x140060000"}}),
        cancellation_token_t::create(), stale,
        json{{"fixture_tool", "expected_generation"}});
    require_fixture(result.is_error() &&
                        result.error_code() == "MCP_TOOL_TARGET_POLICY_REJECTED" &&
                        backend.query_calls == before,
                    "stack_frame", "stale_generation",
                    "stale expected_generation reached the typed backend");
    const auto& details = result.structured_content().at("error").at("details");
    require_fixture(details.value("expected", 0ULL) == 8ULL &&
                        details.value("actual", 0ULL) == 9ULL,
                    "stack_frame", "stale_generation",
                    "stale generation diagnostics lost expected and actual values");
    ++completed;
}

void verify_conflicts(stack_handlers_t& handlers,
                      backend_state_t& backend,
                      std::size_t& completed) {
    const auto options = matching_options();
    const json metadata{{"fixture_tool", "stack_conflicts"}};

    backend.store.clear();
    backend.store.seed_frame("0x140070000", {
        make_slot(-0x20, 16U, std::nullopt, std::nullopt, "inferred",
                  analysis::fact_provenance_t::recursive_decode, 72U),
    });
    std::size_t before = backend.overlay_calls;
    auto result = adapters::declare_stack(
        handlers,
        routed({{"items", json{{"addr", "0x140070000"},
                                 {"offset", "-0x18"},
                                 {"name", "partial"},
                                 {"ty", "int"}}}}),
        cancellation_token_t::create(), options, metadata);
    require_fixture(!result.is_error() && backend.overlay_calls == before &&
                        result.structured_content().at("result")[0].at("error") ==
                            "offset_overlap_conflict",
                    "declare_stack", "typed_overlap",
                    "partial overlap with an inferred typed slot was not rejected preflight");
    ++completed;

    backend.store.clear();
    before = backend.overlay_calls;
    result = adapters::declare_stack(
        handlers,
        routed({{"items", json::array({
            json{{"addr", "0x140071000"}, {"offset", "-0x40"},
                 {"name", "buffer"}, {"ty", "char[16]"}},
            json{{"addr", "0x140071000"}, {"offset", "-0x38"},
                 {"name", "counter"}, {"ty", "int"}},
        })}}),
        cancellation_token_t::create(), options, metadata);
    const auto& overlap_results = result.structured_content().at("result");
    require_fixture(!result.is_error() && backend.overlay_calls == before + 1U &&
                        !overlap_results[0].contains("error") &&
                        overlap_results[1].at("error") == "offset_overlap_conflict" &&
                        result.aida_metadata().at("overlay_receipt").at("operations") == 1U,
                    "declare_stack", "request_overlap",
                    "intra-request overlap was not filtered before the atomic overlay commit");
    ++completed;

    backend.store.clear();
    backend.store.seed_frame("0x140072000", {
        make_slot(-0x10, 4U, std::string("counter"), std::string("int"),
                  "declared", analysis::fact_provenance_t::user_definition,
                  100U, analysis::stack_slot_kind_t::unknown),
    });
    before = backend.overlay_calls;
    result = adapters::declare_stack(
        handlers,
        routed({{"items", json{{"addr", "0x140072000"},
                                 {"offset", "-0x30"},
                                 {"name", "counter"},
                                 {"ty", "char*"}}}}),
        cancellation_token_t::create(), options, metadata);
    require_fixture(!result.is_error() && backend.overlay_calls == before &&
                        result.structured_content().at("result")[0].at("error") ==
                            "type_conflict",
                    "declare_stack", "type_conflict",
                    "conflicting type for an existing named slot was not rejected");
    ++completed;

    backend.store.clear();
    backend.store.seed_frame("0x140073000", {
        make_slot(-0x30, 8U, std::nullopt, std::nullopt, "inferred",
                  analysis::fact_provenance_t::unwind_metadata, 91U),
    });
    before = backend.overlay_calls;
    result = adapters::declare_stack(
        handlers,
        routed({{"items", json{{"addr", "0x140073000"},
                                 {"offset", "-0x30"},
                                 {"name", "typed_local"},
                                 {"ty", "int"}}}}),
        cancellation_token_t::create(), options, metadata);
    require_fixture(!result.is_error() && backend.overlay_calls == before + 1U &&
                        backend.store.has_named_slot("0x140073000", "typed_local"),
                    "declare_stack", "typed_attachment",
                    "exact declaration did not attach to the inferred typed slot");
    ++completed;
}

void verify_reversible_overlay(stack_handlers_t& handlers,
                               backend_state_t& backend,
                               std::size_t& completed) {
    backend.store.clear();
    const auto options = matching_options();
    const json metadata{{"fixture_tool", "stack_reversible_overlay"}};
    auto result = adapters::declare_stack(
        handlers,
        routed({{"items", json::array({
            json{{"addr", "0x140080000"}, {"offset", "-0x10"},
                 {"name", "undo_var"}, {"ty", "int"}},
            json{{"addr", "0x140080000"}, {"offset", "-0x20"},
                 {"name", "keep_var"}, {"ty", "long long"}},
        })}}),
        cancellation_token_t::create(), options, metadata);
    const auto& receipt = result.aida_metadata().at("overlay_receipt");
    require_fixture(!result.is_error() &&
                        backend.store.named_slot_count("0x140080000") == 2U &&
                        backend.store.history_size() == 1U &&
                        receipt.at("mode") == "reversible_overlay" &&
                        receipt.at("operations") == 2U &&
                        receipt.at("non_overlapping") == true &&
                        receipt.at("live_write") == false &&
                        receipt.at("target_file_write") == false &&
                        backend.live_writes == 0U && backend.target_file_writes == 0U,
                    "declare_stack", "reversible_commit",
                    "stack declaration lacks a verified isolated transaction receipt");
    ++completed;

    result = adapters::delete_stack(
        handlers,
        routed({{"items", json{{"addr", "0x140080000"}, {"name", "undo_var"}}}}),
        cancellation_token_t::create(), options, metadata);
    require_fixture(!result.is_error() &&
                        !backend.store.has_named_slot("0x140080000", "undo_var") &&
                        backend.store.has_named_slot("0x140080000", "keep_var") &&
                        backend.store.history_size() == 2U,
                    "delete_stack", "reversible_delete",
                    "delete-by-name was not committed as a reversible offset operation");
    ++completed;

    require_fixture(backend.store.undo_last() &&
                        backend.store.has_named_slot("0x140080000", "undo_var") &&
                        backend.store.has_named_slot("0x140080000", "keep_var"),
                    "delete_stack", "undo_delete",
                    "undo did not restore the deleted typed variable");
    ++completed;

    require_fixture(backend.store.undo_last() &&
                        backend.store.named_slot_count("0x140080000") == 0U &&
                        backend.store.history_size() == 0U,
                    "declare_stack", "undo_declare",
                    "undo did not restore the pre-declaration frame");
    ++completed;

    const auto verify_tamper = [&](bool& flag, std::string_view category) {
        backend.store.clear();
        flag = true;
        auto tampered = adapters::declare_stack(
            handlers,
            routed({{"items", json{{"addr", "0x140081000"},
                                     {"offset", "-0x10"},
                                     {"name", "tampered"},
                                     {"ty", "int"}}}}),
            cancellation_token_t::create(), options, metadata);
        flag = false;
        require_fixture(tampered.is_error() &&
                            tampered.error_code() == "MCP_TOOL_OUTPUT_INVALID",
                        "declare_stack", category,
                        "unsafe overlay receipt was not rejected fail-closed");
        require_fixture(backend.store.undo_last(), "declare_stack", category,
                        "tampered fixture transaction could not be reversed");
        ++completed;
    };
    verify_tamper(backend.receipt_live_write, "live_write_receipt");
    verify_tamper(backend.receipt_target_file_write, "target_file_receipt");
    backend.receipt_non_overlapping = false;
    auto tampered = adapters::declare_stack(
        handlers,
        routed({{"items", json{{"addr", "0x140082000"},
                                 {"offset", "-0x10"},
                                 {"name", "tampered"},
                                 {"ty", "int"}}}}),
        cancellation_token_t::create(), options, metadata);
    backend.receipt_non_overlapping = true;
    require_fixture(tampered.is_error() &&
                        tampered.error_code() == "MCP_TOOL_OUTPUT_INVALID" &&
                        backend.store.undo_last(),
                    "declare_stack", "non_overlap_receipt",
                    "explicitly overlapping receipt was not rejected and reversed");
    ++completed;
}

void verify_absent_and_invalid_typed_frames(stack_handlers_t& handlers,
                                            backend_state_t& backend,
                                            std::size_t& completed) {
    backend.store.clear();
    backend.store.mark_missing("0x140090000");
    auto result = adapters::stack_frame(
        handlers, routed({{"addrs", "0x140090000"}}),
        cancellation_token_t::create(), matching_options(),
        json{{"fixture_tool", "absent_frame"}});
    require_fixture(!result.is_error() &&
                        result.structured_content().at("result")[0].at("vars").is_null() &&
                        result.structured_content().at("result")[0].at("error") ==
                            "stack_frame_not_found" &&
                        result.aida_metadata().at("typed_frames")[0].at("status") ==
                            "backend_rejected",
                    "stack_frame", "absent_frame",
                    "absent production frame was not represented in generated-compatible form");
    ++completed;

    backend.store.clear();
    backend.invalid_confidence = true;
    result = adapters::stack_frame(
        handlers, routed({{"addrs", "0x140090100"}}),
        cancellation_token_t::create(), matching_options(),
        json{{"fixture_tool", "invalid_typed_frame"}});
    backend.invalid_confidence = false;
    require_fixture(result.is_error() &&
                        result.error_code() == "MCP_TOOL_OUTPUT_INVALID",
                    "stack_frame", "invalid_typed_frame",
                    "out-of-range typed confidence was not rejected");
    ++completed;
}

void verify_stack_handlers() {
    target_resolver_t resolver;
    effect_lock_manager_t locks;
    require(static_cast<bool>(resolver.publish(
                make_target(1U, 4101U, 0xA101U, "fixture-alpha.exe"))),
            "first stack handler target publication failed");
    require(static_cast<bool>(resolver.publish(
                make_target(2U, 4102U, 0xA102U, "fixture-beta.exe"))),
            "second stack handler target publication failed");

    backend_state_t backend;
    workspace_adapter_handlers_t workspace_handlers;
    workspace_handlers.query = [&backend](
        const adapter_call_context_t& context, const adapter_request_t& request) {
        return backend.respond("query", context, request);
    };
    workspace_handlers.overlay = [&backend](
        const adapter_call_context_t& context, const adapter_request_t& request) {
        return backend.respond("overlay", context, request);
    };
    workspace_adapter_t workspace(resolver, locks, std::move(workspace_handlers));
    protocol::schema_runtime_t schemas(64U);
    stack_handlers_t handlers(workspace, schemas);

    verify_contracts(handlers, schemas);

    std::size_t completed = 0U;
    for (std::size_t index = 0; index < k_stack_tool_count; ++index) {
        require(k_stack_adapters[index] != nullptr,
                "stack adapter function is not linked");
        verify_standard_fixture(
            stack_tool_names()[index], k_stack_adapters[index],
            handlers, backend, completed);
    }
    require(completed == k_stack_tool_count * 6U,
            "stack standard fixture count differs from the exact inventory");

    verify_generated_compatibility(handlers, backend, completed);
    verify_provenance_confidence(handlers, backend, completed);
    verify_expected_generation(handlers, backend, completed);
    verify_conflicts(handlers, backend, completed);
    verify_reversible_overlay(handlers, backend, completed);
    verify_absent_and_invalid_typed_frames(handlers, backend, completed);

    require(completed == 37U,
            "stack C16 fixture count differs from the exact verified inventory");
}

}

bool run_stack_handlers_harness(std::string& failure) {
    try {
        verify_stack_handlers();
    } catch (const std::exception& error) {
        failure.assign(error.what());
        return false;
    }
    failure.clear();
    return true;
}

}
