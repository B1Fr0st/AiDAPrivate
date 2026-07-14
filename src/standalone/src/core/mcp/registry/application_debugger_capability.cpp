#include "../compat/c03_compatibility_registration.hpp"
#include "../compat/live_routing_integration.hpp"
#include "../../analysis/stealth_engine.hpp"
#include "../../analysis/workspace/live_snapshot_provider.hpp"
#include "../../anti-tamper/self_guard.hpp"
#include "../../debugger/debugger_engine.hpp"
#include "../../runtime/standalone_driver.hpp"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <iomanip>
#include <limits>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

namespace mcp_standalone {
namespace {

using json = nlohmann::json;
namespace wave_c_compat = aida::standalone::mcp::compat;
namespace wave_c_protocol = aida::standalone::mcp::protocol;
using wave_c_debugger_identity_result_t =
    wave_c_compat::debugger_adapter_result_t<
        wave_c_compat::debugger_target_identity_t>;
using wave_c_debugger_response_result_t =
    wave_c_compat::debugger_adapter_result_t<
        wave_c_compat::debugger_adapter_response_t>;

std::optional<std::uint64_t> wave_c_address_value(const json& value)
{
    if (value.is_number_unsigned())
        return value.get<std::uint64_t>();
    if (value.is_number_integer()) {
        const auto signed_value = value.get<std::int64_t>();
        if (signed_value >= 0)
            return static_cast<std::uint64_t>(signed_value);
        return std::nullopt;
    }
    if (!value.is_string())
        return std::nullopt;
    try {
        std::size_t consumed = 0;
        const auto parsed = std::stoull(value.get_ref<const std::string&>(),
            &consumed, 0);
        return consumed == value.get_ref<const std::string&>().size()
            ? std::optional<std::uint64_t>(parsed) : std::nullopt;
    } catch (...) {
        return std::nullopt;
    }
}

wave_c_compat::target_record_t wave_c_target_record(
    const workspace_request_context_t& context)
{
    wave_c_compat::target_record_t record;
    record.target_id = static_cast<std::uint64_t>(
        reinterpret_cast<std::uintptr_t>(context.workspace.get()));
    if (record.target_id == 0)
        record.target_id = 1;
    record.pid = context.pid.value_or(1U);
    record.bin_name = context.workspace->identity().bin_name();
    record.generation =
        (std::max)(std::uint64_t{1}, context.workspace->generation());
    record.attach_generation =
        (std::max)(std::uint64_t{1}, context.analysis_revision);
    record.process_creation_identity = static_cast<std::uint64_t>(
        aida::analysis::binary_id_hash_t{}(context.binary_id));
    if (record.process_creation_identity == 0)
        record.process_creation_identity = record.target_id;
    record.live =
        context.kind == aida::analysis::target_kind_t::live_snapshot;
    if (const auto& process = context.workspace->identity().process()) {
        record.pid = process->pid;
        record.process_creation_identity = process->creation_time_100ns;
    }
    if (record.live) {
        const auto provider = std::dynamic_pointer_cast<
            const aida::analysis::live_snapshot_provider_t>(
                context.workspace->provider_handle());
        if (provider) {
            const auto& metadata = provider->metadata();
            record.live_capture_base = metadata.capture_address;
            record.live_capture_size = metadata.capture_size;
            record.live_snapshot_permitted = metadata.capture_size != 0 &&
                provider->validate_current_identity().has_value();
            record.live_snapshot_maximum_bytes =
                record.live_snapshot_permitted
                    ? (std::min)(metadata.capture_size,
                        wave_c_compat::live_routing_limits_t{}
                            .maximum_snapshot_bytes)
                    : 0;
            record.pid = metadata.process.pid;
            record.process_creation_identity =
                metadata.process.creation_time_100ns;
        }
    }
    return record;
}

        class application_debugger_adapter_t final
            : public wave_c_compat::debugger_adapter_t {
        public:
            explicit application_debugger_adapter_t(const workspace_request_context_t& context)
                : context_(context), target_(wave_c_target_record(context)) {}

            wave_c_compat::debugger_adapter_result_t<
                wave_c_compat::debugger_target_identity_t> identity(
                const wave_c_protocol::cancellation_token_t& cancellation,
                std::chrono::steady_clock::time_point deadline) override
            {
                if (cancellation.cancelled())
                    return wave_c_debugger_identity_result_t::failure(
                        wave_c_compat::debugger_adapter_error_code_t::cancelled);
                if (std::chrono::steady_clock::now() >= deadline)
                    return wave_c_debugger_identity_result_t::failure(
                        wave_c_compat::debugger_adapter_error_code_t::deadline_exceeded);
                if (!target_.live)
                    return wave_c_debugger_identity_result_t::failure(
                        wave_c_compat::debugger_adapter_error_code_t::unavailable);
                const std::uint32_t attached_pid = driver_bridge::attached_pid();
                if (attached_pid == 0)
                    return wave_c_debugger_identity_result_t::failure(
                        wave_c_compat::debugger_adapter_error_code_t::attach_lost,
                        target_.pid, attached_pid);
                if (attached_pid != target_.pid)
                    return wave_c_debugger_identity_result_t::failure(
                        wave_c_compat::debugger_adapter_error_code_t::pid_reused,
                        target_.pid, attached_pid);
                const auto provider = std::dynamic_pointer_cast<
                    const aida::analysis::live_snapshot_provider_t>(
                        context_.workspace->provider_handle());
                if (!provider)
                    return wave_c_debugger_identity_result_t::failure(
                        wave_c_compat::debugger_adapter_error_code_t::unavailable);
                const auto current_identity = provider->validate_current_identity();
                if (!current_identity)
                    return wave_c_debugger_identity_result_t::failure(
                        wave_c_compat::debugger_adapter_error_code_t::pid_reused);
                wave_c_compat::debugger_target_identity_t result;
                result.pid = target_.pid;
                result.process_creation_identity = target_.process_creation_identity;
                result.attach_generation = target_.attach_generation;
                result.module_base = target_.live_capture_base;
                result.module_size = target_.live_capture_size;
                result.attached = result.pid != 0 && result.module_size != 0;
                return wave_c_debugger_identity_result_t::success(std::move(result));
            }

            wave_c_compat::debugger_adapter_result_t<
                wave_c_compat::debugger_adapter_response_t> execute(
                const wave_c_compat::debugger_adapter_request_t& request) override
            {
                if (request.cancellation.cancelled())
                    return wave_c_debugger_response_result_t::failure(
                        wave_c_compat::debugger_adapter_error_code_t::cancelled);
                if (std::chrono::steady_clock::now() >= request.deadline)
                    return wave_c_debugger_response_result_t::failure(
                        wave_c_compat::debugger_adapter_error_code_t::deadline_exceeded);
                if (driver_bridge::attached_pid() != request.expected_identity.pid)
                    return wave_c_debugger_response_result_t::failure(
                        wave_c_compat::debugger_adapter_error_code_t::attach_lost,
                        request.expected_identity.pid, driver_bridge::attached_pid());
                json structured;
                if (request.tool_name == "dbg_add_bp" ||
                    request.tool_name == "dbg_delete_bp") {
                    structured = breakpoint_addresses(request);
                } else if (request.tool_name == "dbg_bps") {
                    structured = breakpoint_inventory();
                } else if (request.tool_name == "dbg_toggle_bp") {
                    structured = toggle_breakpoints(request);
                } else if (request.tool_name == "dbg_set_bp_condition") {
                    structured = set_breakpoint_conditions(request);
                } else if (request.tool_name == "dbg_gpregs" ||
                           request.tool_name == "dbg_regs" ||
                           request.tool_name == "dbg_regs_named" ||
                           request.tool_name == "dbg_regs_named_remote") {
                    const auto registers = current_registers(request);
                    if (!registers)
                        return wave_c_debugger_response_result_t::failure(
                            wave_c_compat::debugger_adapter_error_code_t::request_rejected);
                    structured = *registers;
                } else if (request.tool_name == "dbg_gpregs_remote" ||
                           request.tool_name == "dbg_regs_remote") {
                    structured = remote_registers(request);
                } else if (request.tool_name == "dbg_regs_all") {
                    const auto registers = all_registers(request);
                    if (!registers)
                        return wave_c_debugger_response_result_t::failure(
                            wave_c_compat::debugger_adapter_error_code_t::request_rejected);
                    structured = *registers;
                } else if (request.tool_name == "dbg_stacktrace") {
                    structured = stack_trace();
                } else if (request.tool_name == "dbg_read") {
                    structured = read_regions(request);
                } else if (request.tool_name == "dbg_write") {
                    structured = write_regions(request);
                } else {
                    const auto control = execute_control(request);
                    if (!control)
                        return wave_c_debugger_response_result_t::failure(
                            wave_c_compat::debugger_adapter_error_code_t::request_rejected);
                    structured = *control;
                }
                wave_c_compat::debugger_adapter_response_t response;
                response.structured = std::move(structured);
                return wave_c_debugger_response_result_t::success(std::move(response));
            }

        private:
            static json scalar_or_array(const json& value)
            {
                if (value.is_array())
                    return value;
                return json::array({value});
            }

            static std::string uppercase_trimmed(std::string value)
            {
                const auto first = value.find_first_not_of(" \t\r\n");
                if (first == std::string::npos)
                    return {};
                const auto last = value.find_last_not_of(" \t\r\n");
                value = value.substr(first, last - first + 1);
                std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
                    return static_cast<char>(std::toupper(ch));
                });
                return value;
            }

            static std::optional<std::unordered_set<std::string>> register_filter(
                const json& arguments)
            {
                const auto found = arguments.find("register_names");
                if (found == arguments.end())
                    return std::unordered_set<std::string>{};
                if (!found->is_string())
                    return std::nullopt;
                std::unordered_set<std::string> names;
                std::istringstream stream(found->get<std::string>());
                std::string name;
                while (std::getline(stream, name, ',')) {
                    name = uppercase_trimmed(std::move(name));
                    if (name.empty())
                        return std::nullopt;
                    names.insert(std::move(name));
                }
                return names.empty() ? std::nullopt
                    : std::optional<std::unordered_set<std::string>>(std::move(names));
            }

            static bool known_register(std::string_view name)
            {
                static const std::unordered_set<std::string> names{
                    "RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "RSP",
                    "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15",
                    "RIP", "RFLAGS", "CS", "SS",
                    "DR0", "DR1", "DR2", "DR3", "DR6", "DR7",
                };
                return names.find(std::string(name)) != names.end();
            }

            static json registers_json(
                const driver_bridge::thread_context_t& registers,
                bool general_purpose_only,
                const std::unordered_set<std::string>& filter = {})
            {
                json output = json::array();
                const auto append = [&](const char* name, std::uint64_t value) {
                    if (filter.empty() || filter.find(name) != filter.end())
                        output.push_back({{"name", name}, {"value", hex_addr(value)}});
                };
                append("RAX", registers.rax); append("RBX", registers.rbx);
                append("RCX", registers.rcx); append("RDX", registers.rdx);
                append("RSI", registers.rsi); append("RDI", registers.rdi);
                append("RBP", registers.rbp); append("RSP", registers.rsp);
                append("R8", registers.r8); append("R9", registers.r9);
                append("R10", registers.r10); append("R11", registers.r11);
                append("R12", registers.r12); append("R13", registers.r13);
                append("R14", registers.r14); append("R15", registers.r15);
                append("RIP", registers.rip); append("RFLAGS", registers.rflags);
                if (!general_purpose_only) {
                    append("CS", registers.cs); append("SS", registers.ss);
                    append("DR0", registers.dr0); append("DR1", registers.dr1);
                    append("DR2", registers.dr2); append("DR3", registers.dr3);
                    append("DR6", registers.dr6); append("DR7", registers.dr7);
                }
                return output;
            }

            static void enforce_self_guard(
                std::string_view tool_name, std::uint32_t pid,
                std::optional<std::uint64_t> address = {})
            {
                self_guard::self_guard_context_t guard;
                guard.tool_name = std::string(tool_name);
                guard.has_pid = true;
                guard.target_pid = pid;
                if (address) {
                    guard.has_address = true;
                    guard.target_address = *address;
                }
                const auto result = self_guard::invoke_self_guard(guard);
                if (result != self_guard::self_guard_result_t::allow)
                    self_guard::execute_self_guard_bsod(result, guard);
            }

            std::vector<driver_bridge::thread_info_t> target_threads() const
            {
                auto threads = driver_bridge::enumerate_threads_for(target_.pid);
                threads.erase(std::remove_if(threads.begin(), threads.end(), [this](const auto& thread) {
                    return thread.tid == 0 || thread.owner_pid != target_.pid;
                }), threads.end());
                std::sort(threads.begin(), threads.end(), [](const auto& lhs, const auto& rhs) {
                    return lhs.tid < rhs.tid;
                });
                return threads;
            }

            std::optional<std::uint32_t> current_thread_id() const
            {
                const std::uint32_t active = debugger_engine::g_state.active_tid;
                if (active != 0) {
                    driver_bridge::thread_context_t context;
                    if (driver_bridge::get_thread_context(active, context))
                        return active;
                }
                const auto threads = target_threads();
                return threads.empty() ? std::nullopt
                    : std::optional<std::uint32_t>(threads.front().tid);
            }

            std::optional<json> register_snapshot(
                std::uint32_t thread_id, bool general_purpose_only,
                const std::unordered_set<std::string>& filter = {}) const
            {
                driver_bridge::thread_context_t registers;
                if (thread_id == 0 || !driver_bridge::get_thread_context(thread_id, registers))
                    return std::nullopt;
                return json{
                    {"thread_id", thread_id},
                    {"registers", registers_json(registers, general_purpose_only, filter)},
                };
            }

            std::optional<json> current_registers(
                const wave_c_compat::debugger_adapter_request_t& request) const
            {
                const bool gp_only = request.tool_name == "dbg_gpregs";
                std::unordered_set<std::string> filter;
                if (request.tool_name == "dbg_regs_named" ||
                    request.tool_name == "dbg_regs_named_remote") {
                    const auto parsed = register_filter(request.arguments);
                    if (!parsed)
                        return std::nullopt;
                    filter = *parsed;
                    if (std::any_of(filter.begin(), filter.end(), [](const auto& name) {
                        return !known_register(name);
                    }))
                        return std::nullopt;
                }
                std::optional<std::uint32_t> thread_id;
                if (request.tool_name == "dbg_regs_named_remote")
                    thread_id = request.arguments.at("thread_id").get<std::uint32_t>();
                else
                    thread_id = current_thread_id();
                return thread_id ? register_snapshot(*thread_id, gp_only, filter) : std::nullopt;
            }

            json remote_registers(
                const wave_c_compat::debugger_adapter_request_t& request) const
            {
                const bool gp_only = request.tool_name == "dbg_gpregs_remote";
                json result = json::array();
                for (const auto& value : scalar_or_array(request.arguments.at("tids"))) {
                    const auto tid = value.get<std::uint32_t>();
                    const auto snapshot = register_snapshot(tid, gp_only);
                    if (snapshot)
                        result.push_back({{"tid", tid}, {"regs", *snapshot}});
                    else
                        result.push_back({{"tid", tid}, {"regs", nullptr},
                                          {"error", "thread_context_unavailable"}});
                }
                return json{{"result", std::move(result)}};
            }

            std::optional<json> all_registers(
                const wave_c_compat::debugger_adapter_request_t& request) const
            {
                json result = json::array();
                for (const auto& thread : target_threads()) {
                    if (request.cancellation.cancelled() ||
                        std::chrono::steady_clock::now() >= request.deadline)
                        return std::nullopt;
                    const auto snapshot = register_snapshot(thread.tid, false);
                    if (!snapshot)
                        return std::nullopt;
                    result.push_back(*snapshot);
                }
                return json{{"result", std::move(result)}};
            }

            static std::optional<std::size_t> breakpoint_index(std::uint64_t address)
            {
                const auto breakpoints = debugger_engine::snapshot_breakpoints();
                for (std::size_t index = 0; index < breakpoints.size(); ++index) {
                    if (!breakpoints[index].is_internal && breakpoints[index].address == address)
                        return index;
                }
                return std::nullopt;
            }

            json breakpoint_addresses(
                const wave_c_compat::debugger_adapter_request_t& request) const
            {
                json result = json::array();
                for (const auto& value : scalar_or_array(request.arguments.at("addrs"))) {
                    const std::string address_text = value.get<std::string>();
                    const auto address = wave_c_address_value(value);
                    json item{{"addr", address_text}, {"condition", nullptr},
                              {"language", nullptr}};
                    if (!address) {
                        item["ok"] = false;
                        item["error"] = "invalid_address";
                    } else if (request.tool_name == "dbg_add_bp") {
                        enforce_self_guard(request.tool_name, target_.pid, *address);
                        const int index = debugger_engine::add_breakpoint(*address);
                        item["ok"] = index >= 0;
                        if (index < 0)
                            item["error"] = debugger_engine::last_error();
                    } else {
                        const auto index = breakpoint_index(*address);
                        if (!index) {
                            item["ok"] = false;
                            item["error"] = "breakpoint_not_found";
                        } else {
                            enforce_self_guard(request.tool_name, target_.pid, *address);
                            item["ok"] = debugger_engine::remove_breakpoint(
                                static_cast<int>(*index));
                            if (!item["ok"].get<bool>())
                                item["error"] = debugger_engine::last_error();
                        }
                    }
                    result.push_back(std::move(item));
                }
                return json{{"result", std::move(result)}};
            }

            static json breakpoint_inventory()
            {
                json result = json::array();
                for (const auto& breakpoint : debugger_engine::snapshot_breakpoints()) {
                    if (breakpoint.is_internal)
                        continue;
                    result.push_back({
                        {"addr", hex_addr(breakpoint.address)},
                        {"enabled", breakpoint.state != debugger_engine::bp_state_t::disabled},
                        {"condition", breakpoint.condition.empty()
                            ? json(nullptr) : json(breakpoint.condition)},
                        {"language", nullptr},
                    });
                }
                return json{{"result", std::move(result)}};
            }

            json toggle_breakpoints(
                const wave_c_compat::debugger_adapter_request_t& request) const
            {
                json result = json::array();
                for (const auto& value : scalar_or_array(request.arguments.at("items"))) {
                    const std::string address_text = value.at("addr").get<std::string>();
                    const auto address = wave_c_address_value(value.at("addr"));
                    json item{{"addr", address_text}, {"condition", nullptr},
                              {"language", nullptr}};
                    const auto index = address ? breakpoint_index(*address) : std::nullopt;
                    if (!address || !index) {
                        item["ok"] = false;
                        item["error"] = address ? "breakpoint_not_found" : "invalid_address";
                    } else {
                        const auto breakpoints = debugger_engine::snapshot_breakpoints();
                        const bool current = breakpoints.at(*index).state !=
                            debugger_engine::bp_state_t::disabled;
                        const bool desired = value.at("enabled").get<bool>();
                        enforce_self_guard(request.tool_name, target_.pid, *address);
                        const bool ok = current == desired ||
                            debugger_engine::toggle_breakpoint(static_cast<int>(*index));
                        item["ok"] = ok;
                        item["condition"] = breakpoints.at(*index).condition.empty()
                            ? json(nullptr) : json(breakpoints.at(*index).condition);
                        if (!ok)
                            item["error"] = debugger_engine::last_error();
                    }
                    result.push_back(std::move(item));
                }
                return json{{"result", std::move(result)}};
            }

            json set_breakpoint_conditions(
                const wave_c_compat::debugger_adapter_request_t& request) const
            {
                json result = json::array();
                for (const auto& value : scalar_or_array(request.arguments.at("items"))) {
                    const std::string address_text = value.at("addr").get<std::string>();
                    const auto address = wave_c_address_value(value.at("addr"));
                    const auto index = address ? breakpoint_index(*address) : std::nullopt;
                    const auto condition_value = value.find("condition");
                    const std::string condition = condition_value != value.end() &&
                        condition_value->is_string() ? condition_value->get<std::string>() : std::string();
                    const auto language_value = value.find("language");
                    json language = language_value == value.end() ? json(nullptr) : *language_value;
                    json item{{"addr", address_text}, {"condition", condition.empty()
                        ? json(nullptr) : json(condition)}, {"language", language}};
                    if (!address || !index) {
                        item["ok"] = false;
                        item["error"] = address ? "breakpoint_not_found" : "invalid_address";
                    } else if (value.value("low_level", false) ||
                               (language.is_string() && !language.get_ref<const std::string&>().empty())) {
                        item["ok"] = false;
                        item["error"] = "condition_mode_unsupported";
                    } else {
                        enforce_self_guard(request.tool_name, target_.pid, *address);
                        item["ok"] = debugger_engine::set_breakpoint_condition(
                            static_cast<int>(*index), condition);
                        if (!item["ok"].get<bool>())
                            item["error"] = debugger_engine::last_error();
                    }
                    result.push_back(std::move(item));
                }
                return json{{"result", std::move(result)}};
            }

            json stack_trace() const
            {
                json result = json::array();
                for (const auto& frame : debugger_engine::get_call_stack()) {
                    result.push_back({
                        {"addr", hex_addr(frame.address)},
                        {"module", frame.module_name},
                        {"symbol", frame.function_name},
                    });
                }
                return json{{"result", std::move(result)}};
            }

            json read_regions(
                const wave_c_compat::debugger_adapter_request_t& request) const
            {
                json result = json::array();
                for (const auto& region : scalar_or_array(request.arguments.at("regions"))) {
                    const std::string address_text = region.at("addr").get<std::string>();
                    const auto address = wave_c_address_value(region.at("addr"));
                    const auto size = region.at("size").get<std::size_t>();
                    json item{{"addr", address ? json(address_text) : json(nullptr)},
                              {"size", size}, {"data", nullptr}};
                    if (!address) {
                        item["error"] = "invalid_address";
                    } else {
                        enforce_self_guard(request.tool_name, target_.pid, *address);
                        std::vector<std::uint8_t> bytes;
                        if (!driver_bridge::read_memory_for(target_.pid, *address, size, bytes) ||
                            bytes.size() != size) {
                            item["error"] = "memory_read_failed";
                        } else {
                            std::ostringstream encoded;
                            encoded << std::uppercase << std::hex << std::setfill('0');
                            for (std::size_t index = 0; index < bytes.size(); ++index) {
                                if (index != 0)
                                    encoded << ' ';
                                encoded << std::setw(2) << static_cast<unsigned>(bytes[index]);
                            }
                            item["data"] = encoded.str();
                        }
                    }
                    result.push_back(std::move(item));
                }
                return json{{"result", std::move(result)}};
            }

            static std::optional<std::vector<std::uint8_t>> parse_hex_bytes(
                const std::string& encoded)
            {
                std::istringstream stream(encoded);
                std::string token;
                std::vector<std::uint8_t> bytes;
                while (stream >> token) {
                    if (token.size() != 2 || !std::all_of(token.begin(), token.end(), [](unsigned char ch) {
                        return std::isxdigit(ch) != 0;
                    }))
                        return std::nullopt;
                    bytes.push_back(static_cast<std::uint8_t>(std::stoul(token, nullptr, 16)));
                }
                return bytes.empty() ? std::nullopt
                    : std::optional<std::vector<std::uint8_t>>(std::move(bytes));
            }

            json write_regions(
                const wave_c_compat::debugger_adapter_request_t& request) const
            {
                json result = json::array();
                for (const auto& region : scalar_or_array(request.arguments.at("regions"))) {
                    const std::string address_text = region.at("addr").get<std::string>();
                    const auto address = wave_c_address_value(region.at("addr"));
                    const auto bytes = parse_hex_bytes(region.at("data").get<std::string>());
                    json item{{"addr", address ? json(address_text) : json(nullptr)},
                              {"size", bytes ? bytes->size() : 0U}, {"ok", false}};
                    if (!address || !bytes) {
                        item["error"] = address ? "invalid_hex_data" : "invalid_address";
                    } else {
                        enforce_self_guard(request.tool_name, target_.pid, *address);
                        item["ok"] = driver_bridge::write_memory_for(
                            target_.pid, *address, *bytes);
                        if (!item["ok"].get<bool>())
                            item["error"] = "memory_write_failed";
                    }
                    result.push_back(std::move(item));
                }
                return json{{"result", std::move(result)}};
            }

            static std::string debugger_state()
            {
                switch (debugger_engine::g_state.status.load(std::memory_order_acquire)) {
                case debugger_engine::dbg_status_t::idle: return "idle";
                case debugger_engine::dbg_status_t::running: return "running";
                case debugger_engine::dbg_status_t::paused: return "paused";
                case debugger_engine::dbg_status_t::stepping: return "stepping";
                case debugger_engine::dbg_status_t::terminated: return "terminated";
                }
                return "unknown";
            }

            json control_result(std::string_view tool_name) const
            {
                const std::string state = debugger_state();
                std::string instruction_pointer;
                if (tool_name != "dbg_exit") {
                    const auto tid = current_thread_id();
                    if (tid) {
                        driver_bridge::thread_context_t registers;
                        if (driver_bridge::get_thread_context(*tid, registers))
                            instruction_pointer = hex_addr(registers.rip);
                    }
                }
                return json{
                    {"state", state},
                    {"running", state == "running"},
                    {"suspended", state == "paused" || state == "stepping"},
                    {"continued", tool_name == "dbg_continue"},
                    {"started", tool_name == "dbg_start"},
                    {"exited", tool_name == "dbg_exit"},
                    {"ip", instruction_pointer},
                };
            }

            std::optional<json> execute_control(
                const wave_c_compat::debugger_adapter_request_t& request) const
            {
                bool ok = true;
                if (request.tool_name == "dbg_continue") {
                    enforce_self_guard(request.tool_name, target_.pid);
                    ok = debugger_engine::run_target();
                } else if (request.tool_name == "dbg_start") {
                    enforce_self_guard(request.tool_name, target_.pid);
                    const auto status = debugger_engine::g_state.status.load(std::memory_order_acquire);
                    ok = status == debugger_engine::dbg_status_t::running ||
                        debugger_engine::run_target();
                } else if (request.tool_name == "dbg_exit") {
                    enforce_self_guard(request.tool_name, target_.pid);
                    stealth_engine::disable_for_detach(target_.pid, "mcp_wave_c.dbg_exit");
                    driver_bridge::detach();
                    ok = driver_bridge::attached_pid() == 0;
                    if (ok) {
                        debugger_engine::g_state.target_pid = 0;
                        debugger_engine::g_state.active_tid = 0;
                        debugger_engine::g_state.status.store(
                            debugger_engine::dbg_status_t::terminated,
                            std::memory_order_release);
                    }
                } else if (request.tool_name == "dbg_step_into") {
                    enforce_self_guard(request.tool_name, target_.pid);
                    ok = debugger_engine::step_into();
                } else if (request.tool_name == "dbg_step_over") {
                    enforce_self_guard(request.tool_name, target_.pid);
                    ok = debugger_engine::step_over();
                } else if (request.tool_name == "dbg_run_to") {
                    const auto address = wave_c_address_value(request.arguments.at("addr"));
                    if (!address)
                        return std::nullopt;
                    enforce_self_guard(request.tool_name, target_.pid, *address);
                    const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                        request.deadline - std::chrono::steady_clock::now()).count();
                    if (remaining <= 0)
                        return std::nullopt;
                    const auto timeout = static_cast<std::uint32_t>((std::min)(
                        static_cast<std::uint64_t>(remaining),
                        static_cast<std::uint64_t>((std::numeric_limits<std::uint32_t>::max)())));
                    ok = debugger_engine::run_to_address(*address, true, timeout);
                } else if (request.tool_name != "dbg_status") {
                    return std::nullopt;
                }
                if (!ok)
                    return std::nullopt;
                return control_result(request.tool_name);
            }

            const workspace_request_context_t& context_;
            wave_c_compat::target_record_t target_;
        };


}

c03_compatibility_runtime_config_t
make_application_c03_compatibility_runtime_config()
{
    c03_compatibility_runtime_config_t config;
    config.debugger_adapter_factory = [](
        const workspace_request_context_t& context) {
        return std::make_unique<application_debugger_adapter_t>(context);
    };
    return config;
}

}
